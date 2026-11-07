# DuckDB transactions after a failed statement

Issue #1453 asks for every place that issues a statement inside an open
DuckDB transaction and carries on after that statement fails other than by
rolling back. This document is the inventory. No site carries on: every
transaction that wyrelog opens is ended by a ROLLBACK, or by a COMMIT that
DuckDB itself turns into one, once a statement in it fails. Two defects in
the policy-store audit replay (T6) were fixed on the way: another thread's
statement could run inside its transaction, and a rollback left an
in-memory cache behind.

`wyrelog/policy/` uses SQLite only and has no DuckDB statements. `wyctl` and
the client library have none either.

## The DuckDB 2.0 behaviour the arguments rely on

`tests/test-audit-conn.c` pins each of these, so a DuckDB upgrade or a
configuration change that alters them fails there first.
`check_duckdb_transaction_abort_contract` uses a connection opened the way
wyrelog opens the audit connection; `check_duckdb_failed_commit_ends_transaction`
needs a commit-time conflict, which takes two connections, and wyrelog never
opens two on one database, so it uses a plain `duckdb_open`. Both hold in
the prebuilt build and in the secure bridge's source build alike.

- **F1. An error aborts the transaction.** After a failed prepare, a failed
  prepared execution, a statement that raises (`error()`), or an appender
  flush that violates a key, every later statement fails with "Current
  transaction is aborted" until ROLLBACK. This holds under the default
  `default_transaction_invalidation_policy`,
  `ALL_ERRORS_INVALIDATE_TRANSACTION`, which wyrelog never changes; the test
  asserts the setting. It is not true of every error: a statement refused
  because another result still holds the connection (`ResourceInUse`), and
  appender errors raised before a flush (a wrong type, an incomplete row),
  leave the transaction usable. wyrelog relies on neither.
- **F2. A COMMIT of an aborted transaction reports success and keeps
  nothing.** DuckDB rewrites it to a ROLLBACK
  (`src/main/client_context.cpp`, the invalidated-transaction branch of the
  commit path). So code that swallowed an error and then committed would
  lose every write in the transaction while reporting success. This is the
  hazard the inventory looks for at every COMMIT.
- **F3. A COMMIT that fails when it commits leaves no transaction.** A
  primary-key conflict found at commit time, for example, ends the
  transaction before the error is reported, so a ROLLBACK issued next fails
  with "no transaction is active" and the connection is usable again
  (`src/transaction/transaction_context.cpp`, `Commit()`). One commit-time
  failure means the opposite of what it says: "Transaction COMMIT succeeded
  and is durable, but the autocheckpoint failed"
  (`src/transaction/duck_transaction_manager.cpp`). wyrelog treats every
  COMMIT error as "not committed". In the fact store a commit-time failure
  therefore also fails the ROLLBACK that `wyl_fact_store_transaction_finish`
  issues next, which poisons the store and returns an internal error, and
  `initialize_identity_unlocked` returns an internal error rather than an
  open error. Both fail closed, as intended.
- **F4. A ROLLBACK ends the transaction** (`TransactionContext::Rollback()`
  clears it before rolling back), provided the ROLLBACK reaches the
  transaction: it does not if the database has already been invalidated by a
  fatal error, if a result still holds the connection, or under the test
  seam `WYL_DUCKDB_TEST_TRANSACTION_CONTROL`. In those cases the transaction
  stays open and aborted.

## How the search was made exhaustive

Every execution form under `wyrelog/`, comments excluded:

| Form | Uses |
|---|---|
| `duckdb_query` | 30: `audit/conn.c` 18, `fact/store.c` 9, `daemon/delta.c` 2, `fact/compound.c` 1 |
| `duckdb_prepare` / `duckdb_execute_prepared` | 49 / 49: `audit/conn.c` 21, `fact/store.c` 20, `fact/compound.c` 4, `fact/legacy-store-identity-private.c` 3, `fact/replay-store-private.c` 1 |
| appender | every call is in `fact/store.c`: `duckdb_appender_create` 2, `_begin_row` 2, `_end_row` 2, `_destroy` 3, `duckdb_append_*` 16; no `_flush` |
| `duckdb_interrupt` | 1, `fact/replay-store-private.c` |
| streaming, pending, arrow, `extract_statements`, `register_*` | none |
| C++ in the secure bridge | `Prepare` 2, `Execute` 2, `Query` 2 (one split across lines), `Interrupt` 1; no transaction statement |

The six `BEGIN TRANSACTION` literals (`fact/store.c` 1,
`fact/store-identity-private.c` 2, `audit/conn.c` 3) were mapped to their
functions, and every statement to the function that runs it and then
through the wrappers to its callers: `exec_sql` (`fact/store.c`, `fact/compound.c`),
`fact_identity_execute`, `execute_no_rows`/`query_count`
(`fact/store-identity-private.c`), `query_ok`,
`rollback_transaction_unlocked`, `commit_transaction_unlocked` and
`audit_conn_run` (`audit/conn.c`) and `cpp_identity_execute` (the bridge).

## Transactions

| | Opener | What can fail inside | Handling | Verdict |
|---|---|---|---|---|
| T1 | `wyl_fact_store_transaction_begin` / `_finish` (`fact/store.c`) | Any statement of its nine callers: compound put, the two batch-shape and forget-intent-state migrations, schema migration, append, graph update, retract, forget completion, orphaned-forget repair | Each step runs only if the previous one succeeded; `_finish` rolls back on any failure, and a failed ROLLBACK poisons the store | Safe |
| T2 | `validate_identity_snapshot` (`fact/store-identity-private.c`) | Catalog and metadata reads | Stops at the first failure, then COMMITs on OK or POLICY and rolls back otherwise. A failed statement yields POLICY only through the bridge's permission or authority exceptions | Safe: the snapshot is read-only, so the COMMIT keeps nothing either way (F2) |
| T3 | `initialize_identity_unlocked` (same file) | CREATE, the identity inserts, re-validation | Every failure rolls back | Safe |
| T4 | `ensure_service_exchange_schema` metadata transaction (`audit/conn.c`) | Prepare, bind or execution of the insert, the readback | Rolls back. The final ROLLBACK's result is checked; the early one after a bind failure is not | Safe (F4) |
| T5 | `wyl_audit_conn_service_exchange_project` (`audit/conn.c`) | Preflight reads, both inserts, readback, COMMIT | Exactly one ROLLBACK plus eviction of the stream's chain tail cache | Safe |
| T6 | `wyl_handle_load_policy_store_audit_events` (`wyl-handle.c`), on the audit connection through `wyl_audit_conn_transaction_begin`/`_commit`/`_rollback` | Intention reconciliation, then one audit event and checkpoint insert per policy-store row | The first failure stops the replay; the transaction is rolled back | Safe, after the two fixes below |

**T6 let other threads into its transaction.** The replay held only the
engine session between BEGIN and COMMIT, while other threads use the audit
connection without it: `wyl_audit_mirror_event` and
`wyl_audit_complete_authoritative_event` run after the engine session is
released, and the audit routes query it. The
connection's own lock did not close the gap either: only the insert, the
service-exchange projection and the sink identity took it, while
`wyl_audit_conn_create_schema` (which the mirror runs before every insert),
`_table_exists`, `_verify_chain`, `_query_events_json`, `_delete_event` and
the user-stream functions ran their statements without it. Another thread's
statement could therefore run inside the replay's transaction. If it succeeded, it was
committed or rolled back with the replay, after being reported as written.
If it failed, it aborted the transaction without the replay seeing it, the
replay's COMMIT then reported success and kept nothing (F2), and the replay
marked its intentions committed. Now every audit-connection function that
runs a statement takes the connection's lock, a recursive one; the event
query holds it for its statement only and redacts the materialised rows
after releasing it, so the redactor's session state is never taken under
it. The replay holds the lock for its whole transaction
(`wyl_audit_conn_transaction_begin` to `_commit` or `_rollback`); its own
calls re-enter it, and other threads wait.
`check_audit_replay_holds_audit_connection` in `tests/test-audit-emit.c`
checks from another thread that the lock is held inside the replay's
transaction, then has a writer read the chain and mirror an event, and
asserts that the read completes only after the replay ends, that the
mirrored event is durable afterwards and that the chain verifies. It runs
the replay both to its commit and into a rollback after an insert; in the
rollback the waiting writer must not link its event to the rolled-back row.

**T6 left a stale cache.** Each insert advances the audit connection's
chain tail cache. A replay that failed after inserting rows (a corrupt
policy-store row, a failed engine projection, a failed COMMIT, or an insert
that failed before executing: in prepare, bind or the duplicate check)
rolled the rows back but left the cache pointing at them, so the next
insert linked to a row that no longer existed and
`wyl_audit_conn_verify_chain` reported `missing_link` from then on. Only a
failed execution of the insert evicted the cache, which is why it went
unnoticed. `wyl_audit_conn_transaction_rollback` now forgets the cache in
the same lock hold as the ROLLBACK, so the next insert reads the tail from
the durable rows.
`check_policy_store_audit_replay_rollback_keeps_chain_contiguous` in
`tests/test-audit-emit.c` drives a replay into a corrupt row after one
insert, then replays again and verifies the chain.

The replay runs when a handle opens and at runtime: from `daemon/checks.c`,
`daemon/delta.c`, the audit query route and after an MFA enrollment is
published (`daemon/http.c`).

## Statements that run with no transaction open

A failure in these rolls back only that statement:

- the fact store's probes, schema DDL, batch and forget-intent reads, and
  the forget deletes and intent writes outside T1; `fact/compound.c`'s reads;
  `fact/replay-store-private.c`; all of `fact/legacy-store-identity-private.c`;
- the audit connection's schema creation, `pragma_table_info` probes and
  ALTERs, validators, preflight reads, user-stream statements, chain
  verification and queries, and its post-commit CHECKPOINT and readbacks;
- `daemon/delta.c`'s two queries and the bridge's own statements.

That classification assumes no transaction is open on the same connection from
elsewhere. The fact store runs one session at a time, and its transactions
exist only inside a session. Once the audit connection is shared, every
statement on it runs under its lock (the statements `wyl_audit_conn_open` runs
come before that), and the replay holds the lock for its whole transaction. The
only statements that bypass it are `daemon/delta.c`'s two readiness probes,
which run through `wyl_audit_conn_get_connection` on the separate readiness
handle the daemon opens and checks on one thread before it serves, so no
transaction can be open on that connection.

## Open items

These are not statements carried on in an aborted transaction, so they are
outside #1453, but the audit surfaced them:

- **A durable COMMIT reported as failed** (#1499). After F3's autocheckpoint
  failure the fact store poisons itself, which fails closed, but its callers
  also cancel the physical quota reservation of bytes that are on disk.
- **A late interrupt carries over** (#1500). The replay store wires
  `duckdb_interrupt` to the fact store connection it borrows. An interrupt
  that lands after its statement has returned stays set and fails the next
  statement on that connection, possibly another session's inside a T1
  transaction; T1 then rolls back, so nothing is kept, but the failure is
  spurious.
- **One unchecked ROLLBACK**, T4's after a bind failure, is safe by F4,
  except after the fatal errors listed there.
- **Nothing checks the audit connection's lock order.** It is not one of
  the service-auth lock ranks (`WylServiceAuthRank` in
  `auth/service-auth-coordination-private.h`), and no lock-order guard
  covers it. Its order today is engine session, then the audit lock, and
  nothing taken under the audit lock waits on another thread. A later
  change that took the engine session, or any lock another thread holds
  while waiting for the audit lock, under it would deadlock unnoticed.

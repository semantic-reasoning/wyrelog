# Engine-session publication contract

`WylHandle` owns one evaluator aggregate: the read engine, delta engine,
symbol map, buffered deltas, callbacks, replacement state, and poison state.
Production code that operates on that aggregate must acquire a typed
`WylEngineSession`. The capability is recursive on its owner thread, so one
complete decision, loader, replay, or replacement can retain a single
linearization interval while calling scoped session operations. The raw mutex
owner is file-local implementation detail and is not a production symbol.

A session token is thread-affine. A foreign-thread release is rejected without
consuming or unlocking the token; the owner must subsequently release it.
Nested owner-thread sessions are allowed and must be released on that same
thread in reverse acquisition order. The general committed-publication runner
accepts only an outermost session and rejects entry from a nested session or a
delta callback with `WYRELOG_E_BUSY` before starting the durable transaction.
Holding a session and requesting reload or committed reconciliation is also
rejected, including from a delta callback.

The lock rank is:

```text
optional service-auth READ/WRITE lease
  -> handle engine session
    -> short-lived policy/audit store work
      -> daemon context
        -> service registry
```

Do not acquire a service-auth lease while holding the engine session. A store
iterator invoked inside an engine session may recursively call handle engine
helpers, but an inner store/context/registry owner must not newly enter an
engine session.

## Replacement and failure classes

An ordinary reload is used only when durable authority is known not to have
changed. It constructs and loads a candidate while holding the engine session.
Failure discards the candidate, its symbol map, and its pending deltas, then
restores the complete old pair. Success replaces the old pair atomically.

After a durable commit, uncertainty about publication or read-back is a
different failure class. `wyl_handle_poison_engine_pair()` is only an ordinary,
fallible request to fence the pair: callers must check its result, and
`WYRELOG_E_BUSY` means that it acquired no engine session and made no mutation.
A committed mutation instead acquires and retains a `WylEngineSession` before
entering higher-ranked store, context, or registry work, keeps it through commit
and projection or read-back, and calls
`wyl_handle_fail_committed_engine_projection()` on uncertainty before releasing
the session. Never commit while holding a higher-ranked owner and then try to
acquire the engine session to fence the result; that rank inversion can leave a
durable mutation unfenced. Committed-failure poisoning is idempotent, discards
every usable engine reference and buffered delta, and makes evaluator
operations and readiness fail closed. An ordinary reload cannot clear poison.

Recovery from committed uncertainty uses
`wyl_handle_reconcile_committed_engine_pair()`. The caller first owns any
required service-auth lease, then supplies a verifier that performs the exact
read-back required by the committed operation. Reconstruction and verification
run under one exclusive recursive engine session. Any load or verification
failure leaves the handle poisoned; only successful full reconstruction and
verification publishes READY.

## Conditional MFA lockout publication

MFA failed-attempt counters do not affect evaluator relations until the
threshold transition. The committed-publication mutation therefore returns an
explicit mode: attempts one through four commit with `NONE`, retain the exact
published engine pair, and do not invoke replacement callbacks. The threshold
attempt atomically changes `mfa_required` to `locked`, appends the `lock`
principal event, and commits with `FULL`. Auto-unlock reads `locked_at`, checks
the elapsed window, changes `locked` to `unverified`, and appends `unlock`
inside the same write transaction before using `FULL`.

The HTTP boundary carries the transaction result forward instead of inferring
it with a second store read. The threshold request is still the invalid proof
that caused the transition and returns 401; later requests that begin locked
return 429. An elapsed auto-unlock returns 401 authentication-required. Store,
commit, reconstruction, callback, or exact-readback faults return 500 and, once
the projected commit is confirmed, poison the pair. A `NONE` commit ambiguity
returns its error but retains the pair because either durable outcome has the
same evaluator projection.

Repair must use committed reconciliation with an exact verifier. For lockout,
that verifier requires the durable transition's exact `principal_fired` event
ID and one recognized current principal state from the reconstructed snapshot;
the current state may be a serialized successor. Failed reconstruction or
verification leaves poison set. Only a successful exact verification publishes
READY, which is also how restart reconstruction re-establishes the projection.

## Authenticated relogin compatibility

The legacy login boundary has two deliberately narrow authenticated-principal
edges. A normal relogin changes `authenticated` to `mfa_required`; an explicit
skip-MFA relogin publishes an `authenticated` to `authenticated` self-loop.
The mutation reads the durable current principal state inside its transaction,
validates that exact edge, compare-and-sets from the observed state, and appends
the matching positive principal event. The self-loop is still a publication:
it receives its own event ID and exact verification instead of being treated as
a no-op. Missing principals retain the existing canonical `unverified` login
edges. Locked, revoked, and every other unsupported predecessor fail with a
conflict and no session, event, audit, or projection side effect.

This compatibility rule governs one login publication only. It does not define
cross-session precedence, invalidate older sessions, or make a later login
retroactively supersede an earlier one; those global session semantics remain
tracked by #752.

## Signed-template custody

The principal FSM Datalog change updates the canonical template digest, but its
production Ed25519 signature is owned by the external release custodian. Issue
#755 tracks signing this exact frozen candidate and returning a signature-only
incorporation change. Until then, production manifest verification must fail
closed. Do not rotate the public key, weaken signature verification, or use a
repository/CI key as a substitute.

Manifest-omitted archives with `require_template_manifest=false` are permitted
only as disposable diagnostic builds for semantic and sanitizer verification.
They are not release candidates and must not modify the tracked manifest. Any
code, test, template, manifest digest, or documentation change after candidate
freeze invalidates the custody evidence and requires a new #755 signing round.

The audit publication lane is the one deliberate reentrant exception. An
audit emitted by a detached delta callback commits its durable row, classifies
that one audit projection against the current pair without interning symbols,
and inserts only the missing audit input facts. Exact projections are
read-only; partial or contradictory projections fail closed. This lane never
replaces the pair, changes the store generation, replays historical rows, or
fans audit relations out through the delta callback. A post-commit projection
or exact-readback failure preserves the durable audit row and poisons the
pair. Consequently, request-local facts and compound identifiers remain valid
for the rest of their owning insert/query/remove interval.

Raw read/delta getters and legacy handle-level evaluator helpers exist only in
the `WYL_TEST_HANDLE_SEAMS` archive. They return borrowed pointers for focused
tests and are unavailable to production callers. Production code uses
`WylEngineSession` operations. The `engine-session-boundary` test guards the
protected entry-point inventory and an explicit owner-function allowlist.

Delta callbacks receive an immutable detached batch. Clearing or replacing the
callback during delivery affects later batches only; every row in the detached
batch is delivered exactly once to the callback captured for that batch. If a
callback poisons the pair, delivery stops immediately and the publication that
owned the batch fails, including when poisoning occurs on the last row.

Deterministic concurrency checkpoints are compiled only into the non-installed
handle test archive. Production shared and static artifacts must not contain
their symbols; `handle-test-seams-not-shipped` verifies that boundary.

# ADR 0004: Durable Record Atomicity and Convergence

Status: accepted

Related issue: #873

## Context

One logical durable record is sometimes represented by several rows or by
state changes that cannot all occur in one storage operation. A process can
stop after any successful write. Unless the representation is atomic or has a
durable convergence protocol, that stop can leave a permanent state which no
normal operation can complete.

The fact subsystem already contains three sound patterns:

- The forget protocol writes a `fact_forget_intent` row before destructive
  steps. `wyl_fact_store_forget_reconcile` replays every pending intent until
  the deletion and completion record converge.
- The graph provisioning record in `fact_graph_provisioning` persists the
  current phase. `wyl_fact_graph_provisioning_recover` resumes the staged,
  published, and verified phases instead of inferring completion from a
  partially published artifact.
- `initialize_identity_unlocked` creates the metadata table and writes all six
  provisioned store-identity keys inside one DuckDB transaction. Failure at
  any key or at commit rolls the whole identity back.

Legacy store identity was the counterexample. `store.c` and `compound.c` each
implemented their own writer for the same `tenant_id` and `graph_id` keys.
Each writer committed the tenant row and graph row as separate statements. A
stop between them produced a tenant-only identity which readers and writers
then permanently refused. The nearby transactional identity implementation did
not prevent the rule from being missed because the invariant was not recorded
and the logical record had two authorities.

## Decision

A durable logical record spread across more than one write is written in one
statement or one transaction. Where that is genuinely impossible, the system
persists an intention or phase before the first non-atomic side effect and
provides an idempotent recovery path which drives every recorded operation to
a terminal state. Permanent refusal of a reachable intermediate state is not
an acceptable substitute for atomicity or convergence.

One durable record has one writer. Different public or private entry points
delegate to that writer rather than copying its SQL, ordering, validation, or
repair policy. The writer documents its locking and transaction contract so a
caller cannot accidentally place a second authority around the same rows.

Use the smallest mechanism which makes the invariant true:

1. Prefer one statement when the database can represent the complete record in
   that statement.
2. Use one transaction when the record requires several database statements.
3. Use a durable intention or phase plus reconciliation when work crosses
   storage engines or includes filesystem side effects which cannot share a
   transaction.

Recovery may repair an old intermediate state only when the state is reachable
from the former writer, the present identity agrees with the caller, and
durable data cannot be relabelled by the repair. Read-only validation does not
repair. Unexpected orientations, a partial identity whose present tenant
disagrees, and a partial identity with durable fact batches fail without
mutation and remain distinguishable from an ordinary complete identity
mismatch.

Fault tests exercise the failure boundary after each partial step, or force a
later row in one statement to fail at execution time. The proof must inspect
durable state after failure and retry or reopen; returning an injected error
before executing the write is not evidence of rollback.

For legacy identity binding, both callers now delegate to one shared writer.
A fresh `tenant_id`/`graph_id` tuple is one multi-row `INSERT`. The only repair
is the formerly reachable tenant-present, graph-absent state on a binding
write, and only when the tenant matches and `fact_batches` is empty.

## Consequences

New multi-row or multi-system records must identify their atomic statement,
transaction, or convergence owner during design and review. Reviewers should
search for every writer of the record rather than validating one call path in
isolation, and supported legacy configurations require direct coverage.

Convergence records add durable state and replay logic, so they are reserved
for boundaries where a statement or transaction cannot work. Conversely, a
shorter implementation is not acceptable if it exposes a reachable permanent
wedge.

This rule does not imply atomicity across DuckDB, SQLite, and the filesystem.
It requires an explicit intention/phase protocol at those boundaries. It also
does not authorize broad migration or relabelling: recovery remains narrowly
scoped to states whose ownership and safety can be proved.

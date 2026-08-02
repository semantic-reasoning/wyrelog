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
thread. Holding a session and requesting reload or committed reconciliation is
rejected with `WYRELOG_E_BUSY`, including from a delta callback.

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
different failure class. Call `wyl_handle_poison_engine_pair()` before
returning the failure. Poisoning is idempotent, discards every usable engine
reference and buffered delta, and makes evaluator operations and readiness
fail closed. An ordinary reload cannot clear poison.

Recovery from committed uncertainty uses
`wyl_handle_reconcile_committed_engine_pair()`. The caller first owns any
required service-auth lease, then supplies a verifier that performs the exact
read-back required by the committed operation. Reconstruction and verification
run under one exclusive recursive engine session. Any load or verification
failure leaves the handle poisoned; only successful full reconstruction and
verification publishes READY.

Raw read/delta getters and legacy handle-level evaluator helpers exist only in
the `WYL_TEST_HANDLE_SEAMS` archive. They return borrowed pointers for focused
tests and are unavailable to production callers. Production code uses
`WylEngineSession` operations. The `engine-session-boundary` test guards the
protected entry-point inventory and an explicit owner-function allowlist.

Delta callbacks receive an immutable detached batch. Clearing or replacing the
callback during delivery affects later batches only; every row in the detached
batch is delivered exactly once to the callback captured for that batch.

Deterministic concurrency checkpoints are compiled only into the non-installed
handle test archive. Production shared and static artifacts must not contain
their symbols; `handle-test-seams-not-shipped` verifies that boundary.

# ADR 0007: Fact Publication Lock Order

Status: proposed (implementation checkpoint)

Related issues: #987, #986

## Context

Fact graph unseal crosses four synchronization domains: the handle replay
coordinator, the physical fact-root/artifact lease, the runtime publication
writer, and the policy graph publication fence.  The artifact fence in #989
prevents a physical replacement, but it does not by itself prove that these
domains are acquired in a deadlock-free order.

The root writer lease is a lifetime/OS lease rather than a process mutex.  It
therefore has a documented lifetime position, but is not held as a nested
GLib mutex.  Runtime entry locks also have an internal order that must not be
reversed: `writer_lock` precedes `state_lock` whenever both are held.

## Decision

The cross-domain order for unseal and publication is:

```
root writer lease lifetime
  -> handle fact-replay coordinator
    -> artifact mutation lease
      -> runtime publication writer (then runtime state lock)
        -> policy graph publication fence
```

The following rules are mandatory:

1. A caller verifies/acquires the root writer lease before entering the
   handle's fact-replay coordinator and retains it through the publication
   sequence.
2. The coordinator is acquired before artifact validation or runtime
   publication.  A path holding the coordinator must not call back into a
   caller that can reacquire it.
3. The artifact mutation lease is acquired before the runtime publication
   writer.  The artifact lease's namespace/OS lock is acquired in the order
   defined by its private backend and is released before the enclosing
   handle coordinator is released.
4. The runtime writer is acquired before runtime state; cleanup releases
   state before writer.  No build callback may recursively enter the same
   runtime entry.
5. The policy graph publication fence is acquired only after runtime
   publication has closed the entry.  No callback while holding the policy
   fence may reacquire the coordinator, artifact lease, or runtime writer.
6. Failure and compensation release domains in reverse acquisition order.

This ADR records the current implementation contract.  It is not evidence by
itself that every concurrent schedule is safe; the deterministic barrier test
must exercise each cross-domain edge and prove bounded join/cleanup.

## Evidence and verification

`tests/test-fact-publication-lock-order-boundary.py` is intentionally a
call-order smoke check: it guards the two production unseal call sites and
does not claim to prove every concurrent schedule.  The runtime test-only
lock event seam now records actual `writer_lock` and `state_lock` acquisition
and release, and `fact-runtime/lock-events-writer-before-state` proves the
runtime sub-order and cleanup.  Runtime build callbacks also refuse
same-entry recursive refresh with `WYRELOG_E_BUSY`; the focused
`fact-runtime/refresh-refuses-own-build-callback` test proves that this known
self-deadlock is bounded.

A future cross-domain test-only seam must additionally force the opposing
thread at each artifact/coordinator/policy acquisition barrier, assert that
no cycle is entered, join all threads within a bounded deadline, and verify
that a subsequent unseal succeeds after every failure path.  Until that test
exists, this ADR and the #987 lock-order acceptance criterion remain
incomplete.

The first #992 implementation checkpoint adds a unified, test-only event
stream for the actual artifact lease, runtime writer/state, policy fence, and
handle-coordinator boundaries.  Events carry an atomic sequence and thread
identity; release events are emitted after the underlying close or unlock
while the borrowed subject remains valid for the synchronous callback.  The
direct graph-unseal forward trace verifies the observed artifact (when the
secure bridge is enabled) -> runtime writer -> runtime state -> policy fence
subsequence.  This checkpoint deliberately does not claim real-handle
contention, reverse-order deadlock freedom, or bounded subprocess cleanup;
those remain the acceptance scope of #992's subsequent matrix unit.

## Bounded matrix unit contract

The next #992 unit is the dedicated
`test-fact-publication-lock-matrix` executable.  Meson registers it only when
the secure DuckDB bridge is enabled, links the handle test-seam archive and
the fact-test support fixture, and serializes it with a 180-second test
budget.  The current source implements the POSIX artifact-lease case; Meson
excludes this unit on Windows until a native Windows lease child harness is
added.  The build must not claim secure publication evidence for an off-bridge
or unsupported platform configuration.

Each forward or opposing-order scenario runs behind a monotonic deadline.  A
scenario that reaches its watchdog uses a monotonic bounded polling window,
then sends a force-exit request and performs a definitive OS child reap.  The
reap does not join application worker locks; it only waits for the already
force-terminated child to leave the kernel process table.  The parent
confirms the child has exited, then the fixture reacquires the artifact lease
and reruns a graph operation.  Successful
reacquisition and graph recovery are required evidence that timeout cleanup
did not leave an OS lease, coordinator, runtime lock, policy fence, or SQLite
transaction held.  This cleanup contract applies to the POSIX artifact
implementation in this unit.  Windows native lease ownership remains an
explicit follow-up rather than an inferred equivalent.

The event stream and direct handle trace already provide observed evidence for
the forward edges:

```
handle coordinator -> artifact mutation lease -> runtime writer
runtime writer -> runtime state -> policy fence
```

The artifact edge is observed through the platform's actual lease boundary
when the secure bridge is enabled, and the runtime and policy edges are
observed through their test-only acquisition events.  The matrix may use
synthetic barrier participants to hold a primitive at a controlled point;
those barrier events are scheduling instrumentation, not proof that a
production callback takes the same path.  Static ADR/call-site checks,
synthetic barriers, and a single forward trace remain insufficient evidence
for reverse-order deadlock freedom.

The later full-matrix unit must add actual reverse-order attempts for
artifact↔runtime and runtime↔policy, plus the coordinator↔policy-store
lifecycle where the wrapper permits it.  That later unit must record which
primitive was observed, which edge was only synthesized, and which platform
path was unavailable.  This bounded registration/checkpoint intentionally
does not prove all reverse interleavings, exhaustive callback cycles, or
complete Windows/POSIX equivalence; those cases remain incomplete until a
follow-up executable exercises and records them.

# ADR 0005: Bounded Main Artifact Transition Evidence and Backend Split

Status: accepted

Related issues: #623, #552, #609, #616, #622

## Context

#552 must restore a validated graph database over an existing main artifact.
The normal bounded DuckDB namespace correctly forbids replacing the held main
artifact, and #609 and #616 both carry that prohibition unconditionally.
Folding a restore exception into either would weaken a live safety contract
for the benefit of an offline operation, and having the #552 coordinator issue
raw renames instead would bypass identity, staging, durability, collision
preservation, platform parity, and crash classification all at once.

#623 therefore owns a separate authority. Its structure was settled while
units 1 and 2a were implemented, and several of the rules below were reached
only by finding the alternative defective in code. ADR 0004 records that an
invariant which is not written down does not prevent the rule from being
missed, even when a sound implementation of it sits nearby. These are written
down for that reason.

## Decision

### The authority is split into a value-only contract and platform backends

`graph-artifact-main-transition-private.{h,c}` classifies state and authorizes
operations. It contains no filesystem call of any kind. Backends observe the
namespace, execute authorized mutations, and report what happened; they never
decide what is legal.

The split exists so the state machine can be tested exhaustively without a
filesystem, and so the two platform backends cannot drift apart on the
question of what a given namespace shape means.

### Durability is evidence, never inferred from a successful mutation

A rename returning success says nothing about whether the directory entry
survived a power loss. Every durability claim in this authority originates in
an actual flush, and is carried as a latched receipt in the transition object.

Receipts are latched at `record` time and are inputs to `record` only.
`authorize` never reads the durability fields of an observation; it reads the
latches it holds. A fresh admission after a restart therefore begins with all
four latches clear, which is the correct reading: a receipt is historical and
cannot be re-observed from a directory.

### The epoch rule

A successful `record` of any rename or unlink operation -- `RETAIN`,
`PUBLISH`, `ROLLBACK`, `RETIRE_STAGE`, `FINALIZE` -- ends the directory epoch
and clears both directory-seam latches regardless of their value. The receipt
no longer describes the directory it attested and must be re-earned. This is
not a regression; it is a new epoch.

File-seam latches are not cleared, because they attest inode data and a rename
does not change it.

Without this rule the accompanying "PROVEN is absorbing" rule reads as
unconditional and is wrong: a seam could attest a flush taken before the
mutation it was supposed to order.

### Only directory seams may report UNSUPPORTED

`staged_file` and `rollback_file` are file seams. A file seam reporting
UNSUPPORTED is itself a refusal, because flushing a regular file is not
optional on any supported platform. `directory_after_retain` and
`directory_after_publish` are directory seams, and they are the only place the
documented platform capability gap is allowed to surface.

A directory flush the platform cannot prove blocks `FINALIZE` alone -- the
single irreversible step -- so the operation rests convergently rather than
resting in a state with no main artifact.

### Every mutation targets an absent name

`RETAIN` moves the old main aside before `PUBLISH` runs. The contract
consequently never needs a replace-or-exchange primitive, and no operation
ever overwrites a name that exists.

This is what makes native Windows parity reachable: only the classic rename
path is ever taken there, and it has no capability gap. The gap is POSIX-only,
where the no-replace rename fails closed off Linux and Apple.

### The capability flag comes from an out-of-band probe

`no_replace_supported` must be established by a probe performed before any
mutation is authorized, against artifacts the operation owns and retires. It
must never be inferred from a failed real rename, because `EEXIST`, `EINVAL`,
`ENOSYS` and `ENOENT` all collapse onto one return code -- so inferring
capability from it misclassifies a foreign-file collision as a missing
primitive, and the reverse.

A probe that cannot classify unambiguously fails rather than guessing.

### No orphan

No state may leave an operation-owned artifact resident with no legal
operation able to retire it. This is checked in both modes. The cleanup path
of the expected-main-absent mode was unrecordable for two revisions because
its terminal state had been defined only in terms of the other mode.

### Totality

When a predicate is duplicated across two functions, both must cover the same
domain totally, or the pair diverges at exactly the cells nobody walked. The
gate and the next-operation projection diverged three times during unit 1.

A backend that mirrors "which operation is legal here" beside its own dispatch
is the next instance of this, and is prohibited: `authorize` is the only judge
of legality.

### Names are derived, never chosen

The three operation-scoped names are derived from one canonical UUIDv7 string
and nothing else:

    final    = facts.duckdb
    stage    = restore-<canonical>.duckdb
    rollback = restore-<canonical>.duckdb.superseded

Derivation validates by round trip -- parse, re-format, compare -- so a
non-canonical spelling is rejected rather than normalised. Two spellings of
one UUID would otherwise derive two different name sets for one operation.

Exactly two implementations of this derivation exist in the tree: the
contract's own, and the platform-neutral backend-side header both backends
include. One agreement test relates them. A third derivation appearing
anywhere is the signal that a backend has gone around that header.

### An effect the backend cannot determine is UNKNOWN, never NOT_APPLIED

`NOT_APPLIED` asserts that the kernel rejected the operation. The contract
treats `NOT_APPLIED` paired with the post-mutation shape as a terminal
ambiguous collision, because either the backend owed `UNKNOWN` or a third
party produced that shape -- and adopting the second as our own success is a
substitution attack arriving through the effect argument rather than through
an absence check.

A backend that reports `NOT_APPLIED` where it owed `UNKNOWN` therefore poisons
the operation permanently rather than merely losing a step.

### Inventory and transition evidence are one capture

Admission never pairs a transition observation with a separately synthesized
or later-taken #622 snapshot. On POSIX the normal namespace and transition
provider call one shared scanner. On Windows the transition provider asks the
retained locator for a complete begin scan and a complete end scan. The main,
stage, rollback, lock, directory identity, anomaly counts, and fingerprint are
therefore values from one bounded begin/end epoch. A mismatch publishes
neither half and reports `UNSTABLE`.

The operation-derived stage and rollback remain `UNKNOWN_ENTRY` anomalies in
the inventory. Their exact count is checked against the separately captured
identity evidence; an extra unknown therefore cannot be mistaken for an
operation artifact. Malformed, substituted, case-colliding, reparse, or
ambiguous entries remain hard anomalies.

Provider construction binds three authorities, not two: the exact resolver,
the directory opened from it, and the writer lease that authorizes that
resolver. This relation is revalidated before and after capture and before
execution. A valid lease from another root is an authority failure, not a
weaker valid lease.

On Windows, that revalidation also requires the retained root and graph
directory handles to remain non-inheritable and the graph directory to retain
its protected owner-only ACL. Construction, every capture boundary, and every
execution boundary fail closed if either native authority property changes.

### The unit-4 driver is a compatibility fixture, not #552 durability

The test driver persists the complete request semantics and consumer
generation behind an injected load/compare-and-swap value-store interface.
It writes `ATTEMPT_UNKNOWN` by CAS before a caller may invoke a mutation. A
stale attempt CAS suppresses the invocation. If the backend action ran but the
completion CAS is stale or the process exits first, the durable marker remains
`ATTEMPT_UNKNOWN`; restart is inspect-only and never replays that action. After
a process loss, a fresh provider, fresh capture, and fresh transition classify
the physical state; no record is ever applied to a destroyed transition and no
rename or unlink is replayed blindly.

Fresh physical classification deliberately does not reproduce historical
durability latches or the transient `ROLLED_BACK` state. A completed
`SYNC_PUBLISH_DIR` recorded as `PUBLISHED_DURABLE` therefore reopens as
`PUBLISHED` and may repeat only the idempotent directory sync. A completed
rollback recorded as `ROLLED_BACK` reopens as `READY` and may retire the stage
only when the persisted request forbids forward resume; it never repeats the
rollback rename. Preflight cancellation returns before load, attempt CAS, or
action invocation. Retryable sync and acknowledged `UNSUPPORTED` directory
durability remain nonterminal and are never promoted to proven durability.

The fixture's store is deliberately separate from graph state. Its in-process
implementation proves revision ordering, and the child-process tests persist
the complete request, generation, revision, and marker outside the graph
directory before releasing all authority. This is a compatibility contract for
#552, not a claim of machine-crash persistence.
#552 still owns the real journal, registry-generation CAS, restore policy, and
durability guarantees.

## Consequences

Unit 1 proves the wiring of the `REPARSE`, `OWNERSHIP`, `LINK_SUBSTITUTION`
and `PRIMITIVE_UNSUPPORTED` refusals and claims no detection. A backend that
supplies those inputs without implementing their detection satisfies the
contract and proves nothing. The evidence is owed by the backends: the
capability probe, the no-follow open flags, the file-status and protected
owner-only validation, and the file-identity and link-count pair.

`resume_forbidden` carries two responsibilities. It blocks re-driving a
restore, and it unlocks the operations that end one -- `ROLLBACK` to unwind
and `RETIRE_STAGE` to clean up. A bug that sets it spuriously does not corrupt
a graph, since `ROLLBACK` restores the previous main before `RETIRE_STAGE`
unlinks the stage; but an incorrect journal read can unwind a live restore as
well as decline a fresh one. The flag is a policy assertion #552 owns; #623
enforces it and cannot verify it.

A genuinely foreign file in the graph directory still fails a restore closed
with no documented path to clear it. The admission gate counts the operation's
own artifacts, so it no longer refuses its own stage, but the stray-file story
remains #552's to write.

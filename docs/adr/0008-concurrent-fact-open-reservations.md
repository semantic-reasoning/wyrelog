# ADR 0008: Concurrent Fact-Store Open Reservation Ownership

Status: proposed for review

Related issues: #1098, #1154

## Context

Issue #1098 cannot safely count only HTTP opens. Legacy HTTP, provisioned
graphs, provisioning recovery, replay, maintenance, nested handles, and
caller-owned artifact leases can all retain a physical fact store. A counter
attached to one wrapper would either undercount concurrent stores or release a
slot before the underlying DuckDB and artifact resources are gone.

The policy SQLite database is the authority for quota configuration and
durable reservations. It is not a transaction boundary for DuckDB or the
filesystem, so acquisition and cleanup must be modeled as a recoverable
protocol. PID and elapsed-time reclamation are insufficient because PID reuse
and delayed cleanup can make a live owner look stale.

## Decision

One slot represents one independently owned physical fact-store open resource,
including the period in which its acquisition is pending. Multiple references
to the same owned resource borrow the same token. A second physical open gets
a different token. An artifact lease that will cause a physical store to be
opened reserves before acquisition; a lease-only operation does not consume a
fact-store-open slot.

Every token has a random reservation id and an owner-incarnation id. The
incarnation is unique per process lifetime and may own multiple reservations;
reservation ids are unique per reservation and are never reused. The owner
first creates and identity-binds a per-token native lease file under the
verified fact root, then publishes the pending reservation. POSIX holds an
exclusive `flock` on its descriptor; Windows holds an exclusive `HANDLE` with
delete/share modes disabled and the file identity pinned. The owner retains
each token lease through acquisition and teardown. At process initialization
the coordinator installs an `atfork` prepare/parent/child protocol. Token
creation, close, and the registry of token, artifact, and store descriptors
all take the coordinator's fork mutex; the prepare hook takes that mutex and
quiesces registry mutation, the parent hook releases it, and the child hook
uses only async-signal-safe close operations on the frozen descriptor list.
The child hook closes every inherited token and artifact descriptor/handle,
marks inherited store references unusable, and sets an inherited-resource
poison flag. The child must create a new owner incarnation before it can open
or settle a store. Thus a child that remains alive after the parent exits
cannot use the parent's token or retain its artifact lease. Missing or
replaced lease files fail closed. Reconciliation validates root and file
identity and attempts the same non-blocking exclusive lease: a live owner
returns `E_BUSY`, while a terminated owner has released its kernel handle/lock.
On Windows, the root identity is read from a separately opened directory
handle, while the token identity is read back from the successfully acquired
exclusive token `HANDLE` and compared with the durable token identity.
Reclamation requires both identity proofs and an atomic
owner-incarnation/reservation compare-and-set. PID and age are diagnostics
only.

## Resource accounting

| Open path | Counted resource | Token owner / transfer |
| --- | --- | --- |
| `wyl_fact_store_open` from legacy HTTP | physical graph store | HTTP operation owns until `wyl_fact_store_close` |
| `wyl_fact_store_open_provisioned_graph` | physical graph store | provisioning coordinator transfers to returned store |
| `wyl_fact_store_open_identified_provisioned_pair_pinned` | staged/final physical store acquisition | provisioning operation owns; transfer only after activation |
| `open_graph_store` in replay | physical graph store | replay operation owns; nested readers borrow |
| maintenance/recovery reopen | physical graph store | operation owns until close and settlement |
| Nested handle/read | existing physical store reference | borrows the existing token; no new slot |
| `wyl_fact_store_open_provisioned_namespace_with_lease` | future physical acquisition | reservation precedes acquisition; lease alone is not charged |

The implementation must inventory each production call site before enabling the
quota. A usable store is published only with an active token. Pending,
active, and cleanup-pending tokens all consume capacity, so the invariant is:

```
new_charged_usage <= finite_limit
```

`pending + acquiring + active + cleanup_pending` is charged usage. Existing usage may
exceed a newly lowered limit; lowering never evicts a live store and admission
stays closed until charged usage falls below the new limit.

## Durable state protocol

The reservation table contains `reservation_id`, `owner_incarnation`,
tenant/resource identity, state (`pending`, `acquiring`, `active`, or
`cleanup_pending`),
and timestamps. A unique key on the reservation id makes settlement
idempotent.

1. Generate the reservation id, acquire its native lease, and bind its root and
   file identity. Under the policy writer authority and `BEGIN IMMEDIATE`,
   validate the tenant and limit, then insert a pending token if charged usage
   is strictly less than the limit (`charged_usage + 1 <= limit`, checked
   without integer overflow). The insert includes unique reservation and
   incarnation ids and is conditional on the owner-incarnation record. A
   denied request acquires no graph, DuckDB, or artifact resource and releases
   the just-created native lease.
2. Commit the reservation and release SQLite/authority locks before physical
   acquisition. Blocking filesystem and DuckDB work never occurs under the
   policy transaction.
3. Transition `pending` to `acquiring` with a conditional CAS, then acquire
   the artifact and physical store. The acquisition owner serializes with the
   cancellation barrier: after acquisition it observes the cancellation flag
   and either tears down or conditionally changes `acquiring` to `active`.
   Only the owner that wins that CAS may publish the store to another owner;
   if cancellation arrives after activation but before publication, it marks
   the active token for cleanup and removes the unpublished handoff. If a
   reference was already published, cancellation waits for that reference to
   release before teardown. Activation updates SQLite in a short transaction
   while retaining the per-token native and artifact leases.
4. If acquisition fails or is cancelled, the token owner performs teardown;
   cancellation wins only with `UPDATE ... WHERE reservation_id=? AND
   owner_incarnation=? AND state='pending'`. After teardown, it conditionally
   settles that exact token. If teardown or settlement fails, keep the token in
   `cleanup_pending` and retry conservatively.
5. On close, destroy DuckDB and close the physical store, then release the
   artifact lease and confirm that release. The owner retains the native lease
   through the conditional settlement transaction and releases it only after
   settlement is durable and the token file has been retired. Repeated
   close/settle calls are no-ops for an already-settled reservation. If
   artifact release fails, settlement is not attempted and the token remains
   charged in `cleanup_pending`.

The state changes are conditional and token-specific:

```
pending -> acquiring          WHERE id=? AND owner=? AND state='pending'
pending -> cleanup_pending    WHERE id=? AND owner=? AND state='pending'
acquiring -> active           WHERE id=? AND owner=? AND state='acquiring'
acquiring -> cleanup_pending  WHERE id=? AND owner=? AND state='acquiring'
active  -> cleanup_pending    WHERE id=? AND owner=? AND state='active'
cleanup_pending -> settled    WHERE id=? AND owner=? AND state='cleanup_pending'
```

`settled` is represented by the immutable settlement record (or absence only
after that record is durable). A new reservation can never reuse an old
reservation id. An owner incarnation may own multiple reservations, but a
retired incarnation can never admit another one. The owner retains the
physical-resource pointer until close has completed; reconciliation never calls close through a
freed pointer. If the state CAS loses, the caller relinquishes only resources
it can prove it owns and does not alter the winner's token. Cancellation never
settles an `acquiring` token directly: it sets a cancellation flag, waits for
the acquisition owner to acknowledge completion, and that owner performs
teardown and the one settlement. A cancellation barrier is required before an
`acquiring -> cleanup_pending` transition. The barrier is the same handoff
mutex plus an acquisition-owner acknowledgement; a cancellation request that
observes `acquiring` sets the flag, and the acquisition owner performs teardown
and settlement after acknowledging it. A cancellation request that observes
`active` takes the handoff mutex first, preventing any new reference from
being published.

### Crash and race table

| Boundary | Durable state | Possible resource | Charged | Recovery |
| --- | --- | --- | --- | --- |
| reservation commit | pending | none | 1 | owner acquires or cancels exact token |
| acquisition in progress | acquiring | artifact/DuckDB | 1 | liveness proof decides whether owner is live; otherwise exclusive recovery cleans it |
| activation commit | active | usable store | 1 | owner close settles active token |
| cancellation after acquisition | acquiring/cleanup-pending | resource may exist | 1 | acquisition owner acknowledges cancellation, tears down, then settles |
| close before settlement | cleanup-pending | resource may remain | 1 | retry close, then settle exact token |
| settlement commit | settled | no counted resource | 0 | duplicate settlement is harmless |
| owner crash | pending/acquiring/active/cleanup-pending | uncertain | 1 | reacquire exact lease identity; only exclusive acquire plus incarnation CAS permits recovery |
| acquisition races cancellation | acquiring | one or both resources | 1 | cancellation barrier acknowledges the acquisition owner; that owner tears down and settles the exact token |

Reconciliation is serialized by the policy writer authority and uses the
owner-incarnation/liveness proof plus resource identity. It first acquires and
retains the verified per-token native lease outside SQLite. In a short
transaction it claims the exact row with
`UPDATE reservations SET owner_incarnation=?, recovery_claim=? WHERE
reservation_id=? AND owner_incarnation=? AND state IN (...)`; the two owner
values are the observed durable owner and the new recovery incarnation. It
then releases SQLite, performs recovery/teardown outside the transaction,
reacquires the writer authority, and conditionally settles using the recovery
incarnation and claim. A reconciler crash releases its native lease and leaves
the row charged; the next reconciler repeats the same proof and claim CAS,
including when the previous owner was itself a reconciler. The native lease is
held through identity validation, claim, recovery, and settlement, and is
released only after the settlement result is durable. A concurrent reconciler
cannot settle the same token twice, and delayed cleanup cannot release
capacity belonging to a later reservation because every transition matches
reservation id, incarnation, and (for recovery) claim.

If the policy store shuts down, the reservation coordinator retains settlement
context rather than a borrowed `wyl_policy_store_t`; failed persistence leaves
the prior durable state charged and schedules retry.

The native lease file is created with the random reservation id and is removed
only after a denied admission, or after a durable settlement. Every lease-file
create, replace, and retire operation must first hold the root namespace
writer lease; this is the enforced trust boundary for namespace mutation.
Retirement holds that lease and the native lease, validates the root and exact
file identity immediately before removal, then removes the entry and closes
the native handle: POSIX uses `unlinkat` on the verified root descriptor;
Windows marks the verified token handle delete-pending with
`SetFileInformationByHandle` while the exclusive handle remains open. A
competing cleaner using the protocol cannot acquire the namespace lease or
held native lease. If an out-of-protocol actor can mutate the directory, the
implementation treats identity as unverifiable and does not unlink. Before
settlement this leaves the reservation charged for conservative recovery;
after durable settlement it leaves an uncharged cleanup tombstone and never
resurrects the reservation or repeats physical teardown. Identity safety is
not claimed against that actor. Startup orphan cleanup follows the same
namespace lease and exact-identity check: a live unpublished owner remains
protected and its file is left in place, while a terminated owner can be
cleaned after the absence of a matching durable reservation is confirmed. A
pre-publication crash therefore cannot be mistaken for a live token, and a
settled token cannot strand a charged row without its identity proof.

## Limits, status, and failures

Absent limit means unlimited admission, but usage is still recorded so a later
finite limit applies to existing usage. Zero refuses new reservations. Lowering
the limit below current charged usage preserves all existing resources and
blocks new reservations until usage falls. Values outside the SQLite signed
integer domain are rejected before mutation. Status reports pending, acquiring,
active, cleanup-pending, and charged totals separately; storage/reconciliation errors
are errors, not quota exhaustion.

Quota refusal uses the existing HTTP envelope with HTTP 429,
`error=fact_quota_exceeded`, and `dimension=concurrent_opens`. Authorized
client and `wyctl` status surfaces expose the same typed counts and limit.

## Lock and lifetime order

The lifecycle uses an acquisition graph rather than one total order. The
edges are: verified root -> root namespace writer lease -> per-token native
lease -> reservation writer authority/SQLite -> pending publication; pending publication -> artifact
acquisition; artifact/native ownership -> activation writer authority/SQLite;
and store/runtime teardown -> artifact release -> settlement writer
authority/SQLite. Reservation and reconciliation release SQLite before
waiting for artifact or store resources. No path acquires an artifact while
holding SQLite, so the activation artifact-to-SQLite edge cannot complete a
cycle through artifact acquisition. The phase-specific held sets are:
reservation holds native lease plus writer authority+SQLite while publishing
the pending row; acquisition holds native and artifact leases but no SQLite;
activation holds native and artifact leases together with writer authority and
SQLite while changing `acquiring` to `active`; close holds store/runtime locks
while destroying DuckDB, releases and confirms the artifact lease, settles
while retaining native, then performs identity-safe retirement and releases
the native lease; reconciliation holds
its verified native lease while claiming, recovering, and settling, but never
waits for a close while SQLite is held. The handoff mutex is acquired only for
publication or cancellation state changes and is never held while acquiring a
resource.

Nested references to the same physical store borrow its token. A genuinely new
nested physical open at limit one is refused or deferred after its parent
coordinator is released. Settlement after policy shutdown is owned by a
root-scoped reservation coordinator retaining the verified policy path, root
identity, reservation id, and owner incarnation—not a policy-store or freed
store pointer. Its retry worker reacquires root authority and a fresh policy
store, revalidates identity, and conditionally settles; failed reopen/write
leaves the token charged and retries without repeating DuckDB destruction.

## Acceptance plan for #1098

- Barrier-controlled process tests for limits 0, 1, N, unlimited, tenant
  isolation, lowering, overflow, and simultaneous admission.
- `test-fact-open-reservation-accounting` tests every concrete inventory row
  above, including nested ownership transfer
  and caller-owned lease acquisition.
- Injected failures at reservation, acquisition, activation, close, and
  settlement; barriers cover pending-publication versus reconciliation,
  cancellation versus activation, policy shutdown before cleanup, lease-file
  replacement, and acquisition-vs-cancellation.
- Repeated close/reopen and concurrent settlement tests proving no leak or
  double release.
- `test-fact-open-reservation-reconcile` terminates owners at every crash row,
  including live-owner preservation, PID reuse, and competing reconcilers.
- Fork tests keep a child alive after the parent exits and verify that inherited
  descriptors and store references cannot be used or counted as the child's
  reservation; the child must create a new incarnation. A fork barrier races
  descriptor creation/close and proves the prepare hook freezes the registry
  before the child performs its async-signal-safe cleanup.
- `test-fact-open-reservation-status` covers lowering, zero/unlimited,
  overflow, and charged-state reporting. Migration preservation tests retain
  limits and reservations, plus HTTP 429,
  client parsing, CLI authorization, and golden status output.
- A second physical nested open at limit one must be refused without waiting
  under the parent coordinator. Native Windows and POSIX liveness/lease tests
  cover non-inherited descriptors, identity replacement, live-owner
  preservation, concurrent reconcilers, pre-publication orphan cleanup, and
  settlement retirement. A normal-close versus recovery-claim barrier proves
  the native lease remains held through settlement and that a takeover cannot
  trigger duplicate teardown. Artifact-release failure and the replacement
  barrier between final identity validation and deletion prove that capacity
  remains charged when artifact release or pre-settlement cleanup cannot be
  established; post-settlement retirement failure leaves only an uncharged
  tombstone. Sanitizer tests cover cleanup after policy shutdown.
  Barriers and injected failures replace timing sleeps.

This ADR is the prerequisite design artifact for #1098. Implementation must
not begin until the resource inventory, transition table, native liveness
mechanism, and lock-order evidence are reviewed and accepted.

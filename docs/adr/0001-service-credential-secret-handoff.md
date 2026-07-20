# ADR 0001: Service Credential Secret Handoff

Status: accepted

Related issues: #475, #506, #508, #515, #516, #517

## Context

A service-credential operation has two different durable boundaries. The
policy store can atomically establish that a credential exists; publication
can later make its plaintext secret available in an operator-owned file. A
lost response or process crash between those boundaries must not issue a
second credential, lose the only copy of a secret that must still be
published, or cause a journal to become a plaintext secret store.

The current credential secret is an opaque, secure-memory object. The policy
store owns the credential verification key (CVK) through a KeyProvider-sealed,
provider-bound envelope. The existing `wyctl` publication backend accepts
sensitive text transiently, but it does not yet provide the recovery contract
described below.

## Decision

The policy SQLite database will hold a provider-sealed escrow row. Creation of
that row is in the same authority transaction as the credential, operation
fence, lifecycle event, and audit intention. The escrow plaintext is never
placed in an operation journal, audit payload, log, SQL metadata, process
ordinary memory, or a retry queue.

Version 5 is the legacy delivery journal. Version 6 adds non-secret remediation
provenance: the last remediation action and request, its source-snapshot digest
and request fingerprint, and the applied target state. A decoder rejects
versions 1--4, any v5/v6 hybrid, and either version when it violates its exact
field contract. Version 5 remains readable for legacy recovery but is never
eligible for terminal journal retirement. The journal is not an escrow
fallback.

The sole plaintext-file exception is the final published credential document.
The publication backend must create it with owner-only permissions and retain
the exact receipt needed to inspect, resynchronize, or clean up that specific
file. It is a deliberate delivery artifact, not an additional internal
plaintext cache.

## Threat model and scope

This decision protects against process loss, response loss, retry, and
publication crash windows while preserving the policy store as the authority
for credential existence. It also protects against accidental secret exposure
through ordinary allocations, diagnostics, audit metadata, journal bytes, and
SQLite metadata.

It does not make an operator-owned destination safe when its owner, the
running operating-system account, or its configured KeyProvider is
compromised. It does not provide exactly-once delivery of arbitrary file bytes,
cross-host secret replication, user-visible secret recovery after the final
file is deliberately removed, or a general-purpose secret vault.

## Escrow key ownership and validation

Escrow uses a KeyProvider purpose separate from both the policy database key
and the CVK. The sealed envelope embeds fixed magic, format version, purpose,
domain, escrow reference, credential/operation binding, and provider-binding
data. Unseal must verify all of those values after decryption before returning
the secret to the executor. The executor receives the result only in a secure
secret container and clears it on every return path.

If the provider is unavailable, malformed, bound to a different provider, or
cannot unseal and verify the envelope, execution fails closed. It must not
create a replacement credential, publish a guessed value, downgrade to a
journal secret, or report delivery success. Provider rotation rewraps the
unchanged escrow plaintext under the new provider binding while preserving the
escrow reference and operation binding; it does not regenerate a credential.

## State machine and delivery contract

| Durable state | Meaning | Allowed next action |
| --- | --- | --- |
| `PREPARED` | Request intent is durable; no credential or escrow exists. | Expiry/cancel blocks only authoritative admission; no-commit evidence may terminalize without escrow. |
| `SERVER_COMMITTED` | Credential, fence, event, audit intention, and escrow are durable. | Remains retryable regardless of expiry/cancel; durably reserve the publication plan before any staging side effect. |
| `PUBLICATION_PLANNED` | The exact destination, parent identity, reservation id, stage basename, and receipt correlation are durable; no receipt is durable yet. | Create or verify only the exact owner-only stage named by this plan, then checkpoint its identity in `PUBLICATION_PREPARED`. |
| `PUBLICATION_PREPARED` | A destination-specific receipt is durable. | Exact final credential id+secret checkpoints `FILE_PUBLISHED`; exact owned nonfinal stage with absent destination may clean that stage only, then a durable cleanup resets receipt and checkpoints `SERVER_COMMITTED`. |
| `FILE_PUBLISHED` | Exact receipt confirms the final owner-only document. | Delete escrow only after this checkpoint. |
| `CLEANUP_REQUIRED` | Escrow deletion failed after `FILE_PUBLISHED` was durable. | Retry escrow deletion without changing credential or publication. |
| `OPERATOR_ACTION_REQUIRED` | Receipt or escrow evidence is foreign, mismatched, indeterminate, explicitly held, irreconcilably uncertain after `FILE_PUBLISHED`, or proves the exact successor revoked/expired; escrow id/digest, successor tuple, actor, receipt, and immutable identity remain byte-for-byte unchanged. | Separately authorized resume or remediation only. |
| `TERMINAL` | A non-delivery terminal result is durable. | Read-only reporting. |

Delivery is at least once and idempotent by escrow reference plus exact
publication receipt. Exactly-once *bytes* cannot be promised: a crash after a
filesystem rename and before receipt persistence can leave a correctly written
file without a durable acknowledgement. Therefore `inspect` and `resync` must
determine whether a receipt identifies the exact published document, not merely
whether a path exists. The current `wyctl` publication interface has
plan/prepare/commit/inspect/resync/cleanup operations, but lacks this complete
escrow-reference and exact-content recovery guarantee; it is an explicit gap
to close before an executor is enabled.

`OPERATOR_ACTION_REQUIRED` is never entered merely for expiry or cancellation:
those conditions affect only `PREPARED` admission. Cleanup/inspection I/O
uncertainty, foreign replacement, and wrong credential id or secret enter OAR
with no destructive write. Invalid direct transitions fail closed.

## Ordering and crash windows

| Order | Durable work | Crash result | Recovery rule |
| --- | --- | --- | --- |
| 1 | Authoritative transaction writes credential, fence, event, audit intention, and sealed escrow. | Nothing commits, or all commit. | Retry authoritative execution only when no committed fence exists. |
| 2 | Journal checkpoints `SERVER_COMMITTED` with escrow reference/digest. | Escrow may exist before the journal checkpoint. | Reconcile durable policy evidence; never reissue. |
| 3 | Journal checkpoints `PUBLICATION_PLANNED` with the destination, parent identity, reservation id, stage basename, and receipt correlation. | The plan is durable before any stage exists. | Retry only this byte-identical plan; never choose a new stage name. |
| 4 | The backend durably creates or verifies the exact owner-only stage, then the journal checkpoints its receipt and identity in `PUBLICATION_PREPARED`. | The exact stage may exist while the journal still says `PUBLICATION_PLANNED`. | Retry `stage_exact` with the same plan and content; accept an identical owned stage only, and never overwrite or clean foreign evidence. |
| 5 | Publication commit creates the owner-only final file. | Final file may exist without a durable completion checkpoint. | Inspect/resync the exact pinned receipt target; do not blindly overwrite. |
| 6 | Exact inspection checkpoints `FILE_PUBLISHED`. | Delivery may be complete but journal stale. | At-least-once inspection/resync, then checkpoint. |
| 7 | Delete escrow only after `FILE_PUBLISHED` is durable. | Escrow delete may fail after delivery is durable. | Enter `CLEANUP_REQUIRED` and retry deletion only. |

Expiry, cancellation before the authoritative transaction, or terminal
authorization failure produces no credential or escrow. A `PREPARED` record
with authoritative no-commit evidence may terminalize without escrow; an
escrow row for such a no-commit record is corruption and fails closed. Once
committed, the escrow and successor remain retryable; expiry/cancel alone never
causes OAR, revocation, wipe, deletion, or terminalization.

In `PUBLICATION_PREPARED`, only exact final destination evidence for the
expected credential id and secret checkpoints `FILE_PUBLISHED`. An exact owned
nonfinal stage with an absent destination permits cleanup of that backend stage
artifact only, never escrow; only durable cleanup success may clear the receipt
and checkpoint `SERVER_COMMITTED` for a fresh prepare. Cleanup uncertainty,
foreign replacement, wrong id/secret, or inspection uncertainty enters OAR
without a destructive write.

Escrow deletion is ordered strictly after the `FILE_PUBLISHED` checkpoint. A
deletion failure enters `CLEANUP_REQUIRED` and retries deletion only; it does
not change credential or publication. A post-policy-commit or
post-publish/pre-checkpoint crash retains escrow until exact inspection can
checkpoint delivery. Irreconcilable post-checkpoint escrow database uncertainty
enters OAR and preserves the durable tuple.

An exact revoked or expired successor enters OAR and retains the durable tuple
byte-for-byte; it never causes automatic unseal, publication, revoke, wipe,
deletion, or terminalization. Automatic escrow deletion is limited to exact
final receipt evidence plus a durable `FILE_PUBLISHED` checkpoint.

Manual `OPERATOR_REVOKE_AND_WIPE` and resume are separate, fresh-authenticated
operations. Revoke-and-wipe requires explicit confirmation, a distinct
remediation request and audit action, and the exact credential id and
generation; if the successor is already inactive it verifies that exact tuple
before tombstoning and wiping escrow. Resume is separately authorized and
inspects the receipt before retry. Neither remediation path reuses the
original actor or request id. Terminal metadata retirement follows the private
receipt-first rules below; active or recoverable escrow is never eligible.

## Terminal journal retirement

Retirement is limited to an exact version-6 `TERMINAL` snapshot. The eligible
terminal evidence is either `FILE_PUBLISHED` with no remediation marker or
with the exact preceding `RESUME` marker, or `OPERATOR_REVOKE_AND_WIPE` with
its exact revoke marker. `NOT_COMMITTED`, version 5, and every nonterminal
state are excluded.

The policy authority follows the exact delivery or remediation provenance and
verifies both escrow-id absence and original-request escrow absence in the
same write transaction. The retention basis is the greatest timestamp among
the journal and every referenced delivery, remediation, or revoke-event row.
A trusted clock must be at least 30 days beyond that basis before the authority
can commit retirement evidence.

Retirement first commits an immutable, permanent, non-secret receipt. Only
after that commit may the coordinator delete and synchronize the exact anchored
journal snapshot, matching its request id, raw digest, version, terminal kind,
and remediation marker. A crash after receipt commit replays from that receipt;
an already missing snapshot is normalized to success only after the receipt
has been validated. Without a receipt, a missing snapshot remains
`NOT_FOUND`.

The permanent receipt burns the original request id. Retirement and guarded
operation begin share its lifecycle-lock namespace, and guarded begin rejects
reuse whenever that receipt exists. The receipt contains no secret, path,
ciphertext, or duplicate full credential tuple; it retains only the non-secret
identifiers, digests, timestamps, and provenance references required to prove
the deletion. Public ingress and any scheduling policy remain deferred to
#517.

## Consequences

Secret delivery becomes a recoverable workflow rather than a best-effort
return value. It adds KeyProvider purpose/versioning, escrow retention, exact
receipt semantics, and operational compensation requirements. In return, it
keeps secret material out of the operation journal and makes response-loss and
post-commit crashes fail closed without credential duplication.

## Follow-up issue plan

The implementation order is #510, then #511/#512/#514 in parallel where
their interfaces permit, then #513, then #515, then #516, and finally #517. #515
also depends on #508's current-actor authorization design and implementation.

1. [#510](https://github.com/semantic-reasoning/wyrelog/issues/510) adds only the private provider-sealed escrow
   table and opaque DTO/API. Its v1 envelope binds operation/request/actor,
   target digest, credential tuple, deadline, escrow id, and version. It is
   accepted only when providerless or unhealthy configurations fail closed,
   every binding/blob swap is rejected, duplicate ids and rollback leave no
   row, plaintext never reaches metadata/diagnostics, and unseal is private
   locked-memory-only work.
2. [#511](https://github.com/semantic-reasoning/wyrelog/issues/511) depends on #510 and rewraps pending rows while old
   and new providers coexist. It must preserve row identity/binding after a
   successful rotation, leave no mixed set or provider-generation advance on
   unseal/seal/database failure, wipe temporary buffers, and ignore consumed
   or terminal rows.
3. [#512](https://github.com/semantic-reasoning/wyrelog/issues/512) depends on the #510 envelope contract and defines
   journal v5 only: preallocated escrow id, immutable non-secret binding
   digest, receipt metadata, terminal reason, and legal lifecycle transitions,
   including durable `OPERATOR_ACTION_REQUIRED` and post-`FILE_PUBLISHED`
   `CLEANUP_REQUIRED`. Expiry/cancel blocks only `PREPARED` admission, never
   committed retry. Exact final id+secret evidence checkpoints
   `FILE_PUBLISHED`; exact owned nonfinal stage cleanup can reset receipt to
   `SERVER_COMMITTED` only after durable cleanup. Cleanup/inspect uncertainty,
   foreign or mismatched identity, wrong id/secret, and authoritative exact
   inactive-successor evidence enter OAR without a destructive write,
   preserving the durable tuple byte-for-byte and never automatically wiping
   or terminalizing it. Only separately authorized OAR action may resume or
   remediate. Codec and
   replay/checkpoint tests must reject v1--v4, changed id/digest/receipt, and
   invalid/direct transitions while proving that no plaintext, sealed blob, or
   secret canary occurs in journal bytes.
4. [#513](https://github.com/semantic-reasoning/wyrelog/issues/513) depends on #510, #512, #504, and #505. It refactors
   private issue and checked-rotate cores to generate material exactly once and
   atomically write the sealed escrow with credential, request/fence, event,
   and audit. Fault and stale-CAS/fence tests must leave no material, escrow,
   or domain side effect; committed retries must find the same escrow and
   successor; legacy direct APIs remain outside handoff mode.
5. [#514](https://github.com/semantic-reasoning/wyrelog/issues/514) must merge before escrow publication transitions.
   It hardens `wyctl` plan/receipt commit, inspect, resync, and cleanup to
   prove the exact credential id and secret on both POSIX and Windows. Tests
   must classify malformed, foreign, wrong-id/wrong-secret, and
   rename/fsync-uncertain files as non-delivered, wipe sensitive buffers, and
   verify the destination parent before destructive work.
6. [#515](https://github.com/semantic-reasoning/wyrelog/issues/515) depends on #508, #512, #513, and #514. It adds the
   private authenticated executor: current authenticated actor must equal the
   durable actor and retain management authorization before any escrow consume.
   Authorized issue/rotate must publish exactly the owner-only receipt and
   delete escrow only after `FILE_PUBLISHED`; mismatch, permission loss,
   malformed intent, or foreign receipt must perform no unseal, mutation,
   publication, or secret exposure. Crash seams must converge without a second
   credential and domain audit/event actor must remain the durable actor.
7. [#516](https://github.com/semantic-reasoning/wyrelog/issues/516) follows
   #515 (and therefore its v5/atomic prerequisites). It supplies
   receipt-aware `OPERATOR_ACTION_REQUIRED`, explicit terminal remediation,
   post-delivery deletion, version-6 remediation provenance, and permanent
   receipt-first terminal journal retirement. Tests must
   prove that committed expiry/cancel preserves byte-identical escrow,
   successor, and receipt state in its existing lifecycle state and never
   enters OAR merely for expiry/cancel, without automatic
   unseal/publish/revoke/wipe; only exact inspected receipt plus
   `FILE_PUBLISHED` permits automatic deletion. Authoritative exact revoked or
   expired successor evidence alone enters OAR and preserves state; it never
   permits automatic wipe or terminalization.
   Manual
   revoke-and-wipe/resume requires fresh authorization, confirmation where
   applicable, a distinct request/audit, and exact credential tuple (including
   inactive-tuple verification). Retirement accepts only exact eligible v6
   terminal evidence after the 30-day minimum, commits its permanent non-secret
   receipt before exact snapshot deletion, and permanently prevents reuse of
   the original request id.
8. [#517](https://github.com/semantic-reasoning/wyrelog/issues/517) depends on
   #515 and #516 and is the final public ingress and scheduling contract. It
   must disable or replace legacy direct plaintext
   issue/rotate ingress, make dropped-response retry return the same operation
   and credential without a second secret, redact unauthorized/error/log/body
   paths, and document at-least-once idempotent destination delivery without
   promising exactly-once observable responses.

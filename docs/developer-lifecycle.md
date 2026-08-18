# Developer lifecycle constraints

## Raw `fork()`

Wyrelog deliberately installs no `pthread_atfork` handlers. After a process
with any live Wyrelog handle, store, provider, lease, logger, or error state
calls raw `fork()`, the child must immediately call an `exec*` function or
`_exit()`.

Before `exec*` or `_exit()`, the child must not call any Wyrelog API, close or
free inherited Wyrelog state, format a Wyrelog error, emit a log, call GLib
cleanup that can reach Wyrelog state, or call C `exit()`. The child may use
only async-signal-safe preparation required for `exec*`; if `exec*` fails it
must terminate with `_exit()`.

Policy-store lease descriptors use `CLOEXEC`. Windows lease handles are
created non-inheritable. This makes `fork()` followed immediately by `exec*`
safe without child-side lifecycle processing while preserving the live
parent's exclusive store lease.

## Fact-root writer lease

A handle opened with a non-empty fact root is a writer and must acquire one
exclusive root lease before it opens or creates the policy store. The lock
order is fact-root writer lease, policy-store lease, graph-authority mutex,
runtime engine ownership, then DuckDB. Ordered shutdown destroys graph
engines and closes the policy store before releasing the root lease. Every
failed handle open follows the same release order.

The fact root is a bootstrap prerequisite: daemon setup may create the empty
owner-only root before handle open. Lease acquisition then opens and pins the
root with the secure graph resolver; later lease decisions never trust an
unchecked configured pathname. After opening the policy store, handle startup
binds its graph resolver under the graph-authority mutex only when the lease
authorizes that resolver's exact native root identity. This authorization
precedes policy schema creation and startup graph replay. Startup readiness
uses scratch policy and audit stores and deliberately passes no fact root to
its handle, so it neither acquires write authority nor opens a writable fact
store. The runtime handle is the first startup consumer that acquires
authority.

On POSIX, the exclusive non-blocking `flock()` is held on the verified root
directory descriptor itself. There is no sidecar and no fallback to a
process-associated `fcntl()` lock. A process-local device/inode registry
closes alias gaps before the kernel lock attempt. On Windows, a fixed
`.wyrelog-writer-lock` file is opened relative to the pinned root handle with
share mode zero. The file must be a zero-length, single-link, non-reparse
regular file protected by the exact owner-only ACL and must retain the named
file identity recorded under that root.

The Windows artifact is permanent coordination metadata and is never removed
or replaced during normal release or recovery. Its presence is not evidence
of a live owner; the share-mode open is. POSIX and Windows both rely on handle
close for orderly release and operating-system process teardown for crash
release. Operators must not delete, truncate, chmod, relink, or otherwise
"recover" the authority object. A live conflict returns `WYRELOG_E_BUSY`;
malformed or replaced authority returns `WYRELOG_E_POLICY`; native failures
return `WYRELOG_E_IO`. Operator-visible startup errors use those fixed,
path-free error strings.

Lease verification also proves whether another secure resolver has the same
native root identity. This is the required contract for backup, restore, and
future maintenance entry points. It prevents cooperating writers and detects
persistent root replacement; it does not make DuckDB's later pathname opens
descriptor-bound. That remaining same-owner pathname window belongs to #544.

## Provider-backed store path threat model

Every provider-backed store, encrypted or plaintext, must be placed in an
operator-owned, non-replaceable namespace. The resolved parent and every path
ancestor must be protected from rename, reparse, and write operations by any
principal whose trust is lower than the operating-system identity running
Wyrelog for the store's entire lifetime, from before open until close has
completed. This is a deployment requirement, not an optional hardening
measure.

The store lease provides alias normalization, retained-parent identity
verification, cooperating-process exclusion tied to the lease sidecar/store
lease identity, and stale-close prevention. It does not pin or continuously
match the canonical SQLite store inode. After acquisition, Wyrelog pins its
own canonical reads, encrypted persistence, and clear-work helper cleanup to
the resolved parent authority.

SQLite does not expose a portable `openat()` VFS. It opens an encrypted
clear-work database, or a plaintext provider-backed canonical database,
through a lease-resolved pathname. Parent-identity checks bracket only the
initial main-database `sqlite3_open_v2()` call. They can detect a persistent
parent replacement across that initial bracket, but not a transient
swap-and-restore inside it. Later VFS opens for journal, WAL, SHM, temporary,
and other files remain pathname-derived throughout the store lifetime and are
not pinned or bracketed by those checks. Persistent or transient namespace
changes after the post-open check are therefore also unprotected. The lease
does not make an attacker-writable namespace safe at any point in the store
lifetime.

## Policy-store provider ownership

`wyl_policy_store_open_with_options()` consumes a non-null KeyProvider state
on every outcome once both `opts` and `out_store` have passed entry validation.
It copies the supplied vtable by value. A successful open retains the state
until store close; a failure releases it before returning. The caller must not
invoke provider operations or `wipe` after transfer. If
`keyprovider_state_free` is non-null, the caller must not release the state:
Wyrelog invokes `wipe` exactly once when that callback is available, then
invokes `keyprovider_state_free` exactly once.

A providerless configuration has null vtable, state, and free callback. Any
other combination is configured and requires non-null state and vtable, with
all of `probe`, `seal`, `unseal`, `derive`, `wipe`, and `clear_sealed_blob`.
The state free callback is the only optional member. Configured plaintext
stores call `probe` exactly once, call no `derive`, and retain the provider for
the same close-time lifecycle as encrypted stores.

If `keyprovider_state_free` is null, Wyrelog still consumes the logical
provider state and invokes `wipe` exactly once when available, but does not
deallocate its backing storage. That storage must outlive a successful store
handle. The caller may reclaim it only after store close, or after a failed
open returns; its contents must not be reused as KeyProvider state. Invalid
partial configurations are released using only the lifecycle callbacks they
provide; an unavailable callback is invoked zero times.

An invalid entry where `opts` or `out_store` is null transfers nothing and
invokes no lifecycle callback. If store lease acquisition returns
`WYRELOG_E_BUSY`, no operational KeyProvider callback (`probe`, `seal`,
`unseal`, or `derive`) is invoked; the transferred state's lifecycle cleanup
still follows the available-callback rules above.

`seal` callers pass an output initialized to `{ NULL, 0 }`. Failure preserves
that empty value. A successful output is released only through the producing
provider's `clear_sealed_blob`, which securely wipes its length, uses the
matching allocator to free it, and resets it to `{ NULL, 0 }`. Clearing a null
or already-cleared blob is safe.

Key rotation performs no transfer for an empty path, null option, or aliased
non-null old/new state. After basic validation it consumes both states on every
outcome. The old provider is retained by the internal store while the new
provider is validated and used. An old-provider failure, including
`WYRELOG_E_BUSY`, also releases the new provider. Rotation uses the old store's
snapshotted CVK secure runtime for locked scratch. The runtime supplied through
`new_opts`, if any, is not adopted or invoked by this transient operation.

The clear SQLite work database is disposable rotation staging. After schema
and snapshot validation in `BEGIN IMMEDIATE`, an existing CVK is unsealed with
the old provider and re-sealed under a distinct new-provider binding with its
generation incremented; the 32-byte CVK and every credential verifier remain
unchanged. The staged transaction commits before an encrypted candidate is
prepared with the new database key. A fully written, file-synced and closed
temporary file is then renamed over the canonical file. That rename is the
sole rotation linearization point: a failure before it leaves the old canonical
file byte-for-byte unchanged, while a failure of directory durability after it
is logged as a warning and the already-committed rotation returns success.
Provider handoff and secret-buffer cleanup occur while the exclusive lease is
still held, and close never performs a second persist.

The post-rename warning contains no key, CVK, credential or path material. It
means atomic visibility has committed successfully but power-loss durability of
the directory entry could not be confirmed; it must never be translated into a
failure that invites an unsafe retry with the old root.

Crash recovery follows the same boundary: a crash before rename leaves the old
root authoritative; a crash after rename leaves the new root authoritative.
The operation is deliberately not crash-resumable or idempotently retryable in
#354 because a caller cannot infer which root won after losing the response.
Operators must retain both roots and follow the explicit recovery procedure
tracked by #364.

## Service credential verification key

The service credential CVK is created only by the issuance path. The
existing-only path never creates authority: an empty store returns
`WYRELOG_E_NOT_FOUND`, while credentials without the singleton CVK row are a
policy-corruption failure. Both paths reject an outer SQLite transaction and
serialize their top-level `BEGIN IMMEDIATE` transaction with a per-store
mutex. A newly generated or unsealed CVK becomes observable through the
store's borrowed cache only after the database commit succeeds.

The cache is a locked, store-owned 124-byte version-1 envelope. It is wiped,
unlocked, and freed at store close. The envelope binds its fixed magic,
domain, version, singleton slot, generation, provider binding, and 32-byte CVK
at fixed byte offsets. The provider binding is derived under the KeyProvider
label `wyrelog.service-credential.cvk.provider-binding.v1` and a separately
domain-separated keyed BLAKE2b transcript. Provider outputs are always
released with the producing provider's `clear_sealed_blob` callback.

The optional CVK runtime table is shallow-copied at store open. Its callbacks
and `data` pointer are borrowed; no ownership is transferred. The callback
code and data context must outlive the store and remain valid through the end
of `wyl_policy_store_close()`.

Root-provider rotation never creates a missing CVK. A missing row with existing
credentials is policy corruption; a missing row with no credentials follows
the legacy database-key-only rotation path without CVK derive, unseal, seal or
random-number callbacks. Existing rows require a non-overflowing generation
and a new provider binding distinct from the old binding.

## Service lifecycle audit reconciliation

Service-principal and service-credential operations succeed when their local
SQLite savepoint commits the authority state, lifecycle event, sanitized audit
row, and pending audit intention together. The external Wirelog projection and
DuckDB audit mirror are eventual, post-commit work; mirror failure must never be
translated into lifecycle failure, secret loss, or secret re-issuance.

Audit-enabled handles reconcile pending and failed intentions explicitly and
again while opening a persistent handle. A failed projection records a retry
attempt and remains eligible for idempotent reconciliation. There is no
automatic lifecycle adapter: callers that require a live mirror invoke the
private reconciler only after the lifecycle call returns. The daemon
single-writer contract applies while lifecycle mutations and reconciliation
share a policy store.

Reconciliation classifies the complete Wirelog projection for an audit ID as
absent, exact, or inconsistent. Only an absent projection may be inserted and
only an exact projection may be skipped. A partial, duplicate, mismatched, or
unexpected optional fact is policy corruption: reconciliation fails the
intention without writing DuckDB or marking it committed. Normal projection
errors roll back every input inserted by that attempt, so a partial projection
is never a valid retry checkpoint.

## Public Service Credential HTTP contract

The daemon publishes the Service Credential API as one feature-gated route
set. The management routes are `/service-principals` and
`/service-credentials`; the audit-enabled build adds the loopback-only
`POST /auth/service-token`, and the fact-store-enabled build adds the
`/service-credential-operations` collection plus its `reconcile` and `recover`
actions. A build without an owning feature does not register that feature's
route or a compatibility stub.

The exact method/template matrix contains eight base routes. Audit alone adds
one (nine total), fact store alone adds three (eleven total), and enabling both
produces twelve. `/service-principals` and `/service-credentials` are the only
intentional prefix registrations. The operation collection, its two actions,
and `/auth/service-token` are singleton registrations protected by the shared
exact-registration adapter.

The exact management paths are `POST` and `GET /service-principals`,
`POST /service-principals/{subject}/disable`, `POST` and `GET
/service-principals/{subject}/credentials`, `GET /service-credentials/{id}`,
`POST /service-credentials/{id}/rotate`, and `DELETE
/service-credentials/{id}`. The fact-store-enabled operation paths are `GET
/service-credential-operations`, `POST
/service-credential-operations/reconcile`, and `POST
/service-credential-operations/recover`. No alias, legacy, hidden, or alternate
route is supported. Reconciliation and recovery return sanitized, non-secret
operation evidence; they never return a credential secret.

Path ownership is decided before method selection, authentication, body or
query parsing, logging, limiter consumption, storage access, locks, or
mutation. A trailing slash, deeper or doubled segment, suffix collision, or
other unknown shape therefore returns the generic `404 {"error":"not_found"}`
for every method and credential/body combination. Once a canonical template
matches, an unsupported method returns `405 method_not_allowed`; identifier,
query, and body validation then retain their route-specific semantic errors.
In-tree client and CLI callers construct only the canonical paths above and do
not rely on prefix aliases or trailing-slash normalization.

All eleven management routes share one authorization envelope. They are
SYSTEM-profile, actual-listener-and-peer loopback endpoints that accept only an
`Authorization: Bearer` human session. The session must be live, ACTIVE,
MFA-assured, and rooted in the sole resolver tenant `__wr_default`; refreshing
a token does not create MFA assurance. Every request supplies strict guard
context and is authorized again while its READ or WRITE service-authority lease
is held. Principal routes require `wr.service_principal.manage`; credential and
operation routes require `wr.service_credential.manage`.

### Service-authority WRITE terminalization

A daemon service-authority WRITE owner acquires resources in the order lease
(rank 1), engine session (rank 2), policy-store pin (rank 3), request context
(rank 4), and registry state (rank 5). Every terminal path unwinds that order
in reverse, closes any authority transaction and maintenance claim, and then
explicitly finalizes the WRITE lease. A route must not access the borrowed
policy store after finalization and must not attach a success status, header,
or body before finalization succeeds. The wrapper destructor is only a
non-asserting fail-closed emergency path; production owners explicitly
finalize, and repeated finalization returns the first cached result without
entering terminal release again.

Terminal release checks the store pin, lock rank, and sole-owner accounting.
Any inconsistency latches service authentication unavailable for the remaining
daemon process lifetime. Cleanup failure dominates the route result and emits
HTTP 500 with `policy_write_cleanup_failed`, even when the primary operation
had otherwise succeeded or failed differently. A durable mutation may already
have committed before cleanup failed, so this response never represents a
rollback or proves that no commit occurred. Diagnostics contain only the
static owner identifier, the primary internal result when known, the primary
HTTP status and error code, and the numeric cleanup result; they must not
include credentials, tokens, actors, tenants, request paths, or bodies.

There is deliberately no in-process reset path for the unavailable latch.
Human authentication, health, and ordinary decision handling remain available,
but subsequent service-authority WRITE acquisition fails closed. Only daemon
restart, which constructs a fresh handle and authority coordinator, restores
service-management availability after the underlying fault is corrected.

The management bearer tenant and the managed target tenant are deliberately
different concepts. Credential and operation requests select their target with
the `tenant` query parameter while authentication stays rooted in
`__wr_default`. Principal management is global: an omitted principal tenant or
an explicit `__wr_default` is accepted, and a non-default principal tenant is a
usage error. For credential IDs and operation records, the authority derives
the tenant from stored credential or journal state and requires an exact match
with the selected target. Unknown IDs, missing authoritative records, and
cross-target probes therefore share the same not-found response and do not
leak existence across tenants.

Client callers that manage a non-default target use the additive
`*_for_tenant` credential and operation APIs. The legacy methods remain ABI
compatible and select `__wr_default` as their target, so they fail closed
rather than silently borrowing the authenticated client's tenant for a
non-default management operation. Issue already carries its target explicitly
in `WylClientServiceCredentialIssueRequest.tenant_id`.

Service-token exchange accepts only a strict JSON credential ID/secret body
over actual loopback transport. Non-loopback requests, malformed or oversized
bodies, unknown credentials, and limiter denials fail closed with sanitized
responses. A successful response contains only the short-lived access token;
session metadata, tenant data, credential secrets, and raw request material are
never echoed.

### Service bearer decision authority

The sole bearer resolver retains its service-authentication READ lease whenever
the bearer resolves to a service credential. It takes no endpoint argument and
so does not decide this per handler: after the signed token, live service
session, access-token record, ACTIVE registry tuple, and tenant have matched
exactly, it hands the lease to the caller on the auth context. Only the human
bearer tail and the session-token path release inside the resolver, and human
decisions keep using the public `wyl_decide()` path.

What confines the retained lease is therefore the shape of its use rather than
a per-endpoint decision, and that shape is gated by
`tools/check-daemon-bearer-resolver-structure.py`: `service_lease` is assigned
in exactly one place, the resolver; its address reaches exactly one consumer,
`decide_authenticated_request`, which transfers it into a request-unique,
one-shot decision authority that holds it through request-context insertion,
policy query, context removal and terminal release; and it has exactly one
last-resort terminal release, in the auth context destructor, for a request
that ends without reaching that consumer.

Service lifecycle state is projected from the durable `service_principals`
records into `service_principal_state`; it is never borrowed from the human
`principal_states` table. The resolver authority contributes an ephemeral
`service_request_auth(context, subject, tenant)` row. Signed policy permits a
service decision only when that exact subject is active, the requested
permission is in `approved_data_plane_permission`, the subject has the
permission, and the credential tenant is the requested scope. Cleanup failure
poisons the engine pair, and terminal-release uncertainty leaves the response
DENY.

On the HTTP wire, `session_token` remains the legacy `/decide` name for the
policy scope; a service request must set it to the credential tenant. An
invalid bearer returns 401. A valid service bearer with no matching role, a
foreign scope, or a control-plane permission returns 200 with DENY. Granting a
matching role can change the same token to ALLOW; revoking that role changes it
back to DENY. A service subject passed directly to public `wyl_decide()` has no
resolver-created authority and therefore cannot use this service-only rule.

Each successful exchange carries an owned copy of its exact service authority
identity (`session_id`, `jti`, credential ID and generation, principal, tenant,
and expiry) from activation through the Soup response lifecycle. A failure
after activation but before response handoff, Soup's `request-aborted`
terminal signal, or destruction of an activated response identity that received
neither terminal signal retires only that exact registry/session/access tuple.
The last case is the fail-closed fallback for transports that discard a message
without reporting a terminal signal. An already-absent exact tuple makes
repeated cleanup harmless; a partial, cross-linked, or mismatched tuple leaves
all observed state intact and latches service authentication unavailable.
Soup's `request-finished` signal means the response was written and preserves
the live tuple until explicit invalidation, key rotation, expiry retirement, or
daemon shutdown.

An aborted delivery does not refund its rate-limit permit and is not an
idempotent exchange checkpoint. A caller retry performs a new exchange with a
distinct session ID and JTI. Service bearer state is process-local, so restart
does not restore an earlier live tuple; normal expiry retirement removes the
registry entry and both live companions together. The successful JSON response
buffer remains length-owned by the daemon while Soup writes it and is
zeroized before release on both finished and aborted response paths.

Client code that carries a credential secret or access token must first accept
only a canonical literal loopback URL. Hostnames, ambiguous numeric addresses,
IPv4-mapped IPv6, zone identifiers, userinfo, non-loopback authorities, and
authority-changing redirects are rejected before the secret-bearing request is
sent. Client cleanup wipes only buffers owned by the client; transport-library,
kernel, and caller-owned immutable buffers are outside that guarantee.

The daemon listener is loopback-only, so a non-loopback peer cannot reach the
production route at the network layer. The HTTP smoke suite therefore covers a
successful production-route exchange and exercises the core transport guard
with a non-loopback marker for the denial path. Fence uncertainty is represented
by the canonical `not_committed_terminal` reconciliation outcome; there is no
separate uncertainty enum.

### Escrow credential handoff wire contract

The escrow issue/rotate handoff is exposed on two of the management routes
above: issue is `POST /service-principals/{subject}/credentials` and rotate is
`POST /service-credentials/{id}/rotate`. Both write the one-time secret to an
owner-only publication file on the daemon host, so both are loopback-only: a
non-loopback transport is rejected with `403 service_credential_denied` before
any authentication, state read, or write. The caller must hold
`wr.service_credential.manage` for the request tenant. See ADR 0001 for the
design and the durable state machine behind this contract.

The request body is a strict JSON object; every field value is a quoted string
on the wire. Issue requires `version` (`"1"`), `tenant` (equal to the selected
target tenant), `request_id`, `destination`, and `expires_at_us`. The subject
path identifies the principal but does not encode or establish the target
tenant. Rotate requires `version`, `request_id`, `destination`, and
`expires_at_us`; its principal and authoritative target tenant come from the
retired credential. `request_id` is exactly 27 ASCII-alphanumeric characters
(a canonical KSUID); it is the idempotency key. `destination` names the escrow publication
target and `expires_at_us` is a quoted decimal count of microseconds since the
epoch that must parse and be strictly greater than zero. Both `destination` and
`expires_at_us` are mandatory: the daemon never server-recomputes an expiry.

A successful call returns `200` with a non-secret JSON receipt of the exact
shape `{state, request_id, credential_id, generation, destination,
publication_receipt_id, delivered}`. `generation` is a JSON number and
`delivered` is a JSON boolean; the remaining fields are strings or `null`. The
credential secret is never placed in the response, an error body, or a log.
`state` is one of the eight lowercase operation-state names: `prepared`,
`server_committed`, `publication_planned`, `publication_prepared`,
`file_published`, `cleanup_required`, `operator_action_required`, and
`terminal`. `delivered` is `true` only at the `terminal` state whose reason is
a durable file publication; every operator-action and non-delivery terminal
outcome reports `delivered` as `false`.

Delivery is at-least-once and idempotent by `request_id`: a repeated
`request_id` returns the same operation, credential, and receipt and never
mints a second secret. It is not observably exactly-once. A crash after the
publication file is durably written but before its receipt is durable can leave
a correct owner-only file without a durable acknowledgement, so a caller may
observe the receipt zero or one time per attempt; the durable file and the
policy authority, not the response, are the source of truth.

The handoff module return code maps onto the HTTP status and error code as
follows:

| Return code | HTTP status | Error code |
| --- | --- | --- |
| `WYRELOG_E_OK` | 200 | (JSON receipt) |
| `WYRELOG_E_NOT_FOUND` / `WYRELOG_E_BUSY` | 503 | `service_credential_unavailable` |
| `WYRELOG_E_POLICY` | 409 | `service_credential_conflict` |
| `WYRELOG_E_INVALID` | 400 | `invalid_service_credential_request` |
| `WYRELOG_E_AUTH` | 403 | `service_credential_denied` |
| any other | 500 | `service_credential_failed` |

An unconfigured deployment (no owner-only operation or publication root) reports
`503 service_credential_unavailable` and touches no state.

### Authority-retirement replay contract

Principal disable, credential revoke, tenant seal, and credential rotate use a
caller-owned canonical request ID to recover a committed result after response
loss. Principal disable and tenant seal accept exactly this JSON object, with a
maximum body size of 1024 bytes:

```json
{"version":"1","request_id":"<canonical 27-character KSUID>"}
```

Missing, empty, duplicate, additional, wrongly typed, unsupported-version, and
noncanonical fields are rejected with HTTP 400. Credential revoke retains the
same strict body contract; rotate retains its escrow handoff body and operation
receipt. The caller request ID is authority identity. It is deliberately
different from the server-generated `X-Wyrelog-Request-Id` response header,
which correlates one HTTP attempt and is also used for that attempt's policy
decision audit.

Every attempt performs current authorization before receipt lookup. An exact
authorized retry returns the original typed result without another lifecycle
event, audit/outbox intention, authority mutation, or registry barrier. A new
key against an already terminal object records a separately authorized and
audited no-op. Reuse of a key for a different operation, target, actor,
fingerprint, or version returns HTTP 409. Tenant seal receipts also bind the
tenant lifecycle and sealed generations: after unseal or another transition,
an old seal key returns `409 tenant_seal_superseded` with recorded and current
lifecycle/sealed generations and never reseals the tenant.

Tenant lifecycle states `active`, `sealing`, and `unsealing` require the #549
drain coordinator and return `503 tenant_lifecycle_coordination_required` from
the seal route without mutation. Other authority coordination failures return
503, while receipt, event, audit, or terminal-row structural failures return
500. A 500 or 503 must not be retried with a new key: preserve the original key,
restore authority availability as required, and retry so the durable receipt
can classify the result.

## Private service credential operation retirement

Terminal handoff journal retirement is private library work. It has no daemon
route, `wyctl` command, public API, timer, or scheduling policy. #517 delivered
the public loopback issue/rotate ingress, but retirement itself stays private
and operator-driven; automatic retirement scheduling is out of scope.

Eligibility requires an exact version-6 `TERMINAL` snapshot: `FILE_PUBLISHED`
with no remediation marker or the exact prior `RESUME` marker, or
`OPERATOR_REVOKE_AND_WIPE` with its exact revoke marker. Version 5,
`NOT_COMMITTED`, and every nonterminal state are excluded. The trusted clock
must be at least 30 days beyond the greatest timestamp among the journal and
all referenced delivery, remediation, and revoke-event provenance.

The purge coordinator preserves this order for one original request id:
lifecycle lock, service-authority write lease, short authority transaction,
permanent receipt, transaction completion, then exact anchored journal
deletion and synchronization. The authority transaction either validates an
existing receipt or records and commits the exact non-secret provenance and
dual escrow absence. No journal filesystem read or deletion occurs while that
transaction is active. The lifecycle lock and write lease remain held through
deletion; exact storage deletion takes the shorter operation lock inside that
boundary.

Crash recovery is receipt first. A validated permanent receipt supplies the
exact delete expectation, and only that path may treat an already missing
snapshot as success. If no receipt exists, the coordinator must load and
validate an eligible version-6 terminal snapshot, obtain the authority receipt,
and confirm its replay before deleting anything.

Production operation creation must use the retirement-guarded begin path. It
checks the permanent receipt while holding the same lifecycle lock and write
lease used by purge, so a burned request id cannot create or replay a journal.
The raw locked begin helper is restricted to the retirement coordinator and
explicit test friends; it is not a production ingress contract.

Permanent retirement receipts and lifecycle or operation lock artifacts must
never be manually updated or deleted. There is no supported administrative
reset that makes a retired request id reusable.

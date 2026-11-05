<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Service-Credential Threat Model (v1)

This document states the security boundaries, the deliberate v1 non-goals, and
the accepted limitations of the service-credential subsystem. It is a companion
to the operator runbook's "Service Credential Handoff" and "Key Rotation"
sections (`docs/operator-runbook.md`) and to the platform evidence matrix
(`docs/service-credential-platform-support.md`). Read those for the operator
procedures and for what kind of proof each platform provides; read this for what
the subsystem intentionally does **not** defend against and why.

The guiding principle is least authority: a service credential is a
data-plane-only principal whose live authorization is decided at `/decide`
against current policy, whose management is reserved to human SYSTEM admins in
`__wr_default`, and whose entire surface is loopback-only and file-mediated.

Owner-issued data credentials (#1341) are a separate credential kind with their
own boundaries. They are described under "Owner-issued data credentials" below.
The non-goals and the custody section below describe service credentials; where
one of them also binds data credentials, or is replaced for them, the data
credential section says so. The host trust boundary, loopback confinement, the
KeyProvider trust anchor and the in-process-memory caveat apply to both kinds.

## V1 non-goals

These are out of scope for v1 by design, not defects. Each is a bounded,
documented limitation.

- **No workload refresh token.** A service token has a fixed, short server-side
  TTL and no refresh path. A workload re-exchanges its credential to obtain a
  new token. There is intentionally nothing that can silently extend or renew a
  live token's lifetime.
- **No secret recovery, redisplay, or replay.** The 32-byte credential secret is
  returned exactly once, out-of-band, into the owner-only escrow document. It is
  never re-derivable, re-displayable, or replayable from the authoritative
  store, which persists only a versioned salted verifier and lifecycle metadata.
  A lost secret is rotated, not recovered. A data credential's secret is never
  redisplayed or recovered either, but it is delivered differently; see
  "Secret delivery" under "Owner-issued data credentials".
- **No tenant-local management.** Principal and credential management is a human
  SYSTEM capability bound to the management resolver tenant `__wr_default`. There
  is no tenant-local management authority; a tenant cannot self-administer its
  own service principals. This non-goal does not cover data credentials. A
  tenant owner issues, lists, rotates and revokes those for their own tenant, so
  that a program can use the tenant's data without an administrator creating a
  principal for it. Service principals and service credentials stay
  SYSTEM-managed.
- **No remote / proxy / TLS / mTLS / Unix-socket transport.** The management
  routes and the `/auth/service-token` exchange are loopback-only. Peer and
  listener addresses are validated against a canonical literal loopback address,
  and `Forwarded` / `X-Forwarded-*` are never trusted. There is no supported
  network, reverse-proxy, TLS/mTLS, or Unix-domain-socket transport in v1.
- **No automated rotation.** Credential and KeyProvider-root rotation are
  operator-initiated. Nothing rotates on a schedule or on its own.
- **No multi-root auto-recovery at normal store open.** A normal single-root
  store open never auto-recovers an interrupted key rotation. Recovery is
  explicit (`wyctl key recover` / `resume`) and requires both provider roots;
  see the corrected disclosure below.
- **No cryptographic wipe of SQLite internal page memory.** The wyrelog-owned
  decrypted image buffer is zeroed on close, but the subsystem does not and
  cannot scrub SQLite's own internal page cache or other process-memory copies
  the library may retain. This is the accepted in-process-memory caveat below.

## Custody and transport boundaries

The subsystem's confidentiality rests on local file custody and loopback
confinement, not on a network security layer:

- **Escrow documents (`0600`).** The one-time secret is delivered only to the
  owner-only escrow document under `--credential-publication-root`. Anyone who
  can read that file before the workload consumes it holds the credential secret;
  protect it like the KeyProvider key file. It is never written to stdout, argv,
  or a query parameter. This applies to service credentials. A data
  credential's secret has no escrow document.
- **Owner-only roots (`0700`).** `--credential-publication-root`,
  `--operation-root`, and the fact root are each `0700` and must be mutually
  disjoint and disjoint from the policy/audit/event-spool paths; overlap fails
  startup closed. This keeps a delivered secret or a durable operation journal
  from sharing a directory with another store.
- **Loopback confinement.** Management and exchange trust only a real loopback
  transport. An attacker without local host access and without the ability to
  reach the loopback listener cannot present, mint, or manage credentials. The
  threat model assumes the host and its filesystem permissions are the trust
  boundary.
- **KeyProvider trust anchor.** The encrypted policy store, sealed under the
  KeyProvider, is the authority for verifier and CVK material. Whoever controls
  the KeyProvider key and the store path controls credential verification.

## Owner-issued data credentials (#1341)

**Status: partly implemented.** This section records the boundary that the
implementation units must build: #1473 (storage), #1474 (management routes),
#1475 (exchange and per-use checks), #1476 (lifecycle revocation) and #1477
(`wyctl` and runbook). Storage, the management routes, the exchange, the
per-use checks and lifecycle revocation have landed: a tenant owner can issue,
list, rotate and revoke data credentials, a program can exchange one at
`/auth/service-token` and use its bearer on the data routes, and the lifecycle
events below revoke them. A credential's last-used time is the time
of its last exchange. An exchange of an unknown credential id is refused
sooner than one with a wrong secret, so its timing can tell whether an id
exists; ids are not secrets, and the exchange limiter applies. Where the
shipped behaviour differs from this section, #1477 corrects this document.

### Why the boundary moves

Today a program cannot read or write a tenant's facts:

- A human bearer can, but obtaining one needs `/auth/login` and interactive
  TOTP MFA.
- A service credential cannot. A `svc:` principal's authority is confined to the
  data-plane allowlist in `templates/access/bootstrap.dl`
  (`approved_data_plane_permission`: `wr.stream.read`, `wr.stream.list`,
  `wr.svc.read_decision`). Every fact and datalog permission is control-plane,
  so a service bearer is denied them even when a role grants them, as
  `wr.svc_agent` does for the fact mutation permissions.

A data credential lets the tenant's owner give a program a fixed, narrow set of
data operations. It is a new credential kind, not a new use of service
principals.

### Credential kind

- **Bound at issuance** to `(tenant, issuer, operations, graphs, expiry)`. The
  tenant is the tenant that issued it. The issuer is the owner who issued it.
  `graphs` is optional; when it is empty the credential covers every graph in
  the tenant. A named graph is bound by its graph id, and a scope is never
  emptied into "every graph". Graphs leave a tenant today only when the tenant
  is deleted, which revokes every credential in it. Any future operation that
  removes a single graph must revoke, in the same transaction, every credential
  whose scope names that graph, so that a later graph with the same id is never
  covered.
- **Not a principal.** It has no `svc:` subject, is never granted a role, and is
  never named in `approved_data_plane_permission`. The data-plane allowlist for
  ordinary service principals does not change.
- **Its own identity.** A bearer obtained from a data credential authenticates
  as that credential, under an identity distinct from every human and `svc:`
  subject. It never authenticates as its issuer. The issuer's subject id is
  consulted only for the issuer check at use (check 5 below). So a route that
  derives authority from the actor, such as ownership comparison against
  `tenants.owner_subject_id` or a `/decide` call on the actor, never sees the
  issuer through a data credential.
- **Immutable scope.** Nothing widens a credential after issuance. Changing the
  operations or graphs means issuing a new credential. Rotation keeps the scope
  and the original expiry, and replaces only the secret, so rotating never
  extends a credential's life. Rotation is owner-initiated; nothing rotates a
  data credential automatically.
- **Stored as a verifier.** The store keeps a versioned salted verifier and
  lifecycle metadata, as for service credentials, and never the secret.

### Operations

The owner chooses any combination of five operations. Each one is exactly the
permission the existing route already checks:

| Operation | Permission | Routes |
|---|---|---|
| `query` | `wr.datalog.query`, `wr.fact.read` | `POST /datalog/...`; `GET /facts/verify` |
| `infer` | `wr.datalog.infer` | none yet; rule packs are stored but not evaluated |
| `insert` | `wr.fact.append` | the facts `:append` route |
| `delete` | `wr.fact.retract` | the facts `:retract` route |
| `update` | `wr.fact.update` | the facts `:update` routes |

The check is per operation. An `insert`-only credential is refused on retract
and update, although all three are fact mutations.

### Never reachable

A data credential never authorizes any action outside the table above,
whatever its operations. In particular:

- `wr.fact.forget` (irreversible erasure) and `wr.fact.repair`;
- schema and rule-pack registration (`wr.schema.manage`), graph management
  (`wr.graph.manage`) and quota configuration;
- policy, audit, key and tenant actions;
- every service-principal, service-credential and data-credential management
  action, so a data credential can never issue, rotate or revoke a credential;
- the service data-plane permissions (`wr.stream.read`, `wr.stream.list`,
  `wr.svc.read_decision`);
- every other permission.

### Who manages them

- **Issue and rotate:** only the tenant's current owner
  (`tenants.owner_subject_id`, #1338). The owner needs a live, MFA-assured
  human session with the usual guard context. The authority comes from
  ownership. Neither a SYSTEM admin nor a holder of tenant-scoped
  `wr.system_admin` can issue on the owner's behalf. An owner who also holds
  SYSTEM authority issues as the owner. A SYSTEM admin can still become the
  owner through `/tenants/transfer-owner` and then issue; that transfer is
  audited and revokes the previous owner's credentials. Rotation re-checks the
  issuer requirements of issuance (see below), and only an active credential
  can be rotated, so a revoked one stays revoked. A sealed tenant refuses issue
  and rotate. The owner check and the credential insert run inside the same
  policy write, so an issue racing an ownership transfer either completes
  before the transfer, and is revoked by it, or is refused.
- **List and revoke:** the owner, and a SYSTEM admin for incident response. Here
  SYSTEM admin means a principal allowed `wr.tenant.manage` on `__wr_default`,
  the capacity the existing tenant routes already recognize. Both stay
  available while the tenant is sealed. A listing shows id, operations, graphs,
  issuer, created, expires and last-used time, and state. It never shows the
  secret, salt or verifier.
- **Never a credential's bearer:** a `svc:` bearer and a data-credential bearer
  are refused on every management route.

### Never more than its issuer

- **At issuance,** the owner must currently hold, in the tenant, every
  permission mapped to each requested operation (both of them for `query`), and
  each named graph must exist in the tenant.
- **At every use,** the request is refused unless all of these hold:
  1. the credential is active and unexpired;
  2. the request's tenant is the credential's tenant;
  3. a graph-addressed request names a graph in the credential's scope, when
     the scope is set;
  4. the route's operation is in the credential's operations;
  5. the issuer is still the tenant's owner, is not disabled, and currently
     holds, in the tenant, the permission the route checks;
  6. the tenant is not sealed.

  Revoking an owner's own permission therefore narrows their credentials on the
  next request. A sealed tenant refuses every operation, and unsealing restores
  the credentials that have not expired or been revoked meanwhile.
- **Lifecycle events revoke durably.** Ownership transfer revokes the previous
  owner's credentials in the tenant. Disabling or deleting a user revokes every
  credential that user issued. Deleting a tenant revokes every credential in
  it. Each revocation commits in the same transaction as the event, and the
  event fails if the revocation fails. A replay of an event that already
  committed revokes nothing, so a former owner replaying an old transfer
  cannot end credentials issued since. A revoked credential's bearer is
  refused at its next request, because every request looks the credential up.
  Credentials that have expired but are still active are revoked too, so the
  list shows why they ended. The per-use owner check stays as defence in depth
  against any owner change that does not go through a transfer.

### Use

A program exchanges the credential for a short-TTL bearer bound to the
credential id, through `/auth/service-token` or a sibling route. As with
service tokens, there is no refresh token: the program exchanges again.

- The program presents the secret only in the body of the exchange request,
  never in a URL, a query parameter, a header, or argv. The daemon never logs
  it from the request.
- The existing service-token exchange rate limiter applies to data-credential
  exchange.
- There is no rate limit on the query routes today, for any caller. Fact
  writes are limited only by the tenant's `write_rate` fact quota, which is off
  until an operator sets it (operator runbook, "Tenant Resource Quotas"). A
  data-credential bearer is limited exactly as a human bearer is. This is
  accepted for this kind.
- Writes count against the tenant's fact quotas, including `write_rate`,
  exactly as human writes do. Those quotas are shared with the tenant's human
  writers.

### Secret delivery

The secret is returned exactly once, in the body of the authenticated issue or
rotate response, over the same loopback-only listener as every other route.
There is no escrow document, because a tenant owner need not have shell access
to the daemon host.

- The daemon zeroizes every copy it owns once the response is sent: the
  generated secret, its encoded form and the response body. Copies held in the
  HTTP library's transport buffers fall under the in-process-memory caveat
  below. The daemon never writes the secret to a log line, an audit row, a
  header, or a later response.
- A replayed issue or rotate request, for example one repeating an idempotency
  key, never returns the secret again. It may report the credential id and
  state only.
- If the issue response is lost, the credential still exists and counts
  against the caps. The owner lists the tenant's credentials and revokes the
  one whose secret never arrived, identified by its created time and scope and
  by never showing a last-used time.
- `wyctl` writes it to the file named by `--output`, created exclusively with
  mode `0600`, and refuses to overwrite an existing file. It never prints the
  secret to stdout or stderr and never takes it in argv. It zeroizes its own
  buffer after writing.
- A lost secret is rotated, never redisplayed.

The response travels over loopback inside the host trust boundary described
above, so a process that can read the loopback traffic or the daemon's memory
is outside this boundary, as it is for every other secret here.

### Blast radius and limits

Before this kind existed, no program identity could write a fact. A leaked data
credential therefore widens what a leak can do: until it expires or is revoked,
whoever holds it may perform its operations on its graphs, from any process
that can reach the loopback listener. It cannot erase, repair, change schema,
manage graphs or reach any control-plane action. Because the tenant's fact
quotas are shared, a leaked write-capable credential can also exhaust them and
so block the owner's own writes. Revoking it stops further consumption.
`write_rate` recovers as its bucket refills, but rows and bytes committed under
`logical_bytes` stay charged: nothing releases committed logical usage today,
not even `forget`, so the owner's writes stay blocked until an operator raises
that limit. Every
operation it performs is audited with the credential id and its
issuer, so the owner or a SYSTEM admin can find and revoke it.

The limits bound that exposure:

- **Mandatory expiry.** Every data credential has an expiry, capped by a
  deployment-wide maximum. The default maximum is 90 days.
- **Per-tenant caps.** At most 32 live data credentials per tenant by default,
  of which at most 8 may be write-capable (holding `insert`, `delete` or
  `update`). Revoked and expired credentials do not count.
- **Fact quotas.** The tenant's existing fact quotas apply to writes made
  through a credential. An operator who issues write-capable credentials may
  set `write_rate` to bound how fast a leaked one can write.

The expiry maximum and the caps are deployment configuration. An operator may
lower or raise them, and the store enforces whatever values are configured.
The fact quotas stay per tenant, configured as they are today.

### Audit

Issue, rotate and revoke are audited with the actor, issuer, tenant,
operations, graphs and credential id. A lifecycle revocation writes one audit
row per credential, with action `data_credential_lifecycle_revoke`: the event's
actor as subject, the credential's tenant as resource, the credential id as
origin and the event's request id. Its summary carries the credential's scope
as the route audits render it, then the acting capacity, the reason
(`ownership_transfer`, `issuer_disabled`, `issuer_deleted` or
`tenant_deleted`), the event's action and the event's audit id. A user delete
revokes the user's credentials under its own request first; each tenant it
deletes then revokes whatever else is still active there under that tenant
delete's request. A tenant delete revokes before it purges, so these audit rows
are the record of credentials the purge removed. A lifecycle revocation is
recorded at the event's time, or at the credential's creation if that is later,
so a clock that stepped back cannot make the event fail. Every data operation
made through a credential is attributed to the credential id and its
issuer.

### Interaction with tenant deletion

A data credential is not "another subject's permission" under the tenant-delete
refusal rule (#1340). It never blocks a tenant delete, and it is revoked with
the tenant, as the owner's own permissions are.

### Transport

The loopback-only rule above applies unchanged. Until a remote transport lands
(#1342), a program using a data credential must run on the daemon host.

## Accepted disclosures

### Encrypted stores operate in memory; no plaintext on disk (#363)

Encrypted policy stores operate on an in-memory SQLite connection: the
AEAD-authenticated canonical file is read through the retained parent directory
descriptor, deserialized into a `:memory:` connection, and re-serialized and
re-encrypted on persist. No plaintext database, journal, WAL/SHM, or temporary
artifact is ever created on disk
(`wyrelog/policy/store.c`: `:memory:` open at store.c:7205 / store.c:8599,
deserialize of the decrypted buffer at store.c:7214, canonical read through the
retained parent directory descriptor at store.c:8534-8538, serialize-and-encrypt
on persist at store.c:7487-7548). A legacy `.wyrelog-clear` file is swept if
present but is never created (best-effort `unlinkat` at store.c:8509 and on close
at store.c:8708; the plaintext work-file writers are defined but never called).
The wyrelog-owned decrypted image buffer is zeroed on close (`sodium_memzero`
at store.c:8698-8704). Provider-backed **plaintext** file stores are
unsupported and fail closed with a policy error *before* any SQLite open
(store.c:8584, backed by an always-false pinned-backend probe).

The accepted limitation: this zeroes only the application-owned decrypted image
buffer. It is **not** a claim that the decrypted data is wiped or scrubbed from
all process memory, and it provides **no** cryptographic erasure of SQLite's
internal page cache. An attacker who can read the daemon's live process memory
is outside this boundary. (Line numbers reflect the merged tree in this
worktree; the behavior, not any single line, is the contract.)

### Key rotation recovery is explicit and fails closed (#364)

Interrupted KeyProvider-root rotation is crash-recoverable, but recovery is
**explicit, not automatic**. A normal single-root store open does **not**
auto-recover an interrupted rotation. An operator must run `wyctl key recover`
(or its alias `wyctl key resume`) with both provider roots available, after
classifying the state with `wyctl key status --store …`. Recovery either
resumes an OLD-root store forward to the intended NEW generation or recognizes
an already-committed NEW result and completes only durable cleanup. When the
state is **AMBIGUOUS** — neither or both roots authenticate — recovery
deliberately **fails closed** without changing any canonical byte and **retains
both roots**. The canonical rename is the linearization point: there is no
rollback after it. These classifier and recovery paths are unit/library-proven
(`tests/test-policy-store-service-cvk.c`), not driven by a packaged e2e; the
packaged rotation e2e drives only `wyctl key rotate`.

## In-process-memory caveat

The subsystem protects secrets at rest (encrypted store, `0600`/`0700` custody)
and in transit (loopback confinement, secret never on argv/stdout/query). It
does **not** defend against an adversary who already reads the daemon's live
process memory. While secrets are held in locked, zeroized daemon memory where
the implementation controls the buffer, copies that libraries such as SQLite
keep in their own internal caches are outside the subsystem's control (see #363
above). Live-process-memory disclosure is an accepted out-of-scope threat for
v1.

## Cross-references

- Operator procedures: `docs/operator-runbook.md` — "Service Credential
  Handoff" and "Key Rotation" (including "Interrupted rotation recovery").
- Evidence by platform and proof kind:
  `docs/service-credential-platform-support.md`.
- Criterion-to-evidence map: `docs/service-credential-traceability.md`.

> Documentation follow-up (flag only): `docs/developer-lifecycle.md:81-90`
> carries older prose that predates the in-memory encrypted-store behavior
> described under #363 above and should be reconciled in a separate change. This
> threat model describes the implemented in-memory behavior, which is
> authoritative.

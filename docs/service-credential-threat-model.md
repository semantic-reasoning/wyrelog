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
  A lost secret is rotated, not recovered.
- **No tenant-local management.** Principal and credential management is a human
  SYSTEM capability bound to the management resolver tenant `__wr_default`. There
  is no tenant-local management authority; a tenant cannot self-administer its
  own service principals.
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
  or a query parameter.
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

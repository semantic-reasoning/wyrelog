<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Service-Credential Criterion-to-Evidence Traceability (#352 V1)

This document maps every claim in the #352 V1 product contract to the stable
evidence that proves it, and to the CI gate that keeps that evidence green. It
satisfies the #361 close condition ("maps every product and security claim in
the umbrella to exact passing evidence and documents the accepted #363/#364
limitations"). For operator procedures see `docs/operator-runbook.md`; for the
accepted limitations and non-goals see `docs/service-credential-threat-model.md`;
for what kind of proof each platform provides see
`docs/service-credential-platform-support.md`.

## How to read the labels

Every row is labeled **Runtime** or **Build/Unit**, consistent with the platform
evidence matrix's non-negotiable rule that a build-only or unit result is never
presented as runtime proof, and `skip != pass`.

- **Runtime** — proven by a packaged, encrypted, end-to-end `meson test`
  registration that boots a real daemon, provisions and encrypts a real store,
  and exercises the live path. These run on **Linux** only (the sole
  packaged-runtime platform); macOS and Windows are build-only for the packaged
  lifecycle.
- **Build/Unit** — proven by an in-process C unit executable or a static
  source/config consistency checker. Real proof of the code path, but not a
  packaged runtime guarantee of the live lifecycle.

Stable evidence names used below:

| Short name | Kind | Path / registration |
|---|---|---|
| `service-credential-lifecycle-e2e` | Runtime (Linux) | `tests/check-service-credential-lifecycle-e2e.sh` |
| `service-credential-zero-survivor-e2e` | Runtime (Linux) | `tests/check-service-credential-zero-survivor-e2e.sh` |
| `service-credential-rotation-e2e` | Runtime (Linux) | `tests/check-service-credential-rotation-e2e.sh` |
| `service-credential-leak-scan-e2e` | Runtime (Linux) | `tests/check-service-credential-leak-scan-e2e.sh` |
| `service-credential-publication-fault-e2e` | Runtime (Linux; fault-injection build) | `tests/check-service-credential-publication-fault-e2e.sh` |
| `service-credential-platform-matrix` | Build/Unit (static consistency checker; runs on every runner) | `tests/check-service-credential-platform-matrix.py` |
| `service-credential-operation-coordinator-execute` | Build/Unit | `tests/test-service-credential-operation-coordinator-execute.c` |
| `policy-store-service-cvk` (rotation-recovery cases) | Build/Unit | `tests/test-policy-store-service-cvk.c` |
| `bootstrap.dl` (signed workload-safe permission plane) | Build/Unit (frozen signed Datalog artifact) | `templates/access/bootstrap.dl` |

## CI gates

- **All Runtime rows** are gated by the **`service-credential-e2e`** job in
  `.github/workflows/ci-main.yml` and `.github/workflows/ci-pr.yml`
  (`runs-on: ubuntu-latest`). That job configures
  `-Denable_client=enabled -Denable_fact_store=enabled -Denable_audit=enabled
  -Denable_fault_injection=enabled -Dduckdb_source=prebuilt` and runs the five
  packaged e2e tests plus `service-credential-platform-matrix` by name.
- **`service-credential-platform-matrix`** additionally runs **unconditionally
  on every platform's CI** (it fails loud on any drift between the platform
  classification, the meson gating, and the workflow definitions), so a
  build-only platform can never silently masquerade as runtime.
- **Build/Unit rows** (`service-credential-operation-coordinator-execute`,
  `policy-store-service-cvk`) run in the standard `meson test` suite CI, not in
  the dedicated `service-credential-e2e` job.

## Identity and authority

| #352 V1-contract claim | Evidence | Runtime / Build-Unit | CI gate |
|---|---|---|---|
| Human and service subjects cannot collide; service subjects use a reserved validated namespace (`svc:`). | `service-credential-lifecycle-e2e`; `policy-store-service-cvk` (subject-namespace checks) | Runtime + Build/Unit | `service-credential-e2e`; standard `meson test` |
| A credential row is the sole tenant authority during exchange; the exchange request carries no tenant and has no default-tenant fallback. | `service-credential-lifecycle-e2e` (tenant-A allow / tenant-B `tenant_denied`) | Runtime | `service-credential-e2e` |
| A zero-role service credential authenticates but is unauthorized until a workload-safe tenant-scoped role is granted. | `service-credential-lifecycle-e2e` (zero-role `/decide` deny -> grant -> allow) | Runtime | `service-credential-e2e` |
| Live role grant/revoke changes the authorization result of the same unexpired token immediately. | `service-credential-lifecycle-e2e` (grant/revoke flips same token at `/decide`) | Runtime | `service-credential-e2e` |
| Service principals are data-plane-only; direct or transitive control-plane permissions are rejected atomically. | `bootstrap.dl` (`approved_data_plane_permission` allowlist + control-plane partition); enforcement merged (#356), custodian-signed release candidate pending (#367); `service-credential-lifecycle-e2e` (safe role grant path) | Build/Unit + Runtime | standard `meson test`; `service-credential-e2e` |
| Service principals cannot bootstrap, enroll TOTP, use human login/refresh/skip-MFA, manage credentials, or obtain system/policy/tenant/audit/security/key authority. | `bootstrap.dl` (control-plane partition); `service-credential-lifecycle-e2e` | Build/Unit + Runtime | standard `meson test`; `service-credential-e2e` |

## Credential and key material

| #352 V1-contract claim | Evidence | Runtime / Build-Unit | CI gate |
|---|---|---|---|
| Public IDs use the strict versioned `wlc_<KSUID>` contract. | `service-credential-lifecycle-e2e` (receipt `credential_id=wlc_…`) | Runtime | `service-credential-e2e` |
| The 32-byte secret is returned exactly once and never accepted through argv or query parameters. | `service-credential-lifecycle-e2e`; `service-credential-leak-scan-e2e` | Runtime | `service-credential-e2e` |
| Only the versioned salted verifier and lifecycle metadata persist in the authoritative encrypted policy store. | `policy-store-service-cvk`; `service-credential-leak-scan-e2e` | Build/Unit + Runtime | standard `meson test`; `service-credential-e2e` |
| One random sealed CVK is generated for a fresh store; the plaintext CVK exists only in locked, zeroized daemon memory. | `policy-store-service-cvk` | Build/Unit | standard `meson test` |
| Normal KeyProvider root rotation re-seals the identical CVK and preserves verifier bytes and credential usability. | `service-credential-rotation-e2e` (`status=rotated`, verifier byte-identical, CVK re-sealed); `policy-store-service-cvk` (rotation-recovery cases) | Runtime + Build/Unit | `service-credential-e2e`; standard `meson test` |
| Secret, plaintext CVK, JWT, `Authorization` body, and duplicate verifier material never enter facts, audit payloads, logs, errors, CLI output, recovery journals, or unrelated columns. | `service-credential-leak-scan-e2e` | Runtime | `service-credential-e2e` |

## Session and bearer contract

| #352 V1-contract claim | Evidence | Runtime / Build-Unit | CI gate |
|---|---|---|---|
| Service exchange creates the normal live session and access-token state with exact service auth method, credential ID/generation, subject, tenant, session ID, and jti. | `service-credential-lifecycle-e2e`; `service-credential-operation-coordinator-execute` | Runtime + Build/Unit | `service-credential-e2e`; standard `meson test` |
| The existing `resolve_bearer_session()` path is the sole bearer resolver. | `service-credential-lifecycle-e2e` (exchange resolves through the same bearer path) | Runtime | `service-credential-e2e` |
| The resolver accepts a service pair only when the exact registry entry is `ACTIVE`; `PENDING`, `REVOKED`, absent, or mismatched entries fail closed. | `service-credential-zero-survivor-e2e` | Runtime | `service-credential-e2e` |
| V1 service tokens have a fixed short server-side TTL and no workload refresh token. | `service-credential-lifecycle-e2e` (no-refresh assertion) | Runtime | `service-credential-e2e` |

## Management and transport

| #352 V1-contract claim | Evidence | Runtime / Build-Unit | CI gate |
|---|---|---|---|
| Management is available only to a live human bearer bound to `__wr_default` in the SYSTEM profile, authorized by the dedicated management permissions (self-arm, #729). | `service-credential-lifecycle-e2e` (self-arm then manage) | Runtime | `service-credential-e2e` |
| Management may target an active tenant only through the explicit cross-tenant control-plane contract. | `service-credential-lifecycle-e2e` | Runtime | `service-credential-e2e` |
| Issuance, rotation, revoke, metadata, operation-reconciliation, and `/auth/service-token` are loopback-only; peer/listener addresses validated; `Forwarded` / `X-Forwarded-*` never trusted. | `service-credential-lifecycle-e2e`; `service-credential-platform-matrix` | Runtime + Build/Unit | `service-credential-e2e`; every-runner matrix |
| Every Service Credential route stays unregistered until the complete route set is published atomically (#359). | `service-credential-platform-matrix` (source/config consistency); `service-credential-lifecycle-e2e` (routes live only in the packaged daemon) | Build/Unit + Runtime | every-runner matrix; `service-credential-e2e` |

## Umbrella acceptance / before-closure

| #352 close condition | Evidence | Runtime / Build-Unit | CI gate |
|---|---|---|---|
| #382: packaged encrypted supported-platform workflow — create, safe role grant, issue, exchange, tenant-A access, tenant-B denial, live grant/revoke, rotate/revoke, restart, operation recovery, root rotation, durable sanitized audit. | `service-credential-lifecycle-e2e` + `service-credential-zero-survivor-e2e` + `service-credential-rotation-e2e` + `service-credential-leak-scan-e2e` + `service-credential-publication-fault-e2e`; classified by `service-credential-platform-matrix` | Runtime (aggregate) | `service-credential-e2e` |
| #383: post-commit publication failure leaves a durable secret-free orphan, recoverable read-only, restart-surviving, revocable through the public path. | `service-credential-publication-fault-e2e` (#754); `service-credential-operation-coordinator-execute` | Runtime + Build/Unit | `service-credential-e2e`; standard `meson test` |
| #361: every product/security claim mapped to passing evidence; accepted #363/#364 limitations documented. | This document + `docs/operator-runbook.md` + `docs/service-credential-threat-model.md` | Documentation | (doc deliverable; no test gate) |
| No credential secret / plaintext CVK / JWT / `Authorization` body / disallowed verifier copy present in dumps, facts, logs, audit, errors, argv, query strings, or recovery files. | `service-credential-leak-scan-e2e` | Runtime | `service-credential-e2e` |
| No Service Credential behavior exposed through an unsigned policy artifact, partial route set, alternate bearer resolver, undocumented recovery path, or unowned invalidation guarantee. | `bootstrap.dl` — enforcement merged (#356); custodian-signed release candidate pending (#367); `service-credential-platform-matrix`; `service-credential-publication-fault-e2e` (documented recovery path); `service-credential-zero-survivor-e2e` (owned invalidation) | Build/Unit + Runtime | every-runner matrix; `service-credential-e2e` |

## Signed workload-safe policy plane: merge state

The data-plane allowlist and control-plane partition (`bootstrap.dl`) are the
signed workload-safe permission plane. Its **enforcement plane is merged
(#356, CLOSED)**. The **custodian-signed release candidate is still pending
(#367, OPEN)** — the offline custodian signature over the frozen canonical
digest has not yet been incorporated, and the umbrella #352 remains OPEN. This
row is therefore labeled "enforcement merged (#356); custodian-signed release
candidate pending (#367)"; it does not claim the signing gate is closed.

## Note on the harness helper

The packaged e2e drivers use a stdlib-only test harness,
`tests/wyrelog_sc_e2e.py` (subcommands such as `totp-admin`, `arm`, `http-post`,
`decide`, `assert-decide`, `assert-no-refresh`, `scan-absent`,
`escrow-extract`). It is **test-only**: it lives under `tests/`, is never
installed or packaged, and is not a shipped operator tool. The operator-facing
equivalents are the `wyctl` subcommands and HTTP routes documented in
`docs/operator-runbook.md`; the harness's `arm` helper corresponds to the
`POST /service-management-authority/arm` self-arm route, and its `totp-admin`
helper to the MFA-enrollment flow — both already documented in the runbook.

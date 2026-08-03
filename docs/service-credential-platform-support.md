<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Service-Credential Platform Evidence Matrix

**Status: FROZEN / authoritative.** This document is the single source of truth
for *what kind of proof* each operating system provides for the packaged,
encrypted service-credential lifecycle. It is enforced mechanically by
`tests/check-service-credential-platform-matrix.py`, which fails the build if
the classification below ever drifts out of agreement with the meson test
gating or the CI workflow definitions. Do not edit the classification without
also updating that checker and the sources it cites.

## Terminology

- **Packaged-runtime-supported** — the platform runs the *packaged, encrypted,
  end-to-end* service-credential lifecycle suite as real `meson test`
  registrations. This is a runtime guarantee: the daemon boots, a real store is
  provisioned and encrypted, credentials are issued/exchanged/rotated/revoked,
  and the audit sink is exercised. A runtime-supported classification **requires**
  its applicable packaged suite to be registered and runnable on that platform.
- **Build-only-supported** — the platform compiles the service-credential code
  paths and runs its native build/security/file gates (DuckDB bridge, secure
  filesystem, Windows fact-artifact namespace, POSIX file/security checks), but
  is **not** asserted to run the packaged lifecycle suite. Build-only evidence is
  labeled as *build evidence* and is **never** reported as runtime proof.

## The rule (non-negotiable)

- **skip != pass.** A skipped test is not evidence of anything.
- A platform classified **packaged-runtime-supported** whose applicable packaged
  runner is unavailable is a **FAILING / BLOCKING** gate, not a silent pass. A
  missing supported runner blocks the gate.
- A **build-only** classification must never be reported as a runtime guarantee.
- The checker (`tests/check-service-credential-platform-matrix.py`) itself must
  fail loud on any drift, including a missing source/config file it needs to
  read. It runs **unconditionally** on every platform's CI so drift is caught
  everywhere.

## The matrix

| Platform | Classification | What actually runs (evidence) |
| --- | --- | --- |
| **Linux** | **Packaged-runtime-supported** | Full packaged encrypted service-credential lifecycle e2e suite (runtime proof). |
| **macOS** | **Build-only-supported** | POSIX build + native security/file gates (build evidence, not runtime proof). |
| **Windows** | **Build-only-supported** | Native file/security/DuckDB gates (build evidence, not runtime proof). |

### Linux — packaged-runtime platform (authoritative)

Linux is the sole platform that runs the packaged, encrypted service-credential
lifecycle suite as a runtime guarantee. The applicable packaged suite, gated in
`tests/meson.build` under `host_machine.system() == 'linux'` (nested inside
`build_client` -> `enable_fact_store` -> `enable_audit`), is:

Runtime `test(...)` registrations (Linux-only):

- `service-credential-lifecycle-e2e` — bootstrap -> real-TOTP admin -> self-arm
  -> tenant/principal -> issue -> exchange -> `/decide` deny -> grant ->
  `/decide` allow.
- `service-credential-zero-survivor-e2e` — revoke / principal-disable /
  tenant-seal each leave zero usable or pending service tokens; no
  refresh/renewal path.
- `service-credential-rotation-e2e` — KeyProvider root rotation + credential
  rotation across real daemon restarts, with a durable sanitized audit.
- `service-credential-leak-scan-e2e` — per-run unique canaries for every
  observable sensitive value are asserted ABSENT (raw+base64+hex) from every
  forbidden sink.

Build-guaranteed helper executables the suite depends on (they read the
encrypted store / durable audit that a system CLI cannot):

- `check-service-credential-store-inspect`
- `check-audit-events-query`

These helper `executable()` builds remain available on the other POSIX build
platform (macOS) as a build gate; only their consuming runtime `test(...)`
registrations are Linux-only.

#### Predecessor-gated portion (NOT claimed as runtime-proven)

The **#380** server-success / local-publication-failure + orphan-recovery
runtime portion is **BLOCKED by predecessor #754**: there is no packaged
fault-injection seam that lets the packaged e2e harness force a
local-publication failure after a server-side success, so that path cannot yet
be proven at packaged-runtime scope. Until **#754** lands that seam, this
portion is covered by **C-unit evidence**, not by a packaged-runtime gate:

- `tests/test-service-credential-operation-coordinator-execute.c`
  (registered as the `service-credential-operation-coordinator-execute` test).

This is deliberately **not** counted as runtime proof in the matrix. When #754
lands the fault-injection seam, promote the #380 orphan-recovery portion into
the Linux packaged-runtime suite and update this document and the checker.

### macOS — build-only + native POSIX security/file gates

macOS is classified **build-only**. We deliberately do **not** assert a
packaged-runtime guarantee on macOS: documented macOS runtime flakiness (the
service-credential `handoff-e2e` intermittently SIGABRTs and passes on re-run)
would make a macOS packaged-runtime gate unreliable, and we do not assert a
runtime guarantee we cannot reliably hold. The daemon/shell e2e harness is
additionally already POSIX-shell/`sh`-driven and gated to Linux for these
packaged suites.

What actually runs on macOS (build evidence, `.github/workflows/ci-*.yml`,
`build-posix` job, `macos-latest`):

- Builds the project from pinned-source DuckDB (`-Dduckdb_source=subproject`)
  and runs `meson test -C builddir --print-errorlogs --suite wyrelog`.
- Native secure-DuckDB gates: `secure-duckdb-bridge`,
  `secure-duckdb-filesystem`, `secure-duckdb-recording-filesystem`.
- Additional POSIX build coverage via the `duckdb-checkpoint-seam` and
  `daemon-http-shared-fact` jobs (`macos-latest`).

All of the above is **build evidence**, not packaged service-credential runtime
proof.

### Windows — build-only + native file/security/DuckDB gates

Windows is classified **build-only**. The daemon/shell service-credential e2e
tests are POSIX-only by construction (`sh`-driven, gated off Windows), so no
packaged-runtime guarantee is asserted on Windows.

What actually runs on Windows (build evidence, `.github/workflows/ci-*.yml`,
`build-windows` job, `windows-latest`):

- Builds `wyctl` and `wyrelogd` with clang-cl and vcpkg-provided dependencies,
  across `fact_store`/`secure_bridge` matrix legs.
- Native gates on the secure-bridge leg: `secure-duckdb-bridge`,
  `secure-duckdb-recording-filesystem`, `fact-artifact-namespace-windows`.
- The default leg runs `meson test -C builddir --print-errorlogs --suite
  wyrelog` (the POSIX-only SC e2e tests do not register here, by design).

All of the above is **build evidence**, not packaged service-credential runtime
proof.

## Authoritative sources (what makes this enforceable)

The classification is not aspirational prose; it is derived from and checked
against these authoritative artifacts:

1. **Meson test gating** — `tests/meson.build`. The four
   `service-credential-*-e2e` `test(...)` registrations live inside a
   `host_machine.system() == 'linux'` gate (nested under `build_client`,
   `enable_fact_store`, `enable_audit`). This is what makes Linux the sole
   packaged-runtime platform: the suite does not silently run or skip elsewhere.
2. **CI workflow definitions** — `.github/workflows/ci-main.yml` and
   `.github/workflows/ci-pr.yml`. The `build-posix` job provides the Linux
   (`ubuntu-latest`) and macOS (`macos-latest`) runners; the Linux leg runs the
   `meson test ... --suite wyrelog` packaged suite. The `build-windows` job
   provides the Windows runner and its named native gates
   (`secure-duckdb-bridge`, `fact-artifact-namespace-windows`).
3. **C-unit predecessor evidence** —
   `tests/test-service-credential-operation-coordinator-execute.c` covers the
   #380 orphan-recovery portion that is blocked by predecessor #754.

If any of these drift out of agreement with this matrix,
`tests/check-service-credential-platform-matrix.py` fails the build.

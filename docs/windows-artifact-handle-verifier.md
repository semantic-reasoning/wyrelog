# Windows artifact handle verifier

The native Windows artifact suite has a fail-closed Application Verifier gate
for invalid HANDLE use and HANDLE leaks. It runs in the existing
`build-windows-secure-bridge` CI leg, after the ordinary native tests.

## Prerequisites

- 64-bit native Windows and a 64-bit Administrator PowerShell process.
- CI pins every Windows matrix entry to the GitHub-hosted `windows-2025` label
  and checks `runner.environment == github-hosted` before setup. GitHub-hosted
  Windows VMs run as administrators with UAC disabled. The explicit label
  avoids the repository's observed self-hosted `windows-latest` collision, and
  the runtime check makes a self-hosted runner assigned the same explicit label
  fail closed. The AppVerifier runner independently records and checks the same
  provenance before instrumentation.
- The Windows SDK Application Verifier feature (`OptionId.AvrfExternal`). The
  runner requires the Microsoft-signed 64-bit tool at
  `%SystemRoot%\System32\appverif.exe`. If it is absent, the runner installs
  the official `Microsoft.WindowsSDK.10.0.28000` WinGet package with only
  `OptionId.AvrfExternal`; installation failure or continued absence is a hard
  failure, not a skip.
- A configured Windows build with
  `-Denable_windows_artifact_test_hooks=enabled` and the native test targets
  already built.

The CI runner records the AppVerifier path, SHA-256, file/product versions,
Authenticode signer, Windows version, image names, layers, stops, and selector
in `environment.json`. It accepts only the Microsoft Application Verifier
binary from the declared Windows SDK 26100 or 28000 family.
CI explicitly builds both test-only probe targets before entering the gate.
The secure-bridge leg also builds
`test-secure-duckdb-temp-child-windows.exe`, a separate native image linked to
the test-seam archive and DuckDB rather than the shipped library.
`runner-started.json` records the runner environment/name and preserves startup
context even if the Administrator, tool, build, or target prerequisite check
fails.

## Exact invocation

From an elevated PowerShell in the repository root:

```powershell
meson setup builddir -Denable_fact_store=enabled `
  -Denable_secure_duckdb_bridge=enabled -Dduckdb_source=subproject `
  -Denable_windows_artifact_test_hooks=enabled
meson compile -C builddir
& .\tools\run-windows-appverifier.ps1 `
  -BuildDirectory builddir `
  -OutputDirectory builddir\appverifier-artifacts
```

For each exact process image, the runner enables `Handles` and `Leak`. The
Handles layer automatically enables handle tracing; the runner deliberately
does not set the SDK-version-specific `Handles.Traces` property. It configures
stops `0x300` and `0x901` as active,
exception-terminating, logged with stacks, and non-continuable. Settings are
image-name based, so subprocesses that re-execute
`test-fact-artifact-namespace-windows.exe` receive the same checks.

The runner performs four isolated phases:

1. `clean-probe`: a test-only DLL creates a named event HANDLE and closes it
   before unload. The probe must exit zero without Handles/Leak stops.
2. `invalid-probe`: the same function closes the event and deliberately tries
   to close the invalid HANDLE again. The probe must terminate with Handles
   stop `0x300`.
3. `artifact-suite`: Meson runs the full
   `fact-artifact-namespace-windows` selector and the nine independently
   registered lifecycle selectors (`main-sidecar`,
   `sidecar-replacement-isolated`, `temp-binding-replacement-isolated`,
   `lock-entry-replacement-isolated`, `temp-token-real-crash-recovery`,
   `cross-process`, `temp-root-spill-child-capabilities`,
   `temp-root-wrapper-ownership`, and `mutation-handle-lifetime`) under the
   same Handles/Leak configuration.
   This preserves later lifecycle coverage if an aggregate process aborts.
   Every invocation must exit zero without relevant stops.
4. `secure-temp-child`: the separately instrumented
   `test-secure-duckdb-temp-child-windows.exe` constructs an exact Windows
   provisioned pair, opens it through
   `wyl_fact_artifact_namespace_open_provisioned_pair_internal`, and drives a
   real `WylSecureDuckdbFileSystem` temporary child through create, write,
   flush, close, retirement, and destruction. This phase must exit zero with
   no Handles or Leak stop. Keeping it in its own image and evidence directory
   prevents a clean artifact-suite process from standing in for the production
   secure-filesystem path.

   The runner launches this image directly rather than through Meson. It
   validates and prepends the build's pinned
   `subprojects\libchronoid` shared-runtime directory followed by the vcpkg
   `bin` directory, preserving and then exactly restoring the caller's process
   `PATH`. An uninstrumented direct launch must first pass and is captured in
   `loader-preflight.txt`; only then does the runner enable AppVerifier and
   repeat the exact image under Handles/Leak instrumentation.

The activation fault is isolated to the test-only probe. The reused-slot
ownership test retains its deliberate invalid `CloseHandle` consumption
assertion in ordinary test runs. For the instrumented artifact phase only, the
runner sets `WYRELOG_APPVERIFIER_HANDLE_GATE=1` around the Meson child process
and restores the caller's prior process-environment value in `finally`, so that
assertion does not terminate the aggregate process a second time and the marker
cannot leak into later ordinary tests. The reused-slot ownership body and every
other case still run under Handles/Leak checking.

The double-close negative control proves that the configured Handles
instrument is active and terminating. It is test-only and does not alter
production ownership. The Leak layer and stop `0x901` remain enabled for the
artifact suite, but AppVerifier 10.0.26100 did not report a test-only named
event left open immediately before owner-DLL unload, so that behavior is not
used as the gate's activation proof. Issue #659 separately owns mutation-path
lifetime coverage and remains open until its production-suite evidence is
complete.

## Mutation lifetime coverage and limits

The `mutation-handle-lifetime` selector groups the object-specific lifetime
checks added for #659. They capture a `FILE_ID_128` before a name is removed or
made delete-pending, retain an exact witness across the mutation, and then
prove that the production owner disappears at the protocol-specific cleanup
point. The covered protocols include working-handle release, raw and
higher-level replacement, sidecar retirement, temporary-token unlink and
recovery, and temporary-child/root retirement. Replacement tests distinguish
the caller-owned displaced target from production-owned replacement state;
recovery tests account for owners acquired and released entirely inside the
recovery call.

The File-ID oracle is deliberately bounded. Before treating a failed
`OpenFileById` query as an unavailable filesystem capability, each test proves
that its known-open witness still has the expected identity. A local run may
then report a capability skip. Under `WYRELOG_APPVERIFIER_HANDLE_GATE=1`, the
same condition is fatal, so hosted evidence cannot silently omit a lifetime
observation. The three close-reversion negative controls recorded by #737
remain the mutation-sensitivity evidence for this primitive.

The reachability oracle cannot detect a leaked HANDLE while the object still
has a name. Graph directories, lock guardians, ordinary sidecar bindings, and
I/O-session duplicates therefore rely on the Handles/Leak instrumentation in
this runner. The aggregate process and the independent
`mutation-handle-lifetime` process must both be clean before hosted evidence is
accepted.

`test-windows-artifact-handle-lifetime-boundary.py` is a structural inventory,
not a runtime ownership proof. It requires one row for every native or external
Windows wrapper that transitively reaches a bounded mutation transport,
validates exact test-to-entry and entry-to-linearizer reachability, pins known
fault arms/probes, and rejects direct native-transport bypasses. It records
which rows have an object-reachability oracle and which remain
AppVerifier-only.

The temporary-child wrapper rows carry no unresolved ownership residual. The
create wrapper returns an independently owned child and transfers its binding
and I/O duplicate into the wrapper session. Open-existing borrows the caller's
child and transfers only its newly acquired binding and duplicate. Finish,
close-then-finish, and abort consume those session-specific owners without
terminalizing the caller's child. Rollback consumes an unpublished child and
either frees its preallocated orphan evidence after a certain retirement or
returns that evidence when the post-delete directory flush is uncertain.

The independently registered `temp-root-wrapper-ownership` selector exercises
those transfers and terminal dispositions. The structural inventory also pins
the three creation wrappers' directory-flush fault reachability and the
delete-linearized unpublished-child cleanup. These checks resolve
[issue #882](https://github.com/semantic-reasoning/wyrelog/issues/882), but they
do not replace runtime HANDLE evidence: ordinary runs may skip the File-ID
reachability oracle when the volume cannot answer it, while the hosted
Application Verifier gate makes that condition fatal and remains authoritative
for named-object leaks and invalid closes.

## Evidence and cleanup

Each phase has a distinct directory below the requested output root. Binary
`.dat` logs emitted under the phase's AppVerifier-created `AppVerifierLogs/`
directory are copied to `raw/`, every log is converted to XML under `xml/`, and
configuration, process output, and conversion output are retained. XML is
checked structurally through `logEntry` attributes; the negative control
requires `LayerName="Handles"` and numeric `StopCode="0x300"`.

The runner deletes old settings and logs before every phase. It exports and
validates phase evidence before deleting current settings/logs, then verifies
that no target image remains enabled. A final cleanup repeats and checks the
probe, artifact-suite, and secure-temp-child images after every success or
failure. CI uploads
`builddir/appverifier-artifacts/` with `always()`; missing evidence is itself a
gate failure.

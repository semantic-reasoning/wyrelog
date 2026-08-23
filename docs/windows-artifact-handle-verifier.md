# Windows artifact handle verifier

The native Windows artifact suite has a fail-closed Application Verifier gate
for invalid HANDLE use and HANDLE leaks. It runs in the existing
`build-windows-secure-bridge` CI leg, after the ordinary native tests.

## Prerequisites

- 64-bit native Windows and a 64-bit Administrator PowerShell process.
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

For each exact process image, the runner enables `Handles` and `Leak`, enables
HANDLE traces, and configures stops `0x300` and `0x901` as active,
exception-terminating, logged with stacks, and non-continuable. Settings are
image-name based, so subprocesses that re-execute
`test-fact-artifact-namespace-windows.exe` receive the same checks.

The runner performs four isolated phases:

1. `clean-probe`: a test-only DLL creates a named event HANDLE and closes it
   before unload. The probe must exit zero without Handles/Leak stops.
2. `leak-probe`: the same exported function creates the same named event and
   intentionally omits that close. DLL unload must terminate the probe and
   produce AppVerifier Leak stop `0x901`.
3. `invalid-probe`: the same function closes the event and deliberately tries
   to close the invalid HANDLE again. The probe must terminate with Handles
   stop `0x300`.
4. `artifact-suite`: Meson runs the full
   `fact-artifact-namespace-windows` selector and the seven independently
   registered lifecycle selectors (`main-sidecar`,
   `sidecar-replacement-isolated`, `temp-binding-replacement-isolated`,
   `lock-entry-replacement-isolated`, `temp-token-real-crash-recovery`,
   `cross-process`, and `temp-root-spill-child-capabilities`) under the same
   Handles/Leak configuration.
   This preserves later lifecycle coverage if an aggregate process aborts.
   Every invocation must exit zero without relevant stops.

This negative control proves that the configured instrument detects a named
kernel HANDLE leak. It is test-only and does not alter production ownership.
Issue #659 separately owns mutation-path lifetime coverage and remains open
until its production-suite evidence is complete.

## Evidence and cleanup

Each phase has a distinct directory below the requested output root. Binary
`.dat` logs are copied to `raw/`, every log is converted to XML under `xml/`,
and configuration, process output, and conversion output are retained. XML is
checked structurally through `logEntry` attributes; the negative control
requires `LayerName="Leak"` and numeric `StopCode="0x901"`.

The runner deletes old settings and logs before every phase. It exports and
validates phase evidence before deleting current settings/logs, then verifies
that neither target image remains enabled. A final cleanup repeats and checks
both images after every success or failure. CI uploads
`builddir/appverifier-artifacts/` with `always()`; missing evidence is itself a
gate failure.

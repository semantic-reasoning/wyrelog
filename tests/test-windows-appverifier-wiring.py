#!/usr/bin/env python3
"""Guard the native Windows Application Verifier CI contract."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
script = (root / "tools" / "run-windows-appverifier.ps1").read_text(
    encoding="utf-8"
)

required_script_tokens = (
    "System32\\appverif.exe",
    "OptionId.AvrfExternal",
    "Microsoft.WindowsSDK.10.0.28000",
    "'/features OptionId.AvrfExternal /quiet /norestart'",
    "'-query', '*', '-for', $ImageName",
    "'-enable', 'Handles', 'Leak', '-for', $ImageName",
    "'Handles.Traces=true'",
    "'-configure', '0x300', '0x901', '-for', $ImageName",
    "'ErrorReport=0x1C1', 'Flavor=0x2'",
    "'-logtoxml', $raw.FullName, $xml_path",
    'SelectNodes("//*[local-name()=\'logEntry\']")',
    "$expected_stop = if ($Mode -eq 'leak') { 0x901 } else { 0x300 }",
    "$unexpected.Count -ne 0",
    "clean-probe",
    "leak-probe",
    "invalid-probe",
    "artifact-suite",
    "runner-started.json",
    "test-windows-appverifier-probe.exe",
    "test-fact-artifact-namespace-windows.exe",
    "finally {",
    "Assert-Target-Disabled",
    'Assert-Success $query "query cleared AppVerifier settings for $ImageName"',
    "$version_info.OriginalFilename -ine 'appverif.exe'",
    "$version_match.Groups[3].Value -notin @('26100', '28000')",
    "$app_verifier_hash -notmatch '^[0-9A-F]{64}$'",
)
for token in required_script_tokens:
    if token not in script:
        raise SystemExit(f"Windows AppVerifier runner lost fail-closed token: {token}")

output_root = script.index("$script:output_root =")
startup_evidence = script.index("runner-started.json")
build_prerequisite = script.index("$script:build_root =")
required_target_check = script.index("foreach ($required in")
if not output_root < startup_evidence < build_prerequisite < required_target_check:
    raise SystemExit(
        "Windows AppVerifier runner must preserve startup evidence before "
        "build and target prerequisite checks"
    )

if "continue-on-error" in script or "SilentlyContinue" in script:
    raise SystemExit("Windows AppVerifier runner must not suppress failures")

probe_dll = (root / "tests" / "windows-appverifier-probe-dll.c").read_text(
    encoding="utf-8"
)
probe_driver = (root / "tests" / "windows-appverifier-probe.c").read_text(
    encoding="utf-8"
)
for token in (
    "Local\\\\WyrelogAppVerifierHandleProbe",
    "CreateEventW",
    "mode == 0",
    "mode == 1",
):
    if token not in probe_dll:
        raise SystemExit(f"AppVerifier HANDLE probe lost mode/resource token: {token}")
if probe_dll.count("CloseHandle (event)") != 2:
    raise SystemExit("AppVerifier probe must retain clean close and invalid close")
for token in ("L\"clean\"", "L\"leak\"", "L\"invalid\"", "FreeLibrary"):
    if token not in probe_driver:
        raise SystemExit(f"AppVerifier probe driver lost execution token: {token}")

meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
for target in (
    "test-windows-appverifier-probe-dll",
    "test-windows-appverifier-probe",
):
    if target not in meson:
        raise SystemExit(f"missing Windows AppVerifier probe target: {target}")
probe = meson.index("'test-windows-appverifier-probe-dll'")
guard = meson.rindex("if host_machine.system() == 'windows'", 0, probe)
if ".allowed()" not in meson[guard:probe]:
    raise SystemExit("AppVerifier probes must stay inside the Windows hook gate")


def job(workflow: str, name: str) -> str:
    start = workflow.index(f"  {name}:\n")
    match = re.search(r"\n  [A-Za-z0-9_-]+:\n", workflow[start + 1 :])
    return workflow[start:] if match is None else workflow[start : start + 1 + match.start()]


for workflow_name in ("ci-pr.yml", "ci-main.yml"):
    workflow = (root / ".github" / "workflows" / workflow_name).read_text(
        encoding="utf-8"
    )
    windows = job(workflow, "build-windows")
    run_name = "      - name: Run Windows Application Verifier handle gate"
    upload_name = "      - name: Upload Windows Application Verifier evidence"
    if windows.count(run_name) != 1 or windows.count(upload_name) != 1:
        raise SystemExit(f"{workflow_name} must contain one verifier run/upload pair")
    run_start = windows.index(run_name)
    upload_start = windows.index(upload_name)
    if not windows.index("      - name: Build and test (clang-cl)") < run_start < upload_start:
        raise SystemExit(f"{workflow_name} verifier gate ordering drifted")
    probe_compile = (
        "meson compile -C builddir test-windows-appverifier-probe "
        "test-windows-appverifier-probe-dll"
    )
    if windows.count(probe_compile) != 1 or windows.index(probe_compile) > run_start:
        raise SystemExit(f"{workflow_name} must build verifier probes before the gate")
    run_step = windows[run_start:upload_start]
    upload_step = windows[upload_start:]
    for token in (
        "        if: matrix.secure_bridge == 'enabled'",
        "tools\\run-windows-appverifier.ps1",
        "-BuildDirectory builddir",
        "-OutputDirectory builddir\\appverifier-artifacts",
    ):
        if token not in run_step:
            raise SystemExit(f"{workflow_name} verifier invocation drifted: {token}")
    if "continue-on-error:" in run_step:
        raise SystemExit(f"{workflow_name} verifier failure must fail its job")
    for token in (
        "        if: always() && matrix.secure_bridge == 'enabled'",
        "          path: builddir/appverifier-artifacts/",
        "          if-no-files-found: error",
    ):
        if token not in upload_step:
            raise SystemExit(f"{workflow_name} verifier evidence drifted: {token}")

for selector in (
    "fact-artifact-namespace-windows",
    "fact-artifact-namespace-windows-main-sidecar",
    "fact-artifact-namespace-windows-sidecar-replacement-isolated",
    "fact-artifact-namespace-windows-temp-binding-replacement-isolated",
    "fact-artifact-namespace-windows-lock-entry-replacement-isolated",
    "fact-artifact-namespace-windows-temp-token-real-crash-recovery",
    "fact-artifact-namespace-windows-cross-process",
    "fact-artifact-namespace-windows-temp-root-spill-child-capabilities",
):
    if script.count(f"'{selector}'") < 2:
        raise SystemExit(f"AppVerifier runner lost runtime/evidence selector: {selector}")

print("Windows Application Verifier wiring: OK")

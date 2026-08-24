#!/usr/bin/env python3
"""Guard the native Windows Application Verifier CI contract."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
script = (root / "tools" / "run-windows-appverifier.ps1").read_text(
    encoding="utf-8"
)
meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
windows_test = (
    root / "tests" / "test-fact-artifact-namespace-windows.c"
).read_text(encoding="utf-8")

required_script_tokens = (
    "System32\\appverif.exe",
    "OptionId.AvrfExternal",
    "Microsoft.WindowsSDK.10.0.28000",
    "'/features OptionId.AvrfExternal /quiet /norestart'",
    "'-query', '*', '-for', $ImageName",
    "'-enable', 'Handles', 'Leak', '-for', $ImageName",
    "'-configure', '0x300', '0x901', '-for', $ImageName",
    "'ErrorReport=0x1C1', 'Flavor=0x2'",
    "$appverifier_logs = Join-Path $phase_path 'AppVerifierLogs'",
    "Get-ChildItem -LiteralPath $appverifier_logs",
    "$raw.Directory.FullName -ne $appverifier_logs",
    "'-logtoxml', $raw.FullName, $xml_path",
    'SelectNodes("//*[local-name()=\'logEntry\']")',
    "$expected_layer = 'Handles'",
    "$expected_stop = 0x300",
    "$unexpected.Count -ne 0",
    "clean-probe",
    "invalid-probe",
    "artifact-suite",
    "runner-started.json",
    "$env:GITHUB_ACTIONS -eq 'true'",
    "$env:RUNNER_ENVIRONMENT -ne 'github-hosted'",
    "runner_environment = $env:RUNNER_ENVIRONMENT",
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
hosted_failure = script.index(
    "throw 'CI Application Verifier requires a GitHub-hosted runner'"
)
administrator_failure = script.index(
    "throw 'Application Verifier requires an Administrator process'"
)
build_prerequisite = script.index("$script:build_root =")
required_target_check = script.index("foreach ($required in")
if not (
    output_root
    < startup_evidence
    < hosted_failure
    < administrator_failure
    < build_prerequisite
    < required_target_check
):
    raise SystemExit(
        "Windows AppVerifier runner must preserve startup evidence before "
        "hosted-runner, administrator, build, and target prerequisite checks"
    )

if "Handles.Traces" in script:
    raise SystemExit(
        "Handles enables tracing automatically; a version-specific property "
        "override must not be used"
    )
if "continue-on-error" in script or "SilentlyContinue" in script:
    raise SystemExit("Windows AppVerifier runner must not suppress failures")
if "leak-probe" in script or "-Mode leak" in script:
    raise SystemExit("AppVerifier negative control must use the reliable double-close")

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
    "mode != 1",
):
    if token not in probe_dll:
        raise SystemExit(f"AppVerifier HANDLE probe lost mode/resource token: {token}")
if probe_dll.count("CloseHandle (event)") != 2:
    raise SystemExit("AppVerifier probe must retain clean close and invalid close")
for token in ("L\"clean\"", "L\"invalid\"", "FreeLibrary"):
    if token not in probe_driver:
        raise SystemExit(f"AppVerifier probe driver lost execution token: {token}")
if 'L"leak"' in probe_driver:
    raise SystemExit("AppVerifier probe driver must not expose an unverified leak mode")

artifact_suite = (
    root / "tests" / "test-fact-artifact-namespace-windows.c"
).read_text(encoding="utf-8")
artifact_phase = script[
    script.index("function Invoke-Artifact-Suite") : script.index("\nif ($env:OS")
]
for token in (
    "$previous_gate_marker = [Environment]::GetEnvironmentVariable(",
    "'WYRELOG_APPVERIFIER_HANDLE_GATE', '1', 'Process'",
    "} finally {",
    "'WYRELOG_APPVERIFIER_HANDLE_GATE', $previous_gate_marker, 'Process'",
):
    if token not in artifact_phase:
        raise SystemExit(
            f"the AppVerifier artifact phase lost marker isolation: {token}"
        )
reused_test = artifact_suite[
    artifact_suite.index("test_working_handle_free_never_closes_reused_handle") :
    artifact_suite.index("typedef enum", artifact_suite.index(
        "test_working_handle_free_never_closes_reused_handle"
    ))
]
for token in (
    'g_getenv ("WYRELOG_APPVERIFIER_HANDLE_GATE") == NULL',
    "g_assert_false (CloseHandle (issued))",
):
    if token not in reused_test:
        raise SystemExit(
            f"the instrumented suite lost its isolated negative-control token: {token}"
        )

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
    if "    runs-on: ${{ matrix.runner }}" not in windows:
        raise SystemExit(f"{workflow_name} Windows runner selection drifted")
    runner_rows = (
        (
            "          - runner: windows-2025\n"
            "            fact_store: disabled\n"
            "            secure_bridge: disabled"
        ),
        (
            "          - runner: windows-2025\n"
            "            fact_store: enabled\n"
            "            secure_bridge: disabled"
        ),
        (
            "          - runner: windows-2025\n"
            "            fact_store: enabled\n"
            "            secure_bridge: enabled"
        ),
    )
    if windows.count("          - runner:") != 3 or any(
        windows.count(row) != 1 for row in runner_rows
    ):
        raise SystemExit(
            f"{workflow_name} must preserve all three Windows runner rows"
        )
    hosted_contract = (
        "      - name: Verify hosted Windows runner contract\n"
        "        shell: powershell\n"
        "        run: |\n"
        "          if ('${{ runner.environment }}' -ne 'github-hosted') {\n"
        "            throw 'the Windows matrix requires a GitHub-hosted runner'\n"
        "          }"
    )
    if windows.count(hosted_contract) != 1:
        raise SystemExit(f"{workflow_name} lost the hosted Windows contract")
    if windows.index(hosted_contract) > windows.index(
        "      - name: Check out source"
    ):
        raise SystemExit(
            f"{workflow_name} must verify hosted provenance before checkout"
        )
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

suite_start = script.index("function Invoke-Artifact-Suite")
suite_end = script.index("\n}\n\nif ($env:OS", suite_start)
runtime_suite = script[suite_start:suite_end]
metadata_start = script.index("  suite_selectors = @(")
metadata_end = script.index("\n  )", metadata_start)
evidence_selectors = script[metadata_start:metadata_end]

for selector in (
    "fact-artifact-namespace-windows",
    "fact-artifact-namespace-windows-main-sidecar",
    "fact-artifact-namespace-windows-sidecar-replacement-isolated",
    "fact-artifact-namespace-windows-temp-binding-replacement-isolated",
    "fact-artifact-namespace-windows-lock-entry-replacement-isolated",
    "fact-artifact-namespace-windows-temp-token-real-crash-recovery",
    "fact-artifact-namespace-windows-cross-process",
    "fact-artifact-namespace-windows-temp-root-spill-child-capabilities",
    "fact-artifact-namespace-windows-mutation-handle-lifetime",
):
    quoted = f"'{selector}'"
    if runtime_suite.count(quoted) != 1:
        raise SystemExit(
            f"AppVerifier runtime suite must contain selector exactly once: {selector}"
        )
    if evidence_selectors.count(quoted) != 1:
        raise SystemExit(
            f"AppVerifier evidence must contain selector exactly once: {selector}"
        )

lifetime_registration = (
    "['mutation-handle-lifetime', "
    "'/fact/artifact-namespace/windows/mutation-handle-lifetime']"
)
if meson.count(lifetime_registration) != 1:
    raise SystemExit("Meson must register the mutation HANDLE-lifetime selector once")

expected_lifetime_cases = (
    (
        "/fact/artifact-namespace/windows/mutation-handle-lifetime/working-guardian",
        "test_working_handle_free_closes_unlinked_object",
    ),
    (
        "/fact/artifact-namespace/windows/mutation-handle-lifetime/raw-replace",
        "test_locator_replace_open_destination",
    ),
    (
        "/fact/artifact-namespace/windows/mutation-handle-lifetime/sidecar-replace-retire",
        "test_native_namespace_sidecar_replacement_isolated",
    ),
    (
        "/fact/artifact-namespace/windows/mutation-handle-lifetime/neutral-replace",
        "test_native_namespace_main_sidecar_lifecycle",
    ),
    (
        "/fact/artifact-namespace/windows/mutation-handle-lifetime/temp-tokens",
        "test_mutation_handle_lifetime_temp_tokens",
    ),
    (
        "/fact/artifact-namespace/windows/mutation-handle-lifetime/temp-tree",
        "test_mutation_handle_lifetime_temp_tree",
    ),
)
guarded_array_marker = "static const WinGuardedCase win_guarded_cases[] = {"


def normalize_c_preprocessing(source: str) -> str:
    normalized = source.replace("??=", "#").replace("??/", "\\")
    normalized = normalized.replace("\\\r\n", "").replace("\\\n", "")
    normalized = normalized.replace("%:", "#")
    normalized = re.sub(r"/\*.*?\*/", " ", normalized, flags=re.S)
    return re.sub(r"//[^\r\n]*", "", normalized)


def validate_registration_macro_guard(source: str) -> None:
    start = source.index(guarded_array_marker) + len(guarded_array_marker)
    end = source.index("\n};", start)
    initializer = normalize_c_preprocessing(source[start:end])
    first_element = re.search(r"^\s*\{", initializer, flags=re.M)
    if first_element is None:
        raise SystemExit("mutation lifetime callback array has no elements")
    guard = initializer[: first_element.start()]
    if not guard.strip():
        raise SystemExit("mutation lifetime callback macro guard is missing")
    directives = [
        " ".join(item.split())
        for item in re.findall(r"^\s*#\s*([^\r\n]*)", guard, flags=re.M)
    ]
    if len(directives) != 3 or directives[1:] != [
        'error "mutation HANDLE-lifetime callbacks must not be macros"',
        "endif",
    ]:
        raise SystemExit("mutation lifetime callback macro guard drifted")
    condition = directives[0]
    callbacks = re.findall(
        r"defined\s*\(\s*([A-Za-z_]\w*)\s*\)", condition
    )
    expected_callbacks = [callback for _, callback in expected_lifetime_cases]
    remainder = re.sub(
        r"defined\s*\(\s*[A-Za-z_]\w*\s*\)", "", condition
    )
    remainder = re.sub(r"^(?:if)\s*|\|\||\s+", "", remainder)
    if (
        len(callbacks) != len(expected_callbacks)
        or set(callbacks) != set(expected_callbacks)
        or remainder
    ):
        raise SystemExit("mutation lifetime callback macro guard set drifted")
    non_directive = re.sub(
        r"^\s*#[^\r\n]*(?:\r?\n|$)", "", guard, flags=re.M
    )
    if non_directive.strip():
        raise SystemExit("callback macro guard must precede the first array element")


validate_registration_macro_guard(windows_test)


def reject_lifetime_callback_macros(source: str) -> None:
    normalized = normalize_c_preprocessing(source)
    for _, callback in expected_lifetime_cases:
        if re.search(
            rf"^\s*#\s*(?:define|undef)\s+{re.escape(callback)}\b",
            normalized,
            flags=re.M,
        ):
            raise SystemExit(
                f"mutation HANDLE-lifetime callback must not be a macro: {callback}"
            )


reject_lifetime_callback_macros(windows_test)


def reject_late_registration_directives(source: str) -> None:
    array_position = source.index(guarded_array_marker)
    function_starts = []
    for _, callback in expected_lifetime_cases:
        definitions = list(
            re.finditer(
                rf"\n{re.escape(callback)}\s*\(void\)\s*\{{",
                source[:array_position],
            )
        )
        callback_position = definitions[-1].start() if definitions else -1
        function_start = source.rfind("\nstatic void", 0, callback_position)
        if callback_position < 0 or function_start < 0:
            raise SystemExit(f"could not isolate mutation callback {callback}")
        function_starts.append(function_start)
    late_region = normalize_c_preprocessing(
        source[min(function_starts):array_position]
    )
    directives = [
        " ".join(item.split())
        for item in re.findall(r"^\s*#\s*([^\r\n]*)", late_region, flags=re.M)
    ]
    if (
        len(directives) != 2
        or directives[:2]
        != ["ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS", "endif"]
    ):
        raise SystemExit("mutation lifetime registrations reject late directives")


reject_late_registration_directives(windows_test)
lifetime_case_pattern = re.compile(
    r'\{\s*"(/fact/artifact-namespace/windows/'
    r'mutation-handle-lifetime/[^"]+)",\s*([A-Za-z_]\w*)\s*\}\s*,'
)


def guarded_array(source: str) -> tuple[int, int, str]:
    start = source.index(guarded_array_marker) + len(guarded_array_marker)
    end = source.index("\n};", start)
    initializer = normalize_c_preprocessing(source[start:end])
    first_element = re.search(r"^\s*\{", initializer, flags=re.M)
    if first_element is None:
        raise SystemExit("win_guarded_cases has no direct elements")
    initializer = initializer[first_element.start() :]
    if re.search(r"^\s*#", initializer, flags=re.M):
        raise SystemExit("win_guarded_cases must not contain preprocessing directives")
    return start, end, initializer


def guarded_case_pairs(source: str) -> list[tuple[str, str]]:
    _, _, initializer = guarded_array(source)
    pairs: list[tuple[str, str]] = []
    cursor = 0
    while initializer[cursor:].strip():
        while cursor < len(initializer) and initializer[cursor].isspace():
            cursor += 1
        if cursor >= len(initializer) or initializer[cursor] != "{":
            raise SystemExit(
                "win_guarded_cases must contain only direct path/function elements"
            )
        end = initializer.find("}", cursor + 1)
        if end < 0:
            raise SystemExit("win_guarded_cases has an unterminated element")
        element = initializer[cursor + 1 : end]
        match = re.fullmatch(
            r'\s*"([^"]+)",\s*([A-Za-z_]\w*)(?P<rest>.*)',
            element,
            flags=re.S,
        )
        if match is None:
            raise SystemExit("win_guarded_cases has a malformed direct element")
        path = match.group(1)
        if path.startswith(
            "/fact/artifact-namespace/windows/mutation-handle-lifetime/"
        ) and match.group("rest").strip():
            raise SystemExit("mutation HANDLE-lifetime cases must have two fields")
        pairs.append((path, match.group(2)))
        cursor = end + 1
        while cursor < len(initializer) and initializer[cursor].isspace():
            cursor += 1
        if cursor >= len(initializer) or initializer[cursor] != ",":
            raise SystemExit("win_guarded_cases direct element lost its comma")
        cursor += 1
    return pairs


def lifetime_registration_pairs(source: str) -> list[tuple[str, str]]:
    prefix = "/fact/artifact-namespace/windows/mutation-handle-lifetime/"
    return [pair for pair in guarded_case_pairs(source) if pair[0].startswith(prefix)]


lifetime_cases = lifetime_registration_pairs(windows_test)
if len(lifetime_cases) != len(expected_lifetime_cases) or set(
    lifetime_cases
) != set(expected_lifetime_cases):
    raise SystemExit("mutation HANDLE-lifetime selector registrations drifted")

array_start, array_end, _ = guarded_array(windows_test)
array_source = windows_test[array_start:array_end]
live_rows = [match.group(0) for match in lifetime_case_pattern.finditer(array_source)]
comment_only_array = lifetime_case_pattern.sub("", array_source)
comment_only_array += "\n/* comment-only mutation\n" + "\n".join(live_rows) + "\n*/"
comment_only_source = (
    windows_test[:array_start]
    + comment_only_array
    + windows_test[array_end:]
)
if lifetime_registration_pairs(comment_only_source):
    raise SystemExit("wiring self-test accepted comment-only lifetime cases")

preprocessor_only_array = (
    lifetime_case_pattern.sub("", array_source)
    + "\n#if 0\n"
    + "\n".join(live_rows)
    + "\n#endif"
)
preprocessor_only_source = (
    windows_test[:array_start]
    + preprocessor_only_array
    + windows_test[array_end:]
)
try:
    lifetime_registration_pairs(preprocessor_only_source)
except SystemExit as error:
    if "preprocessing directives" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted preprocessor-disabled cases")

macro_only_array = (
    lifetime_case_pattern.sub("", array_source)
    + "\nWYL_ELIDE_LIFETIME_CASES(\n"
    + "\n".join(live_rows)
    + "\n)"
)
macro_only_source = (
    "#define WYL_ELIDE_LIFETIME_CASES(...)\n"
    + windows_test[:array_start]
    + macro_only_array
    + windows_test[array_end:]
)
try:
    lifetime_registration_pairs(macro_only_source)
except SystemExit as error:
    if "only direct path/function elements" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted macro-elided lifetime cases")

callback_aliases = "\n".join(
    f"#define {callback} test_locator_relative_entry_lifecycle"
    for _, callback in expected_lifetime_cases
)
try:
    reject_lifetime_callback_macros(callback_aliases + "\n" + windows_test)
except SystemExit as error:
    if "callback must not be a macro" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted callback macro aliases")

comment_aliases = "\n".join(
    f"#define /* alias */ {callback} test_locator_relative_entry_lifecycle"
    for _, callback in expected_lifetime_cases
)
try:
    reject_lifetime_callback_macros(comment_aliases + "\n" + windows_test)
except SystemExit as error:
    if "callback must not be a macro" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted comment-interposed aliases")

splice_aliases = "\n".join(
    f"#define {callback[:len(callback) // 2]}\\\n"
    f"{callback[len(callback) // 2:]} test_locator_relative_entry_lifecycle"
    for _, callback in expected_lifetime_cases
)
try:
    reject_lifetime_callback_macros(splice_aliases + "\n" + windows_test)
except SystemExit as error:
    if "callback must not be a macro" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted line-spliced callback aliases")

for directive_token in ("%:define", "??=define"):
    alternative_aliases = "\n".join(
        f"{directive_token} {callback} test_locator_relative_entry_lifecycle"
        for _, callback in expected_lifetime_cases
    )
    try:
        reject_lifetime_callback_macros(
            alternative_aliases + "\n" + windows_test
        )
    except SystemExit as error:
        if "callback must not be a macro" not in str(error):
            raise
    else:
        raise SystemExit(
            f"wiring self-test accepted {directive_token} callback aliases"
        )

trigraph_splice_aliases = "\n".join(
    f"??=define {callback[:len(callback) // 2]}??/\n"
    f"{callback[len(callback) // 2:]} test_locator_relative_entry_lifecycle"
    for _, callback in expected_lifetime_cases
)
try:
    reject_lifetime_callback_macros(
        trigraph_splice_aliases + "\n" + windows_test
    )
except SystemExit as error:
    if "callback must not be a macro" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted trigraph-spliced aliases")

late_include_source = windows_test.replace(
    guarded_array_marker,
    '#include "callback-aliases.h"\n' + guarded_array_marker,
    1,
)
try:
    reject_late_registration_directives(late_include_source)
except SystemExit as error:
    if "reject late directives" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted a late callback-alias include")

array_position = windows_test.index(guarded_array_marker)
last_callback_match = re.search(
    r"\ntest_mutation_handle_lifetime_temp_tree\s*\(void\)\s*\{",
    windows_test[:array_position],
)
if last_callback_match is None:
    raise SystemExit("wiring self-test could not isolate final callback")
last_callback_position = last_callback_match.start()
final_callback_end = windows_test.rfind(
    "\n}", last_callback_position, array_position
)
in_callback_include_source = (
    windows_test[:final_callback_end]
    + '\n#include "callback-aliases.h"'
    + windows_test[final_callback_end:]
)
try:
    reject_late_registration_directives(in_callback_include_source)
except SystemExit as error:
    if "reject late directives" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted an in-callback alias include")

before_final_callback_source = windows_test.replace(
    "static void\ntest_mutation_handle_lifetime_temp_tree",
    '#include "callback-aliases.h"\n'
    "static void\ntest_mutation_handle_lifetime_temp_tree",
    1,
)
try:
    reject_late_registration_directives(before_final_callback_source)
except SystemExit as error:
    if "reject late directives" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted an earlier callback-alias include")

guard_without_callback = windows_test.replace(
    "  || defined (test_mutation_handle_lifetime_temp_tree)\n",
    "",
    1,
)
try:
    validate_registration_macro_guard(guard_without_callback)
except SystemExit as error:
    if "callback macro guard" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted an incomplete callback guard")

guard_with_gap_token = windows_test.replace(
    guarded_array_marker + "\n#if",
    guarded_array_marker + "\nRESTORE_LIFETIME_CALLBACK_ALIASES()\n#if",
    1,
)
try:
    validate_registration_macro_guard(guard_with_gap_token)
except SystemExit as error:
    if "precede the first array element" not in str(error):
        raise
else:
    raise SystemExit("wiring self-test accepted a post-guard restore token")

print("Windows Application Verifier wiring: OK")

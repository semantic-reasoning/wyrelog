#!/usr/bin/env python3
"""Guard the native Windows Application Verifier CI contract."""

from pathlib import Path
import hashlib
import re
import sys


class FixtureContractError(ValueError):
    pass


def active_cpp_source(source: str) -> str:
    """Remove #if 0 regions and comments while preserving active strings."""
    active = True
    stack: list[tuple[bool, bool]] = []
    selected: list[str] = []
    for line in source.splitlines(keepends=True):
        directive = re.match(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", line)
        if directive:
            kind, expression = directive.groups()
            if kind in {"if", "ifdef", "ifndef"}:
                condition = expression.strip() not in {"0", "FALSE", "false"}
                stack.append((active, condition))
                active = active and condition
            elif kind == "elif":
                if not stack:
                    raise FixtureContractError("unbalanced #elif in fixture")
                parent, _ = stack[-1]
                condition = expression.strip() not in {"0", "FALSE", "false"}
                stack[-1] = (parent, condition)
                active = parent and condition
            elif kind == "else":
                if not stack:
                    raise FixtureContractError("unbalanced #else in fixture")
                parent, condition = stack[-1]
                stack[-1] = (parent, not condition)
                active = parent and not condition
            else:
                if not stack:
                    raise FixtureContractError("unbalanced #endif in fixture")
                parent, _ = stack.pop()
                active = parent
            selected.append("\n" if line.endswith("\n") else "")
        elif active:
            selected.append(line)
        else:
            selected.append("\n" if line.endswith("\n") else "")
    if stack:
        raise FixtureContractError("unterminated preprocessor region in fixture")

    text = "".join(selected)
    output: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if quote is not None:
            output.append(char)
            if char == "\\" and index + 1 < len(text):
                index += 1
                output.append(text[index])
            elif char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
            output.append(char)
        elif char == "/" and next_char == "/":
            output.extend((" ", " "))
            index += 2
            while index < len(text) and text[index] != "\n":
                output.append(" ")
                index += 1
            if index < len(text):
                output.append("\n")
        elif char == "/" and next_char == "*":
            output.extend((" ", " "))
            index += 2
            while index < len(text):
                if index + 1 < len(text) and text[index : index + 2] == "*/":
                    output.extend((" ", " "))
                    index += 1
                    break
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
        else:
            output.append(char)
        index += 1
    return "".join(output)


def function_braces(source: str, signature: str) -> tuple[int, int]:
    start = source.find(signature)
    if start < 0:
        raise FixtureContractError(f"missing active function: {signature}")
    opening = source.find("{", start + len(signature))
    if opening < 0:
        raise FixtureContractError(f"missing body for active function: {signature}")
    depth = 0
    quote: str | None = None
    index = opening
    while index < len(source):
        char = source[index]
        if quote is not None:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return opening, index
        index += 1
    raise FixtureContractError(f"unterminated active function: {signature}")


def function_body(source: str, signature: str) -> str:
    opening, closing = function_braces(source, signature)
    return source[opening + 1 : closing]


def cpp_code_only(source: str) -> str:
    """Blank string and character literals without changing source offsets."""
    output = list(source)
    quote: str | None = None
    index = 0
    while index < len(source):
        char = source[index]
        if quote is None and char in {'"', "'"}:
            quote = char
            output[index] = " "
        elif quote is not None:
            output[index] = "\n" if char == "\n" else " "
            if char == "\\" and index + 1 < len(source):
                index += 1
                output[index] = "\n" if source[index] == "\n" else " "
            elif char == quote:
                quote = None
        index += 1
    if quote is not None:
        raise FixtureContractError("unterminated literal in fixture")
    return "".join(output)


def require_ordered_patterns(
    source: str, patterns: tuple[str, ...], contract: str
) -> None:
    offset = 0
    for pattern in patterns:
        match = re.search(pattern, source[offset:])
        if match is None:
            raise FixtureContractError(f"{contract} lost active call: {pattern}")
        absolute = offset + match.start()
        depth = source[:absolute].count("{") - source[:absolute].count("}")
        if depth != 0:
            raise FixtureContractError(f"{contract} call is not top-level: {pattern}")
        offset += match.end()


def require_straight_line(source: str, contract: str) -> None:
    forbidden = (
        r"\bif\b",
        r"\belse\b",
        r"\bfor\b",
        r"\bwhile\b",
        r"\bdo\b",
        r"\bswitch\b",
        r"\bcase\b",
        r"\btry\b",
        r"\bcatch\b",
        r"\bgoto\b",
        r"\bthrow\b",
        r"\bco_return\b",
        r"\bdecltype\b",
        r"\bnoexcept\s*\(",
        r"\brequires\b",
        r"\bg_test_skip\s*\(",
        r"\bg_test_incomplete\s*\(",
        r"\bg_assert_not_reached\s*\(",
        r"\b(?:exit|_Exit|abort|longjmp)\s*\(",
        r"\b__builtin_unreachable\s*\(",
        r"\[[^\]\n]*\]\s*(?:\([^)]*\)\s*)?(?:mutable\s*)?\{",
        r"\?",
        r"&&",
        r"\|\|",
    )
    for pattern in forbidden:
        if re.search(pattern, source):
            raise FixtureContractError(
                f"{contract} contains conditional or dead control: {pattern}"
            )


def validate_secure_temp_fixture(source: str) -> None:
    source_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if source_digest != "c213bbcf99b68c8901a55e59c43249d8efe4ce8be9eb186a543dd9fa0cfe259a":
        raise FixtureContractError(
            "secure fixture changed outside its reviewed full-source allowlist"
        )
    for digraph in ("%:", "<%", "%>", "<:", ":>", "??="):
        if digraph in source:
            raise FixtureContractError(
                f"secure fixture contains rejected preprocessing token: {digraph}"
            )
    conditional_directives = [
        re.sub(r"\s+", " ", match.group(0).strip())
        for match in re.finditer(
            r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b[^\n]*",
            source,
        )
    ]
    if conditional_directives != ["#ifndef G_OS_WIN32", "#endif"]:
        raise FixtureContractError(
            "secure fixture contains an unreviewed conditional compilation path"
        )
    active = active_cpp_source(source)
    expected_bodies = {
        "ProvisionedPairFixture ()":
            "e7bd8defef11bd4bfd29f64250d8a1587ed34dd3275049203800aadb84fb182e",
        "test_secure_temp_child_lifecycle (void)":
            "b3e7a35f64937ee241ff79f7785e315c887c1ccc6983c557309c2a94721ab90b",
        "main (int argc, char **argv)":
            "5d4ef1f5bc55a843efa25188c5f9ed5f63c3656a56f72c4a4eb9fcee4145774e",
    }
    for signature, expected_digest in expected_bodies.items():
        canonical = " ".join(function_body(active, signature).split())
        observed_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if observed_digest != expected_digest:
            raise FixtureContractError(
                f"secure fixture changed outside its reviewed skeleton: {signature}"
            )
    constructor = cpp_code_only(
        function_body(active, "ProvisionedPairFixture ()")
    )
    require_straight_line(constructor, "secure fixture constructor")
    if re.search(r"\breturn\b", constructor):
        raise FixtureContractError("secure fixture constructor returns early")
    require_ordered_patterns(
        constructor,
        (
            r"\bwyl_test_make_secure_fact_root\s*\(",
            r"\bwyl_fact_graph_directory_stage_create_exact\s*\(",
            r"\bwyl_fact_graph_stage_get_windows_operation_evidence\s*\(",
            r"\bwyl_fact_graph_stage_publish_with_evidence\s*\(",
            r"\bwyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence\s*\(",
            r"\bwyl_fact_artifact_namespace_open_provisioned_pair_internal\s*\(",
        ),
        "secure fixture constructor",
    )
    lifecycle = cpp_code_only(
        function_body(active, "test_secure_temp_child_lifecycle (void)")
    )
    require_straight_line(lifecycle, "secure temp-child lifecycle")
    if re.search(r"\breturn\b", lifecycle):
        raise FixtureContractError("secure temp-child lifecycle returns early")
    require_ordered_patterns(
        lifecycle,
        (
            r"\bProvisionedPairFixture\s+fixture\s*;",
            r"\bWylSecureDuckdbFileSystem\s+filesystem\s*\(",
            r"\bfilesystem\s*\.\s*TemporaryDirectory\s*\(",
            r"\bfilesystem\s*\.\s*OpenFile\s*\(",
            r"\bfilesystem\s*\.\s*Write\s*\(",
            r"\bfilesystem\s*\.\s*FileSync\s*\(",
            r"\bfilesystem\s*\.\s*Read\s*\(",
            r"\btemporary\s*->\s*Close\s*\(",
            r"\bfilesystem\s*\.\s*TryRemoveFile\s*\(",
            r"\btemporary\s*\.\s*reset\s*\(",
        ),
        "secure temp-child lifecycle",
    )
    main = function_body(active, "main (int argc, char **argv)")
    main_code = cpp_code_only(main)
    require_straight_line(main_code, "secure fixture main")
    registration = re.search(r"\bg_test_add_func\s*\(", main_code)
    if registration is None:
        raise FixtureContractError("main does not execute the secure lifecycle test")
    registration_end = main_code.find(")", registration.end())
    if registration_end < 0:
        raise FixtureContractError("main has an unterminated test registration")
    registration_code = main_code[registration.start() : registration_end + 1]
    registration_source = main[registration.start() : registration_end + 1]
    if (
        '"/secure-duckdb/windows/temp-child/ownership"'
        not in registration_source
        or re.search(
            r",\s*test_secure_temp_child_lifecycle\s*\)", registration_code
        )
        is None
        or re.search(r"\bg_test_run\s*\(\s*\)", main_code) is None
    ):
        raise FixtureContractError("main does not execute the secure lifecycle test")
    if (
        len(re.findall(r"\breturn\b", main_code)) != 1
        or len(re.findall(r"\bg_test_run\s*\(", main_code)) != 1
        or re.search(r"\breturn\s+g_test_run\s*\(\s*\)\s*;", main_code)
        is None
    ):
        raise FixtureContractError("main must terminate only through g_test_run")
    require_ordered_patterns(
        main_code,
        (
            r"\bg_test_init\s*\(",
            r"\bg_test_add_func\s*\(",
            r"\breturn\s+g_test_run\s*\(",
        ),
        "secure fixture main",
    )


def replace_function_body(source: str, signature: str, replacement: str) -> str:
    opening, closing = function_braces(source, signature)
    return source[:opening] + replacement + source[closing + 1 :]


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
    "[AllowEmptyCollection()]",
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
if re.search(
    r"\[Parameter\(Mandatory = \$true\)\]\s*"
    r"\[AllowEmptyCollection\(\)\]\s*\[string\[\]\] \$Arguments",
    script,
) is None:
    raise SystemExit("argument-free AppVerifier images require an empty array contract")

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
libchronoid_runtime_validation = script.index(
    "throw 'Windows AppVerifier requires the libchronoid runtime directory'"
)
vcpkg_runtime_lookup = script.index(
    "$vcpkg_installed_value = [Environment]::GetEnvironmentVariable("
)
if "'VCPKG_INSTALLED_DIR', 'Process')" not in script[vcpkg_runtime_lookup:]:
    raise SystemExit("Windows AppVerifier runtime lookup must be process-local")
vcpkg_runtime_validation = script.index(
    "throw 'Windows AppVerifier requires the vcpkg runtime directory'"
)
runner_temp_validation = script.index(
    "throw 'Windows AppVerifier vcpkg root escaped RUNNER_TEMP'"
)
if not (
    output_root
    < startup_evidence
    < hosted_failure
    < administrator_failure
    < build_prerequisite
    < libchronoid_runtime_validation
    < vcpkg_runtime_lookup
    < vcpkg_runtime_validation
    < runner_temp_validation
    < required_target_check
):
    raise SystemExit(
        "Windows AppVerifier runner must preserve startup evidence before "
        "hosted-runner, administrator, build, runtime, and target prerequisite checks"
    )

runtime_helper = script[
    script.index("function Invoke-Secure-Fixture-With-RuntimePath") :
    script.index("function Invoke-Secure-Temp-Child")
]
runtime_helper_tokens = (
    "$previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
    "$runtime_prefix = [string]::Concat(",
    "$script:libchronoid_runtime_directory,",
    "$script:vcpkg_runtime_directory)",
    "$secure_path = if ([string]::IsNullOrEmpty($previous_path))",
    "[Environment]::SetEnvironmentVariable('PATH', $secure_path, 'Process')",
    "$result = Invoke-Captured -FilePath $script:secure_temp_child_path",
    "} finally {",
    "[Environment]::SetEnvironmentVariable('PATH', $previous_path, 'Process')",
)
if any(runtime_helper.count(token) != 1 for token in runtime_helper_tokens):
    raise SystemExit(
        "secure AppVerifier runtime helper must isolate canonical build and vcpkg PATHs"
    )
if [runtime_helper.index(token) for token in runtime_helper_tokens] != sorted(
    runtime_helper.index(token) for token in runtime_helper_tokens
):
    raise SystemExit(
        "secure AppVerifier runtime helper must restore PATH after direct invocation"
    )

secure_phase = script[
    script.index("function Invoke-Secure-Temp-Child") : script.index("\nif ($env:OS")
]
secure_phase_tokens = (
    "$loader_probe = Invoke-Secure-Fixture-With-RuntimePath",
    "'loader-preflight.txt'",
    "Assert-Success $loader_probe 'launch secure temp-child loader preflight'",
    "Enable-Target -ImageName $script:secure_temp_child_image",
    "$result = Invoke-Secure-Fixture-With-RuntimePath",
    "'process.txt'",
    "$entries = @(Export-Phase-Logs -Phase $phase)",
)
if any(secure_phase.count(token) != 1 for token in secure_phase_tokens):
    raise SystemExit(
        "secure AppVerifier phase must prove its loader before instrumentation"
    )
if [secure_phase.index(token) for token in secure_phase_tokens] != sorted(
    secure_phase.index(token) for token in secure_phase_tokens
):
    raise SystemExit(
        "secure AppVerifier phase must preserve preflight, enable, run, export order"
    )
secure_clear = "Clear-Target -ImageName $script:secure_temp_child_image"
if (
    secure_phase.count(secure_clear) != 2
    or secure_phase.index(secure_clear) > secure_phase.index(secure_phase_tokens[0])
    or secure_phase.rindex(secure_clear) < secure_phase.index(secure_phase_tokens[-1])
):
    raise SystemExit("secure AppVerifier phase must bracket both direct launches")
for token in (
    "libchronoid_runtime_directory = $script:libchronoid_runtime_directory",
    "vcpkg_installed_directory = $script:vcpkg_installed_directory",
    "vcpkg_runtime_directory = $script:vcpkg_runtime_directory",
    "duckdb_linkage = 'source-pinned-static'",
):
    if script.count(token) != 1:
        raise SystemExit(f"Windows AppVerifier metadata lost runtime token: {token}")


def validate_runtime_path_contract(
    candidate: str,
    *,
    enforce_runner_digest: bool = True,
    enforce_slice_digests: bool = True,
) -> None:
    candidate_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    if (
        enforce_runner_digest
        and candidate_digest
        != "f69a421e81d3fbd1f4704c5254d1dab79f0cc97d9b8a12ffb567479aa5794a14"
    ):
        raise FixtureContractError(
            "Windows AppVerifier runner changed outside its reviewed source allowlist"
        )
    required = (
        "$libchronoid_runtime_value -notmatch '^[A-Za-z]:[\\\\/]'",
        "$libchronoid_runtime_value.Contains([System.IO.Path]::PathSeparator)",
        "$script:libchronoid_runtime_directory = (",
        "$expected_libchronoid_runtime, [StringComparison]::OrdinalIgnoreCase",
        "$vcpkg_installed_value -notmatch '^[A-Za-z]:[\\\\/]'",
        "$vcpkg_installed_value.Contains([System.IO.Path]::PathSeparator)",
        "$script:vcpkg_runtime_directory = (",
        "$expected_vcpkg_runtime, [StringComparison]::OrdinalIgnoreCase",
        "$script:vcpkg_installed_directory.StartsWith(",
        "$runner_temp_prefix, [StringComparison]::OrdinalIgnoreCase",
        "$script:runner_temp_directory.TrimEnd([char[]]@(",
        "[System.IO.Path]::AltDirectorySeparatorChar))",
        "$loader_probe = Invoke-Secure-Fixture-With-RuntimePath",
        "Assert-Success $loader_probe 'launch secure temp-child loader preflight'",
        "$result = Invoke-Secure-Fixture-With-RuntimePath",
        "[Environment]::SetEnvironmentVariable('PATH', $previous_path, 'Process')",
        "libchronoid_runtime_directory = $script:libchronoid_runtime_directory",
        "duckdb_linkage = 'source-pinned-static'",
    )
    for token in required:
        if token not in candidate:
            raise FixtureContractError(
                f"Windows AppVerifier runtime contract lost token: {token}"
            )
    if re.search(
        r"\$libchronoid_runtime_value = Join-Path \(\s*"
        r"Join-Path \$script:build_root 'subprojects'\) 'libchronoid'",
        candidate,
    ) is None:
        raise FixtureContractError(
            "libchronoid runtime must be the literal in-tree subproject child"
        )
    if re.search(
        r"\$script:runner_temp_directory\.TrimEnd\(\[char\[\]\]@\(\s*"
        r"\[System\.IO\.Path\]::DirectorySeparatorChar,\s*"
        r"\[System\.IO\.Path\]::AltDirectorySeparatorChar\)\)",
        candidate,
    ) is None:
        raise FixtureContractError(
            "RUNNER_TEMP trimming must include both Windows separators"
        )
    candidate_helper = candidate[
        candidate.index("function Invoke-Secure-Fixture-With-RuntimePath") :
        candidate.index("function Invoke-Secure-Temp-Child")
    ]
    helper_digest = hashlib.sha256(candidate_helper.encode("utf-8")).hexdigest()
    if (
        enforce_slice_digests
        and helper_digest
        != "81a352686b425790b42ede7091ca49d55c22d6df2a2d46731568fa6a00f15d96"
    ):
        raise FixtureContractError(
            "secure runtime helper changed outside its reviewed full-body allowlist"
        )
    if re.search(
        r"\$runtime_prefix = \[string\]::Concat\(\s*"
        r"\$script:libchronoid_runtime_directory,\s*"
        r"\[System\.IO\.Path\]::PathSeparator,\s*"
        r"\$script:vcpkg_runtime_directory\)",
        candidate_helper,
    ) is None:
        raise FixtureContractError(
            "secure runtime prefix must order libchronoid before vcpkg"
        )
    if re.search(
        r"\$secure_path = if \(\[string\]::IsNullOrEmpty\(\$previous_path\)\) \{\s*"
        r"\$runtime_prefix\s*\} else \{\s*"
        r"\[string\]::Concat\(\$runtime_prefix,\s*"
        r"\[System\.IO\.Path\]::PathSeparator,\s*\$previous_path\)\s*\}",
        candidate_helper,
    ) is None:
        raise FixtureContractError(
            "secure runtime prefix must precede the inherited process PATH"
        )
    secure_path_references = re.findall(
        r"\$(?:script:secure_temp_child_path|\{script:secure_temp_child_path\})",
        candidate_helper,
        flags=re.IGNORECASE,
    )
    captured_calls = re.findall(
        r"\bInvoke-Captured\b", candidate_helper, flags=re.IGNORECASE
    )
    if (
        len(secure_path_references) != 1
        or len(captured_calls) != 1
        or candidate_helper.count(
            "Invoke-Captured -FilePath $script:secure_temp_child_path"
        )
        != 1
    ):
        raise FixtureContractError("secure runtime helper must launch one exact image")
    if re.search(
        r"&|\b(?:Start-Process|Invoke-Expression)\b|"
        r"test-secure-duckdb-temp-child-windows\.exe",
        candidate_helper,
        flags=re.IGNORECASE,
    ):
        raise FixtureContractError(
            "secure runtime helper contains an unreviewed launch route"
        )
    if re.search(
        r"\b(?:return|exit|throw|break|continue)\b",
        candidate_helper,
        flags=re.IGNORECASE,
    ):
        raise FixtureContractError("secure runtime helper contains early termination")
    helper_order = (
        "try {",
        "[Environment]::SetEnvironmentVariable('PATH', $secure_path, 'Process')",
        "$result = Invoke-Captured -FilePath $script:secure_temp_child_path",
        "} finally {",
        "[Environment]::SetEnvironmentVariable('PATH', $previous_path, 'Process')",
        "$result\n}",
    )
    helper_offsets = [candidate_helper.index(token) for token in helper_order]
    if helper_offsets != sorted(helper_offsets):
        raise FixtureContractError(
            "secure runtime helper lost try, launch, finally, restore order"
        )
    reviewed_helper = """function Invoke-Secure-Fixture-With-RuntimePath {
  param([Parameter(Mandatory = $true)] [string] $LogPath)

  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')
  $runtime_prefix = [string]::Concat(
    $script:libchronoid_runtime_directory,
    [System.IO.Path]::PathSeparator,
    $script:vcpkg_runtime_directory)
  $secure_path = if ([string]::IsNullOrEmpty($previous_path)) {
    $runtime_prefix
  } else {
    [string]::Concat($runtime_prefix, [System.IO.Path]::PathSeparator,
      $previous_path)
  }
  try {
    [Environment]::SetEnvironmentVariable('PATH', $secure_path, 'Process')
    $result = Invoke-Captured -FilePath $script:secure_temp_child_path -Arguments @(
    ) -LogPath $LogPath
  } finally {
    [Environment]::SetEnvironmentVariable('PATH', $previous_path, 'Process')
  }
  $result
}"""
    if candidate_helper.strip() != reviewed_helper:
        raise FixtureContractError(
            "secure runtime helper changed outside its explicit source allowlist"
        )
    candidate_phase = candidate[
        candidate.index("function Invoke-Secure-Temp-Child") :
        candidate.index("\nif ($env:OS")
    ]
    phase_digest = hashlib.sha256(candidate_phase.encode("utf-8")).hexdigest()
    if (
        enforce_slice_digests
        and phase_digest
        != "c5bf2d01f381cae8793342a6e20386f4be50682def3f2c03c176da8075e427c3"
    ):
        raise FixtureContractError(
            "secure AppVerifier phase changed outside its reviewed source allowlist"
        )
    phase_direct_references = re.findall(
        r"\$(?:script:secure_temp_child_path|\{script:secure_temp_child_path\})",
        candidate_phase,
        flags=re.IGNORECASE,
    )
    if (
        candidate_phase.count("Invoke-Secure-Fixture-With-RuntimePath") != 2
        or phase_direct_references
    ):
        raise FixtureContractError(
            "secure AppVerifier phase must use only its two reviewed helper calls"
        )
    if re.search(
        r"&|\b(?:Invoke-Captured|Start-Process|Invoke-Expression)\b|"
        r"test-secure-duckdb-temp-child-windows\.exe",
        candidate_phase,
        flags=re.IGNORECASE,
    ):
        raise FixtureContractError(
            "secure AppVerifier phase contains an unreviewed launch route"
        )
    if re.search(
        r"\b(?:return|exit|break|continue)\b",
        candidate_phase,
        flags=re.IGNORECASE,
    ):
        raise FixtureContractError(
            "secure AppVerifier phase contains early termination"
        )
    ordered = (
        "$loader_probe = Invoke-Secure-Fixture-With-RuntimePath",
        "Assert-Success $loader_probe 'launch secure temp-child loader preflight'",
        "Enable-Target -ImageName $script:secure_temp_child_image",
        "$result = Invoke-Secure-Fixture-With-RuntimePath",
        "$entries = @(Export-Phase-Logs -Phase $phase)",
    )
    offsets = [candidate_phase.index(token) for token in ordered]
    if offsets != sorted(offsets):
        raise FixtureContractError(
            "secure runtime preflight and instrumented launch are out of order"
        )
    reviewed_phase = """function Invoke-Secure-Temp-Child {
  $phase = New-Phase 'secure-temp-child'
  $env:VERIFIER_LOG_PATH = $phase
  Clear-Target -ImageName $script:secure_temp_child_image -EvidenceDirectory $phase
  $loader_probe = Invoke-Secure-Fixture-With-RuntimePath -LogPath (
    Join-Path $phase 'loader-preflight.txt')
  Assert-Success $loader_probe 'launch secure temp-child loader preflight'
  Enable-Target -ImageName $script:secure_temp_child_image -EvidenceDirectory $phase
  $result = Invoke-Secure-Fixture-With-RuntimePath -LogPath (
    Join-Path $phase 'process.txt')
  $entries = @(Export-Phase-Logs -Phase $phase)
  if ($result.ExitCode -ne 0) {
    throw "instrumented secure temp-child fixture exited $($result.ExitCode)"
  }
  Assert-Clean-Entries -Entries $entries -PhaseName 'secure temp-child'
  Clear-Target -ImageName $script:secure_temp_child_image -EvidenceDirectory $phase
}"""
    if candidate_phase.strip() != reviewed_phase:
        raise FixtureContractError(
            "secure AppVerifier phase changed outside its explicit source allowlist"
        )


validate_runtime_path_contract(script)
runtime_mutations = {
    "libchronoid-drive-qualified": (
        "$libchronoid_runtime_value -notmatch '^[A-Za-z]:[\\\\/]'"
    ),
    "libchronoid-path-list": (
        "$libchronoid_runtime_value.Contains([System.IO.Path]::PathSeparator)"
    ),
    "literal-libchronoid-child": (
        "$libchronoid_runtime_value = Join-Path ("
    ),
    "libchronoid-canonical-equality": (
        "$expected_libchronoid_runtime, [StringComparison]::OrdinalIgnoreCase"
    ),
    "libchronoid-runtime-prefix": "$script:libchronoid_runtime_directory,",
    "vcpkg-runtime-prefix": "$script:vcpkg_runtime_directory)",
    "libchronoid-runtime-metadata": (
        "libchronoid_runtime_directory = $script:libchronoid_runtime_directory"
    ),
    "drive-qualified-root": "$vcpkg_installed_value -notmatch '^[A-Za-z]:[\\\\/]'",
    "literal-bin-child": "$expected_vcpkg_runtime, [StringComparison]::OrdinalIgnoreCase",
    "hosted-containment": "$script:vcpkg_installed_directory.StartsWith(",
    "separator-trim": "[System.IO.Path]::AltDirectorySeparatorChar))",
    "primary-separator-trim": "[System.IO.Path]::DirectorySeparatorChar,",
    "loader-preflight": "$loader_probe = Invoke-Secure-Fixture-With-RuntimePath",
    "runtime-helper": "$result = Invoke-Secure-Fixture-With-RuntimePath",
    "exact-path-restoration": (
        "[Environment]::SetEnvironmentVariable('PATH', $previous_path, 'Process')"
    ),
}
for mutation_name, removed_token in runtime_mutations.items():
    mutation = script.replace(removed_token, f"removed-{mutation_name}", 1)
    try:
        validate_runtime_path_contract(
            mutation,
            enforce_runner_digest=False,
            enforce_slice_digests=False,
        )
    except (FixtureContractError, ValueError):
        continue
    raise SystemExit(
        f"Windows AppVerifier checker accepted {mutation_name} negative control"
    )
runtime_prefix = (
    "  $runtime_prefix = [string]::Concat(\n"
    "    $script:libchronoid_runtime_directory,\n"
    "    [System.IO.Path]::PathSeparator,\n"
    "    $script:vcpkg_runtime_directory)"
)
runtime_prefix_mutations = {
    "reversed-runtime-prefix": (
        "  $runtime_prefix = [string]::Concat(\n"
        "    $script:vcpkg_runtime_directory,\n"
        "    [System.IO.Path]::PathSeparator,\n"
        "    $script:libchronoid_runtime_directory)"
    ),
    "tests-directory-substitution": (
        "  $runtime_prefix = [string]::Concat(\n"
        "    $tests_root,\n"
        "    [System.IO.Path]::PathSeparator,\n"
        "    $script:vcpkg_runtime_directory)"
    ),
    "missing-vcpkg-runtime-prefix": (
        "  $runtime_prefix = $script:libchronoid_runtime_directory"
    ),
}
for mutation_name, replacement in runtime_prefix_mutations.items():
    mutation = script.replace(runtime_prefix, replacement, 1)
    try:
        validate_runtime_path_contract(
            mutation,
            enforce_runner_digest=False,
            enforce_slice_digests=False,
        )
    except (FixtureContractError, ValueError):
        continue
    raise SystemExit(
        f"Windows AppVerifier checker accepted {mutation_name} negative control"
    )
early_launch_mutation = script.replace(
    "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
    "  & $script:secure_temp_child_path\n"
    "  return\n\n"
    "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
    1,
)
try:
    validate_runtime_path_contract(
        early_launch_mutation,
        enforce_runner_digest=False,
        enforce_slice_digests=False,
    )
except (FixtureContractError, ValueError):
    pass
else:
    raise SystemExit(
        "Windows AppVerifier checker accepted early untrusted launch negative control"
    )
braced_launch_mutation = script.replace(
    "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
    "  if ($true) { return (Invoke-Captured -FilePath "
    "${script:secure_temp_child_path} -Arguments @() -LogPath $LogPath) }\n\n"
    "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
    1,
)
try:
    validate_runtime_path_contract(
        braced_launch_mutation,
        enforce_runner_digest=False,
        enforce_slice_digests=False,
    )
except (FixtureContractError, ValueError):
    pass
else:
    raise SystemExit(
        "Windows AppVerifier checker accepted braced pre-PATH launch negative control"
    )
for direct_reference in (
    "$script:secure_temp_child_path",
    "$ScRiPt:SeCuRe_TeMp_ChIlD_PaTh",
    "${script:secure_temp_child_path}",
    "${ScRiPt:SeCuRe_TeMp_ChIlD_PaTh}",
):
    helper_bypass_mutation = script.replace(
        "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
        f"  & {direct_reference}\n"
        "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
        1,
    )
    try:
        validate_runtime_path_contract(
            helper_bypass_mutation,
            enforce_runner_digest=False,
            enforce_slice_digests=False,
        )
    except (FixtureContractError, ValueError):
        continue
    raise SystemExit(
        "Windows AppVerifier checker accepted direct helper bypass negative control: "
        f"{direct_reference}"
    )
for direct_launch in (
    "& (Join-Path $tests_root 'test-secure-duckdb-temp-child-windows.exe')",
    "Start-Process -FilePath (Join-Path $tests_root "
    "'test-secure-duckdb-temp-child-windows.exe') -Wait",
    "$p = Get-Variable -Scope Script -Name secure_temp_child_path "
    "-ValueOnly; & $p",
    "$p = Get-Variable -Scope Script -Name secure_temp_child_path "
    "-ValueOnly; start $p -Wait",
    "$p = Get-Variable -Scope Script -Name secure_temp_child_path "
    "-ValueOnly; [System.Diagnostics.Process]::Start($p)",
    "StArT-PrOcEsS -FilePath (Join-Path $tests_root "
    "'TeSt-SeCuRe-DuCkDb-TeMp-ChIlD-WiNdOwS.ExE') -Wait",
):
    helper_launch_mutation = script.replace(
        "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
        f"  {direct_launch}\n"
        "  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')",
        1,
    )
    try:
        validate_runtime_path_contract(
            helper_launch_mutation,
            enforce_runner_digest=False,
            enforce_slice_digests=False,
        )
    except (FixtureContractError, ValueError):
        continue
    raise SystemExit(
        "Windows AppVerifier checker accepted literal helper launch negative control: "
        f"{direct_launch}"
    )
phase_launch_mutation = script.replace(
    "function Invoke-Secure-Temp-Child {\n",
    "function Invoke-Secure-Temp-Child {\n"
    "  & ${script:secure_temp_child_path}\n"
    "  return\n",
    1,
)
try:
    validate_runtime_path_contract(
        phase_launch_mutation,
        enforce_runner_digest=False,
        enforce_slice_digests=False,
    )
except (FixtureContractError, ValueError):
    pass
else:
    raise SystemExit(
        "Windows AppVerifier checker accepted secure-phase early launch negative control"
    )
for direct_reference in (
    "$script:secure_temp_child_path",
    "$ScRiPt:SeCuRe_TeMp_ChIlD_PaTh",
    "${script:secure_temp_child_path}",
    "${ScRiPt:SeCuRe_TeMp_ChIlD_PaTh}",
):
    phase_bypass_mutation = script.replace(
        "function Invoke-Secure-Temp-Child {\n",
        f"function Invoke-Secure-Temp-Child {{\n  & {direct_reference}\n",
        1,
    )
    try:
        validate_runtime_path_contract(
            phase_bypass_mutation,
            enforce_runner_digest=False,
            enforce_slice_digests=False,
        )
    except (FixtureContractError, ValueError):
        continue
    raise SystemExit(
        "Windows AppVerifier checker accepted direct secure-phase bypass "
        f"negative control: {direct_reference}"
    )
for direct_launch in (
    "& (Join-Path $tests_root 'test-secure-duckdb-temp-child-windows.exe')",
    "Start-Process -FilePath (Join-Path $tests_root "
    "'test-secure-duckdb-temp-child-windows.exe') -Wait",
    "$p = Get-Variable -Scope Script -Name secure_temp_child_path "
    "-ValueOnly; & $p",
    "$p = Get-Variable -Scope Script -Name secure_temp_child_path "
    "-ValueOnly; start $p -Wait",
    "$p = Get-Variable -Scope Script -Name secure_temp_child_path "
    "-ValueOnly; [System.Diagnostics.Process]::Start($p)",
    "StArT-PrOcEsS -FilePath (Join-Path $tests_root "
    "'TeSt-SeCuRe-DuCkDb-TeMp-ChIlD-WiNdOwS.ExE') -Wait",
):
    phase_launch_mutation = script.replace(
        "function Invoke-Secure-Temp-Child {\n",
        f"function Invoke-Secure-Temp-Child {{\n  {direct_launch}\n",
        1,
    )
    try:
        validate_runtime_path_contract(
            phase_launch_mutation,
            enforce_runner_digest=False,
            enforce_slice_digests=False,
        )
    except (FixtureContractError, ValueError):
        continue
    raise SystemExit(
        "Windows AppVerifier checker accepted literal secure-phase launch "
        f"negative control: {direct_launch}"
    )
for return_keyword in ("return", "ReTuRn"):
    phase_return_mutation = script.replace(
        "function Invoke-Secure-Temp-Child {\n",
        f"function Invoke-Secure-Temp-Child {{\n  {return_keyword}\n",
        1,
    )
    try:
        validate_runtime_path_contract(
            phase_return_mutation,
            enforce_runner_digest=False,
            enforce_slice_digests=False,
        )
    except (FixtureContractError, ValueError):
        continue
    raise SystemExit(
        "Windows AppVerifier checker accepted secure-phase early return "
        f"negative control: {return_keyword}"
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

secure_temp_fixture_path = (
    root / "tests" / "test-secure-duckdb-temp-child-windows.cc"
)
if not secure_temp_fixture_path.is_file():
    raise SystemExit("missing native Windows secure-DuckDB temp-child fixture")
secure_temp_fixture = secure_temp_fixture_path.read_text(encoding="utf-8")
for token in (
    "wyl_test_make_secure_fact_root",
    "wyl_fact_graph_directory_stage_create_exact",
    "wyl_fact_graph_stage_get_windows_operation_evidence",
    "wyl_fact_graph_stage_publish_with_evidence",
    "wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence",
    "wyl_fact_artifact_namespace_open_provisioned_pair_internal",
    "WylSecureDuckdbFileSystem",
    "TemporaryDirectory",
    "duckdb_temp_storage_S32K-0.tmp",
    "TempChildrenCreatedForTest",
    "TryRemoveFile",
):
    if token not in secure_temp_fixture:
        raise SystemExit(f"secure temp-child fixture lost runtime token: {token}")
try:
    validate_secure_temp_fixture(secure_temp_fixture)
except FixtureContractError as error:
    raise SystemExit(str(error)) from error

lifecycle_opening, lifecycle_closing = function_braces(
    secure_temp_fixture, "test_secure_temp_child_lifecycle (void)"
)
lifecycle_source_body = secure_temp_fixture[
    lifecycle_opening + 1 : lifecycle_closing
]

mutations = {
    "inactive-copy": (
        "#if 0\n" + secure_temp_fixture + "\n#endif\n"
        "int main (int argc, char **argv) { return argc == 0 && argv == nullptr; }\n"
    ),
    "comment-only-constructor": replace_function_body(
        secure_temp_fixture,
        "ProvisionedPairFixture ()",
        "{ /* wyl_test_make_secure_fact_root "
        "wyl_fact_graph_directory_stage_create_exact "
        "wyl_fact_graph_stage_get_windows_operation_evidence "
        "wyl_fact_graph_stage_publish_with_evidence "
        "wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence "
        "wyl_fact_artifact_namespace_open_provisioned_pair_internal */ }",
    ),
    "trivial-main": replace_function_body(
        secure_temp_fixture,
        "main (int argc, char **argv)",
        "{ (void) argc; (void) argv; return 0; }",
    ),
    "string-only-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{ \"ProvisionedPairFixture fixture; "
        "WylSecureDuckdbFileSystem filesystem( filesystem.TemporaryDirectory( "
        "filesystem.OpenFile( filesystem.Write( filesystem.FileSync( "
        "filesystem.Read( temporary->Close( filesystem.TryRemoveFile( "
        "temporary.reset(\"; }",
    ),
    "parenthesized-zero-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{\n#if (0)\nProvisionedPairFixture fixture;\n#else\nreturn;\n#endif\n}",
    ),
    "ifndef-windows-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{\n#ifndef G_OS_WIN32\nProvisionedPairFixture fixture;\n"
        "#else\nreturn;\n#endif\n}",
    ),
    "dead-if-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{ if (false) { ProvisionedPairFixture fixture; "
        "WylSecureDuckdbFileSystem filesystem( fixture.namespace_, false); "
        "filesystem.TemporaryDirectory(); filesystem.OpenFile(); "
        "filesystem.Write(); filesystem.FileSync(); filesystem.Read(); "
        "temporary->Close(); filesystem.TryRemoveFile(); temporary.reset(); } }",
    ),
    "dead-main-registration": replace_function_body(
        secure_temp_fixture,
        "main (int argc, char **argv)",
        "{ if (false) { g_test_init(&argc, &argv, nullptr); "
        "g_test_add_func(\"/secure-duckdb/windows/temp-child/ownership\", "
        "test_secure_temp_child_lifecycle); return g_test_run(); } return 0; }",
    ),
    "digraph-inactive-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{\n%:if 0\nProvisionedPairFixture fixture;\n"
        "%:else\nreturn;\n%:endif\n}",
    ),
    "dead-lambda-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{ auto dead = [] { ProvisionedPairFixture fixture; "
        "WylSecureDuckdbFileSystem filesystem( fixture.namespace_, false); "
        "filesystem.TemporaryDirectory(); filesystem.OpenFile(); "
        "filesystem.Write(); filesystem.FileSync(); filesystem.Read(); "
        "temporary->Close(); filesystem.TryRemoveFile(); temporary.reset(); }; "
        "(void) dead; }",
    ),
    "quick-exit-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{ std::quick_exit (0);" + lifecycle_source_body + "}",
    ),
    "sizeof-lifecycle": replace_function_body(
        secure_temp_fixture,
        "test_secure_temp_child_lifecycle (void)",
        "{ ProvisionedPairFixture fixture; "
        "WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false); "
        "(void) sizeof ((filesystem.TemporaryDirectory (), "
        "filesystem.OpenFile (), filesystem.Write (), filesystem.FileSync (), "
        "filesystem.Read (), temporary->Close (), filesystem.TryRemoveFile (), "
        "temporary.reset (), 0)); }",
    ),
    "macro-elided-registration": (
        "#define g_test_add_func(...) ((void) 0)\n" + secure_temp_fixture
    ),
    "global-quick-exit": (
        "#include <cstdlib>\n"
        "static const int early_success = (std::quick_exit (0), 0);\n"
        + secure_temp_fixture
    ),
}
for mutation_name, mutation in mutations.items():
    try:
        validate_secure_temp_fixture(mutation)
    except FixtureContractError:
        continue
    raise SystemExit(
        f"secure fixture checker accepted {mutation_name} negative control"
    )

meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
for target in (
    "test-windows-appverifier-probe-dll",
    "test-windows-appverifier-probe",
    "test-secure-duckdb-temp-child-windows",
):
    if target not in meson:
        raise SystemExit(f"missing Windows AppVerifier probe target: {target}")
probe = meson.index("'test-windows-appverifier-probe-dll'")
guard = meson.rindex("if host_machine.system() == 'windows'", 0, probe)
if ".allowed()" not in meson[guard:probe]:
    raise SystemExit("AppVerifier probes must stay inside the Windows hook gate")
secure_target = meson.index("'test-secure-duckdb-temp-child-windows'")
secure_target_end = meson.index("\n    )", secure_target) + len("\n    )")
secure_target_block = meson[secure_target:secure_target_end]
for token in (
    "wyrelog_handle_test_seams_dep",
    "duckdb_dep",
    "fact_test_support_deps",
):
    if token not in secure_target_block:
        raise SystemExit(f"secure temp-child target lost dependency: {token}")
if "wyrelog_dep" in secure_target_block:
    raise SystemExit("secure temp-child target must not link the shipped library")
if meson.count("test('secure-duckdb-temp-child-windows'") != 1:
    raise SystemExit("secure temp-child fixture must have one Meson test selector")


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
        "test-windows-appverifier-probe-dll "
        "test-secure-duckdb-temp-child-windows"
    )
    if windows.count(probe_compile) != 1 or windows.index(probe_compile) > run_start:
        raise SystemExit(f"{workflow_name} must build verifier probes before the gate")
    ordinary_secure_selector = (
        "meson test -C builddir secure-duckdb-bridge "
        "secure-duckdb-recording-filesystem secure-duckdb-temp-child-windows"
    )
    if windows.count(ordinary_secure_selector) != 1:
        raise SystemExit(
            f"{workflow_name} must run the secure temp-child fixture normally"
        )
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
    "fact-artifact-namespace-windows-temp-root-wrapper-ownership",
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

for token in (
    "function Invoke-Secure-Temp-Child",
    "secure-temp-child",
    "test-secure-duckdb-temp-child-windows.exe",
    "$script:secure_temp_child_image",
    "Invoke-Secure-Temp-Child",
    "secure_temp_child_image = $script:secure_temp_child_image",
):
    if token not in script:
        raise SystemExit(f"AppVerifier secure temp-child phase drifted: {token}")

secure_phase = script[
    script.index("function Invoke-Secure-Temp-Child") : script.index(
        "\nif ($env:OS", script.index("function Invoke-Secure-Temp-Child")
    )
]
secure_phase_route = (
    "New-Phase 'secure-temp-child'",
    "Clear-Target -ImageName $script:secure_temp_child_image",
    "$loader_probe = Invoke-Secure-Fixture-With-RuntimePath",
    "Assert-Success $loader_probe 'launch secure temp-child loader preflight'",
    "Enable-Target -ImageName $script:secure_temp_child_image",
    "$result = Invoke-Secure-Fixture-With-RuntimePath",
    "Export-Phase-Logs -Phase $phase",
    "Assert-Clean-Entries -Entries $entries -PhaseName 'secure temp-child'",
    "Clear-Target -ImageName $script:secure_temp_child_image",
)
phase_offsets = []
search_from = 0
for token in secure_phase_route:
    offset = secure_phase.find(token, search_from)
    if offset < 0:
        raise SystemExit(f"secure temp-child phase lost ordered operation: {token}")
    phase_offsets.append(offset)
    search_from = offset + len(token)
if "$script:meson_path" in secure_phase:
    raise SystemExit("secure temp-child must run as its own image, not through Meson")
if "test-secure-duckdb-temp-child-windows.exe" in artifact_phase:
    raise SystemExit("secure temp-child image must not be folded into artifact-suite")
invoke_secure = script.index("  Invoke-Secure-Temp-Child")
final_cleanup = script.index("  foreach ($image in @(")
if not invoke_secure < script.index("} catch {", invoke_secure) < final_cleanup:
    raise SystemExit("secure temp-child phase must precede fail-closed cleanup")
if "$script:secure_temp_child_image" not in script[final_cleanup:]:
    raise SystemExit("final cleanup lost the secure temp-child image")

documentation = (
    root / "docs" / "windows-artifact-handle-verifier.md"
).read_text(encoding="utf-8")
for token in (
    "secure-temp-child",
    "test-secure-duckdb-temp-child-windows.exe",
    "WylSecureDuckdbFileSystem",
    "provisioned pair",
):
    if token not in documentation:
        raise SystemExit(f"AppVerifier documentation lost secure phase token: {token}")

print("Windows Application Verifier wiring: OK")

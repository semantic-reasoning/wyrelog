#!/usr/bin/env python3
"""Structural guard for issue #623's restart-safe driver boundary."""

from __future__ import annotations

import ast
import functools
import hashlib
import pathlib
import re
import sys
from collections.abc import Mapping


FILES = (
    "wyrelog/fact/graph-artifact-transition-posix-private.c",
    "wyrelog/fact/graph-artifact-transition-posix-private.h",
    "wyrelog/fact/graph-artifact-namespace-private.c",
    "wyrelog/fact/graph-artifact-transition-windows-private.c",
    "wyrelog/fact/graph-artifact-transition-windows-private.h",
    "wyrelog/fact/graph-artifact-windows-locator-private.c",
    "wyrelog/fact/graph-artifact-windows-locator-private.h",
    "tests/fact-artifact-transition-driver-fixture.c",
    "tests/fact-artifact-transition-driver-fixture.h",
    "tests/fact-test-support.c",
    "tests/fact-test-support.h",
    "tests/test-fact-artifact-transition-driver.c",
    "tests/test-fact-artifact-transition-posix.c",
    "tests/test-fact-artifact-transition-windows.c",
    "meson.build",
    "meson/wirelog-dependency/meson.build",
    "wyrelog/meson.build",
    "tests/meson.build",
    ".github/workflows/ci-pr.yml",
    ".github/workflows/ci-main.yml",
)


TRIGRAPHS = {
    "??=": "#",
    "??/": "\\",
    "??'": "^",
    "??(": "[",
    "??)": "]",
    "??!": "|",
    "??<": "{",
    "??>": "}",
    "??-": "~",
}

ASSERTION_BACKEND_SYMBOLS = (
    "g_assertion_message",
    "g_assertion_message_expr",
    "g_assertion_message_cmpnum",
    "g_assertion_message_cmpint",
    "g_assertion_message_cmpstr",
    "g_assertion_message_cmpstrv",
    "g_assertion_message_error",
)

ASSERTION_SYMBOLS = (
    "g_assert_true",
    "g_assert_false",
    "g_assert_nonnull",
    "g_assert_null",
    "g_assert_no_error",
    "g_assert_error",
    "g_assert_cmpint",
    "g_assert_cmpuint",
    "g_assert_cmpstr",
    "g_assert_cmpmem",
    "g_assert_not_reached",
    *ASSERTION_BACKEND_SYMBOLS,
    "G_DISABLE_ASSERT",
    "G_DISABLE_CHECKS",
)

COMPILER_PROTECTED_SYMBOLS = (
    "GetHandleInformation",
    "IsValidSid",
    "HANDLE_FLAG_INHERIT",
    "wyl_fact_graph_win_validate_protected_owner_acl_for_user",
    "WYRELOG_E_OK",
    "WYRELOG_E_INVALID",
    "WYRELOG_E_NOMEM",
    "WYRELOG_E_IO",
    "WYRELOG_E_CRYPTO",
    "WYRELOG_E_POLICY",
    "WYRELOG_E_AUTH",
    "WYRELOG_E_INTERNAL",
    "WYRELOG_E_EXEC",
    "WYRELOG_E_NOT_FOUND",
    "WYRELOG_E_BREAK_GLASS_DISABLED",
    "WYRELOG_E_BUSY",
    "WYRELOG_E_CANCELLED",
    "WYRELOG_E_CONFLICT",
    *ASSERTION_SYMBOLS,
)

TOKEN_PASTE_ALLOWLIST = {
    "tests/test-fact-artifact-transition-driver.c": (
        "#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
    ),
    "tests/test-fact-artifact-transition-posix.c": (
        "#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        "#define PF(name) WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_ ## name",
    ),
    "tests/test-fact-artifact-transition-windows.c": (
        "#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        "#define WF(name) WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_ ## name",
    ),
    "wyrelog/wyctl/wyctl-publication-backend-private.c": (
        "#define WYCTL_PUB_CONCRETE(op) wyctl_publication_windows_ ## op",
        "#define WYCTL_PUB_CONCRETE(op) wyctl_publication_posix_ ## op",
    ),
    "wyrelog/daemon/http.c": (
        "#define WYL_DAEMON_POLICY_WRITE_OWNER_ENUM(symbol, name) "
        "WYL_DAEMON_POLICY_WRITE_OWNER_ ## symbol,",
        "#define WYL_DAEMON_POLICY_WRITE_OWNER_NAME(symbol, name) "
        "[WYL_DAEMON_POLICY_WRITE_OWNER_ ## symbol] = #name,",
    ),
}

CXX_SOURCE_DIGESTS = {
    "wyrelog/fact/secure-duckdb-bridge-private.cc":
        "4ce1c455c8e63e4e1a1968f98649a21ca247f2f761a671e8a25fb0c5bd3d73ff",
    "wyrelog/fact/secure-duckdb-file-handle-private.cc":
        "e8bc7ae828e424cf8ba18828d1b966e12b0e561d60237a5ea745499389968d36",
    "wyrelog/fact/secure-duckdb-file-handle-private.hpp":
        "260beeedcd799a2e02d8a562a5c46faf311331276eb62d4f29bcd4dc7e5892d7",
    "wyrelog/fact/secure-duckdb-filesystem-private.cc":
        "2d4993079472ba1b23162b4716322b62df38215af80f49b11dd6e3edc3d1e3ab",
    "wyrelog/fact/secure-duckdb-filesystem-private.hpp":
        "4b64f8c807ab167a08f039af3c4e835f74058236217a7c8da7fdfa2708f71ea2",
}

PROTECTED_INCLUDE_DIGESTS = {
    "tests/test-fact-artifact-transition-driver.c":
        "c15817aeb1aea0593c9b7d0af33582e1228d61ba8b9501b55d3197d306b5b8b6",
    "tests/test-fact-artifact-transition-posix.c":
        "aa9c8004d6162f88c396e2ae3e74a5d8dbcdd5c396287315a42b76480dc1cf27",
    "tests/test-fact-artifact-transition-windows.c":
        "4e19001f0567a0a9fc63b6094474840bf9a516ced48f3b7005a84bbcdcaf93fc",
    "tests/fact-artifact-transition-driver-fixture.c":
        "74a975256e7128de001fb2729451d1e8e0fd174d0d2e86b5d7171b06fc28b842",
    "tests/fact-artifact-transition-driver-fixture.h":
        "712d2bd9b4daac5a7761c41fc00ac0b863b2097c574b81c62d8851b7bbac7a69",
    "tests/fact-test-support.c":
        "3434434d9b44519041ffcb447df27700eee8c7651c882afcda9aec40203fc9ff",
    "tests/fact-test-support.h":
        "6f68c68513d1dd2ee687735b77fb3de05e6ddca4917269d9d615e1e4aab75bee",
}

PROTECTED_DIRECTIVE_DIGESTS = {
    "wyrelog/fact/graph-artifact-transition-windows-private.c":
        "75f0c23580c6d2e7263bd49667b9f99950ed637741ac84e1b0d63e92af8b772f",
    "tests/test-fact-artifact-transition-windows.c":
        "107ffd8238dacceccebe05d94969aa38f4632464581051f120cb59a4845652a1",
}

TEST_HEADER_INVENTORY = {
    "tests/fact-artifact-transition-driver-fixture.h",
    "tests/fact-test-support.h",
    "tests/test-daemon-http-decide-seed-helper.h",
    "tests/test-publication-root.h",
    "tests/test-service-credential-operation-root.h",
}

TEST_REGISTRATION_PROFILES = {
    "tests/test-fact-artifact-transition-driver.c": (
        8,
        "687d7ba994a2128fd9cee1d1f17df794bda684e91064064f522f03b81ca2f40d",
    ),
    "tests/test-fact-artifact-transition-posix.c": (
        38,
        "bd2ff88c97c47c7b65155e15d789b408b6e65b4284f0c956f53c429661161d28",
    ),
    "tests/test-fact-artifact-transition-windows.c": (
        24,
        "02dd244998665bf5e83fb8d4d94c16f47c759e1d292354b753b56201839b1d4b",
    ),
}

TEST_REGISTERED_BODY_SHA256 = {
    "tests/test-fact-artifact-transition-driver.c":
        "30618d210f824fd80d688dcd6174350fc432660ea47d9e82154e50a75f96d5da",
    "tests/test-fact-artifact-transition-posix.c":
        "a38188f40329926c7b84250dc9c914ecc56e7160eadf81946cc7ef19c2dbc44d",
    "tests/test-fact-artifact-transition-windows.c":
        "e28928fc2a46782f2558da57eab95c8a9ae831fb53857d816544d65a2e54f9fb",
}

WINDOWS_AUTHORITY_BODY_SHA256 = (
    "70e9c26052cbe13895dc9a99c0323a00b0f5c78a0e95923661cb8ccfe8d9b121"
)
WINDOWS_AUTHORITY_TEST_BODY_SHA256 = (
    "8548251dd61f2b63a7f7d7699ce8f867b0d36149a22404d4434a53a2c22aa32a"
)
WINDOWS_AUTHORITY_CALLER_BODY_SHA256 = {
    "wyl_fact_artifact_transition_windows_open":
        "e44f9e4a8d31bf6f99a83a79d44e77d8d4342dd53d2b24ab2eb8f0030bc6d6a4",
    "wyl_fact_artifact_transition_windows_capture":
        "1f09b653232cc457cc1d1815cedf0318596d2154638ebfdb332575ba8b7a810e",
    "wyl_fact_artifact_transition_windows_execute":
        "743b9c1fb2eb8ed8b6efaf2bd8290df15506375630f12b6f340fdcf29e8454a6",
}

POSIX_AUTHORITY_CALLER_BODY_SHA256 = {
    "wyl_fact_artifact_transition_posix_open":
        "4d9316b4debfe5e881e8e20a483a744ab2bf55c28b915527a6d328e4cceb47f1",
    "wyl_fact_artifact_transition_posix_capture":
        "2d6e19dc40a8b60f173b900b4261c6b562122ca715c29cc872aad638f76affe3",
    "wyl_fact_artifact_transition_posix_execute":
        "aea637b4b6c3feae29392168e3cb0a9784c328ab28a1275bd6831730d01b869a",
}
POSIX_AUTHORITY_TEST_BODY_SHA256 = (
    "3cbfcbae6979204e8855c845dc4e80b6b4710ab3beb3dd9518c7f9931aa4dcce"
)
POSIX_AUTHORITY_BODY_SHA256 = (
    "55927259bd5d7cb7b41d799502939bc9ca9ed61b902a3cb2dd8cb9a5f07897a0"
)

TERMINATION_PROFILES = {
    "tests/test-fact-artifact-transition-posix.c": (
        "_exit (77)",
        "_exit (78)",
    ),
    "tests/test-fact-artifact-transition-windows.c": (
        "ExitProcess (effect == MT (EFFECT_APPLIED) && windows_write_counter "
        "(action->counter_path, 1) ? DRIVER_CHILD_CRASHED_AFTER_RETAIN : "
        "DRIVER_CHILD_ERROR)",
        "TerminateProcess (process.hProcess, DRIVER_CHILD_ERROR)",
    ),
}


def normalize_c_translation(text: str) -> str:
    """Apply C17 translation phases 1 and 2 before structural inspection."""
    for trigraph, replacement in TRIGRAPHS.items():
        text = text.replace(trigraph, replacement)
    return re.sub(r"\\(?:\r\n|\n)", "", text)


def require_c_composition_profile(name: str, text: str) -> None:
    logical = normalize_c_translation(text)
    token_pastes = tuple(
        " ".join(line.split())
        for line in logical.splitlines()
        if "##" in line or "%:%:" in line
    )
    if token_pastes != TOKEN_PASTE_ALLOWLIST.get(name, ()):
        raise AssertionError(f"C token-paste profile drift: {name}")
    code = strip_c_comments_and_literals(logical)
    if re.search(r"\b(?:asm|__asm|__asm__|_Pragma|__pragma)\b", code):
        raise AssertionError(
            f"assembly/pragma operator is not allowed in protected closure: {name}"
        )


def require_include_profile(name: str, text: str) -> None:
    logical = normalize_c_translation(text)
    includes = [
        line
        for line in logical.splitlines()
        if re.match(r"^\s*(?:#|%:)\s*include\b", line)
    ]
    encoded = (("\n".join(includes) + "\n") if includes else "").encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != PROTECTED_INCLUDE_DIGESTS[name]:
        raise AssertionError(f"protected include profile drift: {name}")


def require_directive_profile(name: str, text: str) -> None:
    logical = normalize_c_translation(text)
    directives = [
        line
        for line in logical.splitlines()
        if re.match(r"^\s*(?:#|%:)\s*[A-Za-z_]", line)
    ]
    encoded = (
        (("\n".join(directives) + "\n") if directives else "").encode("utf-8")
    )
    if hashlib.sha256(encoded).hexdigest() != PROTECTED_DIRECTIVE_DIGESTS[name]:
        raise AssertionError(f"protected preprocessor directive profile drift: {name}")


def require_termination_profile(name: str, raw: str, code: str) -> None:
    termination = re.compile(
        r"\b(?:g_test_skip|g_test_incomplete|exit|_Exit|quick_exit|_exit|"
        r"ExitProcess|TerminateProcess|ExitThread|RtlExitUserProcess|"
        r"NtTerminateProcess|ZwTerminateProcess|_endthread|_endthreadex|"
        r"pthread_exit|thrd_exit|longjmp|syscall|execl|execle|execlp|execv|"
        r"execve|execvp|execvpe|execveat|fexecve)\b"
    )
    calls: list[str] = []
    for match in termination.finditer(code):
        open_paren = code.find("(", match.end())
        if open_paren < 0:
            raise AssertionError(f"malformed termination primitive in {name}")
        depth = 1
        position = open_paren + 1
        while position < len(code) and depth:
            if code[position] == "(":
                depth += 1
            elif code[position] == ")":
                depth -= 1
            position += 1
        if depth:
            raise AssertionError(f"unterminated termination primitive in {name}")
        calls.append(" ".join(raw[match.start():position].split()))
    if tuple(calls) != TERMINATION_PROFILES.get(name, ()):
        raise AssertionError(f"successful termination profile drift: {name}")


def strip_c_comments_and_literals(text: str) -> str:
    """Blank comments and literals in phase-2-normalized C, preserving offsets."""
    output = list(text)
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if char == '"':
                output[index] = " "
                state = "string"
            elif char == "'":
                output[index] = " "
                state = "character"
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block-comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                output[index] = " "
        else:
            if char == "\\" and following:
                output[index] = " "
                if following != "\n":
                    output[index + 1] = " "
                index += 2
                continue
            if (state == "string" and char == '"') or (
                state == "character" and char == "'"
            ):
                output[index] = " "
                state = "code"
            elif char != "\n":
                output[index] = " "
        index += 1
    return "".join(output)


def function_body_spans(code: str, symbol: str) -> list[tuple[int, int]]:
    """Return every syntactic function definition span for a symbol."""
    spans: list[tuple[int, int]] = []
    for match in re.finditer(rf"\b{re.escape(symbol)}\b", code):
        start = match.start()
        open_paren = code.find("(", start + len(symbol))
        if open_paren < 0:
            continue
        depth = 1
        position = open_paren + 1
        while position < len(code) and depth:
            if code[position] == "(":
                depth += 1
            elif code[position] == ")":
                depth -= 1
            position += 1
        while position < len(code) and code[position].isspace():
            position += 1
        if position < len(code) and code[position] == "{":
            body_start = position
            depth = 1
            position += 1
            while position < len(code) and depth:
                if code[position] == "{":
                    depth += 1
                elif code[position] == "}":
                    depth -= 1
                position += 1
            if depth:
                raise AssertionError(f"unterminated function definition: {symbol}")
            spans.append((body_start, position))
    return spans


def has_definition_like_declarator(code: str, symbol: str) -> bool:
    """Recognize definitions with object- or function-like empty macro suffixes."""
    for match in re.finditer(rf"\b{re.escape(symbol)}\b", code):
        open_paren = code.find("(", match.end())
        if open_paren < 0:
            continue
        depth = 1
        position = open_paren + 1
        while position < len(code) and depth:
            if code[position] == "(":
                depth += 1
            elif code[position] == ")":
                depth -= 1
            position += 1
        if depth:
            continue
        while position < len(code):
            while position < len(code) and code[position].isspace():
                position += 1
            if position < len(code) and code[position] == "{":
                return True
            macro = re.match(r"[A-Za-z_]\w*", code[position:])
            if macro is None:
                break
            position += macro.end()
            while position < len(code) and code[position].isspace():
                position += 1
            if position < len(code) and code[position] == "(":
                depth = 1
                position += 1
                while position < len(code) and depth:
                    if code[position] == "(":
                        depth += 1
                    elif code[position] == ")":
                        depth -= 1
                    position += 1
                if depth:
                    break
    return False


def function_body_span(
    code: str, symbol: str, required: str | None = None
) -> tuple[int, int]:
    """Return one unambiguous function definition span, optionally by body token."""
    spans = function_body_spans(code, symbol)
    if required is not None:
        spans = [span for span in spans if required in code[span[0] : span[1]]]
    if len(spans) != 1:
        raise AssertionError(
            f"expected one function definition: {symbol}; found {len(spans)}"
        )
    return spans[0]


def function_body(code: str, symbol: str, required: str | None = None) -> str:
    start, end = function_body_span(code, symbol, required)
    return code[start:end]


def in_preprocessor_conditional(raw: str, position: int) -> bool:
    depth = 0
    for line in raw[:position].splitlines():
        directive = line.lstrip()
        if re.match(r"(?:#|%:)\s*(if|ifdef|ifndef)\b", directive):
            depth += 1
        elif re.match(r"(?:#|%:)\s*endif\b", directive):
            depth = max(0, depth - 1)
    return depth != 0


def conditional_profile(code: str) -> list[tuple[str, str]]:
    profile: list[tuple[str, str]] = []
    directive_pattern = re.compile(
        r"(?m)^\s*(?:#|%:)\s*(if|ifdef|ifndef|elif|else|endif)\b([^\n]*)"
    )
    for match in directive_pattern.finditer(code):
        profile.append((match.group(1), " ".join(match.group(2).split())))
    return profile


def require_test_runtime_integrity(raw: str, code: str, label: str) -> None:
    for api in (
        "g_test_init",
        "g_test_add_func",
        "g_test_run",
        *ASSERTION_BACKEND_SYMBOLS,
    ):
        if has_definition_like_declarator(code, api):
            raise AssertionError(
                f"{label}: protected test/assertion API is locally defined: {api}"
            )
    if re.search(
        r"\b(?:constructor|G_DEFINE_CONSTRUCTOR|__attribute__|__declspec)\b",
        code,
    ):
        raise AssertionError(f"{label}: pre-main compiler extension is not allowed")
    pragmas = re.findall(r"(?m)^\s*(?:#|%:)\s*pragma\s+([^\n]+)", code)
    if any(not pragma.strip().startswith("once") for pragma in pragmas):
        raise AssertionError(f"{label}: pre-main pragma is not allowed")
    if any(token in raw for token in (".CRT$X", ".init_array", ".preinit_array")):
        raise AssertionError(f"{label}: pre-main linker section is not allowed")


def require_test_registrations(
    raw: str,
    code: str,
    expected: Mapping[str, str],
    expected_profile: tuple[int, str],
    expected_body_sha256: str,
    label: str,
    expected_conditionals: list[tuple[str, str]],
    expected_main_definitions: int = 1,
) -> None:
    protected = {
        "main",
        "return",
        "if",
        "goto",
        "g_test_init",
        "g_test_add_func",
        "g_test_run",
        *ASSERTION_SYMBOLS,
        *expected.values(),
    }
    protected_pattern = "|".join(re.escape(symbol) for symbol in sorted(protected))
    shadow = re.search(
        rf"(?m)^\s*(?:#|%:)\s*(?:define|undef)\s+(?:{protected_pattern})\b",
        code,
    )
    if shadow is not None:
        raise AssertionError(f"{label}: protected test symbol is macro-shadowed")
    if conditional_profile(code) != expected_conditionals:
        raise AssertionError(f"{label}: unexpected preprocessor conditional profile")
    main_spans = function_body_spans(code, "main")
    if len(main_spans) != expected_main_definitions:
        raise AssertionError(
            f"{label}: expected {expected_main_definitions} main definitions; "
            f"found {len(main_spans)}"
        )
    for function in set(expected.values()):
        definitions = function_body_spans(code, function)
        if len(definitions) != 1:
            raise AssertionError(
                f"{label}: expected one protected definition {function}; "
                f"found {len(definitions)}"
            )
        body = code[definitions[0][0] : definitions[0][1]]
        if re.search(
            r"\b(?:return|g_test_skip|g_test_incomplete|exit|_Exit|quick_exit|"
            r"_exit|ExitProcess|TerminateProcess|longjmp)\b",
            body,
        ):
            raise AssertionError(
                f"{label}: protected test body has an early termination path: {function}"
            )
    require_test_runtime_integrity(raw, code, label)
    start, end = function_body_span(code, "main", "g_test_init")
    body_code = code[start:end]
    body_raw = raw[start:end]
    if body_code.count("g_test_init") != 1:
        raise AssertionError(f"{label}: expected one g_test_init call")
    init = body_code.find("g_test_init")
    prefix = body_code[1:init]
    if label == "driver runtime registration":
        prefix_pattern = r"\s*"
    elif label == "POSIX runtime registration":
        prefix_pattern = (
            r"\s*if\s*\(\s*argc\s*==\s*5\s*&&\s*strcmp\s*\(\s*"
            r"argv\s*\[\s*1\s*\]\s*,\s*\)\s*==\s*0\s*\)\s*"
            r"return\s+run_posix_driver_crash_child\s*\(\s*"
            r"argv\s*\[\s*2\s*\]\s*,\s*argv\s*\[\s*3\s*\]\s*,\s*"
            r"argv\s*\[\s*4\s*\]\s*\)\s*;\s*"
            r"driver_test_executable\s*=\s*g_canonicalize_filename\s*\(\s*"
            r"argv\s*\[\s*0\s*\]\s*,\s*NULL\s*\)\s*;\s*"
        )
    else:
        prefix_pattern = (
            r"\s*if\s*\(\s*argc\s*==\s*5\s*&&\s*strcmp\s*\(\s*"
            r"argv\s*\[\s*1\s*\]\s*,\s*\)\s*==\s*0\s*\)\s*"
            r"return\s+run_driver_crash_child\s*\(\s*"
            r"argv\s*\[\s*2\s*\]\s*,\s*argv\s*\[\s*3\s*\]\s*,\s*"
            r"argv\s*\[\s*4\s*\]\s*\)\s*;\s*"
        )
    if re.fullmatch(prefix_pattern, prefix) is None:
        raise AssertionError(f"{label}: non-canonical control flow before g_test_init")
    init_end = body_code.find(";", init)
    if init_end < 0:
        raise AssertionError(f"{label}: unterminated g_test_init call")
    registration_statement = (
        r"g_test_add_func\s*\(\s*,\s*[A-Za-z_]\w*\s*\)\s*;"
    )
    straight_line_suffix = (
        rf"(?:\s*{registration_statement})*"
        r"\s*return\s+g_test_run\s*\(\s*\)\s*;\s*"
    )
    if re.fullmatch(straight_line_suffix, body_code[init_end + 1 : -1]) is None:
        raise AssertionError(
            f"{label}: registrations must form a reachable straight-line g_test_run suffix"
        )
    registrations: list[tuple[str, str]] = []
    cursor = 0
    token = "g_test_add_func"
    while True:
        call = body_code.find(token, cursor)
        if call < 0:
            break
        depth = body_code[:call].count("{") - body_code[:call].count("}")
        if depth != 1:
            raise AssertionError(f"{label}: test registration is not at direct main scope")
        boundary = max(
            body_code.rfind(";", 0, call),
            body_code.rfind("{", 0, call),
            body_code.rfind("}", 0, call),
        )
        if body_code[boundary + 1 : call].strip():
            raise AssertionError(f"{label}: test registration is control-flow guarded")
        if in_preprocessor_conditional(body_raw, call):
            raise AssertionError(f"{label}: test registration is preprocessor guarded")
        open_paren = body_code.find("(", call + len(token))
        paren_depth = 1
        position = open_paren + 1
        while position < len(body_code) and paren_depth:
            if body_code[position] == "(":
                paren_depth += 1
            elif body_code[position] == ")":
                paren_depth -= 1
            position += 1
        if paren_depth:
            raise AssertionError(f"{label}: unterminated g_test_add_func")
        raw_call = body_raw[call:position]
        match = re.fullmatch(
            r'g_test_add_func\s*\(\s*"([^"\\]+)"\s*,\s*([A-Za-z_]\w*)\s*\)',
            raw_call,
            re.DOTALL,
        )
        if match is None:
            raise AssertionError(f"{label}: malformed test registration mapping")
        registrations.append((match.group(1), match.group(2)))
        cursor = position
    registration_bytes = "".join(
        f"{path}\0{function}\n" for path, function in registrations
    ).encode("utf-8")
    actual_profile = (len(registrations), hashlib.sha256(registration_bytes).hexdigest())
    if actual_profile != expected_profile:
        raise AssertionError(
            f"{label}: complete path-to-callback registration profile drift"
        )
    registered_body_profile: list[str] = []
    for path, function in registrations:
        definitions = function_body_spans(code, function)
        if len(definitions) != 1:
            raise AssertionError(
                f"{label}: expected one registered definition {function}; "
                f"found {len(definitions)}"
            )
        body = code[definitions[0][0] : definitions[0][1]]
        registered_body_profile.append(
            f"{path}\0{function}\0"
            f"{hashlib.sha256(body.encode('utf-8')).hexdigest()}\n"
        )
    actual_body_sha256 = hashlib.sha256(
        "".join(registered_body_profile).encode("utf-8")
    ).hexdigest()
    if actual_body_sha256 != expected_body_sha256:
        raise AssertionError(f"{label}: complete registered test body profile drift")
    for path, function in expected.items():
        if registrations.count((path, function)) != 1:
            raise AssertionError(
                f"{label}: expected exactly one direct registration {path} -> {function}"
            )


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        raise AssertionError(f"{label}: missing {token}")


def require_before(text: str, first: str, second: str, label: str) -> None:
    require(text, first, label)
    require(text, second, label)
    if text.find(first) >= text.find(second):
        raise AssertionError(f"{label}: {first} must precede {second}")


@functools.lru_cache(maxsize=4)
def production_translation_units(root_text: str) -> tuple[tuple[str, str], ...]:
    root = pathlib.Path(root_text)
    suffixes = {
        ".c", ".cc", ".cpp", ".cxx", ".s", ".S",
        ".h", ".hh", ".hpp", ".hxx",
    }
    return tuple(
        (
            path.relative_to(root).as_posix(),
            path.read_text(encoding="utf-8"),
        )
        for path in sorted((root / "wyrelog").rglob("*"))
        if path.is_file() and path.suffix in suffixes
    )


def validate_production_unit(name: str, text: str) -> None:
    pattern = re.compile(r"\bg_test_(?:init|add_func|run)\b")
    require_c_composition_profile(name, text)
    if pattern.search(text):
        raise AssertionError(
            f"production translation unit defines/references protected test API: {name}"
        )
    if name in CXX_SOURCE_DIGESTS and (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != CXX_SOURCE_DIGESTS[name]
    ):
        raise AssertionError(f"protected C++ source profile drift: {name}")
    logical = normalize_c_translation(text)
    code = strip_c_comments_and_literals(logical)
    protected_macro_pattern = "|".join(
        re.escape(symbol) for symbol in COMPILER_PROTECTED_SYMBOLS
    )
    if re.search(
        rf"(?m)^\s*(?:#|%:)\s*(?:define|undef)\s+"
        rf"(?:{protected_macro_pattern})\b",
        code,
    ):
        raise AssertionError(f"protected compiler macro profile drift: {name}")
    for symbol in ASSERTION_BACKEND_SYMBOLS:
        if has_definition_like_declarator(code, symbol):
            raise AssertionError(
                f"production/test closure defines assertion backend {symbol}: {name}"
            )
    if re.search(r"\b(?:constructor|G_DEFINE_CONSTRUCTOR|__declspec)\b", code):
        raise AssertionError(f"production pre-main extension is not allowed: {name}")
    pragmas = re.findall(r"(?m)^\s*(?:#|%:)\s*pragma\s+([^\n]+)", code)
    if any(not pragma.strip().startswith("once") for pragma in pragmas):
        raise AssertionError(f"production pre-main pragma is not allowed: {name}")
    if any(token in logical for token in (".CRT", ".init_array", ".preinit_array")):
        raise AssertionError(f"production pre-main section is not allowed: {name}")


@functools.lru_cache(maxsize=4)
def validate_production_baseline(root_text: str) -> frozenset[str]:
    names: set[str] = set()
    for name, text in production_translation_units(root_text):
        validate_production_unit(name, text)
        names.add(name)
    discovered_cxx = {
        name
        for name in names
        if pathlib.Path(name).suffix in {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}
    }
    if discovered_cxx != CXX_SOURCE_DIGESTS.keys():
        raise AssertionError("protected C++ source/header inventory drift")
    return frozenset(names)


def require_no_production_test_api(
    root: pathlib.Path, overrides: Mapping[str, str] | None
) -> None:
    root_text = str(root.resolve())
    production_names = validate_production_baseline(root_text)
    if not overrides:
        return
    for name in production_names & overrides.keys():
        validate_production_unit(name, overrides[name])
    unknown_production = {
        name
        for name in overrides
        if name.startswith("wyrelog/")
        and pathlib.Path(name).suffix
        in {".c", ".cc", ".cpp", ".cxx", ".s", ".S", ".h", ".hh", ".hpp", ".hxx"}
        and name not in production_names
    }
    if unknown_production:
        raise AssertionError(
            f"production override is outside inventoried closure: {sorted(unknown_production)}"
        )


@functools.lru_cache(maxsize=4)
def test_headers(root_text: str) -> tuple[tuple[str, str], ...]:
    root = pathlib.Path(root_text)
    suffixes = {".h", ".hh", ".hpp", ".hxx"}
    return tuple(
        (path.relative_to(root).as_posix(), path.read_text(encoding="utf-8"))
        for path in sorted((root / "tests").rglob("*"))
        if path.is_file() and path.suffix in suffixes
    )


@functools.lru_cache(maxsize=4)
def validate_test_header_baseline(root_text: str) -> frozenset[str]:
    names: set[str] = set()
    for name, text in test_headers(root_text):
        validate_production_unit(name, text)
        names.add(name)
    if names != TEST_HEADER_INVENTORY:
        raise AssertionError("test header inventory drift")
    return frozenset(names)


def require_test_header_integrity(
    root: pathlib.Path, overrides: Mapping[str, str] | None
) -> None:
    root_text = str(root.resolve())
    names = validate_test_header_baseline(root_text)
    if not overrides:
        return
    for name in names & overrides.keys():
        validate_production_unit(name, overrides[name])
    unknown_headers = {
        name
        for name in overrides
        if name.startswith("tests/")
        and pathlib.Path(name).suffix in {".h", ".hh", ".hpp", ".hxx"}
        and name not in names
    }
    if unknown_headers:
        raise AssertionError(
            f"test header is outside inventoried closure: {sorted(unknown_headers)}"
        )


def meson_code_projection(text: str) -> str:
    """Blank Meson comments and strings while preserving source offsets."""
    output = list(text)
    position = 0
    state = "code"
    delimiter = ""
    while position < len(text):
        if state == "code":
            if text[position] == "#":
                output[position] = " "
                state = "comment"
                position += 1
                continue
            if text[position : position + 3] in ("'''", '\"\"\"'):
                delimiter = text[position : position + 3]
                output[position : position + 3] = "   "
                state = "triple-string"
                position += 3
                continue
            if text[position] in ("'", '"'):
                delimiter = text[position]
                output[position] = " "
                state = "string"
                position += 1
                continue
        elif state == "comment":
            if text[position] == "\n":
                state = "code"
            else:
                output[position] = " "
            position += 1
            continue
        elif state == "triple-string":
            if text[position : position + 3] == delimiter:
                output[position : position + 3] = "   "
                position += 3
                state = "code"
                delimiter = ""
                continue
            if text[position] != "\n":
                output[position] = " "
            position += 1
            continue
        else:
            output[position] = " "
            if text[position] == "\\" and position + 1 < len(text):
                if text[position + 1] != "\n":
                    output[position + 1] = " "
                position += 2
                continue
            if text[position] == delimiter:
                state = "code"
                delimiter = ""
            elif text[position] == "\n":
                raise AssertionError("unterminated Meson single-line string")
            position += 1
            continue
        position += 1
    if state in ("string", "triple-string"):
        raise AssertionError("unterminated Meson string")
    return "".join(output)


def normalize_meson_translation(text: str) -> str:
    """Splice Meson normal-state line continuations without moving offsets."""
    return re.sub(r"\\(?:\r\n|\n)", lambda match: " " * len(match.group()), text)


def meson_call_end(projection: str, open_paren: int, label: str) -> int:
    depth = 1
    position = open_paren + 1
    while position < len(projection) and depth:
        char = projection[position]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        position += 1
    if depth:
        raise AssertionError(f"unterminated Meson call: {label}")
    return position


def meson_conditional_stack(
    text: str, projection: str, source_position: int
) -> tuple[str, ...]:
    stack: list[tuple[str, str]] = []
    offset = 0
    raw_lines = text.splitlines(keepends=True)
    projected_lines = projection.splitlines(keepends=True)
    for raw_line, projected_line in zip(raw_lines, projected_lines, strict=True):
        if offset >= source_position:
            break
        match = re.match(
            r"^\s*(if|elif|else|endif|foreach|endforeach)\b", projected_line
        )
        if match is not None:
            directive = match.group(1)
            normalized = " ".join(raw_line.split())
            if directive == "if":
                stack.append(("if", normalized))
            elif directive in ("elif", "else"):
                if not stack or stack[-1][0] != "if":
                    raise AssertionError("unbalanced Meson conditional")
                stack[-1] = ("if", normalized)
            elif directive == "endif":
                if not stack or stack[-1][0] != "if":
                    raise AssertionError("unbalanced Meson conditional")
                stack.pop()
            elif directive == "foreach":
                stack.append(("foreach", normalized))
            else:
                if not stack or stack[-1][0] != "foreach":
                    raise AssertionError("unbalanced Meson foreach")
                stack.pop()
        offset += len(raw_line)
    return tuple(item[1] for item in stack)


def meson_call(
    text: str,
    assignment: str,
    callee: str = "executable",
    expected_context: tuple[str, ...] = (),
) -> str:
    projection = meson_code_projection(text)
    assignments = list(
        re.finditer(
            rf"(?m)^\s*{re.escape(assignment)}\s*(?:\+?=)", projection
        )
    )
    if len(assignments) != 1:
        raise AssertionError(
            f"expected one active Meson assignment {assignment}; found "
            f"{len(assignments)}"
        )
    match = re.search(
        rf"(?m)^\s*{re.escape(assignment)}\s*=\s*{re.escape(callee)}\s*\(",
        projection,
    )
    if match is None or match.start() != assignments[0].start():
        raise AssertionError(f"invalid Meson assignment: {assignment}")
    start = projection.find(assignment, match.start(), match.end())
    if meson_conditional_stack(text, projection, start) != expected_context:
        raise AssertionError(f"unexpected Meson conditional context: {assignment}")
    open_paren = projection.find("(", start, match.end())
    end = meson_call_end(projection, open_paren, assignment)
    return " ".join(text[start:end].split())


def meson_function_calls(text: str, function: str) -> list[str]:
    projection = meson_code_projection(text)
    calls: list[str] = []
    for match in re.finditer(
        rf"\b{re.escape(function)}\s*\(", projection
    ):
        start = match.start()
        open_paren = projection.find("(", start, match.end())
        end = meson_call_end(projection, open_paren, function)
        calls.append(" ".join(text[start:end].split()))
    return calls


def meson_first_static_string(call: str) -> str | None:
    open_paren = call.find("(")
    if open_paren < 0:
        return None
    position = open_paren + 1
    quote = ""
    escaped = False
    while position < len(call):
        char = call[position]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif char == ",":
            break
        position += 1
    if position >= len(call):
        return None
    expression = call[open_paren + 1 : position]
    literal = r"(?:'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
    if re.fullmatch(rf"\s*{literal}(?:\s*\+\s*{literal})*\s*", expression) is None:
        return None
    values: list[str] = []
    for token in re.findall(literal, expression):
        value = ast.literal_eval(token)
        if not isinstance(value, str):
            return None
        values.append(value)
    return "".join(values)


def require_meson_test_mapping(
    text: str,
    test_name: str,
    expected_call: str,
    expected_context: tuple[str, ...] = (),
) -> None:
    projection = meson_code_projection(text)
    matching: list[tuple[str, int]] = []
    for match in re.finditer(r"\btest\s*\(", projection):
        open_paren = projection.find("(", match.start(), match.end())
        end = meson_call_end(projection, open_paren, "test")
        call = " ".join(text[match.start():end].split())
        if meson_first_static_string(call) == test_name:
            matching.append((call, match.start()))
    if len(matching) != 1 or matching[0][0] != expected_call:
        raise AssertionError(f"Meson runtime mapping drift for {test_name}")
    if meson_conditional_stack(text, projection, matching[0][1]) != expected_context:
        raise AssertionError(f"unexpected Meson test context for {test_name}")


def meson_assignment_lines(
    text: str, symbol: str
) -> list[tuple[str, tuple[str, ...]]]:
    projection = meson_code_projection(text)
    assignments: list[tuple[str, tuple[str, ...]]] = []
    for match in re.finditer(
        rf"(?m)^\s*{re.escape(symbol)}\s*(?:\+?=)[^\n]*", projection
    ):
        line_start = projection.rfind("\n", 0, match.start()) + 1
        line_end = projection.find("\n", match.start())
        if line_end < 0:
            line_end = len(projection)
        assignments.append(
            (
                " ".join(text[line_start:line_end].split()),
                meson_conditional_stack(text, projection, match.start()),
            )
        )
    return assignments


def require_meson_compiler_profile(
    root_meson: str, library_meson: str, test_meson: str
) -> None:
    root_meson = normalize_meson_translation(root_meson)
    library_meson = normalize_meson_translation(library_meson)
    test_meson = normalize_meson_translation(test_meson)
    expected_targets = {
        "test_fact_artifact_transition_driver": ((),
            "test_fact_artifact_transition_driver = executable( "
            "'test-fact-artifact-transition-driver', "
            "'test-fact-artifact-transition-driver.c', "
            "'fact-artifact-transition-driver-fixture.c', "
            "include_directories : include_directories('../wyrelog'), "
            "dependencies : [wyrelog_dep], )"
        ),
        "test_fact_artifact_transition_posix": (
            ("if host_machine.system() != 'windows'",),
            "test_fact_artifact_transition_posix = executable( "
            "'test-fact-artifact-transition-posix', "
            "'test-fact-artifact-transition-posix.c', "
            "'fact-artifact-transition-driver-fixture.c', 'fact-test-support.c', "
            "include_directories : include_directories('../wyrelog'), "
            "c_args : fact_test_support_c_args, "
            "dependencies : [wyrelog_dep] + fact_test_support_deps, )"
        ),
        "test_fact_artifact_transition_windows": (
            ("if host_machine.system() == 'windows'",),
            "test_fact_artifact_transition_windows = executable( "
            "'test-fact-artifact-transition-windows', "
            "'test-fact-artifact-transition-windows.c', "
            "'fact-artifact-transition-driver-fixture.c', 'fact-test-support.c', "
            "include_directories : include_directories('../wyrelog'), "
            "c_args : fact_test_support_c_args, "
            "dependencies : [wyrelog_handle_test_seams_dep] + "
            "fact_test_support_deps, )"
        ),
    }
    for assignment, (context, expected) in expected_targets.items():
        if meson_call(test_meson, assignment, expected_context=context) != expected:
            raise AssertionError(
                f"Meson compiler profile drift for protected target {assignment}"
            )
    executable_names = {
        "test-fact-artifact-transition-driver",
        "test-fact-artifact-transition-posix",
        "test-fact-artifact-transition-windows",
    }
    executable_calls = meson_function_calls(test_meson, "executable")
    for executable_name in executable_names:
        if sum(
            meson_first_static_string(call) == executable_name
            for call in executable_calls
        ) != 1:
            raise AssertionError(
                f"Meson executable-name binding drift for {executable_name}"
            )
    expected_test_mappings = {
        "fact-artifact-transition-driver": (
            (),
            "test('fact-artifact-transition-driver', "
            "test_fact_artifact_transition_driver)",
        ),
        "fact-artifact-transition-driver-wiring": (
            (),
            "test('fact-artifact-transition-driver-wiring', python3, args : [ "
            "meson.current_source_dir() / "
            "'test-fact-artifact-transition-driver-wiring.py', "
            "meson.project_source_root(), ], timeout : 120, )",
        ),
        "fact-artifact-transition-driver-wiring-self": (
            (),
            "test('fact-artifact-transition-driver-wiring-self', python3, args : [ "
            "meson.current_source_dir() / "
            "'test-fact-artifact-transition-driver-wiring.py', '--self-test', "
            "meson.project_source_root(), ], timeout : 300, )",
        ),
        "fact-artifact-transition-posix": (
            ("if host_machine.system() != 'windows'",),
            "test('fact-artifact-transition-posix', "
            "test_fact_artifact_transition_posix)",
        ),
        "fact-artifact-transition-windows": (
            ("if host_machine.system() == 'windows'",),
            "test('fact-artifact-transition-windows', "
            "test_fact_artifact_transition_windows)",
        ),
    }
    for test_name, (context, expected) in expected_test_mappings.items():
        require_meson_test_mapping(test_meson, test_name, expected, context)
    if meson_call(test_meson, "python3", "find_program") != (
        "python3 = find_program('python3')"
    ):
        raise AssertionError("Meson Python test-runner binding drift")
    protected_loop_variables = {
        *expected_targets,
        "python3",
        "fact_test_support_deps",
        "fact_test_support_c_args",
    }
    test_projection = meson_code_projection(test_meson)
    for match in re.finditer(r"(?m)^\s*foreach\s+([^:\n]+)\s*:", test_projection):
        loop_variables = {
            variable.strip() for variable in match.group(1).split(",")
        }
        if loop_variables & protected_loop_variables:
            raise AssertionError("Meson foreach shadows a protected variable")
    expected_dependencies = {
        "wyrelog_dep": (
            "wyrelog_dep = declare_dependency( link_with : libwyrelog, "
            "include_directories : wyrelog_inc, dependencies : [glib_dep, gio_dep], )"
        ),
        "wyrelog_handle_test_seams_dep": (
            "wyrelog_handle_test_seams_dep = declare_dependency( "
            "link_with : wyrelog_handle_test_seams_lib, "
            "include_directories : wyrelog_inc, dependencies : [glib_dep, gio_dep], "
            "compile_args : ['-DWYL_TEST_HANDLE_SEAMS'], )"
        ),
    }
    for assignment, expected in expected_dependencies.items():
        if meson_call(library_meson, assignment, "declare_dependency") != expected:
            raise AssertionError(
                f"Meson compiler profile drift for protected dependency {assignment}"
            )
    meson_files = (root_meson, library_meson, test_meson)
    for symbol in (*expected_targets, *expected_dependencies, "python3"):
        assignment_count = sum(
            len(meson_assignment_lines(source, symbol)) for source in meson_files
        )
        if assignment_count != 1:
            raise AssertionError(
                f"expected one repository Meson assignment {symbol}; "
                f"found {assignment_count}"
            )
    for symbol in ("fact_test_support_deps", "fact_test_support_c_args"):
        assignment_count = sum(
            len(meson_assignment_lines(source, symbol)) for source in meson_files
        )
        if assignment_count != 2:
            raise AssertionError(
                f"unexpected repository Meson assignment count for {symbol}"
            )
    if meson_function_calls(test_meson, "declare_dependency"):
        raise AssertionError("Meson test declarations must not create dependencies")
    windows_context = ("if host_machine.system() == 'windows'",)
    if meson_assignment_lines(test_meson, "fact_test_support_deps") != [
        ("fact_test_support_deps = []", ()),
        ("fact_test_support_deps += advapi32_dep", windows_context),
    ] or meson_assignment_lines(test_meson, "fact_test_support_c_args") != [
        ("fact_test_support_c_args = []", ()),
        (
            "fact_test_support_c_args += '-D_WIN32_WINNT=0x0602'",
            windows_context,
        ),
    ]:
        raise AssertionError("Meson fact_test_support_c_args profile drift")
    project_profile = meson_function_calls(root_meson, "project")
    if project_profile != [
        "project('wyrelog', 'c', version : '0.1.0', "
        "license : 'GPL-3.0-or-later', meson_version : '>= 1.1.0', "
        "default_options : [ 'c_std=c17', 'warning_level=2', ], )"
    ]:
        raise AssertionError("Meson project/default compiler options profile drift")
    project_calls = meson_function_calls(
        root_meson + "\n" + library_meson + "\n" + test_meson,
        "add_project_arguments",
    )
    if project_calls != [
        "add_project_arguments('-DWYL_ENABLE_FAULT_INJECTION', language : 'c')",
        "add_project_arguments('-DWYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS', language : 'c')",
    ]:
        raise AssertionError("Meson project C compiler arguments profile drift")
    if meson_function_calls(
        root_meson + "\n" + library_meson + "\n" + test_meson,
        "add_global_arguments",
    ):
        raise AssertionError("Meson global compiler arguments are not allowed")
    expected_root_commands = [
        "run_command( git_program, '-C', meson.project_source_root(), "
        "'rev-parse', '--show-toplevel', check : false, )",
        "run_command( posix_sh, '-c', 'CDPATH= cd \"$1\" && pwd -P', "
        "'sh', meson.project_source_root(), check : false, )",
        "run_command( posix_sh, '-c', 'CDPATH= cd \"$1\" && pwd -P', "
        "'sh', git_toplevel.stdout().strip(), check : false, )",
        "run_command(git_hook_setup, check : true)",
    ]
    if meson_function_calls(root_meson, "run_command") != expected_root_commands:
        raise AssertionError("Meson root run_command profile drift")
    if meson_function_calls(library_meson, "run_command") or meson_function_calls(
        test_meson, "run_command"
    ):
        raise AssertionError("Meson subdirectories must not execute run_command")
    expected_configure_files = [
        "configure_file( input : "
        "'../wyrelog/wyctl/org.wyrelog.wyctl.gschema.xml', "
        "output : 'org.wyrelog.wyctl.gschema.xml', copy : true, )"
    ]
    if meson_function_calls(test_meson, "configure_file") != expected_configure_files:
        raise AssertionError("Meson configure_file profile drift")
    expected_custom_targets = [
        "custom_target('wyctl-gschemas-compiled', input : wyctl_gschema_staged, "
        "output : 'gschemas.compiled', command : [glib_compile_schemas_prog, "
        "'--strict', '--targetdir=@OUTDIR@', meson.current_build_dir()], "
        "build_by_default : true, )"
    ]
    if meson_function_calls(test_meson, "custom_target") != expected_custom_targets:
        raise AssertionError("Meson custom_target command profile drift")
    for source in (root_meson, library_meson):
        if meson_function_calls(source, "configure_file") or meson_function_calls(
            source, "custom_target"
        ):
            raise AssertionError("unexpected root/library Meson generation command")
    for dynamic in (
        "set_variable",
        "unset_variable",
        "add_test_setup",
        "override_find_program",
        "subdir_done",
        "add_postconf_script",
        "generator",
        "run_target",
        "vcs_tag",
    ):
        if meson_function_calls(
            root_meson + "\n" + library_meson + "\n" + test_meson, dynamic
        ):
            raise AssertionError(f"Meson dynamic variable mutation is not allowed: {dynamic}")


def require_repository_meson_profile(
    root: pathlib.Path,
    raw: Mapping[str, str],
    overrides: Mapping[str, str] | None,
) -> None:
    expected = {
        "meson.build",
        "meson/wirelog-dependency/meson.build",
        "wyrelog/meson.build",
        "tests/meson.build",
    }
    meson_paths = [root / "meson.build"]
    for directory in ("meson", "wyrelog", "tests"):
        meson_paths.extend((root / directory).rglob("meson.build"))
    discovered = {path.relative_to(root).as_posix() for path in meson_paths}
    if discovered != expected:
        raise AssertionError("repository Meson file inventory drift")
    if overrides:
        unknown = {
            name for name in overrides if name.endswith("meson.build") and name not in expected
        }
        if unknown:
            raise AssertionError(f"Meson override is outside inventory: {sorted(unknown)}")
    nested = raw["meson/wirelog-dependency/meson.build"]
    if hashlib.sha256(nested.encode("utf-8")).hexdigest() != (
        "737f8e0481782bce9cef7f2b2c658d7cfbfb4051767da807cb152c151b1e7376"
    ):
        raise AssertionError("wirelog dependency Meson profile drift")
    if meson_function_calls(raw["meson.build"], "subdir") != [
        "subdir('meson/wirelog-dependency')",
        "subdir('wyrelog')",
        "subdir('tests')",
    ]:
        raise AssertionError("root Meson subdir profile drift")
    for name in (
        "meson/wirelog-dependency/meson.build",
        "wyrelog/meson.build",
        "tests/meson.build",
    ):
        if meson_function_calls(raw[name], "subdir"):
            raise AssertionError(f"nested Meson subdir is not allowed: {name}")


def verify(root: pathlib.Path, overrides: Mapping[str, str] | None = None) -> None:
    require_no_production_test_api(root, overrides)
    require_test_header_integrity(root, overrides)
    raw = {
        name: (
            overrides[name]
            if overrides and name in overrides
            else (root / name).read_text(encoding="utf-8")
        )
        for name in FILES
    }
    require_repository_meson_profile(root, raw, overrides)
    for source_name in (
        "tests/fact-artifact-transition-driver-fixture.c",
        "tests/fact-artifact-transition-driver-fixture.h",
        "tests/fact-test-support.c",
        "tests/fact-test-support.h",
        "tests/test-fact-artifact-transition-driver.c",
        "tests/test-fact-artifact-transition-posix.c",
        "tests/test-fact-artifact-transition-windows.c",
    ):
        require_c_composition_profile(source_name, raw[source_name])
        require_include_profile(source_name, raw[source_name])
    for source_name in PROTECTED_DIRECTIVE_DIGESTS:
        require_directive_profile(source_name, raw[source_name])
    logical = {
        name: normalize_c_translation(text)
        for name, text in raw.items()
        if name.endswith((".c", ".h"))
    }
    code = {
        name: strip_c_comments_and_literals(text)
        for name, text in logical.items()
    }
    posix = code["wyrelog/fact/graph-artifact-transition-posix-private.c"]
    namespace = code["wyrelog/fact/graph-artifact-namespace-private.c"]
    windows = code["wyrelog/fact/graph-artifact-transition-windows-private.c"]
    win_locator = code["wyrelog/fact/graph-artifact-windows-locator-private.c"]
    fixture = code["tests/fact-artifact-transition-driver-fixture.c"]
    driver_test = code["tests/test-fact-artifact-transition-driver.c"]
    posix_test = code["tests/test-fact-artifact-transition-posix.c"]
    windows_test = code["tests/test-fact-artifact-transition-windows.c"]

    require_test_registrations(
        logical["tests/test-fact-artifact-transition-driver.c"],
        driver_test,
        {
            "/fact/artifact-transition-driver/cancellation-boundary":
                "test_cancellation_stops_before_attempt_boundary",
            "/fact/artifact-transition-driver/sync-retry-unsupported":
                "test_retryable_and_unsupported_sync_remain_nondurable",
        },
        TEST_REGISTRATION_PROFILES["tests/test-fact-artifact-transition-driver.c"],
        TEST_REGISTERED_BODY_SHA256["tests/test-fact-artifact-transition-driver.c"],
        "driver runtime registration",
        [],
    )
    require_test_registrations(
        logical["tests/test-fact-artifact-transition-posix.c"],
        posix_test,
        {
            "/fact/artifact-transition-posix/execute/mode-a-lifecycle":
                "test_execute_mode_a_full_lifecycle",
            "/fact/artifact-transition-posix/execute/mode-a-rollback-lifecycle":
                "test_execute_mode_a_rollback_lifecycle",
            "/fact/artifact-transition-posix/driver/child-crash-restart":
                "test_child_crash_restarts_from_fresh_capture",
        },
        TEST_REGISTRATION_PROFILES["tests/test-fact-artifact-transition-posix.c"],
        TEST_REGISTERED_BODY_SHA256["tests/test-fact-artifact-transition-posix.c"],
        "POSIX runtime registration",
        [("ifdef", "__APPLE__"), ("endif", "")],
    )
    require_test_registrations(
        logical["tests/test-fact-artifact-transition-windows.c"],
        windows_test,
        {
            "/fact-artifact-transition/windows/mode-a-lifecycle":
                "test_mode_a_full_lifecycle",
            "/fact-artifact-transition/windows/mode-a-rollback":
                "test_mode_a_rollback_lifecycle",
            "/fact-artifact-transition/windows/driver/directory-authority":
                "test_graph_directory_authority_is_revalidated",
            "/fact-artifact-transition/windows/driver/child-crash-restart":
                "test_child_crash_restarts_from_fresh_capture",
        },
        TEST_REGISTRATION_PROFILES["tests/test-fact-artifact-transition-windows.c"],
        TEST_REGISTERED_BODY_SHA256["tests/test-fact-artifact-transition-windows.c"],
        "Windows runtime registration",
        [("ifdef", "G_OS_WIN32"), ("else", ""), ("endif", "")],
        2,
    )
    for source_name in (
        "tests/fact-artifact-transition-driver-fixture.c",
        "tests/fact-artifact-transition-driver-fixture.h",
        "tests/fact-test-support.c",
        "tests/fact-test-support.h",
        "wyrelog/fact/graph-artifact-transition-posix-private.c",
        "wyrelog/fact/graph-artifact-namespace-private.c",
        "wyrelog/fact/graph-artifact-transition-windows-private.c",
        "wyrelog/fact/graph-artifact-windows-locator-private.c",
    ):
        require_test_runtime_integrity(
            logical[source_name], code[source_name], f"source closure {source_name}"
        )
    for source_name in (
        "tests/fact-artifact-transition-driver-fixture.c",
        "tests/fact-artifact-transition-driver-fixture.h",
        "tests/fact-test-support.c",
        "tests/fact-test-support.h",
        "tests/test-fact-artifact-transition-driver.c",
        "tests/test-fact-artifact-transition-posix.c",
        "tests/test-fact-artifact-transition-windows.c",
    ):
        require_termination_profile(
            source_name, logical[source_name], code[source_name]
        )
    compiler_protected = (
        "main",
        "return",
        "if",
        "goto",
        "g_test_init",
        "g_test_add_func",
        "g_test_run",
        *COMPILER_PROTECTED_SYMBOLS,
        "test_cancellation_stops_before_attempt_boundary",
        "test_retryable_and_unsupported_sync_remain_nondurable",
        "test_execute_mode_a_full_lifecycle",
        "test_execute_mode_a_rollback_lifecycle",
        "test_mode_a_full_lifecycle",
        "test_mode_a_rollback_lifecycle",
        "test_graph_directory_authority_is_revalidated",
        "test_child_crash_restarts_from_fresh_capture",
    )
    meson_sources = (
        raw["meson.build"]
        + "\n"
        + raw["wyrelog/meson.build"]
        + "\n"
        + raw["tests/meson.build"]
    )
    for symbol in compiler_protected:
        if re.search(
            rf"(?:-D|-U|/D|/U)[^\n]{{0,80}}?{re.escape(symbol)}\b",
            meson_sources,
        ):
            raise AssertionError(
                f"Meson compiler arguments must not shadow protected symbol {symbol}"
            )
        if re.search(
            rf"(?m)^\s*(?:#|%:)\s*(?:define|undef)\s+{re.escape(symbol)}\b",
            "\n".join(code.values()),
        ):
            raise AssertionError(
                f"C sources must not macro-shadow protected symbol {symbol}"
            )
    require_meson_compiler_profile(
        raw["meson.build"], raw["wyrelog/meson.build"], raw["tests/meson.build"]
    )

    posix_capture = function_body(
        posix, "wyl_fact_artifact_transition_posix_capture"
    )
    require(posix_capture, "provider_revalidate_authority", "POSIX capture authority")
    require(
        posix_capture,
        "wyl_fact_artifact_inventory_posix_capture",
        "POSIX correlated capture",
    )
    posix_authority = function_body(posix, "provider_revalidate_authority")
    if (
        hashlib.sha256(posix_authority.encode("utf-8")).hexdigest()
        != POSIX_AUTHORITY_BODY_SHA256
    ):
        raise AssertionError("POSIX authority normalized body profile drift")
    require(
        posix_authority,
        "wyl_fact_root_writer_lease_authorizes_resolver",
        "POSIX resolver/lease binding",
    )
    posix_open = function_body(posix, "wyl_fact_artifact_transition_posix_open")
    posix_execute = function_body(
        posix, "wyl_fact_artifact_transition_posix_execute"
    )
    for symbol, body in (
        ("wyl_fact_artifact_transition_posix_open", posix_open),
        ("wyl_fact_artifact_transition_posix_capture", posix_capture),
        ("wyl_fact_artifact_transition_posix_execute", posix_execute),
    ):
        if (
            hashlib.sha256(body.encode("utf-8")).hexdigest()
            != POSIX_AUTHORITY_CALLER_BODY_SHA256[symbol]
        ):
            raise AssertionError(
                f"POSIX authority caller normalized body profile drift: {symbol}"
            )
    posix_authority_test = function_body(
        posix_test, "test_foreign_root_authority_never_mutates"
    )
    if (
        hashlib.sha256(posix_authority_test.encode("utf-8")).hexdigest()
        != POSIX_AUTHORITY_TEST_BODY_SHA256
    ):
        raise AssertionError("POSIX root-authority test normalized body profile drift")
    normal_capture = function_body(
        namespace,
        "wyl_fact_artifact_namespace_inventory_snapshot",
        "wyl_fact_artifact_inventory_posix_capture",
    )
    if not re.search(
        r"wyl_fact_artifact_inventory_posix_capture\s*\([^;]*?NULL\s*,\s*NULL\s*,",
        normal_capture,
        re.DOTALL,
    ):
        raise AssertionError("normal namespace capture must disable transition names")

    windows_capture = function_body(
        windows, "wyl_fact_artifact_transition_windows_capture"
    )
    scan = "wyl_fact_artifact_win_locator_transition_inventory_scan"
    if windows_capture.count(scan) != 2:
        raise AssertionError("Windows capture must take exactly two active scans")
    require(
        windows_capture,
        "WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_CAPTURE_BETWEEN_SCANS_RETIRE_STAGE",
        "Windows between-scan mutation seam",
    )
    windows_authority = function_body(windows, "provider_revalidate_authority")
    if (
        hashlib.sha256(windows_authority.encode("utf-8")).hexdigest()
        != WINDOWS_AUTHORITY_BODY_SHA256
    ):
        raise AssertionError("Windows authority normalized body profile drift")
    require(
        windows_authority,
        "wyl_fact_root_writer_lease_authorizes_resolver",
        "Windows resolver/lease binding",
    )
    handle_checks = (
        ("root", "root"),
        ("graph", "graph"),
    )
    for handle, flags in handle_checks:
        query = re.compile(
            rf"GetHandleInformation\s*\(\s*provider->{handle}_handle\s*,\s*"
            rf"&{flags}_flags\s*\)"
        )
        predicate = re.compile(
            rf"\(\s*{flags}_flags\s*&\s*HANDLE_FLAG_INHERIT\s*\)\s*!=\s*0"
        )
        if len(query.findall(windows_authority)) != 1:
            raise AssertionError(
                f"Windows authority must inspect retained {handle} handle into "
                f"its matching flags"
            )
        if len(predicate.findall(windows_authority)) != 1:
            raise AssertionError(
                f"Windows authority must reject inheritable {handle} handle"
            )
    handle_guard = re.compile(
        r"if\s*\(\s*"
        r"!GetHandleInformation\s*\(\s*provider->root_handle\s*,\s*"
        r"&root_flags\s*\)\s*\|\|\s*"
        r"!GetHandleInformation\s*\(\s*provider->graph_handle\s*,\s*"
        r"&graph_flags\s*\)\s*\|\|\s*"
        r"\(\s*root_flags\s*&\s*HANDLE_FLAG_INHERIT\s*\)\s*!=\s*0\s*"
        r"\|\|\s*"
        r"\(\s*graph_flags\s*&\s*HANDLE_FLAG_INHERIT\s*\)\s*!=\s*0\s*"
        r"\)\s*return\s+WYRELOG_E_POLICY\s*;"
    )
    guard_matches = list(handle_guard.finditer(windows_authority))
    if len(guard_matches) != 1:
        raise AssertionError(
            "Windows retained handles must share one exact fail-closed guard"
        )
    guard = guard_matches[0]
    guard_depth = windows_authority[: guard.start()].count("{") - windows_authority[
        : guard.start()
    ].count("}")
    if guard_depth != 1:
        raise AssertionError(
            "Windows retained-handle guard must be at direct function scope"
        )
    require(
        windows_authority,
        "wyl_fact_graph_win_validate_protected_owner_acl_for_user",
        "Windows graph-directory owner-only ACL binding",
    )
    require(
        windows_authority,
        "provider->owner",
        "Windows graph-directory pinned owner binding",
    )
    windows_open = function_body(
        windows, "wyl_fact_artifact_transition_windows_open"
    )
    windows_execute = function_body(
        windows, "wyl_fact_artifact_transition_windows_execute"
    )
    for symbol, body in (
        ("wyl_fact_artifact_transition_windows_open", windows_open),
        ("wyl_fact_artifact_transition_windows_capture", windows_capture),
        ("wyl_fact_artifact_transition_windows_execute", windows_execute),
    ):
        if (
            hashlib.sha256(body.encode("utf-8")).hexdigest()
            != WINDOWS_AUTHORITY_CALLER_BODY_SHA256[symbol]
        ):
            raise AssertionError(
                f"Windows authority caller normalized body profile drift: {symbol}"
            )
    if windows_open.count("provider_revalidate_authority") != 1:
        raise AssertionError("Windows provider open must revalidate authority once")
    if windows_capture.count("provider_revalidate_authority") != 3:
        raise AssertionError("Windows capture must revalidate every authority boundary")
    if windows_execute.count("provider_revalidate_authority") != 1:
        raise AssertionError("Windows execution must revalidate authority once")
    windows_authority_test = function_body(
        windows_test, "test_graph_directory_authority_is_revalidated"
    )
    if (
        hashlib.sha256(windows_authority_test.encode("utf-8")).hexdigest()
        != WINDOWS_AUTHORITY_TEST_BODY_SHA256
    ):
        raise AssertionError("Windows authority test normalized body profile drift")
    handle_mutations = re.findall(
        r"SetHandleInformation\s*\(\s*fixture\.directory\."
        r"(graph|root)_handle\s*,\s*HANDLE_FLAG_INHERIT\s*,\s*"
        r"(HANDLE_FLAG_INHERIT|0)\s*\)",
        windows_authority_test,
    )
    if handle_mutations != [
        ("graph", "HANDLE_FLAG_INHERIT"),
        ("graph", "0"),
        ("root", "HANDLE_FLAG_INHERIT"),
        ("root", "0"),
        ("graph", "HANDLE_FLAG_INHERIT"),
        ("graph", "0"),
        ("root", "HANDLE_FLAG_INHERIT"),
        ("root", "0"),
    ]:
        raise AssertionError(
            "Windows authority test must mutate graph and root handles in order"
        )
    for token, count in (
        ("SetHandleInformation", 8),
        ("unprotect_directory_acl", 2),
        ("set_directory_owner_only_acl", 2),
        ("wyl_fact_artifact_transition_windows_open", 4),
        ("wyl_fact_artifact_transition_windows_capture", 5),
        ("wyl_fact_artifact_transition_windows_execute", 3),
    ):
        if windows_authority_test.count(token) != count:
            raise AssertionError(
                f"Windows graph-directory authority test profile drift: {token}"
            )
    locator_scan = function_body(
        win_locator, "wyl_fact_artifact_win_locator_transition_inventory_scan"
    )
    require(locator_scan, "inventory_scan", "Windows shared scanner")

    run = function_body(fixture, "wyl_test_driver_run_mutation")
    require(
        run,
        "loaded.consumer_generation != expected_consumer_generation",
        "consumer generation binding",
    )
    require_before(run, "if (cancelled)", "load_valid", "cancellation boundary")
    require_before(
        run,
        "store->compare_and_swap",
        "return action",
        "durable attempt before backend action",
    )
    require_before(
        run,
        "WYL_TEST_DRIVER_TRACE_CAS_ATTEMPT",
        "store->compare_and_swap",
        "attempt trace ordering",
    )
    require(run, "WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN", "attempt marker")
    complete = function_body(fixture, "wyl_test_driver_complete_mutation")
    require(complete, "completed_state_legal", "completion state validation")
    restart = function_body(fixture, "wyl_test_driver_restart_action")
    require_before(
        restart,
        "stored->marker == WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN",
        "stored->marker == WYL_TEST_DRIVER_MARKER_NONE",
        "unknown attempt restart ordering",
    )
    if not re.search(
        r"WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN\s*\)\s*"
        r"return\s+WYL_TEST_DRIVER_RESTART_INSPECT_ONLY",
        restart,
    ):
        raise AssertionError("an unknown attempt must be inspect-only")
    require(restart, "if (!stored_value_valid", "fail-closed restart validation")
    require(
        restart,
        "return WYL_TEST_DRIVER_RESTART_REFUSE",
        "fail-closed restart result",
    )
    restart_compact = " ".join(restart.split())
    publish_alias = (
        "stored->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR "
        "&& stored->completed_state == "
        "WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE "
        "&& fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED) "
        "return WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR"
    )
    if publish_alias not in restart_compact:
        raise AssertionError("durable publication must re-earn sync after fresh capture")
    rollback_alias = (
        "stored->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK "
        "&& stored->completed_state == "
        "WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK "
        "&& fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY) "
        "return stored->resume_forbidden ? WYL_TEST_DRIVER_RESTART_RETIRE_STAGE"
    )
    if rollback_alias not in restart_compact:
        raise AssertionError("rolled-back physical READY must retire stage without replay")
    stored_valid = function_body(fixture, "stored_value_valid")
    require(stored_valid, "default:", "invalid marker rejection")
    require(stored_valid, "return FALSE", "invalid persisted value rejection")
    forbidden = (
        "rename(",
        "renameat",
        "unlink(",
        "unlinkat",
        "MoveFile",
        "DeleteFile",
    )
    if any(token in fixture for token in forbidden):
        raise AssertionError("neutral driver fixture contains a raw filesystem mutation")
    cancellation = function_body(
        driver_test, "test_cancellation_stops_before_attempt_boundary"
    )
    require(cancellation, "WYRELOG_E_CANCELLED", "driver cancellation result")
    require(cancellation, "action.calls", "cancelled action suppression")
    sync_boundaries = function_body(
        driver_test, "test_retryable_and_unsupported_sync_remain_nondurable"
    )
    require(sync_boundaries, "STATE_READY", "retryable sync remains nonterminal")
    require(
        sync_boundaries,
        "durability_unprovable_acknowledged",
        "unsupported durability acknowledgement",
    )
    require(
        sync_boundaries,
        "STATE_PUBLISHED",
        "unsupported sync is not promoted to durable",
    )

    require(posix_test, "g_spawn_sync", "POSIX fresh-process restart")
    require(posix_test, "posix_store_load", "POSIX persisted driver store")
    require(posix_test, "wyl_test_driver_run_mutation", "POSIX driver action boundary")
    require(posix_test, "wyl_test_driver_restart_action", "POSIX restart policy")
    require(
        posix_test,
        "test_end_to_end_classification",
        "POSIX real-capture classification matrix",
    )
    for lifecycle_test in (
        "test_execute_mode_a_full_lifecycle",
        "test_execute_mode_b_full_lifecycle",
        "test_execute_mode_a_rollback_lifecycle",
    ):
        body = function_body(posix_test, lifecycle_test)
        require(body, "transition_posix_capture", f"real capture in {lifecycle_test}")
        require(body, "main_transition_admit", f"real admission in {lifecycle_test}")
    require(
        function_body(posix_test, "test_execute_mode_a_full_lifecycle"),
        "WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR",
        "POSIX durable-publication restart alias",
    )
    require(
        function_body(posix_test, "test_execute_mode_a_rollback_lifecycle"),
        "WYL_TEST_DRIVER_RESTART_RETIRE_STAGE",
        "POSIX rolled-back restart alias",
    )
    require(windows_test, "CreateProcessW", "Windows fresh-process restart")
    require(windows_test, "windows_store_load", "Windows persisted driver store")
    require(
        windows_test,
        "wyl_test_driver_run_mutation",
        "Windows driver action boundary",
    )
    require(windows_test, "wyl_test_driver_restart_action", "Windows restart policy")
    require(windows_test, "test_real_capture_state_matrix", "Windows real-capture matrix")
    for lifecycle_test in (
        "test_mode_a_full_lifecycle",
        "test_mode_b_full_lifecycle_absent_rollback",
        "test_mode_a_rollback_lifecycle",
    ):
        body = function_body(windows_test, lifecycle_test)
        require(
            body,
            "transition_windows_capture",
            f"real capture in {lifecycle_test}",
        )
        require(body, "main_transition_admit", f"real admission in {lifecycle_test}")
    require(
        function_body(windows_test, "test_mode_a_full_lifecycle"),
        "WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR",
        "Windows durable-publication restart alias",
    )
    require(
        function_body(windows_test, "test_mode_a_rollback_lifecycle"),
        "WYL_TEST_DRIVER_RESTART_RETIRE_STAGE",
        "Windows rolled-back restart alias",
    )
    require(
        windows_test,
        "test_between_scan_mutation_publishes_no_outputs",
        "Windows unstable capture regression",
    )
    require(
        windows_test,
        "test_case_alias_is_ambiguous_without_mutation",
        "Windows case-alias regression",
    )

    meson = raw["tests/meson.build"]
    for token in (
        "fact-artifact-transition-driver",
        "fact-artifact-transition-driver-wiring",
        "fact-artifact-transition-driver-wiring-self",
        "fact-artifact-transition-posix",
        "fact-artifact-transition-windows",
    ):
        require(meson, token, "Meson registration")
    for workflow_name in (
        ".github/workflows/ci-pr.yml",
        ".github/workflows/ci-main.yml",
    ):
        workflow = raw[workflow_name]
        for token in (
            "fact-artifact-transition-driver",
            "fact-artifact-transition-driver-wiring",
            "fact-artifact-transition-driver-wiring-self",
            "fact-artifact-transition-windows",
        ):
            require(workflow, token, f"CI registration in {workflow_name}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"self-test fixture drift for {label}: expected one {old}")
    return text.replace(old, new, 1)


def negative_mutations(root: pathlib.Path) -> list[tuple[str, dict[str, str]]]:
    raw = {name: (root / name).read_text(encoding="utf-8") for name in FILES}
    fixture_name = "tests/fact-artifact-transition-driver-fixture.c"
    windows_name = "wyrelog/fact/graph-artifact-transition-windows-private.c"
    namespace_name = "wyrelog/fact/graph-artifact-namespace-private.c"
    posix_test_name = "tests/test-fact-artifact-transition-posix.c"
    windows_test_name = "tests/test-fact-artifact-transition-windows.c"
    mutations: list[tuple[str, dict[str, str]]] = []

    def add(label: str, name: str, old: str, new: str) -> None:
        mutations.append((label, {name: replace_once(raw[name], old, new, label)}))

    def hide_registration(
        label: str, name: str, function: str, mode: str = "remove"
    ) -> None:
        pattern = re.compile(
            r'^  g_test_add_func\s*\(\s*"[^"\\]+"\s*,\s*'
            + re.escape(function)
            + r"\s*\);",
            re.MULTILINE | re.DOTALL,
        )
        matches = list(pattern.finditer(raw[name]))
        if len(matches) != 1:
            raise AssertionError(
                f"self-test fixture drift for {label}: expected one registration"
            )
        call = matches[0].group(0)
        if mode == "if-false":
            replacement = "  if (FALSE) {\n" + "\n".join(
                "  " + line for line in call.splitlines()
            ) + "\n  }"
        elif mode == "preprocessor":
            replacement = "  #if 0\n" + call + "\n  #endif"
        else:
            replacement = "  /* registration removed by negative self-test */"
        mutated = raw[name][: matches[0].start()] + replacement + raw[name][matches[0].end() :]
        mutations.append((label, {name: mutated}))

    def insert_after_test_init(label: str, name: str, statement: str) -> str:
        pattern = re.compile(r"(?m)^  g_test_init\s*\([^;]+;\n")
        matches = list(pattern.finditer(raw[name]))
        if len(matches) != 1:
            raise AssertionError(
                f"self-test fixture drift for {label}: expected one g_test_init"
            )
        match = matches[0]
        mutated = raw[name][: match.end()] + statement + raw[name][match.end() :]
        mutations.append((label, {name: mutated}))
        return mutated

    def replace_function_body(
        label: str, name: str, symbol: str, replacement: str
    ) -> str:
        code = strip_c_comments_and_literals(normalize_c_translation(raw[name]))
        spans = function_body_spans(code, symbol)
        if len(spans) != 1:
            raise AssertionError(
                f"self-test fixture drift for {label}: expected one {symbol} body"
            )
        start, end = spans[0]
        return raw[name][:start] + replacement + raw[name][end:]

    posix_name = "wyrelog/fact/graph-artifact-transition-posix-private.c"
    dead_posix_capture = replace_once(
        raw[posix_name],
        "  wyrelog_error_t status = provider_revalidate_authority (provider);\n"
        "  if (status != WYRELOG_E_OK)\n"
        "    return status;\n"
        "  if (posix_fault_take\n"
        "        (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_OBSERVE_LEASE_FSTAT))",
        "  wyrelog_error_t status = WYRELOG_E_OK;\n"
        "  if (FALSE)\n"
        "    status = provider_revalidate_authority (provider);\n"
        "  if (status != WYRELOG_E_OK)\n"
        "    return status;\n"
        "  if (posix_fault_take\n"
        "        (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_OBSERVE_LEASE_FSTAT))",
        "POSIX dead capture authority call",
    )
    empty_posix_authority_test = replace_function_body(
        "POSIX empty root-authority test",
        posix_test_name,
        "test_foreign_root_authority_never_mutates",
        "{}",
    )
    weakened_posix_authority = replace_function_body(
        "POSIX weakened provider authority",
        posix_name,
        "provider_revalidate_authority",
        "{\n"
        "  return wyl_fact_root_writer_lease_authorizes_resolver\n"
        "    (provider->lease, provider->resolver);\n"
        "}",
    )
    empty_posix_correlated_test = replace_function_body(
        "POSIX empty correlated-capture test",
        posix_test_name,
        "test_capture_is_correlated_and_unstable_is_not_published",
        "{}",
    )
    mutations.extend(
        [
            ("POSIX dead capture authority call", {posix_name: dead_posix_capture}),
            (
                "POSIX empty root-authority test",
                {posix_test_name: empty_posix_authority_test},
            ),
            (
                "POSIX coordinated dead authority and empty test",
                {
                    posix_name: dead_posix_capture,
                    posix_test_name: empty_posix_authority_test,
                },
            ),
            (
                "POSIX weakened provider authority",
                {posix_name: weakened_posix_authority},
            ),
            (
                "POSIX empty correlated-capture test",
                {posix_test_name: empty_posix_correlated_test},
            ),
        ]
    )

    add(
        "generation binding",
        fixture_name,
        "loaded.consumer_generation != expected_consumer_generation",
        "FALSE /* generation deliberately ignored */",
    )
    add(
        "durable attempt before action",
        fixture_name,
        "return action (op, action_data, out_completed_state);",
        "return WYRELOG_E_OK; /* action (op, action_data, out_completed_state); */",
    )
    add(
        "inspect-only unknown attempt",
        fixture_name,
        "return WYL_TEST_DRIVER_RESTART_INSPECT_ONLY;",
        "return WYL_TEST_DRIVER_RESTART_CONTINUE;",
    )
    add(
        "cancellation boundary",
        fixture_name,
        "if (cancelled)\n    return WYRELOG_E_CANCELLED;",
        "if (FALSE)\n    return WYRELOG_E_CANCELLED;",
    )
    add(
        "rolled-back physical alias",
        fixture_name,
        "WYL_TEST_DRIVER_RESTART_RETIRE_STAGE",
        "WYL_TEST_DRIVER_RESTART_ROLLBACK_ONLY",
    )
    add(
        "published-durable physical alias",
        fixture_name,
        "== WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE\n"
        "      && fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED)",
        "== WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE\n"
        "      && fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE)",
    )
    add(
        "retry and unsupported driver case",
        "tests/test-fact-artifact-transition-driver.c",
        "test_retryable_and_unsupported_sync_remain_nondurable (void)",
        "test_disabled_sync_boundaries (void)",
    )
    add(
        "neutral fixture mutation leak",
        fixture_name,
        "#include <string.h>",
        "#include <string.h>\nstatic void leak (void) { unlinkat (0, \"x\", 0); }",
    )
    fixture_runner_override = replace_once(
        raw[fixture_name],
        "#include <string.h>",
        "#include <string.h>\n"
        "#ifndef G_OS_WIN32\n"
        "int\ng_test_run (void)\n{\n  return 0;\n}\n"
        "#endif",
        "fixture-local g_test_run replacement",
    )
    mutations.append(
        ("fixture-local g_test_run replacement", {fixture_name: fixture_runner_override})
    )
    fixture_pasted_runner = replace_once(
        raw[fixture_name],
        "#include <string.h>",
        "#include <string.h>\n"
        "#define JOIN_RAW(a, b) a ## b\n"
        "#define JOIN(a, b) JOIN_RAW (a, b)\n"
        "int\nJOIN (g_test_, run) (void)\n{\n  return 0;\n}",
        "fixture token-pasted g_test_run replacement",
    )
    mutations.append(
        (
            "fixture token-pasted g_test_run replacement",
            {fixture_name: fixture_pasted_runner},
        )
    )
    scan = "wyl_fact_artifact_win_locator_transition_inventory_scan"
    second_scan = raw[windows_name].find(scan, raw[windows_name].find(scan) + 1)
    if second_scan < 0:
        raise AssertionError("self-test fixture drift for second Windows scan")
    mutated_windows = (
        raw[windows_name][:second_scan]
        + '"wyl_fact_artifact_win_locator_transition_inventory_scan"'
        + raw[windows_name][second_scan + len(scan) :]
    )
    mutations.append(("active second Windows scan", {windows_name: mutated_windows}))
    add(
        "normal namespace isolation",
        namespace_name,
        "namespace_->owner, namespace_->lock_pin_fd, NULL, NULL,",
        'namespace_->owner, namespace_->lock_pin_fd, "stage", "rollback",',
    )
    add("POSIX fresh process", posix_test_name, "g_spawn_sync", "g_spawn_async")
    add("Windows fresh process", windows_test_name, "CreateProcessW", "CreateThread")
    constructor_exit = (
        "#include <stdlib.h>\n"
        "__attribute__ ((constructor))\n"
        "static void\npass_without_tests (void)\n{\n  exit (0);\n}\n"
        + raw[posix_test_name]
    )
    mutations.append(
        ("POSIX constructor successful exit", {posix_test_name: constructor_exit})
    )
    pasted_constructor = replace_once(
        raw[posix_test_name],
        "#include <unistd.h>",
        "#include <unistd.h>\n"
        "#define WYL_JOIN_INNER(a, b) a ## b\n"
        "#define WYL_JOIN(a, b) WYL_JOIN_INNER (a, b)\n"
        "#define WYL_ATTR WYL_JOIN (__attri, bute__)\n"
        "#define WYL_CTOR WYL_JOIN (constr, uctor)\n"
        "static void wyl_preflight_success (void) WYL_ATTR ((WYL_CTOR));\n"
        "static void\nwyl_preflight_success (void)\n{\n  _exit (0);\n}",
        "POSIX token-pasted constructor exit",
    )
    mutations.append(
        ("POSIX token-pasted constructor exit", {posix_test_name: pasted_constructor})
    )
    exec_replacement = replace_once(
        raw[posix_test_name],
        "test_execute_mode_a_full_lifecycle (void)\n{",
        "test_execute_mode_a_full_lifecycle (void)\n{\n"
        "  execl (\"/usr/bin/true\", \"true\", (char *) NULL);",
        "POSIX successful process replacement",
    )
    mutations.append(
        ("POSIX successful process replacement", {posix_test_name: exec_replacement})
    )
    workflow_name = ".github/workflows/ci-pr.yml"
    mutations.append(
        (
            "PR CI registration",
            {
                workflow_name: raw[workflow_name].replace(
                    "fact-artifact-transition-driver-wiring-self",
                    "fact-artifact-transition-driver-wiring-disabled",
                )
            },
        )
    )
    add(
        "Meson registration",
        "tests/meson.build",
        "'fact-artifact-transition-driver-wiring-self'",
        "'fact-artifact-transition-driver-wiring-disabled'",
    )
    registration_pattern = re.compile(
        r'^  g_test_add_func\s*\(\s*"([^"\\]+)"\s*,\s*'
        r"([A-Za-z_]\w*)\s*\);",
        re.MULTILINE | re.DOTALL,
    )
    registration_files = (
        ("driver", "tests/test-fact-artifact-transition-driver.c"),
        ("POSIX", posix_test_name),
        ("Windows", windows_test_name),
    )
    hide_modes = ("remove", "if-false", "preprocessor")
    for suite_label, name in registration_files:
        calls = list(registration_pattern.finditer(raw[name]))
        expected_count = TEST_REGISTRATION_PROFILES[name][0]
        if len(calls) != expected_count:
            raise AssertionError(
                f"self-test fixture drift for {suite_label}: expected "
                f"{expected_count} registrations"
            )
        for index, call_match in enumerate(calls):
            path, function = call_match.group(1), call_match.group(2)
            hide_registration(
                f"{suite_label} registration removal {path}",
                name,
                function,
                hide_modes[index % len(hide_modes)],
            )
            replacement_function = calls[(index + 1) % len(calls)].group(2)
            call = call_match.group(0)
            mis_mapped_call = re.sub(
                rf"\b{re.escape(function)}\b(?=\s*\)\s*;)",
                replacement_function,
                call,
                count=1,
            )
            mutated = (
                raw[name][: call_match.start()]
                + mis_mapped_call
                + raw[name][call_match.end() :]
            )
            mutations.append(
                (
                    f"{suite_label} registration mis-mapping {path}",
                    {name: mutated},
                )
            )

    add(
        "Windows graph-directory ACL authority removal",
        windows_name,
        "  return wyl_fact_graph_win_validate_protected_owner_acl_for_user\n"
        "           (provider->graph_handle, provider->owner,\n"
        "             OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);",
        "  return WYRELOG_E_OK;",
    )
    add(
        "Windows graph-handle inheritance authority removal",
        windows_name,
        "      || (graph_flags & HANDLE_FLAG_INHERIT) != 0)",
        "      || FALSE)",
    )
    add(
        "Windows root-handle query remapping",
        windows_name,
        "GetHandleInformation (provider->root_handle, &root_flags)",
        "GetHandleInformation (provider->graph_handle, &root_flags)",
    )
    add(
        "Windows graph-handle query remapping",
        windows_name,
        "GetHandleInformation (provider->graph_handle, &graph_flags)",
        "GetHandleInformation (provider->root_handle, &graph_flags)",
    )
    add(
        "Windows root-handle inheritance predicate weakening",
        windows_name,
        "(root_flags & HANDLE_FLAG_INHERIT) != 0",
        "(root_flags & HANDLE_FLAG_INHERIT) == 2",
    )
    dead_root_query = replace_once(
        raw[windows_name],
        "  if (!GetHandleInformation (provider->root_handle, &root_flags)",
        "  if (FALSE)\n"
        "    (void) GetHandleInformation (provider->root_handle, &root_flags);\n"
        "  if (!GetHandleInformation (provider->graph_handle, &root_flags)",
        "Windows coordinated root-authority decoy",
    )
    test_start = raw[windows_test_name].find(
        "test_graph_directory_authority_is_revalidated (void)\n{"
    )
    test_end = raw[windows_test_name].find("\n}\n\nstatic void", test_start)
    if test_start < 0 or test_end < 0:
        raise AssertionError(
            "self-test fixture drift for Windows root-authority test body"
        )
    authority_test_body = raw[windows_test_name][test_start:test_end]
    if authority_test_body.count("fixture.directory.root_handle") != 4:
        raise AssertionError(
            "self-test fixture drift for Windows root-handle mutations"
        )
    graph_only_authority_test = authority_test_body.replace(
        "fixture.directory.root_handle", "fixture.directory.graph_handle"
    )
    coordinated_test = (
        raw[windows_test_name][:test_start]
        + graph_only_authority_test
        + raw[windows_test_name][test_end:]
    )
    mutations.append(
        (
            "Windows coordinated dead root authority and graph-only test",
            {
                windows_name: dead_root_query,
                windows_test_name: coordinated_test,
            },
        )
    )
    dead_guard = replace_once(
        raw[windows_name],
        "  if (!GetHandleInformation (provider->root_handle, &root_flags)",
        "  if (FALSE)\n"
        "  if (!GetHandleInformation (provider->root_handle, &root_flags)",
        "Windows unconditional authority guard",
    )
    mutations.append(
        ("Windows dead exact authority guard", {windows_name: dead_guard})
    )
    authority_test_marker = (
        "test_graph_directory_authority_is_revalidated (void)\n{"
    )
    wrapped_authority_test_body = authority_test_body.replace(
        authority_test_marker,
        authority_test_marker + "\n  if (FALSE) {",
        1,
    ) + "\n  }"
    wrapped_authority_test = (
        raw[windows_test_name][:test_start]
        + wrapped_authority_test_body
        + raw[windows_test_name][test_end:]
    )
    mutations.append(
        (
            "Windows coordinated dead authority guard and test body",
            {
                windows_name: dead_guard,
                windows_test_name: wrapped_authority_test,
            },
        )
    )
    macro_shadowed_authority = replace_once(
        raw[windows_name],
        "#include <winternl.h>",
        "#include <winternl.h>\n"
        "#define GetHandleInformation(handle, flags) "
        "(*(flags) = 0, TRUE)",
        "Windows authority API macro shadow",
    )
    assertion_shadows = "\n".join(
        f"#define {symbol}(...) ((void) 0)"
        for symbol in (
            "g_assertion_message",
            "g_assertion_message_expr",
            "g_assertion_message_cmpnum",
            "g_assertion_message_cmpint",
            "g_assertion_message_cmpstr",
            "g_assertion_message_cmpstrv",
            "g_assertion_message_error",
        )
    )
    macro_shadowed_test = replace_once(
        raw[windows_test_name],
        '#include "fact/root-writer-lease-private.h"',
        '#include "fact/root-writer-lease-private.h"\n' + assertion_shadows,
        "Windows assertion backend macro shadow",
    )
    mutations.append(
        (
            "Windows coordinated authority and assertion macro shadows",
            {
                windows_name: macro_shadowed_authority,
                windows_test_name: macro_shadowed_test,
            },
        )
    )
    security_header_name = "wyrelog/fact/graph-windows-security-private.h"
    security_header = (root / security_header_name).read_text(encoding="utf-8")
    header_api_shadow = replace_once(
        security_header,
        "#include <windows.h>",
        "#include <windows.h>\n"
        "#define GetHandleInformation(handle, flags) "
        "(*(flags) = 0, TRUE)",
        "Windows included-header authority API macro shadow",
    )
    mutations.append(
        (
            "Windows included-header authority API macro shadow",
            {security_header_name: header_api_shadow},
        )
    )
    header_flag_shadow = replace_once(
        security_header,
        "#include <windows.h>",
        "#include <windows.h>\n"
        "#undef HANDLE_FLAG_INHERIT\n"
        "#define HANDLE_FLAG_INHERIT 0",
        "Windows included-header authority flag macro shadow",
    )
    mutations.append(
        (
            "Windows included-header authority flag macro shadow",
            {security_header_name: header_flag_shadow},
        )
    )
    caller_repair = replace_once(
        raw[windows_name],
        "  rc = provider_revalidate_authority (p);",
        "  SetHandleInformation (p->root_handle, HANDLE_FLAG_INHERIT, 0);\n"
        "  SetHandleInformation (p->graph_handle, HANDLE_FLAG_INHERIT, 0);\n"
        "  rc = provider_revalidate_authority (p);",
        "Windows provider-open caller authority repair",
    )
    mutations.append(
        ("Windows provider-open caller authority repair", {windows_name: caller_repair})
    )
    assertion_function_shadow = (
        "void\n"
        "g_assertion_message_cmpint (const char *domain, const char *file, "
        "int line,\n"
        "    const char *func, const char *expr, guint64 arg1, "
        "const char *cmp,\n"
        "    guint64 arg2, char numtype)\n"
        "{\n"
        "  ExitProcess (0);\n"
        "}\n\n"
        "void\n"
        "g_assertion_message_cmpnum (const char *domain, const char *file, "
        "int line,\n"
        "    const char *func, const char *expr, long double arg1, "
        "const char *cmp,\n"
        "    long double arg2, char numtype)\n"
        "{\n"
        "  ExitProcess (0);\n"
        "}\n"
    )
    assertion_function_test = replace_once(
        raw[windows_test_name],
        "#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        assertion_function_shadow
        + "\n#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        "Windows local assertion backend functions",
    )
    mutations.append(
        (
            "Windows coordinated caller repair and assertion functions",
            {
                windows_name: caller_repair,
                windows_test_name: assertion_function_test,
            },
        )
    )
    security_source_name = "wyrelog/fact/graph-windows-security-private.c"
    security_source = (root / security_source_name).read_text(encoding="utf-8")
    hidden_assertion_function_shadow = (
        "#define WYL_ASSERT_DEF\n"
        + assertion_function_shadow.replace(")\n{", ") WYL_ASSERT_DEF\n{")
    )
    hidden_assertion_function_test = replace_once(
        raw[windows_test_name],
        "#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        hidden_assertion_function_shadow
        + "\n#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        "Windows macro-hidden assertion backend functions",
    )
    mutations.append(
        (
            "Windows macro-hidden assertion backend functions",
            {windows_test_name: hidden_assertion_function_test},
        )
    )
    function_like_assertion_shadow = (
        "#define WYL_ASSERT_DEF(...)\n"
        + assertion_function_shadow.replace(")\n{", ") WYL_ASSERT_DEF(domain)\n{")
    )
    function_like_security_assertion = replace_once(
        security_source,
        "#include <string.h>",
        "#include <string.h>\n\n" + function_like_assertion_shadow,
        "Windows function-like-macro-hidden assertion backend",
    )
    mutations.append(
        (
            "Windows function-like-macro-hidden assertion backend",
            {security_source_name: function_like_security_assertion},
        )
    )
    driver_test_name = "tests/test-fact-artifact-transition-driver.c"
    function_like_test_assertion = replace_once(
        raw[driver_test_name],
        "#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        function_like_assertion_shadow.replace("ExitProcess (0);", "exit (0);")
        + "\n#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name",
        "driver function-like-macro-hidden assertion backend",
    )
    mutations.append(
        (
            "driver function-like-macro-hidden assertion backend",
            {driver_test_name: function_like_test_assertion},
        )
    )
    authority_helper_shadow = replace_once(
        security_header,
        "G_END_DECLS",
        "#define wyl_fact_graph_win_validate_protected_owner_acl_for_user(...) "
        "WYRELOG_E_OK\n\nG_END_DECLS",
        "Windows authority helper macro shadow",
    )
    authority_helper_implementation = replace_once(
        security_source,
        '#include "fact/graph-windows-security-private.h"',
        '#include "fact/graph-windows-security-private.h"\n'
        "#undef wyl_fact_graph_win_validate_protected_owner_acl_for_user",
        "Windows authority helper implementation undef",
    )
    mutations.extend(
        [
            (
                "Windows authority helper macro shadow",
                {security_header_name: authority_helper_shadow},
            ),
            (
                "Windows coordinated helper and macro-hidden assertion shadow",
                {
                    security_header_name: authority_helper_shadow,
                    security_source_name: authority_helper_implementation,
                    windows_test_name: hidden_assertion_function_test,
                },
            ),
        ]
    )
    semantic_error_shadow = replace_once(
        security_header,
        '#include "wyrelog/error.h"',
        '#include "wyrelog/error.h"\n'
        "#define WYRELOG_E_POLICY WYRELOG_E_OK",
        "Windows authority semantic error macro shadow",
    )
    assertion_backend_definition = (
        "void\n"
        "g_assertion_message (const char *domain, const char *file, int line,\n"
        "    const char *func, const char *message)\n"
        "{\n"
        "  ExitProcess (0);\n"
        "}\n"
    )
    security_assertion_backend = replace_once(
        security_source,
        "#include <string.h>",
        "#include <string.h>\n\n" + assertion_backend_definition,
        "Windows security assertion backend definition",
    )
    mutations.append(
        (
            "Windows coordinated semantic error and assertion backend shadow",
            {
                security_header_name: semantic_error_shadow,
                security_source_name: security_assertion_backend,
            },
        )
    )
    add(
        "Windows provider-open authority removal",
        windows_name,
        "  rc = provider_revalidate_authority (p);",
        "  rc = WYRELOG_E_OK;",
    )
    add(
        "Windows capture-entry authority removal",
        windows_name,
        "  wyrelog_error_t rc = provider_revalidate_authority (provider);",
        "  wyrelog_error_t rc = WYRELOG_E_OK;",
    )
    add(
        "Windows execute-entry authority removal",
        windows_name,
        "  wyrelog_error_t status = provider_revalidate_authority (provider);",
        "  wyrelog_error_t status = WYRELOG_E_OK;",
    )
    for label, name in (
        ("driver early successful exit", "tests/test-fact-artifact-transition-driver.c"),
        ("POSIX early successful exit", posix_test_name),
        ("Windows early successful exit", windows_test_name),
    ):
        insert_after_test_init(label, name, "  return 0;\n")

    goto_name = posix_test_name
    goto_mutated = insert_after_test_init(
        "POSIX goto over registrations", goto_name, "  goto registrations_done;\n"
    )
    goto_mutated = replace_once(
        goto_mutated,
        "  return g_test_run ();",
        "registrations_done:\n  return g_test_run ();",
        "POSIX goto label",
    )
    mutations[-1] = ("POSIX goto over registrations", {goto_name: goto_mutated})

    driver_name = "tests/test-fact-artifact-transition-driver.c"
    line_splice_target = (
        '  g_test_add_func ("/fact/artifact-transition-driver/cancellation-boundary",\n'
        "      test_cancellation_stops_before_attempt_boundary);"
    )
    line_spliced = replace_once(
        raw[driver_name],
        line_splice_target,
        "  // registration hidden by translation-phase splice \\\n"
        + line_splice_target,
        "line-spliced registration comment",
    )
    mutations.append(("line-spliced registration comment", {driver_name: line_spliced}))

    macro_anchor = "\nint\nmain (int argc, char **argv)"
    api_shadow = replace_once(
        raw[driver_name],
        macro_anchor,
        "\n#define g_test_add_func(path, function) ((void) 0)\n" + macro_anchor,
        "registration API macro shadow",
    )
    mutations.append(("registration API macro shadow", {driver_name: api_shadow}))
    assertion_shadow = replace_once(
        raw[driver_name],
        macro_anchor,
        "\n#define g_assert_cmpint(left, op, right) ((void) 0)\n" + macro_anchor,
        "assertion macro shadow",
    )
    mutations.append(("assertion macro shadow", {driver_name: assertion_shadow}))
    function_shadow = replace_once(
        raw[driver_name],
        macro_anchor,
        "\n#define test_cancellation_stops_before_attempt_boundary "
        "test_corrupt_store_always_refuses\n" + macro_anchor,
        "protected function macro alias",
    )
    mutations.append(("protected function macro alias", {driver_name: function_shadow}))
    digraph_shadow = replace_once(
        raw[driver_name],
        macro_anchor,
        "\n%:define g_test_add_func(path, function) ((void) 0)\n" + macro_anchor,
        "digraph registration API macro shadow",
    )
    mutations.append(
        ("digraph registration API macro shadow", {driver_name: digraph_shadow})
    )
    trigraph_shadow = replace_once(
        raw[driver_name],
        macro_anchor,
        "\n??=define g_test_add_??/\n"
        "func(path, function) ((void) 0)\n"
        + macro_anchor,
        "trigraph-spliced registration API macro shadow",
    )
    mutations.append(
        (
            "trigraph-spliced registration API macro shadow",
            {driver_name: trigraph_shadow},
        )
    )
    return_shadow = replace_once(
        raw[driver_name],
        macro_anchor,
        "\n#define return if (0) return\n" + macro_anchor,
        "return keyword macro shadow",
    )
    mutations.append(("return keyword macro shadow", {driver_name: return_shadow}))
    local_runner = replace_once(
        raw[driver_name],
        macro_anchor,
        "\nint\ng_test_run (void)\n{\n  return 0;\n}\n" + macro_anchor,
        "local g_test_run replacement",
    )
    mutations.append(("local g_test_run replacement", {driver_name: local_runner}))
    early_test_return = replace_once(
        raw[driver_name],
        "test_cancellation_stops_before_attempt_boundary (void)\n{",
        "test_cancellation_stops_before_attempt_boundary (void)\n{\n  return;",
        "protected test early return",
    )
    mutations.append(("protected test early return", {driver_name: early_test_return}))
    helper_exit = replace_once(
        raw[driver_name],
        "memory_store_new (void)\n{",
        "memory_store_new (void)\n{\n  extern void exit (int status);\n  exit (0);",
        "protected helper successful exit",
    )
    mutations.append(("protected helper successful exit", {driver_name: helper_exit}))
    pragma_weak = replace_once(
        raw[driver_name],
        macro_anchor,
        "\nint\nwyl_preflight_noop (void)\n{\n  return 0;\n}\n"
        "_Pragma (\"weak g_test_run = wyl_preflight_noop\")\n"
        + macro_anchor,
        "pragma weak g_test_run replacement",
    )
    mutations.append(
        ("pragma weak g_test_run replacement", {driver_name: pragma_weak})
    )
    trigraph_comment = replace_once(
        raw[driver_name],
        line_splice_target,
        "  // registration hidden by trigraph splice ??/\n" + line_splice_target,
        "trigraph-spliced registration comment",
    )
    mutations.append(
        ("trigraph-spliced registration comment", {driver_name: trigraph_comment})
    )

    driver_code = strip_c_comments_and_literals(
        normalize_c_translation(raw[driver_name])
    )
    main_start, main_end = function_body_span(driver_code, "main", "g_test_init")
    declaration_start = raw[driver_name].rfind("\nint\nmain", 0, main_start)
    if declaration_start < 0:
        raise AssertionError("self-test fixture drift for inactive decoy main")
    declaration_start += 1
    main_definition = raw[driver_name][declaration_start:main_end]
    decoy_main = main_definition.replace(
        "  g_test_init (&argc, &argv, NULL);",
        "  g_test_init (&argc, &argv, NULL);\n  return 0;",
        1,
    )
    decoy_main_mutated = (
        raw[driver_name][:declaration_start]
        + "#if 0\n"
        + main_definition
        + "\n#endif\n"
        + decoy_main
        + raw[driver_name][main_end:]
    )
    mutations.append(
        ("inactive decoy main with real early exit", {driver_name: decoy_main_mutated})
    )

    protected_symbol = "test_cancellation_stops_before_attempt_boundary"
    protected_start, protected_end = function_body_span(driver_code, protected_symbol)
    protected_declaration = raw[driver_name].rfind(
        "\nstatic void\n" + protected_symbol, 0, protected_start
    )
    if protected_declaration < 0:
        raise AssertionError("self-test fixture drift for inactive protected decoy")
    protected_declaration += 1
    protected_definition = raw[driver_name][protected_declaration:protected_end]
    no_op_definition = (
        raw[driver_name][protected_declaration:protected_start]
        + "{\n  g_assert_true (TRUE);\n}"
    )
    decoy_protected_mutated = (
        raw[driver_name][:protected_declaration]
        + "#if 0\n"
        + protected_definition
        + "\n#endif\n"
        + no_op_definition
        + raw[driver_name][protected_end:]
    )
    mutations.append(
        (
            "inactive protected-function decoy with real no-op",
            {driver_name: decoy_protected_mutated},
        )
    )
    meson_alias = (
        "add_project_arguments('-Dg_test_add_func=ignored_test_registration', "
        "language: 'c')\n" + raw["tests/meson.build"]
    )
    mutations.append(("Meson registration API alias", {"tests/meson.build": meson_alias}))
    meson_split_alias = replace_once(
        raw["tests/meson.build"],
        "  dependencies : [wyrelog_dep],\n)\n"
        "test('fact-artifact-transition-driver'",
        "  c_args : ['-Dg_test_' + 'run=g_test_subprocess'],\n"
        "  dependencies : [wyrelog_dep],\n)\n"
        "test('fact-artifact-transition-driver'",
        "Meson split-literal target alias",
    )
    mutations.append(
        ("Meson split-literal target alias", {"tests/meson.build": meson_split_alias})
    )
    driver_target = (
        "test_fact_artifact_transition_driver = executable(\n"
        "  'test-fact-artifact-transition-driver',\n"
        "  'test-fact-artifact-transition-driver.c',\n"
        "  'fact-artifact-transition-driver-fixture.c',\n"
        "  include_directories : include_directories('../wyrelog'),\n"
        "  dependencies : [wyrelog_dep],\n"
        ")\n"
    )
    cross_file_dependency_rebind = replace_once(
        raw["tests/meson.build"],
        driver_target,
        "wyrelog_dep = declare_dependency(\n"
        "  dependencies : [wyrelog_dep],\n"
        "  compile_args : ['-Dg_test_' + 'run=g_test_subprocess'],\n"
        ")\n"
        + driver_target,
        "Meson cross-file dependency rebinding",
    )
    mutations.append(
        (
            "Meson cross-file dependency rebinding",
            {"tests/meson.build": cross_file_dependency_rebind},
        )
    )
    driver_target_alias = driver_target.replace(
        "  dependencies : [wyrelog_dep],",
        "  c_args : ['-Dg_test_' + 'run=g_test_subprocess'],\n"
        "  dependencies : [wyrelog_dep],",
    )
    triple_decoy = replace_once(
        raw["tests/meson.build"],
        driver_target,
        "'''\n" + driver_target + "'''\n" + driver_target_alias,
        "Meson triple-string target decoy",
    )
    mutations.append(
        ("Meson triple-string target decoy", {"tests/meson.build": triple_decoy})
    )
    comment_decoy = replace_once(
        raw["tests/meson.build"],
        driver_target,
        "\n".join("# " + line for line in driver_target.splitlines())
        + "\n"
        + driver_target_alias,
        "Meson comment target decoy",
    )
    mutations.append(
        ("Meson comment target decoy", {"tests/meson.build": comment_decoy})
    )
    inactive_decoy = replace_once(
        raw["tests/meson.build"],
        driver_target,
        "if false\n" + driver_target + "endif\n" + driver_target_alias,
        "Meson inactive target decoy",
    )
    mutations.append(
        ("Meson inactive target decoy", {"tests/meson.build": inactive_decoy})
    )
    dynamic_names_then_done = (
        "decoy_driver_name = 'fact-artifact-transition-' + 'driver'\n"
        "decoy_posix_name = 'fact-artifact-transition-' + 'posix'\n"
        "decoy_windows_name = 'fact-artifact-transition-' + 'windows'\n"
        "alias_target('test-' + decoy_driver_name, "
        "test_fact_artifact_transition_names)\n"
        "alias_target('test-' + decoy_posix_name, "
        "test_fact_artifact_transition_names)\n"
        "alias_target('test-' + decoy_windows_name, "
        "test_fact_artifact_transition_names)\n"
        "test(decoy_driver_name, test_fact_artifact_transition_names)\n"
        "test(decoy_driver_name + '-wiring', python3, args : ['-c', 'pass'])\n"
        "test(decoy_driver_name + '-wiring-self', python3, "
        "args : ['-c', 'pass'])\n"
        "test(decoy_posix_name, test_fact_artifact_transition_names)\n"
        "test(decoy_windows_name, test_fact_artifact_transition_names)\n"
        "subdir_done()\n\n"
    )
    subdir_done_decoy = replace_once(
        raw["tests/meson.build"],
        driver_target,
        dynamic_names_then_done + driver_target,
        "Meson dynamic names before subdir_done",
    )
    mutations.append(
        (
            "Meson dynamic names before subdir_done",
            {"tests/meson.build": subdir_done_decoy},
        )
    )
    continuation_rebind = replace_once(
        raw["tests/meson.build"],
        "test('fact-artifact-transition-driver', "
        "test_fact_artifact_transition_driver)",
        "test_fact_artifact_transition_driver \\\n"
        "= python3\n"
        "test('fact-artifact-transition-driver', "
        "test_fact_artifact_transition_driver)",
        "Meson continued target rebinding",
    )
    mutations.append(
        ("Meson continued target rebinding", {"tests/meson.build": continuation_rebind})
    )
    continued_set_variable = (
        "set_variable \\\n"
        "('test_fact_artifact_transition_driver', python3)\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        (
            "Meson continued dynamic target rebinding",
            {"tests/meson.build": continued_set_variable},
        )
    )
    continued_test_wrapper = (
        "add_test_setup \\\n"
        "('bypass', exe_wrapper : [python3, '-c', 'pass'], is_default : true)\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        (
            "Meson continued default no-op wrapper",
            {"tests/meson.build": continued_test_wrapper},
        )
    )
    overwrite_command = (
        "run_command(python3, '-c', "
        "'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("
        "\"raise SystemExit(0)\\\\n\")', "
        "meson.current_source_dir() / "
        "'test-fact-artifact-transition-driver-wiring.py', check : true)"
    )
    test_run_command = replace_once(
        raw["tests/meson.build"],
        "python3 = find_program('python3')",
        "python3 = find_program('python3')\n" + overwrite_command,
        "Meson test-source run_command overwrite",
    )
    mutations.append(
        (
            "Meson test-source run_command overwrite",
            {"tests/meson.build": test_run_command},
        )
    )
    root_overwrite_command = (
        "run_command(find_program('python3'), '-c', "
        "'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("
        "\"raise SystemExit(0)\\\\n\")', "
        "meson.project_source_root() / 'tests' / "
        "'test-fact-artifact-transition-driver-wiring.py', check : true)\n"
    )
    root_run_command = replace_once(
        raw["meson.build"],
        "subdir('wyrelog')",
        root_overwrite_command + "subdir('wyrelog')",
        "Meson root run_command overwrite",
    )
    mutations.append(
        ("Meson root run_command overwrite", {"meson.build": root_run_command})
    )
    postconf_overwrite = (
        "meson.add_postconf_script(python3, '-c', "
        "'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("
        "\"raise SystemExit(0)\\\\n\")', "
        "meson.current_source_dir() / "
        "'test-fact-artifact-transition-driver-wiring.py')\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        (
            "Meson post-configuration checker overwrite",
            {"tests/meson.build": postconf_overwrite},
        )
    )
    configure_overwrite = (
        "configure_file(output : 'driver-wiring-marker', command : [python3, '-c', "
        "'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("
        "\"raise SystemExit(0)\\\\n\"); pathlib.Path(sys.argv[2]).touch()', "
        "meson.current_source_dir() / "
        "'test-fact-artifact-transition-driver-wiring.py', '@OUTPUT@'])\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        (
            "Meson configure_file checker overwrite",
            {"tests/meson.build": configure_overwrite},
        )
    )
    custom_target_overwrite = (
        "custom_target('driver-wiring-overwrite', output : 'driver-wiring-marker', "
        "command : [python3, '-c', "
        "'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("
        "\"raise SystemExit(0)\\\\n\"); pathlib.Path(sys.argv[2]).touch()', "
        "meson.current_source_dir() / "
        "'test-fact-artifact-transition-driver-wiring.py', '@OUTPUT@'], "
        "build_by_default : true)\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        (
            "Meson custom_target checker overwrite",
            {"tests/meson.build": custom_target_overwrite},
        )
    )
    spaced_override = (
        "meson . override_find_program('python3', find_program('true'))\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        ("Meson spaced-dot program override", {"tests/meson.build": spaced_override})
    )
    parenthesized_override = (
        "(meson).override_find_program('python3', find_program('true'))\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        (
            "Meson parenthesized-receiver program override",
            {"tests/meson.build": parenthesized_override},
        )
    )
    continued_override = (
        "meson \\\n. \\\n"
        "override_find_program('python3', find_program('true'))\n"
        + raw["tests/meson.build"]
    )
    mutations.append(
        (
            "Meson continued-dot program override",
            {"tests/meson.build": continued_override},
        )
    )
    driver_mapping = (
        "test('fact-artifact-transition-driver', "
        "test_fact_artifact_transition_driver)"
    )
    foreach_shadow = replace_once(
        raw["tests/meson.build"],
        driver_mapping,
        "foreach test_fact_artifact_transition_driver : [find_program('true')]\n"
        "  "
        + driver_mapping
        + "\nendforeach",
        "Meson foreach target shadow",
    )
    mutations.append(
        ("Meson foreach target shadow", {"tests/meson.build": foreach_shadow})
    )
    second_foreach_shadow = replace_once(
        raw["tests/meson.build"],
        driver_mapping,
        "foreach ignored, test_fact_artifact_transition_driver : "
        "{'driver': find_program('true')}\n  "
        + driver_mapping
        + "\nendforeach",
        "Meson second foreach-variable target shadow",
    )
    mutations.append(
        (
            "Meson second foreach-variable target shadow",
            {"tests/meson.build": second_foreach_shadow},
        )
    )
    foreach_dynamic_decoy = replace_once(
        raw["tests/meson.build"],
        driver_target,
        "foreach inactive : []\n" + driver_target + "endforeach\n",
        "Meson foreach dynamic-name target decoy",
    )
    foreach_dynamic_decoy = replace_once(
        foreach_dynamic_decoy,
        driver_mapping,
        "foreach inactive : []\n  "
        + driver_mapping
        + "\nendforeach\n"
        "decoy_driver = executable(\n"
        "  'test-fact-artifact-' + 'transition-driver',\n"
        "  'test-fact-artifact-transition-names.c',\n"
        "  include_directories : include_directories('../wyrelog'),\n"
        "  dependencies : [wyrelog_dep],\n"
        ")\n"
        "test('fact-artifact-' + 'transition-driver', decoy_driver)",
        "Meson foreach dynamic-name mapping decoy",
    )
    mutations.append(
        (
            "Meson foreach dynamic-name target and mapping decoy",
            {"tests/meson.build": foreach_dynamic_decoy},
        )
    )
    for test_name, target in (
        (
            "fact-artifact-transition-driver",
            "test_fact_artifact_transition_driver",
        ),
        (
            "fact-artifact-transition-posix",
            "test_fact_artifact_transition_posix",
        ),
        (
            "fact-artifact-transition-windows",
            "test_fact_artifact_transition_windows",
        ),
    ):
        remapped = replace_once(
            raw["tests/meson.build"],
            f"test('{test_name}', {target})",
            f"test('{test_name}', python3)",
            f"Meson {test_name} remapping",
        )
        mutations.append(
            (f"Meson {test_name} remapping", {"tests/meson.build": remapped})
        )
    rebound_target = replace_once(
        raw["tests/meson.build"],
        "test('fact-artifact-transition-driver', "
        "test_fact_artifact_transition_driver)",
        "test_fact_artifact_transition_driver = python3\n"
        "test('fact-artifact-transition-driver', "
        "test_fact_artifact_transition_driver)",
        "Meson protected target rebinding",
    )
    mutations.append(
        ("Meson protected target rebinding", {"tests/meson.build": rebound_target})
    )
    wiring_remap = replace_once(
        raw["tests/meson.build"],
        "test('fact-artifact-transition-driver-wiring', python3,",
        "test('fact-artifact-transition-driver-wiring', "
        "test_fact_artifact_transition_driver,",
        "Meson wiring checker remapping",
    )
    mutations.append(
        ("Meson wiring checker remapping", {"tests/meson.build": wiring_remap})
    )
    wiring_timeout_weakened = replace_once(
        raw["tests/meson.build"],
        "test('fact-artifact-transition-driver-wiring', python3,\n"
        "  args : [\n"
        "    meson.current_source_dir() / "
        "'test-fact-artifact-transition-driver-wiring.py',\n"
        "    meson.project_source_root(),\n"
        "  ],\n"
        "  timeout : 120,\n"
        ")",
        "test('fact-artifact-transition-driver-wiring', python3,\n"
        "  args : [\n"
        "    meson.current_source_dir() / "
        "'test-fact-artifact-transition-driver-wiring.py',\n"
        "    meson.project_source_root(),\n"
        "  ],\n"
        "  timeout : 30,\n"
        ")",
        "Meson wiring checker timeout weakening",
    )
    mutations.append(
        (
            "Meson wiring checker timeout weakening",
            {"tests/meson.build": wiring_timeout_weakened},
        )
    )
    python_rebind = replace_once(
        raw["tests/meson.build"],
        "python3 = find_program('python3')",
        "python3 = find_program('python3')\npython3 = find_program('true')",
        "Meson Python runner rebinding",
    )
    mutations.append(
        ("Meson Python runner rebinding", {"tests/meson.build": python_rebind})
    )
    test_wrapper = (
        "add_test_setup('bypass', exe_wrapper : [python3, '-c', 'pass'], "
        "is_default : true)\n" + raw["tests/meson.build"]
    )
    mutations.append(
        ("Meson default no-op test wrapper", {"tests/meson.build": test_wrapper})
    )
    meson_variable_alias = replace_once(
        raw["tests/meson.build"],
        "fact_test_support_c_args = []",
        "fact_test_support_c_args = ['-Dg_test_' + 'run=g_test_subprocess']",
        "Meson variable-composed alias",
    )
    mutations.append(
        ("Meson variable-composed alias", {"tests/meson.build": meson_variable_alias})
    )
    project_default_alias = replace_once(
        raw["meson.build"],
        "    'warning_level=2',",
        "    'warning_level=2',\n"
        "    'c_args=-Dg_test_run=g_test_subprocess',",
        "Meson project default compiler alias",
    )
    mutations.append(
        ("Meson project default compiler alias", {"meson.build": project_default_alias})
    )
    dependency_alias = replace_once(
        raw["wyrelog/meson.build"],
        "wyrelog_dep = declare_dependency(\n  link_with : libwyrelog,",
        "wyrelog_dep = declare_dependency(\n"
        "  compile_args : ['-Dg_test_' + 'run=g_test_subprocess'],\n"
        "  link_with : libwyrelog,",
        "Meson dependency-composed alias",
    )
    mutations.append(
        (
            "Meson dependency-composed alias",
            {"wyrelog/meson.build": dependency_alias},
        )
    )
    production_name = "wyrelog/wyl-version.c"
    production_runner = (
        "int\ng_test_run (void)\n{\n  return 0;\n}\n"
        + (root / production_name).read_text(encoding="utf-8")
    )
    mutations.append(
        ("unlisted production g_test_run replacement", {production_name: production_runner})
    )
    production_header_name = "wyrelog/fact/graph-artifact-main-transition-private.h"
    production_header = (root / production_header_name).read_text(encoding="utf-8")
    header_runner_override = (
        "#define g_test_run() 0\n" + production_header
    )
    mutations.append(
        (
            "production-header g_test_run replacement",
            {production_header_name: header_runner_override},
        )
    )
    header_assertion_override = (
        "#undef g_assert_cmpint\n"
        "#define g_assert_cmpint(...) ((void) 0)\n"
        "#undef g_assert_cmpuint\n"
        "#define g_assert_cmpuint(...) ((void) 0)\n"
        + production_header
    )
    mutations.append(
        (
            "production-header assertion replacement",
            {production_header_name: header_assertion_override},
        )
    )
    fixture_header_name = "tests/fact-artifact-transition-driver-fixture.h"
    fixture_header_helper = (
        raw[fixture_header_name]
        + "\nstatic inline void\nwyl_preflight_pass (void)\n{\n"
        "  extern void exit (int status);\n  exit (0);\n}\n"
    )
    driver_indirect_exit = replace_once(
        raw[driver_name],
        "test_cancellation_stops_before_attempt_boundary (void)\n{",
        "test_cancellation_stops_before_attempt_boundary (void)\n{\n"
        "  wyl_preflight_pass ();",
        "fixture-header indirect successful exit",
    )
    mutations.append(
        (
            "fixture-header indirect successful exit",
            {fixture_header_name: fixture_header_helper, driver_name: driver_indirect_exit},
        )
    )
    production_constructor_name = (
        "wyrelog/fact/graph-artifact-main-transition-private.c"
    )
    production_constructor = (
        "#include <stdlib.h>\n"
        "__attribute__ ((constructor))\n"
        "static void\npreflight_pass (void)\n{\n  exit (0);\n}\n"
        + (root / production_constructor_name).read_text(encoding="utf-8")
    )
    mutations.append(
        (
            "production constructor successful exit",
            {production_constructor_name: production_constructor},
        )
    )
    cxx_constructor_name = "wyrelog/fact/secure-duckdb-bridge-private.cc"
    cxx_constructor = (
        (root / cxx_constructor_name).read_text(encoding="utf-8")
        + "\n#include <cstdlib>\n"
        "namespace {\n"
        "struct PreflightPass { PreflightPass () { std::exit (0); } };\n"
        "PreflightPass preflight_pass;\n"
        "}\n"
    )
    mutations.append(
        (
            "C++ static-initialization successful exit",
            {cxx_constructor_name: cxx_constructor},
        )
    )
    new_cxx_name = "wyrelog/fact/preflight-pass.cc"
    new_cxx = (
        "#include <cstdlib>\n"
        "namespace {\n"
        "struct PreflightPass { PreflightPass () { std::exit (0); } };\n"
        "PreflightPass preflight_pass;\n"
        "}\n"
    )
    new_cxx_meson = replace_once(
        raw["wyrelog/meson.build"],
        "libwyrelog = library('wyrelog',",
        "wyrelog_sources += files('fact/preflight-pass.cc')\n"
        "libwyrelog = library('wyrelog',",
        "new C++ static-initialization source registration",
    )
    mutations.append(
        (
            "new C++ static-initialization source registration",
            {new_cxx_name: new_cxx, "wyrelog/meson.build": new_cxx_meson},
        )
    )
    new_header_name = "tests/assertion-bypass.h"
    new_header = (
        "#pragma once\n"
        "#undef g_assert_cmpint\n"
        "#define g_assert_cmpint(...) ((void) 0)\n"
        "#undef g_assert_cmpuint\n"
        "#define g_assert_cmpuint(...) ((void) 0)\n"
    )
    driver_with_new_header = replace_once(
        raw[driver_name],
        "#include <glib.h>",
        "#include <glib.h>\n#include \"assertion-bypass.h\"",
        "new test assertion-bypass header",
    )
    mutations.append(
        (
            "new test assertion-bypass header",
            {new_header_name: new_header, driver_name: driver_with_new_header},
        )
    )
    shadow_header_name = "tests/dirent.h"
    shadow_header = (
        "#include_next <dirent.h>\n"
        "int\nmain (void)\n{\n  return 0;\n}\n"
        "#define main wyl_hidden_transition_posix_main\n"
    )
    mutations.append(
        ("test-local system-header shadow", {shadow_header_name: shadow_header})
    )
    nested_meson_name = "tests/vacuous-driver-tests/meson.build"
    nested_meson = (
        "add_test_setup('vacuous-driver-tests', "
        "exe_wrapper : [python3, '-c', 'raise SystemExit(0)'], "
        "is_default : true)\n"
    )
    tests_with_subdir = raw["tests/meson.build"] + (
        "\nsubdir('vacuous-driver-tests')\n"
    )
    mutations.append(
        (
            "nested Meson default test wrapper",
            {nested_meson_name: nested_meson, "tests/meson.build": tests_with_subdir},
        )
    )
    return mutations


def positive_mutations(root: pathlib.Path) -> list[tuple[str, dict[str, str]]]:
    raw = {name: (root / name).read_text(encoding="utf-8") for name in FILES}
    inert = (
        "# run_command(python3, '-c', 'raise SystemExit(0)')\n"
        "'''\n"
        "meson . override_find_program('python3', find_program('true'))\n"
        "run_command(python3, '-c', 'raise SystemExit(0)')\n"
        "subdir_done()\n"
        "meson.add_postconf_script(find_program('true'))\n"
        "configure_file(output : 'x', command : [find_program('true')])\n"
        "custom_target('x', output : 'x', command : [find_program('true')])\n"
        "'''\n"
    )
    inert_c = (
        raw["tests/fact-artifact-transition-driver-fixture.c"]
        + "\nstatic const char *const inert_pragma_text = \"_Pragma weak g_test_run\";\n"
        "/* __pragma and exit (0) remain inert in comments. */\n"
    )
    return [
        (
            "Meson comment and triple-string decoys remain inert",
            {"tests/meson.build": inert + raw["tests/meson.build"]},
        ),
        (
            "C string and comment pragma decoys remain inert",
            {"tests/fact-artifact-transition-driver-fixture.c": inert_c},
        ),
    ]


def main() -> int:
    args = sys.argv[1:]
    self_test = "--self-test" in args
    args = [arg for arg in args if arg != "--self-test"]
    root = pathlib.Path(args[0] if args else ".").resolve()
    verify(root)
    if self_test:
        for _, overrides in positive_mutations(root):
            verify(root, overrides)
        for label, overrides in negative_mutations(root):
            try:
                verify(root, overrides)
            except AssertionError:
                continue
            raise AssertionError(f"negative self-test did not reject: {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

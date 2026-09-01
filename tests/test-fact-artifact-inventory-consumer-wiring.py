#!/usr/bin/env python3
"""Guard issue #622 inventory completeness and consumer/platform wiring."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import shlex
import sys


HEADER = "wyrelog/fact/graph-artifact-inventory-private.h"
MODEL = "wyrelog/fact/graph-artifact-inventory-private.c"
POSIX_PROVIDER = "wyrelog/fact/graph-artifact-namespace-private.c"
POSIX_NAMESPACE_HEADER = "wyrelog/fact/graph-artifact-namespace-private.h"
POSIX_INVENTORY_HEADER = (
    "wyrelog/fact/graph-artifact-inventory-posix-private.h"
)
MAIN_TRANSITION_HEADER = (
    "wyrelog/fact/graph-artifact-main-transition-private.h"
)
POSIX_LOCK_HEADER_CLOSURE = (
    POSIX_NAMESPACE_HEADER,
    POSIX_INVENTORY_HEADER,
    "wyrelog/fact/graph-provisioned-pair-internal.h",
    "wyrelog/wyl-id-private.h",
    "wyrelog/error.h",
    HEADER,
    MAIN_TRANSITION_HEADER,
    "wyrelog/fact/graph-locator-private.h",
    "wyrelog/fact/graph-windows-security-private.h",
    "wyrelog/fact/recovery-mac-private.h",
)
WINDOWS_PROVIDER = "wyrelog/fact/graph-artifact-windows-namespace-private.c"
MODEL_TEST = "tests/test-fact-artifact-inventory.c"
CONSUMER_TEST = "tests/test-fact-artifact-inventory-consumers.c"
MESON = "tests/meson.build"
CI_PR = ".github/workflows/ci-pr.yml"
CI_MAIN = ".github/workflows/ci-main.yml"

ARTIFACT_LOCK_DIAGNOSTIC = (
    "#869 ruling 1 would be invalid: a read-only mount could admit a read-only "
    "open the engine builder refuses, causing boot to report a pending-erasure "
    "state for that graph"
)
EXPECTED_POSIX_OPENAT_PROFILE_SHA256 = (
    "e53298e179e2c767efd021602bda7a69ae88ab46b28320d6f10dbb3ec86c0e17"
)
EXPECTED_POSIX_DIRECTIVE_PROFILE_SHA256 = (
    "0ce8c0ada1d16956a8e35fc943a38057d1cafbafd72018303ce7b32cfffc85f7"
)
EXPECTED_POSIX_SYSCALL_PROFILE_SHA256 = (
    "dd48522fa6ad547569db5958756489866cf22f2e2f61e9693c511b42e68833cd"
)
EXPECTED_POSIX_CALL_PROFILE_SHA256 = (
    "b8d10b059d0affb45718474feb21a92f6560a5a539bdbfd5b8493104a68b93f8"
)
EXPECTED_POSIX_SEMANTIC_TOKEN_PROFILE_SHA256 = (
    "39e49b4436e109c13bd9aae7aa7e11451ab6fbcb82634592c42cdf1893b18de7"
)
BASELINE_POSIX_COMMENTLESS_SHA256 = (
    "7481ee195e91afa1851283b2958c57087f0000b4e685424ed05b01cefd83bf73"
)
EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_COUNTS = (
    13, 7, 10, 8, 2, 3, 4, 36, 6, 5,
)
EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256 = (
    "6d2306c7000d07c4497048196a52e8e1534775e81da4a6016b67fd7d6c66de8e"
)
EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_COUNTS = (
    1299, 70, 65, 98, 89, 364, 501, 821, 120, 315,
)
EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256 = (
    "d8a85c02832b0a3d6bf44fecf7f3e733912670dc90e3a2929761d98fe538e694"
)
POSIX_CALL_CALLEE_PATTERN = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
PROHIBITED_POSIX_INDIRECT_CALL_PATTERN = re.compile(r"[\)\]]\s*\(")
PROHIBITED_POSIX_UCN_PATTERN = re.compile(
    r"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})"
)
POSIX_STANDALONE_STRING_DECLARATION_PATTERN = re.compile(
    r"\bstatic\s+const\s+(?:char|gchar)\s*\*\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
    r'"(?:\\.|[^"\\])*"\s*;',
    re.DOTALL,
)
PROHIBITED_POSIX_DIRECT_OPEN_FUNCTIONS = (
    "open",
    "open64",
    "openat64",
    "openat2",
    "creat",
    "creat64",
    "fopen",
    "fopen64",
    "freopen",
    "freopen64",
    "__open",
    "__open64",
    "__open_alias",
    "__open64_alias",
    "__open_2",
    "__open64_2",
    "__openat_alias",
    "__openat64_alias",
    "__openat_2",
    "__openat64_2",
    "__openat2_alias",
    "__creat",
    "__creat64",
)
PROHIBITED_POSIX_DIRECT_OPEN_PATTERN = re.compile(
    r"\b(?:"
    + "|".join(re.escape(function) for function in PROHIBITED_POSIX_DIRECT_OPEN_FUNCTIONS)
    + r")\b"
)

TRACKED_INPUTS = (
    MODEL,
    POSIX_PROVIDER,
    *POSIX_LOCK_HEADER_CLOSURE,
    WINDOWS_PROVIDER,
    MODEL_TEST,
    CONSUMER_TEST,
    MESON,
    CI_PR,
    CI_MAIN,
)

EXPECTED_MESON_REGION = """test_fact_artifact_inventory = executable('test-fact-artifact-inventory',
  'test-fact-artifact-inventory.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-inventory-contract', test_fact_artifact_inventory)

test_fact_artifact_inventory_consumers = executable(
  'test-fact-artifact-inventory-consumers',
  'test-fact-artifact-inventory-consumers.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-inventory-consumer-contract',
  test_fact_artifact_inventory_consumers)

test('fact-artifact-inventory-consumer-wiring', python3,
  args : [
    meson.current_source_dir() / 'test-fact-artifact-inventory-consumer-wiring.py',
    meson.project_source_root(),
  ],
)
test('fact-artifact-inventory-consumer-wiring-self', python3,
  args : [
    meson.current_source_dir() / 'test-fact-artifact-inventory-consumer-wiring.py',
    '--self-test',
    meson.project_source_root(),
  ],
  timeout : 120,
)
"""


class ContractError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ContractError(code, message)


def load_inputs(root: Path) -> dict[str, str]:
    return {path: (root / path).read_text(encoding="utf-8") for path in TRACKED_INPUTS}


def evidence_struct(header: str) -> str:
    match = re.search(
        r"typedef struct\s*\{(?P<body>[^{}]*)\}\s*"
        r"WylFactArtifactInventorySlotEvidence\s*;",
        header,
    )
    require(match is not None, "E_INVENTORY_VALUE_AUTHORITY", "slot evidence type is missing")
    return match.group("body")


def validate_value_authority(inputs: dict[str, str]) -> None:
    header = inputs[HEADER]
    body = evidence_struct(header)
    uncommented = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.DOTALL)
    declarations = tuple(
        re.sub(r"\s+", " ", declaration.strip())
        for declaration in re.findall(r"[^;]+;", uncommented)
    )
    required_fields = (
        "gboolean present;",
        "WylFactArtifactInventoryIdentity identity;",
        "guint64 logical_bytes;",
        "gboolean allocation_supported;",
        "guint64 allocated_bytes;",
    )
    require(
        declarations == required_fields
        and re.sub(r"[^;]+;", "", uncommented).strip() == "",
        "E_INVENTORY_VALUE_AUTHORITY",
        "slot evidence must contain only the exact five value-only fields",
    )
    forbidden = re.search(
        r"\b(?:g?char|gpointer|void)\s*\*|\b(?:path|name|handle|fd|token)\b",
        body,
        re.IGNORECASE,
    )
    require(
        forbidden is None,
        "E_INVENTORY_VALUE_AUTHORITY",
        "slot evidence exposes a raw name, path, pointer, handle, descriptor, or token",
    )
    require(
        header.count("wyl_fact_artifact_inventory_snapshot_get_slot_evidence") == 1,
        "E_INVENTORY_VALUE_AUTHORITY",
        "value-only slot accessor must be declared exactly once",
    )


def validate_model_completeness(inputs: dict[str, str]) -> None:
    model = inputs[MODEL]
    finalize = re.search(
        r"wyl_fact_artifact_inventory_snapshot_finalize\s*.*?\n\}",
        model,
        re.DOTALL,
    )
    require(finalize is not None, "E_INVENTORY_ALL_SLOTS", "finalize implementation is missing")
    finalize_text = finalize.group(0)
    require(
        re.search(
            r"slot\s*=\s*0\s*;\s*slot\s*<\s*"
            r"WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT\s*;\s*slot\+\+",
            finalize_text,
        )
        is not None,
        "E_INVENTORY_ALL_SLOTS",
        "finalize does not inventory every fixed and TEMP slot",
    )
    require(
        "!snapshot->slot_set[slot]" in finalize_text
        and "WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY" in finalize_text
        and "snapshot_zero_result (snapshot)" in finalize_text,
        "E_INVENTORY_ALL_SLOTS",
        "missing-slot failure must be POLICY and clear all partial evidence",
    )
    accessor = re.search(
        r"wyl_fact_artifact_inventory_snapshot_get_slot_evidence\s*.*?\n\}",
        model,
        re.DOTALL,
    )
    require(accessor is not None, "E_INVENTORY_PUBLICATION", "slot accessor is missing")
    accessor_text = accessor.group(0)
    require(
        "snapshot_published (snapshot)" in accessor_text
        and "WylFactArtifactInventorySlotEvidence) { 0 }" in accessor_text,
        "E_INVENTORY_PUBLICATION",
        "slot accessor does not hide partial/failure state with initialized output",
    )
    canonical_tokens = (
        "slot < WYL_FACT_ARTIFACT_INVENTORY_TEMP",
        "slot == WYL_FACT_ARTIFACT_INVENTORY_TEMP",
        "!present",
        "!allocation_supported",
    )
    require(
        all(token in model for token in canonical_tokens),
        "E_INVENTORY_CANONICAL_SLOT",
        "fixed, TEMP, absent, and allocation canonical forms are not enforced",
    )


def validate_provider_slots(inputs: dict[str, str], path: str, code: str) -> None:
    provider = inputs[path]
    require(
        re.search(
            r"for\s*\(guint slot\s*=\s*0\s*;[^)]*"
            r"slot\s*<=\s*WYL_FACT_ARTIFACT_INVENTORY_LOCK\s*;",
            provider,
            re.DOTALL,
        )
        is not None,
        code,
        "provider does not assign every fixed slot through LOCK",
    )
    require(
        re.search(
            r"snapshot_set_slot\s*\(snapshot,\s*"
            r"WYL_FACT_ARTIFACT_INVENTORY_TEMP\s*,\s*NULL",
            provider,
            re.DOTALL,
        )
        is not None,
        code,
        "provider does not assign the aggregate TEMP slot",
    )


def normalize_c_line_splices(source: str) -> str:
    return re.sub(r"(?:\\|\?\?/)\r?\n", "", source)


def strip_c_comments(source: str) -> str:
    result: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(source):
        character = source[index]
        if quote is not None:
            result.append(character)
            if character == "\\" and index + 1 < len(source):
                index += 1
                result.append(source[index])
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in ("'", '"'):
            quote = character
            result.append(character)
            index += 1
            continue
        if source.startswith("//", index):
            result.extend("  ")
            index += 2
            while index < len(source) and source[index] != "\n":
                result.append(" ")
                index += 1
            continue
        if source.startswith("/*", index):
            result.extend("  ")
            index += 2
            while index < len(source) and not source.startswith("*/", index):
                result.append("\n" if source[index] == "\n" else " ")
                index += 1
            require(
                index < len(source),
                "E_INVENTORY_REGRESSION_TESTS",
                "unterminated C block comment in model test",
            )
            result.extend("  ")
            index += 2
            continue
        result.append(character)
        index += 1
    require(
        quote is None,
        "E_INVENTORY_REGRESSION_TESTS",
        "unterminated C literal in model test",
    )
    return "".join(result)


def strip_c_literals(source: str) -> str:
    result: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(source):
        character = source[index]
        if quote is None:
            if character in ("'", '"'):
                quote = character
                result.append(" ")
            else:
                result.append(character)
            index += 1
            continue
        if character == "\\" and index + 1 < len(source):
            result.append(" ")
            index += 1
            result.append("\n" if source[index] == "\n" else " ")
        elif character == quote:
            quote = None
            result.append(" ")
        else:
            result.append("\n" if character == "\n" else " ")
        index += 1
    require(
        quote is None,
        "E_INVENTORY_REGRESSION_TESTS",
        "unterminated C literal in regression test",
    )
    return "".join(result)


def c_function_body_bounds(source: str, function: str) -> tuple[int, int] | None:
    match = re.search(
        rf"\b{re.escape(function)}\s*\([^;{{}}]*\)\s*\{{",
        source,
        re.DOTALL,
    )
    if match is None:
        return None
    opening = match.end() - 1
    depth = 1
    quote: str | None = None
    escaped = False
    for index in range(opening + 1, len(source)):
        character = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in ("'", '"'):
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return opening + 1, index
    return None


def c_function_body(source: str, function: str) -> str | None:
    bounds = c_function_body_bounds(source, function)
    return None if bounds is None else source[bounds[0]:bounds[1]]


def split_c_arguments(arguments: str) -> tuple[str, ...] | None:
    result: list[str] = []
    start = 0
    depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = set(pairs.values())
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    for index, character in enumerate(arguments):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in ("'", '"'):
            quote = character
            continue
        if character in pairs:
            stack.append(pairs[character])
            depth += 1
        elif character in closing:
            if not stack or stack.pop() != character:
                return None
            depth -= 1
        elif character == "," and depth == 0:
            result.append(arguments[start:index].strip())
            start = index + 1
    if stack or quote is not None:
        return None
    result.append(arguments[start:].strip())
    return tuple(result)


def c_call_arguments(source: str, function: str) -> tuple[tuple[str, ...], ...] | None:
    calls: list[tuple[str, ...]] = []
    discovery = strip_c_literals(source)
    for match in re.finditer(rf"\b{re.escape(function)}\s*\(", discovery):
        opening = match.end() - 1
        depth = 1
        index = opening + 1
        while index < len(discovery) and depth:
            if discovery[index] == "(":
                depth += 1
            elif discovery[index] == ")":
                depth -= 1
            index += 1
        if depth:
            return None
        arguments = split_c_arguments(source[opening + 1:index - 1])
        if arguments is None:
            return None
        calls.append(arguments)
    return tuple(calls)


def c_named_call_profile(
    source: str,
) -> tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] | None:
    calls: list[tuple[str, tuple[tuple[str, ...], ...]]] = []
    discovery = strip_c_literals(source)
    for match in POSIX_CALL_CALLEE_PATTERN.finditer(discovery):
        opening = match.end() - 1
        depth = 1
        index = opening + 1
        while index < len(discovery) and depth:
            if discovery[index] == "(":
                depth += 1
            elif discovery[index] == ")":
                depth -= 1
            index += 1
        if depth:
            return None
        arguments = split_c_arguments(source[opening + 1:index - 1])
        if arguments is None:
            return None
        calls.append(
            (
                match.group(1),
                tuple(c_tokens(argument) for argument in arguments),
            )
        )
    return tuple(calls)


def c_tokens(source: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|->|\S", source))


def c_call_profile_sha256(calls: tuple[tuple[str, ...], ...]) -> str:
    profile = tuple(
        tuple(c_tokens(argument) for argument in arguments)
        for arguments in calls
    )
    return hashlib.sha256(repr(profile).encode("ascii")).hexdigest()


def c_source_profile_sha256(items: tuple[str, ...]) -> str:
    profile = tuple(c_tokens(item) for item in items)
    return hashlib.sha256(repr(profile).encode("ascii")).hexdigest()


def posix_lock_header_closure_profile(
    inputs: dict[str, str],
) -> tuple[tuple[int, ...], str, tuple[int, ...], str]:
    directive_counts: list[int] = []
    directive_profile: list[tuple[str, tuple[tuple[str, ...], ...]]] = []
    semantic_counts: list[int] = []
    semantic_profile: list[tuple[str, tuple[str, ...]]] = []
    directive_pattern = re.compile(
        r"^\s*(?:#|%:|\?\?=)[^\n]*", re.MULTILINE
    )
    for path in POSIX_LOCK_HEADER_CLOSURE:
        source = strip_c_comments(normalize_c_line_splices(inputs[path]))
        directives = tuple(directive_pattern.findall(source))
        semantic_tokens = c_tokens(
            strip_c_literals(directive_pattern.sub("", source))
        )
        directive_counts.append(len(directives))
        directive_profile.append(
            (path, tuple(c_tokens(directive) for directive in directives))
        )
        semantic_counts.append(len(semantic_tokens))
        semantic_profile.append((path, semantic_tokens))
    return (
        tuple(directive_counts),
        hashlib.sha256(repr(tuple(directive_profile)).encode("utf-8")).hexdigest(),
        tuple(semantic_counts),
        hashlib.sha256(repr(tuple(semantic_profile)).encode("utf-8")).hexdigest(),
    )


def artifact_lock_require(condition: bool) -> None:
    require(
        condition,
        "E_ARTIFACT_LOCK_ACCESS_MODE",
        ARTIFACT_LOCK_DIAGNOSTIC,
    )


def direct_flag_set(expression: str) -> frozenset[str] | None:
    compact = re.sub(r"\s+", "", expression)
    if re.fullmatch(r"O_[A-Z0-9_]+(?:\|O_[A-Z0-9_]+)*", compact) is None:
        return None
    flags = compact.split("|")
    if len(flags) != len(set(flags)):
        return None
    return frozenset(flags)


def body_brace_depth_at(body: str, offset: int) -> int | None:
    depth = 0
    for character in body[:offset]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                return None
    return depth


def validate_artifact_lock_access_mode(inputs: dict[str, str]) -> None:
    (
        header_directive_counts,
        header_directive_hash,
        header_semantic_counts,
        header_semantic_hash,
    ) = posix_lock_header_closure_profile(inputs)
    artifact_lock_require(
        header_directive_counts
        == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_COUNTS
    )
    artifact_lock_require(
        header_directive_hash
        == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256
    )
    artifact_lock_require(
        header_semantic_counts
        == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_COUNTS
    )
    artifact_lock_require(
        header_semantic_hash
        == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256
    )
    translation_unit = normalize_c_line_splices(inputs[POSIX_PROVIDER])
    common_end_anchor = "\n#ifdef G_OS_WIN32\nstruct WylFactArtifactNamespace"
    artifact_lock_require(translation_unit.count(common_end_anchor) == 1)
    posix_anchor = "#else\n#include <errno.h>"
    artifact_lock_require(translation_unit.count(posix_anchor) == 1)
    common_source = translation_unit[:translation_unit.index(common_end_anchor)]
    source = translation_unit[translation_unit.index(posix_anchor):]
    include_source = strip_c_comments(common_source + "\n" + source)
    active_directives = tuple(
        re.findall(r"^\s*(?:#|%:|\?\?=)[^\n]*", include_source, re.MULTILINE)
    )
    artifact_lock_require(
        c_source_profile_sha256(active_directives)
        == EXPECTED_POSIX_DIRECTIVE_PROFILE_SHA256
    )
    include_directives = re.findall(
        r"^\s*(?P<intro>#|%:|\?\?=)\s*include\s+"
        r"(?P<operand>[^\n]+?)\s*$",
        include_source,
        re.MULTILINE,
    )
    artifact_lock_require(
        include_directives
        == [
            ("#", '"fact/graph-artifact-namespace-private.h"'),
            ("#", '"fact/graph-artifact-inventory-posix-private.h"'),
            ("#", '"fact/graph-provisioned-pair-internal.h"'),
            ("#", '"wyl-id-private.h"'),
            ("#", "<sodium.h>"),
            ("#", "<string.h>"),
            ("#", "<errno.h>"),
            ("#", "<fcntl.h>"),
            ("#", "<sys/file.h>"),
            ("#", "<sys/stat.h>"),
            ("#", "<unistd.h>"),
            ("#", "<stdio.h>"),
            ("#", "<dirent.h>"),
            ("#", "<sys/syscall.h>"),
        ]
    )
    commentless_source = strip_c_comments(source)
    name_table_discovery = strip_c_literals(commentless_source)
    name_tables = tuple(
        re.finditer(
            r"\bstatic\s+const\s+gchar\s*\*\s*names\s*\[\s*\]\s*=\s*"
            r"\{(?P<body>.*?)\}\s*;",
            name_table_discovery,
            re.DOTALL,
        )
    )
    artifact_lock_require(len(name_tables) == 1)
    name_body = commentless_source[
        name_tables[0].start("body"):name_tables[0].end("body")
    ]
    c_string = re.compile(r'"(?:\\.|[^"\\])*"')
    artifact_lock_require(
        tuple(literal[1:-1] for literal in c_string.findall(name_body))
        == (
            "facts.duckdb",
            "facts.duckdb.wal",
            "facts.duckdb.wal.checkpoint",
            "facts.duckdb.wal.recovery",
            "facts.duckdb.lock",
        )
    )
    artifact_lock_require(
        c_tokens(c_string.sub("STRING", name_body))
        == (
            "STRING", ",", "STRING", ",", "STRING", ",", "STRING",
            ",", "STRING", ",", "NULL",
        )
    )
    openat_profile = c_call_arguments(commentless_source, "openat")
    artifact_lock_require(openat_profile is not None and len(openat_profile) == 23)
    assert openat_profile is not None
    artifact_lock_require(
        c_call_profile_sha256(openat_profile)
        == EXPECTED_POSIX_OPENAT_PROFILE_SHA256
    )
    syscall_profile = c_call_arguments(commentless_source, "syscall")
    artifact_lock_require(syscall_profile is not None and len(syscall_profile) == 2)
    assert syscall_profile is not None
    artifact_lock_require(
        c_call_profile_sha256(syscall_profile)
        == EXPECTED_POSIX_SYSCALL_PROFILE_SHA256
    )
    artifact_lock_require(
        len(re.findall(r'"facts\.duckdb\.lock"', commentless_source)) == 1
    )
    source = strip_c_literals(commentless_source)
    if (
        hashlib.sha256(commentless_source.encode("utf-8")).hexdigest()
        != BASELINE_POSIX_COMMENTLESS_SHA256
    ):
        semantic_source = POSIX_STANDALONE_STRING_DECLARATION_PATTERN.sub(
            "", commentless_source
        )
        semantic_tokens = c_tokens(strip_c_literals(semantic_source))
        artifact_lock_require(len(semantic_tokens) == 30860)
        artifact_lock_require(
            hashlib.sha256(repr(semantic_tokens).encode("utf-8")).hexdigest()
            == EXPECTED_POSIX_SEMANTIC_TOKEN_PROFILE_SHA256
        )
        call_profile = c_named_call_profile(commentless_source)
        artifact_lock_require(call_profile is not None and len(call_profile) == 2085)
        assert call_profile is not None
        artifact_lock_require(
            hashlib.sha256(repr(call_profile).encode("utf-8")).hexdigest()
            == EXPECTED_POSIX_CALL_PROFILE_SHA256
        )
    artifact_lock_require(source.isascii())
    artifact_lock_require("$" not in source)
    artifact_lock_require(PROHIBITED_POSIX_UCN_PATTERN.search(source) is None)
    artifact_lock_require(PROHIBITED_POSIX_INDIRECT_CALL_PATTERN.search(source) is None)
    artifact_lock_require(PROHIBITED_POSIX_DIRECT_OPEN_PATTERN.search(source) is None)
    artifact_lock_require(len(re.findall(r"\bnames\b", source)) == 2)
    name_for_body = c_function_body(source, "name_for")
    artifact_lock_require(name_for_body is not None)
    assert name_for_body is not None
    artifact_lock_require(
        c_tokens(name_for_body)
        == (
            "return", "n", "<", "=", "WYL_FACT_ARTIFACT_LOCK", "?",
            "names", "[", "n", "]", ":", "NULL", ";",
        )
    )
    artifact_lock_require(
        len(re.findall(r"\bWYL_FACT_ARTIFACT_LOCK\b", source)) == 9
    )
    protected_directive_token = re.compile(
        r"\b(?:O_RDWR|O_RDONLY|WYL_FACT_ARTIFACT_LOCK|openat|"
        r"open_checked_lock|acquire_lease)\b"
    )
    directives = re.findall(r"^\s*(?:#|%:|\?\?=)[^\n]*", source, re.MULTILINE)
    artifact_lock_require(
        all(protected_directive_token.search(directive) is None for directive in directives)
    )
    artifact_lock_require(
        all(
            re.search(r"##|%:%:|\?\?=\s*\?\?=", directive) is None
            for directive in directives
        )
    )

    definitions = tuple(
        re.finditer(r"\bopen_checked_lock\s*\((?P<params>[^;{}]*)\)\s*\{", source)
    )
    artifact_lock_require(len(definitions) == 1)
    definition = definitions[0]
    artifact_lock_require(
        c_tokens(definition.group("params"))
        == (
            "WylFactArtifactNamespace",
            "*",
            "n",
            ",",
            "gint",
            "*",
            "out_fd",
        )
    )
    lock_body = c_function_body(source, "open_checked_lock")
    artifact_lock_require(lock_body is not None)
    assert lock_body is not None
    artifact_lock_require(re.search(r"^\s*#", lock_body, re.MULTILINE) is None)

    calls = c_call_arguments(lock_body, "openat")
    artifact_lock_require(calls is not None and len(calls) == 3)
    assert calls is not None
    all_openat_calls = c_call_arguments(source, "openat")
    artifact_lock_require(all_openat_calls is not None)
    assert all_openat_calls is not None
    artifact_lock_require(len(all_openat_calls) == 23)
    artifact_lock_require(
        len(re.findall(r"\bopenat\b", source)) == len(all_openat_calls)
    )
    all_lock_calls = tuple(
        arguments
        for arguments in all_openat_calls
        if len(arguments) >= 2
        and "WYL_FACT_ARTIFACT_LOCK" in c_tokens(arguments[1])
    )
    artifact_lock_require(all_lock_calls == calls)
    create_flags = frozenset(
        {"O_RDWR", "O_NONBLOCK", "O_CLOEXEC", "O_NOFOLLOW", "O_CREAT", "O_EXCL"}
    )
    existing_flags = frozenset(
        {"O_RDWR", "O_NONBLOCK", "O_CLOEXEC", "O_NOFOLLOW"}
    )
    profiles: list[str] = []
    for arguments in calls:
        artifact_lock_require(len(arguments) in (3, 4))
        artifact_lock_require(c_tokens(arguments[0]) == ("n", "->", "fd"))
        artifact_lock_require(
            c_tokens(arguments[1])
            == ("name_for", "(", "WYL_FACT_ARTIFACT_LOCK", ")")
        )
        flags = direct_flag_set(arguments[2])
        if len(arguments) == 4:
            artifact_lock_require(flags == create_flags)
            artifact_lock_require(c_tokens(arguments[3]) == ("0600",))
            profiles.append("create")
        else:
            artifact_lock_require(flags == existing_flags)
            profiles.append("existing")
    artifact_lock_require(sorted(profiles) == ["create", "existing", "existing"])

    pin_body = c_function_body(source, "pin_lock_domain")
    artifact_lock_require(pin_body is not None)
    assert pin_body is not None
    pin_calls = c_call_arguments(pin_body, "open_checked_lock")
    artifact_lock_require(pin_calls == (("n", "&fd"),))
    artifact_lock_require(
        len(
            re.findall(
                r"\bwyrelog_error_t\s+r\s*=\s*"
                r"open_checked_lock\s*\(\s*n\s*,\s*&fd\s*\)\s*;",
                pin_body,
            )
        )
        == 1
    )

    acquire_body = c_function_body(source, "acquire_lease")
    artifact_lock_require(acquire_body is not None)
    assert acquire_body is not None
    artifact_lock_require(re.search(r"^\s*#", acquire_body, re.MULTILINE) is None)
    acquire_calls = c_call_arguments(acquire_body, "open_checked_lock")
    artifact_lock_require(acquire_calls == (("n", "&fd"),))
    direct_call = re.search(
        r"\bwyrelog_error_t\s+r\s*=\s*"
        r"open_checked_lock\s*\(\s*n\s*,\s*&fd\s*\)\s*;",
        acquire_body,
    )
    artifact_lock_require(direct_call is not None)
    assert direct_call is not None
    artifact_lock_require(body_brace_depth_at(acquire_body, direct_call.start()) == 0)
    first_mode_use = re.search(r"\bexclusive\b", acquire_body)
    artifact_lock_require(
        first_mode_use is not None and direct_call.end() < first_mode_use.start()
    )

    wrappers = (
        (
            "wyl_fact_artifact_namespace_acquire_reader_guard",
            "FALSE",
        ),
        (
            "wyl_fact_artifact_namespace_acquire_mutation_lease",
            "TRUE",
        ),
    )
    for function, mode in wrappers:
        body = c_function_body(source, function)
        artifact_lock_require(body is not None)
        assert body is not None
        artifact_lock_require(
            c_tokens(body)
            == (
                "return",
                "acquire_lease",
                "(",
                "n",
                ",",
                mode,
                ",",
                "out_lease",
                ")",
                ";",
            )
        )


def straight_line_c_body(body: str) -> bool:
    return (
        re.search(
            r"\b(?:if|else|for|while|do|switch|goto|return|break|continue)\b",
            body,
        )
        is None
        and re.search(r"^\s*#", body, re.MULTILINE) is None
        and not any(token in body for token in ("{", "}", "?"))
    )


def no_prohibited_c_termination(body: str) -> bool:
    return (
        re.search(
            r"\b(?:exit|_exit|_Exit|quick_exit|g_test_skip|g_test_incomplete)\b",
            body,
        )
        is None
    )


def validate_runtime_tests(inputs: dict[str, str]) -> None:
    model_test = inputs[MODEL_TEST]
    spliced_model_test = normalize_c_line_splices(model_test)
    active_model_test = strip_c_comments(spliced_model_test)
    active_translation_unit = strip_c_literals(active_model_test)
    directives = tuple(
        re.sub(r"\s+", " ", line.strip())
        for line in active_model_test.splitlines()
        if re.match(r"\s*(?:#|%:|\?\?=)", line)
    )
    require(
        directives
        == (
            "#include <glib.h>",
            "#include <string.h>",
            '#include "fact/graph-artifact-inventory-private.h"',
        )
        and no_prohibited_c_termination(active_translation_unit),
        "E_INVENTORY_REGRESSION_TESTS",
        "model test preprocessing or termination surface is not approved",
    )
    require(
        re.search(
            r"static\s+void\s+test_omitted_slot_matrix_fails_closed\s*\(",
            model_test,
        )
        is not None
        and re.search(
            r"omitted\s*=\s*0\s*;\s*omitted\s*<\s*"
            r"WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT",
            model_test,
        )
        is not None
        and "WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY" in model_test,
        "E_INVENTORY_OMITTED_SLOT_TEST",
        "the runtime test does not omit each slot and require POLICY",
    )
    consumer_test = inputs[CONSUMER_TEST]
    require(
        "backup_like_has_complete_closure" in consumer_test
        and "WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN" in consumer_test
        and "QUOTA_EVIDENCE_LOWER_BOUND_BLOCKED" in consumer_test,
        "E_INVENTORY_CONSUMER_TEST",
        "backup closure and quota lower-bound/block contracts are incomplete",
    )
    regression_cases = {
        "test_anomaly_limit_overflow_clears_evidence": (
            "/fact/artifact-inventory/anomaly-limit-overflow",
            (
                "wyl_fact_artifact_inventory_snapshot_new (1)",
                "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_OK);",
                "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_POLICY);",
                "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW);",
                "assert_no_published_evidence (snapshot);",
            ),
        ),
        "test_contradictory_extended_identity_fails_closed": (
            "/fact/artifact-inventory/contradictory-extended-identity",
            (
                "contradictory.object = 99;",
                "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot, WYL_FACT_ARTIFACT_INVENTORY_MAIN, &contradictory, TRUE, 1, TRUE, 1), ==, WYRELOG_E_POLICY);",
                "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);",
                "assert_no_published_evidence (snapshot);",
            ),
        ),
        "test_extended_observation_mismatch_clears_evidence": (
            "/fact/artifact-inventory/extended-observation-mismatch",
            (
                "point.directory_identity = extended_identity (21, 1);",
                "point.guard_identity = extended_identity (22, 1);",
                "changed.directory_identity.object_bytes[15] = 2;",
                "populate_slots_except (snapshot, -1, &point);",
                "wyl_fact_artifact_inventory_snapshot_end (snapshot, &changed);",
                "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot), ==, WYRELOG_E_BUSY);",
                "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSTABLE);",
                "assert_no_published_evidence (snapshot);",
            ),
        ),
    }
    main_body = c_function_body(active_model_test, "main")
    main_without_terminal_return = (
        ""
        if main_body is None
        else strip_c_literals(main_body).replace("return g_test_run ();", "", 1)
    )
    require(
        main_body is not None
        and main_body.count("return g_test_run ();") == 1
        and straight_line_c_body(main_without_terminal_return)
        and no_prohibited_c_termination(main_without_terminal_return),
        "E_INVENTORY_REGRESSION_TESTS",
        "model test registration entry point is missing or conditional",
    )
    for function, (test_path, statements) in regression_cases.items():
        body = c_function_body(active_model_test, function)
        executable_body = "" if body is None else strip_c_literals(body)
        normalized = re.sub(r"\s+", " ", executable_body).strip()
        registration = re.compile(
            rf"g_test_add_func\s*\(\s*{re.escape(chr(34) + test_path + chr(34))}\s*,\s*"
            rf"{re.escape(function)}\s*\)\s*;"
        )
        require(
            body is not None
            and straight_line_c_body(executable_body)
            and no_prohibited_c_termination(executable_body)
            and all(statement in normalized for statement in statements)
            and main_body is not None
            and len(registration.findall(main_body)) == 1,
            "E_INVENTORY_REGRESSION_TESTS",
            f"model regression case {function} is missing or incomplete",
        )
    anomaly_body = c_function_body(
        active_model_test, "test_anomaly_limit_overflow_clears_evidence"
    )
    require(
        anomaly_body is not None
        and strip_c_literals(anomaly_body).count(
            "wyl_fact_artifact_inventory_snapshot_add_anomaly"
        )
        == 2,
        "E_INVENTORY_REGRESSION_TESTS",
        "anomaly limit test must cross the configured bound",
    )


def meson_region_bounds(meson: str) -> tuple[int, int]:
    start_anchor = "test_fact_artifact_inventory = executable"
    end_anchor = "test_fact_artifact_namespace = executable"
    require(
        meson.count(start_anchor) == 1 and meson.count(end_anchor) == 1,
        "E_INVENTORY_MESON",
        "inventory test region anchors must be unique",
    )
    start = meson.index(start_anchor)
    end = meson.index(end_anchor)
    require(end > start, "E_INVENTORY_MESON", "inventory test region is missing")
    return start, end


def meson_region(meson: str) -> str:
    start, end = meson_region_bounds(meson)
    return meson[start:end]


def strip_meson_comments_and_strings(source: str) -> str:
    source = source.replace("\r\n", "\n").replace("\r", "\n")
    result: list[str] = []
    index = 0
    state = "normal"
    while index < len(source):
        character = source[index]
        if state == "triple-single":
            if source.startswith("'''", index):
                result.extend((" ", " ", " "))
                index += 3
                state = "normal"
                continue
            result.append("\n" if character == "\n" else " ")
            index += 1
            continue
        if state in ("single", "double"):
            if character == "\\" and index + 1 < len(source):
                require(
                    source[index + 1] != "\n",
                    "E_INVENTORY_MESON",
                    "ordinary Meson string uses a physical-line continuation",
                )
                result.extend(
                    (" ", "\n" if source[index + 1] == "\n" else " ")
                )
                index += 2
                continue
            require(
                character != "\n",
                "E_INVENTORY_MESON",
                "ordinary Meson string crosses a physical line",
            )
            if (state == "single" and character == "'") or (
                state == "double" and character == '"'
            ):
                state = "normal"
            result.append("\n" if character == "\n" else " ")
            index += 1
            continue
        if source.startswith("'''", index):
            result.extend((" ", " ", " "))
            index += 3
            state = "triple-single"
            continue
        if character in ("'", '"'):
            state = "single" if character == "'" else "double"
            result.append(" ")
            index += 1
            continue
        if character == "\\":
            continuation = re.match(r"\\[ \t]*(?:#[^\n]*)?\n", source[index:])
            require(
                continuation is not None,
                "E_INVENTORY_MESON",
                "unsupported or malformed Meson line continuation",
            )
            index += continuation.end()
            continue
        if character == "#":
            while index < len(source) and source[index] != "\n":
                result.append(" ")
                index += 1
            continue
        result.append(character)
        index += 1
    require(
        state == "normal",
        "E_INVENTORY_MESON",
        "unterminated Meson string precedes inventory registration",
    )
    return "".join(result)


def validate_meson_region_reachability(meson: str) -> None:
    start, _ = meson_region_bounds(meson)
    before = strip_meson_comments_and_strings(meson[:start])
    require(
        re.search(r"\bsubdir_done\s*\(", before) is None,
        "E_INVENTORY_MESON",
        "subdir_done can terminate tests/meson.build before inventory registration",
    )
    stack: list[str] = []
    for line in before.splitlines():
        statement = line.strip()
        if not statement:
            continue
        if re.match(r"^if\b", statement):
            stack.append("if")
        elif re.match(r"^foreach\b", statement):
            stack.append("foreach")
        elif re.match(r"^(?:elif|else)\b", statement):
            require(
                bool(stack) and stack[-1] == "if",
                "E_INVENTORY_MESON",
                "malformed conditional precedes inventory registration",
            )
        elif re.match(r"^endif\b", statement):
            require(
                bool(stack) and stack.pop() == "if",
                "E_INVENTORY_MESON",
                "unbalanced endif precedes inventory registration",
            )
        elif re.match(r"^endforeach\b", statement):
            require(
                bool(stack) and stack.pop() == "foreach",
                "E_INVENTORY_MESON",
                "unbalanced endforeach precedes inventory registration",
            )
    require(
        not stack,
        "E_INVENTORY_MESON",
        "inventory registration must begin at top level",
    )


def canonical_meson_region(region: str) -> str:
    normalized = region.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in normalized.split("\n")]
    return "\n".join(lines).strip("\n") + "\n"


def validate_meson(inputs: dict[str, str]) -> None:
    meson = inputs[MESON]
    validate_meson_region_reachability(meson)
    region = meson_region(meson)
    require(
        canonical_meson_region(region) == EXPECTED_MESON_REGION,
        "E_INVENTORY_MESON",
        "model, consumer, and wiring Meson profile drifted",
    )
    require(
        "fact-artifact-namespace-inventory" in meson
        and "'/fact-artifact-namespace/inventory-provider'" in meson
        and "['inventory', '/fact/artifact-namespace/windows/inventory']" in meson,
        "E_INVENTORY_MESON",
        "POSIX or native-Windows focused provider registration is missing",
    )


def section(workflow: str, start: str, end: str | None) -> str:
    begin = workflow.find(start)
    finish = len(workflow) if end is None else workflow.find(end, begin + len(start))
    require(begin >= 0 and finish > begin, "E_INVENTORY_CI_SHAPE", f"workflow section {start!r} is missing")
    return workflow[begin:finish]


FOCUSED_TESTS = (
    "fact-artifact-inventory-contract",
    "fact-artifact-inventory-consumer-contract",
    "fact-artifact-inventory-consumer-wiring",
    "fact-artifact-inventory-consumer-wiring-self",
)
POSIX_TESTS = FOCUSED_TESTS[:2] + (
    "fact-artifact-namespace-inventory",
) + FOCUSED_TESTS[2:] + (
    "fact-artifact-transition-driver",
    "fact-artifact-transition-driver-wiring",
    "fact-artifact-transition-driver-wiring-self",
    "fact-artifact-transition-posix",
)
SECURE_COMPILE_TARGETS = (
    "test-fact-artifact-inventory",
    "test-fact-artifact-inventory-consumers",
    "test-fact-artifact-namespace",
    "test-fact-artifact-transition-driver",
    "test-fact-artifact-transition-posix",
)
SECURE_HISTORICAL_COMPILE_TARGETS = (
    "test-secure-duckdb-bridge",
    "test-secure-duckdb-filesystem",
    "test-secure-duckdb-recording-filesystem",
)
SECURE_HISTORICAL_TESTS = (
    "secure-duckdb-bridge",
    "secure-duckdb-filesystem",
    "secure-duckdb-recording-filesystem",
)
SANITIZER_COMPILE_COMMAND = (
    "meson",
    "compile",
    "-C",
    "build-policy-write-sanitizer",
    *SECURE_COMPILE_TARGETS,
    "test-service-auth-coordination",
    "test-daemon-http-decide",
    "test-daemon-http-decide-audit",
    "test-daemon-http-decide-service",
)
SANITIZER_TEST_COMMAND = (
    "meson",
    "test",
    "-C",
    "build-policy-write-sanitizer",
    "--no-rebuild",
    *POSIX_TESTS,
    "service-auth-coordination",
    "daemon-http-decide",
    "daemon-http-decide-audit",
    "daemon-http-decide-service",
    "--print-errorlogs",
)
WINDOWS_SECURE_TEST_COMMAND = (
    "meson",
    "test",
    "-C",
    "builddir",
    "secure-duckdb-bridge",
    "secure-duckdb-recording-filesystem",
    "secure-duckdb-temp-child-windows",
    *FOCUSED_TESTS,
    "fact-artifact-transition-driver",
    "fact-artifact-transition-driver-wiring",
    "fact-artifact-transition-driver-wiring-self",
    "fact-artifact-transition-windows",
    "fact-artifact-namespace-windows",
    "fact-artifact-namespace-windows-inventory",
    "fact-artifact-namespace-windows-sidecar-replacement-isolated",
    "fact-artifact-namespace-windows-temp-binding-replacement-isolated",
    "fact-artifact-namespace-windows-lock-entry-replacement-isolated",
    "fact-artifact-namespace-windows-temp-token-real-crash-recovery",
    "fact-artifact-namespace-windows-cross-process",
    "fact-artifact-namespace-windows-temp-root-spill-child-capabilities",
    "fact-artifact-namespace-windows-temp-root-wrapper-ownership",
    "fact-provisioning-construct",
    "duckdb-after-walstart-no-wal",
    "duckdb-after-walstart-rendezvous",
    "duckdb-valid-commit-failure",
    "duckdb-valid-rollback-failure",
    "duckdb-fixed-wal-successful-checkpoint",
    "duckdb-fixed-wal-pre-move-abort-reopen",
    "duckdb-fixed-wal-interrupted-recovery",
    "fact-artifact-main-transition",
    "--print-errorlogs",
)
SECURE_POSIX_ACTIVE_COMMANDS = (
    "set -euo pipefail",
    'if [ "$RUNNER_OS" = Linux ]; then',
    "patch --version",
    "else",
    "gpatch --version",
    "fi | grep -F 'GNU patch'",
    'if [ "$RUNNER_OS" = Linux ]; then',
    "CC=cc CXX=c++ meson setup build-secure-duckdb -Denable_fact_store=enabled -Dduckdb_source=subproject -Denable_secure_duckdb_bridge=enabled",
    "else",
    "meson setup build-secure-duckdb -Denable_fact_store=enabled -Dduckdb_source=subproject -Denable_secure_duckdb_bridge=enabled",
    "fi",
    'if [ "$RUNNER_OS" = Linux ]; then',
    "time_args=(-v)",
    "else",
    "time_args=(-l)",
    "fi",
    'if [ "$RUNNER_OS" = macOS ]; then',
    "meson compile -C build-secure-duckdb -j 1 test-fact-darwin-provisioned-pair",
    "meson test -C build-secure-duckdb --no-rebuild fact-darwin-provisioned-pair --print-errorlogs",
    "fi",
    '/usr/bin/time "${time_args[@]}" meson compile -C build-secure-duckdb -j 1 test-fact-artifact-inventory test-fact-artifact-inventory-consumers test-fact-artifact-namespace test-fact-artifact-transition-driver test-fact-artifact-transition-posix test-secure-duckdb-bridge test-secure-duckdb-filesystem test-secure-duckdb-recording-filesystem',
    "meson test -C build-secure-duckdb --no-rebuild fact-artifact-inventory-contract fact-artifact-inventory-consumer-contract fact-artifact-namespace-inventory fact-artifact-inventory-consumer-wiring fact-artifact-inventory-consumer-wiring-self fact-artifact-transition-driver fact-artifact-transition-driver-wiring fact-artifact-transition-driver-wiring-self fact-artifact-transition-posix secure-duckdb-bridge secure-duckdb-filesystem secure-duckdb-recording-filesystem --print-errorlogs",
    "if meson setup build-secure-duckdb-prebuilt -Denable_fact_store=enabled -Dduckdb_source=prebuilt -Denable_secure_duckdb_bridge=enabled; then",
    "echo 'secure DuckDB bridge unexpectedly accepted prebuilt DuckDB'",
    "exit 1",
    "fi",
)
WINDOWS_ACTIVE_COMMANDS = (
    "$command = @'",
    "@echo off",
    'call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"',
    "set PKG_CONFIG=%VCPKG_INSTALLED_DIR%\\tools\\pkgconf\\pkgconf.exe",
    'if "${{ matrix.duckdb_source }}"=="prebuilt" set PATH=%GITHUB_WORKSPACE%\\subprojects\\duckdb-prebuilt-windows-amd64;%PATH%',
    'if "${{ matrix.duckdb_source }}"=="subproject" set PATH=%GITHUB_WORKSPACE%\\builddir\\subprojects\\duckdb-amalgamated-src;%PATH%',
    "set PATH=%VCPKG_INSTALLED_DIR%\\tools\\pkgconf;%VCPKG_INSTALLED_DIR%\\bin;%PATH%",
    "rem GLib locates gspawn-win64-helper beside the loaded glib DLL",
    "rem (vcpkg bin), but vcpkg installs it under tools\\glib. Stage it",
    "rem beside the DLL so g_subprocess-based tests can launch children.",
    'copy /Y "%VCPKG_INSTALLED_DIR%\\tools\\glib\\gspawn-win64-helper*.exe" "%VCPKG_INSTALLED_DIR%\\bin\\" >NUL',
    "meson compile -C builddir wyctl wyrelogd",
    "if not exist builddir\\wyrelog\\wyctl.exe exit /b 1",
    "builddir\\wyrelog\\wyctl.exe --help >NUL",
    'builddir\\wyrelog\\wyrelogd.exe --help | findstr /C:"--listen-port"',
    'if "${{ matrix.secure_bridge }}"=="enabled" (',
    "meson compile -C builddir test-windows-appverifier-probe test-windows-appverifier-probe-dll test-secure-duckdb-temp-child-windows test-fact-artifact-transition-driver test-fact-artifact-transition-windows",
    "meson test -C builddir secure-duckdb-bridge secure-duckdb-recording-filesystem secure-duckdb-temp-child-windows fact-artifact-inventory-contract fact-artifact-inventory-consumer-contract fact-artifact-inventory-consumer-wiring fact-artifact-inventory-consumer-wiring-self fact-artifact-transition-driver fact-artifact-transition-driver-wiring fact-artifact-transition-driver-wiring-self fact-artifact-transition-windows fact-artifact-namespace-windows fact-artifact-namespace-windows-inventory fact-artifact-namespace-windows-sidecar-replacement-isolated fact-artifact-namespace-windows-temp-binding-replacement-isolated fact-artifact-namespace-windows-lock-entry-replacement-isolated fact-artifact-namespace-windows-temp-token-real-crash-recovery fact-artifact-namespace-windows-cross-process fact-artifact-namespace-windows-temp-root-spill-child-capabilities fact-artifact-namespace-windows-temp-root-wrapper-ownership fact-provisioning-construct duckdb-after-walstart-no-wal duckdb-after-walstart-rendezvous duckdb-valid-commit-failure duckdb-valid-rollback-failure duckdb-fixed-wal-successful-checkpoint duckdb-fixed-wal-pre-move-abort-reopen duckdb-fixed-wal-interrupted-recovery fact-artifact-main-transition --print-errorlogs",
    'meson test -C builddir secure-duckdb-recording-filesystem --no-rebuild --print-errorlogs --test-args="-p /secure-duckdb-bridge/recording-filesystem/live-wal-read-only-recovery"',
    ") else (",
    "meson test -C builddir --print-errorlogs --suite wyrelog",
    ")",
    "'@",
    '& "$env:GITHUB_WORKSPACE\\tools\\run-windows-with-symbolic-link-privilege.ps1" -Command $command',
    "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
)


def named_step(job: str, name: str) -> str:
    marker = f"      - name: {name}"
    require(
        job.count(marker) == 1,
        "E_INVENTORY_CI_SHAPE",
        f"workflow step {name!r} must occur exactly once",
    )
    begin = job.find(marker)
    finish = job.find("\n      - name:", begin + len(marker))
    if finish < 0:
        finish = len(job)
    return job[begin:finish]


def run_body(step: str) -> str:
    marker = "        run: |\n"
    require(
        step.count(marker) == 1,
        "E_INVENTORY_CI_SHAPE",
        "inventory workflow step must use one literal run block",
    )
    return step.split(marker, 1)[1]


def validate_step_profile(
    step: str, name: str, code: str, shell: str | None = None
) -> None:
    run_marker = "        run: |\n"
    require(
        step.count(run_marker) == 1,
        code,
        f"protected workflow step {name!r} must use one literal run block",
    )
    preamble = step.split(run_marker, 1)[0] + run_marker
    expected = f"      - name: {name}\n"
    if shell is not None:
        expected += f"        shell: {shell}\n"
    expected += run_marker
    require(
        preamble == expected,
        code,
        f"protected workflow step {name!r} metadata drifted",
    )


def plain_mapping_keys_at_indent(
    source: str, indent: int, code: str
) -> tuple[str, ...]:
    prefix = " " * indent
    keys: list[str] = []
    for line in source.splitlines():
        if not line.startswith(prefix):
            continue
        remainder = line[indent:]
        if not remainder or remainder.startswith((" ", "#")):
            continue
        match = re.fullmatch(
            r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<value>.*)", remainder
        )
        require(
            match is not None,
            code,
            "protected workflow mapping uses unsupported key syntax",
        )
        value = match.group("value").strip()
        require(
            not value.startswith(("!", "&", "*", "{", "["))
            and re.search(r"(?:^|\s)(?:&|\*)[A-Za-z_][A-Za-z0-9_-]*", value)
            is None,
            code,
            "protected workflow mapping uses a tag, anchor, alias, or flow value",
        )
        keys.append(match.group("key"))
    return tuple(keys)


def validate_workflow_mapping_profile(workflow: str) -> None:
    require(
        plain_mapping_keys_at_indent(workflow, 0, "E_INVENTORY_CI_SHAPE")
        == ("name", "on", "permissions", "concurrency", "env", "jobs"),
        "E_INVENTORY_CI_SHAPE",
        "workflow-level key profile drifted",
    )


def validate_job_profile(job: str, code: str, expected: tuple[str, ...]) -> None:
    require(
        plain_mapping_keys_at_indent(job, 4, code) == expected,
        code,
        "protected workflow job key profile drifted",
    )


def active_logical_commands(step: str) -> list[str]:
    commands: list[str] = []
    current = ""
    for line in run_body(step).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
        else:
            commands.append(current)
            current = ""
    if current:
        commands.append(current)
    return commands


def posix_command(step: str, anchor: str) -> tuple[str, ...]:
    matches = [
        command for command in active_logical_commands(step) if anchor in command
    ]
    require(
        len(matches) == 1,
        "E_INVENTORY_CI_SHAPE",
        f"expected exactly one active command containing {anchor!r}",
    )
    try:
        return tuple(shlex.split(matches[0], comments=True, posix=True))
    except ValueError as error:
        raise ContractError("E_INVENTORY_CI_SHAPE", str(error)) from error


def windows_command(step: str, prefix: str, anchor: str) -> tuple[str, ...]:
    matches = [
        command
        for command in active_logical_commands(step)
        if command.startswith(prefix) and anchor in command
    ]
    require(
        len(matches) == 1,
        "E_INVENTORY_CI_SHAPE",
        f"expected exactly one active Windows command containing {anchor!r}",
    )
    return tuple(matches[0].split())


def inventory_commands(workflow: str) -> tuple[tuple[str, ...], ...]:
    posix = section(workflow, "  build-posix:", "  duckdb-linux-link-closure:")
    default_step = named_step(posix, "Verify artifact inventory consumer contract")
    secure_step = named_step(posix, "Build secure DuckDB backend from pinned source")
    sanitizer = section(
        workflow,
        "  policy-write-focused-sanitizer:",
        "  daemon-http-shared-fact-audit-disabled:",
    )
    sanitizer_compile_step = named_step(
        sanitizer, "Compile focused policy WRITE tests"
    )
    sanitizer_test_step = named_step(sanitizer, "Test focused policy WRITE paths")
    windows = section(workflow, "  build-windows:", None)
    windows_step = named_step(windows, "Build and test (clang-cl)")
    return (
        posix_command(default_step, "meson test -C builddir --no-rebuild"),
        posix_command(
            secure_step,
            '/usr/bin/time "${time_args[@]}" meson compile -C build-secure-duckdb -j 1',
        ),
        posix_command(
            secure_step,
            "meson test -C build-secure-duckdb --no-rebuild fact-artifact-inventory-contract",
        ),
        posix_command(
            sanitizer_compile_step,
            "meson compile -C build-policy-write-sanitizer",
        ),
        posix_command(
            sanitizer_test_step,
            "meson test -C build-policy-write-sanitizer --no-rebuild",
        ),
        windows_command(
            windows_step,
            "meson test -C builddir ",
            "secure-duckdb-temp-child-windows",
        ),
    )


def active_inventory_commands(workflow: str) -> tuple[str, ...]:
    posix = section(workflow, "  build-posix:", "  duckdb-linux-link-closure:")
    sanitizer = section(
        workflow,
        "  policy-write-focused-sanitizer:",
        "  daemon-http-shared-fact-audit-disabled:",
    )
    windows = section(workflow, "  build-windows:", None)
    secure_step = named_step(
        posix, "Build secure DuckDB backend from pinned source"
    )
    secure_active = active_logical_commands(secure_step)
    steps = (
        named_step(posix, "Verify artifact inventory consumer contract"),
        secure_step,
        named_step(sanitizer, "Compile focused policy WRITE tests"),
        named_step(sanitizer, "Test focused policy WRITE paths"),
        named_step(windows, "Build and test (clang-cl)"),
    )
    return tuple(secure_active[:6]) + tuple(
        command
        for step in steps
        for command in active_logical_commands(step)
        if "fact-artifact-inventory" in command
        or "fact-artifact-namespace-inventory" in command
        or "fact-artifact-namespace-windows-inventory" in command
    )


def validate_workflow(path: str, workflow: str) -> None:
    validate_workflow_mapping_profile(workflow)
    posix = section(workflow, "  build-posix:", "  duckdb-linux-link-closure:")
    sanitizer = section(
        workflow,
        "  policy-write-focused-sanitizer:",
        "  daemon-http-shared-fact-audit-disabled:",
    )
    windows = section(workflow, "  build-windows:", None)
    validate_job_profile(
        posix,
        "E_INVENTORY_CI_POSIX",
        ("name", "runs-on", "timeout-minutes", "env", "strategy", "steps"),
    )
    validate_job_profile(
        sanitizer,
        "E_INVENTORY_CI_SANITIZER",
        ("name", "runs-on", "timeout-minutes", "env", "steps"),
    )
    validate_job_profile(
        windows,
        "E_INVENTORY_CI_WINDOWS",
        ("name", "runs-on", "timeout-minutes", "strategy", "env", "steps"),
    )

    default_step = named_step(posix, "Verify artifact inventory consumer contract")
    secure_step = named_step(posix, "Build secure DuckDB backend from pinned source")
    sanitizer_compile_step = named_step(
        sanitizer, "Compile focused policy WRITE tests"
    )
    sanitizer_test_step = named_step(sanitizer, "Test focused policy WRITE paths")
    windows_step = named_step(windows, "Build and test (clang-cl)")
    validate_step_profile(
        default_step,
        "Verify artifact inventory consumer contract",
        "E_INVENTORY_CI_POSIX",
    )
    validate_step_profile(
        secure_step,
        "Build secure DuckDB backend from pinned source",
        "E_INVENTORY_CI_POSIX",
    )
    validate_step_profile(
        sanitizer_compile_step,
        "Compile focused policy WRITE tests",
        "E_INVENTORY_CI_SANITIZER",
    )
    validate_step_profile(
        sanitizer_test_step,
        "Test focused policy WRITE paths",
        "E_INVENTORY_CI_SANITIZER",
    )
    validate_step_profile(
        windows_step,
        "Build and test (clang-cl)",
        "E_INVENTORY_CI_WINDOWS",
        shell="powershell",
    )

    (
        default_command,
        secure_compile_command,
        secure_test_command,
        sanitizer_compile_command,
        sanitizer_test_command,
        windows_test_command,
    ) = inventory_commands(workflow)
    default_active = active_logical_commands(default_step)
    secure_active = active_logical_commands(secure_step)
    sanitizer_compile_active = active_logical_commands(sanitizer_compile_step)
    sanitizer_test_active = active_logical_commands(sanitizer_test_step)
    windows_active = active_logical_commands(windows_step)
    require(
        default_command
        == (
            "meson",
            "test",
            "-C",
            "builddir",
            "--no-rebuild",
            *POSIX_TESTS,
            "--print-errorlogs",
        )
        and secure_compile_command
        == (
            "/usr/bin/time",
            "${time_args[@]}",
            "meson",
            "compile",
            "-C",
            "build-secure-duckdb",
            "-j",
            "1",
            *SECURE_COMPILE_TARGETS,
            *SECURE_HISTORICAL_COMPILE_TARGETS,
        )
        and secure_test_command
        == (
            "meson",
            "test",
            "-C",
            "build-secure-duckdb",
            "--no-rebuild",
            *POSIX_TESTS,
            *SECURE_HISTORICAL_TESTS,
            "--print-errorlogs",
        )
        and len(default_active) == 1
        and tuple(secure_active) == SECURE_POSIX_ACTIVE_COMMANDS,
        "E_INVENTORY_CI_POSIX",
        f"{path} does not run exact model/consumer/provider/wiring gates in default and secure POSIX builds",
    )
    require(
        sanitizer_compile_command == SANITIZER_COMPILE_COMMAND
        and sanitizer_test_command == SANITIZER_TEST_COMMAND
        and len(sanitizer_compile_active) == 1
        and len(sanitizer_test_active) == 1,
        "E_INVENTORY_CI_SANITIZER",
        f"{path} sanitizer job omits an inventory consumer/provider gate",
    )
    require(
        windows_test_command == WINDOWS_SECURE_TEST_COMMAND
        and tuple(windows_active) == WINDOWS_ACTIVE_COMMANDS,
        "E_INVENTORY_CI_WINDOWS",
        f"{path} secure native-Windows row omits inventory evidence",
    )


def validate_ci(inputs: dict[str, str]) -> None:
    validate_workflow(CI_PR, inputs[CI_PR])
    validate_workflow(CI_MAIN, inputs[CI_MAIN])


def validate_ci_parity(inputs: dict[str, str]) -> None:
    require(
        active_inventory_commands(inputs[CI_PR])
        == active_inventory_commands(inputs[CI_MAIN]),
        "E_INVENTORY_CI_PARITY",
        "PR and main inventory gate inventories differ",
    )


def validate(inputs: dict[str, str]) -> None:
    validate_value_authority(inputs)
    validate_model_completeness(inputs)
    validate_provider_slots(inputs, POSIX_PROVIDER, "E_INVENTORY_POSIX_SLOTS")
    validate_provider_slots(inputs, WINDOWS_PROVIDER, "E_INVENTORY_WINDOWS_SLOTS")
    validate_artifact_lock_access_mode(inputs)
    validate_runtime_tests(inputs)
    validate_meson(inputs)
    validate_ci(inputs)
    validate_ci_parity(inputs)


def diagnostic_codes(inputs: dict[str, str]) -> set[str]:
    validators = (
        validate_value_authority,
        validate_model_completeness,
        lambda value: validate_provider_slots(value, POSIX_PROVIDER, "E_INVENTORY_POSIX_SLOTS"),
        lambda value: validate_provider_slots(value, WINDOWS_PROVIDER, "E_INVENTORY_WINDOWS_SLOTS"),
        validate_artifact_lock_access_mode,
        validate_runtime_tests,
        validate_meson,
        validate_ci,
        validate_ci_parity,
    )
    codes: set[str] = set()
    for validator in validators:
        try:
            validator(inputs)
        except ContractError as error:
            codes.add(error.code)
    return codes


def replaced(inputs: dict[str, str], path: str, old: str, new: str) -> dict[str, str]:
    require(old in inputs[path], "E_SELF_TEST", f"mutation anchor missing in {path}: {old!r}")
    result = dict(inputs)
    result[path] = result[path].replace(old, new, 1)
    return result


def replaced_model_function_body(
    inputs: dict[str, str], function: str, new_body: str
) -> dict[str, str]:
    source = inputs[MODEL_TEST]
    bounds = c_function_body_bounds(source, function)
    require(bounds is not None, "E_SELF_TEST", f"function mutation missing: {function}")
    result = dict(inputs)
    result[MODEL_TEST] = source[:bounds[0]] + new_body + source[bounds[1]:]
    return result


def replace_in_workflow_section(
    workflow: str, start: str, end: str | None, old: str, new: str
) -> str:
    begin = workflow.find(start)
    finish = len(workflow) if end is None else workflow.find(end, begin + len(start))
    require(begin >= 0 and finish > begin, "E_SELF_TEST", f"mutation section missing: {start}")
    body = workflow[begin:finish]
    require(old in body, "E_SELF_TEST", f"mutation anchor missing in {start}: {old}")
    return workflow[:begin] + body.replace(old, new) + workflow[finish:]


def replace_in_named_step(
    workflow: str, job_start: str, job_end: str | None, name: str, old: str, new: str
) -> str:
    begin = workflow.find(job_start)
    finish = len(workflow) if job_end is None else workflow.find(job_end, begin + len(job_start))
    require(begin >= 0 and finish > begin, "E_SELF_TEST", f"mutation job missing: {job_start}")
    job = workflow[begin:finish]
    marker = f"      - name: {name}"
    step_begin = job.find(marker)
    require(step_begin >= 0, "E_SELF_TEST", f"mutation step missing: {name}")
    step_finish = job.find("\n      - name:", step_begin + len(marker))
    if step_finish < 0:
        step_finish = len(job)
    step = job[step_begin:step_finish]
    require(old in step, "E_SELF_TEST", f"mutation anchor missing in {name}: {old}")
    changed = job[:step_begin] + step.replace(old, new, 1) + job[step_finish:]
    return workflow[:begin] + changed + workflow[finish:]


def replace_once_in_named_step(
    workflow: str, job_start: str, job_end: str | None, name: str, old: str, new: str
) -> str:
    begin = workflow.find(job_start)
    finish = len(workflow) if job_end is None else workflow.find(
        job_end, begin + len(job_start)
    )
    require(begin >= 0 and finish > begin, "E_SELF_TEST", "probe job is missing")
    job = workflow[begin:finish]
    marker = f"      - name: {name}"
    step_begin = job.find(marker)
    require(step_begin >= 0, "E_SELF_TEST", "probe step is missing")
    step_finish = job.find("\n      - name:", step_begin + len(marker))
    if step_finish < 0:
        step_finish = len(job)
    step = job[step_begin:step_finish]
    require(
        step.count(old) == 1,
        "E_SELF_TEST",
        f"probe mutation anchor count drifted: {old!r}",
    )
    changed = job[:step_begin] + step.replace(old, new, 1) + job[step_finish:]
    return workflow[:begin] + changed + workflow[finish:]


def move_secure_patch_probe_after_setup(workflow: str) -> str:
    probe = (
        '          if [ "$RUNNER_OS" = Linux ]; then\n'
        "            patch --version\n"
        "          else\n"
        "            gpatch --version\n"
        "          fi | grep -F 'GNU patch'\n"
    )
    without_probe = replace_once_in_named_step(
        workflow,
        "  build-posix:",
        "  duckdb-linux-link-closure:",
        "Build secure DuckDB backend from pinned source",
        probe,
        "",
    )
    return replace_once_in_named_step(
        without_probe,
        "  build-posix:",
        "  duckdb-linux-link-closure:",
        "Build secure DuckDB backend from pinned source",
        "          fi\n          if [ \"$RUNNER_OS\" = Linux ]; then\n"
        "            time_args=(-v)\n",
        "          fi\n"
        + probe
        + "          if [ \"$RUNNER_OS\" = Linux ]; then\n"
        "            time_args=(-v)\n",
    )


def move_windows_inventory_command_to_else(workflow: str) -> str:
    job_start = workflow.find("  build-windows:\n")
    require(job_start >= 0, "E_SELF_TEST", "Windows job mutation anchor is missing")
    marker = "      - name: Build and test (clang-cl)"
    step_start = workflow.find(marker, job_start)
    require(step_start >= 0, "E_SELF_TEST", "Windows test step mutation anchor is missing")
    step_end = workflow.find("\n      - name:", step_start + len(marker))
    if step_end < 0:
        step_end = len(workflow)
    step = workflow[step_start:step_end]
    lines = step.splitlines(keepends=True)
    command_index = next(
        (
            index
            for index, line in enumerate(lines)
            if "meson test -C builddir secure-duckdb-bridge" in line
            and "fact-artifact-namespace-windows-inventory" in line
        ),
        -1,
    )
    else_index = next(
        (index for index, line in enumerate(lines) if line.strip() == ") else ("),
        -1,
    )
    require(
        command_index >= 0 and else_index > command_index,
        "E_SELF_TEST",
        "Windows secure branch mutation anchors are missing",
    )
    command = lines.pop(command_index)
    else_index -= 1
    lines.insert(else_index + 1, command)
    changed = "".join(lines)
    return workflow[:step_start] + changed + workflow[step_end:]


def run_self_test(inputs: dict[str, str]) -> None:
    validate(inputs)
    mutations: list[tuple[str, dict[str, str], set[str]]] = []

    def require_header_profile(
        label: str,
        mutated: dict[str, str],
        expected_directive_hash: str,
        expected_semantic_hash: str,
    ) -> None:
        directive_counts, directive_hash, semantic_counts, semantic_hash = (
            posix_lock_header_closure_profile(mutated)
        )
        require(
            directive_counts
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_COUNTS,
            "E_SELF_TEST",
            f"mutation {label} did not preserve directive counts",
        )
        require(
            directive_hash == expected_directive_hash,
            "E_SELF_TEST",
            f"mutation {label} produced the wrong directive profile",
        )
        require(
            semantic_counts
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_COUNTS,
            "E_SELF_TEST",
            f"mutation {label} did not preserve semantic token counts",
        )
        require(
            semantic_hash == expected_semantic_hash,
            "E_SELF_TEST",
            f"mutation {label} produced the wrong semantic profile",
        )

    header_members = tuple(
        (
            path,
            re.sub(r"[^a-z0-9]+", "-", Path(path).stem.lower()).strip("-"),
        )
        for path in POSIX_LOCK_HEADER_CLOSURE
    )
    for index, (path, slug) in enumerate(header_members):
        label = f"pre-fcntl-{slug}-directive-membership"
        mutation = dict(inputs)
        mutation[path] += (
            f"\n#define WYL_ARTIFACT_LOCK_HEADER_MEMBERSHIP_{index} 1\n"
        )
        directive_counts, directive_hash, semantic_counts, semantic_hash = (
            posix_lock_header_closure_profile(mutation)
        )
        expected_counts = list(
            EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_COUNTS
        )
        expected_counts[index] += 1
        require(
            directive_counts == tuple(expected_counts),
            "E_SELF_TEST",
            f"mutation {label} did not affect only its directive count",
        )
        require(
            directive_hash
            != EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256,
            "E_SELF_TEST",
            f"mutation {label} did not change the directive profile",
        )
        require(
            semantic_counts
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_COUNTS
            and semantic_hash
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256,
            "E_SELF_TEST",
            f"mutation {label} changed the semantic profile",
        )
        mutations.append((label, mutation, {"E_ARTIFACT_LOCK_ACCESS_MODE"}))

    for index, (path, slug) in enumerate(header_members):
        label = f"pre-fcntl-{slug}-semantic-membership"
        mutation = dict(inputs)
        mutation[path] += (
            f"\ntypedef int WylArtifactLockHeaderMembership{index};\n"
        )
        directive_counts, directive_hash, semantic_counts, semantic_hash = (
            posix_lock_header_closure_profile(mutation)
        )
        expected_counts = list(
            EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_COUNTS
        )
        expected_counts[index] += 4
        require(
            directive_counts
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_COUNTS
            and directive_hash
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256,
            "E_SELF_TEST",
            f"mutation {label} changed the directive profile",
        )
        require(
            semantic_counts == tuple(expected_counts),
            "E_SELF_TEST",
            f"mutation {label} did not affect only its semantic token count",
        )
        require(
            semantic_hash
            != EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256,
            "E_SELF_TEST",
            f"mutation {label} did not change the semantic profile",
        )
        mutations.append((label, mutation, {"E_ARTIFACT_LOCK_ACCESS_MODE"}))

    for label, path in (
        (
            "pre-fcntl-inventory-posix-count-preserving-lock-alias",
            POSIX_INVENTORY_HEADER,
        ),
        (
            "pre-fcntl-main-transition-count-preserving-lock-alias",
            MAIN_TRANSITION_HEADER,
        ),
        (
            "pre-fcntl-namespace-count-preserving-lock-alias",
            POSIX_NAMESPACE_HEADER,
        ),
        (
            "pre-fcntl-inventory-count-preserving-lock-alias",
            HEADER,
        ),
    ):
        for anchor in (
            "#pragma once",
            "#include <glib.h>",
            '#include "wyrelog/error.h"',
        ):
            require(
                inputs[path].count(anchor) == 1,
                "E_SELF_TEST",
                f"mutation anchor count drifted in {path}: {anchor!r}",
            )
        mutation = replaced(inputs, path, "#pragma once", "#include <fcntl.h>")
        mutation = replaced(
            mutation, path, "#include <glib.h>", "#undef O_RDWR"
        )
        mutation = replaced(
            mutation,
            path,
            '#include "wyrelog/error.h"',
            "#define O_RDWR O_RDONLY",
        )
        directive_profile = posix_lock_header_closure_profile(mutation)[1]
        require(
            directive_profile
            != EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256,
            "E_SELF_TEST",
            f"mutation {label} did not change the directive profile",
        )
        require_header_profile(
            label,
            mutation,
            directive_profile,
            EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256,
        )
        mutations.append((label, mutation, {"E_ARTIFACT_LOCK_ACCESS_MODE"}))

    for label, path in (
        ("pre-fcntl-namespace-header-lock-alias", POSIX_NAMESPACE_HEADER),
        ("pre-fcntl-inventory-header-lock-alias", HEADER),
    ):
        mutation = replaced(
            inputs,
            path,
            "#include <glib.h>\n",
            "#include <glib.h>\n#include <fcntl.h>\n"
            "#undef O_RDWR\n#define O_RDWR O_RDONLY\n",
        )
        directive_counts, directive_hash, semantic_counts, semantic_hash = (
            posix_lock_header_closure_profile(mutation)
        )
        expected_counts = list(
            EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_COUNTS
        )
        expected_counts[POSIX_LOCK_HEADER_CLOSURE.index(path)] += 3
        require(
            directive_counts == tuple(expected_counts)
            and directive_hash
            != EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256
            and semantic_counts
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_COUNTS
            and semantic_hash
            == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256,
            "E_SELF_TEST",
            f"mutation {label} did not isolate the full directive profile",
        )
        mutations.append((label, mutation, {"E_ARTIFACT_LOCK_ACCESS_MODE"}))

    for label, path, old, new in (
        (
            "direct-posix-header-count-preserving-parameter-rename",
            POSIX_INVENTORY_HEADER,
            "(gpointer user_data);",
            "(gpointer callback_data);",
        ),
        (
            "transitive-main-transition-header-count-preserving-parameter-rename",
            MAIN_TRANSITION_HEADER,
            "void wyl_fact_artifact_main_transition_free\n"
            "  (WylFactArtifactMainTransition *transition);",
            "void wyl_fact_artifact_main_transition_free\n"
            "  (WylFactArtifactMainTransition *transition_to_free);",
        ),
        (
            "pre-fcntl-inventory-count-preserving-free-parameter",
            HEADER,
            "void wyl_fact_artifact_inventory_snapshot_free\n"
            "  (WylFactArtifactInventorySnapshot *snapshot);",
            "void wyl_fact_artifact_inventory_snapshot_free\n"
            "  (WylFactArtifactInventorySnapshot *snapshot_to_free);",
        ),
    ):
        require(
            inputs[path].count(old) == 1,
            "E_SELF_TEST",
            f"mutation anchor count drifted in {path}: {old!r}",
        )
        mutation = replaced(inputs, path, old, new)
        semantic_profile = posix_lock_header_closure_profile(mutation)[3]
        require(
            semantic_profile
            != EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256,
            "E_SELF_TEST",
            f"mutation {label} did not change the semantic profile",
        )
        require_header_profile(
            label,
            mutation,
            EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256,
            semantic_profile,
        )
        mutations.append((label, mutation, {"E_ARTIFACT_LOCK_ACCESS_MODE"}))

    openat_interposition = dict(inputs)
    openat_interposition[HEADER] += (
        "\nextern long syscall (long number, ...);\n\n"
        "int\nopenat (int directory_fd, const char *path, int flags, ...)\n"
        "{\n"
        "  (void) flags;\n"
        "  return (int) syscall (257L, directory_fd, path, 0);\n"
        "}\n"
    )
    interposition_profile = posix_lock_header_closure_profile(
        openat_interposition
    )
    require(
        interposition_profile[0]
        == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_COUNTS
        and interposition_profile[1]
        == EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256
        and interposition_profile[2]
        != EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_COUNTS
        and interposition_profile[3]
        != EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256,
        "E_SELF_TEST",
        "semantic openat interposition did not isolate the semantic profile",
    )
    mutations.append(
        (
            "pre-fcntl-inventory-openat-read-only-interposition",
            openat_interposition,
            {"E_ARTIFACT_LOCK_ACCESS_MODE"},
        )
    )

    directive_comment = dict(inputs)
    directive_comment[HEADER] += (
        "\n/*\n#include <fcntl.h>\n#undef O_RDWR\n"
        "#define O_RDWR O_RDONLY\n*/\n"
    )
    require_header_profile(
        "pre-fcntl-inventory-directive-comment-decoy",
        directive_comment,
        EXPECTED_POSIX_LOCK_HEADER_CLOSURE_DIRECTIVE_PROFILE_SHA256,
        EXPECTED_POSIX_LOCK_HEADER_CLOSURE_SEMANTIC_TOKEN_PROFILE_SHA256,
    )
    mutations.append(
        ("pre-fcntl-inventory-directive-comment-decoy", directive_comment, set())
    )

    lock_create = (
        "O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL"
    )
    for label, old, new in (
        ("lock-create-read-only", lock_create, lock_create.replace("O_RDWR", "O_RDONLY")),
        (
            "lock-fallback-read-only",
            "pin = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),\n"
            "              O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);",
            "pin = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),\n"
            "              O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);",
        ),
        (
            "lock-guard-read-only",
            "gint fd = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),\n"
            "          O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);",
            "gint fd = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),\n"
            "          O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);",
        ),
        ("lock-dynamic-flags", lock_create, "lock_flags"),
        (
            "lock-conditional-flags",
            lock_create,
            "(n->lock_pin_fd < 0 ? O_RDWR : O_RDONLY) | O_NONBLOCK | "
            "O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL",
        ),
        (
            "lock-access-parameter",
            "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)",
            "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd, "
            "gboolean writable)",
        ),
        (
            "lock-call-redirect",
            "name_for (WYL_FACT_ARTIFACT_LOCK),\n"
            "            O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_CREAT",
            "name_for (WYL_FACT_ARTIFACT_MAIN),\n"
            "            O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_CREAT",
        ),
        (
            "lock-call-removed",
            "pin = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),",
            "pin = guarded_openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),",
        ),
        (
            "reader-wrapper-mode",
            "return acquire_lease (n, FALSE, out_lease);",
            "return acquire_lease (n, TRUE, out_lease);",
        ),
        (
            "mutation-wrapper-mode",
            "return acquire_lease (n, TRUE, out_lease);",
            "return acquire_lease (n, FALSE, out_lease);",
        ),
    ):
        mutation = replaced(inputs, POSIX_PROVIDER, old, new)
        mutations.append((label, mutation, {"E_ARTIFACT_LOCK_ACCESS_MODE"}))

    conditional_call = replaced(
        inputs,
        POSIX_PROVIDER,
        "  wyrelog_error_t r = open_checked_lock (n, &fd);\n"
        "  if (r != WYRELOG_E_OK)\n"
        "    return r;\n"
        "  if (flock (fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0)",
        "  wyrelog_error_t r = WYRELOG_E_OK;\n"
        "  if (exclusive)\n"
        "    r = open_checked_lock (n, &fd);\n"
        "  if (r != WYRELOG_E_OK)\n"
        "    return r;\n"
        "  if (flock (fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0)",
    )
    mutations.append(
        ("conditional-acquire-call", conditional_call, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    pin_bypass = replaced(
        inputs,
        POSIX_PROVIDER,
        "  wyrelog_error_t r = open_checked_lock (n, &fd);",
        "  wyrelog_error_t r = open_unchecked_lock (n, &fd);",
    )
    mutations.append(
        ("pin-lock-domain-bypass", pin_bypass, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    macro_alias = replaced(
        inputs,
        POSIX_PROVIDER,
        "#include <fcntl.h>\n",
        "#include <fcntl.h>\n#undef O_RDWR\n#define O_RDWR O_RDONLY\n",
    )
    mutations.append(
        ("lock-access-macro-alias", macro_alias, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    directive_comment = replaced(
        inputs,
        POSIX_PROVIDER,
        "#include <fcntl.h>\n",
        "#include <fcntl.h> /* declares openat; O_RDWR is required */\n",
    )
    mutations.append(("lock-directive-comment", directive_comment, set()))

    included_alias = replaced(
        inputs,
        POSIX_PROVIDER,
        "#include <fcntl.h>\n",
        '#include <fcntl.h>\n#include "artifact-lock-read-only-alias.h"\n',
    )
    included_alias["artifact-lock-read-only-alias.h"] = (
        "#undef O_RDWR\n#define O_RDWR O_RDONLY\n"
    )
    mutations.append(
        ("included-lock-access-alias", included_alias, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    def with_extra_posix_source(extra: str) -> dict[str, str]:
        result = dict(inputs)
        provider_prefix, provider_suffix = result[POSIX_PROVIDER].rsplit(
            "#endif\n", 1
        )
        result[POSIX_PROVIDER] = (
            provider_prefix + extra + "#endif\n" + provider_suffix
        )
        return result

    for label, callee, target in (
        (
            "extra-read-only-lock-open",
            "openat",
            "name_for (WYL_FACT_ARTIFACT_LOCK)",
        ),
        (
            "parenthesized-lock-target",
            "openat",
            "(name_for (WYL_FACT_ARTIFACT_LOCK))",
        ),
        (
            "comma-expression-lock-target",
            "openat",
            "(0, name_for (WYL_FACT_ARTIFACT_LOCK))",
        ),
        (
            "literal-lock-target",
            "openat",
            '"facts.duckdb.lock"',
        ),
        (
            "parenthesized-openat-callee",
            "(openat)",
            "name_for (WYL_FACT_ARTIFACT_LOCK)",
        ),
        (
            "dereferenced-openat-callee",
            "(*openat)",
            "name_for (WYL_FACT_ARTIFACT_LOCK)",
        ),
    ):
        extra_lock_open = with_extra_posix_source(
            "static void artifact_lock_extra_open (WylFactArtifactNamespace *n)\n"
            "{\n"
            f"  (void) {callee} (n->fd, {target},\n"
            "      O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);\n"
            "}\n"
        )
        mutations.append(
            (label, extra_lock_open, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
        )

    helper_returned_lock = with_extra_posix_source(
        "static const gchar *artifact_lock_hidden_name (void)\n"
        "{\n"
        "  return name_for (WYL_FACT_ARTIFACT_LOCK);\n"
        "}\n"
        "static void artifact_lock_helper_return_open "
        "(WylFactArtifactNamespace *n)\n"
        "{\n"
        "  (void) openat (n->fd, artifact_lock_hidden_name (),\n"
        "      O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);\n"
        "}\n"
    )
    mutations.append(
        ("helper-returned-lock-target", helper_returned_lock,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    existing_main_target = (
        "name_for (WYL_FACT_ARTIFACT_MAIN),\n"
        "            O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW"
    )
    for label, replacement in (
        (
            "balanced-adjacent-literal-lock-target",
            '"facts.duckdb." "lock",\n'
            "            O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW",
        ),
        (
            "balanced-numeric-lock-target",
            "name_for ((WylFactArtifactName) 4),\n"
            "            O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW",
        ),
    ):
        balanced_substitution = replaced(
            inputs,
            POSIX_PROVIDER,
            existing_main_target,
            replacement,
        )
        mutations.append(
            (label, balanced_substitution, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
        )

    token_pasted_open = with_extra_posix_source(
        "#define WYL_JOIN_TOKENS_(left, right) left ## right\n"
        "#define WYL_JOIN_TOKENS(left, right) "
        "WYL_JOIN_TOKENS_(left, right)\n"
        "static void artifact_lock_token_pasted_open "
        "(WylFactArtifactNamespace *n)\n"
        "{\n"
        "  (void) WYL_JOIN_TOKENS (open, at) "
        "(n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),\n"
        "      O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);\n"
        "}\n"
    )
    mutations.append(
        ("token-pasted-lock-open", token_pasted_open, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    early_mode_use = replaced(
        inputs,
        POSIX_PROVIDER,
        "  if (!n || !out_lease)\n"
        "    return WYRELOG_E_INVALID;\n"
        "  gint fd = -1;\n"
        "  wyrelog_error_t r = open_checked_lock (n, &fd);",
        "  if (!n || !out_lease)\n"
        "    return WYRELOG_E_INVALID;\n"
        "  gint fd = exclusive ? -1 : -1;\n"
        "  wyrelog_error_t r = open_checked_lock (n, &fd);",
    )
    mutations.append(
        ("mode-used-before-lock", early_mode_use, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    threaded_mode = replaced(
        inputs,
        POSIX_PROVIDER,
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)",
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd, "
        "gboolean exclusive)",
    )
    threaded_mode = replaced(
        threaded_mode,
        POSIX_PROVIDER,
        lock_create,
        "(exclusive ? O_RDWR : O_RDONLY) | O_NONBLOCK | O_CLOEXEC | "
        "O_NOFOLLOW | O_CREAT | O_EXCL",
    )
    threaded_mode = replaced(
        threaded_mode,
        POSIX_PROVIDER,
        "  wyrelog_error_t r = open_checked_lock (n, &fd);",
        "  wyrelog_error_t r = open_checked_lock (n, &fd, TRUE);",
    )
    threaded_mode = replaced(
        threaded_mode,
        POSIX_PROVIDER,
        "  wyrelog_error_t r = open_checked_lock (n, &fd);",
        "  wyrelog_error_t r = open_checked_lock (n, &fd, exclusive);",
    )
    mutations.append(
        ("thread-reader-access-mode", threaded_mode, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    decoys = dict(inputs)
    decoys[POSIX_PROVIDER] += (
        "\n/* open_checked_lock(n, fd, O_RDONLY); "
        "openat(n->fd, name_for(WYL_FACT_ARTIFACT_LOCK), flags); "
        "facts.duckdb.lock */\n"
        "static const char *artifact_lock_decoy = "
        "\"openat(n->fd, name, O_RDONLY)\";\n"
        "static const char *artifact_name_table_decoy = "
        "\"static const gchar *names[] = { NULL };\";\n"
    )
    mutations.append(("artifact-lock-decoys", decoys, set()))

    swapped_name_mapping = replaced(
        inputs,
        POSIX_PROVIDER,
        '{ "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",\n'
        '  "facts.duckdb.wal.recovery", "facts.duckdb.lock", NULL};',
        '{ "facts.duckdb.lock", "facts.duckdb.wal", '
        '"facts.duckdb.wal.checkpoint",\n'
        '  "facts.duckdb.wal.recovery", "facts.duckdb", NULL};',
    )
    mutations.append(
        ("main-lock-name-mapping-swap", swapped_name_mapping,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    for label, directive in (
        ("artifact-name-table-macro-redirect", "#define names redirected_names\n"),
        ("artifact-main-enum-macro-redirect", "#define WYL_FACT_ARTIFACT_MAIN 4\n"),
    ):
        macro_redirect = replaced(
            inputs,
            POSIX_PROVIDER,
            "#include <fcntl.h>\n",
            "#include <fcntl.h>\n" + directive,
        )
        mutations.append(
            (label, macro_redirect, {"E_ARTIFACT_LOCK_ACCESS_MODE"})
        )

    runtime_name_retarget = replaced(
        inputs,
        POSIX_PROVIDER,
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)\n{",
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)\n"
        "{\n  names[0] = names[4];",
    )
    mutations.append(
        ("runtime-artifact-name-retarget", runtime_name_retarget,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    raw_open_syscall = replaced(
        inputs,
        POSIX_PROVIDER,
        "extern long syscall (long, ...);\n",
        "extern long syscall (long, ...);\n"
        "static void artifact_lock_raw_open (gint dirfd)\n"
        "{\n"
        "  (void) syscall (SYS_openat, dirfd, "
        '"facts.duckdb." "lock",\n'
        "      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);\n"
        "}\n",
    )
    mutations.append(
        ("raw-open-syscall", raw_open_syscall,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    raw_libc_open = replaced(
        inputs,
        POSIX_PROVIDER,
        "extern long syscall (long, ...);\n",
        "extern long syscall (long, ...);\n"
        "static void artifact_lock_libc_open (gint dirfd)\n"
        "{\n"
        "  g_autofree gchar *path = g_strdup_printf (\"/proc/self/fd/%d/%s\",\n"
        "      dirfd, \"facts.duckdb.\" \"lock\");\n"
        "  (void) open (path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);\n"
        "}\n",
    )
    mutations.append(
        ("raw-libc-open", raw_libc_open,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    raw_libc_openat64_2 = replaced(
        inputs,
        POSIX_PROVIDER,
        "extern long syscall (long, ...);\n",
        "extern long syscall (long, ...);\n"
        "extern int __openat64_2 (int, const char *, int);\n"
        "static void artifact_lock_libc_openat64_2 (gint dirfd)\n"
        "{\n"
        "  (void) __openat64_2 (dirfd, \"facts.duckdb.\" \"lock\",\n"
        "      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);\n"
        "}\n",
    )
    mutations.append(
        ("raw-libc-openat64-2", raw_libc_openat64_2,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    raw_glib_mapped_file = replaced(
        inputs,
        POSIX_PROVIDER,
        "extern long syscall (long, ...);\n",
        "extern long syscall (long, ...);\n"
        "static void artifact_lock_glib_map (gint dirfd)\n"
        "{\n"
        "  g_autofree gchar *path = g_strdup_printf (\"/proc/self/fd/%d/%s\",\n"
        "      dirfd, \"facts.duckdb.\" \"lock\");\n"
        "  (void) g_mapped_file_new (path, FALSE, NULL);\n"
        "}\n",
    )
    mutations.append(
        ("raw-glib-mapped-file", raw_glib_mapped_file,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    parenthesized_glib_mapped_file = replaced(
        inputs,
        POSIX_PROVIDER,
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)\n{",
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)\n"
        "{\n"
        "  g_autofree gchar *review_path = (g_strdup_printf) "
        "(\"/proc/self/fd/%d/%s\",\n"
        "      n->fd, \"facts.duckdb.\" \"lock\");\n"
        "  (void) (g_mapped_file_new) (review_path, FALSE, NULL);",
    )
    mutations.append(
        ("parenthesized-glib-mapped-file", parenthesized_glib_mapped_file,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    unicode_glib_aliases = replaced(
        inputs,
        POSIX_PROVIDER,
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)\n{",
        "open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)\n"
        "{\n"
        "  __auto_type \u03bb = g_strdup_printf;\n"
        "  __auto_type \u03bc = g_mapped_file_new;\n"
        "  g_autofree gchar *review_path = \u03bb (\"/proc/self/fd/%d/%s\",\n"
        "      n->fd, \"facts.duckdb.\" \"lock\");\n"
        "  (void) \u03bc (review_path, FALSE, NULL);",
    )
    mutations.append(
        ("unicode-glib-aliases", unicode_glib_aliases,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )
    ucn_glib_aliases = dict(unicode_glib_aliases)
    ucn_glib_aliases[POSIX_PROVIDER] = (
        ucn_glib_aliases[POSIX_PROVIDER]
        .replace("\u03bb", "\\u03bb")
        .replace("\u03bc", "\\u03bc")
    )
    mutations.append(
        ("ucn-glib-aliases", ucn_glib_aliases,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )
    dollar_glib_aliases = dict(unicode_glib_aliases)
    dollar_glib_aliases[POSIX_PROVIDER] = (
        dollar_glib_aliases[POSIX_PROVIDER]
        .replace("\u03bb", "$0")
        .replace("\u03bc", "$1")
    )
    mutations.append(
        ("dollar-glib-aliases", dollar_glib_aliases,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    existing_callee_retarget = replaced(
        inputs,
        POSIX_PROVIDER,
        "g_autofree gchar *destination = g_strdup_printf "
        "(\"tmp-%s\", destination_token);",
        "g_autofree gchar *destination = g_strdup_printf "
        "(\"/proc/self/fd/%d/%s\", lease->namespace_->fd, "
        "\"facts.duckdb.\" \"lock\");",
    )
    existing_callee_retarget = replaced(
        existing_callee_retarget,
        POSIX_PROVIDER,
        "  g_autofree gchar *source = NULL;\n",
        "  g_autofree gchar *source = NULL;\n"
        "  __auto_type g_strcmp0 = g_mapped_file_new;\n",
    )
    existing_callee_retarget = replaced(
        existing_callee_retarget,
        POSIX_PROVIDER,
        "if (g_strcmp0 (binding->token, destination_token) == 0)",
        "if (g_strcmp0 (destination, FALSE, NULL) == NULL)",
    )
    mutations.append(
        ("existing-callee-retarget", existing_callee_retarget,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    unchanged_call_retarget = replaced(
        inputs,
        POSIX_PROVIDER,
        "temp_evidence_v2_text_valid (const gchar *value, guint16 length,\n"
        "    gboolean required)\n{",
        "temp_evidence_v2_text_valid (const gchar *value, guint16 length,\n"
        "    gboolean required)\n"
        "{\n"
        "  __auto_type g_utf8_validate = g_mapped_file_new;\n"
        "  value = \"/proc/self/fd/3/facts.duckdb.\" \"lock\";\n"
        "  length = FALSE;\n"
        "  required = FALSE;",
    )
    mutations.append(
        ("unchanged-call-retarget", unchanged_call_retarget,
         {"E_ARTIFACT_LOCK_ACCESS_MODE"})
    )

    message_mutation = replaced(
        inputs,
        POSIX_PROVIDER,
        "O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL",
        "O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL",
    )
    try:
        validate_artifact_lock_access_mode(message_mutation)
    except ContractError as error:
        require(
            str(error)
            == "E_ARTIFACT_LOCK_ACCESS_MODE: " + ARTIFACT_LOCK_DIAGNOSTIC,
            "E_SELF_TEST",
            "artifact lock diagnostic no longer names #869 ruling 1 and its "
            "pending-erasure consequence",
        )
    else:
        raise ContractError(
            "E_SELF_TEST",
            "artifact lock diagnostic mutation unexpectedly passed",
        )

    raw_authority = replaced(
        inputs,
        HEADER,
        "  gboolean present;",
        "  gboolean present;\n  gpointer handle;",
    )
    mutations.append(
        (
            "raw-authority",
            raw_authority,
            {"E_ARTIFACT_LOCK_ACCESS_MODE", "E_INVENTORY_VALUE_AUTHORITY"},
        )
    )
    for label, declaration in (
        ("typed-namespace-authority", "WylFactArtifactNamespace *namespace_;"),
        ("entry-name-array", "gchar entry_name[256];"),
        ("reopen-path-array", "guint8 reopen_path_bytes[256];"),
    ):
        extra_field = replaced(
            inputs,
            HEADER,
            "  gboolean present;",
            f"  gboolean present;\n  {declaration}",
        )
        mutations.append(
            (
                label,
                extra_field,
                {"E_ARTIFACT_LOCK_ACCESS_MODE", "E_INVENTORY_VALUE_AUTHORITY"},
            )
        )

    weakened = replaced(
        inputs,
        MODEL,
        "slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT",
        "slot + 1 < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT",
    )
    mutations.append(("weaken-all-slots", weakened, {"E_INVENTORY_ALL_SLOTS"}))

    posix_omit = dict(inputs)
    require(
        "WYL_FACT_ARTIFACT_INVENTORY_TEMP, NULL" in posix_omit[POSIX_PROVIDER],
        "E_SELF_TEST",
        "POSIX TEMP mutation anchor is missing",
    )
    posix_omit[POSIX_PROVIDER] = posix_omit[POSIX_PROVIDER].replace(
        "WYL_FACT_ARTIFACT_INVENTORY_TEMP, NULL",
        "WYL_FACT_ARTIFACT_INVENTORY_LOCK, NULL",
    )
    mutations.append(
        (
            "posix-omit-temp",
            posix_omit,
            {"E_ARTIFACT_LOCK_ACCESS_MODE", "E_INVENTORY_POSIX_SLOTS"},
        )
    )

    windows_omit = replaced(
        inputs,
        WINDOWS_PROVIDER,
        "WYL_FACT_ARTIFACT_INVENTORY_TEMP, NULL,",
        "WYL_FACT_ARTIFACT_INVENTORY_LOCK, NULL,",
    )
    mutations.append(("windows-omit-temp", windows_omit, {"E_INVENTORY_WINDOWS_SLOTS"}))

    omitted_test = replaced(
        inputs,
        MODEL_TEST,
        "test_omitted_slot_matrix_fails_closed",
        "test_removed_omitted_slot_matrix",
    )
    mutations.append(("remove-omitted-test", omitted_test, {"E_INVENTORY_OMITTED_SLOT_TEST"}))

    for label, function in (
        ("remove-anomaly-regression", "test_anomaly_limit_overflow_clears_evidence"),
        (
            "remove-contradictory-identity-regression",
            "test_contradictory_extended_identity_fails_closed",
        ),
        (
            "remove-extended-observation-regression",
            "test_extended_observation_mismatch_clears_evidence",
        ),
    ):
        regression_removed = replaced(
            inputs,
            MODEL_TEST,
            function,
            f"removed_{function}",
        )
        mutations.append(
            (label, regression_removed, {"E_INVENTORY_REGRESSION_TESTS"})
        )

    registration_commented = replaced(
        inputs,
        MODEL_TEST,
        '  g_test_add_func ("/fact/artifact-inventory/anomaly-limit-overflow",\n'
        "      test_anomaly_limit_overflow_clears_evidence);",
        '  /* g_test_add_func ("/fact/artifact-inventory/anomaly-limit-overflow",\n'
        "      test_anomaly_limit_overflow_clears_evidence); */",
    )
    mutations.append(
        (
            "comment-anomaly-registration",
            registration_commented,
            {"E_INVENTORY_REGRESSION_TESTS"},
        )
    )

    dead_anomaly = replaced(
        inputs,
        MODEL_TEST,
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n",
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n"
        "  if (FALSE)\n    return;\n",
    )
    mutations.append(
        ("dead-anomaly-body", dead_anomaly, {"E_INVENTORY_REGRESSION_TESTS"})
    )

    preprocessor_anomaly = replaced(
        inputs,
        MODEL_TEST,
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n",
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n#if 0\n#endif\n",
    )
    mutations.append(
        (
            "conditional-anomaly-body",
            preprocessor_anomaly,
            {"E_INVENTORY_REGRESSION_TESTS"},
        )
    )

    quoted_anomaly = replaced_model_function_body(
        inputs,
        "test_anomaly_limit_overflow_clears_evidence",
        "\n  const gchar *shape_only = \""
        "wyl_fact_artifact_inventory_snapshot_new (1) "
        "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly "
        "(snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, "
        "WYRELOG_E_OK); "
        "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly "
        "(snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, "
        "WYRELOG_E_POLICY); "
        "g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status "
        "(snapshot), ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW); "
        "assert_no_published_evidence (snapshot);\";\n"
        "  g_assert_nonnull (shape_only);\n",
    )
    mutations.append(
        ("quoted-anomaly-shapes", quoted_anomaly, {"E_INVENTORY_REGRESSION_TESTS"})
    )

    for label, anchor, insertion in (
        (
            "main-success-exit",
            "main (int argc, char **argv)\n{\n",
            "main (int argc, char **argv)\n{\n  exit (0);\n",
        ),
        (
            "anomaly-success-exit",
            "test_anomaly_limit_overflow_clears_evidence (void)\n{\n",
            "test_anomaly_limit_overflow_clears_evidence (void)\n{\n"
            "  exit (0);\n",
        ),
        (
            "anomaly-skip",
            "test_anomaly_limit_overflow_clears_evidence (void)\n{\n",
            "test_anomaly_limit_overflow_clears_evidence (void)\n{\n"
            '  g_test_skip ("decoy");\n',
        ),
    ):
        terminated = replaced(inputs, MODEL_TEST, anchor, insertion)
        mutations.append(
            (label, terminated, {"E_INVENTORY_REGRESSION_TESTS"})
        )

    spliced_exit = replaced(
        inputs,
        MODEL_TEST,
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n",
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n"
        + "  ex"
        + chr(92)
        + "\nit (0);\n",
    )
    mutations.append(
        ("spliced-anomaly-exit", spliced_exit, {"E_INVENTORY_REGRESSION_TESTS"})
    )

    macro_alias = replaced(
        inputs,
        MODEL_TEST,
        '#include "fact/graph-artifact-inventory-private.h"\n',
        '#include "fact/graph-artifact-inventory-private.h"\n'
        "#define finish_success exit\n",
    )
    macro_alias = replaced(
        macro_alias,
        MODEL_TEST,
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n",
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n"
        "  finish_success (0);\n",
    )
    mutations.append(
        ("macro-anomaly-exit", macro_alias, {"E_INVENTORY_REGRESSION_TESTS"})
    )

    meson_removed = replaced(
        inputs,
        MESON,
        "fact-artifact-inventory-consumer-contract",
        "removed-inventory-consumer-contract",
    )
    mutations.append(("meson-consumer", meson_removed, {"E_INVENTORY_MESON"}))

    meson_macro_alias = replaced(
        inputs,
        MODEL_TEST,
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n",
        "test_anomaly_limit_overflow_clears_evidence (void)\n{\n"
        "  finish_success;\n",
    )
    meson_macro_alias = replaced(
        meson_macro_alias,
        MESON,
        "  'test-fact-artifact-inventory.c',\n",
        "  'test-fact-artifact-inventory.c',\n"
        "  c_args : ['-Dfinish_success=return'],\n",
    )
    mutations.append(
        ("meson-macro-alias", meson_macro_alias, {"E_INVENTORY_MESON"})
    )

    for label, opener, closer in (
        ("meson-outer-false", "if false\n", "\nendif\n"),
        (
            "meson-outer-empty-foreach",
            "foreach disabled_inventory : []\n",
            "\nendforeach\n",
        ),
    ):
        meson_outer_control = replaced(
            inputs,
            MESON,
            "test_fact_artifact_inventory = executable",
            opener + "test_fact_artifact_inventory = executable",
        )
        meson_outer_control[MESON] += closer
        mutations.append(
            (label, meson_outer_control, {"E_INVENTORY_MESON"})
        )

    meson_early_done = replaced(
        inputs,
        MESON,
        "test_fact_artifact_inventory = executable",
        "subdir_done()\n\ntest_fact_artifact_inventory = executable",
    )
    mutations.append(
        ("meson-early-subdir-done", meson_early_done, {"E_INVENTORY_MESON"})
    )

    for label, decoy in (
        (
            "meson-comment-control-decoy",
            "# subdir_done() if false foreach disabled : []\n",
        ),
        (
            "meson-string-control-decoy",
            "inventory_control_decoy = 'subdir_done() if false foreach'\n",
        ),
    ):
        meson_decoy = replaced(
            inputs,
            MESON,
            "test_fact_artifact_inventory = executable",
            decoy + "test_fact_artifact_inventory = executable",
        )
        mutations.append((label, meson_decoy, set()))

    meson_triple_hidden_done = replaced(
        inputs,
        MESON,
        "test_fact_artifact_inventory = executable",
        "inventory_decoy = '''don't stop here'''\n"
        "subdir_done()\n"
        "test_fact_artifact_inventory = executable",
    )
    mutations.append(
        (
            "meson-triple-string-hidden-done",
            meson_triple_hidden_done,
            {"E_INVENTORY_MESON"},
        )
    )

    meson_triple_decoy = replaced(
        inputs,
        MESON,
        "test_fact_artifact_inventory = executable",
        "inventory_decoy = '''don't run subdir_done() if false endif'''\n"
        "test_fact_artifact_inventory = executable",
    )
    mutations.append(("meson-triple-string-decoy", meson_triple_decoy, set()))

    meson_unterminated_triple = replaced(
        inputs,
        MESON,
        "test_fact_artifact_inventory = executable",
        "inventory_decoy = '''unterminated\n"
        "test_fact_artifact_inventory = executable",
    )
    mutations.append(
        (
            "meson-unterminated-triple-string",
            meson_unterminated_triple,
            {"E_INVENTORY_MESON"},
        )
    )

    for label, split_call in (
        ("meson-split-subdir-done", "subdir_done \\" + "\n()\n"),
        (
            "meson-commented-continuation-subdir-done",
            "subdir_done \\   # continuation\n()\n",
        ),
    ):
        meson_continued_done = replaced(
            inputs,
            MESON,
            "test_fact_artifact_inventory = executable",
            split_call + "test_fact_artifact_inventory = executable",
        )
        mutations.append(
            (label, meson_continued_done, {"E_INVENTORY_MESON"})
        )

    for label, decoy, expected in (
        (
            "meson-triple-continuation-decoy",
            "inventory_decoy = '''subdir_done \\" + "\n()'''\n",
            set(),
        ),
        (
            "meson-ordinary-continuation-decoy",
            "inventory_decoy = 'subdir_done \\" + "\n()'\n",
            {"E_INVENTORY_MESON"},
        ),
        (
            "meson-comment-continuation-decoy",
            "# subdir_done \\" + "\n# ()\n",
            set(),
        ),
        (
            "meson-harmless-active-continuation",
            "inventory_decoy = 1 + \\" + "\n  2\n",
            set(),
        ),
    ):
        meson_continuation_decoy = replaced(
            inputs,
            MESON,
            "test_fact_artifact_inventory = executable",
            decoy + "test_fact_artifact_inventory = executable",
        )
        mutations.append((label, meson_continuation_decoy, expected))

    for label, job_start, job_end, step_name, old, new, expected in (
        (
            "posix-step-if-false",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Verify artifact inventory consumer contract",
            "        run: |\n",
            "        if: ${{ false }}\n        run: |\n",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "sanitizer-step-continue-on-error",
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "Test focused policy WRITE paths",
            "        run: |\n",
            "        continue-on-error: true\n        run: |\n",
            "E_INVENTORY_CI_SANITIZER",
        ),
        (
            "windows-step-nonexecuting-shell",
            "  build-windows:",
            None,
            "Build and test (clang-cl)",
            "        shell: powershell\n",
            "        shell: bash -n {0}\n",
            "E_INVENTORY_CI_WINDOWS",
        ),
    ):
        metadata_bypass = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            metadata_bypass[path] = replace_in_named_step(
                metadata_bypass[path],
                job_start,
                job_end,
                step_name,
                old,
                new,
            )
        mutations.append((label, metadata_bypass, {expected}))

    for label, start, end, insertion, expected in (
        (
            "posix-job-if-false",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "  build-posix:\n    if: ${{ false }}",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "sanitizer-job-continue-on-error",
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "  policy-write-focused-sanitizer:\n    continue-on-error: true",
            "E_INVENTORY_CI_SANITIZER",
        ),
        (
            "windows-job-run-defaults",
            "  build-windows:",
            None,
            "  build-windows:\n    defaults:\n      run:\n        shell: bash -n {0}",
            "E_INVENTORY_CI_WINDOWS",
        ),
    ):
        job_bypass = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            job_bypass[path] = replace_in_workflow_section(
                job_bypass[path], start, end, start, insertion
            )
        mutations.append((label, job_bypass, {expected}))

    workflow_defaults = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        workflow_defaults[path] = (
            "defaults:\n  run:\n    shell: bash -n {0}\n"
            + workflow_defaults[path]
        )
    mutations.append(
        ("workflow-run-defaults", workflow_defaults, {"E_INVENTORY_CI_SHAPE"})
    )

    for label, text in (
        (
            "workflow-quoted-defaults",
            '"defaults": {run: {shell: bash -n {0}}}\n',
        ),
        (
            "workflow-explicit-defaults",
            "? defaults\n: {run: {shell: bash -n {0}}}\n",
        ),
    ):
        unusual_workflow_key = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            unusual_workflow_key[path] = text + unusual_workflow_key[path]
        mutations.append(
            (label, unusual_workflow_key, {"E_INVENTORY_CI_SHAPE"})
        )

    for label, start, end, insertion, expected in (
        (
            "posix-job-if-after-steps",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "    if: ${{ false }}\n\n",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "sanitizer-job-continue-after-steps",
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "    continue-on-error: true\n\n",
            "E_INVENTORY_CI_SANITIZER",
        ),
        (
            "sanitizer-job-defaults-after-steps",
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "    defaults:\n      run:\n        shell: bash -n {0}\n\n",
            "E_INVENTORY_CI_SANITIZER",
        ),
    ):
        post_steps_control = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            boundary = end
            require(boundary is not None, "E_SELF_TEST", "post-step boundary is missing")
            post_steps_control[path] = post_steps_control[path].replace(
                boundary, insertion + boundary, 1
            )
        mutations.append((label, post_steps_control, {expected}))

    for label, key_text in (
        ("posix-job-quoted-if", '    "if": ${{ false }}\n'),
        ("posix-job-explicit-if", "    ? if\n    : ${{ false }}\n"),
    ):
        unusual_job_key = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            unusual_job_key[path] = replace_in_workflow_section(
                unusual_job_key[path],
                "  build-posix:",
                "  duckdb-linux-link-closure:",
                "  build-posix:\n",
                "  build-posix:\n" + key_text,
            )
        mutations.append(
            (label, unusual_job_key, {"E_INVENTORY_CI_POSIX"})
        )

    for label, start, end, token, expected in (
        (
            "posix-ci",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "fact-artifact-namespace-inventory",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "sanitizer-ci",
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "test-fact-artifact-inventory-consumers",
            "E_INVENTORY_CI_SANITIZER",
        ),
        (
            "windows-ci",
            "  build-windows:",
            None,
            "fact-artifact-namespace-windows-inventory",
            "E_INVENTORY_CI_WINDOWS",
        ),
    ):
        mutated = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            mutated[path] = replace_in_workflow_section(
                mutated[path], start, end, token, f"disabled-{label}"
            )
        mutations.append((label, mutated, {expected}))

    secure_compile = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        secure_compile[path] = replace_in_named_step(
            secure_compile[path],
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "test-fact-artifact-inventory-consumers",
            "removed-fact-artifact-inventory-consumers",
        )
    mutations.append(("secure-compile-target", secure_compile, {"E_INVENTORY_CI_POSIX"}))

    secure_runtime = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        secure_runtime[path] = replace_in_named_step(
            secure_runtime[path],
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "fact-artifact-inventory-consumer-wiring-self",
            "removed-fact-artifact-inventory-consumer-wiring-self",
        )
    mutations.append(("secure-runtime-test", secure_runtime, {"E_INVENTORY_CI_POSIX"}))

    for label, old, new in (
        (
            "secure-patch-probe-removed",
            "            patch --version\n",
            "",
        ),
        (
            "secure-gpatch-probe-replaced",
            "            gpatch --version\n",
            "            unapproved-patch --version\n",
        ),
        (
            "secure-patch-proof-weakened",
            "          fi | grep -F 'GNU patch'\n",
            "          fi | grep -F patch\n",
        ),
        (
            "secure-patch-proof-masked",
            "          fi | grep -F 'GNU patch'\n",
            "          fi | grep -F 'GNU patch' || true\n",
        ),
        (
            "secure-patch-proof-early-success",
            "          if [ \"$RUNNER_OS\" = Linux ]; then\n"
            "            patch --version\n",
            "          exit 0\n"
            "          if [ \"$RUNNER_OS\" = Linux ]; then\n"
            "            patch --version\n",
        ),
    ):
        probe_mutation = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            probe_mutation[path] = replace_once_in_named_step(
                probe_mutation[path],
                "  build-posix:",
                "  duckdb-linux-link-closure:",
                "Build secure DuckDB backend from pinned source",
                old,
                new,
            )
        mutations.append((label, probe_mutation, {"E_INVENTORY_CI_POSIX"}))

    moved_probe = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        moved_probe[path] = move_secure_patch_probe_after_setup(moved_probe[path])
    mutations.append(
        ("secure-patch-proof-moved", moved_probe, {"E_INVENTORY_CI_POSIX"})
    )

    probe_parity = dict(inputs)
    probe_parity[CI_PR] = replace_once_in_named_step(
        probe_parity[CI_PR],
        "  build-posix:",
        "  duckdb-linux-link-closure:",
        "Build secure DuckDB backend from pinned source",
        "            gpatch --version\n",
        "            unapproved-patch --version\n",
    )
    mutations.append(
        (
            "secure-patch-proof-parity",
            probe_parity,
            {"E_INVENTORY_CI_POSIX", "E_INVENTORY_CI_PARITY"},
        )
    )

    for label, job_start, job_end, step_name, old, new, expected in (
        (
            "comment-default-runtime",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Verify artifact inventory consumer contract",
            "fact-artifact-inventory-contract",
            "# fact-artifact-inventory-contract",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "comment-secure-compile",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "test-fact-artifact-inventory-consumers",
            "# test-fact-artifact-inventory-consumers",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "comment-secure-runtime",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "fact-artifact-inventory-consumer-wiring-self",
            "# fact-artifact-inventory-consumer-wiring-self",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "comment-sanitizer-compile",
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "Compile focused policy WRITE tests",
            "test-fact-artifact-inventory-consumers",
            "# test-fact-artifact-inventory-consumers",
            "E_INVENTORY_CI_SANITIZER",
        ),
    ):
        commented = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            commented[path] = replace_in_named_step(
                commented[path], job_start, job_end, step_name, old, new
            )
        mutations.append((label, commented, {expected}))

    windows_decoy = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        windows_decoy[path] = replace_in_named_step(
            windows_decoy[path],
            "  build-windows:",
            None,
            "Build and test (clang-cl)",
            "fact-artifact-namespace-windows-inventory",
            "disabled-fact-artifact-namespace-windows-inventory",
        )
        windows_decoy[path] = replace_in_named_step(
            windows_decoy[path],
            "  build-windows:",
            None,
            "Build and test (clang-cl)",
            "          '@",
            "          rem fact-artifact-namespace-windows-inventory\n          '@",
        )
    mutations.append(("windows-comment-decoy", windows_decoy, {"E_INVENTORY_CI_WINDOWS"}))

    windows_unsafe_rem = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        windows_unsafe_rem[path] = replace_in_named_step(
            windows_unsafe_rem[path],
            "  build-windows:",
            None,
            "Build and test (clang-cl)",
            '          if "${{ matrix.secure_bridge }}"=="enabled" (',
            '          rem advisory & exit /b 0\n'
            '          if "${{ matrix.secure_bridge }}"=="enabled" (',
        )
    mutations.append(
        ("windows-unsafe-rem", windows_unsafe_rem, {"E_INVENTORY_CI_WINDOWS"})
    )

    sanitizer_swallow = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        sanitizer_swallow[path] = replace_in_named_step(
            sanitizer_swallow[path],
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "Test focused policy WRITE paths",
            "            --print-errorlogs",
            "            --print-errorlogs || true",
        )
    mutations.append(
        ("sanitizer-failure-swallow", sanitizer_swallow, {"E_INVENTORY_CI_SANITIZER"})
    )

    windows_swallow = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        windows_swallow[path] = replace_in_named_step(
            windows_swallow[path],
            "  build-windows:",
            None,
            "Build and test (clang-cl)",
            "fact-artifact-main-transition --print-errorlogs",
            "fact-artifact-main-transition --print-errorlogs & exit /b 0",
        )
    mutations.append(
        ("windows-failure-swallow", windows_swallow, {"E_INVENTORY_CI_WINDOWS"})
    )

    windows_wrong_branch = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        windows_wrong_branch[path] = move_windows_inventory_command_to_else(
            windows_wrong_branch[path]
        )
    mutations.append(
        ("windows-wrong-branch", windows_wrong_branch, {"E_INVENTORY_CI_WINDOWS"})
    )

    for label, job_start, job_end, step_name, old, new, expected in (
        (
            "default-early-success",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Verify artifact inventory consumer contract",
            "          meson test -C builddir",
            "          exit 0\n          meson test -C builddir",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "secure-early-success",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "          /usr/bin/time",
            "          exit 0\n          /usr/bin/time",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "sanitizer-early-success",
            "  policy-write-focused-sanitizer:",
            "  daemon-http-shared-fact-audit-disabled:",
            "Test focused policy WRITE paths",
            "          meson test -C build-policy-write-sanitizer",
            "          exit 0\n          meson test -C build-policy-write-sanitizer",
            "E_INVENTORY_CI_SANITIZER",
        ),
        (
            "windows-early-success",
            "  build-windows:",
            None,
            "Build and test (clang-cl)",
            '          if "${{ matrix.secure_bridge }}"=="enabled" (',
            '          exit /b 0\n          if "${{ matrix.secure_bridge }}"=="enabled" (',
            "E_INVENTORY_CI_WINDOWS",
        ),
    ):
        early_success = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            early_success[path] = replace_in_named_step(
                early_success[path], job_start, job_end, step_name, old, new
            )
        mutations.append((label, early_success, {expected}))

    for label, job_start, job_end, step_name, old, new, expected in (
        (
            "secure-wrapped-success-exit",
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "          /usr/bin/time",
            "          if true; then exit 0; fi\n          /usr/bin/time",
            "E_INVENTORY_CI_POSIX",
        ),
        (
            "windows-wrapped-success-exit",
            "  build-windows:",
            None,
            "Build and test (clang-cl)",
            '          if "${{ matrix.secure_bridge }}"=="enabled" (',
            '          if 1==1 exit /b 0\n          if "${{ matrix.secure_bridge }}"=="enabled" (',
            "E_INVENTORY_CI_WINDOWS",
        ),
    ):
        wrapped_success = dict(inputs)
        for path in (CI_PR, CI_MAIN):
            wrapped_success[path] = replace_in_named_step(
                wrapped_success[path], job_start, job_end, step_name, old, new
            )
        mutations.append((label, wrapped_success, {expected}))

    secure_false_branch = dict(inputs)
    for path in (CI_PR, CI_MAIN):
        secure_false_branch[path] = replace_in_named_step(
            secure_false_branch[path],
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "          /usr/bin/time",
            "          if false; then\n          /usr/bin/time",
        )
        secure_false_branch[path] = replace_in_named_step(
            secure_false_branch[path],
            "  build-posix:",
            "  duckdb-linux-link-closure:",
            "Build secure DuckDB backend from pinned source",
            "            --print-errorlogs",
            "            --print-errorlogs\n          fi",
        )
    mutations.append(
        ("secure-false-wrapper", secure_false_branch, {"E_INVENTORY_CI_POSIX"})
    )

    parity = dict(inputs)
    parity[CI_PR] = replace_in_named_step(
        parity[CI_PR],
        "  build-posix:",
        "  duckdb-linux-link-closure:",
        "Build secure DuckDB backend from pinned source",
        "            --print-errorlogs",
        "            --print-errorlogs\n          echo fact-artifact-inventory-contract parity-probe",
    )
    mutations.append(
        (
            "pr-main-parity",
            parity,
            {"E_INVENTORY_CI_POSIX", "E_INVENTORY_CI_PARITY"},
        )
    )

    for label, mutated, expected in mutations:
        actual = diagnostic_codes(mutated)
        require(
            actual == expected,
            "E_SELF_TEST",
            f"mutation {label} produced {sorted(actual)}, expected {sorted(expected)}",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        inputs = load_inputs(args.root.resolve())
        if args.self_test:
            run_self_test(inputs)
        else:
            validate(inputs)
    except (ContractError, OSError, UnicodeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

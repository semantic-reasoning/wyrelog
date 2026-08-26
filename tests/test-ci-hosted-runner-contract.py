#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail closed when hosted-intended Actions jobs can run on self-hosted hosts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Callable


WORKFLOW_PATHS = (
    ".github/workflows/ci-pr.yml",
    ".github/workflows/ci-main.yml",
    ".github/workflows/actionlint.yml",
    ".github/workflows/codeql.yml",
)

CI_JOBS = (
    "format",
    "build-posix",
    "service-credential-e2e",
    "duckdb-checkpoint-seam",
    "daemon-http-shared-fact",
    "policy-write-focused-sanitizer",
    "daemon-http-shared-fact-audit-disabled",
    "build-windows",
)

EXPECTED_JOBS = {
    ".github/workflows/ci-pr.yml": CI_JOBS,
    ".github/workflows/ci-main.yml": CI_JOBS,
    ".github/workflows/actionlint.yml": ("actionlint",),
    ".github/workflows/codeql.yml": ("analyze",),
}

EXPECTED_TOP_LEVEL_KEYS = {
    ".github/workflows/ci-pr.yml": (
        "name", "on", "permissions", "concurrency", "env", "jobs"
    ),
    ".github/workflows/ci-main.yml": (
        "name", "on", "permissions", "concurrency", "env", "jobs"
    ),
    ".github/workflows/actionlint.yml": (
        "name", "on", "permissions", "concurrency", "jobs"
    ),
    ".github/workflows/codeql.yml": (
        "name", "on", "permissions", "concurrency", "env", "jobs"
    ),
}

EXPECTED_JOB_KEYS = {
    "format": ("name", "runs-on", "timeout-minutes", "steps"),
    "build-posix": (
        "name", "runs-on", "timeout-minutes", "env", "strategy", "steps"
    ),
    "service-credential-e2e": (
        "name", "runs-on", "timeout-minutes", "steps"
    ),
    "duckdb-checkpoint-seam": (
        "name", "runs-on", "timeout-minutes", "strategy", "steps"
    ),
    "daemon-http-shared-fact": (
        "name", "runs-on", "timeout-minutes", "strategy", "steps"
    ),
    "policy-write-focused-sanitizer": (
        "name", "runs-on", "timeout-minutes", "env", "steps"
    ),
    "daemon-http-shared-fact-audit-disabled": (
        "name", "runs-on", "timeout-minutes", "strategy", "steps"
    ),
    "build-windows": (
        "name", "runs-on", "timeout-minutes", "strategy", "env", "steps"
    ),
    "actionlint": ("name", "runs-on", "steps"),
    "analyze": ("name", "runs-on", "steps"),
}

EXPECTED_RUNS_ON = {
    "format": "ubuntu-latest",
    "build-posix": "${{ matrix.os }}",
    "service-credential-e2e": "ubuntu-latest",
    "duckdb-checkpoint-seam": "${{ matrix.os }}",
    "daemon-http-shared-fact": "${{ matrix.os }}",
    "policy-write-focused-sanitizer": "ubuntu-latest",
    "daemon-http-shared-fact-audit-disabled": "ubuntu-latest",
    "build-windows": "${{ matrix.runner }}",
    "actionlint": "ubuntu-latest",
    "analyze": "ubuntu-latest",
}

EXPECTED_WORKFLOW_ENV = {
    ".github/workflows/ci-pr.yml": (
        ("FORCE_JAVASCRIPT_ACTIONS_TO_NODE24", "true"),
    ),
    ".github/workflows/ci-main.yml": (
        ("FORCE_JAVASCRIPT_ACTIONS_TO_NODE24", "true"),
    ),
    ".github/workflows/actionlint.yml": (),
    ".github/workflows/codeql.yml": (
        ("FORCE_JAVASCRIPT_ACTIONS_TO_NODE24", "true"),
    ),
}

EXPECTED_JOB_ENV = {
    "build-posix": (
        ("SCCACHE_GHA_ENABLED", '"true"'),
        ("SCCACHE_BASEDIRS", "${{ github.workspace }}"),
    ),
    "policy-write-focused-sanitizer": (
        ("SCCACHE_GHA_ENABLED", '"true"'),
        ("SCCACHE_BASEDIRS", "${{ github.workspace }}"),
        (
            "ASAN_OPTIONS",
            "halt_on_error=1:abort_on_error=1:print_summary=1",
        ),
        (
            "UBSAN_OPTIONS",
            "halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1",
        ),
    ),
    "build-windows": (
        ("SCCACHE_GHA_ENABLED", '"true"'),
        ("SCCACHE_BASEDIRS", "${{ github.workspace }}"),
    ),
}

POSIX_GUARD = (
    "      - name: Verify GitHub-hosted runner contract\n"
    "        shell: bash\n"
    "        run: |\n"
    "          if [ \"${{ runner.environment }}\" != 'github-hosted' ]; then\n"
    "            echo '::error::this job requires a GitHub-hosted runner'\n"
    "            exit 1\n"
    "          fi\n"
)

WINDOWS_GUARD = (
    "      - name: Verify hosted Windows runner contract\n"
    "        shell: powershell\n"
    "        run: |\n"
    "          if ('${{ runner.environment }}' -ne 'github-hosted') {\n"
    "            throw 'the Windows matrix requires a GitHub-hosted runner'\n"
    "          }\n"
)

HOSTED_STATUS_PREFIX = (
    "${{ runner.environment == 'github-hosted' && ("
)
HOSTED_STATUS_SUFFIX = ") }}"
STATUS_FAILURE = HOSTED_STATUS_PREFIX + "failure()" + HOSTED_STATUS_SUFFIX
STATUS_ALWAYS = HOSTED_STATUS_PREFIX + "always()" + HOSTED_STATUS_SUFFIX
STATUS_ALWAYS_LINUX = (
    HOSTED_STATUS_PREFIX
    + "always() && runner.os == 'Linux'"
    + HOSTED_STATUS_SUFFIX
)
STATUS_AUDIT_CAPTURE = (
    HOSTED_STATUS_PREFIX
    + "always() && steps.compile_daemon_http.outcome == 'success'"
    + HOSTED_STATUS_SUFFIX
)
STATUS_APPVERIFIER_UPLOAD = (
    HOSTED_STATUS_PREFIX
    + "always() && matrix.secure_bridge == 'enabled'"
    + HOSTED_STATUS_SUFFIX
)
STATUS_NOT_CANCELLED = (
    HOSTED_STATUS_PREFIX + "!cancelled()" + HOSTED_STATUS_SUFFIX
)

COMMON_CI_STATUS_HANDLERS = {
    "build-posix": (
        ("Remove secure DuckDB compile swap", STATUS_ALWAYS_LINUX),
        ("Show sccache statistics", STATUS_ALWAYS),
        ("Upload meson logs on failure", STATUS_FAILURE),
    ),
    "service-credential-e2e": (
        ("Upload meson logs on failure", STATUS_FAILURE),
    ),
    "duckdb-checkpoint-seam": (
        ("Remove bounded Linux compile swap", STATUS_ALWAYS_LINUX),
        ("Upload seam meson logs on failure", STATUS_FAILURE),
    ),
    "daemon-http-shared-fact": (
        ("Upload daemon HTTP meson logs on failure", STATUS_FAILURE),
    ),
    "policy-write-focused-sanitizer": (
        ("Show sccache statistics", STATUS_ALWAYS),
        ("Upload policy WRITE sanitizer logs on failure", STATUS_FAILURE),
    ),
    "daemon-http-shared-fact-audit-disabled": (
        (
            "Upload audit-disabled daemon HTTP meson logs on failure",
            STATUS_FAILURE,
        ),
    ),
    "build-windows": (
        ("Upload Windows Application Verifier evidence", STATUS_APPVERIFIER_UPLOAD),
        ("Show sccache statistics", STATUS_NOT_CANCELLED),
        ("Upload meson logs on failure", STATUS_ALWAYS),
    ),
}

EXPECTED_STATUS_HANDLERS = {
    ".github/workflows/ci-pr.yml": {
        **COMMON_CI_STATUS_HANDLERS,
        "daemon-http-shared-fact": (
            ("Capture daemon HTTP audit provenance", STATUS_AUDIT_CAPTURE),
            ("Upload daemon HTTP meson logs on failure", STATUS_FAILURE),
        ),
    },
    ".github/workflows/ci-main.yml": COMMON_CI_STATUS_HANDLERS,
    ".github/workflows/actionlint.yml": {},
    ".github/workflows/codeql.yml": {},
}

# These exact action manifests were audited at the pinned commits. They are
# node24 actions with no runs.pre and no Docker or composite-action indirection.
CHECKOUT_ACTION = (
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
)
CACHE_ACTION = "actions/cache@caa296126883cff596d87d8935842f9db880ef25"
CACHE_RESTORE_ACTION = (
    "actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25"
)
CACHE_SAVE_ACTION = (
    "actions/cache/save@caa296126883cff596d87d8935842f9db880ef25"
)
UPLOAD_ACTION = (
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"
)
SCCACHE_ACTION = (
    "mozilla-actions/sccache-action@9e7fa8a12102821edf02ca5dbea1acd0f89a2696"
)
CODEQL_INIT_ACTION = (
    "github/codeql-action/init@db488ddef3bf6cb639b32c2e9a7c0a7ea8271d28"
)
CODEQL_ANALYZE_ACTION = (
    "github/codeql-action/analyze@db488ddef3bf6cb639b32c2e9a7c0a7ea8271d28"
)
CODEQL_UPLOAD_ACTION = (
    "github/codeql-action/upload-sarif@db488ddef3bf6cb639b32c2e9a7c0a7ea8271d28"
)


def actions(*entries: tuple[str, str]) -> tuple[tuple[str, str], ...]:
    return entries


COMMON_ACTIONS = {
    "format": actions(("Check out source", CHECKOUT_ACTION)),
    "service-credential-e2e": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Cache meson packagecache", CACHE_ACTION),
        ("Upload meson logs on failure", UPLOAD_ACTION),
    ),
    "daemon-http-shared-fact": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Restore meson packagecache", CACHE_RESTORE_ACTION),
        ("Upload daemon HTTP meson logs on failure", UPLOAD_ACTION),
    ),
    "policy-write-focused-sanitizer": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Restore meson packagecache", CACHE_RESTORE_ACTION),
        ("Set up sccache", SCCACHE_ACTION),
        ("Upload policy WRITE sanitizer logs on failure", UPLOAD_ACTION),
    ),
    "daemon-http-shared-fact-audit-disabled": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Restore meson packagecache", CACHE_RESTORE_ACTION),
        ("Upload audit-disabled daemon HTTP meson logs on failure", UPLOAD_ACTION),
    ),
}

PR_ACTIONS = {
    **COMMON_ACTIONS,
    "build-posix": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Restore meson packagecache", CACHE_RESTORE_ACTION),
        ("Set up sccache", SCCACHE_ACTION),
        ("Upload meson logs on failure", UPLOAD_ACTION),
    ),
    "duckdb-checkpoint-seam": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Restore meson packagecache", CACHE_RESTORE_ACTION),
        ("Upload seam meson logs on failure", UPLOAD_ACTION),
    ),
    "build-windows": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Set up sccache", SCCACHE_ACTION),
        ("Restore vcpkg binary packages", CACHE_RESTORE_ACTION),
        ("Restore vcpkg installed tree", CACHE_RESTORE_ACTION),
        ("Save vcpkg binary packages", CACHE_SAVE_ACTION),
        ("Save vcpkg installed tree", CACHE_SAVE_ACTION),
        ("Restore meson packagecache", CACHE_RESTORE_ACTION),
        ("Save meson packagecache", CACHE_SAVE_ACTION),
        ("Upload Windows Application Verifier evidence", UPLOAD_ACTION),
        ("Upload meson logs on failure", UPLOAD_ACTION),
    ),
}

MAIN_ACTIONS = {
    **COMMON_ACTIONS,
    "build-posix": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Cache meson packagecache", CACHE_ACTION),
        ("Set up sccache", SCCACHE_ACTION),
        ("Upload meson logs on failure", UPLOAD_ACTION),
    ),
    "duckdb-checkpoint-seam": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Cache meson packagecache", CACHE_ACTION),
        ("Upload seam meson logs on failure", UPLOAD_ACTION),
    ),
    "build-windows": actions(
        ("Check out source", CHECKOUT_ACTION),
        ("Set up sccache", SCCACHE_ACTION),
        ("Cache vcpkg binary packages", CACHE_ACTION),
        ("Restore vcpkg installed tree", CACHE_RESTORE_ACTION),
        ("Save vcpkg installed tree", CACHE_SAVE_ACTION),
        ("Cache meson packagecache", CACHE_ACTION),
        ("Upload Windows Application Verifier evidence", UPLOAD_ACTION),
        ("Upload meson logs on failure", UPLOAD_ACTION),
    ),
}

EXPECTED_ACTIONS = {
    ".github/workflows/ci-pr.yml": PR_ACTIONS,
    ".github/workflows/ci-main.yml": MAIN_ACTIONS,
    ".github/workflows/actionlint.yml": {
        "actionlint": actions(("Check out source", CHECKOUT_ACTION)),
    },
    ".github/workflows/codeql.yml": {
        "analyze": actions(
            ("Check out source", CHECKOUT_ACTION),
            ("Initialize CodeQL", CODEQL_INIT_ACTION),
            ("Perform CodeQL analysis", CODEQL_ANALYZE_ACTION),
            ("Upload CodeQL SARIF", CODEQL_UPLOAD_ACTION),
        ),
    },
}

ACTIONLINT_INSTALL = (
    "      - name: Lint workflow definitions\n"
    "        shell: bash\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    "          actionlint_version='1.7.12'\n"
    "          actionlint_archive=\"actionlint_${actionlint_version}_linux_amd64.tar.gz\"\n"
    "          actionlint_url=\"https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/${actionlint_archive}\"\n"
    "          actionlint_sha256='8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8'\n"
    "          actionlint_dir=\"$RUNNER_TEMP/actionlint-${actionlint_version}\"\n"
    "          mkdir -p \"$actionlint_dir\"\n"
    "          curl --fail --location --silent --show-error \\\n"
    "            --output \"$actionlint_dir/$actionlint_archive\" \"$actionlint_url\"\n"
    "          printf '%s  %s\\n' \"$actionlint_sha256\" \\\n"
    "            \"$actionlint_dir/$actionlint_archive\" | sha256sum --check -\n"
    "          tar -xzf \"$actionlint_dir/$actionlint_archive\" -C \"$actionlint_dir\"\n"
    "          \"$actionlint_dir/actionlint\" -color\n"
)

CANONICAL_STATUS_CONDITIONS = frozenset(
    condition
    for workflow in EXPECTED_STATUS_HANDLERS.values()
    for handlers in workflow.values()
    for _, condition in handlers
)

STATUS_FUNCTION = re.compile(
    r"(?<![A-Za-z0-9_])(success|failure|always|cancelled)\s*\(",
    re.IGNORECASE,
)
PLAIN_KEY = re.compile(r"([A-Za-z0-9_-]+):(?:\s*(.*))?$")
FLOW_SEQUENCE = re.compile(r"\[([^]]*)\]$")
PINNED_ACTION = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}"
)
BLOCK_SCALARS = ("|", "|-", "|+", ">", ">-", ">+")


class ContractError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code


def reject(code: str, detail: str) -> None:
    raise ContractError(code, detail)


@dataclass(frozen=True)
class Step:
    text: str
    keys: tuple[tuple[str, str], ...]

    def value(self, key: str) -> str | None:
        values = [value for candidate, value in self.keys if candidate == key]
        if len(values) > 1:
            reject("E_STEP_DUPLICATE_KEY", f"step repeats {key}")
        return values[0] if values else None


@dataclass(frozen=True)
class JobModel:
    name: str
    runs_on: str
    matrix: tuple[tuple[tuple[str, str], ...], ...]


def indentation(line: str) -> int:
    if "\t" in line[: len(line) - len(line.lstrip(" \t"))]:
        reject("E_YAML_INDENT", "tabs are forbidden in workflow indentation")
    return len(line) - len(line.lstrip(" "))


def mapping_key(line: str, indent: int, code: str) -> tuple[str, str]:
    if indentation(line) != indent:
        reject(code, f"expected {indent}-space mapping indentation: {line!r}")
    match = PLAIN_KEY.fullmatch(line[indent:])
    if match is None:
        reject(code, f"protected mapping key is not canonical plain YAML: {line!r}")
    key = match.group(1)
    value = match.group(2) or ""
    if (
        re.search(r"(^|[\s:\[,]?)(?:&|\*)[A-Za-z0-9_-]+(?:$|[\s,\]])", value)
        or "<<:" in value
        or "!!" in value
    ):
        reject("E_YAML_INDIRECTION", f"YAML indirection is forbidden: {line!r}")
    if value.startswith(("!", "&", "*", "{")) and not value.startswith("${{"):
        reject("E_YAML_INDIRECTION", f"unsupported protected YAML value: {line!r}")
    return key, value


def validate_inline_scalar(
    lines: list[str],
    index: int,
    end: int,
    indent: int,
    value: str,
    code: str,
    detail: str,
) -> None:
    if not value or value in BLOCK_SCALARS or re.search(r"\s#", value):
        reject(code, f"{detail} must be one complete inline scalar")
    for following in lines[index + 1 : end]:
        if not following.strip() or following.lstrip().startswith("#"):
            continue
        if indentation(following) > indent:
            reject(code, f"{detail} continues beyond its physical line")
        break


def top_level_keys(path: str, lines: list[str]) -> tuple[str, ...]:
    keys = []
    for index, line in enumerate(lines):
        if not line or line.lstrip().startswith("#"):
            continue
        if indentation(line) != 0:
            continue
        key, value = mapping_key(line, 0, "E_WORKFLOW_KEY_SYNTAX")
        if key == "name":
            validate_inline_scalar(
                lines,
                index,
                len(lines),
                0,
                value,
                "E_WORKFLOW_SCALAR_SPAN",
                f"{path} workflow name",
            )
        elif value:
            reject(
                "E_WORKFLOW_KEY_SYNTAX",
                f"{path} top-level {key} must be a block mapping",
            )
        keys.append(key)
    expected = EXPECTED_TOP_LEVEL_KEYS[path]
    if tuple(keys) != expected:
        reject("E_WORKFLOW_KEYS", f"{path} top-level keys {tuple(keys)!r} != {expected!r}")
    return tuple(keys)


def find_unique_line(lines: list[str], needle: str, code: str) -> int:
    matches = [index for index, line in enumerate(lines) if line == needle]
    if len(matches) != 1:
        reject(code, f"expected one {needle!r}, found {len(matches)}")
    return matches[0]


def child_mapping(
    lines: list[str],
    start: int,
    end: int,
    indent: int,
    code: str,
    scalar_code: str,
) -> tuple[tuple[str, str], ...]:
    values = []
    for index in range(start, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current_indent = indentation(line)
        if current_indent < indent:
            break
        if current_indent != indent:
            continue
        key, value = mapping_key(line, indent, code)
        if value:
            validate_inline_scalar(
                lines,
                index,
                end,
                indent,
                value,
                scalar_code,
                f"protected {key}",
            )
        values.append((key, value))
    return tuple(values)


def workflow_env(path: str, lines: list[str], jobs_start: int) -> None:
    env_lines = [index for index, line in enumerate(lines[:jobs_start]) if line == "env:"]
    expected = EXPECTED_WORKFLOW_ENV[path]
    if not expected:
        if env_lines:
            reject("E_WORKFLOW_ENV", f"{path} unexpectedly defines workflow env")
        return
    if len(env_lines) != 1:
        reject("E_WORKFLOW_ENV", f"{path} must define exactly one workflow env")
    actual = child_mapping(
        lines,
        env_lines[0] + 1,
        jobs_start,
        2,
        "E_WORKFLOW_ENV",
        "E_WORKFLOW_ENV_SCALAR_SPAN",
    )
    if actual != expected:
        reject("E_WORKFLOW_ENV", f"{path} workflow env {actual!r} != {expected!r}")


def job_blocks(path: str, lines: list[str]) -> tuple[tuple[str, int, int], ...]:
    jobs_start = find_unique_line(lines, "jobs:", "E_JOBS_MAPPING")
    starts = []
    for index in range(jobs_start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) == 0:
            reject("E_JOBS_MAPPING", f"{path} has a top-level key after jobs")
        if indentation(line) != 2:
            continue
        key, value = mapping_key(line, 2, "E_JOB_KEY_SYNTAX")
        if value:
            reject("E_JOB_KEY_SYNTAX", f"{path} job {key} must be a block mapping")
        starts.append((key, index))
    names = tuple(name for name, _ in starts)
    if names != EXPECTED_JOBS[path]:
        reject("E_JOB_INVENTORY", f"{path} jobs {names!r} != {EXPECTED_JOBS[path]!r}")
    blocks = []
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        blocks.append((name, start, end))
    workflow_env(path, lines, jobs_start)
    return tuple(blocks)


def job_fields(path: str, name: str, lines: list[str], start: int, end: int) -> dict[str, tuple[str, int]]:
    entries = []
    for index in range(start + 1, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) != 4:
            continue
        key, value = mapping_key(line, 4, "E_JOB_FIELD_SYNTAX")
        if value and key not in ("env", "strategy", "steps"):
            validate_inline_scalar(
                lines,
                index,
                end,
                4,
                value,
                "E_JOB_SCALAR_SPAN",
                f"{path}:{name} job field {key}",
            )
        entries.append((key, value, index))
    keys = tuple(key for key, _, _ in entries)
    expected = EXPECTED_JOB_KEYS[name]
    if keys != expected:
        reject("E_JOB_FIELDS", f"{path}:{name} fields {keys!r} != {expected!r}")
    return {key: (value, index) for key, value, index in entries}


def parse_flow_sequence(value: str, path: str, name: str) -> tuple[str, ...]:
    match = FLOW_SEQUENCE.fullmatch(value)
    if match is None:
        reject("E_MATRIX", f"{path}:{name} matrix flow sequence is not canonical")
    return tuple(item.strip() for item in match.group(1).split(","))


def parse_matrix(path: str, name: str, lines: list[str], strategy_start: int, steps_start: int) -> tuple[tuple[tuple[str, str], ...], ...]:
    strategy = child_mapping(
        lines,
        strategy_start + 1,
        steps_start,
        6,
        "E_STRATEGY",
        "E_STRATEGY_SCALAR_SPAN",
    )
    if tuple(key for key, _ in strategy) != ("fail-fast", "matrix"):
        reject("E_STRATEGY", f"{path}:{name} strategy keys drifted")
    if strategy[0][1] != "false" or strategy[1][1]:
        reject("E_STRATEGY", f"{path}:{name} strategy values drifted")
    matrix_start = find_unique_line(
        lines[strategy_start:steps_start], "      matrix:", "E_MATRIX"
    ) + strategy_start
    matrix_entries = child_mapping(
        lines,
        matrix_start + 1,
        steps_start,
        8,
        "E_MATRIX",
        "E_MATRIX_SCALAR_SPAN",
    )
    if len(matrix_entries) != 1:
        reject("E_MATRIX", f"{path}:{name} must have one matrix entry")
    matrix_key, matrix_value = matrix_entries[0]
    if matrix_key == "include":
        if matrix_value:
            reject("E_MATRIX", f"{path}:{name} include must be a block sequence")
        rows = []
        current = []
        for index in range(matrix_start + 1, steps_start):
            line = lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            current_indent = indentation(line)
            if current_indent == 10 and line[10:].startswith("- "):
                if current:
                    rows.append(tuple(current))
                field = mapping_key(" " * 12 + line[12:], 12, "E_MATRIX")
                validate_inline_scalar(
                    lines,
                    index,
                    steps_start,
                    12,
                    field[1],
                    "E_MATRIX_SCALAR_SPAN",
                    f"{path}:{name} matrix field {field[0]}",
                )
                current = [field]
            elif current_indent == 12 and current:
                field = mapping_key(line, 12, "E_MATRIX")
                validate_inline_scalar(
                    lines,
                    index,
                    steps_start,
                    12,
                    field[1],
                    "E_MATRIX_SCALAR_SPAN",
                    f"{path}:{name} matrix field {field[0]}",
                )
                current.append(field)
            elif current_indent >= 10:
                reject("E_MATRIX", f"{path}:{name} unsupported include syntax: {line!r}")
        if current:
            rows.append(tuple(current))
        return tuple(rows)
    values = parse_flow_sequence(matrix_value, path, name)
    return tuple((((matrix_key, value),)) for value in values)


def expected_matrix(path: str, name: str) -> tuple[tuple[tuple[str, str], ...], ...]:
    if name == "build-posix":
        rows = (
            (("os", "ubuntu-latest"), ("tpm", "enabled")),
            (("os", "macos-latest"), ("tpm", "disabled")),
        )
        if path.endswith("ci-main.yml"):
            rows = (
                rows[0] + (("duckdb", "prebuilt"),),
                rows[1] + (("duckdb", "subproject"),),
            )
        return rows
    if name in ("duckdb-checkpoint-seam", "daemon-http-shared-fact"):
        return ((("os", "ubuntu-latest"),), (("os", "macos-latest"),))
    if name == "daemon-http-shared-fact-audit-disabled":
        return ((("fact_store", "enabled"),), (("fact_store", "disabled"),))
    if name == "build-windows":
        return (
            (
                ("runner", "windows-2025"),
                ("fact_store", "disabled"),
                ("secure_bridge", "disabled"),
                ("duckdb_source", "prebuilt"),
                ("job_suffix", "''"),
            ),
            (
                ("runner", "windows-2025"),
                ("fact_store", "enabled"),
                ("secure_bridge", "disabled"),
                ("duckdb_source", "prebuilt"),
                ("job_suffix", "-fact"),
            ),
            (
                ("runner", "windows-2025"),
                ("fact_store", "enabled"),
                ("secure_bridge", "enabled"),
                ("duckdb_source", "subproject"),
                ("job_suffix", "-secure-bridge"),
            ),
        )
    return ()


def validate_nested_step_mapping(
    path: str,
    job: str,
    parent: str,
    lines: list[str],
    start: int,
    end: int,
) -> None:
    found = False
    block_indent: int | None = None
    for index in range(start, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current_indent = indentation(line)
        if block_indent is not None:
            if current_indent > block_indent:
                continue
            block_indent = None
        if current_indent != 10:
            reject(
                "E_STEP_NESTED_SCALAR_SPAN",
                f"{path}:{job} unsupported content below step {parent}",
            )
        key, value = mapping_key(line, 10, "E_STEP_MAPPING")
        found = True
        if value in BLOCK_SCALARS:
            if parent != "with":
                reject(
                    "E_STEP_NESTED_SCALAR_SPAN",
                    f"{path}:{job} step env {key} cannot use a block scalar",
                )
            block_indent = 10
            continue
        validate_inline_scalar(
            lines,
            index,
            end,
            10,
            value,
            "E_STEP_NESTED_SCALAR_SPAN",
            f"{path}:{job} step {parent}.{key}",
        )
    if not found:
        reject("E_STEP_MAPPING", f"{path}:{job} step {parent} mapping is empty")


def parse_step(path: str, job: str, lines: list[str], start: int, end: int) -> Step:
    first = lines[start][8:]
    if not first or first.startswith(("*", "&", "!", "<<:", "'", '"')):
        reject("E_STEP_MAPPING", f"{path}:{job} unsupported sequence item")
    entries = [(mapping_key(" " * 8 + first, 8, "E_STEP_MAPPING"), start)]
    for index in range(start + 1, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current_indent = indentation(line)
        if current_indent == 8:
            entries.append((mapping_key(line, 8, "E_STEP_MAPPING"), index))
        elif current_indent < 8:
            reject("E_STEP_MAPPING", f"{path}:{job} malformed step indentation")

    keys = [entry for entry, _ in entries]
    for position, ((key, value), index) in enumerate(entries):
        field_end = entries[position + 1][1] if position + 1 < len(entries) else end
        if value in BLOCK_SCALARS:
            if key != "run":
                reject(
                    "E_IF_SCALAR" if key == "if" else "E_STEP_SCALAR_SPAN",
                    f"{path}:{job} step {key} cannot use a block scalar",
                )
            continue
        if not value:
            if key not in ("with", "env"):
                reject(
                    "E_IF_SCALAR" if key == "if" else "E_STEP_SCALAR_SPAN",
                    f"{path}:{job} step {key} must have an inline value",
                )
            validate_nested_step_mapping(
                path, job, key, lines, index + 1, field_end
            )
            continue
        validate_inline_scalar(
            lines,
            index,
            field_end,
            8,
            value,
            "E_IF_SCALAR" if key == "if" else "E_STEP_SCALAR_SPAN",
            f"{path}:{job} step {key}",
        )
    names = tuple(key for key, _ in keys)
    if len(names) != len(set(names)):
        reject("E_STEP_DUPLICATE_KEY", f"{path}:{job} repeats a step key")
    allowed = {
        "name",
        "id",
        "if",
        "continue-on-error",
        "timeout-minutes",
        "shell",
        "run",
        "uses",
        "with",
        "env",
    }
    if not set(names) <= allowed:
        reject("E_STEP_FIELDS", f"{path}:{job} unsupported step keys {names!r}")
    step_lines = lines[start:end]
    while step_lines and (
        not step_lines[-1].strip() or step_lines[-1].lstrip().startswith("#")
    ):
        step_lines = step_lines[:-1]
    return Step("\n".join(step_lines) + "\n", tuple(keys))


def parse_steps(path: str, job: str, lines: list[str], steps_start: int, end: int) -> tuple[Step, ...]:
    starts = []
    for index in range(steps_start + 1, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) == 6:
            if not line.startswith("      - "):
                reject("E_STEP_MAPPING", f"{path}:{job} steps must be mappings")
            starts.append(index)
    if not starts:
        reject("E_STEP_INVENTORY", f"{path}:{job} has no steps")
    steps = []
    for position, start in enumerate(starts):
        step_end = starts[position + 1] if position + 1 < len(starts) else end
        steps.append(parse_step(path, job, lines, start, step_end))
    return tuple(steps)


def validate_guard(path: str, name: str, steps: tuple[Step, ...]) -> None:
    expected = WINDOWS_GUARD if name == "build-windows" else POSIX_GUARD
    if steps[0].text != expected:
        reject("E_FIRST_GUARD", f"{path}:{name} first step is not the exact hosted guard")
    checkout = [
        index for index, step in enumerate(steps)
        if (step.value("uses") or "").startswith("actions/checkout@")
    ]
    if len(checkout) != 1 or checkout[0] == 0:
        reject("E_CHECKOUT_ORDER", f"{path}:{name} checkout inventory/order drifted")


def validate_actions(path: str, name: str, steps: tuple[Step, ...]) -> None:
    actual = []
    for step in steps:
        action = step.value("uses")
        if action is None:
            continue
        if action.startswith(("docker://", "./", "../")):
            reject(
                "E_ACTION_KIND",
                f"{path}:{name} Docker and local actions are forbidden",
            )
        if PINNED_ACTION.fullmatch(action) is None:
            reject(
                "E_ACTION_PIN",
                f"{path}:{name} action is not pinned to a full commit SHA",
            )
        step_name = step.value("name")
        if step_name is None:
            reject("E_ACTION_INVENTORY", f"{path}:{name} action has no step name")
        actual.append((step_name, action))
    expected = EXPECTED_ACTIONS[path].get(name, ())
    if tuple(actual) != expected:
        reject(
            "E_ACTION_INVENTORY",
            f"{path}:{name} action inventory drifted",
        )
    if path == ".github/workflows/actionlint.yml" and name == "actionlint":
        if len(steps) < 3 or steps[2].text != ACTIONLINT_INSTALL:
            reject(
                "E_ACTIONLINT_INSTALL",
                "actionlint install/checksum/execution contract drifted",
            )


def validate_conditions(path: str, name: str, steps: tuple[Step, ...]) -> None:
    actual_status_handlers = []
    for step in steps:
        condition = step.value("if")
        if condition is None:
            continue
        if not condition or condition.startswith(("'", '"', "!", "&", "*", "|", ">")):
            reject("E_IF_SCALAR", f"{path}:{name} if must be one plain line")
        if "\\" in condition:
            reject("E_IF_SCALAR", f"{path}:{name} escaped if scalar is unsupported")
        if STATUS_FUNCTION.search(condition) is None:
            continue
        if condition not in CANONICAL_STATUS_CONDITIONS:
            reject(
                "E_STATUS_PREDICATE",
                f"{path}:{name} status condition is not an approved complete scalar",
            )
        step_name = step.value("name")
        if step_name is None:
            reject("E_STATUS_INVENTORY", f"{path}:{name} status handler has no name")
        actual_status_handlers.append((step_name, condition))
    expected = EXPECTED_STATUS_HANDLERS[path].get(name, ())
    if tuple(actual_status_handlers) != expected:
        reject(
            "E_STATUS_INVENTORY",
            f"{path}:{name} status handler inventory drifted",
        )


def validate_workflow(path: str, text: str) -> dict[str, JobModel]:
    if "\r" in text:
        reject("E_LINE_ENDING", f"{path} must use LF line endings")
    lines = text.splitlines()
    top_level_keys(path, lines)
    models = {}
    for name, start, end in job_blocks(path, lines):
        fields = job_fields(path, name, lines, start, end)
        runs_on = fields["runs-on"][0]
        for block_field in ("env", "strategy", "steps"):
            if block_field in fields and fields[block_field][0]:
                reject(
                    "E_JOB_FIELDS",
                    f"{path}:{name} {block_field} must be a block mapping",
                )
        env_expected = EXPECTED_JOB_ENV.get(name, ())
        if "env" in fields:
            env_start = fields["env"][1]
            env_actual = child_mapping(
                lines,
                env_start + 1,
                end,
                6,
                "E_JOB_ENV",
                "E_JOB_ENV_SCALAR_SPAN",
            )
            if env_actual != env_expected:
                reject("E_JOB_ENV", f"{path}:{name} job env drifted")
        elif env_expected:
            reject("E_JOB_ENV", f"{path}:{name} lost its frozen job env")
        matrix = ()
        if "strategy" in fields:
            matrix = parse_matrix(
                path, name, lines, fields["strategy"][1], fields["steps"][1]
            )
        steps = parse_steps(path, name, lines, fields["steps"][1], end)
        validate_guard(path, name, steps)
        validate_actions(path, name, steps)
        validate_conditions(path, name, steps)
        models[name] = JobModel(name, runs_on, matrix)
    return models


def validate_expected_profiles(path: str, models: dict[str, JobModel]) -> None:
    for name, model in models.items():
        if model.runs_on != EXPECTED_RUNS_ON[name]:
            reject("E_RUNS_ON", f"{path}:{name} runs-on drifted")
        expected = expected_matrix(path, name)
        if model.matrix != expected:
            reject("E_MATRIX", f"{path}:{name} matrix {model.matrix!r} drifted")


def parity_projection(model: dict[str, JobModel]) -> tuple[tuple[str, str, tuple], ...]:
    projection = []
    for name in CI_JOBS:
        job = model[name]
        matrix = job.matrix
        if name == "build-posix":
            matrix = tuple(tuple(field for field in row if field[0] != "duckdb") for row in matrix)
        projection.append((name, job.runs_on, matrix))
    return tuple(projection)


def validate_texts(texts: dict[str, str]) -> None:
    if tuple(texts) != WORKFLOW_PATHS:
        reject("E_WORKFLOW_INVENTORY", "workflow inventory/order drifted")
    models = {path: validate_workflow(path, texts[path]) for path in WORKFLOW_PATHS}
    if parity_projection(models[WORKFLOW_PATHS[0]]) != parity_projection(
        models[WORKFLOW_PATHS[1]]
    ):
        reject("E_PR_MAIN_PARITY", "PR/main hosted runner profiles drifted")
    for path in WORKFLOW_PATHS:
        validate_expected_profiles(path, models[path])


def read_texts(root: Path) -> dict[str, str]:
    texts = {}
    for path in WORKFLOW_PATHS:
        try:
            texts[path] = (root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            reject("E_WORKFLOW_READ", f"cannot read {path}: {error}")
    return texts


def replace_once(text: str, old: str, new: str) -> str:
    if old not in text:
        raise AssertionError(f"self-test mutation anchor is missing: {old!r}")
    return text.replace(old, new, 1)


def mutate(path: str, transform: Callable[[str], str]) -> Callable[[dict[str, str]], dict[str, str]]:
    def apply(texts: dict[str, str]) -> dict[str, str]:
        changed = dict(texts)
        changed[path] = transform(changed[path])
        return changed
    return apply


def mutate_pair(
    first: str, second: str, transform: Callable[[str], str]
) -> Callable[[dict[str, str]], dict[str, str]]:
    def apply(texts: dict[str, str]) -> dict[str, str]:
        changed = dict(texts)
        changed[first] = transform(changed[first])
        changed[second] = transform(changed[second])
        return changed

    return apply


def expect_failure(name: str, texts: dict[str, str], code: str) -> None:
    try:
        validate_texts(texts)
    except ContractError as error:
        if error.code != code:
            raise SystemExit(
                f"self-test {name} expected {code}, got {error}"
            ) from error
    else:
        raise SystemExit(f"self-test {name} unexpectedly passed")


def run_self_test(root: Path) -> None:
    baseline = read_texts(root)
    validate_texts(baseline)

    pr = WORKFLOW_PATHS[0]
    main = WORKFLOW_PATHS[1]
    actionlint = WORKFLOW_PATHS[2]
    codeql = WORKFLOW_PATHS[3]
    hosted_failure = (
        "        if: ${{ runner.environment == 'github-hosted' && (failure()) }}"
    )
    linux_if = "        if: runner.os == 'Linux'"
    status_breakouts = (
        (
            "compact-or-always",
            "${{ runner.environment == 'github-hosted' && "
            "(failure())||always()&&(true) }}",
        ),
        (
            "or-success",
            "${{ runner.environment == 'github-hosted' && "
            "(failure()) || success() && (true) }}",
        ),
        (
            "or-failure",
            "${{ runner.environment == 'github-hosted' && "
            "(failure()) || failure() && (true) }}",
        ),
        (
            "or-not-cancelled",
            "${{ runner.environment == 'github-hosted' && "
            "(failure()) || !cancelled() }}",
        ),
        (
            "or-contains",
            "${{ runner.environment == 'github-hosted' && "
            "(failure()) || contains('x', 'x') }}",
        ),
        (
            "external-and",
            "${{ runner.environment == 'github-hosted' && "
            "(failure()) && true && (true) }}",
        ),
        (
            "noncanonical-inner",
            "${{ runner.environment == 'github-hosted' && "
            "(failure() && true) }}",
        ),
        (
            "surplus-parenthesis",
            "${{ runner.environment == 'github-hosted' && "
            "((failure())) }}",
        ),
        (
            "alternate-quote",
            '${{ runner.environment == "github-hosted" && (failure()) }}',
        ),
    )

    cases = (
        (
            "missing-guard",
            mutate(pr, lambda text: replace_once(text, POSIX_GUARD + "\n", "")),
            "E_FIRST_GUARD",
        ),
        (
            "late-guard",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    POSIX_GUARD + "\n      - name: Check out source\n",
                    "      - name: Check out source\n"
                    + POSIX_GUARD.replace("      - name:", "\n      - name:", 1),
                ),
            ),
            "E_FIRST_GUARD",
        ),
        (
            "weakened-guard",
            mutate(
                codeql,
                lambda text: replace_once(
                    text,
                    " != 'github-hosted'",
                    " != 'github-hosted' && \"${{ runner.environment }}\" != 'self-hosted'",
                ),
            ),
            "E_FIRST_GUARD",
        ),
        (
            "leaky-guard",
            mutate(
                main,
                lambda text: replace_once(
                    text,
                    "this job requires a GitHub-hosted runner",
                    "runner $RUNNER_NAME requires a GitHub-hosted runner",
                ),
            ),
            "E_FIRST_GUARD",
        ),
        *(
            (
                f"ungated-{label}",
                mutate(
                    pr,
                    lambda text, condition=condition: replace_once(
                        text, linux_if, f"        if: {condition}"
                    ),
                ),
                "E_STATUS_PREDICATE",
            )
            for label, condition in (
                ("success", "success()"),
                ("not-success", "${{ !success() }}"),
                ("failure", "failure()"),
                ("uppercase-failure", "Failure()"),
                ("always", "always()"),
                ("cancelled", "cancelled()"),
                ("not-cancelled", "${{ !cancelled() }}"),
                ("or-true", "success() || true"),
            )
        ),
        (
            "multiline-condition",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    hosted_failure,
                    "        if: >\n"
                    "          ${{ runner.environment == 'github-hosted' &&\n"
                    "          (failure()) }}",
                ),
            ),
            "E_IF_SCALAR",
        ),
        (
            "multiline-plain-condition",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    hosted_failure,
                    "        if: ${{\n          failure() }}",
                ),
            ),
            "E_IF_SCALAR",
        ),
        (
            "multiline-first-key-condition",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      - name: Install build dependencies (Linux)\n"
                    + linux_if
                    + "\n",
                    "      - if: ${{\n"
                    "          failure() }}\n"
                    "        name: Install build dependencies (Linux)\n",
                ),
            ),
            "E_IF_SCALAR",
        ),
        (
            "multiline-hosted-predicate",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    hosted_failure,
                    "        if: ${{ runner.environment ==\n"
                    "          'github-hosted' && (failure()) }}",
                ),
            ),
            "E_IF_SCALAR",
        ),
        (
            "multiline-status-introduction",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    linux_if,
                    "        if: runner.os ==\n"
                    "          'Linux' && failure()",
                ),
            ),
            "E_IF_SCALAR",
        ),
        (
            "multiline-comment-gap",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    hosted_failure,
                    "        if: ${{\n"
                    "          # a comment cannot hide scalar continuation\n"
                    "          failure() }}",
                ),
            ),
            "E_IF_SCALAR",
        ),
        (
            "multiline-extra-scalar-line",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    hosted_failure,
                    hosted_failure + "\n          || true",
                ),
            ),
            "E_IF_SCALAR",
        ),
        *(
            (
                f"block-condition-{indicator.replace('|', 'literal').replace('>', 'folded').replace('+', 'keep').replace('-', 'strip')}",
                mutate(
                    pr,
                    lambda text, indicator=indicator: replace_once(
                        text,
                        hosted_failure,
                        f"        if: {indicator}\n"
                        "          ${{ runner.environment == 'github-hosted' "
                        "&& (failure()) }}",
                    ),
                ),
                "E_IF_SCALAR",
            )
            for indicator in (">-", ">+", "|", "|-", "|+")
        ),
        (
            "tagged-condition",
            mutate(
                pr,
                lambda text: replace_once(text, hosted_failure, "        if: !unsafe failure()"),
            ),
            "E_YAML_INDIRECTION",
        ),
        (
            "quoted-condition",
            mutate(
                pr,
                lambda text: replace_once(
                    text, hosted_failure, '        if: "${{ failure() }}"'
                ),
            ),
            "E_IF_SCALAR",
        ),
        (
            "wrapped-or-true-condition",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    hosted_failure,
                    "        if: ${{ runner.environment == 'github-hosted' "
                    "&& (failure() || true) }}",
                ),
            ),
            "E_STATUS_PREDICATE",
        ),
        (
            "hosted-group-breakout",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    hosted_failure,
                    "        if: ${{ runner.environment == 'github-hosted' "
                    "&& (failure()) || always() && (true) }}",
                ),
            ),
            "E_STATUS_PREDICATE",
        ),
        *(
            (
                f"status-breakout-{label}",
                mutate(
                    pr,
                    lambda text, condition=condition: replace_once(
                        text, hosted_failure, f"        if: {condition}"
                    ),
                ),
                "E_STATUS_PREDICATE",
            )
            for label, condition in status_breakouts
        ),
        (
            "missing-status-handler",
            mutate(pr, lambda text: replace_once(text, hosted_failure + "\n", "")),
            "E_STATUS_INVENTORY",
        ),
        (
            "additional-status-handler",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    POSIX_GUARD + "\n",
                    POSIX_GUARD
                    + "\n      - name: Additional status handler\n"
                    + f"        if: {STATUS_FAILURE}\n"
                    + "        run: echo guarded\n\n",
                ),
            ),
            "E_STATUS_INVENTORY",
        ),
        (
            "one-sided-status-condition-drift",
            mutate(
                main,
                lambda text: replace_once(
                    text,
                    f"        if: {STATUS_ALWAYS_LINUX}\n",
                    f"        if: {STATUS_ALWAYS}\n",
                ),
            ),
            "E_STATUS_INVENTORY",
        ),
        (
            "status-handler-name-drift",
            mutate(
                main,
                lambda text: replace_once(
                    text,
                    "      - name: Remove secure DuckDB compile swap\n",
                    "      - name: Renamed secure DuckDB cleanup\n",
                ),
            ),
            "E_STATUS_INVENTORY",
        ),
        (
            "folded-status-handler-name",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      - name: Upload meson logs on failure\n"
                    + hosted_failure
                    + "\n",
                    "      - name: Upload meson logs on failure\n"
                    "          renamed in YAML\n"
                    + hosted_failure
                    + "\n",
                ),
            ),
            "E_STEP_SCALAR_SPAN",
        ),
        (
            "folded-workflow-env",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n",
                    "  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n"
                    "    false\n",
                ),
            ),
            "E_WORKFLOW_ENV_SCALAR_SPAN",
        ),
        (
            "folded-workflow-name",
            mutate(
                pr,
                lambda text: replace_once(
                    text, "name: CI PR\n", "name: CI PR\n  renamed in YAML\n"
                ),
            ),
            "E_WORKFLOW_SCALAR_SPAN",
        ),
        (
            "folded-job-name",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "    name: format\n",
                    "    name: format\n      renamed in YAML\n",
                ),
            ),
            "E_JOB_SCALAR_SPAN",
        ),
        (
            "folded-job-runs-on-after-comment",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "    runs-on: ubuntu-latest\n",
                    "    runs-on: ubuntu-latest\n"
                    "      # comments do not terminate a plain scalar\n"
                    "      self-hosted\n",
                ),
            ),
            "E_JOB_SCALAR_SPAN",
        ),
        (
            "folded-job-timeout",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "    timeout-minutes: 10\n",
                    "    timeout-minutes: 10\n      90\n",
                ),
            ),
            "E_JOB_SCALAR_SPAN",
        ),
        (
            "folded-job-env",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    '      SCCACHE_GHA_ENABLED: "true"\n',
                    '      SCCACHE_GHA_ENABLED: "true"\n        false\n',
                ),
            ),
            "E_JOB_ENV_SCALAR_SPAN",
        ),
        (
            "folded-strategy",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      fail-fast: false\n",
                    "      fail-fast: false\n        true\n",
                ),
            ),
            "E_STRATEGY_SCALAR_SPAN",
        ),
        (
            "folded-flow-matrix",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "        os: [ubuntu-latest, macos-latest]\n",
                    "        os: [ubuntu-latest, macos-latest]\n"
                    "          self-hosted\n",
                ),
            ),
            "E_MATRIX_SCALAR_SPAN",
        ),
        (
            "folded-include-first-field",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "          - os: ubuntu-latest\n",
                    "          - os: ubuntu-latest\n              self-hosted\n",
                ),
            ),
            "E_MATRIX_SCALAR_SPAN",
        ),
        (
            "folded-include-later-field",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "            tpm: enabled\n",
                    "            tpm: enabled\n              disabled\n",
                ),
            ),
            "E_MATRIX_SCALAR_SPAN",
        ),
        *(
            (
                f"folded-step-{field}",
                mutate(
                    pr,
                    lambda text, field=field, value=value: replace_once(
                        text,
                        f"        {field}: {value}\n",
                        f"        {field}: {value}\n          continued\n",
                    ),
                ),
                "E_STEP_SCALAR_SPAN",
            )
            for field, value in (
                ("id", "sccache"),
                ("uses", "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"),
                ("shell", "bash"),
                ("timeout-minutes", "6"),
                ("continue-on-error", "true"),
            )
        ),
        (
            "folded-step-with-value",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "          fetch-depth: 0\n",
                    "          fetch-depth: 0\n            1\n",
                ),
            ),
            "E_STEP_NESTED_SCALAR_SPAN",
        ),
        (
            "folded-step-env-value",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "          HOMEBREW_NO_REQUIRE_TAP_TRUST: 1\n",
                    "          HOMEBREW_NO_REQUIRE_TAP_TRUST: 1\n            0\n",
                ),
            ),
            "E_STEP_NESTED_SCALAR_SPAN",
        ),
        (
            "inline-comment-job-scalar",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "    timeout-minutes: 10\n",
                    "    timeout-minutes: 10 # mutable\n",
                ),
            ),
            "E_JOB_SCALAR_SPAN",
        ),
        (
            "block-job-scalar",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "    runs-on: ubuntu-latest\n",
                    "    runs-on: >\n      ubuntu-latest\n",
                ),
            ),
            "E_JOB_SCALAR_SPAN",
        ),
        (
            "block-step-name",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      - name: Check out source\n",
                    "      - name: >\n          Check out source\n",
                ),
            ),
            "E_STEP_SCALAR_SPAN",
        ),
        (
            "block-step-env-value",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "          HOMEBREW_NO_REQUIRE_TAP_TRUST: 1\n",
                    "          HOMEBREW_NO_REQUIRE_TAP_TRUST: >\n"
                    "            1\n",
                ),
            ),
            "E_STEP_NESTED_SCALAR_SPAN",
        ),
        (
            "docker-actionlint",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    ACTIONLINT_INSTALL,
                    "      - name: Lint workflow definitions\n"
                    "        uses: docker://rhysd/actionlint:1.7.12\n",
                ),
            ),
            "E_ACTION_KIND",
        ),
        (
            "synthetic-pre-capable-action",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    f"        uses: {CHECKOUT_ACTION}\n",
                    f"        uses: {CHECKOUT_ACTION}\n\n"
                    "      - name: Synthetic pre-capable action\n"
                    "        if: false\n"
                    "        uses: example/pre-action@"
                    "0000000000000000000000000000000000000000\n",
                ),
            ),
            "E_ACTION_INVENTORY",
        ),
        (
            "local-action",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    f"        uses: {CHECKOUT_ACTION}\n",
                    f"        uses: {CHECKOUT_ACTION}\n\n"
                    "      - name: Local composite action\n"
                    "        uses: ./.github/actions/unsafe\n",
                ),
            ),
            "E_ACTION_KIND",
        ),
        (
            "mutable-action-tag",
            mutate(
                pr,
                lambda text: replace_once(text, CHECKOUT_ACTION, "actions/checkout@v5"),
            ),
            "E_ACTION_PIN",
        ),
        (
            "short-action-sha",
            mutate(
                pr,
                lambda text: replace_once(
                    text, CHECKOUT_ACTION, "actions/checkout@fbc6f39"
                ),
            ),
            "E_ACTION_PIN",
        ),
        (
            "expression-action-ref",
            mutate(
                pr,
                lambda text: replace_once(
                    text, CHECKOUT_ACTION, "actions/checkout@${{ github.sha }}"
                ),
            ),
            "E_ACTION_PIN",
        ),
        (
            "wrong-action-sha",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    CACHE_RESTORE_ACTION,
                    "actions/cache/restore@0000000000000000000000000000000000000000",
                ),
            ),
            "E_ACTION_INVENTORY",
        ),
        (
            "wrong-action-subpath",
            mutate(
                pr,
                lambda text: replace_once(
                    text, CACHE_RESTORE_ACTION, CACHE_SAVE_ACTION
                ),
            ),
            "E_ACTION_INVENTORY",
        ),
        (
            "approved-action-in-wrong-job",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    f"        uses: {CHECKOUT_ACTION}\n",
                    f"        uses: {CHECKOUT_ACTION}\n\n"
                    "      - name: Unexpected cache action\n"
                    f"        uses: {CACHE_RESTORE_ACTION}\n",
                ),
            ),
            "E_ACTION_INVENTORY",
        ),
        (
            "action-step-name-drift",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      - name: Restore meson packagecache\n",
                    "      - name: Restore packagecache elsewhere\n",
                ),
            ),
            "E_ACTION_INVENTORY",
        ),
        (
            "actionlint-digest-drift",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
            ),
            "E_ACTIONLINT_INSTALL",
        ),
        (
            "actionlint-latest-url",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    "releases/download/v${actionlint_version}",
                    "releases/latest/download",
                ),
            ),
            "E_ACTIONLINT_INSTALL",
        ),
        (
            "actionlint-extract-before-verify",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    "          printf '%s  %s\\n' \"$actionlint_sha256\" \\\n"
                    "            \"$actionlint_dir/$actionlint_archive\" | sha256sum --check -\n"
                    "          tar -xzf \"$actionlint_dir/$actionlint_archive\" -C \"$actionlint_dir\"\n",
                    "          tar -xzf \"$actionlint_dir/$actionlint_archive\" -C \"$actionlint_dir\"\n"
                    "          printf '%s  %s\\n' \"$actionlint_sha256\" \\\n"
                    "            \"$actionlint_dir/$actionlint_archive\" | sha256sum --check -\n",
                ),
            ),
            "E_ACTIONLINT_INSTALL",
        ),
        (
            "actionlint-curl-pipe-shell",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text,
                    "          curl --fail --location --silent --show-error \\\n"
                    "            --output \"$actionlint_dir/$actionlint_archive\" \"$actionlint_url\"\n",
                    "          curl --fail --location \"$actionlint_url\" | sh\n",
                ),
            ),
            "E_ACTIONLINT_INSTALL",
        ),
        (
            "first-key-condition",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      - name: Install build dependencies (Linux)\n"
                    + linux_if
                    + "\n",
                    "      - if: failure()\n"
                    "        name: Install build dependencies (Linux)\n",
                ),
            ),
            "E_STATUS_PREDICATE",
        ),
        (
            "quoted-job-key",
            mutate(pr, lambda text: replace_once(text, "  format:\n", "  'format':\n")),
            "E_JOB_KEY_SYNTAX",
        ),
        (
            "escaped-job-key",
            mutate(pr, lambda text: replace_once(text, "  format:\n", "  for\\mat:\n")),
            "E_JOB_KEY_SYNTAX",
        ),
        (
            "quoted-workflow-key",
            mutate(pr, lambda text: replace_once(text, "name: CI PR\n", "'name': CI PR\n")),
            "E_WORKFLOW_KEY_SYNTAX",
        ),
        (
            "explicit-workflow-key",
            mutate(pr, lambda text: replace_once(text, "name: CI PR\n", "? name\n: CI PR\n")),
            "E_WORKFLOW_KEY_SYNTAX",
        ),
        (
            "tagged-workflow-value",
            mutate(pr, lambda text: replace_once(text, "name: CI PR\n", "name: !unsafe CI PR\n")),
            "E_YAML_INDIRECTION",
        ),
        (
            "anchored-job",
            mutate(pr, lambda text: replace_once(text, "  format:\n", "  format: &shared\n")),
            "E_YAML_INDIRECTION",
        ),
        (
            "unknown-job",
            mutate(pr, lambda text: text + "\n  surprise:\n    runs-on: ubuntu-latest\n"),
            "E_JOB_INVENTORY",
        ),
        (
            "step-merge-alias",
            mutate(
                pr,
                lambda text: replace_once(
                    text, POSIX_GUARD, POSIX_GUARD + "\n      - <<: *shared\n"
                ),
            ),
            "E_STEP_MAPPING",
        ),
        (
            "quoted-step-key",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      - name: Check out source\n",
                    "      - 'name': Check out source\n",
                ),
            ),
            "E_STEP_MAPPING",
        ),
        (
            "tagged-step-item",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      - name: Check out source\n",
                    "      - !unsafe\n        name: Check out source\n",
                ),
            ),
            "E_STEP_MAPPING",
        ),
        *(
            (
                f"job-{field}",
                mutate(
                    pr,
                    lambda text, field=field: replace_once(
                        text,
                        "    runs-on: ubuntu-latest\n",
                        f"    runs-on: ubuntu-latest\n    {field}: unsafe\n",
                    ),
                ),
                "E_JOB_FIELDS",
            )
            for field in ("container", "services", "defaults", "continue-on-error", "uses")
        ),
        (
            "workflow-defaults",
            mutate(
                actionlint,
                lambda text: replace_once(text, "jobs:\n", "defaults:\n  run:\n    shell: bash\n\njobs:\n"),
            ),
            "E_WORKFLOW_KEYS",
        ),
        (
            "flow-default-alias",
            mutate(
                actionlint,
                lambda text: replace_once(
                    text, "jobs:\n", "defaults: {run: *unsafe}\n\njobs:\n"
                ),
            ),
            "E_YAML_INDIRECTION",
        ),
        (
            "workflow-env-drift",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n",
                    "  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true\n"
                    "  PATH: /tmp/unsafe\n",
                ),
            ),
            "E_WORKFLOW_ENV",
        ),
        (
            "job-env-drift",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    '      SCCACHE_GHA_ENABLED: "true"\n',
                    '      SCCACHE_GHA_ENABLED: "true"\n'
                    "      BASH_ENV: /tmp/unsafe\n",
                ),
            ),
            "E_JOB_ENV",
        ),
        (
            "flow-steps-value",
            mutate(pr, lambda text: replace_once(text, "    steps:\n", "    steps: []\n")),
            "E_JOB_FIELDS",
        ),
        (
            "crlf-workflow",
            mutate(actionlint, lambda text: text.replace("\n", "\r\n")),
            "E_LINE_ENDING",
        ),
        (
            "matrix-exclude",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "      matrix:\n        include:\n",
                    "      matrix:\n        exclude: [unsafe]\n        include:\n",
                ),
            ),
            "E_MATRIX",
        ),
        (
            "one-sided-matrix-tpm-drift",
            mutate(
                pr,
                lambda text: replace_once(text, "            tpm: enabled\n", "            tpm: disabled\n"),
            ),
            "E_PR_MAIN_PARITY",
        ),
        (
            "matrix-extra-include-key",
            mutate(
                pr,
                lambda text: replace_once(
                    text,
                    "            tpm: enabled\n",
                    "            tpm: enabled\n            extra: unsafe\n",
                ),
            ),
            "E_PR_MAIN_PARITY",
        ),
        (
            "windows-row-drift",
            mutate(
                main,
                lambda text: replace_once(
                    text, "          - runner: windows-2025\n", "          - runner: windows-latest\n"
                ),
            ),
            "E_PR_MAIN_PARITY",
        ),
        (
            "missing-windows-row",
            mutate(
                main,
                lambda text: replace_once(
                    text,
                    "          - runner: windows-2025\n"
                    "            fact_store: disabled\n"
                    "            secure_bridge: disabled\n"
                    "            duckdb_source: prebuilt\n"
                    "            job_suffix: ''\n",
                    "",
                ),
            ),
            "E_PR_MAIN_PARITY",
        ),
        (
            "main-duckdb-matrix-drift",
            mutate(
                main,
                lambda text: replace_once(
                    text,
                    "            duckdb: prebuilt\n",
                    "            duckdb: subproject\n",
                ),
            ),
            "E_MATRIX",
        ),
        (
            "coordinated-windows-row-drift",
            mutate_pair(
                pr,
                main,
                lambda text: replace_once(
                    text,
                    "          - runner: windows-2025\n",
                    "          - runner: windows-latest\n",
                ),
            ),
            "E_MATRIX",
        ),
        (
            "missing-actionlint-job",
            mutate(actionlint, lambda text: text[: text.index("  actionlint:\n")]),
            "E_JOB_INVENTORY",
        ),
        (
            "missing-codeql-job",
            mutate(codeql, lambda text: text[: text.index("  analyze:\n")]),
            "E_JOB_INVENTORY",
        ),
        (
            "weakened-windows-guard",
            mutate(
                main,
                lambda text: replace_once(text, " -ne 'github-hosted'", " -eq 'github-hosted'"),
            ),
            "E_FIRST_GUARD",
        ),
        (
            "one-sided-pr-main-drift",
            mutate(
                main,
                lambda text: replace_once(
                    text,
                    "    runs-on: ${{ matrix.os }}\n",
                    "    runs-on: ubuntu-latest\n",
                ),
            ),
            "E_PR_MAIN_PARITY",
        ),
    )

    for name, transform, code in cases:
        expect_failure(name, transform(baseline), code)

    positive = dict(baseline)
    positive[actionlint] = replace_once(
        positive[actionlint],
        POSIX_GUARD + "\n      - name: Check out source",
        POSIX_GUARD
        + "\n      # Comments are non-executable metadata; checkout may follow later.\n"
        + "      - name: Check out source",
    )
    validate_texts(positive)

    positive_first_key = dict(baseline)
    positive_first_key[pr] = replace_once(
        positive_first_key[pr],
        "      - name: Upload meson logs on failure\n"
        + hosted_failure
        + "\n",
        f"      - if: {STATUS_FAILURE}\n"
        "        name: Upload meson logs on failure\n",
    )
    validate_texts(positive_first_key)

    positive_condition_comment = dict(baseline)
    positive_condition_comment[pr] = replace_once(
        positive_condition_comment[pr],
        hosted_failure
        + "\n        # actions/upload-artifact v6\n"
        + f"        uses: {UPLOAD_ACTION}",
        hosted_failure
        + "\n        # Standalone comments do not continue the if scalar.\n"
        + "        # actions/upload-artifact v6\n"
        + f"        uses: {UPLOAD_ACTION}",
    )
    validate_texts(positive_condition_comment)

    positive_run_block = dict(baseline)
    positive_run_block[codeql] = replace_once(
        positive_run_block[codeql],
        "        run: meson compile -C builddir",
        "        run: |\n"
        "          echo 'if: failure()' >/dev/null\n"
        "          echo 'uses: docker://not-an-action' >/dev/null\n"
        "          echo 'uses: ./not-an-action' >/dev/null\n"
        "          meson compile -C builddir",
    )
    validate_texts(positive_run_block)

    positive_nested_block = dict(baseline)
    positive_nested_block[pr] = replace_once(
        positive_nested_block[pr],
        "          path: builddir/meson-logs/\n",
        "          path: |\n"
        "            builddir/meson-logs/\n"
        "            if: failure()\n",
    )
    validate_texts(positive_nested_block)

    positive_scalar_comment = dict(baseline)
    positive_scalar_comment[pr] = replace_once(
        positive_scalar_comment[pr],
        "    name: format\n    runs-on: ubuntu-latest\n",
        "    name: format\n"
        "      # A standalone comment is not a scalar continuation.\n"
        "    runs-on: ubuntu-latest\n",
    )
    validate_texts(positive_scalar_comment)

    positive_post_guard_run = dict(baseline)
    positive_post_guard_run[actionlint] = replace_once(
        positive_post_guard_run[actionlint],
        ACTIONLINT_INSTALL,
        ACTIONLINT_INSTALL
        + "\n      - name: Safe shell-only post-guard work\n"
        + "        run: echo safe\n",
    )
    validate_texts(positive_post_guard_run)
    print(f"CI hosted-runner contract self-test: {len(cases)} negative controls OK")


def usage() -> None:
    raise SystemExit(f"usage: {Path(sys.argv[0]).name} [--self-test] SOURCE_ROOT")


def main() -> None:
    if len(sys.argv) == 2:
        root = Path(sys.argv[1])
        validate_texts(read_texts(root))
        print("CI hosted-runner contract: OK")
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--self-test":
        run_self_test(Path(sys.argv[2]))
        return
    usage()


if __name__ == "__main__":
    try:
        main()
    except ContractError as error:
        raise SystemExit(str(error)) from error

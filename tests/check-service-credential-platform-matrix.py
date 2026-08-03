#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Enforce the frozen service-credential platform evidence matrix (#382 Unit 6).

This is a static source/doc/config consistency gate. It fails loud (non-zero
exit + a clear message) whenever the authoritative artifacts drift out of
agreement with docs/service-credential-platform-support.md:

  * tests/meson.build          -- the four packaged service-credential e2e
                                  test() registrations MUST sit inside a
                                  `host_machine.system() == 'linux'` gate, so
                                  Linux is the sole packaged-RUNTIME platform
                                  and the suite never silently runs/skips
                                  elsewhere.
  * the matrix doc             -- MUST classify all three platforms exactly as
                                  the meson gating implies (Linux=runtime,
                                  macOS/Windows=build-only) and MUST reference
                                  the #380 orphan-recovery portion together with
                                  its now-implemented #754 packaged
                                  fault-injection proof
                                  (service-credential-publication-fault-e2e).
  * .github/workflows/ci-*.yml -- the RUNTIME platform (Linux) MUST have a
                                  runner job that runs the packaged meson
                                  suite, and each BUILD-ONLY platform
                                  (macOS, Windows) MUST have its runner job and
                                  named native gates present. A matrix-claimed
                                  platform with no runner BLOCKS the gate.

The checker NEVER skips-as-pass: a missing file it needs to read is a FAILURE,
not a pass.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


SC_E2E_TESTS = (
    "service-credential-lifecycle-e2e",
    "service-credential-zero-survivor-e2e",
    "service-credential-rotation-e2e",
    "service-credential-leak-scan-e2e",
)

# The #380 orphan-recovery packaged proof (#754). It runs on Linux like the
# others, but is nested one level deeper under the enable_fault_injection build
# gate: the single-shot publication-fault seam and its daemon flag are compiled
# in only when that option is set, so a release build cannot be armed.
FAULT_INJECTION_TEST = "service-credential-publication-fault-e2e"
FAULT_INJECTION_GATE = "enable_fault_injection"

LINUX_GATE = "host_machine.system() == 'linux'"
WINDOWS_NEGATIVE_GATE = "host_machine.system() != 'windows'"

# Named native build/security gates that MUST be present for each build-only
# platform's runner, proving the platform is really exercised (build evidence).
WINDOWS_NATIVE_GATES = ("secure-duckdb-bridge", "fact-artifact-namespace-windows")
MACOS_NATIVE_GATES = ("secure-duckdb-bridge",)

USAGE = (
    "usage: check-service-credential-platform-matrix.py "
    "MESON_BUILD MATRIX_DOC CI_MAIN CI_PR EVIDENCE_C"
)


def fail(message: str) -> "NoReturn":  # noqa: F821 - sentinel return type
    raise SystemExit(f"service-credential platform matrix drift: {message}")


def read_text_or_fail(path: Path, label: str) -> str:
    """Read a required file; a missing/unreadable file is a FAILURE, not a skip."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read required {label} at {path}: {exc}")


def strip_meson_comment(line: str) -> str:
    """Drop a trailing '#' comment, honoring single/double quoted strings."""
    out = []
    quote = None
    for ch in line:
        if quote is not None:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out)


def paren_balance(text: str) -> int:
    """Net '(' minus ')' outside quoted strings."""
    depth = 0
    quote = None
    for ch in text:
        if quote is not None:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
    return depth


def read_condition(lines: list[str], start: int) -> tuple[str, int]:
    """Read a possibly multi-line `if`/`elif` condition.

    Returns (condition_text, lines_consumed). Continuation is detected by an
    unbalanced parenthesis depth across the accumulated text, which covers the
    `and`-wrapped multi-line conditions used elsewhere in this meson file.
    """
    first = strip_meson_comment(lines[start]).strip()
    # Drop the leading keyword ('if' or 'elif').
    condition = first.split(None, 1)[1] if len(first.split(None, 1)) > 1 else ""
    consumed = 1
    idx = start + 1
    while paren_balance(condition) != 0 and idx < len(lines):
        condition += " " + strip_meson_comment(lines[idx]).strip()
        consumed += 1
        idx += 1
    return condition, consumed


def open_if_conditions_at(lines: list[str], target_idx: int) -> list[str]:
    """Return the list of `if`/`elif` conditions open when line target_idx runs.

    Tracks both `if`/`endif` and `foreach`/`endforeach` on one stack so that
    endif/endforeach match their opener; conditions from currently-open `if`
    frames are returned outermost-first.
    """
    stack: list[tuple[str, str]] = []  # (kind, condition)
    i = 0
    while i < target_idx and i < len(lines):
        stripped = strip_meson_comment(lines[i]).strip()
        tokens = stripped.split()
        keyword = tokens[0] if tokens else ""
        if keyword == "if":
            condition, consumed = read_condition(lines, i)
            stack.append(("if", condition))
            i += consumed
            continue
        if keyword == "elif":
            condition, consumed = read_condition(lines, i)
            if stack and stack[-1][0] == "if":
                stack[-1] = ("if", condition)
            i += consumed
            continue
        if keyword == "endif":
            if stack and stack[-1][0] == "if":
                stack.pop()
        elif keyword == "foreach":
            stack.append(("foreach", ""))
        elif keyword == "endforeach":
            if stack and stack[-1][0] == "foreach":
                stack.pop()
        i += 1
    return [cond for kind, cond in stack if kind == "if"]


def find_test_line(lines: list[str], test_name: str) -> int:
    """Index of the line registering `test('<test_name>', ...)`; fail if absent."""
    pattern = re.compile(r"""\btest\(\s*['"]""" + re.escape(test_name) + r"""['"]""")
    for idx, line in enumerate(lines):
        if pattern.search(strip_meson_comment(line)):
            return idx
    fail(
        f"no test('{test_name}', ...) registration found in tests/meson.build; "
        "the packaged service-credential e2e suite must stay registered"
    )
    raise AssertionError  # unreachable; keeps type checkers happy


def check_meson_gating(meson_text: str) -> None:
    lines = meson_text.splitlines()
    for test_name in SC_E2E_TESTS:
        idx = find_test_line(lines, test_name)
        conditions = open_if_conditions_at(lines, idx)
        joined = " || ".join(conditions)
        if LINUX_GATE not in joined:
            fail(
                f"test('{test_name}') is not inside a `{LINUX_GATE}` gate; "
                "Linux must be the sole packaged-runtime platform. Open "
                f"conditions were: {conditions!r}. If the gate was broadened "
                f"(e.g. back to `{WINDOWS_NEGATIVE_GATE}`), update the matrix "
                "doc and this checker deliberately."
            )

    # The #380 orphan-recovery proof (#754) must be registered AND gated on both
    # Linux (like the others) and the enable_fault_injection build option, so it
    # only exists where the packaged fault seam is compiled in.
    fault_idx = find_test_line(lines, FAULT_INJECTION_TEST)
    fault_conditions = open_if_conditions_at(lines, fault_idx)
    fault_joined = " || ".join(fault_conditions)
    if LINUX_GATE not in fault_joined:
        fail(
            f"test('{FAULT_INJECTION_TEST}') is not inside a `{LINUX_GATE}` "
            f"gate; open conditions were: {fault_conditions!r}"
        )
    if FAULT_INJECTION_GATE not in fault_joined:
        fail(
            f"test('{FAULT_INJECTION_TEST}') (the #380/#754 orphan-recovery "
            f"proof) must be nested under a `{FAULT_INJECTION_GATE}` build gate "
            "so the packaged fault seam only exists in enable_fault_injection "
            f"builds; open conditions were: {fault_conditions!r}"
        )


def check_matrix_doc(doc_text: str) -> None:
    lowered = doc_text.lower()

    def classified(platform: str, classification: str) -> bool:
        # Require the platform token and its classification to co-occur on a
        # single (table-row / bullet) line so a stray mention elsewhere in the
        # prose cannot satisfy the assertion.
        needle_platform = platform.lower()
        needle_class = classification.lower()
        for line in lowered.splitlines():
            if needle_platform in line and needle_class in line:
                return True
        return False

    if not classified("linux", "packaged-runtime-supported"):
        fail(
            "matrix doc does not classify Linux as "
            "'Packaged-runtime-supported' on a single row"
        )
    if not classified("macos", "build-only-supported"):
        fail("matrix doc does not classify macOS as 'Build-only-supported'")
    if not classified("windows", "build-only-supported"):
        fail("matrix doc does not classify Windows as 'Build-only-supported'")

    # skip != pass rule must be stated.
    if "skip != pass" not in lowered:
        fail("matrix doc must state the rule explicitly: 'skip != pass'")

    # The #380 orphan-recovery portion must reference #754 and its now-running
    # packaged proof, plus the C-unit evidence that covers the same boundary.
    if "#754" not in doc_text:
        fail(
            "matrix doc must reference #754 (the implemented packaged "
            "fault-injection seam) for the #380 orphan-recovery runtime portion"
        )
    if "#380" not in doc_text:
        fail("matrix doc must reference the #380 orphan-recovery portion")
    if FAULT_INJECTION_TEST not in doc_text:
        fail(
            "matrix doc must reference the packaged #380 orphan-recovery proof "
            f"'{FAULT_INJECTION_TEST}' now that #754 is implemented and it runs "
            "on Linux"
        )
    if FAULT_INJECTION_GATE not in doc_text:
        fail(
            "matrix doc must state that the #380 proof additionally requires the "
            f"'{FAULT_INJECTION_GATE}' build option (a documented build gate, "
            "not a skip-as-pass)"
        )
    if "test-service-credential-operation-coordinator-execute.c" not in doc_text:
        fail(
            "matrix doc must link the C-unit evidence "
            "(test-service-credential-operation-coordinator-execute.c) covering "
            "the #380 orphan-recovery boundary"
        )


def check_ci_workflow(path: Path, ci_text: str) -> None:
    label = path.name

    # Runtime platform: Linux runner job present AND runs the packaged suite.
    if "ubuntu-latest" not in ci_text:
        fail(f"{label}: no Linux (ubuntu-latest) runner job; the matrix's "
             "packaged-runtime platform must have a runner")
    if "--suite wyrelog" not in ci_text:
        fail(f"{label}: Linux runner does not run the packaged meson suite "
             "(`meson test ... --suite wyrelog`); a runtime platform with no "
             "packaged runner BLOCKS the gate")

    # Build-only platform: macOS runner + its native gate present.
    if "macos-latest" not in ci_text:
        fail(f"{label}: no macOS (macos-latest) runner job for the build-only "
             "platform the matrix claims")
    for gate in MACOS_NATIVE_GATES:
        if gate not in ci_text:
            fail(f"{label}: macOS build-only gate '{gate}' is not present")

    # Build-only platform: Windows runner + its native gates present.
    if "windows-latest" not in ci_text:
        fail(f"{label}: no Windows (windows-latest) runner job for the "
             "build-only platform the matrix claims")
    for gate in WINDOWS_NATIVE_GATES:
        if gate not in ci_text:
            fail(f"{label}: Windows build-only native gate '{gate}' is not "
                 "present; the matrix claims it runs there")


def main(argv: list[str]) -> None:
    if len(argv) != 6:
        fail(USAGE)

    meson_path = Path(argv[1])
    doc_path = Path(argv[2])
    ci_main_path = Path(argv[3])
    ci_pr_path = Path(argv[4])
    evidence_path = Path(argv[5])

    meson_text = read_text_or_fail(meson_path, "tests/meson.build")
    doc_text = read_text_or_fail(doc_path, "matrix doc")
    ci_main_text = read_text_or_fail(ci_main_path, "ci-main.yml")
    ci_pr_text = read_text_or_fail(ci_pr_path, "ci-pr.yml")

    # The C-unit evidence the doc links must actually exist.
    if not evidence_path.is_file():
        fail(
            "the #380/#754 C-unit evidence file is missing: "
            f"{evidence_path}"
        )

    check_meson_gating(meson_text)
    check_matrix_doc(doc_text)
    check_ci_workflow(ci_main_path, ci_main_text)
    check_ci_workflow(ci_pr_path, ci_pr_text)

    print(
        "service-credential platform matrix consistent: "
        "Linux=packaged-runtime, macOS/Windows=build-only; "
        "meson gating, matrix doc, and CI workflows agree"
    )


if __name__ == "__main__":
    main(sys.argv)

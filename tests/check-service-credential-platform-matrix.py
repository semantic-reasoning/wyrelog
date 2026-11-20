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
                                  The service-credential-e2e job, the only
                                  enable_fault_injection build, MUST also run
                                  the wyctl token-file fault tests (#1546).
  * tests/test-wyctl-basic.c   -- every `-p` path the filtered
                                  wyctl-token-file-write-faults registration
                                  passes MUST be a g_test_add_func literal
                                  there: GLib exits 0 with `1..0` for an
                                  unknown -p, so a typo would pass silently.

`--self-test` runs the #1546 checks against built-in negative cases.

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

# The exact condition terms that open each gate. A gate is open only when one
# of these is a positive top-level conjunct of an enclosing condition, so a
# negated gate, an `or` alternative, or an `else` branch does not count.
LINUX_GATE_FORMS = (LINUX_GATE,)
FAULT_INJECTION_GATE_FORMS = (
    f"get_option('{FAULT_INJECTION_GATE}').allowed()",
    f"get_option('{FAULT_INJECTION_GATE}').enabled()",
)

# Named native build/security gates that MUST be present for each build-only
# platform's runner, proving the platform is really exercised (build evidence).
WINDOWS_NATIVE_GATES = ("secure-duckdb-bridge", "fact-artifact-namespace-windows")
MACOS_NATIVE_GATES = ("secure-duckdb-bridge",)

# The wyctl token-file write-fault tests (#1546). The hook and its CLI flag
# exist only in enable_fault_injection builds, and service-credential-e2e is
# the only CI job built that way, so it must name both in its meson test list.
TOKEN_FILE_FAULT_TESTS = ("wyctl-token-file", "wyctl-token-file-write-faults")
TOKEN_FILE_FAULT_REGISTRATION = "wyctl-token-file-write-faults"
TOKEN_FILE_FAULT_PATHS_VAR = "wyctl_token_file_fault_paths"

USAGE = (
    "usage: check-service-credential-platform-matrix.py "
    "MESON_BUILD MATRIX_DOC CI_MAIN CI_PR EVIDENCE_C TEST_WYCTL_BASIC_C\n"
    "       check-service-credential-platform-matrix.py --self-test"
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


# A block keyword at the start of a line. Meson needs no space after it, so
# `if(` and `elif(` count; `\b` keeps `if_x = ...` from matching.
BLOCK_KEYWORD = re.compile(r"(if|elif|else|endif|foreach|endforeach)\b")


def block_keyword(stripped: str) -> re.Match[str] | None:
    return BLOCK_KEYWORD.match(stripped)


def read_condition(lines: list[str], start: int) -> tuple[str, int]:
    """Read a possibly multi-line `if`/`elif` condition.

    Returns (condition_text, lines_consumed). Continuation is detected by an
    unbalanced parenthesis depth across the accumulated text, which covers the
    `and`-wrapped multi-line conditions used elsewhere in this meson file, or
    by a trailing `\\` line continuation, which is dropped from the text.
    """
    first = strip_meson_comment(lines[start]).strip()
    # Drop the leading keyword ('if' or 'elif').
    keyword = block_keyword(first)
    condition = first[keyword.end():].strip() if keyword else ""
    consumed = 1
    idx = start + 1

    def continued(text: str) -> bool:
        return text.endswith("\\")

    while ((paren_balance(condition) != 0 or continued(condition))
           and idx < len(lines)):
        if continued(condition):
            condition = condition[:-1].rstrip()
        condition += " " + strip_meson_comment(lines[idx]).strip()
        consumed += 1
        idx += 1
    return condition, consumed


def open_if_conditions_at(lines: list[str], target_idx: int) -> list[str]:
    """Return the list of `if`/`elif` conditions open when line target_idx runs.

    Tracks both `if`/`endif` and `foreach`/`endforeach` on one stack so that
    endif/endforeach match their opener; conditions from currently-open `if`
    frames are returned outermost-first. Inside an `else` branch the frame's
    condition is the negation of every `if`/`elif` condition before it.
    """
    # (kind, condition in force, conditions of the branches seen so far)
    stack: list[tuple[str, str, list[str]]] = []
    i = 0
    while i < target_idx and i < len(lines):
        stripped = strip_meson_comment(lines[i]).strip()
        match = block_keyword(stripped)
        keyword = match.group(1) if match else ""
        if keyword == "if":
            condition, consumed = read_condition(lines, i)
            stack.append(("if", condition, [condition]))
            i += consumed
            continue
        if keyword == "elif":
            condition, consumed = read_condition(lines, i)
            if stack and stack[-1][0] == "if":
                stack[-1] = ("if", condition, stack[-1][2] + [condition])
            i += consumed
            continue
        if keyword == "else":
            if stack and stack[-1][0] == "if":
                branches = stack[-1][2]
                negated = " and ".join(f"not ({cond})" for cond in branches)
                stack[-1] = ("if", negated, branches)
        elif keyword == "endif":
            if stack and stack[-1][0] == "if":
                stack.pop()
        elif keyword == "foreach":
            stack.append(("foreach", "", []))
        elif keyword == "endforeach":
            if stack and stack[-1][0] == "foreach":
                stack.pop()
        i += 1
    return [cond for kind, cond, _ in stack if kind == "if"]


def split_top_level(text: str, separator: str) -> list[str]:
    """Split at `separator` outside parentheses and quoted strings."""
    parts = []
    depth = 0
    quote = None
    start = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and text.startswith(separator, i):
            parts.append(text[start:i])
            i += len(separator)
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def strip_outer_parens(text: str) -> str:
    """Remove parenthesis pairs that enclose the whole of `text`."""
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        inner = text[1:-1]
        # The pair encloses everything only if no prefix of the inner text
        # closes more than it opens, as in `(a) and (b)`.
        depth = 0
        quote = None
        for ch in inner:
            if quote is not None:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    return text
        text = inner.strip()
    return text


def positive_terms(condition: str) -> list[str]:
    """The top-level conjuncts that must hold for `condition` to be true.

    A negated term or an `or` alternative stays whole (`not X`, `X or Y`), so
    it never equals a gate form: neither guarantees the gate it names.
    """
    condition = strip_outer_parens(" ".join(condition.split()))
    # `and` binds tighter than `or`, so a top-level `or` makes the whole
    # condition one alternative-bearing term.
    if len(split_top_level(condition, " or ")) > 1:
        return [condition]
    parts = split_top_level(condition, " and ")
    if len(parts) > 1:
        return [term for part in parts for term in positive_terms(part)]
    return [condition]


def gate_open(conditions: list[str], forms: tuple[str, ...]) -> bool:
    """True iff some open condition requires one of the gate's forms.

    Terms are compared whole, not searched, so `not X` does not open X.
    Unmodelled forms fail closed (`else` of `if not G`, double quotes, other
    spacing), except the ternary `?:`, which binds looser than `and` and is
    not parsed; tests/meson.build uses none of these around a gate.
    """
    return any(term in forms
               for condition in conditions
               for term in positive_terms(condition))


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
        if not gate_open(conditions, LINUX_GATE_FORMS):
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
    if not gate_open(fault_conditions, LINUX_GATE_FORMS):
        fail(
            f"test('{FAULT_INJECTION_TEST}') is not inside a `{LINUX_GATE}` "
            f"gate; open conditions were: {fault_conditions!r}"
        )
    if not gate_open(fault_conditions, FAULT_INJECTION_GATE_FORMS):
        fail(
            f"test('{FAULT_INJECTION_TEST}') (the #380/#754 orphan-recovery "
            f"proof) must be nested under a `{FAULT_INJECTION_GATE}` build gate "
            "so the packaged fault seam only exists in enable_fault_injection "
            f"builds; open conditions were: {fault_conditions!r}"
        )


def fault_job_meson_tests(label: str, ci_text: str) -> list[str]:
    """Test names on the service-credential-e2e job's `meson test` line.

    Exact tokens, so `wyctl-token-file-write-faults` cannot stand in for
    `wyctl-token-file`, and a mention in a comment or another job does not
    count.
    """
    lines = ci_text.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if line.rstrip() == "  service-credential-e2e:"), None)
    if start is None:
        fail(f"{label}: no 'service-credential-e2e:' job to hold the "
             "enable_fault_injection tests")
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r"^  \S", lines[i])), len(lines))
    job = "\n".join(strip_yaml_comment(line) for line in lines[start:end])
    match = re.search(r"meson test -C builddir((?:[^\n]*\\\n)*[^\n]*)", job)
    if match is None:
        fail(f"{label}: the service-credential-e2e job has no "
             "`meson test -C builddir` step")
    return [token for token in re.split(r"[\s\\]+", match.group(1))
            if token and not token.startswith("-")]


def strip_yaml_comment(line: str) -> str:
    stripped = line.lstrip()
    return "" if stripped.startswith("#") else line


def check_ci_token_file_faults(label: str, ci_text: str) -> None:
    tests = fault_job_meson_tests(label, ci_text)
    for name in TOKEN_FILE_FAULT_TESTS:
        if name not in tests:
            fail(f"{label}: the service-credential-e2e job is the only "
                 f"enable_fault_injection build, so its meson test list must "
                 f"name '{name}' (#1546); it names {tests!r}")


def token_file_fault_paths(meson_text: str) -> list[str]:
    lines = meson_text.splitlines()
    idx = find_test_line(lines, TOKEN_FILE_FAULT_REGISTRATION)
    open_conditions = open_if_conditions_at(lines, idx)
    conditions = " || ".join(open_conditions)
    if not gate_open(open_conditions, FAULT_INJECTION_GATE_FORMS):
        fail(f"test('{TOKEN_FILE_FAULT_REGISTRATION}') must sit under a "
             f"`{FAULT_INJECTION_GATE}` gate; open conditions were: "
             f"{conditions!r}")
    match = re.search(re.escape(TOKEN_FILE_FAULT_PATHS_VAR)
                      + r"\s*=\s*\[(.*?)\]", meson_text, re.DOTALL)
    if match is None:
        fail(f"tests/meson.build: no `{TOKEN_FILE_FAULT_PATHS_VAR} = [...]` "
             f"list for test('{TOKEN_FILE_FAULT_REGISTRATION}')")
    paths = re.findall(r"'([^']+)'", match.group(1))
    if not paths:
        fail(f"tests/meson.build: `{TOKEN_FILE_FAULT_PATHS_VAR}` is empty, so "
             f"test('{TOKEN_FILE_FAULT_REGISTRATION}') would run nothing")
    return paths


def check_token_file_fault_paths(meson_text: str, c_text: str) -> None:
    registered = set(re.findall(r'g_test_add_func\s*\(\s*"([^"]+)"', c_text))
    for path in token_file_fault_paths(meson_text):
        if path not in registered:
            fail(f"tests/meson.build: test('{TOKEN_FILE_FAULT_REGISTRATION}') "
                 f"passes -p '{path}', but tests/test-wyctl-basic.c has no "
                 "g_test_add_func for it; GLib exits 0 with '1..0' for an "
                 "unknown -p, so the test would pass without running it")


def self_test() -> None:
    job = (
        "jobs:\n"
        "  service-credential-e2e:\n"
        "    steps:\n"
        "      - run: |\n"
        "          meson test -C builddir --print-errorlogs \\\n"
        "            service-credential-platform-matrix \\\n"
        "{tests}"
        "  next-job:\n"
        "    steps:\n"
        "      - run: meson test -C builddir wyctl-token-file\n"
    )
    both = ("            wyctl-token-file \\\n"
            "            wyctl-token-file-write-faults\n")
    meson = (
        "if get_option('enable_fault_injection').allowed()\n"
        "  wyctl_token_file_fault_paths = [\n"
        "{paths}"
        "  ]\n"
        "  test('wyctl-token-file-write-faults', python3)\n"
        "endif\n"
    )
    c_text = ('  g_test_add_func ("/wyctl/a", test_a);\n'
              '  g_test_add_func (\n      "/wyctl/b", test_b);\n')

    def expect(action, needle: str | None) -> None:
        try:
            action()
        except SystemExit as exc:
            if needle is None or needle not in str(exc):
                raise SystemExit(f"self-test: unexpected failure: {exc}")
            return
        if needle is not None:
            raise SystemExit(f"self-test: expected a failure naming {needle!r}")

    expect(lambda: check_ci_token_file_faults("ok.yml",
           job.format(tests=both)), None)
    # Only the longer name: the shorter must not match as a substring.
    expect(lambda: check_ci_token_file_faults("short.yml", job.format(
           tests="            wyctl-token-file-write-faults\n")),
           "must name 'wyctl-token-file'")
    # The unit test named only in a comment and in another job.
    expect(lambda: check_ci_token_file_faults("comment.yml", job.format(
           tests="            # wyctl-token-file\n"
                 "            wyctl-token-file-write-faults\n")),
           "must name 'wyctl-token-file'")
    expect(lambda: check_ci_token_file_faults("missing.yml", job.format(
           tests="            wyctl-token-file\n")),
           "must name 'wyctl-token-file-write-faults'")
    expect(lambda: check_ci_token_file_faults("nojob.yml", "jobs:\n"),
           "no 'service-credential-e2e:' job")

    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n    '/wyctl/b',\n"), c_text), None)
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n    '/wyctl/renamed',\n"), c_text),
           "passes -p '/wyctl/renamed'")
    expect(lambda: check_token_file_fault_paths(meson.format(paths=""),
           c_text), "is empty")
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(
           "get_option('enable_fault_injection').allowed()", "true"),
           c_text), "must sit under a `enable_fault_injection` gate")
    # An `else` branch runs exactly when the gate is false.
    expect(lambda: check_token_file_fault_paths(
           "if get_option('enable_fault_injection').allowed()\n"
           "  x = 1\n"
           "else\n"
           "  wyctl_token_file_fault_paths = ['/wyctl/a']\n"
           "  test('wyctl-token-file-write-faults', python3)\n"
           "endif\n", c_text),
           "must sit under a `enable_fault_injection` gate")
    # A negated gate names the option but excludes it.
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(
           "if get_option", "if not get_option"), c_text),
           "must sit under a `enable_fault_injection` gate")
    # A parenthesized conjunction still opens the gate (the outer parens are
    # stripped before splitting).
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(
           "if get_option('enable_fault_injection').allowed()\n",
           "if (get_option('enable_fault_injection').allowed() and \\\n"
           "    host_machine.system() != 'windows')\n"), c_text), None)
    # Parenthesized conjuncts: `(x) and (G)` is not one enclosing pair.
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(
           "if get_option('enable_fault_injection').allowed()\n",
           "if (x) and (get_option('enable_fault_injection').allowed())\n"),
           c_text), None)
    # `.enabled()` opens the gate as well as `.allowed()`.
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(".allowed()", ".enabled()"),
           c_text), None)
    # The real form: the gate on a `\`-continued line.
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(
           "if get_option('enable_fault_injection').allowed()\n",
           "if host_machine.system() != 'windows' and \\\n"
           "    get_option('enable_fault_injection').allowed()\n"),
           c_text), None)
    # `and` binds tighter than `or`: the gate is one alternative, not required.
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(
           "if get_option",
           "if true or host_machine.system() != 'windows' and get_option"),
           c_text), "must sit under a `enable_fault_injection` gate")
    # Names that merely start with a keyword are not block keywords: read as
    # keywords, `else_y` would flip the gate and `endif_x` would close it.
    for name in ("else_y", "endif_x"):
        expect(lambda: check_token_file_fault_paths(meson.format(
               paths="    '/wyctl/a',\n").replace(
               "  wyctl_token_file_fault_paths",
               f"  {name} = 1\n  wyctl_token_file_fault_paths"), c_text),
               None)
    # `if(` needs no space either, and its condition still opens the gate.
    expect(lambda: check_token_file_fault_paths(meson.format(
           paths="    '/wyctl/a',\n").replace(
           "if get_option('enable_fault_injection').allowed()\n",
           "if(get_option('enable_fault_injection').allowed())\n"),
           c_text), None)
    # `elif(` needs no space; its branch runs only when the gate is false.
    expect(lambda: check_token_file_fault_paths(
           "if get_option('enable_fault_injection').allowed()\n"
           "  x = 1\n"
           "elif(true)\n"
           "  wyctl_token_file_fault_paths = ['/wyctl/a']\n"
           "  test('wyctl-token-file-write-faults', python3)\n"
           "endif\n", c_text),
           "must sit under a `enable_fault_injection` gate")

    sc_meson = (
        "if host_machine.system() == 'linux'\n"
        "  test('service-credential-lifecycle-e2e', sh)\n"
        "  test('service-credential-zero-survivor-e2e', sh)\n"
        "  test('service-credential-rotation-e2e', sh)\n"
        "{leak_scan}"
        "  if get_option('enable_fault_injection').allowed()\n"
        "    test('service-credential-publication-fault-e2e', sh)\n"
        "  endif\n"
        "{tail}"
        "endif\n"
    )
    leak_scan = "  test('service-credential-leak-scan-e2e', sh)\n"
    expect(lambda: check_meson_gating(sc_meson.format(
           leak_scan=leak_scan, tail="")), None)
    expect(lambda: check_meson_gating(sc_meson.format(
           leak_scan="", tail="else\n" + leak_scan)),
           "test('service-credential-leak-scan-e2e') is not inside a "
           "`host_machine.system() == 'linux'` gate")
    print("service-credential platform matrix self-test passed")


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

    # Dedicated packaged-SC-e2e job (#766): the SC e2e drivers are gated on
    # build_client/enable_fact_store/enable_audit (+ enable_fault_injection),
    # which the general --suite wyrelog job above does not set, so those tests
    # never register there. A dedicated job MUST build with exactly those
    # options and run the packaged suite, or the matrix's Linux runtime claim
    # would be documented-but-unenforced (a skip-as-pass). Removing or defanging
    # the job fails this gate.
    if "service-credential-e2e" not in ci_text:
        fail(f"{label}: no dedicated 'service-credential-e2e' job; the packaged "
             "SC e2e suite must run in CI to enforce the Linux runtime claim")
    for opt in ("enable_client", "enable_fact_store", FAULT_INJECTION_GATE):
        # Require the actual build flag, not a bare substring (which could match
        # a comment), so dropping the option from the meson setup fails the gate.
        if f"-D{opt}=enabled" not in ci_text:
            fail(f"{label}: the service-credential-e2e job must build with "
                 f"-D{opt}=enabled so the packaged SC e2e suite registers")
    for test_name in SC_E2E_TESTS + (FAULT_INJECTION_TEST,):
        if test_name not in ci_text:
            fail(f"{label}: the service-credential-e2e job must run "
                 f"'{test_name}'; the packaged runtime gate must be exercised")
    check_ci_token_file_faults(label, ci_text)

    # Build-only platform: macOS runner + its native gate present.
    if "macos-latest" not in ci_text:
        fail(f"{label}: no macOS (macos-latest) runner job for the build-only "
             "platform the matrix claims")
    for gate in MACOS_NATIVE_GATES:
        if gate not in ci_text:
            fail(f"{label}: macOS build-only gate '{gate}' is not present")

    # Build-only platform: Windows runner + its native gates present.
    if ("runs-on: ${{ matrix.runner }}" not in ci_text
            or ci_text.count("- runner: windows-2025") != 3):
        fail(f"{label}: the three Windows build-only matrix rows must use "
             "the explicit windows-2025 runner")
    for gate in WINDOWS_NATIVE_GATES:
        if gate not in ci_text:
            fail(f"{label}: Windows build-only native gate '{gate}' is not "
                 "present; the matrix claims it runs there")


def main(argv: list[str]) -> None:
    if len(argv) == 2 and argv[1] == "--self-test":
        self_test()
        return
    if len(argv) != 7:
        fail(USAGE)

    meson_path = Path(argv[1])
    doc_path = Path(argv[2])
    ci_main_path = Path(argv[3])
    ci_pr_path = Path(argv[4])
    evidence_path = Path(argv[5])
    wyctl_basic_path = Path(argv[6])

    meson_text = read_text_or_fail(meson_path, "tests/meson.build")
    doc_text = read_text_or_fail(doc_path, "matrix doc")
    ci_main_text = read_text_or_fail(ci_main_path, "ci-main.yml")
    ci_pr_text = read_text_or_fail(ci_pr_path, "ci-pr.yml")
    wyctl_basic_text = read_text_or_fail(wyctl_basic_path,
                                         "tests/test-wyctl-basic.c")

    # The C-unit evidence the doc links must actually exist.
    if not evidence_path.is_file():
        fail(
            "the #380/#754 C-unit evidence file is missing: "
            f"{evidence_path}"
        )

    check_meson_gating(meson_text)
    check_token_file_fault_paths(meson_text, wyctl_basic_text)
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

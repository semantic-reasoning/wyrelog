#!/usr/bin/env python3
"""Guard the Windows artifact test fault hooks out of shipped code.

The hooks substitute a directory-flush result and a sidecar-replacement fault.
A shipped library must contain neither: an armed hook makes an operation report
a failure that should have succeeded, and the armed form also costs an
interlocked read on every directory flush.  This checks the compile gate
structurally, by preprocessing the modules with the macro undefined and proving
no hook survives, rather than by matching spellings.
"""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
MACRO = "WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS"
OPTION = "enable_windows_artifact_test_hooks"

# Every identity the hooks reach: the two public pairs, the internal taker, the
# armable state each pair mutates, and the fault vocabulary.  None may survive
# into a shipped translation unit.
HOOK_SYMBOLS = (
    "wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test",
    "wyl_fact_artifact_win_locator_take_next_directory_flush_error_for_test",
    "wyl_fact_artifact_win_locator_fail_next_rename_status_for_test",
    "wyl_fact_artifact_win_locator_take_next_rename_status_for_test",
    "wyl_fact_artifact_win_namespace_set_test_fault",
    "wyl_fact_artifact_win_namespace_take_test_fault",
    "win_namespace_fault_take",
    "next_directory_flush_error",
    "next_rename_status",
    "win_namespace_test_fault",
    "WylFactArtifactWinNamespaceTestFault",
    "WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_",
)

GATED_SOURCES = (
    "wyrelog/fact/graph-artifact-windows-locator-private.h",
    "wyrelog/fact/graph-artifact-windows-locator-private.c",
    "wyrelog/fact/graph-artifact-windows-namespace-private.h",
    "wyrelog/fact/graph-artifact-windows-namespace-private.c",
)


def without_macro_branches(source: str, macro: str) -> str:
    """Blank branches that require @macro while retaining line layout."""
    output = []
    stack: list[tuple[bool, bool, bool]] = []
    enabled = True
    opener = re.compile(rf"#\s*(ifdef|ifndef)\s+{re.escape(macro)}\b")
    defined_opener = re.compile(
        rf"#\s*if\s+defined\s*\(\s*{re.escape(macro)}\s*\)")
    for line in source.splitlines(keepends=True):
        directive = line.lstrip()
        match = opener.match(directive)
        defined_match = defined_opener.match(directive)
        if match or defined_match:
            parent = enabled
            positive = defined_match is not None or match.group(1) == "ifdef"
            branch = not positive  # the macro is undefined in a shipped build
            stack.append((True, parent, branch))
            enabled = parent and branch
            output.append("\n" if line.endswith("\n") else "")
            continue
        if re.match(r"#\s*(if|ifdef|ifndef)\b", directive):
            stack.append((False, enabled, True))
        elif re.match(r"#\s*else\b", directive) and stack and stack[-1][0]:
            target, parent, branch = stack[-1]
            branch = not branch
            stack[-1] = (target, parent, branch)
            enabled = parent and branch
            output.append("\n" if line.endswith("\n") else "")
            continue
        elif re.match(r"#\s*endif\b", directive) and stack:
            target, parent, _branch = stack.pop()
            if target:
                enabled = parent
                output.append("\n" if line.endswith("\n") else "")
                continue
        output.append(line if enabled else ("\n" if line.endswith("\n") else ""))
    return "".join(output)


def body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"missing function {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated function {name}")


sources = {rel: (root / rel).read_text(encoding="utf-8")
           for rel in GATED_SOURCES}

# The gate must not be vacuous.  If the hooks were deleted outright this file
# would otherwise keep passing and stop guarding anything, so require that the
# hooked build still declares, defines and consumes every identity.
for symbol in HOOK_SYMBOLS:
    if not any(symbol in text for text in sources.values()):
        raise SystemExit(
            f"{symbol} is gone: this gate would now pass vacuously")

# The shipped build is the text that survives with the macro undefined.
for rel, text in sources.items():
    shipped = without_macro_branches(text, MACRO)
    for symbol in HOOK_SYMBOLS:
        if symbol in shipped:
            raise SystemExit(
                f"{rel} leaks the test hook identity {symbol} into a shipped "
                "build: it must sit inside a "
                f"#ifdef {MACRO} branch")

# The unhooked directory flush must still be a real flush, and must read no
# armable state to decide its result.
locator = without_macro_branches(
    sources["wyrelog/fact/graph-artifact-windows-locator-private.c"], MACRO)
flush = body(locator, "wyl_fact_artifact_win_locator_flush_directory")
if "FlushFileBuffers" not in flush or "GetLastError" not in flush:
    raise SystemExit("the shipped directory flush must call the native flush "
                     "and read its native error")
if "InterlockedExchange" in flush:
    raise SystemExit("the shipped directory flush must not pay an interlocked "
                     "read for a hook it cannot contain")

# The option itself: a feature, off by default, so a release configuration
# gets the shipped form without having to ask for it.
options = (root / "meson.options").read_text(encoding="utf-8")
start = options.find(f"option('{OPTION}'")
if start < 0:
    raise SystemExit(f"meson.options must declare {OPTION}")
option_block = options[start:options.index("\n)\n", start)]
if "type : 'feature'" not in option_block:
    raise SystemExit(f"{OPTION} must be a feature option")
if "value : 'disabled'" not in option_block:
    raise SystemExit(f"{OPTION} must default to disabled")

# The macro reaches the compiler from exactly one place, and only when the
# option allows it.  A project argument is what makes the library and every
# test that links it agree on one definition.
build = (root / "meson.build").read_text(encoding="utf-8")
if build.count(f"-D{MACRO}") != 1:
    raise SystemExit(f"-D{MACRO} must be defined in exactly one place")
guard = re.search(
    rf"get_option\s*\(\s*'{OPTION}'\s*\)(.*?)add_project_arguments\s*\(\s*"
    rf"'-D{MACRO}'", build, re.S)
if guard is None or ".allowed()" not in guard.group(1):
    raise SystemExit(
        f"-D{MACRO} must be added only inside the {OPTION} .allowed() guard")

# The test binary built on the hooks must be gated on the same option, so a
# shipped configuration cannot try to build it against a library without them.
tests_build = (root / "tests/meson.build").read_text(encoding="utf-8")
target = tests_build.find("'test-fact-artifact-namespace-windows'")
if target < 0:
    raise SystemExit("the Windows artifact test target must remain registered")
condition = tests_build.rindex("if host_machine.system() == 'windows'", 0,
                               target)
if ".allowed()" not in tests_build[condition:target]:
    raise SystemExit(
        "the Windows artifact test target must be gated on "
        f"{OPTION}: its fixture arms and disarms both hooks")

print("windows artifact test hook wiring: OK")

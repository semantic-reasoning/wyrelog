#!/usr/bin/env python3
"""Guard the service-credential storage test fault hooks out of shipped code.

Two of these hooks take a caller-supplied function pointer and run it inside the
credential publication rename and exact-delete paths, so a shipped library must
not contain them at all.  The gate is a per-target macro rather than a build
option: only the focused storage test, which compiles these translation units
itself, defines it.  libwyrelog is never given it in any configuration, so the
guarantee here is structural rather than default-dependent.

This preprocesses the module with the macro undefined and proves no hook
survives, rather than matching spellings.
"""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
MACRO = "WYL_ENABLE_SERVICE_CREDENTIAL_STORAGE_TEST_HOOKS"
TARGET = "test_service_credential_operation_storage = executable("

MODULE_C = "wyrelog/auth/service-credential-operation-storage-windows-private.c"
MODULE_H = "wyrelog/auth/service-credential-operation-storage-windows-private.h"

# Every identity the hooks reach: the three public pairs, the two internal
# runners, the armable state each mutates, the lock that serialises them, and
# the function-pointer type one of them accepts.
HOOK_SYMBOLS = (
    "wyl_win_child_fail_next_directory_flush_for_test",
    "wyl_win_child_take_next_directory_flush_error_for_test",
    "wyl_win_child_set_before_rename_hook_for_test",
    "wyl_win_child_take_before_rename_hook_for_test",
    "wyl_win_child_run_before_rename_hook_for_test",
    "wyl_win_child_set_before_exact_delete_hook_for_test",
    "wyl_win_child_take_before_exact_delete_hook_for_test",
    "wyl_win_child_run_before_exact_delete_hook_for_test",
    "wyl_win_next_directory_flush_error",
    "wyl_win_before_rename_hook",
    "wyl_win_before_exact_delete_hook",
    "wyl_win_test_hooks",
    "WylWinChildBeforeRenameHookForTest",
)

# Deliberately NOT gated: a pure NTSTATUS classifier with no armable state and
# no call site in the storage paths.  Pinned here so the gate cannot quietly
# widen to swallow it, nor narrow and leave a real hook beside it.
UNGATED_SYMBOL = "wyl_win_child_classify_nt_create_status_for_test"


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
           for rel in (MODULE_C, MODULE_H)}

# The gate must not be vacuous.  If the hooks were deleted outright this file
# would otherwise keep passing while guarding nothing.
for symbol in HOOK_SYMBOLS + (UNGATED_SYMBOL,):
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
                f"build: it must sit inside a #ifdef {MACRO} branch")

shipped_h = without_macro_branches(sources[MODULE_H], MACRO)
if UNGATED_SYMBOL not in shipped_h:
    raise SystemExit(
        f"{UNGATED_SYMBOL} is a pure classifier, not a fault hook; it must "
        "stay outside the gate so the gate's scope stays exact")

# The unhooked directory flush must still be a real flush, must reject a bad
# handle, and must read no armable state to decide its result.
shipped_c = without_macro_branches(sources[MODULE_C], MACRO)
flush = body(shipped_c, "wyl_win_flush_directory")
if "FlushFileBuffers" not in flush or "GetLastError" not in flush:
    raise SystemExit("the shipped directory flush must call the native flush "
                     "and read its native error")
if "INVALID_HANDLE_VALUE" not in flush:
    raise SystemExit("the shipped directory flush must still reject a bad root")
if "InterlockedExchange" in flush:
    raise SystemExit("the shipped directory flush must not pay an interlocked "
                     "read for a hook it cannot contain")

# The macro is a per-target argument on exactly one test, and reaches nothing
# else.  This is what makes the guarantee structural instead of a default: no
# configuration of this project can put the hooks in libwyrelog.
tests_build = (root / "tests/meson.build").read_text(encoding="utf-8")
if tests_build.count(MACRO) != 1:
    raise SystemExit(
        f"{MACRO} must be defined for exactly one test target")
target_start = tests_build.find(TARGET)
if target_start < 0:
    raise SystemExit("the focused storage test target must remain registered")
target_block = tests_build[target_start:tests_build.index("\n)\n", target_start)]
if f"-D{MACRO}" not in target_block:
    raise SystemExit(
        f"{MACRO} must be a c_args entry on {TARGET.split(' =')[0]}")

for rel in ("meson.build", "wyrelog/meson.build", "meson.options"):
    text = (root / rel).read_text(encoding="utf-8")
    if MACRO in text or "enable_service_credential_storage_test_hooks" in text:
        raise SystemExit(
            f"{rel} must not mention {MACRO}: a project argument or build "
            "option would let a shipped libwyrelog compile the hooks")

print("service-credential storage test hook wiring: OK")

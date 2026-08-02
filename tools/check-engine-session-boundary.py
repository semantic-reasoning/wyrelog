#!/usr/bin/env python3
"""Check the structural boundary around the handle-owned engine pair.

This intentionally checks symbols and ownership, not C control flow.  The
typed WylEngineSession capability is the proof that production consumers hold
one interval; legacy handle operations exist only in test-seam preprocessing.
"""

from pathlib import Path
import re
import sys


LEGACY_HANDLE_OPERATIONS = (
    "wyl_handle_intern_engine_symbol",
    "wyl_handle_dup_engine_symbol",
    "wyl_handle_make_engine_compound",
    "wyl_handle_make_read_engine_compound",
    "wyl_handle_make_guard_context_compound",
    "wyl_handle_engine_insert",
    "wyl_handle_engine_remove",
    "wyl_handle_engine_contains",
    "wyl_handle_engine_decide",
    "wyl_handle_engine_step_delta",
    "wyl_handle_engine_set_delta_callback",
    "wyl_handle_replay_delta_insert",
    "wyl_handle_get_read_engine",
    "wyl_handle_get_delta_engine",
)
AGGREGATE_FIELDS = (
    "read_engine",
    "delta_engine",
    "engine_symbols_by_id",
    "pending_deltas",
    "delta_callback",
    "delta_callback_user_data",
    "engine_pair_poisoned",
    "engine_pair_replacement_building",
)
OWNER = "wyrelog/wyl-handle.c"
OWNED_ENGINE_ALLOWLIST = {
    OWNER,
    "wyrelog/wyl-engine.c",
    "wyrelog/wyl-engine-private.h",
    "wyrelog/fact/compound.c",
    "wyrelog/fact/query.c",
    "wyrelog/fact/replay.c",
}


def without_test_seams(source: str) -> str:
    """Blank WYL_TEST_HANDLE_SEAMS branches while retaining line layout."""
    output = []
    stack: list[tuple[bool, bool, bool]] = []
    enabled = True
    for line in source.splitlines(keepends=True):
        directive = line.lstrip()
        match = re.match(r"#\s*(ifdef|ifndef)\s+WYL_TEST_HANDLE_SEAMS\b",
                         directive)
        defined_match = re.match(
            r"#\s*if\s+defined\s*\(\s*WYL_TEST_HANDLE_SEAMS\s*\)",
            directive)
        if match or defined_match:
            parent = enabled
            positive = defined_match is not None or match.group(1) == "ifdef"
            branch = not positive  # the macro is undefined in production
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


def mask_comments_and_literals(source: str) -> str:
    """Replace comments and literals, preserving newlines and token spacing."""
    pattern = re.compile(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )
    return pattern.sub(lambda m: "".join("\n" if c == "\n" else " "
                                          for c in m.group()), source)


def check(sources: dict[str, str]) -> list[str]:
    errors = []
    legacy = re.compile(r"\b(?:" + "|".join(map(re.escape,
                        LEGACY_HANDLE_OPERATIONS)) + r")\s*\(")
    fields = re.compile(r"->(?:" + "|".join(map(re.escape,
                        AGGREGATE_FIELDS)) + r")\b")
    owned = re.compile(r"\bwyl_engine_owned_[A-Za-z0-9_]*\s*\(")
    raw_lock = re.compile(r"\bwyl_handle_lock_engine_session\s*\(")

    for path, raw in sources.items():
        source = mask_comments_and_literals(without_test_seams(raw))
        if legacy.search(source):
            errors.append(f"legacy handle engine operation in production: {path}")
        if path != OWNER and fields.search(source):
            errors.append(f"handle-owned engine aggregate accessed outside owner: {path}")
        if path not in OWNED_ENGINE_ALLOWLIST and owned.search(source):
            errors.append(f"owned engine primitive outside allowlist: {path}")
        if path not in {OWNER, "wyrelog/wyl-handle-private.h"} and raw_lock.search(source):
            errors.append(f"untyped engine lock outside owner: {path}")
    return sorted(set(errors))


def self_test() -> int:
    accepted = {
        OWNER: "static void owner(WylHandle *h) { h->read_engine = 0; }",
        "wyrelog/good.c": (
            "void good(WylEngineSession *s) { "
            "wyl_engine_session_insert(s, \"r\", 0, 0); }\n"
            "#ifdef WYL_TEST_HANDLE_SEAMS\n"
            "void seam(WylHandle *h) { wyl_handle_get_read_engine(h); }\n"
            "#endif\n"
        ),
    }
    if check(accepted):
        print("self-test rejected valid fixture", file=sys.stderr)
        return 1

    mutants = (
        "void bad(WylHandle *h) { wyl_handle_engine_insert(h, 0, 0, 0); }",
        "void bad(WylHandle *h) { (void) h->delta_engine; }",
        "void bad(WylEngine *e) { wyl_engine_owned_insert(e, 0, 0, 0); }",
        "void bad(WylHandle *h) { wyl_handle_lock_engine_session(h); }",
    )
    for mutant in mutants:
        if not check({OWNER: "", "wyrelog/bad.c": mutant}):
            print(f"self-test accepted mutant: {mutant}", file=sys.stderr)
            return 1
    literal = 'const char *s = "wyl_handle_get_read_engine(h)"; /* h->read_engine */'
    if check({OWNER: "", "wyrelog/literal.c": literal}):
        print("self-test rejected comments/literals", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    if len(sys.argv) != 2:
        print("usage: check-engine-session-boundary.py SOURCE_ROOT | --self-test",
              file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    sources = {
        str(path.relative_to(root)): path.read_text(encoding="utf-8")
        for path in (root / "wyrelog").rglob("*")
        if path.suffix in {".c", ".cc", ".h", ".hh", ".hpp"}
    }
    errors = check(sources)
    if errors:
        print("engine-session boundary violations:", *errors, sep="\n  ",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

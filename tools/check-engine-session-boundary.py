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
OWNER_ONLY_FIELDS = ("template_dir", "engine_session_mutex")
OWNER = "wyrelog/wyl-handle.c"
OWNED_ENGINE_ALLOWLIST = {
    OWNER,
    "wyrelog/wyl-engine.c",
    "wyrelog/wyl-engine-private.h",
    "wyrelog/fact/compound.c",
    "wyrelog/fact/query.c",
    "wyrelog/fact/replay.c",
}
OWNER_FUNCTION_ALLOWLIST = {
    "classify_audit_projection",
    "clear_pending_deltas",
    "engine_pair_unavailable",
    "fail_partial_engine_pair_mutation_locked",
    "flush_pending_deltas",
    "poison_engine_pair_locked",
    "probe_audit_projection_relation",
    "repair_engine_pair_after_projection_failure",
    "replace_engine_pair",
    "replace_live_engine_pair_serialized",
    "step_delta_engine_and_flush",
    "wyl_engine_session_acquire",
    "wyl_handle_buffer_delta_cb",
    "wyl_handle_complete_shutdown",
    "wyl_handle_dup_engine_symbol_locked",
    "wyl_handle_engine_contains_locked",
    "wyl_handle_engine_decide_locked",
    "wyl_handle_engine_insert_locked",
    "wyl_handle_engine_pair_is_poisoned",
    "wyl_handle_engine_pair_is_ready",
    "wyl_handle_engine_remove_locked",
    "wyl_handle_engine_set_delta_callback_locked",
    "wyl_handle_engine_step_delta_locked",
    "wyl_handle_finalize",
    "wyl_handle_init",
    "wyl_handle_insert_audit_fact",
    "wyl_handle_intern_engine_symbol_locked",
    "wyl_handle_intern_guard_symbol",
    "wyl_handle_intern_symbol_on_engine",
    "wyl_handle_load_policy_store_audit_events",
    "wyl_handle_load_policy_store_audit_facts",
    "wyl_handle_load_policy_store_direct_permissions",
    "wyl_handle_load_policy_store_permission_state_events",
    "wyl_handle_load_policy_store_permission_states",
    "wyl_handle_load_policy_store_principal_events",
    "wyl_handle_load_policy_store_principal_states",
    "wyl_handle_load_policy_store_role_memberships",
    "wyl_handle_load_policy_store_role_permissions",
    "wyl_handle_load_policy_store_session_events",
    "wyl_handle_load_policy_store_session_states",
    "engine_session_lock_owner",
    "wyl_handle_make_engine_compound_locked",
    "wyl_handle_make_guard_binary_compound",
    "wyl_handle_make_guard_cmp_compound",
    "wyl_handle_make_guard_context_compound_locked",
    "wyl_handle_make_guard_expr_compound",
    "wyl_handle_make_guard_tag_compound",
    "wyl_handle_make_guard_unary_compound",
    "wyl_handle_make_read_engine_compound_locked",
    "wyl_handle_open_engine_pair",
    "wyl_handle_open_with_options",
    "wyl_handle_poison_engine_pair",
    "wyl_handle_reconcile_committed_engine_pair",
    "wyl_handle_replay_delta_insert_locked",
    "wyl_handle_seed_perm_arm_rule_on_engine",
    "wyl_handle_seed_perm_arm_rules",
    "wyl_handle_shutdown_ordered",
}
CONTROL_WORDS = {"if", "for", "while", "switch"}


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


def top_level_functions(source: str) -> list[tuple[str, str]]:
    """Return top-level C function names and bodies from already-masked text."""
    functions = []
    depth = 0
    start = 0
    name = None
    for index, char in enumerate(source):
        if char == "{":
            if depth == 0:
                prefix = source[max(0, index - 2000):index]
                match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*"
                                  r"\([^;{}]*\)\s*$", prefix, re.DOTALL)
                if match and match.group(1) not in CONTROL_WORDS:
                    name = match.group(1)
                    start = index
            depth += 1
        elif char == "}" and depth > 0:
            depth -= 1
            if depth == 0 and name is not None:
                functions.append((name, source[start:index + 1]))
                name = None
    return functions


def check(sources: dict[str, str]) -> list[str]:
    errors = []
    legacy = re.compile(r"\b(?:" + "|".join(map(re.escape,
                        LEGACY_HANDLE_OPERATIONS)) + r")\s*\(")
    fields = re.compile(r"->(?:" + "|".join(map(re.escape,
                        AGGREGATE_FIELDS)) + r")\b")
    owner_fields = re.compile(r"->(?:" + "|".join(map(re.escape,
                              AGGREGATE_FIELDS + OWNER_ONLY_FIELDS)) + r")\b")
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
        if path != OWNER and raw_lock.search(source):
            errors.append(f"untyped engine lock outside owner: {path}")
        if path == OWNER:
            for name, body in top_level_functions(source):
                if (owner_fields.search(body) or owned.search(body)
                        or raw_lock.search(body)) and name not in OWNER_FUNCTION_ALLOWLIST:
                    errors.append(
                        f"owner aggregate access outside function allowlist: {name}")
    return sorted(set(errors))


def self_test() -> int:
    accepted = {
        OWNER: "static void allowed_owner(WylHandle *h) { (void) h; }",
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
    owner_mutants = (
        "static void bad_read(WylHandle *h) { h->read_engine = 0; }",
        "static void bad_template(WylHandle *h) { h->template_dir = 0; }",
        "static void bad_mutex(WylHandle *h) { g_rec_mutex_lock(&h->engine_session_mutex); }",
        "static void bad_owned(WylEngine *e) { wyl_engine_owned_step(e); }",
    )
    for mutant in owner_mutants:
        if not check({OWNER: mutant}):
            print(f"self-test accepted owner mutant: {mutant}", file=sys.stderr)
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

#!/usr/bin/env python3
"""Reject handle-engine entry points that bypass the engine session."""

from pathlib import Path
import re
import sys


LOCKED_ENTRY_POINTS = (
    "wyl_handle_shutdown_ordered",
    "wyl_handle_load_policy_store_audit_events",
    "wyl_handle_engine_pair_is_ready",
    "wyl_handle_engine_pair_is_poisoned",
    "wyl_handle_poison_engine_pair",
    "wyl_handle_open_engine_pair",
    "wyl_handle_reconcile_committed_engine_pair",
    "wyl_handle_intern_engine_symbol",
    "wyl_handle_dup_engine_symbol",
    "wyl_handle_make_engine_compound",
    "wyl_handle_make_read_engine_compound",
    "wyl_handle_make_guard_context_compound",
    "wyl_handle_engine_insert",
    "wyl_handle_engine_remove",
    "wyl_handle_engine_step_delta",
    "wyl_handle_engine_set_delta_callback",
    "wyl_handle_load_policy_store_role_permissions",
    "wyl_handle_load_policy_store_role_memberships",
    "wyl_handle_load_policy_store_direct_permissions",
    "wyl_handle_load_policy_store_permission_states",
    "wyl_handle_load_policy_store_permission_state_events",
    "wyl_handle_load_policy_store_principal_states",
    "wyl_handle_load_policy_store_principal_events",
    "wyl_handle_load_policy_store_session_states",
    "wyl_handle_load_policy_store_session_events",
    "wyl_handle_insert_audit_fact",
    "wyl_handle_load_policy_store_audit_facts",
    "wyl_handle_engine_contains",
    "wyl_handle_engine_decide",
    "wyl_handle_replay_delta_insert",
    "wyl_decide",
)

POISON_DISTINGUISHED_ENTRY_POINTS = {
    "reload_policy_snapshot": "wyl-perm.c",
    "wyl_perm_grant": "wyl-perm.c",
    "wyl_perm_revoke": "wyl-perm.c",
    "wyl_role_grant": "wyl-perm.c",
    "wyl_role_revoke": "wyl-perm.c",
    "reload_session_snapshot": "wyl-session.c",
    "login_skip_mfa_allowed": "wyl-session.c",
    "insert_principal_event_fact": "wyl-session.c",
    "insert_session_event_fact": "wyl-session.c",
    "apply_principal_state_mutation": "wyl-session.c",
    "apply_session_state_mutation": "wyl-session.c",
    "apply_login_state_mutation": "wyl-session.c",
}


def function_body(source: str, name: str) -> str | None:
    match = re.search(rf"\b{re.escape(name)}\s*\([^;]*?\)\s*\{{", source,
                      flags=re.DOTALL)
    if match is None:
        return None
    start = match.end() - 1
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-engine-session-boundary.py SOURCE_ROOT",
              file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    handle_path = root / "wyrelog" / "wyl-handle.c"
    decide_path = root / "wyrelog" / "wyl-decide.c"
    sources = {
        "wyl_decide": decide_path.read_text(encoding="utf-8"),
        "handle": handle_path.read_text(encoding="utf-8"),
        "wyl-perm.c": (root / "wyrelog" / "wyl-perm.c").read_text(
            encoding="utf-8"),
        "wyl-session.c": (root / "wyrelog" / "wyl-session.c").read_text(
            encoding="utf-8"),
    }

    errors = []
    for name in LOCKED_ENTRY_POINTS:
        source = sources["wyl_decide"] if name == "wyl_decide" else sources["handle"]
        body = function_body(source, name)
        if body is None:
            errors.append(f"missing protected entry point: {name}")
        elif "wyl_handle_lock_engine_session" not in body:
            errors.append(f"engine session acquisition missing: {name}")

    reload_body = function_body(sources["handle"],
                                "wyl_handle_reload_engine_pair")
    if reload_body is None or "replace_live_engine_pair_serialized" not in reload_body:
        errors.append("reload must delegate to serialized replacement")
    if reload_body is not None and re.search(r"\breplace_engine_pair\s*\(", reload_body):
        errors.append("reload bypasses serialized replacement")

    for name, source_name in POISON_DISTINGUISHED_ENTRY_POINTS.items():
        body = function_body(sources[source_name], name)
        if body is None:
            errors.append(f"missing poison-sensitive entry point: {name}")
        elif "wyl_handle_engine_pair_is_poisoned" not in body:
            errors.append(f"poison is conflated with an unopened pair: {name}")

    raw_getter = re.compile(r"\bwyl_handle_get_(?:read|delta)_engine\s*\(")
    for path in (root / "wyrelog").rglob("*.c"):
        if path == handle_path:
            continue
        if raw_getter.search(path.read_text(encoding="utf-8")):
            errors.append(f"raw borrowed engine used outside owner: {path.relative_to(root)}")

    if errors:
        print("engine-session boundary violations:", *errors, sep="\n  ",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

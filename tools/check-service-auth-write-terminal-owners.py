#!/usr/bin/env python3
"""Pin every production WRITE lease owner to the exact terminal cleanup.

Production owners of a ``WylServiceAuthWriteLease`` must relinquish it through
``wyl_service_auth_write_lease_release_terminal``.  The ordinary
``wyl_service_auth_write_lease_release`` and ``wyl_service_auth_write_lease_free``
entry points remain only as the terminal primitive's own building blocks, so
they are forbidden in call position anywhere in ``wyrelog/**/*.c`` except inside
the two primitive definitions themselves (``_free`` legitimately calls
``_release`` while consuming the lease).

The scan is deliberately lightweight: it masks comments and string literals,
walks each top-level function-definition body, and inspects call-position
identifiers.  File-scope prototypes and the ``G_DEFINE_AUTOPTR_CLEANUP_FUNC``
registration never appear inside a definition body, so they are ignored.
"""

import re
import sys
from pathlib import Path

RELEASE = "wyl_service_auth_write_lease_release"
FREE = "wyl_service_auth_write_lease_free"
TERMINAL = "wyl_service_auth_write_lease_release_terminal"

# The only definitions allowed to call the ordinary release/free tokens are the
# two primitives themselves; ``_free`` internally consumes an active lease via
# ``_release``.
ALLOWLIST = {RELEASE, FREE}

# Every migrated non-HTTP production owner must relinquish through exactly one
# terminal call.  Keeping the roster here pins the migration: a renamed or
# dropped owner, or a second/zero terminal call, fails the guard.
MIGRATED_OWNERS = {
    # ``service_mutation_finish`` is the archetype: a second terminal call
    # finalizes the lease on the fault-injection-only stuck-claim branch.
    "service_mutation_finish": 2,
    "resume_committed_handoff": 1,
    "wyl_service_credential_operation_coordinator_purge_retired": 1,
    "wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded": 1,
    "resolve_current_attention": 1,
    "wyl_service_credential_operation_coordinator_maintain_expired_locked": 1,
    "service_exchange_authority_dispose": 1,
    "wyl_service_exchange_authority_rollback": 1,
    "wyl_service_exchange_recover_committed": 1,
    "run_bootstrap_publication": 1,
    "wyl_handle_reload_engine_pair": 1,
    "wyl_service_permission_maintenance_dry_run": 1,
    "wyl_service_permission_maintenance_apply": 1,
}


def masked(text: str) -> str:
    pattern = re.compile(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S
    )
    return pattern.sub(lambda match: " " * len(match.group(0)), text)


def function_name_before_brace(header: str) -> str | None:
    """Return the function name for a definition header ending at ``{``.

    ``header`` is the source between the previous top-level ``;``/``}`` and the
    opening brace.  A definition ends with a balanced parameter list, so the
    name is the identifier preceding the ``(`` that opens that list.  Function
    pointer parameters keep their own parentheses, hence the backward balance.
    """
    stripped = header.rstrip()
    if not stripped.endswith(")"):
        return None
    depth = 0
    index = len(stripped) - 1
    while index >= 0:
        char = stripped[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                break
        index -= 1
    if index < 0:
        return None
    end = index
    while end > 0 and stripped[end - 1].isspace():
        end -= 1
    begin = end
    while begin > 0 and (stripped[begin - 1].isalnum() or stripped[begin - 1] == "_"):
        begin -= 1
    name = stripped[begin:end]
    return name or None


def iter_functions(source: str):
    """Yield ``(name, body)`` for every top-level function definition."""
    length = len(source)
    index = 0
    segment_start = 0
    while index < length:
        char = source[index]
        if char == ";":
            segment_start = index + 1
        elif char == "}":
            # A stray top-level close cannot precede a definition body.
            segment_start = index + 1
        elif char == "{":
            depth = 0
            close = index
            while close < length:
                if source[close] == "{":
                    depth += 1
                elif source[close] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                close += 1
            name = function_name_before_brace(source[segment_start:index])
            if name is not None:
                yield name, source[index + 1 : close]
            index = close + 1
            segment_start = index
            continue
        index += 1


def calls(body: str, symbol: str) -> int:
    # ``_release`` must not match ``_release_terminal``; the trailing ``\s*\(``
    # guarantees the identifier ends at the call, never mid-token.
    return len(re.findall(r"\b" + re.escape(symbol) + r"\s*\(", body))


def check_source(root: Path) -> list[str]:
    errors: list[str] = []
    terminal_counts: dict[str, int] = {name: 0 for name in MIGRATED_OWNERS}
    files = sorted(
        path
        for path in (root / "wyrelog").rglob("*.c")
        if "tests" not in path.parts
    )
    if not files:
        return [f"no production sources found under {root / 'wyrelog'}"]
    for path in files:
        source = masked(path.read_text(encoding="utf-8"))
        rel = path.relative_to(root)
        for name, body in iter_functions(source):
            if name not in ALLOWLIST:
                for symbol in (RELEASE, FREE):
                    if calls(body, symbol):
                        errors.append(
                            f"{rel}:{name} calls {symbol}; production WRITE "
                            f"lease owners must use {TERMINAL}"
                        )
            if name in terminal_counts:
                terminal_counts[name] += calls(body, TERMINAL)
    for name, expected in MIGRATED_OWNERS.items():
        found = terminal_counts[name]
        if found != expected:
            errors.append(
                f"migrated owner {name} must contain exactly {expected} "
                f"{TERMINAL} call(s); found {found}"
            )
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} SOURCE_ROOT", file=sys.stderr)
        return 2
    errors = check_source(Path(sys.argv[1]))
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Prove the WRITE lease terminal-owner guard rejects representative drift."""

import subprocess
import sys
import tempfile
from pathlib import Path

# Each migrated owner and the exact number of terminal calls it must own.  The
# archetype ``service_mutation_finish`` finalizes a stuck-claim lease with a
# second terminal call, so it owns two.
OWNERS = {
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

# The two primitives are the only definitions allowed to call the ordinary
# release/free tokens; ``_free`` consumes an active lease through ``_release``.
PRIMITIVES = """\
wyrelog_error_t
wyl_service_auth_write_lease_release (WylServiceAuthWriteLease *lease) {
  return WYRELOG_E_OK;
}
void
wyl_service_auth_write_lease_free (WylServiceAuthWriteLease *lease) {
  if (wyl_service_auth_write_lease_release (lease) != WYRELOG_E_OK)
    return;
}
"""


def owner_definition(name: str, terminal_calls: int) -> str:
    body = "".join(
        f"  wyl_service_auth_write_lease_release_terminal (&lease);\n"
        for _ in range(terminal_calls)
    )
    return f"static wyrelog_error_t\n{name} (void) {{\n{body}  return WYRELOG_E_OK;\n}}\n"


def base() -> str:
    parts = [PRIMITIVES]
    for name, count in OWNERS.items():
        parts.append(owner_definition(name, count))
    return "\n".join(parts)


BASE = base()

# A file-scope prototype and the autoptr registration reference the forbidden
# tokens outside any definition body; the guard must accept them.
FILE_SCOPE_TAIL = (
    "\nvoid wyl_service_auth_write_lease_free (WylServiceAuthWriteLease *lease);\n"
    "G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthWriteLease,\n"
    "    wyl_service_auth_write_lease_free)\n"
)


def run(guard: str, text: str) -> int:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "wyrelog" / "auth"
        source.mkdir(parents=True)
        (source / "fixture.c").write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, guard, directory], check=False
        ).returncode


def main() -> int:
    guard = sys.argv[1]

    accepted = [
        BASE,  # primitive pair + every migrated owner terminalized
        BASE + FILE_SCOPE_TAIL,  # file-scope prototype / autoptr registration
    ]

    rejected = [
        # A new owner calling the ordinary release entry point.
        BASE
        + "\nstatic wyrelog_error_t rogue_release (void) {\n"
        "  return wyl_service_auth_write_lease_release (lease);\n}\n",
        # A new owner calling the ordinary free entry point.
        BASE
        + "\nstatic void rogue_free (void) {\n"
        "  wyl_service_auth_write_lease_free (lease);\n}\n",
        # A migrated owner reverting to the ordinary release+free pair.
        BASE.replace(
            "static wyrelog_error_t\nresume_committed_handoff (void) {\n"
            "  wyl_service_auth_write_lease_release_terminal (&lease);\n",
            "static wyrelog_error_t\nresume_committed_handoff (void) {\n"
            "  wyl_service_auth_write_lease_release (lease);\n"
            "  wyl_service_auth_write_lease_free (lease);\n",
        ),
        # A migrated owner that stopped relinquishing its lease at all.
        BASE.replace(
            "static wyrelog_error_t\nrun_bootstrap_publication (void) {\n"
            "  wyl_service_auth_write_lease_release_terminal (&lease);\n",
            "static wyrelog_error_t\nrun_bootstrap_publication (void) {\n",
        ),
        # A migrated owner that grew a second, unexpected terminal call.
        BASE.replace(
            "static wyrelog_error_t\nresolve_current_attention (void) {\n"
            "  wyl_service_auth_write_lease_release_terminal (&lease);\n",
            "static wyrelog_error_t\nresolve_current_attention (void) {\n"
            "  wyl_service_auth_write_lease_release_terminal (&lease);\n"
            "  wyl_service_auth_write_lease_release_terminal (&lease);\n",
        ),
        # A migrated owner renamed away breaks the pinned roster.
        BASE.replace(
            "wyl_service_permission_maintenance_apply (void)",
            "wyl_service_permission_maintenance_apply_renamed (void)",
        ),
    ]

    if any(run(guard, text) != 0 for text in accepted):
        return 1
    if any(run(guard, text) == 0 for text in rejected):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

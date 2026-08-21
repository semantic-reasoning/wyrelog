#!/usr/bin/env python3
"""Guard the DuckDB v1.5.5 fixed-WAL lifecycle evidence boundary."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
source = (
    root / "tests" / "test-secure-duckdb-recording-filesystem.cc"
).read_text(encoding="utf-8")
meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
docs = (
    root / "docs" / "duckdb-fixed-wal-lifecycle-evidence.md"
).read_text(encoding="utf-8")

for forbidden in (
    "replacement_gate",
    "ObserveCheckpointSidecarRemoval",
    "PauseCheckpointMainOperation",
    "checkpoint_payload",
    "debug_checkpoint_sleep_ms",
):
    if forbidden in source:
        raise SystemExit(
            f"fixed WAL evidence regained a timing/filesystem gate: {forbidden}"
        )

required_source = (
    "assert_checkpoint_abort_child_exact_grammar",
    "assert_recovery_replacement_exact_grammar",
    "assert_incomplete_recovery_reopen_exact_grammar",
    '"BEFORE_WAL_FINISH"',
    '"BEFORE_HEADER"',
    "Checkpoint aborted before header write because of PRAGMA",
    "Checkpoint aborted before truncate because of PRAGMA",
    "source_155_open_flags (18)",
    "source_155_open_flags (1)",
    'event->operation == "close" || event->operation == "destroy"',
    "move.live_handles.size (), ==, 2",
    "assert_fixed_wal_rows",
    "drain_thread_until",
    "checkpoint concurrency threads did not drain within ",
)
for token in required_source:
    if token not in source:
        raise SystemExit(f"fixed WAL lifecycle grammar drifted: {token}")

helper_start = source.index("checkpoint_with_concurrent_commit (")
helper_end = source.index(
    "\nstatic void\ndump_handle_lifecycle_if_requested", helper_start
)
helper = source[helper_start:helper_end]
timeout_start = helper.index("if (!commit_finished)")
timeout_end = helper.index(
    'g_error ("checkpoint-WAL commit did not finish within 5000 ms");',
    timeout_start,
)
timeout_cleanup = helper[timeout_start:timeout_end]
required_timeout_cleanup = (
    "release_after_wal_start (latch);",
    "commit_drained = drain_thread_until",
    "checkpoint_drained = drain_thread_until",
)
for token in required_timeout_cleanup:
    if token not in timeout_cleanup:
        raise SystemExit(
            f"commit timeout lost bounded thread cleanup: {token}"
        )
if timeout_cleanup.index("release_after_wal_start (latch);") > min(
    timeout_cleanup.index("commit_drained = drain_thread_until"),
    timeout_cleanup.index("checkpoint_drained = drain_thread_until"),
):
    raise SystemExit("commit timeout must release the latch before draining")

named_tests = (
    "duckdb-fixed-wal-successful-checkpoint",
    "duckdb-fixed-wal-pre-move-abort-reopen",
    "duckdb-fixed-wal-interrupted-recovery",
)
for token in named_tests:
    if meson.count(token) != 1:
        raise SystemExit(f"focused seam test registration drifted: {token}")

seam_start = meson.index(
    "test_duckdb_after_walstart = executable("
)
seam_end = meson.index("\nendif", seam_start)
seam = meson[seam_start:seam_end]
for token in named_tests:
    if token not in seam:
        raise SystemExit(f"{token} escaped the native seam target")

for workflow_name in ("ci-pr.yml", "ci-main.yml"):
    workflow = (
        root / ".github" / "workflows" / workflow_name
    ).read_text(encoding="utf-8")
    job_start = workflow.index("  duckdb-checkpoint-seam:")
    job_end = workflow.index("\n  build-windows:", job_start)
    job = workflow[job_start:job_end]
    for token in named_tests + (
        "Repeat fixed WAL lifecycle evidence",
        "for iteration in 1 2 3 4 5",
    ):
        if token not in job:
            raise SystemExit(
                f"{workflow_name} fixed WAL repeat contract drifted: {token}"
            )

required_docs = (
    "AFTER_WAL_START",
    ".wal.checkpoint -> .wal",
    ".wal.recovery -> .wal",
    "BEFORE_WAL_FINISH",
    "BEFORE_HEADER",
    "complete relevant live-handle set",
    "v1.5.5",
)
for token in required_docs:
    if token not in docs:
        raise SystemExit(f"fixed WAL upgrade contract drifted: {token}")

print("DuckDB fixed WAL lifecycle boundary: OK")

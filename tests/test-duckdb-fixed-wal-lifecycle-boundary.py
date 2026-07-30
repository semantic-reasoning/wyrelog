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
)
for token in required_source:
    if token not in source:
        raise SystemExit(f"fixed WAL lifecycle grammar drifted: {token}")

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
seam_end = meson.index("\n  endif\nendif", seam_start)
seam = meson[seam_start:seam_end]
for token in named_tests:
    if token not in seam:
        raise SystemExit(f"{token} escaped the non-Windows seam target")

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

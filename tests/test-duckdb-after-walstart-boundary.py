#!/usr/bin/env python3
"""Pin the DuckDB v2.0.0 AFTER_WAL_START test seam to its source boundary."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
wrap = (root / "subprojects" / "duckdb-source.wrap").read_text(
    encoding="utf-8")
patch_path = (
    root / "subprojects" / "packagefiles" / "duckdb-source"
    / "0002-test-seams.patch")
patch = patch_path.read_text(encoding="utf-8")

required_wrap = (
    "source_filename = duckdb-v2.0.0.tar.gz",
    "source_hash = "
    "7e89053255046bfb26afbd7f524a2fb84df7dbef496aa911ea35e4a1182fdc00",
    "duckdb-source/0002-test-seams.patch",
)
for token in required_wrap:
    if wrap.count(token) != 1:
        raise SystemExit(f"DuckDB v2.0.0 seam wrap boundary drifted: {token}")

# 2.0 takes the checkpoint context from the wrapper on the line after
# WALStartCheckpoint; the seam must follow that and nothing else.
source_boundary = (
    " \tauto has_wal = storage_manager.WALStartCheckpoint(meta_block, options, "
    "active_checkpoint);\n"
    " \tcheckpoint_context = active_checkpoint.GetCheckpointContext();\n"
    " \n"
    "+#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START"
)
if source_boundary not in patch:
    raise SystemExit(
        "AFTER_WAL_START must remain immediately after WALStartCheckpoint")

callback_boundary = (
    "+\tif (has_wal && test_options.test_after_wal_start) {\n"
    '+\t\ttest_options.test_after_wal_start("AFTER_WAL_START", '
    "test_options.test_after_wal_start_context);\n"
    "+\t}"
)
if patch.count(callback_boundary) != 1:
    raise SystemExit("AFTER_WAL_START callback phase or call count drifted")

if patch.index(callback_boundary) > patch.index(
        " \tauto checkpoint_sleep_ms = "
        "Settings::Get<DebugCheckpointSleepMsSetting>"):
    raise SystemExit("AFTER_WAL_START must precede debug sleep and serialization")

if patch.count("#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START") != 2:
    raise SystemExit("the seam must remain fully compile-time test-only")

print("DuckDB AFTER_WAL_START source boundary: OK")

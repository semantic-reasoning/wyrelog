#!/usr/bin/env python3
"""Pin the DuckDB v1.5.5 AFTER_WAL_START test seam to its source boundary."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
wrap = (root / "subprojects" / "duckdb-amalgamated.wrap").read_text(
    encoding="utf-8")
patch_path = (
    root / "subprojects" / "packagefiles" / "duckdb-amalgamated"
    / "0003-test-after-walstart-rendezvous.patch")
patch = patch_path.read_text(encoding="utf-8")

required_wrap = (
    "source_filename = libduckdb-src-v1.5.5.zip",
    "source_hash = "
    "102813201cf8072b8a56b6013978963f3c89202a148fd152d06909477e36fbf8",
    "duckdb-amalgamated/0003-test-after-walstart-rendezvous.patch",
)
for token in required_wrap:
    if wrap.count(token) != 1:
        raise SystemExit(f"DuckDB v1.5.5 seam wrap boundary drifted: {token}")

source_boundary = (
    "+\tauto has_wal = storage_manager.WALStartCheckpoint(meta_block, options);\n"
    "+\n"
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
        "+\tauto checkpoint_sleep_ms = "
        "Settings::Get<DebugCheckpointSleepMsSetting>"):
    raise SystemExit("AFTER_WAL_START must precede debug sleep and serialization")

if patch.count("#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START") != 2:
    raise SystemExit("the seam must remain fully compile-time test-only")

print("DuckDB AFTER_WAL_START source boundary: OK")

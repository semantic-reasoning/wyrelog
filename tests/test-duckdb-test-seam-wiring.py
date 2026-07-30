#!/usr/bin/env python3
"""Guard separation between regular and seam-enabled DuckDB targets."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
package = (
    root / "subprojects" / "packagefiles" / "duckdb-amalgamated"
    / "meson.build").read_text(encoding="utf-8")
parent = (root / "meson.build").read_text(encoding="utf-8")

regular_start = package.index("duckdb_lib = static_library(")
regular_end = package.index("\n)\n", regular_start)
regular = package[regular_start:regular_end]
if "WYL_DUCKDB_TEST_AFTER_WAL_START" in regular:
    raise SystemExit("regular duckdb_lib must compile without the test seam")

seam_start = package.index(
    "duckdb_test_seam_lib = static_library('duckdb-test-after-wal-start'")
seam_end = package.index("\n  )\n", seam_start)
seam = package[seam_start:seam_end]
if seam.count("duckdb.cpp") != 1:
    raise SystemExit("test seam must compile the pinned amalgamation directly")
if "duckdb_test_seam_compile_args" not in seam:
    raise SystemExit("test seam target must receive its compile-time macro")
if "install : false" not in seam or "build_by_default : false" not in seam:
    raise SystemExit("test seam target must remain non-installed and test-only")

if package.count("'-DWYL_DUCKDB_TEST_AFTER_WAL_START=1'") != 1:
    raise SystemExit("the seam macro must be defined for exactly one dependency")
if "if host_machine.system() != 'windows'" not in package:
    raise SystemExit("the seam variant must not become Windows runtime work")
if "duckdb_test_seam_dep = duckdb_subproject.get_variable(" not in parent:
    raise SystemExit("the source-pinned parent must expose the test dependency")

print("DuckDB test seam dependency boundary: OK")

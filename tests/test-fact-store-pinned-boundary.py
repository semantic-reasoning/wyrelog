#!/usr/bin/env python3
"""Lock the pinned identity opener to typed, bounded storage authority."""

from pathlib import Path
import sys

root = Path(sys.argv[1])
core = (root / "wyrelog/fact/store-identity-private.c").read_text()
bridge = (root / "wyrelog/fact/secure-duckdb-bridge-private.cc").read_text()
header = (root / "wyrelog/fact/store-private.h").read_text()
types = (
    root / "wyrelog/fact/store-identity-types-private.h"
).read_text()
windows = (
    root / "wyrelog/fact/secure-duckdb-bridge-windows-private.c"
).read_text()

for forbidden in ("#include <duckdb.h>", "#include <duckdb.hpp>", "ToString"):
    if forbidden in core:
        raise SystemExit(f"pure-C identity core contains provider token: {forbidden}")

for required in (
    "WYL_FACT_STORE_IDENTITY_CELL_NULL",
    "WYL_FACT_STORE_IDENTITY_CELL_INT64",
    "WYL_FACT_STORE_IDENTITY_CELL_BYTES",
    "VALUES (?,?)",
    "BEGIN TRANSACTION;",
    "ROLLBACK;",
):
    if required not in core:
        raise SystemExit(f"typed identity core lost contract: {required}")

for forbidden in (
    "/proc/self/fd",
    "LocalFileSystem",
    "ToString",
    "wyl_fact_store_t **",
):
    if forbidden in bridge:
        raise SystemExit(f"pinned source adapter escaped its boundary: {forbidden}")

for required in (
    "connection->Prepare (sql)",
    "GetValue<int64_t>",
    "GetValue<duckdb::string>",
    "bridge_new_bounded",
    "bridge_populate_bounded",
    "DetachLeaseOwnership",
    "bridge_finalize_storage",
    "PinnedLifecycleResults",
    "reduce_pinned_lifecycle",
    "pinned_authority_revalidate",
    "wyl_fact_artifact_mutation_lease_revalidate",
    "WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT",
    "WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE",
):
    if required not in bridge:
        raise SystemExit(f"pinned source adapter lost contract: {required}")

if "preserve_first_error" in bridge:
    raise SystemExit("pinned lifecycle collapsed distinct stage authority")

if "unsuitable" not in header or "security-sensitive provisioning" not in header:
    raise SystemExit("legacy pathname warning is missing")
if "returns no live DuckDB handle" not in types:
    raise SystemExit("pinned one-shot handle boundary is missing")
if "WYL_FACT_STORE_IDENTITY_RESULT_OPEN" not in windows:
    raise SystemExit("Windows fail-closed result classification is missing")

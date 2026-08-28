#!/usr/bin/env python3
"""Pin the DuckDB v1.5.5 transaction-control failure seam."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
wrap = (root / "subprojects" / "duckdb-amalgamated.wrap").read_text(
    encoding="utf-8"
)
patch = (
    root
    / "subprojects"
    / "packagefiles"
    / "duckdb-amalgamated"
    / "0003-test-after-walstart-rendezvous.patch"
).read_text(encoding="utf-8")

required_wrap = (
    "source_filename = libduckdb-src-v1.5.5.zip",
    "source_hash = "
    "102813201cf8072b8a56b6013978963f3c89202a148fd152d06909477e36fbf8",
    "duckdb-amalgamated/0003-test-after-walstart-rendezvous.patch",
)
for token in required_wrap:
    if wrap.count(token) != 1:
        raise SystemExit(f"DuckDB v1.5.5 transaction seam drifted: {token}")

fields = (
    "+#ifdef WYL_DUCKDB_TEST_TRANSACTION_CONTROL\n"
    "+\t//! Wyrelog's source-pinned transaction-control failure seam. These fields\n"
    "+\t//! are absent from regular DuckDB builds and are not SQL-visible controls.\n"
    "+\tusing transaction_control_callback_t = bool (*)(const char *phase, "
    "void *context);\n"
    "+\ttransaction_control_callback_t test_transaction_control = nullptr;\n"
    "+\tvoid *test_transaction_control_context = nullptr;\n"
    "+#endif"
)
if patch.count(fields) != 1:
    raise SystemExit("transaction-control callback fields drifted")

commit = (
    "+\t\t\t// explicitly commit the current transaction\n"
    "+#ifdef WYL_DUCKDB_TEST_TRANSACTION_CONTROL\n"
    "+\t\t\tauto &test_options = DBConfig::GetConfig(client).options;\n"
    "+\t\t\tif (test_options.test_transaction_control &&\n"
    "+\t\t\t    test_options.test_transaction_control(\"BEFORE_COMMIT\",\n"
    "+\t\t\t        test_options.test_transaction_control_context)) {\n"
    "+\t\t\t\tthrow PermissionException(\"Test-injected COMMIT failure\");\n"
    "+\t\t\t}\n"
    "+#endif\n"
    "+\t\t\tclient.transaction.Commit();"
)
rollback = (
    "+\t\t} else {\n"
    "+#ifdef WYL_DUCKDB_TEST_TRANSACTION_CONTROL\n"
    "+\t\t\tauto &test_options = DBConfig::GetConfig(client).options;\n"
    "+\t\t\tif (info->type == TransactionType::ROLLBACK &&\n"
    "+\t\t\t    test_options.test_transaction_control &&\n"
    "+\t\t\t    test_options.test_transaction_control(\"BEFORE_ROLLBACK\",\n"
    "+\t\t\t        test_options.test_transaction_control_context)) {\n"
    "+\t\t\t\tthrow PermissionException(\"Test-injected ROLLBACK failure\");\n"
    "+\t\t\t}\n"
    "+#endif\n"
    "+\t\t\t// Explicitly rollback the current transaction"
)
if patch.count(commit) != 1 or patch.count(rollback) != 1:
    raise SystemExit("transaction-control callbacks left their branch-local boundaries")
if patch.count("+#ifdef WYL_DUCKDB_TEST_TRANSACTION_CONTROL") != 3:
    raise SystemExit("transaction-control seam must have exactly three compile guards")
if patch.count('test_transaction_control("BEFORE_COMMIT"') != 1:
    raise SystemExit("BEFORE_COMMIT phase drifted")
if patch.count('test_transaction_control("BEFORE_ROLLBACK"') != 1:
    raise SystemExit("BEFORE_ROLLBACK phase drifted")

print("DuckDB valid transaction-control source boundary: OK")

#!/usr/bin/env python3
"""Pin the DuckDB v2.0.0 transaction-control failure seam."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
wrap = (root / "subprojects" / "duckdb-source.wrap").read_text(
    encoding="utf-8"
)
patch = (
    root
    / "subprojects"
    / "packagefiles"
    / "duckdb-source"
    / "0002-test-seams.patch"
).read_text(encoding="utf-8")

required_wrap = (
    "source_filename = duckdb-v2.0.0.tar.gz",
    "source_hash = "
    "7e89053255046bfb26afbd7f524a2fb84df7dbef496aa911ea35e4a1182fdc00",
    "duckdb-source/0002-test-seams.patch",
)
for token in required_wrap:
    if wrap.count(token) != 1:
        raise SystemExit(f"DuckDB v2.0.0 transaction seam drifted: {token}")

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

# Each callback sits in its own branch, after the autocommit refusal and
# immediately before the operation it can fail.
commit = (
    " \t\t\tthrow TransactionException(\"cannot commit - no transaction is active\");\n"
    " \t\t}\n"
    "+#ifdef WYL_DUCKDB_TEST_TRANSACTION_CONTROL\n"
    "+\t\t{\n"
    "+\t\t\tauto &test_options = DBConfig::GetConfig(*this).options;\n"
    "+\t\t\tif (test_options.test_transaction_control &&\n"
    "+\t\t\t    test_options.test_transaction_control(\"BEFORE_COMMIT\", "
    "test_options.test_transaction_control_context)) {\n"
    "+\t\t\t\tthrow PermissionException(\"Test-injected COMMIT failure\");\n"
    "+\t\t\t}\n"
    "+\t\t}\n"
    "+#endif\n"
    " \t\ttransaction.Commit();"
)
rollback = (
    " \t\t\tthrow TransactionException(\"cannot rollback - no transaction is active\");\n"
    " \t\t}\n"
    "+#ifdef WYL_DUCKDB_TEST_TRANSACTION_CONTROL\n"
    "+\t\t{\n"
    "+\t\t\tauto &test_options = DBConfig::GetConfig(*this).options;\n"
    "+\t\t\tif (info.type == TransactionType::ROLLBACK && "
    "test_options.test_transaction_control &&\n"
    "+\t\t\t    test_options.test_transaction_control(\"BEFORE_ROLLBACK\", "
    "test_options.test_transaction_control_context)) {\n"
    "+\t\t\t\tthrow PermissionException(\"Test-injected ROLLBACK failure\");\n"
    "+\t\t\t}\n"
    "+\t\t}\n"
    "+#endif\n"
    " \t\tauto &valid_checker = ValidChecker::Get(transaction.ActiveTransaction());"
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

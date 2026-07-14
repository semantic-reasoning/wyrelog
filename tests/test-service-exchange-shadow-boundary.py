#!/usr/bin/env python3
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

required = (
    'PRAGMA main.table_info(',
    'PRAGMA main.foreign_key_list(',
    'pragma_index_list(?, \'main\')',
    'PRAGMA main.index_xinfo(',
    'FROM main.service_exchange_audit_intentions',
    'INSERT INTO main.service_exchange_audit_intentions(',
    'UPDATE main.service_authority_writer_gate',
    'FROM main.service_authority_writer_gate',
    'main.sqlite_schema',
)
missing = [token for token in required if token not in source]
if missing:
    raise SystemExit("missing main qualification: " + ", ".join(missing))

runtime = source[source.index("service_exchange_select_one"):]
forbidden = (
    'FROM service_exchange_audit_intentions',
    'INSERT INTO service_exchange_audit_intentions',
    'UPDATE service_exchange_audit_intentions',
    'DELETE FROM service_exchange_audit_intentions',
)
present = [token for token in forbidden if token in runtime]
if present:
    raise SystemExit("unqualified exchange CRUD: " + ", ".join(present))

receipt = source[source.index("struct _WylServiceExchangeReceipt"):]
receipt = receipt[:receipt.index("};")]
for token in ("wyl_policy_store_t", "WylServiceAuthorityTransaction *",
              "WylServiceAuthWriteLease", "session_id", "jti;"):
    if token in receipt:
        raise SystemExit("receipt leaks authority/raw identity: " + token)
for token in ("projection", "acknowledgement", "receipt_ack"):
    if token in receipt.lower():
        raise SystemExit("receipt boundary grew projection/ACK: " + token)
if "receipt_get_record" in source:
    raise SystemExit("receipt exposes mutable internal record alias")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[opening:pos + 1]
    raise ValueError("unterminated function: " + signature)


def check_typed_recovery_read_boundary(text: str) -> list[str]:
    errors = []
    marker = "service_exchange_require_read_participant"
    try:
        helper = function_body(text, marker + " (")
        load = function_body(
            text, "wyl_policy_store_service_exchange_intention_load\n")
        enumerate_ = function_body(
            text, "wyl_policy_store_service_exchange_intention_enumerate\n")
        append = function_body(
            text, "wyl_policy_store_service_exchange_intention_append\n")
    except (ValueError, IndexError) as error:
        return [str(error)]

    forbidden = (
        "acquire_write_intent", "prepare_commit_evidence", "commit_evidence",
        "service_exchange_receipt", "receipt_take", "INSERT", "UPDATE",
        "DELETE", "sqlite3_exec", "exec_sql", "begin_mutation",
        "commit_mutation", "rollback_mutation", "intention_append",
        "record_credential_last_used", "service_exchange_require_participant",
    )
    for label, body in (("helper", helper), ("load", load),
                        ("enumerate", enumerate_)):
        for token in forbidden:
            if token in body:
                errors.append(f"typed recovery {label} references {token}")
    for label, body in (("load", load), ("enumerate", enumerate_)):
        if body.count(marker) != 1:
            errors.append(f"{label} does not solely enter typed read participant")
        if "transaction_enter_participant" in body:
            errors.append(f"{label} bypasses typed read participant")
        if "FROM main.service_exchange_audit_intentions" not in body:
            errors.append(f"{label} lost exact qualified typed source")
    if "service_exchange_require_participant" not in append:
        errors.append("append no longer requires write participant")
    if marker in append:
        errors.append("append aliases typed read participant")
    return errors


boundary_errors = check_typed_recovery_read_boundary(source)
if boundary_errors:
    raise SystemExit("; ".join(boundary_errors))

# Keep the structural test non-vacuous: representative forbidden mutations
# must be rejected by the same checker used for the production source.
read_call = "service_exchange_require_read_participant (txn, store)"
first_read_call = source.index(read_call, source.index(
    "wyl_policy_store_service_exchange_intention_load\n"))
second_read_call = source.index(read_call, source.index(
    "wyl_policy_store_service_exchange_intention_enumerate\n"))
helper_return_token = (
    "return wyl_policy_store_service_authority_transaction_enter_participant")
helper_return = source.index(helper_return_token, source.index(
    "service_exchange_require_read_participant ("))


def replace_at(text: str, pos: int, old: str, new: str) -> str:
    if text[pos:pos + len(old)] != old:
        raise ValueError("mutant target moved")
    return text[:pos] + new + text[pos + len(old):]


mutants = (
    replace_at(source, first_read_call, read_call,
               "service_exchange_require_participant (txn, store)"),
    replace_at(source, second_read_call, read_call,
               "service_exchange_require_participant (txn, store)"),
    replace_at(source, first_read_call, read_call,
               "wyl_policy_store_service_authority_transaction_enter_participant"
               " (txn, store)"),
    replace_at(source, second_read_call, read_call,
               "wyl_policy_store_service_authority_transaction_enter_participant"
               " (txn, store)"),
    # Direct active-code injections at the exact load call site.  These are
    # intentionally expressions rather than comments/string-only canaries.
    replace_at(source, first_read_call, read_call,
               "(wyl_policy_store_service_authority_prepare_commit_evidence"
               " (txn, store, NULL), " + read_call + ")"),
    replace_at(source, first_read_call, read_call,
               "(wyl_policy_store_service_exchange_receipt_take"
               " (txn, NULL, NULL, store, NULL), " + read_call + ")"),
    # Direct enumerate-body mutation, raw UPDATE, and sqlite3_exec aliases.
    replace_at(source, second_read_call, read_call,
               "(wyl_policy_store_begin_mutation (store), "
               + read_call + ")"),
    replace_at(source, second_read_call, read_call,
               "(exec_sql (store->db, \"UPDATE main."
               "service_exchange_audit_intentions SET outcome='deny';\"), "
               + read_call + ")"),
    replace_at(source, second_read_call, read_call,
               "(sqlite3_exec (store->db, \"DELETE FROM main."
               "service_exchange_audit_intentions;\", NULL, NULL, NULL), "
               + read_call + ")"),
    replace_at(source, helper_return, helper_return_token,
               "wyl_policy_store_service_authority_prepare_commit_evidence"
               " (txn, store, NULL); return "
               "wyl_policy_store_service_authority_transaction_enter_participant"),
    source.replace("rc = service_exchange_require_participant (txn, store);",
                   "rc = service_exchange_require_read_participant (txn, store);",
                   1),
)
for index, mutant in enumerate(mutants):
    if mutant == source or not check_typed_recovery_read_boundary(mutant):
        raise SystemExit(f"typed recovery read boundary mutant {index} escaped")

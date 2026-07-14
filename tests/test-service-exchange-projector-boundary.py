#!/usr/bin/env python3
"""Structural and mutant guard for the private foreground projector."""

from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
header_path = root / "wyrelog/auth/service-exchange-projector-private.h"
source_path = root / "wyrelog/auth/service-exchange-projector-private.c"
header = header_path.read_text()
source = source_path.read_text()
meson = (root / "wyrelog/meson.build").read_text()
public = "\n".join(p.read_text() for p in (root / "wyrelog").glob("*.h"))

PROJECTOR = "wyl_service_exchange_project_committed"
VALIDATOR = "wyl_service_exchange_projection_ack_validate_receipt"
ATOM_A = "wyl_audit_conn_service_exchange_project"
RECEIPT = "wyl_service_exchange_receipt_dup_record"
RECOVERY = "wyl_service_exchange_recover_committed"
RECOVERY_ITEM = "recovery_project_item"


def function_body(text, name):
    matches = list(re.finditer(r"\n(?:static\s+)?(?:G_GNUC_INTERNAL\s+)?"
                               r"wyrelog_error_t\s*\n?"
                               + re.escape(name) + r"\s*\(", text))
    if len(matches) != 1:
        raise ValueError(f"{name} definition count={len(matches)}")
    opening = text.find("{", matches[0].end())
    if opening < 0:
        raise ValueError(f"{name} has no body")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening:index + 1]
    raise ValueError(f"{name} body is unterminated")


def violations(text):
    errors = []
    try:
        projector = function_body(text, PROJECTOR)
        validator = function_body(text, VALIDATOR)
        recovery = function_body(text, RECOVERY)
        recovery_item = function_body(text, RECOVERY_ITEM)
    except ValueError as error:
        return [str(error)]
    boundaries = projector + validator
    outside = (text.replace(projector, "").replace(validator, "")
               .replace(recovery_item, ""))
    if ATOM_A in outside or RECEIPT in outside:
        errors.append("receipt/Atom A consumed outside sole boundaries")
    for body, label in ((projector, "projector"), (validator, "validator")):
        for token in ("wyl_service_auth_authority_validate_available",
                      "wyl_service_auth_write_lease_get_policy_store",
                      "wyl_policy_store_service_authority_transaction_is_active",
                      "wyl_handle_policy_store_pin_current",
                      "wyl_service_exchange_receipt_snapshot_for_active_write",
                      RECEIPT, ATOM_A):
            if body.count(token) != 1:
                errors.append(f"{label} requires exactly one {token}")
        ordered = [body.find(token) for token in (
            "wyl_service_auth_authority_validate_available",
            "wyl_service_auth_write_lease_get_policy_store",
            "wyl_policy_store_service_authority_transaction_is_active",
            "wyl_handle_policy_store_pin_current",
            "wyl_service_exchange_receipt_snapshot_for_active_write",
            RECEIPT, ATOM_A)]
        if ordered != sorted(ordered) or -1 in ordered:
            errors.append(f"{label} lock/validation order changed")
    for forbidden in ("wyl_service_auth_write_lease_release",
                      "wyl_service_auth_write_lease_free",
                      "wyl_service_auth_authority_acquire_read",
                      "wyl_service_auth_authority_acquire_write"):
        if forbidden in boundaries:
            errors.append("borrowed WRITE is released/free/acquired/upgraded")
    recovery_forbidden = (
        "wyl_handle_policy_store_pin_current", "receipt", "commit_evidence",
        "intention_append", "intention_load", "sqlite3_", "audit_intentions",
        ATOM_A,
    )
    for token in recovery_forbidden:
        if token in recovery:
            errors.append("recovery scheduler contains forbidden " + token)
    recovery_order = [recovery.find(token) for token in (
        "wyl_service_auth_authority_acquire_write",
        "wyl_service_auth_write_lease_get_policy_store",
        "wyl_handle_policy_store_capture_generation",
        "wyl_policy_store_service_authority_transaction_begin",
        "wyl_policy_store_service_exchange_intention_enumerate",
        "wyl_policy_store_service_authority_transaction_commit",
        "wyl_service_auth_write_lease_release",
        RECOVERY_ITEM,
    )]
    if recovery_order != sorted(recovery_order) or -1 in recovery_order:
        errors.append("recovery WRITE/enumerate/release order changed")
    for token in ("receipt", "commit_evidence", "intention_append",
                  "intention_load", "sqlite3_", "audit_intentions"):
        if token in recovery_item:
            errors.append("recovery item contains forbidden " + token)
    item_order = [recovery_item.find(token) for token in (
        "wyl_handle_policy_store_pin_current",
        "wyl_handle_policy_store_validate_generation", ATOM_A,
        "wyl_handle_policy_store_unpin")]
    if item_order != sorted(item_order) or -1 in item_order:
        errors.append("recovery item pin/Atom A/unpin order changed")
    if recovery_item.count("wyl_handle_policy_store_pin_current") != 1:
        errors.append("recovery item must acquire exactly one lifecycle pin")
    if recovery_item.count("wyl_handle_policy_store_unpin") != 1:
        errors.append("recovery item must release exactly one lifecycle pin")
    return errors


if "service-exchange-projector-private.h" in public:
    raise SystemExit("projector leaked into a public header")
public_block = meson.split("wyrelog_public_headers", 1)[1].split(")", 1)[0]
if "service-exchange-projector-private.h" in public_block:
    raise SystemExit("projector private header is installed")
for forbidden in ("secret", "raw_session", "raw_jti", "audit_store_path"):
    if forbidden in (header + source).lower():
        raise SystemExit("projector boundary contains forbidden token: "
                         + forbidden)
for symbol in (PROJECTOR, VALIDATOR,
               RECOVERY,
               "wyl_service_exchange_projection_ack_ref",
               "wyl_service_exchange_projection_ack_unref",
               "wyl_service_exchange_projection_ack_dup_record"):
    declaration = re.search(r"G_GNUC_INTERNAL[^;]*\b" + re.escape(symbol)
                            + r"\b", header, re.S)
    if declaration is None:
        raise SystemExit("private symbol lacks hidden declaration: " + symbol)

actual_errors = violations(source)
if actual_errors:
    raise SystemExit("; ".join(actual_errors))

repo_consumers = []
for path in root.rglob("*"):
    if not path.is_file() or path.suffix not in {".c", ".h"}:
        continue
    if path in {header_path, source_path} or "build" in path.parts:
        continue
    text = path.read_text(errors="ignore")
    if PROJECTOR in text or VALIDATOR in text:
        if path.name != "test-service-exchange-projector.c":
            repo_consumers.append(str(path.relative_to(root)))
if repo_consumers:
    raise SystemExit("projector leaked to route/non-test consumers: "
                     + ", ".join(repo_consumers))

# Non-vacuity: every forbidden structural change must be rejected.
mutants = [
    source.replace("wyl_handle_policy_store_pin_current", "removed_pin", 1),
    source.replace("rc = wyl_handle_policy_store_pin_current (handle, &fresh_store);",
                   "rc = wyl_audit_conn_service_exchange_project (conn, "
                   "&projection, &readback);", 1),
    source.replace("if (out_ack != NULL)\n    *out_ack = NULL;",
                   "wyl_service_auth_write_lease_release (write_lease);\n  "
                   "if (out_ack != NULL)\n    *out_ack = NULL;", 1),
    source + "\nwyrelog_error_t\n" + PROJECTOR + " (void) { return 0; }\n",
    source.replace("#endif", "static void decoy(void) { " + ATOM_A
                   + "(); }\n#endif", 1),
    source.replace("wyrelog_error_t rc = wyl_service_auth_authority_acquire_write",
                   "wyl_handle_policy_store_pin_current (handle, NULL);\n  "
                   "wyrelog_error_t rc = "
                   "wyl_service_auth_authority_acquire_write", 1),
    source.replace("rc = wyl_audit_conn_service_exchange_project (conn,",
                   "wyl_handle_policy_store_unpin (item->handle, store);\n"
                   "      rc = wyl_audit_conn_service_exchange_project (conn,",
                   1),
]
for index, mutant in enumerate(mutants):
    if not violations(mutant):
        raise SystemExit(f"structural guard accepted mutant {index}")

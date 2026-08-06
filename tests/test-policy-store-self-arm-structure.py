#!/usr/bin/env python3
"""Freeze the transaction-only, receipt-last self-arm store boundary."""

from pathlib import Path
import re
import sys


source = Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.rindex("static wyrelog_error_t", 0,
    source.index("self_arm_insert_three_text"))
end = source.index("wyl_policy_store_foreach_tenant", start)
body = source[start:end]
upper = body.upper()

for forbidden in (
    "INSERT OR IGNORE",
    "INSERT OR REPLACE",
    "ON CONFLICT",
    "UPSERT",
    "AUDIT_INTENTIONS",
    "PUBLICATION_TRANSACTION_BEGIN",
    "PUBLICATION_TRANSACTION_COMMIT",
    "PUBLICATION_TRANSACTION_ROLLBACK",
):
    if forbidden in upper:
        raise SystemExit(f"forbidden self-arm mutation token: {forbidden}")

for helper in (
    "self_arm_insert_three_text",
    "self_arm_insert_audit",
    "self_arm_insert_receipt",
):
    if not re.search(rf"static\s+wyrelog_error_t\s+{helper}\s*\(", body):
        raise SystemExit(f"self-arm insert helper must remain static: {helper}")

if body.count("wyl_policy_store_publish_self_arm_bundle (") != 1:
    raise SystemExit("self-arm must expose exactly one mutation entrypoint")
publication = body[body.index("wyl_policy_store_publish_self_arm_bundle (") :]
if publication.count("self_arm_insert_three_text (store") != 8:
    raise SystemExit("self-arm mutation must write exactly eight authority rows")
if publication.count("self_arm_insert_audit (store") != 2:
    raise SystemExit("self-arm mutation must write exactly two audit rows")
if publication.count("self_arm_insert_receipt (store") != 1:
    raise SystemExit("self-arm mutation must write exactly one receipt row")
receipt_call = publication.index("self_arm_insert_receipt (store")
last_audit_call = publication.rindex("self_arm_insert_audit (store")
final_classify = publication.rindex("wyl_policy_store_classify_self_arm_bundle")
if not last_audit_call < receipt_call < final_classify:
    raise SystemExit("receipt must be last durable insert before validation")
if "state != WYL_POLICY_SELF_ARM_BUNDLE_ALL_ABSENT" not in publication:
    raise SystemExit("mutation must gate writes on ALL_ABSENT")
if "WYL_POLICY_SELF_ARM_BUNDLE_LEGACY_PRESENT" not in publication:
    raise SystemExit("legacy complete bundles must remain no-write")

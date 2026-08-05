#!/usr/bin/env python3
"""Keep the daemon self-arm route bounded to one publication runner."""

from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("typedef struct\n{\n  WylPolicySelfArmBundle bundle;")
end = source.index("\nSoupServer *", start)
body = source[start:end]

if body.count("wyl_policy_store_publish_self_arm_bundle (") != 1:
    raise SystemExit("self-arm route must publish one immutable bundle")
if body.count("wyl_engine_session_run_committed_publication (") != 1:
    raise SystemExit("self-arm route must use one committed runner")
if "managed_perms" in body or "wyl_policy_store_grant_direct_permission" in body:
    raise SystemExit("legacy per-permission self-arm loop remains")
if "wyl_daemon_policy_write_finish_result (&write, rc)" not in body:
    raise SystemExit("self-arm route must finalize WRITE before response")
if not re.search(r"wyl_request_id_new\s*\(publication\.server_operation_id", body):
    raise SystemExit("self-arm provenance IDs must be frozen before WRITE")
handler = body[body.index("service_management_authority_arm_handler") :]
if handler.count("ensure_request_id_header (msg)") != 1:
    raise SystemExit("self-arm must capture one request id for eligibility and bundle")

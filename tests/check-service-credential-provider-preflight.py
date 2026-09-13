#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only state and redacted HTTP proof for the nonproduction fixture only."""
import argparse
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import urllib.parse

from wyrelog_sc_e2e import _mint_ksuid, _post, _read_token


TABLES = (
    "service_credential_cvk", "service_credentials",
    "service_credential_events", "service_credential_handoff_escrows",
    "service_credential_handoff_dispositions", "service_domain_requests",
    "service_credential_operation_fences",
)
DIAGNOSTIC = b"service-credential handoff refused: effective-provider-unavailable"
DESTINATION = "provider-preflight-sentinel.json"


class ValidationFailure(Exception):
    """Only static, non-secret assertion messages belong here."""


def require(condition, message):
    if not condition:
        raise ValidationFailure(message)


def snapshot(args):
    # mode=ro must fail for missing files/tables; this is not an encrypted DB.
    with closing(sqlite3.connect(Path(args.policy).resolve().as_uri() + "?mode=ro",
                                 uri=True)) as db:
        db.execute("BEGIN")
        counts = {}
        for table in TABLES:
            try:
                counts[table] = db.execute("SELECT count(*) FROM " + table).fetchone()[0]
            except sqlite3.Error:
                raise ValidationFailure("cannot inspect expected table " + table) from None
    operation_root = Path(args.operation_root)
    publication_root = Path(args.publication_root)
    require(operation_root.is_dir() and publication_root.is_dir(), "roots absent")
    require(not list(operation_root.glob("op-*")), "operation journal residue")
    require(not list(publication_root.iterdir()), "publication residue")
    return counts


def check_private_output(args, state, body=b""):
    token = _read_token(args.token_file).encode()
    key = Path(args.key).read_bytes()
    require(bool(token) and bool(key), "empty sentinel")
    needles = [token, key, args.policy.encode(), args.key.encode(),
               ("file:" + args.key).encode(), args.operation_root.encode(),
               args.publication_root.encode(), b"svc:svc-app", b"tenant-a",
               DESTINATION.encode(), state["request_id"].encode()]
    logs = []
    for path, offset in zip(args.log, state["log_offsets"]):
        data = Path(path).read_bytes()
        require(len(data) >= offset, "log truncated")
        logs.append(data[offset:])
    for needle in needles:
        for form in (needle, base64.b64encode(needle), needle.hex().encode()):
            require(all(form not in data for data in [body] + logs),
                    "sensitive value appeared in output")
    require(sum(data.count(DIAGNOSTIC) for data in logs) == 1,
            "expected exactly one provider-preflight diagnostic")


def request(args):
    state = {"counts": snapshot(args), "request_id": _mint_ksuid(),
             "log_offsets": [Path(path).stat().st_size for path in args.log]}
    require(all(state["counts"][table] == 0 for table in TABLES[:5]),
            "fixture already has credential state")
    now = time.time_ns() // 1000
    query = urllib.parse.urlencode({"tenant": "tenant-a", "guard_timestamp": str(now),
                                    "guard_loc_class": "trusted", "guard_risk": "0"})
    payload = {"version": "1", "tenant": "tenant-a",
               "request_id": state["request_id"], "destination": DESTINATION,
               "expires_at_us": str(now + 3600 * 1000000)}
    status, body = _post(args.url + "/service-principals/svc:svc-app/credentials?"
                         + query, token=_read_token(args.token_file),
                         data=json.dumps(payload).encode())
    require(status == 503, "expected HTTP 503")
    require(json.loads(body) == {"error": "service_credential_unavailable"},
            "unexpected response object")
    check_private_output(args, state, body.encode())
    require(snapshot(args) == state["counts"], "live credential state changed")
    fd = os.open(args.state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(state, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("request", "verify-stopped"))
    for name in ("policy", "key", "operation-root", "publication-root",
                 "token-file", "state"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--url")
    parser.add_argument("--log", action="append", required=True)
    args = parser.parse_args()
    try:
        if args.phase == "request":
            require(bool(args.url), "missing URL")
            request(args)
        else:
            state = json.loads(Path(args.state).read_text(encoding="utf-8"))
            require(snapshot(args) == state["counts"], "durable credential state changed")
            check_private_output(args, state)
    except ValidationFailure as error:
        print("provider-preflight: " + str(error), file=sys.stderr)
        return 1
    except Exception as error:
        # Neither an HTTP body nor exception text may disclose fixture secrets.
        print("provider-preflight: " + type(error).__name__ + " (details redacted)",
              file=sys.stderr)
        return 1
    print("provider-preflight: " + args.phase + " passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

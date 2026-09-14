#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify a denied credential handoff is classified and diagnosed safely."""
import argparse
import base64
import json
import os
from pathlib import Path
import sys
import time
import urllib.parse

from wyrelog_sc_e2e import _mint_ksuid, _post, _read_token


DIAGNOSTIC = b"service-credential handoff refused: service-credential-management-permission"
DESTINATION = "policy-refusal-sentinel.json"
CONFLICT_DIAGNOSTIC = (
    b"service-credential handoff refused: "
    b"existing-operation-input-binding-conflict")
DESTINATION_DIAGNOSTIC = (
    b"service-credential handoff refused: destination-name")
OPERATION_ROOT_DIAGNOSTIC = (
    b"service-credential handoff refused: operation-root-open")


class ValidationFailure(Exception):
    """Only static, non-secret assertion messages belong here."""


def require(condition, message):
    if not condition:
        raise ValidationFailure(message)


def snapshot(args):
    return (sorted(Path(args.operation_root).iterdir()),
            sorted(Path(args.publication_root).iterdir()))


def check_redaction(args, token, request_id, destination, body, logs,
                    diagnostic=DIAGNOSTIC):
    needles = [token.encode(), Path(args.key).read_bytes(), args.key.encode(),
               ("file:" + args.key).encode(), args.operation_root.encode(),
               args.publication_root.encode(), b"admin2", b"tenant-a",
               b"__wr_default", b"svc:svc-app", request_id.encode(),
               destination.encode()]
    for needle in needles:
        forms = (needle, base64.b64encode(needle), needle.hex().encode())
        require(all(form not in data for form in forms for data in [body] + logs),
                "sensitive value appeared in response or log")
    require(sum(data.count(diagnostic) for data in logs) == 1,
            "expected one static refusal diagnostic")


def run(args):
    token = _read_token(args.token_file)
    before = snapshot(args)
    offsets = [Path(path).stat().st_size for path in args.log]
    request_id = _mint_ksuid()
    now = time.time_ns() // 1000
    query = urllib.parse.urlencode({"tenant": "tenant-a",
                                    "guard_timestamp": str(now),
                                    "guard_loc_class": "trusted",
                                    "guard_risk": "0"})
    payload = {"version": "1", "tenant": "tenant-a",
               "request_id": request_id, "destination": DESTINATION,
               "expires_at_us": str(now + 3600 * 1000000)}
    url = (args.url + "/service-principals/svc:svc-app/credentials?" + query)
    status, response = _post(url, token=token,
                             data=json.dumps(payload).encode("utf-8"))
    require(status == 403, "expected HTTP 403 policy denial")
    require(json.loads(response) == {"error": "service_credential_denied"},
            "unexpected policy-denial response")

    logs = []
    for path, offset in zip(args.log, offsets):
        data = Path(path).read_bytes()
        require(len(data) >= offset, "log truncated")
        logs.append(data[offset:])
    check_redaction(args, token, request_id, DESTINATION, response.encode(),
                    logs)
    require(snapshot(args) == before, "refused request left durable or file state")


def run_conflict(args):
    require(bool(args.request_id), "missing original request id")
    token = _read_token(args.token_file)
    before = snapshot(args)
    offsets = [Path(path).stat().st_size for path in args.log]
    now = time.time_ns() // 1000
    query = urllib.parse.urlencode({"tenant": "tenant-a",
                                    "guard_timestamp": str(now),
                                    "guard_loc_class": "trusted",
                                    "guard_risk": "0"})
    payload = {"version": "1", "tenant": "tenant-a",
               "request_id": args.request_id, "destination": "changed.json",
               "expires_at_us": str(now + 3600 * 1000000)}
    url = (args.url + "/service-principals/svc:svc-app/credentials?" + query)
    status, response = _post(url, token=token,
                             data=json.dumps(payload).encode("utf-8"))
    require(status == 409, "expected HTTP 409 request-intent conflict")
    require(json.loads(response) == {"error": "service_credential_conflict"},
            "unexpected request-intent conflict response")
    logs = []
    for path, offset in zip(args.log, offsets):
        data = Path(path).read_bytes()
        require(len(data) >= offset, "log truncated")
        logs.append(data[offset:])
    check_redaction(args, token, args.request_id, "changed.json",
                    response.encode(), logs, CONFLICT_DIAGNOSTIC)
    require(snapshot(args) == before,
            "conflicting request changed durable or file state")


def run_invalid_destination(args):
    token = _read_token(args.token_file)
    before = snapshot(args)
    offsets = [Path(path).stat().st_size for path in args.log]
    request_id = _mint_ksuid()
    now = time.time_ns() // 1000
    query = urllib.parse.urlencode({"tenant": "tenant-a",
                                    "guard_timestamp": str(now),
                                    "guard_loc_class": "trusted",
                                    "guard_risk": "0"})
    destination = "nested/path"
    payload = {"version": "1", "tenant": "tenant-a",
               "request_id": request_id, "destination": destination,
               "expires_at_us": str(now + 3600 * 1000000)}
    url = (args.url + "/service-principals/svc:svc-app/credentials?" + query)
    status, response = _post(url, token=token,
                             data=json.dumps(payload).encode("utf-8"))
    require(status == 400, "expected HTTP 400 invalid destination")
    require(json.loads(response) == {"error": "invalid_service_credential_request"},
            "unexpected invalid-destination response")
    logs = []
    for path, offset in zip(args.log, offsets):
        data = Path(path).read_bytes()
        require(len(data) >= offset, "log truncated")
        logs.append(data[offset:])
    check_redaction(args, token, request_id, destination, response.encode(),
                    logs, DESTINATION_DIAGNOSTIC)
    require(snapshot(args) == before,
            "invalid destination left durable or file state")


def run_insecure_operation_root(args):
    token = _read_token(args.token_file)
    before = snapshot(args)
    offsets = [Path(path).stat().st_size for path in args.log]
    request_id = _mint_ksuid()
    now = time.time_ns() // 1000
    query = urllib.parse.urlencode({"tenant": "tenant-a",
                                    "guard_timestamp": str(now),
                                    "guard_loc_class": "trusted",
                                    "guard_risk": "0"})
    destination = "insecure-root.json"
    payload = {"version": "1", "tenant": "tenant-a",
               "request_id": request_id, "destination": destination,
               "expires_at_us": str(now + 3600 * 1000000)}
    url = (args.url + "/service-principals/svc:svc-app/credentials?" + query)
    os.chmod(args.operation_root, 0o755)
    try:
        status, response = _post(url, token=token,
                                 data=json.dumps(payload).encode("utf-8"))
        require(status == 500, "expected HTTP 500 insecure operation root")
        require(json.loads(response) == {"error": "service_credential_failed"},
                "unexpected insecure-operation-root response")
        logs = []
        for path, offset in zip(args.log, offsets):
            data = Path(path).read_bytes()
            require(len(data) >= offset, "log truncated")
            logs.append(data[offset:])
        check_redaction(args, token, request_id, destination, response.encode(),
                        logs, OPERATION_ROOT_DIAGNOSTIC)
        require(snapshot(args) == before,
                "insecure operation root changed durable or file state")
    finally:
        os.chmod(args.operation_root, 0o700)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("url", "key", "operation-root", "publication-root",
                 "token-file"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=("authorization", "conflict",
                        "invalid-destination", "insecure-operation-root"),
                        default="authorization")
    parser.add_argument("--request-id")
    parser.add_argument("--log", action="append", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "conflict":
            run_conflict(args)
        elif args.mode == "invalid-destination":
            run_invalid_destination(args)
        elif args.mode == "insecure-operation-root":
            run_insecure_operation_root(args)
        else:
            run(args)
    except ValidationFailure as error:
        print("policy-refusal: " + str(error), file=sys.stderr)
        return 1
    except Exception as error:  # Never display exception data or fixture secrets.
        print("policy-refusal: " + type(error).__name__ + " (details redacted)",
              file=sys.stderr)
        return 1
    print("policy-refusal: HTTP status, diagnostic, redaction and state passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

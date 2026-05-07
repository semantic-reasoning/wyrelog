#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3
EXPECT_AUDIT=${4:-0}
PORT=$("$PYTHON" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
TMPDIR=$(mktemp -d)
POLICY_DB="$TMPDIR/policy.sqlite"
AUDIT_DB="$TMPDIR/audit.duckdb"
AUDIT_ARGS=
if [ "$EXPECT_AUDIT" = "1" ]; then
  AUDIT_ARGS="--audit-db $AUDIT_DB"
fi

# shellcheck disable=SC2086
"$WYRELOGD" --template-dir "$TEMPLATE_DIR" --policy-db "$POLICY_DB" \
  $AUDIT_ARGS --listen-port "$PORT" &
PID=$!

cleanup() {
  kill "$PID" 2>/dev/null || true
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

"$PYTHON" - "$PORT" "$EXPECT_AUDIT" <<'PY'
import sys
import json
import time
import urllib.request
import urllib.error

port = sys.argv[1]
expect_audit = sys.argv[2] == "1"
base = f"http://127.0.0.1:{port}"
last_error = None

def audit_endpoint_requires_auth():
    try:
        urllib.request.urlopen(
            f"{base}/audit/events?filter=action%28%29",
            timeout=1,
        ).read()
        return not expect_audit
    except urllib.error.HTTPError as exc:
        return exc.code == 401 if expect_audit else False

def audit_events_match_startup_readiness(payload):
    events = json.loads(payload)
    if not expect_audit or events == []:
        return events == []
    return any(
        event.get("subject_id") == "wyrelogd-skip-mfa-user"
        and event.get("action") == "login_skip_mfa"
        and event.get("deny_reason") == "skip_mfa_not_allowed"
        and event.get("decision") == 0
        for event in events
    )

def invalid_decide_is_rejected():
    try:
        urllib.request.urlopen(
            f"{base}/decide?user=healthz-user&perm=wr.audit.read",
            data=b"",
            timeout=1,
        ).read()
        return False
    except urllib.error.HTTPError as exc:
        return exc.code == 400

def decide_requires_post():
    try:
        urllib.request.urlopen(
            f"{base}/decide?user=healthz-user"
            "&perm=wr.audit.read&session_token=healthz-scope",
            timeout=1,
        ).read()
        return False
    except urllib.error.HTTPError as exc:
        return exc.code == 405

def decide_denies_unseeded_user():
    payload = urllib.request.urlopen(
        f"{base}/decide?user=healthz-user"
        "&perm=wr.audit.read&session_token=healthz-scope",
        data=b"",
        timeout=1,
    ).read()
    body = json.loads(payload)
    return (
        body.get("decision") == 0
        and "deny_reason" in body
        and "deny_origin" in body
    )

for _ in range(150):
    try:
        health = urllib.request.urlopen(f"{base}/healthz", timeout=1).read()
        if health != b"ok\n":
            sys.exit(1)
        ready = urllib.request.urlopen(f"{base}/readyz", timeout=1).read()
        if ready != b"ready\n":
            sys.exit(1)
        if expect_audit:
            if not audit_endpoint_requires_auth():
                sys.exit(1)
        else:
            events = urllib.request.urlopen(
                f"{base}/audit/events?filter=decision%3Ddeny",
                timeout=1,
            ).read()
            if not audit_events_match_startup_readiness(events):
                sys.exit(1)
        if not invalid_decide_is_rejected():
            sys.exit(1)
        if not decide_requires_post():
            sys.exit(1)
        if not decide_denies_unseeded_user():
            sys.exit(1)
        sys.exit(0)
    except Exception as exc:
        last_error = exc
        time.sleep(0.1)

print(last_error, file=sys.stderr)
sys.exit(1)
PY

kill -TERM "$PID"
wait "$PID"
trap - EXIT INT TERM
rm -rf "$TMPDIR"

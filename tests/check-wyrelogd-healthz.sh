#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3
EXPECT_AUDIT=${4:-0}
PORT=$((39000 + $$ % 20000))

"$WYRELOGD" --template-dir "$TEMPLATE_DIR" --listen-port "$PORT" &
PID=$!

cleanup() {
  kill "$PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$PYTHON" - "$PORT" "$EXPECT_AUDIT" <<'PY'
import sys
import time
import urllib.request
import urllib.error

port = sys.argv[1]
expect_audit = sys.argv[2] == "1"
base = f"http://127.0.0.1:{port}"
last_error = None

def invalid_filter_is_rejected():
    try:
        urllib.request.urlopen(
            f"{base}/audit/events?filter=action%28%29",
            timeout=1,
        ).read()
        return False
    except urllib.error.HTTPError as exc:
        return exc.code == 400

for _ in range(50):
    try:
        health = urllib.request.urlopen(f"{base}/healthz", timeout=1).read()
        events = urllib.request.urlopen(
            f"{base}/audit/events?filter=decision%3Ddeny",
            timeout=1,
        ).read()
        if health != b"ok\n" or events != b"[]":
            sys.exit(1)
        if expect_audit and not invalid_filter_is_rejected():
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

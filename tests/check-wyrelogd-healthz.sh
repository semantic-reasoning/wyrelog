#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3
PORT=$((39000 + $$ % 20000))

"$WYRELOGD" --template-dir "$TEMPLATE_DIR" --listen-port "$PORT" &
PID=$!

cleanup() {
  kill "$PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$PYTHON" - "$PORT" <<'PY'
import sys
import time
import urllib.request

port = sys.argv[1]
url = f"http://127.0.0.1:{port}/healthz"
last_error = None

for _ in range(50):
    try:
        body = urllib.request.urlopen(url, timeout=1).read()
        sys.exit(0 if body == b"ok\n" else 1)
    except Exception as exc:
        last_error = exc
        time.sleep(0.1)

print(last_error, file=sys.stderr)
sys.exit(1)
PY

kill -TERM "$PID"
wait "$PID"
trap - EXIT INT TERM

#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYCTL=$1
WYRELOGD=$2
TEMPLATE_DIR=$3
PYTHON=$4
PORT=$("$PYTHON" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
BASE_URL="http://127.0.0.1:$PORT"
TMPDIR=$(mktemp -d)
POLICY_DB="$TMPDIR/policy.sqlite"
OUT="$TMPDIR/wyctl.out"
ERR="$TMPDIR/wyctl.err"
PID=

cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

"$WYRELOGD" --template-dir "$TEMPLATE_DIR" --policy-db "$POLICY_DB" \
  --listen-port "$PORT" &
PID=$!

i=0
while [ "$i" -lt 150 ]; do
  i=$((i + 1))
  if "$WYCTL" --daemon-url "$BASE_URL" --timeout-ms 500 status \
      >"$OUT" 2>"$ERR"; then
    if [ "$(cat "$OUT")" = "ok" ] && [ ! -s "$ERR" ]; then
      if ! "$WYCTL" --daemon-url "$BASE_URL" --timeout-ms 500 status \
          --readiness >"$OUT" 2>"$ERR"; then
        echo "wyctl readiness status failed" >&2
        cat "$OUT" >&2
        cat "$ERR" >&2
        exit 1
      fi
      if [ "$(cat "$OUT")" != "status=ready" ] || [ -s "$ERR" ]; then
        echo "wyctl readiness status returned unexpected output" >&2
        cat "$OUT" >&2
        cat "$ERR" >&2
        exit 1
      fi
      kill -TERM "$PID"
      wait "$PID"
      PID=
      trap - EXIT INT TERM
      rm -rf "$TMPDIR"
      exit 0
    fi
    echo "wyctl status returned unexpected output" >&2
    cat "$OUT" >&2
    cat "$ERR" >&2
    exit 1
  fi
  sleep 0.1
done

echo "wyctl status did not reach live daemon" >&2
cat "$ERR" >&2
exit 1

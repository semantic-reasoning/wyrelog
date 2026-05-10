#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

"$PYTHON" - "$TMPDIR/system.key" "$TMPDIR/service.key" <<'PY'
import os
import pathlib
import sys

for raw in sys.argv[1:]:
    pathlib.Path(raw).write_bytes(os.urandom(32))
PY

if "$WYRELOGD" --profile=nope --check >/dev/null 2>"$TMPDIR/bad.err"; then
  echo "invalid profile was accepted" >&2
  exit 1
fi
if ! grep -q "profile must be system or service" "$TMPDIR/bad.err"; then
  echo "invalid profile did not report a stable error" >&2
  cat "$TMPDIR/bad.err" >&2
  exit 1
fi

"$WYRELOGD" --production --profile=system \
  --template-dir "$TEMPLATE_DIR" \
  --policy-db "$TMPDIR/system/policy.sqlite" \
  --policy-keyprovider "$TMPDIR/system.key" \
  --audit-db "$TMPDIR/system/audit.duckdb" \
  --check

"$WYRELOGD" --production --profile=service \
  --template-dir "$TEMPLATE_DIR" \
  --policy-db "$TMPDIR/service/policy.sqlite" \
  --policy-keyprovider "$TMPDIR/service.key" \
  --audit-db "$TMPDIR/service/audit.duckdb" \
  --system-url "http://127.0.0.1:1" \
  --event-spool-dir "$TMPDIR/service/event-spool" \
  --event-queue-limit 8 \
  --check

if [ ! -d "$TMPDIR/service/event-spool" ]; then
  echo "service profile did not create the event spool" >&2
  exit 1
fi

"$WYRELOGD" --profile=service \
  --template-dir "$TEMPLATE_DIR" \
  --system-url "http://127.0.0.1:1" \
  --event-spool-dir "$TMPDIR/service/run-spool" \
  --event-queue-limit 2 \
  --listen-port 0 \
  >"$TMPDIR/service-run.out" 2>"$TMPDIR/service-run.err" &
SERVICE_PID=$!
SPOOLED=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if find "$TMPDIR/service/run-spool" -name '*.event' -print -quit \
      2>/dev/null | grep -q .; then
    SPOOLED=1
    break
  fi
  if ! kill -0 "$SERVICE_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done
kill "$SERVICE_PID" 2>/dev/null || true
wait "$SERVICE_PID" 2>/dev/null || true
if [ "$SPOOLED" -ne 1 ]; then
  echo "service profile did not spool an event during system outage" >&2
  cat "$TMPDIR/service-run.err" >&2
  exit 1
fi

mkdir -p "$TMPDIR/service/full-spool"
printf '{"profile":"service","event":"existing"}' \
  >"$TMPDIR/service/full-spool/existing.event"
if "$WYRELOGD" --profile=service \
    --template-dir "$TEMPLATE_DIR" \
    --system-url "http://127.0.0.1:1" \
    --event-spool-dir "$TMPDIR/service/full-spool" \
    --event-queue-limit 1 \
    --listen-port 0 \
    >/dev/null 2>"$TMPDIR/full-spool.err"; then
  echo "full event spool was accepted" >&2
  exit 1
fi
if ! grep -q "event spool queue limit reached" "$TMPDIR/full-spool.err"; then
  echo "full event spool did not report a stable error" >&2
  cat "$TMPDIR/full-spool.err" >&2
  exit 1
fi

"$PYTHON" - "$TMPDIR/http.port" "$TMPDIR/http.requests" <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
import pathlib
import sys

port_path = pathlib.Path(sys.argv[1])
requests_path = pathlib.Path(sys.argv[2])
seen = 0

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global seen
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        with requests_path.open("a", encoding="utf-8") as out:
            out.write(body + "\n")
        seen += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, fmt, *args):
        return

server = HTTPServer(("127.0.0.1", 0), Handler)
port_path.write_text(str(server.server_port), encoding="utf-8")
while seen < 2:
    server.handle_request()
PY
HTTP_PID=$!
for _ in 1 2 3 4 5; do
  [ -s "$TMPDIR/http.port" ] && break
  sleep 1
done
if [ ! -s "$TMPDIR/http.port" ]; then
  echo "test HTTP endpoint did not start" >&2
  kill "$HTTP_PID" 2>/dev/null || true
  exit 1
fi
HTTP_PORT=$(cat "$TMPDIR/http.port")

mkdir -p "$TMPDIR/service/drain-spool"
printf '{"profile":"service","event":"existing"}' \
  >"$TMPDIR/service/drain-spool/existing.event"
"$WYRELOGD" --profile=service \
  --template-dir "$TEMPLATE_DIR" \
  --system-url "http://127.0.0.1:$HTTP_PORT" \
  --event-spool-dir "$TMPDIR/service/drain-spool" \
  --event-queue-limit 8 \
  --listen-port 0 \
  >"$TMPDIR/service-drain.out" 2>"$TMPDIR/service-drain.err" &
SERVICE_PID=$!
HTTP_DONE=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    HTTP_DONE=1
    break
  fi
  if ! kill -0 "$SERVICE_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done
kill "$SERVICE_PID" 2>/dev/null || true
kill "$HTTP_PID" 2>/dev/null || true
wait "$SERVICE_PID" 2>/dev/null || true
wait "$HTTP_PID" 2>/dev/null || true
if [ "$HTTP_DONE" -ne 1 ]; then
  echo "service profile did not drain and forward events" >&2
  cat "$TMPDIR/service-drain.err" >&2
  exit 1
fi
if find "$TMPDIR/service/drain-spool" -name '*.event' -print -quit \
    | grep -q .; then
  echo "service profile left drained events in the spool" >&2
  exit 1
fi
if [ "$(grep -c '"profile":"service"' "$TMPDIR/http.requests")" -ne 2 ]; then
  echo "service profile did not forward the expected event count" >&2
  cat "$TMPDIR/http.requests" >&2
  exit 1
fi

if "$WYRELOGD" --profile=service --event-queue-limit 0 \
    --check >/dev/null 2>"$TMPDIR/limit.err"; then
  echo "zero event queue limit was accepted" >&2
  exit 1
fi
if ! grep -q "event queue limit must be a positive integer" \
    "$TMPDIR/limit.err"; then
  echo "invalid event queue limit did not report a stable error" >&2
  cat "$TMPDIR/limit.err" >&2
  exit 1
fi

cat >"$TMPDIR/service.ini" <<EOF
[daemon]
profile=service
template_dir=$TEMPLATE_DIR
policy_db=$TMPDIR/config/policy.sqlite
policy_keyprovider=$TMPDIR/service.key
audit_db=$TMPDIR/config/audit.duckdb
system_url=http://127.0.0.1:8765
event_spool_dir=$TMPDIR/config/event-spool
event_queue_limit=9
listen_port=9876
production=true
EOF

"$WYRELOGD" --config "$TMPDIR/service.ini" --profile-info \
  >"$TMPDIR/profile.out"
grep -q '^profile=service$' "$TMPDIR/profile.out"
grep -q "^policy_db=$TMPDIR/config/policy.sqlite$" "$TMPDIR/profile.out"
grep -q "^event_spool_dir=$TMPDIR/config/event-spool$" "$TMPDIR/profile.out"
grep -q '^event_queue_limit=9$' "$TMPDIR/profile.out"
grep -q '^listen_port=9876$' "$TMPDIR/profile.out"

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

FACT_ARGS=
FACT_SYSTEM_ARGS=
FACT_SERVICE_ARGS=
if "$WYRELOGD" --profile=system --production --profile-info \
    | grep -q '^fact_root=/var/lib/wyrelog/system/facts$'; then
  FACT_ARGS=1
  FACT_SYSTEM_ARGS="--fact-root $TMPDIR/system/facts"
  FACT_SERVICE_ARGS="--fact-root $TMPDIR/service/facts"
else
  "$WYRELOGD" --profile=system --production --profile-info \
    >"$TMPDIR/profile-system-no-fact.out"
  grep -q '^fact_root=$' "$TMPDIR/profile-system-no-fact.out"
  grep -q '^fact_store_mode=$' "$TMPDIR/profile-system-no-fact.out"
fi

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
  $FACT_SYSTEM_ARGS \
  --check

"$WYRELOGD" --production --profile=service \
  --template-dir "$TEMPLATE_DIR" \
  --policy-db "$TMPDIR/service/policy.sqlite" \
  --policy-keyprovider "$TMPDIR/service.key" \
  --audit-db "$TMPDIR/service/audit.duckdb" \
  $FACT_SERVICE_ARGS \
  --system-url "http://127.0.0.1:1" \
  --event-spool-dir "$TMPDIR/service/event-spool" \
  --event-queue-limit 8 \
  --check

if [ ! -d "$TMPDIR/service/event-spool" ]; then
  echo "service profile did not create the event spool" >&2
  exit 1
fi
if [ -n "$FACT_ARGS" ] && [ ! -d "$TMPDIR/service/facts" ]; then
  echo "service profile did not create the fact root" >&2
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
i=0
while [ "$i" -lt 30 ]; do
  i=$((i + 1))
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

"$PYTHON" - "$TMPDIR/http.port" "$TMPDIR/http.requests" \
  2>"$TMPDIR/http.err" <<'PY' &
from http.server import BaseHTTPRequestHandler
import pathlib
from socketserver import TCPServer
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

server = TCPServer(("127.0.0.1", 0), Handler)
port_path.write_text(str(server.server_address[1]), encoding="utf-8")
while seen < 2:
    server.handle_request()
PY
HTTP_PID=$!
i=0
while [ "$i" -lt 15 ]; do
  i=$((i + 1))
  [ -s "$TMPDIR/http.port" ] && break
  sleep 1
done
if [ ! -s "$TMPDIR/http.port" ]; then
  echo "test HTTP endpoint did not start" >&2
  if kill -0 "$HTTP_PID" 2>/dev/null; then
    echo "test HTTP endpoint process is still running" >&2
  else
    echo "test HTTP endpoint process exited before startup" >&2
  fi
  cat "$TMPDIR/http.err" >&2
  kill "$HTTP_PID" 2>/dev/null || true
  wait "$HTTP_PID" 2>/dev/null || true
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
i=0
while [ "$i" -lt 30 ]; do
  i=$((i + 1))
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
fact_root=$TMPDIR/config/facts
fact_store_mode=per-tenant-graph
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
grep -q "^fact_root=$TMPDIR/config/facts$" "$TMPDIR/profile.out"
grep -q '^fact_store_mode=per-tenant-graph$' "$TMPDIR/profile.out"
grep -q "^event_spool_dir=$TMPDIR/config/event-spool$" "$TMPDIR/profile.out"
grep -q '^event_queue_limit=9$' "$TMPDIR/profile.out"
grep -q '^listen_port=9876$' "$TMPDIR/profile.out"

if [ -n "$FACT_ARGS" ]; then
  "$WYRELOGD" --production --profile=system --profile-info \
    >"$TMPDIR/profile-system-default.out"
  grep -q '^fact_root=/var/lib/wyrelog/system/facts$' \
    "$TMPDIR/profile-system-default.out"
  "$WYRELOGD" --production --profile=service --profile-info \
    >"$TMPDIR/profile-service-default.out"
  grep -q '^fact_root=/var/lib/wyrelog/service/facts$' \
    "$TMPDIR/profile-service-default.out"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$TMPDIR/conflict/policy.sqlite" \
      --policy-keyprovider "$TMPDIR/system.key" \
      --audit-db "$TMPDIR/conflict/audit.duckdb" \
      --fact-root "$TMPDIR/conflict" \
      --check >/dev/null 2>"$TMPDIR/fact-policy-conflict.err"; then
    echo "fact root containing policy database was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the policy database path" \
    "$TMPDIR/fact-policy-conflict.err"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$TMPDIR/policy-file" \
      --policy-keyprovider "$TMPDIR/system.key" \
      --audit-db "$TMPDIR/audit.duckdb" \
      --fact-root "$TMPDIR/policy-file/facts" \
      --check >/dev/null 2>"$TMPDIR/fact-under-policy-conflict.err"; then
    echo "fact root under policy database path was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the policy database path" \
    "$TMPDIR/fact-under-policy-conflict.err"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$TMPDIR/policy.sqlite" \
      --policy-keyprovider "$TMPDIR/system.key" \
      --audit-db "$TMPDIR/audit-file" \
      --fact-root "$TMPDIR/audit-file/facts" \
      --check >/dev/null 2>"$TMPDIR/fact-under-audit-conflict.err"; then
    echo "fact root under audit database path was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the audit database path" \
    "$TMPDIR/fact-under-audit-conflict.err"

  mkdir -p "$TMPDIR/policy-real" "$TMPDIR/audit-real" "$TMPDIR/spool-real"
  ln -s "$TMPDIR/policy-real" "$TMPDIR/policy-link"
  ln -s "$TMPDIR/audit-real" "$TMPDIR/audit-link"
  ln -s "$TMPDIR/spool-real" "$TMPDIR/spool-link"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$TMPDIR/policy-real/policy.sqlite" \
      --policy-keyprovider "$TMPDIR/system.key" \
      --audit-db "$TMPDIR/audit.duckdb" \
      --fact-root "$TMPDIR/policy-link" \
      --check >/dev/null 2>"$TMPDIR/fact-policy-symlink-conflict.err"; then
    echo "fact root aliasing the policy database tree was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the policy database path" \
    "$TMPDIR/fact-policy-symlink-conflict.err"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$TMPDIR/policy.sqlite" \
      --policy-keyprovider "$TMPDIR/system.key" \
      --audit-db "$TMPDIR/audit-real/audit.duckdb" \
      --fact-root "$TMPDIR/audit-link" \
      --check >/dev/null 2>"$TMPDIR/fact-audit-symlink-conflict.err"; then
    echo "fact root aliasing the audit database tree was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the audit database path" \
    "$TMPDIR/fact-audit-symlink-conflict.err"

  if "$WYRELOGD" --profile=service \
      --event-spool-dir "$TMPDIR/same-tree" \
      --fact-root "$TMPDIR/same-tree" \
      --check >/dev/null 2>"$TMPDIR/fact-spool-conflict.err"; then
    echo "fact root matching event spool was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the service event spool" \
    "$TMPDIR/fact-spool-conflict.err"

  if "$WYRELOGD" --profile=service \
      --event-spool-dir "$TMPDIR/spool-real" \
      --fact-root "$TMPDIR/spool-link" \
      --check >/dev/null 2>"$TMPDIR/fact-spool-symlink-conflict.err"; then
    echo "fact root aliasing the service event spool was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the service event spool" \
    "$TMPDIR/fact-spool-symlink-conflict.err"

  mkdir -p "$TMPDIR/open-facts"
  chmod 0755 "$TMPDIR/open-facts"
  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$TMPDIR/open-policy.sqlite" \
      --policy-keyprovider "$TMPDIR/system.key" \
      --audit-db "$TMPDIR/open-audit.duckdb" \
      --fact-root "$TMPDIR/open-facts" \
      --check >/dev/null 2>"$TMPDIR/fact-open-permissions.err"; then
    echo "group-or-other-accessible fact root was accepted" >&2
    exit 1
  fi
  grep -q "fact root must not be accessible by group or other users" \
    "$TMPDIR/fact-open-permissions.err"

  mkdir -p "$TMPDIR/no-write-facts"
  chmod 0500 "$TMPDIR/no-write-facts"
  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$TMPDIR/no-write-policy.sqlite" \
      --policy-keyprovider "$TMPDIR/system.key" \
      --audit-db "$TMPDIR/no-write-audit.duckdb" \
      --fact-root "$TMPDIR/no-write-facts" \
      --check >/dev/null 2>"$TMPDIR/fact-owner-permissions.err"; then
    echo "owner-unwritable fact root was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be readable, writable, and searchable by owner" \
    "$TMPDIR/fact-owner-permissions.err"
fi

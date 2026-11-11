#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3

PROFILE_TMPDIR=$(mktemp -d)
trap 'rm -rf "$PROFILE_TMPDIR"' EXIT INT TERM
# Fact-root traversal rejects symlink ancestors (including macOS /var).
PROFILE_TMPDIR=$(cd "$PROFILE_TMPDIR" && pwd -P)

"$PYTHON" - "$PROFILE_TMPDIR/system.key" "$PROFILE_TMPDIR/service.key" <<'PY'
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
  FACT_SYSTEM_ARGS="--fact-root $PROFILE_TMPDIR/system/facts"
  FACT_SERVICE_ARGS="--fact-root $PROFILE_TMPDIR/service/facts"
else
  "$WYRELOGD" --profile=system --production --profile-info \
    >"$PROFILE_TMPDIR/profile-system-no-fact.out"
  grep -q '^fact_root=$' "$PROFILE_TMPDIR/profile-system-no-fact.out"
  grep -q '^fact_store_mode=$' "$PROFILE_TMPDIR/profile-system-no-fact.out"
fi

if "$WYRELOGD" --profile=nope --check >/dev/null 2>"$PROFILE_TMPDIR/bad.err"; then
  echo "invalid profile was accepted" >&2
  exit 1
fi
if ! grep -q "profile must be system or service" "$PROFILE_TMPDIR/bad.err"; then
  echo "invalid profile did not report a stable error" >&2
  cat "$PROFILE_TMPDIR/bad.err" >&2
  exit 1
fi

"$WYRELOGD" --production --profile=system \
  --template-dir "$TEMPLATE_DIR" \
  --policy-db "$PROFILE_TMPDIR/system/policy.sqlite" \
  --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
  --audit-db "$PROFILE_TMPDIR/system/audit.duckdb" \
  $FACT_SYSTEM_ARGS \
  --check

# A production daemon uses a temporary policy store for readiness checks.
# Its lease creates a sidecar in the fixture directory, which must be removed when the
# readiness handle is released during shutdown.
PORT=$("$PYTHON" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
mkdir -p "$PROFILE_TMPDIR/readiness"
TMPDIR="$PROFILE_TMPDIR" "$WYRELOGD" --production --profile=system \
  --template-dir "$TEMPLATE_DIR" \
  --policy-db "$PROFILE_TMPDIR/readiness/policy.sqlite" \
  --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
  --audit-db "$PROFILE_TMPDIR/readiness/audit.duckdb" \
  $FACT_SYSTEM_ARGS --listen-port "$PORT" \
  >"$PROFILE_TMPDIR/readiness.stdout" 2>"$PROFILE_TMPDIR/readiness.stderr" &
READINESS_PID=$!
ready=0
i=0
while [ "$i" -lt 50 ]; do
  i=$((i + 1))
  if "$PYTHON" - "$PORT" <<'PY'
import sys
import urllib.request

try:
    urllib.request.urlopen(
        f"http://127.0.0.1:{sys.argv[1]}/healthz", timeout=1
    ).read()
except Exception:
    sys.exit(1)
PY
  then
    ready=1
    break
  fi
  if ! kill -0 "$READINESS_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
kill "$READINESS_PID" 2>/dev/null || true
wait "$READINESS_PID" 2>/dev/null || true
if [ "$ready" -ne 1 ]; then
  echo "production daemon did not become ready" >&2
  cat "$PROFILE_TMPDIR/readiness.stderr" >&2
  exit 1
fi
if find "$PROFILE_TMPDIR" -maxdepth 1 -name 'wyrelog-readiness-policy-*.sqlite.wyrelog-lock' \
    -print -quit | grep -q .; then
  echo "production readiness policy lock sidecar was left in the fixture directory" >&2
  exit 1
fi

"$WYRELOGD" --production --profile=service \
  --template-dir "$TEMPLATE_DIR" \
  --policy-db "$PROFILE_TMPDIR/service/policy.sqlite" \
  --policy-keyprovider "$PROFILE_TMPDIR/service.key" \
  --audit-db "$PROFILE_TMPDIR/service/audit.duckdb" \
  $FACT_SERVICE_ARGS \
  --system-url "http://127.0.0.1:1" \
  --event-spool-dir "$PROFILE_TMPDIR/service/event-spool" \
  --event-queue-limit 8 \
  --check

if [ ! -d "$PROFILE_TMPDIR/service/event-spool" ]; then
  echo "service profile did not create the event spool" >&2
  exit 1
fi
if [ -n "$FACT_ARGS" ] && [ ! -d "$PROFILE_TMPDIR/service/facts" ]; then
  echo "service profile did not create the fact root" >&2
  exit 1
fi

"$WYRELOGD" --profile=service \
  --template-dir "$TEMPLATE_DIR" \
  --system-url "http://127.0.0.1:1" \
  --event-spool-dir "$PROFILE_TMPDIR/service/run-spool" \
  --event-queue-limit 2 \
  --listen-port 0 \
  >"$PROFILE_TMPDIR/service-run.out" 2>"$PROFILE_TMPDIR/service-run.err" &
SERVICE_PID=$!
SPOOLED=0
i=0
while [ "$i" -lt 30 ]; do
  i=$((i + 1))
  if find "$PROFILE_TMPDIR/service/run-spool" -name '*.event' -print -quit \
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
  cat "$PROFILE_TMPDIR/service-run.err" >&2
  exit 1
fi

mkdir -p "$PROFILE_TMPDIR/service/full-spool"
printf '{"profile":"service","event":"existing"}' \
  >"$PROFILE_TMPDIR/service/full-spool/existing.event"
if "$WYRELOGD" --profile=service \
    --template-dir "$TEMPLATE_DIR" \
    --system-url "http://127.0.0.1:1" \
    --event-spool-dir "$PROFILE_TMPDIR/service/full-spool" \
    --event-queue-limit 1 \
    --listen-port 0 \
    >/dev/null 2>"$PROFILE_TMPDIR/full-spool.err"; then
  echo "full event spool was accepted" >&2
  exit 1
fi
if ! grep -q "event spool queue limit reached" "$PROFILE_TMPDIR/full-spool.err"; then
  echo "full event spool did not report a stable error" >&2
  cat "$PROFILE_TMPDIR/full-spool.err" >&2
  exit 1
fi

"$PYTHON" - "$PROFILE_TMPDIR/http.port" "$PROFILE_TMPDIR/http.requests" \
  2>"$PROFILE_TMPDIR/http.err" <<'PY' &
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
  [ -s "$PROFILE_TMPDIR/http.port" ] && break
  sleep 1
done
if [ ! -s "$PROFILE_TMPDIR/http.port" ]; then
  echo "test HTTP endpoint did not start" >&2
  if kill -0 "$HTTP_PID" 2>/dev/null; then
    echo "test HTTP endpoint process is still running" >&2
  else
    echo "test HTTP endpoint process exited before startup" >&2
  fi
  cat "$PROFILE_TMPDIR/http.err" >&2
  kill "$HTTP_PID" 2>/dev/null || true
  wait "$HTTP_PID" 2>/dev/null || true
  exit 1
fi
HTTP_PORT=$(cat "$PROFILE_TMPDIR/http.port")

mkdir -p "$PROFILE_TMPDIR/service/drain-spool"
printf '{"profile":"service","event":"existing"}' \
  >"$PROFILE_TMPDIR/service/drain-spool/existing.event"
"$WYRELOGD" --profile=service \
  --template-dir "$TEMPLATE_DIR" \
  --system-url "http://127.0.0.1:$HTTP_PORT" \
  --event-spool-dir "$PROFILE_TMPDIR/service/drain-spool" \
  --event-queue-limit 8 \
  --listen-port 0 \
  >"$PROFILE_TMPDIR/service-drain.out" 2>"$PROFILE_TMPDIR/service-drain.err" &
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
  cat "$PROFILE_TMPDIR/service-drain.err" >&2
  exit 1
fi
if find "$PROFILE_TMPDIR/service/drain-spool" -name '*.event' -print -quit \
    | grep -q .; then
  echo "service profile left drained events in the spool" >&2
  exit 1
fi
if [ "$(grep -c '"profile":"service"' "$PROFILE_TMPDIR/http.requests")" -ne 2 ]; then
  echo "service profile did not forward the expected event count" >&2
  cat "$PROFILE_TMPDIR/http.requests" >&2
  exit 1
fi

if "$WYRELOGD" --profile=service --event-queue-limit 0 \
    --check >/dev/null 2>"$PROFILE_TMPDIR/limit.err"; then
  echo "zero event queue limit was accepted" >&2
  exit 1
fi
if ! grep -q "event queue limit must be a positive integer" \
    "$PROFILE_TMPDIR/limit.err"; then
  echo "invalid event queue limit did not report a stable error" >&2
  cat "$PROFILE_TMPDIR/limit.err" >&2
  exit 1
fi

cat >"$PROFILE_TMPDIR/service.ini" <<EOF
[daemon]
profile=service
template_dir=$TEMPLATE_DIR
policy_db=$PROFILE_TMPDIR/config/policy.sqlite
policy_keyprovider=$PROFILE_TMPDIR/service.key
audit_db=$PROFILE_TMPDIR/config/audit.duckdb
fact_root=$PROFILE_TMPDIR/config/facts
fact_store_mode=per-tenant-graph
system_url=http://127.0.0.1:8765
event_spool_dir=$PROFILE_TMPDIR/config/event-spool
event_queue_limit=9
listen_port=9876
production=true
EOF

"$WYRELOGD" --config "$PROFILE_TMPDIR/service.ini" --profile-info \
  >"$PROFILE_TMPDIR/profile.out"
grep -q '^profile=service$' "$PROFILE_TMPDIR/profile.out"
grep -q "^policy_db=$PROFILE_TMPDIR/config/policy.sqlite$" "$PROFILE_TMPDIR/profile.out"
grep -q "^fact_root=$PROFILE_TMPDIR/config/facts$" "$PROFILE_TMPDIR/profile.out"
grep -q '^fact_store_mode=per-tenant-graph$' "$PROFILE_TMPDIR/profile.out"
grep -q "^event_spool_dir=$PROFILE_TMPDIR/config/event-spool$" "$PROFILE_TMPDIR/profile.out"
grep -q '^event_queue_limit=9$' "$PROFILE_TMPDIR/profile.out"
grep -q '^listen_port=9876$' "$PROFILE_TMPDIR/profile.out"

if [ -n "$FACT_ARGS" ]; then
  "$WYRELOGD" --production --profile=system --profile-info \
    >"$PROFILE_TMPDIR/profile-system-default.out"
  grep -q '^fact_root=/var/lib/wyrelog/system/facts$' \
    "$PROFILE_TMPDIR/profile-system-default.out"
  "$WYRELOGD" --production --profile=service --profile-info \
    >"$PROFILE_TMPDIR/profile-service-default.out"
  grep -q '^fact_root=/var/lib/wyrelog/service/facts$' \
    "$PROFILE_TMPDIR/profile-service-default.out"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$PROFILE_TMPDIR/conflict/policy.sqlite" \
      --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
      --audit-db "$PROFILE_TMPDIR/conflict/audit.duckdb" \
      --fact-root "$PROFILE_TMPDIR/conflict" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-policy-conflict.err"; then
    echo "fact root containing policy database was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the policy database path" \
    "$PROFILE_TMPDIR/fact-policy-conflict.err"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$PROFILE_TMPDIR/policy-file" \
      --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
      --audit-db "$PROFILE_TMPDIR/audit.duckdb" \
      --fact-root "$PROFILE_TMPDIR/policy-file/facts" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-under-policy-conflict.err"; then
    echo "fact root under policy database path was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the policy database path" \
    "$PROFILE_TMPDIR/fact-under-policy-conflict.err"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$PROFILE_TMPDIR/policy.sqlite" \
      --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
      --audit-db "$PROFILE_TMPDIR/audit-file" \
      --fact-root "$PROFILE_TMPDIR/audit-file/facts" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-under-audit-conflict.err"; then
    echo "fact root under audit database path was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the audit database path" \
    "$PROFILE_TMPDIR/fact-under-audit-conflict.err"

  mkdir -p "$PROFILE_TMPDIR/policy-real" "$PROFILE_TMPDIR/audit-real" "$PROFILE_TMPDIR/spool-real"
  ln -s "$PROFILE_TMPDIR/policy-real" "$PROFILE_TMPDIR/policy-link"
  ln -s "$PROFILE_TMPDIR/audit-real" "$PROFILE_TMPDIR/audit-link"
  ln -s "$PROFILE_TMPDIR/spool-real" "$PROFILE_TMPDIR/spool-link"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$PROFILE_TMPDIR/policy-real/policy.sqlite" \
      --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
      --audit-db "$PROFILE_TMPDIR/audit.duckdb" \
      --fact-root "$PROFILE_TMPDIR/policy-link" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-policy-symlink-conflict.err"; then
    echo "fact root aliasing the policy database tree was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the policy database path" \
    "$PROFILE_TMPDIR/fact-policy-symlink-conflict.err"

  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$PROFILE_TMPDIR/policy.sqlite" \
      --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
      --audit-db "$PROFILE_TMPDIR/audit-real/audit.duckdb" \
      --fact-root "$PROFILE_TMPDIR/audit-link" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-audit-symlink-conflict.err"; then
    echo "fact root aliasing the audit database tree was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the audit database path" \
    "$PROFILE_TMPDIR/fact-audit-symlink-conflict.err"

  if "$WYRELOGD" --profile=service \
      --event-spool-dir "$PROFILE_TMPDIR/same-tree" \
      --fact-root "$PROFILE_TMPDIR/same-tree" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-spool-conflict.err"; then
    echo "fact root matching event spool was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the service event spool" \
    "$PROFILE_TMPDIR/fact-spool-conflict.err"

  if "$WYRELOGD" --profile=service \
      --event-spool-dir "$PROFILE_TMPDIR/spool-real" \
      --fact-root "$PROFILE_TMPDIR/spool-link" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-spool-symlink-conflict.err"; then
    echo "fact root aliasing the service event spool was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be distinct from the service event spool" \
    "$PROFILE_TMPDIR/fact-spool-symlink-conflict.err"

  mkdir -p "$PROFILE_TMPDIR/open-facts"
  chmod 0755 "$PROFILE_TMPDIR/open-facts"
  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$PROFILE_TMPDIR/open-policy.sqlite" \
      --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
      --audit-db "$PROFILE_TMPDIR/open-audit.duckdb" \
      --fact-root "$PROFILE_TMPDIR/open-facts" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-open-permissions.err"; then
    echo "group-or-other-accessible fact root was accepted" >&2
    exit 1
  fi
  grep -q "fact root must not be accessible by group or other users" \
    "$PROFILE_TMPDIR/fact-open-permissions.err"

  mkdir -p "$PROFILE_TMPDIR/no-write-facts"
  chmod 0500 "$PROFILE_TMPDIR/no-write-facts"
  if "$WYRELOGD" --production --profile=system \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$PROFILE_TMPDIR/no-write-policy.sqlite" \
      --policy-keyprovider "$PROFILE_TMPDIR/system.key" \
      --audit-db "$PROFILE_TMPDIR/no-write-audit.duckdb" \
      --fact-root "$PROFILE_TMPDIR/no-write-facts" \
      --check >/dev/null 2>"$PROFILE_TMPDIR/fact-owner-permissions.err"; then
    echo "owner-unwritable fact root was accepted" >&2
    exit 1
  fi
  grep -q "fact root must be readable, writable, and searchable by owner" \
    "$PROFILE_TMPDIR/fact-owner-permissions.err"
fi

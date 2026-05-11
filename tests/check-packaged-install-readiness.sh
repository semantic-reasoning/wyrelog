#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
WYCTL=$2
TEMPLATE_DIR=$3
SOURCE_ROOT=$4
PYTHON=$5

PORT=$("$PYTHON" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

TMPDIR=$(mktemp -d)
PID=

cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

for path in \
  "$SOURCE_ROOT/packaging/systemd/wyrelog.service" \
  "$SOURCE_ROOT/packaging/systemd/wyrelog-system.service" \
  "$SOURCE_ROOT/packaging/systemd/wyrelog-service.service" \
  "$SOURCE_ROOT/packaging/sysusers.d/wyrelog.conf" \
  "$SOURCE_ROOT/packaging/tmpfiles.d/wyrelog.conf" \
  "$SOURCE_ROOT/packaging/wyrelogd.env" \
  "$SOURCE_ROOT/packaging/system.env" \
  "$SOURCE_ROOT/packaging/service.env" \
  "$SOURCE_ROOT/tools/verify-template-release.sh" \
  "$SOURCE_ROOT/docs/operator-runbook.md"; do
  test -s "$path"
done

if ! grep -q -- "--production" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog.service"; then
  echo "service unit does not enable production gates" >&2
  exit 1
fi
if ! grep -q -- "LoadCredential=wyrelog-system-policy-key:" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-system.service"; then
  echo "system unit does not load policy key as a systemd credential" >&2
  exit 1
fi
if ! grep -q -- "--policy-keyprovider systemd-creds:wyrelog-system-policy-key" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-system.service"; then
  echo "system unit does not use the systemd credential KeyProvider" >&2
  exit 1
fi
if ! grep -q -- "--profile=system" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-system.service"; then
  echo "system unit does not select the system profile" >&2
  exit 1
fi
if ! grep -q -- "--profile=service" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-service.service"; then
  echo "service unit does not select the service profile" >&2
  exit 1
fi
if ! grep -q "WYL_LOG=warn" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog.service"; then
  echo "service unit does not set production log ceiling" >&2
  exit 1
fi

INSTALL_ROOT="$TMPDIR/install"
mkdir -p "$INSTALL_ROOT/usr/share/wyrelog" \
  "$INSTALL_ROOT/usr/share/wyrelog/tools" \
  "$INSTALL_ROOT/etc/wyrelog" \
  "$INSTALL_ROOT/etc/wyrelog/system" \
  "$INSTALL_ROOT/etc/wyrelog/service" \
  "$INSTALL_ROOT/var/lib/wyrelog" \
  "$INSTALL_ROOT/var/lib/wyrelog/system" \
  "$INSTALL_ROOT/var/lib/wyrelog/service" \
  "$INSTALL_ROOT/var/log/wyrelog" \
  "$INSTALL_ROOT/var/log/wyrelog/system" \
  "$INSTALL_ROOT/var/log/wyrelog/service" \
  "$INSTALL_ROOT/run/wyrelog"
cp -R "$TEMPLATE_DIR" "$INSTALL_ROOT/usr/share/wyrelog/access"
cp "$SOURCE_ROOT/tools/verify-template-release.sh" \
  "$INSTALL_ROOT/usr/share/wyrelog/tools/verify-template-release.sh"
chmod 0755 "$INSTALL_ROOT/usr/share/wyrelog/tools/verify-template-release.sh"

"$PYTHON" - "$INSTALL_ROOT/etc/wyrelog/system/policy.key" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_bytes(os.urandom(32))
PY

TEMPLATE_INSTALL="$INSTALL_ROOT/usr/share/wyrelog/access"
POLICY_DB="$INSTALL_ROOT/var/lib/wyrelog/system/policy.sqlite"
AUDIT_DB="$INSTALL_ROOT/var/log/wyrelog/system/audit.duckdb"
KEY="$INSTALL_ROOT/etc/wyrelog/system/policy.key"
BASE_URL="http://127.0.0.1:$PORT"

"$WYCTL" key status --keyprovider "$KEY" >"$TMPDIR/key.out"
if [ "$(cat "$TMPDIR/key.out")" != "status=ready type=file bytes=32" ]; then
  echo "unexpected key status output" >&2
  cat "$TMPDIR/key.out" >&2
  exit 1
fi
CREDENTIALS_DIRECTORY="$INSTALL_ROOT/etc/wyrelog/system" \
  "$WYCTL" key status --keyprovider systemd-creds:policy.key \
  >"$TMPDIR/key-creds.out"
if [ "$(cat "$TMPDIR/key-creds.out")" != "status=ready type=systemd-creds bytes=32" ]; then
  echo "unexpected credential key status output" >&2
  cat "$TMPDIR/key-creds.out" >&2
  exit 1
fi

"$WYRELOGD" --template-info --template-dir "$TEMPLATE_INSTALL" \
  >"$TMPDIR/template-info.out"
grep -q '^version=' "$TMPDIR/template-info.out"
grep -q '^sha256=' "$TMPDIR/template-info.out"
grep -q '^migrations=' "$TMPDIR/template-info.out"
grep -q '^latest_migration_version=' "$TMPDIR/template-info.out"

"$INSTALL_ROOT/usr/share/wyrelog/tools/verify-template-release.sh" \
  "$WYRELOGD" "$TEMPLATE_INSTALL" \
  0 0ffe885e14222878f18fc1376adf2df32efeda66fab2e8437e320d7d6928b028 \
  1 0 >"$TMPDIR/template-release.out"
if [ "$(cat "$TMPDIR/template-release.out")" != \
    "status=verified version=0 sha256=0ffe885e14222878f18fc1376adf2df32efeda66fab2e8437e320d7d6928b028 migrations=1 latest_migration_version=0" ]; then
  echo "unexpected template release verification output" >&2
  cat "$TMPDIR/template-release.out" >&2
  exit 1
fi
if "$INSTALL_ROOT/usr/share/wyrelog/tools/verify-template-release.sh" \
    "$WYRELOGD" "$TEMPLATE_INSTALL" \
    0 0000000000000000000000000000000000000000000000000000000000000000 \
    1 0 >"$TMPDIR/template-replay.out" 2>"$TMPDIR/template-replay.err"; then
  echo "template release verification accepted a stale artifact identity" >&2
  exit 1
fi

"$WYRELOGD" --production \
  --profile system \
  --template-dir "$TEMPLATE_INSTALL" \
  --policy-db "$POLICY_DB" \
  --policy-keyprovider "file:$KEY" \
  --audit-db "$AUDIT_DB" \
  --check

ROTATE_DB="$INSTALL_ROOT/var/lib/wyrelog/system/rotate.sqlite"
ROTATE_AUDIT_DB="$INSTALL_ROOT/var/log/wyrelog/system/rotate-audit.duckdb"
ROTATE_NEW_KEY="$INSTALL_ROOT/etc/wyrelog/system/policy-rotated.key"
"$PYTHON" - "$ROTATE_NEW_KEY" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_bytes(os.urandom(32))
PY
"$WYRELOGD" --production \
  --profile system \
  --template-dir "$TEMPLATE_INSTALL" \
  --policy-db "$ROTATE_DB" \
  --policy-keyprovider "file:$KEY" \
  --audit-db "$ROTATE_AUDIT_DB" \
  --check
"$WYCTL" key rotate --store "$ROTATE_DB" \
  --from-keyprovider "file:$KEY" \
  --to-keyprovider "file:$ROTATE_NEW_KEY" >"$TMPDIR/rotate.out"
if [ "$(cat "$TMPDIR/rotate.out")" != "status=rotated store=$ROTATE_DB" ]; then
  echo "unexpected key rotation output" >&2
  cat "$TMPDIR/rotate.out" >&2
  exit 1
fi
if "$WYCTL" key rotate --store "$ROTATE_DB" \
    --from-keyprovider "file:$KEY" \
    --to-keyprovider "file:$ROTATE_NEW_KEY" \
    >"$TMPDIR/rotate-old.out" 2>"$TMPDIR/rotate-old.err"; then
  echo "old keyprovider still opens rotated policy store" >&2
  exit 1
fi
"$WYCTL" key rotate --store "$ROTATE_DB" \
  --from-keyprovider "file:$ROTATE_NEW_KEY" \
  --to-keyprovider "file:$ROTATE_NEW_KEY" >"$TMPDIR/rotate-verify.out"

CREDENTIALS_DIRECTORY="$INSTALL_ROOT/etc/wyrelog/system" \
  "$WYRELOGD" --production \
  --profile system \
  --template-dir "$TEMPLATE_INSTALL" \
  --policy-db "$POLICY_DB.credential" \
  --policy-keyprovider systemd-creds:policy.key \
  --audit-db "$AUDIT_DB.credential" \
  --check

"$WYRELOGD" --production \
  --profile system \
  --template-dir "$TEMPLATE_INSTALL" \
  --policy-db "$POLICY_DB" \
  --policy-keyprovider "file:$KEY" \
  --audit-db "$AUDIT_DB" \
  --listen-port "$PORT" &
PID=$!

i=0
while [ "$i" -lt 150 ]; do
  i=$((i + 1))
  if "$WYCTL" --daemon-url "$BASE_URL" --timeout-ms 500 status \
      >"$TMPDIR/status.out" 2>"$TMPDIR/status.err"; then
    if [ "$(cat "$TMPDIR/status.out")" != "ok" ]; then
      echo "unexpected status output" >&2
      cat "$TMPDIR/status.out" >&2
      cat "$TMPDIR/status.err" >&2
      exit 1
    fi
    "$WYCTL" --daemon-url "$BASE_URL" --timeout-ms 500 status \
      --readiness >"$TMPDIR/ready.out" 2>"$TMPDIR/ready.err"
    if [ "$(cat "$TMPDIR/ready.out")" != "status=ready" ]; then
      echo "unexpected readiness output" >&2
      cat "$TMPDIR/ready.out" >&2
      cat "$TMPDIR/ready.err" >&2
      exit 1
    fi
    "$PYTHON" - "$BASE_URL" <<'PY'
import json
import sys
import urllib.request

body = urllib.request.urlopen(f"{sys.argv[1]}/profile/status", timeout=1).read()
status = json.loads(body.decode())
if status.get("profile") != "system":
    raise SystemExit(status)
if status.get("event_queue_limit") != 1024:
    raise SystemExit(status)
PY
    kill -TERM "$PID"
    wait "$PID"
    PID=
    exit 0
  fi
  sleep 0.1
done

echo "packaged install smoke did not reach live daemon" >&2
cat "$TMPDIR/status.err" >&2 || true
exit 1

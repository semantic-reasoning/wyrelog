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
  "$SOURCE_ROOT/packaging/wyrelog/examples/wyrelogd-system.conf.example" \
  "$SOURCE_ROOT/packaging/wyrelog/examples/wyrelogd-service.conf.example" \
  "$SOURCE_ROOT/tools/verify-template-release.sh" \
  "$SOURCE_ROOT/docs/operator-runbook.md"; do
  test -s "$path"
done

# Profile-unit ExecStart shape: post-issue-#335 the system/service units
# load all settings from /etc/wyrelog/wyrelogd.conf via --config. The
# operational source of truth for per-flag values now lives in the
# example conf files installed under ${datadir}/wyrelog/examples/, so
# the assertions for policy_keyprovider, profile, etc. were migrated
# from inspecting the unit ExecStart to inspecting those examples.
SYSTEM_EXAMPLE="$SOURCE_ROOT/packaging/wyrelog/examples/wyrelogd-system.conf.example"
SERVICE_EXAMPLE="$SOURCE_ROOT/packaging/wyrelog/examples/wyrelogd-service.conf.example"
for unit in \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-system.service" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-service.service"; do
  if ! grep -q -- \
      "^ExecStart=/usr/bin/wyrelogd --config /etc/wyrelog/wyrelogd.conf --production$" \
      "$unit"; then
    echo "profile unit $unit does not invoke wyrelogd via --config" >&2
    exit 1
  fi
  if ! grep -q -- "^ReadOnlyPaths=/etc/wyrelog/wyrelogd.conf$" "$unit"; then
    echo "profile unit $unit does not pin conf file read-only" >&2
    exit 1
  fi
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
if ! grep -q -- "^policy_keyprovider=systemd-creds:wyrelog-system-policy-key$" \
    "$SYSTEM_EXAMPLE"; then
  echo "system example conf does not use the systemd credential KeyProvider" >&2
  exit 1
fi
if ! grep -q -- "^policy_keyprovider=systemd-creds:wyrelog-service-policy-key$" \
    "$SERVICE_EXAMPLE"; then
  echo "service example conf does not use the systemd credential KeyProvider" >&2
  exit 1
fi
if ! grep -q -- "^profile=system$" "$SYSTEM_EXAMPLE"; then
  echo "system example conf does not select the system profile" >&2
  exit 1
fi
if ! grep -q -- "^profile=service$" "$SERVICE_EXAMPLE"; then
  echo "service example conf does not select the service profile" >&2
  exit 1
fi
if ! grep -q -- "/var/lib/wyrelog/system/facts" \
    "$SOURCE_ROOT/packaging/tmpfiles.d/wyrelog.conf"; then
  echo "tmpfiles does not create the system fact root" >&2
  exit 1
fi
if ! grep -q -- "/var/lib/wyrelog/service/facts" \
    "$SOURCE_ROOT/packaging/tmpfiles.d/wyrelog.conf"; then
  echo "tmpfiles does not create the service fact root" >&2
  exit 1
fi
if ! grep -q '^d /var/lib/wyrelog/system/facts 0700 wyrelog wyrelog -$' \
    "$SOURCE_ROOT/packaging/tmpfiles.d/wyrelog.conf"; then
  echo "tmpfiles system fact root does not enforce 0700 wyrelog ownership" >&2
  exit 1
fi
if ! grep -q '^d /var/lib/wyrelog/service/facts 0700 wyrelog wyrelog -$' \
    "$SOURCE_ROOT/packaging/tmpfiles.d/wyrelog.conf"; then
  echo "tmpfiles service fact root does not enforce 0700 wyrelog ownership" >&2
  exit 1
fi
if ! grep -q -- "ReadWritePaths=/var/lib/wyrelog/system" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-system.service"; then
  echo "system unit does not allow writes under the system state root" >&2
  exit 1
fi
if ! grep -q -- "ReadWritePaths=/var/lib/wyrelog/service" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-service.service"; then
  echo "service unit does not allow writes under the service state root" >&2
  exit 1
fi
if ! grep -q "WYL_LOG=warn" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog.service"; then
  echo "service unit does not set production log ceiling" >&2
  exit 1
fi

if grep -q -- "--fact-root" "$SOURCE_ROOT/packaging/systemd/wyrelog.service" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-system.service" \
    "$SOURCE_ROOT/packaging/systemd/wyrelog-service.service"; then
  echo "static units must rely on profile fact-root defaults for build compatibility" >&2
  exit 1
fi
# Mirror the rule into the example conf files: the operator-facing
# templates must rely on options.c profile defaults for fact_root so
# the policy/audit/fact paths stay consistent with the daemon's
# resolve-time defaults.
if grep -q '^fact_root=' "$SYSTEM_EXAMPLE" "$SERVICE_EXAMPLE"; then
  echo "example conf files must rely on profile fact_root defaults" >&2
  exit 1
fi

SYSTEM_PROFILE_INFO="$TMPDIR/system-profile-info.out"
SERVICE_PROFILE_INFO="$TMPDIR/service-profile-info.out"
"$WYRELOGD" --profile=system --profile-info --production >"$SYSTEM_PROFILE_INFO"
"$WYRELOGD" --profile=service --profile-info --production >"$SERVICE_PROFILE_INFO"
grep -q '^policy_db=/var/lib/wyrelog/system/policy.sqlite$' "$SYSTEM_PROFILE_INFO"
grep -q '^audit_db=/var/log/wyrelog/system/audit.duckdb$' "$SYSTEM_PROFILE_INFO"
grep -q '^policy_db=/var/lib/wyrelog/service/policy.sqlite$' "$SERVICE_PROFILE_INFO"
grep -q '^audit_db=/var/log/wyrelog/service/audit.duckdb$' "$SERVICE_PROFILE_INFO"
if grep -q '^fact_root=.' "$SYSTEM_PROFILE_INFO"; then
  grep -q '^fact_root=/var/lib/wyrelog/system/facts$' "$SYSTEM_PROFILE_INFO"
  grep -q '^fact_root=/var/lib/wyrelog/service/facts$' "$SERVICE_PROFILE_INFO"
fi
"$PYTHON" - "$SYSTEM_PROFILE_INFO" "$SERVICE_PROFILE_INFO" <<'EOF2'
import sys

def load(path):
    out = {}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if '=' in line:
            k, v = line.split('=', 1)
            out[k] = v
    return out
for path in sys.argv[1:]:
    info = load(path)
    values = [info['policy_db'], info['audit_db']]
    fact_root = info.get('fact_root')
    if fact_root:
        values.append(fact_root)
    if len(set(values)) != len(values):
        raise SystemExit(f'profile paths overlap in {path}: {values}')
    if fact_root:
        fact = fact_root.rstrip('/') + '/'
        for key in ('policy_db', 'audit_db'):
            if info[key].startswith(fact):
                raise SystemExit(f'{key} is inside fact root in {path}')
EOF2
INSTALL_ROOT="$TMPDIR/install"
mkdir -p "$INSTALL_ROOT/usr/share/wyrelog" \
  "$INSTALL_ROOT/usr/share/wyrelog/tools" \
  "$INSTALL_ROOT/etc/wyrelog" \
  "$INSTALL_ROOT/etc/wyrelog/system" \
  "$INSTALL_ROOT/etc/wyrelog/service" \
  "$INSTALL_ROOT/var/lib/wyrelog" \
  "$INSTALL_ROOT/var/lib/wyrelog/system" \
  "$INSTALL_ROOT/var/lib/wyrelog/system/facts" \
  "$INSTALL_ROOT/var/lib/wyrelog/service" \
  "$INSTALL_ROOT/var/lib/wyrelog/service/facts" \
  "$INSTALL_ROOT/var/log/wyrelog" \
  "$INSTALL_ROOT/var/log/wyrelog/system" \
  "$INSTALL_ROOT/var/log/wyrelog/service" \
  "$INSTALL_ROOT/run/wyrelog"
chmod 0700 "$INSTALL_ROOT/var/lib/wyrelog/system/facts" \
  "$INSTALL_ROOT/var/lib/wyrelog/service/facts"
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
FACT_ROOT="$INSTALL_ROOT/var/lib/wyrelog/system/facts"
KEY="$INSTALL_ROOT/etc/wyrelog/system/policy.key"
FACT_ARGS=
if "$WYRELOGD" --profile=system --production --profile-info \
    | grep -q '^fact_root=/var/lib/wyrelog/system/facts$'; then
  FACT_ARGS="--fact-root $FACT_ROOT"
fi
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
  0 79a515224215caae6733fc0e3d90c99b261809861d2b3f643db4c615486e0499 \
  1 0 >"$TMPDIR/template-release.out"
if [ "$(cat "$TMPDIR/template-release.out")" != \
    "status=verified version=0 sha256=79a515224215caae6733fc0e3d90c99b261809861d2b3f643db4c615486e0499 migrations=1 latest_migration_version=0" ]; then
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
  $FACT_ARGS \
  --check
if [ -n "$FACT_ARGS" ]; then
  printf 'fact-root-writable\n' >"$FACT_ROOT/.write-check"
  test -s "$FACT_ROOT/.write-check"
fi

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
  $FACT_ARGS \
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
  $FACT_ARGS \
  --check

"$WYRELOGD" --production \
  --profile system \
  --template-dir "$TEMPLATE_INSTALL" \
  --policy-db "$POLICY_DB" \
  --policy-keyprovider "file:$KEY" \
  --audit-db "$AUDIT_DB" \
  $FACT_ARGS \
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

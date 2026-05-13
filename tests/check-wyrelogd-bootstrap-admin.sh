#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Integration test for the --bootstrap-admin-subject /
# --bootstrap-admin-allow-skip-mfa daemon flags. Drives the wyrelogd
# binary as a subprocess against an empty encrypted policy store on a
# scratch port, verifies that:
#
#   1. fresh bootstrap on an empty store seals the marker and applies
#      the wr.system_admin role membership and the
#      wr.login.skip_mfa direct permission;
#   1b. the bootstrapped admin can mint a first bearer token and use it
#      through wyctl policy mutation;
#   2. restart with the same subject is idempotent and the marker
#      remains stable;
#   3. restart with a different subject fails closed with a clear
#      stderr message and a non-zero exit;
#   4. --bootstrap-admin-subject together with --check is rejected at
#      options-parse time;
#   5. --bootstrap-admin-allow-skip-mfa without --bootstrap-admin-subject
#      is rejected at options-parse time.

set -eu

WYRELOGD=$1
WYCTL=$2
TEMPLATE_DIR=$3
PYTHON=$4

TMPDIR=$(mktemp -d)
POLICY_DB="$TMPDIR/policy.sqlite"
KEY_FILE="$TMPDIR/policy.key"
AUDIT_DB="$TMPDIR/audit.duckdb"
LOG="$TMPDIR/daemon.log"
PID=

cleanup() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

"$PYTHON" - "$KEY_FILE" <<'PY'
import os
import sys

with open(sys.argv[1], "wb") as f:
    f.write(os.urandom(32))
os.chmod(sys.argv[1], 0o600)
PY

pick_port() {
  "$PYTHON" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_until_serving() {
  port=$1
  i=0
  while [ "$i" -lt 200 ]; do
    i=$((i + 1))
    if "$WYCTL" --daemon-url "http://127.0.0.1:$port" --timeout-ms 500 \
        status >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_daemon() {
  port=$1
  shift
  : >"$LOG"
  (
    "$WYRELOGD" \
      --template-dir "$TEMPLATE_DIR" \
      --policy-db "$POLICY_DB" \
      --policy-keyprovider "file:$KEY_FILE" \
      --audit-db "$AUDIT_DB" \
      --listen-port "$port" \
      "$@" \
      >"$LOG.out" 2>"$LOG.err"
  ) &
  PID=$!
}

stop_daemon() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=
  fi
}

# Case 4 (cheap, no port): --bootstrap-admin-subject + --check rejected.
if "$WYRELOGD" \
    --template-dir "$TEMPLATE_DIR" \
    --policy-db "$POLICY_DB" \
    --policy-keyprovider "file:$KEY_FILE" \
    --bootstrap-admin-subject "admin1" \
    --check \
    >"$TMPDIR/check.out" 2>"$TMPDIR/check.err"; then
  echo "bootstrap-admin + --check should be rejected at parse time" >&2
  cat "$TMPDIR/check.err" >&2
  exit 1
fi
if ! grep -q "must not be combined with --check" "$TMPDIR/check.err"; then
  echo "bootstrap-admin + --check stderr missing expected message" >&2
  cat "$TMPDIR/check.err" >&2
  exit 1
fi

# Case 5 (cheap, no port): allow-skip-mfa without subject rejected.
if "$WYRELOGD" \
    --template-dir "$TEMPLATE_DIR" \
    --policy-db "$POLICY_DB" \
    --policy-keyprovider "file:$KEY_FILE" \
    --bootstrap-admin-allow-skip-mfa \
    --check \
    >"$TMPDIR/orphan.out" 2>"$TMPDIR/orphan.err"; then
  echo "allow-skip-mfa without subject should be rejected" >&2
  cat "$TMPDIR/orphan.err" >&2
  exit 1
fi
if ! grep -q "requires --bootstrap-admin-subject" "$TMPDIR/orphan.err"; then
  echo "allow-skip-mfa without subject stderr missing expected message" >&2
  cat "$TMPDIR/orphan.err" >&2
  exit 1
fi

# Confirm no policy store was written by the parse-time rejections so
# the encrypted store is still virgin for the runtime cases below.
if [ -e "$POLICY_DB" ]; then
  echo "policy store unexpectedly created by parse-time rejection" >&2
  exit 1
fi

# Case 1: fresh bootstrap on empty store.
PORT=$(pick_port)
start_daemon "$PORT" \
  --bootstrap-admin-subject "admin1" \
  --bootstrap-admin-allow-skip-mfa
if ! wait_until_serving "$PORT"; then
  echo "daemon did not come up on fresh bootstrap" >&2
  cat "$LOG.err" >&2
  exit 1
fi

TOKEN_FILE="$TMPDIR/admin1.token"
"$PYTHON" - "http://127.0.0.1:$PORT" "$TOKEN_FILE" <<'PY'
import json
import sys
import urllib.error
import urllib.request

base_url = sys.argv[1]
token_path = sys.argv[2]
url = f"{base_url}/auth/login?username=admin1&skip_mfa=true"
req = urllib.request.Request(url, method="POST")
try:
    with urllib.request.urlopen(req, timeout=3) as response:
        body = json.load(response)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f"bootstrap admin login failed: HTTP {exc.code}\n")
    sys.stderr.write(exc.read().decode("utf-8", "replace"))
    sys.stderr.write("\n")
    raise SystemExit(1)

token = body.get("access_token")
if not token:
    sys.stderr.write("bootstrap admin login response did not include access_token\n")
    raise SystemExit(1)
with open(token_path, "w", encoding="utf-8") as f:
    f.write(token)
    f.write("\n")
PY

"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy permission-grant \
  --subject "bootstrap-target" \
  --perm "wr.stream.read" \
  --scope "__wr_default" \
  --access-token-file "$TOKEN_FILE" \
  --guard-timestamp 123 \
  --guard-loc-class public \
  --guard-risk 29 >/dev/null

stop_daemon

if [ ! -e "$POLICY_DB" ]; then
  echo "policy store missing after fresh bootstrap" >&2
  exit 1
fi

# Confirm the bootstrap audit row landed in the audit DB. The audit
# store is a plain DuckDB file written by wyrelog/audit; the
# bootstrap_admin_apply emit (wyrelog/daemon/checks.c) sets
# subject_id='wyrelogd' and resource_id='<bootstrap subject>'. Stash
# the row count for the idempotent-reapply check after Case 2.
APPLY_COUNT_AFTER_CASE1=$("$PYTHON" - "$AUDIT_DB" <<'PY'
import sys
try:
    import duckdb
except ImportError:
    # DuckDB Python bindings absent in this build's harness; tolerate
    # by short-circuiting both Case 1 and Case 2 audit assertions.
    print("skip")
    sys.exit(0)

con = duckdb.connect(sys.argv[1], read_only=True)
rows = con.execute(
    "SELECT COUNT(*) FROM audit_events "
    "WHERE action = 'bootstrap_admin_apply' "
    "AND resource_id = 'admin1'"
).fetchall()
print(rows[0][0])
PY
)
if [ "$APPLY_COUNT_AFTER_CASE1" != "skip" ]; then
  if [ "$APPLY_COUNT_AFTER_CASE1" -lt 1 ]; then
    echo "audit DB missing bootstrap_admin_apply row for admin1" >&2
    exit 1
  fi
fi

# Case 2: restart with same subject is idempotent.
PORT=$(pick_port)
start_daemon "$PORT" \
  --bootstrap-admin-subject "admin1" \
  --bootstrap-admin-allow-skip-mfa
if ! wait_until_serving "$PORT"; then
  echo "daemon did not come up on idempotent reapply" >&2
  cat "$LOG.err" >&2
  exit 1
fi
stop_daemon

# After the idempotent reapply the audit row count for
# bootstrap_admin_apply against admin1 must have grown by exactly 1
# (one row per boot that runs the bootstrap path, applied=FALSE this
# time with deny_reason=already_sealed_same_subject).
if [ "$APPLY_COUNT_AFTER_CASE1" != "skip" ]; then
  APPLY_COUNT_AFTER_CASE2=$("$PYTHON" - "$AUDIT_DB" <<'PY'
import sys
import duckdb

con = duckdb.connect(sys.argv[1], read_only=True)
rows = con.execute(
    "SELECT COUNT(*) FROM audit_events "
    "WHERE action = 'bootstrap_admin_apply' "
    "AND resource_id = 'admin1'"
).fetchall()
print(rows[0][0])
PY
)
  EXPECTED=$((APPLY_COUNT_AFTER_CASE1 + 1))
  if [ "$APPLY_COUNT_AFTER_CASE2" != "$EXPECTED" ]; then
    echo "idempotent reapply audit row count mismatch:" \
      "expected $EXPECTED, got $APPLY_COUNT_AFTER_CASE2" >&2
    exit 1
  fi
fi

# Case 3: restart with a different subject fails closed.
PORT=$(pick_port)
start_daemon "$PORT" \
  --bootstrap-admin-subject "admin2"
# This daemon must exit non-zero before it ever serves; wait_until_serving
# would loop until timeout. Just wait for the spawned shell to exit.
set +e
wait "$PID"
rc=$?
set -e
PID=

if [ "$rc" -eq 0 ]; then
  echo "daemon should have refused mismatched bootstrap subject" >&2
  cat "$LOG.err" >&2
  exit 1
fi
if ! grep -q "store already sealed for admin1" "$LOG.err"; then
  echo "mismatched-subject daemon stderr missing expected message" >&2
  cat "$LOG.err" >&2
  exit 1
fi

exit 0

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
# wyctl's token-file safety check rejects group/other permission bits.
# Python's default open() honours the process umask, which yields 0644
# on CI runners — chmod down so the chmod-stricter contract holds.
import os
os.chmod(token_path, 0o600)
PY

"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy permission-grant \
  --subject "bootstrap-target" \
  --perm "wr.stream.read" \
  --scope "__wr_default" \
  --access-token-file "$TOKEN_FILE" \
  --guard-timestamp 123 \
  --guard-loc-class public \
  --guard-risk 29 >/dev/null

# The daemon remains the sole owner of the encrypted clear-file while a
# second administrator is created and enrolls through the authenticated
# online two-step flow.
"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy role-grant \
  --subject "admin2" \
  --role "wr.system_admin" \
  --scope "__wr_default" \
  --access-token-file "$TOKEN_FILE" \
  --guard-timestamp 123 \
  --guard-loc-class public \
  --guard-risk 0 >/dev/null

# Enrollment routes are bearer-only and reject malformed bounded JSON before
# creating a challenge or mutating policy state.
"$PYTHON" - "http://127.0.0.1:$PORT" "$TOKEN_FILE" <<'PY'
import sys
import urllib.error
import urllib.request

base_url, token_path = sys.argv[1:]
url = (f"{base_url}/auth/mfa/enroll/start?tenant=__wr_default&"
       "guard_timestamp=123&guard_loc_class=public&guard_risk=0")
for authorization, body, expected in (
        (None, b'{"subject":"admin2"}', 401),
        ("token", b'{', 400),
        ("token", b'{"subject":"admin2","subject":"admin2"}', 400),
        ("token", b'{"wrapper":{"subject":"admin2"}}', 400),
        ("token", b'{"note":"subject admin2"}', 400),
        ("token", b'{"subject":"admin2"} trailing', 400),
        ("token", b'{"subject":"' + b'a' * 5000 + b'"}', 400)):
    headers = {"Content-Type": "application/json"}
    if authorization:
        with open(token_path, encoding="utf-8") as f:
            headers["Authorization"] = "Bearer " + f.read().strip()
    request = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
    try:
        urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as exc:
        if exc.code != expected:
            raise
    else:
        raise SystemExit(f"enrollment request unexpectedly succeeded: {body!r}")
PY

"$PYTHON" - "http://127.0.0.1:$PORT" "$TOKEN_FILE" <<'PY'
import base64
import hashlib
import hmac
import json
import struct
import sys
import time
import urllib.error
import urllib.request

base_url, token_path = sys.argv[1:]
with open(token_path, encoding="utf-8") as f:
    headers = {"Authorization": "Bearer " + f.read().strip(),
               "Content-Type": "application/json"}
query = "?tenant=__wr_default&guard_timestamp=123&guard_loc_class=public&guard_risk=0"
start = urllib.request.Request(base_url + "/auth/mfa/enroll/start" + query,
    data=b'{"subject":"admin2"}', headers=headers, method="POST")
with urllib.request.urlopen(start, timeout=3) as response:
    challenge = json.load(response)
seed = base64.b32decode(challenge["secret_base32"])
step = int(time.time()) // 30
digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[-1] & 0x0f
correct = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000
for code, expected_error in (((correct + 1) % 1000000, "invalid_mfa_enroll_code"),
                             (correct, "invalid_mfa_enroll_challenge")):
    body = json.dumps({"challenge": challenge["challenge"],
                       "code": f"{code:06d}"}).encode()
    confirm = urllib.request.Request(base_url + "/auth/mfa/enroll/confirm" + query,
        data=body, headers=headers, method="POST")
    try:
        urllib.request.urlopen(confirm, timeout=3)
    except urllib.error.HTTPError as exc:
        error = json.loads(exc.read())["error"]
        if exc.code != 401 or error != expected_error:
            raise SystemExit(f"unexpected one-shot response: {exc.code} {error}")
    else:
        raise SystemExit("one-shot enrollment challenge unexpectedly succeeded")
PY

ADMIN2_SECRET="$TMPDIR/admin2.secret"
"$PYTHON" - "$WYCTL" "http://127.0.0.1:$PORT" "$TOKEN_FILE" \
    "$ADMIN2_SECRET" "admin2" <<'PY'
import base64
import hashlib
import hmac
import os
import struct
import subprocess
import sys
import time

wyctl, daemon_url, token_file, secret_path, subject = sys.argv[1:]
proc = subprocess.Popen(
    [wyctl, "--daemon-url", daemon_url, "mfa", "enroll",
     "--subject", subject, "--access-token-file", token_file],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True,
)
uri_line = proc.stdout.readline().strip()
secret_line = proc.stdout.readline().strip()
if not uri_line.startswith("otpauth_uri=") or not secret_line.startswith(
        "secret_base32="):
    sys.stderr.write("online enrollment did not emit enrollment material\n")
    sys.stderr.write(proc.stderr.read())
    proc.kill()
    raise SystemExit(1)
secret_b32 = secret_line.split("=", 1)[1]
seed = base64.b32decode(secret_b32)
step = int(time.time()) // 30
digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[-1] & 0x0f
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000
proc.stdin.write(f"{code:06d}\n")
proc.stdin.flush()
stdout, stderr = proc.communicate(timeout=10)
if proc.returncode != 0:
    sys.stderr.write("online enrollment failed\n")
    sys.stderr.write(stderr)
    raise SystemExit(proc.returncode)
with open(secret_path, "w", encoding="ascii") as f:
    f.write(secret_b32)
os.chmod(secret_path, 0o600)
PY

ADMIN2_TOKEN="$TMPDIR/admin2.token"
"$PYTHON" - "http://127.0.0.1:$PORT" "$ADMIN2_SECRET" \
    "$ADMIN2_TOKEN" <<'PY'
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.request

base_url, secret_path, token_path = sys.argv[1:]
with open(secret_path, encoding="ascii") as f:
    seed = base64.b32decode(f.read().strip())
# Enrollment consumes the current step as its replay watermark. Wait for the
# next step before proving that the newly enrolled administrator can log in.
time.sleep(30 - (time.time() % 30) + 0.25)
login = urllib.request.Request(
    f"{base_url}/auth/login?username=admin2", method="POST")
with urllib.request.urlopen(login, timeout=3) as response:
    session = json.load(response)["session_token"]
step = int(time.time()) // 30
digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[-1] & 0x0f
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000
verify = urllib.request.Request(
    f"{base_url}/auth/mfa/verify?session_token={session}&code={code:06d}",
    method="POST")
with urllib.request.urlopen(verify, timeout=3) as response:
    token = json.load(response)["access_token"]
with open(token_path, "w", encoding="utf-8") as f:
    f.write(token + "\n")
os.chmod(token_path, 0o600)
PY

"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy permission-grant \
  --subject "online-enroll-target" \
  --perm "wr.stream.read" \
  --scope "__wr_default" \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp 123 \
  --guard-loc-class public \
  --guard-risk 0 >/dev/null

"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy role-grant \
  --subject "admin3" --role "wr.system_admin" --scope "__wr_default" \
  --access-token-file "$TOKEN_FILE" --guard-timestamp 123 \
  --guard-loc-class public --guard-risk 0 >/dev/null
"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy role-grant \
  --subject "admin4" --role "wr.system_admin" --scope "__wr_default" \
  --access-token-file "$TOKEN_FILE" --guard-timestamp 123 \
  --guard-loc-class public --guard-risk 0 >/dev/null

# Two independently authenticated bootstrap sessions may start challenges for
# the same subject. Exactly one may commit; the lock-protected second confirm
# observes the enrollment and returns 409 instead of overwriting its secret.
"$PYTHON" - "http://127.0.0.1:$PORT" <<'PY'
import base64, hashlib, hmac, json, struct, sys, time
import urllib.error, urllib.request

base = sys.argv[1]
def login():
    req = urllib.request.Request(
        base + "/auth/login?username=admin1&skip_mfa=true", method="POST")
    with urllib.request.urlopen(req, timeout=3) as response:
        return json.load(response)["access_token"]
def request(path, token, payload):
    query = "?tenant=__wr_default&guard_timestamp=123&guard_loc_class=public&guard_risk=0"
    return urllib.request.Request(base + path + query,
        data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"})
def code(secret):
    seed = base64.b32decode(secret)
    digest = hmac.new(seed, struct.pack(">Q", int(time.time()) // 30),
                      hashlib.sha1).digest()
    offset = digest[-1] & 15
    return (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
tokens = [login(), login()]
# A challenge is bound to the exact authenticated session, not merely actor.
with urllib.request.urlopen(request("/auth/mfa/enroll/start", tokens[0],
        {"subject": "admin4"}), timeout=3) as response:
    cross = json.load(response)
cross_confirm = request("/auth/mfa/enroll/confirm", tokens[1],
    {"challenge": cross["challenge"],
     "code": f"{code(cross['secret_base32']):06d}"})
try:
    urllib.request.urlopen(cross_confirm, timeout=3)
except urllib.error.HTTPError as exc:
    if exc.code != 401 or json.loads(exc.read())["error"] != "invalid_mfa_enroll_challenge":
        raise
else:
    raise SystemExit("cross-session challenge confirmation succeeded")
# A foreign session must not consume the challenge. Its legitimate owner can
# still confirm it successfully afterwards.
owner_confirm = request("/auth/mfa/enroll/confirm", tokens[0],
    {"challenge": cross["challenge"],
     "code": f"{code(cross['secret_base32']):06d}"})
with urllib.request.urlopen(owner_confirm, timeout=3):
    pass
challenges = []
for token in tokens:
    with urllib.request.urlopen(request("/auth/mfa/enroll/start", token,
            {"subject": "admin3"}), timeout=3) as response:
        challenges.append(json.load(response))
for index, (token, challenge) in enumerate(zip(tokens, challenges)):
    confirm = request("/auth/mfa/enroll/confirm", token,
        {"challenge": challenge["challenge"],
         "code": f"{code(challenge['secret_base32']):06d}"})
    if index == 0:
        with urllib.request.urlopen(confirm, timeout=3):
            pass
    else:
        try:
            urllib.request.urlopen(confirm, timeout=3)
        except urllib.error.HTTPError as exc:
            error = json.loads(exc.read())["error"]
            if exc.code != 409 or error != "mfa_already_enrolled":
                raise
        else:
            raise SystemExit("competing enrollment unexpectedly overwrote secret")
PY

# Enroll the bootstrap administrator itself and prove that the live engine
# snapshot immediately observes the atomic skip-MFA revoke.
ADMIN1_SECRET="$TMPDIR/admin1.secret"
"$PYTHON" - "$WYCTL" "http://127.0.0.1:$PORT" "$ADMIN2_TOKEN" \
    "$ADMIN1_SECRET" "admin1" <<'PY'
import base64, hashlib, hmac, os, struct, subprocess, sys, time
wyctl, daemon_url, token_file, secret_path, subject = sys.argv[1:]
proc = subprocess.Popen([wyctl, "--daemon-url", daemon_url, "mfa", "enroll",
    "--subject", subject, "--access-token-file", token_file], stdin=subprocess.PIPE,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
uri = proc.stdout.readline().strip()
secret_line = proc.stdout.readline().strip()
if not uri.startswith("otpauth_uri=") or not secret_line.startswith("secret_base32="):
    raise SystemExit("bootstrap online enrollment material missing")
secret = secret_line.split("=", 1)[1]
seed = base64.b32decode(secret)
step = int(time.time()) // 30
digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[-1] & 15
code = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
proc.stdin.write(f"{code:06d}\n"); proc.stdin.flush()
_, err = proc.communicate(timeout=10)
if proc.returncode != 0:
    sys.stderr.write(err); raise SystemExit(proc.returncode)
with open(secret_path, "w") as f: f.write(secret)
os.chmod(secret_path, 0o600)
PY

"$PYTHON" - "http://127.0.0.1:$PORT" <<'PY'
import json, sys, urllib.error, urllib.request
req = urllib.request.Request(
    sys.argv[1] + "/auth/login?username=admin1&skip_mfa=true", method="POST")
try:
    urllib.request.urlopen(req, timeout=3)
except urllib.error.HTTPError as exc:
    if exc.code != 403:
        raise
else:
    raise SystemExit("bootstrap skip-MFA remained active after self enrollment")
PY

for secret_file in "$ADMIN1_SECRET" "$ADMIN2_SECRET"; do
  secret=$(cat "$secret_file")
  if grep -Fq "$secret" "$LOG.out" "$LOG.err"; then
    echo "TOTP secret leaked to daemon log" >&2
    exit 1
  fi
done

"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy role-revoke \
  --subject "admin1" --role "wr.system_admin" --scope "__wr_default" \
  --access-token-file "$ADMIN2_TOKEN" --guard-timestamp 123 \
  --guard-loc-class public --guard-risk 0 >/dev/null
"$PYTHON" - "http://127.0.0.1:$PORT" "$TOKEN_FILE" <<'PY'
import json, sys, urllib.error, urllib.request
base, token_path = sys.argv[1:]
with open(token_path) as f: token = f.read().strip()
req = urllib.request.Request(
    base + "/auth/mfa/enroll/start?tenant=__wr_default&guard_timestamp=123&guard_loc_class=public&guard_risk=0",
    data=b'{"subject":"admin4"}', method="POST",
    headers={"Authorization": "Bearer " + token,
             "Content-Type": "application/json"})
try:
    urllib.request.urlopen(req, timeout=3)
except urllib.error.HTTPError as exc:
    if exc.code != 403 or json.loads(exc.read())["error"] != "mfa_enroll_denied":
        raise
else:
    raise SystemExit("authenticated but unauthorized enrollment succeeded")
PY

stop_daemon

"$PYTHON" - "$AUDIT_DB" "$ADMIN1_SECRET" "$ADMIN2_SECRET" <<'PY'
import sys
try:
    import duckdb
except ImportError:
    raise SystemExit(0)
con = duckdb.connect(sys.argv[1], read_only=True)
rows = con.execute("SELECT request_id, subject_id, action, resource_id, "
                   "deny_reason, deny_origin FROM audit_events "
                   "WHERE action = 'mfa_enrolled'").fetchall()
if len(rows) < 3:
    raise SystemExit("runtime audit sink missing online mfa_enrolled rows")
payload = repr(rows)
if not any(row[0] for row in rows):
    raise SystemExit("online mfa_enrolled rows missing request_id")
for path in sys.argv[2:]:
    with open(path, encoding="ascii") as f:
        if f.read().strip() in payload:
            raise SystemExit("TOTP secret leaked to runtime audit")
PY

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
RESTART_TOKEN="$TMPDIR/admin2-restart.token"
"$PYTHON" - "http://127.0.0.1:$PORT" "$ADMIN2_SECRET" "$RESTART_TOKEN" <<'PY'
import base64, hashlib, hmac, json, os, struct, sys, time, urllib.request
base, secret_path, token_path = sys.argv[1:]
with open(secret_path) as f: seed = base64.b32decode(f.read().strip())
time.sleep(30 - (time.time() % 30) + 0.25)
login = urllib.request.Request(base + "/auth/login?username=admin2", method="POST")
with urllib.request.urlopen(login, timeout=3) as response:
    session = json.load(response)["session_token"]
step = int(time.time()) // 30
digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[-1] & 15
code = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
verify = urllib.request.Request(
    f"{base}/auth/mfa/verify?session_token={session}&code={code:06d}", method="POST")
with urllib.request.urlopen(verify, timeout=3) as response:
    token = json.load(response)["access_token"]
with open(token_path, "w") as f: f.write(token + "\n")
os.chmod(token_path, 0o600)
PY
"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" policy permission-grant \
  --subject "restart-persistence-target" --perm "wr.stream.read" \
  --scope "__wr_default" --access-token-file "$RESTART_TOKEN" \
  --guard-timestamp 123 --guard-loc-class public --guard-risk 0 >/dev/null
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

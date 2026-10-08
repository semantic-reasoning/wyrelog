#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Product-path regression for #1225: an MFA-authenticated wr.auditor granted
# at __wr_default reads the profile-wide audit stream through HTTP and wyctl.

set -eu

WYRELOGD=$1
WYCTL=$2
TEMPLATE_DIR=$3
PYTHON=$4
TMPDIR=$(mktemp -d)
POLICY_DB="$TMPDIR/policy.sqlite"
KEY_FILE="$TMPDIR/policy.key"
AUDIT_DB="$TMPDIR/audit.duckdb"
LOG_ERR="$TMPDIR/daemon.err"
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

PORT=$("$PYTHON" - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
BASE_URL="http://127.0.0.1:$PORT"
"$WYRELOGD" --template-dir "$TEMPLATE_DIR" --policy-db "$POLICY_DB" \
  --policy-keyprovider "file:$KEY_FILE" --audit-db "$AUDIT_DB" \
  --listen-port "$PORT" --bootstrap-admin-subject admin1 \
  --bootstrap-admin-allow-skip-mfa >"$TMPDIR/daemon.out" 2>"$LOG_ERR" &
PID=$!

i=0
until "$WYCTL" --daemon-url "$BASE_URL" --timeout-ms 500 status \
    >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 200 ]; then
    echo "daemon did not become ready" >&2
    cat "$LOG_ERR" >&2 || true
    exit 1
  fi
  sleep 0.1
done

"$PYTHON" - "$WYCTL" "$BASE_URL" "$TMPDIR" "$LOG_ERR" <<'PY'
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

WYCTL, BASE, WORK, DAEMON_LOG = sys.argv[1:]

def guard():
    return ["--guard-timestamp", str(int(time.time())),
            "--guard-loc-class", "trusted", "--guard-risk", "29"]

def fail(message):
    raise SystemExit(message)

def request(method, path, params=None, token=None, json_body=None):
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")

def cli(*args, check=True):
    proc = subprocess.run([WYCTL, "--daemon-url", BASE, *args],
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=30)
    if check and proc.returncode != 0:
        fail(f"wyctl {' '.join(args[:3])} failed ({proc.returncode}): "
             f"stdout={proc.stdout!r} stderr={proc.stderr!r}; daemon log: "
             f"{Path(DAEMON_LOG).read_text(encoding='utf-8')}")
    return proc

def token_file(name, token):
    path = os.path.join(WORK, name)
    with open(path, "w", encoding="ascii") as output:
        output.write(token + "\n")
    os.chmod(path, 0o600)
    return path

def totp(secret, step=None):
    step = int(time.time()) // 30 if step is None else step
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", step),
                      hashlib.sha1).digest()
    offset = digest[-1] & 0x0f
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1000000:06d}", step

def enroll(subject, operator_token):
    proc = subprocess.Popen(
        [WYCTL, "--daemon-url", BASE, "mfa", "enroll", "--subject", subject,
         "--access-token-file", operator_token],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8")
    uri = proc.stdout.readline().strip()
    secret_line = proc.stdout.readline().strip()
    if not uri.startswith("otpauth_uri=") or not secret_line.startswith(
            "secret_base32="):
        stdout, stderr = proc.communicate(timeout=10)
        fail(f"{subject}: MFA enrollment material was not emitted; "
             f"exit={proc.returncode} stdout={stdout!r} stderr={stderr!r}")
    secret = secret_line.split("=", 1)[1]
    code, step = totp(secret)
    proc.stdin.write(code + "\n")
    proc.stdin.flush()
    _, stderr = proc.communicate(timeout=20)
    if proc.returncode != 0:
        fail(f"{subject}: MFA enrollment failed: {stderr}")
    return secret, step

def login_mfa(subject, secret, enrolled_step):
    # Enrollment consumes its TOTP counter; login must use a fresh one.
    delay = (enrolled_step + 1) * 30 - time.time() + 0.25
    if delay > 0:
        time.sleep(delay)
    status, body = request("POST", "/auth/login",
                           {"username": subject, "tenant": "__wr_default"})
    if status != 200:
        fail(f"{subject}: login failed: {status} {body}")
    challenge = json.loads(body)
    if challenge.get("principal_state") != "mfa_required":
        fail(f"{subject}: expected MFA challenge: {body}")
    code, _ = totp(secret)
    status, body = request("POST", "/auth/mfa/verify", json_body={
        "session_token": challenge["session_token"], "code": code})
    if status != 200:
        fail(f"{subject}: MFA verification failed: {status} {body}")
    return json.loads(body)["access_token"]

def audit_params():
    return {"guard_timestamp": str(int(time.time())),
            "guard_loc_class": "trusted", "guard_risk": "29"}

# Bootstrap admin can enroll itself once, which retires skip-MFA.
status, body = request("POST", "/auth/login", {
    "username": "admin1", "tenant": "__wr_default", "skip_mfa": "true"})
if status != 200:
    fail(f"bootstrap login failed: {status} {body}")
admin_bootstrap = token_file("bootstrap.token", json.loads(body)["access_token"])
admin_secret, admin_step = enroll("admin1", admin_bootstrap)
admin_token = token_file("admin.token",
                         login_mfa("admin1", admin_secret, admin_step))

status, body = request("POST", "/decide", {
    "user": "admin1", "perm": "wr.policy.grant_role",
    "session_token": "__wr_default", "tenant": "__wr_default",
    "guard_timestamp": str(int(time.time())),
    "guard_loc_class": "trusted", "guard_risk": "29"},
    open(admin_token, encoding="ascii").read().strip())
if status != 200 or json.loads(body).get("decision") != 1:
    fail(f"MFA admin lacks role-grant authority at __wr_default: "
         f"{status} {body}")

# Administrative authority alone is intentionally insufficient to read audit.
status, body = request("GET", "/audit/events", audit_params(),
                       open(admin_token, encoding="ascii").read().strip())
if status != 403 or '"audit_denied"' not in body:
    fail(f"system administrator was not denied audit read: {status} {body}")

# Provision the separate auditor using supported CLI and MFA product paths.
cli("policy", "role-grant", "--subject", "carol", "--role", "wr.auditor",
    "--scope", "__wr_default", "--access-token-file", admin_token,
    *guard())
auditor_secret, auditor_step = enroll("carol", admin_token)
auditor_token = login_mfa("carol", auditor_secret, auditor_step)

status, body = request("POST", "/decide", {
    "user": "carol", "perm": "wr.audit.read",
    "session_token": "__wr_default", "tenant": "__wr_default",
    **audit_params()},
    auditor_token)
if status != 200 or json.loads(body).get("decision") != 1:
    fail(f"default-scope wr.auditor did not grant wr.audit.read: "
         f"{status} {body}")

# #1320: wr.audit.read is a guard-catalogue permission.  The role and the
# request guard decide it; it has no armed state, so the admin can neither
# arm nor disarm it, and the decision is the same before and after.
for event in ("grant", "revoke"):
    status, body = request("POST", "/policy/permissions/transition", {
        "subject": "carol", "perm": "wr.audit.read",
        "scope": "__wr_default", "event": event,
        **audit_params()},
        open(admin_token, encoding="ascii").read().strip())
    if status != 400 or '"permission_not_armable"' not in body:
        fail(f"{event} transition of catalogue wr.audit.read was not "
             f"refused: {status} {body}")
    status, body = request("POST", "/decide", {
        "user": "carol", "perm": "wr.audit.read",
        "session_token": "__wr_default", "tenant": "__wr_default",
        **audit_params()},
        auditor_token)
    if status != 200 or json.loads(body).get("decision") != 1:
        fail(f"wr.audit.read changed after a refused {event} transition: "
             f"{status} {body}")
transition = cli("policy", "permission-transition", "--subject", "carol",
    "--perm", "wr.audit.read", "--scope", "__wr_default", "--event", "grant",
    "--access-token-file", admin_token, *guard(), check=False)
if transition.returncode != 3 or "permission_not_armable" not in \
        transition.stderr:
    fail(f"wyctl did not report the refused transition: "
         f"{transition.returncode} {transition.stderr!r}")

# policy explain evaluates a catalogue permission with the request guard,
# as the route does.  Without one it names the missing guard, never
# not_armed, which no operator action could fix.
auditor_token_path = token_file("auditor.token", auditor_token)
explain = cli("policy", "explain", "--user", "carol", "--permission",
    "wr.audit.read", "--resource", "__wr_default", "--access-token-file",
    auditor_token_path, *guard())
if explain.stdout != "allow\n":
    fail(f"guarded policy explain did not allow: {explain.stdout!r}")
explain = cli("policy", "explain", "--user", "carol", "--permission",
    "wr.audit.read", "--resource", "__wr_default", "--access-token-file",
    auditor_token_path, check=False)
if explain.returncode != 0 or explain.stdout != (
        "deny\nreason=guard_unsatisfied\norigin=request_guard\n") \
        or "--guard-timestamp" not in explain.stderr:
    fail(f"unguarded policy explain of a catalogue permission: "
         f"{explain.returncode} {explain.stdout!r} {explain.stderr!r}")

status, body = request("GET", "/audit/events", audit_params(), auditor_token)
if status != 200 or not body.startswith("["):
    fail(f"system-scope auditor could not read audit via HTTP: {status} {body}")

query = cli("audit", "query", "--limit", "50", "--access-token-file",
    auditor_token_path, *guard())
rows = json.loads(query.stdout)
if not any(row.get("action") == "role_grant"
           and row.get("resource_id") == "__wr_default"
           for row in rows):
    fail(f"wyctl audit query omitted the role-grant event: {query.stdout}")
if any(row.get("action", "").startswith("permission_state.")
       for row in rows):
    fail(f"a refused transition left an audit event: {query.stdout}")

# Only the role membership withdraws the permission.
cli("policy", "role-revoke", "--subject", "carol", "--role", "wr.auditor",
    "--scope", "__wr_default", "--access-token-file", admin_token, *guard())
status, body = request("GET", "/audit/events", audit_params(), auditor_token)
if status != 403 or '"audit_denied"' not in body:
    fail(f"auditor kept audit read after the role revoke: {status} {body}")

PY

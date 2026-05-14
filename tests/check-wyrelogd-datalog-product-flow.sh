#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
WYCTL=$2
TEMPLATE_DIR=$3
PYTHON=$4

TMPDIR=$(mktemp -d)
POLICY_DB="$TMPDIR/policy.sqlite"
KEY_FILE="$TMPDIR/policy.key"
AUDIT_DB="$TMPDIR/audit.duckdb"
FACT_ROOT="$TMPDIR/facts"
LOG_OUT="$TMPDIR/daemon.out"
LOG_ERR="$TMPDIR/daemon.err"
PID=
PORT=
BASE_URL=

cleanup() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$FACT_ROOT"
chmod 0700 "$FACT_ROOT"
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

start_daemon() {
  PORT=$(pick_port)
  BASE_URL="http://127.0.0.1:$PORT"
  : >"$LOG_OUT"
  : >"$LOG_ERR"
  "$WYRELOGD" \
    --production \
    --template-dir "$TEMPLATE_DIR" \
    --policy-db "$POLICY_DB" \
    --policy-keyprovider "file:$KEY_FILE" \
    --audit-db "$AUDIT_DB" \
    --fact-root "$FACT_ROOT" \
    --listen-port "$PORT" \
    --bootstrap-admin-subject admin1 \
    --bootstrap-admin-allow-skip-mfa \
    >"$LOG_OUT" 2>"$LOG_ERR" &
  PID=$!

  i=0
  while [ "$i" -lt 200 ]; do
    i=$((i + 1))
    if "$WYCTL" --daemon-url "$BASE_URL" --timeout-ms 500 status \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "daemon did not become ready" >&2
  cat "$LOG_ERR" >&2 || true
  exit 1
}

stop_daemon() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=
  fi
}

login_token() {
  token_file=$1
  "$PYTHON" - "$BASE_URL" "$token_file" <<'PY'
import json
import sys
import urllib.error
import urllib.request
base, token_path = sys.argv[1:]
url = f"{base}/auth/login?username=admin1&tenant=__wr_default&skip_mfa=true"
req = urllib.request.Request(url, method="POST")
try:
    with urllib.request.urlopen(req, timeout=3) as response:
        body = json.load(response)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f"login failed: HTTP {exc.code}\n")
    sys.stderr.write(exc.read().decode("utf-8", "replace"))
    sys.stderr.write("\n")
    raise SystemExit(1)
token = body.get("access_token")
if not token:
    raise SystemExit(f"login returned no access_token: {body}")
with open(token_path, "w", encoding="utf-8") as f:
    f.write(token + "\n")
# wyctl rejects token files with group/other permission bits; chmod
# down so the safety check passes regardless of the runner's umask.
import os
os.chmod(token_path, 0o600)
PY
}

http_post_with_token() {
  token_file=$1
  path=$2
  "$PYTHON" - "$BASE_URL" "$token_file" "$path" <<'PY'
import sys
import urllib.error
import urllib.request
base, token_file, path = sys.argv[1:]
token = open(token_file, encoding="utf-8").read().strip()
req = urllib.request.Request(base + path, method="POST")
req.add_header("Authorization", f"Bearer {token}")
try:
    with urllib.request.urlopen(req, timeout=3) as response:
        response.read()
except urllib.error.HTTPError as exc:
    sys.stderr.write(f"POST {path} failed: HTTP {exc.code}\n")
    sys.stderr.write(exc.read().decode("utf-8", "replace"))
    sys.stderr.write("\n")
    raise SystemExit(1)
PY
}

arm_permission() {
  token_file=$1
  perm=$2
  http_post_with_token "$token_file" "/policy/permissions/transition?subject=admin1&perm=$perm&scope=__wr_default&event=grant&guard_timestamp=123&guard_loc_class=trusted&guard_risk=29"
}

create_graph_schema_and_facts() {
  token_file=$1
  graph=$2
  order_id=$3
  amount=$4
  csv="$TMPDIR/$graph-orders.csv"
  printf 'order_id,amount\n%s,%s\n' "$order_id" "$amount" >"$csv"

  "$WYCTL" --daemon-url "$BASE_URL" graph create \
    --tenant __wr_default \
    --graph "$graph" \
    --access-token-file "$token_file" \
    --guard-timestamp 123 \
    --guard-loc-class trusted \
    --guard-risk 29 >/dev/null
  "$WYCTL" --daemon-url "$BASE_URL" fact schema register \
    --tenant __wr_default \
    --graph "$graph" \
    --namespace shop \
    --relation orders \
    --schema-version 1 \
    --columns order_id:symbol,amount:int64 \
    --access-token-file "$token_file" \
    --guard-timestamp 123 \
    --guard-loc-class trusted \
    --guard-risk 29 >/dev/null
  result=$("$WYCTL" --daemon-url "$BASE_URL" fact put \
    --tenant __wr_default \
    --graph "$graph" \
    --namespace shop \
    --relation orders \
    --schema-version 1 \
    --batch-id "$graph-batch-1" \
    --idempotency-key "$graph-key-1" \
    --format csv \
    --input "$csv" \
    --access-token-file "$token_file" \
    --guard-timestamp 123 \
    --guard-loc-class trusted \
    --guard-risk 29)
  if [ "$result" != "inserted" ]; then
    echo "unexpected fact put result for $graph: $result" >&2
    exit 1
  fi
}

assert_query_row() {
  token_file=$1
  graph=$2
  order_id=$3
  amount=$4
  output="$TMPDIR/$graph-query.json"
  "$WYCTL" --daemon-url "$BASE_URL" datalog query \
    --tenant __wr_default \
    --graph "$graph" \
    --query 'orders(O,A)' \
    --output json \
    --limit 10 \
    --access-token-file "$token_file" \
    --guard-timestamp 123 \
    --guard-loc-class trusted \
    --guard-risk 29 >"$output"
  "$PYTHON" - "$output" "$order_id" "$amount" <<'PY'
import json
import sys
text = open(sys.argv[1], encoding="utf-8").read()
if "storage_path" in text or "facts.duckdb" in text:
    raise SystemExit("query response leaked storage details")
body = json.loads(text)
expected = {"O": sys.argv[2], "A": int(sys.argv[3])}
if expected not in body.get("rows", []):
    raise SystemExit(f"missing {expected}: {body}")
PY
}

assert_fact_status() {
  expected=$1
  "$PYTHON" - "$BASE_URL" "$expected" <<'PY'
import json
import sys
import urllib.request
base, expected = sys.argv[1:]
text = urllib.request.urlopen(f"{base}/facts/status", timeout=3).read().decode()
if "storage_path" in text or "facts.duckdb" in text:
    raise SystemExit("facts status leaked storage details")
body = json.loads(text)
if body.get("status") != expected:
    raise SystemExit(body)
graphs = {(g.get("tenant_id"), g.get("graph_id")): g for g in body.get("graphs", [])}
if expected == "ready":
    if body.get("graphs_total") != 2 or body.get("graphs_ready") != 2 or body.get("graphs_degraded") != 0:
        raise SystemExit(body)
else:
    a = graphs.get(("__wr_default", "orders-a"))
    b = graphs.get(("__wr_default", "orders-b"))
    if not a or not b:
        raise SystemExit(body)
    if a.get("state") != "ready" or a.get("queryable") is not True:
        raise SystemExit(body)
    if b.get("state") == "ready" or b.get("queryable") is not False:
        raise SystemExit(body)
    if b.get("last_error_class") not in ("store_unavailable", "replay_failed"):
        raise SystemExit(body)
PY
}

TOKEN_FILE="$TMPDIR/admin.token"

start_daemon
login_token "$TOKEN_FILE"
for perm in wr.graph.manage wr.schema.manage wr.fact.write wr.datalog.query; do
  arm_permission "$TOKEN_FILE" "$perm"
done
create_graph_schema_and_facts "$TOKEN_FILE" orders-a order-a 42
create_graph_schema_and_facts "$TOKEN_FILE" orders-b order-b 7
assert_query_row "$TOKEN_FILE" orders-a order-a 42
assert_query_row "$TOKEN_FILE" orders-b order-b 7
assert_fact_status ready

stop_daemon
start_daemon
login_token "$TOKEN_FILE"
assert_query_row "$TOKEN_FILE" orders-a order-a 42
assert_query_row "$TOKEN_FILE" orders-b order-b 7
assert_fact_status ready

stop_daemon
printf 'not a database\n' >"$FACT_ROOT/__wr_default/orders-b/facts.duckdb"
start_daemon
login_token "$TOKEN_FILE"
assert_query_row "$TOKEN_FILE" orders-a order-a 42
assert_fact_status degraded
stop_daemon

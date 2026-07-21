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
    raise SystemExit("unexpected facts status")
graph_list = body.get("graphs")
if not isinstance(graph_list, list) or len(graph_list) != 2:
    raise SystemExit("unexpected facts graph count")
expected_graphs = {
    ("__wr_default", "orders-a"),
    ("__wr_default", "orders-b"),
}
graphs = {}
for graph in graph_list:
    if not isinstance(graph, dict):
        raise SystemExit("unexpected facts graph entry")
    key = (graph.get("tenant_id"), graph.get("graph_id"))
    if key not in expected_graphs or key in graphs:
        raise SystemExit("unexpected facts graph identity")
    graphs[key] = graph
ready = [graph for graph in graph_list if graph.get("state") == "ready"]
nonready = [graph for graph in graph_list if graph.get("state") != "ready"]
if expected == "ready":
    if body.get("graphs_total") != 2 or body.get("graphs_ready") != 2 or body.get("graphs_degraded") != 0:
        raise SystemExit("unexpected ready facts totals")
    if len(ready) != 2 or nonready:
        raise SystemExit("unexpected ready facts graph state")
    if any(graph.get("queryable") is not True or graph.get("last_error_class") is not None for graph in ready):
        raise SystemExit("unexpected ready facts graph details")
elif expected == "degraded":
    if body.get("graphs_total") != 2 or body.get("graphs_ready") != 1 or body.get("graphs_degraded") != 1:
        raise SystemExit("unexpected degraded facts totals")
    if len(ready) != 1 or len(nonready) != 1:
        raise SystemExit("unexpected degraded facts graph state")
    if ready[0].get("queryable") is not True or ready[0].get("last_error_class") is not None:
        raise SystemExit("unexpected surviving facts graph details")
    if nonready[0].get("queryable") is not False:
        raise SystemExit("unexpected degraded facts graph queryability")
    if nonready[0].get("last_error_class") not in ("store_unavailable", "replay_failed"):
        raise SystemExit("unexpected degraded facts graph error")
    sys.stdout.write(ready[0]["graph_id"])
else:
    raise SystemExit("unsupported expected facts status")
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
"$PYTHON" - "$FACT_ROOT" <<'PY'
import os
import stat
import sys


def walk_error(_error):
    raise RuntimeError


stores = []
try:
    for root, _dirs, files in os.walk(sys.argv[1], onerror=walk_error):
        for name in files:
            if name != "facts.duckdb":
                continue
            path = os.path.join(root, name)
            if stat.S_ISREG(os.stat(path, follow_symlinks=False).st_mode):
                stores.append(path)
except (OSError, RuntimeError):
    raise SystemExit("failed to enumerate fact stores") from None
stores.sort()
if len(stores) != 2:
    raise SystemExit(f"expected two fact stores, found {len(stores)}")
try:
    with open(stores[0], "wb") as store:
        store.write(b"not a database\n")
except OSError:
    raise SystemExit("failed to corrupt fact store") from None
PY
start_daemon
READY_GRAPH=$(assert_fact_status degraded)
login_token "$TOKEN_FILE"
case "$READY_GRAPH" in
  orders-a)
    assert_query_row "$TOKEN_FILE" orders-a order-a 42
    ;;
  orders-b)
    assert_query_row "$TOKEN_FILE" orders-b order-b 7
    ;;
  *)
    echo "unexpected ready graph: $READY_GRAPH" >&2
    exit 1
    ;;
esac
stop_daemon

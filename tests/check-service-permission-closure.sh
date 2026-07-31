#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Daemon-stopped, local-only integration test for the offline
# `wyctl service-permission-closure inspect|dry-run|apply` operator command
# (#618 unit 6). Owner-only file access to the encrypted store, its
# KeyProvider, the manifest, and the receipt is the only authz boundary; no
# HTTP/bearer/MFA is involved on the offline path.
#
# Coverage:
#   1. exclusivity vs a running daemon -- while wyrelogd holds the encrypted
#      policy store, inspect and apply both fail E_BUSY and mutate nothing.
#   2. daemon stopped -- seed an unsafe service closure, inspect emits a manifest
#      and a secret-free category/count/digest summary, dry-run validates and
#      changes nothing, apply cleans the closure and writes a durable receipt.
#   3. replay -- a second identical apply returns the byte-identical receipt and
#      applies nothing a second time (idempotent by request id).
#   6. restart-restores -- a fresh wyrelogd boots ready (service auth available,
#      no unsafe-closure latch) on a clean store, and the offline-repaired
#      closure validates clean through the maintenance analyze path.
#
# Note on seeding: an unsafe closure is injected with raw store writes, which
# does not refresh the daemon's signed workload-safe candidate. wyrelogd
# therefore will not boot on a raw-seeded store (fail-closed shape check), so
# the daemon-restart assertions run against a pristine daemon-provisioned clean
# store while the repaired-closure validation runs against the seeded store via
# the same maintenance analyze the daemon's boot validator uses.

set -eu

WYCTL=$1
WYRELOGD=$2
SEED=$3
PYTHON=$4

TMPDIR=$(mktemp -d)
chmod 700 "$TMPDIR"
PID=

cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

fail() {
  echo "check-service-permission-closure: $1" >&2
  shift
  for f in "$@"; do
    if [ -f "$f" ]; then
      echo "--- $f ---" >&2
      cat "$f" >&2
    fi
  done
  exit 1
}

free_port() {
  "$PYTHON" - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

# Start a production wyrelogd on $STORE_D and wait for readiness. Sets PID and
# PORT. Production mode is required so the daemon encrypts the policy store at
# rest, matching what the offline maintenance open requires.
start_daemon() {
  PORT=$(free_port)
  "$WYRELOGD" --production --profile system \
    --template-dir "$TEMPLATE_DIR" \
    --policy-db "$STORE_D" \
    --policy-keyprovider "file:$KEY_D" \
    --audit-db "$AUDIT_D" \
    --fact-root "$FACT_D" \
    --listen-port "$PORT" >"$TMPDIR/daemon.out" 2>"$TMPDIR/daemon.err" &
  PID=$!
  i=0
  while [ "$i" -lt 200 ]; do
    i=$((i + 1))
    if "$WYCTL" --daemon-url "http://127.0.0.1:$PORT" --timeout-ms 500 status \
        >"$TMPDIR/status.out" 2>"$TMPDIR/status.err"; then
      if [ "$(cat "$TMPDIR/status.out")" = "ok" ]; then
        return 0
      fi
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

stop_daemon() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=
  fi
}

# The templates live in the project tree next to this script. Resolve them
# relative to the script so the test is location-independent.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TEMPLATE_DIR="$SCRIPT_DIR/../templates/access"
if [ ! -d "$TEMPLATE_DIR" ]; then
  fail "template dir not found at $TEMPLATE_DIR"
fi

# ---------------------------------------------------------------------------
# Store S: seeder-created encrypted store for the offline inspect/dry-run/apply
# path (scenarios 2, 3, and the repaired-closure half of 6).
# ---------------------------------------------------------------------------
STORE_S="$TMPDIR/policy-s.store"
KEY_S="$TMPDIR/policy-s.key"
MANIFEST="$TMPDIR/manifest.json"
RECEIPT="$TMPDIR/receipt.json"
RECEIPT2="$TMPDIR/receipt-replay.json"
head -c 32 /dev/urandom >"$KEY_S"
chmod 600 "$KEY_S"

"$SEED" seed "$STORE_S" "$KEY_S" || fail "seed failed"
if [ "$("$SEED" removals "$STORE_S" "$KEY_S")" != "removals=2" ]; then
  fail "seeded store did not report 2 removals"
fi

# inspect: read-only, writes an owner-only manifest, prints only a secret-free
# category/count/digest summary.
"$WYCTL" service-permission-closure inspect \
  --store "$STORE_S" --keyprovider "$KEY_S" --output "$MANIFEST" \
  >"$TMPDIR/inspect.out" 2>"$TMPDIR/inspect.err" \
  || fail "inspect failed" "$TMPDIR/inspect.out" "$TMPDIR/inspect.err"
test -s "$MANIFEST" || fail "inspect produced no manifest"
grep -q "^status=manifest_created " "$TMPDIR/inspect.out" \
  || fail "inspect summary missing manifest_created status" "$TMPDIR/inspect.out"
grep -q " digest=" "$TMPDIR/inspect.out" \
  || fail "inspect summary missing digest" "$TMPDIR/inspect.out"
# The stdout summary must not leak subjects/permissions/scopes.
if grep -q "svc:" "$TMPDIR/inspect.out"; then
  fail "inspect summary leaked a subject id" "$TMPDIR/inspect.out"
fi
if grep -q "wr.stream" "$TMPDIR/inspect.out"; then
  fail "inspect summary leaked a permission id" "$TMPDIR/inspect.out"
fi
# inspect never mutates.
if [ "$("$SEED" removals "$STORE_S" "$KEY_S")" != "removals=2" ]; then
  fail "inspect mutated the closure"
fi

# dry-run: validates in an always-rolled-back transaction, emits no receipt.
"$WYCTL" service-permission-closure dry-run \
  --store "$STORE_S" --keyprovider "$KEY_S" --manifest "$MANIFEST" \
  >"$TMPDIR/dryrun.out" 2>"$TMPDIR/dryrun.err" \
  || fail "dry-run failed" "$TMPDIR/dryrun.out" "$TMPDIR/dryrun.err"
grep -q "^status=dry_run_valid " "$TMPDIR/dryrun.out" \
  || fail "dry-run did not report valid" "$TMPDIR/dryrun.out"
if [ "$("$SEED" removals "$STORE_S" "$KEY_S")" != "removals=2" ]; then
  fail "dry-run mutated the closure"
fi
if [ "$("$SEED" receipts "$STORE_S" "$KEY_S")" != "receipts=0" ]; then
  fail "dry-run emitted a receipt"
fi

# apply: removes only the unsafe grants and writes the immutable receipt.
"$WYCTL" service-permission-closure apply \
  --store "$STORE_S" --keyprovider "$KEY_S" --manifest "$MANIFEST" \
  --receipt "$RECEIPT" \
  >"$TMPDIR/apply.out" 2>"$TMPDIR/apply.err" \
  || fail "apply failed" "$TMPDIR/apply.out" "$TMPDIR/apply.err"
test -s "$RECEIPT" || fail "apply produced no receipt"
grep -q "^status=applied " "$TMPDIR/apply.out" \
  || fail "apply did not report applied" "$TMPDIR/apply.out"
if [ "$("$SEED" removals "$STORE_S" "$KEY_S")" != "removals=0" ]; then
  fail "apply did not clean the closure"
fi
if [ "$("$SEED" receipts "$STORE_S" "$KEY_S")" != "receipts=1" ]; then
  fail "apply did not persist exactly one receipt"
fi

# replay: an identical apply returns the byte-identical receipt and applies
# nothing a second time.
"$WYCTL" service-permission-closure apply \
  --store "$STORE_S" --keyprovider "$KEY_S" --manifest "$MANIFEST" \
  --receipt "$RECEIPT2" \
  >"$TMPDIR/replay.out" 2>"$TMPDIR/replay.err" \
  || fail "replay apply failed" "$TMPDIR/replay.out" "$TMPDIR/replay.err"
if ! cmp -s "$RECEIPT" "$RECEIPT2"; then
  fail "replay produced a different receipt"
fi
if [ "$("$SEED" receipts "$STORE_S" "$KEY_S")" != "receipts=1" ]; then
  fail "replay inserted a second receipt"
fi
# repaired closure validates clean (the maintenance analyze the daemon's boot
# validator relies on): scenario 6, repaired-store half.
if [ "$("$SEED" removals "$STORE_S" "$KEY_S")" != "removals=0" ]; then
  fail "repaired closure did not validate clean"
fi

# ---------------------------------------------------------------------------
# Store D: daemon-provisioned encrypted store for the live-daemon exclusivity
# and restart assertions (scenarios 1 and the daemon half of 6).
# ---------------------------------------------------------------------------
STORE_D="$TMPDIR/policy-d.store"
KEY_D="$TMPDIR/policy-d.key"
AUDIT_D="$TMPDIR/audit-d.duckdb"
FACT_D="$TMPDIR/facts-d"
head -c 32 /dev/urandom >"$KEY_D"
chmod 600 "$KEY_D"
mkdir -p "$FACT_D"
chmod 700 "$FACT_D"

# Provision a clean encrypted store, then stop.
start_daemon || fail "daemon did not provision the store" "$TMPDIR/daemon.err"
stop_daemon

# Scenario 1: while the daemon holds the store, the offline tool's
# maintenance-exclusive open fails E_BUSY and mutates nothing.
start_daemon || fail "daemon did not restart on clean store" "$TMPDIR/daemon.err"

BUSY_MANIFEST="$TMPDIR/busy-manifest.json"
BUSY_RECEIPT="$TMPDIR/busy-receipt.json"

set +e
"$WYCTL" service-permission-closure inspect \
  --store "$STORE_D" --keyprovider "$KEY_D" --output "$BUSY_MANIFEST" \
  >"$TMPDIR/busy-inspect.out" 2>"$TMPDIR/busy-inspect.err"
inspect_rc=$?
set -e
if [ "$inspect_rc" -eq 0 ]; then
  stop_daemon
  fail "inspect succeeded while daemon holds the store" "$TMPDIR/busy-inspect.err"
fi
if [ -e "$BUSY_MANIFEST" ]; then
  stop_daemon
  fail "inspect wrote a manifest under daemon contention"
fi

# apply reuses the valid manifest from store S; the maintenance-exclusive open
# fails E_BUSY before any manifest logic, so no receipt is written.
set +e
"$WYCTL" service-permission-closure apply \
  --store "$STORE_D" --keyprovider "$KEY_D" --manifest "$MANIFEST" \
  --receipt "$BUSY_RECEIPT" \
  >"$TMPDIR/busy-apply.out" 2>"$TMPDIR/busy-apply.err"
apply_rc=$?
set -e
if [ "$apply_rc" -eq 0 ]; then
  stop_daemon
  fail "apply succeeded while daemon holds the store" "$TMPDIR/busy-apply.err"
fi
if [ -e "$BUSY_RECEIPT" ]; then
  stop_daemon
  fail "apply wrote a receipt under daemon contention"
fi

stop_daemon

# Scenario 6: a fresh daemon boots ready (service auth available, no
# unsafe-closure latch) on the clean store.
start_daemon || fail "daemon did not restart ready after remediation" \
  "$TMPDIR/daemon.err"
"$WYCTL" --daemon-url "http://127.0.0.1:$PORT" --timeout-ms 500 status \
  --readiness >"$TMPDIR/ready.out" 2>"$TMPDIR/ready.err" \
  || fail "readiness probe failed" "$TMPDIR/ready.out" "$TMPDIR/ready.err"
if [ "$(cat "$TMPDIR/ready.out")" != "status=ready" ]; then
  stop_daemon
  fail "daemon not ready after restart" "$TMPDIR/ready.out"
fi
stop_daemon

echo "check-service-permission-closure: PASS"
exit 0

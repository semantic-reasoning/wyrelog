#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3
PORT=$((20000 + $$ % 15000))
TMPDIR=$(mktemp -d)
PID=
RC_FILE="$TMPDIR/daemon.rc"
POLICY_DB="$TMPDIR/policy.sqlite"

cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

"$PYTHON" - "$TEMPLATE_DIR" "$TMPDIR/access" <<'PY'
import pathlib
import shutil
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
shutil.copytree(src, dst)

old = "guarded_perm(P) :- perm_arm_rule(P, _)."
new = (
    'guarded_perm(P) :- perm_arm_rule(P, _), '
    'permission("__wyrelog_test_missing_permission").'
)
for rel in ("decision.dl", "lobac/decision.dl"):
    path = dst / rel
    text = path.read_text()
    if old not in text:
        raise SystemExit(f"{rel}: guarded permission rule not found")
    path.write_text(text.replace(old, new))
PY

if "$WYRELOGD" --template-dir "$TMPDIR/access" --policy-db "$POLICY_DB" \
    --check; then
  echo "readiness fixture unexpectedly passed --check" >&2
  exit 1
fi

(
  set +e
  "$WYRELOGD" --template-dir "$TMPDIR/access" --policy-db "$POLICY_DB" \
    --listen-port "$PORT"
  rc=$?
  printf '%s\n' "$rc" > "$RC_FILE"
  exit "$rc"
) &
PID=$!

i=0
while [ "$i" -lt 50 ] && [ ! -s "$RC_FILE" ]; do
  i=$((i + 1))
  if "$PYTHON" - "$PORT" <<'PY'
import sys
import urllib.request

base = f"http://127.0.0.1:{sys.argv[1]}"
try:
    urllib.request.urlopen(f"{base}/healthz", timeout=1).read()
except Exception:
    sys.exit(1)
sys.exit(0)
PY
  then
    echo "daemon served healthz after readiness failure" >&2
    exit 1
  fi
  sleep 0.1
done

set +e
wait "$PID"
rc=$?
PID=
set -e

if [ "$rc" -eq 0 ]; then
  echo "daemon exited successfully after readiness failure" >&2
  exit 1
fi

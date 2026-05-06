#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3
PORT=$((41000 + $$ % 20000))
TMPDIR=$(mktemp -d)
PID=

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

old = "guarded_perm(P) :- perm_arm_rule(P, G)."
new = (
    'guarded_perm(P) :- perm_arm_rule(P, G), '
    'permission("__wyrelog_test_missing_permission").'
)
for rel in ("decision.dl", "lobac/decision.dl"):
    path = dst / rel
    text = path.read_text()
    if old not in text:
        raise SystemExit(f"{rel}: guarded permission rule not found")
    path.write_text(text.replace(old, new))
PY

if "$WYRELOGD" --template-dir "$TMPDIR/access" --check; then
  echo "readiness fixture unexpectedly passed --check" >&2
  exit 1
fi

"$WYRELOGD" --template-dir "$TMPDIR/access" --listen-port "$PORT" &
PID=$!

if "$PYTHON" - "$PORT" <<'PY'
import sys
import time
import urllib.request

base = f"http://127.0.0.1:{sys.argv[1]}"
for _ in range(50):
    try:
        urllib.request.urlopen(f"{base}/healthz", timeout=1).read()
        sys.exit(0)
    except Exception:
        time.sleep(0.1)
sys.exit(1)
PY
then
  echo "daemon served healthz after readiness failure" >&2
  exit 1
fi

set +e
wait "$PID"
rc=$?
PID=
set -e

if [ "$rc" -eq 0 ]; then
  echo "daemon exited successfully after readiness failure" >&2
  exit 1
fi

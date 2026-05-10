#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

"$PYTHON" - "$TEMPLATE_DIR" "$TMPDIR/access-no-manifest" <<'PY'
import pathlib
import shutil
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
shutil.copytree(src, dst)
(dst / "manifest.ini").unlink()
PY

"$WYRELOGD" --template-dir "$TMPDIR/access-no-manifest" \
  --policy-db "$TMPDIR/nonprod.sqlite" --check

if "$WYRELOGD" --production --template-dir "$TMPDIR/access-no-manifest" \
    --policy-db "$TMPDIR/prod-missing-manifest.sqlite" --check; then
  echo "production mode accepted templates without a manifest" >&2
  exit 1
fi

if "$WYRELOGD" --production --template-dir "$TEMPLATE_DIR" \
    --policy-db "$TMPDIR/prod-dev-keyprovider.sqlite" --check; then
  echo "production mode accepted the development KeyProvider" >&2
  exit 1
fi

"$PYTHON" - "$TMPDIR/prod.key" <<'PY'
import os
import sys

with open(sys.argv[1], "wb") as f:
    f.write(os.urandom(32))
PY

"$WYRELOGD" --production --template-dir "$TEMPLATE_DIR" \
  --policy-db "$TMPDIR/prod.sqlite" \
  --policy-keyprovider "$TMPDIR/prod.key" --check

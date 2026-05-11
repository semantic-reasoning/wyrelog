#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

if [ "$#" -ne 6 ]; then
  echo "usage: $0 WYRELOGD TEMPLATE_DIR VERSION SHA256 MIGRATIONS LATEST_MIGRATION_VERSION" >&2
  exit 64
fi

WYRELOGD=$1
TEMPLATE_DIR=$2
EXPECTED_VERSION=$3
EXPECTED_SHA256=$4
EXPECTED_MIGRATIONS=$5
EXPECTED_LATEST_MIGRATION_VERSION=$6

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

"$WYRELOGD" --template-info --template-dir "$TEMPLATE_DIR" \
  >"$TMPDIR/template-info.out"

read_field() {
  sed -n "s/^$1=//p" "$TMPDIR/template-info.out" | tail -n 1
}

VERSION=$(read_field version)
SHA256=$(read_field sha256)
MIGRATIONS=$(read_field migrations)
LATEST_MIGRATION_VERSION=$(read_field latest_migration_version)

if [ "$VERSION" != "$EXPECTED_VERSION" ]; then
  echo "template version mismatch: expected $EXPECTED_VERSION, got $VERSION" >&2
  exit 1
fi
if [ "$SHA256" != "$EXPECTED_SHA256" ]; then
  echo "template sha256 mismatch: expected $EXPECTED_SHA256, got $SHA256" >&2
  exit 1
fi
if [ "$MIGRATIONS" != "$EXPECTED_MIGRATIONS" ]; then
  echo "template migration count mismatch: expected $EXPECTED_MIGRATIONS, got $MIGRATIONS" >&2
  exit 1
fi
if [ "$LATEST_MIGRATION_VERSION" != "$EXPECTED_LATEST_MIGRATION_VERSION" ]; then
  echo "template latest migration version mismatch: expected $EXPECTED_LATEST_MIGRATION_VERSION, got $LATEST_MIGRATION_VERSION" >&2
  exit 1
fi

printf 'status=verified version=%s sha256=%s migrations=%s latest_migration_version=%s\n' \
  "$VERSION" "$SHA256" "$MIGRATIONS" "$LATEST_MIGRATION_VERSION"

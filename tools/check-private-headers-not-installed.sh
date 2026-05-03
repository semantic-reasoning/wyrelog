#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# check-private-headers-not-installed.sh
#
# Verifies that no file matching *-private.h appears in any
# install_headers() call or public header list in the meson build files.
# Exits 1 if a private header is found in an install path; exits 0 otherwise.

set -eu

SCRIPT_DIR=$(dirname "$0")
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

MESON_FILES="
$PROJECT_ROOT/meson.build
$PROJECT_ROOT/wyrelog/meson.build
"

FOUND=0

for f in $MESON_FILES; do
  if [ ! -f "$f" ]; then
    continue
  fi

  # Look for lines that both mention install_headers or _public_headers
  # and contain a *-private.h filename.
  # We scan the file line by line; a private header on any install-related
  # line is a violation.
  while IFS= read -r line; do
    case "$line" in
      *install_headers*|*_public_headers*|*install_dir*)
        case "$line" in
          *-private.h*)
            echo "ERROR: private header found in install context in $f:" >&2
            echo "  $line" >&2
            FOUND=1
            ;;
        esac
        ;;
    esac
  done < "$f"
done

# Also do a direct grep for belt-and-suspenders coverage across the
# entire wyrelog/ build subtree.
if grep -r -- '-private\.h' \
    "$PROJECT_ROOT/wyrelog/meson.build" \
    "$PROJECT_ROOT/meson.build" \
    2>/dev/null | grep -qE 'install_headers|_public_headers'; then
  echo "ERROR: grep found private header reference in install context." >&2
  FOUND=1
fi

if [ "$FOUND" -eq 1 ]; then
  echo "FAIL: private header(s) would be installed. Aborting." >&2
  exit 1
fi

echo "OK: no private headers found in install paths."
exit 0

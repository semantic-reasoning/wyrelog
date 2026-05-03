#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# check-private-headers-not-installed.sh
#
# Verifies that no file matching *-private.h appears in the installed
# header set.
#
# Strategy (two-tier):
#
#   1. If a builddir exists alongside the project root, use
#      `meson introspect --installed builddir` to query the actual
#      post-build install manifest.  This catches private headers
#      included via multi-line files(...) blocks that a line-grep
#      cannot see because the filename and the install_headers()
#      call are on different lines.
#
#   2. If no builddir exists (e.g. CI lint pass before first build),
#      fall back to a line-grep over all meson.build files in the
#      tree — the original heuristic.
#
# Exit codes: 0 = clean, 1 = private header found in install set.

set -eu

SCRIPT_DIR=$(dirname "$0")
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BUILDDIR="$PROJECT_ROOT/builddir"

FOUND=0

# -----------------------------------------------------------------------
# Tier 1: meson introspect (authoritative, requires a configured builddir)
# -----------------------------------------------------------------------
if [ -d "$BUILDDIR" ] && command -v meson >/dev/null 2>&1; then
  introspect_out=$(meson introspect --installed "$BUILDDIR" 2>/dev/null) || true
  if [ -n "$introspect_out" ]; then
    # introspect --installed emits JSON: {"dest": "src", ...}
    # Both keys and values can be install-destination paths.
    # A -private.h in any path (key or value) is a violation.
    if printf '%s\n' "$introspect_out" | grep -q -- '-private\.h'; then
      echo "ERROR (introspect): private header found in install manifest:" >&2
      printf '%s\n' "$introspect_out" | grep -- '-private\.h' >&2
      FOUND=1
    fi

    if [ "$FOUND" -eq 1 ]; then
      echo "FAIL: private header(s) would be installed. Aborting." >&2
      exit 1
    fi

    echo "OK: no private headers found in install paths (introspect)."
    exit 0
  fi
fi

# -----------------------------------------------------------------------
# Tier 2: line-grep fallback (no builddir or meson not on PATH)
# -----------------------------------------------------------------------
MESON_FILES="
$PROJECT_ROOT/meson.build
$PROJECT_ROOT/wyrelog/meson.build
"

for f in $MESON_FILES; do
  if [ ! -f "$f" ]; then
    continue
  fi

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

# Belt-and-suspenders: grep across the full wyrelog build subtree.
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

echo "OK: no private headers found in install paths (line-grep)."
exit 0

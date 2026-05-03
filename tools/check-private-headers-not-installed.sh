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
#   Tier 1 (authoritative, post-configure / CI after meson setup):
#     If a builddir exists alongside the project root AND meson is on PATH,
#     use `meson introspect --installed builddir` to query the actual
#     post-build install manifest.  This catches private headers included
#     via multi-line files(...) blocks that a line-grep cannot see because
#     the filename and the install_headers() call are on different lines.
#     A meson introspect failure (corrupt builddir, version mismatch) is
#     treated as a hard error — it exits 1 so CI catches the problem rather
#     than silently falling back to the weaker tier-2 check.
#
#   Tier 2 (fresh-checkout linting, no builddir available):
#     Fall back to a line-grep over all meson.build files in the tree —
#     the original heuristic.  Only used when meson is absent from PATH or
#     no builddir exists; not a substitute for tier-1 in CI.
#
# Exit codes: 0 = clean, 1 = private header found in install set or
#             meson introspect error when builddir is present.

set -eu

SCRIPT_DIR=$(dirname "$0")
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BUILDDIR="$PROJECT_ROOT/builddir"

FOUND=0

# -----------------------------------------------------------------------
# Tier 1: meson introspect (authoritative, post-configure CI mode)
# -----------------------------------------------------------------------
if [ -d "$BUILDDIR" ] && command -v meson >/dev/null 2>&1; then
  # Use `if ! var=$(cmd)` — exempt from set -e early-exit — so a meson
  # failure is captured and reported rather than silently terminating the
  # shell before $? can be read.  An empty result from a successful
  # introspect is valid (no installed files at all); non-zero is a hard error.
  # Note: $? inside the then-branch reflects the negated test result, not the
  # original exit code; store it via a subshell trick instead.
  introspect_out=$(meson introspect --installed "$BUILDDIR" 2>&1) || {
    introspect_rc=$?
    echo "ERROR: meson introspect failed (exit $introspect_rc) — builddir may be corrupt or stale." >&2
    echo "$introspect_out" >&2
    echo "Re-run 'meson setup builddir' and retry." >&2
    exit 1
  }

  # introspect --installed emits JSON: {"dest": "src", ...}
  # Both keys and values can be install-destination paths.
  # A -private.h in any path (key or value) is a violation.
  if printf '%s\n' "$introspect_out" | grep -q -- '-private\.h'; then
    echo "ERROR (introspect): private header found in install manifest:" >&2
    printf '%s\n' "$introspect_out" | grep -- '-private\.h' >&2
    echo "FAIL: private header(s) would be installed. Aborting." >&2
    exit 1
  fi

  echo "OK: no private headers found in install paths (introspect)."
  exit 0
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

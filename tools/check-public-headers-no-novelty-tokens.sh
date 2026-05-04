#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# check-public-headers-no-novelty-tokens.sh
#
# CI gate: verifies that installed public headers contain no forbidden
# internal-vocabulary tokens, no raw chronoid type references, and no
# bare struct declarations for WylAccess-prefixed GObject types.
#
# Strategy (two-tier):
#
#   Tier 1 (authoritative, post-configure / CI after meson setup):
#     If a builddir exists alongside the project root AND meson is on
#     PATH, use `meson introspect --installed builddir` to extract the
#     actual installed header paths from the build manifest, then grep
#     those files.  A meson introspect failure is a hard error.
#
#   Tier 2 (fresh-checkout linting, no builddir available):
#     Fall back to grepping the files listed in wyrelog_public_headers
#     in wyrelog/meson.build directly.
#
# Forbidden token regex (case-insensitive, word-bounded):
#   \b(armed|arm_rule|compound_scope|scope_term|differential|
#      delta_propag|fsm_gated|lobac|compound)\b
#
# Also forbidden:
#   - chronoid_uuidv7_t or <chronoid/ (vendored chronoid type leak)
#   - bare struct declarations of WylAccess-prefixed GObject types
#     (T7 bare-struct ABI lock-in guard)
#
# Exit codes: 0 = clean, 1 = violation found or introspect error.

set -eu

SCRIPT_DIR=$(dirname "$0")
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BUILDDIR="$PROJECT_ROOT/builddir"

# Forbidden token pattern (word-bounded, case-insensitive)
TOKEN_RE='\b(armed|arm_rule|compound_scope|scope_term|differential|delta_propag|fsm_gated|lobac|compound)\b'

FOUND=0

check_file () {
  f="$1"

  if [ ! -f "$f" ]; then
    return
  fi

  # Tier check: forbidden internal vocabulary tokens
  if grep -Ei "$TOKEN_RE" "$f" >/dev/null 2>&1; then
    echo "ERROR: forbidden token found in public header: $f" >&2
    grep -Eni "$TOKEN_RE" "$f" >&2
    FOUND=1
  fi

  # Check: no chronoid_uuidv7_t in public headers
  if grep -E 'chronoid_uuidv7_t' "$f" >/dev/null 2>&1; then
    echo "ERROR: chronoid_uuidv7_t found in public header: $f" >&2
    grep -En 'chronoid_uuidv7_t' "$f" >&2
    FOUND=1
  fi

  # Check: no <chronoid/ include in public headers
  if grep -E '<chronoid/' "$f" >/dev/null 2>&1; then
    echo "ERROR: <chronoid/ include found in public header: $f" >&2
    grep -En '<chronoid/' "$f" >&2
    FOUND=1
  fi

  # T7 bare-struct guard: no bare struct declarations for WylAccess types.
  # Matches lines like:
  #   struct _WylAccessEvent { ...
  #   struct WylAccessContext { ...
  # (The typedef alias "typedef struct _WylAccessEvent wyl_access_event_t;"
  #  is intentional and is NOT matched by this pattern.)
  if grep -E '^struct[[:space:]]+_?[Ww][Yy][Ll][Aa]ccess' "$f" >/dev/null 2>&1; then
    echo "ERROR: bare WylAccess struct body declaration in public header: $f" >&2
    grep -En '^struct[[:space:]]+_?[Ww][Yy][Ll][Aa]ccess' "$f" >&2
    FOUND=1
  fi
}

# -----------------------------------------------------------------------
# Tier 1: meson introspect (authoritative, post-configure CI mode)
# -----------------------------------------------------------------------
if [ -d "$BUILDDIR" ] && command -v meson >/dev/null 2>&1; then
  introspect_out=$(meson introspect --installed "$BUILDDIR" 2>&1) || {
    introspect_rc=$?
    echo "ERROR: meson introspect failed (exit $introspect_rc) -- builddir may be corrupt or stale." >&2
    echo "$introspect_out" >&2
    echo "Re-run 'meson setup builddir' and retry." >&2
    exit 1
  }

  # Extract installed header paths: source-side values in the JSON map that
  # live directly under $PROJECT_ROOT/wyrelog/ (the library source dir).
  # The introspect JSON maps install-destination -> source-path.
  # We want source paths that are the project's own public headers, i.e.
  # files under "$PROJECT_ROOT/wyrelog/" but NOT under
  # "$PROJECT_ROOT/subprojects/" or "$PROJECT_ROOT/builddir/".
  header_paths=$(printf '%s\n' "$introspect_out" \
    | grep -o "\"$PROJECT_ROOT/wyrelog/[^\"]*\\.h\"" \
    | sed 's/"//g') || true

  if [ -z "$header_paths" ]; then
    echo "OK: no wyrelog public headers in install manifest (introspect)."
    exit 0
  fi

  for h in $header_paths; do
    check_file "$h"
  done

  if [ "$FOUND" -eq 1 ]; then
    echo "FAIL: public header violation(s) found (introspect). Aborting." >&2
    exit 1
  fi

  echo "OK: no forbidden tokens in public headers (introspect)."
  exit 0
fi

# -----------------------------------------------------------------------
# Tier 2: line-grep fallback (no builddir or meson not on PATH)
# -----------------------------------------------------------------------
MESON_BUILD="$PROJECT_ROOT/wyrelog/meson.build"

if [ ! -f "$MESON_BUILD" ]; then
  echo "ERROR: cannot find $MESON_BUILD for tier-2 fallback." >&2
  exit 1
fi

# Extract filenames listed in wyrelog_public_headers = files(...).
# Read lines between the opening files( and the closing ).
in_block=0
while IFS= read -r line; do
  case "$line" in
    *wyrelog_public_headers*files*)
      in_block=1
      ;;
  esac
  if [ "$in_block" -eq 1 ]; then
    # Extract a quoted filename from the line, e.g. '  '\''audit.h'\'','
    fname=$(printf '%s' "$line" \
      | grep -o "'[^']*\.h'" \
      | sed "s/'//g") || true
    if [ -n "$fname" ]; then
      check_file "$PROJECT_ROOT/wyrelog/$fname"
    fi
    case "$line" in
      *\)*)
        in_block=0
        ;;
    esac
  fi
done < "$MESON_BUILD"

if [ "$FOUND" -eq 1 ]; then
  echo "FAIL: public header violation(s) found (line-grep). Aborting." >&2
  exit 1
fi

echo "OK: no forbidden tokens in public headers (line-grep)."
exit 0

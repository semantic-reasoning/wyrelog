#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fail when a GLib test binary does not register exactly the cases a
# committed manifest lists.
#
# This exists because a case that is never registered leaves no trace.
# When offline restore cases sat behind "#ifdef __linux__" in main(),
# macOS listed 211 of the 383 cases Linux lists and meson reported the run
# as Ok, since a case that does not exist can neither fail nor skip (#1303,
# #1391).  Cases are now registered on every non-Windows host and skip at
# runtime, and meson counts TAP skips outside "passed", so the console
# line looks the same before and after a case disappears.
#
# The property here is the inverse: the binary's -l listing must equal
# the manifest as a set, on every host that runs this guard.  Each
# missing or unexpected path is named.  A binary that is absent, fails,
# or lists nothing, and a manifest that is absent, empty, unsorted, or
# malformed, are failures, never passes: a guard that cannot read its
# input must not report a match.
#
# Usage:
#   check-glib-test-list.sh <test-binary> <manifest>
#   check-glib-test-list.sh --print <test-binary>
#
# --print writes the normalized, sorted listing to stdout, which is the
# form the manifest must take.  GLib before 2.90 lists each case as a
# bare path; 2.90 frames the listing as TAP and prefixes each path with
# "# ".  Both are accepted and the random-seed, plan, and suite
# Start/End lines are dropped.  Comparison is done in the C locale so
# both legs of CI sort the same way whatever the runner's LANG is.

set -eu
LC_ALL=C
export LC_ALL

usage () {
  echo "usage: $0 <test-binary> <manifest>" >&2
  echo "       $0 --print <test-binary>" >&2
  exit 2
}

fail () {
  echo "error: $*" >&2
  exit 1
}

mode=check
if [ "${1:-}" = --print ]; then
  mode=print
  shift
  [ "$#" -eq 1 ] || usage
else
  [ "$#" -eq 2 ] || usage
fi
binary=$1
manifest=${2:-}

# A bare name would be looked up on PATH when run, not in the current
# directory where it was checked.
case $binary in
  */*) ;;
  *) binary=./$binary ;;
esac

tmp=$(mktemp -d) || fail "mktemp failed"
trap 'rm -rf "${tmp:-}"' EXIT
trap 'exit 1' HUP INT TERM

# Listing side.
[ -e "$binary" ] || fail "$binary is missing"
[ -x "$binary" ] || fail "$binary is not executable"

# A bare command under set -e would end the script with the child's own
# status, and meson reads 77 as SKIP.  Every failure here exits 1.
if "$binary" -l > "$tmp/raw" 2> "$tmp/err"; then
  :
else
  rc=$?
  cat "$tmp/err" >&2
  fail "$binary -l exited with status $rc"
fi

sed -n -e 's|^# /|/|' -e '/^\//p' "$tmp/raw" | sort > "$tmp/listing"
count=$(grep -c . "$tmp/listing" || true)
[ "$count" -gt 0 ] || fail "$binary -l listed no test cases"

dups=$(uniq -d "$tmp/listing")
if [ -n "$dups" ]; then
  printf '%s\n' "$dups" | sed 's/^/error: listed more than once: /' >&2
  fail "$binary -l lists a path more than once"
fi

# GLib prints a TAP plan before the paths; when it is there, it must
# agree with the paths that were parsed, so a listing shape this script
# only half understands cannot pass as a shorter listing.
plan=$(sed -n 's/^1\.\.\([0-9][0-9]*\)$/\1/p' "$tmp/raw" | head -n 1)
if [ -n "$plan" ] && [ "$plan" != "$count" ]; then
  fail "$binary -l plan line says $plan cases but $count paths were listed"
fi

if [ "$mode" = print ]; then
  cat "$tmp/listing"
  exit 0
fi

# Manifest side.
[ -e "$manifest" ] || fail "$manifest is missing"
[ -f "$manifest" ] || fail "$manifest is not a regular file"
[ -r "$manifest" ] || fail "$manifest is not readable"
[ -s "$manifest" ] || fail "$manifest is empty"

bad=$(grep -n -v '^/[^[:space:]]*$' "$manifest" | head -n 1 || true)
if [ -n "$bad" ]; then
  fail "$manifest line ${bad%%:*} is not a test path"
fi

sort -u "$manifest" > "$tmp/manifest"
if ! cmp -s "$manifest" "$tmp/manifest"; then
  fail "$manifest is not sorted and unique;" \
    "write it with LC_ALL=C sort -u, one path per line"
fi

comm -23 "$tmp/manifest" "$tmp/listing" > "$tmp/missing"
comm -13 "$tmp/manifest" "$tmp/listing" > "$tmp/unexpected"
if [ -s "$tmp/missing" ] || [ -s "$tmp/unexpected" ]; then
  sed 's/^/missing: /' "$tmp/missing" >&2
  sed 's/^/unexpected: /' "$tmp/unexpected" >&2
  echo "hint: a case missing on one host only belongs in its" \
    "registration, not out of the manifest" >&2
  echo "hint: to regenerate the manifest from a Linux secure build:" >&2
  printf 'hint:   sh "%s" --print "%s" > "%s"\n' "$0" "$binary" "$manifest" >&2
  fail "$binary registers a different set of cases than $manifest"
fi

echo "$count registered cases match $manifest"

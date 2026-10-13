#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Self-test for tools/check-glib-test-list.sh.
#
# The guard exists so that a GLib test case lost from one host's
# registration cannot pass as "fewer subtests" (#1391).  A guard that is
# itself fail-open would recreate the problem, so every failure path is
# exercised here with stub binaries and manifests: each must exit 1 with
# an error line that names the cause, and the two listing shapes GLib
# prints (bare paths before 2.90, "# " prefixed paths from 2.90) must both
# pass.

set -eu
LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <path-to-check-glib-test-list.sh>" >&2
  exit 2
fi

guard=$1
if [ ! -f "$guard" ]; then
  echo "error: $guard is missing" >&2
  exit 1
fi
case $guard in
  /*) ;;
  *) guard=$PWD/$guard ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "${tmp:-}"' EXIT
trap 'exit 1' HUP INT TERM

status=0
checks=0

# write_stub NAME BODY: create an executable sh script that ignores its
# arguments and runs BODY.  printf keeps the body literal under dash.
write_stub () {
  printf '#!/bin/sh\n%s\n' "$2" > "$tmp/$1"
  chmod 755 "$tmp/$1"
}

# expect STATUS PATTERN DESCRIPTION ARGS...: run the guard with ARGS and
# require exit STATUS and, when PATTERN is not empty, that stderr contains
# PATTERN as a fixed string.
expect () {
  want=$1
  pattern=$2
  desc=$3
  shift 3
  checks=$((checks + 1))
  got=0
  sh "$guard" "$@" > "$tmp/out" 2> "$tmp/err" || got=$?
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: $desc: exit $got, want $want" >&2
    sed 's/^/  stderr: /' "$tmp/err" >&2
    status=1
    return
  fi
  if [ -n "$pattern" ] && ! grep -F -q -- "$pattern" "$tmp/err"; then
    echo "FAIL: $desc: stderr lacks '$pattern'" >&2
    sed 's/^/  stderr: /' "$tmp/err" >&2
    status=1
    return
  fi
  echo "ok: $desc"
}

# expect_stdout DESCRIPTION EXPECTED-FILE ARGS...: run the guard and
# require exit 0 with stdout byte-equal to EXPECTED-FILE.
expect_stdout () {
  desc=$1
  expected=$2
  shift 2
  checks=$((checks + 1))
  got=0
  sh "$guard" "$@" > "$tmp/out" 2> "$tmp/err" || got=$?
  if [ "$got" -ne 0 ]; then
    echo "FAIL: $desc: exit $got, want 0" >&2
    sed 's/^/  stderr: /' "$tmp/err" >&2
    status=1
    return
  fi
  if ! cmp -s "$tmp/out" "$expected"; then
    echo "FAIL: $desc: stdout differs from expected" >&2
    sed 's/^/  stdout: /' "$tmp/out" >&2
    status=1
    return
  fi
  echo "ok: $desc"
}

# Listing shapes.  GLib 2.90 frames -l output as TAP with "# " before
# each path; older GLib prints bare paths under the same header and plan.
write_stub tap 'printf "TAP version 14\n# random seed: R02S1\n1..3\n"
printf "# Start of x tests\n# /x/b\n# /x/a\n# End of x tests\n# /c\n"'
write_stub bare 'printf "TAP version 14\n# random seed: R02S1\n1..3\n"
printf "/x/b\n/x/a\n/c\n"'
write_stub empty 'printf "TAP version 14\n# random seed: R02S1\n1..0\n"'
write_stub exit1 'printf "/x/a\n"; exit 1'
write_stub exit77 'printf "TAP version 14\n1..1\n/x/a\n"; exit 77'
write_stub signal 'kill -s SEGV $$'
write_stub dup 'printf "TAP version 14\n1..4\n/x/a\n/x/a\n/x/b\n/c\n"'
write_stub short 'printf "TAP version 14\n1..5\n/x/a\n/x/b\n/c\n"'
write_stub tapshort 'printf "TAP version 14\n1..5\n# /x/a\n# /x/b\n# /c\n"'
write_stub huge 'printf "TAP version 14\n1..99999999999999999999999\n"
printf "/x/a\n/x/b\n/c\n"'
write_stub missing 'printf "TAP version 14\n1..2\n/x/a\n/c\n"'
write_stub extra 'printf "TAP version 14\n1..4\n/x/a\n/x/b\n/c\n/d\n"'
write_stub noplan 'printf "/x/b\n/x/a\n/c\n"'
printf '#!/bin/sh\nprintf "/x/a\\n"\n' > "$tmp/noexec"
chmod 644 "$tmp/noexec"

# Manifests.
printf '/c\n/x/a\n/x/b\n' > "$tmp/good.paths"
: > "$tmp/empty.paths"
printf '/x/b\n/c\n/x/a\n' > "$tmp/unsorted.paths"
printf '/c\n/x/a\n/x/a\n/x/b\n' > "$tmp/dup.paths"
printf '# comment\n/c\n/x/a\n/x/b\n' > "$tmp/comment.paths"
printf '/c\n\n/x/a\n/x/b\n' > "$tmp/blank.paths"
printf '/c\r\n/x/a\r\n/x/b\r\n' > "$tmp/crlf.paths"
printf '/c\n/x/a\n/x/b' > "$tmp/nonl.paths"
printf '/c\n/x/a\n/x/b\n' > "$tmp/unreadable.paths"
chmod 000 "$tmp/unreadable.paths"
mkdir "$tmp/dir.paths"

# Usage.
expect 2 'usage:' 'no arguments rejected'
expect 2 'usage:' 'one argument rejected' "$tmp/tap"
expect 2 'usage:' 'three arguments rejected' \
  "$tmp/tap" "$tmp/good.paths" extra
expect 2 'usage:' '--print without a binary rejected' --print
expect 2 'usage:' '--print with a manifest rejected' \
  --print "$tmp/tap" "$tmp/good.paths"

# Passing shapes.
expect 0 '' 'TAP-framed listing matches manifest' \
  "$tmp/tap" "$tmp/good.paths"
expect 0 '' 'bare listing matches manifest' \
  "$tmp/bare" "$tmp/good.paths"
expect 0 '' 'listing without a plan line matches manifest' \
  "$tmp/noplan" "$tmp/good.paths"
expect_stdout '--print lists TAP-framed paths sorted and bare' \
  "$tmp/good.paths" --print "$tmp/tap"
expect_stdout '--print lists bare paths sorted' \
  "$tmp/good.paths" --print "$tmp/bare"

# Binary failures.
expect 1 'is missing' 'missing binary fails' \
  "$tmp/absent" "$tmp/good.paths"
expect 1 'is not executable' 'non-executable binary fails' \
  "$tmp/noexec" "$tmp/good.paths"
expect 1 'exited with status 1' 'binary exit 1 fails' \
  "$tmp/exit1" "$tmp/good.paths"
expect 1 'exited with status 77' 'binary exit 77 fails with 1, not 77' \
  "$tmp/exit77" "$tmp/good.paths"
expect 1 'exited with status' 'binary killed by a signal fails' \
  "$tmp/signal" "$tmp/good.paths"
expect 1 'listed no test cases' 'empty listing fails' \
  "$tmp/empty" "$tmp/good.paths"
expect 1 'listed no test cases' '--print of an empty listing fails' \
  --print "$tmp/empty"
expect 1 'listed more than once: /x/a' 'duplicate listing entry fails' \
  "$tmp/dup" "$tmp/good.paths"
expect 1 'plan line says 5' 'plan count disagreeing with paths fails' \
  "$tmp/short" "$tmp/good.paths"
expect 1 'plan line says 5' 'TAP-framed plan disagreeing with paths fails' \
  "$tmp/tapshort" "$tmp/good.paths"
expect 1 'plan line says 99999999999999999999999' \
  'plan count beyond integer range fails' \
  "$tmp/huge" "$tmp/good.paths"

# A bare binary name must be the file in the current directory, not a
# PATH lookup.
checks=$((checks + 1))
if (cd "$tmp" && sh "$guard" tap good.paths > out 2> err); then
  echo "ok: bare binary name resolves in the current directory"
else
  echo "FAIL: bare binary name resolves in the current directory" >&2
  sed 's/^/  stderr: /' "$tmp/err" >&2
  status=1
fi

# Manifest failures.
expect 1 'is missing' 'missing manifest fails' \
  "$tmp/tap" "$tmp/absent.paths"
expect 1 'is empty' 'empty manifest fails' \
  "$tmp/tap" "$tmp/empty.paths"
expect 1 'is not a regular file' 'directory manifest fails' \
  "$tmp/tap" "$tmp/dir.paths"
if [ "$(id -u)" -ne 0 ]; then
  expect 1 'is not readable' 'unreadable manifest fails' \
    "$tmp/tap" "$tmp/unreadable.paths"
fi
expect 1 'not sorted and unique' 'unsorted manifest fails' \
  "$tmp/tap" "$tmp/unsorted.paths"
expect 1 'not sorted and unique' 'duplicate manifest entry fails' \
  "$tmp/tap" "$tmp/dup.paths"
expect 1 'not sorted and unique' \
  'manifest without a trailing newline fails' \
  "$tmp/tap" "$tmp/nonl.paths"
expect 1 'line 1 is not a test path' 'manifest comment line fails' \
  "$tmp/tap" "$tmp/comment.paths"
expect 1 'line 2 is not a test path' 'manifest blank line fails' \
  "$tmp/tap" "$tmp/blank.paths"
expect 1 'line 1 is not a test path' 'manifest CRLF line fails' \
  "$tmp/tap" "$tmp/crlf.paths"

# Mismatches name the paths and point at the regeneration command.
expect 1 'missing: /x/b' 'case missing from listing is named' \
  "$tmp/missing" "$tmp/good.paths"
expect 1 'regenerate' 'missing case prints the regeneration hint' \
  "$tmp/missing" "$tmp/good.paths"
expect 1 'unexpected: /d' 'case missing from manifest is named' \
  "$tmp/extra" "$tmp/good.paths"

if [ "$status" -eq 0 ]; then
  echo "check-glib-test-list self-test: $checks checks passed"
else
  echo "check-glib-test-list self-test: failures above" >&2
fi
exit "$status"

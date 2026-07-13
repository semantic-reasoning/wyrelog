#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

guard=$1
root=$2
source_file="$root/wyrelog/daemon/http.c"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/wyrelog-daemon-guard.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

expect_failure()
{
  fixture_root=$1
  fixture_name=$2
  shift 2
  if "$guard" "$fixture_root" "$@" >/dev/null 2>&1; then
    printf '%s\n' "error: guard accepted negative fixture: $fixture_name" >&2
    exit 1
  fi
}

shift 2
expect_failure "$tmp/missing" missing-source "$@"

fixture="$tmp/fixture"
mkdir -p "$fixture/wyrelog/daemon"
cp "$source_file" "$fixture/wyrelog/daemon/http.c"
printf '%s\n' 'policy_mutation_lock' >>"$fixture/wyrelog/daemon/http.c"
expect_failure "$fixture" forbidden-mutex "$@"

cp "$source_file" "$fixture/wyrelog/daemon/http.c"
printf '%s\n' 'g_mutex_lock (&other->lock);' >>"$fixture/wyrelog/daemon/http.c"
expect_failure "$fixture" wrong-lock-target "$@"

cp "$source_file" "$fixture/wyrelog/daemon/http.c"
printf '%s\n' 'g_mutex_lock (&other->lock); /* &ctx->lock */' \
  >>"$fixture/wyrelog/daemon/http.c"
expect_failure "$fixture" lock-target-comment-bypass "$@"

cp "$source_file" "$fixture/wyrelog/daemon/http.c"
chmod 000 "$fixture/wyrelog/daemon/http.c"
if [ ! -r "$fixture/wyrelog/daemon/http.c" ]; then
  expect_failure "$fixture" unreadable-source "$@"
fi
chmod 600 "$fixture/wyrelog/daemon/http.c"

sed 's/^tenant_mutation_handler[[:space:]]*(/tenant_mutation_removed(/' \
  "$source_file" >"$fixture/wyrelog/daemon/http.c"
expect_failure "$fixture" missing-handler "$@"

awk '
  /^tenant_mutation_handler[[:space:]]*\(/ { in_tenant = 1 }
  { print }
  in_tenant && /wyl_daemon_policy_write_acquire[[:space:]]*\(/ && !duplicated {
    print
    duplicated = 1
  }
' "$source_file" >"$fixture/wyrelog/daemon/http.c"
expect_failure "$fixture" duplicate-acquire "$@"

awk '
  /^tenant_mutation_handler[[:space:]]*\(/ { in_tenant = 1 }
  in_tenant &&
      /^[[:space:]]*wyrelog_error_t[[:space:]]+rc[[:space:]]*=[[:space:]]*wyl_daemon_policy_write_acquire[[:space:]]*\(/ && !removed {
    print "  /*"
    print "   * wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);"
    print "   */"
    removed = 1
    next
  }
  { print }
' "$source_file" >"$fixture/wyrelog/daemon/http.c"
expect_failure "$fixture" acquire-block-comment-bypass "$@"

awk '
  /^tenant_mutation_handler[[:space:]]*\(/ { in_tenant = 1 }
  in_tenant &&
      /^[[:space:]]*wyrelog_error_t[[:space:]]+rc[[:space:]]*=[[:space:]]*wyl_daemon_policy_write_acquire[[:space:]]*\(/ && !removed {
    print "#if 0"
    print
    print "#endif"
    removed = 1
    next
  }
  { print }
' "$source_file" >"$fixture/wyrelog/daemon/http.c"
expect_failure "$fixture" acquire-inactive-conditional-bypass "$@"

printf '%s\n' 'OK: daemon WRITE-authority guard rejects negative fixtures'

#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=${1:-.}
if [ "$#" -gt 0 ]; then
  shift
fi
source_file="$root/wyrelog/daemon/http.c"

if [ ! -f "$source_file" ] || [ ! -r "$source_file" ]; then
  printf '%s\n' "error: missing or unreadable daemon source: $source_file" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- "${CC:-cc}"
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/wyrelog-daemon-active.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
stripped_source="$tmp/http-no-includes.c"
active_source="$tmp/http-active.c"
sed '/^[[:space:]]*#[[:space:]]*include[[:space:]]/d' "$source_file" \
  >"$stripped_source"
if ! "$@" -E -P -x c -DWYL_HAS_DAEMON_HTTP -DWYL_HAS_FACT_STORE \
    -DWYL_HAS_AUDIT "$stripped_source" >"$active_source"; then
  printf '%s\n' 'error: failed to preprocess active daemon source' >&2
  exit 1
fi

if grep -n 'policy_mutation_lock' "$active_source" >&2; then
  printf '%s\n' \
    'error: daemon mutations must use the shared service-auth WRITE lease' >&2
  exit 1
fi

mutex_fields=$(grep -E '^[[:space:]]*GMutex[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;' \
  "$active_source" || true)
mutex_count=$(printf '%s\n' "$mutex_fields" | awk 'NF { count++ } END { print count + 0 }')
if [ "$mutex_count" -ne 1 ] ||
    ! printf '%s\n' "$mutex_fields" |
      grep -Eq '^[[:space:]]*GMutex[[:space:]]+lock[[:space:]]*;$'; then
  printf '%s\n' "$mutex_fields" >&2
  printf '%s\n' 'error: daemon context must contain only `GMutex lock;`' >&2
  exit 1
fi

bad_mutex_calls=$(grep -nE 'g_mutex_(lock|unlock)[[:space:]]*\(' "$active_source" |
  grep -vE '^[0-9]+:[[:space:]]*g_mutex_(lock|unlock)[[:space:]]*\([[:space:]]*&ctx->lock[[:space:]]*\)[[:space:]]*;[[:space:]]*$' || true)
if [ -n "$bad_mutex_calls" ]; then
  printf '%s\n' "$bad_mutex_calls" >&2
  printf '%s\n' 'error: daemon raw mutex calls may target only &ctx->lock' >&2
  exit 1
fi

if ! grep -Eq '^wyl_daemon_policy_write_acquire[[:space:]]*\(' "$active_source"; then
  printf '%s\n' 'error: shared daemon WRITE-acquire helper is missing' >&2
  exit 1
fi

awk '
BEGIN {
  expected["tenant_mutation_handler"] = 1
  expected["graph_create_handler"] = 1
  expected["graph_seal_handler"] = 1
  expected["schema_register_handler"] = 1
  expected["facts_route_handler"] = 2
  expected["direct_permission_mutation_handler"] = 1
  expected["policy_permission_transition_handler"] = 1
  expected["role_membership_mutation_handler"] = 1
  expected["mfa_enroll_confirm_handler"] = 1
}
function brace_delta(line, copy, opens, closes) {
  copy = line
  opens = gsub(/\{/, "", copy)
  copy = line
  closes = gsub(/\}/, "", copy)
  return opens - closes
}
{
  if (current == "") {
    for (name in expected) {
      if ($0 ~ "^" name "[[:space:]]*\\(") {
        current = name
        found[name]++
        depth = 0
        body_started = 0
        break
      }
    }
  }
  if (current != "") {
    if ($0 ~ /^[[:space:]]*(wyrelog_error_t[[:space:]]+)?rc[[:space:]]*=[[:space:]]*wyl_daemon_policy_write_acquire[[:space:]]*\([[:space:]]*ctx[[:space:]]*,[[:space:]]*&write[[:space:]]*\)[[:space:]]*;[[:space:]]*$/)
      acquire[current]++
    delta = brace_delta($0)
    if ($0 ~ /\{/)
      body_started = 1
    depth += delta
    if (body_started && depth == 0)
      current = ""
  }
}
END {
  failed = 0
  for (name in expected) {
    if (found[name] == 0) {
      printf "error: required function %s is missing\n", name > "/dev/stderr"
      failed = 1
    } else if (acquire[name] != expected[name]) {
      printf "error: %s must acquire WRITE %d time(s), found %d\n", name,
        expected[name], acquire[name] + 0 > "/dev/stderr"
      failed = 1
    }
  }
  exit failed
}
' "$active_source"

printf '%s\n' 'OK: daemon mutations use the shared WRITE authority'

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

readonly swap_bytes=8589934592
readonly active_size_floor=8000000000
readonly preallocate_free_floor=12000000000
readonly retained_free_floor=4000000000
readonly combined_memory_floor=24000000000
readonly marker_version=wyrelog-duckdb-swap-v1
# A root-owned child of a verified sticky root directory cannot be renamed or
# replaced by the unprivileged runner, unlike runner-owned temporary storage.
readonly trusted_anchor=/var/tmp

lease_path=
swap_path=
marker_path=
expected_marker=
lease_has_swap=0

fail()
{
  echo "DuckDB compile swap: $*" >&2
  exit 1
}

available_bytes()
{
  local target="$1"
  local available

  available="$(df -B1 --output=avail "$target" \
    | tail -1 | tr -d '[:space:]')"
  case "$available" in
    ''|*[!0-9]*)
      fail "invalid free-space result for $target"
      ;;
  esac
  printf '%s\n' "$available"
}

require_free_space()
{
  local floor="$1"
  local target available

  for target in "$trusted_anchor" "$GITHUB_WORKSPACE"; do
    available="$(available_bytes "$target")" || return
    test "$available" -ge "$floor" \
      || fail "insufficient free space on $target"
  done
}

validate_identity_component()
{
  local name="$1"
  local value="$2"

  case "$value" in
    ''|*[!A-Za-z0-9_.-]*)
      fail "invalid task identity component: $name"
      ;;
  esac
}

resolve_lease_paths()
{
  local purpose="$1"
  local workspace_path lease_basename

  case "$purpose" in
    secure|seam)
      ;;
    *)
      fail "unknown lease purpose: $purpose"
      ;;
  esac

  validate_identity_component GITHUB_RUN_ID "${GITHUB_RUN_ID:-}"
  validate_identity_component GITHUB_RUN_ATTEMPT "${GITHUB_RUN_ATTEMPT:-}"
  validate_identity_component GITHUB_JOB "${GITHUB_JOB:-}"
  validate_trusted_anchor
  workspace_path="$(realpath "$GITHUB_WORKSPACE")"
  lease_basename="wyrelog-duckdb-${GITHUB_RUN_ID}-"
  lease_basename+="${GITHUB_RUN_ATTEMPT}-${GITHUB_JOB}-${purpose}.lease"
  lease_path="$trusted_anchor/$lease_basename"
  swap_path="$lease_path/compile.swap"
  marker_path="$lease_path/owner.marker"
  expected_marker="${marker_version}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}"
  expected_marker="${expected_marker}:${GITHUB_JOB}:${purpose}"

  test "$(dirname "$lease_path")" = "$trusted_anchor" \
    || fail "lease escaped trusted anchor: $lease_path"
  test "$(basename "$lease_path")" = "$lease_basename" \
    || fail "lease leaf name drifted: $lease_path"
  test "$(dirname "$swap_path")" = "$lease_path" \
    && test "$(basename "$swap_path")" = compile.swap \
    || fail "swap leaf path drifted: $swap_path"
  test "$(dirname "$marker_path")" = "$lease_path" \
    && test "$(basename "$marker_path")" = owner.marker \
    || fail "marker leaf path drifted: $marker_path"
  case "$lease_path" in
    "$workspace_path"|"$workspace_path"/*)
      fail "lease must remain outside the checkout: $lease_path"
      ;;
  esac
}

require_root_node()
{
  local path="$1"
  local expected_mode="$2"
  local owner group mode

  owner="$(sudo stat -c %u "$path")" \
    || fail "cannot inspect owner: $path"
  group="$(sudo stat -c %g "$path")" \
    || fail "cannot inspect group: $path"
  mode="$(sudo stat -c %a "$path")" \
    || fail "cannot inspect mode: $path"
  test "$owner" = 0 && test "$group" = 0 \
    || fail "lease evidence is not root-owned: $path"
  test "$mode" = "$expected_mode" \
    || fail "lease evidence mode drifted: $path"
}

validate_trusted_anchor()
{
  test "$(realpath "$trusted_anchor")" = "$trusted_anchor" \
    || fail "trusted anchor is not canonical"
  sudo test ! -L "$trusted_anchor" \
    || fail "trusted anchor is a symlink"
  sudo test -d "$trusted_anchor" \
    || fail "trusted anchor is not a directory"
  require_root_node "$trusted_anchor" 1777
}

validate_owned_lease()
{
  local entries expected_entries

  sudo test ! -L "$lease_path" \
    || fail "lease path is a symlink: $lease_path"
  sudo test -d "$lease_path" \
    || fail "lease path is not a directory: $lease_path"
  require_root_node "$lease_path" 700
  sudo test ! -L "$marker_path" \
    || fail "ownership marker is a symlink: $marker_path"
  sudo test -f "$marker_path" \
    || fail "ownership marker is missing: $marker_path"
  require_root_node "$marker_path" 600
  if ! printf '%s\n' "$expected_marker" \
      | sudo cmp -s - "$marker_path"; then
    fail "ownership marker does not match this task byte-for-byte"
  fi

  lease_has_swap=0
  if sudo test -e "$swap_path" || sudo test -L "$swap_path"; then
    sudo test ! -L "$swap_path" \
      || fail "swap file is a symlink: $swap_path"
    sudo test -f "$swap_path" \
      || fail "swap path is not a regular file: $swap_path"
    require_root_node "$swap_path" 600
    lease_has_swap=1
    expected_entries=$'compile.swap\nowner.marker'
  else
    expected_entries=owner.marker
  fi

  entries="$(sudo find "$lease_path" -mindepth 1 -maxdepth 1 \
    -printf '%f\n' | LC_ALL=C sort)" \
    || fail "cannot inspect lease contents"
  test "$entries" = "$expected_entries" \
    || fail "lease contains unowned entries"
}

active_swap_size()
{
  local active_swaps

  active_swaps="$(sudo swapon --show=NAME,SIZE --bytes --noheadings)" \
    || fail "cannot inspect active swap sizes"
  printf '%s\n' "$active_swaps" \
    | awk -v path="$swap_path" '$1 == path { print $2 }'
}

swap_is_active()
{
  local active_swaps

  active_swaps="$(sudo swapon --show=NAME --noheadings)" \
    || fail "cannot inspect active swap paths"
  printf '%s\n' "$active_swaps" | grep -Fxq "$swap_path"
}

recover_unmarked_lease()
{
  if sudo test -e "$marker_path" || sudo test -L "$marker_path"; then
    sudo rm -f -- "$marker_path"
  fi
  sudo rmdir -- "$lease_path" \
    || fail "cannot recover newly-created unmarked lease"
}

provision()
{
  local active_size mem_kib swap_kib combined_bytes

  if sudo test -e "$lease_path" || sudo test -L "$lease_path"; then
    fail "lease path already exists: $lease_path"
  fi
  require_free_space "$preallocate_free_floor"
  sudo mkdir -m 700 -- "$lease_path"
  if ! printf '%s\n' "$expected_marker" \
      | sudo install -m 600 -o 0 -g 0 /dev/stdin "$marker_path"; then
    recover_unmarked_lease
    fail "cannot create task ownership marker"
  fi
  validate_owned_lease

  sudo install -m 600 -o 0 -g 0 /dev/null "$swap_path"
  sudo fallocate -l "$swap_bytes" "$swap_path"
  validate_owned_lease
  test "$(sudo stat -c %s "$swap_path")" -eq "$swap_bytes" \
    || fail "swap file allocation size drifted"
  sudo mkswap "$swap_path"
  sudo swapon "$swap_path"

  active_size="$(active_swap_size)"
  case "$active_size" in
    ''|*[!0-9]*)
      fail "swap is not active at the exact task-owned path"
      ;;
  esac
  test "$active_size" -ge "$active_size_floor" \
    || fail "active swap is smaller than 8 GB"

  mem_kib="$(awk '$1 == "MemTotal:" { print $2 }' /proc/meminfo)"
  swap_kib="$(awk '$1 == "SwapTotal:" { print $2 }' /proc/meminfo)"
  case "$mem_kib:$swap_kib" in
    *[!0-9:]*|:|*:|:*)
      fail "invalid Linux memory accounting"
      ;;
  esac
  combined_bytes="$(( (mem_kib + swap_kib) * 1024 ))"
  test "$combined_bytes" -ge "$combined_memory_floor" \
    || fail "combined RAM and swap floor was not met"
  require_free_space "$retained_free_floor"
}

cleanup()
{
  if ! sudo test -e "$lease_path" && ! sudo test -L "$lease_path"; then
    if swap_is_active; then
      fail "active swap has no owned lease: $swap_path"
    fi
    return 0
  fi
  validate_owned_lease

  if [ "$lease_has_swap" = 1 ]; then
    if swap_is_active; then
      sudo swapoff "$swap_path"
    fi
    if swap_is_active; then
      fail "swap remains active after swapoff: $swap_path"
    fi
    sudo rm -f -- "$swap_path"
  elif swap_is_active; then
    fail "active swap has no owned backing file: $swap_path"
  fi

  sudo rm -f -- "$marker_path"
  sudo rmdir -- "$lease_path"
  if sudo test -e "$lease_path" || sudo test -L "$lease_path"; then
    fail "owned lease remains after cleanup: $lease_path"
  fi
}

test "$#" -eq 2 || fail "usage: $0 {provision|cleanup} {secure|seam}"
operation="$1"
resolve_lease_paths "$2"

case "$operation" in
  provision)
    provision
    ;;
  cleanup)
    cleanup
    ;;
  *)
    fail "unknown operation: $operation"
    ;;
esac

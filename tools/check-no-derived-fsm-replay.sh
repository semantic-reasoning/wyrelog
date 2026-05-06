#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=${1:-.}

matches=$(
  find "$root/wyrelog" -type f \( -name '*.c' -o -name '*.h' \) \
    ! -name 'wyl-handle.c' \
    ! -name 'wyl-handle-private.h' \
    -exec grep -n 'wyl_handle_replay_delta_insert' {} + || true
)

if [ -n "$matches" ]; then
  printf '%s\n' "$matches" >&2
  printf '%s\n' \
    'error: derived FSM delta replay must stay inside WylHandle internals' >&2
  exit 1
fi

printf '%s\n' 'OK: no derived FSM delta replay outside WylHandle internals'

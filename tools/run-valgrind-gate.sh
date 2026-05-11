#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <executable> [args...]" >&2
  exit 2
fi

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind not installed; skipping leak-budget gate" >&2
  exit 77
fi

LOG=${WYL_VALGRIND_LOG:-valgrind.log}
rm -f "$LOG"

set +e
valgrind \
  --leak-check=full \
  --show-leak-kinds=definite \
  --errors-for-leak-kinds=definite \
  --error-exitcode=99 \
  --log-file="$LOG" \
  "$@"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  cat "$LOG" >&2 || true
  exit "$rc"
fi

if ! grep -Eq 'definitely lost: 0 bytes in 0 blocks' "$LOG"; then
  cat "$LOG" >&2 || true
  echo "valgrind definitely-lost budget exceeded" >&2
  exit 99
fi

echo "valgrind definitely-lost budget: 0 bytes"

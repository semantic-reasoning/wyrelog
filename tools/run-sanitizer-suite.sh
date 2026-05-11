#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

BUILD_DIR=${1:-builddir-sanitize}
shift || true
TEST_ARGS=${*:-"--suite wyrelog"}

CC=${CC:-cc}
CFLAGS="${CFLAGS:-} -fsanitize=address,undefined -fno-omit-frame-pointer"
LDFLAGS="${LDFLAGS:-} -fsanitize=address,undefined"
export CC CFLAGS LDFLAGS
export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=1:abort_on_error=1:print_summary=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1}"

if [ ! -d "$BUILD_DIR" ]; then
  meson setup "$BUILD_DIR" -Denable_audit=enabled -Dduckdb_source=prebuilt
fi

meson test -C "$BUILD_DIR" --print-errorlogs $TEST_ARGS

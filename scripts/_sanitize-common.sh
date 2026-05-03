#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Shared helper for the sanitizer build scripts. Sourced from each
# build-{san,tsan,ubsan}.sh; not invoked directly.
#
# Strategy: skip the broad `meson compile` step and run
# `meson test --suite wyrelog`, which only builds the targets the
# wyrelog test suite actually depends on. Subprojects that wyrelog
# does not link stay out of the sanitizer build, so their unrelated
# sanitizer warnings cannot block this gate.

set -euo pipefail

run_sanitizer_build () {
  local san_flag="$1"
  local builddir_suffix="$2"
  shift 2

  local repo_root
  repo_root="$(git rev-parse --show-toplevel)"
  cd "$repo_root"

  local builddir="builddir-${builddir_suffix}"
  rm -rf "$builddir"

  meson setup "$builddir" \
    -Dbuildtype=debug \
    -Db_sanitize="$san_flag" \
    -Db_lundef=false \
    "$@"

  meson test -C "$builddir" --suite wyrelog --print-errorlogs
}

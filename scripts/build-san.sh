#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Local AddressSanitizer build + test runner. Runs the wyrelog test
# suite under -fsanitize=address and exits non-zero on any failure.
#
# Common GLib hints for asan readability:
#   G_SLICE=always-malloc G_DEBUG=gc-friendly ./scripts/build-san.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/_sanitize-common.sh
. "$SCRIPT_DIR/_sanitize-common.sh"
run_sanitizer_build address asan "$@"

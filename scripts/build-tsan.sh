#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Local ThreadSanitizer build + test runner. Runs the wyrelog test
# suite under -fsanitize=thread. wyrelog is single-threaded in v0
# so this is a forward-looking gate.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/_sanitize-common.sh
. "$SCRIPT_DIR/_sanitize-common.sh"
run_sanitizer_build thread tsan "$@"

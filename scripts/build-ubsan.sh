#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Local UndefinedBehaviorSanitizer build + test runner. Runs the
# wyrelog test suite under -fsanitize=undefined.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/_sanitize-common.sh
. "$SCRIPT_DIR/_sanitize-common.sh"
run_sanitizer_build undefined ubsan "$@"

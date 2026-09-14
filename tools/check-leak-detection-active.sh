#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fail when leak detection is not actually active for the binaries a leak job
# is about to run.
#
# This exists because the previous leak gate did the opposite. When valgrind
# was absent tools/run-valgrind-gate.sh exited 77, meson recorded SKIP, and the
# summary line was byte-indistinguishable from a legitimate opt-in skip. No
# workflow ever installed valgrind, so the repo's only leak gate had never run
# and its absence was reported as success (#1059).
#
# The property here is the inverse: if the sanitizer is removed from the build,
# or leak detection is switched off in the environment, this says so and the
# job goes red. A leak job that cannot detect leaks must not pass.

set -eu

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <sanitized-binary> [more-binaries...]" >&2
  exit 2
fi

status=0

for binary in "$@"; do
  if [ ! -x "$binary" ]; then
    echo "error: $binary is missing or not executable" >&2
    status=1
    continue
  fi

  # A sanitized binary either links the shared runtime or, with a static
  # runtime, defines its initialiser. Check both rather than assume a linkage
  # mode: the answer that matters is "is ASan in this image at all".
  linked=0
  if command -v ldd >/dev/null 2>&1 \
      && ldd "$binary" 2>/dev/null | grep -q 'libasan'; then
    linked=1
  fi
  if [ "$linked" -eq 0 ] && command -v nm >/dev/null 2>&1; then
    if nm -D "$binary" 2>/dev/null | grep -q '__asan_init' \
        || nm "$binary" 2>/dev/null | grep -q '__asan_init'; then
      linked=1
    fi
  fi
  if [ "$linked" -eq 0 ]; then
    echo "error: $binary is not built with AddressSanitizer;" \
      "leak detection would report nothing and the job would pass" >&2
    status=1
    continue
  fi

  echo "ok: $binary carries the AddressSanitizer runtime"
done

# LeakSanitizer is on by default under ASan on Linux, so the failure mode worth
# guarding is someone turning it off in the environment to get a job green.
case "${ASAN_OPTIONS:-}" in
  *detect_leaks=0*)
    echo "error: ASAN_OPTIONS disables detect_leaks; a leak job that suppresses" \
      "leak detection is the outcome #1059 exists to prevent" >&2
    status=1
    ;;
esac

# A blanket suppression file is the other way to reach green without fixing
# anything, and #1059 rules it out explicitly.
if [ -n "${LSAN_OPTIONS:-}" ]; then
  case "${LSAN_OPTIONS}" in
    *suppressions=*)
      echo "error: LSAN_OPTIONS names a suppression file; known leaks are" \
        "fixed or justified in-tree, not suppressed wholesale" >&2
      status=1
      ;;
  esac
fi

if [ "$status" -eq 0 ]; then
  echo "leak detection active"
fi
exit "$status"

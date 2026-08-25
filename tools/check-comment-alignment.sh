#!/bin/sh
# Assert that uncrustify leaves correctly aligned block-comment continuation
# stars alone (#872).
#
# The cmt_multi_check_last heuristic removes the leading space from a block
# comment's continuation lines when the first and last lines are the same
# length, measured from the first non-space character.  That pulls correct
# alignment one column left and is idempotent, so the misaligned form becomes
# the only fixed point -- and under CLAUDE.md's ledger rule, the only
# committable one.  tools/uncrustify.cfg sets cmt_indent_multi = false to stop
# it.
#
# This drives the fixture through tools/format-c rather than calling uncrustify
# directly, so it inherits the version pin.  Calling the bare binary let a
# wrong-version formatter -- or one that does nothing at all -- report success,
# which is worse than skipping, because a skip announces itself and a vacuous
# pass does not.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
fixture="$root/tools/format-fixtures/block-comment-alignment.c"

# format-c resolves the repository with git rev-parse from its CWD, and meson
# runs tests with the BUILD directory as CWD.  Every invocation below therefore
# runs from the source root explicitly: an out-of-tree "meson setup" is
# standard and supported, and without this the check FAILS there rather than
# skipping, which is the opposite of what it intends.
if ! git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "source tree is not a git worktree; skipping" >&2
  exit 77
fi
if ! command -v uncrustify >/dev/null 2>&1; then
  echo "uncrustify not installed; skipping" >&2
  exit 77
fi
if ! (cd "$root" && ./tools/format-c --check-version) >/dev/null 2>&1; then
  echo "uncrustify present but not the pinned version; skipping" >&2
  exit 77
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$fixture" "$tmp/block-comment-alignment.c"

(cd "$root" && ./tools/format-c "$tmp/block-comment-alignment.c") >/dev/null

if ! diff -u "$fixture" "$tmp/block-comment-alignment.c"; then
  echo "check-comment-alignment: the formatter rewrote the fixture (#872)." >&2
  echo "  The diff above shows correct alignment being removed." >&2
  exit 1
fi

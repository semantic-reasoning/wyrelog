#!/bin/sh
# Behavioral regression tests for the committed formatting authority.

set -eu

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "test-format-tooling: not inside a Git worktree" >&2
  exit 1
}
"$REPO_ROOT/tools/format-c" --check-version > /dev/null

TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM
TEST_REPO="$TEST_ROOT/repo"
OUTPUT="$TEST_ROOT/output"

# ---------------------------------------------------------------------------
# Uncrustify 0.83.0's default multi-line comment indentation can pull correctly
# aligned continuation stars one column left.  Keep the trigger here as a
# runnable fixture, prove the repository configuration is a fixed point, and
# retain the previous configuration as a negative control.
# ---------------------------------------------------------------------------
COMMENT_CANONICAL="$TEST_ROOT/comment-indent-canonical.c"
COMMENT_FORMATTED="$TEST_ROOT/comment-indent-formatted.c"
COMMENT_OLD_OUTPUT="$TEST_ROOT/comment-indent-old-output.c"
OLD_CONFIG="$TEST_ROOT/uncrustify-old.cfg"
COMMENT_OPTION='cmt_indent_multi      = false'

cat > "$COMMENT_CANONICAL" <<'EOF'
/* SPDX-License-Identifier: GPL-3.0-or-later */
static int
f (void)
{
  /* The control: two intents really are PENDING before the rename, so a zero
   * count below is the survey failing and not an empty fixture.  This is a
   * seeding check, not a convergence check -- no reconcile pass runs here. */
  return 0;
}
EOF

cp "$COMMENT_CANONICAL" "$COMMENT_FORMATTED"
if ! (cd "$REPO_ROOT" && ./tools/format-c "$COMMENT_FORMATTED"); then
  echo "test-format-tooling: current comment fixture formatting failed" >&2
  exit 1
fi
if ! cmp -s "$COMMENT_CANONICAL" "$COMMENT_FORMATTED"; then
  echo "test-format-tooling: aligned comment is not a formatter fixed point" >&2
  diff -u "$COMMENT_CANONICAL" "$COMMENT_FORMATTED" >&2 || true
  exit 1
fi
echo "test-format-tooling: aligned comment fixed point: OK"

UNCRUSTIFY=$(command -v uncrustify 2> /dev/null) || {
  echo "test-format-tooling: pinned uncrustify is unavailable" >&2
  exit 1
}
if [ "$("$UNCRUSTIFY" --version 2>&1 | head -1)" != "Uncrustify-0.83.0_f" ]; then
  echo "test-format-tooling: old-config control requires Uncrustify-0.83.0_f" >&2
  exit 1
fi

if [ "$(grep -Fxc "$COMMENT_OPTION" "$REPO_ROOT/tools/uncrustify.cfg")" -ne 1 ]; then
  echo "test-format-tooling: expected exactly one '$COMMENT_OPTION' assignment" >&2
  exit 1
fi
if ! awk -v expected="$COMMENT_OPTION" '
  $0 == expected { removed++; next }
  { print }
  END { if (removed != 1) exit 1 }
' "$REPO_ROOT/tools/uncrustify.cfg" > "$OLD_CONFIG"; then
  echo "test-format-tooling: could not construct exact old formatter config" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*cmt_indent_multi[[:space:]]*=' "$OLD_CONFIG"; then
  echo "test-format-tooling: old formatter config retained cmt_indent_multi" >&2
  exit 1
fi

cp "$COMMENT_CANONICAL" "$COMMENT_OLD_OUTPUT"
if ! "$UNCRUSTIFY" -c "$OLD_CONFIG" -l C --replace --no-backup -q \
  "$COMMENT_OLD_OUTPUT"; then
  echo "test-format-tooling: old formatter config did not execute successfully" >&2
  exit 1
fi
if cmp -s "$COMMENT_CANONICAL" "$COMMENT_OLD_OUTPUT"; then
  echo "test-format-tooling: old formatter config did not reproduce #872" >&2
  exit 1
fi
echo "test-format-tooling: old comment rewrite reproduced: OK"

expect_failure()
{
  label=$1
  shift
  if "$@" > "$OUTPUT" 2>&1; then
    echo "test-format-tooling: expected failure: $label" >&2
    cat "$OUTPUT" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Installer prefix validation must complete before any download or build
# command runs, so a rejected prefix can never leave side effects behind.
# ---------------------------------------------------------------------------
FAKE_INSTALL_BIN="$TEST_ROOT/fake-install-bin"
INSTALL_SIDE_EFFECT_MARKER="$TEST_ROOT/install-side-effect"
export INSTALL_SIDE_EFFECT_MARKER
mkdir -p "$FAKE_INSTALL_BIN"
for fake_tool in curl cmake tar; do
  {
    printf '%s\n' '#!/bin/sh'
    # shellcheck disable=SC2016 # The generated child script expands these.
    printf '%s\n' 'printf "%s\n" "$0" >> "$INSTALL_SIDE_EFFECT_MARKER"'
    printf '%s\n' 'exit 99'
  } > "$FAKE_INSTALL_BIN/$fake_tool"
  chmod +x "$FAKE_INSTALL_BIN/$fake_tool"
done

expect_prefix_rejected_before_tools()
{
  label=$1
  prefix=$2
  rm -f "$INSTALL_SIDE_EFFECT_MARKER"
  expect_failure "$label" \
    env PATH="$FAKE_INSTALL_BIN:$PATH" \
    "$REPO_ROOT/tools/install-uncrustify.sh" "$prefix"
  if [ -e "$INSTALL_SIDE_EFFECT_MARKER" ]; then
    echo "test-format-tooling: prefix rejected only after running tools: $label" >&2
    exit 1
  fi
}

expect_prefix_rejected_before_tools "relative prefix" "relative/prefix"
expect_prefix_rejected_before_tools "empty prefix" ""

PREFIX_LINK_TARGET="$TEST_ROOT/prefix-target"
PREFIX_LINK="$TEST_ROOT/prefix-link"
mkdir -p "$PREFIX_LINK_TARGET"
ln -s "$PREFIX_LINK_TARGET" "$PREFIX_LINK" 2> /dev/null || true
if [ -L "$PREFIX_LINK" ]; then
  expect_prefix_rejected_before_tools "symlink prefix" "$PREFIX_LINK"
  expect_prefix_rejected_before_tools "symlink prefix with trailing slash" \
    "$PREFIX_LINK/"
else
  # A developer host without symlink support (notably Git for Windows without
  # the privilege) materialises ln -s as a real directory, so there is nothing
  # to reject. The format CI job runs on Linux, where this always executes.
  echo "test-format-tooling: skipping symlink prefix cases (no symlink support)" >&2
fi

# ---------------------------------------------------------------------------
# The committed authority files must stay executable in the index; the checker
# depends on that and cannot repair a committed 100644 mode.
# ---------------------------------------------------------------------------
for authority_path in \
  tools/format-c \
  tools/check-comment-alignment.sh \
  tools/check-format.sh \
  tools/install-uncrustify.sh \
  tools/setup-git-hooks.sh \
  tools/test-format-tooling.sh \
  hooks/pre-commit
do
  authority_mode=$(git -C "$REPO_ROOT" ls-files -s -- "$authority_path" |
    awk 'NR == 1 { print $1 }')
  if [ "$authority_mode" != 100755 ]; then
    echo "test-format-tooling: committed authority is not executable: $authority_path" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Build a self-contained repository carrying the same authority files.
# ---------------------------------------------------------------------------
git init -q "$TEST_REPO"
git -C "$TEST_REPO" config user.name "Format Test"
git -C "$TEST_REPO" config user.email "format-test@example.invalid"
mkdir -p "$TEST_REPO/tools" "$TEST_REPO/hooks"
for copied in \
  tools/format-c \
  tools/check-comment-alignment.sh \
  tools/check-format.sh \
  tools/install-uncrustify.sh \
  tools/setup-git-hooks.sh \
  tools/test-format-tooling.sh \
  tools/uncrustify.cfg \
  hooks/pre-commit
do
  cp -p "$REPO_ROOT/$copied" "$TEST_REPO/$copied"
done

for copied_authority in \
  "$TEST_REPO/tools/format-c" \
  "$TEST_REPO/tools/check-comment-alignment.sh" \
  "$TEST_REPO/tools/check-format.sh" \
  "$TEST_REPO/tools/install-uncrustify.sh" \
  "$TEST_REPO/tools/setup-git-hooks.sh" \
  "$TEST_REPO/tools/test-format-tooling.sh" \
  "$TEST_REPO/hooks/pre-commit"
do
  if [ ! -x "$copied_authority" ]; then
    echo "test-format-tooling: cp -p lost executable mode: $copied_authority" >&2
    exit 1
  fi
done

check_staged()
{
  (cd "$TEST_REPO" && ./tools/check-format.sh --staged)
}

check_ledger()
{
  (cd "$TEST_REPO" && ./tools/check-format.sh --ledger)
}

restore_path()
{
  git -C "$TEST_REPO" restore --staged -- "$1" 2> /dev/null || true
  git -C "$TEST_REPO" restore -- "$1"
}

write_ledger()
{
  printf '%s\n' "$@" > "$TEST_REPO/tools/formatted-files.txt"
  git -C "$TEST_REPO" add tools/formatted-files.txt
}

printf 'int main(void){return 0;}\n' > "$TEST_REPO/sample.c"
"$TEST_REPO/tools/format-c" "$TEST_REPO/sample.c"
git -C "$TEST_REPO" add sample.c tools hooks
# A host without a filesystem executable bit (Git for Windows) stages these as
# 100644, which the checker rejects by design. Record the intended mode
# directly so the fixture is identical on every platform.
git -C "$TEST_REPO" update-index --chmod=+x \
  tools/format-c \
  tools/check-comment-alignment.sh \
  tools/check-format.sh \
  tools/install-uncrustify.sh \
  tools/setup-git-hooks.sh \
  tools/test-format-tooling.sh \
  hooks/pre-commit
write_ledger sample.c
git -C "$TEST_REPO" commit -q -m "seed"

# A migrated, formatted file passes both modes.
check_ledger
check_staged

# --------------------------------------------------------------------------
# Ledger validation.
# --------------------------------------------------------------------------
write_ledger "sample.c" "sample.c"
expect_failure "duplicate ledger entry" check_staged
restore_path tools/formatted-files.txt

write_ledger "zzz.c" "aaa.c"
expect_failure "unsorted ledger" check_staged
restore_path tools/formatted-files.txt

write_ledger "does/not/exist.c"
expect_failure "untracked ledger entry" check_staged
restore_path tools/formatted-files.txt

write_ledger "tools/format-c"
expect_failure "non-C ledger entry" check_staged
restore_path tools/formatted-files.txt

write_ledger "../escape.c"
expect_failure "ledger entry escaping the repository" check_staged
restore_path tools/formatted-files.txt

: > "$TEST_REPO/tools/formatted-files.txt"
git -C "$TEST_REPO" add tools/formatted-files.txt
expect_failure "empty ledger" check_staged
restore_path tools/formatted-files.txt

# --------------------------------------------------------------------------
# A migrated file that stops being a fixed point is rejected by both the
# staged check and the exhaustive ledger scan.
# --------------------------------------------------------------------------
printf 'int\nmain (void)\n{\n        return 0;\n}\n' > "$TEST_REPO/sample.c"
git -C "$TEST_REPO" add sample.c
expect_failure "migrated file is no longer a fixed point" check_staged
expect_failure "ledger scan sees the same drift" check_ledger
restore_path sample.c
check_staged

# --------------------------------------------------------------------------
# A touched C file outside the ledger is rejected; formatting it and adding it
# to the ledger clears the failure. This is what makes the migrated set grow.
# --------------------------------------------------------------------------
printf 'int added(void){return 1;}\n' > "$TEST_REPO/added.c"
git -C "$TEST_REPO" add added.c
expect_failure "changed C file missing from the ledger" check_staged
"$TEST_REPO/tools/format-c" "$TEST_REPO/added.c"
git -C "$TEST_REPO" add added.c
write_ledger "added.c" "sample.c"
check_staged
git -C "$TEST_REPO" commit -q -m "migrate added.c"

# NUL-delimited enumeration must preserve a pathname containing a newline.
# Windows cannot hand such a name to a Win32 formatter, so probe first; the
# format CI job runs on Linux, where this always executes.
ODD_PATH="$(printf 'odd\nname.c')"
if printf 'int odd(void){return 0;}\n' > "$TEST_REPO/$ODD_PATH" 2> /dev/null &&
  "$TEST_REPO/tools/format-c" "$TEST_REPO/$ODD_PATH" 2> /dev/null; then
  git -C "$TEST_REPO" add -- "$ODD_PATH"
  expect_failure "unusual pathname missing from the ledger" check_staged
  git -C "$TEST_REPO" rm -q --cached -- "$ODD_PATH"
  rm -f "$TEST_REPO/$ODD_PATH"
  check_staged
else
  rm -f "$TEST_REPO/$ODD_PATH" 2> /dev/null || true
  echo "test-format-tooling: skipping newline pathname case (unsupported here)" >&2
fi

# --------------------------------------------------------------------------
# The staged formatter blob is the authority and must be executed instead of
# the worktree copy; losing its executable bit is a failure even though the
# checker could chmod its own temporary materialization.
# --------------------------------------------------------------------------
# Stage a correctly formatted C file so the formatter is actually executed on
# content; without one the staged check has nothing to run it against.
printf 'int added(void){return 2;}\n' > "$TEST_REPO/added.c"
"$TEST_REPO/tools/format-c" "$TEST_REPO/added.c"
git -C "$TEST_REPO" add added.c
check_staged

printf '\nexit 97\n' >> "$TEST_REPO/tools/format-c"
git -C "$TEST_REPO" add tools/format-c
expect_failure "staged formatter blob" check_staged
restore_path tools/format-c
check_staged

git -C "$TEST_REPO" update-index --chmod=-x tools/format-c
expect_failure "staged formatter executable mode" check_staged
git -C "$TEST_REPO" update-index --chmod=+x tools/format-c
check_staged

git -C "$TEST_REPO" update-index --chmod=-x hooks/pre-commit
expect_failure "staged hook executable mode" check_staged
git -C "$TEST_REPO" update-index --chmod=+x hooks/pre-commit
check_staged

# --------------------------------------------------------------------------
# The committed hook executes the staged checker blob.
# --------------------------------------------------------------------------
(cd "$TEST_REPO" && ./tools/setup-git-hooks.sh) > /dev/null
printf '\nexit 96\n' >> "$TEST_REPO/tools/check-format.sh"
git -C "$TEST_REPO" add tools/check-format.sh
expect_failure "hook runs the staged checker blob" \
  sh -c 'cd "$1" && ./hooks/pre-commit' sh "$TEST_REPO"
restore_path tools/check-format.sh

echo "test-format-tooling: OK"

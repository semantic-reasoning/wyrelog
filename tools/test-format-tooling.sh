#!/bin/sh
# Behavioral regression tests for the committed formatting authority.

set -eu

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "test-format-tooling: not inside a Git worktree" >&2
  exit 1
}
"$REPO_ROOT/tools/gst-indent" --check-version > /dev/null

TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM
TEST_REPO="$TEST_ROOT/repo"
OUTPUT="$TEST_ROOT/output"

expect_failure()
{
  label=$1
  shift
  if "$@" > "$OUTPUT" 2>&1; then
    echo "test-format-tooling: expected failure: $label" >&2
    exit 1
  fi
}

FAKE_INSTALL_BIN="$TEST_ROOT/fake-install-bin"
INSTALL_SIDE_EFFECT_MARKER="$TEST_ROOT/install-side-effect"
mkdir -p "$FAKE_INSTALL_BIN"
for fake_tool in curl make tar; do
  {
    printf '%s\n' '#!/bin/sh'
    # shellcheck disable=SC2016 # The generated child script expands these.
    printf '%s\n' \
      'printf "%s\n" "$0" >> "$INSTALL_SIDE_EFFECT_MARKER"'
    printf '%s\n' 'exit 99'
  } > "$FAKE_INSTALL_BIN/$fake_tool"
  chmod +x "$FAKE_INSTALL_BIN/$fake_tool"
done

expect_prefix_rejected_before_tools()
{
  label=$1
  prefix=$2
  rm -f "$INSTALL_SIDE_EFFECT_MARKER"
  status=0
  env INSTALL_SIDE_EFFECT_MARKER="$INSTALL_SIDE_EFFECT_MARKER" \
    PATH="$FAKE_INSTALL_BIN:$PATH" \
    "$REPO_ROOT/tools/install-gnu-indent.sh" "$prefix" \
    > "$OUTPUT" 2>&1 || status=$?
  if [ "$status" -ne 2 ]; then
    echo "test-format-tooling: invalid prefix did not exit 2: $label" >&2
    exit 1
  fi
  if [ -e "$INSTALL_SIDE_EFFECT_MARKER" ]; then
    echo "test-format-tooling: invalid prefix invoked download/build tool: $label" >&2
    exit 1
  fi
}

expect_prefix_reaches_tools()
{
  label=$1
  prefix=$2
  rm -f "$INSTALL_SIDE_EFFECT_MARKER"
  expect_failure "$label" \
    env INSTALL_SIDE_EFFECT_MARKER="$INSTALL_SIDE_EFFECT_MARKER" \
    PATH="$FAKE_INSTALL_BIN:$PATH" \
    "$REPO_ROOT/tools/install-gnu-indent.sh" "$prefix"
  if [ ! -s "$INSTALL_SIDE_EFFECT_MARKER" ]; then
    echo "test-format-tooling: valid prefix did not invoke download tool: $label" >&2
    exit 1
  fi
}

# Prefix validation must finish before download or build commands can run.
# Canonical root aliases and a symlink at the requested leaf are always
# rejected. Ancestor symlinks are allowed and resolved physically.
expect_prefix_rejected_before_tools "empty installer prefix" ""
expect_prefix_rejected_before_tools "relative installer prefix" relative
expect_prefix_rejected_before_tools "portable canonical root installer prefix" /..
if [ "$(CDPATH='' cd -P /tmp/.. && pwd -P)" = "/" ]; then
  expect_prefix_rejected_before_tools "tmp dot-dot canonical root prefix" \
    /tmp/..
fi

ROOT_PREFIX_LINK="$TEST_ROOT/root-prefix-link"
ln -s / "$ROOT_PREFIX_LINK"
expect_prefix_rejected_before_tools "root symlink installer prefix" \
  "$ROOT_PREFIX_LINK/"

NON_ROOT_PREFIX_TARGET="$TEST_ROOT/non-root-prefix-target"
NON_ROOT_PREFIX_LINK="$TEST_ROOT/non-root-prefix-link"
mkdir -p "$NON_ROOT_PREFIX_TARGET"
ln -s "$NON_ROOT_PREFIX_TARGET" "$NON_ROOT_PREFIX_LINK"
expect_prefix_rejected_before_tools "non-root symlink installer prefix" \
  "$NON_ROOT_PREFIX_LINK/"

SPACE_PREFIX="$TEST_ROOT/space prefix"
TAB_PREFIX=$(printf '%s/tab\tprefix' "$TEST_ROOT")
NEWLINE_PREFIX=$(printf '%s/newline\nprefix' "$TEST_ROOT")
SEMICOLON_PREFIX="$TEST_ROOT/semicolon;prefix"
DOLLAR_PREFIX="$TEST_ROOT/dollar\$prefix"
BACKTICK_PREFIX="$TEST_ROOT/backtick\`prefix"
QUOTE_PREFIX="$TEST_ROOT/quote'prefix"
expect_prefix_rejected_before_tools "space in canonical installer prefix" \
  "$SPACE_PREFIX"
expect_prefix_rejected_before_tools "tab in canonical installer prefix" \
  "$TAB_PREFIX"
expect_prefix_rejected_before_tools "newline in canonical installer prefix" \
  "$NEWLINE_PREFIX"
expect_prefix_rejected_before_tools "semicolon in installer prefix" \
  "$SEMICOLON_PREFIX"
expect_prefix_rejected_before_tools "dollar in installer prefix" \
  "$DOLLAR_PREFIX"
expect_prefix_rejected_before_tools "backtick in installer prefix" \
  "$BACKTICK_PREFIX"
expect_prefix_rejected_before_tools "quote in installer prefix" \
  "$QUOTE_PREFIX"

rm -f "$INSTALL_SIDE_EFFECT_MARKER"
expect_failure "missing installer python3 diagnostic" \
  env INSTALL_SIDE_EFFECT_MARKER="$INSTALL_SIDE_EFFECT_MARKER" \
  PATH="$FAKE_INSTALL_BIN" \
  "$REPO_ROOT/tools/install-gnu-indent.sh" "$TEST_ROOT/python-prefix"
grep -F "required command not found: python3" "$OUTPUT" > /dev/null
test ! -e "$INSTALL_SIDE_EFFECT_MARKER"

UNSAFE_ANCESTOR_TARGET="$TEST_ROOT/unsafe;ancestor-target"
UNSAFE_ANCESTOR_LINK="$TEST_ROOT/unsafe-ancestor-link"
mkdir -p "$UNSAFE_ANCESTOR_TARGET"
ln -s "$UNSAFE_ANCESTOR_TARGET" "$UNSAFE_ANCESTOR_LINK"
expect_prefix_rejected_before_tools "unsafe canonical ancestor target" \
  "$UNSAFE_ANCESTOR_LINK/installed-prefix"

ANCESTOR_PREFIX_TARGET="$TEST_ROOT/ancestor-prefix-target"
ANCESTOR_PREFIX_LINK="$TEST_ROOT/ancestor-prefix-link"
mkdir -p "$ANCESTOR_PREFIX_TARGET"
ln -s "$ANCESTOR_PREFIX_TARGET" "$ANCESTOR_PREFIX_LINK"
expect_prefix_reaches_tools "ancestor symlink reaches installer download" \
  "$ANCESTOR_PREFIX_LINK/installed-prefix"
test -d "$ANCESTOR_PREFIX_TARGET/installed-prefix"

restore_path()
{
  git -C "$TEST_REPO" restore --staged -- "$1"
  git -C "$TEST_REPO" restore -- "$1"
}

check_all()
{
  (cd "$TEST_REPO" && ./tools/check-format.sh --all)
}

check_staged()
{
  (cd "$TEST_REPO" && ./tools/check-format.sh --staged)
}

run_hook()
{
  (cd "$TEST_REPO" && ./hooks/pre-commit)
}

setup_hooks()
{
  (cd "$TEST_REPO" && ./tools/setup-git-hooks.sh)
}

for authority_path in \
  tools/gst-indent \
  tools/check-format.sh \
  tools/install-gnu-indent.sh \
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

git init -q "$TEST_REPO"
git -C "$TEST_REPO" config user.name "Format Test"
git -C "$TEST_REPO" config user.email "format-test@example.invalid"
mkdir -p "$TEST_REPO/tools" "$TEST_REPO/hooks"
cp -p "$REPO_ROOT/tools/gst-indent" "$TEST_REPO/tools/gst-indent"
cp -p "$REPO_ROOT/tools/check-format.sh" "$TEST_REPO/tools/check-format.sh"
cp -p "$REPO_ROOT/tools/install-gnu-indent.sh" \
  "$TEST_REPO/tools/install-gnu-indent.sh"
cp -p "$REPO_ROOT/tools/setup-git-hooks.sh" \
  "$TEST_REPO/tools/setup-git-hooks.sh"
cp -p "$REPO_ROOT/tools/test-format-tooling.sh" \
  "$TEST_REPO/tools/test-format-tooling.sh"
cp -p "$REPO_ROOT/hooks/pre-commit" "$TEST_REPO/hooks/pre-commit"

for copied_authority in \
  "$TEST_REPO/tools/gst-indent" \
  "$TEST_REPO/tools/check-format.sh" \
  "$TEST_REPO/tools/install-gnu-indent.sh" \
  "$TEST_REPO/tools/setup-git-hooks.sh" \
  "$TEST_REPO/tools/test-format-tooling.sh" \
  "$TEST_REPO/hooks/pre-commit"
do
  if [ ! -x "$copied_authority" ]; then
    echo "test-format-tooling: cp -p lost executable mode: $copied_authority" >&2
    exit 1
  fi
done

printf 'int main(void){return 0;}\n' > "$TEST_REPO/sample.c"
"$TEST_REPO/tools/gst-indent" "$TEST_REPO/sample.c"
git -C "$TEST_REPO" add .
git -C "$TEST_REPO" commit -q -m "initial formatting fixture"
check_all

# NUL-delimited enumeration must preserve a pathname containing a newline.
ODD_PATH='odd
name.c'
printf 'int odd(void){return 1;}\n' > "$TEST_REPO/$ODD_PATH"
"$TEST_REPO/tools/gst-indent" "$TEST_REPO/$ODD_PATH"
git -C "$TEST_REPO" add "$ODD_PATH"
git -C "$TEST_REPO" commit -q -m "add unusual pathname"
check_all

printf 'int odd(void){return 2;}\n' > "$TEST_REPO/$ODD_PATH"
git -C "$TEST_REPO" add "$ODD_PATH"
printf '\n# unusual-path full-scan trigger\n' >> "$TEST_REPO/hooks/pre-commit"
git -C "$TEST_REPO" add hooks/pre-commit
expect_failure "unformatted staged unusual pathname" \
  check_staged
restore_path "$ODD_PATH"
restore_path hooks/pre-commit

# A staged C file is rejected and the same prospective blob passes after
# formatting.
printf 'int main(void){return 3;}\n' > "$TEST_REPO/sample.c"
git -C "$TEST_REPO" add sample.c
expect_failure "unformatted staged C source" \
  check_staged
"$TEST_REPO/tools/gst-indent" "$TEST_REPO/sample.c"
git -C "$TEST_REPO" add sample.c
check_staged
git -C "$TEST_REPO" commit -q -m "format staged fixture"

# A hook-only change requests a full prospective-index scan. An unstaged
# formatter edit must not influence that result.
printf '\n# hook-only trigger\n' >> "$TEST_REPO/hooks/pre-commit"
git -C "$TEST_REPO" add hooks/pre-commit
printf '\nexit 97\n' >> "$TEST_REPO/tools/gst-indent"
check_staged
git -C "$TEST_REPO" restore -- tools/gst-indent
restore_path hooks/pre-commit

# A staged formatter blob is the authority and must be executed instead of the
# worktree copy.
printf '\nexit 97\n' >> "$TEST_REPO/tools/gst-indent"
git -C "$TEST_REPO" add tools/gst-indent
expect_failure "staged formatter blob" \
  check_staged
restore_path tools/gst-indent

# Losing the executable bit is also a prospective formatter failure even
# though the checker could chmod its temporary materialization.
chmod -x "$TEST_REPO/tools/gst-indent"
git -C "$TEST_REPO" add tools/gst-indent
expect_failure "staged formatter executable mode" \
  check_staged
restore_path tools/gst-indent

# The future worktree hook must remain executable; the current hook cannot
# repair a committed 100644 mode after Git has selected it.
chmod -x "$TEST_REPO/hooks/pre-commit"
git -C "$TEST_REPO" add hooks/pre-commit
expect_failure "staged hook executable mode" \
  check_staged
restore_path hooks/pre-commit

# Seed a deliberately unformatted tracked file without the hook. Checker-only
# and hook-only changes must both expose it through the full-scan trigger.
printf 'int invalid(void){return 4;}\n' > "$TEST_REPO/invalid.c"
git -C "$TEST_REPO" add invalid.c
git -C "$TEST_REPO" commit -q --no-verify -m "seed invalid fixture"

printf '\n# checker-only trigger\n' >> "$TEST_REPO/tools/check-format.sh"
git -C "$TEST_REPO" add tools/check-format.sh
expect_failure "checker-only full scan" \
  check_staged
restore_path tools/check-format.sh

printf '\n# hook-only trigger\n' >> "$TEST_REPO/hooks/pre-commit"
git -C "$TEST_REPO" add hooks/pre-commit
expect_failure "hook-only full scan" \
  check_staged
restore_path hooks/pre-commit

"$TEST_REPO/tools/gst-indent" "$TEST_REPO/invalid.c"
git -C "$TEST_REPO" add invalid.c
git -C "$TEST_REPO" commit -q --no-verify -m "repair invalid fixture"

# The committed hook executes the staged checker blob. This is the strongest
# prospective contract possible for a worktree hook; Git itself chooses the
# worktree hook before the script can inspect the index.
printf '\nexit 96\n' >> "$TEST_REPO/tools/check-format.sh"
git -C "$TEST_REPO" add tools/check-format.sh
expect_failure "hook executes staged checker" \
  run_hook
restore_path tools/check-format.sh

# Setup is idempotent, applies to linked worktrees through the common local
# config, and resolves the relative path from each active worktree.
setup_hooks > /dev/null
setup_hooks > /dev/null
test "$(git -C "$TEST_REPO" config --local --get core.hooksPath)" = hooks
git -C "$TEST_REPO" branch linked-format-test
git -C "$TEST_REPO" worktree add -q "$TEST_ROOT/linked" linked-format-test
test "$(git -C "$TEST_ROOT/linked" config --get core.hooksPath)" = hooks
git -C "$TEST_ROOT/linked" hook run pre-commit

# A legacy linked worktree can lose the relative hook after switching to a
# pre-feature commit. Setup remains successful but must identify that worktree
# instead of leaving commits there silently ungated.
LEGACY_WORKTREE="$TEST_ROOT/legacy worktree"
LEGACY_WARNING="$TEST_ROOT/legacy-warning"
git -C "$TEST_REPO" worktree add -q -b legacy-format-test \
  "$LEGACY_WORKTREE" HEAD
git -C "$LEGACY_WORKTREE" rm -q hooks/pre-commit
git -C "$LEGACY_WORKTREE" commit -q -m "simulate pre-hook branch"
if ! setup_hooks > /dev/null 2> "$LEGACY_WARNING"; then
  echo "test-format-tooling: legacy worktree warning blocked setup" >&2
  exit 1
fi
grep -F "warning: linked worktree lacks executable hooks/pre-commit:" \
  "$LEGACY_WARNING" > /dev/null
grep -F "$LEGACY_WORKTREE" "$LEGACY_WARNING" > /dev/null

git clone -q "$TEST_REPO" "$TEST_ROOT/fresh"
(cd "$TEST_ROOT/fresh" && ./tools/setup-git-hooks.sh) > /dev/null
test "$(git -C "$TEST_ROOT/fresh" config --local --get core.hooksPath)" = hooks

# A helper owned by one repository cannot be used while the caller belongs to
# another repository, even when both repositories have valid committed hooks.
# shellcheck disable=SC2016 # The child shell expands its positional arguments.
expect_failure "caller and script repository roots differ" \
  sh -c 'cd "$1" && "$2"' sh "$TEST_ROOT/fresh" \
  "$TEST_REPO/tools/setup-git-hooks.sh"
test "$(git -C "$TEST_ROOT/fresh" config --get core.hooksPath)" = hooks
test "$(git -C "$TEST_REPO" config --get core.hooksPath)" = hooks

# An unpacked source tree below an unrelated parent repository must not mutate
# the parent's hooksPath. This is the same shape Meson guards before invoking
# the helper.
PARENT_REPO="$TEST_ROOT/parent"
NESTED_SOURCE="$PARENT_REPO/unpacked-wyrelog"
git init -q "$PARENT_REPO"
git -C "$PARENT_REPO" config core.hooksPath parent-hooks
mkdir -p "$NESTED_SOURCE/tools" "$NESTED_SOURCE/hooks"
cp -p "$REPO_ROOT/tools/setup-git-hooks.sh" \
  "$NESTED_SOURCE/tools/setup-git-hooks.sh"
cp -p "$REPO_ROOT/hooks/pre-commit" "$NESTED_SOURCE/hooks/pre-commit"
# shellcheck disable=SC2016 # The child shell expands its positional argument.
expect_failure "nested unpacked source refuses parent repository" \
  sh -c 'cd "$1" && ./tools/setup-git-hooks.sh' sh "$NESTED_SOURCE"
test "$(git -C "$PARENT_REPO" config --get core.hooksPath)" = parent-hooks

# Exercise a real commit failure and success through core.hooksPath.
printf 'int main(void){return 5;}\n' > "$TEST_REPO/sample.c"
git -C "$TEST_REPO" add sample.c
expect_failure "real commit rejects unformatted index" \
  git -C "$TEST_REPO" commit -q -m "must fail"
"$TEST_REPO/tools/gst-indent" "$TEST_REPO/sample.c"
git -C "$TEST_REPO" add sample.c
git -C "$TEST_REPO" commit -q -m "formatted commit passes"

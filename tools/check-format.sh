#!/bin/sh
# Check C source against the repository's pinned formatter.
#
# The tree is mid-migration from GNU indent to Uncrustify, so it is not
# uniformly formatted. tools/formatted-files.txt is the ledger of files that
# have been migrated; every one of them must be an exact fixed point of the
# pinned formatter. That ledger check is what keeps a formatter or
# configuration change from drifting silently: it re-verifies the whole
# migrated set on every run, not only what a change happens to touch.
#
# Any C file a change touches must additionally be in the ledger, so the
# migrated set only ever grows and touching a file is what migrates it.

set -eu

usage()
{
  echo "usage: tools/check-format.sh --staged|--changed <base-ref>|--ledger" >&2
  exit 2
}

BASE_REF=
case "${1-}" in
  --staged | --ledger)
    [ "$#" -eq 1 ] || usage
    MODE=$1
    ;;
  --changed)
    [ "$#" -eq 2 ] || usage
    MODE=$1
    BASE_REF=$2
    ;;
  *)
    usage
    ;;
esac

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "format: not inside a Git worktree" >&2
  exit 1
}
WORK_DIR=$(mktemp -d)
FILES="$WORK_DIR/files"
LEDGER="$WORK_DIR/ledger"
CHANGED="$WORK_DIR/changed"
UNMIGRATED="$WORK_DIR/unmigrated"
FAILURES="$WORK_DIR/failures"
INDEX_FORMATTER="$WORK_DIR/format-c"
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM

LEDGER_PATH=tools/formatted-files.txt
SOURCE=tree
FORMATTER="$REPO_ROOT/tools/format-c"

for executable_path in \
  tools/format-c \
  tools/check-comment-alignment.sh \
  tools/check-format.sh \
  tools/install-uncrustify.sh \
  tools/setup-git-hooks.sh \
  tools/test-format-tooling.sh \
  hooks/pre-commit
do
  index_mode=$(git -C "$REPO_ROOT" ls-files -s -- "$executable_path" |
    awk 'NR == 1 { print $1 }')
  if [ "$index_mode" != 100755 ]; then
    echo "format: index requires executable $executable_path" >&2
    exit 1
  fi
done

if [ "$MODE" = "--staged" ]; then
  SOURCE=index

  # The staged check must not execute an unstaged formatter. Materialize the
  # formatter blob from the prospective index before inspecting any source.
  if ! git -C "$REPO_ROOT" cat-file -e :tools/format-c 2>/dev/null; then
    echo "format: prospective index is missing tools/format-c" >&2
    exit 1
  fi
  git -C "$REPO_ROOT" show :tools/format-c > "$INDEX_FORMATTER"
  chmod +x "$INDEX_FORMATTER"
  FORMATTER=$INDEX_FORMATTER
fi

if [ ! -x "$FORMATTER" ]; then
  echo "format: formatter is missing or not executable: tools/format-c" >&2
  exit 1
fi
"$FORMATTER" --check-version > /dev/null

# Read the ledger from the same source as the content it governs, so a staged
# ledger edit is checked against staged content.
if [ "$SOURCE" = index ]; then
  if ! git -C "$REPO_ROOT" show ":$LEDGER_PATH" > "$LEDGER" 2>/dev/null; then
    echo "format: prospective index is missing $LEDGER_PATH" >&2
    exit 1
  fi
elif ! cp "$REPO_ROOT/$LEDGER_PATH" "$LEDGER"; then
  echo "format: missing $LEDGER_PATH" >&2
  exit 1
fi

# A Windows checkout materialises the ledger with CRLF endings. Normalise
# before validating, or every entry looks like it holds an invalid character.
tr -d '\r' < "$LEDGER" > "$LEDGER.lf" && mv "$LEDGER.lf" "$LEDGER"

if [ ! -s "$LEDGER" ]; then
  echo "format: $LEDGER_PATH is empty" >&2
  exit 1
fi
if ! LC_ALL=C sort -c -u "$LEDGER" 2> /dev/null; then
  echo "format: $LEDGER_PATH must be sorted and free of duplicates" >&2
  exit 1
fi
while IFS= read -r ledger_entry; do
  case "$ledger_entry" in
    '' | /* | *..* | *[!-A-Za-z0-9_./]*)
      echo "format: invalid $LEDGER_PATH entry: $ledger_entry" >&2
      exit 1
      ;;
  esac
  case "$ledger_entry" in
    *.c | *.h)
      ;;
    *)
      echo "format: $LEDGER_PATH may only list C sources: $ledger_entry" >&2
      exit 1
      ;;
  esac
done < "$LEDGER"

# One listing rather than one git invocation per entry: the hook runs this on
# every commit and the ledger only grows.
TRACKED="$WORK_DIR/tracked"
UNTRACKED_ENTRIES="$WORK_DIR/untracked-entries"
git -C "$REPO_ROOT" ls-files -- '*.c' '*.h' | LC_ALL=C sort > "$TRACKED"
LC_ALL=C comm -23 "$LEDGER" "$TRACKED" > "$UNTRACKED_ENTRIES"
if [ -s "$UNTRACKED_ENTRIES" ]; then
  echo "format: $LEDGER_PATH lists untracked paths:" >&2
  sed 's/^/  /' "$UNTRACKED_ENTRIES" >&2
  exit 1
fi

# --ledger and --changed re-verify the whole migrated set, which is what
# catches a formatter or configuration change. --staged deliberately does not:
# it runs in the pre-commit hook, where scanning every migrated file costs
# minutes and grows with the ledger. CI carries the exhaustive check instead.
if [ "$MODE" = "--staged" ]; then
  : > "$FILES"
else
  tr '\n' '\0' < "$LEDGER" > "$FILES"
fi

if [ "$MODE" != "--ledger" ]; then
  if [ "$MODE" = "--staged" ]; then
    git -C "$REPO_ROOT" diff --cached --name-only --diff-filter=ACMR -z -- \
      '*.c' '*.h' > "$CHANGED"
  else
    if ! git -C "$REPO_ROOT" rev-parse --verify --quiet "$BASE_REF" \
      > /dev/null; then
      echo "format: unknown base ref: $BASE_REF" >&2
      exit 1
    fi
    git -C "$REPO_ROOT" diff --name-only --diff-filter=ACMR -z \
      "$BASE_REF...HEAD" -- '*.c' '*.h' > "$CHANGED"
  fi

  # A touched C file must be migrated. This is what makes the ledger grow and
  # keeps the unmigrated remainder from being edited in the old style forever.
  : > "$UNMIGRATED"
  tr '\0' '\n' < "$CHANGED" | while IFS= read -r changed_path; do
    [ -n "$changed_path" ] || continue
    if ! grep -Fxq -- "$changed_path" "$LEDGER"; then
      printf '  %s\n' "$changed_path" >> "$UNMIGRATED"
    fi
  done
  if [ -s "$UNMIGRATED" ]; then
    echo "format: changed C files are not migrated to the pinned formatter:" >&2
    cat "$UNMIGRATED" >&2
    echo "format: run ./tools/format-c <file>, then add it to $LEDGER_PATH" >&2
    exit 1
  fi

  if [ "$MODE" = "--staged" ]; then
    cp "$CHANGED" "$FILES"
  fi
fi

if [ ! -s "$FILES" ]; then
  exit 0
fi

# POSIX sh has no portable NUL-delimited read. Linux and macOS both provide
# xargs -0; each child receives one exact pathname as an argv element.
# shellcheck disable=SC2016 # The single-quoted child script expands in sh -c.
if ! xargs -0 -n 1 sh -c '
  repo_root=$1
  source_kind=$2
  formatter=$3
  failures=$4
  path=$5
  input=$(mktemp)
  formatted=$(mktemp)
  trap '"'"'rm -f "$input" "$formatted"'"'"' EXIT HUP INT TERM

  if [ "$source_kind" = index ]; then
    if ! git -C "$repo_root" show ":$path" > "$input"; then
      echo "format: unable to read staged content: $path" >&2
      exit 1
    fi
  elif ! cp "$repo_root/$path" "$input"; then
    echo "format: tracked file is missing from the worktree: $path" >&2
    exit 1
  fi

  cp "$input" "$formatted"
  if ! "$formatter" "$formatted"; then
    echo "format: formatter failed while checking: $path" >&2
    exit 1
  fi
  if ! cmp -s "$input" "$formatted"; then
    {
      printf "  "
      printf "%s" "$path" | sed -n l
    } >> "$failures"
    exit 1
  fi
' sh "$REPO_ROOT" "$SOURCE" "$FORMATTER" "$FAILURES" < "$FILES"
then
  if [ -s "$FAILURES" ]; then
    if [ "$SOURCE" = index ]; then
      echo "format: staged content is not an Uncrustify 0.83.0 fixed point:" >&2
    else
      echo "format: migrated files are not an Uncrustify 0.83.0 fixed point:" >&2
    fi
    cat "$FAILURES" >&2
    echo "format: fix with ./tools/format-c <file>, then stage the result" >&2
  else
    echo "format: formatter failed before completing the fixed-point check" >&2
  fi
  exit 1
fi

#!/bin/sh
# Check tracked or staged C source with the repository's pinned formatter.

set -eu

usage()
{
  echo "usage: tools/check-format.sh --all|--staged" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in
  --all | --staged)
    MODE=$1
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
FAILURES="$WORK_DIR/failures"
INDEX_FORMATTER="$WORK_DIR/gst-indent"
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM

SOURCE=tree
FORMATTER="$REPO_ROOT/tools/gst-indent"
FULL_SCAN=false

for executable_path in \
  tools/gst-indent \
  tools/check-format.sh \
  tools/install-gnu-indent.sh \
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

if [ "$MODE" = "--all" ]; then
  git -C "$REPO_ROOT" ls-files -z -- '*.c' '*.h' > "$FILES"
else
  SOURCE=index

  # The staged check must not execute an unstaged formatter. Materialize the
  # formatter blob from the prospective index before inspecting any source.
  if ! git -C "$REPO_ROOT" cat-file -e :tools/gst-indent 2>/dev/null; then
    echo "format: prospective index is missing tools/gst-indent" >&2
    exit 1
  fi
  git -C "$REPO_ROOT" show :tools/gst-indent > "$INDEX_FORMATTER"
  chmod +x "$INDEX_FORMATTER"
  FORMATTER=$INDEX_FORMATTER

  for authority_path in \
    tools/gst-indent \
    tools/check-format.sh \
    tools/install-gnu-indent.sh \
    tools/setup-git-hooks.sh \
    hooks/pre-commit
  do
    if ! git -C "$REPO_ROOT" diff --cached --quiet -- "$authority_path"; then
      FULL_SCAN=true
      break
    fi
  done

  if [ "$FULL_SCAN" = true ]; then
    echo "format: formatter/checker/hook changed; checking the complete prospective index" >&2
    git -C "$REPO_ROOT" ls-files --cached -z -- '*.c' '*.h' > "$FILES"
  else
    git -C "$REPO_ROOT" diff --cached --name-only --diff-filter=ACMR -z -- \
      '*.c' '*.h' > "$FILES"
  fi
fi

if [ ! -s "$FILES" ]; then
  exit 0
fi

if [ ! -x "$FORMATTER" ]; then
  echo "format: formatter is missing or not executable: tools/gst-indent" >&2
  exit 1
fi
"$FORMATTER" --check-version > /dev/null

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
  backup="${formatted}~"
  trap '"'"'rm -f "$input" "$formatted" "$backup"'"'"' EXIT HUP INT TERM

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
      echo "format: staged content is not a GNU indent 2.2.13 fixed point:" >&2
    else
      echo "format: tracked tree is not a GNU indent 2.2.13 fixed point:" >&2
    fi
    cat "$FAILURES" >&2
    echo "format: fix with ./tools/gst-indent <file>, then stage the result" >&2
  else
    echo "format: formatter failed before completing the fixed-point check" >&2
  fi
  exit 1
fi

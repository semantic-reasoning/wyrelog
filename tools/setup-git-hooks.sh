#!/bin/sh
# Point this repository at its committed hooks in every linked worktree.

set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" 2>/dev/null && pwd -P) || {
  echo "setup-git-hooks: cannot resolve the script directory" >&2
  exit 1
}
SCRIPT_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null) || {
  echo "setup-git-hooks: script is not inside a Git worktree" >&2
  exit 1
}
CALLER_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "setup-git-hooks: not inside a Git worktree" >&2
  exit 1
}

SCRIPT_ROOT=$(CDPATH='' cd "$SCRIPT_ROOT" 2>/dev/null && pwd -P) || exit 1
CALLER_ROOT=$(CDPATH='' cd "$CALLER_ROOT" 2>/dev/null && pwd -P) || exit 1
if [ "$SCRIPT_DIR" != "$SCRIPT_ROOT/tools" ]; then
  echo "setup-git-hooks: refusing a script outside its repository tools directory" >&2
  exit 1
fi
if [ "$CALLER_ROOT" != "$SCRIPT_ROOT" ]; then
  echo "setup-git-hooks: caller and script repository roots do not match" >&2
  exit 1
fi

REPO_ROOT=$SCRIPT_ROOT
HOOK="$REPO_ROOT/hooks/pre-commit"

if [ ! -x "$HOOK" ]; then
  echo "setup-git-hooks: committed pre-commit hook is missing or not executable" >&2
  exit 1
fi

git -C "$REPO_ROOT" config --local core.hooksPath hooks
configured=$(git -C "$REPO_ROOT" config --local --get core.hooksPath)
effective=$(git -C "$REPO_ROOT" config --get core.hooksPath)
if [ "$configured" != hooks ] || [ "$effective" != hooks ]; then
  echo "setup-git-hooks: failed to activate relative core.hooksPath=hooks" >&2
  exit 1
fi

# core.hooksPath is stored in the common local config, so it takes effect in
# every linked worktree immediately. Older branches may not contain the
# committed hook yet; warn for each such worktree instead of leaving the bypass
# silent. Linux and macOS xargs both preserve the NUL-delimited worktree field.
# shellcheck disable=SC2016 # The single-quoted child script expands in sh -c.
git -C "$REPO_ROOT" worktree list --porcelain -z |
  xargs -0 -n 1 sh -c '
    field=$1
    case "$field" in
      "worktree "*)
        worktree_path=${field#worktree }
        if [ ! -x "$worktree_path/hooks/pre-commit" ]; then
          newline=$(printf "\nx")
          newline=${newline%x}
          case "$worktree_path" in
            *"$newline"*)
              path_hex=$(printf "%s" "$worktree_path" |
                od -An -tx1 | tr -d " \n")
              escaped_path="byte-hex:$path_hex"
              ;;
            *)
              escaped_path=$(printf "%s" "$worktree_path" | sed -n l)
              ;;
          esac
          echo "setup-git-hooks: warning: linked worktree lacks executable hooks/pre-commit: $escaped_path" >&2
        fi
        ;;
    esac
  ' sh

echo "setup-git-hooks: using $REPO_ROOT/hooks"

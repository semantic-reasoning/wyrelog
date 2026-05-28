#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

ROOT=${1:-.}
status=0

is_ignored_top_level_redirect_wrap() {
  wrap=$1

  case "$wrap" in
    "$ROOT"/subprojects/nanoarrow.wrap|"$ROOT"/subprojects/xxhash.wrap) ;;
    *) return 1 ;;
  esac

  name=$(basename "$wrap")
  expected_target="wirelog/subprojects/$name"

  grep -q '^\[wrap-redirect\]$' "$wrap" \
    && grep -q "^filename = $expected_target\$" "$wrap"
}

check_wrap_file() {
  wrap=$1

  if grep -q '^\[wrap-file\]' "$wrap"; then
    for key in source_url source_filename source_hash directory; do
      if ! grep -q "^${key} =" "$wrap"; then
        echo "$wrap: missing $key" >&2
        status=1
      fi
    done
    return
  fi

  if grep -q '^\[wrap-git\]' "$wrap"; then
    for key in url revision; do
      if ! grep -q "^${key} =" "$wrap"; then
        echo "$wrap: missing $key" >&2
        status=1
      fi
    done
    if grep -Eq '^revision = (main|master|HEAD)$' "$wrap"; then
      if [ "$(basename "$wrap")" != "wirelog.wrap" ]; then
        echo "$wrap: moving git revision requires an explicit allowlist" >&2
        status=1
      else
        echo "$wrap: moving revision allowed for in-family development dependency" >&2
      fi
    fi
    return
  fi

  echo "$wrap: unknown wrap type" >&2
  status=1
}

for wrap in "$ROOT"/subprojects/*.wrap; do
  [ -e "$wrap" ] || continue
  if is_ignored_top_level_redirect_wrap "$wrap"; then
    continue
  fi
  check_wrap_file "$wrap"
done

for name in wirelog libchronoid nanoarrow "xxHash-0.8.3"; do
  if [ -d "$ROOT/subprojects/$name" ]; then
    if ! find "$ROOT/subprojects/$name" -maxdepth 2 \
        \( -iname 'LICENSE*' -o -iname 'NOTICE*' \) | grep -q .; then
      echo "subprojects/$name: missing LICENSE/NOTICE metadata" >&2
      status=1
    fi
  fi
done

if [ -d "$ROOT/subprojects/packagecache" ]; then
  missing=0
  for wrap in "$ROOT"/subprojects/*.wrap; do
    [ -e "$wrap" ] || continue
    if is_ignored_top_level_redirect_wrap "$wrap"; then
      continue
    fi
    filename=$(sed -n 's/^source_filename = //p' "$wrap" | head -n 1)
    if [ -n "$filename" ] && [ ! -f "$ROOT/subprojects/packagecache/$filename" ]; then
      echo "$wrap: packagecache missing $filename" >&2
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ] && [ "${WYL_SUPPLY_CHAIN_REQUIRE_PACKAGECACHE:-0}" = "1" ]; then
    status=1
  fi
fi

exit "$status"

#!/bin/sh
# Install the exact Uncrustify release used by the formatting contract.

set -eu

VERSION=0.83.0
ARCHIVE="uncrustify-${VERSION}.tar.gz"
URL="https://github.com/uncrustify/uncrustify/releases/download/uncrustify-${VERSION}/${ARCHIVE}"
SHA256=0aed2c5df101d5108b9cc8d6da0dddfad1286a66b49c794e38b2a6d0d868393e

if [ "$#" -ne 1 ]; then
  echo "usage: tools/install-uncrustify.sh <absolute-prefix>" >&2
  exit 2
fi

REQUESTED_PREFIX=$1
case "$REQUESTED_PREFIX" in
  /*)
    ;;
  *)
    echo "install-uncrustify: prefix must be an absolute path" >&2
    exit 2
    ;;
esac

# Ignore trailing separators so they cannot hide a symlink at the requested
# prefix. Symlinks in ancestor components remain allowed for paths such as
# macOS /tmp, but the requested prefix itself must be a real directory.
while [ "$REQUESTED_PREFIX" != "/" ] &&
  [ "${REQUESTED_PREFIX%/}" != "$REQUESTED_PREFIX" ]; do
  REQUESTED_PREFIX=${REQUESTED_PREFIX%/}
done
if [ -L "$REQUESTED_PREFIX" ]; then
  echo "install-uncrustify: prefix must not be a symlink" >&2
  exit 2
fi

for required in curl cmake tar; do
  if ! command -v "$required" > /dev/null 2>&1; then
    echo "install-uncrustify: required command not found: $required" >&2
    exit 1
  fi
done

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM

curl -fsSL "$URL" -o "$WORK_DIR/$ARCHIVE"
if command -v sha256sum > /dev/null 2>&1; then
  printf '%s  %s\n' "$SHA256" "$WORK_DIR/$ARCHIVE" | sha256sum -c -
elif command -v shasum > /dev/null 2>&1; then
  actual=$(shasum -a 256 "$WORK_DIR/$ARCHIVE" | awk '{print $1}')
  if [ "$actual" != "$SHA256" ]; then
    echo "install-uncrustify: archive digest mismatch" >&2
    exit 1
  fi
else
  echo "install-uncrustify: sha256sum or shasum is required" >&2
  exit 1
fi

tar -xzf "$WORK_DIR/$ARCHIVE" -C "$WORK_DIR"
SOURCE_DIR=$(find "$WORK_DIR" -maxdepth 1 -type d -name 'uncrustify*' | head -1)
if [ -z "$SOURCE_DIR" ] || [ ! -f "$SOURCE_DIR/CMakeLists.txt" ]; then
  echo "install-uncrustify: unexpected archive layout" >&2
  exit 1
fi

mkdir -p "$REQUESTED_PREFIX"
if ! cmake -S "$SOURCE_DIR" -B "$WORK_DIR/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$REQUESTED_PREFIX" > "$WORK_DIR/cmake.log" 2>&1; then
  echo "install-uncrustify: cmake configuration failed" >&2
  tail -20 "$WORK_DIR/cmake.log" >&2
  exit 1
fi
if ! cmake --build "$WORK_DIR/build" --parallel > "$WORK_DIR/build.log" 2>&1
then
  echo "install-uncrustify: build failed" >&2
  tail -20 "$WORK_DIR/build.log" >&2
  exit 1
fi
if ! cmake --install "$WORK_DIR/build" > "$WORK_DIR/install.log" 2>&1; then
  echo "install-uncrustify: install failed" >&2
  tail -20 "$WORK_DIR/install.log" >&2
  exit 1
fi

installed="$REQUESTED_PREFIX/bin/uncrustify"
if [ ! -x "$installed" ]; then
  echo "install-uncrustify: installed binary is missing: $installed" >&2
  exit 1
fi
reported=$("$installed" --version 2>&1 | head -1)
case "$reported" in
  "Uncrustify-${VERSION}"*)
    ;;
  *)
    echo "install-uncrustify: installed $reported, expected Uncrustify-$VERSION" >&2
    exit 1
    ;;
esac
echo "$reported"

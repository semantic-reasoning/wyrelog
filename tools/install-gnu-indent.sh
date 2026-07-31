#!/bin/sh
# Install the exact GNU indent release used by the formatting contract.

set -eu

VERSION=2.2.13
ARCHIVE="indent-${VERSION}.tar.gz"
URL="https://ftp.gnu.org/gnu/indent/${ARCHIVE}"
SHA256=9e64634fc4ce6797b204bcb8897ce14fdd0ab48ca57696f78767c59cae578095

if [ "$#" -ne 1 ]; then
  echo "usage: tools/install-gnu-indent.sh <absolute-prefix>" >&2
  exit 2
fi

REQUESTED_PREFIX=$1
case "$REQUESTED_PREFIX" in
  /*)
    ;;
  *)
    echo "install-gnu-indent: prefix must be an absolute path" >&2
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

if ! command -v python3 > /dev/null 2>&1; then
  echo "install-gnu-indent: required command not found: python3" >&2
  exit 1
fi

validate_prefix()
{
  mode=$1
  path=$2
  python3 - "$mode" "$path" <<'PY'
import os
import sys

mode, path = sys.argv[1:]
if mode == "canonical":
    path = os.path.realpath(path)

allowed = frozenset(
    "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-"
)
label = "canonical install prefix" if mode == "canonical" else "install prefix"
if not path.startswith("/"):
    print(f"install-gnu-indent: {label} must be absolute", file=sys.stderr)
    raise SystemExit(2)
if any(character not in allowed for character in path):
    print(
        f"install-gnu-indent: {label} contains a character outside "
        "ASCII /A-Za-z0-9._+-",
        file=sys.stderr,
    )
    raise SystemExit(2)
if mode == "canonical":
    if path == "/":
        print(
            "install-gnu-indent: refusing canonical install prefix /",
            file=sys.stderr,
        )
        raise SystemExit(2)
    sys.stdout.write(path)
PY
}

validate_prefix requested "$REQUESTED_PREFIX"
if [ -L "$REQUESTED_PREFIX" ]; then
  echo "install-gnu-indent: install prefix itself must not be a symlink" >&2
  exit 2
fi

if ! mkdir -p "$REQUESTED_PREFIX"; then
  echo "install-gnu-indent: cannot create install prefix: $REQUESTED_PREFIX" >&2
  exit 2
fi
if [ -L "$REQUESTED_PREFIX" ]; then
  echo "install-gnu-indent: install prefix itself must not be a symlink" >&2
  exit 2
fi

CANONICAL_PREFIX=$(validate_prefix canonical "$REQUESTED_PREFIX") || exit $?

for command in curl make tar; do
  if ! command -v "$command" > /dev/null 2>&1; then
    echo "install-gnu-indent: required command not found: $command" >&2
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
    echo "install-gnu-indent: checksum mismatch for $ARCHIVE" >&2
    exit 1
  fi
else
  echo "install-gnu-indent: sha256sum or shasum is required" >&2
  exit 1
fi

tar -xzf "$WORK_DIR/$ARCHIVE" -C "$WORK_DIR"
(
  cd "$WORK_DIR/indent-$VERSION"
  ./configure --prefix="$CANONICAL_PREFIX"
  make -j2
  make install
)

installed_version=$("$CANONICAL_PREFIX/bin/indent" --version 2>&1 | head -1)
if [ "$installed_version" != "GNU indent $VERSION" ]; then
  echo "install-gnu-indent: installed version mismatch: $installed_version" >&2
  exit 1
fi

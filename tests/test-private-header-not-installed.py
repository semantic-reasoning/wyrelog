#!/usr/bin/env python3
"""Assert that one named private header is absent from Meson's install plan."""

import json
from pathlib import Path
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        print("usage: test-private-header-not-installed.py BUILDDIR HEADER",
              file=sys.stderr)
        return 2
    builddir = Path(sys.argv[1])
    header = sys.argv[2]
    result = subprocess.run(
        ["meson", "introspect", "--installed", str(builddir)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False)
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        return 1
    installed = json.loads(result.stdout)
    for destination, source in installed.items():
        if (Path(destination).name == header or Path(source).name == header):
            print(f"private header would be installed: {source} -> {destination}",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

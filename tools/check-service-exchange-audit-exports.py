#!/usr/bin/env python3
"""Reject service-exchange codec internals from the dynamic export table."""

from pathlib import Path
import re
import shutil
import subprocess
import sys


PROTECTED = {
    "wyl_service_exchange_audit_encode",
    "wyl_service_exchange_audit_material_clear",
}


def run(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError("export inspection failed: " + " ".join(command)
                           + "\n" + result.stdout)
    return result.stdout


def exports(artifact):
    suffix = artifact.suffix.lower()
    if suffix == ".dll":
        tool = shutil.which("llvm-readobj")
        if tool:
            return run([tool, "--coff-exports", str(artifact)])
        tool = shutil.which("objdump")
        if tool:
            return run([tool, "-p", str(artifact)])
        raise RuntimeError("no PE export-table inspector found")
    tool = shutil.which("nm") or shutil.which("llvm-nm")
    if not tool:
        raise RuntimeError("no dynamic symbol inspector found")
    if suffix == ".dylib":
        return run([tool, "-gU", str(artifact)])
    return run([tool, "-D", "--defined-only", str(artifact)])


def main():
    if len(sys.argv) != 2:
        print("usage: check-service-exchange-audit-exports.py LIBRARY",
              file=sys.stderr)
        return 2
    artifact = Path(sys.argv[1])
    if not artifact.is_file():
        print(f"library artifact missing: {artifact}", file=sys.stderr)
        return 1
    try:
        output = exports(artifact)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    found = {symbol for symbol in PROTECTED
             if re.search(r"(?<![A-Za-z0-9_])_?" + re.escape(symbol)
                          + r"(?:@\d+)?(?![A-Za-z0-9_])", output)}
    if found:
        print("private service-exchange symbols exported:", *sorted(found),
              sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

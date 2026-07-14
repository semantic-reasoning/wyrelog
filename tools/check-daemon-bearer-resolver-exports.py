#!/usr/bin/env python3
"""Reject bearer-resolver and test seams from the production export table."""

from pathlib import Path
import re
import shutil
import subprocess
import sys


PROTECTED = {
    "resolve_bearer_session",
    "wyl_daemon_http_resolve_bearer_for_test",
    "wyl_daemon_http_set_service_resolver_checkpoint_for_test",
    "wyl_daemon_http_fail_next_service_resolver_read_release_for_test",
    "wyl_daemon_http_service_resolver_terminal_entries_for_test",
}


def run(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError("export inspection failed: " + " ".join(command)
                           + "\n" + result.stdout)
    return result.stdout


def command_candidates(object_format, artifact):
    path = str(artifact)
    if object_format == "elf":
        return [("nm", "-D", "--defined-only", path),
                ("llvm-nm", "-D", "--defined-only", path)]
    if object_format == "macho":
        return [("nm", "-gU", path), ("llvm-nm", "-gU", path)]
    if object_format == "pe":
        return [("llvm-readobj", "--coff-exports", path),
                ("objdump", "-p", path)]
    raise ValueError(f"unsupported object format: {object_format}")


def exports(object_format, artifact, which=shutil.which, runner=run):
    for candidate in command_candidates(object_format, artifact):
        tool = which(candidate[0])
        if tool:
            return runner([tool, *candidate[1:]])
    raise RuntimeError(f"no {object_format} export-table inspector found")


def protected_symbols(output):
    return {symbol for symbol in PROTECTED
            if re.search(r"(?<![A-Za-z0-9_])_?" + re.escape(symbol)
                         + r"(?:@\d+)?(?![A-Za-z0-9_])", output)}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {"elf", "macho", "pe"}:
        print("usage: check-daemon-bearer-resolver-exports.py "
              "{elf|macho|pe} WYRELOGD",
              file=sys.stderr)
        return 2
    object_format = sys.argv[1]
    artifact = Path(sys.argv[2])
    if not artifact.is_file():
        print(f"daemon artifact missing: {artifact}", file=sys.stderr)
        return 1
    try:
        output = exports(object_format, artifact)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    found = protected_symbols(output)
    if found:
        print("private bearer-resolver symbols exported:", *sorted(found),
              sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

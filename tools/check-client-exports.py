#!/usr/bin/env python3
"""Verify the typed client management API is present in the library."""

from pathlib import Path
import re
import shutil
import subprocess
import sys


REQUIRED = {
    "wyl_client_sensitive_text_clear",
    "wyl_client_service_credential_clear",
    "wyl_client_service_credential_issue",
    "wyl_client_service_credential_handoff_receipt_clear",
    "wyl_client_service_credential_list",
    "wyl_client_service_credential_list_clear",
    "wyl_client_service_credential_get",
    "wyl_client_service_credential_revoke",
    "wyl_client_service_credential_rotate",
    "wyl_client_service_token_exchange",
    "wyl_client_service_token_result_clear",
    "wyl_client_service_principal_clear",
    "wyl_client_service_principal_create",
    "wyl_client_service_principal_disable",
    "wyl_client_service_principal_list",
}


def main():
    if len(sys.argv) != 2:
        print("usage: check-client-exports.py LIBRARY", file=sys.stderr)
        return 2
    artifact = Path(sys.argv[1])
    if not artifact.is_file():
        print(f"library artifact missing: {artifact}", file=sys.stderr)
        return 1
    suffix = artifact.suffix.lower()
    if suffix == ".dll":
        commands = []
        for name, args in (("llvm-readobj", ["--coff-exports"]),
                           ("objdump", ["-p"])):
            tool = shutil.which(name)
            if tool:
                commands.append([tool, *args, str(artifact)])
    elif suffix == ".dylib":
        commands = []
        for name in ("nm", "llvm-nm"):
            tool = shutil.which(name)
            if tool:
                commands.append([tool, "-gU", str(artifact)])
    else:
        commands = []
        for name in ("nm", "llvm-nm"):
            tool = shutil.which(name)
            if tool:
                commands.append([tool, "-g", str(artifact)])
    if not commands:
        print("no symbol inspector found", file=sys.stderr)
        return 1
    output = None
    for command in commands:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
        if result.returncode == 0:
            output = result.stdout
            break
    if output is None:
        print(result.stdout, file=sys.stderr)
        return 1
    missing = sorted(symbol for symbol in REQUIRED
                     if not re.search(r"(?<![A-Za-z0-9_])_?" +
                                     re.escape(symbol) +
                                     r"(?:@\d+)?(?![A-Za-z0-9_])",
                                     output))
    if missing:
        print("missing client exports:", *missing, sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

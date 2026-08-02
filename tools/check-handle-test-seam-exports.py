#!/usr/bin/env python3
"""Reject engine-session test seams from production binary symbols."""

from pathlib import Path
import re
import shutil
import subprocess
import sys


PROTECTED = {
    "wyl_handle_set_engine_session_checkpoint_for_test",
    "wyl_handle_set_reload_decision_checkpoint_for_test",
    "wyl_handle_set_engine_operation_checkpoint_for_test",
    "wyl_handle_set_audit_replay_checkpoint_for_test",
    "wyl_handle_engine_session_locked_for_test",
    "wyl_handle_pending_delta_count_for_test",
}


def run(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError("symbol inspection failed: " + " ".join(command)
                           + "\n" + result.stdout)
    return result.stdout


def command_candidates(object_format, artifact):
    path = str(artifact)
    if object_format == "elf":
        return [("nm", "--defined-only", path),
                ("llvm-nm", "--defined-only", path)]
    if object_format == "macho":
        return [("nm", "-U", path),
                ("llvm-nm", "--defined-only", path)]
    if object_format == "pe":
        return [("llvm-nm", "--defined-only", path),
                ("llvm-readobj", "--coff-exports", path),
                ("objdump", "-p", path)]
    raise ValueError(f"unsupported object format: {object_format}")


def symbols(object_format, artifact, which=shutil.which, runner=run):
    for candidate in command_candidates(object_format, artifact):
        tool = which(candidate[0])
        if tool:
            return runner([tool, *candidate[1:]])
    raise RuntimeError(f"no {object_format} symbol inspector found")


def protected_symbols(output):
    return {symbol for symbol in PROTECTED
            if re.search(r"(?<![A-Za-z0-9_])_?" + re.escape(symbol)
                         + r"(?:@\d+)?(?![A-Za-z0-9_])", output)}


def self_test():
    all_symbols = "\n".join(f"000 T _{symbol}@12" for symbol in PROTECTED)
    if protected_symbols(all_symbols) != PROTECTED:
        raise AssertionError("protected export parser missed a test seam")
    allowed = "000 T wyl_handle_engine_session_locked_for_testing\n"
    if protected_symbols(allowed):
        raise AssertionError("protected export parser accepted a substring")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if len(sys.argv) != 3 or sys.argv[1] not in {"elf", "macho", "pe"}:
        print("usage: check-handle-test-seam-exports.py "
              "{elf|macho|pe} LIBWYRELOG",
              file=sys.stderr)
        return 2
    object_format = sys.argv[1]
    artifact = Path(sys.argv[2])
    if not artifact.is_file():
        print(f"library artifact missing: {artifact}", file=sys.stderr)
        return 1
    try:
        output = symbols(object_format, artifact)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    found = protected_symbols(output)
    if found:
        print("handle test seams present in production library symbols:",
              *sorted(found), sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

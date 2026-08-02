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


def command_candidates(object_format, artifact_kind, artifact):
    path = str(artifact)
    if artifact_kind == "archive":
        if object_format == "pe":
            return [("llvm-nm", "--defined-only", path),
                    ("nm", "--defined-only", path),
                    ("dumpbin", "/nologo", "/symbols", path)]
        return [("nm", "--defined-only", path),
                ("llvm-nm", "--defined-only", path)]
    if artifact_kind != "shared":
        raise ValueError(f"unsupported artifact kind: {artifact_kind}")
    if object_format == "elf":
        return [("nm", "--defined-only", path),
                ("llvm-nm", "--defined-only", path)]
    if object_format == "macho":
        return [("nm", "-U", path),
                ("llvm-nm", "--defined-only", path)]
    if object_format == "pe":
        return [("llvm-readobj", "--coff-exports", path),
                ("objdump", "-p", path),
                ("dumpbin", "/nologo", "/exports", path)]
    raise ValueError(f"unsupported object format: {object_format}")


def symbols(object_format, artifact_kind, artifact, which=shutil.which,
            runner=run):
    for candidate in command_candidates(object_format, artifact_kind,
                                        artifact):
        tool = which(candidate[0])
        if tool:
            return runner([tool, *candidate[1:]])
    raise RuntimeError(f"no {object_format} {artifact_kind} symbol inspector "
                       "found")


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
    pe_shared = command_candidates("pe", "shared", Path("library.dll"))
    if pe_shared[0][0:2] != ("llvm-readobj", "--coff-exports"):
        raise AssertionError("PE shared inspection must prefer export directory")
    pe_archive = command_candidates("pe", "archive", Path("library.lib"))
    if pe_archive[0][0] != "llvm-nm":
        raise AssertionError("PE archive inspection must prefer defined symbols")
    calls = []

    def fake_which(tool):
        return "/fake/" + tool

    def empty_export_runner(command):
        calls.append(command)
        return ""

    output = symbols("pe", "shared", Path("library.dll"), fake_which,
                     empty_export_runner)
    if output or len(calls) != 1 or calls[0][0] != "/fake/llvm-readobj":
        raise AssertionError("successful empty PE export inspection fell through")
    try:
        symbols("pe", "shared", Path("library.dll"), lambda unused: None,
                empty_export_runner)
    except RuntimeError:
        pass
    else:
        raise AssertionError("missing PE export inspector did not fail closed")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if (len(sys.argv) != 5
            or sys.argv[1] not in {"absent", "present"}
            or sys.argv[2] not in {"elf", "macho", "pe"}
            or sys.argv[3] not in {"shared", "archive"}):
        print("usage: check-handle-test-seam-exports.py "
              "{absent|present} {elf|macho|pe} {shared|archive} ARTIFACT",
              file=sys.stderr)
        return 2
    expectation = sys.argv[1]
    object_format = sys.argv[2]
    artifact_kind = sys.argv[3]
    artifact = Path(sys.argv[4])
    if not artifact.is_file():
        print(f"library artifact missing: {artifact}", file=sys.stderr)
        return 1
    try:
        output = symbols(object_format, artifact_kind, artifact)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    found = protected_symbols(output)
    if expectation == "absent" and found:
        print("handle test seams present in production library symbols:",
              *sorted(found), sep="\n  ", file=sys.stderr)
        return 1
    if expectation == "present" and found != PROTECTED:
        print("handle test companion is missing protected symbols:",
              *sorted(PROTECTED - found), sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

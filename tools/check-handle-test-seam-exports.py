#!/usr/bin/env python3
"""Reject guarded test seams from production binary symbols.

Originally scoped to the engine-session seams; the set now covers guarded
*_for_test seams from other subsystems too, so keep the name generic.
"""

from pathlib import Path
import re
import shutil
import subprocess
import sys


PROTECTED = {
    "wyl_audit_conn_duckdb_config_fail_once_for_test",
    "wyl_audit_conn_duckdb_config_snapshot_for_test",
    "wyl_handle_set_engine_session_checkpoint_for_test",
    "wyl_handle_set_reload_decision_checkpoint_for_test",
    "wyl_handle_set_engine_operation_checkpoint_for_test",
    "wyl_handle_set_audit_replay_checkpoint_for_test",
    "wyl_handle_engine_session_locked_for_test",
    "wyl_handle_pending_delta_count_for_test",
    "wyl_fact_store_set_batch_fault_once_for_test",
    "wyl_fact_store_test_exec_sql",
    "wyl_fact_store_test_query_int64",
    "wyl_fact_store_test_query_text",
    "wyl_fact_store_test_rename_metadata_value_column_at_checkpoint",
}
SENTINEL = "wyl_init"


def run(command):
    result = subprocess.run(command, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            check=False)
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


def contains_symbol(output, symbol):
    return re.search(r"(?<![A-Za-z0-9_])_?" + re.escape(symbol)
                     + r"(?:@\d+)?(?![A-Za-z0-9_])", output) is not None


def verify_output(expectation, output):
    if not contains_symbol(output, SENTINEL):
        raise RuntimeError("symbol inspector output lacks production sentinel: "
                           + SENTINEL)
    found = protected_symbols(output)
    if expectation == "absent" and found:
        raise RuntimeError("handle test seams present in production library "
                           "symbols:\n  " + "\n  ".join(sorted(found)))
    if expectation == "present" and found != PROTECTED:
        raise RuntimeError("handle test companion is missing protected "
                           "symbols:\n  "
                           + "\n  ".join(sorted(PROTECTED - found)))


def inspect(expectation, object_format, artifact_kind, artifact,
            which=shutil.which, runner=run):
    output = symbols(object_format, artifact_kind, artifact, which, runner)
    verify_output(expectation, output)


def self_test():
    all_symbols = "\n".join(f"000 T _{symbol}@12" for symbol in PROTECTED)
    if protected_symbols(all_symbols) != PROTECTED:
        raise AssertionError("protected export parser missed a test seam")
    if not contains_symbol("000 T _wyl_init@8\n", SENTINEL):
        raise AssertionError("production sentinel decoration was not parsed")
    verify_output("absent", "000 T wyl_init\n")
    verify_output("present", "000 T wyl_init\n" + all_symbols)
    allowed = "000 T wyl_handle_engine_session_locked_for_testing\n"
    if protected_symbols(allowed):
        raise AssertionError("protected export parser accepted a substring")
    audit_near_match = "000 T wyl_audit_conn_duckdb_config_fail_once_for_testing\n"
    if protected_symbols(audit_near_match):
        raise AssertionError("protected export parser accepted an audit near-match")
    pe_shared = command_candidates("pe", "shared", Path("library.dll"))
    if pe_shared[0][0:2] != ("llvm-readobj", "--coff-exports"):
        raise AssertionError("PE shared inspection must prefer export directory")
    pe_archive = command_candidates("pe", "archive", Path("library.lib"))
    if pe_archive[0][0] != "llvm-nm":
        raise AssertionError("PE archive inspection must prefer defined symbols")
    def fake_which(tool):
        return "/fake/" + tool

    for object_format in ("elf", "macho", "pe"):
        for artifact_kind in ("shared", "archive"):
            for expectation in ("absent", "present"):
                for bad_output in ("", "successful but unparsed output"):
                    calls = []

                    def bad_runner(command, result=bad_output):
                        calls.append(command)
                        return result

                    try:
                        inspect(expectation, object_format, artifact_kind,
                                Path("library.bin"), fake_which, bad_runner)
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError(
                            "empty or malformed inspector output did not fail "
                            "closed")
                    if len(calls) != 1:
                        raise AssertionError(
                            "invalid inspector output fell through")
    try:
        inspect("absent", "pe", "shared", Path("library.dll"),
                lambda unused: None, lambda command: "")
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
        inspect(expectation, object_format, artifact_kind, artifact)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

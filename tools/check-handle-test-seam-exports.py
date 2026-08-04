#!/usr/bin/env python3
"""Reject deterministic engine-session test seams in production artifacts."""

from pathlib import Path
import re
import shutil
import subprocess
import sys


TEST_SEAMS = {
    "wyl_handle_set_engine_session_checkpoint_for_test",
    "wyl_handle_set_engine_replacement_checkpoint_for_test",
    "wyl_handle_set_engine_operation_checkpoint_for_test",
    "wyl_handle_set_engine_snapshot_checkpoint_for_test",
    "wyl_handle_set_audit_replay_checkpoint_for_test",
    "wyl_handle_set_engine_partial_fault_once_for_test",
    "wyl_handle_set_engine_replacement_fault_once_for_test",
    "wyl_handle_engine_session_locked_for_test",
    "wyl_handle_engine_session_depth_for_test",
    "wyl_engine_verification_mutate_keyed_row_for_test",
    "wyl_handle_pending_delta_count_for_test",
    "wyl_handle_buffer_delta_for_test",
    "wyl_handle_flush_pending_deltas_for_test",
    "wyl_policy_store_read_snapshot_finish_fail_once_for_test",
    "wyl_handle_lock_engine_session",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-handle-test-seam-exports.py LIBRARY",
              file=sys.stderr)
        return 2
    artifact = Path(sys.argv[1])
    if not artifact.is_file():
        print(f"library artifact missing: {artifact}", file=sys.stderr)
        return 1
    tool = shutil.which("llvm-nm") or shutil.which("nm")
    if tool is None:
        print("no production-artifact symbol inspector found", file=sys.stderr)
        return 1
    result = subprocess.run([tool, "--defined-only", str(artifact)],
                            check=False, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr)
        return 1
    tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_@]*", result.stdout))
    found = sorted(TEST_SEAMS.intersection(token.split("@", 1)[0]
                                           for token in tokens))
    if found:
        print("test-only handle symbols in production artifact:", *found,
              sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

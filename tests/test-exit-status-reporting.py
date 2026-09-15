#!/usr/bin/env python3
"""Prove that a failing test reports its full site identity and code."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
  if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} REPORTING_EXECUTABLE", file=sys.stderr)
    return 2
  reports = []
  for args, name in (([], "check-alpha"), (["second"], "check-beta")):
    completed = subprocess.run([sys.argv[1], *args], capture_output=True,
        text=True, check=False)
    if completed.returncode != 1:
      print(f"expected fixed failure status 1, got {completed.returncode}",
          file=sys.stderr)
      return 1
    if "WYRELOG_TEST_FAILURE file=" not in completed.stderr \
        or f"function={name}" not in completed.stderr \
        or "code=1601" not in completed.stderr:
      print(f"missing failure identity in stderr: {completed.stderr!r}",
          file=sys.stderr)
      return 1
    if completed.stderr.count("code=1601") != 1:
      print(f"expected one authoritative full-code report: {completed.stderr!r}",
          file=sys.stderr)
      return 1
    reports.append(completed.stderr)
  if reports[0] == reports[1]:
    print("duplicate failure codes did not produce distinct source sites",
        file=sys.stderr)
    return 1
  print("test failure reporting preserves identity and full code")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

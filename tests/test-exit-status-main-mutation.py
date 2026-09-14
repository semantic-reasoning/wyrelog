#!/usr/bin/env python3
"""Require a normalized outer-main mutation to remain a process failure."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
  if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} MUTANT_EXECUTABLE", file=sys.stderr)
    return 2
  completed = subprocess.run([sys.argv[1]], check=False)
  if completed.returncode != 1:
    print("outer main returning 256 did not exit with status 1: "
        f"{completed.returncode}", file=sys.stderr)
    return 1
  print("outer main mutation preserves failure status")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

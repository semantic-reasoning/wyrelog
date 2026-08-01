#!/usr/bin/env python3
"""Exercise repeated and partially successful wyctl option parsing."""

import os
from pathlib import Path
import subprocess
import sys


def run_case(wyctl: Path, arguments: list[str], expected_exit: int,
             stdout_marker: str, stderr_marker: str) -> None:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["WYCTL_DISABLE_GSETTINGS"] = "1"
    completed = subprocess.run(
        [str(wyctl), *arguments],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    if completed.returncode != expected_exit:
        raise AssertionError(
            f"{arguments}: exit {completed.returncode}, expected "
            f"{expected_exit}\nstdout: {completed.stdout}\nstderr: "
            f"{completed.stderr}")
    if stdout_marker not in completed.stdout:
        raise AssertionError(f"{arguments}: missing stdout marker")
    if stderr_marker not in completed.stderr:
        raise AssertionError(f"{arguments}: missing stderr marker")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test-wyctl-option-ownership.py WYCTL", file=sys.stderr)
        return 2
    wyctl = Path(sys.argv[1])
    cases = (
        (["--daemon-url", "http://127.0.0.1:1", "--timeout-ms"], 2, "",
         "Missing argument for --timeout-ms"),
        (["service-principal", "create", "--subject", "svc:test",
          "--display-name", "Worker", "--tenant"], 2, "",
         "Missing argument for --tenant"),
        (["service-credential", "issue", "--subject", "svc:test", "--help"],
         0, "Usage:", ""),
        (["--daemon-url", "http://127.0.0.1:1", "status", "--daemon-url",
          "http://127.0.0.1:2", "--timeout-ms"], 2, "",
         "Missing argument for --timeout-ms"),
    )
    for _ in range(3):
        for arguments, expected_exit, stdout_marker, stderr_marker in cases:
            run_case(wyctl, arguments, expected_exit, stdout_marker,
                     stderr_marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

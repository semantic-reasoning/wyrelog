#!/usr/bin/env python3
"""Run a wyctl test executable with a suite-owned temporary root."""

import os
import shlex
import signal
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: run-wyctl-with-private-tmpdir.py PROGRAM [ARG ...]",
              file=sys.stderr)
        return 2

    child = None

    def stop_child(signum, _frame):
        if child is not None and child.poll() is None:
            try:
                child.send_signal(signum)
                child.wait()
            except OSError:
                pass
        raise SystemExit(128 + signum)

    for signal_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signum = getattr(signal, signal_name, None)
        if signum is not None:
            signal.signal(signum, stop_child)

    env = os.environ.copy()
    command = shlex.split(env.get("MESON_EXE_WRAPPER", ""))
    command.extend(sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="wyctl-suite-") as private_tmpdir:
        env["TMPDIR"] = private_tmpdir
        child = subprocess.Popen(command, env=env)
        returncode = child.wait()

    if returncode < 0:
        return 128 - returncode
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())

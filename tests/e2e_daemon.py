# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared shutdown of a disposable E2E daemon."""
import subprocess
import sys


def stop_daemon(process, timeout=30, *, primary_error=None):
    """Reap the daemon; forced shutdown fails an otherwise successful test.

    Finally callers pass their active exception as primary_error so that a
    timeout is reported to stderr without replacing the original failure.
    Restart/inspection callers omit it to prevent continuing after a kill.
    Signal and reap errors always propagate; exit-status acceptance is left
    to the caller, matching the migrated scripts' existing behavior.
    """
    if process is None:
        return
    if process.poll() is not None:
        return process.wait()
    process.terminate()
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        message = (f'daemon did not stop on SIGTERM within {timeout:g} '
                   'seconds; killed and reaped')
        if primary_error is not None:
            print(message, file=sys.stderr)
            return
        raise AssertionError(message) from error

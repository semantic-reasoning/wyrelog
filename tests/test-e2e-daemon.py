#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove E2E shutdown reaps stubborn daemons without hiding body failures."""
import contextlib
import io
import os
import selectors
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, call

from e2e_daemon import stop_daemon


class DaemonShutdownTests(unittest.TestCase):
    def process(self, *, exited=None, timeout=False, final_status=0):
        process = Mock()
        process.poll.return_value = exited
        process.wait.return_value = final_status
        if timeout:
            process.wait.side_effect = [
                subprocess.TimeoutExpired('test-daemon', 0.05), final_status]
        return process

    def test_missing_process(self):
        stop_daemon(None)

    def test_graceful_stop(self):
        process = self.process(final_status=-signal.SIGTERM)
        stop_daemon(process)
        self.assertEqual(process.mock_calls,
                         [call.poll(), call.terminate(), call.wait(timeout=30)])

    def test_already_exited_is_reaped_without_signaling(self):
        process = self.process(exited=1, final_status=1)
        stop_daemon(process)
        self.assertEqual(process.mock_calls, [call.poll(), call.wait()])

    def test_timeout_kills_and_reaps_before_failing(self):
        # Even a voluntary exit racing with kill cannot make a timeout pass.
        for status in (0, -9):
            with self.subTest(status=status):
                process = self.process(timeout=True, final_status=status)
                next_action = Mock()
                with self.assertRaisesRegex(
                        AssertionError, 'daemon did not stop on SIGTERM') as error:
                    stop_daemon(process, timeout=0.05)
                    next_action()
                self.assertEqual(process.mock_calls, [call.poll(),
                    call.terminate(), call.wait(timeout=0.05), call.kill(),
                    call.wait()])
                self.assertIsInstance(error.exception.__cause__,
                                      subprocess.TimeoutExpired)
                next_action.assert_not_called()

    def test_timeout_preserves_active_body_exception(self):
        process = self.process(timeout=True)
        original = ValueError('original test failure')
        diagnostic = io.StringIO()
        with contextlib.redirect_stderr(diagnostic):
            with self.assertRaises(ValueError) as error:
                try:
                    raise original
                finally:
                    stop_daemon(process, timeout=0.05,
                                primary_error=sys.exc_info()[1])
        self.assertIs(error.exception, original)
        self.assertIn('daemon did not stop on SIGTERM', diagnostic.getvalue())
        self.assertEqual(process.mock_calls, [call.poll(), call.terminate(),
            call.wait(timeout=0.05), call.kill(), call.wait()])

    def test_graceful_stop_preserves_body_exception(self):
        process = self.process()
        original = ValueError('original test failure')
        diagnostic = io.StringIO()
        with contextlib.redirect_stderr(diagnostic):
            with self.assertRaises(ValueError) as error:
                try:
                    raise original
                finally:
                    stop_daemon(process, primary_error=sys.exc_info()[1])
        self.assertIs(error.exception, original)
        self.assertEqual(diagnostic.getvalue(), '')
        process.kill.assert_not_called()

    def test_kill_failure_is_not_success(self):
        process = self.process(timeout=True)
        process.kill.side_effect = OSError('kill refused')
        with self.assertRaisesRegex(OSError, 'kill refused'):
            stop_daemon(process, timeout=0.05)
        self.assertEqual(process.wait.call_count, 1)

    def test_reap_failure_is_not_success(self):
        process = self.process()
        process.wait.side_effect = [subprocess.TimeoutExpired('test-daemon',
            0.05), OSError('reap refused')]
        with self.assertRaisesRegex(OSError, 'reap refused'):
            stop_daemon(process, timeout=0.05)
        process.kill.assert_called_once_with()

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX SIGTERM semantics')
    def test_real_sigterm_ignoring_child_is_killed_and_reaped(self):
        child = subprocess.Popen([sys.executable, '-u', '-c',
            'import signal\n'
            'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
            'print("ready", flush=True)\n'
            'while True: signal.pause()\n'], stdout=subprocess.PIPE,
            text=True, encoding='utf-8')
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5),
                                'child readiness timed out')
            self.assertEqual(child.stdout.readline(), 'ready\n')
            with self.assertRaisesRegex(
                    AssertionError, 'daemon did not stop on SIGTERM'):
                stop_daemon(child, timeout=0.05)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            # A second OS wait must find no child, rather than a zombie.
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
        finally:
            # Independent of the helper under test, including when it regresses.
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdout.close()


if __name__ == '__main__':
    unittest.main()

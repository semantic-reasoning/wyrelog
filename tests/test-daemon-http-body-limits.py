#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real-daemon tests: reject oversized requests before consuming their bodies."""
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time


def resident_kib(pid):
    if sys.platform.startswith("linux"):
        for line in pathlib.Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    if sys.platform == "darwin":
        return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)]))
    return None


def read_response(sock, version):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        assert chunk, f"connection closed before headers: {data!r}"
        data += chunk
    header, body = data.split(b"\r\n\r\n", 1)
    assert header.split()[0] == version.encode(), header
    fields = dict(line.split(b":", 1) for line in header.split(b"\r\n")[1:])
    length = int(fields.get(b"Content-Length", b"0"))
    while len(body) < length:
        chunk = sock.recv(4096)
        assert chunk, "incomplete error body"
        body += chunk
    return int(header.split()[1]), fields, body


def main():
    with tempfile.TemporaryDirectory(prefix="wyl-body-limit-") as root:
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        command = [sys.argv[1], "--template-dir", sys.argv[2],
                   "--policy-db", root + "/policy.sqlite", "--listen-port", str(port)]
        if sys.argv[3] == "1":
            command += ["--audit-db", root + "/audit.duckdb"]
        environment = dict(os.environ, G_DEBUG="fatal-warnings")
        with tempfile.TemporaryFile() as log:
            daemon = subprocess.Popen(command, stdout=log, stderr=log, env=environment)
            try:
                for _ in range(200):
                    assert daemon.poll() is None, "daemon exited during startup"
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError("daemon did not start")

                request_ids = set()

                def request(path, headers, body=b"", method="POST", oversized=True,
                            version="HTTP/1.1"):
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                        sock.sendall((f"{method} {path} {version}\r\nHost: localhost\r\n"
                                      "X-Wyrelog-Request-Id: attacker\r\nConnection: close\r\n"
                                      f"{headers}\r\n\r\n").encode() + body)
                        status, fields, payload = read_response(sock, version)
                        if oversized:
                            assert status == 413, (path, status, payload)
                            assert payload == b'{"error":"request_body_too_large"}'
                            assert fields[b"Connection"].strip() == b"close"
                            identity = fields[b"X-Wyrelog-Request-Id"].strip()
                            assert re.fullmatch(rb"[0-9A-Za-z]{27}", identity), identity
                            assert identity not in request_ids
                            request_ids.add(identity)
                        else:
                            assert status != 413, (path, status)
                        return status

                cases = [("/facts/schema/register", 1048576, "POST"),
                         ("/facts/t/g/s:append", 1048576, "POST"),
                         ("/facts/t/g/s:retract", 1048576, "POST"),
                         ("/facts/t/g/s:forget", 4096, "DELETE"),
                         ("/datalog/t/g", 16384, "POST"),
                         ("/datalog%2ft/g?cap=999999", 16384, "POST"),
                         ("/profile/events", 1024, "POST"),
                         ("/auth/service-token", 16384, "POST"),
                         ("/auth/mfa/enroll/start", 4096, "POST"),
                         ("/auth/mfa/enroll/confirm", 4096, "POST"),
                         ("/tenants/seal", 1024, "POST"),
                         ("/service-principals", 4096, "POST"),
                         ("/service-principals/p/disable", 1024, "POST"),
                         ("/service-credentials/id", 1024, "DELETE"),
                         ("/service-credentials/id/rotate", 4096, "POST"),
                         ("/service-credential-operations/recover", 4096, "POST"),
                         ("/unknown-route", 1048576, "POST")]
                for path, cap, method in cases:
                    # No body is sent: a post-assembly limit would time out here.
                    request(path, f"Content-Length: {cap + 1}", method=method)
                    request(path, f"Content-Length: {cap}", b"x" * cap,
                            method=method, oversized=False)
                request("/datalog/t/g", "Content-Length: 16385\r\nExpect: 100-continue")
                request("/profile/events", "Content-Length: 1025", version="HTTP/1.0")

                baseline = resident_kib(daemon.pid)
                for size in (4 << 20, 64 << 20, 512 << 20):
                    # Advertise a huge chunk, send only enough to exceed the cap,
                    # and await 413 without completing the chunk or the request.
                    request("/datalog/t/g", "Transfer-Encoding: chunked",
                            f"{size:x}\r\n".encode() + b"x" * 32768)
                    current = resident_kib(daemon.pid)
                    if baseline is not None:
                        assert current - baseline < 8 * 1024, (baseline, current, size)
                for _ in range(20):
                    request("/profile/events", "Content-Length: 1025")
                    assert request("/healthz", "Content-Length: 0", method="GET",
                                   oversized=False) == 200
                assert daemon.poll() is None
                print("body limits: declared/streaming, caps, request IDs, RSS, recovery passed")
            except BaseException:
                log.seek(0)
                print(log.read().decode(errors="replace"), file=sys.stderr)
                raise
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()


if __name__ == "__main__":
    main()

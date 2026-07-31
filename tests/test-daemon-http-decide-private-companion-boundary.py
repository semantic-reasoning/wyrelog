#!/usr/bin/env python3
"""Keep the daemon HTTP test-only coordinator companion narrowly bounded."""

from pathlib import Path
import re
import sys


EXPECTED_SOURCES = {
    "../wyrelog/auth/service-credential-operation-coordinator-journal-private.c",
    "../wyrelog/auth/service-credential-operation-coordinator-storage-private.c",
    "../wyrelog/auth/service-credential-operation-storage-private.c",
}
EXPECTED_TARGETS = {
    "test_daemon_http_decide",
    "test_daemon_http_decide_refresh",
    "test_daemon_http_decide_service",
    "test_daemon_http_decide_audit",
}


def fail(message: str) -> None:
    raise SystemExit(message)


if len(sys.argv) != 2:
    fail("usage: test-daemon-http-decide-private-companion-boundary.py MESON")

source = Path(sys.argv[1]).read_text(encoding="utf-8")

matches = re.findall(
    r"test_daemon_http_decide_private_companion\s*=\s*static_library\((.*?)\n"
    r"\s*\)",
    source,
    re.DOTALL,
)
if len(matches) != 1:
    fail("daemon HTTP private companion must be declared exactly once")

companion = matches[0]
actual_sources = set(re.findall(
    r"'(\.\./wyrelog/auth/[^']+\.c)'",
    companion,
))
if actual_sources != EXPECTED_SOURCES:
    fail(
        "daemon HTTP private companion source set mismatch: "
        f"expected {sorted(EXPECTED_SOURCES)}, got {sorted(actual_sources)}"
    )
for required in (
    "gnu_symbol_visibility : 'hidden'",
    "build_by_default : false",
    "install : false",
):
    if required not in companion:
        fail(f"daemon HTTP private companion missing: {required}")

guard = re.search(
    r"if host_machine\.system\(\) != 'windows'\s+"
    r"test_daemon_http_decide_private_companion\s*=\s*static_library\(",
    source,
)
if guard is None:
    fail("daemon HTTP private companion must have an explicit POSIX guard")

if source.count("test_daemon_http_decide_link_with = []") != 1:
    fail("daemon HTTP variants must have one common link list")
if source.count(
        "test_daemon_http_decide_link_with += [\n"
        "      test_daemon_http_decide_private_companion,\n"
        "    ]") != 1:
    fail("daemon HTTP private companion must enter the common link list once")
if "link_whole" in companion:
    fail("daemon HTTP private companion must not use link_whole")

actual_consumers = set(re.findall(
    r"(test_daemon_http_decide(?:_refresh|_service|_audit)?)\s*="
    r"\s*executable\(.*?\n\s*link_with\s*:\s*"
    r"test_daemon_http_decide_link_with,",
    source,
    re.DOTALL,
))
if actual_consumers != EXPECTED_TARGETS:
    fail(
        "daemon HTTP common link consumers mismatch: "
        f"expected {sorted(EXPECTED_TARGETS)}, got {sorted(actual_consumers)}"
    )

if re.search(
        r"test_daemon_http_decide(?:_refresh|_service|_audit)?\s*="
        r"\s*executable\(.*?\n\s*link_whole\s*:",
        source,
        re.DOTALL,
):
    fail("daemon HTTP variants must not use link_whole")

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


if len(sys.argv) != 4:
    fail(
        "usage: test-daemon-http-decide-private-companion-boundary.py "
        "MESON CI_PR CI_MAIN"
    )

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
    r"if \(host_machine\.system\(\) != 'windows' and\s+"
    r"get_option\('enable_fact_store'\)\.allowed\(\)\)\s+"
    r"test_daemon_http_decide_private_companion\s*=\s*static_library\(",
    source,
)
if guard is None:
    fail(
        "daemon HTTP private companion must have explicit POSIX and "
        "fact-store guards"
    )

link_list = source.find("test_daemon_http_decide_link_with = []")
guard_start = source.find(
    "if (host_machine.system() != 'windows' and",
    link_list,
)
first_consumer = source.find(
    "test_daemon_http_decide = executable(",
    guard_start,
)
if link_list == -1 or source.count(
        "test_daemon_http_decide_link_with = []") != 1:
    fail("daemon HTTP variants must have one common link list")
if not link_list < guard_start < first_consumer:
    fail("daemon HTTP common link list must exist outside the feature guard")
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

symbol_test_guard = re.search(
    r"if host_machine\.system\(\) != 'windows'\s+"
    r"check_daemon_http_decide_private_symbols\s*=\s*find_program\(.*?"
    r"test\('daemon-http-decide-private-symbols-self-test'.*?"
    r"if get_option\('enable_fact_store'\)\.allowed\(\)\s+.*?"
    r"test\('daemon-http-decide-private-symbols',",
    source,
    re.DOTALL,
)
if symbol_test_guard is None:
    fail(
        "artifact symbol test must require POSIX and fact-store while its "
        "self-test remains POSIX-only"
    )


def job_body(workflow: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        fail(f"workflow is missing the {name} job")
    return match.group(1)


def step_run(job: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n.*?^        run: \|\n"
        r"(.*?)(?=^      - name: |\Z)",
        job,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        fail(f"daemon HTTP shared fact job is missing step: {name}")
    return "\n".join(
        line.removeprefix("          ") for line in
        match.group(1).rstrip().splitlines()
    )


expected_compile = """\
meson compile -C build-daemon-http-shared \\
  test-daemon-http-decide \\
  test-daemon-http-decide-refresh \\
  test-daemon-http-decide-service \\
  test-daemon-http-decide-audit"""
expected_test = """\
meson test -C build-daemon-http-shared --no-rebuild \\
  daemon-http-decide \\
  daemon-http-decide-refresh \\
  daemon-http-decide-service \\
  daemon-http-decide-audit \\
  daemon-http-decide-private-symbols \\
  --print-errorlogs"""

ci_jobs = []
for workflow_path in map(Path, sys.argv[2:]):
    workflow = workflow_path.read_text(encoding="utf-8")
    if workflow.count("\n  daemon-http-shared-fact:\n") != 1:
        fail(f"{workflow_path} must define one daemon HTTP shared fact job")
    job = job_body(workflow, "daemon-http-shared-fact")
    ci_jobs.append(job)
    for required in (
        "os: [ubuntu-latest, macos-latest]",
        "timeout-minutes: 30",
        "meson setup build-daemon-http-shared",
        "-Ddefault_library=shared",
        "-Denable_client=enabled",
        "-Denable_fact_store=enabled",
        "-Denable_audit=enabled",
        "-Dduckdb_source=prebuilt",
        "meson compile -C build-daemon-http-shared",
        "meson test -C build-daemon-http-shared --no-rebuild",
        "build-daemon-http-shared/meson-logs/",
    ):
        if required not in job:
            fail(f"{workflow_path} daemon HTTP job missing: {required}")
    if "windows" in job.lower():
        fail(f"{workflow_path} daemon HTTP job must stay POSIX-only")
    if step_run(job, "Compile daemon HTTP variants") != expected_compile:
        fail(f"{workflow_path} must compile exactly four daemon HTTP variants")
    if step_run(job, "Test daemon HTTP variants") != expected_test:
        fail(
            f"{workflow_path} must test exactly four daemon HTTP variants "
            "and their artifact symbols"
        )
    for target in (
        "daemon-http-decide",
        "daemon-http-decide-refresh",
        "daemon-http-decide-service",
        "daemon-http-decide-audit",
    ):
        occurrences = re.findall(
            rf"(?<![A-Za-z0-9_-])(?:test-)?{re.escape(target)}"
            r"(?![A-Za-z0-9_-])",
            job,
        )
        if len(occurrences) != 2:
            fail(
                f"{workflow_path} must name {target} exactly in the compile "
                "and test steps"
            )

if ci_jobs[0] != ci_jobs[1]:
    fail("PR and main daemon HTTP shared fact jobs must remain identical")

#!/usr/bin/env python3
"""Keep the daemon HTTP test-only seed helper DSO narrowly bounded."""

from pathlib import Path
import re
import sys


EXPECTED_PRODUCTION_SOURCES = {
    "../wyrelog/auth/service-credential-operation-coordinator-journal-private.c",
    "../wyrelog/auth/service-credential-operation-coordinator-storage-private.c",
    "../wyrelog/auth/service-credential-operation-storage-private.c",
}
EXPECTED_WRAPPER = "test-daemon-http-decide-seed-helper.c"
SEED_SYMBOL = "wyl_test_daemon_http_seed_prepared_operation"
EXPECTED_TARGETS = {
    "test_daemon_http_decide",
    "test_daemon_http_decide_refresh",
    "test_daemon_http_decide_service",
    "test_daemon_http_decide_audit",
}


def fail(message: str) -> None:
    raise SystemExit(message)


if len(sys.argv) != 7:
    fail(
        "usage: test-daemon-http-decide-private-companion-boundary.py "
        "MESON WRAPPER_C WRAPPER_H TEST_C CI_PR CI_MAIN"
    )

source = Path(sys.argv[1]).read_text(encoding="utf-8")
wrapper_source = Path(sys.argv[2]).read_text(encoding="utf-8")
wrapper_header = Path(sys.argv[3]).read_text(encoding="utf-8")
test_source = Path(sys.argv[4]).read_text(encoding="utf-8")

matches = re.findall(
    r"test_daemon_http_decide_seed_helper\s*=\s*shared_library\((.*?)\n"
    r"\s*\)",
    source,
    re.DOTALL,
)
if len(matches) != 1:
    fail("daemon HTTP seed helper must be one shared_library")

helper = matches[0]
actual_production_sources = set(re.findall(
    r"'(\.\./wyrelog/auth/[^']+\.c)'",
    helper,
))
if actual_production_sources != EXPECTED_PRODUCTION_SOURCES:
    fail(
        "daemon HTTP seed helper production source set mismatch: "
        f"expected {sorted(EXPECTED_PRODUCTION_SOURCES)}, "
        f"got {sorted(actual_production_sources)}"
    )
local_sources = set(re.findall(r"'([^'/]+\.c)'", helper))
if local_sources != {EXPECTED_WRAPPER}:
    fail(f"daemon HTTP seed helper wrapper mismatch: {sorted(local_sources)}")
for required in (
    "gnu_symbol_visibility : 'hidden'",
    "build_by_default : false",
    "install : false",
    "'-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS'",
):
    if required not in helper:
        fail(f"daemon HTTP seed helper missing: {required}")

guard = re.search(
    r"if \(host_machine\.system\(\) != 'windows' and\s+"
    r"get_option\('enable_fact_store'\)\.allowed\(\) and\s+"
    r"test_daemon_http_decide_uses_shared_wyrelog\)\s+"
    r"(?:.*?\s+)?test_daemon_http_decide_seed_helper\s*=\s*shared_library\(",
    source,
    re.DOTALL,
)
if guard is None:
    fail(
        "daemon HTTP seed helper must require POSIX, fact-store, and a shared "
        "libwyrelog selection"
    )
selection_contract = re.search(
    r"test_daemon_http_decide_uses_shared_wyrelog\s*=\s*\(\s*"
    r"get_option\('default_library'\) == 'shared'\s*\)\s*"
    r"if get_option\('default_library'\) == 'both'\s*"
    r"(?:#[^\n]*\n\s*)*"
    r"test_daemon_http_decide_uses_shared_wyrelog\s*=\s*true\s*"
    r"if meson\.version\(\)\.version_compare\('>=1\.6\.0'\)\s*"
    r"test_daemon_http_decide_uses_shared_wyrelog\s*=\s*\(\s*"
    r"get_option\('default_both_libraries'\) != 'static'\s*\)\s*"
    r"endif\s*endif",
    source,
)
if selection_contract is None:
    fail(
        "daemon HTTP shared selection must treat Meson 1.1-1.5 both as "
        "shared and Meson 1.6+ both auto/shared as shared"
    )
if source.count("get_option('default_both_libraries')") != 1:
    fail(
        "default_both_libraries must be evaluated exactly once inside its "
        "Meson 1.6+ guard"
    )
if "libwyrelog.get_shared_lib()" not in source:
    fail("daemon HTTP both selection must link libwyrelog's shared target")

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
        "      test_daemon_http_decide_seed_helper,\n"
        "    ]") != 1:
    fail("daemon HTTP seed helper must enter the common link list once")
if "link_whole" in helper:
    fail("daemon HTTP seed helper must not use link_whole")

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

audit_selection_contract = re.search(
    r"test_daemon_http_decide_audit_enabled\s*=\s*"
    r"get_option\('enable_audit'\)\.allowed\(\)\s*"
    r"test_daemon_http_decide_audit_mode\s*=\s*\(\s*"
    r"test_daemon_http_decide_audit_enabled\s*\?\s*'enabled'\s*:\s*"
    r"'disabled'\s*\)",
    source,
)
if audit_selection_contract is None:
    fail("daemon HTTP audit targets and checker must share one feature state")
if source.count("if test_daemon_http_decide_audit_enabled") != 2:
    fail("daemon HTTP audit feature state must guard dependencies and target")
audit_target_contract = re.search(
    r"if test_daemon_http_decide_audit_enabled\s+"
    r"test_daemon_http_decide_audit\s*=\s*executable\("
    r"'test-daemon-http-decide-audit',.*?\n\s*\)\s*"
    r"test_daemon_http_decide_targets\s*\+=\s*"
    r"\[test_daemon_http_decide_audit\]\s*"
    r"test\('daemon-http-decide-audit',\s*"
    r"test_daemon_http_decide_audit,\s*timeout\s*:\s*240,\s*\)\s*"
    r"endif",
    source,
    re.DOTALL,
)
if audit_target_contract is None:
    fail(
        "daemon HTTP audit feature state must guard target construction, "
        "target-list append, and test registration"
    )

symbol_test_guard = re.search(
    r"if host_machine\.system\(\) != 'windows'\s+"
    r"check_daemon_http_decide_private_symbols\s*=\s*find_program\(.*?"
    r"test\('daemon-http-decide-private-symbols-self-test'.*?"
    r"if \(get_option\('enable_fact_store'\)\.allowed\(\) and\s+"
    r"test_daemon_http_decide_uses_shared_wyrelog\)\s+.*?"
    r"test\('daemon-http-decide-private-symbols',",
    source,
    re.DOTALL,
)
if symbol_test_guard is None:
    fail(
        "artifact symbol test must require POSIX and fact-store while its "
        "self-test remains POSIX-only"
    )
if re.search(
        r"test\('daemon-http-decide-private-symbols-self-test',\s*"
        r"check_daemon_http_decide_private_symbols,\s*"
        r"args\s*:\s*\['--self-test'\],\s*\)",
        source,
) is None:
    fail("artifact checker self-test must use the sole --self-test form")
if re.search(
        r"test\('daemon-http-decide-private-symbols',\s*"
        r"check_daemon_http_decide_private_symbols,\s*args\s*:\s*\[\s*"
        r"'--audit-mode',\s*test_daemon_http_decide_audit_mode,\s*"
        r"meson\.project_build_root\(\)\s*/\s*'meson-info'\s*/\s*"
        r"'intro-installed\.json'",
        source,
) is None:
    fail("artifact checker must receive the shared explicit audit mode first")
target_path_contract = re.search(
    r"test_daemon_http_decide_target_paths\s*=\s*\[\]\s*"
    r"foreach target\s*:\s*test_daemon_http_decide_targets\s*"
    r"test_daemon_http_decide_target_paths\s*\+=\s*"
    r"\[target\.full_path\(\)\]\s*endforeach\s*"
    r"test\('daemon-http-decide-private-symbols',\s*"
    r"check_daemon_http_decide_private_symbols,.*?"
    r"\]\s*\+\s*test_daemon_http_decide_target_paths,\s*"
    r"depends\s*:\s*\[\s*test_daemon_http_decide_seed_helper,\s*"
    r"libwyrelog,\s*\]\s*\+\s*test_daemon_http_decide_targets,",
    source,
    re.DOTALL,
)
if target_path_contract is None:
    fail(
        "artifact checker must project and depend on the generic constructed "
        "daemon HTTP target list"
    )
if "test_daemon_http_decide_audit.full_path()" in source:
    fail("artifact checker must not reference an audit target directly")

if wrapper_source.count("G_MODULE_EXPORT") != 1:
    fail("seed helper wrapper must mark exactly one definition default-visible")
if wrapper_header.count("G_MODULE_EXPORT") != 1:
    fail("seed helper header must declare exactly one default-visible API")
if wrapper_source.count(SEED_SYMBOL) != 1 or wrapper_header.count(
        SEED_SYMBOL) != 1:
    fail("seed helper must define and declare exactly one seed API")
for forbidden in (
    "WylServiceCredentialOperationStorage *",
    "WylServiceCredentialOperationRootAnchor *",
    "WylServiceCredentialOperationCoordinatorLock *",
    "WylServiceCredentialOperationRecord *",
):
    if forbidden in wrapper_header:
        fail(f"seed helper header leaks a private object: {forbidden}")
for cleanup in (
    "wyl_service_credential_operation_coordinator_lock_release",
    "wyl_service_credential_operation_record_clear",
    "wyl_service_credential_operation_root_anchor_clear",
    "wyl_service_credential_operation_storage_clear",
    "wyl_service_credential_operation_coordinator_request_clear",
):
    if cleanup not in wrapper_source:
        fail(f"seed helper cleanup closure missing: {cleanup}")
if test_source.count(SEED_SYMBOL) != 1:
    fail("daemon HTTP test must call only the scalar seed helper API")
if re.search(
        r"\bwyl_service_credential_operation_coordinator_"
        r"begin_or_replay_locked\b",
        test_source,
):
    fail("daemon HTTP executable must not call the hidden begin symbol")
if source.count("-DWYL_TEST_DAEMON_HTTP_SEED_HELPER_DSO") != 1:
    fail("daemon HTTP helper DSO selector must be defined exactly once")


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


def step_body(job: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n"
        r"(.*?)(?=^      - name: |\Z)",
        job,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        fail(f"daemon HTTP shared fact job is missing step: {name}")
    return "\n".join(
        line.removeprefix("        ") for line in
        match.group(1).rstrip().splitlines()
    )


def run_step_body(command: str) -> str:
    return "run: |\n" + "\n".join(
        f"  {line}" for line in command.splitlines()
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
expected_audit_disabled_configure = """\
meson setup build-daemon-http-shared-audit-disabled \\
  -Ddefault_library=shared \\
  -Denable_tpm=disabled \\
  -Denable_client=enabled \\
  -Denable_fact_store=enabled \\
  -Denable_audit=disabled \\
  -Dduckdb_source=prebuilt"""
expected_audit_disabled_compile = """\
meson compile -C build-daemon-http-shared-audit-disabled \\
  test-daemon-http-decide \\
  test-daemon-http-decide-refresh \\
  test-daemon-http-decide-service"""
expected_audit_disabled_test = """\
meson test -C build-daemon-http-shared-audit-disabled --no-rebuild \\
  daemon-http-decide-private-symbols \\
  --print-errorlogs"""
expected_audit_disabled_steps = [
    "Check out source",
    "Install build dependencies",
    "Restore meson packagecache",
    "Configure shared fact-store daemon HTTP tests without audit",
    "Compile daemon HTTP variants without audit",
    "Test daemon HTTP private symbols without audit",
    "Upload audit-disabled daemon HTTP meson logs on failure",
]
expected_audit_disabled_checkout = "uses: actions/checkout@v5"
expected_audit_disabled_cache = """\
uses: actions/cache/restore@v5
with:
  path: subprojects/packagecache
  key: Linux-packagecache-${{ hashFiles('subprojects/*.wrap') }}
  restore-keys: |
    Linux-packagecache-"""
expected_audit_disabled_upload = """\
if: failure()
uses: actions/upload-artifact@v6
with:
  name: daemon-http-shared-fact-audit-disabled-logs-ubuntu
  path: build-daemon-http-shared-audit-disabled/meson-logs/
  if-no-files-found: ignore"""

ci_audit_enabled_jobs = []
ci_audit_disabled_jobs = []
for workflow_path in map(Path, sys.argv[5:]):
    workflow = workflow_path.read_text(encoding="utf-8")
    if workflow.count("\n  daemon-http-shared-fact:\n") != 1:
        fail(f"{workflow_path} must define one daemon HTTP shared fact job")
    job = job_body(workflow, "daemon-http-shared-fact")
    ci_audit_enabled_jobs.append(job)
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

    audit_disabled_job_name = "daemon-http-shared-fact-audit-disabled"
    if workflow.count(f"\n  {audit_disabled_job_name}:\n") != 1:
        fail(
            f"{workflow_path} must define one audit-disabled daemon HTTP job"
        )
    audit_disabled_job = job_body(workflow, audit_disabled_job_name)
    ci_audit_disabled_jobs.append(audit_disabled_job)
    actual_steps = re.findall(
        r"^      - name: (.+)$",
        audit_disabled_job,
        re.MULTILINE,
    )
    if actual_steps != expected_audit_disabled_steps:
        fail(
            f"{workflow_path} audit-disabled job step sequence mismatch: "
            f"{actual_steps}"
        )
    for required in (
        "name: daemon-http-shared-fact-audit-disabled-ubuntu",
        "runs-on: ubuntu-latest",
        "timeout-minutes: 30",
    ):
        if audit_disabled_job.count(required) != 1:
            fail(
                f"{workflow_path} audit-disabled job must contain exactly "
                f"one: {required}"
            )
    for forbidden in (
        "matrix:",
        "macos",
        "windows",
        "-Denable_audit=enabled",
        "test-daemon-http-decide-audit",
        "daemon-http-decide-audit \\",
    ):
        if forbidden.lower() in audit_disabled_job.lower():
            fail(
                f"{workflow_path} audit-disabled job contains forbidden "
                f"content: {forbidden}"
            )
    if step_body(
        audit_disabled_job,
        "Check out source",
    ) != expected_audit_disabled_checkout:
        fail(f"{workflow_path} audit-disabled checkout step changed")
    if step_body(
        audit_disabled_job,
        "Restore meson packagecache",
    ) != expected_audit_disabled_cache:
        fail(f"{workflow_path} audit-disabled cache step changed")
    if step_body(
        audit_disabled_job,
        "Upload audit-disabled daemon HTTP meson logs on failure",
    ) != expected_audit_disabled_upload:
        fail(f"{workflow_path} audit-disabled log upload step changed")
    install_step = """\
sudo apt-get update
sudo apt-get install -y --no-install-recommends \\
  meson ninja-build pkg-config \\
  libglib2.0-dev libsqlite3-dev libsoup-3.0-dev libsodium-dev"""
    if step_body(
        audit_disabled_job,
        "Install build dependencies",
    ) != run_step_body(install_step):
        fail(f"{workflow_path} audit-disabled dependencies changed")
    if step_body(
        audit_disabled_job,
        "Configure shared fact-store daemon HTTP tests without audit",
    ) != run_step_body(expected_audit_disabled_configure):
        fail(f"{workflow_path} audit-disabled configure command changed")
    if step_body(
        audit_disabled_job,
        "Compile daemon HTTP variants without audit",
    ) != run_step_body(expected_audit_disabled_compile):
        fail(f"{workflow_path} must compile exactly three non-audit variants")
    if step_body(
        audit_disabled_job,
        "Test daemon HTTP private symbols without audit",
    ) != run_step_body(expected_audit_disabled_test):
        fail(f"{workflow_path} must run only the private-symbol checker")
    if audit_disabled_job.count("-Denable_audit=disabled") != 1:
        fail(f"{workflow_path} must explicitly disable audit exactly once")

if ci_audit_enabled_jobs[0] != ci_audit_enabled_jobs[1]:
    fail("PR and main daemon HTTP shared fact jobs must remain identical")
if ci_audit_disabled_jobs[0] != ci_audit_disabled_jobs[1]:
    fail(
        "PR and main audit-disabled daemon HTTP jobs must remain identical"
    )

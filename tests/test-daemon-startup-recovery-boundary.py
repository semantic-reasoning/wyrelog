#!/usr/bin/env python3
"""Structural gate for the private, pre-exposure startup recovery consumer."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
runtime = (root / "wyrelog/daemon/runtime.c").read_text()
helper = (root / "wyrelog/daemon/startup-recovery-private.c").read_text()
http = (root / "wyrelog/daemon/http.c").read_text()
core_meson = (root / "wyrelog/meson.build").read_text()
test_meson = (root / "tests/meson.build").read_text()


def body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"missing function {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated function {name}")


open_runtime = body(runtime, "open_runtime_handle")
open_readiness = body(runtime, "open_readiness_handle")
run_runtime = body(runtime, "wyl_daemon_run_runtime")
startup = body(helper, "wyl_daemon_recover_service_exchange_on_startup")

consumer = "wyl_daemon_recover_service_exchange_on_startup"
recovery = "wyl_service_exchange_recover_committed"

assert runtime.count(consumer + " (") == 1
assert recovery not in runtime
assert consumer in open_runtime
assert consumer not in open_readiness
assert open_runtime.index("wyl_handle_open_with_options") < open_runtime.index(consumer)
assert open_runtime.index(consumer) < open_runtime.index("wyl_handle_set_mfa_validator")
assert open_runtime.index(consumer) < open_runtime.index("g_clear_object (out_handle)")
assert run_runtime.index("open_runtime_handle") < run_runtime.index(
    "wyl_daemon_start_delta_callbacks"
)
assert run_runtime.index("wyl_daemon_start_delta_callbacks") < run_runtime.index(
    "wyl_daemon_emit_start_event"
)
assert run_runtime.index("wyl_daemon_emit_start_event") < run_runtime.index(
    "wyl_daemon_start_http_server_with_runtime"
)
assert helper.count(recovery + " (") == 1
assert "wyl_audit_conn_service_exchange_get_sink_identity" in startup
assert startup.index("wyl_audit_conn_service_exchange_get_sink_identity") < startup.index(
    recovery
)
assert recovery not in http

core_companion = core_meson.split(
    "service_exchange_private_lib = static_library(", 1
)[1].split("service_exchange_private_dep = declare_dependency(", 1)[0]
startup_companion = core_meson.split(
    "service_exchange_startup_private_lib = static_library(", 1
)[1].split("service_exchange_startup_private_dep = declare_dependency(", 1)[0]
daemon_sources = core_meson.split("wyrelogd_sources = files(", 1)[1].split(
    "wyrelogd_exe = executable(", 1
)[0]
assert core_companion.count("auth/service-exchange-audit-private.c") == 1
assert core_companion.count("auth/service-exchange-projector-private.c") == 1
assert "daemon/startup-recovery-private.c" not in core_companion
assert startup_companion.count("daemon/startup-recovery-private.c") == 1
assert "service_exchange_private_dep" in startup_companion
assert "install : false" in core_companion
assert "install : false" in startup_companion
for private_source in (
    "auth/service-exchange-audit-private.c",
    "auth/service-exchange-projector-private.c",
    "daemon/startup-recovery-private.c",
):
    assert private_source not in daemon_sources
assert "wyrelogd_deps += service_exchange_startup_private_dep" in core_meson
assert "../wyrelog/auth/service-exchange-projector-private.c" not in test_meson
assert "../wyrelog/daemon/startup-recovery-private.c" not in test_meson
assert test_meson.count("../wyrelog/auth/service-exchange-audit-private.c") == 1
assert "service_exchange_private_dep" in test_meson
assert "service_exchange_startup_private_dep" in test_meson

# The full-TU semantic boundary remains unchanged; only its target-local
# runner budget accounts for the measured Windows baseline.
session_boundary_target = test_meson.split(
    "test('check-service-session-private-boundary',", 1
)[1].split("check_service_session_private_boundary_self_test", 1)[0]
session_boundary_self_test = test_meson.split(
    "test('check-service-session-private-boundary-self-test',", 1
)[1].split("check_service_session_private_exports", 1)[0]
assert session_boundary_target.count("timeout : 1500") == 1
assert "timeout : 720" not in session_boundary_target
assert "timeout : 900" not in session_boundary_target
assert session_boundary_target.count("is_parallel : false") == 1
assert session_boundary_self_test.count("timeout : 120") == 1
assert session_boundary_self_test.count("is_parallel : false") == 1
assert "timeout_multiplier" not in test_meson

for public_header in (root / "wyrelog").glob("*.h"):
    assert consumer not in public_header.read_text()
    assert recovery not in public_header.read_text()

# The operator-visible failure is fixed and must not interpolate identities,
# paths, records, payloads, or credentials.
assert 'g_printerr ("wyrelogd: service_exchange_recovery: failed\\n")' in open_runtime
assert "%" not in re.search(
    r'g_printerr \("wyrelogd: service_exchange_recovery: failed\\n"\)',
    open_runtime,
).group(0)

print("daemon startup recovery boundary: OK")

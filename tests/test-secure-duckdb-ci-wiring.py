#!/usr/bin/env python3
"""Guard the hosted-runner build boundary for source-pinned DuckDB."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
step_name = "      - name: Build secure DuckDB backend from pinned source"
provision_secure_name = "      - name: Provision secure DuckDB compile swap"
remove_secure_name = "      - name: Remove secure DuckDB compile swap"
provision_seam_name = "      - name: Provision bounded Linux compile swap"
remove_seam_name = "      - name: Remove bounded Linux compile swap"


def logical_commands(step):
    run_start = step.index("        run: |\n") + len("        run: |\n")
    commands = []
    current = ""
    for line in step[run_start:].splitlines():
        stripped = line.strip()
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
        else:
            commands.append(current)
            current = ""
    if current:
        commands.append(current)
    return commands


def job(workflow, name, next_name):
    start = workflow.index(f"  {name}:\n")
    end = workflow.index(f"\n  {next_name}:\n", start)
    return workflow[start:end]


def named_step(job_text, name):
    start = job_text.index(name)
    end = job_text.find("\n      - name:", start + len(name))
    if end == -1:
        end = len(job_text)
    return job_text[start:end]


for workflow_name in ("ci-pr.yml", "ci-main.yml"):
    workflow = (
        root / ".github" / "workflows" / workflow_name
    ).read_text(encoding="utf-8")
    build_posix = job(workflow, "build-posix", "duckdb-checkpoint-seam")
    checkpoint_seam = job(workflow, "duckdb-checkpoint-seam", "build-windows")
    windows_build = workflow[workflow.index("  build-windows:\n"):]
    if build_posix.count("    timeout-minutes: 45\n") != 1:
        raise SystemExit(f"{workflow_name} POSIX build must stay time bounded")
    provision_secure = named_step(build_posix, provision_secure_name)
    step = named_step(build_posix, step_name)
    remove_secure = named_step(build_posix, remove_secure_name)
    commands = logical_commands(step)
    setup_command = (
        "CC=cc CXX=c++ meson setup build-secure-duckdb "
        "-Denable_fact_store=enabled "
        "-Dduckdb_source=subproject "
        "-Denable_secure_duckdb_bridge=enabled"
    )
    inherited_setup_command = (
        "meson setup build-secure-duckdb "
        "-Denable_fact_store=enabled "
        "-Dduckdb_source=subproject "
        "-Denable_secure_duckdb_bridge=enabled"
    )
    compile_command = (
        '/usr/bin/time "${time_args[@]}" '
        "meson compile -C build-secure-duckdb -j 1 "
        "test-fact-artifact-inventory "
        "test-fact-artifact-inventory-consumers "
        "test-fact-artifact-namespace "
        "test-fact-artifact-transition-driver "
        "test-fact-artifact-transition-posix "
        "test-secure-duckdb-bridge "
        "test-secure-duckdb-filesystem "
        "test-secure-duckdb-recording-filesystem"
    )
    test_command = (
        "meson test -C build-secure-duckdb --no-rebuild "
        "fact-artifact-inventory-contract "
        "fact-artifact-inventory-consumer-contract "
        "fact-artifact-namespace-inventory "
        "fact-artifact-inventory-consumer-wiring "
        "fact-artifact-inventory-consumer-wiring-self "
        "fact-artifact-transition-driver "
        "fact-artifact-transition-driver-wiring "
        "fact-artifact-transition-driver-wiring-self "
        "fact-artifact-transition-posix "
        "secure-duckdb-bridge secure-duckdb-filesystem "
        "secure-duckdb-recording-filesystem --print-errorlogs"
    )
    if commands.count(setup_command) != 1:
        raise SystemExit(
            f"{workflow_name} Linux secure setup must use native compilers"
        )
    setup_index = commands.index(setup_command)
    if commands[setup_index - 1:setup_index + 4] != [
        'if [ "$RUNNER_OS" = Linux ]; then',
        setup_command,
        "else",
        inherited_setup_command,
        "fi",
    ]:
        raise SystemExit(
            f"{workflow_name} native compiler override escaped Linux"
        )
    if commands.count(compile_command) != 1:
        raise SystemExit(
            f"{workflow_name} must compile exactly the bounded secure targets"
        )
    if (
        'time_args=(-v)' not in commands
        or 'time_args=(-l)' not in commands
    ):
        raise SystemExit(
            f"{workflow_name} secure compile resource telemetry drifted"
        )
    if commands.count(test_command) != 1:
        raise SystemExit(
            f"{workflow_name} must test exactly the built secure targets"
        )
    if commands.index(compile_command) > commands.index(test_command):
        raise SystemExit(
            f"{workflow_name} tests run before the bounded explicit compile"
        )
    if not (
        build_posix.index(provision_secure_name)
        < build_posix.index(step_name)
        < build_posix.index(remove_secure_name)
    ):
        raise SystemExit(
            f"{workflow_name} secure swap lifecycle ordering drifted"
        )
    if (
        "        if: runner.os == 'Linux'\n" not in provision_secure
        or logical_commands(provision_secure)
        != ["bash .github/scripts/duckdb-compile-swap.sh provision secure"]
    ):
        raise SystemExit(
            f"{workflow_name} secure swap provisioning is not Linux-only"
        )
    if (
        "        if: ${{ runner.environment == 'github-hosted' && "
        "(always() && runner.os == 'Linux') }}\n" not in remove_secure
        or logical_commands(remove_secure)
        != ["bash .github/scripts/duckdb-compile-swap.sh cleanup secure"]
    ):
        raise SystemExit(
            f"{workflow_name} secure swap cleanup lost always semantics"
        )
    if any(token in step for token in ("continue-on-error:", "|| true", "retry")):
        raise SystemExit(
            f"{workflow_name} secure source failure propagation was weakened"
        )

    windows_test_step = named_step(
        windows_build, "      - name: Build and test (clang-cl)"
    )
    required_windows_tests = (
        "secure-duckdb-bridge",
        "secure-duckdb-recording-filesystem",
        "fact-artifact-namespace-windows",
        "fact-provisioning-construct",
        "duckdb-after-walstart-no-wal",
        "duckdb-after-walstart-rendezvous",
        "duckdb-fixed-wal-successful-checkpoint",
        "duckdb-fixed-wal-pre-move-abort-reopen",
        "duckdb-fixed-wal-interrupted-recovery",
    )
    for token in required_windows_tests:
        if token not in windows_test_step:
            raise SystemExit(
                f"{workflow_name} native Windows secure gate lost {token}"
            )
    if (
        "if meson setup build-secure-duckdb-prebuilt" not in step
        or "-Dduckdb_source=prebuilt" not in step
    ):
        raise SystemExit(
            f"{workflow_name} secure prebuilt rejection was removed"
        )
    log_step = named_step(build_posix, "      - name: Upload meson logs on failure")
    if (
        "        if: ${{ runner.environment == 'github-hosted' && "
        "(failure()) }}\n" not in log_step
        or "          path: |\n" not in log_step
        or "            builddir/meson-logs/\n" not in log_step
        or "            build-secure-duckdb/meson-logs/\n" not in log_step
    ):
        raise SystemExit(
            f"{workflow_name} does not retain secure Meson failure logs"
        )
    provision_seam = named_step(checkpoint_seam, provision_seam_name)
    remove_seam = named_step(checkpoint_seam, remove_seam_name)
    if logical_commands(provision_seam) != [
        "bash .github/scripts/duckdb-compile-swap.sh provision seam"
    ]:
        raise SystemExit(
            f"{workflow_name} checkpoint seam does not reuse swap provisioning"
        )
    if (
        "        if: ${{ runner.environment == 'github-hosted' && "
        "(always() && runner.os == 'Linux') }}\n" not in remove_seam
        or logical_commands(remove_seam)
        != ["bash .github/scripts/duckdb-compile-swap.sh cleanup seam"]
    ):
        raise SystemExit(
            f"{workflow_name} checkpoint seam does not reuse swap cleanup"
        )

runtime_registration = """if host_machine.system() == 'linux'
  test('duckdb-compile-swap', python3,
    args : [files('test-duckdb-compile-swap.py'),
      meson.project_source_root()])
endif
"""
if meson.count(runtime_registration) != 1:
    raise SystemExit("DuckDB swap lifecycle runtime must stay Linux-only")

print("Secure DuckDB hosted-runner CI boundary: OK")

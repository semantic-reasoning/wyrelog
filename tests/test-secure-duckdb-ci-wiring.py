#!/usr/bin/env python3
"""Guard the hosted-runner build boundary for source-pinned DuckDB."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
step_name = "      - name: Build secure DuckDB backend from pinned source"


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


for workflow_name in ("ci-pr.yml", "ci-main.yml"):
    workflow = (
        root / ".github" / "workflows" / workflow_name
    ).read_text(encoding="utf-8")
    step_start = workflow.index(step_name)
    step_end = workflow.index("\n      - name:", step_start + len(step_name))
    step = workflow[step_start:step_end]
    commands = logical_commands(step)
    compile_command = (
        "meson compile -C build-secure-duckdb -j 1 "
        "test-secure-duckdb-bridge "
        "test-secure-duckdb-filesystem "
        "test-secure-duckdb-recording-filesystem"
    )
    test_command = (
        "meson test -C build-secure-duckdb --no-rebuild "
        "secure-duckdb-bridge secure-duckdb-filesystem "
        "secure-duckdb-recording-filesystem --print-errorlogs"
    )
    if commands.count(compile_command) != 1:
        raise SystemExit(
            f"{workflow_name} must compile exactly the bounded secure targets"
        )
    if commands.count(test_command) != 1:
        raise SystemExit(
            f"{workflow_name} must test exactly the built secure targets"
        )
    if commands.index(compile_command) > commands.index(test_command):
        raise SystemExit(
            f"{workflow_name} tests run before the bounded explicit compile"
        )

print("Secure DuckDB hosted-runner CI boundary: OK")

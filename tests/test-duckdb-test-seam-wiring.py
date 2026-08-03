#!/usr/bin/env python3
"""Guard separation between regular and seam-enabled DuckDB targets."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
package = (
    root / "subprojects" / "packagefiles" / "duckdb-amalgamated"
    / "meson.build").read_text(encoding="utf-8")
parent = (root / "meson.build").read_text(encoding="utf-8")
tests = (root / "tests" / "meson.build").read_text(encoding="utf-8")
swap_helper = (
    root / ".github" / "scripts" / "duckdb-compile-swap.sh"
).read_text(encoding="utf-8")

regular_start = package.index("duckdb_lib = static_library(")
regular_end = package.index("\n)\n", regular_start)
regular = package[regular_start:regular_end]
if "WYL_DUCKDB_TEST_AFTER_WAL_START" in regular:
    raise SystemExit("regular duckdb_lib must compile without the test seam")

seam_start = package.index(
    "duckdb_test_seam_lib = static_library('duckdb-test-after-wal-start'")
seam_end = package.index("\n  )\n", seam_start)
seam = package[seam_start:seam_end]
if seam.count("duckdb.cpp") != 1:
    raise SystemExit("test seam must compile the pinned amalgamation directly")
if "duckdb_test_seam_compile_args" not in seam:
    raise SystemExit("test seam target must receive its compile-time macro")
if "install : false" not in seam or "build_by_default : false" not in seam:
    raise SystemExit("test seam target must remain non-installed and test-only")
if "'optimization=' + duckdb_test_seam_optimization" not in seam \
        or "'debug=false'" not in seam:
    raise SystemExit("test seam must stay within its platform CI lease")
if ("duckdb_test_seam_optimization = "
        "host_machine.system() == 'linux' ? '0' : '2'") not in package:
    raise SystemExit("Linux O0 and macOS O2 seam profiles must remain explicit")

if package.count("'-DWYL_DUCKDB_TEST_AFTER_WAL_START=1'") != 1:
    raise SystemExit("the seam macro must be defined for exactly one dependency")
if "if host_machine.system() != 'windows'" not in package:
    raise SystemExit("the seam variant must not become Windows runtime work")
if "duckdb_test_seam_dep = duckdb_subproject.get_variable(" not in parent:
    raise SystemExit("the source-pinned parent must expose the test dependency")

consumer_start = tests.index(
    "test_duckdb_after_walstart = executable(")
consumer_end = tests.index("\n    )\n", consumer_start)
consumer = tests[consumer_start:consumer_end]
if "dependencies : [glib_dep, gio_dep, duckdb_test_seam_dep]" not in consumer:
    raise SystemExit("focused test must consume only the seam-enabled DuckDB")
for forbidden in ("duckdb_dep", "wyrelog_dep"):
    if forbidden in consumer.replace("duckdb_test_seam_dep", ""):
        raise SystemExit(
            f"focused seam test must not dual-link {forbidden}")
if "build_by_default : false" not in consumer:
    raise SystemExit("focused seam runtime must remain test-only")
if tests.count("duckdb_test_seam_dep") != 1:
    raise SystemExit("only the focused runtime may consume the seam dependency")

for workflow_name in ("ci-pr.yml", "ci-main.yml"):
    workflow = (
        root / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8")
    job_start = workflow.index("  duckdb-checkpoint-seam:")
    job_end = workflow.index("\n  daemon-http-shared-fact:", job_start)
    job = workflow[job_start:job_end]
    required = (
        "os: [ubuntu-latest, macos-latest]",
        "timeout-minutes: 45",
        "meson compile -C build-duckdb-seam",
        "-j 1 test-duckdb-after-walstart",
        "test-duckdb-after-walstart",
        "meson test -C build-duckdb-seam --no-rebuild",
        "duckdb-after-walstart-no-wal",
        "duckdb-after-walstart-rendezvous",
        "duckdb-fixed-wal-successful-checkpoint",
        "duckdb-fixed-wal-pre-move-abort-reopen",
        "duckdb-fixed-wal-interrupted-recovery",
        "duckdb-fixed-wal-lifecycle-boundary",
        "Repeat fixed WAL lifecycle evidence",
        "for iteration in 1 2 3 4 5",
        "duckdb-after-walstart-boundary",
        "duckdb-test-seam-wiring",
        "duckdb-compile-swap.sh provision seam",
        "Remove bounded Linux compile swap",
        "duckdb-compile-swap.sh cleanup seam",
    )
    for token in required:
        if token not in job:
            raise SystemExit(
                f"{workflow_name} focused seam job drifted: {token}")
    if "secure-duckdb-recording-filesystem" in job:
        raise SystemExit(
            f"{workflow_name} seam job must not build the regular archive")
    if "sccache" in job:
        raise SystemExit(
            f"{workflow_name} seam job must remain compiler-cache-free")
    if job.count("4000000000") != 1:
        raise SystemExit(
            f"{workflow_name} must recheck disk immediately before compile")

helper_required = (
    'secure|seam',
    'readonly trusted_anchor=/var/tmp',
    'test "$(realpath "$trusted_anchor")" = "$trusted_anchor"',
    'require_root_node "$trusted_anchor" 1777',
    'for target in "$trusted_anchor" "$GITHUB_WORKSPACE"',
    'lease_basename="wyrelog-duckdb-${GITHUB_RUN_ID}-"',
    'lease_basename+="${GITHUB_RUN_ATTEMPT}-'
    '${GITHUB_JOB}-${purpose}.lease"',
    'lease_path="$trusted_anchor/$lease_basename"',
    'swap_path="$lease_path/compile.swap"',
    'marker_path="$lease_path/owner.marker"',
    'sudo test -e "$lease_path" || sudo test -L "$lease_path"',
    'readonly marker_version=wyrelog-duckdb-swap-v1',
    'GITHUB_RUN_ID',
    'GITHUB_RUN_ATTEMPT',
    'GITHUB_JOB',
    'sudo mkdir -m 700 -- "$lease_path"',
    'sudo install -m 600 -o 0 -g 0',
    'sudo cmp -s - "$marker_path"',
    'validate_owned_lease',
    'require_root_node "$lease_path" 700',
    'require_root_node "$marker_path" 600',
    'require_root_node "$swap_path" 600',
    'test ! -L "$lease_path"',
    'test ! -L "$swap_path"',
    'test ! -L "$marker_path"',
    'readonly swap_bytes=8589934592',
    'readonly preallocate_free_floor=12000000000',
    'readonly retained_free_floor=4000000000',
    'readonly combined_memory_floor=24000000000',
    'sudo fallocate -l "$swap_bytes" "$swap_path"',
    'sudo mkswap "$swap_path"',
    'sudo swapon "$swap_path"',
    'sudo swapoff "$swap_path"',
    'sudo rm -f -- "$swap_path"',
    'sudo rm -f -- "$marker_path"',
    'sudo rmdir -- "$lease_path"',
)
for token in helper_required:
    if token not in swap_helper:
        raise SystemExit(f"DuckDB compile swap helper drifted: {token}")
for forbidden in ("RUNNER_TEMP", "realpath -m", "rm -rf", "actual_marker="):
    if forbidden in swap_helper:
        raise SystemExit(f"DuckDB compile swap helper is unsafe: {forbidden}")

print("DuckDB test seam dependency boundary: OK")

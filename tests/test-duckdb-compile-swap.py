#!/usr/bin/env python3
"""Exercise the owned DuckDB compile-swap lifecycle without root access."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile


root = Path(sys.argv[1])
helper = root / ".github" / "scripts" / "duckdb-compile-swap.sh"


def write_command(directory, name, body):
    path = directory / name
    path.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
map_path()
{
  case "$1" in
    /var/tmp) printf '%s\n' "$FAKE_TRUSTED_ANCHOR" ;;
    /var/tmp/*)
      printf '%s/%s\n' "$FAKE_TRUSTED_ANCHOR" "${1#/var/tmp/}"
      ;;
    *) printf '%s\n' "$1" ;;
  esac
}
""" + body,
        encoding="utf-8",
    )
    path.chmod(0o755)


with tempfile.TemporaryDirectory() as temporary:
    base = Path(temporary)
    commands = base / "commands"
    runner_temp = base / "runner"
    trusted_anchor = base / "var-tmp"
    workspace = base / "workspace"
    commands.mkdir()
    runner_temp.mkdir()
    trusted_anchor.mkdir(mode=0o1777)
    workspace.mkdir()
    state = base / "active-swap"

    write_command(commands, "sudo", 'exec "$@"\n')
    write_command(
        commands,
        "realpath",
        """
if [ "$1" = /var/tmp ]; then
  printf '%s\\n' "${FAKE_ANCHOR_CANONICAL:-/var/tmp}"
else
  exec /usr/bin/realpath "$@"
fi
""",
    )
    write_command(
        commands,
        "test",
        """
if [ "${FAKE_ANCHOR_SYMLINK:-0}" = 1 ] \
    && [ "$*" = "! -L /var/tmp" ]; then
  exit 1
fi
args=()
for argument in "$@"; do
  args+=("$(map_path "$argument")")
done
exec /usr/bin/test "${args[@]}"
""",
    )
    write_command(
        commands,
        "stat",
        """
format="$2"
logical_path="$3"
physical_path="$(map_path "$logical_path")"
case "$format" in
  %u)
    if [ "$logical_path" = /var/tmp ]; then
      printf '%s\\n' "${FAKE_ANCHOR_UID:-0}"
    else
      printf '0\\n'
    fi
    ;;
  %g) printf '0\\n' ;;
  %a)
    if [ "$logical_path" = /var/tmp ]; then
      printf '%s\\n' "${FAKE_ANCHOR_MODE:-1777}"
    else
      exec /usr/bin/stat -c %a "$physical_path"
    fi
    ;;
  *) exec /usr/bin/stat -c "$format" "$physical_path" ;;
esac
""",
    )
    write_command(
        commands,
        "install",
        """
mode=
while [ "$#" -gt 2 ]; do
  case "$1" in
    -m) mode="$2"; shift 2 ;;
    -o|-g) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
source_path="$(map_path "$1")"
target_path="$(map_path "$2")"
case "$2" in
  */owner.marker)
    [ "${FAKE_MARKER_INSTALL_FAIL:-0}" = 0 ] || exit 2
    ;;
esac
exec /usr/bin/install -m "$mode" "$source_path" "$target_path"
""",
    )
    write_command(
        commands,
        "mkdir",
        """
args=()
for argument in "$@"; do
  args+=("$(map_path "$argument")")
done
exec /usr/bin/mkdir "${args[@]}"
""",
    )
    write_command(
        commands,
        "find",
        """
path="$(map_path "$1")"
shift
exec /usr/bin/find "$path" "$@"
""",
    )
    for command in ("cat", "rm", "rmdir"):
        write_command(
            commands,
            command,
            f"""
args=()
for argument in "$@"; do
  args+=("$(map_path "$argument")")
done
exec /usr/bin/{command} "${{args[@]}}"
""",
        )
    write_command(
        commands,
        "cmp",
        """
args=()
for argument in "$@"; do
  args+=("$(map_path "$argument")")
done
exec /usr/bin/cmp "${args[@]}"
""",
    )
    write_command(
        commands,
        "mv",
        """
source_path="$(map_path "$1")"
target_path="$(map_path "$2")"
case "$1" in
  /var/tmp/wyrelog-duckdb-*.lease) exit 1 ;;
esac
exec /usr/bin/mv "$source_path" "$target_path"
""",
    )
    write_command(
        commands,
        "df",
        "printf 'Avail\\n        %s\\n' \"$FAKE_DF_AVAILABLE\"\n",
    )
    write_command(
        commands,
        "fallocate",
        '[ "$1" = -l ]\ntruncate -s "$2" "$(map_path "$3")"\n',
    )
    write_command(
        commands,
        "mkswap",
        '[ "${FAKE_MKSWAP_FAIL:-0}" = 0 ] || exit 2\n'
        '[ -f "$(map_path "$1")" ]\n',
    )
    write_command(
        commands,
        "swapon",
        """
case "${1:-}" in
  --show=NAME,SIZE)
    [ "${FAKE_SWAP_INSPECTION_FAIL:-0}" = 0 ] || exit 2
    if [ -s "$FAKE_SWAP_STATE" ]; then
      printf '%s 8589934592\\n' "$(cat "$FAKE_SWAP_STATE")"
    fi
    ;;
  --show=NAME)
    [ "${FAKE_SWAP_INSPECTION_FAIL:-0}" = 0 ] || exit 2
    if [ -s "$FAKE_SWAP_STATE" ]; then
      cat "$FAKE_SWAP_STATE"
    fi
    ;;
  *)
    printf '%s\\n' "$1" > "$FAKE_SWAP_STATE"
    ;;
esac
""",
    )
    write_command(
        commands,
        "swapoff",
        '[ "$(cat "$FAKE_SWAP_STATE")" = "$1" ]\n'
        'rm -f "$FAKE_SWAP_STATE"\n',
    )
    write_command(
        commands,
        "awk",
        """
case "$*" in
  *MemTotal*) printf '%s\\n' "$FAKE_MEM_KIB" ;;
  *SwapTotal*) printf '%s\\n' "$FAKE_SWAP_KIB" ;;
  *) exec /usr/bin/awk "$@" ;;
esac
""",
    )

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{commands}:{environment['PATH']}",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "FAKE_TRUSTED_ANCHOR": str(trusted_anchor),
            "GITHUB_RUN_ID": "681001",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_JOB": "build-posix",
            "FAKE_SWAP_STATE": str(state),
            "FAKE_DF_AVAILABLE": "16000000000",
            "FAKE_MEM_KIB": "16000000",
            "FAKE_SWAP_KIB": "8388608",
        }
    )

    def lease_path(purpose):
        return (
            trusted_anchor
            / f"wyrelog-duckdb-681001-1-build-posix-{purpose}.lease"
        )

    def logical_lease_path(purpose):
        return Path(
            f"/var/tmp/wyrelog-duckdb-681001-1-build-posix-{purpose}.lease"
        )

    def logical_swap_path(purpose):
        return logical_lease_path(purpose) / "compile.swap"

    def swap_path(purpose):
        return lease_path(purpose) / "compile.swap"

    def marker_path(purpose):
        return lease_path(purpose) / "owner.marker"

    def marker_text(purpose):
        return f"wyrelog-duckdb-swap-v1:681001:1:build-posix:{purpose}\n"

    def helper_run(operation, purpose, overrides=None):
        command_environment = environment.copy()
        if overrides:
            command_environment.update(overrides)
        return subprocess.run(
            ["bash", str(helper), operation, purpose],
            check=False,
            env=command_environment,
        )

    for overrides in (
        {"FAKE_ANCHOR_CANONICAL": "/tmp"},
        {"FAKE_ANCHOR_UID": "1000"},
        {"FAKE_ANCHOR_MODE": "0777"},
        {"FAKE_ANCHOR_SYMLINK": "1"},
    ):
        anchor_check = helper_run("provision", "secure", overrides)
        if anchor_check.returncode == 0 or lease_path("secure").exists():
            raise SystemExit("trusted sticky-root anchor check was bypassed")

    provision_target = runner_temp / "provision-symlink-target"
    provision_link = lease_path("secure")
    provision_link.symlink_to(provision_target)
    if helper_run("provision", "secure").returncode == 0:
        raise SystemExit("provision accepted a symlink lease")
    if (
        not provision_link.is_symlink()
        or provision_target.exists()
        or provision_link.readlink() != provision_target
    ):
        raise SystemExit("provision changed a symlink lease or its target")
    provision_link.unlink()

    cleanup_target = runner_temp / "cleanup-symlink-target"
    cleanup_target.mkdir()
    cleanup_sentinel = cleanup_target / "sentinel"
    cleanup_sentinel.write_text("unchanged", encoding="utf-8")
    cleanup_link = lease_path("seam")
    cleanup_link.symlink_to(cleanup_target)
    if helper_run("cleanup", "seam").returncode == 0:
        raise SystemExit("cleanup accepted a symlink lease")
    if (
        not cleanup_link.is_symlink()
        or cleanup_sentinel.read_text(encoding="utf-8") != "unchanged"
        or cleanup_link.readlink() != cleanup_target
    ):
        raise SystemExit("cleanup changed a symlink lease or its target")
    cleanup_link.unlink()
    cleanup_sentinel.unlink()
    cleanup_target.rmdir()

    foreign_file = lease_path("secure")
    foreign_file.write_text("foreign-regular-file", encoding="utf-8")
    if helper_run("provision", "secure").returncode == 0:
        raise SystemExit("provision accepted a foreign lease file")
    if helper_run("cleanup", "secure").returncode == 0:
        raise SystemExit("cleanup accepted a foreign lease file")
    if foreign_file.read_text(encoding="utf-8") != "foreign-regular-file":
        raise SystemExit("always cleanup changed a foreign lease file")
    foreign_file.unlink()

    foreign_directory = lease_path("seam")
    foreign_directory.mkdir(mode=0o700)
    foreign_sentinel = foreign_directory / "sentinel"
    foreign_sentinel.write_text("foreign-directory", encoding="utf-8")
    if helper_run("cleanup", "seam").returncode == 0:
        raise SystemExit("cleanup accepted a foreign lease directory")
    if foreign_sentinel.read_text(encoding="utf-8") != "foreign-directory":
        raise SystemExit("cleanup changed a foreign lease directory")
    foreign_sentinel.unlink()
    foreign_directory.rmdir()

    mismatch_directory = lease_path("secure")
    mismatch_directory.mkdir(mode=0o700)
    mismatch_marker = marker_path("secure")
    mismatch_marker.write_text(
        marker_text("secure") + "\n",
        encoding="utf-8",
    )
    mismatch_marker.chmod(0o600)
    if helper_run("cleanup", "secure").returncode == 0:
        raise SystemExit("cleanup accepted an extra marker newline")
    preserved_marker = mismatch_marker.read_text(encoding="utf-8")
    if preserved_marker != marker_text("secure") + "\n":
        raise SystemExit("cleanup changed a byte-mismatched marker")
    mismatch_marker.unlink()
    mismatch_directory.rmdir()

    symlink_directory = lease_path("seam")
    symlink_directory.mkdir(mode=0o700)
    symlink_marker = marker_path("seam")
    symlink_marker.write_text(marker_text("seam"), encoding="utf-8")
    symlink_marker.chmod(0o600)
    swap_target = runner_temp / "swap-symlink-target"
    swap_target.write_text("unchanged", encoding="utf-8")
    swap_link = swap_path("seam")
    swap_link.symlink_to(swap_target)
    if helper_run("cleanup", "seam").returncode == 0:
        raise SystemExit("cleanup accepted a symlink swap file")
    if (
        not swap_link.is_symlink()
        or swap_target.read_text(encoding="utf-8") != "unchanged"
    ):
        raise SystemExit("cleanup changed a symlink swap file or target")
    swap_link.unlink()
    swap_target.unlink()
    symlink_marker.unlink()
    symlink_directory.rmdir()

    if helper_run("cleanup", "secure").returncode != 0:
        raise SystemExit("cleanup did not ignore an absent lease")
    state.write_text(str(logical_swap_path("secure")), encoding="utf-8")
    absent_active = helper_run("cleanup", "secure")
    if absent_active.returncode == 0:
        raise SystemExit("absent lease hid an active exact swap path")
    if (
        state.read_text(encoding="utf-8") != str(logical_swap_path("secure"))
        or lease_path("secure").exists()
    ):
        raise SystemExit("absent-active cleanup changed external evidence")
    state.unlink()

    invalid = helper_run("provision", "invalid")
    if invalid.returncode == 0 or state.exists():
        raise SystemExit("unknown swap purpose was accepted")

    low_disk = helper_run(
        "provision",
        "secure",
        {"FAKE_DF_AVAILABLE": "11999999999"},
    )
    if low_disk.returncode == 0 or lease_path("secure").exists():
        raise SystemExit("preallocation free-space floor was not fail-closed")

    marker_failure = helper_run(
        "provision",
        "secure",
        {"FAKE_MARKER_INSTALL_FAIL": "1"},
    )
    if marker_failure.returncode == 0 or lease_path("secure").exists():
        raise SystemExit("unmarked lease creation failure was not recovered")

    before_swapon = helper_run(
        "provision",
        "seam",
        {"FAKE_MKSWAP_FAIL": "1"},
    )
    if before_swapon.returncode == 0 or not lease_path("seam").is_dir():
        raise SystemExit("pre-swapon failure did not retain owned evidence")
    if state.exists() or helper_run("cleanup", "seam").returncode != 0:
        raise SystemExit("pre-swapon owned lease was not safely recovered")
    if lease_path("seam").exists():
        raise SystemExit("pre-swapon cleanup left owned evidence")

    if helper_run("provision", "secure").returncode != 0:
        raise SystemExit("replacement-attempt fixture did not provision")
    replacement = subprocess.run(
        [
            "mv",
            str(logical_lease_path("secure")),
            f"{logical_lease_path('secure')}.replacement",
        ],
        check=False,
        env=environment,
    )
    if replacement.returncode == 0 or not lease_path("secure").is_dir():
        raise SystemExit("runner replaced a root lease under sticky anchor")
    if helper_run("cleanup", "secure").returncode != 0:
        raise SystemExit("replacement-attempt fixture did not clean up")

    lifecycle_harness = r"""
set -u
helper="$1"
purpose="$2"
bash "$helper" provision "$purpose" || exit $?
bash -c "$FAKE_PRODUCER"
producer_status=$?
cleanup_status=0
if [ "${FAKE_CLEANUP_INSPECTION_FAIL:-0}" = 1 ]; then
  export FAKE_SWAP_INSPECTION_FAIL=1
fi
bash "$helper" cleanup "$purpose" || cleanup_status=$?
if [ "$producer_status" -ne 0 ]; then
  exit "$producer_status"
fi
exit "$cleanup_status"
"""

    def lifecycle_run(purpose, producer, cleanup_failure=False):
        command_environment = environment.copy()
        command_environment["FAKE_PRODUCER"] = producer
        if cleanup_failure:
            command_environment["FAKE_CLEANUP_INSPECTION_FAIL"] = "1"
        return subprocess.run(
            [
                "bash",
                "-c",
                lifecycle_harness,
                "duckdb-compile-lifecycle",
                str(helper),
                purpose,
            ],
            check=False,
            env=command_environment,
        )

    for purpose, producer, expected_status in (
        ("secure", "exit 0", 0),
        ("seam", "exit 37", 37),
        ("secure", "kill -TERM $$", 143),
    ):
        lifecycle = lifecycle_run(purpose, producer)
        if lifecycle.returncode != expected_status:
            raise SystemExit(
                f"{purpose} producer status {expected_status} was not preserved"
            )
        if lease_path(purpose).exists() or state.exists():
            raise SystemExit(f"{purpose} owned lease survived cleanup")

    combined_floor = helper_run(
        "provision",
        "secure",
        {"FAKE_MEM_KIB": "1", "FAKE_SWAP_KIB": "8388608"},
    )
    if combined_floor.returncode == 0 or not state.exists():
        raise SystemExit("combined-memory floor was not fail-closed")
    if helper_run("cleanup", "secure").returncode != 0:
        raise SystemExit("failed provisioning lease survived always cleanup")
    if lease_path("secure").exists() or state.exists():
        raise SystemExit("always cleanup left failed provisioning evidence")

    if helper_run("provision", "secure").returncode != 0:
        raise SystemExit("cleanup inspection fixture did not provision")
    inspection_failure = helper_run(
        "cleanup",
        "secure",
        {"FAKE_SWAP_INSPECTION_FAIL": "1"},
    )
    if inspection_failure.returncode == 0:
        raise SystemExit("cleanup accepted an unverified inactive state")
    if not lease_path("secure").is_dir() or not state.exists():
        raise SystemExit("failed cleanup removed owned lease evidence")
    if helper_run("cleanup", "secure").returncode != 0:
        raise SystemExit("cleanup retry did not release the exact lease")

    cleanup_failure = lifecycle_run("seam", "exit 37", cleanup_failure=True)
    if cleanup_failure.returncode != 37:
        raise SystemExit("cleanup failure turned producer failure into success")
    if not lease_path("seam").is_dir() or not state.exists():
        raise SystemExit("fail-closed cleanup did not retain owned evidence")
    if helper_run("cleanup", "seam").returncode != 0:
        raise SystemExit("cleanup failure retry did not release the exact lease")

print("DuckDB compile swap ownership lifecycle: OK")

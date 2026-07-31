#!/usr/bin/env python3
"""Verify the POSIX daemon HTTP companion stays linked but unexported."""

from pathlib import Path
import re
import shutil
import subprocess
import sys


BEGIN_SYMBOL = (
    "wyl_service_credential_operation_coordinator_begin_or_replay_locked"
)


def run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"symbol inspection failed: {' '.join(command)}\n{result.stdout}"
        )
    return result.stdout


def normalize_symbol(name: str, macho: bool) -> str:
    normalized = name.split("@", 1)[0]
    if macho and normalized.startswith("_wyl_"):
        normalized = normalized[1:]
    return normalized


def wyl_symbols(output: str, macho: bool) -> set[str]:
    symbols = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        candidate = normalize_symbol(fields[-1], macho)
        if re.fullmatch(r"wyl_[A-Za-z0-9_]+", candidate):
            symbols.add(candidate)
    return symbols


def nm_path() -> str:
    tool = shutil.which("nm") or shutil.which("llvm-nm")
    if tool is None:
        raise RuntimeError("nm or llvm-nm is required")
    return tool


def defined_command(tool: str, artifact: Path, macho: bool) -> list[str]:
    return (
        [tool, "-U", str(artifact)]
        if macho
        else [tool, "--defined-only", str(artifact)]
    )


def exported_command(tool: str, artifact: Path,
                     macho: bool) -> list[str] | None:
    if artifact.suffix == ".a":
        return None
    return (
        [tool, "-gU", str(artifact)]
        if macho
        else [tool, "-D", "--defined-only", str(artifact)]
    )


def defined_symbols(artifact: Path, macho: bool) -> set[str]:
    command = defined_command(nm_path(), artifact, macho)
    return wyl_symbols(run(command), macho)


def exported_symbols(artifact: Path, macho: bool) -> set[str]:
    command = exported_command(nm_path(), artifact, macho)
    if command is None:
        # An archive contributes link inputs, not runtime exports.  The
        # executable checks below still prove that its selected definitions
        # remain hidden in static-library configurations.
        return set()
    return wyl_symbols(run(command), macho)


def self_test() -> int:
    elf = """
00000001 T wyl_public
00000002 T wyl_service_credential_operation_coordinator_begin_or_replay_locked
00000003 T wyl_versioned@@WYRELOG_1
00000004 T prefix_wyl_not_a_symbol
"""
    if wyl_symbols(elf, False) != {
        "wyl_public",
        BEGIN_SYMBOL,
        "wyl_versioned",
    }:
        return 1
    macho = """
00000001 T _wyl_public
00000002 T _wyl_service_credential_operation_coordinator_begin_or_replay_locked
00000003 T __wyl_not_normalized
"""
    if wyl_symbols(macho, True) != {"wyl_public", BEGIN_SYMBOL}:
        return 1
    if normalize_symbol("__wyl_private", True) != "__wyl_private":
        return 1
    artifact = Path("/tmp/test-daemon-http-decide")
    if defined_command("nm", artifact, False) != [
            "nm", "--defined-only", str(artifact)]:
        return 1
    if defined_command("nm", artifact, True) != [
            "nm", "-U", str(artifact)]:
        return 1
    if exported_command("nm", artifact, False) != [
            "nm", "-D", "--defined-only", str(artifact)]:
        return 1
    if exported_command("nm", artifact, True) != [
            "nm", "-gU", str(artifact)]:
        return 1
    if exported_command("nm", Path("/tmp/libwyrelog.a"), False) is not None:
        return 1
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) < 4:
        print(
            "usage: check-daemon-http-decide-private-symbols.py "
            "COMPANION LIBWYRELOG EXECUTABLE...",
            file=sys.stderr,
        )
        return 2

    artifacts = [Path(argument) for argument in sys.argv[1:]]
    missing = [artifact for artifact in artifacts if not artifact.is_file()]
    if missing:
        print("artifact missing:", *missing, sep="\n  ", file=sys.stderr)
        return 1

    companion, library, *executables = artifacts
    macho = sys.platform == "darwin"
    try:
        companion_symbols = defined_symbols(companion, macho)
        library_exports = exported_symbols(library, macho)
        executable_symbols = [
            defined_symbols(executable, macho) for executable in executables
        ]
        executable_exports = [
            exported_symbols(executable, macho) for executable in executables
        ]
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1

    if BEGIN_SYMBOL not in companion_symbols:
        print(
            f"private companion does not define {BEGIN_SYMBOL}",
            file=sys.stderr,
        )
        return 1
    if BEGIN_SYMBOL in library_exports:
        print(f"libwyrelog exports {BEGIN_SYMBOL}", file=sys.stderr)
        return 1

    for executable, symbols, exports in zip(
            executables, executable_symbols, executable_exports):
        if BEGIN_SYMBOL not in symbols:
            print(
                f"{executable} does not contain linked {BEGIN_SYMBOL}",
                file=sys.stderr,
            )
            return 1
        leaked = companion_symbols & exports
        if leaked:
            print(
                f"{executable} exports private companion symbols:",
                *sorted(leaked),
                sep="\n  ",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

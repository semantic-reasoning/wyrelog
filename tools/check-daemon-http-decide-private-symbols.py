#!/usr/bin/env python3
"""Prove the daemon HTTP seed helper is an isolated runtime DSO boundary."""

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


SEED_SYMBOL = "wyl_test_daemon_http_seed_prepared_operation"
BEGIN_SYMBOL = (
    "wyl_service_credential_operation_coordinator_begin_or_replay_locked"
)
STORAGE_OPEN_SYMBOL = "wyl_service_credential_operation_storage_open"
LOAD_SYMBOL = "wyl_service_credential_operation_coordinator_load"
LOCK_ACQUIRE_SYMBOL = (
    "wyl_service_credential_operation_coordinator_lock_acquire"
)
LOCK_RELEASE_SYMBOL = (
    "wyl_service_credential_operation_coordinator_lock_release"
)
HELPER_CLOSURE = {
    BEGIN_SYMBOL,
    STORAGE_OPEN_SYMBOL,
    LOAD_SYMBOL,
    LOCK_ACQUIRE_SYMBOL,
    LOCK_RELEASE_SYMBOL,
}
EXECUTABLE_IMPORTS = {
    SEED_SYMBOL,
    STORAGE_OPEN_SYMBOL,
    LOAD_SYMBOL,
    LOCK_ACQUIRE_SYMBOL,
    LOCK_RELEASE_SYMBOL,
}


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
            f"artifact inspection failed: {' '.join(command)}\n{result.stdout}"
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


def dynamic_defined_external_symbols(output: str, macho: bool) -> set[str]:
    symbols = set()
    for line in output.splitlines():
        match = re.fullmatch(
            r"\s*[0-9A-Fa-f]+\s+[A-Za-z?]\s+(\S+)\s*",
            line,
        )
        if match is None:
            continue
        candidate = match.group(1).split("@", 1)[0]
        if macho and candidate.startswith("_"):
            candidate = candidate[1:]
        symbols.add(candidate)
    return symbols


def helper_exports_are_exact(exports: set[str]) -> bool:
    return exports == {SEED_SYMBOL}


def missing_executable_imports(imports: set[str]) -> set[str]:
    return EXECUTABLE_IMPORTS - imports


def find_tool(*names: str) -> str:
    for name in names:
        tool = shutil.which(name)
        if tool is not None:
            return tool
    raise RuntimeError(f"required artifact inspector missing: {' or '.join(names)}")


def defined_command(tool: str, artifact: Path, macho: bool) -> list[str]:
    return (
        [tool, "-U", str(artifact)]
        if macho
        else [tool, "--defined-only", str(artifact)]
    )


def exported_command(tool: str, artifact: Path, macho: bool) -> list[str]:
    return (
        [tool, "-gU", str(artifact)]
        if macho
        else [tool, "-D", "--defined-only", str(artifact)]
    )


def undefined_command(tool: str, artifact: Path) -> list[str]:
    return [tool, "-u", str(artifact)]


def defined_symbols(artifact: Path, macho: bool) -> set[str]:
    return wyl_symbols(
        run(defined_command(find_tool("nm", "llvm-nm"), artifact, macho)),
        macho,
    )


def exported_symbols(artifact: Path, macho: bool) -> set[str]:
    return wyl_symbols(
        run(exported_command(find_tool("nm", "llvm-nm"), artifact, macho)),
        macho,
    )


def dynamic_external_exports(artifact: Path, macho: bool) -> set[str]:
    return dynamic_defined_external_symbols(
        run(exported_command(find_tool("nm", "llvm-nm"), artifact, macho)),
        macho,
    )


def undefined_symbols(artifact: Path, macho: bool) -> set[str]:
    return wyl_symbols(
        run(undefined_command(find_tool("nm", "llvm-nm"), artifact)),
        macho,
    )


def provider_output(artifact: Path, macho: bool) -> str:
    if macho:
        return run([find_tool("otool"), "-L", str(artifact)])
    return run([
        find_tool("readelf", "llvm-readelf"),
        "-d",
        str(artifact),
    ])


def provider_is_needed(output: str, helper: Path) -> bool:
    return helper.name in output


def install_manifest_is_clean(manifest: Path, helper: Path,
                              header: Path) -> bool:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    encoded = json.dumps(data, sort_keys=True)
    return helper.name not in encoded and header.name not in encoded


def self_test() -> int:
    elf = """
00000001 T wyl_public
00000002 t wyl_service_credential_operation_coordinator_begin_or_replay_locked
                 U wyl_service_credential_operation_storage_open@@WYRELOG_1
00000004 T prefix_wyl_not_a_symbol
"""
    if wyl_symbols(elf, False) != {
        "wyl_public",
        BEGIN_SYMBOL,
        STORAGE_OPEN_SYMBOL,
    }:
        return 1
    macho = """
00000001 T _wyl_test_daemon_http_seed_prepared_operation
                 U _wyl_service_credential_operation_coordinator_load
00000003 T __wyl_not_normalized
"""
    if wyl_symbols(macho, True) != {SEED_SYMBOL, LOAD_SYMBOL}:
        return 1
    adversarial_helper_exports = """
00000001 T wyl_test_daemon_http_seed_prepared_operation
00000002 T unintended_helper_export
"""
    parsed_helper_exports = dynamic_defined_external_symbols(
        adversarial_helper_exports,
        False,
    )
    if parsed_helper_exports != {SEED_SYMBOL, "unintended_helper_export"}:
        return 1
    if helper_exports_are_exact(parsed_helper_exports):
        return 1
    if not helper_exports_are_exact({SEED_SYMBOL}):
        return 1
    macho_helper_exports = """
00000001 T _wyl_test_daemon_http_seed_prepared_operation
00000002 T _unintended_helper_export
"""
    if dynamic_defined_external_symbols(macho_helper_exports, True) != {
        SEED_SYMBOL,
        "unintended_helper_export",
    }:
        return 1
    lockless_imports = {
        SEED_SYMBOL,
        STORAGE_OPEN_SYMBOL,
        LOAD_SYMBOL,
    }
    if missing_executable_imports(lockless_imports) != {
        LOCK_ACQUIRE_SYMBOL,
        LOCK_RELEASE_SYMBOL,
    }:
        return 1
    if missing_executable_imports(EXECUTABLE_IMPORTS):
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
    if undefined_command("nm", artifact) != ["nm", "-u", str(artifact)]:
        return 1
    helper = Path("/tmp/libtest-daemon-http-decide-seed-helper.so")
    if not provider_is_needed(
            " 0x0000000000000001 (NEEDED) Shared library: "
            "[libtest-daemon-http-decide-seed-helper.so]",
            helper):
        return 1
    if provider_is_needed("libwyrelog.so.0", helper):
        return 1
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) < 6:
        print(
            "usage: check-daemon-http-decide-private-symbols.py "
            "INSTALL_MANIFEST HELPER HEADER LIBWYRELOG EXECUTABLE...",
            file=sys.stderr,
        )
        return 2

    manifest = Path(sys.argv[1])
    helper = Path(sys.argv[2])
    header = Path(sys.argv[3])
    library = Path(sys.argv[4])
    executables = [Path(argument) for argument in sys.argv[5:]]
    artifacts = [manifest, helper, header, library, *executables]
    missing = [artifact for artifact in artifacts if not artifact.is_file()]
    if missing:
        print("artifact missing:", *missing, sep="\n  ", file=sys.stderr)
        return 1

    macho = sys.platform == "darwin"
    try:
        helper_exports = dynamic_external_exports(helper, macho)
        helper_definitions = defined_symbols(helper, macho)
        library_exports = exported_symbols(library, macho)
        library_definitions = defined_symbols(library, macho)
        executable_definitions = [
            defined_symbols(executable, macho) for executable in executables
        ]
        executable_imports = [
            undefined_symbols(executable, macho) for executable in executables
        ]
        providers = [
            provider_output(executable, macho) for executable in executables
        ]
        manifest_clean = install_manifest_is_clean(manifest, helper, header)
    except (json.JSONDecodeError, OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        return 1

    if not helper_exports_are_exact(helper_exports):
        print(
            "seed helper dynamic external exports mismatch:",
            *sorted(helper_exports),
            sep="\n  ",
            file=sys.stderr,
        )
        return 1
    missing_closure = HELPER_CLOSURE - helper_definitions
    if missing_closure:
        print(
            "seed helper hidden closure missing:",
            *sorted(missing_closure),
            sep="\n  ",
            file=sys.stderr,
        )
        return 1
    if HELPER_CLOSURE & helper_exports:
        print("seed helper closure is dynamically exported", file=sys.stderr)
        return 1
    forbidden_library_exports = {BEGIN_SYMBOL, SEED_SYMBOL} & library_exports
    if forbidden_library_exports:
        print(
            "libwyrelog exports test/private symbols:",
            *sorted(forbidden_library_exports),
            sep="\n  ",
            file=sys.stderr,
        )
        return 1
    missing_library_definitions = {
        STORAGE_OPEN_SYMBOL,
        LOAD_SYMBOL,
    } - library_definitions
    if missing_library_definitions:
        print(
            "libwyrelog ordinary provider definitions missing:",
            *sorted(missing_library_definitions),
            sep="\n  ",
            file=sys.stderr,
        )
        return 1
    missing_library_exports = {
        STORAGE_OPEN_SYMBOL,
        LOAD_SYMBOL,
    } - library_exports
    if missing_library_exports:
        print(
            "libwyrelog dynamic provider exports missing:",
            *sorted(missing_library_exports),
            sep="\n  ",
            file=sys.stderr,
        )
        return 1
    if not manifest_clean:
        print("seed helper or header appears in the install manifest",
              file=sys.stderr)
        return 1

    helper_private_definitions = helper_definitions - {SEED_SYMBOL}
    for executable, definitions, imports, provider in zip(
            executables, executable_definitions, executable_imports, providers):
        copied = helper_private_definitions & definitions
        if copied or {SEED_SYMBOL, BEGIN_SYMBOL} & definitions:
            print(
                f"{executable} contains copied seed-helper definitions:",
                *sorted(copied | ({SEED_SYMBOL, BEGIN_SYMBOL} & definitions)),
                sep="\n  ",
                file=sys.stderr,
            )
            return 1
        missing_imports = missing_executable_imports(imports)
        if missing_imports:
            print(
                f"{executable} seed/provider imports missing:",
                *sorted(missing_imports),
                sep="\n  ",
                file=sys.stderr,
            )
            return 1
        if not provider_is_needed(provider, helper):
            print(
                f"{executable} has no runtime dependency on {helper.name}",
                file=sys.stderr,
            )
            return 1
        if not provider_is_needed(provider, library):
            print(
                f"{executable} has no runtime dependency on {library.name}",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Prove the daemon HTTP seed helper is an isolated runtime DSO boundary."""

import argparse
from contextlib import redirect_stderr
from io import StringIO
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
COMMON_EXECUTABLE_IMPORTS = {
    STORAGE_OPEN_SYMBOL,
    LOAD_SYMBOL,
    LOCK_ACQUIRE_SYMBOL,
    LOCK_RELEASE_SYMBOL,
}
MANDATORY_EXECUTABLE_NAMES = {
    "test-daemon-http-decide",
    "test-daemon-http-decide-refresh",
    "test-daemon-http-decide-service",
}
AUDIT_EXECUTABLE_NAME = "test-daemon-http-decide-audit"
ALL_EXECUTABLE_NAMES = MANDATORY_EXECUTABLE_NAMES | {
    AUDIT_EXECUTABLE_NAME,
}
SERVICE_EXECUTABLE_NAME = "test-daemon-http-decide-service"


class StoreOnce(argparse.Action):
    """Store a required option while rejecting repeated occurrences."""

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            raise argparse.ArgumentError(
                self,
                f"{option_string} must be specified exactly once",
            )
        setattr(namespace, self.dest, values)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--audit-mode",
        choices=("enabled", "disabled"),
        required=True,
        action=StoreOnce,
    )
    parser.add_argument("install_manifest", type=Path)
    parser.add_argument("helper", type=Path)
    parser.add_argument("header", type=Path)
    parser.add_argument("library", type=Path)
    parser.add_argument("executables", type=Path, nargs="+")
    return parser


def parse_artifact_arguments(argv: list[str]) -> argparse.Namespace:
    return argument_parser().parse_args(argv)


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
        for field in line.split():
            candidate = normalize_symbol(field, macho)
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


def missing_executable_imports(name: str, imports: set[str]) -> set[str]:
    required = set(COMMON_EXECUTABLE_IMPORTS)
    if name == SERVICE_EXECUTABLE_NAME:
        required.add(SEED_SYMBOL)
    return required - imports


def expected_executable_names(audit_mode: str) -> set[str]:
    expected = set(MANDATORY_EXECUTABLE_NAMES)
    if audit_mode == "enabled":
        expected.add(AUDIT_EXECUTABLE_NAME)
    return expected


def executable_names_are_exact(
        executables: list[Path],
        audit_mode: str) -> bool:
    names = [executable.name for executable in executables]
    expected = expected_executable_names(audit_mode)
    return (
        len(names) == len(expected)
        and set(names) == expected
    )


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


def imports_command(tool: str, artifact: Path, macho: bool) -> list[str]:
    return (
        [tool, "-imports", str(artifact)]
        if macho
        else [tool, "-u", str(artifact)]
    )


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


def imported_symbols(artifact: Path, macho: bool) -> set[str]:
    tool = (
        find_tool("dyld_info")
        if macho
        else find_tool("nm", "llvm-nm")
    )
    return wyl_symbols(
        run(imports_command(tool, artifact, macho)),
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


def missing_runtime_dependencies(name: str, output: str, helper: Path,
                                 library: Path) -> set[str]:
    missing = set()
    if not provider_is_needed(output, library):
        missing.add(library.name)
    if (
        name == SERVICE_EXECUTABLE_NAME
        and not provider_is_needed(output, helper)
    ):
        missing.add(helper.name)
    return missing


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
    macho_dyld_imports = """
0x0000000100001000 _wyl_test_daemon_http_seed_prepared_operation (from libtest-daemon-http-decide-seed-helper.dylib)
0x0000000100001010 _wyl_service_credential_operation_storage_open (from libwyrelog.0.dylib)
0x0000000100001020 _wyl_service_credential_operation_coordinator_load (from libwyrelog.0.dylib)
0x0000000100001030 _wyl_service_credential_operation_coordinator_lock_acquire (from libwyrelog.0.dylib)
0x0000000100001040 _wyl_service_credential_operation_coordinator_lock_release (from libwyrelog.0.dylib)
0x0000000100001050 __wyl_not_normalized (from libunintended.dylib)
0x0000000100001060 prefix_wyl_not_a_symbol (from libunintended.dylib)
"""
    service_imports = wyl_symbols(macho_dyld_imports, True)
    if service_imports != COMMON_EXECUTABLE_IMPORTS | {SEED_SYMBOL}:
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
    if missing_executable_imports(
            SERVICE_EXECUTABLE_NAME,
            COMMON_EXECUTABLE_IMPORTS) != {SEED_SYMBOL}:
        return 1
    if missing_executable_imports(
            "test-daemon-http-decide",
            COMMON_EXECUTABLE_IMPORTS):
        return 1
    missing_common_import = COMMON_EXECUTABLE_IMPORTS - {LOCK_RELEASE_SYMBOL}
    if missing_executable_imports(
            "test-daemon-http-decide-audit",
            missing_common_import) != {LOCK_RELEASE_SYMBOL}:
        return 1
    if missing_executable_imports(SERVICE_EXECUTABLE_NAME, service_imports):
        return 1
    executable_matrix = {
        audit_mode: [
            Path("/tmp") / name
            for name in sorted(expected_executable_names(audit_mode))
        ]
        for audit_mode in ("disabled", "enabled")
    }
    for audit_mode, executables in executable_matrix.items():
        if not executable_names_are_exact(executables, audit_mode):
            return 1
        for index in range(len(executables)):
            if executable_names_are_exact(
                    executables[:index] + executables[index + 1:],
                    audit_mode):
                return 1
            duplicate_replacement = (
                executables[:index]
                + [executables[(index + 1) % len(executables)]]
                + executables[index + 1:]
            )
            if executable_names_are_exact(duplicate_replacement, audit_mode):
                return 1
            unknown_replacement = (
                executables[:index]
                + [Path("/tmp/test-daemon-http-decide-unknown")]
                + executables[index + 1:]
            )
            if executable_names_are_exact(unknown_replacement, audit_mode):
                return 1
        for duplicate in executables:
            if executable_names_are_exact(
                    executables + [duplicate], audit_mode):
                return 1
        if executable_names_are_exact(
                executables + [Path("/tmp/test-daemon-http-decide-unknown")],
                audit_mode):
            return 1
    if executable_names_are_exact(
            executable_matrix["disabled"]
            + [Path("/tmp") / AUDIT_EXECUTABLE_NAME],
            "disabled"):
        return 1
    if executable_names_are_exact(
            [
                path for path in executable_matrix["enabled"]
                if path.name != AUDIT_EXECUTABLE_NAME
            ],
            "enabled"):
        return 1

    def artifact_argv(audit_mode: str) -> list[str]:
        return [
            "--audit-mode",
            audit_mode,
            "/tmp/intro-installed.json",
            "/tmp/libseed-helper.so",
            "/tmp/seed-helper.h",
            "/tmp/libwyrelog.so.0",
            *[str(path) for path in executable_matrix[audit_mode]],
        ]

    for audit_mode in ("disabled", "enabled"):
        parsed = parse_artifact_arguments(artifact_argv(audit_mode))
        if parsed.audit_mode != audit_mode:
            return 1
        if parsed.executables != executable_matrix[audit_mode]:
            return 1

    invalid_argument_sets = [
        artifact_argv("disabled")[2:],
        ["--audit-mode"],
        ["--audit-mode", "invalid", *artifact_argv("disabled")[2:]],
        ["--audit", "disabled", *artifact_argv("disabled")[2:]],
        [
            "--audit-mode",
            "disabled",
            "--audit-mode",
            "disabled",
            *artifact_argv("disabled")[2:],
        ],
        [
            "--audit-mode",
            "enabled",
            "--audit-mode",
            "disabled",
            *artifact_argv("disabled")[2:],
        ],
        ["--self-test", *artifact_argv("disabled")],
    ]
    for argv in invalid_argument_sets:
        with redirect_stderr(StringIO()):
            try:
                parse_artifact_arguments(argv)
            except SystemExit as error:
                if error.code != 2:
                    return 1
            else:
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
    if imports_command("nm", artifact, False) != [
            "nm", "-u", str(artifact)]:
        return 1
    if imports_command("dyld_info", artifact, True) != [
            "dyld_info", "-imports", str(artifact)]:
        return 1
    helper = Path("/tmp/libtest-daemon-http-decide-seed-helper.so")
    library = Path("/tmp/libwyrelog.so.0")
    if not provider_is_needed(
            " 0x0000000000000001 (NEEDED) Shared library: "
            "[libtest-daemon-http-decide-seed-helper.so]",
            helper):
        return 1
    if provider_is_needed("libwyrelog.so.0", helper):
        return 1
    if missing_runtime_dependencies(
            SERVICE_EXECUTABLE_NAME,
            library.name,
            helper,
            library) != {helper.name}:
        return 1
    if missing_runtime_dependencies(
            "test-daemon-http-decide",
            library.name,
            helper,
            library):
        return 1
    for name in ALL_EXECUTABLE_NAMES:
        if missing_runtime_dependencies(
                name,
                helper.name,
                helper,
                library) != {library.name}:
            return 1
    if missing_runtime_dependencies(
            SERVICE_EXECUTABLE_NAME,
            f"{helper.name}\n{library.name}",
            helper,
            library):
        return 1
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    arguments = parse_artifact_arguments(sys.argv[1:])
    manifest = arguments.install_manifest
    helper = arguments.helper
    header = arguments.header
    library = arguments.library
    executables = arguments.executables
    if not executable_names_are_exact(executables, arguments.audit_mode):
        print(
            "daemon HTTP executable basename set mismatch:",
            *sorted(executable.name for executable in executables),
            sep="\n  ",
            file=sys.stderr,
        )
        return 1
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
            imported_symbols(executable, macho) for executable in executables
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
        missing_imports = missing_executable_imports(executable.name, imports)
        if missing_imports:
            print(
                f"{executable} seed/provider imports missing:",
                *sorted(missing_imports),
                sep="\n  ",
                file=sys.stderr,
            )
            return 1
        missing_dependencies = missing_runtime_dependencies(
            executable.name,
            provider,
            helper,
            library,
        )
        if missing_dependencies:
            print(
                f"{executable} runtime dependencies missing:",
                *sorted(missing_dependencies),
                sep="\n  ",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

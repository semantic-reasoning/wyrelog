#!/usr/bin/env python3
"""Runtime proof that audit opens cannot use ambient DuckDB extensions."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile


# test-audit-conn-duckdb-hardening's positive control reports this failure
# code when the library refuses external extensions outright.  The process
# status is only a failure bit; the code travels in the WYRELOG_TEST_FAILURE
# diagnostic its main prints.  The source
# subproject is generated without the extension loader, so it must refuse;
# the prebuilt library ships one, so it must not.
NO_EXTENSION_LOADER = 31


FAILURE_CODE = re.compile(r"^WYRELOG_TEST_FAILURE .* code=(-?[0-9]+)$", re.M)


def failure_code(status: int, stderr: str) -> int:
    if status == 0:
        return 0
    codes = FAILURE_CODE.findall(stderr)
    if status != 1 or len(codes) != 1:
        raise RuntimeError(f"child failed without one failure code: {status}")
    return int(codes[0])


def expect_loader_posture(duckdb_source: str, status: int) -> None:
    refused = status == NO_EXTENSION_LOADER
    if duckdb_source == "subproject" and not refused:
        raise RuntimeError(
            f"source-built DuckDB did not refuse external extensions: {status}")
    if duckdb_source == "prebuilt" and refused:
        raise RuntimeError("prebuilt DuckDB lost its extension loader")


def create_sqlite(path: Path) -> None:
    database = sqlite3.connect(path)
    try:
        database.execute("CREATE TABLE foreign_table(value TEXT)")
        database.execute("INSERT INTO foreign_table VALUES('sqlite')")
        database.commit()
    finally:
        database.close()


def isolated_environment(home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                 "LOCALAPPDATA", "APPDATA"):
        environment[name] = str(home)
    environment.pop("DUCKDB_EXTENSION_DIRECTORY", None)
    return environment


def tree_snapshot(root: Path) -> list[tuple[str, str, str]]:
    if not root.exists():
        return []
    entries: list[tuple[str, str, str]] = []

    def visit(directory: Path) -> None:
        with os.scandir(directory) as children:
            for child in children:
                path = Path(child.path)
                relative = path.relative_to(root).as_posix()
                if child.is_symlink():
                    entries.append((relative, "symlink", os.readlink(path)))
                elif child.is_dir(follow_symlinks=False):
                    entries.append((relative, "directory", ""))
                    visit(path)
                elif child.is_file(follow_symlinks=False):
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    entries.append((relative, "file", digest))
                else:
                    entries.append((relative, "other", ""))

    visit(root)
    return sorted(entries)


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_hardened_trace(evidence: str, extension_root: Path) -> None:
    forbidden = (str(extension_root), "AF_INET", "AF_INET6")
    found = [token for token in forbidden if token in evidence]
    if found:
        raise RuntimeError(f"hardened probe used forbidden resources: {found}")


def validate_no_network(evidence: str, probe: str) -> None:
    found = [token for token in ("AF_INET", "AF_INET6") if token in evidence]
    if found:
        raise RuntimeError(f"{probe} used forbidden network: {found}")


def validate_positive_trace(evidence: str, staged: Path) -> None:
    successful_open = re.compile(
        rf'\bopen(?:at|at2)?\([^\n]*"{re.escape(str(staged))}"[^\n]*'
        r'\)\s*=\s*[0-9]+'
    )
    if successful_open.search(evidence) is None:
        raise RuntimeError("positive control did not open the exact staged scanner")
    found = [token for token in ("AF_INET", "AF_INET6") if token in evidence]
    if found:
        raise RuntimeError(f"positive control used forbidden network: {found}")


def trace_parser_self_test() -> None:
    extension_root = Path("/tmp/home/.duckdb/extensions")
    validate_hardened_trace(
        'openat(AT_FDCWD, "/tmp/catalog.sqlite", O_RDONLY) = 3\n',
        extension_root,
    )
    for mutation in (
        f'stat("{extension_root}/v1/linux/scanner", ...) = 0',
        f'mkdir("{extension_root}/v1", 0755) = 0',
        f'openat(AT_FDCWD, "{extension_root}/tmp.download", O_WRONLY) = 4',
        f'rename("/tmp/x", "{extension_root}/scanner") = 0',
        "connect(3, {sa_family=AF_INET}, 16) = 0",
        "connect(3, {sa_family=AF_INET6}, 28) = 0",
    ):
        try:
            validate_hardened_trace(mutation, extension_root)
        except RuntimeError:
            continue
        raise RuntimeError(f"hardened trace mutation survived: {mutation}")

    for source, status, accepted in (
            ("subproject", NO_EXTENSION_LOADER, True),
            ("subproject", 0, False),
            ("subproject", 30, False),
            ("prebuilt", 0, True),
            ("prebuilt", 30, True),
            ("prebuilt", NO_EXTENSION_LOADER, False)):
        try:
            expect_loader_posture(source, status)
        except RuntimeError:
            if accepted:
                raise RuntimeError(
                    f"loader posture rejected {source} status {status}")
            continue
        if not accepted:
            raise RuntimeError(
                f"loader posture accepted {source} status {status}")

    diagnostic = ("WYRELOG_TEST_FAILURE file=t.c function=main line=1 "
                  f"code={NO_EXTENSION_LOADER}\n")
    if (failure_code(0, "") != 0
            or failure_code(1, diagnostic) != NO_EXTENSION_LOADER):
        raise RuntimeError("failure code parser misread a diagnostic")
    for status, stderr in ((1, ""), (2, diagnostic), (1, diagnostic * 2)):
        try:
            failure_code(status, stderr)
        except RuntimeError:
            continue
        raise RuntimeError(f"failure code parser accepted {status} {stderr!r}")
    validate_no_network('openat(AT_FDCWD, "/tmp/x", O_RDONLY) = 3', "self")
    for mutation in ("connect(3, {sa_family=AF_INET}, 16) = 0",
                     "connect(3, {sa_family=AF_INET6}, 28) = 0"):
        try:
            validate_no_network(mutation, "self")
        except RuntimeError:
            continue
        raise RuntimeError(f"network trace mutation survived: {mutation}")

    staged = extension_root / "v1/linux/sqlite_scanner.duckdb_extension"
    validate_positive_trace(
        f'openat(AT_FDCWD, "{staged}", O_RDONLY) = 3', staged,
    )
    for mutation in (
        'openat(AT_FDCWD, "/tmp/other", O_RDONLY) = 3',
        f'newfstatat(AT_FDCWD, "{staged}", 0) = 0',
        f'openat(AT_FDCWD, "{staged}", O_RDONLY) = -1 EACCES',
        f'openat(AT_FDCWD, "/tmp/other/{staged.name}", O_RDONLY) = 3',
        f'openat(AT_FDCWD, "{staged}", O_RDONLY) = 3\n'
        "connect(3, {sa_family=AF_INET}, 16) = 0",
        f'openat(AT_FDCWD, "{staged}", O_RDONLY) = 3\n'
        "connect(3, {sa_family=AF_INET6}, 28) = 0",
    ):
        try:
            validate_positive_trace(mutation, staged)
        except RuntimeError:
            continue
        raise RuntimeError(f"positive trace mutation survived: {mutation}")

    with tempfile.TemporaryDirectory(prefix="wyl-audit-runtime-self-") as raw:
        root = Path(raw)
        before = tree_snapshot(root)
        marker = root / "marker"
        marker.write_text("one\n", encoding="utf-8")
        after_create = tree_snapshot(root)
        if before == after_create:
            raise RuntimeError("tree snapshot missed file creation")
        marker.write_text("two\n", encoding="utf-8")
        if after_create == tree_snapshot(root):
            raise RuntimeError("tree snapshot missed content mutation")


def extension_version(source: Path) -> str:
    parts = source.parts
    try:
        index = parts.index("extensions")
        return parts[index + 1]
    except (ValueError, IndexError) as error:
        raise RuntimeError("scanner path must include extensions/VERSION") from error


def discover_scanner(explicit: Path | None, version: str) -> Path | None:
    if explicit is not None:
        candidate = explicit.resolve()
        if extension_version(candidate) != version:
            raise RuntimeError("explicit scanner version does not match DuckDB")
        return candidate
    configured = os.environ.get("WYL_TEST_DUCKDB_SQLITE_SCANNER")
    if configured:
        candidate = Path(configured).resolve()
        if extension_version(candidate) != version:
            raise RuntimeError("configured scanner version does not match DuckDB")
        return candidate
    candidates = sorted(
        Path.home().glob(
            f".duckdb/extensions/{version}/*/sqlite_scanner.duckdb_extension"
        ),
        reverse=True,
    )
    return candidates[0].resolve() if candidates else None


def stage_extension(source: Path, home: Path) -> Path:
    parts = source.parts
    try:
        index = parts.index(".duckdb")
    except ValueError as error:
        raise RuntimeError("scanner path must be below .duckdb") from error
    relative = Path(*parts[index + 1 :])
    destination = home / ".duckdb" / relative
    destination.parent.mkdir(parents=True)
    for candidate in source.parent.glob(source.name + "*"):
        shutil.copy2(candidate, destination.parent / candidate.name)
    return destination


def run_child(executable: Path, mode: str, catalog: Path,
              environment: dict[str, str], trace: Path,
              codes: tuple[int, ...] = (0,)) -> tuple[int, str]:
    command = [str(executable), mode, str(catalog)]
    tracer = shutil.which("strace") if sys.platform.startswith("linux") else None
    if sys.platform.startswith("linux") and tracer is None:
        raise RuntimeError("Linux hardening evidence requires strace")
    if tracer is not None:
        command = [tracer, "-f", "-e", "trace=file,network", "-o",
                   str(trace), *command]
    completed = subprocess.run(command, check=False, env=environment,
                               stderr=subprocess.PIPE, text=True,
                               encoding="utf-8", errors="replace")
    sys.stderr.write(completed.stderr)
    code = failure_code(completed.returncode, completed.stderr)
    if code not in codes:
        raise subprocess.CalledProcessError(completed.returncode, command)
    if tracer is None:
        return code, ""
    return code, trace.read_text(encoding="utf-8", errors="strict")


def run_clean(executable: Path, duckdb_source: str) -> None:
    with tempfile.TemporaryDirectory(prefix="wyl-audit-autoload-clean-") as raw:
        root = Path(raw)
        home = root / "home"
        home.mkdir()
        catalog = root / "foreign.sqlite"
        create_sqlite(catalog)
        before_home = tree_snapshot(home)
        before_catalog = file_digest(catalog)
        _, evidence = run_child(
            executable, "--foreign-sqlite", catalog,
            isolated_environment(home), root / "hardened.strace",
        )
        validate_hardened_trace(evidence, home / ".duckdb" / "extensions")
        if tree_snapshot(home) != before_home:
            raise RuntimeError("clean-home probe created or changed user state")
        if file_digest(catalog) != before_catalog:
            raise RuntimeError("hardened probe changed the foreign catalog")

        # No scanner is staged, so the prebuilt positive control fails to
        # find one; the source build must fail earlier, for want of a loader.
        positive_home = root / "positive-home"
        positive_home.mkdir()
        status, positive = run_child(
            executable, "--raw-sqlite-positive", catalog,
            isolated_environment(positive_home), root / "positive.strace",
            (30, NO_EXTENSION_LOADER),
        )
        expect_loader_posture(duckdb_source, status)
        validate_no_network(positive, "positive control")


def run_ambient(executable: Path, explicit: Path | None,
                duckdb_source: str) -> int:
    version = subprocess.run(
        [str(executable), "--duckdb-library-version"], check=True,
        capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    if not version:
        raise RuntimeError("DuckDB library version is empty")
    source = discover_scanner(explicit, version)
    if source is None:
        print(f"SKIP: no exact {version} sqlite_scanner is available")
        return 77
    if not source.is_file():
        raise RuntimeError(f"ambient scanner does not exist: {source}")

    with tempfile.TemporaryDirectory(prefix="wyl-audit-autoload-ambient-") as raw:
        root = Path(raw)
        home = root / "home"
        home.mkdir()
        catalog = root / "foreign.sqlite"
        create_sqlite(catalog)
        staged = stage_extension(source, home)
        if not staged.is_file():
            raise RuntimeError("ambient scanner was not staged")
        before_home = tree_snapshot(home)
        before_catalog = file_digest(catalog)
        environment = isolated_environment(home)

        status, positive = run_child(
            executable, "--raw-sqlite-positive", catalog, environment,
            root / "positive.strace", (0, NO_EXTENSION_LOADER),
        )
        expect_loader_posture(duckdb_source, status)
        if status == 0:
            validate_positive_trace(positive, staged)
        else:
            # A library without a loader must not even read the scanner.
            validate_hardened_trace(positive, home / ".duckdb" / "extensions")
        if tree_snapshot(home) != before_home or file_digest(catalog) != before_catalog:
            raise RuntimeError("positive control changed its fixtures")

        _, hardened = run_child(
            executable, "--foreign-sqlite", catalog, environment,
            root / "hardened.strace",
        )
        validate_hardened_trace(
            hardened, home / ".duckdb" / "extensions",
        )
        if tree_snapshot(home) != before_home or file_digest(catalog) != before_catalog:
            raise RuntimeError("hardened ambient probe changed its fixtures")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("clean", "ambient"))
    parser.add_argument("--ambient-extension", type=Path)
    parser.add_argument("--duckdb-source", choices=("prebuilt", "subproject"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("executable", type=Path, nargs="?")
    arguments = parser.parse_args()
    if arguments.self_test:
        trace_parser_self_test()
        return 0
    if (arguments.mode is None or arguments.executable is None
            or arguments.duckdb_source is None):
        parser.error("--mode, --duckdb-source and executable are required "
                     "outside --self-test")
    executable = arguments.executable.resolve()
    if arguments.mode == "clean":
        run_clean(executable, arguments.duckdb_source)
        return 0
    return run_ambient(executable, arguments.ambient_extension,
                       arguments.duckdb_source)


if __name__ == "__main__":
    raise SystemExit(main())

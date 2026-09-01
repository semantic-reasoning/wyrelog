#!/usr/bin/env python3
"""Runtime proof that fact-store opens cannot use ambient DuckDB extensions."""

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


def create_sqlite(path: Path) -> None:
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE foreign_table(value TEXT)")
        database.execute("INSERT INTO foreign_table VALUES('sqlite')")


def clean_environment(home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    environment["USERPROFILE"] = str(home)
    environment.pop("DUCKDB_EXTENSION_DIRECTORY", None)
    return environment


def stage_extension(source: Path, home: Path) -> Path:
    parts = source.parts
    try:
        duckdb_index = parts.index(".duckdb")
    except ValueError as error:
        raise RuntimeError("ambient extension path must be below .duckdb") from error
    relative = Path(*parts[duckdb_index + 1 :])
    destination = home / ".duckdb" / relative
    destination.parent.mkdir(parents=True)
    for candidate in source.parent.glob(source.name + "*"):
        shutil.copy2(candidate, destination.parent / candidate.name)
    return destination


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


def validate_trace(evidence: str) -> None:
    forbidden = (".duckdb/extensions", "AF_INET", "AF_INET6")
    found = [token for token in forbidden if token in evidence]
    if found:
        raise RuntimeError(f"hardened probe used forbidden resources: {found}")


def validate_positive_trace(evidence: str, staged: Path) -> None:
    successful_open = re.compile(
        rf'\bopen(?:at|at2)?\([^\n]*"{re.escape(str(staged))}"[^\n]*'
        r'\)\s*=\s*[0-9]+'
    )
    if successful_open.search(evidence) is None:
        raise RuntimeError("positive control did not successfully open the staged scanner")
    found = [token for token in ("AF_INET", "AF_INET6") if token in evidence]
    if found:
        raise RuntimeError(f"positive control used forbidden network: {found}")


def trace_parser_self_test() -> None:
    validate_trace('openat(AT_FDCWD, "/tmp/catalog.sqlite", O_RDONLY) = 3\n')
    mutations = (
        'stat("/tmp/home/.duckdb/extensions/v1/linux/scanner", ...) = 0',
        'mkdir("/tmp/home/.duckdb/extensions/v1", 0755) = 0',
        'openat(AT_FDCWD, "/tmp/home/.duckdb/extensions/tmp.download", O_WRONLY)',
        'rename("/tmp/x", "/tmp/home/.duckdb/extensions/scanner") = 0',
        'openat(AT_FDCWD, "/tmp/home/.duckdb/extensions/scanner", O_RDONLY)',
        'connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0',
        'connect(3, {sa_family=AF_INET6, sin6_port=htons(443)}, 28) = 0',
    )
    for mutation in mutations:
        try:
            validate_trace(mutation)
        except RuntimeError:
            continue
        raise RuntimeError(f"trace mutation survived: {mutation}")
    staged = Path("/tmp/home/.duckdb/extensions/v1/linux/scanner")
    validate_positive_trace(f'openat(AT_FDCWD, "{staged}", O_RDONLY) = 3', staged)
    for mutation in ("openat(AT_FDCWD, \"/tmp/other\", O_RDONLY) = 3",
                     f'newfstatat(AT_FDCWD, "{staged}", 0) = 0',
                     f'openat(AT_FDCWD, "{staged}", O_RDONLY) = -1 EACCES',
                     f'openat(AT_FDCWD, "/tmp/other/{staged.name}", O_RDONLY) = 3',
                     f'openat(AT_FDCWD, "{staged}", O_RDONLY) = 3\n'
                     "connect(3, {sa_family=AF_INET}, 16) = 0"):
        try:
            validate_positive_trace(mutation, staged)
        except RuntimeError:
            continue
        raise RuntimeError(f"positive trace mutation survived: {mutation}")


def extension_version(source: Path) -> str:
    parts = source.parts
    try:
        extension_index = parts.index("extensions")
        return parts[extension_index + 1]
    except (ValueError, IndexError) as error:
        raise RuntimeError("scanner path must include extensions/VERSION") from error


def discover_ambient_extension(explicit: Path | None,
                               version: str) -> Path | None:
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


def run_hardened_probe(executable: Path, catalog: Path,
                       environment: dict[str, str], trace: Path) -> None:
    command = [str(executable), "--foreign-sqlite", str(catalog)]
    strace = shutil.which("strace") if sys.platform.startswith("linux") else None
    if sys.platform.startswith("linux") and strace is None:
        raise RuntimeError("Linux hardening evidence requires strace")
    if strace is not None:
        command = [strace, "-f", "-e", "trace=file,network", "-o", str(trace),
                   *command]
    subprocess.run(command, check=True, env=environment)
    if strace is None:
        return
    evidence = trace.read_text(encoding="utf-8", errors="strict")
    validate_trace(evidence)


def run_positive_control(executable: Path, catalog: Path,
                         environment: dict[str, str], trace: Path,
                         staged: Path) -> None:
    command = [str(executable), "--raw-sqlite-positive", str(catalog)]
    strace = shutil.which("strace") if sys.platform.startswith("linux") else None
    if sys.platform.startswith("linux") and strace is None:
        raise RuntimeError("Linux positive-control evidence requires strace")
    if strace is not None:
        command = [strace, "-f", "-e", "trace=file,network", "-o", str(trace),
                   *command]
    subprocess.run(command, check=True, env=environment)
    if strace is not None:
        evidence = trace.read_text(encoding="utf-8", errors="strict")
        validate_positive_trace(evidence, staged)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path, nargs="?")
    parser.add_argument("--ambient-extension", type=Path)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        trace_parser_self_test()
        return 0
    if arguments.executable is None:
        parser.error("executable is required outside --self-test")
    version = subprocess.run(
        [str(arguments.executable), "--duckdb-library-version"],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    if not version:
        raise RuntimeError("DuckDB library version is empty")
    ambient_extension = discover_ambient_extension(
        arguments.ambient_extension, version)

    with tempfile.TemporaryDirectory(prefix="wyl-duckdb-autoload-") as raw_dir:
        root = Path(raw_dir)
        home = root / "home"
        home.mkdir()
        catalog = root / "foreign.sqlite"
        trace = root / "hardened.strace"
        create_sqlite(catalog)
        environment = clean_environment(home)

        extension_root = home / ".duckdb" / "extensions"
        sentinel = extension_root / "sentinel" / "trace-visible.invalid"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text("must-not-be-observed\n", encoding="utf-8")
        before = tree_snapshot(extension_root)
        run_hardened_probe(arguments.executable, catalog, environment, trace)
        if tree_snapshot(extension_root) != before:
            raise RuntimeError("clean-home probe created DuckDB extension artifacts")

        if ambient_extension is not None:
            source = ambient_extension
            if not source.is_file():
                raise RuntimeError(f"ambient extension does not exist: {source}")
            staged = stage_extension(source, home)
            before = tree_snapshot(extension_root)
            if not staged.is_file():
                raise RuntimeError("ambient positive-control extension was not staged")
            run_positive_control(
                arguments.executable, catalog, environment,
                root / "positive.strace", staged,
            )
            if tree_snapshot(extension_root) != before:
                raise RuntimeError("positive control modified extension artifacts")
            run_hardened_probe(arguments.executable, catalog, environment, trace)
            if tree_snapshot(extension_root) != before:
                raise RuntimeError("ambient probe modified DuckDB extension artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

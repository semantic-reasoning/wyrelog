#!/usr/bin/env python3
"""Verify the supported Linux product install manifest and ELF closure."""

from __future__ import annotations

import argparse
import configparser
import ctypes
import fnmatch
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "packaging/linux-product-install.json"


class InstallTreeError(Exception):
    pass


def parse_needed(readelf_output: str) -> set[str]:
    return set(re.findall(r"Shared library: \[([^]]+)\]", readelf_output))


def parse_soname(readelf_output: str) -> str | None:
    match = re.search(r"Library soname: \[([^]]+)\]", readelf_output)
    return match.group(1) if match else None


def allowed_path(path: str, patterns: list[str]) -> bool:
    path_parts = path.split("/")
    return any(
        len(path_parts) == len(pattern_parts)
        and all(
            fnmatch.fnmatchcase(path_part, pattern_part)
            for path_part, pattern_part in zip(path_parts, pattern_parts)
        )
        for pattern_parts in (pattern.split("/") for pattern in patterns)
    )


def library_version(path: Path, function_name: str) -> str:
    library = ctypes.CDLL(str(path))
    version_function = getattr(library, function_name)
    version_function.argtypes = []
    version_function.restype = ctypes.c_char_p
    version = version_function()
    if version is None:
        raise ValueError(f"{function_name} returned no version")
    return version.decode("utf-8")


def check_symlink(root: Path, link: Path) -> None:
    try:
        resolved = link.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InstallTreeError(f"broken or cyclic symlink: {link}: {exc}") from exc
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise InstallTreeError(f"symlink escapes install tree: {link} -> {resolved}") from exc


def check_install_paths(root: Path, manifest: dict) -> list[str]:
    errors: list[str] = []
    if root.is_symlink():
        return [f"install prefix root must not be a symlink: {root}"]
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return [f"install prefix root cannot be resolved: {root}: {exc}"]
    if not resolved_root.is_dir():
        return [f"install prefix root is not a directory: {root}"]
    paths = sorted(root.rglob("*"))
    for path in paths:
        if path.is_symlink():
            try:
                check_symlink(root, path)
            except InstallTreeError as exc:
                errors.append(str(exc))
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if not allowed_path(relative, manifest["allowed_paths"]):
            errors.append(f"path outside product manifest: {relative}")

    for required in manifest["required_paths"]:
        if not (root / required).exists():
            errors.append(f"required product path is missing: {required}")

    for library in manifest["required_staged_libraries"]:
        if not any(path.name == library for path in paths):
            errors.append(f"required runtime library is missing from stage: {library}")
    return errors


def check_elf_closure(root: Path, manifest: dict) -> tuple[list[str], set[str]]:
    errors: list[str] = []
    external_seen: set[str] = set()
    library_dir = root / "lib"
    staged_libraries = {
        path.name: path
        for path in library_dir.iterdir()
        if path.is_file() or path.is_symlink()
    } if library_dir.is_dir() else {}
    allowed_system = set(manifest["system_libraries"])
    external = set(manifest["external_libraries"])

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as installed_file:
                is_elf = installed_file.read(4) == b"\x7fELF"
            if not is_elf:
                continue
            result = subprocess.run(
                ["readelf", "-d", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            errors.append(f"cannot inspect ELF {path}: {exc}")
            continue
        if result.returncode != 0:
            errors.append(f"readelf failed for {path}: {result.stderr.strip()}")
            continue
        relative = path.relative_to(root).as_posix()
        for needed in sorted(parse_needed(result.stdout)):
            if needed in staged_libraries:
                resolved_library = staged_libraries[needed].resolve()
                soname_result = subprocess.run(
                    ["readelf", "-d", str(resolved_library)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if soname_result.returncode != 0:
                    errors.append(
                        f"{relative}: staged NEEDED {needed} is not readable as ELF"
                    )
                    continue
                soname = parse_soname(soname_result.stdout)
                if soname is not None and soname != needed:
                    errors.append(
                        f"{relative}: NEEDED {needed} resolves to {resolved_library.name} "
                        f"with SONAME {soname}"
                    )
                continue
            if needed in external:
                external_seen.add(needed)
                continue
            if needed in allowed_system:
                continue
            errors.append(f"{relative}: unresolved, undeclared NEEDED {needed}")

    for name in external - external_seen:
        errors.append(f"declared external runtime library is not referenced: {name}")
    return errors, external_seen


def build_options(builddir: Path) -> dict[str, object]:
    result = subprocess.run(
        ["meson", "introspect", "--buildoptions", str(builddir)],
        check=True,
        capture_output=True,
        text=True,
    )
    return {item["name"]: item["value"] for item in json.loads(result.stdout)}


def check_build_provenance(builddir: Path, manifest: dict) -> list[str]:
    errors: list[str] = []
    options = build_options(builddir)
    for name, expected in manifest["profile"].items():
        actual = options.get(name)
        if isinstance(expected, list):
            actual = sorted(actual or [])
            expected = sorted(expected)
        if actual != expected:
            errors.append(f"Meson option {name}: expected {expected!r}, got {actual!r}")

    result = subprocess.run(
        ["meson", "introspect", "--projectinfo", str(builddir)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprojects = {
        item["name"]: item["version"]
        for item in json.loads(result.stdout).get("subprojects", [])
    }
    for name, expected in manifest["subprojects"].items():
        actual = subprojects.get(name)
        if actual != expected:
            errors.append(f"subproject {name}: expected {expected}, got {actual}")
    duckdb_external = manifest["external_libraries"].get("libduckdb.so", {})
    if duckdb_external.get("version") != subprojects.get("duckdb-prebuilt-linux"):
        errors.append(
            "external libduckdb.so version must match the selected pinned "
            "duckdb-prebuilt-linux subproject version"
        )
    duckdb_artifact = duckdb_external.get("build_artifact")
    if not isinstance(duckdb_artifact, str):
        errors.append("external libduckdb.so must declare its pinned build artifact")
    else:
        artifact_path = ROOT / duckdb_artifact
        try:
            artifact_path.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
            actual_duckdb_version = library_version(
                artifact_path, "duckdb_library_version"
            ).removeprefix("v")
        except (OSError, RuntimeError, ValueError, AttributeError, UnicodeError) as exc:
            errors.append(f"cannot verify pinned DuckDB runtime artifact: {exc}")
        else:
            if actual_duckdb_version != duckdb_external.get("version"):
                errors.append(
                    "pinned DuckDB runtime artifact version: expected "
                    f"{duckdb_external.get('version')}, got {actual_duckdb_version}"
                )

    wraps = {
        "duckdb-prebuilt-linux.wrap": "source_hash",
        "wirelog.wrap": "revision",
        "libchronoid.wrap": "revision",
    }
    for filename, field in wraps.items():
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(ROOT / "subprojects" / filename)
            actual = parser["wrap-file" if field == "source_hash" else "wrap-git"][field]
        except (OSError, KeyError) as exc:
            errors.append(f"cannot read pinned provider from {filename}: {exc}")
            continue
        expected = manifest["duckdb_wrap_sha256"] if field == "source_hash" else manifest[
            "wrap_revisions"
        ][filename]
        if actual != expected:
            errors.append(f"{filename} {field}: expected {expected}, got {actual}")

    nested = {
        "nanoarrow.wrap": "revision",
        "xxhash.wrap": "source_hash",
    }
    wirelog_dir = ROOT / "subprojects/wirelog"
    for filename, field in nested.items():
        parser = configparser.ConfigParser(interpolation=None)
        path = wirelog_dir / "subprojects" / filename
        try:
            parser.read(path)
            actual = parser["wrap-git" if field == "revision" else "wrap-file"][field]
        except (OSError, KeyError) as exc:
            errors.append(f"cannot read nested provider pin from {path}: {exc}")
            continue
        expected = manifest["nested_wrap_pins"][filename]
        if actual != expected:
            errors.append(f"{filename} {field}: expected {expected}, got {actual}")

    return errors


def verify(destdir: Path, prefix: str, builddir: Path, manifest_path: Path) -> list[str]:
    if not prefix.startswith("/") or ".." in Path(prefix).parts:
        return [f"prefix must be an absolute path without traversal: {prefix}"]
    if destdir.is_symlink() or not destdir.is_dir():
        return [f"DESTDIR must be an existing real directory: {destdir}"]
    root = destdir / prefix.lstrip("/")
    if not root.is_dir():
        return [f"install prefix does not exist in DESTDIR: {root}"]
    try:
        root.resolve(strict=True).relative_to(destdir.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        return [f"install prefix escapes DESTDIR: {root}: {exc}"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = check_build_provenance(builddir, manifest)
    errors.extend(check_install_paths(root, manifest))
    closure_errors, _ = check_elf_closure(root, manifest)
    errors.extend(closure_errors)
    return errors


def self_test() -> None:
    manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    assert {"libsodium.so.23", "libsodium.so.26"} <= set(
        manifest["system_libraries"]
    )
    assert parse_needed("Shared library: [liba.so]\nShared library: [libb.so]\n") == {
        "liba.so", "libb.so"
    }
    assert parse_soname("Library soname: [liba.so.1]\n") == "liba.so.1"
    assert allowed_path("bin/wyrelogd", ["bin/wyrelogd"])
    assert allowed_path("etc/wyrelog/wyrelogd.env", ["etc/wyrelog/*.env"])
    assert not allowed_path("bin/xxhsum", ["bin/wyrelogd"])
    assert not allowed_path(
        "etc/wyrelog/nested/rogue.env", ["etc/wyrelog/*.env"]
    )
    assert not allowed_path(
        "lib/systemd/system/nested/rogue.service",
        ["lib/systemd/system/*.service"],
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "root"
        outside = Path(temporary) / "outside"
        (root / "bin").mkdir(parents=True)
        (root / "bin/wyrelogd").touch()
        (root / "bin/xxhsum").touch()
        outside.write_text("not installed", encoding="utf-8")
        (root / "escape").symlink_to(outside)
        errors = check_install_paths(
            root,
            {
                "allowed_paths": ["bin/wyrelogd"],
                "required_paths": ["bin/wyrelogd"],
                "required_staged_libraries": [],
            },
        )
        assert any("bin/xxhsum" in error for error in errors)
        try:
            check_symlink(root, root / "escape")
        except InstallTreeError:
            pass
        else:
            raise AssertionError("escaping symlink was not rejected")
        linked_root = Path(temporary) / "linked-root"
        linked_root.symlink_to(root, target_is_directory=True)
        errors = check_install_paths(
            linked_root,
            {"allowed_paths": ["bin/wyrelogd"], "required_paths": [], "required_staged_libraries": []},
        )
        assert any("must not be a symlink" in error for error in errors)

        destdir = Path(temporary) / "destdir"
        destdir.mkdir()
        (destdir / "usr").symlink_to(outside.parent, target_is_directory=True)
        errors = verify(destdir, "/usr", Path(temporary), DEFAULT_MANIFEST)
        assert any("escapes DESTDIR" in error for error in errors)


def check_profile(builddir: Path, manifest_path: Path) -> list[str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return check_build_provenance(builddir, manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destdir", type=Path)
    parser.add_argument("--prefix", default="/usr")
    parser.add_argument("--builddir", type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--profile-only", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.builddir is None:
        parser.error("--builddir is required")
    if args.profile_only:
        errors = check_profile(args.builddir, args.manifest)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        print("product install build profile and dependency pins verified")
        return 0
    if args.destdir is None:
        parser.error("--destdir and --builddir are required unless --self-test is used")
    errors = verify(args.destdir, args.prefix, args.builddir, args.manifest)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("product install manifest, runtime dependency closure, and pinned profile verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

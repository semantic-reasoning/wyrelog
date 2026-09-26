#!/usr/bin/env python3
"""Create and verify the Linux runtime package tree in an empty DESTDIR."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "packaging/linux-product-install.json"
CHECKER = ROOT / "tools/check-product-install-tree.py"


def validated_prefix_root(destdir: Path, prefix: str) -> Path:
    resolved_destdir = destdir.resolve(strict=True)
    relative_prefix = tuple(part for part in prefix.lstrip("/").split("/") if part)
    prefix_root = resolved_destdir
    for part in relative_prefix:
        prefix_root = prefix_root / part
        if prefix_root.is_symlink():
            raise ValueError(f"refusing symlink in staged prefix path: {prefix_root}")
    try:
        prefix_root.resolve(strict=True).relative_to(resolved_destdir)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"staged prefix escapes DESTDIR: {prefix_root}") from exc
    if not prefix_root.is_dir():
        raise ValueError(f"install did not create prefix tree: {prefix_root}")
    return prefix_root


def prune_development_files(prefix_root: Path, patterns: list[str]) -> list[str]:
    if prefix_root.is_symlink():
        raise ValueError(f"refusing symlinked install prefix: {prefix_root}")
    resolved_root = prefix_root.resolve(strict=True)
    removed: set[Path] = set()
    for pattern in patterns:
        if pattern.endswith("/**"):
            recursive_root = prefix_root / pattern[:-3].rstrip("/")
            matches = {recursive_root}
            if recursive_root.is_dir() and not recursive_root.is_symlink():
                matches.update(recursive_root.rglob("*"))
        else:
            matches = set(prefix_root.glob(pattern))
        for candidate in matches:
            if candidate == prefix_root or prefix_root not in candidate.parents:
                raise ValueError(f"refusing prune path outside install prefix: {candidate}")
            relative = candidate.relative_to(prefix_root)
            ancestor = prefix_root
            for part in relative.parts[:-1]:
                ancestor = ancestor / part
                if ancestor.is_symlink():
                    raise ValueError(f"refusing prune through symlinked directory: {ancestor}")
            try:
                candidate.resolve(strict=False).relative_to(resolved_root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError(f"refusing prune outside install prefix: {candidate}") from exc
            removed.add(candidate)

    removed_paths: list[str] = []
    for candidate in sorted(removed, key=lambda path: (len(path.parts), path.as_posix()), reverse=True):
        if not candidate.exists() and not candidate.is_symlink():
            continue
        if candidate.is_dir() and not candidate.is_symlink():
            candidate.rmdir()
        else:
            candidate.unlink()
        removed_paths.append(candidate.relative_to(prefix_root).as_posix())
    return removed_paths


def stage(builddir: Path, destdir: Path, prefix: str, manifest_path: Path) -> int:
    if destdir.is_symlink() or not destdir.is_dir():
        print(f"ERROR: DESTDIR must be an existing real directory: {destdir}", file=sys.stderr)
        return 2
    if any(destdir.iterdir()):
        print(f"ERROR: DESTDIR must be empty before staging: {destdir}", file=sys.stderr)
        return 2
    if not prefix.startswith("/") or ".." in Path(prefix).parts:
        print(f"ERROR: prefix must be absolute and traversal-free: {prefix}", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profile_check = subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            "--profile-only",
            "--builddir",
            str(builddir),
            "--manifest",
            str(manifest_path),
        ],
        check=False,
    )
    if profile_check.returncode != 0:
        return profile_check.returncode
    compiled = subprocess.run(
        [
            "meson",
            "compile",
            "-C",
            str(builddir),
            "wyrelog/wyrelogd",
            "wyrelog/wyctl",
            "wirelog_cli",
            "xxhsum",
            "subprojects/libchronoid/chronoid:static_library",
        ],
        check=False,
    )
    if compiled.returncode != 0:
        return compiled.returncode
    installed = subprocess.run(
        ["meson", "install", "-C", str(builddir), "--no-rebuild", "--destdir", str(destdir)],
        check=False,
    )
    if installed.returncode != 0:
        return installed.returncode

    try:
        prefix_root = validated_prefix_root(destdir, prefix)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: unsafe or missing install prefix: {exc}", file=sys.stderr)
        return 1
    for relative in prune_development_files(prefix_root, manifest["prune_paths"]):
        print(f"Pruned developer-only install artifact: {relative}")

    return subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            "--destdir",
            str(destdir),
            "--prefix",
            prefix,
            "--builddir",
            str(builddir),
            "--manifest",
            str(manifest_path),
        ],
        check=False,
    ).returncode


def self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "usr"
        (root / "bin").mkdir(parents=True)
        (root / "bin/wirelog_cli").write_text("dev", encoding="utf-8")
        (root / "bin/wyrelogd").write_text("product", encoding="utf-8")
        (root / "lib/libwirelog.so.1").parent.mkdir(parents=True)
        (root / "lib/libwirelog.so.1").write_text("runtime", encoding="utf-8")
        (root / "include/wirelog/wirelog.h").parent.mkdir(parents=True)
        (root / "include/wirelog/wirelog.h").write_text("dev", encoding="utf-8")
        (root / "include/wirelog/io/io_adapter.h").parent.mkdir(parents=True)
        (root / "include/wirelog/io/io_adapter.h").write_text("dev", encoding="utf-8")
        removed = prune_development_files(
            root,
            ["bin/wirelog_cli", "include/**", "lib/*.a", "lib/pkgconfig/**"],
        )
        assert "bin/wirelog_cli" in removed
        assert not (root / "include").exists()
        assert (root / "bin/wyrelogd").is_file()
        assert (root / "lib/libwirelog.so.1").is_file()

    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        staged_root = temporary_root / "stage"
        external_root = temporary_root / "external"
        staged_root.mkdir()
        external_root.mkdir()
        protected = external_root / "protected.h"
        protected.write_text("do not remove", encoding="utf-8")
        try:
            (staged_root / "usr").symlink_to(external_root, target_is_directory=True)
        except (NotImplementedError, OSError):
            return
        try:
            validated_prefix_root(staged_root, "/usr")
        except ValueError:
            pass
        else:
            raise AssertionError("symlinked staged prefix must be rejected")
        assert protected.read_text(encoding="utf-8") == "do not remove"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builddir", type=Path)
    parser.add_argument("--destdir", type=Path)
    parser.add_argument("--prefix", default="/usr")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.builddir is None or args.destdir is None:
        parser.error("--builddir and --destdir are required unless --self-test is used")
    return stage(args.builddir, args.destdir, args.prefix, args.manifest)


if __name__ == "__main__":
    raise SystemExit(main())

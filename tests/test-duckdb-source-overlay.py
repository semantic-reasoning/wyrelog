#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove the committed DuckDB source overlay is what its generator produces.

tools/generate-duckdb-source-overlay.py derives the unity units, source list,
library and consumer include lists and static extension loader from upstream's package_build.py.
The overlay is committed so a configure never runs upstream code; this test
regenerates it from the pinned release tarball and fails on any difference,
including a stale or missing generated file.

usage: test-duckdb-source-overlay.py SOURCE_ROOT ARCHIVE
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tarfile
import tempfile

ARCHIVE_SHA256 = (
    "7e89053255046bfb26afbd7f524a2fb84df7dbef496aa911ea35e4a1182fdc00"
)
ARCHIVE_ROOT = "duckdb-2.0.0"
OVERLAY = Path("subprojects/packagefiles/duckdb-source")
GENERATOR = Path("tools/generate-duckdb-source-overlay.py")
# Hand-written overlay files the generator never owns.
HAND_WRITTEN = frozenset({
    "meson.build",
    "0001-vfs-dynamic-cast.patch",
    "0002-test-seams.patch",
    "0003-llp64-clzll-oracle.patch",
})


def load_generator(root: Path):
    spec = importlib.util.spec_from_file_location(
        "generate_duckdb_source_overlay", root / GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    archive = Path(argv[2]).resolve()
    if sha256(archive) != ARCHIVE_SHA256:
        print("DuckDB archive SHA-256 mismatch", file=sys.stderr)
        return 1
    generator = load_generator(root)
    overlay = root / OVERLAY
    with tempfile.TemporaryDirectory(prefix="wyrelog-duckdb-overlay-") as scratch:
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(scratch, filter="data")
        expected = generator.generate(Path(scratch) / ARCHIVE_ROOT)
    errors = []
    for relative, text in sorted(expected.items()):
        path = overlay / relative
        if not path.is_file():
            errors.append(f"missing generated file: {relative}")
        elif path.read_bytes() != text.encode("utf-8"):
            errors.append(f"generated file drifted: {relative}")
    present = {
        str(path.relative_to(overlay))
        for path in overlay.rglob("*") if path.is_file()
    }
    for relative in sorted(present - set(expected) - HAND_WRITTEN):
        errors.append(f"stale overlay file: {relative}")
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print("regenerate with tools/generate-duckdb-source-overlay.py",
              file=sys.stderr)
        return 1
    print(f"DuckDB source overlay: OK ({len(expected)} generated files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate the Meson overlay that builds DuckDB from its full source tree.

DuckDB 2.0 no longer publishes an amalgamation, so the source subproject
compiles the upstream tree directly.  The translation units come from
upstream's own scripts/package_build.py, the packaging path its Python and R
builds use: one unity file per add_library_unity group, the same grouping
DuckDB's CMake build compiles, plus the files it builds on their own.

The overlay is generated once per DuckDB pin and committed, so a configure
never runs upstream code.  Re-run this tool after changing the pin and commit
the result; the duckdb-source-overlay test fails while the two disagree.

usage: generate-duckdb-source-overlay.py DUCKDB_SOURCE_ROOT OVERLAY_DIR
"""

from pathlib import Path
import os
import re
import shutil
import sys
import tempfile

# Files this tool owns inside the overlay.  meson.build and the patches are
# written by hand and never touched here.
UNITY_DIR = "unity"
SOURCES = "sources.txt"
INCLUDES = "includes.txt"
CONSUMER_INCLUDES = "consumer-includes.txt"
PUBLIC_HEADERS = "src/include"
LOADER = "generated_extension_loader_package_build.cpp"
# package_build also lists jemalloc for the Python wheels.  The 1.5.5
# amalgamation never carried it and DuckDB's own build links it only as an
# extension, so the allocator stays the system one.
EXCLUDED_PREFIXES = ("third_party/jemalloc/",)


INCLUDE_DIRECTIVE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)


def consumer_includes(source_root: Path, includes):
    """Return the include directories DuckDB's public headers reach.

    The library needs every directory package_build lists; a consumer needs
    only src/include and the third-party directories its headers include,
    followed transitively.  Every directive counts, conditional or not, so
    the result is a superset of what any configuration reads.
    """
    search = [PUBLIC_HEADERS] + [entry for entry in includes
                                 if entry != PUBLIC_HEADERS]
    needed = {PUBLIC_HEADERS}
    pending = sorted((source_root / PUBLIC_HEADERS).rglob("*.h*"))
    seen = set(pending)
    while pending:
        header = pending.pop()
        text = header.read_text(encoding="utf-8", errors="replace")
        for delimiter, name in INCLUDE_DIRECTIVE.findall(text):
            found = None
            if delimiter == '"' and (header.parent / name).is_file():
                found = header.parent / name
            else:
                for directory in search:
                    if (source_root / directory / name).is_file():
                        found = source_root / directory / name
                        needed.add(directory)
                        break
            if found is not None and found not in seen:
                seen.add(found)
                pending.append(found)
    return [entry for entry in search if entry in needed]


def generate(source_root: Path):
    """Return {overlay-relative path: text} for the generated files."""
    scripts = source_root / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        import package_build
    finally:
        sys.path.pop(0)

    # build_package writes its extension loader into the source root itself
    # and lists it by that relative name; move it into the overlay.
    loader = source_root / LOADER
    if loader.exists():
        raise SystemExit(f"{loader} already exists; refusing to overwrite it")
    previous = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="duckdb-overlay-") as staging:
        try:
            # No extension loader and no httplib client: package_build would
            # register both from a static constructor that an archive drops
            # on most linkers and keeps under --whole-archive.  Leaving them
            # out makes every source build refuse INSTALL and LOAD alike.
            sources, includes, _ = package_build.build_package(
                staging, [], folder_name="", extension_load=False)
        finally:
            os.chdir(previous)
            loader_text = (loader.read_text(encoding="utf-8")
                           if loader.exists() else None)
            loader.unlink(missing_ok=True)
        staging = Path(staging)
        files = {}
        listed = []
        for source in sources:
            path = Path(source)
            if path.is_absolute():
                # A generated unity or loader file inside the staging tree.
                relative = path.relative_to(staging)
                text = path.read_text(encoding="utf-8")
                if relative.name.startswith("ub_"):
                    target = f"{UNITY_DIR}/{relative.name}"
                else:
                    raise SystemExit(f"unexpected generated source: {relative}")
                files[target] = text
                listed.append(target)
            elif source == LOADER:
                listed.append(LOADER)
            elif not source.lstrip("/").startswith(EXCLUDED_PREFIXES):
                listed.append(source.lstrip("/"))
        if loader_text is None or LOADER not in listed:
            raise SystemExit("package_build produced no static extension loader")
        files[LOADER] = loader_text
    files[SOURCES] = "".join(f"{entry}\n" for entry in listed)
    includes = [entry for entry in includes
                if not f"{entry}/".startswith(EXCLUDED_PREFIXES)]
    files[INCLUDES] = "".join(f"{entry}\n" for entry in includes)
    files[CONSUMER_INCLUDES] = "".join(
        f"{entry}\n" for entry in consumer_includes(source_root, includes))
    return files


def write(overlay: Path, files):
    unity = overlay / UNITY_DIR
    if unity.exists():
        shutil.rmtree(unity)
    unity.mkdir(parents=True)
    for relative, text in sorted(files.items()):
        target = overlay / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as output:
            output.write(text)


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    source_root = Path(argv[1]).resolve()
    overlay = Path(argv[2]).resolve()
    if not (source_root / "scripts" / "package_build.py").is_file():
        print(f"{source_root} is not a DuckDB source tree", file=sys.stderr)
        return 2
    write(overlay, generate(source_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

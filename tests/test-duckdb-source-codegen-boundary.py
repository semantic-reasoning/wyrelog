#!/usr/bin/env python3
"""Structural gate for source-built DuckDB codegen policy.

The duckdb-amalgamated fallback compiles upstream's single-TU
amalgamation inside the parent build. Without an effective override the
subproject inherits the parent's buildtype, and a default (debug)
configure produces an -O0 libduckdb that runs the DuckDB-backed audit
and fact tests 4-8x slower than the prebuilt package -- slow enough to
blow fixed per-test budgets on shared CI runners (issue #386).

Placement matters: per-subproject core options (buildtype,
optimization, debug) set through project() default_options, a parent
dependency()/subproject() call, or -Dsubproject:option are all silently
ignored by older meson (measured inert on 1.3.2, the ubuntu-latest apt
version) and only honored by newer releases. The one placement every
supported meson honors is override_options on the library target, so
the codegen pin must live there and nowhere else.
"""

from pathlib import Path
import sys

root = Path(sys.argv[1])

subproject = (
    root / "subprojects" / "packagefiles" / "duckdb-amalgamated"
    / "meson.build")
text = subproject.read_text(encoding="utf-8")

start = text.index("duckdb_lib = library(")
end = text.index("\n)\n", start)
target = text[start:end]

if target.count("override_options") != 1:
    raise SystemExit(
        "the duckdb library target must pin codegen via override_options; "
        "project() or caller default_options are inert on meson 1.3.2")
if "'optimization=2'" not in target:
    raise SystemExit("the duckdb library target must pin 'optimization=2'")
if "'debug=false'" not in target:
    raise SystemExit("the duckdb library target must pin 'debug=false'")

head = text[:start]
for option in ("buildtype", "optimization", "debug"):
    if f"'{option}=" in head:
        raise SystemExit(
            f"project() default_options ({option}) are inert on meson "
            "1.3.2; keep the codegen pin on the library target only")

parent = (root / "meson.build").read_text(encoding="utf-8")
call_start = parent.index("duckdb_dep = dependency('duckdb-amalgamated',")
call = parent[call_start:parent.index(")", call_start)]
if "default_options" in call:
    raise SystemExit(
        "caller default_options on the duckdb-amalgamated fallback are "
        "inert on meson 1.3.2; keep the codegen pin on the library target")

print("duckdb source codegen boundary: OK")

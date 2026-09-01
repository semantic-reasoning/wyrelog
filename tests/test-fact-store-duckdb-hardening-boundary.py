#!/usr/bin/env python3
"""Structural and mutation checks for generic DuckDB fact-store hardening."""

from __future__ import annotations

from pathlib import Path
import re
import sys


SETTINGS = (
    'WYL_FACT_STORE_DUCKDB_CONFIG_THREADS, "1"',
    'WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS, "false"',
    'WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS, "false"',
    'WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS, "false"',
    'WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS, "false"',
    'WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE, "READ_ONLY"',
)
SETTING_NAMES = (
    ("WYL_FACT_STORE_DUCKDB_CONFIG_THREADS", "threads"),
    ("WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS",
     "enable_external_access"),
    ("WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS",
     "allow_community_extensions"),
    ("WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS",
     "autoinstall_known_extensions"),
    ("WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS",
     "autoload_known_extensions"),
    ("WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE", "access_mode"),
)


def helper_body(source: str) -> str:
    start = source.find("create_hardened_duckdb_config (")
    if start < 0:
        raise ValueError("shared hardened config helper is missing")
    end = source.find("\n#if defined(WYL_TEST_HANDLE_SEAMS)", start)
    if end < 0:
        raise ValueError("cannot delimit shared hardened config helper")
    return source[start:end]


def validate(source: str) -> list[str]:
    errors: list[str] = []
    try:
        body = helper_body(source)
    except ValueError as error:
        return [str(error)]
    for setting in SETTINGS:
        if setting not in body:
            errors.append(f"hardened helper does not check {setting}")
        pattern = re.escape(setting) + r",\s*out_configured_settings\)\s*!= DuckDBSuccess"
        if re.search(pattern, body) is None:
            errors.append(f"hardened helper does not check the result for {setting}")
    for setting, name in SETTING_NAMES:
        if f'case {setting}:\n      return "{name}";' not in source:
            errors.append(f"setting-name mapping drifted: {setting}")
    if not (
        "if (state == DuckDBSuccess && configured_settings != NULL)" in source
        and "*configured_settings |= 1u << setting;" in source
    ):
        errors.append("accepted-setting observation is not success-only")
    if source.count("create_hardened_duckdb_config (") != 3:
        errors.append("both generic open paths must use the one shared helper")
    if source.count("duckdb_create_config (&config)") != 1:
        errors.append("DuckDB config construction escaped the shared helper")
    if "create_hardened_duckdb_config (read_only, &config," not in source:
        errors.append("identified open does not preserve read-only mapping")
    if "create_hardened_duckdb_config (FALSE, &config," not in source:
        errors.append("generic open does not use hardened config")
    if "g_strcmp0 (path, \":memory:\") == 0" not in source:
        errors.append(":memory: mapping drifted")
    if "duckdb_destroy_config (&config);\n    return WYRELOG_E_IO;" not in body:
        errors.append("partial hardened config is not destroyed on failure")
    generic_start = source.find("\nwyrelog_error_t\nwyl_fact_store_open (")
    generic_end = source.find("\nvoid\nwyl_fact_store_close", generic_start)
    generic_open = source[generic_start:generic_end]
    if "if (out_store == NULL)\n    return WYRELOG_E_INVALID;\n  *out_store = NULL;" not in generic_open:
        errors.append("generic public open does not clear its output on failure")
    return errors


def validate_repository(root: Path, overrides: dict[str, str] | None = None) -> list[str]:
    overrides = overrides or {}

    def read(path: str) -> str:
        if path in overrides:
            return overrides[path]
        return (root / path).read_text(encoding="utf-8")

    source = read("wyrelog/fact/store.c")
    errors = validate(source)
    header_path = "wyrelog/fact/store-duckdb-config-test-seams-private.h"
    header = read(header_path)
    for raw_type in ("duckdb_database", "duckdb_connection", "duckdb_config "):
        if raw_type in header:
            errors.append(f"test seam exposes raw DuckDB authority: {raw_type}")
    if header.count("#if defined(WYL_TEST_HANDLE_SEAMS)") != 1:
        errors.append("test seam declarations escaped their compile guard")
    meson = read("tests/meson.build")
    c_test = read("tests/test-fact-store-duckdb-hardening.c")
    runtime = read("tests/test-fact-store-duckdb-autoload-runtime.py")
    test_names = (
        "fact-store-duckdb-hardening",
        "fact-store-duckdb-autoload-runtime",
        "fact-store-duckdb-autoload-runtime-self-test",
        "fact-store-duckdb-hardening-boundary",
        "fact-store-duckdb-hardening-boundary-self-test",
    )
    for name in test_names:
        if f"test('{name}'" not in meson:
            errors.append(f"Meson test is not registered: {name}")
    hardening_target = meson[meson.find("test_fact_store_duckdb_hardening ="):
                             meson.find("test_fact_store_forget_transaction =")]
    if "wyrelog_handle_test_seams_dep" not in hardening_target \
            or "dependencies : [wyrelog_dep" in hardening_target:
        errors.append("hardening test does not exclusively link the seam archive")
    c_requirements = (
        "wyl_fact_store_open (path, &store) != WYRELOG_E_IO",
        "WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY",
        "WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY",
        "result != WYL_FACT_STORE_IDENTITY_RESULT_OPEN",
        "create_sqlite_catalog (path, TRUE)",
        'duckdb_set_config (config, "autoinstall_known_extensions", "false")',
        "settings[i] == WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE",
        "g_stat (path, &before)",
        "mode, &result, &store), ==,\n        WYRELOG_E_OK",
    )
    for requirement in c_requirements:
        if requirement not in c_test:
            errors.append(f"focused runtime proof drifted: {requirement}")
    if c_test.count("!= WYRELOG_E_IO") < 3:
        errors.append("foreign SQLite probes do not require exact IO failures")
    runtime_requirements = (
        "discover_ambient_extension",
        'sentinel.write_text("must-not-be-observed\\n", encoding="utf-8")',
        "hashlib.sha256(path.read_bytes()).hexdigest()",
        'child.is_symlink()',
        'child.is_dir(follow_symlinks=False)',
        'forbidden = (".duckdb/extensions", "AF_INET", "AF_INET6")',
        "trace_parser_self_test()",
        'f".duckdb/extensions/{version}/*/sqlite_scanner.duckdb_extension"',
        "validate_positive_trace(evidence, staged)",
        "rf'\\bopen(?:at|at2)?\\(",
        "re.escape(str(staged))",
        "r'\\)\\s*=\\s*[0-9]+'",
        "f'newfstatat(AT_FDCWD, \"{staged}\", 0) = 0'",
        "f'openat(AT_FDCWD, \"{staged}\", O_RDONLY) = -1 EACCES'",
        'raise RuntimeError("positive control modified extension artifacts")',
    )
    for requirement in runtime_requirements:
        if requirement not in runtime:
            errors.append(f"portable runtime evidence drifted: {requirement}")
    for workflow_name in ("ci-pr.yml", "ci-main.yml"):
        workflow = read(f".github/workflows/{workflow_name}")
        if "meson ninja-build pkg-config patch strace time" not in workflow:
            errors.append(f"{workflow_name} does not install strace")
        for name in test_names:
            if name not in workflow:
                errors.append(f"{workflow_name} omits source-build gate {name}")
    return errors


def self_test(root: Path) -> list[str]:
    errors: list[str] = []
    paths = (
        "wyrelog/fact/store.c",
        "wyrelog/fact/store-duckdb-config-test-seams-private.h",
        "tests/test-fact-store-duckdb-hardening.c",
        "tests/test-fact-store-duckdb-autoload-runtime.py",
        "tests/meson.build",
        ".github/workflows/ci-pr.yml",
    )
    texts = {path: (root / path).read_text(encoding="utf-8") for path in paths}
    source = texts["wyrelog/fact/store.c"]
    if validate_repository(root):
        return ["unmodified source fails validation"]
    body = helper_body(source)
    body_start = source.index(body)
    for setting in SETTINGS:
        mutated_body = body.replace(
            setting, 'WYL_FACT_STORE_DUCKDB_CONFIG_NONE, "mutated"', 1)
        mutant = source[:body_start] + mutated_body + source[body_start + len(body):]
        if not validate_repository(root, {"wyrelog/fact/store.c": mutant}):
            errors.append(f"mutation survived: {setting}")
    mutations = (
        ("generic-open bypass", "wyrelog/fact/store.c",
         "create_hardened_duckdb_config (FALSE, &config, out_configured_settings)",
         "duckdb_create_config (&config)"),
        ("identified access-mode bypass", "wyrelog/fact/store.c",
         "create_hardened_duckdb_config (read_only, &config,",
         "create_hardened_duckdb_config (FALSE, &config,"),
        ("inverted accepted-setting result", "wyrelog/fact/store.c",
         "state == DuckDBSuccess && configured_settings != NULL",
         "state != DuckDBSuccess && configured_settings != NULL"),
        ("setting-name drift", "wyrelog/fact/store.c",
         'return "enable_external_access";', 'return "external_access";'),
        ("generic output nulling", "wyrelog/fact/store.c",
         "wyl_fact_store_open (const gchar *path, wyl_fact_store_t **out_store)\n{\n"
         "  if (out_store == NULL)\n    return WYRELOG_E_INVALID;\n  *out_store = NULL;",
         "wyl_fact_store_open (const gchar *path, wyl_fact_store_t **out_store)\n{\n"
         "  if (out_store == NULL)\n    return WYRELOG_E_INVALID;"),
        ("exact foreign result", "tests/test-fact-store-duckdb-hardening.c",
         "wyl_fact_store_open (path, &store) != WYRELOG_E_IO",
         "wyl_fact_store_open (path, &store) == WYRELOG_E_OK"),
        ("positive autoinstall", "tests/test-fact-store-duckdb-hardening.c",
         'duckdb_set_config (config, "autoinstall_known_extensions", "false")',
         'duckdb_set_config (config, "autoinstall_known_extensions", "true")'),
        ("access-mode retry", "tests/test-fact-store-duckdb-hardening.c",
         "        mode, &result, &store), ==,\n        WYRELOG_E_OK",
         "        WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result, &store), ==,\n        WYRELOG_E_OK"),
        ("seam guard", "wyrelog/fact/store-duckdb-config-test-seams-private.h",
         "#if defined(WYL_TEST_HANDLE_SEAMS)", "#if 1"),
        ("dual link", "tests/meson.build",
         "dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep]",
         "dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep]"),
        ("ambient sentinel", "tests/test-fact-store-duckdb-autoload-runtime.py",
         'sentinel.write_text("must-not-be-observed\\n", encoding="utf-8")',
         "pass  # sentinel removed"),
        ("trace IPv6", "tests/test-fact-store-duckdb-autoload-runtime.py",
         'forbidden = (".duckdb/extensions", "AF_INET", "AF_INET6")',
         'forbidden = (".duckdb/extensions", "AF_INET")'),
        ("tree hash", "tests/test-fact-store-duckdb-autoload-runtime.py",
         "hashlib.sha256(path.read_bytes()).hexdigest()", "str(path.stat().st_size)"),
        ("version filter", "tests/test-fact-store-duckdb-autoload-runtime.py",
         'f".duckdb/extensions/{version}/*/sqlite_scanner.duckdb_extension"',
         '".duckdb/extensions/*/*/sqlite_scanner.duckdb_extension"'),
        ("successful positive open", "tests/test-fact-store-duckdb-autoload-runtime.py",
         "r'\\)\\s*=\\s*[0-9]+'", "r'\\)\\s*=\\s*.*'"),
        ("positive syscall whitelist", "tests/test-fact-store-duckdb-autoload-runtime.py",
         "rf'\\bopen(?:at|at2)?\\(",
         "rf'\\b(?:open(?:at|at2)?|newfstatat)\\("),
        ("positive full path", "tests/test-fact-store-duckdb-autoload-runtime.py",
         "re.escape(str(staged))", "re.escape(staged.name)"),
        ("successful stat fixture", "tests/test-fact-store-duckdb-autoload-runtime.py",
         "f'newfstatat(AT_FDCWD, \"{staged}\", 0) = 0'",
         "f'fixture-removed-{staged}'"),
        ("failed open fixture", "tests/test-fact-store-duckdb-autoload-runtime.py",
         "f'openat(AT_FDCWD, \"{staged}\", O_RDONLY) = -1 EACCES'",
         "f'fixture-removed-{staged}'"),
        ("runtime self-test registration", "tests/meson.build",
         "test('fact-store-duckdb-autoload-runtime-self-test'",
         "test('removed-runtime-self-test'"),
        ("CI strace", ".github/workflows/ci-pr.yml", "patch strace time",
         "patch time"),
    )
    for label, path, old, new in mutations:
        if old not in texts[path]:
            errors.append(f"self-test fixture missing: {label}")
            continue
        mutant = texts[path].replace(old, new, 1)
        if not validate_repository(root, {path: mutant}):
            errors.append(f"mutation survived: {label}")
    return errors


def main() -> int:
    self_mode = len(sys.argv) == 3 and sys.argv[1] == "--self-test"
    if self_mode:
        root = Path(sys.argv[2])
    elif len(sys.argv) == 2:
        root = Path(sys.argv[1])
    else:
        print(f"usage: {sys.argv[0]} [--self-test] SOURCE_ROOT", file=sys.stderr)
        return 2
    errors = self_test(root) if self_mode else validate_repository(root)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

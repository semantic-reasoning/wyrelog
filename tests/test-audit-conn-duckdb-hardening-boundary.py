#!/usr/bin/env python3
"""Structural and mutation guard for audit DuckDB open hardening."""

from __future__ import annotations

from pathlib import Path
import re
import sys


FILES = (
    "wyrelog/audit/conn.c",
    "wyrelog/audit/conn-private.h",
    "wyrelog/audit/conn-duckdb-config-test-seams-private.h",
    "tests/test-audit-conn-duckdb-hardening.c",
    "tests/test-audit-conn-duckdb-autoload-runtime.py",
    "tests/meson.build",
    "tools/check-handle-test-seam-exports.py",
    "tools/formatted-files.txt",
    ".github/workflows/ci-pr.yml",
    ".github/workflows/ci-main.yml",
)

SOURCE_WINDOWS_WAIVER = """  # Issue #920: DuckDB 1.5.5 compares 64-bit CountZeros results with
  # 32-bit unsigned-long builtins under clang-cl/LLP64.  Until #920 fixes
  # those assertion oracles, positive/effective source-Windows runtime is
  # temporarily waived.  The retained child and structural gates below are
  # not equivalent positive-open or effective-settings evidence.
  audit_duckdb_hardening_source_windows_waived = \\
    host_machine.system() == 'windows' and \\
    cc.get_id() == 'clang-cl' and \\
    get_option('duckdb_source') == 'subproject'
  if not audit_duckdb_hardening_source_windows_waived
"""

SAFE_WINDOWS_GATES = (
    "audit-conn-duckdb-autoload-clean-runtime",
    "audit-conn-duckdb-autoload-ambient-runtime",
    "audit-conn-duckdb-autoload-runtime-self-test",
    "audit-conn-duckdb-hardening-boundary",
    "audit-conn-duckdb-hardening-boundary-self-test",
)

AGGREGATE_REGISTRATION = """    test('audit-conn-duckdb-hardening',
      test_audit_conn_duckdb_hardening,
      env : audit_conn_test_env,
      timeout : 60,
    )
"""
SOURCE_WINDOWS_WAIVER_BLOCK = (
    SOURCE_WINDOWS_WAIVER + AGGREGATE_REGISTRATION + "  endif\n"
)
AGGREGATE_WORKFLOW_INVOCATION = (
    "meson test -C builddir audit-conn-duckdb-hardening "
)


def windows_audit_command() -> str:
    safe = " ".join(SAFE_WINDOWS_GATES)
    return (
        '          if "${{ matrix.duckdb_source }}"=="subproject" (\n'
        f"            meson test -C builddir {safe} --no-rebuild "
        "--print-errorlogs\n"
        "          ) else (\n"
        "            meson test -C builddir audit-conn-duckdb-hardening "
        f"{safe} --no-rebuild --print-errorlogs\n"
        "          )"
    )


def function_body(source: str, name: str) -> str:
    marker = source.find(name + " (")
    if marker < 0:
        marker = source.find(name + "\n")
    if marker < 0:
        raise ValueError(f"missing function: {name}")
    start = source.find("{", marker)
    if start < 0:
        raise ValueError(f"missing function body: {name}")
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise ValueError(f"unterminated function body: {name}")


def validate_repository(root: Path,
                        overrides: dict[str, str] | None = None) -> list[str]:
    overrides = overrides or {}
    texts = {
        path: overrides.get(path, (root / path).read_text(encoding="utf-8"))
        for path in FILES
    }
    errors: list[str] = []
    conn = texts["wyrelog/audit/conn.c"]
    header = texts[
        "wyrelog/audit/conn-duckdb-config-test-seams-private.h"
    ]
    focused = texts["tests/test-audit-conn-duckdb-hardening.c"]
    meson = texts["tests/meson.build"]
    runtime = texts["tests/test-audit-conn-duckdb-autoload-runtime.py"]

    try:
        create = function_body(conn, "create_hardened_duckdb_config")
        apply = function_body(conn, "audit_duckdb_apply_config")
        opener = function_body(conn, "open_duckdb_with_thread_budget")
        public_open = function_body(conn, "wyl_audit_conn_open")
    except ValueError as error:
        return [str(error)]

    settings = (
        ("WYL_AUDIT_DUCKDB_CONFIG_THREADS", "threads", "1"),
        ("WYL_AUDIT_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS",
         "enable_external_access", "false"),
        ("WYL_AUDIT_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS",
         "allow_community_extensions", "false"),
        ("WYL_AUDIT_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS",
         "autoinstall_known_extensions", "false"),
        ("WYL_AUDIT_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS",
         "autoload_known_extensions", "false"),
    )
    mapping = function_body(conn, "audit_duckdb_config_name")
    for operation, name, value in settings:
        mapping_pattern = (
            rf"case\s+{operation}\s*:\s*return\s+\"{name}\"\s*;"
        )
        if re.search(mapping_pattern, mapping) is None:
            errors.append(f"config operation is not bound to {name}")
        call_pattern = (
            rf"audit_duckdb_apply_config\s*\(\s*config\s*,\s*"
            rf"{operation}\s*,\s*\"{value}\"\s*\)\s*"
            rf"!=\s*DuckDBSuccess"
        )
        if re.search(call_pattern, create) is None:
            errors.append(f"hardened helper omits checked {operation}={value}")
        if operation not in header:
            errors.append(f"typed seam omits {operation}")
    if create.count("audit_duckdb_apply_config") != len(settings):
        errors.append("hardened helper must apply each setting exactly once")
    if "configured_settings" in conn or "duckdb_configured_settings" in conn:
        errors.append("audit opener retains synthetic accepted-setting state")
    if "return audit_duckdb_set_config (config, operation, value);" not in apply:
        errors.append("setting helper bypasses the checked config wrapper")
    if "audit_duckdb_destroy_config (&config);" not in create:
        errors.append("setting failure does not destroy partial config")
    if len(re.findall(r"(?<![A-Za-z0-9_])duckdb_create_config \(", conn)) != 1:
        errors.append("audit config creation bypasses its checked wrapper")
    if len(re.findall(r"(?<![A-Za-z0-9_])duckdb_open_ext \(", conn)) != 1:
        errors.append("audit database open bypasses the hardened opener")
    for required in (
        "*out_db = NULL;",
        'g_strcmp0 (path, ":memory:") == 0',
        "create_hardened_duckdb_config",
        "duckdb_database db = NULL;",
        "duckdb_close (&db);",
        "audit_duckdb_destroy_config (&config);",
        "duckdb_free (error);",
        "*out_db = db;",
    ):
        if required not in opener:
            errors.append(f"hardened opener lacks: {required}")
    if "*out_conn = NULL;" not in public_open:
        errors.append("public audit output is not fail-closed")
    connect_failure = re.compile(
        r"if\s*\(\s*duckdb_connect\s*\(\s*self->db\s*,\s*&self->conn\s*\)"
        r"\s*!=\s*DuckDBSuccess\s*\)\s*\{\s*"
        r"duckdb_close\s*\(\s*&self->db\s*\)\s*;\s*"
        r"g_free\s*\(\s*self\s*\)\s*;\s*"
        r"return\s+WYRELOG_E_INTERNAL\s*;\s*\}",
        re.DOTALL,
    )
    if connect_failure.search(public_open) is None:
        errors.append("connect failure does not close, free, and fail internally")
    if "on any non-OK return *out_conn is NULL" not in texts[
            "wyrelog/audit/conn-private.h"]:
        errors.append("private audit contract does not promise NULL on failure")
    if "fact/store" in conn or "store-duckdb-config" in conn:
        errors.append("audit hardening imports fact-store ownership")

    try:
        effective = function_body(focused, "assert_hardened_settings")
    except ValueError as error:
        errors.append(str(error))
        effective = ""
    if "duckdb_settings()" not in effective:
        errors.append("focused test does not query effective DuckDB settings")
    if "duckdb_row_count (&result), ==, G_N_ELEMENTS (expected)" not in effective:
        errors.append("focused test does not require all effective rows exactly once")
    for _operation, name, value in settings:
        if f"'{name}'" not in effective:
            errors.append(f"effective query omits literal setting: {name}")
        expected_pattern = (
            rf"\{{\s*\"{name}\"\s*,\s*\"{value}\"\s*\}}"
        )
        if re.search(expected_pattern, effective) is None:
            errors.append(f"effective assertion omits {name}={value}")
    if "wyl_audit_conn_duckdb_config_get_for_test" in conn or \
            "wyl_audit_conn_duckdb_config_get_for_test" in header:
        errors.append("synthetic effective-setting getter remains")

    guard = "#if defined(WYL_TEST_HANDLE_SEAMS)"
    export_source = texts["tools/check-handle-test-seam-exports.py"]
    protected = export_source[
        export_source.find("PROTECTED = {"):export_source.find("}\n", export_source.find("PROTECTED = {"))
    ]
    for symbol in (
        "wyl_audit_conn_duckdb_config_fail_once_for_test",
        "wyl_audit_conn_duckdb_config_snapshot_for_test",
    ):
        if symbol not in header or symbol not in conn:
            errors.append(f"missing deterministic seam: {symbol}")
        if f'"{symbol}"' not in protected:
            errors.append(f"production symbol guard omits: {symbol}")
    if '"wyl_audit_conn_duckdb_config_get_for_test"' in protected:
        errors.append("production symbol guard retains synthetic getter")
    if guard not in header or header.find(guard) > header.find(
            "wyl_audit_conn_duckdb_config_fail_once_for_test"):
        errors.append("seam declarations are not test guarded")
    if "duckdb_database" in header or "duckdb_connection" in header:
        errors.append("test seam header exposes a raw DuckDB handle")
    if "reset_for_test" in header:
        errors.append("test seam exposes an unsafe global reset")

    exact_dependencies = (
        "dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep]"
    )
    if exact_dependencies not in meson:
        errors.append("focused target does not use the exclusive seam archive")
    hardening_block = meson[meson.find("test_audit_conn_duckdb_hardening"):]
    hardening_block = hardening_block[:hardening_block.find(
        "test_service_exchange_projector")]
    if "wyrelog_dep" in hardening_block or "service_exchange_private_dep" in hardening_block:
        errors.append("focused target dual-links a production implementation")
    executable_at = hardening_block.find(
        "test_audit_conn_duckdb_hardening = executable(")
    waiver_at = hardening_block.find(SOURCE_WINDOWS_WAIVER_BLOCK)
    aggregate_at = waiver_at + len(SOURCE_WINDOWS_WAIVER)
    waiver_end_at = aggregate_at + len(AGGREGATE_REGISTRATION)
    first_safe_at = hardening_block.find(
        "  test('audit-conn-duckdb-autoload-clean-runtime'", waiver_end_at)
    if waiver_at < 0:
        errors.append("source-Windows waiver is not the exact #920 contract")
    elif not (0 <= executable_at < waiver_at < aggregate_at
              < waiver_end_at < first_safe_at):
        errors.append("source-Windows waiver guards more than the aggregate runtime")
    if hardening_block.count(SOURCE_WINDOWS_WAIVER_BLOCK) != 1:
        errors.append(
            "source-Windows waiver must guard only the aggregate runtime")
    if meson.count(
            "if not audit_duckdb_hardening_source_windows_waived") != 1:
        errors.append("focused executable compilation moved under the waiver")
    if hardening_block.count(AGGREGATE_REGISTRATION) != 1:
        errors.append("aggregate audit runtime registration or timeout drifted")
    for forbidden in ("NDEBUG", "b_ndebug", "continue-on-error", "retry"):
        if forbidden in hardening_block:
            errors.append(f"source-Windows waiver masks evidence with {forbidden}")
    for target in (
        "audit-conn-duckdb-hardening",
        "audit-conn-duckdb-autoload-clean-runtime",
        "audit-conn-duckdb-autoload-ambient-runtime",
        "audit-conn-duckdb-autoload-runtime-self-test",
        "audit-conn-duckdb-hardening-boundary",
        "audit-conn-duckdb-hardening-boundary-self-test",
    ):
        if target not in meson:
            errors.append(f"Meson omits required gate: {target}")
    if hardening_block.count("env : audit_conn_test_env") < 4:
        errors.append("new audit tests do not consistently reuse Windows DLL PATH")

    for required in (
        '"HOME", "USERPROFILE"',
        'environment.pop("DUCKDB_EXTENSION_DIRECTORY", None)',
        "database.close()",
        "hashlib.sha256(path.read_bytes()).hexdigest()",
        'tracer, "-f", "-e", "trace=file,network"',
        '"AF_INET", "AF_INET6"',
        "validate_positive_trace",
        "return 77",
        "file_digest(catalog)",
    ):
        if required not in runtime:
            errors.append(f"runtime evidence lacks: {required}")

    ledger = set(texts["tools/formatted-files.txt"].splitlines())
    for path in (
        "tests/test-audit-conn.c",
        "tests/test-audit-conn-duckdb-hardening.c",
        "wyrelog/audit/conn.c",
        "wyrelog/audit/conn-private.h",
        "wyrelog/audit/conn-duckdb-config-test-seams-private.h",
    ):
        if path not in ledger:
            errors.append(f"format ledger omits touched C source: {path}")

    for workflow_path in (".github/workflows/ci-pr.yml",
                          ".github/workflows/ci-main.yml"):
        workflow = texts[workflow_path]
        if "patch strace time" not in workflow:
            errors.append(f"{workflow_path} lacks Linux strace")
        if workflow.count("-Denable_audit=enabled") < 3:
            errors.append(f"{workflow_path} source builds do not enable audit")
        for target in (
            "audit-conn-duckdb-hardening",
            "audit-conn-duckdb-autoload-clean-runtime",
            "audit-conn-duckdb-autoload-runtime-self-test",
            "audit-conn-duckdb-hardening-boundary",
            "audit-conn-duckdb-hardening-boundary-self-test",
        ):
            if target not in workflow:
                errors.append(f"{workflow_path} omits CI gate: {target}")
        if workflow.count(windows_audit_command()) != 1:
            errors.append(
                f"{workflow_path} does not preserve the exact source/prebuilt "
                "Windows audit distinction")
        if workflow.count(AGGREGATE_WORKFLOW_INVOCATION) != 1:
            errors.append(
                f"{workflow_path} must invoke the aggregate runtime exactly "
                "once in the prebuilt branch")
        audit_step_at = workflow.find(
            "      - name: Test audit DuckDB hardening (clang-cl)")
        audit_step_end = workflow.find("\n      - name:", audit_step_at + 1)
        audit_step = workflow[audit_step_at:audit_step_end]
        if "meson compile -C builddir test-audit-conn-duckdb-hardening" not in audit_step:
            errors.append(f"{workflow_path} does not always compile the focused target")
        for forbidden in (
                "NDEBUG", "b_ndebug", "continue-on-error", "retry", "--timeout-multiplier"):
            if forbidden in audit_step:
                errors.append(f"{workflow_path} masks the Windows waiver with {forbidden}")
    return errors


def self_test(root: Path) -> list[str]:
    texts = {path: (root / path).read_text(encoding="utf-8") for path in FILES}
    settings = (
        ("WYL_AUDIT_DUCKDB_CONFIG_THREADS", "threads", "1"),
        ("WYL_AUDIT_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS",
         "enable_external_access", "false"),
        ("WYL_AUDIT_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS",
         "allow_community_extensions", "false"),
        ("WYL_AUDIT_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS",
         "autoinstall_known_extensions", "false"),
        ("WYL_AUDIT_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS",
         "autoload_known_extensions", "false"),
    )
    mutations = [
        ("output null", "wyrelog/audit/conn.c", "*out_conn = NULL;",
         "/* output not cleared */"),
        ("connect condition", "wyrelog/audit/conn.c",
         "duckdb_connect (self->db, &self->conn) != DuckDBSuccess",
         "duckdb_connect (self->db, &self->conn) == DuckDBSuccess"),
        ("connect database close", "wyrelog/audit/conn.c",
         "duckdb_close (&self->db);", "/* database handle leaked */"),
        ("connect wrapper free", "wyrelog/audit/conn.c",
         "g_free (self);", "/* wrapper leaked */"),
        ("connect status", "wyrelog/audit/conn.c",
         "return WYRELOG_E_INTERNAL;", "return WYRELOG_E_IO;"),
        ("memory mapping", "wyrelog/audit/conn.c",
         'g_strcmp0 (path, ":memory:") == 0', "FALSE"),
        ("partial close", "wyrelog/audit/conn.c", "duckdb_close (&db);",
         "/* partial database leaked */"),
        ("error cleanup", "wyrelog/audit/conn.c", "duckdb_free (error);",
         "/* error leaked */"),
        ("setting helper bypass", "wyrelog/audit/conn.c",
         "return audit_duckdb_set_config (config, operation, value);",
         "return duckdb_set_config (config, \"threads\", value);"),
        ("seam guard", "wyrelog/audit/conn-duckdb-config-test-seams-private.h",
         "#if defined(WYL_TEST_HANDLE_SEAMS)", "#if 1"),
        ("dual link", "tests/meson.build",
         "dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep]",
         "dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep]"),
        ("runtime registration", "tests/meson.build",
         "test('audit-conn-duckdb-autoload-runtime-self-test'",
         "test('removed-runtime-self-test'"),
        ("waiver Windows predicate", "tests/meson.build",
         "host_machine.system() == 'windows' and \\",
         "host_machine.system() == 'linux' and \\",),
        ("waiver compiler predicate", "tests/meson.build",
         "cc.get_id() == 'clang-cl' and \\",
         "cc.get_id() == 'clang' and \\",),
        ("waiver source predicate", "tests/meson.build",
         "get_option('duckdb_source') == 'subproject'",
         "get_option('duckdb_source') == 'prebuilt'"),
        ("waiver conjunction", "tests/meson.build",
         "host_machine.system() == 'windows' and \\",
         "host_machine.system() == 'windows' or \\",),
        ("waiver retirement issue", "tests/meson.build", "Issue #920",
         "Issue #000"),
        ("waiver evidence honesty", "tests/meson.build", "not equivalent",
         "equivalent"),
        ("waiver compile boundary", "tests/meson.build",
         "test_audit_conn_duckdb_hardening = executable(",
         "if not audit_duckdb_hardening_source_windows_waived\n"
         "  test_audit_conn_duckdb_hardening = executable("),
        ("waiver timeout", "tests/meson.build", "timeout : 60,",
         "timeout : 600,"),
        ("waiver guarded scope", "tests/meson.build",
         AGGREGATE_REGISTRATION + "  endif",
         AGGREGATE_REGISTRATION
         + "    test('waiver-scope-creep', "
         "test_audit_conn_duckdb_hardening)\n  endif"),
        ("trace IPv6", "tests/test-audit-conn-duckdb-autoload-runtime.py",
         '"AF_INET6"', '"AF_UNSPEC"'),
        ("tree hash", "tests/test-audit-conn-duckdb-autoload-runtime.py",
         "hashlib.sha256(path.read_bytes()).hexdigest()",
         "str(path.stat().st_size)"),
        ("export guard", "tools/check-handle-test-seam-exports.py",
         '"wyl_audit_conn_duckdb_config_fail_once_for_test",', ""),
        ("CI strace", ".github/workflows/ci-pr.yml", "patch strace time",
         "patch time"),
        ("CI safe source gate", ".github/workflows/ci-pr.yml",
         "audit-conn-duckdb-autoload-clean-runtime",
         "removed-audit-clean-runtime"),
        ("CI prebuilt aggregate", ".github/workflows/ci-pr.yml",
         "meson test -C builddir audit-conn-duckdb-hardening ",
         "meson test -C builddir removed-audit-hardening "),
        ("CI unconditional aggregate", ".github/workflows/ci-pr.yml",
         windows_audit_command(),
         windows_audit_command()
         + "\n          meson test -C builddir "
         "audit-conn-duckdb-hardening --no-rebuild --print-errorlogs"),
        ("CI assertion masking", ".github/workflows/ci-pr.yml",
         "meson compile -C builddir test-audit-conn-duckdb-hardening",
         "set NDEBUG=1\n          meson compile -C builddir "
         "test-audit-conn-duckdb-hardening"),
        ("effective row count", "tests/test-audit-conn-duckdb-hardening.c",
         "duckdb_row_count (&result), ==, G_N_ELEMENTS (expected)",
         "duckdb_row_count (&result), >=, 1"),
    ]
    replacement_operation = {
        settings[index][0]: settings[(index + 1) % len(settings)][0]
        for index in range(len(settings))
    }
    for operation, name, value in settings:
        mutations.extend((
            (f"operation {name}", "wyrelog/audit/conn.c",
             operation, replacement_operation[operation]),
            (f"mapping {name}", "wyrelog/audit/conn.c", f'"{name}"',
             f'"mutated_{name}"'),
            (f"value {name}", "wyrelog/audit/conn.c",
             f'{operation}, "{value}")',
             f'{operation}, "mutated_{value}")'),
            (f"unchecked {name}", "wyrelog/audit/conn.c",
             f'{operation}, "{value}")\n      != DuckDBSuccess',
             f'{operation}, "{value}")\n      == DuckDBSuccess'),
            (f"effective query {name}",
             "tests/test-audit-conn-duckdb-hardening.c", f"'{name}'",
             f"'mutated_{name}'"),
            (f"effective assertion {name}",
             "tests/test-audit-conn-duckdb-hardening.c",
             f'{{ "{name}", "{value}" }}',
             f'{{ "{name}", "mutated_{value}" }}'),
        ))
    errors: list[str] = []
    for label, path, old, new in mutations:
        if old not in texts[path]:
            errors.append(f"self-test fixture missing: {label}")
            continue
        mutant = texts[path].replace(old, new)
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

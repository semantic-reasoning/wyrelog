#!/usr/bin/env python3
"""Guard issue #890's checked fact-forget transaction cleanup boundary."""

from __future__ import annotations

from pathlib import Path
import sys


PATHS = (
    "wyrelog/fact/store.c",
    "wyrelog/fact/store-private.h",
    "tests/test-fact-store-forget-transaction.c",
    "tests/test-fact-store-forget-transaction-provisioned.c",
    "tests/meson.build",
    ".github/workflows/ci-pr.yml",
    ".github/workflows/ci-main.yml",
)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def call_body(source: str, signature: str) -> str:
    start = source.index(signature)
    paren = source.index("(", start)
    depth = 0
    for index in range(paren, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated call: {signature}")


def require_once(text: str, token: str, message: str) -> None:
    if text.count(token) != 1:
        raise AssertionError(message)


def validate(files: dict[str, str]) -> None:
    store = files["wyrelog/fact/store.c"]
    header = files["wyrelog/fact/store-private.h"]
    generic = files["tests/test-fact-store-forget-transaction.c"]
    provisioned = files[
        "tests/test-fact-store-forget-transaction-provisioned.c"
    ]
    meson = files["tests/meson.build"]

    helper = function_body(store, "rollback_forget_transaction_unlocked")
    completion = function_body(store, "complete_forget_intent_unlocked")
    require_once(
        helper,
        'rollback_rc = exec_sql (store->conn, "ROLLBACK;");',
        "checked cleanup must execute one real rollback",
    )
    require_once(
        helper,
        "WYL_LOG_ERROR (WYL_LOG_SECTION_IO,",
        "rollback failure must emit one operator-visible error",
    )
    require_once(
        helper,
        '"fact forget transaction rollback failed"',
        "rollback diagnostic literal drifted",
    )
    require_once(
        helper,
        "return WYRELOG_E_INTERNAL;",
        "rollback failure must take INTERNAL precedence",
    )
    require_once(
        helper,
        "return primary_rc;",
        "successful cleanup must preserve the primary error",
    )
    if "duckdb_disconnect" in helper or "duckdb_connect" in helper:
        raise AssertionError("checked cleanup must not replace the connection")

    body_failures = (
        "if (duckdb_prepare (store->conn, audit_sql, &stmt) "
        "!= DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (ok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&stmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (exec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto rollback;\n  }",
        "if (duckdb_prepare (store->conn, update_sql, &ustmt) "
        "!= DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (uok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&ustmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (uexec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto rollback;\n  }",
    )
    for index, failure in enumerate(body_failures, 1):
        require_once(
            completion,
            failure,
            f"body failure {index} escaped the common rollback",
        )
    require_once(
        completion,
        'rc = exec_sql (store->conn, "COMMIT;");\n'
        "  if (rc != WYRELOG_E_OK)\n    goto rollback;",
        "a real COMMIT failure must enter common rollback",
    )
    require_once(
        completion,
        "rollback:\n  return rollback_forget_transaction_unlocked (store, rc);",
        "completion must have one checked cleanup exit",
    )
    if "(void) exec_sql" in completion:
        raise AssertionError("completion still discards transaction cleanup")

    seam_tokens = (
        "WylFactStoreForgetTransactionTestPhase",
        "WylFactStoreForgetTransactionTestHook",
        "wyl_fact_store_set_forget_transaction_test_hook",
    )
    for token in seam_tokens:
        if token not in header:
            raise AssertionError(f"private transaction seam drifted: {token}")
    header_seam = header[
        header.index("#if defined(WYL_TEST_HANDLE_SEAMS)\ntypedef enum") :
        header.index("#endif", header.index(
            "#if defined(WYL_TEST_HANDLE_SEAMS)\ntypedef enum"
        )) + len("#endif")
    ]
    for token in seam_tokens[:2]:
        if token not in header_seam:
            raise AssertionError(f"test seam escaped its compile guard: {token}")
    require_once(
        completion,
        "WYL_FACT_STORE_FORGET_TRANSACTION_AFTER_BEGIN",
        "runtime body-failure seam drifted",
    )
    require_once(
        completion,
        "WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_COMMIT",
        "runtime COMMIT seam drifted",
    )
    require_once(
        helper,
        "WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_ROLLBACK",
        "runtime ROLLBACK seam drifted",
    )

    generic_required = (
        "test_unarmed_control_commits",
        "test_commit_failure_rolls_back",
        "test_body_failure_rolls_back",
        "test_rollback_failure_is_reported",
        'exec_ok (conn, "SELECT 1;")',
        'exec_ok (conn, "BEGIN TRANSACTION;")',
        'exec_ok (conn, "ROLLBACK;")',
        'g_setenv ("WYL_LOG_FILE", log_path, TRUE)',
        '"fact forget transaction rollback failed"',
        "g_strv_length (messages), ==, 2",
        "forget (fixture), ==, WYRELOG_E_INTERNAL",
        "wyl_fact_store_lock (fixture->store)",
        "wyl_fact_store_get_connection (fixture->store)",
        "wyl_fact_store_forget_reconcile",
    )
    for token in generic_required:
        if token not in generic:
            raise AssertionError(f"generic runtime proof drifted: {token}")
    for secret in (
        'g_strstr_len (contents, -1, "tenant-a")',
        'g_strstr_len (contents, -1, "orders")',
        'g_strstr_len (contents, -1, "transaction-fault")',
        'g_strstr_len (contents, -1, "transaction-boundary-test")',
    ):
        if secret not in generic:
            raise AssertionError(f"diagnostic redaction proof drifted: {secret}")

    provisioned_required = (
        "wyl_fact_store_open_provisioned_pair",
        "fail_commit_once",
        'exec_ok (conn, "SELECT 1;")',
        'exec_ok (conn, "BEGIN TRANSACTION;")',
        'exec_ok (conn, "ROLLBACK;")',
        "wyl_fact_store_forget_reconcile",
        "open_live (root, &store)",
    )
    for token in provisioned_required:
        if token not in provisioned:
            raise AssertionError(f"provisioned runtime proof drifted: {token}")
    if provisioned.count("open_live (root, &store)") != 2:
        raise AssertionError("provisioned proof must close and reopen the store")

    generic_target = call_body(
        meson, "test_fact_store_forget_transaction = executable("
    )
    if "wyrelog_handle_test_seams_dep" not in generic_target:
        raise AssertionError("generic test must link the seam archive")
    if "dependencies : [wyrelog_dep" in generic_target:
        raise AssertionError("generic test must not dual-link production wyrelog")
    provisioned_target = call_body(
        meson,
        "test_fact_store_forget_transaction_provisioned = executable(",
    )
    if "wyrelog_handle_test_seams_dep" not in provisioned_target:
        raise AssertionError("provisioned test must link the seam archive")
    require_once(
        meson,
        "test('fact-store-forget-transaction',",
        "generic runtime must be registered once",
    )
    require_once(
        meson,
        "test('fact-store-forget-transaction-provisioned',",
        "provisioned runtime must be registered once",
    )
    require_once(
        meson,
        "test('fact-store-forget-transaction-boundary',",
        "boundary checker must be registered once",
    )
    require_once(
        meson,
        "test('fact-store-forget-transaction-boundary-self',",
        "boundary checker self-test must be registered once",
    )
    provisioned_registration = meson.index(
        "test('fact-store-forget-transaction-provisioned',"
    )
    posix_guard = meson.rfind(
        "if host_machine.system() != 'windows'", 0, provisioned_registration
    )
    guard_end = meson.find("\n  endif", posix_guard)
    if posix_guard == -1 or guard_end < provisioned_registration:
        raise AssertionError("provisioned runtime escaped its POSIX-only guard")

    posix_step_name = (
        "      - name: Test fact forget transaction cleanup with secure DuckDB"
    )
    posix_commands = (
        "meson compile -C build-secure-duckdb -j 1 \\\n"
        "            test-fact-store-forget-transaction \\\n"
        "            test-fact-store-forget-transaction-provisioned\n"
        "          meson test -C build-secure-duckdb --no-rebuild \\\n"
        "            fact-store-forget-transaction \\\n"
        "            fact-store-forget-transaction-provisioned \\\n"
        "            --print-errorlogs"
    )
    windows_step_name = (
        "      - name: Test fact forget transaction cleanup (clang-cl)"
    )
    windows_commands = (
        "meson compile -C builddir test-fact-store-forget-transaction\n"
        "          meson test -C builddir --no-rebuild "
        "fact-store-forget-transaction --print-errorlogs"
    )
    for workflow_path in (
        ".github/workflows/ci-pr.yml",
        ".github/workflows/ci-main.yml",
    ):
        workflow = files[workflow_path]
        require_once(
            workflow,
            posix_step_name,
            f"{workflow_path} must have one POSIX secure cleanup step",
        )
        require_once(
            workflow,
            posix_commands,
            f"{workflow_path} POSIX secure cleanup commands drifted",
        )
        if not (
            workflow.index(
                "      - name: Build secure DuckDB backend from pinned source"
            )
            < workflow.index(posix_step_name)
            < workflow.index("      - name: Remove secure DuckDB compile swap")
        ):
            raise AssertionError(
                f"{workflow_path} POSIX cleanup test escaped the secure lease"
            )
        require_once(
            workflow,
            windows_step_name,
            f"{workflow_path} must have one Windows secure cleanup step",
        )
        require_once(
            workflow,
            windows_commands,
            f"{workflow_path} Windows secure cleanup commands drifted",
        )
        windows_step_start = workflow.index(windows_step_name)
        windows_step_end = workflow.index(
            "\n      - name:", windows_step_start + len(windows_step_name)
        )
        windows_step = workflow[windows_step_start:windows_step_end]
        if "if: matrix.secure_bridge == 'enabled'" not in windows_step:
            raise AssertionError(
                f"{workflow_path} Windows cleanup test is not secure-only"
            )
        if "provisioned" in windows_step:
            raise AssertionError(
                f"{workflow_path} ran the POSIX provisioned case on Windows"
            )
        if not (
            workflow.index("      - name: Build and test (clang-cl)")
            < windows_step_start
            < workflow.index(
                "      - name: Run Windows Application Verifier handle gate"
            )
        ):
            raise AssertionError(
                f"{workflow_path} Windows cleanup test ordering drifted"
            )


def mutate_once(files: dict[str, str], path: str, old: str, new: str) -> None:
    if files[path].count(old) != 1:
        raise AssertionError(f"self-test mutation is not isolated: {path}: {old}")
    files[path] = files[path].replace(old, new, 1)


def expect_rejected(
    baseline: dict[str, str], path: str, old: str, new: str, name: str
) -> None:
    mutated = dict(baseline)
    mutate_once(mutated, path, old, new)
    try:
        validate(mutated)
    except (AssertionError, ValueError):
        return
    raise AssertionError(f"self-test accepted mutation: {name}")


def self_test(baseline: dict[str, str]) -> None:
    store_path = "wyrelog/fact/store.c"
    completion = function_body(
        baseline[store_path], "complete_forget_intent_unlocked"
    )
    body_failures = (
        "if (duckdb_prepare (store->conn, audit_sql, &stmt) "
        "!= DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (ok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&stmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (exec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto rollback;\n  }",
        "if (duckdb_prepare (store->conn, update_sql, &ustmt) "
        "!= DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (uok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&ustmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto rollback;\n  }",
        "if (uexec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto rollback;\n  }",
    )
    for index, failure in enumerate(body_failures, 1):
        if failure not in completion:
            raise AssertionError(f"self-test cannot locate body failure {index}")
        expect_rejected(
            baseline,
            store_path,
            failure,
            failure.replace("goto rollback;", "return WYRELOG_E_IO;"),
            f"body failure {index} bypass",
        )
    expect_rejected(
        baseline,
        store_path,
        'rc = exec_sql (store->conn, "COMMIT;");\n'
        "  if (rc != WYRELOG_E_OK)\n    goto rollback;",
        'rc = exec_sql (store->conn, "COMMIT;");\n'
        "  if (rc != WYRELOG_E_OK)\n    return rc;",
        "COMMIT bypass",
    )
    expect_rejected(
        baseline,
        store_path,
        "WYL_LOG_ERROR (WYL_LOG_SECTION_IO,",
        "WYL_LOG_WARN (WYL_LOG_SECTION_IO,",
        "log downgrade",
    )
    expect_rejected(
        baseline,
        store_path,
        'rollback_rc = exec_sql (store->conn, "ROLLBACK;");',
        '(void) exec_sql (store->conn, "ROLLBACK;");',
        "discarded rollback",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction.c",
        'exec_ok (conn, "BEGIN TRANSACTION;")',
        'exec_ok (conn, "SELECT 1;")',
        "SELECT-only usability proof",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "'test-fact-store-forget-transaction.c',\n"
        "    c_args : ['-DWYL_TEST_HANDLE_SEAMS'],\n"
        "    include_directories : include_directories('../wyrelog'),\n"
        "    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep]",
        "'test-fact-store-forget-transaction.c',\n"
        "    c_args : ['-DWYL_TEST_HANDLE_SEAMS'],\n"
        "    include_directories : include_directories('../wyrelog'),\n"
        "    dependencies : [wyrelog_dep, duckdb_dep]",
        "production-linked generic test",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "test('fact-store-forget-transaction',",
        "test('removed-fact-store-forget-transaction',",
        "missing generic registration",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "test('fact-store-forget-transaction-provisioned',",
        "test('removed-fact-store-forget-transaction-provisioned',",
        "missing provisioned registration",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "test('fact-store-forget-transaction-boundary-self',",
        "test('removed-fact-store-forget-transaction-boundary-self',",
        "missing boundary self-test registration",
    )
    for workflow_path in (
        ".github/workflows/ci-pr.yml",
        ".github/workflows/ci-main.yml",
    ):
        expect_rejected(
            baseline,
            workflow_path,
            "      - name: Test fact forget transaction cleanup with secure DuckDB",
            "      - name: Removed fact forget transaction cleanup with secure DuckDB",
            f"missing POSIX cleanup step in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            "      - name: Test fact forget transaction cleanup (clang-cl)",
            "      - name: Removed fact forget transaction cleanup (clang-cl)",
            f"missing Windows cleanup step in {workflow_path}",
        )


def main() -> None:
    args = sys.argv[1:]
    self_mode = False
    if args and args[0] == "--self-test":
        self_mode = True
        args.pop(0)
    if len(args) != 1:
        raise SystemExit(f"usage: {sys.argv[0]} [--self-test] SOURCE_ROOT")
    root = Path(args[0])
    files = {
        path: (root / path).read_text(encoding="utf-8") for path in PATHS
    }
    try:
        validate(files)
        if self_mode:
            self_test(files)
    except (AssertionError, ValueError) as error:
        raise SystemExit(str(error)) from error
    suffix = " self-test" if self_mode else ""
    print(f"fact-store forget transaction boundary{suffix}: OK")


if __name__ == "__main__":
    main()

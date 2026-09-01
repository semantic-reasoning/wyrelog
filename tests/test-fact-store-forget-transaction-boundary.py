#!/usr/bin/env python3
"""Guard issue #890's checked fact-forget transaction cleanup boundary."""

from __future__ import annotations

from pathlib import Path
import sys


PATHS = (
    "wyrelog/fact/store.c",
    "wyrelog/fact/store-connection-private.h",
    "wyrelog/fact/store-private.h",
    "wyrelog/fact/store-test-seams-private.h",
    "tests/test-fact-store-forget-transaction.c",
    "tests/test-fact-store-forget-transaction-provision-helper.c",
    "tests/test-fact-store-forget-transaction-provisioned.c",
    "tests/test-fact-store-poison.c",
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


def strip_comments(source: str) -> str:
    """Blank out Meson comments, preserving every byte offset."""
    out = []
    for line in source.splitlines(keepends=True):
        hash_at = line.find("#")
        if hash_at == -1:
            out.append(line)
            continue
        keep = line[:hash_at]
        out.append(keep + " " * (len(line.rstrip("\n")) - len(keep))
                   + line[len(line.rstrip("\n")):])
    return "".join(out)


def registration_offset(meson: str, token: str) -> int:
    """Offset of a live registration -- a commented-out one does not count."""
    live = strip_comments(meson)
    if live.count(token) != 1:
        raise AssertionError(f"registration is not live exactly once: {token}")
    return live.index(token)


def enclosing_conditions(meson: str, offset: int) -> list[str]:
    """Conditions of every Meson if-block open at offset, outermost first."""
    stack: list[str] = []
    position = 0
    for line in strip_comments(meson).splitlines(keepends=True):
        if position >= offset:
            break
        stripped = line.strip()
        if stripped.startswith("if "):
            stack.append(stripped[3:].strip())
        elif stripped.startswith("elif "):
            if stack:
                stack[-1] = stripped[5:].strip()
        elif stripped == "else":
            if stack:
                stack[-1] = "not (" + stack[-1] + ")"
        elif stripped == "endif":
            if stack:
                stack.pop()
        position += len(line)
    return stack


def require_once(text: str, token: str, message: str) -> None:
    if text.count(token) != 1:
        raise AssertionError(message)


def validate(files: dict[str, str]) -> None:
    store = files["wyrelog/fact/store.c"]
    header = files["wyrelog/fact/store-private.h"]
    generic = files["tests/test-fact-store-forget-transaction.c"]
    helper_source = files[
        "tests/test-fact-store-forget-transaction-provision-helper.c"
    ]
    provisioned = files[
        "tests/test-fact-store-forget-transaction-provisioned.c"
    ]
    meson = files["tests/meson.build"]

    transaction = function_body(store, "wyl_fact_store_transaction_finish")
    completion = function_body(store, "complete_forget_intent_unlocked")
    for token, message in (
        ('rollback_rc = exec_sql (connection, "ROLLBACK;");',
         "checked cleanup must execute one real rollback"),
        ('"fact forget transaction rollback failed"',
         "rollback diagnostic literal drifted"),
        ("store->health = WYL_FACT_STORE_POISONED;",
         "rollback failure must poison before unlock"),
        ("return WYRELOG_E_INTERNAL;",
         "rollback failure must take INTERNAL precedence"),
        ("WYL_FACT_STORE_TRANSACTION_BEFORE_COMMIT",
         "common commit hook drifted"),
        ("WYL_FACT_STORE_TRANSACTION_BEFORE_ROLLBACK",
         "common rollback hook drifted"),
        ('primary_rc = exec_sql (connection, "COMMIT;");',
         "checked cleanup must execute one real commit"),
    ):
        require_once(transaction, token, message)
    if transaction.count("WYL_LOG_ERROR (WYL_LOG_SECTION_IO,") != 2:
        raise AssertionError("rollback failure diagnostics drifted")
    if "return primary_rc;" not in transaction:
        raise AssertionError("successful cleanup must preserve the primary error")
    if "duckdb_disconnect (" in transaction or "duckdb_connect (" in transaction:
        raise AssertionError("checked cleanup must not replace the connection")

    body_failures = (
        "if (duckdb_prepare (store->conn, audit_sql, &stmt) "
        "!= DuckDBSuccess) {\n    duckdb_destroy_prepare (&stmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (ok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&stmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (exec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto finish;\n  }",
        "if (duckdb_prepare (store->conn, update_sql, &ustmt) "
        "!= DuckDBSuccess) {\n    duckdb_destroy_prepare (&ustmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (uok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&ustmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (uexec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto finish;\n  }",
    )
    for index, failure in enumerate(body_failures, 1):
        require_once(
            completion,
            failure,
            f"body failure {index} escaped the common transaction finish",
        )
    require_once(
        completion,
        "wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE, &transaction)",
        "forget completion must use the common transaction owner",
    )
    require_once(
        completion,
        "finish:\n  return wyl_fact_store_transaction_finish (&transaction, rc);",
        "completion must have one checked cleanup exit",
    )
    if "(void) exec_sql" in completion:
        raise AssertionError("completion still discards transaction cleanup")

    legacy_seam_tokens = (
        "WylFactStoreForgetTransactionTestPhase",
        "WylFactStoreForgetTransactionTestHook",
        "wyl_fact_store_set_forget_transaction_test_hook",
    )
    for token in legacy_seam_tokens:
        if token not in header:
            raise AssertionError(f"private transaction seam drifted: {token}")
    header_seam = header[
        header.index("#if defined(WYL_TEST_HANDLE_SEAMS)\ntypedef enum") :
        header.index("#endif", header.index(
            "#if defined(WYL_TEST_HANDLE_SEAMS)\ntypedef enum"
        )) + len("#endif")
    ]
    for token in legacy_seam_tokens[:2]:
        if token not in header_seam:
            raise AssertionError(f"test seam escaped its compile guard: {token}")
    require_once(
        completion,
        "WYL_FACT_STORE_FORGET_TRANSACTION_AFTER_BEGIN",
        "runtime body-failure seam drifted",
    )
    require_once(
        completion,
        "WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE",
        "runtime transaction kind drifted",
    )

    generic_seam = files["wyrelog/fact/store-test-seams-private.h"]
    for token in (
        "WylFactStoreTransactionTestKind",
        "WylFactStoreTransactionTestPhase",
        "WylFactStoreTransactionTestHook",
        "wyl_fact_store_test_set_transaction_hook",
    ):
        if token not in generic_seam:
            raise AssertionError(f"generic transaction seam drifted: {token}")

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
        "wyl_fact_store_test_exec_sql (store, sql)",
        "wyl_fact_store_test_query_int64 (store, sql, &count)",
        "wyl_fact_store_create_schema (fixture->store), ==,",
        "WYRELOG_E_INTERNAL",
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

    poison = files["tests/test-fact-store-poison.c"]
    for token in (
        "WYL_FACT_STORE_TRANSACTION_TEST_FORGET_COMPLETE",
        "test_file_reopen_recovers_forget",
        "state = 'PENDING'",
        "state = 'COMPLETED'",
        "wyl_fact_store_forget_reconcile",
    ):
        if token not in poison:
            raise AssertionError(f"poison recovery proof drifted: {token}")

    require_once(
        helper_source,
        "wyl_fact_graph_provisioning_run (store, &input, root, &record)",
        "production helper must invoke provisioning exactly once",
    )
    require_once(
        helper_source,
        'wyl_test_make_secure_fact_root\n'
        '        ("wyl-fact-store-forget-transaction-XXXXXX", &error)',
        "production helper must create the secure root",
    )
    if not (
        helper_source.index("wyl_test_make_secure_fact_root")
        < helper_source.index("wyl_policy_store_open (policy_path, &store)")
        < helper_source.index("wyl_fact_graph_provisioning_run")
        < helper_source.index('g_print ("%s\\n%s\\n", root, policy_path)')
    ):
        raise AssertionError("helper create/provision/output ordering drifted")
    for forbidden in (
        "WYL_TEST_HANDLE_SEAMS",
        "wyl_fact_store_set_forget_transaction_test_hook",
    ):
        if forbidden in helper_source:
            raise AssertionError(
                f"production helper acquired test seams: {forbidden}"
            )
    if '"provisioning failed: %s (%d); stage=%d final=%d "' not in helper_source:
        raise AssertionError(
            "production helper must report symbolic and numeric failure evidence"
        )
    require_once(
        helper_source,
        'g_clear_pointer (&store, wyl_policy_store_close);\n'
        '    g_print ("%s\\n%s\\n", root, policy_path);',
        "production helper must close policy and emit both durable paths",
    )
    for constant in (
        '"01890f47-3c4b-7cc2-b8c4-dc0c0c070892"',
        '"01890f47-3c4b-7cc2-b8c4-dc0c0c070893"',
    ):
        require_once(provisioned, constant, f"fixture identity drifted: {constant}")

    provisioned_required = (
        "ProvisionedFixture *fixture = run_provision_helper ()",
        "assert_provisioned_shape (fixture->root, record->stage_basename)",
        "wyl_fact_store_open_provisioned_graph",
        "wyl_policy_store_open (fixture->policy_path, &policy_store)",
        "wyl_policy_store_graph_provisioning_list",
        "fail_commit_once",
        'exec_ok (conn, "SELECT 1;")',
        'exec_ok (conn, "BEGIN TRANSACTION;")',
        'exec_ok (conn, "ROLLBACK;")',
        "wyl_fact_store_forget_reconcile",
        "open_live (policy_store, fixture->root, &store)",
    )
    for token in provisioned_required:
        if token not in provisioned:
            raise AssertionError(f"provisioned runtime proof drifted: {token}")
    if "wyl_fact_graph_provisioning_construct" in provisioned:
        raise AssertionError("seam-linked parent must not provision the store")
    if "wyl_test_make_secure_fact_root" in provisioned:
        raise AssertionError("seam-linked parent must not create the secure root")
    if "wyl_fact_store_open (" in provisioned:
        raise AssertionError("provisioned proof must not use pathname store open")
    if provisioned.count(
        "open_live (policy_store, fixture->root, &store)"
    ) != 2:
        raise AssertionError("provisioned proof must close and reopen the store")
    helper_run = function_body(provisioned, "run_provision_helper")
    for token in (
        "g_path_is_absolute",
        "g_subprocess_newv",
        "G_SUBPROCESS_FLAGS_STDOUT_PIPE",
        "G_SUBPROCESS_FLAGS_STDERR_PIPE",
        "g_subprocess_communicate_utf8",
        "g_subprocess_get_if_exited",
        "g_subprocess_get_exit_status",
        "stderr_text == NULL || stderr_text[0] == '\\0'",
        "stdout_text[length - 1], ==, '\\n'",
        'g_strsplit (stdout_text, "\\n", -1)',
        "g_strv_length (lines), ==, 3",
        "g_assert_null (memchr (stdout_text, '\\r', length));",
    ):
        if token not in helper_run:
            raise AssertionError(f"helper subprocess contract drifted: {token}")
    if (
        "g_subprocess_launcher" in helper_run
        or "g_spawn_command_line" in helper_run
    ):
        raise AssertionError(
            "helper must execute through an absolute argv, not a shell"
        )
    require_once(
        helper_run,
        "g_assert_cmpint (g_subprocess_get_exit_status (process), ==, 0);",
        "helper exit status must be checked exactly",
    )
    shape = function_body(provisioned, "assert_provisioned_shape")
    for token in (
        '"facts.duckdb"',
        "stage_basename",
        "S_ISREG (final_status.st_mode)",
        "S_ISREG (stage_status.st_mode)",
        "final_status.st_mode & 0777, ==, 0600",
        "stage_status.st_mode & 0777, ==, 0600",
        "final_status.st_nlink, ==, 1",
        "g_file_test (stage_path, G_FILE_TEST_EXISTS)",
        "final_status.st_dev, ==, stage_status.st_dev",
        "final_status.st_ino, ==, stage_status.st_ino",
        "final_status.st_nlink, ==, 2",
        "stage_status.st_nlink, ==, 2",
    ):
        if token not in shape:
            raise AssertionError(f"provisioned-shape witness drifted: {token}")
    provisioned_test = function_body(
        provisioned, "test_provisioned_commit_failure_rolls_back"
    )
    if not (
        provisioned_test.index("run_provision_helper ()")
        < provisioned_test.index("assert_provisioned_shape")
        < provisioned_test.index(
            "open_live (policy_store, fixture->root, &store)"
        )
    ):
        raise AssertionError("persisted provisioning handoff ordering drifted")
    if provisioned_test.count("assert_provisioned_shape") != 2:
        raise AssertionError(
            "provisioned shape must be checked before and after use"
        )

    generic_target = call_body(
        meson, "test_fact_store_forget_transaction = executable("
    )
    if "wyrelog_handle_test_seams_dep" not in generic_target:
        raise AssertionError("generic test must link the seam archive")
    if "dependencies : [wyrelog_dep" in generic_target:
        raise AssertionError("generic test must not dual-link production wyrelog")
    helper_target = call_body(
        meson,
        "test_fact_store_forget_transaction_provision_helper = executable(",
    )
    if (
        "dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep]"
        not in helper_target
        or "'fact-test-support.c'" not in helper_target
        or "c_args : fact_test_support_c_args" not in helper_target
        or "+ fact_test_support_deps" not in helper_target
    ):
        raise AssertionError("provision helper lost production root support")
    if (
        "wyrelog_handle_test_seams_dep" in helper_target
        or "WYL_TEST_HANDLE_SEAMS" in helper_target
    ):
        raise AssertionError("provision helper must not link test seams")
    provisioned_target = call_body(
        meson,
        "test_fact_store_forget_transaction_provisioned = executable(",
    )
    if "wyrelog_handle_test_seams_dep" not in provisioned_target:
        raise AssertionError("provisioned test must link the seam archive")
    if "wyrelog_dep" in provisioned_target:
        raise AssertionError("provisioned test must not dual-link production wyrelog")
    if "fact-test-support.c" in provisioned_target:
        raise AssertionError("seam parent must not own secure-root test support")
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
    provisioned_registration_body = call_body(
        meson, "test('fact-store-forget-transaction-provisioned',"
    )
    if (
        "test_fact_store_forget_transaction_provision_helper.full_path()"
        not in provisioned_registration_body
        or "depends : test_fact_store_forget_transaction_provision_helper"
        not in provisioned_registration_body
    ):
        raise AssertionError("provisioned runtime lost its helper dependency")
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
    generic_registration = registration_offset(
        meson, "test('fact-store-forget-transaction',"
    )
    for condition in enclosing_conditions(meson, generic_registration):
        if "host_machine.system()" in condition:
            raise AssertionError(
                "generic runtime must stay registered on Windows, but it is "
                f"under: {condition}"
            )
    generic_body = call_body(
        meson[generic_registration:], "test('fact-store-forget-transaction',"
    )
    if "should_fail" in generic_body:
        raise AssertionError("generic runtime was registered as should_fail")
    if (
        meson.index("test_fact_store_forget_transaction = executable(")
        > generic_registration
    ):
        raise AssertionError("generic executable must precede its registration")

    control_registration = meson.index("test('fact-store-provisioned',")
    control_guard = meson.rfind(
        "if host_machine.system() != 'windows'", 0, control_registration
    )
    control_guard_end = meson.find("\n  endif", control_guard)
    if control_guard == -1 or control_guard_end < control_registration:
        raise AssertionError("provisioning control escaped its POSIX guard")
    if meson.index("test_fact_store_provisioned = executable(") > control_guard:
        raise AssertionError("provisioning control executable became Linux-only")

    provisioned_executable = meson.index(
        "test_fact_store_forget_transaction_provisioned = executable("
    )
    provisioned_registration = meson.index(
        "test('fact-store-forget-transaction-provisioned',"
    )
    posix_guard = meson.rfind(
        "if host_machine.system() != 'windows'", 0, provisioned_executable
    )
    guard_end = meson.find("\n  endif", posix_guard)
    if posix_guard == -1 or guard_end < provisioned_registration:
        raise AssertionError("provisioned executable escaped its POSIX guard")
    helper_executable = meson.index(
        "test_fact_store_forget_transaction_provision_helper = executable("
    )
    if not (
        posix_guard < helper_executable < provisioned_executable
        < provisioned_registration
    ):
        raise AssertionError("provisioning executables became Linux-only")
    if (
        "if host_machine.system() == 'linux'\n"
        "      test('fact-store-forget-transaction-provisioned',"
        in meson
    ):
        raise AssertionError("provisioned runtime became Linux-only")
    require_once(
        meson,
        "# evidence-backed direct-final Darwin.",
        "Meson lost the audited Darwin provisioning runtime",
    )

    posix_step_name = (
        "      - name: Test fact forget transaction cleanup with secure DuckDB"
    )
    posix_commands = (
        "meson compile -C build-secure-duckdb -j 1 \\\n"
        "            test-fact-store-provisioned \\\n"
        "            test-fact-store-forget-transaction \\\n"
        "            test-fact-store-forget-transaction-provision-helper \\\n"
        "            test-fact-store-forget-transaction-provisioned\n"
        "          meson test -C build-secure-duckdb --no-rebuild \\\n"
        "            fact-store-provisioned \\\n"
        "            fact-store-forget-transaction \\\n"
        "            fact-store-forget-transaction-provisioned \\\n"
        "            --print-errorlogs"
    )
    windows_step_name = (
        "      - name: Test fact forget transaction cleanup seam (clang-cl)"
    )
    windows_commands = (
        "meson compile -C builddir test-fact-store-forget-transaction\n"
        "          meson test -C builddir fact-store-forget-transaction "
        "--no-rebuild --print-errorlogs"
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
        posix_step_start = workflow.index(posix_step_name)
        posix_step_end = workflow.index(
            "\n      - name:", posix_step_start + len(posix_step_name)
        )
        posix_step = workflow[posix_step_start:posix_step_end]
        if "runner.os == 'Linux'" in posix_step:
            raise AssertionError(
                f"{workflow_path} restricted the entire POSIX step to Linux"
            )
        for forbidden in (
            "continue-on-error",
            "|| true",
            "retry",
            "exit 77",
            "NDEBUG",
        ):
            if forbidden in posix_step:
                raise AssertionError(
                    f"{workflow_path} tolerated a POSIX cleanup failure: "
                    f"{forbidden}"
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
        for forbidden in (
            "NDEBUG",
            "b_ndebug",
            "continue-on-error",
            "|| true",
            "exit /b",
            "-ErrorAction SilentlyContinue",
            "$ErrorActionPreference = 'Continue'",
            "retry",
            "--no-suite",
        ):
            if forbidden in windows_step:
                raise AssertionError(
                    f"{workflow_path} tolerated a Windows cleanup failure: "
                    f"{forbidden}"
                )
        if "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" not in windows_step:
            raise AssertionError(
                f"{workflow_path} Windows cleanup result is not propagated"
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
    baseline: dict[str, str],
    path: str,
    old: str,
    new: str,
    name: str,
    expect: str | None = None,
) -> None:
    mutated = dict(baseline)
    mutate_once(mutated, path, old, new)
    try:
        validate(mutated)
    except (AssertionError, ValueError) as error:
        if expect is not None and expect not in str(error):
            raise AssertionError(
                f"mutation {name} died on the wrong assertion: {error}"
            ) from error
        return
    raise AssertionError(f"self-test accepted mutation: {name}")


def self_test(baseline: dict[str, str]) -> None:
    store_path = "wyrelog/fact/store.c"
    completion = function_body(
        baseline[store_path], "complete_forget_intent_unlocked"
    )
    body_failures = (
        "if (duckdb_prepare (store->conn, audit_sql, &stmt) "
        "!= DuckDBSuccess) {\n    duckdb_destroy_prepare (&stmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (ok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&stmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (exec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto finish;\n  }",
        "if (duckdb_prepare (store->conn, update_sql, &ustmt) "
        "!= DuckDBSuccess) {\n    duckdb_destroy_prepare (&ustmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (uok != DuckDBSuccess) {\n    duckdb_destroy_prepare (&ustmt);\n"
        "    rc = WYRELOG_E_IO;\n    goto finish;\n  }",
        "if (uexec != DuckDBSuccess) {\n    rc = WYRELOG_E_IO;\n"
        "    goto finish;\n  }",
    )
    for index, failure in enumerate(body_failures, 1):
        if failure not in completion:
            raise AssertionError(f"self-test cannot locate body failure {index}")
        expect_rejected(
            baseline,
            store_path,
            failure,
            failure.replace("goto finish;", "return WYRELOG_E_IO;"),
            f"body failure {index} bypass",
        )
    expect_rejected(
        baseline,
        store_path,
        'primary_rc = exec_sql (connection, "COMMIT;");',
        "primary_rc = WYRELOG_E_IO;",
        "COMMIT bypass",
    )
    expect_rejected(
        baseline,
        store_path,
        'WYL_LOG_ERROR (WYL_LOG_SECTION_IO,\n'
        '          "fact forget transaction rollback failed");',
        'WYL_LOG_WARN (WYL_LOG_SECTION_IO,\n'
        '          "fact forget transaction rollback failed");',
        "log downgrade",
    )
    expect_rejected(
        baseline,
        store_path,
        'rollback_rc = exec_sql (connection, "ROLLBACK;");',
        '(void) exec_sql (connection, "ROLLBACK;");',
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
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provision-helper.c",
        "rc = wyl_fact_graph_provisioning_run (store, &input, root, &record);",
        "rc = wyl_fact_graph_provisioning_run (store, &input, root, &record);\n"
        "  rc = wyl_fact_graph_provisioning_run "
        "(store, &input, root, &record);",
        "duplicate production provisioning",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provision-helper.c",
        'g_clear_pointer (&store, wyl_policy_store_close);\n'
        '    g_print ("%s\\n%s\\n", root, policy_path);',
        'g_print ("%s\\n%s\\n", root, policy_path);\n'
        "  g_clear_pointer (&store, wyl_policy_store_close);",
        "ignored production provisioning failure",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provision-helper.c",
        'wyl_test_make_secure_fact_root\n'
        '        ("wyl-fact-store-forget-transaction-XXXXXX", &error)',
        'g_dir_make_tmp ("wyl-fact-store-forget-transaction-XXXXXX", &error)',
        "missing helper-owned secure root",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provisioned.c",
        "ProvisionedFixture *fixture = run_provision_helper ();",
        "ProvisionedFixture *fixture = run_provision_helper ();\n"
        "  wyl_fact_graph_provisioning_construct "
        "(fixture->root, NULL, NULL);",
        "seam-linked direct provisioning",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provisioned.c",
        "ProvisionedFixture *fixture = run_provision_helper ();",
        "ProvisionedFixture *fixture = NULL;\n"
        "  g_autofree gchar *root = wyl_test_make_secure_fact_root "
        "(\"bad-XXXXXX\", NULL);",
        "seam-parent secure-root creation",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provisioned.c",
        "g_subprocess_get_exit_status (process), ==, 0",
        "g_subprocess_get_exit_status (process), >=, 0",
        "ignored helper exit status",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provisioned.c",
        "g_assert_cmpuint (g_strv_length (lines), ==, 3);",
        "g_assert_cmpuint (g_strv_length (lines), >=, 2);",
        "accepted multiple helper output records",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provisioned.c",
        "g_assert_null (memchr (stdout_text, '\\r', length));",
        "(void) memchr (stdout_text, '\\r', length);",
        "accepted carriage return in helper output",
    )
    expect_rejected(
        baseline,
        "tests/test-fact-store-forget-transaction-provisioned.c",
        "final_status.st_mode & 0777, ==, 0600",
        "final_status.st_mode & 0777, !=, 0",
        "missing retained-pair mode proof",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "'test-fact-store-forget-transaction-provision-helper.c',\n"
        "      'fact-test-support.c',\n"
        "      c_args : fact_test_support_c_args,\n"
        "      include_directories : include_directories('../wyrelog'),\n"
        "      dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep]\n"
        "        + fact_test_support_deps",
        "'test-fact-store-forget-transaction-provision-helper.c',\n"
        "      'fact-test-support.c',\n"
        "      c_args : fact_test_support_c_args,\n"
        "      include_directories : include_directories('../wyrelog'),\n"
        "      dependencies : [wyrelog_handle_test_seams_dep, sqlite_dep, "
        "duckdb_dep]\n        + fact_test_support_deps",
        "seam-linked production helper",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "'test-fact-store-forget-transaction-provision-helper.c',\n"
        "      'fact-test-support.c',",
        "'test-fact-store-forget-transaction-provision-helper.c',",
        "helper without secure-root test support",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "'test-fact-store-forget-transaction-provisioned.c',\n"
        "      c_args :",
        "'test-fact-store-forget-transaction-provisioned.c',\n"
        "      'fact-test-support.c',\n      c_args :",
        "seam parent with secure-root test support",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "'test-fact-store-forget-transaction-provisioned.c',\n"
        "      c_args : ['-DWYL_HAS_SECURE_DUCKDB_BRIDGE', "
        "'-DWYL_TEST_HANDLE_SEAMS'],\n"
        "      include_directories : include_directories('../wyrelog'),\n"
        "      dependencies : [wyrelog_handle_test_seams_dep, sqlite_dep, "
        "duckdb_dep]",
        "'test-fact-store-forget-transaction-provisioned.c',\n"
        "      c_args : ['-DWYL_HAS_SECURE_DUCKDB_BRIDGE', "
        "'-DWYL_TEST_HANDLE_SEAMS'],\n"
        "      include_directories : include_directories('../wyrelog'),\n"
        "      dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep]",
        "production-linked seam parent",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "args : [test_fact_store_forget_transaction_provision_helper."
        "full_path()],",
        "args : [],",
        "missing provision helper path",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "depends : test_fact_store_forget_transaction_provision_helper,",
        "depends : test_fact_store_forget_transaction_provisioned,",
        "missing provision helper build dependency",
    )
    generic_registration = (
        "  test('fact-store-forget-transaction',\n"
        "    test_fact_store_forget_transaction,\n"
        "    timeout : 60,\n"
        "  )"
    )
    indented = "  " + generic_registration.replace("\n", "\n  ")
    expect_rejected(
        baseline,
        "tests/meson.build",
        generic_registration,
        "  if host_machine.system() != 'windows'\n" + indented + "\n  endif",
        "Windows runtime registration withdrawn",
        expect="generic runtime must stay registered on Windows",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        generic_registration,
        "  if host_machine.system() == 'windows'\n  else\n"
        + indented + "\n  endif",
        "Windows runtime registration withdrawn by an inverted guard",
        expect="generic runtime must stay registered on Windows",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        generic_registration,
        generic_registration.replace(
            "    timeout : 60,\n", "    timeout : 60,\n    should_fail : true,\n"
        ),
        "Windows runtime registered as should_fail",
        expect="registered as should_fail",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        generic_registration,
        "\n".join("#" + line for line in generic_registration.splitlines()),
        "Windows runtime registration commented out",
        expect="registration is not live exactly once",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "if host_machine.system() != 'windows'\n"
        "    test('fact-store-provisioned',",
        "if host_machine.system() == 'linux'\n"
        "    test('fact-store-provisioned',",
        "Linux-only provisioning control registration",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "    if host_machine.system() != 'windows'\n"
        "      test('fact-store-forget-transaction-provisioned',",
        "    if host_machine.system() == 'linux'\n"
        "      test('fact-store-forget-transaction-provisioned',",
        "Linux-only provisioned cleanup registration",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "if host_machine.system() != 'windows'\n"
        "    test_fact_store_forget_transaction_provision_helper = executable(",
        "if host_machine.system() == 'linux'\n"
        "    test_fact_store_forget_transaction_provision_helper = executable(",
        "Linux-only provisioning executable definitions",
    )
    expect_rejected(
        baseline,
        "tests/meson.build",
        "# evidence-backed direct-final Darwin.",
        "# direct-final Darwin.",
        "missing Meson Darwin evidence boundary",
    )
    workflow_runtime_block = (
        "          meson test -C build-secure-duckdb --no-rebuild \\\n"
        "            fact-store-provisioned \\\n"
        "            fact-store-forget-transaction \\\n"
        "            fact-store-forget-transaction-provisioned \\\n"
        "            --print-errorlogs"
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
            workflow_runtime_block,
            '          if [ "$RUNNER_OS" = Linux ]; then\n'
            + workflow_runtime_block.replace("          ", "            ", 1)
            + "\n          fi",
            f"Linux-only provisioned runtimes in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            "            test-fact-store-provisioned \\\n",
            "",
            f"missing macOS provisioning control compile in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            "            test-fact-store-forget-transaction-provision-helper \\\n",
            "",
            f"missing macOS helper compile in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            "            test-fact-store-forget-transaction-provisioned\n",
            "",
            f"missing macOS provisioned cleanup compile in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            "          meson test -C build-secure-duckdb --no-rebuild \\\n"
            "            fact-store-provisioned \\\n"
            "            fact-store-forget-transaction \\\n"
            "            fact-store-forget-transaction-provisioned \\\n"
            "            --print-errorlogs",
            "          meson test -C build-secure-duckdb --no-rebuild \\\n"
            "            fact-store-forget-transaction \\\n"
            "            fact-store-forget-transaction-provisioned \\\n"
            "            --print-errorlogs",
            f"missing macOS provisioning control runtime in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            workflow_runtime_block,
            workflow_runtime_block.replace(
                "            fact-store-forget-transaction \\\n", "", 1
            ),
            f"missing generic macOS runtime in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            workflow_runtime_block,
            workflow_runtime_block.replace(
                "            fact-store-forget-transaction-provisioned \\\n",
                "",
                1,
            ),
            f"missing macOS provisioned cleanup runtime in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            workflow_runtime_block,
            workflow_runtime_block + " || true",
            f"tolerated provisioned macOS failure in {workflow_path}",
        )
        expect_rejected(
            baseline,
            workflow_path,
            "      - name: Test fact forget transaction cleanup seam (clang-cl)",
            "      - name: Removed fact forget transaction cleanup seam (clang-cl)",
            f"missing Windows cleanup step in {workflow_path}",
            expect="must have one Windows secure cleanup step",
        )
        windows_runtime_line = (
            "\n          meson test -C builddir fact-store-forget-transaction "
            "--no-rebuild --print-errorlogs"
        )
        expect_rejected(
            baseline,
            workflow_path,
            windows_runtime_line,
            "",
            f"return to compile-only Windows evidence in {workflow_path}",
            expect="Windows secure cleanup commands drifted",
        )
        expect_rejected(
            baseline,
            workflow_path,
            windows_runtime_line,
            windows_runtime_line + " || true",
            f"tolerated Windows cleanup failure in {workflow_path}",
            expect="tolerated a Windows cleanup failure",
        )
        expect_rejected(
            baseline,
            workflow_path,
            windows_runtime_line,
            windows_runtime_line + "\n          exit /b 0",
            f"batch-masked Windows cleanup failure in {workflow_path}",
            expect="tolerated a Windows cleanup failure: exit /b",
        )
        expect_rejected(
            baseline,
            workflow_path,
            "          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n\n"
            "      - name: Test fact-store DuckDB hardening (clang-cl)",
            "\n      - name: Test fact-store DuckDB hardening (clang-cl)",
            f"discarded Windows cleanup exit code in {workflow_path}",
            expect="Windows cleanup result is not propagated",
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

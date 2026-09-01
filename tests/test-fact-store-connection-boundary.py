#!/usr/bin/env python3
"""Keep DuckDB fact-store authority scoped, role-gated, and test-only."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROLE_HEADER = "wyrelog/fact/store-connection-private.h"
CONFIG_SEAM_HEADER = "wyrelog/fact/store-duckdb-config-test-seams-private.h"
ROLE_OWNERS = {
    "wyrelog/fact/store.c",
    "wyrelog/fact/compound.c",
    "wyrelog/fact/replay.c",
}
OLD_AUTHORITY = (
    "wyl_fact_store_get_connection",
    "wyl_fact_store_lock",
    "wyl_fact_store_unlock",
)
SEAM_SYMBOLS = (
    "wyl_fact_store_test_set_transaction_hook",
    "wyl_fact_store_test_set_session_admission_hook",
    "wyl_fact_store_test_try_lock",
    "wyl_fact_store_test_session_admission_count",
    "wyl_fact_store_test_duckdb_call_count",
    "wyl_fact_store_test_exec_sql",
    "wyl_fact_store_test_query_int64",
    "wyl_fact_store_test_query_text",
    "wyl_fact_store_test_rename_metadata_value_column_at_checkpoint",
)


def target_block(meson: str, name: str) -> str:
    name_at = meson.index(f"'{name}'")
    start = meson.rfind("executable(", 0, name_at)
    if start < 0:
        raise AssertionError(f"target declaration missing: {name}")
    end = meson.index("\n  )", start)
    return meson[start:end]


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
                return source[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def validate(files: dict[str, str]) -> None:
    role_header = files[ROLE_HEADER]
    config_seam_header = files[CONFIG_SEAM_HEADER]
    seam_header = files["wyrelog/fact/store-test-seams-private.h"]
    store_header = files["wyrelog/fact/store-private.h"]
    store = files["wyrelog/fact/store.c"]
    compound = files["wyrelog/fact/compound.c"]
    replay = files["wyrelog/fact/replay.c"]
    meson = files["tests/meson.build"]

    if '#include "store-duckdb-config-test-seams-private.h"' not in store:
        raise AssertionError("DuckDB configuration seam include was lost")
    if config_seam_header.count("#if defined(WYL_TEST_HANDLE_SEAMS)") != 1:
        raise AssertionError("DuckDB configuration seams escaped their test guard")
    for declaration in (
        "guint duckdb_configured_settings;",
        "gboolean duckdb_read_only;",
    ):
        if declaration not in store:
            raise AssertionError(
                f"DuckDB configuration field was lost: {declaration}"
            )

    for token in OLD_AUTHORITY:
        offenders = [path for path, text in files.items() if token in text]
        if offenders:
            raise AssertionError(f"legacy raw authority remains: {token}: {offenders}")

    include = '#include "store-connection-private.h"'
    owners = {path for path, text in files.items() if include in text}
    if owners != ROLE_OWNERS:
        raise AssertionError(f"connection role owners drifted: {sorted(owners)}")
    if "#if !defined(WYL_FACT_STORE_CONNECTION_ROLE)" not in role_header:
        raise AssertionError("connection role header lost its inclusion gate")
    if "duckdb_connection" in store_header:
        raise AssertionError("general store-private header exposes DuckDB authority")
    for path in ROLE_OWNERS:
        text = files[path]
        escape_patterns = {
            "static storage": r"\bstatic\s+WylFactStoreConnectionSession\b",
            "global storage":
                r"(?m)^(?:extern\s+)?WylFactStoreConnectionSession\s*\*?\s*\w+\s*(?:=[^;]*)?;",
            "context field":
                r"typedef\s+(?:struct|union)(?:\s+\w+)?\s*\{[^}]*\bWylFactStoreConnectionSession\b",
            "heap allocation":
                r"(?:g_new0?|g_malloc0?)\s*\([^;]*\bWylFactStoreConnectionSession\b",
            "session return":
                r"(?m)^WylFactStoreConnectionSession\s*\*?\s*\w+\s*\(",
            "thread escape": r"\bg_thread_new\s*\(",
        }
        for escape, pattern in escape_patterns.items():
            if re.search(pattern, text):
                raise AssertionError(
                    f"connection session {escape} escaped its scope: {path}"
                )
        session_names = set(re.findall(
            r"WylFactStoreConnectionSession\s+(\w+)\s*=", text
        ))
        pointer_session_names = set(re.findall(
            r"WylFactStoreConnectionSession\s*\*\s*(\w+)", text
        ))
        session_names.update(pointer_session_names)
        allowed_address_calls = {
            "wyl_fact_store_connection_session_begin",
            "wyl_fact_store_connection_session_get",
            "wyl_fact_store_connection_session_end",
            "wyl_fact_store_transaction_begin",
            "execute_forget_intent_unlocked",
        }
        for name in session_names:
            opaque_type = r"(?:gpointer|void\s*\*|guintptr|uintptr_t)"
            cast_type = (
                r"(?:const\s+)?[A-Za-z_]\w*"
                r"(?:\s+(?:const\s+)?[A-Za-z_]\w*)*\s*\*?"
            )
            any_cast = rf"\(\s*{cast_type}\s*\)\s*"
            generic = (
                rf"\b{opaque_type}\s+\w+\s*=\s*"
                rf"(?:{any_cast})?&?\s*{re.escape(name)}\b"
            )
            if re.search(generic, text):
                raise AssertionError(
                    f"connection session entered generic storage: {path}: {name}"
                )
            session_cast = rf"{any_cast}&?\s*{re.escape(name)}\b"
            if re.search(session_cast, text):
                raise AssertionError(
                    f"connection session cast to opaque storage: {path}: {name}"
                )
            opaque_return = (
                rf"\breturn\s+(?:{any_cast})?"
                rf"&?\s*{re.escape(name)}\s*;"
            )
            if re.search(opaque_return, text):
                raise AssertionError(
                    f"connection session escaped by return: {path}: {name}"
                )
            assignment = re.compile(
                rf"(?<![=!<>])=(?!=)\s*(?:{any_cast})?"
                rf"&?\s*{re.escape(name)}\s*;"
            )
            for assigned in assignment.finditer(text):
                statement = text[max(0, assigned.start() - 80):assigned.end()]
                if "transaction->session = session;" in statement:
                    continue
                raise AssertionError(
                    f"connection session escaped by alias: {path}: {name}"
                )
            address = re.compile(rf"(?<!&)&\s*{re.escape(name)}\b")
            for match in address.finditer(text):
                before = text[:match.start()]
                if re.search(r"=\s*(?:\(\s*gpointer\s*\)\s*)?$", before[-80:]):
                    raise AssertionError(
                        f"connection session address escaped by assignment: {path}: {name}"
                    )
                call_open = before.rfind("(")
                call_prefix = before[max(0, call_open - 128):call_open] \
                    if call_open >= 0 else ""
                caller = re.search(r"([A-Za-z_]\w*)\s*$", call_prefix) \
                    if call_open >= 0 else None
                if caller is None or caller.group(1) not in allowed_address_calls:
                    raise AssertionError(
                        f"connection session address forwarded to helper: {path}: {name}"
                    )
        allowed_pointer_calls = {
            "memset",
            "g_private_set",
            "connection_session_is_current",
            "wyl_fact_store_transaction_begin",
            "complete_forget_intent_unlocked",
        }
        for name in pointer_session_names:
            bare_argument = re.compile(
                rf"(?<=[(,])\s*{re.escape(name)}\s*(?=[,)])"
            )
            for match in bare_argument.finditer(text):
                depth = 0
                call_open = None
                for index in range(match.start() - 1, -1, -1):
                    if text[index] == ")":
                        depth += 1
                    elif text[index] == "(":
                        if depth == 0:
                            call_open = index
                            break
                        depth -= 1
                call_prefix = text[max(0, call_open - 128):call_open] \
                    if call_open is not None else ""
                caller = re.search(r"([A-Za-z_]\w*)\s*$", call_prefix)
                if caller is None or caller.group(1) not in allowed_pointer_calls:
                    raise AssertionError(
                        f"connection session pointer forwarded to helper: {path}: {name}"
                    )
    expected_calls = {
        "wyrelog/fact/store.c": (14, 16),
        "wyrelog/fact/compound.c": (5, 7),
        "wyrelog/fact/replay.c": (3, 3),
    }
    for path, (begins, ends) in expected_calls.items():
        text = files[path]
        if text.count("wyl_fact_store_connection_session_begin") != begins:
            raise AssertionError(f"connection session begin inventory drifted: {path}")
        if text.count("wyl_fact_store_connection_session_end") != ends:
            raise AssertionError(f"connection session end inventory drifted: {path}")
    session_functions = {
        "wyrelog/fact/store.c": (
            "wyl_fact_store_test_exec_sql",
            "wyl_fact_store_test_query_int64",
            "wyl_fact_store_test_query_text",
            "wyl_fact_store_create_schema",
            "wyl_fact_store_table_exists",
            "wyl_fact_store_ensure_projection",
            "wyl_fact_store_validate_projection",
            "wyl_fact_store_append_batch_delta (wyl_fact_store_t *store",
            "wyl_fact_store_retract_by_batch_id",
            "wyl_fact_store_count_projection_batch_rows",
            "wyl_fact_store_forget (",
            "wyl_fact_store_forget_pending_count",
            "wyl_fact_store_forget_reconcile (wyl_fact_store_t *store",
        ),
        "wyrelog/fact/compound.c": (
            "wyl_fact_compound_create_schema",
            "wyl_fact_compound_ref_exists",
            "wyl_fact_compound_put",
            "wyl_fact_compound_replay",
            "wyl_fact_compound_replay_cached",
        ),
        "wyrelog/fact/replay.c": (
            "list_replay_relations",
            "replay_relation_into_engine",
        ),
    }
    call = "wyl_fact_store_connection_session_end (&session);"
    for path, signatures in session_functions.items():
        for signature in signatures:
            body = function_body(files[path], signature)
            ends_at = []
            offset = 0
            while True:
                found = body.find(call, offset)
                if found < 0:
                    break
                ends_at.append(found + len(call))
                offset = found + len(call)
            if not ends_at:
                raise AssertionError(f"session owner lost release: {signature}")
            for after in ends_at[:-1]:
                if not body[after:].lstrip().startswith("return "):
                    raise AssertionError(
                        f"non-final session release lacks terminal return: {signature}"
                    )
            released = body[ends_at[-1]:]
            if "duckdb_" in released or re.search(r"\bconn\b", released):
                raise AssertionError(
                    f"stale DuckDB authority used after session end: {signature}"
                )

    if "#if !defined(WYL_TEST_HANDLE_SEAMS)" not in seam_header:
        raise AssertionError("fact-store seams lost their compile-time gate")
    for symbol in SEAM_SYMBOLS:
        if symbol not in seam_header:
            raise AssertionError(f"fact-store seam declaration missing: {symbol}")
        if store.count(symbol) != 1:
            raise AssertionError(f"fact-store seam definition drifted: {symbol}")
    seam_start = store.index(
        "#if defined(WYL_TEST_HANDLE_SEAMS)\nvoid\n"
        "wyl_fact_store_test_set_transaction_hook"
    )
    seam_end = store.index("#endif", seam_start)
    seam_region = store[seam_start:seam_end]
    if any(symbol not in seam_region for symbol in SEAM_SYMBOLS):
        raise AssertionError("fact-store seam escaped the test-only source guard")

    begin = function_body(store, "wyl_fact_store_connection_session_begin")
    for token in (
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "if (!g_mutex_trylock (&store->lock))",
        "store->session_admission_test_hook",
        "g_mutex_lock (&store->lock);",
        "store->health == WYL_FACT_STORE_POISONED",
        "g_mutex_unlock (&store->lock);",
        "return WYRELOG_E_INTERNAL;",
    ):
        if token not in begin:
            raise AssertionError(f"checked session acquisition drifted: {token}")
    test_lock = begin.index("if (!g_mutex_trylock (&store->lock))")
    admission = begin.index("store->session_admission_test_hook", test_lock)
    blocking_lock = begin.index("g_mutex_lock (&store->lock);", admission)
    production_lock = begin.index("#else\n  g_mutex_lock (&store->lock);")
    if not (
        begin.index("g_private_get (&active_connection_session)")
        < begin.index("if (active != NULL)\n    return WYRELOG_E_INTERNAL;")
        < test_lock
        < admission
        < blocking_lock
        < production_lock
        < begin.index("store->health == WYL_FACT_STORE_POISONED")
        < begin.index("session->connection = store->conn;")
    ):
        raise AssertionError("session acquisition no longer checks health under lock")
    connection_bind = begin.index("session->connection = store->conn;")
    admission_prefix = begin[:connection_bind]
    if re.search(r"\bduckdb_\w+\s*\(", admission_prefix) \
            or re.search(r"\bstore->(?:conn|db)\b", admission_prefix):
        raise AssertionError("DuckDB access occurs before TLS and health admission")
    prefix_calls = set(re.findall(
        r"\b([A-Za-z_]\w*)\s*\(", admission_prefix
    ))
    allowed_prefix_calls = {
        "wyl_fact_store_connection_session_begin",
        "if",
        "sizeof",
        "defined",
        "memset",
        "g_private_get",
        "g_mutex_trylock",
        "session_admission_test_hook",
        "g_mutex_lock",
        "g_mutex_unlock",
    }
    if prefix_calls != allowed_prefix_calls:
        raise AssertionError(
            "session admission prefix call inventory drifted: "
            f"{sorted(prefix_calls ^ allowed_prefix_calls)}"
        )
    for token in (
        "store->session_owner != NULL",
        "session->owner = g_thread_self ();",
        "store->session_owner = session->owner;",
        "g_private_set (&active_connection_session, session);",
    ):
        if token not in begin:
            raise AssertionError(f"session ownership/reentry fence drifted: {token}")
    current = function_body(store, "connection_session_is_current")
    for token in (
        "session->owner == g_thread_self ()",
        "session->store->session_owner == session->owner",
        "g_private_get (&active_connection_session) == session",
    ):
        if token not in current:
            raise AssertionError(f"current-session ownership check drifted: {token}")
    session_get = function_body(
        store, "wyl_fact_store_connection_session_get"
    )
    if "connection_session_is_current (session)" not in session_get:
        raise AssertionError("session get bypasses current-session validation")
    end_session = function_body(store, "wyl_fact_store_connection_session_end")
    for token in (
        "connection_session_is_current (session)",
        "store->session_owner = NULL;",
        "g_private_set (&active_connection_session, NULL);",
        "g_mutex_unlock (&store->lock);",
    ):
        if token not in end_session:
            raise AssertionError(f"session ownership cleanup drifted: {token}")

    transaction_begin = function_body(store, "wyl_fact_store_transaction_begin")
    if "connection_session_is_current (session)" not in transaction_begin:
        raise AssertionError("transaction begin bypasses current-session validation")

    finish = function_body(store, "wyl_fact_store_transaction_finish")
    for token in (
        "connection_session_is_current (transaction->session)",
        "WYL_FACT_STORE_TRANSACTION_BEFORE_COMMIT",
        "WYL_FACT_STORE_TRANSACTION_BEFORE_ROLLBACK",
        'exec_sql (connection, "COMMIT;")',
        'exec_sql (connection, "ROLLBACK;")',
        "store->health = WYL_FACT_STORE_POISONED;",
        '"fact store transaction rollback failed"',
        '"fact forget transaction rollback failed"',
        "return WYRELOG_E_INTERNAL;",
        "return primary_rc;",
    ):
        if token not in finish:
            raise AssertionError(f"common transaction cleanup drifted: {token}")
    if finish.index("store->health = WYL_FACT_STORE_POISONED;") > finish.index(
        "return WYRELOG_E_INTERNAL;"
    ):
        raise AssertionError("rollback failure returns before poisoning the store")

    kind_owners = {
        "wyl_fact_store_append_batch_delta (wyl_fact_store_t *store":
            "WYL_FACT_STORE_TRANSACTION_APPEND_CORE",
        "wyl_fact_store_retract_by_batch_id":
            "WYL_FACT_STORE_TRANSACTION_RETRACT_BY_BATCH",
        "complete_forget_intent_unlocked":
            "WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE",
    }
    for signature, kind in kind_owners.items():
        if kind not in function_body(store, signature):
            raise AssertionError(f"transaction owner kind drifted: {signature}")
    if "WYL_FACT_STORE_TRANSACTION_COMPOUND_PUT" not in function_body(
        compound, "wyl_fact_compound_put"
    ):
        raise AssertionError("compound transaction owner kind drifted")

    poison_runtime = files["tests/test-fact-store-poison.c"]
    runtime_tokens = (
        "test_waiter_and_poisoned_matrix",
        "wyl_fact_store_test_try_lock",
        "g_assert_false(wyl_fact_store_test_try_lock(store));",
        "test_retract_owner_poison",
        "test_append_backed_retract_owner_poison",
        "test_compound_owner_poison",
        "test_same_thread_reentry_fails_closed",
        "test_cross_store_reentry_fails_closed",
        "test_file_reopen_recovers_forget",
        "wyl_fact_store_test_duckdb_call_count",
        "wyl_fact_store_forget_reconcile",
        "WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE",
        "WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH",
        "WYL_FACT_STORE_TRANSACTION_TEST_COMPOUND_PUT",
        "WYL_FACT_STORE_TRANSACTION_TEST_FORGET_COMPLETE",
        "wyl_fact_store_test_set_session_admission_hook",
        "while (!gate.entered)",
        "probe.nested_rc, ==, WYRELOG_E_INTERNAL",
        "wyl_fact_replay_open_graph_engine_with_store_for_test",
        "g_assert_null(replay_engine);",
        ".decl poison_marker(value: int64)",
        ".decl poison_marker_observed(value: int64)",
        "poison_marker_observed(V) :- poison_marker(V).",
        "g_assert_cmpuint(marker.rows, ==, 1);",
        "g_assert_cmpint(marker.value, ==, 918);",
        "g_hash_table_size(handles), ==, 1",
        "wyl_fact_store_test_duckdb_call_count(store), ==,",
        "duckdb_calls);",
        "WHERE batch_id = 'owner-retract';",
        "WHERE batch_id = 'owner-seed';",
        "SELECT COUNT(*) FROM compound_terms;",
        "WHERE batch_id = 'retract-core-attempt';",
        "WHERE batch_id = 'retract-core-seed';",
        "SELECT COUNT(*) FROM fact_event_log;",
        'store, &schema, "poison-append"',
    )
    for token in runtime_tokens:
        if token not in poison_runtime:
            raise AssertionError(f"poison runtime proof drifted: {token}")

    matrix = function_body(poison_runtime, "assert_poisoned_api_matrix")
    if matrix.count("wyl_engine_insert(") != 1:
        raise AssertionError("poison engine setup/mutation inventory drifted")
    if matrix.count("assert_engine_marker(engine);") != 2:
        raise AssertionError("poison engine before/after proof drifted")
    matrix_api_calls = (
        "wyl_fact_store_create_schema",
        "wyl_fact_store_table_exists",
        "wyl_fact_store_ensure_projection",
        "wyl_fact_store_validate_projection",
        "wyl_fact_store_count_projection_batch_rows",
        "wyl_fact_store_append_batch_delta",
        "wyl_fact_store_retract_batch_delta",
        "wyl_fact_store_retract_by_batch_id",
        "wyl_fact_store_forget(",
        "wyl_fact_store_forget_reconcile",
        "wyl_fact_compound_create_schema",
        "wyl_fact_compound_ref_exists",
        "wyl_fact_compound_put",
        "wyl_fact_compound_replay(",
        "wyl_fact_compound_replay_cached",
        "wyl_fact_replay_open_graph_engine_with_store_for_test",
        "wyl_fact_store_test_exec_sql",
        "wyl_fact_store_test_query_int64",
        "wyl_fact_store_test_query_text",
    )
    for token in matrix_api_calls:
        if matrix.count(token) != 1:
            raise AssertionError(f"poison API matrix inventory drifted: {token}")
    exact_output_counts = {
        "g_assert_false(exists);": 3,
        "g_assert_false(inserted);": 3,
        "assert_zero_delta(&delta);": 2,
        "g_assert_cmpint(row_count, ==, 0);": 2,
        "g_assert_cmpint(handle, ==, 0);": 2,
    }
    for token, count in exact_output_counts.items():
        if matrix.count(token) != count:
            raise AssertionError(f"poison output inventory drifted: {token}")
    for token in (
        "g_assert_null(table);",
        "g_assert_cmpuint(purged, ==, 0);",
        "g_assert_cmpint(compound_ref, ==, 0);",
        "g_assert_cmpuint(g_hash_table_size(handles), ==, 1);",
        "g_assert_true(g_hash_table_lookup(handles, \"sentinel\") == marker);",
        "g_assert_null(replay_engine);",
        "g_assert_cmpint(query_value, ==, 0);",
        "g_assert_null(query_text);",
        "g_assert_cmpuint(wyl_fact_store_test_duckdb_call_count(store), ==,\n"
        "      duckdb_calls);",
    ):
        if matrix.count(token) != 1:
            raise AssertionError(f"poison output proof drifted: {token}")

    waiter_worker = function_body(poison_runtime, "waiter_worker")
    if waiter_worker.count("wyl_fact_store_table_exists") != 1:
        raise AssertionError("contention waiter no longer enters through public API")
    if "wyl_fact_store_test_try_lock" in waiter_worker:
        raise AssertionError("contention waiter bypasses public API admission")
    waiter_test = function_body(
        poison_runtime, "test_waiter_and_poisoned_matrix"
    )
    for token in (
        "while (!fault.rollback_entered)",
        "g_assert_false(wyl_fact_store_test_try_lock(store));",
        "while (!gate.entered)",
        "fault.release_rollback = TRUE;",
        "g_thread_join(g_steal_pointer(&waiter_thread));",
        "g_assert_cmpint(waiter.rc, ==, WYRELOG_E_INTERNAL);",
    ):
        if token not in waiter_test:
            raise AssertionError(f"contention waiter proof drifted: {token}")
    cross_store = function_body(
        poison_runtime, "test_cross_store_reentry_fails_closed"
    )
    for token in (
        ".store = nested_store",
        "wyl_fact_store_test_set_session_admission_hook(",
        "nested_store, count_admission, &admission_calls",
        "wyl_fact_store_forget(store, &schema.schema, &opts, NULL)",
        "g_assert_cmpint(probe.nested_rc, ==, WYRELOG_E_INTERNAL);",
        "g_assert_false(probe.exists);",
        "g_assert_cmpuint(admission_calls, ==, 0);",
        "wyl_fact_store_test_session_admission_count(nested_store), ==,",
        "nested_session_admissions);",
        "wyl_fact_store_test_duckdb_call_count(nested_store), ==,",
        "nested_duckdb_calls);",
    ):
        if token not in cross_store:
            raise AssertionError(f"cross-store reentry proof drifted: {token}")
    persistence_proofs = {
        "test_waiter_and_poisoned_matrix": (
            "SELECT COUNT(*) FROM fact_batches;",
            "SELECT COUNT(*) FROM fact_event_log;",
            'store, &schema, "poison-append"',
        ),
        "assert_owner_poisoned": (
            "WHERE batch_id = 'owner-retract';",
            "WHERE batch_id = 'owner-seed';",
            'store, &schema, "owner-retract"',
            'store, &schema, "owner-seed"',
            "SELECT COUNT(*) FROM compound_terms;",
            "SELECT COUNT(*) FROM compound_args;",
        ),
        "test_append_backed_retract_owner_poison": (
            "WHERE batch_id = 'retract-core-attempt';",
            "WHERE batch_id = 'retract-core-seed';",
            'store, &schema, "retract-core-attempt"',
            'store, &schema, "retract-core-seed"',
        ),
    }
    for signature, tokens in persistence_proofs.items():
        body = function_body(poison_runtime, signature)
        for token in tokens:
            if token not in body:
                raise AssertionError(
                    f"file-reopen persistence proof drifted: {signature}: {token}"
                )

    replay_test_entry = function_body(
        replay, "wyl_fact_replay_open_graph_engine_with_store_for_test"
    )
    if "open_graph_engine_with_store" not in replay_test_entry:
        raise AssertionError("supplied-store replay seam drifted")
    replay_admission = function_body(replay, "open_graph_engine_with_store")
    for token in (
        "wyl_fact_store_connection_session_begin (store,\n          &admission)",
        "wyl_fact_store_connection_session_end (&admission);",
        "list_replay_relations (policy, store, graph_info, &relations)",
    ):
        if token not in replay_admission:
            raise AssertionError(f"supplied-store replay admission drifted: {token}")
    if replay_admission.index(
        "wyl_fact_store_connection_session_end (&admission);"
    ) > replay_admission.index(
        "list_replay_relations (policy, store, graph_info, &relations)"
    ):
        raise AssertionError("supplied-store health check occurs after policy work")
    replay_seam_start = replay.rfind(
        "#if defined(WYL_TEST_HANDLE_SEAMS)", 0,
        replay.index("wyl_fact_replay_open_graph_engine_with_store_for_test"),
    )
    replay_seam_end = replay.index("#endif", replay_seam_start)
    if not (
        replay_seam_start
        < replay.index("wyl_fact_replay_open_graph_engine_with_store_for_test")
        < replay_seam_end
    ):
        raise AssertionError("supplied-store replay seam escaped test guard")

    relation_end = replay.index(
        "wyl_fact_store_connection_session_end (&session);",
        replay.index("list_replay_relations"),
    )
    schema_load = replay.index("load_relation_schema", relation_end)
    if relation_end >= schema_load:
        raise AssertionError("policy schema load occurs while DuckDB is held")
    relation_post = replay[relation_end:schema_load]
    if "duckdb_" in relation_post or " conn" in relation_post:
        raise AssertionError("stale DuckDB authority used after relation unlock")
    row_end = replay.index(
        "wyl_fact_store_connection_session_end (&session);",
        replay.index("replay_relation_into_engine"),
    )
    materialize = replay.index("materialize_owned_cell", row_end)
    if row_end >= materialize:
        raise AssertionError("engine materialization occurs while DuckDB is held")
    replay_rows = function_body(replay, "replay_relation_into_engine")
    released_rows = replay_rows[replay_rows.index(
        "wyl_fact_store_connection_session_end (&session);") + 1:]
    if "duckdb_" in released_rows or " conn" in released_rows:
        raise AssertionError("stale DuckDB authority used after row unlock")
    for start, end in (
        (replay.index("list_replay_relations"), relation_end),
        (replay.index("replay_relation_into_engine"), row_end),
    ):
        region = replay[start:end]
        if "duckdb_destroy_result" not in region:
            raise AssertionError("DuckDB result is not destroyed in its session")
    for token in (
        "key->namespace_id = g_strdup (namespace_id);",
        "key->relation_name = g_strdup (relation_name);",
        "owned->cells[c].text = g_strdup (value);",
    ):
        if token not in replay:
            raise AssertionError(f"replay retained provider-owned text: {token}")
    if "owned->cells[c].text = value;" in replay:
        raise AssertionError("replay borrowed DuckDB text past result destruction")

    seam_targets = (
        "test-fact-store",
        "test-fact-store-poison",
        "test-fact-store-forget-transaction",
        "test-fact-compound",
        "test-fact-replay",
        "test-fact-provisioning-run",
        "test-fact-store-provisioned",
    )
    for name in seam_targets:
        block = target_block(meson, name)
        if "wyrelog_handle_test_seams_dep" not in block:
            raise AssertionError(f"typed seam target lacks companion library: {name}")
        if "wyrelog_dep" in block:
            raise AssertionError(f"typed seam target links production too: {name}")


def load(root: Path) -> dict[str, str]:
    paths = {
        ROLE_HEADER,
        CONFIG_SEAM_HEADER,
        "wyrelog/fact/store-test-seams-private.h",
        "wyrelog/fact/store-private.h",
        "wyrelog/fact/store.c",
        "wyrelog/fact/compound.c",
        "wyrelog/fact/replay.c",
        "wyrelog/fact/query.c",
        "tests/meson.build",
    }
    for directory in (root / "wyrelog", root / "tests"):
        for path in directory.rglob("*"):
            if path.suffix in {".c", ".h", ".cc", ".cpp"}:
                paths.add(str(path.relative_to(root)))
    return {path: (root / path).read_text(encoding="utf-8") for path in paths}


def self_test(files: dict[str, str]) -> None:
    mutations = []

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        '#include "store-duckdb-config-test-seams-private.h"\n', "", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "  guint duckdb_configured_settings;\n", "", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store-private.h"] += "\nwyl_fact_store_lock(store);\n"
    mutations.append(changed)

    changed = dict(files)
    marker = "wyl_fact_store_connection_session_end (&session);"
    changed["wyrelog/fact/compound.c"] = changed[
        "wyrelog/fact/compound.c"
    ].replace(marker, marker + "\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/compound.c"] = changed[
        "wyrelog/fact/compound.c"
    ].replace(marker, marker + "\n  if (rc == WYRELOG_E_INVALID)\n"
              "    return rc;\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    marker = "wyl_fact_store_connection_session_end (&session);"
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace(marker, marker + "\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("owned->cells[c].text = g_strdup (value);",
              "owned->cells[c].text = value;", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("WylFactStoreConnectionSession session = { 0 };",
              "static\n  WylFactStoreConnectionSession session = { 0 };", 1)
    mutations.append(changed)

    for escaped in (
        "\nWylFactStoreConnectionSession escaped_global;\n",
        "\nWylFactStoreConnectionSession *escaped_global_pointer;\n",
        "\ntypedef struct { WylFactStoreConnectionSession session; } "
        "EscapedContext;\n",
        "\ntypedef union { WylFactStoreConnectionSession *session; gpointer raw; } "
        "EscapedUnion;\n",
        "\nstatic void escaped_heap(void) { "
        "g_new0(WylFactStoreConnectionSession, 1); }\n",
        "\nWylFactStoreConnectionSession escaped_return(void) { "
        "WylFactStoreConnectionSession session = { 0 }; return session; }\n",
        "\nWylFactStoreConnectionSession *escaped_pointer_return(void) { "
        "return NULL; }\n",
        "\nstatic void escaped_thread(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "g_thread_new(\"escaped\", (GThreadFunc) escaped_thread, &session); }\n",
        "\nstatic void escaped_indirect_thread(void) { "
        "WylFactStoreConnectionSession session = { 0 }; gpointer value = &session; "
        "g_thread_new(\"escaped\", (GThreadFunc) escaped_indirect_thread, value); }\n",
        "\nstatic gpointer escaped_opaque;\n"
        "static void escaped_opaque_store(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "escaped_opaque = (gpointer) &session; }\n",
        "\nstatic void escaped_helper(gpointer value) { (void) value; }\n"
        "static void escaped_indirect_helper(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "escaped_helper((gpointer) &session); }\n",
        "\nstatic void *escaped_session_pointer;\n"
        "static void escaped_pointer_alias(WylFactStoreConnectionSession *session) { "
        "escaped_session_pointer = (void *) session; }\n",
        "\nstatic void escaped_opaque_sink(void *value) { (void) value; }\n"
        "static void escaped_pointer_helper(WylFactStoreConnectionSession *session) { "
        "escaped_opaque_sink((gpointer) session); }\n",
        "\nstatic void escaped_bare_sink(void *value) { (void) value; }\n"
        "static void escaped_bare_helper(WylFactStoreConnectionSession *session) { "
        "escaped_bare_sink(session); }\n",
        "\nstatic void escaped_pointer_local(WylFactStoreConnectionSession *session) { "
        "void *alias = session; (void) alias; }\n",
        "\nstatic void *escaped_pointer_return(WylFactStoreConnectionSession *session) { "
        "return session; }\n",
        "\nstatic gconstpointer escaped_const_pointer;\n"
        "static void escaped_gconstpointer(WylFactStoreConnectionSession *session) { "
        "escaped_const_pointer = (gconstpointer) session; }\n",
        "\nstatic const void *escaped_const_void_pointer;\n"
        "static void escaped_const_void(WylFactStoreConnectionSession *session) { "
        "escaped_const_void_pointer = (const void *) session; }\n",
        "\ntypedef gpointer EscapedPointer;\n"
        "static EscapedPointer escaped_custom_pointer;\n"
        "static void escaped_custom_cast(WylFactStoreConnectionSession *session) { "
        "escaped_custom_pointer = (EscapedPointer) session; }\n",
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] += escaped
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("wyl_fact_store_connection_session_end (&session);", "", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/query.c"] += '\n#include "store-connection-private.h"\n'
    mutations.append(changed)

    changed = dict(files)
    changed[ROLE_HEADER] = changed[ROLE_HEADER].replace(
        "#if !defined(WYL_FACT_STORE_CONNECTION_ROLE)", "#if 0", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "#if defined(WYL_TEST_HANDLE_SEAMS)\nvoid\n"
        "wyl_fact_store_test_set_transaction_hook",
        "void\nwyl_fact_store_test_set_transaction_hook",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    marker = "dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep"
    changed["tests/meson.build"] = changed["tests/meson.build"].replace(
        marker, "dependencies : [wyrelog_dep, wyrelog_handle_test_seams_dep, wirelog_dep", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "store->health == WYL_FACT_STORE_POISONED",
        "FALSE",
        1,
    )
    mutations.append(changed)

    for token in (
        "if (active != NULL)",
        "session->owner == g_thread_self ()",
        "session->store->session_owner == session->owner",
        "g_private_get (&active_connection_session) == session",
        "connection_session_is_current (session)",
        "connection_session_is_current (transaction->session)",
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
            token, "FALSE", 1
        )
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "if (active != NULL)\n    if (active->store == store)\n"
        "      return WYRELOG_E_INTERNAL;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nstatic void pre_tls_duckdb_escape(wyl_fact_store_t *store) { "
        "duckdb_query(store->conn, \"SELECT 1;\", NULL); }\n"
    )
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "WylFactStoreConnectionSession *active =\n"
        "      g_private_get (&active_connection_session);",
        "pre_tls_duckdb_escape (store);\n"
        "  WylFactStoreConnectionSession *active =\n"
        "      g_private_get (&active_connection_session);",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
        "  if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "store->health = WYL_FACT_STORE_POISONED;",
        "store->health = WYL_FACT_STORE_HEALTHY;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "g_assert_false(wyl_fact_store_test_try_lock(store));",
        "g_assert_false(TRUE);",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "waiter->rc = wyl_fact_store_table_exists",
        "waiter->rc = fake_internal_table_exists",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "assert_engine_marker(engine);",
        "(void) wyl_engine_insert(engine, \"poison_marker\", marker_value, 1);\n"
        "  assert_engine_marker(engine);",
        1,
    )
    mutations.append(changed)

    for token, replacement in (
        ("SELECT COUNT(*) FROM fact_event_log;",
         "SELECT COUNT(*) FROM fact_batches;"),
        ('store, &schema, "poison-append"',
         'store, &schema, "poison-append-mutated"'),
        ('store, &schema, "owner-retract"',
         'store, &schema, "owner-retract-mutated"'),
        ('store, &schema, "retract-core-attempt"',
         'store, &schema, "retract-core-attempt-mutated"'),
    ):
        changed = dict(files)
        changed["tests/test-fact-store-poison.c"] = changed[
            "tests/test-fact-store-poison.c"
        ].replace(token, replacement, 1)
        mutations.append(changed)

    for path, token in (
        ("wyrelog/fact/store.c", "g_private_get (&active_connection_session)"),
        ("wyrelog/fact/store.c", "store->session_owner = NULL;"),
        ("wyrelog/fact/replay.c",
         "wyl_fact_store_connection_session_end (&admission);"),
        ("tests/test-fact-store-poison.c", "g_assert_false(exists);"),
        ("tests/test-fact-store-poison.c", "g_assert_false(inserted);"),
        ("tests/test-fact-store-poison.c", "assert_zero_delta(&delta);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(row_count, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(table);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(purged, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(compound_ref, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_cmpint(handle, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(g_hash_table_size(handles), ==, 1);"),
        ("tests/test-fact-store-poison.c", "assert_engine_marker(engine);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(admission_calls, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "nested_session_admissions);"),
        ("tests/test-fact-store-poison.c", "nested_duckdb_calls);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(replay_engine);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(query_value, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(query_text);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(wyl_fact_store_test_duckdb_call_count(store), ==,\n"
         "      duckdb_calls);"),
    ):
        changed = dict(files)
        changed[path] = changed[path].replace(token, "", 1)
        mutations.append(changed)

    for index, mutation in enumerate(mutations, 1):
        try:
            validate(mutation)
        except (AssertionError, ValueError):
            continue
        raise AssertionError(f"connection-boundary mutation survived: {index}")


def main() -> int:
    args = sys.argv[1:]
    self_mode = bool(args and args[0] == "--self-test")
    if self_mode:
        args = args[1:]
    if len(args) != 1:
        raise SystemExit("usage: test-fact-store-connection-boundary.py [--self-test] ROOT")
    files = load(Path(args[0]))
    validate(files)
    if self_mode:
        self_test(files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

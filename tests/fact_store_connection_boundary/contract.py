"""Fact-store connection boundary contract and source loader."""

from __future__ import annotations

from pathlib import Path, PurePath
import re

from .parser import *

ROLE_HEADER = "wyrelog/fact/store-connection-private.h"
CONFIG_SEAM_HEADER = "wyrelog/fact/store-duckdb-config-test-seams-private.h"
ROLE_OWNERS = {
    "wyrelog/fact/store.c",
    "wyrelog/fact/compound.c",
    "wyrelog/fact/replay.c",
}
EXPECTED_RAW_INVENTORY = {
    "wyrelog/fact/store.c": (45, 363, 4, 3),
    "wyrelog/fact/compound.c": (0, 123, 14, 0),
    "wyrelog/fact/replay.c": (0, 32, 2, 0),
}
EXPECTED_RAW_MEMBER_FUNCTIONS = {
    "wyrelog/fact/store.c": {
        "complete_forget_intent_unlocked": 2,
        "count_projection_rows_unlocked": 1,
        "existing_batch_matches_unlocked": 1,
        "fact_identity_execute": 1,
        "fact_identity_validation_barrier": 1,
        "forget_intent_state_check_is_current": 1,
        "insert_batch_unlocked": 1,
        "insert_event_unlocked": 1,
        "insert_forget_intent_unlocked": 1,
        "load_batch_forget_fingerprint_unlocked": 1,
        "load_pending_forget_intents_unlocked": 1,
        "lookup_batch_scope_unlocked": 1,
        "migrate_forget_intent_state_check_unlocked": 3,
        "next_sequence_unlocked": 1,
        "prepared_delete_batch_unlocked": 1,
        "reject_audit_database_unlocked": 1,
        "rename_metadata_value_column_once_unlocked": 1,
        "select_valid_rows_for_batch_unlocked": 1,
        "table_exists_unlocked": 1,
        "validate_projection_shape_unlocked": 2,
        "validate_store_scope_unlocked": 1,
        "wyl_fact_store_append_batch_delta": 1,
        "wyl_fact_store_close": 2,
        "wyl_fact_store_connection_session_begin": 2,
        "wyl_fact_store_connection_session_get": 1,
        "wyl_fact_store_create_schema": 2,
        "wyl_fact_store_ensure_projection": 1,
        "wyl_fact_store_open": 4,
        "wyl_fact_store_open_identified": 4,
        "wyl_fact_store_retract_by_batch_id": 1,
        "wyl_fact_store_transaction_begin": 1,
        "wyl_fact_store_transaction_finish": 1,
    },
    "wyrelog/fact/compound.c": {},
    "wyrelog/fact/replay.c": {},
}
EXPECTED_DUCKDB_CALL_FUNCTIONS = {
    "wyrelog/fact/compound.c": {
        "compound_exists_unlocked": 13,
        "compound_hash_matches_unlocked": 16,
        "exec_sql": 3,
        "insert_arg_unlocked": 18,
        "insert_term_unlocked": 13,
        "load_logical_arg_unlocked": 29,
        "load_term_unlocked": 19,
        "replay_unlocked": 12,
    },
    "wyrelog/fact/replay.c": {
        "list_replay_relations": 16,
        "replay_relation_into_engine": 16,
    },
    "wyrelog/fact/store.c": {
        "append_value": 5,
        "bind_optional_varchar": 2,
        "complete_forget_intent_unlocked": 19,
        "count_projection_rows_unlocked": 10,
        "create_hardened_duckdb_config": 2,
        "duckdb_type_for_column": 1,
        "exec_sql": 3,
        "existing_batch_matches_unlocked": 36,
        "fact_identity_bind_param": 3,
        "fact_identity_execute": 25,
        "fact_store_duckdb_set_config": 1,
        "forget_intent_state_check_is_current": 8,
        "insert_batch_unlocked": 20,
        "insert_event_unlocked": 15,
        "insert_forget_intent_unlocked": 19,
        "load_batch_forget_fingerprint_unlocked": 17,
        "load_pending_forget_intents_unlocked": 36,
        "lookup_batch_scope_unlocked": 24,
        "next_sequence_unlocked": 4,
        "open_duckdb_identified": 6,
        "open_duckdb_with_thread_budget": 6,
        "prepared_delete_batch_unlocked": 6,
        "read_projection_value": 6,
        "reject_audit_database_unlocked": 7,
        "select_valid_rows_for_batch_unlocked": 12,
        "table_exists_unlocked": 10,
        "validate_projection_shape_unlocked": 22,
        "validate_schema_shape": 1,
        "wyl_fact_store_append_batch_delta": 10,
        "wyl_fact_store_close": 2,
        "wyl_fact_store_ensure_projection": 1,
        "wyl_fact_store_open": 2,
        "wyl_fact_store_open_identified": 2,
        "wyl_fact_store_retract_by_batch_id": 11,
        "wyl_fact_store_test_query_int64": 4,
        "wyl_fact_store_test_query_text": 5,
    },
}
RAW_PROFILE_ADDITIONS = {
    ("wyrelog/fact/store.c", "WYL_HAS_SECURE_DUCKDB_BRIDGE"): (
        (4, 0, 2, 2),
        {
            "wyl_fact_store_open_provisioned_pair": 2,
            "wyl_fact_store_open_provisioned_namespace_with_lease": 2,
        },
        {},
    ),
}
EXPECTED_TRANSITIVE_RAW_WRAPPERS = {
    "build_graph_engine",
    "execute_forget_intent_unlocked",
    "fact_store_duckdb_apply_config",
    "forget_survey_unlocked",
    "materialize_arg_unlocked",
    "open_graph_engine_with_store",
    "open_graph_store",
    "probe_graph_forgets",
    "quarantine_forget_intent_unlocked",
    "reconcile_graph_forgets",
    "wyl_fact_replay_open_graph_engine",
    "wyl_fact_replay_open_graph_engine_with_store_for_test",
    "wyl_fact_replay_policy_graphs",
    "wyl_fact_replay_refresh_graph",
    "wyl_fact_replay_refresh_graph_closed",
    "wyl_fact_replay_publish_graph_closed_and_open",
    "wyl_fact_replay_refresh_graph_publication",
    "wyl_fact_replay_validate_graph",
    "open_graph_engine_with_artifact_lease",
    "refresh_graph_closed_internal",
    "validate_graph_internal",
    "wyl_fact_replay_refresh_graph_closed_with_artifact_lease",
    "wyl_fact_replay_validate_graph_with_artifact_lease",
}
EXPECTED_TRANSITIVE_RAW_WRAPPERS_BY_PATH = {
    "wyrelog/fact/compound.c": {"materialize_arg_unlocked"},
    "wyrelog/fact/replay.c": {
        "build_graph_engine",
        "open_graph_engine_with_store",
        "open_graph_store",
        "probe_graph_forgets",
        "reconcile_graph_forgets",
        "wyl_fact_replay_open_graph_engine",
        "wyl_fact_replay_open_graph_engine_with_store_for_test",
        "wyl_fact_replay_policy_graphs",
        "wyl_fact_replay_refresh_graph",
        "wyl_fact_replay_refresh_graph_closed",
        "wyl_fact_replay_publish_graph_closed_and_open",
        "wyl_fact_replay_refresh_graph_publication",
        "wyl_fact_replay_validate_graph",
        "open_graph_engine_with_artifact_lease",
        "refresh_graph_closed_internal",
        "validate_graph_internal",
        "wyl_fact_replay_refresh_graph_closed_with_artifact_lease",
        "wyl_fact_replay_validate_graph_with_artifact_lease",
    },
    "wyrelog/fact/store.c": {
        "execute_forget_intent_unlocked",
        "fact_store_duckdb_apply_config",
        "forget_survey_unlocked",
        "quarantine_forget_intent_unlocked",
    },
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
    "wyl_fact_store_test_arm_metadata_value_column_rename_once",
)


def target_block(meson: str, name: str) -> str:
    name_at = meson.index(f"'{name}'")
    start = meson.rfind("executable(", 0, name_at)
    if start < 0:
        raise AssertionError(f"target declaration missing: {name}")
    end = meson.index("\n  )", start)
    return meson[start:end]


def function_body(source: str, signature: str) -> str:
    masked = re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda match: "".join(
            "\n" if character == "\n" else " " for character in match.group(0)
        ),
        source,
        flags=re.DOTALL,
    )
    start = masked.index(signature)
    brace = masked.index("{", start)
    depth = 0
    for index in range(brace, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")
def validate_session_profile(
    body: str, signature: str, raw_helper_names: set[str],
    duckdb_api: re.Pattern[str],
) -> None:
    begin = re.search(
        r"(?:wyrelog_error_t\s+)?rc\s*=\s*"
        r"wyl_fact_store_connection_session_begin\s*"
        r"\(\s*store\s*,\s*&\s*(?P<session>[A-Za-z_]\w*)\s*\)\s*;",
        body,
    )
    if begin is None:
        raise AssertionError(f"session owner lost admission: {signature}")
    begin_at = begin.start()
    if not is_top_level_statement(body, begin_at):
        raise AssertionError(
            f"session authority precedes successful admission: {signature}"
        )
    admitted_session = begin.group("session")
    retrieved = set(re.findall(
        r"wyl_fact_store_connection_session_get\s*"
        r"\(\s*&\s*([A-Za-z_]\w*)\s*\)", body
    ))
    if retrieved - {admitted_session}:
        raise AssertionError(
            f"session authority precedes successful admission: {signature}"
        )
    authority_positions = [
        position for position in (
            body.find("wyl_fact_store_connection_session_get"),
            next((match.start() for match in re.finditer(
                r"(?:->|\.)\s*(?:conn|db|connection)\b", body
            )), -1),
        next((match.start() for match in duckdb_api.finditer(body)), -1),
            first_raw_helper_position(body, raw_helper_names),
        ) if position >= 0
    ]
    failure_guard = re.match(
        r"\s*if\s*\(\s*rc\s*!=\s*WYRELOG_E_OK\s*\)\s*"
        r"return\s+rc\s*;", body[begin.end():],
    )
    success_guard = re.match(
        r"\s*(?:duckdb_result\s+\w+\s*=\s*\{\s*0\s*\}\s*;\s*)?"
        r"if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*\{",
        body[begin.end():],
    )
    success_statement = re.match(
        r"\s*if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*(?!\{)[^;]+;",
        body[begin.end():],
    ) if success_guard is None else None
    if failure_guard is None and success_guard is None \
            and success_statement is None:
        raise AssertionError(
            f"session authority precedes successful admission: {signature}"
        )
    if authority_positions:
        authority_at = min(authority_positions)
        if authority_at < begin_at:
            raise AssertionError(
                f"session authority precedes successful admission: {signature}"
            )
        success_open = begin.end() + success_guard.end() - 1 \
            if success_guard is not None else -1
        if success_guard is not None and not (
            success_open < authority_at < closing_brace(body, success_open)
        ):
            raise AssertionError(
                f"session authority precedes successful admission: {signature}"
            )
        if success_statement is not None and not (
            begin.end() + success_statement.start()
            < authority_at < begin.end() + success_statement.end()
        ):
            raise AssertionError(
                f"session authority precedes successful admission: {signature}"
            )
    ends = list(re.finditer(
        r"wyl_fact_store_connection_session_end\s*\(\s*&\s*"
        + re.escape(admitted_session) + r"\s*\)\s*;", body
    ))
    if not ends:
        raise AssertionError(f"session owner lost release: {signature}")
    final_start, final_end = ends[-1].start(), ends[-1].end()
    if not is_top_level_statement(body, final_start, True):
        raise AssertionError(f"session owner lost release: {signature}")
    labels = {
        match.group(1): match.start()
        for match in re.finditer(
            r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*(?!:)", body
        )
    }
    for jump in re.finditer(r"\bgoto\s+([A-Za-z_]\w*)\s*;", body):
        jump_at = jump.start()
        target_at = labels.get(jump.group(1), -1)
        if jump_at < begin_at <= target_at \
                or begin_at <= jump_at < final_end \
                and not jump_at < target_at < final_start \
                or jump_at >= final_end and begin_at <= target_at < final_end:
            raise AssertionError(
                f"session control flow may bypass release: {signature}"
            )
    if re.search(
        r"\bg_return(?:_val)?_if_(?:fail|reached)\b",
        body[begin_at:final_start],
    ):
        raise AssertionError(f"session return bypasses release: {signature}")
    failure_return_end = begin.end() + failure_guard.end() \
        if failure_guard is not None else begin.end()
    end_ranges = [(match.start(), match.end()) for match in ends]
    for returned in re.finditer(r"\breturn\b", body):
        if returned.start() <= failure_return_end or returned.start() >= final_start:
            continue
        preceding_end = next((end for _start, end in reversed(end_ranges)
                              if end <= returned.start()), -1)
        if preceding_end < 0 or body[preceding_end:returned.start()].strip():
            raise AssertionError(f"session return bypasses release: {signature}")
    released = body[final_end:]
    raw_after_release = any(
        position >= final_end
        for position in raw_helper_positions(body, raw_helper_names)
    )
    if "duckdb_" in released or raw_after_release or re.search(
        r"\bconn\b|(?:->|\.)\s*connection\b", released
    ):
        raise AssertionError(
            f"stale DuckDB authority used after session end: {signature}"
        )


def validate(files: dict[str, str]) -> None:
    role_header = files[ROLE_HEADER]
    config_seam_header = files[CONFIG_SEAM_HEADER]
    seam_header = files["wyrelog/fact/store-test-seams-private.h"]
    store_header = files["wyrelog/fact/store-private.h"]
    store = files["wyrelog/fact/store.c"]
    compound = files["wyrelog/fact/compound.c"]
    replay = files["wyrelog/fact/replay.c"]
    meson = files["tests/meson.build"]
    raw_authority_names = set(EXPECTED_TRANSITIVE_RAW_WRAPPERS)
    for inventory in EXPECTED_RAW_MEMBER_FUNCTIONS.values():
        raw_authority_names.update(inventory)
    for inventory in EXPECTED_DUCKDB_CALL_FUNCTIONS.values():
        raw_authority_names.update(inventory)

    self_test_at = meson.index("test('fact-store-connection-boundary-self'")
    self_test_block = meson[self_test_at:meson.index("\n\n", self_test_at)]
    if "timeout : 900" not in self_test_block \
            or "is_parallel : false" not in self_test_block:
        raise AssertionError(
            "connection boundary self-test lost its serialized CI budget"
        )

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

    macro_escapes = macro_authority_escapes(files, ROLE_OWNERS)
    if macro_escapes:
        raise AssertionError(
            f"macro-generated raw authority remains: {sorted(macro_escapes)}"
        )

    for path, expected in EXPECTED_RAW_INVENTORY.items():
        text = files[path]
        for profile in source_inventory_profiles(
            files, path, ROLE_OWNERS, raw_authority_names
        ):
            profile_expected = list(expected)
            expected_functions = dict(EXPECTED_RAW_MEMBER_FUNCTIONS[path])
            expected_calls = dict(EXPECTED_DUCKDB_CALL_FUNCTIONS[path])
            for (profile_path, macro), (
                inventory_addition, member_additions, call_additions,
            ) in RAW_PROFILE_ADDITIONS.items():
                if profile_path != path or macro not in profile:
                    continue
                profile_expected = [
                    count + addition for count, addition
                    in zip(profile_expected, inventory_addition)
                ]
                for function, addition in member_additions.items():
                    expected_functions[function] = (
                        expected_functions.get(function, 0) + addition
                    )
                for function, addition in call_additions.items():
                    expected_calls[function] = (
                        expected_calls.get(function, 0) + addition
                    )
            expected_for_profile = tuple(profile_expected)
            lexical_code = inventory_code_for_profile(files, path, profile)
            lexical_code = re.sub(
                r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", lexical_code
            )
            actual = (
                len(re.findall(
                    r"(?:->|\.)\s*(?:conn|db|connection)\b",
                    lexical_code,
                )),
                len(re.findall(
                    r"\bduckdb_[A-Za-z_]\w*\s*(?:\)\s*)*\(",
                    lexical_code,
                )),
                len(re.findall(r"\bduckdb_connection\b", lexical_code)),
                len(re.findall(r"\bduckdb_database\b", lexical_code)),
            )
            profile_label = ", ".join(
                f"{name}={value}" for name, value in sorted(profile.items())
            )
            if actual != expected_for_profile:
                raise AssertionError(
                    f"raw DuckDB authority inventory drifted: {path}: "
                    f"profile={profile_label}: expected={expected_for_profile}, "
                    f"actual={actual}"
                )
            member_functions, outside_functions = raw_member_function_inventory(
                lexical_code
            )
            if outside_functions or member_functions != expected_functions:
                raise AssertionError(
                    f"raw DuckDB authority moved between functions: {path}: "
                    f"profile={profile_label}: expected={expected_functions}, "
                    f"actual={member_functions}, outside={outside_functions}"
                )
            call_functions, outside_calls = duckdb_call_function_inventory(
                lexical_code
            )
            if outside_calls or call_functions != expected_calls:
                raise AssertionError(
                    f"DuckDB calls moved between functions: {path}: "
                    f"profile={profile_label}: expected={expected_calls}, "
                    f"actual={call_functions}, outside={outside_calls}"
                )

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
            "quarantine_forget_intent_unlocked",
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
            "migrate_forget_intent_state_check_unlocked",
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
        "wyrelog/fact/store.c": (14, 4, 16),
        "wyrelog/fact/compound.c": (5, 5, 7),
        "wyrelog/fact/replay.c": (3, 2, 3),
    }
    for path, (begins, gets, ends) in expected_calls.items():
        text = files[path]
        if text.count("wyl_fact_store_connection_session_begin") != begins:
            raise AssertionError(f"connection session begin inventory drifted: {path}")
        if text.count("wyl_fact_store_connection_session_get") != gets:
            raise AssertionError(f"connection session get inventory drifted: {path}")
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
    session_owner_keys = {
        (path, match.group(1))
        for path, signatures in session_functions.items()
        for signature in signatures
        if (match := re.search(r"([A-Za-z_]\w*)\s*\(", signature + "("))
        is not None
    }
    duckdb_function_names = {
        match.group(1)
        for path in ROLE_OWNERS
        for match in re.finditer(
            r"\b(duckdb_[A-Za-z_]\w*)\s*(?:\)\s*)*\(",
            inventory_code(files, path),
        )
    } - {"duckdb_type_for_column"}
    duckdb_api = raw_helper_pattern(duckdb_function_names)
    excluded_raw_helpers = {
        "create_hardened_duckdb_config",
        "duckdb_type_for_column",
        "fact_store_duckdb_set_config",
        "open_duckdb_identified",
        "open_duckdb_with_thread_budget",
        "validate_schema_shape",
        "wyl_fact_store_connection_session_begin",
        "wyl_fact_store_connection_session_get",
        "wyl_fact_store_transaction_begin",
        "wyl_fact_store_transaction_finish",
    }
    all_raw_helper_keys, resolved_raw_helpers = transitive_raw_helpers(
        files, session_owner_keys, duckdb_function_names,
        ROLE_OWNERS, raw_authority_names,
    )
    raw_helper_keys = {
        key for key in all_raw_helper_keys
        if key[1] not in excluded_raw_helpers
    }
    call = "wyl_fact_store_connection_session_end (&session);"
    for path, signatures in session_functions.items():
        for signature in signatures:
            owner_match = re.search(r"([A-Za-z_]\w*)\s*\(", signature + "(")
            if owner_match is None:
                raise AssertionError(f"session owner name missing: {signature}")
            owner = owner_match.group(1)
            raw_helper_names = resolved_raw_helpers[(path, owner)] \
                - excluded_raw_helpers
            source_body = function_body(files[path], signature)
            unconditional_body = unconditional_preprocessor_code(source_body)
            if re.search(
                r"\bwyl_fact_store_connection_session_begin\s*\(",
                unconditional_body,
            ) is None:
                raise AssertionError(f"session owner lost admission: {signature}")
            if re.search(
                r"\bwyl_fact_store_connection_session_end\s*\(",
                unconditional_body,
            ) is None:
                raise AssertionError(f"session owner lost release: {signature}")
            profile_bodies = expanded_function_profiles(
                files, path, signature, source_body
            )
            for profile_body in profile_bodies:
                validate_session_profile(
                    profile_body, signature, raw_helper_names, duckdb_api
                )
            body = profile_bodies[0]
            begin_statement = re.search(
                r"(?:wyrelog_error_t\s+)?rc\s*=\s*"
                r"wyl_fact_store_connection_session_begin\s*"
                r"\(\s*store\s*,\s*&\s*(?P<session>[A-Za-z_]\w*)\s*\)\s*;",
                body,
            )
            if begin_statement is None:
                raise AssertionError(f"session owner lost admission: {signature}")
            begin_at = begin_statement.start()
            if not is_top_level_statement(body, begin_at):
                raise AssertionError(
                    f"session authority precedes successful admission: {signature}"
                )
            admitted_session = begin_statement.group("session")
            retrieved_sessions = set(re.findall(
                r"wyl_fact_store_connection_session_get\s*"
                r"\(\s*&\s*([A-Za-z_]\w*)\s*\)",
                body,
            ))
            if retrieved_sessions - {admitted_session}:
                raise AssertionError(
                    f"session authority precedes successful admission: {signature}"
                )
            authority_positions = [
                position for position in (
                    body.find("wyl_fact_store_connection_session_get"),
                    next((match.start() for match in re.finditer(
                        r"(?:->|\.)\s*(?:conn|db|connection)\b", body
                    )), -1),
                    next((match.start() for match in duckdb_api.finditer(body)),
                         -1),
                    first_raw_helper_position(body, raw_helper_names),
                ) if position >= 0
            ]
            failure_guard = re.match(
                r"\s*if\s*\(\s*rc\s*!=\s*WYRELOG_E_OK\s*\)\s*"
                r"return\s+rc\s*;",
                body[begin_statement.end():],
            )
            success_guard = re.match(
                r"\s*(?:duckdb_result\s+\w+\s*=\s*\{\s*0\s*\}\s*;\s*)?"
                r"if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*\{",
                body[begin_statement.end():],
            )
            success_statement = re.match(
                r"\s*if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*"
                r"(?!\{)[^;]+;",
                body[begin_statement.end():],
            ) if success_guard is None else None
            if failure_guard is None and success_guard is None \
                    and success_statement is None:
                raise AssertionError(
                    f"session authority precedes successful admission: {signature}"
                )
            if authority_positions:
                authority_at = min(authority_positions)
                if authority_at < begin_at:
                    raise AssertionError(
                        f"session authority precedes successful admission: "
                        f"{signature}"
                    )
                success_open = begin_statement.end() + success_guard.end() - 1 \
                    if success_guard is not None else -1
                if success_guard is not None and not (
                    success_open < authority_at
                    < closing_brace(body, success_open)
                ):
                    raise AssertionError(
                        f"session authority precedes successful admission: "
                        f"{signature}"
                    )
                if success_statement is not None and not (
                    begin_statement.end() + success_statement.start()
                    < authority_at
                    < begin_statement.end() + success_statement.end()
                ):
                    raise AssertionError(
                        f"session authority precedes successful admission: "
                        f"{signature}"
                    )
            ends_at = []
            offset = 0
            while True:
                found = body.find(call, offset)
                if found < 0:
                    break
                ends_at.append((found, found + len(call)))
                offset = found + len(call)
            if not ends_at:
                raise AssertionError(f"session owner lost release: {signature}")
            if not is_top_level_statement(body, ends_at[-1][0], True):
                raise AssertionError(f"session owner lost release: {signature}")
            labels = {
                match.group(1): match.start()
                for match in re.finditer(
                    r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*(?!:)", body
                )
            }
            for jump in re.finditer(
                r"\bgoto\s+([A-Za-z_]\w*)\s*;", body
            ):
                jump_at = jump.start()
                target_at = labels.get(jump.group(1), -1)
                skips_admission = jump_at < begin_at <= target_at
                bypasses_release = begin_at <= jump_at < ends_at[-1][1] \
                    and not jump_at < target_at < ends_at[-1][0]
                reenters_authority = jump_at >= ends_at[-1][1] \
                    and begin_at <= target_at < ends_at[-1][1]
                if skips_admission or bypasses_release or reenters_authority:
                    raise AssertionError(
                        f"session control flow may bypass release: {signature}"
                    )
            if re.search(
                r"\bg_return(?:_val)?_if_(?:fail|reached)\b",
                body[begin_at:ends_at[-1][0]],
            ):
                raise AssertionError(
                    f"session return bypasses release: {signature}"
                )
            for _start, after in ends_at[:-1]:
                if not body[after:].lstrip().startswith("return "):
                    raise AssertionError(
                        f"non-final session release lacks terminal return: {signature}"
                    )
            failure_return_end = begin_statement.end() + failure_guard.end() \
                if failure_guard is not None else begin_statement.end()
            for returned in re.finditer(r"\breturn\b", body):
                if returned.start() <= failure_return_end \
                        or returned.start() >= ends_at[-1][0]:
                    continue
                preceding_end = next((end for _start, end in reversed(ends_at)
                                      if end <= returned.start()), -1)
                if preceding_end < 0 \
                        or body[preceding_end:returned.start()].strip():
                    raise AssertionError(
                        f"session return bypasses release: {signature}"
                    )
            released = body[ends_at[-1][1]:]
            if "duckdb_" in released or re.search(r"\bconn\b", released):
                raise AssertionError(
                    f"stale DuckDB authority used after session end: {signature}"
                )

    expected_raw_functions = {
        (path, name)
        for path, names in EXPECTED_TRANSITIVE_RAW_WRAPPERS_BY_PATH.items()
        for name in names
    }
    for path, inventory in EXPECTED_RAW_MEMBER_FUNCTIONS.items():
        expected_raw_functions.update((path, name) for name in inventory)
    for path, inventory in EXPECTED_DUCKDB_CALL_FUNCTIONS.items():
        expected_raw_functions.update((path, name) for name in inventory)
    for (path, _macro), (_counts, members, calls) \
            in RAW_PROFILE_ADDITIONS.items():
        expected_raw_functions.update((path, name) for name in members)
        expected_raw_functions.update((path, name) for name in calls)
    unexpected_raw_functions = raw_helper_keys - expected_raw_functions
    if unexpected_raw_functions:
        raise AssertionError(
            "unexpected transitive raw authority functions: "
            f"{sorted(f'{path}:{name}' for path, name in unexpected_raw_functions)}"
        )

    if "#if !defined(WYL_TEST_HANDLE_SEAMS)" not in seam_header:
        raise AssertionError("fact-store seams lost their compile-time gate")
    for symbol in SEAM_SYMBOLS:
        if symbol not in seam_header:
            raise AssertionError(f"fact-store seam declaration missing: {symbol}")
        if store.count(symbol) != 1:
            raise AssertionError(f"fact-store seam definition drifted: {symbol}")
    seam_marker = (
        "#if defined(WYL_TEST_HANDLE_SEAMS)\nvoid\n"
        "wyl_fact_store_test_set_transaction_hook"
    )
    seam_start = store.find(seam_marker)
    if seam_start < 0:
        raise AssertionError("fact-store seam source guard drifted")
    seam_end = store.find("#endif", seam_start)
    if seam_end < 0:
        raise AssertionError("fact-store seam source guard is unterminated")
    seam_region = store[seam_start:seam_end]
    if any(symbol not in seam_region for symbol in SEAM_SYMBOLS):
        raise AssertionError("fact-store seam escaped the test-only source guard")

    begin = function_body(store, "wyl_fact_store_connection_session_begin")
    for token in (
        "g_private_get (&active_connection_session)",
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
            or re.search(
                r"\b(?:store|session)->(?:conn|db|connection)\b",
                admission_prefix,
            ):
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
        "migrate_forget_intent_state_check_unlocked":
            "WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION",
    }
    for signature, kind in kind_owners.items():
        if kind not in function_body(store, signature):
            raise AssertionError(f"transaction owner kind drifted: {signature}")

    forget_complete = function_body(store, "complete_forget_intent_unlocked")
    forget_begin_at = forget_complete.index(
        "wyl_fact_store_transaction_begin (session,"
    )
    rename_at = forget_complete.index(
        "rc = rename_metadata_value_column_once_unlocked (store);"
    )
    finish_at = forget_complete.rindex("finish:")
    if not forget_begin_at < rename_at < finish_at:
        raise AssertionError(
            "forget rename seam escaped its admitted transaction"
        )
    rename_cleanup = re.compile(
        r"rc\s*=\s*rename_metadata_value_column_once_unlocked\s*"
        r"\(\s*store\s*\)\s*;\s*"
        r"if\s*\(\s*rc\s*!=\s*WYRELOG_E_OK\s*\)\s*"
        r"goto\s+finish\s*;"
    )
    if rename_cleanup.search(forget_complete, rename_at, finish_at) is None:
        raise AssertionError(
            "forget rename seam bypasses common transaction cleanup"
        )
    if "WYL_FACT_STORE_TRANSACTION_COMPOUND_PUT" not in function_body(
        compound, "wyl_fact_compound_put"
    ):
        raise AssertionError("compound transaction owner kind drifted")

    migration = function_body(
        store, "migrate_forget_intent_state_check_unlocked"
    )
    if re.search(r"(?m)^[ \t]*#", migration):
        raise AssertionError("forget migration must remain unconditional source")
    production_macro_sources = "\n".join(
        source for path, source in files.items()
        if path.startswith("wyrelog/")
        and Path(path).suffix in {".c", ".h", ".cc", ".cpp"}
    )
    production_macro_sources = production_macro_sources.replace(
        "??/", "\\"
    ).replace("??=", "#")
    production_macro_sources = re.sub(
        r"\\\r?\n", "", production_macro_sources
    )
    production_macro_sources = re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n") or " ",
        production_macro_sources,
        flags=re.DOTALL,
    )
    production_macro_sources = re.sub(
        r"//[^\r\n]*", "", production_macro_sources
    ).replace("%:", "#")
    repository_macros = set(re.findall(
        r"(?m)^[^\S\r\n]*#[^\S\r\n]*define[^\S\r\n]+([A-Za-z_]\w*)\b",
        production_macro_sources,
    ))
    migration_code = migration.replace("??/", "\\").replace("??=", "#")
    migration_code = re.sub(r"\\\r?\n", "", migration_code)
    migration_code = re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        " ",
        migration,
        flags=re.DOTALL,
    )
    used_repository_macros = set(
        re.findall(r"\b[A-Za-z_]\w*\b", migration_code)
    ) & repository_macros
    unexpected_macros = used_repository_macros
    if unexpected_macros:
        raise AssertionError(
            "forget migration uses unaudited repository macro: "
            + ", ".join(sorted(unexpected_macros))
        )
    if "fact_forget_intent_rebuild_sql" not in migration:
        raise AssertionError(
            "forget migration must use the audited rebuild SQL constant"
        )
    macro_definitions = list(re.finditer(
        r"(?m)^[^\S\r\n]*#[^\S\r\n]*define[^\S\r\n]+"
        r"FACT_FORGET_INTENT_COLUMNS\b.*$",
        production_macro_sources,
    ))
    if len(macro_definitions) != 1 or re.search(
        r"(?m)^[^\S\r\n]*#[^\S\r\n]*undef[^\S\r\n]+"
        r"FACT_FORGET_INTENT_COLUMNS\b",
        production_macro_sources,
    ):
        raise AssertionError(
            "forget intent columns macro must have one active definition"
        )
    macro_lines = production_macro_sources[
        macro_definitions[0].start():
    ].splitlines()
    logical_definition = []
    for line in macro_lines:
        logical_definition.append(line)
        if not line.rstrip().endswith("\\"):
            break
    replacement = re.sub(
        r"^[ \t]*#[ \t]*define[ \t]+FACT_FORGET_INTENT_COLUMNS\b",
        "",
        "\n".join(logical_definition),
        count=1,
    )
    replacement = re.sub(r"\\[ \t]*\n", "\n", replacement)
    replacement = re.sub(r'"(?:\\.|[^"\\])*"', "", replacement)
    if replacement.strip():
        raise AssertionError(
            "forget intent columns macro must contain only string literals"
        )
    if re.search(
        r"(?m)^(?:static[ \t]+)?WylFactStoreTransaction\b",
        production_macro_sources,
    ):
        raise AssertionError("fact store transaction owner must not have file scope")
    for token in (
        "wyl_fact_store_transaction_begin (session,",
        "WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION",
        "finish:\n  return wyl_fact_store_transaction_finish "
        "(&transaction, rc);",
    ):
        if token not in migration:
            raise AssertionError(f"forget migration cleanup drifted: {token}")
    begin_guard = (
        "wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION, "
        "&transaction);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;"
    )
    owner_sites = (
        "WylFactStoreTransaction transaction = { 0 };",
        "rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION, "
        "&transaction);",
        "return wyl_fact_store_transaction_finish (&transaction, rc);",
    )
    owner_remainder = migration
    for site in owner_sites:
        if owner_remainder.count(site) != 1:
            raise AssertionError("forget migration transaction owner site drifted")
        owner_remainder = owner_remainder.replace(site, "", 1)
    if re.search(r"\btransaction\b", owner_remainder):
        raise AssertionError(
            "forget migration references transaction outside owner calls"
        )
    admitted_at = migration.index(begin_guard) + len(begin_guard)
    finish_at = migration.index("finish:", admitted_at)
    post_admission = migration[admitted_at:finish_at]
    body_failure_edge = (
        "if (rc != WYRELOG_E_OK)\n"
        "    goto finish;"
    )
    if post_admission.count(body_failure_edge) != 1:
        raise AssertionError(
            "forget migration body-failure cleanup edge drifted"
        )
    if re.search(r"\breturn\b", post_admission):
        raise AssertionError(
            "forget migration bypasses common transaction cleanup"
        )
    if re.search(r"\btransaction\b", post_admission):
        raise AssertionError(
            "forget migration mutates transaction ownership after admission"
        )
    for target in re.findall(r"\bgoto\s+([A-Za-z_]\w*)\s*;", post_admission):
        if target != "finish":
            raise AssertionError(
                f"forget migration escaped common cleanup: goto {target}"
            )
    terminal_cleanup = (
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "}"
    )
    if not migration.rstrip().endswith(terminal_cleanup):
        raise AssertionError("forget migration cleanup is not the terminal exit")
    for escaped in ('"BEGIN TRANSACTION;"', '"COMMIT;"', '"ROLLBACK;"'):
        if escaped in migration:
            raise AssertionError(
                f"forget migration escaped common cleanup: {escaped}"
            )
    migration_body = (
        "rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = exec_sql (store->conn,\n"
        '            "SELECT CASE WHEN ("\n'
        '            "  (SELECT COUNT(*) FROM ("\n'
        '            "     SELECT * FROM fact_forget_intent"\n'
        '            "     EXCEPT SELECT * FROM fact_forget_intent_rebuild)) = 0"\n'
        '            "  AND (SELECT COUNT(*) FROM ("\n'
        '            "     SELECT * FROM fact_forget_intent_rebuild"\n'
        '            "     EXCEPT SELECT * FROM fact_forget_intent)) = 0"\n'
        '            ") THEN 1 ELSE error(\'forget intent rebuild lost rows\') END;");\n'
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"\n'
        '          "ALTER TABLE fact_forget_intent_rebuild "\n'
        '          "  RENAME TO fact_forget_intent;");'
    )
    if post_admission.strip() != migration_body:
        raise AssertionError("forget migration body sequence drifted")
    reconcile = function_body(
        store, "wyrelog_error_t\nwyl_fact_store_forget_reconcile ("
    )
    quarantine_stop = (
        "if (quarantine_rc != WYRELOG_E_OK) {\n"
        "        rc = quarantine_rc;\n"
        "        broke = TRUE;\n"
        "      }"
    )
    if "quarantine_rc = quarantine_forget_intent_unlocked (store," \
            not in reconcile or quarantine_stop not in reconcile:
        raise AssertionError("forget quarantine failure propagation drifted")

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
        "test_migration_commit_failure_rolls_back",
        "test_migration_rollback_failure_poison_reopen",
        "fail_commit_rollback_succeeds",
        "failed), ==, WYRELOG_E_IO",
        "wyl_fact_store_test_duckdb_call_count",
        "wyl_fact_store_forget_reconcile",
        "WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE",
        "WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH",
        "WYL_FACT_STORE_TRANSACTION_TEST_COMPOUND_PUT",
        "WYL_FACT_STORE_TRANSACTION_TEST_FORGET_COMPLETE",
        "WYL_FACT_STORE_TRANSACTION_TEST_FORGET_STATE_MIGRATION",
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

def source_key(root: PurePath, path: PurePath) -> str:
    return path.relative_to(root).as_posix()


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
                paths.add(source_key(root, path))
    return {path: (root / path).read_text(encoding="utf-8") for path in paths}

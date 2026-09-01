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
        if re.search(r"\bstatic\s+WylFactStoreConnectionSession\b",
                     files[path]):
            raise AssertionError(f"connection session retained beyond a scope: {path}")
    expected_calls = {
        "wyrelog/fact/store.c": (4, 4),
        "wyrelog/fact/compound.c": (5, 7),
        "wyrelog/fact/replay.c": (2, 2),
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
        raise AssertionError("typed SQL seams lost their compile-time gate")
    for symbol in SEAM_SYMBOLS:
        if symbol not in seam_header:
            raise AssertionError(f"typed SQL seam declaration missing: {symbol}")
        if store.count(symbol) != 1:
            raise AssertionError(f"typed SQL seam definition drifted: {symbol}")
    first_seam = "\nwyrelog_error_t\nwyl_fact_store_test_exec_sql"
    first_seam_at = store.index(first_seam)
    seam_start = store.rfind("#if defined(WYL_TEST_HANDLE_SEAMS)",
                             0, first_seam_at)
    seam_end = store.index("#endif", first_seam_at)
    if seam_start < 0 or "#endif" in store[seam_start:first_seam_at]:
        raise AssertionError("typed SQL seam lost its immediate test-only guard")
    seam_region = store[seam_start:seam_end]
    if any(symbol not in seam_region for symbol in SEAM_SYMBOLS):
        raise AssertionError("typed SQL seam escaped the test-only source guard")

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
        "#if defined(WYL_TEST_HANDLE_SEAMS)\nwyrelog_error_t",
        "wyrelog_error_t",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    marker = "dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep"
    changed["tests/meson.build"] = changed["tests/meson.build"].replace(
        marker, "dependencies : [wyrelog_dep, wyrelog_handle_test_seams_dep, wirelog_dep", 1
    )
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

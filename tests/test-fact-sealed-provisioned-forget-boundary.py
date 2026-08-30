#!/usr/bin/env python3
"""Guard the provisioned SEALED forget-reconciliation proof for issue #871."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import tempfile


class BoundaryError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BoundaryError(message)


def function_body(source: str, name: str) -> str:
    marker = f"\n{name} ("
    start = source.find(marker)
    require(start >= 0, f"missing function {name}")
    brace = source.find("{", start)
    require(brace >= 0, f"missing body for {name}")
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise BoundaryError(f"unterminated body for {name}")


def secure_step(workflow: str) -> str:
    start = workflow.find("- name: Build secure DuckDB backend from pinned source")
    require(start >= 0, "missing pinned-source secure build step")
    end = workflow.find("- name: Remove secure DuckDB compile swap", start)
    require(end > start, "secure build step has no bounded end")
    return workflow[start:end]


def validate(root: pathlib.Path) -> None:
    replay_path = root / "tests/test-fact-replay.c"
    meson_path = root / "tests/meson.build"
    opener_path = root / "wyrelog/fact/store-open-private.c"
    production_replay_path = root / "wyrelog/fact/replay.c"
    replay = replay_path.read_text(encoding="utf-8")
    meson = meson_path.read_text(encoding="utf-8")
    opener = opener_path.read_text(encoding="utf-8")
    production_replay = production_replay_path.read_text(encoding="utf-8")

    open_body = function_body(opener, "wyl_fact_store_open_provisioned_graph")
    require("WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE" in open_body,
            "provisioned opener no longer admits ACTIVE")
    require("WYL_POLICY_GRAPH_LIFECYCLE_SEALED" in open_body,
            "provisioned opener no longer admits SEALED")
    require("open_provisioned_active" in open_body,
            "authority admission no longer reaches the retained pair")

    graph_open_body = function_body(production_replay, "open_graph_store")
    provisioned_route = (
        "if (provisioned)\n"
        "    return wyl_fact_store_open_provisioned_graph ("
    )
    require(graph_open_body.count(provisioned_route) == 1,
            "boot replay no longer routes provisioned graphs through policy")
    route_index = graph_open_body.index(provisioned_route)
    resolver_index = graph_open_body.find("resolve_fact_db_path")
    raw_open_index = graph_open_body.find("wyl_fact_store_open (")
    require(resolver_index > route_index and raw_open_index > resolver_index,
            "boot replay resolves or path-opens before provisioned admission")

    test_name = "test_boot_converges_forget_on_sealed_provisioned_graph"
    test_body = function_body(replay, test_name)
    helper_names = (
        "provisioned_871_create_graph",
        "provisioned_871_append_one",
        "provisioned_871_count",
        "provisioned_871_text",
        "provisioned_871_status_cb",
    )
    proof = test_body + "".join(function_body(replay, name)
                                for name in helper_names)

    required_tokens = (
        "#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE",
        "g_test_skip",
        "wyl_policy_store_create_fact_graph_provisioning",
        "wyl_fact_graph_provisioning_recover",
        "wyl_fact_store_open_provisioned_graph",
        '"after_intent"',
        "WYRELOG_E_IO",
        "WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE",
        "WYL_POLICY_GRAPH_LIFECYCLE_SEALED",
        "WYL_POLICY_GRAPH_ERROR_NONE",
        "target_active->lifecycle_generation + 1",
        "sealed_authority->reconciliation_generation",
        "state = 'PENDING'",
        "state = 'COMPLETED'",
        "fact_batches",
        "fact_event_log",
        "fact_forget_audit",
        "rows_purged = 1",
        "statuses.saw_active_ready",
        "statuses.saw_sealed_without_engine",
        "control.saw_order_b",
        "sealed.count",
        "WYRELOG_E_POLICY",
    )
    for token in required_tokens:
        require(token in proof, f"proof lost required oracle: {token}")

    required_assertions = (
        ("pre-reconcile keyed pending intent",
         "\"WHERE batch_id = 'sealed-batch-871' AND state = 'PENDING' \"\n"
         "        \"AND rows_purged = 1;\"), ==, 1);"),
        ("pre-reconcile completed absence",
         "\"WHERE batch_id = 'sealed-batch-871' AND state = 'COMPLETED';\"), ==,\n"
         "        0);"),
        ("post-reconcile keyed pending absence",
         "provisioned_871_count (target_store, pending_sql), ==, 0);"),
        ("post-reconcile keyed completion",
         "provisioned_871_count (target_store, completed_sql), ==,\n"
         "        1);"),
        ("batch deletion",
         "\"SELECT COUNT(*) FROM fact_batches \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 0);"),
        ("event deletion",
         "\"SELECT COUNT(*) FROM fact_event_log \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 0);"),
        ("projection deletion",
         "provisioned_871_count (target_store,\n"
         "        projection_after_sql), ==, 0);"),
        ("exactly one audit row",
         "\"SELECT COUNT(*) FROM fact_forget_audit \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 1);"),
        ("exact audit attribution",
         "\"AND tenant_id = 'tenant-871' AND graph_id = 'sealed-orders' \"\n"
         "        \"AND operator = 'operator-871' AND reason = 'sealed-erasure-871' \"\n"
         "        \"AND rows_purged = 1;\"), ==, 1);"),
        ("active control row count",
         "g_assert_cmpuint (control.count, ==, 1);"),
        ("active control row identity",
         "g_assert_true (control.saw_order_b);"),
        ("sealed graph nonqueryable result",
         "tenant_id, target_graph, observed, handle_snapshot_cb, &sealed), ==,\n"
         "        WYRELOG_E_POLICY);"),
        ("sealed graph zero callbacks",
         "g_assert_cmpuint (sealed.count, ==, 0);"),
        ("active runtime admitted",
         "g_assert_true (statuses.saw_active_ready);"),
        ("sealed runtime excluded",
         "g_assert_true (statuses.saw_sealed_without_engine);"),
        ("authority store identity",
         "g_assert_cmpstr (after->store_uuid, ==, sealed_authority->store_uuid);"),
        ("authority format identity",
         "g_assert_cmpuint (after->format_version, ==,\n"
         "        sealed_authority->format_version);"),
        ("authority path identity",
         "g_assert_cmpuint (after->path_encoding_version, ==,\n"
         "        sealed_authority->path_encoding_version);"),
        ("authority lifecycle generation",
         "g_assert_cmpuint (after->lifecycle_generation, ==,\n"
         "        sealed_authority->lifecycle_generation);"),
        ("authority reconciliation generation",
         "g_assert_cmpuint (after->reconciliation_generation, ==,\n"
         "        sealed_authority->reconciliation_generation);"),
    )
    for label, assertion in required_assertions:
        require(proof.count(assertion) == 1,
                f"proof lost exact assertion: {label}")
    require("wyl_fact_store_forget_reconcile" not in proof,
            "test bypasses handle startup by calling reconciler directly")
    require("wyl_fact_store_open (" not in proof,
            "provisioned proof bypasses policy authority with a path open")
    require(replay.count(
        '"/fact-replay/boot-converges-forget-on-sealed-provisioned-graph"'
    ) == 1, "new runtime case must be registered exactly once")

    meson_tokens = (
        "test_fact_replay_c_args = ['-DWYL_HAS_FACT_STORE']",
        "if get_option('enable_secure_duckdb_bridge').enabled()",
        "test_fact_replay_c_args += '-DWYL_HAS_SECURE_DUCKDB_BRIDGE'",
        "c_args : test_fact_replay_c_args",
        "fact-sealed-provisioned-forget-boundary",
        "fact-sealed-provisioned-forget-boundary-self-test",
    )
    for token in meson_tokens:
        require(token in meson, f"Meson lost #871 wiring: {token}")

    for relative in (".github/workflows/ci-pr.yml",
                     ".github/workflows/ci-main.yml"):
        workflow = (root / relative).read_text(encoding="utf-8")
        step = secure_step(workflow)
        require("            test-fact-replay\n" in step,
                f"{relative} does not compile the replay runtime")
        require("            fact-replay \\\n" in step,
                f"{relative} does not execute the replay runtime")
        require("--test-args" not in step,
                f"{relative} filters the secure replay runtime")
        require("continue-on-error" not in step and "|| true" not in step,
                f"{relative} masks secure replay failure")


def mutate_once(root: pathlib.Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    source = path.read_text(encoding="utf-8")
    require(source.count(old) >= 1,
            f"self-test mutation target missing in {relative}: {old}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def self_test(root: pathlib.Path) -> None:
    mutations = (
        ("wyrelog/fact/store-open-private.c",
         "      && authority->lifecycle_state != "
         "WYL_POLICY_GRAPH_LIFECYCLE_SEALED", ""),
        ("wyrelog/fact/replay.c",
         "if (provisioned)\n"
         "    return wyl_fact_store_open_provisioned_graph (",
         "if (FALSE)\n"
         "    return wyl_fact_store_open_provisioned_graph ("),
        ("tests/test-fact-replay.c",
         "wyl_policy_store_create_fact_graph_provisioning",
         "wyl_policy_store_create_fact_graph"),
        ("tests/test-fact-replay.c", "\"after_intent\"",
         "\"before_completion\""),
        ("tests/test-fact-replay.c", "g_test_skip", "g_test_message"),
        ("tests/test-fact-replay.c",
         "\"WHERE batch_id = 'sealed-batch-871' AND state = 'PENDING' \"\n"
         "        \"AND rows_purged = 1;\"), ==, 1);",
         "\"WHERE batch_id = 'sealed-batch-871' AND state = 'PENDING' \"\n"
         "        \"AND rows_purged = 1;\"), ==, 0);"),
        ("tests/test-fact-replay.c",
         "provisioned_871_count (target_store, pending_sql), ==, 0);",
         "provisioned_871_count (target_store, pending_sql), ==, 1);"),
        ("tests/test-fact-replay.c",
         "provisioned_871_count (target_store, completed_sql), ==,\n"
         "        1);",
         "provisioned_871_count (target_store, completed_sql), ==,\n"
         "        0);"),
        ("tests/test-fact-replay.c",
         "\"SELECT COUNT(*) FROM fact_batches \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 0);",
         "\"SELECT COUNT(*) FROM fact_batches \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 1);"),
        ("tests/test-fact-replay.c",
         "\"SELECT COUNT(*) FROM fact_event_log \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 0);",
         "\"SELECT COUNT(*) FROM fact_event_log \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 1);"),
        ("tests/test-fact-replay.c",
         "projection_after_sql), ==, 0);",
         "projection_after_sql), ==, 1);"),
        ("tests/test-fact-replay.c",
         "\"SELECT COUNT(*) FROM fact_forget_audit \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 1);",
         "\"SELECT COUNT(*) FROM fact_forget_audit \"\n"
         "        \"WHERE batch_id = 'sealed-batch-871';\"), ==, 2);"),
        ("tests/test-fact-replay.c", "operator = 'operator-871'",
         "operator = 'operator-other'"),
        ("tests/test-fact-replay.c", "control.count, ==, 1",
         "control.count, ==, 2"),
        ("tests/test-fact-replay.c", "control.saw_order_b",
         "control.saw_order_a"),
        ("tests/test-fact-replay.c",
         "tenant_id, target_graph, observed, handle_snapshot_cb, &sealed), ==,\n"
         "        WYRELOG_E_POLICY);",
         "tenant_id, target_graph, observed, handle_snapshot_cb, &sealed), ==,\n"
         "        WYRELOG_E_OK);"),
        ("tests/test-fact-replay.c", "sealed.count, ==, 0",
         "sealed.count, ==, 1"),
        ("tests/test-fact-replay.c",
         "after->store_uuid, ==, sealed_authority->store_uuid",
         "after->store_uuid, !=, sealed_authority->store_uuid"),
        ("tests/test-fact-replay.c",
         "after->format_version, ==,\n"
         "        sealed_authority->format_version",
         "after->format_version, !=,\n"
         "        sealed_authority->format_version"),
        ("tests/test-fact-replay.c",
         "after->path_encoding_version, ==,\n"
         "        sealed_authority->path_encoding_version",
         "after->path_encoding_version, !=,\n"
         "        sealed_authority->path_encoding_version"),
        ("tests/test-fact-replay.c",
         "after->lifecycle_generation, ==,\n"
         "        sealed_authority->lifecycle_generation",
         "after->lifecycle_generation, ==,\n"
         "        sealed_authority->lifecycle_generation + 1"),
        ("tests/test-fact-replay.c",
         "after->reconciliation_generation, ==,\n"
         "        sealed_authority->reconciliation_generation",
         "after->reconciliation_generation, ==,\n"
         "        sealed_authority->reconciliation_generation + 1"),
        ("tests/test-fact-replay.c", "statuses.saw_active_ready",
         "statuses.seen"),
        ("tests/test-fact-replay.c", "statuses.saw_sealed_without_engine",
         "statuses.seen"),
        ("tests/meson.build",
         "test_fact_replay_c_args += '-DWYL_HAS_SECURE_DUCKDB_BRIDGE'",
         "test_fact_replay_c_args += '-DWYL_HAS_FACT_STORE'"),
        (".github/workflows/ci-pr.yml", "            test-fact-replay\n", ""),
        (".github/workflows/ci-main.yml", "            fact-replay \\\n", ""),
    )
    selected = (
        "tests/test-fact-replay.c",
        "tests/meson.build",
        "wyrelog/fact/store-open-private.c",
        "wyrelog/fact/replay.c",
        ".github/workflows/ci-pr.yml",
        ".github/workflows/ci-main.yml",
    )
    for relative, old, new in mutations:
        with tempfile.TemporaryDirectory(prefix="wyl-871-boundary-") as tmp:
            copy_root = pathlib.Path(tmp)
            for selected_path in selected:
                source = root / selected_path
                destination = copy_root / selected_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            mutate_once(copy_root, relative, old, new)
            try:
                validate(copy_root)
            except BoundaryError:
                continue
            raise BoundaryError(
                f"self-test mutation escaped detection: {relative}: {old}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()
    try:
        validate(root)
        if args.self_test:
            self_test(root)
    except (BoundaryError, OSError) as error:
        print(f"fact sealed provisioned forget boundary: FAIL: {error}")
        return 1
    print("fact sealed provisioned forget boundary: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

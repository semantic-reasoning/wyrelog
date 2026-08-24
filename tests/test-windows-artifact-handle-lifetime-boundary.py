#!/usr/bin/env python3
"""Guard the native Windows artifact HANDLE-lifetime inventory.

The inventory is deliberately structural.  It proves that every production
entry point reaching a bounded native namespace mutation has an explicit,
reviewed lifetime row; Windows runtime tests and Application Verifier prove
the ownership claims recorded in those rows.
"""

from dataclasses import dataclass, replace
from pathlib import Path
import re
import sys


MODULES = (
    "wyrelog/fact/graph-artifact-windows-namespace-private.c",
    "wyrelog/fact/graph-artifact-windows-locator-private.c",
    "wyrelog/fact/graph-artifact-windows-handle-private.c",
    "wyrelog/fact/graph-artifact-windows-lock-private.c",
    "wyrelog/fact/artifact-io-session-windows-private.c",
)

MUTATION_ROOTS = frozenset(
    {
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_locator_create_directory",
        "wyl_fact_artifact_win_directory_open_file",
        "entry_rename",
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_directory_entry_delete_exact",
        "wyl_fact_artifact_win_directory_delete_empty",
    }
)

OWNERSHIP_DESTRUCTORS = frozenset(
    {
        "wyl_fact_artifact_win_working_handle_free",
        "wyl_fact_artifact_win_entry_free",
        "wyl_fact_artifact_win_directory_free",
        "wyl_fact_artifact_win_lock_domain_free",
        "wyl_fact_artifact_win_lock_lease_free",
    }
)

OWNERSHIP_AUDIT_ENTRIES = frozenset(
    {
        "wyl_fact_artifact_io_session_open_existing_temp_child",
    }
)

NAME_STATES = frozenset({"named", "last_name_gone", "delete_pending"})
ORACLES = frozenset({"appverifier_only", "reachability_and_appverifier"})
PHASES = frozenset(
    {
        "pre_acquisition",
        "post_acquisition",
        "pre_linearization",
        "post_linearization",
    }
)
REACHABILITY = frozenset({"covered", "unreachable"})
RESIDUALS = frozenset(
    {
        "none",
        "confirmed_temp_child_ownership_defect",
        "temp_child_transfer_audit_required",
    }
)


@dataclass(frozen=True)
class Function:
    name: str
    body: str
    source: str
    is_static: bool


@dataclass(frozen=True)
class InventoryRow:
    entry: str
    identity: str
    owner: str
    name_state: str
    cleanup: str
    witnesses: str
    oracle: str
    phase: str
    reachability: str
    tests: tuple[str, ...]
    faults: tuple[str, ...]
    linearizer: str
    residual: str


@dataclass(frozen=True)
class FaultHook:
    arm: str
    selector: str
    probe: str


FAULT_HOOKS = {
    "namespace_replace_pre_final": FaultHook(
        "wyl_fact_artifact_win_namespace_set_test_fault",
        "WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_PRE_FINAL_DESTINATION_SUBSTITUTE",
        "WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_PRE_FINAL_DESTINATION_SUBSTITUTE",
    ),
    "namespace_replace_post_rename": FaultHook(
        "wyl_fact_artifact_win_namespace_set_test_fault",
        "WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN",
        "WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN",
    ),
    "locator_directory_flush": FaultHook(
        "wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test",
        "wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test",
        "next_directory_flush_error",
    ),
    "locator_rename_status": FaultHook(
        "wyl_fact_artifact_win_locator_fail_next_rename_status_for_test",
        "wyl_fact_artifact_win_locator_fail_next_rename_status_for_test",
        "wyl_fact_artifact_win_locator_take_next_rename_status_for_test",
    ),
}

RESIDUAL_CONTRACTS = {
    "wyl_fact_artifact_io_session_create_temp_child": (
        "missing",
        "confirmed_temp_child_ownership_defect",
    ),
    "wyl_fact_artifact_io_session_open_existing_temp_child": (
        "wyl_fact_artifact_win_temp_child_binding_free",
        "temp_child_transfer_audit_required",
    ),
}


def row(
    entry: str,
    linearizer: str,
    cleanup: str,
    test: str | tuple[str, ...] | None,
    *,
    identity: str = "entry FileId",
    owner: str = "returned opaque owner",
    name_state: str = "named",
    witnesses: str = "none",
    oracle: str = "appverifier_only",
    phase: str = "post_acquisition",
    reachability: str = "unreachable",
    faults: tuple[str, ...] = (),
    residual: str = "none",
) -> InventoryRow:
    return InventoryRow(
        entry=entry,
        identity=identity,
        owner=owner,
        name_state=name_state,
        cleanup=cleanup,
        witnesses=witnesses,
        oracle=oracle,
        phase=phase,
        reachability=reachability,
        tests=() if test is None else ((test,) if isinstance(test, str) else test),
        faults=faults,
        linearizer=linearizer,
        residual=residual,
    )


# The assertions in these rows are reviewed design claims.  The checker proves
# that the production boundary and every referenced symbol remain complete;
# runtime reachability and AppVerifier prove the claims themselves.
INVENTORY: tuple[InventoryRow, ...] = (
    row(
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_entry_free",
        "test_locator_relative_entry_lifecycle",
        owner="locator entry",
    ),
    row(
        "wyl_fact_artifact_win_locator_create_directory",
        "wyl_fact_artifact_win_locator_create_directory",
        "wyl_fact_artifact_win_directory_free",
        "test_locator_nested_directory_transport",
        identity="directory FileId",
        owner="locator directory",
    ),
    row(
        "wyl_fact_artifact_win_directory_open_file",
        "wyl_fact_artifact_win_directory_open_file",
        "wyl_fact_artifact_win_entry_free",
        "test_locator_nested_directory_transport",
        owner="nested entry",
    ),
    row(
        "wyl_fact_artifact_win_entry_rename_no_replace",
        "entry_rename",
        "wyl_fact_artifact_win_entry_free",
        "test_locator_relative_entry_lifecycle",
        identity="source FileId retained at destination",
        owner="source entry",
        phase="post_linearization",
        faults=("locator_rename_status",),
    ),
    row(
        "wyl_fact_artifact_win_entry_rename_replace_verified",
        "entry_rename",
        "wyl_fact_artifact_win_entry_free",
        "test_locator_rename_unsupported_class_mapping",
        identity="source FileId retained at destination",
        owner="source entry; displaced destination is caller-owned",
        phase="post_linearization",
        faults=("locator_rename_status",),
    ),
    row(
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_entry_free",
        "test_locator_replace_open_destination",
        owner="terminal entry",
        name_state="last_name_gone",
        witnesses="exact path and optional test witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
    ),
    row(
        "wyl_fact_artifact_win_directory_entry_delete_exact",
        "wyl_fact_artifact_win_directory_entry_delete_exact",
        "wyl_fact_artifact_win_entry_free",
        "test_mutation_handle_lifetime_temp_tree",
        owner="terminal child entry",
        name_state="delete_pending",
        witnesses="exact child witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
    ),
    row(
        "wyl_fact_artifact_win_directory_delete_empty",
        "wyl_fact_artifact_win_directory_delete_empty",
        "wyl_fact_artifact_win_directory_free",
        "test_mutation_handle_lifetime_temp_tree",
        identity="directory FileId",
        owner="terminal root directory",
        name_state="delete_pending",
        witnesses="exact directory witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
    ),
    row(
        "wyl_fact_artifact_win_namespace_new",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_namespace_free",
        "test_native_namespace_captured_owner_acl_binding",
        identity="graph and lock FileIds",
        owner="namespace",
    ),
    row(
        "wyl_fact_artifact_win_namespace_new_with_main",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_namespace_free",
        "test_native_namespace_main_sidecar_lifecycle",
        identity="graph, main and lock FileIds",
        owner="namespace",
    ),
    row(
        "wyl_fact_artifact_win_namespace_open_fixed",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_binding_free",
        "test_native_namespace_captured_owner_acl_binding",
        identity="fixed artifact FileId",
        owner="fixed binding",
    ),
    row(
        "wyl_fact_artifact_win_lease_open_sidecar",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_sidecar_binding_free",
        "test_native_namespace_sidecar_replacement_isolated",
        identity="sidecar FileId",
        owner="sidecar binding",
    ),
    row(
        "wyl_fact_artifact_win_lease_create_temp_binding",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_temp_binding_free",
        "test_native_namespace_sidecar_replacement_isolated",
        identity="temporary source FileId",
        owner="temporary binding",
    ),
    row(
        "wyl_fact_artifact_win_lease_create_temp_token",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_temp_token_free",
        "test_mutation_handle_lifetime_temp_tokens",
        identity="temporary token FileId",
        owner="temporary token",
    ),
    row(
        "wyl_fact_artifact_win_lease_create_temp_root",
        "wyl_fact_artifact_win_locator_create_directory",
        "wyl_fact_artifact_win_temp_root_free",
        "test_mutation_handle_lifetime_temp_tree",
        identity="temporary directory FileId",
        owner="temporary root",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_temp_root_create_with_orphan_evidence",
        "wyl_fact_artifact_win_locator_create_directory",
        "wyl_fact_artifact_win_temp_root_free",
        "test_temp_root_spill_child_capabilities",
        identity="temporary directory FileId",
        owner="temporary root and copied evidence",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_temp_root_create_child",
        "wyl_fact_artifact_win_directory_open_file",
        "wyl_fact_artifact_win_temp_child_free",
        "test_mutation_handle_lifetime_temp_tree",
        identity="temporary child FileId",
        owner="temporary child",
    ),
    row(
        "wyl_fact_artifact_win_temp_root_create_child_binding",
        "wyl_fact_artifact_win_directory_open_file",
        "wyl_fact_artifact_win_temp_child_binding_free",
        "test_temp_root_spill_child_capabilities",
        identity="temporary child FileId",
        owner="temporary child binding",
    ),
    row(
        "wyl_fact_artifact_win_temp_root_create_child_with_orphan_evidence",
        "wyl_fact_artifact_win_directory_open_file",
        "wyl_fact_artifact_win_temp_child_binding_free",
        "test_temp_root_spill_child_capabilities",
        identity="temporary child FileId",
        owner="temporary child binding and copied evidence",
    ),
    row(
        "wyl_fact_artifact_win_temp_root_child_exists",
        "wyl_fact_artifact_win_directory_open_file",
        "wyl_fact_artifact_win_entry_free",
        "test_temp_root_spill_child_capabilities",
        identity="probe result FileId when present",
        owner="ephemeral probe entry",
        phase="pre_acquisition",
    ),
    row(
        "wyl_fact_artifact_win_sidecar_binding_publish_no_replace",
        "wyl_fact_artifact_win_entry_rename_no_replace",
        "wyl_fact_artifact_win_sidecar_binding_free",
        "test_native_namespace_main_sidecar_lifecycle",
        identity="sidecar FileId retained at destination",
        owner="sidecar binding",
        phase="post_linearization",
        faults=("locator_directory_flush", "locator_rename_status"),
    ),
    row(
        "wyl_fact_artifact_win_temp_token_rename_no_replace",
        "wyl_fact_artifact_win_entry_rename_no_replace",
        "wyl_fact_artifact_win_temp_token_free",
        "test_native_namespace_main_sidecar_lifecycle",
        identity="token FileId retained at destination",
        owner="temporary token",
        phase="post_linearization",
        faults=("locator_directory_flush", "locator_rename_status"),
    ),
    row(
        "wyl_fact_artifact_win_temp_binding_replace_sidecar",
        "wyl_fact_artifact_win_entry_rename_replace_verified",
        "wyl_fact_artifact_win_entry_free",
        "test_native_namespace_sidecar_replacement_isolated",
        identity="displaced destination FileId",
        owner="internal old destination state until return",
        name_state="last_name_gone",
        witnesses="pre-replacement destination witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=(
            "namespace_replace_pre_final",
            "namespace_replace_post_rename",
            "locator_directory_flush",
            "locator_rename_status",
        ),
    ),
    row(
        "wyl_fact_artifact_win_sidecar_binding_replace_existing_wal",
        "wyl_fact_artifact_win_entry_rename_replace_verified",
        "wyl_fact_artifact_win_entry_free",
        "test_native_namespace_main_sidecar_lifecycle",
        identity="displaced WAL FileId",
        owner="internal old destination state until return",
        name_state="last_name_gone",
        witnesses="pre-replacement WAL witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=(
            "namespace_replace_pre_final",
            "namespace_replace_post_rename",
            "locator_directory_flush",
            "locator_rename_status",
        ),
    ),
    row(
        "wyl_fact_artifact_win_sidecar_binding_retire",
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_sidecar_binding_free",
        "test_native_namespace_sidecar_replacement_isolated",
        identity="retired sidecar FileId",
        owner="terminal sidecar binding",
        name_state="delete_pending",
        witnesses="pre-retirement sidecar witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_temp_token_unlink",
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_temp_token_free",
        "test_mutation_handle_lifetime_temp_tokens",
        identity="unlinked token FileId",
        owner="terminal temporary token",
        name_state="delete_pending",
        witnesses="pre-unlink token witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_lease_recover_temp_token",
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_entry_free",
        "test_mutation_handle_lifetime_temp_tokens",
        identity="recovered token FileId from evidence",
        owner="internal recovery entry, released before return",
        name_state="last_name_gone",
        witnesses="pre-recovery token witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_lease_recover_temp_token_v2",
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_entry_free",
        "test_mutation_handle_lifetime_temp_tokens",
        identity="authenticated recovered token FileId",
        owner="v1 internal recovery entry, released before return",
        name_state="last_name_gone",
        witnesses="pre-recovery token witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_temp_child_retire",
        "wyl_fact_artifact_win_directory_entry_delete_exact",
        "wyl_fact_artifact_win_temp_child_free",
        "test_mutation_handle_lifetime_temp_tree",
        identity="retired child FileId",
        owner="terminal temporary child",
        name_state="delete_pending",
        witnesses="pre-retirement child witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_temp_root_retire",
        "wyl_fact_artifact_win_directory_delete_empty",
        "wyl_fact_artifact_win_temp_root_free",
        "test_mutation_handle_lifetime_temp_tree",
        identity="retired root directory FileId",
        owner="terminal temporary root",
        name_state="delete_pending",
        witnesses="pre-retirement directory witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_win_working_handle_free",
        "wyl_fact_artifact_win_working_handle_free",
        "wyl_fact_artifact_win_working_handle_free",
        "test_working_handle_free_closes_unlinked_object",
        identity="working guardian FileId",
        owner="working-handle guardian",
        name_state="last_name_gone",
        witnesses="pre-free exact witness",
        oracle="reachability_and_appverifier",
        phase="post_acquisition",
        reachability="covered",
    ),
    row(
        "wyl_fact_artifact_win_entry_free",
        "wyl_fact_artifact_win_entry_free",
        "wyl_fact_artifact_win_entry_free",
        "test_locator_replace_open_destination",
        owner="entry guardian",
        name_state="last_name_gone",
        witnesses="captured displaced or deleted FileId",
        oracle="reachability_and_appverifier",
        phase="post_acquisition",
        reachability="covered",
    ),
    row(
        "wyl_fact_artifact_win_directory_free",
        "wyl_fact_artifact_win_directory_free",
        "wyl_fact_artifact_win_directory_free",
        "test_locator_nested_directory_transport",
        identity="directory FileId",
        owner="directory guardian",
        name_state="delete_pending",
        witnesses="captured directory FileId",
        oracle="reachability_and_appverifier",
        phase="post_acquisition",
        reachability="covered",
    ),
    row(
        "wyl_fact_artifact_win_lock_domain_free",
        "wyl_fact_artifact_win_lock_domain_free",
        "wyl_fact_artifact_win_lock_domain_free",
        "test_native_lock_domain_alias_reader_writer_contention",
        identity="named lock FileId",
        owner="lock-domain guardian",
    ),
    row(
        "wyl_fact_artifact_win_lock_lease_free",
        "wyl_fact_artifact_win_lock_lease_free",
        "wyl_fact_artifact_win_lock_lease_free",
        "test_native_lock_domain_alias_reader_writer_contention",
        identity="named lock FileId",
        owner="lock lease duplicate",
    ),
    row(
        "wyl_fact_artifact_io_session_create_temp_root",
        "wyl_fact_artifact_win_locator_create_directory",
        "wyl_fact_artifact_win_temp_root_free",
        None,
        identity="temporary directory FileId",
        owner="returned temporary root",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_artifact_io_session_create_temp_child",
        "wyl_fact_artifact_win_directory_open_file",
        "missing",
        None,
        identity="temporary child FileId",
        owner="unreturned child plus retained internal child binding and I/O session",
        residual="confirmed_temp_child_ownership_defect",
    ),
    row(
        "wyl_fact_artifact_io_session_open_existing_temp_child",
        "wyl_fact_artifact_win_temp_child_open",
        "wyl_fact_artifact_win_temp_child_binding_free",
        None,
        identity="existing temporary child FileId",
        owner="returned I/O session after immediate live-binding release",
        residual="temp_child_transfer_audit_required",
    ),
    row(
        "wyl_fact_artifact_io_session_open_reader_wal",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_sidecar_binding_free",
        None,
        identity="WAL FileId",
        owner="returned read-only I/O session",
    ),
    row(
        "wyl_fact_artifact_io_session_open_sidecar",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_sidecar_binding_free",
        None,
        identity="sidecar FileId",
        owner="returned I/O session and sidecar binding",
    ),
    row(
        "wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_sidecar_binding_free",
        "test_neutral_sidecar_authorities_forward",
        identity="sidecar FileId",
        owner="returned neutral sidecar binding",
    ),
    row(
        "wyl_fact_artifact_namespace_open_provisioned_pair_internal",
        "wyl_fact_artifact_win_locator_open",
        "wyl_fact_artifact_win_namespace_free",
        "test_namespace_from_provisioned_pair",
        identity="provisioned graph, main and lock FileIds",
        owner="returned pair-backed namespace",
    ),
    row(
        "wyl_fact_artifact_sidecar_binding_replace_existing_wal",
        "entry_rename",
        "wyl_fact_artifact_win_entry_free",
        "test_native_namespace_main_sidecar_lifecycle",
        identity="displaced WAL FileId",
        owner="neutral source and destination bindings",
        name_state="last_name_gone",
        witnesses="pre-replacement WAL witness",
        oracle="reachability_and_appverifier",
        phase="post_linearization",
        reachability="covered",
        faults=(
            "namespace_replace_pre_final",
            "namespace_replace_post_rename",
            "locator_directory_flush",
            "locator_rename_status",
        ),
    ),
    row(
        "wyl_fact_artifact_sidecar_binding_retire",
        "wyl_fact_artifact_win_entry_delete_exact",
        "wyl_fact_artifact_win_sidecar_binding_free",
        "test_neutral_sidecar_authorities_forward",
        identity="retired sidecar FileId",
        owner="terminal neutral sidecar binding",
        name_state="delete_pending",
        phase="post_linearization",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_duckdb_temp_root_create_with_orphan_evidence",
        "wyl_fact_artifact_win_locator_create_directory",
        "wyl_fact_artifact_win_temp_root_free",
        None,
        identity="temporary directory FileId",
        owner="returned neutral temporary root and evidence",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_duckdb_temp_root_child_exists",
        "wyl_fact_artifact_win_directory_open_file",
        "wyl_fact_artifact_win_entry_free",
        None,
        identity="probe result FileId when present",
        owner="ephemeral neutral probe entry",
        phase="pre_acquisition",
    ),
    row(
        "wyl_fact_duckdb_temp_child_retire",
        "wyl_fact_artifact_win_directory_entry_delete_exact",
        "wyl_fact_artifact_win_temp_child_free",
        None,
        identity="retired child FileId",
        owner="terminal neutral temporary child",
        name_state="delete_pending",
        phase="post_linearization",
        faults=("locator_directory_flush",),
    ),
    row(
        "wyl_fact_duckdb_temp_root_retire",
        "wyl_fact_artifact_win_directory_delete_empty",
        "wyl_fact_artifact_win_temp_root_free",
        None,
        identity="retired root directory FileId",
        owner="terminal neutral temporary root",
        name_state="delete_pending",
        phase="post_linearization",
        faults=("locator_directory_flush",),
    ),
)


def fail(message: str) -> None:
    raise SystemExit(f"Windows artifact HANDLE-lifetime boundary: {message}")


def strip_comments_and_literals(text: str) -> str:
    """Blank comments and C string/character literals, preserving offsets."""
    out: list[str] = []
    index = 0
    while index < len(text):
        pair = text[index : index + 2]
        char = text[index]
        if pair == "/*":
            end = text.find("*/", index + 2)
            if end < 0:
                fail("unterminated block comment")
            end += 2
            out.extend("\n" if item == "\n" else " " for item in text[index:end])
            index = end
        elif pair == "//":
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            out.extend(" " for _ in text[index:end])
            index = end
        elif char in {'"', "'"}:
            quote = char
            out.append(" ")
            index += 1
            while index < len(text) and text[index] != quote:
                if text[index] == "\\" and index + 1 < len(text):
                    out.extend((" ", " "))
                    index += 2
                else:
                    out.append("\n" if text[index] == "\n" else " ")
                    index += 1
            if index >= len(text):
                fail("unterminated C literal")
            out.append(" ")
            index += 1
        else:
            out.append(char)
            index += 1
    return "".join(out)


def matching(text: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opening:
            depth += 1
        elif text[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    fail(f"unbalanced {opening}{closing} near byte {start}")


def extract_functions(
    source: str, text: str, *, merge_duplicates: bool = False
) -> dict[str, Function]:
    stripped = strip_comments_and_literals(text)
    functions: dict[str, Function] = {}
    keywords = {"if", "for", "while", "switch"}
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", stripped):
        name = match.group(1)
        if name in keywords:
            continue
        close_paren = matching(stripped, stripped.index("(", match.start()), "(", ")")
        cursor = close_paren + 1
        while cursor < len(stripped) and stripped[cursor].isspace():
            cursor += 1
        if cursor >= len(stripped) or stripped[cursor] != "{":
            continue
        close_brace = matching(stripped, cursor, "{", "}")
        boundary = max(
            stripped.rfind(";", 0, match.start()),
            stripped.rfind("}", 0, match.start()),
            stripped.rfind("{", 0, match.start()),
        )
        header = stripped[boundary + 1 : match.start()]
        if "=" in header or re.search(r"\b(return|sizeof)\b", header):
            continue
        function = Function(
            name=name,
            body=stripped[cursor + 1 : close_brace],
            source=source,
            is_static=re.search(r"\bstatic\b", header) is not None,
        )
        if name in functions:
            if not merge_duplicates:
                fail(f"duplicate function definition: {name}")
            previous = functions[name]
            functions[name] = Function(
                name=name,
                body=previous.body + "\n" + function.body,
                source=source,
                is_static=previous.is_static and function.is_static,
            )
        else:
            functions[name] = function
    if not functions:
        fail(f"could not classify any functions in {source}")
    return functions


def load_functions(root: Path, overrides: dict[str, str] | None = None):
    overrides = overrides or {}
    functions: dict[str, Function] = {}
    sources: dict[str, str] = {}
    for relative in MODULES:
        text = overrides.get(relative)
        if text is None:
            text = (root / relative).read_text(encoding="utf-8")
        sources[relative] = text
        for name, function in extract_functions(relative, text).items():
            if name in functions:
                previous = functions[name]
                if not previous.is_static or not function.is_static:
                    fail(f"external function {name} has multiple definitions")
                # File-local helpers may intentionally share a conventional
                # name.  Their union is sufficient for the boundary graph:
                # neither is itself an externally inventoried entry point.
                functions[name] = Function(
                    name=name,
                    body=previous.body + "\n" + function.body,
                    source=previous.source + "," + function.source,
                    is_static=True,
                )
                continue
            functions[name] = function
    return functions, sources


def call_graph(functions: dict[str, Function]) -> dict[str, set[str]]:
    known = functions.keys()
    return {
        name: set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", function.body)) & known
        for name, function in functions.items()
    }


def has_identifier(text: str, identifier: str) -> bool:
    return re.search(rf"\b{re.escape(identifier)}\b", text) is not None


def has_call(text: str, function: str) -> bool:
    return re.search(rf"\b{re.escape(function)}\s*\(", text) is not None


def reachable(graph: dict[str, set[str]], start: str) -> set[str]:
    reached: set[str] = set()
    pending = [start]
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        pending.extend(graph.get(name, ()))
    return reached


def mutation_entries(functions: dict[str, Function]) -> set[str]:
    missing_roots = MUTATION_ROOTS - functions.keys()
    if missing_roots:
        fail("missing mutation roots: " + ", ".join(sorted(missing_roots)))
    graph = call_graph(functions)

    return {
        name
        for name, function in functions.items()
        if not function.is_static and reachable(graph, name) & MUTATION_ROOTS
    }


def validate(root: Path, inventory=INVENTORY, overrides=None) -> list[str]:
    functions, sources = load_functions(root, overrides)
    production_graph = call_graph(functions)
    test_source = "tests/test-fact-artifact-namespace-windows.c"
    test_text = (overrides or {}).get(test_source)
    if test_text is None:
        test_text = (root / test_source).read_text(encoding="utf-8")
    test_functions = extract_functions(test_source, test_text, merge_duplicates=True)
    combined_functions = dict(functions)
    combined_functions.update(test_functions)
    combined_graph = call_graph(combined_functions)
    problems: list[str] = []
    rows_by_entry: dict[str, list[InventoryRow]] = {}
    for row in inventory:
        rows_by_entry.setdefault(row.entry, []).append(row)
        if row.entry not in functions:
            problems.append(f"row names unknown entry {row.entry}")
        if row.cleanup == "missing":
            if row.residual != "confirmed_temp_child_ownership_defect":
                problems.append(f"{row.entry} has an unexplained missing cleanup")
        elif row.cleanup not in functions:
            problems.append(f"{row.entry} names unknown cleanup {row.cleanup}")
        if row.linearizer not in functions:
            problems.append(f"{row.entry} names unknown linearizer {row.linearizer}")
        elif row.entry in functions and row.linearizer not in reachable(
            production_graph, row.entry
        ):
            problems.append(
                f"{row.entry} does not reach linearizer {row.linearizer}"
            )
        if row.name_state not in NAME_STATES:
            problems.append(f"{row.entry} has invalid name state {row.name_state}")
        if row.oracle not in ORACLES:
            problems.append(f"{row.entry} has invalid oracle {row.oracle}")
        if row.phase not in PHASES:
            problems.append(f"{row.entry} has invalid phase {row.phase}")
        if row.reachability not in REACHABILITY:
            problems.append(
                f"{row.entry} has invalid reachability {row.reachability}"
            )
        if row.residual not in RESIDUALS:
            problems.append(f"{row.entry} has invalid residual {row.residual}")
        residual_contract = RESIDUAL_CONTRACTS.get(row.entry)
        if residual_contract is None:
            if row.residual != "none":
                problems.append(
                    f"{row.entry} has an unexpected residual {row.residual}"
                )
        elif (row.cleanup, row.residual) != residual_contract:
            problems.append(
                f"{row.entry} must retain cleanup/residual contract "
                f"{residual_contract}"
            )
        if row.oracle == "reachability_and_appverifier" and row.name_state == "named":
            problems.append(f"{row.entry} assigns reachability to a named object")
        if row.reachability == "covered" and not row.tests:
            problems.append(f"{row.entry} claims coverage without a test")
        for test in row.tests:
            if test not in test_functions:
                problems.append(f"{row.entry} names unknown test {test}")
            elif row.entry not in reachable(combined_graph, test):
                problems.append(f"{test} does not exercise {row.entry}")
        unknown_faults = set(row.faults) - FAULT_HOOKS.keys()
        if unknown_faults:
            problems.append(
                f"{row.entry} names unknown faults "
                + ", ".join(sorted(unknown_faults))
            )
        if row.entry in functions:
            entry_bodies = "\n".join(
                functions[name].body
                for name in reachable(production_graph, row.entry)
            )
            expected_faults = {
                name for name, hook in FAULT_HOOKS.items()
                if has_identifier(entry_bodies, hook.probe)
            }
            if set(row.faults) != expected_faults:
                problems.append(
                    f"{row.entry} fault mapping is {sorted(row.faults)}; "
                    f"expected {sorted(expected_faults)}"
                )
    required = (
        mutation_entries(functions)
        | OWNERSHIP_DESTRUCTORS
        | OWNERSHIP_AUDIT_ENTRIES
    )
    for entry in sorted(required):
        count = len(rows_by_entry.get(entry, ()))
        if count != 1:
            problems.append(f"{entry} has {count} inventory rows; expected 1")
    for entry in rows_by_entry.keys() - required:
        problems.append(f"{entry} is inventoried but does not reach a mutation root")

    for name, hook in FAULT_HOOKS.items():
        if hook.arm not in functions:
            problems.append(f"fault hook {name} names unknown arm {hook.arm}")
            continue
        armed_by = [
            test_name
            for test_name, function in test_functions.items()
            if has_call(function.body, hook.arm)
            and has_identifier(function.body, hook.selector)
        ]
        if not armed_by:
            problems.append(f"fault hook {name} has no deliberate test-side arm")

    native_transports = re.compile(
        r"\b(?:DeleteFileW|RemoveDirectoryW|MoveFileExW|SetFileInformationByHandle)\s*\("
    )
    for relative, text in sources.items():
        if native_transports.search(strip_comments_and_literals(text)):
            problems.append(f"{relative} bypasses the bounded locator mutation transport")
    return problems


def self_test(root: Path) -> None:
    if not INVENTORY:
        return
    first = INVENTORY[0]
    cases = (
        (INVENTORY[1:], "expected 1"),
        (INVENTORY + (first,), "expected 1"),
        (INVENTORY + (replace(first, entry="wyl_unknown_entry"),), "unknown entry"),
        ((replace(first, oracle="invalid"),) + INVENTORY[1:], "invalid oracle"),
        ((replace(first, faults=("stale_fault",)),) + INVENTORY[1:], "unknown faults"),
    )
    for mutant, expected in cases:
        problems = validate(root, mutant)
        if not any(expected in problem for problem in problems):
            fail(f"self-test accepted inventory mutant requiring {expected}")

    external_wrapper = "wyl_fact_artifact_io_session_create_temp_root"
    without_external_wrapper = tuple(
        row for row in INVENTORY if row.entry != external_wrapper
    )
    problems = validate(root, without_external_wrapper)
    if not any(
        external_wrapper in problem and "expected 1" in problem
        for problem in problems
    ):
        fail("self-test accepted a missing external mutation-wrapper row")

    for entry in RESIDUAL_CONTRACTS:
        mutant = tuple(
            replace(
                item,
                cleanup="wyl_fact_artifact_win_entry_free",
                residual="none",
            )
            if item.entry == entry else item
            for item in INVENTORY
        )
        problems = validate(root, mutant)
        if not any(
            entry in problem and "must retain cleanup/residual" in problem
            for problem in problems
        ):
            fail(f"self-test accepted removal of residual contract for {entry}")

    locator = "wyrelog/fact/graph-artifact-windows-locator-private.c"
    locator_text = (root / locator).read_text(encoding="utf-8")
    flush_arm = FAULT_HOOKS["locator_directory_flush"].arm
    without_production_arm = locator_text.replace(
        flush_arm, f"{flush_arm}_not_the_arm"
    )
    problems = validate(root, INVENTORY, {locator: without_production_arm})
    if not any("names unknown arm" in problem for problem in problems):
        fail("self-test accepted a missing production fault arm")

    test_source = "tests/test-fact-artifact-namespace-windows.c"
    test_text = (root / test_source).read_text(encoding="utf-8")
    without_test_arm = test_text.replace(
        flush_arm, f"{flush_arm}_not_the_arm"
    )
    problems = validate(root, INVENTORY, {test_source: without_test_arm})
    if not any("no deliberate test-side arm" in problem for problem in problems):
        fail("self-test accepted a missing test-side fault arm")

    flush_probe = FAULT_HOOKS["locator_directory_flush"].probe
    without_exact_probe = locator_text.replace(
        flush_probe, f"{flush_probe}_not_the_probe"
    )
    problems = validate(root, INVENTORY, {locator: without_exact_probe})
    if not any("fault mapping" in problem for problem in problems):
        fail("self-test accepted a suffix-renamed fault probe")

    namespace_hook = FAULT_HOOKS["namespace_replace_pre_final"]
    without_exact_selector = test_text.replace(
        namespace_hook.selector, f"{namespace_hook.selector}_not_the_selector"
    )
    problems = validate(root, INVENTORY, {test_source: without_exact_selector})
    if not any("no deliberate test-side arm" in problem for problem in problems):
        fail("self-test accepted a suffix-renamed fault selector")

    for relative in (
        "wyrelog/fact/graph-artifact-windows-handle-private.c",
        "wyrelog/fact/graph-artifact-windows-locator-private.c",
    ):
        original = (root / relative).read_text(encoding="utf-8")
        bypass = original + "\nvoid wyl_forbidden (void) { DeleteFileW (NULL); }\n"
        problems = validate(root, INVENTORY, {relative: bypass})
        if not any("bypasses" in problem for problem in problems):
            fail(f"self-test accepted a direct native mutation bypass in {relative}")


def main() -> None:
    if len(sys.argv) == 2:
        root = Path(sys.argv[1])
        run_self_test = False
    elif len(sys.argv) == 3 and sys.argv[1] == "--self-test":
        root = Path(sys.argv[2])
        run_self_test = True
    else:
        fail("usage: test-windows-artifact-handle-lifetime-boundary.py "
             "[--self-test] <root>")
    problems = validate(root)
    if problems:
        fail("; ".join(problems))
    if run_self_test:
        self_test(root)
    print("Windows artifact HANDLE-lifetime boundary: OK")


if __name__ == "__main__":
    main()

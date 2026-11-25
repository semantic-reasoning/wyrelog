#!/usr/bin/env python3
"""Pin the macOS graph restore to the evidence forms of the provisioned
capture and execute.

On macOS the old provisioned main is a one-link file, so the transition
model admits it with or without a witness (#1303 U3), and the public execute
accepts the same unmarked observation.  The proof that the main is the
provisioned object therefore lives only in the provider calls the restore
makes: wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence
and wyl_fact_artifact_transition_posix_execute_provisioned_with_evidence.
Nothing at runtime distinguishes a step that skipped that proof, because the
journal-pinned identity alone also admits the main, and a capture just before
an unproved execute has already passed.  This guard reads the source instead.

Rules, all on wyrelog/fact/offline-restore-commit-authority-private.c.

Arm rules (ARM_RULES), one per function: graph_bind_prove_effect, the two
commit-step helpers graph_capture_provisioned and graph_execute_provisioned,
and graph_provenance_load.  For each:

- the function has exactly one ``#ifdef __APPLE__`` arm, and that arm calls
  its Darwin form (the evidence capture or execute, or for the provenance
  load the evidence decode) exactly once;
- no plain provider call (capture, name-only capture_provisioned, observe,
  name-only execute_provisioned, public execute), in its POSIX, Windows or
  platform-facade spelling, appears in that arm;
- the matching ``#else`` arm holds exactly one nested ``#ifdef G_OS_WIN32``
  arm, which calls its Windows form exactly once and no plain provider call;
- where the rule names one, the innermost ``#else`` keeps its one name-only
  call, so the Linux body is the one this guard does not otherwise judge.

Route rules (ROUTE_RULES), one per ported commit step: the step names no
provisioned capture or execute form, nor any execute form, directly, and
calls each of its helpers.  A direct call is reported before a missing
helper.  The facade capture a step makes for directory and lease identity is
not a provisioned capture and is allowed.  RETAIN and the rollback-side
syncs are pinned through their runs, their shared capture helper
retain_capture and their transaction effects: a run hands its effect over as
a callback, which count_calls does not see, so each effect has its own row.
PUBLISH and its directory flush are pinned the same way through
publish_run, publish_capture and publish_effect.  The resume dispatcher
calls only the step runs, never a provider form, and needs no row.
The macOS companion step has two rows: its transaction effect
darwin_companion_effect re-proves the root writer lease's authority, the
runtime state and the post-publish shape, and darwin_companion_recover calls
each authority helper of the Linux prologue it copies (the lease
acquisition, the policy bind, commit_snapshot_valid, check_policy, the lease
authorization of the resolver, graph_commit_quiesce, check_persisted,
check_runtime and the raw journal load) besides the provenance load and the
shape.  Presence is what a route rule checks: it does not judge the order
or the use of each result.

Companion rules (check_companion_rules), for the macOS companion step
(#1303 U5-7b):

- wyl_fact_offline_restore_graph_commit_companion_recover has exactly one
  ``#ifdef __APPLE__`` arm, which calls darwin_companion_recover exactly once
  and none of the replacement capture, compare, evidence setter, sync or
  mark itself; its ``#else`` arm calls neither darwin_companion_recover, the
  setter nor the capture;
- darwin_companion_recover calls the capture, the setter, the compare and
  the sync exactly once each and the mark never; it reloads the row from
  the setter's committed record exactly once (``row = g_steal_pointer
  (&stored)``); the capture, setter, reload, compare and sync appear in that
  order; a check_persisted lies strictly between the reload and the compare,
  and check_persisted appears exactly twice; and the setter and the sync
  take ``row`` as the expected record.

Select rules (check_select_rules), for the macOS selection step (#1303
U5-8):

- wyl_fact_offline_restore_graph_commit_select_replacement_run has exactly
  one ``#ifdef __APPLE__`` arm, which calls darwin_select_replacement
  exactly once and none of the replacement capture or compare, the store
  selection or open_shape itself; its ``#else`` arm calls neither
  darwin_select_replacement, the compare nor the evidence rebind;
- darwin_select_replacement calls the evidence rebind, the post-publish
  shape, the compare and the store selection exactly once each, and none of
  the capture, the setter, the sync, the mark or open_shape; the provenance
  load, the rebind, the shape, the compare and the selection appear in that
  order; and the selection takes ``row`` as the expected record and
  darwin_companion_effect as its effect.

The selection step also has a route row: it calls each authority helper of
the Linux prologue it copies, the provenance load and the shape.

Finalize rules (check_finalize_rules), for macOS FINALIZE (#1303 U5-9):

- wyl_fact_offline_restore_graph_commit_finalize_run has exactly one
  ``#ifdef __APPLE__`` arm, which calls darwin_finalize_selected exactly
  once and none of the Darwin cleanup shape or execute, the compare, the
  store begin or the store completion itself; its ``#else`` arm calls
  neither darwin_finalize_selected, the Darwin cleanup shape or execute,
  the compare nor the evidence rebind;
- darwin_finalize_selected calls graph_selected_provenance_load, the Darwin
  cleanup shape, the compare, the store begin and the store completion
  exactly once each, in that order, and none of graph_provenance_load, the
  rebind, the Darwin cleanup execute, the Linux cleanup shape or execute,
  the dual witness, the capture, the setter, the sync, the mark or the
  store selection; the completion takes ``row`` as the expected record and
  darwin_finalize_effect as its effect; and a ``row->darwin_operation_evidence
  == NULL`` test precedes its first wyl_fact_graph_resolver_open, so a row
  without evidence is refused before the graph is opened;
- darwin_finalize_effect calls the Darwin cleanup execute exactly once and
  the Linux one never, and compares the row's evidence (evidence_equal);
- graph_selected_provenance_load calls the rebind exactly once and
  evidence_equal at least once, names
  WYL_POLICY_GRAPH_PROVISIONING_RESTORE_SELECTED and never
  WYL_POLICY_GRAPH_PROVISIONING_ACTIVE.

FINALIZE has two route rows: darwin_finalize_selected calls each authority
helper of the Linux finalize prologue it copies (the lease acquisition, the
policy bind, the journal and row loads, the lease authorization of the
resolver, graph_commit_quiesce and check_runtime) and the selected
provenance load; darwin_finalize_effect re-proves the lease's authority and
the runtime state and calls the Darwin cleanup execute.

Terminal rules (check_terminal_rules), for the macOS terminal proof of a
FINALIZED restore (#1303 U5-10):

- wyl_fact_offline_restore_graph_commit_finalized_prove_terminal has exactly
  one ``#ifdef __APPLE__`` arm, which calls darwin_finalized_prove_terminal
  exactly once and none of the Darwin cleanup shape, the compare or the
  selected provenance load itself; its ``#else`` arm calls neither
  darwin_finalized_prove_terminal, the Darwin cleanup shape, the compare,
  the evidence rebind nor the selected provenance load;
- darwin_finalized_prove_terminal calls graph_selected_provenance_load, the
  Darwin cleanup shape and the compare exactly once each, in that order,
  and neither graph_provenance_load nor the rebind;
- it mutates nothing: it calls none of the Darwin cleanup execute, the
  Linux cleanup shape or execute, the dual witness, the capture, the
  setter, the sync, the mark, the store selection, the store begin or
  completion, or the journal attempt begin or completion;
- it refuses every shape but TERMINAL (``shape !=
  WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL``) and never names
  WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL;
- its last check_finalized_persisted follows the compare, and a
  ``row->darwin_operation_evidence == NULL`` test precedes its first
  wyl_fact_graph_resolver_open.

The terminal proof also has a route row: it calls each authority helper of
the Linux terminal proof it copies (the lease acquisition, the policy bind,
the journal and row loads, the lease authorization of the resolver, both
quiescence calls, check_finalized_persisted and check_runtime) and the
selected provenance load.

Promote rules (check_promote_rules), for the macOS promotion of a FINALIZED
restore (#1303 U5-11):

- wyl_fact_offline_restore_graph_commit_promote_run has exactly one
  ``#ifdef __APPLE__`` arm, which calls darwin_promote_selected exactly
  once and none of the Darwin cleanup shape, the compare, the selected
  provenance load, the store promotion or the unseal itself; its ``#else``
  arm calls none of darwin_promote_selected, the Darwin cleanup shape, the
  compare, the rebind or the selected provenance load, and never names
  darwin_promote_effect;
- darwin_promote_selected calls the selected provenance load, the Darwin
  cleanup shape and the store promotion exactly once each, in that order,
  before its first restore_unseal_graph; it calls none of the compare,
  graph_provenance_load, the rebind, the Darwin or Linux cleanup execute,
  the Linux cleanup shape, the dual witness, the capture, the setter, the
  sync, the mark, the store selection, the FINALIZE begin or completion,
  the journal attempt begin or completion, or
  promote_selected_terminal_effect;
- its last check_finalized_persisted lies between the shape and the store
  promotion, which is called as ``(policy, row, ...)`` with
  darwin_promote_effect;
- both it and darwin_promote_effect refuse every shape but TERMINAL and
  never name WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL, and a
  ``row->darwin_operation_evidence == NULL`` test precedes its first
  wyl_fact_graph_resolver_open;
- darwin_promote_effect calls evidence_equal before its shape and the
  shape before the compare, calls no wyl_policy_store_* function, no
  selected provenance load and none of check_finalized_persisted,
  check_policy, check_persisted, graph_provenance_load,
  restore_unseal_graph or graph_commit_quiesce, reaches no local helper
  whose body, or whose own local helpers' bodies, call a
  wyl_policy_store_* or wyl_fact_offline_restore_journal_store_* function,
  and mutates nothing: none of the Darwin or Linux cleanup execute, the
  capture, the setter, the sync, the mark, or the journal attempt begin or
  completion.

Both have route rows: darwin_promote_selected calls each authority helper
of the Linux promotion it copies (the lease acquisition, the policy bind,
the journal and row loads, the lease authorization of the resolver,
graph_commit_quiesce and check_runtime), the selected provenance load,
check_finalized_persisted, the receipt lookup and restore_unseal_graph;
darwin_promote_effect calls the lease authorization, check_runtime, the
Darwin cleanup shape and the compare.

Published rules (check_published_rules), for the macOS published proof of
a promoted restore (#1303 U5-12):

- wyl_fact_offline_restore_graph_commit_published_prove_terminal has
  exactly one ``#ifdef __APPLE__`` arm, which calls
  darwin_published_prove_terminal exactly once and none of the receipt
  lookup, the graph authority read, restore_unseal_graph, the store
  published proof, the Darwin cleanup shape or the compare itself; its
  ``#else`` arm calls none of darwin_published_prove_terminal, the Darwin
  cleanup shape, the compare, the rebind or the selected provenance load
  (the Linux receipt lookup, unseal and published proof stay allowed);
- darwin_published_prove_terminal calls the receipt lookup, the graph
  authority read and restore_unseal_graph exactly once each, and none of
  the store published proof, the row load, the journal load, the selected
  provenance load, graph_provenance_load, the Darwin or Linux cleanup
  shape, the compare, the rebind or the dual witness: each reads a state
  promotion deleted, or re-proves a namespace that is now live;
- it mutates nothing: none of the store promotion, the store selection,
  the FINALIZE begin or completion, the setter, the sync, the mark, the
  capture, the Darwin or Linux cleanup execute, the journal attempt begin
  or completion, or the journal store CAS;
- it names replacement_selected_pending_cleanup and
  WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION before its first
  receipt lookup, and tests ``receipt == NULL`` after the lookup and before
  its first mark_policy_published;
- its first receipt lookup, mark_policy_published,
  mark_lifecycle_handoff, graph authority read and restore_unseal_graph
  come in that order.

Its route row: darwin_published_prove_terminal calls each helper of the
Linux receipt fast path it copies (the journal encode, the receipt lookup,
the journal decode, both marks and restore_unseal_graph) and the graph
authority read.

function_body finds a definition whose return type is on the line before
its name or on the same line, and skips a declaration: a match whose
parameter list reaches a ``;`` before the next ``{``.  It counts braces
without regard to string or character literals; none of the pinned
functions holds a brace literal today.

Self-test: each mutant is applied to one function of a fixture set and must
fail with its own error code.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

SOURCE = "wyrelog/fact/offline-restore-commit-authority-private.c"
EVIDENCE_CALL = (
    "wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence"
)
WINDOWS_EVIDENCE_CALL = (
    "wyl_fact_artifact_transition_windows_capture_provisioned_with_evidence"
)
EXECUTE_EVIDENCE_CALL = (
    "wyl_fact_artifact_transition_posix_execute_provisioned_with_evidence"
)
WINDOWS_EXECUTE_EVIDENCE_CALL = (
    "wyl_fact_artifact_transition_windows_execute_provisioned_with_evidence"
)
DECODE_CALL = "wyl_fact_graph_darwin_evidence_decode"
PROVISIONING_LIST_CALL = "wyl_policy_store_graph_provisioning_list_for_graph"
PLAIN_CALLS = (
    "wyl_fact_artifact_transition_posix_capture_provisioned",
    "wyl_fact_artifact_transition_posix_capture",
    "wyl_fact_artifact_transition_posix_observe",
    # The platform facade's spellings of the same plain calls.
    "wyl_fact_artifact_transition_capture",
    "wyl_fact_artifact_transition_observe",
    # And the Windows backend's own.
    "wyl_fact_artifact_transition_windows_capture",
    "wyl_fact_artifact_transition_windows_observe",
)
EXECUTE_PLAIN_CALLS = (
    "wyl_fact_artifact_transition_posix_execute_provisioned",
    "wyl_fact_artifact_transition_posix_execute",
    "wyl_fact_artifact_transition_execute",
    "wyl_fact_artifact_transition_windows_execute",
)
FORBIDDEN_CALLS = PLAIN_CALLS + EXECUTE_PLAIN_CALLS
COMPANION_RECOVER = "wyl_fact_offline_restore_graph_commit_companion_recover"
DARWIN_COMPANION = "darwin_companion_recover"
CAPTURE_CALL = "wyl_fact_graph_directory_capture_darwin_replacement_evidence"
COMPARE_CALL = "wyl_fact_graph_directory_compare_darwin_replacement_evidence"
SETTER_CALL = "wyl_policy_store_graph_restore_replacement_set_darwin_evidence"
SYNC_CALL = "wyl_policy_store_graph_restore_replacement_sync_with_effect"
MARK_CALL = "wyl_policy_store_graph_restore_replacement_mark_companion_synced"
COMPANION_CALLS = (CAPTURE_CALL, COMPARE_CALL, SETTER_CALL, SYNC_CALL,
                   MARK_CALL)
RELOAD_PATTERN = re.compile(
    r"\brow\s*=\s*g_steal_pointer\s*\(\s*&stored\s*\)"
)
PERSISTED_PATTERN = re.compile(r"(?<![\w])check_persisted\s*\(")
SELECT_RUN = "wyl_fact_offline_restore_graph_commit_select_replacement_run"
DARWIN_SELECT = "darwin_select_replacement"
SELECT_CALL = "wyl_policy_store_graph_restore_select_with_effect"
REBIND_CALL = "wyl_fact_graph_darwin_evidence_rebind"
SHAPE_CALL = "darwin_post_publish_shape"
SELECT_EFFECT = "darwin_companion_effect"
LINUX_SHAPE_CALL = "open_shape"
FINALIZE_RUN = "wyl_fact_offline_restore_graph_commit_finalize_run"
DARWIN_FINALIZE = "darwin_finalize_selected"
FINALIZE_EFFECT = "darwin_finalize_effect"
SELECTED_PROVENANCE = "graph_selected_provenance_load"
CLEANUP_SHAPE_CALL = (
    "wyl_fact_graph_restore_darwin_selected_cleanup_shape_open"
)
CLEANUP_EXECUTE_CALL = "wyl_fact_graph_restore_darwin_selected_cleanup_execute"
LINUX_CLEANUP_SHAPE_CALL = "wyl_fact_graph_restore_selected_cleanup_shape_open"
LINUX_CLEANUP_EXECUTE_CALL = "wyl_fact_graph_restore_selected_cleanup_execute"
DUAL_WITNESS_CALL = "wyl_fact_graph_provisioned_restore_dual_witness_open"
BEGIN_CALL = "wyl_policy_store_graph_restore_selected_finalize_begin"
COMPLETE_CALL = "wyl_policy_store_graph_restore_selected_finalize_with_effect"
TERMINAL_RUN = "wyl_fact_offline_restore_graph_commit_finalized_prove_terminal"
DARWIN_TERMINAL = "darwin_finalized_prove_terminal"
PERSISTED_FINALIZED = "check_finalized_persisted"
JOURNAL_BEGIN_CALL = "wyl_fact_offline_restore_journal_begin_attempt"
JOURNAL_COMPLETE_CALL = "wyl_fact_offline_restore_journal_complete_attempt"
PROMOTE_RUN = "wyl_fact_offline_restore_graph_commit_promote_run"
DARWIN_PROMOTE = "darwin_promote_selected"
PROMOTE_EFFECT = "darwin_promote_effect"
PROMOTE_CALL = "wyl_policy_store_graph_restore_selected_promote_with_effect"
LINUX_PROMOTE_EFFECT = "promote_selected_terminal_effect"
UNSEAL_CALL = "restore_unseal_graph"
PUBLISHED_RUN = (
    "wyl_fact_offline_restore_graph_commit_published_prove_terminal"
)
DARWIN_PUBLISHED = "darwin_published_prove_terminal"
RECEIPT_CALL = "wyl_policy_store_offline_restore_receipt_lookup"
STORE_PUBLISHED_CALL = "wyl_policy_store_graph_restore_published_prove"
ROW_LOAD = "wyl_policy_store_graph_restore_replacement_load"
JOURNAL_LOAD = "wyl_fact_offline_restore_journal_store_load"
MARK_PUBLISHED = "wyl_fact_offline_restore_journal_mark_policy_published"
MARK_HANDOFF = "wyl_fact_offline_restore_journal_mark_lifecycle_handoff"
AUTHORITY_CALL = "wyl_policy_store_read_graph_authority"
# Local helpers that read or write the store: the promote effect runs
# inside the store transaction and must call none of them.
REENTRANT_HELPERS = ("check_finalized_persisted", "check_policy",
                     "check_persisted", "graph_provenance_load",
                     "graph_selected_provenance_load", UNSEAL_CALL,
                     "graph_commit_quiesce")
STORE_ENTRY = re.compile(
    r"(?<![\w])(?:wyl_policy_store_\w+"
    r"|wyl_fact_offline_restore_journal_store_\w+)\s*\("
)


@dataclass(frozen=True)
class ArmRule:
    function: str
    darwin: str
    windows: str
    linux: str | None


ARM_RULES = (
    ArmRule("graph_bind_prove_effect", EVIDENCE_CALL, WINDOWS_EVIDENCE_CALL,
            PLAIN_CALLS[0]),
    ArmRule("graph_capture_provisioned", EVIDENCE_CALL,
            WINDOWS_EVIDENCE_CALL, PLAIN_CALLS[0]),
    ArmRule("graph_execute_provisioned", EXECUTE_EVIDENCE_CALL,
            WINDOWS_EXECUTE_EVIDENCE_CALL, EXECUTE_PLAIN_CALLS[0]),
    ArmRule("graph_provenance_load", DECODE_CALL, PROVISIONING_LIST_CALL,
            None),
)


@dataclass(frozen=True)
class RouteRule:
    function: str
    helpers: tuple[str, ...]


ROUTE_FORBIDDEN = (
    PLAIN_CALLS[0],
    EVIDENCE_CALL,
    WINDOWS_EVIDENCE_CALL,
    EXECUTE_EVIDENCE_CALL,
    WINDOWS_EXECUTE_EVIDENCE_CALL,
) + EXECUTE_PLAIN_CALLS

ROUTE_RULES = (
    RouteRule("wyl_fact_offline_restore_graph_commit_sync_staged_run",
              ("sync_staged_capture_ready", "graph_execute_provisioned")),
    RouteRule("sync_staged_capture_ready", ("graph_capture_provisioned",)),
    RouteRule("wyl_fact_offline_restore_graph_commit_retain_run",
              ("graph_provenance_load",)),
    RouteRule("retain_capture", ("graph_capture_provisioned",)),
    RouteRule("retain_effect", ("retain_capture",
                                "graph_execute_provisioned")),
    RouteRule("wyl_fact_offline_restore_graph_commit_sync_retained_run",
              ("graph_provenance_load",)),
    RouteRule("sync_retained_effect", ("retain_capture",
                                       "graph_execute_provisioned")),
    RouteRule("wyl_fact_offline_restore_graph_commit_publish_run",
              ("graph_provenance_load",)),
    RouteRule("publish_capture", ("retain_capture",)),
    RouteRule("publish_effect", ("publish_capture",
                                 "graph_execute_provisioned")),
    RouteRule("darwin_companion_effect",
              ("wyl_fact_root_writer_lease_authorizes_resolver",
               "check_runtime", "darwin_post_publish_shape")),
    RouteRule("darwin_companion_recover",
              ("wyl_fact_root_writer_lease_acquire",
               "wyl_policy_store_bind_fact_root_authorized",
               "commit_snapshot_valid", "check_policy",
               "wyl_fact_root_writer_lease_authorizes_resolver",
               "graph_commit_quiesce", "check_persisted", "check_runtime",
               "wyl_policy_store_offline_restore_load",
               "graph_provenance_load", "darwin_post_publish_shape")),
    RouteRule("darwin_select_replacement",
              ("wyl_fact_root_writer_lease_acquire",
               "wyl_policy_store_bind_fact_root_authorized",
               "commit_snapshot_valid", "check_policy",
               "wyl_fact_root_writer_lease_authorizes_resolver",
               "graph_commit_quiesce", "check_persisted", "check_runtime",
               "graph_provenance_load", "darwin_post_publish_shape")),
    RouteRule("darwin_finalize_selected",
              ("wyl_fact_root_writer_lease_acquire",
               "wyl_policy_store_bind_fact_root_authorized",
               "wyl_fact_offline_restore_journal_store_load",
               "wyl_policy_store_graph_restore_replacement_load",
               "wyl_fact_root_writer_lease_authorizes_resolver",
               "graph_commit_quiesce", "check_runtime",
               "graph_selected_provenance_load")),
    RouteRule("darwin_finalize_effect",
              ("wyl_fact_root_writer_lease_authorizes_resolver",
               "check_runtime",
               "wyl_fact_graph_restore_darwin_selected_cleanup_execute")),
    RouteRule("darwin_finalized_prove_terminal",
              ("wyl_fact_root_writer_lease_acquire",
               "wyl_policy_store_bind_fact_root_authorized",
               "wyl_fact_offline_restore_journal_store_load",
               "wyl_policy_store_graph_restore_replacement_load",
               "wyl_fact_root_writer_lease_authorizes_resolver",
               "wyl_fact_graph_runtime_manager_quiesce",
               "wyl_fact_graph_runtime_manager_quiesce_missing_closed",
               "check_finalized_persisted", "check_runtime",
               "graph_selected_provenance_load")),
    RouteRule("darwin_promote_selected",
              ("wyl_fact_root_writer_lease_acquire",
               "wyl_policy_store_bind_fact_root_authorized",
               "wyl_fact_offline_restore_journal_store_load",
               "wyl_policy_store_graph_restore_replacement_load",
               "wyl_fact_root_writer_lease_authorizes_resolver",
               "graph_commit_quiesce", "check_runtime",
               "graph_selected_provenance_load", "check_finalized_persisted",
               "wyl_policy_store_offline_restore_receipt_lookup",
               "restore_unseal_graph")),
    RouteRule("darwin_promote_effect",
              ("wyl_fact_root_writer_lease_authorizes_resolver",
               "check_runtime",
               "wyl_fact_graph_restore_darwin_selected_cleanup_shape_open",
               COMPARE_CALL)),
    RouteRule("darwin_published_prove_terminal",
              ("wyl_fact_offline_restore_journal_encode", RECEIPT_CALL,
               "wyl_fact_offline_restore_journal_decode", MARK_PUBLISHED,
               MARK_HANDOFF, AUTHORITY_CALL, "restore_unseal_graph")),
)


class ContractError(Exception):
    """A rule of the guard does not hold."""


def strip_comments(source: str) -> str:
    """Blank C comments, keeping newlines so line structure survives."""
    source = re.sub(
        r"/\*.*?\*/",
        lambda m: re.sub(r"[^\n]", " ", m.group(0)),
        source,
        flags=re.DOTALL,
    )
    return re.sub(r"//[^\n]*", "", source)


def function_body(source: str, name: str) -> str:
    """The brace-delimited body of the definition of ``name``.

    The return type sits on the line before the name, or on the same line
    as it.  A match whose parameter list reaches a ``;`` before the next
    ``{`` is a declaration and is skipped."""
    pattern = re.compile(
        r"^(?:[A-Za-z_][\w \t*]*\n|[A-Za-z_][\w \t*]*[ \t*])"
        + re.escape(name) + r"\s*\(",
        re.M,
    )
    start = -1
    for match in pattern.finditer(source):
        brace = source.find("{", match.end())
        semicolon = source.find(";", match.end())
        if brace >= 0 and (semicolon < 0 or brace < semicolon):
            start = brace
            break
    if start < 0:
        raise ContractError(f"E_NO_FUNCTION: {name} is not defined")
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise ContractError(f"E_NO_FUNCTION: {name} has no closing brace")


def platform_arms(body: str, macro: str) -> list[tuple[str, str]]:
    """Every (if_arm, else_arm) pair of an ``#ifdef <macro>`` block at the
    top level of ``body``; other conditionals are skipped whole."""
    arms: list[tuple[str, str]] = []
    lines = body.splitlines()
    index = 0
    opener = re.compile(r"^\s*#\s*ifdef\s+" + re.escape(macro) + r"\s*$")
    while index < len(lines):
        if opener.match(lines[index]):
            apple: list[str] = []
            other: list[str] = []
            current = apple
            depth = 0
            index += 1
            while index < len(lines):
                line = lines[index]
                if re.match(r"^\s*#\s*if", line):
                    depth += 1
                elif re.match(r"^\s*#\s*endif", line):
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0 and re.match(r"^\s*#\s*else\s*$", line):
                    current = other
                    index += 1
                    continue
                elif depth == 0 and re.match(r"^\s*#\s*elif", line):
                    raise ContractError(
                        "E_APPLE_ELIF: an #elif chain after #ifdef"
                        f" {macro} is not judged"
                    )
                current.append(line)
                index += 1
            else:
                raise ContractError("E_APPLE_UNTERMINATED: missing #endif")
            arms.append(("\n".join(apple), "\n".join(other)))
        elif re.match(r"^\s*#\s*if", lines[index]):
            depth = 0
            index += 1
            while index < len(lines):
                if re.match(r"^\s*#\s*if", lines[index]):
                    depth += 1
                elif re.match(r"^\s*#\s*endif", lines[index]):
                    if depth == 0:
                        break
                    depth -= 1
                index += 1
        index += 1
    return arms


def apple_arms(body: str) -> list[tuple[str, str]]:
    """Every (apple_arm, else_arm) pair of an ``#ifdef __APPLE__`` block."""
    return platform_arms(body, "__APPLE__")


def count_calls(text: str, name: str) -> int:
    """Calls of exactly ``name``, not of a longer identifier."""
    return len(re.findall(r"(?<![\w])" + re.escape(name) + r"\s*\(", text))


def check_arm_rule(source: str, rule: ArmRule) -> None:
    name = rule.function
    body = function_body(source, name)
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_APPLE_ARMS: {name} has {len(arms)} #ifdef __APPLE__ arms,"
            " expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, rule.darwin) != 1:
        raise ContractError(
            f"E_NO_DARWIN_CALL: the Darwin arm of {name} must call"
            f" {rule.darwin} exactly once"
        )
    for plain in FORBIDDEN_CALLS:
        if count_calls(apple, plain) != 0:
            raise ContractError(
                f"E_DARWIN_PLAIN_CALL: the Darwin arm of {name} calls {plain},"
                " which does not prove the provisioned main on macOS"
            )
    windows = platform_arms(other, "G_OS_WIN32")
    if len(windows) != 1:
        raise ContractError(
            f"E_WINDOWS_ARMS: the #else arm of {name} has {len(windows)}"
            " nested #ifdef G_OS_WIN32 arms, expected 1"
        )
    windows_arm, linux = windows[0]
    if count_calls(windows_arm, rule.windows) != 1:
        raise ContractError(
            f"E_NO_WINDOWS_CALL: the Windows arm of {name}"
            f" must call {rule.windows} exactly once"
        )
    for plain in FORBIDDEN_CALLS:
        if count_calls(windows_arm, plain) != 0:
            raise ContractError(
                f"E_WINDOWS_PLAIN_CALL: the Windows arm of {name}"
                f" calls {plain}, which does not prove the provisioned main"
            )
    if rule.linux is not None and count_calls(linux, rule.linux) != 1:
        raise ContractError(
            f"E_LINUX_ARM: the innermost #else arm of {name} must"
            f" keep the name-only {rule.linux} call"
        )


def check_route_rule(source: str, rule: RouteRule) -> None:
    name = rule.function
    body = function_body(source, name)
    for direct in ROUTE_FORBIDDEN:
        if count_calls(body, direct) != 0:
            raise ContractError(
                f"E_ROUTE_DIRECT: {name} calls {direct} directly instead of"
                " through its helper"
            )
    for helper in rule.helpers:
        if count_calls(body, helper) == 0:
            raise ContractError(
                f"E_ROUTE_HELPER: {name} does not call {helper}"
            )


def first_call(text: str, name: str) -> int:
    match = re.search(r"(?<![\w])" + re.escape(name) + r"\s*\(", text)
    return -1 if match is None else match.start()


def check_companion_rules(source: str) -> None:
    body = function_body(source, COMPANION_RECOVER)
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_COMPANION_ARMS: {COMPANION_RECOVER} has {len(arms)}"
            " #ifdef __APPLE__ arms, expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, DARWIN_COMPANION) != 1:
        raise ContractError(
            f"E_COMPANION_ROUTE: the Darwin arm of {COMPANION_RECOVER} must"
            f" call {DARWIN_COMPANION} exactly once"
        )
    for call in COMPANION_CALLS:
        if count_calls(apple, call) != 0:
            raise ContractError(
                f"E_COMPANION_DIRECT: the Darwin arm of {COMPANION_RECOVER}"
                f" calls {call} instead of {DARWIN_COMPANION}"
            )
    for call in (DARWIN_COMPANION, SETTER_CALL, CAPTURE_CALL):
        if count_calls(other, call) != 0:
            raise ContractError(
                f"E_COMPANION_LEAK: the #else arm of {COMPANION_RECOVER}"
                f" calls {call}"
            )
    body = function_body(source, DARWIN_COMPANION)
    for call in (CAPTURE_CALL, SETTER_CALL, COMPARE_CALL, SYNC_CALL):
        if count_calls(body, call) != 1:
            raise ContractError(
                f"E_COMPANION_CALLS: {DARWIN_COMPANION} must call {call}"
                " exactly once"
            )
    if count_calls(body, MARK_CALL) != 0:
        raise ContractError(
            f"E_COMPANION_CALLS: {DARWIN_COMPANION} calls {MARK_CALL}"
        )
    reloads = list(RELOAD_PATTERN.finditer(body))
    if len(reloads) != 1:
        raise ContractError(
            f"E_COMPANION_RELOAD: {DARWIN_COMPANION} must take the setter's"
            " committed row exactly once"
        )
    reload = reloads[0].start()
    capture = first_call(body, CAPTURE_CALL)
    setter = first_call(body, SETTER_CALL)
    compare = first_call(body, COMPARE_CALL)
    sync = first_call(body, SYNC_CALL)
    if not capture < setter < reload < compare < sync:
        raise ContractError(
            f"E_COMPANION_ORDER: {DARWIN_COMPANION} must capture, persist,"
            " reload, compare and sync in that order"
        )
    persisted = [match.start() for match in PERSISTED_PATTERN.finditer(body)]
    if not any(reload < at < compare for at in persisted):
        raise ContractError(
            f"E_COMPANION_REREAD: {DARWIN_COMPANION} must re-read the"
            " persisted row between the reload and the compare"
        )
    if len(persisted) != 2:
        raise ContractError(
            f"E_COMPANION_PERSISTED: {DARWIN_COMPANION} must call"
            f" check_persisted exactly twice, not {len(persisted)} times"
        )
    if (re.search(r"set_darwin_evidence\s*\(\s*policy\s*,\s*row\s*,", body)
            is None
            or re.search(r"sync_with_effect\s*\(\s*policy\s*,\s*row\s*,",
                         body) is None):
        raise ContractError(
            f"E_COMPANION_ROW: {DARWIN_COMPANION} must pass row as the"
            " expected record to the setter and the sync"
        )


def check_select_rules(source: str) -> None:
    body = function_body(source, SELECT_RUN)
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_SELECT_ARMS: {SELECT_RUN} has {len(arms)}"
            " #ifdef __APPLE__ arms, expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, DARWIN_SELECT) != 1:
        raise ContractError(
            f"E_SELECT_ROUTE: the Darwin arm of {SELECT_RUN} must call"
            f" {DARWIN_SELECT} exactly once"
        )
    for call in (COMPARE_CALL, CAPTURE_CALL, SELECT_CALL, LINUX_SHAPE_CALL):
        if count_calls(apple, call) != 0:
            raise ContractError(
                f"E_SELECT_DIRECT: the Darwin arm of {SELECT_RUN} calls"
                f" {call} instead of {DARWIN_SELECT}"
            )
    for call in (DARWIN_SELECT, COMPARE_CALL, REBIND_CALL):
        if count_calls(other, call) != 0:
            raise ContractError(
                f"E_SELECT_LEAK: the #else arm of {SELECT_RUN} calls {call}"
            )
    body = function_body(source, DARWIN_SELECT)
    for call in (REBIND_CALL, SHAPE_CALL, COMPARE_CALL, SELECT_CALL):
        if count_calls(body, call) != 1:
            raise ContractError(
                f"E_SELECT_CALLS: {DARWIN_SELECT} must call {call}"
                " exactly once"
            )
    for call in (CAPTURE_CALL, SETTER_CALL, SYNC_CALL, MARK_CALL,
                 LINUX_SHAPE_CALL):
        if count_calls(body, call) != 0:
            raise ContractError(
                f"E_SELECT_CALLS: {DARWIN_SELECT} calls {call}"
            )
    order = [first_call(body, call) for call in (
        "graph_provenance_load", REBIND_CALL, SHAPE_CALL, COMPARE_CALL,
        SELECT_CALL)]
    if not all(at >= 0 for at in order) or order != sorted(order):
        raise ContractError(
            f"E_SELECT_ORDER: {DARWIN_SELECT} must load the provenance,"
            " rebuild the old evidence, prove the shape, compare and select"
            " in that order"
        )
    match = re.search(
        r"select_with_effect\s*\(\s*policy\s*,\s*row\s*,([^;]*);", body
    )
    if match is None or re.search(
            r"(?<![\w])" + SELECT_EFFECT + r"(?![\w])", match.group(1)
    ) is None:
        raise ContractError(
            f"E_SELECT_EFFECT: {DARWIN_SELECT} must pass row as the expected"
            f" record and {SELECT_EFFECT} as the effect to {SELECT_CALL}"
        )


def check_finalize_rules(source: str) -> None:
    body = function_body(source, FINALIZE_RUN)
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_FINALIZE_ARMS: {FINALIZE_RUN} has {len(arms)}"
            " #ifdef __APPLE__ arms, expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, DARWIN_FINALIZE) != 1:
        raise ContractError(
            f"E_FINALIZE_ROUTE: the Darwin arm of {FINALIZE_RUN} must call"
            f" {DARWIN_FINALIZE} exactly once"
        )
    for call in (CLEANUP_SHAPE_CALL, CLEANUP_EXECUTE_CALL, COMPARE_CALL,
                 BEGIN_CALL, COMPLETE_CALL):
        if count_calls(apple, call) != 0:
            raise ContractError(
                f"E_FINALIZE_DIRECT: the Darwin arm of {FINALIZE_RUN} calls"
                f" {call} instead of {DARWIN_FINALIZE}"
            )
    for call in (DARWIN_FINALIZE, CLEANUP_SHAPE_CALL, CLEANUP_EXECUTE_CALL,
                 COMPARE_CALL, REBIND_CALL):
        if count_calls(other, call) != 0:
            raise ContractError(
                f"E_FINALIZE_LEAK: the #else arm of {FINALIZE_RUN} calls"
                f" {call}"
            )
    body = function_body(source, DARWIN_FINALIZE)
    ordered = (SELECTED_PROVENANCE, CLEANUP_SHAPE_CALL, COMPARE_CALL,
               BEGIN_CALL, COMPLETE_CALL)
    for call in ordered:
        if count_calls(body, call) != 1:
            raise ContractError(
                f"E_FINALIZE_CALLS: {DARWIN_FINALIZE} must call {call}"
                " exactly once"
            )
    for call in ("graph_provenance_load", REBIND_CALL, CLEANUP_EXECUTE_CALL,
                 LINUX_CLEANUP_SHAPE_CALL, LINUX_CLEANUP_EXECUTE_CALL,
                 DUAL_WITNESS_CALL, CAPTURE_CALL, SETTER_CALL, SYNC_CALL,
                 MARK_CALL, SELECT_CALL):
        if count_calls(body, call) != 0:
            raise ContractError(
                f"E_FINALIZE_CALLS: {DARWIN_FINALIZE} calls {call}"
            )
    order = [first_call(body, call) for call in ordered]
    if order != sorted(order):
        raise ContractError(
            f"E_FINALIZE_ORDER: {DARWIN_FINALIZE} must load the selected"
            " provenance, prove the cleanup shape, compare, begin and"
            " complete in that order"
        )
    evidence = re.search(
        r"\brow->darwin_operation_evidence\s*==\s*NULL", body
    )
    opened = first_call(body, "wyl_fact_graph_resolver_open")
    if evidence is None or opened < 0 or evidence.start() > opened:
        raise ContractError(
            f"E_FINALIZE_EARLY_EVIDENCE: {DARWIN_FINALIZE} must refuse a row"
            " without evidence before its first wyl_fact_graph_resolver_open"
        )
    match = re.search(
        r"finalize_with_effect\s*\(\s*policy\s*,\s*row\s*,([^;]*);", body
    )
    if match is None or re.search(
            r"(?<![\w])" + FINALIZE_EFFECT + r"(?![\w])", match.group(1)
    ) is None:
        raise ContractError(
            f"E_FINALIZE_EFFECT: {DARWIN_FINALIZE} must pass row as the"
            f" expected record and {FINALIZE_EFFECT} as the effect to"
            f" {COMPLETE_CALL}"
        )
    body = function_body(source, FINALIZE_EFFECT)
    if (count_calls(body, CLEANUP_EXECUTE_CALL) != 1
            or count_calls(body, LINUX_CLEANUP_EXECUTE_CALL) != 0):
        raise ContractError(
            f"E_FINALIZE_EFFECT_EXECUTE: {FINALIZE_EFFECT} must call"
            f" {CLEANUP_EXECUTE_CALL} exactly once and"
            f" {LINUX_CLEANUP_EXECUTE_CALL} never"
        )
    if count_calls(body, "evidence_equal") == 0:
        raise ContractError(
            f"E_FINALIZE_EFFECT_EVIDENCE: {FINALIZE_EFFECT} must compare the"
            " row's evidence with the bytes compared before it"
        )
    body = function_body(source, SELECTED_PROVENANCE)
    if (count_calls(body, REBIND_CALL) != 1
            or count_calls(body, "evidence_equal") == 0
            or re.search(r"\bWYL_POLICY_GRAPH_PROVISIONING_RESTORE_SELECTED\b",
                         body) is None
            or re.search(r"\bWYL_POLICY_GRAPH_PROVISIONING_ACTIVE\b",
                         body) is not None):
        raise ContractError(
            f"E_FINALIZE_PROVENANCE: {SELECTED_PROVENANCE} must rebuild the"
            f" old evidence once with {REBIND_CALL} from the restore_selected"
            " record, whose evidence must equal the row's, and never read"
            " an ACTIVE record"
        )


def check_terminal_rules(source: str) -> None:
    body = function_body(source, TERMINAL_RUN)
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_TERMINAL_ARMS: {TERMINAL_RUN} has {len(arms)}"
            " #ifdef __APPLE__ arms, expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, DARWIN_TERMINAL) != 1:
        raise ContractError(
            f"E_TERMINAL_ROUTE: the Darwin arm of {TERMINAL_RUN} must call"
            f" {DARWIN_TERMINAL} exactly once"
        )
    for call in (CLEANUP_SHAPE_CALL, COMPARE_CALL, SELECTED_PROVENANCE):
        if count_calls(apple, call) != 0:
            raise ContractError(
                f"E_TERMINAL_DIRECT: the Darwin arm of {TERMINAL_RUN} calls"
                f" {call} instead of {DARWIN_TERMINAL}"
            )
    for call in (DARWIN_TERMINAL, CLEANUP_SHAPE_CALL, COMPARE_CALL,
                 REBIND_CALL, SELECTED_PROVENANCE):
        if count_calls(other, call) != 0:
            raise ContractError(
                f"E_TERMINAL_LEAK: the #else arm of {TERMINAL_RUN} calls"
                f" {call}"
            )
    body = function_body(source, DARWIN_TERMINAL)
    ordered = (SELECTED_PROVENANCE, CLEANUP_SHAPE_CALL, COMPARE_CALL)
    for call in ordered:
        if count_calls(body, call) != 1:
            raise ContractError(
                f"E_TERMINAL_CALLS: {DARWIN_TERMINAL} must call {call}"
                " exactly once"
            )
    for call in ("graph_provenance_load", REBIND_CALL):
        if count_calls(body, call) != 0:
            raise ContractError(
                f"E_TERMINAL_CALLS: {DARWIN_TERMINAL} calls {call}"
            )
    order = [first_call(body, call) for call in ordered]
    if order != sorted(order):
        raise ContractError(
            f"E_TERMINAL_ORDER: {DARWIN_TERMINAL} must load the selected"
            " provenance, prove the cleanup shape and compare in that order"
        )
    for call in (CLEANUP_EXECUTE_CALL, LINUX_CLEANUP_SHAPE_CALL,
                 LINUX_CLEANUP_EXECUTE_CALL, DUAL_WITNESS_CALL, CAPTURE_CALL,
                 SETTER_CALL, SYNC_CALL, MARK_CALL, SELECT_CALL, BEGIN_CALL,
                 COMPLETE_CALL, JOURNAL_BEGIN_CALL, JOURNAL_COMPLETE_CALL):
        if count_calls(body, call) != 0:
            raise ContractError(
                f"E_TERMINAL_MUTATES: {DARWIN_TERMINAL} calls {call}, but"
                " the terminal proof is read-only"
            )
    if (re.search(r"\bshape\s*!=\s*"
                  r"WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL\b",
                  body) is None
            or re.search(r"\bWYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL\b",
                         body) is not None):
        raise ContractError(
            f"E_TERMINAL_SHAPE: {DARWIN_TERMINAL} must refuse every shape"
            " but TERMINAL and never accept DUAL"
        )
    persisted = [match.start() for match in re.finditer(
        r"(?<![\w])" + PERSISTED_FINALIZED + r"\s*\(", body)]
    compared = first_call(body, COMPARE_CALL)
    if not persisted or persisted[-1] < compared:
        raise ContractError(
            f"E_TERMINAL_PERSISTED: {DARWIN_TERMINAL} must re-prove the"
            f" persisted state with {PERSISTED_FINALIZED} after the compare"
        )
    evidence = re.search(
        r"\brow->darwin_operation_evidence\s*==\s*NULL", body
    )
    opened = first_call(body, "wyl_fact_graph_resolver_open")
    if evidence is None or opened < 0 or evidence.start() > opened:
        raise ContractError(
            f"E_TERMINAL_EARLY_EVIDENCE: {DARWIN_TERMINAL} must refuse a row"
            " without evidence before its first wyl_fact_graph_resolver_open"
        )


def names(text: str, name: str) -> bool:
    """Whether ``name`` appears as a whole identifier, called or not."""
    return re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])",
                     text) is not None


C_KEYWORDS = frozenset(("if", "for", "while", "switch", "return", "sizeof",
                        "defined"))


def store_reaching_helper(source: str, body: str,
                          chain: tuple[str, ...],
                          visited: set[str] | None = None,
                          ) -> tuple[str, ...] | None:
    """The call chain from ``chain[-1]`` to the first local helper whose
    body calls the store, or None.  Identifiers not defined in ``source``
    are skipped."""
    visited = set(chain) if visited is None else visited
    for name in re.findall(r"(?<![\w])([A-Za-z_]\w*)\s*\(", body):
        if name in C_KEYWORDS or name in visited:
            continue
        visited.add(name)
        try:
            helper = function_body(source, name)
        except ContractError:
            continue
        if STORE_ENTRY.search(helper) is not None:
            return chain + (name,)
        found = store_reaching_helper(source, helper, chain + (name,),
                                      visited)
        if found is not None:
            return found
    return None


def check_promote_rules(source: str) -> None:
    body = function_body(source, PROMOTE_RUN)
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_PROMOTE_ARMS: {PROMOTE_RUN} has {len(arms)}"
            " #ifdef __APPLE__ arms, expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, DARWIN_PROMOTE) != 1:
        raise ContractError(
            f"E_PROMOTE_ROUTE: the Darwin arm of {PROMOTE_RUN} must call"
            f" {DARWIN_PROMOTE} exactly once"
        )
    for call in (CLEANUP_SHAPE_CALL, COMPARE_CALL, SELECTED_PROVENANCE,
                 PROMOTE_CALL, UNSEAL_CALL):
        if count_calls(apple, call) != 0:
            raise ContractError(
                f"E_PROMOTE_DIRECT: the Darwin arm of {PROMOTE_RUN} calls"
                f" {call} instead of {DARWIN_PROMOTE}"
            )
    for call in (DARWIN_PROMOTE, CLEANUP_SHAPE_CALL, COMPARE_CALL,
                 REBIND_CALL, SELECTED_PROVENANCE):
        if count_calls(other, call) != 0:
            raise ContractError(
                f"E_PROMOTE_LEAK: the #else arm of {PROMOTE_RUN} calls"
                f" {call}"
            )
    if names(other, PROMOTE_EFFECT):
        raise ContractError(
            f"E_PROMOTE_LEAK: the #else arm of {PROMOTE_RUN} names"
            f" {PROMOTE_EFFECT}"
        )
    body = function_body(source, DARWIN_PROMOTE)
    ordered = (SELECTED_PROVENANCE, CLEANUP_SHAPE_CALL, PROMOTE_CALL)
    for call in ordered:
        if count_calls(body, call) != 1:
            raise ContractError(
                f"E_PROMOTE_CALLS: {DARWIN_PROMOTE} must call {call}"
                " exactly once"
            )
    for call in (COMPARE_CALL, "graph_provenance_load", REBIND_CALL,
                 CLEANUP_EXECUTE_CALL, LINUX_CLEANUP_EXECUTE_CALL,
                 LINUX_CLEANUP_SHAPE_CALL, DUAL_WITNESS_CALL, CAPTURE_CALL,
                 SETTER_CALL, SYNC_CALL, MARK_CALL, SELECT_CALL, BEGIN_CALL,
                 COMPLETE_CALL, JOURNAL_BEGIN_CALL, JOURNAL_COMPLETE_CALL,
                 LINUX_PROMOTE_EFFECT):
        if count_calls(body, call) != 0:
            raise ContractError(
                f"E_PROMOTE_CALLS: {DARWIN_PROMOTE} calls {call}"
            )
    order = [first_call(body, call) for call in ordered + (UNSEAL_CALL,)]
    if order != sorted(order):
        raise ContractError(
            f"E_PROMOTE_ORDER: {DARWIN_PROMOTE} must load the selected"
            " provenance, prove the cleanup shape, promote and unseal in that"
            " order"
        )
    persisted = [match.start() for match in re.finditer(
        r"(?<![\w])" + PERSISTED_FINALIZED + r"\s*\(", body)]
    shaped = first_call(body, CLEANUP_SHAPE_CALL)
    promoted = first_call(body, PROMOTE_CALL)
    if not persisted or not shaped < persisted[-1] < promoted:
        raise ContractError(
            f"E_PROMOTE_PERSISTED: {DARWIN_PROMOTE} must re-prove the"
            f" persisted state with {PERSISTED_FINALIZED} after the shape and"
            " before the store promotion"
        )
    call = re.search(r"(?<![\w])" + PROMOTE_CALL + r"\s*\([^;]*;", body)
    if (re.search(r"promote_with_effect\s*\(\s*policy\s*,\s*row\s*,",
                  body) is None
            or call is None or not names(call.group(0), PROMOTE_EFFECT)):
        raise ContractError(
            f"E_PROMOTE_EFFECT: {DARWIN_PROMOTE} must promote the loaded row"
            f" with {PROMOTE_EFFECT}"
        )
    effect = function_body(source, PROMOTE_EFFECT)
    for text, name in ((body, DARWIN_PROMOTE), (effect, PROMOTE_EFFECT)):
        if (re.search(r"\bshape\s*!=\s*"
                      r"WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL\b",
                      text) is None
                or re.search(
                    r"\bWYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL\b",
                    text) is not None):
            raise ContractError(
                f"E_PROMOTE_SHAPE: {name} must refuse every shape but"
                " TERMINAL and never accept DUAL"
            )
    evidence = re.search(
        r"\brow->darwin_operation_evidence\s*==\s*NULL", body
    )
    opened = first_call(body, "wyl_fact_graph_resolver_open")
    if evidence is None or opened < 0 or evidence.start() > opened:
        raise ContractError(
            f"E_PROMOTE_EARLY_EVIDENCE: {DARWIN_PROMOTE} must refuse a row"
            " without evidence before its first wyl_fact_graph_resolver_open"
        )
    equal = first_call(effect, "evidence_equal")
    shaped = first_call(effect, CLEANUP_SHAPE_CALL)
    if equal < 0 or equal > shaped:
        raise ContractError(
            f"E_PROMOTE_EFFECT_EVIDENCE: {PROMOTE_EFFECT} must require the"
            " loaded row's evidence with evidence_equal before its shape"
        )
    if shaped > first_call(effect, COMPARE_CALL):
        raise ContractError(
            f"E_PROMOTE_EFFECT_ORDER: {PROMOTE_EFFECT} must prove the shape"
            " before the compare"
        )
    reentry = re.search(r"(?<![\w])wyl_policy_store_\w+\s*\(", effect)
    if reentry is not None or count_calls(effect, SELECTED_PROVENANCE) != 0:
        raise ContractError(
            f"E_PROMOTE_EFFECT_REENTERS: {PROMOTE_EFFECT} runs inside the"
            " store transaction and must not reenter the store"
        )
    for helper in REENTRANT_HELPERS:
        if count_calls(effect, helper) != 0:
            raise ContractError(
                f"E_PROMOTE_EFFECT_REENTERS: {PROMOTE_EFFECT} calls {helper},"
                " which reenters the store"
            )
    chain = store_reaching_helper(source, effect, (PROMOTE_EFFECT,))
    if chain is not None:
        raise ContractError(
            f"E_PROMOTE_EFFECT_REENTERS: {PROMOTE_EFFECT} reaches the store"
            f" through {' -> '.join(chain)}"
        )
    for call in (CLEANUP_EXECUTE_CALL, LINUX_CLEANUP_EXECUTE_CALL,
                 CAPTURE_CALL, SETTER_CALL, SYNC_CALL, MARK_CALL,
                 JOURNAL_BEGIN_CALL, JOURNAL_COMPLETE_CALL):
        if count_calls(effect, call) != 0:
            raise ContractError(
                f"E_PROMOTE_EFFECT_MUTATES: {PROMOTE_EFFECT} calls {call}, but"
                " promotion changes no file"
            )


def check_published_rules(source: str) -> None:
    body = function_body(source, PUBLISHED_RUN)
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_PUBLISHED_ARMS: {PUBLISHED_RUN} has {len(arms)}"
            " #ifdef __APPLE__ arms, expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, DARWIN_PUBLISHED) != 1:
        raise ContractError(
            f"E_PUBLISHED_ROUTE: the Darwin arm of {PUBLISHED_RUN} must call"
            f" {DARWIN_PUBLISHED} exactly once"
        )
    for call in (RECEIPT_CALL, AUTHORITY_CALL, UNSEAL_CALL,
                 STORE_PUBLISHED_CALL, CLEANUP_SHAPE_CALL, COMPARE_CALL):
        if count_calls(apple, call) != 0:
            raise ContractError(
                f"E_PUBLISHED_DIRECT: the Darwin arm of {PUBLISHED_RUN} calls"
                f" {call} instead of {DARWIN_PUBLISHED}"
            )
    for call in (DARWIN_PUBLISHED, CLEANUP_SHAPE_CALL, COMPARE_CALL,
                 REBIND_CALL, SELECTED_PROVENANCE):
        if names(other, call):
            raise ContractError(
                f"E_PUBLISHED_LEAK: the #else arm of {PUBLISHED_RUN} names"
                f" {call}"
            )
    body = function_body(source, DARWIN_PUBLISHED)
    for call in (RECEIPT_CALL, AUTHORITY_CALL, UNSEAL_CALL):
        if count_calls(body, call) != 1:
            raise ContractError(
                f"E_PUBLISHED_CALLS: {DARWIN_PUBLISHED} must call {call}"
                " exactly once"
            )
    for call in (STORE_PUBLISHED_CALL, ROW_LOAD, JOURNAL_LOAD,
                 SELECTED_PROVENANCE, "graph_provenance_load",
                 CLEANUP_SHAPE_CALL, LINUX_CLEANUP_SHAPE_CALL, COMPARE_CALL,
                 REBIND_CALL, DUAL_WITNESS_CALL):
        if count_calls(body, call) != 0:
            raise ContractError(
                f"E_PUBLISHED_CALLS: {DARWIN_PUBLISHED} calls {call}, which"
                " reads a state promotion deleted or re-proves a live"
                " namespace"
            )
    for call in (PROMOTE_CALL, SELECT_CALL, BEGIN_CALL, COMPLETE_CALL,
                 SETTER_CALL, SYNC_CALL, MARK_CALL, CAPTURE_CALL,
                 CLEANUP_EXECUTE_CALL, LINUX_CLEANUP_EXECUTE_CALL,
                 JOURNAL_BEGIN_CALL, JOURNAL_COMPLETE_CALL,
                 "wyl_fact_offline_restore_journal_store_cas"):
        if count_calls(body, call) != 0:
            raise ContractError(
                f"E_PUBLISHED_MUTATES: {DARWIN_PUBLISHED} calls {call}, but"
                " the proof changes nothing before the unseal"
            )
    looked_up = first_call(body, RECEIPT_CALL)
    for name in ("replacement_selected_pending_cleanup",
                 "WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION"):
        named = re.search(r"(?<![\w])" + name + r"(?![\w])", body)
        if named is None or named.start() > looked_up:
            raise ContractError(
                f"E_PUBLISHED_FINALIZED: {DARWIN_PUBLISHED} must require the"
                f" FINALIZED journal ({name}) before its receipt lookup"
            )
    marked = first_call(body, MARK_PUBLISHED)
    missing = re.search(r"\breceipt\s*==\s*NULL", body[looked_up:])
    if (missing is None or marked < 0
            or looked_up + missing.start() > marked):
        raise ContractError(
            f"E_PUBLISHED_NO_RECEIPT: {DARWIN_PUBLISHED} must refuse a"
            " missing receipt after its lookup and before marking the"
            " journal published"
        )
    order = [first_call(body, call) for call in
             (RECEIPT_CALL, MARK_PUBLISHED, MARK_HANDOFF, AUTHORITY_CALL,
              UNSEAL_CALL)]
    if order != sorted(order):
        raise ContractError(
            f"E_PUBLISHED_ORDER: {DARWIN_PUBLISHED} must look up the"
            " receipt, mark the journal published and handed off, read the"
            " graph authority and unseal in that order"
        )


def check_source(source: str) -> None:
    source = strip_comments(source)
    for rule in ARM_RULES:
        check_arm_rule(source, rule)
    for route in ROUTE_RULES:
        check_route_rule(source, route)
    check_companion_rules(source)
    check_select_rules(source)
    check_finalize_rules(source)
    check_terminal_rules(source)
    check_promote_rules(source)
    check_published_rules(source)


def check_tree(root: Path) -> None:
    path = root / SOURCE
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ContractError(f"E_UNREADABLE: {SOURCE}: {error}") from error
    check_source(source)


BIND_FIXTURE = """\
static wyrelog_error_t
graph_bind_prove_effect (GBytes *canonical_journal,
    const gchar *old_uuid, gpointer user_data)
{
  /* comment with #ifdef __APPLE__ inside must be ignored */
  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef __APPLE__
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence
          (provider, old_uuid, evidence, &request, slot, &lifecycle, &s, &o);
#else
#ifdef G_OS_WIN32
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_windows_capture_provisioned_with_evidence
          (provider, old_uuid, windows_evidence, &request, slot, &lifecycle,
            &s, &o);
#else
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture_provisioned
          (provider, old_uuid, &request, slot, &lifecycle, &s, &o);
#endif
#endif
  return rc;
}
"""

CAPTURE_FIXTURE = """\
static wyrelog_error_t
graph_capture_provisioned (WylFactArtifactTransition *provider,
    const GraphProvenance *provenance, const Request *request)
{
#ifdef __APPLE__
  return wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence
           (provider, provenance->uuid, &provenance->evidence, request, slot,
             lifecycle, out_snapshot, out_observation);
#else
#ifdef G_OS_WIN32
  return wyl_fact_artifact_transition_windows_capture_provisioned_with_evidence
           (provider, provenance->uuid, &provenance->evidence, request, slot,
             lifecycle, out_snapshot, out_observation);
#else
  return wyl_fact_artifact_transition_posix_capture_provisioned (provider,
             provenance->uuid, request, slot, lifecycle, out_snapshot,
             out_observation);
#endif
#endif
}
"""

EXECUTE_FIXTURE = """\
static wyrelog_error_t
graph_execute_provisioned (WylFactArtifactTransition *provider,
    const GraphProvenance *provenance, const Request *request)
{
#ifdef __APPLE__
  return wyl_fact_artifact_transition_posix_execute_provisioned_with_evidence
           (provider, provenance->uuid, &provenance->evidence, request,
             authorized, op, out_effect, out_durability);
#else
#ifdef G_OS_WIN32
  return wyl_fact_artifact_transition_windows_execute_provisioned_with_evidence
           (provider, provenance->uuid, &provenance->evidence, request,
             authorized, op, out_effect, out_durability);
#else
  return wyl_fact_artifact_transition_posix_execute_provisioned (provider,
             provenance->uuid, request, authorized, op, out_effect,
             out_durability);
#endif
#endif
}
"""

PROVENANCE_FIXTURE = """\
static wyrelog_error_t
graph_provenance_load (wyl_policy_store_t *policy,
    const Journal *journal, GraphProvenance *out_provenance)
{
  memset (out_provenance, 0, sizeof *out_provenance);
#ifdef __APPLE__
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list_for_graph
        (policy, journal->tenant_id, journal->selected_graph_id, &records);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_darwin_evidence_decode (evidence_bytes,
            evidence_length, record->op_uuid, &out_provenance->evidence);
  if (rc != WYRELOG_E_OK)
    return rc;
#else
#ifdef G_OS_WIN32
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list_for_graph
        (policy, journal->tenant_id, journal->selected_graph_id, &records);
  if (rc != WYRELOG_E_OK)
    return rc;
#else
  (void) policy;
  (void) journal;
#endif
#endif
  out_provenance->uuid = row->old_provisioning_uuid;
  return WYRELOG_E_OK;
}
"""

SYNC_STAGED_RUN_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_sync_staged_run
  (wyl_policy_store_t *policy, const gchar *fact_root)
{
#if !defined(__linux__) && !defined(__APPLE__) && !defined(G_OS_WIN32)
  return WYRELOG_E_POLICY;
#else
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_open (&resolver, &directory,
            &lease, &provider);
  if (rc == WYRELOG_E_OK)
    rc = sync_staged_capture_ready (provider, &journal, &provenance,
            &observation);
  if (rc == WYRELOG_E_OK)
    rc = graph_execute_provisioned (provider, &provenance, &request,
            &observation, op, &effect, &durability);
  wyl_fact_artifact_transition_free (provider);
  return rc;
#endif
}
"""

CAPTURE_READY_FIXTURE = """\
static wyrelog_error_t
sync_staged_capture_ready (WylFactArtifactTransition *provider,
    const Journal *journal, const GraphProvenance *provenance)
{
  wyrelog_error_t rc = wyl_fact_artifact_transition_capture (provider,
          &lifecycle, &snapshot, &observation);
  if (rc == WYRELOG_E_OK)
    rc = graph_capture_provisioned (provider, provenance, &request,
            slot, &lifecycle, &snapshot, out_observation);
  return rc;
}
"""

RETAIN_RUN_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_retain_run
  (wyl_policy_store_t *policy, const gchar *fact_root)
{
#if !defined(__linux__) && !defined(__APPLE__) && !defined(G_OS_WIN32)
  return WYRELOG_E_POLICY;
#else
  if (rc == WYRELOG_E_OK)
    rc = graph_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_open (&resolver, &directory,
            &lease, &provider);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_retain_with_effect (policy,
            row, &pending, &completed, retain_effect, &context, &result);
  wyl_fact_artifact_transition_free (provider);
  return rc;
#endif
}
"""

RETAIN_CAPTURE_FIXTURE = """\
static wyrelog_error_t
retain_capture (WylFactArtifactTransition *provider,
    const Journal *journal, const GraphProvenance *provenance)
{
  wyrelog_error_t rc = wyl_fact_artifact_transition_capture
        (provider, &lifecycle, &preliminary, &observed);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = graph_capture_provisioned (provider, provenance, &request, slot,
          &lifecycle, out_snapshot, out_observation);
  return rc;
}
"""

RETAIN_EFFECT_FIXTURE = """\
static wyrelog_error_t
retain_effect (const Row *row, gpointer user_data)
{
  wyrelog_error_t rc = wyl_fact_artifact_transition_capture
        (provider, &lifecycle, &initial, &first);
  if (rc == WYRELOG_E_OK)
    rc = retain_capture (provider, journal, provenance,
            slot, &request, &snapshot, &before);
  if (rc == WYRELOG_E_OK)
    rc = graph_execute_provisioned (provider, provenance, &request,
            &synced, WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN,
            &effect, &durability);
  if (rc == WYRELOG_E_OK)
    rc = retain_capture (provider, journal, provenance,
            WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
            &request, &snapshot, &retained);
  if (rc == WYRELOG_E_OK)
    rc = graph_execute_provisioned (provider, provenance, &request,
            &retained, WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
            &sync_effect, &sync_durability);
  return rc;
}
"""

SYNC_RETAINED_RUN_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_sync_retained_run
  (wyl_policy_store_t *policy, const gchar *fact_root)
{
#if !defined(__linux__) && !defined(__APPLE__) && !defined(G_OS_WIN32)
  return WYRELOG_E_POLICY;
#else
  if (rc == WYRELOG_E_OK)
    rc = graph_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_open (&resolver, &directory,
            &lease, &provider);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_sync_retained_with_effect
          (policy, row, &pending, &completed, operation,
            sync_retained_effect, &context, &result);
  wyl_fact_artifact_transition_free (provider);
  return rc;
#endif
}
"""

SYNC_RETAINED_EFFECT_FIXTURE = """\
static wyrelog_error_t
sync_retained_effect (const Row *row, gpointer user_data)
{
  wyrelog_error_t rc = retain_capture (context->provider, context->journal,
          context->provenance,
          WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
          &request, &snapshot, &observation);
  for (guint i = 0; rc == WYRELOG_E_OK && i < count; i++)
    rc = graph_execute_provisioned (context->provider,
            context->provenance, &request, &observation, operation,
            &effect, &durability);
  return rc;
}
"""

PUBLISH_RUN_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_publish_run
  (wyl_policy_store_t *policy, const gchar *fact_root)
{
#if !defined(__linux__) && !defined(__APPLE__) && !defined(G_OS_WIN32)
  return WYRELOG_E_POLICY;
#else
  if (rc == WYRELOG_E_OK)
    rc = graph_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_open (&resolver, &directory,
            lease, operation_uuid, &capability, &provider);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_publish_with_effect
          (policy, row, &pending, &completed, operation,
            publish_effect, &context, &result);
  wyl_fact_artifact_transition_free (provider);
  return rc;
#endif
}
"""

PUBLISH_CAPTURE_FIXTURE = """\
static wyrelog_error_t
publish_capture (PublishEffectContext *context,
    WylFactArtifactMainTransitionRequest *request,
    WylFactArtifactInventorySnapshot **snapshot,
    WylFactArtifactMainTransitionObservation *observation)
{
  return retain_capture (context->provider, context->journal,
             context->provenance,
             WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
             request, snapshot, observation);
}
"""

PUBLISH_EFFECT_FIXTURE = """\
static wyrelog_error_t
publish_effect (const Row *row, gpointer user_data)
{
  wyrelog_error_t rc = publish_capture (context, &request,
          &snapshot, &observation);
  for (guint i = 0; i < G_N_ELEMENTS (prerequisites); i++) {
    if (rc == WYRELOG_E_OK)
      rc = graph_execute_provisioned (context->provider,
              context->provenance, &request, &observation, operation,
              &effect, &durability);
    rc = publish_capture (context, &request, &snapshot, &after);
  }
  if (rc == WYRELOG_E_OK)
    rc = graph_execute_provisioned (context->provider,
            context->provenance, &request, &observation,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
            &rename_effect, &rename_durability);
  rc = publish_capture (context, &request, &snapshot, &after);
  if (rc == WYRELOG_E_OK)
    rc = graph_execute_provisioned (context->provider,
            context->provenance, &request, &observation,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
            &sync_effect, &sync_durability);
  rc = publish_capture (context, &request, &snapshot, &after_sync);
  rc = publish_capture (context, &request, &snapshot, &observation);
  return rc;
}
"""

COMPANION_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_companion_recover
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylPolicyGraphRestoreReplacementRecord **out_committed)
{
  if (policy == NULL)
    return WYRELOG_E_INVALID;
#ifdef __APPLE__
  return darwin_companion_recover (policy, fact_root, runtime,
             operation_uuid, expected_revision, drain_timeout_us,
             out_committed);
#else
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  rc = wyl_policy_store_graph_restore_replacement_sync_with_effect
        (policy, row, raw_journal, sync_companion_effect, &effect,
          &result, out_committed);
  return rc;
#endif
#endif
}
"""

DARWIN_RECOVER_FIXTURE = """\
static wyrelog_error_t
darwin_companion_recover (wyl_policy_store_t *policy,
    const gchar *fact_root,
    WylPolicyGraphRestoreReplacementRecord **out_committed)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK && !commit_snapshot_valid
        (&journal, row, expected_revision))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = graph_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &raw_journal);
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_shape (&resolver, &directory, lease, &journal,
            row, &provenance);
  if (rc == WYRELOG_E_OK && row->darwin_operation_evidence == NULL) {
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_directory_capture_darwin_replacement_evidence
            (&directory, row->replacement_uuid, &graph->staged_main_identity,
            graph->logical_bytes, graph->checksum, &captured));
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_graph_restore_replacement_set_darwin_evidence
            (policy, row, raw_journal, bytes, &stored_result, &stored);
    if (rc == WYRELOG_E_OK) {
      wyl_policy_graph_restore_replacement_record_free (row);
      row = g_steal_pointer (&stored);
    }
    if (rc == WYRELOG_E_OK)
      rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  }
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_directory_compare_darwin_replacement_evidence
            (&directory, row->replacement_uuid, &graph->staged_main_identity,
            graph->logical_bytes, graph->checksum, &expected));
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_sync_with_effect
          (policy, row, raw_journal, darwin_companion_effect, &effect,
            &result, out_committed);
  return rc;
}
"""

DARWIN_EFFECT_FIXTURE = """\
static wyrelog_error_t
darwin_companion_effect
  (const WylPolicyGraphRestoreReplacementRecord *current,
    gpointer user_data)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (effect->lease, effect->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (effect->runtime, effect->key);
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_shape (effect->resolver, effect->directory,
            effect->lease, effect->journal, current, effect->provenance);
  return rc;
}
"""

SELECT_RUN_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_select_replacement_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (policy == NULL)
    return WYRELOG_E_INVALID;
#ifdef __APPLE__
  return darwin_select_replacement (policy, fact_root, runtime,
             operation_uuid, expected_revision, drain_timeout_us,
             out_committed);
#else
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  if (rc == WYRELOG_E_OK)
    rc = open_shape (&resolver, &directory, lease, &journal, row, &layout,
            NULL);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_select_with_effect (policy, row,
            &before, &after, select_replacement_effect, &effect, &result);
  return rc;
#endif
#endif
}
"""

DARWIN_SELECT_FIXTURE = """\
static wyrelog_error_t
darwin_select_replacement (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactOfflineRestoreJournal *out_committed)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK
      && (!commit_snapshot_valid (&journal, row, expected_revision)
      || !g_str_equal (row->phase, "companion_synced")))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = graph_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK
      && (wyl_fact_graph_darwin_evidence_rebind (&expected,
      row->replacement_uuid, graph->old_provisioning_uuid,
      graph->expected_main_identity.object, &rebuilt) != WYRELOG_E_OK
      || !wyl_fact_graph_darwin_evidence_equal (&rebuilt,
      &provenance.evidence)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_shape (&resolver, &directory, lease, &journal,
            row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_directory_compare_darwin_replacement_evidence
              (&directory, row->replacement_uuid, &graph->staged_main_identity,
            graph->logical_bytes, graph->checksum, &expected));
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_select_with_effect (policy, row,
            &before, &after, darwin_companion_effect, &effect, &result);
  return rc;
}
"""

FINALIZE_RUN_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_finalize_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (policy == NULL)
    return WYRELOG_E_INVALID;
#ifdef __APPLE__
  return darwin_finalize_selected (policy, fact_root, runtime,
             operation_uuid, expected_revision, drain_timeout_us,
             out_committed);
#else
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_selected_cleanup_shape_open (&resolver,
            &directory, lease, row->old_provisioning_uuid, operation_uuid,
            row->replacement_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity, &shape);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_selected_finalize_with_effect
          (policy, row, &before, &after, finalize_selected_effect,
            &effect, &result);
  return rc;
#endif
#endif
}
"""

DARWIN_FINALIZE_FIXTURE = """\
static wyrelog_error_t
darwin_finalize_selected (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactOfflineRestoreJournal *out_committed)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  if (rc == WYRELOG_E_OK && (row->darwin_operation_evidence == NULL
      || g_bytes_get_size (row->darwin_operation_evidence)
      != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, TRUE, &key, drain_timeout_us,
            &quiescence);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = graph_selected_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open
            (&resolver, &directory, lease, provenance.uuid,
            &provenance.evidence, operation_uuid, row->replacement_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            graph->logical_bytes, &shape));
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_directory_compare_darwin_replacement_evidence
              (&directory, row->replacement_uuid, &graph->staged_main_identity,
            graph->logical_bytes, graph->checksum, &expected));
  if (rc == WYRELOG_E_OK && fresh)
    rc = wyl_policy_store_graph_restore_selected_finalize_begin (policy,
            row, &before, &after, &result);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_selected_finalize_with_effect
          (policy, row, &before, &after, darwin_finalize_effect, &effect,
            &result);
  return rc;
}
"""

DARWIN_FINALIZE_EFFECT_FIXTURE = """\
static wyrelog_error_t
darwin_finalize_effect
  (const WylPolicyGraphRestoreReplacementRecord *current,
    gpointer user_data)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (effect->lease, effect->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (effect->runtime, effect->key);
  if (rc == WYRELOG_E_OK && (current->darwin_operation_evidence == NULL
      || !evidence_equal (current->darwin_operation_evidence,
      effect->evidence)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_restore_darwin_selected_cleanup_execute
            (effect->resolver, effect->directory, effect->lease,
            effect->provenance->uuid, &effect->provenance->evidence,
            effect->journal->operation_uuid, current->replacement_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            graph->logical_bytes));
  return rc;
}
"""

SELECTED_PROVENANCE_FIXTURE = """\
static wyrelog_error_t
graph_selected_provenance_load (wyl_policy_store_t *policy,
    const WylFactOfflineRestoreJournal *journal,
    GraphProvenance *out_provenance)
{
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list_for_graph
        (policy, journal->tenant_id, journal->selected_graph_id, &records);
  if (record->phase != WYL_POLICY_GRAPH_PROVISIONING_RESTORE_SELECTED
      || !evidence_equal (record->darwin_operation_evidence,
      row->darwin_operation_evidence))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && wyl_fact_graph_darwin_evidence_rebind (&selected,
      row->replacement_uuid, row->old_provisioning_uuid,
      graph->expected_main_identity.object, &out_provenance->evidence)
      != WYRELOG_E_OK)
    rc = WYRELOG_E_POLICY;
  return rc;
}
"""

TERMINAL_RUN_FIXTURE = """\
wyrelog_error_t wyl_fact_offline_restore_graph_commit_finalized_prove_terminal(
  wyl_policy_store_t *policy, const gchar *fact_root,
  WylFactOfflineRestoreJournal *out_committed) {
  if (policy == NULL)
    return WYRELOG_E_INVALID;
#ifdef __APPLE__
  return darwin_finalized_prove_terminal (policy, fact_root, runtime,
             finalized, drain_timeout_us, out_committed);
#else
#ifndef __linux__
  (void)drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_selected_cleanup_shape_open(
      &resolver, &directory, lease, row->old_provisioning_uuid,
      journal.operation_uuid, row->replacement_uuid,
      &graph->expected_main_identity, &graph->staged_main_identity, &shape);
  if (rc == WYRELOG_E_OK &&
      shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL)
    rc = WYRELOG_E_POLICY;
  return rc;
#endif
#endif
}
"""

DARWIN_TERMINAL_FIXTURE = """\
static wyrelog_error_t
darwin_finalized_prove_terminal (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactOfflineRestoreJournal *out_committed)
{
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_encode (finalized,
          &expected_bytes);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            finalized->operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            finalized->operation_uuid, &row);
  if (rc == WYRELOG_E_OK && (row->darwin_operation_evidence == NULL
      || g_bytes_get_size (row->darwin_operation_evidence)
      != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce (runtime, &key,
            drain_timeout_us, &quiescence);
  if (rc == WYRELOG_E_NOT_FOUND) {
    rc = wyl_fact_root_writer_lease_verify (lease);
    if (rc == WYRELOG_E_OK)
      rc = check_finalized_persisted (policy, journal.operation_uuid,
              encoded, row, &journal);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed (runtime,
              &key, drain_timeout_us, &quiescence);
    if (rc == WYRELOG_E_OK)
      rc = check_finalized_persisted (policy, journal.operation_uuid,
              encoded, row, &journal);
  }
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = graph_selected_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open
              (&resolver, &directory, lease, provenance.uuid,
            &provenance.evidence, journal.operation_uuid,
            row->replacement_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity, graph->logical_bytes, &shape));
  if (rc == WYRELOG_E_OK
      && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_directory_compare_darwin_replacement_evidence
              (&directory, row->replacement_uuid, &graph->staged_main_identity,
            graph->logical_bytes, graph->checksum, &expected));
  if (rc == WYRELOG_E_OK)
    rc = check_finalized_persisted (policy, journal.operation_uuid, encoded,
            row, &journal);
  return rc;
}
"""

# Forward declarations ahead of the definitions, in the one-line form of
# the real file, which function_body must skip.
TERMINAL_DECLARATIONS = """\
static wyrelog_error_t darwin_finalized_prove_terminal
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactOfflineRestoreJournal *out_committed);
wyrelog_error_t wyl_fact_offline_restore_graph_commit_finalized_prove_terminal(
  wyl_policy_store_t *policy, WylFactOfflineRestoreJournal *out_committed);
"""

PROMOTE_RUN_FIXTURE = """\
wyrelog_error_t
wyl_fact_offline_restore_graph_commit_promote_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (policy == NULL)
    return WYRELOG_E_INVALID;
#ifdef __APPLE__
  return darwin_promote_selected (policy, fact_root, runtime, operation_uuid,
             expected_revision, drain_timeout_us, out_committed);
#else
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  PromoteEffectContext effect = { &resolver, &directory, lease,
                                  runtime, &key, graph };
  if (rc == WYRELOG_E_OK)
    rc = promote_selected_terminal_effect (row, &effect);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_selected_promote_with_effect
          (policy, row, &before, promote_selected_terminal_effect,
            &effect, &result);
  if (rc == WYRELOG_E_OK)
    rc = restore_unseal_graph (policy, fact_root, runtime,
            out_committed->tenant_id, out_committed->selected_graph_id,
            drain_timeout_us);
  return rc;
#endif
#endif
}
"""

DARWIN_PROMOTE_FIXTURE = """\
static wyrelog_error_t
darwin_promote_selected (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactOfflineRestoreJournal *out_committed)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  if (rc == WYRELOG_E_OK && (row->darwin_operation_evidence == NULL
      || g_bytes_get_size (row->darwin_operation_evidence)
      != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, TRUE, &key, drain_timeout_us,
            &quiescence);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = graph_selected_provenance_load (policy, &journal, row, &provenance);
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open
              (&resolver, &directory, lease, provenance.uuid,
            &provenance.evidence, operation_uuid, row->replacement_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            graph->logical_bytes, &shape));
  if (rc == WYRELOG_E_OK
      && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = check_finalized_persisted (policy, operation_uuid, encoded, row,
            &journal);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_graph_restore_selected_promote_with_effect
          (policy, row, &before, darwin_promote_effect, &effect, &result);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
  }
  if (rc == WYRELOG_E_OK)
    rc = restore_unseal_graph (policy, fact_root, runtime,
            out_committed->tenant_id, out_committed->selected_graph_id,
            drain_timeout_us);
  else {
    wyrelog_error_t receipt_rc =
        wyl_policy_store_offline_restore_receipt_lookup (policy,
            operation_uuid, &receipt);
    if (receipt_rc == WYRELOG_E_OK && receipt != NULL)
      (void) restore_unseal_graph (policy, fact_root, runtime,
          journal.tenant_id, journal.selected_graph_id,
          drain_timeout_us);
  }
  return rc;
}
"""

DARWIN_PROMOTE_EFFECT_FIXTURE = """\
static wyrelog_error_t
darwin_promote_effect
  (const WylPolicyGraphRestoreReplacementRecord *current,
    gpointer user_data)
{
  DarwinPromoteEffect *effect = user_data;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (effect->lease, effect->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (effect->runtime, effect->key);
  if (rc == WYRELOG_E_OK && (current->darwin_operation_evidence == NULL
      || !evidence_equal (current->darwin_operation_evidence,
      effect->evidence)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open
              (effect->resolver, effect->directory, effect->lease,
            effect->provenance->uuid, &effect->provenance->evidence,
            effect->journal->operation_uuid, current->replacement_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            graph->logical_bytes, &shape));
  if (rc == WYRELOG_E_OK
      && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = darwin_post_publish_refusal
          (wyl_fact_graph_directory_compare_darwin_replacement_evidence
              (effect->directory, current->replacement_uuid,
            &graph->staged_main_identity, graph->logical_bytes,
            graph->checksum, effect->expected));
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (effect->lease,
            effect->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (effect->runtime, effect->key);
  return rc;
}
"""

# The real file's one-line forward declarator of the Darwin promotion,
# which function_body must skip.
PROMOTE_DECLARATIONS = """\
static wyrelog_error_t darwin_promote_selected (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactOfflineRestoreJournal *out_committed);
"""

PUBLISHED_RUN_FIXTURE = """\
wyrelog_error_t wyl_fact_offline_restore_graph_commit_published_prove_terminal(
  wyl_policy_store_t *policy, const gchar *fact_root,
  WylFactOfflineRestoreJournal *out_committed) {
  if (policy == NULL)
    return WYRELOG_E_INVALID;
#ifdef __APPLE__
  return darwin_published_prove_terminal (policy, fact_root, runtime,
             finalized, drain_timeout_us, out_committed);
#else
#ifndef __linux__
  (void)drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  wyrelog_error_t receipt_rc = wyl_policy_store_offline_restore_receipt_lookup
        (policy, finalized->operation_uuid, &receipt);
  if (receipt != NULL) {
    rc = restore_unseal_graph (policy, fact_root, runtime,
            finalized->tenant_id, finalized->selected_graph_id,
            drain_timeout_us);
    return rc;
  }
  rc = wyl_policy_store_graph_restore_published_prove(
    policy, &finalized_record, &published);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_selected_cleanup_shape_open(
      &resolver, &directory, lease, graph->old_provisioning_uuid,
      terminal.operation_uuid, row->replacement_uuid,
      &graph->expected_main_identity, &graph->staged_main_identity, &shape);
  if (rc == WYRELOG_E_OK)
    rc = restore_unseal_graph (policy, fact_root, runtime,
            finalized->tenant_id, finalized->selected_graph_id,
            drain_timeout_us);
  return rc;
#endif
#endif
}
"""

# The real body of the Darwin published proof.
DARWIN_PUBLISHED_FIXTURE = """\
static wyrelog_error_t
darwin_published_prove_terminal (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactGraphRuntimeManager *runtime,
    const WylFactOfflineRestoreJournal *finalized, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  g_autoptr (GBytes) finalized_blob = NULL;
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_encode (finalized,
          &finalized_blob);
  if (rc != WYRELOG_E_OK)
    return rc;
  const WylFactOfflineRestoreJournalGraph *graph =
      finalized->graphs != NULL && finalized->graphs->len == 1
      ? g_ptr_array_index (finalized->graphs, 0) : NULL;
  if (finalized->version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION
      || finalized->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || finalized->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || !finalized->replacement_selected_pending_cleanup
      || finalized->policy_generation_published
      || finalized->lifecycle_handoff_complete || graph == NULL
      || graph->transition_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
      || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
      || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
      || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
      || !graph->transition_terminal || !graph->replay_preflighted)
    return WYRELOG_E_POLICY;
  WylPolicyOfflineRestoreReceipt *receipt = NULL;
  rc = wyl_policy_store_offline_restore_receipt_lookup (policy,
          finalized->operation_uuid, &receipt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (receipt == NULL)
    return WYRELOG_E_POLICY;
  guint64 terminal_revision = receipt->final_revision;
  gboolean matches = receipt->scope == WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH
      && g_strcmp0 (receipt->tenant_id, finalized->tenant_id) == 0
      && g_strcmp0 (receipt->selected_graph_id,
          finalized->selected_graph_id) == 0
      && receipt->final_revision == finalized->revision + 2
      && receipt->graph_count == 1
      && g_strcmp0 (receipt->terminal_state, "committed") == 0
      && memcmp (receipt->manifest_sha256, finalized->manifest_sha256,
          sizeof receipt->manifest_sha256) == 0;
  wyl_policy_offline_restore_receipt_free (receipt);
  if (!matches)
    return WYRELOG_E_POLICY;
  g_auto (WylFactOfflineRestoreJournal) terminal = { 0 };
  rc = wyl_fact_offline_restore_journal_decode (finalized_blob, &terminal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_mark_policy_published (&terminal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_mark_lifecycle_handoff (&terminal);
  if (rc == WYRELOG_E_OK && terminal.revision != terminal_revision)
    rc = WYRELOG_E_POLICY;
  WylPolicyGraphAuthorityRecord *authority = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_read_graph_authority (policy, finalized->tenant_id,
            finalized->selected_graph_id, &authority);
  if (rc == WYRELOG_E_OK
      && (authority->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
      || authority->sealed_compatibility))
    rc = WYRELOG_E_POLICY;
  wyl_policy_graph_authority_record_free (authority);
  if (rc == WYRELOG_E_OK) {
    *out_committed = terminal;
    memset (&terminal, 0, sizeof terminal);
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK)
    rc = darwin_finalize_checkpoint ("finalize-darwin-published-before-unseal");
#endif
  if (rc == WYRELOG_E_OK)
    rc = restore_unseal_graph (policy, fact_root, runtime,
            finalized->tenant_id, finalized->selected_graph_id,
            drain_timeout_us);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  return rc;
}
"""

# The real file's forward declaration of the Darwin published proof, which
# function_body must skip.
PUBLISHED_DECLARATIONS = """\
static wyrelog_error_t darwin_published_prove_terminal
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime,
    const WylFactOfflineRestoreJournal *finalized, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);
"""

POSITIVE = {
    "graph_bind_prove_effect": BIND_FIXTURE,
    "graph_capture_provisioned": CAPTURE_FIXTURE,
    "graph_execute_provisioned": EXECUTE_FIXTURE,
    "graph_provenance_load": PROVENANCE_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_sync_staged_run":
        SYNC_STAGED_RUN_FIXTURE,
    "sync_staged_capture_ready": CAPTURE_READY_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_retain_run": RETAIN_RUN_FIXTURE,
    "retain_capture": RETAIN_CAPTURE_FIXTURE,
    "retain_effect": RETAIN_EFFECT_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_sync_retained_run":
        SYNC_RETAINED_RUN_FIXTURE,
    "sync_retained_effect": SYNC_RETAINED_EFFECT_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_publish_run": PUBLISH_RUN_FIXTURE,
    "publish_capture": PUBLISH_CAPTURE_FIXTURE,
    "publish_effect": PUBLISH_EFFECT_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_companion_recover":
        COMPANION_FIXTURE,
    "darwin_companion_recover": DARWIN_RECOVER_FIXTURE,
    "darwin_companion_effect": DARWIN_EFFECT_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_select_replacement_run":
        SELECT_RUN_FIXTURE,
    "darwin_select_replacement": DARWIN_SELECT_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_finalize_run":
        FINALIZE_RUN_FIXTURE,
    "darwin_finalize_selected": DARWIN_FINALIZE_FIXTURE,
    "darwin_finalize_effect": DARWIN_FINALIZE_EFFECT_FIXTURE,
    "graph_selected_provenance_load": SELECTED_PROVENANCE_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_finalized_prove_terminal":
        TERMINAL_RUN_FIXTURE,
    "darwin_finalized_prove_terminal": DARWIN_TERMINAL_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_promote_run": PROMOTE_RUN_FIXTURE,
    "darwin_promote_selected": DARWIN_PROMOTE_FIXTURE,
    "darwin_promote_effect": DARWIN_PROMOTE_EFFECT_FIXTURE,
    "wyl_fact_offline_restore_graph_commit_published_prove_terminal":
        PUBLISHED_RUN_FIXTURE,
    "darwin_published_prove_terminal": DARWIN_PUBLISHED_FIXTURE,
}


def drop_apple_arm(text: str) -> str:
    text = re.sub(r"#ifdef __APPLE__.*?#else\n", "", text, count=1,
                  flags=re.DOTALL)
    head, sep, tail = text.rpartition("#endif\n")
    return head + tail


def replace(old: str, new: str, count: int = -1):
    return lambda text: text.replace(old, new, count)


B = "graph_bind_prove_effect"
C = "graph_capture_provisioned"
X = "graph_execute_provisioned"
P = "graph_provenance_load"
R = "wyl_fact_offline_restore_graph_commit_sync_staged_run"
Q = "sync_staged_capture_ready"
T = "wyl_fact_offline_restore_graph_commit_retain_run"
K = "retain_capture"
E = "retain_effect"
U = "wyl_fact_offline_restore_graph_commit_sync_retained_run"
F = "sync_retained_effect"
V = "wyl_fact_offline_restore_graph_commit_publish_run"
W = "publish_capture"
H = "publish_effect"
Y = "wyl_fact_offline_restore_graph_commit_companion_recover"
Z = "darwin_companion_recover"
G = "darwin_companion_effect"
S = "wyl_fact_offline_restore_graph_commit_select_replacement_run"
D = "darwin_select_replacement"
N = "wyl_fact_offline_restore_graph_commit_finalize_run"
J = "darwin_finalize_selected"
A = "darwin_finalize_effect"
L = "graph_selected_provenance_load"
TR = "wyl_fact_offline_restore_graph_commit_finalized_prove_terminal"
DT = "darwin_finalized_prove_terminal"
PR = "wyl_fact_offline_restore_graph_commit_promote_run"
DP = "darwin_promote_selected"
PE = "darwin_promote_effect"
PP = "wyl_fact_offline_restore_graph_commit_published_prove_terminal"
DB = "darwin_published_prove_terminal"
FINALIZE_SHAPE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open\n"
    "            (&resolver, &directory, lease, provenance.uuid,\n"
    "            &provenance.evidence, operation_uuid, row->replacement_uuid,\n"
    "            &graph->expected_main_identity, &graph->staged_main_identity,"
    "\n"
    "            graph->logical_bytes, &shape));\n"
)
FINALIZE_COMPARE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_directory_compare_darwin_replacement_evidence\n"
    "              (&directory, row->replacement_uuid,"
    " &graph->staged_main_identity,\n"
    "            graph->logical_bytes, graph->checksum, &expected));\n"
)
FINALIZE_BEGIN_LINES = (
    "  if (rc == WYRELOG_E_OK && fresh)\n"
    "    rc = wyl_policy_store_graph_restore_selected_finalize_begin (policy,"
    "\n"
    "            row, &before, &after, &result);\n"
)
FINALIZE_COMPLETE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = wyl_policy_store_graph_restore_selected_finalize_with_effect\n"
    "          (policy, row, &before, &after, darwin_finalize_effect, &effect,"
    "\n"
    "            &result);\n"
)
FINALIZE_EARLY_EVIDENCE_LINES = (
    "  if (rc == WYRELOG_E_OK && (row->darwin_operation_evidence == NULL\n"
    "      || g_bytes_get_size (row->darwin_operation_evidence)\n"
    "      != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE))\n"
    "    rc = WYRELOG_E_POLICY;\n"
)
FINALIZE_RESOLVER_OPEN_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);\n"
)
FINALIZE_EXECUTE_CALL_LINE = (
    "          (wyl_fact_graph_restore_darwin_selected_cleanup_execute\n"
)
TERMINAL_SHAPE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open\n"
    "              (&resolver, &directory, lease, provenance.uuid,\n"
    "            &provenance.evidence, journal.operation_uuid,\n"
    "            row->replacement_uuid, &graph->expected_main_identity,\n"
    "            &graph->staged_main_identity, graph->logical_bytes,"
    " &shape));\n"
)
TERMINAL_COMPARE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_directory_compare_darwin_replacement_evidence\n"
    "              (&directory, row->replacement_uuid,"
    " &graph->staged_main_identity,\n"
    "            graph->logical_bytes, graph->checksum, &expected));\n"
)
TERMINAL_PROVENANCE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = graph_selected_provenance_load (policy, &journal, row,"
    " &provenance);\n"
)
TERMINAL_FINAL_PERSISTED_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = check_finalized_persisted (policy, journal.operation_uuid,"
    " encoded,\n"
    "            row, &journal);\n"
)
TERMINAL_EARLY_EVIDENCE_LINES = FINALIZE_EARLY_EVIDENCE_LINES
TERMINAL_RESOLVER_OPEN_LINES = FINALIZE_RESOLVER_OPEN_LINES
TERMINAL_SHAPE_TEST = (
    "shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL"
)
PROMOTE_PROVENANCE_LINES = TERMINAL_PROVENANCE_LINES
PROMOTE_SHAPE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open\n"
    "              (&resolver, &directory, lease, provenance.uuid,\n"
    "            &provenance.evidence, operation_uuid,"
    " row->replacement_uuid,\n"
    "            &graph->expected_main_identity,"
    " &graph->staged_main_identity,\n"
    "            graph->logical_bytes, &shape));\n"
)
PROMOTE_RECHECK_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = check_finalized_persisted (policy, operation_uuid, encoded,"
    " row,\n"
    "            &journal);\n"
)
PROMOTE_STORE_LINES = (
    "  if (rc == WYRELOG_E_OK) {\n"
    "    rc = wyl_policy_store_graph_restore_selected_promote_with_effect\n"
    "          (policy, row, &before, darwin_promote_effect, &effect,"
    " &result);\n"
)
PROMOTE_UNSEAL_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = restore_unseal_graph (policy, fact_root, runtime,\n"
    "            out_committed->tenant_id, out_committed->selected_graph_id,\n"
    "            drain_timeout_us);\n"
)
PROMOTE_EFFECT_SHAPE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open\n"
    "              (effect->resolver, effect->directory, effect->lease,\n"
    "            effect->provenance->uuid, &effect->provenance->evidence,\n"
    "            effect->journal->operation_uuid, current->replacement_uuid,\n"
    "            &graph->expected_main_identity,"
    " &graph->staged_main_identity,\n"
    "            graph->logical_bytes, &shape));\n"
)
PROMOTE_EFFECT_COMPARE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_directory_compare_darwin_replacement_evidence\n"
    "              (effect->directory, current->replacement_uuid,\n"
    "            &graph->staged_main_identity, graph->logical_bytes,\n"
    "            graph->checksum, effect->expected));\n"
)
PROMOTE_EFFECT_EVIDENCE_LINES = (
    "  if (rc == WYRELOG_E_OK && (current->darwin_operation_evidence == NULL\n"
    "      || !evidence_equal (current->darwin_operation_evidence,\n"
    "      effect->evidence)))\n"
    "    rc = WYRELOG_E_POLICY;\n"
)
SELECT_SHAPE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_shape (&resolver, &directory, lease,"
    " &journal,\n"
    "            row, &provenance);\n"
)
SELECT_COMPARE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_directory_compare_darwin_replacement_evidence\n"
    "              (&directory, row->replacement_uuid,"
    " &graph->staged_main_identity,\n"
    "            graph->logical_bytes, graph->checksum, &expected));\n"
)
SELECT_CALL_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = wyl_policy_store_graph_restore_select_with_effect (policy, row,\n"
    "            &before, &after, darwin_companion_effect, &effect,"
    " &result);\n"
)
SELECT_REBIND_LINES = (
    "  if (rc == WYRELOG_E_OK\n"
    "      && (wyl_fact_graph_darwin_evidence_rebind (&expected,\n"
    "      row->replacement_uuid, graph->old_provisioning_uuid,\n"
    "      graph->expected_main_identity.object, &rebuilt) != WYRELOG_E_OK\n"
    "      || !wyl_fact_graph_darwin_evidence_equal (&rebuilt,\n"
    "      &provenance.evidence)))\n"
    "    rc = WYRELOG_E_POLICY;\n"
)
SETTER_LINES = (
    "    if (rc == WYRELOG_E_OK)\n"
    "      rc = wyl_policy_store_graph_restore_replacement_set_darwin"
    "_evidence\n"
    "            (policy, row, raw_journal, bytes, &stored_result, &stored);\n"
)
SYNC_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = wyl_policy_store_graph_restore_replacement_sync_with_effect\n"
    "          (policy, row, raw_journal, darwin_companion_effect, &effect,\n"
    "            &result, out_committed);\n"
)
COMPARE_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = darwin_post_publish_refusal\n"
    "          (wyl_fact_graph_directory_compare_darwin_replacement_evidence\n"
    "            (&directory, row->replacement_uuid,"
    " &graph->staged_main_identity,\n"
    "            graph->logical_bytes, graph->checksum, &expected));\n"
)
REREAD_LINES = (
    "    if (rc == WYRELOG_E_OK)\n"
    "      rc = check_persisted (policy, operation_uuid, encoded, row,"
    " &journal);\n"
)


PUBLISHED_PREDICATE_LINES = (
    "  if (finalized->version !="
    " WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION\n"
    "      || finalized->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH\n"
    "      || finalized->decision !="
    " WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT\n"
    "      || !finalized->replacement_selected_pending_cleanup\n"
    "      || finalized->policy_generation_published\n"
    "      || finalized->lifecycle_handoff_complete || graph == NULL\n"
    "      || graph->transition_state !=\n"
    "      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED\n"
    "      || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE\n"
    "      || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE\n"
    "      || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED\n"
    "      || !graph->transition_terminal || !graph->replay_preflighted)\n"
    "    return WYRELOG_E_POLICY;\n"
)
PUBLISHED_NO_RECEIPT_LINES = (
    "  if (receipt == NULL)\n"
    "    return WYRELOG_E_POLICY;\n"
)
PUBLISHED_MARK_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = wyl_fact_offline_restore_journal_mark_policy_published"
    " (&terminal);\n"
)
PUBLISHED_AUTHORITY_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = wyl_policy_store_read_graph_authority (policy,"
    " finalized->tenant_id,\n"
    "            finalized->selected_graph_id, &authority);\n"
)
PUBLISHED_UNSEAL_LINES = (
    "  if (rc == WYRELOG_E_OK)\n"
    "    rc = restore_unseal_graph (policy, fact_root, runtime,\n"
    "            finalized->tenant_id, finalized->selected_graph_id,\n"
    "            drain_timeout_us);\n"
)
PUBLISHED_ARM_CALL = (
    "             finalized, drain_timeout_us, out_committed);\n#else"
)


def published_added(call: str):
    return replace(PUBLISHED_UNSEAL_LINES,
                   "  if (rc == WYRELOG_E_OK)\n    rc = " + call + ";\n"
                   + PUBLISHED_UNSEAL_LINES)


def effect_peek(helper_bodies: str):
    """The promote effect calling effect_peek, prepended with its body."""
    def transform(text: str) -> str:
        return helper_bodies + text.replace(
            PROMOTE_EFFECT_SHAPE_LINES,
            "  if (rc == WYRELOG_E_OK)\n    rc = effect_peek (effect);\n"
            + PROMOTE_EFFECT_SHAPE_LINES, 1)
    return transform


EFFECT_PEEK_STORE = (
    "static wyrelog_error_t\n"
    "effect_peek (DarwinPromoteEffect *effect)\n"
    "{\n"
    "  return wyl_policy_store_offline_restore_load (effect->policy,"
    " NULL, NULL);\n"
    "}\n"
)
EFFECT_PEEK_TRANSITIVE = (
    "static wyrelog_error_t\n"
    "effect_peek_inner (DarwinPromoteEffect *effect)\n"
    "{\n"
    "  return wyl_policy_store_offline_restore_load (effect->policy,"
    " NULL, NULL);\n"
    "}\n"
    "static wyrelog_error_t\n"
    "effect_peek (DarwinPromoteEffect *effect)\n"
    "{\n"
    "  return effect_peek_inner (effect);\n"
    "}\n"
)


def move_before(block: str, anchor: str):
    def transform(text: str) -> str:
        assert block in text and anchor in text
        text = text.replace(block, "", 1)
        return text.replace(anchor, block + anchor, 1)
    return transform


MUTANTS = (
    ("bind: swap to name-only", B, replace(
        "capture_provisioned_with_evidence\n          (provider, old_uuid,"
        " evidence,",
        "capture_provisioned\n          (provider, old_uuid,"),
     "E_NO_DARWIN_CALL"),
    ("bind: drop the Apple arm", B, lambda text: re.sub(
        r"#ifdef __APPLE__.*?#else\n", "", text, flags=re.DOTALL
    ).replace("#endif\n", ""), "E_APPLE_ARMS"),
    ("bind: Windows arm swaps to the name-only capture", B, replace(
        "transition_windows_capture_provisioned_with_evidence\n"
        "          (provider, old_uuid, windows_evidence,",
        "transition_posix_capture_provisioned\n"
        "          (provider, old_uuid,"), "E_NO_WINDOWS_CALL"),
    ("bind: Windows arm dropped", B, replace(
        "#ifdef G_OS_WIN32\n", "#if 0\n"), "E_WINDOWS_ARMS"),
    ("bind: plain capture in the Windows arm", B, replace(
        "            &s, &o);\n#else",
        "            &s, &o);\n  rc = wyl_fact_artifact_transition_capture"
        " (provider, &lifecycle, &s, &o);\n#else"), "E_WINDOWS_PLAIN_CALL"),
    ("bind: Windows backend capture in the Windows arm", B, replace(
        "            &s, &o);\n#else",
        "            &s, &o);\n  rc = wyl_fact_artifact_transition_windows"
        "_capture (provider, &lifecycle, &s, &o);\n#else"),
     "E_WINDOWS_PLAIN_CALL"),
    ("bind: plain capture beside the evidence call", B, replace(
        "#else",
        "  rc = wyl_fact_artifact_transition_posix_capture (provider,"
        " &lifecycle, &s, &o);\n#else"), "E_DARWIN_PLAIN_CALL"),
    ("bind: facade capture beside the evidence call", B, replace(
        "#else",
        "  rc = wyl_fact_artifact_transition_capture (provider,"
        " &lifecycle, &s, &o);\n#else"), "E_DARWIN_PLAIN_CALL"),
    ("bind: facade observe beside the evidence call", B, replace(
        "#else",
        "  rc = wyl_fact_artifact_transition_observe (provider,"
        " &lifecycle, &o);\n#else"), "E_DARWIN_PLAIN_CALL"),
    ("bind: evidence call twice", B, replace(
        "#else",
        "  rc = wyl_fact_artifact_transition_posix_capture_provisioned"
        "_with_evidence (provider, old_uuid, evidence, &request, slot,"
        " &lifecycle, &s, &o);\n#else"), "E_NO_DARWIN_CALL"),
    ("bind: Linux arm loses its call", B, replace(
        "    rc = wyl_fact_artifact_transition_posix_capture_provisioned\n"
        "          (provider, old_uuid, &request, slot, &lifecycle, &s,"
        " &o);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_LINUX_ARM"),
    ("bind: function missing", B, replace(
        "graph_bind_prove_effect", "graph_bind_prove_other"),
     "E_NO_FUNCTION"),
    ("capture: Darwin arm swaps to name-only", C, replace(
        "posix_capture_provisioned_with_evidence\n"
        "           (provider, provenance->uuid, &provenance->evidence,",
        "posix_capture_provisioned\n"
        "           (provider, provenance->uuid,"), "E_NO_DARWIN_CALL"),
    ("capture: Apple arm dropped", C, drop_apple_arm, "E_APPLE_ARMS"),
    ("capture: facade capture beside the evidence call", C, replace(
        "out_observation);\n#else",
        "out_observation);\n  wyl_fact_artifact_transition_capture"
        " (provider, lifecycle, out_snapshot, out_observation);\n#else", 1),
     "E_DARWIN_PLAIN_CALL"),
    ("capture: Windows arm dropped", C, replace(
        "#ifdef G_OS_WIN32\n", "#if 0\n"), "E_WINDOWS_ARMS"),
    ("execute: Darwin arm swaps to name-only", X, replace(
        "posix_execute_provisioned_with_evidence\n"
        "           (provider, provenance->uuid, &provenance->evidence,",
        "posix_execute_provisioned\n"
        "           (provider, provenance->uuid,"), "E_NO_DARWIN_CALL"),
    ("execute: Darwin arm calls the public execute", X, replace(
        "posix_execute_provisioned_with_evidence\n"
        "           (provider, provenance->uuid, &provenance->evidence,",
        "posix_execute\n"
        "           (provider,"), "E_NO_DARWIN_CALL"),
    ("execute: facade execute beside the evidence call", X, replace(
        "out_durability);\n#else",
        "out_durability);\n  wyl_fact_artifact_transition_execute"
        " (provider, request, authorized, op, out_effect);\n#else", 1),
     "E_DARWIN_PLAIN_CALL"),
    ("execute: evidence call twice", X, replace(
        "out_durability);\n#else",
        "out_durability);\n  wyl_fact_artifact_transition_posix_execute"
        "_provisioned_with_evidence (provider, uuid, evidence, request,"
        " authorized, op, out_effect, out_durability);\n#else", 1),
     "E_NO_DARWIN_CALL"),
    ("execute: Windows arm calls the plain Windows execute", X, replace(
        "windows_execute_provisioned_with_evidence\n"
        "           (provider, provenance->uuid, &provenance->evidence,",
        "windows_execute\n"
        "           (provider,"), "E_NO_WINDOWS_CALL"),
    ("execute: Linux arm loses its call", X, replace(
        "  return wyl_fact_artifact_transition_posix_execute_provisioned"
        " (provider,\n"
        "             provenance->uuid, request, authorized, op, out_effect,\n"
        "             out_durability);\n",
        "  return WYRELOG_E_OK;\n"), "E_LINUX_ARM"),
    ("execute: function renamed", X, replace(
        "graph_execute_provisioned (", "graph_execute_other ("),
     "E_NO_FUNCTION"),
    ("provenance: decode removed", P, replace(
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_darwin_evidence_decode (evidence_bytes,\n"
        "            evidence_length, record->op_uuid,"
        " &out_provenance->evidence);\n", ""), "E_NO_DARWIN_CALL"),
    ("provenance: Apple arm dropped", P, drop_apple_arm, "E_APPLE_ARMS"),
    ("sync_staged_run: facade execute replaces the helper", R, replace(
        "graph_execute_provisioned (",
        "wyl_fact_artifact_transition_execute ("),
     "E_ROUTE_DIRECT"),
    ("sync_staged_run: evidence execute beside the helper", R, replace(
        "  wyl_fact_artifact_transition_free (provider);",
        "  rc = wyl_fact_artifact_transition_posix_execute_provisioned_with"
        "_evidence (provider, uuid, evidence, &request, &observation, op,"
        " &effect, &durability);\n"
        "  wyl_fact_artifact_transition_free (provider);"), "E_ROUTE_DIRECT"),
    ("capture_ready: evidence capture replaces the helper", Q, replace(
        "graph_capture_provisioned (",
        "wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence"
        " ("),
     "E_ROUTE_DIRECT"),
    ("capture_ready: helper call removed", Q, replace(
        "    rc = graph_capture_provisioned (provider, provenance, &request,\n"
        "            slot, &lifecycle, &snapshot, out_observation);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("retain_run: provenance load removed", T, replace(
        "    rc = graph_provenance_load (policy, &journal, row,"
        " &provenance);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("retain_run: evidence execute beside the effect", T, replace(
        "  wyl_fact_artifact_transition_free (provider);",
        "  rc = wyl_fact_artifact_transition_posix_execute_provisioned_with"
        "_evidence (provider, uuid, evidence, &request, &observation, op,"
        " &effect, &durability);\n"
        "  wyl_fact_artifact_transition_free (provider);"), "E_ROUTE_DIRECT"),
    ("retain_capture: name-only capture replaces the helper", K, replace(
        "graph_capture_provisioned (",
        "wyl_fact_artifact_transition_posix_capture_provisioned ("),
     "E_ROUTE_DIRECT"),
    ("retain_capture: helper call removed", K, replace(
        "  rc = graph_capture_provisioned (provider, provenance, &request,"
        " slot,\n"
        "          &lifecycle, out_snapshot, out_observation);\n", ""),
     "E_ROUTE_HELPER"),
    ("retain_effect: plain execute for RETAIN", E, replace(
        "graph_execute_provisioned (",
        "wyl_fact_artifact_transition_posix_execute (", 1),
     "E_ROUTE_DIRECT"),
    ("retain_effect: evidence capture bypasses the helper", E, replace(
        "    rc = retain_capture (provider, journal, provenance,\n"
        "            WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,",
        "    rc = wyl_fact_artifact_transition_posix_capture_provisioned_with"
        "_evidence (provider, journal, provenance,\n"
        "            WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,"),
     "E_ROUTE_DIRECT"),
    ("retain_effect: facade execute for SYNC_RETAIN_DIR", E, replace(
        "    rc = graph_execute_provisioned (provider, provenance,"
        " &request,\n"
        "            &retained,",
        "    rc = wyl_fact_artifact_transition_execute (provider,"
        " provenance, &request,\n"
        "            &retained,"), "E_ROUTE_DIRECT"),
    ("retain_effect: every helper capture removed", E, replace(
        "retain_capture (", "wyl_fact_artifact_transition_capture ("),
     "E_ROUTE_HELPER"),
    ("sync_retained_run: provenance load removed", U, replace(
        "    rc = graph_provenance_load (policy, &journal, row,"
        " &provenance);\n",
        ""), "E_ROUTE_HELPER"),
    ("sync_retained_effect: Windows execute in the loop", F, replace(
        "graph_execute_provisioned (",
        "wyl_fact_artifact_transition_windows_execute ("),
     "E_ROUTE_DIRECT"),
    ("sync_retained_effect: helper execute removed", F, replace(
        "    rc = graph_execute_provisioned (context->provider,\n"
        "            context->provenance, &request, &observation,"
        " operation,\n"
        "            &effect, &durability);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("publish_run: provenance load removed", V, replace(
        "    rc = graph_provenance_load (policy, &journal, row,"
        " &provenance);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("publish_run: evidence execute beside the effect", V, replace(
        "  wyl_fact_artifact_transition_free (provider);",
        "  rc = wyl_fact_artifact_transition_posix_execute_provisioned_with"
        "_evidence (provider, uuid, evidence, &request, &observation, op,"
        " &effect, &durability);\n"
        "  wyl_fact_artifact_transition_free (provider);"), "E_ROUTE_DIRECT"),
    ("publish_capture: evidence capture replaces the helper", W, replace(
        "retain_capture (",
        "wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence"
        " ("), "E_ROUTE_DIRECT"),
    ("publish_capture: facade capture replaces the helper", W, replace(
        "retain_capture (", "wyl_fact_artifact_transition_capture ("),
     "E_ROUTE_HELPER"),
    ("publish_effect: plain execute for PUBLISH", H, replace(
        "    rc = graph_execute_provisioned (context->provider,\n"
        "            context->provenance, &request, &observation,\n"
        "            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,",
        "    rc = wyl_fact_artifact_transition_posix_execute"
        " (context->provider,\n"
        "            context->provenance, &request, &observation,\n"
        "            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,"),
     "E_ROUTE_DIRECT"),
    ("publish_effect: Windows execute for SYNC_PUBLISH_DIR", H, replace(
        "    rc = graph_execute_provisioned (context->provider,\n"
        "            context->provenance, &request, &observation,\n"
        "            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,",
        "    rc = wyl_fact_artifact_transition_windows_execute"
        " (context->provider,\n"
        "            context->provenance, &request, &observation,\n"
        "            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,"),
     "E_ROUTE_DIRECT"),
    ("publish_effect: every helper capture removed", H, replace(
        "publish_capture (", "wyl_fact_artifact_transition_capture ("),
     "E_ROUTE_HELPER"),
    ("publish_effect: facade execute replaces every helper", H, replace(
        "graph_execute_provisioned (",
        "wyl_fact_artifact_transition_execute ("), "E_ROUTE_DIRECT"),
    ("companion: Apple arm dropped", Y, drop_apple_arm, "E_COMPANION_ARMS"),
    ("companion: Apple arm refuses instead of the call", Y, replace(
        "  return darwin_companion_recover (policy, fact_root, runtime,\n"
        "             operation_uuid, expected_revision, drain_timeout_us,\n"
        "             out_committed);\n",
        "  return WYRELOG_E_POLICY;\n"), "E_COMPANION_ROUTE"),
    ("companion: Apple arm calls the setter directly", Y, replace(
        "             out_committed);\n#else",
        "             out_committed);\n"
        "  rc = wyl_policy_store_graph_restore_replacement_set_darwin_evidence"
        " (policy, row, raw_journal, bytes, &result, &stored);\n#else"),
     "E_COMPANION_DIRECT"),
    ("companion: Linux arm calls the setter", Y, replace(
        "  return rc;\n#endif",
        "  rc = wyl_policy_store_graph_restore_replacement_set_darwin_evidence"
        " (policy, row, raw_journal, bytes, &result, &stored);\n"
        "  return rc;\n#endif"), "E_COMPANION_LEAK"),
    ("companion: function renamed", Z, replace(
        "darwin_companion_recover (", "darwin_companion_other ("),
     "E_NO_FUNCTION"),
    ("darwin recover: capture twice", Z, replace(
        SETTER_LINES,
        "    if (rc == WYRELOG_E_OK)\n"
        "      rc = wyl_fact_graph_directory_capture_darwin_replacement"
        "_evidence"
        " (&directory, uuid, staged, size, checksum, &captured);\n"
        + SETTER_LINES), "E_COMPANION_CALLS"),
    ("darwin recover: compare removed", Z, replace(COMPARE_LINES, ""),
     "E_COMPANION_CALLS"),
    ("darwin recover: mark beside the sync", Z, replace(
        "  return rc;\n}",
        "  rc = wyl_policy_store_graph_restore_replacement_mark_companion"
        "_synced"
        " (policy, row, raw_journal, &result, out_committed);\n"
        "  return rc;\n}"), "E_COMPANION_CALLS"),
    ("darwin recover: reload removed", Z, replace(
        "      row = g_steal_pointer (&stored);\n", ""),
     "E_COMPANION_RELOAD"),
    ("darwin recover: sync before the setter", Z,
     move_before(SYNC_LINES, SETTER_LINES), "E_COMPANION_ORDER"),
    ("darwin recover: compare before the setter", Z,
     move_before(COMPARE_LINES, SETTER_LINES), "E_COMPANION_ORDER"),
    ("darwin recover: re-read removed", Z, replace(REREAD_LINES, ""),
     "E_COMPANION_REREAD"),
    ("darwin recover: prologue check_persisted removed", Z, replace(
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = check_persisted (policy, operation_uuid, encoded, row,"
        " &journal);\n", ""), "E_COMPANION_PERSISTED"),
    ("darwin recover: sync with another expected row", Z, replace(
        "          (policy, row, raw_journal, darwin_companion_effect,",
        "          (policy, expected, raw_journal, darwin_companion_effect,"),
     "E_COMPANION_ROW"),
    ("darwin recover: check_policy dropped", Z, replace(
        "    rc = check_policy (policy, &journal, row);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin recover: graph_commit_quiesce dropped", Z, replace(
        "    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,\n"
        "            operation_uuid, encoded, row, FALSE, &key,"
        " drain_timeout_us,\n"
        "            &quiescence);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin recover: bind dropped", Z, replace(
        "    rc = wyl_policy_store_bind_fact_root_authorized (policy,"
        " fact_root, lease);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin effect: runtime check dropped", G, replace(
        "    rc = check_runtime (effect->runtime, effect->key);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("select: Apple arm dropped", S, drop_apple_arm, "E_SELECT_ARMS"),
    ("select: Darwin step called twice", S, replace(
        "             out_committed);\n#else",
        "             out_committed);\n"
        "  rc = darwin_select_replacement (policy, fact_root, runtime,"
        " operation_uuid, expected_revision, drain_timeout_us,"
        " out_committed);\n#else"), "E_SELECT_ROUTE"),
    ("select: Apple arm compares directly", S, replace(
        "             out_committed);\n#else",
        "             out_committed);\n"
        "  rc = wyl_fact_graph_directory_compare_darwin_replacement_evidence"
        " (&directory, uuid, staged, size, checksum, &expected);\n#else"),
     "E_SELECT_DIRECT"),
    ("select: Linux arm calls the Darwin step", S, replace(
        "  return rc;\n#endif",
        "  rc = darwin_select_replacement (policy, fact_root, runtime,"
        " operation_uuid, expected_revision, drain_timeout_us,"
        " out_committed);\n"
        "  return rc;\n#endif"), "E_SELECT_LEAK"),
    ("darwin select: compare removed", D, replace(SELECT_COMPARE_LINES, ""),
     "E_SELECT_CALLS"),
    ("darwin select: rebind removed", D, replace(SELECT_REBIND_LINES, ""),
     "E_SELECT_CALLS"),
    ("darwin select: capture added", D, replace(
        SELECT_CALL_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_directory_capture_darwin_replacement"
        "_evidence (&directory, uuid, staged, size, checksum, &captured);\n"
        + SELECT_CALL_LINES), "E_SELECT_CALLS"),
    ("darwin select: open_shape beside the Darwin shape", D, replace(
        SELECT_SHAPE_LINES,
        SELECT_SHAPE_LINES
        + "  if (rc == WYRELOG_E_OK)\n"
        "    rc = open_shape (&resolver, &directory, lease, &journal, row,"
        " &layout, NULL);\n"), "E_SELECT_CALLS"),
    ("darwin select: compare after the selection", D,
     move_before(SELECT_CALL_LINES, SELECT_COMPARE_LINES), "E_SELECT_ORDER"),
    ("darwin select: shape after the compare", D,
     move_before(SELECT_COMPARE_LINES, SELECT_SHAPE_LINES), "E_SELECT_ORDER"),
    ("darwin select: rebind after the shape", D,
     move_before(SELECT_SHAPE_LINES, SELECT_REBIND_LINES), "E_SELECT_ORDER"),
    ("darwin select: Linux effect", D, replace(
        "&before, &after, darwin_companion_effect,",
        "&before, &after, select_replacement_effect,"), "E_SELECT_EFFECT"),
    ("darwin select: another expected row", D, replace(
        "select_with_effect (policy, row,",
        "select_with_effect (policy, journal_row,"), "E_SELECT_EFFECT"),
    ("darwin select: provenance load dropped", D, replace(
        "    rc = graph_provenance_load (policy, &journal, row,"
        " &provenance);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin select: check_persisted dropped", D, replace(
        "    rc = check_persisted (policy, operation_uuid, encoded, row,"
        " &journal);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin select: graph_commit_quiesce dropped", D, replace(
        "    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,\n"
        "            operation_uuid, encoded, row, FALSE, &key,"
        " drain_timeout_us,\n"
        "            &quiescence);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin effect: shape dropped", G, replace(
        "    rc = darwin_post_publish_shape (effect->resolver,"
        " effect->directory,\n"
        "            effect->lease, effect->journal, current,"
        " effect->provenance);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("finalize: Apple arm dropped", N, drop_apple_arm, "E_FINALIZE_ARMS"),
    ("finalize: Darwin step called twice", N, replace(
        "             out_committed);\n#else",
        "             out_committed);\n"
        "  rc = darwin_finalize_selected (policy, fact_root, runtime,"
        " operation_uuid, expected_revision, drain_timeout_us,"
        " out_committed);\n#else"), "E_FINALIZE_ROUTE"),
    ("finalize: Apple arm executes directly", N, replace(
        "             out_committed);\n#else",
        "             out_committed);\n"
        "  rc = wyl_fact_graph_restore_darwin_selected_cleanup_execute"
        " (&resolver, &directory, lease, uuid, &evidence, operation_uuid,"
        " replacement, &old_main, &new_main, size);\n#else"),
     "E_FINALIZE_DIRECT"),
    ("finalize: Linux arm calls the Darwin step", N, replace(
        "  return rc;\n#endif",
        "  rc = darwin_finalize_selected (policy, fact_root, runtime,"
        " operation_uuid, expected_revision, drain_timeout_us,"
        " out_committed);\n"
        "  return rc;\n#endif"), "E_FINALIZE_LEAK"),
    ("finalize: Linux arm takes the Darwin shape", N, replace(
        "    rc = wyl_fact_graph_restore_selected_cleanup_shape_open"
        " (&resolver,",
        "    rc = wyl_fact_graph_restore_darwin_selected_cleanup_shape_open"
        " (&resolver,"), "E_FINALIZE_LEAK"),
    ("darwin finalize: ACTIVE loader swapped in", J, replace(
        "    rc = graph_selected_provenance_load (policy,",
        "    rc = graph_provenance_load (policy,"), "E_ROUTE_HELPER"),
    ("darwin finalize: ACTIVE loader beside", J, replace(
        "    rc = graph_selected_provenance_load (policy, &journal, row,"
        " &provenance);\n",
        "    rc = graph_selected_provenance_load (policy, &journal, row,"
        " &provenance);\n"
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = graph_provenance_load (policy, &journal, row,"
        " &provenance);\n"), "E_FINALIZE_CALLS"),
    ("darwin finalize: early row-evidence refusal dropped", J,
     replace(FINALIZE_EARLY_EVIDENCE_LINES, ""),
     "E_FINALIZE_EARLY_EVIDENCE"),
    ("darwin finalize: row-evidence refusal after the resolver open", J,
     move_before(FINALIZE_RESOLVER_OPEN_LINES, FINALIZE_EARLY_EVIDENCE_LINES),
     "E_FINALIZE_EARLY_EVIDENCE"),
    ("darwin finalize: compare dropped", J,
     replace(FINALIZE_COMPARE_LINES, ""), "E_FINALIZE_CALLS"),
    ("darwin finalize: shape dropped", J,
     replace(FINALIZE_SHAPE_LINES, ""), "E_FINALIZE_CALLS"),
    ("darwin finalize: begin dropped", J,
     replace(FINALIZE_BEGIN_LINES, ""), "E_FINALIZE_CALLS"),
    ("darwin finalize: rebind called directly", J, replace(
        FINALIZE_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_darwin_evidence_rebind (&expected, uuid,"
        " old_uuid, object, &rebuilt);\n" + FINALIZE_SHAPE_LINES),
     "E_FINALIZE_CALLS"),
    ("darwin finalize: execute outside the effect", J, replace(
        FINALIZE_BEGIN_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_restore_darwin_selected_cleanup_execute"
        " (&resolver, &directory, lease, uuid, &evidence, operation_uuid,"
        " replacement, &old_main, &new_main, size);\n"
        + FINALIZE_BEGIN_LINES), "E_FINALIZE_CALLS"),
    ("darwin finalize: Linux shape beside the Darwin one", J, replace(
        FINALIZE_SHAPE_LINES,
        FINALIZE_SHAPE_LINES
        + "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_restore_selected_cleanup_shape_open"
        " (&resolver, &directory, lease, old, operation_uuid, replacement,"
        " &old_main, &new_main, &shape);\n"), "E_FINALIZE_CALLS"),
    ("darwin finalize: begin after the completion", J,
     move_before(FINALIZE_COMPLETE_LINES, FINALIZE_BEGIN_LINES),
     "E_FINALIZE_ORDER"),
    ("darwin finalize: compare after begin", J,
     move_before(FINALIZE_BEGIN_LINES, FINALIZE_COMPARE_LINES),
     "E_FINALIZE_ORDER"),
    ("darwin finalize: shape after the compare", J,
     move_before(FINALIZE_COMPARE_LINES, FINALIZE_SHAPE_LINES),
     "E_FINALIZE_ORDER"),
    ("darwin finalize: Linux effect", J, replace(
        "&before, &after, darwin_finalize_effect,",
        "&before, &after, finalize_selected_effect,"), "E_FINALIZE_EFFECT"),
    ("darwin finalize: another expected row", J, replace(
        "          (policy, row, &before, &after, darwin_finalize_effect,",
        "          (policy, journal_row, &before, &after,"
        " darwin_finalize_effect,"), "E_FINALIZE_EFFECT"),
    ("darwin finalize: graph_commit_quiesce dropped", J, replace(
        "    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,\n"
        "            operation_uuid, encoded, row, TRUE, &key,"
        " drain_timeout_us,\n"
        "            &quiescence);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin finalize: check_runtime dropped", J, replace(
        "    rc = check_runtime (runtime, &key);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin finalize: bind dropped", J, replace(
        "    rc = wyl_policy_store_bind_fact_root_authorized (policy,"
        " fact_root, lease);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("finalize effect: Linux execute instead", A, replace(
        FINALIZE_EXECUTE_CALL_LINE,
        "          (wyl_fact_graph_restore_selected_cleanup_execute\n"),
     "E_ROUTE_HELPER"),
    ("finalize effect: Linux execute beside", A, replace(
        "  return rc;\n}",
        "  rc = wyl_fact_graph_restore_selected_cleanup_execute (resolver,"
        " directory, lease, old, operation_uuid, replacement, &old_main,"
        " &new_main);\n"
        "  return rc;\n}"), "E_FINALIZE_EFFECT_EXECUTE"),
    ("finalize effect: no row evidence check", A, replace(
        "  if (rc == WYRELOG_E_OK && (current->darwin_operation_evidence =="
        " NULL\n"
        "      || !evidence_equal (current->darwin_operation_evidence,\n"
        "      effect->evidence)))\n"
        "    rc = WYRELOG_E_POLICY;\n", ""), "E_FINALIZE_EFFECT_EVIDENCE"),
    ("finalize effect: runtime check dropped", A, replace(
        "    rc = check_runtime (effect->runtime, effect->key);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("selected loader: rebind removed", L, replace(
        "wyl_fact_graph_darwin_evidence_rebind (&selected,",
        "wyl_fact_graph_darwin_evidence_decode (&selected,"),
     "E_FINALIZE_PROVENANCE"),
    ("selected loader: ACTIVE record read", L, replace(
        "WYL_POLICY_GRAPH_PROVISIONING_RESTORE_SELECTED",
        "WYL_POLICY_GRAPH_PROVISIONING_ACTIVE"), "E_FINALIZE_PROVENANCE"),
    ("selected loader: row equality dropped", L, replace(
        "      || !evidence_equal (record->darwin_operation_evidence,\n"
        "      row->darwin_operation_evidence))\n", "      )\n"),
     "E_FINALIZE_PROVENANCE"),
    ("terminal: Apple arm dropped", TR, drop_apple_arm, "E_TERMINAL_ARMS"),
    ("terminal: Darwin step called twice", TR, replace(
        "             finalized, drain_timeout_us, out_committed);\n#else",
        "             finalized, drain_timeout_us, out_committed);\n"
        "  rc = darwin_finalized_prove_terminal (policy, fact_root, runtime,"
        " finalized, drain_timeout_us, out_committed);\n#else"),
     "E_TERMINAL_ROUTE"),
    ("terminal: Apple arm proves the shape directly", TR, replace(
        "             finalized, drain_timeout_us, out_committed);\n#else",
        "             finalized, drain_timeout_us, out_committed);\n"
        "  rc = wyl_fact_graph_restore_darwin_selected_cleanup_shape_open"
        " (&resolver, &directory, lease, uuid, &evidence, operation_uuid,"
        " replacement, &old_main, &new_main, size, &shape);\n#else"),
     "E_TERMINAL_DIRECT"),
    ("terminal: Linux arm calls the Darwin step", TR, replace(
        "  return rc;\n#endif",
        "  rc = darwin_finalized_prove_terminal (policy, fact_root, runtime,"
        " finalized, drain_timeout_us, out_committed);\n"
        "  return rc;\n#endif"), "E_TERMINAL_LEAK"),
    ("terminal: Linux arm takes the Darwin shape", TR, replace(
        "    rc = wyl_fact_graph_restore_selected_cleanup_shape_open(",
        "    rc = wyl_fact_graph_restore_darwin_selected_cleanup_shape_open("),
     "E_TERMINAL_LEAK"),
    ("darwin terminal: compare dropped", DT,
     replace(TERMINAL_COMPARE_LINES, ""), "E_TERMINAL_CALLS"),
    ("darwin terminal: provenance load dropped", DT,
     replace(TERMINAL_PROVENANCE_LINES, ""), "E_ROUTE_HELPER"),
    ("darwin terminal: ACTIVE loader swapped in", DT, replace(
        "    rc = graph_selected_provenance_load (policy,",
        "    rc = graph_provenance_load (policy,"), "E_ROUTE_HELPER"),
    ("darwin terminal: ACTIVE loader beside", DT, replace(
        TERMINAL_PROVENANCE_LINES,
        TERMINAL_PROVENANCE_LINES
        + "  if (rc == WYRELOG_E_OK)\n"
        "    rc = graph_provenance_load (policy, &journal, row,"
        " &provenance);\n"), "E_TERMINAL_CALLS"),
    ("darwin terminal: rebind called directly", DT, replace(
        TERMINAL_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_darwin_evidence_rebind (&expected, uuid,"
        " old_uuid, object, &rebuilt);\n" + TERMINAL_SHAPE_LINES),
     "E_TERMINAL_CALLS"),
    ("darwin terminal: compare before the shape", DT,
     move_before(TERMINAL_COMPARE_LINES, TERMINAL_SHAPE_LINES),
     "E_TERMINAL_ORDER"),
    ("darwin terminal: shape before the provenance load", DT,
     move_before(TERMINAL_SHAPE_LINES, TERMINAL_PROVENANCE_LINES),
     "E_TERMINAL_ORDER"),
    ("darwin terminal: cleanup executed", DT, replace(
        TERMINAL_FINAL_PERSISTED_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_restore_darwin_selected_cleanup_execute"
        " (&resolver, &directory, lease, uuid, &evidence, operation_uuid,"
        " replacement, &old_main, &new_main, size);\n"
        + TERMINAL_FINAL_PERSISTED_LINES), "E_TERMINAL_MUTATES"),
    ("darwin terminal: store begin added", DT, replace(
        TERMINAL_FINAL_PERSISTED_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_policy_store_graph_restore_selected_finalize_begin"
        " (policy, row, &before, &after, &result);\n"
        + TERMINAL_FINAL_PERSISTED_LINES), "E_TERMINAL_MUTATES"),
    ("darwin terminal: journal attempt begun", DT, replace(
        TERMINAL_FINAL_PERSISTED_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_offline_restore_journal_begin_attempt (&journal,"
        " journal.selected_graph_id, op);\n"
        + TERMINAL_FINAL_PERSISTED_LINES), "E_TERMINAL_MUTATES"),
    ("darwin terminal: DUAL accepted", DT, replace(
        TERMINAL_SHAPE_TEST,
        "shape == WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID"),
     "E_TERMINAL_SHAPE"),
    ("darwin terminal: DUAL named", DT, replace(
        TERMINAL_SHAPE_TEST,
        TERMINAL_SHAPE_TEST
        + "\n      && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL"),
     "E_TERMINAL_SHAPE"),
    ("darwin terminal: final persisted check dropped", DT,
     replace(TERMINAL_FINAL_PERSISTED_LINES, ""), "E_TERMINAL_PERSISTED"),
    ("darwin terminal: persisted check before the compare", DT,
     move_before(TERMINAL_FINAL_PERSISTED_LINES, TERMINAL_COMPARE_LINES),
     "E_TERMINAL_PERSISTED"),
    ("darwin terminal: early row-evidence refusal dropped", DT,
     replace(TERMINAL_EARLY_EVIDENCE_LINES, ""),
     "E_TERMINAL_EARLY_EVIDENCE"),
    ("darwin terminal: row-evidence refusal after the resolver open", DT,
     move_before(TERMINAL_RESOLVER_OPEN_LINES, TERMINAL_EARLY_EVIDENCE_LINES),
     "E_TERMINAL_EARLY_EVIDENCE"),
    ("darwin terminal: quiesce_missing_closed dropped", DT, replace(
        "      rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed"
        " (runtime,\n"
        "              &key, drain_timeout_us, &quiescence);\n",
        "      rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("darwin terminal: check_runtime dropped", DT, replace(
        "    rc = check_runtime (runtime, &key);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("promote: Apple arm dropped", PR, drop_apple_arm, "E_PROMOTE_ARMS"),
    ("promote: Darwin step called twice", PR, replace(
        "             expected_revision, drain_timeout_us, out_committed);\n"
        "#else",
        "             expected_revision, drain_timeout_us, out_committed);\n"
        "  rc = darwin_promote_selected (policy, fact_root, runtime,"
        " operation_uuid, expected_revision, drain_timeout_us,"
        " out_committed);\n#else"), "E_PROMOTE_ROUTE"),
    ("promote: Apple arm calls the store promotion", PR, replace(
        "             expected_revision, drain_timeout_us, out_committed);\n"
        "#else",
        "             expected_revision, drain_timeout_us, out_committed);\n"
        "  rc = wyl_policy_store_graph_restore_selected_promote_with_effect"
        " (policy, row, &before, darwin_promote_effect, &effect,"
        " &result);\n#else"), "E_PROMOTE_DIRECT"),
    ("promote: Linux arm calls the Darwin step", PR, replace(
        "  return rc;\n#endif",
        "  rc = darwin_promote_selected (policy, fact_root, runtime,"
        " operation_uuid, expected_revision, drain_timeout_us,"
        " out_committed);\n  return rc;\n#endif"), "E_PROMOTE_LEAK"),
    ("promote: Linux arm passes the Darwin effect", PR, replace(
        "          (policy, row, &before, promote_selected_terminal_effect,",
        "          (policy, row, &before, darwin_promote_effect,"),
     "E_PROMOTE_LEAK"),
    ("darwin promote: provenance load dropped", DP,
     replace(PROMOTE_PROVENANCE_LINES, ""), "E_ROUTE_HELPER"),
    ("darwin promote: ACTIVE loader swapped in", DP, replace(
        "    rc = graph_selected_provenance_load (policy,",
        "    rc = graph_provenance_load (policy,"), "E_ROUTE_HELPER"),
    ("darwin promote: ACTIVE loader beside", DP, replace(
        PROMOTE_PROVENANCE_LINES,
        PROMOTE_PROVENANCE_LINES
        + "  if (rc == WYRELOG_E_OK)\n"
        "    rc = graph_provenance_load (policy, &journal, row,"
        " &provenance);\n"), "E_PROMOTE_CALLS"),
    ("darwin promote: rebind called directly", DP, replace(
        PROMOTE_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_darwin_evidence_rebind (&expected, uuid,"
        " old_uuid, object, &rebuilt);\n" + PROMOTE_SHAPE_LINES),
     "E_PROMOTE_CALLS"),
    ("darwin promote: shape dropped", DP,
     replace(PROMOTE_SHAPE_LINES, ""), "E_PROMOTE_CALLS"),
    ("darwin promote: shape after the store promotion", DP,
     move_before(PROMOTE_SHAPE_LINES, PROMOTE_UNSEAL_LINES),
     "E_PROMOTE_ORDER"),
    ("darwin promote: recheck dropped", DP,
     replace(PROMOTE_RECHECK_LINES, ""), "E_ROUTE_HELPER"),
    ("darwin promote: recheck before the shape", DP,
     move_before(PROMOTE_RECHECK_LINES, PROMOTE_SHAPE_LINES),
     "E_PROMOTE_PERSISTED"),
    ("darwin promote: recheck after the store promotion", DP,
     move_before(PROMOTE_RECHECK_LINES, PROMOTE_UNSEAL_LINES),
     "E_PROMOTE_PERSISTED"),
    ("darwin promote: Linux effect passed", DP, replace(
        "darwin_promote_effect, &effect,",
        "promote_selected_terminal_effect, &effect,"), "E_PROMOTE_EFFECT"),
    ("darwin promote: current row passed", DP, replace(
        "          (policy, row, &before, darwin_promote_effect,",
        "          (policy, current, &before, darwin_promote_effect,"),
     "E_PROMOTE_EFFECT"),
    ("darwin promote: DUAL accepted", DP, replace(
        TERMINAL_SHAPE_TEST,
        "shape == WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID"),
     "E_PROMOTE_SHAPE"),
    ("darwin promote: DUAL named", DP, replace(
        TERMINAL_SHAPE_TEST,
        TERMINAL_SHAPE_TEST
        + "\n      && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL"),
     "E_PROMOTE_SHAPE"),
    ("darwin promote: early row-evidence refusal dropped", DP,
     replace(FINALIZE_EARLY_EVIDENCE_LINES, ""), "E_PROMOTE_EARLY_EVIDENCE"),
    ("darwin promote: row-evidence refusal after the resolver open", DP,
     move_before(FINALIZE_RESOLVER_OPEN_LINES, FINALIZE_EARLY_EVIDENCE_LINES),
     "E_PROMOTE_EARLY_EVIDENCE"),
    ("darwin promote: cleanup executed", DP, replace(
        PROMOTE_RECHECK_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_restore_darwin_selected_cleanup_execute"
        " (&resolver, &directory, lease, uuid, &evidence, operation_uuid,"
        " replacement, &old_main, &new_main, size);\n"
        + PROMOTE_RECHECK_LINES), "E_PROMOTE_CALLS"),
    ("darwin promote: FINALIZE completion added", DP, replace(
        PROMOTE_RECHECK_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_policy_store_graph_restore_selected_finalize_with_effect"
        " (policy, row, &before, &after, darwin_finalize_effect, &effect,"
        " &result);\n" + PROMOTE_RECHECK_LINES), "E_PROMOTE_CALLS"),
    ("darwin promote: compare added", DP, replace(
        PROMOTE_RECHECK_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_directory_compare_darwin_replacement_evidence"
        " (&directory, row->replacement_uuid, &identity, size, checksum,"
        " &expected);\n" + PROMOTE_RECHECK_LINES), "E_PROMOTE_CALLS"),
    ("darwin promote: unseal dropped", DP, replace(
        "restore_unseal_graph (", "restore_keep_sealed ("), "E_ROUTE_HELPER"),
    ("darwin promote: receipt lookup dropped", DP, replace(
        "wyl_policy_store_offline_restore_receipt_lookup (",
        "receipt_unread ("), "E_ROUTE_HELPER"),
    ("darwin promote: unseal before the store promotion", DP, replace(
        PROMOTE_STORE_LINES,
        "  rc = restore_unseal_graph (policy, fact_root, runtime, tenant,"
        " graph, drain_timeout_us);\n" + PROMOTE_STORE_LINES),
     "E_PROMOTE_ORDER"),
    ("promote effect: compare dropped", PE,
     replace(PROMOTE_EFFECT_COMPARE_LINES, ""), "E_ROUTE_HELPER"),
    ("promote effect: shape dropped", PE,
     replace(PROMOTE_EFFECT_SHAPE_LINES, ""), "E_ROUTE_HELPER"),
    ("promote effect: Linux shape swapped in", PE, replace(
        "          (wyl_fact_graph_restore_darwin_selected_cleanup_shape_open"
        "\n",
        "          (wyl_fact_graph_restore_selected_cleanup_shape_open\n"),
     "E_ROUTE_HELPER"),
    ("promote effect: check_runtime dropped", PE, replace(
        "    rc = check_runtime (effect->runtime, effect->key);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
    ("promote effect: compare before the shape", PE,
     move_before(PROMOTE_EFFECT_COMPARE_LINES, PROMOTE_EFFECT_SHAPE_LINES),
     "E_PROMOTE_EFFECT_ORDER"),
    ("promote effect: evidence check dropped", PE,
     replace(PROMOTE_EFFECT_EVIDENCE_LINES, ""),
     "E_PROMOTE_EFFECT_EVIDENCE"),
    ("promote effect: row reloaded", PE, replace(
        PROMOTE_EFFECT_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_policy_store_graph_restore_replacement_load (policy,"
        " operation_uuid, &row);\n" + PROMOTE_EFFECT_SHAPE_LINES),
     "E_PROMOTE_EFFECT_REENTERS"),
    ("promote effect: selected provenance reloaded", PE, replace(
        PROMOTE_EFFECT_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = graph_selected_provenance_load (policy, journal, current,"
        " &provenance);\n" + PROMOTE_EFFECT_SHAPE_LINES),
     "E_PROMOTE_EFFECT_REENTERS"),
    ("promote effect: DUAL accepted", PE, replace(
        TERMINAL_SHAPE_TEST,
        "shape == WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID"),
     "E_PROMOTE_SHAPE"),
    ("promote effect: cleanup executed beside the shape", PE, replace(
        PROMOTE_EFFECT_SHAPE_LINES,
        PROMOTE_EFFECT_SHAPE_LINES
        + "  if (rc == WYRELOG_E_OK)\n"
        "    rc = wyl_fact_graph_restore_darwin_selected_cleanup_execute"
        " (effect->resolver, effect->directory, effect->lease, uuid,"
        " &evidence, operation_uuid, replacement, &old_main, &new_main,"
        " size);\n"), "E_PROMOTE_EFFECT_MUTATES"),
    ("promote effect: check_finalized_persisted called", PE, replace(
        PROMOTE_EFFECT_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = check_finalized_persisted (policy, operation_uuid, encoded,"
        " current, journal);\n" + PROMOTE_EFFECT_SHAPE_LINES),
     "E_PROMOTE_EFFECT_REENTERS"),
    ("promote effect: check_policy called", PE, replace(
        PROMOTE_EFFECT_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = check_policy (policy, journal, current);\n"
        + PROMOTE_EFFECT_SHAPE_LINES), "E_PROMOTE_EFFECT_REENTERS"),
    ("promote effect: ACTIVE provenance loaded", PE, replace(
        PROMOTE_EFFECT_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = graph_provenance_load (policy, journal, current,"
        " &provenance);\n" + PROMOTE_EFFECT_SHAPE_LINES),
     "E_PROMOTE_EFFECT_REENTERS"),
    ("promote effect: unseal called", PE, replace(
        PROMOTE_EFFECT_SHAPE_LINES,
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = restore_unseal_graph (policy, fact_root, runtime, tenant,"
        " graph, drain_timeout_us);\n" + PROMOTE_EFFECT_SHAPE_LINES),
     "E_PROMOTE_EFFECT_REENTERS"),
    ("promote effect: local helper reads the store", PE,
     effect_peek(EFFECT_PEEK_STORE), "E_PROMOTE_EFFECT_REENTERS"),
    ("promote effect: local helper reads the store transitively", PE,
     effect_peek(EFFECT_PEEK_TRANSITIVE), "E_PROMOTE_EFFECT_REENTERS"),
    ("published: Apple arm dropped", PP, drop_apple_arm, "E_PUBLISHED_ARMS"),
    ("published: Apple arm calls the promotion instead", PP, replace(
        "  return darwin_published_prove_terminal (policy, fact_root,"
        " runtime,\n",
        "  return darwin_promote_selected (policy, fact_root, runtime,\n"),
     "E_PUBLISHED_ROUTE"),
    ("published: Apple arm looks up the receipt", PP, replace(
        PUBLISHED_ARM_CALL,
        "             finalized, drain_timeout_us, out_committed);\n"
        "  rc = wyl_policy_store_offline_restore_receipt_lookup (policy,"
        " finalized->operation_uuid, &receipt);\n#else"),
     "E_PUBLISHED_DIRECT"),
    ("published: Apple arm unseals", PP, replace(
        PUBLISHED_ARM_CALL,
        "             finalized, drain_timeout_us, out_committed);\n"
        "  rc = restore_unseal_graph (policy, fact_root, runtime, tenant,"
        " graph, drain_timeout_us);\n#else"), "E_PUBLISHED_DIRECT"),
    ("published: Linux arm calls the Darwin proof", PP, replace(
        "  return rc;\n#endif",
        "  rc = darwin_published_prove_terminal (policy, fact_root, runtime,"
        " finalized, drain_timeout_us, out_committed);\n"
        "  return rc;\n#endif"), "E_PUBLISHED_LEAK"),
    ("darwin published: receipt lookup dropped", DB, replace(
        "wyl_policy_store_offline_restore_receipt_lookup (",
        "receipt_unread ("), "E_ROUTE_HELPER"),
    ("darwin published: handoff mark dropped", DB, replace(
        "wyl_fact_offline_restore_journal_mark_lifecycle_handoff (",
        "journal_left_unhanded ("), "E_ROUTE_HELPER"),
    ("darwin published: graph authority read dropped", DB, replace(
        "wyl_policy_store_read_graph_authority (",
        "authority_unread ("), "E_ROUTE_HELPER"),
    ("darwin published: unseal dropped", DB, replace(
        "restore_unseal_graph (", "restore_keep_sealed ("), "E_ROUTE_HELPER"),
    ("darwin published: store published proof added", DB, published_added(
        "wyl_policy_store_graph_restore_published_prove (policy, &record,"
        " &published)"), "E_PUBLISHED_CALLS"),
    ("darwin published: row loaded", DB, published_added(
        "wyl_policy_store_graph_restore_replacement_load (policy,"
        " finalized->operation_uuid, &row)"), "E_PUBLISHED_CALLS"),
    ("darwin published: journal loaded", DB, published_added(
        "wyl_fact_offline_restore_journal_store_load (policy,"
        " finalized->operation_uuid, &journal)"), "E_PUBLISHED_CALLS"),
    ("darwin published: selected provenance loaded", DB, published_added(
        "graph_selected_provenance_load (policy, finalized, row,"
        " &provenance)"), "E_PUBLISHED_CALLS"),
    ("darwin published: TERMINAL proved", DB, published_added(
        "wyl_fact_graph_restore_darwin_selected_cleanup_shape_open"
        " (&resolver, &directory, lease, uuid, &evidence, operation_uuid,"
        " replacement, &old_main, &new_main, size, &shape)"),
     "E_PUBLISHED_CALLS"),
    ("darwin published: bytes compared", DB, published_added(
        "wyl_fact_graph_directory_compare_darwin_replacement_evidence"
        " (&directory, replacement, &identity, size, checksum, &expected)"),
     "E_PUBLISHED_CALLS"),
    ("darwin published: store promotion added", DB, published_added(
        "wyl_policy_store_graph_restore_selected_promote_with_effect"
        " (policy, row, &before, darwin_promote_effect, &effect, &result)"),
     "E_PUBLISHED_MUTATES"),
    ("darwin published: FINALIZED predicate dropped", DB,
     replace(PUBLISHED_PREDICATE_LINES, ""), "E_PUBLISHED_FINALIZED"),
    ("darwin published: FINALIZED predicate after the lookup", DB,
     move_before(PUBLISHED_PREDICATE_LINES, PUBLISHED_NO_RECEIPT_LINES),
     "E_PUBLISHED_FINALIZED"),
    ("darwin published: missing receipt not refused", DB,
     replace(PUBLISHED_NO_RECEIPT_LINES, ""), "E_PUBLISHED_NO_RECEIPT"),
    ("darwin published: unseal before the marks", DB,
     move_before(PUBLISHED_UNSEAL_LINES, PUBLISHED_MARK_LINES),
     "E_PUBLISHED_ORDER"),
    ("darwin published: authority read after the unseal", DB,
     move_before(PUBLISHED_AUTHORITY_LINES,
                 "  if (rc != WYRELOG_E_OK)\n"
                 "    wyl_fact_offline_restore_journal_clear"
                 " (out_committed);\n"), "E_PUBLISHED_ORDER"),
)


def self_test() -> None:
    check_source("".join(POSITIVE.values()))
    for label, target, transform, expected in MUTANTS:
        mutated = transform(POSITIVE[target])
        if mutated == POSITIVE[target]:
            raise ContractError(f"self-test mutant did not apply: {label}")
        source = "".join(
            mutated if name == target else text
            for name, text in POSITIVE.items()
        )
        try:
            check_source(source)
        except ContractError as error:
            if not str(error).startswith(expected + ":"):
                raise ContractError(
                    f"self-test mutant failed for another reason: {label}:"
                    f" {error}"
                ) from error
            continue
        raise ContractError(f"self-test mutant survived: {label}")
    # Forward declarations ahead of the definitions are skipped: the real
    # bodies still pass, and a compare dropped from the real body still
    # fails.
    declared = TERMINAL_DECLARATIONS + "".join(POSITIVE.values())
    check_source(declared)
    dropped = TERMINAL_DECLARATIONS + "".join(
        text.replace(TERMINAL_COMPARE_LINES, "") if name == DT else text
        for name, text in POSITIVE.items()
    )
    if dropped == declared:
        raise ContractError("self-test mutant did not apply: declared compare")
    try:
        check_source(dropped)
    except ContractError as error:
        if not str(error).startswith("E_TERMINAL_CALLS:"):
            raise ContractError(
                "self-test mutant failed for another reason: declared"
                f" compare: {error}"
            ) from error
    else:
        raise ContractError("self-test mutant survived: declared compare")
    # The Darwin promotion's forward declaration is skipped as well: the
    # real bodies still pass, and the effect's compare dropped still fails.
    declared = PROMOTE_DECLARATIONS + "".join(POSITIVE.values())
    check_source(declared)
    dropped = PROMOTE_DECLARATIONS + "".join(
        text.replace(PROMOTE_EFFECT_COMPARE_LINES, "") if name == PE else text
        for name, text in POSITIVE.items()
    )
    if dropped == declared:
        raise ContractError(
            "self-test mutant did not apply: declared promote compare"
        )
    try:
        check_source(dropped)
    except ContractError as error:
        if not str(error).startswith("E_ROUTE_HELPER:"):
            raise ContractError(
                "self-test mutant failed for another reason: declared"
                f" promote compare: {error}"
            ) from error
    else:
        raise ContractError(
            "self-test mutant survived: declared promote compare"
        )
    # The Darwin published proof's forward declaration is skipped too: the
    # real bodies still pass, and the unseal dropped from its real body
    # still fails.
    declared = PUBLISHED_DECLARATIONS + "".join(POSITIVE.values())
    check_source(declared)
    dropped = PUBLISHED_DECLARATIONS + "".join(
        text.replace("restore_unseal_graph (", "restore_keep_sealed (")
        if name == DB else text
        for name, text in POSITIVE.items()
    )
    if dropped == declared:
        raise ContractError(
            "self-test mutant did not apply: declared published unseal"
        )
    try:
        check_source(dropped)
    except ContractError as error:
        if not str(error).startswith("E_ROUTE_HELPER:"):
            raise ContractError(
                "self-test mutant failed for another reason: declared"
                f" published unseal: {error}"
            ) from error
    else:
        raise ContractError(
            "self-test mutant survived: declared published unseal"
        )


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--self-test":
        try:
            self_test()
        except ContractError as error:
            print(f"darwin-restore-bind-wiring self-test: {error}",
                  file=sys.stderr)
            return 1
        print("darwin-restore-bind-wiring self-test: OK")
        return 0
    if len(argv) != 2:
        print(f"usage: {argv[0]} [--self-test] SOURCE_ROOT", file=sys.stderr)
        return 2
    try:
        check_tree(Path(argv[1]))
    except ContractError as error:
        print(f"darwin-restore-bind-wiring: {error}", file=sys.stderr)
        return 1
    print("darwin-restore-bind-wiring: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

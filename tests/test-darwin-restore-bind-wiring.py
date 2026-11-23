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

function_body counts braces without regard to string or character literals;
none of the pinned functions holds a brace literal today.

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
    """The brace-delimited body of the definition of ``name``."""
    match = re.search(
        r"^[A-Za-z_][\w \t*]*\n" + re.escape(name) + r"\s*\(", source, re.M
    )
    if match is None:
        raise ContractError(f"E_NO_FUNCTION: {name} is not defined")
    start = source.index("{", match.end())
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


def check_source(source: str) -> None:
    source = strip_comments(source)
    for rule in ARM_RULES:
        check_arm_rule(source, rule)
    for route in ROUTE_RULES:
        check_route_rule(source, route)
    check_companion_rules(source)
    check_select_rules(source)
    check_finalize_rules(source)


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

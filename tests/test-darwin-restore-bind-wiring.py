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


def check_source(source: str) -> None:
    source = strip_comments(source)
    for rule in ARM_RULES:
        check_arm_rule(source, rule)
    for route in ROUTE_RULES:
        check_route_rule(source, route)
    check_companion_rules(source)


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
    ("darwin effect: shape dropped", G, replace(
        "    rc = darwin_post_publish_shape (effect->resolver,"
        " effect->directory,\n"
        "            effect->lease, effect->journal, current,"
        " effect->provenance);\n",
        "    rc = WYRELOG_E_OK;\n"), "E_ROUTE_HELPER"),
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

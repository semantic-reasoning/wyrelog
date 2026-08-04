#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove the WylSession lifecycle word is only ever touched atomically.

Issue #758: management liveness checks and the coordinator handoff authorize
gates used to read the non-atomic WylSession.state while an async logout wrote
it, a C data race and a TOCTOU that could durably write policy authority after
logout had already won.  The fix makes .state a single atomic word and routes
every reader and writer through the sanctioned accessors so each management
execution linearizes to (a) mutation-before-logout or (b) logout-wins with zero
durable work.

This guard is the completeness backstop.  Source-wide across the daemon and the
three service-credential operation coordinators plus the session core, it fails
closed when:

  * any code reads or writes a WylSession lifecycle field raw (``session->state``
    / ``self->state`` / ``live->state`` / ``service_session->state``) outside the
    two sanctioned accessor DEFINITIONS in the layout header, or
  * the atomic accessors stop using g_atomic, or the field stops being the
    atomic ``volatile gint`` word, or
  * management_session_matches_live stops delegating to the coherent liveness
    primitive, or a coordinator ``*_session_is_active_human`` predicate stops
    routing its decisive state read through the atomic load accessor.

Any NEW raw read therefore fails the check.  The guard carries its own negative
fixtures so it is provably sensitive to the regression it freezes.
"""

import re
import sys
from pathlib import Path


# Sanctioned accessor definitions -- the ONLY code allowed to name the raw
# lifecycle field.  They live in the layout header and use g_atomic.
LOAD_ACCESSOR = "wyl_session_state_load_private"
STORE_ACCESSOR = "wyl_session_state_store_private"
LIVENESS_PRIMITIVE = "wyl_session_liveness_check_private"
IS_ACTIVE_HUMAN = "wyl_session_is_active_human_private"

LAYOUT_HEADER = "wyrelog/wyl-session-layout-private.h"

# Files scanned for raw WylSession lifecycle access, mapped to the set of local
# identifier names that denote a WylSession in that translation unit.  These
# files each also hold unrelated ``->state`` fields on other structs (records,
# leases, tickets, policy writes); restricting to the WylSession spellings keeps
# the guard low-false-positive while still catching any new raw session read.
SCANNED_SOURCES = {
    "wyrelog/wyl-session.c": ("session", "self", "live"),
    "wyrelog/auth/service-session-private.c": ("session",),
    "wyrelog/auth/service-exchange-private.c": ("session",),
    "wyrelog/daemon/http.c": ("session", "self", "live", "service_session"),
    "wyrelog/auth/service-credential-operation-coordinator-execute-private.c":
        ("session",),
    "wyrelog/auth/service-credential-operation-coordinator-cancel-private.c":
        ("session",),
    "wyrelog/auth/service-credential-operation-coordinator-remediate-private.c":
        ("session",),
}

# Coordinator predicates whose decisive lifecycle read must be the atomic load.
COORDINATOR_ACTIVE_HUMAN = {
    "wyrelog/auth/service-credential-operation-coordinator-execute-private.c":
        "handoff_session_is_active_human",
    "wyrelog/auth/service-credential-operation-coordinator-cancel-private.c":
        "handoff_cancel_session_is_active_human",
    "wyrelog/auth/service-credential-operation-coordinator-remediate-private.c":
        "handoff_remediation_session_is_active_human",
}


def fail(message):
    raise SystemExit(f"session-state atomic-accessor guard: {message}")


def strip_comments_and_strings(text):
    """Blank out C comments and string/char literals, preserving newlines.

    Raw ``->state`` mentioned in a comment or literal must not trip the guard,
    and a raw read must not be able to hide inside one either.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c in "\"'":
            quote = c
            out.append(" ")
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                out.append(" ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def extract_function_body(text, name):
    """Return a balanced-brace C function body for structural assertions."""
    match = re.search(r"\n%s\s*\([^;]*?\)\s*\{" % re.escape(name), text,
                      re.DOTALL)
    if match is None:
        fail(f"missing sanctioned definition: {name}")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    fail(f"unterminated definition: {name}")


def raw_state_reads(code, identifiers):
    """Yield every raw WylSession lifecycle field access in stripped code."""
    idents = "|".join(re.escape(name) for name in identifiers)
    pattern = re.compile(r"\b(?:%s)\s*(?:->|\.)\s*state\b" % idents)
    return [match.group(0) for match in pattern.finditer(code)]


def scan_source(rel_path, text, identifiers):
    """Return raw-read violations for one scanned .c translation unit."""
    return raw_state_reads(strip_comments_and_strings(text), identifiers)


def check_layout_header(text):
    """The header may name the raw field ONLY inside the two accessors."""
    stripped = strip_comments_and_strings(text)
    if not re.search(r"\bvolatile\s+gint\s+state\s*;", stripped):
        fail("lifecycle word must be the atomic 'volatile gint state;'")
    load_body = extract_function_body(text, LOAD_ACCESSOR)
    store_body = extract_function_body(text, STORE_ACCESSOR)
    if "g_atomic_int_get" not in strip_comments_and_strings(load_body):
        fail(f"{LOAD_ACCESSOR} must load via g_atomic_int_get")
    if "g_atomic_int_set" not in strip_comments_and_strings(store_body):
        fail(f"{STORE_ACCESSOR} must store via g_atomic_int_set")
    # Every raw ``->state`` / ``.state`` in the header must be inside one of the
    # two accessor bodies; anything else is an unsanctioned raw touch.
    stripped_load = strip_comments_and_strings(load_body)
    stripped_store = strip_comments_and_strings(store_body)
    sanctioned = raw_state_reads(stripped_load, ("session",)) + \
        raw_state_reads(stripped_store, ("session",))
    total = raw_state_reads(stripped, ("session", "self", "live"))
    if len(total) != len(sanctioned):
        fail("layout header touches the lifecycle field outside the accessors")


def check_requirements(sources):
    http = sources["wyrelog/daemon/http.c"]
    matches_live = extract_function_body(http, "management_session_matches_live")
    if LIVENESS_PRIMITIVE not in strip_comments_and_strings(matches_live):
        fail("management_session_matches_live must delegate to "
             f"{LIVENESS_PRIMITIVE}")
    # The decisive gate must sit at/after the one-shot test checkpoint so a
    # logout can interleave; the primitive delegation must follow the seam.
    reauth = extract_function_body(http, "management_reauthorize_inside_write")
    stripped_reauth = strip_comments_and_strings(reauth)
    if "management_reauthorization_checkpoint" in stripped_reauth:
        if (stripped_reauth.index("management_reauthorization_checkpoint")
                > stripped_reauth.index("management_session_matches_live")):
            fail("decisive liveness gate must follow the reauthorization "
                 "checkpoint seam")

    primitive_src = sources["wyrelog/auth/service-session-private.c"]
    primitive = extract_function_body(primitive_src, LIVENESS_PRIMITIVE)
    if IS_ACTIVE_HUMAN not in strip_comments_and_strings(primitive):
        fail(f"{LIVENESS_PRIMITIVE} must gate on {IS_ACTIVE_HUMAN}")

    active_human = extract_function_body(primitive_src, IS_ACTIVE_HUMAN)
    if LOAD_ACCESSOR not in strip_comments_and_strings(active_human):
        fail(f"{IS_ACTIVE_HUMAN} must decide state via {LOAD_ACCESSOR}")

    for rel_path, predicate in COORDINATOR_ACTIVE_HUMAN.items():
        body = extract_function_body(sources[rel_path], predicate)
        if LOAD_ACCESSOR not in strip_comments_and_strings(body):
            fail(f"{predicate} must route its state read through "
                 f"{LOAD_ACCESSOR}")


def collect_violations(root, overrides=None):
    """Full guard pass over the real (or overridden) tree; returns messages."""
    overrides = overrides or {}
    sources = {}
    for rel_path in list(SCANNED_SOURCES) + [LAYOUT_HEADER,
            "wyrelog/wyl-session-private.h"]:
        if rel_path in overrides:
            sources[rel_path] = overrides[rel_path]
        else:
            sources[rel_path] = (Path(root) / rel_path).read_text(
                encoding="utf-8")

    violations = []
    for rel_path, identifiers in SCANNED_SOURCES.items():
        raw = scan_source(rel_path, sources[rel_path], identifiers)
        for hit in raw:
            violations.append(f"raw lifecycle access '{hit}' in {rel_path}")
    return sources, violations


def self_test(root):
    """Prove the guard is sensitive: a reintroduced raw read must be caught."""
    sources, violations = collect_violations(root)
    if violations:
        return  # real-tree failure is reported by main; skip self-test noise

    coordinator = ("wyrelog/auth/"
                   "service-credential-operation-coordinator-execute-private.c")
    original = sources[coordinator]
    mutant = original.replace(
        "wyl_session_state_load_private (session) == WYL_SESSION_STATE_ACTIVE",
        "session->state == WYL_SESSION_STATE_ACTIVE", 1)
    if mutant == original:
        fail("self-test could not construct a raw-read mutant")
    _, mutant_violations = collect_violations(root, {coordinator: mutant})
    if not mutant_violations:
        fail("self-test: guard failed to catch a reintroduced raw state read")

    # A raw read hidden in a comment must NOT trip the guard (no false alarm).
    commented = original.replace(
        "return WYL_IS_SESSION ((gpointer) session)",
        "/* never write session->state raw */\n"
        "  return WYL_IS_SESSION ((gpointer) session)", 1)
    if commented == original:
        fail("self-test could not construct a commented-read fixture")
    _, comment_violations = collect_violations(root, {coordinator: commented})
    if comment_violations:
        fail("self-test: guard false-positived on a commented raw read")

    # Management must keep delegating to the coherent primitive.
    http_path = "wyrelog/daemon/http.c"
    http = sources[http_path]
    unwrapped = http.replace(
        "  return wyl_session_liveness_check_private (session, session_id, "
        "actor,\n      expected_session_tenant, require_mfa);",
        "  return session != NULL;", 1)
    if unwrapped != http:
        try:
            check_requirements({**sources, http_path: unwrapped})
        except SystemExit:
            pass
        else:
            fail("self-test: guard accepted management bypass of the primitive")


def main():
    if len(sys.argv) != 2:
        fail("usage: test-session-state-atomic-accessor-structure.py <root>")
    root = Path(sys.argv[1])
    sources, violations = collect_violations(root)
    if violations:
        fail("; ".join(violations))
    check_layout_header(sources[LAYOUT_HEADER])
    check_requirements(sources)
    self_test(root)
    print("OK: WylSession lifecycle word is touched only through the atomic "
          "accessors")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Keep human refresh synchronous, context-bound, and atomically published."""

from pathlib import Path
import re
import sys


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\n{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if match is None:
        raise SystemExit(f"missing function: {name}")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise SystemExit(f"unterminated function: {name}")


def check(source: str) -> None:
    handler = function_body(source, "refresh_handler")
    classifier = function_body(source, "human_refresh_classify_locked")
    publishable = function_body(source, "human_refresh_candidates_publishable_at")
    access_prepare = function_body(source, "prepare_human_access_candidate")
    refresh_prepare = function_body(source, "prepare_human_refresh_candidate")
    latch = function_body(source, "human_refresh_test_latch_reach")
    context_new = function_body(source, "wyl_daemon_http_context_new")
    forbidden = (
        "WylHumanRefreshRotation", "WylHumanRefreshWaiter",
        "human_refresh_rotation_", "human_refresh_waiter_",
        "soup_server_message_pause", "soup_server_message_unpause",
        "g_main_context_iteration", "g_main_context_invoke",
        "g_idle_source_new", "g_timeout_source_new", "g_cond_wait",
        "issue_access_token (", "issue_refresh_token (",
    )
    for item in forbidden:
        if item in handler:
            raise SystemExit(f"refresh handler regained async/legacy path: {item}")
    for item in ("WylDaemonRefreshCheckpoint", "refresh_checkpoint"):
        if item in source:
            raise SystemExit(f"arbitrary refresh callback remains: {item}")
    for required in (
        "human_refresh_dispatch_owned (ctx)",
        "state->rotating = TRUE", "state->rotation_claim = claim.claim_epoch",
        "prepare_human_access_candidate", "prepare_human_refresh_candidate",
        "state == claim.predecessor_state", "state->epoch == predecessor_epoch",
        "state->rotation_claim == claim.claim_epoch",
        "ctx->auth_epoch == auth_epoch", "ctx->key_epoch == key_epoch",
        "human_refresh_candidates_publishable_at",
        "human_refresh_test_latch_reach (ctx",
    ):
        if required not in handler:
            raise SystemExit(f"refresh handler lost invariant: {required}")
    if handler.find("human_refresh_dispatch_owned (ctx)") > handler.find(
            "g_hash_table_lookup"):
        raise SystemExit("dispatch ownership gate must precede token lookup")
    if "g_main_context_ref_thread_default ()" not in context_new:
        raise SystemExit("HTTP context no longer captures its dispatch context")
    begin = handler.find("/* HUMAN_REFRESH_PUBLICATION_BEGIN */")
    end = handler.find("/* HUMAN_REFRESH_PUBLICATION_END */")
    if begin < 0 or end <= begin:
        raise SystemExit("handler lost publication markers")
    publication = handler[begin:end]
    if publication.count("g_hash_table_insert") != 2:
        raise SystemExit("successor pair must use exactly two unique inserts")
    if "g_hash_table_replace" in publication or "g_strdup" in publication:
        raise SystemExit("publication must steal preowned unique keys")
    for table in ("ctx->access_tokens_by_jti", "ctx->refresh_tokens_by_token"):
        if publication.count(f"!g_hash_table_contains ({table}") != 1:
            raise SystemExit(f"publication lost uniqueness precheck: {table}")
        if publication.count(f"g_hash_table_insert ({table}") != 1:
            raise SystemExit(f"publication lost unique insert: {table}")
    first = publication.find("g_hash_table_insert")
    suffix = publication[first:]
    calls = re.findall(r"\b([a-zA-Z_]\w*)\s*\(", suffix)
    if calls != ["g_hash_table_insert", "g_hash_table_insert",
                 "g_atomic_int_inc"]:
        raise SystemExit("publication performs fallible work after first insert")
    if re.search(r"\b(if|else|switch|goto|return)\b|\?", suffix):
        raise SystemExit("publication branches after first insert")
    for required in (
        "state->successor = committed", "state->consumed_at = committed_at",
        "state->consumed = TRUE", "state->rotating = FALSE",
        "state->rotation_claim = 0",
    ):
        if required not in publication:
            raise SystemExit(f"publication lost predecessor update: {required}")
    for required in (
        "committed_at >= refresh->state->issued_at",
        "committed_at < access->state->expires_at",
        "committed_at < refresh->state->expires_at",
    ):
        if required not in publishable:
            raise SystemExit(f"candidate freshness lost: {required}")
    for required in ("state->consumed",
                     "*result = wyl_human_refresh_result_ref (state->successor)"):
        if required not in classifier:
            raise SystemExit(f"classifier lost grace replay: {required}")
    if source.count('soup_server_add_handler (server, "/auth/refresh",') != 1:
        raise SystemExit("refresh route must be registered exactly once")
    for obsolete in forbidden[:10]:
        if obsolete in source:
            raise SystemExit(f"obsolete async machinery remains: {obsolete}")
    if "g_cond_wait_until" not in latch or "10 * G_USEC_PER_SEC" not in latch:
        raise SystemExit("typed latch lost its bounded wait")
    if "callback" in latch or "gpointer" in latch:
        raise SystemExit("typed latch regained an indirect callback")
    adjacency = (
        (access_prepare, "new_token_id_string (&jti);",
         "refresh_access_id_successes"),
        (access_prepare, "if (rc == WYRELOG_E_OK)",
         "refresh_jwt_sign_successes"),
        (refresh_prepare, "new_token_id_string (&candidate->token);",
         "refresh_token_id_successes"),
        (publication, "published = TRUE;", "refresh_publications"),
    )
    for body, operation, counter in adjacency:
        operation_at = body.find(operation)
        counter_at = body.find(counter, operation_at)
        if operation_at < 0 or counter_at < 0 or counter_at - operation_at > 220:
            raise SystemExit(f"primitive counter lost adjacency: {counter}")
    sign_at = access_prepare.find("rc = wyl_jwt_sign_hs256")
    attempt_at = access_prepare.rfind("refresh_jwt_sign_attempts", 0, sign_at)
    if sign_at < 0 or attempt_at < 0 or sign_at - attempt_at > 180:
        raise SystemExit("JWT attempt counter lost adjacency")
    refresh_free = function_body(source, "wyl_refresh_token_state_free")
    if "wyl_sensitive_string_free (state->token)" not in refresh_free:
        raise SystemExit("refresh token is not wiped")


def check_test_lifecycle(source: str) -> None:
    def require_once(text: str, needle: str, label: str) -> int:
        if text.count(needle) != 1:
            raise SystemExit(f"{label} must occur exactly once")
        return text.find(needle)

    names = (
        "check_concurrent_human_refresh_single_flight",
        "check_human_refresh_response_loss",
        "check_human_refresh_prepared_expiry",
        "check_human_refresh_shutdown_ordering",
    )
    for name in names:
        body = function_body(source, name)
        armed = body.find("wyl_daemon_http_arm_refresh_latch_for_test")
        cleanup = body.find("cleanup:")
        if armed < 0 or cleanup < armed:
            raise SystemExit(f"{name} lost its single cleanup path")
        if re.search(r"\breturn\b", body[armed:cleanup]):
            raise SystemExit(f"{name} returns directly after latch activation")
        tail = body[cleanup:]
        release = tail.find("wyl_daemon_http_release_refresh_latch_for_test")
        join = tail.find("g_thread_join")
        disarm = tail.find("wyl_daemon_http_disarm_refresh_latch_for_test")
        if release < 0 or join < release or disarm < join:
            raise SystemExit(f"{name} cleanup lost release/join/disarm ordering")
    response_loss = function_body(source, "check_human_refresh_response_loss")
    cleanup_marker = require_once(response_loss, "cleanup:",
                                  "response-loss cleanup label")
    loss_normal = response_loss[:cleanup_marker]
    loss_cleanup = response_loss[cleanup_marker:]
    normal_close = require_once(loss_normal, "drop_human_refresh_response",
                                "response-loss normal close")
    normal_close_flag = require_once(loss_normal, "drop_signaled = TRUE;",
                                     "response-loss normal close flag")
    normal_join = require_once(loss_normal, "g_thread_join (thread);",
                               "response-loss normal join")
    normal_join_flag = require_once(loss_normal, "thread_joined = TRUE;",
                                    "response-loss normal join flag")
    normal_release = require_once(
        loss_normal, "wyl_daemon_http_release_refresh_latch_for_test",
        "response-loss normal latch release")
    normal_release_flag = require_once(loss_normal, "latch_released = TRUE;",
                                       "response-loss normal release flag")
    normal_disarm = require_once(
        loss_normal, "wyl_daemon_http_disarm_refresh_latch_for_test",
        "response-loss normal disarm")
    if not (normal_close < normal_close_flag < normal_join < normal_join_flag
            < normal_release < normal_release_flag < normal_disarm):
        raise SystemExit("response-loss normal close/join/release ordering changed")
    cleanup_close = require_once(loss_cleanup, "drop_human_refresh_response",
                                 "response-loss cleanup close")
    cleanup_release = require_once(
        loss_cleanup, "wyl_daemon_http_release_refresh_latch_for_test",
        "response-loss cleanup release")
    cleanup_join = require_once(loss_cleanup, "g_thread_join (thread);",
                                "response-loss cleanup join")
    cleanup_disarm = require_once(
        loss_cleanup, "wyl_daemon_http_disarm_refresh_latch_for_test",
        "response-loss cleanup disarm")
    cleanup_cond = require_once(loss_cleanup, "g_cond_clear (&dropped.changed);",
                                "response-loss cleanup cond clear")
    cleanup_mutex = require_once(loss_cleanup, "g_mutex_clear (&dropped.mutex);",
                                 "response-loss cleanup mutex clear")
    cleanup_return = require_once(loss_cleanup, "return result;",
                                  "response-loss cleanup return")
    for guard in (
        "thread_started && !thread_joined && !drop_signaled",
        "latch_generation != 0 && !latch_released",
        "thread_started && !thread_joined",
        "latch_generation != 0", "sync_initialized",
    ):
        require_once(loss_cleanup, f"if ({guard})",
                     f"response-loss cleanup guard {guard}")
    if not (cleanup_close < cleanup_release < cleanup_join < cleanup_disarm
            < cleanup_cond < cleanup_mutex < cleanup_return):
        raise SystemExit("response-loss cleanup ordering changed")
    expiry = function_body(source, "check_human_refresh_prepared_expiry")
    expiry_cleanup = expiry[expiry.find("cleanup:"):]
    restore = expiry_cleanup.find(
        "wyl_daemon_http_set_refresh_clock_for_test (server, FALSE, 0)")
    if restore < expiry_cleanup.find("g_thread_join"):
        raise SystemExit("prepared-expiry cleanup restores clock before join")


def main() -> int:
    if len(sys.argv) != 3:
        return 2
    source = Path(sys.argv[1]).read_text(encoding="utf-8")
    test_source = Path(sys.argv[2]).read_text(encoding="utf-8")
    check(source)
    check_test_lifecycle(test_source)
    replacements = (
        ("gboolean dispatch_owned = human_refresh_dispatch_owned (ctx)",
         "gboolean dispatch_owned = TRUE"),
        ("state->rotation_claim == claim.claim_epoch", "TRUE"),
        ("state == claim.predecessor_state", "state != claim.predecessor_state"),
        ("committed_at < access->state->expires_at", "TRUE"),
        ("committed_at < refresh->state->expires_at", "TRUE"),
        ("g_hash_table_insert (ctx->access_tokens_by_jti",
         "g_hash_table_replace (ctx->access_tokens_by_jti"),
        ("state->successor = committed;", ""),
        ("wyl_sensitive_string_free (state->token);", "g_free (state->token);"),
    )
    for index, (old, new) in enumerate(replacements):
        mutant = source.replace(old, new, 1)
        if mutant == source:
            raise SystemExit(f"structural mutant anchor missing: {index}")
        try:
            check(mutant)
        except SystemExit:
            continue
        raise SystemExit(f"structural guard accepted forbidden mutant {index}")
    for index, injection in enumerate((
            "g_main_context_iteration (ctx->dispatch_context, FALSE);",
            "soup_server_message_pause (msg);",
            "g_idle_source_new ();"), start=len(replacements)):
        mutant = source.replace("(void) path;", f"(void) path;\n  {injection}", 1)
        try:
            check(mutant)
        except SystemExit:
            continue
        raise SystemExit(f"structural guard accepted async mutant {index}")
    test_mutations = (
        ("drop_human_refresh_response (&dropped);\n  drop_signaled = TRUE;",
         "drop_signaled = TRUE;"),
        ("drop_human_refresh_response (&dropped);\n  drop_signaled = TRUE;\n"
         "  g_thread_join (thread);",
         "g_thread_join (thread);\n  drop_human_refresh_response (&dropped);\n"
         "  drop_signaled = TRUE;"),
        ("drop_human_refresh_response (&dropped);\n    drop_signaled = TRUE;",
         "drop_signaled = TRUE;"),
        ("if (latch_generation != 0 && !latch_released)\n"
         "    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);\n"
         "  if (thread_started && !thread_joined)\n    g_thread_join (thread);",
         "if (thread_started && !thread_joined)\n    g_thread_join (thread);\n"
         "  if (latch_generation != 0 && !latch_released)\n"
         "    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);"),
        ("thread_started && !thread_joined && !drop_signaled",
         "thread_started && thread_joined && drop_signaled"),
        ("latch_generation != 0 && !latch_released",
         "latch_generation != 0 && latch_released"),
        ("thread_started && !thread_joined", "thread_started && thread_joined"),
        ("wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);",
         ""),
        ("thread_joined = TRUE;", "thread_joined = FALSE;"),
        ("latch_released = TRUE;", "latch_released = FALSE;"),
        ("wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);\n"
         "  latch_released = TRUE;", "latch_released = TRUE;"),
    )
    response_fixture = function_body(test_source,
                                     "check_human_refresh_response_loss")
    for index, (old, new) in enumerate(test_mutations):
        mutated_fixture = response_fixture.replace(old, new, 1)
        if mutated_fixture == response_fixture:
            raise SystemExit(f"test lifecycle mutant anchor missing: {index}")
        mutant = test_source.replace(response_fixture, mutated_fixture, 1)
        try:
            check_test_lifecycle(mutant)
        except SystemExit:
            continue
        raise SystemExit(f"lifecycle guard accepted forbidden mutant {index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

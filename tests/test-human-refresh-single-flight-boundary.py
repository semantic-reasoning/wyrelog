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


def without_c_comments(source: str) -> str:
    output = []
    index = 0
    state = "code"
    while index < len(source):
        pair = source[index:index + 2]
        char = source[index]
        if state == "code" and pair in ("//", "/*"):
            output.extend("  ")
            index += 2
            state = "line-comment" if pair == "//" else "block-comment"
            continue
        if state == "line-comment":
            output.append("\n" if char == "\n" else " ")
            index += 1
            if char == "\n":
                state = "code"
            continue
        if state == "block-comment":
            if pair == "*/":
                output.extend("  ")
                index += 2
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        output.append(char)
        index += 1
        if state in ("string", "char") and char == "\\":
            if index < len(source):
                output.append(source[index])
                index += 1
        elif state == "code" and char in ('"', "'"):
            state = "string" if char == '"' else "char"
        elif ((state == "string" and char == '"')
              or (state == "char" and char == "'")):
            state = "code"
    if state in ("block-comment", "string", "char"):
        raise SystemExit("unterminated C lexical construct")
    return "".join(output)


def check(source: str) -> None:
    handler = function_body(source, "refresh_handler")
    classifier = function_body(source, "human_refresh_classify_locked")
    publishable = function_body(source, "human_refresh_candidates_publishable_at")
    access_prepare = function_body(source, "prepare_human_access_candidate")
    refresh_prepare = function_body(source, "prepare_human_refresh_candidate")
    latch = function_body(source, "human_refresh_test_latch_reach")
    context_new = function_body(source, "wyl_daemon_http_context_new")
    nonzero_counter = function_body(source, "human_refresh_next_nonzero")
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
    if "value == 0" not in nonzero_counter or source.count(
            "human_refresh_next_nonzero (&ctx->next_refresh_epoch)") < 2:
        raise SystemExit("refresh epoch counter lost zero-skipping wrap handling")
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
    server_start = function_body(
        without_c_comments(source),
        "wyl_daemon_start_http_server_with_runtime")
    refresh_registrations = re.findall(
        r"\b(wyl_daemon_http_add_(?:exact|prefix|singleton)_handler|"
        r"soup_server_add_handler)\s*\(\s*server\s*,\s*"
        r'"/auth/refresh"\s*,\s*([a-zA-Z_]\w*)\s*,\s*'
        r"([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*\)",
        server_start,
    )
    if refresh_registrations != [
            ("wyl_daemon_http_add_exact_handler", "refresh_handler", "ctx",
             "NULL")]:
        raise SystemExit("refresh route must be registered exactly once")
    # The context owns one periodic source for service-auth expiry retirement.
    # It is not part of human refresh: keep the latter's old timeout machinery
    # forbidden everywhere else, while pinning the former to its single,
    # context-bound construction site.
    retirement_scheduler = "g_timeout_source_new_seconds (1)"
    if source.count("g_timeout_source_new") != 1 or \
            context_new.count(retirement_scheduler) != 1:
        raise SystemExit("service-auth retirement timeout escaped its context owner")
    for required in (
        "ctx->service_auth_retirement_source = " + retirement_scheduler,
        "service_auth_retirement_tick, wyl_daemon_http_context_ref (ctx)",
        "wyl_daemon_http_context_unref",
        "ctx->service_auth_retirement_source, ctx->dispatch_context",
    ):
        if required not in context_new:
            raise SystemExit("service-auth retirement scheduler lost ownership")
    # The policy-WRITE disconnect watch owns one cross-thread hop: GLib requires
    # a GSource be created, attached and destroyed on the thread owning its
    # GMainContext, so the lifecycle ops are marshalled onto the watcher thread.
    # It is not part of human refresh -- the handler ban above still rejects it
    # there -- so keep the blanket sweep for the rest and pin this one to its
    # single, watcher-context-bound marshalling site.
    code = without_c_comments(source)
    marshaller = function_body(code, "policy_write_watch_run_on_watcher")
    watcher_marshal = "g_main_context_invoke_full (ctx->policy_write_watcher_context,"
    if code.count("g_main_context_invoke") != 1 or \
            marshaller.count(watcher_marshal) != 1:
        raise SystemExit("policy-write watcher marshal escaped its single site")
    for obsolete in forbidden[:9]:
        if obsolete == "g_main_context_invoke":
            continue
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
    synchronous_helpers = (access_prepare, refresh_prepare, publishable,
                           classifier)
    hidden_async = (
        "g_main_context_", "g_source_", "g_idle_", "g_timeout_",
        "soup_", "GSocket", "GInputStream", "GOutputStream",
        "g_file_", "GTask", "callback", "g_cond_wait",
    )
    for helper in synchronous_helpers:
        for forbidden_call in hidden_async:
            if forbidden_call in helper:
                raise SystemExit(
                    f"synchronous prepare callgraph regained {forbidden_call}")
    for phase in (
        "WYL_DAEMON_REFRESH_BEFORE_CLAIM",
        "WYL_DAEMON_REFRESH_AFTER_CLAIM",
        "WYL_DAEMON_REFRESH_AFTER_ACCESS_PREPARE",
        "WYL_DAEMON_REFRESH_AFTER_REFRESH_PREPARE",
        "WYL_DAEMON_REFRESH_BEFORE_PUBLICATION",
        "WYL_DAEMON_REFRESH_AFTER_PUBLICATION",
    ):
        if handler.count(phase) != 1:
            raise SystemExit(f"fixed typed latch phase lost: {phase}")


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
    refresh_route = (
        '  wyl_daemon_http_add_exact_handler (server, "/auth/refresh", '
        "refresh_handler,\n      ctx, NULL);")
    replacements = (
        ("gboolean dispatch_owned = human_refresh_dispatch_owned (ctx)",
         "gboolean dispatch_owned = TRUE"),
        ("state->rotation_claim == claim.claim_epoch", "TRUE"),
        ("state == claim.predecessor_state", "state != claim.predecessor_state"),
        ("committed_at < access->state->expires_at", "TRUE"),
        ("committed_at < refresh->state->expires_at", "TRUE"),
        ("g_hash_table_insert (ctx->access_tokens_by_jti, access_key, access_state);",
         "g_hash_table_replace (ctx->access_tokens_by_jti, access_key, access_state);"),
        ("state->successor = committed;", ""),
        ("wyl_sensitive_string_free (state->token);", "g_free (state->token);"),
        ('wyl_daemon_http_add_exact_handler (server, "/auth/refresh",',
         'wyl_daemon_http_add_prefix_handler (server, "/auth/refresh",'),
        (refresh_route, refresh_route + "\n" + refresh_route),
        ('"/auth/refresh", refresh_handler,', '"/auth/refresh", login_handler,'),
        (refresh_route, ""),
        (refresh_route, "  /* disabled registration:\n"
         + refresh_route + "\n  */"),
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
    wrong_owner = (
        source.replace(refresh_route, "", 1)
        + "\nstatic void misplaced_refresh_route (void)\n{\n"
        + refresh_route + "\n}\n")
    try:
        check(wrong_owner)
    except SystemExit:
        pass
    else:
        raise SystemExit("structural guard accepted wrong-owner refresh route")
    for index, injection in enumerate((
            "g_main_context_iteration (ctx->dispatch_context, FALSE);",
            "soup_server_message_pause (msg);",
            "g_main_context_invoke (ctx->dispatch_context, NULL, NULL);",
            "g_idle_source_new ();"), start=len(replacements)):
        mutant = source.replace("(void) path;", f"(void) path;\n  {injection}", 1)
        try:
            check(mutant)
        except SystemExit:
            continue
        raise SystemExit(f"structural guard accepted async mutant {index}")
    # The watcher marshal is allowed exactly once and only inside its owning
    # helper: prove a second site and a relocated site are both still rejected.
    watcher_call = ("g_main_context_invoke_full (ctx->policy_write_watcher_context,"
                    "\n      G_PRIORITY_DEFAULT, cb, op, NULL);")
    if source.count(watcher_call) != 1:
        raise SystemExit("watcher marshal mutant anchor missing")
    for index, mutant in enumerate((
            source.replace(watcher_call, watcher_call + "\n  " + watcher_call, 1),
            source.replace(watcher_call, "", 1)
            + "\nstatic void misplaced_watch_marshal (void)\n{\n  "
            + watcher_call + "\n}\n")):
        try:
            check(mutant)
        except SystemExit:
            continue
        raise SystemExit(f"structural guard accepted watcher marshal mutant {index}")
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

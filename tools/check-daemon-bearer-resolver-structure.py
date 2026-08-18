#!/usr/bin/env python3
"""Keep bearer parsing singular and pin each reviewed service READ owner."""

import re
import sys
from pathlib import Path


def masked(text: str) -> str:
    pattern = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    return pattern.sub(lambda match: " " * len(match.group(0)), text)


def function_span(source: str, name: str, static_only: bool = False) -> tuple[int, int]:
    prefix = r"static\s+wyrelog_error_t\s+" if static_only else r"(?:static\s+)?\w[\w\s\*]*?\s+"
    matches = list(re.finditer(prefix + re.escape(name) + r"\s*\([^;]*?\)\s*\{", source, re.S))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one definition of {name}, found {len(matches)}")
    start = matches[0].start()
    brace = source.find("{", matches[0].start(), matches[0].end())
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return start, pos + 1
    raise ValueError(f"unterminated definition of {name}")


def block_end(source: str, brace: int) -> int:
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return pos + 1
    raise ValueError("unterminated block")


def check(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    source = masked(raw)
    errors: list[str] = []
    try:
        start, end = function_span(source, "resolve_bearer_session", True)
    except ValueError as exc:
        return [str(exc)]

    definitions = re.findall(
        r"(?:static\s+)?wyrelog_error_t\s+([A-Za-z_]\w*bearer\w*)\s*\([^;]*?\)\s*\{",
        source,
        re.S,
    )
    allowed = {"resolve_bearer_session", "wyl_daemon_http_resolve_bearer_for_test"}
    extras = sorted(set(definitions) - allowed)
    if extras:
        errors.append("service-only/copied bearer resolver definition: " + ", ".join(extras))
    if re.search(r"\bresolve_service_bearer\w*\b", source):
        errors.append("service bearer resolver alias/helper is forbidden")
    if re.search(r"#\s*define\s+\w+\s+resolve_bearer_session\b", source) or re.search(
        r"\w+\s*=\s*&?\s*resolve_bearer_session\b(?!\s*\()", source
    ):
        errors.append("resolve_bearer_session alias is forbidden")

    resolver_authority_symbols = (
        "wyl_service_auth_authority_acquire_read",
        "wyl_service_auth_read_lease_get_policy_store",
        "wyl_service_auth_registry_lookup",
        "wyl_service_auth_read_lease_release_terminal",
    )
    management_counts = {
        "service_principal_management_authorize_session": {
            "wyl_service_auth_authority_acquire_read": 1,
            "wyl_service_auth_read_lease_get_policy_store": 1,
            "management_target_is_active": 1,
            "wyl_service_auth_read_lease_release_terminal": 8,
        },
        "service_management_read_release": {
            "wyl_service_auth_read_lease_release_terminal": 1,
        },
        "service_credential_operation_status_execute": {
            "wyl_service_auth_read_lease_get_policy_store": 1,
        },
    }
    # The auth context destructor is the last-resort release for a lease that
    # reached request teardown still owned by the context: the resolver hands
    # one back only for POST /decide, and the decision authority is expected to
    # consume it first. Registering it keeps it inside the reviewed set with a
    # pinned count instead of leaving an unaccounted terminal release.
    #
    # Registered only when present, unlike the mandatory owners above, because
    # the self-test drives this checker with synthetic sources that define no
    # such destructor. It is also the one owner that cannot report a failed
    # release -- G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC fixes the void signature --
    # so it stays outside the discard-result prohibition further down, which
    # covers the owners that can report.
    if re.search(r"^wyl_daemon_auth_context_clear\s*\(", source, re.M):
        management_counts["wyl_daemon_auth_context_clear"] = {
            "wyl_service_auth_read_lease_release_terminal": 1,
        }
    management_edges = {
        "service_principal_management_authorize_session": {
            "service_principal_management_authorize": 1,
            "service_credential_issue_handler": 1,
            "service_credential_rotate_handler": 1,
            "service_credential_revoke_handler": 1,
            "service_principal_create_handler": 1,
            "service_principal_disable_handler": 1,
            "service_credential_operation_reconcile_execute": 1,
            "service_credential_operation_recover_execute": 1,
        },
        "service_principal_management_authorize": {
            "service_credential_list_handler": 1,
            "service_credential_get_handler": 1,
            "service_principal_list_handler": 1,
            "service_credential_operation_status_execute": 1,
        },
        "service_management_read_release": {
            "service_credential_list_handler": 4,
            "service_credential_get_handler": 2,
            "service_principal_list_handler": 1,
            "service_credential_operation_status_execute": 3,
        },
    }
    management_spans: dict[str, tuple[int, int]] = {}
    for name in management_counts:
        try:
            management_spans[name] = function_span(source, name)
        except ValueError as exc:
            errors.append(str(exc))
    for name, expected in management_counts.items():
        if name not in management_spans:
            continue
        owner_start, owner_end = management_spans[name]
        owner_body = source[owner_start:owner_end]
        for symbol, count in expected.items():
            occurrences = len(re.findall(r"\b" + symbol + r"\b", owner_body))
            calls = len(re.findall(r"\b" + symbol + r"\s*\(", owner_body))
            if calls != count or occurrences != calls:
                errors.append(
                    f"{name} must own exactly {count} direct {symbol} call(s); "
                    f"found {calls} calls/{occurrences} references"
                )
        if (
            "wyl_handle_get_policy_store" in owner_body
            or "wyl_service_auth_read_lease_free" in owner_body
            or re.search(
                r"\bwyl_service_auth_read_lease_release\s*\(", owner_body
            )
        ):
            errors.append(
                f"{name} must use only its pinned READ store and terminal release"
            )
    authorize_span = management_spans.get(
        "service_principal_management_authorize_session"
    )
    if authorize_span is not None:
        owner_start, owner_end = authorize_span
        acquire = source.find(
            "wyl_service_auth_authority_acquire_read", owner_start, owner_end
        )
        get_store = source.find(
            "wyl_service_auth_read_lease_get_policy_store", owner_start, owner_end
        )
        target_check = source.find(
            "management_target_is_active", owner_start, owner_end
        )
        release = source.find(
            "wyl_service_auth_read_lease_release_terminal", owner_start, owner_end
        )
        ordered = (acquire, get_store, target_check, release)
        if any(position < 0 for position in ordered) or list(ordered) != sorted(ordered):
            errors.append(
                "management authorization must acquire/get/check its pinned "
                "READ store before any terminal release"
            )
    # #759: the reviewed READ owners that acquire a service READ lease must
    # migrate every error path to the checked terminal release and never
    # discard its result, free an active lease, or read the pinned store after
    # finishing. acquire_read is already restricted (above) to exactly these
    # owners, so scoping the cleanup rules to them covers every acquire owner.
    acquire_owner_bodies: list[tuple[str, str]] = []
    if authorize_span is not None:
        acquire_owner_bodies.append(
            (
                "service_principal_management_authorize_session",
                source[authorize_span[0]:authorize_span[1]],
            )
        )
    acquire_owner_bodies.append(("resolve_bearer_session", source[start:end]))
    for owner_name, owner_body in acquire_owner_bodies:
        if re.search(
            r"\(\s*void\s*\)\s*wyl_service_auth_read_lease_release_terminal",
            owner_body,
        ):
            errors.append(
                f"{owner_name} must not discard the terminal READ release result"
            )
        if re.search(r"\bwyl_service_auth_read_lease_free\s*\(", owner_body):
            errors.append(
                f"{owner_name} must not free an acquired READ lease directly"
            )
        terminal_calls = list(
            re.finditer(
                r"\bwyl_service_auth_read_lease_release_terminal\s*\(", owner_body
            )
        )
        if not terminal_calls and "out_read_lease" not in owner_body:
            errors.append(
                f"{owner_name} acquires a READ lease without a terminal release "
                "or out_read_lease hand-off"
            )
        if terminal_calls:
            last_release = terminal_calls[-1].start()
            if re.search(
                r"\bwyl_service_auth_read_lease_get_policy_store\s*\(",
                owner_body[last_release:],
            ):
                errors.append(
                    f"{owner_name} must not read its pinned store after the "
                    "terminal release"
                )
    for callee, expected_owners in management_edges.items():
        pattern = r"\b" + re.escape(callee) + r"\s*\("
        calls = len(re.findall(pattern, source))
        occurrences = len(re.findall(r"\b" + re.escape(callee) + r"\b", source))
        expected_calls = 1 + sum(expected_owners.values())
        if calls != expected_calls or occurrences != calls:
            errors.append(
                f"{callee} call-site closure mismatch: expected {expected_calls} "
                f"definition/calls, found {calls} calls/{occurrences} references"
            )
        for owner, count in expected_owners.items():
            try:
                owner_start, owner_end = function_span(source, owner)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            actual = len(re.findall(pattern, source[owner_start:owner_end]))
            if actual != count:
                errors.append(
                    f"{owner} must call {callee} exactly {count} time(s); "
                    f"found {actual}"
                )
    status_span = management_spans.get(
        "service_credential_operation_status_execute"
    )
    if status_span is not None:
        owner_start, owner_end = status_span
        authorize = source.find(
            "service_principal_management_authorize", owner_start, owner_end
        )
        get_store = source.find(
            "wyl_service_auth_read_lease_get_policy_store", owner_start, owner_end
        )
        release = source.find(
            "service_management_read_release", owner_start, owner_end
        )
        ordered = (authorize, get_store, release)
        if any(position < 0 for position in ordered) or list(ordered) != sorted(ordered):
            errors.append(
                "operation status must authorize, consume the transferred READ "
                "store, then release it"
            )
    registry_test_span: tuple[int, int] | None = None
    try:
        registry_test_span = function_span(
            source, "wyl_daemon_http_lookup_service_registry_for_test"
        )
    except ValueError as exc:
        if "found 0" not in str(exc):
            errors.append(str(exc))
    if registry_test_span is not None:
        test_start, test_end = registry_test_span
        test_body = source[test_start:test_end]
        registry_occurrences = len(
            re.findall(r"\bwyl_service_auth_registry_lookup\b", test_body)
        )
        registry_calls = len(
            re.findall(r"\bwyl_service_auth_registry_lookup\s*\(", test_body)
        )
        if registry_calls != 1 or registry_occurrences != registry_calls:
            errors.append(
                "registry test seam must own exactly one direct registry lookup"
            )
    for symbol in resolver_authority_symbols:
        positions = [match.start() for match in re.finditer(r"\b" + symbol + r"\b", source)]
        resolver_positions = [pos for pos in positions if start <= pos < end]
        resolver_calls = [
            start + match.start()
            for match in re.finditer(
                r"\b" + symbol + r"\s*\(", source[start:end]
            )
        ]
        permitted_test_positions: list[int] = []
        if symbol == "wyl_service_auth_registry_lookup" and registry_test_span is not None:
            test_start, test_end = registry_test_span
            permitted_test_positions = [
                pos for pos in positions if test_start <= pos < test_end
            ]
        permitted_management_positions = [
            pos
            for pos in positions
            if any(
                owner_start <= pos < owner_end
                and symbol in management_counts[name]
                for name, (owner_start, owner_end) in management_spans.items()
            )
        ]
        if (
            len(resolver_positions) != 1
            or len(resolver_calls) != 1
            or len(permitted_test_positions) > 1
            or len(positions)
            != len(resolver_positions)
            + len(permitted_test_positions)
            + len(permitted_management_positions)
        ):
            errors.append(
                f"{symbol} must occur once in resolve_bearer_session and only in "
                "reviewed management READ owners"
            )
    body = source[start:end]
    if not re.search(r"registry_state\s*!=\s*WYL_SERVICE_AUTH_ACTIVE", body):
        errors.append("ACTIVE registry-state rejection is missing from resolve_bearer_session")
    service_match = re.search(
        r"if\s*\(\s*g_strcmp0\s*\(\s*claims\.auth_method\s*,[^)]*\)\s*==\s*0\s*\)\s*\{",
        body,
        re.S,
    )
    if service_match is None:
        errors.append("positive syntactic service credential branch is missing")
        service_start, service_end = start, start
    else:
        service_start = start + service_match.start()
        brace = start + body.find("{", service_match.start(), service_match.end())
        service_end = block_end(source, brace)
        service_body = source[service_start:service_end]
        if "wyl_handle_get_policy_store" in service_body:
            errors.append("service branch must use only the READ lease pinned store")

    ordered = (
        service_start,
        source.find("wyl_service_auth_authority_acquire_read", service_start, service_end),
        source.find("wyl_policy_store_tenant_exists", service_start, service_end),
        source.find("wyl_daemon_http_context_service_access_token_is_exact", service_start, service_end),
        source.find("wyl_daemon_http_ref_session", service_start, service_end),
        source.find("wyl_service_auth_registry_lookup", service_start, service_end),
        source.find("WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED", service_start, service_end),
        source.find("wyl_service_auth_read_lease_release_terminal", service_start, service_end),
    )
    if any(position < 0 for position in ordered[1:]) or list(ordered) != sorted(ordered):
        errors.append("service authority checks/publication/release ordering is invalid")
    terminal_positions = [
        match.start()
        for match in re.finditer(
            r"\bwyl_service_auth_read_lease_release_terminal\s*\(",
            source[service_start:service_end],
        )
    ]
    if len(terminal_positions) != 1:
        errors.append("terminal release must occur exactly once inside the service branch")
    if re.search(r"\bwyl_service_auth_read_lease_release\s*\(", source[service_start:service_end]):
        errors.append("resolver must use the exactly-once terminal release boundary")
    if "wyl_service_auth_read_lease_free" in source[service_start:service_end]:
        errors.append("resolver must not separately free a terminally consumed lease")
    human = source.find("claims.principal_state_at_issue", service_end, end)
    if human < service_end:
        errors.append("human bearer tail must follow the terminal service branch")
    elif "acquire_read" in source[service_end:end] or "WylServiceAuthReadLease" in source[service_end:end]:
        errors.append("human bearer tail must not acquire service READ authority")

    call_families = (
        (r"\bwyl_jwt_verify\w*\s*\(", "JWT verifier"),
        (r"\bwyl_jwt_parse_access_claims\w*\s*\(", "access-claims parser"),
    )
    for pattern, label in call_families:
        positions = [match.start() for match in re.finditer(pattern, source)]
        if len(positions) != 1 or not (start <= positions[0] < end):
            errors.append(f"{label} production call must occur exactly once inside resolve_bearer_session")

    try:
        wrapper_start, wrapper_end = function_span(
            source, "wyl_daemon_http_resolve_bearer_for_test"
        )
        wrapper = source[wrapper_start:wrapper_end]
        if len(re.findall(r"\bresolve_bearer_session\s*\(", wrapper)) != 1:
            errors.append("test wrapper must forward exactly once to resolve_bearer_session")
        if any(symbol in wrapper for symbol in resolver_authority_symbols):
            errors.append("test wrapper must not reproduce service resolution")
    except ValueError as exc:
        errors.append(str(exc))

    # The service READ lease the resolver keeps for the decision authority.
    #
    # An earlier revision guarded this on "retain_service_decision_authority"
    # and pinned a TRUE/FALSE retain argument at six resolve_bearer_session
    # call sites. Neither exists: the symbol appears nowhere in the source, so
    # the block never ran, and resolve_bearer_session takes no endpoint or
    # retain parameter at all -- it cannot decide per handler, and retains for
    # every service bearer. A check keyed on an interface that was never built
    # is worse than no check, because it reads as coverage.
    #
    # What the implementation actually guarantees, and what this pins instead:
    # the field is written in exactly one place, its address reaches exactly
    # one consumer, and it is terminally released in exactly one place. Those
    # three facts are what keep a retained lease from escaping the request.
    lease_field = "service_lease"
    if re.search(r"\bWylServiceAuthReadLease\s*\*\s*" + lease_field + r"\s*;",
                 source):
        assignments = [
            match.start()
            for match in re.finditer(r"\b" + lease_field + r"\s*=", source)
        ]
        if len(assignments) != 1:
            errors.append(
                f"{lease_field} must be assigned exactly once; found "
                f"{len(assignments)}"
            )
        elif not (start <= assignments[0] < end):
            errors.append(
                f"{lease_field} may only be assigned inside "
                "resolve_bearer_session"
            )
        consumers = list(
            re.finditer(r"&\s*\w+(?:\.|->)" + lease_field + r"\b", source)
        )
        release_owner = "wyl_daemon_auth_context_clear"
        try:
            release_start, release_end = function_span(source, release_owner)
        except ValueError as exc:
            errors.append(str(exc))
            release_start = release_end = -1
        for match in consumers:
            if release_start <= match.start() < release_end:
                continue
            preceding = source[max(0, match.start() - 400):match.start()]
            if "decide_authenticated_request" not in preceding:
                errors.append(
                    f"the address of {lease_field} may only reach "
                    "decide_authenticated_request or the auth context "
                    "destructor"
                )
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} HTTP_C", file=sys.stderr)
        return 2
    errors = check(Path(sys.argv[1]))
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

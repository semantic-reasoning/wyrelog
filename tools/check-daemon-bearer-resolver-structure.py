#!/usr/bin/env python3
"""Keep human and service bearer authentication in one resolver authority."""

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

    authority_symbols = (
        "wyl_service_auth_authority_acquire_read",
        "wyl_service_auth_read_lease_get_policy_store",
        "wyl_service_auth_registry_lookup",
    )
    for symbol in authority_symbols:
        positions = [match.start() for match in re.finditer(r"\b" + symbol + r"\b", source)]
        if len(positions) != 1 or not all(start <= pos < end for pos in positions):
            errors.append(f"{symbol} must occur exactly once inside resolve_bearer_session")
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
        for match in re.finditer(r"\bwyl_service_auth_read_lease_release_terminal\s*\(", source)
    ]
    if len(terminal_positions) != 1 or not (service_start <= terminal_positions[0] < service_end):
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
        if any(symbol in wrapper for symbol in authority_symbols):
            errors.append("test wrapper must not reproduce service resolution")
    except ValueError as exc:
        errors.append(str(exc))
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

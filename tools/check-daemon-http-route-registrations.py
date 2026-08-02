#!/usr/bin/env python3
"""Fail closed over every production daemon HTTP ownership registration."""

from dataclasses import dataclass
from pathlib import Path
import re
import sys
import tempfile


EXACT_API = "wyl_daemon_http_add_exact_handler"
RAW_API = "soup_server_add_handler"
SERVER_OWNER = "wyl_daemon_start_http_server_with_runtime"
EXACT_OWNER = "wyl_daemon_http_add_exact_handler"
FACT = "WYL_HAS_FACT_STORE"
AUDIT = "WYL_HAS_AUDIT"


@dataclass(frozen=True)
class RouteSpec:
    path: str
    callback: str
    data: str = "ctx"
    destroy: str = "NULL"
    feature: str | None = None


ROUTES = (
    RouteSpec("/healthz", "healthz_handler", "NULL"),
    RouteSpec("/readyz", "readyz_handler"),
    RouteSpec("/facts/status", "facts_status_handler"),
    RouteSpec("/facts/schema/register", "schema_register_handler"),
    RouteSpec("/facts", "facts_route_handler"),
    RouteSpec("/datalog", "datalog_query_handler"),
    RouteSpec("/profile/status", "profile_status_handler"),
    RouteSpec("/profile/events", "profile_events_handler"),
    RouteSpec("/auth/login", "login_handler"),
    RouteSpec("/auth/mfa/verify", "mfa_verify_handler"),
    RouteSpec("/auth/mfa/enroll/start", "mfa_enroll_start_handler"),
    RouteSpec("/auth/mfa/enroll/confirm", "mfa_enroll_confirm_handler"),
    RouteSpec("/auth/refresh", "refresh_handler"),
    RouteSpec("/auth/logout", "logout_handler"),
    RouteSpec("/tenants", "tenant_list_handler"),
    RouteSpec("/tenants/create", "tenant_create_handler"),
    RouteSpec("/tenants/seal", "tenant_seal_handler"),
    RouteSpec("/tenants/unseal", "tenant_unseal_handler"),
    RouteSpec("/tenants/delete", "tenant_delete_handler"),
    RouteSpec("/graphs/create", "graph_create_handler"),
    RouteSpec("/graphs/seal", "graph_seal_handler"),
    RouteSpec("/graphs", "graphs_list_handler"),
    RouteSpec("/decide", "decide_handler"),
    RouteSpec("/policy/permissions/grant", "policy_permission_grant_handler"),
    RouteSpec("/policy/permissions/revoke", "policy_permission_revoke_handler"),
    RouteSpec("/policy/permissions/transition",
              "policy_permission_transition_handler"),
    RouteSpec("/policy/roles/grant", "policy_role_grant_handler"),
    RouteSpec("/policy/roles/revoke", "policy_role_revoke_handler"),
    RouteSpec("/audit/events", "audit_events_handler"),
    RouteSpec("/service-principals", "service_principal_management_handler"),
    RouteSpec("/service-credentials", "service_credential_management_handler"),
    RouteSpec("/service-credential-operations",
              "service_credential_operation_status_handler", feature=FACT),
    RouteSpec("/service-credential-operations/reconcile",
              "service_credential_operation_reconcile_handler", feature=FACT),
    RouteSpec("/service-credential-operations/recover",
              "service_credential_operation_recover_handler", feature=FACT),
    RouteSpec("/auth/service-token", "service_token_exchange_http_handler",
              feature=AUDIT),
)

PREFIX_PATHS = {
    "/facts", "/datalog", "/service-principals", "/service-credentials",
}
ISSUE_719_EXACT_PATHS = {
    "/service-credential-operations",
    "/service-credential-operations/reconcile",
    "/service-credential-operations/recover",
    "/auth/service-token",
}
PENDING_RAW_SINGLETONS = {
    spec.path for spec in ROUTES
    if spec.path not in PREFIX_PATHS | ISSUE_719_EXACT_PATHS
}
EXPECTED_BY_PATH = {spec.path: spec for spec in ROUTES}


class GuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int


@dataclass(frozen=True)
class Registration:
    api: str
    path: str
    callback: str
    data: str
    destroy: str
    feature: str | None
    source: Path
    line: int


def lex(source: str) -> list[Token]:
    """Tokenize C while discarding comments and preprocessor directives."""
    tokens = []
    index = 0
    line = 1
    at_line_start = True
    length = len(source)
    while index < length:
        char = source[index]
        if char == "\n":
            line += 1
            index += 1
            at_line_start = True
            continue
        if char in " \t\r\f\v":
            index += 1
            continue
        if at_line_start and char == "#":
            while index < length:
                newline = source.find("\n", index)
                if newline < 0:
                    index = length
                    break
                physical = source[index:newline].rstrip()
                index = newline
                if not physical.endswith("\\"):
                    break
                line += 1
                index += 1
            continue
        at_line_start = False
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = length if newline < 0 else newline
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise GuardError("unterminated C comment")
            line += source.count("\n", index, end + 2)
            index = end + 2
            continue
        if char in {'"', "'"}:
            quote = char
            start = index
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                if source[index] == "\n":
                    raise GuardError("newline in C literal")
                index += 1
            else:
                raise GuardError("unterminated C literal")
            tokens.append(Token("string" if quote == '"' else "char",
                                source[start:index], line))
            continue
        if char.isalpha() or char == "_":
            start = index
            index += 1
            while index < length and (source[index].isalnum()
                                      or source[index] == "_"):
                index += 1
            tokens.append(Token("identifier", source[start:index], line))
            continue
        tokens.append(Token("punct", char, line))
        index += 1
    return tokens


def mates(tokens: list[Token]) -> dict[int, int]:
    stack = []
    result = {}
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index, token in enumerate(tokens):
        if token.value in pairs:
            stack.append((token.value, index))
        elif token.value in pairs.values():
            if not stack or pairs[stack[-1][0]] != token.value:
                raise GuardError("unbalanced C delimiters")
            _value, opening = stack.pop()
            result[opening] = index
            result[index] = opening
    if stack:
        raise GuardError("unbalanced C delimiters")
    return result


def functions(tokens: list[Token], pairing: dict[int, int]):
    result = []
    depth = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.value == "{":
            depth += 1
        elif token.value == "}":
            depth -= 1
        elif (depth == 0 and token.kind == "identifier"
              and index + 1 < len(tokens) and tokens[index + 1].value == "("):
            close = pairing[index + 1]
            if close + 1 < len(tokens) and tokens[close + 1].value == "{":
                body_end = pairing[close + 1]
                result.append((token.value, close + 2, body_end))
                index = body_end
        index += 1
    return result


def split_arguments(tokens: list[Token], opening: int, closing: int):
    arguments = []
    start = opening + 1
    depth = 0
    for index in range(start, closing):
        value = tokens[index].value
        if value in "([{":
            depth += 1
        elif value in ")]}":
            depth -= 1
        elif value == "," and depth == 0:
            arguments.append(tokens[start:index])
            start = index + 1
    arguments.append(tokens[start:closing])
    return arguments


def render(argument: list[Token]) -> str:
    return " ".join(token.value for token in argument)


def literal_path(argument: list[Token]) -> str:
    if len(argument) != 1 or argument[0].kind != "string":
        raise GuardError("registration path must be one literal string")
    raw = argument[0].value
    if not re.fullmatch(r'"/[A-Za-z0-9_{}:./-]*"', raw):
        raise GuardError(f"registration path is not a plain public path: {raw}")
    return raw[1:-1]


def feature_contexts(source: str) -> dict[int, str | None]:
    result = {}
    stack: list[str] = []
    for number, line in enumerate(source.splitlines(), 1):
        route_stack = [item for item in stack
                       if item != "WYL_HAS_DAEMON_HTTP"]
        result[number] = route_stack[-1] if len(route_stack) == 1 else (
            None if not route_stack else "complex")
        match = re.match(r"\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)",
                         line)
        if match is None:
            continue
        kind, tail = match.groups()
        tail = tail.strip()
        if kind == "ifdef":
            stack.append(tail)
        elif kind == "if":
            defined = re.fullmatch(r"defined\s*\(\s*(\w+)\s*\)", tail)
            stack.append(defined.group(1) if defined else "complex")
        elif kind == "ifndef":
            stack.append("complex")
        elif kind in {"else", "elif"}:
            if not stack:
                raise GuardError("unbalanced preprocessor conditional")
            stack[-1] = "complex"
        elif kind == "endif":
            if not stack:
                raise GuardError("unbalanced preprocessor conditional")
            stack.pop()
    if stack:
        raise GuardError("unbalanced preprocessor conditional")
    return result


def scan_source(path: Path) -> list[Registration]:
    source = path.read_text(encoding="utf-8")
    tokens = lex(source)
    pairing = mates(tokens)
    contexts = feature_contexts(source)
    registrations = []
    seen_calls = set()
    marker = re.compile(r"(?:soup_server_add_[A-Za-z0-9_]*handler|"
                        r"[A-Za-z_][A-Za-z0-9_]*add_exact_handler)\Z")
    for owner, start, end in functions(tokens, pairing):
        index = start
        while index < end:
            token = tokens[index]
            if (token.kind != "identifier" or marker.fullmatch(token.value)
                    is None or index + 1 >= end
                    or tokens[index + 1].value != "("):
                index += 1
                continue
            closing = pairing.get(index + 1)
            if closing is None or closing >= end:
                raise GuardError(f"unparsed registration call in {path}")
            seen_calls.add(index)
            arguments = split_arguments(tokens, index + 1, closing)
            if token.value == RAW_API and owner == EXACT_OWNER:
                expected = ["server", "canonical_path",
                            "wyl_daemon_http_exact_handler_dispatch", "exact",
                            "wyl_daemon_http_exact_handler_free"]
                if [render(argument) for argument in arguments] != expected:
                    raise GuardError("exact adapter internal Soup signature changed")
                index = closing + 1
                continue
            if token.value not in {RAW_API, EXACT_API}:
                raise GuardError(f"alternate ownership API: {token.value}")
            if owner != SERVER_OWNER:
                raise GuardError(f"registration outside {SERVER_OWNER}: {owner}")
            if len(arguments) != 5 or render(arguments[0]) != "server":
                raise GuardError("unrecognized registration signature")
            registrations.append(Registration(
                token.value, literal_path(arguments[1]), render(arguments[2]),
                render(arguments[3]), render(arguments[4]),
                contexts.get(token.line), path, token.line))
            index = closing + 1
    for index, token in enumerate(tokens[:-1]):
        if (token.kind != "identifier" or marker.fullmatch(token.value) is None
                or tokens[index + 1].value != "(" or index in seen_calls):
            continue
        closing = pairing.get(index + 1)
        if (closing is not None and closing + 1 < len(tokens)
                and tokens[closing + 1].value in {"{", ";"}):
            continue
        raise GuardError(f"registration call outside parsed function in {path}")
    return registrations


def check_root(root: Path) -> list[Registration]:
    source_root = root / "wyrelog"
    sources = sorted(source_root.rglob("*.c"))
    if not sources:
        raise GuardError("no production C sources discovered")
    registrations = []
    for source in sources:
        registrations.extend(scan_source(source))
    if len(registrations) != len(ROUTES):
        raise GuardError(f"public registration count mismatch: "
                         f"{len(registrations)} != {len(ROUTES)}")
    paths = [registration.path for registration in registrations]
    if len(paths) != len(set(paths)):
        raise GuardError("duplicate public registration path")
    if set(paths) != set(EXPECTED_BY_PATH):
        raise GuardError("unknown or missing public registration path")
    for registration in registrations:
        spec = EXPECTED_BY_PATH[registration.path]
        expected_api = (RAW_API if registration.path in
                        PREFIX_PATHS | PENDING_RAW_SINGLETONS else EXACT_API)
        if registration.api != expected_api:
            raise GuardError(f"registration class mismatch: {registration.path}")
        if (registration.callback, registration.data, registration.destroy) != (
                spec.callback, spec.data, spec.destroy):
            raise GuardError(f"registration ownership mismatch: "
                             f"{registration.path}")
        if registration.feature != spec.feature:
            raise GuardError(f"registration feature mismatch: "
                             f"{registration.path}")
    return registrations


def fixture_source() -> str:
    lines = [
        "typedef void *SoupServer;",
        "static void wyl_daemon_http_add_exact_handler(void *server,",
        "  const char *canonical_path, void *callback, void *user_data,",
        "  void *user_data_destroy) {",
        "  soup_server_add_handler(server, canonical_path,",
        "    wyl_daemon_http_exact_handler_dispatch, exact,",
        "    wyl_daemon_http_exact_handler_free);",
        "}",
        "static void wyl_daemon_start_http_server_with_runtime(void) {",
    ]
    active_feature = None
    for spec in ROUTES:
        if spec.feature != active_feature:
            if active_feature is not None:
                lines.append("#endif")
            if spec.feature is not None:
                lines.append(f"#ifdef {spec.feature}")
            active_feature = spec.feature
        api = (RAW_API if spec.path in PREFIX_PATHS | PENDING_RAW_SINGLETONS
               else EXACT_API)
        lines.append(f"  {api} /* registration */ ( server, \"{spec.path}\","
                     f" {spec.callback}, {spec.data}, {spec.destroy} );")
    if active_feature is not None:
        lines.append("#endif")
    lines.extend(["}", "const char *ignored = \"soup_server_add_handler\";",
                  "/* soup_server_add_websocket_handler(fake); */", ""])
    return "\n".join(lines)


def expect_failure(root: Path, message: str) -> None:
    try:
        check_root(root)
    except GuardError:
        return
    raise GuardError(f"negative fixture accepted: {message}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="wyl-route-guard-") as temporary:
        root = Path(temporary)
        daemon = root / "wyrelog" / "daemon"
        daemon.mkdir(parents=True)
        source_path = daemon / "http.c"
        baseline = fixture_source()
        source_path.write_text(baseline, encoding="utf-8")
        check_root(root)

        mutants = {
            "nonliteral": baseline.replace('"/healthz"', "health_path", 1),
            "concatenated": baseline.replace('"/healthz"',
                                               '"/health" "z"', 1),
            "varied arguments": baseline.replace(
                'healthz_handler, NULL, NULL',
                'healthz_handler, other_data, destroy_data', 1),
            "duplicate": baseline.replace(
                "  soup_server_add_handler /* registration */ ( server, "
                '"/readyz"',
                "  soup_server_add_handler /* registration */ ( server, "
                '"/healthz"', 1),
            "raw singleton": baseline.replace(
                f'{EXACT_API} /* registration */ ( server, '
                '"/auth/service-token"',
                f'{RAW_API} /* registration */ ( server, '
                '"/auth/service-token"', 1),
            "unknown exact": baseline.replace(
                '"/auth/service-token"', '"/auth/service-token-v2"', 1),
            "alternate API": baseline.replace(
                f'{RAW_API} /* registration */ ( server, "/facts"',
                'soup_server_add_early_handler /* registration */ '
                '( server, "/facts"', 1),
            "misplaced feature": baseline.replace(
                f"#ifdef {FACT}", f"#ifdef {AUDIT}", 1),
            "unbalanced call": baseline.replace(
                'healthz_handler, NULL, NULL );',
                'healthz_handler, NULL, NULL ;', 1),
        }
        for name, mutant in mutants.items():
            source_path.write_text(mutant, encoding="utf-8")
            expect_failure(root, name)

        source_path.write_text(baseline, encoding="utf-8")
        alternate = root / "wyrelog" / "alternate.c"
        alternate.write_text(
            "static void alternate(void) {\n"
            "  soup_server_add_websocket_handler(server, \"/hidden\", NULL, "
            "NULL, NULL, callback, NULL);\n}\n", encoding="utf-8")
        expect_failure(root, "alternate production source")


def main() -> int:
    try:
        if sys.argv[1:] == ["--self-test"]:
            self_test()
            print("OK: daemon HTTP registration guard rejects negative fixtures")
            return 0
        if len(sys.argv) != 2:
            raise GuardError("usage: check-daemon-http-route-registrations.py "
                             "ROOT|--self-test")
        registrations = check_root(Path(sys.argv[1]))
        print("OK: daemon HTTP registrations "
              f"{len(registrations)} = {len(PREFIX_PATHS)} prefix + "
              f"{len(registrations) - len(PREFIX_PATHS)} singleton "
              f"({len(PENDING_RAW_SINGLETONS)} pending exact migration)")
        return 0
    except (GuardError, OSError, UnicodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

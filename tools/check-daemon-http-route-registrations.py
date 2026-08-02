#!/usr/bin/env python3
"""Fail closed over every production daemon HTTP ownership registration."""

from dataclasses import dataclass
from pathlib import Path
import re
import sys
import tempfile


SOUP_API = "soup_server_add_handler"
PREFIX_API = "wyl_daemon_http_add_prefix_handler"
RAW_SINGLETON_API = "wyl_daemon_http_add_singleton_handler"
EXACT_API = "wyl_daemon_http_add_exact_handler"
SERVER_OWNER = "wyl_daemon_start_http_server_with_runtime"
PREFIX_OWNER = "wyl_daemon_http_add_prefix_handler"
RAW_SINGLETON_OWNER = "wyl_daemon_http_add_singleton_handler"
EXACT_OWNER = "wyl_daemon_http_add_exact_handler"
FACT = "WYL_HAS_FACT_STORE"
AUDIT = "WYL_HAS_AUDIT"
OWNERSHIP_API = re.compile(
    r"(?:soup_server_add_[A-Za-z0-9_]*handler|"
    r"[A-Za-z_][A-Za-z0-9_]*add_(?:exact|prefix|singleton)_handler)\Z")


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
    RouteSpec("/service-management-authority/arm",
              "service_management_authority_arm_handler"),
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
PREEXISTING_EXACT_PATHS = {
    "/service-management-authority/arm",
}
ISSUE_720_EXACT_PATHS = {
    "/healthz",
    "/readyz",
    "/profile/status",
    "/profile/events",
    "/auth/login",
    "/auth/mfa/verify",
    "/auth/mfa/enroll/start",
    "/auth/mfa/enroll/confirm",
    "/auth/refresh",
    "/auth/logout",
}
PENDING_RAW_SINGLETONS = {
    spec.path for spec in ROUTES
    if spec.path not in PREFIX_PATHS | ISSUE_719_EXACT_PATHS
    | PREEXISTING_EXACT_PATHS | ISSUE_720_EXACT_PATHS
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


def translation_phase_source(source: str) -> str:
    """Apply C phase-1 newline normalization and phase-2 line splicing."""
    if "\0" in source:
        raise GuardError("NUL byte in preprocessing input")
    normalized = source.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.replace("\\\n", "")


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


def function_body_start(tokens: list[Token], pairing: dict[int, int],
                        signature_end: int) -> int | None:
    """Accept a definition's optional post-declarator attribute sequence."""
    index = signature_end + 1
    while index < len(tokens) and tokens[index].kind == "identifier":
        index += 1
        if index < len(tokens) and tokens[index].value == "(":
            closing = pairing.get(index)
            if closing is None:
                raise GuardError("unbalanced post-declarator attribute")
            index = closing + 1
    return index if index < len(tokens) and tokens[index].value == "{" else None


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
            body_start = function_body_start(tokens, pairing, close)
            if body_start is not None:
                body_end = pairing[body_start]
                result.append((token.value, index, body_start + 1, body_end))
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


def preprocessing_view(source: str) -> str:
    """Mask comments and literals while preserving preprocessing layout."""
    output = list(source)
    index = 0
    state = "code"
    while index < len(source):
        if state == "code" and source.startswith("//", index):
            output[index] = output[index + 1] = " "
            index += 2
            state = "line-comment"
            continue
        if state == "code" and source.startswith("/*", index):
            output[index] = output[index + 1] = " "
            index += 2
            state = "block-comment"
            continue
        if state == "line-comment":
            if source[index] == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if source.startswith("*/", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
            else:
                if source[index] != "\n":
                    output[index] = " "
                index += 1
            continue
        if state == "code" and source[index] in {'"', "'"}:
            state = "string" if source[index] == '"' else "char"
            output[index] = " "
            index += 1
            continue
        if state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if source[index] == "\\" and index + 1 < len(source):
                output[index] = " "
                if source[index + 1] != "\n":
                    output[index + 1] = " "
                index += 2
            elif source[index] == quote:
                output[index] = " "
                index += 1
                state = "code"
            else:
                if source[index] != "\n":
                    output[index] = " "
                index += 1
            continue
        index += 1
    if state not in {"code", "line-comment"}:
        raise GuardError("unterminated comment or literal in preprocessing input")
    return "".join(output)


def reject_ownership_preprocessor_references(source: str, path: Path) -> None:
    in_directive = False
    directive_start = 0
    logical_lines = []
    for number, line in enumerate(preprocessing_view(source).splitlines(), 1):
        starts_directive = line.lstrip().startswith("#")
        if starts_directive:
            in_directive = True
            directive_start = number
            logical_lines = []
        if in_directive:
            logical_lines.append(line.rstrip().removesuffix("\\"))
        if in_directive and not line.rstrip().endswith("\\"):
            directive = " ".join(logical_lines)
            tokens = re.findall(r"##|[A-Za-z_][A-Za-z0-9_]*|\S", directive)
            identifiers = [token for token in tokens
                           if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token)]
            if any(OWNERSHIP_API.fullmatch(token) for token in identifiers):
                raise GuardError(f"ownership API in preprocessor directive at "
                                 f"{path}:{directive_start}")
            for index, token in enumerate(tokens):
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                    continue
                pasted = token
                cursor = index
                while (cursor + 2 < len(tokens)
                       and tokens[cursor + 1] == "##"
                       and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",
                                        tokens[cursor + 2])):
                    pasted += tokens[cursor + 2]
                    cursor += 2
                if cursor != index and OWNERSHIP_API.fullmatch(pasted):
                    raise GuardError(f"token-pasted ownership API at "
                                     f"{path}:{directive_start}")
            in_directive = False
    if in_directive:
        raise GuardError(f"unterminated preprocessor directive at "
                         f"{path}:{directive_start}")


def reject_line_marker_spoofing(source: str, path: Path) -> None:
    view = preprocessing_view(source)
    for number, line in enumerate(view.splitlines(), 1):
        if re.match(r'^\s*#\s*(?:line\s+)?[0-9]+(?:\s|$)', line):
            raise GuardError(f"project-owned line marker at {path}:{number}")


def scan_source(path: Path) -> list[Registration]:
    source = translation_phase_source(path.read_text(encoding="utf-8"))
    reject_line_marker_spoofing(source, path)
    reject_ownership_preprocessor_references(source, path)
    tokens = lex(source)
    pairing = mates(tokens)
    contexts = feature_contexts(source)
    registrations = []
    seen_calls = set()
    definitions = functions(tokens, pairing)
    ownership_owners = {PREFIX_OWNER, RAW_SINGLETON_OWNER, EXACT_OWNER}
    owner_definitions = {
        name_index for owner, name_index, _start, _end in definitions
        if owner in ownership_owners
    }
    defined_owners = [owner for owner, _name_index, _start, _end in definitions
                      if owner in ownership_owners]
    if defined_owners and (set(defined_owners) != ownership_owners
                           or len(defined_owners) != len(ownership_owners)
                           or path.parts[-3:] !=
                           ("wyrelog", "daemon", "http.c")):
        raise GuardError(f"ownership adapters outside their owner: {path}")
    allowed_definitions = owner_definitions
    adapter_internal_calls = {owner: 0 for owner in ownership_owners}
    for owner, _name_index, start, end in definitions:
        index = start
        while index < end:
            token = tokens[index]
            if (token.kind != "identifier"
                    or OWNERSHIP_API.fullmatch(token.value)
                    is None or index + 1 >= end
                    or tokens[index + 1].value != "("):
                index += 1
                continue
            closing = pairing.get(index + 1)
            if closing is None or closing >= end:
                raise GuardError(f"unparsed registration call in {path}")
            seen_calls.add(index)
            arguments = split_arguments(tokens, index + 1, closing)
            if token.value == SOUP_API and owner in ownership_owners:
                if owner == EXACT_OWNER:
                    expected = ["server", "canonical_path",
                                "wyl_daemon_http_exact_handler_dispatch",
                                "exact",
                                "wyl_daemon_http_exact_handler_free"]
                else:
                    expected = ["server", "canonical_path", "callback",
                                "user_data", "user_data_destroy"]
                if [render(argument) for argument in arguments] != expected:
                    raise GuardError("ownership adapter Soup signature changed")
                adapter_internal_calls[owner] += 1
                index = closing + 1
                continue
            if token.value not in {PREFIX_API, RAW_SINGLETON_API, EXACT_API}:
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
    for index, token in enumerate(tokens):
        if (token.kind != "identifier"
                or OWNERSHIP_API.fullmatch(token.value) is None
                or index in seen_calls):
            continue
        if index in allowed_definitions:
            continue
        raise GuardError(f"unparsed or indirect ownership API reference at "
                         f"{path}:{token.line}")
    if defined_owners and any(count != 1
                              for count in adapter_internal_calls.values()):
        raise GuardError("each ownership adapter must own one Soup registration")
    return registrations


def check_root(root: Path) -> list[Registration]:
    source_root = root / "wyrelog"
    sources = sorted(source_root.rglob("*.c"))
    if not sources:
        raise GuardError("no production C sources discovered")
    preprocessing_inputs = sorted({
        path for suffix in ("*.h", "*.inc")
        for path in source_root.rglob(suffix)
    })
    for preprocessing_input in preprocessing_inputs:
        hidden_registrations = scan_source(preprocessing_input)
        if hidden_registrations:
            raise GuardError(f"registration in project preprocessing input: "
                             f"{preprocessing_input}")
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
        if registration.path in PREFIX_PATHS:
            expected_api = PREFIX_API
        elif registration.path in PENDING_RAW_SINGLETONS:
            expected_api = RAW_SINGLETON_API
        else:
            expected_api = EXACT_API
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
        "#if 1 /* soup_server_add_handler is only documentation here */",
        "#endif",
        '#define OWNERSHIP_LABEL "soup_server_add_handler"',
        "static void wyl_daemon_http_add_prefix_handler(void *server,",
        "  const char *canonical_path, void *callback, void *user_data,",
        "  void *user_data_destroy) {",
        "  soup_server_add_handler(server, canonical_path, callback,",
        "    user_data, user_data_destroy);",
        "}",
        "static void wyl_daemon_http_add_singleton_handler(void *server,",
        "  const char *canonical_path, void *callback, void *user_data,",
        "  void *user_data_destroy) {",
        "  soup_server_add_handler(server, canonical_path, callback,",
        "    user_data, user_data_destroy);",
        "}",
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
        if spec.path in PREFIX_PATHS:
            api = PREFIX_API
        elif spec.path in PENDING_RAW_SINGLETONS:
            api = RAW_SINGLETON_API
        else:
            api = EXACT_API
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
            "macro alias": (
                "#define HIDDEN_ADD soup_server_add_handler\n" + baseline),
            "continued macro alias": (
                "#define HIDDEN_ADD \\\n"
                "  soup_server_add_handler\n" + baseline),
            "LF identifier splice": (
                "#define HIDDEN_ADD soup_server_add_\\\nhandler\n"
                + baseline),
            "CRLF identifier splice": (
                "#define HIDDEN_ADD soup_server_add_\\\r\nhandler\r\n"
                + baseline),
            "token-pasted macro alias": (
                "#define HIDDEN_ADD soup_server_ ## add_handler\n"
                + baseline),
            "function-pointer alias": baseline + (
                "static void hidden_alias(void) {\n"
                "  void (*hidden_add)(void) = soup_server_add_handler;\n"
                "  hidden_add();\n"
                "}\n"),
            "post-declarator attribute owner": baseline + (
                "static void hidden_owner(void) G_GNUC_NO_INLINE {\n"
                "  soup_server_add_handler(server, \"/hidden\", callback, "
                "data, NULL);\n"
                "}\n"),
            "project line-marker spoof": (
                '#line 700 "trusted.c"\n' + baseline),
            "nonliteral": baseline.replace('"/healthz"', "health_path", 1),
            "concatenated": baseline.replace('"/healthz"',
                                               '"/health" "z"', 1),
            "varied arguments": baseline.replace(
                'healthz_handler, NULL, NULL',
                'healthz_handler, other_data, destroy_data', 1),
            "duplicate": baseline.replace(
                f"  {EXACT_API} /* registration */ ( server, "
                '"/readyz"',
                f"  {EXACT_API} /* registration */ ( server, "
                '"/healthz"', 1),
            "raw singleton": baseline.replace(
                f'{EXACT_API} /* registration */ ( server, '
                '"/auth/service-token"',
                f'{RAW_SINGLETON_API} /* registration */ ( server, '
                '"/auth/service-token"', 1),
            "unknown exact": baseline.replace(
                '"/auth/service-token"', '"/auth/service-token-v2"', 1),
            "alternate API": baseline.replace(
                f'{PREFIX_API} /* registration */ ( server, "/facts"',
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

        hidden_header = daemon / "hidden-route.h"
        hidden_header.write_text(
            "#define HIDDEN_ADD soup_server_add_handler\n", encoding="utf-8")
        header_alias = baseline.replace(
            "static void wyl_daemon_start_http_server_with_runtime(void) {",
            "#include \"hidden-route.h\"\n"
            "static void wyl_daemon_start_http_server_with_runtime(void) {\n"
            "  HIDDEN_ADD(server, \"/hidden\", callback, data, NULL);", 1)
        source_path.write_text(header_alias, encoding="utf-8")
        expect_failure(root, "included project-header alias")
        hidden_header.unlink()

        hidden_header.write_text(
            "static inline void hidden_add(void) {\n"
            "  soup_server_add_handler(server, \"/hidden\", callback, "
            "data, NULL);\n"
            "}\n", encoding="utf-8")
        source_path.write_text(
            '#include "hidden-route.h"\n' + baseline, encoding="utf-8")
        expect_failure(root, "project-header inline registration")
        hidden_header.unlink()

        hidden_include = daemon / "hidden-route.inc"
        hidden_include.write_text(
            "soup_server_add_\\\nhandler(server, \"/hidden\", callback, "
            "data, NULL);\n", encoding="utf-8")
        source_path.write_text(baseline, encoding="utf-8")
        expect_failure(root, "project inc splice registration")
        hidden_include.unlink()

        for wrapper in (PREFIX_API, RAW_SINGLETON_API, EXACT_API):
            hidden_header.write_text(
                f"#define HIDDEN_ADD {wrapper}\n", encoding="utf-8")
            source_path.write_text(header_alias, encoding="utf-8")
            expect_failure(root, f"project-header {wrapper} alias")
            hidden_header.unlink()

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

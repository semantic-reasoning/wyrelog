#!/usr/bin/env python3
"""Fail closed over every production daemon HTTP ownership registration."""

from dataclasses import dataclass
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import argparse
import bisect
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

from _diag_path import escape_ascii_identity, render_source_identity


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
PRODUCTION_DAEMON_TARGET_DIRS = {
    "gcc": "wyrelog/wyrelogd.p",
    "clang": "wyrelog/wyrelogd.p",
    "clang-cl": "wyrelog/wyrelogd.exe.p",
    "msvc": "wyrelog/wyrelogd.exe.p",
}
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
    "/facts/status",
    "/facts/schema/register",
    "/profile/status",
    "/profile/events",
    "/auth/login",
    "/auth/mfa/verify",
    "/auth/mfa/enroll/start",
    "/auth/mfa/enroll/confirm",
    "/auth/refresh",
    "/auth/logout",
    "/tenants",
    "/tenants/create",
    "/tenants/seal",
    "/tenants/unseal",
    "/tenants/delete",
    "/graphs/create",
    "/graphs/seal",
    "/graphs",
    "/decide",
    "/policy/permissions/grant",
    "/policy/permissions/revoke",
    "/policy/permissions/transition",
    "/policy/roles/grant",
    "/policy/roles/revoke",
    "/audit/events",
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
    offset: int


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


@dataclass(frozen=True)
class OwnershipOccurrence:
    source: str
    line: int
    symbol: str
    role: str
    arguments: tuple[str, ...] | None = None


def translation_phase_source(source: str) -> str:
    """Apply C phase-1 newline normalization and phase-2 line splicing."""
    if "\0" in source:
        raise GuardError("NUL byte in preprocessing input")
    normalized = source.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.replace("\\\n", "")


def translation_phase_source_with_lines(source: str) -> tuple[str, list[int]]:
    if "\0" in source:
        raise GuardError("NUL byte in preprocessing input")
    normalized = source.replace("\r\n", "\n").replace("\r", "\n")
    output = []
    physical_line = 1
    line_map = [physical_line]
    index = 0
    while index < len(normalized):
        if normalized.startswith("\\\n", index):
            physical_line += 1
            index += 2
            continue
        output.append(normalized[index])
        if normalized[index] == "\n":
            physical_line += 1
            line_map.append(physical_line)
        index += 1
    return "".join(output), line_map


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
                                source[start:index], line, start))
            continue
        if char.isalpha() or char == "_":
            start = index
            index += 1
            while index < length and (source[index].isalnum()
                                      or source[index] == "_"):
                index += 1
            tokens.append(Token("identifier", source[start:index], line,
                                start))
            continue
        tokens.append(Token("punct", char, line, index))
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


def containing_function(definitions, index: int):
    return next(((owner, start, end)
                 for owner, _name_index, start, end in definitions
                 if start <= index < end), None)


def ownership_call_is_direct_statement(tokens: list[Token],
                                       body_start: int, index: int,
                                       closing: int) -> bool:
    if (index == 0 or closing + 1 >= len(tokens)
            or tokens[index - 1].value not in {"{", ";"}
            or tokens[closing + 1].value != ";"):
        return False
    depth = 0
    for token in tokens[body_start:index]:
        if token.value == "{":
            depth += 1
        elif token.value == "}":
            depth -= 1
    return depth == 0


def ownership_occurrences(tokens: list[Token], pairing: dict[int, int],
                          location_for_line) -> list[OwnershipOccurrence]:
    definitions = functions(tokens, pairing)
    definition_names = {name_index: owner
                        for owner, name_index, _start, _end in definitions}
    result = []
    for index, token in enumerate(tokens):
        if (token.kind != "identifier"
                or OWNERSHIP_API.fullmatch(token.value) is None):
            continue
        if index in definition_names:
            role = f"definition:{definition_names[index]}"
        else:
            owner_body = containing_function(definitions, index)
            owner = owner_body[0] if owner_body is not None else "<global>"
            role = (f"call:{owner}" if index + 1 < len(tokens)
                    and tokens[index + 1].value == "("
                    else f"indirect:{owner}")
        source, line = location_for_line(token.line)
        arguments = None
        if role.startswith("call:"):
            closing = pairing.get(index + 1)
            if closing is None:
                raise GuardError("unparsed ownership call signature")
            if (owner_body is None or not ownership_call_is_direct_statement(
                    tokens, owner_body[1], index, closing)):
                raise GuardError("ownership call is not a direct owner-body "
                                 "expression statement")
            arguments = canonical_arguments(
                split_arguments(tokens, index + 1, closing))
        result.append(OwnershipOccurrence(
            source, line, token.value, role, arguments))
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


def canonical_argument(argument: list[Token]) -> str:
    rendered = render(argument)
    compact = re.sub(r"\s+", "", rendered)
    while compact.startswith("(") and compact.endswith(")"):
        depth = 0
        wraps = True
        for index, char in enumerate(compact):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(compact) - 1:
                    wraps = False
                    break
        if not wraps or depth != 0:
            break
        compact = compact[1:-1]
    if compact in {"NULL", "0", "__null", "nullptr", "(void*)0"}:
        return "NULL"
    return rendered


def canonical_arguments(arguments: list[list[Token]]) -> tuple[str, ...]:
    return tuple(canonical_argument(argument) for argument in arguments)


def literal_path(argument: list[Token]) -> str:
    if len(argument) != 1 or argument[0].kind != "string":
        raise GuardError("registration path must be one literal string")
    raw = argument[0].value
    if not re.fullmatch(r'"/[A-Za-z0-9_{}:./-]*"', raw):
        # raw is, by construction, the one spelling that just failed the safe
        # route charset, so it can carry ESC/tab/bidi/homoglyph bytes.  Render
        # it through the shared ASCII-safe identity so a hostile route literal
        # cannot forge, merge, or suppress this diagnostic.
        raise GuardError(
            "registration path is not a plain public path: "
            + render_source_identity(raw))
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
                                 f"{render_source_identity(path)}:"
                                 f"{directive_start}")
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
                                     f"{render_source_identity(path)}:"
                                     f"{directive_start}")
            in_directive = False
    if in_directive:
        raise GuardError(f"unterminated preprocessor directive at "
                         f"{render_source_identity(path)}:{directive_start}")


def reject_line_marker_spoofing(source: str, path: Path) -> None:
    view = preprocessing_view(source)
    for number, line in enumerate(view.splitlines(), 1):
        if re.match(r'^\s*#\s*(?:line\s+)?[0-9]+(?:\s|$)', line):
            raise GuardError(f"project-owned line marker at "
                             f"{render_source_identity(path)}:{number}")


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
        raise GuardError(f"ownership adapters outside their owner: "
                         f"{render_source_identity(path)}")
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
                raise GuardError(f"unparsed registration call in "
                                 f"{render_source_identity(path)}")
            if not ownership_call_is_direct_statement(
                    tokens, start, index, closing):
                raise GuardError("ownership call is not a direct owner-body "
                                 "expression statement at "
                                 f"{render_source_identity(path)}:"
                                 f"{token.line}")
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
                raise GuardError(
                    "registration outside "
                    f"{SERVER_OWNER}: {escape_ascii_identity(owner)}")
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
                         f"{render_source_identity(path)}:{token.line}")
    if defined_owners and any(count != 1
                              for count in adapter_internal_calls.values()):
        raise GuardError("each ownership adapter must own one Soup registration")
    return registrations


def project_preprocessing_inputs(root: Path) -> list[Path]:
    if (root / ".git").exists() or (root / ".git").is_file():
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--", "*.h", "*.inc"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode != 0:
            raise GuardError("cannot enumerate project preprocessing inputs")
        paths = []
        for raw_path in completed.stdout.split(b"\0"):
            if not raw_path:
                continue
            try:
                relative = raw_path.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise GuardError("non-UTF-8 project preprocessing path") from error
            path = (root / relative).resolve()
            if not path.is_file():
                raise GuardError(f"tracked preprocessing input is missing: "
                                 f"{render_source_identity(relative)}")
            paths.append(path)
        return sorted(paths)
    return sorted({
        path for suffix in ("*.h", "*.inc")
        for path in root.rglob(suffix)
        if "subprojects" not in path.relative_to(root).parts
    })


def check_root(root: Path) -> list[Registration]:
    source_root = root / "wyrelog"
    sources = sorted(source_root.rglob("*.c"))
    if not sources:
        raise GuardError("no production C sources discovered")
    preprocessing_inputs = project_preprocessing_inputs(root)
    for preprocessing_input in preprocessing_inputs:
        hidden_registrations = scan_source(preprocessing_input)
        if hidden_registrations:
            raise GuardError(f"registration in project preprocessing input: "
                             f"{render_source_identity(preprocessing_input)}")
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


def scan_generated_inputs(build_root: Path) -> list[Path]:
    result = []
    for suffix in ("*.h", "*.inc"):
        for path in build_root.rglob(suffix):
            relative = path.relative_to(build_root)
            if "subprojects" not in relative.parts:
                result.append(path)
    return sorted(set(result))


def raw_approved_occurrences(root: Path,
                             build_root: Path) -> Counter[OwnershipOccurrence]:
    paths = sorted({
        path for path in (root / "wyrelog").rglob("*.c")
    } | set(project_preprocessing_inputs(root)))
    generated = scan_generated_inputs(build_root)
    for path in generated:
        hidden_registrations = scan_source(path)
        if hidden_registrations:
            raise GuardError(f"registration in generated preprocessing input: "
                             f"{render_source_identity(path)}")
    occurrences = []
    for path in paths + generated:
        source, line_map = translation_phase_source_with_lines(
            path.read_text(encoding="utf-8"))
        tokens = lex(source)
        pairing = mates(tokens)
        if path in generated:
            label = "@build/" + path.relative_to(build_root).as_posix()
        else:
            label = path.relative_to(root).as_posix()
        occurrences.extend(ownership_occurrences(
            tokens, pairing,
            lambda line, label=label, line_map=line_map:
            (label, line_map[line - 1])))
    return Counter(occurrences)


def raw_disabled_feature_occurrences(root: Path,
                                     enabled: frozenset[str]) \
        -> Counter[OwnershipOccurrence]:
    path = root / "wyrelog" / "daemon" / "http.c"
    raw = path.read_text(encoding="utf-8")
    source, line_map = translation_phase_source_with_lines(raw)
    optional = []
    for registration in scan_source(path):
        spec = EXPECTED_BY_PATH[registration.path]
        if spec.feature is None or spec.feature in enabled:
            continue
        optional.append(OwnershipOccurrence(
            registration.source.relative_to(root).as_posix(),
            line_map[registration.line - 1], registration.api,
            f"call:{SERVER_OWNER}",
            ("server", f'"{registration.path}"', registration.callback,
             registration.data, registration.destroy)))
    return Counter(optional)


def windows_command_line_split(command: str) -> list[str]:
    arguments = []
    index = 0
    while index < len(command):
        while index < len(command) and command[index].isspace():
            index += 1
        if index >= len(command):
            break
        value = []
        quoted = False
        while index < len(command) and (quoted or not command[index].isspace()):
            if command[index] == "\\":
                start = index
                while index < len(command) and command[index] == "\\":
                    index += 1
                count = index - start
                if index < len(command) and command[index] == '"':
                    value.extend("\\" * (count // 2))
                    if count % 2:
                        value.append('"')
                    else:
                        quoted = not quoted
                    index += 1
                else:
                    value.extend("\\" * count)
                continue
            if command[index] == '"':
                quoted = not quoted
                index += 1
                continue
            value.append(command[index])
            index += 1
        if quoted:
            raise GuardError("unterminated Windows compiler command quote")
        arguments.append("".join(value))
    return arguments


def expand_response_files(arguments: list[str], directory: Path,
                          windows: bool, stack: tuple[Path, ...] = (),
                          depth: int = 0) -> list[str]:
    if depth > 16:
        raise GuardError("compiler response nesting is too deep")
    expanded = []
    for argument in arguments:
        if not argument.startswith("@") or argument == "@":
            expanded.append(argument)
            continue
        response = Path(argument[1:])
        response = (response if response.is_absolute()
                    else directory / response).resolve()
        if response in stack:
            raise GuardError("compiler response-file cycle")
        try:
            content = response.read_text(encoding="utf-8-sig")
            nested = (windows_command_line_split(content) if windows
                      else shlex.split(content, posix=True))
        except (OSError, UnicodeError, ValueError) as error:
            raise GuardError(f"cannot expand compiler response: "
                             f"{render_source_identity(response)}") from error
        expanded.extend(expand_response_files(
            nested, directory, windows, stack + (response,), depth + 1))
    return expanded


def resolve_argument_path(argument: str, directory: Path) -> Path:
    path = Path(argument)
    return (path if path.is_absolute() else directory / path).resolve()


def semantic_command(arguments: list[str], directory: Path, source: Path,
                     compiler_id: str) -> list[str]:
    if compiler_id not in {"gcc", "clang", "clang-cl", "msvc"}:
        raise GuardError(f"unsupported compiler dialect: {compiler_id}")
    windows = compiler_id in {"clang-cl", "msvc"}
    arguments = expand_response_files(arguments, directory, windows)
    if not arguments:
        raise GuardError("empty compiler command")
    result = []
    source_count = 0
    index = 0
    paired = {"-o", "-MF", "-MT", "-MQ", "-MJ"}
    windows_paired = {"/fo", "/fd", "/fe", "/sourcedependencies",
                      "/scandependencies"}
    standalone = {"-c", "-MD", "-MMD", "-MP", "-MG", "-M", "-MM"}
    while index < len(arguments):
        argument = arguments[index]
        lower = argument.lower()
        if index > 0:
            try:
                is_source = resolve_argument_path(argument, directory) == source
            except (OSError, ValueError):
                is_source = False
            if is_source:
                source_count += 1
                index += 1
                continue
        if argument in paired or lower in windows_paired:
            if index + 1 >= len(arguments):
                raise GuardError(f"compiler option lacks operand: {argument}")
            index += 2
            continue
        if (argument in standalone or lower in {"/c", "/showincludes"}
                or re.match(r"^-(?:o|MF|MT|MQ|MJ).+", argument)
                or any(lower.startswith(prefix) and lower != prefix
                       for prefix in windows_paired)):
            index += 1
            continue
        result.append(argument)
        index += 1
    if source_count != 1:
        raise GuardError(f"compile entry contains source {source_count} times")
    if windows:
        result.extend(["/nologo", "/E", "/TC", str(source)])
    else:
        result.extend(["-E", "-x", "c", str(source)])
    return result


@dataclass(frozen=True)
class CompileUnit:
    source: Path
    directory: Path
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class ValidatedCompileUnit:
    unit: CompileUnit
    output: Path
    relative_output: str


def production_daemon_target_directory(compiler_id: str) -> str:
    try:
        return PRODUCTION_DAEMON_TARGET_DIRS[compiler_id]
    except KeyError as error:
        raise GuardError(
            f"unsupported compiler dialect: {compiler_id}") from error


def is_production_daemon_output(relative_output: str,
                                compiler_id: str) -> bool:
    parent, separator, _name = relative_output.rpartition("/")
    return (bool(separator)
            and parent == production_daemon_target_directory(compiler_id))


def compile_unit_enabled_features(unit: CompileUnit,
                                  compiler_id: str) -> frozenset[str]:
    windows = compiler_id in {"clang-cl", "msvc"}
    arguments = expand_response_files(
        list(unit.arguments), unit.directory, windows)
    enabled = set()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        lower = argument.lower()
        operand = None
        define = False
        if argument in {"-D", "-U"} or lower in {"/d", "/u"}:
            if index + 1 >= len(arguments):
                raise GuardError(f"compiler option lacks operand: {argument}")
            operand = arguments[index + 1]
            define = argument == "-D" or lower == "/d"
            index += 2
        elif argument.startswith("-D") or argument.startswith("-U"):
            operand = argument[2:]
            define = argument.startswith("-D")
            index += 1
        elif lower.startswith("/d") or lower.startswith("/u"):
            operand = argument[2:]
            define = lower.startswith("/d")
            index += 1
        else:
            index += 1
        if operand is None:
            continue
        name = operand.split("=", 1)[0]
        if name not in {FACT, AUDIT}:
            continue
        if define:
            enabled.add(name)
        else:
            enabled.discard(name)
    return frozenset(enabled)


def production_compile_units(root: Path, build_root: Path,
                             compiler_id: str) -> list[CompileUnit]:
    production_daemon_target_directory(compiler_id)
    database_path = build_root / "compile_commands.json"
    if not database_path.is_file():
        raise GuardError(f"missing compile database: {database_path}")
    try:
        database = json.loads(database_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuardError("invalid compile database") from error
    if not isinstance(database, list):
        raise GuardError("compile database root must be an array")
    windows = compiler_id in {"clang-cl", "msvc"}
    daemon_http = (root / "wyrelog" / "daemon" / "http.c").resolve()
    validated = []
    outputs = set()
    for entry in database:
        if not isinstance(entry, dict):
            raise GuardError("invalid compile database entry")
        try:
            directory = Path(entry["directory"]).resolve()
            source = resolve_argument_path(entry["file"], directory)
        except (KeyError, TypeError, OSError, ValueError) as error:
            raise GuardError("compile entry lacks canonical directory/file") from error
        try:
            relative_source = source.relative_to(root).as_posix()
        except ValueError:
            relative_source = None
        is_project_source = (
            relative_source is not None
            and relative_source.startswith("wyrelog/")
            and relative_source.endswith(".c"))
        output_value = entry.get("output")
        if not isinstance(output_value, str) or not output_value:
            if is_project_source:
                raise GuardError(f"production compile entry lacks output: "
                                 f"{render_source_identity(relative_source)}")
            continue
        output = resolve_argument_path(output_value, directory)
        try:
            relative_output = output.relative_to(build_root).as_posix()
        except ValueError:
            relative_output = None
        claims_production_target = (
            relative_output is not None
            and is_production_daemon_output(relative_output, compiler_id))
        if claims_production_target and not is_project_source:
            raise GuardError(
                "production target compile entry has non-project source: "
                f"{render_source_identity(source)}")
        if not is_project_source:
            continue
        assert relative_source is not None
        if relative_output is None:
            raise GuardError(
                "production compile output escapes build root: "
                f"{render_source_identity(relative_source)}")
        if output in outputs:
            raise GuardError(f"ambiguous production compile output: "
                             f"{render_source_identity(output)}")
        outputs.add(output)
        if "arguments" in entry:
            arguments = entry["arguments"]
            if (not isinstance(arguments, list)
                    or not all(isinstance(item, str) for item in arguments)):
                raise GuardError("invalid compile entry arguments")
        elif isinstance(entry.get("command"), str):
            try:
                arguments = (windows_command_line_split(entry["command"])
                             if windows else
                             shlex.split(entry["command"], posix=True))
            except (GuardError, ValueError) as error:
                raise GuardError("invalid compiler command quoting") from error
        else:
            raise GuardError("compile entry lacks arguments/command")
        unit = CompileUnit(source, directory, tuple(arguments))
        validated.append(ValidatedCompileUnit(
            unit, output, relative_output))
    admitted = [record for record in validated
                if record.relative_output.startswith("wyrelog/")]
    daemon_units = [record.unit for record in admitted
                    if record.unit.source == daemon_http
                    and is_production_daemon_output(
                        record.relative_output, compiler_id)]
    if not daemon_units:
        raise GuardError("production daemon HTTP translation unit is missing")
    if len(daemon_units) != 1:
        raise GuardError("ambiguous production daemon HTTP translation unit")
    units = [record.unit for record in admitted
             if record.unit.source != daemon_http]
    units.append(daemon_units[0])
    return sorted(units, key=lambda unit: (unit.source.as_posix(),
                                           unit.arguments))


LINE_MARKER = re.compile(
    r'^[ \t]*#[ \t]*(?:line[ \t]+)?([0-9]+)[ \t]+'
    r'"([^"\r\n]+)"(?:[ \t]+.*)?$')


def canonical_provenance(marked: str, directory: Path, root: Path,
                         build_root: Path) -> str | None:
    if marked.startswith("<") and marked.endswith(">"):
        return None
    marked = marked.replace("\\\\", "\\")
    directory = directory.resolve()
    root = root.resolve()
    build_root = build_root.resolve()
    path = Path(marked)
    path = (path if path.is_absolute() else directory / path).resolve()
    try:
        relative = path.relative_to(build_root)
        if "subprojects" in relative.parts:
            return None
        return "@build/" + relative.as_posix()
    except ValueError:
        pass
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    if relative.parts and relative.parts[0] in {".git", "subprojects"}:
        return None
    return relative.as_posix()


def canonical_preprocessing_context(
        unit: CompileUnit, root: Path,
        build_root: Path) -> tuple[CompileUnit, Path, Path, str]:
    root = root.resolve()
    build_root = build_root.resolve()
    unit = CompileUnit(unit.source.resolve(), unit.directory.resolve(),
                       unit.arguments)
    label = canonical_provenance(
        str(unit.source), unit.directory, root, build_root)
    if label is None or label.startswith("@build/"):
        raise GuardError("preprocessing unit is outside the project root")
    return unit, root, build_root, label


def expanded_call_arguments(output: str, position: int,
                            symbol: str) -> tuple[str, ...]:
    """Parse one expanded ownership call without lexing the whole TU."""
    cursor = position + len(symbol)
    while cursor < len(output) and output[cursor].isspace():
        cursor += 1
    if cursor >= len(output) or output[cursor] != "(":
        raise GuardError("expanded ownership API is not a direct call")
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    state = "code"
    at_line_start = False
    index = cursor
    end = None
    while index < len(output):
        char = output[index]
        if state == "line-comment":
            if char == "\n":
                state = "code"
                at_line_start = True
            index += 1
            continue
        if state == "block-comment":
            if output.startswith("*/", index):
                state = "code"
                index += 2
            else:
                index += 1
            continue
        if state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if char == "\\":
                if index + 1 >= len(output):
                    raise GuardError("unterminated expanded C literal")
                index += 2
            elif char == quote:
                state = "code"
                index += 1
            elif char == "\n":
                raise GuardError("newline in expanded C literal")
            else:
                index += 1
            continue
        if state == "directive":
            if char == "\n":
                state = "code"
                at_line_start = True
            index += 1
            continue
        if char == "\n":
            at_line_start = True
            index += 1
            continue
        if at_line_start and char in " \t\r\f\v":
            index += 1
            continue
        if at_line_start and char == "#":
            state = "directive"
            index += 1
            continue
        at_line_start = False
        if output.startswith("//", index):
            state = "line-comment"
            index += 2
            continue
        if output.startswith("/*", index):
            state = "block-comment"
            index += 2
            continue
        if char in {'"', "'"}:
            state = "string" if char == '"' else "char"
            index += 1
            continue
        if char in pairs:
            stack.append(char)
        elif char in pairs.values():
            if not stack or pairs[stack[-1]] != char:
                raise GuardError("unbalanced expanded ownership call")
            stack.pop()
            if not stack:
                end = index + 1
                break
        index += 1
    if end is None:
        raise GuardError("unterminated expanded ownership call")
    segment = output[position:end]
    tokens = lex(segment)
    if (len(tokens) < 2 or tokens[0].value != symbol
            or tokens[1].value != "("):
        raise GuardError("expanded ownership API is not a direct call")
    closing = len(tokens) - 1
    if tokens[closing].value != ")":
        raise GuardError("expanded ownership call lacks closing token")
    return canonical_arguments(split_arguments(tokens, 1, closing))


def expanded_occurrence(source: str, physical_line: int, symbol: str,
                        role: str, output: str,
                        position: int) -> OwnershipOccurrence:
    arguments = None
    if role.startswith("call:") or role == "expanded-or-unapproved":
        arguments = expanded_call_arguments(output, position, symbol)
    return OwnershipOccurrence(source, physical_line, symbol, role, arguments)


def preprocessed_project_occurrences(
        output: str, unit: CompileUnit, root: Path,
        build_root: Path) -> Counter[OwnershipOccurrence]:
    unit, root, build_root, unit_label = canonical_preprocessing_context(
        unit, root, build_root)
    marker_pattern = re.compile(
        r'(?m)^[ \t]*#[ \t]*(?:line[ \t]+)?([0-9]+)[ \t]+'
        r'"([^"\r\n]+)"(?:[ \t]+[^\r\n]*)?\r?$')
    marker_matches = list(marker_pattern.finditer(output))
    if not marker_matches:
        raise GuardError("preprocessor output contains no line markers")
    for candidate in re.finditer(
            r'(?m)^[ \t]*#[ \t]*(?:line\b|[0-9])[^\r\n]*$', output):
        if LINE_MARKER.fullmatch(candidate.group(0)) is None:
            raise GuardError("malformed preprocessor line marker")

    marker_starts = []
    markers = []
    saw_unit = False
    for match in marker_matches:
        content_start = match.end()
        if content_start < len(output) and output[content_start] == "\r":
            content_start += 1
        if content_start < len(output) and output[content_start] == "\n":
            content_start += 1
        source = canonical_provenance(
            match.group(2), unit.directory, root, build_root)
        saw_unit = saw_unit or source == unit_label
        marker_starts.append(content_start)
        markers.append((source, int(match.group(1)), match.start()))
    if not saw_unit:
        raise GuardError("preprocessor output contains no source marker")

    sensitive_sources = set()
    sensitive = re.compile(
        r"(?:soup_server_add_[A-Za-z0-9_]*handler|"
        r"[A-Za-z_][A-Za-z0-9_]*add_(?:exact|prefix|singleton)_handler)")
    for match in sensitive.finditer(output):
        marker_index = bisect.bisect_right(marker_starts, match.start()) - 1
        if marker_index >= 0 and markers[marker_index][0] is not None:
            sensitive_sources.add(markers[marker_index][0])

    streams: dict[str, list[str]] = {}
    line_maps: dict[str, list[int]] = {}
    for index, (source, physical_line, _marker_start) in enumerate(markers):
        if source not in sensitive_sources:
            continue
        content_end = (markers[index + 1][2]
                       if index + 1 < len(markers) else len(output))
        fragment = output[marker_starts[index]:content_end]
        lines = fragment.splitlines()
        streams.setdefault(source, []).extend(line + "\n" for line in lines)
        line_maps.setdefault(source, []).extend(
            physical_line + offset for offset in range(len(lines)))

    result: Counter[OwnershipOccurrence] = Counter()
    for source, fragments in streams.items():
        source_text = "".join(fragments)
        if not any(needle in source_text for needle in (
                "soup_server_add_", "add_exact_handler",
                "add_prefix_handler", "add_singleton_handler")):
            continue
        tokens = lex(source_text)
        pairing = mates(tokens)
        line_map = line_maps[source]
        result.update(ownership_occurrences(
            tokens, pairing,
            lambda line, source=source, line_map=line_map:
            (source, line_map[line - 1])))
    return result


def preprocessed_ownership_occurrences(
        output: str, unit: CompileUnit, root: Path, build_root: Path,
        raw_roles: dict[tuple[str, int, str], str]) \
        -> Counter[OwnershipOccurrence]:
    unit, root, build_root, unit_label = canonical_preprocessing_context(
        unit, root, build_root)
    marker_pattern = re.compile(
        r'(?m)^[ \t]*#[ \t]*(?:line[ \t]+)?([0-9]+)[ \t]+'
        r'"([^"\r\n]+)"(?:[ \t]+[^\r\n]*)?\r?$')
    marker_starts = []
    markers = []
    saw_unit = False
    for marker in marker_pattern.finditer(output):
        source = canonical_provenance(
            marker.group(2), unit.directory, root, build_root)
        if source == unit_label:
            saw_unit = True
        content_start = marker.end()
        if content_start < len(output) and output[content_start] == "\r":
            content_start += 1
        if content_start < len(output) and output[content_start] == "\n":
            content_start += 1
        marker_starts.append(content_start)
        markers.append((source, int(marker.group(1))))
    if not markers:
        raise GuardError("preprocessor output contains no line markers")
    if not saw_unit:
        raise GuardError("preprocessor output contains no source marker")
    for candidate in re.finditer(
            r'(?m)^[ \t]*#[ \t]*(?:line\b|[0-9])[^\r\n]*$', output):
        if LINE_MARKER.fullmatch(candidate.group(0)) is None:
            raise GuardError("malformed preprocessor line marker")

    sensitive = re.compile(
        r"(?:soup_server_add_[A-Za-z0-9_]*handler|"
        r"[A-Za-z_][A-Za-z0-9_]*add_(?:exact|prefix|singleton)_handler)")
    result: Counter[OwnershipOccurrence] = Counter()
    visited_lines = set()
    for match in sensitive.finditer(output):
        line_start = output.rfind("\n", 0, match.start()) + 1
        if line_start in visited_lines:
            continue
        visited_lines.add(line_start)
        marker_index = bisect.bisect_right(marker_starts, line_start) - 1
        if marker_index < 0:
            continue
        source, marker_line = markers[marker_index]
        if source is None:
            continue
        line_end = output.find("\n", line_start)
        if line_end < 0:
            line_end = len(output)
        line_text = output[line_start:line_end]
        tokens = lex(line_text)
        physical_line = marker_line + output.count(
            "\n", marker_starts[marker_index], line_start)
        for index, token in enumerate(tokens):
            if (token.kind != "identifier"
                    or OWNERSHIP_API.fullmatch(token.value) is None):
                continue
            key = (source, physical_line, token.value)
            role = raw_roles.get(key, "expanded-or-unapproved")
            if index + 1 >= len(tokens) or tokens[index + 1].value != "(":
                role = "expanded-or-unapproved"
            token_position = line_start + token.offset
            result[expanded_occurrence(source, physical_line, token.value,
                                       role, output, token_position)] += 1
    return result


def preprocess_unit(unit: CompileUnit, root: Path, build_root: Path,
                    compiler_id: str) \
        -> Counter[OwnershipOccurrence]:
    # Compiler line markers are canonical filesystem paths.  Keep their
    # comparison roots canonical too: macOS exposes /var through /private/var,
    # and callers may otherwise supply an equivalent path containing `..`.
    root = root.resolve()
    build_root = build_root.resolve()
    unit = CompileUnit(unit.source.resolve(), unit.directory.resolve(),
                       unit.arguments)
    command = semantic_command(list(unit.arguments), unit.directory,
                               unit.source, compiler_id)
    try:
        completed = subprocess.run(
            command, cwd=unit.directory, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False)
    except OSError as error:
        raise GuardError(f"preprocessor execution failed: {error}") from error
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace")
        raise GuardError(f"preprocessor rejected "
                         f"{render_source_identity(unit.source)}: "
                         f"{diagnostic}")
    try:
        output = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise GuardError(f"preprocessor emitted non-UTF-8 output: "
                         f"{render_source_identity(unit.source)}") from error
    unit_marker = f'"{unit.source}"'
    if unit_marker not in output:
        alternates = {
            unit_marker.replace("\\", "/"),
            unit_marker.replace("\\", "\\\\"),
        }
        if not any(alternate in output for alternate in alternates):
            raise GuardError("preprocessor output contains no source marker")

    if not any(needle in output for needle in (
            "soup_server_add_", "add_exact_handler",
            "add_prefix_handler", "add_singleton_handler")):
        return Counter()

    return preprocessed_project_occurrences(output, unit, root, build_root)


def semantic_occurrences(root: Path, build_root: Path,
                         compiler_id: str, units: list[CompileUnit]) \
        -> Counter[OwnershipOccurrence]:
    workers = min(8, max(1, len(units)))
    result: Counter[OwnershipOccurrence] = Counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(preprocess_unit, unit, root, build_root,
                                   compiler_id) for unit in units]
        for future in futures:
            result.update(future.result())
    return result


def verify_semantic_counters(raw: Counter[OwnershipOccurrence],
                             expanded: Counter[OwnershipOccurrence],
                             allowed_missing: Counter[OwnershipOccurrence]) \
        -> None:
    missing_counter = raw - expanded
    unexpected_counter = expanded - raw
    if missing_counter != allowed_missing or unexpected_counter:
        missing = list(missing_counter.elements())[:8]
        allowed = list(allowed_missing.elements())[:8]
        unexpected = list(unexpected_counter.elements())[:8]
        raise GuardError("preprocessed ownership map differs from raw approval; "
                         f"missing={missing!r}; allowed_missing={allowed!r}; "
                         f"unexpected={unexpected!r}")


def check_semantic_boundary(root: Path, build_root: Path,
                            compiler_id: str) -> None:
    units = production_compile_units(root, build_root, compiler_id)
    daemon_http = (root / "wyrelog" / "daemon" / "http.c").resolve()
    daemon_unit = next(unit for unit in units if unit.source == daemon_http)
    enabled = compile_unit_enabled_features(daemon_unit, compiler_id)
    raw = raw_approved_occurrences(root, build_root)
    expanded = semantic_occurrences(
        root, build_root, compiler_id, units)
    allowed_missing = raw_disabled_feature_occurrences(root, enabled)
    verify_semantic_counters(raw, expanded, allowed_missing)


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


def expect_guard_error(callback, message: str) -> None:
    try:
        callback()
    except GuardError:
        return
    raise GuardError(f"negative fixture accepted: {message}")


def expect_guard_error_message(callback, expected: str, message: str) -> None:
    try:
        callback()
    except GuardError as error:
        if str(error) != expected:
            raise GuardError(
                f"negative fixture returned the wrong error: {message}: "
                f"expected={expected!r}; actual={str(error)!r}") from error
        return
    raise GuardError(f"negative fixture accepted: {message}")


def expect_guard_error_contains(callback, fragments: tuple[str, ...],
                                message: str) -> None:
    try:
        callback()
    except GuardError as error:
        actual = str(error)
        missing = [fragment for fragment in fragments
                   if fragment not in actual]
        if missing:
            raise GuardError(
                f"negative fixture returned the wrong error: {message}: "
                f"missing={missing!r}; actual={actual!r}") from error
        return
    raise GuardError(f"negative fixture accepted: {message}")


def semantic_fixture_result(root: Path, build_root: Path, source: Path,
                            marked: Path, symbol: str,
                            marker_style: str = "gcc") \
        -> Counter[OwnershipOccurrence]:
    unit = CompileUnit(source.resolve(), root.resolve(), ("cc", str(source)))
    source_directive = (f'#line 1 "{source.resolve()}"'
                        if marker_style == "clang-cl"
                        else f'# 1 "{source.resolve()}"')
    directive = (f'#line 17 "{marked.resolve()}"'
                 if marker_style == "clang-cl"
                 else f'# 17 "{marked.resolve()}"')
    output = source_directive + "\n" + directive \
        + f"\n{symbol}(server, \"/hidden\", callback, " \
        "data, NULL);\n"
    return preprocessed_ownership_occurrences(
        output, unit, root.resolve(), build_root.resolve(), {})


def self_test_compile_unit(source: Path, root: Path, build_root: Path,
                           compiler_id: str, compiler: tuple[str, ...],
                           extra: tuple[str, ...] = (),
                           output: Path | None = None) -> CompileUnit:
    if output is None:
        output = build_root / "wyrelog" / "daemon" / "http.c.o"
    output.parent.mkdir(parents=True, exist_ok=True)
    if compiler_id in {"clang-cl", "msvc"}:
        arguments = (*compiler, *extra, f"/Fo{output}", "/c", str(source))
    else:
        arguments = (*compiler, *extra, "-o", str(output), "-c", str(source))
    return CompileUnit(source.resolve(), root.resolve(), arguments)


def self_test_compile_entry(source: Path, root: Path, build_root: Path,
                            compiler_id: str, compiler: tuple[str, ...],
                            output: str,
                            extra: tuple[str, ...] = ()) -> dict[str, object]:
    output_path = build_root / output
    unit = self_test_compile_unit(
        source, root, build_root, compiler_id, compiler, extra, output_path)
    return {
        "directory": str(build_root),
        "file": str(source),
        "output": output,
        "arguments": list(unit.arguments),
    }


def write_self_test_compile_database(build_root: Path,
                                     entries: object) -> None:
    build_root.mkdir(parents=True, exist_ok=True)
    write_exact_fixture(
        build_root / "compile_commands.json",
        json.dumps(entries, ensure_ascii=True) + "\n")


def self_test_production_compile_selection(
        root: Path, source: Path, compiler_id: str,
        compiler: tuple[str, ...]) -> None:
    for dialect, expected, other in (
            ("gcc", "wyrelog/wyrelogd.p/daemon_http.c.o",
             "wyrelog/wyrelogd.exe.p/daemon_http.c.obj"),
            ("clang", "wyrelog/wyrelogd.p/daemon_http.c.o",
             "wyrelog/wyrelogd.exe.p/daemon_http.c.obj"),
            ("clang-cl", "wyrelog/wyrelogd.exe.p/daemon_http.c.obj",
             "wyrelog/wyrelogd.p/daemon_http.c.o"),
            ("msvc", "wyrelog/wyrelogd.exe.p/daemon_http.c.obj",
             "wyrelog/wyrelogd.p/daemon_http.c.o")):
        if not is_production_daemon_output(expected, dialect):
            raise GuardError(
                f"canonical {dialect} production target was not selected")
        for lookalike in (
                other,
                expected.replace("wyrelogd", "wyrelogd-helper", 1),
                expected.replace("/daemon_http", "/nested/daemon_http", 1),
                expected.replace(
                    "wyrelogd", "wyrelogd-readiness-persistent-test", 1)):
            if is_production_daemon_output(lookalike, dialect):
                raise GuardError(
                    f"{dialect} production target lookalike was selected")
    expect_guard_error_message(
        lambda: is_production_daemon_output(
            "wyrelog/wyrelogd.p/daemon_http.c.o", "unknown"),
        "unsupported compiler dialect: unknown",
        "unknown production target compiler dialect")

    windows = compiler_id in {"clang-cl", "msvc"}
    target = ("wyrelog/wyrelogd.exe.p" if windows
              else "wyrelog/wyrelogd.p")
    other_target = ("wyrelog/wyrelogd.p" if windows
                    else "wyrelog/wyrelogd.exe.p")
    readiness_target = ("wyrelog/wyrelogd-readiness-persistent-test.exe.p"
                        if windows else
                        "wyrelog/wyrelogd-readiness-persistent-test.p")
    suffix = ".obj" if windows else ".o"
    production_output = f"{target}/daemon_http.c{suffix}"
    readiness_output = f"{readiness_target}/daemon_http.c{suffix}"
    define = "/D" if windows else "-D"
    build_root = root / "compile-selection-build"

    production = self_test_compile_entry(
        source, root, build_root, compiler_id, compiler, production_output,
        (f"{define}{FACT}",))
    readiness = self_test_compile_entry(
        source, root, build_root, compiler_id, compiler, readiness_output,
        (f"{define}{AUDIT}",
         f"{define}WYL_TEST_PERSISTENT_READINESS_STORE"))
    write_self_test_compile_database(build_root, [production, readiness])
    units = production_compile_units(root, build_root, compiler_id)
    daemon_units = [unit for unit in units if unit.source == source.resolve()]
    if len(daemon_units) != 1:
        raise GuardError(
            "production-plus-readiness fixture did not select one HTTP unit")
    if compile_unit_enabled_features(
            daemon_units[0], compiler_id) != frozenset({FACT}):
        raise GuardError(
            "readiness feature flags contaminated production HTTP selection")
    check_semantic_boundary(root, build_root, compiler_id)

    audit_only = self_test_compile_entry(
        source, root, build_root, compiler_id, compiler, production_output,
        (f"{define}{AUDIT}",))
    conflicting_readiness = self_test_compile_entry(
        source, root, build_root, compiler_id, compiler, readiness_output,
        (f"{define}{FACT}",
         f"{define}WYL_TEST_PERSISTENT_READINESS_STORE"))
    write_self_test_compile_database(
        build_root, [audit_only, conflicting_readiness])
    units = production_compile_units(root, build_root, compiler_id)
    daemon_unit = next(unit for unit in units
                       if unit.source == source.resolve())
    if compile_unit_enabled_features(
            daemon_unit, compiler_id) != frozenset({AUDIT}):
        raise GuardError("fact flags contaminated audit-only HTTP selection")
    check_semantic_boundary(root, build_root, compiler_id)

    write_self_test_compile_database(build_root, [readiness])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "production daemon HTTP translation unit is missing",
        "readiness-only compile database")

    duplicate = self_test_compile_entry(
        source, root, build_root, compiler_id, compiler,
        f"{target}/daemon_http_duplicate.c{suffix}")
    write_self_test_compile_database(build_root, [production, duplicate])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "ambiguous production daemon HTTP translation unit",
        "two canonical production HTTP contexts")

    write_self_test_compile_database(build_root, [production, production])
    duplicate_path = (build_root / production_output).resolve()
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "ambiguous production compile output: "
        f"{render_source_identity(duplicate_path)}",
        "duplicate canonical production output")

    wrong_dialect = dict(production)
    wrong_dialect["output"] = (
        f"{other_target}/daemon_http.c{suffix}")
    write_self_test_compile_database(build_root, [wrong_dialect])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "production daemon HTTP translation unit is missing",
        "cross-dialect production target")
    for name, lookalike in {
        "prefixed target": f"{target}-helper/daemon_http.c{suffix}",
        "nested target": f"{target}/nested/daemon_http.c{suffix}",
        "readiness target": readiness_output,
    }.items():
        entry = dict(production)
        entry["output"] = lookalike
        write_self_test_compile_database(build_root, [entry])
        expect_guard_error_message(
            lambda: production_compile_units(root, build_root, compiler_id),
            "production daemon HTTP translation unit is missing", name)

    database = build_root / "compile_commands.json"
    write_exact_fixture(database, "{\n")
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "invalid compile database", "malformed JSON database")
    write_self_test_compile_database(build_root, {})
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "compile database root must be an array", "non-array database")
    write_self_test_compile_database(build_root, [None])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "invalid compile database entry", "non-dictionary database entry")

    missing_output = dict(production)
    del missing_output["output"]
    write_self_test_compile_database(build_root, [missing_output])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        'production compile entry lacks output: "wyrelog/daemon/http.c"',
        "production entry missing output")

    invalid_arguments = dict(production)
    invalid_arguments["arguments"] = [1]
    write_self_test_compile_database(build_root, [invalid_arguments])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "invalid compile entry arguments", "invalid arguments list")
    missing_command = dict(production)
    del missing_command["arguments"]
    write_self_test_compile_database(build_root, [missing_command])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "compile entry lacks arguments/command", "missing compiler command")

    for dialect, target_dir, command in (
            ("gcc", "wyrelog/wyrelogd.p", "cc '"),
            ("clang-cl", "wyrelog/wyrelogd.exe.p", 'clang-cl "')):
        invalid_quoting = dict(production)
        invalid_quoting["output"] = (
            f"{target_dir}/daemon_http.c"
            + (".obj" if dialect == "clang-cl" else ".o"))
        del invalid_quoting["arguments"]
        invalid_quoting["command"] = command
        write_self_test_compile_database(build_root, [invalid_quoting])
        expect_guard_error_message(
            lambda dialect=dialect: production_compile_units(
                root, build_root, dialect),
            "invalid compiler command quoting",
            f"{dialect} compiler command quoting")

    escaping_output = dict(production)
    escaping_output["output"] = str(root.parent / "escaped-http.o")
    write_self_test_compile_database(build_root, [escaping_output])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        'production compile output escapes build root: '
        '"wyrelog/daemon/http.c"',
        "project compile output escaping build root")

    outside_source = root.parent / "outside-http.c"
    target_claim = dict(production)
    target_claim["file"] = str(outside_source)
    write_self_test_compile_database(build_root, [target_claim])
    expect_guard_error_message(
        lambda: production_compile_units(root, build_root, compiler_id),
        "production target compile entry has non-project source: "
        f"{render_source_identity(outside_source.resolve())}",
        "production target claiming an outside source")

    generated = build_root / "generated" / "hidden-route.h"
    generated.parent.mkdir(parents=True, exist_ok=True)
    write_exact_fixture(
        generated,
        "#define CAT_RAW(a,b) a ## b\n"
        "#define CAT(a,b) CAT_RAW(a,b)\n"
        "#define HIDDEN_ADD CAT(soup_server_add_,handler)\n")
    library = root / "wyrelog" / "library.c"
    write_exact_fixture(
        library,
        "static void hidden_library_owner(void) {\n"
        "  HIDDEN_ADD(server, \"/hidden\", callback, data, NULL);\n"
        "}\n")
    forced = ((f"/FI{generated}",) if windows
              else ("-include", str(generated)))
    library_output = (
        "wyrelog/libwyrelog.dll.p/library.c.obj" if windows else
        "wyrelog/libwyrelog.so.0.p/library.c.o")
    library_entry = self_test_compile_entry(
        library, root, build_root, compiler_id, compiler, library_output,
        forced)
    write_self_test_compile_database(
        build_root, [production, readiness, library_entry])
    expect_guard_error_contains(
        lambda: check_semantic_boundary(root, build_root, compiler_id),
        ("preprocessed ownership map differs", "wyrelog/library.c", SOUP_API),
        "non-daemon production semantic inventory")
    library.unlink()
    generated.unlink()


def self_test_preprocess(source: Path, root: Path, build_root: Path,
                         compiler_id: str, compiler: tuple[str, ...],
                         extra: tuple[str, ...] = ()) \
        -> Counter[OwnershipOccurrence]:
    unit = self_test_compile_unit(
        source, root, build_root, compiler_id, compiler, extra)
    return preprocess_unit(unit, root, build_root, compiler_id)


def write_exact_fixture(path: Path, source: str) -> None:
    expected = source.encode("utf-8")
    if path.write_bytes(expected) != len(expected):
        raise GuardError("short self-test fixture write")
    if path.read_bytes() != expected:
        raise GuardError("self-test fixture bytes changed during write")


def self_test(compiler_id: str, compiler: tuple[str, ...]) -> None:
    # #776: a hostile filename must not forge, merge, or suppress a daemon
    # route-registration diagnostic.  reject_line_marker_spoofing renders the
    # offending path through the shared ASCII-safe renderer, so every hostile
    # spelling stays a single ASCII physical line whose rendered identity is
    # present verbatim (and therefore round-trips) in the emitted message.
    hostile_fragments = (
        "\n", "\r", "\t", "\x1b", "\\", "'", "\"", "‮", "а")
    hostile_messages = []
    for fragment in hostile_fragments:
        hostile_path = Path("wyrelog/a" + fragment + "b.c")
        try:
            reject_line_marker_spoofing("# 1\n", hostile_path)
        except GuardError as error:
            message = str(error)
        else:
            raise GuardError("self-test accepted a hostile line marker")
        if "\n" in message or "\r" in message:
            raise GuardError("self-test emitted a multi-line route diagnostic")
        if not message.isascii():
            raise GuardError("self-test emitted a non-ASCII route diagnostic")
        if render_source_identity(hostile_path) not in message:
            raise GuardError("self-test lost the hostile route identity")
        hostile_messages.append(message)
    # A newline spelling cannot fabricate a second diagnostic line, nor merge
    # with the distinct literal backslash-n sibling.
    newline_message = hostile_messages[0]
    try:
        reject_line_marker_spoofing("# 1\n", Path("wyrelog/a\\nb.c"))
    except GuardError as error:
        literal_message = str(error)
    else:
        raise GuardError("self-test accepted a literal backslash-n marker")
    if newline_message == literal_message:
        raise GuardError("self-test merged newline and backslash-n route paths")

    # #792: a rejected route string-literal must not forge, merge, or suppress
    # the literal_path diagnostic either.  literal_path renders the offending
    # token through the same ASCII-safe identity, so every hostile spelling
    # stays a single ASCII physical line whose rendered identity round-trips.
    route_messages = []
    for fragment in hostile_fragments:
        hostile_raw = '"/a' + fragment + 'b"'
        try:
            literal_path([Token("string", hostile_raw, 1, 0)])
        except GuardError as error:
            message = str(error)
        else:
            raise GuardError("self-test accepted a hostile route literal")
        if "\n" in message or "\r" in message:
            raise GuardError("self-test emitted a multi-line route literal")
        if not message.isascii():
            raise GuardError("self-test emitted a non-ASCII route literal")
        if render_source_identity(hostile_raw) not in message:
            raise GuardError("self-test lost the hostile route literal identity")
        route_messages.append(message)
    # A raw-newline literal cannot merge with the distinct backslash-n sibling.
    route_newline_message = route_messages[0]
    try:
        literal_path([Token("string", '"/a\\nb"', 1, 0)])
    except GuardError as error:
        route_literal_message = str(error)
    else:
        raise GuardError("self-test accepted a literal backslash-n route literal")
    if route_newline_message == route_literal_message:
        raise GuardError(
            "self-test merged newline and backslash-n route literals")

    with tempfile.TemporaryDirectory(prefix="wyl-route-guard-") as temporary:
        root = Path(temporary)
        daemon = root / "wyrelog" / "daemon"
        daemon.mkdir(parents=True)
        source_path = daemon / "http.c"
        baseline = fixture_source()
        write_exact_fixture(source_path, baseline)
        check_root(root)
        self_test_production_compile_selection(
            root, source_path, compiler_id, compiler)
        bounded_arguments = expanded_call_arguments(
            f'{EXACT_API}(server, "/healthz", healthz_handler, NULL, NULL);\n'
            '"unterminated tail', 0, EXACT_API)
        if bounded_arguments != (
                "server", '"/healthz"', "healthz_handler", "NULL", "NULL"):
            raise GuardError("expanded call parser consumed the TU tail")

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
        splice_prefixes = {
            "LF identifier splice":
                b"#define HIDDEN_ADD soup_server_add_\\\nhandler\n",
            "CRLF identifier splice":
                b"#define HIDDEN_ADD soup_server_add_\\\r\nhandler\r\n",
        }
        for name, prefix in splice_prefixes.items():
            if not mutants[name].encode("utf-8").startswith(prefix):
                raise GuardError(f"{name} fixture bytes changed")
        for name, mutant in mutants.items():
            write_exact_fixture(source_path, mutant)
            expect_failure(root, name)

        # #799: a registrar whose enclosing function name carries a non-ASCII
        # homoglyph (the owner token is lexed with Unicode-aware isalpha) must
        # be rejected with a single-line ASCII diagnostic whose rendered owner
        # identity round-trips -- the homoglyph cannot leak raw into stderr.
        homoglyph_owner = "аbc"  # Cyrillic 'a' (U+0430) then b, c.
        homoglyph_source = baseline + (
            f"static void {homoglyph_owner}(void) {{\n"
            f"  {EXACT_API} /* registration */ ( server, \"/hidden\", "
            "callback, data, NULL );\n"
            "}\n")
        if homoglyph_owner.isascii():
            raise GuardError("homoglyph owner fixture is not homoglyphic")
        write_exact_fixture(source_path, homoglyph_source)
        try:
            check_root(root)
        except GuardError as error:
            owner_message = str(error)
        else:
            raise GuardError("self-test accepted a homoglyph registrar owner")
        if "\n" in owner_message or "\r" in owner_message:
            raise GuardError("self-test emitted a multi-line owner diagnostic")
        if not owner_message.isascii():
            raise GuardError("self-test emitted a non-ASCII owner diagnostic")
        if escape_ascii_identity(homoglyph_owner) not in owner_message:
            raise GuardError("self-test lost the hostile owner identity")

        hidden_header = daemon / "hidden-route.h"
        write_exact_fixture(
            hidden_header, "#define HIDDEN_ADD soup_server_add_handler\n")
        header_alias = baseline.replace(
            "static void wyl_daemon_start_http_server_with_runtime(void) {",
            "#include \"hidden-route.h\"\n"
            "static void wyl_daemon_start_http_server_with_runtime(void) {\n"
            "  HIDDEN_ADD(server, \"/hidden\", callback, data, NULL);", 1)
        write_exact_fixture(source_path, header_alias)
        expect_failure(root, "included project-header alias")
        hidden_header.unlink()

        write_exact_fixture(
            hidden_header,
            "static inline void hidden_add(void) {\n"
            "  soup_server_add_handler(server, \"/hidden\", callback, "
            "data, NULL);\n"
            "}\n")
        write_exact_fixture(
            source_path, '#include "hidden-route.h"\n' + baseline)
        expect_failure(root, "project-header inline registration")
        hidden_header.unlink()

        hidden_include = daemon / "hidden-route.inc"
        write_exact_fixture(
            hidden_include,
            "soup_server_add_\\\nhandler(server, \"/hidden\", callback, "
            "data, NULL);\n")
        write_exact_fixture(source_path, baseline)
        expect_failure(root, "project inc splice registration")
        hidden_include.unlink()

        for wrapper in (PREFIX_API, RAW_SINGLETON_API, EXACT_API):
            write_exact_fixture(
                hidden_header, f"#define HIDDEN_ADD {wrapper}\n")
            write_exact_fixture(source_path, header_alias)
            expect_failure(root, f"project-header {wrapper} alias")
            hidden_header.unlink()

        write_exact_fixture(source_path, baseline)
        semantic_macros = {
            "one-level generic paste": (
                "#define CAT_RAW(a,b) a ## b\n"
                "#define HIDDEN_ADD CAT_RAW(soup_server_, add_handler)\n",
                SOUP_API),
            "two-level paste": (
                "#define A soup_server_\n#define B add_handler\n"
                "#define CAT_RAW(a,b) a ## b\n"
                "#define CAT(a,b) CAT_RAW(a,b)\n"
                "#define HIDDEN_ADD CAT(A,B)\n", SOUP_API),
            "three-token paste": (
                "#define CAT3_RAW(a,b,c) a ## b ## c\n"
                "#define CAT3(a,b,c) CAT3_RAW(a,b,c)\n"
                "#define HIDDEN_ADD CAT3(soup_,server_add_,handler)\n",
                SOUP_API),
            "argument-fragment exact wrapper": (
                "#define CAT_RAW(a,b) a ## b\n"
                "#define CAT(a,b) CAT_RAW(a,b)\n"
                "#define HIDDEN_ADD CAT(wyl_daemon_http_add_,exact_handler)\n",
                EXACT_API),
            "argument-fragment prefix wrapper": (
                "#define CAT_RAW(a,b) a ## b\n"
                "#define CAT(a,b) CAT_RAW(a,b)\n"
                "#define HIDDEN_ADD CAT(wyl_daemon_http_add_,prefix_handler)\n",
                PREFIX_API),
            "argument-fragment singleton wrapper": (
                "#define CAT_RAW(a,b) a ## b\n"
                "#define CAT(a,b) CAT_RAW(a,b)\n"
                "#define HIDDEN_ADD CAT(wyl_daemon_http_add_,singleton_handler)\n",
                RAW_SINGLETON_API),
        }
        server_anchor = (
            "static void wyl_daemon_start_http_server_with_runtime(void) {")
        hidden_call = (
            server_anchor + "\n  HIDDEN_ADD(server, \"/hidden\", callback, "
            "data, NULL);")
        for name, (macros, symbol) in semantic_macros.items():
            semantic_source = macros + baseline.replace(
                server_anchor, hidden_call, 1)
            write_exact_fixture(source_path, semantic_source)
            check_root(root)
            result = semantic_fixture_result(
                root, root / "build", source_path, source_path, symbol)
            if not any(item.symbol == symbol
                       and item.role == "expanded-or-unapproved"
                       for item in result):
                raise GuardError(f"semantic fixture accepted: {name}")

        approved_health = (
            f'  {EXACT_API} /* registration */ ( server, "/healthz",'
            ' healthz_handler, NULL, NULL );')
        approved_health_call = approved_health.strip()[:-1]
        paste_macros = (
            "#define CAT_RAW(a,b) a ## b\n"
            "#define CAT(a,b) CAT_RAW(a,b)\n")
        consumed_expansions = {
            "consumed path": (
                f'{EXACT_API}(server, "/hidden", healthz_handler, NULL, NULL)',
                EXACT_API),
            "consumed callback": (
                f'{EXACT_API}(server, "/healthz", hidden_handler, NULL, NULL)',
                EXACT_API),
            "consumed data": (
                f'{EXACT_API}(server, "/healthz", healthz_handler, ctx, NULL)',
                EXACT_API),
            "consumed destroy": (
                f'{EXACT_API}(server, "/healthz", healthz_handler, NULL, '
                'hidden_destroy)', EXACT_API),
            "consumed wrapper": (
                f'{RAW_SINGLETON_API}(server, "/healthz", healthz_handler, '
                'NULL, NULL)', RAW_SINGLETON_API),
            "consumed Soup call": (
                f'{SOUP_API}(server, "/healthz", healthz_handler, NULL, NULL)',
                SOUP_API),
        }
        for name, (expansion, symbol) in consumed_expansions.items():
            if symbol == EXACT_API:
                macro_expansion = expansion.replace(
                    EXACT_API,
                    "CAT(wyl_daemon_http_add_,exact_handler)", 1)
            elif symbol == RAW_SINGLETON_API:
                macro_expansion = expansion.replace(
                    RAW_SINGLETON_API,
                    "CAT(wyl_daemon_http_add_,singleton_handler)", 1)
            else:
                macro_expansion = expansion.replace(
                    SOUP_API, "CAT(soup_server_,add_handler)", 1)
            replacement = (
                paste_macros
                + f"#define REPLACE(ignored) {macro_expansion}\n")
            mutant = replacement + baseline.replace(
                approved_health, f"  REPLACE({approved_health_call});", 1)
            write_exact_fixture(source_path, mutant)
            expect_failure(root, f"{name} raw macro argument")
            expanded = self_test_preprocess(
                source_path, root, root / "build", compiler_id, compiler)
            expected_health_arguments = (
                "server", '"/healthz"', "healthz_handler", "NULL", "NULL")
            if not any(item.symbol == symbol
                       and item.arguments is not None
                       and (item.symbol != EXACT_API
                            or item.arguments != expected_health_arguments)
                       for item in expanded):
                raise GuardError(f"real compiler fixture did not expand: {name}")

        control_expansions = {
            "if false": "if (0) {call}",
            "if true": "if (1) {call}",
            "while false": "while (0) {call}",
            "for false": "for (; 0 ;) {call}",
            "short circuit": "0 && ({call}, 0)",
            "sizeof": "sizeof (({call}, 0))",
            "ternary": "0 ? ({call}, 0) : 0",
            "comma expression": "(0, {call})",
            "do wrapper": "do {{ {call}; }} while (0)",
            "nested consuming macro": "if (1) do {{ {call}; }} while (0)",
        }
        emitted = (
            "CAT(wyl_daemon_http_add_,exact_handler)"
            "(server,\"/healthz\",healthz_handler,NULL,NULL)")
        for name, template in control_expansions.items():
            macro_body = template.format(call=emitted)
            mutant = (paste_macros
                      + f"#define REPLACE(ignored) {macro_body}\n"
                      + baseline.replace(
                          approved_health,
                          f"  REPLACE({approved_health_call});", 1))
            write_exact_fixture(source_path, mutant)
            expect_failure(root, f"{name} raw context")
            expect_guard_error(
                lambda: self_test_preprocess(
                    source_path, root, root / "build", compiler_id,
                    compiler), f"{name} expanded context")

        enveloped = ("#define BEFORE if (0) {\n#define AFTER }\n"
                     + baseline.replace(
                         server_anchor, server_anchor + "\n  BEFORE;", 1)
                     .replace(approved_health,
                              approved_health + "\n  AFTER;", 1))
        write_exact_fixture(source_path, enveloped)
        check_root(root)
        expect_guard_error(
            lambda: self_test_preprocess(
                source_path, root, root / "build", compiler_id, compiler),
            "expanded control envelope around raw-direct call")

        write_exact_fixture(source_path, baseline)
        alias_root = root / "wyrelog" / ".."
        alias_source = alias_root / "wyrelog" / "daemon" / "http.c"
        aliased = self_test_preprocess(
            alias_source, alias_root, alias_root / "build", compiler_id,
            compiler)
        if not any(item.source == "wyrelog/daemon/http.c"
                   for item in aliased):
            raise GuardError("canonical root alias lost source provenance")
        outside = root.parent / (root.name + "-outside.c")
        if semantic_fixture_result(
                root, root / "build", source_path, outside, SOUP_API):
            raise GuardError("outside source gained project provenance")
        raw = raw_approved_occurrences(root, root / "build")
        feature_sets = (
            frozenset(), frozenset({AUDIT}), frozenset({FACT}),
            frozenset({AUDIT, FACT}),
        )
        for enabled in feature_sets:
            allowed = raw_disabled_feature_occurrences(root, enabled)
            expanded = raw - allowed
            verify_semantic_counters(raw, expanded, allowed)
            for active_feature in (None, *sorted(enabled)):
                dropped = next(
                    item for item in expanded
                    if item.role == f"call:{SERVER_OWNER}"
                    and item.arguments is not None
                    and EXPECTED_BY_PATH.get(item.arguments[1][1:-1],
                                             RouteSpec("", "")).feature
                    == active_feature)
                expect_guard_error(
                    lambda raw=raw,
                    expanded=expanded - Counter({dropped: 1}),
                    allowed=allowed: verify_semantic_counters(
                        raw, expanded, allowed),
                    f"active feature occurrence missing: {sorted(enabled)}")

        nested = daemon / "nested-route.h"
        inner = daemon / "inner-route.h"
        write_exact_fixture(inner, semantic_macros["two-level paste"][0])
        write_exact_fixture(nested, '#include "inner-route.h"\n')
        write_exact_fixture(
            source_path, '#include <nested-route.h>\n' + baseline.replace(
                server_anchor, hidden_call, 1))
        check_root(root)
        result = semantic_fixture_result(
            root, root / "build", source_path, inner, SOUP_API, "clang-cl")
        if not result:
            raise GuardError("nested angle-header semantic alias accepted")
        include_args = ((f"/I{daemon}",)
                        if compiler_id in {"clang-cl", "msvc"}
                        else ("-I", str(daemon)))
        real_nested = self_test_preprocess(
            source_path, root, root / "build", compiler_id, compiler,
            include_args)
        if not any(item.symbol == SOUP_API for item in real_nested):
            raise GuardError("real compiler nested-header alias missed")
        nested.unlink()
        inner.unlink()

        forced = daemon / "forced-route.h"
        write_exact_fixture(forced, semantic_macros["two-level paste"][0])
        generated_root = root / "build" / "generated"
        generated_root.mkdir(parents=True)
        generated = generated_root / "route-config.h"
        write_exact_fixture(generated, semantic_macros["three-token paste"][0])
        write_exact_fixture(source_path, baseline.replace(
            server_anchor, hidden_call, 1))
        check_root(root)
        if not semantic_fixture_result(
                root, root / "build", source_path, forced, SOUP_API):
            raise GuardError("forced-header semantic alias accepted")
        generated_result = semantic_fixture_result(
            root, root / "build", source_path, generated, SOUP_API)
        if not any(item.source.startswith("@build/")
                   for item in generated_result):
            raise GuardError("generated-header semantic alias accepted")
        forced_args = ((f"/FI{forced}",)
                       if compiler_id in {"clang-cl", "msvc"}
                       else ("-include", str(forced)))
        real_forced = self_test_preprocess(
            source_path, root, root / "build", compiler_id, compiler,
            forced_args)
        if not any(item.symbol == SOUP_API for item in real_forced):
            raise GuardError("real compiler forced-header alias missed")
        generated_args = ((f"/FI{generated}",)
                          if compiler_id in {"clang-cl", "msvc"}
                          else ("-include", str(generated)))
        real_generated = self_test_preprocess(
            source_path, root, root / "build", compiler_id, compiler,
            generated_args)
        if not any(item.source.startswith("wyrelog/")
                   and item.symbol == SOUP_API for item in real_generated):
            raise GuardError("real compiler generated-header alias missed")
        forced.unlink()

        gcc_command = semantic_command(
            ["cc", "-I", "include", "-include", "forced-route.h", "-MD",
             "-MF", "dep.d", "-o", "out.o", "-c", str(source_path)],
            root, source_path.resolve(), "gcc")
        if gcc_command[-4:] != ["-E", "-x", "c", str(source_path.resolve())]:
            raise GuardError("GCC-like semantic command fixture failed")
        if "-include" not in gcc_command or "forced-route.h" not in gcc_command:
            raise GuardError("GCC forced include was not retained")
        clang_cl_command = semantic_command(
            ["clang-cl", "/Iinclude", "/FIforced-route.h", "/Foout.obj",
             "/c", str(source_path)], root, source_path.resolve(), "clang-cl")
        if clang_cl_command[-4:] != [
                "/nologo", "/E", "/TC", str(source_path.resolve())]:
            raise GuardError("clang-cl semantic command fixture failed")
        if ("/Iinclude" not in clang_cl_command
                or "/FIforced-route.h" not in clang_cl_command):
            raise GuardError("clang-cl include option was not retained")
        response = root / "compiler.rsp"
        response.write_text("-DROUTE_SEMANTIC=1\n", encoding="utf-8")
        response_command = semantic_command(
            ["cc", f"@{response}", str(source_path)], root,
            source_path.resolve(), "gcc")
        if "-DROUTE_SEMANTIC=1" not in response_command:
            raise GuardError("GCC response-file fixture failed")
        response.write_text('/DROUTE_SEMANTIC=1\n', encoding="utf-8")
        response_command = semantic_command(
            ["clang-cl", f"@{response}", str(source_path)], root,
            source_path.resolve(), "clang-cl")
        if "/DROUTE_SEMANTIC=1" not in response_command:
            raise GuardError("clang-cl response-file fixture failed")
        gcc_features = compile_unit_enabled_features(CompileUnit(
            source_path.resolve(), root,
            ("cc", f"-D{FACT}", f"-U{FACT}", "-D", AUDIT)), "gcc")
        if gcc_features != frozenset({AUDIT}):
            raise GuardError("GCC feature-definition fixture failed")
        clang_cl_features = compile_unit_enabled_features(CompileUnit(
            source_path.resolve(), root,
            ("clang-cl", f"/D{FACT}=1", "/D", AUDIT, f"/U{AUDIT}")),
            "clang-cl")
        if clang_cl_features != frozenset({FACT}):
            raise GuardError("clang-cl feature-definition fixture failed")
        response.unlink()
        expect_guard_error(
            lambda: semantic_command(["cc", str(source_path)], root,
                                     source_path.resolve(), "unknown"),
            "unknown compiler dialect")
        expect_guard_error(
            lambda: semantic_command(["cc", "@missing.rsp", str(source_path)],
                                     root, source_path.resolve(), "gcc"),
            "missing response file")
        expect_guard_error(
            lambda: preprocessed_ownership_occurrences(
                f"{SOUP_API}(server);\n",
                CompileUnit(source_path.resolve(), root, ()), root,
                root / "build", {}),
            "missing preprocessor marker")
        expect_guard_error(
            lambda: preprocessed_ownership_occurrences(
                f"{SOUP_API}(server);\n",
                CompileUnit(alias_source, alias_root, ()), alias_root,
                alias_root / "build", {}),
            "missing preprocessor marker through canonical root alias")
        aliased_project = preprocessed_project_occurrences(
            f'# 1 "{alias_source.resolve()}"\n'
            "static void wyl_daemon_start_http_server_with_runtime(void) {\n"
            f'  {EXACT_API}(server, "/healthz", healthz_handler, NULL, NULL);\n'
            "}\n",
            CompileUnit(alias_source, alias_root, ()), alias_root,
            alias_root / "build")
        if not any(item.source == "wyrelog/daemon/http.c"
                   and item.symbol == EXACT_API
                   for item in aliased_project):
            raise GuardError(
                "direct project occurrence lost canonical root alias")
        expect_guard_error(
            lambda: preprocessed_ownership_occurrences(
                f'# 1 "{outside}"\n{SOUP_API}(server);\n',
                CompileUnit(outside, alias_root, ()), alias_root,
                alias_root / "build", {}),
            "outside preprocessing unit")
        expect_guard_error(
            lambda: preprocessed_project_occurrences(
                f'# 1 "{outside}"\n'
                "static void wyl_daemon_start_http_server_with_runtime(void) {\n"
                f'  {EXACT_API}(server, "/healthz", healthz_handler, '
                "NULL, NULL);\n}\n",
                CompileUnit(outside, alias_root, ()), alias_root,
                alias_root / "build"),
            "outside project occurrence unit")
        expect_guard_error(
            lambda: production_compile_units(root, root / "missing-build",
                                             "gcc"),
            "missing compile database")

        write_exact_fixture(source_path, baseline)
        alternate = root / "wyrelog" / "alternate.c"
        write_exact_fixture(
            alternate,
            "static void alternate(void) {\n"
            "  soup_server_add_websocket_handler(server, \"/hidden\", NULL, "
            "NULL, NULL, callback, NULL);\n}\n")
        expect_failure(root, "alternate production source")


def main() -> int:
    try:
        if sys.argv[1:2] == ["--self-test"]:
            if "--" not in sys.argv[2:]:
                raise GuardError("self-test requires a real compiler command")
            separator = sys.argv.index("--", 2)
            self_parser = argparse.ArgumentParser()
            self_parser.add_argument("--compiler-id", required=True)
            self_arguments = self_parser.parse_args(sys.argv[2:separator])
            compiler = tuple(sys.argv[separator + 1:])
            if not compiler:
                raise GuardError("self-test compiler command is empty")
            self_test(self_arguments.compiler_id, compiler)
            print("OK: daemon HTTP registration guard rejects negative fixtures")
            return 0
        parser = argparse.ArgumentParser()
        parser.add_argument("root", type=Path)
        parser.add_argument("--build-root", required=True, type=Path)
        parser.add_argument("--compiler-id", required=True)
        arguments = parser.parse_args()
        root = arguments.root.resolve()
        build_root = arguments.build_root.resolve()
        registrations = check_root(root)
        check_semantic_boundary(root, build_root, arguments.compiler_id)
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

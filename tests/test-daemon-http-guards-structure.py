#!/usr/bin/env python3
"""Freeze the public service-credential HTTP route matrix.

The two management registrations are prefix dispatchers, so their six child
paths do not appear in the libsoup route table.  Keep one canonical manifest
here and prove both the registrations and the dispatcher branches which own
those paths.  This deliberately fails closed when a compatibility alias or a
route-specific feature switch is added.
"""

from pathlib import Path
import re
import sys


source = Path(sys.argv[1]).read_text(encoding="utf-8")

BASE = "base"
AUDIT = "audit"
FACT = "fact"

# (method, public path pattern, owning feature, terminal handler)
CANONICAL_ROUTES = (
    ("POST", "/service-principals", BASE, "service_principal_create_handler"),
    ("GET", "/service-principals", BASE, "service_principal_list_handler"),
    ("POST", "/service-principals/{subject}/disable", BASE,
     "service_principal_disable_handler"),
    ("POST", "/service-principals/{subject}/credentials", BASE,
     "service_credential_issue_handler"),
    ("GET", "/service-principals/{subject}/credentials", BASE,
     "service_credential_list_handler"),
    ("GET", "/service-credentials/{credential_id}", BASE,
     "service_credential_get_handler"),
    ("POST", "/service-credentials/{credential_id}/rotate", BASE,
     "service_credential_rotate_handler"),
    ("DELETE", "/service-credentials/{credential_id}", BASE,
     "service_credential_revoke_handler"),
    ("POST", "/auth/service-token", AUDIT,
     "service_token_exchange_http_handler"),
    ("GET", "/service-credential-operations", FACT,
     "service_credential_operation_status_handler"),
    ("POST", "/service-credential-operations/reconcile", FACT,
     "service_credential_operation_reconcile_handler"),
    ("POST", "/service-credential-operations/recover", FACT,
     "service_credential_operation_recover_handler"),
)


def fail(message):
    raise SystemExit(message)


def extract_function_body(text, name):
    """Return a balanced-brace C function body for structural assertions."""
    match = re.search(r"\n%s\s*\([^;]*?\)\s*\{" % re.escape(name), text,
                      re.DOTALL)
    if match is None:
        fail(f"missing public route owner: {name}")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    fail(f"unterminated public route owner: {name}")


def function_body(name):
    return extract_function_body(source, name)


def assert_contains(body, *needles):
    for needle in needles:
        if needle not in body:
            fail(f"missing public route dispatch evidence: {needle}")


# The manifest itself is executable evidence of the feature matrix.  Exact
# tuple uniqueness also prevents one method/path from acquiring two owners.
route_keys = [(method, path) for method, path, _feature, _handler
              in CANONICAL_ROUTES]
if len(route_keys) != len(set(route_keys)):
    fail("duplicate method/path in canonical public route manifest")

expected_matrix = {
    frozenset(): 8,
    frozenset((AUDIT,)): 9,
    frozenset((FACT,)): 11,
    frozenset((AUDIT, FACT)): 12,
}
for enabled, expected_count in expected_matrix.items():
    actual = [route for route in CANONICAL_ROUTES
              if route[2] == BASE or route[2] in enabled]
    if len(actual) != expected_count:
        fail(f"public route matrix mismatch for {sorted(enabled)}: "
             f"expected {expected_count}, found {len(actual)}")


# Freeze the actual registrations and their feature ownership.  Base prefix
# dispatchers remain direct and unconditional; every singleton must use the
# reusable exact adapter, with optional groups all-or-nothing.
registration_pattern = re.compile(
    r'(soup_server_add_handler|wyl_daemon_http_add_exact_handler)\s*'
    r'\(\s*server\s*,\s*"([^"]+)"\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\b')


def service_registration_manifest(text):
    return [item for item in registration_pattern.findall(text)
            if item[1].startswith("/service-")
            or item[1].startswith("/auth/service")]


service_registrations = service_registration_manifest(source)
expected_registrations = [
    ("soup_server_add_handler", "/service-principals",
     "service_principal_management_handler"),
    ("soup_server_add_handler", "/service-credentials",
     "service_credential_management_handler"),
    ("wyl_daemon_http_add_exact_handler", "/service-credential-operations",
     "service_credential_operation_status_handler"),
    ("wyl_daemon_http_add_exact_handler",
     "/service-credential-operations/reconcile",
     "service_credential_operation_reconcile_handler"),
    ("wyl_daemon_http_add_exact_handler",
     "/service-credential-operations/recover",
     "service_credential_operation_recover_handler"),
    ("wyl_daemon_http_add_exact_handler", "/auth/service-token",
     "service_token_exchange_http_handler"),
]
if service_registrations != expected_registrations:
    fail("public service route registrations differ from canonical set: "
         f"{service_registrations!r}")

registration_block_pattern = re.compile(
    r'soup_server_add_handler\s*\(server,\s*"/service-principals".*?'
    r'#ifdef WYL_HAS_FACT_STORE\s*'
    r'wyl_daemon_http_add_exact_handler\s*\(server,\s*'
    r'"/service-credential-operations".*?'
    r'"/service-credential-operations/reconcile".*?'
    r'"/service-credential-operations/recover".*?'
    r'#endif\s*#ifdef WYL_HAS_AUDIT\s*'
    r'wyl_daemon_http_add_exact_handler\s*\(server,\s*'
    r'"/auth/service-token".*?'
    r'#endif', re.DOTALL)
if registration_block_pattern.search(source) is None:
    fail("public service routes must use only the canonical fact/audit groups")


# Prove the reusable singleton adapter compares path before invoking the
# terminal callback.  This is the production primitive later migrations must
# reuse rather than copying singleton-specific path checks.
exact_dispatch = function_body("wyl_daemon_http_exact_handler_dispatch")
exact_path_check = "g_strcmp0 (path, exact->canonical_path) != 0"
exact_callback = "exact->callback (server, msg, path, query, exact->user_data)"
assert_contains(exact_dispatch, exact_path_check,
                'set_json_error (msg, 404, "not_found")', exact_callback)
if exact_dispatch.index(exact_path_check) > exact_dispatch.index(exact_callback):
    fail("exact route callback can run before canonical path check")
exact_registration = function_body("wyl_daemon_http_add_exact_handler")
assert_contains(exact_registration,
                "wyl_daemon_http_exact_handler_dispatch",
                "soup_server_add_handler (server, canonical_path")


# Prove that the two prefix dispatchers expose precisely the eight base
# method/path combinations and classify shape before method or delegation.
principal_dispatch = function_body("service_principal_management_handler")
principal_classify = (
    "WylServicePrincipalRoute route = service_principal_route_classify (path)")
assert_contains(
    principal_dispatch,
    'wyl_daemon_http_strip_route_prefix (path, "/service-principals")',
    principal_classify,
    "route == WYL_SERVICE_PRINCIPAL_ROUTE_COLLECTION",
    "route == WYL_SERVICE_PRINCIPAL_ROUTE_DISABLE",
    "route == WYL_SERVICE_PRINCIPAL_ROUTE_CREDENTIALS",
    'const gchar *method = soup_server_message_get_method (msg)',
    'service_principal_list_handler (server, msg, path, query, user_data)',
    'service_principal_create_handler (server, msg, path, query, user_data)',
    'service_principal_disable_handler (server, msg, path, query, user_data)',
    'service_credential_list_handler (server, msg, path, query, user_data)',
    'service_credential_issue_handler (server, msg, path, query, user_data)',
    'set_json_error (msg, 404, "not_found")',
    'set_json_error (msg, 405, "method_not_allowed")',
)
if "g_str_has_suffix" in principal_dispatch:
    fail("principal route dispatcher must not use suffix classification")

credential_dispatch = function_body("service_credential_management_handler")
credential_classify = (
    "WylServiceCredentialRoute route = service_credential_route_classify (path)")
assert_contains(
    credential_dispatch,
    'wyl_daemon_http_strip_route_prefix (path, "/service-credentials")',
    credential_classify,
    "route == WYL_SERVICE_CREDENTIAL_ROUTE_ITEM",
    "route == WYL_SERVICE_CREDENTIAL_ROUTE_ROTATE",
    'const gchar *method = soup_server_message_get_method (msg)',
    'service_credential_revoke_handler (server, msg, path, query, user_data)',
    'service_credential_rotate_handler (server, msg, path, query, user_data)',
    'service_credential_get_handler (server, msg, path, query, user_data)',
    'set_json_error (msg, 404, "not_found")',
    'set_json_error (msg, 405, "method_not_allowed")',
)
if "g_str_has_suffix" in credential_dispatch:
    fail("credential route dispatcher must not use suffix classification")

for body, classifier, handlers in (
    (principal_dispatch, principal_classify, (
        "service_principal_list_handler", "service_principal_create_handler",
        "service_principal_disable_handler", "service_credential_list_handler",
        "service_credential_issue_handler")),
    (credential_dispatch, credential_classify, (
        "service_credential_get_handler", "service_credential_revoke_handler",
        "service_credential_rotate_handler")),
):
    classifier_offset = body.index(classifier)
    method_offset = body.index("soup_server_message_get_method")
    if classifier_offset > method_offset:
        fail("public route method inspected before path classification")
    if any(classifier_offset > body.index(handler) for handler in handlers):
        fail("public route delegated before path classification")

principal_classifier = function_body("service_principal_route_classify")
assert_contains(principal_classifier,
                'g_strcmp0 (path, "") == 0',
                "tail == NULL || tail == path + 1",
                'g_strcmp0 (tail, "/disable") == 0',
                'g_strcmp0 (tail, "/credentials") == 0',
                "WYL_SERVICE_PRINCIPAL_ROUTE_UNKNOWN")
credential_classifier = function_body("service_credential_route_classify")
assert_contains(credential_classifier,
                "path[0] != '/' || path[1] == '\\0'",
                "tail == NULL",
                'g_strcmp0 (tail, "/rotate") == 0',
                "WYL_SERVICE_CREDENTIAL_ROUTE_UNKNOWN")

terminal_methods = {
    "service_principal_create_handler": "POST",
    "service_principal_list_handler": "GET",
    "service_principal_disable_handler": "POST",
    "service_credential_issue_handler": "POST",
    "service_credential_list_handler": "GET",
    "service_credential_get_handler": "GET",
    "service_credential_rotate_handler": "POST",
    "service_credential_revoke_handler": "DELETE",
    "service_token_exchange_http_handler": "POST",
    "service_credential_operation_status_handler": "GET",
    "service_credential_operation_reconcile_handler": "POST",
    "service_credential_operation_recover_handler": "POST",
}
for handler, method in terminal_methods.items():
    assert_contains(function_body(handler),
                    f'soup_server_message_get_method (msg), "{method}"')

# Reject known status aliases plus versioned, hidden/test, deeper operation,
# and alternate exchange registrations.  Dispatcher-owned child paths are not
# libsoup registrations, so any additional matching registration is an alias.
for _kind, path, _handler in service_registration_manifest(source):
    if path in {item[1] for item in expected_registrations}:
        continue
    if (re.search(r"/(?:v[0-9]+|\.well-known|hidden|test)(?:/|$)", path)
            or path.startswith("/service-principal")
            or path.startswith("/service-credential")
            or (path.startswith("/auth/") and
                ("service" in path or "credential" in path))):
        fail(f"unexpected public service route alias: {path}")


# Mutation checks prove this guard is sensitive to the two regressions it is
# intended to freeze: bypassing the exact wrapper and moving classification
# behind a method/delegation effect.
direct_singleton_mutant = source.replace(
    'wyl_daemon_http_add_exact_handler (server, "/auth/service-token"',
    'soup_server_add_handler (server, "/auth/service-token"', 1)
if direct_singleton_mutant == source:
    fail("could not construct direct-singleton negative mutant")
if service_registration_manifest(direct_singleton_mutant) == expected_registrations:
    fail("structural guard accepted direct-singleton negative mutant")

registration_anchor = (
    'soup_server_add_handler (server, "/service-credentials",\n'
    '      service_credential_management_handler, ctx, NULL);')
legacy_alias_mutant = source.replace(
    registration_anchor,
    registration_anchor + '\n  soup_server_add_handler (server, '
    '"/service-credentials/legacy", legacy_handler, NULL, NULL);',
    1)
if legacy_alias_mutant == source:
    fail("could not construct unclassified-alias negative mutant")
legacy_manifest = service_registration_manifest(legacy_alias_mutant)
if legacy_manifest == expected_registrations:
    fail("structural guard accepted NULL/NULL alias negative mutant")
if not any(path == "/service-credentials/legacy"
           and handler == "legacy_handler"
           for _kind, path, handler in legacy_manifest):
    fail("registration census missed NULL/NULL alias negative mutant")

varied_args_alias_mutant = source.replace(
    registration_anchor,
    registration_anchor + '\n  wyl_daemon_http_add_exact_handler (server, '
    '"/service-credentials/legacy-varied", legacy_varied_handler, '
    '&arbitrary_context, destroy_arbitrary_context);',
    1)
varied_manifest = service_registration_manifest(varied_args_alias_mutant)
if not any(path == "/service-credentials/legacy-varied"
           and handler == "legacy_varied_handler"
           for _kind, path, handler in varied_manifest):
    fail("registration census missed varied-argument alias negative mutant")
if varied_manifest == expected_registrations:
    fail("structural guard accepted varied-argument alias negative mutant")

for body, classifier in (
    (principal_dispatch, principal_classify),
    (credential_dispatch, credential_classify),
):
    late_classifier_mutant = body.replace(classifier, "", 1) + classifier
    if (late_classifier_mutant.index(classifier)
            < late_classifier_mutant.index("soup_server_message_get_method")):
        fail("ordering guard accepted late-classifier negative mutant")

late_exact_mutant = exact_dispatch.replace(exact_path_check, "", 1)
late_exact_mutant += exact_path_check
if late_exact_mutant.index(exact_path_check) < late_exact_mutant.index(exact_callback):
    fail("ordering guard accepted late exact-path negative mutant")

for forbidden in (
    "/operation-status",
    "/service-credential-operations/status",
):
    if forbidden in source:
        fail(f"unexpected service-credential alias: {forbidden}")

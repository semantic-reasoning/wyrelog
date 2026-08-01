#!/usr/bin/env python3
"""Guard retirement replay authorization and invalidation boundaries."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
DOMAIN_PATH = ROOT / "wyrelog/auth/service-credential-domain.c"
HTTP_PATH = ROOT / "wyrelog/daemon/http.c"


def function_body(source: str, name: str) -> str:
    marker = f"\n{name} ("
    start = source.find(marker)
    if start < 0 or source.find(marker, start + 1) >= 0:
        raise ValueError(f"{name} definition is missing or duplicated")
    opening = source.find("{", start)
    if opening < 0:
        raise ValueError(f"{name} has no body")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening:index + 1]
    raise ValueError(f"{name} body is unterminated")


def mutate_function(source: str, name: str, old: str, new: str) -> str:
    body = function_body(source, name)
    if body.count(old) != 1:
        raise ValueError(f"{name} mutation token count={body.count(old)}")
    return source.replace(body, body.replace(old, new, 1), 1)


DOMAIN_FUNCTIONS = {
    "wyl_service_principal_disable_keyed_with_runtime": (
        "wyl_policy_store_disable_service_principal_keyed_precheck_core",
        "wyl_policy_store_disable_service_principal_keyed_core",
        "wyl_service_auth_selector_init_principal",
    ),
    "wyl_tenant_seal_keyed_with_runtime": (
        "wyl_policy_store_seal_tenant_keyed_precheck_core",
        "wyl_policy_store_seal_tenant_keyed_core",
        "wyl_service_auth_selector_init_tenant",
    ),
    "wyl_service_credential_revoke_keyed_with_runtime": (
        "wyl_policy_store_revoke_service_credential_keyed_precheck_core",
        "wyl_policy_store_revoke_service_credential_keyed_core",
        "wyl_service_auth_selector_init_credential_generation",
    ),
}


def violations(domain: str, http: str) -> list[str]:
    errors: list[str] = []
    for name, (precheck, core, selector) in DOMAIN_FUNCTIONS.items():
        try:
            body = function_body(domain, name)
        except ValueError as error:
            errors.append(str(error))
            continue
        ordered = [body.find(token) for token in (
            "service_mutation_authorize", precheck, core, selector,
            "service_mutation_finish")]
        if -1 in ordered or ordered != sorted(ordered):
            errors.append(f"{name} authorization/replay order changed")
        if body.count(precheck) != 1 or body.count(core) != 1:
            errors.append(f"{name} keyed store boundary is not singular")
        if body.count(selector) != 1:
            errors.append(f"{name} selector boundary is not singular")
        selector_pos = body.find(selector)
        selector_guard = body.rfind("WYL_POLICY_SERVICE_RETIREMENT_"
                                    "FRESH_TRANSITION", 0, selector_pos)
        if selector_guard < 0 or selector_pos - selector_guard > 240:
            errors.append(f"{name} selector is not fresh-transition guarded")
        core_pos = body.find(core)
        no_receipt_guard = body.rfind(
            "if (rc == WYRELOG_E_OK && !receipt_found) {", 0, core_pos)
        if no_receipt_guard < 0 or core_pos - no_receipt_guard > 180:
            errors.append(f"{name} replay can reach mutation core")

    try:
        principal = function_body(http, "service_principal_disable_handler")
        tenant = function_body(http, "tenant_mutation_handler")
        revoke = function_body(http, "service_credential_revoke_handler")
    except ValueError as error:
        errors.append(str(error))
        return errors

    for body, label, parser, keyed, key in (
        (principal, "principal", "request_body_dup_strict_json_object",
         "wyl_service_principal_disable_keyed_with_runtime", "values[1]"),
        (tenant, "tenant", "request_body_dup_strict_json_object",
         "wyl_tenant_seal_keyed_with_runtime", "retirement_values[1]"),
        (revoke, "revoke", "request_body_dup_strict_json_object",
         "wyl_service_credential_revoke_with_runtime", "values[1]"),
    ):
        parser_pos = body.find(parser)
        keyed_pos = body.find(keyed)
        key_pos = body.find(key, keyed_pos)
        if parser_pos < 0 or keyed_pos < 0 or parser_pos > keyed_pos:
            errors.append(f"{label} handler can bypass strict keyed ingress")
        if key_pos < 0 or key_pos - keyed_pos > 300:
            errors.append(f"{label} handler does not pass the body key")
        if "wyl_service_auth_registry_" in body:
            errors.append(f"{label} handler performs raw registry mutation")

    if "decision_request_id = ensure_request_id_header" not in principal:
        errors.append("principal response correlation is not separate")
    if ("const gchar *decision_request_id = NULL" not in tenant
            or "decision_request_id = ensure_request_id_header" not in tenant):
        errors.append("tenant response correlation is not separate")
    if "changed = retirement.recorded_transitioned" not in tenant:
        errors.append("tenant replay does not return recorded wire result")
    if "changed = retirement.transitioned_now" in tenant:
        errors.append("tenant wire result is coupled to selector gating")
    return errors


domain = DOMAIN_PATH.read_text(encoding="utf-8")
http = HTTP_PATH.read_text(encoding="utf-8")
actual = violations(domain, http)
if actual:
    raise SystemExit("; ".join(actual))

# Non-vacuity: representative authorization, replay, selector and ingress
# bypasses must each be rejected by the same checker.
mutants = [
    (mutate_function(domain,
                     "wyl_service_principal_disable_keyed_with_runtime",
                     "service_mutation_authorize", "removed_authorize"),
     http),
    (mutate_function(domain, "wyl_tenant_seal_keyed_with_runtime",
                     "if (rc == WYRELOG_E_OK && !receipt_found) {",
                     "if (rc == WYRELOG_E_OK) {"), http),
    (mutate_function(domain,
                     "wyl_service_credential_revoke_keyed_with_runtime",
                     "WYL_POLICY_SERVICE_RETIREMENT_FRESH_TRANSITION",
                     "WYL_POLICY_SERVICE_RETIREMENT_EXACT_REPLAY"), http),
    (domain, mutate_function(http, "service_principal_disable_handler",
                             "values[1],\n      WYL_SERVICE_RETIREMENT",
                             "decision_request_id,\n      "
                             "WYL_SERVICE_RETIREMENT")),
    (domain, mutate_function(http, "tenant_mutation_handler",
                             "changed = retirement.recorded_transitioned",
                             "changed = retirement.transitioned_now")),
]
for index, (mutant_domain, mutant_http) in enumerate(mutants):
    if not violations(mutant_domain, mutant_http):
        raise SystemExit(f"mutant {index} escaped retirement boundary guard")

sys.exit(0)

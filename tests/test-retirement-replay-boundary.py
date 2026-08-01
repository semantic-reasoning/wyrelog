#!/usr/bin/env python3
"""Guard retirement replay authorization and invalidation boundaries."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
DOMAIN_PATH = ROOT / "wyrelog/auth/service-credential-domain.c"
HTTP_PATH = ROOT / "wyrelog/daemon/http.c"
HANDOFF_PATH = ROOT / "wyrelog/daemon/service-credential-handoff-private.c"
COORDINATOR_PATH = (ROOT / "wyrelog/auth/"
                    "service-credential-operation-coordinator-execute-private.c")


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


def mapped_status(body: str, label: str, code: str, status: str, start: int,
                  errors: list[str]) -> None:
    code_pos = body.find(code, start)
    status_pos = body.find(status, code_pos)
    if code_pos < 0 or status_pos < 0 or status_pos - code_pos > 420:
        errors.append(f"{label} {code} status mapping changed")


def violations(domain: str, http: str, handoff: str,
               coordinator: str) -> list[str]:
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

    for body, label, parser, keyed, key, success_token in (
        (principal, "principal", "request_body_dup_strict_json_object",
         "wyl_service_principal_disable_keyed_with_runtime", "values[1]",
         "soup_server_message_set_status (msg, 200"),
        (tenant, "tenant", "request_body_dup_strict_json_object",
         "wyl_tenant_seal_keyed_with_runtime", "retirement_values[1]",
         "set_tenant_mutation_json"),
        (revoke, "revoke", "request_body_dup_strict_json_object",
         "wyl_service_credential_revoke_with_runtime", "values[1]",
         "soup_server_message_set_status (msg, 200"),
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
        keyed_pos = body.find(keyed)
        registry_pos = body.rfind(
            ".registry = ctx->service_auth_registry,", 0, keyed_pos)
        if registry_pos < 0:
            errors.append(f"{label} handler omits the daemon registry")
        success_pos = body.find(success_token, keyed_pos)
        first_success = body.find(success_token)
        if (success_pos < 0 or keyed_pos > success_pos
                or first_success != success_pos):
            errors.append(f"{label} handler can report success before compound mutation")
        mapped_status(body, label, "if (rc == WYRELOG_E_BUSY)",
                      "set_json_error (msg, 503", keyed_pos, errors)
        mapped_status(body, label, "if (rc != WYRELOG_E_OK)",
                      "set_json_error (msg, 500", keyed_pos, errors)

    if "decision_request_id = ensure_request_id_header" not in principal:
        errors.append("principal response correlation is not separate")
    if ("const gchar *decision_request_id = NULL" not in tenant
            or "decision_request_id = ensure_request_id_header" not in tenant):
        errors.append("tenant response correlation is not separate")
    if "changed = retirement.recorded_transitioned" not in tenant:
        errors.append("tenant replay does not return recorded wire result")
    if "changed = retirement.transitioned_now" in tenant:
        errors.append("tenant wire result is coupled to selector gating")

    try:
        rotate = function_body(http, "service_credential_rotate_handler")
        emit = function_body(http, "service_credential_handoff_emit")
        handoff_entry = function_body(
            handoff, "wyl_daemon_service_credential_handoff")
        execute = function_body(coordinator, "execute_prepared_handoff")
    except ValueError as error:
        errors.append(str(error))
        return errors

    rotate_get = rotate.find("wyl_service_credential_get")
    generation = rotate.find("guint64 current_generation = current.generation")
    expected = rotate.find(".expected_generation = current_generation")
    emit_call = rotate.find("service_credential_handoff_emit")
    if (-1 in (rotate_get, generation, expected, emit_call)
            or [rotate_get, generation, expected, emit_call]
            != sorted((rotate_get, generation, expected, emit_call))):
        errors.append("rotate handler lost authoritative generation binding")
    if "wyl_service_auth_registry_" in rotate:
        errors.append("rotate handler performs raw registry mutation")

    registry_gate = emit.find(
        "if (inputs->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE)")
    registry_assignment = emit.find(
        "hctx.registry = ctx->service_auth_registry", registry_gate)
    compound = emit.find("wyl_daemon_service_credential_handoff")
    success = emit.find("case WYRELOG_E_OK:", compound)
    success_status = emit.find("soup_server_message_set_status (msg, 200",
                               success)
    if (-1 in (registry_gate, registry_assignment, compound, success,
               success_status)
            or registry_assignment > compound or compound > success
            or success > success_status):
        errors.append("rotate HTTP registry/compound/success order changed")
    mapped_status(emit, "rotate", "case WYRELOG_E_BUSY:",
                  "set_json_error (msg, 503", compound, errors)
    mapped_status(emit, "rotate", "default:",
                  "set_json_error (msg, 500", compound, errors)

    handoff_registry = handoff_entry.find(
        "rotate_runtime.registry = ctx->registry")
    handoff_runtime = handoff_entry.find(
        ".rotate_runtime = inputs->kind == "
        "WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE")
    handoff_call = handoff_entry.find(
        "wyl_service_credential_operation_coordinator_handoff")
    if (-1 in (handoff_registry, handoff_runtime, handoff_call)
            or [handoff_registry, handoff_runtime, handoff_call]
            != sorted((handoff_registry, handoff_runtime, handoff_call))):
        errors.append("rotate handoff omits registry-aware runtime")

    generation_check = execute.find(
        "runtime->rotate_runtime->old_credential_generation")
    expected_check = execute.find("record->expected_generation",
                                  generation_check)
    runtime_copy = execute.find(
        "wyl_service_credential_rotate_runtime_t rotate_runtime",
        expected_check)
    checked_rotate = execute.find(
        "wyl_service_credential_rotate_handoff_checked_with_runtime",
        runtime_copy)
    if (-1 in (generation_check, expected_check, runtime_copy, checked_rotate)
            or [generation_check, expected_check, runtime_copy, checked_rotate]
            != sorted((generation_check, expected_check, runtime_copy,
                       checked_rotate))
            or "!= record->expected_generation" not in
            execute[generation_check:runtime_copy]):
        errors.append("rotate coordinator lost generation-checked compound call")
    return errors


domain = DOMAIN_PATH.read_text(encoding="utf-8")
http = HTTP_PATH.read_text(encoding="utf-8")
handoff = HANDOFF_PATH.read_text(encoding="utf-8")
coordinator = COORDINATOR_PATH.read_text(encoding="utf-8")
actual = violations(domain, http, handoff, coordinator)
if actual:
    raise SystemExit("; ".join(actual))

# Non-vacuity: representative authorization, replay, selector and ingress
# bypasses must each be rejected by the same checker.
mutants = [
    (mutate_function(domain,
                     "wyl_service_principal_disable_keyed_with_runtime",
                     "service_mutation_authorize", "removed_authorize"),
     http, handoff, coordinator),
    (mutate_function(domain, "wyl_tenant_seal_keyed_with_runtime",
                     "if (rc == WYRELOG_E_OK && !receipt_found) {",
                     "if (rc == WYRELOG_E_OK) {"), http, handoff, coordinator),
    (mutate_function(domain,
                     "wyl_service_credential_revoke_keyed_with_runtime",
                     "WYL_POLICY_SERVICE_RETIREMENT_FRESH_TRANSITION",
                     "WYL_POLICY_SERVICE_RETIREMENT_EXACT_REPLAY"), http,
     handoff, coordinator),
    (domain, mutate_function(http, "service_principal_disable_handler",
                             "values[1],\n      WYL_SERVICE_RETIREMENT",
                             "decision_request_id,\n      "
                             "WYL_SERVICE_RETIREMENT"), handoff, coordinator),
    (domain, mutate_function(http, "tenant_mutation_handler",
                             "changed = retirement.recorded_transitioned",
                             "changed = retirement.transitioned_now"), handoff,
     coordinator),
]

for function in ("service_principal_disable_handler",
                 "service_credential_revoke_handler",
                 "tenant_mutation_handler"):
    mutants.append((domain, mutate_function(
        http, function, ".registry = ctx->service_auth_registry,",
        ".registry = NULL,"), handoff, coordinator))

mutants.extend([
    (domain, mutate_function(
        http, "service_credential_handoff_emit",
        "hctx.registry = ctx->service_auth_registry;",
        "hctx.registry = NULL;"), handoff, coordinator),
    (domain, http, mutate_function(
        handoff, "wyl_daemon_service_credential_handoff",
        "rotate_runtime.registry = ctx->registry;",
        "rotate_runtime.registry = NULL;"), coordinator),
    (domain, mutate_function(
        http, "service_credential_rotate_handler",
        ".expected_generation = current_generation,",
        ".expected_generation = 0,"), handoff, coordinator),
    (domain, http, handoff, mutate_function(
        coordinator, "execute_prepared_handoff",
        "!= record->expected_generation",
        "== record->expected_generation")),
    (domain, mutate_function(
        http, "service_principal_disable_handler",
        "wyrelog_error_t rc = wyl_service_principal_disable_keyed_with_runtime",
        "soup_server_message_set_status (msg, 200, NULL);\n  "
        "wyrelog_error_t rc = wyl_service_principal_disable_keyed_with_runtime"),
     handoff, coordinator),
    (domain, mutate_function(
        http, "service_credential_revoke_handler",
        "set_json_error (msg, 503,",
        "set_json_error (msg, 409,"), handoff, coordinator),
    (domain, mutate_function(
        http, "service_credential_handoff_emit",
        "set_json_error (msg, 500,",
        "set_json_error (msg, 409,"), handoff, coordinator),
])

for index, (mutant_domain, mutant_http, mutant_handoff,
            mutant_coordinator) in enumerate(mutants):
    if not violations(mutant_domain, mutant_http, mutant_handoff,
                      mutant_coordinator):
        raise SystemExit(f"mutant {index} escaped retirement boundary guard")

sys.exit(0)

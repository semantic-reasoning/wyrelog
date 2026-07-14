#!/usr/bin/env python3
"""Prove the bearer resolver structure guard rejects representative drift."""

import subprocess
import sys
import tempfile
from pathlib import Path


def run(guard: str, text: str) -> int:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "http.c"
        source.write_text(text, encoding="utf-8")
        return subprocess.run([sys.executable, guard, str(source)], check=False).returncode


BASE = r'''
static wyrelog_error_t
resolve_bearer_session(void) {
  wyl_jwt_verify_hs256_access_token();
  wyl_jwt_parse_access_claims_json();
  if (g_strcmp0(claims.auth_method, "service_credential") == 0) {
    wyl_service_auth_authority_acquire_read();
    wyl_service_auth_read_lease_get_policy_store();
    wyl_policy_store_tenant_exists();
    wyl_daemon_http_context_service_access_token_is_exact();
    wyl_daemon_http_ref_session();
    wyl_service_auth_registry_lookup();
    if (registry_state != WYL_SERVICE_AUTH_ACTIVE) return 1;
    WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED;
    wyl_service_auth_read_lease_release_terminal();
    return 0;
  }
  return claims.principal_state_at_issue != 0;
}
wyrelog_error_t
wyl_daemon_http_resolve_bearer_for_test(void) {
  return resolve_bearer_session();
}
'''


def main() -> int:
    guard = sys.argv[1]
    mutants = [
        BASE.replace("static wyrelog_error_t\nresolve_bearer_session", "wyrelog_error_t\nresolve_bearer_session"),
        BASE + "\nstatic wyrelog_error_t resolve_service_bearer_session(void) { return 0; }\n",
        BASE.replace("  wyl_service_auth_registry_lookup();\n", "")
        + "\nstatic void elsewhere(void) { wyl_service_auth_registry_lookup(); }\n",
        BASE.replace("  wyl_service_auth_authority_acquire_read();\n", "")
        + "\nstatic void elsewhere(void) { wyl_service_auth_authority_acquire_read(); }\n",
        BASE.replace("registry_state != WYL_SERVICE_AUTH_ACTIVE", "registry_state == WYL_SERVICE_AUTH_PENDING"),
        BASE.replace("  return resolve_bearer_session();", "  wyl_service_auth_registry_lookup();\n  return resolve_bearer_session();"),
        BASE.replace("  return claims.principal_state_at_issue != 0;", "  wyl_jwt_verify_alternate();\n  return claims.principal_state_at_issue != 0;"),
        BASE.replace("  return claims.principal_state_at_issue != 0;", "  wyl_jwt_parse_access_claims_alternate();\n  return claims.principal_state_at_issue != 0;"),
        BASE + "\nstatic void handler(void) { wyl_jwt_verify_handler_local(); }\n",
        BASE.replace("    wyl_service_auth_read_lease_get_policy_store();", "    wyl_handle_get_policy_store();\n    wyl_service_auth_read_lease_get_policy_store();"),
        BASE.replace("    WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED;\n    wyl_service_auth_read_lease_release_terminal();", "    wyl_service_auth_read_lease_release_terminal();\n    WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED;"),
        BASE.replace("wyl_service_auth_read_lease_release_terminal", "wyl_service_auth_read_lease_release"),
        BASE.replace("if (g_strcmp0(claims.auth_method, \"service_credential\") == 0)", "if (g_strcmp0(claims.auth_method, \"service_credential\") != 0)"),
        BASE.replace("    wyl_service_auth_registry_lookup();", "    /* wyl_service_auth_registry_lookup(); */"),
        BASE.replace("  wyl_jwt_parse_access_claims_json();", "  const char *fake = \"wyl_jwt_parse_access_claims_json();\";"),
        BASE.replace("    wyl_service_auth_read_lease_get_policy_store();\n", "")
        + "\nstatic void elsewhere(void) { wyl_service_auth_read_lease_get_policy_store(); }\n",
        BASE + "\nstatic void handler(void) { wyl_jwt_parse_access_claims_handler(); }\n",
        BASE + "\nstatic void non_bearer_auth(void) { wyl_jwt_verify_non_bearer(); }\n",
        BASE + "\n#define resolver_alias resolve_bearer_session\n",
        BASE + "\nstatic void *resolver_alias = resolve_bearer_session;\n",
        BASE.replace("    wyl_service_auth_read_lease_release_terminal();", "    wyl_service_auth_read_lease_release_terminal();\n    wyl_service_auth_read_lease_release_terminal();"),
        BASE.replace("  return claims.principal_state_at_issue != 0;", "  wyl_service_auth_authority_acquire_read();\n  return claims.principal_state_at_issue != 0;"),
        BASE.replace("    wyl_policy_store_tenant_exists();\n    wyl_daemon_http_context_service_access_token_is_exact();", "    wyl_daemon_http_context_service_access_token_is_exact();\n    wyl_policy_store_tenant_exists();"),
        BASE.replace("    wyl_service_auth_read_lease_release_terminal();", "    wyl_service_auth_read_lease_release_terminal();\n    wyl_service_auth_read_lease_free();"),
        BASE.replace("    wyl_service_auth_authority_acquire_read();", "    /* wyl_service_auth_authority_acquire_read(); */"),
        BASE.replace("  wyl_jwt_verify_hs256_access_token();", "  const char *fake_verify = \"wyl_jwt_verify_hs256_access_token();\";"),
    ]
    if len(mutants) != 26:
        return 3
    if run(guard, BASE) != 0:
        return 1
    return 0 if all(run(guard, mutant) != 0 for mutant in mutants) else 2


if __name__ == "__main__":
    raise SystemExit(main())

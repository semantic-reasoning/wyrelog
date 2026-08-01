#!/usr/bin/env python3
"""Verify complete ownership coverage for wyctl string options."""

from collections import Counter
from pathlib import Path
import re
import sys
import tempfile


EXPECTED_FIELDS = {
    "WyctlOptions": ("daemon_url", "timeout_ms_arg"),
    "WyctlPolicyOptions":
        ("user", "permission", "resource", "access_token_file"),
    "WyctlAuditOptions":
        ("filter", "limit_arg", "access_token_file", "guard_timestamp_arg",
         "guard_loc_class", "guard_risk_arg"),
    "WyctlPolicyPermissionOptions":
        ("subject", "perm", "scope", "access_token_file",
         "guard_timestamp_arg", "guard_loc_class", "guard_risk_arg"),
    "WyctlPolicyRoleOptions":
        ("subject", "role", "scope", "access_token_file",
         "guard_timestamp_arg", "guard_loc_class", "guard_risk_arg"),
    "WyctlGraphOptions":
        ("tenant", "graph", "access_token_file", "guard_timestamp_arg",
         "guard_loc_class", "guard_risk_arg"),
    "WyctlFactSchemaOptions":
        ("tenant", "graph", "namespace_id", "relation", "schema_version_arg",
         "columns_arg", "max_rows_arg", "access_token_file",
         "guard_timestamp_arg", "guard_loc_class", "guard_risk_arg"),
    "WyctlFactPutOptions":
        ("tenant", "graph", "namespace_id", "relation", "schema_version_arg",
         "batch_id", "idempotency_key", "format", "input",
         "access_token_file", "guard_timestamp_arg", "guard_loc_class",
         "guard_risk_arg"),
    "WyctlDatalogQueryOptions":
        ("tenant", "graph", "query", "output", "limit_arg",
         "access_token_file", "guard_timestamp_arg", "guard_loc_class",
         "guard_risk_arg"),
    "WyctlKeyOptions":
        ("keyprovider_path", "store_path", "from_keyprovider_path",
         "to_keyprovider_path"),
    "WyctlServicePermissionClosureOptions":
        ("store_path", "keyprovider_path", "manifest_path", "output_path",
         "receipt_path"),
    "WyctlMfaOptions":
        ("subject", "store_path", "keyprovider_path", "access_token_file"),
    "WyctlServiceTokenOptions": ("credential_file", "token_output"),
    "WyctlServiceCredentialOptions":
        ("subject", "credential_id", "tenant", "destination",
         "expires_at_us_arg", "request_id", "access_token_file",
         "guard_timestamp_arg", "guard_loc_class", "guard_risk_arg"),
    "WyctlServicePrincipalOptions":
        ("subject", "display_name", "tenant", "request_id",
         "access_token_file",
         "guard_timestamp_arg", "guard_loc_class", "guard_risk_arg"),
}

EXPECTED_PARSE_SITES = {
    "run_status": "WyctlOptions",
    "run_auth_service_token": "WyctlServiceTokenOptions",
    "run_policy_decision_command": "WyctlPolicyOptions",
    "run_policy_permission_mutation_command": "WyctlPolicyPermissionOptions",
    "run_policy_role_mutation_command": "WyctlPolicyRoleOptions",
    "run_graph_create": "WyctlGraphOptions",
    "run_fact_schema_register": "WyctlFactSchemaOptions",
    "run_fact_put": "WyctlFactPutOptions",
    "run_datalog_query": "WyctlDatalogQueryOptions",
    "run_audit_query": "WyctlAuditOptions",
    "run_mfa_enroll": "WyctlMfaOptions",
    "run_mfa_reset": "WyctlMfaOptions",
    "run_key_status": "WyctlKeyOptions",
    "run_key_rotate": "WyctlKeyOptions",
    "run_key_recover": "WyctlKeyOptions",
    "run_service_credential_issue": "WyctlServiceCredentialOptions",
    "run_service_credential_rotate": "WyctlServiceCredentialOptions",
    "run_service_principal_create": "WyctlServicePrincipalOptions",
    "run_service_principal_list": "WyctlServicePrincipalOptions",
    "run_service_principal_disable": "WyctlServicePrincipalOptions",
    "run_service_credential_list": "WyctlServiceCredentialOptions",
    "run_service_credential_revoke": "WyctlServiceCredentialOptions",
    "run_service_credential_recover": "WyctlServiceCredentialOptions",
    "run_service_credential_status": "WyctlServiceCredentialOptions",
    "run_service_permission_closure_inspect":
        "WyctlServicePermissionClosureOptions",
    "run_service_permission_closure_manifest_command":
        "WyctlServicePermissionClosureOptions",
    "main": "WyctlOptions",
}

EXPECTED_STRING_DESTINATIONS = 154
EXPECTED_REASSIGNMENTS = Counter({
    ("store_path", "g_steal_pointer (&store_path)"): 2,
    ("keyprovider_path", "g_steal_pointer (&keyprovider_path)"): 2,
    ("settings", "settings"): 1,
})

STRUCT_RE = re.compile(
    r"typedef struct\s*\{(?P<body>.*?)\}\s*(?P<type>Wyctl\w*Options);",
    re.DOTALL)
STRING_FIELD_RE = re.compile(r"\bgchar\s+\*(\w+)\s*;")
STRING_DESTINATION_RE = re.compile(
    r"G_OPTION_ARG_STRING,\s*&opts\.(\w+)", re.DOTALL)
ASSIGNMENT_RE = re.compile(
    r"^\s*opts\.(\w+)\s*=\s*([^;]+);", re.MULTILINE)


def snake_case(type_name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", type_name).lower()


def parse_sites(text: str) -> list[tuple[str, str, str]]:
    """Return (function, option type, source prefix through parse call)."""
    lines = text.splitlines()
    sites = []
    for index, line in enumerate(lines):
        if "g_option_context_parse (" not in line:
            continue
        function = None
        function_line = None
        for previous in range(index, max(-1, index - 160), -1):
            match = re.match(r"(run_[a-z_]+|main) \(", lines[previous])
            if match:
                function = match.group(1)
                function_line = previous
                break
        if function is None or function_line is None:
            sites.append(("<unknown>", "<unknown>", line))
            continue
        prefix = "\n".join(lines[function_line:index + 1])
        holder = re.search(r"g_auto \((Wyctl\w*Options)\) opts", prefix)
        sites.append((function, holder.group(1) if holder else "<missing>",
                      prefix))
    return sites


def check_text(text: str, expected_fields=EXPECTED_FIELDS,
               expected_sites=EXPECTED_PARSE_SITES,
               expected_destinations=EXPECTED_STRING_DESTINATIONS,
               expected_reassignments=EXPECTED_REASSIGNMENTS) -> list[str]:
    violations = []
    holders = {}
    for match in STRUCT_RE.finditer(text):
        holders[match.group("type")] = tuple(
            STRING_FIELD_RE.findall(match.group("body")))
    if holders != expected_fields:
        violations.append(
            f"option-holder inventory differs: expected {expected_fields}, "
            f"found {holders}")

    for holder, fields in expected_fields.items():
        clear_name = f"{snake_case(holder)}_clear"
        clear_match = re.search(
            rf"static void\s+{clear_name}\s*\(\s*{holder}\s+\*\s*opts\s*\)"
            rf"\s*\{{(?P<body>.*?)\n\}}", text, re.DOTALL)
        if clear_match is None:
            violations.append(f"{holder}: missing {clear_name} authority")
            continue
        body = clear_match.group("body")
        for field in fields:
            statement = f"g_clear_pointer (&opts->{field}, g_free);"
            if body.count(statement) != 1:
                violations.append(
                    f"{holder}.{field}: expected one explicit cleanup")
        auto_pattern = (
            rf"G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC \({holder},\s*{clear_name}\);")
        if re.search(auto_pattern, text, re.DOTALL) is None:
            violations.append(f"{holder}: missing auto-cleanup registration")

    if "WyctlOptions" in expected_fields:
        if re.search(r"g_(?:clear_object|clear_pointer|object_unref)\s*"
                     r"\(&opts->settings", text):
            violations.append("WyctlOptions.settings must remain borrowed")
        if "opts->settings is borrowed from main()'s GSettings owner" not in text:
            violations.append(
                "WyctlOptions.settings borrowed ownership is undocumented")

    sites = parse_sites(text)
    found_sites = {function: holder for function, holder, _ in sites}
    if found_sites != expected_sites or len(sites) != len(expected_sites):
        violations.append(
            f"parse-site inventory differs: expected {expected_sites}, "
            f"found {found_sites}")
    for function, holder, prefix in sites:
        if function not in expected_sites or holder not in expected_fields:
            continue
        if holder != expected_sites[function]:
            violations.append(
                f"{function}: expected {expected_sites[function]}, found {holder}")
            continue
        for destination in STRING_DESTINATION_RE.findall(prefix):
            if destination not in expected_fields[holder]:
                violations.append(
                    f"{function}: {destination} lacks {holder} cleanup authority")

    string_entries = text.count("G_OPTION_ARG_STRING")
    destinations = STRING_DESTINATION_RE.findall(text)
    if string_entries != expected_destinations:
        violations.append(
            f"expected {expected_destinations} string entries, found {string_entries}")
    if len(destinations) != string_entries:
        violations.append(
            f"expected every string entry to target opts.*, found "
            f"{len(destinations)} of {string_entries}")

    assignments = Counter(
        (field, " ".join(value.split()))
        for field, value in ASSIGNMENT_RE.findall(text))
    if assignments != expected_reassignments:
        violations.append(
            f"option reassignment inventory differs: expected "
            f"{expected_reassignments}, found {assignments}")

    if "run_status" in expected_sites:
        if "opts.daemon_url != NULL ? opts.daemon_url :\n      " \
                "global_opts->daemon_url" not in text:
            violations.append("run_status must keep daemon URL parsers separate")
        if "opts.timeout_ms_arg != NULL ?\n      opts.timeout_ms_arg : " \
                "global_opts->timeout_ms_arg" not in text:
            violations.append("run_status must keep timeout parsers separate")
    return violations


def check_file(path: Path) -> int:
    violations = check_text(path.read_text(encoding="utf-8"))
    for violation in violations:
        print(f"{path}: {violation}", file=sys.stderr)
    return 1 if violations else 0


def self_test() -> int:
    fixture = """\
typedef struct
{
  gchar *name;
} WyctlMiniOptions;

static void
wyctl_mini_options_clear (WyctlMiniOptions *opts)
{
  g_clear_pointer (&opts->name, g_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WyctlMiniOptions,
    wyctl_mini_options_clear);

int
main (int argc, char **argv)
{
  g_auto (WyctlMiniOptions) opts = { 0 };
  GOptionEntry entries[] = {
    {"name", 0, 0, G_OPTION_ARG_STRING, &opts.name, "Name", "NAME"},
    {NULL}
  };
  if (!g_option_context_parse (context, &argc, &argv, &error))
    return 2;
  return 0;
}
"""
    fields = {"WyctlMiniOptions": ("name",)}
    sites = {"main": "WyctlMiniOptions"}
    if check_text(fixture, fields, sites, 1, Counter()):
        return 1
    mutations = (
        fixture.replace("  g_clear_pointer (&opts->name, g_free);\n", ""),
        fixture.replace("g_auto (WyctlMiniOptions)", "WyctlMiniOptions"),
        fixture.replace("&opts.name", "&opts.missing"),
        fixture.replace("G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC",
                        "G_DEFINE_BROKEN_CLEANUP_CLEAR_FUNC"),
        fixture.replace("  return 0;", "  opts.name = resolved;\n  return 0;"),
    )
    for mutation in mutations:
        if not check_text(mutation, fields, sites, 1, Counter()):
            return 1
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fixture.c"
        path.write_text(fixture, encoding="utf-8")
        if check_text(path.read_text(encoding="utf-8"), fields, sites, 1,
                      Counter()):
            return 1
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 2:
        print("usage: check-wyctl-option-ownership.py WYCTL_C | --self-test",
              file=sys.stderr)
        return 2
    return check_file(Path(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())

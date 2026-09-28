#!/usr/bin/env python3
"""Fail when a daemon HTTP route has neither a wyctl command nor a reason.

The route list is the one tools/check-daemon-http-route-registrations.py
already proves against wyrelog/daemon/http.c, so this gate keeps no second
copy of it.  The /facts prefix is expanded into its operations by reading
the suffixes parse_fact_op_path accepts.  /datalog serves one operation.
/service-principals and /service-credentials dispatch several operations by
method and path shape; each is counted as one route family here, so a new
operation inside those families is not caught (a known limitation, noted in
docs/operator-runbook.md).

Every route must appear in exactly one table:

  COVERAGE     route -> wyctl command path that drives it
  HTTP_ONLY    route -> why an operator has no wyctl command for it
  UNSUPPORTED  route -> why the daemon refuses it outright
  PENDING      route -> wyctl command path planned under #1238

Each COVERAGE path must be listed in tests/test-wyctl-runbook-options.py
COMMAND_PATHS (which runs `wyctl PATH --help`) and each of its steps must be
dispatched by its parent command in wyrelog/wyctl/wyctl.c.  A PENDING path
already dispatched there fails, so implementing a command forces its route
into COVERAGE.  Once a parent dispatches a step, DISPATCHERS must name the
function that dispatches the next one, so a renamed dispatcher fails instead
of reading as "not dispatched".  HTTP_ONLY and UNSUPPORTED routes must be
named in the runbook's "Routes Without a wyctl Command" section.

The route-to-command mapping is maintained by hand: the gate proves that
the command exists and is dispatched, not that it calls that route.  A
dispatch line is read textually, so one disabled by `#if 0` or `&& FALSE`
still counts as dispatched.
"""

from __future__ import annotations

import ast
import functools
import importlib.util
from pathlib import Path
import re
import sys
import tempfile


FACT_OPERATION_ROUTE = "/facts/{tenant}/{graph}/{relation}:{op}"
RUNBOOK_SECTION = "## Routes Without a wyctl Command"
UNSUPPORTED_HEADING = "### Unsupported by the daemon"

COVERAGE = {
    "/healthz": ("status",),
    "/readyz": ("status",),
    "/facts/quota": ("fact", "quota", "configure"),
    "/facts/quota/operation-status": ("fact", "quota", "operation-status"),
    "/facts/schema/register": ("fact", "schema", "register"),
    "/facts/{tenant}/{graph}/{relation}:append": ("fact", "put"),
    "/facts/{tenant}/{graph}/{relation}:retract": ("fact", "retract"),
    "/datalog": ("datalog", "query"),
    "/auth/login": ("auth", "login"),
    "/auth/mfa/verify": ("auth", "login"),
    "/auth/mfa/enroll/start": ("mfa", "enroll"),
    "/auth/mfa/enroll/confirm": ("mfa", "enroll"),
    "/auth/refresh": ("auth", "refresh"),
    "/auth/logout": ("auth", "logout"),
    "/graphs/create": ("graph", "create"),
    "/decide": ("policy", "check"),
    "/policy/permissions/grant": ("policy", "permission-grant"),
    "/policy/permissions/revoke": ("policy", "permission-revoke"),
    "/policy/permissions/transition": ("policy", "permission-transition"),
    "/policy/roles/grant": ("policy", "role-grant"),
    "/policy/roles/revoke": ("policy", "role-revoke"),
    "/audit/events": ("audit", "query"),
    "/service-principals": ("service-principal", "create"),
    "/service-credentials": ("service-credential", "revoke"),
    "/service-credential-operations": ("service-credential", "status"),
    "/service-credential-operations/recover": ("service-credential",
                                               "recover"),
    "/auth/service-token": ("auth", "service-token"),
}

HTTP_ONLY = {
    "/facts/{tenant}/{graph}/{relation}:repair":
        "no wyctl command yet; repair through the HTTP route described in the "
        "runbook (#1280)",
    "/profile/events":
        "machine-to-machine event forwarding from the service profile to "
        "the system profile; not an operator action",
    "/service-management-authority/arm":
        "no wyctl command yet; arm through the HTTP route (#1269)",
    "/service-credential-operations/reconcile":
        "no wyctl command yet; the client library exposes it (#1270)",
}

UNSUPPORTED = {
    "/tenants/delete":
        "the daemon answers 501 tenant_delete_unsupported; retire a tenant "
        "with a tenant seal",
}

PENDING = {
    "/facts/status": ("fact", "status"),
    "/facts/verify": ("fact", "verify"),
    "/facts/{tenant}/{graph}/{relation}:forget": ("fact", "forget"),
    "/graphs": ("graph", "list"),
    "/graphs/seal": ("graph", "seal"),
    "/tenants": ("tenant", "list"),
    "/tenants/create": ("tenant", "create"),
    "/tenants/seal": ("tenant", "seal"),
    "/tenants/unseal": ("tenant", "unseal"),
    "/profile/status": ("profile", "status"),
}

# The function in wyctl.c that dispatches the next step after each prefix.
DISPATCHERS = {
    (): "main",
    ("policy",): "run_policy",
    ("graph",): "run_graph",
    ("fact",): "run_fact",
    ("fact", "schema"): "run_fact_schema",
    ("fact", "quota"): "run_fact_quota_command",
    ("datalog",): "run_datalog",
    ("audit",): "run_audit",
    ("key",): "run_key",
    ("mfa",): "run_mfa",
    ("auth",): "run_auth",
    ("service-principal",): "run_service_principal",
    ("service-credential",): "run_service_credential",
    ("service-permission-closure",): "run_service_permission_closure",
    ("tenant",): "run_tenant",
    ("profile",): "run_profile",
}


class GateError(Exception):
    pass


def load_route_registrations(root: Path):
    tools = root / "tools"
    sys.path.insert(0, str(tools))
    try:
        spec = importlib.util.spec_from_file_location(
            "daemon_http_route_registrations",
            tools / "check-daemon-http-route-registrations.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop("daemon_http_route_registrations", None)
        sys.path.remove(str(tools))
    return [route.path for route in module.ROUTES], set(module.PREFIX_PATHS)


C_TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"'
                     r"|'(?:\\.|[^'\\\n])*'"
                     r"|/\*.*?\*/|//[^\n]*", re.DOTALL)


@functools.lru_cache(maxsize=8)
def strip_comments(source: str) -> str:
    """Blank comments, leaving string and character literals intact, so a
    "//" or "/*" inside a string cannot erase the code after it."""
    return C_TOKEN.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'"
                       else " ", source)


def function_body(source: str, name: str) -> str:
    """Return the body of the one definition of NAME, GNU style: the name
    at column 0 and the opening brace on its own line after the parameters.
    A prototype, which ends in ';', never matches."""
    source = strip_comments(source)
    matches = list(re.finditer(
        r"^" + re.escape(name) + r" \([^;{]*?\)\s*\n\{", source,
        re.MULTILINE))
    if not matches:
        raise GateError(f"no definition of {name}")
    if len(matches) > 1:
        raise GateError(f"{name} is defined {len(matches)} times; the gate "
                        "reads one definition")
    opening = matches[0].end() - 1
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening:index + 1]
    raise GateError(f"unbalanced body of {name}")


FACT_SUFFIX = re.compile(
    r'g_str_has_suffix\s*\(\s*parts\s*\[\s*2\s*\]\s*,\s*'
    r'":([A-Za-z_]+)"\s*\)')
FACT_OP_ENUM = re.compile(r"typedef\s+enum\s*\{([^}]*)\}\s*fact_http_op_t\s*;")


def fact_operations(http_source: str) -> list[str]:
    """The suffixes parse_fact_op_path accepts, in any spacing.  They must
    name exactly the FACT_HTTP_OP_* members of fact_http_op_t, so an
    operation added in a form this pattern does not read still fails."""
    body = function_body(http_source, "parse_fact_op_path")
    operations = FACT_SUFFIX.findall(body)
    if not operations:
        raise GateError("http.c: parse_fact_op_path accepts no operation")
    enum = FACT_OP_ENUM.search(strip_comments(http_source))
    if enum is None:
        raise GateError("http.c: no fact_http_op_t enum")
    members = {name.lower() for name in
               re.findall(r"\bFACT_HTTP_OP_([A-Z_]+)\b", enum.group(1))}
    if members != set(operations):
        raise GateError("http.c: fact_http_op_t members "
                        f"{sorted(members)} differ from the suffixes "
                        f"parse_fact_op_path reads {sorted(set(operations))}")
    return operations


def daemon_routes(root: Path) -> list[str]:
    routes, prefixes = load_route_registrations(root)
    http_source = (root / "wyrelog/daemon/http.c").read_text(encoding="utf-8")
    expanded = []
    for route in routes:
        if route == "/facts":
            if route not in prefixes:
                raise GateError("/facts is no longer a prefix route")
            expanded.extend(FACT_OPERATION_ROUTE.format(
                tenant="{tenant}", graph="{graph}", relation="{relation}",
                op=op) for op in fact_operations(http_source))
        else:
            expanded.append(route)
    return expanded


def dispatched(source: str, path: tuple[str, ...]) -> bool:
    """True when every step of PATH is dispatched by its parent.  A missing
    DISPATCHERS entry or function for a prefix the parent already dispatches
    raises, so it cannot pass as "not dispatched"."""
    for depth, step in enumerate(path):
        prefix = path[:depth]
        parent = DISPATCHERS.get(prefix)
        if parent is None:
            raise GateError(f"wyctl dispatches {' '.join(prefix)} but "
                            "DISPATCHERS names no function for it")
        body = function_body(source, parent)
        needle = (r'g_strcmp0\s*\(\s*argv\s*\[\s*1\s*\]\s*,\s*"'
                  + re.escape(step) + r'"\s*\)\s*==\s*0')
        if re.search(needle, body) is None:
            return False
    return True


def runbook_command_paths(root: Path) -> set[tuple[str, ...]]:
    text = (root / "tests/test-wyctl-runbook-options.py").read_text(
        encoding="utf-8")
    match = re.search(r"^COMMAND_PATHS = (\{.*?^\})", text,
                      re.MULTILINE | re.DOTALL)
    if match is None:
        raise GateError("test-wyctl-runbook-options.py: no COMMAND_PATHS")
    return set(ast.literal_eval(match.group(1)))


def runbook_section(root: Path) -> str:
    text = (root / "docs/operator-runbook.md").read_text(encoding="utf-8")
    start = text.find(RUNBOOK_SECTION + "\n")
    if start < 0:
        raise GateError(f"operator-runbook.md: no '{RUNBOOK_SECTION}'")
    end = text.find("\n## ", start + len(RUNBOOK_SECTION))
    return text[start:end if end >= 0 else len(text)]


def check(root: Path, coverage=COVERAGE, http_only=HTTP_ONLY,
          unsupported=UNSUPPORTED, pending=PENDING) -> list[str]:
    errors = []
    routes = daemon_routes(root)
    tables = {"COVERAGE": coverage, "HTTP_ONLY": http_only,
              "UNSUPPORTED": unsupported, "PENDING": pending}
    for route in routes:
        owners = [name for name, table in tables.items() if route in table]
        if not owners:
            errors.append(f"unacknowledged daemon route: {route}")
        elif len(owners) > 1:
            errors.append(f"route in several tables: {route}: {owners}")
    for name, table in tables.items():
        for route in table:
            if route not in routes:
                errors.append(f"{name} names no daemon route: {route}")

    wyctl_source = (root / "wyrelog/wyctl/wyctl.c").read_text(
        encoding="utf-8")
    command_paths = runbook_command_paths(root)
    def is_dispatched(route, path):
        try:
            return dispatched(wyctl_source, path)
        except GateError as error:
            errors.append(f"{route}: wyctl.c: {error}")
            return None

    for route, path in coverage.items():
        if path not in command_paths:
            errors.append(f"{route}: {' '.join(path)} is not in "
                          "test-wyctl-runbook-options.py COMMAND_PATHS")
        if is_dispatched(route, path) is False:
            errors.append(f"{route}: wyctl does not dispatch "
                          f"{' '.join(path)}")
    for route, path in pending.items():
        if is_dispatched(route, path):
            errors.append(f"{route}: wyctl already dispatches "
                          f"{' '.join(path)}; move it to COVERAGE")

    section = runbook_section(root)
    unsupported_at = section.find(UNSUPPORTED_HEADING)
    for table in (http_only, unsupported):
        for route, reason in table.items():
            if not reason.strip():
                errors.append(f"{route}: empty reason")
    for route in http_only:
        head = section if unsupported_at < 0 else section[:unsupported_at]
        if f"`{route}`" not in head:
            errors.append(f"{route}: not listed in the runbook section "
                          f"'{RUNBOOK_SECTION}'")
    for route in unsupported:
        if unsupported_at < 0 or f"`{route}`" not in section[unsupported_at:]:
            errors.append(f"{route}: not listed under '{UNSUPPORTED_HEADING}'")
    return errors


def summary(http_only=HTTP_ONLY, unsupported=UNSUPPORTED,
            pending=PENDING) -> str:
    lines = ["daemon routes without a wyctl command:"]
    for label, table in (("http-only", http_only),
                         ("unsupported", unsupported)):
        for route, reason in sorted(table.items()):
            lines.append(f"  {label:<11} {route}: {reason}")
    for route, path in sorted(pending.items()):
        lines.append(f"  {'pending':<11} {route}: planned "
                     f"`wyctl {' '.join(path)}`")
    return "\n".join(lines)


def copy_fixture(root: Path, target: Path) -> None:
    for relative in ("tools/check-daemon-http-route-registrations.py",
                     "tools/_diag_path.py", "wyrelog/daemon/http.c",
                     "wyrelog/wyctl/wyctl.c",
                     "tests/test-wyctl-runbook-options.py",
                     "docs/operator-runbook.md"):
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text((root / relative).read_text(encoding="utf-8"),
                               encoding="utf-8")


def edit(target: Path, relative: str, old: str, new: str) -> None:
    path = target / relative
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise GateError(f"self-test anchor in {relative} is not unique: "
                        f"{old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def expect(errors: list[str], fragment: str, label: str) -> None:
    if not any(fragment in error for error in errors):
        raise GateError(f"self-test '{label}' did not fail on {fragment!r}: "
                        f"{errors}")


def self_test(root: Path) -> None:
    baseline = check(root)
    if baseline:
        raise GateError("self-test needs a passing tree: " + "; ".join(
            baseline))

    def with_entry(table, key, value):
        copy = dict(table)
        copy[key] = value
        return copy

    def mutated(label, mutate, fragment, coverage=COVERAGE,
                http_only=HTTP_ONLY, pending=PENDING):
        # Each mutation must fail on the error it names, not merely fail.
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch)
            copy_fixture(root, target)
            if mutate is not None:
                mutate(target)
            try:
                errors = check(target, coverage=coverage,
                               http_only=http_only, pending=pending)
            except GateError as error:
                errors = [str(error)]
            expect(errors, fragment, label)

    def add_fact_operation(target, suffix_call):
        edit(target, "wyrelog/daemon/http.c", "  FACT_HTTP_OP_FORGET,\n",
             "  FACT_HTTP_OP_FORGET,\n  FACT_HTTP_OP_PURGE,\n")
        edit(target, "wyrelog/daemon/http.c", '":retract")) {',
             '":retract") || ' + suffix_call + ' {')

    covered = dict(COVERAGE)
    del covered["/decide"]
    mutated("unacknowledged route", None,
            "unacknowledged daemon route: /decide", coverage=covered)
    mutated("stale key", None, "COVERAGE names no daemon route: /gone",
            coverage=with_entry(COVERAGE, "/gone", ("status",)))
    mutated("route in two tables", None, "route in several tables: /healthz",
            http_only=with_entry(HTTP_ONLY, "/healthz", "twice"))
    mutated("new fact operation",
            lambda t: add_fact_operation(
                t, 'g_str_has_suffix (parts[2], ":purge"))'),
            "unacknowledged daemon route: "
            "/facts/{tenant}/{graph}/{relation}:purge")
    mutated("covered path missing from COMMAND_PATHS",
            lambda t: edit(t, "tests/test-wyctl-runbook-options.py",
                           '    ("audit", "query"): 2,\n', ""),
            "audit query is not in test-wyctl-runbook-options.py")
    mutated("step dispatched under the wrong parent", None,
            "wyctl does not dispatch graph status",
            coverage=with_entry(COVERAGE, "/healthz", ("graph", "status")))
    mutated("pending command already dispatched", None,
            "/graphs: wyctl already dispatches graph create",
            pending=with_entry(PENDING, "/graphs", ("graph", "create")))
    mutated("http-only route missing from the runbook",
            lambda t: edit(t, "docs/operator-runbook.md", "`/profile/events`",
                           "profile events"),
            "/profile/events: not listed in the runbook section")
    mutated("unsupported route outside its heading",
            lambda t: edit(t, "docs/operator-runbook.md", UNSUPPORTED_HEADING,
                           "### Removed heading"),
            "/tenants/delete: not listed under")
    mutated("new daemon route",
            lambda t: edit(t, "tools/check-daemon-http-route-registrations.py",
                           '    RouteSpec("/datalog", "datalog_query_handler"),'
                           '\n',
                           '    RouteSpec("/datalog", "datalog_query_handler"),'
                           '\n    RouteSpec("/brand-new", "new_handler"),\n'),
            "unacknowledged daemon route: /brand-new")
    mutated("dispatch line deleted",
            lambda t: edit(t, "wyrelog/wyctl/wyctl.c",
                           'g_strcmp0 (argv[1], "retract") == 0',
                           'g_strcmp0 (argv[1], "retract-renamed") == 0'),
            "wyctl does not dispatch fact retract")
    mutated("empty reason", None, "/profile/events: empty reason",
            http_only=with_entry(HTTP_ONLY, "/profile/events", " "))
    mutated("dispatcher missing from DISPATCHERS", None,
            "DISPATCHERS names no function",
            coverage=with_entry(COVERAGE, "/healthz",
                                ("key", "rotate", "now")))
    mutated("new fact operation without the space",
            lambda t: add_fact_operation(
                t, 'g_str_has_suffix(parts[2],":purge"))'),
            "unacknowledged daemon route: "
            "/facts/{tenant}/{graph}/{relation}:purge")
    mutated("fact operation added in an unread form",
            lambda t: edit(t, "wyrelog/daemon/http.c",
                           "  FACT_HTTP_OP_FORGET,\n",
                           "  FACT_HTTP_OP_FORGET,\n  FACT_HTTP_OP_PURGE,\n"),
            "fact_http_op_t members")
    mutated("pending dispatch respaced",
            lambda t: edit(t, "wyrelog/wyctl/wyctl.c",
                           'if (g_strcmp0 (argv[1], "create") == 0)\n'
                           '    return run_graph_create',
                           'if (g_strcmp0(argv[1],"create")==0)\n'
                           '    return run_graph_create'),
            "/graphs: wyctl already dispatches graph create",
            pending=with_entry(PENDING, "/graphs", ("graph", "create")))
    mutated("comment opener inside a string",
            lambda t: edit(t, "wyrelog/wyctl/wyctl.c",
                           '    g_printerr ("wyctl: missing graph command\\n");',
                           '    g_printerr ("wyctl: missing graph /* command'
                           '\\n");'),
            "/graphs: wyctl already dispatches graph create",
            pending=with_entry(PENDING, "/graphs", ("graph", "create")))
    mutated("dispatcher renamed",
            lambda t: edit(t, "wyrelog/wyctl/wyctl.c",
                           "\nrun_graph (const WyctlOptions",
                           "\nrun_graph_command (const WyctlOptions"),
            "no definition of run_graph")


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "--self-test":
        root = Path(argv[2]).resolve()
        try:
            self_test(root)
        except GateError as error:
            print(f"wyctl route coverage self-test: {error}", file=sys.stderr)
            return 1
        print("wyctl route coverage self-test: OK")
        return 0
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] != "--list"):
        print(f"usage: {argv[0]} SOURCE_ROOT [--list] | --self-test "
              "SOURCE_ROOT", file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    try:
        errors = check(root)
    except GateError as error:
        errors = [str(error)]
    if len(argv) == 3:
        print(summary())
    if errors:
        for error in errors:
            print(f"wyctl route coverage: {error}", file=sys.stderr)
        return 1
    if len(argv) == 2:
        print(summary())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

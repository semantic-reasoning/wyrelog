#!/usr/bin/env python3
"""Check every wyctl invocation in runbook command blocks against CLI help."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


COMMAND_PATHS = {
    ("status",): 1,
    ("profile", "status"): 2,
    ("policy", "check"): 2,
    ("policy", "explain"): 2,
    ("policy", "permission-grant"): 2,
    ("policy", "permission-revoke"): 2,
    ("policy", "permission-transition"): 2,
    ("policy", "role-grant"): 2,
    ("policy", "role-revoke"): 2,
    ("tenant", "list"): 2,
    ("tenant", "create"): 2,
    ("tenant", "seal"): 2,
    ("tenant", "unseal"): 2,
    ("tenant", "assign-owner"): 2,
    ("graph", "create"): 2,
    ("graph", "list"): 2,
    ("graph", "seal"): 2,
    ("fact", "schema", "register"): 3,
    ("fact", "quota", "configure"): 3,
    ("fact", "quota", "status"): 3,
    ("fact", "quota", "operation-status"): 3,
    ("fact", "put"): 2,
    ("fact", "retract"): 2,
    ("fact", "forget"): 2,
    ("fact", "status"): 2,
    ("fact", "verify"): 2,
    ("datalog", "query"): 2,
    ("audit", "query"): 2,
    ("key", "status"): 2,
    ("key", "rotate"): 2,
    ("key", "recover"): 2,
    ("mfa", "enroll"): 2,
    ("mfa", "reset"): 2,
    ("auth", "service-token"): 2,
    ("auth", "login"): 2,
    ("auth", "refresh"): 2,
    ("auth", "logout"): 2,
    ("service-principal", "create"): 2,
    ("service-principal", "list"): 2,
    ("service-principal", "disable"): 2,
    ("service-credential", "issue"): 2,
    ("service-credential", "rotate"): 2,
    ("service-credential", "list"): 2,
    ("service-credential", "revoke"): 2,
    ("service-credential", "recover"): 2,
    ("service-credential", "status"): 2,
    ("service-permission-closure", "inspect"): 2,
    ("service-permission-closure", "dry-run"): 2,
    ("service-permission-closure", "apply"): 2,
}
GLOBAL_OPTIONS_WITH_VALUES = {"--daemon-url", "--timeout-ms"}
HELP_OPTIONS = re.compile(r"--[a-z][a-z0-9-]*")
REQUIRED_GUARDS = {
    ("policy", "permission-grant"),
    ("policy", "permission-revoke"),
    ("policy", "permission-transition"),
    ("policy", "role-grant"),
    ("policy", "role-revoke"),
    ("audit", "query"),
    ("service-principal", "list"),
    ("fact", "forget"),
    ("fact", "verify"),
    ("graph", "list"),
    ("graph", "seal"),
    ("tenant", "list"),
    ("tenant", "create"),
    ("tenant", "seal"),
    ("tenant", "unseal"),
}
GUARD_OPTIONS = {
    "--guard-timestamp", "--guard-loc-class", "--guard-risk",
}
# Option values wyctl validates locally.  The location classes mirror
# wyl_guard_loc_class_is_valid (wyrelog/wyl-permission-scope.c); an
# example passing any other value exits 2 before reaching the daemon.
OPTION_VALUES = {
    "--guard-loc-class": {"trusted", "semi_trusted", "public", "untrusted"},
}
# Option values the daemon resolves against the shipped templates: an
# example naming an undeclared permission or role fails with
# invalid_policy_mutation against a real daemon.
TEMPLATE_DECLARATIONS = {
    "--perm": re.compile(r'^permission\("([^"]+)"\)\.', re.MULTILINE),
    "--role": re.compile(r'^role\("([^"]+)"\)\.', re.MULTILINE),
}
# The guard catalogue (wyrelog/wyl-permission-scope.c) is decided by the
# request guard; the daemon refuses a transition for any of its entries.
CATALOGUE_ENTRY = re.compile(r'^\s*\{"([^"]+)", build_[a-z_]+\},$', re.MULTILINE)


def runbook_invocations(path: Path) -> list[tuple[int, list[str]]]:
    text = path.read_text(encoding="utf-8")
    in_command_block = False
    lines: list[str] = []
    invocations: list[tuple[int, list[str]]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped_line = line.lstrip()
        if stripped_line.startswith("```"):
            if in_command_block:
                in_command_block = False
            else:
                in_command_block = (
                    stripped_line.startswith("```sh")
                    or stripped_line.startswith("```bash")
                    or stripped_line.startswith("```powershell")
                    or stripped_line.startswith("```pwsh"))
            continue
        if not in_command_block:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if lines:
            lines[-1] += " " + stripped.rstrip("\\^`").strip()
        else:
            lines.append(stripped.rstrip("\\^`").strip())
        if line.rstrip().endswith(("\\", "^", "`")):
            continue
        command = lines.pop()
        try:
            words = shlex.split(command, posix=True)
        except ValueError as exc:
            raise AssertionError(f"{path}:{line_number}: cannot parse {command!r}: {exc}")
        if words and Path(words[0]).name.lower() in ("wyctl", "wyctl.exe"):
            invocations.append((line_number, words[1:]))
        elif len(words) > 1 and Path(words[0]).name.lower() in ("sudo", "env") \
                and Path(words[1]).name.lower() in ("wyctl", "wyctl.exe"):
            invocations.append((line_number, words[2:]))
    if lines:
        raise AssertionError(f"{path}: unterminated continued command")
    return invocations


def command_and_options(arguments: list[str]) -> tuple[tuple[str, ...], list[str]]:
    position = 0
    while position < len(arguments):
        token = arguments[position]
        if token in GLOBAL_OPTIONS_WITH_VALUES:
            position += 2
        elif token == "--version":
            position += 1
        elif token.startswith("-"):
            raise AssertionError(f"unexpected global option before command: {token}")
        else:
            break
    if position >= len(arguments):
        raise AssertionError("wyctl invocation has no command")
    root = arguments[position]
    nested_counts = sorted(
        ((path, count) for path, count in COMMAND_PATHS.items()
         if path[0] == root), key=lambda entry: entry[1], reverse=True)
    for path, count in nested_counts:
        candidate = tuple(arguments[position:position + count])
        if candidate == path:
            return path, arguments[position + count:]
    raise AssertionError(f"unknown runbook command path beginning {root!r}")


def option_values(arguments: list[str]) -> list[tuple[str, str]]:
    """Pair each documented --option with its value, in either form."""
    pairs: list[tuple[str, str]] = []
    for position, token in enumerate(arguments):
        if not token.startswith("--"):
            continue
        if "=" in token:
            option, value = token.split("=", 1)
            pairs.append((option, value))
        elif position + 1 < len(arguments) \
                and not arguments[position + 1].startswith("--"):
            pairs.append((token, arguments[position + 1]))
    return pairs


def supported_options(wyctl: Path, path: tuple[str, ...]) -> set[str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["WYCTL_DISABLE_GSETTINGS"] = "1"
    completed = subprocess.run(
        [str(wyctl), *path, "--help"], check=False, capture_output=True,
        text=True, env=environment)
    if completed.returncode != 0:
        raise AssertionError(
            f"{path}: --help exited {completed.returncode}: {completed.stderr}")
    return set(HELP_OPTIONS.findall(completed.stdout))


def template_declarations(source_root: Path) -> dict[str, set[str]]:
    templates = sorted((source_root / "templates" / "access").glob("*.dl"))
    if not templates:
        raise AssertionError(f"{source_root}: no templates/access/*.dl")
    text = "\n".join(path.read_text(encoding="utf-8") for path in templates)
    declared = {
        option: set(pattern.findall(text))
        for option, pattern in TEMPLATE_DECLARATIONS.items()
    }
    for option, names in declared.items():
        if not names:
            raise AssertionError(f"{source_root}: templates declare no {option}")
    return declared


def guard_catalogue(source_root: Path) -> set[str]:
    source = source_root / "wyrelog" / "wyl-permission-scope.c"
    entries = set(CATALOGUE_ENTRY.findall(source.read_text(encoding="utf-8")))
    if len(entries) != 12:
        raise AssertionError(
            f"{source}: expected 12 guard catalogue entries, found "
            f"{len(entries)}")
    return entries


def check(wyctl: Path, runbook: Path, source_root: Path) -> list[str]:
    errors: list[str] = []
    declared = template_declarations(source_root)
    catalogue = guard_catalogue(source_root)
    content = runbook.read_text(encoding="utf-8")
    for required in (
        "auth login",
        "auth refresh",
        "auth logout",
        "/auth/mfa/verify",
        "application/json",
        "refresh-token-output",
    ):
        if required not in content:
            errors.append(f"{runbook}: bootstrap flow is missing {required!r}")
    invocations = runbook_invocations(runbook)
    if not invocations:
        return [f"{runbook}: found no wyctl commands in command blocks"]
    if len(invocations) != 69:
        errors.append(
            f"{runbook}: expected 69 reviewed wyctl invocations, found "
            f"{len(invocations)}")
    if sum(arguments == ["status"] for _, arguments in invocations) != 2:
        errors.append(
            f"{runbook}: expected both standalone Linux and pwsh status examples")
    cache: dict[tuple[str, ...], set[str]] = {}
    for line, arguments in invocations:
        try:
            path, command_arguments = command_and_options(arguments)
            if path not in cache:
                cache[path] = supported_options(wyctl, path)
            options = cache[path]
            documented = {
                token.split("=", 1)[0] for token in command_arguments
                if token.startswith("--") and token != "--help"
            }
            if path in REQUIRED_GUARDS:
                missing_guards = sorted(GUARD_OPTIONS - documented)
                if missing_guards:
                    errors.append(
                        f"{runbook}:{line}: {path} missing required guards "
                        f"{', '.join(missing_guards)}")
            missing = sorted(documented - options)
            if missing:
                errors.append(
                    f"{runbook}:{line}: {path} does not support "
                    f"{', '.join(missing)}")
            for option, value in option_values(command_arguments):
                accepted = OPTION_VALUES.get(option)
                if accepted is not None and value not in accepted:
                    errors.append(
                        f"{runbook}:{line}: {path} passes {option} "
                        f"{value!r}; wyctl accepts "
                        f"{', '.join(sorted(accepted))}")
                names = declared.get(option)
                if names is not None and "$" not in value \
                        and value not in names:
                    errors.append(
                        f"{runbook}:{line}: {path} passes {option} "
                        f"{value!r}, which the shipped templates do not "
                        f"declare")
                if path == ("policy", "permission-transition") \
                        and option == "--perm" and value in catalogue:
                    errors.append(
                        f"{runbook}:{line}: {path} arms {value!r}, which "
                        f"the guard catalogue decides by request guard")
        except AssertionError as exc:
            errors.append(f"{runbook}:{line}: {exc}")
    return errors


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: test-wyctl-runbook-options.py WYCTL RUNBOOK SOURCE_ROOT",
              file=sys.stderr)
        return 2
    errors = check(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"checked {len(runbook_invocations(Path(sys.argv[2])))} runbook wyctl invocations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

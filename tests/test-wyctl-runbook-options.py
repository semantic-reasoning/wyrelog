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
    ("policy", "check"): 2,
    ("policy", "explain"): 2,
    ("policy", "permission-grant"): 2,
    ("policy", "permission-revoke"): 2,
    ("policy", "role-grant"): 2,
    ("policy", "role-revoke"): 2,
    ("graph", "create"): 2,
    ("fact", "schema", "register"): 3,
    ("fact", "quota", "configure"): 3,
    ("fact", "quota", "status"): 3,
    ("fact", "quota", "operation-status"): 3,
    ("fact", "put"): 2,
    ("fact", "retract"): 2,
    ("datalog", "query"): 2,
    ("audit", "query"): 2,
    ("key", "status"): 2,
    ("key", "rotate"): 2,
    ("key", "recover"): 2,
    ("mfa", "enroll"): 2,
    ("mfa", "reset"): 2,
    ("auth", "service-token"): 2,
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
    ("policy", "role-grant"),
    ("policy", "role-revoke"),
    ("audit", "query"),
    ("service-principal", "list"),
}
GUARD_OPTIONS = {
    "--guard-timestamp", "--guard-loc-class", "--guard-risk",
}


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
            lines[-1] += " " + stripped.rstrip("\\^").strip()
        else:
            lines.append(stripped.rstrip("\\^").strip())
        if line.rstrip().endswith(("\\", "^")):
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


def check(wyctl: Path, runbook: Path) -> list[str]:
    errors: list[str] = []
    content = runbook.read_text(encoding="utf-8")
    for required in (
        "tenant=__wr_default&skip_mfa=true",
        "os.O_EXCL",
        "/auth/mfa/verify",
        "new MFA-assured access token",
    ):
        if required not in content:
            errors.append(f"{runbook}: bootstrap flow is missing {required!r}")
    invocations = runbook_invocations(runbook)
    if not invocations:
        return [f"{runbook}: found no wyctl commands in command blocks"]
    if len(invocations) != 41:
        errors.append(
            f"{runbook}: expected 41 reviewed wyctl invocations, found "
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
        except AssertionError as exc:
            errors.append(f"{runbook}:{line}: {exc}")
    return errors


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: test-wyctl-runbook-options.py WYCTL RUNBOOK", file=sys.stderr)
        return 2
    errors = check(Path(sys.argv[1]), Path(sys.argv[2]))
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"checked {len(runbook_invocations(Path(sys.argv[2])))} runbook wyctl invocations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

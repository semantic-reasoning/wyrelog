#!/usr/bin/env python3
"""Validate offline restore runbook commands against wyctl's current CLI."""

from pathlib import Path
import re
import shlex
import subprocess
import sys


ROUTES = {"dry-run", "begin", "prepare", "commit", "resume", "abort", "status"}
OPTIONS = {
    "--scope", "--tenant", "--graph", "--bundle", "--trusted-sha256",
    "--uuid", "--revision", "--format", "--confirm", "--retry-begin",
    "--access-token-file", "--guard-timestamp", "--guard-loc-class",
    "--guard-risk",
}
REQUIRED_GUARDS = {
    "--access-token-file", "--guard-timestamp", "--guard-loc-class",
    "--guard-risk",
}
HELP_OPTION = re.compile(r"--[a-z][a-z0-9-]*")


def commands(path: Path):
    inside = False
    pending = ""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            inside = stripped.startswith(("```sh", "```bash")) if not inside else False
            continue
        if not inside or not stripped:
            continue
        pending += " " + stripped.rstrip("\\").strip()
        if line.rstrip().endswith("\\"):
            continue
        try:
            words = shlex.split(pending)
        except ValueError as error:
            raise AssertionError(f"{path}:{number}: invalid shell example: {error}")
        pending = ""
        if words and Path(words[0]).name == "wyctl":
            yield number, words[1:]
    if pending:
        raise AssertionError(f"{path}: command continuation is not terminated")


def parse(words):
    position = 0
    if words[:1] == ["--daemon-url"]:
        position = 2
    if words[position:position + 2] != ["fact", "restore"]:
        raise AssertionError("expected `fact restore` command")
    route_index = position + 2
    route = words[route_index]
    if route not in ROUTES:
        raise AssertionError(f"unknown restore route {route!r}")
    args = words[route_index + 1:]
    found = {token.split("=", 1)[0] for token in args if token.startswith("--")}
    missing = REQUIRED_GUARDS - found
    if missing:
        raise AssertionError(f"missing common options: {', '.join(sorted(missing))}")
    unknown = found - OPTIONS
    if unknown:
        raise AssertionError(f"unknown options: {', '.join(sorted(unknown))}")
    required = {"--scope", "--tenant", "--format"}
    if route != "dry-run":
        required.add("--uuid")
    if route in {"dry-run", "begin", "prepare", "commit"}:
        required |= {"--bundle", "--trusted-sha256"}
    if route in {"prepare", "commit", "resume", "abort"}:
        required.add("--revision")
    if route in {"begin", "commit", "abort"}:
        required.add("--confirm")
    if "--retry-begin" in found:
        required |= {"--bundle", "--trusted-sha256"}
        if route != "status":
            raise AssertionError("--retry-begin is only valid on status")
    missing = required - found
    if missing:
        raise AssertionError(f"{route} missing required options: {', '.join(sorted(missing))}")
    scope_value = next((args[i + 1] for i, token in enumerate(args[:-1])
                        if token == "--scope"), None)
    if scope_value not in {"tenant", "graph"}:
        raise AssertionError("--scope must be tenant or graph")
    if scope_value == "graph" and "--graph" not in found:
        raise AssertionError("graph scope requires --graph")
    if scope_value == "tenant" and "--graph" in found:
        raise AssertionError("tenant scope does not accept --graph")
    forbidden = {
        "dry-run": {"--uuid", "--revision", "--confirm", "--retry-begin"},
        "begin": {"--revision", "--retry-begin"},
        "prepare": {"--confirm", "--retry-begin"},
        "commit": {"--retry-begin"},
        "resume": {"--bundle", "--trusted-sha256", "--confirm", "--retry-begin"},
        "abort": {"--bundle", "--trusted-sha256", "--retry-begin"},
        "status": {"--revision", "--confirm"},
    }[route]
    present = forbidden & found
    if present:
        raise AssertionError(f"{route} has forbidden options: {', '.join(sorted(present))}")
    return route, found


def main():
    if len(sys.argv) != 3:
        print("usage: test-offline-restore-runbook.py WYCTL RUNBOOK", file=sys.stderr)
        return 2
    wyctl, runbook = Path(sys.argv[1]), Path(sys.argv[2])
    cache = {}
    found_routes = set()
    count = 0
    errors = []
    for number, words in commands(runbook):
        try:
            route, used = parse(words)
            found_routes.add(route)
            count += 1
            if route not in cache:
                result = subprocess.run(
                    [str(wyctl), "fact", "restore", route, "--help"],
                    capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    raise AssertionError(f"help exited {result.returncode}: {result.stderr}")
                cache[route] = set(HELP_OPTION.findall(result.stdout))
            missing_help = used - cache[route]
            if missing_help:
                raise AssertionError(f"CLI help lacks {', '.join(sorted(missing_help))}")
        except AssertionError as error:
            errors.append(f"{runbook}:{number}: {error}")
    if count < 10:
        errors.append(f"{runbook}: expected at least 10 restore commands, found {count}")
    missing_routes = ROUTES - found_routes
    if missing_routes:
        errors.append(f"{runbook}: missing routes {', '.join(sorted(missing_routes))}")
    text = runbook.read_text(encoding="utf-8")
    for phrase in (
        "PREPARED", "COMMITTING", "UNKNOWN", "foreign", "--retry-begin",
        "| `9` |", "unseal", "Linux", "trusted channel",
        "Restart immediately before COMMIT", "Restart immediately after COMMIT",
        "Foreign artifact walkthrough",
    ):
        if phrase not in text:
            errors.append(f"{runbook}: missing recovery contract {phrase!r}")
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"checked {count} offline restore commands across {len(found_routes)} routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

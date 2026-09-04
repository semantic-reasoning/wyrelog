#!/usr/bin/env python3
"""Reject a duckdb_prepare failure branch that leaks its statement.

duckdb.h:1892: "after calling `duckdb_prepare`, the prepared statement should
always be destroyed using `duckdb_destroy_prepare`, even if the prepare
fails."  The failure branch is the one this tree has repeatedly omitted --
every later branch in the same function destroys correctly.

The check parses the branch the `if` controls rather than looking a fixed
number of lines ahead.  A window scan is unsound in both directions here: it
accepts a `duckdb_destroy_prepare` belonging to the *next* branch -- which is
exactly the shape of this bug, so it certifies it as clean -- and it rejects a
branch whose `goto` reaches a label that destroys.

What this does NOT analyse, stated so the gate is not read as more than it is:

* a prepare inside a `while` or `for` condition, or in a ternary;
* a prepare produced by a macro, which the call regex cannot see;
* a destroy inside a nested block of the branch that cannot actually run;
* a branch that releases through a helper rather than calling
  `duckdb_destroy_prepare` by name -- that is reported as a leak.

None of those shapes exists in the guarded sources today.  The one remaining
shape that seems likely to appear -- assigning the prepare result to a
variable and testing it later -- is refused outright rather than accepted
silently, because accepting it is how a gate becomes decoration.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SOURCES = (
    "wyrelog/audit/conn.c",
    "wyrelog/fact/store.c",
    "wyrelog/fact/compound.c",
    "wyrelog/fact/legacy-store-identity-private.c",
    "wyrelog/fact/replay.c",
    "tests/test-audit-emit.c",
    "tests/test-daemon-http-facts.c",
    "tests/check-audit-events-query.c",
    "tests/test-fact-replay.c",
)

PREPARE = re.compile(r"\bduckdb_prepare\s*\(")
DESTROY = "duckdb_destroy_prepare"
FAILURE = re.compile(r"!=\s*DuckDBSuccess|==\s*DuckDBError")


def strip_noise(source: str) -> str:
    """Blank comments and string literals, preserving every byte offset."""
    out = list(source)
    index = 0
    end = len(source)
    while index < end:
        two = source[index:index + 2]
        if two == "/*":
            close = source.find("*/", index + 2)
            close = end if close == -1 else close + 2
            for position in range(index, close):
                if out[position] != "\n":
                    out[position] = " "
            index = close
        elif two == "//":
            close = source.find("\n", index)
            close = end if close == -1 else close
            for position in range(index, close):
                out[position] = " "
            index = close
        elif source[index] in "\"'":
            quote = source[index]
            position = index + 1
            while position < end:
                if source[position] == "\\":
                    position += 2
                    continue
                if source[position] == quote:
                    position += 1
                    break
                position += 1
            for blank in range(index, min(position, end)):
                if out[blank] != "\n":
                    out[blank] = " "
            index = position
        else:
            index += 1
    return "".join(out)


def matching(text: str, start: int, open_ch: str, close_ch: str) -> int:
    """Offset just past the delimiter matching the one at start."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == open_ch:
            depth += 1
        elif text[index] == close_ch:
            depth -= 1
            if depth == 0:
                return index + 1
    raise ValueError("unterminated delimiter")


def enclosing_if(text: str, prepare_at: int) -> tuple[int, int] | None:
    """Condition span of the `if` whose test contains this prepare call."""
    head = text.rfind("if", 0, prepare_at)
    while head != -1:
        after = head + 2
        while after < len(text) and text[after] in " \t\n":
            after += 1
        if after < len(text) and text[after] == "(":
            close = matching(text, after, "(", ")")
            if after < prepare_at < close:
                return after, close
        head = text.rfind("if", 0, head)
    return None


def branch_body(text: str, condition_end: int) -> str:
    """The statement the `if` controls: a braced block or one statement."""
    index = condition_end
    while index < len(text) and text[index] in " \t\n":
        index += 1
    if index < len(text) and text[index] == "{":
        return text[index:matching(text, index, "{", "}")]
    stop = text.find(";", index)
    return text[index:stop + 1] if stop != -1 else text[index:]


def label_bodies(text: str) -> dict[str, str]:
    """Text from each goto label to the next label or the end of its function.

    Stopping at the next label matters: run to end-of-function instead and a
    label that does not destroy inherits the destroy of one positioned after
    it, which is the same "credit the next branch" error a window scan makes.
    """
    marks = [
        match
        for match in re.finditer(r"^([A-Za-z_]\w*):\s*$", text, re.MULTILINE)
        if match.group(1) not in ("default", "case")
    ]
    bodies: dict[str, str] = {}
    for index, match in enumerate(marks):
        end = text.find("\n}\n", match.end())
        end = len(text) if end == -1 else end
        if index + 1 < len(marks):
            end = min(end, marks[index + 1].start())
        bodies[match.group(1)] = text[match.end():end]
    return bodies


def leaking_sites(source: str) -> list[int]:
    """1-indexed lines of prepare calls whose failure branch never destroys."""
    text = strip_noise(source)
    labels = label_bodies(text)
    leaks = []
    for match in PREPARE.finditer(text):
        span = enclosing_if(text, match.start())
        if span is None:
            if text[:match.start()].rstrip().endswith("="):
                raise ValueError(
                    "duckdb_prepare result assigned to a variable at line "
                    f"{source.count(chr(10), 0, match.start()) + 1}; this gate "
                    "analyses only the inline "
                    "`if (duckdb_prepare (...) != DuckDBSuccess)` form, so "
                    "test the result inline rather than through a variable"
                )
            continue
        condition = text[span[0]:span[1]]
        if not FAILURE.search(condition):
            continue
        body = branch_body(text, span[1])
        if DESTROY in body:
            continue
        reached = re.search(r"\bgoto\s+([A-Za-z_]\w*)\s*;", body)
        if reached is not None and DESTROY in labels.get(reached.group(1), ""):
            continue
        leaks.append(source.count("\n", 0, match.start()) + 1)
    return leaks


def validate(files: dict[str, str]) -> None:
    for path, source in files.items():
        leaks = leaking_sites(source)
        if leaks:
            lines = ", ".join(str(line) for line in leaks)
            raise AssertionError(
                f"{path}: duckdb_prepare failure branch leaks its statement "
                f"at line(s) {lines}; duckdb.h:1892 requires "
                f"duckdb_destroy_prepare even when the prepare fails"
            )


def self_test() -> None:
    safe_plain = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return 1;
  }
  return 0;
}
"""
    leaking_plain = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) != DuckDBSuccess)
    return 1;
  if (duckdb_bind_varchar (stmt, 1, v) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return 1;
  }
  return 0;
}
"""
    safe_goto = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) != DuckDBSuccess) {
    goto out;
  }
  return 0;
out:
  duckdb_destroy_prepare (&stmt);
  return 1;
}
"""
    leaking_goto = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) != DuckDBSuccess) {
    goto out;
  }
  return 0;
out:
  return 1;
}
"""
    commented = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) != DuckDBSuccess)
    /* duckdb_destroy_prepare (&stmt); */
    return 1;
  return 0;
}
"""
    stringy = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) != DuckDBSuccess)
    return fail ("duckdb_destroy_prepare");
  return 0;
}
"""
    not_a_failure_test = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) == DuckDBSuccess)
    return 0;
  return 1;
}
"""
    inheriting_label = """
static int f (void) {
  if (duckdb_prepare (c, "x", &stmt) != DuckDBSuccess) {
    goto early;
  }
  return 0;
early:
  return 1;
late:
  duckdb_destroy_prepare (&stmt);
  return 2;
}
"""
    cases = (
        ("a destroyed failure branch", safe_plain, []),
        ("a plain leaking return", leaking_plain, [3]),
        ("a goto reaching a destroying label", safe_goto, []),
        ("a goto reaching a label that does not destroy", leaking_goto, [3]),
        ("a destroy that is only a comment", commented, [3]),
        ("a destroy that is only a string literal", stringy, [3]),
        ("a label inheriting a later label's destroy", inheriting_label, [3]),
    )
    for name, source, expected in cases:
        actual = leaking_sites(source)
        if actual != expected:
            raise AssertionError(
                f"self-test: {name}: expected {expected}, got {actual}"
            )
    if leaking_sites(not_a_failure_test) != []:
        raise AssertionError("self-test: a success test is not a failure branch")

    split_assignment = """
static int f (void) {
  duckdb_state rc = duckdb_prepare (c, "x", &stmt);
  if (rc != DuckDBSuccess)
    return 1;
  return 0;
}
"""
    try:
        leaking_sites(split_assignment)
    except ValueError as error:
        if "assigned to a variable" not in str(error):
            raise AssertionError(f"self-test: wrong refusal: {error}")
    else:
        raise AssertionError(
            "self-test: the split-assignment form was accepted silently"
        )

    # A case that reports the same answer with stripping disabled is not
    # coverage for stripping.  Both of these have to change without it.
    original = globals()["strip_noise"]
    globals()["strip_noise"] = lambda source: source
    try:
        for name, source in (("comment", commented), ("string", stringy)):
            if leaking_sites(source) == [3]:
                raise AssertionError(
                    f"self-test: the {name} case passes without strip_noise, "
                    "so it does not exercise it"
                )
    finally:
        globals()["strip_noise"] = original

    # The validator must report, not merely compute.
    try:
        validate({"probe.c": leaking_plain})
    except AssertionError as error:
        if "line(s) 3" not in str(error):
            raise AssertionError(f"self-test: report lost the line: {error}")
    else:
        raise AssertionError("self-test: validate accepted a leaking branch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if args.self_test:
        try:
            self_test()
        except (AssertionError, ValueError) as error:
            raise SystemExit(str(error)) from error
        print("duckdb prepare-destroy gate self-test: OK")
        return
    files = {}
    for relative in SOURCES:
        path = args.root / relative
        if not path.is_file():
            raise SystemExit(f"missing required source: {relative}")
        files[relative] = path.read_text(encoding="utf-8")
    try:
        validate(files)
    except (AssertionError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print("duckdb prepare-destroy contract: OK")


if __name__ == "__main__":
    main()

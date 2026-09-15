#!/usr/bin/env python3
"""Require Meson test blocks to depend on executable targets in their args."""

from pathlib import Path
import re
import sys


EXECUTABLE_RE = re.compile(r"(?m)^\s*(\w+)\s*=\s*executable\s*\(")
TEST_RE = re.compile(r"(?m)^\s*test\s*\(")


def balanced_block(text: str, start: int) -> str:
    depth = 0
    quoted = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "'":
                quoted = False
            continue
        if char == "'":
            quoted = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:]


def check(text: str) -> list[str]:
    executable_names = {match.group(1) for match in EXECUTABLE_RE.finditer(text)}
    failures = []
    for match in TEST_RE.finditer(text):
        block = balanced_block(text, text.find("(", match.start()))
        for name in sorted(executable_names):
            if f"{name}.full_path()" in block and not re.search(
                rf"\bdepends\s*:\s*(?:\[[^]]*\]|\b{name}\b)",
                block,
                re.DOTALL,
            ):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(
                    f"line {line}: test using {name}.full_path() lacks depends"
                )
    return failures


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} TESTS_MESON", file=sys.stderr)
        return 2
    failures = check(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

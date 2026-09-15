#!/usr/bin/env python3
"""Fail when a test() runs a built target it did not declare as a dependency.

meson derives a test's build dependencies from its command and from `depends`.
An `executable()` object interpolated into `args` as `.full_path()` is only a
string, so meson sees no edge and does not build it.  `meson test` with a
`--suite` or a name filter -- the form CI uses -- then runs the test against a
path that was never linked, and the failure surfaces as a FileNotFoundError
from the harness rather than as anything about the test under test.

`find_program()` results need no edge, so only targets built from source in
this file are required to appear in `depends`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BUILD_FILE = "tests/meson.build"
TARGET_ASSIGNMENT = re.compile(
    r"^\s*(\w+)\s*=\s*(?:executable|shared_library|static_library|"
    r"both_libraries|library)\s*\(", re.M)
FULL_PATH_USE = re.compile(r"\b(\w+)\s*\.\s*full_path\s*\(\s*\)")
TEST_NAME = re.compile(r"test\s*\(\s*'([^']*)'")
TRIPLE = "'" * 3


def _mask(text: str) -> str:
  """Blank out comments and string bodies, preserving every byte offset.

  Without this a comment such as "compiled directly into the test (rather"
  reads as a `test(` call and swallows the rest of the file.  Offsets are
  preserved so reported line numbers still point at real source.
  """
  out = list(text)
  index = 0
  length = len(text)
  while index < length:
    character = text[index]
    if character == "#":
      while index < length and text[index] != "\n":
        out[index] = " "
        index += 1
    elif character == "'":
      quote = TRIPLE if text.startswith(TRIPLE, index) else "'"
      end = text.find(quote, index + len(quote))
      end = length if end < 0 else end + len(quote)
      for position in range(index, end):
        if text[position] != "\n":
          out[position] = " "
      index = end
    else:
      index += 1
  return "".join(out)


def _call_spans(masked: str, name: str) -> list[tuple[int, int]]:
  """Byte spans of every `name(...)` call, parenthesis-balanced."""
  spans: list[tuple[int, int]] = []
  index = 0
  pattern = re.compile(r"(?<![\w.])" + re.escape(name) + r"\s*\(")
  while True:
    match = pattern.search(masked, index)
    if match is None:
      return spans
    depth = 1
    position = match.end()
    while position < len(masked) and depth:
      if masked[position] == "(":
        depth += 1
      elif masked[position] == ")":
        depth -= 1
      position += 1
    if depth:
      return spans
    spans.append((match.start(), position))
    index = position


def _depends_names(block: str) -> set[str]:
  match = re.search(r"\bdepends\s*:", block)
  if match is None:
    return set()
  tail = block[match.end():]
  stop = len(tail)
  depth = 0
  for index, character in enumerate(tail):
    if character in "([":
      depth += 1
    elif character in ")]":
      if depth == 0:
        stop = index
        break
      depth -= 1
    elif character == "," and depth == 0:
      stop = index
      break
  return set(re.findall(r"\w+", tail[:stop]))


def validate(root: Path) -> list[str]:
  raw = (root / BUILD_FILE).read_text(encoding="utf-8")
  masked = _mask(raw)
  targets = set(TARGET_ASSIGNMENT.findall(masked))
  errors: list[str] = []
  for start, end in _call_spans(masked, "test"):
    block = masked[start:end]
    name = TEST_NAME.search(raw[start:end])
    label = name.group(1) if name else "offset %d" % start
    declared = _depends_names(block)
    for used in sorted(set(FULL_PATH_USE.findall(block))):
      if used in targets and used not in declared:
        line = raw.count("\n", 0, start) + 1
        errors.append(
            "%s:%d: test('%s') runs %s.full_path() but does not name %s "
            "in depends" % (BUILD_FILE, line, label, used, used))
  return errors


def self_test(root: Path) -> list[str]:
  """The guard must object to exactly the shape it exists to forbid."""
  if validate(root):
    return ["self-test requires the repository to pass the guard first"]
  path = root / BUILD_FILE
  saved = path.read_text(encoding="utf-8")
  errors: list[str] = []
  mutations = (
      ("dropped depends", "  depends : exit_status_reporting)", ")",
          "exit_status_reporting"),
      ("comment does not count as a call",
          "test('exit-status-reporting', python3,",
          "# test('exit-status-reporting', python3, (rather\n"
          "test('exit-status-reporting', python3,", None),
  )
  for label, before, after, expected in mutations:
    if saved.count(before) != 1:
      errors.append("mutation setup failed: %s" % label)
      continue
    try:
      path.write_text(saved.replace(before, after, 1), encoding="utf-8")
      reported = validate(root)
    finally:
      path.write_text(saved, encoding="utf-8")
    if expected is None:
      if reported:
        errors.append("guard misreads a comment as a call: %s: %r"
            % (label, reported))
    elif not reported:
      errors.append("mutation survived: %s" % label)
    elif not any(expected in line for line in reported):
      errors.append("mutation died on the wrong check: %s: %r"
          % (label, reported))
  return errors


def main(argv: list[str]) -> int:
  args = list(argv[1:])
  run_self_test = "--self-test" in args
  if run_self_test:
    args.remove("--self-test")
  root = Path(args[0]) if args else Path(__file__).resolve().parent.parent
  errors = self_test(root) if run_self_test else validate(root)
  for error in errors:
    print(error, file=sys.stderr)
  if errors:
    return 1
  print("meson test depends: OK")
  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv))

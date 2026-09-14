#!/usr/bin/env python3
"""Guard that every check_* in test-fact-store.c owns its failure codes.

The file reports failure by returning a distinct integer that main() hands to
the shell as the exit status.  Two functions returning the same value are
indistinguishable in a failing run, which costs exactly the thing a failure
should give you first: which check failed.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


SOURCE = "tests/test-fact-store.c"
# Definitions only: the name at column zero followed by its parameter list.
# A declaration would carry a leading "static gint" on the same line.
DEFINITION = re.compile(r"^(check_[a-z0-9_]+) \(", re.M)
RETURN_CODE = re.compile(r"\breturn\s+([1-9][0-9]*)\s*;")


def mask_noncode(text: str) -> str:
  """Blank comments and literals while preserving offsets and newlines."""
  output: list[str] = []
  index = 0
  state = "code"
  while index < len(text):
    char = text[index]
    following = text[index + 1] if index + 1 < len(text) else ""
    if state == "code":
      if char == "/" and following in ("/", "*"):
        output.extend((" ", " "))
        state = "line" if following == "/" else "block"
        index += 2
      elif char in ('"', "'"):
        output.append(" ")
        state = "string" if char == '"' else "character"
        index += 1
      else:
        output.append(char)
        index += 1
    elif state == "line":
      output.append("\n" if char == "\n" else " ")
      if char == "\n":
        state = "code"
      index += 1
    elif state == "block":
      if char == "*" and following == "/":
        output.extend((" ", " "))
        index += 2
        state = "code"
      else:
        output.append("\n" if char == "\n" else " ")
        index += 1
    else:
      output.append("\n" if char == "\n" else " ")
      if char == "\\" and index + 1 < len(text):
        output.append("\n" if text[index + 1] == "\n" else " ")
        index += 2
      else:
        if (state == "string" and char == '"') or (
            state == "character" and char == "'"):
          state = "code"
        index += 1
  return "".join(output)


def function_bodies(text: str) -> list[tuple[str, int, int]]:
  """Return balanced source spans for check_* definitions only."""
  masked = mask_noncode(text)
  bodies: list[tuple[str, int, int]] = []
  for definition in DEFINITION.finditer(masked):
    opening = masked.find("{", definition.end())
    semicolon = masked.find(";", definition.end())
    if opening < 0 or (semicolon >= 0 and semicolon < opening):
      continue
    depth = 1
    closing = opening + 1
    while closing < len(masked) and depth:
      if masked[closing] == "{":
        depth += 1
      elif masked[closing] == "}":
        depth -= 1
      closing += 1
    if depth:
      raise ValueError(f"unclosed function body for {definition.group(1)}")
    bodies.append((definition.group(1), opening + 1, closing - 1))
  return bodies


def owners(text: str) -> dict[int, str]:
  """Map each failure code to the single function allowed to return it."""
  masked = mask_noncode(text)
  functions = function_bodies(text)
  table: dict[int, str] = {}
  errors: list[str] = []
  for name, start, end in functions:
    body = masked[start:end]
    for raw in RETURN_CODE.findall(body):
      code = int(raw)
      previous = table.get(code)
      if previous is not None and previous != name:
        errors.append(f"failure code {code} is returned by both {previous} "
                      f"and {name}")
      table[code] = name
  if errors:
    raise ValueError("\n".join(sorted(set(errors))))
  return table


def validate_repository(root: Path,
    overrides: dict[str, str] | None = None) -> list[str]:
  errors: list[str] = []
  if overrides is not None and SOURCE in overrides:
    text = overrides[SOURCE]
  else:
    text = (root / SOURCE).read_text(encoding="utf-8")
  if not DEFINITION.search(text):
    return [f"{SOURCE} has no check_* definitions; the detector is broken"]
  try:
    owners(text)
  except ValueError as collision:
    errors.extend(str(collision).split("\n"))
  return errors


def self_test(root: Path) -> list[str]:
  errors: list[str] = []
  text = (root / SOURCE).read_text(encoding="utf-8")
  if validate_repository(root):
    return ["self-test requires a clean repository"]
  functions = function_bodies(text)
  if len(functions) < 2:
    return ["self-test needs at least two check_* definitions"]
  # Take a code the first function owns and make the second return it too.
  _first_name, first_start, first_end = functions[0]
  _second_name, second_start, second_end = functions[1]
  first = RETURN_CODE.search(mask_noncode(text)[first_start:first_end])
  if first is None:
    return ["self-test fixture missing: no return code in the first check"]
  stolen = first.group(1)
  second_body = text[second_start:second_end]
  replaced = RETURN_CODE.sub(f"return {stolen};", second_body, count=1)
  if replaced == second_body:
    return ["self-test fixture missing: second check returns no code"]
  mutant = text[:second_start] + replaced + text[second_end:]
  if not validate_repository(root, {SOURCE: mutant}):
    errors.append("mutation survived: a duplicated failure code")
  fixture = ("check_first (void) { return 20; return 0; }\n"
      "static int retract_by_id_fixture_init (void) { return 21; }\n"
      "check_second (void) { return 21; return 0; }\n")
  try:
    fixture_owners = owners(fixture)
  except ValueError as collision:
    errors.append(f"helper return was misattributed: {collision}")
  else:
    if fixture_owners != {20: "check_first", 21: "check_second"}:
      errors.append("helper returns or repeated return 0 were attributed")
  collision_fixture = fixture.replace("return 21; return 0; }\n",
      "return 20; return 0; }\n", 1)
  try:
    owners(collision_fixture)
  except ValueError:
    pass
  else:
    errors.append("mutation survived: a two-digit duplicated code")
  # A detector that matches nothing would pass everything.
  if not validate_repository(root, {SOURCE: "int main (void) { return 0; }\n"}):
    errors.append("mutation survived: a source with no check_* definitions")
  return errors


def main() -> int:
  if len(sys.argv) == 3 and sys.argv[1] == "--self-test":
    errors = self_test(Path(sys.argv[2]))
  elif len(sys.argv) == 2:
    errors = validate_repository(Path(sys.argv[1]))
  else:
    print(f"usage: {sys.argv[0]} [--self-test] SOURCE_ROOT", file=sys.stderr)
    return 2
  for error in errors:
    print(error, file=sys.stderr)
  if errors:
    return 1
  print("fact store failure codes: OK")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

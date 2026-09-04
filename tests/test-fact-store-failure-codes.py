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
RETURN_CODE = re.compile(r"return (\d{3,4});")


def owners(text: str) -> dict[int, str]:
  """Map each failure code to the single function allowed to return it."""
  starts = [(m.start(), m.group(1)) for m in DEFINITION.finditer(text)]
  starts.sort()
  bounds = [s for s, _ in starts] + [len(text)]
  table: dict[int, str] = {}
  errors: list[str] = []
  for index, (start, name) in enumerate(starts):
    body = text[start:bounds[index + 1]]
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
  starts = [(m.start(), m.group(1)) for m in DEFINITION.finditer(text)]
  starts.sort()
  if len(starts) < 2:
    return ["self-test needs at least two check_* definitions"]
  bounds = [s for s, _ in starts] + [len(text)]
  # Take a code the first function owns and make the second return it too.
  first = RETURN_CODE.search(text[starts[0][0]:bounds[1]])
  if first is None:
    return ["self-test fixture missing: no return code in the first check"]
  stolen = first.group(1)
  second = text[starts[1][0]:bounds[2]]
  replaced = RETURN_CODE.sub(f"return {stolen};", second, count=1)
  if replaced == second:
    return ["self-test fixture missing: second check returns no code"]
  mutant = text.replace(second, replaced, 1)
  if not validate_repository(root, {SOURCE: mutant}):
    errors.append("mutation survived: a duplicated failure code")
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

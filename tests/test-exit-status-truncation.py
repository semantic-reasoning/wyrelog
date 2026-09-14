#!/usr/bin/env python3
"""Guard that no test reports failure with a code the shell turns into zero.

The tests in this tree report failure by returning an integer from main(), and
the shell sees only its low byte.  A nonzero code that is a multiple of 256
therefore arrives as exit status 0, and meson records the run as Ok -- a
failing assertion reporting success.  Eleven files carried such a code before
this guard existed (#1066).

Scope is deliberately narrow.  Codes that merely *collide* after truncation
cost diagnosability, not correctness: the test still fails, you just cannot
tell which assertion fired.  That is #1067's problem and is not checked here,
because fixing it means renumbering hundreds of codes into a 255-slot space
that the larger files cannot fit into.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


SOURCES = "tests/test-*.c"
# Both forms a failure code reaches main() by.  A return-only pattern misses
# "rc = 2560; goto out;", which is how one of the original eleven was written
# and why two separate enumerations of this defect undercounted it.
FAILURE_CODE = re.compile(
    r"\b(?:return|(?:rc|ret|result|status|code)\s*=)\s*(\d+)\s*;")


def offenders(text: str) -> list[int]:
  """Nonzero failure codes in |text| that truncate to exit status 0."""
  found = {int(raw) for raw in FAILURE_CODE.findall(text)}
  return sorted(code for code in found if code and code % 256 == 0)


def validate_repository(root: Path,
    overrides: dict[str, str] | None = None) -> list[str]:
  errors: list[str] = []
  sources = sorted(root.glob(SOURCES))
  if not sources:
    return [f"no {SOURCES} found under {root}; the detector is broken"]
  for source in sources:
    name = source.relative_to(root).as_posix()
    if overrides is not None and name in overrides:
      text = overrides[name]
    else:
      text = source.read_text(encoding="utf-8", errors="replace")
    for code in offenders(text):
      errors.append(f"{name}: failure code {code} truncates to exit status "
                    f"{code & 0xFF}, so a failing run reports success")
  if overrides is not None:
    for name, text in overrides.items():
      if not (root / name).exists():
        for code in offenders(text):
          errors.append(f"{name}: failure code {code} truncates to exit "
                        f"status {code & 0xFF}")
  return errors


def self_test(root: Path) -> list[str]:
  """A detector is worth only what its own mutations prove."""
  errors: list[str] = []
  if validate_repository(root):
    return ["self-test requires a clean repository"]
  sources = sorted(root.glob(SOURCES))
  victim = sources[0].relative_to(root).as_posix()
  text = (root / victim).read_text(encoding="utf-8", errors="replace")
  # Both forms, because the return-only reading is the one that has already
  # missed a real site in this tree.
  for mutation in ("  return 512;\n", "  rc = 512;\n"):
    if not validate_repository(root, {victim: text + mutation}):
      errors.append(f"mutation survived: {mutation.strip()}")
  # A code that truncates to a nonzero status must NOT be reported, or the
  # guard would demand renumbering that belongs to #1067.
  if validate_repository(root, {victim: text + "  return 513;\n"}):
    errors.append("false positive: 513 does not truncate to zero")
  # A detector that matches nothing would pass everything.
  if not validate_repository(root, {"tests/test-detector-probe.c":
      "int main (void) { return 256; }\n"}):
    errors.append("mutation survived: a synthetic source returning 256")
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
  print("exit status truncation: OK")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

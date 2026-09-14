#!/usr/bin/env python3
"""Guard that every variant main can name its failing check.

tests/test-daemon-http-decide.c is compiled four times behind
WYL_TEST_VARIANT_* macros, and each build has its own main. The exit status
those mains return is truncated to 8 bits, while the file carries hundreds of
codes above 255 -- check_tenant_gate_codes_contract's 1900 arrives as 108 and
check_read_only_method_contract's 550 as 38, both reachable from the refresh
variant. So the status alone cannot identify the check that failed, and the
file says so in its own words: CI must use the structured WYRELOG_TEST_DIAG
line as the authoritative discriminator.

That convention was only implemented for one variant, and only in its cleanup
block, so a check returning early bypassed it (#1062). Each main now wraps its
body and prints the untruncated value for every return. This guard exists so a
fifth variant, or a rewrite of an existing main, cannot quietly drop that.

It deliberately checks the mechanism, not the codes. Requiring every code to be
under 256 would be a backlog nobody works through; requiring every main to
report the real one is a property that holds at any size.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


SOURCE = "tests/test-daemon-http-decide.c"
MAIN = re.compile(r"^int\nmain \([^)]*\)\n\{(.*?)^\}", re.M | re.S)
DIAG = re.compile(r'g_printerr \("WYRELOG_TEST_DIAG [a-z_]+ result=%d')


def validate_repository(root: Path,
    overrides: dict[str, str] | None = None) -> list[str]:
  errors: list[str] = []
  if overrides is not None and SOURCE in overrides:
    text = overrides[SOURCE]
  else:
    text = (root / SOURCE).read_text(encoding="utf-8", errors="replace")

  bodies = MAIN.findall(text)
  if not bodies:
    return [f"{SOURCE}: no main found; the detector is broken"]
  # One per variant: refresh, default, service, audit.
  if len(bodies) != 4:
    errors.append(f"{SOURCE}: expected 4 variant mains, found {len(bodies)}; "
                  f"a new variant must report its failing check too")
  for index, body in enumerate(bodies):
    if not DIAG.search(body):
      errors.append(f"{SOURCE}: variant main #{index} prints no "
                    f"WYRELOG_TEST_DIAG result line, so a failure there "
                    f"reports only a truncated exit status")
  return errors


def self_test(root: Path) -> list[str]:
  errors: list[str] = []
  text = (root / SOURCE).read_text(encoding="utf-8", errors="replace")
  if validate_repository(root):
    return ["self-test requires a clean repository"]

  # A main that reports nothing must be caught.
  stripped = DIAG.sub('g_printerr ("nothing useful', text, count=1)
  if not validate_repository(root, {SOURCE: stripped}):
    errors.append("mutation survived: a variant main with no diag line")

  # A detector that matches nothing would pass everything.
  if not validate_repository(root, {SOURCE: "/* no mains here */\n"}):
    errors.append("mutation survived: a source with no main at all")
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
  print("variant diag coverage: OK")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

#!/usr/bin/env python3
"""Fail when a check function in the decide contract file is never called.

tests/test-daemon-http-decide.c is one source compiled four times behind
WYL_TEST_VARIANT_* macros, and its checks are plain static functions called
from whichever variant main owns them.  Nothing links a check to a caller, so
a check can stop running without anything failing: the function still
compiles, the suite still passes, and the file still reads as though the
contract is covered.

That is not hypothetical.  check_raw_login_contract lost its only call in
5e9c2c85 ("test: trim refresh variant login setup", 2026-07-16), which
replaced the call with inline setup.  Seven /auth/refresh and login contract
checks were reachable only through it and did not run for two months --
including the single-flight body assertion that a later issue cited as
existing coverage (#1113).

This checks reachability, not correctness.  A check named here and called
nowhere is either a regression to restore or dead weight to delete; both are
decisions someone has to make, and neither should be made by silence.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


SOURCE = "tests/test-daemon-http-decide.c"
# One known gap, tracked, not tolerated.  check_service_auth_invalidator_
# contract has never been called since bd2efe1a added it; wiring it in makes
# check_compound_tenant_real_resolver_and_activation fail at 2151, because it
# leaves fixture state on the shared server.  Untangling that is #1115, and
# this entry exists so the guard can be enforced now instead of waiting for
# it.  An entry here is a debt with an issue number, so removing the issue
# means removing the entry.
KNOWN_UNREACHED = {
    "check_service_auth_invalidator_contract": 1115,
}
# A definition is the identifier at column 0 followed by its parameter list,
# which is how every check in this file is written.
DEFINITION = re.compile(r"^(check_[A-Za-z0-9_]+) \(", re.M)


def validate_repository(root: Path,
    overrides: dict[str, str] | None = None) -> list[str]:
  if overrides is not None and SOURCE in overrides:
    text = overrides[SOURCE]
  else:
    text = (root / SOURCE).read_text(encoding="utf-8", errors="replace")

  defined = DEFINITION.findall(text)
  if not defined:
    return [f"{SOURCE}: no check definitions found; the detector is broken"]
  errors: list[str] = []
  for name in sorted(set(defined)):
    # Its own definition is one occurrence; a called check has at least one
    # more.  Comments mentioning a name count as references, which is the
    # forgiving direction: this guard is for silence, not for style.
    uses = len(re.findall(r"\b" + re.escape(name) + r"\b", text))
    if uses >= 2:
      if name in KNOWN_UNREACHED:
        errors.append(f"{SOURCE}: {name} is referenced now, so drop its "
                      f"KNOWN_UNREACHED entry and close #"
                      f"{KNOWN_UNREACHED[name]}")
      continue
    if name in KNOWN_UNREACHED:
      continue
    errors.append(f"{SOURCE}: {name} is defined and never referenced, so "
                  f"whatever it checks does not run")
  return errors


def self_test(root: Path) -> list[str]:
  errors: list[str] = []
  text = (root / SOURCE).read_text(encoding="utf-8", errors="replace")
  if validate_repository(root):
    return ["self-test requires a clean repository"]

  # Drop one call and keep its definition, which is exactly the shape
  # 5e9c2c85 left behind.
  defined = sorted(set(DEFINITION.findall(text)))
  mutated_any = False
  for name in defined:
    uses = [m.start() for m in re.finditer(r"\b" + re.escape(name) + r"\b",
            text)]
    if len(uses) != 2:
      continue
    # The later occurrence is the call; blank it out.
    start = uses[-1]
    mutated = text[:start] + "check_self_test_placeholder" + \
        text[start + len(name):]
    if not validate_repository(root, {SOURCE: mutated}):
      errors.append(f"mutation survived: {name} defined with no caller")
    mutated_any = True
    break
  if not mutated_any:
    errors.append("self-test found no check with exactly one call to remove, "
                  "so its mutation tests nothing")

  if not validate_repository(root, {SOURCE: "/* no checks here */\n"}):
    errors.append("mutation survived: a source with no check definitions")
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
  print("decide check reachability: OK")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

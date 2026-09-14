#!/usr/bin/env python3
"""Say which feature-gated test suites this build is not running.

A green `meson test` is only as broad as the build it ran against, and this
tree gates whole suites behind feature options that default to disabled. The
fact store is the sharp case: `enable_fact_store` defaults to `disabled`
(meson.options), tests/meson.build gates 13 registrations on it, so a plain
`meson setup builddir` produces a build where `wyrelog:fact-store` is not
registered at all. Following CLAUDE.md's validation step literally then
reports Ok over a subsystem that was never compiled (#1068).

This makes the omission visible instead of silent. By default it only reports.
Pass --strict -- which the documented validation command does -- to fail when
a suite the documented setup is supposed to cover is inactive, so the
prescribed setup and the prescribed test command cannot disagree quietly.

It reports; it does not decide. Changing the option defaults is a packaging
question (enabling the fact store pulls a prebuilt DuckDB download at setup,
which breaks offline builds) and #1068 keeps it out of scope.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys


# Options whose absence removes whole suites rather than individual cases.
# enable_tpm and the windows hooks are deliberately absent: they gate
# platform-specific behaviour, not a suite a Linux contributor should expect.
GATED = {
    "enable_fact_store": "wyrelog:fact-store and 12 sibling registrations",
    "enable_audit": "18 audit-gated registrations",
    "enable_secure_duckdb_bridge": "6 secure-bridge registrations",
    "enable_break_glass": "2 break-glass registrations",
    "enable_fault_injection": "the fault-injection registration",
}

# What --strict insists on: everything the documented setup command can turn on
# without changing how DuckDB is obtained. enable_secure_duckdb_bridge is
# deliberately absent -- it requires duckdb_source=subproject, which builds
# DuckDB from pinned source, so demanding it in a routine pre-commit step would
# impose a long compile on every contributor. It is still reported, because not
# running those six registrations is worth knowing even when it is the right
# trade.
STRICT_REQUIRED = frozenset({
    "enable_fact_store",
    "enable_audit",
    "enable_break_glass",
    "enable_fault_injection",
})

ROW = re.compile(r"^\s*(enable_[a-z_]+)\s+(\S+)")


def option_values(builddir: Path) -> dict[str, str]:
  """Read the build's own configuration rather than guessing from the path."""
  try:
    out = subprocess.run(
        ["meson", "configure", str(builddir)],
        capture_output=True, text=True, check=False).stdout
  except FileNotFoundError:
    return {}
  values: dict[str, str] = {}
  for line in out.splitlines():
    match = ROW.match(line)
    if match and match.group(1) in GATED:
      values.setdefault(match.group(1), match.group(2))
  return values


def main() -> int:
  args = [a for a in sys.argv[1:] if a != "--strict"]
  strict = "--strict" in sys.argv[1:]
  if len(args) != 1:
    print(f"usage: {sys.argv[0]} [--strict] BUILDDIR", file=sys.stderr)
    return 2

  builddir = Path(args[0])
  values = option_values(builddir)
  if not values:
    print(f"error: could not read {builddir}'s configuration; "
          f"a report that cannot see the build must not pass silently",
          file=sys.stderr)
    return 1

  inactive = [(name, why) for name, why in GATED.items()
              if values.get(name, "disabled") == "disabled"]
  if not inactive:
    print("all feature-gated suites are active in this build")
    return 0

  stream = sys.stderr if strict else sys.stdout
  print(f"{len(inactive)} feature-gated suite group(s) are NOT built here, "
        f"so a green run says nothing about them:", file=stream)
  for name, why in sorted(inactive):
    print(f"  {name}=disabled -> {why}", file=stream)
  missing = [name for name, _ in inactive if name in STRICT_REQUIRED]
  if strict and missing:
    print(f"--strict requires {', '.join(sorted(missing))}; re-run meson setup "
          f"with them enabled, or drop --strict if a narrower build is what "
          f"you meant", file=stream)
    return 1
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

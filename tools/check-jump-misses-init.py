#!/usr/bin/env python3
"""Fail when a goto skips a declaration whose cleanup handler is still armed.

C lets a goto jump past a declaration while the declared object stays in scope
at the label. With a plain pointer that is merely untidy. With
g_auto/g_autoptr/g_autofree/__attribute__((cleanup)) it is a defect: GCC emits
the cleanup call in the epilogue unconditionally, so the skipped initialiser
leaves an indeterminate slot being freed.

It is silent. -Wjump-misses-init is in neither -Wall nor -Wextra, and this
project compiles with -Wall -Wextra and no -Werror, so nothing in the build,
the suite, or the frozen-manifest guards catches it. The instance that
prompted this (#1054) was found by a reviewer reading a diff, and confirmed
twice: once by disassembling the shipped binary and seeing the cleanup call on
every path, once at -O2 by observing the slot hold a value sunk in from the
not-taken branch where -O0 left NULL. The failure is an invalid free whose
reachability depends on the optimiser.

Why this and not -Wjump-misses-init repo-wide: the warning fires ~311 times
across the tree and every one of them is harmless, because the skipped
declarations carry no cleanup handler. Enabling it plainly would bury the next
real instance under benign noise, which makes the reviewer's job harder rather
than easier. This guard applies the cleanup-attribute filter, and that
predicate passes at zero today -- so it is enforced as an error immediately,
with no remediation backlog and no ledger of exceptions.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import json
import re
import shlex
import subprocess
import sys


# GCC writes these notes with Unicode quotes, not ASCII. Matching '...' finds
# nothing and the guard would pass over everything.
NOTE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+):\d+: note: .\S+. declared here")
# A declaration is dangerous only when its own line arms a cleanup handler.
CLEANUP = re.compile(r"\bg_auto(?:ptr|free)?\s*[\s(]|__attribute__\s*\(\s*\(\s*cleanup\b|\bcleanup\s*\(")


class CompileFailure(Exception):
  def __init__(self, source: str, stderr: str):
    super().__init__(source)
    self.source = source
    self.stderr = stderr


def entries_for(build_root: Path, wanted: set[str] | None):
  db = build_root / "compile_commands.json"
  if not db.is_file():
    raise SystemExit(f"error: {db} not found; configure a build first")
  for entry in json.loads(db.read_text(encoding="utf-8")):
    source = entry.get("file", "")
    if not source.endswith(".c"):
      continue
    if wanted and Path(source).name not in wanted:
      continue
    # Sound prune, not a sample: -Wjump-misses-init cannot fire in a
    # translation unit with no goto, and the defect needs a cleanup attribute
    # to matter. Skipping those keeps the guard fast enough to be a test
    # without narrowing what it would catch.
    try:
      text = Path(source).read_text(encoding="utf-8", errors="replace")
    except OSError:
      yield entry
      continue
    if "goto " not in text or not CLEANUP.search(text):
      continue
    yield entry


def scan(entry: dict) -> list[tuple[str, int, str]]:
  """Re-run one compile-command entry with the jump diagnostic enabled."""
  # shlex, not split(): quoted -D values are common here and break naive
  # splitting, which silently drops flags and changes what is compiled.
  argv = shlex.split(entry["command"]) if "command" in entry else list(entry["arguments"])
  keep: list[str] = [argv[0]]
  skip_next = False
  for arg in argv[1:]:
    if skip_next:
      skip_next = False
      continue
    if arg in ("-o", "-MF", "-MQ", "-MT"):
      skip_next = True
      continue
    if arg in ("-c",) or arg.startswith("-MD") or arg.startswith("-MMD"):
      continue
    keep.append(arg)
  keep += ["-fsyntax-only", "-Wjump-misses-init", "-fno-diagnostics-color"]
  proc = subprocess.run(keep, cwd=entry.get("directory", "."),
                        capture_output=True, text=True, check=False)
  # A translation unit that does not compile emits no notes, and reporting OK
  # for it would be the same silent pass this guard exists to remove. Surface
  # it instead of counting zero.
  if re.search(r"^[^:]+:\d+:\d+: error:", proc.stderr, re.M):
    raise CompileFailure(entry.get("file", "?"), proc.stderr)
  found: list[tuple[str, int, str]] = []
  for line in proc.stderr.splitlines():
    match = NOTE.match(line)
    if not match:
      continue
    path = Path(match.group("path"))
    if not path.is_absolute():
      path = Path(entry.get("directory", ".")) / path
    try:
      text = path.read_text(encoding="utf-8", errors="replace").splitlines()
      decl = text[int(match.group("line")) - 1]
    except (OSError, IndexError):
      continue
    if CLEANUP.search(decl):
      found.append((str(path), int(match.group("line")), decl.strip()))
  return found


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--build-root", required=True)
  parser.add_argument("--only", action="append", default=[],
                      help="restrict to these basenames (default: every .c)")
  ns = parser.parse_args()

  wanted = set(ns.only) or None
  dangerous: dict[tuple[str, int], str] = {}
  scanned = 0
  for entry in entries_for(Path(ns.build_root), wanted):
    scanned += 1
    try:
      sites = scan(entry)
    except CompileFailure as failure:
      print(f"error: {failure.source} does not compile under this guard's "
            f"flags, so it was not checked", file=sys.stderr)
      for line in failure.stderr.splitlines()[:6]:
        print(f"  {line}", file=sys.stderr)
      return 1
    for path, line, decl in sites:
      dangerous[(path, line)] = decl

  if dangerous:
    for (path, line), decl in sorted(dangerous.items()):
      print(f"{path}:{line}: a goto skips this declaration while its cleanup "
            f"handler stays armed: {decl}", file=sys.stderr)
    print(f"{len(dangerous)} dangerous site(s); the cleanup would run over an "
          f"indeterminate slot", file=sys.stderr)
    return 1

  # Say what was covered. A site count without its variant count is not
  # comparable between runs: this tree compiles some files up to ten ways, and
  # measuring one entry undercounts.
  print(f"jump-misses-init: OK ({scanned} compile-command entries scanned, "
        f"0 dangerous sites)")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

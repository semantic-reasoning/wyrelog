#!/usr/bin/env python3
"""Guard the native Windows CI matrix timeout and cleanup contract."""

from __future__ import annotations

from pathlib import Path
import re
import sys


WORKFLOWS = ("ci-pr.yml", "ci-main.yml")
REQUIRED_TIMEOUT = "    timeout-minutes: 90\n"
REQUIRED_STEPS = (
    "      - name: Bootstrap vendored vcpkg",
    "      - name: Build and test (clang-cl)",
    "      - name: Verify Windows CI timeout boundary",
    "      - name: Show sccache statistics",
    "        if: ${{ runner.environment == 'github-hosted' && (!cancelled()) }}",
    "      - name: Upload meson logs on failure",
    "        if: ${{ runner.environment == 'github-hosted' && (always()) }}",
    "          path: builddir/meson-logs/",
    "secure-duckdb-recording-filesystem",
    "--test-args=\"-p /secure-duckdb-bridge/recording-filesystem/"
    "live-wal-read-only-recovery\"",
    "fact-artifact-namespace-windows",
    "fact-provisioning-construct",
    "            meson test -C builddir secure-duckdb-bridge",
    "            meson test -C builddir --print-errorlogs --suite wyrelog"
    " --logbase testlog-fullsuite",
    "python3 tests/test-windows-ci-timeout-boundary.py --self-test",
)
MATRIX_ENTRIES = (
    "fact_store: disabled\n            secure_bridge: disabled\n"
    "            duckdb_source: prebuilt",
    "fact_store: enabled\n            secure_bridge: disabled\n"
    "            duckdb_source: prebuilt",
    "fact_store: enabled\n            secure_bridge: enabled\n"
    "            duckdb_source: subproject",
)


# The two aggregates the Windows rows time out on.  Each must stay serialized
# on Windows and keep an explicit deadline at or below its recorded ceiling.
# Raising a ceiling means editing this table, which is the point: a deadline
# may only move when someone states the measurement that moved it.
SERIALIZED_AGGREGATES = (
    ("policy-graph-authority", 90),
    ("fact-store", 60),
)
WINDOWS_SERIAL = "is_parallel : host_machine.system() != 'windows'"
# A checker nothing runs guards nothing.  Unregistering these two lines would
# retire every assertion below without failing anything, so the registrations
# are themselves part of the contract.
REQUIRED_MESON_TESTS = (
    "windows-ci-timeout-boundary",
    "windows-ci-timeout-boundary-self-test",
    "policy-graph-authority",
    "fact-store",
)
# meson test spells this two ways; banning only the long one bans nothing.
# meson's parser sets allow_abbrev, so --timeout-mul and --timeout-m reach
# the same option as the full spelling.  Banning the exact word bans nothing.
TIMEOUT_MULTIPLIER = re.compile(r"(?:^|\s)(?:-t\s*\d|--timeout-m[a-z-]*)")
# Steps that may fail without failing the job: caches and telemetry only.
# Anything else tolerating failure can retire a gate silently, including the
# step that runs this checker.
FAILURE_TOLERANT_STEPS = (
    "Set up sccache",
    "Restore vcpkg installed tree",
    "Save vcpkg binary packages",
    "Save vcpkg installed tree",
    "Save meson packagecache",
)


def read(root: Path, rel: str, overrides: dict[str, str] | None) -> str:
  if overrides is not None and rel in overrides:
    return overrides[rel]
  return (root / rel).read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
  """Drop Meson/YAML comments so a commented-out line cannot satisfy a check.

  A substring test reads "# is_parallel : ..." as the kwarg being present
  while Meson sees no kwarg at all -- parallel on Windows, which is the
  regression this file exists to reject."""
  out = []
  for line in text.split("\n"):
    quoted = False
    escaped = False
    for index, char in enumerate(line):
      if escaped:
        escaped = False
      elif char == "\\":
        escaped = True
      elif char == "'":
        quoted = not quoted
      elif char == "#" and not quoted:
        line = line[:index]
        break
    out.append(line)
  return "\n".join(out)


def job_steps(job: str) -> list[str]:
  """Every step in the job, keyed on the sequence dash, not on `name:`.

  A step may lead with `uses:` and carry no name at all.  Enumerating on
  `- name:` makes such a step invisible, and its own 8-space
  continue-on-error sits below the job-level check."""
  bounds = [m.start() for m in re.finditer(r"\n      - ", job)]
  return [job[a:b] for a, b in zip(bounds, bounds[1:] + [len(job)])]


def step_title(step: str) -> str:
  """The step's name wherever it appears, or "" when it has none."""
  found = re.search(r"\n?\s*-?\s*name:\s*(.+)", step)
  return found.group(1).strip() if found is not None else ""


def windows_job(workflow: str) -> str:
  start = workflow.index("  build-windows:\n")
  rest = workflow[start + len("  build-windows:\n"):]
  following = re.search(r"\n  [A-Za-z0-9_-]+:\n", rest)
  end = (start + len("  build-windows:\n") + following.start()
         if following is not None else len(workflow))
  return workflow[start:end]


def validate_repository(root: Path,
    overrides: dict[str, str] | None = None) -> list[str]:
  errors: list[str] = []
  for name in WORKFLOWS:
    rel = f".github/workflows/{name}"
    job = strip_comments(windows_job(read(root, rel, overrides)))
    if job.count(REQUIRED_TIMEOUT) != 1:
      errors.append(f"{name} build-windows must have one 90-minute timeout")
    for token in REQUIRED_STEPS:
      if token not in job:
        errors.append(
            f"{name} Windows cleanup/build contract drifted: {token}")
    if not ("Cache vcpkg binary packages" in job
            or "Restore vcpkg installed tree" in job):
      errors.append(
          f"{name} Windows dependency cache/provisioning drifted")
    if "fail-fast: false" not in job:
      errors.append(f"{name} Windows matrix must remain independent")
    for entry in MATRIX_ENTRIES:
      if entry not in job:
        errors.append(f"{name} Windows matrix variant was removed")
    if TIMEOUT_MULTIPLIER.search(job) is not None:
      errors.append(f"{name} Windows job must not multiply a deadline")
    if re.search(r"\n    continue-on-error\s*:", job) is not None:
      errors.append(
          f"{name} build-windows must not tolerate its own failure")
    for step in job_steps(job):
      if not re.search(r"\n        continue-on-error\s*:", step):
        continue
      title = step_title(step)
      if title not in FAILURE_TOLERANT_STEPS:
        errors.append(
            f"{name} Windows step must not tolerate failure: "
            f"{title or '(unnamed)'}")
    # Titles are not unique, so an allowlisted name could be reused by a
    # second step that does something else entirely.
    for allowed in FAILURE_TOLERANT_STEPS:
      if sum(1 for s in job_steps(job) if step_title(s) == allowed) > 1:
        errors.append(
            f"{name} Windows job repeats a failure-tolerant step: {allowed}")

  meson = strip_comments(read(root, "tests/meson.build", overrides))
  for test_name in REQUIRED_MESON_TESTS:
    if f"test('{test_name}'" not in meson:
      errors.append(f"Meson test is not registered: {test_name}")
  for test_name, ceiling in SERIALIZED_AGGREGATES:
    # Match to the closing paren at the registration's own indent.  A
    # non-greedy [^)] stops inside host_machine.system() and silently cuts
    # the entry short before is_parallel.
    match = re.search(
        r"\n([ \t]*)test\('" + re.escape(test_name) + r"',.*?\n\1\)",
        meson, re.S)
    if match is None:
      errors.append(f"tests/meson.build lost the {test_name} registration")
      continue
    entry = match.group(0)
    if WINDOWS_SERIAL not in entry:
      errors.append(
          f"{test_name} must stay serialized on Windows: {WINDOWS_SERIAL}")
    deadline = re.search(r"timeout\s*:\s*(\d+)", entry)
    if deadline is None:
      errors.append(f"{test_name} must carry an explicit timeout")
    elif int(deadline.group(1)) > ceiling:
      errors.append(
          f"{test_name} deadline {deadline.group(1)}s exceeds the recorded "
          f"ceiling of {ceiling}s without evidence")
  return errors


def mutate_in_windows_job(text: str, old: str, new: str) -> str | None:
  """Rewrite one occurrence of old inside the build-windows job only.

  A mutation applied to the first match anywhere in the file can land in an
  unrelated job, where the checker is not supposed to look.  Such a mutation
  survives for the right reason and would read as a hole in the checker."""
  job = windows_job(text)
  if old not in job:
    return None
  return text.replace(job, job.replace(old, new, 1), 1)


def self_test(root: Path) -> list[str]:
  errors: list[str] = []
  paths = [f".github/workflows/{name}" for name in WORKFLOWS]
  texts = {rel: (root / rel).read_text(encoding="utf-8") for rel in paths}
  if validate_repository(root):
    return ["self-test requires a clean repository"]
  mutations = (
      ("job timeout removed", ".github/workflows/ci-pr.yml",
       "    timeout-minutes: 90\n", "    timeout-minutes: 360\n"),
      ("full suite step removed", ".github/workflows/ci-main.yml",
       "            meson test -C builddir --print-errorlogs --suite wyrelog",
       "            meson test -C builddir --print-errorlogs --suite none"),
      ("meson log upload removed", ".github/workflows/ci-pr.yml",
       "          path: builddir/meson-logs/",
       "          path: builddir/other-logs/"),
      ("matrix independence removed", ".github/workflows/ci-main.yml",
       "fail-fast: false", "fail-fast: true"),
      ("matrix variant removed", ".github/workflows/ci-pr.yml",
       "fact_store: enabled\n            secure_bridge: enabled\n"
       "            duckdb_source: subproject",
       "fact_store: enabled\n            secure_bridge: enabled\n"
       "            duckdb_source: prebuilt"),
      ("secure bridge tests removed", ".github/workflows/ci-main.yml",
       "            meson test -C builddir secure-duckdb-bridge",
       "            meson test -C builddir other-bridge"),
      ("full suite log base removed", ".github/workflows/ci-pr.yml",
       " --logbase testlog-fullsuite", ""),
  )
  # Fixtures are derived from the registration actually matched, so a kwarg
  # reordering or a reflow does not turn a real check into "fixture missing".
  meson_text = (root / "tests/meson.build").read_text(encoding="utf-8")
  meson_mutations = []
  for test_name, _ in SERIALIZED_AGGREGATES:
    match = re.search(
        r"\n([ \t]*)test\('" + re.escape(test_name) + r"',.*?\n\1\)",
        strip_comments(meson_text), re.S)
    if match is None:
      errors.append(f"self-test fixture missing: {test_name} registration")
      continue
    entry = match.group(0)
    indent = match.group(1)
    meson_mutations += [
        (f"{test_name} unserialized",
         entry, entry.replace(WINDOWS_SERIAL, "is_parallel : true")),
        (f"{test_name} serialization inverted", entry,
         entry.replace("!= 'windows'", "== 'windows'")),
        (f"{test_name} serialization commented out", entry,
         entry.replace(indent + "  " + WINDOWS_SERIAL,
             indent + "  # " + WINDOWS_SERIAL)),
        (f"{test_name} deadline raised without evidence", entry,
         re.sub(r"timeout : \d+", "timeout : 4000", entry)),
        (f"{test_name} deadline deleted", entry,
         re.sub(r"\n[ \t]*timeout : \d+,", "", entry)),
        (f"{test_name} registration unregistered", entry,
         entry.replace(f"test('{test_name}'", f"test('retired-{test_name}'")),
    ]
  meson_mutations.append(
      ("boundary self-test unregistered",
       "test('windows-ci-timeout-boundary-self-test'",
       "test('retired-boundary-self-test'"))
  meson_mutations.append(
      ("boundary checker unregistered",
       "test('windows-ci-timeout-boundary', python3",
       "test('retired-boundary', python3"))
  for label, old, new in meson_mutations:
    if old not in meson_text or old == new:
      errors.append(f"self-test fixture missing: {label}")
      continue
    mutant = dict(texts)
    mutant["tests/meson.build"] = meson_text.replace(old, new, 1)
    if not validate_repository(root, mutant):
      errors.append(f"mutation survived: {label}")

  # The deadline-masking bans had no coverage at all, which is the state this
  # file's own commit message calls indistinguishable from a broken gate.
  # Each payload is appended rather than inserted.  An insertion breaks the
  # pinned command token and dies on THAT assertion instead, which scores as
  # coverage while the ban it names stays unexercised.
  suite_cmd = ("            meson test -C builddir --print-errorlogs"
               " --suite wyrelog --logbase testlog-fullsuite")
  verify = "      - name: Verify Windows CI timeout boundary\n"
  self_test_call = ("          python3 tests/test-windows-ci-timeout-boundary"
                    ".py --self-test \"$GITHUB_WORKSPACE\"")
  job_mutations = (
      ("timeout multiplier, long form",
       suite_cmd, suite_cmd + " --timeout-multiplier 3"),
      ("timeout multiplier, short form",
       suite_cmd, suite_cmd + " -t 3"),
      ("timeout multiplier, short form unspaced",
       suite_cmd, suite_cmd + " -t3"),
      ("timeout multiplier on the hardening step",
       "            meson test -C builddir secure-duckdb-recording-filesystem",
       "            meson test -C builddir -t 3 "
       "secure-duckdb-recording-filesystem"),
      ("job tolerates its own failure",
       "    timeout-minutes: 90\n",
       "    timeout-minutes: 90\n    continue-on-error: true\n"),
      ("job tolerates failure, spaced colon",
       "    timeout-minutes: 90\n",
       "    timeout-minutes: 90\n    continue-on-error : true\n"),
      ("suite step tolerates failure",
       "      - name: Build and test (clang-cl)\n",
       "      - name: Build and test (clang-cl)\n"
       "        continue-on-error: true\n"),
      ("the checker's own step tolerates failure",
       verify, verify + "        continue-on-error: true\n"),
      ("self-test invocation commented out",
       self_test_call, "          # " + self_test_call.strip()),
      ("timeout multiplier, abbreviated",
       suite_cmd, suite_cmd + " --timeout-mul 3"),
      ("timeout multiplier, minimally abbreviated",
       suite_cmd, suite_cmd + " --timeout-m 3"),
      ("nameless step tolerates failure",
       verify,
       "      - uses: actions/checkout@v5\n"
       "        continue-on-error: true\n" + verify),
      ("an allowlisted title is reused",
       verify,
       "      - name: Set up sccache\n"
       "        continue-on-error: true\n"
       "        run: meson test -C builddir --suite wyrelog\n" + verify),
  )
  for label, old, new in job_mutations:
    mutated = mutate_in_windows_job(texts[".github/workflows/ci-pr.yml"],
        old, new)
    if mutated is None:
      errors.append(f"self-test fixture missing: {label}")
      continue
    mutant = dict(texts)
    mutant[".github/workflows/ci-pr.yml"] = mutated
    if not validate_repository(root, mutant):
      errors.append(f"mutation survived: {label}")
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
  print("Windows CI timeout boundary: OK")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

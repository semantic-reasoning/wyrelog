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
    "            meson test -C builddir --print-errorlogs --suite wyrelog",
)
MATRIX_ENTRIES = (
    "fact_store: disabled\n            secure_bridge: disabled\n"
    "            duckdb_source: prebuilt",
    "fact_store: enabled\n            secure_bridge: disabled\n"
    "            duckdb_source: prebuilt",
    "fact_store: enabled\n            secure_bridge: enabled\n"
    "            duckdb_source: subproject",
)


def read(root: Path, rel: str, overrides: dict[str, str] | None) -> str:
  if overrides is not None and rel in overrides:
    return overrides[rel]
  return (root / rel).read_text(encoding="utf-8")


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
    job = windows_job(read(root, rel, overrides))
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
  )
  for label, rel, old, new in mutations:
    mutated = mutate_in_windows_job(texts[rel], old, new)
    if mutated is None:
      errors.append(f"self-test fixture missing: {label}")
      continue
    mutant = dict(texts)
    mutant[rel] = mutated
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

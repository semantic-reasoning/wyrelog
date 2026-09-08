#!/usr/bin/env python3
"""Compare the frozen checker corpus with the decomposed checker externally."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from fact_store_connection_boundary.contract import load, validate
from fact_store_connection_boundary.mutations import MutationCase, self_test


def fingerprint(baseline: dict[str, str], mutation: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for path in sorted(baseline.keys() | mutation.keys()):
        if baseline.get(path) == mutation.get(path):
            continue
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update((mutation.get(path) or "<deleted>").encode("utf-8"))
    return digest.hexdigest()


def run_frozen_checker(pre: Path, root: Path) -> tuple[list[str], list[tuple[str, str]]]:
    source = pre.read_text(encoding="utf-8")
    marker = "    critical_mutation_ids = {id(mutation)"
    if marker not in source:
        raise AssertionError("frozen checker mutation marker is missing")
    probe = (
        "    print('BOUNDARY_MANIFEST ' + json.dumps(["
        "hashlib.sha256((''.join(path + '\\0' + (mutation.get(path) or '<deleted>') "
        "for path in sorted(files.keys() | mutation.keys()) if files.get(path) != mutation.get(path))).encode('utf-8')).hexdigest() "
        "for mutation in mutations]))\n"
        "    print('BOUNDARY_CRITICAL ' + json.dumps([(label, expected) for label, expected, _mutation in critical_mutations]))\n"
    )
    instrumented = source.replace(
        "import functools\n", "import functools\nimport hashlib\nimport json\n", 1
    ).replace(marker, probe + marker, 1)
    with tempfile.TemporaryDirectory(prefix="fact-boundary-equivalence-") as directory:
        script = Path(directory) / pre.name
        script.write_text(instrumented, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(script), "--self-test", str(root)],
            text=True, capture_output=True, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(
            "frozen checker failed:\n" + (result.stdout + result.stderr)
        )
    manifest = next(
        (json.loads(line.removeprefix("BOUNDARY_MANIFEST "))
         for line in result.stdout.splitlines()
         if line.startswith("BOUNDARY_MANIFEST ")),
        None,
    )
    critical = next(
        (json.loads(line.removeprefix("BOUNDARY_CRITICAL "))
         for line in result.stdout.splitlines()
         if line.startswith("BOUNDARY_CRITICAL ")),
        None,
    )
    if manifest is None or critical is None:
        raise AssertionError("frozen checker did not emit its corpus manifest")
    return manifest, critical


def main() -> int:
    args = sys.argv[1:]
    if len(args) != 4 or args[0] != "--pre" or args[2] != "--root":
        raise SystemExit(
            "usage: check-fact-store-connection-boundary-equivalence.py "
            "--pre FROZEN_CHECKER --root ROOT"
        )
    pre, root = Path(args[1]), Path(args[3]).resolve()
    baseline = load(root)
    validate(baseline)
    old_manifest, old_critical_raw = run_frozen_checker(pre, root)
    old_critical = [tuple(item) for item in old_critical_raw]
    cases = self_test(baseline)
    if not all(isinstance(case, MutationCase) for case in cases):
        raise AssertionError("decomposed checker returned invalid mutation cases")
    new_manifest = [case.fingerprint for case in cases]
    new_critical = [
        (case.label, case.expected_error)
        for case in cases if case.critical
    ]
    if old_manifest != new_manifest:
        raise AssertionError("mutation fingerprints differ between checkers")
    if old_critical != new_critical:
        raise AssertionError("critical mutation mappings differ between checkers")
    if len({case.mutation_id for case in cases}) != len(cases):
        raise AssertionError("decomposed mutation IDs are not unique")
    print("equivalence: pristine=PASS")
    print(f"equivalence: mutation-count={len(cases)}")
    print("equivalence: unique-ids=PASS")
    print("equivalence: fingerprints=PASS")
    print(f"equivalence: rejected-pre={len(old_manifest)} rejected-post={len(cases)}")
    print("equivalence: critical-mappings=PASS")
    print("equivalence: status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

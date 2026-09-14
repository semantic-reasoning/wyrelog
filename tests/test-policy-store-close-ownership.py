#!/usr/bin/env python3
"""Keep raw policy-store SQLite borrowers confined to inventoried tests."""

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = Path(__file__).with_name("policy-store-db-borrowers.json")
GET_DB = re.compile(r"\bwyl_policy_store_get_db\s*\(")
STORE_CLOSE = re.compile(r"\bwyl_policy_store_close\s*\(")


def count_references(path: Path) -> int:
    return sum(1 for _ in GET_DB.finditer(path.read_text(encoding="utf-8")))


def count_matches(path: Path, pattern: re.Pattern[str]) -> int:
    return sum(1 for _ in pattern.finditer(path.read_text(encoding="utf-8")))


def source_files(directory: Path):
    return sorted(path for path in directory.rglob("*")
                  if path.is_file() and path.suffix in {".c", ".h"})


def main() -> int:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    expected_borrowers = inventory["raw_db_borrowers"]
    actual_borrowers = {
        path.relative_to(ROOT).as_posix(): count_references(path)
        for path in source_files(ROOT / "tests")
        if count_references(path)
    }
    if actual_borrowers != expected_borrowers:
        print("policy-store raw-db borrower inventory drift", file=sys.stderr)
        print(f"expected: {expected_borrowers}", file=sys.stderr)
        print(f"actual:   {actual_borrowers}", file=sys.stderr)
        return 1

    expected_close_sites = inventory["store_close_sites"]
    actual_close_sites = {
        path.relative_to(ROOT).as_posix(): count_matches(path, STORE_CLOSE)
        for directory in (ROOT / "tests", ROOT / "wyrelog")
        for path in source_files(directory)
        if count_matches(path, STORE_CLOSE)
    }
    if actual_close_sites != expected_close_sites:
        print("policy-store close-site inventory drift", file=sys.stderr)
        print(f"expected: {expected_close_sites}", file=sys.stderr)
        print(f"actual:   {actual_close_sites}", file=sys.stderr)
        return 1

    allowed_production = {
        "wyrelog/policy/store.c": 1,  # definition
        "wyrelog/policy/store-private.h": 1,  # declaration
    }
    production = {
        path.relative_to(ROOT).as_posix(): count_references(path)
        for path in source_files(ROOT / "wyrelog")
        if count_references(path)
    }
    if production != allowed_production:
        print("production code must not borrow raw policy-store SQLite handles",
              file=sys.stderr)
        print(f"expected: {allowed_production}", file=sys.stderr)
        print(f"actual:   {production}", file=sys.stderr)
        return 1

    test_source = (ROOT / "tests/test-policy-graph-authority.c").read_text(
        encoding="utf-8")
    for test_name, required_markers in inventory["lifetime_tests"].items():
        if test_name not in test_source:
            print(f"missing lifetime test {test_name}", file=sys.stderr)
            return 1
        for marker in required_markers:
            if marker not in test_source:
                print(f"{test_name} missing {marker!r}", file=sys.stderr)
                return 1

    print(f"checked {sum(expected_borrowers.values())} raw-db references in "
          f"{len(expected_borrowers)} test files and "
          f"{sum(expected_close_sites.values())} close sites; no production "
          "raw-db borrowers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

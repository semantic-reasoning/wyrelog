#!/usr/bin/env python3
"""Backward-compatible CLI for the fact-store connection boundary checker."""

from __future__ import annotations

from pathlib import Path
import sys

from fact_store_connection_boundary.contract import load, validate
from fact_store_connection_boundary.mutations import self_test


def main() -> int:
    args = sys.argv[1:]
    self_mode = bool(args and args[0] == "--self-test")
    if self_mode:
        args = args[1:]
    # Meson appends component source files as tracked test arguments so edits
    # invalidate the test without changing the legacy CLI contract.
    if len(args) < 1:
        raise SystemExit(
            "usage: test-fact-store-connection-boundary.py [--self-test] ROOT"
        )
    files = load(Path(args[0]))
    validate(files)
    if self_mode:
        self_test(files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

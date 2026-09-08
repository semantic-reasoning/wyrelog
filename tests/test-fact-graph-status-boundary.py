#!/usr/bin/env python3
"""Guard the non-open admission projection for issue #948."""

from __future__ import annotations

from pathlib import Path
import sys


SOURCE = "wyrelog/wyl-handle.c"


def function_body(source: str, name: str) -> str:
    start = source.index(name)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {name}")


def validate(root: Path, source: str | None = None) -> None:
    code = source if source is not None else (root / SOURCE).read_text(
        encoding="utf-8"
    )
    body = function_body(code, "legacy_fact_graph_state")
    expected = (
        "  if (status->admission != WYL_FACT_GRAPH_ADMISSION_OPEN)\n"
        "    return WYL_FACT_GRAPH_STATE_SEALED;"
    )
    if expected not in body:
        raise AssertionError(
            "legacy state projection must classify every non-open admission "
            "as sealed"
        )
    if "status->admission == WYL_FACT_GRAPH_ADMISSION_CLOSED" in body:
        raise AssertionError(
            "state projection still recognizes only the two-valued CLOSED "
            "sentinel"
        )
    status_body = function_body(code, "fact_graph_runtime_status_cb")
    queryable = (
        "runtime_status->queryable\n"
        "        && runtime_status->admission == WYL_FACT_GRAPH_ADMISSION_OPEN"
    )
    if queryable not in status_body:
        raise AssertionError(
            "operator queryability must be explicitly gated by OPEN admission"
        )
    if "runtime_status->admission == WYL_FACT_GRAPH_ADMISSION_CLOSED" in status_body:
        raise AssertionError(
            "queryability still recognizes only the two-valued CLOSED sentinel"
        )


def self_test(root: Path) -> None:
    original = (root / SOURCE).read_text(encoding="utf-8")
    validate(root, original)
    state_mutation = original.replace(
        "if (status->admission != WYL_FACT_GRAPH_ADMISSION_OPEN)",
        "if (status->admission == WYL_FACT_GRAPH_ADMISSION_CLOSED)",
        1,
    )
    if state_mutation == original:
        raise AssertionError("state predicate mutation anchor is missing")
    try:
        validate(root, state_mutation)
    except AssertionError:
        pass
    else:
        raise AssertionError("state predicate mutation survived")

    query_mutation = original.replace(
        "runtime_status->admission == WYL_FACT_GRAPH_ADMISSION_OPEN",
        "runtime_status->admission == WYL_FACT_GRAPH_ADMISSION_CLOSED",
        1,
    )
    if query_mutation == original:
        raise AssertionError("queryable predicate mutation anchor is missing")
    try:
        validate(root, query_mutation)
    except AssertionError:
        return
    raise AssertionError("queryable predicate mutation survived")


def main() -> int:
    args = sys.argv[1:]
    run_self_test = args[:1] == ["--self-test"]
    if run_self_test:
        args = args[1:]
    if len(args) != 1:
        raise SystemExit(f"usage: {sys.argv[0]} [--self-test] ROOT")
    root = Path(args[0]).resolve()
    if run_self_test:
        self_test(root)
    else:
        validate(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

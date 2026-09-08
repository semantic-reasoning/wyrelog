#!/usr/bin/env python3
"""Direct regression tests for the connection-boundary parser helpers."""

from __future__ import annotations

import re

from fact_store_connection_boundary import parser


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    lines = parser.preprocessing_lines(
        "/* hidden { } */\nvalue // hidden\n\"text -> conn\" 'x'\n"
    )
    check(lines[0].strip() == "", "block comments must preserve lines")
    check(lines[1].startswith("value"), "line comment changed code")
    check('"text -> conn"' in lines[2], "string literal was removed")
    check("'x'" in lines[2], "character literal was removed")

    nested = "call(one, inner(two, three), final)"
    arguments, end = parser.invocation_arguments(nested, nested.index("("))
    check(len(arguments) == 3 and end == len(nested), "nested call parsing failed")
    check(
        parser.matching_delimiter("{a: [b, {c: 1}]}", 0, "{", "}") == 15,
        "nested brace parsing failed",
    )

    definitions = {
        "JOIN": (("left", "right"), "left ## right"),
        "ALIAS": (None, "JOIN"),
    }
    expanded = parser.expand_macros("ALIAS(foo, bar)", definitions)
    check("foobar" in expanded, "macro alias/token paste expansion failed")
    check(
        parser.normalize_function_designator("(& target)") == "target",
        "function designator normalization failed",
    )
    aliases = parser.local_alias_scopes(
        "void run(void) { void (*callback)(void) = first; callback(); "
        "callback = second; }"
    )
    check(aliases and any(item[0] == "callback" for item in aliases),
          "assignment/alias analysis failed")

    source = (
        "static void outer(void) { duckdb_open(); inner(); }\n"
        "static void inner(void) { duckdb_query(); }\n"
    )
    spans = parser.source_function_spans(source)
    check({name for _start, _end, name in spans} == {"outer", "inner"},
          "function spans missing")
    calls, outside = parser.duckdb_call_function_inventory(
        parser.active_code(source, set())
    )
    check(outside == 0 and calls["outer"] == 1 and calls["inner"] == 1,
          "DuckDB call inventory failed")

    profiles = parser.external_condition_values(
        "#if WYL_MODE == 2\nvalue\n#endif\n"
    )
    check("WYL_MODE" in profiles and "2" in profiles["WYL_MODE"],
          "conditional profile extraction failed")
    check(re.match(r"^foo$", parser.collapse_token_pastes("foo ##")) is not None,
          "token paste cleanup failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

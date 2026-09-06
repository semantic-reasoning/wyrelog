#!/usr/bin/env python3
"""Keep DuckDB fact-store authority scoped, role-gated, and test-only."""

from __future__ import annotations

import concurrent.futures
import functools
import multiprocessing
import os
from pathlib import Path, PurePath, PureWindowsPath
import posixpath
import re
import sys


ROLE_HEADER = "wyrelog/fact/store-connection-private.h"
CONFIG_SEAM_HEADER = "wyrelog/fact/store-duckdb-config-test-seams-private.h"
ROLE_OWNERS = {
    "wyrelog/fact/store.c",
    "wyrelog/fact/compound.c",
    "wyrelog/fact/replay.c",
}
EXPECTED_RAW_INVENTORY = {
    "wyrelog/fact/store.c": (44, 355, 4, 3),
    "wyrelog/fact/compound.c": (0, 123, 14, 0),
    "wyrelog/fact/replay.c": (0, 32, 2, 0),
}
EXPECTED_RAW_MEMBER_FUNCTIONS = {
    "wyrelog/fact/store.c": {
        "complete_forget_intent_unlocked": 2,
        "count_projection_rows_unlocked": 1,
        "existing_batch_matches_unlocked": 1,
        "fact_identity_execute": 1,
        "fact_identity_validation_barrier": 1,
        "forget_intent_state_check_is_current": 1,
        "insert_batch_unlocked": 1,
        "insert_event_unlocked": 1,
        "insert_forget_intent_unlocked": 1,
        "load_batch_forget_fingerprint_unlocked": 1,
        "load_pending_forget_intents_unlocked": 1,
        "lookup_batch_scope_unlocked": 1,
        "migrate_forget_intent_state_check_unlocked": 3,
        "next_sequence_unlocked": 1,
        "prepared_delete_batch_unlocked": 1,
        "reject_audit_database_unlocked": 1,
        "rename_metadata_value_column_once_unlocked": 1,
        "select_valid_rows_for_batch_unlocked": 1,
        "table_exists_unlocked": 1,
        "validate_projection_shape_unlocked": 2,
        "validate_store_scope_unlocked": 1,
        "wyl_fact_store_append_batch_delta": 1,
        "wyl_fact_store_close": 2,
        "wyl_fact_store_connection_session_begin": 2,
        "wyl_fact_store_connection_session_get": 1,
        "wyl_fact_store_create_schema": 1,
        "wyl_fact_store_ensure_projection": 1,
        "wyl_fact_store_open": 4,
        "wyl_fact_store_open_identified": 4,
        "wyl_fact_store_retract_by_batch_id": 1,
        "wyl_fact_store_transaction_begin": 1,
        "wyl_fact_store_transaction_finish": 1,
    },
    "wyrelog/fact/compound.c": {},
    "wyrelog/fact/replay.c": {},
}
EXPECTED_DUCKDB_CALL_FUNCTIONS = {
    "wyrelog/fact/compound.c": {
        "compound_exists_unlocked": 13,
        "compound_hash_matches_unlocked": 16,
        "exec_sql": 3,
        "insert_arg_unlocked": 18,
        "insert_term_unlocked": 13,
        "load_logical_arg_unlocked": 29,
        "load_term_unlocked": 19,
        "replay_unlocked": 12,
    },
    "wyrelog/fact/replay.c": {
        "list_replay_relations": 16,
        "replay_relation_into_engine": 16,
    },
    "wyrelog/fact/store.c": {
        "append_value": 5,
        "complete_forget_intent_unlocked": 19,
        "count_projection_rows_unlocked": 10,
        "create_hardened_duckdb_config": 2,
        "duckdb_type_for_column": 1,
        "exec_sql": 3,
        "existing_batch_matches_unlocked": 36,
        "fact_identity_bind_param": 3,
        "fact_identity_execute": 25,
        "fact_store_duckdb_set_config": 1,
        "forget_intent_state_check_is_current": 8,
        "insert_batch_unlocked": 20,
        "insert_event_unlocked": 15,
        "insert_forget_intent_unlocked": 19,
        "load_batch_forget_fingerprint_unlocked": 17,
        "load_pending_forget_intents_unlocked": 30,
        "lookup_batch_scope_unlocked": 24,
        "next_sequence_unlocked": 4,
        "open_duckdb_identified": 6,
        "open_duckdb_with_thread_budget": 6,
        "prepared_delete_batch_unlocked": 6,
        "read_projection_value": 6,
        "reject_audit_database_unlocked": 7,
        "select_valid_rows_for_batch_unlocked": 12,
        "table_exists_unlocked": 10,
        "validate_projection_shape_unlocked": 22,
        "validate_schema_shape": 1,
        "wyl_fact_store_append_batch_delta": 10,
        "wyl_fact_store_close": 2,
        "wyl_fact_store_ensure_projection": 1,
        "wyl_fact_store_open": 2,
        "wyl_fact_store_open_identified": 2,
        "wyl_fact_store_retract_by_batch_id": 11,
        "wyl_fact_store_test_query_int64": 4,
        "wyl_fact_store_test_query_text": 5,
    },
}
RAW_PROFILE_ADDITIONS = {
    ("wyrelog/fact/store.c", "WYL_HAS_SECURE_DUCKDB_BRIDGE"): (
        (2, 0, 1, 1),
        {"wyl_fact_store_open_provisioned_pair": 2},
        {},
    ),
}
EXPECTED_TRANSITIVE_RAW_WRAPPERS = {
    "build_graph_engine",
    "execute_forget_intent_unlocked",
    "fact_store_duckdb_apply_config",
    "forget_survey_unlocked",
    "materialize_arg_unlocked",
    "open_graph_engine_with_store",
    "open_graph_store",
    "probe_graph_forgets",
    "quarantine_forget_intent_unlocked",
    "reconcile_graph_forgets",
    "wyl_fact_replay_open_graph_engine",
    "wyl_fact_replay_open_graph_engine_with_store_for_test",
    "wyl_fact_replay_policy_graphs",
    "wyl_fact_replay_refresh_graph",
}
EXPECTED_TRANSITIVE_RAW_WRAPPERS_BY_PATH = {
    "wyrelog/fact/compound.c": {"materialize_arg_unlocked"},
    "wyrelog/fact/replay.c": {
        "build_graph_engine",
        "open_graph_engine_with_store",
        "open_graph_store",
        "probe_graph_forgets",
        "reconcile_graph_forgets",
        "wyl_fact_replay_open_graph_engine",
        "wyl_fact_replay_open_graph_engine_with_store_for_test",
        "wyl_fact_replay_policy_graphs",
        "wyl_fact_replay_refresh_graph",
    },
    "wyrelog/fact/store.c": {
        "execute_forget_intent_unlocked",
        "fact_store_duckdb_apply_config",
        "forget_survey_unlocked",
        "quarantine_forget_intent_unlocked",
    },
}
OLD_AUTHORITY = (
    "wyl_fact_store_get_connection",
    "wyl_fact_store_lock",
    "wyl_fact_store_unlock",
)
SEAM_SYMBOLS = (
    "wyl_fact_store_test_set_transaction_hook",
    "wyl_fact_store_test_set_session_admission_hook",
    "wyl_fact_store_test_try_lock",
    "wyl_fact_store_test_session_admission_count",
    "wyl_fact_store_test_duckdb_call_count",
    "wyl_fact_store_test_exec_sql",
    "wyl_fact_store_test_query_int64",
    "wyl_fact_store_test_query_text",
    "wyl_fact_store_test_arm_metadata_value_column_rename_once",
)


def target_block(meson: str, name: str) -> str:
    name_at = meson.index(f"'{name}'")
    start = meson.rfind("executable(", 0, name_at)
    if start < 0:
        raise AssertionError(f"target declaration missing: {name}")
    end = meson.index("\n  )", start)
    return meson[start:end]


def function_body(source: str, signature: str) -> str:
    masked = re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda match: "".join(
            "\n" if character == "\n" else " " for character in match.group(0)
        ),
        source,
        flags=re.DOTALL,
    )
    start = masked.index(signature)
    brace = masked.index("{", start)
    depth = 0
    for index in range(brace, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


MacroDefinition = tuple[tuple[str, ...] | None, str]


@functools.lru_cache(maxsize=1024)
def preprocessing_lines(source: str) -> tuple[str, ...]:
    for trigraph, replacement in (
        ("??=", "#"), ("??/", "\\"), ("??'", "^"), ("??(", "["),
        ("??)", "]"), ("??!", "|"), ("??<", "{"), ("??>", "}"),
        ("??-", "~"),
    ):
        source = source.replace(trigraph, replacement)
    source = re.sub(r"\\\r?\n", "", source)

    translated = []
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        pair = source[index:index + 2]
        if state == "code" and pair in {"//", "/*"}:
            translated.extend("  ")
            state = "line-comment" if pair == "//" else "block-comment"
            index += 2
            continue
        if state == "line-comment":
            translated.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
            index += 1
            continue
        if state == "block-comment":
            if pair == "*/":
                translated.extend("  ")
                state = "code"
                index += 2
            else:
                translated.append("\n" if char == "\n" else " ")
                index += 1
            continue
        translated.append(char)
        if state == "code" and char in {'"', "'"}:
            state = "string" if char == '"' else "character"
        elif state in {"string", "character"}:
            quote = '"' if state == "string" else "'"
            if char == "\\" and index + 1 < len(source):
                translated.append(source[index + 1])
                index += 2
                continue
            if char == quote:
                state = "code"
        index += 1
    source = "".join(translated)
    source = source.replace("%:%:", "##").replace("%:", "#")
    return tuple(source.split("\n"))


def collapse_token_pastes(replacement: str) -> str:
    token = r"(?:[A-Za-z_]\w*|[-<>])"
    paste = re.compile(rf"({token})\s*##\s*({token})")
    products = ()
    if "##" in replacement:
        products = tuple(
            left + right for left, right in re.findall(
                rf"\(\s*({token})\s*,\s*({token})\s*\)", replacement
            )
        )
    previous = None
    while replacement != previous:
        previous = replacement
        replacement = paste.sub(lambda match: match.group(1) + match.group(2),
                                replacement)
        replacement = re.sub(
            rf"##\s*({token})", lambda match: match.group(1), replacement
        )
        replacement = re.sub(
            rf"({token})\s*##", lambda match: match.group(1), replacement
        )
        replacement = replacement.replace("##", "")
    if products:
        replacement += " " + " ".join(products)
    return replacement


def invocation_arguments(source: str, opening: int) \
        -> tuple[tuple[str, ...], int] | None:
    depth = 1
    start = opening + 1
    arguments = []
    for index in range(start, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                arguments.append(source[start:index])
                return tuple(arguments), index + 1
        elif source[index] == "," and depth == 1:
            arguments.append(source[start:index])
            start = index + 1
    return None


def expand_macros(
    source: str, definitions: dict[str, MacroDefinition], depth: int = 0,
) -> str:
    if depth >= 32:
        if set(re.findall(r"\b[A-Za-z_]\w*\b", source)) & definitions.keys():
            raise AssertionError("macro expansion depth exceeded")
        return source
    changed = False
    referenced = set(re.findall(r"\b[A-Za-z_]\w*\b", source))
    for name in sorted(referenced & definitions.keys(), key=len, reverse=True):
        parameters, replacement = definitions[name]
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        offset = 0
        while True:
            match = pattern.search(source, offset)
            if match is None:
                break
            end = match.end()
            if parameters is None:
                substituted = replacement
            else:
                opening = end
                while opening < len(source) and source[opening].isspace():
                    opening += 1
                if opening >= len(source) or source[opening] != "(":
                    offset = end
                    continue
                invocation = invocation_arguments(source, opening)
                if invocation is None:
                    offset = end
                    continue
                arguments, invocation_end = invocation
                if parameters and parameters[-1] == "__VA_ARGS__" \
                        and len(arguments) >= len(parameters):
                    arguments = (
                        arguments[:len(parameters) - 1]
                        + (", ".join(arguments[len(parameters) - 1:]),)
                    )
                if len(arguments) != len(parameters):
                    offset = invocation_end
                    continue
                substituted = replacement
                for parameter, argument in zip(parameters, arguments, strict=True):
                    substituted = re.sub(
                        rf"(?<!#)#(?!#)\s*{re.escape(parameter)}\b",
                        '"' + argument.replace("\\", "\\\\").replace(
                            '"', '\\"'
                        ) + '"',
                        substituted,
                    )
                    substituted = re.sub(
                        rf"\b{re.escape(parameter)}\b", argument, substituted
                    )
                end = invocation_end
            substituted = collapse_token_pastes(substituted)
            source = source[:match.start()] + substituted + source[end:]
            offset = match.start() + len(substituted)
            changed = True
    return expand_macros(source, definitions, depth + 1) if changed else source


def condition_is_true(
    expression: str, definitions: dict[str, MacroDefinition],
    undefined_is_true: bool,
) -> bool:
    expression = re.sub(
        r"defined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))",
        lambda match: "1" if (match.group(1) or match.group(2)) in definitions
        else "0",
        expression,
    )
    expression = expand_macros(expression, definitions)
    expression = re.sub(
        r"'(?:\\.|[^'\\])'",
        lambda match: str(ord(bytes(
            match.group(0)[1:-1], "utf-8"
        ).decode("unicode_escape"))),
        expression,
    )
    expression = re.sub(
        r"\b[A-Za-z_]\w*\b", "1" if undefined_is_true else "0", expression
    )
    try:
        return bool(evaluate_c_expression(parse_c_expression(expression))[0])
    except (TypeError, ValueError, ZeroDivisionError) as error:
        raise AssertionError(
            f"unsupported preprocessor expression: {expression!r}"
        ) from error


CValue = tuple[int, bool, int]
CNode = tuple[object, ...]
C_BINARY_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 7,
    "<=": 7,
    ">": 7,
    ">=": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
}


def tokenize_c_expression(expression: str) -> list[str]:
    token = re.compile(
        r"\s*(0[xX][0-9a-fA-F]+(?:[uUlL]+)?"
        r"|0[0-7]*(?:[uUlL]+)?|[1-9][0-9]*(?:[uUlL]+)?"
        r"|&&|\|\||<<|>>|<=|>=|==|!="
        r"|[()?:~!+*/%<>&^|-])"
    )
    tokens = []
    offset = 0
    while offset < len(expression):
        match = token.match(expression, offset)
        if match is None:
            if expression[offset:].strip() == "":
                break
            raise ValueError(f"invalid token at {expression[offset:]!r}")
        tokens.append(match.group(1))
        offset = match.end()
    return tokens


def parse_c_integer(token: str) -> CValue:
    suffix = re.search(r"[uUlL]+$", token)
    suffix_text = suffix.group(0).lower() if suffix is not None else ""
    number = token[:-len(suffix_text)] if suffix_text else token
    base = 16 if number.lower().startswith("0x") else 8 \
        if len(number) > 1 and number.startswith("0") else 10
    integer = int(number, base)
    unsigned = "u" in suffix_text or base != 10 and integer > (1 << 63) - 1
    # C preprocessing evaluates signed and unsigned integer constants as
    # intmax_t and uintmax_t, respectively (C17 6.10.1p4).
    return integer, unsigned, 64


def parse_c_expression(expression: str) -> CNode:
    tokens = tokenize_c_expression(expression)
    offset = 0

    def parse_primary() -> CNode:
        nonlocal offset
        if offset >= len(tokens):
            raise ValueError("missing expression")
        current = tokens[offset]
        if current in {"+", "-", "!", "~"}:
            offset += 1
            return "unary", current, parse_primary()
        if current == "(":
            offset += 1
            node = parse_binary(1)
            if offset >= len(tokens) or tokens[offset] != ")":
                raise ValueError("missing closing parenthesis")
            offset += 1
            return node
        if re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*", current):
            offset += 1
            return "literal", parse_c_integer(current)
        raise ValueError(f"unexpected token: {current}")

    def parse_binary(minimum: int) -> CNode:
        nonlocal offset
        left = parse_primary()
        while offset < len(tokens):
            operator = tokens[offset]
            precedence = C_BINARY_PRECEDENCE.get(operator, -1)
            if precedence < minimum:
                break
            offset += 1
            right = parse_binary(precedence + 1)
            left = make_binary_node(operator, left, right)
        if minimum == 1 and offset < len(tokens) and tokens[offset] == "?":
            offset += 1
            when_true = parse_binary(1)
            if offset >= len(tokens) or tokens[offset] != ":":
                raise ValueError("missing ternary colon")
            offset += 1
            left = make_ternary_node(left, when_true, parse_binary(1))
        return left

    result = parse_binary(1)
    if offset != len(tokens):
        raise ValueError(f"trailing token: {tokens[offset]}")
    return result


def make_binary_node(operator: str, left: CNode, right: CNode) -> CNode:
    return "binary", operator, left, right


def make_ternary_node(
    condition: CNode, when_true: CNode, when_false: CNode,
) -> CNode:
    return "ternary", condition, when_true, when_false


def cast_c_value(value: CValue, unsigned: bool, bits: int) -> int:
    integer = value[0]
    return integer % (1 << bits) if unsigned else integer


def usual_c_type(left: CValue, right: CValue) -> tuple[bool, int]:
    if left[1] == right[1]:
        return left[1], max(left[2], right[2])
    unsigned_value = left if left[1] else right
    signed_value = right if left[1] else left
    if unsigned_value[2] >= signed_value[2]:
        return True, unsigned_value[2]
    if signed_value[2] > unsigned_value[2]:
        return False, signed_value[2]
    return True, signed_value[2]


def c_expression_type(node: CNode) -> CValue:
    kind = node[0]
    if kind == "literal":
        return node[1]  # type: ignore[return-value]
    if kind == "unary":
        if node[1] == "!":
            return 0, False, 64
        return c_expression_type(node[2])  # type: ignore[arg-type]
    if kind == "ternary":
        when_true = c_expression_type(node[2])  # type: ignore[arg-type]
        when_false = c_expression_type(node[3])  # type: ignore[arg-type]
        unsigned, bits = usual_c_type(when_true, when_false)
        return 0, unsigned, bits
    if kind == "binary":
        operator = node[1]
        if operator in {"&&", "||", "==", "!=", "<", "<=", ">", ">="}:
            return 0, False, 64
        left = c_expression_type(node[2])  # type: ignore[arg-type]
        if operator in {"<<", ">>"}:
            return 0, left[1], left[2]
        right = c_expression_type(node[3])  # type: ignore[arg-type]
        unsigned, bits = usual_c_type(left, right)
        return 0, unsigned, bits
    raise ValueError(f"invalid expression node: {kind}")


def evaluate_c_expression(node: CNode) -> CValue:
    kind = node[0]
    if kind == "literal":
        return node[1]  # type: ignore[return-value]
    if kind == "unary":
        operator = node[1]
        value = evaluate_c_expression(node[2])  # type: ignore[arg-type]
        if operator == "!":
            return int(not value[0]), False, 64
        result = value[0] if operator == "+" else -value[0] \
            if operator == "-" else ~value[0]
        return cast_c_value((result, value[1], value[2]), value[1], value[2]), \
            value[1], value[2]
    if kind == "ternary":
        condition = evaluate_c_expression(node[1])  # type: ignore[arg-type]
        branch = node[2] if condition[0] else node[3]
        value = evaluate_c_expression(branch)  # type: ignore[arg-type]
        _zero, unsigned, bits = c_expression_type(node)
        return cast_c_value(value, unsigned, bits), unsigned, bits
    if kind != "binary":
        raise ValueError(f"invalid expression node: {kind}")
    operator = node[1]
    left = evaluate_c_expression(node[2])  # type: ignore[arg-type]
    if operator == "&&" and not left[0]:
        return 0, False, 64
    if operator == "||" and left[0]:
        return 1, False, 64
    right = evaluate_c_expression(node[3])  # type: ignore[arg-type]
    if operator in {"&&", "||"}:
        return int(bool(right[0])), False, 64
    if operator in {"<<", ">>"}:
        unsigned, bits = left[1], left[2]
        left_value = cast_c_value(left, unsigned, bits)
        right_value = right[0]
    else:
        unsigned, bits = usual_c_type(left, right)
        left_value = cast_c_value(left, unsigned, bits)
        right_value = cast_c_value(right, unsigned, bits)
    if operator in {"==", "!=", "<", "<=", ">", ">="}:
        comparisons = {
            "==": left_value == right_value,
            "!=": left_value != right_value,
            "<": left_value < right_value,
            "<=": left_value <= right_value,
            ">": left_value > right_value,
            ">=": left_value >= right_value,
        }
        return int(comparisons[operator]), False, 64
    if operator in {"/", "%"}:
        if right_value == 0:
            raise ZeroDivisionError
        quotient = abs(left_value) // abs(right_value)
        if (left_value < 0) != (right_value < 0):
            quotient = -quotient
        result = quotient if operator == "/" \
            else left_value - quotient * right_value
    else:
        operations = {
            "+": lambda: left_value + right_value,
            "-": lambda: left_value - right_value,
            "*": lambda: left_value * right_value,
            "<<": lambda: left_value << right_value,
            ">>": lambda: left_value >> right_value,
            "&": lambda: left_value & right_value,
            "^": lambda: left_value ^ right_value,
            "|": lambda: left_value | right_value,
        }
        if operator not in operations:
            raise ValueError(f"unsupported operator: {operator}")
        result = operations[operator]()
    result = cast_c_value((result, unsigned, bits), unsigned, bits)
    return result, unsigned, bits


def resolve_project_include(
    files: dict[str, str], current_path: str, include: str,
) -> str | None:
    candidates = (
        posixpath.normpath(posixpath.join(posixpath.dirname(current_path), include)),
        posixpath.normpath(include),
        posixpath.normpath(posixpath.join("wyrelog", include)),
    )
    return next((candidate for candidate in candidates if candidate in files), None)


def project_include_closure(
    files: dict[str, str], roots: set[str],
) -> set[str]:
    closure = set()

    def visit(
        path: str, definitions: dict[str, MacroDefinition], stack: set[str],
    ) -> None:
        if path in stack or path not in files:
            return
        closure.add(path)
        stack.add(path)
        for line in preprocessing_lines(strip_literal_if_zero(files[path])):
            directive = re.match(r"^\s*#\s*([A-Za-z_]\w*)\b(.*)$", line)
            if directive is None:
                continue
            command = directive.group(1)
            argument = directive.group(2).strip()
            if command == "define":
                macro = re.match(
                    r"([A-Za-z_]\w*)(\(([^)]*)\))?\s*(.*)$", argument
                )
                if macro is not None:
                    parameters = None if macro.group(2) is None else tuple(
                        item.strip() for item in macro.group(3).split(",")
                    )
                    definitions[macro.group(1)] = (parameters, macro.group(4))
                    # A conditional may define the same include macro to
                    # different headers. Preserve every literal candidate,
                    # even though this lexical pass cannot choose a profile.
                    for candidate in re.finditer(
                        r'(?:"([^"\n]+)"|<([^>\n]+)>)', macro.group(4)
                    ):
                        included = resolve_project_include(
                            files, path,
                            candidate.group(1) or candidate.group(2),
                        )
                        if included is not None:
                            visit(included, dict(definitions), stack)
                continue
            if command == "undef":
                name = re.match(r"([A-Za-z_]\w*)", argument)
                if name is not None:
                    definitions.pop(name.group(1), None)
                continue
            if command != "include":
                continue
            operand = argument if argument.startswith(("\"", "<")) \
                else expand_macros(argument, definitions)
            include = re.match(r'(?:"([^"\n]+)"|<([^>\n]+)>)', operand)
            if include is None:
                continue
            included = resolve_project_include(
                files, path, include.group(1) or include.group(2)
            )
            if included is not None:
                visit(included, definitions, stack)
        stack.remove(path)

    for root in roots:
        visit(root, {}, set())
    return closure


def external_condition_names(source: str) -> set[str]:
    lines = preprocessing_lines(strip_literal_if_zero(source))
    guard_names = set()
    for index, line in enumerate(lines[:12]):
        guard = re.match(r"^\s*#\s*ifndef\s+([A-Za-z_]\w*)", line)
        if guard is not None and any(re.match(
            rf"^\s*#\s*define\s+{re.escape(guard.group(1))}\b", later
        ) for later in lines[index + 1:index + 6]):
            guard_names.add(guard.group(1))
    defined_before = set()
    names = set()
    for line in lines:
        definition = re.match(r"^\s*#\s*define\s+([A-Za-z_]\w*)", line)
        if definition is not None:
            defined_before.add(definition.group(1))
            continue
        directive = re.match(
            r"^\s*#\s*(?:if|elif|ifdef|ifndef)\b(.*)$", line
        )
        if directive is not None:
            condition = re.sub(
                r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                " ", directive.group(1),
            )
            names.update(set(re.findall(
                r"\b[A-Za-z_]\w*\b", condition
            )) - {"defined", "and", "or", "not"}
                - defined_before - guard_names)
    return names


def external_condition_values(source: str) -> dict[str, set[str]]:
    values = {name: {"1"} for name in external_condition_names(source)}
    definitions: dict[str, MacroDefinition] = {}
    for line in preprocessing_lines(strip_literal_if_zero(source)):
        definition = re.match(
            r"^\s*#\s*define\s+([A-Za-z_]\w*)(\(([^)]*)\))?\s*(.*)$",
            line,
        )
        if definition is not None:
            parameters = None if definition.group(2) is None else tuple(
                item.strip() for item in definition.group(3).split(",")
            )
            definitions[definition.group(1)] = (
                parameters, definition.group(4)
            )
            continue
        directive = re.match(
            r"^\s*#\s*(?:if|elif)\b(.*)$", line
        )
        if directive is None:
            continue
        raw_expression = directive.group(1)
        expanded_expression = expand_macros(raw_expression, definitions)
        character_values = set()
        for literal in re.findall(r"'(?:\\.|[^'\\])+'", expanded_expression):
            decoded = bytes(literal[1:-1], "utf-8").decode("unicode_escape")
            if decoded:
                character_values.add(ord(decoded[-1]))
        expression = re.sub(
            r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
            " ", expanded_expression,
        )
        literals = {
            int(token, 16) if token.lower().startswith("0x")
            else int(token, 8) if len(token) > 1 and token.startswith("0")
            else int(token, 10) for token in re.findall(
                r"(?<![A-Za-z_])(?:0[xX][0-9a-fA-F]+|\d+)", expression
            )
        } | character_values
        complex_numeric = expanded_expression != raw_expression or re.search(
            r"(?:<<|>>|[+*/%^]|(?<!&)&(?!&)|(?<!\|)\|(?!\|)"
            r"|(?<![=!<>])-)", expression
        ) is not None
        for name in values:
            if re.search(r"\b" + re.escape(name) + r"\b", expression):
                candidates = set(range(-8, 9)) if complex_numeric else set()
                for literal in literals:
                    candidates.update({
                        literal, literal + 1, literal - 1,
                        -literal, -literal + 1, -literal - 1,
                    })
                values[name].update(map(str, candidates))
    return values


def profile_value_variants(
    options: dict[str, set[str]], fixed: set[str],
) -> list[dict[str, str]]:
    variants: list[dict[str, str]] = [{}]
    for name in sorted(options):
        choices = [None] + sorted(options[name])
        variants = [
            dict(variant, **({name: value} if value is not None else {}))
            for variant in variants for value in choices
        ]
        if len(variants) > 4096:
            raise AssertionError("too many external preprocessor profiles")
    return [dict({name: "1" for name in fixed}, **variant)
            for variant in variants]


def function_profiles(
    files: dict[str, str], path: str, source_body: str,
) -> list[dict[str, str]]:
    body_files = dict(files)
    body_files[path] = source_body
    options: dict[str, set[str]] = {}
    for candidate in project_include_closure(body_files, {path}):
        for name, values in external_condition_values(
            body_files[candidate]
        ).items():
            options.setdefault(name, set()).update(values)
    fixed = {"WYL_HAS_FACT_STORE", "WYL_TEST_HANDLE_SEAMS"}
    for name in fixed:
        options.pop(name, None)
    return profile_value_variants(options, fixed)


def expanded_function_profiles(
    files: dict[str, str], path: str, signature: str, source_body: str,
) -> list[str]:
    expanded = []
    for profile in function_profiles(files, path, source_body):
        definitions: dict[str, MacroDefinition] = {
            name: (None, value) for name, value in profile.items()
        }
        prefix_files = dict(files)
        prefix_files[path] = files[path][:files[path].index(signature)]
        scan_macro_environment(
            prefix_files, path, definitions, set(), False, False, set(),
        )
        body_files = dict(files)
        body_files[path] = source_body
        output: list[str] = []
        scan_macro_environment(
            body_files, path, definitions, set(), True, False, set(), output,
            True,
        )
        expanded.append("\n".join(output))
    return expanded


def scan_macro_environment(
    files: dict[str, str], path: str,
    definitions: dict[str, MacroDefinition], visited: set[str],
    inspect_code: bool, undefined_is_true: bool, once_included: set[str],
    expanded_code: list[str] | None = None,
    include_code: bool = False,
) -> set[tuple[str, str]]:
    lines = preprocessing_lines(files[path])
    if path in visited or path in once_included:
        return set()
    visited.add(path)
    escapes = set()
    active = True
    conditionals: list[list[bool]] = []
    pending_code = []

    def inspect_pending_code() -> None:
        if not pending_code or not inspect_code:
            pending_code.clear()
            return
        code = re.sub(
            r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
            " ", "\n".join(pending_code),
        )
        pending_code.clear()
        used = set(re.findall(r"\b[A-Za-z_]\w*\b", code)) \
            & definitions.keys()
        if not used:
            if expanded_code is not None:
                expanded_code.append(code)
            return
        expanded = expand_macros(code, definitions)
        expanded = re.sub(
            r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", expanded
        )
        if expanded_code is not None:
            expanded_code.append(expanded)
        if expanded == code:
            return
        raw_pattern = re.compile(
            r"(?:->|\.)\s*(?:conn|db|connection)\b"
            r"|\bduckdb_[A-Za-z_]\w*\s*(?:\)\s*)*\("
            r"|\bduckdb_(?:connection|database)\b"
            r"|\bwyl_fact_store_connection_session_get\s*\("
        )
        if len(raw_pattern.findall(expanded)) > len(raw_pattern.findall(code)):
            escapes.update((path, name) for name in used)

    for line in lines:
        directive = re.match(r"^\s*#\s*([A-Za-z_]\w*)\b(.*)$", line)
        if directive is not None:
            inspect_pending_code()
            command = directive.group(1)
            argument = directive.group(2).strip()
            if command == "if":
                condition = condition_is_true(
                    argument, definitions, undefined_is_true
                )
                conditionals.append([active, condition])
                active = active and condition
                continue
            if command == "ifdef":
                condition = argument in definitions or undefined_is_true
                conditionals.append([active, condition])
                active = active and condition
                continue
            if command == "ifndef":
                condition = argument not in definitions and not undefined_is_true
                conditionals.append([active, condition])
                active = active and condition
                continue
            if command == "elif" and conditionals:
                parent_active, taken = conditionals[-1]
                condition = not taken and condition_is_true(
                    argument, definitions, undefined_is_true
                )
                conditionals[-1][1] = taken or condition
                active = parent_active and condition
                continue
            if command == "else" and conditionals:
                parent_active, taken = conditionals[-1]
                active = parent_active and not taken
                conditionals[-1][1] = True
                continue
            if command == "endif" and conditionals:
                parent_active, _taken = conditionals.pop()
                active = parent_active
                continue
            if not active:
                continue
            if command == "pragma" and argument == "once":
                once_included.add(path)
                continue
            if command == "include":
                include_operand = argument if argument.startswith(("\"", "<")) \
                    else expand_macros(argument, definitions)
                include = re.match(
                    r'(?:"([^"\n]+)"|<([^>\n]+)>)',
                    include_operand,
                )
                if include is not None:
                    included = resolve_project_include(
                        files, path, include.group(1) or include.group(2)
                    )
                    if included is not None:
                        escapes.update(scan_macro_environment(
                            files, included, definitions, visited, include_code,
                            undefined_is_true, once_included, expanded_code,
                            include_code,
                        ))
                continue
            if command == "undef":
                name = re.match(r"([A-Za-z_]\w*)", argument)
                if name is not None:
                    definitions.pop(name.group(1), None)
                continue
            if command == "define":
                macro = re.match(
                    r"([A-Za-z_]\w*)(\(([^)]*)\))?\s*(.*)$", argument
                )
                if macro is not None:
                    parameters = None
                    if macro.group(2) is not None:
                        parsed = []
                        for item in macro.group(3).split(","):
                            item = item.strip()
                            if item == "...":
                                item = "__VA_ARGS__"
                            elif item.endswith("..."):
                                item = item[:-3].strip()
                            parsed.append(item)
                        parameters = tuple(parsed)
                    definitions[macro.group(1)] = (parameters, macro.group(4))
            continue
        if not active or not inspect_code:
            continue
        pending_code.append(line)
    inspect_pending_code()
    visited.remove(path)
    return escapes


def macro_authority_escapes(files: dict[str, str]) -> set[tuple[str, str]]:
    relevant = tuple(sorted(
        (path, text) for path, text in files.items()
        if not path.startswith("tests/")
        and path.endswith((".c", ".h", ".cc", ".cpp"))
    ))
    return set(cached_macro_authority_escapes(relevant))


@functools.lru_cache(maxsize=256)
def cached_macro_authority_escapes(
    relevant: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    files = dict(relevant)
    escapes = set()
    profiles = [
        {name: "1" for name in profile} for profile in (
            {"WYL_HAS_FACT_STORE"},
            {"WYL_HAS_FACT_STORE", "WYL_TEST_HANDLE_SEAMS"},
            {"WYL_HAS_FACT_STORE", "WYL_HAS_SECURE_DUCKDB_BRIDGE"},
            {"WYL_HAS_FACT_STORE", "G_OS_WIN32", "_WIN32"},
            {"WYL_HAS_FACT_STORE", "__APPLE__", "__MACH__"},
            {"WYL_HAS_FACT_STORE", "__linux__"},
        )
    ]
    profile_paths = project_include_closure(files, set(ROLE_OWNERS))
    conditional_groups: list[dict[str, set[str]]] = []
    for path, text in files.items():
        if path not in profile_paths:
            continue
        conditional_groups.append(external_condition_values(text))
    profile_variants = list(profiles)
    for options in conditional_groups:
        options.pop("WYL_HAS_FACT_STORE", None)
        profile_variants.extend(profile_value_variants(
            options, {"WYL_HAS_FACT_STORE"}
        ))
    profile_variants = [dict(profile) for profile in {
        tuple(sorted(profile.items())) for profile in profile_variants
    }]
    for path in ROLE_OWNERS:
        for profile in profile_variants:
            definitions: dict[str, MacroDefinition] = {
                name: (None, value) for name, value in profile.items()
            }
            escapes.update(scan_macro_environment(
                files, path, definitions, set(), True, False, set(),
            ))
    return tuple(sorted(escapes))


def strip_literal_if_zero(source: str) -> str:
    output = []
    active = True
    conditionals: list[list[bool]] = []
    for line in preprocessing_lines(source):
        directive = re.match(r"^\s*#\s*([A-Za-z_]\w*)\b(.*)$", line)
        if directive is not None:
            command = directive.group(1)
            argument = directive.group(2).strip()
            if command == "if":
                literal = re.fullmatch(r"\(*\s*([01])\s*\)*", argument)
                known = literal is not None
                taken = known and literal.group(1) == "1"
                conditionals.append([active, known, taken])
                active = active and (taken if known else True)
            elif command in {"ifdef", "ifndef"}:
                conditionals.append([active, False, False])
            elif command == "elif" and conditionals:
                parent_active, known, taken = conditionals[-1]
                literal = re.fullmatch(r"\(*\s*([01])\s*\)*", argument)
                if known and literal is not None:
                    selected = not taken and literal.group(1) == "1"
                    active = parent_active and selected
                    conditionals[-1][2] = taken or selected
                else:
                    active = parent_active
                    conditionals[-1][1] = False
            elif command == "else" and conditionals:
                parent_active, known, taken = conditionals[-1]
                active = parent_active and (not taken if known else True)
                conditionals[-1][2] = True
            elif command == "endif" and conditionals:
                active = conditionals.pop()[0]
            if active:
                output.append(line)
            else:
                output.append("")
            continue
        output.append(line if active else "")
    return "\n".join(output)


def strip_stringified_arguments(
    source: str, files: dict[str, str], current_path: str,
) -> str:
    source = strip_literal_if_zero(source)
    source_lines = preprocessing_lines(source)
    code = "\n".join(
        "" if re.match(r"^\s*#", line) else line for line in source_lines
    )
    reachable = project_include_closure(files, {current_path})
    header_definitions: dict[str, MacroDefinition] = {}
    local_definitions: list[tuple[int, str, MacroDefinition]] = []
    definition_sources = [
        (path, text) for path, text in sorted(files.items())
        if path in reachable and path != current_path
    ] + [("<source>", source)]
    for definition_path, definition_source in definition_sources:
        definition_source = strip_literal_if_zero(definition_source)
        for line_number, line in enumerate(preprocessing_lines(definition_source)):
            directive = re.match(r"^\s*#\s*define\b(.*)$", line)
            if directive is None:
                continue
            macro = re.match(
                r"\s*([A-Za-z_]\w*)(\(([^)]*)\))?\s*(.*)$",
                directive.group(1),
            )
            if macro is None:
                continue
            parameters = None if macro.group(2) is None else tuple(
                item.strip() for item in macro.group(3).split(",")
            )
            definition = (parameters, macro.group(4))
            if definition_path == "<source>":
                local_definitions.append(
                    (line_number, macro.group(1), definition)
                )
            else:
                header_definitions[macro.group(1)] = definition

    macro_names = set(header_definitions) | {
        name for _line, name, _definition in local_definitions
    }

    raw = re.compile(
        r"(?:->|\.)\s*(?:conn|db|connection)\b"
        r"|\bduckdb_[A-Za-z_]\w*\s*(?:\)\s*)*\("
        r"|\bduckdb_(?:connection|database)\b"
    )
    for name in macro_names:
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        offset = 0
        while True:
            match = pattern.search(code, offset)
            if match is None:
                break
            opening = match.end()
            while opening < len(code) and code[opening].isspace():
                opening += 1
            invocation = invocation_arguments(code, opening) \
                if opening < len(code) and code[opening] == "(" else None
            if invocation is None:
                offset = match.end()
                continue
            _arguments, end = invocation
            fragment = code[match.start():end]
            if raw.search(fragment) is None:
                offset = end
                continue
            invocation_line = code.count("\n", 0, match.start())
            definitions = dict(header_definitions)
            for line_number, local_name, definition in local_definitions:
                if line_number < invocation_line:
                    definitions[local_name] = definition
            if name not in definitions:
                offset = end
                continue
            expanded = expand_macros(fragment, definitions)
            expanded = re.sub(
                r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", expanded
            )
            if raw.search(expanded) is None:
                code = code[:match.start()] + expanded + code[end:]
                offset = match.start() + len(expanded)
            else:
                offset = end
    return code


def inventory_code(files: dict[str, str], path: str) -> str:
    relevant = tuple(sorted(
        (candidate, text) for candidate, text in files.items()
        if not candidate.startswith("tests/")
        and candidate.endswith((".c", ".h", ".cc", ".cpp"))
    ))
    return cached_inventory_code(path, relevant)


@functools.lru_cache(maxsize=128)
def cached_inventory_code(
    path: str, relevant: tuple[tuple[str, str], ...],
) -> str:
    files = dict(relevant)
    return inventory_code_for_profile(files, path, {
        "WYL_HAS_FACT_STORE": "1", "WYL_TEST_HANDLE_SEAMS": "1"
    })


def inventory_code_for_profile(
    files: dict[str, str], path: str, profile: dict[str, str],
    include_code: bool = False,
) -> str:
    relevant = tuple(sorted(
        (candidate, text) for candidate, text in files.items()
        if not candidate.startswith("tests/")
        and candidate.endswith((".c", ".h", ".cc", ".cpp"))
    ))
    return cached_inventory_code_for_profile(
        path, relevant, tuple(sorted(profile.items())), include_code
    )


@functools.lru_cache(maxsize=512)
def cached_inventory_code_for_profile(
    path: str, relevant: tuple[tuple[str, str], ...],
    profile: tuple[tuple[str, str], ...],
    include_code: bool,
) -> str:
    files = dict(relevant)
    output: list[str] = []
    definitions: dict[str, MacroDefinition] = {
        name: (None, value) for name, value in profile
    }
    scan_macro_environment(
        files, path, definitions, set(), True, False, set(), output,
        include_code,
    )
    return "\n".join(output)


def source_may_introduce_raw_authority(source: str) -> bool:
    raw_names = set(EXPECTED_TRANSITIVE_RAW_WRAPPERS)
    for inventory in EXPECTED_RAW_MEMBER_FUNCTIONS.values():
        raw_names.update(inventory)
    for inventory in EXPECTED_DUCKDB_CALL_FUNCTIONS.values():
        raw_names.update(inventory)
    raw_token = re.compile(
        r"(?:->|\.)\s*(?:conn|db|connection)\b|\bduckdb_|\b(?:"
        + "|".join(map(re.escape, sorted(raw_names))) + r")\b"
    )
    return "##" in source or raw_token.search(source) is not None \
        or bool(source_function_spans(source))


def source_inventory_profiles(
    files: dict[str, str], path: str,
) -> list[dict[str, str]]:
    fixed = {"WYL_HAS_FACT_STORE", "WYL_TEST_HANDLE_SEAMS"}
    root_options = external_condition_values(files[path])
    for name in fixed:
        root_options.pop(name, None)
    root_definitions = {
        match.group(1) for line in preprocessing_lines(files[path])
        if (match := re.match(
            r"^\s*#\s*define\s+([A-Za-z_]\w*)", line
        )) is not None
    }
    for candidate in project_include_closure(files, {path}) - {path}:
        if not source_may_introduce_raw_authority(files[candidate]):
            continue
        for name, values in external_condition_values(files[candidate]).items():
            if name not in fixed | root_definitions | {"__cplusplus"}:
                root_options.setdefault(name, set()).update(values)
    return profile_value_variants(root_options, fixed)


def active_code(
    source: str,
    initial_definitions: set[str] | dict[str, MacroDefinition],
) -> str:
    definitions: dict[str, MacroDefinition] = dict(initial_definitions) \
        if isinstance(initial_definitions, dict) else {
            name: (None, "1") for name in initial_definitions
        }
    output = []
    pending = []
    active = True
    conditionals: list[list[bool]] = []

    def flush() -> None:
        if pending:
            output.append(expand_macros("\n".join(pending), definitions))
            pending.clear()

    for line in preprocessing_lines(source):
        directive = re.match(r"^\s*#\s*([A-Za-z_]\w*)\b(.*)$", line)
        if directive is not None:
            flush()
            command = directive.group(1)
            argument = directive.group(2).strip()
            if command in {"if", "ifdef", "ifndef"}:
                if command == "if":
                    condition = condition_is_true(argument, definitions, False)
                elif command == "ifdef":
                    condition = argument in definitions
                else:
                    condition = argument not in definitions
                conditionals.append([active, condition])
                active = active and condition
            elif command == "elif" and conditionals:
                parent_active, taken = conditionals[-1]
                condition = not taken and condition_is_true(
                    argument, definitions, False
                )
                conditionals[-1][1] = taken or condition
                active = parent_active and condition
            elif command == "else" and conditionals:
                parent_active, taken = conditionals[-1]
                active = parent_active and not taken
                conditionals[-1][1] = True
            elif command == "endif" and conditionals:
                active = conditionals.pop()[0]
            elif active and command == "define":
                macro = re.match(
                    r"([A-Za-z_]\w*)(\(([^)]*)\))?\s*(.*)$", argument
                )
                if macro is not None:
                    parameters = None if macro.group(2) is None else tuple(
                        item.strip() for item in macro.group(3).split(",")
                    )
                    definitions[macro.group(1)] = (parameters, macro.group(4))
            elif active and command == "undef":
                name = re.match(r"([A-Za-z_]\w*)", argument)
                if name is not None:
                    definitions.pop(name.group(1), None)
            continue
        if active:
            pending.append(line)
    flush()
    code = "\n".join(output)
    return re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", code
    )


def closing_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError("unterminated success admission guard")


def source_function_spans(source: str) -> list[tuple[int, int, str]]:
    spans = []
    seen_openings = set()
    functions = (
        re.compile(
            r"(?m)^(?:[A-Za-z_]\w*[ \t*]+)+"
            r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
        ),
        re.compile(
            r"(?m)^[A-Za-z_]\w*(?:[ \t*]+[A-Za-z_]\w*)*[ \t*]*\n"
            r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
        ),
        re.compile(
            r"(?m)^(?:[A-Za-z_]\w*[ \t*]+)+"
            r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\n"
            r"(?:[ \t]+[^;{}\n]+;[ \t]*\n)+\s*\{"
        ),
        re.compile(
            r"(?m)^[A-Za-z_]\w*(?:[ \t*]+[A-Za-z_]\w*)*[ \t*]*\n"
            r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\n"
            r"(?:[ \t]+[^;{}\n]+;[ \t]*\n)+\s*\{"
        ),
    )
    for function in functions:
        for match in function.finditer(source):
            if match.group("name") in {"if", "for", "while", "switch"}:
                continue
            opening = source.index("{", match.start(), match.end())
            if opening in seen_openings:
                continue
            seen_openings.add(opening)
            spans.append((
                match.start(), closing_brace(source, opening) + 1,
                match.group("name"),
            ))
    spans.sort()
    return spans


def token_function_inventory(
    source: str, token: re.Pattern[str],
) -> tuple[dict[str, int], int]:
    spans = source_function_spans(source)
    counts: dict[str, int] = {}
    outside = 0
    for occurrence in token.finditer(source):
        owner = next((name for start, end, name in spans
                      if start <= occurrence.start() < end), None)
        if owner is None:
            outside += 1
        else:
            counts[owner] = counts.get(owner, 0) + 1
    return counts, outside


def raw_member_function_inventory(source: str) -> tuple[dict[str, int], int]:
    return token_function_inventory(
        source, re.compile(r"(?:->|\.)\s*(?:conn|db|connection)\b")
    )


def duckdb_call_function_inventory(source: str) -> tuple[dict[str, int], int]:
    return token_function_inventory(
        source,
        re.compile(r"\bduckdb_[A-Za-z_]\w*\s*(?:\)\s*)*\("),
    )


def normalize_function_designator(expression: str) -> str | None:
    value = expression.strip()
    previous = None
    while value and value != previous:
        previous = value
        if value.startswith("("):
            closing = matching_delimiter(value, 0, "(", ")")
            if closing == len(value) - 1:
                value = value[1:-1].strip()
                continue
            remainder = value[closing + 1:].strip()
            if remainder:
                value = remainder
                continue
        if value[0] in {"&", "*"}:
            value = value[1:].strip()
    return value if re.fullmatch(r"[A-Za-z_]\w*", value) else None


def transitive_raw_helpers(
    files: dict[str, str], session_owner_keys: set[tuple[str, str]],
    duckdb_function_names: set[str],
) -> tuple[
    set[tuple[str, str]], dict[tuple[str, str], set[str]]
]:
    bodies: dict[tuple[str, str], list[str]] = {}
    translation_units: list[
        tuple[str, str, str, list[tuple[int, int, str]]]
    ] = []
    aliases: dict[tuple[str, str], tuple[str, str]] = {}
    static_functions: set[tuple[str, str]] = set()
    direct: set[tuple[str, str]] = set()
    raw_member = re.compile(r"(?:->|\.)\s*(?:conn|db|connection)\b")
    duckdb_api = re.compile(
        r"\b(?:" + "|".join(
            map(re.escape, sorted(duckdb_function_names))
        ) + r")\b"
    )
    pointer_alias = re.compile(
        r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\([^;=]*\)\s*="
        r"\s*([^;]+)\s*;"
    )
    simple_alias = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*([^;]+)\s*;"
    )
    array_alias = re.compile(
        r"\b([A-Za-z_]\w*)\s*\[[^\]]*\][^;=]*=\s*\{\s*"
        r"([^,}\n]+)"
    )
    for path in ROLE_OWNERS:
        for profile in source_inventory_profiles(files, path):
            source = inventory_code_for_profile(
                files, path, profile, include_code=True
            )
            spans = source_function_spans(source)
            translation_units.append((path, path, source, spans))
            for start, end, name in spans:
                body = source[start:end]
                node = (path, name)
                bodies.setdefault(node, []).append(body)
                opening = body.find("{")
                if opening >= 0 and re.search(
                    r"\bstatic\b", body[:opening]
                ) is not None:
                    static_functions.add(node)
                if raw_member.search(body) or duckdb_api.search(body):
                    direct.add(node)
            for pattern in (pointer_alias, simple_alias, array_alias):
                for match in pattern.finditer(source):
                    alias, expression = match.groups()
                    target = normalize_function_designator(expression)
                    if target is None:
                        continue
                    owner = next((
                        name for start, end, name in spans
                        if start <= match.start() < end
                    ), None)
                    if owner is None:
                        aliases[(path, alias)] = (path, target)
    raw = direct - session_owner_keys

    def resolves_to_raw(
        root: str, name: str,
        seen: frozenset[tuple[str, str]] = frozenset(),
    ) -> bool:
        resolution = (root, name)
        if resolution in seen:
            return False
        local = (root, name)
        if local in bodies:
            return local in raw
        if local in aliases:
            target_root, target_name = aliases[local]
            return local in raw or resolves_to_raw(
                target_root, target_name, seen | {resolution}
            )
        return any(
            raw_node in bodies and raw_node not in static_functions
            for raw_node in raw if raw_node[1] == name
        )

    changed = True
    while changed:
        changed = False
        for alias, target in aliases.items():
            if resolves_to_raw(target[0], target[1]) and alias not in raw:
                raw.add(alias)
                changed = True
        for node, variants in bodies.items():
            if node in raw or node in session_owner_keys:
                continue
            raw_names = {
                name for _path, name in raw
                if resolves_to_raw(node[0], name)
            }
            references_raw = any(
                first_raw_helper_position(body, raw_names) >= 0
                for body in variants
            )
            if references_raw:
                raw.add(node)
                changed = True
    for root, path, source, spans in translation_units:
        outside = []
        offset = 0
        for start, end, _name in spans:
            outside.append(source[offset:start])
            offset = end
        outside.append(source[offset:])
        file_scope = "\n".join(outside)
        file_scope_targets = {
            name for owner, name in raw if owner == root
        } | duckdb_function_names
        file_scope_reference = raw_helper_pattern(file_scope_targets)
        for reference in file_scope_reference.finditer(file_scope):
            statement_start = file_scope.rfind(";", 0, reference.start()) + 1
            if "=" in file_scope[statement_start:reference.start()]:
                raise AssertionError(
                    f"raw authority entered file-scope alias: "
                    f"{path}: {reference.group(0)}"
                )
    resolved_by_function = {
        node: {
            name for _owner, name in raw if resolves_to_raw(root, name)
        }
        for node in bodies for root in (node[0],)
    }
    return raw, resolved_by_function


def raw_helper_pattern(names: set[str]) -> re.Pattern[str]:
    if not names:
        return re.compile(r"(?!x)x")
    return re.compile(
        r"\b(?:" + "|".join(map(re.escape, sorted(names))) + r")\b"
    )


@functools.lru_cache(maxsize=1024)
def matching_delimiter(
    source: str, opening: int, left: str, right: str,
) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated delimiter: {left}{right}")


def c_statement_end(source: str, start: int) -> int:
    offset = start
    while offset < len(source) and source[offset].isspace():
        offset += 1
    if offset >= len(source):
        return offset
    if source[offset] == "{":
        return closing_brace(source, offset) + 1
    case_label = re.match(r"case\b", source[offset:])
    if case_label is not None:
        parentheses = brackets = ternaries = 0
        for index in range(offset + case_label.end(), len(source)):
            character = source[index]
            if character == "(":
                parentheses += 1
            elif character == ")":
                parentheses -= 1
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets -= 1
            elif character == "?" and not (parentheses or brackets):
                ternaries += 1
            elif character == ":" and not (parentheses or brackets):
                if ternaries:
                    ternaries -= 1
                else:
                    return c_statement_end(source, index + 1)
        return len(source)
    label = re.match(r"[A-Za-z_]\w*\s*:(?!:)", source[offset:])
    if label is not None:
        return c_statement_end(source, offset + label.end())
    control = re.match(r"(?:if|for|while|switch)\b", source[offset:])
    if control is not None:
        opening = source.find("(", offset + control.end())
        closing = matching_delimiter(source, opening, "(", ")")
        body_end = c_statement_end(source, closing + 1)
        if control.group(0) == "if":
            tail = body_end
            while tail < len(source) and source[tail].isspace():
                tail += 1
            otherwise = re.match(r"else\b", source[tail:])
            if otherwise is not None:
                return c_statement_end(source, tail + otherwise.end())
        return body_end
    do_loop = re.match(r"do\b", source[offset:])
    if do_loop is not None:
        body_end = c_statement_end(source, offset + do_loop.end())
        while body_end < len(source) and source[body_end].isspace():
            body_end += 1
        trailer = re.match(r"while\s*\(", source[body_end:])
        if trailer is not None:
            opening = source.find("(", body_end)
            closing = matching_delimiter(source, opening, "(", ")")
            semicolon = source.find(";", closing + 1)
            return len(source) if semicolon < 0 else semicolon + 1
    parentheses = brackets = braces = 0
    for index in range(offset, len(source)):
        character = source[index]
        if character == "(":
            parentheses += 1
        elif character == ")":
            parentheses -= 1
        elif character == "[":
            brackets += 1
        elif character == "]":
            brackets -= 1
        elif character == "{":
            braces += 1
        elif character == "}":
            if braces == 0:
                return index
            braces -= 1
        elif character == ";" and not (parentheses or brackets or braces):
            return index + 1
    return len(source)


@functools.lru_cache(maxsize=1024)
def conditional_statement_ranges(body: str) -> tuple[tuple[int, int], ...]:
    ranges = []
    for control in re.finditer(r"\b(?:if|for|while|switch)\s*\(", body):
        opening = body.find("(", control.start())
        closing = matching_delimiter(body, opening, "(", ")")
        body_start = closing + 1
        while body_start < len(body) and body[body_start].isspace():
            body_start += 1
        ranges.append((body_start, c_statement_end(body, control.start())))
    for control in re.finditer(r"\bdo\b", body):
        body_start = control.end()
        while body_start < len(body) and body[body_start].isspace():
            body_start += 1
        ranges.append((body_start, c_statement_end(body, body_start)))
    return tuple(ranges)


def split_top_level_commas(value: str) -> list[tuple[int, str]]:
    items = []
    start = 0
    parentheses = brackets = braces = 0
    for index, character in enumerate(value):
        if character == "(":
            parentheses += 1
        elif character == ")":
            parentheses -= 1
        elif character == "[":
            brackets += 1
        elif character == "]":
            brackets -= 1
        elif character == "{":
            braces += 1
        elif character == "}":
            braces -= 1
        elif character == "," and not (parentheses or brackets or braces):
            items.append((start, value[start:index]))
            start = index + 1
    items.append((start, value[start:]))
    return items


@functools.lru_cache(maxsize=1024)
def local_alias_scopes(
    body: str,
) -> tuple[tuple[str, str, int, int, int, bool, bool], ...]:
    called_aliases = set(re.findall(
        r"(?:\(\s*)*(?:\*\s*)*([A-Za-z_]\w*)(?:\s*\))*"
        r"(?:\s*(?:\[[^\]]+\]|(?:->|\.)\s*[A-Za-z_]\w*))*"
        r"(?:\s*\))?\s*\(", body
    ))
    for call in re.finditer(r"\)\s*\(", body):
        depth = 0
        opening = -1
        for index in range(call.start(), -1, -1):
            if body[index] == ")":
                depth += 1
            elif body[index] == "(":
                depth -= 1
                if depth == 0:
                    opening = index
                    break
        if opening >= 0 and "?" in body[opening:call.start()]:
            called_aliases.update(re.findall(
                r"\b[A-Za-z_]\w*\b", body[opening + 1:call.start()]
            ))
    declaration_patterns = (
        re.compile(
            r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\([^;=]*\)\s*="
            r"\s*([^;]+)\s*;"
        ),
    )
    scopes: list[tuple[str, str, int, int, int, bool, bool]] = []
    for_headers = []
    for loop in re.finditer(r"\bfor\s*\(", body):
        opening = body.find("(", loop.start())
        closing = matching_delimiter(body, opening, "(", ")")
        for_headers.append((opening, closing, c_statement_end(body, closing + 1)))
    declaration_candidates = []
    for pattern in declaration_patterns:
        for match in pattern.finditer(body):
            declaration_candidates.append((
                match.group(1), match.group(2), match.start(1)
            ))
    initializer_headers = (
        re.compile(
            r"\b(?P<alias>[A-Za-z_]\w*)\s*\[[^\]]*\]"
            r"[^;=]*=\s*(?P<opening>\{)"
        ),
        re.compile(
            r"(?m)(?:^|(?<=[;{}]))\s*"
            r"(?:(?:const|volatile|restrict|static|register|auto)\s+)*"
            r"(?:_Atomic\s*\(\s*[A-Za-z_]\w*\s*\)|[A-Za-z_]\w*)"
            r"(?:\s+(?:const|volatile|restrict))*\s+"
            r"(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<opening>\{)"
        ),
    )
    for pattern in initializer_headers:
        for match in pattern.finditer(body):
            opening = match.start("opening")
            closing = matching_delimiter(body, opening, "{", "}")
            declaration_candidates.append((
                match.group("alias"), body[opening + 1:closing],
                match.start("alias"),
            ))
    generic_declaration = re.compile(
        r"(?m)(?:^|(?<=[;{}]))\s*"
        r"(?:(?:const|volatile|restrict|static|register|auto)\s+)*"
        r"(?P<type>_Atomic\s*\(\s*[A-Za-z_]\w*\s*\)|[A-Za-z_]\w*)"
        r"(?:\s+(?:const|volatile|restrict))*\s+"
        r"(?P<declarators>[^;{}]+);"
    )
    for match in generic_declaration.finditer(body):
        if match.group("type") in {
            "case", "do", "else", "for", "if", "return", "sizeof",
            "switch", "while",
        }:
            continue
        declarators = match.group("declarators")
        items = split_top_level_commas(declarators)
        first_declarator = re.match(
            r"\s*\**\s*[A-Za-z_]\w*(?:\s*=\s*.+)?\s*$", items[0][1]
        )
        if first_declarator is None:
            continue
        for item_at, item in items:
            declarator = re.match(
                r"\s*\**\s*([A-Za-z_]\w*)\s*=\s*(.+)\s*$", item
            )
            if declarator is None:
                continue
            declaration_candidates.append((
                declarator.group(1), declarator.group(2),
                match.start("declarators") + item_at + declarator.start(1),
            ))
    alias_dependencies = list(declaration_candidates)
    alias_dependencies.extend(
        (match.group(1), match.group(2), match.start(1))
        for match in re.finditer(
            r"\b([A-Za-z_]\w*)\s*=\s*(?!=)([^;]+);", body
        )
    )
    while True:
        dependencies = {
            name
            for alias, expression, _position in alias_dependencies
            if alias in called_aliases
            for name in re.findall(r"\b[A-Za-z_]\w*\b", expression)
        }
        if dependencies <= called_aliases:
            break
        called_aliases.update(dependencies)
    declaration_locations = {
        (alias, declaration_at)
        for alias, _expression, declaration_at in declaration_candidates
    }
    declaration_bounds: dict[tuple[str, int], int] = {}
    for alias, _expression, declaration_at in declaration_candidates:
        stack = []
        for index, character in enumerate(body[:declaration_at]):
            if character == "{":
                stack.append(index)
            elif character == "}" and stack:
                stack.pop()
        enclosing_for = [
            header for header in for_headers
            if header[0] < declaration_at < header[1]
        ]
        if enclosing_for:
            scope_end = max(enclosing_for, key=lambda header: header[0])[2]
        else:
            scope_end = closing_brace(body, stack[-1]) \
                if stack else len(body)
        declaration_bounds[alias, declaration_at] = scope_end
    for alias, expression, declaration_at in declaration_candidates:
        if alias not in called_aliases:
            continue
        target = expression.strip()
        scope_end = declaration_bounds[alias, declaration_at]
        scopes.append((
            alias, target, declaration_at, scope_end,
            declaration_at, True, False,
        ))
    conditional_ranges = conditional_statement_ranges(body)
    labels = {
        match.group(1): match.start()
        for match in re.finditer(
            r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*(?!:)", body
        )
    }
    forward_jumps = [
        (jump.start(), labels[target])
        for jump in re.finditer(r"\bgoto\s+([A-Za-z_]\w*)\s*;", body)
        for target in (jump.group(1),)
        if target in labels and jump.start() < labels[target]
    ]
    assignment = re.compile(
        r"(?=(?:\(\s*)*(?P<deref>(?:\*\s*(?:\(\s*)*)*)"
        r"(?P<alias>[A-Za-z_]\w*)(?:\s*[+-]\s*0)?(?:\s*\))*"
        r"(?P<access>(?:\s*(?:\[[^\]]+\]|(?:->|\.)\s*"
        r"[A-Za-z_]\w*))*)"
        r"\s*=\s*(?!=)(?P<expression>[^;]+)\s*;)"
    )
    assignment_matches = list(assignment.finditer(body))

    def assignment_is_conditional(assignment_at: int) -> bool:
        statement_start = max(
            body.rfind(delimiter, 0, assignment_at)
            for delimiter in ";{}"
        ) + 1
        expression_prefix = body[statement_start:assignment_at]
        return any(
            start <= assignment_at < end
            for start, end in conditional_ranges
        ) or any(
            start < assignment_at < end for start, end in forward_jumps
        ) or any(operator in expression_prefix for operator in ("&&", "||", "?"))

    pointer_events: dict[
        str, list[tuple[int, str, bool, int, int]]
    ] = {}
    for match in assignment_matches:
        alias = match.group("alias")
        assignment_at = match.start("alias")
        dereference_depth = match.group("deref").count("*")
        dereference_depth += match.group("access").count("[")
        if (alias, assignment_at) in declaration_locations:
            dereference_depth = 0
        if dereference_depth == 0 and not match.group("access").strip():
            declarations_in_scope = [
                (declaration_at, scope_end)
                for (name, declaration_at), scope_end
                in declaration_bounds.items()
                if name == alias
                and declaration_at <= assignment_at < scope_end
            ]
            if declarations_in_scope:
                owner_start, scope_end = max(declarations_in_scope)
            else:
                owner_start, scope_end = -1, len(body)
            pointer_events.setdefault(alias, []).append((
                assignment_at, match.group("expression"),
                assignment_is_conditional(assignment_at),
                owner_start, scope_end,
            ))

    def pointer_state(
        pointer: str, position: int, seen: frozenset[tuple[str, int]],
    ) -> set[str]:
        declarations_in_scope = [
            declaration_at
            for (name, declaration_at), scope_end in declaration_bounds.items()
            if name == pointer and declaration_at <= position < scope_end
        ]
        owner_start = max(declarations_in_scope, default=-1)
        state: set[str] = set()
        for event_at, expression, conditional, event_owner, scope_end \
                in pointer_events.get(pointer, []):
            if (
                event_owner != owner_start or event_at >= position
                or position >= scope_end
            ):
                continue
            event = pointer, event_at
            if event in seen:
                continue
            targets = set(re.findall(
                r"&\s*(?:\(\s*)*([A-Za-z_]\w*)", expression
            ))
            if "?" in expression:
                for name in set(re.findall(r"\b[A-Za-z_]\w*\b", expression)):
                    targets.update(pointer_state(name, event_at, seen | {event}))
            elif not targets:
                designator = normalize_function_designator(expression)
                if designator is not None:
                    targets = pointer_state(
                        designator, event_at, seen | {event}
                    )
            state = state | targets if conditional else targets
        return state

    def append_assignment(
        alias: str, expression: str, assignment_at: int, partial: bool = False,
    ) -> None:
        target = expression.strip()
        if any(
            scope[0] == alias and scope[2] == assignment_at and scope[5]
            for scope in scopes
        ):
            return
        declarations_in_scope = [
            scope for scope in scopes
            if scope[0] == alias and scope[5]
            and scope[2] <= assignment_at < scope[3]
        ]
        if declarations_in_scope:
            declaration = max(
                declarations_in_scope, key=lambda scope: scope[2]
            )
            owner_start, scope_end = declaration[4], declaration[3]
        else:
            owner_start, scope_end = -1, len(body)
        conditional = partial or assignment_is_conditional(assignment_at)
        scopes.append((
            alias, target, assignment_at, scope_end, owner_start,
            False, conditional,
        ))

    for match in assignment_matches:
        alias = match.group("alias")
        updates = {alias} if alias in called_aliases else set()
        dereference_depth = match.group("deref").count("*")
        dereference_depth += match.group("access").count("[")
        if (alias, match.start("alias")) in declaration_locations:
            dereference_depth = 0
        targets = {alias}
        for _level in range(dereference_depth):
            targets = {
                target
                for pointer in targets
                for target in pointer_state(
                    pointer, match.start("alias"), frozenset()
                )
            }
        updates.update(target for target in targets if target in called_aliases)
        for update in updates:
            append_assignment(
                update, match.group("expression"), match.start("alias"),
                partial=update == alias and bool(match.group("access").strip()),
            )
    return tuple(sorted(set(scopes), key=lambda scope: scope[2]))


def raw_helper_positions(body: str, raw_names: set[str]) -> list[int]:
    scopes = local_alias_scopes(body)

    def expression_is_raw(
        expression: str, position: int,
        seen: frozenset[tuple[str, int]],
    ) -> bool:
        designator = normalize_function_designator(expression)
        names = [designator] if designator is not None else re.findall(
            r"\b[A-Za-z_]\w*\b", expression
        )
        return any(resolves(name, position, seen) for name in names)

    def resolves(
        name: str, position: int,
        seen: frozenset[tuple[str, int]] = frozenset(),
    ) -> bool:
        declarations = [
            scope for scope in scopes
            if scope[0] == name and scope[5]
            and scope[2] <= position < scope[3]
        ]
        owner_start = max(declarations, key=lambda scope: scope[2])[4] \
            if declarations else -1
        candidates = [
            scope for scope in scopes
            if scope[0] == name and scope[4] == owner_start
            and scope[2] <= position < scope[3]
        ]
        state = name in raw_names if not declarations else False
        for alias, target, start, _end, _owner, _declaration, conditional \
                in candidates:
            resolution = alias, start
            target_is_raw = resolution not in seen and expression_is_raw(
                target, start - 1, seen | {resolution}
            )
            state = state or target_is_raw if conditional \
                else target_is_raw
        return state

    pattern = raw_helper_pattern(
        raw_names | {scope[0] for scope in scopes}
    )
    return [
        match.start() for match in pattern.finditer(body)
        if resolves(match.group(0), match.start())
    ]


def first_raw_helper_position(body: str, raw_names: set[str]) -> int:
    positions = raw_helper_positions(body, raw_names)
    return min(positions, default=-1)


def unconditional_preprocessor_code(source: str) -> str:
    output = []
    depth = 0
    for line in preprocessing_lines(source):
        directive = re.match(r"^\s*#\s*([A-Za-z_]\w*)\b", line)
        if directive is not None:
            command = directive.group(1)
            if command in {"if", "ifdef", "ifndef"}:
                depth += 1
            elif command == "endif" and depth > 0:
                depth -= 1
            continue
        if depth == 0:
            output.append(line)
    return "\n".join(output)


def validate_session_profile(
    body: str, signature: str, raw_helper_names: set[str],
    duckdb_api: re.Pattern[str],
) -> None:
    begin = re.search(
        r"(?:wyrelog_error_t\s+)?rc\s*=\s*"
        r"wyl_fact_store_connection_session_begin\s*"
        r"\(\s*store\s*,\s*&\s*(?P<session>[A-Za-z_]\w*)\s*\)\s*;",
        body,
    )
    if begin is None:
        raise AssertionError(f"session owner lost admission: {signature}")
    begin_at = begin.start()
    if not is_top_level_statement(body, begin_at):
        raise AssertionError(
            f"session authority precedes successful admission: {signature}"
        )
    admitted_session = begin.group("session")
    retrieved = set(re.findall(
        r"wyl_fact_store_connection_session_get\s*"
        r"\(\s*&\s*([A-Za-z_]\w*)\s*\)", body
    ))
    if retrieved - {admitted_session}:
        raise AssertionError(
            f"session authority precedes successful admission: {signature}"
        )
    authority_positions = [
        position for position in (
            body.find("wyl_fact_store_connection_session_get"),
            next((match.start() for match in re.finditer(
                r"(?:->|\.)\s*(?:conn|db|connection)\b", body
            )), -1),
        next((match.start() for match in duckdb_api.finditer(body)), -1),
            first_raw_helper_position(body, raw_helper_names),
        ) if position >= 0
    ]
    failure_guard = re.match(
        r"\s*if\s*\(\s*rc\s*!=\s*WYRELOG_E_OK\s*\)\s*"
        r"return\s+rc\s*;", body[begin.end():],
    )
    success_guard = re.match(
        r"\s*(?:duckdb_result\s+\w+\s*=\s*\{\s*0\s*\}\s*;\s*)?"
        r"if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*\{",
        body[begin.end():],
    )
    success_statement = re.match(
        r"\s*if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*(?!\{)[^;]+;",
        body[begin.end():],
    ) if success_guard is None else None
    if failure_guard is None and success_guard is None \
            and success_statement is None:
        raise AssertionError(
            f"session authority precedes successful admission: {signature}"
        )
    if authority_positions:
        authority_at = min(authority_positions)
        if authority_at < begin_at:
            raise AssertionError(
                f"session authority precedes successful admission: {signature}"
            )
        success_open = begin.end() + success_guard.end() - 1 \
            if success_guard is not None else -1
        if success_guard is not None and not (
            success_open < authority_at < closing_brace(body, success_open)
        ):
            raise AssertionError(
                f"session authority precedes successful admission: {signature}"
            )
        if success_statement is not None and not (
            begin.end() + success_statement.start()
            < authority_at < begin.end() + success_statement.end()
        ):
            raise AssertionError(
                f"session authority precedes successful admission: {signature}"
            )
    ends = list(re.finditer(
        r"wyl_fact_store_connection_session_end\s*\(\s*&\s*"
        + re.escape(admitted_session) + r"\s*\)\s*;", body
    ))
    if not ends:
        raise AssertionError(f"session owner lost release: {signature}")
    final_start, final_end = ends[-1].start(), ends[-1].end()
    if not is_top_level_statement(body, final_start, True):
        raise AssertionError(f"session owner lost release: {signature}")
    labels = {
        match.group(1): match.start()
        for match in re.finditer(
            r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*(?!:)", body
        )
    }
    for jump in re.finditer(r"\bgoto\s+([A-Za-z_]\w*)\s*;", body):
        jump_at = jump.start()
        target_at = labels.get(jump.group(1), -1)
        if jump_at < begin_at <= target_at \
                or begin_at <= jump_at < final_end \
                and not jump_at < target_at < final_start \
                or jump_at >= final_end and begin_at <= target_at < final_end:
            raise AssertionError(
                f"session control flow may bypass release: {signature}"
            )
    if re.search(
        r"\bg_return(?:_val)?_if_(?:fail|reached)\b",
        body[begin_at:final_start],
    ):
        raise AssertionError(f"session return bypasses release: {signature}")
    failure_return_end = begin.end() + failure_guard.end() \
        if failure_guard is not None else begin.end()
    end_ranges = [(match.start(), match.end()) for match in ends]
    for returned in re.finditer(r"\breturn\b", body):
        if returned.start() <= failure_return_end or returned.start() >= final_start:
            continue
        preceding_end = next((end for _start, end in reversed(end_ranges)
                              if end <= returned.start()), -1)
        if preceding_end < 0 or body[preceding_end:returned.start()].strip():
            raise AssertionError(f"session return bypasses release: {signature}")
    released = body[final_end:]
    raw_after_release = any(
        position >= final_end
        for position in raw_helper_positions(body, raw_helper_names)
    )
    if "duckdb_" in released or raw_after_release or re.search(
        r"\bconn\b|(?:->|\.)\s*connection\b", released
    ):
        raise AssertionError(
            f"stale DuckDB authority used after session end: {signature}"
        )


def is_top_level_statement(
    source: str, position: int, allow_cleanup_label: bool = False,
) -> bool:
    if source[:position].count("{") - source[:position].count("}") != 1:
        return False
    prefix = source[:position].rstrip()
    controlled = re.search(
        r"(?:\b(?:if|for|while|switch)\s*\([^;{}]*\)|\b(?:else|do))\s*$",
        prefix,
    )
    if controlled is not None:
        return False
    label_matches = list(re.finditer(
        r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*$", prefix
    ))
    label = label_matches[-1] if label_matches else None
    if label is not None and label.end() == len(prefix):
        return allow_cleanup_label and is_top_level_statement(
            source, label.start(), False
        )
    return re.search(r"(?:\bcase\b[^;{}]*|\bdefault\b)\s*:\s*$", prefix) \
        is None


def validate(files: dict[str, str]) -> None:
    role_header = files[ROLE_HEADER]
    config_seam_header = files[CONFIG_SEAM_HEADER]
    seam_header = files["wyrelog/fact/store-test-seams-private.h"]
    store_header = files["wyrelog/fact/store-private.h"]
    store = files["wyrelog/fact/store.c"]
    compound = files["wyrelog/fact/compound.c"]
    replay = files["wyrelog/fact/replay.c"]
    meson = files["tests/meson.build"]

    self_test_at = meson.index("test('fact-store-connection-boundary-self'")
    self_test_block = meson[self_test_at:meson.index("\n\n", self_test_at)]
    if "timeout : 900" not in self_test_block \
            or "is_parallel : false" not in self_test_block:
        raise AssertionError(
            "connection boundary self-test lost its serialized CI budget"
        )

    if '#include "store-duckdb-config-test-seams-private.h"' not in store:
        raise AssertionError("DuckDB configuration seam include was lost")
    if config_seam_header.count("#if defined(WYL_TEST_HANDLE_SEAMS)") != 1:
        raise AssertionError("DuckDB configuration seams escaped their test guard")
    for declaration in (
        "guint duckdb_configured_settings;",
        "gboolean duckdb_read_only;",
    ):
        if declaration not in store:
            raise AssertionError(
                f"DuckDB configuration field was lost: {declaration}"
            )

    for token in OLD_AUTHORITY:
        offenders = [path for path, text in files.items() if token in text]
        if offenders:
            raise AssertionError(f"legacy raw authority remains: {token}: {offenders}")

    macro_escapes = macro_authority_escapes(files)
    if macro_escapes:
        raise AssertionError(
            f"macro-generated raw authority remains: {sorted(macro_escapes)}"
        )

    for path, expected in EXPECTED_RAW_INVENTORY.items():
        text = files[path]
        for profile in source_inventory_profiles(files, path):
            profile_expected = list(expected)
            expected_functions = dict(EXPECTED_RAW_MEMBER_FUNCTIONS[path])
            expected_calls = dict(EXPECTED_DUCKDB_CALL_FUNCTIONS[path])
            for (profile_path, macro), (
                inventory_addition, member_additions, call_additions,
            ) in RAW_PROFILE_ADDITIONS.items():
                if profile_path != path or macro not in profile:
                    continue
                profile_expected = [
                    count + addition for count, addition
                    in zip(profile_expected, inventory_addition)
                ]
                for function, addition in member_additions.items():
                    expected_functions[function] = (
                        expected_functions.get(function, 0) + addition
                    )
                for function, addition in call_additions.items():
                    expected_calls[function] = (
                        expected_calls.get(function, 0) + addition
                    )
            expected_for_profile = tuple(profile_expected)
            lexical_code = inventory_code_for_profile(files, path, profile)
            lexical_code = re.sub(
                r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", lexical_code
            )
            actual = (
                len(re.findall(
                    r"(?:->|\.)\s*(?:conn|db|connection)\b",
                    lexical_code,
                )),
                len(re.findall(
                    r"\bduckdb_[A-Za-z_]\w*\s*(?:\)\s*)*\(",
                    lexical_code,
                )),
                len(re.findall(r"\bduckdb_connection\b", lexical_code)),
                len(re.findall(r"\bduckdb_database\b", lexical_code)),
            )
            profile_label = ", ".join(
                f"{name}={value}" for name, value in sorted(profile.items())
            )
            if actual != expected_for_profile:
                raise AssertionError(
                    f"raw DuckDB authority inventory drifted: {path}: "
                    f"profile={profile_label}: expected={expected_for_profile}, "
                    f"actual={actual}"
                )
            member_functions, outside_functions = raw_member_function_inventory(
                lexical_code
            )
            if outside_functions or member_functions != expected_functions:
                raise AssertionError(
                    f"raw DuckDB authority moved between functions: {path}: "
                    f"profile={profile_label}: expected={expected_functions}, "
                    f"actual={member_functions}, outside={outside_functions}"
                )
            call_functions, outside_calls = duckdb_call_function_inventory(
                lexical_code
            )
            if outside_calls or call_functions != expected_calls:
                raise AssertionError(
                    f"DuckDB calls moved between functions: {path}: "
                    f"profile={profile_label}: expected={expected_calls}, "
                    f"actual={call_functions}, outside={outside_calls}"
                )

    include = '#include "store-connection-private.h"'
    owners = {path for path, text in files.items() if include in text}
    if owners != ROLE_OWNERS:
        raise AssertionError(f"connection role owners drifted: {sorted(owners)}")
    if "#if !defined(WYL_FACT_STORE_CONNECTION_ROLE)" not in role_header:
        raise AssertionError("connection role header lost its inclusion gate")
    if "duckdb_connection" in store_header:
        raise AssertionError("general store-private header exposes DuckDB authority")
    for path in ROLE_OWNERS:
        text = files[path]
        escape_patterns = {
            "static storage": r"\bstatic\s+WylFactStoreConnectionSession\b",
            "global storage":
                r"(?m)^(?:extern\s+)?WylFactStoreConnectionSession\s*\*?\s*\w+\s*(?:=[^;]*)?;",
            "context field":
                r"typedef\s+(?:struct|union)(?:\s+\w+)?\s*\{[^}]*\bWylFactStoreConnectionSession\b",
            "heap allocation":
                r"(?:g_new0?|g_malloc0?)\s*\([^;]*\bWylFactStoreConnectionSession\b",
            "session return":
                r"(?m)^WylFactStoreConnectionSession\s*\*?\s*\w+\s*\(",
            "thread escape": r"\bg_thread_new\s*\(",
        }
        for escape, pattern in escape_patterns.items():
            if re.search(pattern, text):
                raise AssertionError(
                    f"connection session {escape} escaped its scope: {path}"
                )
        session_names = set(re.findall(
            r"WylFactStoreConnectionSession\s+(\w+)\s*=", text
        ))
        pointer_session_names = set(re.findall(
            r"WylFactStoreConnectionSession\s*\*\s*(\w+)", text
        ))
        session_names.update(pointer_session_names)
        allowed_address_calls = {
            "wyl_fact_store_connection_session_begin",
            "wyl_fact_store_connection_session_get",
            "wyl_fact_store_connection_session_end",
            "wyl_fact_store_transaction_begin",
            "execute_forget_intent_unlocked",
            "quarantine_forget_intent_unlocked",
        }
        for name in session_names:
            opaque_type = r"(?:gpointer|void\s*\*|guintptr|uintptr_t)"
            cast_type = (
                r"(?:const\s+)?[A-Za-z_]\w*"
                r"(?:\s+(?:const\s+)?[A-Za-z_]\w*)*\s*\*?"
            )
            any_cast = rf"\(\s*{cast_type}\s*\)\s*"
            generic = (
                rf"\b{opaque_type}\s+\w+\s*=\s*"
                rf"(?:{any_cast})?&?\s*{re.escape(name)}\b"
            )
            if re.search(generic, text):
                raise AssertionError(
                    f"connection session entered generic storage: {path}: {name}"
                )
            session_cast = rf"{any_cast}&?\s*{re.escape(name)}\b"
            if re.search(session_cast, text):
                raise AssertionError(
                    f"connection session cast to opaque storage: {path}: {name}"
                )
            opaque_return = (
                rf"\breturn\s+(?:{any_cast})?"
                rf"&?\s*{re.escape(name)}\s*;"
            )
            if re.search(opaque_return, text):
                raise AssertionError(
                    f"connection session escaped by return: {path}: {name}"
                )
            assignment = re.compile(
                rf"(?<![=!<>])=(?!=)\s*(?:{any_cast})?"
                rf"&?\s*{re.escape(name)}\s*;"
            )
            for assigned in assignment.finditer(text):
                statement = text[max(0, assigned.start() - 80):assigned.end()]
                if "transaction->session = session;" in statement:
                    continue
                raise AssertionError(
                    f"connection session escaped by alias: {path}: {name}"
                )
            address = re.compile(rf"(?<!&)&\s*{re.escape(name)}\b")
            for match in address.finditer(text):
                before = text[:match.start()]
                if re.search(r"=\s*(?:\(\s*gpointer\s*\)\s*)?$", before[-80:]):
                    raise AssertionError(
                        f"connection session address escaped by assignment: {path}: {name}"
                    )
                call_open = before.rfind("(")
                call_prefix = before[max(0, call_open - 128):call_open] \
                    if call_open >= 0 else ""
                caller = re.search(r"([A-Za-z_]\w*)\s*$", call_prefix) \
                    if call_open >= 0 else None
                if caller is None or caller.group(1) not in allowed_address_calls:
                    raise AssertionError(
                        f"connection session address forwarded to helper: {path}: {name}"
                    )
        allowed_pointer_calls = {
            "memset",
            "g_private_set",
            "connection_session_is_current",
            "wyl_fact_store_transaction_begin",
            "complete_forget_intent_unlocked",
            "migrate_forget_intent_state_check_unlocked",
        }
        for name in pointer_session_names:
            bare_argument = re.compile(
                rf"(?<=[(,])\s*{re.escape(name)}\s*(?=[,)])"
            )
            for match in bare_argument.finditer(text):
                depth = 0
                call_open = None
                for index in range(match.start() - 1, -1, -1):
                    if text[index] == ")":
                        depth += 1
                    elif text[index] == "(":
                        if depth == 0:
                            call_open = index
                            break
                        depth -= 1
                call_prefix = text[max(0, call_open - 128):call_open] \
                    if call_open is not None else ""
                caller = re.search(r"([A-Za-z_]\w*)\s*$", call_prefix)
                if caller is None or caller.group(1) not in allowed_pointer_calls:
                    raise AssertionError(
                        f"connection session pointer forwarded to helper: {path}: {name}"
                    )
    expected_calls = {
        "wyrelog/fact/store.c": (14, 4, 16),
        "wyrelog/fact/compound.c": (5, 5, 7),
        "wyrelog/fact/replay.c": (3, 2, 3),
    }
    for path, (begins, gets, ends) in expected_calls.items():
        text = files[path]
        if text.count("wyl_fact_store_connection_session_begin") != begins:
            raise AssertionError(f"connection session begin inventory drifted: {path}")
        if text.count("wyl_fact_store_connection_session_get") != gets:
            raise AssertionError(f"connection session get inventory drifted: {path}")
        if text.count("wyl_fact_store_connection_session_end") != ends:
            raise AssertionError(f"connection session end inventory drifted: {path}")
    session_functions = {
        "wyrelog/fact/store.c": (
            "wyl_fact_store_test_exec_sql",
            "wyl_fact_store_test_query_int64",
            "wyl_fact_store_test_query_text",
            "wyl_fact_store_create_schema",
            "wyl_fact_store_table_exists",
            "wyl_fact_store_ensure_projection",
            "wyl_fact_store_validate_projection",
            "wyl_fact_store_append_batch_delta (wyl_fact_store_t *store",
            "wyl_fact_store_retract_by_batch_id",
            "wyl_fact_store_count_projection_batch_rows",
            "wyl_fact_store_forget (",
            "wyl_fact_store_forget_pending_count",
            "wyl_fact_store_forget_reconcile (wyl_fact_store_t *store",
        ),
        "wyrelog/fact/compound.c": (
            "wyl_fact_compound_create_schema",
            "wyl_fact_compound_ref_exists",
            "wyl_fact_compound_put",
            "wyl_fact_compound_replay",
            "wyl_fact_compound_replay_cached",
        ),
        "wyrelog/fact/replay.c": (
            "list_replay_relations",
            "replay_relation_into_engine",
        ),
    }
    session_owner_keys = {
        (path, match.group(1))
        for path, signatures in session_functions.items()
        for signature in signatures
        if (match := re.search(r"([A-Za-z_]\w*)\s*\(", signature + "("))
        is not None
    }
    duckdb_function_names = {
        match.group(1)
        for path in ROLE_OWNERS
        for match in re.finditer(
            r"\b(duckdb_[A-Za-z_]\w*)\s*(?:\)\s*)*\(",
            inventory_code(files, path),
        )
    } - {"duckdb_type_for_column"}
    duckdb_api = raw_helper_pattern(duckdb_function_names)
    excluded_raw_helpers = {
        "create_hardened_duckdb_config",
        "duckdb_type_for_column",
        "fact_store_duckdb_set_config",
        "open_duckdb_identified",
        "open_duckdb_with_thread_budget",
        "validate_schema_shape",
        "wyl_fact_store_connection_session_begin",
        "wyl_fact_store_connection_session_get",
        "wyl_fact_store_transaction_begin",
        "wyl_fact_store_transaction_finish",
    }
    all_raw_helper_keys, resolved_raw_helpers = transitive_raw_helpers(
        files, session_owner_keys, duckdb_function_names
    )
    raw_helper_keys = {
        key for key in all_raw_helper_keys
        if key[1] not in excluded_raw_helpers
    }
    call = "wyl_fact_store_connection_session_end (&session);"
    for path, signatures in session_functions.items():
        for signature in signatures:
            owner_match = re.search(r"([A-Za-z_]\w*)\s*\(", signature + "(")
            if owner_match is None:
                raise AssertionError(f"session owner name missing: {signature}")
            owner = owner_match.group(1)
            raw_helper_names = resolved_raw_helpers[(path, owner)] \
                - excluded_raw_helpers
            source_body = function_body(files[path], signature)
            unconditional_body = unconditional_preprocessor_code(source_body)
            if re.search(
                r"\bwyl_fact_store_connection_session_begin\s*\(",
                unconditional_body,
            ) is None:
                raise AssertionError(f"session owner lost admission: {signature}")
            if re.search(
                r"\bwyl_fact_store_connection_session_end\s*\(",
                unconditional_body,
            ) is None:
                raise AssertionError(f"session owner lost release: {signature}")
            profile_bodies = expanded_function_profiles(
                files, path, signature, source_body
            )
            for profile_body in profile_bodies:
                validate_session_profile(
                    profile_body, signature, raw_helper_names, duckdb_api
                )
            body = profile_bodies[0]
            begin_statement = re.search(
                r"(?:wyrelog_error_t\s+)?rc\s*=\s*"
                r"wyl_fact_store_connection_session_begin\s*"
                r"\(\s*store\s*,\s*&\s*(?P<session>[A-Za-z_]\w*)\s*\)\s*;",
                body,
            )
            if begin_statement is None:
                raise AssertionError(f"session owner lost admission: {signature}")
            begin_at = begin_statement.start()
            if not is_top_level_statement(body, begin_at):
                raise AssertionError(
                    f"session authority precedes successful admission: {signature}"
                )
            admitted_session = begin_statement.group("session")
            retrieved_sessions = set(re.findall(
                r"wyl_fact_store_connection_session_get\s*"
                r"\(\s*&\s*([A-Za-z_]\w*)\s*\)",
                body,
            ))
            if retrieved_sessions - {admitted_session}:
                raise AssertionError(
                    f"session authority precedes successful admission: {signature}"
                )
            authority_positions = [
                position for position in (
                    body.find("wyl_fact_store_connection_session_get"),
                    next((match.start() for match in re.finditer(
                        r"(?:->|\.)\s*(?:conn|db|connection)\b", body
                    )), -1),
                    next((match.start() for match in duckdb_api.finditer(body)),
                         -1),
                    first_raw_helper_position(body, raw_helper_names),
                ) if position >= 0
            ]
            failure_guard = re.match(
                r"\s*if\s*\(\s*rc\s*!=\s*WYRELOG_E_OK\s*\)\s*"
                r"return\s+rc\s*;",
                body[begin_statement.end():],
            )
            success_guard = re.match(
                r"\s*(?:duckdb_result\s+\w+\s*=\s*\{\s*0\s*\}\s*;\s*)?"
                r"if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*\{",
                body[begin_statement.end():],
            )
            success_statement = re.match(
                r"\s*if\s*\(\s*rc\s*==\s*WYRELOG_E_OK\s*\)\s*"
                r"(?!\{)[^;]+;",
                body[begin_statement.end():],
            ) if success_guard is None else None
            if failure_guard is None and success_guard is None \
                    and success_statement is None:
                raise AssertionError(
                    f"session authority precedes successful admission: {signature}"
                )
            if authority_positions:
                authority_at = min(authority_positions)
                if authority_at < begin_at:
                    raise AssertionError(
                        f"session authority precedes successful admission: "
                        f"{signature}"
                    )
                success_open = begin_statement.end() + success_guard.end() - 1 \
                    if success_guard is not None else -1
                if success_guard is not None and not (
                    success_open < authority_at
                    < closing_brace(body, success_open)
                ):
                    raise AssertionError(
                        f"session authority precedes successful admission: "
                        f"{signature}"
                    )
                if success_statement is not None and not (
                    begin_statement.end() + success_statement.start()
                    < authority_at
                    < begin_statement.end() + success_statement.end()
                ):
                    raise AssertionError(
                        f"session authority precedes successful admission: "
                        f"{signature}"
                    )
            ends_at = []
            offset = 0
            while True:
                found = body.find(call, offset)
                if found < 0:
                    break
                ends_at.append((found, found + len(call)))
                offset = found + len(call)
            if not ends_at:
                raise AssertionError(f"session owner lost release: {signature}")
            if not is_top_level_statement(body, ends_at[-1][0], True):
                raise AssertionError(f"session owner lost release: {signature}")
            labels = {
                match.group(1): match.start()
                for match in re.finditer(
                    r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*(?!:)", body
                )
            }
            for jump in re.finditer(
                r"\bgoto\s+([A-Za-z_]\w*)\s*;", body
            ):
                jump_at = jump.start()
                target_at = labels.get(jump.group(1), -1)
                skips_admission = jump_at < begin_at <= target_at
                bypasses_release = begin_at <= jump_at < ends_at[-1][1] \
                    and not jump_at < target_at < ends_at[-1][0]
                reenters_authority = jump_at >= ends_at[-1][1] \
                    and begin_at <= target_at < ends_at[-1][1]
                if skips_admission or bypasses_release or reenters_authority:
                    raise AssertionError(
                        f"session control flow may bypass release: {signature}"
                    )
            if re.search(
                r"\bg_return(?:_val)?_if_(?:fail|reached)\b",
                body[begin_at:ends_at[-1][0]],
            ):
                raise AssertionError(
                    f"session return bypasses release: {signature}"
                )
            for _start, after in ends_at[:-1]:
                if not body[after:].lstrip().startswith("return "):
                    raise AssertionError(
                        f"non-final session release lacks terminal return: {signature}"
                    )
            failure_return_end = begin_statement.end() + failure_guard.end() \
                if failure_guard is not None else begin_statement.end()
            for returned in re.finditer(r"\breturn\b", body):
                if returned.start() <= failure_return_end \
                        or returned.start() >= ends_at[-1][0]:
                    continue
                preceding_end = next((end for _start, end in reversed(ends_at)
                                      if end <= returned.start()), -1)
                if preceding_end < 0 \
                        or body[preceding_end:returned.start()].strip():
                    raise AssertionError(
                        f"session return bypasses release: {signature}"
                    )
            released = body[ends_at[-1][1]:]
            if "duckdb_" in released or re.search(r"\bconn\b", released):
                raise AssertionError(
                    f"stale DuckDB authority used after session end: {signature}"
                )

    expected_raw_functions = {
        (path, name)
        for path, names in EXPECTED_TRANSITIVE_RAW_WRAPPERS_BY_PATH.items()
        for name in names
    }
    for path, inventory in EXPECTED_RAW_MEMBER_FUNCTIONS.items():
        expected_raw_functions.update((path, name) for name in inventory)
    for path, inventory in EXPECTED_DUCKDB_CALL_FUNCTIONS.items():
        expected_raw_functions.update((path, name) for name in inventory)
    for (path, _macro), (_counts, members, calls) \
            in RAW_PROFILE_ADDITIONS.items():
        expected_raw_functions.update((path, name) for name in members)
        expected_raw_functions.update((path, name) for name in calls)
    unexpected_raw_functions = raw_helper_keys - expected_raw_functions
    if unexpected_raw_functions:
        raise AssertionError(
            "unexpected transitive raw authority functions: "
            f"{sorted(f'{path}:{name}' for path, name in unexpected_raw_functions)}"
        )

    if "#if !defined(WYL_TEST_HANDLE_SEAMS)" not in seam_header:
        raise AssertionError("fact-store seams lost their compile-time gate")
    for symbol in SEAM_SYMBOLS:
        if symbol not in seam_header:
            raise AssertionError(f"fact-store seam declaration missing: {symbol}")
        if store.count(symbol) != 1:
            raise AssertionError(f"fact-store seam definition drifted: {symbol}")
    seam_marker = (
        "#if defined(WYL_TEST_HANDLE_SEAMS)\nvoid\n"
        "wyl_fact_store_test_set_transaction_hook"
    )
    seam_start = store.find(seam_marker)
    if seam_start < 0:
        raise AssertionError("fact-store seam source guard drifted")
    seam_end = store.find("#endif", seam_start)
    if seam_end < 0:
        raise AssertionError("fact-store seam source guard is unterminated")
    seam_region = store[seam_start:seam_end]
    if any(symbol not in seam_region for symbol in SEAM_SYMBOLS):
        raise AssertionError("fact-store seam escaped the test-only source guard")

    begin = function_body(store, "wyl_fact_store_connection_session_begin")
    for token in (
        "g_private_get (&active_connection_session)",
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "if (!g_mutex_trylock (&store->lock))",
        "store->session_admission_test_hook",
        "g_mutex_lock (&store->lock);",
        "store->health == WYL_FACT_STORE_POISONED",
        "g_mutex_unlock (&store->lock);",
        "return WYRELOG_E_INTERNAL;",
    ):
        if token not in begin:
            raise AssertionError(f"checked session acquisition drifted: {token}")
    test_lock = begin.index("if (!g_mutex_trylock (&store->lock))")
    admission = begin.index("store->session_admission_test_hook", test_lock)
    blocking_lock = begin.index("g_mutex_lock (&store->lock);", admission)
    production_lock = begin.index("#else\n  g_mutex_lock (&store->lock);")
    if not (
        begin.index("g_private_get (&active_connection_session)")
        < begin.index("if (active != NULL)\n    return WYRELOG_E_INTERNAL;")
        < test_lock
        < admission
        < blocking_lock
        < production_lock
        < begin.index("store->health == WYL_FACT_STORE_POISONED")
        < begin.index("session->connection = store->conn;")
    ):
        raise AssertionError("session acquisition no longer checks health under lock")
    connection_bind = begin.index("session->connection = store->conn;")
    admission_prefix = begin[:connection_bind]
    if re.search(r"\bduckdb_\w+\s*\(", admission_prefix) \
            or re.search(
                r"\b(?:store|session)->(?:conn|db|connection)\b",
                admission_prefix,
            ):
        raise AssertionError("DuckDB access occurs before TLS and health admission")
    prefix_calls = set(re.findall(
        r"\b([A-Za-z_]\w*)\s*\(", admission_prefix
    ))
    allowed_prefix_calls = {
        "wyl_fact_store_connection_session_begin",
        "if",
        "sizeof",
        "defined",
        "memset",
        "g_private_get",
        "g_mutex_trylock",
        "session_admission_test_hook",
        "g_mutex_lock",
        "g_mutex_unlock",
    }
    if prefix_calls != allowed_prefix_calls:
        raise AssertionError(
            "session admission prefix call inventory drifted: "
            f"{sorted(prefix_calls ^ allowed_prefix_calls)}"
        )
    for token in (
        "store->session_owner != NULL",
        "session->owner = g_thread_self ();",
        "store->session_owner = session->owner;",
        "g_private_set (&active_connection_session, session);",
    ):
        if token not in begin:
            raise AssertionError(f"session ownership/reentry fence drifted: {token}")
    current = function_body(store, "connection_session_is_current")
    for token in (
        "session->owner == g_thread_self ()",
        "session->store->session_owner == session->owner",
        "g_private_get (&active_connection_session) == session",
    ):
        if token not in current:
            raise AssertionError(f"current-session ownership check drifted: {token}")
    session_get = function_body(
        store, "wyl_fact_store_connection_session_get"
    )
    if "connection_session_is_current (session)" not in session_get:
        raise AssertionError("session get bypasses current-session validation")
    end_session = function_body(store, "wyl_fact_store_connection_session_end")
    for token in (
        "connection_session_is_current (session)",
        "store->session_owner = NULL;",
        "g_private_set (&active_connection_session, NULL);",
        "g_mutex_unlock (&store->lock);",
    ):
        if token not in end_session:
            raise AssertionError(f"session ownership cleanup drifted: {token}")

    transaction_begin = function_body(store, "wyl_fact_store_transaction_begin")
    if "connection_session_is_current (session)" not in transaction_begin:
        raise AssertionError("transaction begin bypasses current-session validation")

    finish = function_body(store, "wyl_fact_store_transaction_finish")
    for token in (
        "connection_session_is_current (transaction->session)",
        "WYL_FACT_STORE_TRANSACTION_BEFORE_COMMIT",
        "WYL_FACT_STORE_TRANSACTION_BEFORE_ROLLBACK",
        'exec_sql (connection, "COMMIT;")',
        'exec_sql (connection, "ROLLBACK;")',
        "store->health = WYL_FACT_STORE_POISONED;",
        '"fact store transaction rollback failed"',
        '"fact forget transaction rollback failed"',
        "return WYRELOG_E_INTERNAL;",
        "return primary_rc;",
    ):
        if token not in finish:
            raise AssertionError(f"common transaction cleanup drifted: {token}")
    if finish.index("store->health = WYL_FACT_STORE_POISONED;") > finish.index(
        "return WYRELOG_E_INTERNAL;"
    ):
        raise AssertionError("rollback failure returns before poisoning the store")

    kind_owners = {
        "wyl_fact_store_append_batch_delta (wyl_fact_store_t *store":
            "WYL_FACT_STORE_TRANSACTION_APPEND_CORE",
        "wyl_fact_store_retract_by_batch_id":
            "WYL_FACT_STORE_TRANSACTION_RETRACT_BY_BATCH",
        "complete_forget_intent_unlocked":
            "WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE",
        "migrate_forget_intent_state_check_unlocked":
            "WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION",
    }
    for signature, kind in kind_owners.items():
        if kind not in function_body(store, signature):
            raise AssertionError(f"transaction owner kind drifted: {signature}")

    forget_complete = function_body(store, "complete_forget_intent_unlocked")
    forget_begin_at = forget_complete.index(
        "wyl_fact_store_transaction_begin (session,"
    )
    rename_at = forget_complete.index(
        "rc = rename_metadata_value_column_once_unlocked (store);"
    )
    finish_at = forget_complete.rindex("finish:")
    if not forget_begin_at < rename_at < finish_at:
        raise AssertionError(
            "forget rename seam escaped its admitted transaction"
        )
    rename_cleanup = re.compile(
        r"rc\s*=\s*rename_metadata_value_column_once_unlocked\s*"
        r"\(\s*store\s*\)\s*;\s*"
        r"if\s*\(\s*rc\s*!=\s*WYRELOG_E_OK\s*\)\s*"
        r"goto\s+finish\s*;"
    )
    if rename_cleanup.search(forget_complete, rename_at, finish_at) is None:
        raise AssertionError(
            "forget rename seam bypasses common transaction cleanup"
        )
    if "WYL_FACT_STORE_TRANSACTION_COMPOUND_PUT" not in function_body(
        compound, "wyl_fact_compound_put"
    ):
        raise AssertionError("compound transaction owner kind drifted")

    migration = function_body(
        store, "migrate_forget_intent_state_check_unlocked"
    )
    if re.search(r"(?m)^[ \t]*#", migration):
        raise AssertionError("forget migration must remain unconditional source")
    production_macro_sources = "\n".join(
        source for path, source in files.items()
        if path.startswith("wyrelog/")
        and Path(path).suffix in {".c", ".h", ".cc", ".cpp"}
    )
    production_macro_sources = production_macro_sources.replace(
        "??/", "\\"
    ).replace("??=", "#")
    production_macro_sources = re.sub(
        r"\\\r?\n", "", production_macro_sources
    )
    production_macro_sources = re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n") or " ",
        production_macro_sources,
        flags=re.DOTALL,
    )
    production_macro_sources = re.sub(
        r"//[^\r\n]*", "", production_macro_sources
    ).replace("%:", "#")
    repository_macros = set(re.findall(
        r"(?m)^[^\S\r\n]*#[^\S\r\n]*define[^\S\r\n]+([A-Za-z_]\w*)\b",
        production_macro_sources,
    ))
    migration_code = migration.replace("??/", "\\").replace("??=", "#")
    migration_code = re.sub(r"\\\r?\n", "", migration_code)
    migration_code = re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        " ",
        migration,
        flags=re.DOTALL,
    )
    used_repository_macros = set(
        re.findall(r"\b[A-Za-z_]\w*\b", migration_code)
    ) & repository_macros
    unexpected_macros = used_repository_macros
    if unexpected_macros:
        raise AssertionError(
            "forget migration uses unaudited repository macro: "
            + ", ".join(sorted(unexpected_macros))
        )
    if "fact_forget_intent_rebuild_sql" not in migration:
        raise AssertionError(
            "forget migration must use the audited rebuild SQL constant"
        )
    macro_definitions = list(re.finditer(
        r"(?m)^[^\S\r\n]*#[^\S\r\n]*define[^\S\r\n]+"
        r"FACT_FORGET_INTENT_COLUMNS\b.*$",
        production_macro_sources,
    ))
    if len(macro_definitions) != 1 or re.search(
        r"(?m)^[^\S\r\n]*#[^\S\r\n]*undef[^\S\r\n]+"
        r"FACT_FORGET_INTENT_COLUMNS\b",
        production_macro_sources,
    ):
        raise AssertionError(
            "forget intent columns macro must have one active definition"
        )
    macro_lines = production_macro_sources[
        macro_definitions[0].start():
    ].splitlines()
    logical_definition = []
    for line in macro_lines:
        logical_definition.append(line)
        if not line.rstrip().endswith("\\"):
            break
    replacement = re.sub(
        r"^[ \t]*#[ \t]*define[ \t]+FACT_FORGET_INTENT_COLUMNS\b",
        "",
        "\n".join(logical_definition),
        count=1,
    )
    replacement = re.sub(r"\\[ \t]*\n", "\n", replacement)
    replacement = re.sub(r'"(?:\\.|[^"\\])*"', "", replacement)
    if replacement.strip():
        raise AssertionError(
            "forget intent columns macro must contain only string literals"
        )
    if re.search(
        r"(?m)^(?:static[ \t]+)?WylFactStoreTransaction\b",
        production_macro_sources,
    ):
        raise AssertionError("fact store transaction owner must not have file scope")
    for token in (
        "wyl_fact_store_transaction_begin (session,",
        "WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION",
        "finish:\n  return wyl_fact_store_transaction_finish "
        "(&transaction, rc);",
    ):
        if token not in migration:
            raise AssertionError(f"forget migration cleanup drifted: {token}")
    begin_guard = (
        "wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION, "
        "&transaction);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;"
    )
    owner_sites = (
        "WylFactStoreTransaction transaction = { 0 };",
        "rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION, "
        "&transaction);",
        "return wyl_fact_store_transaction_finish (&transaction, rc);",
    )
    owner_remainder = migration
    for site in owner_sites:
        if owner_remainder.count(site) != 1:
            raise AssertionError("forget migration transaction owner site drifted")
        owner_remainder = owner_remainder.replace(site, "", 1)
    if re.search(r"\btransaction\b", owner_remainder):
        raise AssertionError(
            "forget migration references transaction outside owner calls"
        )
    admitted_at = migration.index(begin_guard) + len(begin_guard)
    finish_at = migration.index("finish:", admitted_at)
    post_admission = migration[admitted_at:finish_at]
    body_failure_edge = (
        "if (rc != WYRELOG_E_OK)\n"
        "    goto finish;"
    )
    if post_admission.count(body_failure_edge) != 1:
        raise AssertionError(
            "forget migration body-failure cleanup edge drifted"
        )
    if re.search(r"\breturn\b", post_admission):
        raise AssertionError(
            "forget migration bypasses common transaction cleanup"
        )
    if re.search(r"\btransaction\b", post_admission):
        raise AssertionError(
            "forget migration mutates transaction ownership after admission"
        )
    for target in re.findall(r"\bgoto\s+([A-Za-z_]\w*)\s*;", post_admission):
        if target != "finish":
            raise AssertionError(
                f"forget migration escaped common cleanup: goto {target}"
            )
    terminal_cleanup = (
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "}"
    )
    if not migration.rstrip().endswith(terminal_cleanup):
        raise AssertionError("forget migration cleanup is not the terminal exit")
    for escaped in ('"BEGIN TRANSACTION;"', '"COMMIT;"', '"ROLLBACK;"'):
        if escaped in migration:
            raise AssertionError(
                f"forget migration escaped common cleanup: {escaped}"
            )
    migration_body = (
        "rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  if (rc == WYRELOG_E_OK)\n"
        "    rc = exec_sql (store->conn,\n"
        '            "SELECT CASE WHEN ("\n'
        '            "  (SELECT COUNT(*) FROM ("\n'
        '            "     SELECT * FROM fact_forget_intent"\n'
        '            "     EXCEPT SELECT * FROM fact_forget_intent_rebuild)) = 0"\n'
        '            "  AND (SELECT COUNT(*) FROM ("\n'
        '            "     SELECT * FROM fact_forget_intent_rebuild"\n'
        '            "     EXCEPT SELECT * FROM fact_forget_intent)) = 0"\n'
        '            ") THEN 1 ELSE error(\'forget intent rebuild lost rows\') END;");\n'
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"\n'
        '          "ALTER TABLE fact_forget_intent_rebuild "\n'
        '          "  RENAME TO fact_forget_intent;");'
    )
    if post_admission.strip() != migration_body:
        raise AssertionError("forget migration body sequence drifted")
    reconcile = function_body(
        store, "wyrelog_error_t\nwyl_fact_store_forget_reconcile ("
    )
    quarantine_stop = (
        "if (quarantine_rc != WYRELOG_E_OK) {\n"
        "        rc = quarantine_rc;\n"
        "        broke = TRUE;\n"
        "      }"
    )
    if "quarantine_rc = quarantine_forget_intent_unlocked (store," \
            not in reconcile or quarantine_stop not in reconcile:
        raise AssertionError("forget quarantine failure propagation drifted")

    poison_runtime = files["tests/test-fact-store-poison.c"]
    runtime_tokens = (
        "test_waiter_and_poisoned_matrix",
        "wyl_fact_store_test_try_lock",
        "g_assert_false(wyl_fact_store_test_try_lock(store));",
        "test_retract_owner_poison",
        "test_append_backed_retract_owner_poison",
        "test_compound_owner_poison",
        "test_same_thread_reentry_fails_closed",
        "test_cross_store_reentry_fails_closed",
        "test_file_reopen_recovers_forget",
        "test_migration_commit_failure_rolls_back",
        "test_migration_rollback_failure_poison_reopen",
        "fail_commit_rollback_succeeds",
        "failed), ==, WYRELOG_E_IO",
        "wyl_fact_store_test_duckdb_call_count",
        "wyl_fact_store_forget_reconcile",
        "WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE",
        "WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH",
        "WYL_FACT_STORE_TRANSACTION_TEST_COMPOUND_PUT",
        "WYL_FACT_STORE_TRANSACTION_TEST_FORGET_COMPLETE",
        "WYL_FACT_STORE_TRANSACTION_TEST_FORGET_STATE_MIGRATION",
        "wyl_fact_store_test_set_session_admission_hook",
        "while (!gate.entered)",
        "probe.nested_rc, ==, WYRELOG_E_INTERNAL",
        "wyl_fact_replay_open_graph_engine_with_store_for_test",
        "g_assert_null(replay_engine);",
        ".decl poison_marker(value: int64)",
        ".decl poison_marker_observed(value: int64)",
        "poison_marker_observed(V) :- poison_marker(V).",
        "g_assert_cmpuint(marker.rows, ==, 1);",
        "g_assert_cmpint(marker.value, ==, 918);",
        "g_hash_table_size(handles), ==, 1",
        "wyl_fact_store_test_duckdb_call_count(store), ==,",
        "duckdb_calls);",
        "WHERE batch_id = 'owner-retract';",
        "WHERE batch_id = 'owner-seed';",
        "SELECT COUNT(*) FROM compound_terms;",
        "WHERE batch_id = 'retract-core-attempt';",
        "WHERE batch_id = 'retract-core-seed';",
        "SELECT COUNT(*) FROM fact_event_log;",
        'store, &schema, "poison-append"',
    )
    for token in runtime_tokens:
        if token not in poison_runtime:
            raise AssertionError(f"poison runtime proof drifted: {token}")

    matrix = function_body(poison_runtime, "assert_poisoned_api_matrix")
    if matrix.count("wyl_engine_insert(") != 1:
        raise AssertionError("poison engine setup/mutation inventory drifted")
    if matrix.count("assert_engine_marker(engine);") != 2:
        raise AssertionError("poison engine before/after proof drifted")
    matrix_api_calls = (
        "wyl_fact_store_create_schema",
        "wyl_fact_store_table_exists",
        "wyl_fact_store_ensure_projection",
        "wyl_fact_store_validate_projection",
        "wyl_fact_store_count_projection_batch_rows",
        "wyl_fact_store_append_batch_delta",
        "wyl_fact_store_retract_batch_delta",
        "wyl_fact_store_retract_by_batch_id",
        "wyl_fact_store_forget(",
        "wyl_fact_store_forget_reconcile",
        "wyl_fact_compound_create_schema",
        "wyl_fact_compound_ref_exists",
        "wyl_fact_compound_put",
        "wyl_fact_compound_replay(",
        "wyl_fact_compound_replay_cached",
        "wyl_fact_replay_open_graph_engine_with_store_for_test",
        "wyl_fact_store_test_exec_sql",
        "wyl_fact_store_test_query_int64",
        "wyl_fact_store_test_query_text",
    )
    for token in matrix_api_calls:
        if matrix.count(token) != 1:
            raise AssertionError(f"poison API matrix inventory drifted: {token}")
    exact_output_counts = {
        "g_assert_false(exists);": 3,
        "g_assert_false(inserted);": 3,
        "assert_zero_delta(&delta);": 2,
        "g_assert_cmpint(row_count, ==, 0);": 2,
        "g_assert_cmpint(handle, ==, 0);": 2,
    }
    for token, count in exact_output_counts.items():
        if matrix.count(token) != count:
            raise AssertionError(f"poison output inventory drifted: {token}")
    for token in (
        "g_assert_null(table);",
        "g_assert_cmpuint(purged, ==, 0);",
        "g_assert_cmpint(compound_ref, ==, 0);",
        "g_assert_cmpuint(g_hash_table_size(handles), ==, 1);",
        "g_assert_true(g_hash_table_lookup(handles, \"sentinel\") == marker);",
        "g_assert_null(replay_engine);",
        "g_assert_cmpint(query_value, ==, 0);",
        "g_assert_null(query_text);",
        "g_assert_cmpuint(wyl_fact_store_test_duckdb_call_count(store), ==,\n"
        "      duckdb_calls);",
    ):
        if matrix.count(token) != 1:
            raise AssertionError(f"poison output proof drifted: {token}")

    waiter_worker = function_body(poison_runtime, "waiter_worker")
    if waiter_worker.count("wyl_fact_store_table_exists") != 1:
        raise AssertionError("contention waiter no longer enters through public API")
    if "wyl_fact_store_test_try_lock" in waiter_worker:
        raise AssertionError("contention waiter bypasses public API admission")
    waiter_test = function_body(
        poison_runtime, "test_waiter_and_poisoned_matrix"
    )
    for token in (
        "while (!fault.rollback_entered)",
        "g_assert_false(wyl_fact_store_test_try_lock(store));",
        "while (!gate.entered)",
        "fault.release_rollback = TRUE;",
        "g_thread_join(g_steal_pointer(&waiter_thread));",
        "g_assert_cmpint(waiter.rc, ==, WYRELOG_E_INTERNAL);",
    ):
        if token not in waiter_test:
            raise AssertionError(f"contention waiter proof drifted: {token}")
    cross_store = function_body(
        poison_runtime, "test_cross_store_reentry_fails_closed"
    )
    for token in (
        ".store = nested_store",
        "wyl_fact_store_test_set_session_admission_hook(",
        "nested_store, count_admission, &admission_calls",
        "wyl_fact_store_forget(store, &schema.schema, &opts, NULL)",
        "g_assert_cmpint(probe.nested_rc, ==, WYRELOG_E_INTERNAL);",
        "g_assert_false(probe.exists);",
        "g_assert_cmpuint(admission_calls, ==, 0);",
        "wyl_fact_store_test_session_admission_count(nested_store), ==,",
        "nested_session_admissions);",
        "wyl_fact_store_test_duckdb_call_count(nested_store), ==,",
        "nested_duckdb_calls);",
    ):
        if token not in cross_store:
            raise AssertionError(f"cross-store reentry proof drifted: {token}")
    persistence_proofs = {
        "test_waiter_and_poisoned_matrix": (
            "SELECT COUNT(*) FROM fact_batches;",
            "SELECT COUNT(*) FROM fact_event_log;",
            'store, &schema, "poison-append"',
        ),
        "assert_owner_poisoned": (
            "WHERE batch_id = 'owner-retract';",
            "WHERE batch_id = 'owner-seed';",
            'store, &schema, "owner-retract"',
            'store, &schema, "owner-seed"',
            "SELECT COUNT(*) FROM compound_terms;",
            "SELECT COUNT(*) FROM compound_args;",
        ),
        "test_append_backed_retract_owner_poison": (
            "WHERE batch_id = 'retract-core-attempt';",
            "WHERE batch_id = 'retract-core-seed';",
            'store, &schema, "retract-core-attempt"',
            'store, &schema, "retract-core-seed"',
        ),
    }
    for signature, tokens in persistence_proofs.items():
        body = function_body(poison_runtime, signature)
        for token in tokens:
            if token not in body:
                raise AssertionError(
                    f"file-reopen persistence proof drifted: {signature}: {token}"
                )

    replay_test_entry = function_body(
        replay, "wyl_fact_replay_open_graph_engine_with_store_for_test"
    )
    if "open_graph_engine_with_store" not in replay_test_entry:
        raise AssertionError("supplied-store replay seam drifted")
    replay_admission = function_body(replay, "open_graph_engine_with_store")
    for token in (
        "wyl_fact_store_connection_session_begin (store,\n          &admission)",
        "wyl_fact_store_connection_session_end (&admission);",
        "list_replay_relations (policy, store, graph_info, &relations)",
    ):
        if token not in replay_admission:
            raise AssertionError(f"supplied-store replay admission drifted: {token}")
    if replay_admission.index(
        "wyl_fact_store_connection_session_end (&admission);"
    ) > replay_admission.index(
        "list_replay_relations (policy, store, graph_info, &relations)"
    ):
        raise AssertionError("supplied-store health check occurs after policy work")
    replay_seam_start = replay.rfind(
        "#if defined(WYL_TEST_HANDLE_SEAMS)", 0,
        replay.index("wyl_fact_replay_open_graph_engine_with_store_for_test"),
    )
    replay_seam_end = replay.index("#endif", replay_seam_start)
    if not (
        replay_seam_start
        < replay.index("wyl_fact_replay_open_graph_engine_with_store_for_test")
        < replay_seam_end
    ):
        raise AssertionError("supplied-store replay seam escaped test guard")

    relation_end = replay.index(
        "wyl_fact_store_connection_session_end (&session);",
        replay.index("list_replay_relations"),
    )
    schema_load = replay.index("load_relation_schema", relation_end)
    if relation_end >= schema_load:
        raise AssertionError("policy schema load occurs while DuckDB is held")
    relation_post = replay[relation_end:schema_load]
    if "duckdb_" in relation_post or " conn" in relation_post:
        raise AssertionError("stale DuckDB authority used after relation unlock")
    row_end = replay.index(
        "wyl_fact_store_connection_session_end (&session);",
        replay.index("replay_relation_into_engine"),
    )
    materialize = replay.index("materialize_owned_cell", row_end)
    if row_end >= materialize:
        raise AssertionError("engine materialization occurs while DuckDB is held")
    replay_rows = function_body(replay, "replay_relation_into_engine")
    released_rows = replay_rows[replay_rows.index(
        "wyl_fact_store_connection_session_end (&session);") + 1:]
    if "duckdb_" in released_rows or " conn" in released_rows:
        raise AssertionError("stale DuckDB authority used after row unlock")
    for start, end in (
        (replay.index("list_replay_relations"), relation_end),
        (replay.index("replay_relation_into_engine"), row_end),
    ):
        region = replay[start:end]
        if "duckdb_destroy_result" not in region:
            raise AssertionError("DuckDB result is not destroyed in its session")
    for token in (
        "key->namespace_id = g_strdup (namespace_id);",
        "key->relation_name = g_strdup (relation_name);",
        "owned->cells[c].text = g_strdup (value);",
    ):
        if token not in replay:
            raise AssertionError(f"replay retained provider-owned text: {token}")
    if "owned->cells[c].text = value;" in replay:
        raise AssertionError("replay borrowed DuckDB text past result destruction")

    seam_targets = (
        "test-fact-store",
        "test-fact-store-poison",
        "test-fact-store-forget-transaction",
        "test-fact-compound",
        "test-fact-replay",
        "test-fact-provisioning-run",
        "test-fact-store-provisioned",
    )
    for name in seam_targets:
        block = target_block(meson, name)
        if "wyrelog_handle_test_seams_dep" not in block:
            raise AssertionError(f"typed seam target lacks companion library: {name}")
        if "wyrelog_dep" in block:
            raise AssertionError(f"typed seam target links production too: {name}")


_MUTATION_BASELINE: dict[str, str] | None = None


def initialize_mutation_worker(files: dict[str, str]) -> None:
    global _MUTATION_BASELINE
    _MUTATION_BASELINE = files


def mutation_delta(
    baseline: dict[str, str], mutation: dict[str, str],
) -> tuple[tuple[str, str | None], ...]:
    return tuple(
        (path, mutation.get(path))
        for path in sorted(baseline.keys() | mutation.keys())
        if baseline.get(path) != mutation.get(path)
    )


def mutation_validation_error(
    delta: tuple[tuple[str, str | None], ...],
) -> str | None:
    if _MUTATION_BASELINE is None:
        return "mutation worker has no baseline"
    files = dict(_MUTATION_BASELINE)
    for path, source in delta:
        if source is None:
            files.pop(path, None)
        else:
            files[path] = source
    try:
        validate(files)
    except AssertionError as error:
        return str(error)
    return None


def source_key(root: PurePath, path: PurePath) -> str:
    return path.relative_to(root).as_posix()


def load(root: Path) -> dict[str, str]:
    paths = {
        ROLE_HEADER,
        CONFIG_SEAM_HEADER,
        "wyrelog/fact/store-test-seams-private.h",
        "wyrelog/fact/store-private.h",
        "wyrelog/fact/store.c",
        "wyrelog/fact/compound.c",
        "wyrelog/fact/replay.c",
        "wyrelog/fact/query.c",
        "tests/meson.build",
    }
    for directory in (root / "wyrelog", root / "tests"):
        for path in directory.rglob("*"):
            if path.suffix in {".c", ".h", ".cc", ".cpp"}:
                paths.add(source_key(root, path))
    return {path: (root / path).read_text(encoding="utf-8") for path in paths}


def self_test(files: dict[str, str]) -> None:
    mutations = []
    critical_mutations = []

    windows_root = PureWindowsPath("C:/wyrelog")
    windows_source = windows_root / "wyrelog/fact/store.c"
    if source_key(windows_root, windows_source) != "wyrelog/fact/store.c":
        raise AssertionError("Windows source keys must use POSIX separators")

    for declaration in (
        "struct BoundaryItem { int member; };\n"
        "struct BoundaryItem boundary_value = {0};\n",
        "struct BoundaryItem { int member; };\n"
        "struct BoundaryItem boundary_value = {.member = 1};\n",
    ):
        control = dict(files)
        control["wyrelog/fact/store.c"] += "\n" + declaration
        validate(control)

    safe_macro_controls = (
        "#if 0\n"
        "#define WYL_SAFE_REDEFINED(object) ((object)->conn)\n"
        "#endif\n"
        "#define WYL_SAFE_REDEFINED(value) (value)\n"
        "static int boundary_safe_value = WYL_SAFE_REDEFINED(0);\n",
        "#define WYL_SAFE_PASTE(left, right) left ## right\n"
        "static int WYL_SAFE_PASTE(boundary_, value) = 0;\n",
        "#define WYL_GET_VALUE(object) ((object)->value)\n"
        "struct BoundaryValue { int value; };\n"
        "static struct BoundaryValue boundary_object = {0};\n"
        "static int boundary_member(void) { "
        "return WYL_GET_VALUE(&boundary_object); }\n",
        "#if (0)\n"
        "#define WYL_PAREN_SAFE(object) ((object)->conn)\n"
        "#else\n"
        "#define WYL_PAREN_SAFE(value) (value)\n"
        "#endif\n"
        "static int boundary_parenthesized = WYL_PAREN_SAFE(0);\n",
        "#define WYL_STRING_ONLY(value) \"->conn\"\n"
        "static const char *boundary_string = WYL_STRING_ONLY(ignored);\n",
        "#define WYL_STRINGIFY(value) #value\n"
        "static const char *boundary_stringified = "
        "WYL_STRINGIFY(store->conn);\n",
        "#define WYL_INNER_STRINGIFY(value) #value\n"
        "#define WYL_OUTER_STRINGIFY(value) WYL_INNER_STRINGIFY(value)\n"
        "static const char *boundary_indirect_stringified = "
        "WYL_OUTER_STRINGIFY(store->conn);\n",
        "static const char *boundary_type_string = \"duckdb_connection\";\n"
        "/* duckdb_database is documented here. */\n",
        "#if 0\n"
        "static gpointer boundary_inactive_raw(wyl_fact_store_t *store) "
        "{ return store->conn; }\n"
        "#endif\n",
        "#if 1\n"
        "static int boundary_active_branch = 1;\n"
        "#else\n"
        "static gpointer boundary_dead_else(wyl_fact_store_t *store) "
        "{ return store->conn; }\n"
        "#endif\n",
    )
    for source in safe_macro_controls:
        control = dict(files)
        control["wyrelog/fact/store.c"] += "\n" + source
        validate(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    replay_marker = "static wyrelog_error_t\nlist_replay_relations"
    safe_collision = (
        "static wyrelog_error_t\n"
        "reject_audit_database_unlocked (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n  return WYRELOG_E_OK;\n}\n\n"
        "static wyrelog_error_t\n"
        "boundary_safe_collision_wrapper (wyl_fact_store_t *store)\n"
        "{\n  return reject_audit_database_unlocked (store);\n}\n\n"
    )
    replay_admission = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, safe_collision + replay_marker, 1
    ).replace(
        replay_admission,
        "  (void) boundary_safe_collision_wrapper (store);\n"
        + replay_admission,
        1,
    )
    validate(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    local_alias_target = (
        "static void\n"
        "boundary_safe_session_alias_target (void)\n"
        "{\n}\n\n"
    )
    local_safe_alias = (
        "  {\n"
        "    void (*wyl_fact_store_close) (void) = "
        "boundary_safe_session_alias_target;\n"
        "    wyl_fact_store_close ();\n"
        "  }\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, local_alias_target + replay_marker, 1
    ).replace(
        replay_admission, local_safe_alias + replay_admission, 1
    )
    validate(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    safe_for_alias = (
        "  for (void (*wyl_fact_store_close) (void) = "
        "boundary_safe_session_alias_target; FALSE;)\n"
        "    wyl_fact_store_close ();\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, local_alias_target + replay_marker, 1
    ).replace(
        replay_admission, safe_for_alias + replay_admission, 1
    )
    validate(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    safe_assignment_target = (
        "static void\n"
        "boundary_safe_assignment_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, safe_assignment_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_assignment_alias) (wyl_fact_store_t *) = "
        "wyl_fact_store_close;\n"
        "  {\n"
        "    boundary_assignment_alias = "
        "boundary_safe_assignment_target;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_assignment_alias (store);\n",
        1,
    )
    validate(control)

    control = dict(files)
    control["tests/test-fact-store.c"] += (
        "\n#if 0\n"
        "#define WYL_UNRELATED_SAFE(object) ((object)->conn)\n"
        "#endif\n"
    )
    control["wyrelog/fact/store.c"] += (
        "\n#define WYL_UNRELATED_SAFE(value) (value)\n"
        "static int boundary_unrelated_value = WYL_UNRELATED_SAFE(0);\n"
    )
    validate(control)

    control = dict(files)
    control["wyrelog/fact/stringify-boundary.h"] = (
        "#define WYL_HEADER_STRINGIFY(value) #value\n"
    )
    control["wyrelog/fact/store.c"] = (
        '#include "stringify-boundary.h"\n'
        + control["wyrelog/fact/store.c"]
        + "\nstatic const char *boundary_header_stringified = "
        "WYL_HEADER_STRINGIFY(store->conn);\n"
    )
    validate(control)

    control = dict(files)
    control["wyrelog/fact/session-stringify-boundary.h"] = (
        "#define WYL_SESSION_STRINGIFY(value) #value\n"
    )
    replay_source = control["wyrelog/fact/replay.c"]
    relation_at = replay_source.index("list_replay_relations")
    session_at = replay_source.index(
        "WylFactStoreConnectionSession session = { 0 };", relation_at
    )
    control["wyrelog/fact/replay.c"] = (
        '#include "session-stringify-boundary.h"\n'
        + replay_source[:session_at]
        + "const char *boundary_text = "
        "WYL_SESSION_STRINGIFY(store->conn);\n  "
        + replay_source[session_at:]
    )
    validate(control)

    control = dict(files)
    control["wyrelog/fact/recursive-stringify-inner.h"] = (
        "#define WYL_RECURSIVE_STRINGIFY(value) #value\n"
    )
    control["wyrelog/fact/recursive-stringify-outer.h"] = (
        '#define WYL_RECURSIVE_HEADER "recursive-stringify-inner.h"\n'
        "#include WYL_RECURSIVE_HEADER\n"
    )
    control["wyrelog/fact/store.c"] = (
        '#include "recursive-stringify-outer.h"\n'
        + control["wyrelog/fact/store.c"]
        + "\nstatic const char *boundary_recursive_stringified = "
        "WYL_RECURSIVE_STRINGIFY(store->conn);\n"
    )
    validate(control)

    control = dict(files)
    control["wyrelog/fact/pragma-once-boundary.h"] = (
        "#pragma once\n"
        "#ifndef WYL_PRAGMA_ONCE_SEEN\n"
        "#define WYL_PRAGMA_ONCE_SEEN 1\n"
        "#define WYL_PRAGMA_ONCE_VALUE(value) (value)\n"
        "#else\n"
        "#define WYL_PRAGMA_ONCE_VALUE(object) ((object)->conn)\n"
        "#endif\n"
    )
    control["wyrelog/fact/store.c"] = (
        '#include "pragma-once-boundary.h"\n'
        '#include "pragma-once-boundary.h"\n'
        + control["wyrelog/fact/store.c"]
        + "\nstatic int boundary_pragma_once = WYL_PRAGMA_ONCE_VALUE(0);\n"
    )
    validate(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    relation_at = replay_source.index("list_replay_relations")
    session_at = replay_source.index(
        "WylFactStoreConnectionSession session = { 0 };", relation_at
    )
    control["wyrelog/fact/replay.c"] = (
        replay_source[:session_at]
        + 'const gchar *boundary_text = "} store->conn";\n  '
        + "(void) boundary_text;\n  " + replay_source[session_at:]
    )
    validate(control)

    control = dict(files)
    control["wyrelog/fact/replay.c"] = control[
        "wyrelog/fact/replay.c"
    ].replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "boundary_cleanup:\n"
        "  wyl_fact_store_connection_session_end (&session);\n",
        1,
    )
    validate(control)

    def require_boundary_rejection(
        label: str, expected: str, mutation: dict[str, str],
    ) -> None:
        critical_mutations.append((label, expected, mutation))

    source = files["wyrelog/fact/store.c"]

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    replay_marker = "static wyrelog_error_t\nlist_replay_relations"
    for label, declarations, call in (
        (
            "copied-alias-retains-raw-authority",
            "  void (*boundary_source) (wyl_fact_store_t *) = "
            "wyl_fact_store_close;\n"
            "  void (*boundary_copy) (wyl_fact_store_t *) = boundary_source;\n",
            "  boundary_copy (store);\n",
        ),
        (
            "partial-array-write-retains-other-element-authority",
            "  void (*boundary_slots[2]) (wyl_fact_store_t *) = "
            "{ wyl_fact_store_close, NULL };\n"
            "  boundary_slots[1] = NULL;\n",
            "  boundary_slots[0] (store);\n",
        ),
    ):
        changed = dict(files)
        store_source = changed["wyrelog/fact/store.c"]
        function_at = store_source.index("\nwyl_fact_store_test_exec_sql (")
        changed["wyrelog/fact/store.c"] = store_source[:function_at] + store_source[
            function_at:
        ].replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            declarations
            + "  wyl_fact_store_connection_session_end (&session);\n" + call,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "stale DuckDB authority used after session end", changed
        )
    changed = dict(files)
    local_alias_shadow = (
        "static void\n"
        "boundary_safe_alias_target (void)\n"
        "{\n}\n\n"
        "static void\n"
        "boundary_unrelated_local_alias (void)\n"
        "{\n"
        "  void (*wyl_fact_store_close) (void) = "
        "boundary_safe_alias_target;\n"
        "  wyl_fact_store_close ();\n"
        "}\n\n"
    )
    replay_admission = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, local_alias_shadow + replay_marker, 1
    ).replace(
        replay_admission,
        "  wyl_fact_store_close (store);\n" + replay_admission,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "function-local-alias-must-not-shadow-cross-function-raw-call",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    expired_alias_wrapper = (
        "static void\n"
        "boundary_expired_alias_target (void)\n"
        "{\n}\n\n"
        "static void\n"
        "boundary_expired_alias_wrapper (wyl_fact_store_t *store)\n"
        "{\n"
        "  {\n"
        "    void (*wyl_fact_store_close) (void) = "
        "boundary_expired_alias_target;\n"
        "    wyl_fact_store_close ();\n"
        "  }\n"
        "  wyl_fact_store_close (store);\n"
        "}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, expired_alias_wrapper + replay_marker, 1
    ).replace(
        replay_admission,
        "  boundary_expired_alias_wrapper (store);\n" + replay_admission,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "block-local-alias-must-expire-before-external-raw-call",
        "session authority precedes successful admission",
        changed,
    )

    for label, loop_body in (
        (
            "braced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "    {\n"
            "      wyl_fact_store_close ();\n"
            "    }\n",
        ),
        (
            "unbraced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "    wyl_fact_store_close ();\n",
        ),
        (
            "labeled-braced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "boundary_for_body:\n"
            "    {\n"
            "      wyl_fact_store_close ();\n"
            "    }\n",
        ),
        (
            "labeled-unbraced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "boundary_for_body:\n"
            "    wyl_fact_store_close ();\n",
        ),
        (
            "case-braced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      case 0:\n"
            "        {\n"
            "          wyl_fact_store_close ();\n"
            "        }\n",
        ),
        (
            "case-unbraced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      case 0:\n"
            "        wyl_fact_store_close ();\n",
        ),
        (
            "default-braced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      default:\n"
            "        {\n"
            "          wyl_fact_store_close ();\n"
            "        }\n",
        ),
        (
            "default-unbraced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      default:\n"
            "        wyl_fact_store_close ();\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        for_alias_wrapper = (
            "static void\n"
            "boundary_safe_for_target (void)\n"
            "{\n}\n\n"
            "static void\n"
            "boundary_for_alias_wrapper (wyl_fact_store_t *store)\n"
            "{\n"
            + loop_body
            + "  wyl_fact_store_close (store);\n"
            "}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, for_alias_wrapper + replay_marker, 1
        ).replace(
            replay_admission,
            "  boundary_for_alias_wrapper (store);\n" + replay_admission,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"for-{label}-local-alias-must-expire-after-loop",
            "session authority precedes successful admission",
            changed,
        )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_close_alias) (wyl_fact_store_t *) = "
        "wyl_fact_store_close;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_close_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "local-raw-alias-called-after-session-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, designator in (
        ("parenthesized", "(wyl_fact_store_close)"),
        ("addressed", "&wyl_fact_store_close"),
        ("dereferenced", "(*wyl_fact_store_close)"),
        ("nested-address-dereference", "*(&wyl_fact_store_close)"),
        (
            "cast",
            "(void (*)(wyl_fact_store_t *)) wyl_fact_store_close",
        ),
        (
            "cast-parenthesized",
            "(void (*)(wyl_fact_store_t *)) (wyl_fact_store_close)",
        ),
    ):
        for operation in ("declaration", "assignment"):
            changed = dict(files)
            if operation == "declaration":
                alias_setup = (
                    "  void (*boundary_designator_alias) "
                    "(wyl_fact_store_t *) = " + designator + ";\n"
                )
            else:
                alias_setup = (
                    "  void (*boundary_designator_alias) "
                    "(wyl_fact_store_t *) = boundary_safe_designator_target;\n"
                    "  boundary_designator_alias = " + designator + ";\n"
                )
            replay_source = changed["wyrelog/fact/replay.c"]
            safe_designator_target = (
                "static void\n"
                "boundary_safe_designator_target (wyl_fact_store_t *store)\n"
                "{\n  (void) store;\n}\n\n"
            )
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                replay_marker, safe_designator_target + replay_marker, 1
            ).replace(
                "  wyl_fact_store_connection_session_end (&session);\n",
                alias_setup
                + "  wyl_fact_store_connection_session_end (&session);\n"
                "  boundary_designator_alias (store);\n",
                1,
            )
            mutations.append(changed)
            require_boundary_rejection(
                f"{label}-raw-alias-{operation}-after-session-release",
                "stale DuckDB authority used after session end",
                changed,
            )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    typedef_shadow_target = (
        "static void\n"
        "boundary_safe_typedef_shadow_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, typedef_shadow_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  typedef void (*BoundaryClose) (wyl_fact_store_t *);\n"
        "  BoundaryClose boundary_typedef_alias = wyl_fact_store_close;\n"
        "  {\n"
        "    BoundaryClose boundary_typedef_alias = "
        "boundary_safe_typedef_shadow_target;\n"
        "    (void) boundary_typedef_alias;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_typedef_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "typedef-alias-inner-shadow-must-preserve-outer-raw-target",
        "stale DuckDB authority used after session end",
        changed,
    )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, typedef_shadow_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  typedef void (*BoundaryQualifiedClose) (wyl_fact_store_t *);\n"
        "  volatile BoundaryQualifiedClose boundary_qualified_alias = "
        "wyl_fact_store_close;\n"
        "  {\n"
        "    volatile BoundaryQualifiedClose boundary_qualified_alias = "
        "boundary_safe_typedef_shadow_target;\n"
        "    (void) boundary_qualified_alias;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_qualified_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "qualified-typedef-inner-shadow-preserves-outer-raw-target",
        "stale DuckDB authority used after session end",
        changed,
    )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, typedef_shadow_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  typedef void (*BoundaryAtomicClose) (wyl_fact_store_t *);\n"
        "  _Atomic(BoundaryAtomicClose) boundary_atomic_alias = "
        "wyl_fact_store_close;\n"
        "  {\n"
        "    _Atomic(BoundaryAtomicClose) boundary_atomic_alias = "
        "boundary_safe_typedef_shadow_target;\n"
        "    (void) boundary_atomic_alias;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_atomic_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "atomic-typedef-inner-shadow-preserves-outer-raw-target",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, declarations in (
        (
            "raw-first",
            "  BoundaryAlias boundary_multi_alias = wyl_fact_store_close,\n"
            "      boundary_multi_safe = boundary_safe_multi_target;\n"
            "  (void) boundary_multi_safe;\n",
        ),
        (
            "raw-last",
            "  BoundaryAlias boundary_multi_safe = "
            "boundary_safe_multi_target,\n"
            "      boundary_multi_alias = wyl_fact_store_close;\n"
            "  (void) boundary_multi_safe;\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_multi_target = (
            "typedef void (*BoundaryAlias) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_multi_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_multi_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            declarations
            + "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_multi_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"multi-declarator-{label}-raw-alias-after-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker,
        "typedef void (*BoundaryArrayAlias) (wyl_fact_store_t *);\n\n"
        + replay_marker,
        1,
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryArrayAlias boundary_aliases[] = "
        "{ wyl_fact_store_close };\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_aliases[0] (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "local-array-raw-alias-called-after-session-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, initializer, invocation in (
        (
            "raw-second",
            "{ boundary_safe_array_target, wyl_fact_store_close }",
            "boundary_aliases[1] (store);",
        ),
        (
            "nested-raw-second",
            "{ { boundary_safe_array_target, wyl_fact_store_close } }",
            "boundary_aliases[0][1] (store);",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        array_support = (
            "typedef void (*BoundaryNestedArrayAlias) "
            "(wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_array_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        dimensions = "[][2]" if label.startswith("nested") else "[]"
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, array_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  BoundaryNestedArrayAlias boundary_aliases"
            + dimensions + " = " + initializer + ";\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  " + invocation + "\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"local-array-{label}-called-after-session-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    dispatch_type = (
        "typedef struct\n"
        "{\n  void (*call) (wyl_fact_store_t *);\n}\n"
        "BoundaryDispatch;\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, dispatch_type + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryDispatch boundary_dispatch = "
        "{ wyl_fact_store_close };\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_dispatch.call (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "local-aggregate-raw-alias-called-after-session-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for kind, support, declaration, lvalue in (
        (
            "indexed",
            "typedef void (*BoundaryAssignedAlias) (wyl_fact_store_t *);\n",
            "BoundaryAssignedAlias boundary_assigned_alias[] = "
            "{ boundary_safe_assigned_target };",
            "boundary_assigned_alias[0]",
        ),
        (
            "member",
            "typedef struct\n"
            "{\n  void (*call) (wyl_fact_store_t *);\n}\n"
            "BoundaryAssignedDispatch;\n",
            "BoundaryAssignedDispatch boundary_assigned_alias = "
            "{ boundary_safe_assigned_target };",
            "boundary_assigned_alias.call",
        ),
    ):
        for flow, prefix in (
            ("unconditional", ""),
            ("conditional", "if (store != NULL)\n    "),
        ):
            changed = dict(files)
            replay_source = changed["wyrelog/fact/replay.c"]
            assignment_support = (
                support
                + "static void\n"
                "boundary_safe_assigned_target (wyl_fact_store_t *store)\n"
                "{\n  (void) store;\n}\n\n"
            )
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                replay_marker, assignment_support + replay_marker, 1
            ).replace(
                "  wyl_fact_store_connection_session_end (&session);\n",
                "  " + declaration + "\n"
                "  " + prefix + lvalue + " = wyl_fact_store_close;\n"
                "  wyl_fact_store_connection_session_end (&session);\n"
                "  " + lvalue + " (store);\n",
                1,
            )
            mutations.append(changed)
            require_boundary_rejection(
                f"{flow}-{kind}-raw-assignment-after-session-release",
                "stale DuckDB authority used after session end",
                changed,
            )

    for label, declaration, lvalue, invocation in (
        (
            "parenthesized",
            "BoundaryLvalueAlias boundary_lvalue_alias = "
            "boundary_safe_lvalue_target;",
            "(boundary_lvalue_alias)",
            "boundary_lvalue_alias (store);",
        ),
        (
            "nested-parenthesized",
            "BoundaryLvalueAlias boundary_lvalue_alias = "
            "boundary_safe_lvalue_target;",
            "((boundary_lvalue_alias))",
            "boundary_lvalue_alias (store);",
        ),
        (
            "parenthesized-indexed",
            "BoundaryLvalueAlias boundary_lvalue_alias[] = "
            "{ boundary_safe_lvalue_target };",
            "(boundary_lvalue_alias)[0]",
            "(boundary_lvalue_alias)[0] (store);",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        lvalue_support = (
            "typedef void (*BoundaryLvalueAlias) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_lvalue_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, lvalue_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  " + declaration + "\n"
            "  " + lvalue + " = wyl_fact_store_close;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  " + invocation + "\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-raw-lvalue-assignment-after-session-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    chain_support = (
        "typedef void (*BoundaryChainAlias) (wyl_fact_store_t *);\n"
        "static void\n"
        "boundary_safe_chain_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, chain_support + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryChainAlias boundary_chain_first = "
        "boundary_safe_chain_target;\n"
        "  BoundaryChainAlias boundary_chain_second = "
        "boundary_safe_chain_target;\n"
        "  boundary_chain_first = boundary_chain_second = "
        "wyl_fact_store_close;\n"
        "  (void) boundary_chain_first;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_chain_second (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "chained-raw-assignment-reaches-second-alias-after-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for flow, prefix, slot_initializer, extra_pointer, lvalue in (
        (
            "direct", "", "&boundary_pointer_alias", "",
            "*boundary_pointer_slot",
        ),
        (
            "conditional", "if (store != NULL)\n    ",
            "&boundary_pointer_alias", "",
            "*boundary_pointer_slot",
        ),
        (
            "indexed", "", "&boundary_pointer_alias", "",
            "boundary_pointer_slot[0]",
        ),
        (
            "parenthesized-dereference", "", "&boundary_pointer_alias", "",
            "*(boundary_pointer_slot)",
        ),
        (
            "zero-offset-dereference", "", "&boundary_pointer_alias", "",
            "*(boundary_pointer_slot + 0)",
        ),
        (
            "ternary-retarget", "", "&boundary_pointer_alias",
            "  BoundaryPointerAlias boundary_pointer_second = "
            "boundary_safe_pointer_target;\n"
            "  boundary_pointer_slot = store == NULL ? "
            "&boundary_pointer_second : boundary_pointer_slot;\n",
            "*boundary_pointer_slot",
        ),
        (
            "short-circuit-retarget", "", "&boundary_pointer_alias",
            "  BoundaryPointerAlias boundary_pointer_second = "
            "boundary_safe_pointer_target;\n"
            "  (store == NULL) && "
            "(boundary_pointer_slot = &boundary_pointer_second);\n",
            "*boundary_pointer_slot",
        ),
        (
            "cast-address", "", "(BoundaryPointerAlias *) "
            "(&boundary_pointer_alias)", "", "*boundary_pointer_slot",
        ),
        (
            "multi-level", "", "&boundary_pointer_alias",
            "  BoundaryPointerAlias **boundary_pointer_outer = "
            "&boundary_pointer_slot;\n",
            "**boundary_pointer_outer",
        ),
        (
            "after-inner-shadow", "", "&boundary_pointer_alias",
            "  {\n"
            "    BoundaryPointerAlias boundary_pointer_inner = "
            "boundary_safe_pointer_target;\n"
            "    BoundaryPointerAlias *boundary_pointer_slot = "
            "&boundary_pointer_inner;\n"
            "    (void) boundary_pointer_slot;\n"
            "  }\n",
            "*boundary_pointer_slot",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        pointer_support = (
            "typedef void (*BoundaryPointerAlias) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_pointer_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        pointer_body = (
            "  BoundaryPointerAlias boundary_pointer_alias = "
            "boundary_safe_pointer_target;\n"
            "  BoundaryPointerAlias *boundary_pointer_slot = "
            f"{slot_initializer};\n"
            f"{extra_pointer}"
            f"  {prefix}{lvalue} = wyl_fact_store_close;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_pointer_alias (store);\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, pointer_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            pointer_body,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{flow}-pointer-write-propagates-to-post-release-alias",
            "stale DuckDB authority used after session end",
            changed,
        )

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    pointer_retarget_support = (
        "typedef void (*BoundaryPointerRetargetAlias) (wyl_fact_store_t *);\n"
        "static void\n"
        "boundary_safe_pointer_retarget (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    pointer_retarget_body = (
        "  BoundaryPointerRetargetAlias boundary_pointer_outer = "
        "boundary_safe_pointer_retarget;\n"
        "  BoundaryPointerRetargetAlias *boundary_pointer_shadow = "
        "&boundary_pointer_outer;\n"
        "  {\n"
        "    BoundaryPointerRetargetAlias boundary_pointer_inner = "
        "boundary_safe_pointer_retarget;\n"
        "    BoundaryPointerRetargetAlias *boundary_pointer_shadow = "
        "&boundary_pointer_inner;\n"
        "    *boundary_pointer_shadow = wyl_fact_store_close;\n"
        "  }\n"
        "  BoundaryPointerRetargetAlias boundary_pointer_first = "
        "boundary_safe_pointer_retarget;\n"
        "  BoundaryPointerRetargetAlias boundary_pointer_second = "
        "boundary_safe_pointer_retarget;\n"
        "  BoundaryPointerRetargetAlias *boundary_pointer_retarget = "
        "&boundary_pointer_first;\n"
        "  boundary_pointer_retarget = &boundary_pointer_second;\n"
        "  *boundary_pointer_retarget = wyl_fact_store_close;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_pointer_outer (store);\n"
        "  boundary_pointer_first (store);\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, pointer_retarget_support + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        pointer_retarget_body,
        1,
    )
    validate(control)

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    pointer_declaration_support = (
        "typedef void (*BoundaryPointerDeclarationAlias) "
        "(wyl_fact_store_t *);\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, pointer_declaration_support + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryPointerDeclarationAlias boundary_pointer_raw = "
        "wyl_fact_store_close;\n"
        "  BoundaryPointerDeclarationAlias *boundary_pointer_declaration = "
        "&boundary_pointer_raw;\n"
        "  (void) boundary_pointer_declaration;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_pointer_raw (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "pointer-declaration-does-not-reset-raw-alias",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, callee in (
        (
            "raw-first",
            "store != NULL ? boundary_conditional_raw : "
            "boundary_conditional_safe",
        ),
        (
            "raw-last",
            "store == NULL ? boundary_conditional_safe : "
            "boundary_conditional_raw",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        callee_support = (
            "typedef void (*BoundaryConditionalCallee) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_conditional_callee (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, callee_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  BoundaryConditionalCallee boundary_conditional_raw = "
            "wyl_fact_store_close;\n"
            "  BoundaryConditionalCallee boundary_conditional_safe = "
            "boundary_safe_conditional_callee;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  (" + callee + ") (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"conditional-callee-{label}-raw-after-session-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    inner_assignment_target = (
        "static void\n"
        "boundary_safe_inner_assignment_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, inner_assignment_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_inner_assignment_alias) (wyl_fact_store_t *) = "
        "boundary_safe_inner_assignment_target;\n"
        "  {\n"
        "    boundary_inner_assignment_alias = wyl_fact_store_close;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_inner_assignment_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "inner-block-raw-assignment-persists-after-block",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, reassignment in (
        (
            "conditional",
            "  if (FALSE)\n"
            "    boundary_conditional_alias = "
            "boundary_safe_conditional_target;\n",
        ),
        (
            "inactive",
            "#if 0\n"
            "  boundary_conditional_alias = "
            "boundary_safe_conditional_target;\n"
            "#endif\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_conditional_target = (
            "static void\n"
            "boundary_safe_conditional_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_conditional_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_conditional_alias) (wyl_fact_store_t *) = "
            "wyl_fact_store_close;\n"
            + reassignment
            + "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_conditional_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-safe-reassignment-must-not-hide-raw-alias",
            "stale DuckDB authority used after session end",
            changed,
        )

    for label, expression in (
        (
            "deterministic-ternary",
            "FALSE ? boundary_safe_expression_target : "
            "wyl_fact_store_close",
        ),
        (
            "runtime-ternary",
            "store == NULL ? boundary_safe_expression_target : "
            "wyl_fact_store_close",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_expression_target = (
            "static void\n"
            "boundary_safe_expression_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_expression_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_expression_alias) (wyl_fact_store_t *) = "
            "boundary_safe_expression_target;\n"
            "  boundary_expression_alias = " + expression + ";\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_expression_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-raw-target-reaches-post-release-alias-call",
            "stale DuckDB authority used after session end",
            changed,
        )

    for label, condition in (
        ("inactive", "FALSE"),
        ("runtime-conditional", "store == NULL"),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_comma_target = (
            "static void\n"
            "boundary_safe_comma_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_comma_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_comma_alias) (wyl_fact_store_t *) = "
            "wyl_fact_store_close;\n"
            "  if (" + condition + ")\n"
            "    (void) 0, boundary_comma_alias = "
            "boundary_safe_comma_target;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_comma_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-comma-safe-assignment-must-not-hide-raw-alias",
            "stale DuckDB authority used after session end",
            changed,
        )

    for label, branches in (
        (
            "unbraced-if-else",
            "  if (TRUE)\n"
            "    boundary_branch_alias = wyl_fact_store_close;\n"
            "  else\n"
            "    boundary_branch_alias = boundary_safe_branch_target;\n",
        ),
        (
            "braced-if-else",
            "  if (TRUE)\n"
            "    { boundary_branch_alias = wyl_fact_store_close; }\n"
            "  else\n"
            "    { boundary_branch_alias = "
            "boundary_safe_branch_target; }\n",
        ),
        (
            "nested-else-if",
            "  if (FALSE)\n"
            "    boundary_branch_alias = boundary_safe_branch_target;\n"
            "  else if (TRUE)\n"
            "    boundary_branch_alias = wyl_fact_store_close;\n"
            "  else\n"
            "    boundary_branch_alias = boundary_safe_branch_target;\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_branch_target = (
            "static void\n"
            "boundary_safe_branch_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_branch_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_branch_alias) (wyl_fact_store_t *) = "
            "boundary_safe_branch_target;\n"
            + branches
            + "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_branch_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-raw-branch-must-reach-post-release-call",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    safe_goto_target = (
        "static void\n"
        "boundary_safe_goto_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, safe_goto_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_goto_alias) (wyl_fact_store_t *) = "
        "wyl_fact_store_close;\n"
        "  goto boundary_goto_release;\n"
        "  boundary_goto_alias = boundary_safe_goto_target;\n"
        "boundary_goto_release:\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_goto_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "forward-goto-skips-safe-alias-assignment",
        "stale DuckDB authority used after session end",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION, &transaction",
        "WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE, &transaction",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-transaction-kind-removed",
        "transaction owner kind drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "}\n\n"
        "/* Retire an intent",
        "finish:\n  return rc;\n}\n\n/* Retire an intent",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-common-finish-bypass",
        "forget migration cleanup drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-body-direct-return",
        "forget migration body-failure cleanup edge drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-body-failure-edge-removed",
        "forget migration body-failure cleanup edge drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  rc = WYRELOG_E_OK;\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-body-result-overwritten",
        "forget migration body sequence drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  if (rc != WYRELOG_E_OK) {\n"
        "    transaction.open = FALSE;\n"
        "    goto finish;\n"
        "  }\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-transaction-disarmed",
        "forget migration references transaction outside owner calls",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  WylFactStoreTransaction transaction = { 0 };\n"
        "  rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION,",
        "  WylFactStoreTransaction transaction = { 0 };\n"
        "  WylFactStoreTransaction *owner_alias = &transaction;\n"
        "  rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION,",
        1,
    ).replace(
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  if (rc == WYRELOG_E_OK)",
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  owner_alias->open = FALSE;\n"
        "  if (rc == WYRELOG_E_OK)",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-owner-alias-disarmed",
        "forget migration references transaction outside owner calls",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "#if 0\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "#endif\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "conditional-migration-body-failure-edge",
        "forget migration must remain unconditional source",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "static wyrelog_error_t\n"
        "migrate_forget_intent_state_check_unlocked (",
        "#define WYL_DISARM_MIGRATION transaction.open = FALSE\n\n"
        "static wyrelog_error_t\n"
        "migrate_forget_intent_state_check_unlocked (",
        1,
    ).replace(
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  if (rc == WYRELOG_E_OK)",
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  WYL_DISARM_MIGRATION;\n"
        "  if (rc == WYRELOG_E_OK)",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "external-macro-migration-disarm",
        "forget migration uses unaudited repository macro",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store-connection-private.h"] = changed[
        "wyrelog/fact/store-connection-private.h"
    ].replace(
        "#pragma once\n",
        "#pragma once\n\n"
        "#define WYL_DISARM_MIGRATION_ON_FAILURE() \\\n"
        "  do { if (rc != WYRELOG_E_OK) transaction.open = FALSE; } while (0)\n",
        1,
    )
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  WYL_DISARM_MIGRATION_ON_FAILURE ();\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "header-macro-migration-disarm",
        "forget migration uses unaudited repository macro",
        changed,
    )

    for directive, label in (
        ("%:define", "digraph"),
        ("#/**/define", "comment-separated"),
        ("#\\\ndefine", "line-spliced"),
        ("#\vdefine", "vertical-tab"),
        ("#\fdefine", "form-feed"),
    ):
        changed = dict(files)
        changed["wyrelog/fact/store-connection-private.h"] = changed[
            "wyrelog/fact/store-connection-private.h"
        ].replace(
            "#pragma once\n",
            "#pragma once\n\n"
            f"{directive} WYL_TRANSLATED_DISARM transaction.open = FALSE\n",
            1,
        )
        changed["wyrelog/fact/store.c"] = source.replace(
            "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
            "  if (rc == WYRELOG_E_OK)",
            "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
            "  WYL_TRANSLATED_DISARM;\n"
            "  if (rc == WYRELOG_E_OK)",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-header-macro-migration-disarm",
            "forget migration uses unaudited repository macro",
            changed,
        )

    changed = dict(files)
    changed["wyrelog/fact/store-connection-private.h"] = changed[
        "wyrelog/fact/store-connection-private.h"
    ].replace(
        "#pragma once\n",
        "#pragma once\n\n"
        "#define WYL_SPLICE_DISARM transaction.open = FALSE\n",
        1,
    )
    changed["wyrelog/fact/store.c"] = source.replace(
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n",
        "  WYL_SPLICE_\\\nDISARM;\n"
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "split-header-macro-migration-disarm",
        "forget migration body sequence drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "#define FACT_FORGET_INTENT_COLUMNS \\\n"
        '  "  op_uuid         VARCHAR PRIMARY KEY,"',
        "#define FACT_FORGET_INTENT_COLUMNS \\\n"
        '  "existing columns"; transaction.open = FALSE; \\\n'
        '  "  op_uuid         VARCHAR PRIMARY KEY,"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "trusted-columns-macro-code-injection",
        "forget intent columns macro must contain only string literals",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "#define FACT_FORGET_INTENT_COLUMNS \\\n",
        "static WylFactStoreTransaction transaction;\n"
        "#define FACT_FORGET_INTENT_COLUMNS \\\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "file-scope-transaction-owner",
        "fact store transaction owner must not have file scope",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "    goto bypass_finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    ).replace(
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "}\n\n"
        "/* Retire an intent",
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "bypass_finish:\n"
        "  return rc;\n"
        "}\n\n"
        "/* Retire an intent",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-goto-bypass",
        "forget migration body-failure cleanup edge drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "        rc = quarantine_rc;\n        broke = TRUE;",
        "        (void) quarantine_rc;\n        broke = TRUE;",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "ignored-quarantine-failure",
        "forget quarantine failure propagation drifted",
        changed,
    )

    for label, replacement in (
        (
            "internal-only-quarantine-failure",
            "if (quarantine_rc == WYRELOG_E_INTERNAL) {",
        ),
        (
            "disabled-quarantine-failure",
            "if (FALSE && quarantine_rc != WYRELOG_E_OK) {",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] = source.replace(
            "if (quarantine_rc != WYRELOG_E_OK) {", replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(
            label,
            "forget quarantine failure propagation drifted",
            changed,
        )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        '#include "store-duckdb-config-test-seams-private.h"\n', "", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "  guint duckdb_configured_settings;\n", "", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store-private.h"] += "\nwyl_fact_store_lock(store);\n"
    mutations.append(changed)

    source = files["wyrelog/fact/store.c"]
    begin_region = (
        "  wyrelog_error_t rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE, &transaction);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
    )
    rename_region = (
        "  rc = rename_metadata_value_column_once_unlocked (store);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
    )
    if begin_region not in source or rename_region not in source:
        raise AssertionError("forget rename seam mutation fixture drifted")

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        rename_region, "", 1
    ).replace(
        begin_region,
        "  wyrelog_error_t rc = WYRELOG_E_OK;\n"
        "#if defined(WYL_TEST_HANDLE_SEAMS)\n"
        + rename_region
        + "#endif\n"
        "  rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE, &transaction);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "rename-before-begin", "escaped its admitted transaction", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        rename_region,
        rename_region.replace("    goto finish;", "    return rc;"),
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "rename-direct-return", "bypasses common transaction cleanup", changed
    )

    for macro_path in ("source", "header"):
        for producer_kind in ("direct", "transitive"):
            changed = dict(files)
            definitions = "#define WYL_MEMBER_ID(value) value\n"
            member_name = "WYL_MEMBER_ID"
            if producer_kind == "transitive":
                definitions += (
                    "#define WYL_MEMBER_BRIDGE(value) "
                    "WYL_MEMBER_ID(value)\n"
                )
                member_name = "WYL_MEMBER_BRIDGE"
            definitions += (
                "#define WYL_LITERAL_OP_RAW(object) "
                f"((object)->{member_name}(conn))\n"
            )
            if macro_path == "source":
                role_source = definitions + changed["wyrelog/fact/store.c"]
            else:
                changed[ROLE_HEADER] += "\n" + definitions
                role_source = changed["wyrelog/fact/store.c"]
            create_at = role_source.index("wyl_fact_store_create_schema (")
            session_at = role_source.index(
                "WylFactStoreConnectionSession session = { 0 };", create_at
            )
            changed["wyrelog/fact/store.c"] = (
                role_source[:session_at]
                + "duckdb_connection leaked = "
                "WYL_LITERAL_OP_RAW (store);\n"
                "  (void) leaked;\n  " + role_source[session_at:]
            )
            mutations.append(changed)

    for macro_path in ("source", "header"):
        for operator in ("->", "."):
            changed = dict(files)
            definitions = (
                "#define WYL_PARAMETER_RAW(object, member) "
                f"((object){operator}member)\n"
            )
            if macro_path == "source":
                role_source = definitions + changed["wyrelog/fact/store.c"]
            else:
                changed[ROLE_HEADER] += "\n" + definitions
                role_source = changed["wyrelog/fact/store.c"]
            create_at = role_source.index("wyl_fact_store_create_schema (")
            session_at = role_source.index(
                "WylFactStoreConnectionSession session = { 0 };", create_at
            )
            changed["wyrelog/fact/store.c"] = (
                role_source[:session_at]
                + "duckdb_connection leaked = "
                "WYL_PARAMETER_RAW (store, conn);\n"
                "  (void) leaked;\n  " + role_source[session_at:]
            )
            mutations.append(changed)

    for directive in (
        "/* leading comment */ #define",
        "#/**/define",
        "%:define",
        "??=define",
    ):
        changed = dict(files)
        definitions = (
            f"{directive} WYL_LEXICAL_RAW(object) ((object)->conn)\n"
        )
        role_source = definitions + changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at]
            + "duckdb_connection leaked = WYL_LEXICAL_RAW (store);\n"
            "  (void) leaked;\n  " + role_source[session_at:]
        )
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = (
        "#define WYL_ARGUMENT_PASTE(left, right) left ## right\n"
        + changed["wyrelog/fact/store.c"]
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = "
        "store->WYL_ARGUMENT_PASTE(co, nn);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "argument-token-paste", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = (
        "#if WYL_UNKNOWN_PROFILE\n"
        "#define WYL_BRANCH_RAW(value) (value)\n"
        "#else\n"
        "#define WYL_BRANCH_RAW(object) ((object)->conn)\n"
        "#endif\n"
        + changed["wyrelog/fact/store.c"]
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = WYL_BRANCH_RAW (store);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "active-else-macro", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store-private.h"] += (
        "\n#define WYL_INCLUDED_RAW(object) ((object)->conn)\n"
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = WYL_INCLUDED_RAW (store);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "included-header-macro", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = (
        "#define WYL_STRING_RAW(object) "
        "((void) \"http://\", (object)->conn)\n"
        + changed["wyrelog/fact/store.c"]
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = WYL_STRING_RAW (store);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "string-comment-marker", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed[
        "wyrelog/fact/store.c"
    ].replace(
        "  store->rename_metadata_value_column_once = TRUE;",
        "  (void) duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
        "  store->rename_metadata_value_column_once = TRUE;",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "arm-seam-direct-duckdb", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nwyrelog_error_t\n"
        "wyl_fact_store_raw_escape (wyl_fact_store_t *store)\n"
        "{\n  return duckdb_query (store->conn, \"SELECT 1;\", NULL) "
        "== DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;\n}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "new-external-raw-root", "raw DuckDB authority inventory", changed
    )

    for macro_path in ("source", "header"):
        changed = dict(files)
        definitions = (
            "#define WYL_PASTE(left, right) left ## right\n"
            "#define WYL_RAW_OPERATOR WYL_PASTE(-, >)\n"
            "#define WYL_RAW_MEMBER WYL_PASTE(co, nn)\n"
            "#define WYL_PASTED_RAW(object) "
            "((object) WYL_RAW_OPERATOR WYL_RAW_MEMBER)\n"
        )
        if macro_path == "source":
            role_source = definitions + changed["wyrelog/fact/store.c"]
        else:
            changed[ROLE_HEADER] += "\n" + definitions
            role_source = changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at]
            + "duckdb_connection leaked = WYL_PASTED_RAW (store);\n"
            "  (void) leaked;\n  " + role_source[session_at:]
        )
        mutations.append(changed)

    changed = dict(files)
    marker = "wyl_fact_store_connection_session_end (&session);"
    changed["wyrelog/fact/compound.c"] = changed[
        "wyrelog/fact/compound.c"
    ].replace(marker, marker + "\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/compound.c"] = changed[
        "wyrelog/fact/compound.c"
    ].replace(marker, marker + "\n  if (rc == WYRELOG_E_INVALID)\n"
              "    return rc;\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    marker = "wyl_fact_store_connection_session_end (&session);"
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace(marker, marker + "\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("owned->cells[c].text = g_strdup (value);",
              "owned->cells[c].text = value;", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("WylFactStoreConnectionSession session = { 0 };",
              "static\n  WylFactStoreConnectionSession session = { 0 };", 1)
    mutations.append(changed)

    for escaped in (
        "\nWylFactStoreConnectionSession escaped_global;\n",
        "\nWylFactStoreConnectionSession *escaped_global_pointer;\n",
        "\ntypedef struct { WylFactStoreConnectionSession session; } "
        "EscapedContext;\n",
        "\ntypedef union { WylFactStoreConnectionSession *session; gpointer raw; } "
        "EscapedUnion;\n",
        "\nstatic void escaped_heap(void) { "
        "g_new0(WylFactStoreConnectionSession, 1); }\n",
        "\nWylFactStoreConnectionSession escaped_return(void) { "
        "WylFactStoreConnectionSession session = { 0 }; return session; }\n",
        "\nWylFactStoreConnectionSession *escaped_pointer_return(void) { "
        "return NULL; }\n",
        "\nstatic void escaped_thread(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "g_thread_new(\"escaped\", (GThreadFunc) escaped_thread, &session); }\n",
        "\nstatic void escaped_indirect_thread(void) { "
        "WylFactStoreConnectionSession session = { 0 }; gpointer value = &session; "
        "g_thread_new(\"escaped\", (GThreadFunc) escaped_indirect_thread, value); }\n",
        "\nstatic gpointer escaped_opaque;\n"
        "static void escaped_opaque_store(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "escaped_opaque = (gpointer) &session; }\n",
        "\nstatic void escaped_helper(gpointer value) { (void) value; }\n"
        "static void escaped_indirect_helper(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "escaped_helper((gpointer) &session); }\n",
        "\nstatic void *escaped_session_pointer;\n"
        "static void escaped_pointer_alias(WylFactStoreConnectionSession *session) { "
        "escaped_session_pointer = (void *) session; }\n",
        "\nstatic void escaped_opaque_sink(void *value) { (void) value; }\n"
        "static void escaped_pointer_helper(WylFactStoreConnectionSession *session) { "
        "escaped_opaque_sink((gpointer) session); }\n",
        "\nstatic void escaped_bare_sink(void *value) { (void) value; }\n"
        "static void escaped_bare_helper(WylFactStoreConnectionSession *session) { "
        "escaped_bare_sink(session); }\n",
        "\nstatic void escaped_pointer_local(WylFactStoreConnectionSession *session) { "
        "void *alias = session; (void) alias; }\n",
        "\nstatic void *escaped_pointer_return(WylFactStoreConnectionSession *session) { "
        "return session; }\n",
        "\nstatic gconstpointer escaped_const_pointer;\n"
        "static void escaped_gconstpointer(WylFactStoreConnectionSession *session) { "
        "escaped_const_pointer = (gconstpointer) session; }\n",
        "\nstatic const void *escaped_const_void_pointer;\n"
        "static void escaped_const_void(WylFactStoreConnectionSession *session) { "
        "escaped_const_void_pointer = (const void *) session; }\n",
        "\ntypedef gpointer EscapedPointer;\n"
        "static EscapedPointer escaped_custom_pointer;\n"
        "static void escaped_custom_cast(WylFactStoreConnectionSession *session) { "
        "escaped_custom_pointer = (EscapedPointer) session; }\n",
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] += escaped
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("wyl_fact_store_connection_session_end (&session);", "", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/query.c"] += '\n#include "store-connection-private.h"\n'
    mutations.append(changed)

    changed = dict(files)
    changed[ROLE_HEADER] = changed[ROLE_HEADER].replace(
        "#if !defined(WYL_FACT_STORE_CONNECTION_ROLE)", "#if 0", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "#if defined(WYL_TEST_HANDLE_SEAMS)\nvoid\n"
        "wyl_fact_store_test_set_transaction_hook",
        "void\nwyl_fact_store_test_set_transaction_hook",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    marker = "dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep"
    changed["tests/meson.build"] = changed["tests/meson.build"].replace(
        marker, "dependencies : [wyrelog_dep, wyrelog_handle_test_seams_dep, wirelog_dep", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "store->health == WYL_FACT_STORE_POISONED",
        "FALSE",
        1,
    )
    mutations.append(changed)

    for token in (
        "if (active != NULL)",
        "session->owner == g_thread_self ()",
        "session->store->session_owner == session->owner",
        "g_private_get (&active_connection_session) == session",
        "connection_session_is_current (session)",
        "connection_session_is_current (transaction->session)",
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
            token, "FALSE", 1
        )
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "if (active != NULL)\n    if (active->store == store)\n"
        "      return WYRELOG_E_INTERNAL;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nstatic void pre_tls_duckdb_escape(wyl_fact_store_t *store) { "
        "duckdb_query(store->conn, \"SELECT 1;\", NULL); }\n"
    )
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "WylFactStoreConnectionSession *active =\n"
        "      g_private_get (&active_connection_session);",
        "pre_tls_duckdb_escape (store);\n"
        "  WylFactStoreConnectionSession *active =\n"
        "      g_private_get (&active_connection_session);",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
        "  if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "store->health = WYL_FACT_STORE_POISONED;",
        "store->health = WYL_FACT_STORE_HEALTHY;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "g_assert_false(wyl_fact_store_test_try_lock(store));",
        "g_assert_false(TRUE);",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "waiter->rc = wyl_fact_store_table_exists",
        "waiter->rc = fake_internal_table_exists",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "assert_engine_marker(engine);",
        "(void) wyl_engine_insert(engine, \"poison_marker\", marker_value, 1);\n"
        "  assert_engine_marker(engine);",
        1,
    )
    mutations.append(changed)

    for token, replacement in (
        ("SELECT COUNT(*) FROM fact_event_log;",
         "SELECT COUNT(*) FROM fact_batches;"),
        ('store, &schema, "poison-append"',
         'store, &schema, "poison-append-mutated"'),
        ('store, &schema, "owner-retract"',
         'store, &schema, "owner-retract-mutated"'),
        ('store, &schema, "retract-core-attempt"',
         'store, &schema, "retract-core-attempt-mutated"'),
    ):
        changed = dict(files)
        changed["tests/test-fact-store-poison.c"] = changed[
            "tests/test-fact-store-poison.c"
        ].replace(token, replacement, 1)
        mutations.append(changed)

    for path, token in (
        ("wyrelog/fact/store.c", "g_private_get (&active_connection_session)"),
        ("wyrelog/fact/store.c", "store->session_owner = NULL;"),
        ("wyrelog/fact/replay.c",
         "wyl_fact_store_connection_session_end (&admission);"),
        ("tests/test-fact-store-poison.c", "g_assert_false(exists);"),
        ("tests/test-fact-store-poison.c", "g_assert_false(inserted);"),
        ("tests/test-fact-store-poison.c", "assert_zero_delta(&delta);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(row_count, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(table);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(purged, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(compound_ref, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_cmpint(handle, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(g_hash_table_size(handles), ==, 1);"),
        ("tests/test-fact-store-poison.c", "assert_engine_marker(engine);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(admission_calls, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "nested_session_admissions);"),
        ("tests/test-fact-store-poison.c", "nested_duckdb_calls);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(replay_engine);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(query_value, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(query_text);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(wyl_fact_store_test_duckdb_call_count(store), ==,\n"
         "      duckdb_calls);"),
    ):
        changed = dict(files)
        changed[path] = changed[path].replace(token, "", 1)
        mutations.append(changed)

    for label, body in (
        (
            "renamed-receiver-raw-root",
            "\nstatic gpointer\nraw_receiver_escape (wyl_fact_store_t *s)\n"
            "{\n  return (gpointer) s->conn;\n}\n",
        ),
        (
            "dereferenced-receiver-raw-root",
            "\nstatic gpointer\nraw_dereference_escape "
            "(wyl_fact_store_t *store)\n"
            "{\n  return (gpointer) (*store).conn;\n}\n",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] += body
        mutations.append(changed)
        require_boundary_rejection(
            label, "raw DuckDB authority inventory", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nstatic gpointer WYL_LATE_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer late_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_LATE_STRINGIFY(store->conn); }\n"
        "#define WYL_LATE_STRINGIFY(value) #value\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "late-stringification-definition", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/inactive-stringify-boundary.h"] = (
        "#if 0\n"
        "#define WYL_INACTIVE_COLLIDE(value) #value\n"
        "#endif\n"
    )
    changed["wyrelog/fact/store.c"] = (
        '#include "inactive-stringify-boundary.h"\n'
        + changed["wyrelog/fact/store.c"]
        + "\nstatic gpointer WYL_INACTIVE_COLLIDE(gpointer value) "
        "{ return value; }\n"
        "static gpointer inactive_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_INACTIVE_COLLIDE(store->conn); }\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "inactive-header-stringification", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/undef-stringify-boundary.h"] = (
        "#define WYL_UNDEF_STRINGIFY(value) #value\n"
    )
    changed["wyrelog/fact/store.c"] = (
        '#include "undef-stringify-boundary.h"\n'
        "#undef WYL_UNDEF_STRINGIFY\n"
        + changed["wyrelog/fact/store.c"]
        + "\nstatic gpointer WYL_UNDEF_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer undef_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_UNDEF_STRINGIFY(store->conn); }\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "undef-header-stringifier", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/unrelated-stringify-boundary.h"] = (
        "#define WYL_UNRELATED_STRINGIFY(value) #value\n"
    )
    changed["wyrelog/fact/store.c"] = (
        '#define WYL_LOG_HEADER "unrelated-stringify-boundary.h"\n'
        + changed["wyrelog/fact/store.c"]
        + "\nstatic gpointer WYL_UNRELATED_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer unrelated_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_UNRELATED_STRINGIFY(store->conn); }\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "unrelated-literal-macro-header",
        "raw DuckDB authority inventory",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/later-stringify-boundary.h"] = (
        "#define WYL_LATER_HEADER_STRINGIFY(value) #value\n"
    )
    changed["wyrelog/fact/store.c"] += (
        "\nstatic gpointer WYL_LATER_HEADER_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer later_header_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_LATER_HEADER_STRINGIFY(store->conn); }\n"
        '#include "later-stringify-boundary.h"\n'
    )
    mutations.append(changed)
    require_boundary_rejection(
        "later-header-stringifier", "raw DuckDB authority inventory", changed
    )

    for label, definitions, statement in (
        (
            "apple-profile-raw",
            "#if defined(__APPLE__)\n"
            "#define WYL_PLATFORM_RAW(object, member) ((object)->member)\n"
            "#else\n#define WYL_PLATFORM_RAW(object, member) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_PLATFORM_RAW (store, conn);",
        ),
        (
            "multiline-macro-invocation",
            "#define WYL_MULTILINE_RAW(object) ((object)->conn)\n",
            "duckdb_connection leaked = WYL_MULTILINE_RAW\n    (store);",
        ),
        (
            "variadic-member-macro",
            "#define WYL_VARIADIC_RAW(object, ...) "
            "((object)->__VA_ARGS__)\n",
            "duckdb_connection leaked = WYL_VARIADIC_RAW (store, conn);",
        ),
        (
            "c-integer-conditional",
            "#if -3 / 2 == -1\n"
            "#define WYL_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_INTEGER_RAW (store);",
        ),
        (
            "parenthesized-c-integer-conditional",
            "#if (-3) / 2 == -1\n"
            "#define WYL_PAREN_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_PAREN_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_PAREN_INTEGER_RAW (store);",
        ),
        (
            "left-associative-c-integer-conditional",
            "#if 8 % 3 / 2 == 1\n"
            "#define WYL_ASSOC_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_ASSOC_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_ASSOC_INTEGER_RAW (store);",
        ),
        (
            "multiplicative-c-integer-conditional",
            "#if 8 * 3 / 5 == 4\n"
            "#define WYL_MULTIPLY_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_MULTIPLY_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_MULTIPLY_INTEGER_RAW (store);",
        ),
        (
            "parenthesized-expression-conditional",
            "#if -7 / (2 + 1) == -2\n"
            "#define WYL_EXPRESSION_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_EXPRESSION_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_EXPRESSION_RAW (store);",
        ),
        (
            "ternary-expression-conditional",
            "#if 1 ? 1 : 0\n"
            "#define WYL_TERNARY_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_TERNARY_RAW (store);",
        ),
        (
            "character-expression-conditional",
            "#if 'A' == 65\n"
            "#define WYL_CHARACTER_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_CHARACTER_RAW (store);",
        ),
        (
            "c-comparison-associativity",
            "#if !(3 > 2 > 1)\n"
            "#define WYL_COMPARE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_COMPARE_RAW (store);",
        ),
        (
            "c-false-first-comparison-associativity",
            "#if 2 < 1 < 2\n"
            "#define WYL_FALSE_FIRST_COMPARE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = "
            "WYL_FALSE_FIRST_COMPARE_RAW (store);",
        ),
        (
            "nested-ternary-expression",
            "#if 0 ? 0 : 0 ? 0 : 1\n"
            "#define WYL_NESTED_TERNARY_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_NESTED_TERNARY_RAW (store);",
        ),
        (
            "short-circuit-expression",
            "#if 1 || (1 / 0)\n"
            "#define WYL_SHORT_CIRCUIT_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_SHORT_CIRCUIT_RAW (store);",
        ),
        (
            "unsigned-expression",
            "#if -1U > 0\n"
            "#define WYL_UNSIGNED_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_UNSIGNED_RAW (store);",
        ),
        (
            "unsigned-long-long-expression",
            "#if -1ULL > 0\n"
            "#define WYL_ULL_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_ULL_RAW (store);",
        ),
        (
            "unsigned-hex-expression",
            "#if -0x1U > 0\n"
            "#define WYL_UNSIGNED_HEX_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_UNSIGNED_HEX_RAW (store);",
        ),
        (
            "parenthesized-ternary-expression",
            "#if (0 ? 0 : 1)\n"
            "#define WYL_PAREN_TERNARY_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_PAREN_TERNARY_RAW (store);",
        ),
        (
            "logical-not-precedence",
            "#if !0 < 2\n"
            "#define WYL_NOT_PRECEDENCE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_NOT_PRECEDENCE_RAW (store);",
        ),
        (
            "bitwise-equality-precedence",
            "#if 1 & 2 == 2\n"
            "#define WYL_BITWISE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_BITWISE_RAW (store);",
        ),
        (
            "preprocessor-uintmax-width",
            "#if 0xffffffffU + 1 == 0\n"
            "#define WYL_UINTMAX_RAW(object) (0)\n"
            "#else\n"
            "#define WYL_UINTMAX_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_UINTMAX_RAW (store);",
        ),
        (
            "ternary-common-unsigned-type",
            "#if (1 ? -1 : 0U) > 0\n"
            "#define WYL_TERNARY_TYPE_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_TERNARY_TYPE_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_TERNARY_TYPE_RAW (store);",
        ),
        (
            "unsuffixed-hex-uintmax",
            "#if 0xffffffffffffffff + 1 == 0\n"
            "#define WYL_HEX_UINTMAX_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_HEX_UINTMAX_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_HEX_UINTMAX_RAW (store);",
        ),
    ):
        changed = dict(files)
        role_source = definitions + changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at] + statement + "\n  (void) leaked;\n  "
            + role_source[session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "macro-generated raw authority", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/repeat-boundary.h"] = (
        "#ifdef WYL_REPEAT_ON\n"
        "#define WYL_REPEAT_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_REPEAT_ON 1\n#endif\n"
    )
    role_source = (
        '#include "repeat-boundary.h"\n#include "repeat-boundary.h"\n'
        + changed["wyrelog/fact/store.c"]
    )
    create_at = role_source.index("wyl_fact_store_create_schema (")
    session_at = role_source.index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        role_source[:session_at]
        + "duckdb_connection leaked = WYL_REPEAT_RAW (store);\n"
        "  (void) leaked;\n  " + role_source[session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "repeat-include-state", "macro-generated raw authority", changed
    )

    def queue_macro_escape(
        label: str, definitions: str, statement: str,
        extra_files: dict[str, str] | None = None,
    ) -> None:
        changed = dict(files)
        if extra_files is not None:
            changed.update(extra_files)
        role_source = definitions + changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at] + statement + "\n  "
            + role_source[session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(label, "macro", changed)

    aliases = "#define WYL_DEPTH_0(object) ((object)->conn)\n"
    for index in range(1, 40):
        aliases += f"#define WYL_DEPTH_{index} WYL_DEPTH_{index - 1}\n"
    queue_macro_escape(
        "macro-depth-exhaustion", aliases,
        "(void) WYL_DEPTH_39(store);",
    )
    queue_macro_escape(
        "variadic-call-forwarding",
        "#define WYL_CALL(function, ...) function(__VA_ARGS__)\n",
        "(void) WYL_CALL(duckdb_query, "
        "wyl_fact_store_connection_session_get (&session), "
        "\"SELECT 1;\", NULL);",
    )
    queue_macro_escape(
        "expanded-include",
        "#define WYL_BOUNDARY_HEADER \"macro-boundary.h\"\n"
        "#include WYL_BOUNDARY_HEADER\n",
        "(void) WYL_INCLUDED_ESCAPE(store);",
        {"wyrelog/fact/macro-boundary.h":
            "#define WYL_INCLUDED_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "expanded-angle-include",
        "#define WYL_ANGLE_HEADER <wyrelog/fact/angle-boundary.h>\n"
        "#include WYL_ANGLE_HEADER\n",
        "(void) WYL_ANGLE_ESCAPE(store);",
        {"wyrelog/fact/angle-boundary.h":
            "#define WYL_ANGLE_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "direct-angle-include",
        "#include <wyrelog/fact/direct-angle-boundary.h>\n",
        "(void) WYL_DIRECT_ANGLE_ESCAPE(store);",
        {"wyrelog/fact/direct-angle-boundary.h":
            "#define WYL_DIRECT_ANGLE_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "outside-fact-include",
        '#include "../include/raw-boundary.h"\n',
        "(void) WYL_OUTSIDE_FACT_ESCAPE(store);",
        {"wyrelog/include/raw-boundary.h":
            "#define WYL_OUTSIDE_FACT_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "literal-include-operand",
        "#define literal changed\n"
        '#include "literal-boundary.h"\n',
        "(void) WYL_LITERAL_INCLUDE_ESCAPE(store);",
        {"wyrelog/fact/literal-boundary.h":
            "#define WYL_LITERAL_INCLUDE_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "defined-external-profile",
        "#if defined(WYL_EXTERNAL_PROFILE)\n"
        "#define WYL_EXTERNAL_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_EXTERNAL_RAW(object) (0)\n#endif\n",
        "(void) WYL_EXTERNAL_RAW(store);",
    )
    queue_macro_escape(
        "mixed-external-profile",
        "#if WYL_EXTERNAL_A && !WYL_EXTERNAL_B\n"
        "#define WYL_MIXED_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_MIXED_RAW(object) (0)\n#endif\n",
        "(void) WYL_MIXED_RAW(store);",
    )
    queue_macro_escape(
        "three-way-external-profile",
        "#if WYL_EXTERNAL_A && WYL_EXTERNAL_B && !WYL_EXTERNAL_C\n"
        "#define WYL_THREE_WAY_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_THREE_WAY_RAW(object) (0)\n#endif\n",
        "(void) WYL_THREE_WAY_RAW(store);",
    )
    queue_macro_escape(
        "six-name-external-profile",
        "#if WYL_SIX_A && WYL_SIX_B && WYL_SIX_C "
        "&& !WYL_SIX_D && !WYL_SIX_E && !WYL_SIX_F\n"
        "#define WYL_SIX_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_SIX_RAW(object) (0)\n#endif\n",
        "(void) WYL_SIX_RAW(store);",
    )
    queue_macro_escape(
        "nested-external-profile",
        "#if WYL_NESTED_A\n#if WYL_NESTED_B\n"
        "#define WYL_NESTED_RAW(object) ((object)->conn)\n"
        "#endif\n#endif\n",
        "(void) WYL_NESTED_RAW(store);",
    )
    queue_macro_escape(
        "later-local-profile-definition",
        "#if WYL_LATER_LOCAL\n"
        "#define WYL_LATER_LOCAL_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_LATER_LOCAL_RAW(object) (0)\n#endif\n"
        "#define WYL_LATER_LOCAL 0\n",
        "(void) WYL_LATER_LOCAL_RAW(store);",
    )
    queue_macro_escape(
        "header-local-external-profile",
        '#include "profile-boundary.h"\n',
        "(void) WYL_HEADER_PROFILE_RAW(store);",
        {"wyrelog/fact/profile-boundary.h":
            "#if WYL_HEADER_PROFILE\n"
            "#define WYL_HEADER_PROFILE_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_HEADER_PROFILE_RAW(object) (0)\n#endif\n"},
    )
    queue_macro_escape(
        "recursive-header-external-profile",
        '#include "profile-outer-boundary.h"\n',
        "(void) WYL_RECURSIVE_PROFILE_RAW(store);",
        {
            "wyrelog/fact/profile-outer-boundary.h":
                '#include "profile-inner-boundary.h"\n',
            "wyrelog/fact/profile-inner-boundary.h":
                "#if WYL_RECURSIVE_PROFILE\n"
                "#define WYL_RECURSIVE_PROFILE_RAW(object) ((object)->conn)\n"
                "#else\n"
                "#define WYL_RECURSIVE_PROFILE_RAW(object) (0)\n"
                "#endif\n",
        },
    )
    queue_macro_escape(
        "inherited-macro-include-profile",
        "#define WYL_INHERITED_HEADER \"profile-inherited-inner.h\"\n"
        '#include "profile-inherited-outer.h"\n',
        "(void) WYL_INHERITED_PROFILE_RAW(store);",
        {
            "wyrelog/fact/profile-inherited-outer.h":
                "#include WYL_INHERITED_HEADER\n",
            "wyrelog/fact/profile-inherited-inner.h":
                "#if WYL_INHERITED_PROFILE\n"
                "#define WYL_INHERITED_PROFILE_RAW(object) ((object)->conn)\n"
                "#else\n"
                "#define WYL_INHERITED_PROFILE_RAW(object) (0)\n"
                "#endif\n",
        },
    )
    queue_macro_escape(
        "token-pasted-header-external-profile",
        '#include "profile-token-paste.h"\n',
        "(void) WYL_PROFILE_PASTED_RAW(store);",
        {
            "wyrelog/fact/profile-token-paste.h":
                "#define WYL_PROFILE_CAT(left, right) left ## right\n"
                "#if WYL_PROFILE_PASTED_EXTERNAL\n"
                "#define WYL_PROFILE_PASTED_RAW(object) "
                "((object) WYL_PROFILE_CAT(-, >) WYL_PROFILE_CAT(co, nn))\n"
                "#else\n"
                "#define WYL_PROFILE_PASTED_RAW(object) (0)\n"
                "#endif\n",
        },
    )
    queue_macro_escape(
        "inactive-profile-definition",
        "#if 0\n#define WYL_INACTIVE_DEFINED 1\n#endif\n"
        "#if WYL_INACTIVE_DEFINED\n"
        "#define WYL_INACTIVE_DEFINED_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_INACTIVE_DEFINED_RAW(object) (0)\n#endif\n",
        "(void) WYL_INACTIVE_DEFINED_RAW(store);",
    )
    queue_macro_escape(
        "empty-token-paste",
        "#define WYL_EMPTY_CAT(left, right) left ## right\n"
        "#define WYL_EMPTY_RAW(object) "
        "((object)->WYL_EMPTY_CAT(,conn))\n",
        "(void) WYL_EMPTY_RAW(store);",
    )
    queue_macro_escape(
        "token-pasted-authority-type",
        "#define WYL_TYPE_CAT(left, right) left ## right\n"
        "#define WYL_RAW_TYPE WYL_TYPE_CAT(duckdb_, connection)\n",
        "WYL_RAW_TYPE escaped_connection = NULL; "
        "(void) escaped_connection;",
    )
    queue_macro_escape(
        "inactive-pragma-once",
        '#include "inactive-once-boundary.h"\n'
        '#include "inactive-once-boundary.h"\n',
        "(void) WYL_INACTIVE_ONCE_VALUE(store);",
        {"wyrelog/fact/inactive-once-boundary.h":
            "#if 0\n#pragma once\n#endif\n"
            "#ifndef WYL_INACTIVE_ONCE_SEEN\n"
            "#define WYL_INACTIVE_ONCE_SEEN 1\n"
            "#define WYL_INACTIVE_ONCE_VALUE(value) (value)\n"
            "#else\n"
            "#define WYL_INACTIVE_ONCE_VALUE(object) ((object)->conn)\n"
            "#endif\n"},
    )
    queue_macro_escape(
        "hexadecimal-condition",
        "#if 0x1\n#define WYL_HEX_RAW(object) ((object)->conn)\n#endif\n",
        "(void) WYL_HEX_RAW(store);",
    )
    queue_macro_escape(
        "vertical-tab-directive",
        "#define\vWYL_VERTICAL_RAW(object) ((object)->conn)\n",
        "(void) WYL_VERTICAL_RAW(store);",
    )

    changed = dict(files)
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "(void) (*duckdb_query) (store->conn, \"SELECT 1;\", NULL);\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "parenthesized-duckdb-designator",
        "raw DuckDB authority inventory",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed[
        "wyrelog/fact/store.c"
    ].replace(
        "    rc = exec_sql (store->conn,\n"
        "            \"CREATE TABLE IF NOT EXISTS fact_store_metadata (\"",
        "    rc = exec_sql (NULL,\n"
        "            \"CREATE TABLE IF NOT EXISTS fact_store_metadata (\"",
        1,
    )
    changed["wyrelog/fact/store.c"] += (
        "\nstatic gpointer raw_member_escape(wyl_fact_store_t *store)\n"
        "{\n"
        "  return store->conn;\n"
        "}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "raw-member-moved-between-functions",
        "raw DuckDB authority moved between functions",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\n#if WYL_REVIEW_RAW_PROFILE\n"
        "static wyrelog_error_t\n"
        "review_profile_raw_access (wyl_fact_store_t *store)\n"
        "{\n"
        "  duckdb_result result = { 0 };\n"
        "  duckdb_state state = duckdb_query (store->conn, "
        "\"SELECT 1;\", &result);\n"
        "  duckdb_destroy_result (&result);\n"
        "  return state == DuckDBSuccess ? WYRELOG_E_OK : "
        "WYRELOG_E_QUERY_FAILED;\n"
        "}\n"
        "#endif\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "external-profile-raw-function",
        "raw DuckDB authority inventory drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/review-header-raw-boundary.h"] = (
        "#if WYL_HEADER_RAW_PROFILE\n"
        "static wyrelog_error_t\n"
        "review_header_raw_access (wyl_fact_store_t *store)\n"
        "{\n"
        "  return duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
        "}\n"
        "#endif\n"
    )
    store_marker = (
        "};\n\nstatic WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;"
    )
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        store_marker,
        "};\n\n#include \"review-header-raw-boundary.h\"\n\n"
        "static WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "included-header-external-profile-raw-function",
        "unexpected transitive raw authority functions",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nwyrelog_error_t\n"
        "wyl_fact_store_raw_escape (wyl_fact_store_t *store)\n"
        "{\n"
        "  return reject_audit_database_unlocked (store);\n"
        "}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "new-external-transitive-raw-wrapper",
        "unexpected transitive raw authority functions",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\n#if WYL_REVIEW_WRAPPER_PROFILE\n"
        "wyrelog_error_t\n"
        "wyl_fact_store_profile_raw_escape (wyl_fact_store_t *store)\n"
        "{\n"
        "  return reject_audit_database_unlocked (store);\n"
        "}\n"
        "#endif\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "new-profile-transitive-raw-wrapper",
        "unexpected transitive raw authority functions",
        changed,
    )

    for label, statement in (
        (
            "multiply-parenthesized-duckdb-designator",
            "(void) ((duckdb_query)) (store->conn, \"SELECT 1;\", NULL);",
        ),
        (
            "comment-separated-duckdb-designator",
            "(void) (duckdb_query /* gap */) "
            "(store->conn, \"SELECT 1;\", NULL);",
        ),
    ):
        changed = dict(files)
        create_at = changed["wyrelog/fact/store.c"].index(
            "wyl_fact_store_create_schema ("
        )
        session_at = changed["wyrelog/fact/store.c"].index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            changed["wyrelog/fact/store.c"][:session_at]
            + statement + "\n  "
            + changed["wyrelog/fact/store.c"][session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "raw DuckDB authority inventory", changed
        )

    for label, statement in (
        (
            "ternary-duckdb-designator-before-admission",
            "(void) (1 ? duckdb_query : NULL) "
            "(NULL, \"SELECT 1;\", NULL);",
        ),
        (
            "local-duckdb-function-pointer-before-admission",
            "typedef duckdb_state BoundaryQueryState;\n"
            "  BoundaryQueryState (*boundary_query) () = duckdb_query;\n"
            "  (void) boundary_query (NULL, \"SELECT 1;\", NULL);",
        ),
        (
            "local-addressed-duckdb-function-pointer-before-admission",
            "typedef duckdb_state BoundaryQueryState;\n"
            "  BoundaryQueryState (*boundary_query) () = &duckdb_query;\n"
            "  (void) boundary_query (NULL, \"SELECT 1;\", NULL);",
        ),
    ):
        changed = dict(files)
        create_at = changed["wyrelog/fact/store.c"].index(
            "wyl_fact_store_create_schema ("
        )
        session_at = changed["wyrelog/fact/store.c"].index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            changed["wyrelog/fact/store.c"][:session_at]
            + statement + "\n  "
            + changed["wyrelog/fact/store.c"][session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "session authority precedes successful admission", changed
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    admitted_region = (
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n"
    )
    reordered_region = (
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
    )
    if admitted_region not in replay_source:
        raise AssertionError("session dominance mutation fixture drifted")
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region, reordered_region, 1
    )
    mutations.append(changed)
    require_boundary_rejection(
        "session-get-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "  (void) duckdb_query (NULL, \"SELECT 1;\", NULL);\n"
        + admitted_region,
        1,
    ).replace(
        "    duckdb_free (namespace_id);\n",
        "    (void) namespace_id;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "duckdb-call-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    store_source = changed["wyrelog/fact/store.c"]
    create_session = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  wyrelog_error_t rc = wyl_fact_store_connection_session_begin (store,\n"
        "          &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  rc = reject_audit_database_unlocked (store);\n"
    )
    changed["wyrelog/fact/store.c"] = store_source.replace(
        create_session,
        "  wyrelog_error_t rc = reject_audit_database_unlocked (store);\n"
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "raw-helper-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/review-token-wrapper-boundary.h"] = (
        "#if WYL_HEADER_WRAPPER_PROFILE\n"
        "#define WYL_JOIN_INNER(a, b) a ## b\n"
        "#define WYL_JOIN(a, b) WYL_JOIN_INNER(a, b)\n"
        "#define WYL_RAW_HELPER "
        "WYL_JOIN(reject_audit_database_, unlocked)\n"
        "static wyrelog_error_t WYL_RAW_HELPER(wyl_fact_store_t *);\n"
        "static wyrelog_error_t\n"
        "boundary_token_raw_wrapper (wyl_fact_store_t *store)\n"
        "{\n  return WYL_RAW_HELPER(store);\n}\n"
        "#endif\n"
    )
    changed["wyrelog/fact/store.c"] = store_source.replace(
        store_marker,
        "};\n\n#include \"review-token-wrapper-boundary.h\"\n\n"
        "static WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;",
        1,
    ).replace(
        create_session,
        "#if WYL_HEADER_WRAPPER_PROFILE\n"
        "  (void) boundary_token_raw_wrapper (store);\n"
        "#endif\n" + create_session,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "token-pasted-header-wrapper-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/review-alias-state-boundary.h"] = (
        "#if WYL_REVIEW_ALIAS_PROFILE\n"
        "#define WYL_REVIEW_RAW_HELPER reject_audit_database_unlocked\n"
        "static wyrelog_error_t "
        "WYL_REVIEW_RAW_HELPER(wyl_fact_store_t *);\n"
        "#endif\n"
    )
    changed["wyrelog/fact/review-wrapper-state-boundary.h"] = (
        "#if WYL_REVIEW_WRAPPER_PROFILE\n"
        "static wyrelog_error_t\n"
        "boundary_stateful_raw_wrapper (wyl_fact_store_t *store)\n"
        "{\n  return WYL_REVIEW_RAW_HELPER(store);\n}\n"
        "#endif\n"
    )
    changed["wyrelog/fact/store.c"] = store_source.replace(
        store_marker,
        "};\n\n#include \"review-alias-state-boundary.h\"\n"
        "#include \"review-wrapper-state-boundary.h\"\n\n"
        "static WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;",
        1,
    ).replace(
        create_session,
        "#if WYL_REVIEW_ALIAS_PROFILE && WYL_REVIEW_WRAPPER_PROFILE\n"
        "  (void) boundary_stateful_raw_wrapper (store);\n"
        "#endif\n" + create_session,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "cross-header-macro-state-wrapper-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    for label, declaration, invocation in (
        (
            "cross-tu-session-owner-name-collision",
            "\nstatic wyrelog_error_t list_replay_relations"
            "(wyl_fact_store_t *store)\n"
            "{\n  return reject_audit_database_unlocked (store);\n}\n",
            "  (void) list_replay_relations (store);\n",
        ),
        (
            "transitive-raw-wrapper-before-admission",
            "\nstatic wyrelog_error_t boundary_raw_wrapper"
            "(wyl_fact_store_t *store)\n"
            "{\n  return reject_audit_database_unlocked (store);\n}\n",
            "  (void) boundary_raw_wrapper (store);\n",
        ),
        (
            "old-style-transitive-raw-wrapper-before-admission",
            "\nstatic wyrelog_error_t\n"
            "boundary_old_style_raw_wrapper (store)\n"
            "    wyl_fact_store_t *store;\n"
            "{\n  return reject_audit_database_unlocked (store);\n}\n",
            "  (void) boundary_old_style_raw_wrapper (store);\n",
        ),
        (
            "parenthesized-raw-helper-before-admission",
            "",
            "  (void) (reject_audit_database_unlocked) (store);\n",
        ),
        (
            "dereferenced-raw-helper-before-admission",
            "",
            "  (void) (*reject_audit_database_unlocked) (store);\n",
        ),
        (
            "raw-function-pointer-before-admission",
            "",
            "  wyrelog_error_t (*boundary_raw_call) (wyl_fact_store_t *) = "
            "reject_audit_database_unlocked;\n"
            "  (void) boundary_raw_call (store);\n",
        ),
        (
            "typedef-raw-function-pointer-before-admission",
            "",
            "  typedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "  BoundaryRawCall boundary_raw_call = "
            "reject_audit_database_unlocked;\n"
            "  (void) boundary_raw_call (store);\n",
        ),
        (
            "split-raw-function-pointer-before-admission",
            "",
            "  wyrelog_error_t (*boundary_raw_call) "
            "(wyl_fact_store_t *) = NULL;\n"
            "  boundary_raw_call = reject_audit_database_unlocked;\n"
            "  (void) boundary_raw_call (store);\n",
        ),
        (
            "array-raw-function-pointer-before-admission",
            "",
            "  wyrelog_error_t (*boundary_raw_calls[]) "
            "(wyl_fact_store_t *) = { "
            "reject_audit_database_unlocked };\n"
            "  (void) boundary_raw_calls[0] (store);\n",
        ),
        (
            "callback-raw-helper-before-admission",
            "\nstatic wyrelog_error_t boundary_invoke "
            "(wyrelog_error_t (*function) (wyl_fact_store_t *), "
            "wyl_fact_store_t *store)\n"
            "{\n  return function (store);\n}\n",
            "  (void) boundary_invoke "
            "(reject_audit_database_unlocked, store);\n",
        ),
    ):
        changed = dict(files)
        source_with_call = changed["wyrelog/fact/store.c"].replace(
            create_session, invocation + create_session, 1
        )
        if declaration:
            marker = "wyrelog_error_t\nwyl_fact_store_create_schema"
            source_with_call = source_with_call.replace(
                marker, declaration + "\n" + marker, 1
            )
        changed["wyrelog/fact/store.c"] = source_with_call
        mutations.append(changed)
        require_boundary_rejection(
            label, "session authority precedes successful admission", changed
        )

    changed = dict(files)
    replay_admission = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);"
    )
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace(
        replay_admission,
        "  wyl_fact_store_close (store);\n" + replay_admission,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "cross-tu-external-raw-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    for label, declaration, invocation in (
        (
            "global-duckdb-function-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "static BoundaryQueryState (*boundary_global_query) () = "
            "duckdb_query;\n",
            "  (void) boundary_global_query (NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-addressed-duckdb-function-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "static BoundaryQueryState (*boundary_global_query) () = "
            "&duckdb_query;\n",
            "  (void) boundary_global_query (NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-duckdb-function-array-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "static BoundaryQueryState (*boundary_global_query[]) () = { "
            "NULL, duckdb_query };\n",
            "  (void) boundary_global_query[1] "
            "(NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-duckdb-function-struct-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "typedef struct { BoundaryQueryState (*query) (); } "
            "BoundaryDuckdbDispatch;\n"
            "static BoundaryDuckdbDispatch boundary_global_query = { "
            "duckdb_query };\n",
            "  (void) boundary_global_query.query "
            "(NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-address-of-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "&reject_audit_database_unlocked;\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-parenthesized-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "(reject_audit_database_unlocked);\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-cast-parenthesized-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "(BoundaryRawCall) (reject_audit_database_unlocked);\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-macro-address-raw-alias",
            "\n#define BOUNDARY_RAW reject_audit_database_unlocked\n"
            "typedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = &BOUNDARY_RAW;\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-cast-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "(BoundaryRawCall) reject_audit_database_unlocked;\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-array-second-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw[] = { "
            "NULL, reject_audit_database_unlocked };\n",
            "  (void) boundary_global_raw[1] (store);\n",
        ),
        (
            "global-struct-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "typedef struct { BoundaryRawCall call; } BoundaryRawDispatch;\n"
            "static BoundaryRawDispatch boundary_global_raw = { "
            "reject_audit_database_unlocked };\n",
            "  (void) boundary_global_raw.call (store);\n",
        ),
        (
            "global-nested-array-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw[][2] = { "
            "{ NULL, NULL }, { NULL, reject_audit_database_unlocked } };\n",
            "  (void) boundary_global_raw[1][1] (store);\n",
        ),
    ):
        changed = dict(files)
        source_with_call = changed["wyrelog/fact/store.c"].replace(
            create_session, invocation + create_session, 1
        )
        marker = "wyrelog_error_t\nwyl_fact_store_create_schema"
        changed["wyrelog/fact/store.c"] = source_with_call.replace(
            marker, declaration + "\n" + marker, 1
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "raw authority entered file-scope alias", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "wyl_fact_store_connection_session_get (&session)",
        "/* wyl_fact_store_connection_session_get */ session.connection",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "direct-session-field-with-comment-pad",
        "raw DuckDB authority inventory drifted",
        changed,
    )

    for label, replacement in (
        (
            "inactive-admission-failure-guard",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "#if 0\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "#endif\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "empty-admission-success-guard",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "  if (rc == WYRELOG_E_OK) {\n  }\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "overwritten-admission-result",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "  rc = WYRELOG_E_OK;\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "dead-c-admission-failure-guard",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "  if (0) {\n"
            "    if (rc != WYRELOG_E_OK)\n"
            "      return rc;\n"
            "  }\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "different-admitted-session",
            "  WylFactStoreConnectionSession other_session = { 0 };\n"
            "  rc = wyl_fact_store_connection_session_begin "
            "(store, &other_session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "dead-c-admission-block",
            "  if (0) {\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "    if (rc != WYRELOG_E_OK)\n"
            "      return rc;\n"
            "  }\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "macro-admission-after-authority",
            "#define WYL_BOUNDARY_BEGIN "
            "wyl_fact_store_connection_session_ ## begin\n"
            "#define WYL_BOUNDARY_ADDRESS(value) &value\n"
            "  /* wyl_fact_store_connection_session_begin\n"
            "   * if (rc != WYRELOG_E_OK) return rc; */\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n"
            "  rc = WYL_BOUNDARY_BEGIN(store, WYL_BOUNDARY_ADDRESS(session));\n",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region, replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(
            label,
            "session owner lost admission"
            if label == "macro-admission-after-authority"
            else "session authority precedes successful admission",
            changed,
        )

    changed = dict(files)
    source_order_replacement = (
        "#define WYL_SOURCE_ORDER_BEGIN() WYRELOG_E_OK\n"
        "  rc = WYL_SOURCE_ORDER_BEGIN();\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "#undef WYL_SOURCE_ORDER_BEGIN\n"
        "#define WYL_SOURCE_ORDER_BEGIN "
        "wyl_fact_store_connection_session_begin\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region, source_order_replacement, 1
    )
    mutations.append(changed)
    require_boundary_rejection(
        "source-order-macro-redefinition", "session owner lost admission", changed
    )

    changed = dict(files)
    file_macro_source = (
        "#define WYL_FILE_GET(value) "
        "wyl_fact_store_connection_session_get(&(value))\n"
        + replay_source
    )
    changed["wyrelog/fact/replay.c"] = file_macro_source.replace(
        admitted_region,
        "  duckdb_connection conn = WYL_FILE_GET(session);\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "file-scope-macro-get-before-admission", "macro-generated", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] += (
        "\nstatic gpointer boundary_session_get_escape(void)\n"
        "{\n"
        "  WylFactStoreConnectionSession stray = { 0 };\n"
        "  return (gpointer) "
        "wyl_fact_store_connection_session_get (&stray);\n"
        "}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "session-get-outside-owner", "session get inventory drifted", changed
    )

    for label, replacement, expected in (
        (
            "single-line-dead-admission",
            "  if (0)\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session authority precedes successful admission",
        ),
        (
            "return-before-session-release",
            admitted_region
            + "  if (store != NULL)\n"
            "    return WYRELOG_E_INTERNAL;\n",
            "session return bypasses release",
        ),
        (
            "switch-controlled-admission",
            "  switch (0)\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session authority precedes successful admission",
        ),
        (
            "else-controlled-admission",
            "  if (1)\n"
            "    rc = WYRELOG_E_OK;\n"
            "  else\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session authority precedes successful admission",
        ),
        (
            "goto-skips-session-admission",
            "  if (store != NULL)\n"
            "    goto boundary_after_begin;\n"
            "  rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "boundary_after_begin:\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session control flow may bypass release",
        ),
        (
            "glib-return-macro-skips-release",
            admitted_region
            + "  g_return_val_if_fail (store == NULL, "
            "WYRELOG_E_INTERNAL);\n",
            "session return bypasses release",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region, replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(label, expected, changed)

    for label, replacement, expected in (
        (
            "conditional-profile-skips-admission",
            "#if WYL_SKIP_ADMISSION\n"
            "  rc = WYRELOG_E_OK;\n"
            "#else\n"
            "  rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "#endif\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session owner lost admission",
        ),
        (
            "conditional-profile-skips-release",
            None,
            "session owner lost release",
        ),
    ):
        changed = dict(files)
        if replacement is not None:
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                admitted_region, replacement, 1
            )
        else:
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                "  wyl_fact_store_connection_session_end (&session);\n",
                "#if WYL_SKIP_RELEASE\n"
                "  (void) store;\n"
                "#else\n"
                "  wyl_fact_store_connection_session_end (&session);\n"
                "#endif\n",
                1,
            )
        mutations.append(changed)
        require_boundary_rejection(label, expected, changed)

    changed = dict(files)
    changed["wyrelog/fact/review-return-boundary.h"] = (
        "#define WYL_REVIEW_RETURN(condition, value) "
        "g_return_val_if_fail((condition), (value))\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        admitted_region
        + '#include "review-return-boundary.h"\n'
        "  WYL_REVIEW_RETURN (store == NULL, WYRELOG_E_INTERNAL);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "function-local-include-early-return",
        "session return bypasses release",
        changed,
    )

    for label, prefix, expected in (
        (
            "profile-direct-duckdb-before-admission",
            "#if WYL_PROFILE_EARLY_RAW\n"
            "  (void) duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
            "#endif\n",
            "raw DuckDB authority inventory drifted",
        ),
        (
            "profile-goto-skips-admission",
            "#if WYL_PROFILE_GOTO\n"
            "  goto boundary_profile_after_begin;\n"
            "#endif\n",
            "session control flow may bypass release",
        ),
    ):
        changed = dict(files)
        replacement = prefix + admitted_region
        if label == "profile-goto-skips-admission":
            replacement = replacement.replace(
                "  duckdb_connection conn = ",
                "boundary_profile_after_begin:\n"
                "  duckdb_connection conn = ",
                1,
            )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region, replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(label, expected, changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        admitted_region
        + "#if WYL_PROFILE_RETURN\n"
        "  return WYRELOG_E_INTERNAL;\n"
        "#endif\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "profile-return-skips-release", "session return bypasses release", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#if WYL_ADMISSION_MODE == 2\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-profile-value-skips-admission",
        "session owner lost admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#if WYL_RELATIONAL_ADMISSION_MODE > 1\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-relational-profile-skips-admission",
        "session owner lost admission",
        changed,
    )

    for label, condition in (
        ("numeric-reverse-relational-profile-skips-admission",
         "1 < WYL_REVERSE_ADMISSION_MODE"),
        ("numeric-bitmask-profile-skips-admission",
         "WYL_ADMISSION_FLAGS & 2"),
        ("numeric-character-profile-skips-admission",
         "WYL_CHARACTER_ADMISSION_MODE == 'A'"),
        ("numeric-nonlinear-profile-skips-admission",
         "WYL_NONLINEAR_ADMISSION_MODE * "
         "WYL_NONLINEAR_ADMISSION_MODE == 4"),
        ("numeric-large-nonlinear-profile-skips-admission",
         "WYL_LARGE_NONLINEAR_MODE * WYL_LARGE_NONLINEAR_MODE == 400"),
        ("numeric-negative-profile-skips-admission",
         "WYL_NEGATIVE_ADMISSION_MODE < -1"),
        ("numeric-octal-profile-skips-admission",
         "WYL_OCTAL_ADMISSION_MODE == 010"),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region,
            f"#if {condition}\n"
            "  rc = WYRELOG_E_OK;\n"
            "#else\n"
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "#endif\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "session owner lost admission", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#define WYL_DERIVED_ADMISSION_TWO (1 << 1)\n"
        "#if WYL_DERIVED_ADMISSION_MODE & WYL_DERIVED_ADMISSION_TWO\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-macro-derived-profile-skips-admission",
        "session owner lost admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#define WYL_LARGE_DERIVED_TARGET (1 << 10)\n"
        "#if WYL_LARGE_DERIVED_MODE == WYL_LARGE_DERIVED_TARGET\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-large-macro-derived-profile-skips-admission",
        "session owner lost admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/function-raw-boundary.h"] = (
        "duckdb_connection boundary_included_early = session.connection;\n"
        "(void) boundary_included_early;\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        '#include "function-raw-boundary.h"\n' + admitted_region,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "function-local-include-direct-raw-code",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  if (0)\n"
        "    wyl_fact_store_connection_session_end (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "single-line-dead-session-release", "session owner lost release", changed
    )

    for label, replacement in (
        (
            "switch-controlled-session-release",
            "  switch (0)\n"
            "    wyl_fact_store_connection_session_end (&session);\n",
        ),
        (
            "else-controlled-session-release",
            "  if (1)\n"
            "    rc = WYRELOG_E_OK;\n"
            "  else\n"
            "    wyl_fact_store_connection_session_end (&session);\n",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            replacement,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(label, "session owner lost release", changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  if (store != NULL)\n"
        "    goto boundary_after_release;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "boundary_after_release:\n"
        "  ",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "goto-bypasses-session-release",
        "session control flow may bypass release",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "boundary_reenter_authority:\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  if (store != NULL)\n"
        "    goto boundary_reenter_authority;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "goto-reenters-released-authority",
        "session control flow may bypass release",
        changed,
    )

    critical_mutation_ids = {id(mutation) for _label, _expected, mutation
                             in critical_mutations}
    cases = [
        (label, expected, mutation, True)
        for label, expected, mutation in critical_mutations
    ] + [
        (str(index), None, mutation, False)
        for index, mutation in enumerate(mutations, 1)
        if id(mutation) not in critical_mutation_ids
    ]
    workers = min(4, len(cases), os.cpu_count() or 1)
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=workers,
        mp_context=multiprocessing.get_context("spawn"),
        initializer=initialize_mutation_worker,
        initargs=(files,),
    ) as executor:
        errors = executor.map(
            mutation_validation_error,
            (
                mutation_delta(files, mutation)
                for _label, _expected, mutation, _critical in cases
            ),
            chunksize=1,
        )
        for (label, expected, _mutation, critical), error in zip(cases, errors):
            if error is None:
                kind = "critical mutation" if critical else "mutation"
                raise AssertionError(
                    f"connection-boundary {kind} survived: {label}"
                )
            if critical and expected not in error:
                raise AssertionError(
                    f"connection-boundary critical mutation hit wrong guard: "
                    f"{label}: {error}"
                )


def main() -> int:
    args = sys.argv[1:]
    self_mode = bool(args and args[0] == "--self-test")
    if self_mode:
        args = args[1:]
    if len(args) != 1:
        raise SystemExit("usage: test-fact-store-connection-boundary.py [--self-test] ROOT")
    files = load(Path(args[0]))
    validate(files)
    if self_mode:
        self_test(files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

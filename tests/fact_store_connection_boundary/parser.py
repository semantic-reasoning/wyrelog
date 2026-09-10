"""Lexical and preprocessor analysis helpers for the fact-store boundary checker."""

from __future__ import annotations

import functools
from pathlib import Path, PurePath
import posixpath
import re

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
        # The lookbehind excludes digits as well as identifier characters.
        # Without the digit, a macro whose name ends in more than one digit
        # donates a phantom literal: in G_OS_WIN32 the 3 is rejected for the
        # N before it, and the 2 is then matched because a 3 precedes it.
        # Every macro named in that expression would inherit the phantom
        # value's neighbourhood, and the profile cross-product built from
        # those candidates grows by an order of magnitude.
        literals = {
            int(token, 16) if token.lower().startswith("0x")
            else int(token, 8) if len(token) > 1 and token.startswith("0")
            else int(token, 10) for token in re.findall(
                r"(?<![A-Za-z_0-9])(?:0[xX][0-9a-fA-F]+|\d+)", expression
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


def macro_authority_escapes(
    files: dict[str, str], role_owners: set[str],
) -> set[tuple[str, str]]:
    escapes = set()
    for path in role_owners:
        closure = project_include_closure(files, {path})
        relevant = tuple(sorted(
            (candidate, files[candidate]) for candidate in closure
            if candidate.endswith((".c", ".h", ".cc", ".cpp"))
        ))
        escapes.update(cached_macro_authority_escapes_for_owner(
            path, relevant,
        ))
    return escapes


@functools.lru_cache(maxsize=512)
def cached_macro_authority_escapes_for_owner(
    owner: str, relevant: tuple[tuple[str, str], ...],
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
    conditional_groups: list[dict[str, set[str]]] = []
    for path, text in files.items():
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
    for profile in profile_variants:
        definitions: dict[str, MacroDefinition] = {
            name: (None, value) for name, value in profile.items()
        }
        escapes.update(scan_macro_environment(
            files, owner, definitions, set(), True, False, set(),
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


def source_may_introduce_raw_authority(
    source: str, raw_names: set[str],
) -> bool:
    raw_token = re.compile(
        r"(?:->|\.)\s*(?:conn|db|connection)\b|\bduckdb_|\b(?:"
        + "|".join(map(re.escape, sorted(raw_names))) + r")\b"
    )
    return "##" in source or raw_token.search(source) is not None \
        or bool(source_function_spans(source))


def source_inventory_profiles(
    files: dict[str, str], path: str, role_owners: set[str],
    raw_names: set[str],
) -> list[dict[str, str]]:
    closure = project_include_closure(files, {path})
    relevant = tuple(sorted(
        (candidate, files[candidate]) for candidate in closure
        if candidate.endswith((".c", ".h", ".cc", ".cpp"))
    ))
    return list(cached_source_inventory_profiles(
        path, relevant, tuple(sorted(raw_names)),
    ))


@functools.lru_cache(maxsize=512)
def cached_source_inventory_profiles(
    path: str, relevant: tuple[tuple[str, str], ...],
    raw_names: tuple[str, ...],
) -> tuple[dict[str, str], ...]:
    files = dict(relevant)
    raw_name_set = set(raw_names)
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
        if not source_may_introduce_raw_authority(
            files[candidate], raw_name_set
        ):
            continue
        for name, values in external_condition_values(files[candidate]).items():
            if name not in fixed | root_definitions | {"__cplusplus"}:
                root_options.setdefault(name, set()).update(values)
    return tuple(profile_value_variants(root_options, fixed))


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
    duckdb_function_names: set[str], role_owners: set[str],
    raw_names: set[str],
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
    for path in role_owners:
        for profile in source_inventory_profiles(
            files, path, role_owners, raw_names
        ):
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

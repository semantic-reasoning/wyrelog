#!/usr/bin/env python3
"""Guard that no test reports failure with a code the shell turns into zero.

The tests in this tree report failure by returning an integer from main(), and
the shell sees only its low byte.  A nonzero code that is a multiple of 256
therefore arrives as exit status 0, and meson records the run as Ok -- a
failing assertion reporting success.  Eleven files carried such a code before
this guard existed (#1066).

Scope is deliberately narrow.  Codes that merely *collide* after truncation
cost diagnosability, not correctness: the test still fails, you just cannot
tell which assertion fired.  That is #1067's problem and is not checked here,
because fixing it means renumbering hundreds of codes into a 255-slot space
that the larger files cannot fit into.

The source-flow extension resolves explicitly authored integer literals,
aliases, bounded arithmetic, and conditional joins assigned to returned local
integers. Opaque runtime/API values and caller/loop-derived domains are counted
as unclassified, not considered safe; #1066 remains open until those domains
are reviewed.
"""

from __future__ import annotations

import ast
from bisect import bisect_right
from itertools import product
from pathlib import Path
import re
import sys


SOURCES = "tests/test-*.c"
# Both forms a failure code reaches main() by.  A return-only pattern misses
# "rc = 2560; goto out;", which is how one of the original eleven was written
# and why two separate enumerations of this defect undercounted it.
FAILURE_CODE = re.compile(
    r"\b(?:return|(?:rc|ret|result|status|code)\s*=)\s*(\d+)\s*;")
INTEGER_DECLARATION = re.compile(
    r"\b(?:(?:const|volatile|static|register)\s+)*"
    r"(?:(?:unsigned|signed)\s+)?"
    r"(?:char|short|int|long|bool|_Bool|gboolean|gint(?:8|16|32|64)?|"
    r"guint(?:8|16|32|64)?|gsize|gssize|size_t|ssize_t|"
    r"u?int(?:8|16|32|64)_t|pid_t|uid_t|gid_t|wyrelog_error_t)\b"
    r"(?:\s+(?:unsigned|signed|long|int))*\s+"
    r"([A-Za-z_]\w*)\s*(?=[=;,)|\[])")
ASSIGNMENT = re.compile(r"\b([A-Za-z_]\w*)\s*=(?!=)\s*([^;]+);")
COMPOUND_ASSIGNMENT = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:\+=|-=|\*=|/=|%=|\+\+|--)"
    r"|(?:\+\+|--)\s*([A-Za-z_]\w*)\b")
RETURN = re.compile(r"\breturn\s+([^;]+);")
RETURN_TOKEN = re.compile(r"\breturn\b")
STATUS_SANITIZER_BINDING = re.compile(
    r"(?m)^[ \t]*#[ \t]*(?:define|undef)[ \t]+"
    r"(?:wyl_test_normalize_exit_status|WYL_TEST__EXIT|WYL_TEST_EXIT)\b")
TRIGRAPHS_C17 = {
    "??=": "#", "??/": "\\", "??'": "^", "??(": "[",
    "??)": "]", "??!": "|", "??<": "{", "??>": "}",
    "??-": "~",
}
INTEGER_CAST = re.compile(
    r"\(\s*(?:g?u?int(?:8|16|32|64)?|"
    r"int|unsigned(?:\s+int)?|signed(?:\s+int)?|long(?:\s+int)?|"
    r"short(?:\s+int)?)\s*\)")
C_INTEGER_LITERAL = re.compile(
    r"(?<![A-Za-z_\w])(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)"
    r"(?:[uU](?:ll|LL|l|L)?|(?:ll|LL|l|L)[uU]?)?(?![A-Za-z_\w])")

INTEGER_TYPE_INFO: dict[str, tuple[int, bool]] = {
    "gchar": (8, True), "guchar": (8, False),
    "gint8": (8, True), "guint8": (8, False),
    "gint16": (16, True), "guint16": (16, False),
    "gint32": (32, True), "guint32": (32, False),
    "gint64": (64, True), "guint64": (64, False),
    "int8_t": (8, True), "uint8_t": (8, False),
    "int16_t": (16, True), "uint16_t": (16, False),
    "int32_t": (32, True), "uint32_t": (32, False),
    "int64_t": (64, True), "uint64_t": (64, False),
    "gint": (32, True), "guint": (32, False),
    "gboolean": (32, True), "bool": (1, False), "_Bool": (1, False),
    "int": (32, True), "unsigned": (32, False),
    "unsigned int": (32, False), "signed": (32, True),
    "signed int": (32, True), "long long": (64, True),
    "long long int": (64, True), "unsigned long long": (64, False),
    "unsigned long long int": (64, False), "short": (16, True),
    "short int": (16, True), "unsigned short": (16, False),
    "unsigned short int": (16, False),
    "wyrelog_error_t": (32, True),
}


def _c_integer_value(token: str) -> int:
  """Parse the supported C integer spelling without Python's octal rules."""
  suffix = re.search(r"(?i)(?:u(?:ll|l)?|(?:ll|l)u?)$", token)
  digits = token[:suffix.start()] if suffix else token
  if digits.lower().startswith("0x"):
    return int(digits[2:], 16)
  if len(digits) > 1 and digits.startswith("0"):
    return int(digits[1:] or "0", 8)
  return int(digits, 10)


def _normalise_c_integer_literals(expression: str) -> str:
  return C_INTEGER_LITERAL.sub(
      lambda match: str(_c_integer_value(match.group(0))), expression)


def _convert_integer_values(values: set[int], c_type: str
    ) -> set[int]:
  normalized = " ".join(c_type.split())
  info = INTEGER_TYPE_INFO.get(normalized)
  if info is None:
    raise ValueError(f"unmodelled integer type: {normalized}")
  width, signed = info
  modulus = 1 << width
  converted = {value % modulus for value in values}
  if signed:
    minimum, maximum = -(1 << (width - 1)), (1 << (width - 1)) - 1
    for value in values:
      if value < minimum or value > maximum:
        raise ValueError(f"out-of-range signed conversion to {normalized}")
    converted = {value if value < (1 << (width - 1))
        else value - modulus for value in converted}
  return converted


def mask_noncode(text: str, preserve_literals: bool = False) -> str:
  """Blank comments and string/character literals without moving lines."""
  output: list[str] = []
  index = 0
  state = "code"
  while index < len(text):
    char = text[index]
    following = text[index + 1] if index + 1 < len(text) else ""
    if state == "code":
      if char == "/" and following in ("/", "*"):
        output.extend((" ", " "))
        state = "line" if following == "/" else "block"
        index += 2
        continue
      if char in ('"', "'"):
        output.append(char if preserve_literals else " ")
        state = "string" if char == '"' else "character"
        index += 1
        continue
      output.append(char)
      index += 1
      continue
    if state == "line":
      output.append("\n" if char == "\n" else " ")
      if char == "\n":
        state = "code"
      index += 1
      continue
    if state == "block":
      if char == "*" and following == "/":
        output.extend((" ", " "))
        index += 2
        state = "code"
      else:
        output.append("\n" if char == "\n" else " ")
        index += 1
      continue
    output.append("\n" if char == "\n" else
        (char if preserve_literals else " "))
    if char == "\\" and index + 1 < len(text):
      output.append("\n" if text[index + 1] == "\n" else
          (text[index + 1] if preserve_literals else " "))
      index += 2
      continue
    if (state == "string" and char == '"') or (
        state == "character" and char == "'"):
      state = "code"
    index += 1
  return "".join(output)


def c_logical_source(text: str, language: str
    ) -> tuple[str, list[int]]:
  """Apply language-specific trigraph and line-splicing phases with offsets."""
  if language not in {"c17", "c++17"}:
    raise ValueError(f"unsupported C/C++ language mode: {language}")
  translated: list[str] = []
  offsets: list[int] = []
  index = 0
  while index < len(text):
    trigraph = text[index:index + 3]
    replacement = (TRIGRAPHS_C17.get(trigraph)
        if language == "c17" else None)
    if replacement is not None:
      translated.append(replacement)
      offsets.append(index)
      index += 3
    else:
      translated.append(text[index])
      offsets.append(index)
      index += 1

  logical: list[str] = []
  logical_offsets: list[int] = []
  index = 0
  while index < len(translated):
    if translated[index] == "\\" and index + 1 < len(translated):
      if translated[index + 1] == "\n":
        index += 2
        continue
      if (translated[index + 1] == "\r" and index + 2 < len(translated)
          and translated[index + 2] == "\n"):
        index += 3
        continue
      if translated[index + 1] == "\r":
        index += 2
        continue
    logical.append(translated[index])
    logical_offsets.append(offsets[index])
    index += 1
  return "".join(logical), logical_offsets


def c17_logical_source(text: str) -> tuple[str, list[int]]:
  return c_logical_source(text, "c17")


def source_language(path: str) -> str:
  suffix = Path(path).suffix
  if suffix == ".c":
    return "c17"
  if suffix in {".cc", ".cpp"}:
    return "c++17"
  raise ValueError(f"unsupported test translation-unit extension: {suffix or '(none)'}")


def original_offset(offsets: list[int], logical_index: int,
    source_length: int) -> int:
  if not offsets:
    return 0
  if logical_index >= len(offsets):
    return source_length
  return offsets[max(0, logical_index)]


def offenders(text: str) -> list[int]:
  """Nonzero failure codes in |text| that truncate to exit status 0."""
  found = {int(raw) for raw in FAILURE_CODE.findall(text)}
  return sorted(code for code in found if code and code % 256 == 0)


def function_ranges(masked: str) -> list[tuple[str, int, int, int]]:
  """Return ordinary C function ranges for bounded local-flow analysis."""
  closing: dict[int, int] = {}
  stack: list[int] = []
  for offset, char in enumerate(masked):
    if char == "{":
      stack.append(offset)
    elif char == "}" and stack:
      closing[stack.pop()] = offset
  opening = re.compile(
      r"(?m)^[ \t]*(?:static\s+)?(?:[A-Za-z_]\w*[\s*]+)+"
      r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{")
  functions = []
  for match in opening.finditer(masked):
    name = match.group("name")
    brace = match.end() - 1
    if name not in {"if", "for", "while", "switch", "sizeof"} \
        and brace in closing:
      functions.append((name, match.start(), match.end(), closing[brace]))
  return functions


def _same_integer_value_type(left: str | None, right: str | None) -> bool:
  if left is None or right is None:
    return False
  left_info = INTEGER_TYPE_INFO.get(" ".join(left.split()))
  right_info = INTEGER_TYPE_INFO.get(" ".join(right.split()))
  return left_info is not None and left_info == right_info


def _function_parameter_constants(masked: str, name: str, start: int,
    body_start: int, base: dict[str, set[int]]) -> dict[str, set[int]]:
  constants = dict(base)
  prefix = masked[start:body_start]
  opening = prefix.find("(", prefix.find(name) + len(name))
  if opening >= 0:
    try:
      closing = _matching_delimiter(prefix, opening, "(", ")")
    except ValueError:
      closing = opening
    parameters = prefix[opening + 1:closing]
    for parameter in parameters.split(","):
      identifier = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*$",
          parameter.strip())
      if identifier and identifier.group(1) != "void":
        constants.pop(identifier.group(1), None)

  return constants


def _eval_integer_node(node: ast.AST,
    bindings: dict[str, set[int]]) -> set[int]:
  if isinstance(node, ast.Constant) and isinstance(node.value, int):
    return {node.value}
  if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
      and node.func.id == "wyl_test_normalize_exit_status"
      and len(node.args) == 1 and not node.keywords):
    values = _eval_integer_node(node.args[0], bindings)
    return {1 if value != 0 else 0
        for value in values}
  if isinstance(node, ast.Name) and node.id in bindings:
    return set(bindings[node.id])
  if isinstance(node, ast.UnaryOp) and isinstance(node.op,
      (ast.UAdd, ast.USub)):
    values = _eval_integer_node(node.operand, bindings)
    return values if isinstance(node.op, ast.UAdd) else {-value for value in values}
  if isinstance(node, ast.BinOp) and isinstance(node.op,
      (ast.Add, ast.Sub)):
    left = _eval_integer_node(node.left, bindings)
    right = _eval_integer_node(node.right, bindings)
    if isinstance(node.op, ast.Add):
      values = {a + b for a, b in product(left, right)}
    else:
      values = {a - b for a, b in product(left, right)}
    if len(values) > 256:
      raise ValueError("finite integer domain exceeds 256 values")
    if any(value < -(1 << 31) or value >= (1 << 31)
        for value in values):
      raise ValueError("arithmetic exceeds the modeled signed-int range")
    return values
  raise ValueError(f"unsupported integer expression: {ast.dump(node)}")


def _outer_parens(expression: str) -> str:
  expression = expression.strip()
  while expression.startswith("(") and expression.endswith(")"):
    depth = 0
    encloses_all = True
    for index, char in enumerate(expression):
      if char == "(":
        depth += 1
      elif char == ")":
        depth -= 1
        if depth == 0 and index != len(expression) - 1:
          encloses_all = False
          break
    if not encloses_all:
      break
    expression = expression[1:-1].strip()
  return expression


def finite_c_values(expression: str,
    bindings: dict[str, set[int]]) -> set[int]:
  """Evaluate literals, aliases, bounded arithmetic, and ?: joins only."""
  expression = _outer_parens(expression)
  cast_matches = list(INTEGER_CAST.finditer(expression))
  cast_types: list[str] = []
  if cast_matches:
    if len(cast_matches) != 1 or cast_matches[0].start() != 0:
      raise ValueError("cast is not a supported whole-expression conversion")
    cast = cast_matches[0]
    cast_type = " ".join(cast.group(0)[1:-1].split())
    operand_start = cast.end()
    while operand_start < len(expression) and expression[operand_start].isspace():
      operand_start += 1
    if operand_start < len(expression) and expression[operand_start] == "(":
      operand_end = _matching_delimiter(expression, operand_start, "(", ")")
      if expression[operand_end + 1:].strip():
        raise ValueError("cast expression must enclose the full value")
      expression = expression[operand_start + 1:operand_end]
    else:
      operand = expression[operand_start:]
      if not re.fullmatch(
          r"[+-]?(?:[A-Za-z_]\w*|"
          r"(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)"
          r"(?:[uU](?:ll|LL|l|L)?|(?:ll|LL|l|L)[uU]?)?)", operand):
        raise ValueError("cast operand is outside the supported grammar")
      expression = operand
    cast_types.append(cast_type)
  expression = _normalise_c_integer_literals(expression)
  expression = _outer_parens(expression)
  depth = 0
  question = -1
  nested = 0
  for index, char in enumerate(expression):
    if char in "([":
      depth += 1
    elif char in ")]":
      depth -= 1
    elif depth == 0 and char == "?":
      if question < 0:
        question = index
      else:
        nested += 1
    elif depth == 0 and char == ":" and question >= 0:
      if nested:
        nested -= 1
      else:
        values = (finite_c_values(expression[question + 1:index], bindings)
            | finite_c_values(expression[index + 1:], bindings))
        if len(values) > 256:
          raise ValueError("conditional domain exceeds 256 values")
        return values
  values = _eval_integer_node(ast.parse(expression.replace("/", "//"),
      mode="eval").body, bindings)
  for c_type in reversed(cast_types):
    values = _convert_integer_values(values, c_type)
  return values


def has_top_level_operator(expression: str) -> bool:
  expression = _outer_parens(INTEGER_CAST.sub("", expression))
  depth = 0
  for index, char in enumerate(expression):
    if char in "([":
      depth += 1
    elif char in ")]":
      depth -= 1
    elif depth == 0 and char in "+-*/%?:":
      if char == "-" and index > 0 and expression[index - 1] == ">":
        continue
      return True
  return False


def _status_normalizer_argument(expression: str) -> str | None:
  """Return the argument when expression is exactly the status sanitizer."""
  expression = _outer_parens(expression.strip())
  match = re.match(
      r"wyl_test_normalize_exit_status(?:_named)?\s*\(", expression)
  if match is None:
    return None
  opening = expression.find("(", match.start(), match.end())
  try:
    closing = _matching_delimiter(expression, opening, "(", ")")
  except ValueError:
    return None
  if expression[closing + 1:].strip():
    return None
  arguments = expression[opening + 1:closing].strip()
  if expression[match.start():].startswith("wyl_test_normalize_exit_status_named"):
    depth = 0
    for index, character in enumerate(arguments):
      if character == "(":
        depth += 1
      elif character == ")":
        depth -= 1
      elif character == "," and depth == 0:
        return arguments[index + 1:].strip()
    return None
  return arguments


def _status_normalizer_contract_valid(root: Path) -> bool:
  """Recognize only the audited POSIX normalizer implementation."""
  try:
    header = (root / "tests/test-exit-status.h").read_text(
        encoding="utf-8", errors="replace")
  except OSError:
    return False
  normalized = " ".join(mask_noncode(header).split())
  return re.search(
      r"\bstatic\s+inline\s+int\s+wyl_test_report_exit_status\s*"
      r"\([^)]*\)\s*\{.*?if\s*\(\s*status\s*==\s*0\s*\)\s*"
      r"return\s+0\s*;.*?return\s+1\s*;\s*\}.*?"
      r"#define\s+wyl_test_normalize_exit_status\s*\([^)]*\)\s*.*?"
      r"wyl_test_report_exit_status", normalized) is not None


def _status_propagation_to_main(functions: list[tuple[str, int, int, int]],
    masked: str, condition_constants: dict[str, set[int]],
    normalizer_verified: bool, source_line=None
    ) -> tuple[dict[str, str], dict[str, int]]:
  """Find helpers whose unsanitized return value can reach main."""
  names = {function[0] for function in functions}
  function_return_types = {name: _function_return_type(
      masked, start, body_start, name)
      for name, start, body_start, _body_end in functions}
  local_types: dict[str, dict[str, str | None]] = {}
  for name, _start, body_start, body_end in functions:
    types: dict[str, str | None] = {}
    body = masked[body_start:body_end]
    for declaration in INTEGER_DECLARATION.finditer(body):
      variable = declaration.group(1)
      type_text = body[declaration.start():declaration.start(1)]
      c_type = re.sub(r"\b(?:const|volatile|static|register)\b", "",
          type_text).strip()
      c_type = " ".join(c_type.split())
      if variable in types:
        types[variable] = None
      else:
        types[variable] = c_type
    local_types[name] = types
  target_names = sorted(names, key=lambda name: (-len(name), name))
  target_call = (re.compile(r"\b(" + "|".join(map(re.escape, target_names))
      + r")\s*\(") if target_names else None)
  callees: dict[str, set[tuple[str, bool]]] = {}
  for name, _start, body_start, body_end in functions:
    body = masked[body_start:body_end]
    constants = dict(condition_constants)
    macros, touched_macros, function_macros = _parse_integer_macros(
        masked[:_start], condition_constants)
    for macro in touched_macros:
      constants.pop(macro, None)
    constants.update(macros)
    constants = _function_parameter_constants(
        masked, name, _start, body_start, constants)
    return_sites, assignment_sites, conditional_assignment_calls = \
        _status_flow_sites(
        masked, body_start, body_end, constants, function_macros)
    if target_call is None:
      continue
    for call in target_call.finditer(body):
      target = call.group(1)
      if target == name:
        continue
      if not _same_integer_value_type(function_return_types.get(name),
          function_return_types.get(target)):
        continue
      opening = body.find("(", call.start(), call.end())
      try:
        closing = _matching_delimiter(body, opening, "(", ")")
      except ValueError:
        continue
      prefix = body[:call.start()]
      absolute_call = body_start + call.start()
      if call.start() in conditional_assignment_calls and \
          _same_integer_value_type(local_types[name].get(
              conditional_assignment_calls[call.start()]),
              function_return_types.get(target)):
        variable = conditional_assignment_calls[call.start()]
        sanitized = False
        if normalizer_verified:
          absolute_after_call = body_start + closing + 1
          for site_start, _site_end, expression in return_sites:
            if (site_start > absolute_after_call and
                _outer_parens(_status_normalizer_argument(expression) or "")
                == variable):
              intervening = masked[absolute_after_call:site_start]
              if not re.search(r"\b" + re.escape(variable) +
                  r"\s*(?:=(?!=)|\+=|-=|\*=|/=|%=|\+\+|--)",
                  intervening):
                sanitized = True
                break
        callees.setdefault(name, set()).add((target, sanitized))
      direct_return = any(site_start <= absolute_call < site_end
          and re.search(
              r"\breturn\s+(?:wyl_test_normalize_exit_status\s*\(\s*)?\(*\s*$",
              masked[site_start:absolute_call]) is not None
          and re.fullmatch(r"\s*\)*\s*;?\s*",
              masked[body_start + closing + 1:site_end]) is not None
          for site_start, site_end, _expression in return_sites)
      direct_sanitized_return = (normalizer_verified and direct_return and
          any(site_start <= absolute_call < site_end and
              _status_normalizer_argument(expression) is not None
              for site_start, site_end, expression in return_sites))
      exact_assignment = False
      sanitized_assignment = False
      assignment_site = next(((site_start, site_end)
          for site_start, site_end in assignment_sites
          if site_start <= absolute_call < site_end), None)
      if assignment_site is not None:
        site_start, site_end = assignment_site
        statement_prefix = masked[site_start:absolute_call]
        assignment = re.search(
            r"\b([A-Za-z_]\w*)\s*=(?!=)\s*\(*\s*$",
            statement_prefix)
        statement_end = site_end - 1
        suffix = masked[body_start + closing + 1:site_end]
        if (assignment is not None and
            re.fullmatch(r"\s*\)*\s*;?\s*", suffix) is not None and
            suffix.count(")") == assignment.group(0).count("(")):
          variable = assignment.group(1)
          if not _same_integer_value_type(local_types[name].get(variable),
              function_return_types.get(target)):
            continue
          tail = masked[body_start + closing + 1:body_end]
          returned = re.search(r"\breturn\s+" + re.escape(variable)
              + r"\s*;", tail)
          if returned is not None:
            before_return = tail[:returned.start()]
            overwritten = re.search(r"\b" + re.escape(variable)
                + r"\s*(?:=(?!=)|\+=|-=|\*=|/=|%=|\+\+|--)",
                before_return)
            escaped = re.search(r"&\s*" + re.escape(variable) + r"\b",
                body[:body_start + closing + 1 + returned.start()])
            returned_absolute = body_start + closing + 1 + returned.start()
            reachable_return = any(site_start <= returned_absolute < site_end
                and expression.strip() == variable
                for site_start, site_end, expression in return_sites)
            returned_through_normalizer = (normalizer_verified and any(
                site_start <= returned_absolute < site_end and
                _outer_parens(_status_normalizer_argument(expression) or "")
                == variable
                for site_start, site_end, expression in return_sites))
            assignment_text = (masked[site_start:site_end]
                if assignment_site is not None else "")
            assignment_expression = re.search(
                r"\b" + re.escape(variable)
                + r"\s*=(?!=)\s*(.*?)\s*;?\s*$",
                assignment_text, re.S)
            assigned_through_normalizer = (normalizer_verified and
                _status_normalizer_argument(
                    assignment_expression.group(1)
                    if assignment_expression else "") is not None)
            exact_assignment = (overwritten is None and escaped is None
                and (reachable_return or returned_through_normalizer)
                and returned_absolute > statement_end)
            sanitized_assignment = (exact_assignment and
                (returned_through_normalizer or assigned_through_normalizer))
      if direct_return or exact_assignment:
        callees.setdefault(name, set()).add((target,
            direct_sanitized_return or sanitized_assignment))

  # Callback registrations establish invocation, but not status-value flow.
  # The caller separately reports incompatible callback/destructor signatures
  # as unresolved instead of treating them as process exits.
  callback_roots: dict[str, int] = {}
  registrations = re.compile(
      r"\b(g_test_add_func|g_test_add_data_func|"
      r"g_test_add_data_func_full|g_test_add)\s*\(")
  for match in registrations.finditer(masked):
    opening = masked.find("(", match.start(), match.end())
    try:
      closing = _matching_delimiter(masked, opening, "(", ")")
    except ValueError:
      continue
    arguments: list[str] = []
    argument_start = opening + 1
    depth = 0
    for index in range(argument_start, closing):
      char = masked[index]
      if char in "([{":
        depth += 1
      elif char in ")]}":
        depth -= 1
      elif char == "," and depth == 0:
        arguments.append(masked[argument_start:index])
        argument_start = index + 1
    arguments.append(masked[argument_start:closing])
    registration = match.group(1)
    callback_indexes = ({3, 4, 5} if registration == "g_test_add"
        else {2, 3} if registration == "g_test_add_data_func_full"
        else {2} if registration == "g_test_add_data_func" else {1})
    for index in callback_indexes:
      if index >= len(arguments):
        continue
      argument = arguments[index]
      for target in re.findall(r"\b[A-Za-z_]\w*\b", argument):
        if target in names:
          callback_roots[target] = (source_line(match.start()) if source_line
              else _source_line(masked, match.start()))
  chains = {"main": "main"}
  queue = ["main"]
  while queue:
    current = queue.pop(0)
    for target, sanitized in sorted(callees.get(current, ())):
      if sanitized:
        continue
      if target not in chains:
        chains[target] = f"{target} -> {chains[current]}"
        queue.append(target)
  return chains, callback_roots


def _known_function_return_domains(functions: list[tuple[str, int, int, int]],
    masked: str, constants: dict[str, set[int]]) -> dict[str, set[int] | None]:
  """Summarize simple finite helper returns for interprocedural call sites."""
  by_name = {name: (start, body_start, body_end)
      for name, start, body_start, body_end in functions}
  cache: dict[str, set[int] | None] = {}
  active: set[str] = set()

  def summarize(name: str) -> set[int] | None:
    if name in cache:
      value = cache[name]
      return None if value is None else set(value)
    if name in active or name not in by_name:
      return None
    active.add(name)
    start, body_start, body_end = by_name[name]
    function_constants, touched, function_macros = _parse_integer_macros(
        masked[:start], constants)
    condition_constants = dict(constants)
    for macro in touched:
      condition_constants.pop(macro, None)
    condition_constants.update(function_constants)
    condition_constants = _function_parameter_constants(
        masked, name, start, body_start, condition_constants)
    sites, _assignments, _conditional_calls = _status_flow_sites(
        masked, body_start, body_end, condition_constants, function_macros)
    return_type = _function_return_type(masked, start, body_start, name)
    result: set[int] = set()
    body = masked[body_start:body_end]
    complete = bool(sites) or RETURN_TOKEN.search(body) is not None
    for _site_start, _site_end, expression in sites:
      try:
        values = finite_c_values(expression, condition_constants)
      except (SyntaxError, ValueError, ZeroDivisionError):
        direct_call = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*\(\s*\)\s*",
            expression)
        values = (summarize(direct_call.group(1)) if direct_call else None)
        if values is None:
          complete = False
          break
      try:
        if return_type in INTEGER_TYPE_INFO:
          values = _convert_stored_values(values, return_type)
        elif return_type and return_type.startswith("enum "):
          values = _convert_stored_values(values, "int")
      except ValueError:
        complete = False
        break
      result.update(values)
      if len(result) > 256:
        complete = False
        break
    active.remove(name)
    cache[name] = result if complete else None
    value = cache[name]
    return None if value is None else set(value)

  for function_name, _start, _body_start, _body_end in functions:
    summarize(function_name)
  return cache


def _known_call_result(expression: str,
    summaries: dict[str, set[int] | None]) -> set[int] | None:
  """Resolve a direct finite helper call, preserving the sanitizer contract."""
  normalized_argument = _status_normalizer_argument(expression)
  if normalized_argument is not None:
    inner = normalized_argument
    direct_call = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*\(\s*\)\s*", inner)
    if direct_call is None:
      return None
    values = summaries.get(direct_call.group(1))
    if values is None:
      return None
    return {1 if value != 0 else 0
        for value in values}
  direct_call = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*\(\s*\)\s*",
      expression)
  if direct_call is None:
    return None
  values = summaries.get(direct_call.group(1))
  return None if values is None else set(values)


_LINE_INDEX: dict[int, tuple[str, list[int]]] = {}


def _source_line(text: str, offset: int) -> int:
  cached = _LINE_INDEX.get(id(text))
  if cached is None or cached[0] is not text:
    starts = [0]
    starts.extend(index + 1 for index, char in enumerate(text)
        if char == "\n")
    _LINE_INDEX[id(text)] = (text, starts)
  else:
    starts = cached[1]
  return bisect_right(starts, offset)


def _matching_delimiter(text: str, start: int, opening: str,
    closing: str) -> int:
  depth = 0
  for index in range(start, len(text)):
    if text[index] == opening:
      depth += 1
    elif text[index] == closing:
      depth -= 1
      if depth == 0:
        return index
  raise ValueError(f"unclosed {opening}")


def _parse_statements(text: str, offset: int = 0
    ) -> tuple[list[dict[str, object]], int]:
  """Parse the small statement subset whose local flows we model."""
  statements: list[dict[str, object]] = []
  index = offset
  while index < len(text):
    while index < len(text) and text[index].isspace():
      index += 1
    if index >= len(text) or text[index] == "}":
      return statements, index
    node, index = _parse_one_statement(text, index)
    statements.append(node)
  return statements, index


def _parse_one_statement(text: str, offset: int
    ) -> tuple[dict[str, object], int]:
  index = offset
  while index < len(text) and text[index].isspace():
    index += 1
  if index >= len(text):
    return {"kind": "simple", "start": offset, "end": index,
        "text": ""}, index
  start = index
  if text[index] == "{":
    nested, end = _parse_statements(text, index + 1)
    if end >= len(text) or text[end] != "}":
      raise ValueError("unclosed compound statement")
    return {"kind": "block", "start": start, "end": end + 1,
        "children": nested}, end + 1
  keyword = re.match(r"(?:if|for|while|switch|do)\b", text[index:])
  if keyword:
    kind = keyword.group(0)
    index += keyword.end()
    while index < len(text) and text[index].isspace():
      index += 1
    condition = ""
    if kind != "do" and index < len(text) and text[index] == "(":
      close = _matching_delimiter(text, index, "(", ")")
      condition = text[index + 1:close].strip()
      index = close + 1
    first_node, index = _parse_one_statement(text, index)
    second: list[dict[str, object]] = []
    if kind == "if":
      checkpoint = index
      while checkpoint < len(text) and text[checkpoint].isspace():
        checkpoint += 1
      if re.match(r"else\b", text[checkpoint:]):
        second_node, index = _parse_one_statement(
            text, checkpoint + len("else"))
        second = [second_node]
    return ({"kind": "if" if kind == "if" else "unsupported",
        "control": kind, "condition": condition, "start": start,
        "end": index,
        "first": [first_node], "second": second}, index)
  if re.match(r"return\b", text[index:]):
    index += len("return")
    end = _statement_end(text, index)
    expression = text[index:end].strip()
    return ({"kind": "return", "start": start, "end": end + 1,
        "expression": expression}, end + 1 if end < len(text) else end)
  end = _statement_end(text, index)
  return ({"kind": "simple", "start": start, "end": end + 1,
      "text": text[index:end].strip()}, end + 1 if end < len(text) else end)


def _status_flow_sites(text: str, body_start: int, body_end: int,
    condition_constants: dict[str, set[int]],
    function_macros: dict[str, tuple[tuple[str, ...], str]]
    ) -> tuple[list[tuple[int, int, str]], list[tuple[int, int]], set[int]]:
  """Return reachable returns and unconditional simple-statement ranges."""
  try:
    statements, _end = _parse_statements(text[:body_end], body_start)
  except ValueError:
    return [], [], set()
  returns: list[tuple[int, int, str]] = []
  assignments: list[tuple[int, int]] = []
  conditional_assignment_calls: dict[int, str] = {}

  def written_names(nodes: list[dict[str, object]]) -> set[str]:
    written: set[str] = set()
    for node in nodes:
      kind = str(node["kind"])
      if kind == "simple":
        simple_text = str(node.get("text", ""))
        declaration = INTEGER_DECLARATION.match(simple_text)
        if declaration is None:
          for left, right in re.findall(
              r"\b([A-Za-z_]\w*)\s*(?:=(?!=)|\+=|-=|\*=|/=|%=|\+\+|--)"
              r"|(?:\+\+|--)\s*([A-Za-z_]\w*)\b", simple_text):
            written.add(left or right)
      elif kind == "if":
        condition = str(node["condition"])
        written.update(re.findall(
            r"\b([A-Za-z_]\w*)\s*=(?!=)", condition))
        first = node["first"]
        second = node["second"]
        assert isinstance(first, list) and isinstance(second, list)
        written.update(written_names(first))
        written.update(written_names(second))
      elif kind == "block":
        children = node["children"]
        assert isinstance(children, list)
        written.update(written_names(children))
    return {name for pair in written for name in
        (pair if isinstance(pair, tuple) else (pair,))}

  def visit(nodes: list[dict[str, object]], controlled: bool = False,
      active_constants: dict[str, set[int]] | None = None) -> bool:
    active = dict(condition_constants if active_constants is None
        else active_constants)
    reachable = True
    for node in nodes:
      if not reachable:
        break
      kind = str(node["kind"])
      start = int(node["start"])
      if kind == "return":
        end = _statement_end(text, start) + 1
        returns.append((start, end, str(node["expression"])))
        reachable = False
      elif kind == "simple":
        end = _statement_end(text, start) + 1
        if not controlled:
          assignments.append((start, end))
        simple_text = str(node.get("text", ""))
        declaration = INTEGER_DECLARATION.match(simple_text)
        if declaration is not None:
          variable = declaration.group(1)
          active.pop(variable, None)
          initializer = re.match(r"\s*=\s*([^;,]+)",
              simple_text[declaration.end():])
          if initializer is not None:
            try:
              values = finite_c_values(initializer.group(1), active)
              type_text = simple_text[:declaration.start(1)]
              c_type = " ".join(re.sub(
                  r"\b(?:const|volatile|static|register)\b", "",
                  type_text).split())
              active[variable] = _convert_stored_values(values, c_type)
            except (SyntaxError, ValueError, ZeroDivisionError):
              pass
        else:
          assigned = re.match(r"\s*([A-Za-z_]\w*)\s*(?:=(?!=)|\+=|-=|"
              r"\*=|/=|%=|\+\+|--)", simple_text)
          if assigned is not None:
            active.pop(assigned.group(1), None)
        if re.match(r"\s*(?:goto\b|break\b|continue\b|"
            r"[A-Za-z_]\w*\s*:)", simple_text):
          reachable = False
      elif kind == "block":
        children = node["children"]
        assert isinstance(children, list)
        child_constants = dict(active)
        if visit(children, controlled, child_constants):
          reachable = False
        for variable in written_names(children):
          active.pop(variable, None)
      elif kind == "if":
        first = node["first"]
        second = node["second"]
        assert isinstance(first, list) and isinstance(second, list)
        condition = str(node["condition"])
        if (len(first) == 1 and str(first[0]["kind"]) == "return" and
            not second):
          returned_variable = str(first[0]["expression"]).strip()
          normalized_return = re.fullmatch(
              r"wyl_test_normalize_exit_status\s*\(\s*([A-Za-z_]\w*)\s*\)",
              returned_variable)
          if normalized_return is not None:
            returned_variable = normalized_return.group(1)
          if re.fullmatch(r"[A-Za-z_]\w*", returned_variable):
            for call in re.finditer(r"\b[A-Za-z_]\w*\s*\(", condition):
              opening = condition.find("(", call.start(), call.end())
              try:
                closing = _matching_delimiter(condition, opening, "(", ")")
              except ValueError:
                continue
              prefix = condition[:call.start()]
              assignment = re.search(
                  r"\b([A-Za-z_]\w*)\s*=(?!=)\s*\(*\s*$", prefix)
              suffix = re.sub(r"^\)+", "", condition[closing + 1:].strip())
              suffix = re.sub(r"\)+$", "", suffix.strip()).strip()
              if (assignment is not None and
                  assignment.group(1) == returned_variable and
                  suffix in {"", "!= 0", "!=0"}):
                condition_open = text.find("(", start, body_end)
                conditional_assignment_calls[
                    condition_open + 1 + call.start() - body_start] = \
                    returned_variable
        condition_value: bool | None = None
        try:
          values = _constant_condition_values(condition, active,
              function_macros)
          if len(values) == 1:
            condition_value = bool(next(iter(values)))
        except (SyntaxError, ValueError, ZeroDivisionError):
          pass
        if condition_value is True:
          reachable = not visit(first, True, dict(active))
        elif condition_value is False:
          if second:
            reachable = not visit(second, True, dict(active))
        else:
          first_returns = visit(first, True, dict(active))
          second_returns = bool(second) and visit(second, True, dict(active))
          if first_returns and second_returns:
            reachable = False
        assigned_in_condition = re.findall(
            r"\b([A-Za-z_]\w*)\s*=(?!=)", condition)
        for variable in set(assigned_in_condition) | written_names(first) | \
            written_names(second):
          active.pop(variable, None)
      else:
        # Unsupported loops/switches can suppress or redirect later returns.
        # Keep the remainder unresolved instead of creating a status edge.
        reachable = False
    return not reachable

  visit(statements)
  return returns, assignments, conditional_assignment_calls


def _statement_end(text: str, start: int) -> int:
  depth = 0
  for index in range(start, len(text)):
    char = text[index]
    if char in "([":
      depth += 1
    elif char in ")]":
      depth -= 1
    elif char == ";" and depth == 0:
      return index
  return len(text)


def _parse_enums(masked: str, path: str, source_line=None
    ) -> tuple[dict[str, set[int]], set[str], list[str]]:
  constants: dict[str, set[int]] = {}
  tags: set[str] = set()
  unresolved: list[str] = []
  enum_pattern = re.compile(
      r"\benum(?:\s+([A-Za-z_]\w*))?\s*\{([^}]*)\}")
  for match in enum_pattern.finditer(masked):
    tag = match.group(1)
    if tag:
      tags.add(tag)
    current = -1
    valid = True
    for item in match.group(2).split(","):
      item = item.strip()
      if not item:
        continue
      enumerator = re.fullmatch(
          r"([A-Za-z_]\w*)\s*(?:=\s*(.+))?", item, re.S)
      if not enumerator:
        valid = False
        break
      name, expression = enumerator.groups()
      try:
        values = finite_c_values(expression, constants) if expression else {
            current + 1}
        if len(values) != 1:
          raise ValueError("enum expression is not a single constant")
        current = next(iter(values))
        if current < -(1 << 31) or current >= (1 << 31):
          raise ValueError("enum value is outside the supported int range")
      except (SyntaxError, ValueError, ZeroDivisionError):
        valid = False
        line = (source_line(match.start()) if source_line
            else _source_line(masked, match.start()))
        unresolved.append(f"{path}:{line}: function <enum {tag or 'anonymous'}>: "
            f"expression {item!r}: reason: unsupported enum initializer")
        break
      constants[name] = {current}
    if not valid:
      # Do not retain a prefix as if it were a complete enum definition.
      for item in match.group(2).split(","):
        name = item.strip().split("=", 1)[0].strip()
        constants.pop(name, None)
  return constants, tags, unresolved


def _parse_integer_macros(masked: str,
    constants: dict[str, set[int]]) -> tuple[dict[str, set[int]], set[str],
        dict[str, tuple[tuple[str, ...], str]]]:
  """Resolve simple object-like and function-like macros at this position."""
  directives = re.finditer(
      r"(?m)^\s*#\s*(define\s+([A-Za-z_]\w*)(\([^\n)]*\))?"
      r"(?:[ \t]+([^\n]*))?|undef\s+([A-Za-z_]\w*)\b|"
      r"if\b[^\n]*|ifdef\b[^\n]*|ifndef\b[^\n]*|"
      r"elif\b[^\n]*|else\b[^\n]*|endif\b[^\n]*)",
      masked)
  definitions: dict[str, str] = {}
  function_definitions: dict[str, tuple[tuple[str, ...], str]] = {}
  touched: set[str] = set()
  conditional_names: set[str] = set()
  conditional_depth = 0
  for directive in directives:
    full, defined_name, parameters, expression, undefined_name = \
        directive.groups()
    keyword = full.strip().split(None, 1)[0]
    if keyword in {"if", "ifdef", "ifndef"}:
      conditional_depth += 1
    elif keyword == "endif":
      conditional_depth = max(0, conditional_depth - 1)
    elif keyword in {"else", "elif"}:
      continue
    elif defined_name:
      touched.add(defined_name)
      if conditional_depth:
        conditional_names.add(defined_name)
        definitions.pop(defined_name, None)
        function_definitions.pop(defined_name, None)
      elif parameters is not None:
        function_definitions.pop(defined_name, None)
        params = tuple(item.strip() for item in parameters[1:-1].split(",")
            if item.strip())
        function_definitions[defined_name] = (params, expression or "")
        definitions.pop(defined_name, None)
      else:
        definitions[defined_name] = (expression or "").strip()
        function_definitions.pop(defined_name, None)
    elif undefined_name:
      touched.add(undefined_name)
      definitions.pop(undefined_name, None)
      function_definitions.pop(undefined_name, None)
      if conditional_depth:
        conditional_names.add(undefined_name)
  macros: dict[str, set[int]] = {}
  pending = {name: expression for name, expression in definitions.items()
      if name not in conditional_names}
  while pending:
    progress = False
    for name, expression in list(pending.items()):
      try:
        values = finite_c_values(expression, {**constants, **macros})
      except (SyntaxError, ValueError, ZeroDivisionError):
        continue
      if len(values) != 1:
        del pending[name]
        progress = True
        continue
      macros[name] = values
      del pending[name]
      progress = True
    if not progress:
      break
  return macros, touched | conditional_names, {
      name: definition for name, definition in function_definitions.items()
      if name not in conditional_names}


def _constant_condition_values(expression: str,
    constants: dict[str, set[int]],
    function_macros: dict[str, tuple[tuple[str, ...], str]]) -> set[int]:
  for _iteration in range(8):
    changed = False
    for name, (parameters, replacement) in function_macros.items():
      pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
      for match in reversed(list(pattern.finditer(expression))):
        opening = expression.find("(", match.start(), match.end())
        try:
          closing = _matching_delimiter(expression, opening, "(", ")")
        except ValueError:
          continue
        raw_arguments = expression[opening + 1:closing]
        arguments: list[str] = []
        argument_start = 0
        depth = 0
        for index, char in enumerate(raw_arguments):
          if char in "([{":
            depth += 1
          elif char in ")]}":
            depth -= 1
          elif char == "," and depth == 0:
            arguments.append(raw_arguments[argument_start:index].strip())
            argument_start = index + 1
        if raw_arguments.strip():
          arguments.append(raw_arguments[argument_start:].strip())
        if len(arguments) != len(parameters):
          continue
        expanded = replacement
        for parameter, argument in zip(parameters, arguments):
          expanded = re.sub(r"\b" + re.escape(parameter) + r"\b",
              "(" + argument + ")", expanded)
        changed = True
        expression = expression[:match.start()] + "(" + expanded + ")" \
            + expression[closing + 1:]
    if not changed:
      break
  try:
    return finite_c_values(expression, constants)
  except (SyntaxError, ValueError, ZeroDivisionError):
    comparison = re.fullmatch(r"\s*(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+?)\s*",
        expression)
    if comparison is None:
      raise
    left = finite_c_values(comparison.group(1), constants)
    right = finite_c_values(comparison.group(3), constants)
    operator = comparison.group(2)
    outcomes: set[bool] = set()
    for first in left:
      for second in right:
        outcomes.add(first == second if operator == "==" else
            first != second if operator == "!=" else
            first <= second if operator == "<=" else
            first >= second if operator == ">=" else
            first < second if operator == "<" else first > second)
    if len(outcomes) != 1:
      raise ValueError("condition is not a single truth value")
    return {int(next(iter(outcomes)))}


def _function_return_type(masked: str, start: int, body_start: int,
    name: str) -> str | None:
  header = masked[start:body_start]
  prefix = header.split(name, 1)[0].strip()
  prefix = re.sub(r"\b(?:static|inline|extern|const|volatile)\b", "",
      prefix).strip()
  return " ".join(prefix.split()) or None


def _nonintegral_return_type(c_type: str | None) -> bool:
  if c_type is None:
    return False
  normalized = " ".join(c_type.split())
  return (normalized in {"void", "float", "double", "gfloat", "gdouble"}
      or "*" in normalized or normalized.startswith(("struct ", "union ")))


def _integer_declaration(statement: str, enum_tags: set[str]
    ) -> tuple[str, str, str | None] | None:
  enum_match = re.match(
      r"\s*(?:const\s+)?enum\s+([A-Za-z_]\w*)\s+"
      r"([A-Za-z_]\w*)\s*(?:=\s*(.*))?$", statement, re.S)
  if enum_match and enum_match.group(1) in enum_tags:
    return (enum_match.group(2), f"enum:{enum_match.group(1)}",
        enum_match.group(3))
  match = INTEGER_DECLARATION.search(statement)
  if not match or statement[:match.start()].strip().startswith("return"):
    return None
  variable = match.group(1)
  prefix = statement[:match.start(1)]
  c_type = re.sub(r"\b(?:const|volatile|static|register)\b", "", prefix)
  c_type = " ".join(c_type.split())
  tail = statement[match.end(1):].strip()
  initializer = None
  if tail.startswith("="):
    initializer = tail[1:].strip()
  elif tail:
    return None
  return variable, c_type, initializer


def _convert_stored_values(values: set[int], c_type: str
    ) -> set[int]:
  if c_type.startswith("enum:"):
    return _convert_integer_values(values, "int")
  return _convert_integer_values(values, c_type)


def _report_unresolved(unresolved: list[str], path: str, line: int,
    function: str, expression: str, reason: str) -> None:
  unresolved.append(f"{path}:{line}: function {function}: expression "
      f"{expression!r}: reason: {reason}")


def _possible_truncating_literals(expression: str) -> list[int]:
  values: list[int] = []
  # Constants passed to an opaque call are not themselves returned values.
  # Preserve literals in surrounding arithmetic, e.g. opaque_status() + 256.
  outside_calls = list(expression)
  for call in re.finditer(r"\b[A-Za-z_]\w*\s*\(", expression):
    opening = expression.find("(", call.start(), call.end())
    try:
      closing = _matching_delimiter(expression, opening, "(", ")")
    except ValueError:
      continue
    for index in range(call.start(), closing + 1):
      outside_calls[index] = " "
  for match in C_INTEGER_LITERAL.finditer("".join(outside_calls)):
    try:
      value = _c_integer_value(match.group(0))
    except ValueError:
      continue
    if value and value % 256 == 0:
      values.append(value)
  return values


def _clone_state(state: tuple[dict[str, set[int] | None],
    dict[str, tuple[int, str]]]
    ) -> tuple[dict[str, set[int] | None], dict[str, tuple[int, str]]]:
  values, origins = state
  return ({name: None if domain is None else set(domain)
      for name, domain in values.items()}, dict(origins))


def _execute_statements(statements: list[dict[str, object]],
    states: list[tuple[dict[str, set[int] | None],
        dict[str, tuple[int, str]]]], context: dict[str, object]
    ) -> list[tuple[dict[str, set[int] | None],
        dict[str, tuple[int, str]]]]:
  path = str(context["path"])
  name = str(context["name"])
  masked = str(context["masked"])
  body_start = int(context["body_start"])
  unsafe = context["unsafe"]
  unresolved = context["unresolved"]
  types = context["types"]
  assert isinstance(unsafe, list) and isinstance(unresolved, list)
  assert isinstance(types, dict)
  for statement in statements:
    kind = str(statement["kind"])
    offset = int(statement["start"])
    line_mapper = context.get("source_line")
    line = (line_mapper(offset) if callable(line_mapper)
        else _source_line(masked, offset))
    if kind == "block":
      children = statement["children"]
      assert isinstance(children, list)
      before = set(types)
      states = _execute_statements(children, states, context)
      scoped = set(types) - before
      for variable in scoped:
        types.pop(variable, None)
        for state in states:
          state[0].pop(variable, None)
          state[1].pop(variable, None)
      continue
    if kind == "if":
      condition = str(statement["condition"])
      first = statement["first"]
      second = statement["second"]
      assert isinstance(first, list) and isinstance(second, list)
      result: list[tuple[dict[str, set[int] | None],
          dict[str, tuple[int, str]]]] = []
      for state in states:
        bindings = dict(context["condition_constants"])
        bindings.update({key: domain for key, domain in state[0].items()
            if domain is not None})
        try:
          condition_values = _constant_condition_values(condition, bindings,
              context["function_macros"])
          branches = {bool(value) for value in condition_values}
        except (SyntaxError, ValueError, ZeroDivisionError):
          # An unknown condition never makes either branch infeasible.
          branches = {False, True}
        if not branches:
          branches = {False, True}
        if True in branches:
          result.extend(_execute_statements(first,
              [_clone_state(state)], context))
        if False in branches:
          if second:
            result.extend(_execute_statements(second,
                [_clone_state(state)], context))
          else:
            result.append(_clone_state(state))
      states = result
      if len(states) > 1:
        all_variables = set().union(*(state[0].keys() for state in states))
        merged_values: dict[str, set[int] | None] = {}
        merged_origins: dict[str, tuple[int, str]] = {}
        for variable in all_variables:
          alternatives = [state[0].get(variable) for state in states]
          if any(alternative is None for alternative in alternatives):
            merged_values[variable] = None
          else:
            joined: set[int] = set()
            for alternative in alternatives:
              assert alternative is not None
              joined.update(alternative)
            if len(joined) > 256:
              merged_values[variable] = None
              _report_unresolved(unresolved, path, line, name, condition,
                  f"joined domain for {variable} exceeds the finite bound")
            else:
              merged_values[variable] = joined
          unsafe_origin = next((state[1][variable] for state in states
              if variable in state[1] and state[0].get(variable) is not None
              and any(value != 0 and value % 256 == 0
                  for value in state[0][variable] or set())), None)
          for _values, origins in states:
            if variable in origins:
              merged_origins[variable] = unsafe_origin or origins[variable]
              break
        states = [(merged_values, merged_origins)]
      continue
    if kind == "unsupported":
      control = str(statement["control"])
      _report_unresolved(unresolved, path, line, name,
          str(statement.get("condition", "")),
          f"unsupported {control} control flow")
      for state in states:
        for variable in list(state[0]):
          state[0][variable] = None
      children = statement["first"]
      assert isinstance(children, list)
      # Inspect one body traversal for explicit unsafe literals, but keep every
      # post-loop value unknown because iteration counts are not modeled.
      _execute_statements(children, [_clone_state(states[0])], context) \
          if states else []
      condition = str(statement.get("condition", "")).strip()
      loop_body = masked[offset:int(statement["end"])]
      if control == "while" and not re.search(r"\bbreak\b", loop_body):
        try:
          loop_values = _constant_condition_values(condition,
              context["condition_constants"], context["function_macros"])
        except (SyntaxError, ValueError, ZeroDivisionError):
          loop_values = set()
        if loop_values and all(value != 0 for value in loop_values):
          states = []
      continue
    if kind == "return":
      expression = str(statement["expression"])
      if context.get("nonintegral_return"):
        states = []
        continue
      for values, origins in states:
        bindings = dict(context["enum_constants"])
        bindings.update({key: domain for key, domain in values.items()
            if domain is not None})
        try:
          result_values = finite_c_values(expression, bindings)
        except (SyntaxError, ValueError, ZeroDivisionError) as error:
          result_values = _known_call_result(expression,
              context["known_return_domains"])
          if result_values is None:
            _report_unresolved(unresolved, path, line, name, expression,
                f"returned value is not proven: {error}")
            suspicious = _possible_truncating_literals(expression)
            propagation = context["status_chains"].get(name)
            if suspicious and (name == "main" or propagation):
              unsafe.append(f"{path}:{line}: function {name}: return "
                  f"{expression!r} contains possible truncating values "
                  f"{sorted(set(suspicious))} in an unresolved expression; "
                  f"verified status-value path to main: {propagation or name}")
            elif (name == "main" or propagation) and not (
                context["normalizer_verified"] and
                _status_normalizer_argument(expression) is not None):
              unsafe.append(f"{path}:{line}: function {name}: unresolved "
                  f"return {expression!r} may reach a process status sink; "
                  f"verified status-value path to main: {propagation or name}")
            continue
        return_type = context["return_type"]
        try:
          if isinstance(return_type, str) and return_type in INTEGER_TYPE_INFO:
            result_values = _convert_stored_values(result_values, return_type)
          elif isinstance(return_type, str) and return_type.startswith("enum "):
            result_values = _convert_stored_values(result_values, "int")
        except ValueError as error:
          _report_unresolved(unresolved, path, line, name, expression,
              f"returned value conversion is not proven: {error}")
          propagation = context["status_chains"].get(name)
          if (name == "main" or propagation) and not (
              context["normalizer_verified"] and
              _status_normalizer_argument(expression) is not None):
            unsafe.append(f"{path}:{line}: function {name}: unresolved "
                f"return conversion {expression!r} may reach a process "
                f"status sink; verified status-value path to main: "
                f"{propagation or name}")
          continue
        bad = sorted(value for value in result_values
            if value != 0 and value % 256 == 0)
        if bad:
          identifiers = re.findall(r"\b[A-Za-z_]\w*\b", expression)
          origin = next((origins[item] for item in identifiers
              if item in origins), (line, expression))
          propagation = context["status_chains"].get(name)
          if name == "main" or propagation:
            unsafe.append(f"{path}:{origin[0]}: function {name}: "
                f"{origin[1]!r} resolves to {bad}; returned expression "
                f"{expression!r}; verified status-value path to main: "
                f"{propagation or name}")
      states = []
      continue
    if kind != "simple":
      _report_unresolved(unresolved, path, line, name, "<statement>",
          f"unrecognized statement kind {kind}")
      continue

    source = str(statement["text"])
    if not source:
      continue
    escaped_locals = sorted(set(re.findall(
        r"&\s*([A-Za-z_]\w*)\b", source)) & types.keys())
    if escaped_locals:
      _report_unresolved(unresolved, path, line, name, source,
          "address of returned local escapes bounded alias analysis")
      for values, _origins in states:
        for variable in escaped_locals:
          values[variable] = None
      continue
    declaration = _integer_declaration(source, context["enum_tags"])
    if declaration:
      variable, c_type, initializer = declaration
      if variable in types:
        _report_unresolved(unresolved, path, line, name, source,
            f"shadowed or repeated local {variable} is not modeled")
        for state in states:
          state[0][variable] = None
        continue
      types[variable] = c_type
      for state in states:
        if initializer is None:
          state[0][variable] = None
          state[1][variable] = (line, source)
          continue
        bindings = dict(context["enum_constants"])
        bindings.update({key: domain for key, domain in state[0].items()
            if domain is not None})
        try:
          values = finite_c_values(initializer, bindings)
          state[0][variable] = _convert_stored_values(values, c_type)
          state[1][variable] = (line, f"{variable} = {initializer}")
        except (SyntaxError, ValueError, ZeroDivisionError) as error:
          state[0][variable] = None
          state[1][variable] = (line, f"{variable} = {initializer}")
          _report_unresolved(unresolved, path, line, name, initializer,
              f"initializer for {variable} is unresolved: {error}")
      continue

    if re.search(r"^\s*(?:goto\b|case\b|default\b|[A-Za-z_]\w*\s*:)",
        source):
      _report_unresolved(unresolved, path, line, name, source,
          "label or goto control flow is not modeled")
      for state in states:
        for variable in state[0]:
          state[0][variable] = None
      continue
    assignment = re.fullmatch(
        r"\s*([A-Za-z_]\w*)\s*=(?!=)\s*(.*?)\s*", source, re.S)
    if assignment:
      variable, expression = assignment.groups()
      if variable not in types:
        # Assignment to an untracked object could still feed a later return.
        types[variable] = "<unknown>"
      for state in states:
        bindings = dict(context["enum_constants"])
        bindings.update({key: domain for key, domain in state[0].items()
            if domain is not None})
        try:
          if re.search(r"\b[A-Za-z_]\w*\s*\(", expression):
            raise ValueError("call/side-effect expression is unsupported")
          values = finite_c_values(expression, bindings)
          if types[variable] == "<unknown>":
            raise ValueError(f"type of {variable} is unknown")
          values = _convert_stored_values(values, types[variable])
          state[0][variable] = values
          state[1][variable] = (line, f"{variable} = {expression}")
        except (SyntaxError, ValueError, ZeroDivisionError) as error:
          state[0][variable] = None
          state[1][variable] = (line, f"{variable} = {expression}")
          _report_unresolved(unresolved, path, line, name, expression,
              f"assignment to {variable} is unresolved: {error}")
          suspicious = _possible_truncating_literals(expression)
          propagation = context["status_chains"].get(name)
          if suspicious and (name == "main" or propagation):
            unsafe.append(f"{path}:{line}: function {name}: "
                f"{variable} = {expression} contains possible truncating "
                f"values {sorted(set(suspicious))}; verified status-value "
                f"path to main: {propagation or name}")
      continue
    if COMPOUND_ASSIGNMENT.search(source) or re.search(r"\b\w+\s*\+\+", source):
      _report_unresolved(unresolved, path, line, name, source,
          "compound mutation is outside the finite assignment grammar")
      for state in states:
        for variable in state[0]:
          state[0][variable] = None
      continue
    if re.match(r"\s*(?:_?exit)\s*\(", source):
      _report_unresolved(unresolved, path, line, name, source,
          "exit status consumes an unsupported expression")
      for state in states:
        for variable in state[0]:
          state[0][variable] = None
      continue
    if re.search(r"\w+\s*\(", source):
      affected = [variable for variable in types
          if re.search(r"&\s*" + re.escape(variable) + r"\b", source)]
      if affected:
        _report_unresolved(unresolved, path, line, name, source,
            "call may mutate an addressed returned local")
        for state in states:
          for variable in affected:
            state[0][variable] = None
  return states


def returned_status_analysis(text: str, path: str,
    normalizer_verified: bool = True) -> tuple[list[str], list[str]]:
  """Find unsafe authored values and return unknown domains separately.

  Opaque runtime/API values are retained as unresolved, not classified safe.
  This finite constant-code scan does not claim to prove their value domains.
  """
  try:
    language = source_language(path)
  except ValueError as error:
    return [f"{path}: {error}"], []
  logical, source_offsets = c_logical_source(text, language)
  masked = mask_noncode(logical)
  def source_line(logical_offset: int) -> int:
    return _source_line(text, original_offset(source_offsets, logical_offset,
        len(text)))
  functions = function_ranges(masked)
  unsafe: list[str] = []
  unresolved: list[str] = []
  sanitizer_bindings = list(STATUS_SANITIZER_BINDING.finditer(masked))
  for match in sanitizer_bindings:
    original = original_offset(source_offsets, match.start(), len(text))
    unsafe.append(f"{path}:{_source_line(text, original)}: "
        "source-local preprocessor binding overrides a validated status "
        "sanitizer name")
  normalizer_verified = (normalizer_verified and not sanitizer_bindings)
  enum_constants, enum_tags, enum_unresolved = _parse_enums(
      masked, path, source_line)
  enum_constants.update({"TRUE": {1}, "FALSE": {0}, "true": {1},
      "false": {0}, "NULL": {0}})
  status_chains, callback_roots = _status_propagation_to_main(
      functions, masked, enum_constants, normalizer_verified, source_line)
  known_return_domains = _known_function_return_domains(
      functions, masked, enum_constants)
  unresolved.extend(enum_unresolved)
  functions_by_name = {name: (start, body_start) for name, start, body_start,
      _body_end in functions}
  for callback, registration_line in callback_roots.items():
    start, body_start = functions_by_name[callback]
    callback_return_type = _function_return_type(
        masked, start, body_start, callback)
    if callback_return_type != "void":
      _report_unresolved(unresolved, path, registration_line, callback,
          f"g_test callback {callback}",
          "registered callback return is not consumed as an exit status; "
          f"signature {callback_return_type!r} is not the g_test void contract")

  # A function-signature regex is intentionally not a C parser. Fail closed
  # for return tokens outside its recognized function ranges.
  for match in RETURN_TOKEN.finditer(masked):
    owners = [function for function in functions
        if function[1] <= match.start() < function[3]]
    if len(owners) != 1:
      end = _statement_end(masked, match.end())
      _report_unresolved(unresolved, path, source_line(match.start()),
          "<unknown>", masked[match.end():end].strip(),
          "return is not covered by exactly one recognized function")

  for name, start, body_start, body_end in functions:
    body = masked[body_start:body_end]
    return_type = _function_return_type(masked, start, body_start, name)
    if _nonintegral_return_type(return_type):
      continue
    if return_type not in INTEGER_TYPE_INFO and not (
        return_type and return_type.startswith("enum ")):
      _report_unresolved(unresolved, path, source_line(body_start),
          name, f"return type {return_type!r}",
          "function return type has no modeled integer conversion")
    for directive in re.finditer(
        r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b[^\n]*", body):
      _report_unresolved(unresolved, path,
          source_line(body_start + directive.start()), name,
          directive.group(0).strip(),
          "conditional preprocessor flow is not expanded")
    try:
      statements, _end = _parse_statements(masked, body_start)
    except ValueError as error:
      _report_unresolved(unresolved, path, source_line(body_start),
          name, "<function body>", f"statement parser failed: {error}")
      continue
    initial_types: dict[str, str] = {}
    initial_values: dict[str, set[int] | None] = {}
    function_macros_values, function_macros_touched, function_macros = \
        _parse_integer_macros(masked[:start], enum_constants)
    condition_constants = dict(enum_constants)
    for macro in function_macros_touched:
      condition_constants.pop(macro, None)
    condition_constants.update(function_macros_values)
    condition_constants = _function_parameter_constants(
        masked, name, start, body_start, condition_constants)
    contexts: dict[str, object] = {"path": path, "name": name,
        "functions": functions, "masked": masked, "body_start": body_start,
        "status_chains": status_chains,
        "normalizer_verified": normalizer_verified,
        "source_line": source_line,
        "known_return_domains": known_return_domains,
        "unsafe": unsafe, "unresolved": unresolved,
        "enum_constants": enum_constants,
        "condition_constants": condition_constants,
        "function_macros": function_macros,
        "enum_tags": enum_tags,
        "types": initial_types, "return_type": return_type,
        "nonintegral_return": _nonintegral_return_type(return_type)}
    _execute_statements(statements, [(initial_values, {})], contexts)
  return sorted(set(unsafe)), sorted(set(unresolved))


def validate_repository(root: Path,
    overrides: dict[str, str] | None = None,
    unresolved_out: list[str] | None = None) -> list[str]:
  errors: list[str] = []
  normalizer_verified = _status_normalizer_contract_valid(root)
  if not normalizer_verified:
    errors.append("tests/test-exit-status.h: POSIX status normalizer "
        "does not match the validated truncation contract")
  sources = sorted(root.glob(SOURCES))
  if not sources:
    return [f"no {SOURCES} found under {root}; the detector is broken"]
  for source in sources:
    name = source.relative_to(root).as_posix()
    if overrides is not None and name in overrides:
      text = overrides[name]
    else:
      text = source.read_text(encoding="utf-8", errors="replace")
    for code in offenders(text):
      errors.append(f"{name}: failure code {code} truncates to exit status "
                    f"{code & 0xFF}, so a failing run reports success")
    unsafe, unresolved = returned_status_analysis(text, name,
        normalizer_verified)
    errors.extend(unsafe)
    if unresolved_out is not None:
      unresolved_out.extend(unresolved)
  if overrides is not None:
    for name, text in overrides.items():
      if not (root / name).exists():
        for code in offenders(text):
          errors.append(f"{name}: failure code {code} truncates to exit "
                        f"status {code & 0xFF}")
        unsafe, unresolved = returned_status_analysis(text, name,
            normalizer_verified)
        errors.extend(unsafe)
        if unresolved_out is not None:
          unresolved_out.extend(unresolved)
  return errors


def self_test(root: Path) -> list[str]:
  """A detector is worth only what its own mutations prove."""
  errors: list[str] = []
  for spelling, replacement in TRIGRAPHS_C17.items():
    translated, offsets = c17_logical_source(spelling)
    if translated != replacement or offsets != [0]:
      errors.append(f"C17 trigraph translation failed for {spelling}")
  for sample in ("#define\\\n", "#define??/\r\n"):
    translated, _offsets = c17_logical_source(sample)
    if translated != "#define":
      errors.append("C17 trigraph/line-splice translation failed")
  sources = sorted(root.glob(SOURCES))
  victim = sources[0].relative_to(root).as_posix()
  text = (root / victim).read_text(encoding="utf-8", errors="replace")
  # Both forms, because the return-only reading is the one that has already
  # missed a real site in this tree.
  if not offenders(text + "  return 512;\n"):
    errors.append("mutation survived: return 512")
  if not offenders(text + "  rc = 512;\n"):
    errors.append("mutation survived: rc = 512")
  # A code that truncates to a nonzero status must NOT be reported, or the
  # guard would demand renumbering that belongs to #1067.
  if offenders(text + "  return 513;\n"):
    errors.append("false positive: 513 does not truncate to zero")
  # A detector that matches nothing would pass everything.
  if not offenders("int main (void) { return 256; }\n"):
    errors.append("mutation survived: a synthetic source returning 256")

  status_mutations = {
      "opaque main return": (
          "int opaque_status (void);\n"
          "int main (void) {\n  return opaque_status ();\n}\n", True),
      "opaque main assignment": (
          "int opaque_status (void);\n"
          "int main (void) {\n  int rc = opaque_status ();\n"
          "  return rc;\n}\n", True),
      "opaque helper return": (
          "int opaque_status (void);\n"
          "static int helper (void) { return opaque_status (); }\n"
          "int main (void) { return helper (); }\n", True),
      "opaque helper assignment": (
          "int opaque_status (void);\n"
          "static int helper (void) { int rc = opaque_status (); "
          "return rc; }\n"
          "int main (void) { return helper (); }\n", True),
      "opaque status branch": (
          "int opaque_condition (void);\n"
          "int main (void) { if (opaque_condition ()) return 512; "
          "return 0; }\n", True),
      "opaque normalized main status": (
          "int opaque_status (void);\n"
          "int main (void) { return "
          "wyl_test_normalize_exit_status (opaque_status ()); }\n", False),
      "opaque helper through normalizer": (
          "int opaque_status (void);\n"
          "static int helper (void) { return opaque_status (); }\n"
          "int main (void) { return "
          "wyl_test_normalize_exit_status (helper ()); }\n", False),
      "unrelated helper-local unknown": (
          "int opaque_status (void);\n"
          "static int helper (void) { int ignored = opaque_status (); "
          "return 1; }\n"
          "int main (void) { return helper (); }\n", False),
      "status created after normalizer": (
          "int opaque_status (void);\n"
          "int main (void) { return "
          "wyl_test_normalize_exit_status (opaque_status ()) + 256; }\n",
          True),
      "callback registration only": (
          "int opaque_status (void);\n"
          "static int callback (void) { return opaque_status (); }\n"
          "int main (void) { g_test_add_func (\"/callback\", callback); "
          "return 0; }\n", False),
      "source-local sanitizer override": (
          "#define wyl_test_normalize_exit_status(x) (x)\n"
          "static int helper (void) { return 256; }\n"
          "int main (void) { return "
          "wyl_test_normalize_exit_status (helper ()); }\n", True),
      "trigraph-spliced source sanitizer override": (
          "#define wyl_test_normalize_exit_??/\n"
          "status(x) (x)\n"
          "int main (void) { return "
          "wyl_test_normalize_exit_status (256); }\n", True),
      "trigraph-spliced source sanitizer undefinition": (
          "#undef wyl_test_normalize_exit_??/\n"
          "status\n"
          "int main (void) { return 256; }\n", True),
      "trigraph-created directive marker": (
          "??=define wyl_test_normalize_exit_status(x) (x)\n"
          "int main (void) { return "
          "wyl_test_normalize_exit_status (256); }\n", True),
  }
  for label, (probe, should_fail) in status_mutations.items():
    probe_unsafe, _probe_unresolved = returned_status_analysis(
        probe, f"mutation-{label}.c", True)
    if bool(probe_unsafe) != should_fail:
      errors.append(f"status-flow mutation {label!r}: expected "
          f"{'failure' if should_fail else 'pass'}, got {probe_unsafe}")

  synthetic = ("#define ALWAYS_MACRO 1\n"
      "#define NEVER_MACRO 0\n"
      "#define REDEFINED_MACRO 0\n"
      "#define ALWAYS_FUNCTION_MACRO(x) 1\n"
      "enum FunctionMacroCondition { FUNCTION_MACRO_FLAG = 1 };\n"
      "#define FUNCTION_MACRO_FLAG(x) 0\n"
      "static int alias_case (void) { int source = 256; "
      "int arbitrary_local = source; return arbitrary_local; }\n"
      "static int registered_callback_case (void) { int result = 256; "
      "return result; }\n"
      "static int registered_data_callback_case (void) { return 256; }\n"
      "static int registered_data_destroy_case (void) { return 256; }\n"
      "static int registered_fixture_setup_case (void) { return 256; }\n"
      "static int registered_fixture_test_case (void) { return 256; }\n"
      "static void valid_callback_case (void) { return; }\n"
      "static int count_open_fds_case (void) { int limit = 4096; "
      "return limit; }\n"
      "static int numeric_helper_consumer (void) { "
      "int seen = count_open_fds_case (); if (seen < 0) return 1; "
      "return 0; }\n"
      "static int exit_helper_case (void) { return 256; }\n"
      "static int overwritten_call_case (void) { int rc = "
      "exit_helper_case (); rc = 0; return rc; }\n"
      "static int conditional_mismatch_case (int flag) { int rc = 0; "
      "if (flag) rc = exit_helper_case (); "
      "if (!flag) return rc; return 0; }\n"
      "static int conditional_zero_case (void) { int rc = 0; "
      "if ((rc = exit_helper_case ()) == 0) return rc; return 0; }\n"
      "static int unreachable_call_case (void) { return 0; "
      "int rc = exit_helper_case (); return rc; }\n"
      "static int parenthesized_transform_case (void) { int rc = "
      "(exit_helper_case ()) + 1; return rc; }\n"
      "static int escaped_call_case (void) { int rc = exit_helper_case (); "
      "mutate (&rc); return rc; }\n"
      "static int escaped_pointer_case (void) { int rc = "
      "exit_helper_case (); int *saved = &rc; return rc; }\n"
      "static int escaped_alias_case (void) { int rc = 256; "
      "int *saved = &rc; mutate (saved); return rc; }\n"
      "static char narrow_return_case (void) { "
      "return exit_helper_case (); }\n"
      "static int narrow_local_case (void) { char rc = "
      "exit_helper_case (); return rc; }\n"
      "static gint64 wide_status_case (void) { "
      "return 4294967296LL; }\n"
      "static int int64_to_int_case (void) { "
      "return wide_status_case (); }\n"
      "enum ConstantCondition { ALWAYS = 1 };\n"
      "static int enum_early_return_case (void) { "
      "if (ALWAYS) return 0; return exit_helper_case (); }\n"
      "enum { ALWAYS_ANON = 1 };\n"
      "static int anonymous_enum_early_return_case (void) { "
      "if (ALWAYS_ANON) return 0; return exit_helper_case (); }\n"
      "static int macro_early_return_case (void) { "
      "if (ALWAYS_MACRO) return 0; return exit_helper_case (); }\n"
      "static int macro_never_branch_case (void) { "
      "if (NEVER_MACRO) return exit_helper_case (); return 0; }\n"
      "static int macro_expression_early_return_case (void) { "
      "if (ALWAYS_MACRO == 1) return 0; "
      "return exit_helper_case (); }\n"
      "static int macro_after_local_case (void) { int LATER = 0; "
      "if (LATER) return 0; return exit_helper_case (); }\n"
      "#undef REDEFINED_MACRO\n"
      "#define REDEFINED_MACRO 1\n"
      "static int macro_redefined_case (void) { "
      "if (REDEFINED_MACRO) return exit_helper_case (); return 0; }\n"
      "enum ShadowCondition { SHADOWED_FLAG = 1 };\n"
      "static int enum_shadow_case (void) { int SHADOWED_FLAG = 0; "
      "if (SHADOWED_FLAG) return exit_helper_case (); return 0; }\n"
      "enum NestedShadowCondition { NESTED_FLAG = 1 };\n"
      "static int nested_enum_shadow_case (void) { if (NESTED_FLAG) { } "
      "{ int NESTED_FLAG = 0; if (NESTED_FLAG) "
      "return exit_helper_case (); } return 0; }\n"
      "enum PredeclarationCondition { PREDECL_FLAG = 0 };\n"
      "static int predeclaration_shadow_case (void) { "
      "if (PREDECL_FLAG) return exit_helper_case (); "
      "int PREDECL_FLAG = 1; return 0; }\n"
      "static int true_early_return_case (void) { "
      "if (TRUE) return 0; return exit_helper_case (); }\n"
      "static int false_branch_case (void) { "
      "if (FALSE) return exit_helper_case (); return 0; }\n"
      "static int function_macro_false_case (void) { "
      "if (FUNCTION_MACRO_FLAG (1)) return exit_helper_case (); "
      "return 0; }\n"
      "static int macro_literal_false_case (void) { "
      "if (NEVER_MACRO) return 256; return 0; }\n"
      "static int function_macro_literal_false_case (void) { "
      "if (FUNCTION_MACRO_FLAG ((1, 2))) return 256; return 0; }\n"
      "static int nested_function_macro_early_return_case (void) { "
      "if (ALWAYS_FUNCTION_MACRO ((2))) return 0; "
      "return exit_helper_case (); }\n"
      "static int constant_early_return_case (void) { "
      "if (1) return 0; return exit_helper_case (); }\n"
      "static int infinite_loop_case (void) { while (1) { } "
      "return exit_helper_case (); }\n"
      "static int exit_consumer_case (void) { "
      "exit (exit_helper_case ()); return 0; }\n"
      "static int transformed_return_case (void) { "
      "return exit_helper_case () + 1; }\n"
      "static int transformed_assignment_case (void) { "
      "int rc = exit_helper_case () + 1; return rc; }\n"
      "static int direct_hex_case (void) { return 0x100; }\n"
      "static int direct_octal_case (void) { return 0400; }\n"
      "static int direct_suffix_case (void) { return 512U; }\n"
      "static int direct_cast_case (void) { return (gint) 256; }\n"
      "static long long direct_cast64_case (void) { "
      "return (gint64) 256; }\n"
      "static int conditional_case (int choose) { int value = 0; "
      "value = choose ? 256 : 7; return value; }\n"
      "static int computed_case (void) { int base = 250; "
      "return base + 6; }\n"
      "static int safe_case (int choose) { int value = 0; "
      "value = choose ? 1 : 257; return value; }\n"
      "static int overwritten_case (void) { int value = 256; "
      "value = 0; return value; }\n"
      "static int branch_case (int choose) { int value = 0; "
      "if (choose) value = 256; else value = 0; return value; }\n"
      "static int early_return_case (int choose) { int value = 0; "
      "if (choose) return 256; else value = 0; return value; }\n"
      "static int unbraced_nested_case (int choose) { int value = 0; "
      "if (choose) if (value) value = 256; else value = 0; "
      "return value; }\n"
      "static int safe_branch_case (int choose) { int value = 0; "
      "if (choose) value = 257; else value = 0; return value; }\n"
      "static int narrow_unsigned_case (void) { guint8 value = 256; "
      "value = 512; return value; }\n"
      "static int narrow_cast_case (void) { return (guint8) 256; }\n"
      "static int signed_overflow_case (void) { "
      "int value = 2147483647 + 1; return value; }\n"
      "enum Status { STATUS_NEAR = 255, STATUS_BAD };\n"
      "static int enum_case (void) { enum Status value = STATUS_BAD; "
      "return value; }\n"
      "static int unknown_case (void) { int value = opaque_api_status (); "
      "return value; }\n"
      "static int loop_case (void) { int value = 0; "
      "for (int i = 0; i < 4; i++) value = 254 + i; return value; }\n"
      "static int unknown_computed_case (void) { "
      "return opaque_api_status () + 256; }\n"
      "static int unknown_assignment_case (void) { int value = 0; "
      "value = opaque_api_status () + 256; return value; }\n")
  synthetic += ("static int shadow_case (void) { int value = 0; "
      "{ int value = 256; } return value; }\n"
      "static int goto_case (void) { int value = 256; goto done; "
      "done: return value; }\n"
      "static int switch_case (int tag) { int value = 0; "
      "switch (tag) { case 1: value = 256; break; default: value = 0; } "
      "return value; }\n"
      "static int side_effect_case (void) { int value = 0; "
      "value = opaque_api_status (); return value; }\n"
      "#define MACRO_STATUS 256\n"
      "#define LATER 1\n"
      "static int macro_case (void) { return MACRO_STATUS; }\n")
  synthetic += ("__declspec(dllexport) int unrecognized_return_case (void) "
      "{ return 256; }\n")
  synthetic += ("int main (void) { "
      "g_test_add_func (\"/callback\", registered_callback_case); "
      "g_test_add_func (\"/valid-callback\", valid_callback_case); "
      "g_test_add_data_func (NULL, NULL, registered_data_callback_case); "
      "g_test_add_data_func_full (NULL, NULL, "
      "registered_data_callback_case, registered_data_destroy_case); "
      "g_test_add (NULL, 0, NULL, registered_fixture_setup_case, "
      "registered_fixture_test_case, NULL); "
      "numeric_helper_consumer (); return 0; }\n")
  synthetic_unsafe, synthetic_unresolved = returned_status_analysis(
      synthetic, victim)
  if not any("registered_callback_case" in item and "g_test callback" in item
      for item in synthetic_unresolved):
    errors.append("incompatible g_test callback return was silently omitted")
  if not any("registered_data_callback_case" in item and
      "g_test callback" in item for item in synthetic_unresolved):
    errors.append("g_test_add_data_func callback was not identified")
  if not any("registered_data_destroy_case" in item and
      "g_test callback" in item for item in synthetic_unresolved):
    errors.append("g_test_add_data_func_full destroy callback was not identified")
  if not any("registered_fixture_setup_case" in item and
      "g_test callback" in item for item in synthetic_unresolved):
    errors.append("g_test_add fixture setup callback was not identified")
  if not any("registered_fixture_test_case" in item and
      "g_test callback" in item for item in synthetic_unresolved):
    errors.append("g_test_add fixture test callback was not identified")
  if any("registered_callback_case" in item for item in synthetic_unsafe):
    errors.append("g_test void callback return was misclassified as process status")
  if any("valid_callback_case" in item for item in synthetic_unresolved):
    errors.append("valid void callback was incorrectly unresolved")
  if any("count_open_fds_case" in item for item in synthetic_unsafe):
    errors.append("ordinary numeric helper limit was misclassified as status")
  int64_to_int_probe = synthetic.rsplit("int main (void)", 1)[0] + (
      "int main (void) { return int64_to_int_case (); }\n")
  int64_to_int_unsafe, int64_to_int_unresolved = returned_status_analysis(
      int64_to_int_probe, victim)
  if not any("int64_to_int_case" in item or "wide_status_case" in item
      for item in int64_to_int_unsafe):
    errors.append("unproven int64-to-int status conversion passed")
  if not any("int64_to_int_case" in item for item in int64_to_int_unresolved):
    errors.append("int64-to-int return conversion was not retained as unresolved")
  redefined_macro_probe = synthetic.rsplit("int main (void)", 1)[0] + (
      "int main (void) { return macro_redefined_case (); }\n")
  redefined_macro_unsafe, _redefined_macro_unresolved = \
      returned_status_analysis(redefined_macro_probe, victim)
  if not any("exit_helper_case" in item for item in redefined_macro_unsafe):
    errors.append("macro redefinition order hid a reachable status flow")
  later_macro_probe = synthetic.rsplit("int main (void)", 1)[0] + (
      "int main (void) { return macro_after_local_case (); }\n")
  later_macro_unsafe, _later_macro_unresolved = returned_status_analysis(
      later_macro_probe, victim)
  if not any("exit_helper_case" in item for item in later_macro_unsafe):
    errors.append("later macro definition masked a local condition")
  for function in ("exit_consumer_case", "transformed_return_case",
      "transformed_assignment_case"):
    if not any(function in item for item in synthetic_unresolved):
      errors.append(f"unsupported status consumer {function} was silently omitted")
  expected_unsafe = {
      "alias_case": "[256]",
      "direct_hex_case": "[256]", "direct_octal_case": "[256]",
      "direct_suffix_case": "[512]", "direct_cast_case": "[256]",
      "direct_cast64_case": "[256]", "enum_case": "[256]",
      "branch_case": "[256]", "early_return_case": "[256]",
      "conditional_case": "[256]", "computed_case": "[256]",
  }
  probe_prefix = synthetic.rsplit("int main (void)", 1)[0]
  probe_results: dict[str, list[str]] = {}
  for function in expected_unsafe:
    main_type = "long long" if function == "direct_cast64_case" else "int"
    probe = probe_prefix + (
        f"{main_type} main (void) {{ return {function} (); }}\n")
    probe_results[function], _probe_unresolved = returned_status_analysis(
        probe, victim)
  for function, value in expected_unsafe.items():
    if not any(function in item and value in item
        for item in probe_results[function]):
      errors.append(f"mutation survived: {function} did not expose {value}")
  if not any("conditional_case" in item and "[256]" in item
      for item in probe_results.get("conditional_case", [])):
    errors.append("mutation survived: conditional join includes 256")
  if not any("computed_case" in item and "[256]" in item
      for item in probe_results.get("computed_case", [])):
    errors.append("mutation survived: computed returned value is 256")
  if any("safe_case" in item for item in probe_results.get("safe_case", [])):
    errors.append("false positive: bounded safe domain {1,257}")
  if any("overwritten_case" in item
      for item in probe_results.get("overwritten_case", [])):
    errors.append("false positive: unconditional overwrite returns zero")
  safe_branch_probe = (
      "int main (void) { int choose = 1; int value = 0; "
      "value = choose ? 1 : 257; return value; }\n")
  safe_branch_unsafe, _safe_branch_unresolved = returned_status_analysis(
      safe_branch_probe, victim)
  if any("safe_branch_case" in item for item in safe_branch_unsafe):
    errors.append("false positive: conditional safe domain {0,257}")
  if any("narrow_unsigned_case" in item or "narrow_cast_case" in item
      for item in synthetic_unsafe):
    errors.append("false positive: unsigned narrow conversion truncates to zero")
  if not any("signed_overflow_case" in item
      for item in synthetic_unresolved):
    errors.append("signed overflow was not retained as unresolved")
  if not any("return is not covered" in item
      for item in synthetic_unresolved):
    errors.append("return outside recognized function was not unresolved")
  if not any("unknown_case" in item for item in synthetic_unresolved):
    errors.append("unknown API status was not retained as unresolved")
  unknown_row = next((item for item in synthetic_unresolved
      if "unknown_case" in item), "")
  if not all(fragment in unknown_row for fragment in
      (victim, ":", "function unknown_case", "expression", "reason")):
    errors.append("unknown API unresolved record lacks location/function/expression/reason")
  if not any("loop_case" in item for item in synthetic_unresolved):
    errors.append("loop-derived value was not retained as unresolved")
  for function in ("shadow_case", "goto_case", "switch_case",
      "side_effect_case", "macro_case"):
    if not any(function in item for item in synthetic_unresolved):
      errors.append(f"unsupported flow {function} was not unresolved")
  unknown_probe = probe_prefix + (
      "int main (void) { return unknown_computed_case (); }\n")
  _unknown_probe_unsafe, unknown_probe_unresolved = returned_status_analysis(
      unknown_probe, victim)
  if not any("unknown_computed_case" in item
      for item in unknown_probe_unresolved):
    errors.append("unknown computed return with 256 did not fail closed")
  assignment_probe = probe_prefix + (
      "int main (void) { return unknown_assignment_case (); }\n")
  _assignment_probe_unsafe, assignment_probe_unresolved = \
      returned_status_analysis(assignment_probe, victim)
  if not any("unknown_assignment_case" in item
      for item in assignment_probe_unresolved):
    errors.append("unknown computed assignment with 256 did not fail closed")
  overwritten_probe = probe_prefix + (
      "int main (void) { return overwritten_call_case (); }\n")
  overwritten_call_unsafe, _overwritten_call_unresolved = \
      returned_status_analysis(overwritten_probe, victim)
  if any("exit_helper_case" in item for item in overwritten_call_unsafe):
    errors.append("false positive: call result overwritten before return")
  for function, label in (
      ("conditional_mismatch_case", "mutually exclusive branch"),
      ("conditional_zero_case", "zero-only comparison branch"),
      ("unreachable_call_case", "assignment after return"),
      ("parenthesized_transform_case", "parenthesized transformed value"),
      ("escaped_call_case", "addressed local mutation"),
      ("escaped_pointer_case", "stored local address escape"),
      ("escaped_alias_case", "mutated local through stored address"),
      ("narrow_return_case", "narrowing function return conversion"),
      ("narrow_local_case", "narrowing local assignment conversion"),
      ("int64_to_int_case", "int64-to-int return conversion"),
      ("constant_early_return_case", "constant-true early return"),
      ("enum_early_return_case", "enum-constant early return"),
      ("anonymous_enum_early_return_case", "anonymous enum early return"),
      ("macro_early_return_case", "unknown macro early return"),
      ("macro_never_branch_case", "zero-valued macro branch"),
      ("macro_expression_early_return_case",
          "macro expression early return"),
      ("enum_shadow_case", "local variable shadowing enum constant"),
      ("nested_enum_shadow_case",
          "nested local scope shadowing enum constant"),
      ("predeclaration_shadow_case",
          "enum name before local declaration"),
      ("true_early_return_case", "built-in TRUE early return"),
      ("false_branch_case", "built-in FALSE branch"),
      ("function_macro_false_case", "constant function-like macro"),
      ("macro_literal_false_case", "literal under zero-valued macro"),
      ("function_macro_literal_false_case",
          "literal under function-like macro"),
      ("nested_function_macro_early_return_case",
          "nested function-like macro argument"),
      ("infinite_loop_case", "return after infinite loop")):
    probe = probe_prefix + f"int main (void) {{ return {function} (); }}\n"
    probe_unsafe, probe_unresolved = returned_status_analysis(probe, victim)
    if any("exit_helper_case" in item for item in probe_unsafe):
      errors.append(f"false positive: {label} status edge")
    if (function in {"macro_literal_false_case",
        "function_macro_literal_false_case"} and
        any(function in item for item in probe_unsafe)):
      errors.append(f"false positive: unreachable literal in {label}")
    if function == "int64_to_int_case" and any(
        "direct_cast64_case" in item for item in probe_unsafe):
      errors.append("false positive: int64-to-int status edge")
    if (function.startswith("narrow_") or function == "int64_to_int_case") and not any(
        function in item for item in probe_unresolved):
      errors.append(f"narrowing flow was not left unresolved: {label}")
  if synthetic_unresolved != sorted(set(synthetic_unresolved)):
    errors.append("unresolved diagnostics are not deterministic and unique")
  return errors


def main() -> int:
  unresolved: list[str] = []
  self_test_mode = len(sys.argv) == 3 and sys.argv[1] == "--self-test"
  if self_test_mode:
    errors = self_test(Path(sys.argv[2]))
  elif len(sys.argv) == 2:
    errors = validate_repository(Path(sys.argv[1]), unresolved_out=unresolved)
  else:
    print(f"usage: {sys.argv[0]} [--self-test] SOURCE_ROOT", file=sys.stderr)
    return 2
  for error in errors:
    print(error, file=sys.stderr)
  if errors:
    return 1
  if self_test_mode:
    print("exit status truncation: mutation self-test passed")
    return 0
  unresolved = sorted(set(unresolved))
  print("exit status truncation: passed; "
      f"{len(unresolved)} nonblocking expression-analysis diagnostics remain; "
      "unresolved unsanitized status returns fail the gate")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

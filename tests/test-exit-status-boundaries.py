#!/usr/bin/env python3
"""Inventory process-status boundaries and require normalized test mains."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
RETURNS_MANIFEST = "tests/test-exit-status-returns.json"
SITES_MANIFEST = "tests/test-exit-status-sites.json"
SUPPORT_SOURCES = {"tests/test-exit-status-termination.c"}
SOURCE_SUFFIXES = {".c", ".cc", ".cpp"}
EXIT_CALL = re.compile(
    r"\b(WYL_TEST__EXIT|WYL_TEST_EXIT|WYL_TEST_SKIP|ExitProcess|TerminateProcess|"
    r"_Exit|_exit|quick_exit|exit)\s*\(")
SANITIZER_BINDING = re.compile(
    r"(?m)^[ \t]*#[ \t]*(?:define|undef)[ \t]+"
    r"(?:wyl_test_normalize_exit_status|WYL_TEST__EXIT|WYL_TEST_EXIT"
    r"|WYL_TEST_SKIP)\b")
INCLUDE_DIRECTIVE = re.compile(
    r"^\s*#\s*include\s*([\"<])([^\">]+)[\">]")
CONDITIONAL_DIRECTIVE = re.compile(
    r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b\s*(.*)$")
SUPPORTED_LANGUAGES = ("c17", "c++17")
HEADER_SUFFIXES = {".h", ".hh", ".hpp"}
LOCAL_SUFFIXES = HEADER_SUFFIXES | SOURCE_SUFFIXES
LAMBDA = re.compile(
    r"\[(?:[^\]\n]*)\]\s*(?:\([^;{}]*\)\s*)?"
    r"(?:mutable\s*)?(?:noexcept\s*)?(?:->[^{}]+)?\{")


def _load_parser():
  parser_path = ROOT / "tests/test-exit-status-truncation.py"
  spec = importlib.util.spec_from_file_location("exit_status_parser",
      parser_path)
  if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load parser at {parser_path}")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


PARSER = _load_parser()


def _lambda_ranges(masked: str, start: int, end: int) -> list[tuple[int, int]]:
  ranges: list[tuple[int, int]] = []
  for match in LAMBDA.finditer(masked, start, end):
    opening = match.end() - 1
    try:
      closing = PARSER._matching_delimiter(masked, opening, "{", "}")
    except ValueError as error:
      raise ValueError("unclosed lambda body") from error
    ranges.append((opening + 1, closing))
  return ranges


def _main_returns(text: str, source: str
    ) -> tuple[int, list[dict[str, object]]]:
  language = PARSER.source_language(source)
  logical, source_offsets = PARSER.c_logical_source(text, language)
  masked = PARSER.mask_noncode(logical)
  def source_line(logical_offset: int) -> int:
    original = PARSER.original_offset(source_offsets, logical_offset, len(text))
    return PARSER._source_line(text, original)

  mains = [function for function in PARSER.function_ranges(masked)
      if function[0] == "main"]
  rows: list[dict[str, object]] = []
  for _name, _start, body_start, body_end in mains:
    lambdas = _lambda_ranges(masked, body_start, body_end)
    for match in PARSER.RETURN_TOKEN.finditer(masked, body_start, body_end):
      if any(start <= match.start() < end for start, end in lambdas):
        continue
      stop = PARSER._statement_end(masked, match.end())
      expression = masked[match.end():stop].strip()
      line = source_line(match.start())
      if not expression:
        raise ValueError(f"{source}:{line}: main has a bare return")
      if not re.match(
          r"^wyl_test_normalize_exit_status(?:_named)?\s*\(", expression):
        raise ValueError(
            f"{source}:{line}: main return is not normalized: {expression}")
      rows.append({"line": line, "expression": expression})
  return len(mains), rows


def _termination_sites(text: str, source: str
    ) -> list[dict[str, object]]:
  language = PARSER.source_language(source)
  logical, source_offsets = PARSER.c_logical_source(text, language)
  masked = PARSER.mask_noncode(logical)
  def source_line(logical_offset: int) -> int:
    original = PARSER.original_offset(source_offsets, logical_offset, len(text))
    return PARSER._source_line(text, original)

  sanitizer_binding = SANITIZER_BINDING.search(masked)
  if sanitizer_binding is not None:
    raise ValueError(
        f"{source}:{source_line(sanitizer_binding.start())}: "
        "source-local preprocessor binding overrides a validated status "
        "sanitizer name")
  sites: list[dict[str, object]] = []
  for match in EXIT_CALL.finditer(masked):
    api = match.group(1)
    if api in {"_Exit", "_exit", "exit", "quick_exit"}:
      raise ValueError(
          f"{source}:{source_line(match.start())}: "
          f"unwrapped POSIX termination primitive {api}")
    opening = masked.find("(", match.start(), match.end())
    closing = PARSER._matching_delimiter(masked, opening, "(", ")")
    args = masked[opening + 1:closing].strip()
    if api in {"WYL_TEST__EXIT", "WYL_TEST_EXIT"}:
      tail = masked[closing + 1:]
      tail = tail[len(tail) - len(tail.lstrip()):]
      if not tail.startswith(";"):
        raise ValueError(
            f"{source}:{source_line(match.start())}: "
            f"{api} is not used as a statement")
      line = source_line(match.start())
      temporary = f"wyl_test_exit_status_capture_{line}"
      if re.search(r"\b" + re.escape(temporary) + r"\b", args):
        raise ValueError(
            f"{source}:{line}: macro temporary collides with its argument")
      native = "_Exit" if api == "WYL_TEST__EXIT" else "_exit"
      platform = "posix-normalized-wrapper"
    else:
      native = api
      platform = "windows"
    sites.append({"path": source,
        "line": source_line(match.start()),
        "api": native, "expression": args, "platform": platform})
  return sites


def _sources(root: Path) -> list[Path]:
  return sorted(path for path in root.glob("tests/test-*.*")
      if path.suffix in SOURCE_SUFFIXES
      and path.relative_to(root).as_posix() not in SUPPORT_SOURCES)


def inventory(root: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
  source_rows: list[dict[str, object]] = []
  sites: list[dict[str, object]] = []
  main_count = 0
  return_count = 0
  for path in _sources(root):
    relative = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    mains, returns = _main_returns(text, relative)
    if mains:
      source_rows.append({"path": relative,
          "main_definitions": mains, "normalized_returns": len(returns)})
    main_count += mains
    return_count += len(returns)
    sites.extend(_termination_sites(text, relative))
  returns_data = {"schema": 1, "source_count": len(source_rows),
      "main_definitions": main_count, "normalized_returns": return_count,
      "source_census_sha256": hashlib.sha256(json.dumps(source_rows,
          sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}
  return returns_data, sorted(sites,
      key=lambda row: (str(row["path"]), int(row["line"]), str(row["api"])))


def _validate_header_text(header: str, language: str = "c17") -> list[str]:
  errors: list[str] = []
  logical, _source_offsets = PARSER.c_logical_source(header, language)
  scanned = PARSER.mask_noncode(logical)
  flattened = " ".join(scanned.split())
  for name in ("wyl_test_normalize_exit_status", "WYL_TEST_EXIT",
      "WYL_TEST__EXIT"):
    directives = list(re.finditer(
        r"(?m)^[ \t]*#[ \t]*(define|undef)[ \t]+"
        + re.escape(name) + r"\b", scanned))
    definitions = [match for match in directives
        if match.group(1) == "define"]
    expected = 1 if name == "wyl_test_normalize_exit_status" else 2
    if len(definitions) != expected or len(directives) != expected:
      errors.append(f"header has unexpected sanitizer bindings for {name}")
  capture_bindings = ("WYL_TEST_EXIT_CAPTURE_NAME_I",
      "WYL_TEST_EXIT_CAPTURE_NAME")
  for name in capture_bindings:
    directives = list(re.finditer(
        r"(?m)^[ \t]*#[ \t]*(define|undef)[ \t]+"
        + re.escape(name) + r"\b", scanned))
    if (len(directives) != 1 or directives[0].group(1) != "define"):
      errors.append(f"header has unexpected capture-name binding for {name}")
  capture_helper_i = re.search(
      r"(?m)^#define\s+WYL_TEST_EXIT_CAPTURE_NAME_I\s*\(line\)\s+"
      r"wyl_test_exit_status_capture_\s*##\s*line\s*$", scanned)
  capture_helper = re.search(
      r"(?m)^#define\s+WYL_TEST_EXIT_CAPTURE_NAME\s*\(line\)\s+"
      r"WYL_TEST_EXIT_CAPTURE_NAME_I\s*\(line\)\s*$", scanned)
  if capture_helper_i is None or capture_helper is None:
    errors.append("header capture-name helpers do not match the validated form")
  skip_directives = list(re.finditer(
      r"(?m)^[ \t]*#[ \t]*(define|undef)[ \t]+WYL_TEST_SKIP\b", scanned))
  if len(skip_directives) != 1 or skip_directives[0].group(1) != "define":
    errors.append("header has unexpected bindings for WYL_TEST_SKIP")
  # Nullary by contract.  An argument would make this a second way to return an
  # arbitrary status from main, which is the rule the normalizer exists to keep.
  if re.search(r"(?m)^#define\s+WYL_TEST_SKIP\s*\(\s*\)\s+_exit\s*\(\s*77\s*\)\s*$",
      scanned) is None:
    errors.append("WYL_TEST_SKIP is not the nullary 77 skip primitive")

  windows_else = re.search(r"(?m)^#else\s*$", scanned)
  if windows_else is None:
    errors.append("header is missing the Windows pass-through branch")
  else:
    windows_branch = scanned[windows_else.end():]
    for macro, primitive in (("WYL_TEST__EXIT", "_Exit"),
        ("WYL_TEST_EXIT", "_exit")):
      if re.search(r"(?m)^#define\s+" + macro
          + r"\s*\(status_expression\)\s+" + primitive
          + r"\s*\(\s*status_expression\s*\)\s*$",
          windows_branch) is None:
        errors.append(f"{macro} Windows pass-through definition changed")
  # A search with .*? between the clauses only proves the text is present,
  # not that it is reached: a body that returns the status verbatim and leaves
  # `return 1;` behind as dead code satisfied it, so the whole family stayed
  # green against a normalizer turned into a complete no-op.  Pin the body
  # exactly, the way the WYL_TEST_EXIT macros below are already pinned.
  normalizer = re.search(
      r"\bstatic\s+inline\s+int\s+wyl_test_report_exit_status\s*"
      r"\([^)]*\)\s*\{([^{}]*)\}", flattened)
  if normalizer is None:
    errors.append("POSIX normalizer does not map each nonzero status to 1")
  else:
    ordered_normalizer = (
        r"\s*if\s*\(\s*status\s*==\s*0\s*\)\s*return\s+0\s*;\s*"
        r"\(\s*void\s*\)\s*fprintf\s*\(\s*stderr\s*,\s*,\s*file\s*,"
        r"\s*function\s*,\s*line\s*,\s*status\s*\)\s*;\s*"
        r"\(\s*void\s*\)\s*fflush\s*\(\s*stderr\s*\)\s*;\s*"
        r"return\s+1\s*;\s*")
    if re.fullmatch(ordered_normalizer, normalizer.group(1)) is None:
      errors.append("POSIX normalizer does not map each nonzero status to 1")
  normalizer_definitions = list(re.finditer(
      r"\bstatic\s+inline\s+int\s+wyl_test_report_exit_status\s*"
      r"\([^)]*\)\s*\{", flattened))
  if len(normalizer_definitions) != 1:
    errors.append("header must define exactly one POSIX status normalizer")
  posix_else = re.search(r"(?m)^#else\s*$", scanned)
  for macro in ("WYL_TEST_EXIT", "WYL_TEST__EXIT"):
    definitions = list(re.finditer(
        r"(?m)^#define\s+" + macro + r"\s*\(status_expression\)",
        scanned))
    if len(definitions) != 2 or posix_else is None or not (
        definitions[0].start() < posix_else.start() < definitions[1].start()):
      errors.append(f"{macro} definitions are not confined to POSIX and Windows branches")
  for primitive, macro in (("_exit", "WYL_TEST_EXIT"),
      ("_Exit", "WYL_TEST__EXIT")):
    block = re.search(
        r"#define " + macro + r"\(status_expression\)(.*?)(?=\n#define |\n#else)",
        scanned, re.S)
    if block is None:
      errors.append(f"header is missing {macro}")
      continue
    body = block.group(1)
    if body.count("(status_expression)") != 1:
      errors.append(f"{macro} does not capture its argument exactly once")
    if primitive + " (" not in body:
      errors.append(f"{macro} does not call the matching {primitive}")
    if "wyl_test_normalize_exit_status" in body:
      errors.append(f"{macro} calls a helper on a post-fork path")
    if "malloc" in body or "pthread_mutex" in body:
      errors.append(f"{macro} contains an unsafe post-fork operation")
    flattened_body = " ".join(body.replace("\\\n", " ").split())
    capture = (r"WYL_TEST_EXIT_CAPTURE_NAME\s*\(\s*__LINE__\s*\)")
    ordered_body = (r"do\s*\{\s*int\s+" + capture
        + r"\s*=\s*\(status_expression\)\s*;\s*if\s*\(\s*"
        + capture + r"\s*!=\s*0\s*&&\s*" + capture
        + r"\s*%\s*256\s*==\s*0\s*\)\s*\{\s*" + capture
        + r"\s*=\s*1\s*;\s*\}\s*" + re.escape(primitive)
        + r"\s*\(\s*" + capture + r"\s*\)\s*;\s*\}\s*"
        + r"while\s*\(\s*0\s*\)")
    if re.fullmatch(ordered_body, flattened_body) is None:
      errors.append(f"{macro} body does not match the straight-line sanitizer contract")
    capture_match = re.search(r"int\s+" + capture
        + r"\s*=\s*\(status_expression\)\s*;", flattened_body)
    if capture_match is None:
      errors.append(f"{macro} does not capture its status argument")
    guard = (r"if\s*\(\s*" + capture + r"\s*!=\s*0\s*&&\s*"
        + capture + r"\s*%\s*256\s*==\s*0\s*\)\s*\{\s*"
        + capture + r"\s*=\s*1\s*;\s*\}")
    guard_match = re.search(guard, flattened_body)
    if guard_match is None:
      errors.append(f"{macro} does not normalize nonzero 256 multiples")
    sink_pattern = re.escape(primitive) + r"\s*\(\s*" + capture
    sink_pattern += r"\s*\)\s*;"
    sink_match = re.search(sink_pattern, flattened_body)
    if sink_match is None:
      errors.append(f"{macro} does not terminate with its normalized capture")
    primitive_calls = list(re.finditer(re.escape(primitive) + r"\s*\(",
        flattened_body))
    if len(primitive_calls) != 1:
      errors.append(f"{macro} contains an additional or bypass termination sink")
    any_termination_calls = list(re.finditer(
        r"\b(?:_Exit|_exit|exit|quick_exit|ExitProcess|TerminateProcess)"
        r"\s*\(", flattened_body))
    if len(any_termination_calls) != 1 or (
        any_termination_calls and
        any_termination_calls[0].group(0).split("(", 1)[0].strip()
        != primitive):
      errors.append(f"{macro} contains a bypass termination primitive")
    if (capture_match is not None and guard_match is not None
        and sink_match is not None and
        not capture_match.start() < guard_match.start() < sink_match.start()):
      errors.append(f"{macro} does not normalize before its termination sink")
    if guard_match is not None and sink_match is not None:
      after_guard = flattened_body[guard_match.end():sink_match.start()]
      if re.search(capture + r"\s*(?:=|\+=|-=|\*=|/=|%=|\+\+|--)",
          after_guard):
        errors.append(f"{macro} changes its normalized status before termination")
  return errors


def _condition_value(kind: str, expression: str,
    language: str) -> bool | None:
  expression = expression.strip()
  if kind == "if" and expression in {"0", "1"}:
    return expression == "1"
  if kind in {"ifdef", "ifndef"} and expression == "__cplusplus":
    defined = language == "c++17"
    return defined if kind == "ifdef" else not defined
  if kind == "if" and expression in {
      "defined(__cplusplus)", "defined __cplusplus"}:
    return language == "c++17"
  if kind == "if" and expression in {
      "!defined(__cplusplus)", "!defined __cplusplus"}:
    return language == "c17"
  return None


@lru_cache(maxsize=None)
def _local_includes(text: str, language: str
    ) -> tuple[list[tuple[str, tuple[str, ...], str]], list[str]]:
  logical, _offsets = PARSER.c_logical_source(text, language)
  directives = PARSER.mask_noncode(logical, preserve_literals=True)
  branch_stack: list[dict[str, object]] = []
  conditions: list[str] = []
  active: bool | None = True
  includes: list[tuple[str, tuple[str, ...], str]] = []
  unresolved: list[str] = []
  for line in directives.splitlines():
    conditional = CONDITIONAL_DIRECTIVE.match(line)
    if conditional is not None:
      kind, expression = conditional.groups()
      if kind in {"if", "ifdef", "ifndef"}:
        value = _condition_value(kind, expression, language)
        branch_stack.append({"parent": active, "first": value,
            "else_seen": False,
            "label": f"#{kind} {expression}".strip()})
        active = (False if active is False or value is False else True)
        conditions.append(f"#{kind} {expression}".strip())
      elif kind in {"elif", "else"} and branch_stack:
        frame = branch_stack[-1]
        if kind == "elif" and frame["else_seen"]:
          raise ValueError("malformed conditional directive #elif after #else")
        if kind == "else" and frame["else_seen"]:
          raise ValueError("malformed conditional directive duplicate #else")
        if kind == "else":
          frame["else_seen"] = True
        first = frame["first"]
        frame["label"] = f"#{kind} {expression}".strip()
        value = (True if kind == "else" else
            _condition_value("if", expression, language))
        if first is True:
          active = False
        elif first is False:
          parent = frame["parent"]
          active = (False if parent is False or value is False else True)
          frame["first"] = value
        else:
          # Unknown conditions retain every feasible branch conservatively.
          parent = frame["parent"]
          active = False if parent is False else True
        if conditions:
          conditions[-1] = frame["label"]
      elif kind == "endif" and branch_stack:
        frame = branch_stack.pop()
        active = frame["parent"]
        if conditions:
          conditions.pop()
      elif kind in {"elif", "else", "endif"}:
        raise ValueError(
            f"malformed conditional directive #{kind} in {line.strip()}")
      continue
    if active is False:
      continue
    include = INCLUDE_DIRECTIVE.match(line)
    if include is not None:
      includes.append((include.group(2), tuple(conditions), include.group(1)))
    elif re.match(r"^\s*#\s*include\b", line):
      unresolved.append(line.strip())
  if branch_stack:
    raise ValueError("unterminated conditional include branch")
  return includes, unresolved


def _header_contexts(root: Path,
    header_overrides: dict[str, str] | None = None,
    source_overrides: dict[str, str] | None = None
    ) -> dict[str, dict[str, list[tuple[tuple[str, ...], tuple[str, ...]]]]]:
  local_paths = {path.relative_to(root).as_posix()
      for base in (root / "tests", root / "wyrelog")
      for path in base.glob("**/*") if path.is_file()
      and path.suffix in LOCAL_SUFFIXES}
  local_paths.update(path.name for path in root.iterdir()
      if path.is_file() and path.suffix in LOCAL_SUFFIXES)
  if header_overrides:
    local_paths.update(header_overrides)
  if source_overrides:
    local_paths.update(source_overrides)
  local_basenames = {Path(path).name for path in local_paths}
  contexts: dict[str, dict[str, list[
      tuple[tuple[str, ...], tuple[str, ...]]]]] = {}
  if source_overrides is not None:
    units = {relative: root / relative for relative in source_overrides}
  elif header_overrides is not None:
    units = {}
  else:
    units = {path.relative_to(root).as_posix(): path
        for path in root.glob("tests/**/*")
        if path.is_file() and path.suffix in SOURCE_SUFFIXES}

  def source_text(relative: str, path: Path) -> str:
    if source_overrides and relative in source_overrides:
      return source_overrides[relative]
    return path.read_text(encoding="utf-8", errors="replace")

  def header_text(relative: str) -> str:
    if header_overrides and relative in header_overrides:
      return header_overrides[relative]
    return (root / relative).read_text(encoding="utf-8", errors="replace")

  root_absolute = root.resolve()
  for unit_relative, unit_path in sorted(units.items()):
    try:
      language = PARSER.source_language(unit_relative)
    except ValueError:
      continue
    queue: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = [
        (unit_relative, source_text(unit_relative, unit_path),
         (unit_relative,), ())]
    while queue:
      current, text, chain, inherited_conditions = queue.pop(0)
      includes, unresolved = _local_includes(text, language)
      if unresolved:
        raise ValueError(
            f"{current}: unresolved local include directive(s): "
            + "; ".join(unresolved) + f" (chain {' -> '.join(chain)})")
      for include, conditions, delimiter in includes:
        candidates = []
        if delimiter == '"':
          candidates.append(((root / current).parent / include).resolve())
        candidates.extend([(root / include).resolve(),
            (root / "wyrelog" / include).resolve(),
            (root / "wyrelog" / "wyctl" / include).resolve()])
        relative = None
        for candidate in candidates:
          try:
            possible = candidate.relative_to(root_absolute).as_posix()
          except ValueError:
            continue
          if possible in local_paths:
            relative = possible
            break
        if relative is None:
          if (delimiter == '"' or
              (delimiter == "<" and
               (include.startswith(("wyrelog/", "tests/"))
                or include.startswith(("access/", "fact/", "auth/",
                    "daemon/", "wyctl/"))
                or Path(include).name in local_basenames))):
            raise ValueError(
                f"{current}: unresolved repository-local include "
                f"{delimiter}{include}{'>' if delimiter == '<' else chr(34)} "
                f"(chain {' -> '.join(chain)})")
          continue
        next_chain = chain + (relative,)
        next_conditions = inherited_conditions + tuple(
            f"{current}: {condition}" for condition in conditions)
        records = contexts.setdefault(relative, {}).setdefault(language, [])
        record = (next_chain, next_conditions)
        if record not in records:
          records.append(record)
        if relative not in chain:
          queue.append((relative, header_text(relative), next_chain,
              next_conditions))
  return contexts


def _validate_test_header_bindings(root: Path,
    overrides: dict[str, str] | None = None,
    source_overrides: dict[str, str] | None = None) -> list[str]:
  errors: list[str] = []
  try:
    contexts = _header_contexts(root, overrides, source_overrides)
  except ValueError as error:
    return [str(error)]
  if overrides or source_overrides:
    header_paths = set(overrides or {})
  else:
    header_paths = {path.relative_to(root).as_posix()
        for base in (root / "tests", root / "wyrelog")
        for path in base.glob("**/*") if path.is_file()
        and path.suffix in LOCAL_SUFFIXES}
    header_paths.update(path.name for path in root.iterdir()
        if path.is_file() and path.suffix in LOCAL_SUFFIXES)
  for relative in sorted(header_paths):
    if relative == "tests/test-exit-status.h":
      continue
    text = (overrides[relative] if overrides and relative in overrides
        else (root / relative).read_text(encoding="utf-8", errors="replace"))
    modes = contexts.get(relative, {})
    views = [(language, records) for language, records in sorted(modes.items())]
    if not views:
      views = [(language, []) for language in SUPPORTED_LANGUAGES]
    for language, records in views:
      logical, source_offsets = PARSER.c_logical_source(text, language)
      masked = PARSER.mask_noncode(logical)
      match = SANITIZER_BINDING.search(masked)
      if match is None:
        continue
      original = PARSER.original_offset(source_offsets, match.start(), len(text))
      line = PARSER._source_line(text, original)
      if records:
        chain, conditions = records[0]
        detail = f"include chain {' -> '.join(chain)} under {language}"
        if conditions:
          detail += "; unresolved conditional include(s): " + "; ".join(conditions)
      else:
        detail = (f"unused header conservatively scanned under {language}; "
            "potential false positive")
      errors.append(f"{relative}:{line}: test header rebinds a validated "
          f"status sanitizer ({detail})")
  return errors


def _validate_header(root: Path,
    header_overrides: dict[str, str] | None = None,
    source_overrides: dict[str, str] | None = None) -> list[str]:
  header = (header_overrides.get("tests/test-exit-status.h")
      if header_overrides and "tests/test-exit-status.h" in header_overrides
      else (root / "tests/test-exit-status.h").read_text(encoding="utf-8"))
  try:
    contexts = _header_contexts(root, header_overrides, source_overrides)
  except ValueError as error:
    return [str(error)]
  modes = contexts.get("tests/test-exit-status.h", {})
  languages = sorted(modes) if modes else list(SUPPORTED_LANGUAGES)
  shape_errors = [error for language in languages
      for error in _validate_header_text(header, language)]
  return (shape_errors + _validate_test_header_bindings(root,
      header_overrides, source_overrides))


def validate_repository(root: Path) -> list[str]:
  errors: list[str] = []
  try:
    returns, sites = inventory(root)
  except (OSError, ValueError) as error:
    return [str(error)]
  expected_returns = json.loads(
      (root / RETURNS_MANIFEST).read_text(encoding="utf-8"))
  expected_sites = json.loads(
      (root / SITES_MANIFEST).read_text(encoding="utf-8"))
  if returns != expected_returns:
    errors.append("main return inventory differs from "
        + RETURNS_MANIFEST)
  if sites != expected_sites:
    errors.append("direct termination inventory differs from "
        + SITES_MANIFEST)
  if returns["source_count"] != 170 or returns["main_definitions"] != 177:
    errors.append("main census changed; review and update the inventory")
  if (len(sites) != 76
      or sum(site["api"] == "_exit" for site in sites) != 53
      or sum(site["api"] == "_Exit" for site in sites) != 14
      or sum(site["api"] == "ExitProcess" for site in sites) != 2
      or sum(site["api"] == "TerminateProcess" for site in sites) != 6
      or sum(site["api"] == "WYL_TEST_SKIP" for site in sites) != 1):
    errors.append("direct termination API census changed unexpectedly")
  errors.extend(_validate_header(root))
  return errors


def self_test(root: Path) -> list[str]:
  errors: list[str] = []
  fixture_path = root / "tests/fixtures/test-exit-status-nested-lambda.cpp"
  fixture_source = fixture_path.read_text(encoding="utf-8")
  try:
    _fixture_mains, fixture_sites = _main_returns(
        fixture_source,
        "tests/fixtures/test-exit-status-nested-lambda.cpp")
  except ValueError as error:
    errors.append(f"nested lambda fixture is not normalized: {error}")
  else:
    if len(fixture_sites) != 3:
      errors.append("nested lambda fixture's outer returns were not found")
  outer_mutant = fixture_source.replace(
      "return wyl_test_normalize_exit_status (0);", "return 256;")
  try:
    _main_returns(outer_mutant, "nested-lambda-mutant.cpp")
  except ValueError:
    pass
  else:
    errors.append("nested lambda fixture outer-return mutation survived")
  fixture = (
      "int main (void) {\\n"
      "  auto nested = [] { return 256; };\\n"
      "  (void) nested;\\n"
      "  return wyl_test_normalize_exit_status (0);\\n"
      "}\\n")
  mains, returns = _main_returns(fixture, "nested-lambda.cpp")
  if mains != 1 or len(returns) != 1:
    errors.append("nested lambda return was attributed to main")
  mutant = fixture.replace(
      "return wyl_test_normalize_exit_status (0);", "return 256;")
  try:
    _main_returns(mutant, "nested-lambda-mutant.cpp")
  except ValueError:
    pass
  else:
    errors.append("outer main return mutation survived")
  comment_only = (
      "/* _exit(256); exit(256); quick_exit(256); */\\n"
      "int main(void) { return 0; }\\n")
  if _termination_sites(comment_only, "comment.c"):
    errors.append("comment-only termination call was counted")
  actual = "int child(void) { WYL_TEST_EXIT(256); }\\n"
  if len(_termination_sites(actual, "actual.c")) != 1:
    errors.append("actual termination call was not found")
  language_split_comment = "// ??/\n_exit (256);\n"
  if _termination_sites(language_split_comment, "c-trigraph-comment.c"):
    errors.append("C17 trigraph splice did not continue the line comment")
  try:
    _termination_sites(language_split_comment, "cpp17-line-comment.cpp")
  except ValueError as error:
    if "unwrapped POSIX termination primitive _exit" not in str(error):
      errors.append("C++17 line-splice mutation had the wrong diagnostic")
  else:
    errors.append("C++17 line comment incorrectly consumed the following _exit")
  for api in ("exit", "quick_exit"):
    try:
      _termination_sites(
          f"int opaque_status(void); int child(void) {{ "
          f"{api}(opaque_status()); }}\\n", "raw-exit.c")
    except ValueError as error:
      if f"unwrapped POSIX termination primitive {api}" not in str(error):
        errors.append(f"{api} rejection reported the wrong diagnostic: {error}")
    else:
      errors.append(f"unwrapped {api} termination call escaped the guard")
  for name, directive in (
      ("WYL_TEST_EXIT", "#define WYL_TEST_EXIT(status) _exit(status)"),
      ("WYL_TEST__EXIT", "#undef WYL_TEST__EXIT"),
  ):
    try:
      _termination_sites(
          f"{directive}\\nint child(void) {{ {name}(256); }}\\n",
          "shadowed-exit-macro.c")
    except ValueError as error:
      if "source-local preprocessor binding" not in str(error):
        errors.append(f"{name} shadow rejection had the wrong diagnostic")
    else:
      errors.append(f"source-local {name} binding escaped the guard")
  spliced_source_bindings = (
      "#define wyl_test_normalize_exit_??/\n"
      "status(x) (x)\n",
      "#undef wyl_test_normalize_exit_??/\n"
      "status\n",
      "??=define wyl_test_normalize_exit_status(x) (x)\n",
  )
  for directive in spliced_source_bindings:
    try:
      _termination_sites(directive + "int child(void) { return 0; }\n",
          "trigraph-spliced-sanitizer-binding.c")
    except ValueError as error:
      if "source-local preprocessor binding" not in str(error):
        errors.append("trigraph-spliced source binding had the wrong diagnostic")
    else:
      errors.append("trigraph-spliced source sanitizer binding escaped the guard")
  header = (root / "tests/test-exit-status.h").read_text(encoding="utf-8")
  sanitizer_mutations = (
      ("normalizer zero check", "status == 0", "status != 0"),
      ("normalizer replacement", "  return 1;", "  return status;"),
      ("normalized _Exit argument",
          "_Exit (WYL_TEST_EXIT_CAPTURE_NAME (__LINE__));",
          "_Exit (status_expression);"),
      ("normalized _exit argument",
          "_exit (WYL_TEST_EXIT_CAPTURE_NAME (__LINE__));",
          "_exit (status_expression);"),
  )
  for label, before, after in sanitizer_mutations:
    mutant = header.replace(before, after, 1)
    if mutant == header:
      errors.append(f"sanitizer mutation setup failed: {label}")
    elif not _validate_header_text(mutant):
      errors.append(f"sanitizer mutation survived: {label}")
  # These name the error they must provoke.  A mutation that merely turns the
  # gate red proves nothing about which check caught it -- the normalizer
  # bypass below went undetected for as long as it did because every existing
  # mutant targets a macro, so "some error appeared" was never the normalizer's
  # error.
  named_mutations = (
      ("normalizer returns the status verbatim",
          "  (void) fflush (stderr);\n  return 1;",
          "  (void) fflush (stderr);\n  if (status != 0)\n"
          "    return status;\n  return 1;",
          "POSIX normalizer does not map each nonzero status to 1"),
      ("skip primitive takes an argument",
          "#define WYL_TEST_SKIP() _exit (77)",
          "#define WYL_TEST_SKIP(status_expression) _exit (status_expression)",
          "WYL_TEST_SKIP is not the nullary 77 skip primitive"),
      ("skip primitive yields a status other than 77",
          "#define WYL_TEST_SKIP() _exit (77)",
          "#define WYL_TEST_SKIP() _exit (78)",
          "WYL_TEST_SKIP is not the nullary 77 skip primitive"),
  )
  for label, before, after, expected in named_mutations:
    mutant = header.replace(before, after, 1)
    if mutant == header:
      errors.append(f"sanitizer mutation setup failed: {label}")
      continue
    reported = _validate_header_text(mutant)
    if not reported:
      errors.append(f"sanitizer mutation survived: {label}")
    elif expected not in reported:
      errors.append(f"sanitizer mutation died on the wrong check: {label}: "
          f"expected {expected!r}, got {reported!r}")

  capture = "WYL_TEST_EXIT_CAPTURE_NAME (__LINE__)"
  guard_start = f"    if ({capture} != 0"
  reordered = header.replace(guard_start,
      f"    _Exit ({capture}); \\\n    if ({capture} != 0", 1)
  if reordered == header:
    errors.append("sanitizer mutation setup failed: early _Exit")
  elif not _validate_header_text(reordered):
    errors.append("early _Exit before normalization survived")
  bypass = header.replace(guard_start,
      f"    exit (status_expression); \\\n    if ({capture} != 0", 1)
  if bypass == header:
    errors.append("sanitizer mutation setup failed: alternate exit bypass")
  elif not _validate_header_text(bypass):
    errors.append("alternate primitive before normalization survived")
  outer_guard = header.replace(guard_start,
      f"    if (skip) {{ \\\n    if ({capture} != 0", 1)
  outer_guard = outer_guard.replace(f"    _Exit ({capture});",
      f"    }} \\\n    _Exit ({capture});", 1)
  if outer_guard == header:
    errors.append("sanitizer mutation setup failed: conditional guard")
  elif not _validate_header_text(outer_guard):
    errors.append("outer conditional around normalization survived")
  jump_around_guard = header.replace(guard_start,
      f"    goto exit_before_normalize; \\\n    if ({capture} != 0", 1)
  jump_around_guard = jump_around_guard.replace(f"    _Exit ({capture});",
      f"    exit_before_normalize: _Exit ({capture});", 1)
  if jump_around_guard == header:
    errors.append("sanitizer mutation setup failed: jump around guard")
  elif not _validate_header_text(jump_around_guard):
    errors.append("jump around normalization survived")
  for suffix, label in (
      ("\n#define wyl_test_normalize_exit_status(x) (x)\n",
          "trailing normalizer redefinition"),
      ("\n#undef WYL_TEST_EXIT\n", "trailing exit-wrapper undefinition"),
      ("\n??=define wyl_test_normalize_exit_??/\n"
       "status(x) (x)\n", "trigraph-spliced normalizer redefinition"),
      ("\n#undef WYL_TEST_??/\nEXIT\n",
          "trigraph-spliced wrapper undefinition"),
      ("\n#undef wyl_test_normalize_exit_??/\nstatus\n",
          "trigraph-spliced normalizer undefinition"),
  ):
    if not _validate_header_text(header + suffix):
      errors.append(f"trailing header binding survived: {label}")
  secondary_header = {
      "tests/fixtures/status-sanitizer-shadow.h":
          "#undef wyl_test_normalize_exit_??/\nstatus\n"}
  if not _validate_test_header_bindings(root, secondary_header):
    errors.append("secondary test-header sanitizer redefinition survived")
  shared_language_header = {
      "tests/fixtures/status-language-shadow.h":
          "// ??/\n#undef wyl_test_normalize_exit_status\n"}
  shared_language_sources = {
      "tests/fixtures/status-language-c.c":
          '#include <tests/fixtures/status-language-shadow.h>\n',
      "tests/fixtures/status-language-cpp.cpp":
          '#include "status-language-shadow.h"\n',
  }
  c_view, _c_offsets = PARSER.c_logical_source(
      shared_language_header["tests/fixtures/status-language-shadow.h"],
      "c17")
  cpp_view, _cpp_offsets = PARSER.c_logical_source(
      shared_language_header["tests/fixtures/status-language-shadow.h"],
      "c++17")
  if SANITIZER_BINDING.search(PARSER.mask_noncode(c_view)):
    errors.append("C17 shared-header comment mutation created a binding")
  if not SANITIZER_BINDING.search(PARSER.mask_noncode(cpp_view)):
    errors.append("C++17 shared-header binding mutation was not exposed")
  shared_language_errors = _validate_test_header_bindings(root,
      shared_language_header, shared_language_sources)
  if not any("status-language-shadow.h" in error
      and "c++17" in error for error in shared_language_errors):
    errors.append("shared-header language-specific binding escaped C++17 scan")
  shared_contexts = _header_contexts(root, shared_language_header,
      shared_language_sources)
  c_contexts = shared_contexts.get(
      "tests/fixtures/status-language-shadow.h", {}).get("c17", [])
  if not any(any(item.endswith("status-language-c.c") for item in chain)
      for chain, _conditions in c_contexts):
    errors.append("shared-header context omitted the C17 include chain")

  wyrelog_header = {
      "wyrelog/error.h": (root / "wyrelog/error.h").read_text(
          encoding="utf-8") + "\n#define wyl_test_normalize_exit_status(x) (x)\n"}
  wyrelog_source = {
      "tests/test-access-decision.c":
          "#include <wyrelog/access/decision-private.h>\n"}
  wyrelog_errors = _validate_test_header_bindings(root, wyrelog_header,
      wyrelog_source)
  if not any("wyrelog/error.h" in error
      and "tests/test-access-decision.c" in error
      and "wyrelog/access/decision-private.h" in error
      and "c17" in error for error in wyrelog_errors):
    errors.append("repository-local angle include transitive binding escaped")

  conditional_header = {
      "tests/fixtures/status-conditional-shadow.h":
          "#undef wyl_test_normalize_exit_status\n"}
  conditional_source = {
      "tests/fixtures/status-conditional-include.c":
          "#if ENABLE_STATUS_SHADOW\n"
          "#include \"status-conditional-shadow.h\"\n"
          "#endif\n"}
  conditional_errors = _validate_test_header_bindings(root,
      conditional_header, conditional_source)
  if not any("unresolved conditional include(s)" in error
      and "ENABLE_STATUS_SHADOW" in error
      and "status-conditional-include.c" in error
      for error in conditional_errors):
    errors.append("conditional header binding was not rejected with its chain")
  unresolved_include_errors = _validate_test_header_bindings(root, {}, {
      "tests/fixtures/status-unresolved-include.c":
          '#include "wyrelog/missing-status-header.h"\n'})
  if not any("unresolved repository-local include" in error
      and "status-unresolved-include.c" in error
      for error in unresolved_include_errors):
    errors.append("unresolved quoted local include was not rejected")
  basename_errors = _validate_test_header_bindings(root, {}, {
      "tests/fixtures/status-basename-include.c":
          "#include <decision-private.h>\n"})
  if not any("unresolved repository-local include" in error
      and "status-basename-include.c" in error for error in basename_errors):
    errors.append("unresolved project-header basename was not rejected")
  malformed_errors = _validate_test_header_bindings(root, {}, {
      "tests/fixtures/status-malformed-conditional.c": "#endif\n"})
  if not any("malformed conditional directive" in error
      for error in malformed_errors):
    errors.append("unmatched conditional directive was not rejected")
  for malformed in (
      "#if ENABLE_STATUS_SHADOW\n#else\n#else\n#endif\n",
      "#if ENABLE_STATUS_SHADOW\n#else\n#elif OTHER\n#endif\n",
  ):
    errors_for_branch = _validate_test_header_bindings(root, {}, {
        "tests/fixtures/status-duplicate-conditional.c": malformed})
    if not any("malformed conditional directive" in error
        for error in errors_for_branch):
      errors.append("duplicate conditional branch was not rejected")
  fragment = {
      "wyrelog/access/status-source-fragment.c":
          "#define wyl_test_normalize_exit_status(x) (x)\n"}
  fragment_source = {
      "tests/test-access-decision.c":
          "#include <access/status-source-fragment.c>\n"}
  fragment_errors = _validate_test_header_bindings(root, fragment,
      fragment_source)
  if not any("status-source-fragment.c" in error
      and "test-access-decision.c" in error for error in fragment_errors):
    errors.append("source-fragment sanitizer binding escaped closure scan")
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
  print("exit status boundaries: OK")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

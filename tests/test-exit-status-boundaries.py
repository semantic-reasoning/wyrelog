#!/usr/bin/env python3
"""Inventory process-status boundaries and require normalized test mains."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
RETURNS_MANIFEST = "tests/test-exit-status-returns.json"
SITES_MANIFEST = "tests/test-exit-status-sites.json"
SUPPORT_SOURCES = {"tests/test-exit-status-termination.c"}
SOURCE_SUFFIXES = {".c", ".cc", ".cpp"}
EXIT_CALL = re.compile(
    r"\b(WYL_TEST__EXIT|WYL_TEST_EXIT|ExitProcess|TerminateProcess|"
    r"_Exit|_exit|quick_exit|exit)\s*\(")
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
  masked = PARSER.mask_noncode(text)
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
      line = PARSER._source_line(masked, match.start())
      if not expression:
        raise ValueError(f"{source}:{line}: main has a bare return")
      if not re.match(r"^wyl_test_normalize_exit_status\s*\(", expression):
        raise ValueError(
            f"{source}:{line}: main return is not normalized: {expression}")
      rows.append({"line": line, "expression": expression})
  return len(mains), rows


def _termination_sites(text: str, source: str
    ) -> list[dict[str, object]]:
  masked = PARSER.mask_noncode(text)
  sites: list[dict[str, object]] = []
  for match in EXIT_CALL.finditer(masked):
    api = match.group(1)
    if api in {"_Exit", "_exit", "exit", "quick_exit"}:
      raise ValueError(
          f"{source}:{PARSER._source_line(masked, match.start())}: "
          f"unwrapped POSIX termination primitive {api}")
    opening = masked.find("(", match.start(), match.end())
    closing = PARSER._matching_delimiter(masked, opening, "(", ")")
    args = masked[opening + 1:closing].strip()
    if api in {"WYL_TEST__EXIT", "WYL_TEST_EXIT"}:
      tail = masked[closing + 1:]
      tail = tail[len(tail) - len(tail.lstrip()):]
      if not tail.startswith(";"):
        raise ValueError(
            f"{source}:{PARSER._source_line(masked, match.start())}: "
            f"{api} is not used as a statement")
      line = PARSER._source_line(masked, match.start())
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
        "line": PARSER._source_line(masked, match.start()),
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


def _validate_header(root: Path) -> list[str]:
  header = (root / "tests/test-exit-status.h").read_text(encoding="utf-8")
  errors: list[str] = []
  for primitive, macro in (("_exit", "WYL_TEST_EXIT"),
      ("_Exit", "WYL_TEST__EXIT")):
    block = re.search(
        r"#define " + macro + r"\(status_expression\)(.*?)(?=\n#define |\n#else)",
        header, re.S)
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
  if "status != 0" not in header or "% 256 == 0" not in header:
    errors.append("POSIX normalization does not preserve zero and detect 256 multiples")
  return errors


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
  if returns["source_count"] != 159 or returns["main_definitions"] != 166:
    errors.append("main census changed; review and update the inventory")
  if (len(sites) != 70
      or sum(site["api"] == "_exit" for site in sites) != 49
      or sum(site["api"] == "_Exit" for site in sites) != 13
      or sum(site["api"] == "ExitProcess" for site in sites) != 2
      or sum(site["api"] == "TerminateProcess" for site in sites) != 6):
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
  for api in ("exit", "quick_exit"):
    try:
      _termination_sites(f"int child(void) {{ {api}(256); }}\\n", "raw-exit.c")
    except ValueError as error:
      if f"unwrapped POSIX termination primitive {api}" not in str(error):
        errors.append(f"{api} rejection reported the wrong diagnostic: {error}")
    else:
      errors.append(f"unwrapped {api} termination call escaped the guard")
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

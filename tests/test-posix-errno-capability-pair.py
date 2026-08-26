#!/usr/bin/env python3
"""Guard the ENOTSUP/EOPNOTSUPP capability-classification contract."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import sys


HEADER = "wyrelog/wyl-posix-errno-private.h"
PUBLICATION = "wyrelog/wyctl/wyctl-publication-posix-private.c"
STORE_LEASE = "wyrelog/policy/store-lease.c"
GRAPH_LOCATOR = "wyrelog/fact/graph-locator-private.c"
PAIR_HELPER = "wyl_posix_errno_is_operation_unsupported"
TOKEN_PASTE_ALLOWLIST = {
    "wyrelog/wyctl/wyctl-publication-backend-private.c": Counter({
        ("wyctl_publication_windows_", "op"): 1,
        ("wyctl_publication_posix_", "op"): 1,
    }),
    "wyrelog/daemon/http.c": Counter({
        ("WYL_DAEMON_POLICY_WRITE_OWNER_", "symbol"): 2,
    }),
}
TRIGRAPHS = {
    "??=": "#",
    "??/": "\\",
    "??'": "^",
    "??(": "[",
    "??)": "]",
    "??!": "|",
    "??<": "{",
    "??>": "}",
    "??-": "~",
}


class ContractError(AssertionError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise ContractError(code, detail)


def c_code_only(source: str) -> str:
    """Blank C comments and literals while preserving offsets and newlines."""
    # Translation phase 1 replaces trigraphs, then phase 2 removes each
    # backslash-newline.  Apply them in that order so both a literal splice and
    # an ENO??/<newline>TSUP splice expose the identifier the compiler sees.
    for trigraph, replacement in TRIGRAPHS.items():
        source = source.replace(trigraph, replacement)
    source = re.sub(r"\\(?:\r\n|\n|\r)", "", source)
    # %:%: is the preprocessing-token digraph for ##.  Canonicalize it before
    # comments and literals are blanked so paste inventory sees either spelling.
    source = source.replace("%:%:", "##")
    output = list(source)
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block-comment"
                index += 2
                continue
            if current == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line-comment"
                index += 2
                continue
            if current == '"':
                output[index] = " "
                state = "string"
            elif current == "'":
                output[index] = " "
                state = "character"
        elif state == "block-comment":
            if current == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if current != "\n":
                output[index] = " "
        elif state == "line-comment":
            if current == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state in {"string", "character"}:
            delimiter = '"' if state == "string" else "'"
            if current == "\\":
                output[index] = " "
                if index + 1 < len(source):
                    if source[index + 1] != "\n":
                        output[index + 1] = " "
                    index += 2
                    continue
            if current == delimiter:
                output[index] = " "
                state = "code"
            elif current != "\n":
                output[index] = " "
        index += 1
    return "".join(output)


def compact(source: str) -> str:
    return re.sub(r"\s+", " ", source).strip()


def function_extent(source: str, name: str) -> tuple[int, int, int]:
    match = re.search(rf"\b{re.escape(name)}\s*\([^;]*?\)\s*\{{", source, re.S)
    require(match is not None, "E_FUNCTION", f"missing function {name}")
    assert match is not None
    body_start = match.end()
    depth = 1
    for index in range(body_start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return match.start(), body_start, index
    raise ContractError("E_FUNCTION", f"unterminated function {name}")


def function_body(source: str, name: str) -> str:
    _start, body_start, body_end = function_extent(source, name)
    return source[body_start:body_end]


def if_conditions(source: str) -> list[tuple[int, int, str]]:
    conditions: list[tuple[int, int, str]] = []
    for match in re.finditer(r"\bif\s*\(", source):
        open_paren = source.find("(", match.start())
        depth = 1
        index = open_paren + 1
        while index < len(source) and depth:
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
            index += 1
        require(depth == 0, "E_PARSE", "unterminated if condition")
        conditions.append((open_paren + 1, index - 1,
                           source[open_paren + 1:index - 1]))
    return conditions


def check_pair_helper(files: dict[str, str]) -> None:
    header = c_code_only(files[HEADER])
    body = function_body(header, PAIR_HELPER)
    require(len(re.findall(r"\bENOTSUP\b", body)) == 2,
            "E_PAIR_ENOTSUP", "helper must own ENOTSUP and alias guard")
    require(len(re.findall(r"\bEOPNOTSUPP\b", body)) == 2,
            "E_PAIR_EOPNOTSUPP",
            "helper must own EOPNOTSUPP and alias guard")
    enotsup_if = body.find("error_code == ENOTSUP")
    alias_guard = body.find("#if EOPNOTSUPP != ENOTSUP")
    eopnotsupp_if = body.find("error_code == EOPNOTSUPP")
    alias_end = body.find("#endif", alias_guard)
    require(enotsup_if >= 0, "E_PAIR_ENOTSUP",
            "helper does not classify ENOTSUP")
    require(alias_guard > enotsup_if and eopnotsupp_if > alias_guard
            and alias_end > eopnotsupp_if,
            "E_PAIR_EOPNOTSUPP",
            "EOPNOTSUPP must be classified inside the alias-safe guard")


def check_publication(files: dict[str, str]) -> None:
    source = c_code_only(files[PUBLICATION])
    require('#include "wyrelog/wyl-posix-errno-private.h"' in files[PUBLICATION],
            "E_FULLFSYNC_INCLUDE", "publication does not include pair helper")
    body = compact(function_body(source, "fsync_fd_checked"))
    success = "if (fcntl (fd, F_FULLFSYNC) == 0) return WYRELOG_E_OK;"
    capture = "int fullfsync_errno = errno;"
    condition = ("if (fullfsync_errno != EINVAL && fullfsync_errno != ENOTTY "
                 f"&& !{PAIR_HELPER} (fullfsync_errno))")
    mapping = "return map_errno_to_error (fullfsync_errno);"
    fallback = "if (fsync (fd) != 0) return map_errno_to_error (errno);"
    require(success in body, "E_FULLFSYNC_SUCCESS",
            "F_FULLFSYNC success path changed")
    require(f"{success} {capture}" in body, "E_FULLFSYNC_CAPTURE",
            "F_FULLFSYNC errno is not captured immediately")
    require(condition in body, "E_FULLFSYNC_PAIR",
            "fallback does not use the paired unsupported predicate")
    require(f"{condition} {mapping}" in body, "E_FULLFSYNC_CAPTURED_MAP",
            "hard failure is not mapped from captured F_FULLFSYNC errno")
    require(fallback in body and body.index(fallback) > body.index(mapping),
            "E_FULLFSYNC_FALLBACK",
            "ordinary fsync fallback is absent or reordered")


def check_dormant_exceptions(files: dict[str, str]) -> None:
    store = c_code_only(files[STORE_LEASE])
    store_body = compact(function_body(store, "lock_nonblocking"))
    require("#if defined(__linux__) && defined(F_OFD_SETLK)" in store_body,
            "E_STORE_GUARD", "OFD fallback exception is not Linux-only")
    store_condition = ("errno != EINVAL && errno != ENOSYS "
                       "&& errno != EOPNOTSUPP")
    require(store_condition in store_body and "ENOTSUP" not in store_body,
            "E_STORE_EXCEPTION", "OFD fallback exception drifted")

    graph = c_code_only(files[GRAPH_LOCATOR])
    graph_body = compact(function_body(graph, "link_held_stage_no_overwrite"))
    require("#ifdef __linux__" in graph_body,
            "E_GRAPH_GUARD", "graph-link exception is not Linux-only")
    require(graph_body.count("case EOPNOTSUPP:") == 1
            and "ENOTSUP" not in graph_body,
            "E_GRAPH_EXCEPTION", "graph-link exception drifted")


def check_one_sided_inventory(files: dict[str, str]) -> None:
    allowed_if = {
        (STORE_LEASE,
         compact("errno != EINVAL && errno != ENOSYS "
                 "&& errno != EOPNOTSUPP")),
    }
    allowed_case = {(GRAPH_LOCATOR, "EOPNOTSUPP")}
    for path, raw_source in sorted(files.items()):
        if (not path.startswith("wyrelog/")
                or not path.endswith((".c", ".h"))):
            continue
        source = c_code_only(raw_source)
        if path == HEADER:
            helper_start, _body_start, helper_end = function_extent(
                source, PAIR_HELPER
            )
            source = (
                source[:helper_start]
                + "".join(
                    "\n" if character == "\n" else " "
                    for character in source[helper_start:helper_end + 1]
                )
                + source[helper_end + 1:]
            )
        covered: set[int] = set()
        for start, end, condition in if_conditions(source):
            names = set(re.findall(r"\b(?:ENOTSUP|EOPNOTSUPP)\b", condition))
            if names:
                covered.update(range(start, end))
            if len(names) == 1:
                require((path, compact(condition)) in allowed_if,
                        "E_ONE_SIDED",
                        f"one-sided if classification in {path}")
        for match in re.finditer(r"\bcase\s+(ENOTSUP|EOPNOTSUPP)\s*:", source):
            covered.update(range(match.start(), match.end()))
            require((path, match.group(1)) in allowed_case,
                    "E_ONE_SIDED", f"one-sided case classification in {path}")
        for match in re.finditer(r"\b(?:ENOTSUP|EOPNOTSUPP)\b", source):
            require(match.start() in covered, "E_UNINVENTORIED",
                    f"unsupported errno outside an inventoried condition in {path}")


def check_token_paste_inventory(files: dict[str, str]) -> None:
    """Fail closed on new token-paste machinery that could mint errno names."""
    require(TOKEN_PASTE_ALLOWLIST.keys() <= files.keys(),
            "E_TOKEN_PASTE", "token-paste allowlist source is missing")
    for path, raw_source in sorted(files.items()):
        if (not path.startswith("wyrelog/")
                or not path.endswith((".c", ".h"))):
            continue
        source = c_code_only(raw_source)
        actual = Counter(re.findall(
            r"\b([A-Za-z_]\w*)\s*##\s*([A-Za-z_]\w*)\b", source
        ))
        allowed = TOKEN_PASTE_ALLOWLIST.get(path, Counter())
        require(actual == allowed, "E_TOKEN_PASTE",
                f"token-paste inventory drift in {path}: "
                f"actual={dict(actual)} expected={dict(allowed)}")


def check_contract(files: dict[str, str]) -> None:
    check_pair_helper(files)
    check_publication(files)
    check_dormant_exceptions(files)
    check_token_paste_inventory(files)
    check_one_sided_inventory(files)


def load_files(root: Path) -> dict[str, str]:
    files = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for pattern in ("*.c", "*.h")
        for path in (root / "wyrelog").rglob(pattern)
    }
    return files


def replace_once(files: dict[str, str], path: str, old: str, new: str) -> dict[str, str]:
    require(files[path].count(old) == 1, "E_SELF_MUTATION",
            f"mutation anchor is not unique in {path}")
    mutated = dict(files)
    mutated[path] = files[path].replace(old, new, 1)
    return mutated


def expect_failure(files: dict[str, str], expected: str) -> None:
    try:
        check_contract(files)
    except ContractError as error:
        require(error.code == expected, "E_SELF_DIAGNOSTIC",
                f"expected {expected}, got {error.code}")
        return
    raise ContractError("E_SELF_ACCEPTED", f"mutation passed: {expected}")


def self_test(root: Path) -> None:
    files = load_files(root)
    check_contract(files)
    expect_failure(replace_once(files, HEADER,
        "  if (error_code == ENOTSUP)\n    return TRUE;\n", ""),
        "E_PAIR_ENOTSUP")
    expect_failure(replace_once(files, HEADER,
        "  if (error_code == EOPNOTSUPP)\n    return TRUE;\n", ""),
        "E_PAIR_EOPNOTSUPP")
    expect_failure(replace_once(files, PUBLICATION,
        f"!{PAIR_HELPER} (fullfsync_errno)",
        "fullfsync_errno != ENOTSUP"), "E_FULLFSYNC_PAIR")
    expect_failure(replace_once(files, PUBLICATION,
        "map_errno_to_error (fullfsync_errno)", "map_errno_to_error (errno)"),
        "E_FULLFSYNC_CAPTURED_MAP")
    expect_failure(replace_once(files, PUBLICATION,
        "  int fullfsync_errno = errno;\n",
        "  (void) fsync (fd);\n  int fullfsync_errno = errno;\n"),
        "E_FULLFSYNC_CAPTURE")
    expect_failure(replace_once(files, PUBLICATION,
        "  if (fsync (fd) != 0)\n", "  if (0 != 0)\n"),
        "E_FULLFSYNC_FALLBACK")
    new_site = dict(files)
    new_site["wyrelog/new-one-sided.c"] = (
        "#include <errno.h>\nint f(int err) { if (err == ENOTSUP) return 1; "
        "return 0; }\n"
    )
    expect_failure(new_site, "E_ONE_SIDED")
    existing_header_site = dict(files)
    existing_header_site[HEADER] += (
        "\nstatic inline int one_sided_header (int error_code)\n"
        "{\n  if (error_code == ENOTSUP)\n    return 1;\n  return 0;\n}\n"
    )
    expect_failure(existing_header_site, "E_ONE_SIDED")
    new_header_site = dict(files)
    new_header_site["wyrelog/new-one-sided.h"] = (
        "#include <errno.h>\nstatic inline int f (int error_code)\n"
        "{\n  if (error_code == EOPNOTSUPP)\n    return 1;\n  return 0;\n}\n"
    )
    expect_failure(new_header_site, "E_ONE_SIDED")
    spliced_header_site = dict(files)
    spliced_header_site["wyrelog/new-spliced-one-sided.h"] = (
        "#include <errno.h>\nstatic inline int f (int error_code)\n"
        "{\n  if (error_code == ENO\\\nTSUP)\n    return 1;\n  return 0;\n}\n"
    )
    expect_failure(spliced_header_site, "E_ONE_SIDED")
    spliced_eop_header_site = dict(files)
    spliced_eop_header_site["wyrelog/new-spliced-eop-one-sided.h"] = (
        "#include <errno.h>\nstatic inline int f (int error_code)\n"
        "{\n  if (error_code == EOPNOT\\\nSUPP)\n    return 1;\n  return 0;\n}\n"
    )
    expect_failure(spliced_eop_header_site, "E_ONE_SIDED")
    crlf_spliced_header_site = dict(files)
    crlf_spliced_header_site["wyrelog/new-crlf-spliced-one-sided.h"] = (
        "#include <errno.h>\r\nstatic inline int f (int error_code)\r\n"
        "{\r\n  if (error_code == ENO\\\r\nTSUP)\r\n"
        "    return 1;\r\n  return 0;\r\n}\r\n"
    )
    expect_failure(crlf_spliced_header_site, "E_ONE_SIDED")
    trigraph_spliced_header_site = dict(files)
    trigraph_spliced_header_site["wyrelog/new-trigraph-spliced-one-sided.h"] = (
        "#include <errno.h>\nstatic inline int f (int error_code)\n"
        "{\n  if (error_code == ENO??/\nTSUP)\n"
        "    return 1;\n  return 0;\n}\n"
    )
    expect_failure(trigraph_spliced_header_site, "E_ONE_SIDED")
    pasted_header_site = dict(files)
    pasted_header_site["wyrelog/new-pasted-one-sided.h"] = (
        "#include <errno.h>\n#define WYL_JOIN(a, b) a ## b\n"
        "static inline int f (int error_code)\n"
        "{\n  if (error_code == WYL_JOIN(ENO, TSUP))\n"
        "    return 1;\n  return 0;\n}\n"
    )
    expect_failure(pasted_header_site, "E_TOKEN_PASTE")
    digraph_pasted_header_site = dict(files)
    digraph_pasted_header_site["wyrelog/new-digraph-pasted-one-sided.h"] = (
        "#include <errno.h>\n#define WYL_JOIN(a, b) a %:%: b\n"
        "static inline int f (int error_code)\n"
        "{\n  if (error_code == WYL_JOIN(ENO, TSUP))\n"
        "    return 1;\n  return 0;\n}\n"
    )
    expect_failure(digraph_pasted_header_site, "E_TOKEN_PASTE")
    trigraph_pasted_header_site = dict(files)
    trigraph_pasted_header_site["wyrelog/new-trigraph-pasted-one-sided.h"] = (
        "#include <errno.h>\n#define WYL_JOIN(a, b) a ??=??= b\n"
        "static inline int f (int error_code)\n"
        "{\n  if (error_code == WYL_JOIN(EOPNOT, SUPP))\n"
        "    return 1;\n  return 0;\n}\n"
    )
    expect_failure(trigraph_pasted_header_site, "E_TOKEN_PASTE")
    expect_failure(replace_once(files,
        "wyrelog/wyctl/wyctl-publication-backend-private.c",
        "wyctl_publication_windows_ ## op",
        "wyctl_publication_windows_ op"), "E_TOKEN_PASTE")
    expect_failure(replace_once(files, STORE_LEASE,
        "#if defined(__linux__) && defined(F_OFD_SETLK)",
        "#if defined(F_OFD_SETLK)"), "E_STORE_GUARD")
    expect_failure(replace_once(files, GRAPH_LOCATOR,
        "#ifdef __linux__\n  g_autofree gchar *source",
        "#if 1\n  g_autofree gchar *source"), "E_GRAPH_GUARD")
    decoy = replace_once(files, HEADER,
        "  if (error_code == EOPNOTSUPP)\n    return TRUE;\n", "")
    decoy[HEADER] += (
        '\n/* if (error_code == EOPNOTSUPP) */\n'
        'static const char *pair_decoy = "error_code == EOPNOTSUPP";\n'
    )
    expect_failure(decoy, "E_PAIR_EOPNOTSUPP")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test(Path(__file__).resolve().parents[1])
        print("posix errno capability pair self-test: OK")
        return 0
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} ROOT|--self-test", file=sys.stderr)
        return 2
    check_contract(load_files(Path(sys.argv[1]).resolve()))
    print("posix errno capability pair: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

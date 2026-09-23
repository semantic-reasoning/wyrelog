#!/usr/bin/env python3
"""Guard how a pre-include feature-test macro define may be conditioned.

A feature-test macro only takes effect if it is defined before the first
system header, so its guard has to be answerable there too.  Macros that a
configuration header supplies -- G_OS_WIN32 and its siblings come from
glibconfig.h, reachable only through <glib.h> -- are undefined at that point
on every platform, so a guard written with one is always true and silently
defines the macro on the platform it was meant to exclude.  Only
compiler-predefined or command-line macros such as _WIN32 and __APPLE__ can
answer there.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOTS = ("tests", "wyrelog", "tools")
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp")
FEATURE_TEST_MACROS = (
    "_POSIX_C_SOURCE",
    "_XOPEN_SOURCE",
    "_GNU_SOURCE",
    "_DARWIN_C_SOURCE",
    "_DEFAULT_SOURCE",
    "_BSD_SOURCE",
    "_POSIX_SOURCE",
)
# Tokens a configuration header defines.  None of them is answerable before
# that header has been included, which is the whole defect.
CONFIG_TOKEN_PREFIXES = ("G_OS_", "G_PLATFORM_", "GLIB_")
CONDITIONAL_DIRECTIVES = ("if", "ifdef", "ifndef", "elif", "elifdef",
                          "elifndef")
DIRECTIVE_RE = re.compile(
    r"^[ \t]*#[ \t]*(" + "|".join(CONDITIONAL_DIRECTIVES) + r")\b(.*)$")
INCLUDE_RE = re.compile(r"^[ \t]*#[ \t]*include\b")
DEFINE_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

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


def offending_tokens(expression: str) -> list[str]:
    """Every configuration-header token in one controlling expression.

    Token-level on purpose: the rule is "the controlling expression contains
    such a token", not "the directive is spelled #ifndef".  Matching a fixed
    set of shapes would pass #elif, a bare #if G_OS_WIN32, defined without
    parentheses, and any compound expression.
    """
    return [token for token in IDENTIFIER_RE.findall(expression)
            if token.startswith(CONFIG_TOKEN_PREFIXES)]


def scan_source(relative_path: str, source: str) -> list[str]:
    """Findings for one translation unit, as operator-facing lines."""
    lines = c_code_only(source).splitlines()
    first_include = next(
        (index for index, line in enumerate(lines) if INCLUDE_RE.match(line)),
        len(lines))
    preamble = lines[:first_include]
    defined = [DEFINE_RE.match(line).group(1) for line in preamble
               if DEFINE_RE.match(line)]
    feature_tests = [name for name in defined if name in FEATURE_TEST_MACROS]
    if not feature_tests:
        # No pre-include feature-test define, so nothing here can be
        # conditioned wrongly.  A file with no #include at all lands here too.
        return []
    findings = []
    for index, line in enumerate(preamble):
        match = DIRECTIVE_RE.match(line)
        if match is None:
            continue
        for token in offending_tokens(match.group(2)):
            findings.append(
                f"{relative_path}:{index + 1}: #{match.group(1)} is controlled "
                f"by {token}, which no header has defined yet, so it cannot "
                f"guard the {', '.join(sorted(set(feature_tests)))} define "
                f"below it")
    return findings


def load_sources(root: Path) -> dict[str, str]:
    """Every C/C++ source under the project's own directories.

    Scoped to ROOTS rather than the whole tree: a checkout can carry unrelated
    working copies (a nested worktree, a vendored build) whose contents are not
    this project's contract to keep.  git is deliberately not consulted, so the
    gate still runs from an exported tarball.
    """
    sources = {}
    for name in ROOTS:
        directory = root / name
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            sources[relative] = path.read_text(encoding="utf-8")
    return sources


def check_contract(sources: dict[str, str]) -> None:
    findings = []
    for relative_path, source in sorted(sources.items()):
        findings.extend(scan_source(relative_path, source))
    if findings:
        raise ContractError("E_CONFIG_TOKEN_GUARD", "\n" + "\n".join(findings))


def self_test() -> None:
    def expect_failure(sources: dict[str, str], code: str) -> None:
        try:
            check_contract(sources)
        except ContractError as error:
            if error.code != code:
                raise AssertionError(
                    f"expected {code}, got {error.code}") from error
            return
        raise AssertionError(f"expected {code}, contract accepted the source")

    def expect_success(sources: dict[str, str]) -> None:
        check_contract(sources)

    define = "#define _POSIX_C_SOURCE 200809L\n"
    # One planted violation per directive shape the rule covers.  A self-test
    # that plants only the shape the matcher was written for is an assertion
    # that cannot fail.
    for guard in (
            "#ifndef G_OS_WIN32",
            "#ifdef G_OS_WIN32",
            "#if !defined(G_OS_WIN32)",
            "#if defined G_OS_WIN32",
            "#if G_OS_WIN32",
            "#if defined(G_OS_WIN32) || defined(SOMETHING_ELSE)",
            "#if GLIB_SIZEOF_VOID_P == 8",
    ):
        expect_failure(
            {"tests/planted.c": f"{guard}\n{define}#endif\n#include <stdio.h>\n"},
            "E_CONFIG_TOKEN_GUARD")
    expect_failure(
        {"tests/planted.c": "#ifdef __linux__\n#define _GNU_SOURCE 1\n"
                            "#elif defined(G_OS_WIN32)\n#define _GNU_SOURCE 1\n"
                            "#endif\n#include <stdio.h>\n"},
        "E_CONFIG_TOKEN_GUARD")
    # A compiler-predefined guard is the fix, and must stay accepted.
    expect_success(
        {"tests/planted.c": f"#ifndef _WIN32\n{define}#endif\n"
                            "#include <stdio.h>\n"})
    # The same token AFTER the first include is correct and must stay accepted:
    # glib has supplied it by then.
    expect_success(
        {"tests/planted.c": "#include <glib.h>\n#ifdef G_OS_WIN32\n"
                            "#include <windows.h>\n#endif\n"})
    # No pre-include feature-test define, so a pre-include config token is not
    # this contract's business.
    expect_success(
        {"tests/planted.c": "#ifndef G_OS_WIN32\n#define LOCAL_THING 1\n"
                            "#endif\n#include <stdio.h>\n"})
    # A comment is not code.  Without the literal/comment blanking this is the
    # false positive the scanner would report.
    expect_success(
        {"tests/planted.c": "/* G_OS_WIN32 is unanswerable here; see #1216. */\n"
                            "#include \"local.h\"\n#ifdef G_OS_WIN32\n"
                            "#endif\n"})


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        print("feature-test macro platform guard self-test: OK")
        return 0
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} ROOT|--self-test",
              file=sys.stderr)
        return 2
    check_contract(load_sources(Path(sys.argv[1]).resolve()))
    print("feature-test macro platform guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

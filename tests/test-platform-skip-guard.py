#!/usr/bin/env python3
"""Reject platform-conditional test bodies that return with nothing run.

A test case that does

    #ifdef __APPLE__
      return;
    #else
      ... assertions ...
    #endif

reports PASS on macOS with no assertion run and no skip recorded, so every
summary counts it as coverage the platform does not have.  This guard pins
that shape: inside a function whose name starts with ``test_``, a
preprocessor arm whose condition names a platform macro and whose only
statements are ``return;`` (comments and ``(void) x;`` casts aside) is an
offense.  The fix is to report ``g_test_skip`` with a platform-specific
reason before returning, or to run the platform's own assertions.

The guard pins the shape, not the outcome.  An arm that calls a helper is
accepted whether or not that helper skips, as is an arm with an assertion,
a declaration or any other statement.  An ``#elif`` or ``#else`` arm of a
chain that named a platform macro earlier is a platform arm too: its
controlling condition is the negation of that chain, so the swapped form
``#ifndef __APPLE__ ... #else return; #endif`` is the same silent PASS.
An arm is judged on everything it contains, nested arms included, so an
outer platform arm whose only statement sits behind a nested non-platform
condition is still return-only.

Known limits of the function attribution: a K&R definition, a test name
produced by a macro, a function-pointer return type, and a call-shaped
attribute macro other than ``G_GNUC_*`` between the parameter list and the
body are not recognised as ``test_`` definitions.  None of these shapes
exists under tests/ today.  A cast of a member access such as
``(void) fixture->x;`` counts as a statement, which errs towards accepting.
Other ways to leave a body unrun are outside the pinned shape: a platform
arm that is empty because its skip was deleted, a return wrapped in braces
or G_STMT_START, and a goto that jumps past the assertions.

A block conditioned only on a feature macro such as
WYL_HAS_SECURE_DUCKDB_BRIDGE is out of scope; tools/report-inactive-suites.py
is the answer for option-gated coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import re
import sys
import tempfile


SCAN_DIR = "tests"
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp")
PLATFORM_MACROS = ("__APPLE__", "__linux__", "G_OS_WIN32", "_WIN32",
                   "G_OS_UNIX")
DIRECTIVE_RE = re.compile(r"^[ \t]*#[ \t]*([A-Za-z_]+)\b(.*)$")
OPENERS = ("if", "ifdef", "ifndef")
MIDDLES = ("elif", "elifdef", "elifndef", "else")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A discarded expression statement on a plain identifier, the idiom for an
# unused parameter.  Anything with more structure counts as a statement.
CAST_RE = re.compile(r"\(\s*void\s*\)\s*[A-Za-z_][A-Za-z0-9_]*\s*;")
# Call-shaped tokens that can precede a brace without naming a function.
CONTROL = {"if", "for", "while", "switch", "do", "else", "return", "sizeof",
           "catch", "defined"}
ATTRIBUTES = {"__attribute__", "__declspec", "alignas", "_Alignas",
              "noexcept", "decltype"}
CALL_SHAPED_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_:~]*\s*\(|[()]")
OFFENSE_RE = re.compile(r"(?:return;)+")

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
    def __init__(self, code: str, detail: str,
                 findings: list[str] | None = None) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.findings = findings or []


def require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise ContractError(code, detail)


def c_code_only(source: str) -> str:
    """Blank C comments and literals while preserving offsets and newlines.

    Copied from tests/test-feature-test-macro-platform-guard.py with two
    deviations.  That guard deletes each backslash-newline splice with
    ``re.sub(r"\\(?:\r\n|\n|\r)", "", source)``, which shifts every later
    line number; this guard cites directive lines, so a splice is joined
    into its logical line and the newlines it consumed are re-emitted after
    it, keeping the physical line count intact.  And a literal ends at the
    end of its line, so a stray quote in ``#if 0`` prose or an ``#error``
    message does not blind the rest of the unit.
    """
    # Translation phase 1 replaces trigraphs, then phase 2 removes each
    # backslash-newline.  Apply them in that order so both a literal splice and
    # an ENO??/<newline>TSUP splice expose the identifier the compiler sees.
    for trigraph, replacement in TRIGRAPHS.items():
        source = source.replace(trigraph, replacement)
    joined = []
    pending = 0
    buffer = ""
    for line in re.split(r"\r\n|\n|\r", source):
        if line.endswith("\\"):
            buffer += line[:-1]
            pending += 1
            continue
        joined.append(buffer + line)
        joined.extend([""] * pending)
        buffer = ""
        pending = 0
    if buffer:
        joined.append(buffer)
        joined.extend([""] * (pending - 1))
    source = "\n".join(joined)
    # %:%: is the preprocessing-token digraph for ##.  Canonicalize it before
    # comments and literals are blanked so either spelling reads the same.
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
            elif current == "\n":
                # A C literal cannot span a line once splices are joined, so
                # an unterminated quote ends with its line instead of
                # swallowing every directive and brace after it.
                state = "code"
            else:
                output[index] = " "
        index += 1
    return "".join(output)


def names_platform(expression: str) -> bool:
    """Whether a controlling expression names a platform macro.

    Token-level, as in the feature-test macro guard: #elif, a bare
    #if G_OS_WIN32, defined without parentheses and compound expressions all
    count.
    """
    return any(token in PLATFORM_MACROS
               for token in IDENTIFIER_RE.findall(expression))


def function_name(header: str) -> str | None:
    """Name of the function a brace context opens, or None otherwise.

    ``header`` is the code since the previous ``;``, ``{`` or ``}``.  The
    last call-shaped name at parenthesis depth zero wins, so a storage
    class, a calling-convention macro or a ``G_GNUC_*`` attribute before the
    name does not hide it.  A header ending in ``=`` opens an initializer,
    and one with no call-shaped name opens a struct, namespace or block.
    """
    depth = 0
    best = None
    for match in CALL_SHAPED_RE.finditer(header):
        token = match.group(0)
        if token == ")":
            depth -= 1
            continue
        if token == "(":
            depth += 1
            continue
        if depth == 0:
            name = token.rstrip("( \t\n").split("::")[-1]
            if (name not in CONTROL and name not in ATTRIBUTES
                    and not name.startswith("G_GNUC_")):
                best = name
        depth += 1
    if best is None or header.rstrip().endswith("="):
        return None
    return best


def enclosing_function(contexts: list[str | None]) -> str | None:
    """The outermost function-shaped brace context, or None at file scope.

    A namespace, ``extern "C"`` block or struct body contributes None, so a
    member or lambda body is attributed to the free function around it.
    """
    return next((name for name in contexts if name is not None), None)


@dataclass
class Arm:
    line: int
    keyword: str
    expression: str
    platform: bool
    inherited: bool
    function: str | None
    depth: int
    text: list[str] = field(default_factory=list)


@dataclass
class Chain:
    arm: Arm
    platform: bool
    opener: Arm
    contexts_at_open: list[str | None]
    contexts_at_first_end: list[str | None] | None = None


@dataclass
class ScanStats:
    platform_arms_in_tests: int = 0
    test_functions: set[tuple[str, str]] = field(default_factory=set)


def describe(arm: Arm, relative_path: str, chain: Chain) -> str:
    expression = re.sub(r"\s+", " ", arm.expression).strip()
    where = f"#{arm.keyword} {expression}".rstrip()
    if arm.inherited:
        opener = re.sub(r"\s+", " ", chain.opener.expression).strip()
        where += (f" (of #{chain.opener.keyword} {opener} at "
                  f"{relative_path}:{chain.opener.line})")
    return where


def finish_arm(chain: Chain, depth_now: int, relative_path: str,
               findings: list[str], stats: ScanStats) -> None:
    arm = chain.arm
    if not arm.platform:
        return
    function = arm.function
    if function is None or not function.startswith("test_"):
        return
    stats.platform_arms_in_tests += 1
    compact = re.sub(r"\s+", "", CAST_RE.sub("", "\n".join(arm.text)))
    if depth_now == arm.depth and OFFENSE_RE.fullmatch(compact):
        findings.append(
            f"{relative_path}:{arm.line}: "
            f"{describe(arm, relative_path, chain)}"
            f" in {function} returns without g_test_skip or an assertion in"
            f" that arm, so this platform reports PASS with the rest of the"
            f" body unrun; report g_test_skip (\"<platform-specific reason>\")"
            f" before the return, or run the platform's own assertions")


def scan_source(relative_path: str, source: str,
                stats: ScanStats) -> list[str]:
    """Findings for one translation unit, as operator-facing lines."""
    findings: list[str] = []
    chains: list[Chain] = []
    contexts: list[str | None] = []
    header = ""
    for index, line in enumerate(c_code_only(source).split("\n"), start=1):
        directive = DIRECTIVE_RE.match(line)
        if directive is not None:
            keyword, expression = directive.group(1), directive.group(2)
            if keyword in OPENERS:
                platform = names_platform(expression)
                arm = Arm(index, keyword, expression, platform, False,
                          enclosing_function(contexts), len(contexts))
                chains.append(Chain(arm, platform, arm, list(contexts)))
            elif keyword in MIDDLES or keyword == "endif":
                if not chains:
                    continue
                chain = chains[-1]
                finish_arm(chain, len(contexts), relative_path, findings,
                           stats)
                if chain.contexts_at_first_end is None:
                    chain.contexts_at_first_end = list(contexts)
                if keyword == "endif":
                    contexts[:] = chain.contexts_at_first_end
                    chains.pop()
                    continue
                own = keyword != "else" and names_platform(expression)
                platform = own or chain.platform
                chain.platform = chain.platform or own
                # Sibling arms restart from the contexts the chain opened in,
                # so one function's braces are not counted once per arm.
                contexts[:] = chain.contexts_at_open
                chain.arm = Arm(index, keyword, expression, platform,
                                platform and not own,
                                enclosing_function(contexts), len(contexts))
            # Any other directive, a #define body included, is not code.
            continue
        # Every open arm owns the line: an outer arm is judged on all it
        # contains, nested arms included.
        for chain in chains:
            chain.arm.text.append(line)
        for character in line:
            if character == "{":
                name = function_name(header)
                if name is not None and name.startswith("test_"):
                    stats.test_functions.add((relative_path, name))
                contexts.append(name)
                header = ""
            elif character == "}":
                if contexts:
                    contexts.pop()
                header = ""
            elif character == ";":
                header = ""
            else:
                header += character
        header += "\n"
    return findings


def load_sources(root: Path) -> dict[str, str]:
    """Every C and C++ source below tests/.

    The rule is about ``test_`` functions, so only tests/ is scanned.  git is
    deliberately not consulted, so the gate still runs from an exported
    tarball.  A directory or source that cannot be read, and a source path
    that is a dangling symlink, are failures, not passes.  A symlinked
    directory is not followed, as with the other source-scan guards.
    """
    directory = root / SCAN_DIR

    def unreadable(error: OSError) -> None:
        raise ContractError("E_UNREADABLE", str(error)) from error

    sources: dict[str, str] = {}
    try:
        require(directory.is_dir(), "E_UNREADABLE",
                f"{directory} is not a directory")
        for parent, children, names in os.walk(directory, onerror=unreadable):
            children.sort()
            for name in sorted(names):
                path = Path(parent) / name
                if path.suffix not in SOURCE_SUFFIXES:
                    continue
                if path.is_symlink() and not path.exists():
                    raise ContractError("E_UNREADABLE",
                                        f"{path} is a dangling symlink")
                if not path.is_file():
                    continue
                relative = path.relative_to(root).as_posix()
                sources[relative] = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ContractError("E_UNREADABLE", str(error)) from error
    return dict(sorted(sources.items()))


def check_contract(sources: dict[str, str]) -> None:
    stats = ScanStats()
    findings: list[str] = []
    for relative_path, source in sorted(sources.items()):
        findings.extend(scan_source(relative_path, source, stats))
    if findings:
        raise ContractError("E_PLATFORM_BARE_RETURN",
                            "\n" + "\n".join(findings), findings)
    require(bool(stats.test_functions), "E_NO_TEST_FUNCTIONS",
            f"no test_ function was found under {SCAN_DIR}/")
    require(stats.platform_arms_in_tests > 0, "E_NO_PLATFORM_BLOCKS",
            "no platform-conditioned block inside a test_ function was "
            "visited, so the guard checked nothing")


def self_test() -> None:
    def planted(body: str, name: str = "test_planted") -> str:
        return f"static void\n{name} (gconstpointer data)\n{{\n{body}}}\n"

    def expect_failure(sources: dict[str, str], code: str,
                       needles: tuple[str, ...] = ()) -> None:
        try:
            check_contract(sources)
        except ContractError as error:
            if error.code != code:
                raise AssertionError(
                    f"expected {code}, got {error.code}") from error
            if needles:
                if len(error.findings) != 1:
                    raise AssertionError(
                        f"expected one finding, got {error.findings}")
                for needle in needles:
                    if needle not in error.findings[0]:
                        raise AssertionError(
                            f"expected {needle!r} in {error.findings[0]!r}")
            return
        raise AssertionError(f"expected {code}, contract accepted the source")

    def expect_load_failure(root: Path, what: str) -> None:
        try:
            load_sources(root)
        except ContractError as error:
            if error.code != "E_UNREADABLE":
                raise AssertionError(
                    f"expected E_UNREADABLE for {what}, got {error.code}"
                ) from error
            return
        raise AssertionError(f"{what} was accepted")

    # Positive fixtures: each is one offense, pinned by directive line,
    # keyword and function so a scanner that flagged a sibling arm fails.
    # Pairs rather than a dict, since several fixtures share a needle.
    positives = (
        # bare return under #ifdef __APPLE__
        ("tests/planted.c:4: #ifdef __APPLE__ in",
         planted("#ifdef __APPLE__\n  return;\n#endif\n"
                 "  g_assert_true (TRUE);\n")),
        # under #ifdef G_OS_WIN32, with an #else arm that runs assertions
        ("tests/planted.c:4: #ifdef G_OS_WIN32 in",
         planted("#ifdef G_OS_WIN32\n  return;\n#else\n"
                 "  g_assert_true (TRUE);\n#endif\n")),
        # under #ifndef __linux__
        ("tests/planted.c:4: #ifndef __linux__ in",
         planted("#ifndef __linux__\n  return;\n#endif\n"
                 "  g_assert_true (TRUE);\n")),
        # a comment and an unused-parameter cast do not make it a body
        ("tests/planted.c:4: #ifdef __APPLE__ in",
         planted("#ifdef __APPLE__\n  /* not on macOS */\n  (void) data;\n"
                 "  return;\n#endif\n  g_assert_true (TRUE);\n")),
        # compound condition
        ("tests/planted.c:4: #if !defined(__linux__) && !defined(__APPLE__)"
         " in",
         planted("#if !defined(__linux__) && !defined(__APPLE__)\n"
                 "  return;\n#endif\n  g_assert_true (TRUE);\n")),
        # #elif arm naming a platform macro
        ("tests/planted.c:6: #elif defined(G_OS_WIN32) in",
         planted("#if defined(__linux__)\n  g_assert_true (TRUE);\n"
                 "#elif defined(G_OS_WIN32)\n  return;\n#endif\n")),
        # the swapped form: #else inherits the chain's platform condition
        ("tests/planted.c:6: #else (of #ifndef __APPLE__ at tests/planted.c:4)"
         " in",
         planted("#ifndef __APPLE__\n  g_assert_true (TRUE);\n#else\n"
                 "  return;\n#endif\n")),
        # brace on the definition line
        ("tests/planted.c:2: #ifdef _WIN32 in",
         "static void test_planted (void) {\n#ifdef _WIN32\n  return;\n"
         "#endif\n}\n"),
        # a spliced directive keeps its physical line
        ("tests/planted.c:4: #if defined(__APPLE__) || defined(G_OS_WIN32) in",
         planted("#if defined(__APPLE__) \\\n    || defined(G_OS_WIN32)\n"
                 "  return;\n#endif\n")),
        # a C++ test inside an anonymous namespace (the suffix is not
        # consulted; the namespace brace is the point)
        ("tests/planted.c:5: #ifdef G_OS_WIN32 in",
         "namespace {\nvoid\ntest_planted ()\n{\n#ifdef G_OS_WIN32\n"
         "  return;\n#endif\n}\n}\n"),
        # the outer arm's only statement hides behind a nested condition
        ("tests/planted.c:4: #ifdef __APPLE__ in",
         planted("#ifdef __APPLE__\n#ifdef __aarch64__\n  return;\n#endif\n"
                 "#endif\n  g_assert_true (TRUE);\n")),
        # both nested arms return, so the outer arm is return-only
        ("tests/planted.c:4: #ifdef G_OS_WIN32 in",
         planted("#ifdef G_OS_WIN32\n#ifdef HAVE_X\n  return;\n#else\n"
                 "  return;\n#endif\n#endif\n  g_assert_true (TRUE);\n")),
        # a stray quote in skipped prose must not blind the rest of the unit
        ("tests/planted.c:7: #ifdef __APPLE__ in",
         planted("#if 0\n  don't\n#endif\n#ifdef __APPLE__\n  return;\n"
                 "#endif\n  g_assert_true (TRUE);\n")),
    )
    for needle, source in positives:
        expect_failure({"tests/planted.c": source}, "E_PLATFORM_BARE_RETURN",
                       (needle, "test_planted"))

    # Negative fixtures, each with the number of platform arms the scanner
    # must visit inside a test_ function, so an accepted shape is proven to
    # have been looked at rather than skipped by a broken attribution.
    negatives = (
        # skip then return
        (planted("#ifdef __APPLE__\n  g_test_skip (\"not on macOS\");\n"
                 "  return;\n#endif\n"), 1),
        # assert then return
        (planted("#ifdef __APPLE__\n  g_assert_cmpint (1, ==, 1);\n  return;\n"
                 "#endif\n"), 1),
        # helper call then return: the shape is pinned, not the helper
        (planted("#ifndef __linux__\n  test_planted_fail_closed ();\n"
                 "  return;\n#endif\n"), 1),
        # a bare return in a helper that is not a test
        (planted("#ifdef G_OS_WIN32\n  return;\n#endif\n",
                 name="remove_tree_no_follow"), 0),
        # a condition that names no platform macro
        (planted("#if HAVE_THING\n  return;\n#endif\n"), 0),
        # a feature-only condition is out of scope
        (planted("#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE\n  return;\n#endif\n"),
         0),
        # a platform arm wrapping a whole definition is at file scope
        ("#ifdef __APPLE__\nstatic void\ntest_planted (void)\n{\n  return;\n"
         "}\n#endif\n", 0),
        # an early return inside a conditional is a statement
        (planted("#ifdef __APPLE__\n  if (data == NULL) {\n    return;\n  }\n"
                 "#endif\n"), 1),
        # a value return in a helper
        ("static gboolean\nhelper (void)\n{\n#ifdef G_OS_WIN32\n"
         "  return FALSE;\n#endif\n  return TRUE;\n}\n", 0),
        # the shape inside a comment is not code
        (planted("  /* #ifdef __APPLE__ return; */\n"
                 "  g_assert_true (TRUE);\n"), 0),
        # a brace inside a literal does not shift the depth
        (planted("#ifdef __APPLE__\n  g_test_skip (\"{ not a brace\");\n"
                 "  return;\n#endif\n"), 1),
        # a nested non-platform return after an assertion in the outer arm
        (planted("#ifdef __APPLE__\n  g_assert_true (TRUE);\n#ifdef HAVE_X\n"
                 "  return;\n#endif\n#endif\n"), 1),
    )
    anchor = {"tests/anchor.c": planted(
        "#ifdef G_OS_WIN32\n  g_test_skip (\"x\");\n  return;\n#endif\n",
        name="test_anchor")}
    for source, visited in negatives:
        stats = ScanStats()
        findings = scan_source("tests/planted.c", source, stats)
        if findings:
            raise AssertionError(f"accepted shape was flagged: {findings}")
        if stats.platform_arms_in_tests != visited:
            raise AssertionError(
                f"expected {visited} visited platform arm(s), scanner saw "
                f"{stats.platform_arms_in_tests} in {source!r}")
        # The anchor keeps the fail-closed threshold out of the way.
        check_contract({**anchor, "tests/planted.c": source})

    # Fail closed.
    expect_failure({"tests/x.c": "static int\nhelper (void)\n{\n  return 0;\n"
                                 "}\n"}, "E_NO_TEST_FUNCTIONS")
    expect_failure({"tests/x.c": planted("  g_assert_true (TRUE);\n")},
                   "E_NO_PLATFORM_BLOCKS")
    expect_failure({"tests/x.c": "#ifdef G_OS_WIN32\nstatic int\n"
                                 "helper (void)\n{\n  return 0;\n}\n"
                                 "#endif\n"
                                 + planted("  g_assert_true (TRUE);\n")},
                   "E_NO_PLATFORM_BLOCKS")
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        expect_load_failure(root, "a root without tests/")
        tests = root / SCAN_DIR
        tests.mkdir()
        bad = tests / "bad.c"
        bad.write_bytes(b"\xff\xfe")
        expect_load_failure(root, "an undecodable source")
        bad.unlink()
        # A broken link to something other than a source is not this
        # guard's business; a broken link to a source is.
        try:
            (tests / "notes.txt").symlink_to(root / "absent.txt")
            (tests / "dangling.c").symlink_to(root / "absent.c")
        except OSError:
            pass  # a host that forbids symlinks exercises nothing here
        else:
            expect_load_failure(root, "a dangling symlink")
            (tests / "dangling.c").unlink()
            load_sources(root)
            (tests / "notes.txt").unlink()
        # An unreadable subdirectory must not be silently walked past.
        hidden = tests / "hidden"
        hidden.mkdir()
        (hidden / "x.c").write_bytes(b"int x;\n")
        hidden.chmod(0)
        try:
            if not os.access(hidden, os.R_OK):
                expect_load_failure(root, "an unreadable directory")
        finally:
            hidden.chmod(0o700)


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        print("platform skip guard self-test: OK")
        return 0
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} ROOT|--self-test",
              file=sys.stderr)
        return 2
    try:
        check_contract(load_sources(Path(sys.argv[1]).resolve()))
    except ContractError as error:
        print(error, file=sys.stderr)
        return 1
    print("platform skip guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
r"""Hold the structure guard's definition lexer to the pattern it replaced.

`function_span` used to find every definition the guard pins with a single
regex whose prefix opened on a variable-length class.  `re` had no literal to
scan for, so it retried the lazy prefix at every offset of a 623KB `http.c`:
0.45s per lookup, 38 lookups per run, and a cost that grew with the file until
the guard and its self-test both ran past meson's 30s default on the Windows
job (#1080).  The replacement anchors on the function name and checks the same
two subpatterns over a bounded window.

Nothing else in the suite would notice if the two stopped agreeing.  The
guard's own self-test asserts verdicts, and a span that is off by a few
characters still produces the same verdict on that corpus; the guard's run
against the real `http.c` only notices a disagreement that happens to fall on
one of the 28 names it pins.  So this file keeps the old pattern as an oracle.

`name` is a C identifier in every call the guard makes, and the two
formulations are only equivalent for one: both rely on the prefix's trailing
`\s+` to reject a name that is a suffix of a longer identifier, which a name
containing whitespace or punctuation would not get.

When `function_span` has to change shape for a reason of its own -- a
declaration form it cannot parse today -- replace this test.  Editing the
oracle until it agrees turns the comparison into a tautology, which is the one
failure mode it cannot report.

The fixed corpus below documents the shapes that separate the two
formulations.  It is not what proves them equal: the case that actually
separated them -- an unbalanced, semicolon-free parameter run, where the old
pattern's `[^;]*?` swallows a later definition and `finditer`'s non-overlap
then hides it -- was found by fuzzing, and no hand-written corpus here had it.
Every mutation of `function_span` that changes behaviour now dies on a corpus
case, because the shapes the sweep found were folded back into it; the sweep
stays as the tripwire for the next shape nobody thought of.
"""

from __future__ import annotations

from pathlib import Path
import importlib.util
import random
import re
import sys

GUARD = Path(__file__).resolve().parent.parent / "tools" \
    / "check-daemon-bearer-resolver-structure.py"


def load_guard():
  spec = importlib.util.spec_from_file_location("bearer_structure_guard", GUARD)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def oracle(source: str, name: str, static_only: bool):
  """`function_span` as it was written, kept only to disagree with.

  Both outcomes come back as a tuple so that a disagreement about *whether* a
  definition was found reads as a difference rather than as an exception.
  """
  prefix = (r"static\s+wyrelog_error_t\s+" if static_only
            else r"(?:static\s+)?\w[\w\s\*]*?\s+")
  matches = list(re.finditer(
      prefix + re.escape(name) + r"\s*\([^;]*?\)\s*\{", source, re.S))
  if len(matches) != 1:
    return ("count", len(matches))
  start = matches[0].start()
  brace = source.find("{", matches[0].start(), matches[0].end())
  depth = 0
  for pos in range(brace, len(source)):
    if source[pos] == "{":
      depth += 1
    elif source[pos] == "}":
      depth -= 1
      if depth == 0:
        return ("span", start, pos + 1)
  return ("unterminated",)


# The guard reports both failures through ValueError, so the count has to be
# read back out of the message.  Parsed rather than split blind: a changed
# message should fail as a disagreement this file names, not as a traceback
# from int() that reads like a broken test.
COUNT = re.compile(r"^expected exactly one definition of \S+, found (\d+)$")


def observed(guard, source: str, name: str, static_only: bool):
  try:
    start, end = guard.function_span(source, name, static_only)
  except ValueError as exc:
    text = str(exc)
    if text.startswith("unterminated"):
      return ("unterminated",)
    found = COUNT.match(text)
    if found is None:
      return ("unreadable", text)
    return ("count", int(found.group(1)))
  return ("span", start, end)


# Each entry is a shape that could tell a name-anchored scan apart from a
# whole-file one.  Comments and string literals are absent on purpose: the
# guard blanks them in `masked` before either formulation sees the text.
CORPUS = (
    ("pointer return across lines",
     "static gboolean *\nfoo (SoupServerMessage *msg,\n     const char *path)\n{\n  helper ();\n}\n"),
    ("call before the definition",
     "static void caller (void) { foo (NULL); }\nstatic int\nfoo (void)\n{\n}\n"),
    ("forward declaration then definition",
     "int foo (void);\nstatic int\nfoo (void)\n{\n}\n"),
    ("name is a proper suffix of another definition",
     "static void\nxfoo (void)\n{\n}\nstatic void\nfoo (void)\n{\n}\n"),
    ("name is a proper prefix of another definition",
     "static void\nfoo_extra (void)\n{\n}\nstatic void\nfoo (void)\n{\n}\n"),
    ("two definitions of the same name",
     "void\nfoo (void)\n{\n}\nstatic void\nfoo (void)\n{\n}\n"),
    ("no definition at all",
     "static void bar (void) { }\n"),
    ("declaration with no body",
     "static int foo (void);\n"),
    ("brace inside the parameter text",
     "a foo({x} ) {\n  body;\n}\n"),
    # The case the corpus did not have until the fuzzer produced it: the old
    # pattern matches once from the first `foo`, its `[^;]*?` runs through the
    # second, and `finditer` never restarts inside that match.  A scan that
    # visits every occurrence of the name sees two definitions instead.
    ("unbalanced parameter run swallowing a later definition",
     "a foo((\na foo() {\n}\n"),
    ("unbalanced parameter run, C-shaped",
     "int foo(int (*cb)(void\nstatic int foo(void) {\n  return 0;\n}\n"),
    ("static-only prefix, spaced",
     "static  wyrelog_error_t   foo(void){ }\n"),
    ("unterminated body",
     "static void\nfoo (void)\n{\n  helper ();\n"),
)

# A compact alphabet: enough to build every shape above by accident, small
# enough that short strings collide into interesting ones often.
TOKENS = ("foo", "bar", "(", ")", "{", "}", ";", "*", ",", "=", "&",
          "int", "static", "wyrelog_error_t", " ", "  ", "\t", "\n")
FUZZ_SEED = 1080
# A standing tripwire, not a search: the one shape this sweep found that the
# corpus lacked is now a corpus case, and every mutation of function_span that
# changes behaviour dies on a corpus case rather than here.  Sized to stay
# cheap on the Windows job, where this file has meson's 30s default and no
# multiplier is permitted.
FUZZ_CASES = 10000


def compare(guard, label, source, name, static_only, failures):
  want = oracle(source, name, static_only)
  got = observed(guard, source, name, static_only)
  if want == got:
    return
  failures.append(label)
  print(f"{label}: static_only={static_only}\n"
        f"  source   {source!r}\n"
        f"  pattern  {want}\n"
        f"  function_span {got}", file=sys.stderr)


def main() -> int:
  guard = load_guard()
  failures: list[str] = []

  for label, source in CORPUS:
    for static_only in (False, True):
      compare(guard, f"corpus/{label}", guard.masked(source), "foo",
              static_only, failures)

  rnd = random.Random(FUZZ_SEED)
  for case in range(FUZZ_CASES):
    source = "".join(rnd.choice(TOKENS)
                     for _ in range(rnd.randint(3, 26)))
    for static_only in (False, True):
      compare(guard, f"fuzz/{FUZZ_SEED}/{case}", guard.masked(source), "foo",
              static_only, failures)
    if len(failures) > 20:
      break

  if failures:
    print(f"{len(failures)} lookup(s) disagree with the pattern function_span "
          f"replaced; the seed above reproduces them", file=sys.stderr)
    return 1
  print(f"bearer-resolver span equivalence: OK ({len(CORPUS)} documented "
        f"shapes and {FUZZ_CASES} generated sources, both static_only values)")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

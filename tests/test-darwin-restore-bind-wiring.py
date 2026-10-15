#!/usr/bin/env python3
"""Pin the macOS graph bind to the evidence form of the provisioned capture.

On macOS the old provisioned main is a one-link file, so the transition
model admits it with or without a witness (#1303 U3).  The proof that the
main is the provisioned object therefore lives only in the provider call the
bind makes, which is
wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence.
Nothing at runtime distinguishes a bind that skipped that proof, because the
journal-pinned identity alone also admits the main.  This guard reads the
source instead.

Rules, all on wyrelog/fact/offline-restore-commit-authority-private.c:

- graph_bind_prove_effect has exactly one ``#ifdef __APPLE__`` arm, and that
  arm calls the ``_with_evidence`` capture exactly once.
- No other capture call (plain capture, name-only capture_provisioned,
  observe) appears in that arm.
- The matching ``#else`` arm calls the name-only capture_provisioned, so the
  Linux body is the one this guard does not judge.

Self-test: mutations that swap the Darwin call for the name-only one, drop
the Apple arm, or add a plain capture to it must each fail.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SOURCE = "wyrelog/fact/offline-restore-commit-authority-private.c"
FUNCTION = "graph_bind_prove_effect"
EVIDENCE_CALL = (
    "wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence"
)
PLAIN_CALLS = (
    "wyl_fact_artifact_transition_posix_capture_provisioned",
    "wyl_fact_artifact_transition_posix_capture",
    "wyl_fact_artifact_transition_posix_observe",
)


class ContractError(Exception):
    """A rule of the guard does not hold."""


def strip_comments(source: str) -> str:
    """Blank C comments, keeping newlines so line structure survives."""
    source = re.sub(
        r"/\*.*?\*/",
        lambda m: re.sub(r"[^\n]", " ", m.group(0)),
        source,
        flags=re.DOTALL,
    )
    return re.sub(r"//[^\n]*", "", source)


def function_body(source: str, name: str) -> str:
    """The brace-delimited body of the definition of ``name``."""
    match = re.search(
        r"^[A-Za-z_][\w \t*]*\n" + re.escape(name) + r"\s*\(", source, re.M
    )
    if match is None:
        raise ContractError(f"E_NO_FUNCTION: {name} is not defined")
    start = source.index("{", match.end())
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise ContractError(f"E_NO_FUNCTION: {name} has no closing brace")


def apple_arms(body: str) -> list[tuple[str, str]]:
    """Every (apple_arm, else_arm) pair of an ``#ifdef __APPLE__`` block."""
    arms: list[tuple[str, str]] = []
    lines = body.splitlines()
    index = 0
    while index < len(lines):
        if re.match(r"^\s*#\s*ifdef\s+__APPLE__\s*$", lines[index]):
            apple: list[str] = []
            other: list[str] = []
            current = apple
            depth = 0
            index += 1
            while index < len(lines):
                line = lines[index]
                if re.match(r"^\s*#\s*if", line):
                    depth += 1
                elif re.match(r"^\s*#\s*endif", line):
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0 and re.match(r"^\s*#\s*else\s*$", line):
                    current = other
                    index += 1
                    continue
                elif depth == 0 and re.match(r"^\s*#\s*elif", line):
                    raise ContractError(
                        "E_APPLE_ELIF: an #elif chain is not judged"
                    )
                current.append(line)
                index += 1
            else:
                raise ContractError("E_APPLE_UNTERMINATED: missing #endif")
            arms.append(("\n".join(apple), "\n".join(other)))
        index += 1
    return arms


def count_calls(text: str, name: str) -> int:
    """Calls of exactly ``name``, not of a longer identifier."""
    return len(re.findall(r"(?<![\w])" + re.escape(name) + r"\s*\(", text))


def check_source(source: str) -> None:
    body = strip_comments(function_body(strip_comments(source), FUNCTION))
    arms = apple_arms(body)
    if len(arms) != 1:
        raise ContractError(
            f"E_APPLE_ARMS: {FUNCTION} has {len(arms)} #ifdef __APPLE__ arms,"
            " expected 1"
        )
    apple, other = arms[0]
    if count_calls(apple, EVIDENCE_CALL) != 1:
        raise ContractError(
            f"E_NO_EVIDENCE_CAPTURE: the Darwin arm of {FUNCTION} must call"
            f" {EVIDENCE_CALL} exactly once"
        )
    for plain in PLAIN_CALLS:
        if count_calls(apple, plain) != 0:
            raise ContractError(
                f"E_PLAIN_CAPTURE: the Darwin arm of {FUNCTION} calls {plain},"
                " which does not prove the provisioned main on macOS"
            )
    if count_calls(other, PLAIN_CALLS[0]) != 1:
        raise ContractError(
            f"E_LINUX_ARM: the #else arm of {FUNCTION} must keep the"
            f" name-only {PLAIN_CALLS[0]} call"
        )


def check_tree(root: Path) -> None:
    path = root / SOURCE
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ContractError(f"E_UNREADABLE: {SOURCE}: {error}") from error
    check_source(source)


POSITIVE = """\
static wyrelog_error_t
graph_bind_prove_effect (GBytes *canonical_journal,
    const gchar *old_uuid, gpointer user_data)
{
  /* comment with #ifdef __APPLE__ inside must be ignored */
  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef __APPLE__
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture_provisioned_with_evidence
          (provider, old_uuid, evidence, &request, slot, &lifecycle, &s, &o);
#else
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture_provisioned
          (provider, old_uuid, &request, slot, &lifecycle, &s, &o);
#endif
  return rc;
}
"""


def self_test() -> None:
    check_source(POSITIVE)
    mutants = {
        "swap to name-only": POSITIVE.replace(
            "capture_provisioned_with_evidence\n          (provider, old_uuid,"
            " evidence,",
            "capture_provisioned\n          (provider, old_uuid,",
        ),
        "drop the Apple arm": re.sub(
            r"#ifdef __APPLE__.*?#else\n", "", POSITIVE, flags=re.DOTALL
        ).replace("#endif\n", ""),
        "plain capture beside the evidence call": POSITIVE.replace(
            "#else",
            "  rc = wyl_fact_artifact_transition_posix_capture (provider,"
            " &lifecycle, &s, &o);\n#else",
        ),
        "evidence call twice": POSITIVE.replace(
            "#else",
            "  rc = wyl_fact_artifact_transition_posix_capture_provisioned"
            "_with_evidence (provider, old_uuid, evidence, &request, slot,"
            " &lifecycle, &s, &o);\n#else",
        ),
        "Linux arm loses its call": POSITIVE.replace(
            "    rc = wyl_fact_artifact_transition_posix_capture_provisioned\n"
            "          (provider, old_uuid, &request, slot, &lifecycle, &s,"
            " &o);\n",
            "    rc = WYRELOG_E_OK;\n",
        ),
        "function missing": POSITIVE.replace(
            "graph_bind_prove_effect", "graph_bind_prove_other"
        ),
    }
    for label, mutant in mutants.items():
        if mutant == POSITIVE:
            raise ContractError(f"self-test mutant did not apply: {label}")
        try:
            check_source(mutant)
        except ContractError:
            continue
        raise ContractError(f"self-test mutant survived: {label}")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--self-test":
        try:
            self_test()
        except ContractError as error:
            print(f"darwin-restore-bind-wiring self-test: {error}",
                  file=sys.stderr)
            return 1
        print("darwin-restore-bind-wiring self-test: OK")
        return 0
    if len(argv) != 2:
        print(f"usage: {argv[0]} [--self-test] SOURCE_ROOT", file=sys.stderr)
        return 2
    try:
        check_tree(Path(argv[1]))
    except ContractError as error:
        print(f"darwin-restore-bind-wiring: {error}", file=sys.stderr)
        return 1
    print("darwin-restore-bind-wiring: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

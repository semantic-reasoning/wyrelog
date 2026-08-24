#!/usr/bin/env python3
"""Structural guard for the Windows temp-child wrapper ownership boundary.

This checker proves only compilation gating, output initialization/publication,
and cleanup call ordering.  It does not prove HANDLE closure, runtime
reachability, error propagation, rollback, or retirement health; the native
Windows tests and Application Verifier are authoritative for those properties.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path


def function_body(text: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", text, re.S)
    if match is None:
        raise AssertionError(f"missing function body: {name}")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"unterminated function body: {name}")


def strip_test_seams(text: str) -> str:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    depth = 0
    seam_depth: int | None = None
    for line in lines:
        directive = re.match(r"\s*#\s*(if|ifdef|ifndef|endif)\b(.*)", line)
        if directive:
            kind, rest = directive.groups()
            if kind in {"if", "ifdef", "ifndef"}:
                depth += 1
                if seam_depth is None and "WYL_TEST_HANDLE_SEAMS" in rest:
                    seam_depth = depth
                if seam_depth is None:
                    output.append(line)
                continue
            if kind == "endif":
                if seam_depth is None:
                    output.append(line)
                elif depth == seam_depth:
                    seam_depth = None
                depth -= 1
                continue
        if seam_depth is None:
            output.append(line)
    return "".join(output)


def require_in_order(text: str, needles: list[str], message: str) -> None:
    position = -1
    for needle in needles:
        next_position = text.find(needle, position + 1)
        if next_position < 0:
            raise AssertionError(f"{message}: missing {needle}")
        position = next_position


def check(root: Path) -> None:
    namespace_h = (root / "wyrelog/fact/graph-artifact-windows-namespace-private.h").read_text(encoding="utf-8")
    namespace_c = (root / "wyrelog/fact/graph-artifact-windows-namespace-private.c").read_text(encoding="utf-8")
    session_c = (root / "wyrelog/fact/artifact-io-session-windows-private.c").read_text(encoding="utf-8")
    runtime = (root / "tests/test-fact-artifact-namespace-windows.c").read_text(encoding="utf-8")
    meson = (root / "tests/meson.build").read_text(encoding="utf-8")

    seam_names = [
        "WYL_FACT_ARTIFACT_WIN_TEMP_CHILD_TEST_SEAM_AFTER_CHILD_CREATE",
        "WYL_FACT_ARTIFACT_WIN_TEMP_CHILD_TEST_SEAM_AFTER_BINDING_ACQUIRE",
        "WYL_FACT_ARTIFACT_WIN_TEMP_CHILD_TEST_SEAM_AFTER_IO_SESSION_ACQUIRE",
        "WYL_FACT_ARTIFACT_WIN_TEMP_CHILD_TEST_SEAM_AFTER_WRAPPER_POPULATE",
        "WYL_FACT_ARTIFACT_WIN_TEMP_CHILD_TEST_SEAM_REPORT_FINISH_ERROR",
    ]
    for seam in seam_names:
        if seam not in namespace_h or seam not in namespace_c + session_c:
            raise AssertionError(f"missing archive-only seam: {seam}")
    for shipped in (strip_test_seams(namespace_h), strip_test_seams(namespace_c),
                    strip_test_seams(session_c)):
        if "TEMP_CHILD_TEST_SEAM" in shipped:
            raise AssertionError("temp-child seams escaped WYL_TEST_HANDLE_SEAMS")

    helper = function_body(
        namespace_c, "wyl_fact_artifact_win_temp_root_create_child_with_orphan_evidence"
    )
    for output in ("*out_child = NULL", "*out_binding = NULL", "*out_evidence = NULL"):
        if output not in helper:
            raise AssertionError(f"native helper does not initialize {output}")
    require_in_order(
        helper,
        ["*out_child = child", "*out_binding = binding"],
        "native child and binding publication",
    )
    discard = function_body(
        namespace_c, "wyl_fact_artifact_win_temp_child_discard_unpublished"
    )
    if "*out_evidence = evidence" not in discard:
        raise AssertionError("native helper lacks uncertain rollback evidence transfer")

    wrapper = function_body(session_c, "wyl_fact_artifact_io_session_create_temp_child")
    for output in ("*out_child = NULL", "*out_session = NULL", "*out_evidence = NULL"):
        if output not in wrapper:
            raise AssertionError(f"wrapper does not initialize {output}")
    for token in ("session->temp_child_binding = binding", "*out_child = child",
                  "*out_session = session"):
        if token not in wrapper:
            raise AssertionError(f"wrapper ownership/publication missing: {token}")
    require_in_order(
        function_body(session_c, "temp_child_session_release"),
        ["wyl_fact_artifact_win_io_session_finish", "temp_child_binding_free"],
        "finish must consume the session before releasing its binding",
    )

    if "/fact/artifact-namespace/windows/temp-root/wrapper-ownership" not in runtime:
        raise AssertionError("missing native wrapper ownership runtime selector")
    if "'temp-root-wrapper-ownership'" not in meson:
        raise AssertionError("missing independent Meson wrapper ownership selector")


def self_test(root: Path) -> None:
    check(root)
    mutations = {
        "owner": ("wyrelog/fact/artifact-io-session-windows-private.c",
                  "session->temp_child_binding = binding", "session->sidecar_binding = binding"),
        "publication": ("wyrelog/fact/graph-artifact-windows-namespace-private.c",
                        "wyl_fact_artifact_win_temp_orphan_evidence_free (evidence);\n  *out_child = child",
                        "wyl_fact_artifact_win_temp_orphan_evidence_free (evidence);\n  /* child not published */"),
        "order": ("wyrelog/fact/artifact-io-session-windows-private.c",
            "wyl_fact_artifact_win_io_session_finish (win_session)",
            "wyl_fact_artifact_win_io_session_abort (win_session)",
        ),
        "gate": ("wyrelog/fact/graph-artifact-windows-namespace-private.h",
                 "#ifdef WYL_TEST_HANDLE_SEAMS", "#if 1 /* shipped seam */"),
        "registration": ("tests/meson.build",
            "'temp-root-wrapper-ownership'",
            "'temp-root-wrapper-ownership-removed'",
        ),
    }
    for label, (mutation_file, old, new) in mutations.items():
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory)
            mutated = False
            for relative in (
                "wyrelog/fact/graph-artifact-windows-namespace-private.h",
                "wyrelog/fact/graph-artifact-windows-namespace-private.c",
                "wyrelog/fact/artifact-io-session-windows-private.c",
                "tests/test-fact-artifact-namespace-windows.c",
                "tests/meson.build",
            ):
                target = copy / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                text = (root / relative).read_text(encoding="utf-8")
                if relative == mutation_file and old in text:
                    text = text.replace(old, new, 1)
                    mutated = True
                target.write_text(text, encoding="utf-8")
            if not mutated:
                raise AssertionError(f"self-test mutation anchor missing: {label}")
            try:
                check(copy)
            except AssertionError:
                continue
            raise AssertionError(f"self-test mutation survived: {label}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.self_test:
        self_test(root)
    else:
        check(root)
    print("windows temp-child ownership boundary: OK")


if __name__ == "__main__":
    main()

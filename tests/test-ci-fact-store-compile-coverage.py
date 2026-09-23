#!/usr/bin/env python3
"""Guard that the POSIX CI compiles the whole fact-store tree as strict C.

Issue #1210: a fact-store test called pwrite() without a feature-test macro
and CI stayed green.  The translation unit was compiled, but GCC 13 -- the
ubuntu-latest compiler -- only warns on an implicit function declaration, and
glibc exports pwrite, so the object linked.  Two things close that gap, and
this guard pins both:

  * meson.build promotes -Wimplicit-function-declaration to an error for the
    project's own C, on every compiler that accepts the flag;
  * build-posix compiles every target of a fact-store build on both runners,
    because some fact-store tests are built by no other POSIX job.

The step is pinned as exact text rather than by a list of properties: a
target list, a platform gate, continue-on-error or a masking "|| true" each
reopen the gap, and a property list names only the ones it thought of.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


WORKFLOWS = (".github/workflows/ci-pr.yml", ".github/workflows/ci-main.yml")
JOB = "build-posix"
STEP_NAME = "Build fact-store tree"
EXPECTED_STEP = """\
      - name: Build fact-store tree
        # Compiles every target, tests included, in the fact-store
        # configuration (issues #497 and #1210).  Keep it free of a target
        # list and a platform gate: some fact-store tests are compiled by no
        # other POSIX job.  tests/test-ci-fact-store-compile-coverage.py pins
        # this step.
        run: |
          meson setup build-fact -Denable_fact_store=enabled \\
            -Denable_audit=enabled -Dduckdb_source=prebuilt
          meson compile -C build-fact
"""
EXPECTED_RUNNERS = ("ubuntu-latest", "macos-latest")
LOG_PATH_LINE = "            build-fact/meson-logs/\n"
LOG_STEP_NAME = "Upload meson logs on failure"
MESON_FILES = ("meson.build", "wyrelog/meson.build", "tests/meson.build")
DEMOTING_FLAGS = (
    "-Wno-error=implicit-function-declaration",
    "-Wno-implicit-function-declaration",
)
WERROR_LINE = (
    "add_project_arguments(\n"
    "  cc.get_supported_arguments('-Werror=implicit-function-declaration'),\n"
    "  language : 'c')\n"
)


class ContractError(AssertionError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def fail(code: str, detail: str) -> None:
    raise ContractError(code, detail)


def extract_job(workflow: str, path: str) -> str:
    marker = f"  {JOB}:\n"
    start = workflow.find(marker)
    if start < 0 or workflow.find(marker, start + 1) >= 0:
        fail("E_JOB", f"{path}: job {JOB} must occur exactly once")
    body = workflow[start + len(marker):]
    next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", body)
    return marker + (body if next_job is None else body[:next_job.start()])


def extract_step(job: str, name: str, path: str, code: str) -> str:
    marker = f"      - name: {name}\n"
    start = job.find(marker)
    if start < 0 or job.find(marker, start + 1) >= 0:
        fail(code, f"{path}: {JOB} step {name!r} must occur exactly once")
    next_step = re.search(r"(?m)^      - ", job[start + len(marker):])
    end = len(job) if next_step is None else start + len(marker) + \
        next_step.start()
    # Blank separator lines before the next step are layout, not step text.
    return job[start:end].rstrip("\n") + "\n"


def check_workflow(workflow: str, path: str) -> None:
    job = extract_job(workflow, path)
    header = job[:job.find("    steps:\n")]
    if re.search(r"(?m)^    (if|continue-on-error):", header):
        fail("E_JOB_GATED", f"{path}: {JOB} must not carry a job-level if: "
             "or continue-on-error")
    runners = tuple(re.findall(r"(?m)^          - os: (\S+)\s*$", job))
    if runners != EXPECTED_RUNNERS:
        fail("E_MATRIX", f"{path}: {JOB} runners are {runners}, expected "
             f"{EXPECTED_RUNNERS}")
    step = extract_step(job, STEP_NAME, path, "E_STEP_MISSING")
    if step != EXPECTED_STEP:
        fail("E_STEP_DRIFT", f"{path}: step {STEP_NAME!r} differs from the "
             "pinned text; a target list, platform gate or masking key "
             "reopens #1210")
    logs = extract_step(job, LOG_STEP_NAME, path, "E_LOGS")
    if LOG_PATH_LINE not in logs:
        fail("E_LOGS", f"{path}: {LOG_STEP_NAME!r} does not upload "
             "build-fact/meson-logs/")


def check_meson(sources: dict[str, str]) -> None:
    meson_build = sources["meson.build"]
    if meson_build.count(WERROR_LINE) != 1:
        fail("E_WERROR", "meson.build must promote "
             "-Wimplicit-function-declaration to an error exactly once")
    # Unconditional: an enclosing if or foreach block could skip the call.
    depth = 0
    for line in meson_build[:meson_build.index(WERROR_LINE)].splitlines():
        stripped = line.strip()
        if re.match(r"(if|foreach)\b", stripped):
            depth += 1
        elif re.match(r"end(if|foreach)\b", stripped):
            depth -= 1
    if depth != 0:
        fail("E_WERROR", "meson.build must promote "
             "-Wimplicit-function-declaration outside any if/foreach block")
    for path in MESON_FILES:
        for flag in DEMOTING_FLAGS:
            if flag in sources[path]:
                fail("E_WERROR_DEMOTED", f"{path}: {flag} undoes the error")


def check_contract(sources: dict[str, str]) -> None:
    check_meson(sources)
    for path in WORKFLOWS:
        check_workflow(sources[path], path)


def load_sources(root: Path) -> dict[str, str]:
    return {
        path: (root / path).read_text(encoding="utf-8")
        for path in MESON_FILES + WORKFLOWS
    }


def self_test(root: Path) -> None:
    baseline = load_sources(root)
    check_contract(baseline)

    def mutate(path: str, old: str, new: str) -> dict[str, str]:
        sources = dict(baseline)
        if sources[path].count(old) != 1:
            raise AssertionError(f"self-test anchor not unique in {path}: "
                                 f"{old!r}")
        sources[path] = sources[path].replace(old, new)
        return sources

    def expect(sources: dict[str, str], code: str, label: str) -> None:
        try:
            check_contract(sources)
        except ContractError as error:
            if error.code != code:
                raise AssertionError(
                    f"{label}: expected {code}, got {error.code}") from error
            return
        raise AssertionError(f"{label}: expected {code}, contract accepted")

    compile_line = "          meson compile -C build-fact\n"
    step_head = f"      - name: {STEP_NAME}\n"
    for path in WORKFLOWS:
        expect(mutate(path, compile_line,
                      "          meson compile -C build-fact wyrelogd\n"),
               "E_STEP_DRIFT", f"{path}: target list")
        expect(mutate(path, compile_line,
                      "          meson compile -C build-fact \\\n"
                      "            test-fact-replay\n"),
               "E_STEP_DRIFT", f"{path}: continued target list")
        expect(mutate(path, compile_line,
                      "          meson compile -C build-fact || true\n"),
               "E_STEP_DRIFT", f"{path}: masked failure")
        expect(mutate(path, step_head,
                      step_head + "        if: runner.os == 'Linux'\n"),
               "E_STEP_DRIFT", f"{path}: platform gate")
        expect(mutate(path, step_head,
                      step_head + "        continue-on-error: true\n"),
               "E_STEP_DRIFT", f"{path}: continue-on-error")
        expect(mutate(path, "-Denable_fact_store=enabled \\\n"
                            "            -Denable_audit=enabled "
                            "-Dduckdb_source=prebuilt\n          meson "
                            "compile -C build-fact\n",
                      "-Denable_audit=enabled \\\n"
                      "            -Denable_audit=enabled "
                      "-Dduckdb_source=prebuilt\n          meson "
                      "compile -C build-fact\n"),
               "E_STEP_DRIFT", f"{path}: fact store not enabled")
        expect(mutate(path, step_head, "      - name: Build fact tree\n"),
               "E_STEP_MISSING", f"{path}: step renamed away")
        expect(mutate(path, "          - os: macos-latest\n",
                      "          - os: macos-14\n"),
               "E_MATRIX", f"{path}: macOS runner dropped")
        expect(mutate(path, LOG_PATH_LINE, ""),
               "E_LOGS", f"{path}: fact-store logs not uploaded")
        expect(mutate(path, f"  {JOB}:\n", f"  {JOB}:\n"
                      "    continue-on-error: true\n"),
               "E_JOB_GATED", f"{path}: job-level continue-on-error")
        expect(mutate(path, f"  {JOB}:\n", f"  {JOB}:\n"
                      "    if: github.event_name == 'push'\n"),
               "E_JOB_GATED", f"{path}: job-level if")
    expect(mutate("meson.build", WERROR_LINE,
                  "if false\n" + WERROR_LINE + "endif\n"),
           "E_WERROR", "meson.build: flag under a dead branch")
    expect(mutate("meson.build", "cc = meson.get_compiler('c')\n",
                  "cc = meson.get_compiler('c')\n"
                  "add_project_arguments("
                  "'-Wno-error=implicit-function-declaration', "
                  "language : 'c')\n"),
           "E_WERROR_DEMOTED", "meson.build: demoted after promotion")
    expect(mutate("meson.build", WERROR_LINE, ""),
           "E_WERROR", "meson.build: flag removed")
    expect(mutate("meson.build", "'-Werror=implicit-function-declaration'",
                  "'-Wimplicit-function-declaration'"),
           "E_WERROR", "meson.build: flag demoted to a warning")


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--self-test":
        self_test(Path(args[1]).resolve())
        print("CI fact-store compile coverage self-test: OK")
        return 0
    if len(args) != 1:
        print(f"usage: {Path(sys.argv[0]).name} [--self-test] SOURCE_ROOT",
              file=sys.stderr)
        return 2
    check_contract(load_sources(Path(args[0]).resolve()))
    print("CI fact-store compile coverage: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

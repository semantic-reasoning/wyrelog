#!/usr/bin/env python3
"""Prove source DuckDB exports its Linux pure-C link closure."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Callable


PACKAGE_MESON = "subprojects/packagefiles/duckdb-amalgamated/meson.build"
TESTS_MESON = "tests/meson.build"
CONSUMER = "tests/test-duckdb-source-offbridge-c-consumer.c"
WORKFLOWS = (
    ".github/workflows/ci-pr.yml",
    ".github/workflows/ci-main.yml",
)
TARGET = "test-duckdb-source-offbridge-c-consumer"
NINJA_TARGET = f"tests/{TARGET}"
EXPECTED_CONSUMER_SHA256 = (
    "d725ec816b06f009c90d16ee95718958eeb9db907fed399105bdddcea721e13a"
)


class ContractError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def reject(code: str, detail: str) -> None:
    raise ContractError(code, detail)


def require_once(text: str, token: str, code: str) -> None:
    if text.count(token) != 1:
        reject(code, f"expected exactly one {token!r}")


def require_pattern(text: str, pattern: str, code: str) -> re.Match[str]:
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if match is None:
        reject(code, f"missing pattern {pattern!r}")
    return match


def extract_assignment_call(text: str, variable: str, function: str) -> str:
    marker = f"{variable} = {function}("
    if text.count(marker) != 1:
        reject("E_DEPENDENCY_EXPORT", f"expected one {variable} declaration")
    start = text.index(marker)
    opening = start + len(marker) - 1
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    reject("E_DEPENDENCY_EXPORT", f"unterminated {variable} declaration")


def validate_package(text: str) -> None:
    linux = require_pattern(
        text,
        r"if host_machine\.system\(\) == 'linux'\n(?P<body>.*?)"
        r"\nelif host_machine\.system\(\) == 'darwin'",
        "E_LINUX_BRANCH",
    ).group("body")

    forbidden = (
        "get_id()",
        "find_library('c++'",
        "required : false",
        "no_builtin_args",
    )
    for token in forbidden:
        if token in linux:
            reject("E_WEAK_SELECTION", f"Linux branch contains {token!r}")

    required = (
        "duckdb_cpp_headers_available = cpp.compiles(",
        "duckdb_uses_libstdcxx = cpp.compiles(",
        "duckdb_uses_libcxx = cpp.compiles(",
        "#include <cstddef>",
        "#ifndef __GLIBCXX__",
        "#ifndef _LIBCPP_VERSION",
        "if not duckdb_cpp_headers_available",
        "if duckdb_uses_libstdcxx and duckdb_uses_libcxx",
        "elif duckdb_uses_libcxx",
        "elif not duckdb_uses_libstdcxx",
        "cpp.find_library('m', required : true)",
        "cpp.find_library('stdc++', required : true)",
    )
    for token in required:
        if token not in linux:
            reject("E_ABI_PROBE", f"Linux branch is missing {token!r}")

    if linux.count("#include <cstddef>") != 3:
        reject("E_HEADER_PROBE", "all three probes must use <cstddef>")
    if linux.index("if not duckdb_cpp_headers_available") > linux.index(
        "duckdb_uses_libstdcxx = cpp.compiles("
    ):
        reject("E_HEADER_ORDER", "header availability must fail before ABI probes")

    diagnostics = (
        "configured C++ preprocessing environment cannot include <cstddef>",
        "found both __GLIBCXX__ and _LIBCPP_VERSION",
        "does not support libc++",
        "found neither __GLIBCXX__ nor _LIBCPP_VERSION",
    )
    for diagnostic in diagnostics:
        require_once(linux, diagnostic, "E_DIAGNOSTIC")

    m_index = linux.index("cpp.find_library('m', required : true)")
    stdcxx_index = linux.index("cpp.find_library('stdc++', required : true)")
    supported_index = linux.index("elif not duckdb_uses_libstdcxx")
    if m_index < supported_index or stdcxx_index < supported_index:
        reject("E_LIBRARY_SCOPE", "runtime libraries are outside the supported ABI path")

    owners = (
        ("duckdb_lib", "static_library", None),
        ("duckdb_dep", "declare_dependency", "link_with : duckdb_lib"),
        ("duckdb_test_seam_lib", "static_library", None),
        (
            "duckdb_test_seam_dep",
            "declare_dependency",
            "link_with : duckdb_test_seam_lib",
        ),
    )
    for variable, function, link_with in owners:
        declaration = extract_assignment_call(text, variable, function)
        declaration = "\n".join(
            line.split("#", 1)[0] for line in declaration.splitlines()
        )
        require_once(declaration, "dependencies : duckdb_deps", "E_DEPENDENCY_EXPORT")
        if link_with is not None:
            require_once(declaration, link_with, "E_DEPENDENCY_EXPORT")


def extract_consumer_target(text: str) -> str:
    return require_pattern(
        text,
        rf"{TARGET.replace('-', '_')} = executable\(\s*'{TARGET}',(?P<body>.*?)\n  \)",
        "E_CONSUMER_TARGET",
    ).group("body")


def validate_tests_meson(text: str) -> None:
    for name in (
        "duckdb-linux-link-dependency-wiring",
        "duckdb-linux-link-dependency-wiring-self-test",
    ):
        require_once(text, f"test('{name}'", "E_CHECKER_REGISTRATION")

    condition = (
        "if host_machine.system() == 'linux' and \\\n"
        "    get_option('duckdb_source') == 'subproject' and \\\n"
        "    get_option('enable_fact_store').enabled() and \\\n"
        "    not enable_secure_duckdb_bridge_opt.enabled()"
    )
    require_once(text, condition, "E_CONSUMER_GATING")

    target = extract_consumer_target(text)
    require_once(target, "'test-duckdb-source-offbridge-c-consumer.c'", "E_C_SOURCE")
    if target.count(".c'") != 1:
        reject("E_C_SOURCE", "consumer target must contain exactly one C source")
    require_once(target, "dependencies : duckdb_dep", "E_TARGET_DEPENDENCY")
    if target.count("dependencies") != 1:
        reject("E_TARGET_DEPENDENCY", "consumer must have only duckdb_dep")
    require_once(target, "link_language : 'c'", "E_C_LINK_LANGUAGE")
    if target.count("link_language") != 1:
        reject("E_C_LINK_LANGUAGE", "consumer must have one literal C link language")
    for token in ("link_args", "cpp_args", "link_with"):
        if token in target:
            reject("E_TARGET_WORKAROUND", f"consumer target contains {token!r}")

    require_once(
        text,
        "test('duckdb-source-offbridge-c-consumer',",
        "E_CONSUMER_RUNTIME",
    )
    generated = require_pattern(
        text,
        r"test\('duckdb-linux-link-dependency-wiring-generated',(?P<body>.*?)\n  \)",
        "E_GENERATED_REGISTRATION",
    ).group("body")
    for token in ("'--build-root'", "meson.project_build_root()", "depends :"):
        if token not in generated:
            reject("E_GENERATED_REACHABILITY", f"generated checker lacks {token!r}")


def strip_c_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.DOTALL)


def validate_consumer(text: str) -> None:
    if re.search(
        r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b", text
    ) is not None:
        reject(
            "E_CONSUMER_LIFECYCLE",
            "consumer lifecycle must not be hidden behind preprocessor branches",
        )

    active = strip_c_comments(text)
    if "#include <duckdb.h>" not in active:
        reject("E_CONSUMER_LIFECYCLE", "consumer lacks duckdb.h")
    if len(re.findall(r"\bmain\s*\(", active)) != 1:
        reject("E_CONSUMER_LIFECYCLE", "consumer must define exactly one main()")
    main = require_pattern(
        active,
        r"\bint\s+main\s*\(\s*void\s*\)\s*\{(?P<body>.*)\}\s*$",
        "E_CONSUMER_LIFECYCLE",
    ).group("body")
    if re.search(r"\b(?:if|while)\s*\(\s*(?:0|false|FALSE)\s*\)", main):
        reject("E_CONSUMER_LIFECYCLE", "consumer lifecycle contains dead control flow")
    require_once(main, "int status = 1;", "E_CONSUMER_LIFECYCLE")
    require_once(main, "status = 0;", "E_CONSUMER_LIFECYCLE")
    require_once(main, "return status;", "E_CONSUMER_LIFECYCLE")
    if len(re.findall(r"\breturn\b", main)) != 1:
        reject("E_CONSUMER_LIFECYCLE", "consumer must have one final status return")
    for function in (
        "duckdb_open",
        "duckdb_connect",
        "duckdb_query",
        "duckdb_row_count",
        "duckdb_column_count",
        "duckdb_column_name",
        "duckdb_value_int64",
        "duckdb_destroy_result",
        "duckdb_disconnect",
        "duckdb_close",
    ):
        if re.search(rf"\b{function}\s*\(", main) is None:
            reject("E_CONSUMER_LIFECYCLE", f"consumer lacks {function}()")
    if "SELECT 42 AS answer" not in main:
        reject("E_CONSUMER_QUERY", "consumer must execute the sentinel query")
    require_once(main, "if (duckdb_open (", "E_CONSUMER_LIFECYCLE")
    pre_open = main[: main.index("if (duckdb_open (")]
    if re.search(r"\b(?:if|while|for)\s*\(", pre_open):
        reject(
            "E_CONSUMER_LIFECYCLE",
            "consumer open lifecycle must not be control-flow guarded",
        )

    ordered = (
        main.index("duckdb_open ("),
        main.index("duckdb_connect ("),
        main.index("duckdb_query ("),
        main.index("duckdb_column_name ("),
        main.index("duckdb_row_count ("),
        main.index("duckdb_column_count ("),
        main.index("duckdb_value_int64 ("),
        main.rindex("duckdb_destroy_result ("),
        main.index("status = 0;"),
        main.index("duckdb_disconnect ("),
        main.index("duckdb_close ("),
        main.index("return status;"),
    )
    if tuple(sorted(ordered)) != ordered:
        reject("E_CONSUMER_LIFECYCLE", "consumer lifecycle order drifted")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if digest != EXPECTED_CONSUMER_SHA256:
        reject("E_CONSUMER_LIFECYCLE", "canonical executable consumer drifted")


def extract_ci_job(workflow: str) -> str:
    marker = "  duckdb-linux-link-closure:\n"
    if workflow.count(marker) != 1:
        reject("E_CI_JOB", "DuckDB Linux link closure job must occur once")
    start = workflow.index(marker)
    match = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", workflow[start + len(marker) :])
    if match is None:
        return workflow[start:]
    return workflow[start : start + len(marker) + match.start()]


def extract_ci_step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    if job.count(marker) != 1:
        reject("E_CI_JOB", f"CI step {name!r} must occur once")
    start = job.index(marker)
    match = re.search(r"(?m)^      - name: ", job[start + len(marker) :])
    if match is None:
        return job[start:]
    return job[start : start + len(marker) + match.start()]


def validate_ci_job(job: str, path: str) -> None:
    required_once = (
        "    name: duckdb-linux-link-closure-${{ matrix.compiler }}\n",
        "    runs-on: ubuntu-latest\n",
        "    timeout-minutes: 45\n",
        "      fail-fast: false\n",
        "          - compiler: gcc\n            cc: gcc\n            cxx: g++\n            cxxflags: \"\"\n",
        "          - compiler: clang-libstdcxx\n            cc: clang\n            cxx: clang++\n            cxxflags: -stdlib=libstdc++\n",
        "      - name: Verify GitHub-hosted runner contract\n",
        "      - name: Configure source-offbridge C-link closure\n",
        "      - name: Compile Clang/libstdc++ C consumer\n",
        "      - name: Run Clang/libstdc++ C consumer proof\n",
        "      - name: Run GCC source-offbridge full suite\n",
        "      - name: Reject unsupported C++ ABI configurations\n",
        "      - name: Upload DuckDB Linux link logs on failure\n",
    )
    for token in required_once:
        require_once(job, token, "E_CI_JOB")

    cache_name = (
        "Restore DuckDB source packagecache"
        if path.endswith("ci-pr.yml")
        else "Cache DuckDB source packagecache"
    )
    require_once(job, f"      - name: {cache_name}\n", "E_CI_CACHE")
    cache_action = "actions/cache/restore@" if path.endswith("ci-pr.yml") else "actions/cache@"
    require_once(job, cache_action, "E_CI_CACHE")

    positive_options = (
        "-Denable_fact_store=enabled",
        "-Dduckdb_source=subproject",
        "-Denable_secure_duckdb_bridge=disabled",
    )
    for option in positive_options:
        if job.count(option) != 5:
            reject("E_CI_CONFIG", f"{path}: expected five exact {option} setups")
    for option in ("-Denable_tpm=disabled", "-Denable_audit=disabled"):
        if job.count(option) != 4:
            reject("E_CI_CONFIG", f"{path}: expected four negative-only {option} setups")

    if job.count("meson setup build-duckdb-linux-link ") != 1:
        reject("E_CI_POSITIVE", f"{path}: positive setup inventory drifted")
    if job.count("meson compile -C build-duckdb-linux-link") != 1:
        reject("E_CI_COMPILE", f"{path}: focused compile inventory drifted")
    if job.count("meson test -C build-duckdb-linux-link") != 2:
        reject("E_CI_TEST", f"{path}: focused/full test inventory drifted")
    if job.count("--suite wyrelog") != 1:
        reject("E_CI_FULL_SUITE", f"{path}: full suite must run exactly once")
    if "--no-rebuild" not in job:
        reject("E_CI_FOCUSED", f"{path}: focused proof must not rebuild")

    for build_dir, diagnostic in (
        ("build-duckdb-linux-libcxx", "does not support libc++"),
        ("build-duckdb-linux-both", "found both __GLIBCXX__ and _LIBCPP_VERSION"),
        ("build-duckdb-linux-neither", "found neither __GLIBCXX__ nor _LIBCPP_VERSION"),
        ("build-duckdb-linux-no-header", "cannot include <cstddef>"),
    ):
        require_once(job, f"meson setup {build_dir} ", "E_CI_NEGATIVE")
        require_once(job, diagnostic, "E_CI_NEGATIVE")

    forbidden = (
        "continue-on-error:",
        "|| true",
        "--repeat",
        "--maxfail",
        "if: false",
        "if: ${{ false }}",
    )
    for token in forbidden:
        if token in job:
            reject("E_CI_MASKING", f"{path}: forbidden token {token!r}")
    if re.search(r"\b(?:exit|return)(?:\s+0)?\s*(?:;|$)", job, re.MULTILINE):
        reject("E_CI_MASKING", f"{path}: early successful shell exit is forbidden")

    steps: dict[str, str] = {}
    for name, compiler in (
        ("Compile Clang/libstdc++ C consumer", "clang-libstdcxx"),
        ("Run Clang/libstdc++ C consumer proof", "clang-libstdcxx"),
        ("Run GCC source-offbridge full suite", "gcc"),
        ("Reject unsupported C++ ABI configurations", "clang-libstdcxx"),
    ):
        step = extract_ci_step(job, name)
        steps[name] = step
        condition = f"        if: matrix.compiler == '{compiler}'\n"
        require_once(step, condition, "E_CI_ROW")
        if len(re.findall(r"(?m)^        if:", step)) != 1:
            reject("E_CI_ROW", f"{path}: {name!r} must have one exact row condition")

    configure = extract_ci_step(job, "Configure source-offbridge C-link closure")
    require_once(
        configure,
        "          meson setup build-duckdb-linux-link \\\n",
        "E_CI_STEP",
    )
    for option in positive_options:
        require_once(configure, option, "E_CI_STEP")
    for option in ("-Denable_tpm", "-Denable_audit"):
        if option in configure:
            reject("E_CI_STEP", f"{path}: positive setup is not the exact reproduction")
    actual_positive_options = tuple(
        re.findall(r"(?m)^\s+(-D[^\s\\]+)\s*\\?\s*$", configure)
    )
    if actual_positive_options != positive_options:
        reject("E_CI_STEP", f"{path}: positive setup option inventory drifted")

    compile_step = steps["Compile Clang/libstdc++ C consumer"]
    require_once(
        compile_step,
        "          meson compile -C build-duckdb-linux-link -j 1 \\\n"
        "            test-duckdb-source-offbridge-c-consumer",
        "E_CI_STEP",
    )

    focused_step = steps["Run Clang/libstdc++ C consumer proof"]
    require_once(
        focused_step,
        "          meson test -C build-duckdb-linux-link --no-rebuild "
        "--print-errorlogs \\\n",
        "E_CI_STEP",
    )
    for test_line in (
        "            duckdb-source-offbridge-c-consumer \\\n",
        "            duckdb-linux-link-dependency-wiring \\\n",
        "            duckdb-linux-link-dependency-wiring-self-test \\\n",
        "            duckdb-linux-link-dependency-wiring-generated\n",
    ):
        require_once(focused_step, test_line, "E_CI_STEP")

    require_once(
        steps["Run GCC source-offbridge full suite"],
        "          meson test -C build-duckdb-linux-link --print-errorlogs "
        "--suite wyrelog\n",
        "E_CI_STEP",
    )

    negative_step = steps["Reject unsupported C++ ABI configurations"]
    for build_dir, diagnostic, log_name in (
        ("build-duckdb-linux-libcxx", "does not support libc++", "duckdb-linux-libcxx.log"),
        (
            "build-duckdb-linux-both",
            "found both __GLIBCXX__ and _LIBCPP_VERSION",
            "duckdb-linux-both.log",
        ),
        (
            "build-duckdb-linux-neither",
            "found neither __GLIBCXX__ nor _LIBCPP_VERSION",
            "duckdb-linux-neither.log",
        ),
        (
            "build-duckdb-linux-no-header",
            "cannot include <cstddef>",
            "duckdb-linux-no-header.log",
        ),
    ):
        require_once(negative_step, f"            meson setup {build_dir} ", "E_CI_STEP")
        grep_command = f"          grep -F '{diagnostic}' {log_name}\n"
        if build_dir in {"build-duckdb-linux-both", "build-duckdb-linux-neither"}:
            grep_command = (
                f"          grep -F '{diagnostic}' \\\n"
                f"            {log_name}\n"
            )
        require_once(
            negative_step,
            grep_command,
            "E_CI_STEP",
        )


def validate_workflows(sources: dict[str, str]) -> None:
    jobs = []
    for path in WORKFLOWS:
        job = extract_ci_job(sources[path])
        validate_ci_job(job, path)
        jobs.append(job)
    normalized = jobs[0].replace(
        "Restore DuckDB source packagecache", "<DuckDB source packagecache>"
    ).replace("actions/cache/restore@", "actions/cache@")
    main = jobs[1].replace(
        "Cache DuckDB source packagecache", "<DuckDB source packagecache>"
    )
    if normalized != main:
        reject("E_CI_PARITY", "PR/main DuckDB Linux link jobs diverged")


def normalize_link_tokens(command: str) -> list[str]:
    tokens: list[str] = []
    for token in shlex.split(command):
        if token.startswith("-Wl,"):
            tokens.extend(part for part in token[4:].split(",") if part)
        else:
            tokens.append(token)
    return tokens


def is_archive(token: str) -> bool:
    return Path(token).name == "libduckdb.a"


def is_libm(token: str) -> bool:
    name = Path(token).name
    return token == "-lm" or name == "libm.a" or name.startswith("libm.so")


def is_libstdcxx(token: str) -> bool:
    name = Path(token).name
    return token == "-lstdc++" or name == "libstdc++.a" or name.startswith(
        "libstdc++.so"
    )


def is_pthread(token: str) -> bool:
    name = Path(token).name
    return token == "-lpthread" or name == "libpthread.a" or name.startswith(
        "libpthread.so"
    )


def is_libdl(token: str) -> bool:
    name = Path(token).name
    return token == "-ldl" or name == "libdl.a" or name.startswith("libdl.so")


def c_driver_present(tokens: list[str]) -> bool:
    return any(
        token == "cc"
        or token == "clang"
        or token == "gcc"
        or re.fullmatch(r"(?:.+-)?(?:gcc|clang|cc)(?:-[0-9.]+)?", token)
        for token in (Path(item).name for item in tokens)
    )


def validate_link_command(command: str) -> None:
    tokens = normalize_link_tokens(command)
    archive_indices = [index for index, token in enumerate(tokens) if is_archive(token)]
    if len(archive_indices) != 1:
        reject("E_LINK_ARCHIVE", "link command must contain regular libduckdb.a once")
    archive_index = archive_indices[0]

    group_depth = 0
    for token in tokens:
        if token == "--start-group":
            group_depth += 1
        elif token == "--end-group":
            group_depth -= 1
            if group_depth < 0:
                reject("E_LINK_GROUP", "linker group closes before it opens")
    if group_depth != 0:
        reject("E_LINK_GROUP", "linker groups are unbalanced")

    closure = tokens[archive_index + 1 :]
    if not any(is_pthread(token) for token in closure):
        reject("E_LINK_PTHREAD", "pthread must follow the DuckDB archive")
    if not any(is_libdl(token) for token in closure):
        reject("E_LINK_DL", "libdl must follow the DuckDB archive")
    if not any(is_libm(token) for token in closure):
        reject("E_LINK_M", "libm must follow the DuckDB archive")
    if not any(is_libstdcxx(token) for token in closure):
        reject("E_LINK_STDCXX", "libstdc++ must follow the DuckDB archive")

    output_index = tokens.index("-o") if "-o" in tokens else len(tokens)
    driver_tokens = [Path(token).name for token in tokens[:output_index]]
    if any(token in {"c++", "g++", "clang++"} for token in driver_tokens):
        reject("E_LINK_DRIVER", "consumer is linked with a C++ driver")
    if not c_driver_present(driver_tokens):
        reject("E_LINK_DRIVER", "consumer link command has no recognizable C driver")


def validate_generated_commands(output: str) -> None:
    lines = output.splitlines()
    compile_candidates = [
        line
        for line in lines
        if "test-duckdb-source-offbridge-c-consumer.c" in line and " -c " in line
    ]
    if len(compile_candidates) != 1:
        reject("E_COMPILE_COMMAND", "could not select exactly one C compile command")
    compile_command = compile_candidates[0]
    compile_tokens = normalize_link_tokens(compile_command)
    uses_cpp_language = any(
        compile_tokens[index] == "-x"
        and index + 1 < len(compile_tokens)
        and compile_tokens[index + 1] == "c++"
        for index in range(len(compile_tokens))
    )
    if any(
        Path(token).name in {"c++", "g++", "clang++"} for token in compile_tokens
    ) or uses_cpp_language or "/TP" in compile_tokens:
        reject("E_COMPILE_DRIVER", "consumer source is compiled as C++")
    if not c_driver_present(compile_tokens):
        reject("E_COMPILE_DRIVER", "consumer compile command has no C driver")
    if "-o" not in compile_tokens:
        reject("E_COMPILE_OBJECT", "consumer compile command has no output object")
    object_index = compile_tokens.index("-o") + 1
    if object_index >= len(compile_tokens):
        reject("E_COMPILE_OBJECT", "consumer compile object is missing")
    object_path = compile_tokens[object_index]

    link_candidates = []
    for line in lines:
        tokens = normalize_link_tokens(line)
        if "-o" not in tokens:
            continue
        output_index = tokens.index("-o") + 1
        if output_index < len(tokens) and tokens[output_index] in {
            NINJA_TARGET,
            TARGET,
        }:
            link_candidates.append(line)
    if len(link_candidates) != 1:
        reject("E_NINJA_COMMAND", "could not select exactly one consumer link command")
    link_command = link_candidates[0]
    if object_path not in normalize_link_tokens(link_command):
        reject("E_COMPILE_OBJECT", "consumer C object does not reach the link command")
    validate_link_command(link_command)


def generated_commands(build_root: Path) -> str:
    result = subprocess.run(
        ["ninja", "-C", str(build_root), "-t", "commands", NINJA_TARGET],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        reject("E_NINJA_COMMAND", result.stderr.strip() or "ninja command query failed")
    return result.stdout


def load_sources(root: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for relative in (PACKAGE_MESON, TESTS_MESON, CONSUMER, *WORKFLOWS):
        path = root / relative
        try:
            sources[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            reject("E_READ", f"{relative}: {exc}")
    return sources


def validate_sources(sources: dict[str, str]) -> None:
    validate_package(sources[PACKAGE_MESON])
    validate_tests_meson(sources[TESTS_MESON])
    validate_consumer(sources[CONSUMER])
    validate_workflows(sources)


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"mutation anchor drifted: {old!r}")
    return text.replace(old, new, 1)


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    transform: Callable[[str], str]
    code: str


def expect_failure(operation: Callable[[], None], code: str) -> None:
    try:
        operation()
    except ContractError as exc:
        if exc.code != code:
            reject("E_SELF_TEST", f"expected {code}, received {exc.code}")
    else:
        reject("E_SELF_TEST", f"mutation did not trigger {code}")


def run_self_test(root: Path) -> None:
    sources = load_sources(root)
    validate_sources(sources)
    mutations = (
        Mutation(
            "optional libm",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "cpp.find_library('m', required : true)",
                "cpp.find_library('m', required : false)",
            ),
            "E_WEAK_SELECTION",
        ),
        Mutation(
            "missing libm",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "  duckdb_deps += cpp.find_library('m', required : true)\n",
                "",
            ),
            "E_ABI_PROBE",
        ),
        Mutation(
            "missing libstdc++",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "  duckdb_deps += cpp.find_library('m', required : true)\n"
                "  duckdb_deps += cpp.find_library('stdc++', required : true)\n",
                "  duckdb_deps += cpp.find_library('m', required : true)\n",
            ),
            "E_ABI_PROBE",
        ),
        Mutation(
            "wrong C++ runtime",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "  duckdb_deps += cpp.find_library('m', required : true)\n"
                "  duckdb_deps += cpp.find_library('stdc++', required : true)\n",
                "  duckdb_deps += cpp.find_library('m', required : true)\n"
                "  duckdb_deps += cpp.find_library('c++', required : true)\n",
            ),
            "E_WEAK_SELECTION",
        ),
        Mutation(
            "optional libstdc++",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "  duckdb_deps += cpp.find_library('m', required : true)\n"
                "  duckdb_deps += cpp.find_library('stdc++', required : true)\n",
                "  duckdb_deps += cpp.find_library('m', required : true)\n"
                "  duckdb_deps += cpp.find_library('stdc++', required : false)\n",
            ),
            "E_WEAK_SELECTION",
        ),
        Mutation(
            "compiler id selection",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "duckdb_uses_libstdcxx = cpp.compiles(",
                "duckdb_uses_libstdcxx = cpp.get_id() == 'gcc' and cpp.compiles(",
            ),
            "E_WEAK_SELECTION",
        ),
        Mutation(
            "missing header probe include",
            PACKAGE_MESON,
            lambda text: text.replace(
                "#include <cstddef>", "#include <stddef.h>", 1
            ),
            "E_HEADER_PROBE",
        ),
        Mutation(
            "late header availability failure",
            PACKAGE_MESON,
            lambda text: replace_once(
                replace_once(
                    text,
                    "  if not duckdb_cpp_headers_available\n",
                    "  if true\n",
                ),
                "  duckdb_uses_libcxx = cpp.compiles(\n",
                "  if not duckdb_cpp_headers_available\n"
                "  endif\n\n"
                "  duckdb_uses_libcxx = cpp.compiles(\n",
            ),
            "E_HEADER_ORDER",
        ),
        Mutation(
            "missing libstdc++ marker",
            PACKAGE_MESON,
            lambda text: replace_once(text, "#ifndef __GLIBCXX__\n", "#if 0\n"),
            "E_ABI_PROBE",
        ),
        Mutation(
            "missing libcxx marker",
            PACKAGE_MESON,
            lambda text: replace_once(
                text, "#ifndef _LIBCPP_VERSION\n", "#if 0\n"
            ),
            "E_ABI_PROBE",
        ),
        *(
            Mutation(
                f"diagnostic drift: {diagnostic}",
                PACKAGE_MESON,
                lambda text, diagnostic=diagnostic: replace_once(
                    text, diagnostic, "diagnostic drifted"
                ),
                "E_DIAGNOSTIC",
            )
            for diagnostic in (
                "configured C++ preprocessing environment cannot include <cstddef>",
                "found both __GLIBCXX__ and _LIBCPP_VERSION",
                "does not support libc++",
                "found neither __GLIBCXX__ nor _LIBCPP_VERSION",
            )
        ),
        Mutation(
            "regular dependency loses closure with decoy",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "duckdb_dep = declare_dependency(\n  link_with : duckdb_lib,\n  dependencies : duckdb_deps,",
                "duckdb_dep = declare_dependency(\n  link_with : duckdb_lib,",
            )
            + "\n# dependencies : duckdb_deps\n",
            "E_DEPENDENCY_EXPORT",
        ),
        Mutation(
            "regular dependency keeps only commented closure",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "duckdb_dep = declare_dependency(\n"
                "  link_with : duckdb_lib,\n"
                "  dependencies : duckdb_deps,",
                "duckdb_dep = declare_dependency(\n"
                "  link_with : duckdb_lib,\n"
                "  # dependencies : duckdb_deps,",
            ),
            "E_DEPENDENCY_EXPORT",
        ),
        Mutation(
            "regular dependency keeps only inline-comment closure",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "duckdb_dep = declare_dependency(\n"
                "  link_with : duckdb_lib,\n"
                "  dependencies : duckdb_deps,",
                "duckdb_dep = declare_dependency(\n"
                "  link_with : duckdb_lib, # dependencies : duckdb_deps,",
            ),
            "E_DEPENDENCY_EXPORT",
        ),
        Mutation(
            "regular library loses closure with decoy",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "  dependencies : duckdb_deps,\n  cpp_args : duckdb_compile_args,",
                "  cpp_args : duckdb_compile_args,",
            )
            + "\n# dependencies : duckdb_deps\n",
            "E_DEPENDENCY_EXPORT",
        ),
        Mutation(
            "seam library loses closure with decoy",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "    dependencies : duckdb_deps,\n"
                "    cpp_args : duckdb_test_seam_compile_args,",
                "    cpp_args : duckdb_test_seam_compile_args,",
            )
            + "\n# dependencies : duckdb_deps\n",
            "E_DEPENDENCY_EXPORT",
        ),
        Mutation(
            "seam dependency loses closure with decoy",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "  duckdb_test_seam_dep = declare_dependency(\n"
                "    link_with : duckdb_test_seam_lib,\n"
                "    dependencies : duckdb_deps,",
                "  duckdb_test_seam_dep = declare_dependency(\n"
                "    link_with : duckdb_test_seam_lib,",
            )
            + "\n# dependencies : duckdb_deps\n",
            "E_DEPENDENCY_EXPORT",
        ),
        Mutation(
            "consumer link workaround",
            TESTS_MESON,
            lambda text: replace_once(
                text,
                "dependencies : duckdb_dep,",
                "dependencies : duckdb_dep,\n    link_args : ['-lstdc++'],",
            ),
            "E_TARGET_WORKAROUND",
        ),
        Mutation(
            "consumer automatic link language",
            TESTS_MESON,
            lambda text: replace_once(text, "    link_language : 'c',\n", ""),
            "E_C_LINK_LANGUAGE",
        ),
        Mutation(
            "consumer C++ link language",
            TESTS_MESON,
            lambda text: replace_once(
                text, "link_language : 'c'", "link_language : 'cpp'"
            ),
            "E_C_LINK_LANGUAGE",
        ),
        Mutation(
            "consumer conditional link language",
            TESTS_MESON,
            lambda text: replace_once(
                text,
                "link_language : 'c'",
                "link_language : host_machine.system() == 'linux' ? 'c' : 'cpp'",
            ),
            "E_C_LINK_LANGUAGE",
        ),
        Mutation(
            "consumer extra source",
            TESTS_MESON,
            lambda text: replace_once(
                text,
                "'test-duckdb-source-offbridge-c-consumer.c',",
                "'test-duckdb-source-offbridge-c-consumer.c',\n    'test-engine.c',",
            ),
            "E_C_SOURCE",
        ),
        Mutation(
            "consumer extra dependency",
            TESTS_MESON,
            lambda text: replace_once(
                text,
                "dependencies : duckdb_dep,",
                "dependencies : [duckdb_dep, glib_dep],",
            ),
            "E_TARGET_DEPENDENCY",
        ),
        Mutation(
            "consumer skips query",
            CONSUMER,
            lambda text: replace_once(text, "duckdb_query (", "duckdb_query_removed ("),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer skips cleanup",
            CONSUMER,
            lambda text: text.replace(
                "duckdb_destroy_result (", "duckdb_destroy_result_removed ("
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer hidden in disabled preprocessor branch",
            CONSUMER,
            lambda text: (
                "#if 0\n"
                + text
                + "\n#endif\n\nint\nmain (void)\n{\n  return 0;\n}\n"
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer hidden in block comment",
            CONSUMER,
            lambda text: (
                "/*\n"
                + text
                + "\n*/\n\nint\nmain (void)\n{\n  return 0;\n}\n"
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer lifecycle hidden behind if zero",
            CONSUMER,
            lambda text: replace_once(
                replace_once(
                    text,
                    "  duckdb_database database = NULL;",
                    "  if (0) {\n    duckdb_database database = NULL;",
                ),
                "  return status;\n",
                "  }\n  return 0;\n",
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer lifecycle hidden behind false initial state",
            CONSUMER,
            lambda text: replace_once(
                replace_once(
                    text,
                    "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
                    "  if (database != NULL) {\n"
                    "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
                ),
                "  status = 0;\n",
                "  }\n  status = 0;\n",
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer lifecycle hidden behind constant expression",
            CONSUMER,
            lambda text: replace_once(
                replace_once(
                    text,
                    "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
                    "  if (1 == 0) {\n"
                    "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
                ),
                "  status = 0;\n",
                "  }\n  status = 0;\n",
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer lifecycle skipped by goto",
            CONSUMER,
            lambda text: replace_once(
                replace_once(
                    text,
                    "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
                    "  goto lifecycle_skipped;\n\n"
                    "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
                ),
                "  status = 0;\n",
                "lifecycle_skipped:\n  status = 0;\n",
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "consumer returns success before lifecycle",
            CONSUMER,
            lambda text: replace_once(
                text,
                "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
                "  return 0;\n\n"
                "  if (duckdb_open (NULL, &database) != DuckDBSuccess) {",
            ),
            "E_CONSUMER_LIFECYCLE",
        ),
        Mutation(
            "CI loses Clang row",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "          - compiler: clang-libstdcxx\n"
                "            cc: clang\n"
                "            cxx: clang++\n"
                "            cxxflags: -stdlib=libstdc++\n",
                "",
            ),
            "E_CI_JOB",
        ),
        Mutation(
            "CI moves Clang compile to GCC row",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "      - name: Compile Clang/libstdc++ C consumer\n"
                "        if: matrix.compiler == 'clang-libstdcxx'\n",
                "      - name: Compile Clang/libstdc++ C consumer\n"
                "        if: matrix.compiler == 'gcc'\n",
            ),
            "E_CI_ROW",
        ),
        Mutation(
            "CI moves Clang runtime proof to GCC row",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "      - name: Run Clang/libstdc++ C consumer proof\n"
                "        if: matrix.compiler == 'clang-libstdcxx'\n",
                "      - name: Run Clang/libstdc++ C consumer proof\n"
                "        if: matrix.compiler == 'gcc'\n",
            ),
            "E_CI_ROW",
        ),
        Mutation(
            "CI moves GCC full suite to Clang row",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "      - name: Run GCC source-offbridge full suite\n"
                "        if: matrix.compiler == 'gcc'\n",
                "      - name: Run GCC source-offbridge full suite\n"
                "        if: matrix.compiler == 'clang-libstdcxx'\n",
            ),
            "E_CI_ROW",
        ),
        Mutation(
            "CI moves negative ABI proof to GCC row",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "      - name: Reject unsupported C++ ABI configurations\n"
                "        if: matrix.compiler == 'clang-libstdcxx'\n",
                "      - name: Reject unsupported C++ ABI configurations\n"
                "        if: matrix.compiler == 'gcc'\n",
            ),
            "E_CI_ROW",
        ),
        Mutation(
            "CI moves GCC full-suite command into Clang proof step",
            WORKFLOWS[0],
            lambda text: replace_once(
                replace_once(
                    text,
                    "      - name: Run GCC source-offbridge full suite\n"
                    "        if: matrix.compiler == 'gcc'\n"
                    "        run: |\n"
                    "          meson test -C build-duckdb-linux-link "
                    "--print-errorlogs --suite wyrelog",
                    "      - name: Run GCC source-offbridge full suite\n"
                    "        if: matrix.compiler == 'gcc'\n"
                    "        run: |\n"
                    "          echo 'full suite command moved'",
                ),
                "            duckdb-linux-link-dependency-wiring-generated\n",
                "            duckdb-linux-link-dependency-wiring-generated\n"
                "          meson test -C build-duckdb-linux-link "
                "--print-errorlogs --suite wyrelog\n",
            ),
            "E_CI_STEP",
        ),
        Mutation(
            "CI comments out GCC full-suite command",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "          meson test -C build-duckdb-linux-link "
                "--print-errorlogs --suite wyrelog\n",
                "          echo 'full suite disabled'\n"
                "          # meson test -C build-duckdb-linux-link "
                "--print-errorlogs --suite wyrelog\n",
            ),
            "E_CI_STEP",
        ),
        Mutation(
            "CI replaces full suite with compile-only evidence",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "meson test -C build-duckdb-linux-link --print-errorlogs --suite wyrelog",
                "meson compile -C build-duckdb-linux-link",
            ),
            "E_CI_COMPILE",
        ),
        Mutation(
            "CI tolerates focused failure",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "      - name: Run Clang/libstdc++ C consumer proof\n",
                "      - name: Run Clang/libstdc++ C consumer proof\n"
                "        continue-on-error: true\n",
            ),
            "E_CI_MASKING",
        ),
        Mutation(
            "CI skips GCC full suite",
            WORKFLOWS[0],
            lambda text: replace_once(
                text, "if: matrix.compiler == 'gcc'", "if: false"
            ),
            "E_CI_MASKING",
        ),
        Mutation(
            "CI exits successfully before GCC full suite",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "          meson test -C build-duckdb-linux-link "
                "--print-errorlogs --suite wyrelog\n",
                "          exit 0\n"
                "          meson test -C build-duckdb-linux-link "
                "--print-errorlogs --suite wyrelog\n",
            ),
            "E_CI_MASKING",
        ),
        Mutation(
            "CI repeats GCC full suite",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "meson test -C build-duckdb-linux-link --print-errorlogs --suite wyrelog",
                "meson test -C build-duckdb-linux-link --print-errorlogs "
                "--suite wyrelog --repeat 2",
            ),
            "E_CI_MASKING",
        ),
        Mutation(
            "CI drifts positive configuration",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "meson setup build-duckdb-linux-link \\\n"
                "            -Denable_fact_store=enabled",
                "meson setup build-duckdb-linux-link \\\n"
                "            -Denable_fact_store=disabled",
            ),
            "E_CI_CONFIG",
        ),
        Mutation(
            "CI adds a fourth positive option",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "meson setup build-duckdb-linux-link \\\n"
                "            -Denable_fact_store=enabled \\\n",
                "meson setup build-duckdb-linux-link \\\n"
                "            -Denable_fact_store=enabled \\\n"
                "            -Denable_client=disabled \\\n",
            ),
            "E_CI_STEP",
        ),
        Mutation(
            "CI accepts any negative failure",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "grep -F 'does not support libc++' duckdb-linux-libcxx.log",
                "test -s duckdb-linux-libcxx.log",
            ),
            "E_CI_NEGATIVE",
        ),
        Mutation(
            "CI PR/main drift",
            WORKFLOWS[0],
            lambda text: replace_once(
                text,
                "name: duckdb-linux-link-logs-${{ matrix.compiler }}",
                "name: duckdb-linux-link-pr-${{ matrix.compiler }}",
            ),
            "E_CI_PARITY",
        ),
    )
    for mutation in mutations:
        changed = dict(sources)
        changed[mutation.path] = mutation.transform(changed[mutation.path])
        expect_failure(lambda changed=changed: validate_sources(changed), mutation.code)

    valid = (
        "cc -o tests/test-duckdb-source-offbridge-c-consumer consumer.o "
        "subprojects/duckdb-amalgamated/libduckdb.a "
        "-Wl,--start-group -lpthread -ldl -lm -lstdc++ -Wl,--end-group"
    )
    validate_link_command(valid)
    validate_link_command(valid + " -lstdc++")
    link_mutations = (
        (valid.replace(" -lpthread", ""), "E_LINK_PTHREAD"),
        (valid.replace(" -ldl", ""), "E_LINK_DL"),
        (valid.replace(" -lm", ""), "E_LINK_M"),
        (valid.replace(" -lstdc++", ""), "E_LINK_STDCXX"),
        (valid.replace("cc -o", "c++ -o"), "E_LINK_DRIVER"),
        (valid.replace("-Wl,--end-group", ""), "E_LINK_GROUP"),
        (
            valid.replace("subprojects/duckdb-amalgamated/libduckdb.a ", "")
            .replace("cc -o", "cc -lduckdb -o"),
            "E_LINK_ARCHIVE",
        ),
        (valid.replace("-lm", "-lm-before").replace("cc -o", "cc -lm -o"), "E_LINK_M"),
    )
    for command, code in link_mutations:
        expect_failure(lambda command=command: validate_link_command(command), code)

    object_path = (
        "tests/test-duckdb-source-offbridge-c-consumer.p/"
        "test-duckdb-source-offbridge-c-consumer.c.o"
    )
    compile_command = (
        f"cc -o {object_path} -c "
        "../tests/test-duckdb-source-offbridge-c-consumer.c"
    )
    generated_link = (
        f"cc -o tests/{TARGET} {object_path} "
        "subprojects/duckdb-amalgamated-src/libduckdb.a "
        "-Wl,--start-group -lpthread -ldl -lm -lstdc++ -Wl,--end-group"
    )
    generated = compile_command + "\n" + generated_link
    validate_generated_commands(generated)
    generated_mutations = (
        (generated.replace("cc -o", "g++ -o", 1), "E_COMPILE_DRIVER"),
        (
            compile_command + "\n" + generated_link.replace("cc -o", "g++ -o"),
            "E_LINK_DRIVER",
        ),
        (generated_link, "E_COMPILE_COMMAND"),
        (generated.replace(f" {object_path} ", " missing-object.o ", 1), "E_COMPILE_OBJECT"),
    )
    for commands, code in generated_mutations:
        expect_failure(
            lambda commands=commands: validate_generated_commands(commands), code
        )

    total = len(mutations) + len(link_mutations) + len(generated_mutations)
    print(f"DuckDB Linux link dependency wiring self-test: {total} negative controls OK")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("root", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test(args.root)
        else:
            validate_sources(load_sources(args.root))
            if args.build_root is not None:
                validate_generated_commands(generated_commands(args.build_root))
            print("DuckDB Linux link dependency wiring: OK")
    except ContractError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

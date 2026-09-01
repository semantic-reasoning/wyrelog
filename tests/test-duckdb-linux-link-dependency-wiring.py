#!/usr/bin/env python3
"""Prove source DuckDB exports its Linux pure-C link closure."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Callable


PACKAGE_MESON = "subprojects/packagefiles/duckdb-amalgamated/meson.build"
TESTS_MESON = "tests/meson.build"
CONSUMER = "tests/test-duckdb-source-offbridge-c-consumer.c"
TARGET = "test-duckdb-source-offbridge-c-consumer"
NINJA_TARGET = f"tests/{TARGET}"


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

    if text.count("dependencies : duckdb_deps") != 4:
        reject(
            "E_DEPENDENCY_EXPORT",
            "regular and seam libraries/dependencies must share duckdb_deps",
        )


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


def validate_consumer(text: str) -> None:
    if "#include <duckdb.h>" not in text:
        reject("E_CONSUMER_LIFECYCLE", "consumer lacks duckdb.h")
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
        if re.search(rf"\b{function}\s*\(", text) is None:
            reject("E_CONSUMER_LIFECYCLE", f"consumer lacks {function}()")
    if "SELECT 42 AS answer" not in text:
        reject("E_CONSUMER_QUERY", "consumer must execute the sentinel query")


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
    for relative in (PACKAGE_MESON, TESTS_MESON, CONSUMER):
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
            "missing libcxx marker",
            PACKAGE_MESON,
            lambda text: replace_once(
                text, "#ifndef _LIBCPP_VERSION\n", "#if 0\n"
            ),
            "E_ABI_PROBE",
        ),
        Mutation(
            "lost dependency export",
            PACKAGE_MESON,
            lambda text: replace_once(
                text,
                "duckdb_dep = declare_dependency(\n  link_with : duckdb_lib,\n  dependencies : duckdb_deps,",
                "duckdb_dep = declare_dependency(\n  link_with : duckdb_lib,",
            ),
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

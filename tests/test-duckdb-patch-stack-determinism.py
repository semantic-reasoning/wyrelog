#!/usr/bin/env python3
"""Prove the pinned DuckDB 1.5.5 patch prefix composes deterministically."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable
from zipfile import ZipFile


ARCHIVE_SHA256 = (
    "102813201cf8072b8a56b6013978963f3c89202a148fd152d06909477e36fbf8"
)
ARCHIVE_MEMBERS = frozenset(
    ("duckdb.cpp", "duckdb.hpp", "duckdb.h", "duckdb_extension.h")
)
PATCH_DIR = "subprojects/packagefiles/duckdb-amalgamated"
PATCHES = (
    "0001-vfs-dynamic-cast.patch",
    "0002-windows-amalgamation-compat.patch",
    "0003-test-after-walstart-rendezvous.patch",
    "0004-windows-posix-rename.patch",
)
PATCH_PATHS = tuple(f"{PATCH_DIR}/{name}" for name in PATCHES)
WORKFLOWS = (
    ".github/workflows/ci-pr.yml",
    ".github/workflows/ci-main.yml",
)
EXPECTED_TRIGGER_BLOCKS = {
    ".github/workflows/ci-pr.yml": """on:
  pull_request:
    branches: [main]""" + "\n",
    ".github/workflows/ci-main.yml": """on:
  push:
    branches: [main]""" + "\n",
}
SNAPSHOT_PATHS = (
    ".gitattributes",
    "subprojects/duckdb-amalgamated.wrap",
    "tests/meson.build",
    *PATCH_PATHS,
    *WORKFLOWS,
)
SELF_TEST_TEXT_PATHS = (
    ".gitattributes",
    "subprojects/duckdb-amalgamated.wrap",
    "tests/meson.build",
    *WORKFLOWS,
)
EXPECTED_STAGE_HASHES = {
    PATCHES[0]: (
        "7c7255a94955efe0d64612998159a11805c35bc0e155214ccc8f07549606083e",
        "88a24983c3f2dd792a3bb5cfba1d6f8ed910380c892d2fdbdcfed754ee94dba6",
    ),
    PATCHES[1]: (
        "2010b41750f72bf2cbfee8cbc880f7bd5484d261d15057eb4450f388aec1d3b5",
        "88a24983c3f2dd792a3bb5cfba1d6f8ed910380c892d2fdbdcfed754ee94dba6",
    ),
    PATCHES[2]: (
        "1f1af54c146c06aa899245772ca5e9294d23fdf16924c61884226547612a4e7e",
        "f0a7d4c29dae4bfdf9cd11533d24dbdd56ed904a618680fe744b3755ca5b43a9",
    ),
    PATCHES[3]: (
        "5ec21344eda3815cbc68e33fbeec9ef02296b72be43e396730fde4cdbd0485d6",
        "f0a7d4c29dae4bfdf9cd11533d24dbdd56ed904a618680fe744b3755ca5b43a9",
    ),
}
INTERFACE_GUARD = "#ifdef interface\n#undef interface\n#endif"
EXPECTED_MESON_HEADER = """fs = import('fs')
python3 = find_program('python3')

"""
EXPECTED_MESON_BLOCK = r"""# BEGIN duckdb-patch-stack-determinism
test('duckdb-patch-stack-determinism', python3,
  args : [files('test-duckdb-patch-stack-determinism.py'),
    meson.project_source_root()])

test('duckdb-patch-stack-determinism-self-test', python3,
  args : [files('test-duckdb-patch-stack-determinism.py'),
    '--self-test', meson.project_source_root()])

if enable_secure_duckdb_bridge_opt.enabled() and \
    get_option('duckdb_source') == 'subproject'
  if host_machine.system() == 'linux' or \
      host_machine.system() == 'darwin'
    duckdb_patch_tool_name = host_machine.system() == 'darwin' ? 'gpatch' : 'patch'
    duckdb_patch_tool = find_program(duckdb_patch_tool_name, required : true)
    duckdb_patch_archive = meson.project_source_root() / \
      'subprojects/packagecache/libduckdb-src-v1.5.5.zip'
    if not fs.exists(duckdb_patch_archive)
      error('strict DuckDB patch replay requires the resolved pinned archive')
    endif
    test('duckdb-patch-stack-determinism-strict', python3,
      args : [files('test-duckdb-patch-stack-determinism.py'),
        '--strict-apply',
        '--archive', duckdb_patch_archive,
        '--gnu-patch', duckdb_patch_tool.full_path(),
        meson.project_source_root()],
      timeout : 120)
  endif
endif
# END duckdb-patch-stack-determinism"""
EXPECTED_MESON_SUFFIX = """

meson_exe = find_program('meson')"""
EXPECTED_JOB_HEADER = """  duckdb-checkpoint-seam:
    name: duckdb-checkpoint-seam-${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    timeout-minutes: 45
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
    steps:
"""
EXPECTED_BUILD_HEADERS = {
    ".github/workflows/ci-pr.yml": """  build-posix:
    name: build-${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    timeout-minutes: 45
    env:
      SCCACHE_GHA_ENABLED: "true"
      # Relativise absolute paths baked into debug info so cache entries stay
      # valid across runs even though the workspace path is fixed on hosted
      # runners; matches the Windows job.
      SCCACHE_BASEDIRS: ${{ github.workspace }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            tpm: enabled
          - os: macos-latest
            tpm: disabled
    steps:
""",
    ".github/workflows/ci-main.yml": """  build-posix:
    name: build-${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    # Fail fast on a wedged build instead of letting a hung compile burn the
    # runner's full default lease (macOS still builds DuckDB from source in
    # ~30 min, so keep comfortable headroom over that).
    timeout-minutes: 45
    env:
      SCCACHE_GHA_ENABLED: "true"
      # Relativise absolute paths baked into debug info so cache entries stay
      # valid across runs even though the workspace path is fixed on hosted
      # runners; matches the Windows job.
      SCCACHE_BASEDIRS: ${{ github.workspace }}
    strategy:
      fail-fast: false
      matrix:
        include:
          # The ordinary Linux job uses prebuilt DuckDB for runtime cost. The
          # dedicated secure-backend step below still builds the pinned source
          # and executes the real adapter on both supported POSIX runtimes.
          - os: ubuntu-latest
            tpm: enabled
            duckdb: prebuilt
          - os: macos-latest
            tpm: disabled
            duckdb: subproject
    steps:
""",
}
EXPECTED_RUNNER_STEP = """      - name: Verify GitHub-hosted runner contract
        shell: bash
        run: |
          if [ "${{ runner.environment }}" != 'github-hosted' ]; then
            echo '::error::this job requires a GitHub-hosted runner'
            exit 1
          fi
"""
EXPECTED_BUILD_LINUX_STEP = r"""      - name: Install build dependencies (Linux)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            meson ninja-build pkg-config patch time \
            libglib2.0-dev libsqlite3-dev libsoup-3.0-dev libsodium-dev \
            libtss2-dev""" + "\n"
EXPECTED_LINUX_STEP = r"""      - name: Install build dependencies (Linux)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            meson ninja-build pkg-config patch \
            libglib2.0-dev libsqlite3-dev libsoup-3.0-dev libsodium-dev
          sudo apt-get install -y --no-install-recommends time
          sudo apt-get clean""" + "\n"
EXPECTED_MACOS_STEP = """      - name: Install build dependencies (macOS)
        if: runner.os == 'macOS'
        env:
          HOMEBREW_NO_REQUIRE_TAP_TRUST: 1
        run: |
          brew update
          brew install meson ninja pkg-config glib sqlite libsoup libsodium gpatch""" + "\n"
EXPECTED_SECURE_SETUP_PREFIX = r"""      - name: Build secure DuckDB backend from pinned source
        run: |
          set -euo pipefail
          if [ "$RUNNER_OS" = Linux ]; then
            patch --version
          else
            gpatch --version
          fi | grep -F 'GNU patch'
          if [ "$RUNNER_OS" = Linux ]; then
            CC=cc CXX=c++ meson setup build-secure-duckdb \
              -Denable_fact_store=enabled \
              -Dduckdb_source=subproject \
              -Denable_secure_duckdb_bridge=enabled
          else
            meson setup build-secure-duckdb \
              -Denable_fact_store=enabled \
              -Dduckdb_source=subproject \
              -Denable_secure_duckdb_bridge=enabled
          fi""" + "\n"
EXPECTED_GATE_STEP = r"""      - name: Test focused checkpoint seam
        run: |
          meson test -C build-duckdb-seam --no-rebuild \
            duckdb-after-walstart-no-wal \
            duckdb-after-walstart-rendezvous \
            duckdb-patch-stack-determinism \
            duckdb-patch-stack-determinism-self-test \
            duckdb-patch-stack-determinism-strict \
            duckdb-fixed-wal-successful-checkpoint \
            duckdb-fixed-wal-pre-move-abort-reopen \
            duckdb-fixed-wal-interrupted-recovery \
            duckdb-after-walstart-boundary \
            duckdb-test-seam-wiring \
            duckdb-fixed-wal-lifecycle-boundary \
            --print-errorlogs""" + "\n"
EXPECTED_CACHE_STEPS = {
    ".github/workflows/ci-pr.yml": """      - name: Restore meson packagecache
        # actions/cache v5
        uses: actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25
        with:
          path: subprojects/packagecache
          key: ${{ runner.os }}-packagecache-${{ hashFiles('subprojects/*.wrap') }}
          restore-keys: |
            ${{ runner.os }}-packagecache-""" + "\n",
    ".github/workflows/ci-main.yml": """      - name: Cache meson packagecache
        # actions/cache v5
        uses: actions/cache@caa296126883cff596d87d8935842f9db880ef25
        with:
          path: subprojects/packagecache
          key: ${{ runner.os }}-packagecache-${{ hashFiles('subprojects/*.wrap') }}
          restore-keys: |
            ${{ runner.os }}-packagecache-""" + "\n",
}
EXPECTED_CHECKOUT_STEP = """      - name: Check out source
        # actions/checkout v5
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
"""
EXPECTED_BUILD_PREFIXES = {
    path: header
    + "\n".join(
        (
            EXPECTED_RUNNER_STEP,
            EXPECTED_CHECKOUT_STEP,
            EXPECTED_BUILD_LINUX_STEP,
            EXPECTED_MACOS_STEP,
        )
    )
    + "\n"
    for path, header in EXPECTED_BUILD_HEADERS.items()
}
EXPECTED_PROVISION_STEP = """      - name: Provision bounded Linux compile swap
        if: runner.os == 'Linux'
        shell: bash
        run: |
          bash .github/scripts/duckdb-compile-swap.sh provision seam
"""
EXPECTED_CONFIGURE_STEP = r"""      - name: Configure focused checkpoint seam
        run: |
          CC=cc CXX=c++ meson setup build-duckdb-seam \
            -Denable_tpm=disabled \
            -Denable_fact_store=enabled \
            -Dduckdb_source=subproject \
            -Denable_secure_duckdb_bridge=enabled
"""
EXPECTED_BUILD_STEP = r"""      - name: Build focused checkpoint seam
        shell: bash
        run: |
          set -euo pipefail
          test -z "$(find build-duckdb-seam -name libduckdb.a \
            -print -quit)"
          if [ "$RUNNER_OS" = Linux ]; then
            for target in "$RUNNER_TEMP" "$GITHUB_WORKSPACE"; do
              available="$(df -B1 --output=avail "$target" | tail -1)"
              test "$available" -ge 4000000000
            done
          fi
          if [ "$RUNNER_OS" = Linux ]; then
            /usr/bin/time -v meson compile -C build-duckdb-seam \
              -j 1 test-duckdb-after-walstart
          else
            /usr/bin/time -l meson compile -C build-duckdb-seam \
              -j 1 test-duckdb-after-walstart
          fi
          test -z "$(find build-duckdb-seam -name libduckdb.a \
            -print -quit)"
"""
EXPECTED_REPEAT_STEP = r"""      - name: Repeat fixed WAL lifecycle evidence
        run: |
          set -euo pipefail
          for iteration in 1 2 3 4 5; do
            echo "fixed WAL lifecycle iteration ${iteration}/5"
            meson test -C build-duckdb-seam --no-rebuild \
              duckdb-fixed-wal-successful-checkpoint \
              duckdb-fixed-wal-pre-move-abort-reopen \
              duckdb-fixed-wal-interrupted-recovery \
              --print-errorlogs
          done
"""
EXPECTED_REMOVE_STEP = """      - name: Remove bounded Linux compile swap
        if: ${{ runner.environment == 'github-hosted' && (always() && runner.os == 'Linux') }}
        shell: bash
        run: |
          bash .github/scripts/duckdb-compile-swap.sh cleanup seam
"""
EXPECTED_UPLOAD_STEP = """      - name: Upload seam meson logs on failure
        if: ${{ runner.environment == 'github-hosted' && (failure()) }}
        # actions/upload-artifact v6
        uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f
        with:
          name: duckdb-checkpoint-seam-logs-${{ matrix.os }}
          path: build-duckdb-seam/meson-logs/
          if-no-files-found: ignore
"""
EXPECTED_STEP_NAMES = (
    "Verify GitHub-hosted runner contract",
    "Check out source",
    "Install build dependencies (Linux)",
    "Install build dependencies (macOS)",
    "<packagecache>",
    "Provision bounded Linux compile swap",
    "Configure focused checkpoint seam",
    "Build focused checkpoint seam",
    "Test focused checkpoint seam",
    "Repeat fixed WAL lifecycle evidence",
    "Remove bounded Linux compile swap",
    "Upload seam meson logs on failure",
)
EXPECTED_BUILD_STEP_NAMES = (
    "Verify GitHub-hosted runner contract",
    "Check out source",
    "Install build dependencies (Linux)",
    "Install build dependencies (macOS)",
    "<packagecache>",
    "Set up sccache",
    "Select compiler cache",
    "Configure",
    "Build and test",
    "Verify artifact inventory consumer contract",
    "Build fact-store production daemon",
    "Provision secure DuckDB compile swap",
    "Build secure DuckDB backend from pinned source",
    "Remove secure DuckDB compile swap",
    "Show sccache statistics",
    "Upload meson logs on failure",
)
EXPECTED_PRE_PROOF_HASHES = {
    ".github/workflows/ci-pr.yml": (
        "a945595bc728d01a7a89cef07ff88356044a146c93e947eae94ec2fb71a4617f",
        "d014532fa5ad5a4d0d75b22ebd36a4b6e51843ab043724ed6b34ef9a5a157ea3",
        "c5df0cedcf83eeafa9d16421a3ff5ceb36726ac586d3a7f419d7b1f2e0561839",
        "dce3707c773f8a2ba95c87148804d6e2b3a5162379d099eab66d31b533b40e42",
        "b120f087067e39749c1fb91bb9cfae68964d8778ff9b97d11374bb13ad009318",
        "c825456336a448175b02a0338e5888c8c0d53099d2aaa9f8c6a6df7e7e82431e",
        "4533877c363341c71bb615646fda8b0f46540dad3f72f50450352372d3688409",
        "6e51525425fe4a197b0bf49e9401eb4a6f6387e3cf84972e37aa82fee34dc0f3",
        "d788fd0976e6e1a878d0359e912928961ee4fe15ea7b545855314c70c6f08373",
        "46a7d9b9533745c75e85fdf7ce7460c8cd6c881716603ff2b9e3d94e3896dd05",
        "6966b52d2e6d96ac3712b8354e443d2a3a330ff715a039089bbbc8cd510ea94b",
        "d31df101913ddab60136579dd6729e388f2287cc6930a38d078ab6d8271c2efa",
    ),
    ".github/workflows/ci-main.yml": (
        "a945595bc728d01a7a89cef07ff88356044a146c93e947eae94ec2fb71a4617f",
        "d014532fa5ad5a4d0d75b22ebd36a4b6e51843ab043724ed6b34ef9a5a157ea3",
        "c5df0cedcf83eeafa9d16421a3ff5ceb36726ac586d3a7f419d7b1f2e0561839",
        "dce3707c773f8a2ba95c87148804d6e2b3a5162379d099eab66d31b533b40e42",
        "ae43fd8a04136ea2f10a22885f3d7f703059d739257ad39e6682c07d217ae974",
        "c825456336a448175b02a0338e5888c8c0d53099d2aaa9f8c6a6df7e7e82431e",
        "4533877c363341c71bb615646fda8b0f46540dad3f72f50450352372d3688409",
        "2e1e6ace6dd96f006b3c9e59c3ec247d867ff998498f843e894f74e17bc9bec2",
        "d788fd0976e6e1a878d0359e912928961ee4fe15ea7b545855314c70c6f08373",
        "46a7d9b9533745c75e85fdf7ce7460c8cd6c881716603ff2b9e3d94e3896dd05",
        "589018250102ae9f33a3148db617b648fd02397645ca421fb4a72e80f69e74ba",
        "d31df101913ddab60136579dd6729e388f2287cc6930a38d078ab6d8271c2efa",
    ),
}
EXPECTED_JOB_PROJECTION = EXPECTED_JOB_HEADER + "\n".join(
    (
        EXPECTED_RUNNER_STEP,
        EXPECTED_CHECKOUT_STEP,
        EXPECTED_LINUX_STEP,
        EXPECTED_MACOS_STEP,
        "      - name: <packagecache>",
        EXPECTED_PROVISION_STEP,
        EXPECTED_CONFIGURE_STEP,
        EXPECTED_BUILD_STEP,
        EXPECTED_GATE_STEP,
        EXPECTED_REPEAT_STEP,
        EXPECTED_REMOVE_STEP,
        EXPECTED_UPLOAD_STEP,
    )
) + "\n"


class ContractError(RuntimeError):
    """One deterministic patch-stack invariant failed."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def fail(code: str, detail: str) -> None:
    raise ContractError(code, detail)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_utf8(data: bytes, path: str, *, universal: bool = False) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail("E_UTF8", f"{path}: {exc}")
    if universal:
        return text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def load_snapshot(root: Path) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    for relative in SNAPSHOT_PATHS:
        path = root / relative
        if not path.is_file():
            fail("E_SOURCE_FILE", f"missing required source file: {relative}")
        snapshot[relative] = path.read_bytes()
    return snapshot


def require_once(text: str, token: str, code: str, detail: str) -> None:
    if text.count(token) != 1:
        fail(code, detail)


def validate_attributes(snapshot: dict[str, bytes]) -> None:
    attributes = decode_utf8(
        snapshot[".gitattributes"], ".gitattributes", universal=True
    )
    logical = [line for line in attributes.splitlines() if line.strip()]
    expected = (
        "subprojects/packagefiles/duckdb-amalgamated/"
        "000[1-4]-*.patch text eol=lf"
    )
    if logical != [expected]:
        fail("E_ATTR_RULE", "historical DuckDB patches need the exact LF rule")


def validate_patch_bytes(snapshot: dict[str, bytes]) -> None:
    for relative in PATCH_PATHS:
        data = snapshot[relative]
        if b"\r" in data:
            fail("E_PATCH_CRLF", f"CR byte in {relative}")
    for relative in PATCH_PATHS[1:3]:
        for line_number, line in enumerate(snapshot[relative].splitlines(), 1):
            if line.endswith((b" ", b"\t")):
                fail(
                    "E_PATCH_TRAILING_WS",
                    f"trailing whitespace in {relative}:{line_number}",
                )


def validate_patch_order(snapshot: dict[str, bytes]) -> None:
    wrap = decode_utf8(
        snapshot["subprojects/duckdb-amalgamated.wrap"],
        "subprojects/duckdb-amalgamated.wrap",
    )
    require_once(
        wrap,
        f"source_hash = {ARCHIVE_SHA256}",
        "E_ARCHIVE_PIN",
        "DuckDB archive SHA pin drifted",
    )
    expected = "diff_files = " + ", ".join(
        f"duckdb-amalgamated/{name}" for name in PATCHES
    )
    require_once(
        wrap,
        expected,
        "E_PATCH_ORDER",
        "historical patch order must be exact",
    )


def validate_patch_semantics(snapshot: dict[str, bytes]) -> None:
    patch2 = decode_utf8(snapshot[PATCH_PATHS[1]], PATCH_PATHS[1])
    patch3 = decode_utf8(snapshot[PATCH_PATHS[2]], PATCH_PATHS[2])
    added_guard = "+#ifdef interface\n+#undef interface\n+#endif"
    if patch2.count(added_guard) != 6:
        fail("E_INTERFACE_GUARD_COUNT", "0002 must add exactly six guards")
    mbedtls_anchor = (
        " #include <string.h>\n"
        "-\n"
        "+\n"
        " #if defined(_WIN32)\n"
        " #include <windows.h>\n"
        "+#ifdef interface\n"
        "+#undef interface\n"
        "+#endif\n"
        " #endif\n"
        "-\n"
        "+\n"
        " // Detect platforms known to support explicit_bzero()"
    )
    if patch2.count(mbedtls_anchor) != 1:
        fail(
            "E_MBEDTLS_ANCHOR",
            "mbedtls zeroize guard must retain both unique boundaries",
        )
    option_anchor = (
        "+#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START\n"
        "+\t//! Wyrelog's source-pinned test seam. This field is absent from regular\n"
        "+\t//! DuckDB builds and is not a SQL- or user-visible checkpoint control."
    )
    callback_anchor = (
        "+\tauto has_wal = storage_manager.WALStartCheckpoint(meta_block, options);\n"
        "+\n"
        "+#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START\n"
        "+\tauto &test_options = DBConfig::GetConfig(db.GetDatabase()).options;\n"
        "+\tif (has_wal && test_options.test_after_wal_start) {\n"
        "+\t\ttest_options.test_after_wal_start(\"AFTER_WAL_START\", "
        "test_options.test_after_wal_start_context);"
    )
    if patch3.count(option_anchor) != 1 or patch3.count(callback_anchor) != 1:
        fail(
            "E_AFTER_WAL_ANCHOR",
            "AFTER_WAL_START fields and callback boundary must be unique",
        )
    if patch3.count("+#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START") != 2:
        fail("E_AFTER_WAL_SCOPE", "test seam must have exactly two compile guards")


def extract_top_level_job(workflow: str, name: str) -> str:
    marker = f"  {name}:\n"
    start = workflow.find(marker)
    if start < 0 or workflow.find(marker, start + 1) >= 0:
        fail("E_CI_JOB", f"focused job {name} must occur exactly once")
    next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", workflow[start + len(marker):])
    if next_job is None:
        return workflow[start:]
    end = start + len(marker) + next_job.start()
    return workflow[start:end]


def extract_named_step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = job.find(marker)
    if start < 0 or job.find(marker, start + 1) >= 0:
        fail("E_CI_STEP", f"step {name} must occur exactly once")
    next_step = job.find("\n      - name: ", start + len(marker))
    return job[start:] if next_step < 0 else job[start:next_step]


def validate_workflow_trigger(workflow: str, path: str) -> None:
    if len(re.findall(r"(?m)^on:\s*$", workflow)) != 1:
        fail("E_CI_TRIGGER", f"{path}: workflow must have exactly one on block")
    start = workflow.index("on:\n")
    end = workflow.find("\npermissions:\n", start)
    if end < 0 or workflow[start:end] != EXPECTED_TRIGGER_BLOCKS[path]:
        fail("E_CI_TRIGGER", f"{path}: automatic branch trigger drifted")


def validate_build_patch_tools(workflow: str, path: str) -> None:
    job = extract_top_level_job(workflow, "build-posix")
    cache_name = (
        "Restore meson packagecache"
        if path.endswith("ci-pr.yml")
        else "Cache meson packagecache"
    )
    step_mappings = tuple(re.findall(r"(?m)^      - (.+)$", job))
    if any(not mapping.startswith("name: ") for mapping in step_mappings):
        fail("E_CI_STEP_MAPPING", f"{path}: build-posix has an unnamed step")
    step_names = tuple(
        mapping.removeprefix("name: ") for mapping in step_mappings
    )
    actual_steps = tuple(
        "<packagecache>" if name == cache_name else name
        for name in step_names
    )
    if actual_steps != EXPECTED_BUILD_STEP_NAMES:
        fail("E_CI_STEP_ORDER", f"{path}: build-posix step inventory drifted")
    linux = extract_named_step(job, "Install build dependencies (Linux)")
    macos = extract_named_step(job, "Install build dependencies (macOS)")
    if linux != EXPECTED_BUILD_LINUX_STEP or macos != EXPECTED_MACOS_STEP:
        fail("E_CI_TOOL", f"{path}: build job GNU patch install steps drifted")
    if not job.startswith(EXPECTED_BUILD_PREFIXES[path]):
        fail("E_CI_STEP_ORDER", f"{path}: build-posix prerequisite prefix drifted")
    secure_index = step_names.index("Build secure DuckDB backend from pinned source")
    pre_proof_hashes = tuple(
        hashlib.sha256(extract_named_step(job, name).encode("utf-8")).hexdigest()
        for name in step_names[:secure_index]
    )
    if pre_proof_hashes != EXPECTED_PRE_PROOF_HASHES[path]:
        fail(
            "E_CI_EXEC_PROVENANCE",
            f"{path}: a pre-proof step can change executable provenance",
        )
    secure = extract_named_step(job, "Build secure DuckDB backend from pinned source")
    if not secure.startswith(EXPECTED_SECURE_SETUP_PREFIX):
        fail("E_CI_TOOL_USE", f"{path}: GNU patch point-of-use proof drifted")


def workflow_projection(workflow: str, path: str) -> str:
    validate_workflow_trigger(workflow, path)
    validate_build_patch_tools(workflow, path)
    job = extract_top_level_job(workflow, "duckdb-checkpoint-seam")
    if "os: [ubuntu-latest, macos-latest]" not in job:
        fail("E_CI_MATRIX", f"{path}: Linux/macOS matrix drifted")
    forbidden = (
        "continue-on-error:",
        "if: false",
        "if: ${{ false }}",
        "|| true",
        "; true",
        "shell: cmd",
        "shell: powershell",
        "shell: bash -n",
        "\n          exit 0\n",
    )
    for token in forbidden:
        if token in job:
            fail("E_CI_MASKING", f"{path}: forbidden masking token {token}")
    if re.search(r"(?mi)^\s*if:\s*\$\{\{\s*false\b", job):
        fail("E_CI_MASKING", f"{path}: statically false workflow condition")

    header_end = job.find("    steps:\n")
    if header_end < 0:
        fail("E_CI_JOB", f"{path}: focused job has no steps boundary")
    header = job[: header_end + len("    steps:\n")]
    if header != EXPECTED_JOB_HEADER:
        fail("E_CI_JOB", f"{path}: focused job header drifted")

    actual_steps = list(re.findall(r"(?m)^      - name: (.+)$", job))
    cache_name = (
        "Restore meson packagecache"
        if path.endswith("ci-pr.yml")
        else "Cache meson packagecache"
    )
    actual_steps = [
        "<packagecache>" if name == cache_name else name
        for name in actual_steps
    ]
    if tuple(actual_steps) != EXPECTED_STEP_NAMES:
        fail("E_CI_STEP_ORDER", f"{path}: focused step inventory drifted")

    linux = extract_named_step(job, "Install build dependencies (Linux)")
    macos = extract_named_step(job, "Install build dependencies (macOS)")
    gate = extract_named_step(job, "Test focused checkpoint seam")
    if linux != EXPECTED_LINUX_STEP or macos != EXPECTED_MACOS_STEP:
        fail("E_CI_TOOL", f"{path}: exact GNU patch install steps drifted")
    if gate != EXPECTED_GATE_STEP:
        fail("E_CI_GATES", f"{path}: exact focused gate step drifted")

    cache = extract_named_step(job, cache_name)
    if cache != EXPECTED_CACHE_STEPS[path]:
        fail("E_CI_CACHE", f"{path}: packagecache step drifted")
    projection = job.replace(cache, "      - name: <packagecache>")
    if projection != EXPECTED_JOB_PROJECTION:
        fail("E_CI_JOB_BLOCK", f"{path}: exact focused job body drifted")
    return projection


def validate_meson(snapshot: dict[str, bytes]) -> None:
    meson = decode_utf8(
        snapshot["tests/meson.build"], "tests/meson.build", universal=True
    )
    names = (
        "duckdb-patch-stack-determinism",
        "duckdb-patch-stack-determinism-self-test",
        "duckdb-patch-stack-determinism-strict",
    )
    for name in names:
        if meson.count(f"test('{name}'") != 1:
            fail("E_MESON_REGISTRATION", f"Meson registration drifted: {name}")
    if meson.count("# BEGIN duckdb-patch-stack-determinism") != 1 or \
            meson.count("# END duckdb-patch-stack-determinism") != 1:
        fail("E_MESON_BLOCK", "Meson gate sentinels must be unique")
    start = meson.index("# BEGIN duckdb-patch-stack-determinism")
    end = meson.index("# END duckdb-patch-stack-determinism") + len(
        "# END duckdb-patch-stack-determinism"
    )
    if start != len(EXPECTED_MESON_HEADER):
        fail("E_MESON_REACHABILITY", "Meson verifier header drifted")
    if meson[start:end] != EXPECTED_MESON_BLOCK:
        fail("E_MESON_BLOCK", "exact Meson verifier registrations drifted")
    expected_prefix = (
        EXPECTED_MESON_HEADER + EXPECTED_MESON_BLOCK + EXPECTED_MESON_SUFFIX
    )
    if not meson.startswith(expected_prefix):
        fail("E_MESON_REACHABILITY", "Meson verifier prefix drifted")


def validate_workflows(snapshot: dict[str, bytes]) -> None:
    projections = []
    for relative in WORKFLOWS:
        workflow = decode_utf8(snapshot[relative], relative, universal=True)
        projections.append(workflow_projection(workflow, relative))
    if projections[0] != projections[1]:
        fail("E_CI_PARITY", "PR and main focused patch gates diverged")


def validate_structural(snapshot: dict[str, bytes]) -> None:
    validate_attributes(snapshot)
    validate_patch_bytes(snapshot)
    validate_patch_order(snapshot)
    validate_patch_semantics(snapshot)
    validate_meson(snapshot)
    validate_workflows(snapshot)


@dataclass(frozen=True)
class PatchRun:
    returncode: int
    output: str


def run_patch_process(
    tool: Path, directory: Path, patch_file: Path, fuzz: int
) -> PatchRun:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    completed = subprocess.run(
        [
            str(tool),
            "--batch",
            f"--fuzz={fuzz}",
            "-p1",
            "-i",
            str(patch_file),
        ],
        cwd=directory,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
    )
    return PatchRun(completed.returncode, completed.stdout)


def classify_patch_result(result: PatchRun, stage: str) -> None:
    if re.search(r"\bfuzz(?:ed)?\b", result.output, re.IGNORECASE):
        fail("E_PATCH_FUZZ", f"{stage}: GNU patch reported fuzz")
    if re.search(r"\boffset\b", result.output, re.IGNORECASE):
        fail("E_PATCH_OFFSET", f"{stage}: GNU patch reported an offset")
    if result.returncode != 0:
        tail = result.output.strip().splitlines()[-1:] or ["no output"]
        fail("E_PATCH_APPLY", f"{stage}: status {result.returncode}: {tail[0]}")


def check_artifacts(directory: Path, stage: str) -> None:
    artifacts = sorted(
        str(path.relative_to(directory))
        for path in directory.rglob("*")
        if path.is_file() and path.suffix in (".orig", ".rej")
    )
    if artifacts:
        fail("E_PATCH_ARTIFACT", f"{stage}: unexpected {', '.join(artifacts)}")


def verify_gnu_patch(tool: Path) -> None:
    if not tool.is_absolute() or not tool.is_file():
        fail("E_PATCH_TOOL", "--gnu-patch must be an existing absolute path")
    completed = subprocess.run(
        [str(tool), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
    )
    if completed.returncode != 0 or "GNU patch" not in completed.stdout:
        fail("E_PATCH_TOOL", "strict replay requires GNU patch")


def verify_archive_hash(archive: Path) -> None:
    if not archive.is_file() or sha256_path(archive) != ARCHIVE_SHA256:
        fail("E_ARCHIVE_HASH", "DuckDB archive SHA-256 mismatch")


def checked_zip_members(archive: Path) -> list[tuple[object, str]]:
    checked: list[tuple[object, str]] = []
    seen: set[str] = set()
    with ZipFile(archive) as bundle:
        for info in bundle.infolist():
            name = info.filename.replace("\\", "/")
            pure = PurePosixPath(name)
            if (
                not name
                or name.startswith("/")
                or re.match(r"^[A-Za-z]:", name)
                or ".." in pure.parts
                or pure.is_absolute()
            ):
                fail("E_ARCHIVE_MEMBER", f"unsafe ZIP member: {info.filename}")
            normalized = str(pure)
            if normalized in seen:
                fail("E_ARCHIVE_MEMBER", f"duplicate ZIP member: {normalized}")
            seen.add(normalized)
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if info.is_dir() or kind not in (0, stat.S_IFREG):
                fail("E_ARCHIVE_MEMBER", f"unsupported ZIP member: {normalized}")
            checked.append((info, normalized))
    if seen != ARCHIVE_MEMBERS:
        fail("E_ARCHIVE_MEMBER", "DuckDB archive member inventory drifted")
    return checked


def extract_checked_archive(archive: Path, destination: Path) -> None:
    members = checked_zip_members(archive)
    with ZipFile(archive) as bundle:
        for info, normalized in members:
            target = destination / normalized
            with bundle.open(info, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)


def check_stage_hashes(directory: Path, stage: str) -> None:
    expected_cpp, expected_hpp = EXPECTED_STAGE_HASHES[stage]
    actual = (sha256_path(directory / "duckdb.cpp"), sha256_path(directory / "duckdb.hpp"))
    if actual != (expected_cpp, expected_hpp):
        fail(
            "E_COMPOSED_HASH",
            f"{stage}: composed source hash drifted: {actual[0]} {actual[1]}",
        )


def validate_composed_semantics(directory: Path) -> None:
    cpp = (directory / "duckdb.cpp").read_text(encoding="utf-8")
    hpp = (directory / "duckdb.hpp").read_text(encoding="utf-8")
    if cpp.count(INTERFACE_GUARD) != 6:
        fail("E_COMPOSED_INTERFACE", "composed source needs six interface guards")
    neighborhoods = (
        "#undef CreateDirectory\n" + INTERFACE_GUARD + "\n\n#undef MoveFile",
        "#include <windows.h>\n" + INTERFACE_GUARD + "\n#elif defined(__GNUC__)",
        "#include <windows.h>\n" + INTERFACE_GUARD + "\n#if defined(WINVER)",
        "#include <string.h>\n\n#if defined(_WIN32)\n#include <windows.h>\n"
        + INTERFACE_GUARD
        + "\n#endif\n\n// Detect platforms known to support explicit_bzero()",
        "#include <windows.h>\n" + INTERFACE_GUARD + "\nmbedtls_ms_time_t mbedtls_ms_time",
        "#include <windows.h>\n" + INTERFACE_GUARD + "\n#undef ERROR\n#define ERROR(name)",
    )
    for neighborhood in neighborhoods:
        if cpp.count(neighborhood) != 1:
            fail("E_COMPOSED_INTERFACE", "an intended interface site drifted")
    option_fields = (
        "#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START\n"
        "\t//! Wyrelog's source-pinned test seam. This field is absent from regular\n"
        "\t//! DuckDB builds and is not a SQL- or user-visible checkpoint control.\n"
        "\tusing after_wal_start_callback_t = void (*)(const char *phase, void *context);\n"
        "\tafter_wal_start_callback_t test_after_wal_start = nullptr;\n"
        "\tvoid *test_after_wal_start_context = nullptr;\n"
        "#endif"
    )
    callback = (
        "auto has_wal = storage_manager.WALStartCheckpoint(meta_block, options);\n\n"
        "#ifdef WYL_DUCKDB_TEST_AFTER_WAL_START\n"
        "\tauto &test_options = DBConfig::GetConfig(db.GetDatabase()).options;\n"
        "\tif (has_wal && test_options.test_after_wal_start) {\n"
        "\t\ttest_options.test_after_wal_start(\"AFTER_WAL_START\", "
        "test_options.test_after_wal_start_context);\n"
        "\t}\n#endif\n\n\tcatalog_entry_vector_t catalog_entries;"
    )
    if hpp.count(option_fields) != 1 or cpp.count(callback) != 1:
        fail("E_COMPOSED_AFTER_WAL", "composed AFTER_WAL_START seam drifted")


def strict_replay(root: Path, archive: Path, tool: Path) -> None:
    verify_archive_hash(archive)
    verify_gnu_patch(tool)
    with tempfile.TemporaryDirectory(prefix="wyrelog-duckdb-patches-") as temporary:
        source = Path(temporary)
        extract_checked_archive(archive, source)
        for stage, relative in zip(PATCHES, PATCH_PATHS):
            result = run_patch_process(tool, source, root / relative, 0)
            classify_patch_result(result, stage)
            check_artifacts(source, stage)
            check_stage_hashes(source, stage)
        validate_composed_semantics(source)


def expect_error(operation: Callable[[], None], expected: str) -> None:
    try:
        operation()
    except ContractError as exc:
        if exc.code != expected:
            fail("E_SELF_TEST", f"expected {expected}, received {exc.code}")
    else:
        fail("E_SELF_TEST", f"mutation did not trigger {expected}")


def mutated(
    snapshot: dict[str, bytes], relative: str, transform: Callable[[bytes], bytes]
) -> dict[str, bytes]:
    result = dict(snapshot)
    result[relative] = transform(result[relative])
    return result


def replace_once(data: bytes, old: bytes, new: bytes) -> bytes:
    if data.count(old) != 1:
        fail("E_SELF_TEST", f"fixture token count drifted: {old!r}")
    return data.replace(old, new, 1)


def replace_in_job(data: bytes, job_name: bytes, old: bytes, new: bytes) -> bytes:
    marker = b"  " + job_name + b":\n"
    start = data.find(marker)
    if start < 0:
        fail("E_SELF_TEST", "focused workflow job fixture is missing")
    match = re.search(rb"(?m)^  [A-Za-z0-9_-]+:\n", data[start + len(marker):])
    end = len(data) if match is None else start + len(marker) + match.start()
    job = data[start:end]
    if job.count(old) != 1:
        fail("E_SELF_TEST", f"{job_name!r} job token count drifted: {old!r}")
    return data[:start] + job.replace(old, new, 1) + data[end:]


def replace_in_focused_job(data: bytes, old: bytes, new: bytes) -> bytes:
    return replace_in_job(data, b"duckdb-checkpoint-seam", old, new)


def move_build_install_steps_after_configure(data: bytes) -> bytes:
    workflow = data.decode("utf-8")
    job = extract_top_level_job(workflow, "build-posix")
    linux = extract_named_step(job, "Install build dependencies (Linux)")
    macos = extract_named_step(job, "Install build dependencies (macOS)")
    configure = extract_named_step(job, "Configure")
    moved = job.replace(linux + "\n", "", 1).replace(macos + "\n", "", 1)
    moved = moved.replace(
        configure,
        configure + "\n" + linux + "\n" + macos,
        1,
    )
    if moved == job:
        fail("E_SELF_TEST", "build-posix install movement fixture drifted")
    return data.replace(job.encode("utf-8"), moved.encode("utf-8"), 1)


def move_patch_proof_after_secure_setup(data: bytes) -> bytes:
    proof = (
        b'          if [ "$RUNNER_OS" = Linux ]; then\n'
        b"            patch --version\n"
        b"          else\n"
        b"            gpatch --version\n"
        b"          fi | grep -F 'GNU patch'\n"
    )
    workflow = data.decode("utf-8")
    job = extract_top_level_job(workflow, "build-posix").encode("utf-8")
    secure_marker = b"      - name: Build secure DuckDB backend from pinned source\n"
    secure_start = job.find(secure_marker)
    secure_end = job.find(b"\n      - name: ", secure_start + len(secure_marker))
    if secure_start < 0 or secure_end < 0:
        fail("E_SELF_TEST", "secure build movement fixture drifted")
    secure = job[secure_start:secure_end]
    if secure.count(proof) != 1:
        fail("E_SELF_TEST", "GNU patch proof fixture drifted")
    moved = secure.replace(proof, b"", 1)
    setup_end = b"          fi\n"
    if moved.count(setup_end) < 1:
        fail("E_SELF_TEST", "secure setup boundary fixture drifted")
    moved = moved.replace(setup_end, setup_end + proof, 1)
    return data.replace(secure, moved, 1)


def mutate_both_workflows(
    snapshot: dict[str, bytes], old: bytes, new: bytes
) -> dict[str, bytes]:
    result = dict(snapshot)
    for relative in WORKFLOWS:
        result[relative] = replace_in_focused_job(result[relative], old, new)
    return result


def real_fuzz_probe(tool: Path) -> None:
    patch_text = (
        "diff --git a/sample.txt b/sample.txt\n"
        "--- a/sample.txt\n"
        "+++ b/sample.txt\n"
        "@@ -1,5 +1,5 @@\n"
        " expected-first\n"
        " stable-before\n"
        "-old\n"
        "+new\n"
        " stable-after\n"
        " expected-last\n"
    )
    source_text = "actual-first\nstable-before\nold\nstable-after\nactual-last\n"
    with tempfile.TemporaryDirectory(prefix="wyrelog-fuzz-zero-") as first:
        directory = Path(first)
        (directory / "sample.txt").write_text(source_text, encoding="utf-8")
        patch_file = directory / "probe.patch"
        patch_file.write_text(patch_text, encoding="utf-8")
        result = run_patch_process(tool, directory, patch_file, 0)
        expect_error(lambda: classify_patch_result(result, "fuzz-zero"), "E_PATCH_APPLY")
    with tempfile.TemporaryDirectory(prefix="wyrelog-fuzz-one-") as second:
        directory = Path(second)
        (directory / "sample.txt").write_text(source_text, encoding="utf-8")
        patch_file = directory / "probe.patch"
        patch_file.write_text(patch_text, encoding="utf-8")
        result = run_patch_process(tool, directory, patch_file, 1)
        if result.returncode != 0:
            fail("E_SELF_TEST", "GNU patch fuzz fixture did not apply with fuzz 1")
        expect_error(lambda: classify_patch_result(result, "fuzz-one"), "E_PATCH_FUZZ")


def normalize_self_test_snapshot(snapshot: dict[str, bytes]) -> dict[str, bytes]:
    normalized = dict(snapshot)
    for relative in SELF_TEST_TEXT_PATHS:
        normalized[relative] = decode_utf8(
            normalized[relative], relative, universal=True
        ).encode("utf-8")
    return normalized


def crlf_self_test_snapshot(snapshot: dict[str, bytes]) -> dict[str, bytes]:
    windows = normalize_self_test_snapshot(snapshot)
    for relative in SELF_TEST_TEXT_PATHS:
        windows[relative] = windows[relative].replace(b"\n", b"\r\n")
    return windows


def run_self_tests(
    root: Path, snapshot: dict[str, bytes], *, exercise_crlf: bool = True
) -> None:
    validate_structural(snapshot)
    raw_snapshot = snapshot
    snapshot = normalize_self_test_snapshot(snapshot)
    validate_structural(snapshot)
    cases: tuple[tuple[str, dict[str, bytes]], ...] = (
        (
            "E_ATTR_RULE",
            mutated(snapshot, ".gitattributes", lambda data: data.replace(b"000[1-4]", b"*")),
        ),
        (
            "E_PATCH_ORDER",
            mutated(
                snapshot,
                "subprojects/duckdb-amalgamated.wrap",
                lambda data: replace_once(data, b"0002-windows", b"0092-windows"),
            ),
        ),
        (
            "E_PATCH_CRLF",
            mutated(snapshot, PATCH_PATHS[0], lambda data: data.replace(b"\n", b"\r\n", 1)),
        ),
        (
            "E_PATCH_TRAILING_WS",
            mutated(snapshot, PATCH_PATHS[1], lambda data: data.replace(b"\n", b" \n", 1)),
        ),
        (
            "E_INTERFACE_GUARD_COUNT",
            mutated(
                snapshot,
                PATCH_PATHS[1],
                lambda data: data + b"+#ifdef interface\n+#undef interface\n+#endif\n",
            ),
        ),
        (
            "E_MBEDTLS_ANCHOR",
            mutated(
                snapshot,
                PATCH_PATHS[1],
                lambda data: replace_once(
                    data,
                    b" // Detect platforms known to support explicit_bzero()",
                    b" // moved platform boundary",
                ),
            ),
        ),
        (
            "E_AFTER_WAL_ANCHOR",
            mutated(
                snapshot,
                PATCH_PATHS[2],
                lambda data: replace_once(data, b'"AFTER_WAL_START"', b'"MOVED"'),
            ),
        ),
        (
            "E_MESON_REGISTRATION",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"test('duckdb-patch-stack-determinism-self-test'",
                    b"test('duckdb-patch-stack-self-test'",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"# BEGIN duckdb-patch-stack-determinism",
                    b"if false or false\n# BEGIN duckdb-patch-stack-determinism",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')\n\n",
                    b"foreach python3 : [find_program('true')]\n"
                    b"endforeach\n"
                    b"python3 = find_program('python3')\n\n",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')\n\n",
                    b"foreach ignored, python3 : "
                    b"{'ignored': find_program('true')}\n"
                    b"endforeach\n"
                    b"python3 = find_program('python3')\n\n",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')\n\n",
                    b"set_variable('python' + '3', find_program('true'))\n"
                    b"python3 = find_program('python3')\n\n",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')\n\n",
                    b"set_variable('python@0@'.format('3'), "
                    b"find_program('true'))\n"
                    b"python3 = find_program('python3')\n\n",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')",
                    b"python3 \\\n"
                    b"  = find_program('true')",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')\n\n",
                    b"subdir_done \\\n"
                    b"  ()\n"
                    b"python3 = find_program('python3')\n\n",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"# BEGIN duckdb-patch-stack-determinism",
                    b"subdir_done()\n# BEGIN duckdb-patch-stack-determinism",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')\n\n",
                    b"meson_alias = meson\n"
                    b"meson_alias.override_find_program('python3', "
                    b"find_program('true'))\n"
                    b"python3 = find_program('python3')\n\n",
                ),
            ),
        ),
        (
            "E_MESON_REACHABILITY",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"python3 = find_program('python3')",
                    b"python3 = find_program('true')",
                ),
            ),
        ),
        (
            "E_MESON_BLOCK",
            mutated(
                snapshot,
                "tests/meson.build",
                lambda data: replace_once(
                    data,
                    b"test('duckdb-patch-stack-determinism', python3,",
                    b"test('duckdb-patch-stack-determinism', find_program('true'),",
                ),
            ),
        ),
        (
            "E_CI_TRIGGER",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_once(
                    data,
                    b"on:\n  pull_request:\n    branches: [main]",
                    b"on:\n  workflow_dispatch:",
                ),
            ),
        ),
        (
            "E_CI_TRIGGER",
            mutated(
                snapshot,
                WORKFLOWS[1],
                lambda data: replace_once(
                    data,
                    b"on:\n  push:\n    branches: [main]",
                    b"on:\n  workflow_dispatch:",
                ),
            ),
        ),
        (
            "E_CI_STEP_ORDER",
            mutated(
                snapshot,
                WORKFLOWS[0],
                move_build_install_steps_after_configure,
            ),
        ),
        (
            "E_CI_STEP_MAPPING",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"      - name: Install build dependencies (Linux)\n",
                    b"      - run: meson setup build-too-early "
                    b"-Dduckdb_source=subproject\n\n"
                    b"      - name: Install build dependencies (Linux)\n",
                ),
            ),
        ),
        (
            "E_CI_STEP_MAPPING",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"      - name: Install build dependencies (Linux)\n",
                    b"      - uses: actions/checkout@decoy\n\n"
                    b"      - name: Install build dependencies (Linux)\n",
                ),
            ),
        ),
        (
            "E_CI_STEP_MAPPING",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"      - name: Install build dependencies (Linux)\n",
                    b"      - if: runner.os == 'Linux'\n"
                    b"        run: meson setup build-too-early\n\n"
                    b"      - name: Install build dependencies (Linux)\n",
                ),
            ),
        ),
        (
            "E_CI_STEP_ORDER",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"      - name: Install build dependencies (Linux)\n",
                    b"      - name: Configure too early\n"
                    b"        run: meson setup build-too-early\n\n"
                    b"      - name: Install build dependencies (Linux)\n",
                ),
            ),
        ),
        (
            "E_CI_EXEC_PROVENANCE",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"      - name: Select compiler cache\n"
                    b"        shell: bash\n"
                    b"        run: |\n",
                    b"      - name: Select compiler cache\n"
                    b"        shell: bash\n"
                    b"        run: |\n"
                    b"          mkdir -p \"$RUNNER_TEMP/tool-shadow\"\n"
                    b"          printf '#!/bin/sh\\necho GNU patch 9.9\\n' > "
                    b"\"$RUNNER_TEMP/tool-shadow/gpatch\"\n"
                    b"          chmod +x \"$RUNNER_TEMP/tool-shadow/gpatch\"\n"
                    b"          echo \"$RUNNER_TEMP/tool-shadow\" >> \"$GITHUB_PATH\"\n",
                ),
            ),
        ),
        (
            "E_CI_TOOL",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"brew install meson ninja pkg-config glib sqlite "
                    b"libsoup libsodium gpatch",
                    b"brew install meson ninja pkg-config glib sqlite "
                    b"libsoup libsodium",
                ),
            ),
        ),
        (
            "E_CI_TOOL",
            mutated(
                snapshot,
                WORKFLOWS[1],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"meson ninja-build pkg-config patch time",
                    b"meson ninja-build pkg-config time",
                ),
            ),
        ),
        (
            "E_CI_TOOL_USE",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b'          if [ "$RUNNER_OS" = Linux ]; then\n'
                    b"            patch --version\n"
                    b"          else\n"
                    b"            gpatch --version\n"
                    b"          fi | grep -F 'GNU patch'\n",
                    b"",
                ),
            ),
        ),
        (
            "E_CI_TOOL_USE",
            mutated(
                snapshot,
                WORKFLOWS[0],
                move_patch_proof_after_secure_setup,
            ),
        ),
        (
            "E_CI_TOOL_USE",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"            gpatch --version\n",
                    b"            patch --version\n",
                ),
            ),
        ),
        (
            "E_CI_TOOL_USE",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"          fi | grep -F 'GNU patch'\n",
                    b"          fi | grep -F 'GNU patch' || true\n",
                ),
            ),
        ),
        (
            "E_CI_TOOL_USE",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_job(
                    data,
                    b"build-posix",
                    b"          set -euo pipefail\n",
                    b"          set -euo pipefail\n"
                    b"          PATH=/untrusted:$PATH\n",
                ),
            ),
        ),
        (
            "E_CI_MATRIX",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_focused_job(
                    data,
                    b"os: [ubuntu-latest, macos-latest]",
                    b"os: [ubuntu-latest]",
                ),
            ),
        ),
        (
            "E_CI_MASKING",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_focused_job(
                    data,
                    b"    timeout-minutes: 45\n",
                    b"    timeout-minutes: 45\n    continue-on-error: true\n",
                ),
            ),
        ),
        (
            "E_CI_MASKING",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_focused_job(
                    data,
                    b"    name: duckdb-checkpoint-seam-${{ matrix.os }}\n",
                    b"    name: duckdb-checkpoint-seam-${{ matrix.os }}\n"
                    b"    if: ${{ false && true }}\n",
                ),
            ),
        ),
        (
            "E_CI_MASKING",
            mutate_both_workflows(
                snapshot,
                b"      - name: Test focused checkpoint seam\n"
                b"        run: |\n",
                b"      - name: Test focused checkpoint seam\n"
                b"        if: ${{ false && true }}\n"
                b"        run: |\n",
            ),
        ),
        (
            "E_CI_MASKING",
            mutate_both_workflows(
                snapshot,
                b"      - name: Test focused checkpoint seam\n"
                b"        run: |\n",
                b"      - name: Test focused checkpoint seam\n"
                b"        shell: bash -n {0}\n"
                b"        run: |\n",
            ),
        ),
        (
            "E_CI_MASKING",
            mutate_both_workflows(
                snapshot,
                b"        run: |\n"
                b"          meson test -C build-duckdb-seam --no-rebuild \\\n",
                b"        run: |\n"
                b"          exit 0\n"
                b"          meson test -C build-duckdb-seam --no-rebuild \\\n",
            ),
        ),
        (
            "E_CI_STEP_ORDER",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_focused_job(
                    data,
                    b"      - name: Test focused checkpoint seam\n",
                    b"      - name: Unexpected pre-gate decoy\n"
                    b"        run: echo decoy\n\n"
                    b"      - name: Test focused checkpoint seam\n",
                ),
            ),
        ),
        (
            "E_CI_JOB_BLOCK",
            mutate_both_workflows(
                snapshot,
                b"      - name: Build focused checkpoint seam\n"
                b"        shell: bash\n"
                b"        run: |\n"
                b"          set -euo pipefail\n",
                b"      - name: Build focused checkpoint seam\n"
                b"        shell: bash\n"
                b"        run: |\n"
                b"          set -euo pipefail\n"
                b"          printf 'raise SystemExit(0)\\n' > "
                b"tests/test-duckdb-patch-stack-determinism.py\n",
            ),
        ),
        (
            "E_CI_JOB_BLOCK",
            mutate_both_workflows(
                snapshot,
                b"      - name: Test focused checkpoint seam\n",
                b"      - run: |\n"
                b"          printf 'raise SystemExit(0)\\n' > "
                b"tests/test-duckdb-patch-stack-determinism.py\n\n"
                b"      - name: Test focused checkpoint seam\n",
            ),
        ),
        (
            "E_CI_GATES",
            mutated(
                snapshot,
                WORKFLOWS[0],
                lambda data: replace_in_focused_job(
                    data,
                    b"duckdb-patch-stack-determinism-strict",
                    b"duckdb-patch-stack-strict",
                ),
            ),
        ),
        (
            "E_CI_JOB_BLOCK",
            mutated(
                snapshot,
                WORKFLOWS[1],
                lambda data: replace_in_focused_job(
                    data,
                    b'            echo "fixed WAL lifecycle iteration ${iteration}/5"\n',
                    b'            echo "fixed WAL lifecycle iteration ${iteration}/5"\n'
                    b"            echo parity-drift\n",
                ),
            ),
        ),
    )
    for expected, candidate in cases:
        validate_structural(snapshot)
        expect_error(lambda candidate=candidate: validate_structural(candidate), expected)

    expect_error(
        lambda: classify_patch_result(PatchRun(0, "Hunk #1 succeeded with fuzz 1"), "probe"),
        "E_PATCH_FUZZ",
    )
    expect_error(
        lambda: classify_patch_result(PatchRun(0, "Hunk #1 succeeded (offset 2 lines)"), "probe"),
        "E_PATCH_OFFSET",
    )
    for suffix in (".orig", ".rej"):
        with tempfile.TemporaryDirectory(prefix="wyrelog-artifact-probe-") as temporary:
            artifact = Path(temporary) / f"duckdb.cpp{suffix}"
            artifact.write_bytes(b"unexpected")
            expect_error(
                lambda temporary=temporary: check_artifacts(Path(temporary), "probe"),
                "E_PATCH_ARTIFACT",
            )
    with tempfile.TemporaryDirectory(prefix="wyrelog-hash-probe-") as temporary:
        bad_archive = Path(temporary) / "bad.zip"
        bad_archive.write_bytes(b"not the pinned archive")
        expect_error(lambda: verify_archive_hash(bad_archive), "E_ARCHIVE_HASH")
    with tempfile.TemporaryDirectory(prefix="wyrelog-member-probe-") as temporary:
        bad_bundle = Path(temporary) / "unsafe.zip"
        with ZipFile(bad_bundle, "w") as bundle:
            bundle.writestr("../duckdb.cpp", b"unsafe")
        expect_error(lambda: checked_zip_members(bad_bundle), "E_ARCHIVE_MEMBER")
    with tempfile.TemporaryDirectory(prefix="wyrelog-source-hash-probe-") as temporary:
        source = Path(temporary)
        (source / "duckdb.cpp").write_bytes(b"wrong cpp")
        (source / "duckdb.hpp").write_bytes(b"wrong hpp")
        expect_error(
            lambda: check_stage_hashes(source, PATCHES[0]),
            "E_COMPOSED_HASH",
        )

    discovered = shutil.which("gpatch") or shutil.which("patch")
    if discovered is not None:
        tool = Path(discovered).resolve()
        try:
            verify_gnu_patch(tool)
        except ContractError:
            pass
        else:
            real_fuzz_probe(tool)

    if exercise_crlf:
        windows_snapshot = crlf_self_test_snapshot(raw_snapshot)
        validate_structural(windows_snapshot)
        run_self_tests(root, windows_snapshot, exercise_crlf=False)

        mixed_snapshot = dict(windows_snapshot)
        mixed_snapshot[PATCH_PATHS[0]] = mixed_snapshot[PATCH_PATHS[0]].replace(
            b"\n", b"\r\n", 1
        )
        expect_error(
            lambda: validate_structural(mixed_snapshot),
            "E_PATCH_CRLF",
        )

        invalid_snapshot = dict(raw_snapshot)
        invalid_snapshot["tests/meson.build"] = b"\xff"
        expect_error(
            lambda: validate_structural(invalid_snapshot),
            "E_UTF8",
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--strict-apply", action="store_true")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--gnu-patch", type=Path)
    parser.add_argument("root", type=Path)
    args = parser.parse_args(argv)
    if args.self_test and args.strict_apply:
        parser.error("--self-test and --strict-apply are mutually exclusive")
    if args.strict_apply and (args.archive is None or args.gnu_patch is None):
        parser.error("--strict-apply requires --archive and --gnu-patch")
    if not args.strict_apply and (args.archive is not None or args.gnu_patch is not None):
        parser.error("--archive and --gnu-patch require --strict-apply")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    snapshot = load_snapshot(root)
    validate_structural(snapshot)
    if args.self_test:
        run_self_tests(root, snapshot)
        print("DuckDB patch-stack determinism self-test: OK")
    elif args.strict_apply:
        strict_replay(root, args.archive.resolve(), args.gnu_patch)
        print("DuckDB patch-stack strict replay: OK")
    else:
        print("DuckDB patch-stack structural contract: OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ContractError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Check that CI workflows keep building when sccache setup fails."""

from pathlib import Path
import re
import sys


def require(text: str, needle: str, path: Path) -> None:
    if needle not in text:
        raise SystemExit(f"{path}: missing {needle!r}")


def job_block(text: str, marker: str, path: Path, label: str) -> str:
    """Extract one workflow job, bounded by the next top-level job header.

    Bounding by a named successor job fails open: insert any job between the
    two and the extracted block swallows it, so a needle could be satisfied
    by the inserted job while the intended one had quietly lost it.
    """
    if text.count(marker) != 1:
        raise SystemExit(f"{path}: {label} job mismatch")
    start = text.index(marker)
    rest = text[start + len(marker):]
    # Quoted keys and trailing whitespace are legal YAML that GitHub accepts;
    # missing them would let the block over-extend into the next job, which is
    # the fail-open this bound exists to prevent.
    match = re.search(r"^  [\"']?[A-Za-z0-9_-]+[\"']?:[ \t]*$", rest, re.M)
    if match is None:
        raise SystemExit(f"{path}: {label} job end anchor missing")
    return text[start:start + len(marker) + match.start()]


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parents[1]
    focused_jobs = []
    for name in ("ci-pr.yml", "ci-main.yml"):
        path = root / ".github" / "workflows" / name
        text = path.read_text(encoding="utf-8")
        action = "uses: mozilla-actions/sccache-action@9e7fa8a12102821edf02ca5dbea1acd0f89a2696"
        if text.count(action) != 4:
            raise SystemExit(f"{path}: expected four pinned sccache actions")
        require(text, "id: sccache\n        continue-on-error: true", path)
        require(text, "steps.sccache.outcome", path)
        require(text, "sccache --version", path)
        require(text, "CC=sccache cc", path)
        require(text, "CXX=sccache c++", path)
        require(text, "CC=cc", path)
        require(text, "CXX=c++", path)
        require(text, "WYRELOG_USE_SCCACHE=1", path)
        require(text, "WYRELOG_USE_SCCACHE=0", path)
        require(text, "SCCACHE_EXE", path)
        require(text, "cygpath -w", path)
        require(text, "SCCACHE_LAUNCHER", path)
        require(text, 'set "CC=%SCCACHE_LAUNCHER% clang-cl"', path)
        require(text, 'set "CXX=%SCCACHE_LAUNCHER% clang-cl"', path)
        require(text, 'set "CC=clang-cl"', path)
        require(text, 'set "CXX=clang-cl"', path)
        require(text, "clang-cl --version", path)
        require(text, "if errorlevel 1", path)
        require(text, "rmdir /s /q builddir", path)
        require(text, "meson setup builddir -Denable_tpm=disabled", path)
        require(text, "ninja -C builddir -t commands", path)
        require(text, "findstr /I /C:\"sccache\"", path)
        require(text, "Compile requests[[:space:]]+[1-9][0-9]*", path)
        focused = job_block(text, "  policy-write-focused-sanitizer:\n",
                path, "focused policy WRITE")
        focused_jobs.append(focused)
        for needle in (action, "continue-on-error: true",
                "steps.sccache.outcome", "CC=sccache cc", "CC=cc",
                "runs-on: ubuntu-latest", "-Denable_fact_store=enabled",
                "-Denable_audit=enabled", "-Dduckdb_source=prebuilt",
                "ASAN_OPTIONS: halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS: halt_on_error=1:abort_on_error=1",
                "-Db_sanitize=address,undefined", "--repeat 5"):
            require(focused, needle, path)
        # Same substring hazard as the fact mutation block below.
        require(focused,
            "            service-auth-coordination \\\n"
            "            daemon-http-decide \\\n"
            "            daemon-http-decide-audit \\\n"
            "            daemon-http-decide-service \\\n", path)
        # Pin which suites repeat here too, for the same reason.
        require(focused,
            "            service-auth-coordination \\\n"
            "            daemon-http-decide \\\n"
            "            daemon-http-decide-audit \\\n"
            "            --repeat 5 \\\n", path)
    if focused_jobs[0] != focused_jobs[1]:
        raise SystemExit("policy WRITE focused sanitizer jobs differ")
    mutation_jobs = []
    for name in ("ci-pr.yml", "ci-main.yml"):
        path = root / ".github" / "workflows" / name
        text = path.read_text(encoding="utf-8")
        mutation = job_block(text, "  fact-mutation-focused-sanitizer:\n",
                path, "focused fact mutation")
        mutation_jobs.append(mutation)
        for needle in ("uses: mozilla-actions/sccache-action@9e7fa8a12102821edf02ca5dbea1acd0f89a2696",
                "continue-on-error: true", "steps.sccache.outcome",
                "CC=sccache cc", "CC=cc", "runs-on: ubuntu-latest",
                "-Denable_fact_store=enabled", "-Denable_audit=enabled",
                "-Dduckdb_source=prebuilt", "-Db_sanitize=address,undefined",
                "ASAN_OPTIONS: halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS: halt_on_error=1:abort_on_error=1",
                "--repeat 5"):
            require(mutation, needle, path)
        # Pin the whole test invocation, not the bare suite names: each of
        # those is also a substring of the compile step's target name
        # (test-fact-replay and so on), so naming them individually would
        # still pass if a suite were dropped from the run.
        require(mutation,
            "            fact-replay \\\n"
            "            fact-runtime \\\n"
            "            fact-store \\\n"
            "            daemon-http-facts \\\n"
            "            --num-processes 2 \\\n"
            "            --timeout-multiplier 3 \\\n", path)
        # The repeat step is this issue's query/mutation race deliverable, so
        # pin which suite actually repeats, not merely that a repeat exists.
        require(mutation,
            "            fact-replay \\\n"
            "            fact-runtime \\\n"
            "            --repeat 5 \\\n"
            "            --timeout-multiplier 3 \\\n", path)
        if "detect_leaks=0" in text:
            raise SystemExit(
                f"{path}: fact mutation sanitizer must keep leak detection on")
    if mutation_jobs[0] != mutation_jobs[1]:
        raise SystemExit("fact mutation focused sanitizer jobs differ")
    meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
    require(meson, "[service_session_boundary_cc[1]]", root / "tests/meson.build")
    require(meson, "contains('cache')", root / "tests/meson.build")
    boundary = (root / "tools" /
                "check-service-session-private-boundary.py").read_text(
                    encoding="utf-8")
    require(boundary, "normalize_direct_compiler", root / "tools")
    require(boundary, "return arguments[1:]", root / "tools")
    require(boundary, "min(8, max(2, 2 * (os.cpu_count() or 1)))",
            root / "tools")
    print("sccache fallback workflow guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Check that CI workflows keep building when sccache setup fails."""

from pathlib import Path
import sys


def require(text: str, needle: str, path: Path) -> None:
    if needle not in text:
        raise SystemExit(f"{path}: missing {needle!r}")


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parents[1]
    focused_jobs = []
    for name in ("ci-pr.yml", "ci-main.yml"):
        path = root / ".github" / "workflows" / name
        text = path.read_text(encoding="utf-8")
        action = "uses: mozilla-actions/sccache-action@9e7fa8a12102821edf02ca5dbea1acd0f89a2696"
        if text.count(action) != 3:
            raise SystemExit(f"{path}: expected three pinned sccache actions")
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
        marker = "  policy-write-focused-sanitizer:\n"
        if text.count(marker) != 1:
            raise SystemExit(f"{path}: focused policy WRITE job mismatch")
        start = text.index(marker)
        end = text.index("\n  daemon-http-shared-fact-audit-disabled:", start)
        focused = text[start:end]
        focused_jobs.append(focused)
        for needle in (action, "continue-on-error: true",
                "steps.sccache.outcome", "CC=sccache cc", "CC=cc",
                "runs-on: ubuntu-latest", "-Denable_fact_store=enabled",
                "-Denable_audit=enabled", "-Dduckdb_source=prebuilt",
                "ASAN_OPTIONS: halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS: halt_on_error=1:abort_on_error=1",
                "-Db_sanitize=address,undefined", "service-auth-coordination",
                "daemon-http-decide-service", "--repeat 5"):
            require(focused, needle, path)
    if focused_jobs[0] != focused_jobs[1]:
        raise SystemExit("policy WRITE focused sanitizer jobs differ")
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

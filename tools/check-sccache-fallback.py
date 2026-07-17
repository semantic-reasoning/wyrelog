#!/usr/bin/env python3
"""Check that CI workflows keep building when sccache setup fails."""

from pathlib import Path
import sys


def require(text: str, needle: str, path: Path) -> None:
    if needle not in text:
        raise SystemExit(f"{path}: missing {needle!r}")


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parents[1]
    for name in ("ci-pr.yml", "ci-main.yml"):
        path = root / ".github" / "workflows" / name
        text = path.read_text(encoding="utf-8")
        action = "uses: mozilla-actions/sccache-action@v0.0.10"
        if text.count(action) != 2:
            raise SystemExit(f"{path}: expected two pinned sccache actions")
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
        require(text, "clang-cl --version", path)
        require(text, "if errorlevel 1", path)
        require(text, "rmdir /s /q builddir", path)
        require(text, "c = ['%SCCACHE_LAUNCHER", path)
        require(text, "cpp = ['%SCCACHE_LAUNCHER", path)
        require(text, "c = ['clang-cl']", path)
        require(text, "cpp = ['clang-cl']", path)
        require(text, "ninja -C builddir -t commands", path)
        require(text, "Compile requests[[:space:]]+[1-9][0-9]*", path)
    print("sccache fallback workflow guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

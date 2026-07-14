#!/usr/bin/env python3
"""Non-vacuity tests for the production bearer-resolver export guard."""

import importlib.util
from pathlib import Path
import sys


def load_guard(path):
    spec = importlib.util.spec_from_file_location("bearer_export_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    if len(sys.argv) != 2:
        return 2
    guard = load_guard(Path(sys.argv[1]))
    artifact = Path("wyrelogd-without-an-extension")
    expected = {
        "elf": [("nm", "-D", "--defined-only", str(artifact)),
                ("llvm-nm", "-D", "--defined-only", str(artifact))],
        "macho": [("nm", "-gU", str(artifact)),
                  ("llvm-nm", "-gU", str(artifact))],
        "pe": [("llvm-readobj", "--coff-exports", str(artifact)),
               ("objdump", "-p", str(artifact))],
    }
    for object_format, commands in expected.items():
        assert guard.command_candidates(object_format, artifact) == commands
        calls = []

        def which(name):
            return f"/mock/{name}" if name == commands[1][0] else None

        def runner(command):
            calls.append(command)
            return "exports"

        assert guard.exports(object_format, artifact, which, runner) == "exports"
        assert calls == [[f"/mock/{commands[1][0]}", *commands[1][1:]]]

    target = "wyl_daemon_http_resolve_bearer_for_test"
    assert guard.protected_symbols(f"000 T {target}\n") == {target}
    assert guard.protected_symbols(f"Export {{ Name: _{target}@12 }}\n") == {target}
    assert guard.protected_symbols(f"000 T _{target}\n") == {target}
    allowed = (f"000 T prefix_{target}\n000 T {target}_suffix\n"
               "000 T wyl_daemon_http_resolve_bearer\n")
    assert guard.protected_symbols(allowed) == set()
    all_symbols = "\n".join(f"T _{symbol}" for symbol in guard.PROTECTED)
    assert guard.protected_symbols(all_symbols) == guard.PROTECTED
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

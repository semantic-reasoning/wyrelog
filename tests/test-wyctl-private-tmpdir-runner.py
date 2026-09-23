#!/usr/bin/env python3
"""Verify the wyctl test runner cleans its private root after child abort."""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test-wyctl-private-tmpdir-runner.py RUNNER",
              file=sys.stderr)
        return 2

    runner = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="wyctl-runner-test-") as parent:
        parent_path = Path(parent)
        sentinel = parent_path / "outside-sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        env = os.environ.copy()
        env["TMPDIR"] = str(parent_path)
        env.pop("MESON_EXE_WRAPPER", None)

        child_code = r"""
import os
from pathlib import Path
import tempfile
import sys

if os.name == "posix":
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
root = Path(tempfile.gettempdir())
nested = root / "glib-2.0" / "settings"
nested.mkdir(parents=True)
(nested / "keyfile").write_text("fixture", encoding="utf-8")
(root / "policy.sqlite-wal").write_text("sidecar", encoding="utf-8")
(root / "credential.txt").write_text("test credential", encoding="utf-8")
if os.name == "posix":
    (root / "external-link").symlink_to(sys.argv[1])
os.abort()
"""
        result = subprocess.run(
            [sys.executable, str(runner), sys.executable, "-c", child_code,
             str(sentinel)],
            env=env,
            check=False,
        )

        if result.returncode == 0:
            raise AssertionError("runner hid the child's abnormal exit")
        if sorted(path.name for path in parent_path.iterdir()) != [
                sentinel.name]:
            raise AssertionError("runner left its private temporary root")
        if sentinel.read_text(encoding="utf-8") != "keep":
            raise AssertionError("runner followed a fixture symlink")

        marker = parent_path / "wrapper-ran"
        wrapper_with_marker = parent_path / "wrapper marker.py"
        wrapper_with_marker.write_text(
            "import os, sys\n"
            "open(os.environ['WRAPPER_MARKER'], 'w', encoding='utf-8').close()\n"
            "os.execvp(sys.argv[1], sys.argv[1:])\n",
            encoding="utf-8",
        )
        env["MESON_EXE_WRAPPER"] = shlex.join(
            [sys.executable, str(wrapper_with_marker)])
        env["WRAPPER_MARKER"] = str(marker)
        result = subprocess.run(
            [sys.executable, str(runner), sys.executable, "-c",
             "raise SystemExit(0)"],
            env=env,
            check=False,
        )
        if result.returncode != 0 or not marker.exists():
            raise AssertionError("runner did not invoke Meson's exe wrapper")

    print("private temporary root cleanup after child abort: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

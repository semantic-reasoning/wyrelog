#!/usr/bin/env python3
"""Guard the native Windows CI matrix timeout and cleanup contract."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
required_timeouts = {
    "ci-pr.yml": "    timeout-minutes: 180\n",
    "ci-main.yml": "    timeout-minutes: 90\n",
}
required_steps = (
    "      - name: Bootstrap vendored vcpkg",
    "      - name: Build and test (clang-cl)",
    "      - name: Verify Windows CI timeout boundary",
    "      - name: Show sccache statistics",
    "        if: ${{ !cancelled() }}",
    "      - name: Upload meson logs on failure",
    "        if: always()",
    "          path: builddir/meson-logs/",
    "secure-duckdb-recording-filesystem",
    "--test-args=\"-p /secure-duckdb-bridge/recording-filesystem/live-wal-read-only-recovery\"",
    "fact-artifact-namespace-windows",
    "fact-provisioning-construct",
    "            meson test -C builddir secure-duckdb-bridge",
    "            meson test -C builddir --print-errorlogs --suite wyrelog",
)

for workflow_name in ("ci-pr.yml", "ci-main.yml"):
    workflow = (root / ".github" / "workflows" / workflow_name).read_text(
        encoding="utf-8")
    start = workflow.index("  build-windows:\n")
    next_job = re.search(r"\n  [A-Za-z0-9_-]+:\n", workflow[
        start + len("  build-windows:\n"):])
    end = (start + len("  build-windows:\n") + next_job.start()
           if next_job is not None else len(workflow))
    job = workflow[start:end]
    if job.count(required_timeouts[workflow_name]) != 1:
        raise SystemExit(
            f"{workflow_name} build-windows has the wrong bounded timeout")
    for token in required_steps:
        if token not in job:
            raise SystemExit(
                f"{workflow_name} Windows cleanup/build contract drifted: "
                f"{token}")
    if not ("Cache vcpkg binary packages" in job
            or "Restore vcpkg installed tree" in job):
        raise SystemExit(
            f"{workflow_name} Windows dependency cache/provisioning drifted")
    if "secure-duckdb-recording-filesystem" not in job:
        raise SystemExit(
            f"{workflow_name} secure-bridge tests must remain enabled")
    if "fail-fast: false" not in job:
        raise SystemExit(f"{workflow_name} Windows matrix must remain independent")
    for matrix_entry in (
        "fact_store: disabled\n            secure_bridge: disabled\n            duckdb_source: prebuilt",
        "fact_store: enabled\n            secure_bridge: disabled\n            duckdb_source: prebuilt",
        "fact_store: enabled\n            secure_bridge: enabled\n            duckdb_source: subproject",
    ):
        if matrix_entry not in job:
            raise SystemExit(
                f"{workflow_name} Windows matrix variant was removed")

print("Windows CI timeout boundary: OK")

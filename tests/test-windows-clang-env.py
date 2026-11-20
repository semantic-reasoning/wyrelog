#!/usr/bin/env python3
"""Keep native Windows commands on the installed Clang-compatible STL."""
from pathlib import Path
import sys

CALL = r"call .github\scripts\windows-clang-env.cmd"
FAIL = "if errorlevel 1 exit 1"
RETURN_FAIL = "if errorlevel 1 exit /b 1"


def validate(helper, workflows):
    required = (
        "vswhere.exe",
        "-requires Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64",
        "-property installationPath",
        "if not defined WYRELOG_VS_ROOT",
        'if not exist "%WYRELOG_VS_ROOT%\\VC\\Auxiliary\\Build\\vcvars64.bat"',
        'call "%WYRELOG_VS_ROOT%\\VC\\Auxiliary\\Build\\vcvars64.bat" -vcvars_ver=14.44',
        RETURN_FAIL,
        'if not "%VCToolsVersion:~0,5%"=="14.44"',
        "exit /b 0",
    )
    for token in required:
        if token not in helper:
            raise ValueError(f"missing toolchain requirement: {token}")
    if helper.index(RETURN_FAIL) < helper.index("-vcvars_ver=14.44"):
        raise ValueError("initialization error must be checked after vcvars")
    for name, workflow in workflows.items():
        windows = workflow[workflow.index("  build-windows:\n"):]
        lines = windows.splitlines()
        calls = [i for i, line in enumerate(lines) if line.strip() == CALL]
        if len(calls) != 7 or "vcvars64.bat" in windows:
            raise ValueError(f"{name}: all seven native setup calls must use helper")
        for i in calls:
            if i + 1 == len(lines) or lines[i + 1].strip() != FAIL:
                raise ValueError(f"{name}: helper failure must stop native command")
    if "_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH" in helper:
        raise ValueError("compiler/STL compatibility must remain enforced")


def main():
    root = Path(sys.argv[-1])
    helper = (root / ".github/scripts/windows-clang-env.cmd").read_text(encoding="utf-8")
    workflows = {name: (root / ".github/workflows" / name).read_text(encoding="utf-8")
                 for name in ("ci-pr.yml", "ci-main.yml")}
    validate(helper, workflows)
    if "--self-test" in sys.argv:
        mutations = [
            (helper.replace("-vcvars_ver=14.44", ""), workflows),
            (helper.replace(RETURN_FAIL, "rem ignored failure"), workflows),
            (helper.replace('if not "%VCToolsVersion:~0,5%"=="14.44"', "rem unchecked version"), workflows),
            (helper.replace("-requires Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64", ""), workflows),
        ]
        for name, workflow in workflows.items():
            mutations += [
                (helper, {**workflows, name: workflow.replace(CALL, "rem missing environment", 1)}),
                (helper, {**workflows, name: workflow.replace(CALL + "\n          " + FAIL, CALL + "\n          rem ignored failure", 1)}),
            ]
        for changed_helper, changed_workflows in mutations:
            try:
                validate(changed_helper, changed_workflows)
            except ValueError:
                continue
            raise ValueError("unsafe toolchain mutation passed")
    print("Windows Clang-compatible toolchain contract passed")


if __name__ == "__main__":
    main()

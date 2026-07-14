#!/usr/bin/env python3
"""Reject private service-session symbols in a library artifact."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

PROTECTED = (
    "wyl_session_new_service_detached",
    "wyl_session_get_auth_method_private",
    "wyl_session_is_active_private",
    "wyl_session_copy_persistent_id_private",
    "wyl_session_dup_service_jti_private",
    "wyl_session_dup_service_subject_private",
    "wyl_session_dup_service_tenant_private",
    "wyl_session_dup_service_credential_id_private",
    "wyl_session_get_service_credential_generation_private",
    "wyl_session_get_service_issued_at_seconds_private",
    "wyl_session_get_service_expires_at_seconds_private",
)


def run(command: list[str]) -> str:
    result = subprocess.run(command, check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise RuntimeError(f"export inspection failed: {' '.join(command)}\n"
                           + result.stdout)
    return result.stdout


def normalized_symbols(output: str) -> set[str]:
    result = set()
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_@$?]*", output):
        candidate = token
        if candidate.startswith("__imp_"):
            candidate = candidate[6:]
        candidate = re.sub(r"@\d+$", "", candidate)
        if candidate.startswith("_") and candidate[1:] in PROTECTED:
            candidate = candidate[1:]
        if candidate in PROTECTED:
            result.add(candidate)
    return result


def self_test() -> int:
    for symbol in PROTECTED:
        if normalized_symbols(f"000 T {symbol}\n") != {symbol}:
            return 1
        if normalized_symbols(f"000 T __imp__{symbol}@16\n") != {symbol}:
            return 1
        if normalized_symbols(f"000 T prefix_{symbol}_suffix\n"):
            return 1
    with tempfile.TemporaryDirectory() as directory:
        versioned = Path(directory) / "wyrelog-0.dll"
        versioned.write_bytes(b"fixture")
        if versioned not in family(versioned):
            return 1
    return 0


def family(artifact: Path) -> list[Path]:
    result = [artifact]
    for candidate in artifact.parent.iterdir():
        name = candidate.name.lower()
        if ("wyrelog-service-session-private" in name
                or "wyrelog-client" in name or not candidate.is_file()):
            continue
        if (name.startswith("libwyrelog.so") or name == "libwyrelog.a"
                or name.startswith("libwyrelog.dylib")
                or name in {"wyrelog.dll", "wyrelog.lib", "libwyrelog.dll.a"}):
            result.append(candidate)
    unique = []
    seen = set()
    for candidate in result:
        identity = candidate.resolve()
        if identity not in seen:
            seen.add(identity)
            unique.append(candidate)
    return unique


def inspect(artifact: Path) -> set[str]:
    suffix = artifact.suffix.lower()
    if suffix in {".a", ".lib"}:
        tool = shutil.which("llvm-nm") or shutil.which("nm")
        if tool is None:
            raise RuntimeError("no static-library symbol inspector found")
        output = run([tool, "--defined-only", str(artifact)])
    elif suffix == ".dylib":
        tool = shutil.which("nm")
        if tool is None:
            raise RuntimeError("nm is required for Mach-O export inspection")
        output = run([tool, str(artifact)])
    elif suffix == ".dll":
        tool = shutil.which("llvm-nm") or shutil.which("nm")
        if tool is not None:
            output = run([tool, "--defined-only", str(artifact)])
        else:
            tool = shutil.which("dumpbin")
            if tool is None:
                raise RuntimeError("no PE/COFF export inspector found")
            output = run([tool, "/nologo", "/symbols", str(artifact)])
    else:
        tool = shutil.which("nm") or shutil.which("llvm-nm")
        if tool is None:
            raise RuntimeError("nm is required for ELF export inspection")
        output = run([tool, "--defined-only", str(artifact)])
    return normalized_symbols(output)


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 3 or sys.argv[1] not in {
            "--must-not-contain-family", "--must-contain"}:
        print("usage: check-service-session-private-exports.py "
              "(--must-not-contain-family|--must-contain) LIBRARY",
              file=sys.stderr)
        return 2
    mode = sys.argv[1]
    artifact = Path(sys.argv[2])
    if not artifact.is_file():
        print(f"library artifact missing: {artifact}", file=sys.stderr)
        return 1
    try:
        if mode == "--must-not-contain-family":
            found = set()
            for member in family(artifact):
                found.update(inspect(member))
        else:
            found = inspect(artifact)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1

    if mode == "--must-not-contain-family" and found:
        print("private service-session symbols exported:", *sorted(found),
              sep="\n  ", file=sys.stderr)
        return 1
    if mode == "--must-contain" and set(found) != set(PROTECTED):
        missing = [symbol for symbol in PROTECTED if symbol not in found]
        print("private companion symbols missing:", *missing,
              sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

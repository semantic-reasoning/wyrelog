#!/usr/bin/env python3
"""Keep proof-bound handoff delivery authority out of general/exported APIs."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


FORBIDDEN_GENERAL = (
    "WylServiceCredentialHandoffDeliveryCapability",
    "WylServiceCredentialHandoffDeliveryPreflight",
    "wyl_service_credential_handoff_delivery_",
    "wyl_policy_store_handoff_consume_delivered_core",
    "wyl_policy_store_service_handoff_escrow_delete",
)

FORBIDDEN_EXPORT_PREFIXES = (
    "wyl_service_credential_handoff_delivery_",
    "wyl_service_credential_handoff_prepare_delivery_core",
    "wyl_service_credential_operation_coordinator_maintain_expired",
    "wyl_policy_store_handoff_",
    "wyl_policy_store_service_handoff_escrow_delete",
)

FORBIDDEN_EXPORT_EXACT = {
    "wyl_service_credential_operation_handoff_target_digest",
}

FRIEND_INCLUDES = {
    "service-credential-handoff-delivery-private.h": {
        "wyrelog/auth/service-credential-handoff-delivery-private.c",
        "wyrelog/auth/service-credential-operation-coordinator-execute-private.c",
        "wyrelog/auth/service-credential-operation-coordinator-maintenance-private.c",
    },
    "store-handoff-delivery-private.h": {
        "wyrelog/auth/service-credential-handoff-delivery-private.c",
        "wyrelog/policy/store.c",
    },
}

FRIEND_HEADER_INCLUDES = {
    "service-credential-handoff-delivery-private.h": set(),
    "store-handoff-delivery-private.h": {
        "wyrelog/auth/service-credential-handoff-delivery-private.h",
    },
}


def run(command: list[str]) -> str:
    result = subprocess.run(command, check=False, text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise RuntimeError("export inspection failed:\n" + result.stdout)
    return result.stdout


def artifact_kind(artifact: Path) -> str:
    name = artifact.name.lower()
    if name.endswith((".a", ".lib")):
        return "static"
    if name.endswith(".dll"):
        return "coff"
    if name.endswith(".dylib"):
        return "macho"
    if re.search(r"\.so(?:\.\d+)*$", name):
        return "elf"
    raise RuntimeError(f"unsupported library artifact: {artifact}")


def llvm_readobj_coff_exports(output: str) -> set[str]:
    exports = set()
    in_export = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "Export {":
            in_export = True
        elif in_export and stripped == "}":
            in_export = False
        elif in_export and stripped.startswith("Name:"):
            name = stripped.removeprefix("Name:").strip()
            if name:
                exports.add(name)
    return exports


def objdump_coff_exports(output: str) -> set[str]:
    exports = set()
    in_name_table = False
    for line in output.splitlines():
        if "[Ordinal/Name Pointer] Table" in line:
            in_name_table = True
            continue
        if not in_name_table:
            continue
        match = re.match(r"^\s*\[\s*\d+\]\s+(\S+)\s*$", line)
        if match:
            exports.add(match.group(1))
    return exports


def coff_exported_symbols(artifact: Path) -> set[str]:
    llvm_readobj = shutil.which("llvm-readobj")
    if llvm_readobj is not None:
        return llvm_readobj_coff_exports(
            run([llvm_readobj, "--coff-exports", str(artifact)]))
    objdump = shutil.which("llvm-objdump") or shutil.which("objdump")
    if objdump is not None:
        return objdump_coff_exports(run([objdump, "-p", str(artifact)]))
    raise RuntimeError("llvm-readobj or objdump is required for PE exports")


def exported_symbols(artifact: Path) -> str:
    kind = artifact_kind(artifact)
    if kind == "static":
        # Archive-global symbols are link inputs, not runtime exports.
        return ""
    if kind == "coff":
        return "\n".join(sorted(coff_exported_symbols(artifact)))
    nm = (shutil.which("nm") or shutil.which("llvm-nm"))
    if nm is None:
        raise RuntimeError("nm or llvm-nm is required")
    command = ([nm, "-gU", str(artifact)] if kind == "macho" else
               [nm, "-D", "--defined-only", str(artifact)])
    return run(command)


def forbidden_runtime_exports(output: str, kind: str = "elf") -> set[str]:
    names = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        name = fields[-1].split("@", 1)[0]
        # Mach-O's ABI spelling adds exactly one leading underscore.  Avoid a
        # generic lstrip: multiple underscores are part of a different symbol.
        if kind == "macho" and name.startswith("_wyl_"):
            name = name[1:]
        names.add(name)
    return {
        name for name in names
        if name in FORBIDDEN_EXPORT_EXACT
        or any(name.startswith(prefix)
               for prefix in FORBIDDEN_EXPORT_PREFIXES)
    }


def friend_include_diff(root: Path, include_name: str, allowed: set[str],
                        suffix: str) -> tuple[set[str], set[str]]:
    actual = set()
    pattern = re.compile(
        rf'#include\s+[<"][^">]*{re.escape(include_name)}[>"]')
    for source in (root / "wyrelog").rglob(f"*{suffix}"):
        if source.name == include_name:
            continue
        if pattern.search(source.read_text(encoding="utf-8")):
            actual.add(source.relative_to(root).as_posix())
    return actual - allowed, allowed - actual


def self_test() -> int:
    kinds = {
        "libwyrelog.a": "static",
        "wyrelog.lib": "static",
        "libwyrelog.dll.a": "static",
        "wyrelog.dll": "coff",
        "libwyrelog.dylib": "macho",
        "libwyrelog.so": "elf",
        "libwyrelog.so.0": "elf",
        "libwyrelog.so.0.1": "elf",
    }
    if any(artifact_kind(Path(name)) != kind
           for name, kind in kinds.items()):
        return 1
    llvm_fixture = """
File: wyrelog.dll
Export {
  Ordinal: 1
  Name: wyl_public_api
  RVA: 0x1000
}
Export {
  Ordinal: 2
  Name: wyl_policy_store_handoff_private
  RVA: 0x1010
}
"""
    if llvm_readobj_coff_exports(llvm_fixture) != {
            "wyl_public_api", "wyl_policy_store_handoff_private"}:
        return 1
    objdump_fixture = """
The Import Tables
  DLL Name: dependency.dll
  0000 wyl_policy_store_handoff_import_only
[Ordinal/Name Pointer] Table
        [   0] wyl_public_api
        [   1] wyl_policy_store_handoff_private
"""
    if objdump_coff_exports(objdump_fixture) != {
            "wyl_public_api", "wyl_policy_store_handoff_private"}:
        return 1
    runtime_fixture = """
0001 T wyl_service_credential_operation_coordinator_maintain_expired
0002 T wyl_service_credential_operation_coordinator_maintain_expired_locked
0003 T wyl_service_credential_operation_handoff_target_digest
0004 T wyl_service_credential_operation_handoff_target_digest_extra
0005 T safe_wyl_policy_store_handoff_embedded
"""
    if forbidden_runtime_exports(runtime_fixture) != {
            "wyl_service_credential_operation_coordinator_maintain_expired",
            "wyl_service_credential_operation_coordinator_maintain_expired_locked",
            "wyl_service_credential_operation_handoff_target_digest",
    }:
        return 1
    macho_runtime_fixture = """
0001 T _wyl_service_credential_operation_coordinator_maintain_expired
0002 T _wyl_service_credential_operation_handoff_target_digest
0003 T __wyl_service_credential_operation_handoff_target_digest
"""
    if forbidden_runtime_exports(macho_runtime_fixture, "macho") != {
            "wyl_service_credential_operation_coordinator_maintain_expired",
            "wyl_service_credential_operation_handoff_target_digest",
    }:
        return 1
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / "wyrelog.lib"
        archive.write_bytes(b"not a real archive")
        if exported_symbols(archive) != "":
            return 1
        root = Path(directory)
        allowed = root / "wyrelog/auth/allowed.c"
        unexpected = root / "wyrelog/general.c"
        allowed.parent.mkdir(parents=True)
        allowed.write_text('#include "private-friend.h"\n', encoding="utf-8")
        unexpected.write_text('#include "private-friend.h"\n',
                              encoding="utf-8")
        extra, missing = friend_include_diff(root, "private-friend.h", {
            "wyrelog/auth/allowed.c",
        }, ".c")
        if extra != {"wyrelog/general.c"} or missing:
            return 1
        extra, missing = friend_include_diff(root, "private-friend.h", {
            "wyrelog/auth/allowed.c", "wyrelog/missing.c",
        }, ".c")
        if extra != {"wyrelog/general.c"} or missing != {"wyrelog/missing.c"}:
            return 1
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 3:
        print("usage: check-service-handoff-delivery-boundary.py "
              "ROOT LIB | --self-test",
              file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    artifact = Path(sys.argv[2])
    general_headers = (
        root / "wyrelog/policy/store-private.h",
        root / "wyrelog/auth/service-credential-domain-private.h",
    )
    for header in general_headers:
        text = header.read_text(encoding="utf-8")
        for token in FORBIDDEN_GENERAL:
            if token in text:
                print(f"delivery authority leaked into {header}: {token}",
                      file=sys.stderr)
                return 1
    for include_name, allowed in FRIEND_INCLUDES.items():
        unexpected, missing = friend_include_diff(root, include_name,
                                                   allowed, ".c")
        if unexpected or missing:
            print(f"friend include allowlist mismatch for {include_name}",
                  file=sys.stderr)
            if unexpected:
                print("unexpected:", *sorted(unexpected), sep="\n  ",
                      file=sys.stderr)
            if missing:
                print("missing:", *sorted(missing), sep="\n  ",
                      file=sys.stderr)
            return 1
    for include_name, allowed in FRIEND_HEADER_INCLUDES.items():
        unexpected, missing = friend_include_diff(root, include_name,
                                                   allowed, ".h")
        if unexpected or missing:
            print(f"friend header allowlist mismatch for {include_name}",
                  *sorted(unexpected | missing), sep="\n  ", file=sys.stderr)
            return 1
    friend = (root / "wyrelog/auth/"
              "service-credential-handoff-delivery-private.h")
    friend_text = friend.read_text(encoding="utf-8")
    for opaque in ("WylServiceCredentialHandoffDeliveryCapability",
                   "WylServiceCredentialHandoffDeliveryPreflight"):
        pattern = rf"typedef struct _{opaque}\s+{opaque};"
        if re.search(pattern, friend_text) is None:
            print(f"friend capability is not opaque: {opaque}",
                  file=sys.stderr)
            return 1
    if not artifact.is_file():
        print(f"library artifact missing: {artifact}", file=sys.stderr)
        return 1
    try:
        symbols = exported_symbols(artifact)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    forbidden = forbidden_runtime_exports(symbols, artifact_kind(artifact))
    if forbidden:
        print(f"delivery authority exported by {artifact}:",
              *sorted(forbidden), sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

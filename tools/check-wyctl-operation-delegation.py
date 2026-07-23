#!/usr/bin/env python3
"""Keep the #379 service-credential-operation domain out of the wyctl CLI.

The `wyctl service-credential status`/`recover` commands are strictly
delegation-only: they call the #475 client surface
(wyl_client_service_credential_operation_*) and render the daemon's
non-secret allow-list. They must NOT reach into the #379 durable-operation
domain (the WYL_SERVICE_CREDENTIAL_OPERATION_* macros / the
WylServiceCredentialOperation* types) nor re-implement any part of the
predecessor state machine (a duplicated *_STATE_ / *_JOURNAL_ / *_FENCE_ /
*_PUBLICATION_ enum).

This is a source-level guard on wyctl.c. The link-time backstop is
independent: wyctl_exe links only wyrelog_client_dep, so no #379 library is
on its link line and any accidental use of a #379 symbol would also fail to
link. This checker catches the mistake earlier and with a precise diagnostic.

The forbidden domain tokens are keyed on the full WYL_/Wyl-anchored token so
the PERMITTED client tokens WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_ /
WylClientServiceCredentialOperation are NOT tripped: the anchored spellings
WYL_SERVICE_CREDENTIAL_OPERATION_ and WylServiceCredentialOperation are not
substrings of their WYL_CLIENT_/WylClient- counterparts.
"""

from pathlib import Path
import re
import sys
import tempfile


# The #379 domain symbols, anchored on the full WYL_/Wyl token so the
# permitted #475 client tokens (which merely contain the shared infix) pass.
FORBIDDEN_DOMAIN_PATTERNS = (
    re.compile(r"\bWYL_SERVICE_CREDENTIAL_OPERATION_"),
    re.compile(r"\bWylServiceCredentialOperation"),
)

# A duplicated predecessor state machine would surface as an enum defining
# tokens carrying one of these infixes.
FORBIDDEN_ENUM_INFIXES = ("_STATE_", "_JOURNAL_", "_FENCE_", "_PUBLICATION_")

# C enum bodies never nest braces, so a non-brace body capture is sufficient.
ENUM_BLOCK = re.compile(r"\benum\b[^{}]*\{([^{}]*)\}")


def scan_violations(text: str) -> list[str]:
    violations = []
    for pattern in FORBIDDEN_DOMAIN_PATTERNS:
        for match in pattern.finditer(text):
            violations.append(f"forbidden #379 domain token: {match.group(0)}")
    for block in ENUM_BLOCK.finditer(text):
        body = block.group(1)
        for infix in FORBIDDEN_ENUM_INFIXES:
            if infix in body:
                violations.append(
                    f"duplicated predecessor state machine enum token: {infix}")
    return violations


def check_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    violations = scan_violations(text)
    for violation in violations:
        print(f"{path}: {violation}", file=sys.stderr)
    return 1 if violations else 0


def self_test() -> int:
    # The permitted #475 client tokens and a benign enum must NOT trip.
    permitted = (
        "wyl_client_service_credential_operation_status_list (client, &list);\n"
        "WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ISSUE\n"
        "WylClientServiceCredentialOperationStatusEntry entry = { 0 };\n"
        "enum { WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ROTATE = 2 };\n"
    )
    if scan_violations(permitted):
        return 1

    # Each forbidden sample must be flagged.
    forbidden_samples = (
        "WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED",
        "WylServiceCredentialOperation op;",
        "enum { WYL_FOO_STATE_PREPARED = 1 };",
        "enum { WYL_FOO_JOURNAL_HEAD = 1 };",
        "enum { WYL_FOO_FENCE_ARMED = 1 };",
        "enum { WYL_FOO_PUBLICATION_LIVE = 1 };",
    )
    for sample in forbidden_samples:
        if not scan_violations(sample):
            return 1

    # End-to-end via the file path, mirroring the real invocation: a permitted
    # fixture passes (0), a forbidden fixture fails (nonzero).
    with tempfile.TemporaryDirectory() as directory:
        clean = Path(directory) / "clean.c"
        clean.write_text(permitted, encoding="utf-8")
        if check_file(clean) != 0:
            return 1
        dirty = Path(directory) / "dirty.c"
        dirty.write_text(forbidden_samples[0] + "\n", encoding="utf-8")
        if check_file(dirty) == 0:
            return 1
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 2:
        print("usage: check-wyctl-operation-delegation.py WYCTL_C | --self-test",
              file=sys.stderr)
        return 2
    return check_file(Path(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())

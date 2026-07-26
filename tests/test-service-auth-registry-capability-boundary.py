#!/usr/bin/env python3
"""Keep production registry transitions behind #371 lease capabilities."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
HTTP = ROOT / "wyrelog" / "daemon" / "http.c"
EXCHANGE = ROOT / "wyrelog" / "auth" / "service-exchange-private.c"
HEADER = ROOT / "wyrelog" / "daemon" / "auth-registry-private.h"
DOMAIN = ROOT / "wyrelog" / "auth" / "service-credential-domain.c"
DOMAIN_HEADER = (
    ROOT / "wyrelog" / "auth" / "service-credential-domain-private.h"
)
REMEDIATION_COORDINATOR = (
    ROOT
    / "wyrelog"
    / "auth"
    / "service-credential-operation-coordinator-remediate-private.c"
)
REMEDIATION_COORDINATOR_HEADER = (
    ROOT
    / "wyrelog"
    / "auth"
    / "service-credential-operation-coordinator-remediate-private.h"
)


def without_test_blocks(source: str) -> str:
    kept: list[str] = []
    depth = 0
    removing_at = 0
    for line in source.splitlines():
        directive = line.lstrip()
        if directive.startswith(("#if ", "#ifdef ", "#ifndef ")):
            depth += 1
            if "WYL_TEST_DAEMON_HTTP" in directive and removing_at == 0:
                removing_at = depth
            if removing_at == 0:
                kept.append(line)
            continue
        if directive.startswith("#endif"):
            if removing_at == 0:
                kept.append(line)
            if removing_at == depth:
                removing_at = 0
            depth -= 1
            continue
        if removing_at == 0:
            kept.append(line)
    return "\n".join(kept)


def main() -> int:
    production = without_test_blocks(HTTP.read_text(encoding="utf-8"))
    forbidden = re.compile(
        r"\bwyl_service_auth_registry_"
        r"(reserve|activate|revoke_exact|remove_exact)\s*\("
    )
    matches = forbidden.findall(production)
    if matches:
        print(f"raw production registry transitions remain: {matches}",
              file=sys.stderr)
        return 1
    exchange = EXCHANGE.read_text(encoding="utf-8")
    required_exchange = (
        "wyl_service_auth_registry_session_participant_new_for_write",
        "wyl_service_auth_registry_session_participant_reserve",
        "wyl_service_auth_registry_session_participant_activate",
        "wyl_service_auth_registry_session_participant_remove_exact",
    )
    if any(symbol not in exchange for symbol in required_exchange):
        print("service exchange is not capability-bound", file=sys.stderr)
        return 1
    header = HEADER.read_text(encoding="utf-8")
    required_header = (
        "session_participant_new_for_write",
        "write_participant_revoke_zero_survivors",
    )
    if any(symbol not in header for symbol in required_header):
        print("typed coordination participant API is incomplete",
              file=sys.stderr)
        return 1
    remediation_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            DOMAIN,
            DOMAIN_HEADER,
            REMEDIATION_COORDINATOR,
            REMEDIATION_COORDINATOR_HEADER,
        )
    )
    legacy_remediation = (
        "invalidate_credential",
        "invalidation_data",
    )
    if any(symbol in remediation_sources for symbol in legacy_remediation):
        print("legacy post-commit remediation callback remains",
              file=sys.stderr)
        return 1
    required_remediation = (
        "service_mutation_prepare_registry",
        "service_mutation_prepare_commit_evidence",
        "wyl_service_auth_selector_init_credential_generation",
        "runtime->registry == NULL",
        ".registry = runtime->registry",
    )
    if any(symbol not in remediation_sources for symbol in required_remediation):
        print("handoff remediation is not registry capability-bound",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

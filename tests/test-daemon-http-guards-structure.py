#!/usr/bin/env python3
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

for needle in (
    '"/service-principals"',
    '"/service-credentials"',
):
    if source.count(needle) != 1:
        raise SystemExit(f"service-credential route must be registered once: {needle}")

for needle in (
    '"/service-credential-operations/reconcile"',
    '"/auth/service-token"',
):
    if source.count(needle) != 1:
        raise SystemExit(f"service-credential route must be registered once: {needle}")

for forbidden in ("/operation-status", "/service-credential-operations/status"):
    if forbidden in source:
        raise SystemExit(f"unexpected service-credential alias: {forbidden}")

if source.count('soup_server_add_handler (server, "/') < 10:
    raise SystemExit("daemon route table scan unexpectedly small")

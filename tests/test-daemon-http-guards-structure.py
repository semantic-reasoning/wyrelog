#!/usr/bin/env python3
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

for needle in (
    '"/service-principals"',
    '"/service-credentials"',
    '"/service-credential-operations"',
    '"/auth/service-token"',
    'service-principals',
    'service-credentials',
    'service-credential-operations',
):
    if needle in source:
        raise SystemExit(f"unexpected service-credential route token: {needle}")

if source.count('soup_server_add_handler (server, "/') < 10:
    raise SystemExit("daemon route table scan unexpectedly small")

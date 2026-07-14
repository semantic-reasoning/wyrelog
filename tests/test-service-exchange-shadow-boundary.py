#!/usr/bin/env python3
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

required = (
    'PRAGMA main.table_info(',
    'PRAGMA main.foreign_key_list(',
    'pragma_index_list(?, \'main\')',
    'PRAGMA main.index_xinfo(',
    'FROM main.service_exchange_audit_intentions',
    'INSERT INTO main.service_exchange_audit_intentions(',
    'UPDATE main.service_authority_writer_gate',
    'FROM main.service_authority_writer_gate',
    'main.sqlite_schema',
)
missing = [token for token in required if token not in source]
if missing:
    raise SystemExit("missing main qualification: " + ", ".join(missing))

runtime = source[source.index("service_exchange_select_one"):]
forbidden = (
    'FROM service_exchange_audit_intentions',
    'INSERT INTO service_exchange_audit_intentions',
    'UPDATE service_exchange_audit_intentions',
    'DELETE FROM service_exchange_audit_intentions',
)
present = [token for token in forbidden if token in runtime]
if present:
    raise SystemExit("unqualified exchange CRUD: " + ", ".join(present))

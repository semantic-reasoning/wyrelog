#!/usr/bin/env python3
from pathlib import Path
import sys

header = Path(sys.argv[1]).read_text(encoding="utf-8")
meson = Path(sys.argv[2]).read_text(encoding="utf-8")

if header.count('#include "wyl-id-private.h"') != 0:
    raise SystemExit("bare private ID include is forbidden")
if header.count('#include "wyrelog/wyl-id-private.h"') != 1:
    raise SystemExit("root-qualified private ID include must occur exactly once")

start = meson.index("test_service_exchange_private_root_include = executable(")
end = meson.index("\n)\n", start)
target = meson[start:end]
if "include_directories('../wyrelog')" in target or "-I../wyrelog" in target:
    raise SystemExit("root consumer must not compensate with ../wyrelog include")

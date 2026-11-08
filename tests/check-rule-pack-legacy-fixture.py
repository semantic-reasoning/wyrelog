#!/usr/bin/env python3
"""Verify byte-exact sources of the offline pre-recursion reader fixture."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]) / "tests/fixtures/rule-pack-reader-6201ee46"
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
assert manifest["revision"] == "6201ee46a3cfd5199e694e35d279741c9fd94103"
assert len(manifest["files"]) == 4
for item in manifest["files"]:
    data = (root / item["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == item["sha256"], item["path"]
    blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    assert hashlib.sha1(blob).hexdigest() == item["git_blob"], item["path"]
print("pre-1504 compiler/renderer fixture provenance: OK")

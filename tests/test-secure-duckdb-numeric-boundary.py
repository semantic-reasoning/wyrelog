#!/usr/bin/env python3
"""Guard the POSIX DuckDB adapter's checked numeric conversion boundary."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
handle = (
    root / "wyrelog" / "fact" / "secure-duckdb-file-handle-private.cc"
).read_text(encoding="utf-8")
filesystem = (
    root / "wyrelog" / "fact" / "secure-duckdb-filesystem-private.cc"
).read_text(encoding="utf-8")
meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
runtime_test = (
    root / "tests" / "test-secure-duckdb-filesystem.cc"
).read_text(encoding="utf-8")

required_proofs = (
    "#if !defined(G_OS_WIN32) && !defined(__APPLE__)",
    "SSIZE_MAX",
    "DuckDB idx_t must remain an unsigned integer",
    "POSIX off_t must remain a signed integer",
    "size_t must represent every positive ssize_t",
    "adapter arithmetic requires uint64_t to represent size_t",
    "checked_range (int64_t byte_count, duckdb::idx_t location)",
    "checked_progress_offset (const CheckedRange &range, size_t progress)",
    "checked_transfer (ssize_t amount, size_t remaining)",
    "checked_size (int64_t size)",
    "checked_stat_size (off_t size)",
    "status.st_mtimespec.tv_sec",
    "status.st_mtimespec.tv_nsec",
)
for token in required_proofs:
    if token not in handle:
        raise SystemExit(f"DuckDB numeric proof boundary drifted: {token}")

expected_syscalls = {
    "pread (": 2,
    "pwrite (": 2,
    "ftruncate (": 1,
    "fstat (": 3,
    "fsync (": 1,
}
for call, count in expected_syscalls.items():
    if handle.count(call) != count:
        raise SystemExit(
            f"DuckDB syscall boundary drifted: {call} expected {count}"
        )
    if call in filesystem:
        raise SystemExit(f"filesystem adapter bypassed checked handle: {call}")

required_delegation = (
    "bounded_handle (handle).ReadAt (buffer, bytes, location);",
    "bounded_handle (handle).WriteAt (buffer, bytes, location);",
    "return bounded_handle (handle).ReadSome (buffer, bytes);",
    "return bounded_handle (handle).WriteSome (buffer, bytes);",
    "bounded_handle (handle).SeekTo (location);",
    "return bounded_handle (handle).SeekPosition ();",
    "bounded_handle (handle).TruncateTo (size);",
    "bounded_handle (handle).Sync ();",
)
for token in required_delegation:
    if token not in filesystem:
        raise SystemExit(f"DuckDB adapter delegation drifted: {token}")

# Every narrowing conversion on syscall/cursor values is deliberately listed.
# A new cast must therefore extend the checked helpers and this proof together.
narrowing = re.compile(
    r"static_cast\s*<\s*(?:size_t|off_t|duckdb::idx_t|int64_t)\s*>"
)
if len(narrowing.findall(handle)) != 9:
    raise SystemExit("unchecked narrowing appeared outside the audited helpers")
if len(narrowing.findall(filesystem)) != 1:
    raise SystemExit("filesystem cursor narrowing boundary drifted")

required_cast_contexts = (
    "static_cast < duckdb::idx_t > (std::numeric_limits < off_t >::max ())",
    "static_cast < size_t >(bytes), static_cast < off_t > (offset)",
    "static_cast < off_t > (unsigned_offset + unsigned_progress)",
    "static_cast < size_t > (transferred)",
    "static_cast < duckdb::idx_t > (transferred)",
    "static_cast < int64_t > (transferred)",
    "return static_cast < off_t > (size);",
    "return static_cast < int64_t > (size);",
)
for token in required_cast_contexts:
    if token not in handle:
        raise SystemExit(f"audited handle narrowing changed: {token}")
if (
    "checked_file_size_cursor (int64_t size)" not in filesystem
    or "return static_cast < duckdb::idx_t > (size);" not in filesystem
):
    raise SystemExit("append cursor narrowing escaped its checked boundary")

cursor_mutations = re.findall(r"\boffset_\s*(?:\+=|=)", handle)
if len(cursor_mutations) != 3:
    raise SystemExit("DuckDB cursor gained an unaudited mutation")
if handle.count("offset_ += transfer.cursor;") != 2:
    raise SystemExit("read/write cursor updates bypass checked_transfer")
if "offset_ = location;" not in handle:
    raise SystemExit("seek cursor assignment boundary drifted")

for token in (
    "/secure-duckdb-filesystem/denial-numeric",
    "#define _DARWIN_C_SOURCE 1",
    "O_NOFOLLOW",
    "static_cast < int64_t > (SSIZE_MAX)",
    "static_cast < duckdb::idx_t > (LLONG_MAX)",
    "std::numeric_limits < off_t >::max ()",
):
    if token not in runtime_test:
        raise SystemExit(f"numeric runtime boundary coverage drifted: {token}")

if meson.count("test('duckdb-numeric-boundary'") != 1:
    raise SystemExit("DuckDB numeric source-boundary test is not registered once")

print("DuckDB checked numeric boundary: OK")

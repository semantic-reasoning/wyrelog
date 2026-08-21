#!/usr/bin/env python3
"""Guard the platform-neutral DuckDB adapter's checked numeric conversion boundary."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
handle = (
    root / "wyrelog" / "fact" / "secure-duckdb-file-handle-private.cc"
).read_text(encoding="utf-8")
handle_header = (
    root / "wyrelog" / "fact" / "secure-duckdb-file-handle-private.hpp"
).read_text(encoding="utf-8")
filesystem = (
    root / "wyrelog" / "fact" / "secure-duckdb-filesystem-private.cc"
).read_text(encoding="utf-8")
session_header = (
    root / "wyrelog" / "fact" / "artifact-io-session-private.h"
).read_text(encoding="utf-8")
meson = (root / "tests" / "meson.build").read_text(encoding="utf-8")
runtime_test = (
    root / "tests" / "test-secure-duckdb-filesystem.cc"
).read_text(encoding="utf-8")

# Ensure no raw POSIX descriptor remains in FileHandle / PendingBinding headers
if "int\n      fd_;" in handle_header or "int fd_;" in handle_header:
    raise SystemExit("raw int fd_ leaked into secure-duckdb-file-handle-private.hpp")

required_proofs = (
    "DuckDB idx_t must remain an unsigned integer",
    "DuckDB idx_t must represent every nonnegative uint64_t",
    "adapter arithmetic requires uint64_t to represent size_t",
    "checked_range (int64_t byte_count, duckdb::idx_t location)",
    "checked_transfer (gsize amount, size_t remaining)",
    "checked_size (int64_t size)",
    "checked_stat_size (uint64_t size)",
    "checked_timestamp (uint64_t seconds, uint32_t nanoseconds)",
)
for token in required_proofs:
    if token not in handle:
        raise SystemExit(f"DuckDB numeric proof boundary drifted: {token}")

# Ensure no raw POSIX syscalls are made directly from the C++ adapter handle or filesystem
forbidden_syscalls = (
    "pread (",
    "pwrite (",
    "ftruncate (",
    "fstat (",
    "fsync (",
)
for call in forbidden_syscalls:
    if call in handle:
        raise SystemExit(f"raw POSIX syscall in C++ file handle: {call}")
    if call in filesystem:
        raise SystemExit(f"filesystem adapter bypassed checked handle: {call}")

# Ensure all 9 platform-neutral session operations are declared and used
required_session_ops = (
    "wyl_fact_artifact_io_session_read",
    "wyl_fact_artifact_io_session_write",
    "wyl_fact_artifact_io_session_flush",
    "wyl_fact_artifact_io_session_truncate",
    "wyl_fact_artifact_io_session_size",
    "wyl_fact_artifact_io_session_last_modified",
    "wyl_fact_artifact_io_session_revalidate",
    "wyl_fact_artifact_io_session_finish",
    "wyl_fact_artifact_io_session_abort",
)
for op in required_session_ops:
    if op not in session_header:
        raise SystemExit(f"session operation missing from artifact-io-session-private.h: {op}")
    if op != "wyl_fact_artifact_io_session_abort" and op not in handle:
        raise SystemExit(f"file handle does not invoke session operation: {op}")

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

# Every narrowing conversion on session values is audited.
narrowing = re.compile(
    r"static_cast\s*<\s*(?:size_t|duckdb::idx_t|int64_t)\s*>"
)
if len(narrowing.findall(handle)) != 7:
    raise SystemExit(f"unchecked narrowing in handle ({len(narrowing.findall(handle))})")
if len(narrowing.findall(filesystem)) != 1:
    raise SystemExit("filesystem cursor narrowing boundary drifted")

required_cast_contexts = (
    "static_cast < duckdb::idx_t > (std::numeric_limits < uint64_t >::max ())",
    "static_cast < size_t >(bytes), static_cast < uint64_t > (offset)",
    "static_cast < size_t > (transferred)",
    "static_cast < duckdb::idx_t > (transferred)",
    "static_cast < int64_t > (transferred)",
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
    "O_NOFOLLOW",
    "fs::canonical (created_root)",
    "root = path_to_utf8 (canonical_root);",
    "const auto ssize_max = std::numeric_limits < int64_t >::max ();",
    "static_cast < duckdb::idx_t > (LLONG_MAX)",
):
    if token not in runtime_test:
        raise SystemExit(f"numeric runtime boundary coverage drifted: {token}")

if meson.count("test('duckdb-numeric-boundary'") != 1:
    raise SystemExit("DuckDB numeric source-boundary test is not registered once")

print("DuckDB checked numeric boundary: OK")

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.hpp>
#include <string_view>

/* Keep the adapter tied to the source-pinned C++ ABI.  This header is private
 * and intentionally exposes no filesystem or pathname authority to C callers. */
static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.5",
    "bounded DuckDB filesystem requires v1.5.5");
static_assert (sizeof (duckdb::FileOpenFlags) > 0,
    "DuckDB FileOpenFlags ABI unavailable");
static_assert (sizeof (duckdb::FileHandle) > 0,
    "DuckDB FileHandle ABI unavailable");
static_assert (sizeof (duckdb::FileSystem) > 0,
    "DuckDB FileSystem ABI unavailable");

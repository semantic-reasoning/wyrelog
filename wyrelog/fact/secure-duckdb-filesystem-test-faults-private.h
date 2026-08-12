/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* One-shot fault points injected into the secure DuckDB filesystem for tests.
 * Declared with C linkage so the POSIX artifact-IO session (compiled as C) and
 * the C++ filesystem implementation share the same symbols. */
typedef enum
{
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_NONE = 0,
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION = 1U << 0,
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_TEMP_REGISTRATION = 1U << 1,
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION = 1U << 2,
} WylSecureDuckdbFilesystemTestFault;

void wyl_secure_duckdb_filesystem_set_test_faults (guint faults);
bool wyl_secure_duckdb_filesystem_take_test_fault (guint fault);

#ifdef __cplusplus
}
#endif

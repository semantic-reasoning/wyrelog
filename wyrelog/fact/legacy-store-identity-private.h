/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.h>
#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_FACT_LEGACY_IDENTITY_BIND_STORE = 0,
  WYL_FACT_LEGACY_IDENTITY_BIND_COMPOUND,
} WylFactLegacyIdentityBindEntry;

typedef enum
{
  WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_NONE = 0,
  WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_STORE_SECOND_ROW,
  WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_COMPOUND_SECOND_ROW,
} WylFactLegacyIdentityTestFault;

/* The caller must hold the owning wyl_fact_store_t lock.  This is the only
 * legacy writer for the tenant_id/graph_id identity pair. */
wyrelog_error_t wyl_fact_legacy_identity_validate_unlocked
  (duckdb_connection conn, const gchar * tenant_id, const gchar * graph_id,
    gboolean bind_if_empty, WylFactLegacyIdentityBindEntry entry);

/* Single-shot test seam.  The selected bind executes a two-row INSERT whose
 * second row deliberately conflicts with the first, proving statement-level
 * rollback rather than merely returning before the statement executes. */
void wyl_fact_legacy_identity_set_test_fault
  (WylFactLegacyIdentityTestFault fault);

G_END_DECLS;

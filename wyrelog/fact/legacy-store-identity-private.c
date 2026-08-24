/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "legacy-store-identity-private.h"

static gint legacy_identity_test_fault;

static gboolean
consume_test_fault (WylFactLegacyIdentityTestFault fault)
{
  return g_atomic_int_compare_and_exchange (&legacy_identity_test_fault,
             fault, WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_NONE);
}

void
wyl_fact_legacy_identity_set_test_fault (WylFactLegacyIdentityTestFault fault)
{
  if (fault >= WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_NONE
      && fault <= WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_COMPOUND_SECOND_ROW)
    g_atomic_int_set (&legacy_identity_test_fault, fault);
}

static wyrelog_error_t
metadata_value_unlocked (duckdb_connection conn, const gchar *key,
    gchar **out_value)
{
  duckdb_prepared_statement statement = NULL;
  duckdb_result result = { 0 };

  *out_value = NULL;
  if (duckdb_prepare (conn,
      "SELECT value FROM main.fact_store_metadata WHERE key = ?;",
      &statement) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (statement, 1, key) != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (statement, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&statement);

  idx_t rows = duckdb_row_count (&result);
  if (rows > 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  if (rows == 1) {
    gchar *value = duckdb_value_varchar (&result, 0, 0);
    *out_value = g_strdup (value);
    duckdb_free (value);
    if (*out_value == NULL) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_NOMEM;
    }
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static WylFactLegacyIdentityTestFault
fault_for_entry (WylFactLegacyIdentityBindEntry entry)
{
  return entry == WYL_FACT_LEGACY_IDENTITY_BIND_STORE ?
         WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_STORE_SECOND_ROW :
         WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_COMPOUND_SECOND_ROW;
}

static wyrelog_error_t
insert_complete_identity_unlocked (duckdb_connection conn,
    const gchar *tenant_id, const gchar *graph_id,
    WylFactLegacyIdentityBindEntry entry)
{
  duckdb_prepared_statement statement = NULL;
  static const gchar *sql =
      "INSERT INTO main.fact_store_metadata(key,value) "
      "VALUES ('tenant_id', ?), (?, ?);";
  if (duckdb_prepare (conn, sql, &statement) != DuckDBSuccess)
    return WYRELOG_E_IO;

  const gchar *second_key = consume_test_fault (fault_for_entry (entry)) ?
      "tenant_id" : "graph_id";
  duckdb_state state = duckdb_bind_varchar (statement, 1, tenant_id)
      | duckdb_bind_varchar (statement, 2, second_key)
      | duckdb_bind_varchar (statement, 3, graph_id);
  if (state != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    return WYRELOG_E_IO;
  }
  state = duckdb_execute_prepared (statement, NULL);
  duckdb_destroy_prepare (&statement);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
repair_missing_graph_unlocked (duckdb_connection conn, const gchar *graph_id)
{
  duckdb_prepared_statement statement = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "INSERT INTO main.fact_store_metadata(key,value) "
      "SELECT 'graph_id', ? "
      "WHERE NOT EXISTS (SELECT 1 FROM main.fact_batches);";
  if (duckdb_prepare (conn, sql, &statement) != DuckDBSuccess)
    return WYRELOG_E_INTERNAL;
  if (duckdb_bind_varchar (statement, 1, graph_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (statement, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&statement);
  idx_t changed = duckdb_rows_changed (&result);
  duckdb_destroy_result (&result);
  return changed == 1 ? WYRELOG_E_OK : WYRELOG_E_INTERNAL;
}

wyrelog_error_t
wyl_fact_legacy_identity_validate_unlocked (duckdb_connection conn,
    const gchar *tenant_id, const gchar *graph_id, gboolean bind_if_empty,
    WylFactLegacyIdentityBindEntry entry)
{
  if (conn == NULL || tenant_id == NULL || graph_id == NULL
      || (entry != WYL_FACT_LEGACY_IDENTITY_BIND_STORE
      && entry != WYL_FACT_LEGACY_IDENTITY_BIND_COMPOUND))
    return WYRELOG_E_INVALID;

  g_autofree gchar *store_kind = NULL;
  g_autofree gchar *stored_tenant = NULL;
  g_autofree gchar *stored_graph = NULL;
  wyrelog_error_t rc = metadata_value_unlocked (conn, "store_kind",
          &store_kind);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (g_strcmp0 (store_kind, "wyrelog.fact") != 0)
    return WYRELOG_E_POLICY;

  rc = metadata_value_unlocked (conn, "tenant_id", &stored_tenant);
  if (rc == WYRELOG_E_OK)
    rc = metadata_value_unlocked (conn, "graph_id", &stored_graph);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (stored_graph != NULL && stored_tenant == NULL)
    return WYRELOG_E_INTERNAL;
  if (stored_tenant != NULL && stored_graph == NULL) {
    if (!bind_if_empty || g_strcmp0 (stored_tenant, tenant_id) != 0)
      return WYRELOG_E_INTERNAL;
    return repair_missing_graph_unlocked (conn, graph_id);
  }
  if (stored_tenant == NULL) {
    if (!bind_if_empty)
      return WYRELOG_E_POLICY;
    return insert_complete_identity_unlocked (conn, tenant_id, graph_id,
               entry);
  }

  return g_strcmp0 (stored_tenant, tenant_id) == 0
         && g_strcmp0 (stored_graph, graph_id) == 0 ? WYRELOG_E_OK :
         WYRELOG_E_POLICY;
}

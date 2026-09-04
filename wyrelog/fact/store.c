/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "store-private.h"

#include <string.h>

#include "compound-private.h"
#include "legacy-store-identity-private.h"
#include "store-duckdb-config-test-seams-private.h"
#include "store-identity-private.h"
#include "wyrelog/wyl-log-private.h"

/* Opaque even in non-secure builds so the store handle can carry the live
 * provisioned-pair bridge as a plain pointer (NULL everywhere but the secure
 * provisioned open). */
typedef struct WylSecureDuckdbBridge WylSecureDuckdbBridge;

#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
#include "fact/graph-locator-private.h"
#include "fact/secure-duckdb-bridge-private.h"

/* Bind the retained provisioning pair to a bounded namespace.  Defined in the
 * artifact namespace unit; declared here for the live provisioned open. */
extern wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
  (WylFactGraphProvisionedPair * pair, WylFactArtifactNamespace ** out);
#endif

struct wyl_fact_store_t
{
  duckdb_database db;
  duckdb_connection conn;
  GMutex lock;
#ifdef WYL_TEST_HANDLE_SEAMS
  WylFactStoreBatchFault batch_fault;
#endif
  gchar *identity_tenant_id;
  gchar *identity_graph_id;
  gchar *identity_store_uuid;
  guint64 identity_format_version;
  guint64 identity_path_encoding_version;
  WylSecureDuckdbBridge *provisioned_bridge;
#if defined(WYL_TEST_HANDLE_SEAMS)
  WylFactStoreForgetTransactionTestHook forget_transaction_test_hook;
  gpointer forget_transaction_test_hook_data;
  guint duckdb_configured_settings;
  gboolean duckdb_read_only;
#endif
};

static WylFactStoreIdentityValidationTestHook identity_validation_test_hook;
static gpointer identity_validation_test_hook_data;
G_LOCK_DEFINE_STATIC (identity_validation_test_hook);

#if defined(WYL_TEST_HANDLE_SEAMS)
static WylFactStoreDuckdbConfigSetting duckdb_config_failure =
    WYL_FACT_STORE_DUCKDB_CONFIG_NONE;
G_LOCK_DEFINE_STATIC (duckdb_config_failure);
#endif

static const gchar *
fact_store_duckdb_setting_name (WylFactStoreDuckdbConfigSetting setting)
{
  switch (setting) {
    case WYL_FACT_STORE_DUCKDB_CONFIG_THREADS:
      return "threads";
    case WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS:
      return "enable_external_access";
    case WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS:
      return "allow_community_extensions";
    case WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS:
      return "autoinstall_known_extensions";
    case WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS:
      return "autoload_known_extensions";
    case WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE:
      return "access_mode";
    case WYL_FACT_STORE_DUCKDB_CONFIG_NONE:
      break;
  }
  return NULL;
}

static duckdb_state
fact_store_duckdb_set_config (duckdb_config config,
    WylFactStoreDuckdbConfigSetting setting, const gchar *value)
{
#if defined(WYL_TEST_HANDLE_SEAMS)
  gboolean fail = FALSE;
  G_LOCK (duckdb_config_failure);
  if (duckdb_config_failure == setting) {
    duckdb_config_failure = WYL_FACT_STORE_DUCKDB_CONFIG_NONE;
    fail = TRUE;
  }
  G_UNLOCK (duckdb_config_failure);
  if (fail)
    return DuckDBError;
#endif
  return duckdb_set_config (config, fact_store_duckdb_setting_name (setting),
             value);
}

static duckdb_state
fact_store_duckdb_apply_config (duckdb_config config,
    WylFactStoreDuckdbConfigSetting setting, const gchar *value,
    guint *configured_settings)
{
  duckdb_state state = fact_store_duckdb_set_config (config, setting, value);
  if (state == DuckDBSuccess && configured_settings != NULL)
    *configured_settings |= 1u << setting;
  return state;
}

static wyrelog_error_t
create_hardened_duckdb_config (gboolean read_only, duckdb_config *out_config,
    guint *out_configured_settings)
{
  duckdb_config config = NULL;

  *out_config = NULL;
  if (out_configured_settings != NULL)
    *out_configured_settings = 0;
  if (duckdb_create_config (&config) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (fact_store_duckdb_apply_config (config,
      WYL_FACT_STORE_DUCKDB_CONFIG_THREADS, "1", out_configured_settings)
      != DuckDBSuccess
      || fact_store_duckdb_apply_config (config,
      WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS, "false",
      out_configured_settings)
      != DuckDBSuccess
      || fact_store_duckdb_apply_config (config,
      WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS, "false",
      out_configured_settings)
      != DuckDBSuccess
      || fact_store_duckdb_apply_config (config,
      WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS, "false",
      out_configured_settings)
      != DuckDBSuccess
      || fact_store_duckdb_apply_config (config,
      WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS, "false",
      out_configured_settings)
      != DuckDBSuccess
      || (read_only && fact_store_duckdb_apply_config (config,
      WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE, "READ_ONLY",
      out_configured_settings)
      != DuckDBSuccess)) {
    duckdb_destroy_config (&config);
    return WYRELOG_E_IO;
  }
  *out_config = config;
  return WYRELOG_E_OK;
}

#if defined(WYL_TEST_HANDLE_SEAMS)
void
wyl_fact_store_duckdb_config_fail_once_for_test
  (WylFactStoreDuckdbConfigSetting setting)
{
  G_LOCK (duckdb_config_failure);
  duckdb_config_failure = setting;
  G_UNLOCK (duckdb_config_failure);
}

wyrelog_error_t
wyl_fact_store_duckdb_config_get_for_test (wyl_fact_store_t *store,
    WylFactStoreDuckdbConfigSetting setting, gchar **out_value)
{
  if (out_value != NULL)
    *out_value = NULL;
  const gchar *name = fact_store_duckdb_setting_name (setting);
  if (store == NULL || name == NULL || out_value == NULL)
    return WYRELOG_E_INVALID;

  if ((store->duckdb_configured_settings & (1u << setting)) == 0)
    return WYRELOG_E_IO;
  if (setting == WYL_FACT_STORE_DUCKDB_CONFIG_THREADS)
    *out_value = g_strdup ("1");
  else if (setting == WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE)
    *out_value = g_strdup (store->duckdb_read_only ? "read_only" : "read_write");
  else
    *out_value = g_strdup ("false");
  return WYRELOG_E_OK;
}
#endif

static wyrelog_error_t
open_duckdb_with_thread_budget (const gchar *path, duckdb_database *out_db,
    guint *out_configured_settings)
{
  duckdb_config config = NULL;
  char *error = NULL;
  const gchar *effective_path = path;

  if (out_db != NULL)
    *out_db = NULL;
  if (path != NULL && g_strcmp0 (path, ":memory:") == 0)
    effective_path = NULL;

  if (create_hardened_duckdb_config (FALSE, &config, out_configured_settings)
      != WYRELOG_E_OK)
    return WYRELOG_E_IO;
  if (duckdb_open_ext (effective_path, out_db, config, &error) != DuckDBSuccess) {
    if (out_db != NULL && *out_db != NULL)
      duckdb_close (out_db);
    duckdb_destroy_config (&config);
    if (error != NULL)
      duckdb_free (error);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_config (&config);
  if (error != NULL)
    duckdb_free (error);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
open_duckdb_identified (const gchar *path, gboolean read_only,
    duckdb_database *out_db, guint *out_configured_settings)
{
  duckdb_config config = NULL;
  char *error = NULL;

  *out_db = NULL;
  if (create_hardened_duckdb_config (read_only, &config,
      out_configured_settings) != WYRELOG_E_OK)
    return WYRELOG_E_IO;
  if (duckdb_open_ext (path, out_db, config, &error) != DuckDBSuccess) {
    if (*out_db != NULL)
      duckdb_close (out_db);
    duckdb_destroy_config (&config);
    if (error != NULL)
      duckdb_free (error);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_config (&config);
  if (error != NULL)
    duckdb_free (error);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
exec_sql (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result = { 0 };
  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static void
append_duckdb_identifier (GString *out, const gchar *identifier)
{
  g_string_append_c (out, '"');
  for (const gchar * p = identifier; p != NULL && *p != '\0'; p++) {
    if (*p == '"')
      g_string_append_c (out, '"');
    g_string_append_c (out, *p);
  }
  g_string_append_c (out, '"');
}

static gchar *
hex_identifier (const gchar *prefix, const gchar *value)
{
  g_autoptr (GString) out = g_string_new (prefix);
  if (value == NULL)
    return g_string_free (g_steal_pointer (&out), FALSE);
  for (const gchar * p = value; *p != '\0'; p++)
    g_string_append_printf (out, "_%02x", (guchar) * p);
  return g_string_free (g_steal_pointer (&out), FALSE);
}

static const gchar *
duckdb_type_for_column (const gchar *column_type)
{
  if (g_strcmp0 (column_type, "symbol") == 0
      || g_strcmp0 (column_type, "string") == 0)
    return "VARCHAR";
  if (g_strcmp0 (column_type, "int64") == 0)
    return "BIGINT";
  if (g_strcmp0 (column_type, "bool") == 0)
    return "BOOLEAN";
  if (g_strcmp0 (column_type, "compound_ref") == 0)
    return "BIGINT";
  return NULL;
}

static gboolean
value_matches_column (const wyl_fact_value_t *value,
    const wyl_policy_fact_relation_schema_column_t *column)
{
  if (value->type == WYL_FACT_VALUE_NULL)
    return column->nullable;
  if (g_strcmp0 (column->column_type, "symbol") == 0)
    return value->type == WYL_FACT_VALUE_SYMBOL && value->as.text != NULL;
  if (g_strcmp0 (column->column_type, "string") == 0)
    return value->type == WYL_FACT_VALUE_STRING && value->as.text != NULL;
  if (g_strcmp0 (column->column_type, "int64") == 0)
    return value->type == WYL_FACT_VALUE_INT64;
  if (g_strcmp0 (column->column_type, "bool") == 0)
    return value->type == WYL_FACT_VALUE_BOOL;
  if (g_strcmp0 (column->column_type, "compound_ref") == 0)
    return value->type == WYL_FACT_VALUE_COMPOUND_REF;
  return FALSE;
}

static wyrelog_error_t
validate_schema_shape (const wyl_policy_fact_relation_schema_options_t *schema)
{
  if (schema == NULL || schema->tenant_id == NULL || schema->graph_id == NULL
      || schema->namespace_id == NULL || schema->relation_name == NULL
      || schema->schema_version == 0 || schema->columns == NULL
      || schema->n_columns == 0)
    return WYRELOG_E_INVALID;
  for (gsize i = 0; i < schema->n_columns; i++) {
    if (schema->columns[i].column_name == NULL
        || duckdb_type_for_column (schema->columns[i].column_type) == NULL)
      return WYRELOG_E_INVALID;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_batch_shape (const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch)
{
  wyrelog_error_t rc = validate_schema_shape (schema);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (batch == NULL || batch->batch_id == NULL || batch->batch_id[0] == '\0'
      || batch->tenant_id == NULL || batch->graph_id == NULL
      || batch->namespace_id == NULL || batch->relation_name == NULL
      || batch->schema_version == 0 || batch->idempotency_key == NULL
      || batch->idempotency_key[0] == '\0' || batch->rows == NULL
      || batch->n_rows == 0)
    return WYRELOG_E_INVALID;
  if (batch->op != WYL_FACT_STORE_OP_ASSERT
      && batch->op != WYL_FACT_STORE_OP_RETRACT)
    return WYRELOG_E_INVALID;
  if (g_strcmp0 (schema->tenant_id, batch->tenant_id) != 0
      || g_strcmp0 (schema->graph_id, batch->graph_id) != 0
      || g_strcmp0 (schema->namespace_id, batch->namespace_id) != 0
      || g_strcmp0 (schema->relation_name, batch->relation_name) != 0
      || schema->schema_version != batch->schema_version)
    return WYRELOG_E_POLICY;
  for (gsize i = 0; i < batch->n_rows; i++) {
    const wyl_fact_row_t *row = &batch->rows[i];
    if (row->values == NULL || row->n_values != schema->n_columns)
      return WYRELOG_E_POLICY;
    for (gsize j = 0; j < schema->n_columns; j++) {
      if (!value_matches_column (&row->values[j], &schema->columns[j]))
        return WYRELOG_E_POLICY;
    }
  }
  return WYRELOG_E_OK;
}

static gchar *
batch_content_hash (const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch)
{
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL)
    return NULL;
  g_checksum_update (checksum, (const guchar *) batch->tenant_id, -1);
  g_checksum_update (checksum, (const guchar *) "\0", 1);
  g_checksum_update (checksum, (const guchar *) batch->graph_id, -1);
  g_checksum_update (checksum, (const guchar *) "\0", 1);
  g_checksum_update (checksum, (const guchar *) batch->namespace_id, -1);
  g_checksum_update (checksum, (const guchar *) "\0", 1);
  g_checksum_update (checksum, (const guchar *) batch->relation_name, -1);
  g_checksum_update (checksum, (const guchar *) "\0", 1);
  g_checksum_update (checksum, (const guchar *) &batch->schema_version,
      sizeof (batch->schema_version));
  g_checksum_update (checksum, (const guchar *) &batch->op, sizeof (batch->op));
  for (gsize i = 0; i < batch->n_rows; i++) {
    for (gsize j = 0; j < schema->n_columns; j++) {
      const wyl_fact_value_t *value = &batch->rows[i].values[j];
      g_checksum_update (checksum, (const guchar *) &value->type,
          sizeof (value->type));
      switch (value->type) {
        case WYL_FACT_VALUE_NULL:
          break;
        case WYL_FACT_VALUE_SYMBOL:
        case WYL_FACT_VALUE_STRING:
          g_checksum_update (checksum, (const guchar *) value->as.text, -1);
          break;
        case WYL_FACT_VALUE_INT64:
          g_checksum_update (checksum, (const guchar *) &value->as.int64_value,
              sizeof (value->as.int64_value));
          break;
        case WYL_FACT_VALUE_BOOL:
          g_checksum_update (checksum, (const guchar *) &value->as.bool_value,
              sizeof (value->as.bool_value));
          break;
        case WYL_FACT_VALUE_COMPOUND_REF:
          g_checksum_update (checksum, (const guchar *) &value->as.compound_ref,
              sizeof (value->as.compound_ref));
          break;
      }
      g_checksum_update (checksum, (const guchar *) "\0", 1);
    }
  }
  return g_strdup (g_checksum_get_string (checksum));
}

static wyrelog_error_t
table_exists_unlocked (wyl_fact_store_t *store, const gchar *table_name,
    gboolean *out_exists)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  if (store == NULL || table_name == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;
  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?;";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_varchar (stmt, 1, table_name) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  *out_exists = duckdb_value_int64 (&result, 0, 0) > 0;
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reject_audit_database_unlocked (wyl_fact_store_t *store)
{
  gboolean has_audit_events = FALSE;
  gboolean has_fact_metadata = FALSE;
  wyrelog_error_t rc = table_exists_unlocked (store, "audit_events",
          &has_audit_events);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = table_exists_unlocked (store, "fact_store_metadata", &has_fact_metadata);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (has_audit_events)
    return WYRELOG_E_POLICY;
  if (!has_fact_metadata)
    return WYRELOG_E_OK;

  duckdb_result result = { 0 };
  if (duckdb_query (store->conn,
      "SELECT value FROM fact_store_metadata WHERE key = 'store_kind';",
      &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  gchar *store_kind = duckdb_value_varchar (&result, 0, 0);
  gboolean valid = g_strcmp0 (store_kind, "wyrelog.fact") == 0;
  duckdb_free (store_kind);
  duckdb_destroy_result (&result);
  return valid ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
validate_store_scope_unlocked (wyl_fact_store_t *store, const gchar *tenant_id,
    const gchar *graph_id, gboolean bind_if_empty)
{
  if (store->identity_tenant_id != NULL)
    return g_strcmp0 (store->identity_tenant_id, tenant_id) == 0
           && g_strcmp0 (store->identity_graph_id, graph_id) == 0 ?
           WYRELOG_E_OK : WYRELOG_E_POLICY;

  gboolean has_fact_metadata = FALSE;
  wyrelog_error_t rc = table_exists_unlocked (store, "fact_store_metadata",
          &has_fact_metadata);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!has_fact_metadata)
    return WYRELOG_E_POLICY;
  return wyl_fact_legacy_identity_validate_unlocked (store->conn, tenant_id,
             graph_id, bind_if_empty, WYL_FACT_LEGACY_IDENTITY_BIND_STORE);
}


void wyl_fact_store_identity_set_validation_test_hook
  (WylFactStoreIdentityValidationTestHook hook, gpointer user_data)
{
  G_LOCK (identity_validation_test_hook);
  identity_validation_test_hook = hook;
  identity_validation_test_hook_data = user_data;
  G_UNLOCK (identity_validation_test_hook);
}

#if defined(WYL_TEST_HANDLE_SEAMS)
void
wyl_fact_store_set_forget_transaction_test_hook (wyl_fact_store_t *store,
    WylFactStoreForgetTransactionTestHook hook, gpointer user_data)
{
  if (store == NULL)
    return;
  g_mutex_lock (&store->lock);
  store->forget_transaction_test_hook = hook;
  store->forget_transaction_test_hook_data = user_data;
  g_mutex_unlock (&store->lock);
}

static wyrelog_error_t
forget_transaction_test_hook_unlocked (wyl_fact_store_t *store,
    WylFactStoreForgetTransactionTestPhase phase)
{
  if (store->forget_transaction_test_hook == NULL)
    return WYRELOG_E_OK;
  return store->forget_transaction_test_hook (phase,
             store->forget_transaction_test_hook_data);
}
#endif

static gboolean
fact_identity_bind_param (duckdb_prepared_statement statement, idx_t index,
    const WylFactStoreIdentityCell *cell)
{
  switch (cell->type) {
    case WYL_FACT_STORE_IDENTITY_CELL_NULL:
      return duckdb_bind_null (statement, index) == DuckDBSuccess;
    case WYL_FACT_STORE_IDENTITY_CELL_INT64:
      return duckdb_bind_int64 (statement, index, cell->as.int64_value)
             == DuckDBSuccess;
    case WYL_FACT_STORE_IDENTITY_CELL_BYTES:
      return cell->as.bytes.data != NULL
             && duckdb_bind_varchar_length (statement, index,
                 (const gchar *) cell->as.bytes.data, cell->as.bytes.length)
             == DuckDBSuccess;
  }
  return FALSE;
}

static wyrelog_error_t
fact_identity_execute (gpointer context, const gchar *sql,
    const WylFactStoreIdentityCell *params, gsize n_params,
    WylFactStoreIdentityRowFunc row_func, gpointer row_data, guint64 *out_rows)
{
  wyl_fact_store_t *store = context;
  duckdb_prepared_statement statement = NULL;
  duckdb_result result = { 0 };
  if (out_rows != NULL)
    *out_rows = 0;
  if (store == NULL || sql == NULL || out_rows == NULL
      || (n_params != 0 && params == NULL)
      || duckdb_prepare (store->conn, sql, &statement) != DuckDBSuccess)
    return WYRELOG_E_IO;
  for (gsize i = 0; i < n_params; i++)
    if (!fact_identity_bind_param (statement, i + 1, &params[i])) {
      duckdb_destroy_prepare (&statement);
      return WYRELOG_E_IO;
    }
  if (duckdb_execute_prepared (statement, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&statement);

  idx_t n_rows = duckdb_row_count (&result);
  idx_t n_columns = duckdb_column_count (&result);
  *out_rows = n_rows;
  idx_t chunk_count = duckdb_result_chunk_count (result);
  gboolean keep_going = TRUE;
  for (idx_t chunk_index = 0;
      chunk_index < chunk_count && row_func != NULL && keep_going;
      chunk_index++) {
    duckdb_data_chunk chunk = duckdb_result_get_chunk (result, chunk_index);
    if (chunk == NULL) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_IO;
    }
    idx_t chunk_size = duckdb_data_chunk_get_size (chunk);
    for (idx_t row = 0; row < chunk_size && keep_going; row++) {
      WylFactStoreIdentityCell *cells =
          g_try_new0 (WylFactStoreIdentityCell, n_columns);
      if (n_columns != 0 && cells == NULL) {
        duckdb_destroy_data_chunk (&chunk);
        duckdb_destroy_result (&result);
        return WYRELOG_E_NOMEM;
      }
      gboolean valid = TRUE;
      for (idx_t column = 0; column < n_columns; column++) {
        duckdb_vector vector = duckdb_data_chunk_get_vector (chunk, column);
        uint64_t *validity = duckdb_vector_get_validity (vector);
        if (validity != NULL && !duckdb_validity_row_is_valid (validity, row)) {
          cells[column].type = WYL_FACT_STORE_IDENTITY_CELL_NULL;
          continue;
        }
        duckdb_type type = duckdb_column_type (&result, column);
        if (type == DUCKDB_TYPE_BIGINT) {
          const gint64 *values = duckdb_vector_get_data (vector);
          cells[column].type = WYL_FACT_STORE_IDENTITY_CELL_INT64;
          cells[column].as.int64_value = values[row];
        } else if (type == DUCKDB_TYPE_VARCHAR || type == DUCKDB_TYPE_BLOB) {
          duckdb_string_t *values = duckdb_vector_get_data (vector);
          cells[column].type = WYL_FACT_STORE_IDENTITY_CELL_BYTES;
          cells[column].as.bytes.data = (const guint8 *)
              duckdb_string_t_data (&values[row]);
          cells[column].as.bytes.length = duckdb_string_t_length (values[row]);
        } else {
          valid = FALSE;
          break;
        }
      }
      keep_going = valid && row_func (cells, n_columns, row_data);
      g_free (cells);
    }
    duckdb_destroy_data_chunk (&chunk);
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

/* The column list of fact_forget_intent, shared by CREATE TABLE and by the
 * rebuild that widens its state CHECK.  One definition: a rebuild that
 * restated the columns could silently drop the primary key or a constraint,
 * which is exactly what CREATE TABLE AS SELECT does. */
#define FACT_FORGET_INTENT_COLUMNS \
  "  op_uuid         VARCHAR PRIMARY KEY," \
  "  batch_id        VARCHAR NOT NULL," \
  "  tenant_id       VARCHAR NOT NULL," \
  "  graph_id        VARCHAR NOT NULL," \
  "  namespace_id    VARCHAR NOT NULL," \
  "  relation_name   VARCHAR NOT NULL," \
  "  schema_version  BIGINT NOT NULL," \
  "  projection_table VARCHAR NOT NULL," \
  "  content_hash    VARCHAR NOT NULL," \
  "  idempotency_key VARCHAR NOT NULL," \
  "  operator        VARCHAR NOT NULL," \
  "  reason          VARCHAR NOT NULL," \
  "  rows_purged     BIGINT NOT NULL," \
  "  state           VARCHAR NOT NULL " \
  "    CHECK (state IN ('PENDING', 'COMPLETED', 'QUARANTINED'))," \
  "  created_at_us   BIGINT NOT NULL," \
  "  completed_at_us BIGINT"

static void
fact_identity_validation_barrier (gpointer context)
{
  wyl_fact_store_t *store = context;
  WylFactStoreIdentityValidationTestHook hook = NULL;
  gpointer hook_data = NULL;
  G_LOCK (identity_validation_test_hook);
  hook = identity_validation_test_hook;
  hook_data = identity_validation_test_hook_data;
  identity_validation_test_hook = NULL;
  identity_validation_test_hook_data = NULL;
  G_UNLOCK (identity_validation_test_hook);
  if (hook != NULL)
    hook (store->db, hook_data);
}

wyrelog_error_t
wyl_fact_store_open_identified (const gchar *path,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result, wyl_fact_store_t **out_store)
{
  if (out_store != NULL)
    *out_store = NULL;
  if (out_result != NULL)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  if (path == NULL || path[0] == '\0' || out_store == NULL
      || out_result == NULL
      || !wyl_fact_store_identity_input_is_valid (identity)
      || !wyl_fact_store_identity_mode_is_valid (mode))
    return WYRELOG_E_INVALID;

  wyl_fact_store_identity_process_guard_lock ();
  wyl_fact_store_t *self = g_new0 (wyl_fact_store_t, 1);
  guint *configured_settings = NULL;
#if defined(WYL_TEST_HANDLE_SEAMS)
  configured_settings = &self->duckdb_configured_settings;
  self->duckdb_read_only =
      mode == WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY;
#endif
  wyrelog_error_t rc = open_duckdb_identified (path,
          mode == WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &self->db,
          configured_settings);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    g_free (self);
    wyl_fact_store_identity_process_guard_unlock ();
    return rc;
  }
  if (duckdb_connect (self->db, &self->conn) != DuckDBSuccess) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    duckdb_close (&self->db);
    g_free (self);
    wyl_fact_store_identity_process_guard_unlock ();
    return WYRELOG_E_IO;
  }
  g_mutex_init (&self->lock);
  WylFactStoreIdentityExecutor executor = {
    self, fact_identity_execute, fact_identity_validation_barrier
  };
  rc = wyl_fact_store_identity_execute (&executor, identity, mode, out_result);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_store_close (self);
    wyl_fact_store_identity_process_guard_unlock ();
    return rc;
  }

  self->identity_tenant_id = g_strdup (identity->tenant_id);
  self->identity_graph_id = g_strdup (identity->graph_id);
  self->identity_store_uuid = g_strdup (identity->store_uuid);
  self->identity_format_version = identity->format_version;
  self->identity_path_encoding_version = identity->path_encoding_version;
  *out_store = self;
  wyl_fact_store_identity_process_guard_unlock ();
  return WYRELOG_E_OK;
}

#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
wyrelog_error_t
wyl_fact_store_open_provisioned_pair (WylFactGraphProvisionedPair *pair,
    const WylFactStoreIdentity *identity, gboolean writable,
    wyl_fact_store_t **out_store)
{
  if (out_store != NULL)
    *out_store = NULL;
  if (pair == NULL || out_store == NULL
      || !wyl_fact_store_identity_input_is_valid (identity))
    return WYRELOG_E_INVALID;

  wyl_fact_store_identity_process_guard_lock ();
  WylFactArtifactNamespace *namespace_ = NULL;
  wyrelog_error_t rc =
      wyl_fact_artifact_namespace_open_provisioned_pair_internal (pair,
          &namespace_);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_store_identity_process_guard_unlock ();
    return rc;
  }

  /* Build a live bounded instance and hand back the C-API handle.  The bridge
   * keeps only the lease + health; the store owns the instance and closes it. */
  WylSecureDuckdbBridge *bridge = NULL;
  duckdb_database db = NULL;
  duckdb_connection conn = NULL;
  rc = wyl_secure_duckdb_bridge_open_live_pair (namespace_, writable, &bridge,
          &db, &conn);
  wyl_fact_artifact_namespace_free (namespace_);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_store_identity_process_guard_unlock ();
    return rc;
  }

  wyl_fact_store_t *self = g_new0 (wyl_fact_store_t, 1);
  self->db = db;
  self->conn = conn;
  self->provisioned_bridge = bridge;
  g_mutex_init (&self->lock);
  rc = reject_audit_database_unlocked (self);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_store_close (self);
    wyl_fact_store_identity_process_guard_unlock ();
    return rc;
  }

  self->identity_tenant_id = g_strdup (identity->tenant_id);
  self->identity_graph_id = g_strdup (identity->graph_id);
  self->identity_store_uuid = g_strdup (identity->store_uuid);
  self->identity_format_version = identity->format_version;
  self->identity_path_encoding_version = identity->path_encoding_version;
  *out_store = self;
  wyl_fact_store_identity_process_guard_unlock ();
  return WYRELOG_E_OK;
}
#endif

wyrelog_error_t
wyl_fact_store_open (const gchar *path, wyl_fact_store_t **out_store)
{
  if (out_store == NULL)
    return WYRELOG_E_INVALID;
  *out_store = NULL;

  wyl_fact_store_t *self = g_new0 (wyl_fact_store_t, 1);
  guint *configured_settings = NULL;
#if defined(WYL_TEST_HANDLE_SEAMS)
  configured_settings = &self->duckdb_configured_settings;
#endif
  if (open_duckdb_with_thread_budget (path, &self->db, configured_settings)
      != WYRELOG_E_OK) {
    g_free (self);
    return WYRELOG_E_IO;
  }
  if (duckdb_connect (self->db, &self->conn) != DuckDBSuccess) {
    duckdb_close (&self->db);
    g_free (self);
    return WYRELOG_E_INTERNAL;
  }
  g_mutex_init (&self->lock);
  wyrelog_error_t rc = reject_audit_database_unlocked (self);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_store_close (self);
    return rc;
  }
  *out_store = self;
  return WYRELOG_E_OK;
}

void
wyl_fact_store_close (wyl_fact_store_t *store)
{
  if (store == NULL)
    return;
  duckdb_disconnect (&store->conn);
  duckdb_close (&store->db);
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
  /* Order matters: the disconnect + close above destruct the instance so its
   * shutdown checkpoint runs through the bounded filesystem under the lease the
   * bridge still holds.  Only now is it safe to observe health and release the
   * lease. */
  if (store->provisioned_bridge != NULL)
    (void) wyl_secure_duckdb_bridge_release_live (store->provisioned_bridge);
#endif
  g_mutex_clear (&store->lock);
  g_free (store->identity_tenant_id);
  g_free (store->identity_graph_id);
  g_free (store->identity_store_uuid);
  g_free (store);
}

duckdb_connection
wyl_fact_store_get_connection (wyl_fact_store_t *store)
{
  if (store == NULL) {
    duckdb_connection zero;
    memset (&zero, 0, sizeof (zero));
    return zero;
  }
  return store->conn;
}

void
wyl_fact_store_lock (wyl_fact_store_t *store)
{
  if (store != NULL)
    g_mutex_lock (&store->lock);
}

void
wyl_fact_store_unlock (wyl_fact_store_t *store)
{
  if (store != NULL)
    g_mutex_unlock (&store->lock);
}

wyrelog_error_t
wyl_fact_store_create_schema (wyl_fact_store_t *store)
{
  if (store == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&store->lock);
  wyrelog_error_t rc = reject_audit_database_unlocked (store);
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (store->conn,
            "CREATE TABLE IF NOT EXISTS fact_store_metadata ("
            "  key VARCHAR PRIMARY KEY,"
            "  value VARCHAR NOT NULL"
            ");"
            "INSERT OR IGNORE INTO fact_store_metadata (key, value) "
            "VALUES ('store_kind', 'wyrelog.fact');"
            "CREATE TABLE IF NOT EXISTS fact_batches ("
            "  batch_id VARCHAR PRIMARY KEY,"
            "  tenant_id VARCHAR NOT NULL,"
            "  graph_id VARCHAR NOT NULL,"
            "  namespace_id VARCHAR NOT NULL,"
            "  relation_name VARCHAR NOT NULL,"
            "  schema_version BIGINT NOT NULL,"
            "  source VARCHAR,"
            "  request_id VARCHAR,"
            "  idempotency_key VARCHAR NOT NULL UNIQUE,"
            "  op VARCHAR NOT NULL CHECK (op IN ('assert', 'retract')),"
            "  row_count BIGINT NOT NULL,"
            "  content_hash VARCHAR NOT NULL,"
            "  created_at_us BIGINT NOT NULL"
            ");"
            "CREATE TABLE IF NOT EXISTS fact_event_log ("
            "  seq BIGINT PRIMARY KEY,"
            "  batch_id VARCHAR NOT NULL,"
            "  tenant_id VARCHAR NOT NULL,"
            "  graph_id VARCHAR NOT NULL,"
            "  namespace_id VARCHAR NOT NULL,"
            "  relation_name VARCHAR NOT NULL,"
            "  schema_version BIGINT NOT NULL,"
            "  op VARCHAR NOT NULL CHECK (op IN ('assert', 'retract')),"
            "  created_at_us BIGINT NOT NULL,"
            "  valid BOOLEAN NOT NULL,"
            "  FOREIGN KEY (batch_id) REFERENCES fact_batches (batch_id)" ");"
            "CREATE TABLE IF NOT EXISTS fact_forget_audit ("
            "  id            BIGINT PRIMARY KEY,"
            "  batch_id      VARCHAR NOT NULL,"
            "  tenant_id     VARCHAR NOT NULL,"
            "  graph_id      VARCHAR NOT NULL,"
            "  operator      VARCHAR NOT NULL,"
            "  reason        VARCHAR NOT NULL,"
            "  rows_purged   BIGINT NOT NULL,"
            "  created_at_us BIGINT NOT NULL" ");"
            /*
             * Durable forget intention: the crash-convergence anchor.  A row is
             * committed PENDING before any destructive step and flipped
             * COMPLETED in the same transaction as its audit record, so at most
             * one PENDING intent per batch ever needs replay and replay is a
             * single idempotent re-run.  op_uuid (not the reusable batch_id)
             * is the operation identity; content_hash + idempotency_key pin the
             * exact target batch so a reused identifier cannot be deleted.  It
             * stores only identifiers and the fingerprint, never fact content.
             */
            "CREATE TABLE IF NOT EXISTS fact_forget_intent ("
            FACT_FORGET_INTENT_COLUMNS ");");
  if (rc == WYRELOG_E_OK)
    rc = reject_audit_database_unlocked (store);
  g_mutex_unlock (&store->lock);
  return rc;
}

static wyrelog_error_t
validate_batch_compound_refs (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch)
{
  for (gsize i = 0; i < batch->n_rows; i++) {
    for (gsize j = 0; j < schema->n_columns; j++) {
      if (g_strcmp0 (schema->columns[j].column_type, "compound_ref") != 0)
        continue;
      const wyl_fact_value_t *value = &batch->rows[i].values[j];
      if (value->type == WYL_FACT_VALUE_NULL)
        continue;
      gboolean exists = FALSE;
      wyrelog_error_t rc = wyl_fact_compound_ref_exists (store,
              batch->tenant_id, batch->graph_id, batch->namespace_id,
              value->as.compound_ref, &exists);
      if (rc != WYRELOG_E_OK)
        return rc;
      if (!exists)
        return WYRELOG_E_POLICY;
    }
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_store_table_exists (wyl_fact_store_t *store, const gchar *table_name,
    gboolean *out_exists)
{
  if (store == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&store->lock);
  wyrelog_error_t rc = table_exists_unlocked (store, table_name, out_exists);
  g_mutex_unlock (&store->lock);
  return rc;
}

gchar *
wyl_fact_store_projection_table_name (const
    wyl_policy_fact_relation_schema_options_t *schema)
{
  if (validate_schema_shape (schema) != WYRELOG_E_OK)
    return NULL;
  g_autofree gchar *ns = hex_identifier ("n", schema->namespace_id);
  g_autofree gchar *rel = hex_identifier ("r", schema->relation_name);
  g_autofree gchar *tenant = hex_identifier ("t", schema->tenant_id);
  g_autofree gchar *graph = hex_identifier ("g", schema->graph_id);
  return g_strdup_printf ("rel_%s_%s_%s_%s_v%u", tenant, graph, ns, rel,
             schema->schema_version);
}

static wyrelog_error_t
validate_projection_shape_unlocked (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const gchar *table_name)
{
  duckdb_result result = { 0 };
  g_autofree gchar *sql =
      g_strdup_printf
        ("SELECT name, type, \"notnull\" FROM pragma_table_info('%s') ORDER BY cid;",
          table_name);
  if (duckdb_query (store->conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  idx_t rows = duckdb_row_count (&result);
  if (rows != schema->n_columns + 6) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  for (gsize i = 0; i < schema->n_columns; i++) {
    gchar *name = duckdb_value_varchar (&result, 0, i);
    gchar *type = duckdb_value_varchar (&result, 1, i);
    gboolean notnull = duckdb_value_int64 (&result, 2, i) != 0;
    gboolean ok = g_strcmp0 (name, schema->columns[i].column_name) == 0
        && g_strcmp0 (type,
            duckdb_type_for_column (schema->columns[i].column_type)) == 0
        && notnull == !schema->columns[i].nullable;
    duckdb_free (name);
    duckdb_free (type);
    if (!ok) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_POLICY;
    }
  }

  const gchar *metadata_names[] = {
    "__wyl_tenant_id",
    "__wyl_graph_id",
    "__wyl_seq",
    "__wyl_batch_id",
    "__wyl_row_index",
    "__wyl_valid",
  };
  const gchar *metadata_types[] = {
    "VARCHAR",
    "VARCHAR",
    "BIGINT",
    "VARCHAR",
    "BIGINT",
    "BOOLEAN",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (metadata_names); i++) {
    idx_t row = schema->n_columns + i;
    gchar *name = duckdb_value_varchar (&result, 0, row);
    gchar *type = duckdb_value_varchar (&result, 1, row);
    gboolean ok = g_strcmp0 (name, metadata_names[i]) == 0
        && g_strcmp0 (type, metadata_types[i]) == 0
        && duckdb_value_int64 (&result, 2, row) != 0;
    duckdb_free (name);
    duckdb_free (type);
    if (!ok) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_POLICY;
    }
  }

  duckdb_destroy_result (&result);

  g_autofree gchar *unique_sql =
      g_strdup_printf
        ("SELECT COUNT(*) FROM duckdb_constraints() WHERE table_name = '%s' "
          "AND constraint_type = 'UNIQUE' "
          "AND len(constraint_column_names) = 2 "
          "AND list_contains(constraint_column_names, '__wyl_batch_id') "
          "AND list_contains(constraint_column_names, '__wyl_row_index');",
          table_name);
  if (duckdb_query (store->conn, unique_sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gboolean has_unique = duckdb_value_int64 (&result, 0, 0) == 1;
  duckdb_destroy_result (&result);
  return has_unique ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_store_ensure_projection (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    gchar **out_table_name)
{
  if (out_table_name != NULL)
    *out_table_name = NULL;
  if (store == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = validate_schema_shape (schema);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *table = wyl_fact_store_projection_table_name (schema);
  if (table == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (GString) ddl = g_string_new ("CREATE TABLE IF NOT EXISTS ");
  append_duckdb_identifier (ddl, table);
  g_string_append (ddl, " (");
  for (gsize i = 0; i < schema->n_columns; i++) {
    if (i > 0)
      g_string_append (ddl, ", ");
    append_duckdb_identifier (ddl, schema->columns[i].column_name);
    g_string_append_printf (ddl, " %s%s",
        duckdb_type_for_column (schema->columns[i].column_type),
        schema->columns[i].nullable ? "" : " NOT NULL");
  }
  g_string_append (ddl,
      ", __wyl_tenant_id VARCHAR NOT NULL, __wyl_graph_id VARCHAR NOT NULL, "
      "__wyl_seq BIGINT NOT NULL, __wyl_batch_id VARCHAR NOT NULL, "
      "__wyl_row_index BIGINT NOT NULL, __wyl_valid BOOLEAN NOT NULL, "
      "UNIQUE (__wyl_batch_id, __wyl_row_index));");

  g_mutex_lock (&store->lock);
  rc = reject_audit_database_unlocked (store);
  if (rc == WYRELOG_E_OK)
    rc = validate_store_scope_unlocked (store, schema->tenant_id,
            schema->graph_id, TRUE);
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (store->conn, ddl->str);
  if (rc == WYRELOG_E_OK)
    rc = validate_projection_shape_unlocked (store, schema, table);
  g_mutex_unlock (&store->lock);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (out_table_name != NULL)
    *out_table_name = g_steal_pointer (&table);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_store_validate_projection (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    gboolean *out_exists)
{
  if (out_exists != NULL)
    *out_exists = FALSE;
  if (store == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = validate_schema_shape (schema);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *table = wyl_fact_store_projection_table_name (schema);
  if (table == NULL)
    return WYRELOG_E_INVALID;

  g_mutex_lock (&store->lock);
  rc = reject_audit_database_unlocked (store);
  if (rc == WYRELOG_E_OK)
    rc = validate_store_scope_unlocked (store, schema->tenant_id,
            schema->graph_id, FALSE);
  gboolean exists = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = table_exists_unlocked (store, table, &exists);
  if (rc == WYRELOG_E_OK)
    *out_exists = exists;
  if (rc == WYRELOG_E_OK && exists)
    rc = validate_projection_shape_unlocked (store, schema, table);
  g_mutex_unlock (&store->lock);
  return rc;
}

static wyrelog_error_t
existing_batch_matches_unlocked (wyl_fact_store_t *store,
    const wyl_fact_store_batch_t *batch, const gchar *content_hash,
    gboolean *out_exists)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT batch_id, tenant_id, graph_id, namespace_id, relation_name, "
      "schema_version, source, request_id, idempotency_key, op, row_count, "
      "content_hash FROM fact_batches "
      "WHERE batch_id = ? OR idempotency_key = ?;";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_varchar (stmt, 1, batch->batch_id) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, batch->idempotency_key)
      != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) == 0) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_OK;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  *out_exists = TRUE;
  gchar *batch_id = duckdb_value_varchar (&result, 0, 0);
  gchar *tenant = duckdb_value_varchar (&result, 1, 0);
  gchar *graph = duckdb_value_varchar (&result, 2, 0);
  gchar *namespace_id = duckdb_value_varchar (&result, 3, 0);
  gchar *relation_name = duckdb_value_varchar (&result, 4, 0);
  gchar *source = duckdb_value_varchar (&result, 6, 0);
  gchar *request = duckdb_value_varchar (&result, 7, 0);
  gchar *key = duckdb_value_varchar (&result, 8, 0);
  gchar *op = duckdb_value_varchar (&result, 9, 0);
  gchar *stored_hash = duckdb_value_varchar (&result, 11, 0);
  const gchar *expected_op =
      batch->op == WYL_FACT_STORE_OP_RETRACT ? "retract" : "assert";
  gboolean matches = g_strcmp0 (batch_id, batch->batch_id) == 0
      && g_strcmp0 (tenant, batch->tenant_id) == 0
      && g_strcmp0 (graph, batch->graph_id) == 0
      && g_strcmp0 (namespace_id, batch->namespace_id) == 0
      && g_strcmp0 (relation_name, batch->relation_name) == 0
      && duckdb_value_int64 (&result, 5, 0) == batch->schema_version
      && g_strcmp0 (source, batch->source) == 0
      && g_strcmp0 (request, batch->request_id) == 0
      && g_strcmp0 (key, batch->idempotency_key) == 0
      && g_strcmp0 (op, expected_op) == 0
      && duckdb_value_int64 (&result, 10, 0) == (gint64) batch->n_rows
      && g_strcmp0 (stored_hash, content_hash) == 0;
  duckdb_free (batch_id);
  duckdb_free (tenant);
  duckdb_free (graph);
  duckdb_free (namespace_id);
  duckdb_free (relation_name);
  duckdb_free (source);
  duckdb_free (request);
  duckdb_free (key);
  duckdb_free (op);
  duckdb_free (stored_hash);
  duckdb_destroy_result (&result);
  return matches ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
next_sequence_unlocked (wyl_fact_store_t *store, gint64 *out_seq)
{
  duckdb_result result = { 0 };
  if (duckdb_query (store->conn,
      "SELECT COALESCE(MAX(seq), 0) + 1 FROM fact_event_log;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  *out_seq = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
insert_batch_unlocked (wyl_fact_store_t *store,
    const wyl_fact_store_batch_t *batch, const gchar *content_hash,
    gint64 created_at_us)
{
  duckdb_prepared_statement stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_batches "
      "(batch_id, tenant_id, graph_id, namespace_id, relation_name, "
      " schema_version, source, request_id, idempotency_key, op, row_count, "
      " content_hash, created_at_us) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, batch->batch_id)
      | duckdb_bind_varchar (stmt, 2, batch->tenant_id)
      | duckdb_bind_varchar (stmt, 3, batch->graph_id)
      | duckdb_bind_varchar (stmt, 4, batch->namespace_id)
      | duckdb_bind_varchar (stmt, 5, batch->relation_name)
      | duckdb_bind_int64 (stmt, 6, batch->schema_version)
      | (batch->source != NULL ? duckdb_bind_varchar (stmt, 7, batch->source)
      : duckdb_bind_null (stmt, 7))
      | (batch->request_id != NULL ? duckdb_bind_varchar (stmt, 8,
      batch->request_id) : duckdb_bind_null (stmt, 8))
      | duckdb_bind_varchar (stmt, 9, batch->idempotency_key)
      | duckdb_bind_varchar (stmt, 10,
          batch->op == WYL_FACT_STORE_OP_RETRACT ? "retract" : "assert")
      | duckdb_bind_int64 (stmt, 11, (gint64) batch->n_rows)
      | duckdb_bind_varchar (stmt, 12, content_hash)
      | duckdb_bind_int64 (stmt, 13, created_at_us);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_event_unlocked (wyl_fact_store_t *store,
    const wyl_fact_store_batch_t *batch, gint64 seq, gint64 created_at_us)
{
  duckdb_prepared_statement stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_event_log "
      "(seq, batch_id, tenant_id, graph_id, namespace_id, relation_name, "
      " schema_version, op, created_at_us, valid) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  const gchar *op = batch->op == WYL_FACT_STORE_OP_RETRACT ? "retract" :
      "assert";
  gboolean valid = batch->op != WYL_FACT_STORE_OP_RETRACT;
  duckdb_state ok = duckdb_bind_int64 (stmt, 1, seq)
      | duckdb_bind_varchar (stmt, 2, batch->batch_id)
      | duckdb_bind_varchar (stmt, 3, batch->tenant_id)
      | duckdb_bind_varchar (stmt, 4, batch->graph_id)
      | duckdb_bind_varchar (stmt, 5, batch->namespace_id)
      | duckdb_bind_varchar (stmt, 6, batch->relation_name)
      | duckdb_bind_int64 (stmt, 7, batch->schema_version)
      | duckdb_bind_varchar (stmt, 8, op)
      | duckdb_bind_int64 (stmt, 9, created_at_us)
      | duckdb_bind_boolean (stmt, 10, valid);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
append_value (duckdb_appender appender, const wyl_fact_value_t *value)
{
  if (value->type == WYL_FACT_VALUE_NULL)
    return duckdb_append_null (appender) == DuckDBSuccess ? WYRELOG_E_OK :
           WYRELOG_E_IO;
  switch (value->type) {
    case WYL_FACT_VALUE_SYMBOL:
    case WYL_FACT_VALUE_STRING:
      return duckdb_append_varchar (appender, value->as.text) == DuckDBSuccess
          ? WYRELOG_E_OK : WYRELOG_E_IO;
    case WYL_FACT_VALUE_INT64:
      return duckdb_append_int64 (appender, value->as.int64_value)
             == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    case WYL_FACT_VALUE_BOOL:
      return duckdb_append_bool (appender, value->as.bool_value)
             == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    case WYL_FACT_VALUE_COMPOUND_REF:
      return duckdb_append_int64 (appender, value->as.compound_ref)
             == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    case WYL_FACT_VALUE_NULL:
    default:
      return WYRELOG_E_INVALID;
  }
}

/* Stable, backend-independent logical size of a single fact value, used for
 * quota accounting (issue #546).  Fixed-width scalars count their natural
 * width; text counts its UTF-8 byte length; NULL counts nothing. */
static gint64
fact_value_logical_bytes (const wyl_fact_value_t *value)
{
  switch (value->type) {
    case WYL_FACT_VALUE_SYMBOL:
    case WYL_FACT_VALUE_STRING:
      return value->as.text != NULL ? (gint64) strlen (value->as.text) : 0;
    case WYL_FACT_VALUE_INT64:
    case WYL_FACT_VALUE_COMPOUND_REF:
      return 8;
    case WYL_FACT_VALUE_BOOL:
      return 1;
    case WYL_FACT_VALUE_NULL:
    default:
      return 0;
  }
}

/* Logical byte size of a batch's fact payload (schema columns only; the
 * bookkeeping columns the appender adds are storage overhead, not logical
 * fact bytes). */
static gint64
batch_logical_bytes (const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch)
{
  gint64 total = 0;
  for (gsize i = 0; i < batch->n_rows; i++) {
    for (gsize j = 0; j < schema->n_columns; j++)
      total += fact_value_logical_bytes (&batch->rows[i].values[j]);
  }
  return total;
}

wyrelog_error_t
wyl_fact_store_append_batch (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted)
{
  return wyl_fact_store_append_batch_delta (store, schema, batch, out_inserted,
             NULL);
}

#ifdef WYL_TEST_HANDLE_SEAMS
void
wyl_fact_store_set_batch_fault_once_for_test (wyl_fact_store_t *store,
    WylFactStoreBatchFault fault)
{
  if (store == NULL)
    return;
  g_mutex_lock (&store->lock);
  store->batch_fault = fault;
  g_mutex_unlock (&store->lock);
}

/* Consume the armed fault.  Called with store->lock held. */
static WylFactStoreBatchFault
take_batch_fault_unlocked (wyl_fact_store_t *store)
{
  WylFactStoreBatchFault fault = store->batch_fault;
  store->batch_fault = WYL_FACT_STORE_BATCH_FAULT_NONE;
  return fault;
}
#endif

wyrelog_error_t
wyl_fact_store_append_batch_delta (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted,
    wyl_fact_commit_delta_t *out_delta)
{
  if (out_inserted != NULL)
    *out_inserted = FALSE;
  wyl_fact_commit_delta_init (out_delta);
  if (store == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = validate_batch_shape (schema, batch);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *table = NULL;
  rc = wyl_fact_store_ensure_projection (store, schema, &table);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = validate_batch_compound_refs (store, schema, batch);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *content_hash = batch_content_hash (schema, batch);
  if (content_hash == NULL)
    return WYRELOG_E_NOMEM;

  g_mutex_lock (&store->lock);
  gboolean exists = FALSE;
  rc = reject_audit_database_unlocked (store);
  if (rc == WYRELOG_E_OK)
    rc = validate_store_scope_unlocked (store, batch->tenant_id,
            batch->graph_id, FALSE);
  if (rc == WYRELOG_E_OK)
    rc = existing_batch_matches_unlocked (store, batch, content_hash, &exists);
  if (rc == WYRELOG_E_OK && exists) {
    if (out_inserted != NULL)
      *out_inserted = FALSE;
    g_mutex_unlock (&store->lock);
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK) {
    g_mutex_unlock (&store->lock);
    return rc;
  }

  rc = exec_sql (store->conn, "BEGIN TRANSACTION;");
#ifdef WYL_TEST_HANDLE_SEAMS
  WylFactStoreBatchFault batch_fault = take_batch_fault_unlocked (store);
  if (rc == WYRELOG_E_OK
      && batch_fault == WYL_FACT_STORE_BATCH_FAULT_BEFORE_COMMIT)
    rc = WYRELOG_E_IO;
#endif
  gint64 first_seq = 0;
  gint64 created_at_us = g_get_real_time ();
  if (rc == WYRELOG_E_OK)
    rc = next_sequence_unlocked (store, &first_seq);
  if (rc == WYRELOG_E_OK)
    rc = insert_batch_unlocked (store, batch, content_hash, created_at_us);

  duckdb_appender appender = NULL;
  if (rc == WYRELOG_E_OK
      && duckdb_appender_create (store->conn, NULL, table, &appender)
      != DuckDBSuccess)
    rc = WYRELOG_E_IO;
  for (gsize i = 0; rc == WYRELOG_E_OK && i < batch->n_rows; i++) {
    gint64 seq = first_seq + (gint64) i;
    if (duckdb_appender_begin_row (appender) != DuckDBSuccess) {
      rc = WYRELOG_E_IO;
      break;
    }
    for (gsize j = 0; rc == WYRELOG_E_OK && j < schema->n_columns; j++)
      rc = append_value (appender, &batch->rows[i].values[j]);
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_varchar (appender, batch->tenant_id)
          == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_varchar (appender, batch->graph_id)
          == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_int64 (appender, seq) == DuckDBSuccess ?
          WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_varchar (appender, batch->batch_id) == DuckDBSuccess ?
          WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_int64 (appender, (gint64) i) == DuckDBSuccess ?
          WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_bool (appender, batch->op != WYL_FACT_STORE_OP_RETRACT)
          == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK
        && duckdb_appender_end_row (appender) != DuckDBSuccess)
      rc = WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = insert_event_unlocked (store, batch, seq, created_at_us);
  }
  if (appender != NULL
      && duckdb_appender_destroy (&appender) != DuckDBSuccess
      && rc == WYRELOG_E_OK)
    rc = WYRELOG_E_IO;
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK
      && batch_fault == WYL_FACT_STORE_BATCH_FAULT_AT_COMMIT)
    rc = WYRELOG_E_IO;
#endif
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (store->conn, "COMMIT;");
  else
    (void) exec_sql (store->conn, "ROLLBACK;");
  g_mutex_unlock (&store->lock);
  if (rc == WYRELOG_E_OK) {
    if (out_inserted != NULL)
      *out_inserted = TRUE;
    if (out_delta != NULL) {
      out_delta->inserted = TRUE;
      out_delta->committed_row_delta = (gint64) batch->n_rows;
      out_delta->logical_byte_delta = batch_logical_bytes (schema, batch);
    }
  }
  return rc;
}

/* Retract (soft-delete) facts from the store using tombstone pattern.
 * Records a retract batch as append-only operation. Caller retains ownership of
 * batch.rows and batch.values members; only the struct itself is copied.
 * out_inserted=TRUE indicates batch was recorded (regardless of matching asserts).
 */
wyrelog_error_t
wyl_fact_store_retract_batch (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted)
{
  return wyl_fact_store_retract_batch_delta (store, schema, batch, out_inserted,
             NULL);
}

wyrelog_error_t
wyl_fact_store_retract_batch_delta (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted,
    wyl_fact_commit_delta_t *out_delta)
{
  if (out_inserted != NULL)
    *out_inserted = FALSE;
  wyl_fact_commit_delta_init (out_delta);
  if (store == NULL)
    return WYRELOG_E_INVALID;
  if (batch == NULL)
    return WYRELOG_E_INVALID;
  /* Shallow copy: struct only, not pointed-to rows/values (caller-owned). */
  wyl_fact_store_batch_t *batch_copy = g_memdup2 (batch, sizeof (*batch));
  if (batch_copy == NULL)
    return WYRELOG_E_NOMEM;
  batch_copy->op = WYL_FACT_STORE_OP_RETRACT;
  wyrelog_error_t rc = wyl_fact_store_append_batch_delta (store, schema,
          batch_copy, out_inserted, out_delta);
  g_free (batch_copy);
  return rc;
}

/* Tier-2 retract-by-batch-id: SELECT trigger metadata + valid rows, then
 * INSERT a fresh retract batch tombstone — all under one mutex+transaction.
 * Must NOT call wyl_fact_store_retract_batch (that would require lock release
 * between SELECT and INSERT, opening a race window). */

typedef struct
{
  gchar *tenant_id;
  gchar *graph_id;
  gchar *namespace_id;
  gchar *relation_name;
  gint64 schema_version;
  gchar *op;
} TriggerBatchScope;

static void
trigger_batch_scope_clear (TriggerBatchScope *scope)
{
  if (scope == NULL)
    return;
  g_free (scope->tenant_id);
  g_free (scope->graph_id);
  g_free (scope->namespace_id);
  g_free (scope->relation_name);
  g_free (scope->op);
  memset (scope, 0, sizeof (*scope));
}

static wyrelog_error_t
lookup_batch_scope_unlocked (wyl_fact_store_t *store,
    const gchar *trigger_batch_id, TriggerBatchScope *out_scope,
    gboolean *out_found)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  *out_found = FALSE;
  memset (out_scope, 0, sizeof (*out_scope));
  static const gchar *sql =
      "SELECT tenant_id, graph_id, namespace_id, relation_name, "
      "schema_version, op FROM fact_batches WHERE batch_id = ?;";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_varchar (stmt, 1, trigger_batch_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) == 0) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_OK;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  gchar *tenant = duckdb_value_varchar (&result, 0, 0);
  gchar *graph = duckdb_value_varchar (&result, 1, 0);
  gchar *namespace_id = duckdb_value_varchar (&result, 2, 0);
  gchar *relation_name = duckdb_value_varchar (&result, 3, 0);
  gint64 schema_version = duckdb_value_int64 (&result, 4, 0);
  gchar *op = duckdb_value_varchar (&result, 5, 0);
  out_scope->tenant_id = g_strdup (tenant);
  out_scope->graph_id = g_strdup (graph);
  out_scope->namespace_id = g_strdup (namespace_id);
  out_scope->relation_name = g_strdup (relation_name);
  out_scope->schema_version = schema_version;
  out_scope->op = g_strdup (op);
  duckdb_free (tenant);
  duckdb_free (graph);
  duckdb_free (namespace_id);
  duckdb_free (relation_name);
  duckdb_free (op);
  duckdb_destroy_result (&result);
  if (out_scope->tenant_id == NULL || out_scope->graph_id == NULL
      || out_scope->namespace_id == NULL || out_scope->relation_name == NULL
      || out_scope->op == NULL) {
    trigger_batch_scope_clear (out_scope);
    return WYRELOG_E_NOMEM;
  }
  *out_found = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
read_projection_value (duckdb_result *result, idx_t col, idx_t row,
    const wyl_policy_fact_relation_schema_column_t *column,
    wyl_fact_value_t *out_value, gchar **out_owned_text)
{
  *out_owned_text = NULL;
  if (duckdb_value_is_null (result, col, row)) {
    if (!column->nullable)
      return WYRELOG_E_POLICY;
    out_value->type = WYL_FACT_VALUE_NULL;
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "symbol") == 0
      || g_strcmp0 (column->column_type, "string") == 0) {
    gchar *raw = duckdb_value_varchar (result, col, row);
    if (raw == NULL)
      return WYRELOG_E_NOMEM;
    *out_owned_text = g_strdup (raw);
    duckdb_free (raw);
    if (*out_owned_text == NULL)
      return WYRELOG_E_NOMEM;
    out_value->type = g_strcmp0 (column->column_type, "symbol") == 0
        ? WYL_FACT_VALUE_SYMBOL : WYL_FACT_VALUE_STRING;
    out_value->as.text = *out_owned_text;
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "int64") == 0) {
    out_value->type = WYL_FACT_VALUE_INT64;
    out_value->as.int64_value = duckdb_value_int64 (result, col, row);
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "bool") == 0) {
    out_value->type = WYL_FACT_VALUE_BOOL;
    out_value->as.bool_value = duckdb_value_boolean (result, col, row);
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "compound_ref") == 0) {
    out_value->type = WYL_FACT_VALUE_COMPOUND_REF;
    out_value->as.compound_ref = duckdb_value_int64 (result, col, row);
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_INVALID;
}

static wyrelog_error_t
select_valid_rows_for_batch_unlocked (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const gchar *projection_table, const gchar *trigger_batch_id,
    wyl_fact_value_t **out_values, gchar ***out_owned_strings,
    wyl_fact_row_t **out_rows, gsize *out_n_rows)
{
  *out_values = NULL;
  *out_owned_strings = NULL;
  *out_rows = NULL;
  *out_n_rows = 0;

  g_autoptr (GString) sql = g_string_new ("SELECT ");
  for (gsize i = 0; i < schema->n_columns; i++) {
    if (i > 0)
      g_string_append (sql, ", ");
    append_duckdb_identifier (sql, schema->columns[i].column_name);
  }
  g_string_append (sql, " FROM ");
  append_duckdb_identifier (sql, projection_table);
  g_string_append (sql, " WHERE __wyl_batch_id = ? AND __wyl_valid = TRUE "
      "ORDER BY __wyl_row_index;");

  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  if (duckdb_prepare (store->conn, sql->str, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, trigger_batch_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);

  idx_t n_rows = duckdb_row_count (&result);
  if (n_rows == 0) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_OK;
  }
  if ((gint64) n_rows > WYL_FACT_STORE_RETRACT_BY_BATCH_MAX_ROWS) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }

  wyl_fact_value_t *values = g_new0 (wyl_fact_value_t,
          (gsize) n_rows * schema->n_columns);
  gchar **owned_strings = g_new0 (gchar *,
          (gsize) n_rows * schema->n_columns);
  wyl_fact_row_t *rows = g_new0 (wyl_fact_row_t, (gsize) n_rows);
  wyrelog_error_t rc = WYRELOG_E_OK;
  for (idx_t r = 0; rc == WYRELOG_E_OK && r < n_rows; r++) {
    for (gsize c = 0; rc == WYRELOG_E_OK && c < schema->n_columns; c++) {
      gsize idx = (gsize) r * schema->n_columns + c;
      rc = read_projection_value (&result, c, r, &schema->columns[c],
              &values[idx], &owned_strings[idx]);
    }
    rows[r].values = &values[(gsize) r * schema->n_columns];
    rows[r].n_values = schema->n_columns;
  }
  duckdb_destroy_result (&result);
  if (rc != WYRELOG_E_OK) {
    for (gsize i = 0; i < (gsize) n_rows * schema->n_columns; i++)
      g_free (owned_strings[i]);
    g_free (owned_strings);
    g_free (values);
    g_free (rows);
    return rc;
  }
  *out_values = values;
  *out_owned_strings = owned_strings;
  *out_rows = rows;
  *out_n_rows = (gsize) n_rows;
  return WYRELOG_E_OK;
}

static void
free_projection_rows (wyl_fact_value_t *values, gchar **owned_strings,
    wyl_fact_row_t *rows, gsize n_rows, gsize n_columns)
{
  if (owned_strings != NULL) {
    for (gsize i = 0; i < n_rows * n_columns; i++)
      g_free (owned_strings[i]);
    g_free (owned_strings);
  }
  g_free (values);
  g_free (rows);
}

wyrelog_error_t
wyl_fact_store_retract_by_batch_id (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const gchar *trigger_batch_id, const gchar *new_batch_id,
    const gchar *source, const gchar *request_id,
    const gchar *idempotency_key, gboolean *out_inserted, gint64 *out_row_count)
{
  wyrelog_error_t rc;
  g_autofree gchar *table = NULL;
  TriggerBatchScope scope = { 0 };
  gboolean found = FALSE;
  wyl_fact_value_t *select_values = NULL;
  gchar **owned_strings = NULL;
  wyl_fact_row_t *select_rows = NULL;
  gsize n_select_rows = 0;
  g_autofree gchar *content_hash = NULL;
  duckdb_appender appender = NULL;
  gint64 first_seq = 0;
  gint64 created_at_us = 0;
  wyl_fact_store_batch_t batch_meta;
  gboolean existing = FALSE;
  gboolean tx_open = FALSE;

  if (out_inserted != NULL)
    *out_inserted = FALSE;
  if (out_row_count != NULL)
    *out_row_count = 0;
  if (store == NULL || schema == NULL || trigger_batch_id == NULL
      || trigger_batch_id[0] == '\0' || new_batch_id == NULL
      || new_batch_id[0] == '\0' || idempotency_key == NULL
      || idempotency_key[0] == '\0')
    return WYRELOG_E_INVALID;
  rc = validate_schema_shape (schema);
  if (rc != WYRELOG_E_OK)
    return rc;
  table = wyl_fact_store_projection_table_name (schema);
  if (table == NULL)
    return WYRELOG_E_INVALID;

  memset (&batch_meta, 0, sizeof (batch_meta));
  batch_meta.batch_id = new_batch_id;
  batch_meta.tenant_id = schema->tenant_id;
  batch_meta.graph_id = schema->graph_id;
  batch_meta.namespace_id = schema->namespace_id;
  batch_meta.relation_name = schema->relation_name;
  batch_meta.schema_version = schema->schema_version;
  batch_meta.source = source;
  batch_meta.request_id = request_id;
  batch_meta.idempotency_key = idempotency_key;
  batch_meta.op = WYL_FACT_STORE_OP_RETRACT;

  g_mutex_lock (&store->lock);

  rc = reject_audit_database_unlocked (store);
  if (rc != WYRELOG_E_OK)
    goto unlock_return;
  rc = validate_store_scope_unlocked (store, schema->tenant_id,
          schema->graph_id, FALSE);
  if (rc != WYRELOG_E_OK)
    goto unlock_return;

  rc = lookup_batch_scope_unlocked (store, trigger_batch_id, &scope, &found);
  if (rc != WYRELOG_E_OK)
    goto unlock_return;
  if (!found) {
    rc = WYRELOG_E_NOT_FOUND;
    goto unlock_return;
  }
  if (g_strcmp0 (scope.op, "assert") != 0) {
    rc = WYRELOG_E_POLICY;
    goto unlock_return;
  }
  if (g_strcmp0 (scope.tenant_id, schema->tenant_id) != 0
      || g_strcmp0 (scope.graph_id, schema->graph_id) != 0
      || g_strcmp0 (scope.namespace_id, schema->namespace_id) != 0
      || g_strcmp0 (scope.relation_name, schema->relation_name) != 0
      || (guint32) scope.schema_version != schema->schema_version) {
    rc = WYRELOG_E_POLICY;
    goto unlock_return;
  }

  rc = select_valid_rows_for_batch_unlocked (store, schema, table,
          trigger_batch_id, &select_values, &owned_strings, &select_rows,
          &n_select_rows);
  if (rc != WYRELOG_E_OK)
    goto unlock_return;

  batch_meta.rows = select_rows;
  batch_meta.n_rows = n_select_rows;

  content_hash = batch_content_hash (schema, &batch_meta);
  if (content_hash == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto unlock_return;
  }

  rc = existing_batch_matches_unlocked (store, &batch_meta, content_hash,
          &existing);
  if (rc != WYRELOG_E_OK)
    goto unlock_return;
  if (existing) {
    /* Idempotent replay: same batch_id + idempotency_key match an existing
    * retract row with identical content. Report the recorded row_count. */
    if (out_row_count != NULL)
      *out_row_count = (gint64) n_select_rows;
    rc = WYRELOG_E_OK;
    goto unlock_return;
  }

  rc = exec_sql (store->conn, "BEGIN TRANSACTION;");
  if (rc != WYRELOG_E_OK)
    goto unlock_return;
  tx_open = TRUE;
  created_at_us = g_get_real_time ();
  rc = insert_batch_unlocked (store, &batch_meta, content_hash, created_at_us);
  if (rc == WYRELOG_E_OK && n_select_rows > 0)
    rc = next_sequence_unlocked (store, &first_seq);
  if (rc == WYRELOG_E_OK && n_select_rows > 0
      && duckdb_appender_create (store->conn, NULL, table, &appender)
      != DuckDBSuccess)
    rc = WYRELOG_E_IO;
  for (gsize i = 0; rc == WYRELOG_E_OK && i < n_select_rows; i++) {
    gint64 seq = first_seq + (gint64) i;
    if (duckdb_appender_begin_row (appender) != DuckDBSuccess) {
      rc = WYRELOG_E_IO;
      break;
    }
    for (gsize j = 0; rc == WYRELOG_E_OK && j < schema->n_columns; j++)
      rc = append_value (appender, &select_rows[i].values[j]);
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_varchar (appender, schema->tenant_id)
          == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_varchar (appender, schema->graph_id)
          == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_int64 (appender, seq) == DuckDBSuccess ?
          WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_varchar (appender, new_batch_id) == DuckDBSuccess ?
          WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_int64 (appender, (gint64) i) == DuckDBSuccess ?
          WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = duckdb_append_bool (appender, FALSE) == DuckDBSuccess ?
          WYRELOG_E_OK : WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK
        && duckdb_appender_end_row (appender) != DuckDBSuccess)
      rc = WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = insert_event_unlocked (store, &batch_meta, seq, created_at_us);
  }
  if (appender != NULL) {
    if (duckdb_appender_destroy (&appender) != DuckDBSuccess
        && rc == WYRELOG_E_OK)
      rc = WYRELOG_E_IO;
    appender = NULL;
  }
  if (rc == WYRELOG_E_OK) {
    rc = exec_sql (store->conn, "COMMIT;");
    tx_open = FALSE;
  }

  if (rc == WYRELOG_E_OK) {
    if (out_inserted != NULL)
      *out_inserted = TRUE;
    if (out_row_count != NULL)
      *out_row_count = (gint64) n_select_rows;
  }

unlock_return:
  if (tx_open)
    (void) exec_sql (store->conn, "ROLLBACK;");
  if (appender != NULL)
    duckdb_appender_destroy (&appender);
  trigger_batch_scope_clear (&scope);
  free_projection_rows (select_values, owned_strings, select_rows,
      n_select_rows, schema->n_columns);
  g_mutex_unlock (&store->lock);
  return rc;
}

/*
 * Tier-3 hard delete, crash-convergent.  DuckDB cannot delete an FK parent and
 * its children inside one transaction (the parent DELETE aborts on the
 * still-visible child rows), so the three destructive DELETEs stay autocommit
 * and forward-only.  Convergence rides a durable intention instead: a PENDING
 * fact_forget_intent row is committed before any delete, and it is flipped
 * COMPLETED in the same transaction as its fact_forget_audit record.  So a
 * crash leaves at most one PENDING intent, and wyl_fact_store_forget_reconcile
 * replays it to exactly one fully-forgotten (or already-reused, no-op) result.
 */

static wyrelog_error_t
forget_run_checkpoint (wyrelog_error_t (*checkpoint) (const gchar *, gpointer),
    gpointer user_data, const gchar *point)
{
  if (checkpoint == NULL)
    return WYRELOG_E_OK;
  return checkpoint (point, user_data);
}

typedef struct
{
  gchar *op_uuid;
  gchar *batch_id;
  gchar *tenant_id;
  gchar *graph_id;
  gchar *namespace_id;
  gchar *relation_name;
  gint64 schema_version;
  gchar *projection_table;
  gchar *content_hash;
  gchar *idempotency_key;
  gchar *operator_id;
  gchar *reason;
  gint64 rows_purged;
  gchar *state;
} ForgetIntent;

static void
forget_intent_clear (ForgetIntent *intent)
{
  if (intent == NULL)
    return;
  g_free (intent->op_uuid);
  g_free (intent->batch_id);
  g_free (intent->tenant_id);
  g_free (intent->graph_id);
  g_free (intent->namespace_id);
  g_free (intent->relation_name);
  g_free (intent->projection_table);
  g_free (intent->content_hash);
  g_free (intent->idempotency_key);
  g_free (intent->operator_id);
  g_free (intent->reason);
  g_free (intent->state);
  memset (intent, 0, sizeof (*intent));
}

static void
forget_intent_free (ForgetIntent *intent)
{
  if (intent == NULL)
    return;
  forget_intent_clear (intent);
  g_free (intent);
}

/* Read the reuse-guard fingerprint (content_hash + idempotency_key) of the
 * batch row.  found=FALSE when no such batch row exists. */
static wyrelog_error_t
load_batch_forget_fingerprint_unlocked (wyl_fact_store_t *store,
    const gchar *batch_id, gboolean *out_found, gchar **out_content_hash,
    gchar **out_idempotency_key)
{
  *out_found = FALSE;
  if (out_content_hash != NULL)
    *out_content_hash = NULL;
  if (out_idempotency_key != NULL)
    *out_idempotency_key = NULL;
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT content_hash, idempotency_key FROM fact_batches "
      "WHERE batch_id = ?;";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_varchar (stmt, 1, batch_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) == 0) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_OK;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  gchar *hash = duckdb_value_varchar (&result, 0, 0);
  gchar *idem = duckdb_value_varchar (&result, 1, 0);
  if (out_content_hash != NULL)
    *out_content_hash = g_strdup (hash);
  if (out_idempotency_key != NULL)
    *out_idempotency_key = g_strdup (idem);
  duckdb_free (hash);
  duckdb_free (idem);
  duckdb_destroy_result (&result);
  if ((out_content_hash != NULL && *out_content_hash == NULL)
      || (out_idempotency_key != NULL && *out_idempotency_key == NULL)) {
    g_clear_pointer (out_content_hash, g_free);
    g_clear_pointer (out_idempotency_key, g_free);
    return WYRELOG_E_NOMEM;
  }
  *out_found = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
count_projection_rows_unlocked (wyl_fact_store_t *store, const gchar *table,
    const gchar *batch_id, gint64 *out_rows)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  g_autoptr (GString) sql = g_string_new ("SELECT COUNT(*) FROM ");
  append_duckdb_identifier (sql, table);
  g_string_append (sql, " WHERE __wyl_batch_id = ?;");
  if (duckdb_prepare (store->conn, sql->str, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, batch_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  *out_rows = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
insert_forget_intent_unlocked (wyl_fact_store_t *store,
    const ForgetIntent *intent, gint64 created_at_us)
{
  duckdb_prepared_statement stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_forget_intent "
      "(op_uuid, batch_id, tenant_id, graph_id, namespace_id, relation_name, "
      " schema_version, projection_table, content_hash, idempotency_key, "
      " operator, reason, rows_purged, state, created_at_us, completed_at_us) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, NULL);";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, intent->op_uuid)
      | duckdb_bind_varchar (stmt, 2, intent->batch_id)
      | duckdb_bind_varchar (stmt, 3, intent->tenant_id)
      | duckdb_bind_varchar (stmt, 4, intent->graph_id)
      | duckdb_bind_varchar (stmt, 5, intent->namespace_id)
      | duckdb_bind_varchar (stmt, 6, intent->relation_name)
      | duckdb_bind_int64 (stmt, 7, intent->schema_version)
      | duckdb_bind_varchar (stmt, 8, intent->projection_table)
      | duckdb_bind_varchar (stmt, 9, intent->content_hash)
      | duckdb_bind_varchar (stmt, 10, intent->idempotency_key)
      | duckdb_bind_varchar (stmt, 11, intent->operator_id)
      | duckdb_bind_varchar (stmt, 12, intent->reason)
      | duckdb_bind_int64 (stmt, 13, intent->rows_purged)
      | duckdb_bind_int64 (stmt, 14, created_at_us);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
prepared_delete_batch_unlocked (wyl_fact_store_t *store, const gchar *sql,
    const gchar *batch_id)
{
  duckdb_prepared_statement stmt = NULL;
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    /* duckdb_prepare allocates the statement even when it fails: the
     * object carries the error text.  duckdb.h:1892 requires destroying
     * it anyway. */
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_varchar (stmt, 1, batch_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
rollback_forget_transaction_unlocked (wyl_fact_store_t *store,
    wyrelog_error_t primary_rc)
{
  wyrelog_error_t rollback_rc = WYRELOG_E_OK;
#if defined(WYL_TEST_HANDLE_SEAMS)
  rollback_rc = forget_transaction_test_hook_unlocked (store,
          WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_ROLLBACK);
#endif
  if (rollback_rc == WYRELOG_E_OK)
    rollback_rc = exec_sql (store->conn, "ROLLBACK;");
  if (rollback_rc != WYRELOG_E_OK) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_IO,
        "fact forget transaction rollback failed");
    return WYRELOG_E_INTERNAL;
  }
  return primary_rc;
}

/* Final step: record the audit row and flip the intent COMPLETED in one
 * transaction (no FK-delete, so DuckDB commits it atomically). */
static wyrelog_error_t
complete_forget_intent_unlocked (wyl_fact_store_t *store,
    const ForgetIntent *intent)
{
  wyrelog_error_t rc = exec_sql (store->conn, "BEGIN TRANSACTION;");
  if (rc != WYRELOG_E_OK)
    return rc;
#if defined(WYL_TEST_HANDLE_SEAMS)
  rc = forget_transaction_test_hook_unlocked (store,
          WYL_FACT_STORE_FORGET_TRANSACTION_AFTER_BEGIN);
  if (rc != WYRELOG_E_OK)
    goto rollback;
#endif
  gint64 now_us = g_get_real_time ();
  duckdb_prepared_statement stmt = NULL;
  static const gchar *audit_sql =
      "INSERT INTO fact_forget_audit "
      "(id, batch_id, tenant_id, graph_id, operator, reason, rows_purged, "
      " created_at_us) VALUES ("
      "(SELECT COALESCE(MAX(id), 0) + 1 FROM fact_forget_audit), "
      "?, ?, ?, ?, ?, ?, ?);";
  if (duckdb_prepare (store->conn, audit_sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, intent->batch_id)
      | duckdb_bind_varchar (stmt, 2, intent->tenant_id)
      | duckdb_bind_varchar (stmt, 3, intent->graph_id)
      | duckdb_bind_varchar (stmt, 4, intent->operator_id)
      | duckdb_bind_varchar (stmt, 5, intent->reason)
      | duckdb_bind_int64 (stmt, 6, intent->rows_purged)
      | duckdb_bind_int64 (stmt, 7, now_us);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  duckdb_state exec = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  if (exec != DuckDBSuccess) {
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  duckdb_prepared_statement ustmt = NULL;
  static const gchar *update_sql =
      "UPDATE fact_forget_intent SET state = 'COMPLETED', "
      "completed_at_us = ? WHERE op_uuid = ?;";
  if (duckdb_prepare (store->conn, update_sql, &ustmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&ustmt);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  duckdb_state uok = duckdb_bind_int64 (ustmt, 1, now_us)
      | duckdb_bind_varchar (ustmt, 2, intent->op_uuid);
  if (uok != DuckDBSuccess) {
    duckdb_destroy_prepare (&ustmt);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  duckdb_state uexec = duckdb_execute_prepared (ustmt, NULL);
  duckdb_destroy_prepare (&ustmt);
  if (uexec != DuckDBSuccess) {
    rc = WYRELOG_E_IO;
    goto rollback;
  }
#if defined(WYL_TEST_HANDLE_SEAMS)
  rc = forget_transaction_test_hook_unlocked (store,
          WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_COMMIT);
  if (rc != WYRELOG_E_OK)
    goto rollback;
#endif
  rc = exec_sql (store->conn, "COMMIT;");
  if (rc != WYRELOG_E_OK)
    goto rollback;
  return WYRELOG_E_OK;

rollback:
  return rollback_forget_transaction_unlocked (store, rc);
}

/* Drive one intent to its terminal COMPLETED record.  Idempotent: an already
 * COMPLETED intent is a no-op; a batch whose fingerprint no longer matches was
 * deleted then had its identifier reused, so completion is recorded WITHOUT
 * touching the new batch (closing the identifier-reuse hole). */
static wyrelog_error_t
execute_forget_intent_unlocked (wyl_fact_store_t *store,
    const ForgetIntent *intent,
    wyrelog_error_t (*checkpoint) (const gchar *, gpointer),
    gpointer checkpoint_data, gint64 *out_rows_purged)
{
  if (g_strcmp0 (intent->state, "COMPLETED") == 0) {
    if (out_rows_purged != NULL)
      *out_rows_purged = intent->rows_purged;
    return WYRELOG_E_OK;
  }

  gboolean found = FALSE;
  g_autofree gchar *live_hash = NULL;
  g_autofree gchar *live_idem = NULL;
  wyrelog_error_t rc = load_batch_forget_fingerprint_unlocked (store,
          intent->batch_id, &found, &live_hash, &live_idem);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean run_deletes = found
      && g_strcmp0 (live_hash, intent->content_hash) == 0
      && g_strcmp0 (live_idem, intent->idempotency_key) == 0;

  if (run_deletes) {
    rc = forget_run_checkpoint (checkpoint, checkpoint_data,
            "before_delete_projection");
    if (rc != WYRELOG_E_OK)
      return rc;
    g_autoptr (GString) proj_sql = g_string_new ("DELETE FROM ");
    append_duckdb_identifier (proj_sql, intent->projection_table);
    g_string_append (proj_sql, " WHERE __wyl_batch_id = ?;");
    rc = prepared_delete_batch_unlocked (store, proj_sql->str,
            intent->batch_id);
    if (rc != WYRELOG_E_OK)
      return rc;

    rc = forget_run_checkpoint (checkpoint, checkpoint_data,
            "before_delete_events");
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = prepared_delete_batch_unlocked (store,
            "DELETE FROM fact_event_log WHERE batch_id = ?;", intent->batch_id);
    if (rc != WYRELOG_E_OK)
      return rc;

    rc = forget_run_checkpoint (checkpoint, checkpoint_data,
            "before_delete_batch");
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = prepared_delete_batch_unlocked (store,
            "DELETE FROM fact_batches WHERE batch_id = ?;", intent->batch_id);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  rc = forget_run_checkpoint (checkpoint, checkpoint_data, "before_completion");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = complete_forget_intent_unlocked (store, intent);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (out_rows_purged != NULL)
    *out_rows_purged = intent->rows_purged;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
load_pending_forget_intents_unlocked (wyl_fact_store_t *store, GPtrArray *out)
{
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT op_uuid, batch_id, tenant_id, graph_id, namespace_id, "
      "relation_name, schema_version, projection_table, content_hash, "
      "idempotency_key, operator, reason, rows_purged, state "
      "FROM fact_forget_intent WHERE state = 'PENDING' "
      "ORDER BY created_at_us;";
  if (duckdb_query (store->conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gint64 n_rows = (gint64) duckdb_row_count (&result);
  for (gint64 r = 0; r < n_rows; r++) {
    ForgetIntent *intent = g_new0 (ForgetIntent, 1);
    gchar *op_uuid = duckdb_value_varchar (&result, 0, r);
    gchar *batch_id = duckdb_value_varchar (&result, 1, r);
    gchar *tenant_id = duckdb_value_varchar (&result, 2, r);
    gchar *graph_id = duckdb_value_varchar (&result, 3, r);
    gchar *namespace_id = duckdb_value_varchar (&result, 4, r);
    gchar *relation_name = duckdb_value_varchar (&result, 5, r);
    gchar *projection_table = duckdb_value_varchar (&result, 7, r);
    gchar *content_hash = duckdb_value_varchar (&result, 8, r);
    gchar *idempotency_key = duckdb_value_varchar (&result, 9, r);
    gchar *operator_id = duckdb_value_varchar (&result, 10, r);
    gchar *reason = duckdb_value_varchar (&result, 11, r);
    gchar *state = duckdb_value_varchar (&result, 13, r);
    intent->op_uuid = g_strdup (op_uuid);
    intent->batch_id = g_strdup (batch_id);
    intent->tenant_id = g_strdup (tenant_id);
    intent->graph_id = g_strdup (graph_id);
    intent->namespace_id = g_strdup (namespace_id);
    intent->relation_name = g_strdup (relation_name);
    intent->schema_version = duckdb_value_int64 (&result, 6, r);
    intent->projection_table = g_strdup (projection_table);
    intent->content_hash = g_strdup (content_hash);
    intent->idempotency_key = g_strdup (idempotency_key);
    intent->operator_id = g_strdup (operator_id);
    intent->reason = g_strdup (reason);
    intent->rows_purged = duckdb_value_int64 (&result, 12, r);
    intent->state = g_strdup (state);
    duckdb_free (op_uuid);
    duckdb_free (batch_id);
    duckdb_free (tenant_id);
    duckdb_free (graph_id);
    duckdb_free (namespace_id);
    duckdb_free (relation_name);
    duckdb_free (projection_table);
    duckdb_free (content_hash);
    duckdb_free (idempotency_key);
    duckdb_free (operator_id);
    duckdb_free (reason);
    duckdb_free (state);
    g_ptr_array_add (out, intent);
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_store_forget (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_forget_options_t *opts, gsize *out_rows_purged)
{
  if (out_rows_purged != NULL)
    *out_rows_purged = 0;
  if (store == NULL || schema == NULL || opts == NULL)
    return WYRELOG_E_INVALID;
  if (opts->batch_id == NULL || opts->batch_id[0] == '\0'
      || opts->operator_id == NULL || opts->operator_id[0] == '\0'
      || opts->reason == NULL || opts->reason[0] == '\0')
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = validate_schema_shape (schema);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *table = wyl_fact_store_projection_table_name (schema);
  if (table == NULL)
    return WYRELOG_E_INVALID;

  g_autofree gchar *minted_uuid = NULL;
  const gchar *op_uuid = opts->op_uuid;
  if (op_uuid == NULL || op_uuid[0] == '\0') {
    minted_uuid = g_uuid_string_random ();
    op_uuid = minted_uuid;
  }

  g_mutex_lock (&store->lock);

  ForgetIntent intent = { 0 };
  gboolean found = FALSE;
  g_autofree gchar *content_hash = NULL;
  g_autofree gchar *idempotency_key = NULL;
  rc = load_batch_forget_fingerprint_unlocked (store, opts->batch_id, &found,
          &content_hash, &idempotency_key);
  if (rc != WYRELOG_E_OK)
    goto forget_unlock;
  if (!found) {
    rc = WYRELOG_E_NOT_FOUND;
    goto forget_unlock;
  }

  gint64 rows = 0;
  rc = count_projection_rows_unlocked (store, table, opts->batch_id, &rows);
  if (rc != WYRELOG_E_OK)
    goto forget_unlock;

  intent.op_uuid = g_strdup (op_uuid);
  intent.batch_id = g_strdup (opts->batch_id);
  intent.tenant_id = g_strdup (schema->tenant_id);
  intent.graph_id = g_strdup (schema->graph_id);
  intent.namespace_id = g_strdup (schema->namespace_id);
  intent.relation_name = g_strdup (schema->relation_name);
  intent.schema_version = (gint64) schema->schema_version;
  intent.projection_table = g_strdup (table);
  intent.content_hash = g_strdup (content_hash);
  intent.idempotency_key = g_strdup (idempotency_key);
  intent.operator_id = g_strdup (opts->operator_id);
  intent.reason = g_strdup (opts->reason);
  intent.rows_purged = rows;
  intent.state = g_strdup ("PENDING");

  rc = forget_run_checkpoint (opts->checkpoint, opts->checkpoint_data,
          "before_intent");
  if (rc != WYRELOG_E_OK)
    goto forget_unlock;

  rc = insert_forget_intent_unlocked (store, &intent, g_get_real_time ());
  if (rc != WYRELOG_E_OK)
    goto forget_unlock;

  rc = forget_run_checkpoint (opts->checkpoint, opts->checkpoint_data,
          "after_intent");
  if (rc != WYRELOG_E_OK)
    goto forget_unlock;

  gint64 purged = 0;
  rc = execute_forget_intent_unlocked (store, &intent, opts->checkpoint,
          opts->checkpoint_data, &purged);
  if (rc == WYRELOG_E_OK && out_rows_purged != NULL)
    *out_rows_purged = (gsize) purged;

forget_unlock:
  forget_intent_clear (&intent);
  g_mutex_unlock (&store->lock);
  return rc;
}

/* Widening a CHECK means rebuilding the table: every ALTER TABLE in this tree
 * is ADD COLUMN, and DuckDB has no ADD/DROP CONSTRAINT.
 *
 * Version is read from the constraint text rather than from a metadata key,
 * because fact_store_metadata is pinned to exactly six rows by
 * validate_identity_values and a seventh fails every provisioned open.  Reading
 * the stored constraint is what the policy store already does for its own
 * predecessor migration.
 *
 * Unrecognised text fails closed.  A store whose constraint we cannot identify
 * is not one to rewrite. */
static wyrelog_error_t
forget_intent_state_check_is_current (wyl_fact_store_t *store,
    gboolean *out_current)
{
  *out_current = FALSE;
  duckdb_prepared_statement stmt = NULL;
  static const gchar *sql =
      "SELECT constraint_text FROM duckdb_constraints() "
      "WHERE table_name = 'fact_forget_intent' "
      "AND constraint_text LIKE '%QUARANTINED%';";
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_result result;
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  *out_current = duckdb_row_count (&result) > 0;
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

/* Rebuild fact_forget_intent with the widened CHECK.
 *
 * One covering transaction is enough: DuckDB DDL participates in it, measured
 * against the pinned library -- a rollback after CREATE/copy/DROP/RENAME
 * restores the original table with its original constraint and leaves no
 * orphan.  The head drop is therefore defensive rather than the recovery
 * mechanism.
 *
 * Deliberately far smaller than the policy store's equivalent rebuild, which
 * carries a checkpoint ladder, an authorizer fence and a fresh-image
 * re-verifier.  There is no DuckDB authorizer, and this is one CHECK on one
 * table with no triggers, no views and no foreign-key children.  What is kept
 * from it: the single transaction, the orphan drop, and an equality proof
 * before commit. */
static wyrelog_error_t
migrate_forget_intent_state_check_unlocked (wyl_fact_store_t *store)
{
  gboolean current = FALSE;
  wyrelog_error_t rc = forget_intent_state_check_is_current (store, &current);
  if (rc != WYRELOG_E_OK || current)
    return rc;

  rc = exec_sql (store->conn, "BEGIN TRANSACTION;");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = exec_sql (store->conn,
          "DROP TABLE IF EXISTS fact_forget_intent_rebuild;"
          "CREATE TABLE fact_forget_intent_rebuild ("
          FACT_FORGET_INTENT_COLUMNS ");"
          "INSERT INTO fact_forget_intent_rebuild"
          "  SELECT * FROM fact_forget_intent;");
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (store->conn,
            "SELECT CASE WHEN ("
            "  (SELECT COUNT(*) FROM ("
            "     SELECT * FROM fact_forget_intent"
            "     EXCEPT SELECT * FROM fact_forget_intent_rebuild)) = 0"
            "  AND (SELECT COUNT(*) FROM ("
            "     SELECT * FROM fact_forget_intent_rebuild"
            "     EXCEPT SELECT * FROM fact_forget_intent)) = 0"
            ") THEN 1 ELSE error('forget intent rebuild lost rows') END;");
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->conn, "ROLLBACK;");
    return rc;
  }
  rc = exec_sql (store->conn,
          "DROP TABLE fact_forget_intent;"
          "ALTER TABLE fact_forget_intent_rebuild "
          "  RENAME TO fact_forget_intent;");
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->conn, "ROLLBACK;");
    return rc;
  }
  return exec_sql (store->conn, "COMMIT;");
}

/* Retire an intent that can never converge.  The row stays: it is the record
 * that an erasure was promised and cannot be honoured by this store, and the
 * issue that asked for this put deleting it explicitly out of scope. */
static wyrelog_error_t
quarantine_forget_intent_unlocked (wyl_fact_store_t *store,
    const gchar *batch_id)
{
  wyrelog_error_t rc = migrate_forget_intent_state_check_unlocked (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  return prepared_delete_batch_unlocked (store,
             "UPDATE fact_forget_intent SET state = 'QUARANTINED' "
             "WHERE batch_id = ?;", batch_id);
}

/* The read-only prefix of the reconciler: everything above its first write.
 * The boot probe stops here and the reconciler continues past it, so the
 * predicate that decides whether to take a write lease and the predicate that
 * decides what to execute are one predicate and cannot disagree.  Two copies
 * could, and their failure modes are asymmetric: a spurious escalation wastes
 * a lease, a missed escalation strands an erasure.
 *
 * The caller holds store->lock.  Order matters and is not a convenience:
 *
 *  - the ledger check comes first because a store whose schema has never been
 *    materialized has no ledger and so has nothing to converge.  Boot
 *    deliberately does not create one, so that state is success rather than a
 *    missing-table error.
 *  - the scope guard comes AFTER the pending count because a store whose
 *    schema was materialized but never appended to has a ledger and no bound
 *    identity: create_schema creates fact_forget_intent, while tenant/graph
 *    metadata is written lazily by ensure_projection.  Refusing that store
 *    would report a failed erasure for a graph that has never held a fact, on
 *    every boot, in the branch with the strongest wording.  Within the
 *    pending > 0 branch a pending intent implies bound identity, so the guard
 *    performs a real comparison and can never spuriously refuse.
 *
 * Line lengths here are constrained by #872; re-run ./tools/format-c after
 * editing this comment. */
static wyrelog_error_t
forget_survey_unlocked (wyl_fact_store_t *store,
    const gchar *expected_tenant_id, const gchar *expected_graph_id,
    GPtrArray *pending)
{
  gboolean has_ledger = FALSE;
  wyrelog_error_t rc = table_exists_unlocked (store, "fact_forget_intent",
          &has_ledger);
  if (rc != WYRELOG_E_OK || !has_ledger)
    return rc;
  rc = load_pending_forget_intents_unlocked (store, pending);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (pending->len == 0)
    return WYRELOG_E_OK;
  /* Refuse a store that is not the one the caller meant to open.  A
   * mis-pointed path opens a store whose own identity and whose intents agree
   * with each other, so only an expectation held outside this file can tell
   * them apart.
   *
   * Propagate the real rc rather than flattening it to POLICY.
   * validate_store_scope_unlocked returns E_IO as well as E_POLICY, and a
   * store that could not be read has not told us it is the wrong store -- it
   * has told us nothing.  Since #869 U2 the caller reports a POLICY refusal
   * as "every loaded intent refused as out of scope", so flattening an I/O
   * failure into POLICY would put a false verdict, with a count behind it, on
   * the boot line. */
  return validate_store_scope_unlocked (store, expected_tenant_id,
             expected_graph_id, FALSE);
}

wyrelog_error_t
wyl_fact_store_forget_pending_count (wyl_fact_store_t *store,
    const gchar *expected_tenant_id, const gchar *expected_graph_id,
    gsize *out_pending)
{
  if (out_pending == NULL)
    return WYRELOG_E_INVALID;
  /* Zero before the remaining argument checks, not after: the header promises
   * the count is zeroed on every non-OK outcome, and returning INVALID with
   * the caller's value untouched would break that promise on the one path a
   * caller is most likely to reach by mistake. */
  *out_pending = 0;
  if (store == NULL || expected_tenant_id == NULL || expected_graph_id == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&store->lock);
  g_autoptr (GPtrArray) pending =
      g_ptr_array_new_with_free_func ((GDestroyNotify) forget_intent_free);
  wyrelog_error_t rc = forget_survey_unlocked (store, expected_tenant_id,
          expected_graph_id, pending);
  if (rc == WYRELOG_E_OK)
    *out_pending = pending->len;
  g_mutex_unlock (&store->lock);
  return rc;
}

wyrelog_error_t
wyl_fact_store_forget_reconcile (wyl_fact_store_t *store,
    const gchar *expected_tenant_id, const gchar *expected_graph_id,
    wyrelog_error_t (*checkpoint) (const gchar *, gpointer),
    gpointer checkpoint_data, wyl_fact_forget_outcome_t *out_outcome)
{
  if (out_outcome == NULL)
    return WYRELOG_E_INVALID;
  /* Zeroed before the remaining argument checks, so a caller that ignores the
   * return value cannot read a stale count as work done. */
  memset (out_outcome, 0, sizeof (*out_outcome));
  if (store == NULL || expected_tenant_id == NULL || expected_graph_id == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&store->lock);
  g_autoptr (GPtrArray) pending =
      g_ptr_array_new_with_free_func ((GDestroyNotify) forget_intent_free);
  wyrelog_error_t rc = forget_survey_unlocked (store, expected_tenant_id,
          expected_graph_id, pending);
  /* Unconditionally, whatever the survey returned.  The survey materializes
   * the rows BEFORE it runs the store-scope guard, so a POLICY refusal comes
   * back with the array already filled -- reporting zero there would hide
   * exactly the load-without-disposition divergence this count exists to
   * expose.  The other survey exits fill nothing, so they give zero on their
   * own: a missing ledger adds no rows, and the loader either adds every row
   * or fails before adding any. */
  wyl_fact_forget_outcome_t outcome = { .loaded = pending->len };
  /* Declared above the goto below: jumping past an initialised declaration is
   * legal only while nothing at the label reads it, which is a property a
   * later edit can silently break with no diagnostic. */
  gboolean out_of_scope = FALSE;
  gboolean broke = FALSE;
  if (rc != WYRELOG_E_OK || pending->len == 0) {
    /* Every loaded intent needs a disposition here, or the equality below
     * fires and overwrites this rc with E_INTERNAL -- turning a diagnosable
     * I/O failure into "wyrelog-side invariant violation" on the boot line,
     * which is a worse misdiagnosis than the one propagating the real rc was
     * meant to prevent.
     *
     * The two survey failures that arrive with a full array differ in what
     * they justify saying.  A store-scope refusal is a verdict about the
     * intents: none of them may be deleted through, so every one is refused.
     * Any other failure is not a verdict at all -- the survey could not
     * finish, so nothing was decided about any intent and they are abandoned
     * for the same reason a post-failure intent is: the pass could not
     * proceed. */
    if (rc == WYRELOG_E_POLICY)
      outcome.refused = outcome.loaded;
    else if (rc != WYRELOG_E_OK)
      outcome.abandoned = outcome.loaded;
    goto done;
  }
  for (guint i = 0; i < pending->len; i++) {
    ForgetIntent *intent = g_ptr_array_index (pending, i);
    if (broke) {
      /* Loaded, never attempted, because an earlier intent failed.  Visited
       * and tallied rather than skipped by a break, so every loaded intent
       * reaches exactly one disposition.
       *
       * Deriving this as loaded - (executed + refused + failed) yields the
       * same numbers on every path the tests exercise, so no assertion
       * distinguishes the two.
       *
       * What the counter buys is that |abandoned| reports what happened
       * rather than what must arithmetically be left over.  Measured: put a
       * break back in the failure branch and this counter reports abandoned=0
       * for a pass that skipped two intents, which
       * check_fact_forget_reconcile_abandoned_outranks_refused catches at
       * 2464; the derivation reports 2 either way and the suite stays green.
       *
       * Note what that does NOT show.  Past this point the body only
       * increments: no I/O, no store state, no effect on rc.  So the break is
       * unobservable to a caller who reads only rc, and the derived value is
       * not "wrong" -- it is right by construction, which is exactly the
       * problem.  A derived count cannot disagree with the loop, so it cannot
       * report that the loop stopped doing its job. */
      outcome.abandoned++;
      continue;
    }
    /* The pending query is not scoped, and the executor trusts the intent's
     * own projection table.  One store serves one graph, so an intent naming
     * another scope means this file is not what its identity claims: skip it
     * rather than delete through it, and report so the caller degrades.
     *
     * Branch on the rc.  validate_store_scope_unlocked returns E_IO as well
     * as E_POLICY, and a store that cannot answer a scope question has not
     * told us the intent is out of scope -- it has told us it is unreadable.
     * Deleting through it is unsafe and labelling it "refused as out of
     * scope" is a false operator-facing verdict, so it counts as a failure
     * and stops the pass. */
    wyrelog_error_t scope_rc = validate_store_scope_unlocked (store,
            intent->tenant_id, intent->graph_id, FALSE);
    if (scope_rc == WYRELOG_E_POLICY) {
      outcome.refused++;
      out_of_scope = TRUE;
      /* Retire it.  E_POLICY here is never a transient failure -- the branch
       * below takes E_IO, and every path that produces E_POLICY does so only
       * after a successful read reported an identity mismatch, which cannot
       * become a match later on this store.  So this row would otherwise be
       * loaded and refused on every boot forever, and the ERROR line that
       * reports loaded > executed would fire for it every time, burying a
       * genuinely new stuck erasure in permanent noise.
       *
       * Counted refused exactly once, on the pass that quarantines it, and
       * neither loaded nor refused afterwards.  The outcome equality holds on
       * both passes without a new term.
       *
       * A failure to quarantine is not fatal to the pass: the intent was
       * correctly refused either way, and the next boot retries the retirement
       * rather than losing the refusal. */
      (void) quarantine_forget_intent_unlocked (store, intent->batch_id);
      continue;
    }
    if (scope_rc != WYRELOG_E_OK) {
      rc = scope_rc;
      outcome.failed++;
      broke = TRUE;
      continue;
    }
    rc = execute_forget_intent_unlocked (store, intent, checkpoint,
            checkpoint_data, NULL);
    if (rc != WYRELOG_E_OK) {
      outcome.failed++;
      broke = TRUE;
      continue;
    }
    outcome.executed++;
  }
done:
  /* Not an assertion: boot must never abort on a graph.
   *
   * Only when rc is already OK.  An equality violation means the counts are
   * untrustworthy, but a real error rc is more useful to the operator than
   * knowing the counts disagree -- and overwriting one cost this unit a live
   * misdiagnosis, reporting a metadata read failure as rc=-7, "wyrelog-side
   * invariant violation", on the commonest configuration.  The cost of the
   * narrower guard is that a violation on a non-OK path is not surfaced at
   * all; the loop body is structurally total, so reaching one requires adding
   * a path that increments nothing. */
  if (outcome.executed + outcome.refused + outcome.failed + outcome.abandoned
      != outcome.loaded && rc == WYRELOG_E_OK)
    rc = WYRELOG_E_INTERNAL;
  /* The rc == OK term is load-bearing: a refusal seen before a later failure
   * must not overwrite that failure's rc with POLICY.  Do not simplify this
   * to "if (refused) rc = POLICY" -- dropping the term is caught at 2442.
   *
   * That hazard is NOT new to the sticky flag, and an earlier draft of this
   * comment wrongly said it was.  The old loop also continued on refusal and
   * only broke on failure, so refusal-then-failure was always reachable and
   * this term was already load-bearing at f7bdba9c.  The sticky flag adds no
   * new ordering -- the if (broke) block precedes the scope check, so a
   * refusal still cannot follow a failure.  What this unit adds is the test
   * that pins it.
   *
   * Promoted AFTER the equality, not before.  Promoting first meant the guard
   * read a POLICY rc and disarmed itself on every pass that refused anything:
   * measured at 14 of 22 reconcile calls armed before the move and 16 of 22
   * after, the two additions being exactly the loop-refusal shapes.  The six
   * still disarmed are genuinely non-OK.  A refusal is a routine outcome, not
   * an error path, and it was the one interesting shape the guard was missing.
   * Safe here because out_of_scope is FALSE on every goto done path: it is set
   * only inside the loop. */
  if (rc == WYRELOG_E_OK && out_of_scope)
    rc = WYRELOG_E_POLICY;
  *out_outcome = outcome;
  g_mutex_unlock (&store->lock);
  return rc;
}

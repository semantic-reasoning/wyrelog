/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "store-private.h"

#include <string.h>

#include "compound-private.h"

struct wyl_fact_store_t
{
  duckdb_database db;
  duckdb_connection conn;
  GMutex lock;
  gchar *identity_tenant_id;
  gchar *identity_graph_id;
  gchar *identity_store_uuid;
  guint64 identity_format_version;
  guint64 identity_path_encoding_version;
};

static gint identity_test_fault;
G_LOCK_DEFINE_STATIC (identity_open);
static WylFactStoreIdentityValidationTestHook identity_validation_test_hook;
static gpointer identity_validation_test_hook_data;
G_LOCK_DEFINE_STATIC (identity_validation_test_hook);

#define WYL_FACT_STORE_KIND "wyrelog.fact"
#define WYL_FACT_STORE_FORMAT_VERSION 1
#define WYL_FACT_STORE_PATH_ENCODING_VERSION 1

static wyrelog_error_t
open_duckdb_with_thread_budget (const gchar *path, duckdb_database *out_db)
{
  duckdb_config config = NULL;
  char *error = NULL;
  const gchar *effective_path = path;

  if (out_db != NULL)
    *out_db = NULL;
  if (path != NULL && g_strcmp0 (path, ":memory:") == 0)
    effective_path = NULL;

  if (duckdb_create_config (&config) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_set_config (config, "threads", "1") != DuckDBSuccess) {
    duckdb_destroy_config (&config);
    return WYRELOG_E_IO;
  }
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
    duckdb_database *out_db)
{
  duckdb_config config = NULL;
  char *error = NULL;

  *out_db = NULL;
  if (duckdb_create_config (&config) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_set_config (config, "threads", "1") != DuckDBSuccess
      || (read_only && duckdb_set_config (config, "access_mode", "READ_ONLY")
          != DuckDBSuccess)) {
    duckdb_destroy_config (&config);
    return WYRELOG_E_IO;
  }
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
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
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
metadata_value_unlocked (wyl_fact_store_t *store, const gchar *key,
    gchar **out_value)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  *out_value = NULL;
  if (duckdb_prepare (store->conn,
          "SELECT value FROM fact_store_metadata WHERE key = ?;", &stmt)
      != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, key) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) > 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  if (duckdb_row_count (&result) == 1) {
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

static wyrelog_error_t
insert_metadata_value_unlocked (wyl_fact_store_t *store, const gchar *key,
    const gchar *value)
{
  duckdb_prepared_statement stmt = NULL;
  if (duckdb_prepare (store->conn,
          "INSERT INTO fact_store_metadata (key, value) VALUES (?, ?);",
          &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, key)
      | duckdb_bind_varchar (stmt, 2, value);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
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

  g_autofree gchar *stored_tenant = NULL;
  g_autofree gchar *stored_graph = NULL;
  rc = metadata_value_unlocked (store, "tenant_id", &stored_tenant);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = metadata_value_unlocked (store, "graph_id", &stored_graph);
  if (rc != WYRELOG_E_OK)
    return rc;

  if ((stored_tenant == NULL) != (stored_graph == NULL))
    return WYRELOG_E_POLICY;
  if (stored_tenant == NULL) {
    if (!bind_if_empty)
      return WYRELOG_E_POLICY;
    rc = insert_metadata_value_unlocked (store, "tenant_id", tenant_id);
    if (rc == WYRELOG_E_OK)
      rc = insert_metadata_value_unlocked (store, "graph_id", graph_id);
    return rc;
  }

  return g_strcmp0 (stored_tenant, tenant_id) == 0
      && g_strcmp0 (stored_graph, graph_id) == 0 ? WYRELOG_E_OK :
      WYRELOG_E_POLICY;
}

static gboolean
identity_uuid_is_canonical (const gchar *value)
{
  if (value == NULL || strlen (value) != 36 || value[8] != '-'
      || value[13] != '-' || value[18] != '-' || value[23] != '-')
    return FALSE;
  for (gsize i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23)
      continue;
    if (!g_ascii_isdigit (value[i])
        && !(value[i] >= 'a' && value[i] <= 'f'))
      return FALSE;
  }
  return TRUE;
}

static gboolean
identity_input_is_valid (const WylFactStoreIdentity *identity)
{
  return identity != NULL
      && identity->tenant_id != NULL && identity->tenant_id[0] != '\0'
      && g_utf8_validate (identity->tenant_id, -1, NULL)
      && identity->graph_id != NULL && identity->graph_id[0] != '\0'
      && g_utf8_validate (identity->graph_id, -1, NULL)
      && identity_uuid_is_canonical (identity->store_uuid)
      && identity->format_version > 0
      && identity->format_version <= G_MAXINT64
      && identity->path_encoding_version > 0
      && identity->path_encoding_version <= G_MAXINT64;
}

static gboolean
canonical_decimal (const gchar *value, guint64 *out_value)
{
  guint64 parsed = 0;

  if (value == NULL || value[0] == '\0'
      || (value[0] == '0' && value[1] != '\0'))
    return FALSE;
  for (const gchar * p = value; *p != '\0'; p++) {
    if (!g_ascii_isdigit (*p))
      return FALSE;
    guint digit = (guint) (*p - '0');
    if (parsed > (G_MAXUINT64 - digit) / 10)
      return FALSE;
    parsed = parsed * 10 + digit;
  }
  if (parsed == 0 || parsed > G_MAXINT64)
    return FALSE;
  *out_value = parsed;
  return TRUE;
}

static wyrelog_error_t
query_single_count (duckdb_connection conn, const gchar *sql, gint64 *out_count)
{
  duckdb_result result = { 0 };
  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != 1 || duckdb_column_count (&result) != 1
      || duckdb_value_is_null (&result, 0, 0)) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  *out_count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
identity_metadata_exists (wyl_fact_store_t *store, gboolean *out_exists)
{
  gint64 count = 0;
  wyrelog_error_t rc = query_single_count (store->conn,
      "SELECT COUNT(*) FROM duckdb_tables() "
      "WHERE database_name=current_database() AND schema_name='main' "
      "AND table_name='fact_store_metadata' AND NOT internal;", &count);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_exists = count == 1;
  return count <= 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
identity_catalog_is_empty (wyl_fact_store_t *store, gboolean *out_empty)
{
  static const gchar *sql =
      "SELECT SUM(n) FROM ("
      " SELECT COUNT(*) AS n FROM duckdb_tables()"
      "  WHERE database_name=current_database() AND NOT internal"
      " UNION ALL SELECT COUNT(*) FROM duckdb_views()"
      "  WHERE database_name=current_database() AND NOT internal"
      " UNION ALL SELECT COUNT(*) FROM duckdb_sequences()"
      "  WHERE database_name=current_database()"
      " UNION ALL SELECT COUNT(*) FROM duckdb_types()"
      "  WHERE database_name=current_database() AND NOT internal"
      " UNION ALL SELECT COUNT(*) FROM duckdb_functions()"
      "  WHERE database_name=current_database() AND NOT internal"
      " UNION ALL SELECT COUNT(*) FROM duckdb_schemas()"
      "  WHERE database_name=current_database() AND NOT internal"
      "    AND schema_name NOT IN ('main','information_schema','pg_catalog')"
      ") objects;";
  gint64 count = 0;
  wyrelog_error_t rc = query_single_count (store->conn, sql, &count);
  if (rc == WYRELOG_E_OK)
    *out_empty = count == 0;
  return rc;
}

static wyrelog_error_t
validate_identity_schema (wyl_fact_store_t *store)
{
  duckdb_result result = { 0 };
  static const gchar *names[] = { "key", "value" };
  static const gchar *sql =
      "SELECT column_name,data_type,is_nullable,column_default,"
      "ordinal_position,collation_name FROM information_schema.columns "
      "WHERE table_catalog=current_database() AND table_schema='main' "
      "AND table_name='fact_store_metadata' ORDER BY ordinal_position;";

  if (duckdb_query (store->conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != G_N_ELEMENTS (names)) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  for (idx_t row = 0; row < G_N_ELEMENTS (names); row++) {
    gchar *name = duckdb_value_varchar (&result, 0, row);
    gchar *type = duckdb_value_varchar (&result, 1, row);
    gchar *nullable = duckdb_value_varchar (&result, 2, row);
    gboolean valid = name != NULL && type != NULL && nullable != NULL
        && strcmp (name, names[row]) == 0 && strcmp (type, "VARCHAR") == 0
        && strcmp (nullable, "NO") == 0
        && duckdb_value_is_null (&result, 3, row)
        && duckdb_value_int64 (&result, 4, row) == (gint64) row + 1
        && duckdb_value_is_null (&result, 5, row);
    duckdb_free (name);
    duckdb_free (type);
    duckdb_free (nullable);
    if (!valid) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_POLICY;
    }
  }
  duckdb_destroy_result (&result);

  gint64 primary_key_count = 0;
  gint64 not_null_count = 0;
  gint64 total_count = 0;
  gint64 table_shape_count = 0;
  wyrelog_error_t rc = query_single_count (store->conn,
      "SELECT COUNT(*) FROM duckdb_constraints() "
      "WHERE database_name=current_database() AND schema_name='main' "
      "AND table_name='fact_store_metadata' "
      "AND constraint_type='PRIMARY KEY' "
      "AND len(constraint_column_names)=1 "
      "AND list_contains(constraint_column_names,'key');", &primary_key_count);
  if (rc == WYRELOG_E_OK)
    rc = query_single_count (store->conn,
        "SELECT COUNT(*) FROM duckdb_constraints() "
        "WHERE database_name=current_database() AND schema_name='main' "
        "AND table_name='fact_store_metadata' "
        "AND constraint_type='NOT NULL' "
        "AND len(constraint_column_names)=1 "
        "AND (list_contains(constraint_column_names,'key') "
        "OR list_contains(constraint_column_names,'value'));", &not_null_count);
  if (rc == WYRELOG_E_OK)
    rc = query_single_count (store->conn,
        "SELECT COUNT(*) FROM duckdb_constraints() "
        "WHERE database_name=current_database() AND schema_name='main' "
        "AND table_name='fact_store_metadata';", &total_count);
  if (rc == WYRELOG_E_OK)
    rc = query_single_count (store->conn,
        "SELECT COUNT(*) FROM duckdb_tables() "
        "WHERE database_name=current_database() AND schema_name='main' "
        "AND table_name='fact_store_metadata' AND NOT internal "
        "AND has_primary_key AND column_count=2 AND index_count=1 "
        "AND check_constraint_count=0;", &table_shape_count);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (primary_key_count != 1 || not_null_count != 2 || total_count != 3
      || table_shape_count != 1)
    return WYRELOG_E_POLICY;

  if (duckdb_query (store->conn,
          "SELECT sql FROM duckdb_tables() "
          "WHERE database_name=current_database() AND schema_name='main' "
          "AND table_name='fact_store_metadata' AND NOT internal;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != 1 || duckdb_value_is_null (&result, 0, 0)) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  gchar *ddl = duckdb_value_varchar (&result, 0, 0);
  g_autofree gchar *lower_ddl = ddl != NULL ? g_ascii_strdown (ddl, -1) : NULL;
  duckdb_free (ddl);
  duckdb_destroy_result (&result);
  return lower_ddl != NULL && strstr (lower_ddl, "collate") == NULL ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static gchar *
identity_result_string (duckdb_result *result, idx_t column, idx_t row,
    gboolean *out_valid)
{
  *out_valid = FALSE;
  if (duckdb_value_is_null (result, column, row))
    return NULL;
  duckdb_string value = duckdb_value_string (result, column, row);
  if (value.data == NULL || value.size == 0
      || memchr (value.data, '\0', value.size) != NULL
      || !g_utf8_validate (value.data, value.size, NULL)) {
    if (value.data != NULL)
      duckdb_free (value.data);
    return NULL;
  }
  gchar *copy = g_strndup (value.data, value.size);
  duckdb_free (value.data);
  *out_valid = copy != NULL;
  return copy;
}

static wyrelog_error_t
validate_identity_values (wyl_fact_store_t *store,
    const WylFactStoreIdentity *identity,
    WylFactStoreIdentityResult *out_result)
{
  static const gchar *keys[] = {
    "store_kind", "format_version", "store_uuid", "path_encoding_version",
    "tenant_id", "graph_id"
  };
  gchar *values[G_N_ELEMENTS (keys)] = { NULL };
  gboolean seen[G_N_ELEMENTS (keys)] = { FALSE };
  duckdb_result result = { 0 };
  wyrelog_error_t rc = WYRELOG_E_POLICY;

  if (duckdb_query (store->conn,
          "SELECT key,value FROM main.fact_store_metadata;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != G_N_ELEMENTS (keys)) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA;
    goto out;
  }
  for (idx_t row = 0; row < duckdb_row_count (&result); row++) {
    gboolean key_valid = FALSE;
    gboolean value_valid = FALSE;
    g_autofree gchar *key = identity_result_string (&result, 0, row,
        &key_valid);
    gchar *value = identity_result_string (&result, 1, row, &value_valid);
    if (!key_valid || !value_valid) {
      g_free (value);
      *out_result = WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA;
      goto out;
    }
    gsize slot = G_N_ELEMENTS (keys);
    for (gsize i = 0; i < G_N_ELEMENTS (keys); i++)
      if (strcmp (key, keys[i]) == 0) {
        slot = i;
        break;
      }
    if (slot == G_N_ELEMENTS (keys) || seen[slot]) {
      g_free (value);
      *out_result = WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA;
      goto out;
    }
    seen[slot] = TRUE;
    values[slot] = value;
  }

  if (strcmp (values[0], WYL_FACT_STORE_KIND) != 0
      || !identity_uuid_is_canonical (values[2])
      || values[4][0] == '\0' || values[5][0] == '\0'
      || strcmp (values[2], identity->store_uuid) != 0
      || strcmp (values[4], identity->tenant_id) != 0
      || strcmp (values[5], identity->graph_id) != 0) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY;
    goto out;
  }

  guint64 path_version = 0;
  if (!canonical_decimal (values[3], &path_version)
      || path_version != identity->path_encoding_version
      || path_version != WYL_FACT_STORE_PATH_ENCODING_VERSION) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING;
    goto out;
  }

  guint64 format_version = 0;
  if (!canonical_decimal (values[1], &format_version)
      || format_version != identity->format_version
      || format_version != WYL_FACT_STORE_FORMAT_VERSION) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_FORMAT;
    goto out;
  }

  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  rc = WYRELOG_E_OK;

out:
  for (gsize i = 0; i < G_N_ELEMENTS (values); i++)
    g_free (values[i]);
  duckdb_destroy_result (&result);
  return rc;
}

static wyrelog_error_t
validate_identity_unlocked (wyl_fact_store_t *store,
    const WylFactStoreIdentity *identity, gboolean *out_missing,
    WylFactStoreIdentityResult *out_result)
{
  gboolean exists = FALSE;
  *out_missing = FALSE;
  wyrelog_error_t rc = identity_metadata_exists (store, &exists);
  if (rc != WYRELOG_E_OK) {
    *out_result = rc == WYRELOG_E_POLICY ?
        WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA :
        WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  if (!exists) {
    *out_missing = TRUE;
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA;
    return WYRELOG_E_POLICY;
  }
  rc = validate_identity_schema (store);
  if (rc != WYRELOG_E_OK) {
    *out_result = rc == WYRELOG_E_POLICY ?
        WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA :
        WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
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

  gint64 audit_tables = 0;
  rc = query_single_count (store->conn,
      "SELECT COUNT(*) FROM duckdb_tables() "
      "WHERE database_name=current_database() AND schema_name='main' "
      "AND table_name='audit_events' AND NOT internal;", &audit_tables);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  if (audit_tables != 0) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY;
    return WYRELOG_E_POLICY;
  }
  return validate_identity_values (store, identity, out_result);
}

static wyrelog_error_t
validate_identity_snapshot (wyl_fact_store_t *store,
    const WylFactStoreIdentity *identity, gboolean *out_missing,
    WylFactStoreIdentityResult *out_result)
{
  wyrelog_error_t rc = exec_sql (store->conn, "BEGIN TRANSACTION;");
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }

  rc = validate_identity_unlocked (store, identity, out_missing, out_result);
  const gchar *cleanup_sql =
      rc == WYRELOG_E_OK || rc == WYRELOG_E_POLICY ? "COMMIT;" : "ROLLBACK;";
  if (exec_sql (store->conn, cleanup_sql) != WYRELOG_E_OK) {
    if (cleanup_sql[0] == 'C')
      (void) exec_sql (store->conn, "ROLLBACK;");
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    return WYRELOG_E_INTERNAL;
  }
  return rc;
}

static gboolean
identity_fault (WylFactStoreIdentityTestFault fault)
{
  return g_atomic_int_compare_and_exchange (&identity_test_fault, fault,
      WYL_FACT_STORE_IDENTITY_TEST_FAULT_NONE);
}

void
wyl_fact_store_identity_set_test_fault (WylFactStoreIdentityTestFault fault)
{
  if (fault >= WYL_FACT_STORE_IDENTITY_TEST_FAULT_NONE
      && fault <= WYL_FACT_STORE_IDENTITY_TEST_FAULT_BEFORE_COMMIT)
    g_atomic_int_set (&identity_test_fault, fault);
}

void wyl_fact_store_identity_set_validation_test_hook
    (WylFactStoreIdentityValidationTestHook hook, gpointer user_data)
{
  G_LOCK (identity_validation_test_hook);
  identity_validation_test_hook = hook;
  identity_validation_test_hook_data = user_data;
  G_UNLOCK (identity_validation_test_hook);
}

static wyrelog_error_t
insert_identity_value (wyl_fact_store_t *store, const gchar *key,
    const gchar *value)
{
  duckdb_prepared_statement stmt = NULL;
  if (duckdb_prepare (store->conn,
          "INSERT INTO main.fact_store_metadata(key,value) VALUES (?,?);",
          &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  duckdb_state state = duckdb_bind_varchar_length (stmt, 1, key, strlen (key));
  if (state == DuckDBSuccess)
    state = duckdb_bind_varchar_length (stmt, 2, value, strlen (value));
  if (state == DuckDBSuccess)
    state = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
initialize_identity_unlocked (wyl_fact_store_t *store,
    const WylFactStoreIdentity *identity,
    WylFactStoreIdentityResult *out_result)
{
  gboolean in_transaction = FALSE;
  gboolean empty = FALSE;
  wyrelog_error_t rc = exec_sql (store->conn, "BEGIN TRANSACTION;");
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  in_transaction = TRUE;
  rc = identity_catalog_is_empty (store, &empty);
  if (rc != WYRELOG_E_OK || !empty) {
    *out_result = rc == WYRELOG_E_OK ? WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA :
        WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    rc = rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    goto rollback;
  }
  rc = exec_sql (store->conn,
      "CREATE TABLE main.fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);");
  if (rc != WYRELOG_E_OK)
    goto internal_or_open;
  if (identity_fault (WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE))
    goto injected;

  gchar format[32];
  gchar path_encoding[32];
  g_snprintf (format, sizeof format, "%" G_GUINT64_FORMAT,
      identity->format_version);
  g_snprintf (path_encoding, sizeof path_encoding, "%" G_GUINT64_FORMAT,
      identity->path_encoding_version);
  static const gchar *keys[] = {
    "store_kind", "format_version", "store_uuid", "path_encoding_version",
    "tenant_id", "graph_id"
  };
  const gchar *values[] = {
    WYL_FACT_STORE_KIND, format, identity->store_uuid, path_encoding,
    identity->tenant_id, identity->graph_id
  };
  const WylFactStoreIdentityTestFault faults[] = {
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_STORE_KIND,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_FORMAT_VERSION,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_STORE_UUID,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_PATH_ENCODING_VERSION,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_TENANT_ID,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_GRAPH_ID,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (keys); i++) {
    rc = insert_identity_value (store, keys[i], values[i]);
    if (rc != WYRELOG_E_OK)
      goto internal_or_open;
    if (identity_fault (faults[i]))
      goto injected;
  }

  gboolean missing = FALSE;
  rc = validate_identity_unlocked (store, identity, &missing, out_result);
  if (rc != WYRELOG_E_OK || missing)
    goto rollback;
  if (identity_fault (WYL_FACT_STORE_IDENTITY_TEST_FAULT_BEFORE_COMMIT))
    goto injected;
  rc = exec_sql (store->conn, "COMMIT;");
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    goto rollback;
  }
  return WYRELOG_E_OK;

injected:
  rc = WYRELOG_E_INTERNAL;
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  goto rollback;

internal_or_open:
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;

rollback:
  if (in_transaction && exec_sql (store->conn, "ROLLBACK;") != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    return WYRELOG_E_INTERNAL;
  }
  return rc;
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
      || out_result == NULL || !identity_input_is_valid (identity)
      || (mode != WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY
          && mode != WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY))
    return WYRELOG_E_INVALID;

  /*
   * DuckDB does not serialize two independently opened database objects that
   * race to create the same new catalog.  Keep identity discovery and the
   * initialization commit in one process-wide critical section.  The
   * cross-process writer lease belongs to the later engine-ownership work.
   */
  G_LOCK (identity_open);
  wyl_fact_store_t *self = g_new0 (wyl_fact_store_t, 1);
  wyrelog_error_t rc = open_duckdb_identified (path,
      mode == WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &self->db);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    g_free (self);
    G_UNLOCK (identity_open);
    return rc;
  }
  if (duckdb_connect (self->db, &self->conn) != DuckDBSuccess) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    duckdb_close (&self->db);
    g_free (self);
    G_UNLOCK (identity_open);
    return WYRELOG_E_IO;
  }
  g_mutex_init (&self->lock);

  gboolean missing = FALSE;
  rc = validate_identity_snapshot (self, identity, &missing, out_result);
  if (rc != WYRELOG_E_OK && missing
      && mode == WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY) {
    if (identity->path_encoding_version != WYL_FACT_STORE_PATH_ENCODING_VERSION) {
      *out_result = WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING;
      rc = WYRELOG_E_POLICY;
    } else if (identity->format_version != WYL_FACT_STORE_FORMAT_VERSION) {
      *out_result = WYL_FACT_STORE_IDENTITY_RESULT_FORMAT;
      rc = WYRELOG_E_POLICY;
    } else {
      rc = initialize_identity_unlocked (self, identity, out_result);
    }
  }
  if (rc != WYRELOG_E_OK) {
    wyl_fact_store_close (self);
    G_UNLOCK (identity_open);
    return rc;
  }

  self->identity_tenant_id = g_strdup (identity->tenant_id);
  self->identity_graph_id = g_strdup (identity->graph_id);
  self->identity_store_uuid = g_strdup (identity->store_uuid);
  self->identity_format_version = identity->format_version;
  self->identity_path_encoding_version = identity->path_encoding_version;
  *out_store = self;
  G_UNLOCK (identity_open);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_store_open (const gchar *path, wyl_fact_store_t **out_store)
{
  if (out_store == NULL)
    return WYRELOG_E_INVALID;

  wyl_fact_store_t *self = g_new0 (wyl_fact_store_t, 1);
  if (open_duckdb_with_thread_budget (path, &self->db) != WYRELOG_E_OK) {
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
        "  created_at_us BIGINT NOT NULL" ");");
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
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
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
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
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
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
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

wyrelog_error_t
wyl_fact_store_append_batch (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted)
{
  if (out_inserted != NULL)
    *out_inserted = FALSE;
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
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (store->conn, "COMMIT;");
  else
    (void) exec_sql (store->conn, "ROLLBACK;");
  g_mutex_unlock (&store->lock);
  if (rc == WYRELOG_E_OK && out_inserted != NULL)
    *out_inserted = TRUE;
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
  if (out_inserted != NULL)
    *out_inserted = FALSE;
  if (store == NULL)
    return WYRELOG_E_INVALID;
  if (batch == NULL)
    return WYRELOG_E_INVALID;
  /* Shallow copy: struct only, not pointed-to rows/values (caller-owned). */
  wyl_fact_store_batch_t *batch_copy = g_memdup2 (batch, sizeof (*batch));
  if (batch_copy == NULL)
    return WYRELOG_E_NOMEM;
  batch_copy->op = WYL_FACT_STORE_OP_RETRACT;
  wyrelog_error_t rc = wyl_fact_store_append_batch (store, schema, batch_copy,
      out_inserted);
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
  if (duckdb_prepare (store->conn, sql, &stmt) != DuckDBSuccess)
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

/* Tier-3 hard-delete: physically removes all rows for batch_id from the
 * projection table, fact_event_log, and fact_batches (in FK-safe order),
 * then records the operation in fact_forget_audit.
 *
 * Each statement runs in autocommit mode (no explicit transaction) because
 * DuckDB does not propagate intra-transaction DELETE visibility to FK checks
 * within the same transaction.  The audit INSERT is the final step; if it
 * fails the data rows are already gone and the operator must retry. */
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

  /* Build the single-quoted, escaped batch_id literal once. */
  g_autoptr (GString) batch_id_lit = g_string_new ("'");
  for (const gchar * p = opts->batch_id; *p != '\0'; p++) {
    if (*p == '\'')
      g_string_append_c (batch_id_lit, '\'');
    g_string_append_c (batch_id_lit, *p);
  }
  g_string_append_c (batch_id_lit, '\'');

  g_mutex_lock (&store->lock);

  /* Verify the batch exists. */
  TriggerBatchScope scope = { 0 };
  gboolean found = FALSE;
  rc = lookup_batch_scope_unlocked (store, opts->batch_id, &scope, &found);
  if (rc != WYRELOG_E_OK)
    goto forget_unlock;
  if (!found) {
    rc = WYRELOG_E_NOT_FOUND;
    goto forget_unlock;
  }
  trigger_batch_scope_clear (&scope);

  /* Count projection rows before deletion. */
  gint64 rows_purged = 0;
  {
    g_autoptr (GString) count_sql = g_string_new ("SELECT COUNT(*) FROM ");
    append_duckdb_identifier (count_sql, table);
    g_string_append_printf (count_sql, " WHERE __wyl_batch_id = %s;",
        batch_id_lit->str);
    duckdb_result result = { 0 };
    if (duckdb_query (store->conn, count_sql->str, &result) != DuckDBSuccess) {
      duckdb_destroy_result (&result);
      rc = WYRELOG_E_IO;
      goto forget_unlock;
    }
    rows_purged = duckdb_value_int64 (&result, 0, 0);
    duckdb_destroy_result (&result);
  }

  /* 1. DELETE projection rows. */
  {
    g_autoptr (GString) sql = g_string_new ("DELETE FROM ");
    append_duckdb_identifier (sql, table);
    g_string_append_printf (sql, " WHERE __wyl_batch_id = %s;",
        batch_id_lit->str);
    rc = exec_sql (store->conn, sql->str);
    if (rc != WYRELOG_E_OK)
      goto forget_unlock;
  }

  /* 2. DELETE fact_event_log rows (must precede fact_batches due to FK). */
  {
    g_autofree gchar *sql = g_strdup_printf
        ("DELETE FROM fact_event_log WHERE batch_id = %s;",
        batch_id_lit->str);
    rc = exec_sql (store->conn, sql);
    if (rc != WYRELOG_E_OK)
      goto forget_unlock;
  }

  /* 3. DELETE fact_batches row. */
  {
    g_autofree gchar *sql = g_strdup_printf
        ("DELETE FROM fact_batches WHERE batch_id = %s;",
        batch_id_lit->str);
    rc = exec_sql (store->conn, sql);
    if (rc != WYRELOG_E_OK)
      goto forget_unlock;
  }

  /* 4. INSERT audit record. */
  {
    g_autoptr (GString) tid_lit = g_string_new ("'");
    for (const gchar * p = schema->tenant_id; *p != '\0'; p++) {
      if (*p == '\'')
        g_string_append_c (tid_lit, '\'');
      g_string_append_c (tid_lit, *p);
    }
    g_string_append_c (tid_lit, '\'');

    g_autoptr (GString) gid_lit = g_string_new ("'");
    for (const gchar * p = schema->graph_id; *p != '\0'; p++) {
      if (*p == '\'')
        g_string_append_c (gid_lit, '\'');
      g_string_append_c (gid_lit, *p);
    }
    g_string_append_c (gid_lit, '\'');

    g_autoptr (GString) op_lit = g_string_new ("'");
    for (const gchar * p = opts->operator_id; *p != '\0'; p++) {
      if (*p == '\'')
        g_string_append_c (op_lit, '\'');
      g_string_append_c (op_lit, *p);
    }
    g_string_append_c (op_lit, '\'');

    g_autoptr (GString) reason_lit = g_string_new ("'");
    for (const gchar * p = opts->reason; *p != '\0'; p++) {
      if (*p == '\'')
        g_string_append_c (reason_lit, '\'');
      g_string_append_c (reason_lit, *p);
    }
    g_string_append_c (reason_lit, '\'');

    gint64 now_us = g_get_real_time ();
    g_autofree gchar *audit_sql = g_strdup_printf
        ("INSERT INTO fact_forget_audit "
        "(id, batch_id, tenant_id, graph_id, operator, reason, "
        " rows_purged, created_at_us) "
        "VALUES ("
        "(SELECT COALESCE(MAX(id), 0) + 1 FROM fact_forget_audit),"
        " %s, %s, %s, %s, %s," " %" G_GINT64_FORMAT ", %" G_GINT64_FORMAT ");",
        batch_id_lit->str, tid_lit->str, gid_lit->str,
        op_lit->str, reason_lit->str, rows_purged, now_us);
    rc = exec_sql (store->conn, audit_sql);
    if (rc != WYRELOG_E_OK)
      goto forget_unlock;
  }

  if (out_rows_purged != NULL)
    *out_rows_purged = (gsize) rows_purged;

forget_unlock:
  trigger_batch_scope_clear (&scope);
  g_mutex_unlock (&store->lock);
  return rc;
}

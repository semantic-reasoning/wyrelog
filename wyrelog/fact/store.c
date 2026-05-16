/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "store-private.h"

#include <string.h>

#include "compound-private.h"

struct wyl_fact_store_t
{
  duckdb_database db;
  duckdb_connection conn;
  GMutex lock;
};

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

wyrelog_error_t
wyl_fact_store_open (const gchar *path, wyl_fact_store_t **out_store)
{
  if (out_store == NULL)
    return WYRELOG_E_INVALID;
  const gchar *effective_path = path;
  if (path != NULL && g_strcmp0 (path, ":memory:") == 0)
    effective_path = NULL;

  wyl_fact_store_t *self = g_new0 (wyl_fact_store_t, 1);
  if (duckdb_open (effective_path, &self->db) != DuckDBSuccess) {
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

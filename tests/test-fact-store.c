/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/fact/store-private.h"
#include "wyrelog/policy/store-private.h"

static gboolean
count_i64 (duckdb_connection conn, const gchar *sql, gint64 *out_value)
{
  duckdb_result result = { 0 };
  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return FALSE;
  }
  *out_value = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return TRUE;
}

static gboolean
query_text (duckdb_connection conn, const gchar *sql, gchar **out_value)
{
  duckdb_result result = { 0 };
  *out_value = NULL;
  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return FALSE;
  }
  if (duckdb_row_count (&result) == 0) {
    duckdb_destroy_result (&result);
    return FALSE;
  }
  gchar *value = duckdb_value_varchar (&result, 0, 0);
  *out_value = g_strdup (value);
  duckdb_free (value);
  duckdb_destroy_result (&result);
  return *out_value != NULL;
}

static gboolean
create_duckdb_with_sql (const gchar *path, const gchar *sql)
{
  duckdb_database db;
  duckdb_connection conn;
  duckdb_result result = { 0 };

  if (duckdb_open (path, &db) != DuckDBSuccess)
    return FALSE;
  if (duckdb_connect (db, &conn) != DuckDBSuccess) {
    duckdb_close (&db);
    return FALSE;
  }
  gboolean ok = duckdb_query (conn, sql, &result) == DuckDBSuccess;
  duckdb_destroy_result (&result);
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  return ok;
}

static wyl_policy_fact_relation_schema_options_t
make_schema (const wyl_policy_fact_relation_schema_column_t *columns,
    gsize n_columns)
{
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = n_columns,
  };
  return schema;
}

static gint
check_fact_store_appends_idempotently (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 10;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 11;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"customer_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"status", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
      G_N_ELEMENTS (columns));
  g_autofree gchar *table = NULL;
  if (wyl_fact_store_ensure_projection (store, &schema, &table)
      != WYRELOG_E_OK)
    return 12;
  if (table == NULL || !g_str_has_prefix (table, "rel_"))
    return 13;
  wyl_policy_fact_relation_schema_options_t tenant_b_schema = schema;
  tenant_b_schema.tenant_id = "tenant-b";
  g_autofree gchar *tenant_b_table =
      wyl_fact_store_projection_table_name (&tenant_b_schema);
  if (tenant_b_table == NULL || g_strcmp0 (tenant_b_table, table) == 0)
    return 131;
  if (wyl_fact_store_ensure_projection (store, &tenant_b_schema, NULL)
      != WYRELOG_E_POLICY)
    return 132;

  const gsize n_rows = 10000;
  wyl_fact_value_t *values = g_new0 (wyl_fact_value_t,
      n_rows * G_N_ELEMENTS (columns));
  wyl_fact_row_t *rows = g_new0 (wyl_fact_row_t, n_rows);
  gchar **order_ids = g_new0 (gchar *, n_rows);
  gchar **customer_ids = g_new0 (gchar *, n_rows);
  for (gsize i = 0; i < n_rows; i++) {
    order_ids[i] = g_strdup_printf ("o-%05" G_GSIZE_FORMAT, i);
    customer_ids[i] = g_strdup_printf ("c-%03" G_GSIZE_FORMAT, i % 128);
    wyl_fact_value_t *row = &values[i * G_N_ELEMENTS (columns)];
    row[0].type = WYL_FACT_VALUE_SYMBOL;
    row[0].as.text = order_ids[i];
    row[1].type = WYL_FACT_VALUE_SYMBOL;
    row[1].as.text = customer_ids[i];
    row[2].type = WYL_FACT_VALUE_INT64;
    row[2].as.int64_value = (gint64) i;
    row[3].type = WYL_FACT_VALUE_SYMBOL;
    row[3].as.text = (i % 2) == 0 ? "open" : "closed";
    rows[i].values = row;
    rows[i].n_values = G_N_ELEMENTS (columns);
  }

  const wyl_fact_store_batch_t batch = {
    .batch_id = "batch-1",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .request_id = "request-1",
    .idempotency_key = "source:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = n_rows,
  };
  gboolean inserted = FALSE;
  if (wyl_fact_store_append_batch (store, &schema, &batch, &inserted)
      != WYRELOG_E_OK || !inserted)
    return 14;
  if (wyl_fact_store_append_batch (store, &schema, &batch, &inserted)
      != WYRELOG_E_OK || inserted)
    return 15;
  wyl_fact_store_batch_t conflicting_key = batch;
  conflicting_key.idempotency_key = "source:other";
  if (wyl_fact_store_append_batch (store, &schema, &conflicting_key, NULL)
      != WYRELOG_E_POLICY)
    return 151;
  wyl_fact_store_batch_t conflicting_batch = batch;
  conflicting_batch.batch_id = "batch-other";
  if (wyl_fact_store_append_batch (store, &schema, &conflicting_batch, NULL)
      != WYRELOG_E_POLICY)
    return 152;

  duckdb_connection conn = wyl_fact_store_get_connection (store);
  gint64 count = 0;
  g_autofree gchar *count_sql = g_strdup_printf ("SELECT COUNT(*) FROM %s;",
      table);
  if (!count_i64 (conn, count_sql, &count) || count != (gint64) n_rows)
    return 16;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_batches;", &count)
      || count != 1)
    return 17;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_event_log;", &count)
      || count != (gint64) n_rows)
    return 18;

  g_autofree gchar *type_sql = g_strdup_printf
      ("SELECT type FROM pragma_table_info('%s') WHERE name = 'amount';",
      table);
  g_autofree gchar *amount_type = NULL;
  if (!query_text (conn, type_sql, &amount_type)
      || g_strcmp0 (amount_type, "BIGINT") != 0)
    return 19;
  if (!count_i64 (conn,
          "SELECT COUNT(*) FROM pragma_table_info('fact_event_log') "
          "WHERE lower(type) LIKE '%json%';", &count) || count != 0)
    return 20;
  g_autofree gchar *scope_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE __wyl_tenant_id = 'tenant-a' "
      "AND __wyl_graph_id = 'orders';", table);
  if (!count_i64 (conn, scope_sql, &count) || count != (gint64) n_rows)
    return 201;

  wyl_fact_value_t bad_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-00000"},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "c-000"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 999999},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "open"},
  };
  const wyl_fact_row_t bad_rows[] = {
    {bad_values, G_N_ELEMENTS (bad_values)},
  };
  wyl_fact_store_batch_t conflict = batch;
  conflict.rows = bad_rows;
  conflict.n_rows = G_N_ELEMENTS (bad_rows);
  if (wyl_fact_store_append_batch (store, &schema, &conflict, NULL)
      != WYRELOG_E_POLICY)
    return 21;

  for (gsize i = 0; i < n_rows; i++) {
    g_free (order_ids[i]);
    g_free (customer_ids[i]);
  }
  g_free (order_ids);
  g_free (customer_ids);
  g_free (rows);
  g_free (values);
  return 0;
}

static gint
check_fact_corruption_does_not_block_policy_open (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-corrupt-XXXXXX", &error);
  if (dir == NULL)
    return 50;
  g_autofree gchar *path = g_build_filename (dir, "facts.duckdb", NULL);
  if (!g_file_set_contents (path, "not a duckdb database", -1, &error))
    return 51;

  wyl_fact_store_t *fact_store = NULL;
  if (wyl_fact_store_open (path, &fact_store) == WYRELOG_E_OK) {
    wyl_fact_store_close (fact_store);
    return 52;
  }

  g_autoptr (wyl_policy_store_t) policy_store = NULL;
  if (wyl_policy_store_open (NULL, &policy_store) != WYRELOG_E_OK)
    return 53;
  if (wyl_policy_store_create_schema (policy_store) != WYRELOG_E_OK)
    return 54;

  (void) g_remove (path);
  (void) g_rmdir (dir);
  return 0;
}

static gint
expect_projection_drift_rejected (const wyl_policy_fact_relation_schema_column_t
    *columns, gsize n_columns, const gchar *projection_columns_sql,
    gint base_code)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return base_code;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return base_code + 1;
  wyl_policy_fact_relation_schema_options_t schema =
      make_schema (columns, n_columns);
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  g_autofree gchar *sql = g_strdup_printf
      ("CREATE TABLE %s (%s);", table, projection_columns_sql);
  duckdb_result drift_result = { 0 };
  if (duckdb_query (wyl_fact_store_get_connection (store), sql, &drift_result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&drift_result);
    return base_code + 2;
  }
  duckdb_destroy_result (&drift_result);
  if (wyl_fact_store_ensure_projection (store, &schema, NULL)
      != WYRELOG_E_POLICY)
    return base_code + 3;
  return 0;
}

static gint
check_fact_store_rejects_schema_drift (void)
{
  const wyl_policy_fact_relation_schema_column_t required_columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  gint rc = expect_projection_drift_rejected (required_columns,
      G_N_ELEMENTS (required_columns),
      "order_id VARCHAR NOT NULL, amount BIGINT NOT NULL, "
      "__wyl_tenant_id VARCHAR NOT NULL, __wyl_graph_id VARCHAR NOT NULL, "
      "__wyl_seq BIGINT NOT NULL, __wyl_batch_id VARCHAR NOT NULL, "
      "__wyl_row_index BIGINT NOT NULL, __wyl_valid BOOLEAN NOT NULL", 30);
  if (rc != 0)
    return rc;

  rc = expect_projection_drift_rejected (required_columns,
      G_N_ELEMENTS (required_columns),
      "order_id VARCHAR NOT NULL, amount VARCHAR NOT NULL, "
      "__wyl_tenant_id VARCHAR NOT NULL, __wyl_graph_id VARCHAR NOT NULL, "
      "__wyl_seq BIGINT NOT NULL, __wyl_batch_id VARCHAR NOT NULL, "
      "__wyl_row_index BIGINT NOT NULL, __wyl_valid BOOLEAN NOT NULL, "
      "UNIQUE (__wyl_batch_id, __wyl_row_index)", 40);
  if (rc != 0)
    return rc;

  rc = expect_projection_drift_rejected (required_columns,
      G_N_ELEMENTS (required_columns),
      "order_id VARCHAR NOT NULL, amount BIGINT NOT NULL, "
      "__wyl_tenant_id VARCHAR NOT NULL, __wyl_graph_id VARCHAR NOT NULL, "
      "__wyl_seq BIGINT NOT NULL, __wyl_batch_id VARCHAR NOT NULL, "
      "__wyl_row_index BIGINT NOT NULL, __wyl_valid BOOLEAN NOT NULL, "
      "UNIQUE (__wyl_batch_id, __wyl_row_index, amount)", 50);
  if (rc != 0)
    return rc;

  const wyl_policy_fact_relation_schema_column_t nullable_columns[] = {
    {"note", "string", TRUE, TRUE},
  };
  rc = expect_projection_drift_rejected (nullable_columns,
      G_N_ELEMENTS (nullable_columns),
      "note VARCHAR NOT NULL, __wyl_tenant_id VARCHAR NOT NULL, "
      "__wyl_graph_id VARCHAR NOT NULL, __wyl_seq BIGINT NOT NULL, "
      "__wyl_batch_id VARCHAR NOT NULL, __wyl_row_index BIGINT NOT NULL, "
      "__wyl_valid BOOLEAN NOT NULL, "
      "UNIQUE (__wyl_batch_id, __wyl_row_index)", 60);
  if (rc != 0)
    return rc;

  return 0;
}

static gint
check_fact_store_rejects_audit_shape (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-store-XXXXXX", &error);
  if (dir == NULL)
    return 80;
  g_autofree gchar *path = g_build_filename (dir, "audit.duckdb", NULL);
  if (!create_duckdb_with_sql (path,
          "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);"))
    return 81;

  wyl_fact_store_t *store = NULL;
  if (wyl_fact_store_open (path, &store) != WYRELOG_E_POLICY) {
    wyl_fact_store_close (store);
    return 82;
  }
  (void) g_remove (path);
  g_autofree gchar *mixed_path = g_build_filename (dir, "mixed.duckdb", NULL);
  if (!create_duckdb_with_sql (mixed_path,
          "CREATE TABLE fact_store_metadata (key VARCHAR PRIMARY KEY, "
          "value VARCHAR NOT NULL);"
          "INSERT INTO fact_store_metadata VALUES "
          "('store_kind', 'wyrelog.fact');"
          "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);"))
    return 83;
  if (wyl_fact_store_open (mixed_path, &store) != WYRELOG_E_POLICY) {
    wyl_fact_store_close (store);
    return 84;
  }
  (void) g_remove (mixed_path);
  g_autofree gchar *wrong_path = g_build_filename (dir, "wrong.duckdb", NULL);
  if (!create_duckdb_with_sql (wrong_path,
          "CREATE TABLE fact_store_metadata (key VARCHAR PRIMARY KEY, "
          "value VARCHAR NOT NULL);"
          "INSERT INTO fact_store_metadata VALUES "
          "('store_kind', 'wyrelog.audit');"))
    return 85;
  if (wyl_fact_store_open (wrong_path, &store) != WYRELOG_E_POLICY) {
    wyl_fact_store_close (store);
    return 86;
  }
  (void) g_remove (wrong_path);

  g_autoptr (wyl_fact_store_t) live_store = NULL;
  if (wyl_fact_store_open (NULL, &live_store) != WYRELOG_E_OK)
    return 87;
  if (wyl_fact_store_create_schema (live_store) != WYRELOG_E_OK)
    return 88;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
      G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (live_store, &schema, NULL)
      != WYRELOG_E_OK)
    return 89;
  duckdb_result audit_result = { 0 };
  if (duckdb_query (wyl_fact_store_get_connection (live_store),
          "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);",
          &audit_result) != DuckDBSuccess) {
    duckdb_destroy_result (&audit_result);
    return 90;
  }
  duckdb_destroy_result (&audit_result);
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
  };
  const wyl_fact_row_t rows[] = {
    {values, G_N_ELEMENTS (values)},
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "batch-contaminated",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .idempotency_key = "contaminated:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  if (wyl_fact_store_append_batch (live_store, &schema, &batch, NULL)
      != WYRELOG_E_POLICY)
    return 91;

  (void) g_rmdir (dir);
  return 0;
}

int
main (void)
{
  gint rc = check_fact_store_appends_idempotently ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_rejects_schema_drift ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_rejects_audit_shape ();
  if (rc != 0)
    return rc;
  rc = check_fact_corruption_does_not_block_policy_open ();
  if (rc != 0)
    return rc;
  return 0;
}

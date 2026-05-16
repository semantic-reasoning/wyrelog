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
check_fact_store_retracts_idempotently (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 100;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 101;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
      G_N_ELEMENTS (columns));
  g_autofree gchar *table = NULL;
  if (wyl_fact_store_ensure_projection (store, &schema, &table)
      != WYRELOG_E_OK)
    return 102;

  /* Case 1: normal retract -> inserted=TRUE. */
  wyl_fact_value_t assert_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-a"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 11},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-b"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 22},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = FALSE},
  };
  const wyl_fact_row_t assert_rows[] = {
    {assert_values, 3},
    {assert_values + 3, 3},
  };
  const wyl_fact_store_batch_t assert_batch = {
    .batch_id = "batch-1",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .idempotency_key = "assert:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = assert_rows,
    .n_rows = G_N_ELEMENTS (assert_rows),
  };
  gboolean inserted = FALSE;
  if (wyl_fact_store_append_batch (store, &schema, &assert_batch, &inserted)
      != WYRELOG_E_OK || !inserted)
    return 103;

  wyl_fact_value_t retract_a_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-a"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 11},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
  };
  const wyl_fact_row_t retract_a_rows[] = {
    {retract_a_values, 3},
  };
  const wyl_fact_store_batch_t retract_a_batch = {
    .batch_id = "batch-2",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .idempotency_key = "retract:1",
    .op = WYL_FACT_STORE_OP_ASSERT,     /* must be overridden by retract API. */
    .rows = retract_a_rows,
    .n_rows = G_N_ELEMENTS (retract_a_rows),
  };
  inserted = FALSE;
  if (wyl_fact_store_retract_batch (store, &schema, &retract_a_batch,
          &inserted) != WYRELOG_E_OK || !inserted)
    return 104;

  duckdb_connection conn = wyl_fact_store_get_connection (store);
  gint64 count = 0;
  g_autofree gchar *order_a_valid_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE order_id = 'order-a' "
      "AND __wyl_valid = TRUE;", table);
  if (!count_i64 (conn, order_a_valid_sql, &count) || count != 0)
    return 105;
  g_autofree gchar *order_a_invalid_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE order_id = 'order-a' "
      "AND __wyl_valid = FALSE;", table);
  if (!count_i64 (conn, order_a_invalid_sql, &count) || count != 1)
    return 106;
  g_autofree gchar *order_b_valid_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE order_id = 'order-b' "
      "AND __wyl_valid = TRUE;", table);
  if (!count_i64 (conn, order_b_valid_sql, &count) || count != 1)
    return 107;

  /* Confirm batch op was recorded as retract. */
  g_autofree gchar *batch_op = NULL;
  if (!query_text (conn,
          "SELECT op FROM fact_batches WHERE batch_id = 'batch-2';",
          &batch_op) || g_strcmp0 (batch_op, "retract") != 0)
    return 108;

  /* Case 2: idempotent retry -> inserted=FALSE. */
  inserted = TRUE;
  if (wyl_fact_store_retract_batch (store, &schema, &retract_a_batch,
          &inserted) != WYRELOG_E_OK || inserted)
    return 110;

  /* Case 3: non-existent row retract -> WYRELOG_E_OK (silent ok). */
  wyl_fact_value_t retract_c_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-c"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 99},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = FALSE},
  };
  const wyl_fact_row_t retract_c_rows[] = {
    {retract_c_values, 3},
  };
  const wyl_fact_store_batch_t retract_c_batch = {
    .batch_id = "batch-3",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .idempotency_key = "retract:2",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = retract_c_rows,
    .n_rows = G_N_ELEMENTS (retract_c_rows),
  };
  inserted = FALSE;
  if (wyl_fact_store_retract_batch (store, &schema, &retract_c_batch,
          &inserted) != WYRELOG_E_OK || !inserted)
    return 120;
  g_autofree gchar *order_c_invalid_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE order_id = 'order-c' "
      "AND __wyl_valid = FALSE;", table);
  if (!count_i64 (conn, order_c_invalid_sql, &count) || count != 1)
    return 121;

  /* Case 4: wrong scope retract -> WYRELOG_E_POLICY. */
  wyl_policy_fact_relation_schema_options_t wrong_schema = schema;
  wrong_schema.tenant_id = "tenant-b";
  wrong_schema.graph_id = "graph-b";
  wyl_fact_store_batch_t wrong_scope_batch = retract_a_batch;
  wrong_scope_batch.batch_id = "batch-4";
  wrong_scope_batch.tenant_id = "tenant-b";
  wrong_scope_batch.graph_id = "graph-b";
  wrong_scope_batch.idempotency_key = "retract:3";
  if (wyl_fact_store_retract_batch (store, &wrong_schema, &wrong_scope_batch,
          NULL) != WYRELOG_E_POLICY)
    return 130;

  return 0;
}

/* Tier-2 wyl_fact_store_retract_by_batch_id: helpers + 10 cases. */
typedef struct
{
  wyl_fact_store_t *store;
  wyl_policy_fact_relation_schema_options_t schema;
  gchar *table;
} RetractByIdFixture;

static gint
retract_by_id_fixture_init (RetractByIdFixture *fix,
    const wyl_policy_fact_relation_schema_column_t *columns, gsize n_columns)
{
  fix->store = NULL;
  fix->table = NULL;
  if (wyl_fact_store_open (NULL, &fix->store) != WYRELOG_E_OK)
    return 1;
  if (wyl_fact_store_create_schema (fix->store) != WYRELOG_E_OK)
    return 2;
  fix->schema = make_schema (columns, n_columns);
  if (wyl_fact_store_ensure_projection (fix->store, &fix->schema, &fix->table)
      != WYRELOG_E_OK)
    return 3;
  return 0;
}

static void
retract_by_id_fixture_clear (RetractByIdFixture *fix)
{
  g_free (fix->table);
  wyl_fact_store_close (fix->store);
}

static gint
retract_by_id_seed_assert (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const gchar *batch_id, const gchar *idempotency_key,
    const wyl_fact_row_t *rows, gsize n_rows)
{
  wyl_fact_store_batch_t batch = {
    .batch_id = batch_id,
    .tenant_id = schema->tenant_id,
    .graph_id = schema->graph_id,
    .namespace_id = schema->namespace_id,
    .relation_name = schema->relation_name,
    .schema_version = schema->schema_version,
    .source = "unit-test",
    .idempotency_key = idempotency_key,
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = n_rows,
  };
  gboolean inserted = FALSE;
  if (wyl_fact_store_append_batch (store, schema, &batch, &inserted)
      != WYRELOG_E_OK || !inserted)
    return 1;
  return 0;
}

static gint
check_retract_by_id_normal_three_rows (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  gint rc_init = retract_by_id_fixture_init (&fix, columns,
      G_N_ELEMENTS (columns));
  if (rc_init != 0)
    return 1000 + rc_init;

  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 1},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-2"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 2},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-3"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 3},
  };
  const wyl_fact_row_t rows[] = {
    {values, 2},
    {values + 2, 2},
    {values + 4, 2},
  };
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "trigger-1",
          "seed:1", rows, 3) != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1010;
  }

  gboolean inserted = FALSE;
  gint64 row_count = -1;
  wyrelog_error_t rc = wyl_fact_store_retract_by_batch_id (fix.store,
      &fix.schema, "trigger-1", "retract-1", "unit-test", "request-1",
      "idem:retract:1", &inserted, &row_count);
  if (rc != WYRELOG_E_OK || !inserted || row_count != 3) {
    retract_by_id_fixture_clear (&fix);
    return 1020;
  }

  duckdb_connection conn = wyl_fact_store_get_connection (fix.store);
  gint64 count = 0;
  /* Original assert rows (trigger-1) stay physically in the table with
   * __wyl_valid=TRUE; the retract adds NEW tombstone rows for retract-1
   * with __wyl_valid=FALSE — it does NOT flip existing rows in-place. */
  g_autofree gchar *trigger_valid_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE __wyl_valid = TRUE "
      "AND __wyl_batch_id = 'trigger-1';", fix.table);
  if (!count_i64 (conn, trigger_valid_sql, &count) || count != 3) {
    retract_by_id_fixture_clear (&fix);
    return 1030;
  }
  g_autofree gchar *invalid_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE __wyl_valid = FALSE "
      "AND __wyl_batch_id = 'retract-1';", fix.table);
  if (!count_i64 (conn, invalid_sql, &count) || count != 3) {
    retract_by_id_fixture_clear (&fix);
    return 1040;
  }
  g_autofree gchar *batch_op = NULL;
  if (!query_text (conn,
          "SELECT op FROM fact_batches WHERE batch_id = 'retract-1';",
          &batch_op) || g_strcmp0 (batch_op, "retract") != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1050;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_idempotent_replay (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1100;
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
  };
  const wyl_fact_row_t rows[] = {
    {values, 1},
  };
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "trig",
          "seed:1", rows, 1) != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1101;
  }
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_OK || !inserted || row_count != 1) {
    retract_by_id_fixture_clear (&fix);
    return 1102;
  }
  /* Replay with same trigger + new_batch_id + idempotency_key. */
  inserted = TRUE;
  row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_OK || inserted) {
    retract_by_id_fixture_clear (&fix);
    return 1103;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_second_retract_same_trigger (void)
{
  /* In the append-only tombstone model the trigger batch rows always have
   * __wyl_valid=TRUE; each retract-by-id on the same trigger inserts a fresh
   * set of tombstone rows with a new batch_id and __wyl_valid=FALSE.
   * A second call with a different new_batch_id+idempotency_key must succeed
   * (inserted=TRUE) and report row_count equal to the trigger's row count. */
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1200;
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
  };
  const wyl_fact_row_t rows[] = {
    {values, 1},
  };
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "trig",
          "seed:1", rows, 1) != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1201;
  }
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_OK || !inserted || row_count != 1) {
    retract_by_id_fixture_clear (&fix);
    return 1202;
  }
  /* Second retract-by-id with a DIFFERENT batch_id+idempotency_key.
   * The trigger rows are still valid in the projection table (tombstoning is
   * append-only), so this also succeeds with row_count=1. */
  inserted = FALSE;
  row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "new-2", "src", "req", "idem-2", &inserted, &row_count)
      != WYRELOG_E_OK || !inserted || row_count != 1) {
    retract_by_id_fixture_clear (&fix);
    return 1203;
  }
  /* Two tombstone batches now exist. */
  duckdb_connection conn = wyl_fact_store_get_connection (fix.store);
  gint64 count = 0;
  if (!count_i64 (conn,
          "SELECT COUNT(*) FROM fact_batches WHERE op = 'retract';",
          &count) || count != 2) {
    retract_by_id_fixture_clear (&fix);
    return 1204;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_not_found (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1300;
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  wyrelog_error_t rc = wyl_fact_store_retract_by_batch_id (fix.store,
      &fix.schema, "missing", "new-1", "src", "req", "idem-1", &inserted,
      &row_count);
  if (rc != WYRELOG_E_NOT_FOUND) {
    retract_by_id_fixture_clear (&fix);
    return 1301;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_trigger_is_retract_batch (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1400;
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
  };
  const wyl_fact_row_t rows[] = {
    {values, 1},
  };
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "seed",
          "seed:1", rows, 1) != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1401;
  }
  /* Make a real retract batch via Tier-1 API. */
  wyl_fact_store_batch_t retract_batch = {
    .batch_id = "ret",
    .tenant_id = fix.schema.tenant_id,
    .graph_id = fix.schema.graph_id,
    .namespace_id = fix.schema.namespace_id,
    .relation_name = fix.schema.relation_name,
    .schema_version = fix.schema.schema_version,
    .source = "unit-test",
    .idempotency_key = "retract-batch:1",
    .op = WYL_FACT_STORE_OP_ASSERT,     /* overridden by Tier-1 wrapper */
    .rows = rows,
    .n_rows = 1,
  };
  if (wyl_fact_store_retract_batch (fix.store, &fix.schema, &retract_batch,
          NULL) != WYRELOG_E_OK) {
    retract_by_id_fixture_clear (&fix);
    return 1402;
  }
  /* Now pointing retract-by-id at a retract batch must be rejected. */
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "ret",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_POLICY) {
    retract_by_id_fixture_clear (&fix);
    return 1403;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_scope_mismatch (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1500;
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
  };
  const wyl_fact_row_t rows[] = {
    {values, 1},
  };
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "trig",
          "seed:1", rows, 1) != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1501;
  }
  /* Caller schema describes a different relation than the trigger batch. */
  wyl_policy_fact_relation_schema_options_t wrong = fix.schema;
  wrong.relation_name = "other";
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &wrong, "trig",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_POLICY) {
    retract_by_id_fixture_clear (&fix);
    return 1502;
  }
  /* Tenant mismatch. */
  wyl_policy_fact_relation_schema_options_t wrong_tenant = fix.schema;
  wrong_tenant.tenant_id = "tenant-other";
  if (wyl_fact_store_retract_by_batch_id (fix.store, &wrong_tenant, "trig",
          "new-2", "src", "req", "idem-2", &inserted, &row_count)
      != WYRELOG_E_POLICY) {
    retract_by_id_fixture_clear (&fix);
    return 1503;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_exceeds_max_rows (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1600;
  const gsize n_rows = WYL_FACT_STORE_RETRACT_BY_BATCH_MAX_ROWS + 1;
  wyl_fact_value_t *values = g_new0 (wyl_fact_value_t, n_rows);
  wyl_fact_row_t *rows = g_new0 (wyl_fact_row_t, n_rows);
  gchar **ids = g_new0 (gchar *, n_rows);
  for (gsize i = 0; i < n_rows; i++) {
    ids[i] = g_strdup_printf ("o-%05" G_GSIZE_FORMAT, i);
    values[i].type = WYL_FACT_VALUE_SYMBOL;
    values[i].as.text = ids[i];
    rows[i].values = &values[i];
    rows[i].n_values = 1;
  }
  gint result = 0;
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "huge",
          "seed:1", rows, n_rows) != 0) {
    result = 1601;
    goto cleanup;
  }
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "huge",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_POLICY) {
    result = 1602;
    goto cleanup;
  }
cleanup:
  for (gsize i = 0; i < n_rows; i++)
    g_free (ids[i]);
  g_free (ids);
  g_free (rows);
  g_free (values);
  retract_by_id_fixture_clear (&fix);
  return result;
}

static gint
check_retract_by_id_schema_version_mismatch (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1700;
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
  };
  const wyl_fact_row_t rows[] = {
    {values, 1},
  };
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "trig",
          "seed:1", rows, 1) != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1701;
  }
  wyl_policy_fact_relation_schema_options_t bumped = fix.schema;
  bumped.schema_version = 2;
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &bumped, "trig",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_POLICY) {
    retract_by_id_fixture_clear (&fix);
    return 1702;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_invalid_args (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 1) != 0)
    return 1800;
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (NULL, &fix.schema, "trig",
          "new", "src", "req", "idem", &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1801;
  }
  if (wyl_fact_store_retract_by_batch_id (fix.store, NULL, "trig",
          "new", "src", "req", "idem", &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1802;
  }
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, NULL,
          "new", "src", "req", "idem", &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1803;
  }
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "",
          "new", "src", "req", "idem", &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1804;
  }
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          NULL, "src", "req", "idem", &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1805;
  }
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "", "src", "req", "idem", &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1806;
  }
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "new", "src", "req", NULL, &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1807;
  }
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "new", "src", "req", "", &inserted, &row_count)
      != WYRELOG_E_INVALID) {
    retract_by_id_fixture_clear (&fix);
    return 1808;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_retract_by_id_partial_already_retracted (void)
{
  /* Three rows asserted; one row retracted via Tier-1 retract_batch first;
   * retract-by-batch on the original trigger should retract only the
   * remaining 2 valid rows (row_count=2). */
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  RetractByIdFixture fix = { 0 };
  if (retract_by_id_fixture_init (&fix, columns, 2) != 0)
    return 1900;
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 1},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-2"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 2},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-3"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 3},
  };
  const wyl_fact_row_t rows[] = {
    {values, 2},
    {values + 2, 2},
    {values + 4, 2},
  };
  if (retract_by_id_seed_assert (fix.store, &fix.schema, "trig",
          "seed:1", rows, 3) != 0) {
    retract_by_id_fixture_clear (&fix);
    return 1901;
  }
  /* Tier-1 retract row o-2 only (separate batch). */
  const wyl_fact_row_t partial_rows[] = {
    {values + 2, 2},
  };
  wyl_fact_store_batch_t partial = {
    .batch_id = "partial",
    .tenant_id = fix.schema.tenant_id,
    .graph_id = fix.schema.graph_id,
    .namespace_id = fix.schema.namespace_id,
    .relation_name = fix.schema.relation_name,
    .schema_version = fix.schema.schema_version,
    .source = "unit-test",
    .idempotency_key = "partial:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = partial_rows,
    .n_rows = 1,
  };
  if (wyl_fact_store_retract_batch (fix.store, &fix.schema, &partial, NULL)
      != WYRELOG_E_OK) {
    retract_by_id_fixture_clear (&fix);
    return 1902;
  }
  /* Retract-by-batch on trigger: the trigger batch has 3 rows with
   * __wyl_batch_id='trig' and __wyl_valid=TRUE (tombstoning is append-only,
   * the Tier-1 partial retract of o-2 created a separate tombstone row under
   * batch "partial" and did NOT flip the original trigger row). So
   * retract-by-id selects all 3 trigger rows and inserts 3 tombstone rows
   * under new-1 with __wyl_valid=FALSE. row_count=3. */
  gboolean inserted = FALSE;
  gint64 row_count = -1;
  if (wyl_fact_store_retract_by_batch_id (fix.store, &fix.schema, "trig",
          "new-1", "src", "req", "idem-1", &inserted, &row_count)
      != WYRELOG_E_OK || !inserted || row_count != 3) {
    retract_by_id_fixture_clear (&fix);
    return 1903;
  }
  duckdb_connection conn = wyl_fact_store_get_connection (fix.store);
  gint64 count = 0;
  /* 3 tombstone rows for new-1 must exist with __wyl_valid=FALSE. */
  g_autofree gchar *tombstone_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s WHERE __wyl_valid = FALSE "
      "AND __wyl_batch_id = 'new-1';", fix.table);
  if (!count_i64 (conn, tombstone_sql, &count) || count != 3) {
    retract_by_id_fixture_clear (&fix);
    return 1904;
  }
  retract_by_id_fixture_clear (&fix);
  return 0;
}

static gint
check_fact_store_retract_by_batch_id (void)
{
  gint rc = check_retract_by_id_normal_three_rows ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_idempotent_replay ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_second_retract_same_trigger ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_not_found ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_trigger_is_retract_batch ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_scope_mismatch ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_exceeds_max_rows ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_schema_version_mismatch ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_invalid_args ();
  if (rc != 0)
    return rc;
  rc = check_retract_by_id_partial_already_retracted ();
  if (rc != 0)
    return rc;
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

/* Tier-3 wyl_fact_store_forget: 2 cases. */

static gint
check_fact_forget_basic (void)
{
  /* Assert a batch, forget it, verify rows=0 remain in projection and
   * fact_batches, and that fact_forget_audit has one record. */
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 2000;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 2001;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
      G_N_ELEMENTS (columns));
  g_autofree gchar *table = NULL;
  if (wyl_fact_store_ensure_projection (store, &schema, &table)
      != WYRELOG_E_OK)
    return 2002;

  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 42},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-2"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 99},
  };
  const wyl_fact_row_t rows[] = {
    {values, 2},
    {values + 2, 2},
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "forget-me",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .idempotency_key = "forget:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean inserted = FALSE;
  if (wyl_fact_store_append_batch (store, &schema, &batch, &inserted)
      != WYRELOG_E_OK || !inserted)
    return 2003;

  const wyl_fact_store_forget_options_t opts = {
    .batch_id = "forget-me",
    .operator_id = "admin",
    .reason = "gdpr-erasure",
  };
  gsize rows_purged = 0;
  if (wyl_fact_store_forget (store, &schema, &opts, &rows_purged)
      != WYRELOG_E_OK || rows_purged != 2)
    return 2004;

  duckdb_connection conn = wyl_fact_store_get_connection (store);
  gint64 count = 0;
  g_autofree gchar *proj_sql = g_strdup_printf
      ("SELECT COUNT(*) FROM %s;", table);
  if (!count_i64 (conn, proj_sql, &count) || count != 0)
    return 2005;
  if (!count_i64 (conn,
          "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'forget-me';",
          &count) || count != 0)
    return 2006;
  if (!count_i64 (conn,
          "SELECT COUNT(*) FROM fact_forget_audit;", &count) || count != 1)
    return 2007;
  return 0;
}

static gint
check_fact_forget_not_found (void)
{
  /* Forget on a missing batch_id must return WYRELOG_E_NOT_FOUND. */
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 2100;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 2101;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
      G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (store, &schema, NULL) != WYRELOG_E_OK)
    return 2102;

  const wyl_fact_store_forget_options_t opts = {
    .batch_id = "does-not-exist",
    .operator_id = "admin",
    .reason = "test",
  };
  if (wyl_fact_store_forget (store, &schema, &opts, NULL)
      != WYRELOG_E_NOT_FOUND)
    return 2103;
  return 0;
}

static gint
check_fact_store_forget (void)
{
  gint rc = check_fact_forget_basic ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_not_found ();
  if (rc != 0)
    return rc;
  return 0;
}

static gint
check_fact_forget_audit_table_exists (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 20;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 21;
  gint64 count = -1;
  if (!count_i64 (wyl_fact_store_get_connection (store),
          "SELECT COUNT(*) FROM information_schema.tables "
          "WHERE table_name = 'fact_forget_audit';", &count))
    return 22;
  if (count != 1)
    return 23;
  return 0;
}

int
main (void)
{
  gint rc = check_fact_forget_audit_table_exists ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_forget ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_retract_by_batch_id ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_appends_idempotently ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_retracts_idempotently ();
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

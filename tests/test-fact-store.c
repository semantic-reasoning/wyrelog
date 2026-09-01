/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/fact/legacy-store-identity-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/store-test-seams-private.h"
#include "wyrelog/policy/store-private.h"

static gboolean
exec_ok (wyl_fact_store_t *store, const gchar *sql)
{
  return wyl_fact_store_test_exec_sql (store, sql) == WYRELOG_E_OK;
}

static gboolean
count_i64 (wyl_fact_store_t *store, const gchar *sql, gint64 *out_value)
{
  return wyl_fact_store_test_query_int64 (store, sql, out_value)
         == WYRELOG_E_OK;
}

static gboolean
query_text (wyl_fact_store_t *store, const gchar *sql, gchar **out_value)
{
  /* Own the slot: callers reuse a single g_autofree local across queries, and
   * an unconditional overwrite here would leak the previous value. */
  g_clear_pointer (out_value, g_free);
  return wyl_fact_store_test_query_text (store, sql, out_value)
         == WYRELOG_E_OK;
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

/* A sink for reconcile calls whose counts are not the subject of the test.
 * Tests that assert on counts declare their own local instead. */
static wyl_fact_forget_outcome_t forget_outcome_discard;

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

/*
 * Failure-code allocation.  main() hands these to the shell as the exit
 * status, so two functions sharing one are indistinguishable in a failing
 * run.  tests/test-fact-store-failure-codes.py enforces uniqueness; this
 * table is here so the next author can pick a free range without reading
 * the whole file.  Ranges are inclusive of what is used, not reserved.
 *
 *   100-130      check_fact_store_retracts_idempotently
 *   131-201      check_fact_store_appends_idempotently
 *   800-806      check_fact_store_thread_budget
 *   900-909      check_fact_store_reports_commit_delta
 *   960-973      check_fact_store_batch_commit_fault
 *   1010-1050    check_retract_by_id_normal_three_rows
 *   1100-1103    check_retract_by_id_idempotent_replay
 *   1200-1204    check_retract_by_id_second_retract_same_trigger
 *   1300-1301    check_retract_by_id_not_found
 *   1400-1403    check_retract_by_id_trigger_is_retract_batch
 *   1500-1503    check_retract_by_id_scope_mismatch
 *   1600         check_retract_by_id_exceeds_max_rows
 *   1700-1702    check_retract_by_id_schema_version_mismatch
 *   1800-1808    check_retract_by_id_invalid_args
 *   1900-1904    check_retract_by_id_partial_already_retracted
 *   2000-2007    check_fact_forget_basic
 *   2100-2103    check_fact_forget_not_found
 *   2200-2214    check_fact_forget_crash_convergence
 *   2230-2240    check_fact_forget_rejects_identifier_reuse
 *   2250-2260    check_fact_forget_reconcile_refuses_wrong_scope
 *   2270-2276    check_fact_forget_reconcile_skips_out_of_scope_intent
 *   2290-2294    check_fact_forget_reconcile_ignores_schema_only_store
 *   2300-2313    check_fact_store_identity_rejects_foreign_catalogs
 *   2320-2332    check_fact_forget_pending_count_refuses_wrong_scope
 *   2340-2360    check_fact_forget_read_only_open_replays_the_wal
 *   2400-2404    check_fact_forget_reconcile_counts_executed
 *   2410-2414    check_fact_forget_reconcile_counts_refused_without_abandoning
 *   2420-2423    check_fact_forget_reconcile_counts_a_store_scope_refusal
 *   2430-2437    check_fact_forget_reconcile_zeroes_outcome_on_invalid
 *   2440-2448    check_fact_forget_reconcile_failure_rc_survives_a_refusal
 *   2450-2457    check_fact_forget_reconcile_survey_io_failure_keeps_its_rc
 *   2460-2465    check_fact_forget_reconcile_abandoned_outranks_refused
 *   2470-2477
 *       check_fact_forget_reconcile_loop_scope_failure_is_not_a_refusal
 *   2500-2504    check_fact_store_identity_concurrency
 *   2600-2604    check_fact_store_identity_validation_snapshot
 *   2700-2723    check_fact_store_identity_basic
 *   2800-2806    check_fact_forget_pending_count_reports_without_executing
 *   2810-2815    check_fact_forget_pending_count_ignores_schema_only_store
 *   3000-3014    check_legacy_identity_binding_is_atomic_and_recoverable
 */
static gint
check_legacy_identity_binding_is_atomic_and_recoverable (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));

  /* An execute-time conflict in the second VALUES row rolls back the first
   * row too.  Close/reopen then proves a normal retry binds both rows. */
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-legacy-bind-XXXXXX", &error);
  if (dir == NULL)
    return 3000;
  g_autofree gchar *path = g_build_filename (dir, "facts.duckdb", NULL);
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (path, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
      return 3001;
    wyl_fact_legacy_identity_set_test_fault
      (WYL_FACT_LEGACY_IDENTITY_TEST_FAULT_STORE_SECOND_ROW);
    if (wyl_fact_store_ensure_projection (store, &schema, NULL)
        != WYRELOG_E_IO)
      return 3002;
    gint64 count = -1;
    if (!count_i64 (store,
        "SELECT COUNT(*) FROM fact_store_metadata "
        "WHERE key IN ('tenant_id','graph_id');", &count) || count != 0)
      return 3003;
  }
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (path, &store) != WYRELOG_E_OK
        || wyl_fact_store_ensure_projection (store, &schema, NULL)
        != WYRELOG_E_OK)
      return 3004;
    gint64 count = -1;
    if (!count_i64 (store,
        "SELECT COUNT(*) FROM fact_store_metadata "
        "WHERE (key='tenant_id' AND value='tenant-a') "
        "OR (key='graph_id' AND value='orders');", &count) || count != 2)
      return 3005;
  }
  (void) g_remove (path);
  (void) g_rmdir (dir);

  /* A matching tenant-only wedge repairs only graph_id.  Successful repair
   * also proves the existing tenant primary key was not reinserted. */
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK
        || !exec_ok (store,
        "INSERT INTO fact_store_metadata VALUES ('tenant_id','tenant-a');")
        || wyl_fact_store_ensure_projection (store, &schema, NULL)
        != WYRELOG_E_OK)
      return 3006;
    gint64 count = -1;
    if (!count_i64 (store,
        "SELECT COUNT(*) FROM fact_store_metadata "
        "WHERE (key='tenant_id' AND value='tenant-a') "
        "OR (key='graph_id' AND value='orders');", &count) || count != 2)
      return 3007;
  }

  /* Reader-only access never repairs a partial identity. */
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    gboolean exists = TRUE;
    if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK
        || !exec_ok (store,
        "INSERT INTO fact_store_metadata VALUES ('tenant_id','tenant-a');")
        || wyl_fact_store_validate_projection (store, &schema, &exists)
        != WYRELOG_E_INTERNAL || exists)
      return 3008;
    gint64 count = -1;
    if (!count_i64 (store,
        "SELECT COUNT(*) FROM fact_store_metadata WHERE key='graph_id';",
        &count) || count != 0)
      return 3009;
  }

  /* A tenant mismatch is a malformed partial record, not a normal complete
   * identity conflict, and is left untouched. */
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK
        || !exec_ok (store,
        "INSERT INTO fact_store_metadata VALUES ('tenant_id','tenant-b');")
        || wyl_fact_store_ensure_projection (store, &schema, NULL)
        != WYRELOG_E_INTERNAL)
      return 3010;
  }

  /* Durable fact rows make a tenant-only identity unsafe to repair.  The
   * NOT EXISTS guard and graph_id insert execute as one statement. */
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK
        || !exec_ok (store,
        "INSERT INTO fact_store_metadata VALUES ('tenant_id','tenant-a');"
        "INSERT INTO fact_batches VALUES ('existing','tenant-a','orders',"
        "'shop','order',1,NULL,NULL,'existing:1','assert',0,'hash',1);")
        || wyl_fact_store_ensure_projection (store, &schema, NULL)
        != WYRELOG_E_INTERNAL)
      return 3011;
    gint64 count = -1;
    if (!count_i64 (store,
        "SELECT COUNT(*) FROM fact_store_metadata WHERE key='graph_id';",
        &count) || count != 0)
      return 3012;
  }

  /* The unreachable reverse XOR is never repaired. */
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK
        || !exec_ok (store,
        "INSERT INTO fact_store_metadata VALUES ('graph_id','orders');")
        || wyl_fact_store_ensure_projection (store, &schema, NULL)
        != WYRELOG_E_INTERNAL)
      return 3013;
  }

  /* A complete foreign tuple remains the ordinary policy mismatch. */
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK
        || !exec_ok (store,
        "INSERT INTO fact_store_metadata VALUES "
        "('tenant_id','tenant-a'),('graph_id','other');")
        || wyl_fact_store_ensure_projection (store, &schema, NULL)
        != WYRELOG_E_POLICY)
      return 3014;
  }
  return 0;
}

static gint
check_fact_store_thread_budget (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-store-threads-XXXXXX",
          &error);
  if (dir == NULL)
    return 800;
  g_autofree gchar *path = g_build_filename (dir, "fact.db", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (path, &store) != WYRELOG_E_OK)
    return 801;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 802;

  wyl_fact_store_t *conn = store;
  g_autofree gchar *threads = NULL;
  if (!query_text (conn,
      "SELECT value FROM duckdb_settings() WHERE name = 'threads';",
      &threads) || g_strcmp0 (threads, "1") != 0)
    return 803;

  g_autoptr (wyl_fact_store_t) memory_store = NULL;
  if (wyl_fact_store_open (NULL, &memory_store) != WYRELOG_E_OK)
    return 804;
  if (wyl_fact_store_create_schema (memory_store) != WYRELOG_E_OK)
    return 805;
  if (!query_text (memory_store,
      "SELECT value FROM duckdb_settings() WHERE name = 'threads';",
      &threads) || g_strcmp0 (threads, "1") != 0)
    return 806;
  return 0;
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

  wyl_fact_store_t *conn = store;
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
    return 2532;

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

  wyl_fact_store_t *conn = store;
  gint64 count = 0;
  /* Retraction is append-only: preserve the original valid assert row and
   * append an invalid tombstone. Replay applies both events in sequence to
   * derive the effective state; the projection table itself retains both. */
  g_autofree gchar *order_a_valid_sql = g_strdup_printf
        ("SELECT COUNT(*) FROM %s WHERE order_id = 'order-a' "
          "AND __wyl_valid = TRUE;", table);
  if (!count_i64 (conn, order_a_valid_sql, &count) || count != 1)
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

  wyl_fact_store_t *conn = fix.store;
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
  wyl_fact_store_t *conn = fix.store;
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
  wyl_fact_store_t *conn = fix.store;
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
  if (!exec_ok (store, sql)) {
    return base_code + 2;
  }
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
check_fact_store_projection_validation (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
      || wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 70;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (store, &schema, NULL)
      != WYRELOG_E_OK)
    return 71;
  g_autofree gchar *initial_table =
      wyl_fact_store_projection_table_name (&schema);
  g_autofree gchar *drop_sql = g_strdup_printf ("DROP TABLE %s;",
          initial_table);
  if (!exec_ok (store, drop_sql)) {
    return 72;
  }
  gboolean exists = TRUE;
  if (wyl_fact_store_validate_projection (store, &schema, &exists)
      != WYRELOG_E_OK || exists)
    return 73;
  if (wyl_fact_store_ensure_projection (store, &schema, NULL)
      != WYRELOG_E_OK
      || wyl_fact_store_validate_projection (store, &schema, &exists)
      != WYRELOG_E_OK || !exists)
    return 74;
  if (wyl_fact_store_ensure_projection (store, &schema, NULL)
      != WYRELOG_E_OK)
    return 75;

  wyl_policy_fact_relation_schema_options_t malformed = schema;
  malformed.schema_version = 2;
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&malformed);
  g_autofree gchar *sql = g_strdup_printf
        ("CREATE TABLE %s (order_id VARCHAR NOT NULL, amount VARCHAR NOT NULL, "
          "__wyl_tenant_id VARCHAR NOT NULL, __wyl_graph_id VARCHAR NOT NULL, "
          "__wyl_seq BIGINT NOT NULL, __wyl_batch_id VARCHAR NOT NULL, "
          "__wyl_row_index BIGINT NOT NULL, __wyl_valid BOOLEAN NOT NULL, "
          "UNIQUE (__wyl_batch_id, __wyl_row_index));", table);
  if (!exec_ok (store, sql)) {
    return 76;
  }
  if (wyl_fact_store_validate_projection (store, &malformed, &exists)
      != WYRELOG_E_POLICY || !exists)
    return 77;
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
  if (!exec_ok (live_store,
      "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);")) {
    return 90;
  }
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

  wyl_fact_store_t *conn = store;
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
  if (!count_i64 (store,
      "SELECT COUNT(*) FROM information_schema.tables "
      "WHERE table_name = 'fact_forget_audit';", &count))
    return 22;
  if (count != 1)
    return 23;
  return 0;
}

/* Fault seam: abort the forget protocol at one named durable boundary so a
 * subsequent reconcile has to prove convergence from that exact crash point. */
static wyrelog_error_t
forget_fault_checkpoint (const gchar *point, gpointer user_data)
{
  const gchar *fail_at = user_data;
  if (fail_at != NULL && g_strcmp0 (point, fail_at) == 0)
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

static gint
forget_append_sample (wyl_fact_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const gchar *batch_id, const gchar *idem, const gchar *sym, gint64 amount)
{
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = sym},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = amount},
  };
  const wyl_fact_row_t rows[] = {
    {values, 2},
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = batch_id,
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .idempotency_key = idem,
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean inserted = FALSE;
  if (wyl_fact_store_append_batch (store, schema, &batch, &inserted)
      != WYRELOG_E_OK || !inserted)
    return -1;
  return 0;
}

/* A crash at each destructive seam converges, via reconcile, to exactly one
 * fully-forgotten result (data rows gone, one audit row, intent COMPLETED)
 * and a second reconcile is a no-op (no duplicate audit). */
static gint
check_fact_forget_crash_convergence (void)
{
  const gchar *seams[] = {
    "after_intent", "before_delete_projection", "before_delete_events",
    "before_delete_batch", "before_completion",
  };
  for (guint s = 0; s < G_N_ELEMENTS (seams); s++) {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
      return 2200;
    if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
      return 2201;
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
            G_N_ELEMENTS (columns));
    g_autofree gchar *table = NULL;
    if (wyl_fact_store_ensure_projection (store, &schema, &table)
        != WYRELOG_E_OK)
      return 2202;
    if (forget_append_sample (store, &schema, "crash-me", "crash:1", "o-1", 42)
        != 0)
      return 2203;

    wyl_fact_store_forget_options_t opts = {
      .batch_id = "crash-me",
      .operator_id = "admin",
      .reason = "gdpr-erasure",
      .checkpoint = forget_fault_checkpoint,
      .checkpoint_data = (gpointer) seams[s],
    };
    if (wyl_fact_store_forget (store, &schema, &opts, NULL) == WYRELOG_E_OK)
      return 2204;

    wyl_fact_store_t *conn = store;
    gint64 count = 0;
    if (!count_i64 (conn,
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
        &count) || count != 1)
      return 2205;

    if (wyl_fact_store_forget_reconcile (store, "tenant-a",
        "orders", NULL, NULL, &forget_outcome_discard) != WYRELOG_E_OK)
      return 2206;

    g_autofree gchar *proj_sql = g_strdup_printf
          ("SELECT COUNT(*) FROM %s;", table);
    if (!count_i64 (conn, proj_sql, &count) || count != 0)
      return 2207;
    if (!count_i64 (conn,
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'crash-me';",
        &count) || count != 0)
      return 2208;
    if (!count_i64 (conn,
        "SELECT COUNT(*) FROM fact_event_log WHERE batch_id = 'crash-me';",
        &count) || count != 0)
      return 2209;
    if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_audit;", &count)
        || count != 1)
      return 2210;
    if (!count_i64 (conn,
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'COMPLETED';",
        &count) || count != 1)
      return 2211;
    if (!count_i64 (conn,
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
        &count) || count != 0)
      return 2212;

    if (wyl_fact_store_forget_reconcile (store, "tenant-a",
        "orders", NULL, NULL, &forget_outcome_discard) != WYRELOG_E_OK)
      return 2213;
    if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_audit;", &count)
        || count != 1)
      return 2214;
  }
  return 0;
}

/* A stale intent whose identifier was reused by a NEW batch must converge by
 * recording completion WITHOUT deleting the new batch (AC-2). */
static gint
check_fact_forget_rejects_identifier_reuse (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 2230;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 2231;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));
  g_autofree gchar *table = NULL;
  if (wyl_fact_store_ensure_projection (store, &schema, &table)
      != WYRELOG_E_OK)
    return 2232;

  if (forget_append_sample (store, &schema, "dup-id", "orig:1", "o-1", 42)
      != 0)
    return 2233;
  wyl_fact_store_forget_options_t opts = {
    .batch_id = "dup-id",
    .operator_id = "admin",
    .reason = "gdpr-erasure",
    .checkpoint = forget_fault_checkpoint,
    .checkpoint_data = (gpointer) "before_completion",
  };
  if (wyl_fact_store_forget (store, &schema, &opts, NULL) == WYRELOG_E_OK)
    return 2234;

  wyl_fact_store_t *conn = store;
  gint64 count = 0;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'dup-id';", &count)
      || count != 0)
    return 2235;

  if (forget_append_sample (store, &schema, "dup-id", "reuse:2", "o-2", 99)
      != 0)
    return 2236;

  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
      NULL, &forget_outcome_discard) != WYRELOG_E_OK)
    return 2237;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'dup-id';", &count)
      || count != 1)
    return 2238;
  g_autofree gchar *proj_sql = g_strdup_printf
        ("SELECT COUNT(*) FROM %s WHERE __wyl_batch_id = 'dup-id';", table);
  if (!count_i64 (conn, proj_sql, &count) || count != 1)
    return 2239;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
      &count) || count != 0)
    return 2240;
  return 0;
}

/* Issue #547: seed one store with an interrupted forget whose intent is
 * durable but whose deletes have not run, so a reconcile that executes and a
 * reconcile that skips are distinguishable by the surviving rows. */
static gint
forget_seed_pending_intent (wyl_fact_store_t **out_store,
    wyl_policy_fact_relation_schema_options_t *out_schema, gchar **out_table)
{
  /* Static because out_schema keeps borrowed pointers into it. */
  static const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  *out_store = NULL;
  *out_table = NULL;
  if (wyl_fact_store_open (NULL, out_store) != WYRELOG_E_OK)
    return -1;
  if (wyl_fact_store_create_schema (*out_store) != WYRELOG_E_OK)
    return -2;
  *out_schema = make_schema (columns, G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (*out_store, out_schema, out_table)
      != WYRELOG_E_OK)
    return -3;
  if (forget_append_sample (*out_store, out_schema, "crash-me", "crash:1",
      "o-1", 42) != 0)
    return -4;
  /* after_intent: the intent is committed, no delete has run yet. */
  wyl_fact_store_forget_options_t opts = {
    .batch_id = "crash-me",
    .operator_id = "admin",
    .reason = "gdpr-erasure",
    .checkpoint = forget_fault_checkpoint,
    .checkpoint_data = (gpointer) "after_intent",
  };
  if (wyl_fact_store_forget (*out_store, out_schema, &opts, NULL)
      == WYRELOG_E_OK)
    return -5;
  return 0;
}

/* Reconciling with a scope this store does not serve must refuse and change
 * nothing.  Asserted on both sides deliberately: a guard exercised only where
 * it accepts is indistinguishable from no guard, so the same store is
 * reconciled again with the scope it really serves and must then converge. */
static gint
check_fact_forget_reconcile_refuses_wrong_scope (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_pending_intent (&store, &schema, &table) != 0)
    return 2250;
  wyl_fact_store_t *conn = store;
  gint64 count = 0;

  if (wyl_fact_store_forget_reconcile (store, "tenant-z", "orders", NULL,
      NULL, &forget_outcome_discard) != WYRELOG_E_POLICY)
    return 2251;
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "shipments", NULL,
      NULL, &forget_outcome_discard) != WYRELOG_E_POLICY)
    return 2252;
  /* An absent expectation is a caller error, not permission to skip the
   * check: the scope arguments cannot be opted out of. */
  if (wyl_fact_store_forget_reconcile (store, NULL, "orders", NULL, NULL,
      &forget_outcome_discard) != WYRELOG_E_INVALID)
    return 2253;
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", NULL, NULL, NULL,
      &forget_outcome_discard) != WYRELOG_E_INVALID)
    return 2254;

  g_autofree gchar *proj_sql = g_strdup_printf
        ("SELECT COUNT(*) FROM %s;", table);
  if (!count_i64 (conn, proj_sql, &count) || count != 1)
    return 2255;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
      &count) || count != 1)
    return 2256;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_audit;", &count)
      || count != 0)
    return 2257;

  /* The refusals above were caused by the scope, not by anything else about
   * this store: with the right scope the very same call converges. */
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
      NULL, &forget_outcome_discard) != WYRELOG_E_OK)
    return 2258;
  if (!count_i64 (conn, proj_sql, &count) || count != 0)
    return 2259;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_audit;", &count)
      || count != 1)
    return 2260;
  return 0;
}

/* A store whose schema was materialized but never appended to has a forget
 * ledger -- wyl_fact_store_create_schema creates fact_forget_intent -- and no
 * bound identity, because tenant/graph metadata is written lazily on first
 * projection.  Nothing is pending, so there is nothing to converge and nothing
 * to delete through.  Reconcile must report that as success: refusing it would
 * emit a boot ERROR claiming an erasure is incomplete for a graph that has
 * never held a fact. */
static gint
check_fact_forget_reconcile_ignores_schema_only_store (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 2290;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 2291;

  wyl_fact_store_t *conn = store;
  gint64 count = 0;
  /* The ledger really does exist and really is empty, so the case under test
   * is reached past the ledger check rather than short-circuited by it. */
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_intent;", &count)
      || count != 0)
    return 2292;
  /* And the identity really is unbound, which is what the scope check would
   * otherwise refuse. */
  g_autofree gchar *bound = NULL;
  /* query_text reports a missing row as FALSE with a NULL value, which is
   * exactly the unbound state. */
  if (query_text (conn,
      "SELECT value FROM fact_store_metadata WHERE key = 'tenant_id';",
      &bound) || bound != NULL)
    return 2293;

  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
      NULL, &forget_outcome_discard) != WYRELOG_E_OK)
    return 2294;
  return 0;
}

/* An intent naming a scope this store does not serve is corruption, and the
 * store-level check cannot catch it: the identity of the store is correct and
 * only the intent is wrong.  The reconciler must skip that intent rather than
 * delete through it, and must report so the caller degrades. */
static gint
check_fact_forget_reconcile_skips_out_of_scope_intent (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_pending_intent (&store, &schema, &table) != 0)
    return 2270;
  wyl_fact_store_t *conn = store;

  if (!exec_ok (conn,
      "UPDATE fact_forget_intent SET tenant_id = 'tenant-z' "
      "WHERE state = 'PENDING';"))
    return 2271;

  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
      NULL, &forget_outcome_discard) != WYRELOG_E_POLICY)
    return 2272;

  gint64 count = 0;
  g_autofree gchar *proj_sql = g_strdup_printf
        ("SELECT COUNT(*) FROM %s;", table);
  if (!count_i64 (conn, proj_sql, &count) || count != 1)
    return 2273;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'crash-me';",
      &count) || count != 1)
    return 2274;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_audit;", &count)
      || count != 0)
    return 2275;
  /* Skipping is not completing: the intent must not be recorded as done.  It
   * is now QUARANTINED rather than PENDING -- retired, because the refusal is
   * an identity mismatch that cannot become a match later -- and the point of
   * this assertion is unchanged: it is not COMPLETED, so the erasure is not
   * claimed to have happened. */
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'COMPLETED';",
      &count) || count != 0)
    return 2276;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'QUARANTINED';",
      &count) || count != 1)
    return 2277;
  return 0;
}

/* The boot probe asks whether anything is pending WITHOUT taking a write
 * lease, so it must answer the question and change nothing.  A probe that
 * answered by calling the reconciler would pass a bare count assertion and
 * fail these: the intent would be gone and an audit row would exist. */
static gint
check_fact_forget_pending_count_reports_without_executing (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_pending_intent (&store, &schema, &table) != 0)
    return 2800;
  wyl_fact_store_t *conn = store;

  gsize pending = 0;
  if (wyl_fact_store_forget_pending_count (store, "tenant-a", "orders",
      &pending) != WYRELOG_E_OK)
    return 2801;
  if (pending != 1)
    return 2802;

  gint64 count = 0;
  /* Still pending: the survey did not converge it. */
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
      &count) || count != 1)
    return 2803;
  /* And nothing was deleted through. */
  g_autofree gchar *proj_sql = g_strdup_printf
        ("SELECT COUNT(*) FROM %s;", table);
  if (!count_i64 (conn, proj_sql, &count) || count != 1)
    return 2804;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_audit;", &count)
      || count != 0)
    return 2805;

  /* Asking twice is the boot-over-boot case and must be stable. */
  pending = 0;
  if (wyl_fact_store_forget_pending_count (store, "tenant-a", "orders",
      &pending) != WYRELOG_E_OK || pending != 1)
    return 2806;
  return 0;
}

/* The counterpart of check_fact_forget_reconcile_ignores_schema_only_store:
 * a store whose schema was materialized but never appended to has a ledger and
 * no bound identity.  The survey must report zero rather than refuse, or boot
 * would escalate to a write lease and then report a failed erasure for a graph
 * that has never held a fact. */
static gint
check_fact_forget_pending_count_ignores_schema_only_store (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 2810;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 2811;

  wyl_fact_store_t *conn = store;
  gint64 count = 0;
  /* The ledger exists and is empty, so the case is reached past the ledger
   * check rather than short-circuited by it. */
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_intent;", &count)
      || count != 0)
    return 2812;
  /* And the identity really is unbound, which is what a scope check placed
   * before the count would refuse. */
  g_autofree gchar *bound = NULL;
  if (query_text (conn,
      "SELECT value FROM fact_store_metadata WHERE key = 'tenant_id';",
      &bound) || bound != NULL)
    return 2813;

  gsize pending = 1;
  if (wyl_fact_store_forget_pending_count (store, "tenant-a", "orders",
      &pending) != WYRELOG_E_OK)
    return 2814;
  if (pending != 0)
    return 2815;
  return 0;
}

/* A store that is not the one the caller meant to open must be refused by the
 * survey, so boot never escalates to a write lease it would then refuse.
 * Before #869 U1 such a store took that lease on every boot and did
 * nothing with it. */
static gint
check_fact_forget_pending_count_refuses_wrong_scope (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_pending_intent (&store, &schema, &table) != 0)
    return 2320;

  gsize pending = 99;
  if (wyl_fact_store_forget_pending_count (store, "tenant-z", "orders",
      &pending) != WYRELOG_E_POLICY)
    return 2321;
  /* The header promises the count is zeroed on every non-OK outcome, so a
   * caller that ignores the return value cannot read a stale 99 as
   * convergence work.  The seed above is that stale value. */
  if (pending != 0)
    return 2329;
  pending = 99;
  if (wyl_fact_store_forget_pending_count (store, "tenant-a", "shipments",
      &pending) != WYRELOG_E_POLICY)
    return 2322;
  if (pending != 0)
    return 2330;

  /* Refusing is not converging: nothing may have been written. */
  wyl_fact_store_t *conn = store;
  gint64 count = 0;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
      &count) || count != 1)
    return 2323;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_audit;", &count)
      || count != 0)
    return 2324;

  /* The header's zeroing promise covers the INVALID paths too, and a caller
   * that passes a bad argument is the likeliest to ignore the return value.
   * Seed a stale count before each so a missing zero is visible. */
  pending = 99;
  if (wyl_fact_store_forget_pending_count (NULL, "tenant-a", "orders",
      &pending) != WYRELOG_E_INVALID)
    return 2325;
  if (pending != 0)
    return 2331;
  pending = 99;
  if (wyl_fact_store_forget_pending_count (store, NULL, "orders", &pending)
      != WYRELOG_E_INVALID)
    return 2326;
  if (pending != 0)
    return 2332;
  if (wyl_fact_store_forget_pending_count (store, "tenant-a", NULL, &pending)
      != WYRELOG_E_INVALID)
    return 2327;
  if (wyl_fact_store_forget_pending_count (store, "tenant-a", "orders", NULL)
      != WYRELOG_E_INVALID)
    return 2328;
  return 0;
}

static const WylFactStoreIdentity test_identity = {
  .tenant_id = "tenant-a",
  .graph_id = "orders",
  .store_uuid = "01890f47-3c4b-6cc2-b8c4-dc0c0c073989",
  .format_version = 1,
  .path_encoding_version = 1,
};

#define TEST_IDENTITY_ROWS                                                \
  "INSERT INTO fact_store_metadata(key,value) VALUES"                     \
  "('store_kind','wyrelog.fact'),('format_version','1'),"                 \
  "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"               \
  "('path_encoding_version','1'),('tenant_id','tenant-a'),"               \
  "('graph_id','orders');"

static gboolean
identified_open_is (const gchar *path, const WylFactStoreIdentity *identity,
    WylFactStoreIdentityOpenMode mode, wyrelog_error_t expected_rc,
    WylFactStoreIdentityResult expected_result)
{
  wyl_fact_store_t *store = (wyl_fact_store_t *) 0x1;
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  wyrelog_error_t rc = wyl_fact_store_open_identified (path, identity, mode,
          &result, &store);
  gboolean valid = rc == expected_rc && result == expected_result
      && ((rc == WYRELOG_E_OK) == (store != NULL));
  wyl_fact_store_close (store);
  return valid;
}

/* Return the size of |path|, or -1 if it does not exist. */
static gint64
file_size_or_missing (const gchar *path)
{
  GStatBuf st;
  if (g_stat (path, &st) != 0)
    return -1;
  return (gint64) st.st_size;
}

static gboolean
exec_ok_sql (wyl_fact_store_t *store, const gchar *sql)
{
  return exec_ok (store, sql);
}

/* Seed |n| pending intents in one store, batch-N / o-N, all in scope.
 * Ordering does not need pinning: intents load ORDER BY created_at_us, and
 * measured single-INSERT latency through this API is ~326us, so successive
 * forgets cannot share a microsecond.  A fixture that seeded rows by direct
 * SQL with a literal created_at_us WOULD need pinning, via
 * UPDATE fact_forget_intent SET created_at_us = <n> WHERE op_uuid = '<..>'. */
static gint
forget_seed_n_pending_at (const gchar *path, wyl_fact_store_t **out_store,
    wyl_policy_fact_relation_schema_options_t *out_schema, gchar **out_table,
    guint n)
{
  static const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  *out_store = NULL;
  *out_table = NULL;
  if (wyl_fact_store_open (path, out_store) != WYRELOG_E_OK)
    return -1;
  if (wyl_fact_store_create_schema (*out_store) != WYRELOG_E_OK)
    return -2;
  *out_schema = make_schema (columns, G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (*out_store, out_schema, out_table)
      != WYRELOG_E_OK)
    return -3;
  for (guint i = 0; i < n; i++) {
    g_autofree gchar *batch = g_strdup_printf ("batch-%u", i);
    g_autofree gchar *idem = g_strdup_printf ("crash:%u", i);
    g_autofree gchar *sym = g_strdup_printf ("o-%u", i);
    if (forget_append_sample (*out_store, out_schema, batch, idem, sym,
        (gint64) (10 + i)) != 0)
      return -4;
    wyl_fact_store_forget_options_t opts = {
      .batch_id = batch,
      .operator_id = "admin",
      .reason = "gdpr-erasure",
      .checkpoint = forget_fault_checkpoint,
      .checkpoint_data = (gpointer) "after_intent",
    };
    if (wyl_fact_store_forget (*out_store, out_schema, &opts, NULL)
        == WYRELOG_E_OK)
      return -5;
  }
  return 0;
}

static gint
forget_seed_n_pending (wyl_fact_store_t **out_store,
    wyl_policy_fact_relation_schema_options_t *out_schema, gchar **out_table,
    guint n)
{
  return forget_seed_n_pending_at (NULL, out_store, out_schema, out_table, n);
}

/* Rewrite the state CHECK back to its pre-change text, so the migration runs
 * against a table this code produced rather than a hand-written imitation of
 * an old one.  The rebuild is spelled out here rather than reusing the
 * production helper: a fixture that shared the code under test could not
 * disagree with it. */
static gboolean
forget_narrow_intent_state_check (wyl_fact_store_t *store)
{
  return exec_ok_sql (store,
             "BEGIN TRANSACTION;"
             "CREATE TABLE fact_forget_intent_old ("
             "  op_uuid         VARCHAR PRIMARY KEY,"
             "  batch_id        VARCHAR NOT NULL,"
             "  tenant_id       VARCHAR NOT NULL,"
             "  graph_id        VARCHAR NOT NULL,"
             "  namespace_id    VARCHAR NOT NULL,"
             "  relation_name   VARCHAR NOT NULL,"
             "  schema_version  BIGINT NOT NULL,"
             "  projection_table VARCHAR NOT NULL,"
             "  content_hash    VARCHAR NOT NULL,"
             "  idempotency_key VARCHAR NOT NULL,"
             "  operator        VARCHAR NOT NULL,"
             "  reason          VARCHAR NOT NULL,"
             "  rows_purged     BIGINT NOT NULL,"
             "  state           VARCHAR NOT NULL "
             "    CHECK (state IN ('PENDING', 'COMPLETED')),"
             "  created_at_us   BIGINT NOT NULL,"
             "  completed_at_us BIGINT);"
             "INSERT INTO fact_forget_intent_old"
             "  SELECT * FROM fact_forget_intent;"
             "DROP TABLE fact_forget_intent;"
             "ALTER TABLE fact_forget_intent_old"
             "  RENAME TO fact_forget_intent;"
             "COMMIT;");
}

/* Rewrite one intent's tenant so the per-intent scope check refuses it.  The
 * STORE's identity is untouched, so the store-level guard still passes and
 * only this intent is out of scope. */
static gboolean
forget_mark_intent_foreign (wyl_fact_store_t *store, const gchar *batch_id)
{
  g_autofree gchar *sql = g_strdup_printf
        ("UPDATE fact_forget_intent SET tenant_id = 'tenant-z' "
          "WHERE batch_id = '%s';", batch_id);
  return exec_ok_sql (store, sql);
}

/* Fail the Nth execution that reaches |point|, so a multi-intent fixture can
 * fail one intent and leave the others alone. */
typedef struct
{
  const gchar *point;
  guint fail_on_nth;
  guint seen;
} ForgetNthFault;

static wyrelog_error_t
forget_fault_nth (const gchar *point, gpointer user_data)
{
  ForgetNthFault *fault = user_data;
  if (g_strcmp0 (point, fault->point) != 0)
    return WYRELOG_E_OK;
  fault->seen++;
  return fault->seen == fault->fail_on_nth ? WYRELOG_E_IO : WYRELOG_E_OK;
}

/* The hazard the sticky flag creates, and the reason the rc == OK term in
 * "if (rc == OK && out_of_scope) rc = POLICY" is load-bearing.
 *
 * Three intents: the first out of scope, the second fails, the third is
 * therefore never attempted, so a refusal is seen BEFORE a failure in the same
 * pass.  That ordering was reachable before the sticky flag too -- the old
 * loop also continued on refusal -- so this test pins a guard that was already
 * load-bearing rather than one the restructure created.  If that term were
 * dropped
 * for the tidier "if (refused) rc = POLICY", the caller would be told this
 * store has a scope problem when what it actually has is an I/O failure
 * mid-erasure, and the boot log would name the wrong remedy.
 *
 * No other test in this file has more than one pending intent, so nothing
 * else would catch that regression. */
static gint
check_fact_forget_reconcile_failure_rc_survives_a_refusal (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 3) != 0)
    return 2440;
  if (!forget_mark_intent_foreign (store, "batch-0"))
    return 2441;

  ForgetNthFault fault = {
    .point = "before_delete_projection",
    .fail_on_nth = 1,
  };
  wyl_fact_forget_outcome_t out = { 0 };
  wyrelog_error_t rc = wyl_fact_store_forget_reconcile (store, "tenant-a",
          "orders", forget_fault_nth, &fault, &out);

  /* The failure rc reaches the caller; POLICY must not have masked it. */
  if (rc == WYRELOG_E_POLICY)
    return 2442;
  if (rc != WYRELOG_E_IO)
    return 2443;
  /* And every intent is accounted for, one disposition each. */
  if (out.loaded != 3)
    return 2444;
  if (out.refused != 1)
    return 2445;
  if (out.failed != 1)
    return 2446;
  if (out.abandoned != 1)
    return 2447;
  if (out.executed != 0)
    return 2448;
  return 0;
}

/* A survey that fails for a reason OTHER than scope still comes back with the
 * intents materialized, because the loader fills the array before the scope
 * guard runs.  Those intents must reach a disposition, or the equality fires
 * and replaces the real rc with E_INTERNAL -- which reaches the boot log as
 * rc=-7, "wyrelog-side invariant violation", instead of rc=-3.  That is a
 * worse misdiagnosis than the POLICY flattening that propagating the real rc
 * was meant to prevent, and it is reachable on the production boot path:
 * wyl_fact_store_open leaves the identity unset, so validate_store_scope_
 * unlocked falls through to metadata_value_unlocked, whose prepare can fail.
 *
 * Renaming the metadata value column reproduces that: the table still exists,
 * so table_exists_unlocked passes, and the prepare then fails. */
static gint
check_fact_forget_reconcile_survey_io_failure_keeps_its_rc (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 2) != 0)
    return 2450;
  wyl_fact_store_t *conn = store;

  /* The control: two intents really are PENDING before the rename, so a zero
  * count below is the survey failing and not an empty fixture.  This is a
  * seeding check, not a convergence check -- no reconcile pass runs here. */
  gint64 pending_rows = 0;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
      &pending_rows) || pending_rows != 2)
    return 2451;

  if (!exec_ok_sql (conn,
      "ALTER TABLE fact_store_metadata RENAME COLUMN value TO value_x;"))
    return 2452;

  wyl_fact_forget_outcome_t out = { 0 };
  wyrelog_error_t rc = wyl_fact_store_forget_reconcile (store, "tenant-a",
          "orders", NULL, NULL, &out);

  /* E_INTERNAL here means the equality ate the real rc, which is the defect
   * this test exists for; assert the exact rc rather than merely "not OK". */
  if (rc == WYRELOG_E_INTERNAL)
    return 2453;
  if (rc != WYRELOG_E_IO)
    return 2454;
  /* And the intents the survey loaded are accounted for, so the equality
   * holds without needing to hide them. */
  if (out.loaded != 2)
    return 2455;
  if (out.abandoned != 2)
    return 2456;
  if (out.executed != 0 || out.refused != 0 || out.failed != 0)
    return 2457;
  return 0;
}

/* abandoned outranks refused: an intent that is BOTH out of scope and
 * reached after a failure counts as abandoned, because it was never
 * attempted.  Evaluating the scope check first would also re-enter the store
 * reads that may be what is failing.  Without this, moving the if (broke)
 * block below the scope check passes every other test in the file. */
static gint
check_fact_forget_reconcile_abandoned_outranks_refused (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 3) != 0)
    return 2460;
  /* Failure first, out-of-scope second: the reverse of
   * check_fact_forget_reconcile_failure_rc_survives_a_refusal. */
  if (!forget_mark_intent_foreign (store, "batch-1"))
    return 2461;

  ForgetNthFault fault = {
    .point = "before_delete_projection",
    .fail_on_nth = 1,
  };
  wyl_fact_forget_outcome_t out = { 0 };
  wyrelog_error_t rc = wyl_fact_store_forget_reconcile (store, "tenant-a",
          "orders", forget_fault_nth, &fault, &out);
  if (rc != WYRELOG_E_IO)
    return 2462;
  if (out.loaded != 3 || out.failed != 1)
    return 2463;
  /* The out-of-scope intent at index 1 is abandoned, not refused. */
  if (out.abandoned != 2)
    return 2464;
  if (out.refused != 0)
    return 2465;
  return 0;
}

/* Every loaded intent reaches exactly one disposition, and the counts say
 * which.  A healthy pass: one intent in, one executed. */
static gint
check_fact_forget_reconcile_counts_executed (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_pending_intent (&store, &schema, &table) != 0)
    return 2400;
  wyl_fact_forget_outcome_t out = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
      NULL, &out) != WYRELOG_E_OK)
    return 2401;
  if (out.loaded != 1 || out.executed != 1)
    return 2402;
  if (out.refused != 0 || out.failed != 0 || out.abandoned != 0)
    return 2403;
  if (out.quarantined != 0)
    return 2404;
  return 0;
}

/* Rename the metadata column the store-scope check reads, at the first
 * before_completion seam, so its ANSWER changes between the survey and a later
 * iteration.  Shaped like ForgetNthFault above; no new fault machinery.
 * |renamed| is the fixture's own control -- see the test. */
typedef struct
{
  wyl_fact_store_t *store;
  guint seen;
  gboolean renamed;
} ForgetRenameAtNth;

static wyrelog_error_t
forget_rename_metadata_at_first_completion (const gchar *point,
    gpointer user_data)
{
  ForgetRenameAtNth *fault = user_data;
  if (g_strcmp0 (point, "before_completion") != 0)
    return WYRELOG_E_OK;
  if (++fault->seen != 1)
    return WYRELOG_E_OK;
  fault->renamed =
      wyl_fact_store_test_rename_metadata_value_column_at_checkpoint
        (fault->store) == WYRELOG_E_OK;
  return WYRELOG_E_OK;
}

/* Quarantine is for permanent conditions only.  A transient failure -- an I/O
 * fault mid-erasure -- must stay PENDING and be retried, because the condition
 * that produced it can be gone by the next boot.  Retiring one would turn a
 * recoverable erasure into a permanent refusal, which is the failure mode the
 * quarantine path exists to avoid rather than to create. */
static gint
check_fact_forget_reconcile_does_not_quarantine_a_transient_failure (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 2) != 0)
    return 2490;

  ForgetNthFault fault = {"before_delete_projection", 1, 0};
  wyl_fact_forget_outcome_t first = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders",
      forget_fault_nth, &fault, &first) != WYRELOG_E_IO)
    return 2491;
  if (first.failed != 1)
    return 2492;

  wyl_fact_store_t *conn = store;
  gint64 count = 0;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'QUARANTINED';",
      &count))
    return 2493;
  if (count != 0)
    return 2494;

  /* And it converges: with the fault gone the intent is loaded again and
   * executes, which is what "retryable" has to mean to be worth anything. */
  wyl_fact_forget_outcome_t second = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL, NULL,
      &second) != WYRELOG_E_OK)
    return 2495;
  if (second.executed == 0)
    return 2496;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';",
      &count))
    return 2497;
  if (count != 0)
    return 2498;
  return 0;
}

/* The terminal state has to be durable, or the next boot loads the row again
 * and nothing was retired.  Same store on disk, closed and reopened. */
static gint
check_fact_forget_quarantine_survives_a_restart (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-quarantine-XXXXXX", &error);
  if (dir == NULL)
    return 2510;
  g_autofree gchar *path = g_build_filename (dir, "fact.db", NULL);

  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    wyl_policy_fact_relation_schema_options_t schema;
    g_autofree gchar *table = NULL;
    if (forget_seed_n_pending_at (path, &store, &schema, &table, 2) != 0)
      return 2511;
    if (!forget_mark_intent_foreign (store, "batch-0"))
      return 2512;
    wyl_fact_forget_outcome_t out = { 0 };
    if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
        NULL, &out) != WYRELOG_E_POLICY)
      return 2513;
    if (out.refused != 1)
      return 2514;
  }

  g_autoptr (wyl_fact_store_t) reopened = NULL;
  if (wyl_fact_store_open (path, &reopened) != WYRELOG_E_OK)
    return 2515;
  gint64 count = 0;
  if (!count_i64 (reopened,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'QUARANTINED';",
      &count))
    return 2516;
  if (count != 1)
    return 2517;

  /* The operator surface is the reconcile outcome itself, and after a restart
   * it reports the retired row as neither loaded nor refused. */
  wyl_fact_forget_outcome_t after = { 0 };
  if (wyl_fact_store_forget_reconcile (reopened, "tenant-a", "orders", NULL,
      NULL, &after) != WYRELOG_E_OK)
    return 2518;
  if (after.loaded != 0 || after.refused != 0)
    return 2519;
  return 0;
}

/* A store written before the state CHECK was widened has to open, migrate and
 * reconcile.  The fixture is a store created by the current code whose CHECK
 * is then rewritten to the pre-change text, so the migration is exercised
 * against a real table rather than a hand-written approximation of one. */
static gint
check_fact_forget_intent_state_check_migrates_an_old_store (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 2) != 0)
    return 2520;
  wyl_fact_store_t *conn = store;
  if (!forget_narrow_intent_state_check (conn))
    return 2521;
  /* Both foreign, so one pass quarantines twice: the first call migrates and
   * the second finds the widened constraint already in place.  Idempotence
   * matters here rather than across passes, because that is where a rebuild
   * that dropped the constraint would rebuild again and again. */
  if (!forget_mark_intent_foreign (conn, "batch-0"))
    return 2522;
  if (!forget_mark_intent_foreign (conn, "batch-1"))
    return 2523;

  gint64 before = 0;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_intent;", &before))
    return 2524;

  wyl_fact_forget_outcome_t out = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL, NULL,
      &out) != WYRELOG_E_POLICY)
    return 2525;
  if (out.loaded != 2 || out.refused != 2 || out.executed != 0)
    return 2526;

  /* Every row survived the rebuild. */
  gint64 after = 0;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_forget_intent;", &after))
    return 2527;
  if (after != before)
    return 2528;
  gint64 quarantined = 0;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'QUARANTINED';",
      &quarantined))
    return 2529;
  if (quarantined != 2)
    return 2530;

  /* The migrated table carries the widened constraint rather than none at
   * all: CREATE TABLE AS SELECT would have dropped both it and the primary
   * key, leaving a store that accepts any state string. */
  gint64 constrained = 0;
  if (!count_i64 (conn,
      "SELECT COUNT(*) FROM duckdb_constraints() "
      "WHERE table_name = 'fact_forget_intent' "
      "AND constraint_text LIKE '%QUARANTINED%';", &constrained))
    return 2531;
  if (constrained != 1)
    return 2536;
  if (exec_ok_sql (conn,
      "UPDATE fact_forget_intent SET state = 'NONSENSE' "
      "WHERE batch_id = 'batch-0';"))
    return 2533;

  /* And it reconciles: the next pass loads nothing. */
  wyl_fact_forget_outcome_t second = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL, NULL,
      &second) != WYRELOG_E_OK)
    return 2534;
  if (second.loaded != 0)
    return 2535;
  return 0;
}

/* Drive a real duckdb_prepare failure, so the destroy on that branch is
 * exercised rather than merely present.
 *
 * Issue #944 is explicit that a sweep with no forced failure is unverified by
 * construction: if nothing drives the branch, reverting the fix fails nothing.
 * Dropping the projection table under an existing batch makes
 * count_projection_rows_unlocked prepare against a missing relation, which is
 * a genuine binder error rather than an injected one -- so under ASan the leak
 * that appears when the destroy is removed is the product's, not the
 * fixture's.
 *
 * The forget path reads fact_batches before it touches the projection, so the
 * fingerprint lookup still succeeds and the failure lands where it is
 * wanted. */
static gint
check_fact_store_forget_survives_a_missing_projection (void)
{
  static const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 2025;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 2026;
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));
  g_autofree gchar *table = NULL;
  if (wyl_fact_store_ensure_projection (store, &schema, &table)
      != WYRELOG_E_OK)
    return 2027;
  if (forget_append_sample (store, &schema, "batch-missing", "idem-missing",
      "o-missing", 41) != 0)
    return 2028;

  g_autofree gchar *drop = g_strdup_printf ("DROP TABLE \"%s\";", table);
  if (!exec_ok_sql (store, drop))
    return 2029;

  /* The prepare fails, so the forget cannot proceed.  What matters here is
   * not the code -- it is that the branch ran at all, under a sanitizer. */
  wyl_fact_store_forget_options_t opts = {
    .batch_id = "batch-missing",
    .operator_id = "admin",
    .reason = "gdpr-erasure",
  };
  if (wyl_fact_store_forget (store, &schema, &opts, NULL) == WYRELOG_E_OK)
    return 2030;
  return 0;
}

/* An intent naming a tenant this store does not own can never converge: the
 * refusal is an identity mismatch, and identity does not change under a store
 * once bound.  Before quarantine such a row stayed PENDING forever -- loaded,
 * refused, and reported by the boot ERROR line on every restart, so the signal
 * meaning "something needs attention" became permanent noise and a genuinely
 * new stuck erasure was indistinguishable from it. */
static gint
check_fact_forget_reconcile_quarantines_a_foreign_intent (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 2) != 0)
    return 2480;
  if (!forget_mark_intent_foreign (store, "batch-0"))
    return 2481;

  /* First pass: the foreign intent is refused, exactly as before.  Quarantine
   * happens during the pass that refuses it, so it is counted once and the
   * outcome equality holds unchanged. */
  wyl_fact_forget_outcome_t first = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL, NULL,
      &first) != WYRELOG_E_POLICY)
    return 2482;
  if (first.loaded != 2 || first.refused != 1 || first.executed != 1)
    return 2483;

  /* Second pass: the quarantined row is neither loaded nor refused.  This is
   * the assertion the whole change exists for -- without it the row returns
   * every boot forever. */
  wyl_fact_forget_outcome_t second = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL, NULL,
      &second) != WYRELOG_E_OK)
    return 2484;
  if (second.loaded != 0)
    return 2485;
  if (second.refused != 0)
    return 2486;

  /* The evidence survives.  A quarantined intent is the record that an erasure
   * was promised and cannot be honoured by this store, so the row stays. */
  gint64 quarantined = 0;
  if (!count_i64 (store,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'QUARANTINED';",
      &quarantined))
    return 2487;
  if (quarantined != 1)
    return 2488;
  return 0;
}

/* The loop-level scope check must report an unreadable store as a FAILURE, not
 * as an out-of-scope refusal.  Those carry opposite operator meanings: refused
 * says "this store is not the one we meant to open", failed says "this store
 * would not answer".  Reporting the second as the first is the same false
 * verdict, with a count behind it, that #869 U2-1 removed one level up in the
 * survey.
 *
 * Reaching the branch needs the metadata read's answer to change mid-pass,
 * which is why it survived every mutation until now.  Intent 1 executes; the
 * seam then renames the column the scope check reads; intent 2's check returns
 * E_IO; intent 3 is abandoned.  complete_forget_intent_unlocked touches only
 * fact_forget_audit and fact_forget_intent, so intent 1 still completes after
 * the rename, and there is no open transaction at that seam -- the only BEGIN
 * in this path is inside that function, after it.
 *
 * This is a test seam that is NULL in production; it shows the branch is
 * reachable, not that DDL races are a supported configuration.  See the
 * four-part note in store-private.h for the production mechanisms.
 *
 * The refused and failed assertions come FIRST and are the point: treating any
 * non-OK scope rc as out-of-scope reports refused=2 failed=0 here, and the
 * failure should name that shape rather than the rc it also changes. */
static gint
check_fact_forget_reconcile_loop_scope_failure_is_not_a_refusal (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 3) != 0)
    return 2470;

  ForgetRenameAtNth fault = {
    .store = store,
    .seen = 0,
    .renamed = FALSE,
  };
  wyl_fact_forget_outcome_t out = { 0 };
  wyrelog_error_t rc = wyl_fact_store_forget_reconcile (store, "tenant-a",
          "orders", forget_rename_metadata_at_first_completion, &fault, &out);

  /* The fixture's control.  A silently no-opped ALTER would let all three
   * intents converge, failing the assertions below for a reason that has
   * nothing to do with the loop -- and the failure would point at the code
   * rather than at the fixture. */
  if (!fault.renamed)
    return 2471;

  /* The shape the mutation breaks: it reports refused=2, failed=0. */
  if (out.refused != 0)
    return 2472;
  if (out.failed != 1)
    return 2473;
  if (out.executed != 1)
    return 2474;
  if (out.abandoned != 1)
    return 2475;
  if (out.loaded != 3)
    return 2476;
  if (rc != WYRELOG_E_IO)
    return 2477;
  return 0;
}

/* A refusal must NOT stop the pass.  Two intents, the first out of scope:
 * the second still executes, and nothing is abandoned.  A reconciler that
 * broke on refusal leaves one intent with no disposition at all, which this
 * fixture's executed=1 assertion (2413) contradicts.  In practice that
 * mutation trips 2443 first, in the three-intent fixture above: the equality
 * guard sees the short sum and returns E_INTERNAL before the POLICY promotion
 * can run, so the rc is neither POLICY nor E_IO.  Measured on this revision --
 * it tripped 2442 before the promotion moved below the guard, and that number
 * was stale for one revision. */
static gint
check_fact_forget_reconcile_counts_refused_without_abandoning (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 2) != 0)
    return 2410;
  if (!forget_mark_intent_foreign (store, "batch-0"))
    return 2411;
  wyl_fact_forget_outcome_t out = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
      NULL, &out) != WYRELOG_E_POLICY)
    return 2412;
  if (out.loaded != 2 || out.refused != 1 || out.executed != 1)
    return 2413;
  if (out.abandoned != 0 || out.failed != 0)
    return 2414;
  return 0;
}

/* A store-scope refusal disposes of every loaded intent identically.
 * Reporting loaded=0 here -- as an earlier draft of this contract did --
 * would blind the equality on the one path where materialization and
 * disposition can diverge, because the survey fills the array BEFORE it runs
 * the store-scope guard. */
static gint
check_fact_forget_reconcile_counts_a_store_scope_refusal (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_n_pending (&store, &schema, &table, 2) != 0)
    return 2420;
  wyl_fact_forget_outcome_t out = { 0 };
  if (wyl_fact_store_forget_reconcile (store, "tenant-z", "orders", NULL,
      NULL, &out) != WYRELOG_E_POLICY)
    return 2421;
  if (out.loaded != 2 || out.refused != 2)
    return 2422;
  if (out.executed != 0 || out.failed != 0 || out.abandoned != 0)
    return 2423;
  return 0;
}

/* The counts are zeroed on every INVALID path, so a caller that ignores the
 * return value cannot read a stale count as work done. */
static gint
check_fact_forget_reconcile_zeroes_outcome_on_invalid (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  wyl_policy_fact_relation_schema_options_t schema;
  g_autofree gchar *table = NULL;
  if (forget_seed_pending_intent (&store, &schema, &table) != 0)
    return 2430;
  wyl_fact_forget_outcome_t out = { .loaded = 99, .executed = 99 };
  if (wyl_fact_store_forget_reconcile (store, NULL, "orders", NULL, NULL,
      &out) != WYRELOG_E_INVALID)
    return 2431;
  if (out.loaded != 0 || out.executed != 0)
    return 2432;
  out.loaded = 99;
  if (wyl_fact_store_forget_reconcile (NULL, "tenant-a", "orders", NULL, NULL,
      &out) != WYRELOG_E_INVALID)
    return 2433;
  if (out.loaded != 0)
    return 2434;
  out.loaded = 99;
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", NULL, NULL, NULL,
      &out) != WYRELOG_E_INVALID)
    return 2435;
  if (out.loaded != 0)
    return 2436;
  if (wyl_fact_store_forget_reconcile (store, "tenant-a", "orders", NULL,
      NULL, NULL) != WYRELOG_E_INVALID)
    return 2437;
  return 0;
}

/* THIS ASSERTION EXISTS TO FAIL ON A DUCKDB UPGRADE.
 *
 * #869 U1 made boot ask read-only whether a forget intent is pending.  A
 * forget is durable in two steps, so a crash between them leaves a PENDING
 * intent that may live only in the write-ahead log.  If DuckDB's read-only
 * mode ever stops replaying the WAL, that intent becomes invisible: the probe
 * counts zero, boot publishes CONVERGED, and an erasure the daemon accepted
 * an instruction to perform is silently lost -- with every test in this suite
 * still green.  It is the only failure mode in this area that is quiet;
 * everything else fails loudly.
 *
 * The property is currently guaranteed only by a trace of vendored
 * third-party code.  Line numbers below are against the IN-TREE PATCHED
 * amalgamation of DuckDB v1.5.5; the same sites sit 73 lines earlier in
 * duckdb.cpp.orig, so check the version before concluding a citation is
 * stale rather than that behaviour changed.  Replay is unconditional WITH
 * RESPECT TO READ-ONLY at :430010 (the branch selector at :429896 sends
 * read-only down the replaying arm; its polarity is the opposite of a
 * suppressor), and the read-only guards at :448100, :448249 and :448266
 * suppress only mutation of the WAL -- file removal and a MoveFile -- never
 * its replay.  A version bump can invalidate that trace with no other
 * signal, which is why this is an assertion and not a comment.
 *
 * READ THESE THREE LIMITS BEFORE CITING THIS TEST.
 *
 *  1. It does not cover the boot probe off-bridge.  There, open_graph_store
 *     discards |writable| (replay.c:611) and calls wyl_fact_store_open, which
 *     never sets access_mode -- the probe opens read-WRITE and replays the WAL
 *     trivially.  The silent failure mode this guards is therefore BRIDGE-ONLY
 *     in production.
 *  2. It does not cover the boot probe under the bridge either.  That path is
 *     wyl_fact_store_open_provisioned_graph; this test reaches READ_ONLY
 *     through wyl_fact_store_open_identified (VALIDATE_ONLY), which is a call
 *     path the probe takes in NEITHER configuration.  What it pins is the
 *     DuckDB-side property both would depend on.
 *  3. It does not cover the bridge's bounded filesystem serving the WAL
 *     sidecar read-only.  Nothing exercises a WAL-resident intent end to end
 *     through the bridge; that gap is real and is recorded on #869.
 *
 * The pragma at step 3 is load-bearing and was measured, not assumed: without
 * it the WAL is ABSENT after close, with it 134 bytes survive, and it is
 * honoured at duckdb_close even when set on a connection since disconnected.
 * The checkpoint at step 2 is equally load-bearing -- without it the identity
 * table fact_store_metadata is itself WAL-only, so a non-replaying open fails
 * loudly in identity validation (2350) and this test would fire for the wrong
 * reason.  Note it is fact_store_metadata that fails there, NOT
 * fact_forget_intent: an absent ledger returns OK with count 0, because
 * forget_survey_unlocked treats a missing table as nothing-to-converge.
 *
 * Phase 2 is the control.  It pins that the intent is reachable ONLY through
 * the WAL, so phase 1 cannot pass by reading the base file.  It pins the
 * fixture's dependence on the WAL; it does not promise DuckDB will keep
 * replaying it.  That is what phase 1 is for. */
static gint
check_fact_forget_read_only_open_replays_the_wal (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-wal-XXXXXX", &error);
  if (dir == NULL)
    return 2340;
  g_autofree gchar *path = g_build_filename (dir, "facts.duckdb", NULL);
  g_autofree gchar *wal = g_build_filename (dir, "facts.duckdb.wal", NULL);
  g_autofree gchar *parked = g_build_filename (dir, "parked.wal", NULL);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));

  {
    wyl_fact_store_t *store = NULL;
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    if (wyl_fact_store_open_identified (path, &test_identity,
        WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result, &store)
        != WYRELOG_E_OK || store == NULL)
      return 2341;
    g_autoptr (wyl_fact_store_t) owned = store;
    if (wyl_fact_store_create_schema (owned) != WYRELOG_E_OK)
      return 2342;
    g_autofree gchar *table = NULL;
    if (wyl_fact_store_ensure_projection (owned, &schema, &table)
        != WYRELOG_E_OK)
      return 2343;
    if (forget_append_sample (owned, &schema, "wal-batch", "wal:1", "o-1", 7)
        != 0)
      return 2344;

    wyl_fact_store_t *conn = owned;
    /* Step 2: drive schema and data into the base file. */
    if (!exec_ok_sql (conn, "CHECKPOINT;"))
      return 2345;
    if (file_size_or_missing (wal) > 0)
      return 2346;
    /* Step 3: stop the shutdown checkpoint from absorbing the WAL. */
    if (!exec_ok_sql (conn, "PRAGMA disable_checkpoint_on_shutdown;"))
      return 2347;
    /* Step 4: crash after the intent is durable and before the delete. */
    wyl_fact_store_forget_options_t opts = {
      .batch_id = "wal-batch",
      .operator_id = "admin",
      .reason = "gdpr-erasure",
      .checkpoint = forget_fault_checkpoint,
      .checkpoint_data = (gpointer) "after_intent",
    };
    if (wyl_fact_store_forget (owned, &schema, &opts, NULL) == WYRELOG_E_OK)
      return 2348;
  }

  /* The control for phase 1: the intent really is in the WAL and the WAL
   * really did survive the close.  Without this a silently ignored pragma
   * would make every assertion below vacuous. */
  gint64 wal_size = file_size_or_missing (wal);
  if (wal_size <= 0)
    return 2349;

  /* Phase 1: THE STANDING ASSERTION.  A read-only open must see it. */
  {
    wyl_fact_store_t *store = NULL;
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    if (wyl_fact_store_open_identified (path, &test_identity,
        WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result, &store)
        != WYRELOG_E_OK || store == NULL)
      return 2350;
    g_autoptr (wyl_fact_store_t) owned = store;
    /* The handle really is read-only.  Without this, a refactor that made
     * VALIDATE_ONLY open read-write would leave 2352 and 2357 both passing
     * and the test would silently stop being about read-only replay at all
     * -- which is its entire subject. */
    if (exec_ok_sql (owned,
        "CREATE TABLE wal_probe_rw (x INTEGER);"))
      return 2360;
    gsize pending = 0;
    if (wyl_fact_store_forget_pending_count (owned, "tenant-a", "orders",
        &pending) != WYRELOG_E_OK)
      return 2351;
    if (pending != 1)
      return 2352;
  }
  /* Read-only did not consume the WAL, so the fixture is re-assertable. */
  if (file_size_or_missing (wal) != wal_size)
    return 2353;

  /* Phase 2, the control: with the WAL moved aside the same open succeeds,
   * the ledger table still exists in the checkpointed base file, and the
   * count is zero with no error anywhere.  That is the silent-stranding
   * shape, and it is what phase 1 rules out. */
  if (g_rename (wal, parked) != 0)
    return 2354;
  {
    wyl_fact_store_t *store = NULL;
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    if (wyl_fact_store_open_identified (path, &test_identity,
        WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result, &store)
        != WYRELOG_E_OK || store == NULL)
      return 2355;
    g_autoptr (wyl_fact_store_t) owned = store;
    /* The ledger really is in the base file, so the zero below is the WAL
     * being gone and not the table being absent -- forget_survey_unlocked
     * returns OK with count 0 for a missing table, which would satisfy 2357
     * for entirely the wrong reason. */
    gint64 ledger_rows = -1;
    if (!count_i64 (owned,
        "SELECT COUNT(*) FROM fact_forget_intent;", &ledger_rows)
        || ledger_rows != 0)
      return 2359;
    gsize pending = 99;
    if (wyl_fact_store_forget_pending_count (owned, "tenant-a", "orders",
        &pending) != WYRELOG_E_OK)
      return 2356;
    if (pending != 0)
      return 2357;
  }
  if (g_rename (parked, wal) != 0)
    return 2358;
  return 0;
}

static gint
check_fact_store_identity_basic (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-identity-XXXXXX", &error);
  if (dir == NULL)
    return 2700;
  g_autofree gchar *path = g_build_filename (dir, "facts.duckdb", NULL);

  if (!identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_IO,
      WYL_FACT_STORE_IDENTITY_RESULT_OPEN))
    return 2701;
  if (g_file_test (path, G_FILE_TEST_EXISTS))
    return 2702;

  wyl_fact_store_t *store = NULL;
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  if (wyl_fact_store_open_identified (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result, &store)
      != WYRELOG_E_OK || result != WYL_FACT_STORE_IDENTITY_RESULT_NONE
      || store == NULL)
    return 2703;
  gint64 count = 0;
  if (!count_i64 (store,
      "SELECT COUNT(*) FROM main.fact_store_metadata;", &count)
      || count != 6)
    return 2704;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 2705;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (store, &schema, NULL) != WYRELOG_E_OK)
    return 2713;
  const wyl_fact_value_t value = {
    .type = WYL_FACT_VALUE_SYMBOL,
    .as.text = "o-1",
  };
  const wyl_fact_row_t row = { &value, 1 };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "identity-batch",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "identity-test",
    .idempotency_key = "identity:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = &row,
    .n_rows = 1,
  };
  gboolean inserted = FALSE;
  if (wyl_fact_store_append_batch (store, &schema, &batch, &inserted)
      != WYRELOG_E_OK || !inserted)
    return 2718;
  schema.tenant_id = "tenant-b";
  if (wyl_fact_store_ensure_projection (store, &schema, NULL)
      != WYRELOG_E_POLICY)
    return 2714;
  wyl_fact_store_close (store);

  if (!identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE)
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE))
    return 2706;

  WylFactStoreIdentity foreign = test_identity;
  foreign.tenant_id = "tenant-b";
  if (!identified_open_is (path, &foreign,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2707;
  foreign = test_identity;
  foreign.graph_id = "other";
  if (!identified_open_is (path, &foreign,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2708;
  foreign = test_identity;
  foreign.store_uuid = "01890f47-3c4b-6cc2-b8c4-dc0c0c073988";
  if (!identified_open_is (path, &foreign,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2709;

  foreign = test_identity;
  foreign.path_encoding_version = 2;
  if (!identified_open_is (path, &foreign,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING))
    return 2710;
  foreign = test_identity;
  foreign.format_version = 2;
  if (!identified_open_is (path, &foreign,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT))
    return 2711;
  foreign = test_identity;
  foreign.store_uuid = "01890F47-3c4b-6cc2-b8c4-dc0c0c073989";
  store = (wyl_fact_store_t *) 0x1;
  result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  if (wyl_fact_store_open_identified (path, &foreign,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result, &store)
      != WYRELOG_E_INVALID || store != NULL)
    return 2712;

  if (!create_duckdb_with_sql (path,
      "UPDATE fact_store_metadata SET value='2' "
      "WHERE key='path_encoding_version';")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING))
    return 2715;
  if (!create_duckdb_with_sql (path,
      "UPDATE fact_store_metadata SET value='01' "
      "WHERE key='path_encoding_version';")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING))
    return 2719;
  if (!create_duckdb_with_sql (path,
      "UPDATE fact_store_metadata SET value='0' "
      "WHERE key='path_encoding_version';")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING))
    return 2720;
  if (!create_duckdb_with_sql (path,
      "UPDATE fact_store_metadata SET value='1' "
      "WHERE key='path_encoding_version';"
      "UPDATE fact_store_metadata SET value='2' "
      "WHERE key='format_version';")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT))
    return 2716;
  if (!create_duckdb_with_sql (path,
      "UPDATE fact_store_metadata SET value='0' "
      "WHERE key='format_version';")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT))
    return 2721;
  if (!create_duckdb_with_sql (path,
      "UPDATE fact_store_metadata SET value='1' "
      "WHERE key='format_version';"
      "UPDATE fact_store_metadata SET value='wyrelog.audit' "
      "WHERE key='store_kind';")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2722;
  if (!create_duckdb_with_sql (path,
      "UPDATE fact_store_metadata SET value='wyrelog.fact' "
      "WHERE key='store_kind';"
      "INSERT INTO fact_store_metadata VALUES ('unknown','value');")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2723;
  if (!create_duckdb_with_sql (path,
      "DELETE FROM fact_store_metadata WHERE key='unknown';"
      "UPDATE fact_store_metadata SET value="
      "'01890F47-3c4b-6cc2-b8c4-dc0c0c073989' WHERE key='store_uuid';")
      || !identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2717;

  g_remove (path);
  g_rmdir (dir);
  return 0;
}

static gint
check_fact_store_identity_rejects_foreign_catalogs (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-foreign-XXXXXX", &error);
  if (dir == NULL)
    return 2300;
  g_autofree gchar *partial = g_build_filename (dir, "partial.db", NULL);
  g_autofree gchar *duplicate = g_build_filename (dir, "duplicate.db", NULL);
  g_autofree gchar *foreign = g_build_filename (dir, "foreign.db", NULL);
  g_autofree gchar *noncanonical =
      g_build_filename (dir, "noncanonical.db", NULL);
  g_autofree gchar *mixed = g_build_filename (dir, "mixed.db", NULL);
  g_autofree gchar *extra_index =
      g_build_filename (dir, "extra-index.db", NULL);
  g_autofree gchar *extra_column =
      g_build_filename (dir, "extra-column.db", NULL);
  g_autofree gchar *defaulted = g_build_filename (dir, "defaulted.db", NULL);
  g_autofree gchar *collated = g_build_filename (dir, "collated.db", NULL);
  g_autofree gchar *composite = g_build_filename (dir, "composite.db", NULL);
  g_autofree gchar *embedded_nul =
      g_build_filename (dir, "embedded-nul.db", NULL);
  g_autofree gchar *policy = g_build_filename (dir, "policy.sqlite", NULL);

  if (!create_duckdb_with_sql (partial,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);"
      "INSERT INTO fact_store_metadata VALUES"
      "('store_kind','wyrelog.fact');")
      || !identified_open_is (partial, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2301;

  if (!create_duckdb_with_sql (duplicate,
      "CREATE TABLE fact_store_metadata(key VARCHAR,value VARCHAR NOT NULL);"
      "INSERT INTO fact_store_metadata VALUES"
      "('store_kind','wyrelog.fact'),('store_kind','wyrelog.fact'),"
      "('format_version','1'),('store_uuid',"
      "'01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
      "('path_encoding_version','1'),('tenant_id','tenant-a'),"
      "('graph_id','orders');")
      || !identified_open_is (duplicate, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2302;

  if (!create_duckdb_with_sql (foreign, "CREATE TABLE unrelated(value INT);")
      || !identified_open_is (foreign, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2303;

  if (!create_duckdb_with_sql (noncanonical,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);"
      "INSERT INTO fact_store_metadata VALUES"
      "('store_kind','wyrelog.fact'),('format_version','01'),"
      "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
      "('path_encoding_version','1'),('tenant_id','tenant-a'),"
      "('graph_id','orders');")
      || !identified_open_is (noncanonical, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT))
    return 2304;

  if (!identified_open_is (mixed, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE)
      || !create_duckdb_with_sql (mixed,
      "CREATE TABLE audit_events(seq BIGINT PRIMARY KEY);")
      || !identified_open_is (mixed, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2305;

  if (!create_duckdb_with_sql (extra_index,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);"
      TEST_IDENTITY_ROWS
      "CREATE INDEX extra_metadata_index ON fact_store_metadata(value);")
      || !identified_open_is (extra_index, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2306;

  if (!create_duckdb_with_sql (extra_column,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL,extra VARCHAR);"
      TEST_IDENTITY_ROWS)
      || !identified_open_is (extra_column, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2307;

  if (!create_duckdb_with_sql (defaulted,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL DEFAULT 'x');"
      TEST_IDENTITY_ROWS)
      || !identified_open_is (defaulted, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2308;

  if (!create_duckdb_with_sql (collated,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR COLLATE nocase PRIMARY KEY,"
      "value VARCHAR COLLATE nocase NOT NULL);" TEST_IDENTITY_ROWS)
      || !identified_open_is (collated, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2312;

  if (!create_duckdb_with_sql (composite,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR NOT NULL,value VARCHAR NOT NULL,"
      "PRIMARY KEY(key,value));" TEST_IDENTITY_ROWS)
      || !identified_open_is (composite, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2313;

  if (create_duckdb_with_sql (embedded_nul,
      "CREATE TABLE fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);"
      TEST_IDENTITY_ROWS
      "UPDATE fact_store_metadata SET value='tenant' || chr(0) || '-a' "
      "WHERE key='tenant_id';")
      && !identified_open_is (embedded_nul, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
    return 2309;

  g_autoptr (wyl_policy_store_t) policy_store = NULL;
  if (wyl_policy_store_open (policy, &policy_store) != WYRELOG_E_OK
      || wyl_policy_store_create_schema (policy_store) != WYRELOG_E_OK)
    return 2310;
  g_clear_pointer (&policy_store, wyl_policy_store_close);
  if (!identified_open_is (policy, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_IO,
      WYL_FACT_STORE_IDENTITY_RESULT_OPEN))
    return 2311;

  g_remove (partial);
  g_remove (duplicate);
  g_remove (foreign);
  g_remove (noncanonical);
  g_remove (mixed);
  g_remove (extra_index);
  g_remove (extra_column);
  g_remove (defaulted);
  g_remove (collated);
  g_remove (composite);
  g_remove (embedded_nul);
  g_remove (policy);
  g_rmdir (dir);
  return 0;
}

static gint
check_fact_store_identity_rolls_back (void)
{
  for (gint fault = WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE;
      fault <= WYL_FACT_STORE_IDENTITY_TEST_FAULT_BEFORE_COMMIT; fault++) {
    g_autoptr (GError) error = NULL;
    g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-rollback-XXXXXX",
            &error);
    if (dir == NULL)
      return 2400 + fault;
    g_autofree gchar *path = g_build_filename (dir, "facts.duckdb", NULL);
    wyl_fact_store_identity_set_test_fault (
      (WylFactStoreIdentityTestFault) fault);
    if (!identified_open_is (path, &test_identity,
        WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_INTERNAL,
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL))
      return 2410 + fault;
    if (!identified_open_is (path, &test_identity,
        WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
        WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA))
      return 2420 + fault;
    if (!identified_open_is (path, &test_identity,
        WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_OK,
        WYL_FACT_STORE_IDENTITY_RESULT_NONE))
      return 2430 + fault;
    g_remove (path);
    g_rmdir (dir);
  }
  return 0;
}

typedef struct
{
  const gchar *path;
  const WylFactStoreIdentity *identity;
  GMutex *mutex;
  GCond *cond;
  guint *waiting;
  gboolean *go;
  wyrelog_error_t rc;
  WylFactStoreIdentityResult result;
} IdentityThread;

static gpointer
identity_open_thread (gpointer data)
{
  IdentityThread *thread = data;
  g_mutex_lock (thread->mutex);
  (*thread->waiting)++;
  g_cond_broadcast (thread->cond);
  while (!*thread->go)
    g_cond_wait (thread->cond, thread->mutex);
  g_mutex_unlock (thread->mutex);

  wyl_fact_store_t *store = NULL;
  thread->rc = wyl_fact_store_open_identified (thread->path, thread->identity,
          WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &thread->result, &store);
  wyl_fact_store_close (store);
  return NULL;
}

static gboolean
run_identity_race (const gchar *path,
    const WylFactStoreIdentity *left_identity,
    const WylFactStoreIdentity *right_identity, IdentityThread *left,
    IdentityThread *right)
{
  GMutex mutex;
  GCond cond;
  guint waiting = 0;
  gboolean go = FALSE;
  g_mutex_init (&mutex);
  g_cond_init (&cond);
  *left = (IdentityThread) {
    path, left_identity, &mutex, &cond, &waiting, &go,
    WYRELOG_E_INTERNAL, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL
  };
  *right = (IdentityThread) {
    path, right_identity, &mutex, &cond, &waiting, &go,
    WYRELOG_E_INTERNAL, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL
  };
  GThread *left_thread = g_thread_new ("identity-left",
          identity_open_thread, left);
  GThread *right_thread = g_thread_new ("identity-right",
          identity_open_thread, right);
  g_mutex_lock (&mutex);
  while (waiting != 2)
    g_cond_wait (&cond, &mutex);
  go = TRUE;
  g_cond_broadcast (&cond);
  g_mutex_unlock (&mutex);
  g_thread_join (left_thread);
  g_thread_join (right_thread);
  g_cond_clear (&cond);
  g_mutex_clear (&mutex);
  return TRUE;
}

static gboolean
identity_race_outcome_is_retryable (const IdentityThread *thread)
{
  return (thread->rc == WYRELOG_E_OK
         && thread->result == WYL_FACT_STORE_IDENTITY_RESULT_NONE)
         || (thread->rc == WYRELOG_E_IO
         && thread->result == WYL_FACT_STORE_IDENTITY_RESULT_OPEN);
}

static gint
check_fact_store_identity_concurrency (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-concurrency-XXXXXX",
          &error);
  if (dir == NULL)
    return 2500;
  g_autofree gchar *same_path = g_build_filename (dir, "same.db", NULL);
  IdentityThread left;
  IdentityThread right;
  run_identity_race (same_path, &test_identity, &test_identity, &left, &right);
  if (!identity_race_outcome_is_retryable (&left)
      || !identity_race_outcome_is_retryable (&right)
      || (left.rc != WYRELOG_E_OK && right.rc != WYRELOG_E_OK)
      || !identified_open_is (same_path, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE)
      || !identified_open_is (same_path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE))
    return 2501;

  g_autofree gchar *conflict_path = g_build_filename (dir, "conflict.db", NULL);
  WylFactStoreIdentity other = test_identity;
  other.store_uuid = "01890f47-3c4b-6cc2-b8c4-dc0c0c073988";
  run_identity_race (conflict_path, &test_identity, &other, &left, &right);
  gboolean left_won = left.rc == WYRELOG_E_OK;
  gboolean right_won = right.rc == WYRELOG_E_OK;
  const IdentityThread *loser = left_won ? &right : &left;
  gboolean loser_retryable =
      (loser->rc == WYRELOG_E_POLICY
      && loser->result == WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY)
      || (loser->rc == WYRELOG_E_IO
      && loser->result == WYL_FACT_STORE_IDENTITY_RESULT_OPEN);
  if (left_won == right_won || !loser_retryable)
    return 2502;
  const WylFactStoreIdentity *winner_identity =
      left_won ? &test_identity : &other;
  const WylFactStoreIdentity *loser_identity =
      left_won ? &other : &test_identity;
  if (!identified_open_is (conflict_path,
      winner_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE))
    return 2503;
  if (!identified_open_is (conflict_path, loser_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2504;

  g_remove (same_path);
  g_remove (conflict_path);
  g_rmdir (dir);
  return 0;
}

typedef struct
{
  gboolean updated;
} IdentitySnapshotMutation;

static void
identity_snapshot_mutate (duckdb_database db, gpointer user_data)
{
  IdentitySnapshotMutation *mutation = user_data;
  duckdb_connection writer = NULL;
  duckdb_result update = { 0 };
  if (duckdb_connect (db, &writer) == DuckDBSuccess) {
    mutation->updated = duckdb_query (writer,
            "BEGIN TRANSACTION;"
            "UPDATE main.fact_store_metadata SET value="
            "'01890f47-3c4b-6cc2-b8c4-dc0c0c073988' WHERE key='store_uuid';"
            "CREATE TABLE main.audit_events(seq BIGINT PRIMARY KEY);"
            "COMMIT;", &update) == DuckDBSuccess;
  }
  duckdb_destroy_result (&update);
  duckdb_disconnect (&writer);
}

static gint
check_fact_store_identity_validation_snapshot (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fact-snapshot-XXXXXX",
          &error);
  if (dir == NULL)
    return 2600;
  g_autofree gchar *path = g_build_filename (dir, "facts.duckdb", NULL);
  if (!identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE))
    return 2601;

  IdentitySnapshotMutation mutation = { FALSE };
  wyl_fact_store_identity_set_validation_test_hook
    (identity_snapshot_mutate, &mutation);
  if (!identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, WYRELOG_E_OK,
      WYL_FACT_STORE_IDENTITY_RESULT_NONE)
      || !mutation.updated)
    return 2603;
  if (!identified_open_is (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, WYRELOG_E_POLICY,
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY))
    return 2604;

  g_remove (path);
  g_rmdir (dir);
  return 0;
}

/* Issue #546: a mutation faulted at or before its DuckDB commit leaves nothing
 * durable, and the aborted attempt does not poison the idempotency key. */
static gint
check_fact_store_batch_commit_fault (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 960;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 961;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"k", "symbol", FALSE, TRUE},
    {"v", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (store, &schema, NULL) != WYRELOG_E_OK)
    return 962;

  wyl_fact_value_t values[2] = { 0 };
  values[0].type = WYL_FACT_VALUE_SYMBOL;
  values[0].as.text = "kf";
  values[1].type = WYL_FACT_VALUE_INT64;
  values[1].as.int64_value = 7;
  wyl_fact_row_t rows[1] = { {values, 2} };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "fault-batch-1",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .request_id = "req-fault-1",
    .idempotency_key = "fault:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = 1,
  };

  wyl_fact_store_t *conn = store;
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  if (table == NULL)
    return 963;
  g_autofree gchar *count_sql = g_strdup_printf ("SELECT COUNT(*) FROM %s;",
          table);

  /* Both fault values must leave the same postcondition: nothing durable.
   * That is all this asserts -- everything AT_COMMIT stages is inside the
   * rolled-back transaction, so no durable observable distinguishes it from
   * BEFORE_COMMIT.  The placement of the two injection points is enforced by
   * reading store.c, not by this test. */
  const WylFactStoreBatchFault faults[] = {
    WYL_FACT_STORE_BATCH_FAULT_BEFORE_COMMIT,
    WYL_FACT_STORE_BATCH_FAULT_AT_COMMIT,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (faults); i++) {
    wyl_fact_store_set_batch_fault_once_for_test (store, faults[i]);
    gboolean inserted = TRUE;
    wyl_fact_commit_delta_t delta;
    wyl_fact_commit_delta_init (&delta);
    if (wyl_fact_store_append_batch_delta (store, &schema, &batch, &inserted,
        &delta) == WYRELOG_E_OK)
      return 964;
    if (inserted || delta.inserted || delta.committed_row_delta != 0)
      return 965;

    gint64 count = -1;
    if (!count_i64 (conn, count_sql, &count) || count != 0)
      return 966;
    if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_batches;", &count)
        || count != 0)
      return 967;
    if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_event_log;", &count)
        || count != 0)
      return 968;
  }

  /* The aborted attempts did not claim the idempotency key: the same batch
   * now applies exactly once. */
  gboolean inserted = FALSE;
  wyl_fact_commit_delta_t delta;
  wyl_fact_commit_delta_init (&delta);
  if (wyl_fact_store_append_batch_delta (store, &schema, &batch, &inserted,
      &delta) != WYRELOG_E_OK)
    return 969;
  if (!inserted || !delta.inserted || delta.committed_row_delta != 1
      || delta.logical_byte_delta <= 0)
    return 970;
  gint64 count = -1;
  if (!count_i64 (conn, count_sql, &count) || count != 1)
    return 971;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_batches;", &count)
      || count != 1)
    return 972;
  if (!count_i64 (conn, "SELECT COUNT(*) FROM fact_event_log;", &count)
      || count != 1)
    return 973;
  return 0;
}

/* Issue #546: append/retract report committed resource deltas; an idempotent
 * no-op reports the zero delta. */
static gint
check_fact_store_reports_commit_delta (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 900;
  if (wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
    return 901;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"k", "symbol", FALSE, TRUE},
    {"v", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));
  if (wyl_fact_store_ensure_projection (store, &schema, NULL) != WYRELOG_E_OK)
    return 902;

  /* Two rows; each symbol "ab" is 2 logical bytes and each int64 is 8, so the
   * batch payload is 2 * (2 + 8) = 20 logical bytes. */
  wyl_fact_value_t values[4] = { 0 };
  wyl_fact_row_t rows[2] = { 0 };
  for (gsize i = 0; i < 2; i++) {
    wyl_fact_value_t *row = &values[i * 2];
    row[0].type = WYL_FACT_VALUE_SYMBOL;
    row[0].as.text = "ab";
    row[1].type = WYL_FACT_VALUE_INT64;
    row[1].as.int64_value = (gint64) i;
    rows[i].values = row;
    rows[i].n_values = 2;
  }
  const wyl_fact_store_batch_t batch = {
    .batch_id = "delta-batch-1",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .request_id = "req-delta-1",
    .idempotency_key = "delta:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = 2,
  };

  /* Pre-poison the delta to prove the store overwrites every field. */
  gboolean inserted = FALSE;
  wyl_fact_commit_delta_t delta = {TRUE, -1, -1};
  if (wyl_fact_store_append_batch_delta (store, &schema, &batch, &inserted,
      &delta) != WYRELOG_E_OK || !inserted)
    return 903;
  if (!delta.inserted || delta.committed_row_delta != 2
      || delta.logical_byte_delta != 20)
    return 904;

  /* Idempotent replay of the same batch: no-op with the zero delta. */
  wyl_fact_commit_delta_t replay_delta = {TRUE, 7, 7};
  if (wyl_fact_store_append_batch_delta (store, &schema, &batch, &inserted,
      &replay_delta) != WYRELOG_E_OK || inserted)
    return 905;
  if (replay_delta.inserted || replay_delta.committed_row_delta != 0
      || replay_delta.logical_byte_delta != 0)
    return 906;

  /* Retract reports its tombstone batch's committed delta. */
  wyl_fact_store_batch_t retract = batch;
  retract.batch_id = "delta-retract-1";
  retract.idempotency_key = "delta:retract:1";
  wyl_fact_commit_delta_t retract_delta;
  wyl_fact_commit_delta_init (&retract_delta);
  if (wyl_fact_store_retract_batch_delta (store, &schema, &retract, &inserted,
      &retract_delta) != WYRELOG_E_OK || !inserted)
    return 907;
  if (!retract_delta.inserted || retract_delta.committed_row_delta != 2
      || retract_delta.logical_byte_delta != 20)
    return 908;

  /* The plain wrappers still accept a NULL delta. */
  wyl_fact_store_batch_t plain = batch;
  plain.batch_id = "delta-plain-1";
  plain.idempotency_key = "delta:plain:1";
  if (wyl_fact_store_append_batch (store, &schema, &plain, NULL)
      != WYRELOG_E_OK)
    return 909;

  return 0;
}

static gint
check_projection_batch_count_validates_scope (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (columns,
          G_N_ELEMENTS (columns));
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK
      || wyl_fact_store_create_schema (store) != WYRELOG_E_OK
      || wyl_fact_store_ensure_projection (store, &schema, NULL)
      != WYRELOG_E_OK)
    return 3100;

  gint64 rows = 99;
  wyl_policy_fact_relation_schema_options_t invalid = schema;
  invalid.columns = NULL;
  if (wyl_fact_store_count_projection_batch_rows (store, &invalid, "batch-1",
      &rows) != WYRELOG_E_INVALID || rows != 0)
    return 3101;

  rows = 99;
  wyl_policy_fact_relation_schema_options_t foreign = schema;
  foreign.graph_id = "foreign-graph";
  if (wyl_fact_store_count_projection_batch_rows (store, &foreign, "batch-1",
      &rows) != WYRELOG_E_POLICY || rows != 0)
    return 3102;
  return 0;
}

int
main (void)
{
  gint rc = check_fact_store_thread_budget ();
  if (rc != 0)
    return rc;
  rc = check_legacy_identity_binding_is_atomic_and_recoverable ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_survey_io_failure_keeps_its_rc ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_abandoned_outranks_refused ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_failure_rc_survives_a_refusal ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_loop_scope_failure_is_not_a_refusal ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_forget_survives_a_missing_projection ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_quarantines_a_foreign_intent ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_does_not_quarantine_a_transient_failure ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_quarantine_survives_a_restart ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_intent_state_check_migrates_an_old_store ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_counts_executed ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_counts_refused_without_abandoning ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_counts_a_store_scope_refusal ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_zeroes_outcome_on_invalid ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_read_only_open_replays_the_wal ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_identity_basic ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_identity_rejects_foreign_catalogs ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_identity_rolls_back ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_identity_concurrency ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_identity_validation_snapshot ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_audit_table_exists ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_forget ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_crash_convergence ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_rejects_identifier_reuse ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_refuses_wrong_scope ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_skips_out_of_scope_intent ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_reconcile_ignores_schema_only_store ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_pending_count_reports_without_executing ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_pending_count_ignores_schema_only_store ();
  if (rc != 0)
    return rc;
  rc = check_fact_forget_pending_count_refuses_wrong_scope ();
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
  rc = check_fact_store_reports_commit_delta ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_batch_commit_fault ();
  if (rc != 0)
    return rc;
  rc = check_projection_batch_count_validates_scope ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_rejects_schema_drift ();
  if (rc != 0)
    return rc;
  rc = check_fact_store_projection_validation ();
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

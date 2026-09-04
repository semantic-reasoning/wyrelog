/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "fact-test-support.h"
#include "wyrelog/daemon/fact-status.h"
#include "wyrelog/fact/compound-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
#include "wyrelog/fact/provisioning-run-private.h"
#include "wyrelog/fact/store-open-private.h"
#include "wyrelog/wyl-id-private.h"
#endif

#define TEST(name) g_test_message ("%s", name)

wyrelog_error_t wyl_engine_open_source (const gchar * dl_src,
    guint32 num_workers, WylEngine ** out);

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  gchar *storage_path;
} GraphPathProbe;

static wyrelog_error_t
capture_graph_path_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  GraphPathProbe *probe = user_data;
  if (g_strcmp0 (probe->tenant_id, info->tenant_id) == 0
      && g_strcmp0 (probe->graph_id, info->graph_id) == 0)
    probe->storage_path = g_strdup (info->storage_path);
  return WYRELOG_E_OK;
}

static gchar *
lookup_graph_storage_path (wyl_policy_store_t *store, const gchar *tenant_id,
    const gchar *graph_id)
{
  GraphPathProbe probe = { tenant_id, graph_id, NULL };
  if (wyl_policy_store_foreach_fact_graph (store, tenant_id,
      capture_graph_path_cb, &probe) != WYRELOG_E_OK)
    return NULL;
  return probe.storage_path;
}

static void
tamper_graph_storage_path (const gchar *policy_path, const gchar *tenant_id,
    const gchar *graph_id, const gchar *storage_path)
{
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_open (policy_path, &db), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "UPDATE fact_graphs SET storage_path=? "
      "WHERE tenant_id=? AND graph_id=?;", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, storage_path, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 2, tenant_id, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 3, graph_id, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  sqlite3_close (db);
}

static void
remove_tree (const gchar *path)
{
  if (path == NULL)
    return;
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name = NULL;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (path);
}

static wyl_policy_fact_relation_schema_options_t
make_schema (const gchar *tenant_id, const gchar *graph_id,
    const wyl_policy_fact_relation_schema_column_t *columns, gsize n_columns)
{
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = n_columns,
  };
  return schema;
}

static void
create_graph_with_schema (wyl_policy_store_t *store, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, tenant_id, &created),
      ==, WYRELOG_E_OK);

  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"},
    {"amount", "int64"},
    {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (store, &graph_opts,
      NULL), ==, WYRELOG_E_OK);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (store,
      &schema), ==, WYRELOG_E_OK);
}

static wyl_policy_fact_relation_schema_options_t
make_route_schema (const gchar *tenant_id, const gchar *graph_id,
    const gchar *relation_name,
    const wyl_policy_fact_relation_schema_column_t *columns, gsize n_columns)
{
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "logistics",
    .relation_name = relation_name,
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = n_columns,
  };
  return schema;
}

static void
create_compound_graph_with_schemas (wyl_policy_store_t *store,
    const gchar *root, const gchar *tenant_id, const gchar *graph_id)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, tenant_id, &created),
      ==, WYRELOG_E_OK);

  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"route", "compound_ref"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"shipment-route", graph_columns, G_N_ELEMENTS (graph_columns)},
    {"shipment-audit", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (store, &graph_opts,
      NULL), ==, WYRELOG_E_OK);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"route", "compound_ref", FALSE, TRUE},
  };
  for (guint i = 0; i < G_N_ELEMENTS (graph_relations); i++) {
    wyl_policy_fact_relation_schema_options_t schema = make_route_schema
          (tenant_id, graph_id, graph_relations[i].relation_name, columns,
            G_N_ELEMENTS (columns));
    g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (store,
        &schema), ==, WYRELOG_E_OK);
  }
}

static void
append_order_batches (wyl_policy_store_t *policy, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id)
{
  (void) root;
  g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
          tenant_id, graph_id);
  g_assert_nonnull (storage_path);
  g_autofree gchar *fact_path = g_build_filename (storage_path,
          "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));

  wyl_fact_value_t values1[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-a"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 11},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-b"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 22},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = FALSE},
  };
  wyl_fact_row_t rows1[] = {
    {values1, 3},
    {values1 + 3, 3},
  };
  const wyl_fact_store_batch_t batch1 = {
    .batch_id = "batch-1",
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = 1,
    .source = "test",
    .idempotency_key = "key-1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows1,
    .n_rows = G_N_ELEMENTS (rows1),
  };
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch1,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);

  wyl_fact_value_t values2[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-a"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 11},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
  };
  wyl_fact_row_t rows2[] = {
    {values2, 3},
  };
  const wyl_fact_store_batch_t batch2 = {
    .batch_id = "batch-2",
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = 1,
    .source = "test",
    .idempotency_key = "key-2",
    .op = WYL_FACT_STORE_OP_RETRACT,
    .rows = rows2,
    .n_rows = G_N_ELEMENTS (rows2),
  };
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch2,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  g_clear_pointer (&store, wyl_fact_store_close);
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (fact_path, &error));
  g_assert_no_error (error);
}

static void
put_route_compounds (wyl_fact_store_t *store, const gchar *tenant_id,
    const gchar *graph_id, gint64 *out_child_ref, gint64 *out_parent_ref)
{
  const wyl_fact_compound_arg_t args[] = {
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "ICN"},
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "LAX"},
  };
  const wyl_fact_compound_value_t value = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "logistics",
    .functor = "path",
    .args = args,
    .n_args = G_N_ELEMENTS (args),
  };
  gint64 child_ref = 0;
  g_assert_cmpint (wyl_fact_compound_put (store, &value, &child_ref), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (child_ref, >, 0);

  const wyl_fact_compound_arg_t parent_args[] = {
    {.type = WYL_FACT_COMPOUND_ARG_COMPOUND_REF,.as.compound_ref = child_ref},
  };
  const wyl_fact_compound_value_t parent_value = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "logistics",
    .functor = "wrap",
    .args = parent_args,
    .n_args = G_N_ELEMENTS (parent_args),
  };
  gint64 parent_ref = 0;
  g_assert_cmpint (wyl_fact_compound_put (store, &parent_value, &parent_ref),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (parent_ref, >, 0);
  *out_child_ref = child_ref;
  *out_parent_ref = parent_ref;
}

static void
append_compound_route_batches (wyl_policy_store_t *policy,
    const gchar *tenant_id, const gchar *graph_id)
{
  g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
          tenant_id, graph_id);
  g_assert_nonnull (storage_path);
  g_autofree gchar *fact_path = g_build_filename (storage_path,
          "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_compound_create_schema (store), ==, WYRELOG_E_OK);
  gint64 child_ref = 0;
  gint64 parent_ref = 0;
  put_route_compounds (store, tenant_id, graph_id, &child_ref, &parent_ref);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"route", "compound_ref", FALSE, TRUE},
  };
  const gchar *relations[] = { "shipment-route", "shipment-audit" };
  const gint64 refs[] = { child_ref, parent_ref };
  for (guint i = 0; i < G_N_ELEMENTS (relations); i++) {
    wyl_policy_fact_relation_schema_options_t schema = make_route_schema
          (tenant_id, graph_id, relations[i], columns, G_N_ELEMENTS (columns));
    wyl_fact_value_t values[] = {
      {.type = WYL_FACT_VALUE_COMPOUND_REF,.as.compound_ref = refs[i]},
    };
    wyl_fact_row_t rows[] = {
      {values, G_N_ELEMENTS (values)},
    };
    g_autofree gchar *batch_id = g_strdup_printf ("route-batch-%u", i);
    g_autofree gchar *idempotency_key = g_strdup_printf ("route-key-%u", i);
    const wyl_fact_store_batch_t batch = {
      .batch_id = batch_id,
      .tenant_id = tenant_id,
      .graph_id = graph_id,
      .namespace_id = "logistics",
      .relation_name = relations[i],
      .schema_version = 1,
      .source = "test",
      .idempotency_key = idempotency_key,
      .op = WYL_FACT_STORE_OP_ASSERT,
      .rows = rows,
      .n_rows = G_N_ELEMENTS (rows),
    };
    gboolean inserted = FALSE;
    g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
        &inserted), ==, WYRELOG_E_OK);
    g_assert_true (inserted);
  }
  g_clear_pointer (&store, wyl_fact_store_close);
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (fact_path, &error));
  g_assert_no_error (error);
}

typedef struct
{
  const gchar *relation;
  guint count;
  gboolean saw_order_b;
} SnapshotProbe;

static void
snapshot_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  SnapshotProbe *probe = user_data;
  if (g_strcmp0 (relation, probe->relation) != 0 || ncols != 3)
    return;
  probe->count++;
  if (row[1] == 22 && row[2] == 0)
    probe->saw_order_b = TRUE;
}

static void
assert_replayed_order_b_only (WylEngine *engine)
{
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  SnapshotProbe probe = { observed, 0, FALSE };
  g_assert_cmpint (wyl_engine_snapshot (engine, observed, snapshot_cb, &probe),
      ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.count, ==, 1);
  g_assert_true (probe.saw_order_b);
}

static void
handle_snapshot_cb (WylEngine *engine, const gchar *relation,
    const gint64 *row, guint ncols, gpointer user_data)
{
  (void) engine;
  snapshot_cb (relation, row, ncols, user_data);
}

static void
assert_handle_replayed_order_b_only (WylHandle *handle,
    const gchar *tenant_id, const gchar *graph_id)
{
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  SnapshotProbe probe = { observed, 0, FALSE };
  g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle, tenant_id,
      graph_id, observed, handle_snapshot_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.count, ==, 1);
  g_assert_true (probe.saw_order_b);
}

typedef struct
{
  guint total;
  guint ready;
  guint unavailable;
  wyl_fact_graph_state_t last_state;
  gboolean saw_tenant_a_ready;
  gboolean saw_tenant_a_stale;
  gboolean saw_tenant_b_unavailable;
} FactStatusProbe;

static wyrelog_error_t
fact_status_cb (const wyl_fact_graph_status_t *status, gpointer user_data)
{
  FactStatusProbe *probe = user_data;
  probe->total++;
  probe->last_state = status->state;
  if (status->state == WYL_FACT_GRAPH_STATE_READY)
    probe->ready++;
  if (status->state == WYL_FACT_GRAPH_STATE_STORE_UNAVAILABLE)
    probe->unavailable++;
  if (g_strcmp0 (status->tenant_id, "tenant-a") == 0
      && g_strcmp0 (status->graph_id, "orders") == 0
      && status->state == WYL_FACT_GRAPH_STATE_READY
      && status->queryable && status->last_error_class == NULL)
    probe->saw_tenant_a_ready = TRUE;
  if (g_strcmp0 (status->tenant_id, "tenant-a") == 0
      && g_strcmp0 (status->graph_id, "orders") == 0
      && status->state == WYL_FACT_GRAPH_STATE_STORE_UNAVAILABLE
      && status->queryable
      && g_strcmp0 (status->last_error_class, "store_unavailable") == 0)
    probe->saw_tenant_a_stale = TRUE;
  if (g_strcmp0 (status->tenant_id, "tenant-b") == 0
      && g_strcmp0 (status->graph_id, "orders") == 0
      && status->state == WYL_FACT_GRAPH_STATE_STORE_UNAVAILABLE
      && !status->queryable
      && g_strcmp0 (status->last_error_class, "store_unavailable") == 0)
    probe->saw_tenant_b_unavailable = TRUE;
  return WYRELOG_E_OK;
}

static void
assert_handle_stale_fact_status (WylHandle *handle)
{
  FactStatusProbe probe = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.total, ==, 2);
  g_assert_cmpuint (probe.ready, ==, 0);
  g_assert_cmpuint (probe.unavailable, ==, 2);
  g_assert_true (probe.saw_tenant_a_stale);
  g_assert_true (probe.saw_tenant_b_unavailable);
}

static void
assert_handle_fact_status (WylHandle *handle)
{
  FactStatusProbe probe = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.total, ==, 2);
  g_assert_cmpuint (probe.ready, ==, 1);
  g_assert_cmpuint (probe.unavailable, ==, 1);
  g_assert_true (probe.saw_tenant_a_ready);
  g_assert_true (probe.saw_tenant_b_unavailable);

  g_autofree gchar *json = wyl_daemon_fact_status_json (handle, TRUE);
  g_assert_nonnull (json);
  g_assert_nonnull (strstr (json, "\"status\":\"degraded\""));
  g_assert_nonnull (strstr (json, "\"tenant_id\":\"tenant-a\""));
  g_assert_nonnull (strstr (json, "\"tenant_id\":\"tenant-b\""));
  g_assert_nonnull (strstr (json, "\"graph_id\":\"orders\""));
  g_assert_nonnull (strstr (json,
      "\"last_error_class\":\"store_unavailable\""));
  g_assert_null (strstr (json, "facts.duckdb"));
  g_assert_null (strstr (json, "storage_path"));
}

typedef struct
{
  const gchar *relation;
  guint count;
  gint64 handle;
} CompoundSnapshotProbe;

static void
compound_snapshot_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  CompoundSnapshotProbe *probe = user_data;
  if (g_strcmp0 (relation, probe->relation) != 0 || ncols != 1)
    return;
  probe->count++;
  if (probe->handle > 0)
    g_assert_cmpint (probe->handle, ==, row[0]);
  probe->handle = row[0];
}

static gint64
snapshot_single_compound_handle (WylEngine *engine, const gchar *relation_name)
{
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("logistics", relation_name);
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  CompoundSnapshotProbe probe = { observed, 0, 0 };
  g_assert_cmpint (wyl_engine_snapshot (engine, observed, compound_snapshot_cb,
      &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.count, >, 0);
  g_assert_cmpint (probe.handle, >, 0);
  return probe.handle;
}

/* Abort a forget at a named durable boundary, the way a crash would. */
static wyrelog_error_t
forget_crash_at (const gchar *point, gpointer user_data)
{
  return g_strcmp0 (point, (const gchar *) user_data) == 0
         ? WYRELOG_E_IO : WYRELOG_E_OK;
}

static gint64
count_in_graph_store (wyl_policy_store_t *policy, const gchar *tenant_id,
    const gchar *graph_id, const gchar *sql)
{
  g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
          tenant_id, graph_id);
  g_assert_nonnull (storage_path);
  g_autofree gchar *fact_path = g_build_filename (storage_path,
          "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==, WYRELOG_E_OK);
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (conn, sql, &result), ==, DuckDBSuccess);
  gint64 value = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return value;
}

/* Issue #547: boot reconciliation must converge each graph's own pending work,
 * and a graph it cannot open must not stop the daemon from starting.
 *
 * The single-graph case cannot show either property: a driver that reconciled
 * one hard-coded graph would pass it, and a driver that propagated failure
 * would never be exercised. */
static void
test_boot_forget_is_per_graph_and_never_aborts (void)
{
  TEST ("boot converges each graph's own forget and survives one it cannot "
      "open");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-forget-multi-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);
  g_autofree gchar *broken_path = NULL;

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    create_graph_with_schema (policy, root, "tenant-b", "orders");
    create_graph_with_schema (policy, root, "tenant-a", "broken");
    append_order_batches (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-b", "orders");
    append_order_batches (policy, root, "tenant-a", "broken");

    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
      {"expedited", "bool", FALSE, TRUE},
    };
    /* Crash a forget on BOTH healthy graphs, of different batches, so a
     * driver that reconciles one graph for another cannot pass. */
    const gchar *tenants[] = { "tenant-a", "tenant-b" };
    const gchar *batches[] = { "batch-1", "batch-2" };
    for (gsize i = 0; i < G_N_ELEMENTS (tenants); i++) {
      g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
              tenants[i], "orders");
      g_assert_nonnull (storage_path);
      g_autofree gchar *fact_path = g_build_filename (storage_path,
              "facts.duckdb", NULL);
      g_autoptr (wyl_fact_store_t) store = NULL;
      g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==,
          WYRELOG_E_OK);
      wyl_policy_fact_relation_schema_options_t schema = make_schema
            (tenants[i], "orders", columns, G_N_ELEMENTS (columns));
      wyl_fact_store_forget_options_t opts = {
        .batch_id = batches[i],
        .operator_id = "admin",
        .reason = "gdpr-erasure",
        .checkpoint = forget_crash_at,
        .checkpoint_data = (gpointer) "before_completion",
      };
      g_assert_cmpint (wyl_fact_store_forget (store, &schema, &opts, NULL),
          !=, WYRELOG_E_OK);
    }

    /* And corrupt a third graph's store so its reconcile cannot succeed. */
    g_autofree gchar *broken_storage = lookup_graph_storage_path (policy,
            "tenant-a", "broken");
    g_assert_nonnull (broken_storage);
    broken_path = g_build_filename (broken_storage, "facts.duckdb", NULL);
    g_assert_true (g_file_set_contents (broken_path, "not a database", -1,
        NULL));
    g_assert_true (wyl_test_secure_regular_file (broken_path, &error));
    g_assert_no_error (error);
  }

  /* The daemon must still start. */
  {
    g_autoptr (WylHandle) handle = NULL;
    const WylHandleOpenOptions opts = {
      .policy_store_path = policy_path,
      .fact_root = root,
    };
    g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
        WYRELOG_E_OK);
  }

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    /* Each healthy graph converged its OWN batch. */
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
        ==, 0);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-b", "orders",
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
        ==, 0);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'batch-1';"),
        ==, 0);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-b", "orders",
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'batch-2';"),
        ==, 0);
    /* Each converged only its own: the other graph's batch is untouched. */
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'batch-2';"),
        ==, 1);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-b", "orders",
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'batch-1';"),
        ==, 1);
  }

  remove_tree (root);
}

/* Issue #547: a forget interrupted by a crash leaves a durable PENDING intent
 * that nothing in the request path resumes.  Starting the daemon must converge
 * it.  The proof is a fresh handle open and the durable state afterwards --
 * this test never calls the reconciler itself, because doing so would prove
 * only that the reconciler works, not that anything drives it. */
static void
test_boot_converges_interrupted_forget (void)
{
  TEST ("opening a handle converges a forget a crash left pending");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-forget-boot-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");

    /* Crash a forget of batch-1 just before it records completion. */
    g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
            "tenant-a", "orders");
    g_assert_nonnull (storage_path);
    g_autofree gchar *fact_path = g_build_filename (storage_path,
            "facts.duckdb", NULL);
    g_autoptr (wyl_fact_store_t) store = NULL;
    g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==,
        WYRELOG_E_OK);
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
      {"expedited", "bool", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema = make_schema ("tenant-a",
            "orders", columns, G_N_ELEMENTS (columns));
    wyl_fact_store_forget_options_t opts = {
      .batch_id = "batch-1",
      .operator_id = "admin",
      .reason = "gdpr-erasure",
      .checkpoint = forget_crash_at,
      .checkpoint_data = (gpointer) "before_completion",
    };
    g_assert_cmpint (wyl_fact_store_forget (store, &schema, &opts, NULL), !=,
        WYRELOG_E_OK);
  }

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    /* Durable evidence that the crash left work behind. */
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
        ==, 1);
  }

  /* The restart.  Nothing else in this test touches the reconciler. */
  {
    g_autoptr (WylHandle) handle = NULL;
    const WylHandleOpenOptions opts = {
      .policy_store_path = policy_path,
      .fact_root = root,
    };
    g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
        WYRELOG_E_OK);
    /* This graph is not sealed, so the very same snapshot call succeeds -- and
     * returns nothing, because batch-1 asserted both orders while batch-2 only
     * retracted one, so erasing batch-1 leaves no net fact.  The sealed twin
     * of this test asserts this call fails outright; the pairing is what makes
     * that failure attributable to the seal rather than to a mistyped relation
     * name. */
    g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
          ("shop.ns", "orders-rel");
    g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
    SnapshotProbe probe = { observed, 0, FALSE };
    g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
        "tenant-a", "orders", observed, handle_snapshot_cb, &probe), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (probe.count, ==, 0);
  }

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    /* Converged: no pending intent, and the batch really is gone. */
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
        ==, 0);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'batch-1';"),
        ==, 0);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_audit WHERE batch_id = 'batch-1';"),
        ==, 1);
  }

  remove_tree (root);
}

/* Issue #547: sealing blocks admission of new data, not erasure of data
 * already stored.  A sealed graph refuses forget at the request boundary, so
 * a forget a crash left pending on one has no in-product remedy at all except
 * this one.  That makes the sealed case the reason boot reconciliation exists,
 * not an edge of it.
 *
 * This is also the property #548 has to preserve when it turns sealing into a
 * runtime barrier: startup may publish no engine for a sealed graph, and this
 * test asserts it does not, but it must still open that graph's store to
 * finish an erasure already recorded against it. */
static void
test_boot_converges_forget_on_sealed_graph (void)
{
  TEST ("opening a handle converges a pending forget on a sealed graph");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-forget-sealed-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");

    g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
            "tenant-a", "orders");
    g_assert_nonnull (storage_path);
    g_autofree gchar *fact_path = g_build_filename (storage_path,
            "facts.duckdb", NULL);
    g_autoptr (wyl_fact_store_t) store = NULL;
    g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==,
        WYRELOG_E_OK);
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
      {"expedited", "bool", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema = make_schema ("tenant-a",
            "orders", columns, G_N_ELEMENTS (columns));
    wyl_fact_store_forget_options_t opts = {
      .batch_id = "batch-1",
      .operator_id = "admin",
      .reason = "gdpr-erasure",
      .checkpoint = forget_crash_at,
      .checkpoint_data = (gpointer) "before_completion",
    };
    g_assert_cmpint (wyl_fact_store_forget (store, &schema, &opts, NULL), !=,
        WYRELOG_E_OK);
    g_clear_pointer (&store, wyl_fact_store_close);

    /* Seal only after the crash, exactly as an operator sealing a graph with
     * unfinished erasure work would. */
    g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
        "orders"), ==, WYRELOG_E_OK);
  }

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    /* The seal really took: without this the test would prove nothing about
     * sealed graphs, because an unsealed one converges either way. */
    gboolean active = TRUE;
    g_assert_cmpint (wyl_policy_store_fact_graph_is_active (policy, "tenant-a",
        "orders", &active), ==, WYRELOG_E_OK);
    g_assert_false (active);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
        ==, 1);
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    const WylHandleOpenOptions opts = {
      .policy_store_path = policy_path,
      .fact_root = root,
    };
    g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
        WYRELOG_E_OK);
    /* A sealed graph gets no engine.  Convergence below is therefore not a
     * side effect of the graph having been replayed like any other. */
    g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
          ("shop.ns", "orders-rel");
    g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
    SnapshotProbe probe = { observed, 0, FALSE };
    g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
        "tenant-a", "orders", observed, handle_snapshot_cb, &probe), !=,
        WYRELOG_E_OK);
  }

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
        ==, 0);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'batch-1';"),
        ==, 0);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_audit WHERE batch_id = 'batch-1';"),
        ==, 1);
    /* The graph is still sealed: erasure converged without unsealing it. */
    gboolean active = TRUE;
    g_assert_cmpint (wyl_policy_store_fact_graph_is_active (policy, "tenant-a",
        "orders", &active), ==, WYRELOG_E_OK);
    g_assert_false (active);
  }

  remove_tree (root);
}
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
static void
provisioned_871_create_graph (wyl_policy_store_t *policy, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id)
{
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"},
    {"amount", "int64"},
    {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  gchar op_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_policy_store_create_fact_graph_provisioning (policy,
      &graph_opts, NULL, op_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpstr (op_uuid, !=, "");
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (policy, op_uuid, root,
      NULL), ==, WYRELOG_E_OK);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (policy,
      &schema), ==, WYRELOG_E_OK);
}

static gchar *
provisioned_871_append_one (wyl_fact_store_t *store, const gchar *tenant_id,
    const gchar *graph_id, const gchar *batch_id,
    const gchar *idempotency_key, const gchar *order_id, gint64 amount,
    gboolean expedited)
{
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  g_assert_nonnull (table);
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = order_id},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = amount},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = expedited},
  };
  wyl_fact_row_t rows[] = {
    {values, G_N_ELEMENTS (values)},
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = batch_id,
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = 1,
    .source = "issue-871",
    .idempotency_key = idempotency_key,
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  return g_steal_pointer (&table);
}

static gint64
provisioned_871_count (wyl_fact_store_t *store, const gchar *sql)
{
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_fact_store_get_connection (store), sql,
      &result), ==, DuckDBSuccess);
  g_assert_cmpuint (duckdb_row_count (&result), ==, 1);
  gint64 value = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return value;
}

static gchar *
provisioned_871_text (wyl_fact_store_t *store, const gchar *sql)
{
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_fact_store_get_connection (store), sql,
      &result), ==, DuckDBSuccess);
  g_assert_cmpuint (duckdb_row_count (&result), ==, 1);
  gchar *value = duckdb_value_varchar (&result, 0, 0);
  g_assert_nonnull (value);
  gchar *copy = g_strdup (value);
  duckdb_free (value);
  duckdb_destroy_result (&result);
  return copy;
}

typedef struct
{
  guint seen;
  gboolean saw_active_ready;
  gboolean saw_sealed_without_engine;
} Provisioned871StatusProbe;

static wyrelog_error_t
provisioned_871_status_cb (const wyl_fact_graph_status_t *status,
    gpointer user_data)
{
  Provisioned871StatusProbe *probe = user_data;
  probe->seen++;
  if (g_strcmp0 (status->tenant_id, "tenant-871") == 0
      && g_strcmp0 (status->graph_id, "active-orders") == 0
      && status->state == WYL_FACT_GRAPH_STATE_READY && status->queryable
      && status->last_error_class == NULL)
    probe->saw_active_ready = TRUE;
  if (g_strcmp0 (status->tenant_id, "tenant-871") == 0
      && g_strcmp0 (status->graph_id, "sealed-orders") == 0
      && status->state != WYL_FACT_GRAPH_STATE_READY && !status->queryable)
    probe->saw_sealed_without_engine = TRUE;
  return WYRELOG_E_OK;
}
#endif

/* Issue #871: the legacy sealed-store path is covered above, but provisioned
 * stores cross a distinct authority gate.  This case proves startup may open
 * a retained SEALED pair to finish an already-recorded erasure without
 * publishing an engine or changing the graph's authority. */
static void
test_boot_converges_forget_on_sealed_provisioned_graph (void)
{
#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE
  g_test_skip ("requires the secure DuckDB provisioned-store bridge");
  return;
#else
  TEST ("opening a handle converges a provisioned sealed graph's pending "
      "forget");
  const gchar *tenant_id = "tenant-871";
  const gchar *target_graph = "sealed-orders";
  const gchar *control_graph = "active-orders";
  const gchar *batch_id = "sealed-batch-871";
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioned-sealed-871-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);
  WylPolicyGraphAuthorityRecord *sealed_authority = NULL;
  g_autofree gchar *forget_op_uuid = NULL;

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    gboolean created = FALSE;
    g_assert_cmpint (wyl_policy_store_create_tenant (policy, tenant_id,
        &created), ==, WYRELOG_E_OK);
    g_assert_true (created);
    provisioned_871_create_graph (policy, root, tenant_id, target_graph);
    provisioned_871_create_graph (policy, root, tenant_id, control_graph);

    WylPolicyGraphAuthorityRecord *target_active = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
        target_graph, &target_active), ==, WYRELOG_E_OK);
    g_assert_nonnull (target_active);
    g_assert_cmpint (target_active->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
    g_assert_cmpint (target_active->last_error_class, ==,
        WYL_POLICY_GRAPH_ERROR_NONE);
    g_assert_true (target_active->has_store_identity);
    g_assert_nonnull (target_active->store_uuid);
    g_assert_cmpstr (target_active->store_uuid, !=, "");

    g_autoptr (wyl_fact_store_t) control_store = NULL;
    g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy, root,
        tenant_id, control_graph, TRUE, &control_store), ==, WYRELOG_E_OK);
    g_autofree gchar *control_table = provisioned_871_append_one
          (control_store, tenant_id, control_graph, "control-batch-871",
            "control-key-871", "order-b", 22, FALSE);
    g_assert_cmpint (provisioned_871_count (control_store,
        "SELECT COUNT(*) FROM fact_batches "
        "WHERE batch_id = 'control-batch-871';"), ==, 1);
    g_clear_pointer (&control_store, wyl_fact_store_close);

    g_autoptr (wyl_fact_store_t) target_store = NULL;
    g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy, root,
        tenant_id, target_graph, TRUE, &target_store), ==, WYRELOG_E_OK);
    g_autofree gchar *target_table = provisioned_871_append_one
          (target_store, tenant_id, target_graph, batch_id, "sealed-key-871",
            "order-sealed", 71, TRUE);
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
      {"expedited", "bool", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
            target_graph, columns, G_N_ELEMENTS (columns));
    const wyl_fact_store_forget_options_t forget_opts = {
      .batch_id = batch_id,
      .operator_id = "operator-871",
      .reason = "sealed-erasure-871",
      .checkpoint = forget_crash_at,
      .checkpoint_data = (gpointer) "after_intent",
    };
    g_assert_cmpint (wyl_fact_store_forget (target_store, &schema,
        &forget_opts, NULL), ==, WYRELOG_E_IO);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_forget_intent "
        "WHERE batch_id = 'sealed-batch-871' AND state = 'PENDING' "
        "AND rows_purged = 1;"), ==, 1);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_forget_intent "
        "WHERE batch_id = 'sealed-batch-871' AND state = 'COMPLETED';"), ==,
        0);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_batches "
        "WHERE batch_id = 'sealed-batch-871';"), ==, 1);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_event_log "
        "WHERE batch_id = 'sealed-batch-871';"), ==, 1);
    g_autofree gchar *projection_before_sql = g_strdup_printf
          ("SELECT COUNT(*) FROM %s WHERE __wyl_batch_id = "
            "'sealed-batch-871';", target_table);
    g_assert_cmpint (provisioned_871_count (target_store,
        projection_before_sql), ==, 1);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_forget_audit "
        "WHERE batch_id = 'sealed-batch-871';"), ==, 0);
    forget_op_uuid = provisioned_871_text (target_store,
            "SELECT op_uuid FROM fact_forget_intent "
            "WHERE batch_id = 'sealed-batch-871' AND state = 'PENDING';");
    g_assert_nonnull (forget_op_uuid);
    g_clear_pointer (&target_store, wyl_fact_store_close);

    g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, tenant_id,
        target_graph), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
        target_graph, &sealed_authority), ==, WYRELOG_E_OK);
    g_assert_nonnull (sealed_authority);
    g_assert_cmpint (sealed_authority->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
    g_assert_cmpint (sealed_authority->last_error_class, ==,
        WYL_POLICY_GRAPH_ERROR_NONE);
    g_assert_true (sealed_authority->has_store_identity);
    g_assert_cmpstr (sealed_authority->store_uuid, ==,
        target_active->store_uuid);
    g_assert_cmpuint (sealed_authority->format_version, ==,
        target_active->format_version);
    g_assert_cmpuint (sealed_authority->path_encoding_version, ==,
        target_active->path_encoding_version);
    g_assert_cmpuint (sealed_authority->lifecycle_generation, ==,
        target_active->lifecycle_generation + 1);
    g_assert_cmpuint (sealed_authority->reconciliation_generation, ==,
        target_active->reconciliation_generation);
    wyl_policy_graph_authority_record_free (target_active);
  }

  /* A genuinely fresh handle is the only thing allowed to drive reconcile. */
  {
    g_autoptr (WylHandle) handle = NULL;
    const WylHandleOpenOptions opts = {
      .policy_store_path = policy_path,
      .fact_root = root,
    };
    g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
        WYRELOG_E_OK);
    g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
          ("shop.ns", "orders-rel");
    g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
    SnapshotProbe control = { observed, 0, FALSE };
    g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
        tenant_id, control_graph, observed, handle_snapshot_cb, &control), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (control.count, ==, 1);
    g_assert_true (control.saw_order_b);
    SnapshotProbe sealed = { observed, 0, FALSE };
    g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
        tenant_id, target_graph, observed, handle_snapshot_cb, &sealed), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpuint (sealed.count, ==, 0);
    Provisioned871StatusProbe statuses = { 0 };
    g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
        provisioned_871_status_cb, &statuses), ==, WYRELOG_E_OK);
    g_assert_cmpuint (statuses.seen, ==, 2);
    g_assert_true (statuses.saw_active_ready);
    g_assert_true (statuses.saw_sealed_without_engine);
  }

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    WylPolicyGraphAuthorityRecord *after = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
        target_graph, &after), ==, WYRELOG_E_OK);
    g_assert_nonnull (after);
    g_assert_cmpint (after->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
    g_assert_cmpint (after->last_error_class, ==,
        WYL_POLICY_GRAPH_ERROR_NONE);
    g_assert_true (after->has_store_identity);
    g_assert_cmpstr (after->store_uuid, ==, sealed_authority->store_uuid);
    g_assert_cmpuint (after->format_version, ==,
        sealed_authority->format_version);
    g_assert_cmpuint (after->path_encoding_version, ==,
        sealed_authority->path_encoding_version);
    g_assert_cmpuint (after->lifecycle_generation, ==,
        sealed_authority->lifecycle_generation);
    g_assert_cmpuint (after->reconciliation_generation, ==,
        sealed_authority->reconciliation_generation);
    wyl_policy_graph_authority_record_free (after);

    WylPolicyGraphAuthorityRecord *control_authority = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
        control_graph, &control_authority), ==, WYRELOG_E_OK);
    g_assert_nonnull (control_authority);
    g_assert_cmpint (control_authority->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
    g_assert_cmpint (control_authority->last_error_class, ==,
        WYL_POLICY_GRAPH_ERROR_NONE);
    wyl_policy_graph_authority_record_free (control_authority);

    g_autoptr (wyl_fact_store_t) target_store = NULL;
    g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy, root,
        tenant_id, target_graph, FALSE, &target_store), ==, WYRELOG_E_OK);
    g_autofree gchar *pending_sql = g_strdup_printf
          ("SELECT COUNT(*) FROM fact_forget_intent WHERE op_uuid = '%s' "
            "AND state = 'PENDING';", forget_op_uuid);
    g_autofree gchar *completed_sql = g_strdup_printf
          ("SELECT COUNT(*) FROM fact_forget_intent WHERE op_uuid = '%s' "
            "AND state = 'COMPLETED' AND rows_purged = 1;", forget_op_uuid);
    g_assert_cmpint (provisioned_871_count (target_store, pending_sql), ==, 0);
    g_assert_cmpint (provisioned_871_count (target_store, completed_sql), ==,
        1);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_batches "
        "WHERE batch_id = 'sealed-batch-871';"), ==, 0);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_event_log "
        "WHERE batch_id = 'sealed-batch-871';"), ==, 0);
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
      {"expedited", "bool", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
            target_graph, columns, G_N_ELEMENTS (columns));
    g_autofree gchar *target_table =
        wyl_fact_store_projection_table_name (&schema);
    g_autofree gchar *projection_after_sql = g_strdup_printf
          ("SELECT COUNT(*) FROM %s WHERE __wyl_batch_id = "
            "'sealed-batch-871';", target_table);
    g_assert_cmpint (provisioned_871_count (target_store,
        projection_after_sql), ==, 0);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_forget_audit "
        "WHERE batch_id = 'sealed-batch-871';"), ==, 1);
    g_assert_cmpint (provisioned_871_count (target_store,
        "SELECT COUNT(*) FROM fact_forget_audit "
        "WHERE batch_id = 'sealed-batch-871' "
        "AND tenant_id = 'tenant-871' AND graph_id = 'sealed-orders' "
        "AND operator = 'operator-871' AND reason = 'sealed-erasure-871' "
        "AND rows_purged = 1;"), ==, 1);
  }

  wyl_policy_graph_authority_record_free (sealed_authority);
  remove_tree (root);
#endif
}


/* Leave a durable, unconverged erasure on a graph that is otherwise healthy.
 *
 * after_intent is the seam that matters: the intent is committed and no delete
 * has run, so the rows the intent names are still present and a reconcile that
 * executed would be visible as their absence.  Rewriting the intent's tenant
 * then makes the reconciler's per-intent scope check skip it -- POLICY, with
 * the store open, which is the ledger-was-read class rather than the
 * could-not-open class. */
/* Undo seed_unconverged_erasure's fault: strip the `missing__` prefix so the
 * intent names its real projection again and the next pass converges it.
 *
 * The strip happens in C rather than in SQL.  A `replace()` in the UPDATE
 * read more naturally, but it was the only DuckDB-side use of that function
 * in the tree -- every other one runs against SQLite -- and it failed on the
 * macOS row while passing everywhere else.  A bound parameter needs nothing
 * from the SQL dialect, so it cannot differ between rows.
 *
 * Every DuckDB failure here reports its own error text.  The previous form
 * asserted on the return code alone, so a failure showed up as `1 == 0` with
 * nothing saying why. */
static void
repair_forget_projection_table (duckdb_connection conn)
{
  static const gchar prefix[] = "missing__";
  duckdb_result res = { 0 };
  if (duckdb_query (conn,
      "SELECT projection_table FROM fact_forget_intent "
      "WHERE state = 'PENDING';", &res) != DuckDBSuccess) {
    g_error ("reading the faulted intent failed: %s",
        duckdb_result_error (&res));
  }
  if (duckdb_row_count (&res) != 1) {
    g_error ("expected one PENDING intent to repair, found %" G_GUINT64_FORMAT,
        (guint64) duckdb_row_count (&res));
  }
  /* duckdb_value_varchar allocates with DuckDB's allocator, so it is freed
   * with duckdb_free rather than g_free. */
  gchar *faulted = duckdb_value_varchar (&res, 0, 0);
  duckdb_destroy_result (&res);
  g_assert_nonnull (faulted);
  g_assert_true (g_str_has_prefix (faulted, prefix));
  g_autofree gchar *real_name = g_strdup (faulted + sizeof (prefix) - 1);
  duckdb_free (faulted);

  duckdb_prepared_statement stmt = NULL;
  if (duckdb_prepare (conn,
      "UPDATE fact_forget_intent SET projection_table = ? "
      "WHERE state = 'PENDING';", &stmt) != DuckDBSuccess) {
    g_autofree gchar *why = g_strdup (duckdb_prepare_error (stmt));
    duckdb_destroy_prepare (&stmt);
    g_error ("preparing the repair failed: %s", why != NULL ? why : "(none)");
  }
  if (duckdb_bind_varchar (stmt, 1, real_name) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    g_error ("binding the repaired projection name failed");
  }
  duckdb_result upd = { 0 };
  if (duckdb_execute_prepared (stmt, &upd) != DuckDBSuccess) {
    g_autofree gchar *why = g_strdup (duckdb_result_error (&upd));
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&upd);
    g_error ("the repair UPDATE failed: %s", why != NULL ? why : "(none)");
  }
  duckdb_destroy_prepare (&stmt);
  duckdb_destroy_result (&upd);
}

static void
seed_unconverged_erasure (wyl_policy_store_t *policy, const gchar *tenant_id,
    const gchar *graph_id)
{
  g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
          tenant_id, graph_id);
  g_assert_nonnull (storage_path);
  g_autofree gchar *fact_path = g_build_filename (storage_path,
          "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  wyl_fact_store_forget_options_t opts = {
    .batch_id = "batch-1",
    .operator_id = "admin",
    .reason = "gdpr-erasure",
    .checkpoint = forget_crash_at,
    .checkpoint_data = (gpointer) "after_intent",
  };
  g_assert_cmpint (wyl_fact_store_forget (store, &schema, &opts, NULL), !=,
      WYRELOG_E_OK);

  /* Point the intent at a projection table that does not exist, so executing
   * it fails and it stays PENDING.  This used to rewrite the tenant to
   * `tenant-z` instead, which the reconciler refuses -- but since #941 an
   * identity mismatch is quarantined on the first pass that sees it, and
   * handle-open runs such a pass, so by replay time there would be no
   * outstanding erasure left to report.  A retryable failure is what an
   * unconverged erasure looks like now: quarantine is for the permanent
   * conditions, and this is not one of them. */
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (conn,
      "UPDATE fact_forget_intent "
      "SET projection_table = 'missing__' || projection_table "
      "WHERE state = 'PENDING';", &result), ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
}

/* No graph reports the forget axis.  Used where every graph is degraded for a
 * replay reason: the axis must not surface at all, rather than surfacing as
 * converged. */
static wyrelog_error_t
no_forget_state_cb (const wyl_fact_graph_status_t *status, gpointer user_data)
{
  (void) user_data;
  g_assert_cmpint (status->state, !=, WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE);
  return WYRELOG_E_OK;
}

static void
assert_no_graph_reports_forget_state (WylHandle *handle)
{
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      no_forget_state_cb, NULL), ==, WYRELOG_E_OK);
  g_autofree gchar *json = wyl_daemon_fact_status_json (handle, TRUE);
  g_assert_nonnull (json);
  g_assert_null (strstr (json, "forget_incomplete"));
}

/* The state of the one graph a fixture holds, read through the same path the
 * daemon status surface uses. */
static wyl_fact_graph_state_t
assert_single_graph_state (WylHandle *handle)
{
  FactStatusProbe probe = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.total, ==, 1);
  return probe.last_state;
}

/* Issue #870: the verdict clears when the erasure converges, and a targeted
 * refresh must not clear it.
 *
 * These are the two halves of "the setter is total".  Boot writes CONVERGED on
 * success, so a graph that converges on a later replay heals itself -- without
 * that, the zero value is a lie and the graph stays incomplete for the life of
 * the process.  A targeted post-mutation refresh does not read the forget
 * ledger, so it learns nothing about any erasure and must leave the verdict
 * alone; clearing there would silently drop the signal on the next append. */
static void
test_forget_state_clears_on_convergence_but_not_on_refresh (void)
{
  TEST ("convergence clears the verdict; a targeted refresh does not");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-status-clear-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    seed_unconverged_erasure (policy, "tenant-a", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (assert_single_graph_state (handle), ==,
      WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE);

  /* A targeted refresh leaves it alone: it never read the ledger. */
  wyl_policy_store_t *policy = wyl_handle_get_policy_store (handle);
  wyl_policy_fact_graph_info_t info = { 0 };
  info.tenant_id = "tenant-a";
  info.graph_id = "orders";
  info.schema_version = 1;
  WylFactGraphRuntimeStatus rt = { 0 };
  g_assert_cmpint (wyl_handle_refresh_fact_graph (handle, &info, &rt), ==,
      WYRELOG_E_OK);
  wyl_fact_graph_runtime_status_clear (&rt);
  g_assert_cmpint (assert_single_graph_state (handle), ==,
      WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE);

  /* Repair the intent so the next full replay converges it -- the inverse of
   * the fixture's fault, so the two cannot drift apart. */
  {
    g_autofree gchar *sp = lookup_graph_storage_path (policy, "tenant-a",
            "orders");
    g_assert_nonnull (sp);
    g_autofree gchar *fp = g_build_filename (sp, "facts.duckdb", NULL);
    g_autoptr (wyl_fact_store_t) st = NULL;
    g_assert_cmpint (wyl_fact_store_open (fp, &st), ==, WYRELOG_E_OK);
    repair_forget_projection_table (wyl_fact_store_get_connection (st));
  }

  wyl_fact_replay_summary_t summary = { 0 };
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, &summary), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (summary.graphs_forget_reconcile_failed, ==, 0);
  /* Converged, and the verdict cleared itself. */
  g_assert_cmpint (assert_single_graph_state (handle), ==,
      WYL_FACT_GRAPH_STATE_READY);
  g_autofree gchar *json = wyl_daemon_fact_status_json (handle, TRUE);
  g_assert_nonnull (json);
  g_assert_nonnull (strstr (json, "\"status\":\"ready\""));
  g_assert_null (strstr (json, "forget_incomplete"));

  remove_tree (root);
}

/* Issue #870 precedence, in the only state where it bites: a graph that is
 * BOTH incomplete and degraded for a replay reason.
 *
 * The rule is that the forget axis is consulted only where replay health would
 * report ready.  Every other test leaves the axis converged on a degraded
 * graph, so removing the rule changes nothing in them -- verified by mutation:
 * consulting the axis unconditionally survives the rest of the suite.  This
 * fixture is what makes the rule falsifiable, by composing an unconverged
 * erasure with the duplicate-schema-version collision that fails the engine
 * build.
 *
 * Masking is the intended behaviour, not a compromise: the engine class is the
 * more actionable of the two, an operator cannot act on the erasure until the
 * graph replays at all, and the aggregate is degraded either way.  What must
 * not happen is the reverse -- a replay failure reported as a compliance
 * state. */
static void
test_replay_failure_outranks_an_outstanding_erasure (void)
{
  TEST ("a graph both degraded and incomplete reports the replay reason");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-status-mask-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    seed_unconverged_erasure (policy, "tenant-a", "orders");

    /* A second schema version of the same relation collides on the
     * version-independent wirelog name, so the engine build fails.  Same
     * shape as /fact-replay/dup-version-degrades, which exists to pin that. */
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema_v2 = make_schema
          ("tenant-a", "orders", columns, G_N_ELEMENTS (columns));
    schema_v2.schema_version = 2;
    schema_v2.relation_visible = FALSE;
    g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (policy,
        &schema_v2), ==, WYRELOG_E_OK);

    g_autofree gchar *sp = lookup_graph_storage_path (policy, "tenant-a",
            "orders");
    g_assert_nonnull (sp);
    g_autofree gchar *fp = g_build_filename (sp, "facts.duckdb", NULL);
    g_autoptr (wyl_fact_store_t) st = NULL;
    g_assert_cmpint (wyl_fact_store_open (fp, &st), ==, WYRELOG_E_OK);
    wyl_fact_value_t v2[] = {
      {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-c"},
      {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 33},
    };
    wyl_fact_row_t r2[] = { {v2, 2} };
    const wyl_fact_store_batch_t b2 = {
      .batch_id = "batch-v2",
      .tenant_id = "tenant-a",
      .graph_id = "orders",
      .namespace_id = "shop.ns",
      .relation_name = "orders-rel",
      .schema_version = 2,
      .source = "test",
      .idempotency_key = "key-v2",
      .op = WYL_FACT_STORE_OP_ASSERT,
      .rows = r2,
      .n_rows = G_N_ELEMENTS (r2),
    };
    gboolean ins = FALSE;
    g_assert_cmpint (wyl_fact_store_append_batch (st, &schema_v2, &b2, &ins),
        ==, WYRELOG_E_OK);
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  wyl_fact_replay_summary_t summary = { 0 };
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, &summary), ==,
      WYRELOG_E_OK);
  /* Both conditions really are present: the erasure did not converge AND the
   * engine did not build.  Without these the test could pass by producing
   * neither. */
  g_assert_cmpuint (summary.graphs_forget_reconcile_failed, ==, 1);
  g_assert_cmpuint (summary.graphs_degraded, ==, 1);
  g_assert_cmpuint (summary.graphs_loaded, ==, 0);

  /* The replay reason wins, and the compliance state does not surface. */
  g_assert_cmpint (assert_single_graph_state (handle), !=,
      WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE);
  g_autofree gchar *json = wyl_daemon_fact_status_json (handle, TRUE);
  g_assert_nonnull (json);
  g_assert_null (strstr (json, "forget_incomplete"));
  g_assert_nonnull (strstr (json, "\"status\":\"degraded\""));

  remove_tree (root);
}

/* Issue #870: the setter must be called AFTER the graph's refresh, and this
 * is the test that fails if it moves.
 *
 * A plan sentence is not a guarantee.  Writing the verdict next to the
 * reconcile that produces it is the natural placement and is wrong: the setter
 * never creates an entry and refuses a tombstone, so an early write is dropped
 * and the refresh then publishes CONVERGED over it -- this issue's own defect,
 * reintroduced by call placement alone.
 *
 * The tombstone is reached without any fixture work, because retire_unseen
 * runs at the tail of every replay: a graph deleted from policy is retired,
 * and re-creating it under the same identity reuses the same on-disk store
 * with its pending intent intact, since deleting the policy row never touches
 * the DuckDB file. */
static void
test_forget_state_survives_retire_and_recreate (void)
{
  TEST ("an erasure outstanding across retire and recreate is still reported");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-status-recreate-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    seed_unconverged_erasure (policy, "tenant-a", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (assert_single_graph_state (handle), ==,
      WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE);

  wyl_policy_store_t *policy = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (policy);
  g_assert_nonnull (db);

  /* Retire the graph: absent from policy, so the replay's tail sweep
   * tombstones its runtime entry. */
  g_assert_cmpint (sqlite3_exec (db,
      "DELETE FROM fact_relation_activation;"
      "DELETE FROM fact_relation_query_allowlist;"
      "DELETE FROM fact_relation_schema_columns;"
      "DELETE FROM fact_relation_schemas;"
      "DELETE FROM fact_namespaces;"
      "DELETE FROM fact_graph_query_allowlist;"
      "DELETE FROM fact_graph_relation_columns;"
      "DELETE FROM fact_graph_relations;"
      "DELETE FROM fact_graphs;", NULL, NULL, NULL), ==, SQLITE_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, &summary), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (summary.graphs_seen, ==, 0);

  /* Re-create under the same identity.  The store, and its pending intent,
   * were never touched. */
  create_graph_with_schema (policy, root, "tenant-a", "orders");
  memset (&summary, 0, sizeof summary);
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, &summary), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (summary.graphs_seen, ==, 1);
  g_assert_cmpuint (summary.graphs_forget_reconcile_failed, ==, 1);

  /* The verdict reached the surface across the tombstone.  Written before the
   * refresh it would have been refused, and the republish would report ready
   * on a graph still holding data it accepted an instruction to delete. */
  g_assert_cmpint (assert_single_graph_state (handle), ==,
      WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE);

  remove_tree (root);
}

/* Issue #870: a graph whose boot forget reconciliation did not converge must
 * not be reported ready.
 *
 * The fixture is a real unconverged erasure on an otherwise healthy ACTIVE
 * graph, not a synthesised runtime state: crash a forget at after_intent so
 * the intent is durable and no delete has run, then rewrite its tenant so the
 * reconciler's per-intent scope check skips it and returns POLICY with the
 * store open.  That is the ERROR class -- ledger read, intent not converged --
 * and it leaves the engine buildable, which is the combination the status
 * surface previously reported as ready.
 *
 * Every assertion about durable state comes first: if the seeding were wrong
 * and the reconcile actually converged, the still-PENDING and row-present
 * checks fail before any status assertion runs, so this cannot pass while
 * testing nothing. */
static void
test_status_is_not_ready_while_an_erasure_is_outstanding (void)
{
  TEST ("a graph with an unconverged erasure is not reported ready");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-status-erasure-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    seed_unconverged_erasure (policy, "tenant-a", "orders");
  }

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    /* Durable evidence the erasure really is outstanding, asserted before any
     * status claim depends on it. */
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
        ==, 1);
    g_assert_cmpint (count_in_graph_store (policy, "tenant-a", "orders",
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'batch-1';"),
        ==, 1);
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  FactStatusProbe probe = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.total, ==, 1);
  g_assert_cmpuint (probe.ready, ==, 0);

  g_autofree gchar *json = wyl_daemon_fact_status_json (handle, TRUE);
  g_assert_nonnull (json);
  /* The literal state name, not merely the tally: without its own case in
   * wyl_fact_graph_state_name an appended enum value renders as some other
   * string while every count assertion still passes. */
  g_assert_nonnull (strstr (json, "\"state\":\"forget_incomplete\""));
  g_assert_nonnull (strstr (json, "\"status\":\"degraded\""));
  g_assert_nonnull (strstr (json, "\"graphs_ready\":0"));
  g_assert_nonnull (strstr (json, "\"graphs_degraded\":1"));
  /* The graph still serves queries -- this is a health axis, not a barrier. */
  g_assert_nonnull (strstr (json, "\"queryable\":true"));
  /* Redaction is unchanged.  The last two are the ones a compliance state
   * would be tempted to carry -- the operator who requested the erasure and
   * the reason they gave -- and the fixture really does set both, so they can
   * fail.  `missing__` is the fixture's broken projection name; it has no
   * path to this JSON today, so treat it as a cheap tripwire rather than as
   * coverage. */
  g_assert_null (strstr (json, "facts.duckdb"));
  g_assert_null (strstr (json, "storage_path"));
  g_assert_null (strstr (json, root));
  g_assert_null (strstr (json, "admin"));
  g_assert_null (strstr (json, "gdpr-erasure"));
  g_assert_null (strstr (json, "batch-1"));
  g_assert_null (strstr (json, "missing__"));

  remove_tree (root);
}

static void
test_direct_replay_retracts_and_mangles (void)
{
  TEST ("direct replay loads net facts with mangled relation names");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-replay-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");
  append_order_batches (policy, root, "tenant-a", "orders");

  GraphPathProbe info_probe = { "tenant-a", "orders", NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (policy, "tenant-a",
      capture_graph_path_cb, &info_probe), ==, WYRELOG_E_OK);
  g_assert_nonnull (info_probe.storage_path);
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .storage_path = info_probe.storage_path,
    .schema_version = 1,
  };
  g_autoptr (WylEngine) engine = NULL;
  g_assert_cmpint (wyl_fact_replay_open_graph_engine (policy, root, &info,
      &engine), ==, WYRELOG_E_OK);
  assert_replayed_order_b_only (engine);
  g_free (info_probe.storage_path);
  g_clear_pointer (&engine, wyl_engine_close);
  g_clear_pointer (&policy, wyl_policy_store_close);
  remove_tree (root);
}

static void
test_direct_replay_shares_compounds_across_relations (void)
{
  TEST ("direct replay keeps compound handles graph scoped across relations");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-replay-compound-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_compound_graph_with_schemas (policy, root, "tenant-a", "shipments");
  append_compound_route_batches (policy, "tenant-a", "shipments");

  GraphPathProbe info_probe = { "tenant-a", "shipments", NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (policy, "tenant-a",
      capture_graph_path_cb, &info_probe), ==, WYRELOG_E_OK);
  g_assert_nonnull (info_probe.storage_path);
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .storage_path = info_probe.storage_path,
    .schema_version = 1,
  };
  g_autoptr (WylEngine) engine = NULL;
  g_assert_cmpint (wyl_fact_replay_open_graph_engine (policy, root, &info,
      &engine), ==, WYRELOG_E_OK);

  gint64 child_handle = snapshot_single_compound_handle (engine,
          "shipment-route");
  gint64 parent_handle = snapshot_single_compound_handle (engine,
          "shipment-audit");
  g_assert_cmpint (child_handle, >, 0);
  g_assert_cmpint (parent_handle, >, 0);
  g_free (info_probe.storage_path);
  g_clear_pointer (&engine, wyl_engine_close);
  g_clear_pointer (&policy, wyl_policy_store_close);
  remove_tree (root);
}

static gchar *
test_compound_cache_key (const gchar *namespace_id, gint64 compound_ref)
{
  return g_strdup_printf ("%s:%" G_GINT64_FORMAT, namespace_id, compound_ref);
}

static void
test_compound_replay_cache_reuses_nested_child (void)
{
  TEST ("compound replay cache reuses nested child handles");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-replay-cache-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *fact_path = g_build_filename (root, "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_compound_create_schema (store), ==, WYRELOG_E_OK);
  gint64 child_ref = 0;
  gint64 parent_ref = 0;
  put_route_compounds (store, "tenant-a", "shipments", &child_ref, &parent_ref);

  g_autoptr (WylEngine) engine = NULL;
  g_assert_cmpint (wyl_engine_open_source
        (".decl shipment(route: path/2 side)\n", 1, &engine), ==, WYRELOG_E_OK);
  g_autoptr (GHashTable) handles =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  gint64 parent_handle = 0;
  g_assert_cmpint (wyl_fact_compound_replay_cached (store, engine, "tenant-a",
      "shipments", "logistics", parent_ref, handles, &parent_handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (parent_handle, >, 0);
  g_autofree gchar *child_key = test_compound_cache_key ("logistics",
          child_ref);
  gint64 *nested_child_handle = g_hash_table_lookup (handles, child_key);
  g_assert_nonnull (nested_child_handle);
  g_assert_cmpint (*nested_child_handle, >, 0);

  gint64 direct_child_handle = 0;
  g_assert_cmpint (wyl_fact_compound_replay_cached (store, engine, "tenant-a",
      "shipments", "logistics", child_ref, handles, &direct_child_handle),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (direct_child_handle, ==, *nested_child_handle);
  g_clear_pointer (&engine, wyl_engine_close);
  g_clear_pointer (&store, wyl_fact_store_close);
  remove_tree (root);
}

static void
test_handle_replay_is_idempotent_and_graph_local (void)
{
  TEST ("handle replay replaces graph engines and isolates corrupt graphs");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-replay-handle-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);
  g_autofree gchar *bad_path = NULL;
  g_autofree gchar *good_path = NULL;

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    create_graph_with_schema (policy, root, "tenant-b", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");

    good_path = lookup_graph_storage_path (policy, "tenant-a", "orders");
    g_assert_nonnull (good_path);

    bad_path = lookup_graph_storage_path (policy, "tenant-b", "orders");
    g_assert_nonnull (bad_path);
    sqlite3 *policy_db = wyl_policy_store_get_db (policy);
    g_assert_nonnull (policy_db);
    g_assert_cmpint (sqlite3_exec (policy_db,
        "INSERT INTO fact_graphs "
        "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
        "owner_scope,sealed,created_at,updated_at) "
        "SELECT tenant_id,'invalid graph','fact://invalid',storage_path,"
        "schema_version,owner_scope,0,unixepoch(),unixepoch() "
        "FROM fact_graphs WHERE tenant_id='tenant-a' AND "
        "graph_id='orders';", NULL, NULL, NULL), ==, SQLITE_OK);
    g_autofree gchar *bad_fact_path = g_build_filename (bad_path,
            "facts.duckdb", NULL);
    g_assert_true (g_file_set_contents (bad_fact_path, "not a database", -1,
        NULL));
    g_assert_true (wyl_test_secure_regular_file (bad_fact_path, &error));
    g_assert_no_error (error);
  }
  tamper_graph_storage_path (policy_path, "tenant-a", "orders", bad_path);

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
  assert_handle_replayed_order_b_only (handle, "tenant-a", "orders");
  SnapshotProbe unavailable = { 0 };
  g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
      "tenant-b", "orders", "unused", handle_snapshot_cb,
      &unavailable), ==, WYRELOG_E_POLICY);
  assert_handle_fact_status (handle);

  g_autofree gchar *good_fact_path = g_build_filename (good_path,
          "facts.duckdb", NULL);
  g_assert_true (g_file_set_contents (good_fact_path, "not a database", -1,
      NULL));
  g_assert_true (wyl_test_secure_regular_file (good_fact_path, &error));
  g_assert_no_error (error);

  wyl_fact_replay_summary_t summary = { 0 };
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, &summary), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (summary.graphs_seen, ==, 3);
  g_assert_cmpuint (summary.graphs_loaded, ==, 0);
  g_assert_cmpuint (summary.graphs_degraded, ==, 3);
  /* #547: every graph here either fails key validation or fails to open, so
   * none of them reached a forget ledger and none can have failed to converge.
   * Asserting both halves is what makes the open-versus-reconcile split
   * falsifiable: inverting the branch moves the count to the wrong field, and
   * merging the two counters back breaks the first line. */
  g_assert_cmpuint (summary.graphs_forget_reconcile_failed, ==, 0);
  g_assert_cmpuint (summary.graphs_forget_probe_unavailable, ==, 2);
  /* #870: no graph here reports a forget state, and this is a weak guard by
   * construction -- say so rather than let it read as coverage.  Nothing is
   * written for an unprobed graph, so the axis stays at its CONVERGED zero
   * and no forget state can surface whatever the mapping does.  It therefore
   * does NOT pin the precedence rule -- removing that rule leaves this
   * passing, and /fact-replay/replay-failure-outranks-erasure is what
   * falsifies it -- and it does not pin the decision to write nothing for an
   * unprobed graph either, which flipping to INCOMPLETE leaves passing too.
   * No mutation found so far reaches it at all: every graph here is degraded,
   * so the only change that would surface a forget state is writing a verdict
   * for an unprobed graph AND removing the precedence rule together -- and
   * that combination aborts this test earlier, in assert_handle_fact_status,
   * because a graph that should read store_unavailable reads
   * forget_incomplete instead.
   *
   * So this is a tripwire, not coverage.  It is kept because it is the one
   * place in the suite that records which properties here are unpinned, and
   * because the claim above has been wrong three times: state what a check
   * catches only after trying to make it fail. */
  assert_no_graph_reports_forget_state (handle);
  assert_handle_replayed_order_b_only (handle, "tenant-a", "orders");
  assert_handle_stale_fact_status (handle);

  sqlite3 *policy_db = wyl_policy_store_get_db
        (wyl_handle_get_policy_store (handle));
  g_assert_nonnull (policy_db);
  g_assert_cmpint (sqlite3_exec (policy_db,
      "DELETE FROM fact_relation_activation;"
      "DELETE FROM fact_relation_query_allowlist;"
      "DELETE FROM fact_relation_schema_columns;"
      "DELETE FROM fact_relation_schemas;"
      "DELETE FROM fact_namespaces;"
      "DELETE FROM fact_graph_query_allowlist;"
      "DELETE FROM fact_graph_relation_columns;"
      "DELETE FROM fact_graph_relations;"
      "DELETE FROM fact_graphs;", NULL, NULL, NULL), ==, SQLITE_OK);
  memset (&summary, 0, sizeof summary);
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, &summary), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (summary.graphs_seen, ==, 0);
  g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
      "tenant-a", "orders", "unused", handle_snapshot_cb, &(SnapshotProbe) {
    0
  }
      ), ==, WYRELOG_E_NOT_FOUND);
  FactStatusProbe swept = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &swept), ==, WYRELOG_E_OK);
  g_assert_cmpuint (swept.total, ==, 0);
  g_clear_object (&handle);
  remove_tree (root);
}

static void
test_handle_replay_rejects_fact_root_replacement (void)
{
  TEST ("handle replay retains the startup fact-root identity");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *base = wyl_test_make_secure_fact_root
        ("wyl-fact-replay-pin-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *root = g_build_filename (base, "facts", NULL);
  g_autofree gchar *old_root = g_build_filename (base, "facts-old", NULL);
  g_autofree gchar *policy_path = g_build_filename (base, "policy.sqlite",
          NULL);
  g_assert_true (wyl_test_create_secure_directory (root, &error));
  g_assert_no_error (error);

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
#ifdef G_OS_WIN32
  g_assert_cmpint (g_rename (root, old_root), ==, -1);
  g_assert_true (g_file_test (root, G_FILE_TEST_IS_DIR));
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, NULL), ==,
      WYRELOG_E_OK);
#else
  g_assert_cmpint (g_rename (root, old_root), ==, 0);
  g_assert_true (wyl_test_create_secure_directory (root, &error));
  g_assert_no_error (error);

  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, NULL), ==,
      WYRELOG_E_POLICY);
  g_autoptr (GDir) replacement = g_dir_open (root, 0, &error);
  g_assert_no_error (error);
  g_assert_nonnull (replacement);
  g_assert_null (g_dir_read_name (replacement));
#endif

  g_clear_object (&handle);
  remove_tree (base);
}

static void
test_replay_dup_version_relation_degrades (void)
{
  TEST ("two schema versions of one relation collide to a duplicate .decl");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-replay-dupver-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");

    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema_v2 = make_schema (
      "tenant-a", "orders", columns, G_N_ELEMENTS (columns));
    schema_v2.schema_version = 2;
    schema_v2.relation_visible = FALSE;
    g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (policy,
        &schema_v2), ==, WYRELOG_E_OK);

    g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
            "tenant-a", "orders");
    g_assert_nonnull (storage_path);
    g_autofree gchar *fact_path = g_build_filename (storage_path,
            "facts.duckdb", NULL);
    g_autoptr (wyl_fact_store_t) store = NULL;
    g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);

    wyl_fact_value_t values[] = {
      {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-c"},
      {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 33},
    };
    wyl_fact_row_t rows[] = { {values, 2} };
    const wyl_fact_store_batch_t batch = {
      .batch_id = "batch-v2",
      .tenant_id = "tenant-a",
      .graph_id = "orders",
      .namespace_id = "shop.ns",
      .relation_name = "orders-rel",
      .schema_version = 2,
      .source = "test",
      .idempotency_key = "key-v2",
      .op = WYL_FACT_STORE_OP_ASSERT,
      .rows = rows,
      .n_rows = G_N_ELEMENTS (rows),
    };
    gboolean inserted = FALSE;
    g_assert_cmpint (wyl_fact_store_append_batch (store, &schema_v2, &batch,
        &inserted), ==, WYRELOG_E_OK);
    g_assert_true (inserted);
    g_clear_pointer (&store, wyl_fact_store_close);

    /* Pin exactly one active version (v1) in the activation registry, which is
     * the relation authority C2 enumerates from; without it C2 falls back to
     * the ambiguous fact_batches DISTINCT and the graph still degrades. */
    WylPolicyAuthorityMutationResult ar;
    g_assert_cmpint (wyl_policy_store_reserve_relation_activation (policy,
        "tenant-a", "orders", "shop.ns", "orders-rel", &ar), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_transition_relation_activation (policy,
        "tenant-a", "orders", "shop.ns", "orders-rel",
        WYL_POLICY_RELATION_ACTIVATION_UNBOUND, 0,
        WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, FALSE, 0, TRUE, 1,
        "none", &ar), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_transition_relation_activation (policy,
        "tenant-a", "orders", "shop.ns", "orders-rel",
        WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, 1,
        WYL_POLICY_RELATION_ACTIVATION_ACTIVE, TRUE, 1, FALSE, 0,
        "none", &ar), ==, WYRELOG_E_OK);
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  g_assert_cmpint (wyl_handle_replay_fact_graphs (handle, &summary), ==,
      WYRELOG_E_OK);
  /* Pre-fix, two enumerated versions of orders-rel emit a duplicate .decl for
   * the version-independent wirelog name, so wirelog rejects the program and
   * the graph degrades.  #545 C2 enumerates from the activation registry (one
   * active version per relation), so replay declares exactly one .decl and the
   * graph converges. */
  g_assert_cmpuint (summary.graphs_seen, ==, 1);
  g_assert_cmpuint (summary.graphs_degraded, ==, 0);
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);
  /* A graph that opens and converges touches neither forget counter. */
  g_assert_cmpuint (summary.graphs_forget_reconcile_failed, ==, 0);
  g_assert_cmpuint (summary.graphs_forget_probe_unavailable, ==, 0);

  g_clear_object (&handle);
  remove_tree (root);
}

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  wyl_policy_fact_graph_info_t info;
  gboolean found;
} FullGraphInfoProbe;

static wyrelog_error_t
capture_full_graph_info_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  FullGraphInfoProbe *probe = user_data;
  if (probe->found
      || g_strcmp0 (probe->tenant_id, info->tenant_id) != 0
      || g_strcmp0 (probe->graph_id, info->graph_id) != 0)
    return WYRELOG_E_OK;
  probe->info.tenant_id = g_strdup (info->tenant_id);
  probe->info.graph_id = g_strdup (info->graph_id);
  probe->info.storage_uri = g_strdup (info->storage_uri);
  probe->info.storage_path = g_strdup (info->storage_path);
  probe->info.owner_scope = g_strdup (info->owner_scope);
  probe->info.schema_version = info->schema_version;
  probe->info.sealed = info->sealed;
  probe->found = TRUE;
  return WYRELOG_E_OK;
}

static void
clear_full_graph_info (wyl_policy_fact_graph_info_t *info)
{
  g_free ((gchar *) info->tenant_id);
  g_free ((gchar *) info->graph_id);
  g_free ((gchar *) info->storage_uri);
  g_free ((gchar *) info->storage_path);
  g_free ((gchar *) info->owner_scope);
  memset (info, 0, sizeof (*info));
}

/* Capture one graph's (operation_generation, engine_generation) pair.  These
 * two counters are what acceptance criterion 1 is actually about, and
 * wyl_fact_graph_status_t does not carry them. */
typedef struct
{
  guint64 operation_generation;
  guint64 engine_generation;
  WylFactGraphRuntimeState state;
  gboolean queryable;
} GraphGenerations;

static GraphGenerations
capture_generations (WylHandle *handle, const gchar *tenant_id,
    const gchar *graph_id)
{
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_handle_get_fact_graph_runtime_status (handle, tenant_id,
      graph_id, &status), ==, WYRELOG_E_OK);
  GraphGenerations out = {
    .operation_generation = status.operation_generation,
    .engine_generation = status.engine_generation,
    .state = status.state,
    .queryable = status.queryable,
  };
  wyl_fact_graph_runtime_status_clear (&status);
  return out;
}

static void
assert_generations_unchanged (WylHandle *handle, const gchar *tenant_id,
    const gchar *graph_id, const GraphGenerations *before)
{
  GraphGenerations now = capture_generations (handle, tenant_id, graph_id);
  g_assert_cmpuint (now.operation_generation, ==, before->operation_generation);
  g_assert_cmpuint (now.engine_generation, ==, before->engine_generation);
  g_assert_cmpint (now.state, ==, before->state);
  g_assert_true (now.queryable);
}

/* Issue #546: a single-graph refresh converges only its own graph and never
 * disturbs a sibling -- neither a sibling in the SAME tenant nor one in a
 * different tenant.  Asserting READY counts alone is too weak: a sibling whose
 * engine was silently rebuilt would still report ready.  The acceptance
 * criterion is about generations, so this asserts the generations. */
static void
test_handle_refresh_fact_graph_is_isolated (void)
{
  TEST ("single-graph refresh leaves same-tenant and cross-tenant "
      "sibling generations untouched");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-refresh-iso-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    create_graph_with_schema (policy, root, "tenant-a", "inventory");
    create_graph_with_schema (policy, root, "tenant-b", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "inventory");
    append_order_batches (policy, root, "tenant-b", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  /* Startup replay makes all three graphs READY and queryable. */
  FactStatusProbe before = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &before), ==, WYRELOG_E_OK);
  g_assert_cmpuint (before.total, ==, 3);
  g_assert_cmpuint (before.ready, ==, 3);

  const GraphGenerations target_before = capture_generations (handle,
          "tenant-a", "orders");
  const GraphGenerations same_tenant_before = capture_generations (handle,
          "tenant-a", "inventory");
  const GraphGenerations other_tenant_before = capture_generations (handle,
          "tenant-b", "orders");

  /* Capture tenant-a/orders' full authority info, then refresh only it. */
  FullGraphInfoProbe target = { "tenant-a", "orders", { 0 }, FALSE };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph
        (wyl_handle_get_policy_store (handle), "tenant-a",
      capture_full_graph_info_cb, &target), ==, WYRELOG_E_OK);
  g_assert_true (target.found);

  WylFactGraphRuntimeStatus status;
  g_assert_cmpint (wyl_handle_refresh_fact_graph (handle, &target.info,
      &status), ==, WYRELOG_E_OK);
  g_assert_true (status.queryable);
  wyl_fact_graph_runtime_status_clear (&status);
  clear_full_graph_info (&target.info);

  /* The refreshed graph advanced exactly one operation and one engine
   * generation: the refresh was admitted once and published once. */
  const GraphGenerations target_after = capture_generations (handle,
          "tenant-a", "orders");
  g_assert_cmpuint (target_after.operation_generation, ==,
      target_before.operation_generation + 1);
  g_assert_cmpuint (target_after.engine_generation, ==,
      target_before.engine_generation + 1);
  g_assert_true (target_after.queryable);

  /* Neither sibling moved on either counter -- not the same-tenant one, and
   * not the cross-tenant one. */
  assert_generations_unchanged (handle, "tenant-a", "inventory",
      &same_tenant_before);
  assert_generations_unchanged (handle, "tenant-b", "orders",
      &other_tenant_before);

  /* A wrong retire_unseen on the one-element seen set would have swept the
   * siblings out of the runtime entirely. */
  FactStatusProbe after = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (after.total, ==, 3);
  g_assert_cmpuint (after.ready, ==, 3);

  g_clear_object (&handle);
  remove_tree (root);
}

/* Drive one mutation through the single internal entry point, exactly as the
 * daemon route does.  Returns the rc; |out_outcome| carries the class. */
static wyrelog_error_t
commit_one_mutation_op (WylHandle *handle, wyl_policy_store_t *policy,
    const gchar *tenant_id, const gchar *graph_id, const gchar *batch_id,
    const gchar *idempotency_key, wyl_fact_store_op_t op,
    const gchar *order_id, WylFactStoreBatchFault batch_fault,
    const wyl_policy_fact_relation_schema_options_t *schema_override,
    gboolean *out_inserted, wyl_fact_mutation_outcome_t *out_outcome)
{
  g_autofree gchar *storage_path = lookup_graph_storage_path (policy,
          tenant_id, graph_id);
  g_assert_nonnull (storage_path);
  g_autofree gchar *fact_path = g_build_filename (storage_path,
          "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  if (batch_fault != WYL_FACT_STORE_BATCH_FAULT_NONE)
    wyl_fact_store_set_batch_fault_once_for_test (store, batch_fault);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = schema_override != NULL
      ? *schema_override
      : make_schema (tenant_id, graph_id, columns, G_N_ELEMENTS (columns));
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = order_id},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 99},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
  };
  g_assert_cmpuint (schema.n_columns, <=, G_N_ELEMENTS (values));
  wyl_fact_row_t rows[] = { {values, schema.n_columns} };
  const wyl_fact_store_batch_t batch = {
    .batch_id = batch_id,
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = schema.schema_version,
    .source = "test",
    .idempotency_key = idempotency_key,
    .op = op,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };

  FullGraphInfoProbe target = { tenant_id, graph_id, { 0 }, FALSE };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (policy, tenant_id,
      capture_full_graph_info_cb, &target), ==, WYRELOG_E_OK);
  g_assert_true (target.found);

  wyrelog_error_t rc = wyl_handle_commit_fact_mutation (handle, &store,
          &schema, &batch, &target.info, out_inserted, out_outcome);
  /* The entry point consumes the store: it must be NULL now, and the
   * g_autoptr below must therefore be a no-op rather than a double close. */
  g_assert_null (store);
  clear_full_graph_info (&target.info);
  return rc;
}

static wyrelog_error_t
commit_one_mutation (WylHandle *handle, wyl_policy_store_t *policy,
    const gchar *tenant_id, const gchar *graph_id, const gchar *batch_id,
    const gchar *idempotency_key, gboolean *out_inserted,
    wyl_fact_mutation_outcome_t *out_outcome)
{
  return commit_one_mutation_op (handle, policy, tenant_id, graph_id, batch_id,
             idempotency_key, WYL_FACT_STORE_OP_ASSERT, "order-z",
             WYL_FACT_STORE_BATCH_FAULT_NONE, NULL, out_inserted,
             out_outcome);
}

/* Issue #546: the internal mutation entry point commits, then refreshes only
 * the graph it committed to.  This is the append/retract path the acceptance
 * criteria are actually written about -- the direct-refresh test above cannot
 * reach it. */
static void
test_handle_commit_fact_mutation_refreshes_only_its_graph (void)
{
  TEST ("committed mutation refreshes its own graph and no sibling");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-commit-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    create_graph_with_schema (policy, root, "tenant-a", "inventory");
    create_graph_with_schema (policy, root, "tenant-b", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "inventory");
    append_order_batches (policy, root, "tenant-b", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  const GraphGenerations target_before = capture_generations (handle,
          "tenant-a", "orders");
  const GraphGenerations same_tenant_before = capture_generations (handle,
          "tenant-a", "inventory");
  const GraphGenerations other_tenant_before = capture_generations (handle,
          "tenant-b", "orders");

  gboolean inserted = FALSE;
  wyl_fact_mutation_outcome_t outcome;
  wyl_fact_mutation_outcome_init (&outcome);
  g_assert_cmpint (commit_one_mutation (handle,
      wyl_handle_get_policy_store (handle), "tenant-a", "orders", "commit-1",
      "commit-key-1", &inserted, &outcome), ==, WYRELOG_E_OK);

  /* Committed AND refreshed. */
  g_assert_true (inserted);
  g_assert_cmpint (outcome.mutation_class, ==,
      WYL_FACT_MUTATION_COMMITTED_READY);
  g_assert_true (outcome.delta.inserted);
  g_assert_cmpint (outcome.delta.committed_row_delta, ==, 1);
  g_assert_true (outcome.engine_queryable);
  g_assert_false (outcome.needs_runtime_reconcile);

  const GraphGenerations target_after = capture_generations (handle,
          "tenant-a", "orders");
  g_assert_cmpuint (target_after.engine_generation, ==,
      target_before.engine_generation + 1);
  g_assert_cmpuint (target_after.operation_generation, ==,
      target_before.operation_generation + 1);
  /* The outcome reports the generation the refresh actually published. */
  g_assert_cmpuint (outcome.engine_generation, ==,
      target_after.engine_generation);

  /* Prove the ORDER, not merely that both steps happened: the published
   * engine must already contain the row this call committed.  Every
   * generation and outcome assertion above also passes against a
   * refresh-then-commit implementation; this one does not.  The fixture
   * leaves the observed relation with exactly order-b, so a correct
   * commit-then-refresh yields two rows and the wrong order yields one. */
  {
    g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
          ("shop.ns", "orders-rel");
    g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
    SnapshotProbe probe = { observed, 0, FALSE };
    g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
        "tenant-a", "orders", observed, handle_snapshot_cb, &probe), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (probe.count, ==, 2);
  }

  /* An append to one graph moves no other graph, in either tenant. */
  assert_generations_unchanged (handle, "tenant-a", "inventory",
      &same_tenant_before);
  assert_generations_unchanged (handle, "tenant-b", "orders",
      &other_tenant_before);

  g_clear_object (&handle);
  remove_tree (root);
}

/* Issue #546 concurrent isolation.
 *
 * What this proves and what it does NOT: the DuckDB commits genuinely run in
 * parallel -- each thread opens its own store on a different graph's file with
 * no shared lock -- and the status reads take no coordinator lock, holding the
 * per-entry state lock only for the copy and never across the engine build, so
 * a read completes while another graph is mid-refresh.  The REFRESHES,
 * however, serialize on the handle-global fact_replay_coordinator_lock, so
 * this is isolation under interleaving, not concurrent engine builds.  Do not
 * cite it as evidence of per-key refresh concurrency; that is what #548/#549
 * are meant to unlock.
 *
 * The invariant under test is an accounting property, and it holds under any
 * serialization: each graph's engine_generation advances by exactly its own
 * successful mutations and by no one else's. */
/* Deliberately ASYMMETRIC: with equal counts, a symmetric cross-attribution
 * (a's refresh bumping b's counter and vice versa) would produce exactly the
 * same totals and go undetected. */
#define MUTATION_ISOLATION_ROUNDS_A 8
#define MUTATION_ISOLATION_ROUNDS_B 6
/* Each assert is retracted by the following round, so an odd count would
 * leave one row behind and break the surviving-row assertion below. */
G_STATIC_ASSERT (MUTATION_ISOLATION_ROUNDS_A % 2 == 0);
G_STATIC_ASSERT (MUTATION_ISOLATION_ROUNDS_B % 2 == 0);

typedef struct
{
  WylHandle *handle;
  wyl_policy_store_t *policy;
  const gchar *tenant_id;
  const gchar *graph_id;
  guint rounds;
  guint successes;
  guint failures;
} MutationWorkerCtx;

static gpointer
mutation_isolation_worker (gpointer data)
{
  MutationWorkerCtx *ctx = data;
  for (guint i = 0; i < ctx->rounds; i++) {
    /* Alternate assert and retract so the retract arm of the entry point's
     * dispatch is exercised concurrently too, not just the assert arm. */
    gboolean retract = (i % 2) == 1;
    g_autofree gchar *order_id = g_strdup_printf ("order-%s-%s-%u",
            ctx->tenant_id, ctx->graph_id, retract ? i - 1 : i);
    g_autofree gchar *batch_id = g_strdup_printf ("iso-%s-%s-%u",
            ctx->tenant_id, ctx->graph_id, i);
    g_autofree gchar *key = g_strdup_printf ("iso-key-%s-%s-%u",
            ctx->tenant_id, ctx->graph_id, i);
    gboolean inserted = FALSE;
    wyl_fact_mutation_outcome_t outcome;
    wyl_fact_mutation_outcome_init (&outcome);
    wyrelog_error_t rc = commit_one_mutation_op (ctx->handle, ctx->policy,
            ctx->tenant_id, ctx->graph_id, batch_id, key,
            retract ? WYL_FACT_STORE_OP_RETRACT : WYL_FACT_STORE_OP_ASSERT,
            order_id, WYL_FACT_STORE_BATCH_FAULT_NONE, NULL, &inserted,
            &outcome);
    if (rc != WYRELOG_E_OK
        || outcome.mutation_class != WYL_FACT_MUTATION_COMMITTED_READY) {
      ctx->failures++;
      continue;
    }
    ctx->successes++;
  }
  return NULL;
}

typedef struct
{
  WylHandle *handle;
  GraphGenerations baseline;
  /* stop is cross-thread; failures and observations are written only here
   * and read only after the join, like the workers' counters. */
  gint stop;
  guint failures;
  guint observations;
} QuietObserverCtx;

/* Watch an UNMUTATED graph for the whole window.  A before/after snapshot
 * cannot tell a generation that never moved from one that moved and moved
 * back; this can, because wyl_handle_get_fact_graph_runtime_status takes no
 * coordinator lock and so can read while another graph refreshes. */
static gpointer
quiet_graph_observer (gpointer data)
{
  QuietObserverCtx *ctx = data;
  while (!g_atomic_int_get (&ctx->stop)) {
    WylFactGraphRuntimeStatus status = { 0 };
    if (wyl_handle_get_fact_graph_runtime_status (ctx->handle, "tenant-a",
        "inventory", &status) != WYRELOG_E_OK) {
      ctx->failures++;
      wyl_fact_graph_runtime_status_clear (&status);
      break;
    }
    if (status.engine_generation != ctx->baseline.engine_generation
        || status.operation_generation != ctx->baseline.operation_generation)
      ctx->failures++;
    wyl_fact_graph_runtime_status_clear (&status);
    ctx->observations++;
    g_usleep (200);
  }
  return NULL;
}

static void
test_mutation_isolation_is_concurrent (void)
{
  TEST ("concurrent mutations on two graphs never move a third graph's "
      "generations");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-iso-conc-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    create_graph_with_schema (policy, root, "tenant-a", "inventory");
    create_graph_with_schema (policy, root, "tenant-b", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "inventory");
    append_order_batches (policy, root, "tenant-b", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
  wyl_policy_store_t *policy = wyl_handle_get_policy_store (handle);

  const GraphGenerations a_before = capture_generations (handle, "tenant-a",
          "orders");
  const GraphGenerations b_before = capture_generations (handle, "tenant-b",
          "orders");
  const GraphGenerations quiet_before = capture_generations (handle,
          "tenant-a", "inventory");

  MutationWorkerCtx a = {
    .handle = handle,.policy = policy,.tenant_id = "tenant-a",
    .graph_id = "orders",.rounds = MUTATION_ISOLATION_ROUNDS_A,
  };
  MutationWorkerCtx b = {
    .handle = handle,.policy = policy,.tenant_id = "tenant-b",
    .graph_id = "orders",.rounds = MUTATION_ISOLATION_ROUNDS_B,
  };
  QuietObserverCtx observer = {
    .handle = handle,.baseline = quiet_before,
  };

  GThread *watcher = g_thread_new ("iso-observer", quiet_graph_observer,
          &observer);
  GThread *worker_a = g_thread_new ("iso-a", mutation_isolation_worker, &a);
  GThread *worker_b = g_thread_new ("iso-b", mutation_isolation_worker, &b);
  g_thread_join (worker_a);
  g_thread_join (worker_b);
  g_atomic_int_set (&observer.stop, 1);
  g_thread_join (watcher);

  g_assert_cmpuint (a.failures, ==, 0);
  g_assert_cmpuint (b.failures, ==, 0);
  g_assert_cmpuint (a.successes, ==, MUTATION_ISOLATION_ROUNDS_A);
  g_assert_cmpuint (b.successes, ==, MUTATION_ISOLATION_ROUNDS_B);

  /* Failures first: if the very first poll failed, the observer breaks with
   * zero observations, and asserting the count first would report a
   * misleading "observer never ran". */
  g_assert_cmpuint (observer.failures, ==, 0);
  g_assert_cmpuint (observer.observations, >, 0);

  /* Each mutated graph advanced by exactly its OWN successful mutations --
   * neither graph's refreshes were attributed to the other. */
  const GraphGenerations a_after = capture_generations (handle, "tenant-a",
          "orders");
  const GraphGenerations b_after = capture_generations (handle, "tenant-b",
          "orders");
  g_assert_cmpuint (a_after.engine_generation, ==,
      a_before.engine_generation + a.successes);
  g_assert_cmpuint (b_after.engine_generation, ==,
      b_before.engine_generation + b.successes);

  /* And the untouched graph is where it started, on both counters. */
  assert_generations_unchanged (handle, "tenant-a", "inventory",
      &quiet_before);

  /* Prove the retracts actually matched the rows they name.  A retract is a
   * tombstone append that succeeds even against a row that never existed, so
   * the alternating assert/retract pairing above would be decorative without
   * this: every asserted order-* row is retracted again, leaving only the
   * fixture's order-b in the observed relation. */
  assert_handle_replayed_order_b_only (handle, "tenant-a", "orders");
  assert_handle_replayed_order_b_only (handle, "tenant-b", "orders");

  g_clear_object (&handle);
  remove_tree (root);
}

/* Issue #546: a mutation that fails at its DuckDB commit is PRECOMMIT_FAILED --
 * nothing durable, and no graph's generations move, not even the target's.  A
 * refresh must not run for a commit that did not happen. */
static void
test_commit_fact_mutation_precommit_failure_is_isolated (void)
{
  TEST ("a failed commit leaves every graph's generations untouched");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-precommit-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    create_graph_with_schema (policy, root, "tenant-a", "inventory");
    append_order_batches (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "inventory");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  const GraphGenerations target_before = capture_generations (handle,
          "tenant-a", "orders");
  const GraphGenerations sibling_before = capture_generations (handle,
          "tenant-a", "inventory");

  /* Poison BOTH out-params.  wyl_fact_mutation_outcome_init leaves exactly
   * the PRECOMMIT_FAILED state, so asserting it straight after an init would
   * pass even against a callee that never wrote the struct. */
  gboolean inserted = TRUE;
  wyl_fact_mutation_outcome_t outcome = {
    .mutation_class = WYL_FACT_MUTATION_COMMITTED_READY,
    .delta = {.inserted = TRUE,.committed_row_delta = 99,
              .logical_byte_delta = 99},
    .degraded_class = WYL_FACT_GRAPH_REPLAY_FAILED,
    .engine_queryable = TRUE,
    .needs_runtime_reconcile = TRUE,
    .needs_durable_reconcile = TRUE,
    .engine_generation = 4242,
  };
  g_assert_cmpint (commit_one_mutation_op (handle,
      wyl_handle_get_policy_store (handle), "tenant-a", "orders",
      "precommit-1", "precommit-key-1", WYL_FACT_STORE_OP_ASSERT, "order-p",
      WYL_FACT_STORE_BATCH_FAULT_AT_COMMIT, NULL, &inserted, &outcome), !=,
      WYRELOG_E_OK);

  /* Every field of the documented PRECOMMIT_FAILED invariant. */
  g_assert_cmpint (outcome.mutation_class, ==,
      WYL_FACT_MUTATION_PRECOMMIT_FAILED);
  g_assert_false (inserted);
  g_assert_false (outcome.delta.inserted);
  g_assert_cmpint (outcome.delta.committed_row_delta, ==, 0);
  g_assert_cmpint (outcome.delta.logical_byte_delta, ==, 0);
  g_assert_cmpuint (outcome.engine_generation, ==, 0);
  g_assert_false (outcome.engine_queryable);
  g_assert_cmpint (outcome.degraded_class, ==, WYL_FACT_GRAPH_REPLAY_NONE);
  g_assert_false (outcome.needs_runtime_reconcile);
  g_assert_false (outcome.needs_durable_reconcile);

  /* No refresh ran: even the graph the mutation targeted is untouched on BOTH
   * counters, so a failed commit does not consume an operation. */
  assert_generations_unchanged (handle, "tenant-a", "orders", &target_before);
  assert_generations_unchanged (handle, "tenant-a", "inventory",
      &sibling_before);

  /* And the engine still shows only what was there before. */
  assert_handle_replayed_order_b_only (handle, "tenant-a", "orders");

  g_clear_object (&handle);
  remove_tree (root);
}

/* Count rows in a graph's observed relation. */
static guint
observed_row_count (WylHandle *handle, const gchar *tenant_id,
    const gchar *graph_id)
{
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  SnapshotProbe probe = { observed, 0, FALSE };
  g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle, tenant_id,
      graph_id, observed, handle_snapshot_cb, &probe), ==, WYRELOG_E_OK);
  return probe.count;
}

/* Issue #546, contract item 4: a retried idempotency key is a committed no-op
 * that STILL refreshes.  The engine_generation clause is the least intuitive
 * part of the contract and the easiest for a "skip the refresh on a no-op"
 * optimisation to break invisibly, so it is asserted explicitly. */
static void
test_commit_fact_mutation_idempotent_retry (void)
{
  TEST ("a retried idempotency key refreshes again without applying twice");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-retry-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
  wyl_policy_store_t *policy = wyl_handle_get_policy_store (handle);

  const GraphGenerations before = capture_generations (handle, "tenant-a",
          "orders");

  gboolean inserted = FALSE;
  wyl_fact_mutation_outcome_t outcome;
  wyl_fact_mutation_outcome_init (&outcome);
  g_assert_cmpint (commit_one_mutation (handle, policy, "tenant-a", "orders",
      "retry-1", "retry-key-1", &inserted, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  g_assert_cmpint (outcome.delta.committed_row_delta, ==, 1);
  const guint rows_after_first = observed_row_count (handle, "tenant-a",
          "orders");
  g_assert_cmpuint (rows_after_first, ==, 2);

  const GraphGenerations after_first = capture_generations (handle, "tenant-a",
          "orders");
  g_assert_cmpuint (after_first.engine_generation, ==,
      before.engine_generation + 1);

  /* Same batch_id and idempotency_key: a committed no-op. */
  gboolean retry_inserted = TRUE;
  wyl_fact_mutation_outcome_t retry;
  wyl_fact_mutation_outcome_init (&retry);
  g_assert_cmpint (commit_one_mutation (handle, policy, "tenant-a", "orders",
      "retry-1", "retry-key-1", &retry_inserted, &retry), ==, WYRELOG_E_OK);

  g_assert_false (retry_inserted);
  g_assert_false (retry.delta.inserted);
  g_assert_cmpint (retry.delta.committed_row_delta, ==, 0);
  g_assert_cmpint (retry.delta.logical_byte_delta, ==, 0);
  g_assert_cmpint (retry.mutation_class, ==,
      WYL_FACT_MUTATION_COMMITTED_READY);

  /* Contract item 4: the refresh STILL ran. */
  const GraphGenerations after_retry = capture_generations (handle, "tenant-a",
          "orders");
  g_assert_cmpuint (after_retry.engine_generation, ==,
      after_first.engine_generation + 1);
  g_assert_cmpuint (retry.engine_generation, ==,
      after_retry.engine_generation);

  /* The refreshed engine still serves exactly the pre-retry content.  This is
   * NOT a no-double-apply check: the observed relation is derived and has set
   * semantics, so re-applying an identical tuple would be invisible here.
   * The no-double-apply evidence is the store-layer delta above (inserted
   * FALSE, zero row delta), and the durable row-count version lives in
   * tests/test-daemon-http-facts.c. */
  g_assert_cmpuint (observed_row_count (handle, "tenant-a", "orders"), ==,
      rows_after_first);

  g_clear_object (&handle);
  remove_tree (root);
}

/* Issue #546: the COMMITTED_DEGRADED arm of the mutation entry point.
 *
 * Reaching it needs a commit that SUCCEEDS and a rebuild that FAILS, and
 * nothing can run between those two steps.  Corrupting the store cannot do it
 * -- the commit would fail first.  The lever is that the two steps consult
 * different sources of truth: the append validates only against the schema it
 * is handed, while the rebuild re-enumerates the relation from the store.
 *
 * This graph's relation is NOT in the activation registry -- neither
 * create_graph_with_schema nor register_fact_relation_schema populates
 * fact_relation_activation -- so list_replay_relations falls back to the
 * DISTINCT enumeration over fact_batches, which has no intra-loop dedup.  The
 * committed v2 batch makes that yield both v1 and v2 of orders-rel, and
 * build_graph_program emits a duplicate .decl for the version-independent
 * wirelog name.  See test_replay_dup_version_relation_degrades for the same
 * collision and for the activation registry that removes it: if graph
 * creation ever starts populating that registry, this arrangement stops
 * degrading and this test will FAIL with COMMITTED_READY.  The fix is a new
 * lever, not a relaxed assertion. */
/* A graph closed to admission but still holding a published engine.  It is
 * the state a seal leaves behind when its drain expires against a graph that
 * was already durably sealed: the compensation rule declines to reopen a
 * durably sealed graph, and the eviction never runs because the drain did not
 * finish.  Nothing clears it short of a restart, so it is the state an
 * operator is most likely to poll -- and the one the status surface has
 * described incorrectly. */
typedef struct
{
  WylHandle *handle;
  GMutex mutex;
  GCond changed;
  gboolean inside;
  gboolean release;
  wyrelog_error_t result;
} SealBarrierHold;

static void
seal_barrier_hold_cb (WylEngine *engine, const gchar *relation,
    const gint64 *row, guint ncols, gpointer user_data)
{
  SealBarrierHold *hold = user_data;
  (void) engine;
  (void) relation;
  (void) row;
  (void) ncols;
  /* The engine call is counted while this callback runs, and the drain waits
   * on exactly that counter.  Holding here is what makes the timeout
   * deterministic instead of a race. */
  g_mutex_lock (&hold->mutex);
  hold->inside = TRUE;
  g_cond_broadcast (&hold->changed);
  while (!hold->release)
    g_cond_wait (&hold->changed, &hold->mutex);
  g_mutex_unlock (&hold->mutex);
}

static gpointer
seal_barrier_holder (gpointer user_data)
{
  SealBarrierHold *hold = user_data;
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  hold->result = wyl_handle_snapshot_fact_graph_relation (hold->handle,
          "tenant-a", "orders", observed, seal_barrier_hold_cb, hold);
  return NULL;
}

typedef struct
{
  guint total;
  guint sealed;
  guint ready;
  gboolean sealed_is_queryable;
  gboolean saw_sealed_error_class;
} SealedStatusProbe;

static wyrelog_error_t
sealed_status_cb (const wyl_fact_graph_status_t *status, gpointer user_data)
{
  SealedStatusProbe *probe = user_data;
  probe->total++;
  if (status->state == WYL_FACT_GRAPH_STATE_READY)
    probe->ready++;
  if (g_strcmp0 (status->graph_id, "orders") == 0
      && g_strcmp0 (status->tenant_id, "tenant-a") == 0
      && status->state == WYL_FACT_GRAPH_STATE_SEALED) {
    probe->sealed++;
    probe->sealed_is_queryable = status->queryable;
    probe->saw_sealed_error_class = status->last_error_class != NULL;
  }
  return WYRELOG_E_OK;
}

static void
test_closed_graph_reports_sealed_not_ready (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-sealed-status-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  /* Durably seal behind the runtime's back, so the seal below takes the
   * already_sealed branch and declines to reopen when its drain expires.
   * Sealing through the handle instead would evict, which is the state this
   * test is NOT about. */
  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
        "orders"), ==, WYRELOG_E_OK);
  }

  SealBarrierHold hold = { handle, };
  g_mutex_init (&hold.mutex);
  g_cond_init (&hold.changed);
  hold.result = WYRELOG_E_INTERNAL;
  GThread *holder = g_thread_new ("seal-barrier-hold", seal_barrier_holder,
          &hold);
  g_mutex_lock (&hold.mutex);
  while (!hold.inside)
    g_cond_wait (&hold.changed, &hold.mutex);
  g_mutex_unlock (&hold.mutex);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    wyl_policy_fact_graph_info_t info = {
      .tenant_id = "tenant-a",
      .graph_id = "orders",
    };
    WylFactGraphSealOutcome outcome = { 0 };
    /* BUSY, because the held engine call outlives the drain. */
    g_assert_cmpint (wyl_handle_seal_fact_graph (handle, &info, 50 * 1000,
        &outcome), ==, WYRELOG_E_BUSY);
    g_assert_true (outcome.runtime_barrier_established);
    g_assert_false (outcome.engine_evicted);
    wyl_fact_graph_seal_outcome_clear (&outcome);
  }

  /* The state under test really is closed-and-published, not evicted: a query
   * is refused while the engine is still there.  Without this the assertions
   * below would pass just as well against a graph that never had an engine,
   * which is the vacuous version of this test. */
  {
    g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
          ("shop.ns", "orders-rel");
    g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
    SnapshotProbe probe = { observed, 0, FALSE };
    g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle,
        "tenant-a", "orders", observed, handle_snapshot_cb, &probe), ==,
        WYRELOG_E_BUSY);
  }

  SealedStatusProbe probe = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      sealed_status_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.total, ==, 1);
  g_assert_cmpuint (probe.sealed, ==, 1);
  g_assert_cmpuint (probe.ready, ==, 0);
  /* The barrier is what the surface must describe.  Reporting queryable here
   * would repeat the runbook's promise that a queryable graph serves queries,
   * against a graph that just refused one. */
  g_assert_false (probe.sealed_is_queryable);
  /* Sealed is a lifecycle state, not a failure: it must not surface as an
   * error class. */
  g_assert_false (probe.saw_sealed_error_class);

  g_autofree gchar *json = wyl_daemon_fact_status_json (handle, TRUE);
  g_assert_nonnull (json);
  g_assert_nonnull (strstr (json, "\"state\":\"sealed\""));
  /* The negative is the load-bearing half: a body carrying both would satisfy
   * the positive alone. */
  g_assert_null (strstr (json, "\"state\":\"ready\""));
  g_assert_null (strstr (json, "\"queryable\":true"));

  /* A seal is an operator's own decision, so it is neither a health problem
   * nor evidence of health.  Counting it as degraded would raise an alert for
   * an intended state; counting it as ready would hide a graph that answers
   * nothing.  It gets its own bucket and leaves the aggregate alone. */
  g_assert_nonnull (strstr (json, "\"graphs_total\":1"));
  g_assert_nonnull (strstr (json, "\"graphs_sealed\":1"));
  g_assert_nonnull (strstr (json, "\"graphs_ready\":0"));
  g_assert_nonnull (strstr (json, "\"graphs_degraded\":0"));
  g_assert_nonnull (strstr (json, "\"status\":\"ready\""));

  g_mutex_lock (&hold.mutex);
  hold.release = TRUE;
  g_cond_broadcast (&hold.changed);
  g_mutex_unlock (&hold.mutex);
  g_thread_join (holder);
  g_assert_cmpint (hold.result, ==, WYRELOG_E_OK);
  g_mutex_clear (&hold.mutex);
  g_cond_clear (&hold.changed);
  g_clear_object (&handle);

  /* The same verdict on the path production actually takes.  Nothing calls
   * the runtime seal sequencer yet; what closes admission in a shipped daemon
   * is the boot pass, reading the durable bit.  That graph gets no engine, so
   * it arrives here from the other direction -- state DEGRADED with admission
   * closed rather than READY with an engine published -- and must still
   * report sealed rather than a replay reason it never earned. */
  {
    g_autoptr (WylHandle) rebooted = NULL;
    g_assert_cmpint (wyl_handle_open_with_options (&opts, &rebooted), ==,
        WYRELOG_E_OK);
    SealedStatusProbe booted = { 0 };
    g_assert_cmpint (wyl_handle_foreach_fact_graph_status (rebooted,
        sealed_status_cb, &booted), ==, WYRELOG_E_OK);
    g_assert_cmpuint (booted.sealed, ==, 1);
    g_assert_cmpuint (booted.ready, ==, 0);
    g_assert_false (booted.saw_sealed_error_class);

    g_autofree gchar *booted_json = wyl_daemon_fact_status_json (rebooted,
            TRUE);
    g_assert_nonnull (booted_json);
    g_assert_nonnull (strstr (booted_json, "\"state\":\"sealed\""));
    /* The reason the runbook currently names for this graph, and the one it
     * must stop naming. */
    g_assert_null (strstr (booted_json, "schema_mismatch"));
    /* The buckets on the reachable path too, not only on the drain-expiry
     * fixture above: this is the graph an operator's aggregate actually
     * counts. */
    g_assert_nonnull (strstr (booted_json, "\"graphs_sealed\":1"));
    g_assert_nonnull (strstr (booted_json, "\"graphs_degraded\":0"));
  }
}

/* A successful seal evicts, and evict_closed detaches the engine without
 * reopening admission -- so a sealed-and-evicted entry is EVICTED *and*
 * CLOSED at once.  That is the only state where the EVICTED/ABANDONED early
 * return and the SEALED branch disagree, which makes it the state that pins
 * their order.  The sequencer has no production caller yet, but it is
 * callable here, and the ordering it settles is what an operator sees the
 * moment the seal route is wired to it. */
static void
test_evicted_and_closed_reports_evicted_not_sealed (void)
{
  TEST ("a graph both evicted and closed keeps the evicted verdict");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-evicted-closed-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  /* Nothing holds an engine call open, so the drain completes and the seal
   * evicts.  That is the whole difference between this fixture and the
   * closed-and-published one above, and it is what makes the two orderings
   * distinguishable. */
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_handle_seal_fact_graph (handle, &info, -1, &outcome),
      ==, WYRELOG_E_OK);
  /* The fixture really is both.  Without the eviction the assertion below
   * would hold for the ordinary sealed reason; without the closed admission
   * it would hold whatever the order is. */
  g_assert_true (outcome.engine_evicted);
  g_assert_cmpint (outcome.status.state, ==, WYL_FACT_GRAPH_RUNTIME_EVICTED);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_seal_outcome_clear (&outcome);

  /* EVICTED outranks CLOSED: a tombstone stays off the surface rather than
   * being reported sealed.  Moving the SEALED branch ahead of the
   * EVICTED/ABANDONED early return reports it sealed and fails here. */
  SealedStatusProbe probe = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      sealed_status_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.total, ==, 0);
  g_assert_cmpuint (probe.sealed, ==, 0);

  g_autofree gchar *json = wyl_daemon_fact_status_json (handle, TRUE);
  g_assert_nonnull (json);
  g_assert_nonnull (strstr (json, "\"graphs_total\":0"));
  g_assert_null (strstr (json, "\"state\":\"sealed\""));

  remove_tree (root);
}

/* The other half of the closed-graph surface: a mutation the barrier refuses.
 * The durable append lands, then the post-commit refresh is refused by
 * admission -- not by a replay failure -- and the two must not be rendered
 * alike.  Driven at the handle entry point, which is where the classification
 * lives; the HTTP route in front of it gates a durably sealed graph earlier,
 * so a test there would assert against a 409 and prove nothing about this. */
static void
test_mutation_refused_by_a_barrier_is_not_degraded (void)
{
  TEST ("a mutation the seal barrier refuses is not committed-degraded");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-barrier-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
      "orders"), ==, WYRELOG_E_OK);

  SealBarrierHold hold = { handle, };
  g_mutex_init (&hold.mutex);
  g_cond_init (&hold.changed);
  hold.result = WYRELOG_E_INTERNAL;
  GThread *holder = g_thread_new ("barrier-hold", seal_barrier_holder, &hold);
  g_mutex_lock (&hold.mutex);
  while (!hold.inside)
    g_cond_wait (&hold.changed, &hold.mutex);
  g_mutex_unlock (&hold.mutex);

  {
    wyl_policy_fact_graph_info_t info = {
      .tenant_id = "tenant-a",
      .graph_id = "orders",
    };
    WylFactGraphSealOutcome sealed = { 0 };
    g_assert_cmpint (wyl_handle_seal_fact_graph (handle, &info, 50 * 1000,
        &sealed), ==, WYRELOG_E_BUSY);
    g_assert_true (sealed.runtime_barrier_established);
    wyl_fact_graph_seal_outcome_clear (&sealed);
  }

  gboolean inserted = FALSE;
  wyl_fact_mutation_outcome_t outcome = { 0 };
  g_assert_cmpint (commit_one_mutation_op (handle, policy, "tenant-a",
      "orders", "batch-barrier", "key-barrier", WYL_FACT_STORE_OP_ASSERT,
      "order-c", WYL_FACT_STORE_BATCH_FAULT_NONE, NULL, &inserted, &outcome),
      ==, WYRELOG_E_OK);

  /* The append really committed.  Without this the assertions below cannot
   * tell a barrier refusal from a precommit failure, which also carries no
   * durable reconcile. */
  g_assert_true (inserted);
  g_assert_true (outcome.delta.inserted);
  g_assert_cmpint (outcome.delta.committed_row_delta, ==, 1);

  g_assert_cmpint (outcome.mutation_class, ==,
      WYL_FACT_MUTATION_COMMITTED_BARRIER);
  /* The engine lacks the batch, so a reconcile is genuinely owed -- but the
   * durable state is intact and asking an operator to repair it is wrong. */
  g_assert_true (outcome.needs_runtime_reconcile);
  g_assert_false (outcome.needs_durable_reconcile);
  /* No replay failed, so naming a degradation reason would invent one. */
  g_assert_cmpint (outcome.degraded_class, ==, WYL_FACT_GRAPH_REPLAY_NONE);

  g_mutex_lock (&hold.mutex);
  hold.release = TRUE;
  g_cond_broadcast (&hold.changed);
  g_mutex_unlock (&hold.mutex);
  g_thread_join (holder);
  g_mutex_clear (&hold.mutex);
  g_cond_clear (&hold.changed);
}

static void
test_commit_fact_mutation_reports_committed_degraded (void)
{
  TEST ("a commit whose rebuild fails is committed-but-degraded");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-degraded-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  const wyl_policy_fact_relation_schema_column_t v2_columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema_v2 = make_schema ("tenant-a",
          "orders", v2_columns, G_N_ELEMENTS (v2_columns));
  schema_v2.schema_version = 2;
  schema_v2.relation_visible = FALSE;

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    create_graph_with_schema (policy, root, "tenant-a", "inventory");
    append_order_batches (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "inventory");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);
  wyl_policy_store_t *policy = wyl_handle_get_policy_store (handle);

  const GraphGenerations before = capture_generations (handle, "tenant-a",
          "orders");
  const GraphGenerations sibling_before = capture_generations (handle,
          "tenant-a", "inventory");

  /* Poison the rebuild without touching the store file. */
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (policy,
      &schema_v2), ==, WYRELOG_E_OK);

  gboolean inserted = FALSE;
  wyl_fact_mutation_outcome_t outcome;
  wyl_fact_mutation_outcome_init (&outcome);
  g_assert_cmpint (commit_one_mutation_op (handle, policy, "tenant-a",
      "orders", "degraded-1", "degraded-key-1", WYL_FACT_STORE_OP_ASSERT,
      "order-d", WYL_FACT_STORE_BATCH_FAULT_NONE, &schema_v2, &inserted,
      &outcome), ==, WYRELOG_E_OK);

  /* Durable, and reported as such -- never as a commit failure. */
  g_assert_true (inserted);
  g_assert_cmpint (outcome.mutation_class, ==,
      WYL_FACT_MUTATION_COMMITTED_DEGRADED);
  g_assert_true (outcome.delta.inserted);
  g_assert_cmpint (outcome.delta.committed_row_delta, ==, 1);
  g_assert_true (outcome.needs_runtime_reconcile);
  g_assert_true (outcome.needs_durable_reconcile);
  /* The EXACT class, not merely non-NONE.  Without the registered v2 schema
   * the rebuild still fails, but for a different reason: the fallback still
   * enumerates version 2 from fact_batches, finds no schema columns for it,
   * and that WYRELOG_E_NOT_FOUND classifies as store_unavailable.  Asserting
   * only non-NONE would pass on that accident and stop testing the lever.
   * SCHEMA_MISMATCH is the mapping of WYRELOG_E_POLICY, so it narrows the
   * failure to this class rather than uniquely pinning the duplicate .decl. */
  g_assert_cmpint (outcome.degraded_class, ==,
      WYL_FACT_GRAPH_REPLAY_SCHEMA_MISMATCH);

  /* The prior complete generation stays queryable and is NOT superseded: a
   * failed build consumes an operation but publishes no engine. */
  const GraphGenerations after = capture_generations (handle, "tenant-a",
          "orders");
  g_assert_cmpuint (after.engine_generation, ==, before.engine_generation);
  /* Exactly one operation: the entry point refreshes once.  A loose '>' here
   * would pass a regression that refreshed twice. */
  g_assert_cmpuint (after.operation_generation, ==,
      before.operation_generation + 1);
  g_assert_true (outcome.engine_queryable);

  /* A degraded mutation still moves no other graph. */
  assert_generations_unchanged (handle, "tenant-a", "inventory",
      &sibling_before);

  g_clear_object (&handle);
  remove_tree (root);
}

/* Issue #546 required test: committed-but-degraded RECOVERY.  The degraded
 * case above stops at READY_STALE; this drives the whole transition, degraded
 * back to READY, and pins which counter moves on each leg.  Recovery is a
 * refresh-layer property, so it is driven at that layer; the degraded OUTCOME
 * mapping is proven through the mutation entry point separately. */
static void
test_handle_refresh_fact_graph_recovers_from_degraded (void)
{
  TEST ("a degraded graph returns to READY once its store is sound again");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-recover-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);
  g_autofree gchar *storage_path = NULL;

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    storage_path = lookup_graph_storage_path (policy, "tenant-a", "orders");
    g_assert_nonnull (storage_path);
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  const GraphGenerations sound = capture_generations (handle, "tenant-a",
          "orders");
  g_assert_cmpint (sound.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);

  FullGraphInfoProbe target = { "tenant-a", "orders", { 0 }, FALSE };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph
        (wyl_handle_get_policy_store (handle), "tenant-a",
      capture_full_graph_info_cb, &target), ==, WYRELOG_E_OK);
  g_assert_true (target.found);

  /* Set the store aside, then break it. */
  g_autofree gchar *fact_path = g_build_filename (storage_path, "facts.duckdb",
          NULL);
  g_autofree gchar *saved = NULL;
  gsize saved_len = 0;
  g_assert_true (g_file_get_contents (fact_path, &saved, &saved_len, NULL));
  g_assert_true (g_file_set_contents (fact_path, "not a database", -1, NULL));
  g_assert_true (wyl_test_secure_regular_file (fact_path, &error));
  g_assert_no_error (error);

  WylFactGraphRuntimeStatus degraded = { 0 };
  g_assert_cmpint (wyl_handle_refresh_fact_graph (handle, &target.info,
      &degraded), !=, WYRELOG_E_OK);
  g_assert_cmpint (degraded.state, ==, WYL_FACT_GRAPH_RUNTIME_READY_STALE);
  g_assert_true (degraded.queryable);
  wyl_fact_graph_runtime_status_clear (&degraded);

  /* The failed build consumed an operation but published no engine, so the
   * prior generation is still the one being served. */
  const GraphGenerations stale = capture_generations (handle, "tenant-a",
          "orders");
  g_assert_cmpuint (stale.engine_generation, ==, sound.engine_generation);
  g_assert_cmpuint (stale.operation_generation, ==,
      sound.operation_generation + 1);
  g_assert_true (stale.queryable);
  assert_handle_replayed_order_b_only (handle, "tenant-a", "orders");

  /* Put the store back and reconcile. */
  g_assert_true (g_file_set_contents (fact_path, saved, (gssize) saved_len,
      NULL));
  g_assert_true (wyl_test_secure_regular_file (fact_path, &error));
  g_assert_no_error (error);

  WylFactGraphRuntimeStatus recovered = { 0 };
  g_assert_cmpint (wyl_handle_refresh_fact_graph (handle, &target.info,
      &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovered.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_true (recovered.queryable);
  g_assert_cmpint (recovered.last_replay_class, ==,
      WYL_FACT_GRAPH_REPLAY_NONE);
  wyl_fact_graph_runtime_status_clear (&recovered);
  clear_full_graph_info (&target.info);

  /* Only the successful build published: exactly one engine generation over
   * the pre-corruption value, despite two refresh attempts. */
  const GraphGenerations back = capture_generations (handle, "tenant-a",
          "orders");
  g_assert_cmpint (back.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_cmpuint (back.engine_generation, ==, sound.engine_generation + 1);
  assert_handle_replayed_order_b_only (handle, "tenant-a", "orders");

  g_clear_object (&handle);
  remove_tree (root);
}

/* Issue #546: when the post-commit engine rebuild fails, the single-graph
 * refresh reports failure while the prior complete generation stays queryable
 * (READY_STALE) -- the daemon maps this to a committed-but-degraded 200. */
static void
test_handle_refresh_fact_graph_reports_degraded (void)
{
  TEST ("single-graph refresh degrades to READY_STALE on a failed rebuild");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-refresh-deg-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);
  g_autofree gchar *storage_path = NULL;

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
    storage_path = lookup_graph_storage_path (policy, "tenant-a", "orders");
    g_assert_nonnull (storage_path);
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  /* Startup replay makes the graph READY with a complete engine. */
  FactStatusProbe before = { 0 };
  g_assert_cmpint (wyl_handle_foreach_fact_graph_status (handle,
      fact_status_cb, &before), ==, WYRELOG_E_OK);
  g_assert_cmpuint (before.ready, ==, 1);

  /* Capture the graph's authority info, then corrupt its fact store so the
   * next engine rebuild fails after the already-committed data. */
  FullGraphInfoProbe target = { "tenant-a", "orders", { 0 }, FALSE };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph
        (wyl_handle_get_policy_store (handle), "tenant-a",
      capture_full_graph_info_cb, &target), ==, WYRELOG_E_OK);
  g_assert_true (target.found);

  g_autofree gchar *fact_path = g_build_filename (storage_path, "facts.duckdb",
          NULL);
  g_assert_true (g_file_set_contents (fact_path, "not a database", -1, NULL));
  g_assert_true (wyl_test_secure_regular_file (fact_path, &error));
  g_assert_no_error (error);

  WylFactGraphRuntimeStatus status;
  wyrelog_error_t rc = wyl_handle_refresh_fact_graph (handle, &target.info,
          &status);
  g_assert_cmpint (rc, !=, WYRELOG_E_OK);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY_STALE);
  g_assert_true (status.queryable);
  wyl_fact_graph_runtime_status_clear (&status);
  clear_full_graph_info (&target.info);

  g_clear_object (&handle);
  remove_tree (root);
}

typedef struct
{
  WylHandle *handle;
  const wyl_policy_fact_graph_info_t *info;
  const gchar *observed;
  guint iterations;
  volatile gint failures;
} RefreshRaceCtx;

static gpointer
refresh_race_writer (gpointer data)
{
  RefreshRaceCtx *ctx = data;
  for (guint i = 0; i < ctx->iterations; i++) {
    WylFactGraphRuntimeStatus status;
    wyrelog_error_t rc = wyl_handle_refresh_fact_graph (ctx->handle, ctx->info,
            &status);
    if (rc != WYRELOG_E_OK)
      g_atomic_int_inc (&ctx->failures);
    wyl_fact_graph_runtime_status_clear (&status);
  }
  return NULL;
}

static gpointer
refresh_race_reader (gpointer data)
{
  RefreshRaceCtx *ctx = data;
  for (guint i = 0; i < ctx->iterations; i++) {
    SnapshotProbe probe = { ctx->observed, 0, FALSE };
    wyrelog_error_t rc = wyl_handle_snapshot_fact_graph_relation (ctx->handle,
            "tenant-a", "orders", ctx->observed, handle_snapshot_cb, &probe);
    /* A concurrent reader must always observe a COMPLETE generation: the row
     * is already durable and every refresh rebuilds the same single row, so a
     * failed snapshot or a torn read (count != 1) would be a race. */
    if (rc != WYRELOG_E_OK || probe.count != 1)
      g_atomic_int_inc (&ctx->failures);
  }
  return NULL;
}

/* Issue #546: concurrent single-graph refreshes and queries on the same graph
 * stay race-free -- readers never see a partial generation.  Run under the
 * sanitizer builds this also exercises the runtime manager's generation swap
 * for data races. */
static void
test_handle_refresh_fact_graph_races_with_queries (void)
{
  TEST ("concurrent single-graph refresh and query stay race-free");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-refresh-race-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "orders");
    append_order_batches (policy, root, "tenant-a", "orders");
  }

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions opts = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&opts, &handle), ==,
      WYRELOG_E_OK);

  FullGraphInfoProbe target = { "tenant-a", "orders", { 0 }, FALSE };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph
        (wyl_handle_get_policy_store (handle), "tenant-a",
      capture_full_graph_info_cb, &target), ==, WYRELOG_E_OK);
  g_assert_true (target.found);

  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);

  RefreshRaceCtx ctx = { handle, &target.info, observed, 150, 0 };
  GThread *writer = g_thread_new ("refresh-writer", refresh_race_writer, &ctx);
  GThread *reader_a = g_thread_new ("refresh-reader-a", refresh_race_reader,
          &ctx);
  GThread *reader_b = g_thread_new ("refresh-reader-b", refresh_race_reader,
          &ctx);
  g_thread_join (writer);
  g_thread_join (reader_a);
  g_thread_join (reader_b);
  g_assert_cmpint (g_atomic_int_get (&ctx.failures), ==, 0);

  clear_full_graph_info (&target.info);
  g_clear_object (&handle);
  remove_tree (root);
}

/* A daemon configured without a fact root never probes for pending forgets at
 * all, which is not the same as a probe that was refused.  This pins that such
 * a boot reports no probe/build disagreement.
 *
 * Read what this does and does not establish.  It passes with the
 * forget_attempted guard removed, and it also passes with the ENTIRE tripwire
 * block deleted -- the counter is then permanently zero and both assertions
 * below hold in either configuration.  So this pins no part of the tripwire:
 * it cannot tell "present and correctly silent" from "absent".  With no fact
 * root the engine build fails for the same missing root, so graph_rc is never
 * OK and the tripwire cannot fire either way (measured: seen=1 loaded=0
 * degraded=1).  This is a characterization of the observable outcome, nothing
 * more.
 *
 * The tripwire itself cannot be driven from a test in either configuration:
 * off-bridge the two opens are the same call and would have to fail and then
 * succeed within one loop iteration, and under the bridge disagreeing also
 * means losing a LOCK_SH|LOCK_NB race on demand.  Note that off-bridge is
 * hard to drive, not impossible in production -- a transient EMFILE between
 * the two opens produces it.
 *
 * That is why it is counted rather than only logged -- the
 * belief that it never happens is then falsifiable in the field, which is the
 * evidence #550 would need to add a third forget state. */
static void
test_no_fact_root_is_not_a_probe_disagreement (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-replay-nofactroot-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);

  /* The control: the graph really is seen, so a zero below is the guard
   * holding and not an empty run. */
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, "", manager, &summary);
  g_assert_cmpuint (summary.graphs_seen, >, 0);
  g_assert_cmpuint (summary.graphs_forget_probe_disagreed, ==, 0);

  /* NULL is the other spelling of "no fact root" and must behave the same. */
  wyl_fact_replay_summary_t null_summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, NULL, manager, &null_summary);
  g_assert_cmpuint (null_summary.graphs_seen, >, 0);
  g_assert_cmpuint (null_summary.graphs_forget_probe_disagreed, ==, 0);

  remove_tree (root);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-replay/boot-converges-interrupted-forget",
      test_boot_converges_interrupted_forget);
  g_test_add_func ("/fact-replay/boot-forget-per-graph-never-aborts",
      test_boot_forget_is_per_graph_and_never_aborts);
  g_test_add_func ("/fact-replay/forget-state-clears-on-convergence",
      test_forget_state_clears_on_convergence_but_not_on_refresh);
  g_test_add_func ("/fact-replay/replay-failure-outranks-erasure",
      test_replay_failure_outranks_an_outstanding_erasure);
  g_test_add_func ("/fact-replay/forget-state-survives-retire-recreate",
      test_forget_state_survives_retire_and_recreate);
  g_test_add_func ("/fact-replay/status-not-ready-while-erasure-outstanding",
      test_status_is_not_ready_while_an_erasure_is_outstanding);
  g_test_add_func ("/fact-replay/boot-converges-forget-on-sealed-graph",
      test_boot_converges_forget_on_sealed_graph);
  g_test_add_func
    ("/fact-replay/boot-converges-forget-on-sealed-provisioned-graph",
      test_boot_converges_forget_on_sealed_provisioned_graph);
  g_test_add_func ("/fact-replay/no-fact-root-is-not-a-probe-disagreement",
      test_no_fact_root_is_not_a_probe_disagreement);
  g_test_add_func ("/fact-replay/direct",
      test_direct_replay_retracts_and_mangles);
  g_test_add_func ("/fact-replay/compound-shared",
      test_direct_replay_shares_compounds_across_relations);
  g_test_add_func ("/fact-replay/compound-cache-nested",
      test_compound_replay_cache_reuses_nested_child);
  g_test_add_func ("/fact-replay/handle",
      test_handle_replay_is_idempotent_and_graph_local);
  g_test_add_func ("/fact-replay/handle-root-replacement",
      test_handle_replay_rejects_fact_root_replacement);
  g_test_add_func ("/fact-replay/dup-version-degrades",
      test_replay_dup_version_relation_degrades);
  g_test_add_func ("/fact-replay/single-graph-refresh-isolated",
      test_handle_refresh_fact_graph_is_isolated);
  g_test_add_func ("/fact-replay/mutation-commits-and-refreshes",
      test_handle_commit_fact_mutation_refreshes_only_its_graph);
  g_test_add_func ("/fact-replay/mutation-isolation-concurrent",
      test_mutation_isolation_is_concurrent);
  g_test_add_func ("/fact-replay/mutation-precommit-failed-is-isolated",
      test_commit_fact_mutation_precommit_failure_is_isolated);
  g_test_add_func ("/fact-replay/mutation-idempotent-retry",
      test_commit_fact_mutation_idempotent_retry);
  g_test_add_func ("/fact-replay/mutation-committed-degraded",
      test_commit_fact_mutation_reports_committed_degraded);
  g_test_add_func ("/fact-replay/refresh-recovers-from-degraded",
      test_handle_refresh_fact_graph_recovers_from_degraded);
  g_test_add_func ("/fact-replay/single-graph-refresh-degrades",
      test_handle_refresh_fact_graph_reports_degraded);
  g_test_add_func ("/fact-replay/single-graph-refresh-race",
      test_handle_refresh_fact_graph_races_with_queries);
  g_test_add_func ("/fact-replay/closed-graph-reports-sealed",
      test_closed_graph_reports_sealed_not_ready);
  g_test_add_func ("/fact-replay/barrier-refusal-is-not-degraded",
      test_mutation_refused_by_a_barrier_is_not_degraded);
  g_test_add_func ("/fact-replay/evicted-closed-outranks-sealed",
      test_evicted_and_closed_reports_evicted_not_sealed);
  return g_test_run ();
}

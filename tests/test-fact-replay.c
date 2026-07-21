/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "fact-test-support.h"
#include "wyrelog/daemon/fact-status.h"
#include "wyrelog/fact/compound-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

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
  gboolean saw_tenant_a_ready;
  gboolean saw_tenant_a_stale;
  gboolean saw_tenant_b_unavailable;
} FactStatusProbe;

static wyrelog_error_t
fact_status_cb (const wyl_fact_graph_status_t *status, gpointer user_data)
{
  FactStatusProbe *probe = user_data;
  probe->total++;
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
  assert_handle_replayed_order_b_only (handle, "tenant-a", "orders");
  assert_handle_stale_fact_status (handle);

  sqlite3 *policy_db = wyl_policy_store_get_db
      (wyl_handle_get_policy_store (handle));
  g_assert_nonnull (policy_db);
  g_assert_cmpint (sqlite3_exec (policy_db,
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
          0}
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

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
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
  return g_test_run ();
}

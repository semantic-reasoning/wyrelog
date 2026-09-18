/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>
#include <glib/gstdio.h>

#include "fact-test-support.h"
#include "wyrelog/fact/schema-private.h"
#include "wyrelog/policy/store-private.h"

static void
cleanup_fact_root (const gchar *root)
{
  if (root == NULL)
    return;
  g_autoptr (GDir) directory = g_dir_open (root, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (root, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        cleanup_fact_root (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (root);
}

static wyrelog_error_t
open_store_with_graph (wyl_policy_store_t **out_store, gchar **out_root)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-schema-XXXXXX", &error);
  if (root == NULL)
    return WYRELOG_E_IO;

  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  wyrelog_error_t rc = wyl_policy_store_open (NULL, &store);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_create_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_create_tenant (store, "tenant-a", &created);
  if (rc != WYRELOG_E_OK)
    return rc;

  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"subject", "symbol"},
    {"object", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"site.edge", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = "tenant-a",
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  rc = wyl_policy_store_create_fact_graph (store, &graph_opts, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_store = g_steal_pointer (&store);
  *out_root = g_steal_pointer (&root);
  return WYRELOG_E_OK;
}

static wyl_policy_fact_relation_schema_options_t
make_order_schema (const wyl_policy_fact_relation_schema_column_t *columns,
    gsize n_columns,
    const wyl_policy_fact_relation_schema_query_t *queries, gsize n_queries)
{
  wyl_policy_fact_relation_schema_options_t opts = {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = n_columns,
    .queries = queries,
    .n_queries = n_queries,
  };
  return opts;
}

static gint
check_relation_schema_registration_and_validation (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  wyrelog_error_t rc = open_store_with_graph (&store, &root);
  if (rc != WYRELOG_E_OK)
    return 10;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"customer_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"status", "symbol", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_query_t queries[] = {
    {"orders_by_status", "wr.fact.read", 1000},
  };
  wyl_policy_fact_relation_schema_options_t opts = make_order_schema (columns,
          G_N_ELEMENTS (columns), queries, G_N_ELEMENTS (queries));
  gboolean schema_exists = TRUE;
  if (wyl_policy_store_fact_relation_schema_exists (store, "tenant-a",
      "graph-main", "shop", "orders", 0, &schema_exists) != WYRELOG_E_OK
      || schema_exists)
    return 101;
  if (wyl_policy_store_register_fact_relation_schema (store, &opts)
      != WYRELOG_E_OK)
    return 11;
  if (wyl_policy_store_fact_relation_schema_exists (store, "tenant-a",
      "graph-main", "shop", "orders", 0, &schema_exists) != WYRELOG_E_OK
      || !schema_exists)
    return 102;
  if (wyl_policy_store_fact_relation_schema_exists (store, "tenant-a",
      "graph-main", "shop", "orders", 1, &schema_exists) != WYRELOG_E_OK
      || !schema_exists)
    return 103;

  WylPolicyFactQuotaConfig schema_quota = {
    .has_limit = TRUE,
    .hard_limit = 2,
  };
  if (wyl_policy_store_set_fact_quota_config (store, "tenant-a",
      WYL_POLICY_FACT_QUOTA_SCHEMA_COUNT, &schema_quota) != WYRELOG_E_OK)
    return 104;
  WylPolicyFactSchemaQuotaStatus schema_status = { 0 };
  if (wyl_policy_store_get_fact_schema_quota_status (store, "tenant-a",
      &schema_status) != WYRELOG_E_OK || !schema_status.has_limit
      || schema_status.registered != 1)
    return 105;
  if (wyl_policy_store_fact_relation_schema_exists (store, "tenant-a",
      "graph-main", "shop", "orders", 2, &schema_exists) != WYRELOG_E_OK
      || schema_exists)
    return 106;
  /* Internal callers retain versioned metadata for the staged activation
   * workflow. The public HTTP route imposes the one-registration policy. */
  wyl_policy_fact_relation_schema_options_t staged_opts = opts;
  staged_opts.schema_version = 2;
  staged_opts.relation_visible = FALSE;
  staged_opts.queries = NULL;
  staged_opts.n_queries = 0;
  if (wyl_policy_store_register_fact_relation_schema (store, &staged_opts)
      != WYRELOG_E_OK)
    return 105;
  if (wyl_policy_store_fact_relation_schema_exists (store, "tenant-a",
      "graph-main", "shop", "orders", 2, &schema_exists) != WYRELOG_E_OK
      || !schema_exists)
    return 106;
  wyrelog_error_t schema_status_rc =
      wyl_policy_store_get_fact_schema_quota_status (store, "tenant-a",
          &schema_status);
  if (schema_status_rc != WYRELOG_E_OK || schema_status.registered != 2)
    return 107;

  wyl_policy_fact_relation_schema_options_t over_limit_opts = staged_opts;
  over_limit_opts.schema_version = 3;
  gboolean quota_exceeded = FALSE;
  if (wyl_policy_store_register_fact_relation_schema_with_quota_result (store,
      &over_limit_opts, &quota_exceeded) != WYRELOG_E_POLICY
      || !quota_exceeded
      || wyl_policy_store_fact_relation_schema_exists (store, "tenant-a",
      "graph-main", "shop", "orders", 3, &schema_exists) != WYRELOG_E_OK
      || schema_exists)
    return 108;
  schema_quota.hard_limit = 10;
  if (wyl_policy_store_set_fact_quota_config (store, "tenant-a",
      WYL_POLICY_FACT_QUOTA_SCHEMA_COUNT, &schema_quota) != WYRELOG_E_OK)
    return 109;

  /* A query-name uniqueness collision is an expected conflict, and the
   * registration transaction must leave no schema metadata behind. */
  const wyl_policy_fact_relation_schema_query_t collision_query[] = {
    {"orders_by_status", "wr.fact.read", 1000},
  };
  wyl_policy_fact_relation_schema_options_t collision_opts =
      make_order_schema (columns, G_N_ELEMENTS (columns), collision_query,
          G_N_ELEMENTS (collision_query));
  collision_opts.namespace_id = "other";
  collision_opts.relation_name = "different_orders";
  wyrelog_error_t collision_rc =
      wyl_policy_store_register_fact_relation_schema (store, &collision_opts);
  if (collision_rc != WYRELOG_E_CONFLICT)
    return 107;
  if (wyl_policy_store_fact_relation_schema_exists (store, "tenant-a",
      "graph-main", "other", "different_orders", 1, &schema_exists)
      != WYRELOG_E_OK || schema_exists)
    return 108;

  const wyl_policy_fact_relation_schema_column_t nullable_columns[] = {
    {"value", "int64", TRUE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t nullable_opts = make_order_schema
        (nullable_columns, G_N_ELEMENTS (nullable_columns), NULL, 0);
  nullable_opts.relation_name = "nullable_values";
  if (wyl_policy_store_register_fact_relation_schema (store, &nullable_opts)
      != WYRELOG_E_OK)
    return 111;

  gboolean relation_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *loaded = NULL;
  gsize n_loaded = 0;
  if (wyl_policy_store_load_fact_relation_schema_columns (store, "tenant-a",
      "graph-main", "shop", "orders", 1, &relation_visible, &loaded,
      &n_loaded) != WYRELOG_E_OK)
    return 12;
  if (!relation_visible || n_loaded != G_N_ELEMENTS (columns)
      || g_strcmp0 (loaded[2].column_name, "amount") != 0
      || g_strcmp0 (loaded[2].column_type, "int64") != 0
      || loaded[2].nullable || !loaded[2].visible) {
    wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);
    return 13;
  }
  wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);

  const wyl_fact_value_t good_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "c-1"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 42},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "open"},
  };
  const wyl_fact_row_t good_rows[] = {
    {good_values, G_N_ELEMENTS (good_values)},
  };
  const wyl_fact_batch_t good_batch = {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 1,
    .rows = good_rows,
    .n_rows = G_N_ELEMENTS (good_rows),
  };
  g_autofree gchar *reason = NULL;
  if (wyl_fact_schema_validate_batch (store, &good_batch, &reason)
      != WYRELOG_E_OK || reason != NULL)
    return 14;

  const wyl_fact_value_t short_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
  };
  const wyl_fact_row_t short_rows[] = {
    {short_values, G_N_ELEMENTS (short_values)},
  };
  wyl_fact_batch_t bad_batch = good_batch;
  bad_batch.rows = short_rows;
  if (wyl_fact_schema_validate_batch (store, &bad_batch, NULL)
      != WYRELOG_E_POLICY)
    return 15;

  const wyl_fact_value_t typed_bad_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "c-1"},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "not-an-int"},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "open"},
  };
  const wyl_fact_row_t typed_bad_rows[] = {
    {typed_bad_values, G_N_ELEMENTS (typed_bad_values)},
  };
  bad_batch = good_batch;
  bad_batch.rows = typed_bad_rows;
  if (wyl_fact_schema_validate_batch (store, &bad_batch, NULL)
      != WYRELOG_E_POLICY)
    return 16;

  const wyl_fact_value_t null_text_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = NULL},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "c-1"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 42},
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "open"},
  };
  const wyl_fact_row_t null_text_rows[] = {
    {null_text_values, G_N_ELEMENTS (null_text_values)},
  };
  bad_batch = good_batch;
  bad_batch.rows = null_text_rows;
  if (wyl_fact_schema_validate_batch (store, &bad_batch, NULL)
      != WYRELOG_E_POLICY)
    return 161;

  bad_batch = good_batch;
  bad_batch.schema_version = 3;
  if (wyl_fact_schema_validate_batch (store, &bad_batch, NULL)
      != WYRELOG_E_NOT_FOUND)
    return 17;
  if (wyl_fact_schema_validate_batch (store, &good_batch, NULL)
      != WYRELOG_E_OK)
    return 171;

  const wyl_fact_value_t nullable_nonnull_value[] = {
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 7},
  };
  const wyl_fact_row_t nullable_nonnull_row[] = {
    {nullable_nonnull_value, G_N_ELEMENTS (nullable_nonnull_value)},
  };
  wyl_fact_batch_t nullable_batch = {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .namespace_id = "shop",
    .relation_name = "nullable_values",
    .schema_version = 1,
    .rows = nullable_nonnull_row,
    .n_rows = G_N_ELEMENTS (nullable_nonnull_row),
  };
  if (wyl_fact_schema_validate_batch (store, &nullable_batch, NULL)
      != WYRELOG_E_OK)
    return 172;
  const wyl_fact_value_t nullable_null_value[] = {
    {.type = WYL_FACT_VALUE_NULL},
  };
  const wyl_fact_row_t nullable_null_row[] = {
    {nullable_null_value, G_N_ELEMENTS (nullable_null_value)},
  };
  nullable_batch.rows = nullable_null_row;
  if (wyl_fact_schema_validate_batch (store, &nullable_batch, NULL)
      != WYRELOG_E_POLICY)
    return 173;

  bad_batch = good_batch;
  bad_batch.relation_name = "missing";
  if (wyl_fact_schema_validate_batch (store, &bad_batch, NULL)
      != WYRELOG_E_NOT_FOUND)
    return 18;

  g_autofree gchar *ddl = wyl_fact_schema_build_duckdb_projection_ddl (&opts);
  if (ddl == NULL || !g_str_has_prefix (ddl,
      "CREATE TABLE IF NOT EXISTS \"tenant-a__graph-main__shop__orders_v1\"")
      || strstr (ddl, "\"amount\" BIGINT NOT NULL") == NULL)
    return 19;

  g_autofree gchar *decl = wyl_fact_schema_build_wirelog_declaration (&opts);
  if (decl == NULL
      || g_strcmp0 (decl,
      ".decl w_73_68_6f_70_w_6f_72_64_65_72_73(w_6f_72_64_65_72_5f_69_64: symbol, w_63_75_73_74_6f_6d_65_72_5f_69_64: symbol, w_61_6d_6f_75_6e_74: int64, w_73_74_61_74_75_73: symbol)")
      != 0)
    return 20;

  const wyl_policy_fact_relation_schema_column_t wirelog_columns[] = {
    {"order-id", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t wirelog_opts = opts;
  wirelog_opts.namespace_id = "shop-us";
  wirelog_opts.relation_name = "order-line";
  wirelog_opts.columns = wirelog_columns;
  wirelog_opts.n_columns = G_N_ELEMENTS (wirelog_columns);
  g_autofree gchar *mangled_decl =
      wyl_fact_schema_build_wirelog_declaration (&wirelog_opts);
  if (mangled_decl == NULL
      || g_strcmp0 (mangled_decl,
      ".decl w_73_68_6f_70_2d_75_73_w_6f_72_64_65_72_2d_6c_69_6e_65(w_6f_72_64_65_72_2d_69_64: symbol)")
      != 0)
    return 201;
  wirelog_opts.namespace_id = "shop_x2d_us";
  g_autofree gchar *collision_decl =
      wyl_fact_schema_build_wirelog_declaration (&wirelog_opts);
  if (collision_decl == NULL || g_strcmp0 (collision_decl, mangled_decl) == 0)
    return 202;

  wyrelog_error_t duplicate_rc =
      wyl_policy_store_register_fact_relation_schema (store, &opts);
  if (duplicate_rc != WYRELOG_E_POLICY)
    return 21;

  opts.namespace_id = "wr.internal";
  if (wyl_policy_store_register_fact_relation_schema (store, &opts)
      != WYRELOG_E_INVALID)
    return 22;

  if (wyl_policy_store_seal_fact_graph (store, "tenant-a", "graph-main")
      != WYRELOG_E_OK)
    return 23;
  if (wyl_fact_schema_validate_batch (store, &good_batch, NULL)
      != WYRELOG_E_NOT_FOUND)
    return 24;

  g_clear_pointer (&store, wyl_policy_store_close);
  cleanup_fact_root (root);
  return 0;
}

typedef struct
{
  GMutex mutex;
  GCond condition;
  guint ready;
  gboolean go;
} SchemaQuotaRaceGate;

typedef struct
{
  const gchar *path;
  const gchar *relation_name;
  SchemaQuotaRaceGate *gate;
  wyrelog_error_t rc;
  gboolean quota_exceeded;
} SchemaQuotaRaceAttempt;

static gpointer
schema_quota_race_worker (gpointer user_data)
{
  SchemaQuotaRaceAttempt *attempt = user_data;
  wyl_policy_store_open_options_t options = { .path = attempt->path };
  g_autoptr (wyl_policy_store_t) store = NULL;
  attempt->rc = wyl_policy_store_open_with_options (&options, &store);

  g_mutex_lock (&attempt->gate->mutex);
  attempt->gate->ready++;
  g_cond_broadcast (&attempt->gate->condition);
  while (!attempt->gate->go)
    g_cond_wait (&attempt->gate->condition, &attempt->gate->mutex);
  g_mutex_unlock (&attempt->gate->mutex);

  if (attempt->rc != WYRELOG_E_OK)
    return NULL;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"value", "symbol", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .namespace_id = "race",
    .relation_name = attempt->relation_name,
    .schema_version = 1,
    .relation_visible = FALSE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  for (guint retry = 0; retry < 8; retry++) {
    attempt->rc = wyl_policy_store_register_fact_relation_schema_with_quota_result
          (store, &schema, &attempt->quota_exceeded);
    if (attempt->rc != WYRELOG_E_BUSY)
      break;
    g_usleep (1000u << MIN (retry, 6u));
  }
  return NULL;
}

static gint
check_schema_quota_concurrent_registration (void)
{
  g_autofree gchar *root = g_dir_make_tmp ("wyl-fact-schema-quota-XXXXXX",
          NULL);
  if (root == NULL)
    return 30;
  g_autofree gchar *path = g_build_filename (root, "policy.sqlite", NULL);
  g_autofree gchar *fact_root = g_build_filename (root, "facts", NULL);
  if (g_mkdir (fact_root, 0700) != 0)
    return 31;

  wyl_policy_store_open_options_t options = { .path = path };
  g_autoptr (wyl_policy_store_t) setup = NULL;
  if (wyl_policy_store_open_with_options (&options, &setup) != WYRELOG_E_OK
      || wyl_policy_store_create_schema (setup) != WYRELOG_E_OK)
    return 32;
  gboolean created = FALSE;
  if (wyl_policy_store_create_tenant (setup, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 33;
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"subject", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"site.edge", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph = {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .fact_root = fact_root,
    .schema_version = 1,
    .owner_scope = "tenant-a",
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  wyrelog_error_t graph_rc = WYRELOG_E_BUSY;
  /* Recovery can include a filesystem handoff before the policy row is
   * visible as resumable.  Hosted macOS runners expose a longer scheduler
   * gap than the local Linux fixture, so allow bounded backoff through the
   * full recovery window rather than treating the transient policy result as
   * a permanent setup failure. */
  for (guint attempt = 0; attempt < 8; attempt++) {
    graph_rc = wyl_policy_store_create_fact_graph (setup, &graph, NULL);
    /* A failed materialization can leave the graph reservation visible until
     * its cleanup boundary completes.  Retrying the identical request lets
     * the durable resume path settle that transient POLICY result as well as
     * the explicit busy/I/O outcomes. */
    if (graph_rc != WYRELOG_E_BUSY && graph_rc != WYRELOG_E_IO
        && graph_rc != WYRELOG_E_POLICY)
      break;
    g_usleep (1000u << MIN (attempt, 7u));
  }
  wyrelog_error_t quota_rc = wyl_policy_store_set_fact_quota_config (setup,
          "tenant-a", WYL_POLICY_FACT_QUOTA_SCHEMA_COUNT,
          &(WylPolicyFactQuotaConfig) { .has_limit = TRUE, .hard_limit = 1 });
  if (graph_rc != WYRELOG_E_OK || quota_rc != WYRELOG_E_OK) {
    g_printerr ("schema quota setup failed graph=%d quota=%d\n", graph_rc,
        quota_rc);
    g_clear_pointer (&setup, wyl_policy_store_close);
    cleanup_fact_root (root);
    return 34;
  }
  g_clear_pointer (&setup, wyl_policy_store_close);

  SchemaQuotaRaceGate gate = { 0 };
  g_mutex_init (&gate.mutex);
  g_cond_init (&gate.condition);
  SchemaQuotaRaceAttempt attempts[] = {
    {path, "race_a", &gate, WYRELOG_E_INTERNAL, FALSE},
    {path, "race_b", &gate, WYRELOG_E_INTERNAL, FALSE},
  };
  GThread *threads[] = {
    g_thread_new ("schema-quota-a", schema_quota_race_worker, &attempts[0]),
    g_thread_new ("schema-quota-b", schema_quota_race_worker, &attempts[1]),
  };
  g_mutex_lock (&gate.mutex);
  while (gate.ready != G_N_ELEMENTS (threads))
    g_cond_wait (&gate.condition, &gate.mutex);
  gate.go = TRUE;
  g_cond_broadcast (&gate.condition);
  g_mutex_unlock (&gate.mutex);
  g_thread_join (threads[0]);
  g_thread_join (threads[1]);
  g_cond_clear (&gate.condition);
  g_mutex_clear (&gate.mutex);

  guint admitted = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (attempts); i++) {
    if (attempts[i].rc == WYRELOG_E_OK)
      admitted++;
    else if (attempts[i].rc != WYRELOG_E_POLICY
        && attempts[i].rc != WYRELOG_E_BUSY
        && attempts[i].rc != WYRELOG_E_IO) {
      g_clear_pointer (&setup, wyl_policy_store_close);
      cleanup_fact_root (root);
      return 35;
    }
  }
  if (admitted > 1) {
    cleanup_fact_root (root);
    return 36;
  }

  g_autoptr (wyl_policy_store_t) verify = NULL;
  WylPolicyFactSchemaQuotaStatus status = { 0 };
  if (wyl_policy_store_open_with_options (&options, &verify) != WYRELOG_E_OK
      || (admitted == 0 && wyl_policy_store_register_fact_relation_schema
        (verify, &(wyl_policy_fact_relation_schema_options_t) {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .namespace_id = "race",
    .relation_name = "race_fallback",
    .schema_version = 1,
    .relation_visible = FALSE,
    .columns = (const wyl_policy_fact_relation_schema_column_t[]) {
      {"value", "symbol", FALSE, TRUE},
    },
    .n_columns = 1,
  }) != WYRELOG_E_OK)
      || wyl_policy_store_get_fact_schema_quota_status (verify, "tenant-a",
      &status) != WYRELOG_E_OK || status.registered != 1) {
    cleanup_fact_root (root);
    return 37;
  }
  cleanup_fact_root (root);
  return 0;
}

int
main (void)
{
  gint rc = check_relation_schema_registration_and_validation ();
  if (rc != 0)
    return wyl_test_normalize_exit_status (rc);
  rc = check_schema_quota_concurrent_registration ();
  if (rc != 0)
    return wyl_test_normalize_exit_status (rc);
  return wyl_test_normalize_exit_status (0);
}

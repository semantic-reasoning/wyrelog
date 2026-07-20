/* SPDX-License-Identifier: GPL-3.0-or-later */
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
  if (wyl_policy_store_register_fact_relation_schema (store, &opts)
      != WYRELOG_E_OK)
    return 11;

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
  bad_batch.schema_version = 2;
  if (wyl_fact_schema_validate_batch (store, &bad_batch, NULL)
      != WYRELOG_E_NOT_FOUND)
    return 17;
  if (wyl_fact_schema_validate_batch (store, &good_batch, NULL)
      != WYRELOG_E_OK)
    return 171;

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

  if (wyl_policy_store_register_fact_relation_schema (store, &opts)
      != WYRELOG_E_POLICY)
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

int
main (void)
{
  gint rc = check_relation_schema_registration_and_validation ();
  if (rc != 0)
    return rc;
  return 0;
}

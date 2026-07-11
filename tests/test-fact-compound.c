/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "wyrelog/fact/compound-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/schema-private.h"
#include "wyrelog/engine.h"
#include "wyrelog/wyl-engine-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  gint64 expected_order;
  guint matches;
} SeenOrder;

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

static gchar *
make_tmpdir (void)
{
  g_autoptr (GError) err = NULL;
  gchar *dir = g_dir_make_tmp ("wyl-fact-compound-XXXXXX", &err);
  if (dir == NULL)
    g_printerr ("make_tmpdir: %s\n", err != NULL ? err->message : "?");
  return dir;
}

static gboolean
write_file_in_dir (const gchar *dir, const gchar *filename,
    const gchar *contents)
{
  g_autofree gchar *path = g_build_filename (dir, filename, NULL);
  g_autoptr (GError) err = NULL;
  gboolean ok = g_file_set_contents (path, contents, -1, &err);
  if (!ok)
    g_printerr ("write_file_in_dir(%s): %s\n", filename,
        err != NULL ? err->message : "?");
  return ok;
}

static void
rmdir_recursive (const gchar *dir)
{
  g_autoptr (GDir) d = g_dir_open (dir, 0, NULL);
  if (d == NULL) {
    g_rmdir (dir);
    return;
  }
  const gchar *name;
  while ((name = g_dir_read_name (d)) != NULL) {
    g_autofree gchar *path = g_build_filename (dir, name, NULL);
    if (g_file_test (path, G_FILE_TEST_IS_DIR))
      rmdir_recursive (path);
    else
      g_unlink (path);
  }
  g_rmdir (dir);
}

static gboolean
write_shipment_templates (const gchar *dir)
{
  g_autofree gchar *fsm_dir = g_build_filename (dir, "fsm", NULL);
  g_autofree gchar *lobac_dir = g_build_filename (dir, "lobac", NULL);
  if (g_mkdir (fsm_dir, 0755) != 0 || g_mkdir (lobac_dir, 0755) != 0)
    return FALSE;
  return write_file_in_dir (dir, "bootstrap.dl",
      ".decl shipment(order_id: symbol, route: path/2 side, carrier: symbol)\n"
      ".decl seen(order_id: symbol)\n"
      "seen(Order) :- shipment(Order, path(_, _), _).\n")
      && write_file_in_dir (dir, "fsm/principal.dl", "// principal stub\n")
      && write_file_in_dir (dir, "fsm/session.dl", "// session stub\n")
      && write_file_in_dir (dir, "fsm/permission_scope.dl",
      "// permission scope stub\n")
      && write_file_in_dir (dir, "lobac/decision.dl", "// decision stub\n");
}

static wyrelog_error_t
open_shipment_engine (gchar **tmpdir_out, WylEngine **out_engine)
{
  *tmpdir_out = NULL;
  *out_engine = NULL;
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return WYRELOG_E_IO;
  if (!write_shipment_templates (dir)) {
    rmdir_recursive (dir);
    return WYRELOG_E_IO;
  }
  /* Manifest authenticity is outside these synthetic evaluator fixtures. */
  wyrelog_error_t rc = wyl_engine_open_with_options (dir, 1, FALSE, out_engine);
  if (rc != WYRELOG_E_OK) {
    rmdir_recursive (dir);
    return rc;
  }
  *tmpdir_out = g_steal_pointer (&dir);
  return WYRELOG_E_OK;
}

static void
seen_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  SeenOrder *seen = user_data;
  if (g_strcmp0 (relation, "seen") == 0 && ncols == 1
      && row[0] == seen->expected_order)
    seen->matches++;
}

static wyrelog_error_t
replay_and_query (wyl_fact_store_t *store, gint64 durable_ref,
    gint64 *out_handle)
{
  g_autofree gchar *engine_dir = NULL;
  g_autoptr (WylEngine) engine = NULL;
  wyrelog_error_t rc = open_shipment_engine (&engine_dir, &engine);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
      "logistics", durable_ref, out_handle);
  if (rc != WYRELOG_E_OK) {
    rmdir_recursive (engine_dir);
    return rc;
  }

  gint64 order_id = 0;
  gint64 carrier_id = 0;
  rc = wyl_engine_intern_symbol (engine, "order-1", &order_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_engine_intern_symbol (engine, "carrier-ke", &carrier_id);
  if (rc != WYRELOG_E_OK) {
    rmdir_recursive (engine_dir);
    return rc;
  }
  const gint64 row[] = { order_id, *out_handle, carrier_id };
  rc = wyl_engine_insert (engine, "shipment", row, G_N_ELEMENTS (row));
  if (rc != WYRELOG_E_OK) {
    rmdir_recursive (engine_dir);
    return rc;
  }
  SeenOrder seen = { order_id, 0 };
  rc = wyl_engine_snapshot (engine, "seen", seen_cb, &seen);
  rmdir_recursive (engine_dir);
  if (rc != WYRELOG_E_OK)
    return rc;
  return seen.matches == 1 ? WYRELOG_E_OK : WYRELOG_E_EXEC;
}

static gint
check_compound_persists_and_replays (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 10;
  g_autofree gchar *path = g_build_filename (dir, "facts.duckdb", NULL);

  gint64 durable_ref = 0;
  gint64 first_handle = 0;
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (path, &store) != WYRELOG_E_OK)
      return 11;
    if (wyl_fact_compound_create_schema (store) != WYRELOG_E_OK)
      return 12;
    const wyl_fact_compound_arg_t args[] = {
      {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "ICN"},
      {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "LAX"},
    };
    const wyl_fact_compound_value_t value = {
      .tenant_id = "tenant-a",
      .graph_id = "shipments",
      .namespace_id = "logistics",
      .functor = "path",
      .args = args,
      .n_args = G_N_ELEMENTS (args),
    };
    if (wyl_fact_compound_put (store, &value, &durable_ref) != WYRELOG_E_OK
        || durable_ref <= 0)
      return 13;
    gint64 duplicate_ref = 0;
    if (wyl_fact_compound_put (store, &value, &duplicate_ref) != WYRELOG_E_OK
        || duplicate_ref != durable_ref)
      return 131;
    duckdb_connection conn = wyl_fact_store_get_connection (store);
    gint64 count = 0;
    if (!count_i64 (conn,
            "SELECT COUNT(*) FROM compound_terms WHERE functor = 'path' "
            "AND arity = 2;", &count) || count != 1)
      return 14;
    if (!count_i64 (conn,
            "SELECT COUNT(*) FROM compound_args WHERE arg_type = 'symbol' "
            "AND symbol_value IN ('ICN', 'LAX');", &count) || count != 2)
      return 15;
    if (!count_i64 (conn,
            "SELECT COUNT(*) FROM compound_args WHERE int64_value IS NOT NULL "
            "OR child_compound_ref IS NOT NULL;", &count) || count != 0)
      return 16;
    if (replay_and_query (store, durable_ref, &first_handle) != WYRELOG_E_OK)
      return 17;
    if (first_handle <= 0 || first_handle == durable_ref)
      return 18;
  }

  {
    g_autoptr (wyl_fact_store_t) reopened = NULL;
    if (wyl_fact_store_open (path, &reopened) != WYRELOG_E_OK)
      return 19;
    gint64 second_handle = 0;
    if (replay_and_query (reopened, durable_ref, &second_handle)
        != WYRELOG_E_OK)
      return 20;
    if (second_handle <= 0 || second_handle == durable_ref)
      return 21;
  }

  (void) g_remove (path);
  rmdir_recursive (dir);
  return 0;
}

static gint
check_compound_tenant_scope_and_append_validation (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 30;
  if (wyl_fact_compound_create_schema (store) != WYRELOG_E_OK)
    return 31;

  const wyl_fact_compound_arg_t args[] = {
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "ICN"},
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "LAX"},
  };
  wyl_fact_compound_value_t value = {
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "logistics",
    .functor = "path",
    .args = args,
    .n_args = G_N_ELEMENTS (args),
  };
  gint64 ref = 0;
  if (wyl_fact_compound_put (store, &value, &ref) != WYRELOG_E_OK)
    return 32;
  value.tenant_id = "tenant-b";
  gint64 other_ref = 0;
  if (wyl_fact_compound_put (store, &value, &other_ref) != WYRELOG_E_POLICY)
    return 33;
  gboolean exists = TRUE;
  if (wyl_fact_compound_ref_exists (store, "tenant-b", "shipments",
          "logistics", ref, &exists) != WYRELOG_E_POLICY)
    return 34;
  if (wyl_fact_compound_ref_exists (store, "tenant-a", "shipments",
          "other", ref, &exists) != WYRELOG_E_OK || exists)
    return 341;

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"route", "compound_ref", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "logistics",
    .relation_name = "shipment",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  if (wyl_fact_store_ensure_projection (store, &schema, NULL) != WYRELOG_E_OK)
    return 35;
  wyl_fact_value_t row_values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-1"},
    {.type = WYL_FACT_VALUE_COMPOUND_REF,.as.compound_ref = ref + 1},
  };
  const wyl_fact_row_t rows[] = {
    {row_values, G_N_ELEMENTS (row_values)},
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "batch-missing-compound",
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "logistics",
    .relation_name = "shipment",
    .schema_version = 1,
    .idempotency_key = "missing-compound:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  if (wyl_fact_store_append_batch (store, &schema, &batch, NULL)
      != WYRELOG_E_POLICY)
    return 36;
  const wyl_policy_fact_relation_schema_options_t other_namespace_schema = {
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "other",
    .relation_name = "shipment",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  const wyl_fact_store_batch_t other_namespace_batch = {
    .batch_id = "batch-wrong-namespace",
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "other",
    .relation_name = "shipment",
    .schema_version = 1,
    .idempotency_key = "wrong-namespace:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  row_values[1].as.compound_ref = ref;
  if (wyl_fact_store_append_batch (store, &other_namespace_schema,
          &other_namespace_batch, NULL) != WYRELOG_E_POLICY)
    return 361;
  row_values[1].as.compound_ref = ref;
  if (wyl_fact_store_append_batch (store, &schema, &batch, NULL)
      != WYRELOG_E_OK)
    return 37;
  return 0;
}

static gint
check_compound_corruption_is_local (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 50;
  if (wyl_fact_compound_create_schema (store) != WYRELOG_E_OK)
    return 51;
  const wyl_fact_compound_arg_t args[] = {
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "ICN"},
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "LAX"},
  };
  wyl_fact_compound_value_t value = {
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "logistics",
    .functor = "path",
    .args = args,
    .n_args = G_N_ELEMENTS (args),
  };
  gint64 bad_ref = 0;
  if (wyl_fact_compound_put (store, &value, &bad_ref) != WYRELOG_E_OK)
    return 52;
  value.functor = "safe_path";
  gint64 good_ref = 0;
  if (wyl_fact_compound_put (store, &value, &good_ref) != WYRELOG_E_OK)
    return 53;
  value.functor = "drift_path";
  gint64 drift_ref = 0;
  if (wyl_fact_compound_put (store, &value, &drift_ref) != WYRELOG_E_OK)
    return 531;
  duckdb_result result = { 0 };
  g_autofree gchar *sql = g_strdup_printf
      ("DELETE FROM compound_args WHERE compound_ref = %" G_GINT64_FORMAT
      " AND arg_index = 1;", bad_ref);
  if (duckdb_query (wyl_fact_store_get_connection (store), sql, &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 54;
  }
  duckdb_destroy_result (&result);
  g_autofree gchar *drift_sql = g_strdup_printf
      ("UPDATE compound_args SET symbol_value = 'SFO' "
      "WHERE compound_ref = %" G_GINT64_FORMAT " AND arg_index = 0;",
      drift_ref);
  if (duckdb_query (wyl_fact_store_get_connection (store), drift_sql, &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 541;
  }
  duckdb_destroy_result (&result);

  g_autofree gchar *engine_dir = NULL;
  g_autoptr (WylEngine) engine = NULL;
  if (open_shipment_engine (&engine_dir, &engine) != WYRELOG_E_OK)
    return 55;
  gint64 ignored = 0;
  if (wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
          "logistics", bad_ref, &ignored) != WYRELOG_E_POLICY) {
    rmdir_recursive (engine_dir);
    return 56;
  }
  if (wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
          "logistics", drift_ref, &ignored) != WYRELOG_E_POLICY) {
    rmdir_recursive (engine_dir);
    return 561;
  }
  if (wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
          "logistics", good_ref, &ignored) != WYRELOG_E_OK) {
    rmdir_recursive (engine_dir);
    return 57;
  }
  rmdir_recursive (engine_dir);
  return 0;
}

static gint
check_nested_compound_replay (void)
{
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (NULL, &store) != WYRELOG_E_OK)
    return 70;
  if (wyl_fact_compound_create_schema (store) != WYRELOG_E_OK)
    return 71;
  const wyl_fact_compound_arg_t metadata_args[] = {
    {.type = WYL_FACT_COMPOUND_ARG_INT64,.as.int64_value = 1700000001},
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL,.as.text = "public"},
    {.type = WYL_FACT_COMPOUND_ARG_INT64,.as.int64_value = 70},
  };
  const wyl_fact_compound_value_t metadata_value = {
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "logistics",
    .functor = "metadata",
    .args = metadata_args,
    .n_args = G_N_ELEMENTS (metadata_args),
  };
  gint64 metadata_ref = 0;
  if (wyl_fact_compound_put (store, &metadata_value, &metadata_ref)
      != WYRELOG_E_OK)
    return 72;
  const wyl_fact_compound_arg_t scope_args[] = {
    {.type = WYL_FACT_COMPOUND_ARG_COMPOUND_REF,.as.compound_ref =
          metadata_ref},
    {.type = WYL_FACT_COMPOUND_ARG_INT64,.as.int64_value = 7},
  };
  const wyl_fact_compound_value_t scope_value = {
    .tenant_id = "tenant-a",
    .graph_id = "shipments",
    .namespace_id = "logistics",
    .functor = "scope",
    .args = scope_args,
    .n_args = G_N_ELEMENTS (scope_args),
  };
  gint64 scope_ref = 0;
  if (wyl_fact_compound_put (store, &scope_value, &scope_ref)
      != WYRELOG_E_OK || scope_ref == metadata_ref)
    return 73;

  g_autoptr (WylEngine) engine = NULL;
  if (wyl_engine_open (WYL_TEST_TEMPLATE_DIR, 1, &engine) != WYRELOG_E_OK)
    return 74;
  gint64 handle = 0;
  if (wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
          "logistics", scope_ref, &handle) != WYRELOG_E_OK || handle <= 0)
    return 75;
  duckdb_result result = { 0 };
  g_autofree gchar *cycle_sql = g_strdup_printf
      ("UPDATE compound_args SET child_compound_ref = %" G_GINT64_FORMAT
      " WHERE compound_ref = %" G_GINT64_FORMAT " AND arg_index = 0;",
      scope_ref, scope_ref);
  if (duckdb_query (wyl_fact_store_get_connection (store), cycle_sql, &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 76;
  }
  duckdb_destroy_result (&result);
  if (wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
          "logistics", scope_ref, &handle) != WYRELOG_E_POLICY)
    return 77;
  if (wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
          "logistics", metadata_ref, &handle) != WYRELOG_E_OK)
    return 78;
  gint64 chain_ref = metadata_ref;
  for (guint i = 0; i < 34; i++) {
    const wyl_fact_compound_arg_t chain_args[] = {
      {.type = WYL_FACT_COMPOUND_ARG_COMPOUND_REF,.as.compound_ref = chain_ref},
      {.type = WYL_FACT_COMPOUND_ARG_INT64,.as.int64_value = (gint64) i},
    };
    const wyl_fact_compound_value_t chain_value = {
      .tenant_id = "tenant-a",
      .graph_id = "shipments",
      .namespace_id = "logistics",
      .functor = "scope",
      .args = chain_args,
      .n_args = G_N_ELEMENTS (chain_args),
    };
    if (wyl_fact_compound_put (store, &chain_value, &chain_ref)
        != WYRELOG_E_OK)
      return 79;
  }
  if (wyl_fact_compound_replay (store, engine, "tenant-a", "shipments",
          "logistics", chain_ref, &handle) != WYRELOG_E_POLICY)
    return 80;
  return 0;
}

int
main (void)
{
  gint rc = check_compound_persists_and_replays ();
  if (rc != 0)
    return rc;
  rc = check_compound_tenant_scope_and_append_validation ();
  if (rc != 0)
    return rc;
  rc = check_compound_corruption_is_local ();
  if (rc != 0)
    return rc;
  rc = check_nested_compound_replay ();
  if (rc != 0)
    return rc;
  return 0;
}

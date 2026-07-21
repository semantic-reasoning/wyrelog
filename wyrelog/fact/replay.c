/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "replay-private.h"

#include <string.h>

#include "compound-private.h"
#include "graph-locator-private.h"
#include "wyrelog/wyl-engine-private.h"

#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#define WYL_FACT_REPLAY_MAX_ROWS G_MAXUINT32

typedef struct
{
  gchar *namespace_id;
  gchar *relation_name;
  guint32 schema_version;
  gboolean relation_visible;
  wyl_policy_fact_relation_schema_column_t *columns;
  gsize n_columns;
  gchar *projection_table;
  gchar *wirelog_relation;
} ReplayRelation;

typedef struct
{
  WylEngine *engine;
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  wyl_fact_store_t *store;
  GHashTable *compound_handles;
} ReplayMaterializeCtx;

const gchar *
wyl_fact_graph_state_name (wyl_fact_graph_state_t state)
{
  switch (state) {
    case WYL_FACT_GRAPH_STATE_READY:
      return "ready";
    case WYL_FACT_GRAPH_STATE_DEGRADED:
      return "degraded";
    case WYL_FACT_GRAPH_STATE_SCHEMA_MISMATCH:
      return "schema_mismatch";
    case WYL_FACT_GRAPH_STATE_REPLAY_FAILED:
      return "replay_failed";
    case WYL_FACT_GRAPH_STATE_STORE_UNAVAILABLE:
      return "store_unavailable";
    default:
      return "degraded";
  }
}

void
wyl_fact_graph_status_free (gpointer data)
{
  wyl_fact_graph_status_t *status = data;
  if (status == NULL)
    return;
  g_free (status->tenant_id);
  g_free (status->graph_id);
  g_free (status->last_error_class);
  g_free (status);
}

static void
append_wirelog_identifier (GString *out, const gchar *identifier)
{
  if (identifier == NULL || identifier[0] == '\0') {
    g_string_append_c (out, 'w');
    return;
  }

  g_string_append_c (out, 'w');
  for (const gchar * p = identifier; *p != '\0'; p++)
    g_string_append_printf (out, "_%02x", (guchar) * p);
}

gchar *
wyl_fact_replay_wirelog_relation_name (const gchar *namespace_id,
    const gchar *relation_name)
{
  if (namespace_id == NULL || relation_name == NULL)
    return NULL;

  g_autoptr (GString) out = g_string_new (NULL);
  append_wirelog_identifier (out, namespace_id);
  g_string_append_c (out, '_');
  append_wirelog_identifier (out, relation_name);
  return g_string_free (g_steal_pointer (&out), FALSE);
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

static void
replay_relation_free (gpointer data)
{
  ReplayRelation *rel = data;
  if (rel == NULL)
    return;
  g_free (rel->namespace_id);
  g_free (rel->relation_name);
  for (gsize i = 0; i < rel->n_columns; i++) {
    g_free ((gchar *) rel->columns[i].column_name);
    g_free ((gchar *) rel->columns[i].column_type);
  }
  g_free (rel->columns);
  g_free (rel->projection_table);
  g_free (rel->wirelog_relation);
  g_free (rel);
}

static wyrelog_error_t
copy_schema_columns (const wyl_policy_fact_relation_schema_column_info_t *in,
    gsize n_columns, wyl_policy_fact_relation_schema_column_t **out)
{
  *out = NULL;
  if (in == NULL || n_columns == 0)
    return WYRELOG_E_INVALID;

  wyl_policy_fact_relation_schema_column_t *copy =
      g_new0 (wyl_policy_fact_relation_schema_column_t, n_columns);
  for (gsize i = 0; i < n_columns; i++) {
    copy[i].column_name = g_strdup (in[i].column_name);
    copy[i].column_type = g_strdup (in[i].column_type);
    copy[i].nullable = in[i].nullable;
    copy[i].visible = in[i].visible;
    if (copy[i].column_name == NULL || copy[i].column_type == NULL) {
      for (gsize j = 0; j <= i; j++) {
        g_free ((gchar *) copy[j].column_name);
        g_free ((gchar *) copy[j].column_type);
      }
      g_free (copy);
      return WYRELOG_E_NOMEM;
    }
  }
  *out = copy;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
load_relation_schema (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *graph, const gchar *namespace_id,
    const gchar *relation_name, guint32 schema_version,
    ReplayRelation **out_relation)
{
  *out_relation = NULL;

  gboolean relation_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *columns = NULL;
  gsize n_columns = 0;
  wyrelog_error_t rc = wyl_policy_store_load_fact_relation_schema_columns
      (policy, graph->tenant_id, graph->graph_id, namespace_id, relation_name,
      schema_version, &relation_visible, &columns, &n_columns);
  if (rc != WYRELOG_E_OK)
    return rc;

  ReplayRelation *rel = g_new0 (ReplayRelation, 1);
  rel->namespace_id = g_strdup (namespace_id);
  rel->relation_name = g_strdup (relation_name);
  rel->schema_version = schema_version;
  rel->relation_visible = relation_visible;
  rc = copy_schema_columns (columns, n_columns, &rel->columns);
  rel->n_columns = n_columns;
  wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
  if (rc != WYRELOG_E_OK) {
    replay_relation_free (rel);
    return rc;
  }

  const wyl_policy_fact_relation_schema_options_t opts = {
    .tenant_id = graph->tenant_id,
    .graph_id = graph->graph_id,
    .namespace_id = rel->namespace_id,
    .relation_name = rel->relation_name,
    .schema_version = rel->schema_version,
    .relation_visible = rel->relation_visible,
    .columns = rel->columns,
    .n_columns = rel->n_columns,
  };
  rel->projection_table = wyl_fact_store_projection_table_name (&opts);
  rel->wirelog_relation =
      wyl_fact_replay_wirelog_relation_name (rel->namespace_id,
      rel->relation_name);
  if (rel->namespace_id == NULL || rel->relation_name == NULL
      || rel->projection_table == NULL || rel->wirelog_relation == NULL) {
    replay_relation_free (rel);
    return WYRELOG_E_NOMEM;
  }

  *out_relation = rel;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
list_replay_relations (wyl_policy_store_t *policy, wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph, GPtrArray **out_relations)
{
  *out_relations = NULL;
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  if (conn == NULL || graph == NULL)
    return WYRELOG_E_INVALID;

  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT DISTINCT namespace_id, relation_name, schema_version "
      "FROM fact_batches WHERE tenant_id = ? AND graph_id = ? "
      "ORDER BY namespace_id, relation_name, schema_version;";
  if (duckdb_prepare (conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, graph->tenant_id) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, graph->graph_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);

  g_autoptr (GPtrArray) relations =
      g_ptr_array_new_with_free_func (replay_relation_free);
  wyrelog_error_t rc = WYRELOG_E_OK;
  for (idx_t row = 0; rc == WYRELOG_E_OK && row < duckdb_row_count (&result);
      row++) {
    if (duckdb_value_is_null (&result, 0, row)
        || duckdb_value_is_null (&result, 1, row)
        || duckdb_value_is_null (&result, 2, row)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    gchar *namespace_id = duckdb_value_varchar (&result, 0, row);
    gchar *relation_name = duckdb_value_varchar (&result, 1, row);
    gint64 schema_version = duckdb_value_int64 (&result, 2, row);
    if (namespace_id == NULL || relation_name == NULL || schema_version <= 0
        || schema_version > G_MAXUINT32) {
      rc = WYRELOG_E_POLICY;
    } else {
      ReplayRelation *rel = NULL;
      rc = load_relation_schema (policy, graph, namespace_id, relation_name,
          (guint32) schema_version, &rel);
      if (rc == WYRELOG_E_OK)
        g_ptr_array_add (relations, rel);
    }
    duckdb_free (namespace_id);
    duckdb_free (relation_name);
  }
  duckdb_destroy_result (&result);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_relations = g_steal_pointer (&relations);
  return WYRELOG_E_OK;
}

static gchar *
build_graph_program (GPtrArray *relations)
{
  g_autoptr (GString) program = g_string_new (NULL);
  for (guint i = 0; relations != NULL && i < relations->len; i++) {
    ReplayRelation *rel = g_ptr_array_index (relations, i);
    const gchar *relation_names[2] = { rel->wirelog_relation, NULL };
    g_autofree gchar *observed_relation = g_strdup_printf ("%s_observed",
        rel->wirelog_relation);
    relation_names[1] = observed_relation;

    for (guint decl_idx = 0; decl_idx < G_N_ELEMENTS (relation_names);
        decl_idx++) {
      g_string_append (program, ".decl ");
      g_string_append (program, relation_names[decl_idx]);
      g_string_append_c (program, '(');
      for (gsize col = 0; col < rel->n_columns; col++) {
        const gchar *column_type = rel->columns[col].column_type;
        const gchar *wire_type = NULL;
        if (g_strcmp0 (column_type, "symbol") == 0
            || g_strcmp0 (column_type, "string") == 0)
          wire_type = "symbol";
        else if (g_strcmp0 (column_type, "int64") == 0
            || g_strcmp0 (column_type, "bool") == 0
            || g_strcmp0 (column_type, "compound_ref") == 0)
          wire_type = "int64";
        else
          return NULL;
        if (col > 0)
          g_string_append (program, ", ");
        append_wirelog_identifier (program, rel->columns[col].column_name);
        g_string_append_printf (program, ": %s", wire_type);
      }
      g_string_append (program, ")\n");
    }

    g_string_append (program, observed_relation);
    g_string_append_c (program, '(');
    for (gsize col = 0; col < rel->n_columns; col++) {
      if (col > 0)
        g_string_append (program, ", ");
      g_string_append_printf (program, "V%" G_GSIZE_FORMAT, col);
    }
    g_string_append (program, ") :- ");
    g_string_append (program, rel->wirelog_relation);
    g_string_append_c (program, '(');
    for (gsize col = 0; col < rel->n_columns; col++) {
      if (col > 0)
        g_string_append (program, ", ");
      g_string_append_printf (program, "V%" G_GSIZE_FORMAT, col);
    }
    g_string_append (program, ").\n");
  }
  return g_string_free (g_steal_pointer (&program), FALSE);
}

static wyrelog_error_t
materialize_cell (ReplayMaterializeCtx *ctx,
    const wyl_policy_fact_relation_schema_column_t *column,
    duckdb_result *result, idx_t col, idx_t row, gint64 *out)
{
  if (duckdb_value_is_null (result, col, row))
    return WYRELOG_E_POLICY;

  if (g_strcmp0 (column->column_type, "symbol") == 0
      || g_strcmp0 (column->column_type, "string") == 0) {
    gchar *value = duckdb_value_varchar (result, col, row);
    if (value == NULL)
      return WYRELOG_E_POLICY;
    wyrelog_error_t rc = wyl_engine_owned_intern_symbol (ctx->engine, value,
        out);
    duckdb_free (value);
    return rc;
  }
  if (g_strcmp0 (column->column_type, "int64") == 0) {
    *out = duckdb_value_int64 (result, col, row);
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "bool") == 0) {
    *out = duckdb_value_boolean (result, col, row) ? 1 : 0;
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "compound_ref") == 0) {
    gint64 compound_ref = duckdb_value_int64 (result, col, row);
    wyrelog_error_t rc = wyl_fact_compound_replay_cached (ctx->store,
        ctx->engine, ctx->tenant_id, ctx->graph_id, ctx->namespace_id,
        compound_ref, ctx->compound_handles, out);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (*out <= 0)
      return WYRELOG_E_INTERNAL;
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_POLICY;
}

static gchar *
row_key (const gint64 *row, gsize ncols)
{
  return g_base64_encode ((const guchar *) row, sizeof (gint64) * ncols);
}

static void
insert_or_replace_row (GHashTable *rows, const gint64 *row, gsize ncols)
{
  g_autofree gchar *key = row_key (row, ncols);
  gint64 *copy = g_memdup2 (row, sizeof (gint64) * ncols);
  g_hash_table_replace (rows, g_steal_pointer (&key), copy);
}

static void
remove_row (GHashTable *rows, const gint64 *row, gsize ncols)
{
  g_autofree gchar *key = row_key (row, ncols);
  g_hash_table_remove (rows, key);
}

static wyrelog_error_t
replay_relation_into_engine (wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph, ReplayRelation *rel,
    WylEngine *engine, GHashTable *compound_handles)
{
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  if (conn == NULL || graph == NULL || rel == NULL || engine == NULL
      || compound_handles == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (GString) sql = g_string_new ("SELECT ");
  for (gsize i = 0; i < rel->n_columns; i++) {
    if (i > 0)
      g_string_append (sql, ", ");
    append_duckdb_identifier (sql, rel->columns[i].column_name);
  }
  g_string_append (sql, ", __wyl_valid FROM ");
  append_duckdb_identifier (sql, rel->projection_table);
  g_string_append (sql,
      " WHERE __wyl_tenant_id = ? AND __wyl_graph_id = ? "
      "ORDER BY __wyl_seq, __wyl_row_index;");

  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  if (duckdb_prepare (conn, sql->str, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, graph->tenant_id) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, graph->graph_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);

  if (duckdb_row_count (&result) > WYL_FACT_REPLAY_MAX_ROWS) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }

  g_autoptr (GHashTable) current_rows =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  ReplayMaterializeCtx mat = {
    .engine = engine,
    .tenant_id = graph->tenant_id,
    .graph_id = graph->graph_id,
    .namespace_id = rel->namespace_id,
    .store = store,
    .compound_handles = compound_handles,
  };

  wyrelog_error_t rc = WYRELOG_E_OK;
  for (idx_t r = 0; rc == WYRELOG_E_OK && r < duckdb_row_count (&result); r++) {
    if (duckdb_value_is_null (&result, rel->n_columns, r)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    g_autofree gint64 *wire_row = g_new0 (gint64, rel->n_columns);
    for (gsize c = 0; rc == WYRELOG_E_OK && c < rel->n_columns; c++)
      rc = materialize_cell (&mat, &rel->columns[c], &result, c, r,
          &wire_row[c]);
    if (rc != WYRELOG_E_OK)
      break;
    gboolean valid = duckdb_value_boolean (&result, rel->n_columns, r);
    if (valid)
      insert_or_replace_row (current_rows, wire_row, rel->n_columns);
    else
      remove_row (current_rows, wire_row, rel->n_columns);
  }
  duckdb_destroy_result (&result);
  if (rc != WYRELOG_E_OK)
    return rc;

  GHashTableIter iter;
  gpointer key = NULL;
  gpointer value = NULL;
  g_hash_table_iter_init (&iter, current_rows);
  while (g_hash_table_iter_next (&iter, &key, &value)) {
    (void) key;
    rc = wyl_engine_owned_insert (engine, rel->wirelog_relation,
        (const gint64 *) value, rel->n_columns);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
replay_relations_into_engine (wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph, GPtrArray *relations,
    WylEngine *engine)
{
  g_autoptr (GHashTable) compound_handles =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  for (guint i = 0; relations != NULL && i < relations->len; i++) {
    wyrelog_error_t rc = replay_relation_into_engine (store, graph,
        g_ptr_array_index (relations, i), engine, compound_handles);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
resolve_fact_db_path (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gchar **out_path)
{
  *out_path = NULL;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  wyrelog_error_t rc = wyl_policy_store_open_fact_graph_directory (policy,
      fact_root, graph_info->tenant_id, graph_info->graph_id, FALSE,
      &directory);
  gint fd = -1;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_file (&directory, "facts.duckdb",
        FALSE, &fd);
  if (rc == WYRELOG_E_OK) {
    *out_path = wyl_fact_graph_directory_descriptive_file (&directory,
        "facts.duckdb");
    if (*out_path == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (fd >= 0)
#ifdef G_OS_WIN32
    _close (fd);
#else
    close (fd);
#endif
  wyl_fact_graph_directory_clear (&directory);
  return rc;
}

wyrelog_error_t
wyl_fact_replay_open_graph_engine (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylEngine **out_engine)
{
  if (out_engine != NULL)
    *out_engine = NULL;
  if (policy == NULL || fact_root == NULL || fact_root[0] == '\0'
      || graph_info == NULL || out_engine == NULL)
    return WYRELOG_E_INVALID;
  if (graph_info->sealed)
    return WYRELOG_E_POLICY;

  g_autofree gchar *fact_db_path = NULL;
  wyrelog_error_t rc = resolve_fact_db_path (policy, fact_root, graph_info,
      &fact_db_path);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_fact_store_t) store = NULL;
  rc = wyl_fact_store_open (fact_db_path, &store);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (GPtrArray) relations = NULL;
  rc = list_replay_relations (policy, store, graph_info, &relations);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *program = build_graph_program (relations);
  if (program == NULL)
    return WYRELOG_E_NOMEM;

  WylEngine *engine = NULL;
  rc = wyl_engine_open_source (program, 1, &engine);
  if (rc != WYRELOG_E_OK)
    return rc;
  wyl_engine_set_owner (engine, WYL_ENGINE_OWNER_READ);

  rc = replay_relations_into_engine (store, graph_info, relations, engine);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (engine);
    return rc;
  }

  *out_engine = engine;
  return WYRELOG_E_OK;
}

typedef struct
{
  wyl_policy_fact_graph_info_t info;
  WylFactGraphKey key;
  gboolean key_valid;
} OwnedGraphSpec;

static void
owned_graph_spec_free (gpointer data)
{
  OwnedGraphSpec *spec = data;
  if (spec == NULL)
    return;
  g_free ((gchar *) spec->info.tenant_id);
  g_free ((gchar *) spec->info.graph_id);
  g_free ((gchar *) spec->info.storage_uri);
  g_free ((gchar *) spec->info.storage_path);
  g_free ((gchar *) spec->info.owner_scope);
  wyl_fact_graph_key_clear (&spec->key);
  g_free (spec);
}

static wyrelog_error_t
collect_graph_spec (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  GPtrArray *specs = user_data;
  OwnedGraphSpec *spec = g_new0 (OwnedGraphSpec, 1);
  spec->info.tenant_id = g_strdup (info->tenant_id);
  spec->info.graph_id = g_strdup (info->graph_id);
  spec->info.storage_uri = g_strdup (info->storage_uri);
  spec->info.storage_path = g_strdup (info->storage_path);
  spec->info.schema_version = info->schema_version;
  spec->info.owner_scope = g_strdup (info->owner_scope);
  spec->info.sealed = info->sealed;
  wyrelog_error_t rc = wyl_fact_graph_key_init (&spec->key, info->tenant_id,
      info->graph_id);
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_INVALID) {
    owned_graph_spec_free (spec);
    return rc;
  }
  spec->key_valid = rc == WYRELOG_E_OK;
  g_ptr_array_add (specs, spec);
  return WYRELOG_E_OK;
}

typedef struct
{
  wyl_policy_store_t *policy;
  const gchar *fact_root;
  const wyl_policy_fact_graph_info_t *info;
} GraphBuildCtx;

static wyrelog_error_t
build_graph_engine (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  GraphBuildCtx *ctx = user_data;
  if (g_strcmp0 (key->tenant_id, ctx->info->tenant_id) != 0
      || g_strcmp0 (key->graph_id, ctx->info->graph_id) != 0)
    return WYRELOG_E_INTERNAL;
  return wyl_fact_replay_open_graph_engine (ctx->policy, ctx->fact_root,
      ctx->info, out_engine);
}

wyrelog_error_t
wyl_fact_replay_policy_graphs (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactGraphRuntimeManager *runtime_manager,
    wyl_fact_replay_summary_t *out_summary)
{
  if (out_summary != NULL)
    memset (out_summary, 0, sizeof (*out_summary));
  if (policy == NULL || runtime_manager == NULL)
    return WYRELOG_E_INVALID;

  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  g_autoptr (GPtrArray) specs =
      g_ptr_array_new_with_free_func (owned_graph_spec_free);
  wyrelog_error_t rc = wyl_policy_store_foreach_fact_graph (policy, NULL,
      collect_graph_spec, specs);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_fact_replay_summary_t summary = { 0 };
  g_autoptr (GPtrArray) seen_keys = g_ptr_array_new ();
  for (guint i = 0; i < specs->len; i++) {
    OwnedGraphSpec *spec = g_ptr_array_index (specs, i);
    summary.graphs_seen++;
    if (!spec->key_valid) {
      summary.graphs_degraded++;
      continue;
    }
    GraphBuildCtx build = { policy, fact_root, &spec->info };
    wyrelog_error_t graph_rc = wyl_fact_graph_runtime_manager_refresh
        (runtime_manager, &spec->key, build_graph_engine, &build, NULL);
    if (graph_rc == WYRELOG_E_OK)
      summary.graphs_loaded++;
    else
      summary.graphs_degraded++;
    g_ptr_array_add (seen_keys, &spec->key);
  }
  rc = wyl_fact_graph_runtime_manager_retire_unseen (runtime_manager,
      (const WylFactGraphKey * const *) seen_keys->pdata, seen_keys->len);
  if (out_summary != NULL)
    *out_summary = summary;
  return rc;
}

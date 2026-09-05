/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "replay-private.h"

#include <string.h>

#include "compound-private.h"
#include "graph-locator-private.h"
#include "wyrelog/wyl-engine-private.h"
#include "wyrelog/wyl-log-private.h"
#define WYL_FACT_STORE_CONNECTION_ROLE 1
#include "store-connection-private.h"
#undef WYL_FACT_STORE_CONNECTION_ROLE
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
#include "fact/store-open-private.h"
#endif

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

typedef struct
{
  gchar *namespace_id;
  gchar *relation_name;
  guint32 schema_version;
} ReplayRelationKey;

typedef struct
{
  gchar *text;
  gint64 integer;
  gboolean boolean;
} ReplayOwnedCell;

typedef struct
{
  ReplayOwnedCell *cells;
  gsize n_cells;
  gboolean valid;
} ReplayOwnedRow;

static void
replay_relation_key_free (gpointer data)
{
  ReplayRelationKey *key = data;
  if (key == NULL)
    return;
  g_free (key->namespace_id);
  g_free (key->relation_name);
  g_free (key);
}

static void
replay_owned_row_free (gpointer data)
{
  ReplayOwnedRow *row = data;
  if (row == NULL)
    return;
  for (gsize i = 0; i < row->n_cells; i++)
    g_free (row->cells[i].text);
  g_free (row->cells);
  g_free (row);
}

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
    case WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE:
      return "forget_incomplete";
    case WYL_FACT_GRAPH_STATE_SEALED:
      return "sealed";
  }
  /* No default arm: -Wswitch then names a state added without a string.  It
   * is a warning rather than an error here (werror is off), so it does not
   * stop a build -- the test asserting the literal name is what does.  This
   * return covers a value outside the enum, and says so rather than
   * rendering it as a plausible state. */
  return "unknown";
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

static gchar *
replay_relation_seen_key (const gchar *namespace_id, const gchar *relation_name)
{
  return g_strconcat (namespace_id, "\x1f", relation_name, NULL);
}

/* Enumerates the relations to replay for one graph.  The policy activation
 * registry is authoritative (#545): every relation it lists active contributes
 * EXACTLY ONE schema version, so a registered-but-never-appended relation is
 * still declared, and two schema versions of one relation can never both be
 * declared (which would collide on the unversioned wirelog relation name).
 * Relations not yet owned by the registry fall back to the historical
 * fact_batches enumeration, per (namespace, relation), so graphs predating
 * schema convergence keep replaying exactly as before -- the union is strictly
 * additive and cannot regress an existing graph. */
static wyrelog_error_t
list_replay_relations (wyl_policy_store_t *policy, wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph, GPtrArray **out_relations)
{
  *out_relations = NULL;
  if (policy == NULL || store == NULL || graph == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (GPtrArray) relations =
      g_ptr_array_new_with_free_func (replay_relation_free);
  g_autoptr (GHashTable) seen =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  g_autoptr (GPtrArray) active = NULL;
  wyrelog_error_t rc = wyl_policy_store_list_active_fact_relations (policy,
          graph->tenant_id, graph->graph_id, &active);
  if (rc != WYRELOG_E_OK)
    return rc;
  for (guint i = 0; rc == WYRELOG_E_OK && active != NULL && i < active->len;
      i++) {
    const WylPolicyRelationActivationRecord *record =
        g_ptr_array_index (active, i);
    if (!record->has_active_schema_version
        || record->active_schema_version == 0
        || record->active_schema_version > G_MAXUINT32) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    ReplayRelation *rel = NULL;
    rc = load_relation_schema (policy, graph, record->namespace_id,
            record->relation_name, (guint32) record->active_schema_version,
            &rel);
    if (rc == WYRELOG_E_OK) {
      g_ptr_array_add (relations, rel);
      g_hash_table_add (seen, replay_relation_seen_key (record->namespace_id,
          record->relation_name));
    }
  }
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (GPtrArray) stored_keys =
      g_ptr_array_new_with_free_func (replay_relation_key_free);
  WylFactStoreConnectionSession session = { 0 };
  rc = wyl_fact_store_connection_session_begin (store, &session);
  if (rc != WYRELOG_E_OK)
    return rc;
  duckdb_connection conn = wyl_fact_store_connection_session_get (&session);
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT DISTINCT namespace_id, relation_name, schema_version "
      "FROM fact_batches WHERE tenant_id = ? AND graph_id = ? "
      "ORDER BY namespace_id, relation_name, schema_version;";
  if (duckdb_prepare (conn, sql, &stmt) != DuckDBSuccess)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK
      && (duckdb_bind_varchar (stmt, 1, graph->tenant_id) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, graph->graph_id) != DuckDBSuccess)) {
    rc = WYRELOG_E_IO;
  }
  if (rc == WYRELOG_E_OK
      && duckdb_execute_prepared (stmt, &result) != DuckDBSuccess)
    rc = WYRELOG_E_IO;

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
      ReplayRelationKey *key = g_new0 (ReplayRelationKey, 1);
      key->namespace_id = g_strdup (namespace_id);
      key->relation_name = g_strdup (relation_name);
      key->schema_version = (guint32) schema_version;
      if (key->namespace_id == NULL || key->relation_name == NULL) {
        replay_relation_key_free (key);
        rc = WYRELOG_E_NOMEM;
      } else {
        g_ptr_array_add (stored_keys, key);
      }
    }
    duckdb_free (namespace_id);
    duckdb_free (relation_name);
  }
  duckdb_destroy_prepare (&stmt);
  duckdb_destroy_result (&result);
  wyl_fact_store_connection_session_end (&session);
  if (rc != WYRELOG_E_OK)
    return rc;

  for (guint i = 0; rc == WYRELOG_E_OK && i < stored_keys->len; i++) {
    ReplayRelationKey *stored = g_ptr_array_index (stored_keys, i);
    g_autofree gchar *key = replay_relation_seen_key (stored->namespace_id,
            stored->relation_name);
    if (!g_hash_table_contains (seen, key)) {
      ReplayRelation *rel = NULL;
      rc = load_relation_schema (policy, graph, stored->namespace_id,
              stored->relation_name, stored->schema_version, &rel);
      if (rc == WYRELOG_E_OK)
        g_ptr_array_add (relations, rel);
    }
  }
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
materialize_owned_cell (ReplayMaterializeCtx *ctx,
    const wyl_policy_fact_relation_schema_column_t *column,
    const ReplayOwnedCell *cell, gint64 *out)
{
  if (g_strcmp0 (column->column_type, "symbol") == 0
      || g_strcmp0 (column->column_type, "string") == 0) {
    if (cell->text == NULL)
      return WYRELOG_E_POLICY;
    return wyl_engine_owned_intern_symbol (ctx->engine, cell->text, out);
  }
  if (g_strcmp0 (column->column_type, "int64") == 0) {
    *out = cell->integer;
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "bool") == 0) {
    *out = cell->boolean ? 1 : 0;
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "compound_ref") == 0) {
    wyrelog_error_t rc = wyl_fact_compound_replay_cached (ctx->store,
            ctx->engine, ctx->tenant_id, ctx->graph_id, ctx->namespace_id,
            cell->integer, ctx->compound_handles, out);
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
  if (store == NULL || graph == NULL || rel == NULL || engine == NULL
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

  g_autoptr (GPtrArray) owned_rows =
      g_ptr_array_new_with_free_func (replay_owned_row_free);
  WylFactStoreConnectionSession session = { 0 };
  wyrelog_error_t rc = wyl_fact_store_connection_session_begin (store,
          &session);
  if (rc != WYRELOG_E_OK)
    return rc;
  duckdb_connection conn = wyl_fact_store_connection_session_get (&session);
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  if (duckdb_prepare (conn, sql->str, &stmt) != DuckDBSuccess)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK
      && (duckdb_bind_varchar (stmt, 1, graph->tenant_id) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, graph->graph_id) != DuckDBSuccess))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK
      && duckdb_execute_prepared (stmt, &result) != DuckDBSuccess)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK
      && duckdb_row_count (&result) > WYL_FACT_REPLAY_MAX_ROWS)
    rc = WYRELOG_E_POLICY;

  for (idx_t r = 0; rc == WYRELOG_E_OK && r < duckdb_row_count (&result); r++) {
    if (duckdb_value_is_null (&result, rel->n_columns, r)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    ReplayOwnedRow *owned = g_new0 (ReplayOwnedRow, 1);
    owned->n_cells = rel->n_columns;
    owned->cells = g_new0 (ReplayOwnedCell, rel->n_columns);
    owned->valid = duckdb_value_boolean (&result, rel->n_columns, r);
    for (gsize c = 0; rc == WYRELOG_E_OK && c < rel->n_columns; c++) {
      if (duckdb_value_is_null (&result, c, r)) {
        rc = WYRELOG_E_POLICY;
        break;
      }
      const gchar *type = rel->columns[c].column_type;
      if (g_strcmp0 (type, "symbol") == 0
          || g_strcmp0 (type, "string") == 0) {
        gchar *value = duckdb_value_varchar (&result, c, r);
        if (value == NULL) {
          rc = WYRELOG_E_POLICY;
        } else {
          owned->cells[c].text = g_strdup (value);
          duckdb_free (value);
          if (owned->cells[c].text == NULL)
            rc = WYRELOG_E_NOMEM;
        }
      } else if (g_strcmp0 (type, "int64") == 0
          || g_strcmp0 (type, "compound_ref") == 0) {
        owned->cells[c].integer = duckdb_value_int64 (&result, c, r);
      } else if (g_strcmp0 (type, "bool") == 0) {
        owned->cells[c].boolean = duckdb_value_boolean (&result, c, r);
      } else {
        rc = WYRELOG_E_POLICY;
      }
    }
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (owned_rows, owned);
    else
      replay_owned_row_free (owned);
  }
  duckdb_destroy_prepare (&stmt);
  duckdb_destroy_result (&result);
  wyl_fact_store_connection_session_end (&session);
  if (rc != WYRELOG_E_OK)
    return rc;

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

  for (guint r = 0; rc == WYRELOG_E_OK && r < owned_rows->len; r++) {
    ReplayOwnedRow *owned = g_ptr_array_index (owned_rows, r);
    g_autofree gint64 *wire_row = g_new0 (gint64, rel->n_columns);
    for (gsize c = 0; rc == WYRELOG_E_OK && c < rel->n_columns; c++)
      rc = materialize_owned_cell (&mat, &rel->columns[c], &owned->cells[c],
              &wire_row[c]);
    if (rc != WYRELOG_E_OK)
      break;
    if (owned->valid)
      insert_or_replace_row (current_rows, wire_row, rel->n_columns);
    else
      remove_row (current_rows, wire_row, rel->n_columns);
  }
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

/* Open one graph's fact store, choosing the same provisioned/legacy path the
 * engine builder chooses.  Extracted so the two callers cannot drift: they
 * differ only in whether they need to write. */
static wyrelog_error_t
open_graph_store (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gboolean writable,
    wyl_fact_store_t **out_store)
{
  g_assert (out_store != NULL);
  *out_store = NULL;
  gboolean provisioned = FALSE;
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
  {
    WylPolicyGraphAuthorityRecord *authority = NULL;
    if (wyl_policy_store_read_graph_authority (policy, graph_info->tenant_id,
        graph_info->graph_id, &authority) == WYRELOG_E_OK
        && authority != NULL && authority->lifecycle_state
        != WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED)
      provisioned = TRUE;
    wyl_policy_graph_authority_record_free (authority);
  }
  if (provisioned)
    return wyl_fact_store_open_provisioned_graph (policy, fact_root,
               graph_info->tenant_id, graph_info->graph_id, writable,
               out_store);
#else
  (void) writable;
#endif
  g_autofree gchar *fact_db_path = NULL;
  wyrelog_error_t rc = resolve_fact_db_path (policy, fact_root, graph_info,
          &fact_db_path);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_fact_store_open (fact_db_path, out_store);
}

static wyrelog_error_t
open_graph_engine_with_store (wyl_policy_store_t *policy,
    wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph_info, WylEngine **out_engine)
{
  if (out_engine != NULL)
    *out_engine = NULL;
  if (policy == NULL || store == NULL || graph_info == NULL
      || out_engine == NULL)
    return WYRELOG_E_INVALID;
  if (graph_info->sealed)
    return WYRELOG_E_POLICY;

  /* Reject an already poisoned supplied store before policy enumeration.  If
   * another thread poisons after this admission, each later store session
   * rechecks health before any DuckDB access and the unpublished engine is
   * destroyed on failure. */
  WylFactStoreConnectionSession admission = { 0 };
  wyrelog_error_t rc = wyl_fact_store_connection_session_begin (store,
          &admission);
  if (rc != WYRELOG_E_OK)
    return rc;
  wyl_fact_store_connection_session_end (&admission);

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

#if defined(WYL_TEST_HANDLE_SEAMS)
wyrelog_error_t
wyl_fact_replay_open_graph_engine_with_store_for_test
  (wyl_policy_store_t *policy, wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph_info, WylEngine **out_engine)
{
  return open_graph_engine_with_store (policy, store, graph_info, out_engine);
}
#endif

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

  g_autoptr (wyl_fact_store_t) store = NULL;
  wyrelog_error_t rc = open_graph_store (policy, fact_root, graph_info,
          FALSE, &store);
  if (rc != WYRELOG_E_OK)
    return rc;
  return open_graph_engine_with_store (policy, store, graph_info,
             out_engine);
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

/* Ask whether a graph has any pending forget intention without asking for
 * write access.  "Only a read lease" is the bridge case: off-bridge, and for
 * a LEGACY_UNCLASSIFIED graph under the bridge, open_graph_store discards
 * |writable| and this takes the same read-write DuckDB handle the engine
 * builder takes.
 *
 * The store handle lives and dies inside this function and the count
 * is returned by value, so no probe handle is in scope where the caller
 * escalates to a writable open.  That makes "the probe contends with the
 * escalation it decided on" unrepresentable rather than something a test has
 * to police -- which matters because off-bridge the two opens are the same
 * call and no off-bridge test could catch it.
 *
 * *out_opened reports whether the store was examined at all: TRUE means the
 * open succeeded, FALSE that it did not.  Do not read more into a failure
 * than that.  TRUE with a non-OK rc means only that we opened the store --
 * the survey can still fail with E_IO out of table_exists_unlocked or
 * load_pending_forget_intents_unlocked, which is a store examined and nothing
 * learned.  Today the caller cannot tell that from a genuinely unconverged
 * erasure and reports both as incomplete; separating them is what U2's
 * loaded/executed/refused/failed counts are for. */
static wyrelog_error_t
probe_graph_forgets (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gboolean *out_opened,
    gsize *out_pending)
{
  g_assert (out_opened != NULL);
  g_assert (out_pending != NULL);
  *out_opened = FALSE;
  *out_pending = 0;

  g_autoptr (wyl_fact_store_t) probe = NULL;
  wyrelog_error_t rc = open_graph_store (policy, fact_root, graph_info, FALSE,
          &probe);
  /* A graph whose store has never been written has nothing to converge.  The
   * resolver reports that as NOT_FOUND. */
  if (rc == WYRELOG_E_NOT_FOUND)
    return WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_opened = TRUE;
  return wyl_fact_store_forget_pending_count (probe, graph_info->tenant_id,
             graph_info->graph_id, out_pending);
}

/* Converge any forget interrupted by a crash, before the engine for this graph
 * is built.  A forget is durable in two steps -- a PENDING intent, then the
 * deletion and its completion -- and nothing in the request path resumes the
 * second step, so an interrupted forget stays pending until something drives
 * it.  Since a sealed graph refuses forget at the request boundary and there
 * is no unseal route, startup is its only remedy.
 *
 * Sealed graphs are therefore included deliberately: sealing blocks admission
 * of new data, not erasure of existing data, and the store opener serves a
 * sealed graph for exactly this reason.  That is a different question from
 * whether a sealed graph gets a query engine, which it does not.
 *
 * Returns non-OK only to be counted and logged by the caller.  It must never
 * reach the handle open, which destroys the handle on any replay failure.
 *
 * The line lengths of this comment are constrained by #872: some block shapes
 * make uncrustify rewrite the continuation stars.  Re-run ./tools/format-c
 * after editing it.
 *
 * A graph whose key does not validate is skipped by the caller before this
 * runs, so it is never probed and produces neither log line.  That is
 * deliberate: such a graph has no usable identity to name in a message.
 *
 * out_opened reports whether the store was opened at all, because the caller
 * cannot say the same thing about both outcomes.  A store that would not open
 * has told us nothing about any erasure: the graph may be DEGRADED or still
 * PROVISIONING, in which case no forget was ever recorded for it, and the
 * engine build about to run reports that state through its own channel.  Only
 * a store that opened has a ledger the reconciler could read. */
static wyrelog_error_t
reconcile_graph_forgets (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gboolean *out_opened)
{
  g_assert (out_opened != NULL);
  *out_opened = FALSE;
  if (policy == NULL || fact_root == NULL || fact_root[0] == '\0'
      || graph_info == NULL)
    return WYRELOG_E_INVALID;

  gsize pending = 0;
  wyrelog_error_t rc = probe_graph_forgets (policy, fact_root, graph_info,
          out_opened, &pending);
  /* Nothing pending, or we could not find out.  Either way no write lease is
   * taken: the overwhelmingly common boot has no outstanding erasure, and
   * taking an exclusive lease on every graph to discover that is what this
   * probe exists to avoid. */
  if (rc != WYRELOG_E_OK || pending == 0)
    return rc;

  /* Something is pending, so escalate.  The probe's store handle is already
   * closed -- it never leaves probe_graph_forgets -- so this open cannot
   * contend with it. */
  g_autoptr (wyl_fact_store_t) store = NULL;
  rc = open_graph_store (policy, fact_root, graph_info, TRUE, &store);
  /* NOT_FOUND is not benign here.  The probe just read this store, so a
   * resolver that now reports it missing is an anomaly, not a graph that was
   * never written, and reporting it as convergence would claim an erasure
   * completed that did not. */
  if (rc != WYRELOG_E_OK)
    return rc;
  /* No schema creation here: this runs for every graph at every boot.  A
   * store with no forget ledger has nothing pending, and the reconciler
   * reports that as success rather than as a missing-table error. */
  /* U2-1 threads the outcome out of the reconciler; U2-2 carries it into the
   * replay summary.  Discarded here so this unit stays one behavioural
   * change. */
  wyl_fact_forget_outcome_t outcome = { 0 };
  return wyl_fact_store_forget_reconcile (store, graph_info->tenant_id,
             graph_info->graph_id, NULL, NULL, &outcome);
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
    /* CONVERGED, INCOMPLETE, or no verdict at all -- see the write below. */
    gboolean forget_probed = FALSE;
    gboolean forget_incomplete = FALSE;
    gboolean forget_attempted = FALSE;
    /* Hoisted so the tripwire below can report it: the rc is what separates a
     * lost lease race from a transient resource failure at probe time, and
     * those two produce an identical signal. */
    wyrelog_error_t forget_rc = WYRELOG_E_OK;
    if (fact_root != NULL && fact_root[0] != '\0') {
      forget_attempted = TRUE;
      gboolean opened = FALSE;
      forget_rc = reconcile_graph_forgets (policy, fact_root,
              &spec->info, &opened);
      forget_probed = forget_rc == WYRELOG_E_OK || opened;
      forget_incomplete = forget_rc != WYRELOG_E_OK && opened;
      if (forget_rc != WYRELOG_E_OK) {
        if (opened)
          summary.graphs_forget_reconcile_failed++;
        else
          summary.graphs_forget_probe_unavailable++;
        const gchar *tenant = spec->info.tenant_id != NULL
              ? spec->info.tenant_id : "(unset)";
        const gchar *graph = spec->info.graph_id != NULL
              ? spec->info.graph_id : "(unset)";
        /* The counter alone is not observable: the only in-product caller
         * passes a NULL summary.  An erasure that could not be converged must
         * not be silent, or the daemon comes up reporting ready with data it
         * promised to delete.  Say only what the outcome supports: a store
         * that never opened is not evidence that an erasure is outstanding,
         * and claiming otherwise on every boot of an unopenable graph would
         * bury the case that is. */
        if (opened)
          WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
              "a pending fact forget recorded for tenant %s graph %s could "
              "not be converged: rc=%d; that erasure is still incomplete",
              tenant, graph, (int) forget_rc);
        else
          WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
              "could not open the fact store of tenant %s graph %s to look "
              "for a pending forget: rc=%d", tenant, graph, (int) forget_rc);
      }
    }
    GraphBuildCtx build = { policy, fact_root, &spec->info };
    wyrelog_error_t graph_rc = wyl_fact_graph_runtime_manager_refresh
          (runtime_manager, &spec->key, build_graph_engine, &build, NULL);
    if (graph_rc == WYRELOG_E_OK)
      summary.graphs_loaded++;
    else if (spec->info.sealed)
      /* The refusal is the point, not a failure.  build_graph_engine declines
       * a sealed graph before it opens anything, so this arm costs a hash
       * lookup and no file open -- and the refresh still runs because it is
       * the only thing that materializes the entry, which the admission write
       * below needs and which foreach_status needs to report the graph at
       * all. */
      summary.graphs_sealed++;
    else
      summary.graphs_degraded++;
    /* The forget probe and the engine builder open the same store with
     * byte-identical arguments, so a probe that could not open it while the
     * engine built fine is two identical opens disagreeing.  The bridge makes
     * that possible -- the reader guard takes LOCK_SH|LOCK_NB and can lose to
     * transient contention, the residual shape #870 left behind -- but a lost
     * lease is NOT the only cause.  Any transient resource failure that clears
     * between the two opens produces the identical signal, and EMFILE at probe
     * time is neither bridge-specific nor rare.  That is why the rc is
     * reported: a reader of this counter must be able to tell an exhausted
     * descriptor table from a lost race, because only one of the two is
     * evidence that the population #550 asks about exists.  Report it here,
     * where both outcomes are in hand.
     *
     * Not an assertion: boot must never abort on a graph.  And no status
     * verdict, because we do not know whether an erasure is outstanding --
     * the two opens disagreeing is itself the anomaly worth naming.
     *
     * This line is also the instrument that settles whether the racy window
     * is a population worth its own WylFactGraphForgetState value in #550.
     * If it is ever observed in the field, that population exists; until
     * then, nothing shows it does.
     *
     * forget_attempted is half of the condition, not padding around it.  The
     * state being reported is "the probe ran and was refused, while the engine
     * built", and forget_probed cannot express that on its own: it is FALSE
     * both when a probe was refused and when no probe was ever attempted,
     * which is the same conflation this issue removes one layer up.  Without
     * this term the line would read "the forget block established no verdict",
     * a weaker and different claim than the one above.  (It happens to be
     * inert today -- with no fact root the engine build fails for the same
     * missing root, so graph_rc is not OK either: seen=1 loaded=0 degraded=1.
     * That is why no test discriminates it, not a reason to drop it.) */
    if (forget_attempted && !forget_probed && graph_rc == WYRELOG_E_OK) {
      summary.graphs_forget_probe_disagreed++;
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "the fact store of tenant %s graph %s refused the forget probe "
          "with rc=%d but served the engine build moments later; the "
          "pending-erasure state of that graph was not established",
          spec->info.tenant_id != NULL ? spec->info.tenant_id : "(unset)",
          spec->info.graph_id != NULL ? spec->info.graph_id : "(unset)",
          (int) forget_rc);
    }
    /* After the refresh, never before it.  The setter does not create an
     * entry and refuses a tombstone, so a verdict written earlier is dropped
     * -- NOT_FOUND on a graph the runtime has not built yet, which is every
     * graph of a fresh daemon, or BUSY on one retired by an earlier replay --
     * and the refresh then publishes CONVERGED over it.  Either return from
     * this call means it has been moved to the wrong place.
     *
     * Written on both outcomes, because the CONVERGED zero is only honest if
     * success asserts it: a graph that converges on a later replay must clear
     * itself.  Not written when the store never opened, which is neither
     * outcome -- nothing was learned, and claiming convergence there would be
     * the over-report that #547 removed from the boot log.  Worse, it would
     * erase a standing verdict: a graph already INCOMPLETE whose store then
     * fails to open would be reported converged, which is this issue's own
     * defect arriving through the failure path.
     *
     * Argued, not proved, and the whole choice is unpinned rather than just
     * its reasoning: flipping this to write INCOMPLETE for an unprobed graph
     * passes the entire suite unchanged.  The reason is now stronger than it
     * was when this was written.  Since #869 U1 the forget probe and the
     * engine builder BOTH open read-only (probe_graph_forgets and
     * wyl_fact_replay_open_graph_engine), so they are the same call in every
     * configuration, not only off-bridge: a graph that could not be probed
     * also failed to build and is never mapped through the forget axis.  The
     * write-lease refusal that used to be the one observable state no longer
     * reaches this decision at all, because no write lease is taken unless
     * something is pending.  What remains is the LOCK_SH race the tripwire
     * above counts.  Do not read the green suite as agreement with this
     * decision.
     *
     * The residual this used to leave -- a bridge graph refused a write lease
     * keeping the CONVERGED zero and reporting ready over an unreconciled
     * ledger -- is closed by #869 U1 and no longer applies.  A write lease is
     * requested only after the read-only probe has counted a pending intent,
     * so a refusal now lands with the store opened: graphs_forget_reconcile_
     * failed, an ERROR that survives wyrelog_log_max_level=error, and
     * FORGET_INCOMPLETE.  Do not re-open #870 or #550 on the strength of the
     * older wording. */
    if (forget_probed)
      (void) wyl_fact_graph_runtime_manager_set_forget_state (runtime_manager,
          &spec->key, forget_incomplete ? WYL_FACT_GRAPH_FORGET_INCOMPLETE
          : WYL_FACT_GRAPH_FORGET_CONVERGED);
    /* Re-establish the runtime barrier from the durable bit.  Admission is
     * runtime-only state, so without this a restart reopens every graph the
     * policy store still calls sealed -- a seal survives a crash in policy and
     * not in the runtime.
     *
     * Written in BOTH directions on purpose.  Closing the sealed ones and
     * leaving the rest alone would strand, as permanently closed, any graph
     * unsealed out of band while the daemon was down; the axis has to be a
     * function of the durable bit, not a latch.
     *
         * One ordering is forced and proved: this must follow the refresh,
     * because close_admission deliberately mints no entry and would answer
     * NOT_FOUND for every graph on a fresh manager.  Deleting the refresh
     * fails the suite.
     *
     * A second is argued, not proved.  It must also follow set_forget_state,
     * which refuses an EVICTED entry -- so once the live seal evicts here, an
     * admission write placed ahead of it would leave the axis at its default
     * CONVERGED over an erasure that is still owed.  This loop does not evict,
     * so swapping the two blocks today changes nothing and the suite stays
     * green; verified by doing it.  Whoever adds the eviction owns making
     * that ordering falsifiable.
     *
     * A third an earlier draft claimed is not an ordering at all.  Being
     * before retire_unseen buys nothing: every key here is added to
     * seen_keys, so retirement skips it.
     *
     * The rc is discarded the way set_forget_state's is: NOT_FOUND cannot
     * happen because the refresh above created the entry, and BUSY means
     * shutdown raced the boot pass, which the caller learns from
     * retire_unseen. */
    if (spec->info.sealed) {
      (void) wyl_fact_graph_runtime_manager_close_admission (runtime_manager,
          &spec->key);
      /* Deliberately NOT evicted here.  At boot the sealed graph's refresh
       * already failed, so there is no engine to detach and the only thing an
       * eviction would change is DEGRADED -> EVICTED -- and EVICTED is the
       * one state fact_graph_runtime_status_cb skips, so the graph would
       * disappear from an operator's listing entirely and a query against it
       * would answer NOT_FOUND where it used to answer POLICY.  Trading a
       * wrong entry for a missing one is not an improvement.
       *
       * Eviction belongs to the live seal, where a published engine actually
       * exists to take away, and the sealed state has to arrive on the
       * reporting surface in the same change that starts producing it. */
    } else {
      (void) wyl_fact_graph_runtime_manager_open_admission (runtime_manager,
          &spec->key);
    }
    g_ptr_array_add (seen_keys, &spec->key);
  }
  rc = wyl_fact_graph_runtime_manager_retire_unseen (runtime_manager,
          (const WylFactGraphKey * const *) seen_keys->pdata, seen_keys->len);
  if (out_summary != NULL)
    *out_summary = summary;
  return rc;
}

wyrelog_error_t
wyl_fact_replay_refresh_graph (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactGraphRuntimeStatus *out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof (*out_status));
  if (policy == NULL || graph_info == NULL || graph_info->tenant_id == NULL
      || graph_info->graph_id == NULL || runtime_manager == NULL)
    return WYRELOG_E_INVALID;

  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Refresh ONLY this one key.  This deliberately never calls
   * retire_unseen or foreach-refresh: a targeted post-mutation refresh must
   * leave every sibling graph's runtime entry and generation untouched
   * (issue #546 isolation), and retiring on a one-element seen set would
   * detach all other entries. */
  GraphBuildCtx build = { policy, fact_root, graph_info };
  rc = wyl_fact_graph_runtime_manager_refresh (runtime_manager, &key,
          build_graph_engine, &build, out_status);
  wyl_fact_graph_key_clear (&key);
  return rc;
}

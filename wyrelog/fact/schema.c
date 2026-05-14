/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "schema-private.h"

#include <string.h>

static void
set_reason (gchar **out_reason, const gchar *reason)
{
  if (out_reason != NULL)
    *out_reason = g_strdup (reason);
}

static gboolean
value_matches_column (const wyl_fact_value_t *value,
    const wyl_policy_fact_relation_schema_column_info_t *column)
{
  if (value->type == WYL_FACT_VALUE_NULL)
    return column->nullable;
  if (g_strcmp0 (column->column_type, "symbol") == 0)
    return value->type == WYL_FACT_VALUE_SYMBOL && value->as.text != NULL;
  if (g_strcmp0 (column->column_type, "string") == 0)
    return value->type == WYL_FACT_VALUE_STRING && value->as.text != NULL;
  if (g_strcmp0 (column->column_type, "int64") == 0)
    return value->type == WYL_FACT_VALUE_INT64;
  if (g_strcmp0 (column->column_type, "bool") == 0)
    return value->type == WYL_FACT_VALUE_BOOL;
  if (g_strcmp0 (column->column_type, "compound_ref") == 0)
    return value->type == WYL_FACT_VALUE_COMPOUND_REF;
  return FALSE;
}

wyrelog_error_t
wyl_fact_schema_validate_batch (wyl_policy_store_t *store,
    const wyl_fact_batch_t *batch, gchar **out_reason)
{
  gboolean relation_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *columns = NULL;
  gsize n_columns = 0;

  if (out_reason != NULL)
    *out_reason = NULL;
  if (store == NULL || batch == NULL || batch->tenant_id == NULL
      || batch->graph_id == NULL || batch->namespace_id == NULL
      || batch->relation_name == NULL || batch->schema_version == 0
      || (batch->rows == NULL && batch->n_rows > 0)) {
    set_reason (out_reason, "invalid batch");
    return WYRELOG_E_INVALID;
  }

  gboolean graph_active = FALSE;
  wyrelog_error_t rc = wyl_policy_store_fact_graph_is_active (store,
      batch->tenant_id, batch->graph_id, &graph_active);
  if (rc != WYRELOG_E_OK) {
    set_reason (out_reason, "invalid graph scope");
    return rc;
  }
  if (!graph_active) {
    set_reason (out_reason, "fact graph not active");
    return WYRELOG_E_NOT_FOUND;
  }

  rc = wyl_policy_store_load_fact_relation_schema_columns
      (store, batch->tenant_id, batch->graph_id, batch->namespace_id,
      batch->relation_name, batch->schema_version, &relation_visible,
      &columns, &n_columns);
  if (rc != WYRELOG_E_OK) {
    set_reason (out_reason, "relation schema not found");
    return rc;
  }
  (void) relation_visible;

  for (gsize i = 0; i < batch->n_rows; i++) {
    const wyl_fact_row_t *row = &batch->rows[i];
    if (row->values == NULL || row->n_values != n_columns) {
      wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
      set_reason (out_reason, "fact row arity mismatch");
      return WYRELOG_E_POLICY;
    }
    for (gsize j = 0; j < n_columns; j++) {
      if (!value_matches_column (&row->values[j], &columns[j])) {
        wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
        set_reason (out_reason, "fact row type mismatch");
        return WYRELOG_E_POLICY;
      }
    }
  }

  wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
  return WYRELOG_E_OK;
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

static const gchar *
duckdb_type_for_column (const gchar *column_type)
{
  if (g_strcmp0 (column_type, "symbol") == 0
      || g_strcmp0 (column_type, "string") == 0)
    return "VARCHAR";
  if (g_strcmp0 (column_type, "int64") == 0)
    return "BIGINT";
  if (g_strcmp0 (column_type, "bool") == 0)
    return "BOOLEAN";
  if (g_strcmp0 (column_type, "compound_ref") == 0)
    return "BIGINT";
  return NULL;
}

static const gchar *
wirelog_type_for_column (const gchar *column_type)
{
  if (g_strcmp0 (column_type, "symbol") == 0
      || g_strcmp0 (column_type, "string") == 0)
    return "symbol";
  if (g_strcmp0 (column_type, "int64") == 0
      || g_strcmp0 (column_type, "compound_ref") == 0)
    return "int64";
  if (g_strcmp0 (column_type, "bool") == 0)
    return "bool";
  return NULL;
}

static void
append_wirelog_identifier (GString *out, const gchar *identifier)
{
  if (identifier == NULL || identifier[0] == '\0') {
    g_string_append_c (out, 'w');
    return;
  }

  g_string_append_c (out, 'w');
  for (const gchar * p = identifier; *p != '\0'; p++) {
    guchar c = (guchar) * p;
    g_string_append_printf (out, "_%02x", c);
  }
}

gchar *
wyl_fact_schema_build_duckdb_projection_ddl (const
    wyl_policy_fact_relation_schema_options_t *opts)
{
  if (opts == NULL || opts->tenant_id == NULL || opts->graph_id == NULL
      || opts->namespace_id == NULL || opts->relation_name == NULL
      || opts->schema_version == 0 || opts->columns == NULL
      || opts->n_columns == 0)
    return NULL;

  g_autoptr (GString) out = g_string_new ("CREATE TABLE IF NOT EXISTS ");
  g_autofree gchar *table = g_strdup_printf ("%s__%s__%s__%s_v%u",
      opts->tenant_id, opts->graph_id, opts->namespace_id,
      opts->relation_name, opts->schema_version);
  append_duckdb_identifier (out, table);
  g_string_append (out, " (");
  for (gsize i = 0; i < opts->n_columns; i++) {
    const gchar *duck_type =
        duckdb_type_for_column (opts->columns[i].column_type);
    if (duck_type == NULL)
      return NULL;
    if (i > 0)
      g_string_append (out, ", ");
    append_duckdb_identifier (out, opts->columns[i].column_name);
    g_string_append_printf (out, " %s%s", duck_type,
        opts->columns[i].nullable ? "" : " NOT NULL");
  }
  g_string_append (out, ");");
  return g_string_free (g_steal_pointer (&out), FALSE);
}

gchar *
wyl_fact_schema_build_wirelog_declaration (const
    wyl_policy_fact_relation_schema_options_t *opts)
{
  if (opts == NULL || opts->namespace_id == NULL || opts->relation_name == NULL
      || opts->columns == NULL || opts->n_columns == 0)
    return NULL;

  g_autoptr (GString) out = g_string_new (".decl ");
  append_wirelog_identifier (out, opts->namespace_id);
  g_string_append_c (out, '_');
  append_wirelog_identifier (out, opts->relation_name);
  g_string_append_c (out, '(');
  for (gsize i = 0; i < opts->n_columns; i++) {
    const gchar *wirelog_type = wirelog_type_for_column
        (opts->columns[i].column_type);
    if (wirelog_type == NULL)
      return NULL;
    if (i > 0)
      g_string_append (out, ", ");
    append_wirelog_identifier (out, opts->columns[i].column_name);
    g_string_append_printf (out, ": %s", wirelog_type);
  }
  g_string_append_c (out, ')');
  return g_string_free (g_steal_pointer (&out), FALSE);
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "query-private.h"

#include <errno.h>
#include <string.h>

#include "replay-private.h"
#include "wyrelog/wyl-engine-private.h"
#include "wyrelog/policy/store-private.h"

#define WYL_FACT_DATALOG_QUERY_MAX_LEN 512
#define WYL_FACT_DATALOG_MAX_ARGS 32
#define WYL_FACT_DATALOG_HARD_ROW_LIMIT 1000

typedef enum
{
  QUERY_ARG_VARIABLE,
  QUERY_ARG_WILDCARD,
  QUERY_ARG_STRING,
  QUERY_ARG_INT64,
  QUERY_ARG_BOOL,
} QueryArgKind;

typedef struct
{
  QueryArgKind kind;
  gchar *text;
  gint64 i64;
  gboolean boolean;
} QueryArg;

typedef struct
{
  gchar *name;
  QueryArg args[WYL_FACT_DATALOG_MAX_ARGS];
  gsize n_args;
} ParsedQuery;

typedef struct
{
  const ParsedQuery *parsed;
  const wyl_policy_fact_relation_schema_column_info_t *columns;
  gsize n_columns;
  guint limit;
  GString *rows_json;
  guint row_count;
  gboolean truncated;
} CollectCtx;

static void
append_json_string_local (GString *json, const gchar *value)
{
  g_string_append_c (json, '"');
  for (const guchar * p = (const guchar *)(value != NULL ? value : "");
      *p != '\0'; p++) {
    switch (*p) {
      case '"':
        g_string_append (json, "\\\"");
        break;
      case '\\':
        g_string_append (json, "\\\\");
        break;
      case '\b':
        g_string_append (json, "\\b");
        break;
      case '\f':
        g_string_append (json, "\\f");
        break;
      case '\n':
        g_string_append (json, "\\n");
        break;
      case '\r':
        g_string_append (json, "\\r");
        break;
      case '\t':
        g_string_append (json, "\\t");
        break;
      default:
        if (*p < 0x20)
          g_string_append_printf (json, "\\u%04x", *p);
        else
          g_string_append_c (json, (gchar) * p);
        break;
    }
  }
  g_string_append_c (json, '"');
}

static gboolean
customer_name_is_valid (const gchar *value)
{
  if (value == NULL || value[0] == '\0' || g_str_has_prefix (value, "wr."))
    return FALSE;
  for (const gchar * p = value; *p != '\0'; p++) {
    if (!(g_ascii_isalnum (*p) || *p == '_' || *p == '-' || *p == '.'))
      return FALSE;
  }
  return TRUE;
}

static void
parsed_query_clear (ParsedQuery *parsed)
{
  if (parsed == NULL)
    return;
  g_free (parsed->name);
  for (gsize i = 0; i < parsed->n_args; i++)
    g_free (parsed->args[i].text);
  memset (parsed, 0, sizeof (*parsed));
}

static const gchar *
skip_ws (const gchar *p)
{
  while (p != NULL && g_ascii_isspace (*p))
    p++;
  return p;
}

static gboolean
parse_identifier (const gchar **cursor, gchar **out_ident)
{
  const gchar *p = *cursor;
  if (!(g_ascii_isalpha (*p) || *p == '_'))
    return FALSE;
  const gchar *start = p++;
  while (g_ascii_isalnum (*p) || *p == '_' || *p == '-' || *p == '.')
    p++;
  *out_ident = g_strndup (start, (gsize) (p - start));
  *cursor = p;
  return *out_ident != NULL;
}

static gboolean
parse_quoted_string (const gchar **cursor, gchar **out)
{
  const gchar *p = *cursor;
  if (*p != '"')
    return FALSE;
  p++;
  g_autoptr (GString) value = g_string_new (NULL);
  while (*p != '\0' && *p != '"') {
    if ((guchar) * p < 0x20 || *p == '\\')
      return FALSE;
    g_string_append_c (value, *p++);
  }
  if (*p != '"')
    return FALSE;
  *cursor = p + 1;
  *out = g_string_free (g_steal_pointer (&value), FALSE);
  return *out != NULL;
}

static gboolean
parse_int64_literal (const gchar **cursor, gint64 *out)
{
  const gchar *p = *cursor;
  if (*p != '-' && !g_ascii_isdigit (*p))
    return FALSE;
  errno = 0;
  gchar *end = NULL;
  gint64 value = g_ascii_strtoll (p, &end, 10);
  if (errno != 0 || end == p)
    return FALSE;
  *cursor = end;
  *out = value;
  return TRUE;
}

static gboolean
parse_query_arg (const gchar **cursor, QueryArg *arg)
{
  const gchar *p = skip_ws (*cursor);
  memset (arg, 0, sizeof (*arg));
  if (*p == '_') {
    arg->kind = QUERY_ARG_WILDCARD;
    *cursor = p + 1;
    return TRUE;
  }
  if (*p == '"') {
    arg->kind = QUERY_ARG_STRING;
    if (!parse_quoted_string (&p, &arg->text))
      return FALSE;
    *cursor = p;
    return TRUE;
  }
  if (g_str_has_prefix (p, "true") && !g_ascii_isalnum (p[4]) && p[4] != '_') {
    arg->kind = QUERY_ARG_BOOL;
    arg->boolean = TRUE;
    *cursor = p + 4;
    return TRUE;
  }
  if (g_str_has_prefix (p, "false") && !g_ascii_isalnum (p[5]) && p[5] != '_') {
    arg->kind = QUERY_ARG_BOOL;
    arg->boolean = FALSE;
    *cursor = p + 5;
    return TRUE;
  }
  if (*p == '-' || g_ascii_isdigit (*p)) {
    arg->kind = QUERY_ARG_INT64;
    if (!parse_int64_literal (&p, &arg->i64))
      return FALSE;
    *cursor = p;
    return TRUE;
  }
  if (g_ascii_isupper (*p)) {
    arg->kind = QUERY_ARG_VARIABLE;
    if (!parse_identifier (&p, &arg->text))
      return FALSE;
    *cursor = p;
    return TRUE;
  }
  return FALSE;
}

static gboolean
parse_relation_atom (const gchar *query, ParsedQuery *out)
{
  if (query == NULL || strlen (query) > WYL_FACT_DATALOG_QUERY_MAX_LEN)
    return FALSE;
  if (strstr (query, ":-") != NULL || strstr (query, ".decl") != NULL ||
      strchr (query, ';') != NULL)
    return FALSE;

  const gchar *p = skip_ws (query);
  memset (out, 0, sizeof (*out));
  if (!parse_identifier (&p, &out->name) || !customer_name_is_valid (out->name))
    goto fail;
  p = skip_ws (p);
  if (*p != '(')
    goto fail;
  p++;
  p = skip_ws (p);
  if (*p == ')')
    goto fail;
  while (*p != '\0') {
    if (out->n_args >= WYL_FACT_DATALOG_MAX_ARGS)
      goto fail;
    if (!parse_query_arg (&p, &out->args[out->n_args]))
      goto fail;
    out->n_args++;
    p = skip_ws (p);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == ')') {
      p++;
      break;
    }
    goto fail;
  }
  p = skip_ws (p);
  if (*p != '\0')
    goto fail;
  return TRUE;

fail:
  parsed_query_clear (out);
  return FALSE;
}

static gboolean
schema_value_matches (WylEngine *engine,
    const wyl_policy_fact_relation_schema_column_info_t *column,
    const QueryArg *arg, gint64 cell)
{
  if (arg->kind == QUERY_ARG_WILDCARD || arg->kind == QUERY_ARG_VARIABLE)
    return TRUE;
  if (g_strcmp0 (column->column_type, "symbol") == 0 ||
      g_strcmp0 (column->column_type, "string") == 0) {
    if (arg->kind != QUERY_ARG_STRING)
      return FALSE;
    g_autofree gchar *value = wyl_engine_owned_dup_interned_symbol (engine,
        cell);
    return g_strcmp0 (value, arg->text) == 0;
  }
  if (g_strcmp0 (column->column_type, "int64") == 0)
    return arg->kind == QUERY_ARG_INT64 && arg->i64 == cell;
  if (g_strcmp0 (column->column_type, "bool") == 0)
    return arg->kind == QUERY_ARG_BOOL && (arg->boolean ? 1 : 0) == cell;
  return FALSE;
}

static gboolean
row_satisfies_query (WylEngine *engine, const CollectCtx *ctx,
    const gint64 *row)
{
  g_autoptr (GHashTable) variable_values =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  for (gsize i = 0; i < ctx->n_columns; i++) {
    const QueryArg *arg = &ctx->parsed->args[i];
    if (!schema_value_matches (engine, &ctx->columns[i], arg, row[i]))
      return FALSE;
    if (arg->kind == QUERY_ARG_VARIABLE) {
      gint64 *existing = g_hash_table_lookup (variable_values, arg->text);
      if (existing != NULL) {
        if (*existing != row[i])
          return FALSE;
      } else {
        gint64 *copy = g_new (gint64, 1);
        *copy = row[i];
        g_hash_table_insert (variable_values, g_strdup (arg->text), copy);
      }
    }
  }
  return TRUE;
}

static void
append_cell_json (GString *json, WylEngine *engine,
    const wyl_policy_fact_relation_schema_column_info_t *column, gint64 cell)
{
  if (g_strcmp0 (column->column_type, "symbol") == 0 ||
      g_strcmp0 (column->column_type, "string") == 0) {
    g_autofree gchar *value = wyl_engine_owned_dup_interned_symbol (engine,
        cell);
    append_json_string_local (json, value != NULL ? value : "");
  } else if (g_strcmp0 (column->column_type, "bool") == 0) {
    g_string_append (json, cell != 0 ? "true" : "false");
  } else {
    g_string_append_printf (json, "%" G_GINT64_FORMAT, cell);
  }
}

static gboolean
query_arg_is_emitted_variable (const ParsedQuery *parsed, gsize index)
{
  if (parsed->args[index].kind != QUERY_ARG_VARIABLE)
    return FALSE;
  for (gsize i = 0; i < index; i++) {
    if (parsed->args[i].kind == QUERY_ARG_VARIABLE &&
        g_strcmp0 (parsed->args[i].text, parsed->args[index].text) == 0)
      return FALSE;
  }
  return TRUE;
}

static void
collect_tuple (WylEngine *engine, const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  (void) relation;
  CollectCtx *ctx = user_data;
  if (ctx->truncated || ncols != ctx->n_columns)
    return;
  if (!row_satisfies_query (engine, ctx, row))
    return;
  if (ctx->row_count >= ctx->limit) {
    ctx->truncated = TRUE;
    return;
  }
  if (ctx->row_count > 0)
    g_string_append_c (ctx->rows_json, ',');
  g_string_append_c (ctx->rows_json, '{');
  gboolean first = TRUE;
  for (gsize i = 0; i < ctx->n_columns; i++) {
    if (!query_arg_is_emitted_variable (ctx->parsed, i))
      continue;
    if (!first)
      g_string_append_c (ctx->rows_json, ',');
    first = FALSE;
    append_json_string_local (ctx->rows_json, ctx->parsed->args[i].text);
    g_string_append_c (ctx->rows_json, ':');
    append_cell_json (ctx->rows_json, engine, &ctx->columns[i], row[i]);
  }
  g_string_append_c (ctx->rows_json, '}');
  ctx->row_count++;
}

static gboolean
schema_is_query_visible (const wyl_policy_fact_relation_schema_column_info_t
    *cols, gsize n_cols)
{
  for (gsize i = 0; i < n_cols; i++) {
    if (!cols[i].visible)
      return FALSE;
    if (g_strcmp0 (cols[i].column_type, "compound_ref") == 0)
      return FALSE;
  }
  return TRUE;
}

wyrelog_error_t
wyl_fact_datalog_query_json (WylHandle *handle,
    const wyl_fact_datalog_query_options_t *opts, gchar **out_json,
    gboolean *out_truncated, guint *out_row_count, gchar **out_query_name)
{
  if (out_json != NULL)
    *out_json = NULL;
  if (out_truncated != NULL)
    *out_truncated = FALSE;
  if (out_row_count != NULL)
    *out_row_count = 0;
  if (out_query_name != NULL)
    *out_query_name = NULL;
  if (handle == NULL || opts == NULL || out_json == NULL ||
      opts->tenant_id == NULL || opts->graph_id == NULL || opts->query == NULL)
    return WYRELOG_E_INVALID;

  ParsedQuery parsed = { 0 };
  if (!parse_relation_atom (opts->query, &parsed))
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_policy_fact_relation_query_info_t query_info = { 0 };
  wyrelog_error_t rc = wyl_policy_store_load_fact_relation_query (store,
      opts->tenant_id, opts->graph_id, parsed.name, &query_info);
  if (rc != WYRELOG_E_OK) {
    parsed_query_clear (&parsed);
    return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
  }
  if (g_strcmp0 (query_info.required_permission_id, "wr.datalog.query") != 0) {
    wyl_policy_fact_relation_query_info_clear (&query_info);
    parsed_query_clear (&parsed);
    return WYRELOG_E_POLICY;
  }

  gboolean relation_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *columns = NULL;
  gsize n_columns = 0;
  rc = wyl_policy_store_load_fact_relation_schema_columns (store,
      opts->tenant_id, opts->graph_id, query_info.namespace_id,
      query_info.relation_name, query_info.schema_version, &relation_visible,
      &columns, &n_columns);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_fact_relation_query_info_clear (&query_info);
    parsed_query_clear (&parsed);
    return rc;
  }
  if (!relation_visible || parsed.n_args != n_columns ||
      !schema_is_query_visible (columns, n_columns)) {
    wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
    wyl_policy_fact_relation_query_info_clear (&query_info);
    parsed_query_clear (&parsed);
    return WYRELOG_E_POLICY;
  }

  guint limit = opts->limit == 0 ? query_info.max_rows : opts->limit;
  limit = MIN (limit, query_info.max_rows);
  limit = MIN (limit, (guint) WYL_FACT_DATALOG_HARD_ROW_LIMIT);
  if (limit == 0)
    limit = 1;

  g_autoptr (GString) rows = g_string_new (NULL);
  CollectCtx ctx = {
    .parsed = &parsed,
    .columns = columns,
    .n_columns = n_columns,
    .limit = limit,
    .rows_json = rows,
  };
  g_autofree gchar *wire_relation = wyl_fact_replay_wirelog_relation_name
      (query_info.namespace_id, query_info.relation_name);
  g_autofree gchar *snapshot_relation =
      wire_relation != NULL ? g_strdup_printf ("%s_observed", wire_relation) :
      NULL;
  if (wire_relation == NULL)
    rc = WYRELOG_E_NOMEM;
  else
    rc = wyl_handle_snapshot_fact_graph_relation (handle, opts->tenant_id,
        opts->graph_id, snapshot_relation, collect_tuple, &ctx);

  if (rc == WYRELOG_E_OK) {
    g_autoptr (GString) body = g_string_new ("{\"ok\":true,\"tenant_id\":");
    append_json_string_local (body, opts->tenant_id);
    g_string_append (body, ",\"graph_id\":");
    append_json_string_local (body, opts->graph_id);
    g_string_append (body, ",\"query_id\":");
    append_json_string_local (body,
        opts->query_id != NULL ? opts->query_id : "");
    g_string_append (body, ",\"relation\":");
    append_json_string_local (body, parsed.name);
    g_string_append (body, ",\"columns\":[");
    gboolean first = TRUE;
    for (gsize i = 0; i < n_columns; i++) {
      if (!query_arg_is_emitted_variable (&parsed, i))
        continue;
      if (!first)
        g_string_append_c (body, ',');
      first = FALSE;
      append_json_string_local (body, parsed.args[i].text);
    }
    g_string_append (body, "],\"rows\":[");
    g_string_append_len (body, rows->str, rows->len);
    g_string_append_printf (body, "],\"row_count\":%u,\"truncated\":%s}",
        ctx.row_count, ctx.truncated ? "true" : "false");
    *out_json = g_string_free (g_steal_pointer (&body), FALSE);
    if (out_truncated != NULL)
      *out_truncated = ctx.truncated;
    if (out_row_count != NULL)
      *out_row_count = ctx.row_count;
    if (out_query_name != NULL)
      *out_query_name = g_strdup (parsed.name);
  }

  wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
  wyl_policy_fact_relation_query_info_clear (&query_info);
  parsed_query_clear (&parsed);
  return rc;
}

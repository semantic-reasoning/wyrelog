/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "compound-private.h"

#include <duckdb.h>
#include <string.h>

#include "store-private.h"
#include "wyrelog/wyl-engine-private.h"

#define WYL_FACT_COMPOUND_MAX_DEPTH 32

static const gchar *
arg_type_name (wyl_fact_compound_arg_type_t type)
{
  switch (type) {
    case WYL_FACT_COMPOUND_ARG_SYMBOL:
      return "symbol";
    case WYL_FACT_COMPOUND_ARG_STRING:
      return "string";
    case WYL_FACT_COMPOUND_ARG_INT64:
      return "int64";
    case WYL_FACT_COMPOUND_ARG_BOOL:
      return "bool";
    case WYL_FACT_COMPOUND_ARG_COMPOUND_REF:
      return "compound_ref";
    default:
      return NULL;
  }
}

static gboolean
arg_type_from_name (const gchar *name, wyl_fact_compound_arg_type_t *out_type)
{
  if (g_strcmp0 (name, "symbol") == 0)
    *out_type = WYL_FACT_COMPOUND_ARG_SYMBOL;
  else if (g_strcmp0 (name, "string") == 0)
    *out_type = WYL_FACT_COMPOUND_ARG_STRING;
  else if (g_strcmp0 (name, "int64") == 0)
    *out_type = WYL_FACT_COMPOUND_ARG_INT64;
  else if (g_strcmp0 (name, "bool") == 0)
    *out_type = WYL_FACT_COMPOUND_ARG_BOOL;
  else if (g_strcmp0 (name, "compound_ref") == 0)
    *out_type = WYL_FACT_COMPOUND_ARG_COMPOUND_REF;
  else
    return FALSE;
  return TRUE;
}

static gboolean
value_shape_valid (const wyl_fact_compound_value_t *value)
{
  if (value == NULL || value->tenant_id == NULL || value->graph_id == NULL
      || value->namespace_id == NULL || value->functor == NULL
      || value->functor[0] == '\0' || value->args == NULL
      || value->n_args == 0 || value->n_args > G_MAXUINT32)
    return FALSE;
  for (gsize i = 0; i < value->n_args; i++) {
    const wyl_fact_compound_arg_t *arg = &value->args[i];
    if (arg_type_name (arg->type) == NULL)
      return FALSE;
    if ((arg->type == WYL_FACT_COMPOUND_ARG_SYMBOL
            || arg->type == WYL_FACT_COMPOUND_ARG_STRING)
        && (arg->as.text == NULL || arg->as.text[0] == '\0'))
      return FALSE;
    if (arg->type == WYL_FACT_COMPOUND_ARG_COMPOUND_REF
        && arg->as.compound_ref <= 0)
      return FALSE;
  }
  return TRUE;
}

static void
checksum_bytes (GChecksum *checksum, const gchar *tag, const gchar *value,
    gsize len)
{
  gchar len_buf[64];
  g_snprintf (len_buf, sizeof (len_buf), "%zu", len);
  g_checksum_update (checksum, (const guchar *) tag, strlen (tag));
  g_checksum_update (checksum, (const guchar *) ":", 1);
  g_checksum_update (checksum, (const guchar *) len_buf, strlen (len_buf));
  g_checksum_update (checksum, (const guchar *) ":", 1);
  g_checksum_update (checksum, (const guchar *) value, len);
  g_checksum_update (checksum, (const guchar *) ";", 1);
}

static void
checksum_string (GChecksum *checksum, const gchar *value)
{
  checksum_bytes (checksum, "s", value, strlen (value));
}

static void
checksum_i64_text (GChecksum *checksum, gint64 value)
{
  gchar buf[64];
  g_snprintf (buf, sizeof (buf), "%" G_GINT64_FORMAT, value);
  checksum_bytes (checksum, "i", buf, strlen (buf));
}

static gchar *
compound_hash (const wyl_fact_compound_value_t *value)
{
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL)
    return NULL;
  checksum_string (checksum, "wyl-fact-compound-v1");
  checksum_string (checksum, value->tenant_id);
  checksum_string (checksum, value->graph_id);
  checksum_string (checksum, value->namespace_id);
  checksum_string (checksum, value->functor);
  checksum_i64_text (checksum, (gint64) value->n_args);
  for (gsize i = 0; i < value->n_args; i++) {
    const wyl_fact_compound_arg_t *arg = &value->args[i];
    checksum_i64_text (checksum, (gint64) i);
    checksum_string (checksum, arg_type_name (arg->type));
    switch (arg->type) {
      case WYL_FACT_COMPOUND_ARG_SYMBOL:
      case WYL_FACT_COMPOUND_ARG_STRING:
        checksum_string (checksum, arg->as.text);
        break;
      case WYL_FACT_COMPOUND_ARG_INT64:
        checksum_i64_text (checksum, arg->as.int64_value);
        break;
      case WYL_FACT_COMPOUND_ARG_BOOL:
        checksum_string (checksum, arg->as.bool_value ? "true" : "false");
        break;
      case WYL_FACT_COMPOUND_ARG_COMPOUND_REF:
        checksum_i64_text (checksum, arg->as.compound_ref);
        break;
      default:
        return NULL;
    }
  }
  return g_strdup (g_checksum_get_string (checksum));
}

static gint64
compound_ref_from_hash (const gchar *hash)
{
  guint64 value = 0;
  for (gsize i = 0; i < 16 && hash[i] != '\0'; i++) {
    value <<= 4;
    if (hash[i] >= '0' && hash[i] <= '9')
      value |= (guint64) (hash[i] - '0');
    else if (hash[i] >= 'a' && hash[i] <= 'f')
      value |= (guint64) (hash[i] - 'a' + 10);
    else if (hash[i] >= 'A' && hash[i] <= 'F')
      value |= (guint64) (hash[i] - 'A' + 10);
  }
  value &= (guint64) G_MAXINT64;
  if (value == 0)
    value = 1;
  return (gint64) value;
}

static wyrelog_error_t
exec_sql (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result = { 0 };
  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
metadata_value_unlocked (duckdb_connection conn, const gchar *key,
    gchar **out_value)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  *out_value = NULL;
  if (duckdb_prepare (conn,
          "SELECT value FROM fact_store_metadata WHERE key = ?;", &stmt)
      != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, key) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) > 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  if (duckdb_row_count (&result) == 1) {
    gchar *value = duckdb_value_varchar (&result, 0, 0);
    *out_value = g_strdup (value);
    duckdb_free (value);
    if (*out_value == NULL) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_NOMEM;
    }
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
insert_metadata_unlocked (duckdb_connection conn, const gchar *key,
    const gchar *value)
{
  duckdb_prepared_statement stmt = NULL;
  if (duckdb_prepare (conn,
          "INSERT INTO fact_store_metadata (key, value) VALUES (?, ?);",
          &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, key)
      | duckdb_bind_varchar (stmt, 2, value);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
validate_scope_unlocked (duckdb_connection conn, const gchar *tenant_id,
    const gchar *graph_id, gboolean bind_if_empty)
{
  g_autofree gchar *store_kind = NULL;
  wyrelog_error_t rc = metadata_value_unlocked (conn, "store_kind",
      &store_kind);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (g_strcmp0 (store_kind, "wyrelog.fact") != 0)
    return WYRELOG_E_POLICY;

  g_autofree gchar *stored_tenant = NULL;
  g_autofree gchar *stored_graph = NULL;
  rc = metadata_value_unlocked (conn, "tenant_id", &stored_tenant);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = metadata_value_unlocked (conn, "graph_id", &stored_graph);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((stored_tenant == NULL) != (stored_graph == NULL))
    return WYRELOG_E_POLICY;
  if (stored_tenant == NULL) {
    if (!bind_if_empty)
      return WYRELOG_E_POLICY;
    rc = insert_metadata_unlocked (conn, "tenant_id", tenant_id);
    if (rc == WYRELOG_E_OK)
      rc = insert_metadata_unlocked (conn, "graph_id", graph_id);
    return rc;
  }
  return g_strcmp0 (stored_tenant, tenant_id) == 0
      && g_strcmp0 (stored_graph, graph_id) == 0 ? WYRELOG_E_OK :
      WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_compound_create_schema (wyl_fact_store_t *store)
{
  if (store == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_store_create_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  duckdb_connection conn = wyl_fact_store_get_connection (store);
  wyl_fact_store_lock (store);
  rc = exec_sql (conn,
      "CREATE TABLE IF NOT EXISTS compound_terms ("
      "  compound_ref BIGINT PRIMARY KEY,"
      "  tenant_id VARCHAR NOT NULL,"
      "  graph_id VARCHAR NOT NULL,"
      "  namespace_id VARCHAR NOT NULL,"
      "  functor VARCHAR NOT NULL,"
      "  arity BIGINT NOT NULL,"
      "  content_hash VARCHAR NOT NULL UNIQUE,"
      "  created_at_us BIGINT NOT NULL"
      ");"
      "CREATE TABLE IF NOT EXISTS compound_args ("
      "  compound_ref BIGINT NOT NULL,"
      "  arg_index BIGINT NOT NULL,"
      "  arg_type VARCHAR NOT NULL CHECK (arg_type IN "
      "('symbol', 'string', 'int64', 'bool', 'compound_ref')),"
      "  symbol_value VARCHAR,"
      "  string_value VARCHAR,"
      "  int64_value BIGINT,"
      "  bool_value BOOLEAN,"
      "  child_compound_ref BIGINT,"
      "  PRIMARY KEY (compound_ref, arg_index),"
      "  FOREIGN KEY (compound_ref) REFERENCES compound_terms (compound_ref)"
      ");");
  wyl_fact_store_unlock (store);
  return rc;
}

static wyrelog_error_t
compound_exists_unlocked (duckdb_connection conn, const gchar *tenant_id,
    const gchar *graph_id, const gchar *namespace_id, gint64 compound_ref,
    gboolean *out_exists)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  *out_exists = FALSE;
  if (duckdb_prepare (conn,
          "SELECT COUNT(*) FROM compound_terms WHERE tenant_id = ? "
          "AND graph_id = ? AND namespace_id = ? AND compound_ref = ?;",
          &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, tenant_id)
      | duckdb_bind_varchar (stmt, 2, graph_id)
      | duckdb_bind_varchar (stmt, 3, namespace_id)
      | duckdb_bind_int64 (stmt, 4, compound_ref);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  *out_exists = duckdb_value_int64 (&result, 0, 0) == 1;
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
compound_hash_matches_unlocked (duckdb_connection conn, const gchar *tenant_id,
    const gchar *graph_id, const gchar *namespace_id, gint64 compound_ref,
    const gchar *expected_hash, gboolean *out_matches)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  *out_matches = FALSE;
  if (duckdb_prepare (conn,
          "SELECT content_hash FROM compound_terms WHERE tenant_id = ? "
          "AND graph_id = ? AND namespace_id = ? AND compound_ref = ?;",
          &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, tenant_id)
      | duckdb_bind_varchar (stmt, 2, graph_id)
      | duckdb_bind_varchar (stmt, 3, namespace_id)
      | duckdb_bind_int64 (stmt, 4, compound_ref);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  gchar *stored_hash = duckdb_value_varchar (&result, 0, 0);
  *out_matches = g_strcmp0 (stored_hash, expected_hash) == 0;
  duckdb_free (stored_hash);
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_compound_ref_exists (wyl_fact_store_t *store, const gchar *tenant_id,
    const gchar *graph_id, const gchar *namespace_id, gint64 compound_ref,
    gboolean *out_exists)
{
  if (out_exists != NULL)
    *out_exists = FALSE;
  if (store == NULL || tenant_id == NULL || graph_id == NULL
      || namespace_id == NULL || compound_ref <= 0 || out_exists == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_compound_create_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  wyl_fact_store_lock (store);
  rc = validate_scope_unlocked (conn, tenant_id, graph_id, FALSE);
  if (rc == WYRELOG_E_OK)
    rc = compound_exists_unlocked (conn, tenant_id, graph_id, namespace_id,
        compound_ref, out_exists);
  wyl_fact_store_unlock (store);
  return rc;
}

static wyrelog_error_t
insert_term_unlocked (duckdb_connection conn,
    const wyl_fact_compound_value_t *value, gint64 compound_ref,
    const gchar *hash)
{
  duckdb_prepared_statement stmt = NULL;
  if (duckdb_prepare (conn,
          "INSERT INTO compound_terms "
          "(compound_ref, tenant_id, graph_id, namespace_id, functor, arity, "
          " content_hash, created_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
          &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  duckdb_state ok = duckdb_bind_int64 (stmt, 1, compound_ref)
      | duckdb_bind_varchar (stmt, 2, value->tenant_id)
      | duckdb_bind_varchar (stmt, 3, value->graph_id)
      | duckdb_bind_varchar (stmt, 4, value->namespace_id)
      | duckdb_bind_varchar (stmt, 5, value->functor)
      | duckdb_bind_int64 (stmt, 6, (gint64) value->n_args)
      | duckdb_bind_varchar (stmt, 7, hash)
      | duckdb_bind_int64 (stmt, 8, g_get_real_time ());
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_arg_unlocked (duckdb_connection conn, gint64 compound_ref, gsize index,
    const wyl_fact_compound_arg_t *arg)
{
  duckdb_prepared_statement stmt = NULL;
  if (duckdb_prepare (conn,
          "INSERT INTO compound_args "
          "(compound_ref, arg_index, arg_type, symbol_value, string_value, "
          " int64_value, bool_value, child_compound_ref) "
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?);", &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  const gchar *type_name = arg_type_name (arg->type);
  duckdb_state ok = duckdb_bind_int64 (stmt, 1, compound_ref)
      | duckdb_bind_int64 (stmt, 2, (gint64) index)
      | duckdb_bind_varchar (stmt, 3, type_name);
  if (arg->type == WYL_FACT_COMPOUND_ARG_SYMBOL)
    ok |= duckdb_bind_varchar (stmt, 4, arg->as.text);
  else
    ok |= duckdb_bind_null (stmt, 4);
  if (arg->type == WYL_FACT_COMPOUND_ARG_STRING)
    ok |= duckdb_bind_varchar (stmt, 5, arg->as.text);
  else
    ok |= duckdb_bind_null (stmt, 5);
  if (arg->type == WYL_FACT_COMPOUND_ARG_INT64)
    ok |= duckdb_bind_int64 (stmt, 6, arg->as.int64_value);
  else
    ok |= duckdb_bind_null (stmt, 6);
  if (arg->type == WYL_FACT_COMPOUND_ARG_BOOL)
    ok |= duckdb_bind_boolean (stmt, 7, arg->as.bool_value);
  else
    ok |= duckdb_bind_null (stmt, 7);
  if (arg->type == WYL_FACT_COMPOUND_ARG_COMPOUND_REF)
    ok |= duckdb_bind_int64 (stmt, 8, arg->as.compound_ref);
  else
    ok |= duckdb_bind_null (stmt, 8);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state rc = duckdb_execute_prepared (stmt, NULL);
  duckdb_destroy_prepare (&stmt);
  return rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_compound_put (wyl_fact_store_t *store,
    const wyl_fact_compound_value_t *value, gint64 *out_compound_ref)
{
  if (out_compound_ref != NULL)
    *out_compound_ref = 0;
  if (store == NULL || out_compound_ref == NULL || !value_shape_valid (value))
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_fact_compound_create_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *hash = compound_hash (value);
  if (hash == NULL)
    return WYRELOG_E_NOMEM;
  gint64 compound_ref = compound_ref_from_hash (hash);
  duckdb_connection conn = wyl_fact_store_get_connection (store);

  wyl_fact_store_lock (store);
  rc = validate_scope_unlocked (conn, value->tenant_id, value->graph_id, TRUE);
  gboolean exists = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = compound_exists_unlocked (conn, value->tenant_id, value->graph_id,
        value->namespace_id, compound_ref, &exists);
  if (rc == WYRELOG_E_OK && exists) {
    gboolean hash_matches = FALSE;
    rc = compound_hash_matches_unlocked (conn, value->tenant_id,
        value->graph_id, value->namespace_id, compound_ref, hash,
        &hash_matches);
    if (rc != WYRELOG_E_OK || !hash_matches) {
      wyl_fact_store_unlock (store);
      return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    }
    *out_compound_ref = compound_ref;
    wyl_fact_store_unlock (store);
    return WYRELOG_E_OK;
  }
  for (gsize i = 0; rc == WYRELOG_E_OK && i < value->n_args; i++) {
    if (value->args[i].type != WYL_FACT_COMPOUND_ARG_COMPOUND_REF)
      continue;
    gboolean child_exists = FALSE;
    rc = compound_exists_unlocked (conn, value->tenant_id, value->graph_id,
        value->namespace_id, value->args[i].as.compound_ref, &child_exists);
    if (rc == WYRELOG_E_OK && !child_exists)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (conn, "BEGIN TRANSACTION;");
  if (rc == WYRELOG_E_OK)
    rc = insert_term_unlocked (conn, value, compound_ref, hash);
  for (gsize i = 0; rc == WYRELOG_E_OK && i < value->n_args; i++)
    rc = insert_arg_unlocked (conn, compound_ref, i, &value->args[i]);
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (conn, "COMMIT;");
  else
    (void) exec_sql (conn, "ROLLBACK;");
  wyl_fact_store_unlock (store);
  if (rc == WYRELOG_E_OK)
    *out_compound_ref = compound_ref;
  return rc;
}

typedef struct
{
  gchar *functor;
  gchar *content_hash;
  gint64 arity;
} loaded_term_t;

static void
loaded_term_clear (loaded_term_t *term)
{
  g_free (term->functor);
  g_free (term->content_hash);
}

static wyrelog_error_t
load_term_unlocked (duckdb_connection conn, const gchar *tenant_id,
    const gchar *graph_id, const gchar *namespace_id, gint64 compound_ref,
    loaded_term_t *out_term)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  memset (out_term, 0, sizeof (*out_term));
  if (duckdb_prepare (conn,
          "SELECT functor, arity, content_hash FROM compound_terms "
          "WHERE tenant_id = ? "
          "AND graph_id = ? AND namespace_id = ? AND compound_ref = ?;",
          &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  duckdb_state ok = duckdb_bind_varchar (stmt, 1, tenant_id)
      | duckdb_bind_varchar (stmt, 2, graph_id)
      | duckdb_bind_varchar (stmt, 3, namespace_id)
      | duckdb_bind_int64 (stmt, 4, compound_ref);
  if (ok != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_NOT_FOUND;
  }
  gchar *functor = duckdb_value_varchar (&result, 0, 0);
  out_term->functor = g_strdup (functor);
  duckdb_free (functor);
  out_term->arity = duckdb_value_int64 (&result, 1, 0);
  gchar *content_hash = duckdb_value_varchar (&result, 2, 0);
  out_term->content_hash = g_strdup (content_hash);
  duckdb_free (content_hash);
  duckdb_destroy_result (&result);
  if (out_term->functor == NULL || out_term->functor[0] == '\0'
      || out_term->content_hash == NULL || out_term->content_hash[0] == '\0'
      || out_term->arity <= 0 || out_term->arity > G_MAXUINT32) {
    loaded_term_clear (out_term);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t replay_unlocked (duckdb_connection conn,
    WylEngine * engine, const gchar * tenant_id, const gchar * graph_id,
    const gchar * namespace_id, gint64 compound_ref, guint depth,
    GHashTable * seen, gint64 * out_handle);

static wyrelog_error_t
load_logical_arg_unlocked (idx_t row, duckdb_result *result,
    wyl_fact_compound_arg_t *out_arg)
{
  if (duckdb_value_int64 (result, 0, row) != (gint64) row)
    return WYRELOG_E_POLICY;
  gchar *type_text = duckdb_value_varchar (result, 1, row);
  wyl_fact_compound_arg_type_t type = 0;
  gboolean type_ok = arg_type_from_name (type_text, &type);
  duckdb_free (type_text);
  if (!type_ok)
    return WYRELOG_E_POLICY;

  switch (type) {
    case WYL_FACT_COMPOUND_ARG_SYMBOL:
    case WYL_FACT_COMPOUND_ARG_STRING:
    {
      idx_t col = type == WYL_FACT_COMPOUND_ARG_SYMBOL ? 2 : 3;
      if (duckdb_value_is_null (result, col, row)
          || !duckdb_value_is_null (result, 4, row)
          || !duckdb_value_is_null (result, 5, row)
          || !duckdb_value_is_null (result, 6, row)
          || (col == 2 && !duckdb_value_is_null (result, 3, row))
          || (col == 3 && !duckdb_value_is_null (result, 2, row)))
        return WYRELOG_E_POLICY;
      gchar *text = duckdb_value_varchar (result, col, row);
      if (text == NULL)
        return WYRELOG_E_POLICY;
      out_arg->type = type;
      out_arg->as.text = g_strdup (text);
      duckdb_free (text);
      return out_arg->as.text != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
    }
    case WYL_FACT_COMPOUND_ARG_INT64:
      if (!duckdb_value_is_null (result, 2, row)
          || !duckdb_value_is_null (result, 3, row)
          || duckdb_value_is_null (result, 4, row)
          || !duckdb_value_is_null (result, 5, row)
          || !duckdb_value_is_null (result, 6, row))
        return WYRELOG_E_POLICY;
      out_arg->type = WYL_FACT_COMPOUND_ARG_INT64;
      out_arg->as.int64_value = duckdb_value_int64 (result, 4, row);
      return WYRELOG_E_OK;
    case WYL_FACT_COMPOUND_ARG_BOOL:
      if (!duckdb_value_is_null (result, 2, row)
          || !duckdb_value_is_null (result, 3, row)
          || !duckdb_value_is_null (result, 4, row)
          || duckdb_value_is_null (result, 5, row)
          || !duckdb_value_is_null (result, 6, row))
        return WYRELOG_E_POLICY;
      out_arg->type = WYL_FACT_COMPOUND_ARG_BOOL;
      out_arg->as.bool_value = duckdb_value_boolean (result, 5, row);
      return WYRELOG_E_OK;
    case WYL_FACT_COMPOUND_ARG_COMPOUND_REF:
    {
      if (!duckdb_value_is_null (result, 2, row)
          || !duckdb_value_is_null (result, 3, row)
          || !duckdb_value_is_null (result, 4, row)
          || !duckdb_value_is_null (result, 5, row)
          || duckdb_value_is_null (result, 6, row))
        return WYRELOG_E_POLICY;
      gint64 child_ref = duckdb_value_int64 (result, 6, row);
      if (child_ref <= 0)
        return WYRELOG_E_POLICY;
      out_arg->type = WYL_FACT_COMPOUND_ARG_COMPOUND_REF;
      out_arg->as.compound_ref = child_ref;
      return WYRELOG_E_OK;
    }
    default:
      return WYRELOG_E_POLICY;
  }
}

static void
clear_logical_args (wyl_fact_compound_arg_t *args, gsize n_args)
{
  if (args == NULL)
    return;
  for (gsize i = 0; i < n_args; i++) {
    if (args[i].type == WYL_FACT_COMPOUND_ARG_SYMBOL
        || args[i].type == WYL_FACT_COMPOUND_ARG_STRING)
      g_free ((gchar *) args[i].as.text);
  }
}

static wyrelog_error_t
materialize_arg_unlocked (duckdb_connection conn, WylEngine *engine,
    const gchar *tenant_id, const gchar *graph_id, const gchar *namespace_id,
    guint depth, GHashTable *seen, const wyl_fact_compound_arg_t *logical_arg,
    wirelog_compound_arg_t *out_arg)
{
  switch (logical_arg->type) {
    case WYL_FACT_COMPOUND_ARG_SYMBOL:
    case WYL_FACT_COMPOUND_ARG_STRING:
    {
      gint64 symbol_id = 0;
      wyrelog_error_t rc = wyl_engine_owned_intern_symbol (engine,
          logical_arg->as.text, &symbol_id);
      if (rc != WYRELOG_E_OK)
        return rc;
      out_arg->type = WIRELOG_TYPE_STRING;
      out_arg->value = symbol_id;
      return WYRELOG_E_OK;
    }
    case WYL_FACT_COMPOUND_ARG_INT64:
      out_arg->type = WIRELOG_TYPE_INT64;
      out_arg->value = logical_arg->as.int64_value;
      return WYRELOG_E_OK;
    case WYL_FACT_COMPOUND_ARG_BOOL:
      out_arg->type = WIRELOG_TYPE_BOOL;
      out_arg->value = logical_arg->as.bool_value ? 1 : 0;
      return WYRELOG_E_OK;
    case WYL_FACT_COMPOUND_ARG_COMPOUND_REF:
    {
      gint64 child_handle = 0;
      wyrelog_error_t rc = replay_unlocked (conn, engine, tenant_id, graph_id,
          namespace_id, logical_arg->as.compound_ref, depth + 1, seen,
          &child_handle);
      if (rc != WYRELOG_E_OK)
        return rc;
      out_arg->type = WIRELOG_TYPE_INT64;
      out_arg->value = child_handle;
      return WYRELOG_E_OK;
    }
    default:
      return WYRELOG_E_POLICY;
  }
}

static wyrelog_error_t
replay_unlocked (duckdb_connection conn, WylEngine *engine,
    const gchar *tenant_id, const gchar *graph_id, const gchar *namespace_id,
    gint64 compound_ref, guint depth, GHashTable *seen, gint64 *out_handle)
{
  if (depth > WYL_FACT_COMPOUND_MAX_DEPTH)
    return WYRELOG_E_POLICY;
  if (g_hash_table_contains (seen, &compound_ref))
    return WYRELOG_E_POLICY;
  gint64 *seen_key = g_new (gint64, 1);
  *seen_key = compound_ref;
  g_hash_table_add (seen, seen_key);

  loaded_term_t term = { 0 };
  wyrelog_error_t rc = load_term_unlocked (conn, tenant_id, graph_id,
      namespace_id, compound_ref, &term);
  if (rc != WYRELOG_E_OK) {
    g_hash_table_remove (seen, &compound_ref);
    return rc;
  }

  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  if (duckdb_prepare (conn,
          "SELECT arg_index, arg_type, symbol_value, string_value, "
          "int64_value, bool_value, child_compound_ref FROM compound_args "
          "WHERE compound_ref = ? ORDER BY arg_index;", &stmt)
      != DuckDBSuccess) {
    loaded_term_clear (&term);
    g_hash_table_remove (seen, &compound_ref);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_int64 (stmt, 1, compound_ref) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    loaded_term_clear (&term);
    g_hash_table_remove (seen, &compound_ref);
    return WYRELOG_E_IO;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    loaded_term_clear (&term);
    g_hash_table_remove (seen, &compound_ref);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) != (idx_t) term.arity) {
    duckdb_destroy_result (&result);
    loaded_term_clear (&term);
    g_hash_table_remove (seen, &compound_ref);
    return WYRELOG_E_POLICY;
  }

  g_autofree wyl_fact_compound_arg_t *logical_args =
      g_new0 (wyl_fact_compound_arg_t, (gsize) term.arity);
  for (idx_t i = 0; rc == WYRELOG_E_OK && i < duckdb_row_count (&result); i++)
    rc = load_logical_arg_unlocked (i, &result, &logical_args[i]);
  duckdb_destroy_result (&result);
  if (rc == WYRELOG_E_OK) {
    const wyl_fact_compound_value_t loaded_value = {
      .tenant_id = tenant_id,
      .graph_id = graph_id,
      .namespace_id = namespace_id,
      .functor = term.functor,
      .args = logical_args,
      .n_args = (gsize) term.arity,
    };
    g_autofree gchar *loaded_hash = compound_hash (&loaded_value);
    if (loaded_hash == NULL)
      rc = WYRELOG_E_NOMEM;
    else if (g_strcmp0 (loaded_hash, term.content_hash) != 0)
      rc = WYRELOG_E_POLICY;
  }
  g_autofree wirelog_compound_arg_t *args = g_new0 (wirelog_compound_arg_t,
      (gsize) term.arity);
  for (gsize i = 0; rc == WYRELOG_E_OK && i < (gsize) term.arity; i++)
    rc = materialize_arg_unlocked (conn, engine, tenant_id, graph_id,
        namespace_id, depth, seen, &logical_args[i], &args[i]);
  if (rc == WYRELOG_E_OK)
    rc = wyl_engine_owned_make_compound (engine, term.functor, args,
        (gsize) term.arity, out_handle);
  clear_logical_args (logical_args, (gsize) term.arity);
  loaded_term_clear (&term);
  g_hash_table_remove (seen, &compound_ref);
  return rc;
}

wyrelog_error_t
wyl_fact_compound_replay (wyl_fact_store_t *store, WylEngine *engine,
    const gchar *tenant_id, const gchar *graph_id, const gchar *namespace_id,
    gint64 compound_ref, gint64 *out_handle)
{
  if (out_handle != NULL)
    *out_handle = 0;
  if (store == NULL || engine == NULL || tenant_id == NULL || graph_id == NULL
      || namespace_id == NULL || compound_ref <= 0 || out_handle == NULL)
    return WYRELOG_E_INVALID;
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  g_autoptr (GHashTable) seen = g_hash_table_new_full (g_int64_hash,
      g_int64_equal, g_free, NULL);
  wyl_fact_store_lock (store);
  wyrelog_error_t rc = validate_scope_unlocked (conn, tenant_id, graph_id,
      FALSE);
  if (rc == WYRELOG_E_OK)
    rc = replay_unlocked (conn, engine, tenant_id, graph_id, namespace_id,
        compound_ref, 0, seen, out_handle);
  wyl_fact_store_unlock (store);
  return rc;
}

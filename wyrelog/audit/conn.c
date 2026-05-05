/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "conn-private.h"

#include <string.h>

#include "wyrelog/decide.h"

struct wyl_audit_conn_t
{
  duckdb_database db;
  duckdb_connection conn;
};

wyrelog_error_t
wyl_audit_conn_open (const gchar *path, wyl_audit_conn_t **out_conn)
{
  if (out_conn == NULL)
    return WYRELOG_E_INVALID;

  /* DuckDB treats NULL as "open an in-memory database"; the
   * literal ":memory:" string maps to the same outcome but going
   * through NULL avoids a DuckDB-version-dependent string parse. */
  const gchar *effective_path = path;
  if (path != NULL && g_strcmp0 (path, ":memory:") == 0)
    effective_path = NULL;

  wyl_audit_conn_t *self = g_new0 (wyl_audit_conn_t, 1);
  if (duckdb_open (effective_path, &self->db) != DuckDBSuccess) {
    g_free (self);
    return WYRELOG_E_IO;
  }
  if (duckdb_connect (self->db, &self->conn) != DuckDBSuccess) {
    duckdb_close (&self->db);
    g_free (self);
    return WYRELOG_E_INTERNAL;
  }

  *out_conn = self;
  return WYRELOG_E_OK;
}

void
wyl_audit_conn_close (wyl_audit_conn_t *conn)
{
  if (conn == NULL)
    return;
  /* DuckDB requires disconnect before close, in that order; both
   * APIs zero their handle so re-entering this function on an
   * already-closed conn would still be safe, but the caller has
   * already free'd the wrapper at that point. */
  duckdb_disconnect (&conn->conn);
  duckdb_close (&conn->db);
  g_free (conn);
}

duckdb_connection
wyl_audit_conn_get_connection (wyl_audit_conn_t *conn)
{
  if (conn == NULL) {
    duckdb_connection zero;
    memset (&zero, 0, sizeof (zero));
    return zero;
  }
  return conn->conn;
}

wyrelog_error_t
wyl_audit_conn_create_schema (wyl_audit_conn_t *conn)
{
  static const gchar *ddl =
      "CREATE TABLE IF NOT EXISTS audit_events ("
      "  id            VARCHAR PRIMARY KEY,"
      "  created_at_us BIGINT  NOT NULL,"
      "  subject_id    VARCHAR,"
      "  action        VARCHAR,"
      "  resource_id   VARCHAR,"
      "  deny_reason   VARCHAR,"
      "  deny_origin   VARCHAR,"
      "  decision      SMALLINT NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_created_at_us "
      "  ON audit_events (created_at_us);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_subject_id "
      "  ON audit_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_action "
      "  ON audit_events (action);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_decision "
      "  ON audit_events (decision);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_reason "
      "  ON audit_events (deny_reason);";

  if (conn == NULL)
    return WYRELOG_E_INVALID;

  duckdb_result result;
  if (duckdb_query (conn->conn, ddl, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_audit_conn_table_exists (wyl_audit_conn_t *conn, const gchar *table_name,
    gboolean *out_exists)
{
  duckdb_prepared_statement stmt;
  duckdb_result result;
  duckdb_state rc;

  if (conn == NULL || table_name == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT COUNT(*) FROM information_schema.tables " "WHERE table_name = ?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_varchar (stmt, 1, table_name) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (rc != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  *out_exists = duckdb_value_int64 (&result, 0, 0) > 0;
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static void
append_json_string (GString *json, const gchar *value)
{
  g_string_append_c (json, '"');

  for (const guchar * p = (const guchar *)value; *p != '\0'; p++) {
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

static void
append_json_member_string (GString *json, const gchar *name,
    duckdb_result *result, idx_t col, idx_t row)
{
  g_string_append_c (json, '"');
  g_string_append (json, name);
  g_string_append (json, "\":");

  if (duckdb_value_is_null (result, col, row)) {
    g_string_append (json, "null");
    return;
  }

  gchar *value = duckdb_value_varchar (result, col, row);
  append_json_string (json, value);
  duckdb_free (value);
}

static gboolean
parse_audit_filter (const gchar *filter, const gchar **out_column,
    gint16 *out_decision, const gchar **out_string)
{
  *out_column = NULL;
  *out_string = NULL;
  *out_decision = WYL_DECISION_DENY;

  if (filter == NULL || filter[0] == '\0')
    return TRUE;

  const gchar *eq = strchr (filter, '=');
  if (eq == NULL || eq == filter || eq[1] == '\0')
    return FALSE;

  g_autofree gchar *key = g_strndup (filter, (gsize) (eq - filter));
  const gchar *value = eq + 1;

  if (g_strcmp0 (key, "decision") == 0) {
    *out_column = "decision";
    if (g_strcmp0 (value, "deny") == 0) {
      *out_decision = WYL_DECISION_DENY;
      return TRUE;
    }
    if (g_strcmp0 (value, "allow") == 0) {
      *out_decision = WYL_DECISION_ALLOW;
      return TRUE;
    }
    return FALSE;
  }

  if (g_strcmp0 (key, "subject_id") == 0)
    *out_column = "subject_id";
  else if (g_strcmp0 (key, "action") == 0)
    *out_column = "action";
  else if (g_strcmp0 (key, "resource_id") == 0)
    *out_column = "resource_id";
  else if (g_strcmp0 (key, "deny_reason") == 0)
    *out_column = "deny_reason";
  else if (g_strcmp0 (key, "deny_origin") == 0)
    *out_column = "deny_origin";

  if (*out_column != NULL) {
    *out_string = value;
    return TRUE;
  }

  return FALSE;
}

wyrelog_error_t
wyl_audit_conn_query_events_json (wyl_audit_conn_t *conn,
    const gchar *filter, gchar **out_json)
{
  const gchar *column;
  const gchar *string_value;
  gint16 decision_value;
  duckdb_prepared_statement stmt;
  duckdb_result result;
  duckdb_state rc;

  if (conn == NULL || out_json == NULL)
    return WYRELOG_E_INVALID;
  *out_json = NULL;

  if (!parse_audit_filter (filter, &column, &decision_value, &string_value))
    return WYRELOG_E_INVALID;

  g_autofree gchar *sql = NULL;
  if (column == NULL) {
    sql =
        g_strdup ("SELECT id, created_at_us, subject_id, action, resource_id, "
        "deny_reason, deny_origin, decision " "FROM audit_events "
        "ORDER BY created_at_us DESC, id DESC " "LIMIT 100;");
  } else {
    sql =
        g_strdup_printf
        ("SELECT id, created_at_us, subject_id, action, resource_id, "
        "deny_reason, deny_origin, decision " "FROM audit_events "
        "WHERE %s = ? " "ORDER BY created_at_us DESC, id DESC " "LIMIT 100;",
        column);
  }

  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  if (column != NULL) {
    duckdb_state bind_rc;
    if (g_strcmp0 (column, "decision") == 0)
      bind_rc = duckdb_bind_int16 (stmt, 1, decision_value);
    else
      bind_rc = duckdb_bind_varchar (stmt, 1, string_value);
    if (bind_rc != DuckDBSuccess) {
      duckdb_destroy_prepare (&stmt);
      return WYRELOG_E_IO;
    }
  }

  rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (rc != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  g_autoptr (GString) json = g_string_new ("[");
  idx_t rows = duckdb_row_count (&result);
  for (idx_t row = 0; row < rows; row++) {
    if (row > 0)
      g_string_append_c (json, ',');

    g_string_append_c (json, '{');
    append_json_member_string (json, "id", &result, 0, row);
    g_string_append_printf (json, ",\"created_at_us\":%" G_GINT64_FORMAT,
        duckdb_value_int64 (&result, 1, row));
    g_string_append_c (json, ',');
    append_json_member_string (json, "subject_id", &result, 2, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "action", &result, 3, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "resource_id", &result, 4, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "deny_reason", &result, 5, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "deny_origin", &result, 6, row);
    g_string_append_printf (json, ",\"decision\":%" G_GINT16_FORMAT "}",
        (gint16) duckdb_value_int64 (&result, 7, row));
  }
  g_string_append_c (json, ']');

  duckdb_destroy_result (&result);
  *out_json = g_string_free (g_steal_pointer (&json), FALSE);
  return WYRELOG_E_OK;
}

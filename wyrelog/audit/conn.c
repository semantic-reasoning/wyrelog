/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "conn-private.h"

#include <string.h>

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
      "  deny_origin   VARCHAR," "  decision      SMALLINT NOT NULL" ");";

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

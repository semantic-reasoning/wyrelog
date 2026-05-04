/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <duckdb.h>

#include "wyrelog/audit/conn-private.h"

#ifndef WYL_TEST_DUCKDB_SCHEMA_PATH
#error "WYL_TEST_DUCKDB_SCHEMA_PATH must be defined by the build."
#endif

/* --- in-memory open/close lifecycle ---------------------------- */

static gint
check_open_memory_null_path (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 1;
  if (conn == NULL)
    return 2;
  return 0;
}

static gint
check_open_memory_literal (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (":memory:", &conn) != WYRELOG_E_OK)
    return 10;
  if (conn == NULL)
    return 11;
  return 0;
}

/* --- on-disk open + DDL round-trip ----------------------------- */

static gint
check_open_tempfile_and_query (void)
{
  g_autoptr (GError) err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-audit-XXXXXX", &err);
  if (tmpdir == NULL)
    return 20;
  g_autofree gchar *path = g_build_filename (tmpdir, "audit.db", NULL);

  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK) {
    g_rmdir (tmpdir);
    return 21;
  }
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  duckdb_result result;
  if (duckdb_query (h, "CREATE TABLE t (x INTEGER);", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_unlink (path);
    g_rmdir (tmpdir);
    return 22;
  }
  duckdb_destroy_result (&result);

  /* close before unlink so the database file is no longer mapped. */
  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_unlink (path);
  g_rmdir (tmpdir);
  return 0;
}

/* --- bad path fails closed ------------------------------------- */

static gint
check_open_bad_path (void)
{
  /* An obviously unwritable parent. The sentinel pointer must
   * survive the call untouched. */
  wyl_audit_conn_t *sentinel = (wyl_audit_conn_t *) (gpointer) 0xDEADBEEF;
  wyl_audit_conn_t *conn = sentinel;
  wyrelog_error_t rc =
      wyl_audit_conn_open ("/nonexistent-dir-wyrelog-audit/audit.db", &conn);
  if (rc == WYRELOG_E_OK)
    return 30;
  if (conn != sentinel)
    return 31;
  return 0;
}

/* --- argument validation --------------------------------------- */

static gint
check_invalid_args (void)
{
  if (wyl_audit_conn_open ("anything", NULL) != WYRELOG_E_INVALID)
    return 40;
  return 0;
}

/* --- close semantics ------------------------------------------- */

static gint
check_close_null_noop (void)
{
  /* Direct NULL close is a no-op. */
  wyl_audit_conn_close (NULL);

  /* Open then explicit close, then a second close on a NULL local
   * is also a no-op. autoptr cleanup at scope-end on the same
   * NULL-after-steal pointer is a no-op too. */
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 50;
  wyl_audit_conn_close (g_steal_pointer (&conn));
  /* conn is now NULL; the autoptr scope-end will see NULL. */
  if (conn != NULL)
    return 51;
  return 0;
}

/* --- handle accessor on NULL ---------------------------------- */

static gint
check_get_connection_null (void)
{
  duckdb_connection h = wyl_audit_conn_get_connection (NULL);
  /* The accessor returns a zero-initialised handle on NULL input;
   * DuckDB treats that as not-a-connection. We can't dereference
   * it here without crashing, but we can confirm the field is
   * zero by reading the bytes. Since the type is opaque we
   * compare against a freshly memset zero buffer of the same
   * size. */
  duckdb_connection zero;
  memset (&zero, 0, sizeof (zero));
  if (memcmp (&h, &zero, sizeof (h)) != 0)
    return 60;
  return 0;
}

/* --- DDL schema creation -------------------------------------- */

static gint
check_create_schema (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 70;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 71;
  /* Idempotent: a second call must also succeed because the DDL
   * uses CREATE TABLE IF NOT EXISTS. */
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 72;

  /* The freshly created table must be queryable and empty. */
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  duckdb_result result;
  if (duckdb_query (h, "SELECT COUNT(*) FROM audit_events;",
          &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 73;
  }
  if (duckdb_value_int64 (&result, 0, 0) != 0) {
    duckdb_destroy_result (&result);
    return 74;
  }
  duckdb_destroy_result (&result);
  return 0;
}

static gint
check_create_schema_null_arg (void)
{
  if (wyl_audit_conn_create_schema (NULL) != WYRELOG_E_INVALID)
    return 80;
  return 0;
}

static gint
check_template_schema_creates_audit_events (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  g_autofree gchar *schema = NULL;
  gsize schema_len = 0;
  g_autoptr (GError) error = NULL;
  duckdb_result result;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 85;
  if (!g_file_get_contents (WYL_TEST_DUCKDB_SCHEMA_PATH, &schema,
          &schema_len, &error))
    return 86;

  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  if (duckdb_query (h, schema, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 87;
  }
  duckdb_destroy_result (&result);

  gboolean exists = FALSE;
  if (wyl_audit_conn_table_exists (conn, "audit_events", &exists)
      != WYRELOG_E_OK)
    return 88;
  if (!exists)
    return 89;
  return 0;
}

static gint
check_table_probe_reports_schema (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 90;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 91;

  gboolean exists = FALSE;
  if (wyl_audit_conn_table_exists (conn, "audit_events", &exists)
      != WYRELOG_E_OK)
    return 92;
  if (!exists)
    return 93;

  if (wyl_audit_conn_table_exists (conn, "missing_table", &exists)
      != WYRELOG_E_OK)
    return 94;
  if (exists)
    return 95;
  return 0;
}

static gint
check_table_probe_rejects_invalid_args (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  gboolean exists = FALSE;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 100;
  if (wyl_audit_conn_table_exists (NULL, "audit_events", &exists)
      != WYRELOG_E_INVALID)
    return 101;
  if (wyl_audit_conn_table_exists (conn, NULL, &exists)
      != WYRELOG_E_INVALID)
    return 102;
  if (wyl_audit_conn_table_exists (conn, "audit_events", NULL)
      != WYRELOG_E_INVALID)
    return 103;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_open_memory_null_path ()) != 0)
    return rc;
  if ((rc = check_open_memory_literal ()) != 0)
    return rc;
  if ((rc = check_open_tempfile_and_query ()) != 0)
    return rc;
  if ((rc = check_open_bad_path ()) != 0)
    return rc;
  if ((rc = check_invalid_args ()) != 0)
    return rc;
  if ((rc = check_close_null_noop ()) != 0)
    return rc;
  if ((rc = check_get_connection_null ()) != 0)
    return rc;
  if ((rc = check_create_schema ()) != 0)
    return rc;
  if ((rc = check_create_schema_null_arg ()) != 0)
    return rc;
  if ((rc = check_template_schema_creates_audit_events ()) != 0)
    return rc;
  if ((rc = check_table_probe_reports_schema ()) != 0)
    return rc;
  if ((rc = check_table_probe_rejects_invalid_args ()) != 0)
    return rc;
  return 0;
}

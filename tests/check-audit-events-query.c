/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Test helper for the packaged service-credential rotation e2e (#382 Unit 3).
 * The daemon's audit sink is a DuckDB database. The shell harness must not
 * depend on a system `duckdb` CLI being present, because a host without it
 * would silently drop the acceptance gate (a skip-as-pass). This helper is
 * built against the project's own DuckDB dependency, so it is always
 * available, and prints the count of durable audit rows matching an
 * (action, decision) pair:
 *
 *   <audit.duckdb> <action> <decision>
 *       print the integer count(*) from audit_events WHERE action=<action>
 *       AND decision=<decision>; exit 0 on success, non-zero on open/query
 *       failure.
 *
 * The database is opened READ_ONLY and is only ever inspected while the daemon
 * is STOPPED.
 */
#include <duckdb.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
  if (argc != 4) {
    g_printerr ("usage: %s <audit.duckdb> <action> <decision>\n", argv[0]);
    return 2;
  }
  const gchar *audit_path = argv[1];
  const gchar *action = argv[2];
  const gchar *decision = argv[3];

  duckdb_config config = NULL;
  if (duckdb_create_config (&config) != DuckDBSuccess) {
    g_printerr ("audit-query: cannot create duckdb config\n");
    return 1;
  }
  duckdb_set_config (config, "access_mode", "READ_ONLY");

  duckdb_database db = NULL;
  char *open_error = NULL;
  if (duckdb_open_ext (audit_path, &db, config, &open_error) != DuckDBSuccess) {
    g_printerr ("audit-query: open %s failed: %s\n", audit_path,
        open_error != NULL ? open_error : "(unknown)");
    duckdb_free (open_error);
    duckdb_destroy_config (&config);
    return 1;
  }
  duckdb_destroy_config (&config);

  duckdb_connection conn = NULL;
  if (duckdb_connect (db, &conn) != DuckDBSuccess) {
    g_printerr ("audit-query: connect to %s failed\n", audit_path);
    duckdb_close (&db);
    return 1;
  }

  duckdb_prepared_statement stmt = NULL;
  duckdb_result result;
  gboolean have_result = FALSE;
  int status = 1;

  if (duckdb_prepare (conn,
          "SELECT count(*) FROM audit_events "
          "WHERE action = ? AND decision = ?", &stmt) != DuckDBSuccess) {
    g_printerr ("audit-query: prepare failed: %s\n",
        duckdb_prepare_error (stmt));
    goto out;
  }
  if (duckdb_bind_varchar (stmt, 1, action) != DuckDBSuccess
      || duckdb_bind_int32 (stmt, 2, atoi (decision)) != DuckDBSuccess) {
    g_printerr ("audit-query: bind failed\n");
    goto out;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    g_printerr ("audit-query: execute failed\n");
    goto out;
  }
  have_result = TRUE;
  g_print ("%" G_GINT64_FORMAT "\n",
      (gint64) duckdb_value_int64 (&result, 0, 0));
  status = 0;

out:
  if (have_result)
    duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  return status;
}

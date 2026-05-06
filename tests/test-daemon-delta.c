/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>
#include <duckdb.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "daemon/delta.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static wyrelog_error_t
intern3 (WylHandle *handle, const gchar *a, const gchar *b, const gchar *c,
    gint64 row[3])
{
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_intern_engine_symbol (handle, c, &row[2]);
}

static wyrelog_error_t
break_audit_events_table (WylHandle *handle)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };

  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);

  memset (&result, 0, sizeof (result));
  if (duckdb_query (conn,
          "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static gint
check_delta_callback_counts_audit_failure (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[3];
  WylDaemonRuntime runtime = { 0 };

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;
  runtime.handle = handle;
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 11;
  if (break_audit_events_table (handle) != WYRELOG_E_OK)
    return 12;
  if (intern3 (handle, "daemon-delta-audit-user", "wr.viewer",
          "daemon-delta-audit-scope", row) != WYRELOG_E_OK)
    return 13;

  if (wyl_handle_engine_insert (handle, "member_of", row, 3) != WYRELOG_E_OK)
    return 14;
  if (runtime.inserted != 1)
    return 15;
  if (runtime.audit_errors != 1)
    return 16;
  if (runtime.last_audit_error == WYRELOG_E_OK)
    return 17;

  if (wyl_handle_engine_set_delta_callback (handle, NULL, NULL)
      != WYRELOG_E_OK)
    return 18;
  return 0;
}

static gint
check_delta_readiness_fails_on_audit_failure (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;
  if (break_audit_events_table (handle) != WYRELOG_E_OK)
    return 31;
  if (wyl_daemon_check_delta_ready (handle) != WYRELOG_E_IO)
    return 32;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_delta_callback_counts_audit_failure ()) != 0)
    return rc;
  if ((rc = check_delta_readiness_fails_on_audit_failure ()) != 0)
    return rc;
  return 0;
}

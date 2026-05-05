/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <duckdb.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/engine.h"
#include "wyrelog/wyl-handle-private.h"
#include "daemon/checks.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static gboolean
count_duckdb_rows (duckdb_connection conn, const gchar *sql, gint64 *out_count)
{
  duckdb_result result = { 0 };

  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return FALSE;
  }

  *out_count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return TRUE;
}

typedef struct
{
  gint64 action_id;
  guint matches;
} AuditActionProbe;

static void
count_audit_action_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  (void) relation;
  AuditActionProbe *probe = user_data;

  if (ncols == 2 && row[1] == probe->action_id)
    probe->matches++;
}

static gint
check_login_skip_mfa_ready_rejects_production_path (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 count = 0;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;
  if (wyl_daemon_check_login_skip_mfa_ready (handle) != WYRELOG_E_OK)
    return 11;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (!count_duckdb_rows (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'login_skip_mfa' "
          "AND subject_id = 'wyrelogd-skip-mfa-user' "
          "AND deny_reason = 'skip_mfa_not_allowed' "
          "AND decision = 0;", &count))
    return 12;
  if (count != 1)
    return 13;

  gint64 row[2];
  gboolean found = FALSE;
  if (wyl_handle_intern_engine_symbol (handle, "wyrelogd-skip-mfa-user",
          &row[0]) != WYRELOG_E_OK)
    return 14;
  if (wyl_handle_intern_engine_symbol (handle, "authenticated", &row[1])
      != WYRELOG_E_OK)
    return 15;
  if (wyl_handle_engine_contains (handle, "principal_state", row, 2, &found)
      != WYRELOG_E_OK)
    return 16;
  if (found)
    return 17;
  return 0;
}

static gint
check_login_skip_mfa_ready_allows_development_path (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 count = 0;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;
  if (wyl_policy_store_set_deployment_mode (wyl_handle_get_policy_store
          (handle), "development") != WYRELOG_E_OK)
    return 31;
  if (wyl_daemon_check_login_skip_mfa_ready (handle) != WYRELOG_E_OK)
    return 32;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (!count_duckdb_rows (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'principal_state' "
          "AND subject_id = 'wyrelogd-skip-mfa-user' "
          "AND deny_reason = 'login_skip_mfa' "
          "AND resource_id = 'authenticated' " "AND decision = 1;", &count))
    return 33;
  if (count != 1)
    return 34;
  return 0;
}

static gint
check_policy_audit_facts_ready_loads_read_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 count = 0;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;
  if (wyl_daemon_check_policy_audit_facts_ready (handle) != WYRELOG_E_OK)
    return 51;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (!count_duckdb_rows (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'policy_audit_reload_check';", &count))
    return 52;
  if (count != 0)
    return 53;

  AuditActionProbe probe = { 0 };
  if (wyl_handle_intern_engine_symbol (handle, "policy_audit_reload_check",
          &probe.action_id) != WYRELOG_E_OK)
    return 54;
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "audit_event_action", count_audit_action_cb, &probe) != WYRELOG_E_OK)
    return 55;
  if (probe.matches == 0)
    return 56;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_policy_audit_facts_ready_loads_read_engine ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_ready_rejects_production_path ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_ready_allows_development_path ()) != 0)
    return rc;
  return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <duckdb.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/engine.h"
#include "wyrelog/policy/store-private.h"
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

typedef struct
{
  guint matches;
} PermissionStateEventProbe;

typedef struct
{
  guint matches;
} AuditEventProbe;

static wyrelog_error_t
permission_state_event_probe_cb (gint64 event_id, const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *event,
    const gchar *from_state, const gchar *to_state, gpointer user_data)
{
  (void) event_id;
  (void) scope;
  PermissionStateEventProbe *probe = user_data;

  if (g_strcmp0 (subject_id, "wyrelogd-perm-state-user") == 0
      && g_strcmp0 (perm_id, "wyrelogd.perm_state.read") == 0
      && g_strcmp0 (event, "grant") == 0
      && g_strcmp0 (from_state, "dormant") == 0
      && g_strcmp0 (to_state, "armed") == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
audit_event_probe_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, gpointer user_data)
{
  (void) id;
  (void) created_at_us;
  (void) request_id;
  (void) deny_origin;
  AuditEventProbe *probe = user_data;

  if (g_strcmp0 (subject_id, "wyrelogd") == 0
      && g_strcmp0 (action, "permission_state.grant") == 0
      && g_strcmp0 (resource_id, "wyrelogd.perm_state.read") == 0
      && g_strcmp0 (deny_reason, "daemon_check") == 0
      && decision == WYL_DECISION_ALLOW)
    probe->matches++;
  return WYRELOG_E_OK;
}

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
check_login_skip_mfa_ready_allows_policy_path (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 count = 0;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_grant_direct_permission (wyl_handle_get_policy_store
          (handle), "wyrelogd-skip-mfa-user", "wr.login.skip_mfa", "login")
      != WYRELOG_E_OK)
    return 41;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 45;
  if (wyl_daemon_check_login_skip_mfa_ready (handle) != WYRELOG_E_OK)
    return 42;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (!count_duckdb_rows (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'principal_state' "
          "AND subject_id = 'wyrelogd-skip-mfa-user' "
          "AND deny_reason = 'login_skip_mfa' "
          "AND resource_id = 'authenticated' AND decision = 1;", &count))
    return 43;
  if (count != 1)
    return 44;
  return 0;
}

static gint
check_login_skip_mfa_ready_allows_role_policy_path (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 count = 0;
  wyl_policy_store_t *store = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 46;
  store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "wyrelogd-skip-mfa-role",
          "skip mfa role") != WYRELOG_E_OK)
    return 47;
  if (wyl_policy_store_grant_role_permission (store,
          "wyrelogd-skip-mfa-role", "wr.login.skip_mfa") != WYRELOG_E_OK)
    return 48;
  if (wyl_policy_store_grant_role_membership (store,
          "wyrelogd-skip-mfa-user", "wyrelogd-skip-mfa-role", "login")
      != WYRELOG_E_OK)
    return 49;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 60;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  g_autoptr (WylSession) session = NULL;
  wyl_login_req_set_username (login, "wyrelogd-skip-mfa-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 61;
  if (session == NULL)
    return 64;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (!count_duckdb_rows (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'principal_state' "
          "AND subject_id = 'wyrelogd-skip-mfa-user' "
          "AND deny_reason = 'login_skip_mfa' "
          "AND resource_id = 'authenticated' AND decision = 1;", &count))
    return 62;
  if (count != 1)
    return 63;
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

static gint
check_direct_permission_grant_ready_allows_decide (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 count = 0;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;
  if (wyl_daemon_check_direct_permission_grant_ready (handle) != WYRELOG_E_OK)
    return 71;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (!count_duckdb_rows (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'permission_grant' "
          "AND subject_id = 'wyrelogd-direct-grant-user' "
          "AND deny_origin = 'wyrelogd.direct_grant.read' "
          "AND decision = 1;", &count))
    return 72;
  if (count != 1)
    return 73;
  return 0;
}

static gint
check_permission_state_transition_ready_allows_decide (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 count = 0;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 74;
  if (wyl_daemon_check_permission_state_transition_ready (handle)
      != WYRELOG_E_OK)
    return 75;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  PermissionStateEventProbe probe = { 0 };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_probe_cb, &probe) != WYRELOG_E_OK)
    return 76;
  if (probe.matches != 1)
    return 77;

  AuditEventProbe audit_probe = { 0 };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &audit_probe) != WYRELOG_E_OK)
    return 78;
  if (audit_probe.matches != 1)
    return 79;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (!count_duckdb_rows (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'permission_state.grant' "
          "AND subject_id = 'wyrelogd' "
          "AND resource_id = 'wyrelogd.perm_state.read' "
          "AND deny_reason = 'daemon_check' " "AND decision = 1;", &count))
    return 80;
  if (count != 1)
    return 81;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_policy_audit_facts_ready_loads_read_engine ()) != 0)
    return rc;
  if ((rc = check_direct_permission_grant_ready_allows_decide ()) != 0)
    return rc;
  if ((rc = check_permission_state_transition_ready_allows_decide ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_ready_rejects_production_path ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_ready_allows_development_path ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_ready_allows_policy_path ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_ready_allows_role_policy_path ()) != 0)
    return rc;
  return 0;
}

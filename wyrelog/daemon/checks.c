/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/checks.h"

#include <glib.h>

#include "daemon/delta.h"
#include "wyrelog/wyl-handle-private.h"

wyrelog_error_t
wyl_daemon_check_wirelog_policy_ready (WylHandle *handle)
{
  gint64 row[1];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, "wr.audit.read", &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean found = FALSE;
  rc = wyl_handle_engine_contains (handle, "guarded_perm", row, 1, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_check_policy_store_ready (WylHandle *handle)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  const gchar *tables[] = {
    "roles",
    "permissions",
    "role_permissions",
    "role_inheritances",
    "role_memberships",
    "role_membership_events",
    "direct_permissions",
    "direct_permission_events",
    "principal_events",
    "principal_states",
    "session_states",
    "session_events",
    "audit_events",
    "policy_signatures",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (tables); i++) {
    gboolean found = FALSE;
    wyrelog_error_t rc =
        wyl_policy_store_table_exists (store, tables[i], &found);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!found)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_check_audit_sink_ready (WylHandle *handle)
{
#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  gboolean found = FALSE;

  wyrelog_error_t rc =
      wyl_audit_conn_table_exists (conn, "audit_events", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_IO;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "daemon_check");
  wyl_audit_event_set_resource_id (ev, "audit_events");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  rc = wyl_audit_emit (handle, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
#else
  (void) handle;
#endif
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_check_policy_snapshot_reload_ready (WylHandle *handle)
{
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "wyrelogd-snapshot-user");
  wyl_login_req_set_skip_mfa (login, TRUE);

  g_autoptr (WylSession) session = NULL;
  gboolean skip_mfa_was_allowed =
      wyl_handle_get_login_skip_mfa_allowed (handle);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  wyl_handle_set_login_skip_mfa_allowed (handle, skip_mfa_was_allowed);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "wyrelogd-snapshot-user");
  wyl_grant_req_set_action (grant, "wyrelogd.snapshot.read");
  wyl_grant_req_set_resource_id (grant, session_id);
  rc = wyl_perm_grant (handle, grant);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-snapshot-user");
  wyl_decide_req_set_action (decide, "wyrelogd.snapshot.read");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
insert_symbol_row (WylHandle *handle, const gchar *relation,
    const gchar *const *symbols, gsize ncols)
{
  gint64 row[4];

  if (ncols == 0 || ncols > G_N_ELEMENTS (row))
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < ncols; i++) {
    wyrelog_error_t rc =
        wyl_handle_intern_engine_symbol (handle, symbols[i], &row[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  return wyl_handle_engine_insert (handle, relation, row, ncols);
}

wyrelog_error_t
wyl_daemon_check_role_permission_snapshot_reload_ready (WylHandle *handle)
{
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "wyrelogd-role-user");
  wyl_login_req_set_skip_mfa (login, TRUE);

  g_autoptr (WylSession) session = NULL;
  gboolean skip_mfa_was_allowed =
      wyl_handle_get_login_skip_mfa_allowed (handle);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  wyl_handle_set_login_skip_mfa_allowed (handle, skip_mfa_was_allowed);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  rc = wyl_policy_store_upsert_role (store, "wr.snapshot-child",
      "snapshot child");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_upsert_role (store, "wr.snapshot-parent",
      "snapshot parent");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_upsert_permission (store, "wyrelogd.role.read",
      "role read", "basic");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_role_permission (store, "wr.snapshot-parent",
      "wyrelogd.role.read");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_role_inheritance (store, "wr.snapshot-child",
      "wr.snapshot-parent");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_reload_engine_pair (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *member_row[] = {
    "wyrelogd-role-user",
    "wr.snapshot-child",
    session_id,
  };
  rc = insert_symbol_row (handle, "member_of", member_row,
      G_N_ELEMENTS (member_row));
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *perm_state_row[] = {
    "wyrelogd-role-user",
    "wyrelogd.role.read",
    session_id,
    "armed",
  };
  rc = insert_symbol_row (handle, "perm_state", perm_state_row,
      G_N_ELEMENTS (perm_state_row));
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-role-user");
  wyl_decide_req_set_action (decide, "wyrelogd.role.read");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_daemon_emit_start_event (WylHandle *handle)
{
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "daemon_start");
  wyl_audit_event_set_resource_id (ev, "audit_events");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  return wyl_audit_emit (handle, ev);
#else
  (void) handle;
  return WYRELOG_E_OK;
#endif
}

int
wyl_daemon_run_checks (WylHandle *handle)
{
  wyrelog_error_t rc = wyl_daemon_check_delta_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: delta readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_wirelog_policy_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_policy_store_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy store readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_policy_snapshot_reload_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy snapshot reload check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_role_permission_snapshot_reload_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: role permission reload check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_audit_sink_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: audit readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  return 0;
}

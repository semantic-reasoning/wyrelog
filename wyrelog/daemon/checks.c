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
    "wyrelog_config",
    "roles",
    "permissions",
    "role_permissions",
    "role_inheritances",
    "role_memberships",
    "role_membership_events",
    "direct_permissions",
    "direct_permission_events",
    "permission_states",
    "permission_state_events",
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

static wyrelog_error_t
contains_symbol_row2 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, gboolean *out_found)
{
  gint64 row[2];

  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_contains (handle, relation, row, 2, out_found);
}

wyrelog_error_t
wyl_daemon_check_policy_audit_facts_ready (WylHandle *handle)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();

  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "policy_audit_reload_check");
  wyl_audit_event_set_resource_id (ev, "audit_event");
  wyl_audit_event_set_deny_reason (ev, "readiness");
  wyl_audit_event_set_deny_origin (ev, "policy_store");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);

  g_autofree gchar *audit_id = wyl_audit_event_dup_id_string (ev);
  if (audit_id == NULL)
    return WYRELOG_E_INTERNAL;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_append_audit_event (store, audit_id,
      wyl_audit_event_get_created_at_us (ev),
      wyl_audit_event_get_subject_id (ev), wyl_audit_event_get_action (ev),
      wyl_audit_event_get_resource_id (ev),
      wyl_audit_event_get_deny_reason (ev),
      wyl_audit_event_get_deny_origin (ev),
      wyl_audit_event_get_decision (ev));
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_handle_reload_engine_pair (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 event_row[3];
  gboolean found = FALSE;
  rc = wyl_handle_intern_engine_symbol (handle, audit_id, &event_row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  event_row[1] = wyl_audit_event_get_created_at_us (ev);
  rc = wyl_handle_intern_engine_symbol (handle, "allow", &event_row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_contains (handle, "audit_event", event_row, 3, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;

  rc = contains_symbol_row2 (handle, "audit_event_action", audit_id,
      "policy_audit_reload_check", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;

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
wyl_daemon_check_login_skip_mfa_ready (WylHandle *handle)
{
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  g_autoptr (WylSession) session = NULL;

  wyl_login_req_set_username (login, "wyrelogd-skip-mfa-user");
  wyl_login_req_set_skip_mfa (login, TRUE);

  gboolean allowed = wyl_handle_get_login_skip_mfa_allowed (handle);
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  if (!allowed && rc == WYRELOG_E_POLICY)
    return WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK)
    return rc;
  if (session == NULL)
    return WYRELOG_E_POLICY;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "wyrelogd-skip-mfa-user");
  wyl_grant_req_set_action (grant, "wyrelogd.skip_mfa.ready");
  wyl_grant_req_set_resource_id (grant, session_id);
  rc = wyl_perm_grant (handle, grant);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-skip-mfa-user");
  wyl_decide_req_set_action (decide, "wyrelogd.skip_mfa.ready");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return WYRELOG_E_POLICY;

  return WYRELOG_E_OK;
}

static wyrelog_error_t
login_check_principal (WylHandle *handle, const gchar *username,
    WylSession **out_session)
{
  if (out_session == NULL)
    return WYRELOG_E_INVALID;
  *out_session = NULL;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, username);

  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_session_mfa_verify (handle, session);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_session = g_steal_pointer (&session);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_check_policy_snapshot_reload_ready (WylHandle *handle)
{
  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc =
      login_check_principal (handle, "wyrelogd-snapshot-user", &session);
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

wyrelog_error_t
wyl_daemon_check_direct_permission_grant_ready (WylHandle *handle)
{
  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc =
      login_check_principal (handle, "wyrelogd-direct-grant-user", &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "wyrelogd-direct-grant-user");
  wyl_grant_req_set_action (grant, "wyrelogd.direct_grant.read");
  wyl_grant_req_set_resource_id (grant, session_id);
  rc = wyl_perm_grant (handle, grant);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean found = FALSE;
  rc = wyl_policy_store_direct_permission_exists (wyl_handle_get_policy_store
      (handle), "wyrelogd-direct-grant-user", "wyrelogd.direct_grant.read",
      session_id, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-direct-grant-user");
  wyl_decide_req_set_action (decide, "wyrelogd.direct_grant.read");
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
  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc =
      login_check_principal (handle, "wyrelogd-role-user", &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  rc = wyl_policy_store_upsert_role (store, "site.snapshot-child",
      "snapshot child");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_upsert_role (store, "site.snapshot-parent",
      "snapshot parent");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_upsert_permission (store, "wyrelogd.role.read",
      "role read", "basic");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_role_permission (store, "site.snapshot-parent",
      "wyrelogd.role.read");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_role_inheritance (store, "site.snapshot-child",
      "site.snapshot-parent");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_reload_engine_pair (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *member_row[] = {
    "wyrelogd-role-user",
    "site.snapshot-child",
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

  rc = wyl_daemon_check_policy_audit_facts_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy audit fact readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_policy_snapshot_reload_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy snapshot reload check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_direct_permission_grant_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: direct permission grant check failed: %s\n",
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

  rc = wyl_daemon_check_login_skip_mfa_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: login skip-mfa readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  return 0;
}

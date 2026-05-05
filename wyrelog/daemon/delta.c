/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/delta.h"

#include "wyrelog/wyl-handle-private.h"

#ifdef WYL_HAS_AUDIT
static void
record_daemon_audit_result (WylDaemonRuntime *runtime, wyrelog_error_t rc)
{
  if (runtime == NULL || rc == WYRELOG_E_OK)
    return;

  runtime->audit_errors++;
  runtime->last_audit_error = rc;
}

static void
emit_wirelog_effective_member_audit (WylDaemonRuntime *runtime,
    const gint64 row[3], WylDeltaKind kind)
{
  if (runtime == NULL || runtime->handle == NULL)
    return;

  g_autofree gchar *user =
      wyl_handle_dup_engine_symbol (runtime->handle, row[0]);
  g_autofree gchar *role =
      wyl_handle_dup_engine_symbol (runtime->handle, row[1]);
  g_autofree gchar *scope =
      wyl_handle_dup_engine_symbol (runtime->handle, row[2]);
  if (user == NULL || role == NULL || scope == NULL)
    return;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, user);
  wyl_audit_event_set_action (ev, "effective_member_delta");
  wyl_audit_event_set_resource_id (ev, role);
  wyl_audit_event_set_deny_reason (ev,
      kind == WYL_DELTA_INSERT ? "insert" : "remove");
  wyl_audit_event_set_deny_origin (ev, scope);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  record_daemon_audit_result (runtime, wyl_audit_emit (runtime->handle, ev));
}

static void
emit_wirelog_fsm_fired_audit (WylDaemonRuntime *runtime, const gchar *relation,
    const gint64 row[5], WylDeltaKind kind)
{
  if (runtime == NULL || runtime->handle == NULL)
    return;

  g_autofree gchar *entity =
      wyl_handle_dup_engine_symbol (runtime->handle, row[1]);
  g_autofree gchar *from_state =
      wyl_handle_dup_engine_symbol (runtime->handle, row[2]);
  g_autofree gchar *event =
      wyl_handle_dup_engine_symbol (runtime->handle, row[3]);
  g_autofree gchar *to_state =
      wyl_handle_dup_engine_symbol (runtime->handle, row[4]);
  if (entity == NULL || from_state == NULL || event == NULL || to_state == NULL)
    return;

  g_autofree gchar *action = g_strdup_printf ("%s_delta_%s", relation,
      kind == WYL_DELTA_INSERT ? "insert" : "remove");
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, entity);
  wyl_audit_event_set_action (ev, action);
  wyl_audit_event_set_resource_id (ev, to_state);
  wyl_audit_event_set_deny_reason (ev, event);
  wyl_audit_event_set_deny_origin (ev, from_state);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  record_daemon_audit_result (runtime, wyl_audit_emit (runtime->handle, ev));
}

static wyrelog_error_t
check_wirelog_delta_audit_rows (WylHandle *handle)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT "
          "COUNT(*) FILTER (WHERE action = 'effective_member_delta' "
          "AND subject_id = 'wyrelogd-check-user' "
          "AND resource_id = 'wr.viewer' "
          "AND deny_origin = 'wyrelogd-check-scope' "
          "AND deny_reason = 'insert' "
          "AND decision = 1), "
          "COUNT(*) FILTER (WHERE action = 'effective_member_delta' "
          "AND subject_id = 'wyrelogd-check-user' "
          "AND resource_id = 'wr.viewer' "
          "AND deny_origin = 'wyrelogd-check-scope' "
          "AND deny_reason = 'remove' "
          "AND decision = 1) " "FROM audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  gint64 inserts = duckdb_value_int64 (&result, 0, 0);
  gint64 removes = duckdb_value_int64 (&result, 1, 0);
  duckdb_destroy_result (&result);
  return inserts == 1 && removes == 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
check_wirelog_fsm_audit_rows (WylHandle *handle)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT "
          "COUNT(*) FILTER (WHERE action = 'principal_fired_delta_insert' "
          "AND subject_id = 'wyrelogd-principal-user' "
          "AND resource_id = 'mfa_required' "
          "AND deny_reason = 'login_ok' "
          "AND deny_origin = 'unverified' "
          "AND decision = 1), "
          "COUNT(*) FILTER (WHERE action = 'session_fired_delta_insert' "
          "AND subject_id = 'wyrelogd-session' "
          "AND resource_id = 'elevated' "
          "AND deny_reason = 'elevate_grant' "
          "AND deny_origin = 'active' "
          "AND decision = 1), "
          "COUNT(*) FILTER (WHERE action = 'principal_fired_delta_remove' "
          "AND subject_id = 'wyrelogd-principal-user' "
          "AND resource_id = 'mfa_required' "
          "AND deny_reason = 'login_ok' "
          "AND deny_origin = 'unverified' "
          "AND decision = 1), "
          "COUNT(*) FILTER (WHERE action = 'session_fired_delta_remove' "
          "AND subject_id = 'wyrelogd-session' "
          "AND resource_id = 'elevated' "
          "AND deny_reason = 'elevate_grant' "
          "AND deny_origin = 'active' "
          "AND decision = 1) " "FROM audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  gint64 principal_inserts = duckdb_value_int64 (&result, 0, 0);
  gint64 session_inserts = duckdb_value_int64 (&result, 1, 0);
  gint64 principal_removes = duckdb_value_int64 (&result, 2, 0);
  gint64 session_removes = duckdb_value_int64 (&result, 3, 0);
  duckdb_destroy_result (&result);
  return principal_inserts == 1 && session_inserts == 1
      && principal_removes == 1 && session_removes == 1 ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}
#endif

static void
daemon_delta_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  WylDaemonRuntime *runtime = user_data;

  if (runtime == NULL)
    return;
  if (kind == WYL_DELTA_INSERT) {
    runtime->inserted++;
  } else if (kind == WYL_DELTA_REMOVE) {
    runtime->removed++;
  }

  if (g_strcmp0 (relation, "effective_member") != 0)
    goto fsm_relations;
  if ((kind != WYL_DELTA_INSERT && kind != WYL_DELTA_REMOVE) || ncols != 3)
    return;

#ifdef WYL_HAS_AUDIT
  emit_wirelog_effective_member_audit (runtime, row, kind);
#endif

  if (!runtime->expect_effective_member)
    return;
  if (row[0] == runtime->expected_row[0]
      && row[1] == runtime->expected_row[1]
      && row[2] == runtime->expected_row[2]) {
    if (kind == WYL_DELTA_INSERT)
      runtime->matched_expected_insert = TRUE;
    else if (kind == WYL_DELTA_REMOVE)
      runtime->matched_expected_remove = TRUE;
  }
  return;

fsm_relations:
  if ((g_strcmp0 (relation, "principal_fired") != 0
          && g_strcmp0 (relation, "session_fired") != 0)
      || (kind != WYL_DELTA_INSERT && kind != WYL_DELTA_REMOVE) || ncols != 5)
    return;

#ifdef WYL_HAS_AUDIT
  emit_wirelog_fsm_fired_audit (runtime, relation, row, kind);
#endif

  if (runtime->expect_principal_fired
      && g_strcmp0 (relation, "principal_fired") == 0
      && row[0] == runtime->expected_principal_fired[0]
      && row[1] == runtime->expected_principal_fired[1]
      && row[2] == runtime->expected_principal_fired[2]
      && row[3] == runtime->expected_principal_fired[3]
      && row[4] == runtime->expected_principal_fired[4]) {
    if (kind == WYL_DELTA_INSERT)
      runtime->matched_principal_fired_insert = TRUE;
    else if (kind == WYL_DELTA_REMOVE)
      runtime->matched_principal_fired_remove = TRUE;
  }
  if (runtime->expect_session_fired
      && g_strcmp0 (relation, "session_fired") == 0
      && row[0] == runtime->expected_session_fired[0]
      && row[1] == runtime->expected_session_fired[1]
      && row[2] == runtime->expected_session_fired[2]
      && row[3] == runtime->expected_session_fired[3]
      && row[4] == runtime->expected_session_fired[4]) {
    if (kind == WYL_DELTA_INSERT)
      runtime->matched_session_fired_insert = TRUE;
    else if (kind == WYL_DELTA_REMOVE)
      runtime->matched_session_fired_remove = TRUE;
  }
}

wyrelog_error_t
wyl_daemon_start_delta_callbacks (WylHandle *handle, WylDaemonRuntime *runtime)
{
  return wyl_handle_engine_set_delta_callback (handle, daemon_delta_cb,
      runtime);
}

wyrelog_error_t
wyl_daemon_check_delta_ready (WylHandle *handle)
{
  WylDaemonRuntime runtime = {
    .handle = handle,
    .expect_effective_member = TRUE,
    .expect_principal_fired = TRUE,
    .expect_session_fired = TRUE,
  };

  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, "wyrelogd-check-user",
      &runtime.expected_row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "wr.viewer",
      &runtime.expected_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "wyrelogd-check-scope",
      &runtime.expected_row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  runtime.expected_principal_fired[0] = 1;
  rc = wyl_handle_intern_engine_symbol (handle, "wyrelogd-principal-user",
      &runtime.expected_principal_fired[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "unverified",
      &runtime.expected_principal_fired[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "login_ok",
      &runtime.expected_principal_fired[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "mfa_required",
      &runtime.expected_principal_fired[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  runtime.expected_session_fired[0] = 2;
  rc = wyl_handle_intern_engine_symbol (handle, "wyrelogd-session",
      &runtime.expected_session_fired[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "active",
      &runtime.expected_session_fired[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "elevate_grant",
      &runtime.expected_session_fired[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "elevated",
      &runtime.expected_session_fired[4]);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_daemon_start_delta_callbacks (handle, &runtime);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 principal_event[5] = {
    runtime.expected_principal_fired[0],
    runtime.expected_principal_fired[1],
    runtime.expected_principal_fired[3],
    runtime.expected_principal_fired[2],
    runtime.expected_principal_fired[4],
  };
  gint64 session_event[5] = {
    runtime.expected_session_fired[0],
    runtime.expected_session_fired[1],
    runtime.expected_session_fired[3],
    runtime.expected_session_fired[2],
    runtime.expected_session_fired[4],
  };

  rc = wyl_handle_engine_insert (handle, "member_of", runtime.expected_row, 3);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (runtime.inserted == 0 || !runtime.matched_expected_insert) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_handle_engine_insert (handle, "principal_event", principal_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_principal_fired_insert) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_handle_engine_insert (handle, "session_event", session_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_session_fired_insert) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_handle_engine_remove (handle, "principal_event", principal_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_principal_fired_remove) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_handle_engine_remove (handle, "session_event", session_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_session_fired_remove) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_handle_engine_remove (handle, "member_of", runtime.expected_row, 3);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (runtime.removed == 0 || !runtime.matched_expected_remove) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }
#ifdef WYL_HAS_AUDIT
  if (runtime.audit_errors > 0) {
    rc = runtime.last_audit_error != WYRELOG_E_OK ?
        runtime.last_audit_error : WYRELOG_E_IO;
    goto cleanup;
  }
  rc = check_wirelog_delta_audit_rows (handle);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  rc = check_wirelog_fsm_audit_rows (handle);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
#endif

cleanup:
  wyrelog_error_t cleanup_rc =
      wyl_handle_engine_set_delta_callback (handle, NULL, NULL);
  if (rc == WYRELOG_E_OK)
    rc = cleanup_rc;
  return rc;
}

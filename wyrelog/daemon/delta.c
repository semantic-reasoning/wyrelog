/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/delta.h"

#include "wyrelog/wyl-handle-private.h"

#ifdef WYL_HAS_AUDIT
#include "wyrelog/audit/event-private.h"

static void
record_daemon_audit_result (WylDaemonRuntime *runtime, wyrelog_error_t rc)
{
  if (runtime == NULL || rc == WYRELOG_E_OK)
    return;

  g_atomic_int_set (&runtime->audit_degraded, TRUE);
  runtime->audit_errors++;
  runtime->last_audit_error = rc;
}

static wyrelog_error_t
persist_daemon_audit_event (WylDaemonRuntime *runtime, const WylAuditEvent *ev)
{
  if (runtime == NULL || runtime->handle == NULL || ev == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_audit_emit (runtime->handle, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_audit_mirror_event (runtime->handle, ev);
}

/* WYL_ENGINE_SESSION_REQUIRES: synchronous engine-delta callback chain. */
static void
emit_wirelog_effective_member_audit (WylEngineSession *session,
    WylDaemonRuntime *runtime, const gint64 row[3], WylDeltaKind kind)
{
  if (runtime == NULL || runtime->handle == NULL)
    return;

  g_autofree gchar *user = wyl_engine_session_dup_symbol (session, row[0]);
  g_autofree gchar *role = wyl_engine_session_dup_symbol (session, row[1]);
  g_autofree gchar *scope = wyl_engine_session_dup_symbol (session, row[2]);
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
  record_daemon_audit_result (runtime, persist_daemon_audit_event (runtime,
          ev));
}

/* WYL_ENGINE_SESSION_REQUIRES: synchronous engine-delta callback chain. */
static void
emit_wirelog_fsm_fired_audit (WylEngineSession *session,
    WylDaemonRuntime *runtime, const gchar *relation, const gint64 row[5],
    WylDeltaKind kind)
{
  if (runtime == NULL || runtime->handle == NULL)
    return;

  g_autofree gchar *entity = wyl_engine_session_dup_symbol (session, row[1]);
  g_autofree gchar *from_state =
      wyl_engine_session_dup_symbol (session, row[2]);
  g_autofree gchar *event = wyl_engine_session_dup_symbol (session, row[3]);
  g_autofree gchar *to_state = wyl_engine_session_dup_symbol (session, row[4]);
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
  record_daemon_audit_result (runtime, persist_daemon_audit_event (runtime,
          ev));
}

/* WYL_ENGINE_SESSION_REQUIRES: synchronous engine-delta callback chain. */
static void
emit_wirelog_perm_state_fired_audit (WylEngineSession *session,
    WylDaemonRuntime *runtime, const gint64 row[7], WylDeltaKind kind)
{
  if (runtime == NULL || runtime->handle == NULL)
    return;

  g_autofree gchar *subject = wyl_engine_session_dup_symbol (session, row[1]);
  g_autofree gchar *perm = wyl_engine_session_dup_symbol (session, row[2]);
  g_autofree gchar *scope = wyl_engine_session_dup_symbol (session, row[3]);
  g_autofree gchar *from_state =
      wyl_engine_session_dup_symbol (session, row[4]);
  g_autofree gchar *event = wyl_engine_session_dup_symbol (session, row[5]);
  g_autofree gchar *to_state = wyl_engine_session_dup_symbol (session, row[6]);
  if (subject == NULL || perm == NULL || scope == NULL || from_state == NULL
      || event == NULL || to_state == NULL)
    return;

  g_autofree gchar *transition =
      g_strdup_printf ("%s:%s:%s", from_state, event, to_state);
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, subject);
  wyl_audit_event_set_action (ev,
      kind == WYL_DELTA_INSERT ? "perm_state_fired_delta_insert" :
      "perm_state_fired_delta_remove");
  wyl_audit_event_set_resource_id (ev, perm);
  wyl_audit_event_set_deny_reason (ev, transition);
  wyl_audit_event_set_deny_origin (ev, scope);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  record_daemon_audit_result (runtime, persist_daemon_audit_event (runtime,
          ev));
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
          "AND decision = 1), "
          "COUNT(*) FILTER (WHERE action = 'perm_state_fired_delta_insert' "
          "AND subject_id = 'wyrelogd-perm-state-user' "
          "AND resource_id = 'wyrelogd.perm_state.read' "
          "AND deny_reason = 'dormant:grant:armed' "
          "AND deny_origin = 'wyrelogd-perm-state-scope' "
          "AND decision = 1), "
          "COUNT(*) FILTER (WHERE action = 'perm_state_fired_delta_remove' "
          "AND subject_id = 'wyrelogd-perm-state-user' "
          "AND resource_id = 'wyrelogd.perm_state.read' "
          "AND deny_reason = 'dormant:grant:armed' "
          "AND deny_origin = 'wyrelogd-perm-state-scope' "
          "AND decision = 1) " "FROM audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  gint64 principal_inserts = duckdb_value_int64 (&result, 0, 0);
  gint64 session_inserts = duckdb_value_int64 (&result, 1, 0);
  gint64 principal_removes = duckdb_value_int64 (&result, 2, 0);
  gint64 session_removes = duckdb_value_int64 (&result, 3, 0);
  gint64 perm_state_inserts = duckdb_value_int64 (&result, 4, 0);
  gint64 perm_state_removes = duckdb_value_int64 (&result, 5, 0);
  duckdb_destroy_result (&result);
  return principal_inserts == 1 && session_inserts == 1
      && principal_removes == 1 && session_removes == 1
      && perm_state_inserts == 1 && perm_state_removes == 1 ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}
#endif

/* WYL_ENGINE_SESSION_REQUIRES: synchronously invoked while engine is locked. */
static void
daemon_delta_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  WylDaemonRuntime *runtime = user_data;

  if (runtime == NULL)
    return;
  g_autoptr (WylEngineSession) session =
      wyl_engine_session_acquire (runtime->handle);

  runtime->delta_events_seen++;
  runtime->last_delta_event_us = g_get_real_time ();

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
  emit_wirelog_effective_member_audit (session, runtime, row, kind);
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
    goto perm_state_fired_relation;

#ifdef WYL_HAS_AUDIT
  emit_wirelog_fsm_fired_audit (session, runtime, relation, row, kind);
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
  return;

perm_state_fired_relation:
  if (g_strcmp0 (relation, "perm_state_fired") != 0
      || (kind != WYL_DELTA_INSERT && kind != WYL_DELTA_REMOVE) || ncols != 7)
    return;

#ifdef WYL_HAS_AUDIT
  emit_wirelog_perm_state_fired_audit (session, runtime, row, kind);
#endif

  if (!runtime->expect_perm_state_fired)
    return;
  if (row[0] == runtime->expected_perm_state_fired[0]
      && row[1] == runtime->expected_perm_state_fired[1]
      && row[2] == runtime->expected_perm_state_fired[2]
      && row[3] == runtime->expected_perm_state_fired[3]
      && row[4] == runtime->expected_perm_state_fired[4]
      && row[5] == runtime->expected_perm_state_fired[5]
      && row[6] == runtime->expected_perm_state_fired[6]) {
    if (kind == WYL_DELTA_INSERT)
      runtime->matched_perm_state_fired_insert = TRUE;
    else if (kind == WYL_DELTA_REMOVE)
      runtime->matched_perm_state_fired_remove = TRUE;
  }
}

wyrelog_error_t
wyl_daemon_start_delta_callbacks (WylHandle *handle, WylDaemonRuntime *runtime)
{
  if (runtime == NULL)
    return WYRELOG_E_INVALID;
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);

  wyrelog_error_t rc =
      wyl_engine_session_set_delta_callback (session, daemon_delta_cb, runtime);
  runtime->last_delta_error = rc;
  g_atomic_int_set (&runtime->delta_session_live, rc == WYRELOG_E_OK);
  return rc;
}

wyrelog_error_t
wyl_daemon_check_delta_ready (WylHandle *handle)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  WylDaemonRuntime runtime = {
    .handle = handle,
    .expect_effective_member = TRUE,
    .expect_principal_fired = TRUE,
    .expect_session_fired = TRUE,
    .expect_perm_state_fired = TRUE,
  };

  wyrelog_error_t rc =
      wyl_engine_session_intern_symbol (engine_session, "wyrelogd-check-user",
      &runtime.expected_row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "wr.viewer",
      &runtime.expected_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session,
      "wyrelogd-check-scope", &runtime.expected_row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  runtime.expected_principal_fired[0] = 1;
  rc = wyl_engine_session_intern_symbol (engine_session,
      "wyrelogd-principal-user", &runtime.expected_principal_fired[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "unverified",
      &runtime.expected_principal_fired[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "login_ok",
      &runtime.expected_principal_fired[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "mfa_required",
      &runtime.expected_principal_fired[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  runtime.expected_session_fired[0] = 2;
  rc = wyl_engine_session_intern_symbol (engine_session, "wyrelogd-session",
      &runtime.expected_session_fired[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "active",
      &runtime.expected_session_fired[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "elevate_grant",
      &runtime.expected_session_fired[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "elevated",
      &runtime.expected_session_fired[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  runtime.expected_perm_state_fired[0] = 3;
  rc = wyl_engine_session_intern_symbol (engine_session,
      "wyrelogd-perm-state-user", &runtime.expected_perm_state_fired[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session,
      "wyrelogd.perm_state.read", &runtime.expected_perm_state_fired[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session,
      "wyrelogd-perm-state-scope", &runtime.expected_perm_state_fired[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "dormant",
      &runtime.expected_perm_state_fired[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "grant",
      &runtime.expected_perm_state_fired[5]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_session_intern_symbol (engine_session, "armed",
      &runtime.expected_perm_state_fired[6]);
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
  gint64 perm_state_event[7] = {
    runtime.expected_perm_state_fired[0],
    runtime.expected_perm_state_fired[1],
    runtime.expected_perm_state_fired[2],
    runtime.expected_perm_state_fired[3],
    runtime.expected_perm_state_fired[5],
    runtime.expected_perm_state_fired[4],
    runtime.expected_perm_state_fired[6],
  };

  rc = wyl_engine_session_insert (engine_session, "member_of",
      runtime.expected_row, 3);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (runtime.inserted == 0 || !runtime.matched_expected_insert) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_engine_session_insert (engine_session, "principal_event",
      principal_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_principal_fired_insert) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_engine_session_insert (engine_session, "session_event",
      session_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_session_fired_insert) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_engine_session_insert (engine_session, "perm_state_event",
      perm_state_event, 7);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_perm_state_fired_insert) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_engine_session_remove (engine_session, "principal_event",
      principal_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_principal_fired_remove) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_engine_session_remove (engine_session, "session_event",
      session_event, 5);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_session_fired_remove) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_engine_session_remove (engine_session, "perm_state_event",
      perm_state_event, 7);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (!runtime.matched_perm_state_fired_remove) {
    rc = WYRELOG_E_POLICY;
    goto cleanup;
  }

  rc = wyl_engine_session_remove (engine_session, "member_of",
      runtime.expected_row, 3);
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
  rc = wyl_handle_load_policy_store_audit_events (handle);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  rc = check_wirelog_delta_audit_rows (handle);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  rc = check_wirelog_fsm_audit_rows (handle);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
#endif

cleanup:
  wyrelog_error_t cleanup_rc =
      wyl_engine_session_set_delta_callback (engine_session, NULL, NULL);
  if (rc == WYRELOG_E_OK)
    rc = cleanup_rc;
  return rc;
}

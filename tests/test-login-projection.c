/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/policy/store-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static gboolean
policy_count_rows (wyl_policy_store_t *store, const gchar *sql,
    gint64 *out_count)
{
  sqlite3_stmt *stmt = NULL;

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return FALSE;

  gboolean ok = sqlite3_step (stmt) == SQLITE_ROW;
  if (ok)
    *out_count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
runtime_count_rows (WylHandle *handle, const gchar *sql, gint64 *out_count)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };

  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return FALSE;
  }

  gboolean ok = duckdb_row_count (&result) == 1;
  if (ok)
    *out_count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return ok;
}

static gboolean
bind_text_params (sqlite3_stmt *stmt, const gchar **params, guint n_params)
{
  for (guint i = 0; i < n_params; i++) {
    if (sqlite3_bind_text (stmt, (int) i + 1, params[i], -1,
            SQLITE_TRANSIENT) != SQLITE_OK)
      return FALSE;
  }
  return TRUE;
}

static gboolean
policy_select_int64_params (wyl_policy_store_t *store, const gchar *sql,
    const gchar **params, guint n_params, gint64 *out_value)
{
  sqlite3_stmt *stmt = NULL;

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return FALSE;
  if (!bind_text_params (stmt, params, n_params)) {
    sqlite3_finalize (stmt);
    return FALSE;
  }

  gboolean ok = sqlite3_step (stmt) == SQLITE_ROW;
  if (ok)
    *out_value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
policy_count_rows_params (wyl_policy_store_t *store, const gchar *sql,
    const gchar **params, guint n_params, gint64 *out_count)
{
  return policy_select_int64_params (store, sql, params, n_params, out_count);
}

static gboolean
policy_select_text_params (wyl_policy_store_t *store, const gchar *sql,
    const gchar **params, guint n_params, gchar **out_value)
{
  sqlite3_stmt *stmt = NULL;

  if (out_value == NULL)
    return FALSE;
  *out_value = NULL;

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return FALSE;
  if (!bind_text_params (stmt, params, n_params)) {
    sqlite3_finalize (stmt);
    return FALSE;
  }

  gboolean ok = sqlite3_step (stmt) == SQLITE_ROW;
  if (ok) {
    const unsigned char *text = sqlite3_column_text (stmt, 0);
    *out_value = g_strdup ((const gchar *) text);
    ok = *out_value != NULL;
  }
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
engine_contains_symbol_row2 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b)
{
  gint64 row[2];
  gboolean found = FALSE;

  if (wyl_handle_intern_engine_symbol (handle, a, &row[0]) != WYRELOG_E_OK)
    return FALSE;
  if (wyl_handle_intern_engine_symbol (handle, b, &row[1]) != WYRELOG_E_OK)
    return FALSE;
  if (wyl_handle_engine_contains (handle, relation, row, 2, &found)
      != WYRELOG_E_OK)
    return FALSE;
  return found;
}

static gboolean
engine_contains_event_row5 (WylHandle *handle, const gchar *relation,
    gint64 event_id, const gchar *subject, const gchar *from_state,
    const gchar *event, const gchar *to_state)
{
  gint64 row[5];
  gboolean found = FALSE;

  row[0] = event_id;
  if (wyl_handle_intern_engine_symbol (handle, subject, &row[1])
      != WYRELOG_E_OK)
    return FALSE;
  if (wyl_handle_intern_engine_symbol (handle, from_state, &row[2])
      != WYRELOG_E_OK)
    return FALSE;
  if (wyl_handle_intern_engine_symbol (handle, event, &row[3])
      != WYRELOG_E_OK)
    return FALSE;
  if (wyl_handle_intern_engine_symbol (handle, to_state, &row[4])
      != WYRELOG_E_OK)
    return FALSE;
  if (wyl_handle_engine_contains (handle, relation, row, 5, &found)
      != WYRELOG_E_OK)
    return FALSE;
  return found;
}

static gboolean
engine_contains_audit_event (WylHandle *handle, const gchar *id,
    gint64 created_at_us, const gchar *decision)
{
  gint64 row[3];
  gboolean found = FALSE;

  if (wyl_handle_intern_engine_symbol (handle, id, &row[0]) != WYRELOG_E_OK)
    return FALSE;
  row[1] = created_at_us;
  if (wyl_handle_intern_engine_symbol (handle, decision, &row[2])
      != WYRELOG_E_OK)
    return FALSE;
  if (wyl_handle_engine_contains (handle, "audit_event", row, 3, &found)
      != WYRELOG_E_OK)
    return FALSE;
  return found;
}

static gboolean
engine_contains_audit_attr (WylHandle *handle, const gchar *relation,
    const gchar *audit_id, const gchar *value)
{
  return engine_contains_symbol_row2 (handle, relation, audit_id, value);
}

static gboolean
decide_allows (WylHandle *handle, const gchar *subject, const gchar *action,
    const gchar *resource)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);

  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return FALSE;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW;
}

static gint
check_login_projects_mfa_required_principal_state (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 90;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "projection-login-user");

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 91;
  if (session == NULL)
    return 92;

  gint64 count = -1;
  if (!policy_count_rows (wyl_handle_get_policy_store (handle),
          "SELECT COUNT(*) FROM principal_states "
          "WHERE subject_id = 'projection-login-user' "
          "AND state = 'mfa_required';", &count))
    return 94;
  if (count != 1) {
    g_printerr ("store principal state count=%" G_GINT64_FORMAT "\n", count);
    return 95;
  }
  if (!engine_contains_symbol_row2 (handle, "principal_state",
          "projection-login-user", "mfa_required"))
    return 93;
  return 0;
}

static gint
check_login_reload_failure_keeps_durable_state_repairable (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;

  wyl_handle_set_engine_insert_fault_once (handle, "principal_state",
      WYRELOG_E_INTERNAL);

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "projection-reload-fail-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_INTERNAL)
    return 11;
  if (session != NULL)
    return 12;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = -1;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM principal_states "
          "WHERE subject_id = 'projection-reload-fail-user' "
          "AND state = 'mfa_required';", &count))
    return 13;
  if (count != 1)
    return 14;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM session_states WHERE state = 'active';",
          &count))
    return 15;
  if (count != 1)
    return 16;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action IN ('principal_state', 'session_state');", &count))
    return 17;
  if (count != 2)
    return 18;

  gboolean contains = FALSE;
  gint64 mfa_required[2];
  if (wyl_handle_intern_engine_symbol (handle, "projection-reload-fail-user",
          &mfa_required[0]) != WYRELOG_E_OK)
    return 19;
  if (wyl_handle_intern_engine_symbol (handle, "mfa_required",
          &mfa_required[1]) != WYRELOG_E_OK)
    return 20;
  if (wyl_handle_engine_contains (handle, "principal_state", mfa_required, 2,
          &contains) != WYRELOG_E_OK)
    return 21;
  if (contains)
    return 22;

  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 23;
  return 0;
}

static gint
check_anonymous_login_reload_failure_keeps_session_state (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;

  wyl_handle_set_engine_insert_fault_once (handle, "session_state",
      WYRELOG_E_INTERNAL);

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, NULL, &session) != WYRELOG_E_INTERNAL)
    return 31;
  if (session != NULL)
    return 32;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = -1;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM principal_states;", &count))
    return 33;
  if (count != 0)
    return 34;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM session_states WHERE state = 'active';",
          &count))
    return 35;
  if (count != 1)
    return 36;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM session_events "
          "WHERE event = 'request' AND from_state = 'idle' "
          "AND to_state = 'active';", &count))
    return 37;
  if (count != 1)
    return 38;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'session_state' AND resource_id = 'active';", &count))
    return 39;
  if (count != 1)
    return 40;

  return 0;
}

static gint
check_login_event_projection_failure_is_reported (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 140;

  wyl_handle_set_engine_insert_fault_once (handle, "principal_event",
      WYRELOG_E_INTERNAL);

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "projection-event-fail-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_INTERNAL)
    return 141;
  if (session != NULL)
    return 142;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = -1;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM principal_events "
          "WHERE subject_id = 'projection-event-fail-user' "
          "AND event = 'login_ok' "
          "AND from_state = 'unverified' "
          "AND to_state = 'mfa_required';", &count))
    return 143;
  if (count != 1)
    return 144;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM session_events "
          "WHERE event = 'request' AND from_state = 'idle' "
          "AND to_state = 'active';", &count))
    return 145;
  if (count != 1)
    return 146;
  gint64 principal_event_id = -1;
  if (!policy_select_int64_params (store,
          "SELECT event_id FROM principal_events "
          "WHERE subject_id = 'projection-event-fail-user' "
          "AND event = 'login_ok' "
          "AND from_state = 'unverified' "
          "AND to_state = 'mfa_required';", NULL, 0, &principal_event_id))
    return 147;
  gint64 session_event_id = -1;
  if (!policy_select_int64_params (store,
          "SELECT event_id FROM session_events "
          "WHERE event = 'request' AND from_state = 'idle' "
          "AND to_state = 'active';", NULL, 0, &session_event_id))
    return 148;
  g_autofree gchar *session_id = NULL;
  if (!policy_select_text_params (store,
          "SELECT session_id FROM session_events "
          "WHERE event = 'request' AND from_state = 'idle' "
          "AND to_state = 'active';", NULL, 0, &session_id))
    return 149;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 155;
  if (!engine_contains_event_row5 (handle, "principal_fired",
          principal_event_id, "projection-event-fail-user", "unverified",
          "login_ok", "mfa_required"))
    return 156;
  if (!engine_contains_event_row5 (handle, "session_fired", session_event_id,
          session_id, "idle", "request", "active"))
    return 157;
  return 0;
}

static gint
check_anonymous_session_event_projection_failure_is_reported (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 150;

  wyl_handle_set_engine_insert_fault_once (handle, "session_event",
      WYRELOG_E_INTERNAL);

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, NULL, &session) != WYRELOG_E_INTERNAL)
    return 151;
  if (session != NULL)
    return 152;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = -1;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM session_events "
          "WHERE event = 'request' AND from_state = 'idle' "
          "AND to_state = 'active';", &count))
    return 153;
  if (count != 1)
    return 154;
  gint64 event_id = -1;
  if (!policy_select_int64_params (store,
          "SELECT event_id FROM session_events "
          "WHERE event = 'request' AND from_state = 'idle' "
          "AND to_state = 'active';", NULL, 0, &event_id))
    return 158;
  g_autofree gchar *session_id = NULL;
  if (!policy_select_text_params (store,
          "SELECT session_id FROM session_events "
          "WHERE event = 'request' AND from_state = 'idle' "
          "AND to_state = 'active';", NULL, 0, &session_id))
    return 159;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 160;
  if (!engine_contains_event_row5 (handle, "session_fired", event_id,
          session_id, "idle", "request", "active"))
    return 161;
  return 0;
}

static gint
check_skip_mfa_login_projects_authority_state (void)
{
  static const gchar *username = "projection-skip-mfa-user";
  static const gchar *perm_id = "site.projection.skip_mfa.read";
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, username);
  wyl_login_req_set_skip_mfa (login, TRUE);

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 51;
  if (session == NULL)
    return 52;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 53;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = -1;
  const gchar *session_param[] = { session_id };

  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM principal_states "
          "WHERE subject_id = 'projection-skip-mfa-user' "
          "AND state = 'authenticated';", &count))
    return 54;
  if (count != 1)
    return 55;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM principal_events "
          "WHERE subject_id = 'projection-skip-mfa-user' "
          "AND event = 'login_skip_mfa' "
          "AND from_state = 'unverified' "
          "AND to_state = 'authenticated';", &count))
    return 56;
  if (count != 1)
    return 57;
  if (!policy_count_rows_params (store,
          "SELECT COUNT(*) FROM session_states "
          "WHERE session_id = ? AND state = 'active';",
          session_param, G_N_ELEMENTS (session_param), &count))
    return 58;
  if (count != 1)
    return 59;
  if (!policy_count_rows_params (store,
          "SELECT COUNT(*) FROM session_events "
          "WHERE session_id = ? AND event = 'request' "
          "AND from_state = 'idle' AND to_state = 'active';",
          session_param, G_N_ELEMENTS (session_param), &count))
    return 60;
  if (count != 1)
    return 61;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE subject_id = 'projection-skip-mfa-user' "
          "AND action = 'principal_state' "
          "AND resource_id = 'authenticated' "
          "AND deny_reason = 'login_skip_mfa' "
          "AND deny_origin = 'unverified' AND decision = 1;", &count))
    return 62;
  if (count != 1)
    return 63;
  if (!policy_count_rows_params (store,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE subject_id = ? AND action = 'session_state' "
          "AND resource_id = 'active' AND deny_origin = 'idle' "
          "AND decision = 1;",
          session_param, G_N_ELEMENTS (session_param), &count))
    return 64;
  if (count != 1)
    return 65;

  gint64 principal_event_id = -1;
  if (!policy_select_int64_params (store,
          "SELECT event_id FROM principal_events "
          "WHERE subject_id = 'projection-skip-mfa-user' "
          "AND event = 'login_skip_mfa' "
          "AND from_state = 'unverified' "
          "AND to_state = 'authenticated';", NULL, 0, &principal_event_id))
    return 66;
  gint64 session_event_id = -1;
  if (!policy_select_int64_params (store,
          "SELECT event_id FROM session_events "
          "WHERE session_id = ? AND event = 'request' "
          "AND from_state = 'idle' AND to_state = 'active';",
          session_param, G_N_ELEMENTS (session_param), &session_event_id))
    return 67;

  g_autofree gchar *audit_id = NULL;
  if (!policy_select_text_params (store,
          "SELECT id FROM audit_events "
          "WHERE subject_id = 'projection-skip-mfa-user' "
          "AND action = 'principal_state' "
          "AND resource_id = 'authenticated' "
          "AND deny_reason = 'login_skip_mfa' "
          "AND deny_origin = 'unverified' AND decision = 1;",
          NULL, 0, &audit_id))
    return 68;
  gint64 audit_created_at_us = -1;
  const gchar *audit_param[] = { audit_id };
  if (!policy_select_int64_params (store,
          "SELECT created_at_us FROM audit_events WHERE id = ?;",
          audit_param, G_N_ELEMENTS (audit_param), &audit_created_at_us))
    return 69;

  if (wyl_policy_store_upsert_permission (store, perm_id,
          "skip mfa projection read", "basic") != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_grant_direct_permission (store, username, perm_id,
          session_id) != WYRELOG_E_OK)
    return 71;
  if (wyl_handle_load_policy_store_direct_permissions (handle) != WYRELOG_E_OK)
    return 72;
  if (!decide_allows (handle, username, perm_id, session_id))
    return 73;
  if (!engine_contains_event_row5 (handle, "principal_fired",
          principal_event_id, username, "unverified", "login_skip_mfa",
          "authenticated"))
    return 74;
  if (!engine_contains_event_row5 (handle, "session_fired", session_event_id,
          session_id, "idle", "request", "active"))
    return 75;
  if (!engine_contains_audit_event (handle, audit_id, audit_created_at_us,
          "allow"))
    return 76;
  if (!engine_contains_audit_attr (handle, "audit_event_subject", audit_id,
          username))
    return 77;
  if (!engine_contains_audit_attr (handle, "audit_event_action", audit_id,
          "principal_state"))
    return 78;
  if (!engine_contains_audit_attr (handle, "audit_event_resource", audit_id,
          "authenticated"))
    return 79;
  if (!engine_contains_audit_attr (handle, "audit_event_deny_reason",
          audit_id, "login_skip_mfa"))
    return 80;
  if (!engine_contains_audit_attr (handle, "audit_event_deny_origin",
          audit_id, "unverified"))
    return 81;

  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 82;
  if (!decide_allows (handle, username, perm_id, session_id))
    return 83;
  if (!engine_contains_event_row5 (handle, "principal_fired",
          principal_event_id, username, "unverified", "login_skip_mfa",
          "authenticated"))
    return 84;
  if (!engine_contains_event_row5 (handle, "session_fired", session_event_id,
          session_id, "idle", "request", "active"))
    return 85;
  if (!engine_contains_audit_event (handle, audit_id, audit_created_at_us,
          "allow"))
    return 86;

  return 0;
}

static gint
check_handle_reopens_persistent_policy_and_audit_paths (void)
{
  static const gchar *username = "projection-persistent-user";
  static const gchar *perm_id = "site.projection.persistent.read";

  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyrelog-persist-XXXXXX", &error);
  if (dir == NULL)
    return 110;

  g_autofree gchar *policy_path = g_build_filename (dir, "policy.sqlite", NULL);
  g_autofree gchar *audit_path = g_build_filename (dir, "audit.duckdb", NULL);
  g_autofree gchar *session_id = NULL;
  g_autofree gchar *audit_id = NULL;
  gint64 audit_created_at_us = -1;

  {
    g_autoptr (WylHandle) handle = NULL;
    WylHandleOpenOptions opts = {
      .template_dir = WYL_TEST_TEMPLATE_DIR,
      .policy_store_path = policy_path,
      .audit_store_path = audit_path,
    };
    if (wyl_handle_open_with_options (&opts, &handle) != WYRELOG_E_OK)
      return 111;
    wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);

    g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
    wyl_login_req_set_username (login, username);
    wyl_login_req_set_skip_mfa (login, TRUE);

    g_autoptr (WylSession) session = NULL;
    if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
      return 112;
    if (session == NULL)
      return 113;
    session_id = wyl_session_dup_id_string (session);
    if (session_id == NULL)
      return 114;

    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    if (wyl_policy_store_upsert_permission (store, perm_id,
            "persistent projection read", "basic") != WYRELOG_E_OK)
      return 115;
    if (wyl_policy_store_grant_direct_permission (store, username, perm_id,
            session_id) != WYRELOG_E_OK)
      return 116;
    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
      return 117;
    if (!decide_allows (handle, username, perm_id, session_id))
      return 118;

    if (!policy_select_text_params (store,
            "SELECT id FROM audit_events "
            "WHERE subject_id = ? AND action = 'principal_state' "
            "AND resource_id = 'authenticated' "
            "AND deny_reason = 'login_skip_mfa';", &username, 1, &audit_id))
      return 119;
    const gchar *audit_param[] = { audit_id };
    if (!policy_select_int64_params (store,
            "SELECT created_at_us FROM audit_events WHERE id = ?;",
            audit_param, G_N_ELEMENTS (audit_param), &audit_created_at_us))
      return 120;

    gint64 runtime_count = -1;
    if (!runtime_count_rows (handle,
            "SELECT COUNT(*) FROM audit_events "
            "WHERE action = 'principal_state' "
            "AND subject_id = 'projection-persistent-user';", &runtime_count))
      return 121;
    if (runtime_count != 1)
      return 122;
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    WylHandleOpenOptions opts = {
      .template_dir = WYL_TEST_TEMPLATE_DIR,
      .policy_store_path = policy_path,
      .audit_store_path = audit_path,
    };
    if (wyl_handle_open_with_options (&opts, &handle) != WYRELOG_E_OK)
      return 123;

    if (!decide_allows (handle, username, perm_id, session_id))
      return 124;
    if (!engine_contains_symbol_row2 (handle, "principal_state", username,
            "authenticated"))
      return 125;
    const gchar *session_param[] = { session_id };
    gint64 state_count = -1;
    if (!policy_count_rows_params (wyl_handle_get_policy_store (handle),
            "SELECT COUNT(*) FROM session_states "
            "WHERE session_id = ? AND state = 'active';",
            session_param, G_N_ELEMENTS (session_param), &state_count))
      return 126;
    if (state_count != 1)
      return 132;
    if (!engine_contains_audit_event (handle, audit_id, audit_created_at_us,
            "allow"))
      return 127;
    if (!engine_contains_audit_attr (handle, "audit_event_subject", audit_id,
            username))
      return 128;
    if (!engine_contains_audit_attr (handle, "audit_event_action", audit_id,
            "principal_state"))
      return 129;

    gint64 runtime_count = -1;
    if (!runtime_count_rows (handle,
            "SELECT COUNT(*) FROM audit_events "
            "WHERE action = 'principal_state' "
            "AND subject_id = 'projection-persistent-user';", &runtime_count))
      return 130;
    if (runtime_count != 1)
      return 131;
  }

  g_remove (audit_path);
  g_remove (policy_path);
  g_rmdir (dir);
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_login_projects_mfa_required_principal_state ()) != 0)
    return rc;
  if ((rc = check_login_reload_failure_keeps_durable_state_repairable ()) != 0)
    return rc;
  if ((rc = check_anonymous_login_reload_failure_keeps_session_state ()) != 0)
    return rc;
  if ((rc = check_login_event_projection_failure_is_reported ()) != 0)
    return rc;
  if ((rc =
          check_anonymous_session_event_projection_failure_is_reported ()) != 0)
    return rc;
  if ((rc = check_skip_mfa_login_projects_authority_state ()) != 0)
    return rc;
  if ((rc = check_handle_reopens_persistent_policy_and_audit_paths ()) != 0)
    return rc;
  return 0;
}

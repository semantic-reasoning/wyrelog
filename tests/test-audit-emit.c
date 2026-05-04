/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <duckdb.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/*
 * End-to-end audit-emit test. wyl_init opens the audit log and
 * creates the schema; we then construct an audit event, hand it to
 * wyl_audit_emit, and verify the row landed in the audit_events
 * table by querying the underlying DuckDB connection through the
 * private accessor pair.
 */

static wyrelog_error_t
intern_symbol (WylHandle *handle, const gchar *symbol, gint64 *out_id)
{
  return wyl_handle_intern_engine_symbol (handle, symbol, out_id);
}

static wyrelog_error_t
insert_symbol_row1 (WylHandle *handle, const gchar *relation,
    const gchar *value)
{
  gint64 row[1];
  wyrelog_error_t rc = intern_symbol (handle, value, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 1);
}

static wyrelog_error_t
insert_symbol_row2 (WylHandle *handle, const gchar *relation, const gchar *a,
    const gchar *b)
{
  gint64 row[2];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 2);
}

static wyrelog_error_t
insert_symbol_row3 (WylHandle *handle, const gchar *relation, const gchar *a,
    const gchar *b, const gchar *c)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 3);
}

static wyrelog_error_t
insert_symbol_row4 (WylHandle *handle, const gchar *relation, const gchar *a,
    const gchar *b, const gchar *c, const gchar *d)
{
  gint64 row[4];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, d, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 4);
}

static wyrelog_error_t
insert_not_armed_decide_fixture (WylHandle *handle)
{
  wyrelog_error_t rc = insert_symbol_row2 (handle, "role_permission",
      "wr.audit-role", "wr.audit-permission");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", "audit-user",
      "wr.audit-role", "audit-scope");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", "audit-user",
      "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", "audit-scope", "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static wyrelog_error_t
insert_allow_decide_fixture (WylHandle *handle)
{
  wyrelog_error_t rc = insert_symbol_row2 (handle, "role_permission",
      "wr.audit-allow-role", "wr.audit-allow");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", "audit-allow-user",
      "wr.audit-allow-role", "audit-allow-scope");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", "audit-allow-user",
      "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", "audit-allow-scope",
      "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row1 (handle, "session_active", "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row4 (handle, "perm_state", "audit-allow-user",
      "wr.audit-allow", "audit-allow-scope", "armed");
}

static gint
check_emit_inserts_a_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "alice");
  wyl_audit_event_set_action (ev, "read");
  wyl_audit_event_set_resource_id (ev, "doc/42");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);

  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 11;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT COUNT(*) FROM audit_events;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 12;
  }
  if (duckdb_value_int64 (&result, 0, 0) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 13;
  }
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return 0;
}

static gint
check_emit_persists_event_fields (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "bob");
  wyl_audit_event_set_action (ev, "write");
  wyl_audit_event_set_resource_id (ev, "doc/99");
  wyl_audit_event_set_deny_reason (ev, "not_armed");
  wyl_audit_event_set_deny_origin (ev, "perm_state");
  wyl_audit_event_set_decision (ev, WYL_DECISION_DENY);

  g_autofree gchar *expected_id = wyl_audit_event_dup_id_string (ev);

  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 21;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT id, subject_id, action, resource_id, deny_reason, "
          "deny_origin, decision "
          "FROM audit_events;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 22;
  }
  gint rc = 0;
  const gchar *id = duckdb_value_varchar (&result, 0, 0);
  const gchar *subject = duckdb_value_varchar (&result, 1, 0);
  const gchar *action = duckdb_value_varchar (&result, 2, 0);
  const gchar *resource = duckdb_value_varchar (&result, 3, 0);
  const gchar *deny_reason = duckdb_value_varchar (&result, 4, 0);
  const gchar *deny_origin = duckdb_value_varchar (&result, 5, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 6, 0);

  if (g_strcmp0 (id, expected_id) != 0)
    rc = 23;
  else if (g_strcmp0 (subject, "bob") != 0)
    rc = 24;
  else if (g_strcmp0 (action, "write") != 0)
    rc = 25;
  else if (g_strcmp0 (resource, "doc/99") != 0)
    rc = 26;
  else if (g_strcmp0 (deny_reason, "not_armed") != 0)
    rc = 27;
  else if (g_strcmp0 (deny_origin, "perm_state") != 0)
    rc = 28;
  else if (decision != WYL_DECISION_DENY)
    rc = 29;

  duckdb_free ((void *) id);
  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) deny_reason);
  duckdb_free ((void *) deny_origin);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_decide_persists_representative_deny_reason (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 40;
  if (insert_not_armed_decide_fixture (handle) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 41;
  }

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "audit-user");
  wyl_decide_req_set_action (req, "wr.audit-permission");
  wyl_decide_req_set_resource_id (req, "audit-scope");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 42;
  }
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY) {
    g_object_unref (handle);
    return 43;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT deny_reason, deny_origin, decision "
          "FROM audit_events;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 44;
  }

  gint rc = 0;
  const gchar *deny_reason = duckdb_value_varchar (&result, 0, 0);
  const gchar *deny_origin = duckdb_value_varchar (&result, 1, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 2, 0);
  if (g_strcmp0 (deny_reason, "not_armed") != 0)
    rc = 45;
  else if (g_strcmp0 (deny_origin, "perm_state") != 0)
    rc = 46;
  else if (decision != WYL_DECISION_DENY)
    rc = 47;

  duckdb_free ((void *) deny_reason);
  duckdb_free ((void *) deny_origin);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_decide_fail_closes_on_audit_append_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;
  if (insert_allow_decide_fixture (handle) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 51;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 52;
  }
  duckdb_destroy_result (&result);

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "audit-allow-user");
  wyl_decide_req_set_action (req, "wr.audit-allow");
  wyl_decide_req_set_resource_id (req, "audit-allow-scope");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 53;
  }
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY) {
    g_object_unref (handle);
    return 54;
  }
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "audit_unavailable") != 0) {
    g_object_unref (handle);
    return 55;
  }
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "audit_events") != 0) {
    g_object_unref (handle);
    return 56;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_session_transition_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 60;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-session-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 61;
  }
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL) {
    g_object_unref (handle);
    return 62;
  }
  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 63;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_origin, decision "
          "FROM audit_events WHERE action = 'session_state';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 64;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 65;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *old_state = duckdb_value_varchar (&result, 3, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);
  if (g_strcmp0 (subject, session_id) != 0)
    rc = 66;
  else if (g_strcmp0 (action, "session_state") != 0)
    rc = 67;
  else if (g_strcmp0 (resource, "idle") != 0)
    rc = 68;
  else if (g_strcmp0 (old_state, "active") != 0)
    rc = 69;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 70;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) old_state);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_principal_transition_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 80;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-principal-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 81;
  }
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 82;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_origin, decision "
          "FROM audit_events WHERE action = 'principal_state';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 83;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 84;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *old_state = duckdb_value_varchar (&result, 3, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);
  if (g_strcmp0 (subject, "audit-principal-user") != 0)
    rc = 85;
  else if (g_strcmp0 (action, "principal_state") != 0)
    rc = 86;
  else if (g_strcmp0 (resource, "authenticated") != 0)
    rc = 87;
  else if (g_strcmp0 (old_state, "mfa_required") != 0)
    rc = 88;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 89;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) old_state);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_emit_rejects_null_args (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();

  if (wyl_audit_emit (NULL, ev) != WYRELOG_E_INVALID) {
    g_object_unref (handle);
    return 31;
  }
  if (wyl_audit_emit (handle, NULL) != WYRELOG_E_INVALID) {
    g_object_unref (handle);
    return 32;
  }
  g_object_unref (handle);
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_emit_inserts_a_row ()) != 0)
    return rc;
  if ((rc = check_emit_persists_event_fields ()) != 0)
    return rc;
  if ((rc = check_decide_persists_representative_deny_reason ()) != 0)
    return rc;
  if ((rc = check_decide_fail_closes_on_audit_append_failure ()) != 0)
    return rc;
  if ((rc = check_session_transition_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_principal_transition_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_emit_rejects_null_args ()) != 0)
    return rc;
  return 0;
}

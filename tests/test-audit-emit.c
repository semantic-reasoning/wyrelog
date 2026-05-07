/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <duckdb.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/policy/store-private.h"
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

static gboolean
policy_count_rows (wyl_policy_store_t *store, const gchar *sql,
    gint64 *out_count)
{
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return FALSE;

  gboolean ok = FALSE;
  if (sqlite3_step (stmt) == SQLITE_ROW) {
    *out_count = sqlite3_column_int64 (stmt, 0);
    ok = TRUE;
  }
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
policy_count_audit_rows (WylHandle *handle, const gchar *id, gint64 *out_count)
{
  sqlite3_stmt *stmt = NULL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
          "SELECT COUNT(*) FROM audit_events WHERE id = ?;", -1, &stmt, NULL)
      != SQLITE_OK)
    return FALSE;
  if (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return FALSE;
  }

  gboolean ok = FALSE;
  if (sqlite3_step (stmt) == SQLITE_ROW) {
    *out_count = sqlite3_column_int64 (stmt, 0);
    ok = TRUE;
  }
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
policy_get_audit_intention_state (WylHandle *handle, const gchar *id,
    gchar **out_state, gint64 *out_attempt_count)
{
  sqlite3_stmt *stmt = NULL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
          "SELECT state, attempt_count FROM audit_intentions "
          "WHERE audit_id = ?;", -1, &stmt, NULL) != SQLITE_OK)
    return FALSE;
  if (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return FALSE;
  }

  gboolean ok = FALSE;
  if (sqlite3_step (stmt) == SQLITE_ROW) {
    *out_state = g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
    *out_attempt_count = sqlite3_column_int64 (stmt, 1);
    ok = TRUE;
  }
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
runtime_count_audit_rows (WylHandle *handle, const gchar *id, gint64 *out_count)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  if (duckdb_prepare (conn,
          "SELECT COUNT(*) FROM audit_events WHERE id = ?;", &stmt)
      != DuckDBSuccess)
    return FALSE;
  if (duckdb_bind_varchar (stmt, 1, id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return FALSE;
  }

  gboolean ok = FALSE;
  if (duckdb_execute_prepared (stmt, &result) == DuckDBSuccess
      && duckdb_row_count (&result) == 1) {
    *out_count = duckdb_value_int64 (&result, 0, 0);
    ok = TRUE;
  }
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  return ok;
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

static gint seed_audit_role_permission (WylHandle * handle,
    const gchar * role_id, const gchar * perm_id);

static wyrelog_error_t
contains_audit_event_fact (WylHandle *handle, const gchar *id,
    gint64 created_at_us, const gchar *decision, gboolean *out_contains)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  row[1] = created_at_us;
  rc = intern_symbol (handle, decision, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_contains (handle, "audit_event", row, 3,
      out_contains);
}

static wyrelog_error_t
contains_audit_event_attr_fact (WylHandle *handle, const gchar *relation,
    const gchar *id, const gchar *value, gboolean *out_contains)
{
  gint64 row[2];
  wyrelog_error_t rc = intern_symbol (handle, id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, value, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_contains (handle, relation, row, 2, out_contains);
}

typedef struct
{
  gint64 audit_id;
  guint matches;
} AuditFactCount;

static void
count_audit_fact_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  (void) relation;
  AuditFactCount *count = user_data;

  if (ncols >= 1 && row[0] == count->audit_id)
    count->matches++;
}

static wyrelog_error_t
count_audit_attr_facts (WylHandle *handle, const gchar *relation,
    const gchar *id, guint *out_count)
{
  gint64 audit_id = 0;
  wyrelog_error_t rc = intern_symbol (handle, id, &audit_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  AuditFactCount count = { audit_id, 0 };
  rc = wyl_engine_snapshot (wyl_handle_get_read_engine (handle), relation,
      count_audit_fact_cb, &count);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_count = count.matches;
  return WYRELOG_E_OK;
}

static gint
check_live_audit_projection_for_action (WylHandle *handle, const gchar *action,
    const gchar *subject, const gchar *resource, const gchar *origin,
    gint base_code)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  static const gchar *sql =
      "SELECT id, created_at_us FROM audit_events WHERE action = ?;";
  if (duckdb_prepare (conn, sql, &stmt) != DuckDBSuccess)
    return base_code;
  if (duckdb_bind_varchar (stmt, 1, action) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return base_code + 1;
  }
  if (duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    return base_code + 2;
  }
  duckdb_destroy_prepare (&stmt);
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    return base_code + 3;
  }

  gchar *id = duckdb_value_varchar (&result, 0, 0);
  gint64 created_at_us = duckdb_value_int64 (&result, 1, 0);
  gint rc = 0;
  gboolean contains = FALSE;

  if (contains_audit_event_fact (handle, id, created_at_us, "allow",
          &contains) != WYRELOG_E_OK || !contains)
    rc = base_code + 4;
  else if (contains_audit_event_attr_fact (handle, "audit_event_subject", id,
          subject, &contains) != WYRELOG_E_OK || !contains)
    rc = base_code + 5;
  else if (contains_audit_event_attr_fact (handle, "audit_event_action", id,
          action, &contains) != WYRELOG_E_OK || !contains)
    rc = base_code + 6;
  else if (contains_audit_event_attr_fact (handle, "audit_event_resource", id,
          resource, &contains) != WYRELOG_E_OK || !contains)
    rc = base_code + 7;
  else if (contains_audit_event_attr_fact (handle,
          "audit_event_deny_origin", id, origin, &contains) != WYRELOG_E_OK
      || !contains)
    rc = base_code + 8;

  duckdb_free (id);
  duckdb_destroy_result (&result);
  return rc;
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
  wyl_audit_event_set_request_id (ev, "req-audit-emit");
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
          "deny_origin, request_id, decision "
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
  const gchar *request_id = duckdb_value_varchar (&result, 6, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 7, 0);

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
  else if (g_strcmp0 (request_id, "req-audit-emit") != 0)
    rc = 30;
  else if (decision != WYL_DECISION_DENY)
    rc = 29;

  duckdb_free ((void *) id);
  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) deny_reason);
  duckdb_free ((void *) deny_origin);
  duckdb_free ((void *) request_id);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_query_events_json_filters_rows (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 140;

  g_autoptr (WylAuditEvent) denied = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (denied, "json-bob");
  wyl_audit_event_set_action (denied, "write");
  wyl_audit_event_set_resource_id (denied, "doc/99");
  wyl_audit_event_set_deny_reason (denied, "not_armed");
  wyl_audit_event_set_deny_origin (denied, "perm_state");
  wyl_audit_event_set_request_id (denied, "req-json-bob");
  wyl_audit_event_set_decision (denied, WYL_DECISION_DENY);

  g_autoptr (WylAuditEvent) allowed = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (allowed, "json-alice");
  wyl_audit_event_set_action (allowed, "read");
  wyl_audit_event_set_resource_id (allowed, "doc/42");
  wyl_audit_event_set_decision (allowed, WYL_DECISION_ALLOW);

  if (wyl_audit_emit (handle, denied) != WYRELOG_E_OK
      || wyl_audit_emit (handle, allowed) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 141;
  }

  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  g_autofree gchar *deny_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "decision=deny", &deny_json)
      != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 142;
  }
  if (g_strstr_len (deny_json, -1, "\"subject_id\":\"json-bob\"") == NULL
      || g_strstr_len (deny_json, -1, "\"subject_id\":\"json-alice\"")
      != NULL || g_strstr_len (deny_json, -1, "\"decision\":0") == NULL) {
    g_object_unref (handle);
    return 143;
  }

  g_autofree gchar *action_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "action(\"read\")",
          &action_json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 144;
  }
  if (g_strstr_len (action_json, -1, "\"subject_id\":\"json-alice\"") == NULL
      || g_strstr_len (action_json, -1, "\"subject_id\":\"json-bob\"")
      != NULL) {
    g_object_unref (handle);
    return 145;
  }

  g_autofree gchar *reason_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "deny_reason(\"not_armed\")",
          &reason_json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 1540;
  }
  if (g_strstr_len (reason_json, -1, "\"subject_id\":\"json-bob\"") == NULL
      || g_strstr_len (reason_json, -1, "\"subject_id\":\"json-alice\"")
      != NULL || g_strstr_len (reason_json, -1,
          "\"deny_origin\":\"perm_state\"") == NULL) {
    g_object_unref (handle);
    return 1541;
  }

  g_autofree gchar *origin_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "deny_origin(\"perm_state\")",
          &origin_json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 1542;
  }
  if (g_strstr_len (origin_json, -1, "\"subject_id\":\"json-bob\"") == NULL
      || g_strstr_len (origin_json, -1, "\"subject_id\":\"json-alice\"")
      != NULL || g_strstr_len (origin_json, -1,
          "\"deny_reason\":\"not_armed\"") == NULL) {
    g_object_unref (handle);
    return 1543;
  }

  g_autofree gchar *request_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "request_id(\"req-json-bob\")",
          &request_json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 1544;
  }
  if (g_strstr_len (request_json, -1, "\"subject_id\":\"json-bob\"")
      == NULL || g_strstr_len (request_json, -1,
          "\"request_id\":\"req-json-bob\"") == NULL
      || g_strstr_len (request_json, -1, "\"subject_id\":\"json-alice\"")
      != NULL) {
    g_object_unref (handle);
    return 1545;
  }

  g_autofree gchar *all_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, NULL, &all_json)
      != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 146;
  }
  if (g_strstr_len (all_json, -1, "\"subject_id\":\"json-alice\"") == NULL
      || g_strstr_len (all_json, -1, "\"subject_id\":\"json-bob\"")
      == NULL) {
    g_object_unref (handle);
    return 147;
  }

  g_autofree gchar *bad_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "decision=maybe", &bad_json)
      != WYRELOG_E_INVALID) {
    g_object_unref (handle);
    return 148;
  }
  if (bad_json != NULL) {
    g_object_unref (handle);
    return 149;
  }

  g_autofree gchar *bad_compound_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "action()", &bad_compound_json)
      != WYRELOG_E_INVALID) {
    g_object_unref (handle);
    return 152;
  }
  if (bad_compound_json != NULL) {
    g_object_unref (handle);
    return 153;
  }

  g_autofree gchar *compound_decision_json = NULL;
  if (wyl_audit_conn_query_events_json (conn, "decision(\"allow\")",
          &compound_decision_json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 150;
  }
  if (g_strstr_len (compound_decision_json, -1,
          "\"subject_id\":\"json-alice\"") == NULL
      || g_strstr_len (compound_decision_json, -1,
          "\"subject_id\":\"json-bob\"") != NULL
      || g_strstr_len (compound_decision_json, -1, "\"decision\":1")
      == NULL) {
    g_object_unref (handle);
    return 151;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_emit_mirrors_policy_store_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 160;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "policy-audit-user");
  wyl_audit_event_set_action (ev, "audit.write");
  wyl_audit_event_set_resource_id (ev, "audit-log");
  wyl_audit_event_set_deny_reason (ev, "allowed");
  wyl_audit_event_set_deny_origin (ev, "test");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  g_autofree gchar *expected_id = wyl_audit_event_dup_id_string (ev);

  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 161;
  }

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT subject_id, action, resource_id, deny_reason, deny_origin, "
      "decision FROM audit_events WHERE id = ?;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 162;
  }
  if (sqlite3_bind_text (stmt, 1, expected_id, -1, SQLITE_TRANSIENT)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    g_object_unref (handle);
    return 163;
  }

  int step_rc = sqlite3_step (stmt);
  gint rc = 0;
  if (step_rc != SQLITE_ROW)
    rc = 164;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 0),
          "policy-audit-user") != 0)
    rc = 165;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 1),
          "audit.write") != 0)
    rc = 166;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 2),
          "audit-log") != 0)
    rc = 167;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 3),
          "allowed") != 0)
    rc = 168;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 4),
          "test") != 0)
    rc = 169;
  else if (sqlite3_column_int (stmt, 5) != WYL_DECISION_ALLOW)
    rc = 170;

  sqlite3_finalize (stmt);
  if (rc == 0) {
    g_autofree gchar *state = NULL;
    gint64 attempt_count = -1;
    if (!policy_get_audit_intention_state (handle, expected_id, &state,
            &attempt_count))
      rc = 500;
    else if (g_strcmp0 (state, "committed") != 0 || attempt_count != 0)
      rc = 501;
  }
  g_object_unref (handle);
  return rc;
}

static gint
check_policy_store_audit_replay_loads_runtime_query (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 171;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  static const gchar *replay_id = "01890c10-2e3f-7000-8000-000000000003";
  if (wyl_policy_store_append_audit_event (store, replay_id, 789, NULL,
          "audit.replay", "replay-resource", NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 172;
  }
  static const gchar *full_replay_id = "01890c10-2e3f-7000-8000-000000000012";
  gboolean full_inserted = FALSE;
  if (wyl_policy_store_append_audit_event_full (store, full_replay_id, 790,
          "replay-user", "audit.replay.full", "replay-full-resource",
          "not_armed", "perm_state", "req-replay-full", WYL_DECISION_DENY,
          &full_inserted) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 205;
  }
  if (!full_inserted) {
    g_object_unref (handle);
    return 216;
  }
  if (wyl_handle_load_policy_store_audit_events (handle) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 173;
  }
  if (wyl_handle_load_policy_store_audit_events (handle) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 182;
  }

  duckdb_connection duck_conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result count_result;
  if (duckdb_query (duck_conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE id = '01890c10-2e3f-7000-8000-000000000003';",
          &count_result) != DuckDBSuccess) {
    duckdb_destroy_result (&count_result);
    g_object_unref (handle);
    return 183;
  }
  if (duckdb_value_int64 (&count_result, 0, 0) != 1) {
    duckdb_destroy_result (&count_result);
    g_object_unref (handle);
    return 184;
  }
  duckdb_destroy_result (&count_result);

  g_autofree gchar *json = NULL;
  if (wyl_audit_conn_query_events_json (wyl_handle_get_audit_conn (handle),
          "action(\"audit.replay\")", &json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 174;
  }

  gint rc = 0;
  if (g_strstr_len (json, -1,
          "\"id\":\"01890c10-2e3f-7000-8000-000000000003\"") == NULL)
    rc = 175;
  else if (g_strstr_len (json, -1, "\"created_at_us\":789") == NULL)
    rc = 176;
  else if (g_strstr_len (json, -1, "\"subject_id\":null") == NULL)
    rc = 177;
  else if (g_strstr_len (json, -1, "\"resource_id\":\"replay-resource\"")
      == NULL)
    rc = 178;
  else if (g_strstr_len (json, -1, "\"deny_reason\":null") == NULL)
    rc = 179;
  else if (g_strstr_len (json, -1, "\"deny_origin\":null") == NULL)
    rc = 180;
  else if (g_strstr_len (json, -1, "\"request_id\":null") == NULL)
    rc = 214;
  else if (g_strstr_len (json, -1, "\"decision\":1") == NULL)
    rc = 181;
  if (rc != 0) {
    g_object_unref (handle);
    return rc;
  }

  g_clear_pointer (&json, g_free);
  if (wyl_audit_conn_query_events_json (wyl_handle_get_audit_conn (handle),
          "action(\"audit.replay.full\")", &json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 206;
  }

  if (g_strstr_len (json, -1,
          "\"id\":\"01890c10-2e3f-7000-8000-000000000012\"") == NULL)
    rc = 207;
  else if (g_strstr_len (json, -1, "\"created_at_us\":790") == NULL)
    rc = 208;
  else if (g_strstr_len (json, -1, "\"subject_id\":\"replay-user\"") == NULL)
    rc = 209;
  else if (g_strstr_len (json, -1,
          "\"resource_id\":\"replay-full-resource\"") == NULL)
    rc = 210;
  else if (g_strstr_len (json, -1, "\"deny_reason\":\"not_armed\"") == NULL)
    rc = 211;
  else if (g_strstr_len (json, -1, "\"deny_origin\":\"perm_state\"") == NULL)
    rc = 212;
  else if (g_strstr_len (json, -1, "\"request_id\":\"req-replay-full\"")
      == NULL)
    rc = 215;
  else if (g_strstr_len (json, -1, "\"decision\":0") == NULL)
    rc = 213;

  g_object_unref (handle);
  return rc;
}

static gint
check_emit_replays_runtime_query_after_table_loss (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 432;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  memset (&result, 0, sizeof (result));
  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 433;
  }
  duckdb_destroy_result (&result);

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "runtime-replay-user");
  wyl_audit_event_set_action (ev, "audit.runtime.replay");
  wyl_audit_event_set_resource_id (ev, "runtime-replay-resource");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);
  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 434;
  }

  gint64 count = -1;
  if (!policy_count_audit_rows (handle, id, &count) || count != 1) {
    g_object_unref (handle);
    return 435;
  }
  if (wyl_handle_load_policy_store_audit_events (handle) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 436;
  }

  g_autofree gchar *json = NULL;
  if (wyl_audit_conn_query_events_json (wyl_handle_get_audit_conn (handle),
          "action(\"audit.runtime.replay\")", &json) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 437;
  }
  if (g_strstr_len (json, -1, id) == NULL ||
      g_strstr_len (json, -1, "\"subject_id\":\"runtime-replay-user\"")
      == NULL) {
    g_object_unref (handle);
    return 438;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_audit_conn_insert_event_idempotence (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 185;

  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  static const gchar *id = "01890c10-2e3f-7000-8000-000000000004";
  if (wyl_audit_conn_insert_event (conn, id, 890, "same-user",
          "same.action", "same-resource", NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 186;
  }
  if (wyl_audit_conn_insert_event (conn, id, 890, "same-user",
          "same.action", "same-resource", NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 187;
  }
  if (wyl_audit_conn_insert_event (conn, id, 890, "same-user",
          "different.action", "same-resource", NULL, NULL,
          WYL_DECISION_ALLOW) != WYRELOG_E_POLICY) {
    g_object_unref (handle);
    return 188;
  }
  if (wyl_audit_conn_insert_event (conn, "not-a-uuid", 890, "same-user",
          "same.action", "same-resource", NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_INVALID) {
    g_object_unref (handle);
    return 189;
  }

  duckdb_connection duck_conn = wyl_audit_conn_get_connection (conn);
  duckdb_result result;
  if (duckdb_query (duck_conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE id = '01890c10-2e3f-7000-8000-000000000004';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 190;
  }

  gint rc = 0;
  if (duckdb_value_int64 (&result, 0, 0) != 1)
    rc = 191;

  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_duplicate_emit_keeps_runtime_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 192;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "duplicate-user");
  wyl_audit_event_set_action (ev, "duplicate.action");
  wyl_audit_event_set_resource_id (ev, "duplicate-resource");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);

  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 193;
  }
  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 194;
  }

  duckdb_connection duck_conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result;
  memset (&result, 0, sizeof (result));

  static const gchar *sql = "SELECT COUNT(*) FROM audit_events WHERE id = ?;";
  if (duckdb_prepare (duck_conn, sql, &stmt) != DuckDBSuccess) {
    g_object_unref (handle);
    return 195;
  }
  if (duckdb_bind_varchar (stmt, 1, id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    g_object_unref (handle);
    return 196;
  }
  duckdb_state step_rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (step_rc != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 197;
  }

  gint rc = 0;
  if (duckdb_value_int64 (&result, 0, 0) != 1)
    rc = 198;

  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_policy_store_audit_replay_rolls_back_corrupt_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 199;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  static const gchar *valid_id = "01890c10-2e3f-7000-8000-000000000005";
  if (wyl_policy_store_append_audit_event (store, valid_id, 901,
          "valid-user", "valid.action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 200;
  }
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO audit_events "
          "(id, created_at_us, action, decision) "
          "VALUES ('not-a-uuid', 902, 'bad.action', 1);",
          NULL, NULL, NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 201;
  }
  if (wyl_handle_load_policy_store_audit_events (handle) != WYRELOG_E_POLICY) {
    g_object_unref (handle);
    return 202;
  }

  duckdb_connection duck_conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  memset (&result, 0, sizeof (result));
  if (duckdb_query (duck_conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE id = '01890c10-2e3f-7000-8000-000000000005';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 203;
  }

  gint rc = 0;
  if (duckdb_value_int64 (&result, 0, 0) != 0)
    rc = 204;

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
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0) {
    g_object_unref (handle);
    return 3000;
  }
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0) {
    g_object_unref (handle);
    return 3001;
  }

  sqlite3_stmt *stmt = NULL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  static const gchar *policy_sql =
      "SELECT id, created_at_us FROM audit_events "
      "WHERE subject_id = 'audit-user' "
      "AND action = 'wr.audit-permission' "
      "AND resource_id = 'audit-scope' "
      "AND deny_reason = 'not_armed' "
      "AND deny_origin = 'perm_state' AND decision = 0;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), policy_sql, -1,
          &stmt, NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 3002;
  }
  if (sqlite3_step (stmt) != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    g_object_unref (handle);
    return 3003;
  }
  g_autofree gchar *audit_id_copy =
      g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
  gint64 created_at_us = sqlite3_column_int64 (stmt, 1);
  if (sqlite3_step (stmt) != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    g_object_unref (handle);
    return 3004;
  }
  sqlite3_finalize (stmt);

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_prepared_statement duck_stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *runtime_sql =
      "SELECT deny_reason, deny_origin, decision "
      "FROM audit_events WHERE id = ?;";
  if (duckdb_prepare (conn, runtime_sql, &duck_stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&duck_stmt);
    g_object_unref (handle);
    return 44;
  }
  if (duckdb_bind_varchar (duck_stmt, 1, audit_id_copy) != DuckDBSuccess) {
    duckdb_destroy_prepare (&duck_stmt);
    g_object_unref (handle);
    return 3005;
  }
  if (duckdb_execute_prepared (duck_stmt, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&duck_stmt);
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 3006;
  }
  duckdb_destroy_prepare (&duck_stmt);
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 3007;
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
  if (rc != 0) {
    g_object_unref (handle);
    return rc;
  }

  gboolean contains = FALSE;
  if (contains_audit_event_fact (handle, audit_id_copy, created_at_us, "deny",
          &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 3008;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_reason",
          audit_id_copy, "not_armed", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 3009;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_origin",
          audit_id_copy, "perm_state", &contains) != WYRELOG_E_OK
      || !contains) {
    g_object_unref (handle);
    return 3010;
  }

  g_object_unref (handle);
  return rc;
}

static gint
check_decide_allows_when_runtime_audit_projection_fails (void)
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
  memset (&result, 0, sizeof (result));
  if (duckdb_query (conn,
          "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);", &result)
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
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW) {
    g_object_unref (handle);
    return 54;
  }
  static const gchar *audit_sql =
      "SELECT id, created_at_us FROM audit_events "
      "WHERE action = ? AND subject_id = ? "
      "AND resource_id = ? AND decision = ?;";
  sqlite3_stmt *stmt = NULL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), audit_sql, -1,
          &stmt, NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 55;
  }
  if (sqlite3_bind_text (stmt, 1, "wr.audit-allow", -1, SQLITE_TRANSIENT)
      != SQLITE_OK
      || sqlite3_bind_text (stmt, 2, "audit-allow-user", -1, SQLITE_TRANSIENT)
      != SQLITE_OK
      || sqlite3_bind_text (stmt, 3, "audit-allow-scope", -1,
          SQLITE_TRANSIENT) != SQLITE_OK
      || sqlite3_bind_int (stmt, 4, WYL_DECISION_ALLOW) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    g_object_unref (handle);
    return 304;
  }
  if (sqlite3_step (stmt) != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    g_object_unref (handle);
    return 56;
  }
  g_autofree gchar *id =
      g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
  gint64 created_at_us = sqlite3_column_int64 (stmt, 1);
  if (sqlite3_step (stmt) != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    g_object_unref (handle);
    return 301;
  }
  sqlite3_finalize (stmt);

  g_autofree gchar *state = NULL;
  gint64 attempt_count = -1;
  if (!policy_get_audit_intention_state (handle, id, &state, &attempt_count)) {
    g_object_unref (handle);
    return 506;
  }
  if (g_strcmp0 (state, "failed") != 0 || attempt_count != 1) {
    g_object_unref (handle);
    return 507;
  }

  gboolean contains = FALSE;
  if (contains_audit_event_fact (handle, id, created_at_us, "allow",
          &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 302;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_action", id,
          "wr.audit-allow", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 303;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_subject", id,
          "audit-allow-user", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 305;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_resource", id,
          "audit-allow-scope", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 306;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_permission_grant_rolls_back_on_store_audit_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 57;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_permission_grant_audit "
          "BEFORE INSERT ON audit_events "
          "BEGIN SELECT RAISE(ABORT, 'fail audit'); END;",
          NULL, NULL, NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 58;
  }

  g_autoptr (wyl_grant_req_t) req = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (req, "audit-grant-rollback-user");
  wyl_grant_req_set_action (req, "site.audit-grant-rollback");
  wyl_grant_req_set_resource_id (req, "audit-grant-rollback-scope");
  if (wyl_perm_grant (handle, req) != WYRELOG_E_IO) {
    g_object_unref (handle);
    return 59;
  }

  gboolean exists = TRUE;
  if (wyl_policy_store_direct_permission_exists (store,
          "audit-grant-rollback-user", "site.audit-grant-rollback",
          "audit-grant-rollback-scope", &exists) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 60;
  }
  if (exists) {
    g_object_unref (handle);
    return 61;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_role_grant_rolls_back_on_store_audit_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 246;
  if (seed_audit_role_permission (handle, "site.audit-role-rollback",
          "site.audit-role-rollback.read") != 0) {
    g_object_unref (handle);
    return 69;
  }

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_role_grant_audit "
          "BEFORE INSERT ON audit_events "
          "BEGIN SELECT RAISE(ABORT, 'fail audit'); END;",
          NULL, NULL, NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 70;
  }

  g_autoptr (wyl_role_grant_req_t) req = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (req, "audit-role-rollback-user");
  wyl_role_grant_req_set_role_id (req, "site.audit-role-rollback");
  wyl_role_grant_req_set_scope (req, "audit-role-rollback-scope");
  if (wyl_role_grant (handle, req) != WYRELOG_E_IO) {
    g_object_unref (handle);
    return 71;
  }

  gboolean exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store,
          "audit-role-rollback-user", "site.audit-role-rollback",
          "audit-role-rollback-scope", &exists) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 72;
  }
  if (exists) {
    g_object_unref (handle);
    return 73;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_permission_grant_survives_runtime_audit_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 62;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 63;
  }
  duckdb_destroy_result (&result);

  g_autoptr (wyl_grant_req_t) req = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (req, "audit-grant-runtime-user");
  wyl_grant_req_set_action (req, "site.audit-grant-runtime");
  wyl_grant_req_set_resource_id (req, "audit-grant-runtime-scope");
  if (wyl_perm_grant (handle, req) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 64;
  }

  sqlite3_stmt *stmt = NULL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
          "SELECT COUNT(*) FROM audit_events WHERE action = ?;", -1, &stmt,
          NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 65;
  }
  if (sqlite3_bind_text (stmt, 1, "permission_grant", -1,
          SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    g_object_unref (handle);
    return 66;
  }
  int step_rc = sqlite3_step (stmt);
  gint64 count = step_rc == SQLITE_ROW ? sqlite3_column_int64 (stmt, 0) : -1;
  sqlite3_finalize (stmt);
  if (count != 1) {
    g_object_unref (handle);
    return 67;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_login_survives_runtime_audit_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 68;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 247;
  }
  duckdb_destroy_result (&result);

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-login-runtime-user");
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 248;
  }
  if (session == NULL) {
    g_object_unref (handle);
    return 249;
  }

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = -1;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'login_skip_mfa';", &count)) {
    g_object_unref (handle);
    return 250;
  }
  if (count != 1) {
    g_object_unref (handle);
    return 251;
  }
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'session_state';", &count)) {
    g_object_unref (handle);
    return 252;
  }
  if (count != 1) {
    g_object_unref (handle);
    return 253;
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
          "FROM audit_events WHERE action = 'session_state' "
          "AND deny_origin = 'active';", &result)
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
check_login_session_state_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 110;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-login-session-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 111;
  }
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL) {
    g_object_unref (handle);
    return 112;
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
    return 113;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 114;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *old_state = duckdb_value_varchar (&result, 3, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);
  if (g_strcmp0 (subject, session_id) != 0)
    rc = 115;
  else if (g_strcmp0 (action, "session_state") != 0)
    rc = 116;
  else if (g_strcmp0 (resource, "active") != 0)
    rc = 117;
  else if (g_strcmp0 (old_state, "idle") != 0)
    rc = 118;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 119;

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
          "SELECT subject_id, action, resource_id, deny_reason, "
          "deny_origin, decision "
          "FROM audit_events WHERE action = 'principal_state' "
          "AND deny_origin = 'mfa_required';", &result)
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
  const gchar *event = duckdb_value_varchar (&result, 3, 0);
  const gchar *old_state = duckdb_value_varchar (&result, 4, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 5, 0);
  if (g_strcmp0 (subject, "audit-principal-user") != 0)
    rc = 85;
  else if (g_strcmp0 (action, "principal_state") != 0)
    rc = 86;
  else if (g_strcmp0 (resource, "authenticated") != 0)
    rc = 87;
  else if (g_strcmp0 (event, "mfa_ok") != 0)
    rc = 88;
  else if (g_strcmp0 (old_state, "mfa_required") != 0)
    rc = 89;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 90;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) event);
  duckdb_free ((void *) old_state);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_login_principal_state_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 90;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-login-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 91;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_reason, "
          "deny_origin, decision "
          "FROM audit_events WHERE action = 'principal_state';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 92;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 93;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *event = duckdb_value_varchar (&result, 3, 0);
  const gchar *old_state = duckdb_value_varchar (&result, 4, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 5, 0);
  if (g_strcmp0 (subject, "audit-login-user") != 0)
    rc = 94;
  else if (g_strcmp0 (action, "principal_state") != 0)
    rc = 95;
  else if (g_strcmp0 (resource, "mfa_required") != 0)
    rc = 96;
  else if (g_strcmp0 (event, "login_ok") != 0)
    rc = 97;
  else if (g_strcmp0 (old_state, "unverified") != 0)
    rc = 98;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 99;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) event);
  duckdb_free ((void *) old_state);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_login_skip_mfa_emits_canonical_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 100;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-skip-mfa-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 101;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_reason, "
          "deny_origin, decision "
          "FROM audit_events WHERE action = 'login_skip_mfa';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 102;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 103;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  gboolean reason_is_null = duckdb_value_is_null (&result, 3, 0);
  gboolean origin_is_null = duckdb_value_is_null (&result, 4, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 5, 0);
  if (g_strcmp0 (subject, "audit-skip-mfa-user") != 0)
    rc = 104;
  else if (g_strcmp0 (action, "login_skip_mfa") != 0)
    rc = 105;
  else if (g_strcmp0 (resource, "principal_state") != 0)
    rc = 106;
  else if (!reason_is_null)
    rc = 107;
  else if (!origin_is_null)
    rc = 108;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 109;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_denied_login_skip_mfa_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 110;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-skip-mfa-denied-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_POLICY) {
    g_object_unref (handle);
    return 111;
  }
  if (session != NULL) {
    g_object_unref (handle);
    return 112;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_reason, "
          "deny_origin, decision "
          "FROM audit_events WHERE action = 'login_skip_mfa';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 113;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 114;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *reason = duckdb_value_varchar (&result, 3, 0);
  const gchar *origin = duckdb_value_varchar (&result, 4, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 5, 0);
  if (g_strcmp0 (subject, "audit-skip-mfa-denied-user") != 0)
    rc = 115;
  else if (g_strcmp0 (action, "login_skip_mfa") != 0)
    rc = 116;
  else if (g_strcmp0 (resource, "principal_state") != 0)
    rc = 117;
  else if (g_strcmp0 (reason, "skip_mfa_not_allowed") != 0)
    rc = 118;
  else if (g_strcmp0 (origin, "login_ingress") != 0)
    rc = 119;
  else if (decision != WYL_DECISION_DENY)
    rc = 120;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) reason);
  duckdb_free ((void *) origin);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_denied_login_skip_mfa_reports_audit_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 225;

  wyl_handle_set_engine_insert_fault_once (handle, "audit_event_input",
      WYRELOG_E_INTERNAL);

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-skip-mfa-fail-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_INTERNAL) {
    g_object_unref (handle);
    return 226;
  }
  if (session != NULL) {
    g_object_unref (handle);
    return 227;
  }

  gboolean contains = FALSE;
  gint64 authenticated[2];
  if (intern_symbol (handle, "audit-skip-mfa-fail-user",
          &authenticated[0]) != WYRELOG_E_OK
      || intern_symbol (handle, "authenticated", &authenticated[1])
      != WYRELOG_E_OK
      || wyl_handle_engine_contains (handle, "principal_state", authenticated,
          2, &contains) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 228;
  }
  if (contains) {
    g_object_unref (handle);
    return 229;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_allowed_login_skip_mfa_rolls_back_on_store_audit_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 230;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_skip_mfa_principal_audit "
          "BEFORE INSERT ON audit_events WHEN NEW.action = 'login_skip_mfa' "
          "BEGIN SELECT RAISE(ABORT, 'fail audit'); END;",
          NULL, NULL, NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 231;
  }

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-skip-mfa-store-fail-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_IO) {
    g_object_unref (handle);
    return 232;
  }
  if (session != NULL) {
    g_object_unref (handle);
    return 233;
  }

  gboolean contains = FALSE;
  gint64 authenticated[2];
  if (intern_symbol (handle, "audit-skip-mfa-store-fail-user",
          &authenticated[0]) != WYRELOG_E_OK
      || intern_symbol (handle, "authenticated", &authenticated[1])
      != WYRELOG_E_OK
      || wyl_handle_engine_contains (handle, "principal_state", authenticated,
          2, &contains) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 234;
  }
  if (contains) {
    g_object_unref (handle);
    return 235;
  }

  gint64 count = -1;
  if (!policy_count_rows (store, "SELECT COUNT(*) FROM principal_states;",
          &count)) {
    g_object_unref (handle);
    return 254;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 255;
  }
  if (!policy_count_rows (store, "SELECT COUNT(*) FROM principal_events;",
          &count)) {
    g_object_unref (handle);
    return 256;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 257;
  }
  if (!policy_count_rows (store, "SELECT COUNT(*) FROM audit_events;", &count)) {
    g_object_unref (handle);
    return 258;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 259;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_login_session_state_rolls_back_on_store_audit_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 236;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_session_state_audit "
          "BEFORE INSERT ON audit_events WHEN NEW.action = 'session_state' "
          "BEGIN SELECT RAISE(ABORT, 'fail audit'); END;",
          NULL, NULL, NULL) != SQLITE_OK) {
    g_object_unref (handle);
    return 237;
  }

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-session-store-fail-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_IO) {
    g_object_unref (handle);
    return 238;
  }
  if (session != NULL) {
    g_object_unref (handle);
    return 239;
  }

  gint64 count = -1;
  if (!policy_count_rows (store, "SELECT COUNT(*) FROM session_states;",
          &count)) {
    g_object_unref (handle);
    return 240;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 241;
  }

  if (!policy_count_rows (store, "SELECT COUNT(*) FROM principal_states;",
          &count)) {
    g_object_unref (handle);
    return 242;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 243;
  }
  if (!policy_count_rows (store, "SELECT COUNT(*) FROM session_events;",
          &count)) {
    g_object_unref (handle);
    return 244;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 245;
  }
  if (!policy_count_rows (store, "SELECT COUNT(*) FROM principal_events;",
          &count)) {
    g_object_unref (handle);
    return 260;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 261;
  }
  if (!policy_count_rows (store, "SELECT COUNT(*) FROM audit_events;", &count)) {
    g_object_unref (handle);
    return 262;
  }
  if (count != 0) {
    g_object_unref (handle);
    return 263;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_permission_grant_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 120;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "audit-grant-user");
  wyl_grant_req_set_action (grant, "site.audit-grant");
  wyl_grant_req_set_resource_id (grant, "audit-grant-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 121;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_origin, decision "
          "FROM audit_events WHERE action = 'permission_grant';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 122;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 123;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *permission = duckdb_value_varchar (&result, 3, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);
  if (g_strcmp0 (subject, "audit-grant-user") != 0)
    rc = 124;
  else if (g_strcmp0 (action, "permission_grant") != 0)
    rc = 125;
  else if (g_strcmp0 (resource, "audit-grant-scope") != 0)
    rc = 126;
  else if (g_strcmp0 (permission, "site.audit-grant") != 0)
    rc = 127;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 128;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) permission);
  duckdb_destroy_result (&result);
  if (rc == 0)
    rc = check_live_audit_projection_for_action (handle, "permission_grant",
        "audit-grant-user", "audit-grant-scope", "site.audit-grant", 129);
  g_object_unref (handle);
  return rc;
}

static gint
check_permission_grant_actor_emits_audit_subject (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1290;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "audit-grant-target");
  wyl_grant_req_set_action (grant, "site.audit-grant-actor");
  wyl_grant_req_set_resource_id (grant, "audit-grant-actor-scope");
  wyl_grant_req_set_actor_id (grant, "audit-grant-actor");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 1291;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id FROM audit_events "
          "WHERE action = 'permission_grant' "
          "AND deny_origin = 'site.audit-grant-actor';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 1292;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 1293;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  if (g_strcmp0 (subject, "audit-grant-actor") != 0)
    rc = 1294;

  duckdb_free ((void *) subject);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return rc;
}

static gint
check_permission_revoke_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 130;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "audit-revoke-user");
  wyl_grant_req_set_action (grant, "site.audit-revoke");
  wyl_grant_req_set_resource_id (grant, "audit-revoke-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 131;
  }

  g_autoptr (wyl_revoke_req_t) revoke = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (revoke, "audit-revoke-user");
  wyl_revoke_req_set_action (revoke, "site.audit-revoke");
  wyl_revoke_req_set_resource_id (revoke, "audit-revoke-scope");
  if (wyl_perm_revoke (handle, revoke) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 132;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_origin, decision "
          "FROM audit_events WHERE action = 'permission_revoke';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 133;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 134;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *permission = duckdb_value_varchar (&result, 3, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);
  if (g_strcmp0 (subject, "audit-revoke-user") != 0)
    rc = 135;
  else if (g_strcmp0 (action, "permission_revoke") != 0)
    rc = 136;
  else if (g_strcmp0 (resource, "audit-revoke-scope") != 0)
    rc = 137;
  else if (g_strcmp0 (permission, "site.audit-revoke") != 0)
    rc = 138;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 139;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) permission);
  duckdb_destroy_result (&result);
  if (rc == 0)
    rc = check_live_audit_projection_for_action (handle, "permission_revoke",
        "audit-revoke-user", "audit-revoke-scope", "site.audit-revoke", 1390);
  g_object_unref (handle);
  return rc;
}

static gint
seed_audit_role_permission (WylHandle *handle, const gchar *role_id,
    const gchar *perm_id)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  if (wyl_policy_store_upsert_role (store, role_id, role_id) != WYRELOG_E_OK)
    return 1;
  if (wyl_policy_store_upsert_permission (store, perm_id, perm_id, "basic")
      != WYRELOG_E_OK)
    return 2;
  if (wyl_policy_store_grant_role_permission (store, role_id, perm_id)
      != WYRELOG_E_OK)
    return 3;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 4;
  return 0;
}

static gint
check_role_grant_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 140;
  if (seed_audit_role_permission (handle, "site.audit-role-grant",
          "site.audit-role-grant.read") != 0) {
    g_object_unref (handle);
    return 141;
  }

  g_autoptr (wyl_role_grant_req_t) grant = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (grant, "audit-role-grant-user");
  wyl_role_grant_req_set_role_id (grant, "site.audit-role-grant");
  wyl_role_grant_req_set_scope (grant, "audit-role-grant-scope");
  if (wyl_role_grant (handle, grant) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 142;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_origin, decision "
          "FROM audit_events WHERE action = 'role_grant';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 143;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 144;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *role = duckdb_value_varchar (&result, 3, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);
  if (g_strcmp0 (subject, "audit-role-grant-user") != 0)
    rc = 145;
  else if (g_strcmp0 (action, "role_grant") != 0)
    rc = 146;
  else if (g_strcmp0 (resource, "audit-role-grant-scope") != 0)
    rc = 147;
  else if (g_strcmp0 (role, "site.audit-role-grant") != 0)
    rc = 148;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 149;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) role);
  duckdb_destroy_result (&result);
  if (rc == 0)
    rc = check_live_audit_projection_for_action (handle, "role_grant",
        "audit-role-grant-user", "audit-role-grant-scope",
        "site.audit-role-grant", 1490);
  g_object_unref (handle);
  return rc;
}

static gint
check_role_revoke_emits_audit_row (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 150;
  if (seed_audit_role_permission (handle, "site.audit-role-revoke",
          "site.audit-role-revoke.read") != 0) {
    g_object_unref (handle);
    return 151;
  }

  g_autoptr (wyl_role_grant_req_t) grant = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (grant, "audit-role-revoke-user");
  wyl_role_grant_req_set_role_id (grant, "site.audit-role-revoke");
  wyl_role_grant_req_set_scope (grant, "audit-role-revoke-scope");
  if (wyl_role_grant (handle, grant) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 152;
  }

  g_autoptr (wyl_role_revoke_req_t) revoke = wyl_role_revoke_req_new ();
  wyl_role_revoke_req_set_subject_id (revoke, "audit-role-revoke-user");
  wyl_role_revoke_req_set_role_id (revoke, "site.audit-role-revoke");
  wyl_role_revoke_req_set_scope (revoke, "audit-role-revoke-scope");
  if (wyl_role_revoke (handle, revoke) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 153;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT subject_id, action, resource_id, deny_origin, decision "
          "FROM audit_events WHERE action = 'role_revoke';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 154;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 155;
  }

  gint rc = 0;
  const gchar *subject = duckdb_value_varchar (&result, 0, 0);
  const gchar *action = duckdb_value_varchar (&result, 1, 0);
  const gchar *resource = duckdb_value_varchar (&result, 2, 0);
  const gchar *role = duckdb_value_varchar (&result, 3, 0);
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);
  if (g_strcmp0 (subject, "audit-role-revoke-user") != 0)
    rc = 156;
  else if (g_strcmp0 (action, "role_revoke") != 0)
    rc = 157;
  else if (g_strcmp0 (resource, "audit-role-revoke-scope") != 0)
    rc = 158;
  else if (g_strcmp0 (role, "site.audit-role-revoke") != 0)
    rc = 159;
  else if (decision != WYL_DECISION_ALLOW)
    rc = 160;

  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
  duckdb_free ((void *) role);
  duckdb_destroy_result (&result);
  if (rc == 0)
    rc = check_live_audit_projection_for_action (handle, "role_revoke",
        "audit-role-revoke-user", "audit-role-revoke-scope",
        "site.audit-role-revoke", 1600);
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

static gint
check_emit_projects_wirelog_facts_immediately (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 193;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "audit-live-user");
  wyl_audit_event_set_action (ev, "audit-live-action");
  wyl_audit_event_set_resource_id (ev, "audit-live-resource");
  wyl_audit_event_set_deny_reason (ev, "not_armed");
  wyl_audit_event_set_deny_origin (ev, "perm_state");
  wyl_audit_event_set_decision (ev, WYL_DECISION_DENY);
  g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);
  gint64 created_at_us = wyl_audit_event_get_created_at_us (ev);

  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 194;
  }

  gboolean contains = FALSE;
  if (contains_audit_event_fact (handle, id, created_at_us, "deny", &contains)
      != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 195;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_subject", id,
          "audit-live-user", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 196;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_action", id,
          "audit-live-action", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 197;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_resource", id,
          "audit-live-resource", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 198;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_reason", id,
          "not_armed", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 199;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_origin", id,
          "perm_state", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 200;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_emit_projects_sparse_wirelog_facts_immediately (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 201;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_action (ev, "audit-live-sparse-action");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);
  gint64 created_at_us = wyl_audit_event_get_created_at_us (ev);

  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 202;
  }

  gboolean contains = FALSE;
  if (contains_audit_event_fact (handle, id, created_at_us, "allow", &contains)
      != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 203;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_action", id,
          "audit-live-sparse-action", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 204;
  }

  static const gchar *relations[] = {
    "audit_event_subject",
    "audit_event_resource",
    "audit_event_deny_reason",
    "audit_event_deny_origin",
    "audit_event_request_id",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (relations); i++) {
    guint count = 0;
    if (count_audit_attr_facts (handle, relations[i], id, &count)
        != WYRELOG_E_OK) {
      g_object_unref (handle);
      return (gint) (205 + i);
    }
    if (count != 0) {
      g_object_unref (handle);
      return (gint) (210 + i);
    }
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_emit_reports_live_projection_failure (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 215;

  wyl_handle_set_engine_insert_fault_once (handle, "audit_event_input",
      WYRELOG_E_INTERNAL);

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "audit-live-fail-user");
  wyl_audit_event_set_action (ev, "audit-live-fail-action");
  wyl_audit_event_set_decision (ev, WYL_DECISION_DENY);
  g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);
  if (wyl_audit_emit (handle, ev) != WYRELOG_E_INTERNAL) {
    g_object_unref (handle);
    return 216;
  }
  gint64 count = -1;
  if (!runtime_count_audit_rows (handle, id, &count) || count != 0) {
    g_object_unref (handle);
    return 225;
  }
  if (!policy_count_audit_rows (handle, id, &count) || count != 0) {
    g_object_unref (handle);
    return 226;
  }
  g_autofree gchar *state = NULL;
  gint64 attempt_count = -1;
  if (!policy_get_audit_intention_state (handle, id, &state, &attempt_count)) {
    g_object_unref (handle);
    return 502;
  }
  if (g_strcmp0 (state, "failed") != 0 || attempt_count != 1) {
    g_object_unref (handle);
    return 503;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_failed_duplicate_emit_keeps_durable_rows (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 227;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "audit-live-duplicate-user");
  wyl_audit_event_set_action (ev, "audit-live-duplicate-action");
  wyl_audit_event_set_resource_id (ev, "audit-live-duplicate-resource");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);
  gint64 created_at_us = wyl_audit_event_get_created_at_us (ev);

  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 228;
  }

  wyl_handle_set_engine_insert_fault_once (handle, "audit_event_input",
      WYRELOG_E_INTERNAL);
  if (wyl_audit_emit (handle, ev) != WYRELOG_E_INTERNAL) {
    g_object_unref (handle);
    return 229;
  }

  gint64 count = -1;
  if (!runtime_count_audit_rows (handle, id, &count) || count != 1) {
    g_object_unref (handle);
    return 230;
  }
  if (!policy_count_audit_rows (handle, id, &count) || count != 1) {
    g_object_unref (handle);
    return 231;
  }
  g_autofree gchar *state = NULL;
  gint64 attempt_count = -1;
  if (!policy_get_audit_intention_state (handle, id, &state, &attempt_count)) {
    g_object_unref (handle);
    return 504;
  }
  if (g_strcmp0 (state, "committed") != 0 || attempt_count != 0) {
    g_object_unref (handle);
    return 505;
  }
  gboolean contains = FALSE;
  if (contains_audit_event_fact (handle, id, created_at_us, "allow",
          &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 232;
  }

  g_object_unref (handle);
  return 0;
}

static gint
check_emit_rolls_back_partial_live_projection_failure (void)
{
  static const gchar *fault_relations[] = {
    "audit_event_subject_input",
    "audit_event_action_input",
    "audit_event_resource_input",
    "audit_event_deny_reason_input",
    "audit_event_deny_origin_input",
    "audit_event_request_id_input",
  };
  static const gchar *projected_relations[] = {
    "audit_event",
    "audit_event_subject",
    "audit_event_action",
    "audit_event_resource",
    "audit_event_deny_reason",
    "audit_event_deny_origin",
    "audit_event_request_id",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (fault_relations); i++) {
    WylHandle *handle = NULL;
    if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
      return (gint) (264 + i);

    wyl_handle_set_engine_insert_fault_once (handle, fault_relations[i],
        WYRELOG_E_INTERNAL);

    g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
    wyl_audit_event_set_subject_id (ev, "audit-live-partial-user");
    wyl_audit_event_set_action (ev, "audit-live-partial-action");
    wyl_audit_event_set_resource_id (ev, "audit-live-partial-resource");
    wyl_audit_event_set_deny_reason (ev, "not_armed");
    wyl_audit_event_set_deny_origin (ev, "perm_state");
    wyl_audit_event_set_request_id (ev, "req-partial");
    wyl_audit_event_set_decision (ev, WYL_DECISION_DENY);
    g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);

    if (wyl_audit_emit (handle, ev) != WYRELOG_E_INTERNAL) {
      g_object_unref (handle);
      return (gint) (270 + i);
    }
    gint64 count = -1;
    if (!runtime_count_audit_rows (handle, id, &count) || count != 0) {
      g_object_unref (handle);
      return (gint) (390 + i);
    }
    if (!policy_count_audit_rows (handle, id, &count) || count != 0) {
      g_object_unref (handle);
      return (gint) (400 + i);
    }

    for (gsize j = 0; j < G_N_ELEMENTS (projected_relations); j++) {
      guint count = 0;
      if (count_audit_attr_facts (handle, projected_relations[j], id, &count)
          != WYRELOG_E_OK) {
        g_object_unref (handle);
        return (gint) (276 + i * 10 + j);
      }
      if (count != 0) {
        g_object_unref (handle);
        return (gint) (336 + i * 10 + j);
      }
    }

    g_object_unref (handle);
  }
  return 0;
}

static gint
check_denied_login_skip_mfa_projects_audit_fact (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 217;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "audit-live-skip-mfa-denied-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_POLICY) {
    g_object_unref (handle);
    return 218;
  }
  if (session != NULL) {
    g_object_unref (handle);
    return 219;
  }

  gboolean contains = FALSE;
  gint64 authenticated[2];
  if (intern_symbol (handle, "audit-live-skip-mfa-denied-user",
          &authenticated[0]) != WYRELOG_E_OK
      || intern_symbol (handle, "authenticated", &authenticated[1])
      != WYRELOG_E_OK
      || wyl_handle_engine_contains (handle, "principal_state", authenticated,
          2, &contains) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 220;
  }
  if (contains) {
    g_object_unref (handle);
    return 221;
  }

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT id FROM audit_events WHERE action = 'login_skip_mfa';",
          &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 222;
  }
  if (duckdb_row_count (&result) != 1) {
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 223;
  }
  const gchar *audit_id = duckdb_value_varchar (&result, 0, 0);
  if (contains_audit_event_attr_fact (handle, "audit_event_action",
          audit_id, "login_skip_mfa", &contains) != WYRELOG_E_OK || !contains) {
    duckdb_free ((void *) audit_id);
    duckdb_destroy_result (&result);
    g_object_unref (handle);
    return 224;
  }

  duckdb_free ((void *) audit_id);
  duckdb_destroy_result (&result);
  g_object_unref (handle);
  return 0;
}

static gint
check_policy_store_audit_rows_load_wirelog_facts (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 161;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  static const gchar *full_id = "01890c10-2e3f-7000-8000-000000000010";
  gboolean full_inserted = FALSE;
  if (wyl_policy_store_append_audit_event_full (store, full_id, 1001,
          "audit-fact-user", "audit-fact-action", "audit-fact-resource",
          "not_armed", "perm_state", "req-audit-fact", WYL_DECISION_DENY,
          &full_inserted) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 162;
  }
  if (!full_inserted) {
    g_object_unref (handle);
    return 194;
  }
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 163;
  }

  gboolean contains = FALSE;
  wyrelog_error_t fact_rc =
      contains_audit_event_fact (handle, full_id, 1001, "deny", &contains);
  if (fact_rc != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 192;
  }
  if (!contains) {
    g_object_unref (handle);
    return 164;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_subject", full_id,
          "audit-fact-user", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 165;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_action", full_id,
          "audit-fact-action", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 166;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_resource", full_id,
          "audit-fact-resource", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 167;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_reason",
          full_id, "not_armed", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 168;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_origin",
          full_id, "perm_state", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 169;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_request_id",
          full_id, "req-audit-fact", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 193;
  }

  static const gchar *sparse_id = "01890c10-2e3f-7000-8000-000000000011";
  if (wyl_policy_store_append_audit_event (store, sparse_id, 1002, NULL,
          "audit-sparse-action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 170;
  }
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK) {
    g_object_unref (handle);
    return 171;
  }
  if (contains_audit_event_fact (handle, sparse_id, 1002, "allow", &contains)
      != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 172;
  }
  if (contains_audit_event_attr_fact (handle, "audit_event_action", sparse_id,
          "audit-sparse-action", &contains) != WYRELOG_E_OK || !contains) {
    g_object_unref (handle);
    return 173;
  }

  static const struct
  {
    const gchar *relation;
    guint expected;
  } optional_counts[] = {
    {"audit_event_subject", 0},
    {"audit_event_resource", 0},
    {"audit_event_deny_reason", 0},
    {"audit_event_deny_origin", 0},
    {"audit_event_request_id", 0},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (optional_counts); i++) {
    guint count = 0;
    if (count_audit_attr_facts (handle, optional_counts[i].relation,
            sparse_id, &count) != WYRELOG_E_OK) {
      g_object_unref (handle);
      return (gint) (174 + i);
    }
    if (count != optional_counts[i].expected) {
      g_object_unref (handle);
      return (gint) (180 + i);
    }
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
  if ((rc = check_query_events_json_filters_rows ()) != 0)
    return rc;
  if ((rc = check_emit_mirrors_policy_store_row ()) != 0)
    return rc;
  if ((rc = check_policy_store_audit_replay_loads_runtime_query ()) != 0)
    return rc;
  if ((rc = check_emit_replays_runtime_query_after_table_loss ()) != 0)
    return rc;
  if ((rc = check_audit_conn_insert_event_idempotence ()) != 0)
    return rc;
  if ((rc = check_duplicate_emit_keeps_runtime_row ()) != 0)
    return rc;
  if ((rc = check_policy_store_audit_replay_rolls_back_corrupt_row ()) != 0)
    return rc;
  if ((rc = check_emit_projects_wirelog_facts_immediately ()) != 0)
    return rc;
  if ((rc = check_emit_projects_sparse_wirelog_facts_immediately ()) != 0)
    return rc;
  if ((rc = check_emit_reports_live_projection_failure ()) != 0)
    return rc;
  if ((rc = check_failed_duplicate_emit_keeps_durable_rows ()) != 0)
    return rc;
  if ((rc = check_emit_rolls_back_partial_live_projection_failure ()) != 0)
    return rc;
  if ((rc = check_decide_persists_representative_deny_reason ()) != 0)
    return rc;
  if ((rc = check_decide_allows_when_runtime_audit_projection_fails ()) != 0)
    return rc;
  if ((rc = check_permission_grant_rolls_back_on_store_audit_failure ()) != 0)
    return rc;
  if ((rc = check_role_grant_rolls_back_on_store_audit_failure ()) != 0)
    return rc;
  if ((rc = check_permission_grant_survives_runtime_audit_failure ()) != 0)
    return rc;
  if ((rc = check_login_survives_runtime_audit_failure ()) != 0)
    return rc;
  if ((rc = check_session_transition_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_login_session_state_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_principal_transition_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_login_principal_state_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_emits_canonical_audit_row ()) != 0)
    return rc;
  if ((rc = check_denied_login_skip_mfa_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_denied_login_skip_mfa_reports_audit_failure ()) != 0)
    return rc;
  if ((rc = check_allowed_login_skip_mfa_rolls_back_on_store_audit_failure ())
      != 0)
    return rc;
  if ((rc = check_login_session_state_rolls_back_on_store_audit_failure ())
      != 0)
    return rc;
  if ((rc = check_denied_login_skip_mfa_projects_audit_fact ()) != 0)
    return rc;
  if ((rc = check_permission_grant_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_permission_grant_actor_emits_audit_subject ()) != 0)
    return rc;
  if ((rc = check_permission_revoke_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_role_grant_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_role_revoke_emits_audit_row ()) != 0)
    return rc;
  if ((rc = check_policy_store_audit_rows_load_wirelog_facts ()) != 0)
    return rc;
  if ((rc = check_emit_rejects_null_args ()) != 0)
    return rc;
  return 0;
}

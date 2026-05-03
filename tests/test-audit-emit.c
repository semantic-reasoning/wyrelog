/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <duckdb.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/wyl-handle-private.h"

/*
 * End-to-end audit-emit test. wyl_init opens the audit log and
 * creates the schema; we then construct an audit event, hand it to
 * wyl_audit_emit, and verify the row landed in the audit_events
 * table by querying the underlying DuckDB connection through the
 * private accessor pair.
 */

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
          "SELECT id, subject_id, action, resource_id, decision "
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
  gint16 decision = (gint16) duckdb_value_int64 (&result, 4, 0);

  if (g_strcmp0 (id, expected_id) != 0)
    rc = 23;
  else if (g_strcmp0 (subject, "bob") != 0)
    rc = 24;
  else if (g_strcmp0 (action, "write") != 0)
    rc = 25;
  else if (g_strcmp0 (resource, "doc/99") != 0)
    rc = 26;
  else if (decision != WYL_DECISION_DENY)
    rc = 27;

  duckdb_free ((void *) id);
  duckdb_free ((void *) subject);
  duckdb_free ((void *) action);
  duckdb_free ((void *) resource);
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
  if ((rc = check_emit_rejects_null_args ()) != 0)
    return rc;
  return 0;
}

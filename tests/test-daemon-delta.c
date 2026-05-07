/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>
#include <duckdb.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/audit/conn-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "daemon/delta.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static wyrelog_error_t
intern_symbol (WylHandle *handle, const gchar *symbol, gint64 *out_id)
{
  return wyl_handle_intern_engine_symbol (handle, symbol, out_id);
}

static wyrelog_error_t
intern3 (WylHandle *handle, const gchar *a, const gchar *b, const gchar *c,
    gint64 row[3])
{
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return intern_symbol (handle, c, &row[2]);
}

static wyrelog_error_t
intern_perm_event7 (WylHandle *handle, gint64 event_id, const gchar *subject,
    const gchar *perm, const gchar *scope, const gchar *event,
    const gchar *from_state, const gchar *to_state, gint64 row[7])
{
  row[0] = event_id;
  wyrelog_error_t rc = intern_symbol (handle, subject, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, perm, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, scope, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, event, &row[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, from_state, &row[5]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return intern_symbol (handle, to_state, &row[6]);
}

static wyrelog_error_t
contains_audit_event_fact (WylHandle *handle, const gchar *id,
    gint64 created_at_us, gboolean *out_contains)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  row[1] = created_at_us;
  rc = intern_symbol (handle, "allow", &row[2]);
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
  const gchar *action;
  const gchar *subject;
  const gchar *resource;
  const gchar *reason;
  const gchar *origin;
  gchar *id;
  gint64 created_at_us;
  guint matches;
} AuditRowLookup;

typedef AuditRowLookup AuditRowCount;

static wyrelog_error_t
lookup_audit_row_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, gpointer user_data)
{
  (void) request_id;
  AuditRowLookup *lookup = user_data;

  if (decision != WYL_DECISION_ALLOW
      || g_strcmp0 (action, lookup->action) != 0
      || g_strcmp0 (subject_id, lookup->subject) != 0
      || g_strcmp0 (resource_id, lookup->resource) != 0
      || g_strcmp0 (deny_reason, lookup->reason) != 0
      || g_strcmp0 (deny_origin, lookup->origin) != 0)
    return WYRELOG_E_OK;

  lookup->matches++;
  g_free (lookup->id);
  lookup->id = g_strdup (id);
  lookup->created_at_us = created_at_us;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
count_audit_row_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, gpointer user_data)
{
  (void) id;
  (void) created_at_us;
  (void) request_id;
  AuditRowCount *count = user_data;

  if (decision == WYL_DECISION_ALLOW
      && g_strcmp0 (action, count->action) == 0
      && g_strcmp0 (subject_id, count->subject) == 0
      && g_strcmp0 (resource_id, count->resource) == 0
      && g_strcmp0 (deny_reason, count->reason) == 0
      && g_strcmp0 (deny_origin, count->origin) == 0)
    count->matches++;
  return WYRELOG_E_OK;
}

static gboolean
lookup_policy_audit_row (WylHandle *handle, const gchar *action,
    const gchar *subject, const gchar *resource, const gchar *reason,
    const gchar *origin, gchar **out_id, gint64 *out_created_at_us)
{
  AuditRowLookup lookup = {
    .action = action,
    .subject = subject,
    .resource = resource,
    .reason = reason,
    .origin = origin,
    .created_at_us = -1,
  };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_foreach_audit_event (store,
      lookup_audit_row_cb, &lookup);
  if (rc != WYRELOG_E_OK || lookup.matches != 1) {
    g_free (lookup.id);
    return FALSE;
  }

  *out_id = g_steal_pointer (&lookup.id);
  *out_created_at_us = lookup.created_at_us;
  return TRUE;
}

static gboolean
count_policy_audit_rows (WylHandle *handle, const gchar *action,
    const gchar *subject, const gchar *resource, const gchar *reason,
    const gchar *origin, guint *out_matches)
{
  AuditRowCount count = {
    .action = action,
    .subject = subject,
    .resource = resource,
    .reason = reason,
    .origin = origin,
  };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_foreach_audit_event (store,
      count_audit_row_cb, &count);
  if (rc != WYRELOG_E_OK)
    return FALSE;

  *out_matches = count.matches;
  return TRUE;
}

static wyrelog_error_t
drop_audit_events_table (WylHandle *handle)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };

  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
malform_audit_events_table (WylHandle *handle)
{
  duckdb_result result = { 0 };
  wyrelog_error_t rc = drop_audit_events_table (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  if (duckdb_query (conn,
          "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static gint
check_delta_callback_ignores_runtime_projection_failure (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[3];
  WylDaemonRuntime runtime = { 0 };

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;
  runtime.handle = handle;
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 11;
  if (!g_atomic_int_get (&runtime.delta_session_live))
    return 26;
  if (malform_audit_events_table (handle) != WYRELOG_E_OK)
    return 12;
  if (intern3 (handle, "daemon-delta-audit-user", "wr.viewer",
          "daemon-delta-audit-scope", row) != WYRELOG_E_OK)
    return 13;

  if (wyl_handle_engine_insert (handle, "member_of", row, 3) != WYRELOG_E_OK)
    return 14;
  if (runtime.inserted == 0)
    return 15;
  if (runtime.delta_events_seen == 0 || runtime.last_delta_event_us <= 0)
    return 27;
  if (runtime.audit_errors != 0)
    return 16;
  if (g_atomic_int_get (&runtime.audit_degraded))
    return 28;
  if (runtime.last_audit_error != WYRELOG_E_OK)
    return 17;

  g_autofree gchar *id = NULL;
  gint64 created_at_us = -1;
  if (!lookup_policy_audit_row (handle, "effective_member_delta",
          "daemon-delta-audit-user", "wr.viewer", "insert",
          "daemon-delta-audit-scope", &id, &created_at_us))
    return 18;
  gboolean contains = FALSE;
  if (contains_audit_event_fact (handle, id, created_at_us, &contains)
      != WYRELOG_E_OK || !contains)
    return 19;
  if (contains_audit_event_attr_fact (handle, "audit_event_action", id,
          "effective_member_delta", &contains) != WYRELOG_E_OK || !contains)
    return 20;
  if (contains_audit_event_attr_fact (handle, "audit_event_subject", id,
          "daemon-delta-audit-user", &contains) != WYRELOG_E_OK || !contains)
    return 21;
  if (contains_audit_event_attr_fact (handle, "audit_event_resource", id,
          "wr.viewer", &contains) != WYRELOG_E_OK || !contains)
    return 22;
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_reason", id,
          "insert", &contains) != WYRELOG_E_OK || !contains)
    return 23;
  if (contains_audit_event_attr_fact (handle, "audit_event_deny_origin", id,
          "daemon-delta-audit-scope", &contains) != WYRELOG_E_OK || !contains)
    return 24;

  if (wyl_handle_engine_set_delta_callback (handle, NULL, NULL)
      != WYRELOG_E_OK)
    return 25;
  return 0;
}

static gint
check_perm_state_delta_persists_audit_rows (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 event_row[7];
  WylDaemonRuntime runtime = { 0 };

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;
  runtime.handle = handle;
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 51;
  if (!g_atomic_int_get (&runtime.delta_session_live))
    return 64;
  if (intern_perm_event7 (handle, 701, "daemon-delta-perm-user",
          "site.daemon-delta.perm", "daemon-delta-perm-scope", "grant",
          "dormant", "armed", event_row) != WYRELOG_E_OK)
    return 52;

  if (wyl_handle_engine_insert (handle, "perm_state_event", event_row, 7)
      != WYRELOG_E_OK)
    return 53;
  if (runtime.inserted == 0)
    return 54;
  if (runtime.delta_events_seen == 0 || runtime.last_delta_event_us <= 0)
    return 65;
  if (runtime.audit_errors != 0)
    return 55;
  if (g_atomic_int_get (&runtime.audit_degraded))
    return 66;

  if (wyl_handle_engine_remove (handle, "perm_state_event", event_row, 7)
      != WYRELOG_E_OK)
    return 56;
  if (runtime.removed == 0)
    return 57;
  if (runtime.delta_events_seen < 2)
    return 67;
  if (runtime.audit_errors != 0)
    return 58;
  if (g_atomic_int_get (&runtime.audit_degraded))
    return 68;

  g_autofree gchar *insert_id = NULL;
  gint64 insert_created_at_us = -1;
  if (!lookup_policy_audit_row (handle, "perm_state_fired_delta_insert",
          "daemon-delta-perm-user", "site.daemon-delta.perm",
          "dormant:grant:armed", "daemon-delta-perm-scope", &insert_id,
          &insert_created_at_us))
    return 59;
  g_autofree gchar *remove_id = NULL;
  gint64 remove_created_at_us = -1;
  if (!lookup_policy_audit_row (handle, "perm_state_fired_delta_remove",
          "daemon-delta-perm-user", "site.daemon-delta.perm",
          "dormant:grant:armed", "daemon-delta-perm-scope", &remove_id,
          &remove_created_at_us))
    return 60;

  gboolean contains = FALSE;
  if (contains_audit_event_attr_fact (handle, "audit_event_action", insert_id,
          "perm_state_fired_delta_insert", &contains) != WYRELOG_E_OK
      || !contains)
    return 61;
  if (contains_audit_event_attr_fact (handle, "audit_event_action", remove_id,
          "perm_state_fired_delta_remove", &contains) != WYRELOG_E_OK
      || !contains)
    return 62;

  if (wyl_handle_engine_set_delta_callback (handle, NULL, NULL)
      != WYRELOG_E_OK)
    return 63;
  return 0;
}

static gint
check_invalid_perm_state_delta_skips_audit_rows (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 event_row[7];
  WylDaemonRuntime runtime = { 0 };

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;
  runtime.handle = handle;
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 71;
  if (!g_atomic_int_get (&runtime.delta_session_live))
    return 79;
  if (intern_perm_event7 (handle, 702, "daemon-delta-invalid-user",
          "site.daemon-delta.invalid", "daemon-delta-invalid-scope", "grant",
          "armed", "dormant", event_row) != WYRELOG_E_OK)
    return 72;

  if (wyl_handle_engine_insert (handle, "perm_state_event", event_row, 7)
      != WYRELOG_E_OK)
    return 73;
  if (runtime.inserted != 0 || runtime.removed != 0)
    return 74;
  if (runtime.delta_events_seen != 0 || runtime.last_delta_event_us != 0)
    return 80;
  if (runtime.audit_errors != 0)
    return 75;
  if (g_atomic_int_get (&runtime.audit_degraded))
    return 81;

  guint matches = 0;
  if (!count_policy_audit_rows (handle, "perm_state_fired_delta_insert",
          "daemon-delta-invalid-user", "site.daemon-delta.invalid",
          "armed:grant:dormant", "daemon-delta-invalid-scope", &matches))
    return 76;
  if (matches != 0)
    return 77;

  if (wyl_handle_engine_set_delta_callback (handle, NULL, NULL)
      != WYRELOG_E_OK)
    return 78;
  return 0;
}

static gint
check_delta_readiness_recovers_audit_table_loss (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;
  if (drop_audit_events_table (handle) != WYRELOG_E_OK)
    return 31;
  if (wyl_daemon_check_delta_ready (handle) != WYRELOG_E_OK)
    return 32;
  return 0;
}

static gint
check_delta_readiness_fails_on_malformed_audit_projection (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 40;
  if (malform_audit_events_table (handle) != WYRELOG_E_OK)
    return 41;
  if (wyl_daemon_check_delta_ready (handle) != WYRELOG_E_IO)
    return 42;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_delta_callback_ignores_runtime_projection_failure ()) != 0)
    return rc;
  if ((rc = check_perm_state_delta_persists_audit_rows ()) != 0)
    return rc;
  if ((rc = check_invalid_perm_state_delta_skips_audit_rows ()) != 0)
    return rc;
  if ((rc = check_delta_readiness_recovers_audit_table_loss ()) != 0)
    return rc;
  if ((rc = check_delta_readiness_fails_on_malformed_audit_projection ()) != 0)
    return rc;
  return 0;
}

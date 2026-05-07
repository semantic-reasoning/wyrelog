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
  if (malform_audit_events_table (handle) != WYRELOG_E_OK)
    return 12;
  if (intern3 (handle, "daemon-delta-audit-user", "wr.viewer",
          "daemon-delta-audit-scope", row) != WYRELOG_E_OK)
    return 13;

  if (wyl_handle_engine_insert (handle, "member_of", row, 3) != WYRELOG_E_OK)
    return 14;
  if (runtime.inserted == 0)
    return 15;
  if (runtime.audit_errors != 0)
    return 16;
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
  if ((rc = check_delta_readiness_recovers_audit_table_loss ()) != 0)
    return rc;
  if ((rc = check_delta_readiness_fails_on_malformed_audit_projection ()) != 0)
    return rc;
  return 0;
}

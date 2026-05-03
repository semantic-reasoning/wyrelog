/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "wyl-id-private.h"

#ifdef WYL_HAS_AUDIT
#include <duckdb.h>

#include "audit/conn-private.h"
#include "wyl-handle-private.h"
#endif

struct _WylAuditEvent
{
  GObject parent_instance;
  wyl_id_t id;
  gint64 created_at_us;
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
  wyl_decision_t decision;
};

G_DEFINE_FINAL_TYPE (WylAuditEvent, wyl_audit_event, G_TYPE_OBJECT);

static void
wyl_audit_event_finalize (GObject *object)
{
  WylAuditEvent *self = WYL_AUDIT_EVENT (object);

  g_free (self->subject_id);
  g_free (self->action);
  g_free (self->resource_id);

  G_OBJECT_CLASS (wyl_audit_event_parent_class)->finalize (object);
}

static void
wyl_audit_event_class_init (WylAuditEventClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_audit_event_finalize;
}

static void
wyl_audit_event_init (WylAuditEvent *self)
{
  /* Construct-time stamping: every WylAuditEvent gets a fresh
   * time-ordered identifier and a microsecond-resolution wall-clock
   * timestamp. The pair survives any future field additions because
   * id and created_at_us are treated as the immutable witnesses of
   * the event's existence; downstream serialisers can rely on them
   * to deduplicate and to order events without consulting any other
   * field. Failure to mint an id is fatal for this construction --
   * a zero-id event would collapse the uniqueness guarantee that
   * downstream readers depend on, so we abort rather than ship a
   * partially-initialised object. */
  if (wyl_id_new (&self->id) != WYRELOG_E_OK)
    g_error ("wyl_audit_event_init: failed to mint identifier");
  self->created_at_us = g_get_real_time ();
}

WylAuditEvent *
wyl_audit_event_new (void)
{
  return g_object_new (WYL_TYPE_AUDIT_EVENT, NULL);
}

gchar *
wyl_audit_event_dup_id_string (const WylAuditEvent *self)
{
  gchar buf[WYL_ID_STRING_BUF];

  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), NULL);

  if (wyl_id_format (&self->id, buf, sizeof buf) != WYRELOG_E_OK)
    return NULL;
  return g_strdup (buf);
}

gint64
wyl_audit_event_get_created_at_us (const WylAuditEvent *self)
{
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), -1);
  return self->created_at_us;
}

void
wyl_audit_event_set_subject_id (WylAuditEvent *self, const gchar *subject_id)
{
  g_return_if_fail (WYL_IS_AUDIT_EVENT (self));
  g_free (self->subject_id);
  self->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_audit_event_get_subject_id (const WylAuditEvent *self)
{
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), NULL);
  return self->subject_id;
}

void
wyl_audit_event_set_action (WylAuditEvent *self, const gchar *action)
{
  g_return_if_fail (WYL_IS_AUDIT_EVENT (self));
  g_free (self->action);
  self->action = g_strdup (action);
}

const gchar *
wyl_audit_event_get_action (const WylAuditEvent *self)
{
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), NULL);
  return self->action;
}

void
wyl_audit_event_set_resource_id (WylAuditEvent *self, const gchar *resource_id)
{
  g_return_if_fail (WYL_IS_AUDIT_EVENT (self));
  g_free (self->resource_id);
  self->resource_id = g_strdup (resource_id);
}

const gchar *
wyl_audit_event_get_resource_id (const WylAuditEvent *self)
{
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), NULL);
  return self->resource_id;
}

void
wyl_audit_event_set_decision (WylAuditEvent *self, wyl_decision_t decision)
{
  g_return_if_fail (WYL_IS_AUDIT_EVENT (self));
  self->decision = decision;
}

wyl_decision_t
wyl_audit_event_get_decision (const WylAuditEvent *self)
{
  /* Fail-closed default for a NULL or unset event: an audit event
   * that was never populated must not silently appear as ALLOW. */
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), WYL_DECISION_DENY);
  return self->decision;
}

wyrelog_error_t
wyl_audit_emit (WylHandle *handle, const WylAuditEvent *event)
{
#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *audit_conn;
  duckdb_connection conn;
  duckdb_prepared_statement stmt;
  duckdb_result result;
  duckdb_state rc;
  gchar id_buf[WYL_ID_STRING_BUF];
  const gchar *value;

  if (handle == NULL || event == NULL)
    return WYRELOG_E_INVALID;

  audit_conn = wyl_handle_get_audit_conn (handle);
  if (audit_conn == NULL)
    return WYRELOG_E_INTERNAL;

  conn = wyl_audit_conn_get_connection (audit_conn);

  static const gchar *sql =
      "INSERT INTO audit_events "
      "(id, created_at_us, subject_id, action, resource_id, decision) "
      "VALUES (?, ?, ?, ?, ?, ?);";

  if (duckdb_prepare (conn, sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  if (wyl_id_format (&event->id, id_buf, sizeof id_buf) != WYRELOG_E_OK) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_INTERNAL;
  }
  duckdb_bind_varchar (stmt, 1, id_buf);
  duckdb_bind_int64 (stmt, 2, event->created_at_us);

  value = event->subject_id;
  if (value != NULL)
    duckdb_bind_varchar (stmt, 3, value);
  else
    duckdb_bind_null (stmt, 3);

  value = event->action;
  if (value != NULL)
    duckdb_bind_varchar (stmt, 4, value);
  else
    duckdb_bind_null (stmt, 4);

  value = event->resource_id;
  if (value != NULL)
    duckdb_bind_varchar (stmt, 5, value);
  else
    duckdb_bind_null (stmt, 5);

  duckdb_bind_int16 (stmt, 6, (int16_t) event->decision);

  rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);

  return (rc == DuckDBSuccess) ? WYRELOG_E_OK : WYRELOG_E_IO;
#else
  (void) handle;
  (void) event;
  return WYRELOG_E_INTERNAL;
#endif
}

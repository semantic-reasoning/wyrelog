/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "audit/event-private.h"
#include "wyl-id-private.h"

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"
#include "policy/store-private.h"
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
  gchar *deny_reason;
  gchar *deny_origin;
  gchar *request_id;
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
  g_free (self->deny_reason);
  g_free (self->deny_origin);
  g_free (self->request_id);

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

wyrelog_error_t
wyl_audit_event_new_from_fields (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, WylAuditEvent **out_event)
{
  wyl_id_t parsed_id;

  if (out_event == NULL)
    return WYRELOG_E_INVALID;
  *out_event = NULL;
  if (id == NULL || created_at_us < 0)
    return WYRELOG_E_INVALID;
  if (decision != WYL_DECISION_DENY && decision != WYL_DECISION_ALLOW)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_id_parse (id, &parsed_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylAuditEvent *self = wyl_audit_event_new ();
  self->id = parsed_id;
  self->created_at_us = created_at_us;
  wyl_audit_event_set_subject_id (self, subject_id);
  wyl_audit_event_set_action (self, action);
  wyl_audit_event_set_resource_id (self, resource_id);
  wyl_audit_event_set_deny_reason (self, deny_reason);
  wyl_audit_event_set_deny_origin (self, deny_origin);
  wyl_audit_event_set_request_id (self, request_id);
  wyl_audit_event_set_decision (self, decision);

  *out_event = self;
  return WYRELOG_E_OK;
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
wyl_audit_event_set_deny_reason (WylAuditEvent *self, const gchar *deny_reason)
{
  g_return_if_fail (WYL_IS_AUDIT_EVENT (self));
  g_free (self->deny_reason);
  self->deny_reason = g_strdup (deny_reason);
}

const gchar *
wyl_audit_event_get_deny_reason (const WylAuditEvent *self)
{
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), NULL);
  return self->deny_reason;
}

void
wyl_audit_event_set_deny_origin (WylAuditEvent *self, const gchar *deny_origin)
{
  g_return_if_fail (WYL_IS_AUDIT_EVENT (self));
  g_free (self->deny_origin);
  self->deny_origin = g_strdup (deny_origin);
}

const gchar *
wyl_audit_event_get_deny_origin (const WylAuditEvent *self)
{
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), NULL);
  return self->deny_origin;
}

void
wyl_audit_event_set_request_id (WylAuditEvent *self, const gchar *request_id)
{
  g_return_if_fail (WYL_IS_AUDIT_EVENT (self));
  g_free (self->request_id);
  self->request_id = g_strdup (request_id);
}

const gchar *
wyl_audit_event_get_request_id (const WylAuditEvent *self)
{
  g_return_val_if_fail (WYL_IS_AUDIT_EVENT (self), NULL);
  return self->request_id;
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
wyl_audit_mirror_event (WylHandle *handle, const WylAuditEvent *event)
{
#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *audit_conn;
  gchar id_buf[WYL_ID_STRING_BUF];

  if (handle == NULL || event == NULL)
    return WYRELOG_E_INVALID;

  audit_conn = wyl_handle_get_audit_conn (handle);
  if (audit_conn == NULL)
    return WYRELOG_E_INTERNAL;
  wyrelog_error_t rc = wyl_audit_conn_create_schema (audit_conn);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (wyl_id_format (&event->id, id_buf, sizeof id_buf) != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;

  gboolean inserted = FALSE;
  return wyl_audit_conn_insert_event_full (audit_conn, id_buf,
      event->created_at_us, event->subject_id, event->action,
      event->resource_id, event->deny_reason, event->deny_origin,
      event->request_id, event->decision, &inserted);
#else
  (void) handle;
  (void) event;
  return WYRELOG_E_INTERNAL;
#endif
}

wyrelog_error_t
wyl_audit_emit (WylHandle *handle, const WylAuditEvent *event)
{
#ifdef WYL_HAS_AUDIT
  gchar id_buf[WYL_ID_STRING_BUF];
  gboolean store_inserted = FALSE;

  if (handle == NULL || event == NULL)
    return WYRELOG_E_INVALID;

  if (wyl_id_format (&event->id, id_buf, sizeof id_buf) != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;

  wyrelog_error_t store_rc =
      wyl_policy_store_record_audit_intention_full (wyl_handle_get_policy_store
      (handle), id_buf, event->created_at_us,
      event->subject_id, event->action, event->resource_id,
      event->deny_reason, event->deny_origin, event->request_id,
      event->decision,
      &store_inserted);
  if (store_rc != WYRELOG_E_OK)
    return store_rc;

  store_inserted = FALSE;
  store_rc =
      wyl_policy_store_append_audit_event_full (wyl_handle_get_policy_store
      (handle), id_buf, event->created_at_us,
      event->subject_id, event->action, event->resource_id,
      event->deny_reason, event->deny_origin, event->request_id,
      event->decision, &store_inserted);
  if (store_rc != WYRELOG_E_OK) {
    (void) wyl_policy_store_mark_audit_intention_failed
        (wyl_handle_get_policy_store (handle), id_buf,
        "sqlite audit append failed");
    return store_rc;
  }

  wyrelog_error_t rc = wyl_handle_insert_audit_fact (handle, id_buf,
      event->created_at_us,
      event->subject_id, event->action, event->resource_id,
      event->deny_reason, event->deny_origin, event->request_id,
      event->decision);
  if (rc != WYRELOG_E_OK) {
    if (store_inserted) {
      wyrelog_error_t cleanup_rc =
          wyl_policy_store_delete_audit_event (wyl_handle_get_policy_store
          (handle), id_buf);
      if (cleanup_rc != WYRELOG_E_OK)
        return cleanup_rc;
    }
    (void) wyl_policy_store_mark_audit_intention_failed
        (wyl_handle_get_policy_store (handle), id_buf,
        "wirelog fact projection failed");
    return rc;
  }

  wyl_audit_conn_t *audit_conn = wyl_handle_get_audit_conn (handle);
  if (audit_conn == NULL) {
    (void) wyl_policy_store_mark_audit_intention_committed
        (wyl_handle_get_policy_store (handle), id_buf);
    return WYRELOG_E_OK;
  }

  rc = wyl_audit_conn_create_schema (audit_conn);
  if (rc != WYRELOG_E_OK) {
    (void) wyl_policy_store_mark_audit_intention_failed
        (wyl_handle_get_policy_store (handle), id_buf,
        "duckdb schema unavailable");
    return WYRELOG_E_OK;
  }

  gboolean inserted = FALSE;
  rc = wyl_audit_conn_insert_event_full (audit_conn, id_buf,
      event->created_at_us, event->subject_id, event->action,
      event->resource_id, event->deny_reason, event->deny_origin,
      event->request_id, event->decision, &inserted);
  if (rc != WYRELOG_E_OK) {
    (void) wyl_policy_store_mark_audit_intention_failed
        (wyl_handle_get_policy_store (handle), id_buf, "duckdb append failed");
    return WYRELOG_E_OK;
  }

  (void) wyl_policy_store_mark_audit_intention_committed
      (wyl_handle_get_policy_store (handle), id_buf);

  return WYRELOG_E_OK;
#else
  (void) handle;
  (void) event;
  return WYRELOG_E_INTERNAL;
#endif
}

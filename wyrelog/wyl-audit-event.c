/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "wyl-id-private.h"

struct _WylAuditEvent
{
  GObject parent_instance;
  wyl_id_t id;
  gint64 created_at_us;
};

G_DEFINE_FINAL_TYPE (WylAuditEvent, wyl_audit_event, G_TYPE_OBJECT);

static void
wyl_audit_event_class_init (WylAuditEventClass *klass)
{
  (void) klass;
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

wyrelog_error_t
wyl_audit_emit (WylHandle *handle, const WylAuditEvent *event)
{
  (void) handle;
  (void) event;
  return WYRELOG_E_INTERNAL;
}

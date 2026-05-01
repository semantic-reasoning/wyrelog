/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _WylAuditEvent
{
  GObject parent_instance;
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
  (void) self;
}

wyrelog_error_t
wyl_audit_emit (WylHandle *handle, const WylAuditEvent *event)
{
  (void) handle;
  (void) event;
  return WYRELOG_E_INTERNAL;
}

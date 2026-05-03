/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/decide.h"
#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS;

/*
 * WylAuditEvent - immutable audit record passed to wyl_audit_emit.
 *
 * GObject-based so callers can keep refs while the daemon serializes
 * the event to the audit chain.
 */
G_DECLARE_FINAL_TYPE (WylAuditEvent, wyl_audit_event,
    WYL, AUDIT_EVENT, GObject);
#define WYL_TYPE_AUDIT_EVENT (wyl_audit_event_get_type ())

/*
 * Construct a fresh audit event stamped with a freshly minted
 * identifier and a wall-clock created_at. May abort the process via
 * g_error if the entropy source declines: a zero-identifier event
 * would collapse uniqueness for downstream serialisers, so fail-fast
 * is preferred over silently shipping a partially-initialised object.
 */
WylAuditEvent *wyl_audit_event_new (void);

gchar *wyl_audit_event_dup_id_string (const WylAuditEvent * self);

/*
 * Returns the construct-time wall-clock stamp in microseconds since
 * the Unix epoch (g_get_real_time). Returns -1 on a NULL argument so
 * callers can distinguish "no event" from a legitimate epoch-zero
 * stamp.
 */
gint64 wyl_audit_event_get_created_at_us (const WylAuditEvent * self);

/*
 * Setters / getters for the decision-context fields of an audit
 * event. Setters duplicate the caller's string so the event becomes
 * independent of the caller's buffer; passing NULL clears the
 * field. Getters return a borrowed pointer valid until the next set
 * call or until the event is finalised.
 */
void wyl_audit_event_set_subject_id (WylAuditEvent * self,
    const gchar * subject_id);
const gchar *wyl_audit_event_get_subject_id (const WylAuditEvent * self);

void wyl_audit_event_set_action (WylAuditEvent * self, const gchar * action);
const gchar *wyl_audit_event_get_action (const WylAuditEvent * self);

void wyl_audit_event_set_resource_id (WylAuditEvent * self,
    const gchar * resource_id);
const gchar *wyl_audit_event_get_resource_id (const WylAuditEvent * self);

/*
 * Records the verdict produced for the request the event describes.
 * Default for a freshly constructed event is WYL_DECISION_DENY so
 * an event the daemon never populated stays fail-closed at the
 * audit boundary.
 */
void wyl_audit_event_set_decision (WylAuditEvent * self,
    wyl_decision_t decision);

/*
 * Returns the verdict carried by |self|. Returns WYL_DECISION_DENY
 * on a NULL argument or non-WylAuditEvent so the fail-closed
 * contract holds across the API boundary.
 */
wyl_decision_t wyl_audit_event_get_decision (const WylAuditEvent * self);

wyrelog_error_t wyl_audit_emit (WylHandle * handle,
    const WylAuditEvent * event);

G_END_DECLS;

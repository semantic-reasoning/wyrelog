/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/audit.h"

G_BEGIN_DECLS;

/*
 * Rehydrates an audit event from persisted wire/store fields. This is private
 * because callers should not mint arbitrary ids or timestamps for newly
 * produced audit events.
 */
wyrelog_error_t wyl_audit_event_new_from_fields (const gchar * id,
    gint64 created_at_us,
    const gchar * subject_id,
    const gchar * action,
    const gchar * resource_id,
    const gchar * deny_reason,
    const gchar * deny_origin,
    const gchar * request_id,
    wyl_decision_t decision, WylAuditEvent ** out_event);

wyrelog_error_t wyl_audit_mirror_event (WylHandle * handle,
    const WylAuditEvent * event);

/* Best-effort completion for an event whose authoritative SQLite row and
 * intention have already committed. Mirror failures are recorded on the
 * intention and never invalidate the authoritative publication. */
void wyl_audit_complete_authoritative_event (WylHandle * handle,
    const WylAuditEvent * event);

G_END_DECLS;

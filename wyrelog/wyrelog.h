/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * WylHandle - server-side embedding handle.
 *
 * Owns the policy database, audit log, and worker threads of an
 * embedded wyrelog instance. Created with wyl_init, shut down with
 * wyl_shutdown, released with g_object_unref (or g_autoptr(WylHandle)
 * in scoped form).
 */
G_DECLARE_FINAL_TYPE (WylHandle, wyl_handle, WYL, HANDLE, GObject);
#define WYL_TYPE_HANDLE (wyl_handle_get_type ())

/*
 * WylSession - active authenticated session.
 *
 * Carries the principal identity, MFA state, and tenant binding for a
 * sequence of decide calls. Acquired through wyl_session_login,
 * released with g_object_unref / g_autoptr.
 */
G_DECLARE_FINAL_TYPE (WylSession, wyl_session, WYL, SESSION, GObject);
#define WYL_TYPE_SESSION (wyl_session_get_type ())

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
 * Plain integer session identifier. Stable across the lifetime of a
 * WylHandle; not a GObject.
 */
typedef guint64 wyl_session_id_t;

/*
 * Opaque request/response carriers for decide / login / perm.
 *
 * Constructed with the matching _new function, populated through
 * setters (added in follow-up commits) and freed with the matching
 * _free function or via g_autoptr (GLib autoptr cleanup is wired
 * below).
 */
typedef struct _wyl_decide_req wyl_decide_req_t;
typedef struct _wyl_decide_resp wyl_decide_resp_t;
typedef struct _wyl_login_req wyl_login_req_t;
typedef struct _wyl_grant_req wyl_grant_req_t;
typedef struct _wyl_revoke_req wyl_revoke_req_t;

wyl_decide_req_t *wyl_decide_req_new (void);
void wyl_decide_req_free (wyl_decide_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_decide_req_t, wyl_decide_req_free);

wyl_decide_resp_t *wyl_decide_resp_new (void);
void wyl_decide_resp_free (wyl_decide_resp_t * resp);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_decide_resp_t, wyl_decide_resp_free);

wyl_login_req_t *wyl_login_req_new (void);
void wyl_login_req_free (wyl_login_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_login_req_t, wyl_login_req_free);

wyl_grant_req_t *wyl_grant_req_new (void);
void wyl_grant_req_free (wyl_grant_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_grant_req_t, wyl_grant_req_free);

wyl_revoke_req_t *wyl_revoke_req_new (void);
void wyl_revoke_req_free (wyl_revoke_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_revoke_req_t, wyl_revoke_req_free);

/* Lifecycle */
wyrelog_error_t wyl_init (const gchar * config_path, WylHandle ** out_handle);
void wyl_shutdown (WylHandle * handle);

/* Decide */
wyrelog_error_t wyl_decide (WylHandle * handle,
    const wyl_decide_req_t * req, wyl_decide_resp_t * resp);

/* Sessions */
wyrelog_error_t wyl_session_login (WylHandle * handle,
    const wyl_login_req_t * req, WylSession ** out_session);
wyrelog_error_t wyl_session_logout (WylHandle * handle, wyl_session_id_t sid);

/* Permissions (admin) */
wyrelog_error_t wyl_perm_grant (WylHandle * handle,
    const wyl_grant_req_t * req);
wyrelog_error_t wyl_perm_revoke (WylHandle * handle,
    const wyl_revoke_req_t * req);

/* Audit */
wyrelog_error_t wyl_audit_emit (WylHandle * handle,
    const WylAuditEvent * event);

/* Meta */
const gchar *wyrelog_version_string (void);

G_END_DECLS;

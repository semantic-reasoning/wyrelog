/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS;

/*
 * WylSession - active login session.
 *
 * Carries the principal identity, MFA state, and tenant binding for a
 * sequence of decide calls. Acquired through wyl_session_login,
 * released with g_object_unref / g_autoptr.
 */
G_DECLARE_FINAL_TYPE (WylSession, wyl_session, WYL, SESSION, GObject);
#define WYL_TYPE_SESSION (wyl_session_get_type ())

/*
 * Plain integer session identifier. Stable across the lifetime of a
 * WylHandle; not a GObject.
 */
typedef guint64 wyl_session_id_t;

/*
 * Opaque login-request carrier. Constructed with wyl_login_req_new,
 * populated through setters (added in follow-up commits) and freed
 * with wyl_login_req_free or via g_autoptr.
 */
typedef struct _wyl_login_req wyl_login_req_t;

typedef wyrelog_error_t (*WylMfaValidator) (WylHandle * handle,
    WylSession * session, const gchar * proof, gpointer user_data);

wyl_login_req_t *wyl_login_req_new (void);
void wyl_login_req_free (wyl_login_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_login_req_t, wyl_login_req_free);

/*
 * Set the principal username carried by the login request. Replaces
 * any previously set value (the prior string is freed). |username|
 * may be NULL to clear the field; the caller's string is duplicated
 * into the request so it may be freed immediately after the call.
 */
void wyl_login_req_set_username (wyl_login_req_t * req, const gchar * username);

/*
 * Returns the borrowed username carried by |req|, or NULL when
 * unset. The pointer is owned by the request and remains valid
 * until the next set call or until the request is freed.
 */
const gchar *wyl_login_req_get_username (const wyl_login_req_t * req);

/*
 * Marks the request as already satisfying the MFA requirement. When TRUE,
 * wyl_session_login may drive the principal FSM through the login_skip_mfa
 * event and record the principal as authenticated. The host-side ingress
 * policy must allow this path through an explicit WylHandle override or a
 * non-production Policy DB deployment mode; otherwise login fails with
 * WYRELOG_E_POLICY. The default for a fresh request is FALSE.
 */
void wyl_login_req_set_skip_mfa (wyl_login_req_t * req, gboolean skip_mfa);
gboolean wyl_login_req_get_skip_mfa (const wyl_login_req_t * req);
void wyl_login_req_set_request_id (wyl_login_req_t * req,
    const gchar * request_id);
const gchar *wyl_login_req_get_request_id (const wyl_login_req_t * req);
void wyl_login_req_set_tenant (wyl_login_req_t * req, const gchar * tenant);
const gchar *wyl_login_req_get_tenant (const wyl_login_req_t * req);

wyrelog_error_t wyl_session_login (WylHandle * handle,
    const wyl_login_req_t * req, WylSession ** out_session);

/*
 * Trusted host-side transition primitive. This function records that MFA was
 * already verified by external trusted code; it does not inspect OTP material
 * and must not be wired directly to user-supplied HTTP or client proof.
 */
wyrelog_error_t wyl_session_mfa_verify (WylHandle * handle,
    WylSession * session);

/*
 * Proof-bearing MFA boundary. The principal transition is applied only after
 * |validator| accepts |proof|. Missing or empty proof and missing validator
 * fail before any Policy DB, audit, or read-engine mutation is attempted.
 */
wyrelog_error_t wyl_session_mfa_verify_with_proof (WylHandle * handle,
    WylSession * session, const gchar * proof, WylMfaValidator validator,
    gpointer user_data);
wyrelog_error_t wyl_session_elevate (WylHandle * handle, WylSession * session);
wyrelog_error_t wyl_session_drop_elevation (WylHandle * handle,
    WylSession * session);
wyrelog_error_t wyl_session_idle_timeout (WylHandle * handle,
    WylSession * session);
wyrelog_error_t wyl_session_expire (WylHandle * handle, WylSession * session);
wyrelog_error_t wyl_session_close (WylHandle * handle, WylSession * session);
wyrelog_error_t wyl_session_close_with_request_id (WylHandle * handle,
    WylSession * session, const gchar * request_id);
wyrelog_error_t wyl_session_logout (WylHandle * handle, wyl_session_id_t sid);

/*
 * Returns the session's construct-time identifier as a 36-character
 * canonical string (caller frees with g_free or g_autofree). May
 * return NULL only if the session is NULL or not a WylSession. The
 * id is independent of wyl_session_id_t (the integer handle used
 * for logout dispatch) -- this is the long-lived persistence-side
 * identifier carried into audit events.
 */
gchar *wyl_session_dup_id_string (const WylSession * self);

/*
 * Returns the construct-time wall-clock stamp in microseconds since
 * the Unix epoch (g_get_real_time). Returns -1 on a NULL argument.
 */
gint64 wyl_session_get_created_at_us (const WylSession * self);

/*
 * Returns the handle-scoped integer session id assigned to |self| on
 * the wyl_session_login success path. The id is non-zero for any
 * session returned through wyl_session_login and stable across the
 * lifetime of the owning WylHandle. Pass it to wyl_session_logout to
 * tear down the durable session state. Returns 0 when |self| is NULL
 * or not a WylSession.
 */
wyl_session_id_t wyl_session_get_id (const WylSession * self);

/*
 * Returns a heap-allocated copy of the principal username carried
 * into the session by wyl_session_login (i.e. wyl_login_req's
 * username field at login time). Returns NULL when the request
 * supplied no username or when |self| is NULL or not a WylSession.
 * Caller frees with g_free or g_autofree.
 */
gchar *wyl_session_dup_username (const WylSession * self);
gchar *wyl_session_dup_tenant (const WylSession * self);

G_END_DECLS;

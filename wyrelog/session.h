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
 * Marks the request as already satisfying the MFA requirement. When
 * TRUE, wyl_session_login drives the principal FSM through the
 * login_skip_mfa event and records the principal as authenticated.
 * The default for a fresh request is FALSE.
 */
void wyl_login_req_set_skip_mfa (wyl_login_req_t * req, gboolean skip_mfa);
gboolean wyl_login_req_get_skip_mfa (const wyl_login_req_t * req);

wyrelog_error_t wyl_session_login (WylHandle * handle,
    const wyl_login_req_t * req, WylSession ** out_session);
wyrelog_error_t wyl_session_mfa_verify (WylHandle * handle,
    WylSession * session);
wyrelog_error_t wyl_session_elevate (WylHandle * handle, WylSession * session);
wyrelog_error_t wyl_session_drop_elevation (WylHandle * handle,
    WylSession * session);
wyrelog_error_t wyl_session_close (WylHandle * handle, WylSession * session);
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
 * Returns a heap-allocated copy of the principal username carried
 * into the session by wyl_session_login (i.e. wyl_login_req's
 * username field at login time). Returns NULL when the request
 * supplied no username or when |self| is NULL or not a WylSession.
 * Caller frees with g_free or g_autofree.
 */
gchar *wyl_session_dup_username (const WylSession * self);

G_END_DECLS;

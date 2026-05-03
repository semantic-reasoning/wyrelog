/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS;

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

wyrelog_error_t wyl_session_login (WylHandle * handle,
    const wyl_login_req_t * req, WylSession ** out_session);
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

G_END_DECLS;

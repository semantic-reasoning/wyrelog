/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS;

/*
 * Opaque admin request carriers for grant / revoke.
 *
 * Constructed with the matching _new function, populated through
 * setters (added in follow-up commits) and freed with the matching
 * _free function or via g_autoptr.
 */
typedef struct _wyl_grant_req wyl_grant_req_t;
typedef struct _wyl_revoke_req wyl_revoke_req_t;

wyl_grant_req_t *wyl_grant_req_new (void);
void wyl_grant_req_free (wyl_grant_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_grant_req_t, wyl_grant_req_free);

/*
 * Setters / getters for the subject, action, and resource fields
 * of an admin grant request. Setters duplicate the caller's string
 * so the caller may free it immediately after the call; passing
 * NULL clears the field. Getters return a borrowed pointer that is
 * valid until the next set call or until the request is freed.
 */
void wyl_grant_req_set_subject_id (wyl_grant_req_t * req,
    const gchar * subject_id);
const gchar *wyl_grant_req_get_subject_id (const wyl_grant_req_t * req);

void wyl_grant_req_set_action (wyl_grant_req_t * req, const gchar * action);
const gchar *wyl_grant_req_get_action (const wyl_grant_req_t * req);

void wyl_grant_req_set_resource_id (wyl_grant_req_t * req,
    const gchar * resource_id);
const gchar *wyl_grant_req_get_resource_id (const wyl_grant_req_t * req);

wyl_revoke_req_t *wyl_revoke_req_new (void);
void wyl_revoke_req_free (wyl_revoke_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_revoke_req_t, wyl_revoke_req_free);

wyrelog_error_t wyl_perm_grant (WylHandle * handle,
    const wyl_grant_req_t * req);
wyrelog_error_t wyl_perm_revoke (WylHandle * handle,
    const wyl_revoke_req_t * req);

G_END_DECLS;

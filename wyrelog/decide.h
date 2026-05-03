/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS;

/*
 * Opaque request/response carriers for decide.
 *
 * Constructed with the matching _new function, populated through
 * setters (added in follow-up commits) and freed with the matching
 * _free function or via g_autoptr.
 */
typedef struct _wyl_decide_req wyl_decide_req_t;
typedef struct _wyl_decide_resp wyl_decide_resp_t;

wyl_decide_req_t *wyl_decide_req_new (void);
void wyl_decide_req_free (wyl_decide_req_t * req);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_decide_req_t, wyl_decide_req_free);

/*
 * Setters / getters for the subject, action, and resource fields
 * of a decide request. Setters duplicate the caller's string so
 * the caller may free it immediately after the call; passing NULL
 * clears the field. Getters return a borrowed pointer that is
 * valid until the next set call or until the request is freed.
 */
void wyl_decide_req_set_subject_id (wyl_decide_req_t * req,
    const gchar * subject_id);
const gchar *wyl_decide_req_get_subject_id (const wyl_decide_req_t * req);

void wyl_decide_req_set_action (wyl_decide_req_t * req, const gchar * action);
const gchar *wyl_decide_req_get_action (const wyl_decide_req_t * req);

void wyl_decide_req_set_resource_id (wyl_decide_req_t * req,
    const gchar * resource_id);
const gchar *wyl_decide_req_get_resource_id (const wyl_decide_req_t * req);

wyl_decide_resp_t *wyl_decide_resp_new (void);
void wyl_decide_resp_free (wyl_decide_resp_t * resp);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_decide_resp_t, wyl_decide_resp_free);

wyrelog_error_t wyl_decide (WylHandle * handle,
    const wyl_decide_req_t * req, wyl_decide_resp_t * resp);

G_END_DECLS;

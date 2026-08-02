/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/decide.h"

G_BEGIN_DECLS;

/*
 * Private decide levers that must NOT ride on the public ABI in
 * decide.h. Keeping the "assert this bearer authenticated" control off
 * the installed surface prevents an external embedder from self-asserting
 * an authenticated principal state it never earned.
 *
 * wyl_decide_req_set_service_bearer_authenticated marks a request as
 * carrying a service (svc:) bearer that the daemon has FULLY validated
 * against the live session, access-token exactness, and the service-auth
 * registry reservation. When set, wyl_decide injects a TRANSIENT
 * principal_state(subject,"authenticated") fact into the read engine for
 * the duration of that single decide only (see wyl-decide.c, #740 WALL 1).
 * The flag defaults FALSE (constructor is g_new0), so every existing
 * caller and every embedder is unaffected.
 *
 * ONLY the daemon's fully-validated service-bearer decide sites may set
 * this. Never set it for human bearers, session-token paths, the
 * service-credential operation coordinators (they gate on
 * WYL_SESSION_AUTH_METHOD_HUMAN), or the checks.c self-check
 * (synthetic subject "wyrelogd-skip-mfa-user").
 */
void wyl_decide_req_set_service_bearer_authenticated (wyl_decide_req_t * req,
    gboolean authenticated);
gboolean wyl_decide_req_get_service_bearer_authenticated
    (const wyl_decide_req_t * req);

G_END_DECLS;

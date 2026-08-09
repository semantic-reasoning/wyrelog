/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/decide.h"
#include <glib.h>
#include "auth/service-auth-coordination-private.h"

G_BEGIN_DECLS

void wyl_decide_req_set_service_bearer_authenticated
  (wyl_decide_req_t *req, gboolean authenticated);
gboolean wyl_decide_req_get_service_bearer_authenticated
  (const wyl_decide_req_t *req);
    typedef struct _WylServiceDecisionAuthority WylServiceDecisionAuthority;

/* Creates a request-local service decision capability after the sole bearer
 * resolver has validated the complete credential tuple. Success consumes
 * |*inout_lease|; every failure leaves it owned by the caller. */
wyrelog_error_t wyl_service_decision_authority_new_resolved
    (WylHandle * handle, WylServiceAuthReadLease ** inout_lease,
    const gchar * subject_id, const gchar * tenant_id,
    WylServiceDecisionAuthority ** out_authority);
void wyl_service_decision_authority_free
    (WylServiceDecisionAuthority * authority);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceDecisionAuthority,
    wyl_service_decision_authority_free);

/* Consumes |authority| exactly once. The retained resolver READ lease spans
 * request-context insert, signed-policy query, and cleanup. */
wyrelog_error_t wyl_decide_with_service_authority (WylHandle * handle,
    const wyl_decide_req_t * req, WylServiceDecisionAuthority * authority,
    wyl_decide_resp_t * resp);

G_END_DECLS

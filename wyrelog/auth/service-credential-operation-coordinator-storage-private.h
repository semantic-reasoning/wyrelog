/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-storage-private.h"

G_BEGIN_DECLS;

/* Persist or replay the journal entry selected solely by request_id.  The
 * caller must initialize out_record with
 * WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT; it is unchanged on error.
 * A successful replay may return any valid lifecycle state for the original
 * operation.  expires_at_us is deliberately not represented in the journal
 * record format and is therefore excluded from the durable identity tuple. */
wyrelog_error_t wyl_service_credential_operation_coordinator_begin_or_replay
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    const gchar * operation_id, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);

G_END_DECLS;

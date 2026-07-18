/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-journal-private.h"
G_BEGIN_DECLS
/* out_record must be initialized with WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT.
 * It is unchanged on failure and replaced (after validation) on success. */
    wyrelog_error_t wyl_service_credential_operation_coordinator_build_prepared
    (const WylServiceCredentialOperationCoordinatorRequest * request,
    const gchar * operation_id, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record);
G_END_DECLS

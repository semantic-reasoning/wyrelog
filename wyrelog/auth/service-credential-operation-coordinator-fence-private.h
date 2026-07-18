/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "auth/service-credential-operation-journal-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS
/* This is deliberately a classification, not a state transition.  The
 * caller owns fence lookup, durable checkpointing, and all retry policy. */
    typedef enum
{
  WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_COMMIT_REQUIRED = 1,
  WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_REPLAY_COMMITTED = 2,
  WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING = 3,
  WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_TERMINAL_NO_COMMIT = 4,
  WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_CONFLICT = 5,
} WylServiceCredentialOperationFenceClassification;

/* Classify a durable journal snapshot against the result of the read-only
 * operation-fence precheck.  |precheck_rc| must be WYRELOG_E_OK (a fence was
 * found) or WYRELOG_E_NOT_FOUND (no fence exists); other lookup errors are
 * propagated unchanged.  out_classification is unchanged on every error.
 *
 * A COMMITTED fence supplies the successor tuple which a later coordinator
 * step must durably checkpoint.  This helper never calls the policy store,
 * mutates the record or fence result, or writes journal storage. */
wyrelog_error_t wyl_service_credential_operation_coordinator_classify_fence
    (const WylServiceCredentialOperationRecord * record,
    wyrelog_error_t precheck_rc,
    const WylServiceCredentialFenceResult * fence,
    WylServiceCredentialOperationFenceClassification * out_classification);

G_END_DECLS

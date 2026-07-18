/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS
/* Recovery only reads durable policy evidence and, when that evidence proves
 * a successful server mutation, checkpoints the existing journal record. It
 * never invokes a server mutation or publishes a credential. */
    typedef enum
{
  WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_PENDING = 1,
  WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_TERMINAL_NO_COMMIT = 2,
  WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_CONFLICT = 3,
  WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED = 4,
  WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED_REPLAY = 5,
} WylServiceCredentialOperationRecoveryOutcome;

/* On success, returns the loaded PREPARED record for non-commit outcomes or
 * the durable SERVER_COMMITTED record after a checkpoint. A PREPARED request
 * with no fence evidence at or after expires_at_us fails WYRELOG_E_POLICY;
 * committed evidence remains recoverable after expiry. Future issuance must
 * independently enforce expiry. Caller outputs are unchanged on error. */
wyrelog_error_t wyl_service_credential_operation_coordinator_recover
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    wyl_policy_store_t * policy_store, GCancellable * cancellable,
    const gchar * request_id, gint64 now_us,
    WylServiceCredentialOperationRecoveryOutcome * out_outcome,
    WylServiceCredentialOperationRecord * out_record);
G_END_DECLS

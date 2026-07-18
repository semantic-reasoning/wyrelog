/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-recovery-private.h"
#include "auth/service-credential-operation-coordinator-fence-private.h"

wyrelog_error_t
    wyl_service_credential_operation_coordinator_recover
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    wyl_policy_store_t * policy_store, GCancellable * cancellable,
    const gchar * request_id, gint64 now_us,
    WylServiceCredentialOperationRecoveryOutcome * out_outcome,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord loaded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord checkpointed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialFenceResult fence = { 0 };
  WylServiceCredentialOperationFenceClassification classification;
  WylServiceCredentialOperationRecoveryOutcome outcome;
  gboolean replayed = FALSE;
  gboolean precheck_missing;
  wyrelog_error_t rc;
  if (storage == NULL || anchor == NULL || policy_store == NULL
      || out_outcome == NULL || out_record == NULL || now_us <= 0
      ||
      !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  rc = wyl_service_credential_operation_coordinator_load (storage, anchor,
      request_id, &loaded);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (loaded.kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE) {
    if (loaded.subject_id == NULL || loaded.tenant_id == NULL) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    rc = wyl_policy_store_precheck_service_credential_operation_fence_with_committed (policy_store, cancellable, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, request_id, loaded.subject_id, loaded.tenant_id, NULL, &fence);
  } else if (loaded.kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE) {
    if (loaded.old_credential_id == NULL) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    rc = wyl_policy_store_precheck_service_credential_operation_fence_with_committed (policy_store, cancellable, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, request_id, NULL, NULL, loaded.old_credential_id, &fence);
  } else {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  precheck_missing = rc == WYRELOG_E_NOT_FOUND;
  rc = wyl_service_credential_operation_coordinator_classify_fence (&loaded, rc,
      &fence, &classification);
  if (rc != WYRELOG_E_OK)
    goto out;
  switch (classification) {
    case WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING:
      if (loaded.state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
          && precheck_missing && now_us >= loaded.expires_at_us) {
        rc = WYRELOG_E_POLICY;
        goto out;
      }
      outcome = WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_PENDING;
      break;
    case WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_TERMINAL_NO_COMMIT:
      outcome = WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_TERMINAL_NO_COMMIT;
      break;
    case WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_CONFLICT:
      outcome = WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_CONFLICT;
      break;
    case WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_REPLAY_COMMITTED:
      outcome =
          WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED_REPLAY;
      break;
    case WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_COMMIT_REQUIRED:
      if (now_us < loaded.updated_at_us) {
        rc = WYRELOG_E_INVALID;
        goto out;
      }
      rc = wyl_service_credential_operation_coordinator_checkpoint_server_committed (storage, anchor, request_id, fence.successor_credential_id, fence.successor_generation, now_us, &replayed, &checkpointed);
      if (rc != WYRELOG_E_OK)
        goto out;
      outcome =
          replayed ?
          WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED_REPLAY :
          WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED;
      wyl_service_credential_operation_record_clear (&loaded);
      loaded = checkpointed;
      checkpointed = (WylServiceCredentialOperationRecord)
          WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
      break;
    default:
      rc = WYRELOG_E_POLICY;
      goto out;
  }
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = loaded;
  loaded = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  *out_outcome = outcome;
  rc = WYRELOG_E_OK;
out:
  wyl_service_credential_operation_record_clear (&checkpointed);
  wyl_service_credential_operation_record_clear (&loaded);
  return rc;
}

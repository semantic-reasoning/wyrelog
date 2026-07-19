/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-execute-private.h"
#include "policy/store-private.h"

wyrelog_error_t
    wyl_service_credential_operation_coordinator_authorize_and_execute
    (WylHandle * handle,
    const WylServiceCredentialOperationRecord * record,
    const gchar * authenticated_actor_subject_id,
    const WylServiceCredentialOperationExecuteRuntime * runtime,
    wyl_service_credential_issue_result_t * out)
{
  if (out != NULL)
    wyl_service_credential_issue_result_clear (out);
  if (handle == NULL || record == NULL || authenticated_actor_subject_id == NULL
      || runtime == NULL || runtime->revalidate == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  if (!wyl_service_credential_operation_record_is_valid (record)
      || !wyl_policy_service_actor_subject_is_valid
      (authenticated_actor_subject_id))
    return WYRELOG_E_INVALID;
  /* Structural ROTATE argument shape: a rotate intent with no CAS runtime can
   * never execute, so reject it with the other E_INVALID argument checks and
   * before the authority callback fires. */
  if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE
      && runtime->rotate_runtime == NULL)
    return WYRELOG_E_INVALID;
  if (record->state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
    return WYRELOG_E_POLICY;
  if (g_strcmp0 (authenticated_actor_subject_id, record->actor_subject_id) != 0)
    return WYRELOG_E_POLICY;
  /* Generation-binding gate: the CAS runtime must bind exactly the generation
   * the durable intent authorized. A mismatched intent can never execute, so
   * deny before the authority callback and its audit side effect. */
  if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE
      && runtime->rotate_runtime->old_credential_generation
      != record->expected_generation)
    return WYRELOG_E_POLICY;
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = runtime->revalidate,
    .data = runtime->revalidate_data,
  };
  switch (record->kind) {
    case WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE:{
      wyl_service_credential_issue_runtime_t issue_runtime = {
        .authorization = &authorization,
      };
      return wyl_service_credential_issue_with_runtime (handle,
          record->subject_id,
          record->tenant_id, record->actor_subject_id, record->request_id,
          record->expires_at_us, &issue_runtime, out);
    }
    case WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE:{
      wyl_service_credential_rotate_runtime_t rotate_runtime =
          *runtime->rotate_runtime;
      rotate_runtime.authorization = &authorization;
      return wyl_service_credential_rotate_with_runtime (handle,
          record->old_credential_id, record->actor_subject_id,
          record->request_id, record->expires_at_us, &rotate_runtime, out);
    }
    default:
      return WYRELOG_E_POLICY;
  }
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-journal-private.h"

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_prepared
    (const WylServiceCredentialOperationCoordinatorRequest * request,
    const gchar * operation_id, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record)
{
  if (out_record == NULL || request == NULL || operation_id == NULL
      || operation_id[0] == '\0' || now_us <= 0
      || !wyl_service_credential_operation_coordinator_request_is_valid
      (request))
    return WYRELOG_E_INVALID;
  *out_record = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  out_record->version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION;
  out_record->kind = request->kind;
  out_record->state = WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED;
  out_record->operation_id = g_strdup (operation_id);
  out_record->request_id = g_strdup (request->request_id);
  out_record->subject_id = g_strdup (request->subject_id);
  out_record->tenant_id = g_strdup (request->tenant_id);
  out_record->destination = g_strdup (request->destination);
  out_record->parent_identity = g_strdup (request->parent_identity);
  out_record->old_credential_id = g_strdup (request->old_credential_id);
  out_record->successor_generation = request->expected_generation;
  out_record->created_at_us = now_us;
  out_record->updated_at_us = now_us;
  if (out_record->operation_id == NULL || out_record->request_id == NULL
      || out_record->subject_id == NULL || out_record->destination == NULL
      || out_record->parent_identity == NULL
      || (request->tenant_id != NULL && out_record->tenant_id == NULL)
      || (request->old_credential_id != NULL
          && out_record->old_credential_id == NULL)) {
    wyl_service_credential_operation_record_clear (out_record);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

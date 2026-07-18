/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-journal-private.h"

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_prepared
    (const WylServiceCredentialOperationCoordinatorRequest * request,
    const gchar * operation_id, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord temp =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  if (out_record == NULL || request == NULL || operation_id == NULL
      || operation_id[0] == '\0' || now_us <= 0
      || !wyl_service_credential_operation_coordinator_request_is_valid
      (request))
    return WYRELOG_E_INVALID;
  temp.version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION;
  temp.kind = request->kind;
  temp.state = WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED;
  temp.operation_id = g_strdup (operation_id);
  temp.request_id = g_strdup (request->request_id);
  temp.subject_id = g_strdup (request->subject_id);
  temp.tenant_id = g_strdup (request->tenant_id);
  temp.destination = g_strdup (request->destination);
  temp.parent_identity = g_strdup (request->parent_identity);
  temp.old_credential_id = g_strdup (request->old_credential_id);
  temp.successor_generation = request->expected_generation;
  temp.expires_at_us = request->expires_at_us;
  temp.created_at_us = now_us;
  temp.updated_at_us = now_us;
  if (temp.operation_id == NULL || temp.request_id == NULL
      || (request->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE
          && temp.subject_id == NULL)
      || temp.destination == NULL
      || temp.parent_identity == NULL
      || (request->tenant_id != NULL && temp.tenant_id == NULL)
      || (request->old_credential_id != NULL && temp.old_credential_id == NULL)) {
    wyl_service_credential_operation_record_clear (&temp);
    return WYRELOG_E_NOMEM;
  }
  if (!wyl_service_credential_operation_record_is_valid (&temp)) {
    wyl_service_credential_operation_record_clear (&temp);
    return WYRELOG_E_INVALID;
  }
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = temp;
  return WYRELOG_E_OK;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-journal-private.h"

#include "auth/service-credential-private.h"
#include <string.h>

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
  temp.actor_subject_id = g_strdup (request->actor_subject_id);
  temp.old_credential_id = g_strdup (request->old_credential_id);
  temp.expected_generation = request->expected_generation;
  temp.expires_at_us = request->expires_at_us;
  temp.created_at_us = now_us;
  temp.updated_at_us = now_us;
  if (temp.operation_id == NULL || temp.request_id == NULL
      || (request->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE
          && temp.subject_id == NULL)
      || temp.destination == NULL
      || temp.parent_identity == NULL
      || temp.actor_subject_id == NULL
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

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_server_committed
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * successor_credential_id, guint64 successor_generation,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc;

  if (existing == NULL || out_record == NULL || now_us <= 0
      || !wyl_service_credential_operation_record_is_valid (existing)
      || !wyl_service_credential_id_is_canonical (successor_credential_id,
          successor_credential_id ==
          NULL ? 0 : strlen (successor_credential_id))
      || successor_generation == 0)
    return WYRELOG_E_INVALID;
  if (now_us < existing->updated_at_us)
    return WYRELOG_E_INVALID;

  if (existing->state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED) {
    if (g_strcmp0 (existing->successor_credential_id, successor_credential_id)
        != 0 || existing->successor_generation != successor_generation)
      return WYRELOG_E_POLICY;
  } else if (existing->state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
    return WYRELOG_E_POLICY;

  /* The codec makes a deep copy while retaining the complete immutable
   * request intent.  It also keeps this transition independent of storage. */
  rc = wyl_service_credential_operation_record_encode (existing, &encoded);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_service_credential_operation_record_decode (encoded, &next);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (existing->state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED) {
    next.state = WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED;
    g_clear_pointer (&next.successor_credential_id, g_free);
    next.successor_credential_id = g_strdup (successor_credential_id);
    if (next.successor_credential_id == NULL) {
      rc = WYRELOG_E_NOMEM;
      goto out;
    }
    next.successor_generation = successor_generation;
    next.updated_at_us = now_us;
  }
  if (!wyl_service_credential_operation_record_is_valid (&next)) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = next;
  next = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  rc = WYRELOG_E_OK;
out:
  wyl_service_credential_operation_record_clear (&next);
  return rc;
}

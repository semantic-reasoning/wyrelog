/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "auth/service-credential-operation-coordinator-fence-private.h"

#include "auth/service-credential-private.h"
#include <string.h>

static gboolean
text_is_absent (const gchar *value)
{
  return value == NULL || value[0] == '\0';
}

/* Journal-codec validity deliberately permits lifecycle-independent optional
 * fields.  The coordinator must tighten that to the immutable v1 fence
 * target before it can act on a precheck answer. */
static gboolean
    record_has_canonical_fence_target
    (const WylServiceCredentialOperationRecord * record)
{
  if (!wyl_service_credential_operation_record_is_valid (record)
      || !g_str_equal (record->operation_id, record->request_id))
    return FALSE;
  if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
      && !text_is_absent (record->successor_credential_id))
    return FALSE;
  if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
      && (!wyl_service_credential_id_is_canonical
          (record->successor_credential_id,
              record->successor_credential_id == NULL ? 0 :
              strlen (record->successor_credential_id))
          || record->successor_generation == 0))
    return FALSE;
  if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE)
    return text_is_absent (record->old_credential_id)
        && record->expected_generation == 0;
  return record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE
      && text_is_absent (record->tenant_id)
      && record->expected_generation > 0;
}

static gboolean
fence_is_empty (const WylServiceCredentialFenceResult *fence)
{
  return fence->state == 0 && text_is_absent (fence->successor_credential_id)
      && fence->successor_generation == 0;
}

static gboolean
fence_has_canonical_successor (const WylServiceCredentialFenceResult *fence)
{
  gsize successor_len = strnlen (fence->successor_credential_id,
      sizeof fence->successor_credential_id);
  return successor_len < sizeof fence->successor_credential_id
      && fence->successor_generation > 0
      && fence->successor_generation <= G_MAXINT64
      && wyl_service_credential_id_is_canonical
      (fence->successor_credential_id, successor_len);
}

static gboolean
    fence_successor_is_valid_for_record
    (const WylServiceCredentialOperationRecord * record,
    const WylServiceCredentialFenceResult * fence)
{
  return fence_has_canonical_successor (fence)
      && record->state >= WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_classify_fence
    (const WylServiceCredentialOperationRecord * record,
    wyrelog_error_t precheck_rc,
    const WylServiceCredentialFenceResult * fence,
    WylServiceCredentialOperationFenceClassification * out_classification)
{
  WylServiceCredentialOperationFenceClassification classification;

  if (record == NULL || fence == NULL || out_classification == NULL)
    return WYRELOG_E_INVALID;
  if (!record_has_canonical_fence_target (record))
    return WYRELOG_E_POLICY;
  if (precheck_rc != WYRELOG_E_OK && precheck_rc != WYRELOG_E_NOT_FOUND)
    return precheck_rc;

  if (precheck_rc == WYRELOG_E_NOT_FOUND) {
    if (!fence_is_empty (fence)
        || record->state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
      return WYRELOG_E_POLICY;
    classification = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  } else {
    switch (fence->state) {
      case WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED:
        if (!fence_successor_is_valid_for_record (record, fence))
          return WYRELOG_E_POLICY;
        if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
          classification =
              WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_COMMIT_REQUIRED;
        else if (record->state ==
            WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
            && g_str_equal (record->successor_credential_id,
                fence->successor_credential_id)
            && record->successor_generation == fence->successor_generation)
          classification =
              WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_REPLAY_COMMITTED;
        else
          return WYRELOG_E_POLICY;
        break;
      case WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL:
        if (!text_is_absent (fence->successor_credential_id)
            || fence->successor_generation != 0
            || record->state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
          return WYRELOG_E_POLICY;
        classification =
            WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_TERMINAL_NO_COMMIT;
        break;
      case WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT:
        if (!text_is_absent (fence->successor_credential_id)
            || fence->successor_generation != 0
            || record->state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
          return WYRELOG_E_POLICY;
        classification = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_CONFLICT;
        break;
      default:
        return WYRELOG_E_POLICY;
    }
  }

  *out_classification = classification;
  return WYRELOG_E_OK;
}

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
  temp.escrow_id = g_strdup (request->escrow_id);
  memcpy (temp.escrow_binding_digest, request->escrow_binding_digest,
      sizeof temp.escrow_binding_digest);
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
      || temp.escrow_id == NULL
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
    wyl_service_credential_operation_coordinator_build_server_committed_bound
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * successor_credential_id, guint64 successor_generation,
    const guint8 * binding_digest, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record)
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
      || successor_generation == 0 || binding_digest == NULL)
    return WYRELOG_E_INVALID;
  if (now_us < existing->updated_at_us)
    return WYRELOG_E_INVALID;

  if (existing->state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED) {
    if (g_strcmp0 (existing->successor_credential_id, successor_credential_id)
        != 0 || existing->successor_generation != successor_generation
        || memcmp (existing->escrow_binding_digest, binding_digest,
            sizeof existing->escrow_binding_digest) != 0)
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
    memcpy (next.escrow_binding_digest, binding_digest,
        sizeof next.escrow_binding_digest);
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

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_server_committed
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * successor_credential_id, guint64 successor_generation,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record)
{
  return existing == NULL ? WYRELOG_E_INVALID :
      wyl_service_credential_operation_coordinator_build_server_committed_bound
      (existing, successor_credential_id, successor_generation,
      existing->escrow_binding_digest, now_us, out_record);
}

static wyrelog_error_t
clone_for_transition (const WylServiceCredentialOperationRecord *existing,
    gint64 now_us, WylServiceCredentialOperationRecord *out)
{
  g_autoptr (GBytes) encoded = NULL;
  if (existing == NULL || out == NULL || now_us < existing->updated_at_us
      || !wyl_service_credential_operation_record_is_valid (existing))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_service_credential_operation_record_encode
      (existing, &encoded);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_service_credential_operation_record_decode (encoded, out);
  if (rc == WYRELOG_E_OK)
    out->updated_at_us = now_us;
  return rc;
}

static wyrelog_error_t
finish_transition (WylServiceCredentialOperationRecord *next,
    WylServiceCredentialOperationRecord *out)
{
  if (!wyl_service_credential_operation_record_is_valid (next))
    return WYRELOG_E_POLICY;
  wyl_service_credential_operation_record_clear (out);
  *out = *next;
  *next = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_publication_prepared
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * reservation_id, const gchar * stage_basename,
    const gchar * stage_identity, const gchar * publication_receipt_id,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyrelog_error_t rc = clone_for_transition (existing, now_us, &next);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (existing->state != WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  next.state = WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED;
  next.publication_receipt_version = 1;
  g_clear_pointer (&next.reservation_id, g_free);
  g_clear_pointer (&next.stage_basename, g_free);
  g_clear_pointer (&next.stage_identity, g_free);
  g_clear_pointer (&next.publication_receipt_id, g_free);
  next.reservation_id = g_strdup (reservation_id);
  next.stage_basename = g_strdup (stage_basename);
  next.stage_identity = g_strdup (stage_identity);
  next.publication_receipt_id = g_strdup (publication_receipt_id);
  if (next.reservation_id == NULL || next.stage_basename == NULL
      || next.stage_identity == NULL || next.publication_receipt_id == NULL)
    rc = WYRELOG_E_NOMEM;
  else
    rc = finish_transition (&next, out_record);
out:
  wyl_service_credential_operation_record_clear (&next);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_file_published
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * reservation_id, const gchar * stage_basename,
    const gchar * stage_identity, const gchar * publication_receipt_id,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyrelog_error_t rc = clone_for_transition (existing, now_us, &next);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (existing->state != WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
      || g_strcmp0 (existing->reservation_id, reservation_id) != 0
      || g_strcmp0 (existing->stage_basename, stage_basename) != 0
      || g_strcmp0 (existing->stage_identity, stage_identity) != 0
      || g_strcmp0 (existing->publication_receipt_id,
          publication_receipt_id) != 0) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  next.state = WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED;
  rc = finish_transition (&next, out_record);
out:
  wyl_service_credential_operation_record_clear (&next);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_cleanup_required
    (const WylServiceCredentialOperationRecord * existing, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyrelog_error_t rc = clone_for_transition (existing, now_us, &next);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (existing->state != WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  next.state = WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED;
  rc = finish_transition (&next, out_record);
out:
  wyl_service_credential_operation_record_clear (&next);
  return rc;
}

static wyrelog_error_t
build_reason_transition (const WylServiceCredentialOperationRecord *existing,
    WylServiceCredentialOperationState state, const gchar *reason,
    gint64 now_us, WylServiceCredentialOperationRecord *out_record)
{
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyrelog_error_t rc = clone_for_transition (existing, now_us, &next);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (reason == NULL || reason[0] == '\0') {
    rc = WYRELOG_E_INVALID;
    goto out;
  }
  next.state = state;
  next.terminal_reason = g_strdup (reason);
  if (next.terminal_reason == NULL)
    rc = WYRELOG_E_NOMEM;
  else
    rc = finish_transition (&next, out_record);
out:
  wyl_service_credential_operation_record_clear (&next);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_operator_action_required
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * reason, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record)
{
  if (existing == NULL || (existing->state
          != WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
          && existing->state !=
          WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
          && existing->state != WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
          && existing->state !=
          WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED))
    return WYRELOG_E_POLICY;
  return build_reason_transition (existing,
      WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED, reason,
      now_us, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_terminal
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * reason, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record)
{
  if (existing == NULL || (existing->state
          != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
          && existing->state != WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
          && existing->state !=
          WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED))
    return WYRELOG_E_POLICY;
  return build_reason_transition (existing,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL, reason, now_us, out_record);
}

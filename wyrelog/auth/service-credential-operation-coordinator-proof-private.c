/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-proof-private.h"

#include <sodium.h>
#include <string.h>

static void
put_u32be (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static wyrelog_error_t
target_digest_update_text (crypto_generichash_state *state, const gchar *value)
{
  guint8 encoded_len[4];
  gsize len;

  if (value == NULL)
    return WYRELOG_E_POLICY;
  len = strlen (value);
  if (len > G_MAXUINT32)
    return WYRELOG_E_POLICY;
  put_u32be (encoded_len, (guint32) len);
  return crypto_generichash_update (state, encoded_len, sizeof encoded_len) == 0
      && crypto_generichash_update (state, (const guint8 *) value, len) == 0 ?
      WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

wyrelog_error_t
    wyl_service_credential_operation_handoff_target_digest
    (const WylServiceCredentialOperationRecord * record,
    guint8
    out_digest[WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES])
{
  static const gchar domain[] =
      "wyrelog.service-credential-owner-publication-target.v1";
  crypto_generichash_state state;
  wyrelog_error_t rc;

  if (record == NULL || out_digest == NULL)
    return WYRELOG_E_INVALID;
  if (crypto_generichash_init (&state, NULL, 0,
          WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES) != 0)
    return WYRELOG_E_CRYPTO;
  rc = target_digest_update_text (&state, domain);
  if (rc == WYRELOG_E_OK)
    rc = target_digest_update_text (&state, record->destination);
  if (rc == WYRELOG_E_OK)
    rc = target_digest_update_text (&state, record->parent_identity);
  if (rc == WYRELOG_E_OK
      && crypto_generichash_final (&state, out_digest,
          WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES) != 0)
    rc = WYRELOG_E_CRYPTO;
  sodium_memzero (&state, sizeof state);
  if (rc != WYRELOG_E_OK)
    sodium_memzero (out_digest,
        WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_maintenance_proof_from_record
    (const WylServiceCredentialOperationRecord * record, wyl_id_t * escrow_id,
    WylPolicyServiceHandoffMaintenanceProof * out)
{
  if (record == NULL || escrow_id == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_id_parse (record->escrow_id, escrow_id) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  memset (out, 0, sizeof *out);
  out->tuple = (WylPolicyServiceHandoffExactTuple) {
  .original_request_id = record->request_id,.escrow_id =
        escrow_id,.successor_credential_id =
        record->successor_credential_id != NULL
        && record->successor_credential_id[0] !=
        '\0' ? record->
        successor_credential_id : NULL,.successor_issuance_generation =
        record->successor_generation,.original_actor_subject_id =
        record->actor_subject_id,};
  memcpy (out->tuple.binding_digest, record->escrow_binding_digest,
      sizeof out->tuple.binding_digest);
  if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE) {
    out->operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
    out->subject_id = record->subject_id;
    out->tenant_id = record->tenant_id;
  } else if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE) {
    out->operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
    out->old_credential_id = record->old_credential_id;
  } else {
    return WYRELOG_E_POLICY;
  }
  out->deadline_at_us = record->expires_at_us;
  return wyl_service_credential_operation_handoff_target_digest (record,
      out->target_digest);
}

void wyl_service_credential_operation_remediation_proof_from_result
    (const wyl_service_credential_handoff_remediation_result_t * result,
    WylServiceCredentialOperationRemediationProof * proof)
{
  memset (proof, 0, sizeof *proof);
  proof->remediation_request_id = result->remediation_request_id;
  proof->decision_request_id = result->decision_request_id;
  proof->current_actor_subject_id = result->current_actor_subject_id;
  proof->action = result->action;
  proof->confirmation_version = result->confirmation_version;
  proof->confirmed = result->confirmed;
  proof->created_at_us = result->created_at_us;
  memcpy (proof->request_fingerprint, result->request_fingerprint,
      sizeof proof->request_fingerprint);
  proof->source_kind = result->source_kind;
  memcpy (proof->source_snapshot_digest, result->journal_snapshot_digest,
      sizeof proof->source_snapshot_digest);
  proof->observed_state = result->observed_state;
  proof->original_request_id = result->original_request_id;
  proof->original_actor_subject_id = result->original_actor_subject_id;
  proof->escrow_id = result->escrow_id;
  memcpy (proof->binding_digest, result->binding_digest,
      sizeof proof->binding_digest);
  proof->successor_credential_id = result->successor_credential_id;
  proof->successor_issuance_generation = result->successor_issuance_generation;
  proof->source_disposition_id = result->source_disposition_id;
  proof->source_audit_id = result->source_audit_id;
  proof->source_reason = result->source_reason;
  proof->oar_source_state = result->oar_source_state;
  proof->oar_cause = result->oar_cause;
  proof->resume_target_state = result->resume_target_state;
  proof->outcome = result->outcome;
  proof->escrow_outcome = result->escrow_outcome;
  proof->credential_generation_after = result->credential_generation_after;
  proof->audit_id = result->audit_id;
  proof->authority_replayed = result->replayed;
  proof->revoked_now = result->revoked_now;
  proof->invalidation_generation = result->invalidation_generation;
  proof->revoke_event_id = result->revoke_event_id;
  proof->revoke_event_generation = result->revoke_event_generation;
  proof->revoke_event_request_id = result->revoke_event_request_id;
  proof->revoke_event_actor_subject_id = result->revoke_event_actor_subject_id;
  proof->revoke_event_created_at_us = result->revoke_event_created_at_us;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-maintenance-private.h"

#include "auth/service-auth-coordination-private.h"
#include "auth/service-credential-handoff-delivery-private.h"
#include "policy/store-handoff-maintenance-private.h"
#include "wyl-handle-private.h"

#include <sodium.h>
#include <string.h>

static wyrelog_error_t
authority_transaction_finish (wyl_policy_store_t *store,
    WylServiceAuthorityTransaction *transaction, wyrelog_error_t operation)
{
  wyrelog_error_t result = operation;
  wyrelog_error_t terminal = operation == WYRELOG_E_OK ?
      wyl_policy_store_service_authority_transaction_commit (transaction) :
      wyl_policy_store_service_authority_transaction_rollback (transaction);

  if (operation == WYRELOG_E_OK || terminal != WYRELOG_E_OK)
    result = terminal;
  if (wyl_policy_store_service_authority_transaction_is_poisoned (store)) {
    wyrelog_error_t abort_rc =
        wyl_policy_store_service_authority_transaction_abort (transaction);
    if (abort_rc != WYRELOG_E_OK)
      result = abort_rc;
  }
  wyl_policy_store_service_authority_transaction_free (transaction);
  return result;
}

static wyrelog_error_t
    maintenance_proof_from_record
    (const WylServiceCredentialOperationRecord * record, wyl_id_t * escrow_id,
    WylPolicyServiceHandoffMaintenanceProof * out)
{
  wyrelog_error_t rc;

  if (record == NULL || escrow_id == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  rc = wyl_id_parse (record->escrow_id, escrow_id);
  if (rc != WYRELOG_E_OK)
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

static wyrelog_error_t
    delivery_proof_from_record
    (const WylServiceCredentialOperationRecord * record,
    const WylPolicyServiceHandoffMaintenanceProof * maintenance,
    WylServiceCredentialHandoffDeliveryProof * out)
{
  WylServiceCredentialHandoffDeliverySource source;

  if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED)
    source = WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_FILE_PUBLISHED;
  else if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED)
    source = WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_CLEANUP_REQUIRED;
  else
    return WYRELOG_E_INVALID;
  *out = (WylServiceCredentialHandoffDeliveryProof) {
  .source = source,.tuple = maintenance->tuple,.actor_subject_id =
        record->actor_subject_id,.operation =
        record->kind ==
        WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE ? "issue" :
        "rotate",.deadline_at_us = record->expires_at_us,.receipt_version =
        record->publication_receipt_version,.destination =
        record->destination,.reservation_id =
        record->reservation_id,.parent_identity =
        record->parent_identity,.stage_basename =
        record->stage_basename,.stage_identity =
        record->stage_identity,.publication_receipt_id =
        record->publication_receipt_id,};
  memcpy (out->target_digest, maintenance->target_digest,
      sizeof out->target_digest);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
maintain_prepared_authority (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    WylPolicyServiceHandoffPreparedMaintenanceResult *out)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);

  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_authority_prepare_commit_evidence
        (transaction, store, &evidence);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_maintain_prepared_core (transaction, store,
        proof, out);
  if (rc == WYRELOG_E_INVALID)
    rc = WYRELOG_E_POLICY;
  if (transaction != NULL)
    rc = authority_transaction_finish (store, transaction, rc);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_prepared_maintenance_result_clear (out);
  return rc;
}

static wyrelog_error_t
maintain_committed_authority (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult *out)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);

  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_maintain_committed_core (transaction, store,
        proof, out);
  if (rc == WYRELOG_E_INVALID)
    rc = WYRELOG_E_POLICY;
  if (transaction != NULL)
    rc = authority_transaction_finish (store, transaction, rc);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_committed_maintenance_result_clear (out);
  return rc;
}

static wyrelog_error_t
lookup_delivery_authority (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const WylServiceCredentialHandoffDeliveryProof *proof,
    gboolean *out_found,
    WylPolicyServiceHandoffDispositionResult *out_disposition)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);

  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_handoff_lookup_delivery_core (transaction,
        store, proof, out_found, out_disposition);
  if (transaction != NULL)
    rc = authority_transaction_finish (store, transaction, rc);
  if (rc != WYRELOG_E_OK) {
    *out_found = FALSE;
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  }
  return rc;
}

static wyrelog_error_t
backfill_legacy_delivery_authority (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const WylServiceCredentialHandoffDeliveryProof *proof,
    WylPolicyServiceHandoffDispositionResult *out_disposition)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  WylServiceCredentialHandoffDeliveryPreflight *preflight = NULL;
  WylServiceCredentialHandoffDeliveryOutcome outcome = 0;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);

  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_handoff_prepare_delivery_core (transaction,
        store, proof, &outcome, &preflight, out_disposition);
  if (rc == WYRELOG_E_INVALID)
    rc = WYRELOG_E_POLICY;
  if (transaction != NULL)
    rc = authority_transaction_finish (store, transaction, rc);
  if (rc == WYRELOG_E_OK
      && outcome != WYL_SERVICE_HANDOFF_DELIVERY_LEGACY_BACKFILLED
      && outcome != WYL_SERVICE_HANDOFF_DELIVERY_REPLAYED)
    rc = WYRELOG_E_POLICY;
  wyl_service_credential_handoff_delivery_preflight_free (preflight);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  return rc;
}

static gint64
checkpoint_time (const WylServiceCredentialOperationRecord *record,
    gint64 authority_created_at_us)
{
  return MAX (record->updated_at_us, authority_created_at_us);
}

static void
return_record (WylServiceCredentialOperationRecord *source,
    WylServiceCredentialOperationMaintenanceOutcome outcome,
    WylServiceCredentialOperationMaintenanceOutcome *out_outcome,
    WylServiceCredentialOperationRecord *out_record)
{
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = *source;
  *source = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  *out_outcome = outcome;
}

static void
    remediation_proof_from_result
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

wyrelog_error_t
    wyl_service_credential_operation_coordinator_maintain_expired_locked
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, GCancellable * cancellable,
    WylServiceCredentialOperationMaintenanceOutcome * out_outcome,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylPolicyServiceHandoffMaintenanceProof proof = { 0 };
  WylPolicyServiceHandoffPreparedMaintenanceResult prepared = { 0 };
  WylPolicyServiceHandoffCommittedMaintenanceResult committed = { 0 };
  WylPolicyServiceHandoffDispositionResult delivery_disposition = { 0 };
  WylServiceCredentialHandoffDeliveryProof delivery_proof = { 0 };
  wyl_service_credential_handoff_remediation_result_t remediation = { 0 };
  WylServiceCredentialOperationRemediationProof remediation_proof = { 0 };
  WylServiceAuthWriteLease *lease = NULL;
  wyl_policy_store_t *store = NULL;
  wyl_id_t escrow_id;
  gboolean delivery_found = FALSE;
  gboolean replayed = FALSE;
  guint8 snapshot_digest[crypto_generichash_BYTES] = { 0 };
  wyrelog_error_t rc;

  if (handle == NULL || storage == NULL || anchor == NULL
      || out_outcome == NULL || out_record == NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id)
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;

  rc = wyl_service_credential_operation_coordinator_load_snapshot (storage,
      anchor, request_id, snapshot_digest, &record);
  if (rc != WYRELOG_E_OK)
    goto out;

  rc = wyl_service_credential_handoff_resolve_remediation_incident (handle,
      request_id, snapshot_digest, &remediation);
  if (rc == WYRELOG_E_NOT_FOUND
      && record.last_remediation_action !=
      WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_NONE)
    rc = wyl_service_credential_handoff_resolve_remediation_incident (handle,
        request_id, record.last_remediation_source_snapshot_digest,
        &remediation);
  if (rc == WYRELOG_E_NOT_FOUND) {
    if (record.last_remediation_action !=
        WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_NONE) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    rc = WYRELOG_E_OK;
  } else if (rc != WYRELOG_E_OK) {
    goto out;
  } else {
    remediation_proof_from_result (&remediation, &remediation_proof);
    if (remediation.action == WYL_SERVICE_HANDOFF_REMEDIATION_RESUME)
      rc = wyl_service_credential_operation_coordinator_checkpoint_operator_resume (storage, anchor, request_id, &remediation_proof, checkpoint_time (&record, remediation.created_at_us), &replayed, &next);
    else if (remediation.action ==
        WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE)
      rc = wyl_service_credential_operation_coordinator_checkpoint_operator_revoke_and_wipe (storage, anchor, request_id, &remediation_proof, checkpoint_time (&record, remediation.created_at_us), &replayed, &next);
    else
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      goto out;
    wyl_service_credential_operation_record_clear (&record);
    record = next;
    next = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    if (remediation.action == WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE) {
      return_record (&record,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED, out_outcome,
          out_record);
      rc = WYRELOG_E_OK;
      goto out;
    }
  }

  if (record.state == WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED) {
    return_record (&record,
        WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED, out_outcome,
        out_record);
    rc = WYRELOG_E_OK;
    goto out;
  }
  if (record.state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL) {
    WylServiceCredentialOperationTerminalKind terminal_kind = 0;
    if (!wyl_service_credential_operation_terminal_reason_parse
        (record.terminal_reason, &terminal_kind, NULL)) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    if (terminal_kind ==
        WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE
        && (record.version !=
            WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION
            || record.last_remediation_action !=
            WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_REVOKE_AND_WIPE)) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    if (terminal_kind !=
        WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_NOT_COMMITTED) {
      return_record (&record,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED, out_outcome,
          out_record);
      rc = WYRELOG_E_OK;
      goto out;
    }
  } else if (record.state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
      && record.state !=
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED
      && record.state !=
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }

  rc = maintenance_proof_from_record (&record, &escrow_id, &proof);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, cancellable,
      &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (lease, handle, &store);
  if (rc != WYRELOG_E_OK)
    goto out;

  if (record.state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
      || record.state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED) {
    rc = delivery_proof_from_record (&record, &proof, &delivery_proof);
    if (rc != WYRELOG_E_OK)
      goto out;
    rc = lookup_delivery_authority (handle, lease, store, &delivery_proof,
        &delivery_found, &delivery_disposition);
    if (rc == WYRELOG_E_INVALID)
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      goto out;
    if (delivery_found) {
      rc = wyl_service_credential_operation_coordinator_checkpoint_terminal_file_published (storage, anchor, request_id, checkpoint_time (&record, delivery_disposition.created_at_us), &replayed, &next);
      if (rc != WYRELOG_E_OK)
        goto out;
      return_record (&next,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED, out_outcome,
          out_record);
      rc = WYRELOG_E_OK;
      goto out;
    }
    wyl_policy_service_handoff_disposition_result_clear (&delivery_disposition);
  }

  if (record.state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
      || record.state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL) {
    rc = maintain_prepared_authority (handle, lease, store, &proof, &prepared);
    if (rc != WYRELOG_E_OK)
      goto out;

    if (record.state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL) {
      if (prepared.outcome !=
          WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED) {
        rc = WYRELOG_E_POLICY;
        goto out;
      }
      return_record (&record,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED, out_outcome,
          out_record);
      rc = WYRELOG_E_OK;
      goto out;
    }
    if (prepared.outcome == WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_DUE) {
      return_record (&record,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED, out_outcome,
          out_record);
      rc = WYRELOG_E_OK;
      goto out;
    }
    if (prepared.outcome ==
        WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED) {
      rc = wyl_service_credential_operation_coordinator_checkpoint_terminal_not_committed (storage, anchor, request_id, checkpoint_time (&record, prepared.created_at_us), &replayed, &next);
      if (rc != WYRELOG_E_OK)
        goto out;
      return_record (&next,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_TERMINAL_NOT_COMMITTED,
          out_outcome, out_record);
      rc = WYRELOG_E_OK;
      goto out;
    }
    if (prepared.outcome != WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_COMMITTED) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    rc = wyl_service_credential_operation_coordinator_checkpoint_server_committed_bound (storage, anchor, request_id, prepared.successor_credential_id, prepared.successor_generation, prepared.binding_digest, checkpoint_time (&record, prepared.created_at_us), &replayed, &next);
    if (rc != WYRELOG_E_OK)
      goto out;
    wyl_service_credential_operation_record_clear (&record);
    record = next;
    next = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    wyl_policy_service_handoff_prepared_maintenance_result_clear (&prepared);
    rc = maintenance_proof_from_record (&record, &escrow_id, &proof);
    if (rc != WYRELOG_E_OK)
      goto out;
  }

  rc = maintain_committed_authority (handle, lease, store, &proof, &committed);
  if (rc != WYRELOG_E_OK)
    goto out;
  switch (committed.outcome) {
    case WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ACTIVE:
      return_record (&record,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED, out_outcome,
          out_record);
      break;
    case WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_MISSING:
    case WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_FOREIGN:
      if (committed.outcome ==
          WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_MISSING
          && record.state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED) {
        rc = backfill_legacy_delivery_authority (handle, lease, store,
            &delivery_proof, &delivery_disposition);
        if (rc == WYRELOG_E_INVALID)
          rc = WYRELOG_E_POLICY;
        if (rc != WYRELOG_E_OK)
          goto out;
        rc = wyl_service_credential_operation_coordinator_checkpoint_terminal_file_published (storage, anchor, request_id, checkpoint_time (&record, delivery_disposition.created_at_us), &replayed, &next);
        if (rc != WYRELOG_E_OK)
          goto out;
        return_record (&next,
            WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED,
            out_outcome, out_record);
        break;
      }
      rc = wyl_service_credential_operation_coordinator_checkpoint_escrow_oar
          (storage, anchor, request_id,
          committed.outcome ==
          WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_MISSING ?
          WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_MISSING :
          WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_FOREIGN,
          checkpoint_time (&record, committed.created_at_us), &replayed, &next);
      if (rc != WYRELOG_E_OK)
        goto out;
      return_record (&next,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_OPERATOR_ACTION_REQUIRED,
          out_outcome, out_record);
      break;
    case WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_EXPIRED:
    case WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_REVOKED:
      rc = wyl_service_credential_operation_coordinator_checkpoint_successor_inactive_oar (storage, anchor, request_id, committed.outcome == WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_EXPIRED ? WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_EXPIRED : WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_REVOKED, checkpoint_time (&record, committed.created_at_us), &replayed, &next);
      if (rc != WYRELOG_E_OK)
        goto out;
      return_record (&next,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_OPERATOR_ACTION_REQUIRED,
          out_outcome, out_record);
      break;
    case WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED:
    case WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED:
      /* Attention is deliberately not a journal transition. */
      return_record (&record,
          WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_ATTENTION_REQUIRED,
          out_outcome, out_record);
      break;
    default:
      rc = WYRELOG_E_POLICY;
      goto out;
  }
  rc = WYRELOG_E_OK;

out:
  sodium_memzero (snapshot_digest, sizeof snapshot_digest);
  sodium_memzero (&remediation_proof, sizeof remediation_proof);
  wyl_service_credential_handoff_remediation_result_clear (&remediation);
  sodium_memzero (&proof, sizeof proof);
  sodium_memzero (&delivery_proof, sizeof delivery_proof);
  wyl_policy_service_handoff_disposition_result_clear (&delivery_disposition);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&committed);
  wyl_policy_service_handoff_prepared_maintenance_result_clear (&prepared);
  wyl_service_credential_operation_record_clear (&next);
  wyl_service_credential_operation_record_clear (&record);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (rc == WYRELOG_E_OK && release_rc != WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_maintain_expired
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, GCancellable * cancellable,
    WylServiceCredentialOperationMaintenanceOutcome * out_outcome,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  wyrelog_error_t rc;

  if (handle == NULL || storage == NULL || anchor == NULL
      || out_outcome == NULL || out_record == NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id)
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  rc = wyl_service_credential_operation_coordinator_lock_acquire (storage,
      anchor, request_id, &lifecycle_lock);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_operation_coordinator_maintain_expired_locked
        (handle, storage, anchor, request_id, cancellable, out_outcome,
        out_record);
  wyl_service_credential_operation_coordinator_lock_release (storage, anchor,
      &lifecycle_lock);
  return rc;
}

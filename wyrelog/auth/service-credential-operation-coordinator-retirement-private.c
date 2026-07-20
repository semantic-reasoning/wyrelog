/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-retirement-private.h"

#include "auth/service-auth-coordination-private.h"
#include "auth/service-credential-handoff-delivery-private.h"
#include "auth/service-credential-operation-coordinator-proof-private.h"
#include "policy/store-private.h"
#include "wyl-handle-private.h"

#include <sodium.h>
#include <string.h>

static void (*before_delete_hook_for_test) (gpointer data);
static gpointer before_delete_hook_data_for_test;

void wyl_service_credential_operation_retirement_set_before_delete_hook_for_test
    (void (*hook) (gpointer data), gpointer data)
{
  before_delete_hook_for_test = hook;
  before_delete_hook_data_for_test = data;
}

static gboolean
retirement_cancelled (GCancellable *cancellable)
{
  return cancellable != NULL && g_cancellable_is_cancelled (cancellable);
}

static wyrelog_error_t
authority_transaction_finish (wyl_policy_store_t *store,
    WylServiceAuthorityTransaction *transaction, wyrelog_error_t operation,
    gboolean commit)
{
  wyrelog_error_t result = operation;
  wyrelog_error_t terminal = commit && operation == WYRELOG_E_OK ?
      wyl_policy_store_service_authority_transaction_commit (transaction) :
      wyl_policy_store_service_authority_transaction_rollback (transaction);

  if (terminal != WYRELOG_E_OK)
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
retirement_lookup_authority (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const gchar *request_id, WylPolicyServiceHandoffRetirementResult *out)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);

  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_retirement_lookup_core (transaction, store,
        request_id, out);
  if (rc == WYRELOG_E_INVALID)
    rc = WYRELOG_E_POLICY;
  if (transaction != NULL)
    rc = authority_transaction_finish (store, transaction, rc,
        rc == WYRELOG_E_OK);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_retirement_result_clear (out);
  return rc;
}

static wyrelog_error_t
retirement_record_authority (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRetirementInput *input,
    WylPolicyServiceHandoffRetirementResult *out)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);

  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_retirement_record_core (transaction, store,
        input, out);
  if (rc == WYRELOG_E_INVALID)
    rc = WYRELOG_E_POLICY;
  if (transaction != NULL)
    rc = authority_transaction_finish (store, transaction, rc,
        rc == WYRELOG_E_OK);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_retirement_result_clear (out);
  return rc;
}

static wyrelog_error_t
delete_expectation_from_receipt (const gchar *request_id,
    const WylPolicyServiceHandoffRetirementResult *receipt,
    WylServiceCredentialOperationExactDeleteExpectation *out)
{
  if (receipt == NULL || out == NULL
      || g_strcmp0 (request_id, receipt->original_request_id) != 0
      || sodium_is_zero (receipt->raw_journal_snapshot_digest,
          sizeof receipt->raw_journal_snapshot_digest))
    return WYRELOG_E_POLICY;
  *out = (WylServiceCredentialOperationExactDeleteExpectation) {
  .request_id = request_id,.expected_journal_version =
        WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,};
  memcpy (out->raw_snapshot_digest, receipt->raw_journal_snapshot_digest,
      sizeof out->raw_snapshot_digest);
  if (receipt->terminal_kind == WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED) {
    if (receipt->revoke_remediation_request_id != NULL)
      return WYRELOG_E_POLICY;
    out->terminal_kind =
        WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED;
    out->remediation_request_id = receipt->resume_remediation_request_id;
    return WYRELOG_E_OK;
  }
  if (receipt->terminal_kind !=
      WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE
      || receipt->revoke_remediation_request_id == NULL
      || receipt->resume_remediation_request_id != NULL)
    return WYRELOG_E_POLICY;
  out->terminal_kind =
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE;
  out->remediation_request_id = receipt->revoke_remediation_request_id;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
retirement_input_from_snapshot (const gchar *request_id,
    const WylServiceCredentialOperationRecord *record,
    const guint8 raw_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES],
    wyl_id_t *escrow_id, WylPolicyServiceHandoffRetirementInput *out)
{
  WylPolicyServiceHandoffMaintenanceProof maintenance = { 0 };
  WylServiceCredentialOperationTerminalKind terminal_kind = 0;
  g_autofree gchar *terminal_remediation = NULL;

  if (record == NULL || raw_digest == NULL || escrow_id == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  if (record->version != WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION
      || record->state != WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL
      || !wyl_service_credential_operation_record_is_valid (record)
      || g_strcmp0 (record->request_id, request_id) != 0
      || g_strcmp0 (record->operation_id, request_id) != 0
      || record->updated_at_us <= 0 || sodium_is_zero (raw_digest,
          WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES)
      || !wyl_service_credential_operation_terminal_reason_parse
      (record->terminal_reason, &terminal_kind, &terminal_remediation))
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc =
      wyl_service_credential_operation_maintenance_proof_from_record (record,
      escrow_id, &maintenance);
  if (rc != WYRELOG_E_OK)
    return rc == WYRELOG_E_INVALID ? WYRELOG_E_POLICY : rc;
  memset (out, 0, sizeof *out);
  out->journal_version = record->version;
  out->journal_state = WYL_POLICY_HANDOFF_REMEDIATION_STATE_TERMINAL;
  out->tuple = maintenance.tuple;
  out->journal_updated_at_us = record->updated_at_us;
  memcpy (out->raw_journal_snapshot_digest, raw_digest,
      sizeof out->raw_journal_snapshot_digest);

  if (terminal_kind == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED) {
    if (terminal_remediation != NULL
        || (record->last_remediation_action !=
            WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_NONE
            && record->last_remediation_action !=
            WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_RESUME))
      return WYRELOG_E_POLICY;
    out->terminal_kind = WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED;
    out->delivery_actor_subject_id = record->actor_subject_id;
    rc = wyl_service_credential_handoff_delivery_retirement_proof_digest
        (record, &out->tuple, maintenance.target_digest,
        out->delivery_proof_digest);
    if (rc != WYRELOG_E_OK)
      return rc == WYRELOG_E_INVALID ? WYRELOG_E_POLICY : rc;
    if (record->last_remediation_action ==
        WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_RESUME)
      out->remediation_request_id = record->last_remediation_request_id;
  } else if (terminal_kind ==
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE) {
    if (record->last_remediation_action !=
        WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_REVOKE_AND_WIPE
        || terminal_remediation == NULL
        || g_strcmp0 (terminal_remediation,
            record->last_remediation_request_id) != 0
        || record->last_remediation_applied_target_state !=
        WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL)
      return WYRELOG_E_POLICY;
    out->terminal_kind = WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE;
    out->remediation_request_id = record->last_remediation_request_id;
  } else {
    return WYRELOG_E_POLICY;
  }
  if (out->remediation_request_id != NULL) {
    memcpy (out->remediation_source_snapshot_digest,
        record->last_remediation_source_snapshot_digest,
        sizeof out->remediation_source_snapshot_digest);
    memcpy (out->remediation_request_fingerprint,
        record->last_remediation_request_fingerprint,
        sizeof out->remediation_request_fingerprint);
  }
  return WYRELOG_E_OK;
}

void wyl_service_credential_operation_retirement_result_clear
    (WylServiceCredentialOperationRetirementResult * result)
{
  if (result != NULL)
    sodium_memzero (result, sizeof *result);
}

void wyl_service_credential_operation_guarded_begin_result_clear
    (WylServiceCredentialOperationGuardedBeginResult * result)
{
  if (result == NULL)
    return;
  wyl_service_credential_operation_record_clear (&result->record);
  sodium_memzero (result, sizeof *result);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_purge_retired
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, GCancellable * cancellable,
    WylServiceCredentialOperationRetirementResult * out_result)
{
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylPolicyServiceHandoffRetirementInput input = { 0 };
  WylPolicyServiceHandoffRetirementResult receipt = { 0 };
  WylPolicyServiceHandoffRetirementResult replay = { 0 };
  WylServiceCredentialOperationExactDeleteExpectation expectation =
      WYL_SERVICE_CREDENTIAL_OPERATION_EXACT_DELETE_EXPECTATION_INIT;
  WylServiceAuthWriteLease *lease = NULL;
  wyl_policy_store_t *store = NULL;
  guint8 raw_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES] = { 0 };
  wyl_id_t escrow_id;
  gboolean receipt_replayed = FALSE;
  gboolean locked = FALSE;
  wyrelog_error_t rc;

  if (out_result != NULL)
    wyl_service_credential_operation_retirement_result_clear (out_result);
  if (handle == NULL || storage == NULL || anchor == NULL || out_result == NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id)
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  if (retirement_cancelled (cancellable))
    return WYRELOG_E_BUSY;
  rc = wyl_service_credential_operation_coordinator_lock_acquire (storage,
      anchor, request_id, &lifecycle_lock);
  if (rc != WYRELOG_E_OK)
    goto out;
  locked = TRUE;
  if (retirement_cancelled (cancellable)) {
    rc = WYRELOG_E_BUSY;
    goto out;
  }
  rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, cancellable,
      &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (lease, handle, &store);
  if (rc == WYRELOG_E_OK && store != wyl_handle_get_policy_store (handle))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    goto out;

  rc = retirement_lookup_authority (handle, lease, store, request_id, &receipt);
  if (rc == WYRELOG_E_OK) {
    receipt_replayed = TRUE;
  } else if (rc == WYRELOG_E_NOT_FOUND) {
    rc = wyl_service_credential_operation_coordinator_load_snapshot (storage,
        anchor, request_id, raw_digest, &record);
    if (rc == WYRELOG_E_INVALID)
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      goto out;
    rc = retirement_input_from_snapshot (request_id, &record, raw_digest,
        &escrow_id, &input);
    if (rc == WYRELOG_E_INVALID)
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      goto out;
    if (retirement_cancelled (cancellable)) {
      rc = WYRELOG_E_BUSY;
      goto out;
    }
    rc = retirement_record_authority (handle, lease, store, &input, &receipt);
    if (rc != WYRELOG_E_OK)
      goto out;
    rc = retirement_record_authority (handle, lease, store, &input, &replay);
    if (rc != WYRELOG_E_OK)
      goto out;
    if (!replay.replayed) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    wyl_policy_service_handoff_retirement_result_clear (&receipt);
    receipt = replay;
    memset (&replay, 0, sizeof replay);
  } else {
    goto out;
  }
  rc = delete_expectation_from_receipt (request_id, &receipt, &expectation);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (before_delete_hook_for_test != NULL) {
    void (*hook) (gpointer data) = before_delete_hook_for_test;
    gpointer hook_data = before_delete_hook_data_for_test;
    before_delete_hook_for_test = NULL;
    before_delete_hook_data_for_test = NULL;
    hook (hook_data);
  }
  if (retirement_cancelled (cancellable)) {
    rc = WYRELOG_E_BUSY;
    goto out;
  }
  rc = wyl_service_credential_operation_coordinator_delete_exact_terminal_snapshot (storage, anchor, &lifecycle_lock, &expectation);
  gboolean deleted = rc == WYRELOG_E_OK;
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_OK;
  if (rc == WYRELOG_E_OK) {
    *out_result = (WylServiceCredentialOperationRetirementResult) {
    .receipt_replayed = receipt_replayed,.snapshot_deleted = deleted,.kind =
          receipt.terminal_kind,.retired_at_us = receipt.retired_at_us,};
  }
out:
  sodium_memzero (raw_digest, sizeof raw_digest);
  wyl_service_credential_operation_record_clear (&record);
  wyl_policy_service_handoff_retirement_result_clear (&replay);
  wyl_policy_service_handoff_retirement_result_clear (&receipt);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (rc == WYRELOG_E_OK && release_rc != WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  if (locked)
    wyl_service_credential_operation_coordinator_lock_release (storage,
        anchor, &lifecycle_lock);
  if (rc != WYRELOG_E_OK)
    wyl_service_credential_operation_retirement_result_clear (out_result);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    GCancellable * cancellable,
    WylServiceCredentialOperationGuardedBeginResult * out_result)
{
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylPolicyServiceHandoffRetirementResult receipt = { 0 };
  WylServiceAuthWriteLease *lease = NULL;
  wyl_policy_store_t *store = NULL;
  gboolean replayed = FALSE;
  gboolean locked = FALSE;
  wyrelog_error_t rc;

  if (out_result != NULL)
    wyl_service_credential_operation_guarded_begin_result_clear (out_result);
  if (handle == NULL || storage == NULL || anchor == NULL || request == NULL
      || out_result == NULL
      || !wyl_service_credential_operation_coordinator_request_is_valid
      (request)
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  if (retirement_cancelled (cancellable))
    return WYRELOG_E_BUSY;
  rc = wyl_service_credential_operation_coordinator_lock_acquire (storage,
      anchor, request->request_id, &lifecycle_lock);
  if (rc != WYRELOG_E_OK)
    goto out;
  locked = TRUE;
  if (retirement_cancelled (cancellable)) {
    rc = WYRELOG_E_BUSY;
    goto out;
  }
  rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, cancellable,
      &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (lease, handle, &store);
  if (rc == WYRELOG_E_OK && store != wyl_handle_get_policy_store (handle))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = retirement_lookup_authority (handle, lease, store,
      request->request_id, &receipt);
  if (rc == WYRELOG_E_OK) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  if (rc != WYRELOG_E_NOT_FOUND)
    goto out;
  if (retirement_cancelled (cancellable)) {
    rc = WYRELOG_E_BUSY;
    goto out;
  }
  gint64 now_us = g_get_real_time ();
  if (now_us <= 0) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  rc = wyl_service_credential_operation_coordinator_begin_or_replay_locked
      (storage, anchor, &lifecycle_lock, request, now_us, &replayed,
      &out_result->record);
  if (rc == WYRELOG_E_OK)
    out_result->replayed = replayed;
out:
  wyl_policy_service_handoff_retirement_result_clear (&receipt);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (rc == WYRELOG_E_OK && release_rc != WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  if (locked)
    wyl_service_credential_operation_coordinator_lock_release (storage,
        anchor, &lifecycle_lock);
  if (rc != WYRELOG_E_OK)
    wyl_service_credential_operation_guarded_begin_result_clear (out_result);
  return rc;
}

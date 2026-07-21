/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-execute-private.h"
#include "../wyctl/wyctl-publication-private.h"
#include "auth/service-auth-coordination-private.h"
#include "auth/service-credential-handoff-delivery-private.h"
#include "auth/service-credential-operation-coordinator-auth-private.h"
#include "auth/service-credential-operation-coordinator-maintenance-private.h"
#include "auth/service-credential-operation-coordinator-retirement-private.h"
#include "auth/service-credential-operation-destination-private.h"
#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "policy/store-private.h"
#include "wyrelog/decide.h"
#include "wyl-handle-private.h"
#include "wyl-id-private.h"
#include "wyl-permission-scope-private.h"
#include "wyl-session-layout-private.h"

#include <sodium.h>
#include <string.h>

#define HANDOFF_MANAGE_ACTION "wr.service_credential.manage"

typedef struct
{
  WylHandle *handle;
  const WylServiceCredentialOperationRecord *record;
  const WylServiceCredentialOperationHandoffExecuteRuntime *runtime;
  const gchar *session_resource_id;
  const gchar *session_tenant;
} HandoffAuthorization;

static gboolean
handoff_session_is_active_human (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
      && session->state == WYL_SESSION_STATE_ACTIVE
      && session->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN;
}

static void
handoff_sensitive_clear (WyctlSensitiveText *text)
{
  if (text->text != NULL)
    sodium_memzero (text->text, text->len);
  g_clear_pointer (&text->text, g_free);
  text->len = 0;
}

static void
handoff_plan_clear (WyctlPublicationPlan *plan)
{
  g_clear_pointer (&plan->destination, g_free);
  g_clear_pointer (&plan->reservation_id, g_free);
  g_clear_pointer (&plan->parent_identity, g_free);
  g_clear_pointer (&plan->stage_basename, g_free);
  memset (plan, 0, sizeof *plan);
}

static void
handoff_receipt_clear (WyctlPublicationReceipt *receipt)
{
  g_clear_pointer (&receipt->destination, g_free);
  g_clear_pointer (&receipt->reservation_id, g_free);
  g_clear_pointer (&receipt->parent_identity, g_free);
  g_clear_pointer (&receipt->stage_basename, g_free);
  g_clear_pointer (&receipt->stage_identity, g_free);
  memset (receipt, 0, sizeof *receipt);
}

static void
handoff_publication_result_clear (WyctlPublicationResult *result)
{
  memset (result, 0, sizeof *result);
}

static gchar *
handoff_stage_basename (const gchar *destination, const gchar *reservation_id)
{
  g_autofree gchar *seed = g_strconcat (reservation_id, "\n", destination,
      NULL);
  g_autofree gchar *digest = seed == NULL ? NULL :
      g_compute_checksum_for_string (G_CHECKSUM_SHA256, seed, -1);
  return digest == NULL ? NULL : g_strdup_printf ("wypub-%.*s", 16, digest);
}

static gboolean
handoff_plan_is_valid (const WyctlPublicationPlan *plan)
{
  wyl_id_t reservation;
  g_autofree gchar *stage_basename = NULL;
  return plan != NULL && plan->version == WYCTL_PUBLICATION_PLAN_VERSION
      && wyl_service_credential_operation_destination_is_valid
      (plan->destination)
      && plan->parent_identity != NULL && plan->parent_identity[0] != '\0'
      && plan->reservation_id != NULL
      && wyl_id_parse (plan->reservation_id, &reservation) == WYRELOG_E_OK
      && plan->stage_basename != NULL
      && (stage_basename = handoff_stage_basename (plan->destination,
          plan->reservation_id)) != NULL
      && g_strcmp0 (stage_basename, plan->stage_basename) == 0;
}

static gboolean
handoff_receipt_is_valid (const WyctlPublicationReceipt *receipt)
{
  WyctlPublicationPlan plan = {
    .version = receipt != NULL ? receipt->version : 0,
    .destination = receipt != NULL ? receipt->destination : NULL,
    .reservation_id = receipt != NULL ? receipt->reservation_id : NULL,
    .parent_identity = receipt != NULL ? receipt->parent_identity : NULL,
    .stage_basename = receipt != NULL ? receipt->stage_basename : NULL,
  };
  return receipt != NULL
      && receipt->version == WYCTL_PUBLICATION_RECEIPT_VERSION
      && receipt->stage_identity != NULL && receipt->stage_identity[0] != '\0'
      && handoff_plan_is_valid (&plan);
}

static gboolean
handoff_publication_result_is_valid (const WyctlPublicationResult *result)
{
  return result != NULL && result->version == WYCTL_PUBLICATION_RESULT_VERSION
      && result->kind >= WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED
      && result->kind <= WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
}

static wyrelog_error_t
handoff_plan_request_create (const gchar *destination,
    const gchar *parent_identity, WyctlPublicationPlan *out)
{
  wyl_id_t reservation;
  gchar reservation_id[WYL_ID_STRING_BUF];
  wyrelog_error_t rc = wyl_id_new (&reservation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_id_format (&reservation, reservation_id, sizeof reservation_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out = (WyctlPublicationPlan) {
  .version = WYCTL_PUBLICATION_PLAN_VERSION,.destination =
        g_strdup (destination),.reservation_id =
        g_strdup (reservation_id),.parent_identity =
        g_strdup (parent_identity),.stage_basename =
        handoff_stage_basename (destination, reservation_id),};
  if (out->destination == NULL || out->reservation_id == NULL
      || out->parent_identity == NULL || out->stage_basename == NULL) {
    handoff_plan_clear (out);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

static gint64
handoff_now_us (const WylServiceCredentialOperationHandoffExecuteRuntime
    *runtime)
{
  return runtime->now_us != NULL ? runtime->now_us (runtime->clock_data) :
      g_get_real_time ();
}

static gboolean
handoff_session_matches (const HandoffAuthorization *authorization)
{
  g_autofree gchar *username = NULL;
  g_autofree gchar *session_id = NULL;
  g_autofree gchar *tenant = NULL;
  if (!handoff_session_is_active_human (authorization->runtime->session))
    return FALSE;
  username = wyl_session_dup_username (authorization->runtime->session);
  session_id = wyl_session_dup_id_string (authorization->runtime->session);
  tenant = wyl_session_dup_tenant (authorization->runtime->session);
  return username != NULL && session_id != NULL && tenant != NULL
      && g_strcmp0 (username, authorization->record->actor_subject_id) == 0
      && g_strcmp0 (username,
      authorization->runtime->authenticated_actor_subject_id) == 0
      && g_strcmp0 (session_id, authorization->session_resource_id) == 0
      && g_strcmp0 (tenant, authorization->session_tenant) == 0;
}

static wyrelog_error_t
handoff_authorize (gpointer data, const gchar *actor_subject_id)
{
  HandoffAuthorization *authorization = data;
  if (authorization == NULL
      || g_strcmp0 (actor_subject_id,
          authorization->record->actor_subject_id) != 0
      || !handoff_session_matches (authorization))
    return WYRELOG_E_POLICY;

  g_autoptr (wyl_decide_req_t) request = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) response = wyl_decide_resp_new ();
  if (request == NULL || response == NULL)
    return WYRELOG_E_NOMEM;
  wyl_decide_req_set_subject_id (request,
      authorization->record->actor_subject_id);
  wyl_decide_req_set_action (request, HANDOFF_MANAGE_ACTION);
  wyl_decide_req_set_resource_id (request, authorization->session_resource_id);
  wyl_decide_req_set_request_id (request,
      authorization->runtime->decision_request_id);
  wyl_decide_req_set_guard_context (request,
      authorization->runtime->guard_timestamp,
      authorization->runtime->guard_loc_class,
      authorization->runtime->guard_risk);
  wyrelog_error_t rc = wyl_decide (authorization->handle, request, response);
  if (rc == WYRELOG_E_OK
      && wyl_decide_resp_get_decision (response) != WYL_DECISION_ALLOW)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && authorization->runtime->after_authorization != NULL)
    authorization->runtime->after_authorization
        (authorization->runtime->authorization_checkpoint_data);
  return rc;
}

static gboolean
    handoff_escrow_matches
    (const wyl_policy_service_handoff_escrow_info_t * escrow,
    const WylServiceCredentialOperationRecord * record,
    const wyl_id_t * escrow_id, const guint8 * target_digest)
{
  const gchar *operation =
      record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE ? "issue" :
      "rotate";
  return wyl_id_equal (&escrow->escrow_id, escrow_id)
      && g_strcmp0 (escrow->operation, operation) == 0
      && g_strcmp0 (escrow->request_id, record->request_id) == 0
      && g_strcmp0 (escrow->actor_subject_id, record->actor_subject_id) == 0
      && sodium_memcmp (escrow->target_digest, target_digest,
      WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES) == 0
      && g_strcmp0 (escrow->credential_id,
      record->successor_credential_id) == 0
      && escrow->credential_generation == record->successor_generation
      && escrow->deadline_at_us == record->expires_at_us
      && sodium_memcmp (escrow->binding_digest,
      record->escrow_binding_digest,
      WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES) == 0;
}

static wyrelog_error_t
handoff_escrow_load_exact (wyl_policy_store_t *store,
    const WylServiceCredentialOperationRecord *record,
    const wyl_id_t *escrow_id, const guint8 *target_digest,
    wyl_policy_service_handoff_escrow_info_t *out)
{
  wyrelog_error_t rc = wyl_policy_store_service_handoff_escrow_load (store,
      escrow_id, out);
  if (rc == WYRELOG_E_OK
      && !handoff_escrow_matches (out, record, escrow_id, target_digest)) {
    wyl_policy_service_handoff_escrow_info_clear (out);
    rc = WYRELOG_E_POLICY;
  }
  return rc;
}

static wyrelog_error_t
handoff_secret_encode (wyl_policy_service_handoff_secret_t *secret,
    WyctlSensitiveText *out)
{
  gsize raw_len = 0;
  const guint8 *raw = wyl_policy_service_handoff_secret_peek (secret,
      &raw_len);
  if (raw == NULL || raw_len != WYL_SERVICE_CREDENTIAL_SECRET_BYTES)
    return WYRELOG_E_POLICY;
  out->text = g_malloc0 (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN + 1);
  if (out->text == NULL)
    return WYRELOG_E_NOMEM;
  out->len = WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN;
  if (sodium_bin2base64 (out->text,
          WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN + 1, raw, raw_len,
          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
    handoff_sensitive_clear (out);
    return WYRELOG_E_CRYPTO;
  }
  return WYRELOG_E_OK;
}

static gboolean
handoff_plan_matches_record (const WyctlPublicationPlan *plan,
    const WylServiceCredentialOperationRecord *record)
{
  return handoff_plan_is_valid (plan)
      && g_strcmp0 (plan->destination, record->destination) == 0
      && g_strcmp0 (plan->parent_identity, record->parent_identity) == 0;
}

static wyrelog_error_t
handoff_plan_from_record (const WylServiceCredentialOperationRecord *record,
    WyctlPublicationPlan *out)
{
  *out = (WyctlPublicationPlan) {
  .version = WYCTL_PUBLICATION_PLAN_VERSION,.destination =
        g_strdup (record->destination),.reservation_id =
        g_strdup (record->reservation_id),.parent_identity =
        g_strdup (record->parent_identity),.stage_basename =
        g_strdup (record->stage_basename),};
  if (out->destination == NULL || out->reservation_id == NULL
      || out->parent_identity == NULL || out->stage_basename == NULL) {
    handoff_plan_clear (out);
    return WYRELOG_E_NOMEM;
  }
  return handoff_plan_matches_record (out, record) ? WYRELOG_E_OK :
      WYRELOG_E_POLICY;
}

static wyrelog_error_t
    handoff_receipt_from_record
    (const WylServiceCredentialOperationRecord * record,
    WyctlPublicationReceipt * out)
{
  *out = (WyctlPublicationReceipt) {
  .version = WYCTL_PUBLICATION_RECEIPT_VERSION,.destination =
        g_strdup (record->destination),.reservation_id =
        g_strdup (record->reservation_id),.parent_identity =
        g_strdup (record->parent_identity),.stage_basename =
        g_strdup (record->stage_basename),.stage_identity =
        g_strdup (record->stage_identity),};
  if (out->destination == NULL || out->reservation_id == NULL
      || out->parent_identity == NULL || out->stage_basename == NULL
      || out->stage_identity == NULL) {
    handoff_receipt_clear (out);
    return WYRELOG_E_NOMEM;
  }
  return handoff_receipt_is_valid (out)
      && g_strcmp0 (record->publication_receipt_id,
      record->reservation_id) == 0 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static gboolean
publication_is_exact_durable (const WyctlPublicationResult *result)
{
  return handoff_publication_result_is_valid (result)
      && result->kind == WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE
      && result->exact_identity && !result->cleanup_required;
}

static gboolean
publication_is_exact_precommit (const WyctlPublicationResult *result)
{
  return handoff_publication_result_is_valid (result)
      && result->kind == WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED
      && result->exact_identity && result->cleanup_required;
}

static gboolean
    publication_is_foreign_or_nonexact_commit
    (const WyctlPublicationResult * result)
{
  return !handoff_publication_result_is_valid (result)
      || result->kind == WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN
      || (result->kind == WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE
      && (!result->exact_identity || result->cleanup_required));
}

static gboolean
    handoff_result_matches_prepared
    (const wyl_service_credential_handoff_result_t * result,
    const WylServiceCredentialOperationRecord * record,
    const wyl_id_t * escrow_id, const guint8 * target_digest)
{
  const gchar *operation =
      record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE ? "issue" :
      "rotate";
  return result->credential.credential_id != NULL
      && result->credential.generation != 0
      && wyl_id_equal (&result->handoff.escrow_id, escrow_id)
      && g_strcmp0 (result->handoff.operation, operation) == 0
      && g_strcmp0 (result->handoff.request_id, record->request_id) == 0
      && g_strcmp0 (result->handoff.actor_subject_id,
      record->actor_subject_id) == 0
      && sodium_memcmp (result->handoff.target_digest, target_digest,
      WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES) == 0
      && g_strcmp0 (result->handoff.credential_id,
      result->credential.credential_id) == 0
      && result->handoff.credential_generation == result->credential.generation
      && result->handoff.deadline_at_us == record->expires_at_us;
}

static gboolean
receipt_matches_plan (const WyctlPublicationReceipt *receipt,
    const WyctlPublicationPlan *plan)
{
  return handoff_receipt_is_valid (receipt)
      && g_strcmp0 (receipt->destination, plan->destination) == 0
      && g_strcmp0 (receipt->reservation_id, plan->reservation_id) == 0
      && g_strcmp0 (receipt->parent_identity, plan->parent_identity) == 0
      && g_strcmp0 (receipt->stage_basename, plan->stage_basename) == 0;
}

static wyrelog_error_t
execute_prepared_handoff (WylHandle *handle,
    const WylServiceCredentialOperationRecord *record,
    const WylServiceCredentialOperationHandoffExecuteRuntime *runtime,
    HandoffAuthorization *authorization, const wyl_id_t *escrow_id,
    const guint8 *target_digest, wyl_service_credential_handoff_result_t *out)
{
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = escrow_id,
    .target_digest = target_digest,
    .deadline_at_us = record->expires_at_us,
  };
  wyl_service_credential_mutation_authorization_t mutation_authorization = {
    .authorize = handoff_authorize,
    .data = authorization,
  };
  if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE) {
    wyl_service_credential_issue_runtime_t issue_runtime = {
      .authorization = &mutation_authorization,
    };
    return wyl_service_credential_issue_handoff_with_runtime (handle,
        record->subject_id, record->tenant_id, record->actor_subject_id,
        record->request_id, record->expires_at_us, &handoff, &issue_runtime,
        out);
  }
  if (runtime->rotate_runtime == NULL
      || runtime->rotate_runtime->old_credential_generation
      != record->expected_generation)
    return WYRELOG_E_POLICY;
  wyl_service_credential_rotate_runtime_t rotate_runtime =
      *runtime->rotate_runtime;
  rotate_runtime.authorization = &mutation_authorization;
  return wyl_service_credential_rotate_handoff_checked_with_runtime (handle,
      record->old_credential_id, record->actor_subject_id, record->request_id,
      record->expires_at_us, &handoff, &rotate_runtime, out);
}

static wyrelog_error_t
handoff_authority_transaction_finish (wyl_policy_store_t *store,
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

static WylPolicyServiceHandoffExactTuple
handoff_exact_tuple (const WylServiceCredentialOperationRecord *record,
    const wyl_id_t *escrow_id)
{
  WylPolicyServiceHandoffExactTuple tuple = {
    .original_request_id = record->request_id,
    .escrow_id = escrow_id,
    .successor_credential_id = record->successor_credential_id,
    .successor_issuance_generation = record->successor_generation,
    .original_actor_subject_id = record->actor_subject_id,
  };
  memcpy (tuple.binding_digest, record->escrow_binding_digest,
      sizeof tuple.binding_digest);
  return tuple;
}

static wyrelog_error_t
handoff_classify_for_publication (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const WylPolicyServiceHandoffExactTuple *tuple,
    const gchar *actor_subject_id,
    WylPolicyServiceHandoffPublicationOutcome *out_outcome,
    WylPolicyServiceHandoffDispositionResult *out_disposition)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_classify_for_publication_core (transaction,
        store, tuple, actor_subject_id, out_outcome, out_disposition);
  return transaction == NULL ? rc :
      handoff_authority_transaction_finish (store, transaction, rc);
}

static wyrelog_error_t
handoff_prepare_delivery (WylHandle *handle, WylServiceAuthWriteLease *lease,
    wyl_policy_store_t *store,
    const WylServiceCredentialHandoffDeliveryProof *proof,
    WylServiceCredentialHandoffDeliveryOutcome *out_outcome,
    WylServiceCredentialHandoffDeliveryPreflight **out_preflight,
    WylPolicyServiceHandoffDispositionResult *out_disposition)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_handoff_prepare_delivery_core (transaction,
        store, proof, out_outcome, out_preflight, out_disposition);
  if (transaction != NULL)
    rc = handoff_authority_transaction_finish (store, transaction, rc);
  if (rc != WYRELOG_E_OK) {
    g_clear_pointer (out_preflight,
        wyl_service_credential_handoff_delivery_preflight_free);
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  }
  return rc;
}

static wyrelog_error_t
handoff_consume_delivery (WylHandle *handle, WylServiceAuthWriteLease *lease,
    wyl_policy_store_t *store,
    WylServiceCredentialHandoffDeliveryCapability *capability,
    WylPolicyServiceHandoffPublicationOutcome *out_outcome,
    WylPolicyServiceHandoffDispositionResult *out_disposition)
{
  WylServiceAuthorityTransaction *transaction = NULL;
  wyrelog_error_t rc = wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_handoff_delivery_consume_core (transaction,
        store, capability, out_outcome, out_disposition);
  if (transaction != NULL)
    rc = handoff_authority_transaction_finish (store, transaction, rc);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  return rc;
}

static WylServiceCredentialOperationOarCause
handoff_inactive_cause (WylPolicyServiceHandoffPublicationOutcome outcome)
{
  return outcome == WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_EXPIRED ?
      WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_EXPIRED :
      WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_REVOKED;
}

static wyrelog_error_t
handoff_require_active_or_checkpoint (WylHandle *handle,
    WylServiceAuthWriteLease *lease, wyl_policy_store_t *store,
    const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id,
    const WylServiceCredentialOperationHandoffExecuteRuntime *runtime,
    const WylPolicyServiceHandoffExactTuple *tuple,
    WylServiceCredentialOperationRecord *record, gboolean *out_active)
{
  WylPolicyServiceHandoffDispositionResult disposition = { 0 };
  WylPolicyServiceHandoffPublicationOutcome outcome = 0;
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = FALSE;
  *out_active = FALSE;
  wyrelog_error_t rc = handoff_classify_for_publication (handle, lease, store,
      tuple, record->actor_subject_id, &outcome, &disposition);
  if (rc == WYRELOG_E_OK && outcome == WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE) {
    *out_active = TRUE;
  } else if (rc == WYRELOG_E_OK) {
    rc = wyl_service_credential_operation_coordinator_checkpoint_successor_inactive_oar (storage, anchor, request_id, handoff_inactive_cause (outcome), handoff_now_us (runtime), &replayed, &next);
    if (rc == WYRELOG_E_OK) {
      wyl_service_credential_operation_record_clear (record);
      *record = next;
      next = (WylServiceCredentialOperationRecord)
          WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    }
  }
  wyl_service_credential_operation_record_clear (&next);
  wyl_policy_service_handoff_disposition_result_clear (&disposition);
  return rc;
}

static wyrelog_error_t
resume_committed_handoff (WylHandle *handle,
    const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id,
    const WylServiceCredentialOperationHandoffExecuteRuntime *runtime,
    HandoffAuthorization *authorization, const wyl_id_t *escrow_id,
    const guint8 *target_digest, WylServiceCredentialOperationRecord *record)
{
  WylServiceAuthWriteLease *lease = NULL;
  wyl_policy_store_t *store = NULL;
  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
  wyl_policy_service_handoff_secret_t *sealed_secret = NULL;
  WylPolicyServiceHandoffDispositionResult disposition = { 0 };
  WylServiceCredentialHandoffDeliveryPreflight *preflight = NULL;
  WylServiceCredentialHandoffDeliveryCapability *capability = NULL;
  WyctlSensitiveText secret = { 0 };
  WyctlPublicationPlan plan = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationReceiptTargetLease *target_lease = NULL;
  WyctlPublicationReceiptTargetKind target_kind =
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
  WyctlPublicationResult result = { 0 };
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = FALSE;
  gboolean stage_replayed = FALSE;
  wyrelog_error_t rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle,
      runtime->cancellable, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (lease, handle, &store);
  if (rc == WYRELOG_E_OK)
    rc = handoff_authorize (authorization, record->actor_subject_id);

  while (rc == WYRELOG_E_OK) {
    wyl_policy_service_handoff_escrow_info_clear (&escrow);
    wyl_policy_service_handoff_secret_clear (&sealed_secret);
    wyl_policy_service_handoff_disposition_result_clear (&disposition);
    g_clear_pointer (&preflight,
        wyl_service_credential_handoff_delivery_preflight_free);
    g_clear_pointer (&capability,
        wyl_service_credential_handoff_delivery_capability_free);
    handoff_sensitive_clear (&secret);
    handoff_plan_clear (&plan);
    handoff_receipt_clear (&receipt);
    handoff_publication_result_clear (&result);
    if (target_lease != NULL) {
      runtime->publication->receipt_target_release
          (runtime->publication_data, target_lease);
      target_lease = NULL;
    }
    target_kind = WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
    wyl_service_credential_operation_record_clear (&next);

    WylPolicyServiceHandoffExactTuple tuple =
        handoff_exact_tuple (record, escrow_id);

    if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED) {
      WyctlPublicationPlan request = { 0 };
      rc = handoff_escrow_load_exact (store, record, escrow_id, target_digest,
          &escrow);
      if (rc == WYRELOG_E_OK)
        rc = handoff_plan_request_create (record->destination,
            record->parent_identity, &request);
      gboolean active = FALSE;
      if (rc == WYRELOG_E_OK)
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
      if (rc == WYRELOG_E_OK && !active) {
        handoff_plan_clear (&request);
        break;
      }
      if (rc == WYRELOG_E_OK)
        rc = runtime->publication->plan (runtime->publication_data, &request,
            &plan);
      handoff_plan_clear (&request);
      if (rc == WYRELOG_E_OK && !handoff_plan_matches_record (&plan, record))
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK)
        rc = wyl_service_credential_operation_coordinator_checkpoint_publication_planned (storage, anchor, request_id, plan.reservation_id, plan.stage_basename, plan.reservation_id, handoff_now_us (runtime), &replayed, &next);
    } else if (record->state ==
        WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED) {
      rc = handoff_escrow_load_exact (store, record, escrow_id, target_digest,
          &escrow);
      if (rc == WYRELOG_E_OK)
        rc = handoff_plan_from_record (record, &plan);
      gboolean active = FALSE;
      if (rc == WYRELOG_E_OK)
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
      if (rc == WYRELOG_E_OK && !active)
        break;
      if (rc == WYRELOG_E_OK)
        rc = wyl_policy_store_service_handoff_escrow_unseal (store, &escrow,
            &sealed_secret);
      if (rc == WYRELOG_E_OK)
        rc = handoff_secret_encode (sealed_secret, &secret);
      if (rc == WYRELOG_E_OK)
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
      if (rc == WYRELOG_E_OK && !active)
        break;
      if (rc == WYRELOG_E_OK)
        rc = runtime->publication->stage_exact (runtime->publication_data,
            &plan, record->successor_credential_id, &secret, &receipt, &result,
            &stage_replayed);
      if (rc == WYRELOG_E_OK && (!publication_is_exact_durable (&result)
              || !receipt_matches_plan (&receipt, &plan)))
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK)
        rc = wyl_service_credential_operation_coordinator_checkpoint_publication_prepared (storage, anchor, request_id, receipt.reservation_id, receipt.stage_basename, receipt.stage_identity, receipt.reservation_id, handoff_now_us (runtime), &replayed, &next);
    } else if (record->state ==
        WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED) {
      gboolean active = FALSE;
      rc = handoff_plan_from_record (record, &plan);
      if (rc == WYRELOG_E_OK)
        rc = handoff_receipt_from_record (record, &receipt);
      if (rc == WYRELOG_E_OK)
        rc = runtime->publication->receipt_target_acquire
            (runtime->publication_data, &plan, &receipt, FALSE,
            &target_lease, &target_kind);
      if (rc == WYRELOG_E_OK && target_kind !=
          WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE
          && target_kind != WYCTL_PUBLICATION_RECEIPT_TARGET_DESTINATION)
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK && target_lease == NULL)
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK)
        rc = handoff_escrow_load_exact (store, record, escrow_id,
            target_digest, &escrow);
      if (rc == WYRELOG_E_OK)
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
      if (rc == WYRELOG_E_OK && !active)
        break;
      if (rc == WYRELOG_E_OK)
        rc = wyl_policy_store_service_handoff_escrow_unseal (store, &escrow,
            &sealed_secret);
      if (rc == WYRELOG_E_OK)
        rc = handoff_secret_encode (sealed_secret, &secret);
      if (rc == WYRELOG_E_OK)
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
      if (rc == WYRELOG_E_OK && !active)
        break;
      if (rc == WYRELOG_E_OK)
        rc = runtime->publication->receipt_target_inspect
            (runtime->publication_data, target_lease,
            record->successor_credential_id, &secret, &result);
      if (rc == WYRELOG_E_OK && result.kind ==
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN) {
        handoff_publication_result_clear (&result);
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
        if (rc == WYRELOG_E_OK && active)
          rc = runtime->publication->receipt_target_inspect
              (runtime->publication_data, target_lease,
              record->successor_credential_id, &secret, &result);
        if (rc == WYRELOG_E_OK && !active)
          break;
      }
      if (rc == WYRELOG_E_OK
          && ((target_kind == WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE
                  && !publication_is_exact_precommit (&result))
              || (target_kind ==
                  WYCTL_PUBLICATION_RECEIPT_TARGET_DESTINATION
                  && !publication_is_exact_durable (&result))))
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK && publication_is_exact_precommit (&result)) {
        handoff_publication_result_clear (&result);
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
        if (rc == WYRELOG_E_OK && active)
          rc = runtime->publication->receipt_target_commit
              (runtime->publication_data, target_lease,
              record->successor_credential_id, &secret, &result);
        if (rc == WYRELOG_E_OK && !active)
          break;
        if (rc == WYRELOG_E_OK
            && publication_is_foreign_or_nonexact_commit (&result))
          rc = WYRELOG_E_POLICY;
        if (rc == WYRELOG_E_OK) {
          handoff_publication_result_clear (&result);
          rc = handoff_require_active_or_checkpoint (handle, lease, store,
              storage, anchor, request_id, runtime, &tuple, record, &active);
          if (rc == WYRELOG_E_OK && active)
            rc = runtime->publication->receipt_target_inspect
                (runtime->publication_data, target_lease,
                record->successor_credential_id, &secret, &result);
          if (rc == WYRELOG_E_OK && !active)
            break;
        }
      }
      if (rc == WYRELOG_E_OK && !publication_is_exact_durable (&result))
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK)
        rc = wyl_service_credential_operation_coordinator_checkpoint_file_published (storage, anchor, request_id, receipt.reservation_id, receipt.stage_basename, receipt.stage_identity, receipt.reservation_id, handoff_now_us (runtime), &replayed, &next);
    } else if (record->state ==
        WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
        || record->state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED) {
      WylServiceCredentialHandoffDeliveryProof proof = {
        .source = record->state ==
            WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED ?
            WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_FILE_PUBLISHED :
            WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_CLEANUP_REQUIRED,
        .tuple = tuple,
        .actor_subject_id = record->actor_subject_id,
        .operation = record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE ?
            "issue" : "rotate",
        .deadline_at_us = record->expires_at_us,
        .receipt_version = record->publication_receipt_version,
        .destination = record->destination,
        .reservation_id = record->reservation_id,
        .parent_identity = record->parent_identity,
        .stage_basename = record->stage_basename,
        .stage_identity = record->stage_identity,
        .publication_receipt_id = record->publication_receipt_id,
      };
      memcpy (proof.target_digest, target_digest, sizeof proof.target_digest);
      WylServiceCredentialHandoffDeliveryOutcome delivery_outcome = 0;
      rc = handoff_prepare_delivery (handle, lease, store, &proof,
          &delivery_outcome, &preflight, &disposition);
      if (rc != WYRELOG_E_OK)
        break;
      if (delivery_outcome == WYL_SERVICE_HANDOFF_DELIVERY_REPLAYED
          || delivery_outcome ==
          WYL_SERVICE_HANDOFF_DELIVERY_LEGACY_BACKFILLED) {
        rc = wyl_service_credential_operation_coordinator_checkpoint_terminal_file_published (storage, anchor, request_id, handoff_now_us (runtime), &replayed, &next);
        if (rc == WYRELOG_E_OK) {
          wyl_service_credential_operation_record_clear (record);
          *record = next;
          next = (WylServiceCredentialOperationRecord)
              WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
        }
        break;
      }
      if (delivery_outcome == WYL_SERVICE_HANDOFF_DELIVERY_SUCCESSOR_EXPIRED
          || delivery_outcome ==
          WYL_SERVICE_HANDOFF_DELIVERY_SUCCESSOR_REVOKED) {
        WylServiceCredentialOperationOarCause cause =
            delivery_outcome ==
            WYL_SERVICE_HANDOFF_DELIVERY_SUCCESSOR_EXPIRED ?
            WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_EXPIRED :
            WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_REVOKED;
        rc = wyl_service_credential_operation_coordinator_checkpoint_successor_inactive_oar (storage, anchor, request_id, cause, handoff_now_us (runtime), &replayed, &next);
        if (rc == WYRELOG_E_OK) {
          wyl_service_credential_operation_record_clear (record);
          *record = next;
          next = (WylServiceCredentialOperationRecord)
              WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
        }
        break;
      }
      gboolean active = FALSE;
      rc = handoff_plan_from_record (record, &plan);
      if (rc == WYRELOG_E_OK)
        rc = handoff_receipt_from_record (record, &receipt);
      if (rc == WYRELOG_E_OK)
        rc = runtime->publication->receipt_target_acquire
            (runtime->publication_data, &plan, &receipt, TRUE,
            &target_lease, &target_kind);
      if (rc == WYRELOG_E_OK
          && target_kind ==
          WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN) {
        if (target_lease != NULL) {
          runtime->publication->receipt_target_release
              (runtime->publication_data, target_lease);
          target_lease = NULL;
        }
        rc = wyl_service_credential_operation_coordinator_checkpoint_receipt_oar
            (storage, anchor, request_id,
            WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_FOREIGN,
            handoff_now_us (runtime), &replayed, &next);
        if (rc == WYRELOG_E_OK) {
          wyl_service_credential_operation_record_clear (record);
          *record = next;
          next = (WylServiceCredentialOperationRecord)
              WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
        }
        break;
      }
      if (rc == WYRELOG_E_OK
          && (target_kind != WYCTL_PUBLICATION_RECEIPT_TARGET_DESTINATION
              || target_lease == NULL))
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK)
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
      if (rc == WYRELOG_E_OK && !active)
        break;
      if (rc == WYRELOG_E_OK)
        rc = wyl_service_credential_handoff_delivery_unseal (store, preflight,
            &sealed_secret);
      if (rc == WYRELOG_E_OK)
        rc = handoff_secret_encode (sealed_secret, &secret);
      gboolean inspect_attempted = FALSE;
      if (rc == WYRELOG_E_OK) {
        rc = handoff_require_active_or_checkpoint (handle, lease, store,
            storage, anchor, request_id, runtime, &tuple, record, &active);
        if (rc == WYRELOG_E_OK && active) {
          inspect_attempted = TRUE;
          rc = runtime->publication->receipt_target_inspect
              (runtime->publication_data, target_lease,
              record->successor_credential_id, &secret, &result);
        }
      }
      if (rc == WYRELOG_E_OK && !active)
        break;
      if (rc != WYRELOG_E_OK || !publication_is_exact_durable (&result)) {
        if (target_lease != NULL) {
          runtime->publication->receipt_target_release
              (runtime->publication_data, target_lease);
          target_lease = NULL;
        }
        if (inspect_attempted) {
          WylServiceCredentialOperationOarCause cause =
              rc == WYRELOG_E_OK
              && result.kind == WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN ?
              WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_FOREIGN :
              WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN;
          wyrelog_error_t checkpoint_rc =
              wyl_service_credential_operation_coordinator_checkpoint_receipt_oar
              (storage, anchor, request_id, cause, handoff_now_us (runtime),
              &replayed, &next);
          if (checkpoint_rc == WYRELOG_E_OK) {
            wyl_service_credential_operation_record_clear (record);
            *record = next;
            next = (WylServiceCredentialOperationRecord)
                WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
            rc = WYRELOG_E_OK;
          } else {
            rc = checkpoint_rc;
          }
        }
        break;
      }
      rc = wyl_service_credential_handoff_delivery_confirm_inspection
          (preflight, &result, &capability);
      if (rc == WYRELOG_E_OK)
        preflight = NULL;
      if (target_lease != NULL) {
        runtime->publication->receipt_target_release
            (runtime->publication_data, target_lease);
        target_lease = NULL;
      }
      if (rc != WYRELOG_E_OK)
        break;
      WylPolicyServiceHandoffPublicationOutcome consume_outcome = 0;
      rc = handoff_consume_delivery (handle, lease, store, capability,
          &consume_outcome, &disposition);
      if (rc == WYRELOG_E_OK
          && consume_outcome != WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE) {
        rc = wyl_service_credential_operation_coordinator_checkpoint_successor_inactive_oar (storage, anchor, request_id, handoff_inactive_cause (consume_outcome), handoff_now_us (runtime), &replayed, &next);
        if (rc == WYRELOG_E_OK) {
          wyl_service_credential_operation_record_clear (record);
          *record = next;
          next = (WylServiceCredentialOperationRecord)
              WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
        }
        break;
      }
      if (rc != WYRELOG_E_OK) {
        wyrelog_error_t consume_rc = rc;
        if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED) {
          wyrelog_error_t checkpoint_rc =
              wyl_service_credential_operation_coordinator_checkpoint_cleanup_required
              (storage, anchor, request_id, handoff_now_us (runtime),
              &replayed, &next);
          if (checkpoint_rc != WYRELOG_E_OK)
            rc = checkpoint_rc;
          else
            rc = consume_rc;
        }
        break;
      }
      rc = wyl_service_credential_operation_coordinator_checkpoint_terminal_file_published (storage, anchor, request_id, handoff_now_us (runtime), &replayed, &next);
      if (rc == WYRELOG_E_OK) {
        wyl_service_credential_operation_record_clear (record);
        *record = next;
        next = (WylServiceCredentialOperationRecord)
            WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
      }
      break;
    } else {
      rc = WYRELOG_E_POLICY;
    }

    if (rc == WYRELOG_E_OK) {
      wyl_service_credential_operation_record_clear (record);
      *record = next;
      next = (WylServiceCredentialOperationRecord)
          WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    }
  }

  wyl_service_credential_operation_record_clear (&next);
  if (target_lease != NULL)
    runtime->publication->receipt_target_release (runtime->publication_data,
        target_lease);
  handoff_publication_result_clear (&result);
  handoff_receipt_clear (&receipt);
  handoff_plan_clear (&plan);
  handoff_sensitive_clear (&secret);
  wyl_policy_service_handoff_secret_clear (&sealed_secret);
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
  wyl_policy_service_handoff_disposition_result_clear (&disposition);
  g_clear_pointer (&preflight,
      wyl_service_credential_handoff_delivery_preflight_free);
  g_clear_pointer (&capability,
      wyl_service_credential_handoff_delivery_capability_free);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (rc == WYRELOG_E_OK && release_rc != WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  return rc;
}


static wyrelog_error_t
    handoff_maintenance_stops_execution
    (WylServiceCredentialOperationMaintenanceOutcome outcome,
    const WylServiceCredentialOperationRecord * record, gboolean * out_stop)
{
  *out_stop = FALSE;
  if (outcome ==
      WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_TERMINAL_NOT_COMMITTED
      || outcome ==
      WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_ATTENTION_REQUIRED
      || outcome ==
      WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_OPERATOR_ACTION_REQUIRED) {
    *out_stop = TRUE;
    return WYRELOG_E_OK;
  }
  if (outcome != WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED)
    return WYRELOG_E_POLICY;
  if (record->state ==
      WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED) {
    *out_stop = TRUE;
    return WYRELOG_E_OK;
  }
  if (record->state != WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL)
    return WYRELOG_E_OK;

  WylServiceCredentialOperationTerminalKind terminal_kind = 0;
  if (!wyl_service_credential_operation_terminal_reason_parse
      (record->terminal_reason, &terminal_kind, NULL)
      || (terminal_kind !=
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_NOT_COMMITTED
          && terminal_kind !=
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED
          && (terminal_kind !=
              WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE
              || record->version !=
              WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION
              || record->last_remediation_action !=
              WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_REVOKE_AND_WIPE)))
    return WYRELOG_E_POLICY;
  *out_stop = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_execute_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    const WylServiceCredentialOperationHandoffExecuteRuntime * runtime,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord recovered =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyl_service_credential_handoff_result_t mutation = { 0 };
  wyl_service_credential_t old_credential = { 0 };
  WylServiceCredentialOperationMaintenanceOutcome maintenance_outcome = 0;
  g_autofree gchar *session_actor = NULL;
  g_autofree gchar *session_tenant = NULL;
  g_autofree gchar *session_resource_id = NULL;
  guint8 target_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES] = { 0 };
  wyl_id_t escrow_id;
  gboolean checkpoint_replayed = FALSE;
  gboolean maintenance_stop = FALSE;
  gboolean locked = FALSE;
  gint64 now_us;
  wyrelog_error_t rc;

  if (handle == NULL || storage == NULL || anchor == NULL || runtime == NULL
      || out_record == NULL || runtime->session == NULL
      || runtime->authenticated_actor_subject_id == NULL
      || runtime->guard_timestamp < 0 || runtime->guard_loc_class == NULL
      || !wyl_guard_loc_class_is_valid (runtime->guard_loc_class)
      || runtime->guard_risk < 0 || runtime->guard_risk > 100
      || runtime->decision_request_id == NULL
      || runtime->decision_request_id[0] == '\0'
      || runtime->publication == NULL || runtime->publication->plan == NULL
      || runtime->publication->stage_exact == NULL
      || runtime->publication->receipt_target_acquire == NULL
      || runtime->publication->receipt_target_inspect == NULL
      || runtime->publication->receipt_target_commit == NULL
      || runtime->publication->receipt_target_release == NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id)
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)
      || (runtime->cancellable != NULL
          && !G_IS_CANCELLABLE (runtime->cancellable)))
    return WYRELOG_E_INVALID;
  session_actor = wyl_session_dup_username (runtime->session);
  session_tenant = wyl_session_dup_tenant (runtime->session);
  session_resource_id = wyl_session_dup_id_string (runtime->session);
  if (!handoff_session_is_active_human (runtime->session)
      || session_actor == NULL || session_tenant == NULL
      || session_resource_id == NULL
      || !wyl_policy_service_actor_subject_is_valid (session_actor)
      || g_strcmp0 (session_actor,
          runtime->authenticated_actor_subject_id) != 0)
    return WYRELOG_E_POLICY;

  rc = wyl_service_credential_operation_coordinator_lock_acquire (storage,
      anchor, request_id, &lifecycle_lock);
  if (rc != WYRELOG_E_OK)
    goto out;
  locked = TRUE;
  rc = wyl_service_credential_operation_coordinator_load (storage, anchor,
      request_id, &record);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (g_strcmp0 (record.actor_subject_id, session_actor) != 0) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  if (record.kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE) {
    if (g_strcmp0 (record.tenant_id, session_tenant) != 0) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
  } else if (record.kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE) {
    rc = wyl_service_credential_operation_coordinator_get_credential_pinned
        (handle, runtime->cancellable, record.old_credential_id,
        &old_credential);
    if (rc != WYRELOG_E_OK)
      goto out;
    if (g_strcmp0 (old_credential.tenant_id, session_tenant) != 0) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
  } else {
    rc = WYRELOG_E_POLICY;
    goto out;
  }

  rc = wyl_service_credential_operation_coordinator_maintain_expired_locked
      (handle, storage, anchor, request_id, runtime->cancellable,
      &maintenance_outcome, &recovered);
  if (rc != WYRELOG_E_OK)
    goto out;
  wyl_service_credential_operation_record_clear (&record);
  record = recovered;
  recovered = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  rc = handoff_maintenance_stops_execution (maintenance_outcome, &record,
      &maintenance_stop);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (maintenance_stop) {
    wyl_service_credential_operation_record_clear (out_record);
    *out_record = record;
    record = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    rc = WYRELOG_E_OK;
    goto out;
  }

  now_us = handoff_now_us (runtime);
  if (now_us <= 0) {
    rc = WYRELOG_E_INVALID;
    goto out;
  }

  if (record.state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
      && record.state != WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  rc = wyl_id_parse (record.escrow_id, &escrow_id);
  if (rc != WYRELOG_E_OK) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  rc = wyl_service_credential_operation_handoff_target_digest (&record,
      target_digest);
  if (rc != WYRELOG_E_OK)
    goto out;

  HandoffAuthorization authorization = {
    .handle = handle,
    .record = &record,
    .runtime = runtime,
    .session_resource_id = session_resource_id,
    .session_tenant = session_tenant,
  };
  if (record.state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED) {
    rc = execute_prepared_handoff (handle, &record, runtime, &authorization,
        &escrow_id, target_digest, &mutation);
    if (rc != WYRELOG_E_OK)
      goto out;
    if (!handoff_result_matches_prepared (&mutation, &record, &escrow_id,
            target_digest)) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    rc = wyl_service_credential_operation_coordinator_checkpoint_server_committed_bound (storage, anchor, request_id, mutation.handoff.credential_id, mutation.handoff.credential_generation, mutation.handoff.binding_digest, handoff_now_us (runtime), &checkpoint_replayed, &recovered);
    if (rc != WYRELOG_E_OK)
      goto out;
    wyl_service_credential_operation_record_clear (&record);
    record = recovered;
    recovered = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    authorization.record = &record;

    maintenance_outcome = 0;
    maintenance_stop = FALSE;
    rc = wyl_service_credential_operation_coordinator_maintain_expired_locked
        (handle, storage, anchor, request_id, runtime->cancellable,
        &maintenance_outcome, &recovered);
    if (rc != WYRELOG_E_OK)
      goto out;
    wyl_service_credential_operation_record_clear (&record);
    record = recovered;
    recovered = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    authorization.record = &record;
    rc = handoff_maintenance_stops_execution (maintenance_outcome, &record,
        &maintenance_stop);
    if (rc != WYRELOG_E_OK)
      goto out;
    if (maintenance_stop) {
      wyl_service_credential_operation_record_clear (out_record);
      *out_record = record;
      record = (WylServiceCredentialOperationRecord)
          WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
      rc = WYRELOG_E_OK;
      goto out;
    }
  }

  rc = resume_committed_handoff (handle, storage, anchor, request_id, runtime,
      &authorization, &escrow_id, target_digest, &record);
  if (rc == WYRELOG_E_OK) {
    wyl_service_credential_operation_record_clear (out_record);
    *out_record = record;
    record = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  }

out:
  sodium_memzero (target_digest, sizeof target_digest);
  wyl_service_credential_clear (&old_credential);
  wyl_service_credential_handoff_result_clear (&mutation);
  wyl_service_credential_operation_record_clear (&recovered);
  wyl_service_credential_operation_record_clear (&record);
  if (locked)
    wyl_service_credential_operation_coordinator_lock_release (storage,
        anchor, &lifecycle_lock);
  return rc;
}

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

static void
handoff_put_u32be (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

/* Domain-separated, length-prefixed BLAKE2b of a single request_id into a
 * fixed-size digest.  The length prefixes keep the domain and request_id
 * unambiguous, so two distinct request identities can never collide. */
static wyrelog_error_t
handoff_domain_hash (const gchar *domain, const gchar *request_id,
    guint8 *out, gsize out_len)
{
  crypto_generichash_state state;
  const gchar *inputs[2] = { domain, request_id };
  if (crypto_generichash_init (&state, NULL, 0, out_len) != 0)
    return WYRELOG_E_CRYPTO;
  for (gsize i = 0; i < G_N_ELEMENTS (inputs); i++) {
    gsize len = strlen (inputs[i]);
    guint8 encoded_len[4];
    if (len > G_MAXUINT32) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
    handoff_put_u32be (encoded_len, (guint32) len);
    if (crypto_generichash_update (&state, encoded_len, sizeof encoded_len) != 0
        || crypto_generichash_update (&state, (const guint8 *) inputs[i],
            len) != 0) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
  }
  if (crypto_generichash_final (&state, out, out_len) != 0) {
    sodium_memzero (&state, sizeof state);
    return WYRELOG_E_CRYPTO;
  }
  sodium_memzero (&state, sizeof state);
  return WYRELOG_E_OK;
}

/* Deterministically derive the escrow_id into request from
 * request->request_id.  The escrow_id is an immutable identity token, not a
 * capability: the same request_id always yields the same escrow_id, which is
 * exactly what lets a retry replay instead of conflict.  On success
 * request->escrow_id is a freshly owned string.
 *
 * escrow_binding_digest is deliberately NOT derived here: it is the actual
 * committed escrow binding, minted by the domain primitive at server-commit and
 * stamped into the record by checkpoint_server_committed_bound.  It MUST be zero
 * on a not-yet-committed request; a non-zero value fails the prepared-record
 * maintenance invariant.  The caller leaves it zeroed. */
static wyrelog_error_t
handoff_derive_escrow (WylServiceCredentialOperationCoordinatorRequest *request)
{
  static const gchar id_domain[] = "wyrelog.sc.escrow.id.v1";
  guint8 id_bytes[WYL_ID_BYTES];
  wyl_id_t id;
  wyl_id_t verify;
  gchar buf[WYL_ID_STRING_BUF];
  wyrelog_error_t rc = handoff_domain_hash (id_domain, request->request_id,
      id_bytes, sizeof id_bytes);
  if (rc != WYRELOG_E_OK)
    return rc;
  /* Stamp the RFC 9562 UUIDv7 version and variant nibbles so the 16 hash bytes
   * render as a canonical id that wyl_id_parse accepts. */
  id_bytes[6] = (guint8) (0x70 | (id_bytes[6] & 0x0f));
  id_bytes[8] = (guint8) (0x80 | (id_bytes[8] & 0x3f));
  memcpy (id.bytes, id_bytes, sizeof id.bytes);
  rc = wyl_id_format (&id, buf, sizeof buf);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (wyl_id_parse (buf, &verify) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  request->escrow_id = g_strdup (buf);
  return request->escrow_id != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    const WylServiceCredentialOperationHandoffExecuteRuntime * runtime,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord existing =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationGuardedBeginResult guarded =
      WYL_SERVICE_CREDENTIAL_OPERATION_GUARDED_BEGIN_RESULT_INIT;
  WylServiceCredentialOperationCoordinatorRequest local;
  wyrelog_error_t rc;

  if (out_record != NULL)
    wyl_service_credential_operation_record_clear (out_record);
  if (handle == NULL || storage == NULL || anchor == NULL || request == NULL
      || runtime == NULL || out_record == NULL)
    return WYRELOG_E_INVALID;

  /* Shallow copy borrows the caller's strings; only escrow_id is ever owned by
   * this frame.  expires_at_us and expected_generation are carried through
   * unchanged as the caller-supplied immutable operation identity. */
  local = *request;
  local.escrow_id = NULL;
  memset (local.escrow_binding_digest, 0, sizeof local.escrow_binding_digest);

  rc = handoff_derive_escrow (&local);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (!wyl_service_credential_operation_coordinator_request_is_valid (&local)) {
    rc = WYRELOG_E_INVALID;
    goto out;
  }

  rc = wyl_service_credential_operation_coordinator_load (storage, anchor,
      local.request_id, &existing);
  if (rc == WYRELOG_E_NOT_FOUND) {
    rc = wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded (handle, storage, anchor, &local, runtime->cancellable, &guarded);
    wyl_service_credential_operation_guarded_begin_result_clear (&guarded);
    if (rc != WYRELOG_E_OK)
      goto out;
  } else if (rc == WYRELOG_E_OK) {
    wyl_service_credential_operation_record_clear (&existing);
  } else {
    goto out;
  }

  rc = wyl_service_credential_operation_coordinator_execute_handoff (handle,
      storage, anchor, local.request_id, runtime, out_record);

out:
  g_free (local.escrow_id);
  wyl_service_credential_operation_record_clear (&existing);
  return rc;
}

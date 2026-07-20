/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-remediate-private.h"

#include "auth/service-auth-coordination-private.h"
#include "auth/service-credential-operation-coordinator-auth-private.h"
#include "auth/service-credential-operation-coordinator-maintenance-private.h"
#include "auth/service-credential-operation-coordinator-private.h"
#include "policy/store-handoff-maintenance-private.h"
#include "policy/store-private.h"
#include "wyrelog/decide.h"
#include "wyl-handle-private.h"
#include "wyl-permission-scope-private.h"
#include "wyl-session-layout-private.h"

#include <sodium.h>
#include <string.h>

#define HANDOFF_MANAGE_ACTION "wr.service_credential.manage"

typedef struct
{
  WylHandle *handle;
  const WylServiceCredentialOperationHandoffRemediationRuntime *runtime;
  const gchar *current_actor_subject_id;
  const gchar *session_resource_id;
  const gchar *session_tenant;
} HandoffRemediationAuthorization;

void wyl_service_credential_operation_handoff_remediation_result_clear
    (WylServiceCredentialOperationHandoffRemediationResult * result)
{
  if (result == NULL)
    return;
  g_clear_pointer (&result->remediation_request_id, g_free);
  g_clear_pointer (&result->audit_id, g_free);
  sodium_memzero (result, sizeof *result);
}

static gboolean
handoff_remediation_session_is_active_human (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
      && session->state == WYL_SESSION_STATE_ACTIVE
      && session->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN;
}

static gboolean
    handoff_remediation_cancelled
    (const WylServiceCredentialOperationHandoffRemediationRuntime * runtime)
{
  return runtime->cancellable != NULL
      && g_cancellable_is_cancelled (runtime->cancellable);
}

static gboolean
    handoff_remediation_session_matches
    (const HandoffRemediationAuthorization * auth)
{
  g_autofree gchar *username = NULL;
  g_autofree gchar *session_id = NULL;
  g_autofree gchar *tenant = NULL;

  if (!handoff_remediation_session_is_active_human (auth->runtime->session))
    return FALSE;
  username = wyl_session_dup_username (auth->runtime->session);
  session_id = wyl_session_dup_id_string (auth->runtime->session);
  tenant = wyl_session_dup_tenant (auth->runtime->session);
  return username != NULL && session_id != NULL && tenant != NULL
      && g_strcmp0 (username, auth->current_actor_subject_id) == 0
      && g_strcmp0 (username,
      auth->runtime->authenticated_actor_subject_id) == 0
      && g_strcmp0 (session_id, auth->session_resource_id) == 0
      && g_strcmp0 (tenant, auth->session_tenant) == 0;
}

static wyrelog_error_t
handoff_remediation_authorize (gpointer data, const gchar *actor_subject_id)
{
  HandoffRemediationAuthorization *auth = data;
  if (auth == NULL || handoff_remediation_cancelled (auth->runtime)
      || g_strcmp0 (actor_subject_id, auth->current_actor_subject_id) != 0
      || !handoff_remediation_session_matches (auth))
    return auth != NULL && handoff_remediation_cancelled (auth->runtime) ?
        WYRELOG_E_BUSY : WYRELOG_E_POLICY;

  g_autoptr (wyl_decide_req_t) request = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) response = wyl_decide_resp_new ();
  if (request == NULL || response == NULL)
    return WYRELOG_E_NOMEM;
  wyl_decide_req_set_subject_id (request, auth->current_actor_subject_id);
  wyl_decide_req_set_action (request, HANDOFF_MANAGE_ACTION);
  wyl_decide_req_set_resource_id (request, auth->session_resource_id);
  wyl_decide_req_set_request_id (request, auth->runtime->decision_request_id);
  wyl_decide_req_set_guard_context (request,
      auth->runtime->guard_timestamp, auth->runtime->guard_loc_class,
      auth->runtime->guard_risk);
  wyrelog_error_t rc = wyl_decide (auth->handle, request, response);
  if (rc == WYRELOG_E_OK
      && wyl_decide_resp_get_decision (response) != WYL_DECISION_ALLOW)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && handoff_remediation_cancelled (auth->runtime))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK && auth->runtime->after_authorization != NULL)
    auth->runtime->after_authorization
        (auth->runtime->authorization_checkpoint_data);
  if (rc == WYRELOG_E_OK && handoff_remediation_cancelled (auth->runtime))
    rc = WYRELOG_E_BUSY;
  return rc;
}

static gboolean
handoff_remediation_uuid_is_valid (const gchar *id)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];

  return id != NULL && wyl_id_parse (id, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && g_strcmp0 (id, canonical) == 0;
}

static gboolean
handoff_remediation_request_is_valid (const gchar *original_request_id,
    const WylServiceCredentialOperationHandoffRemediationRequest *request,
    const gchar *decision_request_id)
{
  return request != NULL
      && wyl_service_credential_operation_coordinator_request_id_is_valid
      (original_request_id)
      && wyl_service_credential_operation_coordinator_request_id_is_valid
      (request->remediation_request_id)
      && wyl_service_credential_operation_coordinator_request_id_is_valid
      (decision_request_id)
      && handoff_remediation_uuid_is_valid (request->audit_id)
      && g_strcmp0 (original_request_id,
      request->remediation_request_id) != 0
      && g_strcmp0 (original_request_id, decision_request_id) != 0
      && g_strcmp0 (request->remediation_request_id,
      decision_request_id) != 0
      && ((request->action == WYL_SERVICE_HANDOFF_REMEDIATION_RESUME
          && request->confirmation_version == 0 && !request->confirmed)
      || (request->action ==
          WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE
          && request->confirmation_version == 1 && request->confirmed));
}

static gboolean
    handoff_remediation_state_is_committed
    (WylServiceCredentialOperationState state)
{
  return state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED;
}

static wyrelog_error_t
authority_transaction_finish (wyl_policy_store_t *store,
    WylServiceAuthorityTransaction *transaction, wyrelog_error_t operation)
{
  wyrelog_error_t result = operation;
  wyrelog_error_t terminal =
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
resolve_current_attention (WylHandle *handle,
    const WylServiceCredentialOperationHandoffRemediationRuntime *runtime,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult *out)
{
  WylServiceAuthWriteLease *lease = NULL;
  WylServiceAuthorityTransaction *transaction = NULL;
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle,
      runtime->cancellable, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (lease, handle, &store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_authority_transaction_begin (store, handle,
        lease, &transaction);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_resolve_current_attention_core
        (transaction, store, proof, out);
  if (transaction != NULL)
    rc = authority_transaction_finish (store, transaction, rc);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (rc == WYRELOG_E_OK && release_rc != WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_committed_maintenance_result_clear (out);
  return rc;
}

static wyrelog_error_t
    handoff_remediation_input_from_record
    (const WylServiceCredentialOperationRecord * record,
    const guint8 snapshot_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES],
    const WylServiceCredentialOperationHandoffRemediationRequest * request,
    const gchar * decision_request_id, const gchar * current_actor_subject_id,
    const WylPolicyServiceHandoffCommittedMaintenanceResult * attention,
    wyl_id_t * escrow_id,
    wyl_service_credential_handoff_remediation_input_t * out)
{
  if (record->successor_credential_id == NULL
      || record->successor_generation == 0
      || sodium_is_zero (record->escrow_binding_digest,
          sizeof record->escrow_binding_digest)
      || wyl_id_parse (record->escrow_id, escrow_id) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  *out = (wyl_service_credential_handoff_remediation_input_t) {
    .remediation_request_id =
        request->remediation_request_id,.decision_request_id =
        decision_request_id,.current_actor_subject_id =
        current_actor_subject_id,.audit_id = request->audit_id,.tuple = {
      .original_request_id = record->request_id,
      .escrow_id = escrow_id,
      .successor_credential_id = record->successor_credential_id,
      .successor_issuance_generation = record->successor_generation,
      .original_actor_subject_id = record->actor_subject_id,
    },.action = request->action,.confirmation_version =
        request->confirmation_version,.confirmed =
        request->confirmed,.observed_state =
        (wyl_service_credential_handoff_remediation_journal_state_t)
  record->state,};
  memcpy (out->tuple.binding_digest, record->escrow_binding_digest,
      sizeof out->tuple.binding_digest);
  memcpy (out->journal_snapshot_digest, snapshot_digest,
      sizeof out->journal_snapshot_digest);
  if (handoff_remediation_state_is_committed (record->state)) {
    if (attention == NULL
        || (attention->outcome !=
            WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED
            && attention->outcome !=
            WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED))
      return WYRELOG_E_POLICY;
    out->source_kind =
        WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION;
    out->source_disposition_id = attention->disposition.disposition_id;
    out->source_audit_id = attention->disposition.audit_id;
    out->source_reason = attention->outcome ==
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED ?
        WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED :
        WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED;
    return WYRELOG_E_OK;
  }
  if (record->state !=
      WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED)
    return WYRELOG_E_POLICY;
  WylServiceCredentialOperationState source = 0;
  WylServiceCredentialOperationOarCause cause = 0;
  if (!wyl_service_credential_operation_oar_reason_parse
      (record->terminal_reason, &source, &cause))
    return WYRELOG_E_POLICY;
  out->source_kind =
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED;
  out->oar_source_state =
      (wyl_service_credential_handoff_remediation_journal_state_t) source;
  out->oar_cause =
      (wyl_service_credential_handoff_remediation_oar_cause_t) cause;
  out->resume_target_state = out->oar_source_state;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
    handoff_remediation_input_from_incident
    (const WylServiceCredentialOperationRecord * record,
    const guint8 snapshot_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES],
    const WylServiceCredentialOperationHandoffRemediationRequest * request,
    const gchar * decision_request_id, const gchar * current_actor_subject_id,
    const wyl_service_credential_handoff_remediation_result_t * incident,
    wyl_id_t * escrow_id,
    wyl_service_credential_handoff_remediation_input_t * out)
{
  if (g_strcmp0 (incident->original_request_id, record->request_id) != 0
      || g_strcmp0 (incident->original_actor_subject_id,
          record->actor_subject_id) != 0
      || g_strcmp0 (incident->escrow_id, record->escrow_id) != 0
      || g_strcmp0 (incident->successor_credential_id,
          record->successor_credential_id) != 0
      || incident->successor_issuance_generation !=
      record->successor_generation
      || sodium_memcmp (incident->binding_digest,
          record->escrow_binding_digest,
          sizeof record->escrow_binding_digest) != 0
      || sodium_memcmp (incident->journal_snapshot_digest, snapshot_digest,
          WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES) != 0
      || incident->observed_state !=
      (wyl_service_credential_handoff_remediation_journal_state_t)
      record->state)
    return WYRELOG_E_POLICY;

  WylPolicyServiceHandoffCommittedMaintenanceResult attention = { 0 };
  const WylPolicyServiceHandoffCommittedMaintenanceResult *attention_ptr = NULL;
  if (handoff_remediation_state_is_committed (record->state)) {
    if (incident->source_kind !=
        WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION
        || incident->source_disposition_id == NULL
        || incident->source_audit_id == NULL
        || (incident->source_reason !=
            WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED
            && incident->source_reason !=
            WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED)
        || incident->oar_source_state != 0 || incident->oar_cause != 0
        || incident->resume_target_state != 0)
      return WYRELOG_E_POLICY;
    attention.outcome = incident->source_reason ==
        WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED ?
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED :
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED;
    attention.disposition.disposition_id = incident->source_disposition_id;
    attention.disposition.audit_id = incident->source_audit_id;
    attention_ptr = &attention;
  }

  wyrelog_error_t rc = handoff_remediation_input_from_record (record,
      snapshot_digest, request, decision_request_id,
      current_actor_subject_id, attention_ptr, escrow_id, out);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (out->source_kind != incident->source_kind
      || out->observed_state != incident->observed_state
      || g_strcmp0 (out->source_disposition_id,
          incident->source_disposition_id) != 0
      || g_strcmp0 (out->source_audit_id, incident->source_audit_id) != 0
      || out->source_reason != incident->source_reason
      || out->oar_source_state != incident->oar_source_state
      || out->oar_cause != incident->oar_cause
      || out->resume_target_state != incident->resume_target_state)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static gboolean
    resolved_action_matches_request
    (const wyl_service_credential_handoff_remediation_result_t * result,
    const gchar * original_request_id,
    const WylServiceCredentialOperationHandoffRemediationRequest * request,
    const WylServiceCredentialOperationHandoffRemediationRuntime * runtime,
    const gchar * current_actor_subject_id)
{
  return result->replayed
      && g_strcmp0 (result->original_request_id, original_request_id) == 0
      && g_strcmp0 (result->remediation_request_id,
      request->remediation_request_id) == 0
      && g_strcmp0 (result->decision_request_id,
      runtime->decision_request_id) == 0
      && g_strcmp0 (result->audit_id, request->audit_id) == 0
      && g_strcmp0 (result->current_actor_subject_id,
      current_actor_subject_id) == 0 && result->action == request->action
      && result->confirmation_version == request->confirmation_version
      && result->confirmed == request->confirmed;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_remediate_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * original_request_id,
    const WylServiceCredentialOperationHandoffRemediationRequest * request,
    const WylServiceCredentialOperationHandoffRemediationRuntime * runtime,
    WylServiceCredentialOperationHandoffRemediationResult * out_result)
{
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord checkpointed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyl_service_credential_t old_credential = { 0 };
  wyl_service_credential_handoff_remediation_input_t input = { 0 };
  wyl_service_credential_handoff_remediation_result_t authority = { 0 };
  wyl_service_credential_handoff_remediation_result_t incident = { 0 };
  WylServiceCredentialOperationRemediationProof remediation_proof = { 0 };
  WylPolicyServiceHandoffMaintenanceProof maintenance_proof = { 0 };
  WylPolicyServiceHandoffCommittedMaintenanceResult attention = { 0 };
  g_autofree gchar *session_actor = NULL;
  g_autofree gchar *session_tenant = NULL;
  g_autofree gchar *session_resource_id = NULL;
  wyl_id_t escrow_id;
  guint8 snapshot_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES] = { 0 };
  gboolean locked = FALSE;
  gboolean journal_replayed = FALSE;
  gboolean resolve_existing = FALSE;
  gboolean incident_found = FALSE;
  wyrelog_error_t rc;

  if (out_result != NULL)
    wyl_service_credential_operation_handoff_remediation_result_clear
        (out_result);
  if (handle == NULL || storage == NULL || anchor == NULL || runtime == NULL
      || out_result == NULL || runtime->session == NULL
      || runtime->authenticated_actor_subject_id == NULL
      || !wyl_policy_service_actor_subject_is_valid
      (runtime->authenticated_actor_subject_id)
      || runtime->guard_timestamp < 0 || runtime->guard_loc_class == NULL
      || !wyl_guard_loc_class_is_valid (runtime->guard_loc_class)
      || runtime->guard_risk < 0 || runtime->guard_risk > 100
      || !handoff_remediation_request_is_valid (original_request_id, request,
          runtime->decision_request_id)
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)
      || (runtime->cancellable != NULL
          && !G_IS_CANCELLABLE (runtime->cancellable)))
    return WYRELOG_E_INVALID;
  if (handoff_remediation_cancelled (runtime))
    return WYRELOG_E_BUSY;

  session_actor = wyl_session_dup_username (runtime->session);
  session_tenant = wyl_session_dup_tenant (runtime->session);
  session_resource_id = wyl_session_dup_id_string (runtime->session);
  if (!handoff_remediation_session_is_active_human (runtime->session)
      || session_actor == NULL || session_tenant == NULL
      || session_resource_id == NULL
      || !wyl_policy_service_actor_subject_is_valid (session_actor)
      || g_strcmp0 (session_actor,
          runtime->authenticated_actor_subject_id) != 0)
    return WYRELOG_E_POLICY;

  rc = wyl_service_credential_operation_coordinator_lock_acquire (storage,
      anchor, original_request_id, &lifecycle_lock);
  if (rc != WYRELOG_E_OK)
    goto out;
  locked = TRUE;
  if (handoff_remediation_cancelled (runtime)) {
    rc = WYRELOG_E_BUSY;
    goto out;
  }
  rc = wyl_service_credential_operation_coordinator_load_snapshot (storage,
      anchor, original_request_id, snapshot_digest, &record);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (g_strcmp0 (record.actor_subject_id, session_actor) == 0) {
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

  if (record.last_remediation_action !=
      WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_NONE) {
    if (g_strcmp0 (record.last_remediation_request_id,
            request->remediation_request_id) == 0) {
      resolve_existing = TRUE;
    } else if (record.state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
  }
  if (!resolve_existing) {
    rc = wyl_service_credential_handoff_resolve_remediation_incident (handle,
        original_request_id, snapshot_digest, &incident);
    if (rc == WYRELOG_E_OK)
      incident_found = TRUE;
    else if (rc != WYRELOG_E_NOT_FOUND) {
      goto out;
    } else {
      rc = WYRELOG_E_OK;
    }
  }

  HandoffRemediationAuthorization authorization = {
    .handle = handle,
    .runtime = runtime,
    .current_actor_subject_id = session_actor,
    .session_resource_id = session_resource_id,
    .session_tenant = session_tenant,
  };
  wyl_service_credential_mutation_authorization_t mutation_authorization = {
    .authorize = handoff_remediation_authorize,
    .data = &authorization,
  };
  wyl_service_credential_handoff_remediation_runtime_t remediation_runtime = {
    .authorization = &mutation_authorization,
    .invalidate_credential = runtime->invalidate_credential,
    .invalidation_data = runtime->invalidation_data,
  };

  if (resolve_existing) {
    rc = wyl_service_credential_handoff_resolve_remediation (handle,
        request->remediation_request_id, session_actor, &remediation_runtime,
        &authority);
    if (rc != WYRELOG_E_OK)
      goto out;
    if (!resolved_action_matches_request (&authority, original_request_id,
            request, runtime, session_actor)) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
  } else {
    if (incident_found) {
      rc = handoff_remediation_input_from_incident (&record,
          snapshot_digest, request, runtime->decision_request_id,
          session_actor, &incident, &escrow_id, &input);
      if (rc != WYRELOG_E_OK)
        goto out;
    } else if (handoff_remediation_state_is_committed (record.state)) {
      rc = wyl_service_credential_operation_maintenance_proof_from_record
          (&record, &escrow_id, &maintenance_proof);
      if (rc == WYRELOG_E_OK)
        rc = resolve_current_attention (handle, runtime, &maintenance_proof,
            &attention);
      if (rc != WYRELOG_E_OK)
        goto out;
    }
    if (!incident_found) {
      rc = handoff_remediation_input_from_record (&record, snapshot_digest,
          request, runtime->decision_request_id, session_actor,
          handoff_remediation_state_is_committed (record.state) ? &attention :
          NULL, &escrow_id, &input);
      if (rc != WYRELOG_E_OK)
        goto out;
    }
    rc = wyl_service_credential_handoff_remediate_exact (handle, &input,
        &remediation_runtime, &authority);
    if (rc != WYRELOG_E_OK)
      goto out;
  }

  wyl_service_credential_operation_remediation_proof_from_result (&authority,
      &remediation_proof);
  gint64 now_us = runtime->now_us != NULL ?
      runtime->now_us (runtime->clock_data) : g_get_real_time ();
  now_us = MAX (now_us, MAX (record.updated_at_us, authority.created_at_us));
  if (authority.action == WYL_SERVICE_HANDOFF_REMEDIATION_RESUME)
    rc = wyl_service_credential_operation_coordinator_checkpoint_operator_resume
        (storage, anchor, original_request_id, &remediation_proof, now_us,
        &journal_replayed, &checkpointed);
  else if (authority.action == WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE)
    rc = wyl_service_credential_operation_coordinator_checkpoint_operator_revoke_and_wipe (storage, anchor, original_request_id, &remediation_proof, now_us, &journal_replayed, &checkpointed);
  else
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    goto out;

  out_result->remediation_request_id =
      g_strdup (authority.remediation_request_id);
  out_result->audit_id = g_strdup (authority.audit_id);
  if (out_result->remediation_request_id == NULL
      || out_result->audit_id == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto out;
  }
  out_result->authority_replayed = authority.replayed;
  out_result->journal_replayed = journal_replayed;
  out_result->action = authority.action;
  out_result->outcome = authority.outcome;
  out_result->escrow_outcome = authority.escrow_outcome;
  out_result->created_at_us = authority.created_at_us;
  out_result->source_kind = authority.source_kind;
  out_result->observed_state = authority.observed_state;
  out_result->oar_source_state = authority.oar_source_state;
  out_result->oar_cause = authority.oar_cause;
  out_result->resume_target_state = authority.resume_target_state;
  out_result->source_reason = authority.source_reason;
  out_result->checkpoint_state = checkpointed.state;
  out_result->checkpoint_target_state =
      checkpointed.last_remediation_applied_target_state;
out:
  sodium_memzero (snapshot_digest, sizeof snapshot_digest);
  sodium_memzero (&remediation_proof, sizeof remediation_proof);
  sodium_memzero (&maintenance_proof, sizeof maintenance_proof);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&attention);
  wyl_service_credential_handoff_remediation_result_clear (&incident);
  wyl_service_credential_handoff_remediation_result_clear (&authority);
  wyl_service_credential_operation_record_clear (&checkpointed);
  wyl_service_credential_operation_record_clear (&record);
  wyl_service_credential_clear (&old_credential);
  if (locked)
    wyl_service_credential_operation_coordinator_lock_release (storage,
        anchor, &lifecycle_lock);
  if (rc != WYRELOG_E_OK)
    wyl_service_credential_operation_handoff_remediation_result_clear
        (out_result);
  return rc;
}

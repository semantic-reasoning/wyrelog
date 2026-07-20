/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-cancel-private.h"

#include "auth/service-credential-operation-coordinator-auth-private.h"
#include "auth/service-credential-operation-coordinator-proof-private.h"
#include "auth/service-credential-operation-coordinator-private.h"
#include "policy/store-private.h"
#include "wyrelog/decide.h"
#include "wyl-permission-scope-private.h"
#include "wyl-session-layout-private.h"

#include <sodium.h>
#include <string.h>

#define HANDOFF_MANAGE_ACTION "wr.service_credential.manage"

typedef struct
{
  WylHandle *handle;
  const WylServiceCredentialOperationHandoffCancelRuntime *runtime;
  const gchar *current_actor_subject_id;
  const gchar *session_resource_id;
  const gchar *session_tenant;
} HandoffCancellationAuthorization;

static gboolean
handoff_cancel_session_is_active_human (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
      && session->state == WYL_SESSION_STATE_ACTIVE
      && session->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN;
}

static gboolean
handoff_cancel_session_matches (const HandoffCancellationAuthorization *auth)
{
  g_autofree gchar *username = NULL;
  g_autofree gchar *session_id = NULL;
  g_autofree gchar *tenant = NULL;

  if (!handoff_cancel_session_is_active_human (auth->runtime->session))
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

static gboolean
handoff_cancelled (const WylServiceCredentialOperationHandoffCancelRuntime
    *runtime)
{
  return runtime->cancellable != NULL
      && g_cancellable_is_cancelled (runtime->cancellable);
}

static wyrelog_error_t
handoff_cancel_authorize (gpointer data, const gchar *actor_subject_id)
{
  HandoffCancellationAuthorization *auth = data;
  if (auth == NULL || handoff_cancelled (auth->runtime)
      || g_strcmp0 (actor_subject_id, auth->current_actor_subject_id) != 0
      || !handoff_cancel_session_matches (auth))
    return auth != NULL && handoff_cancelled (auth->runtime) ?
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
  if (rc == WYRELOG_E_OK && handoff_cancelled (auth->runtime))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK && auth->runtime->after_authorization != NULL)
    auth->runtime->after_authorization
        (auth->runtime->authorization_checkpoint_data);
  if (rc == WYRELOG_E_OK && handoff_cancelled (auth->runtime))
    rc = WYRELOG_E_BUSY;
  return rc;
}

static gboolean
handoff_cancel_uuid_is_valid (const gchar *id)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];

  return id != NULL
      && wyl_id_parse (id, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && g_strcmp0 (id, canonical) == 0;
}

static gboolean
handoff_cancel_ids_are_valid (const gchar *original_request_id,
    const WylServiceCredentialOperationHandoffCancelRequest *request,
    const gchar *decision_request_id)
{
  return request != NULL
      && wyl_service_credential_operation_coordinator_request_id_is_valid
      (original_request_id)
      && wyl_service_credential_operation_coordinator_request_id_is_valid
      (request->cancellation_request_id)
      && wyl_service_credential_operation_coordinator_request_id_is_valid
      (decision_request_id)
      && handoff_cancel_uuid_is_valid (request->disposition_id)
      && handoff_cancel_uuid_is_valid (request->audit_id)
      && g_strcmp0 (request->disposition_id, request->audit_id) != 0
      && g_strcmp0 (original_request_id,
      request->cancellation_request_id) != 0
      && g_strcmp0 (original_request_id, decision_request_id) != 0
      && g_strcmp0 (request->cancellation_request_id, decision_request_id) != 0;
}

static gboolean
handoff_cancel_state_is_committed (WylServiceCredentialOperationState state)
{
  return state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED;
}

static wyrelog_error_t
handoff_cancel_input_from_record (const WylServiceCredentialOperationRecord
    *record,
    const WylServiceCredentialOperationHandoffCancelRequest *request,
    const gchar *decision_request_id, const gchar *current_actor_subject_id,
    wyl_id_t *escrow_id,
    wyl_service_credential_handoff_cancellation_input_t *out)
{
  if (!handoff_cancel_state_is_committed (record->state)
      || record->version != WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION
      || record->successor_credential_id == NULL
      || record->successor_generation == 0
      || g_strcmp0 (record->actor_subject_id, current_actor_subject_id) == 0)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_id_parse (record->escrow_id, escrow_id);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;

  *out = (wyl_service_credential_handoff_cancellation_input_t) {
    .cancellation_request_id =
        request->cancellation_request_id,.decision_request_id =
        decision_request_id,.current_actor_subject_id =
        current_actor_subject_id,.disposition_id =
        request->disposition_id,.audit_id = request->audit_id,.tuple = {
      .original_request_id = record->request_id,
      .escrow_id = escrow_id,
      .successor_credential_id = record->successor_credential_id,
      .successor_issuance_generation = record->successor_generation,
      .original_actor_subject_id = record->actor_subject_id,
  },.operation = record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE ?
        WYL_SERVICE_HANDOFF_FENCE_ISSUE :
        WYL_SERVICE_HANDOFF_FENCE_ROTATE,.target_a =
        record->kind ==
        WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE ? record->old_credential_id :
        record->subject_id,.target_b =
        record->kind ==
        WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE ? record->
        tenant_id : NULL,.deadline_at_us = record->expires_at_us,};
  memcpy (out->tuple.binding_digest, record->escrow_binding_digest,
      sizeof out->tuple.binding_digest);
  return wyl_service_credential_operation_handoff_target_digest (record,
      out->target_digest);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_cancel_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * original_request_id,
    const WylServiceCredentialOperationHandoffCancelRequest * request,
    const WylServiceCredentialOperationHandoffCancelRuntime * runtime,
    wyl_service_credential_handoff_cancellation_result_t * out_result)
{
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyl_service_credential_t old_credential = { 0 };
  wyl_service_credential_handoff_cancellation_input_t input = { 0 };
  g_autofree gchar *session_actor = NULL;
  g_autofree gchar *session_tenant = NULL;
  g_autofree gchar *session_resource_id = NULL;
  wyl_id_t escrow_id;
  gboolean locked = FALSE;
  wyrelog_error_t rc;

  if (out_result != NULL)
    wyl_service_credential_handoff_cancellation_result_clear (out_result);
  if (handle == NULL || storage == NULL || anchor == NULL || runtime == NULL
      || out_result == NULL || runtime->session == NULL
      || runtime->authenticated_actor_subject_id == NULL
      || !wyl_policy_service_actor_subject_is_valid
      (runtime->authenticated_actor_subject_id)
      || runtime->guard_timestamp < 0 || runtime->guard_loc_class == NULL
      || !wyl_guard_loc_class_is_valid (runtime->guard_loc_class)
      || runtime->guard_risk < 0 || runtime->guard_risk > 100
      || !handoff_cancel_ids_are_valid (original_request_id, request,
          runtime->decision_request_id)
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)
      || (runtime->cancellable != NULL
          && !G_IS_CANCELLABLE (runtime->cancellable)))
    return WYRELOG_E_INVALID;
  if (handoff_cancelled (runtime))
    return WYRELOG_E_BUSY;

  session_actor = wyl_session_dup_username (runtime->session);
  session_tenant = wyl_session_dup_tenant (runtime->session);
  session_resource_id = wyl_session_dup_id_string (runtime->session);
  if (!handoff_cancel_session_is_active_human (runtime->session)
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
  if (handoff_cancelled (runtime)) {
    rc = WYRELOG_E_BUSY;
    goto out;
  }
  rc = wyl_service_credential_operation_coordinator_load (storage, anchor,
      original_request_id, &record);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (!handoff_cancel_state_is_committed (record.state)) {
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
  rc = handoff_cancel_input_from_record (&record, request,
      runtime->decision_request_id, session_actor, &escrow_id, &input);
  if (rc != WYRELOG_E_OK)
    goto out;

  HandoffCancellationAuthorization authorization = {
    .handle = handle,
    .runtime = runtime,
    .current_actor_subject_id = session_actor,
    .session_resource_id = session_resource_id,
    .session_tenant = session_tenant,
  };
  wyl_service_credential_mutation_authorization_t mutation_authorization = {
    .authorize = handoff_cancel_authorize,
    .data = &authorization,
  };
  wyl_service_credential_handoff_cancellation_runtime_t cancel_runtime = {
    .authorization = &mutation_authorization,
  };
  rc = wyl_service_credential_handoff_claim_cancellation (handle, &input,
      &cancel_runtime, out_result);

out:
  sodium_memzero (&escrow_id, sizeof escrow_id);
  sodium_memzero (&input, sizeof input);
  wyl_service_credential_clear (&old_credential);
  wyl_service_credential_operation_record_clear (&record);
  if (locked)
    wyl_service_credential_operation_coordinator_lock_release (storage,
        anchor, &lifecycle_lock);
  return rc;
}

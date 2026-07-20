/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "service-credential-domain-private.h"

#include <string.h>

#include "wyrelog/wyl-handle-private.h"

static wyrelog_error_t
pin_policy_store (WylHandle *handle, wyl_policy_store_t **out_store)
{
  return wyl_handle_policy_store_pin_current (handle, out_store);
}

typedef struct
{
  WylHandle *handle;
  wyl_policy_store_t *store;
  WylServiceAuthWriteLease *lease;
  WylServiceAuthorityTransaction *transaction;
  WylServiceAuthorityCommitEvidence *evidence;
  gboolean owns_handle_pin;
    wyrelog_error_t (*invalidate_credential) (gpointer data,
      const gchar * credential_id, guint64 generation);
  gpointer invalidation_data;
  const gchar *invalidation_credential_id;
  guint64 invalidation_generation;
} ServiceMutation;

static wyrelog_error_t
service_mutation_begin (WylHandle *handle, ServiceMutation *mutation)
{
  memset (mutation, 0, sizeof *mutation);
  mutation->handle = handle;
  wyrelog_error_t rc = pin_policy_store (handle, &mutation->store);
  if (rc != WYRELOG_E_OK)
    return rc;
  mutation->owns_handle_pin = TRUE;
  rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
      &mutation->lease);
  if (rc != WYRELOG_E_OK)
    return rc;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_mutation_start_transaction (ServiceMutation *mutation)
{
  return wyl_policy_store_service_authority_transaction_begin
      (mutation->store, mutation->handle, mutation->lease,
      &mutation->transaction);
}

static wyrelog_error_t
service_mutation_authorize (ServiceMutation *mutation,
    const wyl_service_credential_mutation_authorization_t *authorization,
    const gchar *actor_subject_id)
{
  if (authorization == NULL)
    return WYRELOG_E_OK;
  if (mutation == NULL || mutation->lease == NULL
      || authorization->authorize == NULL)
    return WYRELOG_E_INVALID;
  return authorization->authorize (authorization->data, actor_subject_id);
}

static wyrelog_error_t
service_mutation_reconcile_operation_fence (ServiceMutation *mutation,
    WylServiceCredentialFenceOperation operation, const gchar *request_id,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *old_credential_id)
{
  if (mutation->evidence == NULL) {
    wyrelog_error_t evidence_rc =
        wyl_policy_store_service_authority_prepare_commit_evidence
        (mutation->transaction, mutation->store, &mutation->evidence);
    if (evidence_rc != WYRELOG_E_OK)
      return evidence_rc;
  }
  WylServiceCredentialFenceResult fence = { 0 };
  wyrelog_error_t rc =
      wyl_policy_store_reconcile_service_credential_operation_fence
      (mutation->transaction, mutation->store, NULL, operation, request_id,
      subject_id, tenant_id, old_credential_id, &fence);
  if (rc == WYRELOG_E_OK
      && fence.state !=
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL)
    rc = WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
service_mutation_finish (ServiceMutation *mutation, wyrelog_error_t operation)
{
  wyrelog_error_t result = operation;
  if (mutation->transaction != NULL) {
    wyrelog_error_t terminal = operation == WYRELOG_E_OK ?
        wyl_policy_store_service_authority_transaction_commit
        (mutation->transaction) :
        wyl_policy_store_service_authority_transaction_rollback
        (mutation->transaction);
    if (operation == WYRELOG_E_OK)
      result = terminal;
    else if (terminal != WYRELOG_E_OK)
      result = terminal;
    if (wyl_policy_store_service_authority_transaction_is_poisoned
        (mutation->store)) {
      wyrelog_error_t abort_rc =
          wyl_policy_store_service_authority_transaction_abort
          (mutation->transaction);
      if (abort_rc != WYRELOG_E_OK)
        result = abort_rc;
    }
    wyl_policy_store_service_authority_transaction_free (mutation->transaction);
    mutation->transaction = NULL;
  }
  if (result == WYRELOG_E_OK && mutation->invalidate_credential != NULL) {
    result = mutation->invalidate_credential (mutation->invalidation_data,
        mutation->invalidation_credential_id,
        mutation->invalidation_generation);
    if (result != WYRELOG_E_OK && mutation->lease != NULL)
      (void) wyl_service_auth_write_lease_mark_unavailable (mutation->lease,
          mutation->handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT);
  }
  if (mutation->evidence != NULL) {
    wyl_policy_store_service_authority_commit_evidence_unref
        (mutation->evidence);
    mutation->evidence = NULL;
  }
  if (mutation->lease != NULL) {
    wyrelog_error_t release_rc =
        wyl_service_auth_write_lease_release (mutation->lease);
    if (result == WYRELOG_E_OK && release_rc != WYRELOG_E_OK)
      result = release_rc;
    wyl_service_auth_write_lease_free (mutation->lease);
    mutation->lease = NULL;
  }
  if (mutation->owns_handle_pin) {
    wyl_handle_policy_store_unpin (mutation->handle, mutation->store);
    mutation->owns_handle_pin = FALSE;
  }
  return result;
}

void
wyl_service_principal_clear (wyl_service_principal_t *principal)
{
  if (principal == NULL)
    return;
  g_free (principal->subject_id);
  g_free (principal->display_name);
  g_free (principal->state);
  g_free (principal->created_by);
  g_free (principal->disabled_by);
  memset (principal, 0, sizeof (*principal));
}

static void
copy_principal (const wyl_policy_service_principal_info_t *source,
    wyl_service_principal_t *target)
{
  wyl_service_principal_clear (target);
  target->subject_id = g_strdup (source->subject_id);
  target->display_name = g_strdup (source->display_name);
  target->state = g_strdup (source->state);
  target->generation = source->generation;
  target->created_by = g_strdup (source->created_by);
  target->created_at_us = source->created_at_us;
  target->updated_at_us = source->updated_at_us;
  target->disabled_by = g_strdup (source->disabled_by);
  target->disabled_at_us = source->disabled_at_us;
}

static wyrelog_error_t
finish_principal_result (wyrelog_error_t rc,
    wyl_policy_service_principal_info_t *stored, wyl_service_principal_t *out)
{
  if (rc == WYRELOG_E_OK)
    copy_principal (stored, out);
  wyl_policy_service_principal_info_clear (stored);
  return rc;
}

wyrelog_error_t
wyl_service_principal_create (WylHandle *handle, const gchar *subject_id,
    const gchar *display_name, const gchar *actor_subject_id,
    const gchar *request_id, wyl_service_principal_t *out)
{
  if (out != NULL)
    wyl_service_principal_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  wyl_policy_service_principal_info_t stored = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_create_service_principal_core
        (mutation.transaction, mutation.store, subject_id, display_name,
        actor_subject_id, request_id, &stored);
  rc = service_mutation_finish (&mutation, rc);
  return finish_principal_result (rc, &stored, out);
}

wyrelog_error_t
wyl_service_principal_get (WylHandle *handle, const gchar *subject_id,
    wyl_service_principal_t *out)
{
  if (out != NULL)
    wyl_service_principal_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  wyl_policy_service_principal_info_t stored = { 0 };
  wyrelog_error_t rc = wyl_policy_store_lookup_service_principal
      (wyl_handle_get_policy_store (handle), subject_id, &stored);
  return finish_principal_result (rc, &stored, out);
}

typedef struct
{
  wyl_service_principal_cb cb;
  gpointer user_data;
} PrincipalForeach;

static wyrelog_error_t
foreach_principal_adapter (const wyl_policy_service_principal_info_t *stored,
    gpointer user_data)
{
  PrincipalForeach *foreach = user_data;
  wyl_service_principal_t principal = { 0 };
  copy_principal (stored, &principal);
  wyrelog_error_t rc = foreach->cb (&principal, foreach->user_data);
  wyl_service_principal_clear (&principal);
  return rc;
}

wyrelog_error_t
wyl_service_principal_foreach (WylHandle *handle, wyl_service_principal_cb cb,
    gpointer user_data)
{
  if (handle == NULL || cb == NULL)
    return WYRELOG_E_INVALID;
  PrincipalForeach foreach = { cb, user_data };
  return wyl_policy_store_foreach_service_principal
      (wyl_handle_get_policy_store (handle), foreach_principal_adapter,
      &foreach);
}

wyrelog_error_t
wyl_service_principal_disable (WylHandle *handle, const gchar *subject_id,
    const gchar *actor_subject_id, const gchar *request_id,
    wyl_service_principal_t *out)
{
  if (out != NULL)
    wyl_service_principal_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  wyl_policy_service_principal_info_t stored = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_disable_service_principal_core
        (mutation.transaction, mutation.store, subject_id, actor_subject_id,
        request_id, &stored);
  rc = service_mutation_finish (&mutation, rc);
  return finish_principal_result (rc, &stored, out);
}

void
wyl_service_credential_clear (wyl_service_credential_t *credential)
{
  if (credential == NULL)
    return;
  g_free (credential->credential_id);
  g_free (credential->subject_id);
  g_free (credential->tenant_id);
  g_free (credential->state);
  g_free (credential->created_by);
  g_free (credential->revoked_by);
  g_free (credential->rotated_from_id);
  memset (credential, 0, sizeof (*credential));
}

void wyl_service_credential_issue_result_clear
    (wyl_service_credential_issue_result_t * result)
{
  if (result == NULL)
    return;
  wyl_service_credential_clear (&result->credential);
  wyl_service_credential_secret_clear (&result->secret);
}

void
wyl_service_credential_handoff_clear (wyl_service_credential_handoff_t *handoff)
{
  if (handoff == NULL)
    return;
  g_free (handoff->operation);
  g_free (handoff->request_id);
  g_free (handoff->actor_subject_id);
  g_free (handoff->credential_id);
  memset (handoff, 0, sizeof *handoff);
}

void wyl_service_credential_handoff_result_clear
    (wyl_service_credential_handoff_result_t * result)
{
  if (result == NULL)
    return;
  wyl_service_credential_clear (&result->credential);
  wyl_service_credential_handoff_clear (&result->handoff);
}

static void
copy_credential (const wyl_policy_service_credential_info_t *source,
    wyl_service_credential_t *target)
{
  wyl_service_credential_clear (target);
  target->credential_id = g_strdup (source->credential_id);
  target->credential_format_version = source->credential_format_version;
  target->subject_id = g_strdup (source->subject_id);
  target->tenant_id = g_strdup (source->tenant_id);
  target->generation = source->generation;
  target->state = g_strdup (source->state);
  target->created_by = g_strdup (source->created_by);
  target->created_at_us = source->created_at_us;
  target->updated_at_us = source->updated_at_us;
  target->expires_at_us = source->expires_at_us;
  target->last_used_at_us = source->last_used_at_us;
  target->revoked_by = g_strdup (source->revoked_by);
  target->revoked_at_us = source->revoked_at_us;
  target->rotated_from_id = g_strdup (source->rotated_from_id);
}

static void
copy_handoff (const wyl_policy_service_handoff_escrow_info_t *source,
    wyl_service_credential_handoff_t *target)
{
  wyl_service_credential_handoff_clear (target);
  target->escrow_id = source->escrow_id;
  target->operation = g_strdup (source->operation);
  target->request_id = g_strdup (source->request_id);
  target->actor_subject_id = g_strdup (source->actor_subject_id);
  memcpy (target->target_digest, source->target_digest,
      sizeof target->target_digest);
  target->credential_id = g_strdup (source->credential_id);
  target->credential_generation = source->credential_generation;
  target->deadline_at_us = source->deadline_at_us;
  memcpy (target->binding_digest, source->binding_digest,
      sizeof target->binding_digest);
}

static wyrelog_error_t
service_mutation_precheck_handoff_fence (ServiceMutation *mutation,
    WylServiceCredentialFenceOperation operation, const gchar *request_id,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *old_credential_id, gboolean *out_replay)
{
  *out_replay = FALSE;
  WylServiceCredentialFenceResult fence = { 0 };
  wyrelog_error_t rc =
      wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (mutation->store, NULL, operation, request_id, subject_id, tenant_id,
      old_credential_id, &fence);
  if (rc == WYRELOG_E_NOT_FOUND)
    return WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK)
    return rc;
  if (fence.state != WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED)
    return WYRELOG_E_POLICY;
  *out_replay = TRUE;
  return WYRELOG_E_OK;
}

static wyl_policy_service_handoff_request_t
policy_handoff_request (const wyl_service_credential_handoff_request_t *handoff)
{
  return (wyl_policy_service_handoff_request_t) {
  .escrow_id = handoff != NULL ? handoff->escrow_id : NULL,.target_digest =
        handoff != NULL ? handoff->target_digest : NULL,.deadline_at_us =
        handoff != NULL ? handoff->deadline_at_us : 0,};
}

static gboolean
    service_handoff_request_valid
    (const wyl_service_credential_handoff_request_t * handoff)
{
  if (handoff == NULL || handoff->escrow_id == NULL
      || handoff->target_digest == NULL || handoff->deadline_at_us <= 0)
    return FALSE;
  gchar formatted[WYL_ID_STRING_BUF];
  return wyl_id_format (handoff->escrow_id, formatted, sizeof formatted)
      == WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_credential_issue (WylHandle *handle, const gchar *subject_id,
    const gchar *tenant_id, const gchar *actor_subject_id,
    const gchar *request_id, gint64 expires_at_us,
    wyl_service_credential_issue_result_t *out)
{
  return wyl_service_credential_issue_with_runtime (handle, subject_id,
      tenant_id, actor_subject_id, request_id, expires_at_us, NULL, out);
}

wyrelog_error_t
wyl_service_credential_issue_with_runtime (WylHandle *handle,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *actor_subject_id, const gchar *request_id,
    gint64 expires_at_us, const wyl_service_credential_issue_runtime_t *runtime,
    wyl_service_credential_issue_result_t *out)
{
  if (out != NULL)
    wyl_service_credential_issue_result_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  wyl_policy_service_credential_info_t stored = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_authorize (&mutation,
        runtime != NULL ? runtime->authorization : NULL, actor_subject_id);
  if (rc == WYRELOG_E_OK) {
    WylServiceCredentialFenceResult fence = { 0 };
    rc = wyl_policy_store_precheck_service_credential_operation_fence
        (mutation.store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
        request_id, subject_id, tenant_id, NULL, &fence);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    else if (rc == WYRELOG_E_NOT_FOUND)
      rc = WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_ensure_service_cvk_for_issuance (mutation.store,
        &cvk, &cvk_len);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_reconcile_operation_fence (&mutation,
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, request_id, subject_id,
        tenant_id, NULL);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_issue_service_credential_core
        (mutation.transaction, mutation.store, subject_id, tenant_id,
        actor_subject_id, request_id, expires_at_us,
        runtime != NULL ? runtime->credential_runtime : NULL, cvk, cvk_len,
        &stored, &secret);
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK) {
    copy_credential (&stored, &out->credential);
    out->secret = secret;
    secret = NULL;
  }
  wyl_service_credential_secret_clear (&secret);
  wyl_policy_service_credential_info_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_issue_handoff_with_runtime (WylHandle *handle,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *actor_subject_id, const gchar *request_id,
    gint64 expires_at_us,
    const wyl_service_credential_handoff_request_t *handoff,
    const wyl_service_credential_issue_runtime_t *runtime,
    wyl_service_credential_handoff_result_t *out)
{
  if (out != NULL)
    wyl_service_credential_handoff_result_clear (out);
  if (handle == NULL || !service_handoff_request_valid (handoff)
      || out == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  wyl_policy_service_credential_info_t stored = { 0 };
  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  gboolean replay = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_authorize (&mutation,
        runtime != NULL ? runtime->authorization : NULL, actor_subject_id);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_precheck_handoff_fence (&mutation,
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, request_id, subject_id,
        tenant_id, NULL, &replay);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_ensure_service_cvk_for_issuance (mutation.store,
        &cvk, &cvk_len);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK && !replay)
    rc = service_mutation_reconcile_operation_fence (&mutation,
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, request_id, subject_id,
        tenant_id, NULL);
  wyl_policy_service_handoff_request_t policy_handoff =
      policy_handoff_request (handoff);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_issue_service_credential_handoff_core
        (mutation.transaction, mutation.store, subject_id, tenant_id,
        actor_subject_id, request_id, expires_at_us,
        runtime != NULL ? runtime->credential_runtime : NULL, cvk, cvk_len,
        &policy_handoff, &stored, &escrow);
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK) {
    copy_credential (&stored, &out->credential);
    copy_handoff (&escrow, &out->handoff);
  }
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
  wyl_policy_service_credential_info_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_get (WylHandle *handle, const gchar *credential_id,
    wyl_service_credential_t *out)
{
  if (out != NULL)
    wyl_service_credential_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  wyl_policy_service_credential_info_t stored = { 0 };
  wyrelog_error_t rc = wyl_policy_store_lookup_service_credential_by_id
      (wyl_handle_get_policy_store (handle), credential_id, &stored);
  if (rc == WYRELOG_E_OK)
    copy_credential (&stored, out);
  wyl_policy_service_credential_info_clear (&stored);
  return rc;
}

typedef struct
{
  wyl_service_credential_cb cb;
  gpointer user_data;
} CredentialForeach;

static wyrelog_error_t
foreach_credential_adapter (const wyl_policy_service_credential_info_t *stored,
    gpointer user_data)
{
  CredentialForeach *foreach = user_data;
  wyl_service_credential_t credential = { 0 };
  copy_credential (stored, &credential);
  wyrelog_error_t rc = foreach->cb (&credential, foreach->user_data);
  wyl_service_credential_clear (&credential);
  return rc;
}

wyrelog_error_t
wyl_service_credential_foreach (WylHandle *handle, const gchar *subject_id,
    const gchar *tenant_id, wyl_service_credential_cb cb, gpointer user_data)
{
  if (handle == NULL || cb == NULL)
    return WYRELOG_E_INVALID;
  CredentialForeach foreach = { cb, user_data };
  return wyl_policy_store_foreach_service_credential
      (wyl_handle_get_policy_store (handle), subject_id, tenant_id,
      foreach_credential_adapter, &foreach);
}

wyrelog_error_t
wyl_service_credential_verify_authoritative_with_runtime (WylHandle *handle,
    const gchar *credential_id, const gchar *presented_secret,
    gsize presented_secret_len,
    const wyl_service_credential_verify_runtime_t *runtime,
    gboolean *out_authenticated)
{
  if (out_authenticated != NULL)
    *out_authenticated = FALSE;
  if (handle == NULL || out_authenticated == NULL)
    return WYRELOG_E_INVALID;
  return wyl_policy_store_verify_service_credential_by_id
      (wyl_handle_get_policy_store (handle), credential_id, presented_secret,
      presented_secret_len, runtime != NULL ? runtime->before_gate : NULL,
      runtime != NULL ? runtime->now_us : NULL,
      runtime != NULL ? runtime->data : NULL,
      runtime != NULL ? runtime->credential_runtime : NULL, out_authenticated);
}

wyrelog_error_t
wyl_service_credential_verify_authoritative (WylHandle *handle,
    const gchar *credential_id, const gchar *presented_secret,
    gsize presented_secret_len, gboolean *out_authenticated)
{
  return wyl_service_credential_verify_authoritative_with_runtime (handle,
      credential_id, presented_secret, presented_secret_len, NULL,
      out_authenticated);
}

wyrelog_error_t
wyl_service_credential_revoke_with_runtime (WylHandle *handle,
    const gchar *credential_id,
    const gchar *actor_subject_id, const gchar *request_id,
    const wyl_service_credential_revoke_runtime_t *runtime,
    wyl_service_credential_t *out)
{
  if (out != NULL)
    wyl_service_credential_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  if (rc == WYRELOG_E_OK && runtime != NULL) {
    mutation.invalidate_credential = runtime->invalidate_credential;
    mutation.invalidation_data = runtime->invalidation_data;
  }
  wyl_policy_service_credential_info_t stored = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_revoke_service_credential_core
        (mutation.transaction, mutation.store, credential_id,
        actor_subject_id, request_id, &stored);
  if (rc == WYRELOG_E_OK && mutation.invalidate_credential != NULL
      && stored.generation > 0) {
    mutation.invalidation_credential_id = stored.credential_id;
    mutation.invalidation_generation = stored.generation - 1;
  }
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK)
    copy_credential (&stored, out);
  wyl_policy_service_credential_info_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_revoke (WylHandle *handle, const gchar *credential_id,
    const gchar *actor_subject_id, const gchar *request_id,
    wyl_service_credential_t *out)
{
  return wyl_service_credential_revoke_with_runtime (handle, credential_id,
      actor_subject_id, request_id, NULL, out);
}

void wyl_service_credential_handoff_disposition_result_clear
    (wyl_service_credential_handoff_disposition_result_t * result)
{
  if (result == NULL)
    return;
  g_clear_pointer (&result->disposition_id, g_free);
  g_clear_pointer (&result->audit_id, g_free);
  memset (result, 0, sizeof *result);
}

void wyl_service_credential_handoff_cancellation_result_clear
    (wyl_service_credential_handoff_cancellation_result_t * result)
{
  if (result == NULL)
    return;
  g_clear_pointer (&result->disposition_id, g_free);
  g_clear_pointer (&result->audit_id, g_free);
  memset (result, 0, sizeof *result);
}

void wyl_service_credential_handoff_remediation_result_clear
    (wyl_service_credential_handoff_remediation_result_t * result)
{
  if (result == NULL)
    return;
  g_clear_pointer (&result->audit_id, g_free);
  g_clear_pointer (&result->remediation_request_id, g_free);
  g_clear_pointer (&result->decision_request_id, g_free);
  g_clear_pointer (&result->current_actor_subject_id, g_free);
  g_clear_pointer (&result->original_request_id, g_free);
  g_clear_pointer (&result->original_actor_subject_id, g_free);
  g_clear_pointer (&result->source_disposition_id, g_free);
  g_clear_pointer (&result->source_audit_id, g_free);
  g_clear_pointer (&result->revoke_event_request_id, g_free);
  g_clear_pointer (&result->revoke_event_actor_subject_id, g_free);
  memset (result, 0, sizeof *result);
}

static void
    service_handoff_translate_exact_tuple
    (const wyl_service_credential_handoff_exact_tuple_t * source,
    WylPolicyServiceHandoffExactTuple * target)
{
  memset (target, 0, sizeof *target);
  target->original_request_id = source->original_request_id;
  target->escrow_id = source->escrow_id;
  memcpy (target->binding_digest, source->binding_digest,
      sizeof target->binding_digest);
  target->successor_credential_id = source->successor_credential_id;
  target->successor_issuance_generation = source->successor_issuance_generation;
  target->original_actor_subject_id = source->original_actor_subject_id;
}

static void
    service_handoff_translate_disposition
    (const wyl_service_credential_handoff_disposition_input_t * source,
    WylPolicyServiceHandoffDispositionInput * target)
{
  memset (target, 0, sizeof *target);
  target->disposition_id = source->disposition_id;
  target->audit_id = source->audit_id;
  service_handoff_translate_exact_tuple (&source->tuple, &target->tuple);
  target->actor_subject_id = source->actor_subject_id;
  target->reason = (WylPolicyServiceHandoffDispositionReason) source->reason;
  target->outcome = (WylPolicyServiceHandoffDispositionOutcome) source->outcome;
}

static wyrelog_error_t
service_handoff_run_disposition (WylHandle *handle,
    const wyl_service_credential_handoff_disposition_input_t *input,
    wyl_service_credential_handoff_disposition_result_t *out_result)
{
  if (out_result != NULL)
    wyl_service_credential_handoff_disposition_result_clear (out_result);
  if (handle == NULL || input == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  WylPolicyServiceHandoffDispositionInput stored_input;
  WylPolicyServiceHandoffNoCommitEvidence no_commit_evidence = { 0 };
  WylPolicyServiceHandoffDispositionResult stored = { 0 };
  service_handoff_translate_disposition (input, &stored_input);
  if (input->no_commit_evidence != NULL) {
    no_commit_evidence.operation = (WylPolicyServiceHandoffFenceOperation)
        input->no_commit_evidence->operation;
    no_commit_evidence.target_a = input->no_commit_evidence->target_a;
    no_commit_evidence.target_b = input->no_commit_evidence->target_b;
    stored_input.no_commit_evidence = &no_commit_evidence;
  }
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_record_service_handoff_disposition_core
        (mutation.transaction, mutation.store, &stored_input, &stored);
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK) {
    out_result->replayed = stored.replayed;
    out_result->disposition_id = g_steal_pointer (&stored.disposition_id);
    out_result->audit_id = g_steal_pointer (&stored.audit_id);
  }
  wyl_policy_service_handoff_disposition_result_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_handoff_record_disposition (WylHandle *handle,
    const wyl_service_credential_handoff_disposition_input_t *input,
    wyl_service_credential_handoff_disposition_result_t *out_result)
{
  return service_handoff_run_disposition (handle, input, out_result);
}

wyrelog_error_t
wyl_service_credential_handoff_record_not_committed (WylHandle *handle,
    const wyl_service_credential_handoff_disposition_input_t *input,
    wyl_service_credential_handoff_disposition_result_t *out_result)
{
  if (out_result != NULL)
    wyl_service_credential_handoff_disposition_result_clear (out_result);
  if (handle == NULL || input == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  wyl_service_credential_handoff_disposition_input_t exact = *input;
  exact.reason = WYL_SERVICE_HANDOFF_DISPOSITION_NOT_COMMITTED;
  exact.outcome = WYL_SERVICE_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  WylPolicyServiceHandoffDispositionInput stored_input;
  WylPolicyServiceHandoffNoCommitEvidence evidence = { 0 };
  WylPolicyServiceHandoffDispositionResult stored = { 0 };
  service_handoff_translate_disposition (&exact, &stored_input);
  if (exact.no_commit_evidence != NULL) {
    evidence.operation = (WylPolicyServiceHandoffFenceOperation)
        exact.no_commit_evidence->operation;
    evidence.target_a = exact.no_commit_evidence->target_a;
    evidence.target_b = exact.no_commit_evidence->target_b;
    stored_input.no_commit_evidence = &evidence;
  }
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_record_service_handoff_not_committed_core
        (mutation.transaction, mutation.store, &stored_input, &stored);
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK) {
    out_result->replayed = stored.replayed;
    out_result->disposition_id = g_steal_pointer (&stored.disposition_id);
    out_result->audit_id = g_steal_pointer (&stored.audit_id);
  }
  wyl_policy_service_handoff_disposition_result_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_handoff_claim_cancellation (WylHandle *handle,
    const wyl_service_credential_handoff_cancellation_input_t *input,
    const wyl_service_credential_handoff_cancellation_runtime_t *runtime,
    wyl_service_credential_handoff_cancellation_result_t *out_result)
{
  if (out_result != NULL)
    wyl_service_credential_handoff_cancellation_result_clear (out_result);
  if (handle == NULL || input == NULL || runtime == NULL
      || runtime->authorization == NULL
      || runtime->authorization->authorize == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  WylPolicyServiceHandoffCancellationInput stored_input = {
    .cancellation_request_id = input->cancellation_request_id,
    .decision_request_id = input->decision_request_id,
    .current_actor_subject_id = input->current_actor_subject_id,
    .disposition_id = input->disposition_id,
    .audit_id = input->audit_id,
    .observation =
        (WylPolicyServiceHandoffCancellationObservation) input->observation,
    .operation = (WylPolicyServiceHandoffFenceOperation) input->operation,
    .target_a = input->target_a,
    .target_b = input->target_b,
    .deadline_at_us = input->deadline_at_us,
  };
  service_handoff_translate_exact_tuple (&input->tuple, &stored_input.tuple);
  memcpy (stored_input.target_digest, input->target_digest,
      sizeof stored_input.target_digest);
  WylPolicyServiceHandoffCancellationResult stored = { 0 };
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_authorize (&mutation, runtime->authorization,
        input->current_actor_subject_id);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK
      && input->observation ==
      WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_PREPARED)
    rc = wyl_policy_store_service_authority_prepare_commit_evidence
        (mutation.transaction, mutation.store, &evidence);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_claim_cancellation_core
        (mutation.transaction, mutation.store, &stored_input, &stored);
  rc = service_mutation_finish (&mutation, rc);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  if (rc == WYRELOG_E_OK) {
    out_result->replayed = stored.replayed;
    out_result->outcome =
        (wyl_service_credential_handoff_cancellation_outcome_t)
        stored.outcome;
    out_result->disposition_id = g_steal_pointer (&stored.disposition_id);
    out_result->audit_id = g_steal_pointer (&stored.audit_id);
    out_result->created_at_us = stored.created_at_us;
    g_strlcpy (out_result->successor_credential_id,
        stored.successor_credential_id,
        sizeof out_result->successor_credential_id);
    out_result->successor_issuance_generation =
        stored.successor_issuance_generation;
    memcpy (out_result->binding_digest, stored.binding_digest,
        sizeof out_result->binding_digest);
  }
  wyl_policy_service_handoff_cancellation_result_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_handoff_remediate_exact (WylHandle *handle,
    const wyl_service_credential_handoff_remediation_input_t *input,
    const wyl_service_credential_handoff_remediation_runtime_t *runtime,
    wyl_service_credential_handoff_remediation_result_t *out_result)
{
  if (out_result != NULL)
    wyl_service_credential_handoff_remediation_result_clear (out_result);
  if (handle == NULL || input == NULL || runtime == NULL
      || runtime->authorization == NULL
      || runtime->authorization->authorize == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  if (rc == WYRELOG_E_OK) {
    mutation.invalidate_credential = runtime->invalidate_credential;
    mutation.invalidation_data = runtime->invalidation_data;
  }
  WylPolicyServiceHandoffRemediationInput stored_input = {
    .remediation_request_id = input->remediation_request_id,
    .decision_request_id = input->decision_request_id,
    .current_actor_subject_id = input->current_actor_subject_id,
    .audit_id = input->audit_id,
    .action = (WylPolicyServiceHandoffRemediationAction) input->action,
    .confirmation_version = input->confirmation_version,
    .confirmed = input->confirmed,
    .source_kind = (WylPolicyServiceHandoffRemediationSourceKind)
        input->source_kind,
    .observed_state = (WylPolicyServiceHandoffRemediationJournalState)
        input->observed_state,
    .source_disposition_id = input->source_disposition_id,
    .source_audit_id = input->source_audit_id,
    .source_reason = (WylPolicyServiceHandoffDispositionReason)
        input->source_reason,
    .oar_source_state = (WylPolicyServiceHandoffRemediationJournalState)
        input->oar_source_state,
    .oar_cause = (WylPolicyServiceHandoffRemediationOarCause) input->oar_cause,
    .resume_target_state = (WylPolicyServiceHandoffRemediationJournalState)
        input->resume_target_state,
  };
  memcpy (stored_input.journal_snapshot_digest,
      input->journal_snapshot_digest,
      sizeof stored_input.journal_snapshot_digest);
  service_handoff_translate_exact_tuple (&input->tuple, &stored_input.tuple);
  WylPolicyServiceHandoffRemediationResult stored = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_authorize (&mutation, runtime->authorization,
        input->current_actor_subject_id);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_remediate_service_handoff_exact_core
        (mutation.transaction, mutation.store, &stored_input, &stored);
  if (rc == WYRELOG_E_OK && mutation.invalidate_credential != NULL
      && stored.invalidation_generation > 0) {
    mutation.invalidation_credential_id = input->tuple.successor_credential_id;
    mutation.invalidation_generation = stored.invalidation_generation;
  }
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK) {
    out_result->replayed = stored.replayed;
    out_result->revoked_now = stored.revoked_now;
    out_result->outcome =
        (wyl_service_credential_handoff_remediation_outcome_t) stored.outcome;
    out_result->escrow_outcome =
        (wyl_service_credential_handoff_remediation_escrow_outcome_t)
        stored.escrow_outcome;
    out_result->invalidation_generation = stored.invalidation_generation;
    out_result->credential_generation_after =
        stored.credential_generation_after;
    out_result->revoke_event_id = stored.revoke_event_id;
    out_result->revoke_event_generation = stored.revoke_event_generation;
    out_result->revoke_event_request_id =
        g_steal_pointer (&stored.revoke_event_request_id);
    out_result->revoke_event_actor_subject_id =
        g_steal_pointer (&stored.revoke_event_actor_subject_id);
    out_result->revoke_event_created_at_us = stored.revoke_event_created_at_us;
    out_result->remediation_request_id =
        g_steal_pointer (&stored.remediation_request_id);
    out_result->action =
        (wyl_service_credential_handoff_remediation_action_t) stored.action;
    out_result->confirmation_version = stored.confirmation_version;
    out_result->confirmed = stored.confirmed;
    out_result->created_at_us = stored.created_at_us;
    out_result->source_kind =
        (wyl_service_credential_handoff_remediation_source_kind_t)
        stored.source_kind;
    memcpy (out_result->journal_snapshot_digest,
        stored.journal_snapshot_digest,
        sizeof out_result->journal_snapshot_digest);
    memcpy (out_result->request_fingerprint, stored.request_fingerprint,
        sizeof out_result->request_fingerprint);
    out_result->observed_state =
        (wyl_service_credential_handoff_remediation_journal_state_t)
        stored.observed_state;
    out_result->oar_source_state =
        (wyl_service_credential_handoff_remediation_journal_state_t)
        stored.oar_source_state;
    out_result->oar_cause =
        (wyl_service_credential_handoff_remediation_oar_cause_t)
        stored.oar_cause;
    out_result->resume_target_state =
        (wyl_service_credential_handoff_remediation_journal_state_t)
        stored.resume_target_state;
    out_result->source_reason =
        (wyl_service_credential_handoff_disposition_reason_t)
        stored.source_reason;
    out_result->decision_request_id =
        g_steal_pointer (&stored.decision_request_id);
    out_result->current_actor_subject_id =
        g_steal_pointer (&stored.current_actor_subject_id);
    out_result->original_request_id =
        g_steal_pointer (&stored.original_request_id);
    out_result->original_actor_subject_id =
        g_steal_pointer (&stored.original_actor_subject_id);
    out_result->source_disposition_id =
        g_steal_pointer (&stored.source_disposition_id);
    out_result->source_audit_id = g_steal_pointer (&stored.source_audit_id);
    g_strlcpy (out_result->escrow_id, stored.escrow_id,
        sizeof out_result->escrow_id);
    memcpy (out_result->binding_digest, stored.binding_digest,
        sizeof out_result->binding_digest);
    g_strlcpy (out_result->successor_credential_id,
        stored.successor_credential_id,
        sizeof out_result->successor_credential_id);
    out_result->successor_issuance_generation =
        stored.successor_issuance_generation;
    out_result->audit_id = g_steal_pointer (&stored.audit_id);
  }
  wyl_policy_service_handoff_remediation_result_clear (&stored);
  return rc;
}

static void
    service_handoff_take_remediation_result
    (WylPolicyServiceHandoffRemediationResult * stored,
    wyl_service_credential_handoff_remediation_result_t * out)
{
  out->replayed = stored->replayed;
  out->revoked_now = stored->revoked_now;
  out->outcome =
      (wyl_service_credential_handoff_remediation_outcome_t) stored->outcome;
  out->escrow_outcome =
      (wyl_service_credential_handoff_remediation_escrow_outcome_t)
      stored->escrow_outcome;
  out->invalidation_generation = stored->invalidation_generation;
  out->credential_generation_after = stored->credential_generation_after;
  out->revoke_event_id = stored->revoke_event_id;
  out->revoke_event_generation = stored->revoke_event_generation;
  out->revoke_event_request_id =
      g_steal_pointer (&stored->revoke_event_request_id);
  out->revoke_event_actor_subject_id =
      g_steal_pointer (&stored->revoke_event_actor_subject_id);
  out->revoke_event_created_at_us = stored->revoke_event_created_at_us;
  out->remediation_request_id =
      g_steal_pointer (&stored->remediation_request_id);
  out->action =
      (wyl_service_credential_handoff_remediation_action_t) stored->action;
  out->confirmation_version = stored->confirmation_version;
  out->confirmed = stored->confirmed;
  out->created_at_us = stored->created_at_us;
  out->source_kind = (wyl_service_credential_handoff_remediation_source_kind_t)
      stored->source_kind;
  memcpy (out->journal_snapshot_digest, stored->journal_snapshot_digest,
      sizeof out->journal_snapshot_digest);
  memcpy (out->request_fingerprint, stored->request_fingerprint,
      sizeof out->request_fingerprint);
  out->observed_state =
      (wyl_service_credential_handoff_remediation_journal_state_t)
      stored->observed_state;
  out->oar_source_state =
      (wyl_service_credential_handoff_remediation_journal_state_t)
      stored->oar_source_state;
  out->oar_cause = (wyl_service_credential_handoff_remediation_oar_cause_t)
      stored->oar_cause;
  out->resume_target_state =
      (wyl_service_credential_handoff_remediation_journal_state_t)
      stored->resume_target_state;
  out->source_reason = (wyl_service_credential_handoff_disposition_reason_t)
      stored->source_reason;
  out->decision_request_id = g_steal_pointer (&stored->decision_request_id);
  out->current_actor_subject_id =
      g_steal_pointer (&stored->current_actor_subject_id);
  out->original_request_id = g_steal_pointer (&stored->original_request_id);
  out->original_actor_subject_id =
      g_steal_pointer (&stored->original_actor_subject_id);
  out->source_disposition_id = g_steal_pointer (&stored->source_disposition_id);
  out->source_audit_id = g_steal_pointer (&stored->source_audit_id);
  g_strlcpy (out->escrow_id, stored->escrow_id, sizeof out->escrow_id);
  memcpy (out->binding_digest, stored->binding_digest,
      sizeof out->binding_digest);
  g_strlcpy (out->successor_credential_id, stored->successor_credential_id,
      sizeof out->successor_credential_id);
  out->successor_issuance_generation = stored->successor_issuance_generation;
  out->audit_id = g_steal_pointer (&stored->audit_id);
}

wyrelog_error_t
wyl_service_credential_handoff_resolve_remediation (WylHandle *handle,
    const gchar *remediation_request_id, const gchar *current_actor_subject_id,
    const wyl_service_credential_handoff_remediation_runtime_t *runtime,
    wyl_service_credential_handoff_remediation_result_t *out_result)
{
  if (out_result != NULL)
    wyl_service_credential_handoff_remediation_result_clear (out_result);
  if (handle == NULL || remediation_request_id == NULL
      || current_actor_subject_id == NULL || runtime == NULL
      || runtime->authorization == NULL
      || runtime->authorization->authorize == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  if (rc == WYRELOG_E_OK) {
    mutation.invalidate_credential = runtime->invalidate_credential;
    mutation.invalidation_data = runtime->invalidation_data;
    rc = service_mutation_authorize (&mutation, runtime->authorization,
        current_actor_subject_id);
  }
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  WylPolicyServiceHandoffRemediationResult stored = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_resolve_service_handoff_remediation_core
        (mutation.transaction, mutation.store, remediation_request_id,
        current_actor_subject_id, &stored);
  if (rc == WYRELOG_E_OK && mutation.invalidate_credential != NULL
      && stored.invalidation_generation > 0) {
    mutation.invalidation_credential_id = stored.successor_credential_id;
    mutation.invalidation_generation = stored.invalidation_generation;
  }
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK)
    service_handoff_take_remediation_result (&stored, out_result);
  wyl_policy_service_handoff_remediation_result_clear (&stored);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_handoff_resolve_remediation_incident
    (WylHandle * handle, const gchar * original_request_id,
    const guint8 journal_snapshot_digest
    [WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES],
    wyl_service_credential_handoff_remediation_result_t * out_result)
{
  if (out_result != NULL)
    wyl_service_credential_handoff_remediation_result_clear (out_result);
  if (handle == NULL || original_request_id == NULL
      || journal_snapshot_digest == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  WylPolicyServiceHandoffRemediationResult stored = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_resolve_service_handoff_remediation_incident_core
        (mutation.transaction, mutation.store, original_request_id,
        journal_snapshot_digest, &stored);
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK)
    service_handoff_take_remediation_result (&stored, out_result);
  wyl_policy_service_handoff_remediation_result_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_rotate_with_runtime (WylHandle *handle,
    const gchar *old_credential_id, const gchar *actor_subject_id,
    const gchar *request_id, gint64 new_expires_at_us,
    const wyl_service_credential_rotate_runtime_t *runtime,
    wyl_service_credential_issue_result_t *out)
{
  if (out != NULL)
    wyl_service_credential_issue_result_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  if (runtime != NULL && runtime->invalidate_credential != NULL
      && runtime->old_credential_generation == 0)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  if (rc == WYRELOG_E_OK && runtime != NULL) {
    mutation.invalidate_credential = runtime->invalidate_credential;
    mutation.invalidation_data = runtime->invalidation_data;
    mutation.invalidation_credential_id = old_credential_id;
    mutation.invalidation_generation = runtime->old_credential_generation;
  }
  wyl_policy_service_credential_info_t stored = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_authorize (&mutation,
        runtime != NULL ? runtime->authorization : NULL, actor_subject_id);
  if (rc == WYRELOG_E_OK) {
    WylServiceCredentialFenceResult fence = { 0 };
    rc = wyl_policy_store_precheck_service_credential_operation_fence
        (mutation.store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
        request_id, NULL, NULL, old_credential_id, &fence);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    else if (rc == WYRELOG_E_NOT_FOUND)
      rc = WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_materialize_service_cvk_existing (mutation.store,
        &cvk, &cvk_len);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_reconcile_operation_fence (&mutation,
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, request_id, NULL, NULL,
        old_credential_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_rotate_service_credential_core
        (mutation.transaction, mutation.store, old_credential_id,
        actor_subject_id, request_id, new_expires_at_us,
        runtime != NULL ? runtime->now_us : NULL,
        runtime != NULL ? runtime->data : NULL,
        runtime != NULL ? runtime->credential_runtime : NULL,
        runtime != NULL ? runtime->old_credential_generation : 0, cvk, cvk_len,
        &stored, &secret);
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK) {
    copy_credential (&stored, &out->credential);
    out->secret = secret;
    secret = NULL;
  }
  wyl_service_credential_secret_clear (&secret);
  wyl_policy_service_credential_info_clear (&stored);
  return rc;
}

wyrelog_error_t
wyl_service_credential_rotate (WylHandle *handle,
    const gchar *old_credential_id, const gchar *actor_subject_id,
    const gchar *request_id, gint64 new_expires_at_us,
    wyl_service_credential_issue_result_t *out)
{
  return wyl_service_credential_rotate_with_runtime (handle,
      old_credential_id, actor_subject_id, request_id, new_expires_at_us, NULL,
      out);
}

wyrelog_error_t
wyl_service_credential_rotate_handoff_checked_with_runtime (WylHandle *handle,
    const gchar *old_credential_id, const gchar *actor_subject_id,
    const gchar *request_id, gint64 new_expires_at_us,
    const wyl_service_credential_handoff_request_t *handoff,
    const wyl_service_credential_rotate_runtime_t *runtime,
    wyl_service_credential_handoff_result_t *out)
{
  if (out != NULL)
    wyl_service_credential_handoff_result_clear (out);
  if (handle == NULL || !service_handoff_request_valid (handoff)
      || runtime == NULL
      || runtime->old_credential_generation == 0 || out == NULL)
    return WYRELOG_E_INVALID;
  ServiceMutation mutation;
  wyrelog_error_t rc = service_mutation_begin (handle, &mutation);
  wyl_policy_service_credential_info_t stored = { 0 };
  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  gboolean replay = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_authorize (&mutation, runtime->authorization,
        actor_subject_id);
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_precheck_handoff_fence (&mutation,
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, request_id, NULL, NULL,
        old_credential_id, &replay);
  if (rc == WYRELOG_E_OK && !replay) {
    mutation.invalidate_credential = runtime->invalidate_credential;
    mutation.invalidation_data = runtime->invalidation_data;
    mutation.invalidation_credential_id = old_credential_id;
    mutation.invalidation_generation = runtime->old_credential_generation;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_materialize_service_cvk_existing (mutation.store,
        &cvk, &cvk_len);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = service_mutation_start_transaction (&mutation);
  if (rc == WYRELOG_E_OK && !replay)
    rc = service_mutation_reconcile_operation_fence (&mutation,
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, request_id, NULL, NULL,
        old_credential_id);
  wyl_policy_service_handoff_request_t policy_handoff =
      policy_handoff_request (handoff);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_rotate_service_credential_handoff_core
        (mutation.transaction, mutation.store, old_credential_id,
        actor_subject_id, request_id, new_expires_at_us, runtime->now_us,
        runtime->data, runtime->credential_runtime,
        runtime->old_credential_generation, cvk, cvk_len, &policy_handoff,
        &stored, &escrow);
  rc = service_mutation_finish (&mutation, rc);
  if (rc == WYRELOG_E_OK) {
    copy_credential (&stored, &out->credential);
    copy_handoff (&escrow, &out->handoff);
  }
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
  wyl_policy_service_credential_info_clear (&stored);
  return rc;
}

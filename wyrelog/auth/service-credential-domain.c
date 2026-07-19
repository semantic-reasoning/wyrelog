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

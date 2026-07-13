/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "service-credential-domain-private.h"

#include <string.h>

#include "wyrelog/wyl-handle-private.h"

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
  wyl_policy_service_principal_info_t stored = { 0 };
  wyrelog_error_t rc = wyl_policy_store_create_service_principal
      (wyl_handle_get_policy_store (handle), subject_id, display_name,
      actor_subject_id, request_id, &stored);
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
  wyl_policy_service_principal_info_t stored = { 0 };
  wyrelog_error_t rc = wyl_policy_store_disable_service_principal
      (wyl_handle_get_policy_store (handle), subject_id, actor_subject_id,
      request_id, &stored);
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
  if (out != NULL)
    wyl_service_credential_issue_result_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  wyl_policy_service_credential_info_t stored = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  wyrelog_error_t rc = wyl_policy_store_issue_service_credential
      (wyl_handle_get_policy_store (handle), subject_id, tenant_id,
      actor_subject_id, request_id, expires_at_us, &stored, &secret);
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
wyl_service_credential_revoke (WylHandle *handle, const gchar *credential_id,
    const gchar *actor_subject_id, const gchar *request_id,
    wyl_service_credential_t *out)
{
  if (out != NULL)
    wyl_service_credential_clear (out);
  if (handle == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  wyl_policy_service_credential_info_t stored = { 0 };
  wyrelog_error_t rc = wyl_policy_store_revoke_service_credential
      (wyl_handle_get_policy_store (handle), credential_id, actor_subject_id,
      request_id, &stored);
  if (rc == WYRELOG_E_OK)
    copy_credential (&stored, out);
  wyl_policy_service_credential_info_clear (&stored);
  return rc;
}

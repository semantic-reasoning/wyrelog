/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "service-exchange-private.h"

#include <string.h>

#include "wyrelog/wyl-handle-private.h"

static void
service_exchange_authority_dispose (WylServiceExchangeAuthority *authority)
{
  if (authority == NULL)
    return;
  wyl_policy_service_credential_info_clear (&authority->credential);
  if (authority->transaction != NULL) {
    (void) wyl_policy_store_service_authority_transaction_rollback
        (authority->transaction);
    wyl_policy_store_service_authority_transaction_free
        (authority->transaction);
    authority->transaction = NULL;
  }
  if (authority->lease != NULL) {
    (void) wyl_service_auth_write_lease_release (authority->lease);
    wyl_service_auth_write_lease_free (authority->lease);
    authority->lease = NULL;
  }
  authority->handle = NULL;
  authority->store = NULL;
  authority->cvk = NULL;
  authority->cvk_len = 0;
}

static gboolean
credential_is_active_now (const wyl_policy_service_credential_info_t *info,
    gint64 now_us)
{
  return info != NULL && info->credential_id != NULL && info->subject_id != NULL
      && info->tenant_id != NULL && info->generation > 0
      && g_strcmp0 (info->state, "active") == 0
      && (info->expires_at_us == 0 || info->expires_at_us > now_us);
}

void
wyl_service_exchange_authority_clear (WylServiceExchangeAuthority *authority)
{
  service_exchange_authority_dispose (authority);
  if (authority != NULL)
    memset (authority, 0, sizeof *authority);
}

static wyrelog_error_t
exchange_authenticate_credential (WylServiceAuthorityTransaction *txn,
    wyl_policy_store_t *store, const guint8 *cvk, gsize cvk_len,
    const gchar *credential_id,
    const gchar *presented_secret, gsize presented_secret_len, gint64 now_us,
    wyl_policy_service_credential_info_t *out_credential)
{
  if (out_credential != NULL)
    wyl_policy_service_credential_info_clear (out_credential);
  if (txn == NULL || store == NULL || cvk == NULL || cvk_len == 0
      || credential_id == NULL
      || presented_secret == NULL || presented_secret_len == 0
      || now_us <= 0 || out_credential == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  if (rc != WYRELOG_E_OK)
    return rc;
  wyl_policy_service_credential_info_t credential = { 0 };
  rc = wyl_policy_store_lookup_service_credential_by_id (store,
      credential_id, &credential);
  if (rc == WYRELOG_E_NOT_FOUND || rc == WYRELOG_E_INVALID)
    rc = WYRELOG_E_AUTH;
  if (rc == WYRELOG_E_OK) {
    wyl_policy_principal_kind_t kind = WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
    rc = wyl_policy_store_get_principal_kind (store, credential.subject_id,
        &kind);
    if (rc == WYRELOG_E_NOT_FOUND || rc == WYRELOG_E_INVALID)
      rc = WYRELOG_E_AUTH;
    if (rc == WYRELOG_E_OK && kind != WYL_POLICY_PRINCIPAL_KIND_SERVICE)
      rc = WYRELOG_E_AUTH;
  }
  if (rc == WYRELOG_E_OK) {
    wyl_policy_service_principal_info_t principal = { 0 };
    rc = wyl_policy_store_lookup_service_principal (store,
        credential.subject_id, &principal);
    if (rc == WYRELOG_E_NOT_FOUND || rc == WYRELOG_E_INVALID)
      rc = WYRELOG_E_AUTH;
    if (rc == WYRELOG_E_OK
        && (principal.state == NULL
            || !g_str_equal (principal.state, "active")))
      rc = WYRELOG_E_AUTH;
    wyl_policy_service_principal_info_clear (&principal);
  }

  gboolean tenant_active = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_is_active (store, credential.tenant_id,
        &tenant_active);
  if (rc == WYRELOG_E_NOT_FOUND || rc == WYRELOG_E_INVALID)
    rc = WYRELOG_E_AUTH;
  if (rc == WYRELOG_E_OK && !tenant_active)
    rc = WYRELOG_E_AUTH;

  gboolean secret_match = FALSE;
  if (rc == WYRELOG_E_OK) {
    if (!credential_is_active_now (&credential, now_us))
      rc = WYRELOG_E_AUTH;
    else
      rc = wyl_service_credential_verify
          (credential.credential_format_version,
          credential.verifier_version, cvk, cvk_len, credential.credential_id,
          strlen (credential.credential_id), credential.tenant_id,
          strlen (credential.tenant_id), credential.subject_id,
          strlen (credential.subject_id), credential.salt,
          sizeof credential.salt, credential.verifier,
          sizeof credential.verifier, presented_secret, presented_secret_len,
          &secret_match);
    if (rc == WYRELOG_E_INVALID)
      rc = WYRELOG_E_AUTH;
  }
  if (rc == WYRELOG_E_OK && !secret_match)
    rc = WYRELOG_E_AUTH;

  if (rc == WYRELOG_E_OK) {
    *out_credential = credential;
    memset (&credential, 0, sizeof credential);
  } else {
    wyl_policy_service_credential_info_clear (&credential);
  }
  return rc;
}

wyrelog_error_t
wyl_service_exchange_authority_begin (WylHandle *handle,
    const gchar *credential_id, const gchar *presented_secret,
    gsize presented_secret_len, gint64 now_us,
    WylServiceExchangeAuthority *out_authority)
{
  if (out_authority != NULL)
    wyl_service_exchange_authority_clear (out_authority);
  if (handle == NULL || credential_id == NULL || presented_secret == NULL
      || presented_secret_len == 0 || now_us <= 0 || out_authority == NULL)
    return WYRELOG_E_INVALID;

  WylServiceExchangeAuthority authority = { 0 };
  authority.handle = handle;
  wyrelog_error_t rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
      &authority.lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (authority.lease,
        handle, &authority.store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_materialize_service_cvk_existing (authority.store,
        &authority.cvk, &authority.cvk_len);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_authority_transaction_begin
        (authority.store, handle, authority.lease, &authority.transaction);
  if (rc == WYRELOG_E_OK)
    rc = exchange_authenticate_credential (authority.transaction,
        authority.store, authority.cvk, authority.cvk_len, credential_id,
        presented_secret, presented_secret_len, now_us, &authority.credential);

  if (rc == WYRELOG_E_OK) {
    authority.denial = WYL_SERVICE_EXCHANGE_DENIAL_NONE;
    authority.verified = TRUE;
    *out_authority = authority;
    return WYRELOG_E_OK;
  }

  WylServiceExchangeDenial denial = rc == WYRELOG_E_AUTH ?
      WYL_SERVICE_EXCHANGE_DENIAL_AUTH :
      rc == WYRELOG_E_BUSY ?
      WYL_SERVICE_EXCHANGE_DENIAL_UNAVAILABLE :
      WYL_SERVICE_EXCHANGE_DENIAL_NONE;
  service_exchange_authority_dispose (&authority);
  if (out_authority != NULL) {
    memset (out_authority, 0, sizeof *out_authority);
    out_authority->denial = denial;
  }
  return rc;
}

wyrelog_error_t
wyl_service_exchange_authority_rollback (WylServiceExchangeAuthority *authority)
{
  if (authority == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (authority->transaction != NULL) {
    rc = wyl_policy_store_service_authority_transaction_rollback
        (authority->transaction);
    wyl_policy_store_service_authority_transaction_free
        (authority->transaction);
    authority->transaction = NULL;
  }
  if (authority->lease != NULL) {
    wyrelog_error_t release_rc =
        wyl_service_auth_write_lease_release (authority->lease);
    if (rc == WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (authority->lease);
    authority->lease = NULL;
  }
  wyl_policy_service_credential_info_clear (&authority->credential);
  authority->handle = NULL;
  authority->store = NULL;
  authority->denial = WYL_SERVICE_EXCHANGE_DENIAL_NONE;
  authority->verified = FALSE;
  return rc;
}

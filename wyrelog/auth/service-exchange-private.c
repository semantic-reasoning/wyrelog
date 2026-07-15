/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "service-exchange-private.h"

#include <sodium.h>
#include <string.h>

#include "auth/jwt-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-session-layout-private.h"
#include "wyrelog/wyl-session-private.h"

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

static void
service_exchange_prepared_dispose (WylServiceExchangePrepared *prepared)
{
  if (prepared == NULL)
    return;
  if (prepared->access_token != NULL)
    sodium_memzero (prepared->access_token, strlen (prepared->access_token));
  g_clear_object (&prepared->session);
  g_clear_pointer (&prepared->access_token, g_free);
}

void
wyl_service_exchange_prepared_clear (WylServiceExchangePrepared *prepared)
{
  service_exchange_prepared_dispose (prepared);
  if (prepared != NULL)
    memset (prepared, 0, sizeof *prepared);
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

static gboolean
credential_secret_is_sane (const guint8 *secret, gsize secret_len)
{
  return secret != NULL && secret_len > 0;
}

static void
append_json_string (GString *json, const gchar *value)
{
  g_string_append_c (json, '"');
  for (const guchar * p = (const guchar *)value; *p != '\0'; p++) {
    switch (*p) {
      case '"':
        g_string_append (json, "\\\"");
        break;
      case '\\':
        g_string_append (json, "\\\\");
        break;
      case '\b':
        g_string_append (json, "\\b");
        break;
      case '\f':
        g_string_append (json, "\\f");
        break;
      case '\n':
        g_string_append (json, "\\n");
        break;
      case '\r':
        g_string_append (json, "\\r");
        break;
      case '\t':
        g_string_append (json, "\\t");
        break;
      default:
        if (*p < 0x20)
          g_string_append_printf (json, "\\u%04x", (guint) * p);
        else
          g_string_append_c (json, (gchar) * p);
    }
  }
  g_string_append_c (json, '"');
}

static wyrelog_error_t
exchange_sign_service_token (const gchar *key_id, const WylSession *session,
    const gchar *session_text, const gchar *issuer, const gchar *audience,
    const guint8 *secret, gsize secret_len, gchar **out_token)
{
  if (out_token == NULL || key_id == NULL || session == NULL
      || session_text == NULL || issuer == NULL || audience == NULL
      || secret == NULL || secret_len == 0)
    return WYRELOG_E_INVALID;
  *out_token = NULL;

  g_autofree gchar *header = NULL;
  wyrelog_error_t rc = wyl_jwt_build_header_json (key_id, &header);
  if (rc != WYRELOG_E_OK)
    return rc;

  GString *payload = g_string_new ("{\"jti\":");
#define APPEND_STRING_CLAIM(name, value) G_STMT_START { \
  g_string_append (payload, name); append_json_string (payload, value); \
} G_STMT_END
  append_json_string (payload, session->service_jti);
  APPEND_STRING_CLAIM (",\"sub\":", session->service_subject_id);
  APPEND_STRING_CLAIM (",\"iss\":", issuer);
  APPEND_STRING_CLAIM (",\"aud\":", audience);
  g_string_append_printf (payload,
      ",\"iat\":%" G_GINT64_FORMAT ",\"nbf\":%" G_GINT64_FORMAT
      ",\"exp\":%" G_GINT64_FORMAT, session->service_issued_at_seconds,
      session->service_issued_at_seconds,
      session->service_issued_at_seconds + WYL_JWT_SERVICE_ACCESS_TTL_SECONDS);
  APPEND_STRING_CLAIM (",\"tenant\":", session->tenant);
  g_string_append (payload, ",\"principal_state_at_issue\":\"authenticated\"");
  APPEND_STRING_CLAIM (",\"session_id\":", session_text);
  g_string_append (payload, ",\"auth_method\":\"service_credential\"");
  APPEND_STRING_CLAIM (",\"credential_id\":", session->service_credential_id);
#undef APPEND_STRING_CLAIM
  g_string_append_printf (payload, ",\"credential_generation\":%"
      G_GUINT64_FORMAT "}", session->service_credential_generation);

  g_autofree gchar *header_segment = NULL;
  g_autofree gchar *payload_segment = NULL;
  rc = wyl_jwt_base64url_encode ((const guint8 *) header, strlen (header),
      &header_segment);
  if (rc == WYRELOG_E_OK)
    rc = wyl_jwt_base64url_encode ((const guint8 *) payload->str,
        payload->len, &payload_segment);
  g_string_free (payload, TRUE);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *signing_input = g_strdup_printf ("%s.%s",
      header_segment, payload_segment);
  if (sodium_init () < 0)
    return WYRELOG_E_INTERNAL;

  guint8 signature[crypto_auth_hmacsha256_BYTES];
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init (&state, secret, secret_len);
  crypto_auth_hmacsha256_update (&state, (const guint8 *) signing_input,
      strlen (signing_input));
  crypto_auth_hmacsha256_final (&state, signature);

  g_autofree gchar *signature_segment = NULL;
  rc = wyl_jwt_base64url_encode (signature, sizeof signature,
      &signature_segment);
  if (rc == WYRELOG_E_OK)
    *out_token = g_strdup_printf ("%s.%s", signing_input, signature_segment);
  return rc;
}

static wyrelog_error_t
exchange_build_prepared (const WylServiceExchangeAuthority *authority,
    const gchar *session_text, const gchar *jti_text, const gchar *key_id,
    const gchar *issuer, const gchar *audience, gint64 issued_at_seconds,
    const guint8 *token_secret, gsize token_secret_len,
    WylServiceExchangePrepared *out_prepared)
{
  if (out_prepared != NULL)
    wyl_service_exchange_prepared_clear (out_prepared);
  if (authority == NULL || !authority->verified || authority->handle == NULL
      || session_text == NULL || jti_text == NULL || key_id == NULL
      || issuer == NULL || audience == NULL || issued_at_seconds < 0
      || out_prepared == NULL || !credential_secret_is_sane (token_secret,
          token_secret_len))
    return WYRELOG_E_INVALID;
  if (authority->credential.credential_id == NULL
      || authority->credential.subject_id == NULL
      || authority->credential.tenant_id == NULL
      || authority->credential.generation == 0)
    return WYRELOG_E_INVALID;

  wyl_service_session_descriptor_t descriptor = {
    .session_id = WYL_ID_NIL,
    .jti = jti_text,
    .subject_id = authority->credential.subject_id,
    .tenant_id = authority->credential.tenant_id,
    .credential_id = authority->credential.credential_id,
    .credential_generation = authority->credential.generation,
    .issued_at_seconds = issued_at_seconds,
    .expires_at_seconds = issued_at_seconds +
        WYL_JWT_SERVICE_ACCESS_TTL_SECONDS,
  };
  if (wyl_id_parse (session_text, &descriptor.session_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  WylSession *session = g_object_new (WYL_TYPE_SESSION, NULL);
  session->id = descriptor.session_id;
  session->state = WYL_SESSION_STATE_ACTIVE;
  session->auth_method = WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL;
  session->service_jti = g_strdup (descriptor.jti);
  session->service_subject_id = g_strdup (descriptor.subject_id);
  session->tenant = g_strdup (descriptor.tenant_id);
  session->service_credential_id = g_strdup (descriptor.credential_id);
  session->service_credential_generation = descriptor.credential_generation;
  session->service_issued_at_seconds = descriptor.issued_at_seconds;
  session->service_expires_at_seconds = descriptor.expires_at_seconds;

  gchar *token = NULL;
  wyrelog_error_t rc = exchange_sign_service_token (key_id, session,
      session_text, issuer, audience, token_secret, token_secret_len, &token);
  if (rc != WYRELOG_E_OK) {
    g_clear_object (&session);
    return rc;
  }

  *out_prepared = (WylServiceExchangePrepared) {
  .session = session,.access_token = token,};
  return WYRELOG_E_OK;
}

static wyrelog_error_t
exchange_prepare_and_publish (const WylServiceExchangeAuthority *authority,
    const gchar *key_id, const gchar *issuer, const gchar *audience,
    gint64 issued_at_seconds, const guint8 *token_secret,
    gsize token_secret_len, const WylServiceExchangeRegistryHooks *hooks,
    WylServiceExchangePrepared *out_prepared)
{
  if (out_prepared != NULL)
    wyl_service_exchange_prepared_clear (out_prepared);
  if (authority == NULL || hooks == NULL || hooks->reserve == NULL
      || hooks->activate == NULL || hooks->remove_exact == NULL)
    return WYRELOG_E_INVALID;

  wyl_id_t session_id = WYL_ID_NIL;
  if (wyl_id_new (&session_id) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  gchar session_text[WYL_ID_STRING_BUF];
  if (wyl_id_format (&session_id, session_text, sizeof session_text)
      != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;

  wyl_id_t jti = WYL_ID_NIL;
  if (wyl_id_new (&jti) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  gchar jti_text[WYL_ID_STRING_BUF];
  if (wyl_id_format (&jti, jti_text, sizeof jti_text) != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;

  wyrelog_error_t rc = hooks->reserve (hooks->user_data, session_text,
      jti_text, authority->credential.credential_id,
      authority->credential.generation, authority->credential.subject_id,
      authority->credential.tenant_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylServiceExchangePrepared prepared = { 0 };
  rc = exchange_build_prepared (authority, session_text, jti_text, key_id,
      issuer, audience, issued_at_seconds, token_secret, token_secret_len,
      &prepared);
  if (rc != WYRELOG_E_OK) {
    gboolean removed = FALSE;
    (void) hooks->remove_exact (hooks->user_data, session_text, jti_text,
        authority->credential.credential_id,
        authority->credential.generation, authority->credential.subject_id,
        authority->credential.tenant_id, &removed);
    return rc;
  }

  gboolean activated = FALSE;
  rc = hooks->activate (hooks->user_data, session_text, jti_text,
      authority->credential.credential_id, authority->credential.generation,
      authority->credential.subject_id, authority->credential.tenant_id,
      &activated);
  if (rc == WYRELOG_E_OK && !activated)
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK) {
    gboolean removed = FALSE;
    wyrelog_error_t cleanup_rc = hooks->remove_exact (hooks->user_data,
        session_text, jti_text, authority->credential.credential_id,
        authority->credential.generation, authority->credential.subject_id,
        authority->credential.tenant_id, &removed);
    if (cleanup_rc != WYRELOG_E_OK)
      rc = cleanup_rc;
    wyl_service_exchange_prepared_clear (&prepared);
    return rc;
  }

  *out_prepared = prepared;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_exchange_authority_prepare_token (WylServiceExchangeAuthority
    *authority, const gchar *key_id, const gchar *issuer, const gchar *audience,
    gint64 issued_at_seconds, const guint8 *token_secret,
    gsize token_secret_len, WylServiceExchangePrepared *out_prepared)
{
  if (out_prepared != NULL)
    wyl_service_exchange_prepared_clear (out_prepared);
  if (authority == NULL || !authority->verified || authority->handle == NULL
      || key_id == NULL || issuer == NULL || audience == NULL
      || issued_at_seconds < 0 || out_prepared == NULL
      || !credential_secret_is_sane (token_secret, token_secret_len))
    return WYRELOG_E_INVALID;
  if (authority->credential.credential_id == NULL
      || authority->credential.subject_id == NULL
      || authority->credential.tenant_id == NULL
      || authority->credential.generation == 0)
    return WYRELOG_E_INVALID;

  wyl_id_t session_id = WYL_ID_NIL;
  if (wyl_id_new (&session_id) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  gchar session_text[WYL_ID_STRING_BUF];
  if (wyl_id_format (&session_id, session_text, sizeof session_text)
      != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;

  wyl_id_t jti = WYL_ID_NIL;
  if (wyl_id_new (&jti) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  gchar jti_text[WYL_ID_STRING_BUF];
  if (wyl_id_format (&jti, jti_text, sizeof jti_text) != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;
  return exchange_build_prepared (authority, session_text, jti_text, key_id,
      issuer, audience, issued_at_seconds, token_secret, token_secret_len,
      out_prepared);
}

wyrelog_error_t
wyl_service_exchange_authority_complete (WylServiceExchangeAuthority *authority,
    const gchar *key_id, const gchar *issuer, const gchar *audience,
    gint64 issued_at_seconds, const guint8 *token_secret,
    gsize token_secret_len, const WylServiceExchangeRegistryHooks *hooks,
    WylServiceExchangePrepared *out_prepared)
{
  if (authority == NULL || !authority->verified || authority->handle == NULL
      || key_id == NULL || issuer == NULL || audience == NULL
      || issued_at_seconds < 0 || out_prepared == NULL
      || !credential_secret_is_sane (token_secret, token_secret_len))
    return WYRELOG_E_INVALID;
  if (authority->credential.credential_id == NULL
      || authority->credential.subject_id == NULL
      || authority->credential.tenant_id == NULL
      || authority->credential.generation == 0)
    return WYRELOG_E_INVALID;
  return exchange_prepare_and_publish (authority, key_id, issuer, audience,
      issued_at_seconds, token_secret, token_secret_len, hooks, out_prepared);
}

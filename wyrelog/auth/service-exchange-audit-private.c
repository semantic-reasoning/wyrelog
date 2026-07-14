/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-exchange-audit-private.h"

#include <chronoid/ksuid.h>
#include <sodium.h>
#include <string.h>

#include "auth/service-credential-private.h"
#include "policy/store-private.h"
#include "wyl-id-private.h"

#define FINGERPRINT_DOMAIN "wyrelog.service-exchange.audit-fingerprint"
#define PAYLOAD_DOMAIN "wyrelog.service-exchange.intention-payload"
#define EVENT_TYPE "service.credential.exchange"
#define OUTCOME "allowed"
#define MAX_BINDING_BYTES 128u

typedef enum
{
  WYL_SERVICE_EXCHANGE_FINGERPRINT_SESSION_ID = 1,
  WYL_SERVICE_EXCHANGE_FINGERPRINT_JTI = 2,
} WylServiceExchangeFingerprintKind;

static void
put_u32_be (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static void
put_u64_be (guint8 out[8], guint64 value)
{
  for (guint i = 0; i < 8; i++)
    out[i] = (guint8) (value >> (56 - 8 * i));
}

static gboolean
text_is_utf8_without_nul (wyl_service_exchange_text_t text, gsize min,
    gsize max)
{
  return text.data != NULL && text.len >= min && text.len <= max
      && memchr (text.data, '\0', text.len) == NULL
      && g_utf8_validate (text.data, text.len, NULL);
}

static gboolean
uuid_is_canonical (wyl_service_exchange_text_t text)
{
  if (text.data == NULL || text.len != WYL_SERVICE_EXCHANGE_UUID_LEN
      || memchr (text.data, '\0', text.len) != NULL)
    return FALSE;
  gchar value[WYL_SERVICE_EXCHANGE_UUID_BUF];
  memcpy (value, text.data, text.len);
  value[text.len] = '\0';
  wyl_id_t parsed;
  gchar canonical[WYL_SERVICE_EXCHANGE_UUID_BUF];
  return wyl_id_parse (value, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && memcmp (value, canonical, text.len) == 0;
}

static gboolean
typed_uuid_is_canonical_non_nil (const wyl_id_t *id)
{
  if (id == NULL || wyl_id_equal (id, &WYL_ID_NIL))
    return FALSE;
  gchar encoded[WYL_SERVICE_EXCHANGE_UUID_BUF];
  wyl_id_t parsed;
  return wyl_id_format (id, encoded, sizeof encoded) == WYRELOG_E_OK
      && wyl_id_parse (encoded, &parsed) == WYRELOG_E_OK
      && wyl_id_equal (id, &parsed);
}

static gboolean
wyl_service_exchange_request_id_is_canonical (const gchar *value,
    gsize value_len)
{
  if (value == NULL || value_len != WYL_SERVICE_EXCHANGE_REQUEST_ID_LEN
      || memchr (value, '\0', value_len) != NULL)
    return FALSE;
  chronoid_ksuid_t parsed;
  if (chronoid_ksuid_parse (&parsed, value, value_len) != CHRONOID_KSUID_OK)
    return FALSE;
  gchar canonical[WYL_SERVICE_EXCHANGE_REQUEST_ID_BUF];
  chronoid_ksuid_format (&parsed, canonical);
  canonical[WYL_SERVICE_EXCHANGE_REQUEST_ID_LEN] = '\0';
  return memcmp (value, canonical, value_len) == 0;
}

static gboolean
fingerprint_identifier_is_valid (WylServiceExchangeFingerprintKind kind,
    const gchar *identifier, gsize identifier_len)
{
  wyl_service_exchange_text_t text = { identifier, identifier_len };
  return (kind == WYL_SERVICE_EXCHANGE_FINGERPRINT_SESSION_ID
      || kind == WYL_SERVICE_EXCHANGE_FINGERPRINT_JTI)
      && uuid_is_canonical (text);
}

static wyrelog_error_t
service_exchange_fingerprint_v1 (WylServiceExchangeFingerprintKind kind,
    const gchar *identifier, gsize identifier_len,
    gchar out_hex[WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF])
{
  if (out_hex != NULL)
    out_hex[0] = '\0';
  if (out_hex == NULL
      || !fingerprint_identifier_is_valid (kind, identifier, identifier_len))
    return WYRELOG_E_INVALID;

  const gchar *kind_text = kind == WYL_SERVICE_EXCHANGE_FINGERPRINT_SESSION_ID
      ? "session_id" : "jti";
  guint8 u32[4], u64[8], zero = 0;
  crypto_hash_sha256_state state;
  if (crypto_hash_sha256_init (&state) != 0)
    return WYRELOG_E_CRYPTO;
#define HASH(data, len) G_STMT_START { \
  if (crypto_hash_sha256_update (&state, (const guint8 *) (data), (len)) != 0) \
    return WYRELOG_E_CRYPTO; \
} G_STMT_END
  HASH (FINGERPRINT_DOMAIN, sizeof FINGERPRINT_DOMAIN - 1);
  HASH (&zero, 1);
  put_u32_be (u32, WYL_SERVICE_EXCHANGE_FINGERPRINT_SCHEMA_VERSION);
  HASH (u32, sizeof u32);
  put_u32_be (u32, (guint32) strlen (kind_text));
  HASH (u32, sizeof u32);
  HASH (kind_text, strlen (kind_text));
  put_u64_be (u64, identifier_len);
  HASH (u64, sizeof u64);
  HASH (identifier, identifier_len);
  guint8 digest[crypto_hash_sha256_BYTES];
  if (crypto_hash_sha256_final (&state, digest) != 0)
    return WYRELOG_E_CRYPTO;
#undef HASH
  sodium_bin2hex (out_hex, WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF,
      digest, sizeof digest);
  sodium_memzero (digest, sizeof digest);
  return WYRELOG_E_OK;
}

static void
append_u32 (GByteArray *bytes, guint32 value)
{
  guint8 encoded[4];
  put_u32_be (encoded, value);
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_u64 (GByteArray *bytes, guint64 value)
{
  guint8 encoded[8];
  put_u64_be (encoded, value);
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_text (GByteArray *bytes, wyl_service_exchange_text_t text)
{
  append_u32 (bytes, (guint32) text.len);
  g_byte_array_append (bytes, (const guint8 *) text.data, text.len);
}

static gboolean
input_is_valid (const wyl_service_exchange_audit_input_t *input)
{
  if (input == NULL || !typed_uuid_is_canonical_non_nil (&input->intention_id)
      || !wyl_service_exchange_request_id_is_canonical
      (input->request_id.data, input->request_id.len)
      || !wyl_service_credential_id_is_canonical (input->credential_id.data,
          input->credential_id.len)
      || input->credential_generation == 0
      || input->credential_generation > G_MAXINT64
      || !text_is_utf8_without_nul (input->service_principal, 5,
          MAX_BINDING_BYTES)
      || !wyl_policy_service_subject_is_valid (input->service_principal.data,
          input->service_principal.len)
      || !text_is_utf8_without_nul (input->tenant_id, 1, MAX_BINDING_BYTES)
      || !uuid_is_canonical (input->session_id)
      || !uuid_is_canonical (input->jti) || input->created_at_us <= 0)
    return FALSE;
  gchar tenant[MAX_BINDING_BYTES + 1];
  memcpy (tenant, input->tenant_id.data, input->tenant_id.len);
  tenant[input->tenant_id.len] = '\0';
  return wyl_policy_store_tenant_id_is_valid (tenant);
}

void wyl_service_exchange_audit_material_clear
    (wyl_service_exchange_audit_material_t * material)
{
  if (material == NULL)
    return;
  g_clear_pointer (&material->canonical_payload, g_bytes_unref);
  sodium_memzero (material, sizeof *material);
}

wyrelog_error_t
wyl_service_exchange_audit_encode (const
    wyl_service_exchange_audit_input_t *input,
    wyl_service_exchange_audit_material_t *out_material)
{
  if (out_material == NULL)
    return WYRELOG_E_INVALID;
  static const guint8 zero_fingerprint[WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF]
  = { 0 };
  static const guint8 zero_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF] = { 0 };
  static const guint8 zero_request[WYL_SERVICE_EXCHANGE_REQUEST_ID_BUF] = { 0 };
  if (out_material->canonical_payload != NULL
      || memcmp (out_material->intention_id, zero_uuid, sizeof zero_uuid) != 0
      || memcmp (out_material->request_id, zero_request,
          sizeof zero_request) != 0
      || memcmp (out_material->session_fingerprint, zero_fingerprint,
          sizeof zero_fingerprint) != 0
      || memcmp (out_material->jti_fingerprint, zero_fingerprint,
          sizeof zero_fingerprint) != 0
      || memcmp (out_material->payload_digest, zero_fingerprint,
          sizeof zero_fingerprint) != 0)
    return WYRELOG_E_INVALID;
  if (!input_is_valid (input))
    return WYRELOG_E_INVALID;

  wyl_service_exchange_audit_material_t material =
      WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT;
  gchar intention_id[WYL_SERVICE_EXCHANGE_UUID_BUF];
  if (wyl_id_format (&input->intention_id, intention_id,
          sizeof intention_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  gchar session_hex[WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF];
  gchar jti_hex[WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF];
  wyrelog_error_t rc =
      service_exchange_fingerprint_v1
      (WYL_SERVICE_EXCHANGE_FINGERPRINT_SESSION_ID, input->session_id.data,
      input->session_id.len, session_hex);
  if (rc == WYRELOG_E_OK)
    rc = service_exchange_fingerprint_v1 (WYL_SERVICE_EXCHANGE_FINGERPRINT_JTI,
        input->jti.data, input->jti.len, jti_hex);
  if (rc != WYRELOG_E_OK)
    return rc;

  GByteArray *payload = g_byte_array_new ();
  g_byte_array_append (payload, (const guint8 *) PAYLOAD_DOMAIN,
      sizeof PAYLOAD_DOMAIN - 1);
  g_byte_array_append (payload, (const guint8 *) "\0", 1);
  append_u32 (payload, WYL_SERVICE_EXCHANGE_PAYLOAD_SCHEMA_VERSION);
  append_text (payload, (wyl_service_exchange_text_t) {
      intention_id, WYL_SERVICE_EXCHANGE_UUID_LEN});
  append_text (payload, (wyl_service_exchange_text_t) {
      EVENT_TYPE, sizeof EVENT_TYPE - 1}
  );
  append_text (payload, (wyl_service_exchange_text_t) {
      OUTCOME, sizeof OUTCOME - 1}
  );
  append_u64 (payload, (guint64) input->created_at_us);
  append_text (payload, input->request_id);
  append_text (payload, input->credential_id);
  append_u64 (payload, input->credential_generation);
  append_text (payload, input->service_principal);
  append_text (payload, input->tenant_id);
  append_u32 (payload, WYL_SERVICE_EXCHANGE_FINGERPRINT_SCHEMA_VERSION);
  append_u32 (payload, crypto_hash_sha256_BYTES);
  guint8 fingerprint[crypto_hash_sha256_BYTES];
  if (sodium_hex2bin (fingerprint, sizeof fingerprint, session_hex,
          WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_LEN, NULL, NULL, NULL) != 0) {
    g_byte_array_unref (payload);
    return WYRELOG_E_INTERNAL;
  }
  g_byte_array_append (payload, fingerprint, sizeof fingerprint);
  append_u32 (payload, crypto_hash_sha256_BYTES);
  if (sodium_hex2bin (fingerprint, sizeof fingerprint, jti_hex,
          WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_LEN, NULL, NULL, NULL) != 0) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    g_byte_array_unref (payload);
    return WYRELOG_E_INTERNAL;
  }
  g_byte_array_append (payload, fingerprint, sizeof fingerprint);
  sodium_memzero (fingerprint, sizeof fingerprint);

  guint8 digest[crypto_hash_sha256_BYTES];
  if (crypto_hash_sha256 (digest, payload->data, payload->len) != 0) {
    g_byte_array_unref (payload);
    return WYRELOG_E_CRYPTO;
  }
  memcpy (material.intention_id, intention_id, sizeof intention_id);
  memcpy (material.request_id, input->request_id.data, input->request_id.len);
  memcpy (material.session_fingerprint, session_hex, sizeof session_hex);
  memcpy (material.jti_fingerprint, jti_hex, sizeof jti_hex);
  sodium_bin2hex (material.payload_digest,
      sizeof material.payload_digest, digest, sizeof digest);
  sodium_memzero (digest, sizeof digest);
  material.canonical_payload = g_byte_array_free_to_bytes (payload);
  *out_material = material;
  return WYRELOG_E_OK;
}

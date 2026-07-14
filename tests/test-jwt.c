/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <sodium.h>
#include <string.h>

#include "wyrelog/auth/jwt-private.h"

static const wyl_jwt_issue_input_t valid_input = {
  .key_id = "wyrelogd-test-key",
  .jti = "01890c10-2e3f-7000-8000-000000000101",
  .subject = "alice",
  .issuer = "wyrelogd",
  .audience = "wyrelog-client",
  .tenant = "__wr_default",
  .principal_state_at_issue = "authenticated",
  .session_id = "01890c10-2e3f-7000-8000-000000000102",
  .issued_at = 1000,
  .ttl_seconds = 0,
};

static gboolean
is_base64url_text (const gchar *text)
{
  return text != NULL && strchr (text, '=') == NULL
      && strchr (text, '+') == NULL && strchr (text, '/') == NULL;
}

static gint
check_base64url_round_trip (void)
{
  static const guint8 data[] = { 'w', 'y', 'r', 'e', 0, 0xff };
  g_autofree gchar *encoded = NULL;
  if (wyl_jwt_base64url_encode (data, sizeof data, &encoded) != WYRELOG_E_OK)
    return 10;
  if (!is_base64url_text (encoded))
    return 11;

  g_autoptr (GBytes) decoded = NULL;
  if (wyl_jwt_base64url_decode (encoded, &decoded) != WYRELOG_E_OK)
    return 12;
  gsize decoded_len = 0;
  const guint8 *decoded_data = g_bytes_get_data (decoded, &decoded_len);
  if (decoded_len != sizeof data || memcmp (decoded_data, data, sizeof data)
      != 0)
    return 13;

  g_clear_pointer (&decoded, g_bytes_unref);
  if (wyl_jwt_base64url_decode ("abc=", &decoded) != WYRELOG_E_INVALID)
    return 14;
  if (wyl_jwt_base64url_decode ("a", &decoded) != WYRELOG_E_INVALID)
    return 15;
  if (wyl_jwt_base64url_encode (NULL, 1, &encoded) != WYRELOG_E_INVALID)
    return 16;
  return 0;
}

static gint
check_header_json_contains_required_claims (void)
{
  g_autofree gchar *header = NULL;
  if (wyl_jwt_build_header_json (valid_input.key_id, &header)
      != WYRELOG_E_OK)
    return 20;
  if (g_strcmp0 (header,
          "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"wyrelogd-test-key\"}")
      != 0)
    return 21;
  if (wyl_jwt_build_header_json ("", &header) != WYRELOG_E_INVALID)
    return 22;
  return 0;
}

static gint
check_payload_json_contains_required_claims (void)
{
  g_autofree gchar *payload = NULL;
  if (wyl_jwt_build_payload_json (&valid_input, &payload) != WYRELOG_E_OK)
    return 30;

  const gchar *expected =
      "{\"jti\":\"01890c10-2e3f-7000-8000-000000000101\","
      "\"sub\":\"alice\",\"iss\":\"wyrelogd\","
      "\"aud\":\"wyrelog-client\",\"iat\":1000,\"nbf\":1000,"
      "\"exp\":1900,\"tenant\":\"__wr_default\","
      "\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"01890c10-2e3f-7000-8000-000000000102\"}";
  if (g_strcmp0 (payload, expected) != 0)
    return 31;
  return 0;
}

static gint
check_payload_json_escapes_strings (void)
{
  wyl_jwt_issue_input_t input = valid_input;
  input.subject = "a\"b\\c\n";

  g_autofree gchar *payload = NULL;
  if (wyl_jwt_build_payload_json (&input, &payload) != WYRELOG_E_OK)
    return 40;
  if (strstr (payload, "\"sub\":\"a\\\"b\\\\c\\n\"") == NULL)
    return 41;
  return 0;
}

static gint
check_payload_rejects_missing_claims (void)
{
  wyl_jwt_issue_input_t input = valid_input;
  input.tenant = "";

  g_autofree gchar *payload = NULL;
  if (wyl_jwt_build_payload_json (&input, &payload) != WYRELOG_E_INVALID)
    return 50;
  input = valid_input;
  input.issued_at = -1;
  if (wyl_jwt_build_payload_json (&input, &payload) != WYRELOG_E_INVALID)
    return 51;
  input = valid_input;
  input.issued_at = G_MAXINT64 - 10;
  input.ttl_seconds = 11;
  if (wyl_jwt_build_payload_json (&input, &payload) != WYRELOG_E_INVALID)
    return 52;
  return 0;
}

static gint
check_unsigned_segments_are_base64url (void)
{
  g_autofree gchar *header_segment = NULL;
  g_autofree gchar *payload_segment = NULL;
  if (wyl_jwt_build_unsigned_segments (&valid_input, &header_segment,
          &payload_segment) != WYRELOG_E_OK)
    return 60;
  if (!is_base64url_text (header_segment) ||
      !is_base64url_text (payload_segment))
    return 61;

  g_autoptr (GBytes) header_bytes = NULL;
  if (wyl_jwt_base64url_decode (header_segment, &header_bytes)
      != WYRELOG_E_OK)
    return 62;
  gsize header_len = 0;
  const gchar *header = g_bytes_get_data (header_bytes, &header_len);
  const gchar *expected = "{\"alg\":\"HS256\",\"typ\":\"JWT\","
      "\"kid\":\"wyrelogd-test-key\"}";
  if (header_len != strlen (expected) || memcmp (header, expected,
          header_len) != 0)
    return 63;

  g_autoptr (GBytes) payload_bytes = NULL;
  if (wyl_jwt_base64url_decode (payload_segment, &payload_bytes)
      != WYRELOG_E_OK)
    return 64;
  gsize payload_len = 0;
  const gchar *payload = g_bytes_get_data (payload_bytes, &payload_len);
  g_autofree gchar *payload_text = g_strndup (payload, payload_len);
  if (payload_len == 0 || strstr (payload_text, "\"exp\":1900") == NULL)
    return 65;

  g_autofree gchar *missing_header_segment = NULL;
  g_autofree gchar *missing_payload_segment = NULL;
  if (wyl_jwt_build_unsigned_segments (NULL, &missing_header_segment,
          &missing_payload_segment) != WYRELOG_E_INVALID)
    return 66;
  return 0;
}

static gint
check_hs256_token_signature_round_trip (void)
{
  static const guint8 secret[] = "test-secret";
  g_autofree gchar *token = NULL;
  if (wyl_jwt_sign_hs256 (&valid_input, secret, strlen ((const gchar *) secret),
          &token) != WYRELOG_E_OK)
    return 70;

  g_auto (GStrv) parts = g_strsplit (token, ".", 0);
  if (parts[0] == NULL || parts[1] == NULL || parts[2] == NULL ||
      parts[3] != NULL)
    return 71;
  if (!is_base64url_text (parts[0]) || !is_base64url_text (parts[1]) ||
      !is_base64url_text (parts[2]))
    return 72;

  g_autoptr (GBytes) payload = NULL;
  if (wyl_jwt_verify_hs256_signature (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, &payload)
      != WYRELOG_E_OK)
    return 73;
  gsize payload_len = 0;
  const gchar *payload_data = g_bytes_get_data (payload, &payload_len);
  g_autofree gchar *payload_text = g_strndup (payload_data, payload_len);
  if (strstr (payload_text, "\"sub\":\"alice\"") == NULL)
    return 74;
  return 0;
}

static gint
check_hs256_signature_fails_closed (void)
{
  static const guint8 secret[] = "test-secret";
  static const guint8 wrong_secret[] = "wrong-secret";
  g_autofree gchar *token = NULL;
  if (wyl_jwt_sign_hs256 (&valid_input, secret, strlen ((const gchar *) secret),
          &token) != WYRELOG_E_OK)
    return 80;

  g_autoptr (GBytes) payload = NULL;
  if (wyl_jwt_verify_hs256_signature (token, wrong_secret,
          strlen ((const gchar *) wrong_secret), valid_input.key_id, &payload)
      != WYRELOG_E_POLICY)
    return 81;
  if (wyl_jwt_verify_hs256_signature ("a.b", secret,
          strlen ((const gchar *) secret), valid_input.key_id, &payload)
      != WYRELOG_E_INVALID)
    return 82;
  if (wyl_jwt_sign_hs256 (&valid_input, NULL, 0, &token)
      != WYRELOG_E_INVALID)
    return 83;

  g_auto (GStrv) parts = g_strsplit (token, ".", 0);
  g_autofree gchar *tampered_payload = g_strdup_printf ("%s.%sA.%s",
      parts[0], parts[1], parts[2]);
  if (wyl_jwt_verify_hs256_signature (tampered_payload, secret,
          strlen ((const gchar *) secret), valid_input.key_id, &payload)
      != WYRELOG_E_POLICY)
    return 84;

  g_autofree gchar *tampered_signature = g_strdup_printf ("%s.%s.%sA",
      parts[0], parts[1], parts[2]);
  if (wyl_jwt_verify_hs256_signature (tampered_signature, secret,
          strlen ((const gchar *) secret), valid_input.key_id, &payload)
      != WYRELOG_E_POLICY)
    return 85;

  const gchar *none_header = "{\"alg\":\"none\",\"typ\":\"JWT\","
      "\"kid\":\"wyrelogd-test-key\"}";
  g_autofree gchar *none_header_segment = NULL;
  if (wyl_jwt_base64url_encode ((const guint8 *) none_header,
          strlen (none_header), &none_header_segment) != WYRELOG_E_OK)
    return 86;
  g_autofree gchar *none_token = g_strdup_printf ("%s.%s.%s",
      none_header_segment, parts[1], parts[2]);
  if (wyl_jwt_verify_hs256_signature (none_token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, &payload)
      != WYRELOG_E_POLICY)
    return 87;
  return 0;
}

static gint
check_hs256_access_token_claims_and_time (void)
{
  static const guint8 secret[] = "test-secret";
  g_autofree gchar *token = NULL;
  if (wyl_jwt_sign_hs256 (&valid_input, secret, strlen ((const gchar *) secret),
          &token) != WYRELOG_E_OK)
    return 90;

  g_autoptr (GBytes) payload = NULL;
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_OK)
    return 91;
  if (payload == NULL)
    return 92;
  wyl_jwt_access_claims_t claims = { 0 };
  if (wyl_jwt_parse_access_claims_json (payload, &claims) != WYRELOG_E_OK)
    return 99;
  gint claims_rc = 0;
  if (g_strcmp0 (claims.jti, "01890c10-2e3f-7000-8000-000000000101") != 0)
    claims_rc = 100;
  else if (g_strcmp0 (claims.subject, "alice") != 0)
    claims_rc = 101;
  else if (g_strcmp0 (claims.tenant, "__wr_default") != 0)
    claims_rc = 102;
  else if (g_strcmp0 (claims.session_id,
          "01890c10-2e3f-7000-8000-000000000102") != 0)
    claims_rc = 103;
  wyl_jwt_access_claims_clear (&claims);
  if (claims_rc != 0)
    return claims_rc;

  g_clear_pointer (&payload, g_bytes_unref);
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1899, &payload) != WYRELOG_E_OK)
    return 93;
  g_clear_pointer (&payload, g_bytes_unref);
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "other-issuer",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_POLICY)
    return 94;
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "other-audience", 1000, &payload) != WYRELOG_E_POLICY)
    return 95;
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 999, &payload) != WYRELOG_E_POLICY)
    return 96;
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1900, &payload) != WYRELOG_E_POLICY)
    return 97;
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_INVALID)
    return 98;
  if (wyl_jwt_verify_hs256_access_token (token, secret,
          strlen ((const gchar *) secret), "other-key", "wyrelogd",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_POLICY)
    return 104;
  return 0;
}

static wyrelog_error_t
sign_custom_header_payload_bytes (const gchar *header, const guint8 *payload,
    gsize payload_len, const guint8 *secret, gsize secret_len,
    gchar **out_token)
{
  if (header == NULL || payload == NULL || secret == NULL || secret_len == 0
      || out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;
  if (sodium_init () < 0)
    return WYRELOG_E_INTERNAL;

  g_autofree gchar *header_segment = NULL;
  g_autofree gchar *payload_segment = NULL;
  wyrelog_error_t rc = wyl_jwt_base64url_encode ((const guint8 *) header,
      strlen (header), &header_segment);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_jwt_base64url_encode (payload, payload_len, &payload_segment);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *signing_input = g_strdup_printf ("%s.%s", header_segment,
      payload_segment);
  guint8 signature[crypto_auth_hmacsha256_BYTES];
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init (&state, secret, secret_len);
  crypto_auth_hmacsha256_update (&state, (const guint8 *) signing_input,
      strlen (signing_input));
  crypto_auth_hmacsha256_final (&state, signature);

  g_autofree gchar *signature_segment = NULL;
  rc = wyl_jwt_base64url_encode (signature, sizeof signature,
      &signature_segment);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_token = g_strdup_printf ("%s.%s", signing_input, signature_segment);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
sign_custom_payload_bytes (const guint8 *payload, gsize payload_len,
    const guint8 *secret, gsize secret_len, gchar **out_token)
{
  const gchar *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\","
      "\"kid\":\"wyrelogd-test-key\"}";
  return sign_custom_header_payload_bytes (header, payload, payload_len,
      secret, secret_len, out_token);
}

static wyrelog_error_t
sign_custom_payload (const gchar *payload, const guint8 *secret,
    gsize secret_len, gchar **out_token)
{
  if (payload == NULL)
    return WYRELOG_E_INVALID;
  return sign_custom_payload_bytes ((const guint8 *) payload, strlen (payload),
      secret, secret_len, out_token);
}

static gint
check_hs256_signature_rejects_ambiguous_headers (void)
{
  static const guint8 secret[] = "test-secret";
  const gchar *payload =
      "{\"jti\":\"jti\",\"sub\":\"alice\",\"iss\":\"wyrelogd\","
      "\"aud\":\"wyrelog-client\",\"iat\":1000,\"nbf\":1000,\"exp\":1900,"
      "\"tenant\":\"t\",\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"session\"}";
  const gchar *headers[] = {
    "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
    "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"other-key\"}",
    "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"wyrelogd-test-key\","
        "\"kid\":\"other-key\"}",
    "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"wyrelogd-test-key\","
        "\"x5u\":\"https://example.invalid/key\"}",
    "{\"alg\":{\"name\":\"HS256\"},\"typ\":\"JWT\","
        "\"kid\":\"wyrelogd-test-key\"}",
  };

  for (guint i = 0; i < G_N_ELEMENTS (headers); i++) {
    g_autofree gchar *token = NULL;
    if (sign_custom_header_payload_bytes (headers[i], (const guint8 *) payload,
            strlen (payload), secret, strlen ((const gchar *) secret),
            &token) != WYRELOG_E_OK)
      return 120 + (gint) i;

    g_autoptr (GBytes) decoded_payload = NULL;
    if (wyl_jwt_verify_hs256_signature (token, secret,
            strlen ((const gchar *) secret), valid_input.key_id,
            &decoded_payload) != WYRELOG_E_POLICY)
      return 130 + (gint) i;
  }
  return 0;
}

static gint
check_hs256_access_token_rejects_ambiguous_claims (void)
{
  static const guint8 secret[] = "test-secret";
  const gchar *duplicate_payload =
      "{\"jti\":\"jti\",\"sub\":\"alice\",\"iss\":\"wyrelogd\","
      "\"iss\":\"evil\",\"aud\":\"wyrelog-client\",\"iat\":1000,"
      "\"nbf\":1000,\"exp\":1900,\"tenant\":\"__wr_default\","
      "\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"session\"}";
  g_autofree gchar *duplicate_token = NULL;
  if (sign_custom_payload (duplicate_payload, secret,
          strlen ((const gchar *) secret), &duplicate_token) != WYRELOG_E_OK)
    return 110;

  g_autoptr (GBytes) payload = NULL;
  if (wyl_jwt_verify_hs256_access_token (duplicate_token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_POLICY)
    return 111;

  const gchar *nested_payload =
      "{\"nested\":{\"iss\":\"wyrelogd\",\"aud\":\"wyrelog-client\","
      "\"nbf\":1000,\"exp\":1900},\"jti\":\"jti\",\"sub\":\"alice\","
      "\"iss\":\"evil\",\"aud\":\"evil\",\"iat\":1000,\"tenant\":\"t\","
      "\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"session\"}";
  g_autofree gchar *nested_token = NULL;
  if (sign_custom_payload (nested_payload, secret,
          strlen ((const gchar *) secret), &nested_token) != WYRELOG_E_OK)
    return 112;
  if (wyl_jwt_verify_hs256_access_token (nested_token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_POLICY)
    return 113;

  const gchar *nul_issuer_payload =
      "{\"jti\":\"jti\",\"sub\":\"alice\",\"iss\":\"wyrelogd\\u0000evil\","
      "\"aud\":\"wyrelog-client\",\"iat\":1000,\"nbf\":1000,\"exp\":1900,"
      "\"tenant\":\"t\",\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"session\"}";
  g_autofree gchar *nul_issuer_token = NULL;
  if (sign_custom_payload (nul_issuer_payload, secret,
          strlen ((const gchar *) secret), &nul_issuer_token) != WYRELOG_E_OK)
    return 114;
  if (wyl_jwt_verify_hs256_access_token (nul_issuer_token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_POLICY)
    return 115;

  const gchar *short_escape_payload =
      "{\"jti\":\"jti\",\"sub\":\"alice\",\"iss\":\"wyrelogd\\u00\","
      "\"aud\":\"wyrelog-client\",\"iat\":1000,\"nbf\":1000,\"exp\":1900,"
      "\"tenant\":\"t\",\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"session\"}";
  g_autofree gchar *short_escape_token = NULL;
  if (sign_custom_payload (short_escape_payload, secret,
          strlen ((const gchar *) secret), &short_escape_token)
      != WYRELOG_E_OK)
    return 116;
  if (wyl_jwt_verify_hs256_access_token (short_escape_token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_POLICY)
    return 117;

  static const guint8 raw_nul_payload[] =
      "{\"jti\":\"jti\",\"sub\":\"alice\",\"iss\":\"wyrelogd\","
      "\"aud\":\"wyrelog-client\",\"iat\":1000,\"nbf\":1000,\"exp\":1900,"
      "\"tenant\":\"t\",\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"session\"}" "\0" "{\"trailing\":\"ignored\"}";
  g_autofree gchar *raw_nul_token = NULL;
  if (sign_custom_payload_bytes (raw_nul_payload, sizeof raw_nul_payload - 1,
          secret, strlen ((const gchar *) secret), &raw_nul_token)
      != WYRELOG_E_OK)
    return 118;
  if (wyl_jwt_verify_hs256_access_token (raw_nul_token, secret,
          strlen ((const gchar *) secret), valid_input.key_id, "wyrelogd",
          "wyrelog-client", 1000, &payload) != WYRELOG_E_POLICY)
    return 119;
  return 0;
}

static const wyl_jwt_service_issue_input_t valid_service_input = {
  .key_id = "wyrelogd-test-key",
  .jti = "01890c10-2e3f-7000-8000-000000000201",
  .subject = "svc:jwt:worker",
  .issuer = "wyrelogd",
  .audience = "wyrelog-client",
  .tenant = "tenant-a",
  .session_id = "01890c10-2e3f-7000-8000-000000000202",
  .credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
  .credential_generation = G_MAXUINT64,
  .issued_at = 2000,
};

static gint
check_service_claim_round_trip (void)
{
  static const guint8 secret[] = "service-test-secret";
  g_autofree gchar *token = NULL;
  if (wyl_jwt_sign_hs256_service (&valid_service_input, secret,
          sizeof secret - 1, &token) != WYRELOG_E_OK)
    return 150;
  g_autoptr (GBytes) payload = NULL;
  if (wyl_jwt_verify_hs256_access_token (token, secret, sizeof secret - 1,
          valid_service_input.key_id, valid_service_input.issuer,
          valid_service_input.audience, 2000, &payload) != WYRELOG_E_OK)
    return 151;
  wyl_jwt_access_claims_t claims = { 0 };
  if (wyl_jwt_parse_access_claims_json (payload, &claims) != WYRELOG_E_OK)
    return 152;
  gboolean exact = g_strcmp0 (claims.jti, valid_service_input.jti) == 0
      && g_strcmp0 (claims.subject, valid_service_input.subject) == 0
      && g_strcmp0 (claims.tenant, valid_service_input.tenant) == 0
      && g_strcmp0 (claims.session_id, valid_service_input.session_id) == 0
      && g_strcmp0 (claims.auth_method, "service_credential") == 0
      && g_strcmp0 (claims.credential_id,
      valid_service_input.credential_id) == 0
      && claims.credential_generation == G_MAXUINT64
      && claims.issued_at == 2000 && claims.not_before == 2000
      && claims.expires_at == 2300;
  wyl_jwt_access_claims_clear (&claims);
  if (!exact)
    return 153;

  wyl_jwt_service_issue_input_t invalid = valid_service_input;
  invalid.credential_generation = 0;
  g_clear_pointer (&token, g_free);
  if (wyl_jwt_sign_hs256_service (&invalid, secret, sizeof secret - 1,
          &token) != WYRELOG_E_INVALID)
    return 154;
  invalid = valid_service_input;
  invalid.issued_at = G_MAXINT64 - 299;
  if (wyl_jwt_sign_hs256_service (&invalid, secret, sizeof secret - 1,
          &token) != WYRELOG_E_INVALID)
    return 155;

  invalid.issued_at = G_MAXINT64 - WYL_JWT_SERVICE_ACCESS_TTL_SECONDS;
  if (wyl_jwt_sign_hs256_service (&invalid, secret, sizeof secret - 1,
          &token) != WYRELOG_E_OK)
    return 156;
  g_clear_pointer (&payload, g_bytes_unref);
  if (wyl_jwt_verify_hs256_access_token (token, secret, sizeof secret - 1,
          invalid.key_id, invalid.issuer, invalid.audience, invalid.issued_at,
          &payload) != WYRELOG_E_OK)
    return 157;
  memset (&claims, 0, sizeof claims);
  if (wyl_jwt_parse_access_claims_json (payload, &claims) != WYRELOG_E_OK
      || claims.issued_at != invalid.issued_at
      || claims.not_before != invalid.issued_at
      || claims.expires_at != G_MAXINT64) {
    wyl_jwt_access_claims_clear (&claims);
    return 158;
  }
  wyl_jwt_access_claims_clear (&claims);

  g_clear_pointer (&token, g_free);
  if (wyl_jwt_sign_hs256_service (&valid_service_input, secret,
          sizeof secret - 1, &token) != WYRELOG_E_OK)
    return 159;
  g_clear_pointer (&payload, g_bytes_unref);
  if (wyl_jwt_verify_hs256_access_token (token, secret, sizeof secret - 1,
          valid_service_input.key_id, valid_service_input.issuer,
          valid_service_input.audience, valid_service_input.issued_at - 1,
          &payload) != WYRELOG_E_POLICY || payload != NULL)
    return 160;
  if (wyl_jwt_verify_hs256_access_token (token, secret, sizeof secret - 1,
          valid_service_input.key_id, valid_service_input.issuer,
          valid_service_input.audience,
          valid_service_input.issued_at + WYL_JWT_SERVICE_ACCESS_TTL_SECONDS,
          &payload) != WYRELOG_E_POLICY || payload != NULL)
    return 161;
  return 0;
}

static wyrelog_error_t
parse_claim_text (const gchar *text)
{
  g_autoptr (GBytes) bytes = g_bytes_new_static (text, strlen (text));
  wyl_jwt_access_claims_t claims = { 0 };
  wyrelog_error_t rc = wyl_jwt_parse_access_claims_json (bytes, &claims);
  wyl_jwt_access_claims_clear (&claims);
  return rc;
}

static gchar *
replace_claim_fragment (const gchar *text, const gchar *from, const gchar *to)
{
  const gchar *match = strstr (text, from);
  if (match == NULL)
    return NULL;
  return g_strdup_printf ("%.*s%s%s", (gint) (match - text), text, to,
      match + strlen (from));
}

#define SERVICE_BASE \
  "\"jti\":\"01890c10-2e3f-7000-8000-000000000201\"," \
  "\"sub\":\"svc:jwt:worker\",\"iss\":\"wyrelogd\"," \
  "\"aud\":\"wyrelog-client\",\"iat\":2000,\"nbf\":2000," \
  "\"exp\":2300,\"tenant\":\"tenant-a\"," \
  "\"principal_state_at_issue\":\"authenticated\"," \
  "\"session_id\":\"01890c10-2e3f-7000-8000-000000000202\""
#define SERVICE_ONLY \
  "\"auth_method\":\"service_credential\"," \
  "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\"," \
  "\"credential_generation\":1"

static gint
check_service_claims_fail_closed (void)
{
  const gchar *invalid[] = {
    "{" SERVICE_BASE ",\"auth_method\":\"service_credential\"}",
    "{" SERVICE_BASE ",\"credential_id\":"
        "\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\"}",
    "{" SERVICE_BASE ",\"credential_generation\":1}",
    "{" SERVICE_BASE "," SERVICE_ONLY ",\"sid\":\"alias\"}",
    "{" SERVICE_BASE "," SERVICE_ONLY ",\"auth_method\":"
        "\"service_credential\"}",
    "{" SERVICE_BASE ",\"auth_method\":1,\"credential_id\":"
        "\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\"," "\"credential_generation\":1}",
    "{" SERVICE_BASE ",\"auth_method\":\"service_credential\","
        "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
        "\"credential_generation\":\"1\"}",
    "{" SERVICE_BASE ",\"auth_method\":\"unknown\","
        "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
        "\"credential_generation\":1}",
    "{" SERVICE_BASE ",\"auth_method\":\"service_credential\","
        "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
        "\"credential_generation\":0}",
    "{" SERVICE_BASE ",\"auth_method\":\"service_credential\","
        "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
        "\"credential_generation\":18446744073709551616}",
    "{" SERVICE_BASE ",\"auth_method\":\"service_credential\","
        "\"credential_id\":\"wlc_bad\",\"credential_generation\":1}",
    "{" SERVICE_BASE "," SERVICE_ONLY "} trailing",
    "{" SERVICE_BASE ",\"auth_method\":\"service_credential\","
        "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
        "\"credential_generation\":01}",
  };
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    if (parse_claim_text (invalid[i]) == WYRELOG_E_OK)
      return 170 + (gint) i;

  const gchar *bad_time =
      "{\"jti\":\"01890c10-2e3f-7000-8000-000000000201\","
      "\"sub\":\"svc:jwt:worker\",\"iss\":\"wyrelogd\","
      "\"aud\":\"wyrelog-client\",\"iat\":2000,\"nbf\":2001,"
      "\"exp\":2300,\"tenant\":\"tenant-a\","
      "\"principal_state_at_issue\":\"authenticated\","
      "\"session_id\":\"01890c10-2e3f-7000-8000-000000000202\","
      SERVICE_ONLY "}";
  if (parse_claim_text (bad_time) != WYRELOG_E_POLICY)
    return 180;
  g_autofree gchar *bad_expiry = g_strdup ("{" SERVICE_BASE ","
      SERVICE_ONLY "}");
  gchar *expiry = strstr (bad_expiry, "\"exp\":2300");
  if (expiry == NULL)
    return 181;
  expiry[strlen ("\"exp\":230")] = '1';
  if (parse_claim_text (bad_expiry) != WYRELOG_E_POLICY)
    return 182;

  const gchar *valid_payload = "{" SERVICE_BASE "," SERVICE_ONLY "}";
  const gchar *invalid_identity[][2] = {
    {"01890c10-2e3f-7000-8000-000000000201", "not-a-jti"},
    {"01890c10-2e3f-7000-8000-000000000202", "not-a-session"},
    {"svc:jwt:worker", "alice"},
    {"tenant-a", "bad tenant"},
    {"authenticated", "active"},
  };
  for (guint i = 0; i < G_N_ELEMENTS (invalid_identity); i++) {
    g_autofree gchar *mutated = replace_claim_fragment (valid_payload,
        invalid_identity[i][0], invalid_identity[i][1]);
    if (mutated == NULL || parse_claim_text (mutated) == WYRELOG_E_OK)
      return 183 + (gint) i;
  }
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_base64url_round_trip ()) != 0)
    return rc;
  if ((rc = check_header_json_contains_required_claims ()) != 0)
    return rc;
  if ((rc = check_payload_json_contains_required_claims ()) != 0)
    return rc;
  if ((rc = check_payload_json_escapes_strings ()) != 0)
    return rc;
  if ((rc = check_payload_rejects_missing_claims ()) != 0)
    return rc;
  if ((rc = check_unsigned_segments_are_base64url ()) != 0)
    return rc;
  if ((rc = check_hs256_token_signature_round_trip ()) != 0)
    return rc;
  if ((rc = check_hs256_signature_fails_closed ()) != 0)
    return rc;
  if ((rc = check_hs256_access_token_claims_and_time ()) != 0)
    return rc;
  if ((rc = check_hs256_signature_rejects_ambiguous_headers ()) != 0)
    return rc;
  if ((rc = check_hs256_access_token_rejects_ambiguous_claims ()) != 0)
    return rc;
  if ((rc = check_service_claim_round_trip ()) != 0)
    return rc;
  if ((rc = check_service_claims_fail_closed ()) != 0)
    return rc;
  return 0;
}

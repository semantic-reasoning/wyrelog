/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/jwt-private.h"

#include <sodium.h>
#include <string.h>

static gboolean
non_empty (const gchar *value)
{
  return value != NULL && value[0] != '\0';
}

static wyrelog_error_t
validate_issue_input (const wyl_jwt_issue_input_t *input)
{
  if (input == NULL || !non_empty (input->jti) || !non_empty (input->subject)
      || !non_empty (input->issuer) || !non_empty (input->audience)
      || !non_empty (input->tenant)
      || !non_empty (input->principal_state_at_issue)
      || !non_empty (input->session_id) || input->issued_at < 0
      || input->ttl_seconds < 0)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
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
        break;
    }
  }
  g_string_append_c (json, '"');
}

wyrelog_error_t
wyl_jwt_base64url_encode (const guint8 *data, gsize len, gchar **out_text)
{
  if ((data == NULL && len > 0) || out_text == NULL)
    return WYRELOG_E_INVALID;

  *out_text = NULL;
  g_autofree gchar *encoded = g_base64_encode (data, len);
  for (gchar * p = encoded; *p != '\0'; p++) {
    if (*p == '+')
      *p = '-';
    else if (*p == '/')
      *p = '_';
    else if (*p == '=') {
      *p = '\0';
      break;
    }
  }
  *out_text = g_steal_pointer (&encoded);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_base64url_decode (const gchar *text, GBytes **out_bytes)
{
  if (text == NULL || out_bytes == NULL)
    return WYRELOG_E_INVALID;

  *out_bytes = NULL;
  gsize len = strlen (text);
  if (len % 4 == 1)
    return WYRELOG_E_INVALID;
  for (const gchar * p = text; *p != '\0'; p++) {
    if (!(g_ascii_isalnum (*p) || *p == '-' || *p == '_'))
      return WYRELOG_E_INVALID;
  }

  g_autofree gchar *padded = g_strdup (text);
  for (gchar * p = padded; *p != '\0'; p++) {
    if (*p == '-')
      *p = '+';
    else if (*p == '_')
      *p = '/';
  }
  gsize pad = (4 - (len % 4)) % 4;
  if (pad > 0) {
    g_autofree gchar *padding = g_strnfill (pad, '=');
    g_autofree gchar *tmp = g_strconcat (padded, padding, NULL);
    g_free (g_steal_pointer (&padded));
    padded = g_steal_pointer (&tmp);
  }

  gsize out_len = 0;
  guchar *decoded = g_base64_decode (padded, &out_len);
  *out_bytes = g_bytes_new_take (decoded, out_len);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_build_header_json (gchar **out_json)
{
  if (out_json == NULL)
    return WYRELOG_E_INVALID;
  *out_json = g_strdup ("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_build_payload_json (const wyl_jwt_issue_input_t *input,
    gchar **out_json)
{
  if (out_json == NULL)
    return WYRELOG_E_INVALID;
  *out_json = NULL;
  wyrelog_error_t rc = validate_issue_input (input);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 ttl = input->ttl_seconds > 0 ? input->ttl_seconds :
      WYL_JWT_ACCESS_TTL_SECONDS;
  if (ttl > G_MAXINT64 - input->issued_at)
    return WYRELOG_E_INVALID;
  gint64 expires_at = input->issued_at + ttl;

  GString *json = g_string_new ("{");
  g_string_append (json, "\"jti\":");
  append_json_string (json, input->jti);
  g_string_append (json, ",\"sub\":");
  append_json_string (json, input->subject);
  g_string_append (json, ",\"iss\":");
  append_json_string (json, input->issuer);
  g_string_append (json, ",\"aud\":");
  append_json_string (json, input->audience);
  g_string_append_printf (json,
      ",\"iat\":%" G_GINT64_FORMAT ",\"nbf\":%" G_GINT64_FORMAT
      ",\"exp\":%" G_GINT64_FORMAT,
      input->issued_at, input->issued_at, expires_at);
  g_string_append (json, ",\"tenant\":");
  append_json_string (json, input->tenant);
  g_string_append (json, ",\"principal_state_at_issue\":");
  append_json_string (json, input->principal_state_at_issue);
  g_string_append (json, ",\"session_id\":");
  append_json_string (json, input->session_id);
  g_string_append_c (json, '}');

  *out_json = g_string_free (json, FALSE);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_build_unsigned_segments (const wyl_jwt_issue_input_t *input,
    gchar **out_header_segment, gchar **out_payload_segment)
{
  if (out_header_segment == NULL || out_payload_segment == NULL)
    return WYRELOG_E_INVALID;
  *out_header_segment = NULL;
  *out_payload_segment = NULL;

  g_autofree gchar *header = NULL;
  g_autofree gchar *payload = NULL;
  wyrelog_error_t rc = wyl_jwt_build_header_json (&header);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_jwt_build_payload_json (input, &payload);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_jwt_base64url_encode ((const guint8 *) header, strlen (header),
      out_header_segment);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_jwt_base64url_encode ((const guint8 *) payload, strlen (payload),
      out_payload_segment);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_header_segment, g_free);
  return rc;
}

static wyrelog_error_t
signing_secret_valid (const guint8 *secret, gsize secret_len)
{
  if (secret == NULL || secret_len == 0)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
sign_hs256_input (const gchar *signing_input, const guint8 *secret,
    gsize secret_len, guint8 out_signature[crypto_auth_hmacsha256_BYTES])
{
  if (signing_input == NULL || signing_secret_valid (secret, secret_len)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  if (sodium_init () < 0)
    return WYRELOG_E_INTERNAL;

  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init (&state, secret, secret_len);
  crypto_auth_hmacsha256_update (&state, (const guint8 *) signing_input,
      strlen (signing_input));
  crypto_auth_hmacsha256_final (&state, out_signature);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_sign_hs256 (const wyl_jwt_issue_input_t *input,
    const guint8 *secret, gsize secret_len, gchar **out_token)
{
  if (out_token == NULL || signing_secret_valid (secret, secret_len)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  *out_token = NULL;

  g_autofree gchar *header_segment = NULL;
  g_autofree gchar *payload_segment = NULL;
  wyrelog_error_t rc = wyl_jwt_build_unsigned_segments (input,
      &header_segment, &payload_segment);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *signing_input = g_strdup_printf ("%s.%s",
      header_segment, payload_segment);
  guint8 signature[crypto_auth_hmacsha256_BYTES];
  rc = sign_hs256_input (signing_input, secret, secret_len, signature);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *signature_segment = NULL;
  rc = wyl_jwt_base64url_encode (signature, sizeof signature,
      &signature_segment);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_token = g_strdup_printf ("%s.%s", signing_input, signature_segment);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_verify_hs256_signature (const gchar *token, const guint8 *secret,
    gsize secret_len, GBytes **out_payload_json)
{
  if (token == NULL || out_payload_json == NULL ||
      signing_secret_valid (secret, secret_len) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  *out_payload_json = NULL;

  g_auto (GStrv) parts = g_strsplit (token, ".", 0);
  if (parts[0] == NULL || parts[1] == NULL || parts[2] == NULL ||
      parts[3] != NULL || parts[0][0] == '\0' || parts[1][0] == '\0' ||
      parts[2][0] == '\0')
    return WYRELOG_E_INVALID;

  g_autoptr (GBytes) header = NULL;
  wyrelog_error_t rc = wyl_jwt_base64url_decode (parts[0], &header);
  if (rc != WYRELOG_E_OK)
    return rc;
  gsize header_len = 0;
  const gchar *header_data = g_bytes_get_data (header, &header_len);
  if (header_len != strlen ("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") ||
      memcmp (header_data, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
          header_len) != 0)
    return WYRELOG_E_POLICY;

  g_autoptr (GBytes) signature = NULL;
  rc = wyl_jwt_base64url_decode (parts[2], &signature);
  if (rc != WYRELOG_E_OK)
    return rc;
  gsize signature_len = 0;
  const guint8 *signature_data = g_bytes_get_data (signature, &signature_len);
  if (signature_len != crypto_auth_hmacsha256_BYTES)
    return WYRELOG_E_POLICY;

  g_autofree gchar *signing_input = g_strdup_printf ("%s.%s",
      parts[0], parts[1]);
  guint8 expected[crypto_auth_hmacsha256_BYTES];
  rc = sign_hs256_input (signing_input, secret, secret_len, expected);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (sodium_memcmp (signature_data, expected, sizeof expected) != 0)
    return WYRELOG_E_POLICY;

  g_autoptr (GBytes) payload = NULL;
  rc = wyl_jwt_base64url_decode (parts[1], &payload);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_payload_json = g_steal_pointer (&payload);
  return WYRELOG_E_OK;
}

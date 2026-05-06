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

static gboolean
hex_value (gchar c, guint *out)
{
  if (c >= '0' && c <= '9')
    *out = (guint) (c - '0');
  else if (c >= 'a' && c <= 'f')
    *out = (guint) (c - 'a' + 10);
  else if (c >= 'A' && c <= 'F')
    *out = (guint) (c - 'A' + 10);
  else
    return FALSE;
  return TRUE;
}

static wyrelog_error_t
parse_json_string (const gchar **cursor, gchar **out_value)
{
  if (cursor == NULL || *cursor == NULL || out_value == NULL || **cursor != '"')
    return WYRELOG_E_INVALID;
  *out_value = NULL;

  const gchar *p = *cursor + 1;
  GString *value = g_string_new (NULL);
  while (*p != '\0' && *p != '"') {
    if ((guchar) * p < 0x20) {
      g_string_free (value, TRUE);
      return WYRELOG_E_POLICY;
    }
    if (*p != '\\') {
      g_string_append_c (value, *p++);
      continue;
    }

    p++;
    switch (*p) {
      case '"':
      case '\\':
      case '/':
        g_string_append_c (value, *p++);
        break;
      case 'b':
        g_string_append_c (value, '\b');
        p++;
        break;
      case 'f':
        g_string_append_c (value, '\f');
        p++;
        break;
      case 'n':
        g_string_append_c (value, '\n');
        p++;
        break;
      case 'r':
        g_string_append_c (value, '\r');
        p++;
        break;
      case 't':
        g_string_append_c (value, '\t');
        p++;
        break;
      case 'u':{
        guint h0, h1, h2, h3;
        for (guint i = 1; i <= 4; i++) {
          if (p[i] == '\0') {
            g_string_free (value, TRUE);
            return WYRELOG_E_POLICY;
          }
        }
        if (!hex_value (p[1], &h0) || !hex_value (p[2], &h1) ||
            !hex_value (p[3], &h2) || !hex_value (p[4], &h3)) {
          g_string_free (value, TRUE);
          return WYRELOG_E_POLICY;
        }
        guint codepoint = (h0 << 12) | (h1 << 8) | (h2 << 4) | h3;
        if (codepoint < 0x20 || codepoint > 0x7f) {
          g_string_free (value, TRUE);
          return WYRELOG_E_POLICY;
        }
        g_string_append_c (value, (gchar) codepoint);
        p += 5;
        break;
      }
      default:
        g_string_free (value, TRUE);
        return WYRELOG_E_POLICY;
    }
  }
  if (*p != '"') {
    g_string_free (value, TRUE);
    return WYRELOG_E_POLICY;
  }

  *cursor = p + 1;
  *out_value = g_string_free (value, FALSE);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
parse_json_uint64 (const gchar **cursor, gint64 *out_value)
{
  if (cursor == NULL || *cursor == NULL || out_value == NULL ||
      !g_ascii_isdigit (**cursor))
    return WYRELOG_E_INVALID;

  gint64 value = 0;
  const gchar *p = *cursor;
  while (g_ascii_isdigit (*p)) {
    gint digit = *p - '0';
    if (value > (G_MAXINT64 - digit) / 10)
      return WYRELOG_E_POLICY;
    value = value * 10 + digit;
    p++;
  }

  *cursor = p;
  *out_value = value;
  return WYRELOG_E_OK;
}

static void
skip_json_ws (const gchar **cursor)
{
  while (g_ascii_isspace (**cursor))
    (*cursor)++;
}

typedef struct
{
  wyl_jwt_access_claims_t claims;
  guint seen_mask;
} ParsedJwtClaims;

enum
{
  CLAIM_JTI = 1u << 0,
  CLAIM_SUB = 1u << 1,
  CLAIM_ISS = 1u << 2,
  CLAIM_AUD = 1u << 3,
  CLAIM_IAT = 1u << 4,
  CLAIM_NBF = 1u << 5,
  CLAIM_EXP = 1u << 6,
  CLAIM_TENANT = 1u << 7,
  CLAIM_PRINCIPAL_STATE = 1u << 8,
  CLAIM_SESSION_ID = 1u << 9,
  CLAIM_REQUIRED_MASK = (1u << 10) - 1,
};

static void
parsed_jwt_claims_clear (ParsedJwtClaims *claims)
{
  wyl_jwt_access_claims_clear (&claims->claims);
  memset (claims, 0, sizeof *claims);
}

void
wyl_jwt_access_claims_clear (wyl_jwt_access_claims_t *claims)
{
  if (claims == NULL)
    return;
  g_free (claims->jti);
  g_free (claims->subject);
  g_free (claims->issuer);
  g_free (claims->audience);
  g_free (claims->tenant);
  g_free (claims->principal_state_at_issue);
  g_free (claims->session_id);
  memset (claims, 0, sizeof *claims);
}

static wyrelog_error_t
mark_claim_seen (ParsedJwtClaims *claims, guint bit)
{
  if ((claims->seen_mask & bit) != 0)
    return WYRELOG_E_POLICY;
  claims->seen_mask |= bit;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
parse_string_claim_value (const gchar **cursor, ParsedJwtClaims *claims,
    guint bit, gchar **out_value)
{
  wyrelog_error_t rc = mark_claim_seen (claims, bit);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *value = NULL;
  rc = parse_json_string (cursor, &value);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (value[0] == '\0')
    return WYRELOG_E_POLICY;
  if (out_value != NULL)
    *out_value = g_steal_pointer (&value);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
parse_int_claim_value (const gchar **cursor, ParsedJwtClaims *claims,
    guint bit, gint64 *out_value)
{
  wyrelog_error_t rc = mark_claim_seen (claims, bit);
  if (rc != WYRELOG_E_OK)
    return rc;
  return parse_json_uint64 (cursor, out_value);
}

static wyrelog_error_t
parse_jwt_payload_claims (const gchar *payload, ParsedJwtClaims *claims)
{
  if (payload == NULL || claims == NULL)
    return WYRELOG_E_INVALID;
  memset (claims, 0, sizeof *claims);

  const gchar *p = payload;
  skip_json_ws (&p);
  if (*p++ != '{')
    return WYRELOG_E_POLICY;
  skip_json_ws (&p);
  while (*p != '}') {
    g_autofree gchar *key = NULL;
    wyrelog_error_t rc = parse_json_string (&p, &key);
    if (rc != WYRELOG_E_OK)
      return rc;
    skip_json_ws (&p);
    if (*p++ != ':')
      return WYRELOG_E_POLICY;
    skip_json_ws (&p);

    if (g_strcmp0 (key, "jti") == 0)
      rc = parse_string_claim_value (&p, claims, CLAIM_JTI,
          &claims->claims.jti);
    else if (g_strcmp0 (key, "sub") == 0)
      rc = parse_string_claim_value (&p, claims, CLAIM_SUB,
          &claims->claims.subject);
    else if (g_strcmp0 (key, "iss") == 0)
      rc = parse_string_claim_value (&p, claims, CLAIM_ISS,
          &claims->claims.issuer);
    else if (g_strcmp0 (key, "aud") == 0)
      rc = parse_string_claim_value (&p, claims, CLAIM_AUD,
          &claims->claims.audience);
    else if (g_strcmp0 (key, "iat") == 0) {
      gint64 ignored = 0;
      rc = parse_int_claim_value (&p, claims, CLAIM_IAT, &ignored);
    } else if (g_strcmp0 (key, "nbf") == 0)
      rc = parse_int_claim_value (&p, claims, CLAIM_NBF,
          &claims->claims.not_before);
    else if (g_strcmp0 (key, "exp") == 0)
      rc = parse_int_claim_value (&p, claims, CLAIM_EXP,
          &claims->claims.expires_at);
    else if (g_strcmp0 (key, "tenant") == 0)
      rc = parse_string_claim_value (&p, claims, CLAIM_TENANT,
          &claims->claims.tenant);
    else if (g_strcmp0 (key, "principal_state_at_issue") == 0)
      rc = parse_string_claim_value (&p, claims, CLAIM_PRINCIPAL_STATE,
          &claims->claims.principal_state_at_issue);
    else if (g_strcmp0 (key, "session_id") == 0)
      rc = parse_string_claim_value (&p, claims, CLAIM_SESSION_ID,
          &claims->claims.session_id);
    else
      return WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      return rc;

    skip_json_ws (&p);
    if (*p == ',') {
      p++;
      skip_json_ws (&p);
      if (*p == '}')
        return WYRELOG_E_POLICY;
    } else if (*p != '}') {
      return WYRELOG_E_POLICY;
    }
  }
  p++;
  skip_json_ws (&p);
  if (*p != '\0')
    return WYRELOG_E_POLICY;
  if ((claims->seen_mask & CLAIM_REQUIRED_MASK) != CLAIM_REQUIRED_MASK)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_parse_access_claims_json (GBytes *payload_json,
    wyl_jwt_access_claims_t *out_claims)
{
  if (payload_json == NULL || out_claims == NULL)
    return WYRELOG_E_INVALID;
  memset (out_claims, 0, sizeof *out_claims);

  gsize payload_len = 0;
  const gchar *payload_data = g_bytes_get_data (payload_json, &payload_len);
  if (memchr (payload_data, '\0', payload_len) != NULL)
    return WYRELOG_E_POLICY;
  g_autofree gchar *payload_text = g_strndup (payload_data, payload_len);
  ParsedJwtClaims claims = { 0 };
  wyrelog_error_t rc = parse_jwt_payload_claims (payload_text, &claims);
  if (rc != WYRELOG_E_OK) {
    parsed_jwt_claims_clear (&claims);
    return rc;
  }

  *out_claims = claims.claims;
  memset (&claims, 0, sizeof claims);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_jwt_verify_hs256_access_token (const gchar *token, const guint8 *secret,
    gsize secret_len, const gchar *expected_issuer,
    const gchar *expected_audience, gint64 now, GBytes **out_payload_json)
{
  if (!non_empty (expected_issuer) || !non_empty (expected_audience) ||
      now < 0 || out_payload_json == NULL)
    return WYRELOG_E_INVALID;
  *out_payload_json = NULL;

  g_autoptr (GBytes) payload = NULL;
  wyrelog_error_t rc = wyl_jwt_verify_hs256_signature (token, secret,
      secret_len, &payload);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_jwt_access_claims_t claims = { 0 };
  rc = wyl_jwt_parse_access_claims_json (payload, &claims);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean claims_valid = g_strcmp0 (claims.issuer, expected_issuer) == 0
      && g_strcmp0 (claims.audience, expected_audience) == 0
      && now >= claims.not_before && now < claims.expires_at;
  wyl_jwt_access_claims_clear (&claims);
  if (!claims_valid)
    return WYRELOG_E_POLICY;

  *out_payload_json = g_steal_pointer (&payload);
  return WYRELOG_E_OK;
}

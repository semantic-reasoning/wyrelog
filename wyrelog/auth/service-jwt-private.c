/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/jwt-private.h"

#include <sodium.h>
#include <string.h>

#include "auth/service-credential-private.h"
#include "policy/store-private.h"
#include "wyl-id-private.h"

static gboolean
canonical_id_text (const gchar *value)
{
  wyl_id_t parsed;
  gchar encoded[WYL_ID_STRING_BUF];
  return value != NULL && wyl_id_parse (value, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, encoded, sizeof encoded) == WYRELOG_E_OK
      && strcmp (value, encoded) == 0;
}

static gboolean
valid_input (const wyl_jwt_service_issue_input_t *input)
{
  return input != NULL && input->key_id != NULL && input->key_id[0] != '\0'
      && canonical_id_text (input->jti)
      && canonical_id_text (input->session_id) && input->issuer != NULL
      && input->issuer[0] != '\0' && input->audience != NULL
      && input->audience[0] != '\0' && input->subject != NULL
      && wyl_policy_service_subject_is_valid (input->subject,
      strlen (input->subject)) && input->tenant != NULL
      && wyl_policy_store_tenant_id_is_valid (input->tenant)
      && input->credential_id != NULL
      && wyl_service_credential_id_is_canonical (input->credential_id,
      strlen (input->credential_id)) && input->credential_generation != 0
      && input->issued_at >= 0 && input->issued_at <= G_MAXINT64
      - WYL_JWT_SERVICE_ACCESS_TTL_SECONDS;
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

wyrelog_error_t
wyl_jwt_sign_hs256_service (const wyl_jwt_service_issue_input_t *input,
    const guint8 *secret, gsize secret_len, gchar **out_token)
{
  if (out_token == NULL || secret == NULL || secret_len == 0)
    return WYRELOG_E_INVALID;
  *out_token = NULL;
  if (!valid_input (input))
    return WYRELOG_E_INVALID;

  g_autofree gchar *header = NULL;
  wyrelog_error_t rc = wyl_jwt_build_header_json (input->key_id, &header);
  if (rc != WYRELOG_E_OK)
    return rc;
  GString *payload = g_string_new ("{\"jti\":");
#define APPEND_STRING_CLAIM(name, value) G_STMT_START { \
  g_string_append (payload, name); append_json_string (payload, value); \
} G_STMT_END
  append_json_string (payload, input->jti);
  APPEND_STRING_CLAIM (",\"sub\":", input->subject);
  APPEND_STRING_CLAIM (",\"iss\":", input->issuer);
  APPEND_STRING_CLAIM (",\"aud\":", input->audience);
  g_string_append_printf (payload,
      ",\"iat\":%" G_GINT64_FORMAT ",\"nbf\":%" G_GINT64_FORMAT
      ",\"exp\":%" G_GINT64_FORMAT, input->issued_at, input->issued_at,
      input->issued_at + WYL_JWT_SERVICE_ACCESS_TTL_SECONDS);
  APPEND_STRING_CLAIM (",\"tenant\":", input->tenant);
  g_string_append (payload, ",\"principal_state_at_issue\":\"authenticated\"");
  APPEND_STRING_CLAIM (",\"session_id\":", input->session_id);
  g_string_append (payload, ",\"auth_method\":\"service_credential\"");
  APPEND_STRING_CLAIM (",\"credential_id\":", input->credential_id);
#undef APPEND_STRING_CLAIM
  g_string_append_printf (payload, ",\"credential_generation\":%"
      G_GUINT64_FORMAT "}", input->credential_generation);

  g_autofree gchar *header_segment = NULL, *payload_segment = NULL;
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

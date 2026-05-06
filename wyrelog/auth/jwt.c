/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/jwt-private.h"

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

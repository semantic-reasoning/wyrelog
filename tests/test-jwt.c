/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/auth/jwt-private.h"

static const wyl_jwt_issue_input_t valid_input = {
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

  if (wyl_jwt_base64url_decode ("abc=", &decoded) != WYRELOG_E_INVALID)
    return 14;
  if (wyl_jwt_base64url_decode ("a", &decoded) != WYRELOG_E_INVALID)
    return 15;
  if (wyl_jwt_base64url_encode (NULL, 1, &encoded) != WYRELOG_E_INVALID)
    return 16;
  return 0;
}

static gint
check_header_json_is_fixed (void)
{
  g_autofree gchar *header = NULL;
  if (wyl_jwt_build_header_json (&header) != WYRELOG_E_OK)
    return 20;
  if (g_strcmp0 (header, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}") != 0)
    return 21;
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
  if (header_len != strlen ("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") ||
      memcmp (header, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", header_len) != 0)
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
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_base64url_round_trip ()) != 0)
    return rc;
  if ((rc = check_header_json_is_fixed ()) != 0)
    return rc;
  if ((rc = check_payload_json_contains_required_claims ()) != 0)
    return rc;
  if ((rc = check_payload_json_escapes_strings ()) != 0)
    return rc;
  if ((rc = check_payload_rejects_missing_claims ()) != 0)
    return rc;
  if ((rc = check_unsigned_segments_are_base64url ()) != 0)
    return rc;
  return 0;
}

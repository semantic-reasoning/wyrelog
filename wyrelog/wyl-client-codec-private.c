/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyl-client-codec-private.h"

#include <sodium.h>
#include <string.h>

#include "wyrelog/auth/service-credential-private.h"

#define WYL_CLIENT_CODEC_MAX_DOCUMENT (16u * 1024u)
#define WYL_CLIENT_CODEC_MAX_STRING (4096u)

typedef struct
{
  const gchar *data;
  gsize len;
  gsize pos;
} JsonCursor;

static void
skip_ws (JsonCursor *cursor)
{
  while (cursor->pos < cursor->len
      && g_ascii_isspace ((guchar) cursor->data[cursor->pos]))
    cursor->pos++;
}

static gboolean
take (JsonCursor *cursor, gchar expected)
{
  skip_ws (cursor);
  if (cursor->pos >= cursor->len || cursor->data[cursor->pos] != expected)
    return FALSE;
  cursor->pos++;
  return TRUE;
}

static gboolean
hex_digit (gchar value, guint *out)
{
  if (value >= '0' && value <= '9') {
    *out = (guint) (value - '0');
    return TRUE;
  }
  if (value >= 'a' && value <= 'f') {
    *out = (guint) (value - 'a' + 10);
    return TRUE;
  }
  if (value >= 'A' && value <= 'F') {
    *out = (guint) (value - 'A' + 10);
    return TRUE;
  }
  return FALSE;
}

static gboolean
parse_string (JsonCursor *cursor, gchar **out)
{
  g_autoptr (GString) value = NULL;
  if (out == NULL || !take (cursor, '"'))
    return FALSE;
  value = g_string_new (NULL);
  if (value == NULL)
    return FALSE;

  while (cursor->pos < cursor->len) {
    const gchar current = cursor->data[cursor->pos++];
    if (current == '"') {
      if (!g_utf8_validate (value->str, value->len, NULL))
        return FALSE;
      *out = g_string_free (g_steal_pointer (&value), FALSE);
      return *out != NULL;
    }
    if ((guchar) current < 0x20)
      return FALSE;
    if (current != '\\') {
      if (value->len >= WYL_CLIENT_CODEC_MAX_STRING)
        return FALSE;
      g_string_append_c (value, current);
      continue;
    }
    if (cursor->pos >= cursor->len)
      return FALSE;
    switch (cursor->data[cursor->pos++]) {
      case '"':
      case '\\':
      case '/':
        g_string_append_c (value, cursor->data[cursor->pos - 1]);
        break;
      case 'b':
        g_string_append_c (value, '\b');
        break;
      case 'f':
        g_string_append_c (value, '\f');
        break;
      case 'n':
        g_string_append_c (value, '\n');
        break;
      case 'r':
        g_string_append_c (value, '\r');
        break;
      case 't':
        g_string_append_c (value, '\t');
        break;
      case 'u':{
        guint codepoint = 0;
        for (guint i = 0; i < 4; i++) {
          guint digit = 0;
          if (cursor->pos >= cursor->len
              || !hex_digit (cursor->data[cursor->pos++], &digit))
            return FALSE;
          codepoint = (codepoint << 4) | digit;
        }
        if (codepoint > 0x7f || codepoint < 0x20
            || value->len >= WYL_CLIENT_CODEC_MAX_STRING)
          return FALSE;
        g_string_append_c (value, (gchar) codepoint);
        break;
      }
      default:
        return FALSE;
    }
    if (value->len > WYL_CLIENT_CODEC_MAX_STRING)
      return FALSE;
  }
  return FALSE;
}

static gboolean
parse_uint64 (JsonCursor *cursor, guint64 *out)
{
  guint64 value = 0;
  gsize digits = 0;
  skip_ws (cursor);
  if (cursor->pos < cursor->len && cursor->data[cursor->pos] == '0'
      && cursor->pos + 1 < cursor->len
      && g_ascii_isdigit ((guchar) cursor->data[cursor->pos + 1]))
    return FALSE;
  while (cursor->pos < cursor->len
      && g_ascii_isdigit ((guchar) cursor->data[cursor->pos])) {
    const guint digit = (guint) (cursor->data[cursor->pos++] - '0');
    if (value > (G_MAXUINT64 - digit) / 10)
      return FALSE;
    value = value * 10 + digit;
    digits++;
  }
  if (digits == 0)
    return FALSE;
  *out = value;
  return TRUE;
}

static gboolean
string_is_plain_token (const gchar *value)
{
  if (value == NULL || value[0] == '\0'
      || strlen (value) > WYL_CLIENT_CODEC_MAX_STRING)
    return FALSE;
  for (const guchar * p = (const guchar *)value; *p != '\0'; p++)
    if (g_ascii_iscntrl (*p) || g_ascii_isspace (*p))
      return FALSE;
  return TRUE;
}

static gboolean
credential_secret_is_valid (const gchar *value)
{
  static const gchar allowed[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  return value != NULL
      && strlen (value) == WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN
      && strspn (value, allowed) == WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN;
}

void
wyl_client_sensitive_text_clear (WylClientSensitiveText *value)
{
  if (value == NULL)
    return;
  if (value->text != NULL && value->len != 0)
    sodium_memzero (value->text, value->len);
  g_clear_pointer (&value->text, g_free);
  value->len = 0;
}

void wyl_client_service_credential_issue_result_clear
    (WylClientServiceCredentialIssueResult * value)
{
  if (value == NULL)
    return;
  g_clear_pointer (&value->credential_id, g_free);
  wyl_client_sensitive_text_clear (&value->credential_secret);
  value->generation = 0;
}

void
wyl_client_service_token_result_clear (WylClientServiceTokenResult *value)
{
  if (value == NULL)
    return;
  wyl_client_sensitive_text_clear (&value->access_token);
}

static gboolean
document_init (const gchar *document, gsize document_len, JsonCursor *cursor)
{
  if (document == NULL || cursor == NULL || document_len == 0
      || document_len > WYL_CLIENT_CODEC_MAX_DOCUMENT
      || memchr (document, '\0', document_len) != NULL)
    return FALSE;
  *cursor = (JsonCursor) {
  document, document_len, 0};
  return TRUE;
}

static gboolean
document_done (JsonCursor *cursor)
{
  skip_ws (cursor);
  return cursor->pos == cursor->len;
}

wyrelog_error_t
wyl_client_service_token_result_decode (const gchar *document,
    gsize document_len, WylClientServiceTokenResult *out_result)
{
  JsonCursor cursor;
  gchar *key = NULL;
  gchar *access_token = NULL;
  gboolean seen_access_token = FALSE;
  if (out_result == NULL || !document_init (document, document_len, &cursor)
      || !take (&cursor, '{')) {
    if (out_result != NULL)
      wyl_client_service_token_result_clear (out_result);
    return WYRELOG_E_INVALID;
  }
  wyl_client_service_token_result_clear (out_result);
  skip_ws (&cursor);
  if (take (&cursor, '}'))
    return WYRELOG_E_INVALID;
  while (TRUE) {
    g_clear_pointer (&key, g_free);
    if (!parse_string (&cursor, &key) || !take (&cursor, ':'))
      goto invalid;
    if (g_strcmp0 (key, "access_token") != 0 || seen_access_token
        || !parse_string (&cursor, &access_token)
        || !string_is_plain_token (access_token))
      goto invalid;
    seen_access_token = TRUE;
    if (take (&cursor, '}'))
      break;
    if (!take (&cursor, ','))
      goto invalid;
  }
  if (!seen_access_token || !document_done (&cursor))
    goto invalid;
  out_result->access_token.text = g_steal_pointer (&access_token);
  out_result->access_token.len = strlen (out_result->access_token.text);
  g_free (key);
  return WYRELOG_E_OK;
invalid:
  g_free (key);
  if (access_token != NULL) {
    sodium_memzero (access_token, strlen (access_token));
    g_free (access_token);
  }
  wyl_client_service_token_result_clear (out_result);
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
wyl_client_service_credential_issue_result_decode (const gchar *document,
    gsize document_len, WylClientServiceCredentialIssueResult *out_result)
{
  JsonCursor cursor;
  gchar *key = NULL;
  gchar *credential_id = NULL;
  gchar *credential_secret = NULL;
  guint64 generation = 0;
  gboolean seen_outer = FALSE;
  gboolean seen_id = FALSE;
  gboolean seen_generation = FALSE;
  gboolean seen_secret = FALSE;
  if (out_result == NULL || !document_init (document, document_len, &cursor)
      || !take (&cursor, '{')) {
    if (out_result != NULL)
      wyl_client_service_credential_issue_result_clear (out_result);
    return WYRELOG_E_INVALID;
  }
  wyl_client_service_credential_issue_result_clear (out_result);
  skip_ws (&cursor);
  if (!parse_string (&cursor, &key)
      || g_strcmp0 (key, "service_credential") != 0 || !take (&cursor, ':')
      || !take (&cursor, '{'))
    goto invalid;
  seen_outer = TRUE;
  g_clear_pointer (&key, g_free);
  while (TRUE) {
    if (!parse_string (&cursor, &key) || !take (&cursor, ':'))
      goto invalid;
    if (g_strcmp0 (key, "credential_id") == 0) {
      if (seen_id || !parse_string (&cursor, &credential_id)
          || !string_is_plain_token (credential_id)
          || !wyl_service_credential_id_is_canonical (credential_id,
              strlen (credential_id)))
        goto invalid;
      seen_id = TRUE;
    } else if (g_strcmp0 (key, "generation") == 0) {
      if (seen_generation || !parse_uint64 (&cursor, &generation))
        goto invalid;
      seen_generation = TRUE;
    } else if (g_strcmp0 (key, "credential_secret") == 0) {
      if (seen_secret || !parse_string (&cursor, &credential_secret)
          || !credential_secret_is_valid (credential_secret))
        goto invalid;
      seen_secret = TRUE;
    } else {
      goto invalid;
    }
    g_clear_pointer (&key, g_free);
    if (take (&cursor, '}'))
      break;
    if (!take (&cursor, ','))
      goto invalid;
  }
  if (!take (&cursor, '}') || !seen_outer || !seen_id || !seen_generation
      || !seen_secret || generation == 0 || !document_done (&cursor))
    goto invalid;
  out_result->credential_id = g_steal_pointer (&credential_id);
  out_result->generation = generation;
  out_result->credential_secret.text = g_steal_pointer (&credential_secret);
  out_result->credential_secret.len = strlen
      (out_result->credential_secret.text);
  g_free (key);
  return WYRELOG_E_OK;
invalid:
  g_free (key);
  g_free (credential_id);
  if (credential_secret != NULL) {
    sodium_memzero (credential_secret, strlen (credential_secret));
    g_free (credential_secret);
  }
  wyl_client_service_credential_issue_result_clear (out_result);
  return WYRELOG_E_INVALID;
}

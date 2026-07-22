/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyl-client-codec-private.h"

#include <sodium.h>
#include <string.h>

#include "wyrelog/auth/service-credential-operation-destination-private.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-request-id-private.h"

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
parse_int64 (JsonCursor *cursor, gint64 *out)
{
  gboolean negative = FALSE;
  guint64 magnitude = 0;
  skip_ws (cursor);
  if (cursor->pos < cursor->len && cursor->data[cursor->pos] == '-') {
    negative = TRUE;
    cursor->pos++;
  }
  if (!parse_uint64 (cursor, &magnitude)
      || (negative && magnitude > (guint64) G_MAXINT64 + 1)
      || (!negative && magnitude > G_MAXINT64))
    return FALSE;
  if (negative && magnitude == (guint64) G_MAXINT64 + 1)
    *out = G_MININT64;
  else
    *out = negative ? -(gint64) magnitude : (gint64) magnitude;
  return TRUE;
}

static gboolean
parse_nullable_string (JsonCursor *cursor, gchar **out)
{
  skip_ws (cursor);
  if (cursor->pos + 4 <= cursor->len
      && memcmp (cursor->data + cursor->pos, "null", 4) == 0) {
    cursor->pos += 4;
    *out = NULL;
    return TRUE;
  }
  return parse_string (cursor, out);
}

/* Consumes a bare true/false literal.  A trailing non-delimiter (e.g. "truex")
 * is rejected by the caller's subsequent take(',')/take('}'), which requires a
 * value separator or object end immediately after the token. */
static gboolean
parse_bool (JsonCursor *cursor, gboolean *out)
{
  skip_ws (cursor);
  if (cursor->pos + 4 <= cursor->len
      && memcmp (cursor->data + cursor->pos, "true", 4) == 0) {
    cursor->pos += 4;
    *out = TRUE;
    return TRUE;
  }
  if (cursor->pos + 5 <= cursor->len
      && memcmp (cursor->data + cursor->pos, "false", 5) == 0) {
    cursor->pos += 5;
    *out = FALSE;
    return TRUE;
  }
  return FALSE;
}

static gboolean
string_is_request_id (const gchar *value)
{
  if (value == NULL || strlen (value) != WYL_REQUEST_ID_STRING_LEN)
    return FALSE;
  for (const guchar * p = (const guchar *)value; *p != '\0'; p++)
    if (!g_ascii_isalnum (*p))
      return FALSE;
  return TRUE;
}

static gboolean
handoff_state_is_known (const gchar *value)
{
  static const gchar *const states[] = {
    "prepared", "server_committed", "publication_planned",
    "publication_prepared", "file_published", "cleanup_required",
    "operator_action_required", "terminal", "unknown"
  };
  if (value == NULL)
    return FALSE;
  for (gsize i = 0; i < G_N_ELEMENTS (states); i++)
    if (g_strcmp0 (value, states[i]) == 0)
      return TRUE;
  return FALSE;
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
string_is_display_name (const gchar *value)
{
  if (value == NULL || value[0] == '\0'
      || strlen (value) > WYL_CLIENT_CODEC_MAX_STRING
      || !g_utf8_validate (value, -1, NULL))
    return FALSE;
  for (const guchar * p = (const guchar *)value; *p != '\0'; p++)
    if (g_ascii_iscntrl (*p))
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

void wyl_client_service_credential_handoff_receipt_clear
    (WylClientServiceCredentialHandoffReceipt * value)
{
  if (value == NULL)
    return;
  g_clear_pointer (&value->state, g_free);
  g_clear_pointer (&value->request_id, g_free);
  g_clear_pointer (&value->credential_id, g_free);
  g_clear_pointer (&value->destination, g_free);
  g_clear_pointer (&value->publication_receipt_id, g_free);
  value->generation = 0;
  value->delivered = FALSE;
}

void
wyl_client_service_token_result_clear (WylClientServiceTokenResult *value)
{
  if (value == NULL)
    return;
  wyl_client_sensitive_text_clear (&value->access_token);
}

void
wyl_client_service_principal_clear (WylClientServicePrincipal *value)
{
  if (value == NULL)
    return;
  g_clear_pointer (&value->subject_id, g_free);
  g_clear_pointer (&value->display_name, g_free);
  g_clear_pointer (&value->state, g_free);
}

void wyl_client_service_principal_list_clear
    (WylClientServicePrincipalList * value)
{
  if (value == NULL)
    return;
  for (gsize i = 0; i < value->len; i++)
    wyl_client_service_principal_clear (&value->items[i]);
  g_clear_pointer (&value->items, g_free);
  value->len = 0;
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

static gboolean
parse_principal_object (JsonCursor *cursor, WylClientServicePrincipal *out)
{
  gchar *key = NULL;
  gboolean seen_subject = FALSE;
  gboolean seen_display = FALSE;
  gboolean seen_state = FALSE;
  if (out == NULL || !take (cursor, '{'))
    return FALSE;
  wyl_client_service_principal_clear (out);
  while (TRUE) {
    g_clear_pointer (&key, g_free);
    if (!parse_string (cursor, &key) || !take (cursor, ':'))
      goto invalid;
    if (g_strcmp0 (key, "subject_id") == 0) {
      if (seen_subject || !parse_string (cursor, &out->subject_id)
          || !string_is_plain_token (out->subject_id))
        goto invalid;
      seen_subject = TRUE;
    } else if (g_strcmp0 (key, "display_name") == 0) {
      if (seen_display || !parse_string (cursor, &out->display_name)
          || !string_is_display_name (out->display_name))
        goto invalid;
      seen_display = TRUE;
    } else if (g_strcmp0 (key, "state") == 0) {
      if (seen_state || !parse_string (cursor, &out->state)
          || !string_is_plain_token (out->state))
        goto invalid;
      seen_state = TRUE;
    } else {
      goto invalid;
    }
    if (take (cursor, '}'))
      break;
    if (!take (cursor, ','))
      goto invalid;
  }
  g_free (key);
  return seen_subject && seen_display && seen_state;
invalid:
  g_free (key);
  wyl_client_service_principal_clear (out);
  return FALSE;
}

wyrelog_error_t
wyl_client_service_principal_decode (const gchar *document,
    gsize document_len, WylClientServicePrincipal *out_principal)
{
  JsonCursor cursor;
  gchar *key = NULL;
  if (out_principal == NULL)
    return WYRELOG_E_INVALID;
  wyl_client_service_principal_clear (out_principal);
  if (!document_init (document, document_len, &cursor))
    return WYRELOG_E_INVALID;
  if (!take (&cursor, '{') || !parse_string (&cursor, &key)
      || g_strcmp0 (key, "service_principal") != 0 || !take (&cursor, ':'))
    goto invalid;
  g_free (key);
  key = NULL;
  if (!parse_principal_object (&cursor, out_principal)
      || !take (&cursor, '}') || !document_done (&cursor))
    goto invalid;
  return WYRELOG_E_OK;
invalid:
  g_free (key);
  wyl_client_service_principal_clear (out_principal);
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
wyl_client_service_principal_list_decode (const gchar *document,
    gsize document_len, WylClientServicePrincipalList *out_principals)
{
  JsonCursor cursor;
  gchar *key = NULL;
  GArray *items = NULL;
  if (out_principals == NULL)
    return WYRELOG_E_INVALID;
  wyl_client_service_principal_list_clear (out_principals);
  if (!document_init (document, document_len, &cursor))
    return WYRELOG_E_INVALID;
  if (!take (&cursor, '{') || !parse_string (&cursor, &key)
      || g_strcmp0 (key, "service_principals") != 0 || !take (&cursor, ':')
      || !take (&cursor, '['))
    goto invalid;
  g_clear_pointer (&key, g_free);
  items = g_array_new (FALSE, TRUE, sizeof (WylClientServicePrincipal));
  if (items == NULL)
    goto invalid;
  skip_ws (&cursor);
  if (!take (&cursor, ']')) {
    while (TRUE) {
      WylClientServicePrincipal principal = { 0 };
      if (!parse_principal_object (&cursor, &principal))
        goto invalid;
      g_array_append_val (items, principal);
      if (take (&cursor, ']'))
        break;
      if (!take (&cursor, ','))
        goto invalid;
    }
  }
  if (!take (&cursor, '}') || !document_done (&cursor))
    goto invalid;
  out_principals->len = items->len;
  out_principals->items = (WylClientServicePrincipal *)
      g_array_free (g_steal_pointer (&items), FALSE);
  return WYRELOG_E_OK;
invalid:
  g_free (key);
  if (items != NULL) {
    for (gsize i = 0; i < items->len; i++)
      wyl_client_service_principal_clear
          (&g_array_index (items, WylClientServicePrincipal, i));
    g_array_free (items, TRUE);
  }
  wyl_client_service_principal_list_clear (out_principals);
  return WYRELOG_E_INVALID;
}

void
wyl_client_service_credential_clear (WylClientServiceCredential *value)
{
  if (value == NULL)
    return;
  g_clear_pointer (&value->credential_id, g_free);
  g_clear_pointer (&value->subject_id, g_free);
  g_clear_pointer (&value->tenant_id, g_free);
  g_clear_pointer (&value->state, g_free);
  g_clear_pointer (&value->created_by, g_free);
  g_clear_pointer (&value->revoked_by, g_free);
  g_clear_pointer (&value->rotated_from_id, g_free);
  memset (value, 0, sizeof *value);
}

void wyl_client_service_credential_list_clear
    (WylClientServiceCredentialList * value)
{
  if (value == NULL)
    return;
  for (gsize i = 0; i < value->len; i++)
    wyl_client_service_credential_clear (&value->items[i]);
  g_clear_pointer (&value->items, g_free);
  value->len = 0;
}

static gboolean
parse_credential_object (JsonCursor *cursor, WylClientServiceCredential *out,
    gchar **out_secret)
{
  gchar *key = NULL;
  gboolean seen[15] = { FALSE };
  if (out_secret != NULL)
    *out_secret = NULL;
  if (out == NULL || !take (cursor, '{'))
    return FALSE;
  wyl_client_service_credential_clear (out);
  while (TRUE) {
    g_clear_pointer (&key, g_free);
    if (!parse_string (cursor, &key) || !take (cursor, ':'))
      goto invalid;
    guint field = 0;
    if (g_strcmp0 (key, "credential_id") == 0)
      field = 1;
    else if (g_strcmp0 (key, "credential_format_version") == 0)
      field = 2;
    else if (g_strcmp0 (key, "subject_id") == 0)
      field = 3;
    else if (g_strcmp0 (key, "tenant_id") == 0)
      field = 4;
    else if (g_strcmp0 (key, "generation") == 0)
      field = 5;
    else if (g_strcmp0 (key, "state") == 0)
      field = 6;
    else if (g_strcmp0 (key, "created_by") == 0)
      field = 7;
    else if (g_strcmp0 (key, "created_at_us") == 0)
      field = 8;
    else if (g_strcmp0 (key, "updated_at_us") == 0)
      field = 9;
    else if (g_strcmp0 (key, "expires_at_us") == 0)
      field = 10;
    else if (g_strcmp0 (key, "last_used_at_us") == 0)
      field = 11;
    else if (g_strcmp0 (key, "revoked_by") == 0)
      field = 12;
    else if (g_strcmp0 (key, "revoked_at_us") == 0)
      field = 13;
    else if (g_strcmp0 (key, "rotated_from_id") == 0)
      field = 14;
    else if (g_strcmp0 (key, "credential_secret") == 0)
      field = 15;
    else
      goto invalid;
    if (seen[field - 1])
      goto invalid;
    seen[field - 1] = TRUE;
    switch (field) {
      case 1:
        if (!parse_string (cursor, &out->credential_id)
            || !wyl_service_credential_id_is_canonical
            (out->credential_id, strlen (out->credential_id)))
          goto invalid;
        break;
      case 2:{
        guint64 version = 0;
        if (!parse_uint64 (cursor, &version) || version != 1)
          goto invalid;
        out->credential_format_version = (guint32) version;
        break;
      }
      case 3:
        if (!parse_string (cursor, &out->subject_id)
            || !wyl_policy_service_subject_is_valid (out->subject_id,
                strlen (out->subject_id)))
          goto invalid;
        break;
      case 4:
        if (!parse_string (cursor, &out->tenant_id)
            || !string_is_plain_token (out->tenant_id))
          goto invalid;
        break;
      case 5:
        if (!parse_uint64 (cursor, &out->generation) || out->generation == 0)
          goto invalid;
        break;
      case 6:
        if (!parse_string (cursor, &out->state)
            || (g_strcmp0 (out->state, "active") != 0
                && g_strcmp0 (out->state, "revoked") != 0))
          goto invalid;
        break;
      case 7:
        if (!parse_string (cursor, &out->created_by)
            || !string_is_plain_token (out->created_by))
          goto invalid;
        break;
      case 8:
        if (!parse_int64 (cursor, &out->created_at_us))
          goto invalid;
        break;
      case 9:
        if (!parse_int64 (cursor, &out->updated_at_us))
          goto invalid;
        break;
      case 10:
        if (!parse_int64 (cursor, &out->expires_at_us))
          goto invalid;
        break;
      case 11:
        if (!parse_int64 (cursor, &out->last_used_at_us))
          goto invalid;
        break;
      case 12:
        if (!parse_nullable_string (cursor, &out->revoked_by)
            || (out->revoked_by != NULL
                && !string_is_plain_token (out->revoked_by)))
          goto invalid;
        break;
      case 13:
        if (!parse_int64 (cursor, &out->revoked_at_us))
          goto invalid;
        break;
      case 14:
        if (!parse_nullable_string (cursor, &out->rotated_from_id)
            || (out->rotated_from_id != NULL
                && !wyl_service_credential_id_is_canonical
                (out->rotated_from_id, strlen (out->rotated_from_id))))
          goto invalid;
        break;
      case 15:
        if (out_secret == NULL || !parse_string (cursor, out_secret)
            || !credential_secret_is_valid (*out_secret))
          goto invalid;
        break;
    }
    if (take (cursor, '}'))
      break;
    if (!take (cursor, ','))
      goto invalid;
  }
  g_free (key);
  for (guint i = 0; i < 14; i++)
    if (!seen[i])
      goto invalid_no_key;
  if (out_secret != NULL && !seen[14])
    goto invalid_no_key;
  return TRUE;
invalid:
  g_free (key);
invalid_no_key:
  if (out_secret != NULL && *out_secret != NULL) {
    sodium_memzero (*out_secret, strlen (*out_secret));
    g_clear_pointer (out_secret, g_free);
  }
  wyl_client_service_credential_clear (out);
  return FALSE;
}

static wyrelog_error_t
credential_document_decode (const gchar *document, gsize document_len,
    const gchar *wrapper, WylClientServiceCredential *out)
{
  JsonCursor cursor;
  gchar *key = NULL;
  if (out == NULL)
    return WYRELOG_E_INVALID;
  wyl_client_service_credential_clear (out);
  if (!document_init (document, document_len, &cursor) || !take (&cursor, '{')
      || !parse_string (&cursor, &key) || g_strcmp0 (key, wrapper) != 0
      || !take (&cursor, ':') || !parse_credential_object (&cursor, out, NULL)
      || !take (&cursor, '}') || !document_done (&cursor))
    goto invalid;
  g_free (key);
  return WYRELOG_E_OK;
invalid:
  g_free (key);
  wyl_client_service_credential_clear (out);
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
wyl_client_service_credential_decode (const gchar *document,
    gsize document_len, WylClientServiceCredential *out_credential)
{
  return credential_document_decode (document, document_len,
      "service_credential", out_credential);
}

wyrelog_error_t
wyl_client_service_credential_list_decode (const gchar *document,
    gsize document_len, WylClientServiceCredentialList *out_credentials)
{
  JsonCursor cursor;
  gchar *key = NULL;
  GArray *items = NULL;
  if (out_credentials == NULL)
    return WYRELOG_E_INVALID;
  wyl_client_service_credential_list_clear (out_credentials);
  if (!document_init (document, document_len, &cursor) || !take (&cursor, '{')
      || !parse_string (&cursor, &key)
      || g_strcmp0 (key, "service_credentials") != 0 || !take (&cursor, ':')
      || !take (&cursor, '['))
    goto invalid;
  g_clear_pointer (&key, g_free);
  items = g_array_new (FALSE, TRUE, sizeof (WylClientServiceCredential));
  if (items == NULL)
    goto invalid;
  if (!take (&cursor, ']')) {
    while (TRUE) {
      WylClientServiceCredential item = { 0 };
      if (!parse_credential_object (&cursor, &item, NULL))
        goto invalid;
      g_array_append_val (items, item);
      if (take (&cursor, ']'))
        break;
      if (!take (&cursor, ','))
        goto invalid;
    }
  }
  if (!take (&cursor, '}') || !document_done (&cursor))
    goto invalid;
  out_credentials->len = items->len;
  out_credentials->items = (WylClientServiceCredential *)
      g_array_free (g_steal_pointer (&items), FALSE);
  return WYRELOG_E_OK;
invalid:
  g_free (key);
  if (items != NULL) {
    for (gsize i = 0; i < items->len; i++)
      wyl_client_service_credential_clear
          (&g_array_index (items, WylClientServiceCredential, i));
    g_array_free (items, TRUE);
  }
  wyl_client_service_credential_list_clear (out_credentials);
  return WYRELOG_E_INVALID;
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
wyl_client_service_credential_handoff_receipt_decode (const gchar *document,
    gsize document_len, WylClientServiceCredentialHandoffReceipt *out_receipt)
{
  JsonCursor cursor;
  gchar *key = NULL;
  gboolean seen_state = FALSE;
  gboolean seen_request_id = FALSE;
  gboolean seen_credential_id = FALSE;
  gboolean seen_generation = FALSE;
  gboolean seen_destination = FALSE;
  gboolean seen_publication_receipt_id = FALSE;
  gboolean seen_delivered = FALSE;
  if (out_receipt == NULL || !document_init (document, document_len, &cursor)
      || !take (&cursor, '{')) {
    if (out_receipt != NULL)
      wyl_client_service_credential_handoff_receipt_clear (out_receipt);
    return WYRELOG_E_INVALID;
  }
  wyl_client_service_credential_handoff_receipt_clear (out_receipt);
  while (TRUE) {
    g_clear_pointer (&key, g_free);
    if (!parse_string (&cursor, &key) || !take (&cursor, ':'))
      goto invalid;
    if (g_strcmp0 (key, "state") == 0) {
      if (seen_state || !parse_string (&cursor, &out_receipt->state)
          || !handoff_state_is_known (out_receipt->state))
        goto invalid;
      seen_state = TRUE;
    } else if (g_strcmp0 (key, "request_id") == 0) {
      if (seen_request_id || !parse_string (&cursor, &out_receipt->request_id)
          || !string_is_request_id (out_receipt->request_id))
        goto invalid;
      seen_request_id = TRUE;
    } else if (g_strcmp0 (key, "credential_id") == 0) {
      if (seen_credential_id
          || !parse_nullable_string (&cursor, &out_receipt->credential_id)
          || (out_receipt->credential_id != NULL
              && !wyl_service_credential_id_is_canonical
              (out_receipt->credential_id,
                  strlen (out_receipt->credential_id))))
        goto invalid;
      seen_credential_id = TRUE;
    } else if (g_strcmp0 (key, "generation") == 0) {
      if (seen_generation || !parse_uint64 (&cursor, &out_receipt->generation))
        goto invalid;
      seen_generation = TRUE;
    } else if (g_strcmp0 (key, "destination") == 0) {
      if (seen_destination || !parse_string (&cursor, &out_receipt->destination)
          || !wyl_service_credential_operation_destination_is_valid
          (out_receipt->destination))
        goto invalid;
      seen_destination = TRUE;
    } else if (g_strcmp0 (key, "publication_receipt_id") == 0) {
      if (seen_publication_receipt_id
          || !parse_nullable_string (&cursor,
              &out_receipt->publication_receipt_id))
        goto invalid;
      seen_publication_receipt_id = TRUE;
    } else if (g_strcmp0 (key, "delivered") == 0) {
      if (seen_delivered || !parse_bool (&cursor, &out_receipt->delivered))
        goto invalid;
      seen_delivered = TRUE;
    } else {
      goto invalid;
    }
    if (take (&cursor, '}'))
      break;
    if (!take (&cursor, ','))
      goto invalid;
  }
  if (!document_done (&cursor) || !seen_state || !seen_request_id
      || !seen_credential_id || !seen_generation || !seen_destination
      || !seen_publication_receipt_id || !seen_delivered)
    goto invalid;
  g_free (key);
  return WYRELOG_E_OK;
invalid:
  g_free (key);
  wyl_client_service_credential_handoff_receipt_clear (out_receipt);
  return WYRELOG_E_INVALID;
}

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
#define WYL_CLIENT_FACT_STATUS_MAX_GRAPHS (16384u)
#define WYL_CLIENT_FACT_STATUS_MAX_WIRE_NAME (64u)

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
      case 'u': {
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
    document, document_len, 0
  };
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
  gboolean seen_generation = FALSE;
  gboolean seen_created_by = FALSE;
  gboolean seen_created_at = FALSE;
  gboolean seen_updated_at = FALSE;
  gboolean seen_disabled_by = FALSE;
  gboolean seen_disabled_at = FALSE;
  guint64 generation = 0;
  gint64 created_at_us = 0;
  gint64 updated_at_us = 0;
  gint64 disabled_at_us = 0;
  g_autofree gchar *created_by = NULL;
  g_autofree gchar *disabled_by = NULL;
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
    } else if (g_strcmp0 (key, "generation") == 0) {
      if (seen_generation || !parse_uint64 (cursor, &generation)
          || generation == 0)
        goto invalid;
      seen_generation = TRUE;
    } else if (g_strcmp0 (key, "created_by") == 0) {
      if (seen_created_by || !parse_string (cursor, &created_by)
          || !string_is_plain_token (created_by))
        goto invalid;
      seen_created_by = TRUE;
    } else if (g_strcmp0 (key, "created_at_us") == 0) {
      if (seen_created_at || !parse_int64 (cursor, &created_at_us)
          || created_at_us <= 0)
        goto invalid;
      seen_created_at = TRUE;
    } else if (g_strcmp0 (key, "updated_at_us") == 0) {
      if (seen_updated_at || !parse_int64 (cursor, &updated_at_us)
          || updated_at_us <= 0)
        goto invalid;
      seen_updated_at = TRUE;
    } else if (g_strcmp0 (key, "disabled_by") == 0) {
      if (seen_disabled_by || !parse_nullable_string (cursor, &disabled_by)
          || (disabled_by != NULL && !string_is_plain_token (disabled_by)))
        goto invalid;
      seen_disabled_by = TRUE;
    } else if (g_strcmp0 (key, "disabled_at_us") == 0) {
      if (seen_disabled_at || !parse_int64 (cursor, &disabled_at_us))
        goto invalid;
      seen_disabled_at = TRUE;
    } else {
      goto invalid;
    }
    if (take (cursor, '}'))
      break;
    if (!take (cursor, ','))
      goto invalid;
  }
  g_free (key);
  return seen_subject && seen_display && seen_state && seen_generation
         && seen_created_by && seen_created_at && seen_updated_at
         && seen_disabled_by && seen_disabled_at
         && updated_at_us >= created_at_us
         && ((g_strcmp0 (out->state, "active") == 0 && disabled_by == NULL
         && disabled_at_us == 0)
         || (g_strcmp0 (out->state, "disabled") == 0 && disabled_by != NULL
         && disabled_at_us > 0 && updated_at_us >= disabled_at_us));
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
      case 2: {
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

void
wyl_client_fact_graph_status_clear (WylClientFactGraphStatus *status)
{
  if (status == NULL)
    return;
  g_clear_pointer (&status->tenant_id, g_free);
  g_clear_pointer (&status->graph_id, g_free);
  g_clear_pointer (&status->state_name, g_free);
  g_clear_pointer (&status->last_error_class, g_free);
  status->state = WYL_CLIENT_FACT_GRAPH_STATE_UNKNOWN;
  status->reason_class = WYL_CLIENT_FACT_REASON_NONE;
  status->queryable = FALSE;
}

void
wyl_client_fact_status_clear (WylClientFactStatus *status)
{
  if (status == NULL)
    return;
  for (gsize i = 0; i < status->n_graphs; i++)
    wyl_client_fact_graph_status_clear (&status->graphs[i]);
  g_clear_pointer (&status->graphs, g_free);
  g_clear_pointer (&status->status_name, g_free);
  *status = (WylClientFactStatus) { 0 };
}

void
wyl_client_fact_status_free (WylClientFactStatus *status)
{
  if (status == NULL)
    return;
  wyl_client_fact_status_clear (status);
  g_free (status);
}

static gboolean
fact_status_skip_number (JsonCursor *cursor)
{
  skip_ws (cursor);
  if (cursor->pos < cursor->len && cursor->data[cursor->pos] == '-')
    cursor->pos++;
  if (cursor->pos >= cursor->len)
    return FALSE;
  if (cursor->data[cursor->pos] == '0') {
    cursor->pos++;
    if (cursor->pos < cursor->len
        && g_ascii_isdigit ((guchar) cursor->data[cursor->pos]))
      return FALSE;
  } else {
    if (cursor->data[cursor->pos] < '1'
        || cursor->data[cursor->pos] > '9')
      return FALSE;
    while (cursor->pos < cursor->len
        && g_ascii_isdigit ((guchar) cursor->data[cursor->pos]))
      cursor->pos++;
  }
  if (cursor->pos < cursor->len && cursor->data[cursor->pos] == '.') {
    cursor->pos++;
    gsize start = cursor->pos;
    while (cursor->pos < cursor->len
        && g_ascii_isdigit ((guchar) cursor->data[cursor->pos]))
      cursor->pos++;
    if (cursor->pos == start)
      return FALSE;
  }
  if (cursor->pos < cursor->len
      && (cursor->data[cursor->pos] == 'e'
      || cursor->data[cursor->pos] == 'E')) {
    cursor->pos++;
    if (cursor->pos < cursor->len
        && (cursor->data[cursor->pos] == '+'
        || cursor->data[cursor->pos] == '-'))
      cursor->pos++;
    gsize start = cursor->pos;
    while (cursor->pos < cursor->len
        && g_ascii_isdigit ((guchar) cursor->data[cursor->pos]))
      cursor->pos++;
    if (cursor->pos == start)
      return FALSE;
  }
  return TRUE;
}

static gboolean
fact_status_read_hex4 (JsonCursor *cursor, gunichar *out_codepoint)
{
  gunichar codepoint = 0;
  for (guint i = 0; i < 4; i++) {
    guint digit = 0;
    if (cursor->pos >= cursor->len
        || !hex_digit (cursor->data[cursor->pos++], &digit))
      return FALSE;
    codepoint = (codepoint << 4) | digit;
  }
  *out_codepoint = codepoint;
  return TRUE;
}

static gboolean
fact_status_parse_key (JsonCursor *cursor, gchar **out_key)
{
  g_autoptr (GString) value = NULL;
  if (out_key == NULL || !take (cursor, '"'))
    return FALSE;
  *out_key = NULL;
  value = g_string_new (NULL);
  if (value == NULL)
    return FALSE;
  while (cursor->pos < cursor->len) {
    const gchar ch = cursor->data[cursor->pos++];
    if (ch == '"') {
      if (!g_utf8_validate (value->str, value->len, NULL))
        return FALSE;
      *out_key = g_string_free (g_steal_pointer (&value), FALSE);
      return TRUE;
    }
    if ((guchar) ch < 0x20)
      return FALSE;
    if (ch != '\\') {
      g_string_append_c (value, ch);
    } else {
      if (cursor->pos >= cursor->len)
        return FALSE;
      const gchar escape = cursor->data[cursor->pos++];
      switch (escape) {
        case '"':
        case '\\':
        case '/':
          g_string_append_c (value, escape);
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
        case 'u': {
          gunichar codepoint = 0;
          if (!fact_status_read_hex4 (cursor, &codepoint) || codepoint == 0)
            return FALSE;
          if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
            gunichar low = 0;
            if (cursor->pos + 2 > cursor->len
                || cursor->data[cursor->pos++] != '\\'
                || cursor->data[cursor->pos++] != 'u'
                || !fact_status_read_hex4 (cursor, &low)
                || low < 0xdc00 || low > 0xdfff)
              return FALSE;
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10)
                + (low - 0xdc00);
          } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
            return FALSE;
          }
          g_string_append_unichar (value, codepoint);
          break;
        }
        default:
          return FALSE;
      }
    }
    if (value->len > WYL_CLIENT_CODEC_MAX_STRING)
      return FALSE;
  }
  return FALSE;
}

static gboolean
fact_status_skip_string (JsonCursor *cursor)
{
  if (!take (cursor, '"'))
    return FALSE;
  gsize raw_start = cursor->pos;
  while (cursor->pos < cursor->len) {
    const gchar ch = cursor->data[cursor->pos++];
    if (ch == '"')
      return g_utf8_validate (cursor->data + raw_start,
                 cursor->pos - raw_start - 1, NULL);
    if ((guchar) ch < 0x20)
      return FALSE;
    if (ch != '\\')
      continue;

    if (!g_utf8_validate (cursor->data + raw_start,
        cursor->pos - raw_start - 1, NULL)
        || cursor->pos >= cursor->len)
      return FALSE;
    const gchar escape = cursor->data[cursor->pos++];
    if (strchr ("\"\\/bfnrt", escape) != NULL) {
      raw_start = cursor->pos;
      continue;
    }
    if (escape != 'u' || cursor->pos + 4 > cursor->len)
      return FALSE;
    for (guint i = 0; i < 4; i++) {
      guint digit = 0;
      if (!hex_digit (cursor->data[cursor->pos++], &digit))
        return FALSE;
    }
    raw_start = cursor->pos;
  }
  return FALSE;
}

static gboolean
fact_status_skip_value (JsonCursor *cursor, guint depth)
{
  if (depth > 32)
    return FALSE;
  skip_ws (cursor);
  if (cursor->pos >= cursor->len)
    return FALSE;
  gchar ch = cursor->data[cursor->pos];
  if (ch == '"')
    return fact_status_skip_string (cursor);
  if (ch == '{') {
    cursor->pos++;
    if (take (cursor, '}'))
      return TRUE;
    while (TRUE) {
      g_autofree gchar *key = NULL;
      if (!fact_status_parse_key (cursor, &key) || !take (cursor, ':')
          || !fact_status_skip_value (cursor, depth + 1))
        return FALSE;
      if (take (cursor, '}'))
        return TRUE;
      if (!take (cursor, ','))
        return FALSE;
    }
  }
  if (ch == '[') {
    cursor->pos++;
    if (take (cursor, ']'))
      return TRUE;
    while (TRUE) {
      if (!fact_status_skip_value (cursor, depth + 1))
        return FALSE;
      if (take (cursor, ']'))
        return TRUE;
      if (!take (cursor, ','))
        return FALSE;
    }
  }
  if (cursor->pos + 4 <= cursor->len
      && (memcmp (cursor->data + cursor->pos, "true", 4) == 0
      || memcmp (cursor->data + cursor->pos, "null", 4) == 0)) {
    cursor->pos += 4;
    return TRUE;
  }
  if (cursor->pos + 5 <= cursor->len
      && memcmp (cursor->data + cursor->pos, "false", 5) == 0) {
    cursor->pos += 5;
    return TRUE;
  }
  return fact_status_skip_number (cursor);
}

static WylClientFactStatusKind
fact_status_kind_from_name (const gchar *name)
{
  if (g_strcmp0 (name, "ready") == 0)
    return WYL_CLIENT_FACT_STATUS_READY;
  if (g_strcmp0 (name, "degraded") == 0)
    return WYL_CLIENT_FACT_STATUS_DEGRADED;
  if (g_strcmp0 (name, "disabled") == 0)
    return WYL_CLIENT_FACT_STATUS_DISABLED;
  return WYL_CLIENT_FACT_STATUS_UNKNOWN;
}

static WylClientFactGraphState
fact_graph_state_from_name (const gchar *name)
{
  if (g_strcmp0 (name, "ready") == 0)
    return WYL_CLIENT_FACT_GRAPH_STATE_READY;
  if (g_strcmp0 (name, "degraded") == 0)
    return WYL_CLIENT_FACT_GRAPH_STATE_DEGRADED;
  if (g_strcmp0 (name, "schema_mismatch") == 0)
    return WYL_CLIENT_FACT_GRAPH_STATE_SCHEMA_MISMATCH;
  if (g_strcmp0 (name, "replay_failed") == 0)
    return WYL_CLIENT_FACT_GRAPH_STATE_REPLAY_FAILED;
  if (g_strcmp0 (name, "store_unavailable") == 0)
    return WYL_CLIENT_FACT_GRAPH_STATE_STORE_UNAVAILABLE;
  if (g_strcmp0 (name, "forget_incomplete") == 0)
    return WYL_CLIENT_FACT_GRAPH_STATE_FORGET_INCOMPLETE;
  if (g_strcmp0 (name, "sealed") == 0)
    return WYL_CLIENT_FACT_GRAPH_STATE_SEALED;
  return WYL_CLIENT_FACT_GRAPH_STATE_UNKNOWN;
}

static gboolean
fact_status_wire_name_is_valid (const gchar *name)
{
  if (name == NULL || name[0] == '\0'
      || strlen (name) > WYL_CLIENT_FACT_STATUS_MAX_WIRE_NAME)
    return FALSE;
  for (const guchar *p = (const guchar *) name; *p != '\0'; p++)
    if (!g_ascii_isalnum (*p) && *p != '_' && *p != '-')
      return FALSE;
  return TRUE;
}

static WylClientFactReasonClass
fact_reason_class_from_name (const gchar *name)
{
  if (g_strcmp0 (name, "degraded") == 0)
    return WYL_CLIENT_FACT_REASON_DEGRADED;
  if (g_strcmp0 (name, "schema_mismatch") == 0)
    return WYL_CLIENT_FACT_REASON_SCHEMA_MISMATCH;
  if (g_strcmp0 (name, "replay_failed") == 0)
    return WYL_CLIENT_FACT_REASON_REPLAY_FAILED;
  if (g_strcmp0 (name, "store_unavailable") == 0)
    return WYL_CLIENT_FACT_REASON_STORE_UNAVAILABLE;
  if (g_strcmp0 (name, "forget_incomplete") == 0)
    return WYL_CLIENT_FACT_REASON_FORGET_INCOMPLETE;
  return WYL_CLIENT_FACT_REASON_UNKNOWN;
}

static gboolean
fact_status_parse_graph (JsonCursor *cursor,
    WylClientFactGraphStatus *graph)
{
  gboolean seen_tenant = FALSE, seen_graph = FALSE, seen_state = FALSE;
  gboolean seen_queryable = FALSE, seen_reason = FALSE;
  if (!take (cursor, '{'))
    return FALSE;
  while (TRUE) {
    g_autofree gchar *key = NULL;
    if (!fact_status_parse_key (cursor, &key) || !take (cursor, ':'))
      return FALSE;
    if (g_strcmp0 (key, "tenant_id") == 0) {
      if (seen_tenant || !parse_string (cursor, &graph->tenant_id)
          || graph->tenant_id[0] == '\0')
        return FALSE;
      seen_tenant = TRUE;
    } else if (g_strcmp0 (key, "graph_id") == 0) {
      if (seen_graph || !parse_string (cursor, &graph->graph_id)
          || graph->graph_id[0] == '\0')
        return FALSE;
      seen_graph = TRUE;
    } else if (g_strcmp0 (key, "state") == 0) {
      if (seen_state || !parse_string (cursor, &graph->state_name)
          || !fact_status_wire_name_is_valid (graph->state_name))
        return FALSE;
      graph->state = fact_graph_state_from_name (graph->state_name);
      seen_state = TRUE;
    } else if (g_strcmp0 (key, "queryable") == 0) {
      if (seen_queryable || !parse_bool (cursor, &graph->queryable))
        return FALSE;
      seen_queryable = TRUE;
    } else if (g_strcmp0 (key, "last_error_class") == 0) {
      if (seen_reason || !parse_nullable_string (cursor,
          &graph->last_error_class)
          || (graph->last_error_class != NULL
          && !fact_status_wire_name_is_valid (graph->last_error_class)))
        return FALSE;
      graph->reason_class = graph->last_error_class == NULL
          ? WYL_CLIENT_FACT_REASON_NONE
          : fact_reason_class_from_name (graph->last_error_class);
      seen_reason = TRUE;
    } else if (!fact_status_skip_value (cursor, 0)) {
      return FALSE;
    }
    if (take (cursor, '}'))
      break;
    if (!take (cursor, ','))
      return FALSE;
  }
  return seen_tenant && seen_graph && seen_state && seen_queryable
         && seen_reason;
}

wyrelog_error_t
wyl_client_fact_status_decode (const gchar *document, gsize document_len,
    WylClientFactStatus *out_status)
{
  if (out_status == NULL)
    return WYRELOG_E_INVALID;
  wyl_client_fact_status_clear (out_status);
  if (document == NULL || document_len == 0
      || document_len > WYL_CLIENT_FACT_STATUS_MAX_DOCUMENT
      || memchr (document, '\0', document_len) != NULL
      /* g_ascii_isspace() in the shared JSON cursor also accepts VT and FF;
       * JSON itself permits only SP, HT, CR, and LF as whitespace. */
      || memchr (document, '\v', document_len) != NULL
      || memchr (document, '\f', document_len) != NULL)
    return WYRELOG_E_INVALID;

  JsonCursor cursor = { document, document_len, 0 };
  WylClientFactStatus parsed = { 0 };
  gboolean seen_status = FALSE, seen_total = FALSE, seen_ready = FALSE;
  gboolean seen_degraded = FALSE, seen_sealed = FALSE, seen_graphs = FALSE;
  GArray *graphs = g_array_new (FALSE, TRUE,
          sizeof (WylClientFactGraphStatus));
  g_array_set_clear_func (graphs,
      (GDestroyNotify) wyl_client_fact_graph_status_clear);
  GHashTable *identities = g_hash_table_new_full (g_str_hash, g_str_equal,
          g_free, NULL);
  if (!take (&cursor, '{'))
    goto invalid;

  while (TRUE) {
    g_autofree gchar *key = NULL;
    if (!fact_status_parse_key (&cursor, &key) || !take (&cursor, ':'))
      goto invalid;
    if (g_strcmp0 (key, "status") == 0) {
      if (seen_status || !parse_string (&cursor, &parsed.status_name)
          || !fact_status_wire_name_is_valid (parsed.status_name))
        goto invalid;
      parsed.status = fact_status_kind_from_name (parsed.status_name);
      seen_status = TRUE;
    } else if (g_strcmp0 (key, "graphs_total") == 0) {
      if (seen_total || !parse_uint64 (&cursor, &parsed.graphs_total))
        goto invalid;
      seen_total = TRUE;
    } else if (g_strcmp0 (key, "graphs_ready") == 0) {
      if (seen_ready || !parse_uint64 (&cursor, &parsed.graphs_ready))
        goto invalid;
      seen_ready = TRUE;
    } else if (g_strcmp0 (key, "graphs_degraded") == 0) {
      if (seen_degraded || !parse_uint64 (&cursor, &parsed.graphs_degraded))
        goto invalid;
      seen_degraded = TRUE;
    } else if (g_strcmp0 (key, "graphs_sealed") == 0) {
      if (seen_sealed || !parse_uint64 (&cursor, &parsed.graphs_sealed))
        goto invalid;
      seen_sealed = TRUE;
    } else if (g_strcmp0 (key, "graphs") == 0) {
      if (seen_graphs || !take (&cursor, '['))
        goto invalid;
      seen_graphs = TRUE;
      parsed.has_graphs = TRUE;
      if (!take (&cursor, ']')) {
        while (TRUE) {
          WylClientFactGraphStatus graph = { 0 };
          if (graphs->len >= WYL_CLIENT_FACT_STATUS_MAX_GRAPHS
              || !fact_status_parse_graph (&cursor, &graph)) {
            wyl_client_fact_graph_status_clear (&graph);
            goto invalid;
          }
          g_autofree gchar *identity = g_strdup_printf ("%" G_GSIZE_FORMAT
                  ":%s%s", strlen (graph.tenant_id), graph.tenant_id,
                  graph.graph_id);
          if (g_hash_table_contains (identities, identity)) {
            wyl_client_fact_graph_status_clear (&graph);
            goto invalid;
          }
          g_hash_table_add (identities, g_steal_pointer (&identity));
          g_array_append_val (graphs, graph);
          if (take (&cursor, ']'))
            break;
          if (!take (&cursor, ','))
            goto invalid;
        }
      }
    } else if (!fact_status_skip_value (&cursor, 0)) {
      goto invalid;
    }
    if (take (&cursor, '}'))
      break;
    if (!take (&cursor, ','))
      goto invalid;
  }

  if (!document_done (&cursor) || !seen_status || !seen_total || !seen_ready
      || !seen_degraded || !seen_sealed
      || parsed.graphs_ready > G_MAXUINT64 - parsed.graphs_degraded
      || parsed.graphs_ready + parsed.graphs_degraded
      > G_MAXUINT64 - parsed.graphs_sealed
      || parsed.graphs_total != parsed.graphs_ready + parsed.graphs_degraded
      + parsed.graphs_sealed
      || (seen_graphs && graphs->len != parsed.graphs_total)
      || (parsed.status == WYL_CLIENT_FACT_STATUS_READY
      && parsed.graphs_degraded != 0)
      || (parsed.status == WYL_CLIENT_FACT_STATUS_DEGRADED
      && parsed.graphs_degraded == 0)
      || (parsed.status == WYL_CLIENT_FACT_STATUS_DISABLED
      && parsed.graphs_total != 0))
    goto invalid;

  if (seen_graphs) {
    guint64 ready = 0, degraded = 0, sealed = 0;
    for (gsize i = 0; i < graphs->len; i++) {
      WylClientFactGraphStatus *graph = &g_array_index (graphs,
              WylClientFactGraphStatus, i);
      if (graph->state == WYL_CLIENT_FACT_GRAPH_STATE_READY)
        ready++;
      else if (graph->state == WYL_CLIENT_FACT_GRAPH_STATE_SEALED)
        sealed++;
      else
        degraded++;
    }
    if (ready != parsed.graphs_ready || sealed != parsed.graphs_sealed
        || degraded != parsed.graphs_degraded)
      goto invalid;
  }

  parsed.n_graphs = graphs->len;
  parsed.graphs = (WylClientFactGraphStatus *) g_array_free (graphs, FALSE);
  graphs = NULL;
  *out_status = parsed;
  g_hash_table_unref (identities);
  return WYRELOG_E_OK;

invalid:
  g_array_free (graphs, TRUE);
  g_hash_table_unref (identities);
  g_free (parsed.status_name);
  return WYRELOG_E_INVALID;
}

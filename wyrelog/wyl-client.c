/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyl-client-private.h"

struct _WylClient
{
  GObject parent_instance;
  gchar *base_url;
  SoupSession *session;
};

G_DEFINE_FINAL_TYPE (WylClient, wyl_client, G_TYPE_OBJECT);

static void
wyl_client_finalize (GObject *object)
{
  WylClient *self = WYL_CLIENT (object);

  g_free (self->base_url);
  g_clear_object (&self->session);

  G_OBJECT_CLASS (wyl_client_parent_class)->finalize (object);
}

static void
wyl_client_class_init (WylClientClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_client_finalize;
}

static void
wyl_client_init (WylClient *self)
{
  (void) self;
}

wyrelog_error_t
wyl_client_new (const gchar *base_url, WylClient **out_client)
{
  if (out_client == NULL)
    return WYRELOG_E_INVALID;
  *out_client = NULL;
  if (base_url == NULL || base_url[0] == '\0')
    return WYRELOG_E_INVALID;

  g_autoptr (GError) error = NULL;
  g_autoptr (GUri) uri = g_uri_parse (base_url, G_URI_FLAGS_NONE, &error);
  if (uri == NULL)
    return WYRELOG_E_INVALID;

  const gchar *scheme = g_uri_get_scheme (uri);
  if (g_strcmp0 (scheme, "http") != 0 && g_strcmp0 (scheme, "https") != 0)
    return WYRELOG_E_INVALID;

  WylClient *client = g_object_new (WYL_TYPE_CLIENT, NULL);
  client->base_url = g_strdup (base_url);
  client->session = soup_session_new ();
  *out_client = client;
  return WYRELOG_E_OK;
}

gchar *
wyl_client_dup_base_url (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->base_url);
}

SoupSession *
wyl_client_get_soup_session (WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT (client), NULL);
  return client->session;
}

wyrelog_error_t
wyl_client_send_message (WylClient *client, SoupMessage *message,
    GBytes **out_body)
{
  if (client == NULL || !WYL_IS_CLIENT (client) || message == NULL ||
      out_body == NULL)
    return WYRELOG_E_INVALID;
  *out_body = NULL;

  g_autoptr (GError) error = NULL;
  GBytes *body = soup_session_send_and_read (client->session, message, NULL,
      &error);
  if (body == NULL)
    return WYRELOG_E_IO;

  guint status = soup_message_get_status (message);
  if (status < 200 || status >= 300) {
    g_bytes_unref (body);
    return WYRELOG_E_IO;
  }

  *out_body = body;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_login (WylClient *client, const gchar *username,
    const gchar *password)
{
  (void) client;
  (void) username;
  (void) password;
  return WYRELOG_E_INTERNAL;
}

wyrelog_error_t
wyl_client_token_refresh (WylClient *client)
{
  (void) client;
  return WYRELOG_E_INTERNAL;
}

wyrelog_error_t
wyl_client_mfa_verify (WylClient *client, const gchar *otp)
{
  (void) client;
  (void) otp;
  return WYRELOG_E_INTERNAL;
}

typedef struct
{
  const gchar *data;
  gsize size;
  gsize pos;
} JsonCursor;

static void
json_skip_ws (JsonCursor *cursor)
{
  while (cursor->pos < cursor->size &&
      g_ascii_isspace (cursor->data[cursor->pos]))
    cursor->pos++;
}

static gboolean
json_consume (JsonCursor *cursor, gchar ch)
{
  json_skip_ws (cursor);
  if (cursor->pos >= cursor->size || cursor->data[cursor->pos] != ch)
    return FALSE;
  cursor->pos++;
  return TRUE;
}

static gboolean
json_hex_is_valid (gchar ch)
{
  return g_ascii_isxdigit (ch);
}

static gboolean
json_parse_string (JsonCursor *cursor, gchar **out_string)
{
  if (out_string == NULL)
    return FALSE;
  *out_string = NULL;
  if (!json_consume (cursor, '"'))
    return FALSE;

  g_autoptr (GString) value = g_string_new (NULL);
  while (cursor->pos < cursor->size) {
    guchar ch = (guchar) cursor->data[cursor->pos++];
    if (ch == '"') {
      *out_string = g_string_free (g_steal_pointer (&value), FALSE);
      return TRUE;
    }
    if (ch < 0x20)
      return FALSE;
    if (ch != '\\') {
      g_string_append_c (value, (gchar) ch);
      continue;
    }
    if (cursor->pos >= cursor->size)
      return FALSE;
    ch = (guchar) cursor->data[cursor->pos++];
    switch (ch) {
      case '"':
      case '\\':
      case '/':
        g_string_append_c (value, (gchar) ch);
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
      case 'u':
        if (cursor->pos + 4 > cursor->size)
          return FALSE;
        for (guint i = 0; i < 4; i++) {
          if (!json_hex_is_valid (cursor->data[cursor->pos++]))
            return FALSE;
        }
        g_string_append_c (value, '?');
        break;
      default:
        return FALSE;
    }
  }
  return FALSE;
}

static gboolean
json_parse_nullable_string (JsonCursor *cursor)
{
  json_skip_ws (cursor);
  if (cursor->pos + 4 <= cursor->size &&
      memcmp (cursor->data + cursor->pos, "null", 4) == 0) {
    cursor->pos += 4;
    return TRUE;
  }

  g_autofree gchar *value = NULL;
  return json_parse_string (cursor, &value);
}

static gboolean
json_parse_decision (JsonCursor *cursor, gint *out_decision)
{
  if (out_decision == NULL)
    return FALSE;
  json_skip_ws (cursor);
  if (cursor->pos >= cursor->size)
    return FALSE;
  gchar ch = cursor->data[cursor->pos++];
  if (ch != '0' && ch != '1')
    return FALSE;
  if (cursor->pos < cursor->size && g_ascii_isdigit (cursor->data[cursor->pos]))
    return FALSE;
  *out_decision = ch == '1' ? WYL_DECISION_ALLOW : WYL_DECISION_DENY;
  return TRUE;
}

static gboolean
parse_decide_response_json (const gchar *data, gsize size, gint *out_decision)
{
  if (data == NULL || out_decision == NULL)
    return FALSE;

  JsonCursor cursor = { data, size, 0 };
  if (!json_consume (&cursor, '{'))
    return FALSE;

  gboolean have_decision = FALSE;
  gboolean have_deny_reason = FALSE;
  gboolean have_deny_origin = FALSE;
  gint decision = WYL_DECISION_DENY;
  json_skip_ws (&cursor);
  if (cursor.pos < cursor.size && cursor.data[cursor.pos] == '}')
    return FALSE;

  while (TRUE) {
    g_autofree gchar *key = NULL;
    if (!json_parse_string (&cursor, &key) || !json_consume (&cursor, ':'))
      return FALSE;

    if (g_strcmp0 (key, "decision") == 0) {
      if (have_decision || !json_parse_decision (&cursor, &decision))
        return FALSE;
      have_decision = TRUE;
    } else if (g_strcmp0 (key, "deny_reason") == 0 ||
        g_strcmp0 (key, "deny_origin") == 0) {
      gboolean *seen = g_strcmp0 (key, "deny_reason") == 0 ?
          &have_deny_reason : &have_deny_origin;
      if (*seen)
        return FALSE;
      if (!json_parse_nullable_string (&cursor))
        return FALSE;
      *seen = TRUE;
    } else {
      return FALSE;
    }

    json_skip_ws (&cursor);
    if (cursor.pos < cursor.size && cursor.data[cursor.pos] == ',') {
      cursor.pos++;
      continue;
    }
    if (cursor.pos < cursor.size && cursor.data[cursor.pos] == '}') {
      cursor.pos++;
      break;
    }
    return FALSE;
  }

  json_skip_ws (&cursor);
  if (!have_decision || !have_deny_reason || !have_deny_origin ||
      cursor.pos != cursor.size)
    return FALSE;
  *out_decision = decision;
  return TRUE;
}

wyrelog_error_t
wyl_client_decide (WylClient *client, const gchar *user, const gchar *perm,
    const gchar *session_token, gint *out_decision)
{
  if (client == NULL || !WYL_IS_CLIENT (client) || user == NULL ||
      perm == NULL || session_token == NULL || out_decision == NULL)
    return WYRELOG_E_INVALID;
  *out_decision = WYL_DECISION_DENY;

  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (base_url == NULL)
    return WYRELOG_E_INVALID;
  while (base_url[0] != '\0' && g_str_has_suffix (base_url, "/"))
    base_url[strlen (base_url) - 1] = '\0';

  g_autofree gchar *escaped_user = g_uri_escape_string (user, NULL, TRUE);
  g_autofree gchar *escaped_perm = g_uri_escape_string (perm, NULL, TRUE);
  g_autofree gchar *escaped_session_token =
      g_uri_escape_string (session_token, NULL, TRUE);
  g_autofree gchar *uri =
      g_strdup_printf ("%s/decide?user=%s&perm=%s&session_token=%s", base_url,
      escaped_user,
      escaped_perm, escaped_session_token);

  g_autoptr (SoupMessage) message = soup_message_new ("POST", uri);
  if (message == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (GBytes) body = NULL;
  wyrelog_error_t rc = wyl_client_send_message (client, message, &body);
  if (rc != WYRELOG_E_OK)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  gint decision = WYL_DECISION_DENY;
  if (!parse_decide_response_json (body_data, body_size, &decision))
    return WYRELOG_E_IO;

  *out_decision = decision;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_tenant_select (WylClient *client, const gchar *tenant)
{
  (void) client;
  (void) tenant;
  return WYRELOG_E_INTERNAL;
}

wyrelog_error_t
wyl_client_event_emit (WylClient *client, const gchar *event_kind,
    const gchar *event_payload_json)
{
  (void) client;
  (void) event_kind;
  (void) event_payload_json;
  return WYRELOG_E_INTERNAL;
}

const gchar *
wyrelog_client_version_string (void)
{
  return "0.1.0";
}

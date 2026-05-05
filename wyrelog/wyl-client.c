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

wyrelog_error_t
wyl_client_decide (WylClient *client, const gchar *user, const gchar *perm,
    const gchar *session_token, gint *out_decision)
{
  (void) client;
  (void) user;
  (void) perm;
  (void) session_token;
  (void) out_decision;
  return WYRELOG_E_INTERNAL;
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

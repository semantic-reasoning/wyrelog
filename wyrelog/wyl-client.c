/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/client.h"

struct _WylClient
{
  GObject parent_instance;
};

G_DEFINE_FINAL_TYPE (WylClient, wyl_client, G_TYPE_OBJECT);

static void
wyl_client_class_init (WylClientClass *klass)
{
  (void) klass;
}

static void
wyl_client_init (WylClient *self)
{
  (void) self;
}

wyrelog_error_t
wyl_client_new (const gchar *base_url, WylClient **out_client)
{
  (void) base_url;

  if (out_client == NULL)
    return WYRELOG_E_INVALID;

  *out_client = g_object_new (WYL_TYPE_CLIENT, NULL);
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

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include "auth/service-credential-private.h"
#include "policy/store-private.h"
#include "wyl-session-layout-private.h"

static gboolean
session_id_is_canonical_non_nil (const wyl_id_t *id)
{
  if (id == NULL || wyl_id_equal (id, &WYL_ID_NIL))
    return FALSE;
  gchar encoded[WYL_ID_STRING_BUF];
  wyl_id_t parsed;
  return wyl_id_format (id, encoded, sizeof encoded) == WYRELOG_E_OK
      && wyl_id_parse (encoded, &parsed) == WYRELOG_E_OK
      && wyl_id_equal (id, &parsed);
}

static gboolean
jti_is_canonical (const gchar *value)
{
  if (value == NULL)
    return FALSE;
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  return wyl_id_parse (value, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && strcmp (value, canonical) == 0;
}

static gboolean
descriptor_is_valid (const wyl_service_session_descriptor_t *descriptor)
{
  return descriptor != NULL
      && session_id_is_canonical_non_nil (&descriptor->session_id)
      && jti_is_canonical (descriptor->jti)
      && descriptor->subject_id != NULL
      && wyl_policy_service_subject_is_valid (descriptor->subject_id,
      strlen (descriptor->subject_id))
      && descriptor->tenant_id != NULL
      && wyl_policy_store_tenant_id_is_valid (descriptor->tenant_id)
      && descriptor->credential_id != NULL
      && wyl_service_credential_id_is_canonical (descriptor->credential_id,
      strlen (descriptor->credential_id))
      && descriptor->credential_generation != 0
      && descriptor->issued_at_seconds >= 0
      && descriptor->issued_at_seconds <= G_MAXINT64 - 300
      && descriptor->expires_at_seconds == descriptor->issued_at_seconds + 300;
}

wyrelog_error_t
wyl_session_new_service_detached (const
    wyl_service_session_descriptor_t *descriptor, WylSession **out_session)
{
  if (out_session == NULL)
    return WYRELOG_E_INVALID;
  *out_session = NULL;
  if (!descriptor_is_valid (descriptor))
    return WYRELOG_E_INVALID;

  WylSession *session = g_object_new (WYL_TYPE_SESSION, NULL);
  session->id = descriptor->session_id;
  session->state = WYL_SESSION_STATE_ACTIVE;
  session->auth_method = WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL;
  session->service_jti = g_strdup (descriptor->jti);
  session->service_subject_id = g_strdup (descriptor->subject_id);
  session->tenant = g_strdup (descriptor->tenant_id);
  session->service_credential_id = g_strdup (descriptor->credential_id);
  session->service_credential_generation = descriptor->credential_generation;
  session->service_issued_at_seconds = descriptor->issued_at_seconds;
  session->service_expires_at_seconds = descriptor->expires_at_seconds;
  *out_session = session;
  return WYRELOG_E_OK;
}

wyl_session_auth_method_t
wyl_session_get_auth_method_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ? session->auth_method :
      WYL_SESSION_AUTH_METHOD_LAST_;
}

gboolean
wyl_session_is_active_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
      && session->state == WYL_SESSION_STATE_ACTIVE;
}

gboolean
wyl_session_is_active_human_private (const WylSession *session)
{
  return wyl_session_is_active_private (session)
      && wyl_session_get_auth_method_private (session)
      == WYL_SESSION_AUTH_METHOD_HUMAN;
}

wyrelog_error_t
wyl_session_copy_persistent_id_private (const WylSession *session,
    wyl_id_t *out_id)
{
  if (!WYL_IS_SESSION ((gpointer) session) || out_id == NULL)
    return WYRELOG_E_INVALID;
  *out_id = session->id;
  return WYRELOG_E_OK;
}

gchar *
wyl_session_dup_service_jti_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ?
      g_strdup (session->service_jti) : NULL;
}

gchar *
wyl_session_dup_service_subject_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ?
      g_strdup (session->service_subject_id) : NULL;
}

gchar *
wyl_session_dup_service_tenant_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ?
      g_strdup (session->tenant) : NULL;
}

gchar *
wyl_session_dup_service_credential_id_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ?
      g_strdup (session->service_credential_id) : NULL;
}

guint64
wyl_session_get_service_credential_generation_private (const
    WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ?
      session->service_credential_generation : 0;
}

gint64
wyl_session_get_service_issued_at_seconds_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ?
      session->service_issued_at_seconds : -1;
}

gint64
wyl_session_get_service_expires_at_seconds_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ?
      session->service_expires_at_seconds : -1;
}

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
  wyl_session_state_store_private (session, WYL_SESSION_STATE_ACTIVE);
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
         && wyl_session_state_load_private (session) == WYL_SESSION_STATE_ACTIVE;
}

gboolean
wyl_session_is_active_human_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
         && wyl_session_state_load_private (session) == WYL_SESSION_STATE_ACTIVE
         && session->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN;
}

gboolean
wyl_session_is_mfa_assured_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
         && session->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN
         && g_atomic_int_get ((gint *) &session->mfa_assured) != 0;
}

/* Issue #752: read the authentication epoch this session won (0 if it never
 * won an authenticating transition).  The value is a write-once volatile
 * gint64 (GLib has no 64-bit atomic); the winning commit stores it before
 * publishing mfa_assured, so any reader that runs after authentication
 * observes the settled, non-torn value.  Lives here in the companion archive
 * so the daemon can read the epoch through this stable boundary rather than
 * touching the raw layout. */
gint64
wyl_session_authn_epoch_load_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ? session->authn_epoch : 0;
}

/* The daemon HTTP test targets link the companion archive alongside the
 * shared library. Its core session definitions are hidden, so retain the
 * companion bridge for those external test callers. The weak attribute
 * prevents a duplicate strong definition when a static production library
 * and this companion archive share one link image. */
#if defined(__GNUC__) || defined(__clang__)
# define WYL_SESSION_COMPANION_WEAK __attribute__ ((weak))
#else
# define WYL_SESSION_COMPANION_WEAK
#endif
WYL_SESSION_COMPANION_WEAK gboolean
wyl_session_reauth_pending_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
         && g_atomic_int_get ((gint *) &session->reauth_pending) != 0;
}

WYL_SESSION_COMPANION_WEAK gint64
wyl_session_reauth_expected_epoch_private (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session) ? session->reauth_expected_epoch : 0;
}
#undef WYL_SESSION_COMPANION_WEAK

gboolean
wyl_session_liveness_check_private (const WylSession *session,
    const gchar *expect_session_id, const gchar *expect_actor,
    const gchar *expect_tenant, gboolean require_mfa)
{
  if (session == NULL || !WYL_IS_SESSION ((gpointer) session)
      || !wyl_session_is_active_human_private (session)
      || (require_mfa && (!wyl_session_is_mfa_assured_private (session)
      || wyl_session_authn_epoch_load_private (session) == 0)))
    return FALSE;
  g_autofree gchar *live_session_id = wyl_session_dup_id_string (session);
  g_autofree gchar *live_actor = wyl_session_dup_username (session);
  g_autofree gchar *live_tenant = wyl_session_dup_tenant (session);
  return live_session_id != NULL && live_actor != NULL && live_tenant != NULL
         && g_strcmp0 (live_session_id, expect_session_id) == 0
         && g_strcmp0 (live_actor, expect_actor) == 0
         && g_strcmp0 (live_tenant, expect_tenant) == 0;
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

gboolean
wyl_session_matches_service_tuple_private (const WylSession *session,
    const gchar *session_id, const gchar *jti, const gchar *subject_id,
    const gchar *tenant_id, const gchar *credential_id,
    guint64 credential_generation, gint64 issued_at_seconds,
    gint64 expires_at_seconds)
{
  gchar encoded[WYL_ID_STRING_BUF];
  return WYL_IS_SESSION ((gpointer) session)
         && wyl_session_state_load_private (session) == WYL_SESSION_STATE_ACTIVE
         && session->auth_method == WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
         && session_id != NULL
         && wyl_id_format (&session->id, encoded, sizeof encoded) == WYRELOG_E_OK
         && strcmp (encoded, session_id) == 0
         && g_strcmp0 (session->service_jti, jti) == 0
         && g_strcmp0 (session->service_subject_id, subject_id) == 0
         && g_strcmp0 (session->tenant, tenant_id) == 0
         && g_strcmp0 (session->service_credential_id, credential_id) == 0
         && session->service_credential_generation == credential_generation
         && session->service_issued_at_seconds == issued_at_seconds
         && session->service_expires_at_seconds == expires_at_seconds;
}

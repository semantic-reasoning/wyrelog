/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-session-private.h"

static gint validator_calls;

static wyrelog_error_t
unexpected_validator (WylHandle *handle, WylSession *session,
    const gchar *proof, gpointer user_data)
{
  (void) handle;
  (void) session;
  (void) proof;
  (void) user_data;
  validator_calls++;
  return WYRELOG_E_OK;
}

static gint
make_descriptor (wyl_service_session_descriptor_t *descriptor,
    gchar jti[WYL_ID_STRING_BUF],
    gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF])
{
  wyl_id_t jti_id;
  if (wyl_id_new (&descriptor->session_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, WYL_ID_STRING_BUF) != WYRELOG_E_OK
      || wyl_service_credential_id_new (credential_id,
          WYL_SERVICE_CREDENTIAL_ID_BUF) != WYRELOG_E_OK)
    return 1;
  descriptor->jti = jti;
  descriptor->subject_id = "svc:metadata-test";
  descriptor->tenant_id = "default";
  descriptor->credential_id = credential_id;
  descriptor->credential_generation = G_MAXUINT64;
  descriptor->issued_at_seconds = 123456;
  descriptor->expires_at_seconds = 123756;
  return 0;
}

static gint
check_exact_copy_and_accessors (void)
{
  wyl_service_session_descriptor_t descriptor = { 0 };
  gchar jti[WYL_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  gchar subject[] = "svc:metadata-test";
  gchar tenant[] = "default";
  if (make_descriptor (&descriptor, jti, credential_id) != 0)
    return 10;
  descriptor.subject_id = subject;
  descriptor.tenant_id = tenant;
  wyl_id_t expected_id = descriptor.session_id;
  gchar expected_jti[WYL_ID_STRING_BUF];
  gchar expected_credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  g_strlcpy (expected_jti, jti, sizeof expected_jti);
  g_strlcpy (expected_credential, credential_id, sizeof expected_credential);

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_new_service_detached (&descriptor, &session) != WYRELOG_E_OK
      || session == NULL)
    return 11;

  memset (jti, 'x', sizeof jti - 1);
  jti[sizeof jti - 1] = '\0';
  memset (credential_id, 'x', sizeof credential_id - 1);
  credential_id[sizeof credential_id - 1] = '\0';
  memset (subject, 'x', sizeof subject - 1);
  memset (tenant, 'x', sizeof tenant - 1);

  wyl_id_t copied_id = WYL_ID_NIL;
  g_autofree gchar *copied_jti = wyl_session_dup_service_jti_private (session);
  g_autofree gchar *copied_subject =
      wyl_session_dup_service_subject_private (session);
  g_autofree gchar *copied_tenant =
      wyl_session_dup_service_tenant_private (session);
  g_autofree gchar *copied_credential =
      wyl_session_dup_service_credential_id_private (session);
  if (wyl_session_get_auth_method_private (session)
      != WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
      || !wyl_session_is_active_private (session)
      || wyl_session_copy_persistent_id_private (session, &copied_id)
      != WYRELOG_E_OK || !wyl_id_equal (&copied_id, &expected_id)
      || g_strcmp0 (copied_jti, expected_jti) != 0
      || g_strcmp0 (copied_subject, "svc:metadata-test") != 0
      || g_strcmp0 (copied_tenant, "default") != 0
      || g_strcmp0 (copied_credential, expected_credential) != 0
      || wyl_session_get_service_credential_generation_private (session)
      != G_MAXUINT64
      || wyl_session_get_service_issued_at_seconds_private (session) != 123456
      || wyl_session_get_service_expires_at_seconds_private (session) != 123756)
    return 12;

  g_autofree gchar *public_id = wyl_session_dup_id_string (session);
  gchar expected_id_text[WYL_ID_STRING_BUF];
  if (wyl_id_format (&expected_id, expected_id_text, sizeof expected_id_text)
      != WYRELOG_E_OK
      || g_strcmp0 (public_id, expected_id_text) != 0
      || wyl_session_get_id (session) != 0
      || wyl_session_dup_username (session) != NULL)
    return 13;
  return 0;
}

static gint
expect_invalid_descriptor (const wyl_service_session_descriptor_t *descriptor)
{
  WylSession *out = (WylSession *) 0x1;
  return wyl_session_new_service_detached (descriptor, &out)
      == WYRELOG_E_INVALID && out == NULL ? 0 : 1;
}

static gint
check_invalid_and_overflow (void)
{
  wyl_service_session_descriptor_t descriptor = { 0 };
  gchar jti[WYL_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  if (make_descriptor (&descriptor, jti, credential_id) != 0)
    return 20;

  WylSession *sentinel = (WylSession *) 0x1;
  if (wyl_session_new_service_detached (NULL, &sentinel) != WYRELOG_E_INVALID
      || sentinel != NULL
      || wyl_session_new_service_detached (&descriptor, NULL)
      != WYRELOG_E_INVALID)
    return 21;

#define EXPECT_INVALID(mut) G_STMT_START { \
  wyl_service_session_descriptor_t bad = descriptor; \
  mut; \
  if (expect_invalid_descriptor (&bad) != 0) return 22; \
} G_STMT_END
  EXPECT_INVALID (bad.session_id = WYL_ID_NIL);
  EXPECT_INVALID (bad.session_id.bytes[6] = 0);
  EXPECT_INVALID (bad.jti = "not-a-jti");
  EXPECT_INVALID (bad.subject_id = "human");
  EXPECT_INVALID (bad.tenant_id = "bad tenant");
  EXPECT_INVALID (bad.credential_id = "wlc_bad");
  EXPECT_INVALID (bad.credential_generation = 0);
  EXPECT_INVALID (bad.issued_at_seconds = -1);
  EXPECT_INVALID (bad.issued_at_seconds = G_MAXINT64 - 299;
      bad.expires_at_seconds = G_MAXINT64);
  EXPECT_INVALID (bad.expires_at_seconds++);
#undef EXPECT_INVALID
  return 0;
}

static gint
check_human_transition_gates (void)
{
  wyl_service_session_descriptor_t descriptor = { 0 };
  gchar jti[WYL_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  if (make_descriptor (&descriptor, jti, credential_id) != 0)
    return 30;
  g_autoptr (WylSession) session = NULL;
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_session_new_service_detached (&descriptor, &session) != WYRELOG_E_OK
      || wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 31;

  validator_calls = 0;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_POLICY
      || wyl_session_mfa_verify_with_proof (handle, session, "123456",
          unexpected_validator, NULL) != WYRELOG_E_POLICY
      || validator_calls != 0
      || wyl_session_elevate (handle, session) != WYRELOG_E_POLICY
      || wyl_session_drop_elevation (handle, session) != WYRELOG_E_POLICY
      || wyl_session_idle_timeout (handle, session) != WYRELOG_E_POLICY
      || wyl_session_expire (handle, session) != WYRELOG_E_POLICY
      || wyl_session_close (handle, session) != WYRELOG_E_POLICY
      || wyl_session_close_with_request_id (handle, session, "req")
      != WYRELOG_E_POLICY
      || wyl_session_logout (handle, wyl_session_get_id (session))
      != WYRELOG_E_NOT_FOUND)
    return 32;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_exact_copy_and_accessors ()) != 0)
    return rc;
  if ((rc = check_invalid_and_overflow ()) != 0)
    return rc;
  if ((rc = check_human_transition_gates ()) != 0)
    return rc;
  return 0;
}

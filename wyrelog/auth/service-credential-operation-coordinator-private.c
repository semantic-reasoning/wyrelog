/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-private.h"
#include "policy/store-private.h"
#include "wyl-id-private.h"
#include <chronoid/ksuid.h>
#include <sodium.h>
#include <string.h>

static gboolean
text_ok (const gchar *s, gboolean required)
{
  if (s == NULL)
    return !required;
  return (!required || *s != '\0')
      && strlen (s) <= WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_TEXT
      && g_utf8_validate (s, -1, NULL);
}

gboolean
wyl_service_credential_operation_coordinator_request_id_is_valid (const gchar
    *s)
{
  if (!text_ok (s, TRUE) || strlen (s) != 27)
    return FALSE;
  chronoid_ksuid_t parsed;
  char canonical[28];
  if (chronoid_ksuid_parse (&parsed, s, 27) != CHRONOID_KSUID_OK)
    return FALSE;
  chronoid_ksuid_format (&parsed, canonical);
  canonical[27] = '\0';
  return memcmp (canonical, s, 27) == 0;
}

static gboolean
destination_ok (const gchar *s)
{
  if (!text_ok (s, TRUE) || s[0] == '/' || s[0] == '\\'
      || strchr (s, '\\') != NULL || strchr (s, ':'))
    return FALSE;
  const gchar *p = s;
  while (*p) {
    const gchar *q = strchr (p, '/');
    gsize n = q ? (gsize) (q - p) : strlen (p);
    if (!n || (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.'))
      return FALSE;
    p = q ? q + 1 : p + n;
  }
  return TRUE;
}

static gboolean
escrow_identity_ok (const WylServiceCredentialOperationCoordinatorRequest *r)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  return r->escrow_id != NULL
      && wyl_id_parse (r->escrow_id, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && g_str_equal (r->escrow_id, canonical);
}

void wyl_service_credential_operation_coordinator_request_clear
    (WylServiceCredentialOperationCoordinatorRequest * r)
{
  if (!r)
    return;
  g_clear_pointer (&r->request_id, g_free);
  g_clear_pointer (&r->subject_id, g_free);
  g_clear_pointer (&r->tenant_id, g_free);
  g_clear_pointer (&r->destination, g_free);
  g_clear_pointer (&r->parent_identity, g_free);
  g_clear_pointer (&r->actor_subject_id, g_free);
  g_clear_pointer (&r->old_credential_id, g_free);
  g_clear_pointer (&r->escrow_id, g_free);
  memset (r, 0, sizeof *r);
}

gboolean
wyl_service_credential_operation_coordinator_request_is_valid (const
    WylServiceCredentialOperationCoordinatorRequest *r)
{
  if (!r || r->version != WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_VERSION
      || (r->kind != WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE
          && r->kind != WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE)
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (r->request_id)
      || !text_ok (r->subject_id,
          r->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE)
      || !destination_ok (r->destination)
      || !text_ok (r->parent_identity, TRUE)
      || !wyl_policy_service_actor_subject_is_valid (r->actor_subject_id)
      || !escrow_identity_ok (r)
      || r->expires_at_us <= 0 || r->expected_generation > G_MAXINT64)
    return FALSE;
  if (r->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE)
    return text_ok (r->tenant_id, TRUE) && r->old_credential_id == NULL
        && r->expected_generation == 0;
  return r->tenant_id == NULL && r->old_credential_id != NULL
      && r->expected_generation > 0
      && wyl_service_credential_id_is_canonical (r->old_credential_id,
      strlen (r->old_credential_id));
}

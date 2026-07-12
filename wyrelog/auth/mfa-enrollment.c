/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/mfa-enrollment-private.h"

#include "wyrelog/wyl-id-private.h"

#define WYL_MFA_SKIP_PERMISSION "wr.login.skip_mfa"
#define WYL_MFA_SKIP_SCOPE "login"

static wyrelog_error_t
emit_audit (wyl_policy_store_t *store, const gchar *action,
    const gchar *actor, const gchar *resource_id, const gchar *request_id,
    const gchar *origin)
{
  wyl_id_t id = WYL_ID_NIL;
  wyrelog_error_t rc = wyl_id_new (&id);
  if (rc != WYRELOG_E_OK)
    return rc;
  gchar id_str[WYL_ID_STRING_BUF];
  rc = wyl_id_format (&id, id_str, sizeof id_str);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean inserted = FALSE;
  return wyl_policy_store_append_audit_event_full (store, id_str,
      g_get_real_time (), actor, action, resource_id, NULL, origin, request_id,
      WYL_DECISION_ALLOW, &inserted);
}

static wyrelog_error_t
maybe_revoke_skip_mfa (wyl_policy_store_t *store, const gchar *subject,
    const gchar *actor, const gchar *request_id, const gchar *origin)
{
  g_autofree gchar *bootstrap_subject = NULL;
  gint64 sealed_us = 0;
  wyrelog_error_t rc = wyl_policy_store_get_bootstrap_admin (store,
      &bootstrap_subject, &sealed_us);
  if (rc != WYRELOG_E_OK || bootstrap_subject == NULL ||
      g_strcmp0 (bootstrap_subject, subject) != 0)
    return rc;

  gboolean has_perm = FALSE;
  rc = wyl_policy_store_direct_permission_exists (store, subject,
      WYL_MFA_SKIP_PERMISSION, WYL_MFA_SKIP_SCOPE, &has_perm);
  if (rc != WYRELOG_E_OK || !has_perm)
    return rc;

  wyl_id_t id = WYL_ID_NIL;
  rc = wyl_id_new (&id);
  if (rc != WYRELOG_E_OK)
    return rc;
  gchar id_str[WYL_ID_STRING_BUF];
  rc = wyl_id_format (&id, id_str, sizeof id_str);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_apply_direct_permission_mutation_with_audit (store,
      subject, WYL_MFA_SKIP_PERMISSION, WYL_MFA_SKIP_SCOPE, FALSE, id_str,
      g_get_real_time (), actor, "mfa_skip_mfa_revoked", subject, NULL,
      origin, request_id, WYL_DECISION_ALLOW);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_policy_store_apply_permission_state_transition (store, subject,
      WYL_MFA_SKIP_PERMISSION, WYL_MFA_SKIP_SCOPE, "revoke", NULL);
}

wyrelog_error_t
wyl_mfa_enrollment_commit (wyl_policy_store_t *store,
    WylTotpEnrollment *enrollment, const gchar *actor,
    const gchar *request_id, const gchar *audit_origin, gboolean reset_mode)
{
  if (store == NULL || enrollment == NULL || enrollment->subject_id == NULL ||
      enrollment->subject_id[0] == '\0' || actor == NULL || actor[0] == '\0')
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_totp_enrollment_insert (store, enrollment);
  if (rc == WYRELOG_E_OK)
    rc = emit_audit (store, reset_mode ? "mfa_reset" : "mfa_enrolled",
        actor, enrollment->id_uuidv7, request_id, audit_origin);
  if (rc == WYRELOG_E_OK)
    rc = maybe_revoke_skip_mfa (store, enrollment->subject_id, actor,
        request_id, audit_origin);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK)
    wyl_policy_store_rollback_mutation (store);
  return rc;
}

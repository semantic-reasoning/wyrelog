/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/mfa-enrollment-private.h"

#include "wyrelog/wyl-id-private.h"

#define WYL_MFA_SKIP_PERMISSION "wr.login.skip_mfa"
#define WYL_MFA_SKIP_SCOPE "login"

typedef struct
{
  const gchar *subject;
  gboolean found;
} WylMfaSubjectLookup;

static wyrelog_error_t
find_enrollment_subject_membership (const gchar *subject, const gchar *role,
    const gchar *scope, gpointer data)
{
  (void) role;
  (void) scope;
  WylMfaSubjectLookup *lookup = data;
  if (g_strcmp0 (subject, lookup->subject) == 0)
    lookup->found = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
require_enrollment_subject (wyl_policy_store_t *store, const gchar *subject)
{
  gboolean found = FALSE;
  g_autofree gchar *state = NULL;
  wyrelog_error_t rc = wyl_policy_store_get_principal_state (store, subject,
      &state, &found);
  if (rc != WYRELOG_E_OK || found)
    return rc;
  WylMfaSubjectLookup lookup = {.subject = subject };
  rc = wyl_policy_store_foreach_role_membership (store,
      find_enrollment_subject_membership, &lookup);
  if (rc != WYRELOG_E_OK)
    return rc;
  return lookup.found ? WYRELOG_E_OK : WYRELOG_E_NOT_FOUND;
}

static wyrelog_error_t
emit_audit (wyl_policy_store_t *store, const gchar *action,
    const gchar *actor, const gchar *resource_id, const gchar *request_id,
    const gchar *origin, gchar **out_id, gint64 *out_created_at_us)
{
  if (out_id != NULL)
    *out_id = NULL;
  if (out_created_at_us != NULL)
    *out_created_at_us = 0;
  wyl_id_t id = WYL_ID_NIL;
  wyrelog_error_t rc = wyl_id_new (&id);
  if (rc != WYRELOG_E_OK)
    return rc;
  gchar id_str[WYL_ID_STRING_BUF];
  rc = wyl_id_format (&id, id_str, sizeof id_str);
  if (rc != WYRELOG_E_OK)
    return rc;
  gint64 created_at_us = g_get_real_time ();
  gboolean inserted = FALSE;
  rc = wyl_policy_store_append_audit_event_full (store, id_str,
      created_at_us, actor, action, resource_id, NULL, origin, request_id,
      WYL_DECISION_ALLOW, &inserted);
  if (rc == WYRELOG_E_OK && out_id != NULL)
    *out_id = g_strdup (id_str);
  if (rc == WYRELOG_E_OK && out_created_at_us != NULL)
    *out_created_at_us = created_at_us;
  return rc;
}

static wyrelog_error_t
maybe_revoke_skip_mfa (wyl_policy_store_t *store, const gchar *subject,
    const gchar *actor, const gchar *request_id, const gchar *origin,
    gboolean *out_revoked, gchar **out_audit_id,
    gint64 *out_audit_created_at_us)
{
  *out_revoked = FALSE;
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

  rc = wyl_policy_store_revoke_direct_permission (store, subject,
      WYL_MFA_SKIP_PERMISSION, WYL_MFA_SKIP_SCOPE);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_append_direct_permission_event (store, subject,
      WYL_MFA_SKIP_PERMISSION, WYL_MFA_SKIP_SCOPE, "revoke");
  if (rc == WYRELOG_E_OK)
    rc = emit_audit (store, "mfa_skip_mfa_revoked", actor, subject,
        request_id, origin, out_audit_id, out_audit_created_at_us);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_apply_permission_state_transition_body (store,
        subject, WYL_MFA_SKIP_PERMISSION, WYL_MFA_SKIP_SCOPE, "revoke", NULL);
  if (rc == WYRELOG_E_OK)
    *out_revoked = TRUE;
  return rc;
}

void
wyl_mfa_enrollment_mutation_clear (WylMfaEnrollmentMutation *mutation)
{
  if (mutation == NULL)
    return;
  g_clear_pointer (&mutation->enrollment_audit_id, g_free);
  g_clear_pointer (&mutation->revocation_audit_id, g_free);
  mutation->enrollment_audit_created_at_us = 0;
  mutation->revocation_audit_created_at_us = 0;
  mutation->skip_mfa_revoked = FALSE;
}

wyrelog_error_t
wyl_mfa_enrollment_mutate (wyl_policy_store_t *store, gpointer data)
{
  WylMfaEnrollmentMutation *mutation = data;
  if (store == NULL || mutation == NULL || mutation->enrollment == NULL
      || mutation->enrollment->subject_id == NULL
      || mutation->enrollment->subject_id[0] == '\0'
      || mutation->actor == NULL || mutation->actor[0] == '\0')
    return WYRELOG_E_INVALID;

  wyl_mfa_enrollment_mutation_clear (mutation);
  wyrelog_error_t rc = mutation->require_existing_subject ?
      require_enrollment_subject (store, mutation->enrollment->subject_id) :
      WYRELOG_E_OK;
  WylTotpEnrollment existing = { 0 };
  gboolean already_enrolled = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_totp_enrollment_lookup (store,
        mutation->enrollment->subject_id, &existing, &already_enrolled);
  wyl_totp_enrollment_clear (&existing);
  if (rc == WYRELOG_E_OK && already_enrolled
      && mutation->reject_existing_enrollment && !mutation->reset_mode)
    rc = WYRELOG_E_CONFLICT;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_totp_enrollment_insert (store, mutation->enrollment);
  if (rc == WYRELOG_E_OK)
    rc = emit_audit (store, mutation->reset_mode ? "mfa_reset" :
        "mfa_enrolled", mutation->actor, mutation->enrollment->id_uuidv7,
        mutation->request_id, mutation->audit_origin,
        &mutation->enrollment_audit_id,
        &mutation->enrollment_audit_created_at_us);
  if (rc == WYRELOG_E_OK)
    rc = maybe_revoke_skip_mfa (store, mutation->enrollment->subject_id,
        mutation->actor, mutation->request_id, mutation->audit_origin,
        &mutation->skip_mfa_revoked, &mutation->revocation_audit_id,
        &mutation->revocation_audit_created_at_us);
  return rc;
}

wyrelog_error_t
wyl_mfa_enrollment_commit (wyl_policy_store_t *store,
    WylTotpEnrollment *enrollment, const gchar *actor,
    const gchar *request_id, const gchar *audit_origin, gboolean reset_mode)
{
  if (store == NULL || enrollment == NULL || enrollment->subject_id == NULL ||
      enrollment->subject_id[0] == '\0' || actor == NULL || actor[0] == '\0')
    return WYRELOG_E_INVALID;

  WylMfaEnrollmentMutation mutation = {
    .enrollment = enrollment,
    .actor = actor,
    .request_id = request_id,
    .audit_origin = audit_origin,
    .reset_mode = reset_mode,
  };
  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_mfa_enrollment_mutate (store, &mutation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK)
    wyl_policy_store_rollback_mutation (store);
  wyl_mfa_enrollment_mutation_clear (&mutation);
  return rc;
}

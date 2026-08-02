/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "auth/totp.h"
#include "wyrelog/error.h"
#include "wyrelog/policy/store-private.h"

typedef struct
{
  WylTotpEnrollment *enrollment;
  const gchar *actor;
  const gchar *request_id;
  const gchar *audit_origin;
  gboolean reset_mode;
  gboolean require_existing_subject;
  gboolean reject_existing_enrollment;
  gchar *enrollment_audit_id;
  gint64 enrollment_audit_created_at_us;
  gboolean skip_mfa_revoked;
  gchar *revocation_audit_id;
  gint64 revocation_audit_created_at_us;
} WylMfaEnrollmentMutation;

void wyl_mfa_enrollment_mutation_clear (WylMfaEnrollmentMutation * mutation);
wyrelog_error_t wyl_mfa_enrollment_mutate (wyl_policy_store_t * store,
    gpointer data);
wyrelog_error_t wyl_mfa_enrollment_commit (wyl_policy_store_t * store,
    WylTotpEnrollment * enrollment, const gchar * actor,
    const gchar * request_id, const gchar * audit_origin, gboolean reset_mode);

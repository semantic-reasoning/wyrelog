/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "auth/totp.h"
#include "wyrelog/error.h"
#include "wyrelog/policy/store-private.h"

wyrelog_error_t wyl_mfa_enrollment_commit (wyl_policy_store_t * store,
    WylTotpEnrollment * enrollment, const gchar * actor,
    const gchar * request_id, const gchar * audit_origin, gboolean reset_mode);

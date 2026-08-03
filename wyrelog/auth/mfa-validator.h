/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"
#include "wyrelog/session.h"

G_BEGIN_DECLS;

/*
 * Daemon-side TOTP MFA validator (issue #331 commit 3).
 *
 * Implements the WylMfaValidator callback shape (wyrelog/session.h:35)
 * so that wyl_session_mfa_verify_with_proof can apply the principal
 * FSM transition only after a 6-digit TOTP proof is accepted against
 * the per-subject enrollment stored in the policy authority store.
 *
 * Layering (constants are locked at the boundary):
 *   - wyrelog/auth/totp.{c,h}      RFC 6238 primitives (commit 1)
 *   - wyrelog/policy/store.c       totp_enrollments persistence (commit 2)
 *   - wyrelog/auth/mfa-validator.c THIS module: shape check, lookup,
 *                                  match-with-replay-defense, persist
 *                                  the watermark.
 *
 * Replay defense: the validator persists last_verified_step before the caller
 * drives MFA_OK.  The later FULL publication CASes MFA_REQUIRED and resets the
 * counter with its state/event, so a racing threshold lock wins without being
 * overwritten.  A restart between commits stays fail closed because the code
 * watermark was consumed.
 *
 * Error-code surface (commit 3 contract):
 *   WYRELOG_E_OK       proof matched, watermark advanced, caller may
 *                      drive the FSM (mark_session_mfa_verified).
 *   WYRELOG_E_INVALID  malformed input (NULL handle/session, NULL or
 *                      mis-shaped proof, NULL username).
 *   WYRELOG_E_POLICY   no enrollment, wrong code, OR matched code
 *                      replayed.  The HTTP layer (commit 4)
 *                      differentiates enrollment_required vs
 *                      mfa_invalid by inspecting the enrollment row
 *                      separately and never by branching on this
 *                      validator's return code (F5).
 *
 * No log or audit site here ever sees the seed, submitted code, or HMAC
 * intermediate.  Durable principal events are projected by the committed
 * publication path.
 */
typedef enum
{
  WYL_MFA_VALIDATION_ERROR = 0,
  WYL_MFA_VALIDATION_REJECTED,
  WYL_MFA_VALIDATION_REJECTED_LOCKED,
  WYL_MFA_VALIDATION_LOCKED,
  WYL_MFA_VALIDATION_AUTH_REQUIRED,
  WYL_MFA_VALIDATION_AUTH_REQUIRED_UNPUBLISHED,
  WYL_MFA_VALIDATION_VERIFIED,
} WylMfaValidationOutcome;

wyrelog_error_t wyl_mfa_validator_totp (WylHandle * handle,
    WylSession * session, const gchar * proof, gpointer user_data);

/* Daemon HTTP boundary for the built-in validator.  Unlike the generic
 * callback shape, this preserves the security-relevant result that was
 * established by the same durable transaction and then applies MFA_OK only
 * after a verified proof. */
wyrelog_error_t wyl_mfa_verify_totp_with_outcome (WylHandle * handle,
    WylSession * session, const gchar * proof,
    WylMfaValidationOutcome * out_outcome);

G_END_DECLS;

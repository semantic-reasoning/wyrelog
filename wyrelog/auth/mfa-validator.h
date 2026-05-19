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
 * Replay defense: the validator persists last_verified_step in the
 * policy store BEFORE the caller drives the FSM transition (the
 * fact-mutation ordering critic F3 mandates), and rejects any match
 * whose matched_step is <= the persisted watermark using strict >
 * comparison.  See mfa-validator.c for the crash-safety rationale on
 * a restart between the store write and the FSM transition.
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
 * No audit emission inside this module.  The FSM transition the
 * caller drives on success already emits a principal_state audit;
 * commit 5 will add failed-attempt audit on the FAILED_ATTEMPT
 * branch.  No log/audit site here ever sees the seed, the submitted
 * code, or any HMAC intermediate (F2).
 */
wyrelog_error_t wyl_mfa_validator_totp (WylHandle * handle,
    WylSession * session, const gchar * proof, gpointer user_data);

G_END_DECLS;

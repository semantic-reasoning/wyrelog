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
 * Replay defense: matches whose matched_step is <= the persisted
 * watermark are rejected using strict > comparison as a cheap
 * fail-fast.  The AUTHORITATIVE consumption is atomic (issue #751): on
 * a match the validator calls wyl_session_totp_commit_mfa_ok, which in
 * ONE committed-publication transaction re-reads the pre-state,
 * compare-and-advances the watermark, resets the failure counter, and
 * publishes the MFA_REQUIRED -> AUTHENTICATED principal transition.
 * Concurrent duplicates therefore yield exactly one winner, and a crash
 * can never consume the proof without producing the durable
 * authenticated state.
 *
 * Error-code surface:
 *   WYRELOG_E_OK       proof matched and the MFA_OK transition committed
 *                      durably; the session's mfa_assured bit is set.
 *   WYRELOG_E_INVALID  malformed input (NULL handle/session, NULL or
 *                      mis-shaped proof, NULL username).
 *   WYRELOG_E_POLICY   no enrollment, wrong code, a replayed/superseded
 *                      code, OR a principal no longer in mfa_required
 *                      (e.g. already authenticated by a concurrent
 *                      winner).  The HTTP layer differentiates
 *                      enrollment_required vs mfa_invalid by inspecting
 *                      the enrollment row separately and never by
 *                      branching on this validator's return code (F5).
 *   WYRELOG_E_INTERNAL a store or durability failure during the commit.
 *   WYRELOG_E_BUSY     the engine session could not be acquired.
 *
 * The atomic commit emits the principal_state audit itself.  No
 * log/audit site here ever sees the seed, the submitted code, or any
 * HMAC intermediate (F2).
 */
wyrelog_error_t wyl_mfa_validator_totp (WylHandle * handle,
    WylSession * session, const gchar * proof, gpointer user_data);

G_END_DECLS;

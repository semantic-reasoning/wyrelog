/* SPDX-License-Identifier: GPL-3.0-or-later */
/* strnlen() is POSIX 2008; expose it under strict C17 builds where
 * -std=c17 hides POSIX symbols unless a feature-test macro is set. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "auth/mfa-validator.h"

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "auth/totp.h"
#include "wyl-fsm-principal-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-log-private.h"

/*
 * Static assertion that locks the policy-store totp_enrollment secret
 * field size to the canonical RFC 6238 SHA-1 seed length surfaced by
 * the auth/totp module.  This file is the single translation unit
 * that includes both headers, so the assertion lives here.  Architect
 * required this guard during the commit-2 ratification so the two
 * constants can never silently drift across the commit-1 / commit-2
 * boundary.
 */
_Static_assert (WYL_TOTP_ENROLLMENT_SECRET_BYTES == WYL_TOTP_SEED_BYTES,
    "TOTP enrollment secret length must equal the RFC 6238 seed length");

/*
 * Six digits 0-9, exact length, no leading whitespace or padding.
 * The length guard uses strnlen with a (WYL_TOTP_DIGITS + 1)-byte
 * window so we never read past the caller's buffer for short or
 * unterminated inputs (the earlier "proof[WYL_TOTP_DIGITS] == '\\0'"
 * trailing-NUL probe was an OOB read for any non-padded buffer
 * shorter than seven bytes — see issue #331 commit-3 critic F-2).
 * After the length is fixed at exactly WYL_TOTP_DIGITS, the digit-
 * class loop is walked end-to-end without an early-out so the
 * timing of the shape check does not differentiate "first non-digit
 * at offset 0" from "first non-digit at offset 5".  The shape check
 * returns the same WYRELOG_E_INVALID regardless of which position
 * failed.
 */
static gboolean
proof_shape_is_valid (const gchar *proof)
{
  if (proof == NULL)
    return FALSE;
  if (strnlen (proof, WYL_TOTP_DIGITS + 1) != WYL_TOTP_DIGITS)
    return FALSE;

  gboolean ok = TRUE;
  gsize i;
  for (i = 0; i < WYL_TOTP_DIGITS; i++) {
    gchar c = proof[i];
    if (c < '0' || c > '9')
      ok = FALSE;
  }
  return ok;
}

static guint
parse_six_digits (const gchar *proof)
{
  guint code = 0;
  for (gsize i = 0; i < WYL_TOTP_DIGITS; i++)
    code = code * 10 + (guint) (proof[i] - '0');
  return code;
}

/*
 * Issue #331 decision 5 constants: 5 consecutive failures lock the
 * principal; 15 minutes of wallclock idle after locked_at auto-unlocks.
 * The constants live in this translation unit, not in policy/store.c,
 * because lockout-policy values are an auth-layer concern - the policy
 * store only persists the counter and timestamp the validator hands it.
 */
#define WYL_MFA_LOCKOUT_THRESHOLD     5
#define WYL_MFA_AUTO_UNLOCK_SECONDS   (15 * 60)

/*
 * Drive the principal FSM through a FAILED_ATTEMPT event from the
 * MFA_REQUIRED state, and persist the failure to the policy store.
 *
 * In commit 3 this was a pure FSM-shape probe with no durable counter;
 * commit 5 layers durable counter + lockout on top, atomically inside a
 * savepoint via wyl_policy_store_apply_principal_failure.  The store
 * transaction defeats the read-modify-write race that would otherwise
 * let N concurrent failed verify attempts each see counter=N-1 and
 * each fail to LOCK independently (commit-5 critic footgun).
 *
 * Returns WYRELOG_E_OK on success, WYRELOG_E_INVALID for malformed
 * arguments, or WYRELOG_E_INTERNAL on a store fault (the iteration
 * fed back from architect+critic ratification: a transient IO error
 * on the counter write MUST surface as a fail-closed validator return
 * rather than be silently swallowed, otherwise an attacker who can
 * induce IO pressure could brute-force without ever crossing the
 * lockout threshold).
 *
 * F2 (secrets): the policy-store helper never sees the submitted code
 * or the TOTP seed; it only touches subject_id and the integer
 * counter/locked_at.  This callsite likewise carries neither.  The
 * operator-visibility WYL_LOG_WARN on IO failure logs only subject_id
 * and the integer error code.
 *
 * The three negative paths (no enrollment, wrong code, replay) still
 * intentionally differ in computational cost: wrong-code and replay
 * perform 3x HMAC-SHA-1 via wyl_totp_code_matches, while the
 * no-enrollment path skips that work.  Issue #331 decision 7 requires
 * the HTTP layer to surface `enrollment_required` as a distinct error
 * code from `mfa_invalid`, so the no-enrollment bit is already
 * deliberately public at the API surface.  Adding a dummy HMAC here
 * to mask a bit that the spec discloses would be hardening theater,
 * not defense.  Commit 5 adds a savepoint write on every failure
 * branch, which is at most a low-microsecond fixed cost shared by all
 * three negative paths, so the relative differential among them is
 * unchanged from commit 3.
 */
static wyrelog_error_t
note_failed_attempt (WylHandle *handle, const gchar *subject_id)
{
  wyl_principal_state_t next = WYL_PRINCIPAL_STATE_LAST_;
  (void) wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_MFA_REQUIRED,
      WYL_PRINCIPAL_EVENT_FAILED_ATTEMPT, &next);

  if (handle == NULL || subject_id == NULL || subject_id[0] == '\0')
    return WYRELOG_E_INVALID;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_INTERNAL;
  g_autofree gchar *new_state = NULL;
  gint64 new_count = 0;
  gint64 new_locked_at = 0;
  /* Fail closed (architect ratification, commit-5 iteration): an IO
   * error on the counter write means we cannot durably advance the
   * lockout state, so the validator MUST refuse the verify instead of
   * silently dropping the failure - otherwise an attacker who can
   * induce IO pressure could keep brute-forcing without ever crossing
   * the threshold.  The caller maps E_INTERNAL to a 500 mfa_verify_failed
   * response at the HTTP layer (see mfa_verify_handler).
   *
   * Note the asymmetry with reset_principal_failure_counter on the
   * success path: that reset is intentionally best-effort because a
   * transient IO blip there would DoS a user who has already proven
   * possession of the seed, and the counter will be reset on the next
   * successful verify. */
  wyrelog_error_t rc = wyl_policy_store_apply_principal_failure (store,
      subject_id, WYL_MFA_LOCKOUT_THRESHOLD, (gint64) time (NULL),
      &new_state, &new_count, &new_locked_at);
  if (rc != WYRELOG_E_OK) {
    /* Operator-visibility on the IO fault.  Keyed on subject_id and the
     * error code; never includes the submitted code or the seed (F2). */
    WYL_LOG_WARN (WYL_LOG_SECTION_POLICY,
        "mfa: failed to durably record failed attempt for subject_id=%s rc=%d",
        subject_id, (int) rc);
    return WYRELOG_E_INTERNAL;
  }
  return WYRELOG_E_OK;
}

/*
 * Auto-unlock check.  When the principal is in LOCKED state and the
 * 15-minute window has elapsed since locked_at, transition the row to
 * UNVERIFIED via the FSM UNLOCK edge and return TRUE so the caller can
 * treat the verify as "session no longer in mfa_required" (the FSM
 * design routes auto-unlock back to UNVERIFIED, not MFA_REQUIRED -
 * see issue #331 critic flag during commit-4 iteration).
 *
 * Returns TRUE iff the auto-unlock happened.  Returns FALSE when the
 * window has not elapsed, when the principal is not locked, or on a
 * store fault (fail-closed: the row stays as-is and the caller sees
 * the same E_POLICY surface).
 */
static gboolean
maybe_auto_unlock (WylHandle *handle, const gchar *subject_id,
    const gchar *current_state, gint64 locked_at, gint64 now)
{
  if (g_strcmp0 (current_state, "locked") != 0)
    return FALSE;
  if (locked_at == G_MININT64)
    return FALSE;
  if (now < locked_at + WYL_MFA_AUTO_UNLOCK_SECONDS)
    return FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return FALSE;
  if (wyl_policy_store_apply_principal_unlock (store, subject_id)
      != WYRELOG_E_OK)
    return FALSE;
  return TRUE;
}

wyrelog_error_t
wyl_mfa_validator_totp (WylHandle *handle, WylSession *session,
    const gchar *proof, gpointer user_data)
{
  (void) user_data;

  if (handle == NULL || session == NULL)
    return WYRELOG_E_INVALID;
  if (!proof_shape_is_valid (proof))
    return WYRELOG_E_INVALID;

  g_autofree gchar *subject_id = wyl_session_dup_username (session);
  if (subject_id == NULL || subject_id[0] == '\0')
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_INTERNAL;

  gint64 now = (gint64) time (NULL);

  /*
   * Lockout gate (issue #331 commit 5).  We consult the principal_state
   * row BEFORE touching the TOTP enrollment so a locked principal
   * never triggers an HMAC computation - this is a fail-closed
   * shortcut and the lockout-without-hmac test in
   * test-daemon-mfa-validator locks it down.  If the row's auto-unlock
   * window has elapsed we transition LOCKED -> UNVERIFIED and return
   * E_POLICY (the caller's session-state gate will treat the principal
   * as no longer mfa_required and bounce the verify; the user must
   * re-login per the existing FSM design).
   */
  g_autofree gchar *pstate = NULL;
  gint64 pcount = 0;
  gint64 plocked_at = 0;
  gboolean pfound = FALSE;
  wyrelog_error_t rc = wyl_policy_store_get_principal_lock_info (store,
      subject_id, &pstate, &pcount, &plocked_at, &pfound);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (pfound && g_strcmp0 (pstate, "locked") == 0) {
    if (maybe_auto_unlock (handle, subject_id, pstate, plocked_at, now)) {
      /* Row is now UNVERIFIED.  The verify-with-proof contract bounces
       * because the principal is no longer in mfa_required; HTTP layer
       * will surface mfa_auth_required (uniform) on the next call. */
      return WYRELOG_E_POLICY;
    }
    /* Still inside the lockout window: fail closed without consulting
     * the TOTP enrollment.  F1 timing: the HMAC branch is skipped,
     * which is faster than wrong-code/replay paths - but the LOCKED
     * state is already publicly visible via the HTTP 429 mfa_locked
     * response (issue #331 spec), so the timing differential discloses
     * nothing the spec does not. */
    return WYRELOG_E_POLICY;
  }

  /*
   * F5 (enumeration via differential error codes): every negative
   * outcome below funnels through the same WYRELOG_E_POLICY return.
   * The HTTP layer (commit 4) distinguishes enrollment_required vs
   * mfa_invalid by inspecting the enrollment row separately, not by
   * branching on this validator's return code.
   */
  WylTotpEnrollment enr = { 0 };
  gboolean found = FALSE;
  rc = wyl_policy_store_totp_enrollment_lookup (store, subject_id, &enr,
      &found);
  if (rc != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&enr);
    return rc;
  }
  if (!found) {
    /* Drive the same FSM FAILED_ATTEMPT branch the wrong-code path
     * takes so the lockout counter sees every failed verify uniformly.
     * This does NOT equalise the timing of the no-enrollment vs
     * wrong-code branches - see the rationale above note_failed_attempt
     * for why the differential is intentional and consistent with
     * issue #331 decision 7. */
    wyrelog_error_t note_rc = note_failed_attempt (handle, subject_id);
    wyl_totp_enrollment_clear (&enr);
    if (note_rc != WYRELOG_E_OK)
      return WYRELOG_E_INTERNAL;
    return WYRELOG_E_POLICY;
  }

  guint submitted_code = parse_six_digits (proof);
  guint64 matched_step = 0;

  gboolean matched = wyl_totp_code_matches (enr.secret, sizeof enr.secret,
      now, submitted_code, &matched_step, NULL);
  if (!matched) {
    wyrelog_error_t note_rc = note_failed_attempt (handle, subject_id);
    wyl_totp_enrollment_clear (&enr);
    if (note_rc != WYRELOG_E_OK)
      return WYRELOG_E_INTERNAL;
    return WYRELOG_E_POLICY;
  }

  /*
   * Replay defense (architect rule 2, critic F3).  STRICT >, NOT >=:
   * a matched_step equal to the persisted watermark is a replay of
   * the most recently accepted code and MUST fail closed.  The
   * commit-2 schema seeds last_verified_step at INT64_MIN, so any
   * fresh enrollment always satisfies matched_step > last_verified_step
   * on the first call.
   *
   * The signed/unsigned comparison is fine: matched_step is a
   * non-negative step counter that fits well below INT64_MAX for any
   * plausible epoch (RFC 6238 step counts run at 1/30 Hz), and the
   * cast to gint64 is safe.  Should an attacker somehow place a step
   * above INT64_MAX, the gint64 cast would saturate to a negative
   * value and the comparison would reject - which is the conservative
   * direction.
   */
  if ((gint64) matched_step <= enr.last_verified_step) {
    wyrelog_error_t note_rc = note_failed_attempt (handle, subject_id);
    wyl_totp_enrollment_clear (&enr);
    if (note_rc != WYRELOG_E_OK)
      return WYRELOG_E_INTERNAL;
    return WYRELOG_E_POLICY;
  }

  /*
   * Persist the new watermark BEFORE the caller drives the FSM
   * (critic F3).  The two writes (totp_enrollments watermark, FSM
   * principal_state mutation) live in different SQLite-row families
   * inside the same encrypted policy store, but they are not joined
   * by an outer BEGIN IMMEDIATE here because:
   *
   *   - mark_session_mfa_verified (the caller, in wyl-session.c) opens
   *     its own BEGIN IMMEDIATE / COMMIT around the principal_state
   *     update via apply_principal_state_mutation.  Nesting our
   *     update_step inside that transaction would require either a
   *     savepoint or a re-plumbing of the FSM mutation path that is
   *     out of scope for commit 3.
   *
   *   - The crash-safety contract we want here is fail-closed: if
   *     the daemon crashes after this update_step COMMITs but before
   *     the FSM mutation COMMITs, the next attempt with the SAME
   *     code will be rejected because last_verified_step is already
   *     advanced (matched_step <= persisted watermark).  The session
   *     remains mfa_required (FSM state was not advanced), so the
   *     client must obtain a fresh code at a later step.  This is
   *     verified by the restart-simulation test in
   *     tests/test-daemon-mfa-validator.c.
   *
   * F2: no log/audit emission below ever sees the seed or the code.
   */
  rc = wyl_policy_store_totp_enrollment_update_step (store, subject_id,
      (gint64) matched_step);
  wyl_totp_enrollment_clear (&enr);
  if (rc != WYRELOG_E_OK)
    return rc;

  /*
   * Commit-5: a successful TOTP verify resets the lockout counter and
   * clears any prior locked_at on the principal_states row.  This is
   * idempotent when the counter is already zero, so the call is safe
   * to make on every happy path regardless of prior history.
   *
   * Intentional asymmetry with note_failed_attempt (architect ratification,
   * commit-5 iteration): the failure path is FAIL-CLOSED on a counter-
   * write IO error (otherwise an attacker who induces IO pressure could
   * brute-force without ever crossing the threshold), while this success-
   * path counter reset is BEST-EFFORT - a transient IO blip after a
   * verified seed must not DoS a user who has already proven possession,
   * and the next successful verify will retry the reset.  Hence the
   * (void) cast on the return value here is deliberate.
   */
  (void) wyl_policy_store_reset_principal_failure_counter (store, subject_id);

  return WYRELOG_E_OK;
}

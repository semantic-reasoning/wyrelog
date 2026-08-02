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

typedef struct
{
  WylHandle *handle;
  const gchar *subject_id;
  gint64 now;
  WylEnginePublicationMode publication_mode;
  WylPolicyPrincipalFailureReceipt receipt;
} WylMfaFailurePublication;

typedef struct
{
  WylHandle *handle;
  const gchar *subject_id;
  gint64 now;
  WylEnginePublicationMode publication_mode;
  WylPolicyPrincipalUnlockReceipt receipt;
} WylMfaUnlockPublication;

typedef enum
{
  WYL_MFA_AUTO_UNLOCK_PRECOMMIT_ERROR = 0,
  WYL_MFA_AUTO_UNLOCK_NOT_LOCKED,
  WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED,
  WYL_MFA_AUTO_UNLOCK_PUBLISHED,
  WYL_MFA_AUTO_UNLOCK_COMMITTED_UNPUBLISHED,
} WylMfaAutoUnlockOutcome;

static wyrelog_error_t
verification_has_symbols (WylEngineVerification *verification,
    const gchar *relation, const gchar *const *symbols, gsize ncols,
    gboolean *out_found)
{
  if (out_found == NULL)
    return WYRELOG_E_INVALID;
  *out_found = FALSE;
  g_autofree gint64 *row = g_new0 (gint64, ncols);
  for (gsize i = 0; i < ncols; i++) {
    wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
        symbols[i], &row[i]);
    if (rc == WYRELOG_E_NOT_FOUND)
      return WYRELOG_E_OK;
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return wyl_engine_verification_contains (verification, relation, row, ncols,
      out_found);
}

static wyrelog_error_t
verify_single_current_principal_state (WylEngineVerification *verification,
    const gchar *subject_id)
{
  static const gchar *states[] = {
    "unverified",
    "mfa_required",
    "authenticated",
    "locked",
    "revoked",
  };
  guint matches = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (states); i++) {
    const gchar *state_symbols[] = { subject_id, states[i] };
    gboolean found = FALSE;
    wyrelog_error_t rc = verification_has_symbols (verification,
        "principal_state", state_symbols, G_N_ELEMENTS (state_symbols),
        &found);
    if (rc != WYRELOG_E_OK)
      return rc;
    matches += found ? 1 : 0;
  }
  return matches == 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
build_principal_event_row (WylEngineVerification *verification,
    gint64 event_id, const gchar *subject_id, const gchar *event,
    const gchar *from_state, const gchar *to_state, gint64 row[5])
{
  if (event_id <= 0)
    return WYRELOG_E_POLICY;
  row[0] = event_id;
  const gchar *symbols[] = { subject_id, from_state, event, to_state };
  for (gsize i = 0; i < G_N_ELEMENTS (symbols); i++) {
    wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
        symbols[i], &row[i + 1]);
    if (rc != WYRELOG_E_OK)
      return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
verify_principal_publication (WylEngineVerification *verification,
    const gchar *subject_id, const gchar *state, const gchar *event,
    const gchar *from_state, gint64 event_id)
{
  gint64 event_row[5] = { 0 };
  wyrelog_error_t rc = build_principal_event_row (verification, event_id,
      subject_id, event, from_state, state, event_row);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean found = FALSE;
  rc = wyl_engine_verification_contains (verification, "principal_fired",
      event_row, G_N_ELEMENTS (event_row), &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;
  /* The exact transition event proves that this committed mutation is present.
   * The current state may already be a serialized successor from the same
   * candidate snapshot, so require one recognized current state instead of
   * incorrectly insisting that this transition's target is still current. */
  return verify_single_current_principal_state (verification, subject_id);
}

static wyrelog_error_t
enqueue_principal_event (WylEngineVerification *verification,
    const gchar *subject_id, const gchar *state, const gchar *event,
    const gchar *from_state, gint64 event_id)
{
  gint64 event_row[5] = { 0 };
  wyrelog_error_t rc = build_principal_event_row (verification, event_id,
      subject_id, event, from_state, state, event_row);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_engine_verification_enqueue_delta (verification,
      "principal_fired", event_row, G_N_ELEMENTS (event_row), WYL_DELTA_INSERT);
}

static wyrelog_error_t
mutate_failed_attempt (wyl_policy_store_t *store, gpointer data)
{
  WylMfaFailurePublication *ctx = data;
  wyrelog_error_t rc = wyl_policy_store_apply_principal_failure_body (store,
      ctx->subject_id, WYL_MFA_LOCKOUT_THRESHOLD, ctx->now, &ctx->receipt);
  if (rc == WYRELOG_E_OK)
    ctx->publication_mode = ctx->receipt.projection_changed ?
        WYL_ENGINE_PUBLICATION_FULL : WYL_ENGINE_PUBLICATION_NONE;
  return rc;
}

static wyrelog_error_t
verify_failed_attempt (WylEngineVerification *verification, gpointer data)
{
  WylMfaFailurePublication *ctx = data;
  if (!ctx->receipt.projection_changed)
    return WYRELOG_E_INTERNAL;
  return verify_principal_publication (verification, ctx->subject_id, "locked",
      "lock", "mfa_required", ctx->receipt.event_id);
}

static wyrelog_error_t
produce_failed_attempt_delta (WylEngineVerification *verification,
    gpointer data)
{
  WylMfaFailurePublication *ctx = data;
  return enqueue_principal_event (verification, ctx->subject_id, "locked",
      "lock", "mfa_required", ctx->receipt.event_id);
}

static wyrelog_error_t
mutate_auto_unlock (wyl_policy_store_t *store, gpointer data)
{
  WylMfaUnlockPublication *ctx = data;
  wyrelog_error_t rc = wyl_policy_store_apply_principal_unlock_body (store,
      ctx->subject_id, ctx->now, WYL_MFA_AUTO_UNLOCK_SECONDS, &ctx->receipt);
  if (rc == WYRELOG_E_OK)
    ctx->publication_mode = ctx->receipt.outcome ==
        WYL_POLICY_PRINCIPAL_UNLOCKED ? WYL_ENGINE_PUBLICATION_FULL :
        WYL_ENGINE_PUBLICATION_NONE;
  return rc;
}

static wyrelog_error_t
verify_auto_unlock (WylEngineVerification *verification, gpointer data)
{
  WylMfaUnlockPublication *ctx = data;
  return verify_principal_publication (verification, ctx->subject_id,
      "unverified", "unlock", "locked", ctx->receipt.event_id);
}

static wyrelog_error_t
produce_auto_unlock_delta (WylEngineVerification *verification, gpointer data)
{
  WylMfaUnlockPublication *ctx = data;
  return enqueue_principal_event (verification, ctx->subject_id, "unverified",
      "unlock", "locked", ctx->receipt.event_id);
}

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
 * arguments, or the store/publication failure after fencing any live pair
 * whose post-commit projection is uncertain (the iteration
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
note_failed_attempt (WylHandle *handle, const gchar *subject_id,
    gboolean *out_locked, gboolean *out_already_locked)
{
  if (out_locked == NULL || out_already_locked == NULL)
    return WYRELOG_E_INVALID;
  *out_locked = FALSE;
  *out_already_locked = FALSE;
  wyl_principal_state_t next = WYL_PRINCIPAL_STATE_LAST_;
  (void) wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_MFA_REQUIRED,
      WYL_PRINCIPAL_EVENT_FAILED_ATTEMPT, &next);

  if (handle == NULL || subject_id == NULL || subject_id[0] == '\0')
    return WYRELOG_E_INVALID;
  /* Fail closed (architect ratification, commit-5 iteration): an IO
   * error on the counter write means we cannot durably advance the
   * lockout state, so the validator MUST refuse the verify instead of
   * silently dropping the failure - otherwise an attacker who can
   * induce IO pressure could keep brute-forcing without ever crossing
   * the threshold.  The caller maps E_INTERNAL to a 500 mfa_verify_failed
   * response at the HTTP layer (see mfa_verify_handler).
   *
   * The success-side reset is committed later with the exact MFA_OK
   * principal-state transition, so a racing threshold lock cannot be erased. */
  WylMfaFailurePublication publication = {
    .handle = handle,
    .subject_id = subject_id,
    .now = (gint64) time (NULL),
    .publication_mode = WYL_ENGINE_PUBLICATION_INVALID,
    .receipt = {0},
  };
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return WYRELOG_E_BUSY;
  gboolean commit_confirmed = FALSE;
  wyrelog_error_t rc =
      wyl_engine_session_run_conditional_committed_publication (engine_session,
      mutate_failed_attempt, &publication, &publication.publication_mode,
      verify_failed_attempt, &publication, produce_failed_attempt_delta,
      &publication, &commit_confirmed);
  if (rc != WYRELOG_E_OK) {
    /* The principal can become locked after this request's initial gate but
     * before its serialized mutation runs.  That expected supersession is a
     * policy rejection, not an infrastructure failure: the winning request
     * has already published the exact lock transition under the same engine
     * session.  Re-read only the authoritative locked state; every other
     * mutation error remains fail closed as INTERNAL. */
    if (rc == WYRELOG_E_POLICY && !commit_confirmed) {
      g_autofree gchar *state = NULL;
      gint64 count = 0, locked_at = 0;
      gboolean found = FALSE;
      wyrelog_error_t read_rc = wyl_policy_store_get_principal_lock_info
          (wyl_handle_get_policy_store (handle), subject_id, &state, &count,
          &locked_at, &found);
      if (read_rc == WYRELOG_E_OK && found && g_strcmp0 (state, "locked") == 0) {
        *out_already_locked = TRUE;
        return WYRELOG_E_OK;
      }
    }
    /* Operator-visibility on the IO fault.  Keyed on subject_id and the
     * error code; never includes the submitted code or the seed (F2). */
    WYL_LOG_WARN (WYL_LOG_SECTION_POLICY,
        "mfa: failed to durably record failed attempt for subject_id=%s rc=%d",
        subject_id, (int) rc);
    return WYRELOG_E_INTERNAL;
  }
  *out_locked = publication.receipt.projection_changed;
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
 * Returns an error-bearing result and writes TRUE only after the durable
 * unlock, full engine rebuild, and exact state/event verification all finish.
 * A non-locked row or an unelapsed window returns OK with FALSE.  Store and
 * publication failures remain distinguishable and fail closed.
 */
static wyrelog_error_t
maybe_auto_unlock (WylHandle *handle, const gchar *subject_id,
    const gchar *current_state, gint64 locked_at, gint64 now,
    WylMfaAutoUnlockOutcome *out_outcome)
{
  if (out_outcome == NULL)
    return WYRELOG_E_INVALID;
  *out_outcome = WYL_MFA_AUTO_UNLOCK_PRECOMMIT_ERROR;
  if (g_strcmp0 (current_state, "locked") != 0) {
    *out_outcome = WYL_MFA_AUTO_UNLOCK_NOT_LOCKED;
    return WYRELOG_E_OK;
  }
  (void) locked_at;
  WylMfaUnlockPublication publication = {
    .handle = handle,
    .subject_id = subject_id,
    .now = now,
    .publication_mode = WYL_ENGINE_PUBLICATION_INVALID,
    .receipt = {0},
  };
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return WYRELOG_E_BUSY;
  gboolean commit_confirmed = FALSE;
  wyrelog_error_t rc =
      wyl_engine_session_run_conditional_committed_publication (engine_session,
      mutate_auto_unlock, &publication, &publication.publication_mode,
      verify_auto_unlock, &publication, produce_auto_unlock_delta, &publication,
      &commit_confirmed);
  if (rc != WYRELOG_E_OK) {
    if (commit_confirmed && publication.receipt.outcome ==
        WYL_POLICY_PRINCIPAL_UNLOCKED)
      *out_outcome = WYL_MFA_AUTO_UNLOCK_COMMITTED_UNPUBLISHED;
    return rc;
  }
  if (publication.receipt.outcome == WYL_POLICY_PRINCIPAL_UNLOCKED)
    *out_outcome = WYL_MFA_AUTO_UNLOCK_PUBLISHED;
  else if (publication.receipt.outcome ==
      WYL_POLICY_PRINCIPAL_UNLOCK_NOT_ELAPSED)
    *out_outcome = WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED;
  else
    *out_outcome = WYL_MFA_AUTO_UNLOCK_NOT_LOCKED;
  return rc;
}

static wyrelog_error_t
validate_totp_with_outcome (WylHandle *handle, WylSession *session,
    const gchar *proof, WylMfaValidationOutcome *out_outcome)
{
  if (out_outcome == NULL)
    return WYRELOG_E_INVALID;
  *out_outcome = WYL_MFA_VALIDATION_ERROR;
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
    WylMfaAutoUnlockOutcome unlock_outcome =
        WYL_MFA_AUTO_UNLOCK_PRECOMMIT_ERROR;
    rc = maybe_auto_unlock (handle, subject_id, pstate, plocked_at, now,
        &unlock_outcome);
    if (rc != WYRELOG_E_OK) {
      if (unlock_outcome == WYL_MFA_AUTO_UNLOCK_COMMITTED_UNPUBLISHED)
        *out_outcome = WYL_MFA_VALIDATION_AUTH_REQUIRED_UNPUBLISHED;
      return rc;
    }
    if (unlock_outcome == WYL_MFA_AUTO_UNLOCK_PUBLISHED
        || unlock_outcome == WYL_MFA_AUTO_UNLOCK_NOT_LOCKED) {
      /* Row is now UNVERIFIED.  The verify-with-proof contract bounces
       * because the principal is no longer in mfa_required; HTTP layer
       * will surface mfa_auth_required (uniform) on the next call. */
      *out_outcome = WYL_MFA_VALIDATION_AUTH_REQUIRED;
      return WYRELOG_E_POLICY;
    }
    /* Still inside the lockout window: fail closed without consulting
     * the TOTP enrollment.  F1 timing: the HMAC branch is skipped,
     * which is faster than wrong-code/replay paths - but the LOCKED
     * state is already publicly visible via the HTTP 429 mfa_locked
     * response (issue #331 spec), so the timing differential discloses
     * nothing the spec does not. */
    *out_outcome = WYL_MFA_VALIDATION_LOCKED;
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
    gboolean locked = FALSE;
    gboolean already_locked = FALSE;
    wyrelog_error_t note_rc = note_failed_attempt (handle, subject_id,
        &locked, &already_locked);
    wyl_totp_enrollment_clear (&enr);
    if (note_rc != WYRELOG_E_OK)
      return note_rc;
    *out_outcome = already_locked ? WYL_MFA_VALIDATION_LOCKED :
        locked ? WYL_MFA_VALIDATION_REJECTED_LOCKED :
        WYL_MFA_VALIDATION_REJECTED;
    return WYRELOG_E_POLICY;
  }

  guint submitted_code = parse_six_digits (proof);
  guint64 matched_step = 0;

  gboolean matched = wyl_totp_code_matches (enr.secret, sizeof enr.secret,
      now, submitted_code, &matched_step, NULL);
  if (!matched) {
    gboolean locked = FALSE;
    gboolean already_locked = FALSE;
    wyrelog_error_t note_rc = note_failed_attempt (handle, subject_id,
        &locked, &already_locked);
    wyl_totp_enrollment_clear (&enr);
    if (note_rc != WYRELOG_E_OK)
      return note_rc;
    *out_outcome = already_locked ? WYL_MFA_VALIDATION_LOCKED :
        locked ? WYL_MFA_VALIDATION_REJECTED_LOCKED :
        WYL_MFA_VALIDATION_REJECTED;
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
    gboolean locked = FALSE;
    gboolean already_locked = FALSE;
    wyrelog_error_t note_rc = note_failed_attempt (handle, subject_id,
        &locked, &already_locked);
    wyl_totp_enrollment_clear (&enr);
    if (note_rc != WYRELOG_E_OK)
      return note_rc;
    *out_outcome = already_locked ? WYL_MFA_VALIDATION_LOCKED :
        locked ? WYL_MFA_VALIDATION_REJECTED_LOCKED :
        WYL_MFA_VALIDATION_REJECTED;
    return WYRELOG_E_POLICY;
  }

  /* Persist the watermark before the caller's MFA_OK FULL publication.  A
   * crash in between remains fail closed because the same code cannot be
   * reused.  Exact concurrent watermark consumption is tracked by #751; this
   * issue fences only the projected principal authority transition. */
  rc = wyl_policy_store_totp_enrollment_update_step (store, subject_id,
      (gint64) matched_step);
  wyl_totp_enrollment_clear (&enr);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_outcome = WYL_MFA_VALIDATION_VERIFIED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_mfa_validator_totp (WylHandle *handle, WylSession *session,
    const gchar *proof, gpointer user_data)
{
  (void) user_data;
  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
  return validate_totp_with_outcome (handle, session, proof, &outcome);
}

wyrelog_error_t
wyl_mfa_verify_totp_with_outcome (WylHandle *handle, WylSession *session,
    const gchar *proof, WylMfaValidationOutcome *out_outcome)
{
  wyrelog_error_t rc = validate_totp_with_outcome (handle, session, proof,
      out_outcome);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_session_mfa_verify (handle, session);
    if (rc != WYRELOG_E_OK)
      *out_outcome = WYL_MFA_VALIDATION_ERROR;
  }
  return rc;
}

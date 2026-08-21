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
#include "wyl-session-private.h"
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
 * #746: a durable principal transition (MFA_REQUIRED -> LOCKED on the
 * threshold crossing, LOCKED -> UNVERIFIED on auto-unlock) must be
 * published to the live read/delta engine pair, otherwise authorization
 * keeps evaluating against a stale projection that never observed the
 * lockout.  We reuse the #745 committed-publication contract exactly the
 * way service-credential-domain.c does: the durable mutation has already
 * committed in its own savepoint (apply_principal_failure /
 * apply_principal_unlock), so we drive
 * wyl_engine_session_finish_external_publication with COMMIT_COMMITTED,
 * which rebuilds the full engine pair from the current durable snapshot,
 * runs the verifier against the rebuilt candidate, and poisons the pair
 * on any post-commit uncertainty.
 */
typedef struct
{
  const gchar *subject_id;
  wyl_principal_state_t from_state;
  wyl_principal_event_t event;
  wyl_principal_state_t to_state;
  gint64 event_id;
} WylMfaPrincipalPublication;

/*
 * Prove ONLY the immutable principal_fired event row keyed by event_id.
 * The mutable principal_state row is deliberately NOT asserted: a
 * legitimate superseding commit may have already moved it, whereas the
 * append-only event row is always present after a correct rebuild from
 * the durable snapshot - which is exactly what proves the freshly-built
 * projection is not older than current durable authority.  The row
 * shape mirrors wyl-session.c's principal event verifier: the
 * principal_fired/5 column order is {event_id, subject, from, event, to}.
 */
static wyrelog_error_t
verify_principal_event_row (WylEngineVerification *verification, gpointer data)
{
  WylMfaPrincipalPublication *ctx = data;
  const gchar *from_name = wyl_principal_state_name (ctx->from_state);
  const gchar *event_name = wyl_principal_event_name (ctx->event);
  const gchar *to_name = wyl_principal_state_name (ctx->to_state);
  if (from_name == NULL || event_name == NULL || to_name == NULL)
    return WYRELOG_E_INTERNAL;
  if (ctx->event_id <= 0)
    return WYRELOG_E_POLICY;

  gint64 row[5] = { ctx->event_id, 0, 0, 0, 0 };
  const gchar *symbols[] = { ctx->subject_id, from_name, event_name, to_name };
  for (guint i = 0; i < G_N_ELEMENTS (symbols); i++) {
    wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
            symbols[i], &row[i + 1]);
    /* A missing symbol means the row cannot be present: fail closed. */
    if (rc == WYRELOG_E_NOT_FOUND)
      return WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  gboolean exact = FALSE;
  wyrelog_error_t rc =
      wyl_engine_verification_has_exact_keyed_row (verification,
          "principal_fired", ctx->event_id, row, G_N_ELEMENTS (row), &exact);
  if (rc != WYRELOG_E_OK)
    return rc;
  return exact ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

/*
 * Publish a principal transition to the live engine pair by proving the
 * immutable event row.  Fails closed on every uncertainty: a poisoned
 * pair, an unacquirable session, a generation mismatch, or a verifier
 * rejection all propagate a non-OK result (and, past commit,
 * finish_external_publication poisons the pair before returning).  For a
 * genuinely unopened engine (template_dir == NULL, no engines) the
 * acquire still succeeds and finish_external_publication returns OK
 * without poisoning, so unopened deployments stay valid.
 */
static wyrelog_error_t
publish_principal_transition (WylHandle *handle, const gchar *subject_id,
    wyl_principal_state_t from_state, wyl_principal_event_t event,
    wyl_principal_state_t to_state, gint64 event_id)
{
  if (handle == NULL || subject_id == NULL)
    return WYRELOG_E_INVALID;
  /* An already-poisoned pair means the projection is untrustworthy; never
   * report OK (finish_external_publication would return E_INVALID without
   * re-poisoning, but we short-circuit to keep the intent explicit). */
  if (wyl_handle_engine_pair_is_poisoned (handle))
    return WYRELOG_E_INTERNAL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_INTERNAL;
  WylEngineSession *session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_INTERNAL;
  guint64 generation = 0;
  wyrelog_error_t rc = wyl_handle_policy_store_capture_generation (handle,
          store, &generation);
  if (rc == WYRELOG_E_OK) {
    WylMfaPrincipalPublication ctx = {
      subject_id, from_state, event, to_state, event_id
    };
    rc = wyl_engine_session_finish_external_publication (session, store,
            generation, WYL_DURABLE_COMMIT_COMMITTED, verify_principal_event_row,
            &ctx);
  }
  wyl_engine_session_release (session);
  return rc;
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
  gint64 event_id = 0;
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
          &new_state, &new_count, &new_locked_at, &event_id);
  /* #752: WYRELOG_E_POLICY here means the principal is no longer in
   * mfa_required - a concurrent winning verify already authenticated it,
   * or a race unlocked/locked it (apply_principal_failure now gates on
   * state=mfa_required).  There is simply no failed-attempt to count and
   * no lockout to publish; this is benign, not a store fault.  Report
   * success so the caller still rejects the verify with WYRELOG_E_POLICY
   * instead of surfacing a spurious 500.  Only a genuine store fault
   * (E_IO/E_INTERNAL) fails closed below. */
  if (rc == WYRELOG_E_POLICY)
    return WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK) {
    /* Operator-visibility on the IO fault.  Keyed on subject_id and the
    * error code; never includes the submitted code or the seed (F2). */
    WYL_LOG_WARN (WYL_LOG_SECTION_POLICY,
        "mfa: failed to durably record failed attempt for subject_id=%s rc=%d",
        subject_id, (int) rc);
    return WYRELOG_E_INTERNAL;
  }

  /* #746: a fresh threshold crossing (MFA_REQUIRED -> LOCKED) must be
   * published to the live engine pair so authorization observes the
   * lockout.  Attempts 1-4 leave new_state == "mfa_required" and publish
   * nothing.  The totp caller routes already-locked principals away and
   * the store refuses to re-lock, so "locked" here is always a genuine
   * first crossing whose event_id was surfaced by apply_principal_failure.
   * Any publication failure fails closed as E_INTERNAL. */
  if (g_strcmp0 (new_state, "locked") == 0) {
    wyrelog_error_t pub_rc = publish_principal_transition (handle, subject_id,
            WYL_PRINCIPAL_STATE_MFA_REQUIRED, WYL_PRINCIPAL_EVENT_LOCK,
            WYL_PRINCIPAL_STATE_LOCKED, event_id);
    if (pub_rc != WYRELOG_E_OK) {
      WYL_LOG_WARN (WYL_LOG_SECTION_POLICY,
          "mfa: failed to publish lockout transition for subject_id=%s rc=%d",
          subject_id, (int) pub_rc);
      return WYRELOG_E_INTERNAL;
    }
  }
  return WYRELOG_E_OK;
}

/*
 * Auto-unlock check.  When the principal is in LOCKED state and the
 * 15-minute window has elapsed since locked_at, transition the row to
 * UNVERIFIED via the FSM UNLOCK edge (the FSM design routes auto-unlock
 * back to UNVERIFIED, not MFA_REQUIRED - see issue #331 critic flag
 * during commit-4 iteration) AND publish the transition to the live
 * engine pair (#746).
 *
 * The result enum lets the caller separate the two benign "no unlock"
 * outcomes (window not elapsed / not actually locked / raced) - which
 * keep the existing E_POLICY bounce - from a store fault or a
 * publication fault, both of which MUST fail closed as E_INTERNAL so an
 * observably-stale projection can never be authorized against.
 */
typedef enum
{
  WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED = 0,
  WYL_MFA_AUTO_UNLOCK_STORE_FAILURE,
  WYL_MFA_AUTO_UNLOCK_PUBLICATION_FAILURE,
  WYL_MFA_AUTO_UNLOCK_UNLOCKED,
} wyl_mfa_auto_unlock_result_t;

static wyl_mfa_auto_unlock_result_t
maybe_auto_unlock (WylHandle *handle, const gchar *subject_id,
    const gchar *current_state, gint64 locked_at, gint64 now)
{
  if (g_strcmp0 (current_state, "locked") != 0)
    return WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED;
  if (locked_at == G_MININT64)
    return WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED;
  if (now < locked_at + WYL_MFA_AUTO_UNLOCK_SECONDS)
    return WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYL_MFA_AUTO_UNLOCK_STORE_FAILURE;
  gboolean unlocked = FALSE;
  gint64 event_id = 0;
  if (wyl_policy_store_apply_principal_unlock (store, subject_id, &unlocked,
      &event_id) != WYRELOG_E_OK)
    return WYL_MFA_AUTO_UNLOCK_STORE_FAILURE;
  if (!unlocked)
    /* No row actually transitioned (a concurrent writer already moved it
     * out of LOCKED): nothing to publish, treat as a benign no-op so the
     * caller keeps the ordinary E_POLICY bounce. */
    return WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED;
  if (publish_principal_transition (handle, subject_id,
      WYL_PRINCIPAL_STATE_LOCKED, WYL_PRINCIPAL_EVENT_UNLOCK,
      WYL_PRINCIPAL_STATE_UNVERIFIED, event_id) != WYRELOG_E_OK)
    return WYL_MFA_AUTO_UNLOCK_PUBLICATION_FAILURE;
  return WYL_MFA_AUTO_UNLOCK_UNLOCKED;
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
  gboolean reauth = g_strcmp0 (pstate, "authenticated") == 0
      && wyl_session_reauth_pending_private (session)
      && wyl_session_reauth_expected_epoch_private (session) > 0;
  if (pfound && g_strcmp0 (pstate, "locked") == 0) {
    switch (maybe_auto_unlock (handle, subject_id, pstate, plocked_at, now)) {
      case WYL_MFA_AUTO_UNLOCK_UNLOCKED:
      /* Row is now UNVERIFIED and the transition is published.  The
       * verify-with-proof contract bounces because the principal is no
       * longer in mfa_required; HTTP layer will surface mfa_auth_required
       * (uniform) on the next call. */
      case WYL_MFA_AUTO_UNLOCK_NOT_ELAPSED:
        /* Still inside the lockout window (or a benign race): fail closed
         * without consulting the TOTP enrollment.  F1 timing: the HMAC
         * branch is skipped, which is faster than wrong-code/replay paths -
         * but the LOCKED state is already publicly visible via the HTTP 429
         * mfa_locked response (issue #331 spec), so the timing differential
         * discloses nothing the spec does not. */
        return WYRELOG_E_POLICY;
      case WYL_MFA_AUTO_UNLOCK_STORE_FAILURE:
      case WYL_MFA_AUTO_UNLOCK_PUBLICATION_FAILURE:
        /* #746: could not durably-and-observably complete the auto-unlock;
         * refuse rather than authorize against a stale projection. */
        return WYRELOG_E_INTERNAL;
    }
    return WYRELOG_E_INTERNAL;
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
   * Atomically consume the proof and publish MFA_OK (issue #751).  The
   * replay-watermark compare-and-advance, the failure-counter reset
   * (which folds the locked_at clear), and the principal
   * MFA_REQUIRED -> AUTHENTICATED state+event transition now all land
   * in ONE committed-publication transaction inside the orchestrator.
   * That closes the earlier split-commit window where a concurrent
   * duplicate could advance the watermark twice, or a crash between the
   * watermark write and the FSM transition could consume the proof
   * without producing the authenticated durable state.
   *
   * The strict > pre-check above is retained only as a cheap fail-fast:
   * the authoritative gate is the in-transaction pre-state read plus the
   * conditional CAS, which is the single point that decides the winner
   * among concurrent verifiers.  A superseded/replayed attempt (or a
   * principal no longer in mfa_required) resolves to E_POLICY with a
   * clean rollback and no duplicate MFA_OK event.
   *
   * F2: no log/audit emission ever sees the seed or the code.
   */
  wyl_totp_enrollment_clear (&enr);
  if (reauth)
    return wyl_session_totp_reauthenticate (handle, session,
               (gint64) matched_step, NULL);
  return wyl_session_totp_commit_mfa_ok (handle, session,
             (gint64) matched_step, NULL);
}

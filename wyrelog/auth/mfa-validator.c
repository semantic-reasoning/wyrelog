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
 * Drive the principal FSM through a FAILED_ATTEMPT event from the
 * MFA_REQUIRED state.  In commit 3 this is a pure FSM-shape probe
 * (the transition is MFA_REQUIRED -> MFA_REQUIRED with no durable
 * counter); commit 5 will layer a persistent failure counter and
 * lockout policy on top.  Wiring the call here now keeps the
 * validator's failure path on the same FSM-validated branch the
 * lockout logic will read in commit 5.
 *
 * The three negative paths (no enrollment, wrong code, replay)
 * intentionally differ in computational cost: the wrong-code and
 * replay paths perform 3x HMAC-SHA-1 via wyl_totp_code_matches,
 * while the no-enrollment path skips that work.  The resulting
 * timing differential is acceptable because issue #331 decision 7
 * requires the HTTP layer (/auth/mfa/verify) to surface
 * `enrollment_required` as a distinct error code from
 * `mfa_invalid`, so the no-enrollment bit is already deliberately
 * public at the API surface.  Adding a dummy HMAC here to mask a
 * bit that the spec discloses would be hardening theater, not
 * defense.  The FSM step is O(ns) and cannot mask a 3x HMAC cost
 * anyway; do not "fix" the timing gap by inserting a fake HMAC.
 */
static void
note_failed_attempt (void)
{
  wyl_principal_state_t next = WYL_PRINCIPAL_STATE_LAST_;
  (void) wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_MFA_REQUIRED,
      WYL_PRINCIPAL_EVENT_FAILED_ATTEMPT, &next);
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

  /*
   * F5 (enumeration via differential error codes): every negative
   * outcome below funnels through the same WYRELOG_E_POLICY return.
   * The HTTP layer (commit 4) distinguishes enrollment_required vs
   * mfa_invalid by inspecting the enrollment row separately, not by
   * branching on this validator's return code.
   */
  WylTotpEnrollment enr = { 0 };
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_policy_store_totp_enrollment_lookup (store,
      subject_id, &enr, &found);
  if (rc != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&enr);
    return rc;
  }
  if (!found) {
    /* Drive the same FSM FAILED_ATTEMPT branch the wrong-code path
     * takes so commit 5's lockout counter sees every failed verify
     * uniformly.  This does NOT equalise the timing of the
     * no-enrollment vs wrong-code branches — see the rationale
     * above note_failed_attempt for why the differential is
     * intentional and consistent with issue #331 decision 7. */
    note_failed_attempt ();
    wyl_totp_enrollment_clear (&enr);
    return WYRELOG_E_POLICY;
  }

  guint submitted_code = parse_six_digits (proof);
  gint64 now = (gint64) time (NULL);
  guint64 matched_step = 0;

  gboolean matched = wyl_totp_code_matches (enr.secret, sizeof enr.secret,
      now, submitted_code, &matched_step, NULL);
  if (!matched) {
    note_failed_attempt ();
    wyl_totp_enrollment_clear (&enr);
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
   * value and the comparison would reject — which is the conservative
   * direction.
   */
  if ((gint64) matched_step <= enr.last_verified_step) {
    note_failed_attempt ();
    wyl_totp_enrollment_clear (&enr);
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

  return WYRELOG_E_OK;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Unit tests for the daemon-side TOTP MFA validator
 * (wyrelog/auth/mfa-validator.{c,h}).
 *
 * The validator implements the WylMfaValidator callback shape
 * (wyrelog/session.h) used by wyl_session_mfa_verify_with_proof. It
 * resolves the per-subject TOTP enrollment in the handle-owned policy
 * store, evaluates the submitted 6-digit code against the seed at the
 * current step (with the +/-1 skew already encoded by the commit-1
 * TOTP core), and enforces a strict replay watermark using > (NOT >=)
 * against last_verified_step.
 *
 * Footgun coverage these tests exist to lock down:
 *   F1 (timing): malformed proof, missing enrollment, and a wrong code
 *     all walk the same final-return path through the validator. The
 *     tests assert the error code is identical for the missing-enrollment
 *     and wrong-code paths (WYRELOG_E_POLICY), and that NULL/short/long
 *     proofs all return WYRELOG_E_INVALID before the policy store is
 *     touched.
 *   F2 (secret-in-audit): no audit emission is expected from the
 *     validator itself; the only audit row comes from the FSM
 *     transition the caller drives after validator returns
 *     WYRELOG_E_OK. (This file does not poke audit; it only verifies
 *     that last_verified_step is the only mutation the validator
 *     produces.)
 *   F3 (replay): the same submitted code MUST be rejected on a second
 *     call, because the validator advances last_verified_step before
 *     returning. A restart-style test writes last_verified_step
 *     directly via the store helper and confirms a follow-up call
 *     with the same code is rejected.
 */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "auth/mfa-validator.h"
#include "auth/totp.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/session.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyrelog.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static const guint8 TEST_SEED[WYL_TOTP_SEED_BYTES] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x30,
};

static void
fill_seed_copy (guint8 *dst)
{
  memcpy (dst, TEST_SEED, WYL_TOTP_SEED_BYTES);
}

static gint
login_mfa_required_session (WylHandle *handle, const gchar *username,
    WylSession **out_session)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, username);
  if (wyl_session_login (handle, req, out_session) != WYRELOG_E_OK)
    return -1;
  if (*out_session == NULL)
    return -1;
  return 0;
}

static gint
seed_enrollment (WylHandle *handle, const gchar *subject_id)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylTotpEnrollment enr = { 0 };
  enr.subject_id = g_strdup (subject_id);
  fill_seed_copy (enr.secret);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = 1700000000;
  wyrelog_error_t rc = wyl_policy_store_totp_enrollment_insert (store, &enr);
  wyl_totp_enrollment_clear (&enr);
  return (rc == WYRELOG_E_OK) ? 0 : -1;
}

static gint
load_last_verified_step (WylHandle *handle, const gchar *subject_id,
    gint64 *out_step)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylTotpEnrollment out = { 0 };
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_policy_store_totp_enrollment_lookup (store,
      subject_id, &out, &found);
  if (rc != WYRELOG_E_OK || !found) {
    wyl_totp_enrollment_clear (&out);
    return -1;
  }
  *out_step = out.last_verified_step;
  wyl_totp_enrollment_clear (&out);
  return 0;
}

static gint
compute_code_for_now (guint *out_code, gint64 *out_unix_time, guint64 *out_step)
{
  gint64 now = (gint64) time (NULL);
  guint64 step = (guint64) (now / WYL_TOTP_STEP_SECONDS);
  guint code = 0;
  if (wyl_totp_code_at_step (TEST_SEED, sizeof TEST_SEED, step, &code, NULL)
      != WYRELOG_E_OK)
    return -1;
  *out_code = code;
  *out_unix_time = now;
  *out_step = step;
  return 0;
}

static gint
check_validator_rejects_null_proof (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;

  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.null-proof",
          &session) != 0)
    return 11;

  if (wyl_mfa_validator_totp (handle, session, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 12;
  return 0;
}

static gint
check_validator_rejects_short_proof (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 20;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.short-proof",
          &session) != 0)
    return 21;
  if (wyl_mfa_validator_totp (handle, session, "12345", NULL)
      != WYRELOG_E_INVALID)
    return 22;
  return 0;
}

static gint
check_validator_rejects_long_proof (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.long-proof",
          &session) != 0)
    return 31;
  if (wyl_mfa_validator_totp (handle, session, "1234567", NULL)
      != WYRELOG_E_INVALID)
    return 32;
  return 0;
}

static gint
check_validator_rejects_huge_proof (void)
{
  /* F-2 regression guard: a 1024-byte all-digit, NUL-terminated proof
   * must be rejected by the shape check before any read can run past
   * the WYL_TOTP_DIGITS window.  Locks down the strnlen length guard
   * in proof_shape_is_valid against future "optimisations" that would
   * re-introduce the OOB read fixed during commit-3 iteration. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 35;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.huge-proof",
          &session) != 0)
    return 36;
  gchar proof[1025];
  memset (proof, '1', 1024);
  proof[1024] = '\0';
  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_INVALID)
    return 37;
  return 0;
}

static gint
check_validator_rejects_non_digit_proof (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 40;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.non-digit-proof",
          &session) != 0)
    return 41;
  if (wyl_mfa_validator_totp (handle, session, "abcdef", NULL)
      != WYRELOG_E_INVALID)
    return 42;
  if (wyl_mfa_validator_totp (handle, session, "12345 ", NULL)
      != WYRELOG_E_INVALID)
    return 43;
  /* Embedded NUL: also a shape failure. */
  const gchar embedded_nul[7] = { '1', '2', '3', '\0', '5', '6', '\0' };
  if (wyl_mfa_validator_totp (handle, session, embedded_nul, NULL)
      != WYRELOG_E_INVALID)
    return 44;
  return 0;
}

static gint
check_validator_rejects_when_no_enrollment (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.no-enroll", &session) != 0)
    return 51;
  /* No enrollment row inserted: validator must fail closed with POLICY. */
  if (wyl_mfa_validator_totp (handle, session, "000000", NULL)
      != WYRELOG_E_POLICY)
    return 52;
  /* Confirm no enrollment row was created as a side effect. */
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylTotpEnrollment out = { 0 };
  gboolean found = TRUE;
  if (wyl_policy_store_totp_enrollment_lookup (store, "validator.no-enroll",
          &out, &found) != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&out);
    return 53;
  }
  if (found) {
    wyl_totp_enrollment_clear (&out);
    return 54;
  }
  wyl_totp_enrollment_clear (&out);
  return 0;
}

static gint
check_validator_rejects_wrong_code (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 60;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.wrong-code",
          &session) != 0)
    return 61;
  if (seed_enrollment (handle, "validator.wrong-code") != 0)
    return 62;

  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 63;
  /* Pick a value guaranteed to differ from the correct code. */
  guint wrong = (correct + 1) % 1000000;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", wrong);

  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_POLICY)
    return 64;
  /* last_verified_step must NOT have advanced. */
  gint64 step_after = 0;
  if (load_last_verified_step (handle, "validator.wrong-code",
          &step_after) != 0)
    return 65;
  if (step_after != INT64_MIN)
    return 66;
  return 0;
}

static gint
check_validator_accepts_correct_code (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.happy", &session) != 0)
    return 71;
  if (seed_enrollment (handle, "validator.happy") != 0)
    return 72;

  guint code = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&code, &now, &step) != 0)
    return 73;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", code);

  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_OK)
    return 74;

  gint64 step_after = 0;
  if (load_last_verified_step (handle, "validator.happy", &step_after) != 0)
    return 75;
  if (step_after != (gint64) step)
    return 76;
  return 0;
}

static gint
check_validator_rejects_replay_same_session (void)
{
  /* F3: a successful verify must persist the matched step BEFORE the
   * caller advances the FSM, so a re-submission of the same code
   * during the same session window is rejected. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 80;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.replay", &session) != 0)
    return 81;
  if (seed_enrollment (handle, "validator.replay") != 0)
    return 82;

  guint code = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&code, &now, &step) != 0)
    return 83;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", code);

  /* First call: success. */
  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_OK)
    return 84;

  /* Second call with the SAME code: must be rejected as replay. */
  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_POLICY)
    return 85;

  /* last_verified_step should still equal the matched step (not
   * regressed). */
  gint64 step_after = 0;
  if (load_last_verified_step (handle, "validator.replay", &step_after) != 0)
    return 86;
  if (step_after != (gint64) step)
    return 87;
  return 0;
}

static gint
check_validator_rejects_replay_across_restart (void)
{
  /* F3 restart simulation: write last_verified_step directly via the
   * store helper (mirroring a crash-recovery case where the watermark
   * was persisted but the FSM transition was lost), then call the
   * validator with the SAME code that produced that watermark. The
   * validator must fail closed because matched_step <= stored
   * last_verified_step. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 90;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.restart", &session) != 0)
    return 91;
  if (seed_enrollment (handle, "validator.restart") != 0)
    return 92;

  guint code = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&code, &now, &step) != 0)
    return 93;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", code);

  /* Simulate restart-after-watermark-write: bump last_verified_step to
   * the step our code lives in, without driving the validator. */
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_totp_enrollment_update_step (store,
          "validator.restart", (gint64) step) != WYRELOG_E_OK)
    return 94;

  /* Now call the validator with the same code. Must be rejected: the
   * matched step would be == stored watermark, and the rule is strict
   * > not >=. */
  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_POLICY)
    return 95;
  return 0;
}

static gint
read_principal_state (WylHandle *handle, const gchar *subject_id,
    gchar **out_state, gint64 *out_count, gint64 *out_locked_at)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_policy_store_get_principal_lock_info (store,
      subject_id, out_state, out_count, out_locked_at, &found);
  if (rc != WYRELOG_E_OK || !found)
    return -1;
  return 0;
}

static gint
check_validator_locks_after_five_failures (void)
{
  /* Commit-5 architect rule: five consecutive failures must transition
   * the principal to LOCKED.  The state move is durable - it lands in
   * the policy store's principal_states row - and the failure counter
   * is exactly 5 on the threshold step. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 200;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.lockout-five",
          &session) != 0)
    return 201;
  if (seed_enrollment (handle, "validator.lockout-five") != 0)
    return 202;

  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 203;
  guint wrong = (correct + 1) % 1000000;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", wrong);

  /* Five wrong attempts.  After the 5th the validator must transition
   * the principal_state row to 'locked' atomically with the counter
   * increment.  All five calls return E_POLICY (uniform negative). */
  for (int i = 0; i < 5; i++) {
    if (wyl_mfa_validator_totp (handle, session, proof, NULL)
        != WYRELOG_E_POLICY)
      return 210 + i;
  }
  g_autofree gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = 0;
  if (read_principal_state (handle, "validator.lockout-five", &st, &count,
          &locked_at) != 0)
    return 220;
  if (g_strcmp0 (st, "locked") != 0)
    return 221;
  if (count != 5)
    return 222;
  if (locked_at == G_MININT64)
    return 223;
  return 0;
}

static gint
check_validator_locked_principal_rejects_without_hmac (void)
{
  /* When the principal is already LOCKED and the auto-unlock window is
   * not elapsed, the validator must fail closed without consulting the
   * TOTP enrollment (no HMAC computation, no replay-watermark advance).
   * We assert state stays LOCKED and last_verified_step is unchanged. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 230;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.locked-now",
          &session) != 0)
    return 231;
  if (seed_enrollment (handle, "validator.locked-now") != 0)
    return 232;

  /* Drive 5 organic FAILED_ATTEMPTs to transition the principal row to
   * LOCKED with locked_at = now (so the auto-unlock grace has not yet
   * elapsed).  The set_principal_state("locked") shortcut used in the
   * earlier iteration would now collide with the commit-5 iteration
   * defensive guard (apply_principal_failure refuses to mutate a row
   * that is already LOCKED); driving the threshold organically gives
   * the same setup state without bypassing the helper's contract. */
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  for (int i = 0; i < 5; i++) {
    g_autofree gchar *st = NULL;
    gint64 c = 0, l = 0;
    if (wyl_policy_store_apply_principal_failure (store,
            "validator.locked-now", 5, (gint64) time (NULL),
            &st, &c, &l) != WYRELOG_E_OK)
      return 234;
  }

  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 235;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", correct);

  /* Submitting the CORRECT code must still be rejected because the
   * principal is locked. */
  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_POLICY)
    return 236;
  /* State must still be locked. */
  g_autofree gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = 0;
  if (read_principal_state (handle, "validator.locked-now", &st, &count,
          &locked_at) != 0)
    return 237;
  if (g_strcmp0 (st, "locked") != 0)
    return 238;
  /* last_verified_step on the enrollment row must NOT have advanced
   * (validator never consulted the secret). */
  gint64 step_after = 0;
  if (load_last_verified_step (handle, "validator.locked-now",
          &step_after) != 0)
    return 239;
  if (step_after != INT64_MIN)
    return 240;
  return 0;
}

static gint
check_validator_auto_unlocks_after_window (void)
{
  /* Inject a locked principal whose locked_at is 16 minutes in the past
   * (well past the 15-min auto-unlock window).  The next validate call
   * must transition the row LOCKED -> UNVERIFIED via the FSM UNLOCK
   * event and return E_POLICY (the caller's session-state gate will then
   * send the user back to re-login). */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 250;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.auto-unlock",
          &session) != 0)
    return 251;
  if (seed_enrollment (handle, "validator.auto-unlock") != 0)
    return 252;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_set_principal_state (store, "validator.auto-unlock",
          "mfa_required") != WYRELOG_E_OK)
    return 253;
  /* Drive 5 failures with locked_at = now - (16 minutes). */
  gint64 ago = (gint64) time (NULL) - (16 * 60);
  for (int i = 0; i < 5; i++) {
    g_autofree gchar *st = NULL;
    gint64 c = 0, l = 0;
    if (wyl_policy_store_apply_principal_failure (store,
            "validator.auto-unlock", 5, ago, &st, &c, &l) != WYRELOG_E_OK)
      return 254;
  }
  /* Confirm precondition: row is locked. */
  g_autofree gchar *pre_state = NULL;
  gint64 pre_count = 0;
  gint64 pre_locked_at = 0;
  if (read_principal_state (handle, "validator.auto-unlock", &pre_state,
          &pre_count, &pre_locked_at) != 0)
    return 255;
  if (g_strcmp0 (pre_state, "locked") != 0)
    return 256;

  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 257;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", correct);

  /* Call validator: must auto-unlock and return E_POLICY (session no
   * longer in mfa_required; the verify-with-proof contract bounces
   * because the principal is now UNVERIFIED). */
  if (wyl_mfa_validator_totp (handle, session, proof, NULL)
      != WYRELOG_E_POLICY)
    return 258;
  /* Row is now in UNVERIFIED with counter=0, locked_at NULL. */
  g_autofree gchar *post_state = NULL;
  gint64 post_count = -1;
  gint64 post_locked_at = 0;
  if (read_principal_state (handle, "validator.auto-unlock", &post_state,
          &post_count, &post_locked_at) != 0)
    return 259;
  if (g_strcmp0 (post_state, "unverified") != 0)
    return 260;
  if (post_count != 0)
    return 261;
  if (post_locked_at != G_MININT64)
    return 262;
  return 0;
}

static gint
check_validator_resets_counter_on_success (void)
{
  /* 4 failures then 1 success: the counter resets to 0 on success, so
   * a subsequent failure starts the counter at 1, not 5. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 270;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.reset-on-ok",
          &session) != 0)
    return 271;
  if (seed_enrollment (handle, "validator.reset-on-ok") != 0)
    return 272;

  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 273;
  guint wrong = (correct + 1) % 1000000;
  gchar wrong_proof[8];
  g_snprintf (wrong_proof, sizeof wrong_proof, "%06u", wrong);
  gchar good_proof[8];
  g_snprintf (good_proof, sizeof good_proof, "%06u", correct);

  /* 4 failures. */
  for (int i = 0; i < 4; i++) {
    if (wyl_mfa_validator_totp (handle, session, wrong_proof, NULL)
        != WYRELOG_E_POLICY)
      return 274;
  }
  /* Counter must be 4, not locked. */
  g_autofree gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = 0;
  if (read_principal_state (handle, "validator.reset-on-ok", &st, &count,
          &locked_at) != 0)
    return 275;
  if (count != 4 || g_strcmp0 (st, "mfa_required") != 0)
    return 276;

  /* Success: counter goes to 0. */
  if (wyl_mfa_validator_totp (handle, session, good_proof, NULL)
      != WYRELOG_E_OK)
    return 277;
  g_clear_pointer (&st, g_free);
  if (read_principal_state (handle, "validator.reset-on-ok", &st, &count,
          &locked_at) != 0)
    return 278;
  if (count != 0)
    return 279;

  /* Next failure: counter starts at 1. */
  if (wyl_mfa_validator_totp (handle, session, wrong_proof, NULL)
      != WYRELOG_E_POLICY)
    return 280;
  g_clear_pointer (&st, g_free);
  if (read_principal_state (handle, "validator.reset-on-ok", &st, &count,
          &locked_at) != 0)
    return 281;
  if (count != 1)
    return 282;
  return 0;
}

static gint
check_validator_rejects_null_handle_or_session (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 100;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.null-args", &session) != 0)
    return 101;
  if (wyl_mfa_validator_totp (NULL, session, "000000", NULL)
      != WYRELOG_E_INVALID)
    return 102;
  if (wyl_mfa_validator_totp (handle, NULL, "000000", NULL)
      != WYRELOG_E_INVALID)
    return 103;
  return 0;
}

static gint
check_handle_default_validator_is_wired (void)
{
  /* The daemon init path (runtime.c) installs wyl_mfa_validator_totp
   * as the default validator on every WylHandle so the HTTP /auth/mfa
   * route (commit 4) can resolve it without an out-of-band reference.
   * wyl_handle_get_mfa_validator must return the same function pointer
   * for any handle that has been through wyl_daemon_install_mfa_validator. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 110;
  /* By default no validator is set; the daemon installs it. */
  if (wyl_handle_get_mfa_validator (handle, NULL) != NULL)
    return 111;
  wyl_handle_set_mfa_validator (handle, wyl_mfa_validator_totp, NULL);
  gpointer ud = (gpointer) 0xdeadbeef;
  WylMfaValidator v = wyl_handle_get_mfa_validator (handle, &ud);
  if (v != wyl_mfa_validator_totp)
    return 112;
  if (ud != NULL)
    return 113;
  /* Calling through the handle-stored pointer must behave identically
   * to calling the symbol directly: invalid proof shape -> INVALID. */
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.wired", &session) != 0)
    return 114;
  if (v (handle, session, "x", NULL) != WYRELOG_E_INVALID)
    return 115;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_validator_rejects_null_proof ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_short_proof ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_long_proof ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_huge_proof ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_non_digit_proof ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_when_no_enrollment ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_wrong_code ()) != 0)
    return rc;
  if ((rc = check_validator_accepts_correct_code ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_replay_same_session ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_replay_across_restart ()) != 0)
    return rc;
  if ((rc = check_validator_locks_after_five_failures ()) != 0)
    return rc;
  if ((rc = check_validator_locked_principal_rejects_without_hmac ()) != 0)
    return rc;
  if ((rc = check_validator_auto_unlocks_after_window ()) != 0)
    return rc;
  if ((rc = check_validator_resets_counter_on_success ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_null_handle_or_session ()) != 0)
    return rc;
  if ((rc = check_handle_default_validator_is_wired ()) != 0)
    return rc;
  return 0;
}

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
  if ((rc = check_validator_rejects_null_handle_or_session ()) != 0)
    return rc;
  if ((rc = check_handle_default_validator_is_wired ()) != 0)
    return rc;
  return 0;
}

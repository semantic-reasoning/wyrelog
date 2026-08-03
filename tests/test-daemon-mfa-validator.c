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
#include <glib/gstdio.h>

#include "auth/mfa-validator.h"
#include "auth/totp.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/session.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-session-layout-private.h"
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

typedef struct
{
  const gchar *subject_id;
  const gchar *event;
  gint64 event_id;
  guint matches;
} PrincipalEventCapture;

static wyrelog_error_t
capture_principal_event (gint64 event_id, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer data)
{
  (void) from_state;
  (void) to_state;
  PrincipalEventCapture *capture = data;
  if (g_strcmp0 (capture->subject_id, subject_id) == 0
      && g_strcmp0 (capture->event, event) == 0) {
    capture->event_id = event_id;
    capture->matches++;
  }
  return WYRELOG_E_OK;
}

static void
count_lock_delta (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer data)
{
  (void) row;
  if (g_strcmp0 (relation, "principal_fired") == 0 && ncols == 5
      && kind == WYL_DELTA_INSERT)
    (*(guint *) data)++;
}

static gboolean
engine_contains_lock_publication (WylHandle *handle, const gchar *subject_id,
    gint64 event_id)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return FALSE;
  const gchar *symbols[] = {
    subject_id,
    "locked",
    "mfa_required",
    "lock",
  };
  gint64 ids[G_N_ELEMENTS (symbols)] = { 0 };
  for (gsize i = 0; i < G_N_ELEMENTS (symbols); i++) {
    if (wyl_engine_session_lookup_symbol (engine_session, symbols[i], &ids[i])
        != WYRELOG_E_OK)
      return FALSE;
  }
  const gint64 state_row[] = { ids[0], ids[1] };
  const gint64 event_row[] = { event_id, ids[0], ids[2], ids[3], ids[1] };
  gboolean has_state = FALSE;
  gboolean has_event = FALSE;
  return wyl_engine_session_contains (engine_session, "principal_state",
      state_row, G_N_ELEMENTS (state_row), &has_state) == WYRELOG_E_OK
      && wyl_engine_session_contains (engine_session, "principal_fired",
      event_row, G_N_ELEMENTS (event_row), &has_event) == WYRELOG_E_OK
      && has_state && has_event;
}

static gboolean
engine_contains_unlock_publication (WylHandle *handle,
    const gchar *subject_id, gint64 event_id)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return FALSE;
  const gchar *symbols[] = {
    subject_id,
    "unverified",
    "locked",
    "unlock",
  };
  gint64 ids[G_N_ELEMENTS (symbols)] = { 0 };
  for (gsize i = 0; i < G_N_ELEMENTS (symbols); i++) {
    if (wyl_engine_session_lookup_symbol (engine_session, symbols[i], &ids[i])
        != WYRELOG_E_OK)
      return FALSE;
  }
  const gint64 state_row[] = { ids[0], ids[1] };
  const gint64 event_row[] = { event_id, ids[0], ids[2], ids[3], ids[1] };
  gboolean has_state = FALSE, has_event = FALSE;
  return wyl_engine_session_contains (engine_session, "principal_state",
      state_row, G_N_ELEMENTS (state_row), &has_state) == WYRELOG_E_OK
      && wyl_engine_session_contains (engine_session, "principal_fired",
      event_row, G_N_ELEMENTS (event_row), &has_event) == WYRELOG_E_OK
      && has_state && has_event;
}

static gboolean
engine_contains_principal_event (WylHandle *handle, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gint64 event_id)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return FALSE;
  const gchar *symbols[] = { subject_id, from_state, event, to_state };
  gint64 row[5] = { event_id, 0, 0, 0, 0 };
  for (gsize i = 0; i < G_N_ELEMENTS (symbols); i++) {
    if (wyl_engine_session_lookup_symbol (engine_session, symbols[i],
            &row[i + 1]) != WYRELOG_E_OK)
      return FALSE;
  }
  gboolean found = FALSE;
  return wyl_engine_session_contains (engine_session, "principal_fired", row,
      G_N_ELEMENTS (row), &found) == WYRELOG_E_OK && found;
}

static gboolean
engine_contains_principal_state (WylHandle *handle, const gchar *subject_id,
    const gchar *state)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return FALSE;
  const gchar *symbols[] = { subject_id, state };
  gint64 row[2] = { 0 };
  for (gsize i = 0; i < G_N_ELEMENTS (symbols); i++) {
    if (wyl_engine_session_lookup_symbol (engine_session, symbols[i], &row[i])
        != WYRELOG_E_OK)
      return FALSE;
  }
  gboolean found = FALSE;
  return wyl_engine_session_contains (engine_session, "principal_state", row,
      G_N_ELEMENTS (row), &found) == WYRELOG_E_OK && found;
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

  WylEngine *initial_read = wyl_handle_get_read_engine (handle);
  WylEngine *initial_delta = wyl_handle_get_delta_engine (handle);
  guint callbacks = 0;
  if (wyl_handle_engine_set_delta_callback (handle, count_lock_delta,
          &callbacks) != WYRELOG_E_OK)
    return 204;

  /* Five wrong attempts.  After the 5th the validator must transition
   * the principal_state row to 'locked' atomically with the counter
   * increment.  All five calls return E_POLICY (uniform negative). */
  for (int i = 0; i < 4; i++) {
    if (wyl_mfa_validator_totp (handle, session, proof, NULL)
        != WYRELOG_E_POLICY)
      return 210 + i;
    if (wyl_handle_get_read_engine (handle) != initial_read
        || wyl_handle_get_delta_engine (handle) != initial_delta
        || callbacks != 0
        || wyl_handle_pending_delta_count_for_test (handle) != 0)
      return 224;
  }
  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
  if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
      != WYRELOG_E_POLICY || outcome != WYL_MFA_VALIDATION_REJECTED_LOCKED)
    return 225;
  if (wyl_handle_get_read_engine (handle) == initial_read
      || wyl_handle_get_delta_engine (handle) == initial_delta
      || callbacks != 1
      || wyl_handle_pending_delta_count_for_test (handle) != 0)
    return 226;
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
  PrincipalEventCapture capture = {
    .subject_id = "validator.lockout-five",
    .event = "lock",
    .event_id = -1,
  };
  if (wyl_policy_store_foreach_principal_event
      (wyl_handle_get_policy_store (handle), capture_principal_event,
          &capture) != WYRELOG_E_OK || capture.event_id <= 0
      || capture.matches != 1
      || !engine_contains_lock_publication (handle,
          "validator.lockout-five", capture.event_id))
    return 227;
  return 0;
}

typedef struct
{
  wyl_policy_store_t *store;
  const gchar *subject_id;
  wyrelog_error_t rc;
} SerializedMfaSuccessor;

static void
commit_serialized_unlock (gpointer data)
{
  SerializedMfaSuccessor *successor = data;
  successor->rc = wyl_policy_store_apply_principal_unlock (successor->store,
      successor->subject_id);
}

static gint
check_lock_publication_accepts_serialized_unlock (void)
{
  const gchar *subject = "validator.serialized-successor";
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 343;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, subject, &session) != 0
      || seed_enrollment (handle, subject) != 0)
    return 344;
  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 345;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", (correct + 1) % 1000000);
  for (guint failure = 0; failure < 4; failure++) {
    if (wyl_mfa_validator_totp (handle, session, proof, NULL)
        != WYRELOG_E_POLICY)
      return 346;
  }

  SerializedMfaSuccessor successor = {
    .store = wyl_handle_get_policy_store (handle),
    .subject_id = subject,
    .rc = WYRELOG_E_INTERNAL,
  };
  wyl_handle_set_committed_publication_checkpoint_for_test (handle,
      commit_serialized_unlock, &successor);
  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
  if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
      != WYRELOG_E_POLICY || outcome != WYL_MFA_VALIDATION_REJECTED_LOCKED
      || successor.rc != WYRELOG_E_OK
      || !wyl_handle_engine_pair_is_ready (handle)
      || wyl_handle_engine_pair_is_poisoned (handle))
    return 347;

  g_autofree gchar *state = NULL;
  gint64 count = -1, locked_at = 0;
  if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0
      || g_strcmp0 (state, "unverified") != 0 || count != 0
      || locked_at != G_MININT64)
    return 348;
  PrincipalEventCapture lock = {
    .subject_id = subject,
    .event = "lock",
    .event_id = -1,
  };
  PrincipalEventCapture unlock = {
    .subject_id = subject,
    .event = "unlock",
    .event_id = -1,
  };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_foreach_principal_event (store,
          capture_principal_event, &lock) != WYRELOG_E_OK
      || wyl_policy_store_foreach_principal_event (store,
          capture_principal_event, &unlock) != WYRELOG_E_OK
      || lock.matches != 1 || unlock.matches != 1
      || !engine_contains_principal_event (handle, subject, "lock",
          "mfa_required", "locked", lock.event_id)
      || !engine_contains_unlock_publication (handle, subject, unlock.event_id))
    return 349;
  return 0;
}

static gint
check_counter_only_commit_ambiguity_preserves_engine_pair (void)
{
  const gchar *subject = "validator.counter-commit-ambiguity";
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 300;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, subject, &session) != 0
      || seed_enrollment (handle, subject) != 0)
    return 301;

  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 302;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", (correct + 1) % 1000000);

  WylEngine *initial_read = wyl_handle_get_read_engine (handle);
  WylEngine *initial_delta = wyl_handle_get_delta_engine (handle);
  guint callbacks = 0;
  if (wyl_handle_engine_set_delta_callback (handle, count_lock_delta,
          &callbacks) != WYRELOG_E_OK)
    return 303;
  wyl_policy_store_publication_commit_fail_once_for_test
      (wyl_handle_get_policy_store (handle));

  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_REJECTED;
  if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
      != WYRELOG_E_INTERNAL || outcome != WYL_MFA_VALIDATION_ERROR)
    return 304;

  g_autofree gchar *state = NULL;
  gint64 count = 0, locked_at = 0;
  if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0
      || count != 1 || g_strcmp0 (state, "mfa_required") != 0)
    return 305;
  if (wyl_handle_get_read_engine (handle) != initial_read
      || wyl_handle_get_delta_engine (handle) != initial_delta
      || callbacks != 0
      || wyl_handle_pending_delta_count_for_test (handle) != 0
      || wyl_handle_engine_pair_is_poisoned (handle)
      || !wyl_handle_engine_pair_is_ready (handle))
    return 306;
  return 0;
}

static gint
check_projected_commit_ambiguity_poison_engine_pair (void)
{
  const gchar *subject = "validator.lock-commit-ambiguity";
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 310;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, subject, &session) != 0
      || seed_enrollment (handle, subject) != 0)
    return 311;

  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 312;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", (correct + 1) % 1000000);
  for (guint i = 0; i < 4; i++) {
    if (wyl_mfa_validator_totp (handle, session, proof, NULL)
        != WYRELOG_E_POLICY)
      return 313;
  }

  wyl_policy_store_publication_commit_fail_once_for_test
      (wyl_handle_get_policy_store (handle));
  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_REJECTED;
  if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
      != WYRELOG_E_INTERNAL || outcome != WYL_MFA_VALIDATION_ERROR)
    return 314;

  g_autofree gchar *state = NULL;
  gint64 count = 0, locked_at = G_MININT64;
  if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0
      || count != 5 || g_strcmp0 (state, "locked") != 0
      || locked_at == G_MININT64 || !wyl_handle_engine_pair_is_poisoned (handle)
      || wyl_handle_engine_pair_is_ready (handle))
    return 315;
  PrincipalEventCapture capture = {
    .subject_id = subject,
    .event = "lock",
    .event_id = -1,
  };
  if (wyl_policy_store_foreach_principal_event
      (wyl_handle_get_policy_store (handle), capture_principal_event,
          &capture) != WYRELOG_E_OK || capture.matches != 1
      || capture.event_id <= 0)
    return 316;
  return 0;
}

static wyrelog_error_t
verify_lock_reconciliation (WylHandle *handle, gpointer data)
{
  PrincipalEventCapture *capture = data;
  return engine_contains_lock_publication (handle, capture->subject_id,
      capture->event_id) ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
reject_reconciliation (WylHandle *handle, gpointer data)
{
  (void) handle;
  (void) data;
  return WYRELOG_E_POLICY;
}

static gint
check_threshold_postcommit_faults_require_exact_repair (void)
{
  typedef struct
  {
    WylEngineReplacementFault replacement_fault;
    WylPolicySnapshotFinishFailStage snapshot_fault;
    const gchar *suffix;
  } FaultCase;
  const FaultCase cases[] = {
    {WYL_ENGINE_REPLACEMENT_FAULT_PRINCIPAL_STATES,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_NONE, "reload"},
    {WYL_ENGINE_REPLACEMENT_FAULT_PUBLICATION_VERIFY_POLICY,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_NONE, "verifier-policy"},
    {WYL_ENGINE_REPLACEMENT_FAULT_CALLBACK,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_NONE, "callback"},
    {WYL_ENGINE_REPLACEMENT_FAULT_PUBLICATION_DELTA,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_NONE, "delta"},
    {WYL_ENGINE_REPLACEMENT_FAULT_NONE,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_ROLLBACK, "snapshot-rollback"},
    {WYL_ENGINE_REPLACEMENT_FAULT_NONE,
          WYL_POLICY_SNAPSHOT_FINISH_FAIL_TRANSACTION_STATE,
        "snapshot-state"},
    {WYL_ENGINE_REPLACEMENT_FAULT_NONE,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_AUTOCOMMIT, "snapshot-autocommit"},
  };

  for (guint case_index = 0; case_index < G_N_ELEMENTS (cases); case_index++) {
    g_autofree gchar *subject = g_strdup_printf ("validator.postcommit-%s",
        cases[case_index].suffix);
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
      return 320;
    g_autoptr (WylSession) session = NULL;
    if (login_mfa_required_session (handle, subject, &session) != 0
        || seed_enrollment (handle, subject) != 0)
      return 321;
    guint correct = 0;
    gint64 now = 0;
    guint64 step = 0;
    if (compute_code_for_now (&correct, &now, &step) != 0)
      return 322;
    gchar proof[8];
    g_snprintf (proof, sizeof proof, "%06u", (correct + 1) % 1000000);
    guint callbacks = 0;
    if (wyl_handle_engine_set_delta_callback (handle, count_lock_delta,
            &callbacks) != WYRELOG_E_OK)
      return 323;
    for (guint failure = 0; failure < 4; failure++) {
      if (wyl_mfa_validator_totp (handle, session, proof, NULL)
          != WYRELOG_E_POLICY)
        return 323;
    }

    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    if (cases[case_index].replacement_fault
        != WYL_ENGINE_REPLACEMENT_FAULT_NONE)
      wyl_handle_set_engine_replacement_fault_once_for_test (handle,
          cases[case_index].replacement_fault);
    else
      wyl_policy_store_read_snapshot_finish_fail_once_for_test (store,
          cases[case_index].snapshot_fault);
    WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_REJECTED;
    if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
        != WYRELOG_E_INTERNAL || outcome != WYL_MFA_VALIDATION_ERROR
        || !wyl_handle_engine_pair_is_poisoned (handle)
        || wyl_handle_engine_pair_is_ready (handle))
      return 324;

    g_autofree gchar *state = NULL;
    gint64 count = 0, locked_at = G_MININT64;
    if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0
        || count != 5 || g_strcmp0 (state, "locked") != 0
        || locked_at == G_MININT64)
      return 325;
    PrincipalEventCapture capture = {
      .subject_id = subject,
      .event = "lock",
      .event_id = -1,
    };
    if (wyl_policy_store_foreach_principal_event (store,
            capture_principal_event, &capture) != WYRELOG_E_OK
        || capture.matches != 1 || capture.event_id <= 0
        || callbacks != 0
        || wyl_handle_pending_delta_count_for_test (handle) != 0)
      return 326;
    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_INVALID
        || !wyl_handle_engine_pair_is_poisoned (handle)
        || wyl_handle_engine_pair_is_ready (handle))
      return 326;
    if (wyl_handle_reconcile_committed_engine_pair (handle,
            reject_reconciliation, NULL) != WYRELOG_E_POLICY
        || !wyl_handle_engine_pair_is_poisoned (handle)
        || wyl_handle_engine_pair_is_ready (handle)
        || wyl_handle_reconcile_committed_engine_pair (handle,
            verify_lock_reconciliation, &capture) != WYRELOG_E_OK
        || wyl_handle_engine_pair_is_poisoned (handle)
        || !wyl_handle_engine_pair_is_ready (handle)
        || !engine_contains_lock_publication (handle, subject,
            capture.event_id))
      return 326;
  }
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

  WylEngine *initial_read = wyl_handle_get_read_engine (handle);
  WylEngine *initial_delta = wyl_handle_get_delta_engine (handle);
  guint callbacks = 0;
  if (wyl_handle_engine_set_delta_callback (handle, count_lock_delta,
          &callbacks) != WYRELOG_E_OK)
    return 263;

  /* Call validator: must auto-unlock and return E_POLICY (session no
   * longer in mfa_required; the verify-with-proof contract bounces
   * because the principal is now UNVERIFIED). */
  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
  if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
      != WYRELOG_E_POLICY || outcome != WYL_MFA_VALIDATION_AUTH_REQUIRED)
    return 258;
  if (wyl_handle_get_read_engine (handle) == initial_read
      || wyl_handle_get_delta_engine (handle) == initial_delta
      || callbacks != 1 || wyl_handle_pending_delta_count_for_test (handle)
      != 0)
    return 264;
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
  PrincipalEventCapture capture = {
    .subject_id = "validator.auto-unlock",
    .event = "unlock",
    .event_id = -1,
  };
  if (wyl_policy_store_foreach_principal_event (store,
          capture_principal_event, &capture) != WYRELOG_E_OK
      || capture.matches != 1
      || !engine_contains_unlock_publication (handle,
          "validator.auto-unlock", capture.event_id))
    return 265;
  return 0;
}

static wyrelog_error_t
verify_unlock_reconciliation (WylHandle *handle, gpointer data)
{
  PrincipalEventCapture *capture = data;
  return engine_contains_unlock_publication (handle, capture->subject_id,
      capture->event_id) ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static gint
check_auto_unlock_committed_publication_failure_repairs (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 266;
  g_autoptr (WylSession) session = NULL;
  const gchar *subject = "validator.unlock-fault";
  if (login_mfa_required_session (handle, subject, &session) != 0
      || seed_enrollment (handle, subject) != 0)
    return 267;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 ago = (gint64) time (NULL) - (16 * 60);
  for (gint i = 0; i < 5; i++) {
    g_autofree gchar *state = NULL;
    gint64 count = 0, locked_at = 0;
    if (wyl_policy_store_apply_principal_failure (store, subject, 5, ago,
            &state, &count, &locked_at) != WYRELOG_E_OK)
      return 268;
  }
  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 269;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", correct);
  wyl_handle_set_engine_replacement_fault_once_for_test (handle,
      WYL_ENGINE_REPLACEMENT_FAULT_PRINCIPAL_STATES);
  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
  wyrelog_error_t rc = wyl_mfa_verify_totp_with_outcome (handle, session,
      proof, &outcome);
  if (rc == WYRELOG_E_OK || rc == WYRELOG_E_POLICY
      || outcome != WYL_MFA_VALIDATION_AUTH_REQUIRED_UNPUBLISHED
      || !wyl_handle_engine_pair_is_poisoned (handle)
      || wyl_handle_engine_pair_is_ready (handle))
    return 270;
  g_autofree gchar *state = NULL;
  gint64 count = -1, locked_at = 0;
  if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0
      || g_strcmp0 (state, "unverified") != 0 || count != 0
      || locked_at != G_MININT64)
    return 271;
  PrincipalEventCapture capture = {
    .subject_id = subject,
    .event = "unlock",
    .event_id = -1,
  };
  if (wyl_policy_store_foreach_principal_event (store,
          capture_principal_event, &capture) != WYRELOG_E_OK
      || capture.matches != 1
      || wyl_handle_reconcile_committed_engine_pair (handle,
          verify_unlock_reconciliation, &capture) != WYRELOG_E_OK
      || wyl_handle_engine_pair_is_poisoned (handle)
      || !wyl_handle_engine_pair_is_ready (handle))
    return 272;
  return 0;
}

static gint
check_auto_unlock_postcommit_fault_matrix (void)
{
  typedef struct
  {
    WylEngineReplacementFault replacement_fault;
    WylPolicySnapshotFinishFailStage snapshot_fault;
    const gchar *suffix;
  } UnlockFault;
  const UnlockFault faults[] = {
    {WYL_ENGINE_REPLACEMENT_FAULT_PUBLICATION_VERIFY_POLICY,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_NONE, "verify"},
    {WYL_ENGINE_REPLACEMENT_FAULT_CALLBACK,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_NONE, "callback"},
    {WYL_ENGINE_REPLACEMENT_FAULT_PUBLICATION_DELTA,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_NONE, "delta"},
    {WYL_ENGINE_REPLACEMENT_FAULT_NONE,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_ROLLBACK, "snapshot-rollback"},
    {WYL_ENGINE_REPLACEMENT_FAULT_NONE,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_TRANSACTION_STATE, "snapshot-state"},
    {WYL_ENGINE_REPLACEMENT_FAULT_NONE,
        WYL_POLICY_SNAPSHOT_FINISH_FAIL_AUTOCOMMIT, "snapshot-autocommit"},
  };
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    g_autofree gchar *subject = g_strdup_printf ("validator.unlock-%s",
        faults[i].suffix);
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
      return 367;
    g_autoptr (WylSession) session = NULL;
    if (login_mfa_required_session (handle, subject, &session) != 0
        || seed_enrollment (handle, subject) != 0)
      return 368;
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    gint64 ago = (gint64) time (NULL) - (16 * 60);
    for (guint failure = 0; failure < 5; failure++) {
      g_autofree gchar *state = NULL;
      gint64 count = 0, locked_at = 0;
      if (wyl_policy_store_apply_principal_failure (store, subject, 5, ago,
              &state, &count, &locked_at) != WYRELOG_E_OK)
        return 369;
    }
    guint correct = 0;
    gint64 now = 0;
    guint64 step = 0;
    if (compute_code_for_now (&correct, &now, &step) != 0)
      return 370;
    gchar proof[8];
    g_snprintf (proof, sizeof proof, "%06u", correct);
    guint callbacks = 0;
    if (wyl_handle_engine_set_delta_callback (handle, count_lock_delta,
            &callbacks) != WYRELOG_E_OK)
      return 371;
    if (faults[i].replacement_fault != WYL_ENGINE_REPLACEMENT_FAULT_NONE)
      wyl_handle_set_engine_replacement_fault_once_for_test (handle,
          faults[i].replacement_fault);
    else
      wyl_policy_store_read_snapshot_finish_fail_once_for_test (store,
          faults[i].snapshot_fault);
    WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
    wyrelog_error_t rc = wyl_mfa_verify_totp_with_outcome (handle, session,
        proof, &outcome);
    if (rc == WYRELOG_E_OK || outcome !=
        WYL_MFA_VALIDATION_AUTH_REQUIRED_UNPUBLISHED
        || !wyl_handle_engine_pair_is_poisoned (handle)
        || wyl_handle_engine_pair_is_ready (handle) || callbacks != 0
        || wyl_handle_pending_delta_count_for_test (handle) != 0)
      return 372;
    PrincipalEventCapture capture = {
      .subject_id = subject,.event = "unlock",.event_id = -1,
    };
    if (wyl_policy_store_foreach_principal_event (store,
            capture_principal_event, &capture) != WYRELOG_E_OK
        || capture.matches != 1 || capture.event_id <= 0
        || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_INVALID
        || !wyl_handle_engine_pair_is_poisoned (handle)
        || wyl_handle_engine_pair_is_ready (handle)
        || wyl_handle_reconcile_committed_engine_pair (handle,
            reject_reconciliation, NULL) != WYRELOG_E_POLICY
        || !wyl_handle_engine_pair_is_poisoned (handle)
        || wyl_handle_engine_pair_is_ready (handle)
        || wyl_handle_reconcile_committed_engine_pair (handle,
            verify_unlock_reconciliation, &capture) != WYRELOG_E_OK
        || wyl_handle_engine_pair_is_poisoned (handle)
        || !wyl_handle_engine_pair_is_ready (handle)
        || !engine_contains_unlock_publication (handle, subject,
            capture.event_id))
      return 373;
  }
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

  /* Success through the proof-bearing boundary: MFA_OK state/event and the
   * counter reset share one FULL publication transaction. */
  if (wyl_session_mfa_verify_with_proof (handle, session, good_proof,
          wyl_mfa_validator_totp, NULL)
      != WYRELOG_E_OK)
    return 277;
  g_clear_pointer (&st, g_free);
  if (read_principal_state (handle, "validator.reset-on-ok", &st, &count,
          &locked_at) != 0)
    return 278;
  if (count != 0)
    return 279;

  return 0;
}

typedef struct
{
  WylHandle *handle;
  WylSession *session;
  const gchar *proof;
  wyrelog_error_t rc;
  WylMfaValidationOutcome outcome;
  GMutex *mutex;
  GCond *cond;
  guint *ready;
  gboolean *go;
} ConcurrentFailure;

static gpointer
run_concurrent_failure (gpointer data)
{
  ConcurrentFailure *failure = data;
  g_mutex_lock (failure->mutex);
  (*failure->ready)++;
  g_cond_broadcast (failure->cond);
  while (!*failure->go)
    g_cond_wait (failure->cond, failure->mutex);
  g_mutex_unlock (failure->mutex);
  failure->outcome = WYL_MFA_VALIDATION_ERROR;
  failure->rc = wyl_mfa_verify_totp_with_outcome (failure->handle,
      failure->session, failure->proof, &failure->outcome);
  return NULL;
}

static gint
check_concurrent_failures_lock_once (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 280;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "validator.concurrent", &session)
      != 0 || seed_enrollment (handle, "validator.concurrent") != 0)
    return 281;
  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 282;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", (correct + 1) % 1000000);

  ConcurrentFailure failures[8] = { 0 };
  GThread *threads[G_N_ELEMENTS (failures)] = { 0 };
  GMutex mutex;
  GCond cond;
  guint ready = 0;
  gboolean go = FALSE;
  g_mutex_init (&mutex);
  g_cond_init (&cond);
  for (gsize i = 0; i < G_N_ELEMENTS (failures); i++) {
    failures[i] = (ConcurrentFailure) {
    .handle = handle,.session = session,.proof = proof,.rc =
          WYRELOG_E_OK,.mutex = &mutex,.cond = &cond,.ready = &ready,.go =
          &go,};
    threads[i] =
        g_thread_new ("mfa-concurrent-failure", run_concurrent_failure,
        &failures[i]);
  }
  g_mutex_lock (&mutex);
  while (ready != G_N_ELEMENTS (failures))
    g_cond_wait (&cond, &mutex);
  go = TRUE;
  g_cond_broadcast (&cond);
  g_mutex_unlock (&mutex);
  guint locked_transitions = 0;
  guint rejected = 0;
  guint already_locked = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (failures); i++) {
    g_thread_join (threads[i]);
    if (failures[i].rc != WYRELOG_E_POLICY)
      return 283;
    if (failures[i].outcome == WYL_MFA_VALIDATION_REJECTED_LOCKED)
      locked_transitions++;
    else if (failures[i].outcome == WYL_MFA_VALIDATION_REJECTED)
      rejected++;
    else if (failures[i].outcome == WYL_MFA_VALIDATION_LOCKED)
      already_locked++;
    else
      return 283;
  }
  g_cond_clear (&cond);
  g_mutex_clear (&mutex);
  g_autofree gchar *state = NULL;
  gint64 count = 0;
  gint64 locked_at = G_MININT64;
  if (read_principal_state (handle, "validator.concurrent", &state, &count,
          &locked_at) != 0 || g_strcmp0 (state, "locked") != 0 || count != 5
      || locked_at == G_MININT64 || locked_transitions != 1)
    return 284;
  /* The engine session serializes all eight requests.  Four counter-only
   * commits precede exactly one threshold publisher; every later request is
   * an expected locked-authority supersession, never an INTERNAL error. */
  if (rejected != 4 || already_locked != 3)
    return 286;
  PrincipalEventCapture capture = {
    .subject_id = "validator.concurrent",
    .event = "lock",
    .event_id = -1,
  };
  if (wyl_policy_store_foreach_principal_event
      (wyl_handle_get_policy_store (handle), capture_principal_event,
          &capture) != WYRELOG_E_OK || capture.matches != 1
      || !engine_contains_lock_publication (handle, "validator.concurrent",
          capture.event_id))
    return 285;
  return 0;
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  GThread *first_thread;
  gboolean first_started;
  gboolean first_acquired;
  gboolean second_waiting;
  gboolean release_first;
} OrderedMfaRace;

static void
observe_ordered_mfa_race (WylEngineSessionCheckpoint phase, gpointer data)
{
  OrderedMfaRace *race = data;
  g_mutex_lock (&race->mutex);
  gboolean first = g_thread_self () == race->first_thread;
  if (phase == WYL_ENGINE_SESSION_WAITING && !first)
    race->second_waiting = TRUE;
  if (phase == WYL_ENGINE_SESSION_ACQUIRED && first && !race->first_acquired) {
    race->first_acquired = TRUE;
    g_cond_broadcast (&race->changed);
    while (!race->release_first)
      g_cond_wait (&race->changed, &race->mutex);
  }
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
}

typedef enum
{
  ORDERED_MFA_THRESHOLD,
  ORDERED_MFA_SUCCESS,
  ORDERED_MFA_DECISION,
  ORDERED_MFA_LOGIN,
  ORDERED_MFA_UNLOCK,
} OrderedMfaOperation;

typedef struct
{
  OrderedMfaRace *race;
  WylHandle *handle;
  WylSession *session;
  const gchar *proof;
  OrderedMfaOperation operation;
  gboolean first;
  wyrelog_error_t rc;
  WylMfaValidationOutcome outcome;
  wyl_decision_t decision;
} OrderedMfaWorker;

static gpointer
run_ordered_mfa_worker (gpointer data)
{
  OrderedMfaWorker *worker = data;
  if (worker->first) {
    g_mutex_lock (&worker->race->mutex);
    worker->race->first_thread = g_thread_self ();
    worker->race->first_started = TRUE;
    g_cond_broadcast (&worker->race->changed);
    g_mutex_unlock (&worker->race->mutex);
  }
  if (worker->operation == ORDERED_MFA_THRESHOLD
      || worker->operation == ORDERED_MFA_UNLOCK) {
    worker->outcome = WYL_MFA_VALIDATION_ERROR;
    worker->rc = wyl_mfa_verify_totp_with_outcome (worker->handle,
        worker->session, worker->proof, &worker->outcome);
  } else if (worker->operation == ORDERED_MFA_SUCCESS) {
    worker->rc = wyl_session_mfa_verify (worker->handle, worker->session);
  } else if (worker->operation == ORDERED_MFA_DECISION) {
    g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
    wyl_decide_req_set_subject_id (req, "validator.ordered-race");
    wyl_decide_req_set_action (req, "wr.ordered-race.read");
    wyl_decide_req_set_resource_id (req, "ordered-resource");
    g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
    worker->rc = wyl_decide (worker->handle, req, resp);
    worker->decision = wyl_decide_resp_get_decision (resp);
  } else {
    g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
    wyl_login_req_set_username (req, "validator.ordered-race");
    g_autoptr (WylSession) login_session = NULL;
    worker->rc = wyl_session_login (worker->handle, req, &login_session);
  }
  return NULL;
}

static gboolean
wait_ordered_flag (OrderedMfaRace *race, gboolean *flag)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  while (!*flag && g_cond_wait_until (&race->changed, &race->mutex, deadline));
  return *flag;
}

static gint
check_threshold_serializes_with_mfa_and_decision (void)
{
  for (guint scenario = 0; scenario < 4; scenario++) {
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
      return 350;
    g_autoptr (WylSession) session = NULL;
    const gchar *subject = "validator.ordered-race";
    if (login_mfa_required_session (handle, subject, &session) != 0
        || seed_enrollment (handle, subject) != 0)
      return 351;
    guint correct = 0;
    gint64 now = 0;
    guint64 step = 0;
    if (compute_code_for_now (&correct, &now, &step) != 0)
      return 352;
    gchar proof[8];
    g_snprintf (proof, sizeof proof, "%06u", (correct + 1) % 1000000);
    for (guint failure = 0; failure < 4; failure++)
      if (wyl_mfa_validator_totp (handle, session, proof, NULL)
          != WYRELOG_E_POLICY)
        return 353;

    OrderedMfaRace race = { 0 };
    g_mutex_init (&race.mutex);
    g_cond_init (&race.changed);
    OrderedMfaWorker first = {
      .race = &race,
      .handle = handle,
      .session = session,
      .proof = proof,
      .operation = scenario == 1 ? ORDERED_MFA_SUCCESS : ORDERED_MFA_THRESHOLD,
      .first = TRUE,
      .rc = WYRELOG_E_INTERNAL,
    };
    OrderedMfaWorker second = {
      .race = &race,
      .handle = handle,
      .session = session,
      .proof = proof,
      .operation = scenario == 0 ? ORDERED_MFA_SUCCESS :
          scenario == 1 ? ORDERED_MFA_THRESHOLD :
          scenario == 2 ? ORDERED_MFA_DECISION : ORDERED_MFA_LOGIN,
      .rc = WYRELOG_E_INTERNAL,
      .decision = WYL_DECISION_ALLOW,
    };
    wyl_handle_set_engine_session_checkpoint_for_test (handle,
        observe_ordered_mfa_race, &race);
    GThread *first_thread = g_thread_new ("ordered-mfa-first",
        run_ordered_mfa_worker, &first);
    g_mutex_lock (&race.mutex);
    gboolean acquired = wait_ordered_flag (&race, &race.first_acquired);
    g_mutex_unlock (&race.mutex);
    GThread *second_thread = g_thread_new ("ordered-mfa-second",
        run_ordered_mfa_worker, &second);
    g_mutex_lock (&race.mutex);
    gboolean waiting = wait_ordered_flag (&race, &race.second_waiting);
    race.release_first = TRUE;
    g_cond_broadcast (&race.changed);
    g_mutex_unlock (&race.mutex);
    g_thread_join (first_thread);
    g_thread_join (second_thread);
    wyl_handle_set_engine_session_checkpoint_for_test (handle, NULL, NULL);
    g_cond_clear (&race.changed);
    g_mutex_clear (&race.mutex);
    if (!acquired || !waiting)
      return 354;

    g_autofree gchar *state = NULL;
    gint64 count = -1, locked_at = 0;
    if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0)
      return 355;
    if (scenario == 1) {
      if (first.rc != WYRELOG_E_OK || second.rc != WYRELOG_E_INTERNAL
          || g_strcmp0 (state, "authenticated") != 0 || count != 0
          || !engine_contains_principal_state (handle, subject,
              "authenticated"))
        return 356;
    } else {
      if (first.rc != WYRELOG_E_POLICY
          || first.outcome != WYL_MFA_VALIDATION_REJECTED_LOCKED
          || g_strcmp0 (state, "locked") != 0 || count != 5
          || !engine_contains_principal_state (handle, subject, "locked"))
        return 357;
      if (scenario == 0 && second.rc == WYRELOG_E_OK)
        return 358;
      if (scenario == 2 && (second.rc != WYRELOG_E_OK
              || second.decision != WYL_DECISION_DENY))
        return 359;
      if (scenario == 3 && second.rc == WYRELOG_E_OK)
        return 360;
    }
  }
  return 0;
}

static gint
check_auto_unlock_serializes_with_decision (void)
{
  for (guint unlock_first = 0; unlock_first < 2; unlock_first++) {
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
      return 361;
    const gchar *subject = "validator.ordered-race";
    g_autoptr (WylSession) session = NULL;
    if (login_mfa_required_session (handle, subject, &session) != 0
        || seed_enrollment (handle, subject) != 0)
      return 362;
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    gint64 ago = (gint64) time (NULL) - (16 * 60);
    for (guint failure = 0; failure < 5; failure++) {
      g_autofree gchar *state = NULL;
      gint64 count = 0, locked_at = 0;
      if (wyl_policy_store_apply_principal_failure (store, subject, 5, ago,
              &state, &count, &locked_at) != WYRELOG_E_OK)
        return 363;
    }
    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
      return 364;
    guint correct = 0;
    gint64 now = 0;
    guint64 step = 0;
    if (compute_code_for_now (&correct, &now, &step) != 0)
      return 365;
    gchar proof[8];
    g_snprintf (proof, sizeof proof, "%06u", correct);

    OrderedMfaRace race = { 0 };
    g_mutex_init (&race.mutex);
    g_cond_init (&race.changed);
    OrderedMfaWorker first = {
      .race = &race,.handle = handle,.session = session,.proof = proof,
      .operation = unlock_first ? ORDERED_MFA_UNLOCK : ORDERED_MFA_DECISION,
      .first = TRUE,.rc = WYRELOG_E_INTERNAL,.decision = WYL_DECISION_ALLOW,
    };
    OrderedMfaWorker second = {
      .race = &race,.handle = handle,.session = session,.proof = proof,
      .operation = unlock_first ? ORDERED_MFA_DECISION : ORDERED_MFA_UNLOCK,
      .rc = WYRELOG_E_INTERNAL,.decision = WYL_DECISION_ALLOW,
    };
    wyl_handle_set_engine_session_checkpoint_for_test (handle,
        observe_ordered_mfa_race, &race);
    GThread *first_thread = g_thread_new ("unlock-decision-first",
        run_ordered_mfa_worker, &first);
    g_mutex_lock (&race.mutex);
    gboolean acquired = wait_ordered_flag (&race, &race.first_acquired);
    g_mutex_unlock (&race.mutex);
    GThread *second_thread = g_thread_new ("unlock-decision-second",
        run_ordered_mfa_worker, &second);
    g_mutex_lock (&race.mutex);
    gboolean waiting = wait_ordered_flag (&race, &race.second_waiting);
    race.release_first = TRUE;
    g_cond_broadcast (&race.changed);
    g_mutex_unlock (&race.mutex);
    g_thread_join (first_thread);
    g_thread_join (second_thread);
    wyl_handle_set_engine_session_checkpoint_for_test (handle, NULL, NULL);
    g_cond_clear (&race.changed);
    g_mutex_clear (&race.mutex);
    OrderedMfaWorker *unlock = unlock_first ? &first : &second;
    OrderedMfaWorker *decision = unlock_first ? &second : &first;
    g_autofree gchar *state = NULL;
    gint64 count = -1, locked_at = 0;
    if (!acquired || !waiting || unlock->rc != WYRELOG_E_POLICY
        || unlock->outcome != WYL_MFA_VALIDATION_AUTH_REQUIRED
        || decision->rc != WYRELOG_E_OK
        || decision->decision != WYL_DECISION_DENY
        || read_principal_state (handle, subject, &state, &count,
            &locked_at) != 0 || g_strcmp0 (state, "unverified") != 0
        || count != 0 || locked_at != G_MININT64
        || !engine_contains_principal_state (handle, subject, "unverified"))
      return 366;
  }
  return 0;
}

static gint
check_locked_projection_reconstructs_after_restart (void)
{
  const gchar *subject = "validator.restart-locked-projection";
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyrelog-mfa-restart-XXXXXX",
      &error);
  if (dir == NULL)
    return 330;
  g_autofree gchar *policy_path = g_build_filename (dir, "policy.sqlite",
      NULL);
  WylHandleOpenOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = policy_path,
  };
  gint64 lock_event_id = -1;
  gint64 unlock_event_id = -1;
  {
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_handle_open_with_options (&options, &handle) != WYRELOG_E_OK)
      return 331;
    g_autoptr (WylSession) session = NULL;
    if (login_mfa_required_session (handle, subject, &session) != 0
        || seed_enrollment (handle, subject) != 0)
      return 332;
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    gint64 ago = (gint64) time (NULL) - (16 * 60);
    for (guint failure = 0; failure < 5; failure++) {
      g_autofree gchar *state = NULL;
      gint64 count = 0, locked_at = 0;
      if (wyl_policy_store_apply_principal_failure (store, subject, 5, ago,
              &state, &count, &locked_at) != WYRELOG_E_OK)
        return 334;
    }
    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
      return 333;
    PrincipalEventCapture capture = {
      .subject_id = subject,
      .event = "lock",
      .event_id = -1,
    };
    if (wyl_policy_store_foreach_principal_event
        (wyl_handle_get_policy_store (handle), capture_principal_event,
            &capture) != WYRELOG_E_OK || capture.matches != 1
        || !engine_contains_lock_publication (handle, subject,
            capture.event_id))
      return 335;
    lock_event_id = capture.event_id;
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_handle_open_with_options (&options, &handle) != WYRELOG_E_OK
        || !wyl_handle_engine_pair_is_ready (handle)
        || wyl_handle_engine_pair_is_poisoned (handle))
      return 336;
    g_autofree gchar *state = NULL;
    gint64 count = 0, locked_at = G_MININT64;
    if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0
        || count != 5 || g_strcmp0 (state, "locked") != 0
        || locked_at == G_MININT64
        || !engine_contains_lock_publication (handle, subject, lock_event_id))
      return 337;

    g_autoptr (WylSession) session = g_object_new (WYL_TYPE_SESSION, NULL);
    session->username = g_strdup (subject);
    guint correct = 0;
    gint64 now = 0;
    guint64 step = 0;
    if (compute_code_for_now (&correct, &now, &step) != 0)
      return 338;
    gchar proof[8];
    g_snprintf (proof, sizeof proof, "%06u", correct);
    WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
    if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
        != WYRELOG_E_POLICY || outcome != WYL_MFA_VALIDATION_AUTH_REQUIRED)
      return 339;
    PrincipalEventCapture capture = {
      .subject_id = subject,
      .event = "unlock",
      .event_id = -1,
    };
    if (wyl_policy_store_foreach_principal_event
        (wyl_handle_get_policy_store (handle), capture_principal_event,
            &capture) != WYRELOG_E_OK || capture.matches != 1
        || !engine_contains_unlock_publication (handle, subject,
            capture.event_id))
      return 340;
    unlock_event_id = capture.event_id;
  }
  {
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_handle_open_with_options (&options, &handle) != WYRELOG_E_OK
        || !wyl_handle_engine_pair_is_ready (handle)
        || wyl_handle_engine_pair_is_poisoned (handle))
      return 341;
    g_autofree gchar *state = NULL;
    gint64 count = -1, locked_at = 0;
    if (read_principal_state (handle, subject, &state, &count, &locked_at) != 0
        || count != 0 || g_strcmp0 (state, "unverified") != 0
        || locked_at != G_MININT64
        || !engine_contains_unlock_publication (handle, subject,
            unlock_event_id))
      return 342;
  }
  g_remove (policy_path);
  g_rmdir (dir);
  return 0;
}

static gint
check_unopened_handle_fails_closed (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 290;
  g_autoptr (WylSession) session = g_object_new (WYL_TYPE_SESSION, NULL);
  session->username = g_strdup ("validator.unopened");
  if (wyl_policy_store_set_principal_state
      (wyl_handle_get_policy_store (handle), session->username,
          "mfa_required") != WYRELOG_E_OK
      || seed_enrollment (handle, session->username) != 0)
    return 291;
  guint correct = 0;
  gint64 now = 0;
  guint64 step = 0;
  if (compute_code_for_now (&correct, &now, &step) != 0)
    return 292;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", (correct + 1) % 1000000);
  for (gint64 expected = 1; expected <= 4; expected++) {
    WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
    if (wyl_mfa_verify_totp_with_outcome (handle, session, proof, &outcome)
        != WYRELOG_E_POLICY || outcome != WYL_MFA_VALIDATION_REJECTED
        || wyl_handle_engine_pair_is_ready (handle)
        || wyl_handle_engine_pair_is_poisoned (handle))
      return 293;
    g_autofree gchar *state = NULL;
    gint64 count = 0, locked_at = 0;
    if (read_principal_state (handle, session->username, &state, &count,
            &locked_at) != 0 || count != expected
        || g_strcmp0 (state, "mfa_required") != 0)
      return 294;
  }
  WylMfaValidationOutcome outcome = WYL_MFA_VALIDATION_ERROR;
  wyrelog_error_t threshold_rc = wyl_mfa_verify_totp_with_outcome (handle,
      session, proof, &outcome);
  if (threshold_rc != WYRELOG_E_POLICY)
    return 295;
  if (outcome != WYL_MFA_VALIDATION_REJECTED_LOCKED)
    return 296;
  if (wyl_handle_engine_pair_is_ready (handle))
    return 297;
  if (wyl_handle_engine_pair_is_poisoned (handle))
    return 298;
  g_autofree gchar *state = NULL;
  gint64 count = 0, locked_at = 0;
  if (read_principal_state (handle, session->username, &state, &count,
          &locked_at) != 0 || count != 5
      || g_strcmp0 (state, "locked") != 0 || locked_at == G_MININT64)
    return 299;
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
  if ((rc = check_lock_publication_accepts_serialized_unlock ()) != 0)
    return rc;
  if ((rc = check_counter_only_commit_ambiguity_preserves_engine_pair ()) != 0)
    return rc;
  if ((rc = check_projected_commit_ambiguity_poison_engine_pair ()) != 0)
    return rc;
  if ((rc = check_threshold_postcommit_faults_require_exact_repair ()) != 0)
    return rc;
  if ((rc = check_validator_locked_principal_rejects_without_hmac ()) != 0)
    return rc;
  if ((rc = check_validator_auto_unlocks_after_window ()) != 0)
    return rc;
  if ((rc = check_auto_unlock_committed_publication_failure_repairs ()) != 0)
    return rc;
  if ((rc = check_auto_unlock_postcommit_fault_matrix ()) != 0)
    return rc;
  if ((rc = check_validator_resets_counter_on_success ()) != 0)
    return rc;
  if ((rc = check_concurrent_failures_lock_once ()) != 0)
    return rc;
  if ((rc = check_threshold_serializes_with_mfa_and_decision ()) != 0)
    return rc;
  if ((rc = check_auto_unlock_serializes_with_decision ()) != 0)
    return rc;
  if ((rc = check_locked_projection_reconstructs_after_restart ()) != 0)
    return rc;
  if ((rc = check_unopened_handle_fails_closed ()) != 0)
    return rc;
  if ((rc = check_validator_rejects_null_handle_or_session ()) != 0)
    return rc;
  if ((rc = check_handle_default_validator_is_wired ()) != 0)
    return rc;
  return 0;
}

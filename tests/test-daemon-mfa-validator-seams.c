/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Seam-enabled tests for the daemon-side TOTP MFA validator's #746
 * publication behaviour (wyrelog/auth/mfa-validator.c).
 *
 * The validator durably records MFA lockout state transitions
 * (MFA_REQUIRED -> LOCKED on the 5th consecutive failure, and the
 * elapsed-window LOCKED -> UNVERIFIED auto-unlock) and then publishes
 * each transition to the live read/delta engine pair via the #745
 * committed-publication contract, proving the immutable principal_fired
 * event row and failing closed (poisoning the pair) on any post-commit
 * uncertainty.
 *
 * These cases require the WYL_TEST_HANDLE_SEAMS build so they can:
 *   - observe the rebuilt engine projection
 *     (wyl_handle_engine_contains, get_read_engine),
 *   - inspect / assert pair readiness and poison
 *     (wyl_handle_engine_pair_is_ready / _is_poisoned), and
 *   - inject a post-commit rebuild fault
 *     (wyl_handle_set_engine_insert_fault_once) so the fail-closed
 *     poison path is deterministic.
 *
 * The always-on regression coverage (state machine, counter, timing)
 * lives in tests/test-daemon-mfa-validator.c and is unchanged.
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
  memcpy (enr.secret, TEST_SEED, WYL_TOTP_SEED_BYTES);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = 1700000000;
  wyrelog_error_t rc = wyl_policy_store_totp_enrollment_insert (store, &enr);
  wyl_totp_enrollment_clear (&enr);
  return (rc == WYRELOG_E_OK) ? 0 : -1;
}

static gint
compute_code_for_now (guint *out_code)
{
  gint64 now = (gint64) time (NULL);
  guint64 step = (guint64) (now / WYL_TOTP_STEP_SECONDS);
  guint code = 0;
  if (wyl_totp_code_at_step (TEST_SEED, sizeof TEST_SEED, step, &code, NULL)
      != WYRELOG_E_OK)
    return -1;
  *out_code = code;
  return 0;
}

static void
format_wrong_proof (gchar *buf, gsize buf_len)
{
  guint correct = 0;
  (void) compute_code_for_now (&correct);
  g_snprintf (buf, buf_len, "%06u", (correct + 1) % 1000000);
}

static void
format_correct_proof (gchar *buf, gsize buf_len)
{
  guint correct = 0;
  (void) compute_code_for_now (&correct);
  g_snprintf (buf, buf_len, "%06u", correct);
}

static gint
read_principal_state (WylHandle *handle, const gchar *subject_id,
    gchar **out_state)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = 0;
  gint64 locked_at = 0;
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_policy_store_get_principal_lock_info (store,
      subject_id, out_state, &count, &locked_at, &found);
  if (rc != WYRELOG_E_OK || !found)
    return -1;
  return 0;
}

/* Observe principal_state(subject, state) in the rebuilt read engine. */
static gboolean
engine_observes_state (WylHandle *handle, const gchar *subject_id,
    const gchar *state)
{
  gint64 row[2] = { 0, 0 };
  if (wyl_handle_intern_engine_symbol (handle, subject_id, &row[0])
      != WYRELOG_E_OK
      || wyl_handle_intern_engine_symbol (handle, state, &row[1])
      != WYRELOG_E_OK)
    return FALSE;
  gboolean contains = FALSE;
  if (wyl_handle_engine_contains (handle, "principal_state", row, 2, &contains)
      != WYRELOG_E_OK)
    return FALSE;
  return contains;
}

typedef struct
{
  const gchar *subject_id;
  const gchar *event;
  gint64 event_id;
  gboolean found;
} EventFind;

static wyrelog_error_t
event_find_cb (gint64 event_id, const gchar *subject_id, const gchar *event,
    const gchar *from_state, const gchar *to_state, gpointer user_data)
{
  (void) from_state;
  (void) to_state;
  EventFind *find = user_data;
  if (g_strcmp0 (subject_id, find->subject_id) == 0
      && g_strcmp0 (event, find->event) == 0) {
    /* Keep the most recent (highest rowid) matching event. */
    if (!find->found || event_id > find->event_id) {
      find->event_id = event_id;
      find->found = TRUE;
    }
  }
  return WYRELOG_E_OK;
}

static gint
find_event_id (WylHandle *handle, const gchar *subject_id, const gchar *event,
    gint64 *out_id)
{
  EventFind find = { subject_id, event, 0, FALSE };
  if (wyl_policy_store_foreach_principal_event
      (wyl_handle_get_policy_store (handle), event_find_cb, &find)
      != WYRELOG_E_OK || !find.found)
    return -1;
  *out_id = find.event_id;
  return 0;
}

/* Observe the immutable principal_fired event row in the read engine.
 * principal_fired/5 column order: {event_id, subject, from, event, to}. */
static gboolean
engine_observes_fired (WylHandle *handle, gint64 event_id,
    const gchar *subject_id, const gchar *from_state, const gchar *event,
    const gchar *to_state)
{
  gint64 row[5] = { event_id, 0, 0, 0, 0 };
  const gchar *symbols[] = { subject_id, from_state, event, to_state };
  for (guint i = 0; i < G_N_ELEMENTS (symbols); i++) {
    if (wyl_handle_intern_engine_symbol (handle, symbols[i], &row[i + 1])
        != WYRELOG_E_OK)
      return FALSE;
  }
  gboolean contains = FALSE;
  if (wyl_handle_engine_contains (handle, "principal_fired", row, 5, &contains)
      != WYRELOG_E_OK)
    return FALSE;
  return contains;
}

/* Drive |count| failed TOTP verifications with a wrong code.  Returns the
 * validator's return code from the final call (each intermediate call is
 * asserted to be E_POLICY via the caller). */
static wyrelog_error_t
drive_failures (WylHandle *handle, WylSession *session, int count)
{
  gchar wrong[8];
  format_wrong_proof (wrong, sizeof wrong);
  wyrelog_error_t last = WYRELOG_E_OK;
  for (int i = 0; i < count; i++)
    last = wyl_mfa_validator_totp (handle, session, wrong, NULL);
  return last;
}

/* Seed a LOCKED principal directly with a controllable locked_at so the
 * auto-unlock window state is deterministic. */
static gint
seed_locked_principal (WylHandle *handle, const gchar *subject_id,
    gint64 locked_at_secs)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_set_principal_state (store, subject_id, "mfa_required")
      != WYRELOG_E_OK)
    return -1;
  for (int i = 0; i < 5; i++) {
    g_autofree gchar *st = NULL;
    gint64 c = 0, l = 0;
    if (wyl_policy_store_apply_principal_failure (store, subject_id, 5,
            locked_at_secs, &st, &c, &l, NULL) != WYRELOG_E_OK)
      return -1;
  }
  return 0;
}

/* Case 1: the 5th failure publishes and verifies the lock transition. */
static gint
check_fifth_failure_publishes_and_verifies (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 300;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "seam.lock-publish", &session) != 0)
    return 301;
  if (seed_enrollment (handle, "seam.lock-publish") != 0)
    return 302;

  for (int i = 0; i < 4; i++) {
    if (drive_failures (handle, session, 1) != WYRELOG_E_POLICY)
      return 303;
  }
  /* 5th failure: crosses threshold, publishes, and (wrong code) still
   * returns E_POLICY - NOT E_INTERNAL - proving the publication and the
   * exact event-row verification both succeeded. */
  if (drive_failures (handle, session, 1) != WYRELOG_E_POLICY)
    return 304;

  g_autofree gchar *st = NULL;
  if (read_principal_state (handle, "seam.lock-publish", &st) != 0)
    return 305;
  if (g_strcmp0 (st, "locked") != 0)
    return 306;
  if (!wyl_handle_engine_pair_is_ready (handle)
      || wyl_handle_engine_pair_is_poisoned (handle))
    return 307;
  if (!engine_observes_state (handle, "seam.lock-publish", "locked"))
    return 308;
  gint64 event_id = 0;
  if (find_event_id (handle, "seam.lock-publish", "lock", &event_id) != 0)
    return 309;
  if (!engine_observes_fired (handle, event_id, "seam.lock-publish",
          "mfa_required", "lock", "locked"))
    return 310;
  return 0;
}

/* Case 2: an injected post-commit rebuild fault on the 5th failure fails
 * closed - E_INTERNAL, pair poisoned, subsequent verifies denied, and an
 * ordinary reload does NOT clear the poison. */
static gint
check_fifth_failure_publication_fault_fails_closed (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 320;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "seam.lock-fault", &session) != 0)
    return 321;
  if (seed_enrollment (handle, "seam.lock-fault") != 0)
    return 322;

  for (int i = 0; i < 4; i++) {
    if (drive_failures (handle, session, 1) != WYRELOG_E_POLICY)
      return 323;
  }
  /* Poison the post-commit rebuild: the durable lock commits, then the
   * engine-pair rebuild inside finish_external_publication fails on the
   * first principal_state insert. */
  wyl_handle_set_engine_insert_fault_once (handle, "principal_state",
      WYRELOG_E_IO);
  if (drive_failures (handle, session, 1) != WYRELOG_E_INTERNAL)
    return 324;
  /* Durable state still crossed to locked (the store savepoint committed
   * before publication). */
  g_autofree gchar *st = NULL;
  if (read_principal_state (handle, "seam.lock-fault", &st) != 0)
    return 325;
  if (g_strcmp0 (st, "locked") != 0)
    return 326;
  if (wyl_handle_engine_pair_is_ready (handle)
      || !wyl_handle_engine_pair_is_poisoned (handle))
    return 327;
  /* Subsequent verify is denied (the locked principal is bounced). */
  gchar correct[8];
  format_correct_proof (correct, sizeof correct);
  if (wyl_mfa_validator_totp (handle, session, correct, NULL)
      != WYRELOG_E_POLICY)
    return 328;
  /* An ordinary reload cannot clear a poisoned pair. */
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_INVALID)
    return 329;
  if (!wyl_handle_engine_pair_is_poisoned (handle)
      || wyl_handle_engine_pair_is_ready (handle))
    return 330;
  return 0;
}

/* Case 3: an elapsed auto-unlock publishes and verifies the unlock. */
static gint
check_auto_unlock_publishes_and_verifies (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 340;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "seam.unlock-publish", &session) != 0)
    return 341;
  if (seed_enrollment (handle, "seam.unlock-publish") != 0)
    return 342;
  /* Locked 16 minutes ago: past the 15-minute auto-unlock window. */
  gint64 ago = (gint64) time (NULL) - (16 * 60);
  if (seed_locked_principal (handle, "seam.unlock-publish", ago) != 0)
    return 343;

  gchar correct[8];
  format_correct_proof (correct, sizeof correct);
  /* Auto-unlock fires, publishes, and the verify bounces (E_POLICY). */
  if (wyl_mfa_validator_totp (handle, session, correct, NULL)
      != WYRELOG_E_POLICY)
    return 344;

  g_autofree gchar *st = NULL;
  if (read_principal_state (handle, "seam.unlock-publish", &st) != 0)
    return 345;
  if (g_strcmp0 (st, "unverified") != 0)
    return 346;
  if (!wyl_handle_engine_pair_is_ready (handle)
      || wyl_handle_engine_pair_is_poisoned (handle))
    return 347;
  if (!engine_observes_state (handle, "seam.unlock-publish", "unverified"))
    return 348;
  gint64 event_id = 0;
  if (find_event_id (handle, "seam.unlock-publish", "unlock", &event_id) != 0)
    return 349;
  if (!engine_observes_fired (handle, event_id, "seam.unlock-publish",
          "locked", "unlock", "unverified"))
    return 350;
  return 0;
}

/* Case 4a: an in-window locked principal is NOT auto-unlocked and bounces
 * with E_POLICY without touching the engine pair. */
static gint
check_auto_unlock_not_elapsed_is_policy (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 360;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "seam.in-window", &session) != 0)
    return 361;
  if (seed_enrollment (handle, "seam.in-window") != 0)
    return 362;
  if (seed_locked_principal (handle, "seam.in-window", (gint64) time (NULL))
      != 0)
    return 363;

  gchar correct[8];
  format_correct_proof (correct, sizeof correct);
  if (wyl_mfa_validator_totp (handle, session, correct, NULL)
      != WYRELOG_E_POLICY)
    return 364;
  g_autofree gchar *st = NULL;
  if (read_principal_state (handle, "seam.in-window", &st) != 0)
    return 365;
  if (g_strcmp0 (st, "locked") != 0)
    return 366;
  if (!wyl_handle_engine_pair_is_ready (handle)
      || wyl_handle_engine_pair_is_poisoned (handle))
    return 367;
  return 0;
}

/* Case 4b: an injected post-commit rebuild fault on the auto-unlock
 * publication fails closed - E_INTERNAL and pair poisoned. */
static gint
check_auto_unlock_publication_fault_fails_closed (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 370;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "seam.unlock-fault", &session) != 0)
    return 371;
  if (seed_enrollment (handle, "seam.unlock-fault") != 0)
    return 372;
  gint64 ago = (gint64) time (NULL) - (16 * 60);
  if (seed_locked_principal (handle, "seam.unlock-fault", ago) != 0)
    return 373;

  wyl_handle_set_engine_insert_fault_once (handle, "principal_state",
      WYRELOG_E_IO);
  gchar correct[8];
  format_correct_proof (correct, sizeof correct);
  /* The durable unlock commits, then the rebuild inside the publication
   * fails: the validator must fail closed. */
  if (wyl_mfa_validator_totp (handle, session, correct, NULL)
      != WYRELOG_E_INTERNAL)
    return 374;
  if (wyl_handle_engine_pair_is_ready (handle)
      || !wyl_handle_engine_pair_is_poisoned (handle))
    return 375;
  return 0;
}

/* Case 5: the first four failures never replace or poison the engine pair
 * and leave the projection at mfa_required. */
static gint
check_first_four_failures_do_not_republish (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 380;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "seam.no-republish", &session) != 0)
    return 381;
  if (seed_enrollment (handle, "seam.no-republish") != 0)
    return 382;

  WylEngine *before = wyl_handle_get_read_engine (handle);
  if (before == NULL)
    return 383;
  for (int i = 0; i < 4; i++) {
    if (drive_failures (handle, session, 1) != WYRELOG_E_POLICY)
      return 384;
    if (!wyl_handle_engine_pair_is_ready (handle)
        || wyl_handle_engine_pair_is_poisoned (handle))
      return 385;
    /* No publication happened, so the pair identity is unchanged. */
    if (wyl_handle_get_read_engine (handle) != before)
      return 386;
    /* The projection was never advanced past mfa_required. */
    if (engine_observes_state (handle, "seam.no-republish", "locked"))
      return 387;
  }
  g_autofree gchar *st = NULL;
  if (read_principal_state (handle, "seam.no-republish", &st) != 0)
    return 388;
  if (g_strcmp0 (st, "mfa_required") != 0)
    return 389;
  if (!engine_observes_state (handle, "seam.no-republish", "mfa_required"))
    return 390;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_fifth_failure_publishes_and_verifies ()) != 0)
    return rc;
  if ((rc = check_fifth_failure_publication_fault_fails_closed ()) != 0)
    return rc;
  if ((rc = check_auto_unlock_publishes_and_verifies ()) != 0)
    return rc;
  if ((rc = check_auto_unlock_not_elapsed_is_policy ()) != 0)
    return rc;
  if ((rc = check_auto_unlock_publication_fault_fails_closed ()) != 0)
    return rc;
  if ((rc = check_first_four_failures_do_not_republish ()) != 0)
    return rc;
  return 0;
}

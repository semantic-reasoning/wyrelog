/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Concurrency tests for the atomic TOTP MFA_OK commit (issue #751).
 *
 * The fix folds the replay-watermark compare-and-advance, the
 * failure-counter reset, and the principal MFA_REQUIRED -> AUTHENTICATED
 * state+event transition into ONE committed-publication transaction
 * (wyl_session_totp_commit_mfa_ok).  Before the fix these were separate
 * commits with an unconditional watermark write, so two concurrent
 * verifiers presenting the same subject and step could both succeed -
 * double-consuming one proof.
 *
 * CRITICAL (Critic O8): every worker thread shares ONE WylHandle, one
 * WylSession, and therefore one policy store, so the race is genuine.
 * The policy store opens sqlite in SQLITE_OPEN_FULLMUTEX (serialized)
 * mode, and wyl_engine_session_acquire serializes the committed-
 * publication critical section on the handle's recursive engine-session
 * mutex.  Correctness therefore rests on the in-transaction pre-state
 * gate plus the conditional CAS choosing exactly one winner - which is
 * exactly what these tests assert under a barrier-synchronised burst.
 *
 * The race is driven through wyl_session_totp_commit_mfa_ok - the atomic
 * publication unit under test - rather than the full validator wrapper:
 * every store mutation on that path flows through the engine-session
 * lock.  (The validator's failure-path lockout counter writes its own
 * transaction OUTSIDE that lock; racing 8 full validators on one shared
 * sqlite connection would exercise that pre-existing, out-of-#751-scope
 * behaviour, not the atomic MFA_OK commit.)  The single-threaded
 * end-to-end validator path is covered in test-daemon-mfa-validator.c.
 */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <pthread.h>

#include <glib.h>

#include "auth/totp.h"
#include "wyl-session-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/session.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyrelog.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

#define RACE_THREADS 8
/* Each iteration builds a fresh handle so the durable store stays tiny
 * and the per-commit engine rebuild stays cheap.  This internal sweep is
 * a robustness multiplier on top of the barrier-synchronised 8-way race;
 * CI runs the whole binary repeatedly on top of it. */
#define RACE_ITERATIONS 25

static const guint8 TEST_SEED[WYL_TOTP_SEED_BYTES] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x30,
};

/* Portable count-down barrier so this test does not depend on the
 * optional POSIX pthread_barrier_t (absent on some platforms). */
typedef struct
{
  pthread_mutex_t mtx;
  pthread_cond_t cond;
  int target;
  int waiting;
  int generation;
} race_barrier_t;

static void
race_barrier_init (race_barrier_t *b, int target)
{
  pthread_mutex_init (&b->mtx, NULL);
  pthread_cond_init (&b->cond, NULL);
  b->target = target;
  b->waiting = 0;
  b->generation = 0;
}

static void
race_barrier_destroy (race_barrier_t *b)
{
  pthread_mutex_destroy (&b->mtx);
  pthread_cond_destroy (&b->cond);
}

static void
race_barrier_wait (race_barrier_t *b)
{
  pthread_mutex_lock (&b->mtx);
  int gen = b->generation;
  if (++b->waiting == b->target) {
    b->generation++;
    b->waiting = 0;
    pthread_cond_broadcast (&b->cond);
  } else {
    while (gen == b->generation)
      pthread_cond_wait (&b->cond, &b->mtx);
  }
  pthread_mutex_unlock (&b->mtx);
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
  memcpy (enr.secret, TEST_SEED, WYL_TOTP_SEED_BYTES);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = 1700000000;
  wyrelog_error_t rc = wyl_policy_store_totp_enrollment_insert (store, &enr);
  wyl_totp_enrollment_clear (&enr);
  return (rc == WYRELOG_E_OK) ? 0 : -1;
}

static gint
compute_code_for_now (guint *out_code, guint64 *out_step)
{
  gint64 now = (gint64) time (NULL);
  guint64 step = (guint64) (now / WYL_TOTP_STEP_SECONDS);
  guint code = 0;
  if (wyl_totp_code_at_step (TEST_SEED, sizeof TEST_SEED, step, &code, NULL)
      != WYRELOG_E_OK)
    return -1;
  *out_code = code;
  *out_step = step;
  return 0;
}

typedef struct
{
  const gchar *subject_id;
  gint mfa_ok_count;
} MfaOkEventCounter;

static wyrelog_error_t
count_mfa_ok_event_cb (gint64 event_id, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  (void) event_id;
  (void) from_state;
  (void) to_state;
  MfaOkEventCounter *ctr = user_data;
  if (g_strcmp0 (subject_id, ctr->subject_id) == 0
      && g_strcmp0 (event, "mfa_ok") == 0)
    ctr->mfa_ok_count++;
  return WYRELOG_E_OK;
}

static gint
count_mfa_ok_events (WylHandle *handle, const gchar *subject_id)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  MfaOkEventCounter ctr = { subject_id, 0 };
  if (wyl_policy_store_foreach_principal_event (store, count_mfa_ok_event_cb,
          &ctr) != WYRELOG_E_OK)
    return -1;
  return ctr.mfa_ok_count;
}

static gint
assert_single_winner_durable (WylHandle *handle, const gchar *subject_id,
    gint64 step, gint base)
{
  WylTotpEnrollment out = { 0 };
  gboolean found = FALSE;
  if (wyl_policy_store_totp_enrollment_lookup (wyl_handle_get_policy_store
          (handle), subject_id, &out, &found) != WYRELOG_E_OK || !found) {
    wyl_totp_enrollment_clear (&out);
    return base + 1;
  }
  gint64 wm = out.last_verified_step;
  wyl_totp_enrollment_clear (&out);
  if (wm != step)
    return base + 2;

  gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = 0;
  gboolean pfound = FALSE;
  if (wyl_policy_store_get_principal_lock_info (wyl_handle_get_policy_store
          (handle), subject_id, &st, &count, &locked_at,
          &pfound) != WYRELOG_E_OK || !pfound) {
    g_free (st);
    return base + 3;
  }
  gboolean authed = g_strcmp0 (st, "authenticated") == 0;
  g_free (st);
  if (!authed)
    return base + 4;
  if (count != 0)
    return base + 5;
  if (locked_at != G_MININT64)
    return base + 6;
  if (count_mfa_ok_events (handle, subject_id) != 1)
    return base + 7;
  return 0;
}

/* ---- orchestrator-path race (typed receipts) ----------------------- */

typedef struct
{
  WylHandle *handle;
  WylSession *session;
  gint64 matched_step;
  race_barrier_t *barrier;
  wyrelog_error_t rc;
  WylMfaTotpReceipt receipt;
} OrchestratorWorker;

static void *
orchestrator_worker_fn (void *arg)
{
  OrchestratorWorker *w = arg;
  race_barrier_wait (w->barrier);
  w->receipt = (WylMfaTotpReceipt) - 1;
  w->rc = wyl_session_totp_commit_mfa_ok (w->handle, w->session,
      w->matched_step, &w->receipt);
  return NULL;
}

/* One barrier-synchronised burst of RACE_THREADS workers all presenting
 * the same subject and step against a fresh handle/store.  Asserts
 * exactly one WON_COMMITTED winner, the rest REPLAY_SUPERSEDED, and the
 * single-winner durable boundary. */
static gint
check_race_orchestrator_same_step_one_won_receipt (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "race.orch", &session) != 0)
    return 31;
  if (seed_enrollment (handle, "race.orch") != 0)
    return 32;

  guint code = 0;
  guint64 step = 0;
  if (compute_code_for_now (&code, &step) != 0)
    return 33;

  race_barrier_t barrier;
  race_barrier_init (&barrier, RACE_THREADS);
  pthread_t threads[RACE_THREADS];
  OrchestratorWorker workers[RACE_THREADS];
  for (int i = 0; i < RACE_THREADS; i++) {
    workers[i].handle = handle;
    workers[i].session = session;
    workers[i].matched_step = (gint64) step;
    workers[i].barrier = &barrier;
    workers[i].rc = WYRELOG_E_INTERNAL;
    workers[i].receipt = (WylMfaTotpReceipt) - 1;
    if (pthread_create (&threads[i], NULL, orchestrator_worker_fn,
            &workers[i]) != 0) {
      race_barrier_destroy (&barrier);
      return 34;
    }
  }
  for (int i = 0; i < RACE_THREADS; i++)
    pthread_join (threads[i], NULL);
  race_barrier_destroy (&barrier);

  int won = 0, superseded = 0, other = 0;
  for (int i = 0; i < RACE_THREADS; i++) {
    if (workers[i].rc == WYRELOG_E_OK
        && workers[i].receipt == WYL_MFA_TOTP_RECEIPT_WON_COMMITTED)
      won++;
    else if (workers[i].rc == WYRELOG_E_POLICY
        && workers[i].receipt == WYL_MFA_TOTP_RECEIPT_REPLAY_SUPERSEDED)
      superseded++;
    else
      other++;
  }
  if (won != 1)
    return 35;
  if (superseded != RACE_THREADS - 1)
    return 36;
  if (other != 0)
    return 37;

  return assert_single_winner_durable (handle, "race.orch", (gint64) step, 38);
}

/* ---- strictly-newer valid step wins on a fresh principal ----------- */

static gint
check_newer_step_wins_on_fresh_principal (void)
{
  /* The CAS must still admit a genuine strictly-greater step: a fresh
   * mfa_required principal presenting a valid current-step proof commits
   * MFA_OK exactly once.  (An already-authenticated principal cannot
   * re-advance - that FSM pre-state gate is covered in the validator
   * suite - so the newer-step admission is shown on a fresh subject.) */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;
  g_autoptr (WylSession) session = NULL;
  if (login_mfa_required_session (handle, "race.newer", &session) != 0)
    return 51;
  if (seed_enrollment (handle, "race.newer") != 0)
    return 52;

  guint code = 0;
  guint64 step = 0;
  if (compute_code_for_now (&code, &step) != 0)
    return 53;

  WylMfaTotpReceipt receipt = (WylMfaTotpReceipt) - 1;
  if (wyl_session_totp_commit_mfa_ok (handle, session, (gint64) step, &receipt)
      != WYRELOG_E_OK)
    return 54;
  if (receipt != WYL_MFA_TOTP_RECEIPT_WON_COMMITTED)
    return 55;
  return assert_single_winner_durable (handle, "race.newer", (gint64) step, 56);
}

int
main (void)
{
  gint rc;

  for (int iter = 0; iter < RACE_ITERATIONS; iter++) {
    if ((rc = check_race_orchestrator_same_step_one_won_receipt ()) != 0)
      return rc;
  }
  if ((rc = check_newer_step_wins_on_fresh_principal ()) != 0)
    return rc;
  return 0;
}

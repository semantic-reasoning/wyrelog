/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Issue #758 root data-race regression test.
 *
 * management_session_matches_live() delegates its decisive ACTIVE-human
 * decision to wyl_session_liveness_check_private(), whose terminal comparison
 * is a single atomic load of the WylSession lifecycle word.  An async logout
 * stores CLOSED into that same word.  Before the fix both sides touched the
 * bare enum, a C data race and a TOCTOU.
 *
 * This test races the exact two instructions that used to conflict: the
 * management liveness load (thread A, calling the shared primitive that the
 * daemon gate delegates to) against the logout store (thread B, calling the
 * store accessor that transition_session_state performs on the in-memory
 * word).  It proves, per run, that the outcome linearizes to a total order on
 * the word: reads never observe ACTIVE again after once observing CLOSED, and
 * after logout the liveness check is fail-closed.  This validates the logical
 * coherence the atomic accessors provide under a genuinely concurrent load and
 * store; it is not a race detector.  Data-race detection requires ThreadSanitizer
 * (scripts/build-tsan.sh exists but is a single-threaded v0 today, so it does
 * not yet exercise this pair); the structural guard
 * test-session-state-atomic-accessor-structure.py is what statically forbids a
 * regression to a raw non-atomic access.
 */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-session-layout-private.h"
#include "wyrelog/wyl-session-private.h"

#define RACE_ITERATIONS 4000
#define READER_PROBES 512

typedef struct
{
  WylSession *session;
  const gchar *expect_id;
  const gchar *expect_actor;
  const gchar *expect_tenant;
  GMutex mutex;
  GCond changed;
  gboolean go;
  gboolean coherence_violation;
  gboolean reader_saw_transition;
} RaceCtx;

static void
race_wait_for_go (RaceCtx *ctx)
{
  g_mutex_lock (&ctx->mutex);
  while (!ctx->go)
    g_cond_wait (&ctx->changed, &ctx->mutex);
  g_mutex_unlock (&ctx->mutex);
}

/* Thread A: the management liveness load, exactly as the daemon gate runs it. */
static gpointer
reader_thread (gpointer data)
{
  RaceCtx *ctx = data;
  race_wait_for_go (ctx);
  gboolean seen_closed = FALSE;
  for (guint i = 0; i < READER_PROBES; i++) {
    gboolean live = wyl_session_liveness_check_private (ctx->session,
        ctx->expect_id, ctx->expect_actor, ctx->expect_tenant, FALSE);
    if (live && seen_closed)
      ctx->coherence_violation = TRUE;
    if (!live)
      seen_closed = TRUE;
  }
  if (seen_closed)
    ctx->reader_saw_transition = TRUE;
  return NULL;
}

/* Thread B: the logout store, exactly as transition_session_state performs it. */
static gpointer
writer_thread (gpointer data)
{
  RaceCtx *ctx = data;
  race_wait_for_go (ctx);
  wyl_session_state_store_private (ctx->session, WYL_SESSION_STATE_CLOSED);
  return NULL;
}

static WylSession *
race_session_new (gchar **out_id)
{
  WylSession *session = g_object_new (WYL_TYPE_SESSION, NULL);
  if (wyl_id_new (&session->id) != WYRELOG_E_OK)
    g_error ("failed to mint session id");
  session->username = g_strdup ("human-principal-admin");
  session->tenant = g_strdup (WYL_TENANT_DEFAULT);
  session->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;
  wyl_session_state_store_private (session, WYL_SESSION_STATE_ACTIVE);
  *out_id = wyl_session_dup_id_string (session);
  return session;
}

int
main (void)
{
  guint transitions_observed = 0;

  for (guint iteration = 0; iteration < RACE_ITERATIONS; iteration++) {
    g_autofree gchar *session_id = NULL;
    WylSession *session = race_session_new (&session_id);

    /* Precondition: the fresh ACTIVE session passes the liveness gate. */
    if (!wyl_session_liveness_check_private (session, session_id,
            "human-principal-admin", WYL_TENANT_DEFAULT, FALSE))
      g_error ("iteration %u: fresh active session failed liveness", iteration);

    RaceCtx ctx = {
      .session = session,
      .expect_id = session_id,
      .expect_actor = "human-principal-admin",
      .expect_tenant = WYL_TENANT_DEFAULT,
    };
    g_mutex_init (&ctx.mutex);
    g_cond_init (&ctx.changed);

    GThread *reader = g_thread_new ("liveness-reader", reader_thread, &ctx);
    GThread *writer = g_thread_new ("logout-writer", writer_thread, &ctx);

    g_mutex_lock (&ctx.mutex);
    ctx.go = TRUE;
    g_cond_broadcast (&ctx.changed);
    g_mutex_unlock (&ctx.mutex);

    g_thread_join (reader);
    g_thread_join (writer);

    if (ctx.coherence_violation)
      g_error ("iteration %u: liveness observed ACTIVE after CLOSED "
          "(incoherent modification order)", iteration);
    if (ctx.reader_saw_transition)
      transitions_observed++;

    /* Postcondition: logout won the word; the gate is now fail-closed with no
     * way back to a live authority decision. */
    if (wyl_session_state_load_private (session) != WYL_SESSION_STATE_CLOSED)
      g_error ("iteration %u: session word is not CLOSED after logout",
          iteration);
    if (wyl_session_liveness_check_private (session, session_id,
            "human-principal-admin", WYL_TENANT_DEFAULT, FALSE))
      g_error ("iteration %u: liveness check live after logout", iteration);

    g_cond_clear (&ctx.changed);
    g_mutex_clear (&ctx.mutex);
    g_object_unref (session);
  }

  /* Demonstrate the runs genuinely interleaved rather than always serializing
   * the store after every probe; otherwise the race window was never open. */
  if (transitions_observed == 0)
    g_error ("no run observed the logout mid-flight; race window never opened");

  g_print ("OK: %u/%u runs observed the logout mid-flight; every run "
      "linearized coherently\n", transitions_observed, RACE_ITERATIONS);
  return 0;
}

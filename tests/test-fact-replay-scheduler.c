/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>

#include "fact/replay-scheduler-private.h"

typedef struct
{
  GMutex mutex;
  GCond changed;
  GPtrArray *started_labels;
  gboolean release;
} ReplayGate;

typedef struct
{
  ReplayGate *gate;
  const gchar *label;
  gboolean block;
  guint64 rows;
} ReplayCall;

typedef enum
{
  ROUND_ROBIN_NO_BLOCK,
  ROUND_ROBIN_HOLD,
  ROUND_ROBIN_TRIGGER,
} RoundRobinBlock;

typedef struct
{
  GMutex mutex;
  GCond changed;
  GPtrArray *started_labels;
  gboolean release_hold;
  gboolean release_trigger;
} RoundRobinHarness;

typedef struct
{
  RoundRobinHarness *harness;
  const gchar *label;
  RoundRobinBlock block;
} RoundRobinCall;

typedef struct
{
  WylFactReplayScheduler *scheduler;
  wyrelog_error_t shutdown_result;
} ReentrantDestroy;

static WylFactReplaySchedulerConfig test_config (void);

static void
replay_gate_init (ReplayGate *gate)
{
  g_mutex_init (&gate->mutex);
  g_cond_init (&gate->changed);
  gate->started_labels = g_ptr_array_new_with_free_func (g_free);
}

static void
replay_gate_clear (ReplayGate *gate)
{
  g_ptr_array_unref (gate->started_labels);
  g_cond_clear (&gate->changed);
  g_mutex_clear (&gate->mutex);
}

static gboolean
replay_gate_wait_started (ReplayGate *gate, guint count)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&gate->mutex);
  while (gate->started_labels->len < count
      && g_cond_wait_until (&gate->changed, &gate->mutex, deadline))
    ;
  gboolean reached = gate->started_labels->len >= count;
  g_mutex_unlock (&gate->mutex);
  return reached;
}

static void
replay_gate_release (ReplayGate *gate)
{
  g_mutex_lock (&gate->mutex);
  gate->release = TRUE;
  g_cond_broadcast (&gate->changed);
  g_mutex_unlock (&gate->mutex);
}

static gboolean
replay_gate_started (ReplayGate *gate, const gchar *label)
{
  gboolean found = FALSE;
  g_mutex_lock (&gate->mutex);
  for (guint i = 0; i < gate->started_labels->len; i++) {
    if (g_str_equal (g_ptr_array_index (gate->started_labels, i), label)) {
      found = TRUE;
      break;
    }
  }
  g_mutex_unlock (&gate->mutex);
  return found;
}

static wyrelog_error_t
gated_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  ReplayCall *call = user_data;
  GCancellable *cancellable =
      wyl_fact_replay_job_context_get_cancellable (context);
  g_mutex_lock (&call->gate->mutex);
  g_ptr_array_add (call->gate->started_labels, g_strdup (call->label));
  g_cond_broadcast (&call->gate->changed);
  while (call->block && !call->gate->release
      && !g_cancellable_is_cancelled (cancellable)) {
    (void) g_cond_wait_until (&call->gate->changed, &call->gate->mutex,
        g_get_monotonic_time () + 10 * G_TIME_SPAN_MILLISECOND);
  }
  gboolean cancelled = g_cancellable_is_cancelled (cancellable);
  g_mutex_unlock (&call->gate->mutex);
  if (cancelled)
    return WYRELOG_E_CANCELLED;
  wyl_fact_replay_job_context_add_rows (context, call->rows);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
refused_before_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  (void) user_data;
  wyl_fact_replay_job_context_suppress_work_totals (context);
  return WYRELOG_E_POLICY;
}

static void
test_pre_replay_refusal_is_not_completed_or_cancelled (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  g_autoptr (WylFactResourceRecorder) recorder =
      wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant",
      "graph", NULL, refused_before_replay, NULL, NULL, &future), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (future), ==,
      WYRELOG_E_POLICY);
  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.active, ==, 0);
  g_assert_cmpuint (snapshot.completed_total, ==, 0);
  g_assert_cmpuint (snapshot.rows_total, ==, 0);
  g_assert_cmpuint (snapshot.runtime_us_total, ==, 0);
  g_assert_cmpuint (snapshot.cancelled_total, ==, 0);
}

static WylFactReplaySchedulerConfig
test_config (void)
{
  return (WylFactReplaySchedulerConfig) {
           .global_concurrency = 2,
           .tenant_concurrency = 1,
           .global_queue_limit = 8,
           .tenant_queue_limit = 4,
           .row_limit = 100,
           .time_limit_us = 5 * G_TIME_SPAN_SECOND,
  };
}

static gpointer
shutdown_scheduler (gpointer data)
{
  return GINT_TO_POINTER (wyl_fact_replay_scheduler_shutdown (data));
}

static gpointer
churn_scheduler_refs (gpointer data)
{
  WylFactReplayScheduler *scheduler = data;
  for (guint i = 0; i < 10000; i++)
    wyl_fact_replay_scheduler_unref (
      wyl_fact_replay_scheduler_ref (scheduler));
  return NULL;
}

static wyrelog_error_t
counted_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  (void) user_data;
  if (g_cancellable_is_cancelled (
        wyl_fact_replay_job_context_get_cancellable (context)))
    return WYRELOG_E_CANCELLED;
  wyl_fact_replay_job_context_add_rows (context, 1);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
resource_signal_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  WylFactResourceRecorder *recorder = user_data;
  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_replay_job_context_open_begin (context);
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.active_opens, ==, 1);
  wyl_fact_replay_job_context_open_end (context);
  wyl_fact_replay_job_context_record_quota_rejection (context);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
worker_shutdown_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  (void) context;
  WylFactReplayScheduler *scheduler = user_data;
  return wyl_fact_replay_scheduler_shutdown (scheduler) == WYRELOG_E_BUSY
    ? WYRELOG_E_OK
    : WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
round_robin_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  RoundRobinCall *call = user_data;
  GCancellable *cancellable =
      wyl_fact_replay_job_context_get_cancellable (context);
  g_mutex_lock (&call->harness->mutex);
  g_ptr_array_add (call->harness->started_labels, g_strdup (call->label));
  g_cond_broadcast (&call->harness->changed);
  while (!g_cancellable_is_cancelled (cancellable)
      && ((call->block == ROUND_ROBIN_HOLD
      && !call->harness->release_hold)
      || (call->block == ROUND_ROBIN_TRIGGER
      && !call->harness->release_trigger))) {
    (void) g_cond_wait_until (&call->harness->changed,
        &call->harness->mutex,
        g_get_monotonic_time () + 10 * G_TIME_SPAN_MILLISECOND);
  }
  gboolean cancelled = g_cancellable_is_cancelled (cancellable);
  g_mutex_unlock (&call->harness->mutex);
  return cancelled ? WYRELOG_E_CANCELLED : WYRELOG_E_OK;
}

static wyrelog_error_t
saturating_rows_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  (void) user_data;
  wyl_fact_replay_job_context_add_rows (context, G_MAXUINT64);
  wyl_fact_replay_job_context_add_rows (context, 1);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
slow_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  (void) context;
  (void) user_data;
  g_usleep (5 * 1000);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
commit_then_slow_replay (WylFactReplayJobContext *context, gpointer user_data)
{
  (void) user_data;
  wyrelog_error_t rc = wyl_fact_replay_job_context_commit (context);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_usleep (5 * 1000);
  return WYRELOG_E_OK;
}

static void
reentrant_destroy (gpointer user_data)
{
  ReentrantDestroy *destroy = user_data;
  destroy->shutdown_result =
      wyl_fact_replay_scheduler_shutdown (destroy->scheduler);
}

static gboolean
round_robin_wait_started (RoundRobinHarness *harness, guint count)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&harness->mutex);
  while (harness->started_labels->len < count
      && g_cond_wait_until (&harness->changed, &harness->mutex, deadline))
    ;
  gboolean reached = harness->started_labels->len >= count;
  g_mutex_unlock (&harness->mutex);
  return reached;
}

static void
test_tenant_fairness_and_single_flight (void)
{
  ReplayGate gate = { 0 };
  replay_gate_init (&gate);
  WylFactReplaySchedulerConfig config = test_config ();
  g_autoptr (WylFactResourceRecorder) recorder =
      wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);

  ReplayCall a1 = { &gate, "a1", TRUE, 2 };
  ReplayCall a2 = { &gate, "a2", FALSE, 3 };
  ReplayCall b1 = { &gate, "b1", FALSE, 5 };
  g_autoptr (WylFactReplayFuture) a1_future = NULL;
  g_autoptr (WylFactReplayFuture) a2_future = NULL;
  g_autoptr (WylFactReplayFuture) b1_future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g1",
      NULL, gated_replay, &a1, NULL, &a1_future), ==, WYRELOG_E_OK);
  g_assert_true (replay_gate_wait_started (&gate, 1));
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g1",
      NULL, gated_replay, &a2, NULL, &a2_future), ==, WYRELOG_E_BUSY);
  g_assert_null (a2_future);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g2",
      NULL, gated_replay, &a2, NULL, &a2_future), ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) duplicate_queued = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g2",
      NULL, gated_replay, &a2, NULL, &duplicate_queued), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "b", "g1",
      NULL, gated_replay, &b1, NULL, &b1_future), ==, WYRELOG_E_OK);
  g_assert_true (replay_gate_wait_started (&gate, 2));
  g_assert_true (replay_gate_started (&gate, "b1"));
  g_assert_false (replay_gate_started (&gate, "a2"));

  replay_gate_release (&gate);
  g_assert_cmpint (wyl_fact_replay_future_wait (a1_future), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (a2_future), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (b1_future), ==, WYRELOG_E_OK);

  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.active, ==, 0);
  g_assert_cmpuint (snapshot.queued, ==, 0);
  g_assert_cmpuint (snapshot.completed_total, ==, 3);
  g_assert_cmpuint (snapshot.rows_total, ==, 10);
  replay_gate_clear (&gate);
}

static void
test_round_robin_with_continuous_tenant (void)
{
  RoundRobinHarness harness = { 0 };
  g_mutex_init (&harness.mutex);
  g_cond_init (&harness.changed);
  harness.started_labels = g_ptr_array_new_with_free_func (g_free);
  WylFactReplaySchedulerConfig config = test_config ();
  config.global_concurrency = 3;
  config.tenant_concurrency = 2;
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);

  RoundRobinCall calls[] = {
    { &harness, "hold-1", ROUND_ROBIN_HOLD },
    { &harness, "hold-2", ROUND_ROBIN_HOLD },
    { &harness, "trigger", ROUND_ROBIN_TRIGGER },
    { &harness, "a-1", ROUND_ROBIN_NO_BLOCK },
    { &harness, "a-2", ROUND_ROBIN_NO_BLOCK },
    { &harness, "b-1", ROUND_ROBIN_NO_BLOCK },
  };
  WylFactReplayFuture *futures[6] = { NULL };
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "hold", "1",
      NULL, round_robin_replay, &calls[0], NULL, &futures[0]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "hold", "2",
      NULL, round_robin_replay, &calls[1], NULL, &futures[1]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "trigger",
      "1", NULL, round_robin_replay, &calls[2], NULL, &futures[2]), ==,
      WYRELOG_E_OK);
  g_assert_true (round_robin_wait_started (&harness, 3));
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "1",
      NULL, round_robin_replay, &calls[3], NULL, &futures[3]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "2",
      NULL, round_robin_replay, &calls[4], NULL, &futures[4]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "b", "1",
      NULL, round_robin_replay, &calls[5], NULL, &futures[5]), ==,
      WYRELOG_E_OK);
  g_mutex_lock (&harness.mutex);
  harness.release_trigger = TRUE;
  g_cond_broadcast (&harness.changed);
  g_mutex_unlock (&harness.mutex);
  g_assert_true (round_robin_wait_started (&harness, 6));
  g_mutex_lock (&harness.mutex);
  g_assert_cmpstr (g_ptr_array_index (harness.started_labels, 3), ==, "a-1");
  g_assert_cmpstr (g_ptr_array_index (harness.started_labels, 4), ==, "b-1");
  g_assert_cmpstr (g_ptr_array_index (harness.started_labels, 5), ==, "a-2");
  harness.release_hold = TRUE;
  g_cond_broadcast (&harness.changed);
  g_mutex_unlock (&harness.mutex);
  for (guint i = 0; i < G_N_ELEMENTS (futures); i++) {
    g_assert_cmpint (wyl_fact_replay_future_wait (futures[i]), ==,
        WYRELOG_E_OK);
    wyl_fact_replay_future_unref (futures[i]);
  }
  g_ptr_array_unref (harness.started_labels);
  g_cond_clear (&harness.changed);
  g_mutex_clear (&harness.mutex);
}

static void
test_queue_limits_and_shutdown (void)
{
  ReplayGate gate = { 0 };
  replay_gate_init (&gate);
  WylFactReplaySchedulerConfig config = test_config ();
  config.global_queue_limit = 3;
  config.tenant_queue_limit = 2;
  g_autoptr (WylFactResourceRecorder) recorder =
      wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);

  ReplayCall calls[] = {
    { &gate, "a1", TRUE, 0 }, { &gate, "b1", TRUE, 0 },
    { &gate, "a2", FALSE, 0 }, { &gate, "a3", FALSE, 0 },
    { &gate, "c1", FALSE, 0 }, { &gate, "a4", FALSE, 0 },
    { &gate, "d1", FALSE, 0 },
  };
  WylFactReplayFuture *futures[5] = { NULL };
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g1",
      NULL, gated_replay, &calls[0], NULL, &futures[0]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "b", "g1",
      NULL, gated_replay, &calls[1], NULL, &futures[1]), ==,
      WYRELOG_E_OK);
  g_assert_true (replay_gate_wait_started (&gate, 2));
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g2",
      NULL, gated_replay, &calls[2], NULL, &futures[2]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g3",
      NULL, gated_replay, &calls[3], NULL, &futures[3]), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) rejected = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g4",
      NULL, gated_replay, &calls[5], NULL, &rejected), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "c", "g1",
      NULL, gated_replay, &calls[4], NULL, &futures[4]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "d", "g1",
      NULL, gated_replay, &calls[6], NULL, &rejected), ==,
      WYRELOG_E_BUSY);

  g_autoptr (GThread) shutdown_a =
      g_thread_new ("replay-shutdown-a", shutdown_scheduler, scheduler);
  g_autoptr (GThread) shutdown_b =
      g_thread_new ("replay-shutdown-b", shutdown_scheduler, scheduler);
  g_assert_cmpint (GPOINTER_TO_INT (
        g_thread_join (g_steal_pointer (&shutdown_a))), ==, WYRELOG_E_OK);
  g_assert_cmpint (GPOINTER_TO_INT (
        g_thread_join (g_steal_pointer (&shutdown_b))), ==, WYRELOG_E_OK);
  for (guint i = 0; i < G_N_ELEMENTS (futures); i++) {
    g_assert_cmpint (wyl_fact_replay_future_wait (futures[i]), ==,
        WYRELOG_E_CANCELLED);
    wyl_fact_replay_future_unref (futures[i]);
  }
  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.active, ==, 0);
  g_assert_cmpuint (snapshot.queued, ==, 0);
  g_assert_cmpuint (snapshot.completed_total, ==, 2);
  g_assert_cmpuint (snapshot.cancelled_total, ==, 5);
  g_assert_cmpuint (snapshot.queue_rejected_total, ==, 2);
  replay_gate_clear (&gate);
}

static void
test_queued_cancellation (void)
{
  ReplayGate gate = { 0 };
  replay_gate_init (&gate);
  WylFactReplaySchedulerConfig config = test_config ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  ReplayCall active_a = { &gate, "a1", TRUE, 0 };
  ReplayCall active_b = { &gate, "b1", TRUE, 0 };
  ReplayCall queued = { &gate, "a2", FALSE, 0 };
  g_autoptr (WylFactReplayFuture) active_a_future = NULL;
  g_autoptr (WylFactReplayFuture) active_b_future = NULL;
  g_autoptr (WylFactReplayFuture) queued_future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g1",
      NULL, gated_replay, &active_a, NULL, &active_a_future), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "b", "g1",
      NULL, gated_replay, &active_b, NULL, &active_b_future), ==,
      WYRELOG_E_OK);
  g_assert_true (replay_gate_wait_started (&gate, 2));
  g_autoptr (GCancellable) cancel = g_cancellable_new ();
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g2",
      cancel, gated_replay, &queued, NULL, &queued_future), ==,
      WYRELOG_E_OK);
  g_cancellable_cancel (cancel);
  g_assert_cmpint (wyl_fact_replay_future_wait (queued_future), ==,
      WYRELOG_E_CANCELLED);
  g_assert_false (replay_gate_started (&gate, "a2"));
  ReentrantDestroy destroy = { scheduler, WYRELOG_E_INTERNAL };
  g_autoptr (GCancellable) reentrant_cancel = g_cancellable_new ();
  g_autoptr (WylFactReplayFuture) reentrant_future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g3",
      reentrant_cancel, counted_replay, &destroy, reentrant_destroy,
      &reentrant_future), ==, WYRELOG_E_OK);
  g_cancellable_cancel (reentrant_cancel);
  g_assert_cmpint (wyl_fact_replay_future_wait (reentrant_future), ==,
      WYRELOG_E_CANCELLED);
  g_assert_cmpint (destroy.shutdown_result, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (active_a_future), ==,
      WYRELOG_E_CANCELLED);
  g_assert_cmpint (wyl_fact_replay_future_wait (active_b_future), ==,
      WYRELOG_E_CANCELLED);
  replay_gate_clear (&gate);
}

static void
test_shutdown_destroy_reentry_is_busy (void)
{
  ReplayGate gate = { 0 };
  replay_gate_init (&gate);
  WylFactReplaySchedulerConfig config = test_config ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  ReplayCall active_a = { &gate, "a1", TRUE, 0 };
  ReplayCall active_b = { &gate, "b1", TRUE, 0 };
  g_autoptr (WylFactReplayFuture) active_a_future = NULL;
  g_autoptr (WylFactReplayFuture) active_b_future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g1",
      NULL, gated_replay, &active_a, NULL, &active_a_future), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "b", "g1",
      NULL, gated_replay, &active_b, NULL, &active_b_future), ==,
      WYRELOG_E_OK);
  g_assert_true (replay_gate_wait_started (&gate, 2));

  ReentrantDestroy destroy = { scheduler, WYRELOG_E_INTERNAL };
  g_autoptr (WylFactReplayFuture) queued_future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "a", "g2",
      NULL, counted_replay, &destroy, reentrant_destroy, &queued_future), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (destroy.shutdown_result, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_replay_future_wait (queued_future), ==,
      WYRELOG_E_CANCELLED);
  g_assert_cmpint (wyl_fact_replay_future_wait (active_a_future), ==,
      WYRELOG_E_CANCELLED);
  g_assert_cmpint (wyl_fact_replay_future_wait (active_b_future), ==,
      WYRELOG_E_CANCELLED);
  replay_gate_clear (&gate);
}

static void
test_final_worker_unref_is_deferred (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  WylFactReplayScheduler *scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant",
      "graph", NULL, counted_replay,
      wyl_fact_replay_scheduler_ref (scheduler),
      (GDestroyNotify) wyl_fact_replay_scheduler_unref, &future), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_scheduler_unref (scheduler);
  g_assert_cmpint (wyl_fact_replay_future_wait (future), ==, WYRELOG_E_OK);
}

static void
test_detached_future_and_ref_lifetimes (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  config.global_concurrency = 4;
  config.global_queue_limit = 256;
  config.tenant_queue_limit = 128;
  WylFactResourceRecorder *recorder = wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);
  wyl_fact_resource_recorder_unref (recorder);

  g_autoptr (GThread) ref_a =
      g_thread_new ("replay-ref-a", churn_scheduler_refs, scheduler);
  g_autoptr (GThread) ref_b =
      g_thread_new ("replay-ref-b", churn_scheduler_refs, scheduler);
  for (guint i = 0; i < 200; i++) {
    g_autofree gchar *tenant = g_strdup_printf ("tenant-%u", i % 2);
    g_autofree gchar *graph = g_strdup_printf ("graph-%u", i);
    WylFactReplayFuture *future = NULL;
    g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, tenant,
        graph, NULL, counted_replay, NULL, NULL, &future), ==,
        WYRELOG_E_OK);
    wyl_fact_replay_future_unref (future);
  }
  g_thread_join (g_steal_pointer (&ref_a));
  g_thread_join (g_steal_pointer (&ref_b));
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
}

static void
test_worker_shutdown_is_busy (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant",
      "graph", NULL, worker_shutdown_replay, scheduler, NULL, &future),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (future), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
}

static void
test_row_counter_saturates (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  g_autoptr (WylFactResourceRecorder) recorder =
      wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant",
      "graph", NULL, saturating_rows_replay, NULL, NULL, &future), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (future), ==,
      WYRELOG_E_RESOURCE_LIMIT);
  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.rows_total, ==, G_MAXUINT64);
  g_assert_cmpuint (snapshot.row_limit_total, ==, 1);
}

static void
test_deadline_is_enforced (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  config.time_limit_us = G_TIME_SPAN_MILLISECOND;
  g_autoptr (WylFactResourceRecorder) recorder =
      wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant",
      "graph", NULL, slow_replay, NULL, NULL, &future), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (future), ==,
      WYRELOG_E_TIMED_OUT);
  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.timed_out_total, ==, 1);
}

static void
test_commit_closes_deadline (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  config.time_limit_us = G_TIME_SPAN_MILLISECOND;
  g_autoptr (WylFactResourceRecorder) recorder =
      wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant",
      "graph", NULL, commit_then_slow_replay, NULL, NULL, &future), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (future), ==, WYRELOG_E_OK);
  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.timed_out_total, ==, 0);
}

static void
test_resource_signals (void)
{
  WylFactReplaySchedulerConfig config = test_config ();
  g_autoptr (WylFactResourceRecorder) recorder =
      wyl_fact_resource_recorder_new ();
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, recorder,
      &scheduler), ==, WYRELOG_E_OK);
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant",
      "graph", NULL, resource_signal_replay, recorder, NULL, &future), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_future_wait (future), ==, WYRELOG_E_OK);
  WylFactReplayResourceSnapshot snapshot;
  wyl_fact_resource_recorder_snapshot (recorder, &snapshot);
  g_assert_cmpuint (snapshot.active_opens, ==, 0);
  g_assert_cmpuint (snapshot.quota_rejected_total, ==, 1);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-replay-scheduler/fairness-single-flight",
      test_tenant_fairness_and_single_flight);
  g_test_add_func ("/fact-replay-scheduler/round-robin-continuous-tenant",
      test_round_robin_with_continuous_tenant);
  g_test_add_func ("/fact-replay-scheduler/queue-limits-shutdown",
      test_queue_limits_and_shutdown);
  g_test_add_func ("/fact-replay-scheduler/queued-cancellation",
      test_queued_cancellation);
  g_test_add_func ("/fact-replay-scheduler/shutdown-destroy-reentry",
      test_shutdown_destroy_reentry_is_busy);
  g_test_add_func ("/fact-replay-scheduler/final-worker-unref",
      test_final_worker_unref_is_deferred);
  g_test_add_func ("/fact-replay-scheduler/detached-ref-lifetimes",
      test_detached_future_and_ref_lifetimes);
  g_test_add_func ("/fact-replay-scheduler/worker-shutdown-busy",
      test_worker_shutdown_is_busy);
  g_test_add_func ("/fact-replay-scheduler/row-counter-saturates",
      test_row_counter_saturates);
  g_test_add_func ("/fact-replay-scheduler/deadline-enforced",
      test_deadline_is_enforced);
  g_test_add_func ("/fact-replay-scheduler/commit-closes-deadline",
      test_commit_closes_deadline);
  g_test_add_func ("/fact-replay-scheduler/resource-signals",
      test_resource_signals);
  g_test_add_func ("/fact-replay-scheduler/pre-replay-refusal-metrics",
      test_pre_replay_refusal_is_not_completed_or_cancelled);
  return wyl_test_normalize_exit_status (g_test_run ());
}

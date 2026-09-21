/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/replay-scheduler-private.h"

#include <string.h>

typedef enum
{
  REPLAY_JOB_NEW,
  REPLAY_JOB_QUEUED,
  REPLAY_JOB_ACTIVE,
  REPLAY_JOB_GARBAGE,
  REPLAY_JOB_DONE,
} ReplayJobState;

typedef enum
{
  REPLAY_OUTCOME_OPEN,
  REPLAY_OUTCOME_COMMITTED,
  REPLAY_OUTCOME_CANCELLED,
  REPLAY_OUTCOME_TIMED_OUT,
  REPLAY_OUTCOME_RESOURCE_LIMIT,
} ReplayOutcome;

typedef struct _ReplayTenantQueue ReplayTenantQueue;
typedef struct _ReplayJob ReplayJob;

struct _WylFactResourceRecorder
{
  gatomicrefcount refs;
  GMutex mutex;
  WylFactReplayResourceSnapshot values;
};

struct _WylFactReplayFuture
{
  gatomicrefcount refs;
  GMutex mutex;
  GCond changed;
  gboolean done;
  wyrelog_error_t result;
};

struct _ReplayTenantQueue
{
  gchar *tenant_id;
  GQueue jobs;
  guint active;
  guint pending;
  gboolean ready;
};

struct _ReplayJob
{
  WylFactReplayScheduler *scheduler;
  ReplayTenantQueue *tenant;
  gchar *graph_id;
  gchar *graph_key;
  WylFactReplayJobFunc function;
  gpointer user_data;
  GDestroyNotify user_data_destroy;
  GCancellable *caller_cancellable;
  GCancellable *work_cancellable;
  gulong cancel_handler;
  WylFactReplayFuture *future;
  ReplayJobState state;
  gint outcome;
  gboolean cancel_requested;
  gint64 queued_at_us;
};

typedef struct
{
  ReplayJob *job;
  GMutex mutex;
  GCond changed;
  gint64 deadline_us;
  gboolean done;
} ReplayWatchdog;

struct _WylFactReplayJobContext
{
  ReplayJob *job;
  gint64 deadline_us;
  guint64 row_limit;
  guint64 rows;
};

struct _WylFactReplayScheduler
{
  gatomicrefcount refs;
  GMutex mutex;
  GCond changed;
  GCond reaper_changed;
  WylFactReplaySchedulerConfig config;
  WylFactResourceRecorder *recorder;
  GHashTable *tenants;
  GHashTable *graphs;
  GHashTable *active_jobs;
  GQueue ready_tenants;
  GQueue garbage;
  GPtrArray *workers;
  GThread *reaper;
  guint active;
  guint pending;
  gboolean shutting_down;
  gboolean shutdown_complete;
  GThread *shutdown_owner;
};

static guint64
saturating_add (guint64 left, guint64 right)
{
  return G_MAXUINT64 - left < right ? G_MAXUINT64 : left + right;
}

static void
recorder_adjust_gauge (WylFactResourceRecorder *recorder, guint64 *gauge,
    gboolean increment)
{
  if (recorder == NULL)
    return;
  g_mutex_lock (&recorder->mutex);
  if (increment)
    *gauge = saturating_add (*gauge, 1);
  else if (*gauge > 0)
    (*gauge)--;
  g_mutex_unlock (&recorder->mutex);
}

static void
recorder_add (WylFactResourceRecorder *recorder, guint64 *counter,
    guint64 value)
{
  if (recorder == NULL)
    return;
  g_mutex_lock (&recorder->mutex);
  *counter = saturating_add (*counter, value);
  g_mutex_unlock (&recorder->mutex);
}

static void
recorder_queued_to_active (WylFactResourceRecorder *recorder,
    guint64 queue_delay_us)
{
  g_mutex_lock (&recorder->mutex);
  if (recorder->values.queued > 0)
    recorder->values.queued--;
  recorder->values.active = saturating_add (recorder->values.active, 1);
  recorder->values.queue_delay_us_total = saturating_add
        (recorder->values.queue_delay_us_total, queue_delay_us);
  recorder->values.queue_delay_us_max = MAX
        (recorder->values.queue_delay_us_max, queue_delay_us);
  g_mutex_unlock (&recorder->mutex);
}

static void
recorder_complete_active (WylFactResourceRecorder *recorder,
    wyrelog_error_t result, guint64 rows, guint64 runtime_us)
{
  g_mutex_lock (&recorder->mutex);
  if (recorder->values.active > 0)
    recorder->values.active--;
  recorder->values.completed_total = saturating_add
        (recorder->values.completed_total, 1);
  recorder->values.rows_total = saturating_add
        (recorder->values.rows_total, rows);
  recorder->values.runtime_us_total = saturating_add
        (recorder->values.runtime_us_total, runtime_us);
  if (result == WYRELOG_E_CANCELLED)
    recorder->values.cancelled_total = saturating_add
          (recorder->values.cancelled_total, 1);
  else if (result == WYRELOG_E_TIMED_OUT)
    recorder->values.timed_out_total = saturating_add
          (recorder->values.timed_out_total, 1);
  else if (result == WYRELOG_E_RESOURCE_LIMIT)
    recorder->values.row_limit_total = saturating_add
          (recorder->values.row_limit_total, 1);
  g_mutex_unlock (&recorder->mutex);
}

static void
recorder_cancel_queued (WylFactResourceRecorder *recorder)
{
  g_mutex_lock (&recorder->mutex);
  if (recorder->values.queued > 0)
    recorder->values.queued--;
  recorder->values.cancelled_total = saturating_add
        (recorder->values.cancelled_total, 1);
  g_mutex_unlock (&recorder->mutex);
}

WylFactResourceRecorder *
wyl_fact_resource_recorder_new (void)
{
  WylFactResourceRecorder *recorder = g_new0 (WylFactResourceRecorder, 1);
  g_atomic_ref_count_init (&recorder->refs);
  g_mutex_init (&recorder->mutex);
  return recorder;
}

WylFactResourceRecorder *
wyl_fact_resource_recorder_ref (WylFactResourceRecorder *recorder)
{
  if (recorder != NULL)
    g_atomic_ref_count_inc (&recorder->refs);
  return recorder;
}

void
wyl_fact_resource_recorder_unref (WylFactResourceRecorder *recorder)
{
  if (recorder == NULL || !g_atomic_ref_count_dec (&recorder->refs))
    return;
  g_mutex_clear (&recorder->mutex);
  g_free (recorder);
}

void
wyl_fact_resource_recorder_snapshot (WylFactResourceRecorder *recorder,
    WylFactReplayResourceSnapshot *out_snapshot)
{
  if (out_snapshot == NULL)
    return;
  memset (out_snapshot, 0, sizeof (*out_snapshot));
  if (recorder == NULL)
    return;
  g_mutex_lock (&recorder->mutex);
  *out_snapshot = recorder->values;
  g_mutex_unlock (&recorder->mutex);
}

static WylFactReplayFuture *
replay_future_new (void)
{
  WylFactReplayFuture *future = g_new0 (WylFactReplayFuture, 1);
  g_atomic_ref_count_init (&future->refs);
  g_mutex_init (&future->mutex);
  g_cond_init (&future->changed);
  return future;
}

WylFactReplayFuture *
wyl_fact_replay_future_ref (WylFactReplayFuture *future)
{
  if (future != NULL)
    g_atomic_ref_count_inc (&future->refs);
  return future;
}

void
wyl_fact_replay_future_unref (WylFactReplayFuture *future)
{
  if (future == NULL || !g_atomic_ref_count_dec (&future->refs))
    return;
  g_cond_clear (&future->changed);
  g_mutex_clear (&future->mutex);
  g_free (future);
}

static void
replay_future_complete (WylFactReplayFuture *future, wyrelog_error_t result)
{
  g_mutex_lock (&future->mutex);
  if (!future->done) {
    future->result = result;
    future->done = TRUE;
    g_cond_broadcast (&future->changed);
  }
  g_mutex_unlock (&future->mutex);
}

wyrelog_error_t
wyl_fact_replay_future_wait (WylFactReplayFuture *future)
{
  if (future == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&future->mutex);
  while (!future->done)
    g_cond_wait (&future->changed, &future->mutex);
  wyrelog_error_t result = future->result;
  g_mutex_unlock (&future->mutex);
  return result;
}

static void
tenant_queue_free (gpointer data)
{
  ReplayTenantQueue *tenant = data;
  g_assert_true (g_queue_is_empty (&tenant->jobs));
  g_free (tenant->tenant_id);
  g_free (tenant);
}

static void
replay_job_destroy_user_data (ReplayJob *job)
{
  if (job->user_data_destroy != NULL) {
    job->user_data_destroy (job->user_data);
    job->user_data_destroy = NULL;
    job->user_data = NULL;
  }
}

static void
replay_job_free (ReplayJob *job)
{
  if (job->cancel_handler != 0)
    g_cancellable_disconnect (job->caller_cancellable, job->cancel_handler);
  replay_job_destroy_user_data (job);
  g_clear_object (&job->caller_cancellable);
  g_clear_object (&job->work_cancellable);
  wyl_fact_replay_future_unref (job->future);
  g_free (job->graph_id);
  g_free (job->graph_key);
  g_free (job);
}

static gchar *
graph_key_new (const gchar *tenant_id, const gchar *graph_id)
{
  return g_strdup_printf ("%" G_GSIZE_FORMAT ":%s%s", strlen (tenant_id),
             tenant_id, graph_id);
}

static void
tenant_mark_ready_locked (WylFactReplayScheduler *scheduler,
    ReplayTenantQueue *tenant)
{
  if (!tenant->ready && tenant->active < scheduler->config.tenant_concurrency
      && !g_queue_is_empty (&tenant->jobs)) {
    tenant->ready = TRUE;
    g_queue_push_tail (&scheduler->ready_tenants, tenant);
  }
}

static void
replay_job_cancelled (GCancellable *cancellable, gpointer user_data)
{
  (void) cancellable;
  ReplayJob *job = user_data;
  WylFactReplayScheduler *scheduler = job->scheduler;
  if (g_atomic_int_compare_and_exchange (&job->outcome,
      REPLAY_OUTCOME_OPEN, REPLAY_OUTCOME_CANCELLED))
    g_cancellable_cancel (job->work_cancellable);

  g_mutex_lock (&scheduler->mutex);
  if (job->state == REPLAY_JOB_NEW) {
    job->cancel_requested = TRUE;
  } else if (job->state == REPLAY_JOB_QUEUED) {
    g_assert_true (g_queue_remove (&job->tenant->jobs, job));
    job->tenant->pending--;
    scheduler->pending--;
    g_hash_table_remove (scheduler->graphs, job->graph_key);
    job->state = REPLAY_JOB_GARBAGE;
    g_queue_push_tail (&scheduler->garbage, job);
    g_cond_signal (&scheduler->reaper_changed);
  }
  g_mutex_unlock (&scheduler->mutex);
}

static gpointer
replay_watchdog (gpointer data)
{
  ReplayWatchdog *watchdog = data;
  gboolean timed_out = FALSE;
  g_mutex_lock (&watchdog->mutex);
  while (!watchdog->done
      && g_cond_wait_until (&watchdog->changed, &watchdog->mutex,
      watchdog->deadline_us))
    ;
  if (!watchdog->done)
    timed_out = g_atomic_int_compare_and_exchange (&watchdog->job->outcome,
            REPLAY_OUTCOME_OPEN, REPLAY_OUTCOME_TIMED_OUT);
  g_mutex_unlock (&watchdog->mutex);
  if (timed_out)
    g_cancellable_cancel (watchdog->job->work_cancellable);
  return NULL;
}

static ReplayJob *
scheduler_take_job_locked (WylFactReplayScheduler *scheduler)
{
  while (!g_queue_is_empty (&scheduler->ready_tenants)) {
    ReplayTenantQueue *tenant = g_queue_pop_head (&scheduler->ready_tenants);
    tenant->ready = FALSE;
    if (tenant->active >= scheduler->config.tenant_concurrency
        || g_queue_is_empty (&tenant->jobs))
      continue;
    ReplayJob *job = g_queue_pop_head (&tenant->jobs);
    g_assert_cmpint (job->state, ==, REPLAY_JOB_QUEUED);
    tenant->pending--;
    scheduler->pending--;
    tenant->active++;
    scheduler->active++;
    job->state = REPLAY_JOB_ACTIVE;
    g_hash_table_add (scheduler->active_jobs, job);
    tenant_mark_ready_locked (scheduler, tenant);
    return job;
  }
  return NULL;
}

static gpointer
replay_worker (gpointer data)
{
  WylFactReplayScheduler *scheduler = data;
  for (;;) {
    ReplayJob *job = NULL;
    g_mutex_lock (&scheduler->mutex);
    for (;;) {
      job = scheduler_take_job_locked (scheduler);
      if (job != NULL || scheduler->shutting_down)
        break;
      g_cond_wait (&scheduler->changed, &scheduler->mutex);
    }
    g_mutex_unlock (&scheduler->mutex);

    if (job == NULL)
      break;

    gint64 started_at_us = g_get_monotonic_time ();
    guint64 queue_delay_us = (guint64) MAX (0,
            started_at_us - job->queued_at_us);
    recorder_queued_to_active (scheduler->recorder, queue_delay_us);

    WylFactReplayJobContext context = {
      .job = job,
      .deadline_us = scheduler->config.time_limit_us
          > G_MAXINT64 - started_at_us
          ? G_MAXINT64
          : started_at_us + scheduler->config.time_limit_us,
      .row_limit = scheduler->config.row_limit,
    };
    ReplayWatchdog watchdog = {
      .job = job,
      .deadline_us = context.deadline_us,
    };
    g_mutex_init (&watchdog.mutex);
    g_cond_init (&watchdog.changed);
    GThread *watchdog_thread = g_thread_new ("fact-replay-watchdog",
            replay_watchdog, &watchdog);
    wyrelog_error_t result = job->function (&context, job->user_data);
    g_mutex_lock (&watchdog.mutex);
    watchdog.done = TRUE;
    g_cond_signal (&watchdog.changed);
    g_mutex_unlock (&watchdog.mutex);
    g_thread_join (watchdog_thread);
    g_cond_clear (&watchdog.changed);
    g_mutex_clear (&watchdog.mutex);
    if (result == WYRELOG_E_OK)
      result = wyl_fact_replay_job_context_checkpoint (&context);
    gint64 runtime_us = MAX (0, g_get_monotonic_time () - started_at_us);

    g_mutex_lock (&scheduler->mutex);
    g_assert_true (g_hash_table_remove (scheduler->active_jobs, job));
    g_hash_table_remove (scheduler->graphs, job->graph_key);
    job->tenant->active--;
    scheduler->active--;
    job->state = REPLAY_JOB_DONE;
    tenant_mark_ready_locked (scheduler, job->tenant);
    g_cond_broadcast (&scheduler->changed);
    g_mutex_unlock (&scheduler->mutex);

    recorder_complete_active (scheduler->recorder, result, context.rows,
        (guint64) runtime_us);
    replay_job_destroy_user_data (job);
    replay_future_complete (job->future, result);
    replay_job_free (job);
  }
  return NULL;
}

static gpointer
replay_reaper (gpointer data)
{
  WylFactReplayScheduler *scheduler = data;
  for (;;) {
    g_mutex_lock (&scheduler->mutex);
    while (g_queue_is_empty (&scheduler->garbage)
        && !scheduler->shutting_down)
      g_cond_wait (&scheduler->reaper_changed, &scheduler->mutex);
    ReplayJob *job = g_queue_pop_head (&scheduler->garbage);
    gboolean stop = job == NULL && scheduler->shutting_down;
    g_mutex_unlock (&scheduler->mutex);
    if (stop)
      break;
    recorder_cancel_queued (scheduler->recorder);
    replay_job_destroy_user_data (job);
    replay_future_complete (job->future, WYRELOG_E_CANCELLED);
    replay_job_free (job);
  }
  return NULL;
}

wyrelog_error_t
wyl_fact_replay_scheduler_new (const WylFactReplaySchedulerConfig *config,
    WylFactResourceRecorder *recorder,
    WylFactReplayScheduler **out_scheduler)
{
  if (out_scheduler == NULL)
    return WYRELOG_E_INVALID;
  *out_scheduler = NULL;
  if (wyl_fact_replay_scheduler_config_validate (config) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  WylFactReplayScheduler *scheduler = g_new0 (WylFactReplayScheduler, 1);
  g_atomic_ref_count_init (&scheduler->refs);
  g_mutex_init (&scheduler->mutex);
  g_cond_init (&scheduler->changed);
  g_cond_init (&scheduler->reaper_changed);
  scheduler->config = *config;
  scheduler->recorder = recorder != NULL
    ? wyl_fact_resource_recorder_ref (recorder)
    : wyl_fact_resource_recorder_new ();
  scheduler->tenants = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
          tenant_queue_free);
  scheduler->graphs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
          NULL);
  scheduler->active_jobs = g_hash_table_new (g_direct_hash, g_direct_equal);
  scheduler->workers = g_ptr_array_new ();
  for (guint i = 0; i < config->global_concurrency; i++)
    g_ptr_array_add (scheduler->workers,
        g_thread_new ("fact-replay", replay_worker, scheduler));
  scheduler->reaper = g_thread_new ("fact-replay-reaper", replay_reaper,
          scheduler);
  *out_scheduler = scheduler;
  return WYRELOG_E_OK;
}

WylFactReplayScheduler *
wyl_fact_replay_scheduler_ref (WylFactReplayScheduler *scheduler)
{
  if (scheduler != NULL)
    g_atomic_ref_count_inc (&scheduler->refs);
  return scheduler;
}

static gboolean
scheduler_is_worker (WylFactReplayScheduler *scheduler)
{
  GThread *current = g_thread_self ();
  for (guint i = 0; i < scheduler->workers->len; i++) {
    if (g_ptr_array_index (scheduler->workers, i) == current)
      return TRUE;
  }
  return scheduler->reaper == current;
}

wyrelog_error_t
wyl_fact_replay_scheduler_shutdown (WylFactReplayScheduler *scheduler)
{
  if (scheduler == NULL)
    return WYRELOG_E_INVALID;
  if (scheduler_is_worker (scheduler))
    return WYRELOG_E_BUSY;

  g_autoptr (GPtrArray) cancelled = g_ptr_array_new ();
  g_autoptr (GPtrArray) active_cancellables =
      g_ptr_array_new_with_free_func (g_object_unref);
  g_mutex_lock (&scheduler->mutex);
  if (scheduler->shutting_down) {
    if (scheduler->shutdown_owner == g_thread_self ()) {
      g_mutex_unlock (&scheduler->mutex);
      return WYRELOG_E_BUSY;
    }
    while (!scheduler->shutdown_complete)
      g_cond_wait (&scheduler->changed, &scheduler->mutex);
    g_mutex_unlock (&scheduler->mutex);
    return WYRELOG_E_OK;
  }
  scheduler->shutting_down = TRUE;
  scheduler->shutdown_owner = g_thread_self ();
  GHashTableIter tenant_iter;
  gpointer value = NULL;
  g_hash_table_iter_init (&tenant_iter, scheduler->tenants);
  while (g_hash_table_iter_next (&tenant_iter, NULL, &value)) {
    ReplayTenantQueue *tenant = value;
    ReplayJob *job = NULL;
    while ((job = g_queue_pop_head (&tenant->jobs)) != NULL) {
      tenant->pending--;
      scheduler->pending--;
      g_hash_table_remove (scheduler->graphs, job->graph_key);
      job->state = REPLAY_JOB_GARBAGE;
      g_ptr_array_add (cancelled, job);
    }
    tenant->ready = FALSE;
  }
  g_queue_clear (&scheduler->ready_tenants);

  GHashTableIter active_iter;
  gpointer active_job = NULL;
  g_hash_table_iter_init (&active_iter, scheduler->active_jobs);
  while (g_hash_table_iter_next (&active_iter, &active_job, NULL)) {
    ReplayJob *job = active_job;
    if (g_atomic_int_compare_and_exchange (&job->outcome,
        REPLAY_OUTCOME_OPEN, REPLAY_OUTCOME_CANCELLED))
      g_ptr_array_add (active_cancellables,
          g_object_ref (job->work_cancellable));
  }
  g_cond_broadcast (&scheduler->changed);
  g_cond_broadcast (&scheduler->reaper_changed);
  g_mutex_unlock (&scheduler->mutex);

  for (guint i = 0; i < cancelled->len; i++) {
    ReplayJob *job = g_ptr_array_index (cancelled, i);
    recorder_cancel_queued (scheduler->recorder);
    replay_job_destroy_user_data (job);
    replay_future_complete (job->future, WYRELOG_E_CANCELLED);
    replay_job_free (job);
  }
  for (guint i = 0; i < active_cancellables->len; i++)
    g_cancellable_cancel (g_ptr_array_index (active_cancellables, i));

  for (guint i = 0; i < scheduler->workers->len; i++)
    g_thread_join (g_ptr_array_index (scheduler->workers, i));
  g_thread_join (scheduler->reaper);
  g_mutex_lock (&scheduler->mutex);
  scheduler->shutdown_complete = TRUE;
  scheduler->shutdown_owner = NULL;
  g_cond_broadcast (&scheduler->changed);
  g_mutex_unlock (&scheduler->mutex);
  return WYRELOG_E_OK;
}

static gpointer
replay_scheduler_destroy (gpointer data)
{
  WylFactReplayScheduler *scheduler = data;
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  g_assert_true (g_queue_is_empty (&scheduler->garbage));
  g_assert_cmpuint (scheduler->active, ==, 0);
  g_assert_cmpuint (scheduler->pending, ==, 0);
  g_hash_table_unref (scheduler->active_jobs);
  g_hash_table_unref (scheduler->graphs);
  g_hash_table_unref (scheduler->tenants);
  g_ptr_array_unref (scheduler->workers);
  wyl_fact_resource_recorder_unref (scheduler->recorder);
  g_cond_clear (&scheduler->changed);
  g_cond_clear (&scheduler->reaper_changed);
  g_mutex_clear (&scheduler->mutex);
  g_free (scheduler);
  return NULL;
}

void
wyl_fact_replay_scheduler_unref (WylFactReplayScheduler *scheduler)
{
  if (scheduler == NULL || !g_atomic_ref_count_dec (&scheduler->refs))
    return;
  if (scheduler_is_worker (scheduler)) {
    GThread *destroyer = g_thread_new ("fact-replay-destroy",
            replay_scheduler_destroy, scheduler);
    g_thread_unref (destroyer);
    return;
  }
  replay_scheduler_destroy (scheduler);
}

wyrelog_error_t
wyl_fact_replay_scheduler_submit (WylFactReplayScheduler *scheduler,
    const gchar *tenant_id, const gchar *graph_id, GCancellable *cancellable,
    WylFactReplayJobFunc function, gpointer user_data,
    GDestroyNotify user_data_destroy, WylFactReplayFuture **out_future)
{
  if (out_future == NULL)
    return WYRELOG_E_INVALID;
  *out_future = NULL;
  if (scheduler == NULL || tenant_id == NULL || tenant_id[0] == '\0'
      || graph_id == NULL || graph_id[0] == '\0' || function == NULL)
    return WYRELOG_E_INVALID;

  ReplayJob *job = g_new0 (ReplayJob, 1);
  job->scheduler = scheduler;
  job->graph_id = g_strdup (graph_id);
  job->graph_key = graph_key_new (tenant_id, graph_id);
  job->function = function;
  job->user_data = user_data;
  job->user_data_destroy = user_data_destroy;
  job->caller_cancellable = cancellable != NULL ? g_object_ref (cancellable)
                                                 : g_cancellable_new ();
  job->work_cancellable = g_cancellable_new ();
  job->future = replay_future_new ();
  job->state = REPLAY_JOB_NEW;
  job->cancel_handler = g_cancellable_connect (job->caller_cancellable,
          G_CALLBACK (replay_job_cancelled), job, NULL);

  g_mutex_lock (&scheduler->mutex);
  if (job->cancel_requested
      || g_cancellable_is_cancelled (job->caller_cancellable)) {
    job->state = REPLAY_JOB_DONE;
    g_mutex_unlock (&scheduler->mutex);
    *out_future = wyl_fact_replay_future_ref (job->future);
    recorder_add (scheduler->recorder,
        &scheduler->recorder->values.cancelled_total, 1);
    replay_job_destroy_user_data (job);
    replay_future_complete (job->future, WYRELOG_E_CANCELLED);
    replay_job_free (job);
    return WYRELOG_E_OK;
  }
  if (scheduler->shutting_down
      || g_hash_table_contains (scheduler->graphs, job->graph_key)) {
    g_mutex_unlock (&scheduler->mutex);
    replay_job_free (job);
    return WYRELOG_E_BUSY;
  }

  ReplayTenantQueue *tenant = g_hash_table_lookup (scheduler->tenants,
          tenant_id);
  if (tenant == NULL) {
    tenant = g_new0 (ReplayTenantQueue, 1);
    tenant->tenant_id = g_strdup (tenant_id);
    g_hash_table_insert (scheduler->tenants, g_strdup (tenant_id), tenant);
  }
  if (scheduler->pending >= scheduler->config.global_queue_limit
      || tenant->pending >= scheduler->config.tenant_queue_limit) {
    g_mutex_unlock (&scheduler->mutex);
    recorder_add (scheduler->recorder,
        &scheduler->recorder->values.queue_rejected_total, 1);
    replay_job_free (job);
    return WYRELOG_E_BUSY;
  }

  job->tenant = tenant;
  job->queued_at_us = g_get_monotonic_time ();
  tenant->pending++;
  scheduler->pending++;
  g_hash_table_add (scheduler->graphs, g_strdup (job->graph_key));
  recorder_adjust_gauge (scheduler->recorder,
      &scheduler->recorder->values.queued, TRUE);
  job->state = REPLAY_JOB_QUEUED;
  g_queue_push_tail (&tenant->jobs, job);
  tenant_mark_ready_locked (scheduler, tenant);
  *out_future = wyl_fact_replay_future_ref (job->future);
  g_cond_signal (&scheduler->changed);
  g_mutex_unlock (&scheduler->mutex);
  return WYRELOG_E_OK;
}

GCancellable *
wyl_fact_replay_job_context_get_cancellable (WylFactReplayJobContext *context)
{
  return context != NULL ? context->job->work_cancellable : NULL;
}

gint64
wyl_fact_replay_job_context_get_deadline_us (WylFactReplayJobContext *context)
{
  return context != NULL ? context->deadline_us : 0;
}

guint64
wyl_fact_replay_job_context_get_row_limit (WylFactReplayJobContext *context)
{
  return context != NULL ? context->row_limit : 0;
}

void
wyl_fact_replay_job_context_add_rows (WylFactReplayJobContext *context,
    guint64 rows)
{
  if (context != NULL)
    context->rows = saturating_add (context->rows, rows);
}

wyrelog_error_t
wyl_fact_replay_job_context_checkpoint (WylFactReplayJobContext *context)
{
  if (context == NULL)
    return WYRELOG_E_INVALID;
  gint outcome = g_atomic_int_get (&context->job->outcome);
  if (outcome == REPLAY_OUTCOME_COMMITTED)
    return WYRELOG_E_OK;
  if (outcome == REPLAY_OUTCOME_TIMED_OUT)
    return WYRELOG_E_TIMED_OUT;
  if (outcome == REPLAY_OUTCOME_RESOURCE_LIMIT)
    return WYRELOG_E_RESOURCE_LIMIT;
  if (outcome == REPLAY_OUTCOME_CANCELLED
      || g_cancellable_is_cancelled (context->job->work_cancellable))
    return WYRELOG_E_CANCELLED;
  if (g_get_monotonic_time () >= context->deadline_us) {
    if (g_atomic_int_compare_and_exchange (&context->job->outcome,
        REPLAY_OUTCOME_OPEN, REPLAY_OUTCOME_TIMED_OUT))
      g_cancellable_cancel (context->job->work_cancellable);
    outcome = g_atomic_int_get (&context->job->outcome);
    if (outcome == REPLAY_OUTCOME_COMMITTED)
      return WYRELOG_E_OK;
    if (outcome == REPLAY_OUTCOME_CANCELLED)
      return WYRELOG_E_CANCELLED;
    return WYRELOG_E_TIMED_OUT;
  }
  if (context->rows > context->row_limit)
    return WYRELOG_E_RESOURCE_LIMIT;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_replay_job_context_charge_rows (WylFactReplayJobContext *context,
    guint64 rows)
{
  if (context == NULL)
    return WYRELOG_E_INVALID;
  context->rows = saturating_add (context->rows, rows);
  if (context->rows > context->row_limit)
    g_atomic_int_compare_and_exchange (&context->job->outcome,
        REPLAY_OUTCOME_OPEN, REPLAY_OUTCOME_RESOURCE_LIMIT);
  return wyl_fact_replay_job_context_checkpoint (context);
}

wyrelog_error_t
wyl_fact_replay_job_context_commit (WylFactReplayJobContext *context)
{
  if (context == NULL)
    return WYRELOG_E_INVALID;
  if (g_get_monotonic_time () >= context->deadline_us)
    g_atomic_int_compare_and_exchange (&context->job->outcome,
        REPLAY_OUTCOME_OPEN, REPLAY_OUTCOME_TIMED_OUT);
  g_atomic_int_compare_and_exchange (&context->job->outcome,
      REPLAY_OUTCOME_OPEN, REPLAY_OUTCOME_COMMITTED);
  switch (g_atomic_int_get (&context->job->outcome)) {
    case REPLAY_OUTCOME_COMMITTED:
      return WYRELOG_E_OK;
    case REPLAY_OUTCOME_CANCELLED:
      return WYRELOG_E_CANCELLED;
    case REPLAY_OUTCOME_TIMED_OUT:
      return WYRELOG_E_TIMED_OUT;
    case REPLAY_OUTCOME_RESOURCE_LIMIT:
      return WYRELOG_E_RESOURCE_LIMIT;
    case REPLAY_OUTCOME_OPEN:
    default:
      return WYRELOG_E_INTERNAL;
  }
}

void
wyl_fact_replay_scheduler_config_defaults
  (WylFactReplaySchedulerConfig *out_config)
{
  if (out_config == NULL)
    return;
  *out_config = (WylFactReplaySchedulerConfig) {
    .global_concurrency = WYL_FACT_REPLAY_DEFAULT_GLOBAL_CONCURRENCY,
    .tenant_concurrency = WYL_FACT_REPLAY_DEFAULT_TENANT_CONCURRENCY,
    .global_queue_limit = WYL_FACT_REPLAY_DEFAULT_GLOBAL_QUEUE_LIMIT,
    .tenant_queue_limit = WYL_FACT_REPLAY_DEFAULT_TENANT_QUEUE_LIMIT,
    .row_limit = WYL_FACT_REPLAY_DEFAULT_ROW_LIMIT,
    .time_limit_us = WYL_FACT_REPLAY_DEFAULT_TIME_LIMIT_US,
  };
}

gboolean
wyl_fact_replay_scheduler_config_is_zero
  (const WylFactReplaySchedulerConfig *config)
{
  return config != NULL
         && config->global_concurrency == 0
         && config->tenant_concurrency == 0
         && config->global_queue_limit == 0
         && config->tenant_queue_limit == 0
         && config->row_limit == 0
         && config->time_limit_us == 0;
}

wyrelog_error_t
wyl_fact_replay_scheduler_config_validate
  (const WylFactReplaySchedulerConfig *config)
{
  if (config == NULL || config->global_concurrency < 2
      || config->tenant_concurrency == 0
      || config->tenant_concurrency >= config->global_concurrency
      || config->global_queue_limit < 2
      || config->tenant_queue_limit == 0
      || config->tenant_queue_limit >= config->global_queue_limit
      || config->row_limit == 0 || config->time_limit_us <= 0)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

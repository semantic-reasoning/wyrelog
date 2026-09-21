/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_FACT_REPLAY_DEFAULT_GLOBAL_CONCURRENCY 4u
#define WYL_FACT_REPLAY_DEFAULT_TENANT_CONCURRENCY 1u
#define WYL_FACT_REPLAY_DEFAULT_GLOBAL_QUEUE_LIMIT 1024u
#define WYL_FACT_REPLAY_DEFAULT_TENANT_QUEUE_LIMIT 64u
#define WYL_FACT_REPLAY_DEFAULT_ROW_LIMIT G_GUINT64_CONSTANT (1000000)
#define WYL_FACT_REPLAY_DEFAULT_TIME_LIMIT_US G_GINT64_CONSTANT (120000000)

/*
 * Process-local replay resource limits.  An all-zero value means "use the
 * defaults" only at the private WylHandleOpenOptions compatibility boundary;
 * a resolved configuration is always explicit and validates with no zero
 * fields.
 *
 * Reserving capacity is part of the contract, not merely a default choice:
 * one tenant may use neither every worker nor every pending slot.  That leaves
 * another tenant a place to become ready even while the first remains
 * continuously backlogged.
 */
typedef struct
{
  guint global_concurrency;
  guint tenant_concurrency;
  guint global_queue_limit;
  guint tenant_queue_limit;
  guint64 row_limit;
  gint64 time_limit_us;
} WylFactReplaySchedulerConfig;

void wyl_fact_replay_scheduler_config_defaults
  (WylFactReplaySchedulerConfig *out_config);
gboolean wyl_fact_replay_scheduler_config_is_zero
  (const WylFactReplaySchedulerConfig *config);
wyrelog_error_t wyl_fact_replay_scheduler_config_validate
  (const WylFactReplaySchedulerConfig *config);

typedef struct _WylFactReplayScheduler WylFactReplayScheduler;
typedef struct _WylFactReplayFuture WylFactReplayFuture;
typedef struct _WylFactReplayJobContext WylFactReplayJobContext;
typedef struct _WylFactResourceRecorder WylFactResourceRecorder;

typedef struct
{
  guint64 active;
  guint64 queued;
  guint64 active_opens;
  guint64 completed_total;
  guint64 rows_total;
  guint64 runtime_us_total;
  guint64 queue_delay_us_total;
  guint64 queue_delay_us_max;
  guint64 cancelled_total;
  guint64 timed_out_total;
  guint64 row_limit_total;
  guint64 queue_rejected_total;
  guint64 quota_rejected_total;
} WylFactReplayResourceSnapshot;

typedef wyrelog_error_t (*WylFactReplayJobFunc)
  (WylFactReplayJobContext *context, gpointer user_data);

WylFactResourceRecorder *wyl_fact_resource_recorder_new (void);
WylFactResourceRecorder *wyl_fact_resource_recorder_ref
  (WylFactResourceRecorder *recorder);
void wyl_fact_resource_recorder_unref (WylFactResourceRecorder *recorder);
void wyl_fact_resource_recorder_snapshot (WylFactResourceRecorder *recorder,
    WylFactReplayResourceSnapshot *out_snapshot);

wyrelog_error_t wyl_fact_replay_scheduler_new
  (const WylFactReplaySchedulerConfig *config,
    WylFactResourceRecorder *recorder,
    WylFactReplayScheduler **out_scheduler);
WylFactReplayScheduler *wyl_fact_replay_scheduler_ref
  (WylFactReplayScheduler *scheduler);
void wyl_fact_replay_scheduler_unref (WylFactReplayScheduler *scheduler);
wyrelog_error_t wyl_fact_replay_scheduler_shutdown
  (WylFactReplayScheduler *scheduler);

wyrelog_error_t wyl_fact_replay_scheduler_submit
  (WylFactReplayScheduler *scheduler, const gchar *tenant_id,
    const gchar *graph_id, GCancellable *cancellable,
    WylFactReplayJobFunc function, gpointer user_data,
    GDestroyNotify user_data_destroy, WylFactReplayFuture **out_future);

WylFactReplayFuture *wyl_fact_replay_future_ref
  (WylFactReplayFuture *future);
void wyl_fact_replay_future_unref (WylFactReplayFuture *future);
wyrelog_error_t wyl_fact_replay_future_wait (WylFactReplayFuture *future);

GCancellable *wyl_fact_replay_job_context_get_cancellable
  (WylFactReplayJobContext *context);
gint64 wyl_fact_replay_job_context_get_deadline_us
  (WylFactReplayJobContext *context);
guint64 wyl_fact_replay_job_context_get_row_limit
  (WylFactReplayJobContext *context);
void wyl_fact_replay_job_context_add_rows
  (WylFactReplayJobContext *context, guint64 rows);
wyrelog_error_t wyl_fact_replay_job_context_checkpoint
  (WylFactReplayJobContext *context);
wyrelog_error_t wyl_fact_replay_job_context_charge_rows
  (WylFactReplayJobContext *context, guint64 rows);
/* Callback-free atomic publication latch for a runtime state-lock boundary. */
wyrelog_error_t wyl_fact_replay_job_context_commit
  (WylFactReplayJobContext *context);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactResourceRecorder,
    wyl_fact_resource_recorder_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactReplayScheduler,
    wyl_fact_replay_scheduler_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactReplayFuture,
    wyl_fact_replay_future_unref)

G_END_DECLS;

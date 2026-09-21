/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

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

G_END_DECLS;

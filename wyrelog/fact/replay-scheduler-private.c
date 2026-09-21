/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/replay-scheduler-private.h"

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

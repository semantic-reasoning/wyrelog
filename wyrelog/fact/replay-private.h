/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/engine.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

typedef struct
{
  guint graphs_seen;
  guint graphs_loaded;
  guint graphs_degraded;
} wyl_fact_replay_summary_t;

typedef enum
{
  WYL_FACT_GRAPH_STATE_READY = 0,
  WYL_FACT_GRAPH_STATE_DEGRADED,
  WYL_FACT_GRAPH_STATE_SCHEMA_MISMATCH,
  WYL_FACT_GRAPH_STATE_REPLAY_FAILED,
  WYL_FACT_GRAPH_STATE_STORE_UNAVAILABLE,
} wyl_fact_graph_state_t;

typedef struct
{
  gchar *tenant_id;
  gchar *graph_id;
  wyl_fact_graph_state_t state;
  gchar *last_error_class;
  gboolean queryable;
  gint64 last_replay_at_us;
} wyl_fact_graph_status_t;

const gchar *wyl_fact_graph_state_name (wyl_fact_graph_state_t state);
void wyl_fact_graph_status_free (gpointer data);

gchar *wyl_fact_replay_wirelog_relation_name (const gchar * namespace_id,
    const gchar * relation_name);

wyrelog_error_t wyl_fact_replay_open_graph_engine (wyl_policy_store_t * policy,
    const gchar * fact_root, const wyl_policy_fact_graph_info_t * graph_info,
    WylEngine ** out_engine);

wyrelog_error_t wyl_fact_replay_policy_graphs (wyl_policy_store_t * policy,
    const gchar * fact_root, GHashTable * graph_engines,
    GHashTable * graph_statuses, wyl_fact_replay_summary_t * out_summary);

G_END_DECLS;

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

gchar *wyl_fact_replay_wirelog_relation_name (const gchar * namespace_id,
    const gchar * relation_name);

wyrelog_error_t wyl_fact_replay_open_graph_engine (wyl_policy_store_t * policy,
    const wyl_policy_fact_graph_info_t * graph_info, WylEngine ** out_engine);

wyrelog_error_t wyl_fact_replay_policy_graphs (wyl_policy_store_t * policy,
    GHashTable * graph_engines, wyl_fact_replay_summary_t * out_summary);

G_END_DECLS;

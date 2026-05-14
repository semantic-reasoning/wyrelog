/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/wyl-handle-private.h"

G_BEGIN_DECLS;

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *query;
  guint limit;
  const gchar *query_id;
} wyl_fact_datalog_query_options_t;

wyrelog_error_t wyl_fact_datalog_query_json (WylHandle * handle,
    const wyl_fact_datalog_query_options_t * opts, gchar ** out_json,
    gboolean * out_truncated, guint * out_row_count, gchar ** out_query_name);

G_END_DECLS;

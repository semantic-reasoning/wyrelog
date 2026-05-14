/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

typedef struct _WylEngine WylEngine;
typedef struct wyl_fact_store_t wyl_fact_store_t;

G_BEGIN_DECLS;

typedef enum
{
  WYL_FACT_COMPOUND_ARG_SYMBOL = 0,
  WYL_FACT_COMPOUND_ARG_STRING,
  WYL_FACT_COMPOUND_ARG_INT64,
  WYL_FACT_COMPOUND_ARG_BOOL,
  WYL_FACT_COMPOUND_ARG_COMPOUND_REF,
} wyl_fact_compound_arg_type_t;

typedef struct
{
  wyl_fact_compound_arg_type_t type;
  union
  {
    const gchar *text;
    gint64 int64_value;
    gboolean bool_value;
    gint64 compound_ref;
  } as;
} wyl_fact_compound_arg_t;

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  const gchar *functor;
  const wyl_fact_compound_arg_t *args;
  gsize n_args;
} wyl_fact_compound_value_t;

wyrelog_error_t wyl_fact_compound_create_schema (wyl_fact_store_t * store);
wyrelog_error_t wyl_fact_compound_put (wyl_fact_store_t * store,
    const wyl_fact_compound_value_t * value, gint64 * out_compound_ref);
wyrelog_error_t wyl_fact_compound_ref_exists (wyl_fact_store_t * store,
    const gchar * tenant_id, const gchar * graph_id,
    const gchar * namespace_id, gint64 compound_ref, gboolean * out_exists);
wyrelog_error_t wyl_fact_compound_replay (wyl_fact_store_t * store,
    WylEngine * engine, const gchar * tenant_id, const gchar * graph_id,
    const gchar * namespace_id, gint64 compound_ref, gint64 * out_handle);

G_END_DECLS;

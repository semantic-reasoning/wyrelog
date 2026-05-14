/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_FACT_VALUE_NULL = 0,
  WYL_FACT_VALUE_SYMBOL,
  WYL_FACT_VALUE_STRING,
  WYL_FACT_VALUE_INT64,
  WYL_FACT_VALUE_BOOL,
  WYL_FACT_VALUE_COMPOUND_REF,
} wyl_fact_value_type_t;

typedef struct
{
  wyl_fact_value_type_t type;
  union
  {
    const gchar *text;
    gint64 int64_value;
    gboolean bool_value;
    gint64 compound_ref;
  } as;
} wyl_fact_value_t;

typedef struct
{
  const wyl_fact_value_t *values;
  gsize n_values;
} wyl_fact_row_t;

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  const gchar *relation_name;
  guint32 schema_version;
  const wyl_fact_row_t *rows;
  gsize n_rows;
} wyl_fact_batch_t;

wyrelog_error_t wyl_fact_schema_validate_batch (wyl_policy_store_t * store,
    const wyl_fact_batch_t * batch, gchar ** out_reason);
gchar *wyl_fact_schema_build_duckdb_projection_ddl (const
    wyl_policy_fact_relation_schema_options_t * opts);
gchar *wyl_fact_schema_build_wirelog_declaration (const
    wyl_policy_fact_relation_schema_options_t * opts);

G_END_DECLS;

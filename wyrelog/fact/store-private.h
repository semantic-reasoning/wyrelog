/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <duckdb.h>

#include "wyrelog/error.h"
#include "wyrelog/fact/schema-private.h"

G_BEGIN_DECLS;

typedef struct wyl_fact_store_t wyl_fact_store_t;

typedef enum
{
  WYL_FACT_STORE_OP_ASSERT = 0,
  WYL_FACT_STORE_OP_RETRACT,
} wyl_fact_store_op_t;

typedef struct
{
  const gchar *batch_id;
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  const gchar *relation_name;
  guint32 schema_version;
  const gchar *source;
  const gchar *request_id;
  const gchar *idempotency_key;
  wyl_fact_store_op_t op;
  const wyl_fact_row_t *rows;
  gsize n_rows;
} wyl_fact_store_batch_t;

wyrelog_error_t wyl_fact_store_open (const gchar * path,
    wyl_fact_store_t ** out_store);
void wyl_fact_store_close (wyl_fact_store_t * store);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_fact_store_t, wyl_fact_store_close);

duckdb_connection wyl_fact_store_get_connection (wyl_fact_store_t * store);
void wyl_fact_store_lock (wyl_fact_store_t * store);
void wyl_fact_store_unlock (wyl_fact_store_t * store);
wyrelog_error_t wyl_fact_store_create_schema (wyl_fact_store_t * store);
wyrelog_error_t wyl_fact_store_table_exists (wyl_fact_store_t * store,
    const gchar * table_name, gboolean * out_exists);
gchar *wyl_fact_store_projection_table_name (const
    wyl_policy_fact_relation_schema_options_t * schema);
wyrelog_error_t wyl_fact_store_ensure_projection (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    gchar ** out_table_name);
wyrelog_error_t wyl_fact_store_append_batch (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_batch_t * batch, gboolean * out_inserted);
wyrelog_error_t wyl_fact_store_retract_batch (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_batch_t * batch, gboolean * out_inserted);

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <duckdb.h>

#include "wyrelog/fact/schema-private.h"
#include "wyrelog/error.h"

typedef struct wyl_fact_store_t wyl_fact_store_t;
typedef struct _WylFactReplayJobContext WylFactReplayJobContext;
typedef struct WylFactReplayStore WylFactReplayStore;

G_BEGIN_DECLS

typedef enum
{
  WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS = 0,
  WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS,
  WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM,
  WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS,
} WylFactReplayStoreOperation;

typedef enum
{
  WYL_FACT_REPLAY_CELL_NULL = 0,
  WYL_FACT_REPLAY_CELL_TEXT,
  WYL_FACT_REPLAY_CELL_INT64,
  WYL_FACT_REPLAY_CELL_BOOL,
} WylFactReplayCellType;

/* Cell text is borrowed for the duration of the row callback. */
typedef struct
{
  WylFactReplayCellType type;
  union
  {
    const gchar *text;
    gint64 int64_value;
    gboolean bool_value;
  } value;
} WylFactReplayCell;

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  gint64 compound_ref;
  /* Required only for READ_PROJECTION_ROWS. The provider derives and quotes
   * every SQL identifier from this validated schema; callers cannot pass SQL
   * or projection/table/column identifiers directly. */
  const wyl_policy_fact_relation_schema_options_t *projection_schema;
} WylFactReplayStoreRequest;

typedef wyrelog_error_t (*WylFactReplayStoreRowFunc)
  (const WylFactReplayCell *cells, gsize n_cells, gpointer user_data);

typedef struct
{
  wyrelog_error_t (*execute) (gpointer provider,
      WylFactReplayStoreOperation operation,
      const WylFactReplayStoreRequest *request,
      WylFactReplayJobContext *job_context,
      WylFactReplayStoreRowFunc row_func, gpointer row_data);
  wyrelog_error_t (*close) (gpointer provider);
  void (*destroy) (gpointer provider);
} WylFactReplayStoreProvider;

wyrelog_error_t wyl_fact_replay_store_new
  (const WylFactReplayStoreProvider *provider_ops, gpointer provider,
    WylFactReplayStore **out_store);
wyrelog_error_t wyl_fact_replay_store_new_c_store
  (wyl_fact_store_t *store, WylFactReplayJobContext *job_context,
    WylFactReplayStore **out_store);
wyrelog_error_t wyl_fact_replay_store_execute
  (WylFactReplayStore *store, WylFactReplayStoreOperation operation,
    const WylFactReplayStoreRequest *request,
    WylFactReplayJobContext *job_context,
    WylFactReplayStoreRowFunc row_func, gpointer row_data);
wyrelog_error_t wyl_fact_replay_store_close_checked
  (WylFactReplayStore *store);
void wyl_fact_replay_store_free (WylFactReplayStore *store);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactReplayStore,
    wyl_fact_replay_store_free)

#if defined(WYL_TEST_HANDLE_SEAMS)
typedef enum
{
  WYL_FACT_REPLAY_STORE_TEST_BEFORE_EXECUTE = 0,
  WYL_FACT_REPLAY_STORE_TEST_QUERY_CALL_STARTED,
  WYL_FACT_REPLAY_STORE_TEST_AFTER_EXECUTE,
} WylFactReplayStoreTestPhase;

typedef void (*WylFactReplayStoreBeforeExecuteTestHook)
  (duckdb_connection connection, WylFactReplayStoreOperation operation,
    WylFactReplayStoreTestPhase phase, duckdb_state execute_state,
    gpointer user_data);
void wyl_fact_replay_store_set_before_execute_test_hook
  (WylFactReplayStoreBeforeExecuteTestHook hook, gpointer user_data);
void wyl_fact_replay_store_set_projection_failure_column_for_test
  (gint column_index);
#endif

G_END_DECLS

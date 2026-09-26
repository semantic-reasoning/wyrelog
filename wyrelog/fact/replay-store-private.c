/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "replay-store-private.h"

#define WYL_FACT_STORE_CONNECTION_ROLE 1
#include "store-connection-private.h"
#undef WYL_FACT_STORE_CONNECTION_ROLE

#include <duckdb.h>
#include <string.h>

#include "compound-private.h"
#include "replay-scheduler-private.h"
#include "store-private.h"

struct WylFactReplayStore
{
  WylFactReplayStoreProvider ops;
  gpointer provider;
  gboolean closed;
};

typedef struct
{
  wyl_fact_store_t *store;
} CStoreReplayProvider;

#if defined(WYL_TEST_HANDLE_SEAMS)
static WylFactReplayStoreBeforeExecuteTestHook before_execute_test_hook;
static gpointer before_execute_test_hook_data;
static gint projection_failure_column = -1;
G_LOCK_DEFINE_STATIC (before_execute_test_hook);

void
wyl_fact_replay_store_set_before_execute_test_hook
  (WylFactReplayStoreBeforeExecuteTestHook hook, gpointer user_data)
{
  G_LOCK (before_execute_test_hook);
  before_execute_test_hook = hook;
  before_execute_test_hook_data = user_data;
  G_UNLOCK (before_execute_test_hook);
}

void
wyl_fact_replay_store_set_projection_failure_column_for_test (gint column_index)
{
  g_atomic_int_set (&projection_failure_column, column_index);
}

static void
before_execute_test_hook_invoke (duckdb_connection connection,
    WylFactReplayStoreOperation operation,
    WylFactReplayStoreTestPhase phase, duckdb_state execute_state)
{
  G_LOCK (before_execute_test_hook);
  WylFactReplayStoreBeforeExecuteTestHook hook = before_execute_test_hook;
  gpointer user_data = before_execute_test_hook_data;
  G_UNLOCK (before_execute_test_hook);
  if (hook != NULL)
    hook (connection, operation, phase, execute_state, user_data);
}
#endif

static void
replay_store_interrupt (GCancellable *cancellable, gpointer user_data)
{
  (void) cancellable;
  duckdb_interrupt ((duckdb_connection) user_data);
}

static wyrelog_error_t
checkpoint (WylFactReplayJobContext *job_context)
{
  return job_context == NULL ? WYRELOG_E_OK
      : wyl_fact_replay_job_context_checkpoint (job_context);
}

wyrelog_error_t
wyl_fact_replay_store_new (const WylFactReplayStoreProvider *provider_ops,
    gpointer provider, WylFactReplayStore **out_store)
{
  if (out_store != NULL)
    *out_store = NULL;
  if (provider_ops == NULL || provider_ops->execute == NULL
      || provider_ops->close == NULL || provider_ops->destroy == NULL
      || provider == NULL || out_store == NULL)
    return WYRELOG_E_INVALID;
  WylFactReplayStore *store = g_new0 (WylFactReplayStore, 1);
  if (store == NULL)
    return WYRELOG_E_NOMEM;
  store->ops = *provider_ops;
  store->provider = provider;
  *out_store = store;
  return WYRELOG_E_OK;
}

static void
append_identifier (GString *sql, const gchar *identifier)
{
  g_string_append_c (sql, '"');
  for (const gchar *p = identifier; p != NULL && *p != '\0'; p++) {
    if (*p == '"')
      g_string_append_c (sql, '"');
    g_string_append_c (sql, *p);
  }
  g_string_append_c (sql, '"');
}

static wyrelog_error_t
build_projection_query (const wyl_policy_fact_relation_schema_options_t *schema,
    GString **out_sql)
{
  *out_sql = NULL;
  if (schema == NULL || schema->tenant_id == NULL || schema->graph_id == NULL
      || schema->namespace_id == NULL || schema->relation_name == NULL
      || schema->schema_version == 0 || schema->columns == NULL
      || schema->n_columns == 0)
    return WYRELOG_E_INVALID;
  g_autofree gchar *table = wyl_fact_store_projection_table_name (schema);
  if (table == NULL)
    return WYRELOG_E_NOMEM;
  GString *sql = g_string_new ("SELECT ");
  for (gsize i = 0; i < schema->n_columns; i++) {
    if (schema->columns[i].column_name == NULL
        || schema->columns[i].column_type == NULL) {
      g_string_free (sql, TRUE);
      return WYRELOG_E_POLICY;
    }
    if (i != 0)
      g_string_append (sql, ", ");
    append_identifier (sql, schema->columns[i].column_name);
  }
  g_string_append (sql, ", __wyl_valid FROM ");
  append_identifier (sql, table);
  g_string_append (sql,
      " WHERE __wyl_tenant_id = ? AND __wyl_graph_id = ? "
      "ORDER BY __wyl_seq, __wyl_row_index;");
  *out_sql = sql;
  return WYRELOG_E_OK;
}

static const gchar *
operation_sql (WylFactReplayStoreOperation operation)
{
  switch (operation) {
    case WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS:
      return "SELECT DISTINCT namespace_id, relation_name, schema_version "
             "FROM fact_batches WHERE tenant_id = ? AND graph_id = ? "
             "ORDER BY namespace_id, relation_name, schema_version;";
    case WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM:
      return "SELECT functor, arity, content_hash FROM compound_terms "
             "WHERE tenant_id = ? AND graph_id = ? AND namespace_id = ? "
             "AND compound_ref = ?;";
    case WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS:
      return "SELECT a.arg_index, a.arg_type, a.symbol_value, "
             "a.string_value, a.int64_value, a.bool_value, "
             "a.child_compound_ref FROM compound_args AS a "
             "JOIN compound_terms AS t ON t.compound_ref = a.compound_ref "
             "WHERE t.tenant_id = ? AND t.graph_id = ? "
             "AND t.namespace_id = ? AND t.compound_ref = ? "
             "ORDER BY a.arg_index;";
    case WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS:
      return NULL;
    default:
      return NULL;
  }
}

static wyrelog_error_t
bind_request (duckdb_prepared_statement stmt,
    WylFactReplayStoreOperation operation,
    const WylFactReplayStoreRequest *request)
{
  if (operation == WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS
      || operation == WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS) {
    return duckdb_bind_varchar (stmt, 1, request->tenant_id) == DuckDBSuccess
           && duckdb_bind_varchar (stmt, 2, request->graph_id) == DuckDBSuccess
        ? WYRELOG_E_OK : WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_bind_varchar (stmt, 1, request->tenant_id)
      | duckdb_bind_varchar (stmt, 2, request->graph_id)
      | duckdb_bind_varchar (stmt, 3, request->namespace_id)
      | duckdb_bind_int64 (stmt, 4, request->compound_ref);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static WylFactReplayCell
null_cell (void)
{
  WylFactReplayCell cell = { .type = WYL_FACT_REPLAY_CELL_NULL };
  return cell;
}

static WylFactReplayCell
text_cell (duckdb_result *result, idx_t column, idx_t row)
{
  if (duckdb_value_is_null (result, column, row))
    return null_cell ();
  gchar *value = duckdb_value_varchar (result, column, row);
  WylFactReplayCell cell = { .type = WYL_FACT_REPLAY_CELL_TEXT,
                             .value.text = value };
  return cell;
}

static WylFactReplayCell
int64_cell (duckdb_result *result, idx_t column, idx_t row)
{
  if (duckdb_value_is_null (result, column, row))
    return null_cell ();
  WylFactReplayCell cell = { .type = WYL_FACT_REPLAY_CELL_INT64,
                             .value.int64_value = duckdb_value_int64 (result, column, row) };
  return cell;
}

static WylFactReplayCell
bool_cell (duckdb_result *result, idx_t column, idx_t row)
{
  if (duckdb_value_is_null (result, column, row))
    return null_cell ();
  WylFactReplayCell cell = { .type = WYL_FACT_REPLAY_CELL_BOOL,
                             .value.bool_value = duckdb_value_boolean (result, column, row) };
  return cell;
}

static wyrelog_error_t
emit_result_row (duckdb_result *result,
    WylFactReplayStoreOperation operation,
    const WylFactReplayStoreRequest *request, idx_t row,
    WylFactReplayStoreRowFunc row_func, gpointer row_data)
{
  gsize capacity = operation == WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS
      ? request->projection_schema->n_columns + 1 : 7;
  if (capacity == 0 || capacity > G_MAXSIZE / sizeof (WylFactReplayCell))
    return WYRELOG_E_POLICY;
  g_autofree WylFactReplayCell *cells = g_new0 (WylFactReplayCell,
          capacity);
  gsize n_cells = 0;
  switch (operation) {
    case WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS:
      cells[0] = text_cell (result, 0, row);
      cells[1] = text_cell (result, 1, row);
      cells[2] = int64_cell (result, 2, row);
      n_cells = 3;
      break;
    case WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS:
      for (gsize i = 0; i < request->projection_schema->n_columns; i++) {
        const gchar *type = request->projection_schema->columns[i].column_type;
        if (g_strcmp0 (type, "symbol") == 0
            || g_strcmp0 (type, "string") == 0)
          cells[i] = text_cell (result, (idx_t) i, row);
        else if (g_strcmp0 (type, "int64") == 0
            || g_strcmp0 (type, "compound_ref") == 0)
          cells[i] = int64_cell (result, (idx_t) i, row);
        else if (g_strcmp0 (type, "bool") == 0)
          cells[i] = bool_cell (result, (idx_t) i, row);
        else {
          for (gsize j = 0; j < i; j++)
            if (cells[j].type == WYL_FACT_REPLAY_CELL_TEXT)
              duckdb_free ((void *) cells[j].value.text);
          return WYRELOG_E_POLICY;
        }
#if defined(WYL_TEST_HANDLE_SEAMS)
        if (g_atomic_int_compare_and_exchange (&projection_failure_column,
            (gint) i, -1)) {
          for (gsize j = 0; j <= i; j++)
            if (cells[j].type == WYL_FACT_REPLAY_CELL_TEXT)
              duckdb_free ((void *) cells[j].value.text);
          return WYRELOG_E_IO;
        }
#endif
      }
      cells[request->projection_schema->n_columns] = bool_cell (result,
              (idx_t) request->projection_schema->n_columns, row);
      n_cells = request->projection_schema->n_columns + 1;
      break;
    case WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM:
      cells[0] = text_cell (result, 0, row);
      cells[1] = int64_cell (result, 1, row);
      cells[2] = text_cell (result, 2, row);
      n_cells = 3;
      break;
    case WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS:
      cells[0] = int64_cell (result, 0, row);
      cells[1] = text_cell (result, 1, row);
      cells[2] = text_cell (result, 2, row);
      cells[3] = text_cell (result, 3, row);
      cells[4] = int64_cell (result, 4, row);
      cells[5] = bool_cell (result, 5, row);
      cells[6] = int64_cell (result, 6, row);
      n_cells = 7;
      break;
    default:
      return WYRELOG_E_INVALID;
  }
  wyrelog_error_t rc = row_func (cells, n_cells, row_data);
  for (gsize i = 0; i < n_cells; i++)
    if (cells[i].type == WYL_FACT_REPLAY_CELL_TEXT)
      duckdb_free ((void *) cells[i].value.text);
  return rc;
}

static wyrelog_error_t
c_store_execute (gpointer provider, WylFactReplayStoreOperation operation,
    const WylFactReplayStoreRequest *request,
    WylFactReplayJobContext *job_context,
    WylFactReplayStoreRowFunc row_func, gpointer row_data)
{
  CStoreReplayProvider *c_store = provider;
  if (c_store == NULL || c_store->store == NULL || request == NULL
      || row_func == NULL
      || request->tenant_id == NULL || request->graph_id == NULL
      || request->tenant_id[0] == '\0' || request->graph_id[0] == '\0')
    return WYRELOG_E_INVALID;
  if ((operation == WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM
      || operation == WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS)
      && (request->namespace_id == NULL || request->namespace_id[0] == '\0'
      || request->compound_ref <= 0))
    return WYRELOG_E_INVALID;
  if (operation == WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS
      && (request->projection_schema == NULL
      || g_strcmp0 (request->projection_schema->tenant_id,
      request->tenant_id) != 0
      || g_strcmp0 (request->projection_schema->graph_id,
      request->graph_id) != 0))
    return WYRELOG_E_POLICY;

  wyrelog_error_t rc = checkpoint (job_context);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactStoreConnectionSession session = { 0 };
  rc = wyl_fact_store_connection_session_begin (c_store->store, &session);
  if (rc != WYRELOG_E_OK)
    return rc;
  duckdb_connection connection = wyl_fact_store_connection_session_get
        (&session);
  GCancellable *cancellable = job_context == NULL ? NULL
      : wyl_fact_replay_job_context_get_cancellable (job_context);
  gulong interrupt_handler = cancellable == NULL ? 0
      : g_cancellable_connect (cancellable,
          G_CALLBACK (replay_store_interrupt), connection, NULL);
  g_autoptr (GString) projection_sql = NULL;
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  if (operation == WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS) {
    rc = build_projection_query (request->projection_schema, &projection_sql);
    if (rc != WYRELOG_E_OK)
      goto cleanup;
  }
  const gchar *sql = projection_sql == NULL ? operation_sql (operation)
      : projection_sql->str;
  if (sql == NULL) {
    rc = WYRELOG_E_INVALID;
    goto cleanup;
  }

  if (duckdb_prepare (connection, sql, &stmt) != DuckDBSuccess) {
    rc = WYRELOG_E_IO;
    goto cleanup;
  }
  rc = bind_request (stmt, operation, request);
#if defined(WYL_TEST_HANDLE_SEAMS)
  if (rc == WYRELOG_E_OK)
    before_execute_test_hook_invoke (connection, operation,
        WYL_FACT_REPLAY_STORE_TEST_BEFORE_EXECUTE, DuckDBSuccess);
#endif
#if defined(WYL_TEST_HANDLE_SEAMS)
  if (rc == WYRELOG_E_OK)
    before_execute_test_hook_invoke (connection, operation,
        WYL_FACT_REPLAY_STORE_TEST_QUERY_CALL_STARTED, DuckDBSuccess);
#endif
  duckdb_state execute_state = rc == WYRELOG_E_OK
      ? duckdb_execute_prepared (stmt, &result) : DuckDBError;
#if defined(WYL_TEST_HANDLE_SEAMS)
  if (rc == WYRELOG_E_OK)
    before_execute_test_hook_invoke (connection, operation,
        WYL_FACT_REPLAY_STORE_TEST_AFTER_EXECUTE, execute_state);
#endif
  if (rc == WYRELOG_E_OK && execute_state != DuckDBSuccess) {
    rc = checkpoint (job_context);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_IO;
  }
  for (idx_t row = 0; rc == WYRELOG_E_OK && row < duckdb_row_count (&result);
      row++) {
    rc = checkpoint (job_context);
    if (rc == WYRELOG_E_OK)
      rc = emit_result_row (&result, operation, request, row, row_func,
              row_data);
  }
cleanup:
  if (stmt != NULL)
    duckdb_destroy_prepare (&stmt);
  duckdb_destroy_result (&result);
  if (interrupt_handler != 0)
    g_cancellable_disconnect (cancellable, interrupt_handler);
  wyl_fact_store_connection_session_end (&session);
  return rc;
}

static wyrelog_error_t
c_store_close (gpointer provider)
{
  CStoreReplayProvider *c_store = provider;
  return c_store == NULL || c_store->store == NULL
      ? WYRELOG_E_INVALID : WYRELOG_E_OK;
}

static void
c_store_destroy (gpointer provider)
{
  g_free (provider);
}

static const WylFactReplayStoreProvider c_store_ops = {
  .execute = c_store_execute,
  .close = c_store_close,
  .destroy = c_store_destroy,
};

wyrelog_error_t
wyl_fact_replay_store_new_c_store (wyl_fact_store_t *store,
    WylFactReplayJobContext *job_context, WylFactReplayStore **out_store)
{
  if (out_store != NULL)
    *out_store = NULL;
  if (store == NULL || out_store == NULL)
    return WYRELOG_E_INVALID;
  CStoreReplayProvider *provider = g_new0 (CStoreReplayProvider, 1);
  if (provider == NULL)
    return WYRELOG_E_NOMEM;
  (void) job_context;
  provider->store = store;
  wyrelog_error_t rc = wyl_fact_replay_store_new (&c_store_ops, provider,
          out_store);
  if (rc != WYRELOG_E_OK) {
    g_free (provider);
  }
  return rc;
}

wyrelog_error_t
wyl_fact_replay_store_execute (WylFactReplayStore *store,
    WylFactReplayStoreOperation operation,
    const WylFactReplayStoreRequest *request,
    WylFactReplayJobContext *job_context,
    WylFactReplayStoreRowFunc row_func, gpointer row_data)
{
  if (store == NULL || store->closed || request == NULL || row_func == NULL)
    return WYRELOG_E_INVALID;
  return store->ops.execute (store->provider, operation, request, job_context,
             row_func, row_data);
}

wyrelog_error_t
wyl_fact_replay_store_close_checked (WylFactReplayStore *store)
{
  if (store == NULL)
    return WYRELOG_E_INVALID;
  if (store->closed)
    return WYRELOG_E_OK;
  store->closed = TRUE;
  return store->ops.close (store->provider);
}

void
wyl_fact_replay_store_free (WylFactReplayStore *store)
{
  if (store == NULL)
    return;
  if (!store->closed)
    (void) wyl_fact_replay_store_close_checked (store);
  store->ops.destroy (store->provider);
  g_free (store);
}

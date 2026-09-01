/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/engine.h"
#include "wyrelog/fact/compound-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/store-test-seams-private.h"
#include "wyrelog/policy/store-private.h"

wyrelog_error_t wyl_engine_open_source (const gchar * dl_src,
    guint32 num_workers, WylEngine ** out);

typedef struct
{
  wyl_policy_fact_relation_schema_column_t columns[2];
  wyl_policy_fact_relation_schema_options_t schema;
} TestSchema;

typedef struct
{
  wyl_fact_value_t values[2];
  wyl_fact_row_t rows[1];
  wyl_fact_store_batch_t batch;
} TestBatch;

typedef struct
{
  WylFactStoreTransactionTestKind target;
  guint calls[2];
  gboolean block_rollback;
  gboolean rollback_entered;
  gboolean release_rollback;
  GMutex lock;
  GCond cond;
} TransactionFault;

typedef struct
{
  wyl_fact_store_t *store;
  const wyl_policy_fact_relation_schema_options_t *schema;
  const wyl_fact_store_batch_t *batch;
  wyrelog_error_t rc;
  gboolean inserted;
} AppendWorker;

typedef struct
{
  gboolean entered;
  GMutex lock;
  GCond cond;
} AdmissionGate;

typedef struct
{
  wyl_fact_store_t *store;
  wyrelog_error_t rc;
  gboolean exists;
} Waiter;

typedef struct
{
  wyl_fact_store_t *store;
  gboolean called;
  gboolean exists;
  wyrelog_error_t nested_rc;
} ReentryProbe;

typedef struct
{
  guint rows;
  gint64 value;
} EngineMarker;

static void test_schema_init(TestSchema *fixture) {
  fixture->columns[0] = (wyl_policy_fact_relation_schema_column_t){
    "order_id", "symbol", FALSE, TRUE
  };
  fixture->columns[1] = (wyl_policy_fact_relation_schema_column_t){
    "amount", "int64", FALSE, TRUE
  };
  fixture->schema = (wyl_policy_fact_relation_schema_options_t){
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = fixture->columns,
    .n_columns = G_N_ELEMENTS(fixture->columns),
  };
}

static void test_batch_init(TestBatch *fixture, const gchar *batch_id,
    const gchar *idempotency_key) {
  fixture->values[0] = (wyl_fact_value_t){
    .type = WYL_FACT_VALUE_SYMBOL,
    .as.text = "o-1",
  };
  fixture->values[1] = (wyl_fact_value_t){
    .type = WYL_FACT_VALUE_INT64,
    .as.int64_value = 42,
  };
  fixture->rows[0] = (wyl_fact_row_t){
    .values = fixture->values,
    .n_values = G_N_ELEMENTS(fixture->values),
  };
  fixture->batch = (wyl_fact_store_batch_t){
    .batch_id = batch_id,
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "poison-test",
    .request_id = "request-1",
    .idempotency_key = idempotency_key,
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = fixture->rows,
    .n_rows = G_N_ELEMENTS(fixture->rows),
  };
}

static wyl_fact_store_t *open_initialized_store(const gchar *path,
    const TestSchema *schema) {
  wyl_fact_store_t *store = NULL;
  g_assert_cmpint(wyl_fact_store_open(path, &store), ==, WYRELOG_E_OK);
  g_assert_nonnull(store);
  g_assert_cmpint(wyl_fact_store_create_schema(store), ==, WYRELOG_E_OK);
  g_assert_cmpint(
    wyl_fact_store_ensure_projection(store, &schema->schema, NULL), ==,
    WYRELOG_E_OK);
  return store;
}

static void transaction_fault_init(TransactionFault *fault,
    WylFactStoreTransactionTestKind target,
    gboolean block_rollback) {
  memset(fault, 0, sizeof(*fault));
  fault->target = target;
  fault->block_rollback = block_rollback;
  g_mutex_init(&fault->lock);
  g_cond_init(&fault->cond);
}

static void transaction_fault_clear(TransactionFault *fault) {
  g_cond_clear(&fault->cond);
  g_mutex_clear(&fault->lock);
}

static wyrelog_error_t
fail_commit_and_rollback(WylFactStoreTransactionTestKind kind,
    WylFactStoreTransactionTestPhase phase,
    gpointer user_data) {
  TransactionFault *fault = user_data;
  if (kind != fault->target)
    return WYRELOG_E_OK;
  g_assert_cmpuint((guint)phase, <, G_N_ELEMENTS(fault->calls));
  fault->calls[phase]++;
  if (phase == WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK &&
      fault->block_rollback) {
    g_mutex_lock(&fault->lock);
    fault->rollback_entered = TRUE;
    g_cond_broadcast(&fault->cond);
    while (!fault->release_rollback)
      g_cond_wait(&fault->cond, &fault->lock);
    g_mutex_unlock(&fault->lock);
  }
  return WYRELOG_E_IO;
}

static gpointer append_worker(gpointer user_data) {
  AppendWorker *worker = user_data;
  worker->rc = wyl_fact_store_append_batch(worker->store, worker->schema,
          worker->batch, &worker->inserted);
  return NULL;
}

static gpointer waiter_worker(gpointer user_data) {
  Waiter *waiter = user_data;
  waiter->rc = wyl_fact_store_table_exists(waiter->store, "fact_batches",
          &waiter->exists);
  return NULL;
}

static void admission_gate(gpointer user_data) {
  AdmissionGate *gate = user_data;
  g_mutex_lock(&gate->lock);
  gate->entered = TRUE;
  g_cond_broadcast(&gate->cond);
  g_mutex_unlock(&gate->lock);
}

static void count_admission(gpointer user_data) {
  guint *calls = user_data;
  (*calls)++;
}

static wyrelog_error_t probe_reentry(const gchar *point, gpointer user_data) {
  ReentryProbe *probe = user_data;
  if (g_strcmp0(point, "after_intent") == 0) {
    probe->called = TRUE;
    probe->exists = TRUE;
    probe->nested_rc = wyl_fact_store_table_exists(
      probe->store, "fact_batches", &probe->exists);
  }
  return WYRELOG_E_OK;
}

static void engine_marker_row(const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data) {
  EngineMarker *marker = user_data;
  if (g_strcmp0(relation, "poison_marker_observed") == 0 && ncols == 1) {
    marker->rows++;
    marker->value = row[0];
  }
}

static void assert_engine_marker(WylEngine *engine) {
  EngineMarker marker = {0};
  g_assert_cmpint(wyl_engine_snapshot(engine, "poison_marker_observed",
      engine_marker_row, &marker),
      ==, WYRELOG_E_OK);
  g_assert_cmpuint(marker.rows, ==, 1);
  g_assert_cmpint(marker.value, ==, 918);
}

static void assert_zero_delta(const wyl_fact_commit_delta_t *delta) {
  g_assert_false(delta->inserted);
  g_assert_cmpint(delta->committed_row_delta, ==, 0);
  g_assert_cmpint(delta->logical_byte_delta, ==, 0);
}

static gint64 query_count(wyl_fact_store_t *store, const gchar *sql);
static gint64 projection_count_for_batch(wyl_fact_store_t *store,
    const TestSchema *schema, const gchar *batch_id);

static void assert_poisoned_api_matrix(wyl_fact_store_t *store,
    const TestSchema *schema,
    const TestBatch *batch) {
  gboolean exists = TRUE;
  g_assert_cmpint(wyl_fact_store_create_schema(store), ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint(wyl_fact_store_table_exists(store, "fact_batches", &exists),
      ==, WYRELOG_E_INTERNAL);
  g_assert_false(exists);

  gchar *table = GINT_TO_POINTER(1);
  g_assert_cmpint(
    wyl_fact_store_ensure_projection(store, &schema->schema, &table), ==,
    WYRELOG_E_INTERNAL);
  g_assert_null(table);
  exists = TRUE;
  g_assert_cmpint(
    wyl_fact_store_validate_projection(store, &schema->schema, &exists), ==,
    WYRELOG_E_INTERNAL);
  g_assert_false(exists);

  gint64 row_count = -1;
  g_assert_cmpint(
    wyl_fact_store_count_projection_batch_rows(
      store, &schema->schema, batch->batch.batch_id, &row_count),
    ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint(row_count, ==, 0);

  gboolean inserted = TRUE;
  wyl_fact_commit_delta_t delta = {TRUE, -1, -1};
  g_assert_cmpint(wyl_fact_store_append_batch_delta(
        store, &schema->schema, &batch->batch, &inserted, &delta),
      ==, WYRELOG_E_INTERNAL);
  g_assert_false(inserted);
  assert_zero_delta(&delta);

  inserted = TRUE;
  delta = (wyl_fact_commit_delta_t){TRUE, -1, -1};
  g_assert_cmpint(wyl_fact_store_retract_batch_delta(
        store, &schema->schema, &batch->batch, &inserted, &delta),
      ==, WYRELOG_E_INTERNAL);
  g_assert_false(inserted);
  assert_zero_delta(&delta);

  inserted = TRUE;
  row_count = -1;
  g_assert_cmpint(wyl_fact_store_retract_by_batch_id(
        store, &schema->schema, batch->batch.batch_id,
        "poison-retract", "poison-test", "request-2",
        "poison-retract:1", &inserted, &row_count),
      ==, WYRELOG_E_INTERNAL);
  g_assert_false(inserted);
  g_assert_cmpint(row_count, ==, 0);

  const wyl_fact_store_forget_options_t forget_opts = {
    .op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070918",
    .batch_id = batch->batch.batch_id,
    .operator_id = "admin",
    .reason = "poison-matrix",
  };
  gsize purged = G_MAXSIZE;
  g_assert_cmpint(
    wyl_fact_store_forget(store, &schema->schema, &forget_opts, &purged), ==,
    WYRELOG_E_INTERNAL);
  g_assert_cmpuint(purged, ==, 0);
  wyl_fact_forget_outcome_t poison_outcome = { 0 };
  g_assert_cmpint(wyl_fact_store_forget_reconcile(store,
      schema->schema.tenant_id, schema->schema.graph_id, NULL, NULL,
      &poison_outcome), ==, WYRELOG_E_INTERNAL);

  const wyl_fact_compound_arg_t args[] = {
    {.type = WYL_FACT_COMPOUND_ARG_SYMBOL, .as.text = "o-1"},
  };
  const wyl_fact_compound_value_t value = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .functor = "order_ref",
    .args = args,
    .n_args = G_N_ELEMENTS(args),
  };
  g_assert_cmpint(wyl_fact_compound_create_schema(store), ==,
      WYRELOG_E_INTERNAL);
  exists = TRUE;
  g_assert_cmpint(wyl_fact_compound_ref_exists(store, "tenant-a", "orders",
      "shop", 1, &exists),
      ==, WYRELOG_E_INTERNAL);
  g_assert_false(exists);
  gint64 compound_ref = -1;
  g_assert_cmpint(wyl_fact_compound_put(store, &value, &compound_ref), ==,
      WYRELOG_E_INTERNAL);
  g_assert_cmpint(compound_ref, ==, 0);

  g_autoptr(WylEngine) engine = NULL;
  static const gchar engine_source[] =
      ".decl poison_marker(value: int64)\n"
      ".decl poison_marker_observed(value: int64)\n"
      "poison_marker_observed(V) :- poison_marker(V).\n";
  g_assert_cmpint(wyl_engine_open_source(engine_source, 1, &engine), ==,
      WYRELOG_E_OK);
  const gint64 marker_value[] = {918};
  g_assert_cmpint(wyl_engine_insert(
        engine, "poison_marker", marker_value, G_N_ELEMENTS(marker_value)),
      ==, WYRELOG_E_OK);
  assert_engine_marker(engine);
  gint64 handle = -1;
  g_assert_cmpint(wyl_fact_compound_replay(store, engine, "tenant-a", "orders",
      "shop", 1, &handle),
      ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint(handle, ==, 0);
  g_autoptr(GHashTable) handles = g_hash_table_new(g_str_hash, g_str_equal);
  gpointer marker = GINT_TO_POINTER(7);
  g_hash_table_insert(handles, (gpointer) "sentinel", marker);
  handle = -1;
  g_assert_cmpint(wyl_fact_compound_replay_cached(store, engine, "tenant-a",
      "orders", "shop", 1, handles,
      &handle),
      ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint(handle, ==, 0);
  g_assert_cmpuint(g_hash_table_size(handles), ==, 1);
  g_assert_true(g_hash_table_lookup(handles, "sentinel") == marker);
  assert_engine_marker(engine);

  g_autoptr(wyl_policy_store_t) policy = NULL;
  g_assert_cmpint(wyl_policy_store_open(NULL, &policy), ==, WYRELOG_E_OK);
  g_assert_cmpint(wyl_policy_store_create_schema(policy), ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_info_t graph_info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .storage_path = "unused-while-poisoned",
    .schema_version = 1,
  };
  WylEngine *replay_engine = GINT_TO_POINTER(1);
  g_assert_cmpint(wyl_fact_replay_open_graph_engine_with_store_for_test(
        policy, store, &graph_info, &replay_engine),
      ==, WYRELOG_E_INTERNAL);
  g_assert_null(replay_engine);

  guint duckdb_calls = wyl_fact_store_test_duckdb_call_count(store);
  g_assert_cmpint(wyl_fact_store_test_exec_sql(store, "SELECT 1;"), ==,
      WYRELOG_E_INTERNAL);
  gint64 query_value = -1;
  g_assert_cmpint(
    wyl_fact_store_test_query_int64(store, "SELECT 1;", &query_value), ==,
    WYRELOG_E_INTERNAL);
  g_assert_cmpint(query_value, ==, 0);
  gchar *query_text = GINT_TO_POINTER(1);
  g_assert_cmpint(
    wyl_fact_store_test_query_text(store, "SELECT 'x';", &query_text), ==,
    WYRELOG_E_INTERNAL);
  g_assert_null(query_text);
  g_assert_cmpuint(wyl_fact_store_test_duckdb_call_count(store), ==,
      duckdb_calls);
}

static void test_waiter_and_poisoned_matrix(void) {
  g_autoptr(GError) error = NULL;
  g_autofree gchar *dir =
      g_dir_make_tmp("wyl-fact-append-poison-XXXXXX", &error);
  g_assert_no_error(error);
  g_autofree gchar *path = g_build_filename(dir, "facts.duckdb", NULL);
  TestSchema schema;
  TestBatch batch;
  test_schema_init(&schema);
  test_batch_init(&batch, "poison-append", "poison-append:1");
  g_autoptr(wyl_fact_store_t) store = open_initialized_store(path, &schema);

  TransactionFault fault;
  AdmissionGate gate = {0};
  transaction_fault_init(&fault, WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE,
      TRUE);
  g_mutex_init(&gate.lock);
  g_cond_init(&gate.cond);
  wyl_fact_store_test_set_transaction_hook(store, fail_commit_and_rollback,
      &fault);
  wyl_fact_store_test_set_session_admission_hook(store, admission_gate, &gate);
  AppendWorker append = {
    .store = store,
    .schema = &schema.schema,
    .batch = &batch.batch,
    .rc = WYRELOG_E_OK,
    .inserted = TRUE,
  };
  g_autoptr(GThread) append_thread =
      g_thread_new("poison-append", append_worker, &append);

  g_mutex_lock(&fault.lock);
  while (!fault.rollback_entered)
    g_cond_wait(&fault.cond, &fault.lock);
  g_mutex_unlock(&fault.lock);
  g_assert_false(wyl_fact_store_test_try_lock(store));

  Waiter waiter = {
    .store = store,
    .rc = WYRELOG_E_OK,
    .exists = TRUE,
  };
  g_autoptr(GThread) waiter_thread =
      g_thread_new("poison-waiter", waiter_worker, &waiter);
  g_mutex_lock(&gate.lock);
  while (!gate.entered)
    g_cond_wait(&gate.cond, &gate.lock);
  g_mutex_unlock(&gate.lock);

  g_mutex_lock(&fault.lock);
  fault.release_rollback = TRUE;
  g_cond_broadcast(&fault.cond);
  g_mutex_unlock(&fault.lock);
  g_thread_join(g_steal_pointer(&append_thread));
  g_thread_join(g_steal_pointer(&waiter_thread));
  g_assert_cmpint(append.rc, ==, WYRELOG_E_INTERNAL);
  g_assert_false(append.inserted);
  g_assert_cmpint(waiter.rc, ==, WYRELOG_E_INTERNAL);
  g_assert_false(waiter.exists);
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT],
      ==, 1);
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK],
      ==, 1);
  wyl_fact_store_test_set_transaction_hook(store, NULL, NULL);
  wyl_fact_store_test_set_session_admission_hook(store, NULL, NULL);
  assert_poisoned_api_matrix(store, &schema, &batch);

  g_clear_pointer(&store, wyl_fact_store_close);
  g_assert_cmpint(wyl_fact_store_open(path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint(query_count(store, "SELECT COUNT(*) FROM fact_batches;"),
      ==, 0);
  g_assert_cmpint(query_count(store, "SELECT COUNT(*) FROM fact_event_log;"),
      ==, 0);
  g_assert_cmpint(projection_count_for_batch(
        store, &schema, "poison-append"),
      ==, 0);
  g_clear_pointer(&store, wyl_fact_store_close);
  g_assert_cmpint(g_remove(path), ==, 0);
  g_assert_cmpint(g_rmdir(dir), ==, 0);

  g_cond_clear(&gate.cond);
  g_mutex_clear(&gate.lock);
  transaction_fault_clear(&fault);
}

static void assert_owner_poisoned(WylFactStoreTransactionTestKind kind) {
  g_autoptr(GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp("wyl-fact-owner-poison-XXXXXX", &error);
  g_assert_no_error(error);
  g_autofree gchar *path = g_build_filename(dir, "facts.duckdb", NULL);
  TestSchema schema;
  TestBatch batch;
  test_schema_init(&schema);
  test_batch_init(&batch, "owner-seed", "owner-seed:1");
  g_autoptr(wyl_fact_store_t) store = open_initialized_store(path, &schema);

  if (kind == WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH) {
    gboolean inserted = FALSE;
    g_assert_cmpint(wyl_fact_store_append_batch(store, &schema.schema,
        &batch.batch, &inserted),
        ==, WYRELOG_E_OK);
    g_assert_true(inserted);
  } else if (kind == WYL_FACT_STORE_TRANSACTION_TEST_COMPOUND_PUT) {
    g_assert_cmpint(wyl_fact_compound_create_schema(store), ==, WYRELOG_E_OK);
  }

  TransactionFault fault;
  transaction_fault_init(&fault, kind, FALSE);
  wyl_fact_store_test_set_transaction_hook(store, fail_commit_and_rollback,
      &fault);
  if (kind == WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH) {
    gboolean inserted = TRUE;
    gint64 rows = -1;
    g_assert_cmpint(wyl_fact_store_retract_by_batch_id(
          store, &schema.schema, "owner-seed", "owner-retract",
          "poison-test", "request-2", "owner-retract:1",
          &inserted, &rows),
        ==, WYRELOG_E_INTERNAL);
    g_assert_false(inserted);
    g_assert_cmpint(rows, ==, 0);
  } else {
    const wyl_fact_compound_arg_t args[] = {
      {.type = WYL_FACT_COMPOUND_ARG_INT64, .as.int64_value = 42},
    };
    const wyl_fact_compound_value_t value = {
      .tenant_id = "tenant-a",
      .graph_id = "orders",
      .namespace_id = "shop",
      .functor = "amount",
      .args = args,
      .n_args = G_N_ELEMENTS(args),
    };
    gint64 ref = -1;
    g_assert_cmpint(wyl_fact_compound_put(store, &value, &ref), ==,
        WYRELOG_E_INTERNAL);
    g_assert_cmpint(ref, ==, 0);
  }
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT],
      ==, 1);
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK],
      ==, 1);
  wyl_fact_store_test_set_transaction_hook(store, NULL, NULL);
  g_assert_cmpint(wyl_fact_store_create_schema(store), ==, WYRELOG_E_INTERNAL);
  transaction_fault_clear(&fault);

  g_clear_pointer(&store, wyl_fact_store_close);
  g_assert_cmpint(wyl_fact_store_open(path, &store), ==, WYRELOG_E_OK);
  if (kind == WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH) {
    g_assert_cmpint(query_count(store,
        "SELECT COUNT(*) FROM fact_batches "
        "WHERE batch_id = 'owner-retract';"),
        ==, 0);
    g_assert_cmpint(query_count(store,
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id = 'owner-seed';"),
        ==, 1);
    g_assert_cmpint(query_count(store,
        "SELECT COUNT(*) FROM fact_event_log "
        "WHERE batch_id = 'owner-retract';"),
        ==, 0);
    g_assert_cmpint(query_count(store,
        "SELECT COUNT(*) FROM fact_event_log "
        "WHERE batch_id = 'owner-seed';"),
        ==, 1);
    g_assert_cmpint(projection_count_for_batch(
          store, &schema, "owner-retract"),
        ==, 0);
    g_assert_cmpint(projection_count_for_batch(store, &schema, "owner-seed"),
        ==, 1);
  } else {
    g_assert_cmpint(query_count(store,
        "SELECT COUNT(*) FROM compound_terms;"),
        ==, 0);
    g_assert_cmpint(query_count(store,
        "SELECT COUNT(*) FROM compound_args;"),
        ==, 0);
  }
  g_clear_pointer(&store, wyl_fact_store_close);
  g_assert_cmpint(g_remove(path), ==, 0);
  g_assert_cmpint(g_rmdir(dir), ==, 0);
}

static void test_retract_owner_poison(void) {
  assert_owner_poisoned(WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH);
}

static void test_append_backed_retract_owner_poison(void) {
  g_autoptr(GError) error = NULL;
  g_autofree gchar *dir =
      g_dir_make_tmp("wyl-fact-retract-core-poison-XXXXXX", &error);
  g_assert_no_error(error);
  g_autofree gchar *path = g_build_filename(dir, "facts.duckdb", NULL);
  TestSchema schema;
  TestBatch seed;
  TestBatch retract;
  test_schema_init(&schema);
  test_batch_init(&seed, "retract-core-seed", "retract-core-seed:1");
  test_batch_init(&retract, "retract-core-attempt", "retract-core-attempt:1");
  retract.batch.op = WYL_FACT_STORE_OP_RETRACT;
  wyl_fact_store_t *store = open_initialized_store(path, &schema);
  gboolean inserted = FALSE;
  g_assert_cmpint(wyl_fact_store_append_batch(
        store, &schema.schema, &seed.batch, &inserted),
      ==, WYRELOG_E_OK);
  g_assert_true(inserted);

  TransactionFault fault;
  transaction_fault_init(
    &fault, WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE, FALSE);
  wyl_fact_store_test_set_transaction_hook(store, fail_commit_and_rollback,
      &fault);
  inserted = TRUE;
  g_assert_cmpint(wyl_fact_store_retract_batch(
        store, &schema.schema, &retract.batch, &inserted),
      ==, WYRELOG_E_INTERNAL);
  g_assert_false(inserted);
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT],
      ==, 1);
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK],
      ==, 1);
  wyl_fact_store_close(store);
  transaction_fault_clear(&fault);

  store = NULL;
  g_assert_cmpint(wyl_fact_store_open(path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint(query_count(store,
      "SELECT COUNT(*) FROM fact_batches "
      "WHERE batch_id = 'retract-core-attempt';"),
      ==, 0);
  g_assert_cmpint(query_count(store,
      "SELECT COUNT(*) FROM fact_batches "
      "WHERE batch_id = 'retract-core-seed';"),
      ==, 1);
  g_assert_cmpint(query_count(store,
      "SELECT COUNT(*) FROM fact_event_log "
      "WHERE batch_id = 'retract-core-attempt';"),
      ==, 0);
  g_assert_cmpint(query_count(store,
      "SELECT COUNT(*) FROM fact_event_log "
      "WHERE batch_id = 'retract-core-seed';"),
      ==, 1);
  g_assert_cmpint(projection_count_for_batch(
        store, &schema, "retract-core-attempt"),
      ==, 0);
  g_assert_cmpint(projection_count_for_batch(
        store, &schema, "retract-core-seed"),
      ==, 1);
  wyl_fact_store_close(store);
  g_assert_cmpint(g_remove(path), ==, 0);
  g_assert_cmpint(g_rmdir(dir), ==, 0);
}

static void test_same_thread_reentry_fails_closed(void) {
  TestSchema schema;
  TestBatch batch;
  test_schema_init(&schema);
  test_batch_init(&batch, "reentry-seed", "reentry-seed:1");
  g_autoptr(wyl_fact_store_t) store = open_initialized_store(NULL, &schema);
  gboolean inserted = FALSE;
  g_assert_cmpint(wyl_fact_store_append_batch(
        store, &schema.schema, &batch.batch, &inserted),
      ==, WYRELOG_E_OK);
  g_assert_true(inserted);

  ReentryProbe probe = {
    .store = store,
    .nested_rc = WYRELOG_E_OK,
  };
  const wyl_fact_store_forget_options_t opts = {
    .op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070920",
    .batch_id = "reentry-seed",
    .operator_id = "admin",
    .reason = "reentry-probe",
    .checkpoint = probe_reentry,
    .checkpoint_data = &probe,
  };
  g_assert_cmpint(wyl_fact_store_forget(store, &schema.schema, &opts, NULL),
      ==, WYRELOG_E_OK);
  g_assert_true(probe.called);
  g_assert_cmpint(probe.nested_rc, ==, WYRELOG_E_INTERNAL);
  g_assert_false(probe.exists);
  g_assert_cmpint(wyl_fact_store_create_schema(store), ==, WYRELOG_E_OK);
}

static void test_cross_store_reentry_fails_closed(void) {
  TestSchema schema;
  TestBatch batch;
  test_schema_init(&schema);
  test_batch_init(&batch, "cross-store-seed", "cross-store-seed:1");
  g_autoptr(wyl_fact_store_t) store = open_initialized_store(NULL, &schema);
  g_autoptr(wyl_fact_store_t) nested_store =
      open_initialized_store(NULL, &schema);
  gboolean inserted = FALSE;
  g_assert_cmpint(wyl_fact_store_append_batch(
        store, &schema.schema, &batch.batch, &inserted),
      ==, WYRELOG_E_OK);
  g_assert_true(inserted);

  guint admission_calls = 0;
  wyl_fact_store_test_set_session_admission_hook(
    nested_store, count_admission, &admission_calls);
  guint nested_duckdb_calls =
      wyl_fact_store_test_duckdb_call_count(nested_store);
  guint nested_session_admissions =
      wyl_fact_store_test_session_admission_count(nested_store);
  ReentryProbe probe = {
    .store = nested_store,
    .nested_rc = WYRELOG_E_OK,
  };
  const wyl_fact_store_forget_options_t opts = {
    .op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070921",
    .batch_id = "cross-store-seed",
    .operator_id = "admin",
    .reason = "cross-store-reentry-probe",
    .checkpoint = probe_reentry,
    .checkpoint_data = &probe,
  };
  g_assert_cmpint(wyl_fact_store_forget(store, &schema.schema, &opts, NULL),
      ==, WYRELOG_E_OK);
  g_assert_true(probe.called);
  g_assert_cmpint(probe.nested_rc, ==, WYRELOG_E_INTERNAL);
  g_assert_false(probe.exists);
  g_assert_cmpuint(admission_calls, ==, 0);
  g_assert_cmpuint(
    wyl_fact_store_test_session_admission_count(nested_store), ==,
    nested_session_admissions);
  g_assert_cmpuint(wyl_fact_store_test_duckdb_call_count(nested_store), ==,
      nested_duckdb_calls);
  wyl_fact_store_test_set_session_admission_hook(nested_store, NULL, NULL);
  g_assert_cmpint(wyl_fact_store_create_schema(nested_store), ==,
      WYRELOG_E_OK);
}

static void test_compound_owner_poison(void) {
  assert_owner_poisoned(WYL_FACT_STORE_TRANSACTION_TEST_COMPOUND_PUT);
}

static gint64 query_count(wyl_fact_store_t *store, const gchar *sql) {
  gint64 count = -1;
  g_assert_cmpint(wyl_fact_store_test_query_int64(store, sql, &count), ==,
      WYRELOG_E_OK);
  return count;
}

static gint64 projection_count_for_batch(wyl_fact_store_t *store,
    const TestSchema *schema, const gchar *batch_id) {
  gint64 count = -1;
  g_assert_cmpint(wyl_fact_store_count_projection_batch_rows(
        store, &schema->schema, batch_id, &count),
      ==, WYRELOG_E_OK);
  return count;
}

static void test_file_reopen_recovers_forget(void) {
  g_autoptr(GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp("wyl-fact-poison-XXXXXX", &error);
  g_assert_no_error(error);
  g_autofree gchar *path = g_build_filename(dir, "facts.duckdb", NULL);
  TestSchema schema;
  TestBatch batch;
  test_schema_init(&schema);
  test_batch_init(&batch, "forget-seed", "forget-seed:1");
  wyl_fact_store_t *store = open_initialized_store(path, &schema);
  gboolean inserted = FALSE;
  g_assert_cmpint(wyl_fact_store_append_batch(store, &schema.schema,
      &batch.batch, &inserted),
      ==, WYRELOG_E_OK);
  g_assert_true(inserted);

  TransactionFault fault;
  transaction_fault_init(
    &fault, WYL_FACT_STORE_TRANSACTION_TEST_FORGET_COMPLETE, FALSE);
  wyl_fact_store_test_set_transaction_hook(store, fail_commit_and_rollback,
      &fault);
  const wyl_fact_store_forget_options_t opts = {
    .op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070919",
    .batch_id = "forget-seed",
    .operator_id = "admin",
    .reason = "poison-reopen",
  };
  gsize purged = G_MAXSIZE;
  g_assert_cmpint(wyl_fact_store_forget(store, &schema.schema, &opts, &purged),
      ==, WYRELOG_E_INTERNAL);
  g_assert_cmpuint(purged, ==, 0);
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT],
      ==, 1);
  g_assert_cmpuint(fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK],
      ==, 1);
  wyl_fact_store_close(store);
  transaction_fault_clear(&fault);

  store = NULL;
  g_assert_cmpint(wyl_fact_store_open(path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint(
    query_count(
      store,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
    ==, 1);
  g_assert_cmpint(query_count(store, "SELECT COUNT(*) FROM fact_forget_audit;"),
      ==, 0);
  wyl_fact_forget_outcome_t outcome = { 0 };
  g_assert_cmpint(wyl_fact_store_forget_reconcile(store,
      schema.schema.tenant_id, schema.schema.graph_id, NULL, NULL, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint(
    query_count(
      store,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'COMPLETED';"),
    ==, 1);
  g_assert_cmpint(query_count(store, "SELECT COUNT(*) FROM fact_forget_audit;"),
      ==, 1);
  wyl_fact_store_close(store);

  g_assert_cmpint(g_remove(path), ==, 0);
  g_assert_cmpint(g_rmdir(dir), ==, 0);
}

int main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/fact-store/poison/waiter-and-api-matrix",
      test_waiter_and_poisoned_matrix);
  g_test_add_func("/fact-store/poison/retract-owner",
      test_retract_owner_poison);
  g_test_add_func("/fact-store/poison/append-backed-retract-owner",
      test_append_backed_retract_owner_poison);
  g_test_add_func("/fact-store/poison/same-thread-reentry",
      test_same_thread_reentry_fails_closed);
  g_test_add_func("/fact-store/poison/cross-store-reentry",
      test_cross_store_reentry_fails_closed);
  g_test_add_func("/fact-store/poison/compound-owner",
      test_compound_owner_poison);
  g_test_add_func("/fact-store/poison/file-reopen-forget",
      test_file_reopen_recovers_forget);
  return g_test_run();
}

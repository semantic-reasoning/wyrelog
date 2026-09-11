/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include "fact-test-support.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/fact/graph-seal-private.h"
#include "wyrelog/fact/provisioning-run-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/store-open-private.h"
#include "wyrelog/fact/store-private.h"

static const gchar tenant_id[] = "tenant-a";
static const gchar graph_id[] = "orders";

static void
remove_root (const gchar *root)
{
  g_autoptr (GDir) directory = g_dir_open (root, 0, NULL);
  const gchar *name;
  while (directory != NULL && (name = g_dir_read_name (directory)) != NULL) {
    g_autofree gchar *child = g_build_filename (root, name, NULL);
    if (g_file_test (child, G_FILE_TEST_IS_DIR)
        && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
      remove_root (child);
    else
      g_assert_cmpint (g_remove (child), ==, 0);
  }
  g_clear_pointer (&directory, g_dir_close);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

static WylPolicyGraphAuthorityRecord *
read_authority (const gchar *path)
{
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &policy), ==, WYRELOG_E_OK);
  WylPolicyGraphAuthorityRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
      graph_id, &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  return record;
}

static void
seed_provisioned_graph (const gchar *path, const gchar *root)
{
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (policy, tenant_id, &created),
      ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"}, {"amount", "int64"}, {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph = {
    .tenant_id = tenant_id, .graph_id = graph_id, .fact_root = root,
    .schema_version = 1, .owner_scope = tenant_id,
    .relations = relations, .n_relations = G_N_ELEMENTS (relations),
  };
  gchar op_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_policy_store_create_fact_graph_provisioning (policy,
      &graph, NULL, op_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (policy, op_uuid, root,
      NULL), ==, WYRELOG_E_OK);
  WylPolicyGraphProvisioningRecord *operation = NULL;
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (policy, op_uuid,
      &operation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
      graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_nonnull (operation);
  g_assert_nonnull (authority);
  g_assert_cmpint (operation->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  g_assert_cmpint (authority->lifecycle_state, ==, WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  g_assert_cmpstr (operation->tenant_id, ==, authority->tenant_id);
  g_assert_cmpstr (operation->graph_id, ==, authority->graph_id);
  g_assert_nonnull (operation->store_uuid);
  g_assert_cmpstr (operation->store_uuid, ==, authority->store_uuid);
  wyl_policy_graph_provisioning_record_free (operation);
  wyl_policy_graph_authority_record_free (authority);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE}, {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant_id, .graph_id = graph_id,
    .namespace_id = "shop.ns", .relation_name = "orders-rel",
    .schema_version = 1, .relation_visible = TRUE,
    .columns = columns, .n_columns = G_N_ELEMENTS (columns),
  };
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (policy,
      &schema), ==, WYRELOG_E_OK);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy, root,
      tenant_id, graph_id, TRUE, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL, .as.text = "order-a"},
    {.type = WYL_FACT_VALUE_INT64, .as.int64_value = 11},
    {.type = WYL_FACT_VALUE_BOOL, .as.bool_value = TRUE},
  };
  wyl_fact_row_t rows[] = {{values, G_N_ELEMENTS (values)}};
  const wyl_fact_store_batch_t batch = {
    .batch_id = "coordination-batch", .tenant_id = tenant_id,
    .graph_id = graph_id, .namespace_id = "shop.ns", .relation_name = "orders-rel",
    .schema_version = 1, .source = "test", .idempotency_key = "coordination:1",
    .op = WYL_FACT_STORE_OP_ASSERT, .rows = rows, .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
}

static void
count_order (WylEngine *engine, const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  (void) engine;
  (void) relation;
  g_assert_cmpuint (ncols, ==, 3);
  g_assert_cmpint (row[1], ==, 11);
  g_assert_cmpint (row[2], ==, 1);
  (*(guint *) user_data)++;
}

typedef struct _Run Run;
typedef struct
{
  Run *run;
  gboolean unseal;
  GThread *thread;
  gboolean acquired;
  gboolean done;
  guint checkpoints;
  wyrelog_error_t acquire_rc;
  wyrelog_error_t operation_rc;
  wyrelog_error_t release_rc;
  WylPolicyAuthorityMutationResult policy_result;
} Worker;

struct _Run
{
  WylHandle *handle;
  GCancellable *cancel;
  GMutex mutex;
  GCond cond;
  Worker first;
  Worker second;
  const gchar *phase;
  gboolean fail_first;
  gboolean entered;
  gboolean release;
  gboolean hook_timeout;
  guint held_calls;
};

static wyrelog_error_t
hold_first (const gchar *phase, gpointer user_data)
{
  Run *run = user_data;
  g_mutex_lock (&run->mutex);
  Worker *worker = g_thread_self () == run->first.thread
      ? &run->first : &run->second;
  worker->checkpoints++;
  gboolean inject = FALSE;
  if (worker == &run->first && g_strcmp0 (phase, run->phase) == 0) {
    run->held_calls++;
    run->entered = TRUE;
    g_cond_broadcast (&run->cond);
    gint64 deadline = g_get_monotonic_time () + 10 * G_TIME_SPAN_SECOND;
    while (!run->release) {
      if (!g_cond_wait_until (&run->cond, &run->mutex, deadline)) {
        run->hook_timeout = TRUE;
        break;
      }
    }
    inject = run->fail_first;
  }
  gboolean timeout = run->hook_timeout;
  g_mutex_unlock (&run->mutex);
  return timeout ? WYRELOG_E_BUSY : inject ? WYRELOG_E_IO : WYRELOG_E_OK;
}

static gpointer
run_worker (gpointer user_data)
{
  Worker *worker = user_data;
  Run *run = worker->run;
  g_mutex_lock (&run->mutex);
  worker->thread = g_thread_self ();
  g_mutex_unlock (&run->mutex);
  WylServiceAuthWriteLease *lease = NULL;
  worker->acquire_rc = wyl_service_auth_authority_acquire_write
        (wyl_handle_get_service_auth_authority (run->handle), run->handle,
          run->cancel, &lease);
  if (worker->acquire_rc == WYRELOG_E_OK) {
    g_mutex_lock (&run->mutex);
    worker->acquired = TRUE;
    g_mutex_unlock (&run->mutex);
    const wyl_policy_fact_graph_info_t info = {
      .tenant_id = tenant_id, .graph_id = graph_id,
    };
    if (worker->unseal) {
      WylFactGraphUnsealOutcome outcome = { 0 };
      worker->operation_rc = wyl_handle_unseal_fact_graph (run->handle, lease,
              &info, G_TIME_SPAN_SECOND, &outcome);
      worker->policy_result = outcome.policy_result;
      wyl_fact_graph_unseal_outcome_clear (&outcome);
    } else {
      WylFactGraphSealOutcome outcome = { 0 };
      worker->operation_rc = wyl_handle_seal_fact_graph (run->handle, lease,
              &info, G_TIME_SPAN_SECOND, &outcome);
      wyl_fact_graph_seal_outcome_clear (&outcome);
    }
    worker->release_rc = wyl_service_auth_write_lease_release_terminal (&lease);
  }
  g_mutex_lock (&run->mutex);
  worker->done = TRUE;
  g_cond_broadcast (&run->cond);
  g_mutex_unlock (&run->mutex);
  return NULL;
}

static void
test_opposing_wrappers (gconstpointer data)
{
  if (!g_test_subprocess ()) {
    g_test_trap_subprocess (NULL, 30 * G_TIME_SPAN_SECOND, 0);
    g_test_trap_assert_passed ();
    return;
  }
  guint variant = GPOINTER_TO_UINT (data);
  gboolean unseal_first = (variant % 2) == 0;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-opposing-wrappers-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  g_autofree gchar *path = g_build_filename (root, "policy.sqlite", NULL);
  seed_provisioned_graph (path, root);
  WylHandleOpenOptions options = {.policy_store_path = path, .fact_root = root};
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==, WYRELOG_E_OK);
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  guint initial_rows = 0;
  g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle, tenant_id,
      graph_id, observed, count_order, &initial_rows), ==, WYRELOG_E_OK);
  g_assert_cmpuint (initial_rows, ==, 1);
  if (unseal_first) {
    WylServiceAuthWriteLease *lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_write
          (wyl_handle_get_service_auth_authority (handle), handle, NULL,
        &lease), ==, WYRELOG_E_OK);
    const wyl_policy_fact_graph_info_t info = {
      .tenant_id = tenant_id, .graph_id = graph_id,
    };
    WylFactGraphSealOutcome outcome = { 0 };
    wyrelog_error_t rc = wyl_handle_seal_fact_graph (handle, lease, &info,
            G_TIME_SPAN_SECOND, &outcome);
    wyl_fact_graph_seal_outcome_clear (&outcome);
    g_assert_cmpint (wyl_service_auth_write_lease_release_terminal (&lease),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  }
  WylPolicyGraphAuthorityRecord *before = read_authority (path);
  Run run = {.handle = handle, .cancel = g_cancellable_new (),
             .phase = unseal_first ? WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_BEFORE_PUBLICATION
      : WYL_FACT_GRAPH_SEAL_PHASE_DURABLE_WRITE,
             .fail_first = variant >= 2};
  g_mutex_init (&run.mutex);
  g_cond_init (&run.cond);
  run.first = (Worker) {.run = &run, .unseal = unseal_first};
  run.second = (Worker) {.run = &run, .unseal = !unseal_first};
  wyl_fact_graph_seal_set_test_hook (hold_first, &run);
  GThread *first = g_thread_new ("first-wrapper", run_worker, &run.first);
  g_mutex_lock (&run.mutex);
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  while (!run.entered && !run.first.done)
    if (!g_cond_wait_until (&run.cond, &run.mutex, deadline))
      break;
  gboolean entered = run.entered;
  g_mutex_unlock (&run.mutex);
  GThread *second = entered
      ? g_thread_new ("queued-wrapper", run_worker, &run.second) : NULL;
  gboolean queued = FALSE;
  gboolean second_excluded = FALSE;
  deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  while (second != NULL && g_get_monotonic_time () < deadline) {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (handle), &snapshot);
    if (snapshot.waiting_writers == 1 && snapshot.writer_active) {
      queued = TRUE;
      g_mutex_lock (&run.mutex);
      second_excluded = !run.second.acquired && !run.second.done
          && run.second.checkpoints == 0;
      g_mutex_unlock (&run.mutex);
      break;
    }
    g_usleep (1000);
  }
  if (!queued || !second_excluded)
    g_cancellable_cancel (run.cancel);
  g_mutex_lock (&run.mutex);
  run.release = TRUE;
  g_cond_broadcast (&run.cond);
  g_mutex_unlock (&run.mutex);
  g_thread_join (first);
  if (second != NULL)
    g_thread_join (second);
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  WylPolicyGraphAuthorityRecord *after = read_authority (path);
  guint rows = 0;
  wyrelog_error_t snapshot_rc = wyl_handle_snapshot_fact_graph_relation (handle,
          tenant_id, graph_id, observed, count_order, &rows);
  g_test_message ("variant=%u queued=%d first=%d second=%d generation=%"
      G_GUINT64_FORMAT "->%" G_GUINT64_FORMAT " snapshot=%d rows=%u",
      variant, queued, run.first.operation_rc, run.second.operation_rc,
      before->lifecycle_generation, after->lifecycle_generation, snapshot_rc, rows);
  g_clear_object (&handle);
  g_clear_object (&run.cancel);
  g_cond_clear (&run.cond);
  g_mutex_clear (&run.mutex);
  remove_root (root);
  g_assert_true (entered);
  g_assert_true (queued);
  g_assert_true (second_excluded);
  g_assert_false (run.hook_timeout);
  g_assert_cmpuint (run.held_calls, ==, 1);
  g_assert_cmpint (run.first.acquire_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (run.second.acquire_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (run.first.release_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (run.second.release_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (run.first.operation_rc, ==,
      run.fail_first ? WYRELOG_E_IO : WYRELOG_E_OK);
  g_assert_cmpint (run.second.operation_rc, ==,
      variant == 3 ? WYRELOG_E_BUSY : WYRELOG_E_OK);
  if (variant == 3)
    g_assert_cmpint (run.second.policy_result, ==, WYL_POLICY_AUTHORITY_MUTATION_STALE);
  g_assert_cmpstr (after->store_uuid, ==, before->store_uuid);
  g_assert_cmpuint (after->reconciliation_generation, ==, before->reconciliation_generation);
  /* Only the two succeeding variants move the generation, once per durable
   * transition.  A failed first operation moves it not at all: the seal
   * variant is refused before its durable write, and the unseal variant is
   * failed at UNSEAL_BEFORE_PUBLICATION, which aborts the transaction and
   * leaves the authority SEALED rather than resealing it afterwards.  The
   * second operation then finds the graph in the state it started in, so it
   * is a no-op too. */
  g_assert_cmpuint (after->lifecycle_generation, ==,
      before->lifecycle_generation + (variant >= 2 ? 0 : 2));
  g_assert_cmpint (after->lifecycle_state, ==, unseal_first
      ? WYL_POLICY_GRAPH_LIFECYCLE_SEALED : WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  g_assert_cmpint (after->sealed_compatibility, ==, unseal_first);
  g_assert_cmpint (snapshot_rc, ==, unseal_first ? WYRELOG_E_NOT_FOUND : WYRELOG_E_OK);
  g_assert_cmpuint (rows, ==, unseal_first ? 0 : 1);
  wyl_policy_graph_authority_record_free (before);
  wyl_policy_graph_authority_record_free (after);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_data_func ("/fact-coordination/unseal-then-seal",
      GUINT_TO_POINTER (0), test_opposing_wrappers);
  g_test_add_data_func ("/fact-coordination/seal-then-unseal",
      GUINT_TO_POINTER (1), test_opposing_wrappers);
  g_test_add_data_func ("/fact-coordination/failed-unseal-then-seal",
      GUINT_TO_POINTER (2), test_opposing_wrappers);
  g_test_add_data_func ("/fact-coordination/failed-seal-then-unseal",
      GUINT_TO_POINTER (3), test_opposing_wrappers);
  return g_test_run ();
}

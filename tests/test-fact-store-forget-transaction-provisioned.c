/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>

#include "fact/graph-locator-private.h"
#include "fact/store-open-private.h"
#include "fact/store-private.h"

static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070892";
static const gchar tenant_id[] = "tenant-provision";
static const gchar graph_id[] = "graph-provision";
static const gchar *provision_helper_path;

typedef struct
{
  guint commit_calls;
  guint rollback_calls;
} TransactionFault;

typedef struct
{
  gchar *root;
  gchar *policy_path;
  gchar *container;
} ProvisionedFixture;

static void
provisioned_fixture_free (ProvisionedFixture *fixture)
{
  if (fixture == NULL)
    return;
  g_free (fixture->root);
  g_free (fixture->policy_path);
  g_free (fixture->container);
  g_free (fixture);
}

static ProvisionedFixture *
run_provision_helper (void)
{
  const gchar *argv[] = {
    provision_helper_path,
    tenant_id,
    graph_id,
    store_uuid,
    NULL,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GSubprocess) process = g_subprocess_newv (argv,
          G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
          &error);
  g_assert_no_error (error);
  g_assert_nonnull (process);
  g_autofree gchar *stdout_text = NULL;
  g_autofree gchar *stderr_text = NULL;
  g_assert_true (g_subprocess_communicate_utf8 (process, NULL, NULL,
      &stdout_text, &stderr_text, &error));
  g_assert_no_error (error);
  if (!g_subprocess_get_if_exited (process)
      || g_subprocess_get_exit_status (process) != 0)
    g_test_message ("provision helper failed: %s",
        stderr_text != NULL ? stderr_text : "no diagnostic");
  g_assert_true (g_subprocess_get_if_exited (process));
  g_assert_cmpint (g_subprocess_get_exit_status (process), ==, 0);
  g_assert_nonnull (stdout_text);
  g_assert_true (stderr_text == NULL || stderr_text[0] == '\0');
  gsize length = strlen (stdout_text);
  g_assert_cmpuint (length, >, 2);
  g_assert_cmpint (stdout_text[length - 1], ==, '\n');
  g_assert_null (memchr (stdout_text, '\r', length));
  g_auto (GStrv) lines = g_strsplit (stdout_text, "\n", -1);
  g_assert_cmpuint (g_strv_length (lines), ==, 3);
  g_assert_cmpstr (lines[2], ==, "");
  g_assert_true (g_path_is_absolute (lines[0]));
  g_assert_true (g_path_is_absolute (lines[1]));
  ProvisionedFixture *fixture = g_new0 (ProvisionedFixture, 1);
  fixture->root = g_strdup (lines[0]);
  fixture->policy_path = g_strdup (lines[1]);
  fixture->container = g_path_get_dirname (fixture->root);
  g_autofree gchar *policy_container = g_path_get_dirname (
    fixture->policy_path);
  g_assert_cmpstr (policy_container, ==, fixture->container);
  return fixture;
}

static void
assert_provisioned_shape (const gchar *root, const gchar *stage_basename)
{
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  g_autofree gchar *stage_path = g_build_filename (root, tenant_component,
          graph_component, stage_basename, NULL);
  struct stat final_status;
  g_assert_cmpint (stat (final_path, &final_status), ==, 0);
  g_assert_true (S_ISREG (final_status.st_mode));
  g_assert_cmpuint (final_status.st_mode & 0777, ==, 0600);
#ifdef __APPLE__
  g_assert_cmpuint (final_status.st_nlink, ==, 1);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
#else
  struct stat stage_status;
  g_assert_cmpint (stat (stage_path, &stage_status), ==, 0);
  g_assert_true (S_ISREG (stage_status.st_mode));
  g_assert_cmpuint (stage_status.st_mode & 0777, ==, 0600);
  g_assert_cmpuint (final_status.st_dev, ==, stage_status.st_dev);
  g_assert_cmpuint (final_status.st_ino, ==, stage_status.st_ino);
  g_assert_cmpuint (final_status.st_nlink, ==, 2);
  g_assert_cmpuint (stage_status.st_nlink, ==, 2);
#endif
}

static void
remove_root (const gchar *root)
{
  g_autoptr (GDir) directory = g_dir_open (root, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (root, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_root (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

static wyrelog_error_t
open_live (wyl_policy_store_t *policy_store, const gchar *root,
    wyl_fact_store_t **out_store)
{
  return wyl_fact_store_open_provisioned_graph (policy_store, root, tenant_id,
             graph_id, TRUE, out_store);
}

static gboolean
exec_ok (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result = { 0 };
  gboolean ok = duckdb_query (conn, sql, &result) == DuckDBSuccess;
  duckdb_destroy_result (&result);
  return ok;
}

static gint64
count_rows (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (conn, sql, &result), ==, DuckDBSuccess);
  gint64 count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return count;
}

static wyrelog_error_t
fail_commit_once (WylFactStoreForgetTransactionTestPhase phase,
    gpointer user_data)
{
  TransactionFault *fault = user_data;
  if (phase == WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_COMMIT) {
    fault->commit_calls++;
    if (fault->commit_calls == 1)
      return WYRELOG_E_IO;
  } else if (phase == WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_ROLLBACK) {
    fault->rollback_calls++;
  }
  return WYRELOG_E_OK;
}

static void
test_provisioned_commit_failure_rolls_back (void)
{
  ProvisionedFixture *fixture = run_provision_helper ();
  g_autoptr (wyl_policy_store_t) policy_store = NULL;
  g_assert_cmpint (wyl_policy_store_open (fixture->policy_path, &policy_store),
      ==, WYRELOG_E_OK);
  g_autoptr (GPtrArray) records = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list (policy_store,
      tenant_id, &records), ==, WYRELOG_E_OK);
  g_assert_cmpuint (records->len, ==, 1);
  WylPolicyGraphProvisioningRecord *record = g_ptr_array_index (records, 0);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  assert_provisioned_shape (fixture->root, record->stage_basename);

  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (open_live (policy_store, fixture->root, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  g_assert_cmpint (wyl_fact_store_ensure_projection (store, &schema, NULL), ==,
      WYRELOG_E_OK);
  wyl_fact_value_t value = {
    .type = WYL_FACT_VALUE_SYMBOL,
    .as.text = "o-1",
  };
  const wyl_fact_row_t row = {&value, 1};
  const wyl_fact_store_batch_t batch = {
    .batch_id = "provisioned-transaction-fault",
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .idempotency_key = "provisioned-transaction-fault:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = &row,
    .n_rows = 1,
  };
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);

  TransactionFault fault = { 0 };
  wyl_fact_store_set_forget_transaction_test_hook (store, fail_commit_once,
      &fault);
  const wyl_fact_store_forget_options_t opts = {
    .op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070893",
    .batch_id = "provisioned-transaction-fault",
    .operator_id = "admin",
    .reason = "transaction-boundary-test",
  };
  g_assert_cmpint (wyl_fact_store_forget (store, &schema, &opts, NULL), ==,
      WYRELOG_E_IO);
  g_assert_cmpuint (fault.commit_calls, ==, 1);
  g_assert_cmpuint (fault.rollback_calls, ==, 1);

  duckdb_connection conn = wyl_fact_store_get_connection (store);
  g_assert_true (exec_ok (conn, "SELECT 1;"));
  g_assert_true (exec_ok (conn, "BEGIN TRANSACTION;"));
  g_assert_true (exec_ok (conn, "ROLLBACK;"));
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
      ==, 1);
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_audit;"), ==, 0);

  wyl_fact_store_set_forget_transaction_test_hook (store, NULL, NULL);
  g_assert_cmpint (wyl_fact_store_forget_reconcile (store, NULL, NULL), ==,
      WYRELOG_E_OK);
  wyl_fact_store_close (store);

  g_assert_cmpint (open_live (policy_store, fixture->root, &store), ==,
      WYRELOG_E_OK);
  conn = wyl_fact_store_get_connection (store);
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'COMPLETED';"),
      ==, 1);
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_audit;"), ==, 1);
  wyl_fact_store_close (store);
  assert_provisioned_shape (fixture->root, record->stage_basename);
  g_clear_pointer (&records, g_ptr_array_unref);
  g_clear_pointer (&policy_store, wyl_policy_store_close);
  remove_root (fixture->container);
  provisioned_fixture_free (fixture);
}

int
main (int argc, char **argv)
{
  if (argc != 2 || argv[1] == NULL || !g_path_is_absolute (argv[1]))
    return 2;
  provision_helper_path = argv[1];
  argv[1] = NULL;
  argc = 1;
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-store/forget-transaction/provisioned-commit-failure",
      test_provisioned_commit_failure_rolls_back);
  return g_test_run ();
}

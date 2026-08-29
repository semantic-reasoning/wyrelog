/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>

#include "fact/graph-locator-private.h"
#include "fact/store-private.h"

static const gchar operation_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070891";
static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070892";
static const gchar tenant_id[] = "tenant-provision";
static const gchar graph_id[] = "graph-provision";
static const gchar *provision_helper_path;

typedef struct
{
  guint commit_calls;
  guint rollback_calls;
} TransactionFault;

static WylFactStoreIdentity
make_identity (void)
{
  WylFactStoreIdentity identity = { 0 };
  identity.tenant_id = (gchar *) tenant_id;
  identity.graph_id = (gchar *) graph_id;
  identity.store_uuid = (gchar *) store_uuid;
  identity.format_version = 1;
  identity.path_encoding_version = 1;
  return identity;
}

static gchar *
run_provision_helper (void)
{
  const gchar *argv[] = {
    provision_helper_path,
    tenant_id,
    graph_id,
    operation_uuid,
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
  g_assert_cmpuint (length, >, 1);
  g_assert_cmpint (stdout_text[length - 1], ==, '\n');
  g_assert_null (memchr (stdout_text, '\n', length - 1));
  g_assert_null (memchr (stdout_text, '\r', length));
  stdout_text[length - 1] = '\0';
  g_assert_true (g_path_is_absolute (stdout_text));
  return g_steal_pointer (&stdout_text);
}

static void
assert_retained_pair (const gchar *root)
{
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  g_autofree gchar *stage_basename =
      g_strdup_printf ("provision-%s.sqlite", operation_uuid);
  g_autofree gchar *stage_path = g_build_filename (root, tenant_component,
          graph_component, stage_basename, NULL);
  struct stat final_status;
  struct stat stage_status;
  g_assert_cmpint (stat (final_path, &final_status), ==, 0);
  g_assert_cmpint (stat (stage_path, &stage_status), ==, 0);
  g_assert_true (S_ISREG (final_status.st_mode));
  g_assert_true (S_ISREG (stage_status.st_mode));
  g_assert_cmpuint (final_status.st_mode & 0777, ==, 0600);
  g_assert_cmpuint (stage_status.st_mode & 0777, ==, 0600);
  g_assert_cmpuint (final_status.st_dev, ==, stage_status.st_dev);
  g_assert_cmpuint (final_status.st_ino, ==, stage_status.st_ino);
  g_assert_cmpuint (final_status.st_nlink, ==, 2);
  g_assert_cmpuint (stage_status.st_nlink, ==, 2);
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
open_live (const gchar *root, wyl_fact_store_t **out_store)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphProvisionedPair *pair = NULL;
  WylFactStoreIdentity identity = make_identity ();

  wyrelog_error_t rc = wyl_fact_graph_resolver_open (root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, tenant_id, graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator, FALSE,
            &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            operation_uuid, &pair);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_store_open_provisioned_pair (pair, &identity, TRUE,
            out_store);

  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  return rc;
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
  g_autofree gchar *root = run_provision_helper ();
  assert_retained_pair (root);

  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (open_live (root, &store), ==, WYRELOG_E_OK);
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

  g_assert_cmpint (open_live (root, &store), ==, WYRELOG_E_OK);
  conn = wyl_fact_store_get_connection (store);
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'COMPLETED';"),
      ==, 1);
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_audit;"), ==, 1);
  wyl_fact_store_close (store);
  assert_retained_pair (root);
  remove_root (root);
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

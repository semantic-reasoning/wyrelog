/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "fact-test-support.h"
#include "fact/graph-locator-private.h"
#include "fact/provisioning-construct-private.h"
#include "fact/store-private.h"

static const gchar operation_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070891";
static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070892";
static const gchar tenant_id[] = "tenant-provision";
static const gchar graph_id[] = "graph-provision";

typedef struct
{
  guint commit_calls;
  guint rollback_calls;
} TransactionFault;

static WylPolicyGraphProvisioningRecord
make_record (void)
{
  WylPolicyGraphProvisioningRecord record = { 0 };
  record.op_uuid = (gchar *) operation_uuid;
  record.tenant_id = (gchar *) tenant_id;
  record.graph_id = (gchar *) graph_id;
  record.store_uuid = (gchar *) store_uuid;
  record.stage_basename = (gchar *)
      "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070891.sqlite";
  record.expected_lifecycle_generation = 1;
  record.expected_reconciliation_generation = 0;
  record.phase = WYL_POLICY_GRAPH_PROVISIONING_RESERVED;
  return record;
}

static WylPolicyGraphAuthorityRecord
make_authority (void)
{
  WylPolicyGraphAuthorityRecord authority = { 0 };
  authority.tenant_id = (gchar *) tenant_id;
  authority.graph_id = (gchar *) graph_id;
  authority.lifecycle_state = WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING;
  authority.store_uuid = (gchar *) store_uuid;
  authority.format_version = 1;
  authority.path_encoding_version = 1;
  authority.lifecycle_generation = 1;
  authority.reconciliation_generation = 0;
  authority.has_store_identity = TRUE;
  return authority;
}

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
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-forget-transaction-XXXXXX", &error);
  g_assert_no_error (error);
  WylPolicyGraphProvisioningRecord record = make_record ();
  WylPolicyGraphAuthorityRecord authority = make_authority ();
  g_assert_cmpint (wyl_fact_graph_provisioning_construct (root, &record,
      &authority), ==, WYRELOG_E_OK);

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
  remove_root (root);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-store/forget-transaction/provisioned-commit-failure",
      test_provisioned_commit_failure_rolls_back);
  return g_test_run ();
}

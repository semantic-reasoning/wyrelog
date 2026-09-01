/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/store-test-seams-private.h"
#include "wyrelog/wyl-log-private.h"

typedef struct
{
  guint fail_mask;
  guint calls[2];
} TransactionFault;

typedef struct
{
  wyl_fact_store_t *store;
  wyl_policy_fact_relation_schema_options_t schema;
  wyl_policy_fact_relation_schema_column_t columns[2];
} Fixture;

#define PHASE_BIT(phase) (1u << (guint) (phase))

static gboolean
exec_ok (wyl_fact_store_t *store, const gchar *sql)
{
  return wyl_fact_store_test_exec_sql (store, sql) == WYRELOG_E_OK;
}

static gint64
count_rows (wyl_fact_store_t *store, const gchar *sql)
{
  gint64 count = -1;
  g_assert_cmpint (wyl_fact_store_test_query_int64 (store, sql, &count), ==,
      WYRELOG_E_OK);
  return count;
}

static wyrelog_error_t
transaction_fault (WylFactStoreTransactionTestKind kind,
    WylFactStoreTransactionTestPhase phase, gpointer user_data)
{
  TransactionFault *fault = user_data;
  g_assert_cmpint (kind, ==,
      WYL_FACT_STORE_TRANSACTION_TEST_FORGET_COMPLETE);
  g_assert_cmpuint ((guint) phase, <, G_N_ELEMENTS (fault->calls));
  fault->calls[phase]++;
  guint bit = PHASE_BIT (phase);
  if ((fault->fail_mask & bit) != 0) {
    fault->fail_mask &= ~bit;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
fail_forget_body (WylFactStoreForgetTransactionTestPhase phase,
    gpointer user_data)
{
  (void) user_data;
  return phase == WYL_FACT_STORE_FORGET_TRANSACTION_AFTER_BEGIN ?
         WYRELOG_E_IO : WYRELOG_E_OK;
}

static void
fixture_setup (Fixture *fixture, gconstpointer user_data)
{
  (void) user_data;
  fixture->columns[0] = (wyl_policy_fact_relation_schema_column_t) {
    "order_id", "symbol", FALSE, TRUE
  };
  fixture->columns[1] = (wyl_policy_fact_relation_schema_column_t) {
    "amount", "int64", FALSE, TRUE
  };
  fixture->schema = (wyl_policy_fact_relation_schema_options_t) {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = fixture->columns,
    .n_columns = G_N_ELEMENTS (fixture->columns),
  };
  g_assert_cmpint (wyl_fact_store_open (NULL, &fixture->store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (fixture->store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_ensure_projection (fixture->store,
      &fixture->schema, NULL), ==, WYRELOG_E_OK);

  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "o-1"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 42},
  };
  const wyl_fact_row_t rows[] = {
    {values, G_N_ELEMENTS (values)},
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "transaction-fault",
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "order",
    .schema_version = 1,
    .source = "unit-test",
    .idempotency_key = "transaction-fault:1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (fixture->store,
      &fixture->schema, &batch, &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
}

static void
fixture_teardown (Fixture *fixture, gconstpointer user_data)
{
  (void) user_data;
  wyl_fact_store_set_forget_transaction_test_hook (fixture->store, NULL, NULL);
  wyl_fact_store_test_set_transaction_hook (fixture->store, NULL, NULL);
  wyl_fact_store_close (fixture->store);
}

static wyrelog_error_t
forget (Fixture *fixture)
{
  const wyl_fact_store_forget_options_t opts = {
    .op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070890",
    .batch_id = "transaction-fault",
    .operator_id = "admin",
    .reason = "transaction-boundary-test",
  };
  return wyl_fact_store_forget (fixture->store, &fixture->schema, &opts, NULL);
}

static void
assert_pending_without_audit (Fixture *fixture)
{
  wyl_fact_store_t *conn = fixture->store;
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'PENDING';"),
      ==, 1);
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_audit;"), ==, 0);
}

/* An aborted DuckDB transaction that nobody resolved does not merely lose the
 * forget: it fails every later statement on the connection, a later BEGIN
 * included, until something issues a ROLLBACK.  All three statements below
 * fail in that state, which is why the check is all three rather than a
 * SELECT alone. */
static void
assert_connection_accepts_new_transaction (Fixture *fixture)
{
  wyl_fact_store_t *conn = fixture->store;
  g_assert_true (exec_ok (conn, "SELECT 1;"));
  g_assert_true (exec_ok (conn, "BEGIN TRANSACTION;"));
  g_assert_true (exec_ok (conn, "ROLLBACK;"));
}

static void
assert_reconciles (Fixture *fixture)
{
  wyl_fact_forget_outcome_t outcome = { 0 };
  g_assert_cmpint (wyl_fact_store_forget_reconcile (fixture->store, "tenant-a",
      "orders", NULL, NULL, &outcome), ==, WYRELOG_E_OK);
  wyl_fact_store_t *conn = fixture->store;
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_intent WHERE state = 'COMPLETED';"),
      ==, 1);
  g_assert_cmpint (count_rows (conn,
      "SELECT COUNT(*) FROM fact_forget_audit;"), ==, 1);
}

static void
test_unarmed_control_commits (Fixture *fixture, gconstpointer user_data)
{
  (void) user_data;
  TransactionFault fault = { 0 };
  wyl_fact_store_test_set_transaction_hook (fixture->store,
      transaction_fault, &fault);
  g_assert_cmpint (forget (fixture), ==, WYRELOG_E_OK);
  g_assert_cmpuint (
    fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT],
    ==, 1);
  g_assert_cmpuint (
    fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK], ==, 0);
  assert_connection_accepts_new_transaction (fixture);
}

static void
test_commit_failure_rolls_back (Fixture *fixture, gconstpointer user_data)
{
  (void) user_data;
  TransactionFault fault = {
    .fail_mask = PHASE_BIT (WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT),
  };
  wyl_fact_store_test_set_transaction_hook (fixture->store,
      transaction_fault, &fault);
  g_assert_cmpint (forget (fixture), ==, WYRELOG_E_IO);
  g_assert_cmpuint (
    fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT],
    ==, 1);
  g_assert_cmpuint (
    fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK], ==, 1);
  /* Before the state assertions, because every one of them queries this same
   * connection: an unresolved abort makes them fail too, and then the failure
   * names a wrong row count instead of the poisoned connection that caused
   * it.  Asking the connection first is what makes the diagnostic point at
   * the defect. */
  assert_connection_accepts_new_transaction (fixture);
  assert_pending_without_audit (fixture);
  wyl_fact_store_test_set_transaction_hook (fixture->store, NULL, NULL);
  assert_reconciles (fixture);
}

static void
test_body_failure_rolls_back (Fixture *fixture, gconstpointer user_data)
{
  (void) user_data;
  TransactionFault fault = { 0 };
  wyl_fact_store_set_forget_transaction_test_hook (fixture->store,
      fail_forget_body, NULL);
  wyl_fact_store_test_set_transaction_hook (fixture->store,
      transaction_fault, &fault);
  g_assert_cmpint (forget (fixture), ==, WYRELOG_E_IO);
  g_assert_cmpuint (
    fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT],
    ==, 0);
  g_assert_cmpuint (
    fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK], ==, 1);
  /* Before the state assertions, because every one of them queries this same
   * connection: an unresolved abort makes them fail too, and then the failure
   * names a wrong row count instead of the poisoned connection that caused
   * it.  Asking the connection first is what makes the diagnostic point at
   * the defect. */
  assert_connection_accepts_new_transaction (fixture);
  assert_pending_without_audit (fixture);
}

static void
test_rollback_failure_is_reported (Fixture *fixture, gconstpointer user_data)
{
  (void) user_data;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *log_dir = g_dir_make_tmp ("wyl-forget-log-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *log_path = g_build_filename (log_dir, "wyrelog.log", NULL);
  g_setenv ("WYL_LOG_FILE", log_path, TRUE);
  g_setenv ("WYL_LOG", "IO:error", TRUE);
  wyl_log_internal_reconfigure ();

  TransactionFault fault = {
    .fail_mask =
        PHASE_BIT (WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT)
        | PHASE_BIT (WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK),
  };
  wyl_fact_store_test_set_transaction_hook (fixture->store,
      transaction_fault, &fault);
  g_assert_cmpint (forget (fixture), ==, WYRELOG_E_INTERNAL);
  g_assert_cmpuint (
    fault.calls[WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK], ==, 1);

  g_unsetenv ("WYL_LOG_FILE");
  g_unsetenv ("WYL_LOG");
  wyl_log_internal_reconfigure ();
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (log_path, &contents, NULL, &error));
  g_assert_no_error (error);
  g_auto (GStrv) messages = g_strsplit (contents,
          "fact forget transaction rollback failed", -1);
  g_assert_cmpuint (g_strv_length (messages), ==, 2);
  g_assert_null (g_strstr_len (contents, -1, "tenant-a"));
  g_assert_null (g_strstr_len (contents, -1, "orders"));
  g_assert_null (g_strstr_len (contents, -1, "transaction-fault"));
  g_assert_null (g_strstr_len (contents, -1, "transaction-boundary-test"));

  wyl_fact_store_test_set_transaction_hook (fixture->store, NULL, NULL);
  g_assert_cmpint (wyl_fact_store_create_schema (fixture->store), ==,
      WYRELOG_E_INTERNAL);

  g_assert_cmpint (g_remove (log_path), ==, 0);
  g_assert_cmpint (g_rmdir (log_dir), ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
#define ADD_TEST(path, function) \
  g_test_add ((path), Fixture, NULL, fixture_setup, (function), \
      fixture_teardown)
  ADD_TEST ("/fact-store/forget-transaction/unarmed-control",
      test_unarmed_control_commits);
  ADD_TEST ("/fact-store/forget-transaction/commit-failure",
      test_commit_failure_rolls_back);
  ADD_TEST ("/fact-store/forget-transaction/body-failure",
      test_body_failure_rolls_back);
  ADD_TEST ("/fact-store/forget-transaction/rollback-failure",
      test_rollback_failure_is_reported);
#undef ADD_TEST
  return g_test_run ();
}

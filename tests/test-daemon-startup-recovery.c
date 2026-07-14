/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/audit/conn-private.h"
#include "wyrelog/auth/service-exchange-projector-private.h"
#include "wyrelog/daemon/startup-recovery-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

typedef struct
{
  gchar *dir;
  gchar *policy_path;
  gchar *audit_path;
  WylHandle *handle;
} Fixture;

static void
fixture_open (Fixture *f)
{
  WylHandleOpenOptions options = {
    .policy_store_path = f->policy_path,
    .audit_store_path = f->audit_path,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &f->handle), ==,
      WYRELOG_E_OK);
}

static void
fixture_init (Fixture *f)
{
  f->dir = g_dir_make_tmp ("wyl-startup-recovery-XXXXXX", NULL);
  g_assert_nonnull (f->dir);
  f->policy_path = g_build_filename (f->dir, "policy.db", NULL);
  f->audit_path = g_build_filename (f->dir, "audit.duckdb", NULL);
  fixture_open (f);
}

static void
fixture_clear (Fixture *f)
{
  g_clear_object (&f->handle);
  g_remove (f->audit_path);
  g_remove (f->policy_path);
  g_rmdir (f->dir);
  g_free (f->audit_path);
  g_free (f->policy_path);
  g_free (f->dir);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Fixture, fixture_clear);

static wyl_service_exchange_audit_input_t
make_input (void)
{
  wyl_service_exchange_audit_input_t input = {
    .request_id = {"000000000000000000000000000", 27},
    .credential_id = {"wlc_000000000000000000000000000", 31},
    .credential_generation = 1,
    .service_principal = {"svc:startup", 11},
    .tenant_id = {"tenant-a", 8},
    .session_id = {"01890f47-3c4b-7cc2-98c4-dc0c0c07398f", 36},
    .jti = {"01890f47-3c4b-7cc2-a8c4-dc0c0c073990", 36},
    .created_at_us = 10,
  };
  g_assert_cmpint (wyl_id_parse ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
          &input.intention_id), ==, WYRELOG_E_OK);
  return input;
}

static gint64
projection_count (WylHandle *handle)
{
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_audit_conn_get_connection
          (wyl_handle_get_audit_conn (handle)),
          "SELECT count(*) FROM service_exchange_receipt_projections;",
          &result), ==, DuckDBSuccess);
  gint64 count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return count;
}

static void
seed_response_loss (WylHandle *handle)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  WylServiceAuthorityTransaction *txn = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_fail_once (store,
      WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (txn, store, &evidence), ==, WYRELOG_E_OK);
  WylServiceAuthorityWriteIntentOutcome outcome = { 0 };
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &outcome), ==, WYRELOG_E_OK);
  wyl_service_exchange_audit_input_t input = make_input ();
  WylServiceExchangeIntentionClassification classification = 0;
  g_autoptr (WylServiceExchangeIntentionRecord) record = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (txn,
          store, &input, &classification, &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit (txn),
      !=, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (handle), ==, 0);

  wyl_policy_store_service_authority_transaction_free (txn);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_empty_startup_succeeds (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  g_assert_cmpint (wyl_daemon_recover_service_exchange_on_startup (f.handle),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 0);
}

static void
test_response_loss_restart_is_synchronous_and_idempotent (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  seed_response_loss (f.handle);
  g_clear_object (&f.handle);

  fixture_open (&f);
  g_assert_cmpint (wyl_daemon_recover_service_exchange_on_startup (f.handle),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);
  g_clear_object (&f.handle);

  fixture_open (&f);
  g_assert_cmpint (wyl_daemon_recover_service_exchange_on_startup (f.handle),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);
}

static void
test_startup_failure_is_fail_closed (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  seed_response_loss (f.handle);

  wyl_service_exchange_recovery_fail_enumerate_for_test
      (WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_STEP);
  g_assert_cmpint (wyl_daemon_recover_service_exchange_on_startup (f.handle),
      !=, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 0);
  g_assert_cmpint (wyl_daemon_recover_service_exchange_on_startup (f.handle),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);

  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_audit_conn_get_connection
          (wyl_handle_get_audit_conn (f.handle)),
          "UPDATE service_exchange_receipt_projections "
          "SET tenant_id='corrupt';", &result), ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
  g_assert_cmpint (wyl_daemon_recover_service_exchange_on_startup (f.handle),
      ==, WYRELOG_E_POLICY);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/daemon/startup-recovery/empty",
      test_empty_startup_succeeds);
  g_test_add_func ("/daemon/startup-recovery/response-loss-restart",
      test_response_loss_restart_is_synchronous_and_idempotent);
  g_test_add_func ("/daemon/startup-recovery/fail-closed",
      test_startup_failure_is_fail_closed);
  return g_test_run ();
}

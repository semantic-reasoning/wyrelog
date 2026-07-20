/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <string.h>

#include "auth/service-credential-operation-coordinator-retirement-private.h"
#include "wyl-handle-private.h"
#include "wyl-request-id-private.h"

typedef struct
{
  gchar *root;
  gchar *db_path;
  gchar *key_path;
  gchar *key_spec;
  WylHandle *handle;
  WylServiceCredentialOperationStorage storage;
  WylServiceCredentialOperationRootAnchor anchor;
} Fixture;

static void
remove_directory_children (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  const gchar *entry;

  if (directory == NULL)
    return;
  while ((entry = g_dir_read_name (directory)) != NULL) {
    g_autofree gchar *child = g_build_filename (path, entry, NULL);
    (void) g_remove (child);
  }
}

static void
fixture_clear (Fixture *fixture)
{
  wyl_service_credential_operation_storage_clear (&fixture->storage);
  g_clear_object (&fixture->handle);
  remove_directory_children (fixture->root);
  if (fixture->root != NULL)
    (void) g_rmdir (fixture->root);
  g_free (fixture->key_spec);
  g_free (fixture->key_path);
  g_free (fixture->db_path);
  g_free (fixture->root);
  memset (fixture, 0, sizeof *fixture);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Fixture, fixture_clear);

static void
fixture_init (Fixture *fixture)
{
  *fixture = (Fixture) {
  .storage = WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT,.anchor =
        WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT,};
  fixture->root = g_dir_make_tmp ("wyl-retirement-coordinator-XXXXXX", NULL);
  g_assert_nonnull (fixture->root);
  fixture->db_path = g_build_filename (fixture->root, "policy.db", NULL);
  fixture->key_path = g_build_filename (fixture->root, "policy.key", NULL);
  guint8 key[32];
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) (i + 1);
  g_assert_true (g_file_set_contents (fixture->key_path,
          (const gchar *) key, sizeof key, NULL));
  fixture->key_spec = g_strdup_printf ("file:%s", fixture->key_path);
  WylHandleOpenOptions options = {
    .policy_store_path = fixture->db_path,
    .policy_keyprovider_path = fixture->key_spec,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &fixture->handle),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (fixture->root, &fixture->storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&fixture->storage, &fixture->anchor), ==, WYRELOG_E_OK);
}

static WylServiceCredentialOperationCoordinatorRequest
request_new (void)
{
  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request_id, sizeof request_id), ==,
      WYRELOG_E_OK);
  request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  request.request_id = g_strdup (request_id);
  request.subject_id = g_strdup ("subject");
  request.tenant_id = g_strdup ("tenant-a");
  request.destination = g_strdup ("handoff.json");
  request.parent_identity = g_strdup ("parent-v1");
  request.actor_subject_id = g_strdup ("admin");
  request.escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991");
  for (guint i = 0; i < sizeof request.escrow_binding_digest; i++)
    request.escrow_binding_digest[i] = (guint8) (i + 1);
  request.expires_at_us = g_get_real_time () + G_TIME_SPAN_HOUR;
  return request;
}

static void
assert_missing (Fixture *fixture, const gchar *request_id)
{
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, request_id, &record), ==,
      WYRELOG_E_NOT_FOUND);
  wyl_service_credential_operation_record_clear (&record);
}

static void
test_guarded_begin_fresh_replay_and_collision (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylServiceCredentialOperationCoordinatorRequest request = request_new ();
  WylServiceCredentialOperationGuardedBeginResult result =
      WYL_SERVICE_CREDENTIAL_OPERATION_GUARDED_BEGIN_RESULT_INIT;

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded
      (fixture.handle, &fixture.storage, &fixture.anchor, &request, NULL,
          &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  g_assert_cmpstr (result.record.request_id, ==, request.request_id);
  wyl_service_credential_operation_guarded_begin_result_clear (&result);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded
      (fixture.handle, &fixture.storage, &fixture.anchor, &request, NULL,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_operation_guarded_begin_result_clear (&result);

  g_autofree gchar *original_destination = request.destination;
  request.destination = g_strdup ("different.json");
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded
      (fixture.handle, &fixture.storage, &fixture.anchor, &request, NULL,
          &result), ==, WYRELOG_E_POLICY);
  request.destination = g_steal_pointer (&original_destination);
  wyl_service_credential_operation_guarded_begin_result_clear (&result);
  wyl_service_credential_operation_coordinator_request_clear (&request);
}

static void
test_missing_and_cancelled_have_no_effects (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylServiceCredentialOperationCoordinatorRequest request = request_new ();
  WylServiceCredentialOperationRetirementResult retirement =
      WYL_SERVICE_CREDENTIAL_OPERATION_RETIREMENT_RESULT_INIT;
  WylServiceCredentialOperationGuardedBeginResult begin =
      WYL_SERVICE_CREDENTIAL_OPERATION_GUARDED_BEGIN_RESULT_INIT;

  g_assert_cmpint (wyl_service_credential_operation_coordinator_purge_retired
      (fixture.handle, &fixture.storage, &fixture.anchor, request.request_id,
          NULL, &retirement), ==, WYRELOG_E_NOT_FOUND);
  assert_missing (&fixture, request.request_id);
  g_autoptr (GCancellable) cancelled = g_cancellable_new ();
  g_cancellable_cancel (cancelled);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded
      (fixture.handle, &fixture.storage, &fixture.anchor, &request, cancelled,
          &begin), ==, WYRELOG_E_BUSY);
  assert_missing (&fixture, request.request_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_purge_retired
      (fixture.handle, &fixture.storage, &fixture.anchor, request.request_id,
          cancelled, &retirement), ==, WYRELOG_E_BUSY);
  assert_missing (&fixture, request.request_id);
  wyl_service_credential_operation_guarded_begin_result_clear (&begin);
  wyl_service_credential_operation_retirement_result_clear (&retirement);
  wyl_service_credential_operation_coordinator_request_clear (&request);
}

static void
test_raw_begin_requires_matching_lifecycle (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylServiceCredentialOperationCoordinatorRequest first = request_new ();
  WylServiceCredentialOperationCoordinatorRequest second = request_new ();
  WylServiceCredentialOperationCoordinatorLock first_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = FALSE;

  g_assert_cmpint (wyl_service_credential_operation_coordinator_lock_acquire
      (&fixture.storage, &fixture.anchor, first.request_id, &first_lock), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_locked_for_test
      (&fixture.storage, &fixture.anchor, &first_lock, &second,
          g_get_real_time (), &replayed, &record), ==, WYRELOG_E_POLICY);
  wyl_service_credential_operation_coordinator_lock_release (&fixture.storage,
      &fixture.anchor, &first_lock);
  assert_missing (&fixture, second.request_id);
  wyl_service_credential_operation_record_clear (&record);
  wyl_service_credential_operation_coordinator_request_clear (&second);
  wyl_service_credential_operation_coordinator_request_clear (&first);
}

static void
test_corrupt_receipt_fails_closed_without_create (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylServiceCredentialOperationCoordinatorRequest request = request_new ();
  WylServiceCredentialOperationGuardedBeginResult result =
      WYL_SERVICE_CREDENTIAL_OPERATION_GUARDED_BEGIN_RESULT_INIT;
  g_autofree gchar *sql =
      g_strdup_printf
      ("INSERT INTO service_credential_handoff_retirement_receipts("
      "original_request_id,terminal_kind,raw_journal_snapshot_digest,"
      "delivery_disposition_id,delivery_audit_id,delivery_proof_digest,"
      "revoke_remediation_request_id,revoke_audit_id,revoke_event_id,"
      "resume_remediation_request_id,resume_audit_id,"
      "remediation_source_snapshot_digest,remediation_request_fingerprint,"
      "retention_basis_at_us,retired_at_us) VALUES("
      "'%s','file_published',randomblob(32),"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073991',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073992',randomblob(32),"
      "NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,2592000000001);",
      request.request_id);
  gchar *message = NULL;
  sqlite3 *db = wyl_policy_store_get_db
      (wyl_handle_get_policy_store (fixture.handle));
  g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, &message), ==, SQLITE_OK);
  sqlite3_free (message);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded
      (fixture.handle, &fixture.storage, &fixture.anchor, &request, NULL,
          &result), ==, WYRELOG_E_POLICY);
  assert_missing (&fixture, request.request_id);
  wyl_service_credential_operation_guarded_begin_result_clear (&result);
  wyl_service_credential_operation_coordinator_request_clear (&request);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/coordinator/retirement/guarded-begin",
      test_guarded_begin_fresh_replay_and_collision);
  g_test_add_func ("/coordinator/retirement/missing-cancelled",
      test_missing_and_cancelled_have_no_effects);
  g_test_add_func ("/coordinator/retirement/raw-lock-match",
      test_raw_begin_requires_matching_lifecycle);
  g_test_add_func ("/coordinator/retirement/corrupt-receipt",
      test_corrupt_receipt_fails_closed_without_create);
  return g_test_run ();
}

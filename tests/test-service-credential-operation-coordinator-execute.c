/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <string.h>

#include "auth/service-credential-operation-coordinator-execute-private.h"
#include "auth/service-credential-domain-private.h"
#include "auth/service-credential-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyl-request-id-private.h"

#define ROTATE_CANONICAL_ID "wlc_000000000000000000000000000"

typedef struct
{
  WylHandle *handle;
  gchar *dir;
  gchar *db_path;
  gchar *audit_path;
  gchar *key_path;
  gchar *key_spec;
} Fixture;

typedef struct
{
  guint calls;
  wyrelog_error_t rc;
  gchar *seen_actor;
} Stub;

static wyrelog_error_t
stub_revalidate (gpointer data, const gchar *actor_subject_id)
{
  Stub *stub = data;
  stub->calls++;
  g_free (stub->seen_actor);
  stub->seen_actor = g_strdup (actor_subject_id);
  return stub->rc;
}

static void
fixture_clear (Fixture *fixture)
{
  g_clear_object (&fixture->handle);
  if (fixture->db_path != NULL) {
    (void) g_remove (fixture->db_path);
    g_autofree gchar *clear = g_strdup_printf ("%s.wyrelog-clear",
        fixture->db_path);
    g_autofree gchar *lock = g_strdup_printf ("%s.wyrelog-lock",
        fixture->db_path);
    (void) g_remove (clear);
    (void) g_remove (lock);
  }
  if (fixture->key_path != NULL)
    (void) g_remove (fixture->key_path);
  if (fixture->audit_path != NULL)
    (void) g_remove (fixture->audit_path);
  if (fixture->dir != NULL)
    (void) g_rmdir (fixture->dir);
  g_free (fixture->key_spec);
  g_free (fixture->key_path);
  g_free (fixture->audit_path);
  g_free (fixture->db_path);
  g_free (fixture->dir);
  memset (fixture, 0, sizeof (*fixture));
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Fixture, fixture_clear);

static void
fixture_init (Fixture *fixture)
{
  fixture->dir = g_dir_make_tmp ("wyl-credential-execute-XXXXXX", NULL);
  g_assert_nonnull (fixture->dir);
  fixture->db_path = g_build_filename (fixture->dir, "policy.db", NULL);
  fixture->key_path = g_build_filename (fixture->dir, "policy.key", NULL);
  fixture->audit_path = g_build_filename (fixture->dir, "audit.db", NULL);
  guint8 key[32];
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) (i + 1);
  g_assert_true (g_file_set_contents (fixture->key_path,
          (const gchar *) key, sizeof key, NULL));
  fixture->key_spec = g_strdup_printf ("file:%s", fixture->key_path);
  WylHandleOpenOptions options = {
    .policy_store_path = fixture->db_path,
    .policy_keyprovider_path = fixture->key_spec,
    .audit_store_path = fixture->audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &fixture->handle),
      ==, WYRELOG_E_OK);
}

static wyl_policy_store_t *
store_of (WylHandle *handle)
{
  return wyl_handle_get_policy_store (handle);
}

static sqlite3 *
db_of (WylHandle *handle)
{
  return wyl_policy_store_get_db (store_of (handle));
}

static gint64
scalar (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static gboolean
contains_bytes (const guint8 *haystack, gsize haystack_len,
    const guint8 *needle, gsize needle_len)
{
  if (needle_len > haystack_len)
    return FALSE;
  for (gsize i = 0; i <= haystack_len - needle_len; i++)
    if (memcmp (haystack + i, needle, needle_len) == 0)
      return TRUE;
  return FALSE;
}

static gint64
like_scan (sqlite3 *db, const gchar *sql, const gchar *secret)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_autofree gchar *pattern = g_strdup_printf ("%%%s%%", secret);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, pattern, -1, SQLITE_TRANSIENT),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static void
prepare_authority (WylHandle *handle, const gchar *subject_id)
{
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, subject_id,
          subject_id, "admin", "principal-create", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store_of (handle),
          "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
}

static void
fresh_request_id (gchar *buf)
{
  g_assert_cmpint (wyl_request_id_new (buf, WYL_REQUEST_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
}

static WylServiceCredentialOperationRecord
prepared_issue_record (const gchar *actor, const gchar *request_id,
    gint64 expiry)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED,
    .operation_id = g_strdup ("op-1"),
    .request_id = g_strdup (request_id),
    .subject_id = g_strdup ("svc:issue:worker"),
    .tenant_id = g_strdup ("tenant-a"),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup (actor),
    .old_credential_id = g_strdup (""),
    .successor_credential_id = g_strdup (""),
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = 0,
    .successor_generation = 0,
    .expires_at_us = expiry,
    .created_at_us = 100,
    .updated_at_us = 100,
  };
  g_assert_true (wyl_service_credential_operation_record_is_valid (&record));
  return record;
}

static WylServiceCredentialOperationRecord
prepared_rotate_record (const gchar *actor, const gchar *request_id,
    const gchar *old_credential_id, guint64 expected_generation, gint64 expiry)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED,
    .operation_id = g_strdup ("op-1"),
    .request_id = g_strdup (request_id),
    .subject_id = g_strdup ("svc:rotate:worker"),
    .tenant_id = g_strdup (""),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup (actor),
    .old_credential_id = g_strdup (old_credential_id),
    .successor_credential_id = g_strdup (""),
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = expected_generation,
    .successor_generation = 0,
    .expires_at_us = expiry,
    .created_at_us = 100,
    .updated_at_us = 100,
  };
  g_assert_true (wyl_service_credential_operation_record_is_valid (&record));
  return record;
}

static WylServiceCredentialOperationRecord
server_committed_record (const gchar *actor, const gchar *request_id,
    gint64 expiry)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
    .operation_id = g_strdup ("op-1"),
    .request_id = g_strdup (request_id),
    .subject_id = g_strdup ("svc:issue:worker"),
    .tenant_id = g_strdup ("tenant-a"),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup (actor),
    .old_credential_id = g_strdup (""),
    .successor_credential_id = g_strdup (ROTATE_CANONICAL_ID),
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = 0,
    .successor_generation = 1,
    .expires_at_us = expiry,
    .created_at_us = 100,
    .updated_at_us = 100,
  };
  for (guint i = 0; i < sizeof record.escrow_binding_digest; i++)
    record.escrow_binding_digest[i] = (guint8) (i + 1);
  g_assert_true (wyl_service_credential_operation_record_is_valid (&record));
  return record;
}

static gint64
count_credentials (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM service_credentials;");
}

static gint64
count_events (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM service_credential_events;");
}

static gint64
count_audits (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM audit_events;");
}

static gint64
count_requests (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM service_domain_requests;");
}

static void
test_issue_success (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint (count_credentials (db), ==, 0);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);
  g_assert_cmpstr (out.credential.subject_id, ==, "svc:issue:worker");
  g_assert_cmpstr (out.credential.tenant_id, ==, "tenant-a");
  g_assert_cmpuint (out.credential.generation, ==, 1);
  g_assert_cmpuint (stub.calls, ==, 1);
  g_assert_cmpstr (stub.seen_actor, ==, "admin");

  g_assert_cmpint (count_credentials (db), ==, 1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM service_credential_events "
          "WHERE event='issued' AND actor_subject_id='admin';"), ==, 1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM audit_events "
          "WHERE action='service.credential.issue' AND subject_id='admin';"),
      ==, 1);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

static void
test_rotate_success (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:rotate:worker");
  sqlite3 *db = db_of (handle);

  gchar issue_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (issue_request);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  wyl_service_credential_issue_result_t seed = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:rotate:worker",
          "tenant-a", "admin", issue_request, expiry, &seed), ==, WYRELOG_E_OK);
  g_autofree gchar *old_id = g_strdup (seed.credential.credential_id);
  guint64 generation = seed.credential.generation;
  g_assert_cmpuint (generation, ==, 1);
  wyl_service_credential_issue_result_clear (&seed);

  gchar rotate_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (rotate_request);
  WylServiceCredentialOperationRecord record =
      prepared_rotate_record ("admin", rotate_request, old_id, generation,
      expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .old_credential_generation = generation,
  };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
    .rotate_runtime = &rotate_runtime,
  };
  wyl_service_credential_issue_result_t out = { 0 };

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);
  g_assert_cmpstr (out.credential.subject_id, ==, "svc:rotate:worker");
  g_assert_cmpstr (out.credential.rotated_from_id, ==, old_id);
  g_assert_cmpuint (stub.calls, ==, 1);
  g_assert_cmpstr (stub.seen_actor, ==, "admin");
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM service_credentials WHERE state='active';"),
      ==, 1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM audit_events "
          "WHERE action='service.credential.rotate' AND subject_id='admin';"),
      ==, 1);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

static void
test_actor_mismatch (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  gint64 before_creds = count_credentials (db);
  gint64 before_events = count_events (db);
  gint64 before_audits = count_audits (db);
  gint64 before_requests = count_requests (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "mallory", &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpuint (stub.calls, ==, 0);
  g_assert_cmpint (count_credentials (db), ==, before_creds);
  g_assert_cmpint (count_events (db), ==, before_events);
  g_assert_cmpint (count_audits (db), ==, before_audits);
  g_assert_cmpint (count_requests (db), ==, before_requests);

  wyl_service_credential_operation_record_clear (&record);
}

static void
test_permission_loss (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_POLICY };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  gint64 before_creds = count_credentials (db);
  gint64 before_events = count_events (db);
  gint64 before_audits = count_audits (db);
  gint64 before_requests = count_requests (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpuint (stub.calls, ==, 1);
  g_assert_cmpint (count_credentials (db), ==, before_creds);
  g_assert_cmpint (count_events (db), ==, before_events);
  g_assert_cmpint (count_audits (db), ==, before_audits);
  g_assert_cmpint (count_requests (db), ==, before_requests);

  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

/* Not a threaded race: exercises the durable request-id fence when the same
 * PREPARED intent is executed twice. Threaded concurrency of the mutation is
 * owned by the domain/fence suites. */
static void
test_duplicate_fence_idempotency (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };

  WylServiceCredentialOperationRecord first =
      prepared_issue_record ("admin", request_id, expiry);
  wyl_service_credential_issue_result_t out_first = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &first, "admin", &runtime, &out_first), ==, WYRELOG_E_OK);
  g_assert_nonnull (out_first.secret);

  WylServiceCredentialOperationRecord second =
      prepared_issue_record ("admin", request_id, expiry);
  wyl_service_credential_issue_result_t out_second = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &second, "admin", &runtime, &out_second), ==, WYRELOG_E_POLICY);
  g_assert_null (out_second.secret);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM service_credentials "
          "WHERE subject_id='svc:issue:worker' AND state='active';"), ==, 1);

  wyl_service_credential_issue_result_clear (&out_first);
  wyl_service_credential_operation_record_clear (&first);
  wyl_service_credential_operation_record_clear (&second);
  g_free (stub.seen_actor);
}

static void
test_output_byte_preservation (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);

  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (out.secret, &secret_len);
  g_assert_cmpuint (secret_len, ==, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  gboolean authenticated = FALSE;
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          out.credential.credential_id, secret, secret_len, &authenticated),
      ==, WYRELOG_E_OK);
  g_assert_true (authenticated);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

static void
test_no_secret_leakage (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);

  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (out.secret, &secret_len);
  g_autofree gchar *secret_copy = g_strndup (secret, secret_len);

  g_assert_cmpint (like_scan (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE "
          "coalesce(subject_id,'')||coalesce(action,'')||"
          "coalesce(resource_id,'')||coalesce(request_id,'') LIKE ?;",
          secret_copy), ==, 0);
  g_assert_cmpint (like_scan (db_of (handle),
          "SELECT count(*) FROM service_credential_events WHERE "
          "coalesce(credential_id,'')||coalesce(subject_id,'')||"
          "coalesce(tenant_id,'')||coalesce(actor_subject_id,'')||"
          "coalesce(request_id,'') LIKE ?;", secret_copy), ==, 0);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
  g_clear_object (&fixture.handle);

  g_autofree gchar *encrypted = NULL;
  gsize encrypted_len = 0;
  g_assert_true (g_file_get_contents (fixture.db_path, &encrypted,
          &encrypted_len, NULL));
  g_assert_false (contains_bytes ((const guint8 *) encrypted, encrypted_len,
          (const guint8 *) secret_copy, secret_len));
}

static void
test_state_guard_server_committed (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      server_committed_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  gint64 before_creds = count_credentials (db);
  gint64 before_events = count_events (db);
  gint64 before_audits = count_audits (db);
  gint64 before_requests = count_requests (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpuint (stub.calls, ==, 0);
  g_assert_cmpint (count_credentials (db), ==, before_creds);
  g_assert_cmpint (count_events (db), ==, before_events);
  g_assert_cmpint (count_audits (db), ==, before_audits);
  g_assert_cmpint (count_requests (db), ==, before_requests);

  wyl_service_credential_operation_record_clear (&record);
}

static void
test_dispatch_guards (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord issue =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };

  gint64 before_creds = count_credentials (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (NULL, &issue, "admin", &runtime, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, NULL, "admin", &runtime, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, NULL, &runtime, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, "admin", NULL, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, "admin", &runtime, NULL), ==, WYRELOG_E_INVALID);

  WylServiceCredentialOperationExecuteRuntime no_fn = {
    .revalidate = NULL,
    .revalidate_data = &stub,
  };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, "admin", &no_fn, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (stub.calls, ==, 0);

  /* ROTATE record with a NULL rotate_runtime -> WYRELOG_E_INVALID as a
   * structural argument check, before the authority callback ever fires. */
  gchar rotate_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (rotate_request);
  WylServiceCredentialOperationRecord rotate_missing =
      prepared_rotate_record ("admin", rotate_request, ROTATE_CANONICAL_ID, 1,
      expiry);
  WylServiceCredentialOperationExecuteRuntime rotate_no_runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
    .rotate_runtime = NULL,
  };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &rotate_missing, "admin", &rotate_no_runtime, &out), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpuint (stub.calls, ==, 0);

  /* ROTATE record whose bound generation disagrees with the CAS runtime
   * generation -> WYRELOG_E_POLICY before the authority callback fires, so a
   * request that can never execute leaves no audit side effect. */
  gchar mismatch_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (mismatch_request);
  WylServiceCredentialOperationRecord rotate_mismatch =
      prepared_rotate_record ("admin", mismatch_request, ROTATE_CANONICAL_ID, 1,
      expiry);
  wyl_service_credential_rotate_runtime_t bad_runtime = {
    .old_credential_generation = 2,
  };
  WylServiceCredentialOperationExecuteRuntime rotate_bad_gen = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
    .rotate_runtime = &bad_runtime,
  };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &rotate_mismatch, "admin", &rotate_bad_gen, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (stub.calls, ==, 0);
  g_assert_null (out.secret);
  g_assert_cmpint (count_credentials (db), ==, before_creds);

  wyl_service_credential_operation_record_clear (&issue);
  wyl_service_credential_operation_record_clear (&rotate_missing);
  wyl_service_credential_operation_record_clear (&rotate_mismatch);
  g_free (stub.seen_actor);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-credential-operation-execute/issue-success",
      test_issue_success);
  g_test_add_func ("/service-credential-operation-execute/rotate-success",
      test_rotate_success);
  g_test_add_func ("/service-credential-operation-execute/actor-mismatch",
      test_actor_mismatch);
  g_test_add_func ("/service-credential-operation-execute/permission-loss",
      test_permission_loss);
  g_test_add_func ("/service-credential-operation-execute/duplicate-fence",
      test_duplicate_fence_idempotency);
  g_test_add_func ("/service-credential-operation-execute/byte-preservation",
      test_output_byte_preservation);
  g_test_add_func ("/service-credential-operation-execute/no-secret-leakage",
      test_no_secret_leakage);
  g_test_add_func ("/service-credential-operation-execute/state-guard",
      test_state_guard_server_committed);
  g_test_add_func ("/service-credential-operation-execute/dispatch-guards",
      test_dispatch_guards);
  return g_test_run ();
}

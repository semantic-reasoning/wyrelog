/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <sqlite3.h>
#include <string.h>

#include "auth/service-credential-domain-private.h"
#include "policy/store-handoff-delivery-private.h"
#include "policy/store-handoff-maintenance-private.h"
#include "policy/store-handoff-retirement-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-request-id-private.h"

#define COLLISION_ID "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv"
#define SECOND_ID "wlc_000000000000000000000000000"

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
  gboolean called;
  gboolean fail;
  gchar *credential_id;
  guint64 generation;
} InvalidationProbe;

static wyrelog_error_t
probe_credential_invalidation (gpointer data, const gchar *credential_id,
    guint64 generation)
{
  InvalidationProbe *probe = data;
  if (probe == NULL)
    return WYRELOG_E_INVALID;
  probe->called = TRUE;
  g_free (probe->credential_id);
  probe->credential_id = g_strdup (credential_id);
  probe->generation = generation;
  return probe->fail ? WYRELOG_E_IO : WYRELOG_E_OK;
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
  fixture->dir = g_dir_make_tmp ("wyl-credential-domain-XXXXXX", NULL);
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

static void
exec_ok (sqlite3 *db, const gchar *sql)
{
  gchar *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
new_uuid_string (gchar out[WYL_ID_STRING_BUF])
{
  wyl_id_t id;
  g_assert_cmpint (wyl_id_new (&id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&id, out, WYL_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_policy_store_create_tenant (store_of (handle),
          "tenant-b", &created), ==, WYRELOG_E_OK);
}

static wyrelog_error_t
count_credential (const wyl_service_credential_t *credential,
    gpointer user_data)
{
  guint *count = user_data;
  g_assert_nonnull (credential->credential_id);
  (*count)++;
  return WYRELOG_E_OK;
}

static void
test_issue_metadata_and_sanitation (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");

  wyl_service_credential_issue_result_t first = { 0 };
  gint64 expiry = g_get_real_time () + G_USEC_PER_SEC * 60;
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:issue:worker",
          "tenant-a", "admin", "issue-a-1", expiry, &first), ==, WYRELOG_E_OK);
  g_assert_nonnull (first.secret);
  g_assert_true (wyl_service_credential_id_is_canonical
      (first.credential.credential_id,
          strlen (first.credential.credential_id)));
  g_assert_cmpstr (first.credential.subject_id, ==, "svc:issue:worker");
  g_assert_cmpstr (first.credential.tenant_id, ==, "tenant-a");
  g_assert_cmpuint (first.credential.generation, ==, 1);
  g_assert_cmpstr (first.credential.state, ==, "active");
  g_assert_cmpint (first.credential.expires_at_us, ==, expiry);
  g_assert_null (first.credential.rotated_from_id);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (first.secret, &secret_len);
  g_assert_cmpuint (secret_len, ==, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  g_autofree gchar *secret_copy = g_strndup (secret, secret_len);

  wyl_service_credential_t loaded = { 0 };
  g_assert_cmpint (wyl_service_credential_get (handle,
          first.credential.credential_id, &loaded), ==, WYRELOG_E_OK);
  g_assert_cmpstr (loaded.subject_id, ==, "svc:issue:worker");
  g_assert_cmpstr (loaded.tenant_id, ==, "tenant-a");
  wyl_service_credential_clear (&loaded);
  guint count = 0;
  g_assert_cmpint (wyl_service_credential_foreach (handle,
          "svc:issue:worker", "tenant-a", count_credential, &count), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (count, ==, 1);

  wyl_service_credential_issue_result_t second = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:issue:worker",
          "tenant-a", "admin", "issue-a-2", 0, &second), ==, WYRELOG_E_OK);
  wyl_service_credential_issue_result_t other_tenant = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:issue:worker",
          "tenant-b", "admin", "issue-b-1", 0, &other_tenant), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials WHERE state='active';"),
      ==, 3);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events WHERE event='issued';"),
      ==, 3);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events a JOIN audit_intentions i "
          "ON a.id=i.audit_id WHERE a.action='service.credential.issue' "
          "AND i.state='pending';"), ==, 3);

  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE "
          "coalesce(subject_id,'')||coalesce(action,'')||"
          "coalesce(resource_id,'')||coalesce(request_id,'') LIKE ?;", -1,
          &stmt, NULL), ==, SQLITE_OK);
  g_autofree gchar *pattern = g_strdup_printf ("%%%s%%", secret_copy);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, pattern, -1, SQLITE_TRANSIENT),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 0), ==, 0);
  sqlite3_finalize (stmt);
  g_assert_cmpint (sqlite3_prepare_v2 (db_of (handle),
          "SELECT count(*) FROM service_credential_events WHERE "
          "coalesce(credential_id,'')||coalesce(subject_id,'')||"
          "coalesce(tenant_id,'')||coalesce(actor_subject_id,'')||"
          "coalesce(request_id,'') LIKE ?;", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, pattern, -1, SQLITE_TRANSIENT),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 0), ==, 0);
  sqlite3_finalize (stmt);

  g_autofree gchar *reopen_id = g_strdup (first.credential.credential_id);

  wyl_service_credential_issue_result_clear (&first);
  wyl_service_credential_issue_result_clear (&second);
  wyl_service_credential_issue_result_clear (&other_tenant);
  g_clear_object (&fixture.handle);
  g_autofree gchar *encrypted = NULL;
  gsize encrypted_len = 0;
  g_assert_true (g_file_get_contents (fixture.db_path, &encrypted,
          &encrypted_len, NULL));
  g_assert_false (contains_bytes ((const guint8 *) encrypted, encrypted_len,
          (const guint8 *) secret_copy, secret_len));
  WylHandleOpenOptions reopen_options = {
    .policy_store_path = fixture.db_path,
    .policy_keyprovider_path = fixture.key_spec,
    .audit_store_path = fixture.audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&reopen_options,
          &fixture.handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_get (fixture.handle, reopen_id,
          &loaded), ==, WYRELOG_E_OK);
  g_assert_cmpstr (loaded.tenant_id, ==, "tenant-a");
  wyl_service_credential_clear (&loaded);
  wyl_service_credential_issue_result_t replay_after_restart = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (fixture.handle,
          "svc:issue:worker", "tenant-a", "admin", "issue-a-1", expiry,
          &replay_after_restart), ==, WYRELOG_E_POLICY);
  g_assert_null (replay_after_restart.secret);
  g_assert_null (replay_after_restart.credential.credential_id);
}

static void
test_rejections_replay_and_cvk_only (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  wyl_service_credential_issue_result_t result = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:unknown",
          "tenant-a", "admin", "unknown-principal", 0, &result), !=,
      WYRELOG_E_OK);
  g_assert_null (result.secret);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_cvk;"), ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests;"), ==, 0);

  prepare_authority (handle, "svc:reject:worker");
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:reject:worker",
          "missing-tenant", "admin", "unknown-tenant", 0, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:reject:worker",
          "tenant-a", "admin", "expiry-boundary", g_get_real_time (),
          &result), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store_of (handle),
          "tenant-a", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:reject:worker",
          "tenant-a", "admin", "sealed-tenant", 0, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store_of (handle),
          "tenant-a", FALSE), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_disable (handle,
          "svc:reject:worker", "admin", "disable-principal", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:reject:worker",
          "tenant-a", "admin", "disabled-principal", 0, &result), ==,
      WYRELOG_E_POLICY);

  g_auto (Fixture) replay_fixture = { 0 };
  fixture_init (&replay_fixture);
  WylHandle *replay = replay_fixture.handle;
  prepare_authority (replay, "svc:replay:worker");
  g_assert_cmpint (wyl_service_credential_issue (replay, "svc:replay:worker",
          "tenant-a", "admin", "issue-replay", 0, &result), ==, WYRELOG_E_OK);
  g_assert_nonnull (result.secret);
  /* Reuse a populated result directly; replay failure must wipe its secret
   * and clear every metadata field before returning. */
  g_assert_cmpint (wyl_service_credential_issue (replay, "svc:replay:worker",
          "tenant-a", "admin", "issue-replay", 0, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_null (result.secret);
  g_assert_cmpint (wyl_service_principal_disable (replay,
          "svc:replay:worker", "admin", "issue-replay", &principal), ==,
      WYRELOG_E_POLICY);
  g_assert_null (result.credential.credential_id);
}

typedef struct
{
  WylHandle *handle;
  wyrelog_error_t rc;
  wyl_service_credential_issue_result_t result;
} IssueThread;

static gpointer
issue_thread (gpointer data)
{
  IssueThread *thread = data;
  thread->rc = wyl_service_credential_issue (thread->handle,
      "svc:concurrent:issue", "tenant-a", "admin", "concurrent-issue", 0,
      &thread->result);
  return NULL;
}

static void
test_concurrent_request (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:concurrent:issue");
  IssueThread a = {.handle = handle };
  IssueThread b = {.handle = handle };
  GThread *ta = g_thread_new ("issue-a", issue_thread, &a);
  GThread *tb = g_thread_new ("issue-b", issue_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);
  g_test_message ("concurrent issue results: %d, %d", a.rc, b.rc);
  g_assert_true ((a.rc == WYRELOG_E_OK && b.rc == WYRELOG_E_POLICY)
      || (a.rc == WYRELOG_E_POLICY && b.rc == WYRELOG_E_OK));
  g_assert_true ((a.result.secret != NULL) != (b.result.secret != NULL));
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials;"), ==, 1);
  wyl_service_credential_issue_result_clear (&a.result);
  wyl_service_credential_issue_result_clear (&b.result);
}

static void
test_fault_rollback (void)
{
  static const gchar *const targets[] = {
    "service_credentials", "service_credential_events", "audit_events",
    "audit_intentions",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (targets); i++) {
    g_auto (Fixture) fixture = { 0 };
    fixture_init (&fixture);
    WylHandle *handle = fixture.handle;
    prepare_authority (handle, "svc:fault:issue");
    g_autofree gchar *sql = g_strdup_printf
        ("CREATE TRIGGER issue_fault BEFORE INSERT ON %s "
        "BEGIN SELECT RAISE(ABORT,'fault'); END;", targets[i]);
    exec_ok (db_of (handle), sql);
    wyl_service_credential_issue_result_t result = { 0 };
    g_assert_cmpint (wyl_service_credential_issue (handle, "svc:fault:issue",
            "tenant-a", "admin", "fault-issue", 0, &result), !=, WYRELOG_E_OK);
    g_assert_null (result.secret);
    exec_ok (db_of (handle), "DROP TRIGGER issue_fault;");
    g_assert_cmpint (scalar (db_of (handle),
            "SELECT count(*) FROM service_credentials;"), ==, 0);
    g_assert_cmpint (scalar (db_of (handle),
            "SELECT count(*) FROM service_domain_requests "
            "WHERE operation='credential_issue';"), ==, 0);
  }

  g_auto (Fixture) commit_fixture = { 0 };
  fixture_init (&commit_fixture);
  WylHandle *commit = commit_fixture.handle;
  prepare_authority (commit, "svc:commit:issue");
  wyl_policy_store_service_lifecycle_fail_commit_once (store_of (commit));
  wyl_service_credential_issue_result_t result = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (commit, "svc:commit:issue",
          "tenant-a", "admin", "commit-issue", 0, &result), ==, WYRELOG_E_IO);
  g_assert_null (result.secret);
  g_assert_cmpint (scalar (db_of (commit),
          "SELECT count(*) FROM service_credentials;"), ==, 0);

  g_auto (Fixture) validator_fixture = { 0 };
  fixture_init (&validator_fixture);
  WylHandle *validator = validator_fixture.handle;
  prepare_authority (validator, "svc:validator:issue");
  exec_ok (db_of (validator),
      "CREATE TRIGGER unknown_issue_trigger AFTER INSERT ON "
      "service_domain_requests BEGIN SELECT 1; END;");
  g_assert_cmpint (wyl_service_credential_issue (validator,
          "svc:validator:issue", "tenant-a", "admin", "validator-issue", 0,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.secret);
  exec_ok (db_of (validator), "DROP TRIGGER unknown_issue_trigger;");
  g_assert_cmpint (scalar (db_of (validator),
          "SELECT count(*) FROM service_credentials;"), ==, 0);
}

typedef struct
{
  guint ids;
  guint allocs;
  guint frees;
  guint wipes;
  guint unlocks;
  gboolean always_collision;
  gboolean random_fail;
} CollisionRuntime;

static gpointer
test_alloc (gpointer data, gsize size)
{
  CollisionRuntime *runtime = data;
  runtime->allocs++;
  return g_malloc (size);
}

static int
test_lock (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  (void) ptr;
  (void) size;
  return 0;
}

static void
test_wipe (gpointer data, gpointer ptr, gsize size)
{
  CollisionRuntime *runtime = data;
  runtime->wipes++;
  memset (ptr, 0, size);
}

static int
test_unlock (gpointer data, gpointer ptr, gsize size)
{
  CollisionRuntime *runtime = data;
  runtime->unlocks++;
  (void) ptr;
  (void) size;
  return 0;
}

static void
test_free (gpointer data, gpointer ptr)
{
  CollisionRuntime *runtime = data;
  runtime->frees++;
  g_free (ptr);
}

static wyrelog_error_t
test_new_id (gpointer data, gchar out[WYL_SERVICE_CREDENTIAL_ID_BUF])
{
  CollisionRuntime *runtime = data;
  runtime->ids++;
  g_strlcpy (out, runtime->always_collision || runtime->ids == 1 ?
      COLLISION_ID : SECOND_ID, WYL_SERVICE_CREDENTIAL_ID_BUF);
  return WYRELOG_E_OK;
}

static int
test_random (gpointer data, guint8 *out, gsize len)
{
  CollisionRuntime *runtime = data;
  if (runtime->random_fail)
    return -1;
  memset (out, 0x5a, len);
  return 0;
}

typedef struct
{
  WylServiceAuthWriteLease *lease;
  WylServiceAuthorityTransaction *txn;
  WylServiceAuthorityCommitEvidence *evidence;
} Txn;

static void
test_terminal_fence_blocks_issue_before_rng (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:fence:issue-block");

  Txn t = { 0 };
  wyl_policy_store_t *store = store_of (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &t.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, t.lease, &t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (t.txn, store, &t.evidence), ==, WYRELOG_E_OK);
  WylServiceCredentialFenceResult fence_result = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          "fence-block-issue", "svc:fence:issue-block", "tenant-a", NULL,
          &fence_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (fence_result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (t.txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (t.txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t.evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t.lease);
  memset (&t, 0, sizeof t);

  WylServiceCredentialFenceResult fence = { 0 };
  g_assert_cmpint (wyl_policy_store_precheck_service_credential_operation_fence
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          "fence-block-issue", "svc:fence:issue-block", "tenant-a", NULL,
          &fence), ==, WYRELOG_E_OK);
  g_assert_cmpint (fence.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);

  wyl_service_credential_issue_result_t issue_result = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:fence:issue-block", "tenant-a", "admin",
          "fence-block-issue", 0, &issue_result), ==, WYRELOG_E_POLICY);
  g_assert_null (issue_result.secret);
  g_assert_null (issue_result.credential.credential_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests WHERE request_id="
          "'fence-block-issue';"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_cvk;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events;"), ==, 0);
  wyl_service_credential_issue_result_clear (&issue_result);
}

static void
test_terminal_fence_blocks_rotate_before_rng (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:fence:rotate-block");

  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:fence:rotate-block", "tenant-a", "admin", "fence-rotate-old",
          0, &issued), ==, WYRELOG_E_OK);
  g_autofree gchar *old_id = g_strdup (issued.credential.credential_id);
  wyl_service_credential_issue_result_clear (&issued);

  Txn t = { 0 };
  wyl_policy_store_t *store = store_of (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &t.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, t.lease, &t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (t.txn, store, &t.evidence), ==, WYRELOG_E_OK);
  WylServiceCredentialFenceResult result = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
          "fence-block-rotate", NULL, NULL, old_id, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (t.txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (t.txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t.evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t.lease);
  memset (&t, 0, sizeof t);

  WylServiceCredentialFenceResult fence = { 0 };
  g_assert_cmpint (wyl_policy_store_precheck_service_credential_operation_fence
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
          "fence-block-rotate", NULL, NULL, old_id, &fence), ==, WYRELOG_E_OK);
  g_assert_cmpint (fence.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);

  CollisionRuntime state = { 0 };
  wyl_service_credential_runtime_t runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &state,
  };
  wyl_service_credential_issue_result_t rotated = { 0 };
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .credential_runtime = &runtime,
  };
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle,
          old_id, "admin", "fence-block-rotate", 0, &rotate_runtime,
          &rotated), ==, WYRELOG_E_POLICY);
  g_assert_null (rotated.secret);
  g_assert_null (rotated.credential.credential_id);
  g_assert_cmpuint (state.ids, ==, 0);
  g_assert_cmpuint (state.allocs, ==, 0);
  g_assert_cmpuint (state.frees, ==, 0);
  g_assert_cmpuint (state.wipes, ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests WHERE request_id="
          "'fence-block-rotate';"), ==, 0);
  wyl_service_credential_issue_result_clear (&rotated);
}

typedef struct
{
  CollisionRuntime collision;
  wyl_policy_store_t *store;
  wyrelog_error_t reentry_rc;
  gboolean attempted;
} ReentryRuntime;

static int
reentry_random (gpointer data, guint8 *out, gsize len)
{
  ReentryRuntime *runtime = data;
  if (!runtime->attempted) {
    runtime->attempted = TRUE;
    wyl_policy_service_principal_info_t principal = { 0 };
    runtime->reentry_rc = wyl_policy_store_create_service_principal
        (runtime->store, "svc:callback:reentry", "reentry", "admin",
        "callback-reentry", &principal);
    wyl_policy_service_principal_info_clear (&principal);
  }
  memset (out, 0x6b, len);
  return 0;
}

static void
test_same_thread_callback_reentry_is_busy (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:callback:worker");
  ReentryRuntime state = {
    .store = store_of (fixture.handle),
    .reentry_rc = WYRELOG_E_OK,
  };
  wyl_service_credential_runtime_t runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    reentry_random, &state,
  };
  wyl_policy_service_credential_info_t info = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (wyl_policy_store_issue_service_credential_with_runtime
      (state.store, "svc:callback:worker", "tenant-a", "admin",
          "callback-outer", 0, &runtime, &info, &secret), ==, WYRELOG_E_OK);
  g_assert_true (state.attempted);
  g_assert_cmpint (state.reentry_rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (scalar (db_of (fixture.handle),
          "SELECT count(*) FROM service_principals "
          "WHERE subject_id='svc:callback:reentry';"), ==, 0);
  wyl_policy_service_credential_info_clear (&info);
  wyl_service_credential_secret_clear (&secret);
}

typedef struct
{
  WylHandle *handle;
  wyrelog_error_t rc;
  wyl_service_principal_t principal;
} ContendingPrincipal;

static gpointer
contending_principal_thread (gpointer data)
{
  ContendingPrincipal *contender = data;
  contender->rc = wyl_service_principal_create (contender->handle,
      "svc:authority:contender", "contender", "admin",
      "authority-contender", &contender->principal);
  return NULL;
}

typedef struct
{
  CollisionRuntime collision;
  WylHandle *handle;
  ContendingPrincipal contender;
  GThread *thread;
  gboolean entered;
  wyrelog_error_t reentry_rc;
} AuthorityRuntime;

static int
authority_random (gpointer data, guint8 *out, gsize len)
{
  AuthorityRuntime *runtime = data;
  if (!runtime->entered) {
    runtime->entered = TRUE;
    wyl_service_principal_t reentrant = { 0 };
    runtime->reentry_rc = wyl_service_principal_create (runtime->handle,
        "svc:authority:reentrant", "reentrant", "admin",
        "authority-reentrant", &reentrant);
    wyl_service_principal_clear (&reentrant);
    runtime->contender.handle = runtime->handle;
    runtime->contender.rc = WYRELOG_E_INTERNAL;
    runtime->thread = g_thread_new ("authority-contender",
        contending_principal_thread, &runtime->contender);

    gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
    for (;;) {
      WylServiceAuthAuthoritySnapshot snapshot = { 0 };
      wyl_service_auth_authority_snapshot
          (wyl_handle_get_service_auth_authority (runtime->handle), &snapshot);
      if (snapshot.waiting_writers == 1)
        break;
      g_assert_cmpint (g_get_monotonic_time (), <, deadline);
      g_thread_yield ();
    }
  }
  memset (out, 0x7c, len);
  return 0;
}

static void
test_authority_contention_reentry_and_snapshot (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:authority:worker");
  wyl_service_credential_issue_result_t old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:authority:worker", "tenant-a", "admin", "authority-old", 0,
          &old), ==, WYRELOG_E_OK);

  AuthorityRuntime state = {
    .handle = handle,
    .reentry_rc = WYRELOG_E_INTERNAL,
  };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    authority_random, &state,
  };
  wyl_service_credential_rotate_runtime_t runtime = {
    .credential_runtime = &credential_runtime,
  };
  wyl_service_credential_issue_result_t rotated = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle,
          old.credential.credential_id, "admin", "authority-rotate", 0,
          &runtime, &rotated), ==, WYRELOG_E_OK);
  g_assert_true (state.entered);
  g_assert_cmpint (state.reentry_rc, ==, WYRELOG_E_BUSY);
  g_thread_join (state.thread);
  g_assert_cmpint (state.contender.rc, ==, WYRELOG_E_OK);

  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (handle), &snapshot);
  g_assert_false (snapshot.writer_active);
  g_assert_cmpuint (snapshot.waiting_writers, ==, 0);
  g_assert_cmpuint (snapshot.active_readers, ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_principals WHERE subject_id IN "
          "('svc:authority:contender','svc:authority:reentrant');"), ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials WHERE state='active';"),
      ==, 1);
  wyl_service_principal_clear (&state.contender.principal);
  wyl_service_credential_issue_result_clear (&rotated);
  wyl_service_credential_issue_result_clear (&old);
}

static void
test_authority_commit_fault_withholds_secret (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:authority:fault");
  wyl_policy_store_service_authority_transaction_fail_once
      (store_of (handle), WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE);
  wyl_service_credential_issue_result_t result = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:authority:fault", "tenant-a", "admin", "authority-fault", 0,
          &result), ==, WYRELOG_E_IO);
  g_assert_null (result.secret);
  g_assert_null (result.credential.credential_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests WHERE "
          "request_id='authority-fault';"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE "
          "request_id='authority-fault';"), ==, 0);

  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (handle), &snapshot);
  g_assert_false (snapshot.writer_active);
  g_assert_cmpuint (snapshot.waiting_writers, ==, 0);
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:authority:fault", "tenant-a", "admin", "authority-retry", 0,
          &result), ==, WYRELOG_E_OK);
  g_assert_nonnull (result.secret);
  wyl_service_credential_issue_result_clear (&result);
}

static void
test_id_collision_retry_and_wipe (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:collision:issue");
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance
      (store_of (handle), &cvk, &cvk_len), ==, WYRELOG_E_OK);
  g_assert_nonnull (cvk);
  g_assert_cmpuint (cvk_len, ==, WYL_SERVICE_CREDENTIAL_CVK_BYTES);
  exec_ok (db_of (handle),
      "INSERT INTO service_credentials(credential_id,"
      "credential_format_version,subject_id,tenant_id,generation,state,"
      "verifier_version,salt,verifier,created_by,created_at_us,updated_at_us) "
      "VALUES('" COLLISION_ID "',1,'svc:collision:issue','tenant-a',1,"
      "'active',1,zeroblob(16),zeroblob(32),'admin',1,1);");
  CollisionRuntime state = { 0 };
  wyl_service_credential_runtime_t runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &state,
  };
  wyl_policy_service_credential_info_t info = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (wyl_policy_store_issue_service_credential_with_runtime
      (store_of (handle), "svc:collision:issue", "tenant-a", "admin",
          "collision-issue", 0, &runtime, &info, &secret), ==, WYRELOG_E_OK);
  g_assert_cmpuint (state.ids, ==, 2);
  g_assert_cmpstr (info.credential_id, ==, SECOND_ID);
  g_assert_nonnull (secret);
  wyl_policy_service_credential_info_clear (&info);
  wyl_service_credential_secret_clear (&secret);
  g_assert_cmpuint (state.allocs, ==, state.frees);
  g_assert_cmpuint (state.unlocks, ==, state.frees);
  g_assert_cmpuint (state.wipes, >=, state.frees);

  memset (&state, 0, sizeof state);
  state.always_collision = TRUE;
  runtime.data = &state;
  g_assert_cmpint (wyl_policy_store_issue_service_credential_with_runtime
      (store_of (handle), "svc:collision:issue", "tenant-a", "admin",
          "collision-exhausted", 0, &runtime, &info, &secret), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (state.ids, ==, 4);
  g_assert_null (secret);
  g_assert_null (info.credential_id);
  g_assert_cmpuint (state.allocs, ==, state.frees);
  g_assert_cmpuint (state.unlocks, ==, state.frees);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='collision-exhausted';"), ==, 0);
}

typedef struct
{
  WylHandle *handle;
  guint calls;
  gboolean saw_write_lease;
  gchar *actor_subject_id;
  wyrelog_error_t rc;
} AuthorizationProbe;

static wyrelog_error_t
probe_mutation_authorization (gpointer data, const gchar *actor_subject_id)
{
  AuthorizationProbe *probe = data;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  probe->calls++;
  g_free (probe->actor_subject_id);
  probe->actor_subject_id = g_strdup (actor_subject_id);
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (probe->handle), &snapshot);
  probe->saw_write_lease = snapshot.writer_active;
  return probe->rc;
}

typedef struct
{
  gint64 credentials;
  gint64 events;
  gint64 cvk;
  gint64 escrows;
  gint64 fences;
  gint64 requests;
  gint64 audits;
  gint64 audit_intentions;
  gint64 handoff_dispositions;
  gint64 handoff_cancellations;
  gint64 handoff_remediations;
} MutationEffects;

static MutationEffects
mutation_effects (WylHandle *handle)
{
  sqlite3 *db = db_of (handle);
  return (MutationEffects) {
  .credentials =
        scalar (db, "SELECT count(*) FROM service_credentials;"),.events =
        scalar (db, "SELECT count(*) FROM service_credential_events;"),.cvk =
        scalar (db, "SELECT count(*) FROM service_credential_cvk;"),.escrows =
        scalar (db,
        "SELECT count(*) FROM service_credential_handoff_escrows;"),.fences =
        scalar (db,
        "SELECT count(*) FROM service_credential_operation_fences;"),.requests
        =
        scalar (db, "SELECT count(*) FROM service_domain_requests;"),.audits =
        scalar (db, "SELECT count(*) FROM audit_events;"),.audit_intentions =
        scalar (db,
        "SELECT count(*) FROM audit_intentions;"),.handoff_dispositions =
        scalar (db,
        "SELECT count(*) FROM service_credential_handoff_dispositions;"),.handoff_cancellations
        =
        scalar (db,
        "SELECT count(*) FROM service_credential_handoff_cancellation_claims;"),.handoff_remediations
        =
        scalar (db,
        "SELECT count(*) FROM service_credential_handoff_remediation_actions;"),};
}

static void
assert_mutation_effects_equal (MutationEffects actual, MutationEffects expected)
{
  g_assert_cmpint (actual.credentials, ==, expected.credentials);
  g_assert_cmpint (actual.events, ==, expected.events);
  g_assert_cmpint (actual.cvk, ==, expected.cvk);
  g_assert_cmpint (actual.escrows, ==, expected.escrows);
  g_assert_cmpint (actual.fences, ==, expected.fences);
  g_assert_cmpint (actual.requests, ==, expected.requests);
  g_assert_cmpint (actual.audits, ==, expected.audits);
  g_assert_cmpint (actual.audit_intentions, ==, expected.audit_intentions);
  g_assert_cmpint (actual.handoff_dispositions, ==,
      expected.handoff_dispositions);
  g_assert_cmpint (actual.handoff_cancellations, ==,
      expected.handoff_cancellations);
  g_assert_cmpint (actual.handoff_remediations, ==,
      expected.handoff_remediations);
}

static void
assert_disposition_only_delta (MutationEffects actual, MutationEffects expected)
{
  g_assert_cmpint (actual.credentials, ==, expected.credentials);
  g_assert_cmpint (actual.events, ==, expected.events);
  g_assert_cmpint (actual.cvk, ==, expected.cvk);
  g_assert_cmpint (actual.escrows, ==, expected.escrows);
  g_assert_cmpint (actual.fences, ==, expected.fences);
  g_assert_cmpint (actual.requests, ==, expected.requests);
  g_assert_cmpint (actual.audits, ==, expected.audits + 1);
  g_assert_cmpint (actual.audit_intentions, ==, expected.audit_intentions + 1);
  g_assert_cmpint (actual.handoff_dispositions, ==,
      expected.handoff_dispositions + 1);
  g_assert_cmpint (actual.handoff_cancellations, ==,
      expected.handoff_cancellations);
  g_assert_cmpint (actual.handoff_remediations, ==,
      expected.handoff_remediations);
}

static void
assert_disposition_replay_fails_no_mutation (WylHandle *handle,
    const wyl_service_credential_handoff_disposition_input_t *input)
{
  MutationEffects before = mutation_effects (handle);
  wyl_service_credential_handoff_disposition_result_t result = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          input, &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.disposition_id);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle), before);
}

static void
assert_not_committed_replay_fails_no_mutation (WylHandle *handle,
    const wyl_service_credential_handoff_disposition_input_t *input)
{
  MutationEffects before = mutation_effects (handle);
  wyl_service_credential_handoff_disposition_result_t result = { 0 };
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, input,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.disposition_id);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle), before);
}

static void
create_terminal_fence_for_test (WylHandle *handle,
    WylServiceCredentialFenceOperation operation, const gchar *request_id,
    const gchar *field_a, const gchar *field_b)
{
  Txn transaction = { 0 };
  wyl_policy_store_t *store = store_of (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &transaction.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, transaction.lease, &transaction.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (transaction.txn, store, &transaction.evidence), ==, WYRELOG_E_OK);
  WylServiceCredentialFenceResult fence = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence
      (transaction.txn, store, NULL, operation, request_id,
          operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ? field_a : NULL,
          operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ? field_b : NULL,
          operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE ? field_a : NULL,
          &fence), ==, WYRELOG_E_OK);
  g_assert_cmpint (fence.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (transaction.txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (transaction.txn);
  wyl_policy_store_service_authority_commit_evidence_unref
      (transaction.evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (transaction.lease),
      ==, WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (transaction.lease);
}

static void
test_mutation_authorization_denial_inside_write_lease (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:authorize:worker");
  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe probe = {
    .handle = handle,
    .rc = WYRELOG_E_POLICY,
  };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,
    .data = &probe,
  };
  wyl_service_credential_issue_runtime_t issue_runtime = {
    .authorization = &authorization,
    .credential_runtime = &credential_runtime,
  };
  MutationEffects before = mutation_effects (handle);
  wyl_service_credential_issue_result_t denied = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_with_runtime (handle,
          "svc:authorize:worker", "tenant-a", "admin", "authorize-issue",
          0, &issue_runtime, &denied), ==, WYRELOG_E_POLICY);
  g_assert_null (denied.secret);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_cmpstr (probe.actor_subject_id, ==, "admin");
  g_assert_cmpuint (collision.ids, ==, 0);
  g_assert_cmpuint (collision.allocs, ==, 0);
  assert_mutation_effects_equal (mutation_effects (handle), before);

  wyl_service_credential_issue_result_t seed = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:authorize:worker", "tenant-a", "admin", "authorize-seed", 0,
          &seed), ==, WYRELOG_E_OK);
  before = mutation_effects (handle);
  probe.calls = 0;
  probe.saw_write_lease = FALSE;
  memset (&collision, 0, sizeof collision);
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .credential_runtime = &credential_runtime,
    .authorization = &authorization,
  };
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle,
          seed.credential.credential_id, "admin", "authorize-rotate", 0,
          &rotate_runtime, &denied), ==, WYRELOG_E_POLICY);
  g_assert_null (denied.secret);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_cmpstr (probe.actor_subject_id, ==, "admin");
  g_assert_cmpuint (collision.ids, ==, 0);
  g_assert_cmpuint (collision.allocs, ==, 0);
  assert_mutation_effects_equal (mutation_effects (handle), before);

  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (handle), &snapshot);
  g_assert_false (snapshot.writer_active);
  wyl_service_credential_issue_result_clear (&seed);
  wyl_service_credential_issue_result_clear (&denied);
  g_free (probe.actor_subject_id);
}

static void
test_handoff_issue_authorization_replay_and_no_plaintext (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:issue");

  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  wyl_service_credential_issue_runtime_t runtime = {
    .authorization = &authorization,
    .credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0x31, sizeof target);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t first = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:issue", "tenant-a", "admin", "handoff-issue", 0,
          &handoff, &runtime, &first), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_cmpstr (probe.actor_subject_id, ==, "admin");
  g_assert_cmpstr (first.handoff.operation, ==, "issue");
  g_assert_cmpstr (first.handoff.request_id, ==, "handoff-issue");
  g_assert_cmpstr (first.handoff.actor_subject_id, ==, "admin");
  g_assert_cmpstr (first.handoff.credential_id, ==,
      first.credential.credential_id);
  g_assert_cmpuint (first.handoff.credential_generation, ==,
      first.credential.generation);
  g_assert_true (wyl_id_equal (&first.handoff.escrow_id, &escrow_id));
  g_assert_cmpmem (first.handoff.target_digest,
      sizeof first.handoff.target_digest, target, sizeof target);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events "
          "WHERE request_id='handoff-issue' AND actor_subject_id='admin';"),
      ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events "
          "WHERE request_id='handoff-issue' AND subject_id='admin';"), ==, 1);

  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load
      (store_of (handle), &escrow_id, &escrow), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_secret_t *secret = NULL;
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_unseal
      (store_of (handle), &escrow, &secret), ==, WYRELOG_E_OK);
  gsize secret_len = 0;
  const guint8 *plaintext = wyl_policy_service_handoff_secret_peek (secret,
      &secret_len);
  g_assert_nonnull (plaintext);
  g_assert_cmpuint (secret_len, ==, WYL_SERVICE_CREDENTIAL_SECRET_BYTES);
  sqlite3_int64 policy_len = 0;
  unsigned char *policy_bytes = sqlite3_serialize (db_of (handle), "main",
      &policy_len, 0);
  g_assert_nonnull (policy_bytes);
  g_assert_false (contains_bytes (policy_bytes, (gsize) policy_len, plaintext,
          secret_len));
  sqlite3_free (policy_bytes);

  MutationEffects committed = mutation_effects (handle);
  guint ids = collision.ids;
  guint allocs = collision.allocs;
  probe.calls = 0;
  probe.saw_write_lease = FALSE;
  wyl_service_credential_handoff_result_t replay = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:issue", "tenant-a", "admin", "handoff-issue", 0,
          &handoff, &runtime, &replay), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_cmpuint (collision.ids, ==, ids);
  g_assert_cmpuint (collision.allocs, ==, allocs);
  g_assert_cmpstr (replay.credential.credential_id, ==,
      first.credential.credential_id);
  g_assert_cmpmem (replay.handoff.binding_digest,
      sizeof replay.handoff.binding_digest, first.handoff.binding_digest,
      sizeof first.handoff.binding_digest);
  assert_mutation_effects_equal (mutation_effects (handle), committed);

  wyl_id_t denied_escrow_id;
  g_assert_cmpint (wyl_id_new (&denied_escrow_id), ==, WYRELOG_E_OK);
  handoff.escrow_id = &denied_escrow_id;
  probe.rc = WYRELOG_E_POLICY;
  probe.calls = 0;
  probe.saw_write_lease = FALSE;
  wyl_service_credential_handoff_result_t denied = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:issue", "tenant-a", "admin", "handoff-denied", 0,
          &handoff, &runtime, &denied), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_null (denied.credential.credential_id);
  g_assert_null (denied.handoff.credential_id);
  g_assert_cmpuint (collision.ids, ==, ids);
  g_assert_cmpuint (collision.allocs, ==, allocs);
  assert_mutation_effects_equal (mutation_effects (handle), committed);

  wyl_service_credential_handoff_result_clear (&denied);
  wyl_service_credential_handoff_result_clear (&replay);
  wyl_policy_service_handoff_secret_clear (&secret);
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
  wyl_service_credential_handoff_result_clear (&first);
  g_free (probe.actor_subject_id);
}

static void
test_handoff_checked_rotate_stale_rollback_and_replay (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:rotate");
  wyl_service_credential_issue_result_t old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:handoff:rotate", "tenant-a", "admin", "handoff-rotate-seed",
          0, &old), ==, WYRELOG_E_OK);

  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  wyl_service_credential_rotate_runtime_t runtime = {
    .credential_runtime = &credential_runtime,
    .old_credential_generation = old.credential.generation + 1,
    .authorization = &authorization,
  };
  wyl_id_t escrow_id;
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0x32, sizeof target);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  MutationEffects before = mutation_effects (handle);
  wyl_service_credential_handoff_result_t out = { 0 };
  g_assert_cmpint
      (wyl_service_credential_rotate_handoff_checked_with_runtime (handle,
          old.credential.credential_id, "admin", "handoff-rotate-stale", 0,
          &handoff, &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_cmpuint (collision.ids, ==, 0);
  g_assert_cmpuint (collision.allocs, ==, 0);
  g_assert_null (out.credential.credential_id);
  assert_mutation_effects_equal (mutation_effects (handle), before);

  runtime.old_credential_generation = old.credential.generation;
  probe.calls = 0;
  probe.saw_write_lease = FALSE;
  g_assert_cmpint
      (wyl_service_credential_rotate_handoff_checked_with_runtime (handle,
          old.credential.credential_id, "admin", "handoff-rotate", 0,
          &handoff, &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_cmpstr (out.handoff.operation, ==, "rotate");
  g_assert_cmpstr (out.handoff.actor_subject_id, ==, "admin");
  g_assert_cmpstr (out.credential.rotated_from_id, ==,
      old.credential.credential_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events "
          "WHERE request_id='handoff-rotate' AND actor_subject_id='admin';"),
      ==, 2);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events "
          "WHERE request_id='handoff-rotate' AND subject_id='admin';"), ==, 1);
  MutationEffects committed = mutation_effects (handle);
  guint ids = collision.ids;
  guint allocs = collision.allocs;
  wyl_service_credential_handoff_result_t replay = { 0 };
  probe.calls = 0;
  g_assert_cmpint
      (wyl_service_credential_rotate_handoff_checked_with_runtime (handle,
          old.credential.credential_id, "admin", "handoff-rotate", 0,
          &handoff, &runtime, &replay), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_cmpuint (collision.ids, ==, ids);
  g_assert_cmpuint (collision.allocs, ==, allocs);
  g_assert_cmpstr (replay.credential.credential_id, ==,
      out.credential.credential_id);
  assert_mutation_effects_equal (mutation_effects (handle), committed);

  wyl_service_credential_handoff_result_clear (&replay);
  wyl_service_credential_handoff_result_clear (&out);
  wyl_service_credential_issue_result_clear (&old);
  g_free (probe.actor_subject_id);
}

static gint64
fixed_now (gpointer data)
{
  return *(gint64 *) data;
}

typedef struct
{
  GMutex mutex;
  GCond cond;
  gboolean entered;
  gboolean release;
} GateHolder;

static gpointer
gate_alloc (gpointer data, gsize size)
{
  (void) data;
  return g_malloc (size);
}

static int
gate_lock (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  (void) ptr;
  (void) size;
  return 0;
}

static void
gate_wipe (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  memset (ptr, 0, size);
}

static int
gate_unlock (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  (void) ptr;
  (void) size;
  return 0;
}

static void
gate_free (gpointer data, gpointer ptr)
{
  (void) data;
  g_free (ptr);
}

static wyrelog_error_t
gate_new_id (gpointer data, gchar out[WYL_SERVICE_CREDENTIAL_ID_BUF])
{
  (void) data;
  return wyl_service_credential_id_new (out, WYL_SERVICE_CREDENTIAL_ID_BUF);
}

static int
gate_random (gpointer data, guint8 *out, gsize len)
{
  GateHolder *holder = data;
  g_mutex_lock (&holder->mutex);
  holder->entered = TRUE;
  g_cond_broadcast (&holder->cond);
  while (!holder->release)
    g_cond_wait (&holder->cond, &holder->mutex);
  g_mutex_unlock (&holder->mutex);
  memset (out, 0x6b, len);
  return 0;
}

typedef struct
{
  wyl_policy_store_t *store;
  const wyl_service_credential_runtime_t *runtime;
  wyrelog_error_t rc;
  wyl_policy_service_credential_info_t info;
  wyl_service_credential_secret_t *secret;
} GateIssueThread;

static gpointer
gate_issue_thread (gpointer data)
{
  GateIssueThread *thread = data;
  thread->rc = wyl_policy_store_issue_service_credential_with_runtime
      (thread->store, "svc:verify-gate:worker", "tenant-a", "admin",
      "verify-gate-holder", 0, thread->runtime, &thread->info, &thread->secret);
  return NULL;
}

typedef struct
{
  GMutex mutex;
  GCond cond;
  gboolean before_gate;
  gint64 now;
} VerifyGateClock;

static void
verify_before_gate (gpointer data)
{
  VerifyGateClock *clock = data;
  g_mutex_lock (&clock->mutex);
  clock->before_gate = TRUE;
  g_cond_broadcast (&clock->cond);
  g_mutex_unlock (&clock->mutex);
}

static gint64
verify_gate_now (gpointer data)
{
  VerifyGateClock *clock = data;
  g_mutex_lock (&clock->mutex);
  gint64 now = clock->now;
  g_mutex_unlock (&clock->mutex);
  return now;
}

typedef struct
{
  WylHandle *handle;
  const gchar *credential_id;
  const gchar *secret;
  gsize secret_len;
  wyl_service_credential_verify_runtime_t runtime;
  wyrelog_error_t rc;
  gboolean authenticated;
} GateVerifyThread;

static gpointer
gate_verify_thread (gpointer data)
{
  GateVerifyThread *thread = data;
  thread->rc = wyl_service_credential_verify_authoritative_with_runtime
      (thread->handle, thread->credential_id, thread->secret,
      thread->secret_len, &thread->runtime, &thread->authenticated);
  return NULL;
}

static void
test_verify_expiry_clock_inside_gate (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:verify-gate:worker");
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  wyl_service_credential_issue_result_t target = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:verify-gate:worker", "tenant-a", "admin", "verify-gate-target",
          expiry, &target), ==, WYRELOG_E_OK);
  g_autofree gchar *target_id = g_strdup (target.credential.credential_id);
  gsize target_secret_len = 0;
  const gchar *target_secret_borrowed =
      wyl_service_credential_secret_peek_encoded (target.secret,
      &target_secret_len);
  g_autofree gchar *target_secret = g_strndup (target_secret_borrowed,
      target_secret_len);

  GateHolder holder;
  g_mutex_init (&holder.mutex);
  g_cond_init (&holder.cond);
  holder.entered = FALSE;
  holder.release = FALSE;
  wyl_service_credential_runtime_t issue_runtime = {
    gate_alloc, gate_lock, gate_wipe, gate_unlock, gate_free, gate_new_id,
    gate_random, &holder,
  };
  GateIssueThread issue = { store_of (handle), &issue_runtime, -1, {0}, NULL };
  GThread *issuer = g_thread_new ("verify-gate-holder", gate_issue_thread,
      &issue);
  g_mutex_lock (&holder.mutex);
  while (!holder.entered)
    g_cond_wait (&holder.cond, &holder.mutex);
  g_mutex_unlock (&holder.mutex);

  VerifyGateClock clock;
  g_mutex_init (&clock.mutex);
  g_cond_init (&clock.cond);
  clock.before_gate = FALSE;
  clock.now = expiry - 1;
  GateVerifyThread verify = {
    .handle = handle,
    .credential_id = target_id,
    .secret = target_secret,
    .secret_len = target_secret_len,
    .runtime = {
          .before_gate = verify_before_gate,
          .now_us = verify_gate_now,
          .data = &clock,
        },
    .rc = -1,
  };
  GThread *verifier = g_thread_new ("verify-gate-waiter", gate_verify_thread,
      &verify);
  g_mutex_lock (&clock.mutex);
  while (!clock.before_gate)
    g_cond_wait (&clock.cond, &clock.mutex);
  clock.now = expiry;
  g_mutex_unlock (&clock.mutex);

  g_mutex_lock (&holder.mutex);
  holder.release = TRUE;
  g_cond_broadcast (&holder.cond);
  g_mutex_unlock (&holder.mutex);
  g_thread_join (issuer);
  g_thread_join (verifier);
  g_assert_cmpint (issue.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (verify.rc, ==, WYRELOG_E_AUTH);
  g_assert_false (verify.authenticated);

  wyl_policy_service_credential_info_clear (&issue.info);
  wyl_service_credential_secret_clear (&issue.secret);
  wyl_service_credential_issue_result_clear (&target);
  g_cond_clear (&clock.cond);
  g_mutex_clear (&clock.mutex);
  g_cond_clear (&holder.cond);
  g_mutex_clear (&holder.mutex);
}

static void
test_verify_fail_closed_read_only (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:verify:worker");
  gint64 expiry = g_get_real_time () + 10 * G_USEC_PER_SEC;
  wyl_service_credential_issue_result_t first = { 0 };
  wyl_service_credential_issue_result_t second = { 0 };
  wyl_service_credential_issue_result_t expiring = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:verify:worker",
          "tenant-a", "admin", "verify-first", 0, &first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:verify:worker",
          "tenant-b", "admin", "verify-second", 0, &second), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:verify:worker",
          "tenant-a", "admin", "verify-expiring", expiry, &expiring), ==,
      WYRELOG_E_OK);
  gsize first_len = 0;
  gsize second_len = 0;
  const gchar *first_secret = wyl_service_credential_secret_peek_encoded
      (first.secret, &first_len);
  const gchar *second_secret = wyl_service_credential_secret_peek_encoded
      (second.secret, &second_len);
  gboolean authenticated = TRUE;
  gint64 events_before = scalar (db_of (handle),
      "SELECT count(*) FROM service_credential_events;");
  gint64 audits_before = scalar (db_of (handle),
      "SELECT count(*) FROM audit_events;");
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          first.credential.credential_id, first_secret, first_len,
          &authenticated), ==, WYRELOG_E_OK);
  g_assert_true (authenticated);

  static const gchar wrong[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  G_STATIC_ASSERT (sizeof wrong - 1 == WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          first.credential.credential_id, wrong, sizeof wrong - 1,
          &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          SECOND_ID, wrong, sizeof wrong - 1, &authenticated), ==,
      WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          first.credential.credential_id, second_secret, second_len,
          &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_autofree gchar *invalid_alphabet = g_strndup (first_secret, first_len);
  invalid_alphabet[0] = '+';
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          first.credential.credential_id, invalid_alphabet, first_len,
          &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          SECOND_ID, invalid_alphabet, first_len, &authenticated), ==,
      WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_autofree gchar *noncanonical = g_strndup (first_secret, first_len);
  noncanonical[first_len - 1] = 'B';
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          first.credential.credential_id, noncanonical, first_len,
          &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          SECOND_ID, noncanonical, first_len, &authenticated), ==,
      WYRELOG_E_AUTH);
  g_assert_false (authenticated);

  wyl_service_credential_verify_runtime_t clock = {
    .now_us = fixed_now,.data = &expiry,
  };
  gsize expiry_len = 0;
  const gchar *expiry_secret = wyl_service_credential_secret_peek_encoded
      (expiring.secret, &expiry_len);
  g_assert_cmpint (wyl_service_credential_verify_authoritative_with_runtime
      (handle, expiring.credential.credential_id, expiry_secret, expiry_len,
          &clock, &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials "
          "WHERE last_used_at_us IS NOT NULL;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events;"), ==,
      events_before);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events;"), ==, audits_before);

  exec_ok (db_of (handle),
      "INSERT INTO principal_states(subject_id,state,updated_at) "
      "VALUES('svc:verify:worker','idle',1);");
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          second.credential.credential_id, second_secret, second_len,
          &authenticated), ==, WYRELOG_E_POLICY);
  g_assert_false (authenticated);
  exec_ok (db_of (handle),
      "DELETE FROM principal_states WHERE subject_id='svc:verify:worker';");

  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          first.credential.credential_id, first_secret, first_len - 1,
          &authenticated), ==, WYRELOG_E_INVALID);
  g_assert_false (authenticated);
  wyl_service_credential_t revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          first.credential.credential_id, "admin", "verify-revoke",
          &revoked), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          first.credential.credential_id, first_secret, first_len,
          &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  wyl_service_credential_clear (&revoked);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store_of (handle),
          "tenant-b", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          second.credential.credential_id, second_secret, second_len,
          &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store_of (handle),
          "tenant-b", FALSE), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_disable (handle,
          "svc:verify:worker", "admin", "verify-disable", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          second.credential.credential_id, second_secret, second_len,
          &authenticated), ==, WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  wyl_service_credential_issue_result_clear (&first);
  wyl_service_credential_issue_result_clear (&second);
  wyl_service_credential_issue_result_clear (&expiring);
}

static void
test_revoke_lifecycle_and_remediation (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:revoke:worker");
  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:revoke:worker",
          "tenant-a", "admin", "revoke-issue", 0, &issued), ==, WYRELOG_E_OK);
  g_autofree gchar *id = g_strdup (issued.credential.credential_id);
  wyl_service_credential_issue_result_clear (&issued);
  wyl_service_credential_t credential = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle, id, "admin",
          "revoke-issue", &credential), ==, WYRELOG_E_POLICY);
  g_assert_null (credential.credential_id);
  g_assert_cmpint (wyl_service_credential_revoke (handle, id, "admin",
          "revoke-active", &credential), ==, WYRELOG_E_OK);
  g_assert_cmpstr (credential.state, ==, "revoked");
  g_assert_cmpuint (credential.generation, ==, 2);
  g_assert_cmpstr (credential.revoked_by, ==, "admin");
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events "
          "WHERE event='revoked' AND generation=2 "
          "AND related_credential_id IS NULL;"), ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events a JOIN audit_intentions i "
          "ON a.id=i.audit_id WHERE a.action='service.credential.revoke' "
          "AND i.state='pending';"), ==, 1);

  g_clear_object (&fixture.handle);
  WylHandleOpenOptions reopen_options = {
    .policy_store_path = fixture.db_path,
    .policy_keyprovider_path = fixture.key_spec,
    .audit_store_path = fixture.audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&reopen_options,
          &fixture.handle), ==, WYRELOG_E_OK);
  handle = fixture.handle;
  g_assert_cmpint (wyl_service_credential_revoke (handle, id, "admin",
          "revoke-active", &credential), ==, WYRELOG_E_POLICY);
  g_assert_null (credential.credential_id);

  g_assert_cmpint (wyl_service_credential_revoke (handle, id, "admin",
          "revoke-noop", &credential), ==, WYRELOG_E_OK);
  g_assert_cmpuint (credential.generation, ==, 2);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events "
          "WHERE event='revoked';"), ==, 1);
  g_assert_cmpint (wyl_service_credential_revoke (handle, id, "admin",
          "revoke-noop", &credential), ==, WYRELOG_E_POLICY);
  g_assert_null (credential.credential_id);
  g_assert_cmpint (wyl_service_credential_revoke (handle, SECOND_ID, "admin",
          "revoke-unknown", &credential), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (credential.credential_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='revoke-unknown';"), ==, 0);

  wyl_service_credential_issue_result_t hooked = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:revoke:worker",
          "tenant-a", "admin", "revoke-hook-issue", 0, &hooked), ==,
      WYRELOG_E_OK);
  InvalidationProbe probe = { 0 };
  wyl_service_credential_revoke_runtime_t revoke_runtime = {
    .invalidate_credential = probe_credential_invalidation,
    .invalidation_data = &probe,
  };
  g_assert_cmpint (wyl_service_credential_revoke_with_runtime (handle,
          hooked.credential.credential_id, "admin", "revoke-hook",
          &revoke_runtime, &credential), ==, WYRELOG_E_OK);
  g_assert_true (probe.called);
  g_assert_cmpstr (probe.credential_id, ==, hooked.credential.credential_id);
  g_assert_cmpuint (probe.generation, ==, 1);
  g_clear_pointer (&probe.credential_id, g_free);
  wyl_service_credential_issue_result_clear (&hooked);
  wyl_service_credential_clear (&credential);

  wyl_service_credential_issue_result_t remediation = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:revoke:worker",
          "tenant-b", "admin", "remediation-issue", 0, &remediation), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store_of (handle),
          "tenant-b", TRUE), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_disable (handle,
          "svc:revoke:worker", "admin", "remediation-disable", &principal),
      ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          remediation.credential.credential_id, "admin", "remediation-revoke",
          &credential), ==, WYRELOG_E_OK);
  g_assert_cmpstr (credential.state, ==, "revoked");
  wyl_service_credential_clear (&credential);
  wyl_service_credential_issue_result_clear (&remediation);
}

typedef struct
{
  WylHandle *handle;
  const gchar *credential_id;
  wyrelog_error_t rc;
  wyl_service_credential_t out;
} RevokeThread;

static gpointer
revoke_thread (gpointer data)
{
  RevokeThread *thread = data;
  thread->rc = wyl_service_credential_revoke (thread->handle,
      thread->credential_id, "admin", "concurrent-revoke", &thread->out);
  return NULL;
}

static void
test_revoke_concurrency_overflow_faults (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:revoke-concurrent:worker");
  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:revoke-concurrent:worker", "tenant-a", "admin",
          "concurrent-revoke-issue", 0, &issued), ==, WYRELOG_E_OK);
  RevokeThread a = { handle, issued.credential.credential_id, -1, {0} };
  RevokeThread b = { handle, issued.credential.credential_id, -1, {0} };
  GThread *ta = g_thread_new ("revoke-a", revoke_thread, &a);
  GThread *tb = g_thread_new ("revoke-b", revoke_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);
  g_assert_true ((a.rc == WYRELOG_E_OK && b.rc == WYRELOG_E_POLICY)
      || (a.rc == WYRELOG_E_POLICY && b.rc == WYRELOG_E_OK));
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events "
          "WHERE event='revoked';"), ==, 1);
  wyl_service_credential_clear (&a.out);
  wyl_service_credential_clear (&b.out);
  wyl_service_credential_issue_result_clear (&issued);

  wyl_service_credential_issue_result_t overflow = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:revoke-concurrent:worker", "tenant-a", "admin",
          "overflow-issue", 0, &overflow), ==, WYRELOG_E_OK);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db_of (handle),
          "UPDATE service_credentials SET generation=9223372036854775807 "
          "WHERE credential_id=?;", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1,
          overflow.credential.credential_id, -1, SQLITE_TRANSIENT), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  wyl_service_credential_t out = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          overflow.credential.credential_id, "admin", "overflow-revoke",
          &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.credential_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='overflow-revoke';"), ==, 0);
  wyl_service_credential_issue_result_clear (&overflow);

  static const gchar *const targets[] = {
    "service_credential_events", "audit_events", "audit_intentions",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (targets); i++) {
    g_auto (Fixture) fault_fixture = { 0 };
    fixture_init (&fault_fixture);
    WylHandle *fault = fault_fixture.handle;
    prepare_authority (fault, "svc:revoke-fault:worker");
    wyl_service_credential_issue_result_t target = { 0 };
    g_assert_cmpint (wyl_service_credential_issue (fault,
            "svc:revoke-fault:worker", "tenant-a", "admin", "fault-issue", 0,
            &target), ==, WYRELOG_E_OK);
    g_autofree gchar *sql = g_strdup_printf
        ("CREATE TRIGGER revoke_fault BEFORE INSERT ON %s "
        "BEGIN SELECT RAISE(ABORT,'fault'); END;", targets[i]);
    exec_ok (db_of (fault), sql);
    g_assert_cmpint (wyl_service_credential_revoke (fault,
            target.credential.credential_id, "admin", "fault-revoke", &out),
        !=, WYRELOG_E_OK);
    g_assert_null (out.credential_id);
    exec_ok (db_of (fault), "DROP TRIGGER revoke_fault;");
    g_assert_cmpint (scalar (db_of (fault),
            "SELECT count(*) FROM service_credentials WHERE state='revoked';"),
        ==, 0);
    g_assert_cmpint (scalar (db_of (fault),
            "SELECT count(*) FROM service_domain_requests "
            "WHERE request_id='fault-revoke';"), ==, 0);
    wyl_service_credential_issue_result_clear (&target);
  }

  g_auto (Fixture) commit_fixture = { 0 };
  fixture_init (&commit_fixture);
  WylHandle *commit = commit_fixture.handle;
  prepare_authority (commit, "svc:revoke-commit:worker");
  wyl_service_credential_issue_result_t commit_target = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (commit,
          "svc:revoke-commit:worker", "tenant-a", "admin", "commit-issue",
          0, &commit_target), ==, WYRELOG_E_OK);
  wyl_policy_store_service_lifecycle_fail_commit_once (store_of (commit));
  g_assert_cmpint (wyl_service_credential_revoke (commit,
          commit_target.credential.credential_id, "admin", "commit-revoke",
          &out), ==, WYRELOG_E_IO);
  g_assert_null (out.credential_id);
  g_assert_cmpint (scalar (db_of (commit),
          "SELECT count(*) FROM service_credentials WHERE state='revoked';"),
      ==, 0);
  g_assert_cmpint (scalar (db_of (commit),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='commit-revoke';"), ==, 0);
  wyl_service_credential_issue_result_clear (&commit_target);

  g_auto (Fixture) validator_fixture = { 0 };
  fixture_init (&validator_fixture);
  WylHandle *validator = validator_fixture.handle;
  prepare_authority (validator, "svc:revoke-validator:worker");
  wyl_service_credential_issue_result_t validator_target = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (validator,
          "svc:revoke-validator:worker", "tenant-a", "admin",
          "validator-issue", 0, &validator_target), ==, WYRELOG_E_OK);
  exec_ok (db_of (validator),
      "CREATE TRIGGER unknown_revoke_trigger AFTER INSERT ON "
      "service_domain_requests BEGIN SELECT 1; END;");
  g_assert_cmpint (wyl_service_credential_revoke (validator,
          validator_target.credential.credential_id, "admin",
          "validator-revoke", &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.credential_id);
  exec_ok (db_of (validator), "DROP TRIGGER unknown_revoke_trigger;");
  g_assert_cmpint (scalar (db_of (validator),
          "SELECT count(*) FROM service_credentials WHERE state='revoked';"),
      ==, 0);
  g_assert_cmpint (scalar (db_of (validator),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='validator-revoke';"), ==, 0);
  wyl_service_credential_issue_result_clear (&validator_target);
}

static void
test_rotate_happy_linkage_no_grace (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:rotate:worker");
  wyl_service_credential_issue_result_t old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:rotate:worker",
          "tenant-a", "admin", "rotate-old", 0, &old), ==, WYRELOG_E_OK);
  g_autofree gchar *old_id = g_strdup (old.credential.credential_id);
  gsize old_secret_len = 0;
  const gchar *old_secret = wyl_service_credential_secret_peek_encoded
      (old.secret, &old_secret_len);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  wyl_service_credential_issue_result_t rotated = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate (handle, old_id, "admin",
          "rotate-old", expiry, &rotated), ==, WYRELOG_E_POLICY);
  g_assert_null (rotated.secret);
  InvalidationProbe probe = { 0 };
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .invalidate_credential = probe_credential_invalidation,
    .invalidation_data = &probe,
    .old_credential_generation = 1,
  };
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle, old_id,
          "admin", "rotate-happy", expiry, &rotate_runtime, &rotated), ==,
      WYRELOG_E_OK);
  g_assert_true (probe.called);
  g_assert_cmpstr (probe.credential_id, ==, old_id);
  g_assert_cmpuint (probe.generation, ==, 1);
  g_clear_pointer (&probe.credential_id, g_free);
  g_assert_nonnull (rotated.secret);
  g_assert_cmpstr (rotated.credential.subject_id, ==, "svc:rotate:worker");
  g_assert_cmpstr (rotated.credential.tenant_id, ==, "tenant-a");
  g_assert_cmpstr (rotated.credential.state, ==, "active");
  g_assert_cmpuint (rotated.credential.generation, ==, 1);
  g_assert_cmpstr (rotated.credential.rotated_from_id, ==, old_id);
  g_assert_cmpint (rotated.credential.expires_at_us, ==, expiry);
  g_autofree gchar *new_id = g_strdup (rotated.credential.credential_id);
  gsize new_secret_len = 0;
  const gchar *new_secret = wyl_service_credential_secret_peek_encoded
      (rotated.secret, &new_secret_len);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events e "
          "WHERE (e.credential_id=(SELECT credential_id FROM "
          "service_credentials WHERE rotated_from_id IS NOT NULL) "
          "AND e.event='rotated' AND e.generation=1 "
          "AND e.related_credential_id=(SELECT rotated_from_id FROM "
          "service_credentials WHERE credential_id=e.credential_id)) "
          "OR (e.credential_id=(SELECT rotated_from_id FROM "
          "service_credentials WHERE rotated_from_id IS NOT NULL) "
          "AND e.event='revoked' AND e.generation=2 "
          "AND e.related_credential_id=(SELECT credential_id FROM "
          "service_credentials WHERE rotated_from_id=e.credential_id));"),
      ==, 2);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events a JOIN audit_intentions i "
          "ON a.id=i.audit_id WHERE a.action='service.credential.rotate' "
          "AND a.resource_id IN (SELECT rotated_from_id FROM "
          "service_credentials WHERE rotated_from_id IS NOT NULL) "
          "AND i.state='pending';"), ==, 1);

  gboolean authenticated = TRUE;
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          old_id, old_secret, old_secret_len, &authenticated), ==,
      WYRELOG_E_AUTH);
  g_assert_false (authenticated);
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          new_id, new_secret, new_secret_len, &authenticated), ==,
      WYRELOG_E_OK);
  g_assert_true (authenticated);
  sqlite3_stmt *sanitation = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE "
          "coalesce(subject_id,'')||coalesce(action,'')||"
          "coalesce(resource_id,'')||coalesce(request_id,'') LIKE ?;", -1,
          &sanitation, NULL), ==, SQLITE_OK);
  g_autofree gchar *secret_pattern = g_strdup_printf ("%%%s%%", new_secret);
  g_assert_cmpint (sqlite3_bind_text (sanitation, 1, secret_pattern, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (sanitation), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int64 (sanitation, 0), ==, 0);
  sqlite3_finalize (sanitation);

  g_assert_cmpint (wyl_service_credential_rotate (handle, old_id, "admin",
          "rotate-happy", expiry, &rotated), ==, WYRELOG_E_POLICY);
  g_assert_null (rotated.secret);
  g_assert_null (rotated.credential.credential_id);

  g_clear_object (&fixture.handle);
  WylHandleOpenOptions reopen_options = {
    .policy_store_path = fixture.db_path,
    .policy_keyprovider_path = fixture.key_spec,
    .audit_store_path = fixture.audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&reopen_options,
          &fixture.handle), ==, WYRELOG_E_OK);
  handle = fixture.handle;
  g_assert_cmpint (wyl_service_credential_rotate (handle, old_id, "admin",
          "rotate-happy", expiry, &rotated), ==, WYRELOG_E_POLICY);
  g_assert_null (rotated.secret);
  wyl_service_credential_t revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle, new_id, "admin",
          "rotate-new-revoke", &revoked), ==, WYRELOG_E_OK);
  wyl_service_credential_clear (&revoked);
  g_assert_cmpint (wyl_service_credential_revoke (handle, old_id, "admin",
          "rotate-old-noop-revoke", &revoked), ==, WYRELOG_E_OK);
  g_assert_cmpuint (revoked.generation, ==, 2);
  wyl_service_credential_clear (&revoked);
  wyl_service_credential_issue_result_clear (&old);
}

static void
assert_rotate_policy_clear (WylHandle *handle, const gchar *id,
    const gchar *request_id, gint64 expiry,
    const wyl_service_credential_rotate_runtime_t *runtime)
{
  wyl_service_credential_issue_result_t out = { 0 };
  out.credential.credential_id = g_strdup ("populated");
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle, id,
          "admin", request_id, expiry, runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
}

static void
test_rotate_policy_rejections (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:rotate-policy:worker");
  gint64 old_expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  wyl_service_credential_issue_result_t expiring = { 0 }, active = { 0 };
  wyl_service_credential_issue_result_t sealed = { 0 }, revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-policy:worker", "tenant-a", "admin", "rp-expiring",
          old_expiry, &expiring), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-policy:worker", "tenant-a", "admin", "rp-active", 0,
          &active), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-policy:worker", "tenant-b", "admin", "rp-sealed", 0,
          &sealed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-policy:worker", "tenant-a", "admin", "rp-revoked", 0,
          &revoked), ==, WYRELOG_E_OK);
  wyl_service_credential_t revoked_dto = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          revoked.credential.credential_id, "admin", "rp-revoke",
          &revoked_dto), ==, WYRELOG_E_OK);
  wyl_service_credential_clear (&revoked_dto);

  wyl_service_credential_rotate_runtime_t clock = {
    .now_us = fixed_now,.data = &old_expiry,
  };
  assert_rotate_policy_clear (handle, expiring.credential.credential_id,
      "rp-old-expired", 0, &clock);
  assert_rotate_policy_clear (handle, active.credential.credential_id,
      "rp-new-expired", old_expiry, &clock);
  assert_rotate_policy_clear (handle, revoked.credential.credential_id,
      "rp-already-revoked", 0, NULL);
  assert_rotate_policy_clear (handle, SECOND_ID, "rp-unknown", 0, NULL);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store_of (handle),
          "tenant-b", TRUE), ==, WYRELOG_E_OK);
  assert_rotate_policy_clear (handle, sealed.credential.credential_id,
      "rp-sealed-tenant", 0, NULL);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store_of (handle),
          "tenant-b", FALSE), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_disable (handle,
          "svc:rotate-policy:worker", "admin", "rp-disable", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  assert_rotate_policy_clear (handle, active.credential.credential_id,
      "rp-disabled-principal", 0, NULL);
  wyl_service_credential_issue_result_clear (&expiring);
  wyl_service_credential_issue_result_clear (&active);
  wyl_service_credential_issue_result_clear (&sealed);
  wyl_service_credential_issue_result_clear (&revoked);
}

typedef struct
{
  WylHandle *handle;
  const gchar *old_id;
  const gchar *request_id;
  wyrelog_error_t rc;
  wyl_service_credential_issue_result_t out;
} RotateThread;

static gpointer
rotate_thread (gpointer data)
{
  RotateThread *thread = data;
  thread->rc = wyl_service_credential_rotate (thread->handle, thread->old_id,
      "admin", thread->request_id, 0, &thread->out);
  return NULL;
}

static void
test_rotate_concurrency (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:rotate-race:worker");
  wyl_service_credential_issue_result_t old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-race:worker", "tenant-a", "admin", "race-old", 0,
          &old), ==, WYRELOG_E_OK);
  RotateThread a = {
    .handle = handle,.old_id = old.credential.credential_id,
    .request_id = "race-a",.rc = -1,
  };
  RotateThread b = {
    .handle = handle,.old_id = old.credential.credential_id,
    .request_id = "race-b",.rc = -1,
  };
  GThread *ta = g_thread_new ("rotate-a", rotate_thread, &a);
  GThread *tb = g_thread_new ("rotate-b", rotate_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);
  g_assert_true ((a.rc == WYRELOG_E_OK && b.rc == WYRELOG_E_POLICY)
      || (a.rc == WYRELOG_E_POLICY && b.rc == WYRELOG_E_OK));
  g_assert_true ((a.out.secret != NULL) != (b.out.secret != NULL));
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials "
          "WHERE rotated_from_id IS NOT NULL;"), ==, 1);
  wyl_service_credential_issue_result_clear (&a.out);
  wyl_service_credential_issue_result_clear (&b.out);
  wyl_service_credential_issue_result_clear (&old);
}

static void
test_rotate_stale_expected_generation_has_no_effects (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:rotate-cas:worker");
  wyl_service_credential_issue_result_t old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-cas:worker", "tenant-a", "admin", "cas-old", 0,
          &old), ==, WYRELOG_E_OK);
  CollisionRuntime state = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &state,
  };
  wyl_service_credential_rotate_runtime_t runtime = {
    .credential_runtime = &credential_runtime,
    .old_credential_generation = old.credential.generation + 1,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle,
          old.credential.credential_id, "admin", "cas-stale", 0, &runtime,
          &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpuint (state.ids, ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials "
          "WHERE rotated_from_id IS NOT NULL;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events "
          "WHERE request_id='cas-stale';"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE request_id='cas-stale';"),
      ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_operation_fences "
          "WHERE request_id='cas-stale';"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='cas-stale';"), ==, 0);
  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_issue_result_clear (&old);
}

static void
test_rotate_collision_retry_and_wipe (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:rotate-collision:worker");
  wyl_service_credential_issue_result_t old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-collision:worker", "tenant-a", "admin", "rc-old", 0,
          &old), ==, WYRELOG_E_OK);
  exec_ok (db_of (handle),
      "INSERT INTO service_credentials(credential_id,"
      "credential_format_version,subject_id,tenant_id,generation,state,"
      "verifier_version,salt,verifier,created_by,created_at_us,updated_at_us) "
      "VALUES('" COLLISION_ID "',1,'svc:rotate-collision:worker',"
      "'tenant-a',1,'active',1,zeroblob(16),zeroblob(32),'admin',1,1);");
  CollisionRuntime state = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &state,
  };
  wyl_service_credential_rotate_runtime_t runtime = {
    .credential_runtime = &credential_runtime,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle,
          old.credential.credential_id, "admin", "rc-rotate", 0, &runtime,
          &out), ==, WYRELOG_E_OK);
  g_assert_cmpuint (state.ids, ==, 2);
  g_assert_cmpstr (out.credential.credential_id, ==, SECOND_ID);
  wyl_service_credential_issue_result_clear (&out);
  g_assert_cmpuint (state.allocs, ==, state.frees);
  g_assert_cmpuint (state.unlocks, ==, state.frees);
  g_assert_cmpuint (state.wipes, >=, state.frees);
  wyl_service_credential_issue_result_clear (&old);

  wyl_service_credential_issue_result_t exhausted = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-collision:worker", "tenant-a", "admin", "rc-old-2", 0,
          &exhausted), ==, WYRELOG_E_OK);
  memset (&state, 0, sizeof state);
  state.always_collision = TRUE;
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle,
          exhausted.credential.credential_id, "admin", "rc-exhausted", 0,
          &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_cmpuint (state.ids, ==, 4);
  g_assert_cmpuint (state.allocs, ==, state.frees);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='rc-exhausted';"), ==, 0);
  wyl_service_credential_issue_result_clear (&exhausted);

  wyl_service_credential_issue_result_t generation_fault = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:rotate-collision:worker", "tenant-a", "admin", "rc-old-3", 0,
          &generation_fault), ==, WYRELOG_E_OK);
  memset (&state, 0, sizeof state);
  state.random_fail = TRUE;
  g_assert_cmpint (wyl_service_credential_rotate_with_runtime (handle,
          generation_fault.credential.credential_id, "admin",
          "rc-generation-fault", 0, &runtime, &out), ==, WYRELOG_E_CRYPTO);
  g_assert_null (out.secret);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='rc-generation-fault';"), ==, 0);
  wyl_service_credential_issue_result_clear (&generation_fault);
}

static void
assert_failed_rotate_rolled_back (WylHandle *handle,
    const wyl_service_credential_issue_result_t *old, const gchar *request_id)
{
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate (handle,
          old->credential.credential_id, "admin", request_id, 0, &out), !=,
      WYRELOG_E_OK);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials "
          "WHERE rotated_from_id IS NOT NULL;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests WHERE request_id="
          "'rotate-fault';"), ==, 0);
}

static void
assert_credential_verifies (WylHandle *handle,
    const wyl_service_credential_issue_result_t *credential)
{
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (credential->secret, &secret_len);
  gboolean authenticated = FALSE;
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          credential->credential.credential_id, secret, secret_len,
          &authenticated), ==, WYRELOG_E_OK);
  g_assert_true (authenticated);
}

static void
test_rotate_faults_and_overflow (void)
{
  static const wyl_policy_service_rotate_fail_stage_t stages[] = {
    WYL_POLICY_SERVICE_ROTATE_FAIL_INSERT,
    WYL_POLICY_SERVICE_ROTATE_FAIL_OLD_UPDATE,
    WYL_POLICY_SERVICE_ROTATE_FAIL_SUCCESSOR_EVENT,
    WYL_POLICY_SERVICE_ROTATE_FAIL_OLD_EVENT,
    WYL_POLICY_SERVICE_ROTATE_FAIL_AUDIT,
    WYL_POLICY_SERVICE_ROTATE_FAIL_INTENTION,
    WYL_POLICY_SERVICE_ROTATE_FAIL_VALIDATOR,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (stages); i++) {
    g_auto (Fixture) fixture = { 0 };
    fixture_init (&fixture);
    WylHandle *handle = fixture.handle;
    prepare_authority (handle, "svc:rotate-fault:worker");
    wyl_service_credential_issue_result_t old = { 0 };
    g_assert_cmpint (wyl_service_credential_issue (handle,
            "svc:rotate-fault:worker", "tenant-a", "admin", "rf-old", 0,
            &old), ==, WYRELOG_E_OK);
    wyl_policy_store_service_rotate_fail_once (store_of (handle), stages[i]);
    assert_failed_rotate_rolled_back (handle, &old, "rotate-fault");
    assert_credential_verifies (handle, &old);
    wyl_service_credential_issue_result_clear (&old);
  }

  g_auto (Fixture) commit_fixture = { 0 };
  fixture_init (&commit_fixture);
  WylHandle *commit = commit_fixture.handle;
  prepare_authority (commit, "svc:rotate-commit:worker");
  wyl_service_credential_issue_result_t commit_old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (commit,
          "svc:rotate-commit:worker", "tenant-a", "admin", "rf-commit-old",
          0, &commit_old), ==, WYRELOG_E_OK);
  wyl_policy_store_service_lifecycle_fail_commit_once (store_of (commit));
  assert_failed_rotate_rolled_back (commit, &commit_old, "rotate-fault");
  assert_credential_verifies (commit, &commit_old);
  wyl_service_credential_issue_result_clear (&commit_old);

  g_auto (Fixture) overflow_fixture = { 0 };
  fixture_init (&overflow_fixture);
  WylHandle *overflow = overflow_fixture.handle;
  prepare_authority (overflow, "svc:rotate-overflow:worker");
  wyl_service_credential_issue_result_t overflow_old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (overflow,
          "svc:rotate-overflow:worker", "tenant-a", "admin", "rf-o-old", 0,
          &overflow_old), ==, WYRELOG_E_OK);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db_of (overflow),
          "UPDATE service_credentials SET generation=9223372036854775807 "
          "WHERE credential_id=?;", -1, &stmt, NULL), ==, SQLITE_OK);
  sqlite3_bind_text (stmt, 1, overflow_old.credential.credential_id, -1,
      SQLITE_TRANSIENT);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  assert_failed_rotate_rolled_back (overflow, &overflow_old, "rotate-fault");
  assert_credential_verifies (overflow, &overflow_old);
  wyl_service_credential_issue_result_clear (&overflow_old);
}

static void
test_rotate_missing_cvk_does_not_recreate (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:rotate-cvk:worker");
  wyl_service_credential_issue_result_t old = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (fixture.handle,
          "svc:rotate-cvk:worker", "tenant-a", "admin", "cvk-old", 0, &old),
      ==, WYRELOG_E_OK);
  g_autofree gchar *old_id = g_strdup (old.credential.credential_id);
  exec_ok (db_of (fixture.handle), "DELETE FROM service_credential_cvk;");
  g_clear_object (&fixture.handle);
  WylHandleOpenOptions options = {
    .policy_store_path = fixture.db_path,
    .policy_keyprovider_path = fixture.key_spec,
    .audit_store_path = fixture.audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &fixture.handle),
      ==, WYRELOG_E_OK);
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate (fixture.handle, old_id,
          "admin", "cvk-rotate", 0, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_cmpint (scalar (db_of (fixture.handle),
          "SELECT count(*) FROM service_credential_cvk;"), ==, 0);
  g_assert_cmpint (scalar (db_of (fixture.handle),
          "SELECT count(*) FROM service_credentials;"), ==, 1);
  wyl_service_credential_issue_result_clear (&old);
}

static void
test_revoke_invalidation_failure_marks_result_unavailable (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:revoke-hook:worker");
  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (fixture.handle,
          "svc:revoke-hook:worker", "tenant-a", "admin", "hook-issue", 0,
          &issued), ==, WYRELOG_E_OK);
  InvalidationProbe probe = {.fail = TRUE };
  wyl_service_credential_revoke_runtime_t runtime = {
    .invalidate_credential = probe_credential_invalidation,
    .invalidation_data = &probe,
  };
  wyl_service_credential_t out = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke_with_runtime (fixture.handle,
          issued.credential.credential_id, "admin", "hook-revoke", &runtime,
          &out), ==, WYRELOG_E_IO);
  g_assert_true (probe.called);
  g_assert_null (out.credential_id);
  g_assert_cmpint (scalar (db_of (fixture.handle),
          "SELECT count(*) FROM service_credentials WHERE state='revoked';"),
      ==, 1);
  g_clear_pointer (&probe.credential_id, g_free);
  wyl_service_credential_issue_result_clear (&issued);
}

static void
classifier_transaction_begin (WylHandle *handle, Txn *transaction)
{
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &transaction->lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store_of (handle), handle, transaction->lease, &transaction->txn), ==,
      WYRELOG_E_OK);
}

static void
classifier_transaction_end (Txn *transaction)
{
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (transaction->txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (transaction->txn);
  if (transaction->evidence != NULL)
    wyl_policy_store_service_authority_commit_evidence_unref
        (transaction->evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (transaction->lease),
      ==, WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (transaction->lease);
  memset (transaction, 0, sizeof *transaction);
}

static void
retirement_transaction_prepare (wyl_policy_store_t *store, Txn *transaction)
{
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (transaction->txn, store, &transaction->evidence), ==, WYRELOG_E_OK);
}

static void
retirement_transaction_commit (Txn *transaction)
{
  g_assert_nonnull (transaction->evidence);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (transaction->txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (transaction->txn);
  wyl_policy_store_service_authority_commit_evidence_unref
      (transaction->evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (transaction->lease),
      ==, WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (transaction->lease);
  memset (transaction, 0, sizeof *transaction);
}

static gint64
retirement_fixed_now (gpointer data)
{
  return *(const gint64 *) data;
}

#ifdef WYL_TEST_HAS_HANDOFF_MAINTENANCE_CORE
static void
classifier_transaction_prepare_evidence (wyl_policy_store_t *store,
    Txn *transaction)
{
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (transaction->txn, store, &transaction->evidence), ==, WYRELOG_E_OK);
}

static void
classifier_transaction_commit (Txn *transaction)
{
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (transaction->txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (transaction->txn);
  if (transaction->evidence != NULL)
    wyl_policy_store_service_authority_commit_evidence_unref
        (transaction->evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (transaction->lease),
      ==, WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (transaction->lease);
  memset (transaction, 0, sizeof *transaction);
}

static gint64
maintenance_fixed_now (gpointer data)
{
  return *(const gint64 *) data;
}

typedef struct
{
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t escrow_id;
  guint8 target_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  gint64 deadline_at_us;
  wyl_service_credential_handoff_result_t issued;
  WylPolicyServiceHandoffMaintenanceProof proof;
} MaintenanceCommitted;

static void
maintenance_committed_clear (MaintenanceCommitted *committed)
{
  wyl_service_credential_handoff_result_clear (&committed->issued);
  sodium_memzero (committed, sizeof *committed);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (MaintenanceCommitted,
    maintenance_committed_clear);

static void
maintenance_committed_init (WylHandle *handle, const gchar *subject_id,
    MaintenanceCommitted *committed)
{
  memset (committed, 0, sizeof *committed);
  g_assert_cmpint (wyl_request_id_new (committed->request_id,
          sizeof committed->request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&committed->escrow_id), ==, WYRELOG_E_OK);
  memset (committed->target_digest, 0x73, sizeof committed->target_digest);
  committed->deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR;
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &committed->escrow_id,
    .target_digest = committed->target_digest,
    .deadline_at_us = committed->deadline_at_us,
  };
  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  wyl_service_credential_issue_runtime_t runtime = {
    .authorization = &authorization,
  };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          subject_id, "tenant-a", "admin", committed->request_id,
          committed->deadline_at_us + G_TIME_SPAN_HOUR, &handoff, &runtime,
          &committed->issued), ==, WYRELOG_E_OK);
  committed->proof = (WylPolicyServiceHandoffMaintenanceProof) {
    .tuple = {
      .original_request_id = committed->request_id,
      .escrow_id = &committed->escrow_id,
      .successor_credential_id = committed->issued.credential.credential_id,
      .successor_issuance_generation = committed->issued.credential.generation,
      .original_actor_subject_id = "admin",
  },.operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,.subject_id =
        subject_id,.tenant_id = "tenant-a",.deadline_at_us =
        committed->deadline_at_us,};
  memcpy (committed->proof.tuple.binding_digest,
      committed->issued.handoff.binding_digest,
      sizeof committed->proof.tuple.binding_digest);
  memcpy (committed->proof.target_digest, committed->target_digest,
      sizeof committed->proof.target_digest);
  g_free (probe.actor_subject_id);
}

static wyrelog_error_t
maintenance_committed_classify (WylHandle *handle,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult *out, gboolean commit)
{
  Txn transaction = { 0 };
  classifier_transaction_begin (handle, &transaction);
  wyrelog_error_t rc = wyl_policy_store_handoff_maintain_committed_core
      (transaction.txn, store_of (handle), proof, out);
  if (commit && rc == WYRELOG_E_OK)
    classifier_transaction_commit (&transaction);
  else
    classifier_transaction_end (&transaction);
  return rc;
}

static wyrelog_error_t
maintenance_current_attention_resolve (WylHandle *handle,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult *out)
{
  Txn transaction = { 0 };
  classifier_transaction_begin (handle, &transaction);
  wyrelog_error_t rc =
      wyl_policy_store_handoff_resolve_current_attention_core
      (transaction.txn, store_of (handle), proof, out);
  classifier_transaction_end (&transaction);
  return rc;
}

static void
maintenance_assert_prepared_policy_no_mutation (WylHandle *handle,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    MutationEffects expected)
{
  Txn transaction = { 0 };
  WylPolicyServiceHandoffPreparedMaintenanceResult result = { 0 };
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (transaction.txn, store_of (handle), proof, &result), ==,
      WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  assert_mutation_effects_equal (mutation_effects (handle), expected);
  wyl_policy_service_handoff_prepared_maintenance_result_clear (&result);
}

static void
    maintenance_attention_semantic_key
    (const WylPolicyServiceHandoffExactTuple * tuple, const gchar * reason,
    guint8 out[crypto_generichash_BYTES])
{
  gchar escrow[WYL_ID_STRING_BUF];
  gchar generation[32];
  gchar binding[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  g_assert_cmpint (wyl_id_format (tuple->escrow_id, escrow, sizeof escrow),
      ==, WYRELOG_E_OK);
  g_snprintf (generation, sizeof generation, "%" G_GUINT64_FORMAT,
      tuple->successor_issuance_generation);
  sodium_bin2hex (binding, sizeof binding, tuple->binding_digest,
      sizeof tuple->binding_digest);
  const gchar *fields[] = {
    tuple->original_request_id, reason, "attention_required", escrow,
    binding, tuple->successor_credential_id, generation, "none", "",
  };
  crypto_generichash_state state;
  g_assert_cmpint (crypto_generichash_init (&state, NULL, 0, sizeof out[0]
          * crypto_generichash_BYTES), ==, 0);
  static const gchar domain[] = "wyrelog.service-handoff-disposition.v2";
  g_assert_cmpint (crypto_generichash_update (&state,
          (const guint8 *) domain, sizeof domain - 1), ==, 0);
  static const guint8 separator = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (fields); i++) {
    g_assert_cmpint (crypto_generichash_update (&state,
            (const guint8 *) fields[i], strlen (fields[i])), ==, 0);
    g_assert_cmpint (crypto_generichash_update (&state, &separator, 1), ==, 0);
  }
  g_assert_cmpint (crypto_generichash_final (&state, out,
          crypto_generichash_BYTES), ==, 0);
}

static void
maintenance_insert_cancelled_attention (WylHandle *handle,
    const WylPolicyServiceHandoffExactTuple *tuple, gint64 created_at_us,
    gchar disposition_id[WYL_ID_STRING_BUF], gchar audit_id[WYL_ID_STRING_BUF])
{
  new_uuid_string (disposition_id);
  new_uuid_string (audit_id);
  static const gchar actor[] = "system:service-handoff-maintenance";
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_policy_store_append_audit_event_full (store_of (handle),
          audit_id, created_at_us, actor,
          "service.credential.handoff.disposition",
          tuple->original_request_id, NULL, NULL, tuple->original_request_id,
          WYL_DECISION_ALLOW, &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  inserted = FALSE;
  g_assert_cmpint (wyl_policy_store_record_audit_intention_full
      (store_of (handle), audit_id, created_at_us, actor,
          "service.credential.handoff.disposition",
          tuple->original_request_id, NULL, NULL, tuple->original_request_id,
          WYL_DECISION_ALLOW, &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);

  guint8 semantic_key[crypto_generichash_BYTES];
  maintenance_attention_semantic_key (tuple, "operation_cancelled",
      semantic_key);
  gchar escrow[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_format (tuple->escrow_id, escrow, sizeof escrow),
      ==, WYRELOG_E_OK);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db_of (handle),
          "INSERT INTO service_credential_handoff_dispositions"
          " (disposition_id,semantic_key,original_request_id,escrow_id,"
          " binding_digest,successor_credential_id,"
          " successor_issuance_generation,actor_subject_id,reason,outcome,"
          " audit_id,created_at_us) VALUES(?,?,?,?,?,?,?,?,?,?,?,?);", -1,
          &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, disposition_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob (stmt, 2, semantic_key,
          sizeof semantic_key, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 3, tuple->original_request_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 4, escrow, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob (stmt, 5, tuple->binding_digest,
          sizeof tuple->binding_digest, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 6,
          tuple->successor_credential_id, -1, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (stmt, 7,
          (sqlite3_int64) tuple->successor_issuance_generation), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 8, actor, -1, SQLITE_TRANSIENT),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 9, "operation_cancelled", -1,
          SQLITE_STATIC), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 10, "attention_required", -1,
          SQLITE_STATIC), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 11, audit_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (stmt, 12, created_at_us), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  sodium_memzero (semantic_key, sizeof semantic_key);
}

static void
test_handoff_maintenance_escrow_clock_and_attention (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:maintenance-committed");
  g_auto (MaintenanceCommitted) committed = { 0 };
  maintenance_committed_init (handle,
      "svc:handoff:maintenance-committed", &committed);
  wyl_policy_store_t *store = store_of (handle);
  gint64 now_us = committed.deadline_at_us - 1;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store,
      maintenance_fixed_now, &now_us);

  MutationEffects before = mutation_effects (handle);
  WylPolicyServiceHandoffCommittedMaintenanceResult result = { 0 };
  g_assert_cmpint (maintenance_committed_classify (handle, &committed.proof,
          &result, FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ACTIVE);
  g_assert_cmpint (result.created_at_us, ==, now_us);
  assert_mutation_effects_equal (mutation_effects (handle), before);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);

  static const struct
  {
    const gchar *name;
    guint kind;
  } mismatches[] = {
    {"actor", 1}, {"target", 2}, {"deadline", 3}, {"binding", 4},
    {"successor", 5}, {"generation", 6}, {"request", 7},
    {"operation", 8},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (mismatches); i++) {
    WylPolicyServiceHandoffMaintenanceProof foreign = committed.proof;
    gchar other_request[WYL_REQUEST_ID_STRING_BUF];
    if (mismatches[i].kind == 1)
      foreign.tuple.original_actor_subject_id = "other-admin";
    else if (mismatches[i].kind == 2)
      foreign.target_digest[0] ^= 0xff;
    else if (mismatches[i].kind == 3)
      foreign.deadline_at_us++;
    else if (mismatches[i].kind == 4)
      foreign.tuple.binding_digest[0] ^= 0xff;
    else if (mismatches[i].kind == 5)
      foreign.tuple.successor_credential_id = SECOND_ID;
    else if (mismatches[i].kind == 6)
      foreign.tuple.successor_issuance_generation++;
    else if (mismatches[i].kind == 7) {
      g_assert_cmpint (wyl_request_id_new (other_request,
              sizeof other_request), ==, WYRELOG_E_OK);
      foreign.tuple.original_request_id = other_request;
    } else {
      foreign.operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
      foreign.subject_id = NULL;
      foreign.tenant_id = NULL;
      foreign.old_credential_id = committed.issued.credential.credential_id;
    }
    g_test_message ("escrow mismatch: %s", mismatches[i].name);
    g_assert_cmpint (maintenance_committed_classify (handle, &foreign,
            &result, FALSE), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.outcome, ==,
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_FOREIGN);
    wyl_policy_service_handoff_committed_maintenance_result_clear (&result);
  }
  WylPolicyServiceHandoffMaintenanceProof missing = committed.proof;
  wyl_id_t missing_escrow;
  gchar missing_request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&missing_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (missing_request,
          sizeof missing_request), ==, WYRELOG_E_OK);
  missing.tuple.escrow_id = &missing_escrow;
  missing.tuple.original_request_id = missing_request;
  g_assert_cmpint (maintenance_committed_classify (handle, &missing, &result,
          FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_MISSING);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);
  WylPolicyServiceHandoffExactTuple foreign_missing_artifact = missing.tuple;
  wyl_id_t foreign_missing_escrow;
  g_assert_cmpint (wyl_id_new (&foreign_missing_escrow), ==, WYRELOG_E_OK);
  foreign_missing_artifact.escrow_id = &foreign_missing_escrow;
  foreign_missing_artifact.binding_digest[0] ^= 0xff;
  gchar foreign_missing_disposition[WYL_ID_STRING_BUF];
  gchar foreign_missing_audit[WYL_ID_STRING_BUF];
  maintenance_insert_cancelled_attention (handle, &foreign_missing_artifact,
      now_us, foreign_missing_disposition, foreign_missing_audit);
  g_assert_cmpint (maintenance_committed_classify (handle, &missing, &result,
          FALSE), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.outcome, ==, 0);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);

  now_us = committed.deadline_at_us;
  WylPolicyServiceHandoffMaintenanceProof prepared_proof = committed.proof;
  prepared_proof.tuple.successor_credential_id = NULL;
  prepared_proof.tuple.successor_issuance_generation = 0;
  sodium_memzero (prepared_proof.tuple.binding_digest,
      sizeof prepared_proof.tuple.binding_digest);
  Txn prepared_transaction = { 0 };
  classifier_transaction_begin (handle, &prepared_transaction);
  classifier_transaction_prepare_evidence (store, &prepared_transaction);
  WylPolicyServiceHandoffPreparedMaintenanceResult prepared_result = { 0 };
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (prepared_transaction.txn, store, &prepared_proof, &prepared_result),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (prepared_result.outcome, ==,
      WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_COMMITTED);
  g_assert_cmpstr (prepared_result.successor_credential_id, ==,
      committed.issued.credential.credential_id);
  g_assert_cmpuint (prepared_result.successor_generation, ==,
      committed.issued.credential.generation);
  g_assert_cmpmem (prepared_result.binding_digest,
      sizeof prepared_result.binding_digest,
      committed.issued.handoff.binding_digest,
      sizeof committed.issued.handoff.binding_digest);
  classifier_transaction_end (&prepared_transaction);
  wyl_policy_service_handoff_prepared_maintenance_result_clear
      (&prepared_result);

  g_assert_cmpint (maintenance_committed_classify (handle, &committed.proof,
          &result, TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED);
  g_assert_false (result.disposition.replayed);
  g_assert_cmpint (result.created_at_us, ==, committed.deadline_at_us);
  g_autofree gchar *expired_disposition =
      g_strdup (result.disposition.disposition_id);
  g_autofree gchar *expired_audit = g_strdup (result.disposition.audit_id);
  gint64 expired_created_at_us = result.created_at_us;
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);

  now_us = committed.deadline_at_us - G_TIME_SPAN_MINUTE;
  before = mutation_effects (handle);
  g_assert_cmpint (maintenance_committed_classify (handle, &committed.proof,
          &result, FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED);
  g_assert_true (result.disposition.replayed);
  g_assert_cmpstr (result.disposition.disposition_id, ==, expired_disposition);
  g_assert_cmpstr (result.disposition.audit_id, ==, expired_audit);
  g_assert_cmpint (result.created_at_us, ==, expired_created_at_us);
  assert_mutation_effects_equal (mutation_effects (handle), before);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);

  gchar cancelled_disposition[WYL_ID_STRING_BUF];
  gchar cancelled_audit[WYL_ID_STRING_BUF];
  maintenance_insert_cancelled_attention (handle, &committed.proof.tuple,
      expired_created_at_us + 1, cancelled_disposition, cancelled_audit);
  g_assert_cmpint (maintenance_committed_classify (handle, &committed.proof,
          &result, FALSE), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.outcome, ==, 0);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store, NULL, NULL);

  g_auto (Fixture) precedence_fixture = { 0 };
  fixture_init (&precedence_fixture);
  WylHandle *precedence_handle = precedence_fixture.handle;
  prepare_authority (precedence_handle, "svc:handoff:maintenance-precedence");
  g_auto (MaintenanceCommitted) precedence = { 0 };
  maintenance_committed_init (precedence_handle,
      "svc:handoff:maintenance-precedence", &precedence);
  gint64 precedence_now = precedence.deadline_at_us;
  wyl_policy_store_handoff_maintenance_set_clock_for_test
      (store_of (precedence_handle), maintenance_fixed_now, &precedence_now);
  g_assert_cmpint (maintenance_committed_classify (precedence_handle,
          &precedence.proof, &result, TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);
  wyl_service_credential_t revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (precedence_handle,
          precedence.issued.credential.credential_id, "operator",
          "maintenance-revoke", &revoked), ==, WYRELOG_E_OK);
  precedence_now += G_TIME_SPAN_MINUTE;
  g_assert_cmpint (maintenance_committed_classify (precedence_handle,
          &precedence.proof, &result, TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_REVOKED);
  g_assert_false (result.disposition.replayed);
  g_assert_cmpint (result.created_at_us, ==, precedence_now);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);
  WylPolicyServiceHandoffExactTuple foreign_revoked_artifact =
      precedence.proof.tuple;
  wyl_id_t foreign_revoked_escrow;
  g_assert_cmpint (wyl_id_new (&foreign_revoked_escrow), ==, WYRELOG_E_OK);
  foreign_revoked_artifact.escrow_id = &foreign_revoked_escrow;
  foreign_revoked_artifact.binding_digest[0] ^= 0xff;
  gchar foreign_revoked_disposition[WYL_ID_STRING_BUF];
  gchar foreign_revoked_audit[WYL_ID_STRING_BUF];
  maintenance_insert_cancelled_attention (precedence_handle,
      &foreign_revoked_artifact, precedence_now + 1,
      foreign_revoked_disposition, foreign_revoked_audit);
  g_assert_cmpint (maintenance_committed_classify (precedence_handle,
          &precedence.proof, &result, FALSE), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.outcome, ==, 0);
  wyl_policy_service_handoff_committed_maintenance_result_clear (&result);
  wyl_service_credential_clear (&revoked);
  wyl_policy_store_handoff_maintenance_set_clock_for_test
      (store_of (precedence_handle), NULL, NULL);
}

static void
test_handoff_maintenance_prepared_replay_and_rollback (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:maintenance-prepared");
  wyl_policy_store_t *store = store_of (handle);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t escrow_id;
  g_assert_cmpint (wyl_request_id_new (request_id, sizeof request_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  gint64 now_us = g_get_real_time () + G_TIME_SPAN_HOUR;
  WylPolicyServiceHandoffMaintenanceProof proof = {
    .tuple = {
          .original_request_id = request_id,
          .escrow_id = &escrow_id,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
    .subject_id = "svc:handoff:maintenance-prepared",
    .tenant_id = "tenant-a",
    .deadline_at_us = now_us,
  };
  memset (proof.target_digest, 0x61, sizeof proof.target_digest);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store,
      maintenance_fixed_now, &now_us);

  WylPolicyServiceHandoffPreparedMaintenanceResult result = { 0 };
  Txn transaction = { 0 };
  classifier_transaction_begin (handle, &transaction);
  classifier_transaction_prepare_evidence (store, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (transaction.txn, store, &proof, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED);
  g_assert_false (result.disposition.replayed);
  g_assert_cmpint (result.created_at_us, ==, now_us);
  g_autofree gchar *disposition_id =
      g_strdup (result.disposition.disposition_id);
  g_autofree gchar *audit_id = g_strdup (result.disposition.audit_id);
  classifier_transaction_commit (&transaction);
  wyl_policy_service_handoff_prepared_maintenance_result_clear (&result);

  MutationEffects committed = mutation_effects (handle);
  now_us += G_TIME_SPAN_HOUR;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (transaction.txn, store, &proof, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED);
  g_assert_true (result.disposition.replayed);
  g_assert_cmpstr (result.disposition.disposition_id, ==, disposition_id);
  g_assert_cmpstr (result.disposition.audit_id, ==, audit_id);
  g_assert_cmpint (result.created_at_us, <, now_us);
  classifier_transaction_end (&transaction);
  assert_mutation_effects_equal (mutation_effects (handle), committed);
  wyl_policy_service_handoff_prepared_maintenance_result_clear (&result);

  WylPolicyServiceHandoffMaintenanceProof tampered = proof;
  tampered.tuple.original_actor_subject_id = "other-admin";
  maintenance_assert_prepared_policy_no_mutation (handle, &tampered, committed);

  tampered = proof;
  tampered.target_digest[0] ^= 0xff;
  maintenance_assert_prepared_policy_no_mutation (handle, &tampered, committed);

  tampered = proof;
  tampered.deadline_at_us++;
  maintenance_assert_prepared_policy_no_mutation (handle, &tampered, committed);

  tampered = proof;
  tampered.subject_id = "svc:handoff:maintenance-other";
  maintenance_assert_prepared_policy_no_mutation (handle, &tampered, committed);

  tampered = proof;
  tampered.operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
  tampered.subject_id = NULL;
  tampered.tenant_id = NULL;
  tampered.old_credential_id = COLLISION_ID;
  maintenance_assert_prepared_policy_no_mutation (handle, &tampered, committed);
  g_autofree gchar *cardinality_sql = g_strdup_printf
      ("SELECT count(*) FROM service_credential_handoff_dispositions"
      " WHERE original_request_id='%s' AND reason='not_committed';",
      request_id);
  g_assert_cmpint (scalar (db_of (handle), cardinality_sql), ==, 1);
  g_autofree gchar *audit_cardinality_sql = g_strdup_printf
      ("SELECT count(*) FROM audit_events WHERE request_id='%s';",
      request_id);
  g_assert_cmpint (scalar (db_of (handle), audit_cardinality_sql), ==, 1);

  gchar not_due_request[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t not_due_escrow;
  g_assert_cmpint (wyl_request_id_new (not_due_request,
          sizeof not_due_request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&not_due_escrow), ==, WYRELOG_E_OK);
  WylPolicyServiceHandoffMaintenanceProof not_due = proof;
  not_due.tuple.original_request_id = not_due_request;
  not_due.tuple.escrow_id = &not_due_escrow;
  not_due.deadline_at_us = now_us + 1;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (transaction.txn, store, &not_due, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.outcome, ==,
      WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_DUE);
  classifier_transaction_end (&transaction);
  assert_mutation_effects_equal (mutation_effects (handle), committed);
  wyl_policy_service_handoff_prepared_maintenance_result_clear (&result);

  gchar escrow_text[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_format (&escrow_id, escrow_text,
          sizeof escrow_text), ==, WYRELOG_E_OK);
  g_autofree gchar *insert_corrupt_escrow = g_strdup_printf
      ("INSERT INTO service_credential_handoff_escrows"
      " (escrow_id,operation,request_id,actor_subject_id,target_digest,"
      " credential_id,credential_generation,deadline_at_us,binding_digest,"
      " sealed_envelope,created_at_us) VALUES"
      " ('%s','issue','corrupt-request','admin',zeroblob(32),'%s',1,1,"
      " zeroblob(32),x'01',1);", escrow_text, COLLISION_ID);
  exec_ok (db_of (handle), insert_corrupt_escrow);
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (transaction.txn, store, &proof, &result), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  exec_ok (db_of (handle),
      "DELETE FROM service_credential_handoff_escrows"
      " WHERE request_id='corrupt-request';");
  wyl_id_t request_corrupt_escrow;
  gchar request_corrupt_escrow_text[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&request_corrupt_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&request_corrupt_escrow,
          request_corrupt_escrow_text, sizeof request_corrupt_escrow_text),
      ==, WYRELOG_E_OK);
  g_autofree gchar *insert_request_corruption = g_strdup_printf
      ("INSERT INTO service_credential_handoff_escrows"
      " (escrow_id,operation,request_id,actor_subject_id,target_digest,"
      " credential_id,credential_generation,deadline_at_us,binding_digest,"
      " sealed_envelope,created_at_us) VALUES"
      " ('%s','issue','%s','admin',zeroblob(32),'%s',1,1,zeroblob(32),"
      " x'01',1);", request_corrupt_escrow_text, request_id, COLLISION_ID);
  exec_ok (db_of (handle), insert_request_corruption);
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (transaction.txn, store, &proof, &result), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  g_autofree gchar *remove_request_corruption = g_strdup_printf
      ("DELETE FROM service_credential_handoff_escrows"
      " WHERE escrow_id='%s';", request_corrupt_escrow_text);
  exec_ok (db_of (handle), remove_request_corruption);

  static const WylPolicyServiceHandoffFailStage stages[] = {
    WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT,
    WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (stages); i++) {
    gchar failed_request[WYL_REQUEST_ID_STRING_BUF];
    wyl_id_t failed_escrow;
    g_assert_cmpint (wyl_request_id_new (failed_request,
            sizeof failed_request), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_new (&failed_escrow), ==, WYRELOG_E_OK);
    WylPolicyServiceHandoffMaintenanceProof failed = proof;
    failed.tuple.original_request_id = failed_request;
    failed.tuple.escrow_id = &failed_escrow;
    failed.deadline_at_us = now_us;
    MutationEffects before_failure = mutation_effects (handle);
    wyl_policy_store_service_handoff_fail_once (store, stages[i]);
    classifier_transaction_begin (handle, &transaction);
    classifier_transaction_prepare_evidence (store, &transaction);
    g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
        (transaction.txn, store, &failed, &result), ==, WYRELOG_E_IO);
    classifier_transaction_end (&transaction);
    assert_mutation_effects_equal (mutation_effects (handle), before_failure);
    wyl_policy_service_handoff_prepared_maintenance_result_clear (&result);
  }
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store, NULL, NULL);
}
#endif

static void
test_handoff_exact_successor_classifier (void)
{
  gchar operation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar other_request_id[WYL_REQUEST_ID_STRING_BUF];
  const gchar *revoke_request_id = "legacy-revoke-request";
  g_assert_cmpint (wyl_request_id_new (operation_request_id,
          sizeof operation_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (other_request_id,
          sizeof other_request_id), ==, WYRELOG_E_OK);
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:classifier");

  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  wyl_service_credential_issue_runtime_t runtime = {
    .authorization = &authorization,
    .credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0x42, sizeof target);
  gint64 expires_at_us = g_get_real_time () + G_TIME_SPAN_HOUR;
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = expires_at_us + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:classifier", "tenant-a", "admin",
          operation_request_id, expires_at_us, &handoff, &runtime, &issued),
      ==, WYRELOG_E_OK);

  WylPolicyServiceHandoffExactTuple tuple = {
    .original_request_id = operation_request_id,
    .escrow_id = &escrow_id,
    .successor_credential_id = issued.credential.credential_id,
    .successor_issuance_generation = issued.credential.generation,
    .original_actor_subject_id = "admin",
  };
  memcpy (tuple.binding_digest, issued.handoff.binding_digest,
      sizeof tuple.binding_digest);

  Txn transaction = { 0 };
  classifier_transaction_begin (handle, &transaction);
  WylPolicyServiceSuccessorExactClassification classification = { 0 };
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us - 1,
          &classification), ==, WYRELOG_E_OK);
  g_assert_cmpint (classification.disposition, ==,
      WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE);
  g_assert_cmpstr (classification.observed_state, ==, "active");
  g_assert_cmpuint (classification.observed_generation, ==, 1);
  g_assert_cmpint (classification.observed_expires_at_us, ==, expires_at_us);
  g_assert_false (classification.has_revocation_event);
  wyl_policy_service_successor_exact_classification_clear (&classification);

  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_OK);
  g_assert_cmpint (classification.disposition, ==,
      WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED);

  wyl_policy_store_service_handoff_fail_once (store_of (handle),
      WYL_POLICY_HANDOFF_FAIL_CLASSIFIER_LOOKUP_NOMEM);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_NOMEM);
  g_assert_cmpint (classification.disposition, ==, 0);
  g_assert_null (classification.observed_state);

  WylPolicyServiceHandoffExactTuple invalid = tuple;
  memset (invalid.binding_digest, 0, sizeof invalid.binding_digest);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (classification.disposition, ==, 0);
  g_assert_null (classification.observed_state);
  invalid = tuple;
  invalid.original_request_id = "not-a-ksuid";
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_INVALID);
  invalid = tuple;
  invalid.original_request_id = other_request_id;
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  invalid = tuple;
  invalid.successor_credential_id = NULL;
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_INVALID);
  invalid = tuple;
  invalid.successor_issuance_generation = 0;
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_INVALID);
  invalid = tuple;
  invalid.successor_issuance_generation++;
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  invalid = tuple;
  invalid.original_actor_subject_id = "different-operator";
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  invalid = tuple;
  invalid.binding_digest[0] ^= 0xff;
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &invalid, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);

  wyl_service_credential_t revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          issued.credential.credential_id, "remediation-operator",
          revoke_request_id, &revoked), ==, WYRELOG_E_OK);
  classifier_transaction_begin (handle, &transaction);
  wyl_policy_store_service_handoff_fail_once (store_of (handle),
      WYL_POLICY_HANDOFF_FAIL_CLASSIFIER_REVOKED_EVENT_NOMEM);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_NOMEM);
  g_assert_cmpint (classification.disposition, ==, 0);
  g_assert_null (classification.observed_state);
  g_assert_null (classification.revocation_event_actor_subject_id);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_OK);
  g_assert_cmpint (classification.disposition, ==,
      WYL_POLICY_SERVICE_SUCCESSOR_REVOKED);
  g_assert_cmpstr (classification.observed_state, ==, "revoked");
  g_assert_cmpuint (classification.observed_generation, ==, 2);
  g_assert_true (classification.has_revocation_event);
  g_assert_cmpint (classification.revocation_event_id, >, 0);
  g_assert_cmpuint (classification.revocation_event_generation, ==, 2);
  g_assert_cmpstr (classification.revocation_event_actor_subject_id, ==,
      "remediation-operator");
  g_assert_cmpstr (classification.revocation_event_request_id, ==,
      revoke_request_id);
  g_assert_cmpint (classification.revocation_event_created_at_us, >, 0);
  wyl_policy_service_successor_exact_classification_clear (&classification);
  classifier_transaction_end (&transaction);

  exec_ok (db_of (handle),
      "CREATE TEMP TABLE revoked_event_backup AS SELECT * FROM"
      " service_credential_events WHERE credential_id='" COLLISION_ID
      "' AND event='revoked';"
      "DROP TRIGGER trg_service_credential_events_no_delete;"
      "DELETE FROM service_credential_events WHERE credential_id='"
      COLLISION_ID "' AND event='revoked';");
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);

  exec_ok (db_of (handle),
      "INSERT INTO service_credential_events"
      " (credential_id,subject_id,tenant_id,event,from_state,to_state,"
      " generation,actor_subject_id,request_id,related_credential_id,"
      " created_at_us) SELECT credential_id,subject_id,tenant_id,event,"
      " from_state,to_state,generation,actor_subject_id,request_id,"
      " related_credential_id,created_at_us FROM revoked_event_backup;"
      "DROP TRIGGER trg_service_credential_events_no_update;"
      "UPDATE service_credential_events SET actor_subject_id='other-actor'"
      " WHERE credential_id='" COLLISION_ID "' AND event='revoked';");
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);

  exec_ok (db_of (handle),
      "UPDATE service_credential_events SET actor_subject_id=(SELECT"
      " actor_subject_id FROM revoked_event_backup),created_at_us=created_at_us+1"
      " WHERE credential_id='" COLLISION_ID "' AND event='revoked';");
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);

  exec_ok (db_of (handle),
      "DELETE FROM service_credential_events WHERE credential_id='"
      COLLISION_ID "' AND event='revoked';"
      "INSERT INTO service_credential_events"
      " (credential_id,subject_id,tenant_id,event,from_state,to_state,"
      " generation,actor_subject_id,request_id,related_credential_id,"
      " created_at_us) SELECT credential_id,subject_id,tenant_id,event,"
      " from_state,to_state,generation,actor_subject_id,request_id,"
      " related_credential_id,created_at_us FROM revoked_event_backup;"
      "INSERT INTO service_credential_events"
      " (credential_id,subject_id,tenant_id,event,from_state,to_state,"
      " generation,actor_subject_id,request_id,related_credential_id,"
      " created_at_us) SELECT credential_id,subject_id,tenant_id,event,"
      " from_state,to_state,generation,actor_subject_id,request_id,"
      " related_credential_id,created_at_us FROM revoked_event_backup;");
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint
      (wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction.txn, store_of (handle), &tuple, expires_at_us,
          &classification), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);

  wyl_service_credential_clear (&revoked);
  wyl_service_credential_handoff_result_clear (&issued);
  g_free (probe.actor_subject_id);
}

static void
    set_remediation_oar_context
    (wyl_service_credential_handoff_remediation_input_t * input,
    guint8 snapshot_byte,
    wyl_service_credential_handoff_remediation_oar_cause_t cause)
{
  input->source_kind =
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED;
  memset (input->journal_snapshot_digest, snapshot_byte,
      sizeof input->journal_snapshot_digest);
  input->observed_state =
      WYL_SERVICE_HANDOFF_REMEDIATION_STATE_OPERATOR_ACTION_REQUIRED;
  input->oar_source_state =
      WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED;
  input->oar_cause = cause;
  input->resume_target_state =
      WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED;
}

static void
test_handoff_remediation_fresh_authorization_and_replay (void)
{
  gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar remediation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar legacy_collision_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (original_request_id,
          sizeof original_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (remediation_request_id,
          sizeof remediation_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (decision_request_id,
          sizeof decision_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (legacy_collision_request_id,
          sizeof legacy_collision_request_id), ==, WYRELOG_E_OK);
  wyl_id_t audit_uuid;
  gchar audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&audit_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&audit_uuid, audit_id, sizeof audit_id), ==,
      WYRELOG_E_OK);

  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:remediation");

  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe issue_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t issue_authorization = {
    .authorize = probe_mutation_authorization,.data = &issue_probe,
  };
  wyl_service_credential_issue_runtime_t issue_runtime = {
    .authorization = &issue_authorization,
    .credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0x62, sizeof target);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:remediation", "tenant-a", "admin",
          original_request_id, g_get_real_time () + G_TIME_SPAN_HOUR,
          &handoff, &issue_runtime, &issued), ==, WYRELOG_E_OK);

  wyl_service_credential_handoff_remediation_input_t input = {
    .remediation_request_id = remediation_request_id,
    .decision_request_id = decision_request_id,
    .current_actor_subject_id = "operator",
    .audit_id = audit_id,
    .tuple = {
          .original_request_id = original_request_id,
          .escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_RESUME,
  };
  memcpy (input.tuple.binding_digest, issued.handoff.binding_digest,
      sizeof input.tuple.binding_digest);

  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_POLICY };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  wyl_service_credential_handoff_remediation_runtime_t runtime = {
    .authorization = &authorization,
  };
  wyl_service_credential_handoff_remediation_result_t result = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_cmpstr (probe.actor_subject_id, ==, "operator");
  g_assert_null (result.audit_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_remediation_actions;"),
      ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_domain_requests WHERE operation="
          "'credential_handoff_remediate';"), ==, 0);

  g_autofree gchar *legacy_collision_sql = g_strdup_printf
      ("INSERT INTO service_domain_requests"
      " (request_id,operation,resource_id,input_fingerprint,created_at_us)"
      " VALUES('%s','credential_revoke','legacy-resource',zeroblob(32),1);",
      legacy_collision_request_id);
  exec_ok (db_of (handle), legacy_collision_sql);
  MutationEffects before_missing_context = mutation_effects (handle);
  probe.rc = WYRELOG_E_OK;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_INVALID);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_missing_context);
  set_remediation_oar_context (&input, 0xa1,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD);
  wyl_service_credential_handoff_remediation_input_t collision_input = input;
  collision_input.remediation_request_id = legacy_collision_request_id;
  MutationEffects before_collision = mutation_effects (handle);
  probe.rc = WYRELOG_E_OK;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &collision_input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle), before_collision);

  probe.calls = 0;
  probe.saw_write_lease = FALSE;
  probe.rc = WYRELOG_E_OK;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_false (result.replayed);
  g_assert_cmpint (result.outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_RECORDED);
  g_assert_cmpstr (result.remediation_request_id, ==, remediation_request_id);
  g_assert_cmpint (result.source_kind, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED);
  g_assert_cmpint (result.observed_state, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_STATE_OPERATOR_ACTION_REQUIRED);
  g_assert_cmpint (result.oar_source_state, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED);
  g_assert_cmpint (result.oar_cause, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD);
  g_assert_cmpint (sodium_is_zero (result.request_fingerprint,
          sizeof result.request_fingerprint), ==, 0);
  g_assert_cmpint (sodium_memcmp (result.journal_snapshot_digest,
          input.journal_snapshot_digest,
          sizeof result.journal_snapshot_digest), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_remediation_actions;"),
      ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_remediation_actions r"
          " JOIN audit_events e ON e.id=r.audit_id"
          " JOIN audit_intentions i ON i.audit_id=r.audit_id"
          " WHERE r.created_at_us=e.created_at_us"
          " AND r.created_at_us=i.created_at_us"
          " AND e.subject_id=r.current_actor_subject_id"
          " AND i.subject_id=r.current_actor_subject_id"
          " AND e.request_id=r.remediation_request_id"
          " AND i.request_id=r.remediation_request_id;"), ==, 1);
  wyl_service_credential_handoff_remediation_result_clear (&result);

  probe.calls = 0;
  wyl_service_credential_handoff_remediation_runtime_t resolve_runtime = {
    .authorization = &authorization,
  };
  g_assert_cmpint (wyl_service_credential_handoff_resolve_remediation (handle,
          remediation_request_id, "operator", &resolve_runtime, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (result.replayed);
  g_assert_cmpstr (result.decision_request_id, ==, decision_request_id);
  g_assert_cmpstr (result.original_request_id, ==, original_request_id);
  g_assert_cmpstr (result.original_actor_subject_id, ==, "admin");
  g_assert_cmpint (result.escrow_outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_RETAINED);
  wyl_service_credential_handoff_remediation_result_clear (&result);

  g_assert_cmpint
      (wyl_service_credential_handoff_resolve_remediation_incident (handle,
          original_request_id, input.journal_snapshot_digest, &result), ==,
      WYRELOG_E_OK);
  g_assert_true (result.replayed);
  g_assert_cmpstr (result.remediation_request_id, ==, remediation_request_id);
  wyl_service_credential_handoff_remediation_result_clear (&result);

  gchar conflict_remediation[WYL_REQUEST_ID_STRING_BUF];
  gchar conflict_decision[WYL_REQUEST_ID_STRING_BUF];
  gchar conflict_audit[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (conflict_remediation,
          sizeof conflict_remediation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (conflict_decision,
          sizeof conflict_decision), ==, WYRELOG_E_OK);
  new_uuid_string (conflict_audit);
  MutationEffects before_exact_tamper = mutation_effects (handle);
  wyl_service_credential_handoff_remediation_input_t tampered = input;
  tampered.decision_request_id = conflict_decision;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &tampered, &runtime, &result), ==, WYRELOG_E_POLICY);
  tampered = input;
  tampered.audit_id = conflict_audit;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &tampered, &runtime, &result), ==, WYRELOG_E_POLICY);
  tampered = input;
  tampered.oar_cause = WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_FOREIGN;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &tampered, &runtime, &result), ==, WYRELOG_E_POLICY);
  tampered = input;
  tampered.action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE;
  tampered.confirmation_version = 1;
  tampered.confirmed = TRUE;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &tampered, &runtime, &result), ==, WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_exact_tamper);
  wyl_service_credential_handoff_remediation_input_t conflict = input;
  conflict.remediation_request_id = conflict_remediation;
  conflict.decision_request_id = conflict_decision;
  conflict.audit_id = conflict_audit;
  conflict.action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE;
  conflict.confirmation_version = 1;
  conflict.confirmed = TRUE;
  MutationEffects before_incident_conflict = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &conflict, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_incident_conflict);

  gchar epoch_remediation[WYL_REQUEST_ID_STRING_BUF];
  gchar epoch_decision[WYL_REQUEST_ID_STRING_BUF];
  gchar epoch_audit[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (epoch_remediation,
          sizeof epoch_remediation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (epoch_decision,
          sizeof epoch_decision), ==, WYRELOG_E_OK);
  new_uuid_string (epoch_audit);
  wyl_service_credential_handoff_remediation_input_t epoch = input;
  epoch.remediation_request_id = epoch_remediation;
  epoch.decision_request_id = epoch_decision;
  epoch.audit_id = epoch_audit;
  memset (epoch.journal_snapshot_digest, 0xa5,
      sizeof epoch.journal_snapshot_digest);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &epoch, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  wyl_service_credential_handoff_remediation_result_clear (&result);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_remediation_actions;"),
      ==, 2);

  probe.calls = 0;
  probe.saw_write_lease = FALSE;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_remediation_result_clear (&result);

  probe.calls = 0;
  probe.rc = WYRELOG_E_POLICY;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_null (result.audit_id);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_remediation_actions;"),
      ==, 2);

  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, NULL, &result), ==, WYRELOG_E_INVALID);
  g_assert_null (result.audit_id);

  exec_ok (db_of (handle),
      "UPDATE audit_events SET action='corrupt-remediation-audit'"
      " WHERE action='service.credential.handoff.remediation.resume';");
  probe.rc = WYRELOG_E_OK;
  MutationEffects before_corrupt_replay = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_corrupt_replay);

  wyl_service_credential_handoff_result_clear (&issued);
  g_free (probe.actor_subject_id);
  g_free (issue_probe.actor_subject_id);
}

#ifdef WYL_TEST_HAS_HANDOFF_CANCELLATION
typedef struct
{
  gint64 now_us;
  guint calls;
} CancellationClock;

static gint64
cancellation_counting_now (gpointer data)
{
  CancellationClock *clock = data;
  clock->calls++;
  return clock->now_us;
}

static void
test_handoff_cancellation_claim_fresh_authorization_and_replay (void)
{
  gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar other_decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (original_request_id,
          sizeof original_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (cancellation_request_id,
          sizeof cancellation_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (decision_request_id,
          sizeof decision_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (other_decision_request_id,
          sizeof other_decision_request_id), ==, WYRELOG_E_OK);
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  new_uuid_string (disposition_id);
  new_uuid_string (audit_id);

  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  static const gchar subject_id[] = "svc:handoff:cancellation";
  prepare_authority (handle, subject_id);
  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe issue_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t issue_authorization = {
    .authorize = probe_mutation_authorization,.data = &issue_probe,
  };
  wyl_service_credential_issue_runtime_t issue_runtime = {
    .authorization = &issue_authorization,
    .credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0x73, sizeof target);
  gint64 deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR;
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = deadline_at_us,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          subject_id, "tenant-a", "admin", original_request_id,
          deadline_at_us + G_TIME_SPAN_HOUR, &handoff, &issue_runtime, &issued),
      ==, WYRELOG_E_OK);

  wyl_service_credential_handoff_cancellation_input_t input = {
    .cancellation_request_id = cancellation_request_id,
    .decision_request_id = decision_request_id,
    .current_actor_subject_id = "operator",
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_PREPARED,
    .tuple = {
          .original_request_id = original_request_id,
          .escrow_id = &escrow_id,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
    .target_a = subject_id,
    .target_b = "tenant-a",
    .deadline_at_us = deadline_at_us,
  };
  memcpy (input.target_digest, target, sizeof input.target_digest);
  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_POLICY };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  wyl_service_credential_handoff_cancellation_runtime_t runtime = {
    .authorization = &authorization,
  };
  wyl_service_credential_handoff_cancellation_result_t result = { 0 };
  MutationEffects before = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (probe.saw_write_lease);
  g_assert_null (result.disposition_id);
  assert_mutation_effects_equal (mutation_effects (handle), before);

  probe.calls = 0;
  probe.rc = WYRELOG_E_OK;
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_false (result.replayed);
  g_assert_cmpstr (result.disposition_id, ==, disposition_id);
  g_assert_cmpstr (result.audit_id, ==, audit_id);
  g_assert_cmpint (result.created_at_us, >, 0);
  g_assert_cmpint (result.created_at_us, <, deadline_at_us);
  g_assert_cmpint (result.outcome, ==,
      WYL_SERVICE_HANDOFF_CANCELLATION_COMMITTED_ATTENTION);
  g_assert_cmpstr (result.successor_credential_id, ==,
      issued.credential.credential_id);
  g_assert_cmpuint (result.successor_issuance_generation, ==,
      issued.credential.generation);
  g_assert_cmpint (sodium_memcmp (result.binding_digest,
          issued.handoff.binding_digest, sizeof result.binding_digest), ==, 0);
  MutationEffects after = mutation_effects (handle);
  g_assert_cmpint (after.credentials, ==, before.credentials);
  g_assert_cmpint (after.events, ==, before.events);
  g_assert_cmpint (after.escrows, ==, before.escrows);
  g_assert_cmpint (after.requests, ==, before.requests);
  g_assert_cmpint (after.handoff_cancellations, ==,
      before.handoff_cancellations + 1);
  g_assert_cmpint (after.handoff_dispositions, ==,
      before.handoff_dispositions + 1);
  g_assert_cmpint (after.audits, ==, before.audits + 1);
  g_assert_cmpint (after.audit_intentions, ==, before.audit_intentions + 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_cancellation_claims c"
          " JOIN service_credential_handoff_dispositions d"
          " ON d.disposition_id=c.disposition_id AND d.audit_id=c.audit_id"
          " JOIN audit_events e ON e.id=c.audit_id"
          " JOIN audit_intentions i ON i.audit_id=c.audit_id"
          " WHERE d.reason='operation_cancelled'"
          " AND d.outcome='attention_required'"
          " AND e.action='service.credential.handoff.cancel'"
          " AND i.action='service.credential.handoff.cancel'"
          " AND e.request_id=c.cancellation_request_id"
          " AND i.request_id=c.cancellation_request_id;"), ==, 1);
  wyl_service_credential_handoff_cancellation_result_clear (&result);

  /* The journal checkpoint changes only the observation.  Exact replay binds
   * the separately stored resolution tuple without changing the stable
   * request fingerprint. */
  input.observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED;
  input.tuple.successor_credential_id = issued.credential.credential_id;
  input.tuple.successor_issuance_generation = issued.credential.generation;
  memcpy (input.tuple.binding_digest, issued.handoff.binding_digest,
      sizeof input.tuple.binding_digest);

  probe.calls = 0;
  before = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (result.replayed);
  assert_mutation_effects_equal (mutation_effects (handle), before);
  wyl_service_credential_handoff_cancellation_result_clear (&result);
#ifdef WYL_TEST_HAS_HANDOFF_MAINTENANCE_CORE
  gint64 replay_after_deadline = deadline_at_us + 1;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      maintenance_fixed_now, &replay_after_deadline);
  probe.calls = 0;
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (result.replayed);
  assert_mutation_effects_equal (mutation_effects (handle), before);
  wyl_service_credential_handoff_cancellation_result_clear (&result);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      NULL, NULL);

  WylPolicyServiceHandoffMaintenanceProof precedence_proof = {
    .tuple = {
          .original_request_id = original_request_id,
          .escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
    .subject_id = subject_id,
    .tenant_id = "tenant-a",
    .deadline_at_us = deadline_at_us,
  };
  memcpy (precedence_proof.tuple.binding_digest,
      issued.handoff.binding_digest,
      sizeof precedence_proof.tuple.binding_digest);
  memcpy (precedence_proof.target_digest, target,
      sizeof precedence_proof.target_digest);
  WylPolicyServiceHandoffCommittedMaintenanceResult current_attention = {
    0
  };
  g_assert_cmpint (maintenance_current_attention_resolve (handle,
          &precedence_proof, &current_attention), ==, WYRELOG_E_OK);
  g_assert_cmpint (current_attention.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED);
  g_assert_cmpstr (current_attention.disposition.disposition_id, ==,
      disposition_id);
  g_assert_cmpstr (current_attention.disposition.audit_id, ==, audit_id);
  wyl_policy_service_handoff_committed_maintenance_result_clear
      (&current_attention);
  gchar resume_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar resume_decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar resume_audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (resume_request_id,
          sizeof resume_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (resume_decision_id,
          sizeof resume_decision_id), ==, WYRELOG_E_OK);
  new_uuid_string (resume_audit_id);
  wyl_service_credential_handoff_remediation_input_t resume_input = {
    .remediation_request_id = resume_request_id,
    .decision_request_id = resume_decision_id,
    .current_actor_subject_id = "operator",
    .audit_id = resume_audit_id,
    .tuple = {
          .original_request_id = original_request_id,
          .escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_RESUME,
    .source_kind = WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION,
    .observed_state =
        WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED,
    .source_disposition_id = disposition_id,
    .source_audit_id = audit_id,
    .source_reason = WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED,
  };
  memset (resume_input.journal_snapshot_digest, 0xb1,
      sizeof resume_input.journal_snapshot_digest);
  memcpy (resume_input.tuple.binding_digest, issued.handoff.binding_digest,
      sizeof resume_input.tuple.binding_digest);
  wyl_service_credential_handoff_remediation_runtime_t resume_runtime = {
    .authorization = &authorization,
  };
  wyl_service_credential_handoff_remediation_result_t resume_result = { 0 };
  probe.calls = 0;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &resume_input, &resume_runtime, &resume_result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_false (resume_result.replayed);
  wyl_service_credential_handoff_remediation_result_clear (&resume_result);
  g_assert_cmpint (maintenance_current_attention_resolve (handle,
          &precedence_proof, &current_attention), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (current_attention.disposition.disposition_id);
  g_assert_cmpint
      (wyl_service_credential_handoff_resolve_remediation_incident (handle,
          original_request_id, resume_input.journal_snapshot_digest,
          &resume_result), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_remediation_result_clear (&resume_result);
  WylPolicyServiceHandoffCommittedMaintenanceResult resumed_maintenance = {
    0
  };
  g_assert_cmpint (maintenance_committed_classify (handle, &precedence_proof,
          &resumed_maintenance, FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (resumed_maintenance.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ACTIVE);
  wyl_policy_service_handoff_committed_maintenance_result_clear
      (&resumed_maintenance);
  wyl_service_credential_t revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          issued.credential.credential_id, "operator-2",
          "cancellation-precedence-revoke", &revoked), ==, WYRELOG_E_OK);
  probe.calls = 0;
  before = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (result.replayed);
  assert_mutation_effects_equal (mutation_effects (handle), before);
  wyl_service_credential_handoff_cancellation_result_clear (&result);
  WylPolicyServiceHandoffMaintenanceProof prepared_recovery_proof =
      precedence_proof;
  prepared_recovery_proof.tuple.successor_credential_id = NULL;
  prepared_recovery_proof.tuple.successor_issuance_generation = 0;
  sodium_memzero (prepared_recovery_proof.tuple.binding_digest,
      sizeof prepared_recovery_proof.tuple.binding_digest);
  CancellationClock prepared_recovery_clock = {
    .now_us = deadline_at_us - 1,
  };
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      cancellation_counting_now, &prepared_recovery_clock);
  Txn prepared_recovery_transaction = { 0 };
  WylPolicyServiceHandoffPreparedMaintenanceResult prepared_recovery = { 0 };
  classifier_transaction_begin (handle, &prepared_recovery_transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (prepared_recovery_transaction.txn, store_of (handle),
          &prepared_recovery_proof, &prepared_recovery), ==, WYRELOG_E_OK);
  classifier_transaction_end (&prepared_recovery_transaction);
  g_assert_cmpuint (prepared_recovery_clock.calls, ==, 0);
  g_assert_cmpint (prepared_recovery.outcome, ==,
      WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_COMMITTED);
  g_assert_cmpstr (prepared_recovery.successor_credential_id, ==,
      issued.credential.credential_id);
  g_assert_cmpuint (prepared_recovery.successor_generation, ==,
      issued.credential.generation);
  g_assert_cmpint (sodium_memcmp (prepared_recovery.binding_digest,
          issued.handoff.binding_digest,
          sizeof prepared_recovery.binding_digest), ==, 0);
  wyl_policy_service_handoff_prepared_maintenance_result_clear
      (&prepared_recovery);
  gint64 precedence_now = deadline_at_us - 1;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      maintenance_fixed_now, &precedence_now);
  WylPolicyServiceHandoffCommittedMaintenanceResult precedence_result = {
    0
  };
  g_assert_cmpint (maintenance_committed_classify (handle, &precedence_proof,
          &precedence_result, FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (precedence_result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_REVOKED);
  wyl_policy_service_handoff_committed_maintenance_result_clear
      (&precedence_result);
  gchar formatted_escrow[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_format (&escrow_id, formatted_escrow,
          sizeof formatted_escrow), ==, WYRELOG_E_OK);
  g_autofree gchar *delete_escrow = g_strdup_printf
      ("DELETE FROM service_credential_handoff_escrows WHERE escrow_id='%s';",
      formatted_escrow);
  exec_ok (db_of (handle), delete_escrow);
  g_assert_cmpint (maintenance_committed_classify (handle, &precedence_proof,
          &precedence_result, FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (precedence_result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_MISSING);
  wyl_policy_service_handoff_committed_maintenance_result_clear
      (&precedence_result);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      NULL, NULL);
  wyl_service_credential_clear (&revoked);
#endif

  enum
  {
    TAMPER_CANCELLATION_REQUEST,
    TAMPER_DECISION_REQUEST,
    TAMPER_CURRENT_ACTOR,
    TAMPER_DISPOSITION,
    TAMPER_AUDIT,
    TAMPER_ORIGINAL_REQUEST,
    TAMPER_ORIGINAL_ACTOR,
    TAMPER_ESCROW,
    TAMPER_BINDING,
    TAMPER_SUCCESSOR,
    TAMPER_GENERATION,
    TAMPER_OPERATION,
    TAMPER_TARGET_A,
    TAMPER_TARGET_B,
    TAMPER_TARGET_DIGEST,
    TAMPER_DEADLINE,
  };
  static const struct
  {
    const gchar *name;
    guint kind;
  } tampers[] = {
    {"cancellation-request", TAMPER_CANCELLATION_REQUEST},
    {"decision-request", TAMPER_DECISION_REQUEST},
    {"current-actor", TAMPER_CURRENT_ACTOR},
    {"disposition", TAMPER_DISPOSITION},
    {"audit", TAMPER_AUDIT},
    {"original-request", TAMPER_ORIGINAL_REQUEST},
    {"original-actor", TAMPER_ORIGINAL_ACTOR},
    {"escrow", TAMPER_ESCROW},
    {"binding", TAMPER_BINDING},
    {"successor", TAMPER_SUCCESSOR},
    {"generation", TAMPER_GENERATION},
    {"operation", TAMPER_OPERATION},
    {"target-a", TAMPER_TARGET_A},
    {"target-b", TAMPER_TARGET_B},
    {"target-digest", TAMPER_TARGET_DIGEST},
    {"deadline", TAMPER_DEADLINE},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tampers); i++) {
    wyl_service_credential_handoff_cancellation_input_t mismatch = input;
    gchar other_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar other_uuid[WYL_ID_STRING_BUF];
    wyl_id_t other_escrow;
    if (tampers[i].kind == TAMPER_CANCELLATION_REQUEST
        || tampers[i].kind == TAMPER_ORIGINAL_REQUEST)
      g_assert_cmpint (wyl_request_id_new (other_request_id,
              sizeof other_request_id), ==, WYRELOG_E_OK);
    if (tampers[i].kind == TAMPER_DISPOSITION
        || tampers[i].kind == TAMPER_AUDIT)
      new_uuid_string (other_uuid);
    if (tampers[i].kind == TAMPER_CANCELLATION_REQUEST)
      mismatch.cancellation_request_id = other_request_id;
    else if (tampers[i].kind == TAMPER_DECISION_REQUEST)
      mismatch.decision_request_id = other_decision_request_id;
    else if (tampers[i].kind == TAMPER_CURRENT_ACTOR)
      mismatch.current_actor_subject_id = "operator-2";
    else if (tampers[i].kind == TAMPER_DISPOSITION)
      mismatch.disposition_id = other_uuid;
    else if (tampers[i].kind == TAMPER_AUDIT)
      mismatch.audit_id = other_uuid;
    else if (tampers[i].kind == TAMPER_ORIGINAL_REQUEST)
      mismatch.tuple.original_request_id = other_request_id;
    else if (tampers[i].kind == TAMPER_ORIGINAL_ACTOR)
      mismatch.tuple.original_actor_subject_id = "other-admin";
    else if (tampers[i].kind == TAMPER_ESCROW) {
      g_assert_cmpint (wyl_id_new (&other_escrow), ==, WYRELOG_E_OK);
      mismatch.tuple.escrow_id = &other_escrow;
    } else if (tampers[i].kind == TAMPER_BINDING) {
      mismatch.tuple.binding_digest[0] ^= 0xff;
    } else if (tampers[i].kind == TAMPER_SUCCESSOR) {
      mismatch.tuple.successor_credential_id = SECOND_ID;
    } else if (tampers[i].kind == TAMPER_GENERATION) {
      mismatch.tuple.successor_issuance_generation++;
    } else if (tampers[i].kind == TAMPER_OPERATION) {
      mismatch.operation = WYL_SERVICE_HANDOFF_FENCE_ROTATE;
      mismatch.target_a = issued.credential.credential_id;
      mismatch.target_b = NULL;
    } else if (tampers[i].kind == TAMPER_TARGET_A) {
      mismatch.target_a = "svc:handoff:cancellation-other";
    } else if (tampers[i].kind == TAMPER_TARGET_B) {
      mismatch.target_b = "tenant-b";
    } else if (tampers[i].kind == TAMPER_TARGET_DIGEST) {
      mismatch.target_digest[0] ^= 0xff;
    } else {
      mismatch.deadline_at_us++;
    }
    g_test_message ("cancellation replay tamper: %s", tampers[i].name);
    probe.calls = 0;
    before = mutation_effects (handle);
    g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
            &mismatch, &runtime, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpuint (probe.calls, ==, 1);
    g_assert_null (result.disposition_id);
    assert_mutation_effects_equal (mutation_effects (handle), before);
  }

  gchar second_cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar second_decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar second_disposition_id[WYL_ID_STRING_BUF];
  gchar second_audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (second_cancellation_request_id,
          sizeof second_cancellation_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (second_decision_request_id,
          sizeof second_decision_request_id), ==, WYRELOG_E_OK);
  new_uuid_string (second_disposition_id);
  new_uuid_string (second_audit_id);
  wyl_service_credential_handoff_cancellation_input_t second = input;
  second.cancellation_request_id = second_cancellation_request_id;
  second.decision_request_id = second_decision_request_id;
  second.disposition_id = second_disposition_id;
  second.audit_id = second_audit_id;
  probe.calls = 0;
  before = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &second, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_null (result.disposition_id);
  assert_mutation_effects_equal (mutation_effects (handle), before);

  wyl_service_credential_handoff_cancellation_input_t mismatch = input;
  mismatch.current_actor_subject_id = "admin";
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &mismatch, &runtime, &result), ==, WYRELOG_E_INVALID);
  g_assert_null (result.disposition_id);

  gchar fault_original_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (fault_original_request_id,
          sizeof fault_original_request_id), ==, WYRELOG_E_OK);
  wyl_id_t fault_escrow_id;
  g_assert_cmpint (wyl_id_new (&fault_escrow_id), ==, WYRELOG_E_OK);
  guint8 fault_target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (fault_target, 0x74, sizeof fault_target);
  gint64 fault_deadline_at_us = deadline_at_us + G_TIME_SPAN_MINUTE;
  wyl_service_credential_handoff_request_t fault_handoff = {
    .escrow_id = &fault_escrow_id,.target_digest = fault_target,
    .deadline_at_us = fault_deadline_at_us,
  };
  wyl_service_credential_handoff_result_t fault_issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          subject_id, "tenant-a", "admin", fault_original_request_id,
          fault_deadline_at_us + G_TIME_SPAN_HOUR, &fault_handoff,
          &issue_runtime, &fault_issued), ==, WYRELOG_E_OK);
  static const WylPolicyServiceHandoffFailStage fault_stages[] = {
    WYL_POLICY_HANDOFF_FAIL_AFTER_REQUEST_CLAIM,
    WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT,
    WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (fault_stages); i++) {
    gchar fault_cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar fault_decision_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar fault_disposition_id[WYL_ID_STRING_BUF];
    gchar fault_audit_id[WYL_ID_STRING_BUF];
    g_assert_cmpint (wyl_request_id_new (fault_cancellation_request_id,
            sizeof fault_cancellation_request_id), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_request_id_new (fault_decision_request_id,
            sizeof fault_decision_request_id), ==, WYRELOG_E_OK);
    new_uuid_string (fault_disposition_id);
    new_uuid_string (fault_audit_id);
    wyl_service_credential_handoff_cancellation_input_t fault_input = {
      .cancellation_request_id = fault_cancellation_request_id,
      .decision_request_id = fault_decision_request_id,
      .current_actor_subject_id = "operator",
      .disposition_id = fault_disposition_id,
      .audit_id = fault_audit_id,
      .observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED,
      .tuple = {
            .original_request_id = fault_original_request_id,
            .escrow_id = &fault_escrow_id,
            .successor_credential_id = fault_issued.credential.credential_id,
            .successor_issuance_generation = fault_issued.credential.generation,
            .original_actor_subject_id = "admin",
          },
      .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
      .target_a = subject_id,
      .target_b = "tenant-a",
      .deadline_at_us = fault_deadline_at_us,
    };
    memcpy (fault_input.tuple.binding_digest,
        fault_issued.handoff.binding_digest,
        sizeof fault_input.tuple.binding_digest);
    memcpy (fault_input.target_digest, fault_target,
        sizeof fault_input.target_digest);
    before = mutation_effects (handle);
    probe.calls = 0;
    wyl_policy_store_service_handoff_fail_once (store_of (handle),
        fault_stages[i]);
    g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
            &fault_input, &runtime, &result), ==, WYRELOG_E_IO);
    g_assert_cmpuint (probe.calls, ==, 1);
    g_assert_null (result.disposition_id);
    assert_mutation_effects_equal (mutation_effects (handle), before);
  }
#ifdef WYL_TEST_HAS_HANDOFF_MAINTENANCE_CORE
  static const gint64 deadline_offsets[] = { 0, 1 };
  for (gsize i = 0; i < G_N_ELEMENTS (deadline_offsets); i++) {
    gchar boundary_cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar boundary_decision_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar boundary_disposition_id[WYL_ID_STRING_BUF];
    gchar boundary_audit_id[WYL_ID_STRING_BUF];
    g_assert_cmpint (wyl_request_id_new (boundary_cancellation_request_id,
            sizeof boundary_cancellation_request_id), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_request_id_new (boundary_decision_request_id,
            sizeof boundary_decision_request_id), ==, WYRELOG_E_OK);
    new_uuid_string (boundary_disposition_id);
    new_uuid_string (boundary_audit_id);
    wyl_service_credential_handoff_cancellation_input_t boundary_input = {
      .cancellation_request_id = boundary_cancellation_request_id,
      .decision_request_id = boundary_decision_request_id,
      .current_actor_subject_id = "operator",
      .disposition_id = boundary_disposition_id,
      .audit_id = boundary_audit_id,
      .observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED,
      .tuple = {
            .original_request_id = fault_original_request_id,
            .escrow_id = &fault_escrow_id,
            .successor_credential_id = fault_issued.credential.credential_id,
            .successor_issuance_generation = fault_issued.credential.generation,
            .original_actor_subject_id = "admin",
          },
      .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
      .target_a = subject_id,
      .target_b = "tenant-a",
      .deadline_at_us = fault_deadline_at_us,
    };
    memcpy (boundary_input.tuple.binding_digest,
        fault_issued.handoff.binding_digest,
        sizeof boundary_input.tuple.binding_digest);
    memcpy (boundary_input.target_digest, fault_target,
        sizeof boundary_input.target_digest);
    gint64 boundary_now = fault_deadline_at_us + deadline_offsets[i];
    wyl_policy_store_handoff_maintenance_set_clock_for_test
        (store_of (handle), maintenance_fixed_now, &boundary_now);
    before = mutation_effects (handle);
    probe.calls = 0;
    g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
            &boundary_input, &runtime, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpuint (probe.calls, ==, 1);
    g_assert_null (result.disposition_id);
    assert_mutation_effects_equal (mutation_effects (handle), before);
  }
  gchar winning_cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar winning_decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar winning_disposition_id[WYL_ID_STRING_BUF];
  gchar winning_audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (winning_cancellation_request_id,
          sizeof winning_cancellation_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (winning_decision_request_id,
          sizeof winning_decision_request_id), ==, WYRELOG_E_OK);
  new_uuid_string (winning_disposition_id);
  new_uuid_string (winning_audit_id);
  wyl_service_credential_handoff_cancellation_input_t winning_input = {
    .cancellation_request_id = winning_cancellation_request_id,
    .decision_request_id = winning_decision_request_id,
    .current_actor_subject_id = "operator",
    .disposition_id = winning_disposition_id,
    .audit_id = winning_audit_id,
    .observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED,
    .tuple = {
          .original_request_id = fault_original_request_id,
          .escrow_id = &fault_escrow_id,
          .successor_credential_id = fault_issued.credential.credential_id,
          .successor_issuance_generation = fault_issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
    .target_a = subject_id,
    .target_b = "tenant-a",
    .deadline_at_us = fault_deadline_at_us,
  };
  memcpy (winning_input.tuple.binding_digest,
      fault_issued.handoff.binding_digest,
      sizeof winning_input.tuple.binding_digest);
  memcpy (winning_input.target_digest, fault_target,
      sizeof winning_input.target_digest);
  gint64 winning_now = fault_deadline_at_us - 1;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      maintenance_fixed_now, &winning_now);
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &winning_input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  wyl_service_credential_handoff_cancellation_result_clear (&result);
  WylPolicyServiceHandoffMaintenanceProof winning_proof = {
    .tuple = {
          .original_request_id = fault_original_request_id,
          .escrow_id = &fault_escrow_id,
          .successor_credential_id = fault_issued.credential.credential_id,
          .successor_issuance_generation = fault_issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
    .subject_id = subject_id,
    .tenant_id = "tenant-a",
    .deadline_at_us = fault_deadline_at_us,
  };
  memcpy (winning_proof.tuple.binding_digest,
      fault_issued.handoff.binding_digest,
      sizeof winning_proof.tuple.binding_digest);
  memcpy (winning_proof.target_digest, fault_target,
      sizeof winning_proof.target_digest);
  winning_now = fault_deadline_at_us;
  WylPolicyServiceHandoffCommittedMaintenanceResult winning_result = { 0 };
  g_assert_cmpint (maintenance_committed_classify (handle, &winning_proof,
          &winning_result, FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (winning_result.outcome, ==,
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED);
  wyl_policy_service_handoff_committed_maintenance_result_clear
      (&winning_result);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      NULL, NULL);
#endif

  wyl_service_credential_handoff_result_clear (&fault_issued);
  wyl_service_credential_handoff_result_clear (&issued);
  g_free (probe.actor_subject_id);
  g_free (issue_probe.actor_subject_id);
}

static void
test_handoff_cancellation_prepared_terminal_boundary_rollback (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  const gchar *subject_id = "svc:handoff:cancel-prepared-terminal";
  prepare_authority (handle, subject_id);
  wyl_policy_store_t *store = store_of (handle);

  gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  wyl_id_t escrow_id;
  g_assert_cmpint (wyl_request_id_new (original_request_id,
          sizeof original_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (cancellation_request_id,
          sizeof cancellation_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (decision_request_id,
          sizeof decision_request_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  new_uuid_string (disposition_id);
  new_uuid_string (audit_id);
  CancellationClock clock = {
    .now_us = g_get_real_time () + G_TIME_SPAN_MINUTE,
  };
  gint64 deadline_at_us = clock.now_us + G_TIME_SPAN_HOUR;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store,
      cancellation_counting_now, &clock);

  wyl_service_credential_handoff_cancellation_input_t input = {
    .cancellation_request_id = cancellation_request_id,
    .decision_request_id = decision_request_id,
    .current_actor_subject_id = "operator",
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_PREPARED,
    .tuple = {
          .original_request_id = original_request_id,
          .escrow_id = &escrow_id,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
    .target_a = subject_id,
    .target_b = "tenant-a",
    .deadline_at_us = deadline_at_us,
  };
  memset (input.target_digest, 0x81, sizeof input.target_digest);
  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  wyl_service_credential_handoff_cancellation_runtime_t runtime = {
    .authorization = &authorization,
  };
  wyl_service_credential_handoff_cancellation_result_t result = { 0 };
  MutationEffects before = mutation_effects (handle);
  gint64 fences_before = scalar (db_of (handle),
      "SELECT count(*) FROM service_credential_operation_fences;");
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (clock.calls, ==, 1);
  g_assert_false (result.replayed);
  g_assert_cmpint (result.outcome, ==,
      WYL_SERVICE_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED);
  g_assert_cmpstr (result.successor_credential_id, ==, "");
  g_assert_cmpuint (result.successor_issuance_generation, ==, 0);
  g_assert_true (sodium_is_zero (result.binding_digest,
          sizeof result.binding_digest));
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_operation_fences"
          " WHERE terminal_state='not_committed';"), ==, fences_before + 1);
  MutationEffects claimed = mutation_effects (handle);
  g_assert_cmpint (claimed.handoff_cancellations, ==,
      before.handoff_cancellations + 1);
  g_assert_cmpint (claimed.handoff_dispositions, ==,
      before.handoff_dispositions + 1);
  wyl_service_credential_handoff_cancellation_result_clear (&result);

  WylPolicyServiceHandoffMaintenanceProof recovery_proof = {
    .tuple = {
          .original_request_id = original_request_id,
          .escrow_id = &escrow_id,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
    .subject_id = subject_id,
    .tenant_id = "tenant-a",
    .deadline_at_us = deadline_at_us,
  };
  memcpy (recovery_proof.target_digest, input.target_digest,
      sizeof recovery_proof.target_digest);
  WylPolicyServiceHandoffPreparedMaintenanceResult recovery = { 0 };
  Txn recovery_transaction = { 0 };
  clock.calls = 0;
  classifier_transaction_begin (handle, &recovery_transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (recovery_transaction.txn, store, &recovery_proof, &recovery), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (clock.calls, ==, 0);
  g_assert_cmpint (recovery.outcome, ==,
      WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED);
  g_assert_true (recovery.disposition.replayed);
  g_assert_cmpstr (recovery.disposition.disposition_id, ==, disposition_id);
  classifier_transaction_end (&recovery_transaction);
  wyl_policy_service_handoff_prepared_maintenance_result_clear (&recovery);

  input.observation =
      WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_TERMINAL_NOT_COMMITTED;
  clock.now_us = deadline_at_us + 1;
  clock.calls = 0;
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (clock.calls, ==, 0);
  g_assert_true (result.replayed);
  g_assert_cmpint (result.outcome, ==,
      WYL_SERVICE_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED);
  assert_mutation_effects_equal (mutation_effects (handle), claimed);
  wyl_service_credential_handoff_cancellation_result_clear (&result);

  gchar boundary_original[WYL_REQUEST_ID_STRING_BUF];
  gchar boundary_cancel[WYL_REQUEST_ID_STRING_BUF];
  gchar boundary_decision[WYL_REQUEST_ID_STRING_BUF];
  gchar boundary_disposition[WYL_ID_STRING_BUF];
  gchar boundary_audit[WYL_ID_STRING_BUF];
  wyl_id_t boundary_escrow;
  g_assert_cmpint (wyl_request_id_new (boundary_original,
          sizeof boundary_original), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (boundary_cancel,
          sizeof boundary_cancel), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (boundary_decision,
          sizeof boundary_decision), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&boundary_escrow), ==, WYRELOG_E_OK);
  new_uuid_string (boundary_disposition);
  new_uuid_string (boundary_audit);
  wyl_service_credential_handoff_cancellation_input_t boundary = input;
  boundary.cancellation_request_id = boundary_cancel;
  boundary.decision_request_id = boundary_decision;
  boundary.disposition_id = boundary_disposition;
  boundary.audit_id = boundary_audit;
  boundary.observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_PREPARED;
  boundary.tuple.original_request_id = boundary_original;
  boundary.tuple.escrow_id = &boundary_escrow;
  boundary.deadline_at_us = deadline_at_us + G_TIME_SPAN_HOUR;
  memset (boundary.target_digest, 0x82, sizeof boundary.target_digest);
  clock.now_us = boundary.deadline_at_us;
  clock.calls = 0;
  gint64 fences_at_boundary = scalar (db_of (handle),
      "SELECT count(*) FROM service_credential_operation_fences;");
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &boundary, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (clock.calls, ==, 1);
  g_assert_null (result.disposition_id);
  assert_mutation_effects_equal (mutation_effects (handle), claimed);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_operation_fences;"), ==,
      fences_at_boundary);

  gchar rollback_original[WYL_REQUEST_ID_STRING_BUF];
  gchar rollback_cancel[WYL_REQUEST_ID_STRING_BUF];
  gchar rollback_decision[WYL_REQUEST_ID_STRING_BUF];
  gchar rollback_disposition[WYL_ID_STRING_BUF];
  gchar rollback_audit[WYL_ID_STRING_BUF];
  wyl_id_t rollback_escrow;
  g_assert_cmpint (wyl_request_id_new (rollback_original,
          sizeof rollback_original), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (rollback_cancel,
          sizeof rollback_cancel), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (rollback_decision,
          sizeof rollback_decision), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&rollback_escrow), ==, WYRELOG_E_OK);
  new_uuid_string (rollback_disposition);
  new_uuid_string (rollback_audit);
  wyl_service_credential_handoff_cancellation_input_t rollback = boundary;
  rollback.cancellation_request_id = rollback_cancel;
  rollback.decision_request_id = rollback_decision;
  rollback.disposition_id = rollback_disposition;
  rollback.audit_id = rollback_audit;
  rollback.tuple.original_request_id = rollback_original;
  rollback.tuple.escrow_id = &rollback_escrow;
  memset (rollback.target_digest, 0x83, sizeof rollback.target_digest);
  clock.now_us = rollback.deadline_at_us - 1;
  clock.calls = 0;
  wyl_policy_store_service_handoff_fail_once (store,
      WYL_POLICY_HANDOFF_FAIL_AFTER_REQUEST_CLAIM);
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &rollback, &runtime, &result), ==, WYRELOG_E_IO);
  g_assert_cmpuint (clock.calls, ==, 1);
  g_assert_null (result.disposition_id);
  assert_mutation_effects_equal (mutation_effects (handle), claimed);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_operation_fences;"), ==,
      fences_at_boundary);

  gchar extra_disposition[WYL_ID_STRING_BUF];
  gchar extra_audit[WYL_ID_STRING_BUF];
  gchar formatted_escrow[WYL_ID_STRING_BUF];
  new_uuid_string (extra_disposition);
  new_uuid_string (extra_audit);
  g_assert_cmpint (wyl_id_format (&escrow_id, formatted_escrow,
          sizeof formatted_escrow), ==, WYRELOG_E_OK);
  g_autofree gchar *insert_extra = g_strdup_printf
      ("INSERT INTO service_credential_handoff_dispositions"
      " (disposition_id,semantic_key,original_request_id,escrow_id,"
      " binding_digest,successor_credential_id,"
      " successor_issuance_generation,actor_subject_id,reason,outcome,"
      " audit_id,created_at_us) VALUES"
      " ('%s',randomblob(32),'%s','%s',"
      " x'0101010101010101010101010101010101010101010101010101010101010101',"
      " 'wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv',1,'operator',"
      " 'successor_revoked','operator_action_required','%s',1);",
      extra_disposition, original_request_id, formatted_escrow, extra_audit);
  exec_ok (db_of (handle), insert_extra);
  MutationEffects with_extra = mutation_effects (handle);
  clock.calls = 0;
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (clock.calls, ==, 0);
  g_assert_null (result.disposition_id);
  assert_mutation_effects_equal (mutation_effects (handle), with_extra);

  gchar orphan_original[WYL_REQUEST_ID_STRING_BUF];
  gchar orphan_cancel[WYL_REQUEST_ID_STRING_BUF];
  gchar orphan_decision[WYL_REQUEST_ID_STRING_BUF];
  gchar orphan_disposition[WYL_ID_STRING_BUF];
  gchar orphan_audit[WYL_ID_STRING_BUF];
  wyl_id_t orphan_escrow;
  g_assert_cmpint (wyl_request_id_new (orphan_original,
          sizeof orphan_original), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (orphan_cancel, sizeof orphan_cancel),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (orphan_decision,
          sizeof orphan_decision), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&orphan_escrow), ==, WYRELOG_E_OK);
  WylPolicyServiceHandoffExactTuple orphan_artifact = {
    .original_request_id = orphan_original,
    .escrow_id = &orphan_escrow,
    .successor_credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
    .successor_issuance_generation = 1,
    .original_actor_subject_id = "admin",
  };
  memset (orphan_artifact.binding_digest, 0x91,
      sizeof orphan_artifact.binding_digest);
  maintenance_insert_cancelled_attention (handle, &orphan_artifact,
      clock.now_us, orphan_disposition, orphan_audit);
  MutationEffects with_orphan = mutation_effects (handle);
  gint64 orphan_fences = scalar (db_of (handle),
      "SELECT count(*) FROM service_credential_operation_fences;");

  new_uuid_string (orphan_disposition);
  new_uuid_string (orphan_audit);
  wyl_service_credential_handoff_cancellation_input_t orphan_input = {
    .cancellation_request_id = orphan_cancel,
    .decision_request_id = orphan_decision,
    .current_actor_subject_id = "operator",
    .disposition_id = orphan_disposition,
    .audit_id = orphan_audit,
    .observation = WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_PREPARED,
    .tuple = {
          .original_request_id = orphan_original,
          .escrow_id = &orphan_escrow,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
    .target_a = subject_id,
    .target_b = "tenant-a",
    .deadline_at_us = clock.now_us + G_TIME_SPAN_HOUR,
  };
  memset (orphan_input.target_digest, 0x92, sizeof orphan_input.target_digest);
  clock.calls = 0;
  g_assert_cmpint (wyl_service_credential_handoff_claim_cancellation (handle,
          &orphan_input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (clock.calls, ==, 1);
  g_assert_null (result.disposition_id);
  assert_mutation_effects_equal (mutation_effects (handle), with_orphan);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_operation_fences;"), ==,
      orphan_fences);

  WylPolicyServiceHandoffMaintenanceProof orphan_proof = {
    .tuple = {
          .original_request_id = orphan_original,
          .escrow_id = &orphan_escrow,
          .original_actor_subject_id = "admin",
        },
    .operation = WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
    .subject_id = subject_id,
    .tenant_id = "tenant-a",
    .deadline_at_us = orphan_input.deadline_at_us,
  };
  memcpy (orphan_proof.target_digest, orphan_input.target_digest,
      sizeof orphan_proof.target_digest);
  Txn orphan_transaction = { 0 };
  WylPolicyServiceHandoffPreparedMaintenanceResult orphan_result = { 0 };
  clock.calls = 0;
  classifier_transaction_begin (handle, &orphan_transaction);
  g_assert_cmpint (wyl_policy_store_handoff_maintain_prepared_core
      (orphan_transaction.txn, store, &orphan_proof, &orphan_result), ==,
      WYRELOG_E_POLICY);
  classifier_transaction_end (&orphan_transaction);
  g_assert_cmpuint (clock.calls, ==, 0);
  assert_mutation_effects_equal (mutation_effects (handle), with_orphan);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_operation_fences;"), ==,
      orphan_fences);
  wyl_policy_service_handoff_prepared_maintenance_result_clear (&orphan_result);

  wyl_policy_store_handoff_maintenance_set_clock_for_test (store, NULL, NULL);
  g_free (probe.actor_subject_id);
}
#endif

static void
test_handoff_not_committed_requires_exact_fence (void)
{
  g_assert_cmpint (wyl_policy_store_service_handoff_sqlite_error_for_test
      (SQLITE_NOMEM), ==, WYRELOG_E_NOMEM);
  g_assert_cmpint (wyl_policy_store_service_handoff_sqlite_error_for_test
      (SQLITE_CONSTRAINT_UNIQUE), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_service_handoff_sqlite_error_for_test
      (SQLITE_IOERR), ==, WYRELOG_E_IO);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request_id, sizeof request_id), ==,
      WYRELOG_E_OK);
  wyl_id_t disposition_uuid;
  wyl_id_t audit_uuid;
  wyl_id_t absent_escrow_id;
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&disposition_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&audit_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&absent_escrow_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&disposition_uuid, disposition_id,
          sizeof disposition_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&audit_uuid, audit_id, sizeof audit_id), ==,
      WYRELOG_E_OK);

  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:not-committed");

  Txn t = { 0 };
  wyl_policy_store_t *store = store_of (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &t.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, t.lease, &t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (t.txn, store, &t.evidence), ==, WYRELOG_E_OK);
  WylServiceCredentialFenceResult fence = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, request_id,
          "svc:handoff:not-committed", "tenant-a", NULL, &fence), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (fence.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (t.txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (t.txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t.evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t.lease);

  wyl_service_credential_handoff_no_commit_evidence_t evidence = {
    .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
    .target_a = "svc:handoff:not-committed",
    .target_b = "tenant-a",
  };
  wyl_service_credential_handoff_disposition_input_t input = {
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .tuple = {
          .original_request_id = request_id,
          .escrow_id = &absent_escrow_id,
          .original_actor_subject_id = "admin",
        },
    .actor_subject_id = "admin",
    .reason = WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED,
    .outcome = WYL_SERVICE_HANDOFF_OUTCOME_ATTENTION_REQUIRED,
    .no_commit_evidence = &evidence,
  };
  wyl_service_credential_handoff_disposition_result_t result = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &input,
          &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_dispositions d"
          " JOIN audit_events e ON e.id=d.audit_id"
          " JOIN audit_intentions i ON i.audit_id=d.audit_id"
          " WHERE d.reason='not_committed'"
          " AND d.created_at_us=e.created_at_us"
          " AND d.created_at_us=i.created_at_us;"), ==, 1);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &input,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);

  MutationEffects before_nomem = mutation_effects (handle);
  wyl_policy_store_service_handoff_fail_once (store_of (handle),
      WYL_POLICY_HANDOFF_FAIL_SQLITE_NOMEM);
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &input,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  assert_mutation_effects_equal (mutation_effects (handle), before_nomem);
  wyl_policy_store_service_handoff_fail_once (store_of (handle),
      WYL_POLICY_HANDOFF_FAIL_NONE);

  evidence.target_a = "svc:handoff:other";
  assert_not_committed_replay_fails_no_mutation (handle, &input);
  evidence.target_a = "svc:handoff:not-committed";
  evidence.target_b = "tenant-b";
  assert_not_committed_replay_fails_no_mutation (handle, &input);
  evidence.operation = WYL_SERVICE_HANDOFF_FENCE_ROTATE;
  evidence.target_a = COLLISION_ID;
  evidence.target_b = NULL;
  assert_not_committed_replay_fails_no_mutation (handle, &input);
  evidence.operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE;
  evidence.target_a = "svc:handoff:not-committed";
  evidence.target_b = "tenant-a";
  g_autofree gchar *backup_no_commit_audit = g_strdup_printf
      ("CREATE TEMP TABLE no_commit_event_backup AS"
      " SELECT * FROM audit_events WHERE id='%s';"
      "UPDATE audit_events SET action='corrupt-no-commit-audit'"
      " WHERE id='%s';", audit_id, audit_id);
  exec_ok (db_of (handle), backup_no_commit_audit);
  assert_not_committed_replay_fails_no_mutation (handle, &input);
  g_autofree gchar *restore_no_commit_audit = g_strdup_printf
      ("DELETE FROM audit_events WHERE id='%s';"
      "INSERT INTO audit_events SELECT * FROM no_commit_event_backup;"
      "DROP TABLE no_commit_event_backup;", audit_id);
  exec_ok (db_of (handle), restore_no_commit_audit);
  input.no_commit_evidence = NULL;
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &input,
          &result), ==, WYRELOG_E_INVALID);
  input.no_commit_evidence = &evidence;
  evidence.target_a = "malformed";
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &input,
          &result), ==, WYRELOG_E_INVALID);
  evidence.target_a = "svc:handoff:not-committed";

  gchar missing_request[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t missing_disposition_uuid;
  wyl_id_t missing_audit_uuid;
  gchar missing_disposition[WYL_ID_STRING_BUF];
  gchar missing_audit[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (missing_request,
          sizeof missing_request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&missing_disposition_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_new (&missing_audit_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&missing_disposition_uuid,
          missing_disposition, sizeof missing_disposition), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&missing_audit_uuid, missing_audit,
          sizeof missing_audit), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_disposition_input_t missing = input;
  missing.disposition_id = missing_disposition;
  missing.audit_id = missing_audit;
  missing.tuple.original_request_id = missing_request;
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &missing,
          &result), ==, WYRELOG_E_POLICY);

  gchar committed_request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (committed_request,
          sizeof committed_request), ==, WYRELOG_E_OK);
  wyl_service_credential_issue_result_t committed = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:handoff:not-committed", "tenant-a", "admin",
          committed_request, 0, &committed), ==, WYRELOG_E_OK);
  missing.tuple.original_request_id = committed_request;
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &missing,
          &result), ==, WYRELOG_E_POLICY);

  wyl_id_t other_escrow_uuid;
  gchar other_escrow[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&other_escrow_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&other_escrow_uuid, other_escrow,
          sizeof other_escrow), ==, WYRELOG_E_OK);
  g_autofree gchar *insert_request_conflict =
      g_strdup_printf ("INSERT INTO service_credential_handoff_escrows VALUES"
      "('%s','issue','%s','admin',zeroblob(32),'%s',1,%" G_GINT64_FORMAT
      ",zeroblob(32),x'01',%" G_GINT64_FORMAT ");", other_escrow,
      request_id, committed.credential.credential_id,
      g_get_real_time () + G_TIME_SPAN_HOUR, g_get_real_time ());
  exec_ok (db_of (handle), insert_request_conflict);
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &input,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  exec_ok (db_of (handle), "DELETE FROM service_credential_handoff_escrows;");
  gchar absent_escrow[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_format (&absent_escrow_id, absent_escrow,
          sizeof absent_escrow), ==, WYRELOG_E_OK);
  g_autofree gchar *insert_id_conflict =
      g_strdup_printf ("INSERT INTO service_credential_handoff_escrows VALUES"
      "('%s','issue','other-request','admin',zeroblob(32),'%s',1,%"
      G_GINT64_FORMAT ",zeroblob(32),x'01',%" G_GINT64_FORMAT ");",
      absent_escrow, committed.credential.credential_id,
      g_get_real_time () + G_TIME_SPAN_HOUR, g_get_real_time ());
  exec_ok (db_of (handle), insert_id_conflict);
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle, &input,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  exec_ok (db_of (handle), "DELETE FROM service_credential_handoff_escrows;");

  gchar rotate_request[WYL_REQUEST_ID_STRING_BUF];
  gchar rotate_disposition[WYL_ID_STRING_BUF];
  gchar rotate_audit[WYL_ID_STRING_BUF];
  wyl_id_t rotate_escrow;
  g_assert_cmpint (wyl_request_id_new (rotate_request,
          sizeof rotate_request), ==, WYRELOG_E_OK);
  new_uuid_string (rotate_disposition);
  new_uuid_string (rotate_audit);
  g_assert_cmpint (wyl_id_new (&rotate_escrow), ==, WYRELOG_E_OK);
  create_terminal_fence_for_test (handle,
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, rotate_request, COLLISION_ID,
      NULL);
  wyl_service_credential_handoff_no_commit_evidence_t rotate_evidence = {
    .operation = WYL_SERVICE_HANDOFF_FENCE_ROTATE,
    .target_a = COLLISION_ID,
  };
  wyl_service_credential_handoff_disposition_input_t rotate_input = input;
  rotate_input.disposition_id = rotate_disposition;
  rotate_input.audit_id = rotate_audit;
  rotate_input.tuple.original_request_id = rotate_request;
  rotate_input.tuple.escrow_id = &rotate_escrow;
  rotate_input.no_commit_evidence = &rotate_evidence;
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle,
          &rotate_input, &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  MutationEffects before_rotate_replay = mutation_effects (handle);
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle,
          &rotate_input, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_rotate_replay);

  gchar framed_request[WYL_REQUEST_ID_STRING_BUF];
  gchar framed_disposition[WYL_ID_STRING_BUF];
  gchar framed_audit[WYL_ID_STRING_BUF];
  wyl_id_t framed_escrow;
  g_assert_cmpint (wyl_request_id_new (framed_request,
          sizeof framed_request), ==, WYRELOG_E_OK);
  new_uuid_string (framed_disposition);
  new_uuid_string (framed_audit);
  g_assert_cmpint (wyl_id_new (&framed_escrow), ==, WYRELOG_E_OK);
  create_terminal_fence_for_test (handle,
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, framed_request,
      "svc:jobs:worker", "tenant-a");
  wyl_service_credential_handoff_no_commit_evidence_t framed_evidence = {
    .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
    .target_a = "svc:jobs:worker",
    .target_b = "tenant-a",
  };
  wyl_service_credential_handoff_disposition_input_t framed_input = input;
  framed_input.disposition_id = framed_disposition;
  framed_input.audit_id = framed_audit;
  framed_input.tuple.original_request_id = framed_request;
  framed_input.tuple.escrow_id = &framed_escrow;
  framed_input.no_commit_evidence = &framed_evidence;
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle,
          &framed_input, &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  framed_evidence.target_a = "svc:jobs:worke";
  framed_evidence.target_b = "rtenant-a";
  assert_not_committed_replay_fails_no_mutation (handle, &framed_input);
  framed_evidence.target_a = "svc:jobs:worker";
  framed_evidence.target_b = "tenant-a";
  MutationEffects before_framed_replay = mutation_effects (handle);
  g_assert_cmpint
      (wyl_service_credential_handoff_record_not_committed (handle,
          &framed_input, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_framed_replay);
  wyl_service_credential_issue_result_clear (&committed);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_dispositions"
          " WHERE reason='not_committed';"), ==, 3);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM (SELECT original_request_id FROM"
          " service_credential_handoff_dispositions"
          " WHERE reason='not_committed' GROUP BY original_request_id"
          " HAVING count(*)=1);"), ==, 3);
}

static void
test_handoff_disposition_attention_and_oar (void)
{
  gchar original_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (original_id, sizeof original_id), ==,
      WYRELOG_E_OK);
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:disposition");
  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe issue_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &issue_probe,
  };
  wyl_service_credential_issue_runtime_t runtime = {
    .authorization = &authorization,.credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0x53, sizeof target);
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  gint64 deadline = g_get_real_time () + 100 * 1000;
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = deadline,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:disposition", "tenant-a", "admin", original_id,
          deadline + 20 * 1000, &handoff, &runtime, &issued), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_disposition_input_t input = {
    .tuple = {
          .original_request_id = original_id,
          .escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .actor_subject_id = "operator",
    .reason = WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED,
    .outcome = WYL_SERVICE_HANDOFF_OUTCOME_ATTENTION_REQUIRED,
  };
  memcpy (input.tuple.binding_digest, issued.handoff.binding_digest,
      sizeof input.tuple.binding_digest);
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  new_uuid_string (disposition_id);
  new_uuid_string (audit_id);
  input.disposition_id = disposition_id;
  input.audit_id = audit_id;
  input.reason = WYL_SERVICE_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED;
  input.outcome = WYL_SERVICE_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED;
  MutationEffects before_active_expiry = mutation_effects (handle);
  wyl_service_credential_handoff_disposition_result_t result = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_active_expiry);
  wyl_service_credential_handoff_no_commit_evidence_t disallowed_evidence = {
    .operation = WYL_SERVICE_HANDOFF_FENCE_ISSUE,
    .target_a = "svc:handoff:disposition",
    .target_b = "tenant-a",
  };
  input.no_commit_evidence = &disallowed_evidence;
  MutationEffects before_disallowed_evidence = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_INVALID);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_disallowed_evidence);
  input.no_commit_evidence = NULL;

  input.reason = WYL_SERVICE_HANDOFF_DISPOSITION_DELIVERED;
  input.outcome = WYL_SERVICE_HANDOFF_OUTCOME_ESCROW_DELETED;
  MutationEffects before_delivered = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_INVALID);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle), before_delivered);

  input.reason = WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED;
  input.outcome = WYL_SERVICE_HANDOFF_OUTCOME_ATTENTION_REQUIRED;
  MutationEffects before_operation_expiry = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_operation_expiry);
  g_usleep (150 * 1000);
  MutationEffects before_disposition = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_OK);
  assert_disposition_only_delta (mutation_effects (handle), before_disposition);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_dispositions d"
          " JOIN audit_events e ON e.id=d.audit_id"
          " JOIN audit_intentions i ON i.audit_id=d.audit_id"
          " WHERE d.disposition_id=(SELECT disposition_id FROM"
          " service_credential_handoff_dispositions"
          " WHERE reason='operation_expired')"
          " AND d.created_at_us=e.created_at_us"
          " AND d.created_at_us=i.created_at_us;"), ==, 1);

  MutationEffects before_t2_replay = mutation_effects (handle);
  g_usleep (10 * 1000);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  assert_mutation_effects_equal (mutation_effects (handle), before_t2_replay);

  g_autofree gchar *mark_intention_committed = g_strdup_printf
      ("UPDATE audit_intentions SET state='committed' WHERE audit_id='%s';",
      audit_id);
  exec_ok (db_of (handle), mark_intention_committed);
  MutationEffects before_state_replay = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_state_replay);

  exec_ok (db_of (handle),
      "INSERT INTO audit_events"
      " (id,created_at_us,subject_id,action,resource_id,deny_reason,"
      " deny_origin,request_id,decision) VALUES"
      " ('00000000-0000-7000-8000-000000000099',1,'unrelated-actor',"
      " 'corrupt-unrelated-event','unrelated-resource',NULL,NULL,"
      " 'unrelated-request',1);"
      "INSERT INTO audit_intentions"
      " (audit_id,created_at_us,subject_id,action,resource_id,deny_reason,"
      " deny_origin,request_id,decision,state,created_at,updated_at) VALUES"
      " ('00000000-0000-7000-8000-000000000099',2,'other-actor',"
      " 'corrupt-unrelated-intention','other-resource',NULL,NULL,"
      " 'other-request',1,'failed',1,1);");
  MutationEffects before_unrelated_replay = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  wyl_service_credential_handoff_disposition_result_clear (&result);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_unrelated_replay);

  g_autofree gchar *backup_disposition_audit = g_strdup_printf
      ("CREATE TEMP TABLE disposition_event_backup AS"
      " SELECT * FROM audit_events WHERE id='%s';"
      "CREATE TEMP TABLE disposition_intention_backup AS"
      " SELECT * FROM audit_intentions WHERE audit_id='%s';", audit_id,
      audit_id);
  exec_ok (db_of (handle), backup_disposition_audit);
  static const struct
  {
    const gchar *column;
    const gchar *expression;
  } audit_corruptions[] = {
    {"created_at_us", "created_at_us+1"},
    {"subject_id", "'corrupt-actor'"},
    {"action", "'corrupt-action'"},
    {"resource_id", "'corrupt-resource'"},
    {"request_id", "'corrupt-request'"},
    {"decision", "CASE decision WHEN 1 THEN 0 ELSE 1 END"},
    {"deny_reason", "'corrupt-deny-reason'"},
    {"deny_origin", "'corrupt-deny-origin'"},
  };
  static const struct
  {
    const gchar *table;
    const gchar *key;
    const gchar *backup;
  } audit_tables[] = {
    {"audit_events", "id", "disposition_event_backup"},
    {"audit_intentions", "audit_id", "disposition_intention_backup"},
  };
  for (gsize table_index = 0; table_index < G_N_ELEMENTS (audit_tables);
      table_index++) {
    for (gsize case_index = 0;
        case_index < G_N_ELEMENTS (audit_corruptions); case_index++) {
      g_autofree gchar *corrupt = g_strdup_printf
          ("UPDATE %s SET %s=%s WHERE %s='%s';",
          audit_tables[table_index].table,
          audit_corruptions[case_index].column,
          audit_corruptions[case_index].expression,
          audit_tables[table_index].key, audit_id);
      exec_ok (db_of (handle), corrupt);
      assert_disposition_replay_fails_no_mutation (handle, &input);
      g_autofree gchar *restore = g_strdup_printf
          ("DELETE FROM %s WHERE %s='%s';" "INSERT INTO %s SELECT * FROM %s;",
          audit_tables[table_index].table, audit_tables[table_index].key,
          audit_id, audit_tables[table_index].table,
          audit_tables[table_index].backup);
      exec_ok (db_of (handle), restore);
    }
  }

  g_autofree gchar *delete_event = g_strdup_printf
      ("DELETE FROM audit_events WHERE id='%s';", audit_id);
  exec_ok (db_of (handle), delete_event);
  assert_disposition_replay_fails_no_mutation (handle, &input);
  exec_ok (db_of (handle),
      "INSERT INTO audit_events SELECT * FROM disposition_event_backup;");

  g_autofree gchar *delete_intention = g_strdup_printf
      ("DELETE FROM audit_intentions WHERE audit_id='%s';", audit_id);
  exec_ok (db_of (handle), delete_intention);
  assert_disposition_replay_fails_no_mutation (handle, &input);
  exec_ok (db_of (handle),
      "INSERT INTO audit_intentions"
      " SELECT * FROM disposition_intention_backup;"
      "DROP TABLE disposition_event_backup;"
      "DROP TABLE disposition_intention_backup;");

  gchar cancelled_disposition[WYL_ID_STRING_BUF];
  gchar cancelled_audit[WYL_ID_STRING_BUF];
  new_uuid_string (cancelled_disposition);
  new_uuid_string (cancelled_audit);
  input.disposition_id = cancelled_disposition;
  input.audit_id = cancelled_audit;
  input.reason = WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED;
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_INVALID);

  gchar expired_original[WYL_REQUEST_ID_STRING_BUF];
  gchar expired_remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar expired_decision_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (expired_original,
          sizeof expired_original), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (expired_remediation_id,
          sizeof expired_remediation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (expired_decision_id,
          sizeof expired_decision_id), ==, WYRELOG_E_OK);
  wyl_id_t expired_escrow_id;
  guint8 expired_target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (expired_target, 0x54, sizeof expired_target);
  g_assert_cmpint (wyl_id_new (&expired_escrow_id), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_request_t expired_handoff = {
    .escrow_id = &expired_escrow_id,.target_digest = expired_target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_issue_runtime_t default_issue_runtime = {
    .authorization = &authorization,
  };
  wyl_service_credential_handoff_result_t expired_issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:disposition", "tenant-a", "admin", expired_original,
          g_get_real_time () + 100 * 1000, &expired_handoff,
          &default_issue_runtime, &expired_issued), ==, WYRELOG_E_OK);
  g_usleep (150 * 1000);
  gchar expired_remediation_audit[WYL_ID_STRING_BUF];
  new_uuid_string (expired_remediation_audit);
  AuthorizationProbe expired_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t expired_authorization = {
    .authorize = probe_mutation_authorization,.data = &expired_probe,
  };
  InvalidationProbe expired_invalidation = { 0 };
  wyl_service_credential_handoff_remediation_runtime_t expired_runtime = {
    .authorization = &expired_authorization,
    .invalidate_credential = probe_credential_invalidation,
    .invalidation_data = &expired_invalidation,
  };
  wyl_service_credential_handoff_remediation_input_t expired_remediation = {
    .remediation_request_id = expired_remediation_id,
    .decision_request_id = expired_decision_id,
    .current_actor_subject_id = "operator",
    .audit_id = expired_remediation_audit,
    .tuple = {
          .original_request_id = expired_original,
          .escrow_id = &expired_escrow_id,
          .successor_credential_id = expired_issued.credential.credential_id,
          .successor_issuance_generation = expired_issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_RESUME,
  };
  memcpy (expired_remediation.tuple.binding_digest,
      expired_issued.handoff.binding_digest,
      sizeof expired_remediation.tuple.binding_digest);
  set_remediation_oar_context (&expired_remediation, 0xa2,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD);
  MutationEffects before_expired = mutation_effects (handle);
  wyl_service_credential_handoff_remediation_result_t expired_result = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &expired_remediation, &expired_runtime, &expired_result), ==,
      WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle), before_expired);
  expired_remediation.action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE;
  expired_remediation.confirmation_version = 1;
  expired_remediation.confirmed = TRUE;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &expired_remediation, &expired_runtime, &expired_result), ==,
      WYRELOG_E_OK);
  g_assert_false (expired_result.revoked_now);
  g_assert_cmpint (expired_result.outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED);
  MutationEffects after_expired = mutation_effects (handle);
  g_assert_cmpint (after_expired.credentials, ==, before_expired.credentials);
  g_assert_cmpint (after_expired.events, ==, before_expired.events);
  g_assert_cmpint (after_expired.escrows, ==, before_expired.escrows - 1);
  g_assert_true (expired_invalidation.called);
  g_assert_cmpuint (expired_invalidation.generation, ==, 1);
  WylPolicyServiceHandoffRetirementInput expired_retirement = {
    .journal_version = 6,
    .journal_state = WYL_POLICY_HANDOFF_REMEDIATION_STATE_TERMINAL,
    .terminal_kind = WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE,
    .tuple = {
          .original_request_id = expired_original,
          .escrow_id = &expired_escrow_id,
          .successor_credential_id = expired_issued.credential.credential_id,
          .successor_issuance_generation = expired_issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .journal_updated_at_us = expired_result.created_at_us,
    .remediation_request_id = expired_remediation_id,
  };
  memcpy (expired_retirement.tuple.binding_digest,
      expired_issued.handoff.binding_digest,
      sizeof expired_retirement.tuple.binding_digest);
  memset (expired_retirement.raw_journal_snapshot_digest, 0xa5,
      sizeof expired_retirement.raw_journal_snapshot_digest);
  memcpy (expired_retirement.remediation_source_snapshot_digest,
      expired_result.journal_snapshot_digest,
      sizeof expired_retirement.remediation_source_snapshot_digest);
  memcpy (expired_retirement.remediation_request_fingerprint,
      expired_result.request_fingerprint,
      sizeof expired_retirement.remediation_request_fingerprint);
  gint64 expired_retirement_now = expired_result.created_at_us
      + WYL_POLICY_HANDOFF_RETENTION_MIN_US;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      retirement_fixed_now, &expired_retirement_now);
  Txn expired_transaction = { 0 };
  WylPolicyServiceHandoffRetirementResult expired_receipt = { 0 };
  classifier_transaction_begin (handle, &expired_transaction);
  retirement_transaction_prepare (store_of (handle), &expired_transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (expired_transaction.txn, store_of (handle), &expired_retirement,
          &expired_receipt), ==, WYRELOG_E_OK);
  g_assert_cmpint (expired_receipt.revoke_event_id, ==, 0);
  g_assert_cmpstr (expired_receipt.revoke_remediation_request_id, ==,
      expired_remediation_id);
  wyl_policy_service_handoff_retirement_result_clear (&expired_receipt);
  retirement_transaction_commit (&expired_transaction);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      NULL, NULL);
  wyl_service_credential_handoff_remediation_result_clear (&expired_result);
  g_clear_pointer (&expired_invalidation.credential_id, g_free);
  expired_invalidation.called = FALSE;
  expired_probe.calls = 0;
  g_assert_cmpint (wyl_service_credential_handoff_resolve_remediation (handle,
          expired_remediation_id, "operator", &expired_runtime,
          &expired_result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (expired_probe.calls, ==, 1);
  g_assert_true (expired_result.replayed);
  g_assert_true (expired_invalidation.called);
  g_assert_cmpstr (expired_invalidation.credential_id, ==,
      expired_issued.credential.credential_id);
  g_assert_cmpuint (expired_invalidation.generation, ==, 1);
  wyl_service_credential_handoff_remediation_result_clear (&expired_result);
  g_clear_pointer (&expired_invalidation.credential_id, g_free);
  g_free (expired_probe.actor_subject_id);
  wyl_service_credential_handoff_result_clear (&expired_issued);

  gchar expired_disposition[WYL_ID_STRING_BUF];
  gchar expired_audit[WYL_ID_STRING_BUF];
  new_uuid_string (expired_disposition);
  new_uuid_string (expired_audit);
  input.disposition_id = expired_disposition;
  input.audit_id = expired_audit;
  input.reason = WYL_SERVICE_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED;
  input.outcome = WYL_SERVICE_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED;
  before_disposition = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_OK);
  assert_disposition_only_delta (mutation_effects (handle), before_disposition);
  wyl_service_credential_handoff_disposition_result_clear (&result);

  wyl_service_credential_t revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          issued.credential.credential_id, "operator", "legacy-revoke-oar",
          &revoked), ==, WYRELOG_E_OK);
  gchar revoked_disposition[WYL_ID_STRING_BUF];
  gchar revoked_audit[WYL_ID_STRING_BUF];
  new_uuid_string (revoked_disposition);
  new_uuid_string (revoked_audit);
  input.disposition_id = revoked_disposition;
  input.audit_id = revoked_audit;
  input.reason = WYL_SERVICE_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED;
  before_disposition = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_record_disposition (handle,
          &input, &result), ==, WYRELOG_E_OK);
  assert_disposition_only_delta (mutation_effects (handle), before_disposition);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_dispositions;"),
      ==, 3);
  wyl_service_credential_handoff_disposition_result_clear (&result);

  gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar remediation_audit[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (remediation_id,
          sizeof remediation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (decision_id, sizeof decision_id), ==,
      WYRELOG_E_OK);
  new_uuid_string (remediation_audit);
  AuthorizationProbe remediation_probe = {
    .handle = handle,.rc = WYRELOG_E_OK,
  };
  wyl_service_credential_mutation_authorization_t remediation_authorization = {
    .authorize = probe_mutation_authorization,.data = &remediation_probe,
  };
  InvalidationProbe invalidation = { 0 };
  wyl_service_credential_handoff_remediation_runtime_t remediation_runtime = {
    .authorization = &remediation_authorization,
    .invalidate_credential = probe_credential_invalidation,
    .invalidation_data = &invalidation,
  };
  wyl_service_credential_handoff_remediation_input_t remediation = {
    .remediation_request_id = remediation_id,
    .decision_request_id = decision_id,
    .current_actor_subject_id = "operator",
    .audit_id = remediation_audit,
    .tuple = input.tuple,
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_RESUME,
  };
  set_remediation_oar_context (&remediation, 0xa3,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD);
  MutationEffects before_remediation = mutation_effects (handle);
  wyl_service_credential_handoff_remediation_result_t remediation_result = {
    0
  };
  wyl_policy_store_service_handoff_fail_once (store_of (handle),
      WYL_POLICY_HANDOFF_FAIL_CLASSIFIER_REVOKED_EVENT_NOMEM);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &remediation, &remediation_runtime, &remediation_result), ==,
      WYRELOG_E_NOMEM);
  assert_mutation_effects_equal (mutation_effects (handle), before_remediation);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &remediation, &remediation_runtime, &remediation_result), ==,
      WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle), before_remediation);
  remediation.action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE;
  remediation.confirmation_version = 1;
  remediation.confirmed = TRUE;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &remediation, &remediation_runtime, &remediation_result), ==,
      WYRELOG_E_OK);
  g_assert_false (remediation_result.revoked_now);
  g_assert_cmpint (remediation_result.outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED);
  MutationEffects after_remediation = mutation_effects (handle);
  g_assert_cmpint (after_remediation.credentials, ==,
      before_remediation.credentials);
  g_assert_cmpint (after_remediation.events, ==, before_remediation.events);
  g_assert_cmpint (after_remediation.escrows, ==,
      before_remediation.escrows - 1);
  g_assert_cmpint (after_remediation.handoff_remediations, ==,
      before_remediation.handoff_remediations + 1);
  g_assert_true (invalidation.called);
  g_assert_cmpuint (invalidation.generation, ==, 1);
  WylPolicyServiceHandoffRetirementInput revoked_retirement = {
    .journal_version = 6,
    .journal_state = WYL_POLICY_HANDOFF_REMEDIATION_STATE_TERMINAL,
    .terminal_kind = WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE,
    .tuple = {
          .original_request_id = input.tuple.original_request_id,
          .escrow_id = input.tuple.escrow_id,
          .successor_credential_id = input.tuple.successor_credential_id,
          .successor_issuance_generation =
          input.tuple.successor_issuance_generation,
          .original_actor_subject_id = input.tuple.original_actor_subject_id,
        },
    .journal_updated_at_us = remediation_result.created_at_us,
    .remediation_request_id = remediation_id,
  };
  memcpy (revoked_retirement.tuple.binding_digest,
      input.tuple.binding_digest,
      sizeof revoked_retirement.tuple.binding_digest);
  memset (revoked_retirement.raw_journal_snapshot_digest, 0xa6,
      sizeof revoked_retirement.raw_journal_snapshot_digest);
  memcpy (revoked_retirement.remediation_source_snapshot_digest,
      remediation_result.journal_snapshot_digest,
      sizeof revoked_retirement.remediation_source_snapshot_digest);
  memcpy (revoked_retirement.remediation_request_fingerprint,
      remediation_result.request_fingerprint,
      sizeof revoked_retirement.remediation_request_fingerprint);
  gint64 revoked_retirement_now = MAX (remediation_result.created_at_us,
      remediation_result.revoke_event_created_at_us)
      + WYL_POLICY_HANDOFF_RETENTION_MIN_US;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      retirement_fixed_now, &revoked_retirement_now);
  Txn revoked_transaction = { 0 };
  WylPolicyServiceHandoffRetirementResult revoked_receipt = { 0 };
  classifier_transaction_begin (handle, &revoked_transaction);
  retirement_transaction_prepare (store_of (handle), &revoked_transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (revoked_transaction.txn, store_of (handle), &revoked_retirement,
          &revoked_receipt), ==, WYRELOG_E_OK);
  g_assert_cmpint (revoked_receipt.revoke_event_id, ==,
      remediation_result.revoke_event_id);
  wyl_policy_service_handoff_retirement_result_clear (&revoked_receipt);
  retirement_transaction_commit (&revoked_transaction);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store_of (handle),
      NULL, NULL);
  wyl_service_credential_handoff_remediation_result_clear (&remediation_result);
  g_clear_pointer (&invalidation.credential_id, g_free);
  g_free (remediation_probe.actor_subject_id);
  wyl_service_credential_clear (&revoked);
  wyl_service_credential_handoff_result_clear (&issued);
  g_free (issue_probe.actor_subject_id);
}

static void
test_handoff_revoke_wipe_fault_atomicity (void)
{
  gchar original_id[WYL_REQUEST_ID_STRING_BUF];
  gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (original_id, sizeof original_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (remediation_id,
          sizeof remediation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (decision_id, sizeof decision_id), ==,
      WYRELOG_E_OK);
  wyl_id_t audit_uuid;
  gchar audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&audit_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&audit_uuid, audit_id, sizeof audit_id), ==,
      WYRELOG_E_OK);
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:revoke-wipe");
  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe issue_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t issue_authorization = {
    .authorize = probe_mutation_authorization,.data = &issue_probe,
  };
  wyl_service_credential_issue_runtime_t issue_runtime = {
    .authorization = &issue_authorization,
    .credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0x73, sizeof target);
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:revoke-wipe", "tenant-a", "admin", original_id,
          g_get_real_time () + G_TIME_SPAN_HOUR, &handoff, &issue_runtime,
          &issued), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_remediation_input_t input = {
    .remediation_request_id = remediation_id,
    .decision_request_id = decision_id,
    .current_actor_subject_id = "operator",
    .audit_id = audit_id,
    .tuple = {
          .original_request_id = original_id,
          .escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE,
    .confirmation_version = 1,
    .confirmed = TRUE,
  };
  memcpy (input.tuple.binding_digest, issued.handoff.binding_digest,
      sizeof input.tuple.binding_digest);
  set_remediation_oar_context (&input, 0xa4,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD);
  AuthorizationProbe probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &probe,
  };
  InvalidationProbe invalidation = { 0 };
  wyl_service_credential_handoff_remediation_runtime_t runtime = {
    .authorization = &authorization,
    .invalidate_credential = probe_credential_invalidation,
    .invalidation_data = &invalidation,
  };
  static const WylPolicyServiceHandoffFailStage stages[] = {
    WYL_POLICY_HANDOFF_FAIL_AFTER_REQUEST_CLAIM,
    WYL_POLICY_HANDOFF_FAIL_AFTER_CLASSIFY_OR_CAS,
    WYL_POLICY_HANDOFF_FAIL_AFTER_SUCCESSOR_EVENT,
    WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT,
    WYL_POLICY_HANDOFF_FAIL_AFTER_ESCROW_DELETE,
    WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE,
  };
  MutationEffects before = mutation_effects (handle);
  wyl_policy_store_service_handoff_fail_once (store_of (handle),
      WYL_POLICY_HANDOFF_FAIL_CLASSIFIER_LOOKUP_NOMEM);
  wyl_service_credential_handoff_remediation_result_t nomem = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &nomem), ==, WYRELOG_E_NOMEM);
  g_assert_null (nomem.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle), before);
  for (guint i = 0; i < G_N_ELEMENTS (stages); i++) {
    probe.calls = 0;
    invalidation.called = FALSE;
    wyl_policy_store_service_handoff_fail_once (store_of (handle), stages[i]);
    wyl_service_credential_handoff_remediation_result_t failed = { 0 };
    g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
            &input, &runtime, &failed), ==, WYRELOG_E_IO);
    g_assert_cmpuint (probe.calls, ==, 1);
    g_assert_false (invalidation.called);
    g_assert_null (failed.audit_id);
    assert_mutation_effects_equal (mutation_effects (handle), before);
  }
  wyl_service_credential_handoff_remediation_result_t result = { 0 };
  probe.calls = 0;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (result.revoked_now);
  g_assert_false (result.replayed);
  g_assert_cmpint (result.escrow_outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_DELETED);
  g_assert_cmpuint (result.credential_generation_after, ==, 2);
  g_assert_cmpint (result.revoke_event_id, >, 0);
  g_assert_cmpuint (result.revoke_event_generation, ==, 2);
  g_assert_cmpstr (result.revoke_event_request_id, ==, remediation_id);
  g_assert_cmpstr (result.revoke_event_actor_subject_id, ==, "operator");
  g_assert_cmpint (result.revoke_event_created_at_us, ==, result.created_at_us);
  g_assert_true (invalidation.called);
  g_assert_cmpuint (invalidation.generation, ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credentials WHERE state='revoked'"
          " AND generation=2;"), ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_escrows;"), ==, 0);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_events e JOIN"
          " service_credential_handoff_remediation_actions r"
          " ON r.revoke_event_id=e.event_id"
          " WHERE e.event='revoked'"
          " AND e.request_id=r.remediation_request_id"
          " AND e.actor_subject_id=r.current_actor_subject_id"
          " AND e.created_at_us=r.created_at_us;"), ==, 1);
  wyl_service_credential_handoff_remediation_result_clear (&result);
  probe.calls = 0;
  invalidation.called = FALSE;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.calls, ==, 1);
  g_assert_true (result.replayed);
  g_assert_false (result.revoked_now);
  g_assert_true (invalidation.called);
  g_assert_cmpuint (invalidation.generation, ==, 1);
  wyl_service_credential_handoff_remediation_result_clear (&result);

  gchar missing_original[WYL_REQUEST_ID_STRING_BUF];
  gchar missing_remediation[WYL_REQUEST_ID_STRING_BUF];
  gchar missing_decision[WYL_REQUEST_ID_STRING_BUF];
  gchar missing_audit[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (missing_original,
          sizeof missing_original), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (missing_remediation,
          sizeof missing_remediation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (missing_decision,
          sizeof missing_decision), ==, WYRELOG_E_OK);
  new_uuid_string (missing_audit);
  wyl_id_t missing_escrow;
  g_assert_cmpint (wyl_id_new (&missing_escrow), ==, WYRELOG_E_OK);
  guint8 missing_target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (missing_target, 0x91, sizeof missing_target);
  wyl_service_credential_handoff_request_t missing_handoff = {
    .escrow_id = &missing_escrow,
    .target_digest = missing_target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t missing_issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:revoke-wipe", "tenant-a", "admin", missing_original,
          g_get_real_time () + G_TIME_SPAN_HOUR, &missing_handoff,
          &issue_runtime, &missing_issued), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_remediation_input_t missing_input = {
    .remediation_request_id = missing_remediation,
    .decision_request_id = missing_decision,
    .current_actor_subject_id = "operator",
    .audit_id = missing_audit,
    .tuple = {
          .original_request_id = missing_original,
          .escrow_id = &missing_escrow,
          .successor_credential_id = missing_issued.credential.credential_id,
          .successor_issuance_generation = missing_issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE,
    .confirmation_version = 1,
    .confirmed = TRUE,
  };
  memcpy (missing_input.tuple.binding_digest,
      missing_issued.handoff.binding_digest,
      sizeof missing_input.tuple.binding_digest);
  set_remediation_oar_context (&missing_input, 0xb2,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING);
  MutationEffects missing_before = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &missing_input, &runtime, &result), ==, WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle), missing_before);
  gchar missing_escrow_text[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_format (&missing_escrow, missing_escrow_text,
          sizeof missing_escrow_text), ==, WYRELOG_E_OK);
  g_autofree gchar *backup_missing_escrow = g_strdup_printf
      ("CREATE TEMP TABLE missing_escrow_backup AS SELECT * FROM"
      " service_credential_handoff_escrows WHERE escrow_id='%s';",
      missing_escrow_text);
  exec_ok (db_of (handle), backup_missing_escrow);
  g_autofree gchar *make_same_id_foreign = g_strdup_printf
      ("UPDATE service_credential_handoff_escrows SET actor_subject_id="
      "'foreign-actor' WHERE escrow_id='%s';", missing_escrow_text);
  exec_ok (db_of (handle), make_same_id_foreign);
  missing_before = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &missing_input, &runtime, &result), ==, WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle), missing_before);
  wyl_id_t foreign_escrow;
  gchar foreign_escrow_text[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&foreign_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&foreign_escrow, foreign_escrow_text,
          sizeof foreign_escrow_text), ==, WYRELOG_E_OK);
  g_autofree gchar *make_request_foreign = g_strdup_printf
      ("UPDATE service_credential_handoff_escrows SET escrow_id='%s'"
      " WHERE escrow_id='%s';", foreign_escrow_text, missing_escrow_text);
  exec_ok (db_of (handle), make_request_foreign);
  missing_before = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &missing_input, &runtime, &result), ==, WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle), missing_before);
  g_autofree gchar *delete_request_foreign = g_strdup_printf
      ("DELETE FROM service_credential_handoff_escrows WHERE escrow_id='%s';",
      foreign_escrow_text);
  exec_ok (db_of (handle), delete_request_foreign);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &missing_input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.revoked_now);
  g_assert_cmpint (result.escrow_outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT);
  g_assert_cmpstr (result.revoke_event_request_id, ==, missing_remediation);
  g_assert_cmpstr (result.revoke_event_actor_subject_id, ==, "operator");
  wyl_service_credential_handoff_remediation_result_clear (&result);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &missing_input, &runtime, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  g_assert_cmpint (result.escrow_outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT);
  wyl_service_credential_handoff_remediation_result_clear (&result);
  exec_ok (db_of (handle),
      "INSERT INTO service_credential_handoff_escrows"
      " SELECT * FROM missing_escrow_backup;");
  MutationEffects before_absence_replay_tamper = mutation_effects (handle);
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &missing_input, &runtime, &result), ==, WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle),
      before_absence_replay_tamper);
  g_autofree gchar *remove_reintroduced_escrow = g_strdup_printf
      ("DELETE FROM service_credential_handoff_escrows WHERE escrow_id='%s';"
      "DROP TABLE missing_escrow_backup;", missing_escrow_text);
  exec_ok (db_of (handle), remove_reintroduced_escrow);
  wyl_service_credential_handoff_result_clear (&missing_issued);

  MutationEffects completed = mutation_effects (handle);
  input.tuple.binding_digest[0] ^= 0xff;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle), completed);
  input.tuple.binding_digest[0] ^= 0xff;

  gchar other_remediation[WYL_REQUEST_ID_STRING_BUF];
  gchar other_decision[WYL_REQUEST_ID_STRING_BUF];
  gchar other_audit[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (other_remediation,
          sizeof other_remediation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (other_decision,
          sizeof other_decision), ==, WYRELOG_E_OK);
  new_uuid_string (other_audit);
  wyl_service_credential_handoff_remediation_input_t other = input;
  other.remediation_request_id = other_remediation;
  other.decision_request_id = other_decision;
  other.audit_id = other_audit;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &other, &runtime, &result), ==, WYRELOG_E_POLICY);
  assert_mutation_effects_equal (mutation_effects (handle), completed);

  invalidation.fail = TRUE;
  invalidation.called = FALSE;
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &input, &runtime, &result), ==, WYRELOG_E_IO);
  g_assert_true (invalidation.called);
  g_assert_null (result.audit_id);
  assert_mutation_effects_equal (mutation_effects (handle), completed);
  WylServiceAuthUnavailableReason unavailable_reason =
      WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle,
          &unavailable_reason), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (unavailable_reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT);
  g_clear_pointer (&invalidation.credential_id, g_free);
  wyl_service_credential_handoff_result_clear (&issued);
  g_free (probe.actor_subject_id);
  g_free (issue_probe.actor_subject_id);
}

static void
test_handoff_terminal_retirement_resumed_file_dual_proof (void)
{
  gchar original_id[WYL_REQUEST_ID_STRING_BUF];
  gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (original_id, sizeof original_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (remediation_id,
          sizeof remediation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (decision_id, sizeof decision_id), ==,
      WYRELOG_E_OK);
  new_uuid_string (audit_id);
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  wyl_policy_store_t *store = store_of (handle);
  prepare_authority (handle, "svc:handoff:retirement-resume");
  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe issue_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t issue_authorization = {
    .authorize = probe_mutation_authorization,.data = &issue_probe,
  };
  wyl_service_credential_issue_runtime_t issue_runtime = {
    .authorization = &issue_authorization,
    .credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0xc5, sizeof target);
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:retirement-resume", "tenant-a", "admin", original_id,
          g_get_real_time () + G_TIME_SPAN_HOUR, &handoff, &issue_runtime,
          &issued), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_remediation_input_t remediation_input = {
    .remediation_request_id = remediation_id,
    .decision_request_id = decision_id,.current_actor_subject_id = "operator",
    .audit_id = audit_id,
    .tuple = {
          .original_request_id = original_id,.escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_RESUME,
  };
  memcpy (remediation_input.tuple.binding_digest,
      issued.handoff.binding_digest,
      sizeof remediation_input.tuple.binding_digest);
  set_remediation_oar_context (&remediation_input, 0xc6,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD);
  AuthorizationProbe remediation_probe = {
    .handle = handle,.rc = WYRELOG_E_OK,
  };
  wyl_service_credential_mutation_authorization_t remediation_authorization = {
    .authorize = probe_mutation_authorization,.data = &remediation_probe,
  };
  wyl_service_credential_handoff_remediation_runtime_t remediation_runtime = {
    .authorization = &remediation_authorization,
  };
  wyl_service_credential_handoff_remediation_result_t remediation = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &remediation_input, &remediation_runtime, &remediation), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (remediation.escrow_outcome, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_RETAINED);
  WylPolicyServiceHandoffExactTuple tuple = {
    .original_request_id = original_id,.escrow_id = &escrow_id,
    .successor_credential_id = issued.credential.credential_id,
    .successor_issuance_generation = issued.credential.generation,
    .original_actor_subject_id = "admin",
  };
  memcpy (tuple.binding_digest, issued.handoff.binding_digest,
      sizeof tuple.binding_digest);
  guint8 delivery_proof[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  memset (delivery_proof, 0xc7, sizeof delivery_proof);
  WylPolicyServiceHandoffPublicationOutcome publication = 0;
  WylPolicyServiceHandoffDispositionResult delivered = { 0 };
  Txn transaction = { 0 };
  classifier_transaction_begin (handle, &transaction);
  retirement_transaction_prepare (store, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_consume_delivered_core
      (transaction.txn, store, &tuple, "admin", delivery_proof, &publication,
          &delivered), ==, WYRELOG_E_OK);
  retirement_transaction_commit (&transaction);
  /* Historical RESUME provenance remains valid even when the successor is
   * revoked normally after delivery but before terminal metadata retirement. */
  wyl_service_credential_t later_revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          issued.credential.credential_id, "admin", "later-revoke",
          &later_revoked), ==, WYRELOG_E_OK);
  WylPolicyServiceHandoffRetirementInput input = {
    .journal_version = 6,
    .journal_state = WYL_POLICY_HANDOFF_REMEDIATION_STATE_TERMINAL,
    .terminal_kind = WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED,
    .tuple = tuple,.journal_updated_at_us = MAX (delivered.created_at_us,
        remediation.created_at_us),.delivery_actor_subject_id = "admin",
    .remediation_request_id = remediation_id,
  };
  memset (input.raw_journal_snapshot_digest, 0xc8,
      sizeof input.raw_journal_snapshot_digest);
  memcpy (input.delivery_proof_digest, delivery_proof,
      sizeof input.delivery_proof_digest);
  memcpy (input.remediation_source_snapshot_digest,
      remediation.journal_snapshot_digest,
      sizeof input.remediation_source_snapshot_digest);
  memcpy (input.remediation_request_fingerprint,
      remediation.request_fingerprint,
      sizeof input.remediation_request_fingerprint);
  gint64 now_us = input.journal_updated_at_us
      + WYL_POLICY_HANDOFF_RETENTION_MIN_US;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store,
      retirement_fixed_now, &now_us);
  WylPolicyServiceHandoffRetirementResult result = { 0 };
  classifier_transaction_begin (handle, &transaction);
  retirement_transaction_prepare (store, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_OK);
  g_assert_cmpstr (result.resume_remediation_request_id, ==, remediation_id);
  g_assert_cmpstr (result.resume_audit_id, ==, audit_id);
  wyl_policy_service_handoff_retirement_result_clear (&result);
  retirement_transaction_commit (&transaction);
  input.remediation_source_snapshot_digest[0] ^= 0xff;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store, NULL, NULL);
  wyl_service_credential_clear (&later_revoked);
  wyl_policy_service_handoff_disposition_result_clear (&delivered);
  wyl_service_credential_handoff_remediation_result_clear (&remediation);
  wyl_service_credential_handoff_result_clear (&issued);
  g_free (remediation_probe.actor_subject_id);
  g_free (issue_probe.actor_subject_id);
}

static void
test_handoff_terminal_retirement_revoke_fault_replay (void)
{
  gchar original_id[WYL_REQUEST_ID_STRING_BUF];
  gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (original_id, sizeof original_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (remediation_id,
          sizeof remediation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (decision_id, sizeof decision_id), ==,
      WYRELOG_E_OK);
  new_uuid_string (audit_id);
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  wyl_policy_store_t *store = store_of (handle);
  prepare_authority (handle, "svc:handoff:retirement-revoke");
  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe issue_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t issue_authorization = {
    .authorize = probe_mutation_authorization,.data = &issue_probe,
  };
  wyl_service_credential_issue_runtime_t issue_runtime = {
    .authorization = &issue_authorization,
    .credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0xc2, sizeof target);
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:retirement-revoke", "tenant-a", "admin", original_id,
          g_get_real_time () + G_TIME_SPAN_HOUR, &handoff, &issue_runtime,
          &issued), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_remediation_input_t remediation_input = {
    .remediation_request_id = remediation_id,
    .decision_request_id = decision_id,
    .current_actor_subject_id = "operator",
    .audit_id = audit_id,
    .tuple = {
          .original_request_id = original_id,.escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE,
    .confirmation_version = 1,.confirmed = TRUE,
  };
  memcpy (remediation_input.tuple.binding_digest,
      issued.handoff.binding_digest,
      sizeof remediation_input.tuple.binding_digest);
  set_remediation_oar_context (&remediation_input, 0xc3,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD);
  AuthorizationProbe remediation_probe = {
    .handle = handle,.rc = WYRELOG_E_OK,
  };
  wyl_service_credential_mutation_authorization_t remediation_authorization = {
    .authorize = probe_mutation_authorization,.data = &remediation_probe,
  };
  InvalidationProbe invalidation = { 0 };
  wyl_service_credential_handoff_remediation_runtime_t remediation_runtime = {
    .authorization = &remediation_authorization,
    .invalidate_credential = probe_credential_invalidation,
    .invalidation_data = &invalidation,
  };
  wyl_service_credential_handoff_remediation_result_t remediation = { 0 };
  g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
          &remediation_input, &remediation_runtime, &remediation), ==,
      WYRELOG_E_OK);
  g_assert_true (remediation.revoked_now);
  g_assert_cmpint (remediation.revoke_event_id, >, 0);
  WylPolicyServiceHandoffRetirementInput input = {
    .journal_version = 6,
    .journal_state = WYL_POLICY_HANDOFF_REMEDIATION_STATE_TERMINAL,
    .terminal_kind = WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE,
    .tuple = {
          .original_request_id = original_id,.escrow_id = &escrow_id,
          .successor_credential_id = issued.credential.credential_id,
          .successor_issuance_generation = issued.credential.generation,
          .original_actor_subject_id = "admin",
        },
    .journal_updated_at_us = remediation.created_at_us,
    .remediation_request_id = remediation_id,
  };
  memcpy (input.tuple.binding_digest, issued.handoff.binding_digest,
      sizeof input.tuple.binding_digest);
  memset (input.raw_journal_snapshot_digest, 0xc4,
      sizeof input.raw_journal_snapshot_digest);
  memcpy (input.remediation_source_snapshot_digest,
      remediation.journal_snapshot_digest,
      sizeof input.remediation_source_snapshot_digest);
  memcpy (input.remediation_request_fingerprint,
      remediation.request_fingerprint,
      sizeof input.remediation_request_fingerprint);
  gint64 now_us = MAX (remediation.created_at_us,
      remediation.revoke_event_created_at_us)
      + WYL_POLICY_HANDOFF_RETENTION_MIN_US;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store,
      retirement_fixed_now, &now_us);
  WylPolicyServiceHandoffRetirementResult result = { 0 };
  Txn transaction = { 0 };
  wyl_policy_store_service_handoff_fail_once (store,
      WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE);
  classifier_transaction_begin (handle, &transaction);
  retirement_transaction_prepare (store, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_IO);
  classifier_transaction_end (&transaction);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_retirement_receipts;"),
      ==, 0);
  classifier_transaction_begin (handle, &transaction);
  retirement_transaction_prepare (store, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  g_assert_cmpstr (result.revoke_remediation_request_id, ==, remediation_id);
  g_assert_cmpint (result.revoke_event_id, ==, remediation.revoke_event_id);
  wyl_policy_service_handoff_retirement_result_clear (&result);
  retirement_transaction_commit (&transaction);
  input.remediation_request_fingerprint[0] ^= 0xff;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store, NULL, NULL);
  wyl_service_credential_handoff_remediation_result_clear (&remediation);
  wyl_service_credential_handoff_result_clear (&issued);
  g_clear_pointer (&invalidation.credential_id, g_free);
  g_free (remediation_probe.actor_subject_id);
  g_free (issue_probe.actor_subject_id);
}

static void
test_handoff_terminal_retirement_file_boundary_replay (void)
{
  gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (original_request_id,
          sizeof original_request_id), ==, WYRELOG_E_OK);
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  wyl_policy_store_t *store = store_of (handle);
  prepare_authority (handle, "svc:handoff:retirement-file");

  CollisionRuntime collision = { 0 };
  wyl_service_credential_runtime_t credential_runtime = {
    test_alloc, test_lock, test_wipe, test_unlock, test_free, test_new_id,
    test_random, &collision,
  };
  AuthorizationProbe issue_probe = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = probe_mutation_authorization,.data = &issue_probe,
  };
  wyl_service_credential_issue_runtime_t issue_runtime = {
    .authorization = &authorization,.credential_runtime = &credential_runtime,
  };
  wyl_id_t escrow_id;
  guint8 target[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  memset (target, 0xc1, sizeof target);
  g_assert_cmpint (wyl_id_new (&escrow_id), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = &escrow_id,.target_digest = target,
    .deadline_at_us = g_get_real_time () + G_TIME_SPAN_HOUR,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          "svc:handoff:retirement-file", "tenant-a", "admin",
          original_request_id, g_get_real_time () + G_TIME_SPAN_HOUR,
          &handoff, &issue_runtime, &issued), ==, WYRELOG_E_OK);
  WylPolicyServiceHandoffExactTuple tuple = {
    .original_request_id = original_request_id,
    .escrow_id = &escrow_id,
    .successor_credential_id = issued.credential.credential_id,
    .successor_issuance_generation = issued.credential.generation,
    .original_actor_subject_id = "admin",
  };
  memcpy (tuple.binding_digest, issued.handoff.binding_digest,
      sizeof tuple.binding_digest);
  guint8 delivery_proof[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  memset (delivery_proof, 0xd1, sizeof delivery_proof);
  WylPolicyServiceHandoffPublicationOutcome publication = 0;
  WylPolicyServiceHandoffDispositionResult delivered = { 0 };
  Txn transaction = { 0 };
  classifier_transaction_begin (handle, &transaction);
  retirement_transaction_prepare (store, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_consume_delivered_core
      (transaction.txn, store, &tuple, "admin", delivery_proof, &publication,
          &delivered), ==, WYRELOG_E_OK);
  g_assert_cmpint (publication, ==, WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE);
  retirement_transaction_commit (&transaction);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_escrows;"), ==, 0);

  WylPolicyServiceHandoffRetirementInput input = {
    .journal_version = 6,
    .journal_state = WYL_POLICY_HANDOFF_REMEDIATION_STATE_TERMINAL,
    .terminal_kind = WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED,
    .tuple = tuple,
    .journal_updated_at_us = delivered.created_at_us,
    .delivery_actor_subject_id = "admin",
  };
  memset (input.raw_journal_snapshot_digest, 0xe1,
      sizeof input.raw_journal_snapshot_digest);
  memcpy (input.delivery_proof_digest, delivery_proof,
      sizeof input.delivery_proof_digest);
  gint64 now_us = delivered.created_at_us
      + WYL_POLICY_HANDOFF_RETENTION_MIN_US - 1;
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store,
      retirement_fixed_now, &now_us);
  WylPolicyServiceHandoffRetirementResult result = { 0 };
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM service_credential_handoff_retirement_receipts;"),
      ==, 0);

  now_us++;
  classifier_transaction_begin (handle, &transaction);
  retirement_transaction_prepare (store, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  g_assert_cmpstr (result.delivery_disposition_id, ==,
      delivered.disposition_id);
  g_assert_cmpstr (result.delivery_audit_id, ==, delivered.audit_id);
  g_assert_cmpint (result.retention_basis_at_us, ==, delivered.created_at_us);
  g_assert_cmpint (result.retired_at_us, ==, now_us);
  gint64 retired_at_us = result.retired_at_us;
  wyl_policy_service_handoff_retirement_result_clear (&result);
  retirement_transaction_commit (&transaction);

  /* Permanent exact replay never reopens the elapsed-time gate, even if the
   * trusted wall clock regresses after the receipt was committed. */
  now_us = delivered.created_at_us;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  g_assert_cmpint (result.retired_at_us, ==, retired_at_us);
  wyl_policy_service_handoff_retirement_result_clear (&result);
  classifier_transaction_end (&transaction);

  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_lookup_core
      (transaction.txn, store, original_request_id, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.retired_at_us, ==, retired_at_us);
  wyl_policy_service_handoff_retirement_result_clear (&result);
  classifier_transaction_end (&transaction);

  input.journal_version = 5;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_INVALID);
  classifier_transaction_end (&transaction);
  input.journal_version = 6;
  input.raw_journal_snapshot_digest[0] ^= 0xff;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  input.raw_journal_snapshot_digest[0] ^= 0xff;
  input.delivery_proof_digest[0] ^= 0xff;
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_record_core
      (transaction.txn, store, &input, &result), ==, WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  input.delivery_proof_digest[0] ^= 0xff;

  wyl_id_t foreign_escrow_id;
  gchar foreign_escrow[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&foreign_escrow_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&foreign_escrow_id, foreign_escrow,
          sizeof foreign_escrow), ==, WYRELOG_E_OK);
  g_autofree gchar *insert_foreign = g_strdup_printf
      ("INSERT INTO service_credential_handoff_escrows VALUES"
      "('%s','issue','%s','foreign',zeroblob(32),'%s',1,%"
      G_GINT64_FORMAT ",zeroblob(32),x'01',1);", foreign_escrow,
      original_request_id, issued.credential.credential_id,
      g_get_real_time () + G_TIME_SPAN_HOUR);
  exec_ok (db_of (handle), insert_foreign);
  classifier_transaction_begin (handle, &transaction);
  g_assert_cmpint (wyl_policy_store_handoff_retirement_lookup_core
      (transaction.txn, store, original_request_id, &result), ==,
      WYRELOG_E_POLICY);
  classifier_transaction_end (&transaction);
  exec_ok (db_of (handle), "DELETE FROM service_credential_handoff_escrows;");
  wyl_policy_store_handoff_maintenance_set_clock_for_test (store, NULL, NULL);
  wyl_policy_service_handoff_disposition_result_clear (&delivered);
  wyl_service_credential_handoff_result_clear (&issued);
  g_free (issue_probe.actor_subject_id);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/auth/service-credential/issue-metadata-sanitation",
      test_issue_metadata_and_sanitation);
  g_test_add_func ("/auth/service-credential/rejections-replay-cvk-only",
      test_rejections_replay_and_cvk_only);
  g_test_add_func ("/auth/service-credential/terminal-fence-issue-block",
      test_terminal_fence_blocks_issue_before_rng);
  g_test_add_func ("/auth/service-credential/terminal-fence-rotate-block",
      test_terminal_fence_blocks_rotate_before_rng);
  g_test_add_func ("/auth/service-credential/concurrent-request",
      test_concurrent_request);
  g_test_add_func ("/auth/service-credential/fault-rollback",
      test_fault_rollback);
  g_test_add_func ("/auth/service-credential/id-collision-wipe",
      test_id_collision_retry_and_wipe);
  g_test_add_func ("/auth/service-credential/mutation-authorization-denial",
      test_mutation_authorization_denial_inside_write_lease);
  g_test_add_func ("/auth/service-credential/handoff-issue-replay-no-secret",
      test_handoff_issue_authorization_replay_and_no_plaintext);
  g_test_add_func ("/auth/service-credential/handoff-rotate-stale-replay",
      test_handoff_checked_rotate_stale_rollback_and_replay);
  g_test_add_func ("/auth/service-credential/same-thread-callback-reentry",
      test_same_thread_callback_reentry_is_busy);
  g_test_add_func
      ("/auth/service-credential/authority-contention-reentry-snapshot",
      test_authority_contention_reentry_and_snapshot);
  g_test_add_func ("/auth/service-credential/authority-commit-no-secret",
      test_authority_commit_fault_withholds_secret);
  g_test_add_func ("/auth/service-credential/verify-expiry-clock-inside-gate",
      test_verify_expiry_clock_inside_gate);
  g_test_add_func ("/auth/service-credential/verify-fail-closed-read-only",
      test_verify_fail_closed_read_only);
  g_test_add_func ("/auth/service-credential/revoke-lifecycle-remediation",
      test_revoke_lifecycle_and_remediation);
  g_test_add_func
      ("/auth/service-credential/revoke-concurrency-overflow-faults",
      test_revoke_concurrency_overflow_faults);
  g_test_add_func ("/auth/service-credential/rotate-happy-linkage-no-grace",
      test_rotate_happy_linkage_no_grace);
  g_test_add_func ("/auth/service-credential/rotate-policy-rejections",
      test_rotate_policy_rejections);
  g_test_add_func ("/auth/service-credential/rotate-concurrency",
      test_rotate_concurrency);
  g_test_add_func ("/auth/service-credential/rotate-stale-expected-cas",
      test_rotate_stale_expected_generation_has_no_effects);
  g_test_add_func ("/auth/service-credential/rotate-collision-wipe",
      test_rotate_collision_retry_and_wipe);
  g_test_add_func ("/auth/service-credential/rotate-faults-overflow",
      test_rotate_faults_and_overflow);
  g_test_add_func ("/auth/service-credential/rotate-missing-cvk",
      test_rotate_missing_cvk_does_not_recreate);
  g_test_add_func
      ("/auth/service-credential/revoke-invalidation-failure-unavailable",
      test_revoke_invalidation_failure_marks_result_unavailable);
  g_test_add_func ("/auth/service-credential/handoff-exact-classifier",
      test_handoff_exact_successor_classifier);
#ifdef WYL_TEST_HAS_HANDOFF_MAINTENANCE_CORE
  g_test_add_func
      ("/auth/service-credential/handoff-maintenance-escrow-clock-attention",
      test_handoff_maintenance_escrow_clock_and_attention);
  g_test_add_func
      ("/auth/service-credential/handoff-maintenance-prepared-replay-rollback",
      test_handoff_maintenance_prepared_replay_and_rollback);
#endif
  g_test_add_func
      ("/auth/service-credential/handoff-remediation-fresh-auth-replay",
      test_handoff_remediation_fresh_authorization_and_replay);
#ifdef WYL_TEST_HAS_HANDOFF_CANCELLATION
  g_test_add_func
      ("/auth/service-credential/handoff-cancellation-fresh-auth-replay",
      test_handoff_cancellation_claim_fresh_authorization_and_replay);
  g_test_add_func
      ("/auth/service-credential/handoff-cancellation-prepared-terminal-boundary-rollback",
      test_handoff_cancellation_prepared_terminal_boundary_rollback);
#endif
  g_test_add_func
      ("/auth/service-credential/handoff-not-committed-exact-fence",
      test_handoff_not_committed_requires_exact_fence);
  g_test_add_func ("/auth/service-credential/handoff-disposition-attention-oar",
      test_handoff_disposition_attention_and_oar);
  g_test_add_func ("/auth/service-credential/handoff-revoke-wipe-faults",
      test_handoff_revoke_wipe_fault_atomicity);
  g_test_add_func
      ("/auth/service-credential/handoff-terminal-retirement-file-boundary-replay",
      test_handoff_terminal_retirement_file_boundary_replay);
  g_test_add_func
      ("/auth/service-credential/handoff-terminal-retirement-revoke-fault-replay",
      test_handoff_terminal_retirement_revoke_fault_replay);
  g_test_add_func
      ("/auth/service-credential/handoff-terminal-retirement-resumed-file-dual-proof",
      test_handoff_terminal_retirement_resumed_file_dual_proof);
  return g_test_run ();
}

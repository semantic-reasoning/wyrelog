/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <string.h>

#include "auth/service-credential-domain-private.h"
#include "wyrelog/wyl-handle-private.h"

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
        scalar (db, "SELECT count(*) FROM audit_intentions;"),};
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
  return g_test_run ();
}

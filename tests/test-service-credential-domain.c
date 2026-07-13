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
  (void) data;
  memset (out, 0x5a, len);
  return 0;
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

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/auth/service-credential/issue-metadata-sanitation",
      test_issue_metadata_and_sanitation);
  g_test_add_func ("/auth/service-credential/rejections-replay-cvk-only",
      test_rejections_replay_and_cvk_only);
  g_test_add_func ("/auth/service-credential/concurrent-request",
      test_concurrent_request);
  g_test_add_func ("/auth/service-credential/fault-rollback",
      test_fault_rollback);
  g_test_add_func ("/auth/service-credential/id-collision-wipe",
      test_id_collision_retry_and_wipe);
  return g_test_run ();
}

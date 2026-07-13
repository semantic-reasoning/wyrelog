/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "auth/service-credential-domain-private.h"
#include "wyrelog/wyl-handle-private.h"

static void
remove_store_files (const gchar *path)
{
  static const gchar *suffixes[] = {
    "", ".wyrelog-clear", ".wyrelog-lock", ".wyrelog-tmp", "-journal",
    "-wal", "-shm",
    ".wyrelog-clear-journal", ".wyrelog-clear-wal", ".wyrelog-clear-shm",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (suffixes); i++) {
    g_autofree gchar *candidate = g_strdup_printf ("%s%s", path, suffixes[i]);
    (void) g_remove (candidate);
  }
}

static sqlite3 *
handle_db (WylHandle *handle)
{
  return wyl_policy_store_get_db (wyl_handle_get_policy_store (handle));
}

static gint64
scalar_int64 (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
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
exec_rejected (sqlite3 *db, const gchar *sql)
{
  gchar *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  sqlite3_free (message);
  g_assert_cmpint (rc, !=, SQLITE_OK);
}

static wyrelog_error_t
count_principal (const wyl_service_principal_t *principal, gpointer user_data)
{
  guint *count = user_data;
  g_assert_nonnull (principal->subject_id);
  (*count)++;
  return WYRELOG_E_OK;
}

static void
test_create_get_list_disable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  sqlite3 *db = handle_db (handle);
  wyl_service_principal_t principal = { 0 };

  g_assert_cmpint (wyl_service_principal_create (handle, "svc:jobs:worker",
          "jobs worker", "admin.root", "request-create", &principal), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (principal.subject_id, ==, "svc:jobs:worker");
  g_assert_cmpstr (principal.display_name, ==, "jobs worker");
  g_assert_cmpstr (principal.state, ==, "active");
  g_assert_cmpuint (principal.generation, ==, 1);
  g_assert_null (principal.disabled_by);
  wyl_service_principal_clear (&principal);

  g_assert_cmpint (wyl_service_principal_get (handle, "svc:jobs:worker",
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.created_by, ==, "admin.root");
  wyl_service_principal_clear (&principal);
  guint count = 0;
  g_assert_cmpint (wyl_service_principal_foreach (handle, count_principal,
          &count), ==, WYRELOG_E_OK);
  g_assert_cmpuint (count, ==, 1);

  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events "
          "WHERE event='created' AND generation=1;"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events a JOIN audit_intentions i "
          "ON i.audit_id=a.id WHERE a.action='service.principal.create' "
          "AND a.resource_id='svc:jobs:worker' AND a.subject_id='admin.root' "
          "AND a.request_id='request-create' AND i.state='pending';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events WHERE "
          "coalesce(action,'')||coalesce(resource_id,'')||"
          "coalesce(subject_id,'')||coalesce(request_id,'') "
          "LIKE '%jobs worker%';"), ==, 0);

  wyl_service_principal_t failed = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:other",
          "other", "admin.root", "request-create", &failed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (failed.subject_id);
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", "request-create", &failed), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);

  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", "request-disable", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  g_assert_cmpuint (principal.generation, ==, 2);
  g_assert_cmpstr (principal.disabled_by, ==, "admin.root");
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events;"), ==, 2);

  /* A fresh request against an already-disabled principal is a committed
   * no-op attempt: ledger + audit/outbox advance, lifecycle events do not. */
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", "request-disable-noop", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpuint (principal.generation, ==, 2);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events;"), ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_domain_requests;"), ==, 3);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events;"), ==, 3);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_intentions WHERE state='pending';"), ==,
      3);
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", "request-disable-noop", &failed), ==, WYRELOG_E_POLICY);
}

static void
test_collision_classes (void)
{
  static const gchar *const fixtures[] = {
    "INSERT INTO principal_states VALUES('svc:collision','unverified',1,0,NULL);",
    "INSERT INTO principal_events(subject_id,event,from_state,to_state,created_at) VALUES('svc:collision','login_ok','unverified','mfa_required',1);",
    "INSERT INTO totp_enrollments VALUES('svc:collision',zeroblob(20),0,1,'id');",
    "INSERT INTO wyrelog_config VALUES('bootstrap_admin_subject','svc:collision',1);",
    "INSERT INTO session_states VALUES('svc:collision','active',1);",
    "INSERT INTO session_events(session_id,event,from_state,to_state,created_at) VALUES('svc:collision','request','idle','active',1);",
    "INSERT INTO permission_states VALUES('svc:collision','app.read','tenant-a','armed',1);",
    "INSERT INTO permission_state_events(subject_id,perm_id,scope,event,from_state,to_state,created_at) VALUES('svc:collision','app.read','tenant-a','grant','dormant','armed',1);",
    "INSERT INTO role_memberships(subject_id,role_id,scope,granted_at) VALUES('svc:collision','app.reader','tenant-a',1);",
    "INSERT INTO role_membership_events(subject_id,role_id,scope,operation,created_at) VALUES('svc:collision','app.reader','tenant-a','revoke',1);",
    "INSERT INTO direct_permissions VALUES('svc:collision','app.read','tenant-a',1);",
    "INSERT INTO direct_permission_events(subject_id,perm_id,scope,operation,created_at) VALUES('svc:collision','app.read','tenant-a','revoke',1);",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (fixtures); i++) {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    sqlite3 *db = handle_db (handle);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    g_assert_cmpint (wyl_policy_store_upsert_role (store, "app.reader",
            "reader"), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_upsert_permission (store, "app.read",
            "read", "basic"), ==, WYRELOG_E_OK);
    exec_ok (db, fixtures[i]);
    wyl_service_principal_t principal = { 0 };
    g_autofree gchar *request = g_strdup_printf ("collision-%u", (guint) i);
    g_assert_cmpint (wyl_service_principal_create (handle, "svc:collision",
            "collision", "admin", request, &principal), ==, WYRELOG_E_POLICY);
    g_assert_null (principal.subject_id);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principals;"), ==, 0);
  }
}

static void
test_owned_output_contract (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);

  /* First use is zero-initialized. A populated result can then be reused
   * directly by a matching API without an explicit clear. */
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:output-contract", "output contract", "admin",
          "output-contract-create", &principal), ==, WYRELOG_E_OK);
  g_assert_nonnull (principal.subject_id);
  g_assert_cmpint (wyl_service_principal_get (handle,
          "svc:output-contract", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.display_name, ==, "output contract");

  /* Every failure clears a previously populated output. */
  g_assert_cmpint (wyl_service_principal_get (handle, "human-subject",
          &principal), ==, WYRELOG_E_INVALID);
  g_assert_null (principal.subject_id);
  g_assert_null (principal.display_name);
  g_assert_null (principal.state);
  g_assert_null (principal.created_by);
  g_assert_null (principal.disabled_by);
  g_assert_cmpuint (principal.generation, ==, 0);
}

typedef struct
{
  WylHandle *handle;
  const gchar *subject_id;
  const gchar *request_id;
  wyrelog_error_t rc;
} CreateThread;

static gpointer
create_thread (gpointer data)
{
  CreateThread *thread = data;
  wyl_service_principal_t principal = { 0 };
  thread->rc = wyl_service_principal_create (thread->handle,
      thread->subject_id, thread->subject_id, "admin", thread->request_id,
      &principal);
  wyl_service_principal_clear (&principal);
  return NULL;
}

static void
test_concurrent_request_claim (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  CreateThread a = { handle, "svc:concurrent:a", "concurrent-request", -1 };
  CreateThread b = { handle, "svc:concurrent:b", "concurrent-request", -1 };
  GThread *ta = g_thread_new ("principal-a", create_thread, &a);
  GThread *tb = g_thread_new ("principal-b", create_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);
  g_assert_true ((a.rc == WYRELOG_E_OK && b.rc == WYRELOG_E_POLICY)
      || (a.rc == WYRELOG_E_POLICY && b.rc == WYRELOG_E_OK));
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_principals;"), ==, 1);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);
}

typedef struct
{
  WylHandle *handle;
  const gchar *request_id;
  wyrelog_error_t rc;
} DisableThread;

static gpointer
disable_thread (gpointer data)
{
  DisableThread *thread = data;
  wyl_service_principal_t principal = { 0 };
  thread->rc = wyl_service_principal_disable (thread->handle,
      "svc:concurrent:disable", "admin", thread->request_id, &principal);
  wyl_service_principal_clear (&principal);
  return NULL;
}

static void
test_concurrent_disable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:concurrent:disable", "concurrent disable", "admin",
          "concurrent-disable-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);

  DisableThread a = { handle, "concurrent-disable-a", -1 };
  DisableThread b = { handle, "concurrent-disable-b", -1 };
  GThread *ta = g_thread_new ("disable-a", disable_thread, &a);
  GThread *tb = g_thread_new ("disable-b", disable_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);

  g_assert_cmpint (a.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (b.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_principal_get (handle,
          "svc:concurrent:disable", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  g_assert_cmpuint (principal.generation, ==, 2);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_principal_events;"), ==, 2);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_domain_requests;"), ==, 3);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM audit_events;"), ==, 3);
}

static void
test_local_failure_rolls_back (void)
{
  static const gchar *const targets[] = {
    "service_principal_events", "audit_events", "audit_intentions",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (targets); i++) {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    sqlite3 *db = handle_db (handle);
    g_autofree gchar *trigger =
        g_strdup_printf ("CREATE TRIGGER fail_local BEFORE INSERT ON %s "
        "BEGIN SELECT RAISE(ABORT,'fault'); END;", targets[i]);
    exec_ok (db, trigger);
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle, "svc:fault",
            "fault", "admin", "fault-request", &principal), !=, WYRELOG_E_OK);
    g_assert_null (principal.subject_id);
    exec_ok (db, "DROP TRIGGER fail_local;");
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principals;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principal_events;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM audit_events;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM audit_intentions;"), ==, 0);
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    sqlite3 *db = handle_db (handle);
    exec_ok (db,
        "CREATE TRIGGER validation_fault AFTER INSERT "
        "ON service_domain_requests BEGIN SELECT 1; END;");
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle,
            "svc:validation-fault", "fault", "admin", "validation-fault",
            &principal), ==, WYRELOG_E_POLICY);
    exec_ok (db, "DROP TRIGGER validation_fault;");
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principals;"), ==, 0);
  }
  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    wyl_policy_store_service_lifecycle_fail_commit_once (store);
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle,
            "svc:commit-fault", "fault", "admin", "commit-fault",
            &principal), ==, WYRELOG_E_IO);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM service_principals;"), ==, 0);
  }
}

static void
test_restart_replay_and_overflow (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-principal-domain-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_t principal = { 0 };
  g_assert_cmpint (wyl_policy_store_create_service_principal (store,
          "svc:restart", "restart", "admin", "restart-request", &principal),
      ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_clear (&principal);
  wyl_policy_store_close (store);

  store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_disable_service_principal (store,
          "svc:restart", "admin", "restart-request", &principal), ==,
      WYRELOG_E_POLICY);
  g_assert_null (principal.subject_id);

  exec_ok (wyl_policy_store_get_db (store),
      "INSERT INTO service_principals(subject_id,display_name,state,"
      "generation,created_by,created_at_us,updated_at_us) VALUES("
      "'svc:overflow','overflow','active',9223372036854775807,'admin',1,1);");
  g_assert_cmpint (wyl_policy_store_disable_service_principal (store,
          "svc:overflow", "admin", "overflow-request", &principal), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='overflow-request';"), ==, 0);
  wyl_policy_store_close (store);

  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_ledger_integrity (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  sqlite3 *db = handle_db (handle);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:ledger",
          "ledger", "admin", "ledger-request", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  exec_rejected (db,
      "UPDATE service_domain_requests SET resource_id='svc:other';");
  exec_rejected (db, "DELETE FROM service_domain_requests;");
  exec_ok (db, "DROP TRIGGER trg_service_domain_requests_no_delete;");
  g_assert_cmpint (wyl_policy_store_validate_service_schema
      (wyl_handle_get_policy_store (handle)), ==, WYRELOG_E_POLICY);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/auth/service-principal/create-get-list-disable",
      test_create_get_list_disable);
  g_test_add_func ("/auth/service-principal/owned-output-contract",
      test_owned_output_contract);
  g_test_add_func ("/auth/service-principal/collision-classes",
      test_collision_classes);
  g_test_add_func ("/auth/service-principal/concurrent-request",
      test_concurrent_request_claim);
  g_test_add_func ("/auth/service-principal/concurrent-disable",
      test_concurrent_disable);
  g_test_add_func ("/auth/service-principal/local-failure-rollback",
      test_local_failure_rolls_back);
  g_test_add_func ("/auth/service-principal/ledger-integrity",
      test_ledger_integrity);
  g_test_add_func ("/auth/service-principal/restart-replay-overflow",
      test_restart_replay_and_overflow);
  return g_test_run ();
}

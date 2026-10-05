/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * `wyctl tenant assign-owner` (#1338): the offline remedy for a predecessor
 * store whose tenant-owner migration fails closed.  Each case lays down a
 * store as it was before tenants recorded an owner, then drives the real
 * wyctl binary against it as a subprocess.
 */
#include "test-exit-status.h"
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH is required"
#endif

static void
exec_sql_ok (sqlite3 *db, const gchar *sql)
{
  gchar *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite error: %s", message != NULL ? message : "?");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

/* A current store, stripped back to the predecessor shape: no owner column
 * and no owner guards.  `acme' has a creator grant; `orphan' and `spare'
 * have none, so a plain open of this store fails closed. */
static gchar *
create_predecessor_store (const gchar *dir)
{
  gchar *path = g_build_filename (dir, "policy.sqlite", NULL);
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
        WYRELOG_E_OK);
  }
  sqlite3 *db = NULL;
  g_assert_cmpint (sqlite3_open (path, &db), ==, SQLITE_OK);
  exec_sql_ok (db,
      "DROP TRIGGER tenant_owner_insert_guard;"
      "DROP TRIGGER tenant_owner_update_guard;"
      "ALTER TABLE tenants DROP COLUMN owner_subject_id;"
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) VALUES"
      " ('acme',0,1,1),('orphan',0,1,1),('spare',0,1,1);"
      "INSERT INTO role_membership_events"
      " (subject_id,role_id,scope,operation,created_at)"
      " VALUES ('alice','wr.system_admin','acme','grant',1);");
  sqlite3_close (db);
  return path;
}

static gint
run_wyctl (const gchar *const *args, gchar **out_stdout, gchar **out_stderr)
{
  g_autoptr (GPtrArray) argv = g_ptr_array_new ();
  g_ptr_array_add (argv, (gpointer) WYL_TEST_WYCTL_PATH);
  for (gsize i = 0; args[i] != NULL; i++)
    g_ptr_array_add (argv, (gpointer) args[i]);
  g_ptr_array_add (argv, NULL);
  gint wait_status = 0;
  g_autoptr (GError) error = NULL;
  g_assert_true (g_spawn_sync (NULL, (gchar **) argv->pdata, NULL,
      G_SPAWN_DEFAULT, NULL, NULL, out_stdout, out_stderr, &wait_status,
      &error));
  g_assert_no_error (error);
  g_autoptr (GError) status_error = NULL;
  if (g_spawn_check_wait_status (wait_status, &status_error))
    return 0;
  return g_error_matches (status_error, G_SPAWN_EXIT_ERROR,
             status_error->code) ? status_error->code : -1;
}

static gchar *
owner_of (const gchar *store_path, const gchar *tenant_id)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (store_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  WylPolicyTenantAuthorityRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (store, tenant_id,
      &record), ==, WYRELOG_E_OK);
  gchar *owner = g_strdup (record->owner_subject_id);
  wyl_policy_tenant_authority_record_free (record);
  return owner;
}

static void
test_assign_owner_repairs_unresolvable_store (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-tenant-owner-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *store = create_predecessor_store (dir);

  /* Without the remedy the store cannot be opened, and wyctl says which
   * tenants are in the way. */
  {
    g_autoptr (wyl_policy_store_t) plain = NULL;
    g_assert_cmpint (wyl_policy_store_open (store, &plain), ==, WYRELOG_E_OK);
    g_test_expect_message (NULL, G_LOG_LEVEL_WARNING, "*orphan*");
    g_test_expect_message (NULL, G_LOG_LEVEL_WARNING, "*spare*");
    g_assert_cmpint (wyl_policy_store_create_schema (plain), ==,
        WYRELOG_E_POLICY);
    g_test_assert_expected_messages ();
  }

  /* An assignment that leaves a tenant unresolved changes nothing. */
  g_autofree gchar *partial_out = NULL;
  g_autofree gchar *partial_err = NULL;
  const gchar *partial[] = {
    "tenant", "assign-owner", "--store", store, "--assign", "orphan=bob",
    NULL,
  };
  g_assert_cmpint (run_wyctl (partial, &partial_out, &partial_err), ==, 1);
  g_assert_nonnull (strstr (partial_err, "spare"));
  g_assert_nonnull (strstr (partial_err, "tenant owner migration failed"));

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  const gchar *full[] = {
    "tenant", "assign-owner", "--store", store,
    "--assign", "orphan=bob", "--assign", "spare=carol", NULL,
  };
  g_assert_cmpint (run_wyctl (full, &out, &err), ==, 0);
  g_assert_nonnull (strstr (out, "tenant=orphan owner=bob assigned=yes\n"));
  g_assert_nonnull (strstr (out, "tenant=spare owner=carol assigned=yes\n"));

  g_autofree gchar *orphan = owner_of (store, "orphan");
  g_autofree gchar *spare = owner_of (store, "spare");
  g_autofree gchar *acme = owner_of (store, "acme");
  g_assert_cmpstr (orphan, ==, "bob");
  g_assert_cmpstr (spare, ==, "carol");
  g_assert_cmpstr (acme, ==, "alice");

  /* Once owned, a tenant is never reassigned: the request is reported and
   * fails the command rather than being dropped silently. */
  g_autofree gchar *again_out = NULL;
  g_autofree gchar *again_err = NULL;
  const gchar *again[] = {
    "tenant", "assign-owner", "--store", store,
    "--assign", "acme=mallory", "--assign", "ghost=bob", NULL,
  };
  g_assert_cmpint (run_wyctl (again, &again_out, &again_err), ==, 1);
  g_assert_nonnull (strstr (again_out,
      "tenant=acme owner=alice assigned=no reason=already_owned\n"));
  g_assert_nonnull (strstr (again_out,
      "tenant=ghost assigned=no reason=unknown_tenant\n"));
  g_autofree gchar *kept = owner_of (store, "acme");
  g_assert_cmpstr (kept, ==, "alice");

  g_unlink (store);
  g_rmdir (dir);
}

static void
test_assign_owner_rejects_invalid_requests (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-tenant-owner-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *store = create_predecessor_store (dir);
  const gchar *invalid[][2] = {
    {"orphan", NULL},             /* no '=' */
    {"=bob", NULL},
    {"orphan=", NULL},
    {"orphan=wr.system", NULL},
    {"orphan=svc:app", NULL},
    {"__wr_default=bob", NULL},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;
    const gchar *args[] = {
      "tenant", "assign-owner", "--store", store, "--assign", invalid[i][0],
      NULL,
    };
    g_test_message ("--assign %s", invalid[i][0]);
    g_assert_cmpint (run_wyctl (args, &out, &err), ==, 2);
  }
  g_autofree gchar *dup_out = NULL;
  g_autofree gchar *dup_err = NULL;
  const gchar *duplicate[] = {
    "tenant", "assign-owner", "--store", store,
    "--assign", "orphan=bob", "--assign", "orphan=carol", NULL,
  };
  g_assert_cmpint (run_wyctl (duplicate, &dup_out, &dup_err), ==, 2);
  const gchar *missing[] = { "tenant", "assign-owner", "--store", store, NULL };
  g_autofree gchar *missing_out = NULL;
  g_autofree gchar *missing_err = NULL;
  g_assert_cmpint (run_wyctl (missing, &missing_out, &missing_err), ==, 2);

  /* None of the refused requests touched the store. */
  sqlite3 *db = NULL;
  g_assert_cmpint (sqlite3_open (store, &db), ==, SQLITE_OK);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "SELECT count(*) FROM pragma_table_info('tenants') "
      "WHERE name='owner_subject_id';", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int (stmt, 0), ==, 0);
  sqlite3_finalize (stmt);
  sqlite3_close (db);
  g_unlink (store);
  g_rmdir (dir);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/tenant/assign-owner/repairs-unresolvable-store",
      test_assign_owner_repairs_unresolvable_store);
  g_test_add_func ("/wyctl/tenant/assign-owner/rejects-invalid-requests",
      test_assign_owner_rejects_invalid_requests);
  return wyl_test_normalize_exit_status (g_test_run ());
}

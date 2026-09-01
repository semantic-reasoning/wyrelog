/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "audit/conn-duckdb-config-test-seams-private.h"
#include "audit/conn-private.h"

static gchar *
temporary_path (const gchar *leaf, gchar **out_dir)
{
  g_autoptr (GError) error = NULL;
  *out_dir = g_dir_make_tmp ("wyl-audit-duckdb-hardening-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (*out_dir);
  return g_build_filename (*out_dir, leaf, NULL);
}

static void
remove_path_and_dir (const gchar *path, const gchar *dir)
{
  if (path != NULL)
    g_remove (path);
  if (dir != NULL)
    g_rmdir (dir);
}

static WylAuditDuckdbConfigSnapshot
snapshot (void)
{
  WylAuditDuckdbConfigSnapshot value = { 0 };
  wyl_audit_conn_duckdb_config_snapshot_for_test (&value);
  return value;
}

static void
assert_delta (WylAuditDuckdbConfigSnapshot before,
    WylAuditDuckdbConfigSnapshot after, guint creations, guint destroys,
    guint opens)
{
  g_assert_cmpuint (after.config_creations - before.config_creations, ==,
      creations);
  g_assert_cmpuint (after.config_destroys - before.config_destroys, ==,
      destroys);
  g_assert_cmpuint (after.open_attempts - before.open_attempts, ==, opens);
}

static void
assert_hardened_settings (wyl_audit_conn_t *conn)
{
  static const struct
  {
    const gchar *name;
    const gchar *value;
  } expected[] = {
    { "allow_community_extensions", "false" },
    { "autoinstall_known_extensions", "false" },
    { "autoload_known_extensions", "false" },
    { "enable_external_access", "false" },
    { "threads", "1" },
  };
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_audit_conn_get_connection (conn),
      "SELECT name, value FROM duckdb_settings() WHERE name IN ("
      "'allow_community_extensions', 'autoinstall_known_extensions', "
      "'autoload_known_extensions', 'enable_external_access', 'threads') "
      "ORDER BY name;", &result), ==, DuckDBSuccess);
  g_assert_cmpuint (duckdb_row_count (&result), ==, G_N_ELEMENTS (expected));
  for (gsize row = 0; row < G_N_ELEMENTS (expected); row++) {
    gchar *name = duckdb_value_varchar (&result, 0, row);
    gchar *value = duckdb_value_varchar (&result, 1, row);
    g_assert_cmpstr (name, ==, expected[row].name);
    g_assert_cmpstr (value, ==, expected[row].value);
    duckdb_free (name);
    duckdb_free (value);
  }
  duckdb_destroy_result (&result);
}

static void
test_effective_settings (void)
{
  wyl_audit_conn_t *conn = NULL;
  g_assert_cmpint (wyl_audit_conn_open (NULL, &conn), ==, WYRELOG_E_OK);
  assert_hardened_settings (conn);
  wyl_audit_conn_close (conn);

  conn = NULL;
  g_assert_cmpint (wyl_audit_conn_open (":memory:", &conn), ==,
      WYRELOG_E_OK);
  assert_hardened_settings (conn);
  wyl_audit_conn_close (conn);

  g_autofree gchar *dir = NULL;
  g_autofree gchar *path = temporary_path ("audit.duckdb", &dir);
  conn = NULL;
  g_assert_cmpint (wyl_audit_conn_open (path, &conn), ==, WYRELOG_E_OK);
  assert_hardened_settings (conn);
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_audit_conn_get_connection (conn),
      "CREATE TABLE durable(value INTEGER);", &result), ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
  wyl_audit_conn_close (conn);

  conn = NULL;
  g_assert_cmpint (wyl_audit_conn_open (path, &conn), ==, WYRELOG_E_OK);
  assert_hardened_settings (conn);
  wyl_audit_conn_close (conn);
  remove_path_and_dir (path, dir);
}

static void
assert_failure_and_retry (WylAuditDuckdbConfigOperation operation,
    guint expected_creations, guint expected_destroys)
{
  g_autofree gchar *dir = NULL;
  g_autofree gchar *path = temporary_path ("failed.duckdb", &dir);
  wyl_audit_conn_t *conn = (wyl_audit_conn_t *) (gpointer) 0x1;
  WylAuditDuckdbConfigSnapshot before = snapshot ();
  wyl_audit_conn_duckdb_config_fail_once_for_test (operation);
  g_assert_cmpint (wyl_audit_conn_open (path, &conn), ==, WYRELOG_E_IO);
  g_assert_null (conn);
  g_assert_false (g_file_test (path, G_FILE_TEST_EXISTS));
  assert_delta (before, snapshot (), expected_creations, expected_destroys, 0);

  before = snapshot ();
  g_assert_cmpint (wyl_audit_conn_open (path, &conn), ==, WYRELOG_E_OK);
  g_assert_nonnull (conn);
  assert_hardened_settings (conn);
  wyl_audit_conn_close (conn);
  assert_delta (before, snapshot (), 1, 1, 1);
  remove_path_and_dir (path, dir);
}

static void
test_config_create_failure (void)
{
  assert_failure_and_retry (WYL_AUDIT_DUCKDB_CONFIG_CREATE, 0, 0);
}

static void
test_setting_failures (void)
{
  const WylAuditDuckdbConfigOperation operations[] = {
    WYL_AUDIT_DUCKDB_CONFIG_THREADS,
    WYL_AUDIT_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS,
    WYL_AUDIT_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS,
    WYL_AUDIT_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS,
    WYL_AUDIT_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (operations); i++)
    assert_failure_and_retry (operations[i], 1, 1);
}

static void
test_bad_path_cleanup (void)
{
  g_autofree gchar *dir = NULL;
  g_autofree gchar *leaf = temporary_path ("unused", &dir);
  g_autofree gchar *missing = g_build_filename (dir, "missing", NULL);
  g_autofree gchar *path = g_build_filename (missing, "audit.duckdb", NULL);
  wyl_audit_conn_t *conn = (wyl_audit_conn_t *) (gpointer) 0x1;
  WylAuditDuckdbConfigSnapshot before = snapshot ();
  g_assert_cmpint (wyl_audit_conn_open (path, &conn), ==, WYRELOG_E_IO);
  g_assert_null (conn);
  g_assert_false (g_file_test (missing, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (path, G_FILE_TEST_EXISTS));
  assert_delta (before, snapshot (), 1, 1, 1);
  remove_path_and_dir (leaf, dir);
}

typedef struct
{
  wyrelog_error_t rc;
  wyl_audit_conn_t *conn;
} OpenThread;

static gpointer
open_in_thread (gpointer data)
{
  OpenThread *thread = data;
  thread->conn = (wyl_audit_conn_t *) (gpointer) 0x1;
  thread->rc = wyl_audit_conn_open (NULL, &thread->conn);
  return NULL;
}

static void
test_failure_is_consumed_once (void)
{
  OpenThread opens[2] = { 0 };
  GThread *threads[2];
  WylAuditDuckdbConfigSnapshot before = snapshot ();
  wyl_audit_conn_duckdb_config_fail_once_for_test (
    WYL_AUDIT_DUCKDB_CONFIG_THREADS);
  for (gsize i = 0; i < G_N_ELEMENTS (threads); i++)
    threads[i] = g_thread_new ("audit-open", open_in_thread, &opens[i]);
  for (gsize i = 0; i < G_N_ELEMENTS (threads); i++)
    g_thread_join (threads[i]);

  guint successes = 0;
  guint failures = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (opens); i++) {
    if (opens[i].rc == WYRELOG_E_OK && opens[i].conn != NULL)
      successes++;
    if (opens[i].rc == WYRELOG_E_IO && opens[i].conn == NULL)
      failures++;
    wyl_audit_conn_close (opens[i].conn);
  }
  g_assert_cmpuint (successes, ==, 1);
  g_assert_cmpuint (failures, ==, 1);
  assert_delta (before, snapshot (), 2, 2, 1);
}

static gboolean
create_sqlite_catalog (const gchar *path)
{
  sqlite3 *db = NULL;
  if (sqlite3_open (path, &db) != SQLITE_OK) {
    sqlite3_close (db);
    return FALSE;
  }
  gboolean ok = sqlite3_exec (db,
          "CREATE TABLE foreign_table(value TEXT);"
          "INSERT INTO foreign_table VALUES('sqlite');",
          NULL, NULL, NULL) == SQLITE_OK;
  sqlite3_close (db);
  return ok;
}

static gint
probe_foreign_sqlite (const gchar *path)
{
  wyl_audit_conn_t *conn = (wyl_audit_conn_t *) (gpointer) 0x1;
  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_IO || conn != NULL) {
    wyl_audit_conn_close (conn);
    return 20;
  }
  return 0;
}

static gint
raw_sqlite_positive_control (const gchar *path)
{
  duckdb_config config = NULL;
  duckdb_database db = NULL;
  duckdb_connection conn = NULL;
  duckdb_result result = { 0 };
  gint rc = 30;
  if (duckdb_create_config (&config) != DuckDBSuccess)
    goto out;
  if (duckdb_set_config (config, "autoinstall_known_extensions", "false")
      != DuckDBSuccess)
    goto out;
  if (duckdb_open_ext (path, &db, config, NULL) != DuckDBSuccess)
    goto out;
  if (duckdb_connect (db, &conn) != DuckDBSuccess)
    goto out;
  if (duckdb_query (conn, "SELECT COUNT(*) FROM foreign_table;", &result)
      != DuckDBSuccess)
    goto out;
  if (duckdb_value_int64 (&result, 0, 0) != 1)
    goto out;
  rc = 0;
out:
  duckdb_destroy_result (&result);
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  duckdb_destroy_config (&config);
  return rc;
}

static void
test_foreign_sqlite_is_rejected (void)
{
  g_autofree gchar *dir = NULL;
  g_autofree gchar *path = temporary_path ("foreign.sqlite", &dir);
  g_assert_true (create_sqlite_catalog (path));
  g_assert_cmpint (probe_foreign_sqlite (path), ==, 0);
  remove_path_and_dir (path, dir);
}

int
main (int argc, char **argv)
{
  if (argc == 2 && g_strcmp0 (argv[1], "--duckdb-library-version") == 0) {
    g_print ("%s\n", duckdb_library_version ());
    return 0;
  }
  if (argc == 3 && g_strcmp0 (argv[1], "--foreign-sqlite") == 0)
    return probe_foreign_sqlite (argv[2]);
  if (argc == 3 && g_strcmp0 (argv[1], "--raw-sqlite-positive") == 0)
    return raw_sqlite_positive_control (argv[2]);

  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/audit/duckdb-hardening/effective-settings",
      test_effective_settings);
  g_test_add_func ("/audit/duckdb-hardening/config-create-failure",
      test_config_create_failure);
  g_test_add_func ("/audit/duckdb-hardening/setting-failures",
      test_setting_failures);
  g_test_add_func ("/audit/duckdb-hardening/bad-path-cleanup",
      test_bad_path_cleanup);
  g_test_add_func ("/audit/duckdb-hardening/failure-consumed-once",
      test_failure_is_consumed_once);
  g_test_add_func ("/audit/duckdb-hardening/foreign-sqlite-rejected",
      test_foreign_sqlite_is_rejected);
  return g_test_run ();
}

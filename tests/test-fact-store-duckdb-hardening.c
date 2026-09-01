/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <duckdb.h>
#include <sqlite3.h>

#include "fact/store-duckdb-config-test-seams-private.h"
#include "fact/store-private.h"

static const WylFactStoreIdentity test_identity = {
  .tenant_id = "tenant-a",
  .graph_id = "orders",
  .store_uuid = "01890f47-3c4b-6cc2-b8c4-dc0c0c073989",
  .format_version = 1,
  .path_encoding_version = 1,
};

static gchar *
temporary_path (const gchar *leaf, gchar **out_dir)
{
  g_autoptr (GError) error = NULL;
  *out_dir = g_dir_make_tmp ("wyl-duckdb-hardening-XXXXXX", &error);
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

static void
assert_setting (wyl_fact_store_t *store,
    WylFactStoreDuckdbConfigSetting setting, const gchar *expected)
{
  g_autofree gchar *value = NULL;
  g_assert_cmpint (wyl_fact_store_duckdb_config_get_for_test (store, setting,
      &value), ==, WYRELOG_E_OK);
  g_assert_cmpstr (value, ==, expected);
}

static void
assert_common_settings (wyl_fact_store_t *store)
{
  assert_setting (store, WYL_FACT_STORE_DUCKDB_CONFIG_THREADS, "1");
  assert_setting (store, WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS,
      "false");
  assert_setting (store, WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS,
      "false");
  assert_setting (store, WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS,
      "false");
  assert_setting (store, WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS,
      "false");
}

static void
test_effective_settings (void)
{
  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (wyl_fact_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_nonnull (store);
  assert_common_settings (store);
  wyl_fact_store_close (store);

  store = NULL;
  g_assert_cmpint (wyl_fact_store_open (":memory:", &store), ==,
      WYRELOG_E_OK);
  assert_common_settings (store);
  wyl_fact_store_close (store);

  g_autofree gchar *dir = NULL;
  g_autofree gchar *path = temporary_path ("facts.duckdb", &dir);
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  store = NULL;
  g_assert_cmpint (wyl_fact_store_open_identified (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  assert_common_settings (store);
  wyl_fact_store_close (store);

  store = NULL;
  result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  g_assert_cmpint (wyl_fact_store_open_identified (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result, &store), ==,
      WYRELOG_E_OK);
  assert_common_settings (store);
  g_autofree gchar *access_mode = NULL;
  g_assert_cmpint (wyl_fact_store_duckdb_config_get_for_test (store,
      WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE, &access_mode), ==,
      WYRELOG_E_OK);
  g_assert_true (g_ascii_strcasecmp (access_mode, "read_only") == 0);
  wyl_fact_store_close (store);
  remove_path_and_dir (path, dir);
}

static void
test_generic_setting_failures (void)
{
  const WylFactStoreDuckdbConfigSetting settings[] = {
    WYL_FACT_STORE_DUCKDB_CONFIG_THREADS,
    WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS,
    WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS,
    WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS,
    WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (settings); i++) {
    g_autofree gchar *dir = NULL;
    g_autofree gchar *path = temporary_path ("failed.duckdb", &dir);
    wyl_fact_store_t *store = (wyl_fact_store_t *) 0x1;
    wyl_fact_store_duckdb_config_fail_once_for_test (settings[i]);
    g_assert_cmpint (wyl_fact_store_open (path, &store), ==, WYRELOG_E_IO);
    g_assert_null (store);
    g_assert_false (g_file_test (path, G_FILE_TEST_EXISTS));

    g_assert_cmpint (wyl_fact_store_open (path, &store), ==, WYRELOG_E_OK);
    g_assert_nonnull (store);
    wyl_fact_store_close (store);
    remove_path_and_dir (path, dir);
  }
}

static void
test_identified_setting_failures (void)
{
  const WylFactStoreDuckdbConfigSetting settings[] = {
    WYL_FACT_STORE_DUCKDB_CONFIG_THREADS,
    WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS,
    WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS,
    WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS,
    WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS,
    WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (settings); i++) {
    g_autofree gchar *dir = NULL;
    g_autofree gchar *path = temporary_path ("failed.duckdb", &dir);
    wyl_fact_store_t *store = (wyl_fact_store_t *) 0x1;
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    WylFactStoreIdentityOpenMode mode = settings[i]
        == WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE
        ? WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY
        : WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY;
    GStatBuf before = { 0 };
    if (settings[i] == WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE) {
      store = NULL;
      g_assert_cmpint (wyl_fact_store_open_identified (path, &test_identity,
          WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result, &store),
          ==, WYRELOG_E_OK);
      wyl_fact_store_close (store);
      store = (wyl_fact_store_t *) 0x1;
      g_assert_cmpint (g_stat (path, &before), ==, 0);
    }
    wyl_fact_store_duckdb_config_fail_once_for_test (settings[i]);
    g_assert_cmpint (wyl_fact_store_open_identified (path, &test_identity,
        mode, &result, &store), ==, WYRELOG_E_IO);
    g_assert_null (store);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_OPEN);
    if (settings[i] == WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE) {
      GStatBuf after = { 0 };
      g_assert_cmpint (g_stat (path, &after), ==, 0);
      g_assert_cmpint (after.st_size, ==, before.st_size);
      g_assert_cmpint (after.st_mtime, ==, before.st_mtime);
    } else {
      g_assert_false (g_file_test (path, G_FILE_TEST_EXISTS));
    }

    result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified (path, &test_identity,
        mode, &result, &store), ==,
        WYRELOG_E_OK);
    g_assert_nonnull (store);
    wyl_fact_store_close (store);
    remove_path_and_dir (path, dir);
  }
}

typedef struct
{
  wyrelog_error_t rc;
  wyl_fact_store_t *store;
} OpenThread;

static gpointer
open_in_thread (gpointer data)
{
  OpenThread *thread = data;
  thread->store = (wyl_fact_store_t *) 0x1;
  thread->rc = wyl_fact_store_open (NULL, &thread->store);
  return NULL;
}

static void
test_failure_is_consumed_once (void)
{
  OpenThread opens[2] = { 0 };
  GThread *threads[2];
  wyl_fact_store_duckdb_config_fail_once_for_test (
    WYL_FACT_STORE_DUCKDB_CONFIG_THREADS);
  for (gsize i = 0; i < G_N_ELEMENTS (threads); i++)
    threads[i] = g_thread_new ("fact-open", open_in_thread, &opens[i]);
  for (gsize i = 0; i < G_N_ELEMENTS (threads); i++)
    g_thread_join (threads[i]);

  guint successes = 0;
  guint failures = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (opens); i++) {
    if (opens[i].rc == WYRELOG_E_OK && opens[i].store != NULL)
      successes++;
    if (opens[i].rc == WYRELOG_E_IO && opens[i].store == NULL)
      failures++;
    wyl_fact_store_close (opens[i].store);
  }
  g_assert_cmpuint (successes, ==, 1);
  g_assert_cmpuint (failures, ==, 1);
}

static gboolean
create_sqlite_catalog (const gchar *path, gboolean policy_catalog)
{
  sqlite3 *db = NULL;
  if (sqlite3_open (path, &db) != SQLITE_OK) {
    sqlite3_close (db);
    return FALSE;
  }
  const gchar *schema = policy_catalog
      ? "CREATE TABLE policy_signatures(signature_id TEXT PRIMARY KEY);"
      : "CREATE TABLE foreign_table(value TEXT);"
      "INSERT INTO foreign_table VALUES('sqlite');";
  gboolean ok = sqlite3_exec (db, schema,
          NULL, NULL, NULL) == SQLITE_OK;
  sqlite3_close (db);
  return ok;
}

static gint
probe_foreign_sqlite (const gchar *path)
{
  wyl_fact_store_t *store = (wyl_fact_store_t *) 0x1;
  if (wyl_fact_store_open (path, &store) != WYRELOG_E_IO || store != NULL) {
    wyl_fact_store_close (store);
    return 20;
  }

  store = (wyl_fact_store_t *) 0x1;
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  if (wyl_fact_store_open_identified (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result, &store)
      != WYRELOG_E_IO || store != NULL
      || result != WYL_FACT_STORE_IDENTITY_RESULT_OPEN) {
    wyl_fact_store_close (store);
    return 21;
  }

  store = (wyl_fact_store_t *) 0x1;
  result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  if (wyl_fact_store_open_identified (path, &test_identity,
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result, &store)
      != WYRELOG_E_IO || store != NULL
      || result != WYL_FACT_STORE_IDENTITY_RESULT_OPEN) {
    wyl_fact_store_close (store);
    return 22;
  }
  return 0;
}

static gint
raw_sqlite_positive_control (const gchar *path)
{
  duckdb_database db = NULL;
  duckdb_config config = NULL;
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
  g_assert_true (create_sqlite_catalog (path, FALSE));
  g_assert_cmpint (probe_foreign_sqlite (path), ==, 0);
  g_remove (path);
  g_assert_true (create_sqlite_catalog (path, TRUE));
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
  g_test_add_func ("/fact-store/duckdb-hardening/effective-settings",
      test_effective_settings);
  g_test_add_func ("/fact-store/duckdb-hardening/generic-setting-failures",
      test_generic_setting_failures);
  g_test_add_func ("/fact-store/duckdb-hardening/identified-setting-failures",
      test_identified_setting_failures);
  g_test_add_func ("/fact-store/duckdb-hardening/failure-consumed-once",
      test_failure_is_consumed_once);
  g_test_add_func ("/fact-store/duckdb-hardening/foreign-sqlite-rejected",
      test_foreign_sqlite_is_rejected);
  return g_test_run ();
}

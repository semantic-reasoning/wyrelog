/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <string.h>
#ifndef G_OS_WIN32
#include <sys/wait.h>
#endif

#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH is required"
#endif

static gint
run_command (gchar **argv, gchar **out, gchar **err)
{
  g_autoptr (GError) error = NULL;
  gint status = 0;
  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
          out, err, &status, &error));
  g_assert_no_error (error);
#ifdef G_OS_WIN32
  return status;
#else
  return WIFEXITED (status) ? WEXITSTATUS (status) : -1;
#endif
}

static wyrelog_error_t
open_encrypted (const gchar *store_path, const gchar *key_path,
    WylPolicyStoreOpenMode mode, wyl_policy_store_t **out)
{
  wyl_keyprovider_file_t *provider = wyl_keyprovider_file_new (key_path);
  g_assert_nonnull (provider);
  wyl_policy_store_open_options_t options = {
    .path = store_path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = provider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
    .mode = mode,
  };
  return wyl_policy_store_open_with_options (&options, out);
}

static void
test_offline_closure_commands (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-closure-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *store_path = g_build_filename (dir, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (dir, "policy.key", NULL);
  g_autofree gchar *key_spec = g_strdup_printf ("file:%s", key_path);
  g_autofree gchar *manifest_path =
      g_build_filename (dir, "closure.json", NULL);
  guint8 key[32];
  memset (key, 0x5c, sizeof key);
  g_assert_true (g_file_set_contents (key_path, (const gchar *) key,
          sizeof key, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (key_path, 0600), ==, 0);

  wyl_policy_store_t *seed = NULL;
  g_assert_cmpint (open_encrypted (store_path, key_path,
          WYL_POLICY_STORE_OPEN_ATTACHED, &seed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (seed), ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_t principal = { 0 };
  g_assert_cmpint (wyl_policy_store_create_service_principal (seed,
          "svc:cli-closure", "cli closure", "admin", "seed-cli-closure",
          &principal), ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_clear (&principal);
  g_assert_cmpint (wyl_policy_store_upsert_permission (seed, "site.unsafe",
          "unsafe", "basic"), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (seed),
          "INSERT INTO direct_permissions(subject_id,perm_id,scope)"
          " VALUES('svc:cli-closure','site.unsafe','scope');",
          NULL, NULL, NULL), ==, SQLITE_OK);
  wyl_policy_store_close (seed);

  gchar *inspect_argv[] = {
    WYL_TEST_WYCTL_PATH, "service-permission-closure", "inspect",
    "--store", store_path, "--keyprovider", key_spec,
    "--output", manifest_path, NULL
  };
  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  wyl_policy_store_t *attached = NULL;
  g_assert_cmpint (open_encrypted (store_path, key_path,
          WYL_POLICY_STORE_OPEN_ATTACHED, &attached), ==, WYRELOG_E_OK);
  g_assert_cmpint (run_command (inspect_argv, &out, &err), ==, 1);
  g_assert_nonnull (strstr (err, "busy"));
  g_assert_false (g_file_test (manifest_path, G_FILE_TEST_EXISTS));
  wyl_policy_store_close (attached);
  g_clear_pointer (&out, g_free);
  g_clear_pointer (&err, g_free);
  g_assert_cmpint (run_command (inspect_argv, &out, &err), ==, 0);
  g_assert_nonnull (strstr (out, "status=manifest_created"));
  g_assert_true (g_file_test (manifest_path, G_FILE_TEST_IS_REGULAR));

  gchar *dry_argv[] = {
    WYL_TEST_WYCTL_PATH, "service-permission-closure", "dry-run",
    "--store", store_path, "--keyprovider", key_spec,
    "--manifest", manifest_path, NULL
  };
  g_clear_pointer (&out, g_free);
  g_clear_pointer (&err, g_free);
  g_assert_cmpint (run_command (dry_argv, &out, &err), ==, 0);
  g_assert_nonnull (strstr (out, "status=dry_run_valid"));

  gchar *apply_argv[] = {
    WYL_TEST_WYCTL_PATH, "service-permission-closure", "apply",
    "--store", store_path, "--keyprovider", key_spec,
    "--manifest", manifest_path, NULL
  };
  g_clear_pointer (&out, g_free);
  g_clear_pointer (&err, g_free);
  g_assert_cmpint (run_command (apply_argv, &out, &err), ==, 0);
  g_assert_nonnull (strstr (out, "status=applied"));
  g_clear_pointer (&out, g_free);
  g_clear_pointer (&err, g_free);
  g_assert_cmpint (run_command (apply_argv, &out, &err), ==, 0);
  g_assert_nonnull (strstr (out, "status=replayed"));

  wyl_policy_store_t *verify = NULL;
  g_assert_cmpint (open_encrypted (store_path, key_path,
          WYL_POLICY_STORE_OPEN_ATTACHED, &verify), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (verify), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_validate_service_permission_closure
      (verify), ==, WYRELOG_E_OK);
  wyl_policy_store_close (verify);

  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", store_path);
  g_remove (manifest_path);
  g_remove (store_path);
  g_remove (lock_path);
  g_remove (key_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/service-permission-closure/offline",
      test_offline_closure_commands);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>

#ifndef G_OS_WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-backup-bundle-private.h"
#include "wyrelog/fact/offline-backup-manifest-private.h"

#ifndef G_OS_WIN32
typedef struct
{
  gchar *root;
  gchar *manifest_path;
  gchar *graph_path;
  guint8 digest[32];
} Fixture;

static void
fixture_init (Fixture *fixture)
{
  g_autoptr (GError) error = NULL;
  fixture->root = g_dir_make_tmp ("wyrelog-bundle-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (fixture->root);
  g_autofree gchar *component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode ("orders", &component),
      ==, WYRELOG_E_OK);
  g_autofree gchar *name = g_strdup_printf ("graph-%s.duckdb", component);
  fixture->graph_path = g_build_filename (fixture->root, name, NULL);
  fixture->manifest_path = g_build_filename (fixture->root, "manifest", NULL);
  const gchar *content = "validated-backup-bytes";
  g_assert_true (g_file_set_contents (fixture->graph_path, content, -1,
      &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (fixture->graph_path, 0600), ==, 0);
  g_autofree gchar *hash = g_compute_checksum_for_string (G_CHECKSUM_SHA256,
          content, -1);
  g_autofree gchar *checksum = g_strdup_printf ("sha256:%s", hash);
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init (&manifest,
      "tenant", 7), ==, WYRELOG_E_OK);
  WylFactOfflineBackupArtifact artifact = {
    .graph_id = "orders",
    .store_uuid = "00000000-0000-4000-8000-000000000001",
    .format_version = 1,
    .path_encoding_version = 1,
    .schema_digest = "schema",
    .logical_bytes = strlen (content),
    .physical_bytes = strlen (content),
    .checksum = checksum,
  };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add (&manifest,
      &artifact), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) bytes = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&manifest,
      &bytes), ==, WYRELOG_E_OK);
  gsize length = 0;
  const guint8 *data = g_bytes_get_data (bytes, &length);
  g_assert_true (g_file_set_contents (fixture->manifest_path,
      (const gchar *) data, length, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (fixture->manifest_path, 0600), ==, 0);
  g_autoptr (GChecksum) digest = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (digest, data, length);
  gsize digest_length = sizeof fixture->digest;
  g_checksum_get_digest (digest, fixture->digest, &digest_length);
  g_assert_cmpuint (digest_length, ==, sizeof fixture->digest);
  wyl_fact_offline_backup_manifest_clear (&manifest);
}

static void
fixture_clear (Fixture *fixture)
{
  (void) g_remove (fixture->graph_path);
  (void) g_remove (fixture->manifest_path);
  (void) g_rmdir (fixture->root);
  g_free (fixture->graph_path);
  g_free (fixture->manifest_path);
  g_free (fixture->root);
}

static void
test_open_read_and_revalidate (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) bytes = wyl_fact_offline_backup_bundle_manifest_bytes
        (bundle);
  g_assert_nonnull (bytes);
  guint8 data[64] = { 0 };
  gsize read = 0;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_read_at (bundle, "orders",
      0, data, sizeof data, &read), ==, WYRELOG_E_OK);
  g_assert_cmpuint (read, ==, strlen ("validated-backup-bytes"));
  g_assert_cmpmem (data, read, "validated-backup-bytes", read);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_OK);
  const WylFactOfflineRestoreTenantInput *input =
      wyl_fact_offline_backup_bundle_tenant_input ();
  g_assert_cmpint (input->revalidate (bundle), ==, WYRELOG_E_OK);
  g_assert_cmpint (input->read_at ("orders", 0, data, sizeof data, &read,
      bundle), ==, WYRELOG_E_OK);
  WylFactOfflineBackupGraphView view = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_bundle_graph_view (bundle,
      "orders", &view), ==, WYRELOG_E_OK);
  const WylFactOfflineRestoreInput *graph_input =
      wyl_fact_offline_backup_bundle_graph_input ();
  g_assert_cmpint (graph_input->revalidate (&view), ==, WYRELOG_E_OK);
  g_assert_cmpint (graph_input->read_at (0, data, sizeof data, &read,
      &view), ==, WYRELOG_E_OK);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  fixture_clear (&fixture);
}

static void
test_rejects_untrusted_and_mutated_source (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  guint8 wrong_digest[32] = { 0 };
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      wrong_digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  gint fd = g_open (fixture.graph_path, O_WRONLY, 0);
  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (pwrite (fd, "X", 1,
      strlen ("validated-backup-bytes") - 1), ==, 1);
  g_assert_cmpint (close (fd), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  fixture_clear (&fixture);
}

static void
test_rejects_missing_symlink_hardlink_and_mode (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_autofree gchar *original = g_strconcat (fixture.graph_path,
          ".outside", NULL);
  g_assert_cmpint (g_rename (fixture.graph_path, original), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (symlink (original, fixture.graph_path), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (fixture.graph_path), ==, 0);
  g_assert_cmpint (link (original, fixture.graph_path), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (original), ==, 0);
  g_assert_cmpint (g_chmod (fixture.graph_path, 0644), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  fixture_clear (&fixture);
}

static void
test_rejects_extra_and_replacement (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  g_autofree gchar *extra = g_build_filename (fixture.root, "extra", NULL);
  g_autoptr (GError) error = NULL;
  g_assert_true (g_file_set_contents (extra, "x", 1, &error));
  g_assert_no_error (error);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);
  g_assert_cmpint (g_remove (extra), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  g_autofree gchar *old_dir = g_dir_make_tmp
        ("wyrelog-bundle-old-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *old = g_build_filename (old_dir, "old.duckdb", NULL);
  g_assert_cmpint (g_rename (fixture.graph_path, old), ==, 0);
  g_assert_true (g_file_set_contents (fixture.graph_path,
      "validated-backup-bytes", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (fixture.graph_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  g_assert_cmpint (g_remove (old), ==, 0);
  g_assert_cmpint (g_rmdir (old_dir), ==, 0);
  fixture_clear (&fixture);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact/offline-backup-bundle/open-read-revalidate",
      test_open_read_and_revalidate);
  g_test_add_func ("/fact/offline-backup-bundle/untrusted-mutated",
      test_rejects_untrusted_and_mutated_source);
  g_test_add_func ("/fact/offline-backup-bundle/extra-replacement",
      test_rejects_extra_and_replacement);
  g_test_add_func ("/fact/offline-backup-bundle/missing-alias-mode",
      test_rejects_missing_symlink_hardlink_and_mode);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

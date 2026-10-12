/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "test-exit-status.h"
#include "fact-test-support.h"

#include <glib.h>
#include <glib/gstdio.h>

#ifndef G_OS_WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef G_OS_WIN32
#include <windows.h>
#endif

#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-backup-bundle-private.h"
#include "wyrelog/fact/offline-backup-manifest-private.h"
#include "wyrelog/fact/offline-restore-journal-private.h"

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
  fixture->root = wyl_test_make_secure_fact_root ("wyrelog-bundle-XXXXXX",
          &error);
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

#ifdef G_OS_WIN32
typedef struct
{
  gchar *root;
  gchar *manifest_path;
  gchar *graph_path;
  guint8 digest[32];
} Fixture;

static const gchar *const content = "validated-backup-bytes";

/* The secure root carries inheritable ACEs, so a file written into it is
 * marked INHERITED and fails the reader's protected owner-only check.  Every
 * conforming bundle file therefore goes through wyl_test_secure_regular_file;
 * writing one without it is the cheapest non-conforming DACL. */
static void
write_bundle_file (const gchar *path, const guint8 *data, gsize length,
    gboolean secure)
{
  g_autoptr (GError) error = NULL;
  g_assert_true (g_file_set_contents (path, (const gchar *) data,
      (gssize) length, &error));
  g_assert_no_error (error);
  if (secure) {
    g_assert_true (wyl_test_secure_regular_file (path, &error));
    g_assert_no_error (error);
  }
}

static void
fixture_init (Fixture *fixture)
{
  g_autoptr (GError) error = NULL;
  fixture->root = wyl_test_make_secure_fact_root ("wyrelog-bundle-XXXXXX",
          &error);
  g_assert_no_error (error);
  g_assert_nonnull (fixture->root);
  g_autofree gchar *component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode ("orders", &component),
      ==, WYRELOG_E_OK);
  g_autofree gchar *name = g_strdup_printf ("graph-%s.duckdb", component);
  fixture->graph_path = g_build_filename (fixture->root, name, NULL);
  fixture->manifest_path = g_build_filename (fixture->root, "manifest", NULL);
  write_bundle_file (fixture->graph_path, (const guint8 *) content,
      strlen (content), TRUE);
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
  write_bundle_file (fixture->manifest_path, data, length, TRUE);
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

/* Change one byte in place: same object, same length, different bytes. */
static void
overwrite_byte (const gchar *path, guint64 offset, guint8 value)
{
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  OVERLAPPED overlapped = { 0 };
  DWORD written = 0;
  g_assert_nonnull (wide);
  HANDLE handle = CreateFileW ((LPCWSTR) wide, GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  g_assert_true (handle != INVALID_HANDLE_VALUE);
  overlapped.Offset = (DWORD) (offset & 0xffffffffu);
  overlapped.OffsetHigh = (DWORD) (offset >> 32);
  g_assert_true (WriteFile (handle, &value, 1, &written, &overlapped));
  g_assert_cmpuint (written, ==, 1);
  g_assert_true (FlushFileBuffers (handle));
  g_assert_true (CloseHandle (handle));
}

static void
test_windows_open_read_and_revalidate (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) bytes = wyl_fact_offline_backup_bundle_manifest_bytes
        (bundle);
  g_assert_nonnull (bytes);
  g_assert_cmpmem (wyl_fact_offline_backup_bundle_manifest_sha256 (bundle),
      sizeof fixture.digest, fixture.digest, sizeof fixture.digest);
  guint8 data[64] = { 0 };
  gsize read = 0;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_read_at (bundle, "orders",
      0, data, sizeof data, &read), ==, WYRELOG_E_OK);
  g_assert_cmpuint (read, ==, strlen (content));
  g_assert_cmpmem (data, read, content, read);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_read_at (bundle, "orders",
      strlen (content), data, sizeof data, &read), ==, WYRELOG_E_OK);
  g_assert_cmpuint (read, ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_read_at (bundle, "absent",
      0, data, sizeof data, &read), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_OK);
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
test_windows_rejects_untrusted_and_mutated (void)
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
  overwrite_byte (fixture.graph_path, strlen (content) - 1, 'X');
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);

  /* The manifest is held to the same standard as the artifacts. */
  write_bundle_file (fixture.graph_path, (const guint8 *) content,
      strlen (content), TRUE);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  overwrite_byte (fixture.manifest_path, 0, '#');
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  fixture_clear (&fixture);
}

static void
test_windows_rejects_extra_and_replacement (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  g_autofree gchar *extra = g_build_filename (fixture.root, "extra", NULL);
  write_bundle_file (extra, (const guint8 *) "x", 1, TRUE);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);
  g_assert_cmpint (g_remove (extra), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);

  /* The same bytes under the same name, written over the held object: the
   * held handle sees its object go delete-pending and refuses on its own. */
  write_bundle_file (fixture.graph_path, (const guint8 *) content,
      strlen (content), TRUE);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_POLICY);
  guint8 data[8] = { 0 };
  gsize read = 0;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_read_at (bundle, "orders",
      0, data, sizeof data, &read), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (read, ==, 0);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);

  /* The same bytes under the same name as a different object, with the held
   * object moved out of the way intact: every held-handle proof passes and
   * the entry set looks right, so only the name re-binding's identity compare
   * can tell, and it must. */
  g_autoptr (GError) error = NULL;
  g_autofree gchar *outside_dir = g_dir_make_tmp ("wyrelog-bundle-out-XXXXXX",
          &error);
  g_assert_no_error (error);
  g_autofree gchar *outside = g_build_filename (outside_dir, "held.duckdb",
          NULL);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  g_assert_cmpint (g_rename (fixture.graph_path, outside), ==, 0);
  write_bundle_file (fixture.graph_path, (const guint8 *) content,
      strlen (content), TRUE);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  g_assert_cmpint (g_remove (outside), ==, 0);
  g_assert_cmpint (g_rmdir (outside_dir), ==, 0);
  fixture_clear (&fixture);
}

/* Shrink the file in place: same object, same name, fewer bytes. */
static void
truncate_file (const gchar *path, guint64 length)
{
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  FILE_END_OF_FILE_INFO info = { 0 };
  g_assert_nonnull (wide);
  HANDLE handle = CreateFileW ((LPCWSTR) wide, GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  g_assert_true (handle != INVALID_HANDLE_VALUE);
  info.EndOfFile.QuadPart = (LONGLONG) length;
  g_assert_true (SetFileInformationByHandle (handle, FileEndOfFileInfo, &info,
      sizeof info));
  g_assert_true (CloseHandle (handle));
}

static void
test_windows_rejects_truncation_and_manifest_bounds (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  guint8 data[8] = { 0 };
  gsize read = 0;

  /* The held object is the right one but no longer the proven size. */
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  truncate_file (fixture.graph_path, strlen (content) - 1);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_read_at (bundle, "orders",
      0, data, sizeof data, &read), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (read, ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_revalidate (bundle), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);

  /* An empty manifest and an oversized one are refused before being read. */
  write_bundle_file (fixture.manifest_path, (const guint8 *) "", 0, TRUE);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);
  gsize oversized = WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES + 1;
  g_autofree guint8 *filler = g_malloc0 (oversized);
  write_bundle_file (fixture.manifest_path, filler, oversized, TRUE);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);
  fixture_clear (&fixture);
}

static void
test_windows_rejects_missing_alias_acl_and_link (void)
{
  Fixture fixture = { 0 };
  fixture_init (&fixture);
  g_autoptr (GError) error = NULL;
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_autofree gchar *outside_dir = g_dir_make_tmp ("wyrelog-bundle-out-XXXXXX",
          &error);
  g_assert_no_error (error);
  g_autofree gchar *outside = g_build_filename (outside_dir, "orders.duckdb",
          NULL);
  g_autofree gunichar2 *outside_wide = g_utf8_to_utf16 (outside, -1, NULL,
          NULL, NULL);
  g_autofree gunichar2 *graph_wide = g_utf8_to_utf16 (fixture.graph_path, -1,
          NULL, NULL, NULL);
  g_assert_nonnull (outside_wide);
  g_assert_nonnull (graph_wide);

  /* Absent is absent. */
  g_assert_cmpint (g_rename (fixture.graph_path, outside), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (bundle);

  /* A junction under the artifact's name is never the artifact. */
  g_assert_true (wyl_test_create_directory_alias (fixture.graph_path,
      outside_dir, &error));
  g_assert_no_error (error);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);
  g_assert_true (wyl_test_remove_directory_alias (fixture.graph_path,
      &error));
  g_assert_no_error (error);

  /* A second link, minted from outside the bundle, is a second name for an
   * object the bundle alone must own. */
  g_assert_cmpint (g_rename (outside, fixture.graph_path), ==, 0);
  g_assert_true (CreateHardLinkW ((LPCWSTR) outside_wide,
      (LPCWSTR) graph_wide, NULL));
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);
  g_assert_true (DeleteFileW ((LPCWSTR) outside_wide));
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_OK);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);

  /* An inherited, unprotected DACL is exactly what the contract refuses. */
  write_bundle_file (fixture.graph_path, (const guint8 *) content,
      strlen (content), FALSE);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (fixture.root,
      fixture.digest, &bundle), ==, WYRELOG_E_POLICY);
  g_assert_null (bundle);

  g_assert_cmpint (g_rmdir (outside_dir), ==, 0);
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
#ifdef G_OS_WIN32
  g_test_add_func ("/fact/offline-backup-bundle/windows/open-read-revalidate",
      test_windows_open_read_and_revalidate);
  g_test_add_func ("/fact/offline-backup-bundle/windows/untrusted-mutated",
      test_windows_rejects_untrusted_and_mutated);
  g_test_add_func ("/fact/offline-backup-bundle/windows/extra-replacement",
      test_windows_rejects_extra_and_replacement);
  g_test_add_func ("/fact/offline-backup-bundle/windows/missing-alias-acl-link",
      test_windows_rejects_missing_alias_acl_and_link);
  g_test_add_func ("/fact/offline-backup-bundle/windows/truncation-bounds",
      test_windows_rejects_truncation_and_manifest_bounds);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

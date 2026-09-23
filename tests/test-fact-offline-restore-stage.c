/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _WIN32
/* c_std=c17 is strict ISO C, so glibc hides pwrite() unless a feature-test
 * macro is set before the first system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#ifdef G_OS_WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "fact-test-support.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-restore-stage-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"
#include "wyrelog/wyl-id-private.h"

#define PAYLOAD_CHECKSUM \
  "sha256:d89c09dbdbf32efe0a8d5f3693c6ae897d3a5ba818962db9d8d5dc052f767e2b"

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_tree (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

static gboolean
truncate_file (const gchar *path, guint64 size)
{
#ifdef G_OS_WIN32
  glong units = 0;
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, &units, NULL);
  if (wide == NULL || units <= 0)
    return FALSE;
  HANDLE file = CreateFileW ((LPCWSTR) wide, GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return FALSE;
  LARGE_INTEGER position = { .QuadPart = (LONGLONG) size };
  gboolean result = SetFilePointerEx (file, position, NULL, FILE_BEGIN)
      && SetEndOfFile (file);
  CloseHandle (file);
  return result;
#else
  gint fd = g_open (path, O_WRONLY, 0);
  if (fd < 0)
    return FALSE;
  gboolean result = ftruncate (fd, (off_t) size) == 0;
  close (fd);
  return result;
#endif
}

static void
test_create_write_finalize_and_collision (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-stage-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);

  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactRootWriterLease *lease = NULL;
  WylFactOfflineRestoreStage *stage = NULL;
  WylFactOfflineRestoreStage *collision = NULL;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
      &locator, TRUE, &directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_OK);

  wyl_id_t operation_id;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation_id, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_write (stage, 1,
      (const guint8 *) "ignored", 7), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_offline_restore_stage_write (stage, 0,
      (const guint8 *) "restore payload!", 16), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_offline_restore_stage_write (stage, 0,
      (const guint8 *) "restore payload", 15), ==, WYRELOG_E_OK);
  guint64 bytes_written = 0;
  WylFactArtifactInventoryIdentity identity = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage,
      &bytes_written, &identity), ==, WYRELOG_E_OK);
  g_assert_cmpuint (bytes_written, ==, 15);
  g_assert_true (identity.domain != 0 || identity.object != 0
      || identity.object_width == 16);

  g_autofree gchar *stage_basename = g_strdup_printf ("restore-%s.duckdb",
          operation_uuid);
  g_autofree gchar *stage_path = wyl_fact_graph_directory_descriptive_file
        (&directory, stage_basename);
  g_autofree gchar *contents = NULL;
  gsize contents_size = 0;
  g_assert_true (g_file_get_contents (stage_path, &contents, &contents_size,
      &error));
  g_assert_no_error (error);
  g_assert_cmpuint (contents_size, ==, 15);
  g_assert_cmpmem (contents, contents_size, "restore payload", 15);
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 15, PAYLOAD_CHECKSUM, &collision), ==, WYRELOG_E_BUSY);
  g_assert_null (collision);

  wyl_fact_offline_restore_stage_free (stage);
  stage = NULL;
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_root_writer_lease_release (lease);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

typedef struct
{
  gboolean injected;
} RestoreStageFault;

static wyrelog_error_t
fail_after_restore_stage_parent_sync (const gchar *point, gpointer user_data)
{
  RestoreStageFault *fault = user_data;
  if (!fault->injected
      && g_strcmp0 (point, "restore-stage-parent-synced") == 0) {
    fault->injected = TRUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static void
test_post_create_failure_leaves_unrecoverable_orphan (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-stage-orphan-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);

  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactRootWriterLease *lease = NULL;
  WylFactOfflineRestoreStage *stage = NULL;
  RestoreStageFault fault = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver,
      fail_after_restore_stage_parent_sync, &fault);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
      &locator, TRUE, &directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_OK);
  wyl_id_t operation_id;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation_id, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_IO);
  g_assert_true (fault.injected);
  g_assert_null (stage);
  g_autofree gchar *stage_basename = g_strdup_printf ("restore-%s.duckdb",
          operation_uuid);
  g_autofree gchar *stage_path = wyl_fact_graph_directory_descriptive_file
        (&directory, stage_basename);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_IS_REGULAR));
  /* The failed capability does not adopt a named orphan as a retry. */
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_BUSY);
  g_assert_null (stage);

  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_root_writer_lease_release (lease);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_stage_substitution_rejects_write_and_finalize (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-stage-substitute-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactRootWriterLease *lease = NULL;
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
      &locator, TRUE, &directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_OK);
  wyl_id_t operation_id;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation_id, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 14, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_OK);

  g_autofree gchar *stage_basename = g_strdup_printf ("restore-%s.duckdb",
          operation_uuid);
  g_autofree gchar *stage_path = wyl_fact_graph_directory_descriptive_file
        (&directory, stage_basename);
  g_autofree gchar *displaced_path = wyl_fact_graph_directory_descriptive_file
        (&directory, "displaced-orphan");
  g_assert_cmpint (g_rename (stage_path, displaced_path), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_stage_write (stage, 0,
      (const guint8 *) "must not write", 14), ==, WYRELOG_E_POLICY);
  guint64 bytes_written = G_MAXUINT64;
  WylFactArtifactInventoryIdentity identity = { .domain = G_MAXUINT64 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage,
      &bytes_written, &identity), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (bytes_written, ==, 0);
  g_assert_cmpuint (identity.domain, ==, 0);
  g_assert_true (g_file_test (displaced_path, G_FILE_TEST_IS_REGULAR));

  wyl_fact_offline_restore_stage_free (stage);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_root_writer_lease_release (lease);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_short_stage_cannot_finalize (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-stage-short-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactRootWriterLease *lease = NULL;
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
      &locator, TRUE, &directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_OK);
  wyl_id_t operation_id;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation_id, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_write (stage, 0,
      (const guint8 *) "short payload", 13), ==, WYRELOG_E_OK);
  guint64 bytes_written = G_MAXUINT64;
  WylFactArtifactInventoryIdentity identity = { .domain = G_MAXUINT64 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage,
      &bytes_written, &identity), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (bytes_written, ==, 0);
  g_assert_cmpuint (identity.domain, ==, 0);
  g_assert_cmpuint (identity.object, ==, 0);
  g_assert_cmpuint (identity.object_width, ==, 0);

  wyl_fact_offline_restore_stage_free (stage);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_root_writer_lease_release (lease);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_external_truncation_cannot_finalize (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-stage-truncate-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactRootWriterLease *lease = NULL;
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
      &locator, TRUE, &directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_OK);
  wyl_id_t operation_id;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation_id, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_write (stage, 0,
      (const guint8 *) "restore payload", 15), ==, WYRELOG_E_OK);
  g_autofree gchar *stage_basename = g_strdup_printf ("restore-%s.duckdb",
          operation_uuid);
  g_autofree gchar *stage_path = wyl_fact_graph_directory_descriptive_file
        (&directory, stage_basename);
  g_assert_true (truncate_file (stage_path, 14));
  guint64 bytes_written = G_MAXUINT64;
  WylFactArtifactInventoryIdentity identity = { .domain = G_MAXUINT64 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage,
      &bytes_written, &identity), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (bytes_written, ==, 0);
  g_assert_cmpuint (identity.domain, ==, 0);
  g_assert_cmpuint (identity.object, ==, 0);
  g_assert_cmpuint (identity.object_width, ==, 0);

  wyl_fact_offline_restore_stage_free (stage);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_root_writer_lease_release (lease);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_raw_restore_stage_cannot_publish_or_abort (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-stage-private-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphStage native_stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
      &locator, TRUE, &directory), ==, WYRELOG_E_OK);
  wyl_id_t operation_id;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation_id, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_restore_stage_create_exact
        (&directory, operation_uuid, &native_stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_stage_publish (&directory, &native_stage),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_graph_stage_abort (&directory, &native_stage),
      ==, WYRELOG_E_POLICY);
  wyl_fact_graph_stage_clear (&native_stage);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

typedef struct
{
  gchar *root;
  gchar *path;
  WylFactGraphResolver resolver;
  WylFactGraphDirectory directory;
  WylFactGraphLocator locator;
  WylFactRootWriterLease *lease;
  gchar operation_uuid[WYL_ID_STRING_BUF];
} CopyFixture;

static void
copy_fixture_init (CopyFixture *fixture)
{
  *fixture = (CopyFixture) {
    .resolver = WYL_FACT_GRAPH_RESOLVER_INIT,
    .directory = WYL_FACT_GRAPH_DIRECTORY_INIT,
  };
  fixture->root = wyl_test_make_secure_fact_root
        ("wyl-restore-copy-XXXXXX", NULL);
  g_assert_nonnull (fixture->root);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator,
      "tenant-a", "alpha"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, TRUE, &fixture->directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture->root,
      &fixture->lease), ==, WYRELOG_E_OK);
  wyl_id_t operation;
  g_assert_cmpint (wyl_id_new (&operation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation, fixture->operation_uuid,
      sizeof fixture->operation_uuid), ==, WYRELOG_E_OK);
  g_autofree gchar *basename = g_strdup_printf ("restore-%s.duckdb",
          fixture->operation_uuid);
  fixture->path = wyl_fact_graph_directory_descriptive_file
        (&fixture->directory, basename);
}

static void
copy_fixture_clear (CopyFixture *fixture)
{
  wyl_fact_graph_directory_clear (&fixture->directory);
  wyl_fact_graph_resolver_clear (&fixture->resolver);
  wyl_fact_root_writer_lease_release (fixture->lease);
  wyl_fact_graph_locator_clear (&fixture->locator);
  remove_tree (fixture->root);
  g_free (fixture->path);
  g_free (fixture->root);
}

static void
corrupt_first_byte (const gchar *path)
{
#ifdef G_OS_WIN32
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_nonnull (wide);
  HANDLE handle = CreateFileW ((LPCWSTR) wide, GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  g_assert_true (handle != INVALID_HANDLE_VALUE);
  guint8 byte = 0xff;
  DWORD written = 0;
  g_assert_true (WriteFile (handle, &byte, 1, &written, NULL));
  g_assert_cmpuint (written, ==, 1);
  CloseHandle (handle);
#else
  int fd = open (path, O_RDWR);
  g_assert_cmpint (fd, >=, 0);
  guint8 byte = 0xff;
  g_assert_cmpint (pwrite (fd, &byte, 1, 0), ==, 1);
  close (fd);
#endif
}

static void
test_same_size_corruption_cannot_finalize (void)
{
  CopyFixture fixture;
  copy_fixture_init (&fixture);
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture.resolver,
      &fixture.directory, fixture.lease, fixture.operation_uuid,
      15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_write (stage, 0,
      (const guint8 *) "restore payload", 15), ==, WYRELOG_E_OK);
  corrupt_first_byte (fixture.path);
  guint64 bytes_written = G_MAXUINT64;
  WylFactArtifactInventoryIdentity identity = { .domain = G_MAXUINT64 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage,
      &bytes_written, &identity), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (bytes_written, ==, 0);
  g_assert_cmpuint (identity.domain, ==, 0);
  wyl_fact_offline_restore_stage_free (stage);
  copy_fixture_clear (&fixture);
}

static void
assert_zero_identity (const WylFactArtifactInventoryIdentity *identity)
{
  WylFactArtifactInventoryIdentity zero = { 0 };
  g_assert_cmpmem (identity, sizeof *identity, &zero, sizeof zero);
}

static void
assert_failed_stage (CopyFixture *fixture, WylFactOfflineRestoreStage *stage,
    guint64 length, const gchar *checksum)
{
  guint64 count = G_MAXUINT64;
  WylFactArtifactInventoryIdentity identity;
  memset (&identity, 0xff, sizeof identity);
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &count,
      &identity), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (count, ==, 0);
  assert_zero_identity (&identity);
  g_assert_cmpint (wyl_fact_offline_restore_stage_sink (0,
      (const guint8 *) "x", 1, stage), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_offline_restore_stage_revalidate (stage), ==,
      WYRELOG_E_POLICY);
  wyl_fact_offline_restore_stage_free (stage);
  g_assert_true (g_file_test (fixture->path, G_FILE_TEST_IS_REGULAR));
  WylFactOfflineRestoreStage *retry = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture->resolver,
      &fixture->directory, fixture->lease, fixture->operation_uuid,
      length, checksum, &retry), ==, WYRELOG_E_BUSY);
  g_assert_null (retry);
}

static gchar *
checksum_text (const guint8 *bytes, gsize length)
{
  g_autofree gchar *digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
          bytes, length);
  return g_strdup_printf ("sha256:%s", digest);
}

static void
test_binary_stream_and_owned_checksum (void)
{
  const gsize length = 2 * 64 * 1024 + 17;
  g_autofree guint8 *bytes = g_malloc (length);
  for (gsize i = 0; i < length; i++)
    bytes[i] = (guint8) (i % 256);
  g_autofree gchar *checksum = checksum_text (bytes, length);
  CopyFixture fixture;
  copy_fixture_init (&fixture);
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture.resolver,
      &fixture.directory, fixture.lease, fixture.operation_uuid,
      length, checksum, &stage), ==, WYRELOG_E_OK);
  /* Construction owns the expected digest, not the caller's string. */
  memset (checksum, '0', strlen (checksum));
  for (gsize offset = 0; offset < length;) {
    gsize chunk = MIN ((gsize) 32749, length - offset);
    g_assert_cmpint (wyl_fact_offline_restore_stage_sink (offset,
        bytes + offset, chunk, stage), ==, WYRELOG_E_OK);
    offset += chunk;
  }
  /* A producer's final authority checks still precede finalization. */
  g_assert_cmpint (wyl_fact_offline_restore_stage_revalidate (stage), ==,
      WYRELOG_E_OK);
  guint64 count = 0;
  WylFactArtifactInventoryIdentity identity = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &count,
      &identity), ==, WYRELOG_E_OK);
  g_assert_cmpuint (count, ==, length);
#ifdef G_OS_WIN32
  g_assert_cmpuint (identity.object_width, ==, 16);
#else
  g_assert_cmpuint (identity.object, !=, 0);
#endif
  g_autofree gchar *readback = NULL;
  gsize readback_length = 0;
  g_assert_true (g_file_get_contents (fixture.path, &readback,
      &readback_length, NULL));
  g_assert_cmpmem (readback, readback_length, bytes, length);
  g_assert_cmpint (wyl_fact_offline_restore_stage_sink (0, bytes, 1, stage),
      ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &count,
      &identity), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (count, ==, 0);
  assert_zero_identity (&identity);
  wyl_fact_offline_restore_stage_free (stage);
  copy_fixture_clear (&fixture);
}

static void
test_malformed_checksums_do_not_create_stage (void)
{
  /* Reject overlong input without inspecting beyond the maximum encoding. */
  gchar overlong[72];
  memset (overlong, 'a', sizeof overlong);
  memcpy (overlong, "sha256:", 7);
  const gchar *invalid[] = {
    NULL, "", "sha256:", overlong,
    "sha256:D89c09dbdbf32efe0a8d5f3693c6ae897d3a5ba818962db9d8d5dc052f767e2b",
    "sha256:z89c09dbdbf32efe0a8d5f3693c6ae897d3a5ba818962db9d8d5dc052f767e2b",
    "SHA256:d89c09dbdbf32efe0a8d5f3693c6ae897d3a5ba818962db9d8d5dc052f767e2b",
    PAYLOAD_CHECKSUM "0",
    "sha256:d89c09dbdbf32efe0a8d5f3693c6ae897d3a5ba818962db9d8d5dc052f767e2",
  };
  CopyFixture fixture;
  copy_fixture_init (&fixture);
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++) {
    WylFactOfflineRestoreStage *stage = (gpointer) &fixture;
    g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture.resolver,
        &fixture.directory, fixture.lease, fixture.operation_uuid,
        15, invalid[i], &stage), ==, WYRELOG_E_INVALID);
    g_assert_null (stage);
    g_assert_false (g_file_test (fixture.path, G_FILE_TEST_EXISTS));
  }
  copy_fixture_clear (&fixture);
}

static void
test_wrong_stream_digest_is_terminal (void)
{
  CopyFixture fixture;
  copy_fixture_init (&fixture);
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture.resolver,
      &fixture.directory, fixture.lease, fixture.operation_uuid,
      15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_sink (0,
      (const guint8 *) "corrupt payload", 15, stage), ==, WYRELOG_E_OK);
  guint64 count = G_MAXUINT64;
  WylFactArtifactInventoryIdentity identity;
  memset (&identity, 0xff, sizeof identity);
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &count,
      &identity), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (count, ==, 0);
  assert_zero_identity (&identity);
  assert_failed_stage (&fixture, stage, 15, PAYLOAD_CHECKSUM);
  copy_fixture_clear (&fixture);
}

static void
test_invalid_finalize_arguments_are_terminal (void)
{
  for (guint i = 0; i < 2; i++) {
    CopyFixture fixture;
    copy_fixture_init (&fixture);
    WylFactOfflineRestoreStage *stage = NULL;
    g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture.resolver,
        &fixture.directory, fixture.lease, fixture.operation_uuid,
        15, PAYLOAD_CHECKSUM, &stage), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_stage_sink (0,
        (const guint8 *) "restore payload", 15, stage), ==, WYRELOG_E_OK);
    guint64 count = G_MAXUINT64;
    WylFactArtifactInventoryIdentity identity;
    memset (&identity, 0xff, sizeof identity);
    g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage,
        i == 0 ? NULL : &count, i == 1 ? NULL : &identity), ==,
        WYRELOG_E_INVALID);
    if (i == 0)
      assert_zero_identity (&identity);
    else
      g_assert_cmpuint (count, ==, 0);
    assert_failed_stage (&fixture, stage, 15, PAYLOAD_CHECKSUM);
    copy_fixture_clear (&fixture);
  }
}

typedef enum
{
  COPY_FAULT_IO,
  COPY_FAULT_TRUNCATE,
  COPY_FAULT_GROW,
  COPY_FAULT_CORRUPT,
  COPY_FAULT_SUBSTITUTE,
} CopyFaultAction;

typedef struct
{
  const gchar *name;
  const gchar *point;
  CopyFaultAction action;
  wyrelog_error_t expected;
} CopyFaultCase;

typedef struct
{
  const CopyFaultCase *test;
  CopyFixture *fixture;
  gsize length;
  gboolean injected;
} CopyFault;

static wyrelog_error_t
copy_fault_checkpoint (const gchar *point, gpointer user_data)
{
  CopyFault *fault = user_data;
  if (fault->injected || g_strcmp0 (point, fault->test->point) != 0)
    return WYRELOG_E_OK;
  fault->injected = TRUE;
  switch (fault->test->action) {
    case COPY_FAULT_IO:
      return WYRELOG_E_IO;
    case COPY_FAULT_TRUNCATE:
      g_assert_true (truncate_file (fault->fixture->path, fault->length - 1));
      break;
    case COPY_FAULT_GROW:
      g_assert_true (truncate_file (fault->fixture->path, fault->length + 1));
      break;
    case COPY_FAULT_CORRUPT:
      corrupt_first_byte (fault->fixture->path);
      break;
    case COPY_FAULT_SUBSTITUTE: {
      g_autofree gchar *displaced = g_strconcat (fault->fixture->path,
              ".displaced", NULL);
      g_assert_cmpint (g_rename (fault->fixture->path, displaced), ==, 0);
      break;
    }
  }
  return WYRELOG_E_OK;
}

static void
test_readback_fault (gconstpointer data)
{
  const CopyFaultCase *test = data;
  CopyFixture fixture;
  copy_fixture_init (&fixture);
  const gsize length = 2 * 64 * 1024 + 17;
  g_autofree guint8 *bytes = g_malloc0 (length);
  g_autofree gchar *checksum = checksum_text (bytes, length);
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture.resolver,
      &fixture.directory, fixture.lease, fixture.operation_uuid,
      length, checksum, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_sink (0, bytes, length,
      stage), ==, WYRELOG_E_OK);
  CopyFault fault = { test, &fixture, length, FALSE };
  fixture.directory.checkpoint = copy_fault_checkpoint;
  fixture.directory.checkpoint_data = &fault;
  guint64 count = G_MAXUINT64;
  WylFactArtifactInventoryIdentity identity;
  memset (&identity, 0xff, sizeof identity);
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &count,
      &identity), ==, test->expected);
  g_assert_true (fault.injected);
  g_assert_cmpuint (count, ==, 0);
  assert_zero_identity (&identity);
  fixture.directory.checkpoint = NULL;
  fixture.directory.checkpoint_data = NULL;
  if (test->action == COPY_FAULT_SUBSTITUTE) {
    g_autofree gchar *displaced = g_strconcat (fixture.path,
            ".displaced", NULL);
    g_assert_true (g_file_test (displaced, G_FILE_TEST_IS_REGULAR));
    g_assert_cmpint (wyl_fact_offline_restore_stage_revalidate (stage), ==,
        WYRELOG_E_POLICY);
    wyl_fact_offline_restore_stage_free (stage);
  } else {
    assert_failed_stage (&fixture, stage, length, checksum);
  }
  copy_fixture_clear (&fixture);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-offline-restore-stage/create-write-finalize-collision",
      test_create_write_finalize_and_collision);
  g_test_add_func ("/fact-offline-restore-stage/post-create-orphan",
      test_post_create_failure_leaves_unrecoverable_orphan);
  g_test_add_func ("/fact-offline-restore-stage/substitute-fails-closed",
      test_stage_substitution_rejects_write_and_finalize);
  g_test_add_func ("/fact-offline-restore-stage/no-generic-transition",
      test_raw_restore_stage_cannot_publish_or_abort);
  g_test_add_func ("/fact-offline-restore-stage/short-not-finalized",
      test_short_stage_cannot_finalize);
  g_test_add_func ("/fact-offline-restore-stage/external-truncate",
      test_external_truncation_cannot_finalize);
  g_test_add_func ("/fact-offline-restore-stage/same-size-corruption",
      test_same_size_corruption_cannot_finalize);
  g_test_add_func ("/fact-offline-restore-stage/binary-stream-owned-checksum",
      test_binary_stream_and_owned_checksum);
  g_test_add_func ("/fact-offline-restore-stage/malformed-checksum",
      test_malformed_checksums_do_not_create_stage);
  g_test_add_func ("/fact-offline-restore-stage/wrong-stream-digest",
      test_wrong_stream_digest_is_terminal);
  g_test_add_func ("/fact-offline-restore-stage/invalid-finalize-terminal",
      test_invalid_finalize_arguments_are_terminal);
  static const CopyFaultCase faults[] = {
    { "io-before", "restore-stage-before-readback", COPY_FAULT_IO,
      WYRELOG_E_IO },
    { "io-during", "restore-stage-readback-chunk", COPY_FAULT_IO,
      WYRELOG_E_IO },
    { "io-after", "restore-stage-readback-complete", COPY_FAULT_IO,
      WYRELOG_E_IO },
    { "corrupt-before", "restore-stage-before-readback", COPY_FAULT_CORRUPT,
      WYRELOG_E_POLICY },
    { "truncate-during", "restore-stage-readback-chunk", COPY_FAULT_TRUNCATE,
      WYRELOG_E_POLICY },
    { "grow-during", "restore-stage-readback-chunk", COPY_FAULT_GROW,
      WYRELOG_E_POLICY },
    { "grow-after", "restore-stage-readback-complete", COPY_FAULT_GROW,
      WYRELOG_E_POLICY },
    { "substitute-after", "restore-stage-readback-complete",
      COPY_FAULT_SUBSTITUTE, WYRELOG_E_POLICY },
  };
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-restore-stage/",
            faults[i].name, NULL);
    g_test_add_data_func (path, &faults[i], test_readback_fault);
  }
  return wyl_test_normalize_exit_status (g_test_run ());
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
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
      lease, operation_uuid, 15, &stage), ==, WYRELOG_E_OK);
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
      lease, operation_uuid, 15, &collision), ==, WYRELOG_E_BUSY);
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
      lease, operation_uuid, 15, &stage), ==, WYRELOG_E_IO);
  g_assert_true (fault.injected);
  g_assert_null (stage);
  g_autofree gchar *stage_basename = g_strdup_printf ("restore-%s.duckdb",
          operation_uuid);
  g_autofree gchar *stage_path = wyl_fact_graph_directory_descriptive_file
        (&directory, stage_basename);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_IS_REGULAR));
  /* The failed capability does not adopt a named orphan as a retry. */
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, operation_uuid, 15, &stage), ==, WYRELOG_E_BUSY);
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
      lease, operation_uuid, 14, &stage), ==, WYRELOG_E_OK);

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
      lease, operation_uuid, 15, &stage), ==, WYRELOG_E_OK);
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
      lease, operation_uuid, 15, &stage), ==, WYRELOG_E_OK);
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
  return wyl_test_normalize_exit_status (g_test_run ());
}

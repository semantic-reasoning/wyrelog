/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include <string.h>

#ifdef G_OS_WIN32
#include <windows.h>

#include "fact/graph-artifact-windows-handle-private.h"
#include "fact/graph-artifact-windows-lock-private.h"

static WylFactGraphWinIdentity
identity_for (HANDLE handle)
{
  FILE_ID_INFO info = { 0 };
  WylFactGraphWinIdentity identity = { 0 };

  g_assert_true (GetFileInformationByHandleEx (handle, FileIdInfo, &info,
          sizeof info));
  identity.volume_serial = info.VolumeSerialNumber;
  memcpy (identity.file_id, info.FileId.Identifier, sizeof identity.file_id);
  return identity;
}

static HANDLE
open_scratch_file (gchar **out_path)
{
  g_autoptr (GError) error = NULL;
  gchar *directory = g_dir_make_tmp ("wyl-win-artifact-XXXXXX", &error);
  gchar *path;
  wchar_t *wide;
  HANDLE handle;

  g_assert_no_error (error);
  g_assert_nonnull (directory);
  path = g_build_filename (directory, "facts.duckdb.wal", NULL);
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_nonnull (wide);
  handle = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  g_free (wide);
  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  g_free (directory);
  *out_path = path;
  return handle;
}

static HANDLE
open_existing_scratch_file (const gchar *path)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE handle = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  return handle;
}

static void
remove_scratch_file (gchar *path)
{
  g_autofree gchar *directory = g_path_get_dirname (path);
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_autofree wchar_t *wide_directory = g_utf8_to_utf16 (directory, -1, NULL,
      NULL, NULL);

  g_assert_true (DeleteFileW (wide));
  g_assert_true (RemoveDirectoryW (wide_directory));
  g_free (path);
}

static void
test_working_handle_adopt_noninherit_close_once (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE borrowed = INVALID_HANDLE_VALUE;
  DWORD flags = HANDLE_FLAG_INHERIT;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  g_assert_nonnull (binding);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_borrow (binding,
          &borrowed), ==, WYRELOG_E_OK);
  g_assert_true (GetHandleInformation (borrowed, &flags));
  g_assert_cmpuint (flags & HANDLE_FLAG_INHERIT, ==, 0);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_close (binding,
          &borrowed), ==, WYRELOG_E_OK);
  g_assert_cmpint (borrowed == INVALID_HANDLE_VALUE, ==, TRUE);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_close (binding,
          &borrowed), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_win_working_handle_free (binding);
  remove_scratch_file (path);
}

static void
test_working_handle_identity_mismatch_initializes_output (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = (gpointer) 0x1;

  identity.file_id[0] ^= 0xff;
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_true (CloseHandle (issued));
  remove_scratch_file (path);
}

static void
test_working_handle_free_never_closes_reused_handle (void)
{
  gchar *path = NULL;
  gchar *foreign_path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE foreign;
  BY_HANDLE_FILE_INFORMATION info = { 0 };

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  /* Deliberately violate ownership, then force the native handle table to
   * assign the stale numeric value to a distinct file.  Windows reuses a
   * just-closed value immediately; treating failure here as a skip would
   * make the safety regression non-evidence. */
  g_assert_true (CloseHandle (issued));
  foreign = open_scratch_file (&foreign_path);
  g_assert_true (foreign == issued);
  wyl_fact_artifact_win_working_handle_free (binding);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_true (CloseHandle (foreign));
  remove_scratch_file (foreign_path);
  remove_scratch_file (path);
}

static void
test_working_handle_raw_close_revokes_as_policy (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE borrowed = (HANDLE) 1;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (issued));
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_borrow (binding,
          &borrowed), ==, WYRELOG_E_POLICY);
  g_assert_true (borrowed == INVALID_HANDLE_VALUE);
  /* There is no valid owned HANDLE after raw close; free only discards the
   * terminal binding and must not attempt CloseHandle on its stale value. */
  wyl_fact_artifact_win_working_handle_free (binding);
  remove_scratch_file (path);
}

static void
test_working_handle_close_mismatch_revokes_without_foreign_close (void)
{
  gchar *path = NULL;
  gchar *foreign_path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE foreign = open_scratch_file (&foreign_path);
  HANDLE supplied = foreign;
  HANDLE borrowed = (HANDLE) 1;
  BY_HANDLE_FILE_INFORMATION info = { 0 };

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_close (binding,
          &supplied), ==, WYRELOG_E_POLICY);
  g_assert_true (supplied == foreign);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_borrow (binding,
          &borrowed), ==, WYRELOG_E_POLICY);
  g_assert_true (borrowed == INVALID_HANDLE_VALUE);
  /* _free may close only the still-exact owned value, never |foreign|. */
  wyl_fact_artifact_win_working_handle_free (binding);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_true (CloseHandle (foreign));
  remove_scratch_file (foreign_path);
  remove_scratch_file (path);
}

static void
test_native_lock_domain_alias_reader_writer_contention (void)
{
  gchar *path = NULL;
  HANDLE pin = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (pin);
  WylFactGraphWinIdentity directory_identity = identity;
  WylFactArtifactWinLockDomain *domain = NULL;
  WylFactArtifactWinLockDomain *alias_domain = NULL;
  WylFactArtifactWinLockLease *reader_a = NULL;
  WylFactArtifactWinLockLease *reader_b = NULL;
  WylFactArtifactWinLockLease *writer = (gpointer) 0x1;
  HANDLE alias_pin = open_existing_scratch_file (path);
  HANDLE reader_a_handle = open_existing_scratch_file (path);
  HANDLE reader_b_handle = open_existing_scratch_file (path);
  HANDLE writer_handle = open_existing_scratch_file (path);

  /* The key is the graph-directory tuple, not a spelling of its path.  Use a
   * distinct fixture key so parallel tests cannot accidentally join. */
  directory_identity.file_id[0] ^= 0x80;
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
          &identity, pin, &domain), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
          &identity, alias_pin, &alias_domain), ==, WYRELOG_E_OK);
  g_assert_true (domain == alias_domain);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (domain,
          reader_a_handle, FALSE, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (alias_domain,
          reader_b_handle, FALSE, &reader_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (domain,
          writer_handle, TRUE, &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  g_assert_true (CloseHandle (writer_handle));
  wyl_fact_artifact_win_lock_lease_free (reader_a);
  wyl_fact_artifact_win_lock_lease_free (reader_b);
  writer_handle = open_existing_scratch_file (path);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (alias_domain,
          writer_handle, TRUE, &writer), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_lease_revalidate (writer), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_lock_lease_free (writer);
  wyl_fact_artifact_win_lock_domain_free (alias_domain);
  wyl_fact_artifact_win_lock_domain_free (domain);
  remove_scratch_file (path);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/adopt-close",
      test_working_handle_adopt_noninherit_close_once);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/identity-output",
      test_working_handle_identity_mismatch_initializes_output);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/free-reused-handle",
      test_working_handle_free_never_closes_reused_handle);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/raw-close-policy",
      test_working_handle_raw_close_revokes_as_policy);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/close-mismatch",
      test_working_handle_close_mismatch_revokes_without_foreign_close);
  g_test_add_func
      ("/fact/artifact-namespace/windows/lock-domain/alias-contention",
      test_native_lock_domain_alias_reader_writer_contention);
  return g_test_run ();
}
#else
int
main (void)
{
  return 77;
}
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include <string.h>

#ifdef G_OS_WIN32
#include <windows.h>

#include "fact/graph-artifact-windows-handle-private.h"

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
  handle = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE, 0, NULL,
      CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  g_free (wide);
  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  g_free (directory);
  *out_path = path;
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
  return g_test_run ();
}
#else
int
main (void)
{
  return 77;
}
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <glib.h>
#include <glib/gstdio.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#include "auth/service-credential-operation-storage-private.h"

static void
test_resolves_and_rejects_symlink (void)
{
  g_autofree gchar *base = g_dir_make_tmp ("wyl-operation-root-XXXXXX", NULL);
  g_assert_nonnull (base);
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_OK);
  g_assert_true (g_file_test (storage.root_path, G_FILE_TEST_IS_DIR));
  g_assert_cmpint (g_chmod (storage.root_path, 0777), ==, 0);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_POLICY);
  wyl_service_credential_operation_storage_clear (&storage);
#ifndef G_OS_WIN32
  g_autofree gchar *link = g_build_filename (base, "link", NULL);
  g_assert_cmpint (symlink (root, link), ==, 0);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (link,
          &storage), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (link), ==, 0);
#endif
  g_assert_cmpint (g_rmdir (root), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
}

static void
test_rejects_file_root (void)
{
  g_autofree gchar *base = g_dir_make_tmp ("wyl-operation-file-XXXXXX", NULL);
  g_assert_nonnull (base);
  g_autofree gchar *file = g_build_filename (base, "not-a-directory", NULL);
  g_assert_true (g_file_set_contents (file, "x", 1, NULL));
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open (file,
          &storage), ==, WYRELOG_E_POLICY);
  wyl_service_credential_operation_storage_clear (&storage);
  g_assert_cmpint (g_remove (file), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/operation-storage/private-root",
      test_resolves_and_rejects_symlink);
  g_test_add_func ("/operation-storage/file-root", test_rejects_file_root);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <glib.h>
#include <glib/gstdio.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

#include "auth/service-credential-operation-storage-private.h"

static void
test_resolves_and_rejects_symlink (void)
{
#ifdef G_OS_WIN32
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_autofree gchar *base = g_strdup_printf ("%s%cwyrelog-operation-root-%lu",
      local, G_DIR_SEPARATOR, (gulong) GetCurrentProcessId ());
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
  /* A killed prior run may leave these deterministic test directories. */
  g_rmdir (root);
  g_rmdir (base);
#else
  g_autofree gchar *base = g_dir_make_tmp ("wyl-operation-root-XXXXXX", NULL);
  g_assert_nonnull (base);
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
#endif
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  /* The first open clears caller-owned state; an initialized value must be
   * safe to clear before it has ever held a root. */
  wyl_service_credential_operation_storage_clear (&storage);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_OK);
  g_assert_true (g_file_test (storage.root_path, G_FILE_TEST_IS_DIR));
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_assert_true (wyl_service_credential_operation_storage_anchor_matches
      (&storage, &anchor));
  anchor.identity_a++;
  g_assert_false (wyl_service_credential_operation_storage_anchor_matches
      (&storage, &anchor));
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  g_assert_false (wyl_service_credential_operation_storage_anchor_matches
      (&storage, &anchor));
#ifndef G_OS_WIN32
  g_assert_cmpint (g_chmod (storage.root_path, 0777), ==, 0);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_POLICY);
#endif
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

static void
test_child_name_and_anchor_contract (void)
{
  static const gchar *const invalid[] = {
    "", ".", "..", "/absolute", "\\absolute", "C:relative",
    "C:\\absolute", "\\\\server\\share", "has:colon", "has/slash",
    "has\\slash", "trailing.", "trailing ", NULL
  };
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_autofree gchar *too_long = g_malloc0 (256);
  const gchar invalid_utf8[] = "bad\xff";
  memset (too_long, 'a', 255);
  for (gsize i = 0; invalid[i] != NULL; i++)
    g_assert_cmpint (wyl_service_credential_operation_child_name_validate
        (invalid[i], &name), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      (invalid_utf8, &name), ==, WYRELOG_E_POLICY);
  too_long[255] = 'a';
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      (too_long, &name), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("record-01", &name), ==, WYRELOG_E_OK);
  g_assert_cmpstr (name.component, ==, "record-01");
  wyl_service_credential_operation_child_name_clear (&name);
  g_assert_null (name.component);
  g_assert_false (wyl_service_credential_operation_storage_anchor_matches
      (NULL, &anchor));
}

#ifdef G_OS_WIN32
static void
test_rejects_relative_override (void)
{
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_assert_cmpint (local[1], ==, ':');
  g_autofree gchar *short_path = g_strdup_printf ("%c:\\", local[0]);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open (short_path,
          &storage), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_storage_open ("state\\ops",
          &storage), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_storage_open ("C:state",
          &storage), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      ("\\\\server\\share", &storage), ==, WYRELOG_E_POLICY);
  wyl_service_credential_operation_storage_clear (&storage);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/operation-storage/private-root",
      test_resolves_and_rejects_symlink);
  g_test_add_func ("/operation-storage/file-root", test_rejects_file_root);
  g_test_add_func ("/operation-storage/child-contract",
      test_child_name_and_anchor_contract);
#ifdef G_OS_WIN32
  g_test_add_func ("/operation-storage/windows/relative-override",
      test_rejects_relative_override);
#endif
  return g_test_run ();
}

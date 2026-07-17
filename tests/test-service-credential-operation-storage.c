/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <glib.h>
#include <glib/gstdio.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#include <sys/stat.h>
#else
#include <windows.h>
#endif

#include "auth/service-credential-operation-storage-private.h"
#ifdef G_OS_WIN32
#include "auth/service-credential-operation-storage-windows-private.h"
#endif

#ifndef G_OS_WIN32
static void
assert_child_contents (WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, const gchar *expected)
{
  g_autoptr (GBytes) bytes = NULL;
  gsize length = 0;
  gconstpointer data;
  g_assert_cmpint (wyl_service_credential_operation_child_read (storage,
          anchor, name, &bytes), ==, WYRELOG_E_OK);
  data = g_bytes_get_data (bytes, &length);
  g_assert_cmpuint (length, ==, strlen (expected));
  g_assert_true (memcmp (data, expected, length) == 0);
}

static void
test_posix_child_backend (void)
{
  g_autofree gchar *base = g_dir_make_tmp ("wyl-child-XXXXXX", NULL);
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) one = g_bytes_new_static ("one", 3);
  g_autoptr (GBytes) two = g_bytes_new_static ("two", 3);
  g_autoptr (GBytes) oversized = g_bytes_new_take (g_malloc0
      (WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_MAX_BYTES + 1),
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_MAX_BYTES + 1);
  gint lock_fd = -1;
  gint second_lock_fd = -1;

  g_assert_nonnull (base);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("record", &name), ==, WYRELOG_E_OK);
  g_autofree gchar *record = g_build_filename (storage.root_path, "record",
      NULL);
  g_remove (record);

  g_assert_cmpint (wyl_service_credential_operation_child_create (&storage,
          &anchor, &name, one), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_create (&storage,
          &anchor, &name, one), ==, WYRELOG_E_POLICY);
  assert_child_contents (&storage, &anchor, &name, "one");
  g_assert_cmpint (wyl_service_credential_operation_child_replace (&storage,
          &anchor, &name, two), ==, WYRELOG_E_OK);
  assert_child_contents (&storage, &anchor, &name, "two");
  g_autofree gchar *long_component = g_malloc (256);
  memset (long_component, 'x', 255);
  long_component[255] = '\0';
  WylServiceCredentialOperationChildName long_name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      (long_component, &long_name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_replace (&storage,
          &anchor, &long_name, one), ==, WYRELOG_E_OK);
  assert_child_contents (&storage, &anchor, &long_name, "one");
  g_assert_cmpint (wyl_service_credential_operation_child_delete (&storage,
          &anchor, &long_name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_delete (&storage,
          &anchor, &name), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) missing = NULL;
  g_assert_cmpint (wyl_service_credential_operation_child_read (&storage,
          &anchor, &name, &missing), ==, WYRELOG_E_NOT_FOUND);

  g_assert_cmpint (wyl_service_credential_operation_child_create (&storage,
          &anchor, &name, oversized), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_child_replace (&storage,
          &anchor, &name, oversized), ==, WYRELOG_E_POLICY);

  g_assert_cmpint (wyl_service_credential_operation_child_lock (&storage,
          &anchor, &name, &lock_fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_lock (&storage,
          &anchor, &name, &second_lock_fd), ==, WYRELOG_E_BUSY);
  wyl_service_credential_operation_child_unlock (&storage, &anchor, &name,
      lock_fd);
  lock_fd = -1;
  g_assert_cmpint (wyl_service_credential_operation_child_lock (&storage,
          &anchor, &name, &second_lock_fd), ==, WYRELOG_E_OK);
  wyl_service_credential_operation_child_unlock (&storage, &anchor, &name,
      second_lock_fd);
  g_assert_cmpint (wyl_service_credential_operation_child_create (&storage,
          &anchor, &name, one), ==, WYRELOG_E_OK);

  WylServiceCredentialOperationRootAnchor mismatch = anchor;
  mismatch.identity_a++;
  g_assert_cmpint (wyl_service_credential_operation_child_read (&storage,
          &mismatch, &name, &missing), ==, WYRELOG_E_POLICY);

  g_autofree gchar *link = g_build_filename (storage.root_path, "link", NULL);
  g_assert_cmpint (symlink ("record", link), ==, 0);
  WylServiceCredentialOperationChildName link_name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("link", &link_name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_read (&storage,
          &anchor, &link_name, &missing), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (link), ==, 0);

  g_autofree gchar *directory = g_build_filename (storage.root_path,
      "directory", NULL);
  g_assert_cmpint (g_mkdir (directory, 0700), ==, 0);
  WylServiceCredentialOperationChildName directory_name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("directory", &directory_name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_read (&storage,
          &anchor, &directory_name, &missing), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_rmdir (directory), ==, 0);
  g_assert_cmpint (wyl_service_credential_operation_child_delete (&storage,
          &anchor, &name), ==, WYRELOG_E_OK);

  g_autoptr (GDir) entries = g_dir_open (storage.root_path, 0, NULL);
  const gchar *entry;
  while (entries != NULL && (entry = g_dir_read_name (entries)) != NULL)
    if (g_str_has_prefix (entry, ".lock-")
        || g_str_has_prefix (entry, ".replace-"))
      g_remove (g_build_filename (storage.root_path, entry, NULL));

  wyl_service_credential_operation_child_name_clear (&directory_name);
  wyl_service_credential_operation_child_name_clear (&link_name);
  wyl_service_credential_operation_child_name_clear (&long_name);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
  g_assert_cmpint (g_rmdir (root), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
}
#endif

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
  static const gchar *const reserved[] = {
    "CON", "con.txt", "PrN.log", "AUX", "NUL.backup", "COM1",
    "com9.data", "LPT1", "lpt9.log", NULL
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
  for (gsize i = 0; reserved[i] != NULL; i++)
    g_assert_cmpint (wyl_service_credential_operation_child_name_validate
        (reserved[i], &name), ==, WYRELOG_E_POLICY);
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
test_windows_child_read_validation (void)
{
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) bytes = NULL;
  g_assert_cmpint (wyl_win_child_read (NULL, NULL, NULL, &bytes), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("missing", &name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_win_child_read (NULL, NULL, &name, &bytes), ==,
      WYRELOG_E_POLICY);
  wyl_service_credential_operation_child_name_clear (&name);
}

static void
test_windows_child_read_fixture (void)
{
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_autofree gchar *base = g_strdup_printf ("%s\\wyrelog-read-test-%lu",
      local, (gulong) GetCurrentProcessId ());
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) bytes = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylWinChildIdentity identity;
  wyrelog_error_t error;
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("record", &name), ==, WYRELOG_E_OK);
  g_autofree gchar *record = g_build_filename (storage.root_path, "record",
      NULL);
  g_remove (record);
  g_assert_cmpint (wyl_win_child_read (&storage, &anchor, &name, &bytes), ==,
      WYRELOG_E_NOT_FOUND);
  if (!wyl_win_nt_create_relative (storage.root_handle, &name, GENERIC_WRITE,
          WYL_WIN_CHILD_CREATE, &handle, &identity, &error)) {
    g_test_message ("NtCreateFile child create error=%d", error);
    g_assert_not_reached ();
  }
  DWORD written = 0;
  g_assert_true (WriteFile (handle, "hello", 5, &written, NULL));
  g_assert_cmpuint (written, ==, 5);
  g_assert_true (FlushFileBuffers (handle));
  CloseHandle (handle);
  handle = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_win_child_read (&storage, &anchor, &name, &bytes), ==,
      WYRELOG_E_OK);
  gsize size = 0;
  g_assert_cmpmem (g_bytes_get_data (bytes, &size), size, "hello", 5);
  g_remove (record);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
}

static void
test_windows_child_create_fixture (void)
{
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_autofree gchar *base = g_strdup_printf ("%s\\wyrelog-create-test-%lu",
      local, (gulong) GetCurrentProcessId ());
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("empty", &name), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) empty = g_bytes_new_static ("", 0);
  g_assert_cmpint (wyl_win_child_create (&storage, &anchor, &name, empty), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_win_child_create (&storage, &anchor, &name, empty), ==,
      WYRELOG_E_POLICY);
  g_autoptr (GBytes) boundary = g_bytes_new_take (g_malloc0 (64u * 1024u),
      64u * 1024u);
  WylServiceCredentialOperationChildName boundary_name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("boundary", &boundary_name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_win_child_create (&storage, &anchor, &boundary_name,
          boundary), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) roundtrip = NULL;
  g_assert_cmpint (wyl_win_child_read (&storage, &anchor, &boundary_name,
          &roundtrip), ==, WYRELOG_E_OK);
  g_assert_cmpuint (g_bytes_get_size (roundtrip), ==, 64u * 1024u);
  g_autoptr (GBytes) oversized = g_bytes_new_take (g_malloc0
      (64u * 1024u + 1), 64u * 1024u + 1);
  WylServiceCredentialOperationChildName oversized_name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate
      ("oversized", &oversized_name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_win_child_create (&storage, &anchor, &oversized_name,
          oversized), ==, WYRELOG_E_POLICY);
  g_autofree gchar *empty_path =
      g_build_filename (storage.root_path, "empty", NULL);
  g_autofree gchar *boundary_path =
      g_build_filename (storage.root_path, "boundary", NULL);
  g_remove (empty_path);
  g_remove (boundary_path);
  wyl_service_credential_operation_child_name_clear (&oversized_name);
  wyl_service_credential_operation_child_name_clear (&boundary_name);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
}

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
#ifndef G_OS_WIN32
  g_test_add_func ("/operation-storage/posix-child/backend",
      test_posix_child_backend);
#endif
#ifdef G_OS_WIN32
  g_test_add_func ("/operation-storage/windows/child-read-validation",
      test_windows_child_read_validation);
  g_test_add_func ("/operation-storage/windows/child-read-fixture",
      test_windows_child_read_fixture);
  g_test_add_func ("/operation-storage/windows/child-create-fixture",
      test_windows_child_create_fixture);
  g_test_add_func ("/operation-storage/windows/relative-override",
      test_rejects_relative_override);
#endif
  return g_test_run ();
}

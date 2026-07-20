/* SPDX-License-Identifier: GPL-3.0-or-later */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include "fact-test-support.h"

#include <glib/gstdio.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <aclapi.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <winioctl.h>
#else
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef G_OS_WIN32
typedef struct
{
  PSID user;
  PACL acl;
} WylTestOwnerAcl;

typedef struct
{
  DWORD tag;
  WORD data_length;
  WORD reserved;
  WORD substitute_offset;
  WORD substitute_length;
  WORD print_offset;
  WORD print_length;
  WCHAR path_buffer[1];
} WylTestMountPointReparseData;

static void
owner_acl_clear (WylTestOwnerAcl *security)
{
  g_free (security->acl);
  g_free (security->user);
  *security = (WylTestOwnerAcl) {
  0};
}

static gboolean
owner_acl_init (BYTE ace_flags, WylTestOwnerAcl *security, GError **error)
{
  HANDLE token = NULL;
  TOKEN_USER *token_user = NULL;
  DWORD needed = 0;
  gboolean ok = FALSE;

  *security = (WylTestOwnerAcl) {
  0};
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    goto out;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    goto out;
  token_user = g_malloc0 (needed);
  if (!GetTokenInformation (token, TokenUser, token_user, needed, &needed)
      || token_user->User.Sid == NULL || !IsValidSid (token_user->User.Sid))
    goto out;

  DWORD sid_length = GetLengthSid (token_user->User.Sid);
  security->user = g_malloc (sid_length);
  if (!CopySid (sid_length, security->user, token_user->User.Sid))
    goto out;
  DWORD acl_length = sizeof (ACL) + sizeof (ACCESS_ALLOWED_ACE)
      - sizeof (DWORD) + sid_length;
  security->acl = g_malloc0 (acl_length);
  if (!InitializeAcl (security->acl, acl_length, ACL_REVISION)
      || !AddAccessAllowedAceEx (security->acl, ACL_REVISION, ace_flags,
          FILE_ALL_ACCESS, security->user))
    goto out;
  ok = TRUE;

out:
  DWORD saved_error = GetLastError ();
  g_free (token_user);
  if (token != NULL)
    CloseHandle (token);
  if (!ok) {
    owner_acl_clear (security);
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to construct the owner-only test ACL: Win32 error %lu",
        (gulong) saved_error);
  }
  return ok;
}

static gboolean
apply_owner_acl (const gchar *path, BYTE ace_flags, GError **error)
{
  WylTestOwnerAcl security;
  g_autofree gunichar2 *wide = NULL;

  if (!owner_acl_init (ace_flags, &security, error))
    return FALSE;
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, error);
  if (wide == NULL) {
    owner_acl_clear (&security);
    return FALSE;
  }
  DWORD status = SetNamedSecurityInfoW ((LPWSTR) wide, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
      | PROTECTED_DACL_SECURITY_INFORMATION, security.user, NULL,
      security.acl, NULL);
  owner_acl_clear (&security);
  if (status == ERROR_SUCCESS)
    return TRUE;
  g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
      "Failed to protect test path '%s': Win32 error %lu", path,
      (gulong) status);
  return FALSE;
}

static gchar *
canonical_windows_path (const gchar *path, GError **error)
{
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, error);
  if (wide == NULL)
    return NULL;
  HANDLE handle = CreateFileW ((LPCWSTR) wide, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (handle == INVALID_HANDLE_VALUE) {
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to open test root '%s': Win32 error %lu", path,
        (gulong) GetLastError ());
    return NULL;
  }
  DWORD needed = GetFinalPathNameByHandleW (handle, NULL, 0,
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (needed == 0) {
    DWORD saved_error = GetLastError ();
    CloseHandle (handle);
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to canonicalize test root '%s': Win32 error %lu", path,
        (gulong) saved_error);
    return NULL;
  }
  g_autofree WCHAR *resolved = g_new0 (WCHAR, needed + 1);
  DWORD length = GetFinalPathNameByHandleW (handle, resolved, needed + 1,
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  DWORD saved_error = GetLastError ();
  CloseHandle (handle);
  if (length == 0 || length > needed) {
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to canonicalize test root '%s': Win32 error %lu", path,
        (gulong) saved_error);
    return NULL;
  }
  const WCHAR *dos_path = resolved;
  if (wcsncmp (resolved, L"\\\\?\\UNC\\", 8) == 0) {
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "The fact graph tests require a local drive, not a UNC path");
    return NULL;
  }
  if (wcsncmp (resolved, L"\\\\?\\", 4) == 0)
    dos_path += 4;

  DWORD long_capacity = MAX_PATH;
  g_autofree WCHAR *long_path = NULL;
  for (;;) {
    if (long_capacity > G_MAXSIZE / sizeof *long_path) {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_NOMEM,
          "The expanded test root '%s' is too long", path);
      return NULL;
    }
    g_clear_pointer (&long_path, g_free);
    long_path = g_try_new0 (WCHAR, long_capacity);
    if (long_path == NULL) {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_NOMEM,
          "Failed to allocate the expanded test root '%s'", path);
      return NULL;
    }
    DWORD long_length = GetLongPathNameW (dos_path, long_path, long_capacity);
    if (long_length == 0) {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
          "Failed to expand the test root '%s': Win32 error %lu", path,
          (gulong) GetLastError ());
      return NULL;
    }
    if (long_length < long_capacity)
      break;
    long_capacity = long_length;
  }
  return g_utf16_to_utf8 ((const gunichar2 *) long_path, -1, NULL, NULL, error);
}

static gunichar2 *
test_filesystem_wide_path (const gchar *path, GError **error)
{
  glong units = 0;
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, &units, error);
  if (wide == NULL)
    return NULL;
  for (glong i = 0; i < units; i++) {
    if (wide[i] == '/')
      wide[i] = '\\';
  }
  gboolean absolute_drive = units >= 3 && ((wide[0] >= 'A' && wide[0] <= 'Z')
      || (wide[0] >= 'a' && wide[0] <= 'z'))
      && wide[1] == ':' && wide[2] == '\\';
  if (!absolute_drive || units < MAX_PATH)
    return g_steal_pointer (&wide);

  gunichar2 *extended = g_try_new (gunichar2, (gsize) units + 5);
  if (extended == NULL) {
    g_set_error_literal (error, G_FILE_ERROR, G_FILE_ERROR_NOMEM,
        "Failed to allocate a native test path");
    return NULL;
  }
  memcpy (extended, L"\\\\?\\", 4 * sizeof *extended);
  memcpy (extended + 4, wide, ((gsize) units + 1) * sizeof *extended);
  return extended;
}
#endif

gboolean
wyl_test_create_secure_directory (const gchar *path, GError **error)
{
#ifdef G_OS_WIN32
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, error);
  if (wide == NULL)
    return FALSE;
  if (!CreateDirectoryW ((LPCWSTR) wide, NULL)) {
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to create test directory '%s': Win32 error %lu", path,
        (gulong) GetLastError ());
    return FALSE;
  }
  if (apply_owner_acl (path, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, error))
    return TRUE;
  (void) RemoveDirectoryW ((LPCWSTR) wide);
  return FALSE;
#else
  if (g_mkdir (path, 0700) == 0)
    return TRUE;
  gint saved_errno = errno;
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
      "Failed to create test directory '%s': %s", path,
      g_strerror (saved_errno));
  return FALSE;
#endif
}

gboolean
wyl_test_secure_regular_file (const gchar *path, GError **error)
{
#ifdef G_OS_WIN32
  return apply_owner_acl (path, 0, error);
#else
  if (g_chmod (path, 0600) == 0)
    return TRUE;
  gint saved_errno = errno;
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
      "Failed to protect test file '%s': %s", path, g_strerror (saved_errno));
  return FALSE;
#endif
}

gboolean
wyl_test_create_directory_alias (const gchar *alias, const gchar *target,
    GError **error)
{
#ifdef G_OS_WIN32
  g_autofree gunichar2 *wide_alias = g_utf8_to_utf16 (alias, -1, NULL, NULL,
      error);
  g_autofree gunichar2 *wide_target = g_utf8_to_utf16 (target, -1, NULL, NULL,
      error);
  if (wide_alias == NULL || wide_target == NULL)
    return FALSE;

  gsize target_units = wcslen ((const WCHAR *) wide_target);
  g_autofree WCHAR *substitute = g_new (WCHAR, target_units + 5);
  if (swprintf (substitute, target_units + 5, L"\\??\\%ls",
          (const WCHAR *) wide_target) < 0) {
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to construct a junction target for '%s'", target);
    return FALSE;
  }
  gsize substitute_bytes = wcslen (substitute) * sizeof (WCHAR);
  gsize target_bytes = target_units * sizeof (WCHAR);
  gsize path_bytes = substitute_bytes + sizeof (WCHAR) + target_bytes
      + sizeof (WCHAR);
  gsize total = offsetof (WylTestMountPointReparseData, path_buffer)
      + path_bytes;
  if (total > MAXIMUM_REPARSE_DATA_BUFFER_SIZE) {
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "The junction target '%s' is too long", target);
    return FALSE;
  }
  if (!CreateDirectoryW ((LPCWSTR) wide_alias, NULL)) {
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to create junction directory '%s': Win32 error %lu", alias,
        (gulong) GetLastError ());
    return FALSE;
  }

  HANDLE handle = CreateFileW ((LPCWSTR) wide_alias, GENERIC_WRITE, 0, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      NULL);
  if (handle == INVALID_HANDLE_VALUE) {
    DWORD saved_error = GetLastError ();
    (void) RemoveDirectoryW ((LPCWSTR) wide_alias);
    g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
        "Failed to open junction directory '%s': Win32 error %lu", alias,
        (gulong) saved_error);
    return FALSE;
  }

  g_autofree WylTestMountPointReparseData *data = g_malloc0 (total);
  data->tag = IO_REPARSE_TAG_MOUNT_POINT;
  data->data_length = (WORD) (total - 8);
  data->substitute_length = (WORD) substitute_bytes;
  data->print_offset = (WORD) (substitute_bytes + sizeof (WCHAR));
  data->print_length = (WORD) target_bytes;
  memcpy (data->path_buffer, substitute, substitute_bytes);
  memcpy ((guint8 *) data->path_buffer + data->print_offset, wide_target,
      target_bytes);
  DWORD returned = 0;
  gboolean created = DeviceIoControl (handle, FSCTL_SET_REPARSE_POINT, data,
      (DWORD) total, NULL, 0, &returned, NULL);
  DWORD saved_error = GetLastError ();
  CloseHandle (handle);
  if (created)
    return TRUE;
  (void) RemoveDirectoryW ((LPCWSTR) wide_alias);
  g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
      "Failed to create junction '%s': Win32 error %lu", alias,
      (gulong) saved_error);
  return FALSE;
#else
  if (symlink (target, alias) == 0)
    return TRUE;
  gint saved_errno = errno;
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
      "Failed to create directory alias '%s': %s", alias,
      g_strerror (saved_errno));
  return FALSE;
#endif
}

gboolean
wyl_test_remove_directory_alias (const gchar *alias, GError **error)
{
#ifdef G_OS_WIN32
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (alias, -1, NULL, NULL, error);
  if (wide == NULL)
    return FALSE;
  if (RemoveDirectoryW ((LPCWSTR) wide))
    return TRUE;
  DWORD saved_error = GetLastError ();
  g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
      "Failed to remove junction '%s': Win32 error %lu", alias,
      (gulong) saved_error);
  return FALSE;
#else
  if (g_remove (alias) == 0)
    return TRUE;
  gint saved_errno = errno;
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
      "Failed to remove directory alias '%s': %s", alias,
      g_strerror (saved_errno));
  return FALSE;
#endif
}

gboolean
wyl_test_remove_empty_directory (const gchar *path, GError **error)
{
#ifdef G_OS_WIN32
  g_autofree gunichar2 *wide = test_filesystem_wide_path (path, error);
  if (wide == NULL)
    return FALSE;
  if (RemoveDirectoryW ((LPCWSTR) wide))
    return TRUE;
  DWORD saved_error = GetLastError ();
  if (saved_error == ERROR_FILE_NOT_FOUND
      || saved_error == ERROR_PATH_NOT_FOUND)
    return TRUE;
  g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
      "Failed to remove an empty test directory: Win32 error %lu",
      (gulong) saved_error);
  return FALSE;
#else
  if (g_rmdir (path) == 0 || errno == ENOENT)
    return TRUE;
  gint saved_errno = errno;
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
      "Failed to remove an empty test directory: %s", g_strerror (saved_errno));
  return FALSE;
#endif
}

gboolean
wyl_test_path_exists (const gchar *path, gboolean *out_exists, GError **error)
{
  if (out_exists == NULL) {
    g_set_error_literal (error, G_FILE_ERROR, G_FILE_ERROR_INVAL,
        "Missing test path existence output");
    return FALSE;
  }
  *out_exists = FALSE;
#ifdef G_OS_WIN32
  g_autofree gunichar2 *wide = test_filesystem_wide_path (path, error);
  if (wide == NULL)
    return FALSE;
  DWORD attributes = GetFileAttributesW ((LPCWSTR) wide);
  if (attributes != INVALID_FILE_ATTRIBUTES) {
    *out_exists = TRUE;
    return TRUE;
  }
  DWORD saved_error = GetLastError ();
  if (saved_error == ERROR_FILE_NOT_FOUND
      || saved_error == ERROR_PATH_NOT_FOUND)
    return TRUE;
  g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
      "Failed to inspect a native test path: Win32 error %lu",
      (gulong) saved_error);
  return FALSE;
#else
  struct stat status;
  if (lstat (path, &status) == 0) {
    *out_exists = TRUE;
    return TRUE;
  }
  gint saved_errno = errno;
  if (saved_errno == ENOENT)
    return TRUE;
  g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
      "Failed to inspect a test path: %s", g_strerror (saved_errno));
  return FALSE;
#endif
}

gchar *
wyl_test_make_secure_fact_root (const gchar *tmpl, GError **error)
{
  g_autofree gchar *created = g_dir_make_tmp (tmpl, error);
  if (created == NULL)
    return NULL;
#ifdef G_OS_WIN32
  if (!apply_owner_acl (created,
          OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, error)) {
    (void) g_rmdir (created);
    return NULL;
  }
  gchar *root = canonical_windows_path (created, error);
#else
  if (g_chmod (created, 0700) != 0) {
    gint saved_errno = errno;
    g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
        "Failed to protect test root '%s': %s", created,
        g_strerror (saved_errno));
    (void) g_rmdir (created);
    return NULL;
  }
  gchar *root = realpath (created, NULL);
  if (root == NULL) {
    gint saved_errno = errno;
    g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
        "Failed to resolve temporary directory '%s': %s", created,
        g_strerror (saved_errno));
  }
#endif
  if (root != NULL)
    return root;
  (void) g_rmdir (created);
  return NULL;
}

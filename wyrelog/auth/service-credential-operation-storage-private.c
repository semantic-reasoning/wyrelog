/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "auth/service-credential-operation-storage-private.h"

#include <errno.h>
#include <glib/gstdio.h>
#include <sys/stat.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#include <fcntl.h>
#else
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wchar.h>
#endif

#define JOURNAL_SUBPATH "wyrelog/service-credential-operations"

static gboolean
path_is_owner_private_directory (const gchar *path)
{
  GStatBuf st;
  if (g_lstat (path, &st) != 0)
    return FALSE;
#ifdef G_OS_WIN32
  if (!g_file_test (path, G_FILE_TEST_IS_DIR))
    return FALSE;
#else
  if (!S_ISDIR (st.st_mode))
    return FALSE;
#endif
#ifndef G_OS_WIN32
  if (st.st_uid != geteuid () || (st.st_mode & 0777) != 0700)
    return FALSE;
#endif
  return TRUE;
}

#ifndef G_OS_WIN32
static gboolean
fd_is_owner_private_directory (gint fd)
{
  struct stat st;
  return fstat (fd, &st) == 0 && S_ISDIR (st.st_mode)
      && st.st_uid == geteuid () && (st.st_mode & 0777) == 0700;
}
#endif

#ifndef G_OS_WIN32
static gboolean
path_has_safe_ancestors (const gchar *path)
{
  if (!g_path_is_absolute (path))
    return FALSE;
  g_auto (GStrv) parts = g_strsplit (path + 1, "/", -1);
  g_autofree gchar *prefix = g_strdup ("/");
  for (gsize i = 0; parts != NULL && parts[i] != NULL; i++) {
    if (parts[i][0] == '\0' || g_strcmp0 (parts[i], ".") == 0
        || g_strcmp0 (parts[i], "..") == 0 || strchr (parts[i], '\\') != NULL)
      return FALSE;
    g_autofree gchar *next = g_build_filename (prefix, parts[i], NULL);
    GStatBuf st;
    /* Platform-managed prefixes (for example macOS's /var -> /private/var)
     * may legitimately be symlinks.  The final root is still checked with
     * lstat() and opened with O_NOFOLLOW below, so a caller cannot select a
     * symlink as the journal root itself. */
    if (g_lstat (next, &st) == 0 && !S_ISDIR (st.st_mode)
        && !S_ISLNK (st.st_mode))
      return FALSE;
    g_free (g_steal_pointer (&prefix));
    prefix = g_steal_pointer (&next);
  }
  return TRUE;
}
#endif

static wyrelog_error_t
ensure_private_directory (const gchar *path)
{
  if (path == NULL || path[0] == '\0')
    return WYRELOG_E_INVALID;
#ifndef G_OS_WIN32
  if (!path_has_safe_ancestors (path))
    return WYRELOG_E_POLICY;
#endif
  if (g_mkdir_with_parents (path, 0700) != 0 && errno != EEXIST)
    return errno == EACCES || errno == EPERM || errno == ENOTDIR
        ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  if (!path_is_owner_private_directory (path))
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static gchar *
resolve_default_root (void)
{
#ifdef G_OS_WIN32
  wchar_t value[32768];
  DWORD n = GetEnvironmentVariableW (L"LOCALAPPDATA", value,
      G_N_ELEMENTS (value));
  if (n == 0 || n >= G_N_ELEMENTS (value))
    return NULL;
  g_autofree gchar *base = (gchar *) g_utf16_to_utf8 ((gunichar2 *) value, n,
      NULL, NULL, NULL);
  return base == NULL ? NULL : g_build_filename (base, "Wyrelog", "state",
      "service-credential-operations", NULL);
#else
  const gchar *state = g_getenv ("XDG_STATE_HOME");
  if (state == NULL || state[0] == '\0') {
    const gchar *home = g_get_home_dir ();
    if (home == NULL)
      return NULL;
    return g_build_filename (home, ".local", "state", JOURNAL_SUBPATH, NULL);
  }
  return g_build_filename (state, JOURNAL_SUBPATH, NULL);
#endif
}

#ifdef G_OS_WIN32
static gboolean
win_path_is_absolute (const gchar *path)
{
  return path != NULL && g_ascii_isalpha (path[0]) && path[1] == ':'
      && (path[2] == '\\' || path[2] == '/')
      && !g_str_has_prefix (path, "\\\\")
      && !g_str_has_prefix (path, "//")
      && !g_str_has_prefix (path, "\\\\?\\");
}

static gboolean
win_component_is_safe (const gchar *component)
{
  gsize len;
  if (component == NULL || component[0] == '\0'
      || g_str_equal (component, ".") || g_str_equal (component, ".."))
    return FALSE;
  len = strlen (component);
  return len > 0 && component[len - 1] != '.' && component[len - 1] != ' '
      && strchr (component, ':') == NULL;
}

static gboolean
win_sid_matches_current_user (PSID sid)
{
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *user = NULL;
  gboolean result = FALSE;
  if (sid == NULL || !OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY,
          &token))
    return FALSE;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    goto out;
  user = g_malloc (needed);
  if (user == NULL || !GetTokenInformation (token, TokenUser, user, needed,
          &needed))
    goto out;
  result = EqualSid (sid, user->User.Sid);
out:
  g_free (user);
  CloseHandle (token);
  return result;
}

static gboolean
win_descriptor_is_owner_only (PSECURITY_DESCRIPTOR descriptor)
{
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  BOOL present = FALSE, defaulted = FALSE;
  PACL dacl = NULL;
  PSID owner = NULL;
  ACL_SIZE_INFORMATION size = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;
  if (descriptor == NULL
      || !GetSecurityDescriptorControl (descriptor, &control, &revision)
      || (control & SE_DACL_PROTECTED) == 0
      || !GetSecurityDescriptorOwner (descriptor, &owner, NULL)
      || owner == NULL || !win_sid_matches_current_user (owner)
      || !GetSecurityDescriptorDacl (descriptor, &present, &dacl, &defaulted)
      || !present || dacl == NULL || defaulted
      || !GetAclInformation (dacl, &size, sizeof size, AclSizeInformation)
      || size.AceCount != 1
      || !GetAce (dacl, 0, (LPVOID *) & ace) || ace == NULL
      || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE
      || ace->Header.AceFlags != 0 || ace->Mask != FILE_ALL_ACCESS)
    return FALSE;
  return EqualSid (owner, (PSID) & ace->SidStart);
}

static gboolean
win_handle_is_owner_only (HANDLE handle)
{
  PSECURITY_DESCRIPTOR descriptor = NULL;
  DWORD rc;
  gboolean result = FALSE;
  if (handle == INVALID_HANDLE_VALUE || handle == NULL)
    return FALSE;
  rc = GetSecurityInfo (handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL,
      NULL, NULL, &descriptor);
  if (rc == ERROR_SUCCESS) {
    result = win_descriptor_is_owner_only (descriptor);
    LocalFree (descriptor);
  }
  return result;
}

static gboolean
win_init_owner_only_attributes (SECURITY_ATTRIBUTES *attrs,
    PSECURITY_DESCRIPTOR *out_descriptor)
{
  static const wchar_t sddl[] = L"D:P(A;;FA;;;OW)";
  if (attrs == NULL || out_descriptor == NULL
      || !ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl,
          SDDL_REVISION_1, out_descriptor, NULL))
    return FALSE;
  memset (attrs, 0, sizeof *attrs);
  attrs->nLength = sizeof *attrs;
  attrs->lpSecurityDescriptor = *out_descriptor;
  return TRUE;
}

static gboolean
win_path_under_localappdata (const gchar *path)
{
  wchar_t value[32768];
  DWORD n = GetEnvironmentVariableW (L"LOCALAPPDATA", value,
      G_N_ELEMENTS (value));
  g_autofree gchar *base = NULL;
  gsize path_len;
  gsize base_len;
  if (path == NULL)
    return FALSE;
  if (n == 0 || n >= G_N_ELEMENTS (value))
    return FALSE;
  base = (gchar *) g_utf16_to_utf8 ((gunichar2 *) value, n, NULL, NULL, NULL);
  if (base == NULL)
    return FALSE;
  while (g_str_has_suffix (base, "\\") || g_str_has_suffix (base, "/"))
    base[strlen (base) - 1] = '\0';
  path_len = strlen (path);
  base_len = strlen (base);
  if (path_len < base_len)
    return FALSE;
  return g_ascii_strncasecmp (path, base, base_len) == 0
      && (path[base_len] == '\0' || path[base_len] == '\\'
      || path[base_len] == '/');
}

static wyrelog_error_t
win_open_root (const gchar *path, HANDLE *out, GPtrArray **out_ancestors)
{
  g_auto (GStrv) parts = NULL;
  g_autofree gchar *prefix = NULL;
  SECURITY_ATTRIBUTES attrs;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  GPtrArray *handles = NULL;
  gboolean after_localappdata = FALSE;
  if (!win_path_is_absolute (path) || !win_path_under_localappdata (path))
    return WYRELOG_E_POLICY;
  parts = g_strsplit_set (path + 3, "\\/", -1);
  prefix = g_strdup_printf ("%c:\\\\", path[0]);
  handles = g_ptr_array_new ();
  if (handles == NULL)
    return WYRELOG_E_NOMEM;
  for (gsize i = 0; parts[i] != NULL; i++) {
    g_autofree gchar *next = NULL;
    if (!win_component_is_safe (parts[i]))
      goto policy;
    next = g_build_filename (prefix, parts[i], NULL);
    g_autofree gunichar2 *wide = g_utf8_to_utf16 (next, -1, NULL, NULL, NULL);
    if (wide == NULL)
      goto invalid;
    HANDLE h = CreateFileW ((LPCWSTR) wide,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
      if (GetLastError () != ERROR_FILE_NOT_FOUND
          && GetLastError () != ERROR_PATH_NOT_FOUND)
        goto policy;
      if (!win_init_owner_only_attributes (&attrs, &descriptor)
          || (!CreateDirectoryW ((LPCWSTR) wide, &attrs)
              && GetLastError () != ERROR_ALREADY_EXISTS)) {
        if (descriptor != NULL)
          LocalFree (descriptor);
        goto policy;
      }
      LocalFree (descriptor);
      descriptor = NULL;
      h = CreateFileW ((LPCWSTR) wide,
          FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL |
          SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          NULL, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    if (h == INVALID_HANDLE_VALUE)
      goto policy;
    BY_HANDLE_FILE_INFORMATION info = { 0 };
    if (!GetFileInformationByHandle (h, &info)
        || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
      CloseHandle (h);
      goto policy;
    }
    if ((after_localappdata || parts[i + 1] == NULL)
        && !win_handle_is_owner_only (h)) {
      CloseHandle (h);
      goto policy;
    }
    g_ptr_array_add (handles, h);
    g_free (g_steal_pointer (&prefix));
    prefix = g_steal_pointer (&next);
    if (win_path_under_localappdata (prefix))
      after_localappdata = TRUE;
  }
  if (handles->len == 0)
    goto policy;
  *out = g_ptr_array_index (handles, handles->len - 1);
  if (out_ancestors != NULL)
    *out_ancestors = handles;
  else
    g_ptr_array_free (handles, TRUE);
  return WYRELOG_E_OK;
policy:
  if (descriptor != NULL)
    LocalFree (descriptor);
invalid:
  if (handles != NULL) {
    for (guint i = 0; i < handles->len; i++)
      CloseHandle (g_ptr_array_index (handles, i));
    g_ptr_array_free (handles, TRUE);
  }
  return WYRELOG_E_POLICY;
}
#endif

wyrelog_error_t
    wyl_service_credential_operation_storage_open
    (const gchar * override_path,
    WylServiceCredentialOperationStorage * out_storage)
{
  if (out_storage != NULL)
    wyl_service_credential_operation_storage_clear (out_storage);
  if (out_storage == NULL)
    return WYRELOG_E_INVALID;
  gchar *root = (override_path != NULL && override_path[0] != '\0')
      ? g_strdup (override_path) : resolve_default_root ();
  if (root == NULL)
    return WYRELOG_E_NOMEM;
#ifndef G_OS_WIN32
  wyrelog_error_t rc = ensure_private_directory (root);
  if (rc != WYRELOG_E_OK) {
    g_free (root);
    return rc;
  }
#else
  wyrelog_error_t rc = WYRELOG_E_OK;
#endif
#ifndef G_OS_WIN32
  gint root_fd = open (root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root_fd < 0) {
    g_free (root);
    return errno == EACCES || errno == EPERM || errno == ELOOP
        ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  if (!fd_is_owner_private_directory (root_fd)) {
    close (root_fd);
    g_free (root);
    return WYRELOG_E_POLICY;
  }
#endif
  out_storage->root_path = root;
#ifndef G_OS_WIN32
  out_storage->root_fd = root_fd;
  out_storage->owns_root_fd = TRUE;
#else
  HANDLE root_handle = INVALID_HANDLE_VALUE;
  rc = win_open_root (root, &root_handle, &out_storage->ancestor_handles);
  if (rc != WYRELOG_E_OK) {
    out_storage->root_path = NULL;
    g_free (root);
    return rc;
  }
  out_storage->root_handle = root_handle;
  /* #482 anchors and validates the root only.  Handle-relative child
   * linearization and replacement-race protection are owned by #483. */
  BY_HANDLE_FILE_INFORMATION root_info = { 0 };
  if (!GetFileInformationByHandle (root_handle, &root_info)) {
    wyl_service_credential_operation_storage_clear (out_storage);
    return WYRELOG_E_POLICY;
  }
  out_storage->root_volume_serial = root_info.dwVolumeSerialNumber;
  out_storage->root_file_index_high = root_info.nFileIndexHigh;
  out_storage->root_file_index_low = root_info.nFileIndexLow;
#endif
  return WYRELOG_E_OK;
}

void wyl_service_credential_operation_storage_clear
    (WylServiceCredentialOperationStorage * storage)
{
  if (storage == NULL)
    return;
#ifndef G_OS_WIN32
  if (storage->owns_root_fd && storage->root_fd >= 0)
    close (storage->root_fd);
  storage->root_fd = -1;
  storage->owns_root_fd = FALSE;
#else
  if (storage->ancestor_handles != NULL) {
    for (guint i = 0; i < storage->ancestor_handles->len; i++) {
      HANDLE handle = g_ptr_array_index (storage->ancestor_handles, i);
      if (handle != INVALID_HANDLE_VALUE && handle != NULL)
        CloseHandle (handle);
    }
    g_ptr_array_free (storage->ancestor_handles, TRUE);
    storage->ancestor_handles = NULL;
  } else if (storage->root_handle != INVALID_HANDLE_VALUE
      && storage->root_handle != NULL) {
    CloseHandle (storage->root_handle);
  }
  storage->root_handle = INVALID_HANDLE_VALUE;
  storage->root_volume_serial = 0;
  storage->root_file_index_high = 0;
  storage->root_file_index_low = 0;
#endif
  g_clear_pointer (&storage->root_path, g_free);
}

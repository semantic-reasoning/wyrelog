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
#include <sys/file.h>
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
win_sid_matches_token_owner (PSID sid)
{
  HANDLE token = NULL;
  DWORD owner_needed = 0;
  DWORD user_needed = 0;
  TOKEN_OWNER *owner_info = NULL;
  TOKEN_USER *user_info = NULL;
  gboolean result = FALSE;
  if (sid == NULL || !OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY,
          &token))
    return FALSE;
  /* Elevated services can expose either the token owner or interactive user
   * as the ACL owner; every other descriptor SID remains rejected. */
  GetTokenInformation (token, TokenOwner, NULL, 0, &owner_needed);
  if (GetLastError () == ERROR_INSUFFICIENT_BUFFER && owner_needed != 0) {
    owner_info = g_malloc (owner_needed);
    if (owner_info != NULL && GetTokenInformation (token, TokenOwner,
            owner_info, owner_needed, &owner_needed))
      result = owner_info->Owner != NULL && EqualSid (sid, owner_info->Owner);
  }
  if (!result) {
    GetTokenInformation (token, TokenUser, NULL, 0, &user_needed);
    if (GetLastError () == ERROR_INSUFFICIENT_BUFFER && user_needed != 0) {
      user_info = g_malloc (user_needed);
      if (user_info != NULL && GetTokenInformation (token, TokenUser,
              user_info, user_needed, &user_needed))
        result = user_info->User.Sid != NULL
            && EqualSid (sid, user_info->User.Sid);
    }
  }
out:
  g_free (owner_info);
  g_free (user_info);
  CloseHandle (token);
  return result;
}

static PSID
win_copy_token_sid (TOKEN_INFORMATION_CLASS information_class)
{
  HANDLE token = NULL;
  DWORD needed = 0;
  gpointer information = NULL;
  PSID source = NULL;
  PSID copy = NULL;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return NULL;
  GetTokenInformation (token, information_class, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    goto out;
  information = g_malloc (needed);
  if (information == NULL || !GetTokenInformation (token, information_class,
          information, needed, &needed))
    goto out;
  source = information_class == TokenOwner
      ? ((TOKEN_OWNER *) information)->Owner
      : ((TOKEN_USER *) information)->User.Sid;
  if (source == NULL || !IsValidSid (source))
    goto out;
  DWORD length = GetLengthSid (source);
  if (length == 0)
    goto out;
  copy = g_malloc (length);
  if (copy == NULL || !CopySid (length, copy, source)) {
    g_free (copy);
    copy = NULL;
  }
out:
  g_free (information);
  CloseHandle (token);
  return copy;
}

static PSID
win_copy_preferred_token_sid (void)
{
  PSID sid = win_copy_token_sid (TokenOwner);
  return sid != NULL ? sid : win_copy_token_sid (TokenUser);
}

static gboolean
win_descriptor_is_owner_only (PSECURITY_DESCRIPTOR descriptor)
{
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  BOOL present = FALSE, defaulted = FALSE;
  BOOL owner_defaulted = FALSE;
  PACL dacl = NULL;
  PSID owner = NULL;
  ACL_SIZE_INFORMATION size = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;
  if (descriptor == NULL)
    return FALSE;
  if (!GetSecurityDescriptorControl (descriptor, &control, &revision))
    return FALSE;
  if ((control & SE_DACL_PROTECTED) == 0)
    return FALSE;
  if (!GetSecurityDescriptorOwner (descriptor, &owner, &owner_defaulted))
    return FALSE;
  if (owner == NULL)
    return FALSE;
  if (!win_sid_matches_token_owner (owner))
    return FALSE;
  if (!GetSecurityDescriptorDacl (descriptor, &present, &dacl, &defaulted))
    return FALSE;
  if (!present || dacl == NULL || defaulted)
    return FALSE;
  if (!GetAclInformation (dacl, &size, sizeof size, AclSizeInformation))
    return FALSE;
  if (size.AceCount != 1)
    return FALSE;
  if (!GetAce (dacl, 0, (LPVOID *) & ace))
    return FALSE;
  if (ace == NULL || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE
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
    PSECURITY_DESCRIPTOR *out_descriptor, PSID owner_sid)
{
  LPWSTR sid_string = NULL;
  g_autofree wchar_t *sddl = NULL;
  gsize sid_length;
  if (attrs == NULL || out_descriptor == NULL || owner_sid == NULL
      || !ConvertSidToStringSidW (owner_sid, &sid_string))
    return FALSE;
  sid_length = wcslen (sid_string);
  sddl = g_new (wchar_t, 32 + 2 * sid_length);
  if (sddl == NULL
      || swprintf (sddl, 32 + 2 * sid_length,
          L"O:%lsD:P(A;;FA;;;%ls)", sid_string, sid_string) < 0
      || !ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl,
          SDDL_REVISION_1, out_descriptor, NULL)) {
    LocalFree (sid_string);
    return FALSE;
  }
  LocalFree (sid_string);
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
    DWORD directory_access = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
        | READ_CONTROL | SYNCHRONIZE;
    /* Only the final root is flushed after child namespace mutations.
     * FlushFileBuffers requires write access; ancestor anchors remain
     * read-only because they are held solely to pin the validated walk. */
    if (parts[i + 1] == NULL)
      directory_access |= GENERIC_WRITE | FILE_DELETE_CHILD;
    HANDLE h = CreateFileW ((LPCWSTR) wide, directory_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
      if (GetLastError () != ERROR_FILE_NOT_FOUND
          && GetLastError () != ERROR_PATH_NOT_FOUND)
        goto policy;
      g_autofree PSID owner_sid = win_copy_preferred_token_sid ();
      if (!win_init_owner_only_attributes (&attrs, &descriptor, owner_sid)
          || (!CreateDirectoryW ((LPCWSTR) wide, &attrs)
              && GetLastError () != ERROR_ALREADY_EXISTS)) {
        if (descriptor != NULL)
          LocalFree (descriptor);
        goto policy;
      }
      LocalFree (descriptor);
      descriptor = NULL;
      h = CreateFileW ((LPCWSTR) wide, directory_access,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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

void wyl_service_credential_operation_child_name_clear
    (WylServiceCredentialOperationChildName * name)
{
  if (name == NULL)
    return;
  g_clear_pointer (&name->component, g_free);
}

wyrelog_error_t
    wyl_service_credential_operation_child_name_validate
    (const gchar * raw, WylServiceCredentialOperationChildName * out_name)
{
  gsize length;
  if (out_name == NULL)
    return WYRELOG_E_INVALID;
  wyl_service_credential_operation_child_name_clear (out_name);
  if (raw == NULL || raw[0] == '\0' || !g_utf8_validate (raw, -1, NULL))
    return WYRELOG_E_POLICY;
  length = strlen (raw);
  if (length > WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_MAX_BYTES
      || g_str_equal (raw, ".") || g_str_equal (raw, ".."))
    return WYRELOG_E_POLICY;
  {
    static const gchar *const reserved[] = {
      "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
      "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
      "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", NULL
    };
    g_autofree gchar *device = g_strdup (raw);
    gchar *dot = device != NULL ? strchr (device, '.') : NULL;
    if (device == NULL)
      return WYRELOG_E_NOMEM;
    if (dot != NULL)
      *dot = '\0';
    for (gsize i = 0; reserved[i] != NULL; i++)
      if (g_ascii_strcasecmp (device, reserved[i]) == 0)
        return WYRELOG_E_POLICY;
  }
  for (gsize i = 0; i < length; i++) {
    gchar c = raw[i];
    if ((guchar) c < 0x20 || c == '/' || c == '\\' || c == ':'
        || c == '<' || c == '>' || c == '"' || c == '|' || c == '?' || c == '*')
      return WYRELOG_E_POLICY;
  }
  if (raw[length - 1] == '.' || raw[length - 1] == ' ')
    return WYRELOG_E_POLICY;
  out_name->component = g_strdup (raw);
  return out_name->component != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

void wyl_service_credential_operation_root_anchor_clear
    (WylServiceCredentialOperationRootAnchor * anchor)
{
  if (anchor == NULL)
    return;
  anchor->initialized = FALSE;
  anchor->identity_a = 0;
  anchor->identity_b = 0;
}

wyrelog_error_t
    wyl_service_credential_operation_storage_capture_anchor
    (const WylServiceCredentialOperationStorage * storage,
    WylServiceCredentialOperationRootAnchor * out_anchor)
{
  WylServiceCredentialOperationRootAnchor captured =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  if (storage == NULL || out_anchor == NULL)
    return WYRELOG_E_INVALID;
#ifndef G_OS_WIN32
  struct stat info;
  if (storage->root_fd < 0 || fstat (storage->root_fd, &info) != 0)
    return WYRELOG_E_POLICY;
  captured.identity_a = (guint64) info.st_dev;
  captured.identity_b = (guint64) info.st_ino;
#else
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  if (storage->root_handle == INVALID_HANDLE_VALUE
      || storage->root_handle == NULL
      || storage->root_volume_serial == 0
      || (storage->root_file_index_high == 0
          && storage->root_file_index_low == 0)
      || !GetFileInformationByHandle (storage->root_handle, &info)
      || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
      || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || info.dwVolumeSerialNumber != storage->root_volume_serial
      || info.nFileIndexHigh != storage->root_file_index_high
      || info.nFileIndexLow != storage->root_file_index_low)
    return WYRELOG_E_POLICY;
  captured.identity_a = info.dwVolumeSerialNumber;
  captured.identity_b = ((guint64) info.nFileIndexHigh << 32)
      | info.nFileIndexLow;
#endif
  captured.initialized = TRUE;
  *out_anchor = captured;
  return WYRELOG_E_OK;
}

gboolean
    wyl_service_credential_operation_storage_anchor_matches
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor)
{
  WylServiceCredentialOperationRootAnchor current =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  return anchor != NULL && anchor->initialized
      && wyl_service_credential_operation_storage_capture_anchor
      (storage, &current) == WYRELOG_E_OK
      && current.initialized
      && current.identity_a == anchor->identity_a
      && current.identity_b == anchor->identity_b;
}

#ifndef G_OS_WIN32
static wyrelog_error_t
posix_child_errno (gint error)
{
  if (error == ENOENT)
    return WYRELOG_E_NOT_FOUND;
  if (error == EEXIST || error == ELOOP || error == ENOTDIR
      || error == EACCES || error == EPERM)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_IO;
}

static gboolean
posix_child_file_is_private (gint fd)
{
  struct stat info;
  if (fstat (fd, &info) != 0 || !S_ISREG (info.st_mode)
      || info.st_uid != geteuid () || (info.st_mode & 0777) != 0600)
    return FALSE;
  return TRUE;
}

static wyrelog_error_t
posix_child_open (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, gint flags,
    gint *out_fd)
{
  if (out_fd == NULL || storage == NULL || anchor == NULL || name == NULL
      || name->component == NULL || storage->root_fd < 0
      || !anchor->initialized
      || !wyl_service_credential_operation_storage_anchor_matches
      (storage, anchor))
    return WYRELOG_E_POLICY;
  gint fd = openat (storage->root_fd, name->component,
      flags | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return posix_child_errno (errno);
  if (!posix_child_file_is_private (fd)
      || !wyl_service_credential_operation_storage_anchor_matches
      (storage, anchor)) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
posix_child_write_all (gint fd, GBytes *bytes)
{
  gsize size = 0;
  const guint8 *data = bytes != NULL ? g_bytes_get_data (bytes, &size) : NULL;
  if (size > WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_MAX_BYTES)
    return WYRELOG_E_POLICY;
  for (gsize offset = 0; offset < size;) {
    ssize_t written = write (fd, data + offset, size - offset);
    if (written < 0)
      return WYRELOG_E_IO;
    if (written == 0)
      return WYRELOG_E_IO;
    offset += (gsize) written;
  }
  return fsync (fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
    wyl_service_credential_operation_child_read
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, GBytes ** out_bytes)
{
  gint fd = -1;
  struct stat info;
  guint8 *data = NULL;
  gsize size;
  wyrelog_error_t rc;
  if (out_bytes == NULL)
    return WYRELOG_E_INVALID;
  *out_bytes = NULL;
  rc = posix_child_open (storage, anchor, name, O_RDONLY, &fd);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (fstat (fd, &info) != 0 || info.st_size < 0
      || (guint64) info.st_size >
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_MAX_BYTES) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  size = (gsize) info.st_size;
  data = g_malloc (size > 0 ? size : 1);
  if (data == NULL) {
    close (fd);
    return WYRELOG_E_NOMEM;
  }
  for (gsize offset = 0; offset < size;) {
    ssize_t count = read (fd, data + offset, size - offset);
    if (count <= 0) {
      g_free (data);
      close (fd);
      return WYRELOG_E_IO;
    }
    offset += (gsize) count;
  }
  close (fd);
  if (!wyl_service_credential_operation_storage_anchor_matches
      (storage, anchor)) {
    g_free (data);
    return WYRELOG_E_POLICY;
  }
  *out_bytes = g_bytes_new_take (data, size);
  return *out_bytes != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

wyrelog_error_t
    wyl_service_credential_operation_child_create
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, GBytes * bytes)
{
  if (storage == NULL || anchor == NULL || name == NULL
      || name->component == NULL || storage->root_fd < 0 || !anchor->initialized
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  gint fd = openat (storage->root_fd, name->component,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return posix_child_errno (errno);
  wyrelog_error_t rc = posix_child_write_all (fd, bytes);
  if (rc == WYRELOG_E_OK && !posix_child_file_is_private (fd))
    rc = WYRELOG_E_POLICY;
  if (close (fd) != 0 && rc == WYRELOG_E_OK)
    rc = WYRELOG_E_IO;
  if (rc != WYRELOG_E_OK) {
    /* Never unlink by pathname after the anchor has changed. */
    if (wyl_service_credential_operation_storage_anchor_matches (storage,
            anchor))
      unlinkat (storage->root_fd, name->component, 0);
    return rc;
  } else if (fsync (storage->root_fd) != 0) {
    if (wyl_service_credential_operation_storage_anchor_matches (storage,
            anchor))
      unlinkat (storage->root_fd, name->component, 0);
    rc = WYRELOG_E_IO;
  }
  if (rc == WYRELOG_E_OK
      && !wyl_service_credential_operation_storage_anchor_matches
      (storage, anchor))
    rc = WYRELOG_E_POLICY;
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_child_replace
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, GBytes * bytes)
{
  g_autofree gchar *temporary = NULL;
  g_autofree gchar *digest = NULL;
  gint fd = -1;
  wyrelog_error_t rc;
  if (storage == NULL || anchor == NULL || name == NULL
      || name->component == NULL || storage->root_fd < 0 || !anchor->initialized
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  digest = g_compute_checksum_for_string (G_CHECKSUM_SHA256,
      name->component, -1);
  temporary = g_strdup_printf (".replace-%s", digest);
  if (temporary == NULL)
    return WYRELOG_E_NOMEM;
  fd = openat (storage->root_fd, temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return posix_child_errno (errno);
  rc = posix_child_write_all (fd, bytes);
  if (rc == WYRELOG_E_OK && !posix_child_file_is_private (fd))
    rc = WYRELOG_E_POLICY;
  if (close (fd) != 0 && rc == WYRELOG_E_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK) {
    if (!wyl_service_credential_operation_storage_anchor_matches (storage,
            anchor))
      rc = WYRELOG_E_POLICY;
    else if (renameat (storage->root_fd, temporary, storage->root_fd,
            name->component) != 0)
      rc = posix_child_errno (errno);
    else if (fsync (storage->root_fd) != 0)
      rc = WYRELOG_E_IO;
  }
  if (rc != WYRELOG_E_OK
      && wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    unlinkat (storage->root_fd, temporary, 0);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_child_delete
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name)
{
  if (storage == NULL || anchor == NULL || name == NULL
      || name->component == NULL || !anchor->initialized
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  if (unlinkat (storage->root_fd, name->component, 0) != 0)
    return posix_child_errno (errno);
  if (fsync (storage->root_fd) != 0
      || !wyl_service_credential_operation_storage_anchor_matches
      (storage, anchor))
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_service_credential_operation_child_lock
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, gint * out_fd)
{
  if (out_fd == NULL)
    return WYRELOG_E_INVALID;
  *out_fd = -1;
  g_autofree gchar *digest = NULL;
  g_autofree gchar *lock_name = NULL;
  gint fd;
  wyrelog_error_t rc;
  if (storage == NULL || anchor == NULL || name == NULL
      || name->component == NULL || storage->root_fd < 0 || !anchor->initialized
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  digest = g_compute_checksum_for_string (G_CHECKSUM_SHA256,
      name->component, -1);
  lock_name = g_strdup_printf (".lock-%s", digest);
  fd = openat (storage->root_fd, lock_name,
      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return posix_child_errno (errno);
  if (!posix_child_file_is_private (fd)) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  if (!wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  rc = WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK)
    return rc;
  if (flock (*out_fd, LOCK_EX | LOCK_NB) != 0) {
    rc = (errno == EWOULDBLOCK || errno == EAGAIN)
        ? WYRELOG_E_BUSY : WYRELOG_E_IO;
    close (*out_fd);
    *out_fd = -1;
    return rc;
  }
  if (!wyl_service_credential_operation_storage_anchor_matches
      (storage, anchor)) {
    flock (*out_fd, LOCK_UN);
    close (*out_fd);
    *out_fd = -1;
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

void wyl_service_credential_operation_child_unlock
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, gint fd)
{
  (void) storage;
  (void) anchor;
  (void) name;
  if (fd >= 0) {
    /* Keep the zero-length lock file as a stable namespace object.  Removing
     * it after unlocking would let a waiter retain this inode while a third
     * contender creates and locks a replacement inode. */
    flock (fd, LOCK_UN);
    close (fd);
  }
}
#endif

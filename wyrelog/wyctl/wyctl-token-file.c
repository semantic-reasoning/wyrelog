/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 open(O_NOFOLLOW|O_CLOEXEC|O_NOCTTY) and the
 * fstat/read/close trio under strict c_std=c17. Must precede every
 * system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
/* Apple SDKs gate POSIX-only BSD features behind _DARWIN_C_SOURCE
 * when the compiler is invoked under -std=cNN (clang predefines
 * __STRICT_ANSI__). _POSIX_C_SOURCE alone does not expose
 * O_NOFOLLOW on macOS. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "wyctl-token-file.h"

#include <errno.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>
#include <wchar.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

struct _WyctlTokenFileLock
{
#ifdef G_OS_WIN32
  HANDLE handle;
  OVERLAPPED overlap;
#else
  int fd;
#endif
};

#ifdef G_OS_WIN32
static gboolean
wyctl_token_file_windows_handle_is_reparse (HANDLE handle)
{
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (handle, &info))
    return TRUE;
  return (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

static gboolean
wyctl_token_file_windows_handle_is_owner_only (HANDLE handle)
{
  DWORD needed = 0;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  PACL dacl = NULL;
  PSID owner = NULL;
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  BOOL owner_defaulted = FALSE;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  TOKEN_USER *user = NULL;
  HANDLE token = NULL;
  gboolean ok = FALSE;

  if (handle == INVALID_HANDLE_VALUE || handle == NULL
      || !OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return FALSE;
  if (!GetTokenInformation (token, TokenUser, NULL, 0, &needed)
      && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
    goto done;
  user = g_malloc0 (needed);
  if (user == NULL || !GetTokenInformation (token, TokenUser, user, needed,
      &needed))
    goto done;
  if (!GetKernelObjectSecurity (handle,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0,
      &needed) && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
    goto done;
  descriptor = g_malloc0 (needed);
  if (descriptor == NULL || !GetKernelObjectSecurity (handle,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, descriptor,
      needed, &needed))
    goto done;
  if (!GetSecurityDescriptorControl (descriptor, &control, &revision)
      || (control & SE_DACL_PROTECTED) == 0
      || !GetSecurityDescriptorOwner (descriptor, &owner, &owner_defaulted)
      || owner == NULL || !EqualSid (owner, user->User.Sid)
      || !GetSecurityDescriptorDacl (descriptor, &dacl_present, &dacl,
      &dacl_defaulted)
      || !dacl_present || dacl == NULL || dacl_defaulted)
    goto done;
  ACL_SIZE_INFORMATION acl_info = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;
  BYTE owner_rights[SECURITY_MAX_SID_SIZE];
  DWORD owner_rights_size = sizeof owner_rights;
  if (!GetAclInformation (dacl, &acl_info, sizeof acl_info,
      AclSizeInformation) || acl_info.AceCount != 1
      || !GetAce (dacl, 0, (LPVOID *) &ace) || ace == NULL
      || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE
      || !CreateWellKnownSid (WinCreatorOwnerRightsSid, NULL, owner_rights,
      &owner_rights_size))
    goto done;
  ok = EqualSid ((PSID) &ace->SidStart, owner_rights)
      && ace->Mask == FILE_ALL_ACCESS;

done:
  g_free (descriptor);
  g_free (user);
  if (token != NULL)
    CloseHandle (token);
  return ok;
}

typedef struct
{
  HANDLE handle;
  wchar_t *child_path;
} WyctlTokenFileWindowsParentAnchor;

static wchar_t *
wyctl_token_file_windows_normalize_final_path (const wchar_t *path)
{
  const wchar_t *start = path;
  gboolean unc = wcsncmp (start, L"\\\\?\\UNC\\", 8) == 0;
  if (unc)
    start += 8;
  else if (wcsncmp (start, L"\\\\?\\", 4) == 0)
    start += 4;
  gsize payload_length = wcslen (start);
  while (payload_length > 1 && (start[payload_length - 1] == L'\\'
      || start[payload_length - 1] == L'/'))
    payload_length--;
  gsize length = payload_length + (unc ? 2 : 0);
  wchar_t *normalized = g_new (wchar_t, length + 1);
  if (unc) {
    normalized[0] = L'\\';
    normalized[1] = L'\\';
    memcpy (normalized + 2, start, sizeof (wchar_t) * payload_length);
  } else {
    memcpy (normalized, start, sizeof (wchar_t) * length);
  }
  normalized[length] = L'\0';
  return normalized;
}

static gboolean
wyctl_token_file_windows_parent_matches_input (HANDLE handle,
    const wchar_t *input_parent)
{
  DWORD capacity = 512;
  wchar_t *full = NULL;
  wchar_t *actual = NULL;
  DWORD full_length = 0;
  DWORD actual_length = 0;
  for (;;) {
    full = g_realloc (full, sizeof (wchar_t) * capacity);
    full_length = GetFullPathNameW (input_parent, capacity, full, NULL);
    if (full_length == 0) {
      g_free (full);
      return FALSE;
    }
    if (full_length < capacity)
      break;
    if (capacity > UINT32_MAX / 2) {
      g_free (full);
      return FALSE;
    }
    capacity *= 2;
  }
  capacity = 512;
  for (;;) {
    actual = g_realloc (actual, sizeof (wchar_t) * capacity);
    actual_length = GetFinalPathNameByHandleW (handle, actual, capacity,
            VOLUME_NAME_DOS);
    if (actual_length == 0) {
      g_free (full);
      g_free (actual);
      return FALSE;
    }
    if (actual_length < capacity)
      break;
    if (capacity > UINT32_MAX / 2) {
      g_free (full);
      g_free (actual);
      return FALSE;
    }
    capacity *= 2;
  }
  wchar_t *normalized_full =
      wyctl_token_file_windows_normalize_final_path (full);
  wchar_t *normalized_actual =
      wyctl_token_file_windows_normalize_final_path (actual);
  gboolean matches = _wcsicmp (normalized_full, normalized_actual) == 0;
  g_free (normalized_full);
  g_free (normalized_actual);
  g_free (full);
  g_free (actual);
  return matches;
}

static void
wyctl_token_file_windows_parent_anchor_clear (WyctlTokenFileWindowsParentAnchor
    *anchor)
{
  if (anchor == NULL)
    return;
  if (anchor->handle != NULL && anchor->handle != INVALID_HANDLE_VALUE)
    CloseHandle (anchor->handle);
  g_free (anchor->child_path);
  anchor->handle = NULL;
  anchor->child_path = NULL;
}

/* Open and pin the real parent directory, then construct the final path from
 * its handle-resolved canonical name.  Omitting FILE_SHARE_DELETE keeps the
 * pinned directory from being renamed or removed while its child is opened;
 * using the canonical path means an ancestor junction swap cannot redirect
 * the subsequent traversal. */
static gboolean
wyctl_token_file_windows_parent_anchor_open (const gchar *path,
    WyctlTokenFileWindowsParentAnchor *anchor)
{
  g_autofree gchar *parent = g_path_get_dirname (path);
  g_autofree gchar *basename = g_path_get_basename (path);
  g_autofree wchar_t *wparent = (wchar_t *) g_utf8_to_utf16 (parent, -1,
          NULL, NULL, NULL);
  g_autofree wchar_t *wbasename = (wchar_t *) g_utf8_to_utf16 (basename, -1,
          NULL, NULL, NULL);
  if (wparent == NULL || wbasename == NULL || basename[0] == '\0'
      || g_strcmp0 (basename, ".") == 0 || g_strcmp0 (basename, "..") == 0)
    return FALSE;
  /* Drive-relative paths (for example C:token) depend on a per-drive
   * current directory and cannot be safely anchored by this contract. */
  if (wparent[0] != L'\0' && wparent[1] == L':'
      && wparent[2] != L'\\' && wparent[2] != L'/')
    return FALSE;
  for (const wchar_t *p = wbasename; *p != L'\0'; p++) {
    if (*p == L'\\' || *p == L'/')
      return FALSE;
  }

  HANDLE handle = CreateFileW (wparent, FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (handle == INVALID_HANDLE_VALUE)
    return FALSE;

  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (handle, &info)
      || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
      || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    CloseHandle (handle);
    return FALSE;
  }
  /* OPEN_REPARSE_POINT protects only the final parent component. Comparing
   * the handle-resolved DOS path with the lexical absolute input rejects an
   * already-present junction/reparse in any ancestor component. */
  if (!wyctl_token_file_windows_parent_matches_input (handle, wparent)) {
    CloseHandle (handle);
    return FALSE;
  }

  DWORD capacity = 512;
  wchar_t *canonical = NULL;
  DWORD length = 0;
  for (;;) {
    canonical = g_realloc (canonical, sizeof (wchar_t) * capacity);
    length = GetFinalPathNameByHandleW (handle, canonical, capacity,
            VOLUME_NAME_GUID);
    if (length == 0) {
      g_free (canonical);
      CloseHandle (handle);
      return FALSE;
    }
    if (length < capacity)
      break;
    if (capacity > UINT32_MAX / 2) {
      g_free (canonical);
      CloseHandle (handle);
      return FALSE;
    }
    capacity *= 2;
  }

  gboolean separator = length > 0 && canonical[length - 1] != L'\\'
      && canonical[length - 1] != L'/';
  gsize basename_len = wcslen (wbasename);
  wchar_t *child = g_new (wchar_t, length + (separator ? 1 : 0)
          + basename_len + 1);
  memcpy (child, canonical, sizeof (wchar_t) * length);
  g_free (canonical);
  gsize offset = length;
  if (separator)
    child[offset++] = L'\\';
  memcpy (child + offset, wbasename, sizeof (wchar_t) * basename_len);
  child[offset + basename_len] = L'\0';
  anchor->handle = handle;
  anchor->child_path = child;
  return TRUE;
}
#endif

void
wyctl_token_file_free_sensitive (gchar *value, gsize capacity)
{
  if (value == NULL)
    return;
  if (capacity == 0)
    capacity = strlen (value) + 1;
  volatile gchar *wipe = (volatile gchar *) value;
  for (gsize i = 0; i < capacity; i++)
    wipe[i] = 0;
  g_free (value);
}

WyctlTokenFileStatus
wyctl_token_file_write_protected (const gchar *path, const gchar *token,
    gsize token_len)
{
  if (path == NULL || path[0] == '\0')
    return WYCTL_TOKEN_FILE_MISSING_PATH;
  if (token == NULL || token_len == 0 || token_len > WYCTL_TOKEN_FILE_MAX_BYTES)
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
#ifdef G_OS_WIN32
  WyctlTokenFileWindowsParentAnchor anchor = { NULL, NULL };
  if (!wyctl_token_file_windows_parent_anchor_open (path, &anchor))
    return WYCTL_TOKEN_FILE_SYMLINK;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  SECURITY_ATTRIBUTES security = { 0 };
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW
        (L"D:P(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, NULL)) {
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  security.nLength = sizeof security;
  security.lpSecurityDescriptor = descriptor;
  HANDLE h = CreateFileW (anchor.child_path, GENERIC_WRITE | DELETE,
          FILE_SHARE_DELETE,
          &security, CREATE_NEW,
          FILE_ATTRIBUTE_READONLY | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  LocalFree (descriptor);
  if (h == INVALID_HANDLE_VALUE) {
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  if (wyctl_token_file_windows_handle_is_reparse (h)) {
    FILE_DISPOSITION_INFO disposition = { TRUE };
    (void) SetFileInformationByHandle (h, FileDispositionInfo, &disposition,
        sizeof disposition);
    CloseHandle (h);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_SYMLINK;
  }
  DWORD written = 0;
  gboolean ok = WriteFile (h, token, (DWORD) token_len, &written, NULL)
      && written == token_len && FlushFileBuffers (h);
  if (!ok) {
    FILE_DISPOSITION_INFO disposition = { TRUE };
    (void) SetFileInformationByHandle (h, FileDispositionInfo, &disposition,
        sizeof disposition);
    CloseHandle (h);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  CloseHandle (h);
  wyctl_token_file_windows_parent_anchor_clear (&anchor);
  return WYCTL_TOKEN_FILE_OK;
#else
  g_autofree gchar *parent = g_path_get_dirname (path);
  g_autofree gchar *basename = g_path_get_basename (path);
  int dirfd = open (parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dirfd < 0)
    return WYCTL_TOKEN_FILE_IO;
  int fd = openat (dirfd, basename,
          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW, 0600);
  if (fd < 0) {
    close (dirfd);
    return WYCTL_TOKEN_FILE_IO;
  }
  gsize written = 0;
  while (written < token_len) {
    ssize_t n = write (fd, token + written, token_len - written);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      close (fd);
      (void) unlinkat (dirfd, basename, 0);
      close (dirfd);
      return WYCTL_TOKEN_FILE_IO;
    }
    written += (gsize) n;
  }
  gboolean sync_ok = fsync (fd) == 0;
  gboolean close_ok = close (fd) == 0;
  if (!sync_ok || !close_ok) {
    (void) unlinkat (dirfd, basename, 0);
    (void) fsync (dirfd);
    close (dirfd);
    return WYCTL_TOKEN_FILE_IO;
  }
  gboolean parent_sync_ok = fsync (dirfd) == 0;
  gboolean parent_close_ok = close (dirfd) == 0;
  if (!parent_sync_ok)
    return WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN;
  if (!parent_close_ok)
    return WYCTL_TOKEN_FILE_IO;
  return WYCTL_TOKEN_FILE_OK;
#endif
}

static gchar *
wyctl_token_file_lock_path (const gchar *path)
{
  if (path == NULL || path[0] == '\0')
    return NULL;
  g_autofree gchar *parent = g_path_get_dirname (path);
  g_autofree gchar *basename = g_path_get_basename (path);
#ifndef G_OS_WIN32
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL)
    return NULL;
  gchar *canonical = g_build_filename (resolved_parent, basename, NULL);
  free (resolved_parent);
#else
  g_autofree gchar *absolute_parent = g_canonicalize_filename (parent, NULL);
  gchar *canonical = g_build_filename (absolute_parent, basename, NULL);
#endif
  gchar *lock_path = g_strconcat (canonical, ".lock", NULL);
  g_free (canonical);
  return lock_path;
}

WyctlTokenFileStatus
wyctl_token_file_lock_refresh (const gchar *path, WyctlTokenFileLock **out_lock)
{
  if (out_lock == NULL)
    return WYCTL_TOKEN_FILE_IO;
  *out_lock = NULL;
  g_autofree gchar *lock_path = wyctl_token_file_lock_path (path);
  if (lock_path == NULL)
    return WYCTL_TOKEN_FILE_IO;
  WyctlTokenFileLock *lock = g_new0 (WyctlTokenFileLock, 1);
#ifdef G_OS_WIN32
  WyctlTokenFileWindowsParentAnchor anchor = { NULL, NULL };
  PSECURITY_DESCRIPTOR descriptor = NULL;
  SECURITY_ATTRIBUTES security = { 0 };
  if (!wyctl_token_file_windows_parent_anchor_open (lock_path, &anchor) ||
      !ConvertStringSecurityDescriptorToSecurityDescriptorW
        (L"D:P(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, NULL)) {
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    g_free (lock);
    return WYCTL_TOKEN_FILE_IO;
  }
  security.nLength = sizeof security;
  security.lpSecurityDescriptor = descriptor;
  lock->handle = CreateFileW (anchor.child_path,
          GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
          FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_ALWAYS,
          FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  LocalFree (descriptor);
  wyctl_token_file_windows_parent_anchor_clear (&anchor);
  BY_HANDLE_FILE_INFORMATION lock_info;
  if (lock->handle == INVALID_HANDLE_VALUE ||
      !GetFileInformationByHandle (lock->handle, &lock_info)
      || (lock_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || (lock_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
      || lock_info.nNumberOfLinks != 1
      || !wyctl_token_file_windows_handle_is_owner_only (lock->handle)) {
    if (lock->handle != INVALID_HANDLE_VALUE)
      CloseHandle (lock->handle);
    g_free (lock);
    return WYCTL_TOKEN_FILE_SYMLINK;
  }
  if (!LockFileEx (lock->handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0,
      &lock->overlap)) {
    CloseHandle (lock->handle);
    g_free (lock);
    return WYCTL_TOKEN_FILE_IO;
  }
#else
  g_autofree gchar *parent = g_path_get_dirname (lock_path);
  g_autofree gchar *basename = g_path_get_basename (lock_path);
  int dirfd = open (parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dirfd < 0) {
    g_free (lock);
    return WYCTL_TOKEN_FILE_IO;
  }
  lock->fd = openat (dirfd, basename,
          O_RDWR | O_CREAT | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW, 0600);
  close (dirfd);
  if (lock->fd < 0) {
    g_free (lock);
    return WYCTL_TOKEN_FILE_IO;
  }
  struct stat st;
  if (fstat (lock->fd, &st) != 0 || !S_ISREG (st.st_mode)
      || st.st_uid != geteuid () || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0
      || flock (lock->fd, LOCK_EX) != 0) {
    close (lock->fd);
    g_free (lock);
    return WYCTL_TOKEN_FILE_IO;
  }
#endif
  *out_lock = lock;
  return WYCTL_TOKEN_FILE_OK;
}

void
wyctl_token_file_unlock_refresh (WyctlTokenFileLock *lock)
{
  if (lock == NULL)
    return;
#ifdef G_OS_WIN32
  (void) UnlockFileEx (lock->handle, 0, 1, 0, &lock->overlap);
  CloseHandle (lock->handle);
#else
  (void) flock (lock->fd, LOCK_UN);
  close (lock->fd);
#endif
  g_free (lock);
}

WyctlTokenFileStatus
wyctl_token_file_replace_protected (const gchar *path, const gchar *token,
    gsize token_len)
{
  if (path == NULL || path[0] == '\0')
    return WYCTL_TOKEN_FILE_MISSING_PATH;
  if (token == NULL || token_len == 0 || token_len > WYCTL_TOKEN_FILE_MAX_BYTES)
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
#ifdef G_OS_WIN32
  WyctlTokenFileWindowsParentAnchor anchor = { NULL, NULL };
  if (!wyctl_token_file_windows_parent_anchor_open (path, &anchor))
    return WYCTL_TOKEN_FILE_SYMLINK;
  HANDLE current = CreateFileW (anchor.child_path, GENERIC_READ,
          FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
          FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (current == INVALID_HANDLE_VALUE ||
      wyctl_token_file_windows_handle_is_reparse (current)) {
    if (current != INVALID_HANDLE_VALUE)
      CloseHandle (current);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_SYMLINK;
  }
  CloseHandle (current);
  g_autofree gchar *nonce = g_uuid_string_random ();
  g_autofree wchar_t *wnonce = (wchar_t *) g_utf8_to_utf16 (nonce, -1,
          NULL, NULL, NULL);
  gsize child_length = wcslen (anchor.child_path);
  gsize nonce_length = wnonce != NULL ? wcslen (wnonce) : 0;
  wchar_t *tmp_path = wnonce != NULL
      ? g_new (wchar_t, child_length + wcslen (L".tmp.") + nonce_length + 1)
      : NULL;
  if (tmp_path == NULL) {
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  memcpy (tmp_path, anchor.child_path, sizeof (wchar_t) * child_length);
  memcpy (tmp_path + child_length, L".tmp.", sizeof (wchar_t) * wcslen (L".tmp."));
  memcpy (tmp_path + child_length + wcslen (L".tmp."), wnonce,
      sizeof (wchar_t) * (nonce_length + 1));
  PSECURITY_DESCRIPTOR descriptor = NULL;
  SECURITY_ATTRIBUTES security = { 0 };
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW
        (L"D:P(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, NULL)) {
    g_free (tmp_path);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  security.nLength = sizeof security;
  security.lpSecurityDescriptor = descriptor;
  HANDLE temporary = CreateFileW (tmp_path, GENERIC_WRITE | DELETE,
          FILE_SHARE_DELETE, &security, CREATE_NEW,
          FILE_ATTRIBUTE_READONLY | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  LocalFree (descriptor);
  if (temporary == INVALID_HANDLE_VALUE) {
    g_free (tmp_path);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  gsize written = 0;
  gboolean write_ok = TRUE;
  while (written < token_len) {
    DWORD chunk = (DWORD) MIN (token_len - written, (gsize) G_MAXUINT32);
    DWORD count = 0;
    if (!WriteFile (temporary, token + written, chunk, &count, NULL)
        || count == 0) {
      write_ok = FALSE;
      break;
    }
    written += count;
  }
  gboolean flush_ok = write_ok && FlushFileBuffers (temporary);
  gboolean close_ok = CloseHandle (temporary);
  if (!flush_ok || !close_ok) {
    (void) SetFileAttributesW (tmp_path, FILE_ATTRIBUTE_NORMAL);
    (void) DeleteFileW (tmp_path);
    g_free (tmp_path);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  DWORD old_attrs = GetFileAttributesW (anchor.child_path);
  gboolean cleared_readonly = old_attrs != INVALID_FILE_ATTRIBUTES
      && (old_attrs & FILE_ATTRIBUTE_READONLY) != 0;
  if (cleared_readonly && !SetFileAttributesW (anchor.child_path,
      old_attrs & ~FILE_ATTRIBUTE_READONLY)) {
    (void) SetFileAttributesW (tmp_path, FILE_ATTRIBUTE_NORMAL);
    (void) DeleteFileW (tmp_path);
    g_free (tmp_path);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  BOOL moved = MoveFileExW (tmp_path, anchor.child_path,
          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
  if (!moved && cleared_readonly)
    (void) SetFileAttributesW (anchor.child_path, old_attrs);
  if (!moved) {
    (void) SetFileAttributesW (tmp_path, FILE_ATTRIBUTE_NORMAL);
    (void) DeleteFileW (tmp_path);
    g_free (tmp_path);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  g_free (tmp_path);
  wyctl_token_file_windows_parent_anchor_clear (&anchor);
  /* MoveFileExW with WRITE_THROUGH is the strongest directory-entry
   * durability primitive Win32 exposes here; unlike POSIX, a parent
   * directory flush guarantee is not available on all supported filesystems. */
  return WYCTL_TOKEN_FILE_OK;
#else
  g_autofree gchar *parent = g_path_get_dirname (path);
  g_autofree gchar *basename = g_path_get_basename (path);
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL)
    return WYCTL_TOKEN_FILE_IO;
  int dirfd = open (resolved_parent,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  free (resolved_parent);
  if (dirfd < 0)
    return WYCTL_TOKEN_FILE_IO;
  struct stat before;
  if (fstatat (dirfd, basename, &before, AT_SYMLINK_NOFOLLOW) != 0) {
    close (dirfd);
    return WYCTL_TOKEN_FILE_NOT_FOUND;
  }
  if (S_ISLNK (before.st_mode)) {
    close (dirfd);
    return WYCTL_TOKEN_FILE_SYMLINK;
  }
  if (!S_ISREG (before.st_mode) || before.st_uid != geteuid ()
      || (before.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    close (dirfd);
    return WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD;
  }
  g_autofree gchar *tmp = NULL;
  int fd = -1;
  for (guint attempt = 0; attempt < 32; attempt++) {
    g_free (tmp);
    tmp = g_strdup_printf (".wyctl-token-%08x-%08x", g_random_int (),
            g_random_int ());
    fd = openat (dirfd, tmp,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY,
            0600);
    if (fd >= 0 || errno != EEXIST)
      break;
  }
  if (fd < 0) {
    close (dirfd);
    return WYCTL_TOKEN_FILE_IO;
  }
  gsize written = 0;
  while (written < token_len) {
    ssize_t n = write (fd, token + written, token_len - written);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      close (fd);
      (void) unlinkat (dirfd, tmp, 0);
      close (dirfd);
      return WYCTL_TOKEN_FILE_IO;
    }
    written += (gsize) n;
  }
  gboolean file_sync_ok = fsync (fd) == 0;
  gboolean file_close_ok = close (fd) == 0;
  if (!file_sync_ok || !file_close_ok) {
    (void) unlinkat (dirfd, tmp, 0);
    close (dirfd);
    return WYCTL_TOKEN_FILE_IO;
  }
  struct stat current;
  gboolean same = fstatat (dirfd, basename, &current,
          AT_SYMLINK_NOFOLLOW) == 0 && current.st_dev == before.st_dev
      && current.st_ino == before.st_ino;
  if (!same || renameat (dirfd, tmp, dirfd, basename) != 0) {
    (void) unlinkat (dirfd, tmp, 0);
    close (dirfd);
    return WYCTL_TOKEN_FILE_IO;
  }
  gboolean durable = fsync (dirfd) == 0;
  close (dirfd);
  return durable ? WYCTL_TOKEN_FILE_OK : WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN;
#endif
}

WyctlTokenFileStatus
wyctl_token_file_remove_protected (const gchar *path)
{
  if (path == NULL || path[0] == '\0')
    return WYCTL_TOKEN_FILE_MISSING_PATH;
#ifdef G_OS_WIN32
  WyctlTokenFileWindowsParentAnchor anchor = { NULL, NULL };
  if (!wyctl_token_file_windows_parent_anchor_open (path, &anchor))
    return WYCTL_TOKEN_FILE_SYMLINK;
  HANDLE current = CreateFileW (anchor.child_path, DELETE | FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (current == INVALID_HANDLE_VALUE ||
      wyctl_token_file_windows_handle_is_reparse (current)) {
    if (current != INVALID_HANDLE_VALUE)
      CloseHandle (current);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_SYMLINK;
  }
  CloseHandle (current);
  DWORD attrs = GetFileAttributesW (anchor.child_path);
  gboolean cleared_readonly = attrs != INVALID_FILE_ATTRIBUTES
      && (attrs & FILE_ATTRIBUTE_READONLY) != 0;
  if (cleared_readonly)
    (void) SetFileAttributesW (anchor.child_path,
        attrs & ~FILE_ATTRIBUTE_READONLY);
  gboolean removed = DeleteFileW (anchor.child_path);
  if (!removed && cleared_readonly)
    (void) SetFileAttributesW (anchor.child_path, attrs);
  wyctl_token_file_windows_parent_anchor_clear (&anchor);
  return removed ? WYCTL_TOKEN_FILE_OK : WYCTL_TOKEN_FILE_IO;
#else
  g_autofree gchar *parent = g_path_get_dirname (path);
  g_autofree gchar *basename = g_path_get_basename (path);
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL)
    return WYCTL_TOKEN_FILE_IO;
  int dirfd = open (resolved_parent,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  free (resolved_parent);
  if (dirfd < 0)
    return WYCTL_TOKEN_FILE_IO;
  struct stat st;
  if (fstatat (dirfd, basename, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
      !S_ISREG (st.st_mode) || st.st_uid != geteuid () ||
      (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    close (dirfd);
    return WYCTL_TOKEN_FILE_IO;
  }
  gboolean removed = unlinkat (dirfd, basename, 0) == 0;
  gboolean durable = removed && fsync (dirfd) == 0;
  close (dirfd);
  return !removed ? WYCTL_TOKEN_FILE_IO :
         (durable ? WYCTL_TOKEN_FILE_OK : WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN);
#endif
}

static gboolean
wyctl_token_file_remove_if_same_file (const gchar *path,
    guint64 file_id_a, guint64 file_id_b)
{
#ifdef G_OS_WIN32
  WyctlTokenFileWindowsParentAnchor anchor = { NULL, NULL };
  if (!wyctl_token_file_windows_parent_anchor_open (path, &anchor))
    return FALSE;
  HANDLE handle = CreateFileW (anchor.child_path,
          DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
          NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (handle == INVALID_HANDLE_VALUE ||
      wyctl_token_file_windows_handle_is_reparse (handle)) {
    if (handle != INVALID_HANDLE_VALUE)
      CloseHandle (handle);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return FALSE;
  }
  BY_HANDLE_FILE_INFORMATION info;
  gboolean same = GetFileInformationByHandle (handle, &info)
      && info.dwVolumeSerialNumber == (DWORD) file_id_a
      && (((guint64) info.nFileIndexHigh << 32) | info.nFileIndexLow)
      == file_id_b;
  FILE_DISPOSITION_INFO disposition = { TRUE };
  gboolean removed = same && SetFileInformationByHandle (handle,
          FileDispositionInfo, &disposition, sizeof disposition);
  CloseHandle (handle);
  wyctl_token_file_windows_parent_anchor_clear (&anchor);
  return removed;
#else
  g_autofree gchar *parent = g_path_get_dirname (path);
  g_autofree gchar *basename = g_path_get_basename (path);
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL)
    return FALSE;
  int dirfd = open (resolved_parent,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  free (resolved_parent);
  if (dirfd < 0)
    return FALSE;
  struct stat st;
  gboolean same = fstatat (dirfd, basename, &st, AT_SYMLINK_NOFOLLOW) == 0
      && S_ISREG (st.st_mode) && st.st_uid == geteuid ()
      && (guint64) st.st_dev == file_id_a && (guint64) st.st_ino == file_id_b;
  gboolean removed = same && unlinkat (dirfd, basename, 0) == 0;
  gboolean durable = removed && fsync (dirfd) == 0;
  close (dirfd);
  return removed && durable;
#endif
}

WyctlTokenFileStatus
wyctl_token_file_write_pair_protected (const gchar *refresh_path,
    const gchar *refresh_token, gsize refresh_token_len,
    const gchar *access_path, const gchar *access_token,
    gsize access_token_len)
{
  g_autofree gchar *refresh_canonical = refresh_path != NULL
      ? g_canonicalize_filename (refresh_path, NULL) : NULL;
  g_autofree gchar *access_canonical = access_path != NULL
      ? g_canonicalize_filename (access_path, NULL) : NULL;
  if (refresh_path == NULL || access_path == NULL
      || g_strcmp0 (refresh_canonical, access_canonical) == 0)
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
  WyctlTokenFileStatus status = wyctl_token_file_write_protected
        (refresh_path, refresh_token, refresh_token_len);
  if (status != WYCTL_TOKEN_FILE_OK)
    return status;
  guint64 file_id_a = 0;
  guint64 file_id_b = 0;
#ifdef G_OS_WIN32
  WyctlTokenFileWindowsParentAnchor anchor = { NULL, NULL };
  if (wyctl_token_file_windows_parent_anchor_open (refresh_path, &anchor)) {
    HANDLE handle = CreateFileW (anchor.child_path, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION info;
    if (handle != INVALID_HANDLE_VALUE
        && GetFileInformationByHandle (handle, &info)
        && !wyctl_token_file_windows_handle_is_reparse (handle)) {
      file_id_a = info.dwVolumeSerialNumber;
      file_id_b = ((guint64) info.nFileIndexHigh << 32) | info.nFileIndexLow;
    }
    if (handle != INVALID_HANDLE_VALUE)
      CloseHandle (handle);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
  }
#else
  g_autofree gchar *refresh_parent = g_path_get_dirname (refresh_path);
  g_autofree gchar *refresh_basename = g_path_get_basename (refresh_path);
  gchar *resolved_parent = realpath (refresh_parent, NULL);
  if (resolved_parent != NULL) {
    int dirfd = open (resolved_parent,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    free (resolved_parent);
    if (dirfd >= 0) {
      struct stat st;
      if (fstatat (dirfd, refresh_basename, &st, AT_SYMLINK_NOFOLLOW) == 0
          && S_ISREG (st.st_mode) && st.st_uid == geteuid ()) {
        file_id_a = (guint64) st.st_dev;
        file_id_b = (guint64) st.st_ino;
      }
      close (dirfd);
    }
  }
#endif
  if (file_id_b == 0)
    return WYCTL_TOKEN_FILE_IO;
  status = wyctl_token_file_write_protected
        (access_path, access_token, access_token_len);
  if (status != WYCTL_TOKEN_FILE_OK
      && !wyctl_token_file_remove_if_same_file (refresh_path,
      file_id_a, file_id_b))
    return WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN;
  return status;
}

const gchar *
wyctl_token_file_status_message (WyctlTokenFileStatus status)
{
  switch (status) {
    case WYCTL_TOKEN_FILE_OK:
      return NULL;
    case WYCTL_TOKEN_FILE_MISSING_PATH:
      return "wyctl: missing --access-token-file";
    case WYCTL_TOKEN_FILE_NOT_FOUND:
      return "wyctl: access token file not found: %s";
    case WYCTL_TOKEN_FILE_SYMLINK:
      return "wyctl: access token file is a symlink"
             " (refusing to follow): %s";
    case WYCTL_TOKEN_FILE_NOT_REGULAR:
      return "wyctl: access token file is not a regular file: %s";
    case WYCTL_TOKEN_FILE_OWNER_MISMATCH:
      return "wyctl: access token file not owned by current user: %s";
    case WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD:
      return "wyctl: access token file permissions too broad"
             " (require 0600): %s";
    case WYCTL_TOKEN_FILE_IO:
      return "wyctl: unable to read access token file: %s";
    case WYCTL_TOKEN_FILE_EMPTY:
      return "wyctl: empty access token file: %s";
    case WYCTL_TOKEN_FILE_INVALID_BYTES:
      return "wyctl: invalid access token file: %s";
    case WYCTL_TOKEN_FILE_TOO_LARGE:
      return "wyctl: access token file too large: %s";
    case WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY:
      return "wyctl: access token file not marked read-only: %s";
    case WYCTL_TOKEN_FILE_WINDOWS_ACL_UNAVAILABLE:
      return "wyctl: access token file ACL validation unavailable: %s";
    case WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN:
      return "wyctl: token update durability uncertain: %s";
  }
  return NULL;
}

#ifndef G_OS_WIN32
WyctlTokenFileStatus
wyctl_token_file_classify_stat (const struct stat *st, uid_t euid)
{
  if (st == NULL)
    return WYCTL_TOKEN_FILE_IO;
  if (!S_ISREG (st->st_mode))
    return WYCTL_TOKEN_FILE_NOT_REGULAR;
  if (st->st_uid != euid)
    return WYCTL_TOKEN_FILE_OWNER_MISMATCH;
  if ((st->st_mode & (S_IRWXG | S_IRWXO)) != 0)
    return WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD;
  return WYCTL_TOKEN_FILE_OK;
}
#endif

/* Pure attribute-bit-mask classifier (Windows semantics). Compiled
 * on every platform so the Linux unit-test runner exercises the
 * Windows rejection rules with synthetic inputs. */
WyctlTokenFileStatus
wyctl_token_file_classify_windows_attrs (guint32 attrs)
{
  /* FILE_ATTRIBUTE_REPARSE_POINT — symlink, mountpoint, or any
   * other reparse target. We refuse the same way the POSIX path
   * refuses a terminal symlink. */
  if (attrs & 0x00000400u)
    return WYCTL_TOKEN_FILE_SYMLINK;
  /* FILE_ATTRIBUTE_READONLY missing — the issue requires at least
   * this much hardening on Windows. */
  if ((attrs & 0x00000001u) == 0)
    return WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY;
  return WYCTL_TOKEN_FILE_OK;
}

WyctlTokenFileStatus
wyctl_token_file_read (const gchar *path, gchar **out_token)
{
  if (out_token == NULL)
    return WYCTL_TOKEN_FILE_IO;
  *out_token = NULL;

  if (path == NULL || path[0] == '\0')
    return WYCTL_TOKEN_FILE_MISSING_PATH;

#ifdef G_OS_WIN32
  /* Convert the operator-supplied UTF-8 path to UTF-16 for the
   * Win32 wide-string API. */
  WyctlTokenFileWindowsParentAnchor anchor = { NULL, NULL };
  if (!wyctl_token_file_windows_parent_anchor_open (path, &anchor))
    return WYCTL_TOKEN_FILE_SYMLINK;

  HANDLE h = CreateFileW (anchor.child_path, GENERIC_READ, FILE_SHARE_READ,
          NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
          NULL);
  DWORD err = (h == INVALID_HANDLE_VALUE) ? GetLastError () : 0;
  if (h == INVALID_HANDLE_VALUE) {
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
      return WYCTL_TOKEN_FILE_NOT_FOUND;
    return WYCTL_TOKEN_FILE_IO;
  }
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (h, &info)) {
    CloseHandle (h);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return WYCTL_TOKEN_FILE_IO;
  }
  WyctlTokenFileStatus classify =
      wyctl_token_file_classify_windows_attrs (info.dwFileAttributes);
  if (classify != WYCTL_TOKEN_FILE_OK) {
    CloseHandle (h);
    wyctl_token_file_windows_parent_anchor_clear (&anchor);
    return classify;
  }

  gsize cap = WYCTL_TOKEN_FILE_MAX_BYTES;
  gchar *buf = g_malloc (cap + 1);
  gsize got = 0;
  while (got < cap) {
    DWORD chunk = (DWORD) (cap - got);
    DWORD read_n = 0;
    if (!ReadFile (h, buf + got, chunk, &read_n, NULL)) {
      CloseHandle (h);
      wyctl_token_file_windows_parent_anchor_clear (&anchor);
      wyctl_token_file_free_sensitive (buf, cap + 1);
      return WYCTL_TOKEN_FILE_IO;
    }
    if (read_n == 0)
      break;
    got += (gsize) read_n;
  }
  if (got >= cap) {
    gchar overflow = 0;
    DWORD probe = 0;
    if (ReadFile (h, &overflow, 1, &probe, NULL) && probe > 0) {
      CloseHandle (h);
      wyctl_token_file_windows_parent_anchor_clear (&anchor);
      wyctl_token_file_free_sensitive (buf, cap + 1);
      return WYCTL_TOKEN_FILE_TOO_LARGE;
    }
  }
  CloseHandle (h);
  wyctl_token_file_windows_parent_anchor_clear (&anchor);
  buf[got] = '\0';

  if (got == 0) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_EMPTY;
  }
  if (memchr (buf, '\0', got) != NULL) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
  }

  *out_token = buf;
  return WYCTL_TOKEN_FILE_OK;
#else
  int fd = open (path, O_NOFOLLOW | O_CLOEXEC | O_RDONLY | O_NOCTTY);
  if (fd < 0) {
    int saved = errno;
    if (saved == ELOOP)
      return WYCTL_TOKEN_FILE_SYMLINK;
    if (saved == ENOENT || saved == ENOTDIR)
      return WYCTL_TOKEN_FILE_NOT_FOUND;
    return WYCTL_TOKEN_FILE_IO;
  }

  struct stat st;
  if (fstat (fd, &st) != 0) {
    close (fd);
    return WYCTL_TOKEN_FILE_IO;
  }

  WyctlTokenFileStatus classify = wyctl_token_file_classify_stat (&st,
          geteuid ());
  if (classify != WYCTL_TOKEN_FILE_OK) {
    close (fd);
    return classify;
  }

  if (st.st_size > (off_t) WYCTL_TOKEN_FILE_MAX_BYTES) {
    close (fd);
    return WYCTL_TOKEN_FILE_TOO_LARGE;
  }

  /* Read from the same fd we fstatted. No second path-based syscall
   * is allowed past this point — that would reopen the TOCTOU
   * window the open(O_NOFOLLOW) + fstat sequence just closed. */
  gsize cap = WYCTL_TOKEN_FILE_MAX_BYTES;
  gchar *buf = g_malloc (cap + 1);
  gsize got = 0;
  while (got < cap) {
    ssize_t n = read (fd, buf + got, cap - got);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      close (fd);
      wyctl_token_file_free_sensitive (buf, cap + 1);
      return WYCTL_TOKEN_FILE_IO;
    }
    if (n == 0)
      break;
    got += (gsize) n;
  }
  if (got >= cap) {
    /* Probe for additional bytes; if the file grew during read or
     * the initial st.st_size was misleading (e.g. sparse), we still
     * refuse to truncate. */
    gchar overflow = 0;
    ssize_t n = read (fd, &overflow, 1);
    if (n > 0) {
      close (fd);
      wyctl_token_file_free_sensitive (buf, cap + 1);
      return WYCTL_TOKEN_FILE_TOO_LARGE;
    }
  }
  close (fd);
  buf[got] = '\0';

  if (got == 0) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_EMPTY;
  }

  /* Embedded NUL bytes never belong in a bearer token. Surfacing
   * INVALID_BYTES here keeps higher-level normalize logic from
   * mis-classifying the file. */
  if (memchr (buf, '\0', got) != NULL) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
  }

  *out_token = buf;
  return WYCTL_TOKEN_FILE_OK;
#endif
}

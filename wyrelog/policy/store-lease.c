/* SPDX-License-Identifier: GPL-3.0-or-later */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__unix__) || defined(__APPLE__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "store-lease-private.h"

#include <errno.h>
#include <string.h>
#include <wchar.h>

#include "wyrelog/wyl-log-private.h"

#define WYL_POLICY_STORE_LOCK_SUFFIX ".wyrelog-lock"

#ifdef G_OS_WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

struct wyl_policy_store_lease_t
{
  gchar *resolved_path;
  gchar *basename;
  GPtrArray *registry_keys;
#ifdef G_OS_WIN32
  HANDLE parent_handle;
  HANDLE lock_handle;
  guint64 parent_volume;
  guint64 parent_file_index;
#else
  int parent_dirfd;
  int lock_fd;
  guint64 parent_dev;
  guint64 parent_ino;
#endif
};

static GMutex lease_registry_mutex;
static GHashTable *lease_registry;

static GHashTable *
registry_get (void)
{
  if (lease_registry == NULL)
    lease_registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
        NULL);
  return lease_registry;
}

static wyl_policy_store_lease_t *
registry_lookup (const gchar *key)
{
  return key == NULL ? NULL : g_hash_table_lookup (registry_get (), key);
}

static void
registry_bind (wyl_policy_store_lease_t *lease, const gchar *key)
{
  g_hash_table_insert (registry_get (), g_strdup (key), lease);
  g_ptr_array_add (lease->registry_keys, g_strdup (key));
}

static void
registry_unbind_all (wyl_policy_store_lease_t *lease)
{
  if (lease_registry == NULL || lease->registry_keys == NULL)
    return;
  for (guint i = 0; i < lease->registry_keys->len; i++)
    g_hash_table_remove (lease_registry,
        g_ptr_array_index (lease->registry_keys, i));
}

#ifdef G_OS_WIN32
static gchar *
wide_to_utf8 (const wchar_t *wide)
{
  return g_utf16_to_utf8 ((const gunichar2 *) wide, -1, NULL, NULL, NULL);
}

static gchar *
final_path_from_handle (HANDLE handle)
{
  DWORD needed = GetFinalPathNameByHandleW (handle, NULL, 0,
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (needed == 0)
    return NULL;
  wchar_t *wide = g_new0 (wchar_t, needed + 1);
  DWORD written = GetFinalPathNameByHandleW (handle, wide, needed + 1,
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (written == 0 || written > needed) {
    g_free (wide);
    return NULL;
  }
  gchar *utf8 = NULL;
  if (wcsncmp (wide, L"\\\\?\\UNC\\", 8) == 0) {
    g_autofree gchar *unc_tail = wide_to_utf8 (wide + 8);
    if (unc_tail != NULL)
      utf8 = g_strconcat ("\\\\", unc_tail, NULL);
  } else {
    const wchar_t *trimmed = wide;
    if (wcsncmp (wide, L"\\\\?\\", 4) == 0)
      trimmed += 4;
    utf8 = wide_to_utf8 (trimmed);
  }
  g_free (wide);
  return utf8;
}

static gboolean
win_parent_identity (HANDLE handle, guint64 *volume, guint64 *index)
{
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (handle, &info))
    return FALSE;
  *volume = info.dwVolumeSerialNumber;
  *index = ((guint64) info.nFileIndexHigh << 32) | info.nFileIndexLow;
  return TRUE;
}

wyrelog_error_t
wyl_policy_store_lease_acquire (const gchar *path,
    wyl_policy_store_lease_t **out_lease)
{
  if (path == NULL || path[0] == '\0' || out_lease == NULL)
    return WYRELOG_E_INVALID;
  *out_lease = NULL;

  g_autofree gchar *absolute = g_canonicalize_filename (path, NULL);
  g_autofree gchar *parent = g_path_get_dirname (absolute);
  g_autofree gchar *basename = g_path_get_basename (absolute);
  wchar_t *wparent = (wchar_t *) g_utf8_to_utf16 (parent, -1, NULL, NULL,
      NULL);
  if (wparent == NULL)
    return WYRELOG_E_INVALID;
  HANDLE parent_handle = CreateFileW (wparent, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS, NULL);
  g_free (wparent);
  if (parent_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_IO;

  g_autofree gchar *final_parent = final_path_from_handle (parent_handle);
  guint64 volume = 0;
  guint64 parent_index = 0;
  if (final_parent == NULL
      || !win_parent_identity (parent_handle, &volume, &parent_index)) {
    CloseHandle (parent_handle);
    return WYRELOG_E_IO;
  }
  g_autofree gchar *resolved = g_build_filename (final_parent, basename, NULL);
  g_autofree gchar *lock_path = g_strdup_printf ("%s%s", resolved,
      WYL_POLICY_STORE_LOCK_SUFFIX);
  g_autofree gchar *path_key = g_utf8_casefold (resolved, -1);
  g_autofree gchar *location_key = g_strdup_printf ("win:%" G_GUINT64_FORMAT
      ":%" G_GUINT64_FORMAT ":%s", volume, parent_index, basename);

  g_mutex_lock (&lease_registry_mutex);
  if (registry_lookup (path_key) != NULL
      || registry_lookup (location_key) != NULL) {
    g_mutex_unlock (&lease_registry_mutex);
    CloseHandle (parent_handle);
    return WYRELOG_E_BUSY;
  }

  wchar_t *wlock = (wchar_t *) g_utf8_to_utf16 (lock_path, -1, NULL, NULL,
      NULL);
  if (wlock == NULL) {
    g_mutex_unlock (&lease_registry_mutex);
    CloseHandle (parent_handle);
    return WYRELOG_E_INVALID;
  }
  HANDLE lock_handle = CreateFileW (wlock, GENERIC_READ | GENERIC_WRITE, 0,
      NULL, OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  DWORD last_error = lock_handle == INVALID_HANDLE_VALUE ? GetLastError () : 0;
  g_free (wlock);
  if (lock_handle == INVALID_HANDLE_VALUE) {
    g_mutex_unlock (&lease_registry_mutex);
    CloseHandle (parent_handle);
    return (last_error == ERROR_SHARING_VIOLATION
        || last_error == ERROR_LOCK_VIOLATION) ? WYRELOG_E_BUSY : WYRELOG_E_IO;
  }
  BY_HANDLE_FILE_INFORMATION lock_info;
  if (!GetFileInformationByHandle (lock_handle, &lock_info)
      || (lock_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      || (lock_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      || lock_info.nNumberOfLinks != 1) {
    CloseHandle (lock_handle);
    CloseHandle (parent_handle);
    g_mutex_unlock (&lease_registry_mutex);
    return WYRELOG_E_POLICY;
  }

  wyl_policy_store_lease_t *lease = g_new0 (wyl_policy_store_lease_t, 1);
  lease->resolved_path = g_steal_pointer (&resolved);
  lease->basename = g_strdup (basename);
  lease->registry_keys = g_ptr_array_new_with_free_func (g_free);
  lease->parent_handle = parent_handle;
  lease->lock_handle = lock_handle;
  lease->parent_volume = volume;
  lease->parent_file_index = parent_index;
  registry_bind (lease, path_key);
  registry_bind (lease, location_key);
  g_mutex_unlock (&lease_registry_mutex);
  *out_lease = lease;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_lease_verify_parent (const wyl_policy_store_lease_t *lease)
{
  if (lease == NULL || lease->parent_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  guint64 volume = 0;
  guint64 index = 0;
  return win_parent_identity (lease->parent_handle, &volume, &index)
      && volume == lease->parent_volume && index == lease->parent_file_index ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

void
wyl_policy_store_lease_release (wyl_policy_store_lease_t *lease)
{
  if (lease == NULL)
    return;
  g_mutex_lock (&lease_registry_mutex);
  registry_unbind_all (lease);
  CloseHandle (lease->lock_handle);
  CloseHandle (lease->parent_handle);
  g_mutex_unlock (&lease_registry_mutex);
  g_ptr_array_free (lease->registry_keys, TRUE);
  g_free (lease->resolved_path);
  g_free (lease->basename);
  g_free (lease);
}
#else
static wyrelog_error_t
lock_nonblocking (int fd)
{
#if defined(__linux__) && defined(F_OFD_SETLK)
  struct flock ofd = { 0 };
  ofd.l_type = F_WRLCK;
  ofd.l_whence = SEEK_SET;
  if (fcntl (fd, F_OFD_SETLK, &ofd) == 0)
    return WYRELOG_E_OK;
  if (errno == EACCES || errno == EAGAIN)
    return WYRELOG_E_BUSY;
  if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP)
    return WYRELOG_E_IO;
#endif
  if (flock (fd, LOCK_EX | LOCK_NB) == 0)
    return WYRELOG_E_OK;
  return (errno == EWOULDBLOCK || errno == EAGAIN) ? WYRELOG_E_BUSY :
      WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_lease_acquire (const gchar *path,
    wyl_policy_store_lease_t **out_lease)
{
  if (path == NULL || path[0] == '\0' || out_lease == NULL)
    return WYRELOG_E_INVALID;
  *out_lease = NULL;

  g_autofree gchar *absolute = g_canonicalize_filename (path, NULL);
  g_autofree gchar *parent = g_path_get_dirname (absolute);
  g_autofree gchar *basename = g_path_get_basename (absolute);
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL)
    return WYRELOG_E_IO;
  int dirfd = open (resolved_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dirfd < 0) {
    g_free (resolved_parent);
    return WYRELOG_E_IO;
  }
  struct stat parent_stat;
  if (fstat (dirfd, &parent_stat) != 0) {
    close (dirfd);
    g_free (resolved_parent);
    return WYRELOG_E_IO;
  }
  struct stat named_parent_stat;
  if (stat (resolved_parent, &named_parent_stat) != 0
      || parent_stat.st_dev != named_parent_stat.st_dev
      || parent_stat.st_ino != named_parent_stat.st_ino) {
    close (dirfd);
    g_free (resolved_parent);
    return WYRELOG_E_POLICY;
  }
  g_autofree gchar *resolved = g_build_filename (resolved_parent, basename,
      NULL);
  g_free (resolved_parent);
  g_autofree gchar *lock_basename = g_strdup_printf ("%s%s", basename,
      WYL_POLICY_STORE_LOCK_SUFFIX);
  g_autofree gchar *path_key = g_strdup_printf ("path:%s", resolved);
  g_autofree gchar *location_key = g_strdup_printf ("location:%"
      G_GUINT64_FORMAT ":%" G_GUINT64_FORMAT ":%s",
      (guint64) parent_stat.st_dev, (guint64) parent_stat.st_ino, basename);

  g_mutex_lock (&lease_registry_mutex);
  if (registry_lookup (path_key) != NULL
      || registry_lookup (location_key) != NULL) {
    g_mutex_unlock (&lease_registry_mutex);
    close (dirfd);
    return WYRELOG_E_BUSY;
  }
  int lock_fd = openat (dirfd, lock_basename,
      O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
  int open_errno = errno;
  if (lock_fd < 0) {
    g_mutex_unlock (&lease_registry_mutex);
    close (dirfd);
    return open_errno == ELOOP ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  struct stat lock_stat;
  if (fstat (lock_fd, &lock_stat) != 0 || !S_ISREG (lock_stat.st_mode)) {
    close (lock_fd);
    close (dirfd);
    g_mutex_unlock (&lease_registry_mutex);
    return WYRELOG_E_POLICY;
  }
  g_autofree gchar *inode_key = g_strdup_printf ("inode:%" G_GUINT64_FORMAT
      ":%" G_GUINT64_FORMAT, (guint64) lock_stat.st_dev,
      (guint64) lock_stat.st_ino);
  wyl_policy_store_lease_t *same_inode = registry_lookup (inode_key);
  if (same_inode != NULL) {
    registry_bind (same_inode, path_key);
    registry_bind (same_inode, location_key);
    close (lock_fd);            /* OFD/flock locks are not process-wide. */
    close (dirfd);
    g_mutex_unlock (&lease_registry_mutex);
    return WYRELOG_E_BUSY;
  }
  /* Never chmod an attacker-selected multiply-linked inode. A live
   * same-process owner was handled above so its legitimate alias remains a
   * BUSY result without weakening the held lock. */
  if (lock_stat.st_nlink != 1) {
    close (lock_fd);
    close (dirfd);
    g_mutex_unlock (&lease_registry_mutex);
    return WYRELOG_E_POLICY;
  }
  if (fchmod (lock_fd, 0600) != 0 || fstat (lock_fd, &lock_stat) != 0
      || (lock_stat.st_mode & 0777) != 0600) {
    close (lock_fd);
    close (dirfd);
    g_mutex_unlock (&lease_registry_mutex);
    return WYRELOG_E_IO;
  }

  wyrelog_error_t rc = lock_nonblocking (lock_fd);
  if (rc != WYRELOG_E_OK) {
    close (lock_fd);
    close (dirfd);
    g_mutex_unlock (&lease_registry_mutex);
    return rc;
  }

  wyl_policy_store_lease_t *lease = g_new0 (wyl_policy_store_lease_t, 1);
  lease->resolved_path = g_steal_pointer (&resolved);
  lease->basename = g_strdup (basename);
  lease->registry_keys = g_ptr_array_new_with_free_func (g_free);
  lease->parent_dirfd = dirfd;
  lease->lock_fd = lock_fd;
  lease->parent_dev = parent_stat.st_dev;
  lease->parent_ino = parent_stat.st_ino;
  registry_bind (lease, path_key);
  registry_bind (lease, location_key);
  registry_bind (lease, inode_key);
  g_mutex_unlock (&lease_registry_mutex);
  *out_lease = lease;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_lease_verify_parent (const wyl_policy_store_lease_t *lease)
{
  if (lease == NULL || lease->parent_dirfd < 0)
    return WYRELOG_E_INVALID;
  struct stat pinned;
  if (fstat (lease->parent_dirfd, &pinned) != 0)
    return WYRELOG_E_IO;
  g_autofree gchar *parent = g_path_get_dirname (lease->resolved_path);
  struct stat named;
  if (stat (parent, &named) != 0)
    return WYRELOG_E_POLICY;
  return (guint64) pinned.st_dev == lease->parent_dev
      && (guint64) pinned.st_ino == lease->parent_ino
      && pinned.st_dev == named.st_dev && pinned.st_ino == named.st_ino ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

int
wyl_policy_store_lease_parent_dirfd (const wyl_policy_store_lease_t *lease)
{
  return lease == NULL ? -1 : lease->parent_dirfd;
}

const gchar *
wyl_policy_store_lease_basename (const wyl_policy_store_lease_t *lease)
{
  return lease == NULL ? NULL : lease->basename;
}

void
wyl_policy_store_lease_release (wyl_policy_store_lease_t *lease)
{
  if (lease == NULL)
    return;
  g_mutex_lock (&lease_registry_mutex);
  registry_unbind_all (lease);
  close (lease->lock_fd);
  close (lease->parent_dirfd);
  g_mutex_unlock (&lease_registry_mutex);
  g_ptr_array_free (lease->registry_keys, TRUE);
  g_free (lease->resolved_path);
  g_free (lease->basename);
  g_free (lease);
}
#endif

const gchar *
wyl_policy_store_lease_resolved_path (const wyl_policy_store_lease_t *lease)
{
  return lease == NULL ? NULL : lease->resolved_path;
}

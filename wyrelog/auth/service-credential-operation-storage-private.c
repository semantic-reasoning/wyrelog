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
  const gchar *base = g_get_user_data_dir ();
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
  wyrelog_error_t rc = ensure_private_directory (root);
  if (rc != WYRELOG_E_OK) {
    g_free (root);
    return rc;
  }
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
#endif
  g_clear_pointer (&storage->root_path, g_free);
}

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
#endif

#define JOURNAL_SUBPATH "wyrelog/service-credential-operations"

static gboolean
path_is_owner_private_directory (const gchar *path)
{
  GStatBuf st;
  if (g_lstat (path, &st) != 0 || !S_ISDIR (st.st_mode))
    return FALSE;
#ifndef G_OS_WIN32
  if (st.st_uid != geteuid () || (st.st_mode & 0777) != 0700)
    return FALSE;
#endif
  return TRUE;
}

static wyrelog_error_t
ensure_private_directory (const gchar *path)
{
  if (path == NULL || path[0] == '\0')
    return WYRELOG_E_INVALID;
  if (g_mkdir_with_parents (path, 0700) != 0 && errno != EEXIST)
    return errno == EACCES || errno == EPERM || errno == ENOTDIR
        ? WYRELOG_E_POLICY : WYRELOG_E_IO;
#ifndef G_OS_WIN32
  if (g_chmod (path, 0700) != 0)
    return WYRELOG_E_POLICY;
#endif
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
  out_storage->root_path = root;
  return WYRELOG_E_OK;
}

void wyl_service_credential_operation_storage_clear
    (WylServiceCredentialOperationStorage * storage)
{
  if (storage == NULL)
    return;
  g_clear_pointer (&storage->root_path, g_free);
}

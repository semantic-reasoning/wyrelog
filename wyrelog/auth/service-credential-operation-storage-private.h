/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

#ifdef G_OS_WIN32
#include <windows.h>
#endif

G_BEGIN_DECLS;

typedef struct
{
  gchar *root_path;
#ifndef G_OS_WIN32
  gint root_fd;
  gboolean owns_root_fd;
#else
  HANDLE root_handle;
  GPtrArray *ancestor_handles;
  DWORD root_volume_serial;
  DWORD root_file_index_high;
  DWORD root_file_index_low;
#endif
} WylServiceCredentialOperationStorage;

#ifndef G_OS_WIN32
#define WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT { .root_fd = -1, .owns_root_fd = FALSE }
#else
#define WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT \
  { .root_handle = INVALID_HANDLE_VALUE, .ancestor_handles = NULL, \
    .root_volume_serial = 0, .root_file_index_high = 0, \
    .root_file_index_low = 0 }
#endif

/* The override is intended for tests and an explicitly configured state root.
 * A NULL/empty override resolves the platform default and creates only
 * owner-private directories. The returned root is owned by the caller. */
wyrelog_error_t wyl_service_credential_operation_storage_open
    (const gchar * override_path,
    WylServiceCredentialOperationStorage * out_storage);
void wyl_service_credential_operation_storage_clear
    (WylServiceCredentialOperationStorage * storage);

G_END_DECLS;

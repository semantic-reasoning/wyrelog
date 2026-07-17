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

#define WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_MAX_BYTES 255u

/* A child component is deliberately not a path.  It is the single canonical
 * name consumed by a future handle-relative child operation. */
typedef struct
{
  gchar *component;
} WylServiceCredentialOperationChildName;

#define WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT { .component = NULL }

/* This is an immutable snapshot of the validated root identity.  Consumers
 * must pass it back unchanged; no path fallback is permitted. */
typedef struct
{
  gboolean initialized;
  guint64 identity_a;
  guint64 identity_b;
} WylServiceCredentialOperationRootAnchor;

#define WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT \
  { .initialized = FALSE, .identity_a = 0, .identity_b = 0 }

#ifndef G_OS_WIN32
#define WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT \
  { .root_path = NULL, .root_fd = -1, .owns_root_fd = FALSE }
#else
#define WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT \
  { .root_path = NULL, .root_handle = INVALID_HANDLE_VALUE, \
    .ancestor_handles = NULL, \
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

void wyl_service_credential_operation_child_name_clear
    (WylServiceCredentialOperationChildName * name);
wyrelog_error_t wyl_service_credential_operation_child_name_validate
    (const gchar * raw, WylServiceCredentialOperationChildName * out_name);

void wyl_service_credential_operation_root_anchor_clear
    (WylServiceCredentialOperationRootAnchor * anchor);
wyrelog_error_t wyl_service_credential_operation_storage_capture_anchor
    (const WylServiceCredentialOperationStorage * storage,
    WylServiceCredentialOperationRootAnchor * out_anchor);
gboolean wyl_service_credential_operation_storage_anchor_matches
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor);

G_END_DECLS;

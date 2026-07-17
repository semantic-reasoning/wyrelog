/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct
{
  gchar *root_path;
} WylServiceCredentialOperationStorage;

#define WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT { 0 }

/* The override is intended for tests and an explicitly configured state root.
 * A NULL/empty override resolves the platform default and creates only
 * owner-private directories. The returned root is owned by the caller. */
wyrelog_error_t wyl_service_credential_operation_storage_open
    (const gchar * override_path,
    WylServiceCredentialOperationStorage * out_storage);
void wyl_service_credential_operation_storage_clear
    (WylServiceCredentialOperationStorage * storage);

G_END_DECLS;

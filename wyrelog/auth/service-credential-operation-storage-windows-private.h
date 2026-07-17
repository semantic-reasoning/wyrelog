/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "auth/service-credential-operation-storage-private.h"
#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
/* Opens an existing regular child relative to root. This slice deliberately
 * provides no create/replace/delete/lock semantics. */
    BOOL wyl_win_nt_create_relative
    (HANDLE root, const WylServiceCredentialOperationChildName * name,
    ACCESS_MASK access, HANDLE * out_handle);

G_END_DECLS
#endif

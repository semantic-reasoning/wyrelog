/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "auth/service-credential-operation-storage-private.h"
#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS typedef enum
{
  WYL_WIN_CHILD_OPEN = 1,
  WYL_WIN_CHILD_CREATE = 2
} WylWinChildDisposition;

typedef struct
{
  DWORD volume_serial;
  DWORD file_index_high;
  DWORD file_index_low;
} WylWinChildIdentity;

BOOL wyl_win_nt_create_relative
    (HANDLE root, const WylServiceCredentialOperationChildName * name,
    ACCESS_MASK access, WylWinChildDisposition disposition,
    HANDLE * out_handle, WylWinChildIdentity * out_identity,
    wyrelog_error_t * out_error);

G_END_DECLS
#endif

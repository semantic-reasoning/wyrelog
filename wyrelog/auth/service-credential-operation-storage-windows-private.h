/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "auth/service-credential-operation-storage-private.h"
#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS typedef enum
{
  WYL_WIN_CHILD_OPEN = 1,
  WYL_WIN_CHILD_CREATE = 2,
  WYL_WIN_CHILD_OPEN_ALWAYS = 3
} WylWinChildDisposition;

typedef struct
{
  DWORD volume_serial;
  DWORD file_index_high;
  DWORD file_index_low;
} WylWinChildIdentity;

typedef void (*WylWinChildBeforeRenameHookForTest) (gpointer user_data);

BOOL wyl_win_nt_create_relative
    (HANDLE root, const WylServiceCredentialOperationChildName * name,
    ACCESS_MASK access, WylWinChildDisposition disposition, ULONG share_mode,
    HANDLE * out_handle, WylWinChildIdentity * out_identity,
    wyrelog_error_t * out_error);
wyrelog_error_t wyl_win_child_read
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, GBytes ** out_bytes);
wyrelog_error_t wyl_win_child_create
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, GBytes * bytes);
wyrelog_error_t wyl_win_child_replace
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, GBytes * bytes);
wyrelog_error_t wyl_win_child_delete
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name);
G_GNUC_INTERNAL wyrelog_error_t wyl_win_child_delete_exact
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name,
    GBytes * expected_bytes);
G_GNUC_INTERNAL wyrelog_error_t wyl_win_child_confirm_absent
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name);
/* Uses the same permanent zero-length lock namespace contract as POSIX. */
wyrelog_error_t wyl_win_child_lock
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, HANDLE * out_handle);
void wyl_win_child_unlock
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationChildName * name, HANDLE handle);
void wyl_win_child_fail_next_directory_flush_for_test (DWORD error);
void wyl_win_child_set_before_rename_hook_for_test
    (WylWinChildBeforeRenameHookForTest hook, gpointer user_data);
G_GNUC_INTERNAL void
    wyl_win_child_set_before_exact_delete_hook_for_test
    (WylServiceCredentialOperationBeforeExactDeleteHookForTest hook,
    gpointer user_data);
wyrelog_error_t wyl_win_child_classify_nt_create_status_for_test (LONG status);

G_END_DECLS
#endif

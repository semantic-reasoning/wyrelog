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

#ifdef WYL_ENABLE_SERVICE_CREDENTIAL_STORAGE_TEST_HOOKS
typedef void (*WylWinChildBeforeRenameHookForTest) (gpointer user_data);
#endif

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
#ifdef WYL_ENABLE_SERVICE_CREDENTIAL_STORAGE_TEST_HOOKS
/* Compiled only into the focused storage test, which builds these translation
 * units itself and defines the macro through its own c_args.  libwyrelog is
 * never given the macro, so a shipped library declares none of these hooks,
 * defines no armable state for them, and holds no call site that could run
 * one.  Two of them take a caller-supplied function pointer, so they must not
 * exist in a shipped credential-storage path at all. */
G_GNUC_INTERNAL void
    wyl_win_child_fail_next_directory_flush_for_test (DWORD error);
/* Test-only clean-run helper: atomically returns the pending fault and
 * pre-clears it to ERROR_SUCCESS. */
G_GNUC_INTERNAL DWORD
    wyl_win_child_take_next_directory_flush_error_for_test (void);
G_GNUC_INTERNAL void
    wyl_win_child_set_before_rename_hook_for_test
    (WylWinChildBeforeRenameHookForTest hook, gpointer user_data);
/* Test-only clean-run helper: initializes non-NULL outputs to NULL, then
 * takes and clears the paired hook/data snapshot under one lock. */
G_GNUC_INTERNAL void
    wyl_win_child_take_before_rename_hook_for_test
    (WylWinChildBeforeRenameHookForTest * out_hook, gpointer * out_user_data);
G_GNUC_INTERNAL void
    wyl_win_child_set_before_exact_delete_hook_for_test
    (WylServiceCredentialOperationBeforeExactDeleteHookForTest hook,
    gpointer user_data);
/* Test-only clean-run helper: initializes non-NULL outputs to NULL, then
 * takes and clears the paired hook/data snapshot under one lock. */
G_GNUC_INTERNAL void
    wyl_win_child_take_before_exact_delete_hook_for_test
    (WylServiceCredentialOperationBeforeExactDeleteHookForTest * out_hook,
    gpointer * out_user_data);
#endif /* WYL_ENABLE_SERVICE_CREDENTIAL_STORAGE_TEST_HOOKS */
/* Deliberately outside the gate: a pure classifier over an NTSTATUS with no
 * armable state and no call site in the storage paths, so it is not a fault
 * hook and shipping it arms nothing. */
wyrelog_error_t wyl_win_child_classify_nt_create_status_for_test (LONG status);

G_END_DECLS
#endif

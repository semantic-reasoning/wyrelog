/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "auth/service-credential-operation-coordinator-storage-private.h"

G_BEGIN_DECLS
/* One durable operation's non-secret journal record.  The record carries its
 * own authoritative .state field; status listing never infers state from
 * filesystem layout. */
    typedef struct
{
  WylServiceCredentialOperationRecord record;
} WylServiceCredentialOperationStatusEntry;

typedef struct
{
  WylServiceCredentialOperationStatusEntry *entries;
  gsize n_entries;
} WylServiceCredentialOperationStatusList;

/* Enumerate every durable service-credential operation and load each one's
 * non-secret journal record.  This is strictly READ-ONLY: it performs no fence
 * precheck, no policy-store access, and no checkpoint or other write.  It is
 * also tenant-AGNOSTIC and returns ALL operations regardless of subject or
 * tenant; tenant scoping is applied later at the daemon boundary, never here.
 *
 * EVERY per-id load failure is skipped: whether the operation was purged
 * between enumeration and load (WYRELOG_E_NOT_FOUND) or its durable bytes are
 * malformed/undecodable/mismatched (e.g. WYRELOG_E_POLICY), the operation is
 * omitted and enumeration continues.  A read-only diagnostic listing must stay
 * available, and one tenant's corrupt record must never blind another tenant's
 * listing.  Only successfully-loaded records are returned.  Cancellation is the
 * sole abort: a cancelled cancellable, or a load that returns
 * WYRELOG_E_CANCELLED, stops the walk and yields WYRELOG_E_CANCELLED (caller
 * intent, not a record problem).
 *
 * On success *out_list owns the entries (possibly empty) and the caller frees
 * them with wyl_service_credential_operation_status_list_clear.  On any failure
 * *out_list is left untouched. */
wyrelog_error_t wyl_service_credential_operation_coordinator_status_list
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    GCancellable * cancellable,
    WylServiceCredentialOperationStatusList * out_list);

void wyl_service_credential_operation_status_list_clear
    (WylServiceCredentialOperationStatusList * list);

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylServiceCredentialOperationStatusList,
    wyl_service_credential_operation_status_list_clear)
    G_END_DECLS

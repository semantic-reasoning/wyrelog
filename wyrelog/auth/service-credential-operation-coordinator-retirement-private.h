/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "policy/store-handoff-retirement-private.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS typedef struct
{
  gboolean receipt_replayed;
  gboolean snapshot_deleted;
  WylPolicyServiceHandoffRetirementKind kind;
  gint64 retired_at_us;
} WylServiceCredentialOperationRetirementResult;

#define WYL_SERVICE_CREDENTIAL_OPERATION_RETIREMENT_RESULT_INIT { 0 }

G_GNUC_INTERNAL void
    wyl_service_credential_operation_retirement_result_clear
    (WylServiceCredentialOperationRetirementResult * result);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_purge_retired
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, GCancellable * cancellable,
    WylServiceCredentialOperationRetirementResult * out_result);

/* Test-only one-shot observation immediately before the destructive
 * cancellation gate. */
G_GNUC_INTERNAL void
    wyl_service_credential_operation_retirement_set_before_delete_hook_for_test
    (void (*hook) (gpointer data), gpointer data);

typedef struct
{
  gboolean replayed;
  WylServiceCredentialOperationRecord record;
} WylServiceCredentialOperationGuardedBeginResult;

#define WYL_SERVICE_CREDENTIAL_OPERATION_GUARDED_BEGIN_RESULT_INIT \
  { .record = WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT }

G_GNUC_INTERNAL void
    wyl_service_credential_operation_guarded_begin_result_clear
    (WylServiceCredentialOperationGuardedBeginResult * result);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_begin_or_replay_retirement_guarded
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    GCancellable * cancellable,
    WylServiceCredentialOperationGuardedBeginResult * out_result);

G_END_DECLS

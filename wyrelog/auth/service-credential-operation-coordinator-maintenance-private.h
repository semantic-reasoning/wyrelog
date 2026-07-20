/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS typedef enum
{
  /* The authoritative state is not due, already terminal, or already OAR. */
  WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_UNCHANGED = 1,
  /* Durable absence proof advanced PREPARED to terminal NOT_COMMITTED. */
  WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_TERMINAL_NOT_COMMITTED = 2,
  /* A committed successor or operation disposition needs human attention. */
  WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_ATTENTION_REQUIRED = 3,
  /* Authoritative escrow inspection advanced the journal to typed OAR. */
  WYL_SERVICE_CREDENTIAL_OPERATION_MAINTENANCE_OPERATOR_ACTION_REQUIRED = 4,
} WylServiceCredentialOperationMaintenanceOutcome;

/* Reconcile one operation using only its durable journal identity and the
 * policy authority's trusted clock.  The lifecycle lock spans classification
 * and any journal checkpoint, while each authority transaction is completed
 * before journal I/O begins.  A successful call replaces out_record with the
 * exact resulting durable record.  UNCHANGED may therefore return either the
 * byte-identical input state or a tombstone/legacy-backfill terminalization;
 * ATTENTION_REQUIRED returns the byte-identical committed input record. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_maintain_expired
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, GCancellable * cancellable,
    WylServiceCredentialOperationMaintenanceOutcome * out_outcome,
    WylServiceCredentialOperationRecord * out_record);

/* Same operation for an executor that already owns this request's lifecycle
 * lock.  The caller must keep that lock held through return. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_maintain_expired_locked
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, GCancellable * cancellable,
    WylServiceCredentialOperationMaintenanceOutcome * out_outcome,
    WylServiceCredentialOperationRecord * out_record);

/* Frozen publication-target identity shared by execution and maintenance. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_handoff_target_digest
    (const WylServiceCredentialOperationRecord * record,
    guint8
    out_digest[WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES]);

G_END_DECLS

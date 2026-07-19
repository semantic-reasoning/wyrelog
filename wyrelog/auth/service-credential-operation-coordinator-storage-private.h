/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-storage-private.h"

G_BEGIN_DECLS;

/* A lifecycle lock is deliberately distinct from the short-lived journal
 * checkpoint lock.  The native POSIX fd or Windows HANDLE remains opaque to
 * callers and may only be released through the matching API. */
typedef struct
{
  gpointer native_handle;
  WylServiceCredentialOperationChildName child_name;
} WylServiceCredentialOperationCoordinatorLock;

#define WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT \
  { .native_handle = NULL, \
    .child_name = WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT }

wyrelog_error_t wyl_service_credential_operation_coordinator_lock_acquire
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    WylServiceCredentialOperationCoordinatorLock * out_lock);
void wyl_service_credential_operation_coordinator_lock_release
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    WylServiceCredentialOperationCoordinatorLock * lock);

/* Persist or replay the journal entry selected solely by request_id. The
 * persisted operation_id is the canonical request_id; callers cannot supply
 * a separate operation identity. The
 * caller must initialize out_record with
 * WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT; it is unchanged on error.
 * A successful replay may return any valid lifecycle state for the original
 * operation. expires_at_us is persisted as immutable operation intent. */
wyrelog_error_t wyl_service_credential_operation_coordinator_begin_or_replay
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);

/* Load a stable journal snapshot selected solely by a canonical request ID.
 * This intentionally does not acquire the per-operation lock: an anchored
 * atomic replace may yield either the complete old or complete new record.
 * The caller must initialize out_record with
 * WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT; it is unchanged on failure.
 * Missing records return WYRELOG_E_NOT_FOUND. Malformed, unsupported, or
 * mismatched records fail closed with WYRELOG_E_POLICY. */
wyrelog_error_t wyl_service_credential_operation_coordinator_load
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationRecord * out_record);

/* Durably checkpoint the server-side mutation.  The operation is selected by
 * canonical request_id, locked relative to the anchored root, then atomically
 * replaced only for PREPARED -> SERVER_COMMITTED.  A matching durable
 * SERVER_COMMITTED tuple is a replay and leaves its bytes unchanged. */
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_server_committed
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * successor_credential_id,
    guint64 successor_generation, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_server_committed_bound
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * successor_credential_id,
    guint64 successor_generation, const guint8 * binding_digest,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_publication_planned
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * reservation_id,
    const gchar * stage_basename, const gchar * publication_receipt_id,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_publication_prepared
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * reservation_id,
    const gchar * stage_basename, const gchar * stage_identity,
    const gchar * publication_receipt_id, gint64 now_us,
    gboolean * out_replayed, WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_file_published
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * reservation_id,
    const gchar * stage_basename, const gchar * stage_identity,
    const gchar * publication_receipt_id, gint64 now_us,
    gboolean * out_replayed, WylServiceCredentialOperationRecord * out_record);

G_END_DECLS;

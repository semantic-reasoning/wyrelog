/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-journal-private.h"
G_BEGIN_DECLS
/* out_record must be initialized with WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT.
 * It is unchanged on failure and replaced (after validation) on success. */
    wyrelog_error_t wyl_service_credential_operation_coordinator_build_prepared
    (const WylServiceCredentialOperationCoordinatorRequest * request,
    const gchar * operation_id, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record);

/* Advance a valid v3 PREPARED record after the server-side credential
 * mutation has committed.  A matching SERVER_COMMITTED record is replayed
 * without changing its durable timestamp.  out_record is unchanged on
 * failure. */
wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_server_committed
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * successor_credential_id, guint64 successor_generation,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record);
/* Escrow-backed path: PREPARED may carry the all-zero digest; this operation
 * copies the durable escrow binding into SERVER_COMMITTED and makes it part of
 * replay identity. */
wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_server_committed_bound
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * successor_credential_id, guint64 successor_generation,
    const guint8 * binding_digest, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record);

wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_publication_prepared
    (const WylServiceCredentialOperationRecord * existing,
    const gchar * reservation_id, const gchar * stage_basename,
    const gchar * stage_identity, const gchar * publication_receipt_id,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
wyl_service_credential_operation_coordinator_build_file_published (const
    WylServiceCredentialOperationRecord * existing,
    const gchar * reservation_id, const gchar * stage_basename,
    const gchar * stage_identity, const gchar * publication_receipt_id,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
wyl_service_credential_operation_coordinator_build_cleanup_required (const
    WylServiceCredentialOperationRecord * existing, gint64 now_us,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_build_operator_action_required
    (const WylServiceCredentialOperationRecord * existing, const gchar * reason,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
wyl_service_credential_operation_coordinator_build_terminal (const
    WylServiceCredentialOperationRecord * existing, const gchar * reason,
    gint64 now_us, WylServiceCredentialOperationRecord * out_record);
G_END_DECLS

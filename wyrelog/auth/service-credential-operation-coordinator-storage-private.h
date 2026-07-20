/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-storage-private.h"
#include "auth/service-credential-domain-private.h"

G_BEGIN_DECLS;

/* A lifecycle lock is deliberately distinct from the short-lived journal
 * checkpoint lock.  The native POSIX fd or Windows HANDLE remains opaque to
 * callers and may only be released through the matching API. */
typedef struct
{
  gpointer native_handle;
  WylServiceCredentialOperationChildName child_name;
} WylServiceCredentialOperationCoordinatorLock;

/* Borrowed, authority-proven remediation result normalized for one exact
 * journal checkpoint.  Storage revalidates this proof against the raw locked
 * source snapshot before replacing any bytes. */
typedef struct
{
  const gchar *remediation_request_id;
  const gchar *decision_request_id;
  const gchar *current_actor_subject_id;
  wyl_service_credential_handoff_remediation_action_t action;
  guint32 confirmation_version;
  gboolean confirmed;
  gint64 created_at_us;
  guint8 request_fingerprint[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  wyl_service_credential_handoff_remediation_source_kind_t source_kind;
  guint8 source_snapshot_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  wyl_service_credential_handoff_remediation_journal_state_t observed_state;
  const gchar *original_request_id;
  const gchar *original_actor_subject_id;
  const gchar *escrow_id;
  guint8 binding_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  const gchar *successor_credential_id;
  guint64 successor_issuance_generation;
  const gchar *source_disposition_id;
  const gchar *source_audit_id;
  wyl_service_credential_handoff_disposition_reason_t source_reason;
  wyl_service_credential_handoff_remediation_journal_state_t oar_source_state;
  wyl_service_credential_handoff_remediation_oar_cause_t oar_cause;
    wyl_service_credential_handoff_remediation_journal_state_t
      resume_target_state;
  wyl_service_credential_handoff_remediation_outcome_t outcome;
  wyl_service_credential_handoff_remediation_escrow_outcome_t escrow_outcome;
  guint64 credential_generation_after;
  const gchar *audit_id;
  gboolean authority_replayed;
  gboolean revoked_now;
  guint64 invalidation_generation;
  gint64 revoke_event_id;
  guint64 revoke_event_generation;
  const gchar *revoke_event_request_id;
  const gchar *revoke_event_actor_subject_id;
  gint64 revoke_event_created_at_us;
} WylServiceCredentialOperationRemediationProof;

#define WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT \
  { .native_handle = NULL, \
    .child_name = WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT }

typedef struct
{
  const gchar *request_id;
  guint32 expected_journal_version;
  WylServiceCredentialOperationTerminalKind terminal_kind;
  /* Exact revoke ID for OPERATOR_REVOKE_AND_WIPE; optional prior RESUME ID
   * for FILE_PUBLISHED, and NULL only when no remediation marker exists. */
  const gchar *remediation_request_id;
  guint8 raw_snapshot_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
} WylServiceCredentialOperationExactDeleteExpectation;

#define WYL_SERVICE_CREDENTIAL_OPERATION_EXACT_DELETE_EXPECTATION_INIT { 0 }

wyrelog_error_t wyl_service_credential_operation_coordinator_lock_acquire
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    WylServiceCredentialOperationCoordinatorLock * out_lock);
void wyl_service_credential_operation_coordinator_lock_release
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    WylServiceCredentialOperationCoordinatorLock * lock);

/* Requires the matching lifecycle lock from lock_acquire().  The coordinator
 * takes the shorter operation lock only after validating that outer lock,
 * enforcing lifecycle -> operation ordering.  Missing remains NOT_FOUND;
 * only the higher-level purge coordinator may normalize a permanent-receipt
 * replay to success. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_delete_exact_terminal_snapshot
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorLock * lifecycle_lock,
    const WylServiceCredentialOperationExactDeleteExpectation * expectation);

/* Raw storage begin used only after the authority-backed retirement guard.
 * The matching lifecycle lock is mandatory, so begin and permanent receipt
 * creation serialize on one request ID. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_begin_or_replay_locked
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorLock * lifecycle_lock,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);

#ifdef WYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS
/* Storage/journal tests deliberately bypass the authority retirement guard;
 * production code must use begin_or_replay_retirement_guarded(). */
static inline wyrelog_error_t
    wyl_service_credential_operation_coordinator_begin_or_replay_locked_for_test
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorLock * lifecycle_lock,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return wyl_service_credential_operation_coordinator_begin_or_replay_locked
      (storage, anchor, lifecycle_lock, request, now_us, out_replayed,
      out_record);
}

static inline wyrelog_error_t
    wyl_service_credential_operation_coordinator_begin_or_replay_for_test
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  if (out_replayed != NULL)
    *out_replayed = FALSE;
  if (!wyl_service_credential_operation_coordinator_request_is_valid (request))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_service_credential_operation_coordinator_lock_acquire (storage,
      anchor, request != NULL ? request->request_id : NULL, &lifecycle_lock);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_operation_coordinator_begin_or_replay_locked
        (storage, anchor, &lifecycle_lock, request, now_us, out_replayed,
        out_record);
  wyl_service_credential_operation_coordinator_lock_release (storage, anchor,
      &lifecycle_lock);
  return rc;
}
#endif

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
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_load_snapshot
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    guint8 out_snapshot_digest
    [WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES],
    WylServiceCredentialOperationRecord * out_record);

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

/* These lifecycle checkpoints derive their durable reason from the typed
 * operation, so callers cannot provide journal reason strings.  A matching
 * target record is an exact replay whose bytes and timestamp are retained. */
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_cleanup_required
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_successor_inactive_oar
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationOarCause cause,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_receipt_oar
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationOarCause cause,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_escrow_oar
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationOarCause cause,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_terminal_not_committed
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_terminal_file_published
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_operator_resume
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    const WylServiceCredentialOperationRemediationProof * proof,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_operator_revoke_and_wipe
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    const WylServiceCredentialOperationRemediationProof * proof,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record);

G_END_DECLS;

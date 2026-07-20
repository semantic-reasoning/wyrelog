/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "auth/service-credential-domain-private.h"
#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "wyrelog/handle.h"
#include "wyrelog/session.h"

G_BEGIN_DECLS typedef struct
{
  const gchar *remediation_request_id;
  const gchar *audit_id;
  wyl_service_credential_handoff_remediation_action_t action;
  guint32 confirmation_version;
  gboolean confirmed;
} WylServiceCredentialOperationHandoffRemediationRequest;

typedef struct
{
  WylSession *session;
  const gchar *authenticated_actor_subject_id;
  gint64 guard_timestamp;
  const gchar *guard_loc_class;
  gint64 guard_risk;
  const gchar *decision_request_id;
    gint64 (*now_us) (gpointer data);
  gpointer clock_data;
  GCancellable *cancellable;
  void (*after_authorization) (gpointer data);
  gpointer authorization_checkpoint_data;
    wyrelog_error_t (*invalidate_credential) (gpointer data,
      const gchar * credential_id, guint64 generation);
  gpointer invalidation_data;
} WylServiceCredentialOperationHandoffRemediationRuntime;

typedef struct
{
  gboolean authority_replayed;
  gboolean journal_replayed;
  gchar *remediation_request_id;
  gchar *audit_id;
  wyl_service_credential_handoff_remediation_action_t action;
  wyl_service_credential_handoff_remediation_outcome_t outcome;
  wyl_service_credential_handoff_remediation_escrow_outcome_t escrow_outcome;
  gint64 created_at_us;
  wyl_service_credential_handoff_remediation_source_kind_t source_kind;
  wyl_service_credential_handoff_remediation_journal_state_t observed_state;
  wyl_service_credential_handoff_remediation_journal_state_t oar_source_state;
  wyl_service_credential_handoff_remediation_oar_cause_t oar_cause;
    wyl_service_credential_handoff_remediation_journal_state_t
      resume_target_state;
  wyl_service_credential_handoff_disposition_reason_t source_reason;
  WylServiceCredentialOperationState checkpoint_state;
  WylServiceCredentialOperationState checkpoint_target_state;
} WylServiceCredentialOperationHandoffRemediationResult;

#define WYL_SERVICE_CREDENTIAL_OPERATION_HANDOFF_REMEDIATION_RESULT_INIT \
  { 0 }

G_GNUC_INTERNAL void
    wyl_service_credential_operation_handoff_remediation_result_clear
    (WylServiceCredentialOperationHandoffRemediationResult * result);

/* Authenticated terminal remediation for one durable handoff. The caller can
 * supply only fresh action identities and confirmation; the exact tuple,
 * source journal digest, attention provenance, and OAR context are derived
 * while the per-operation lifecycle lock is held. Authority commits before
 * the exact v6 journal checkpoint. RESUME performs no publication, receipt,
 * unseal, or secret I/O; the existing executor owns the subsequent retry. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_remediate_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * original_request_id,
    const WylServiceCredentialOperationHandoffRemediationRequest * request,
    const WylServiceCredentialOperationHandoffRemediationRuntime * runtime,
    WylServiceCredentialOperationHandoffRemediationResult * out_result);

G_END_DECLS

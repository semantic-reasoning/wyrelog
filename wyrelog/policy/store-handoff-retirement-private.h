/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "policy/store-private.h"

G_BEGIN_DECLS
#define WYL_POLICY_HANDOFF_RETENTION_MIN_US (30 * G_TIME_SPAN_DAY)
    typedef enum
{
  WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED = 1,
  WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE = 2,
} WylPolicyServiceHandoffRetirementKind;

/* Non-secret proof copied from a locked v6 TERMINAL journal.  The policy
 * authority independently follows every referenced provenance row before it
 * records a permanent receipt. */
typedef struct
{
  guint32 journal_version;
  WylPolicyServiceHandoffRemediationJournalState journal_state;
  WylPolicyServiceHandoffRetirementKind terminal_kind;
  WylPolicyServiceHandoffExactTuple tuple;
  guint8 raw_journal_snapshot_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gint64 journal_updated_at_us;

  /* FILE_PUBLISHED only. */
  const gchar *delivery_actor_subject_id;
  guint8 delivery_proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];

  /* Required for REVOKE_AND_WIPE and optional for a resumed FILE_PUBLISHED.
   * These are the exact durable v6 remediation marker fields. */
  const gchar *remediation_request_id;
  guint8 remediation_source_snapshot_digest
      [WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  guint8 remediation_request_fingerprint
      [WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
} WylPolicyServiceHandoffRetirementInput;

typedef struct
{
  gboolean replayed;
  gchar *original_request_id;
  WylPolicyServiceHandoffRetirementKind terminal_kind;
  guint8 raw_journal_snapshot_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gchar *delivery_disposition_id;
  gchar *delivery_audit_id;
  guint8 delivery_proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gchar *revoke_remediation_request_id;
  gchar *revoke_audit_id;
  gint64 revoke_event_id;
  gchar *resume_remediation_request_id;
  gchar *resume_audit_id;
  guint8 remediation_source_snapshot_digest
      [WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  guint8 remediation_request_fingerprint
      [WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gint64 retention_basis_at_us;
  gint64 retired_at_us;
} WylPolicyServiceHandoffRetirementResult;

G_GNUC_INTERNAL void wyl_policy_service_handoff_retirement_result_clear
    (WylPolicyServiceHandoffRetirementResult * result);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_retirement_lookup_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store, const gchar * original_request_id,
    WylPolicyServiceHandoffRetirementResult * out_result);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_retirement_record_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffRetirementInput * input,
    WylPolicyServiceHandoffRetirementResult * out_result);

G_END_DECLS

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "policy/store-private.h"

G_BEGIN_DECLS
/* Journal-derived, non-secret proof for policy-owned maintenance decisions.
 * ISSUE uses subject_id+tenant_id and a NULL old_credential_id; ROTATE uses
 * old_credential_id and NULL subject_id+tenant_id.  PREPARED proofs have no
 * successor in tuple.  Committed proofs carry the exact successor tuple. */
    typedef struct
{
  WylPolicyServiceHandoffExactTuple tuple;
  WylServiceCredentialFenceOperation operation;
  const gchar *subject_id;
  const gchar *tenant_id;
  const gchar *old_credential_id;
  guint8 target_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gint64 deadline_at_us;
} WylPolicyServiceHandoffMaintenanceProof;

typedef enum
{
  WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_DUE = 1,
  WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED = 2,
  WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_COMMITTED = 3,
} WylPolicyServiceHandoffPreparedMaintenanceOutcome;

typedef struct
{
  WylPolicyServiceHandoffPreparedMaintenanceOutcome outcome;
  /* Store-authoritative checkpoint time.  NOT_COMMITTED uses the durable
   * disposition created_at_us, including replay; other outcomes use the
   * trusted clock sample taken by this classification. */
  gint64 created_at_us;
  WylPolicyServiceHandoffDispositionResult disposition;
  gchar successor_credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  guint64 successor_generation;
  guint8 binding_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
} WylPolicyServiceHandoffPreparedMaintenanceResult;

typedef enum
{
  WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ACTIVE = 1,
  WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_MISSING = 2,
  WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_FOREIGN = 3,
  WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_EXPIRED = 4,
  WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_REVOKED = 5,
  WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED = 6,
  WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED = 7,
} WylPolicyServiceHandoffCommittedMaintenanceOutcome;

typedef struct
{
  WylPolicyServiceHandoffCommittedMaintenanceOutcome outcome;
  /* Store-authoritative checkpoint time.  Durable disposition outcomes use
   * disposition.created_at_us; non-disposition outcomes use this call's
   * trusted clock sample. */
  gint64 created_at_us;
  WylPolicyServiceHandoffDispositionResult disposition;
} WylPolicyServiceHandoffCommittedMaintenanceResult;

G_GNUC_INTERNAL void
    wyl_policy_service_handoff_prepared_maintenance_result_clear
    (WylPolicyServiceHandoffPreparedMaintenanceResult * result);
G_GNUC_INTERNAL void
    wyl_policy_service_handoff_committed_maintenance_result_clear
    (WylPolicyServiceHandoffCommittedMaintenanceResult * result);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_maintain_prepared_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffPreparedMaintenanceResult * out_result);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_maintain_committed_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult * out_result);

/* Resolve only an existing, still-unconsumed committed ATTENTION incident.
 * Unlike maintenance classification this read never mints an expiry
 * disposition and never changes credential, escrow, or remediation state. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_resolve_current_attention_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult * out_result);

typedef gint64 (*WylPolicyServiceHandoffMaintenanceNowFunc) (gpointer data);

/* Test-only borrowed clock. NULL restores trusted real time. */
G_GNUC_INTERNAL void wyl_policy_store_handoff_maintenance_set_clock_for_test
    (wyl_policy_store_t * store,
    WylPolicyServiceHandoffMaintenanceNowFunc now_us, gpointer data);

G_END_DECLS

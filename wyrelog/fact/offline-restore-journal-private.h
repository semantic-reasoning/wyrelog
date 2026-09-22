/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-main-transition-private.h"
#include "fact/offline-backup-manifest-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

#define WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION 1u
#define WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS 1024u
#define WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES (8u * 1024u * 1024u)
#define WYL_FACT_OFFLINE_RESTORE_MAX_TEXT 1024u

/*
 * Pure, bounded serialization and recovery-decision contract for #552.
 * This surface performs no filesystem or policy mutation and makes no
 * durability claim.  Its SHA-256 detects accidental corruption only; the
 * MANIFEST_AUTHENTICATED value is an assertion supplied by a later loader
 * after authority-protected provenance validation, not a result of decoding.
 * A storage layer must durably CAS a new revision before executing the
 * mutation represented by ATTEMPT_UNKNOWN.
 */

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_SCOPE_INVALID = 0,
  WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT,
  WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH,
} WylFactOfflineRestoreScope;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_NONE = 0,
  WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
} WylFactOfflineRestoreConfirmation;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_MANIFEST_UNVERIFIED = 0,
  WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED,
} WylFactOfflineRestoreManifestTrust;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_DECISION_NONE = 0,
  WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT,
  WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK,
} WylFactOfflineRestoreDecision;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE = 0,
  WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN,
  WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED,
} WylFactOfflineRestoreAttempt;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_NONE = 0,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_CONFIRMATION,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_MANIFEST_TRUST,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_TARGET_NOT_SEALED,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_TARGET_NOT_DRAINED,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_AUTHORITY,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_MAPPING,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_GENERATION,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_INVENTORY,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_UNKNOWN_ARTIFACT,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_FOREIGN_OPERATION,
  WYL_FACT_OFFLINE_RESTORE_CONFLICT_FOREIGN_MAIN,
} WylFactOfflineRestoreConflict;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_RECOVERY_REFUSE = 0,
  WYL_FACT_OFFLINE_RESTORE_RECOVERY_INSPECT_ONLY,
  WYL_FACT_OFFLINE_RESTORE_RECOVERY_ROLLBACK,
  WYL_FACT_OFFLINE_RESTORE_RECOVERY_CONTINUE_COMMIT,
  WYL_FACT_OFFLINE_RESTORE_RECOVERY_POLICY_CAS,
  WYL_FACT_OFFLINE_RESTORE_RECOVERY_LIFECYCLE_HANDOFF,
  WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE,
} WylFactOfflineRestoreRecovery;

typedef struct
{
  const gchar *graph_id;
  guint64 lifecycle_generation;
  guint64 reconciliation_generation;
  WylFactArtifactInventoryIdentity expected_main_identity;
  WylFactArtifactInventoryIdentity staged_main_identity;
} WylFactOfflineRestoreAdmissionGraphEvidence;

typedef struct
{
  /* Closed projection produced while the caller retains the #622 inventory,
   * #623 observation, sealed/drained lifecycle barrier, and root writer
   * authority.  The identifiers below bind that projection to one journal;
   * this value is not itself an authority token. */
  const gchar *operation_uuid;
  const gchar *tenant_id;
  const gchar *selected_graph_id;
  guint8 manifest_sha256[32];
  guint64 tenant_lifecycle_generation;
  guint64 tenant_reconciliation_generation;
  gboolean confirmed;
  gboolean manifest_authenticated;
  gboolean target_sealed;
  gboolean target_drained;
  gboolean exclusive_root_authority;
  gboolean inventory_stable;
  guint unknown_artifacts;
  gboolean foreign_operation_artifact;
  gboolean foreign_main;
  /* Ordered exactly like journal->graphs; borrowed for the call. */
  const GPtrArray *graphs;
} WylFactOfflineRestoreAdmissionEvidence;

typedef struct
{
  gchar *graph_id;
  guint64 lifecycle_generation;
  guint64 reconciliation_generation;
  gboolean expected_main_absent;
  WylFactArtifactInventoryIdentity expected_main_identity;
} WylFactOfflineRestoreTargetGraph;

typedef struct
{
  gchar *graph_id;
  gchar *store_uuid;
  guint64 format_version;
  guint64 path_encoding_version;
  gchar *schema_digest;
  guint64 logical_bytes;
  guint64 physical_bytes;
  gchar *checksum;
  guint64 destination_lifecycle_generation;
  guint64 destination_reconciliation_generation;
  gboolean expected_main_absent;
  WylFactArtifactInventoryIdentity expected_main_identity;
  WylFactArtifactInventoryIdentity staged_main_identity;
  gboolean copied;
  gboolean checksum_verified;
  gboolean identity_verified;
  gboolean schema_verified;
  gboolean replay_preflighted;
  WylFactArtifactMainTransitionState transition_state;
  WylFactArtifactMainTransitionOp next_op;
  gboolean transition_terminal;
  WylFactArtifactMainTransitionOp pending_op;
  WylFactOfflineRestoreAttempt attempt;
  gboolean resume_forbidden;
  gboolean durability_unprovable_acknowledged;
} WylFactOfflineRestoreJournalGraph;

typedef struct
{
  guint version;
  guint64 revision;
  gchar *operation_uuid;
  WylFactOfflineRestoreScope scope;
  gchar *tenant_id;
  gchar *selected_graph_id;
  guint8 manifest_sha256[32];
  guint64 source_tenant_lifecycle_generation;
  guint64 destination_tenant_lifecycle_generation;
  guint64 destination_tenant_reconciliation_generation;
  WylFactOfflineRestoreConfirmation confirmation;
  WylFactOfflineRestoreManifestTrust manifest_trust;
  WylFactOfflineRestoreDecision decision;
  gboolean policy_generation_published;
  gboolean lifecycle_handoff_complete;
  GPtrArray *graphs;
} WylFactOfflineRestoreJournal;

void wyl_fact_offline_restore_target_graph_free
  (WylFactOfflineRestoreTargetGraph *graph);
void wyl_fact_offline_restore_journal_clear
  (WylFactOfflineRestoreJournal *journal);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylFactOfflineRestoreJournal,
    wyl_fact_offline_restore_journal_clear)

WylFactOfflineRestoreConflict wyl_fact_offline_restore_classify_admission
  (const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreAdmissionEvidence *evidence);

wyrelog_error_t wyl_fact_offline_restore_journal_init
  (WylFactOfflineRestoreJournal *journal, GBytes *canonical_manifest,
    const gchar *operation_uuid, WylFactOfflineRestoreScope scope,
    const gchar *selected_graph_id, guint64 destination_tenant_lifecycle,
    guint64 destination_tenant_reconciliation,
    const GPtrArray *destination_graphs,
    WylFactOfflineRestoreConfirmation confirmation,
    WylFactOfflineRestoreManifestTrust manifest_trust);
wyrelog_error_t wyl_fact_offline_restore_journal_encode
  (const WylFactOfflineRestoreJournal *journal, GBytes **out_bytes);
/* |out_journal| must be zero-initialized or previously cleared.  Decode
 * zeroes it on every failure; callers must clear a successful value before
 * reusing the same storage. */
wyrelog_error_t wyl_fact_offline_restore_journal_decode
  (GBytes *bytes, WylFactOfflineRestoreJournal *out_journal);

wyrelog_error_t wyl_fact_offline_restore_journal_mark_preflight
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id);
wyrelog_error_t wyl_fact_offline_restore_journal_bind_staged_identity
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    const WylFactArtifactInventoryIdentity *identity);
wyrelog_error_t wyl_fact_offline_restore_journal_decide
  (WylFactOfflineRestoreJournal *journal,
    WylFactOfflineRestoreDecision decision);
wyrelog_error_t wyl_fact_offline_restore_journal_begin_attempt
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    WylFactArtifactMainTransitionOp operation);
wyrelog_error_t wyl_fact_offline_restore_journal_complete_attempt
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    WylFactArtifactMainTransitionState state,
    WylFactArtifactMainTransitionOp next_op, gboolean terminal);
wyrelog_error_t wyl_fact_offline_restore_journal_mark_policy_published
  (WylFactOfflineRestoreJournal *journal);
wyrelog_error_t wyl_fact_offline_restore_journal_mark_lifecycle_handoff
  (WylFactOfflineRestoreJournal *journal);
WylFactOfflineRestoreRecovery wyl_fact_offline_restore_journal_recovery
  (const WylFactOfflineRestoreJournal *journal);

/* TRUE only when |desired| is the result of exactly one public journal
 * mutator applied to |current|.  This is the semantic half of durable CAS:
 * storage compares revisions, while this helper prevents a caller from
 * changing immutable operation data or combining two state transitions in
 * one revision. */
gboolean wyl_fact_offline_restore_journal_is_legal_successor
  (const WylFactOfflineRestoreJournal *current,
    const WylFactOfflineRestoreJournal *desired);

G_END_DECLS

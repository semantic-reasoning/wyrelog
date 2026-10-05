/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-commit-authority-private.h"

#include <string.h>

#include "fact/graph-artifact-transition-posix-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/offline-restore-stage-private.h"
#include "fact/root-writer-lease-private.h"

#ifdef __linux__
#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*tenant_sync_staged_checkpoint)
  (const gchar *, gpointer);
static gpointer tenant_sync_staged_checkpoint_data;
static wyrelog_error_t (*tenant_retain_checkpoint) (const gchar *, gpointer);
static gpointer tenant_retain_checkpoint_data;
static wyrelog_error_t (*tenant_sync_rollback_checkpoint)
  (const gchar *, gpointer);
static gpointer tenant_sync_rollback_checkpoint_data;
static wyrelog_error_t (*tenant_sync_retain_dir_checkpoint)
  (const gchar *, gpointer);
static gpointer tenant_sync_retain_dir_checkpoint_data;
static wyrelog_error_t (*tenant_publish_checkpoint) (const gchar *, gpointer);
static gpointer tenant_publish_checkpoint_data;
static wyrelog_error_t (*tenant_sync_publish_dir_checkpoint)
  (const gchar *, gpointer);
static gpointer tenant_sync_publish_dir_checkpoint_data;
static wyrelog_error_t (*tenant_reserve_checkpoint)
  (const gchar *, const gchar *, gpointer);
static gpointer tenant_reserve_checkpoint_data;
static wyrelog_error_t (*tenant_companion_checkpoint) (const gchar *, gpointer);
static gpointer tenant_companion_checkpoint_data;
static wyrelog_error_t (*finalize_checkpoint) (const gchar *, gpointer);
static gpointer finalize_checkpoint_data;

void
wyl_fact_offline_restore_tenant_commit_sync_staged_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  tenant_sync_staged_checkpoint = checkpoint;
  tenant_sync_staged_checkpoint_data = data;
}

void
wyl_fact_offline_restore_tenant_commit_retain_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  tenant_retain_checkpoint = checkpoint;
  tenant_retain_checkpoint_data = data;
}

void
wyl_fact_offline_restore_tenant_commit_sync_rollback_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  tenant_sync_rollback_checkpoint = checkpoint;
  tenant_sync_rollback_checkpoint_data = data;
}

void
wyl_fact_offline_restore_tenant_commit_sync_retain_dir_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  tenant_sync_retain_dir_checkpoint = checkpoint;
  tenant_sync_retain_dir_checkpoint_data = data;
}

void
wyl_fact_offline_restore_tenant_commit_publish_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  tenant_publish_checkpoint = checkpoint;
  tenant_publish_checkpoint_data = data;
}

void
wyl_fact_offline_restore_tenant_commit_sync_publish_dir_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  tenant_sync_publish_dir_checkpoint = checkpoint;
  tenant_sync_publish_dir_checkpoint_data = data;
}

void
wyl_fact_offline_restore_tenant_reserve_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, const gchar *, gpointer),
    gpointer data)
{
  tenant_reserve_checkpoint = checkpoint;
  tenant_reserve_checkpoint_data = data;
}

void
wyl_fact_offline_restore_tenant_companion_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  tenant_companion_checkpoint = checkpoint;
  tenant_companion_checkpoint_data = data;
}
#endif
static wyrelog_error_t check_runtime (WylFactGraphRuntimeManager *runtime,
    const WylFactGraphKey *key);

typedef struct
{
  WylFactGraphKey key;
  WylFactGraphQuiescenceToken *quiescence;
  WylFactGraphDirectory directory;
  WylFactArtifactTransitionPosix *provider;
} TenantBindGraph;

typedef struct
{
  WylFactRootWriterLease *lease;
  WylFactGraphResolver *resolver;
  WylFactGraphRuntimeManager *runtime;
  TenantBindGraph *graphs;
  guint graph_count;
} TenantBindEffect;

static gint
tenant_commit_v5_graph_phase (const WylFactOfflineRestoreJournalGraph *graph)
{
  if (graph == NULL || graph->expected_main_absent
      || graph->old_provisioning_uuid == NULL || !graph->replay_preflighted
      || graph->transition_terminal || graph->resume_forbidden
      || graph->durability_unprovable_acknowledged)
    return -1;
  if (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) {
    if (graph->pending_op != graph->next_op)
      return -1;
  } else if (graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
    return -1;
  switch (graph->next_op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
      return graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
             && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
             || graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) ? 0 : -1;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
      return graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
             && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
             || graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) ? 1 : -1;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
      return graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
             && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
             || graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) ? 2 : -1;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      return graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
             && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
             || graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) ? 3 : -1;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      return graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
             && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
             || graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) ? 4 : -1;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      return graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
             && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
             || graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) ? 5 : -1;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE:
      return graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
             && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
             && !graph->transition_terminal ? 6 : -1;
    default:
      return -1;
  }
}

gboolean
wyl_fact_offline_restore_tenant_commit_step_eligible
  (const WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    WylFactArtifactMainTransitionOp operation)
{
  if (journal == NULL || journal->graphs == NULL || journal->graphs->len == 0
      || graph_id == NULL || *graph_id == '\0')
    return FALSE;
  gint operation_phase = -1;
  switch (operation) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED: operation_phase = 0; break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN: operation_phase = 1; break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE: operation_phase = 2; break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR: operation_phase = 3; break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH: operation_phase = 4; break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR: operation_phase = 5; break;
    default: return FALSE;
  }
  gboolean found = FALSE;
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    gint phase = tenant_commit_v5_graph_phase (graph);
    gboolean selected = graph != NULL && g_strcmp0 (graph->graph_id, graph_id) == 0;
    if (selected) {
      if (found || phase != operation_phase)
        return FALSE;
      found = TRUE;
    } else if (phase < 0 || phase > (operation_phase >= 4 ? 6 : operation_phase + 1)
        || (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
        || (operation_phase == 0 && phase > 1)
        || (operation_phase == 1 && phase < 1)
        || (operation_phase == 2 && (phase < 1 || phase > 3))
        || (operation_phase == 3 && (phase < 1 || phase > 4))
        || (operation_phase >= 4 && phase < 1))
      return FALSE;
  }
  return found;
}

static wyrelog_error_t
tenant_commit_v5_prove_reacquire (wyl_policy_store_t *policy,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    const WylFactOfflineRestoreJournal *journal, GBytes *canonical)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  WylPolicyOfflineRestoreRecord *record = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy,
            journal->operation_uuid, &record);
  if (rc == WYRELOG_E_OK && (journal->version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal->graphs == NULL || journal->graphs->len == 0
      || record->revision != journal->revision
      || !g_bytes_equal (record->journal_blob, canonical)))
    rc = WYRELOG_E_POLICY;
  wyl_policy_offline_restore_record_free (record);
  WylPolicyFactBackupSnapshot *snapshot = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_read_fact_backup_snapshot (policy,
            journal->tenant_id, &snapshot);
  if (rc == WYRELOG_E_OK && (snapshot->tenant == NULL
      || snapshot->graphs == NULL
      || snapshot->graphs->len != journal->graphs->len
      || snapshot->tenant->lifecycle_state !=
      WYL_POLICY_TENANT_LIFECYCLE_SEALED
      || !snapshot->tenant->sealed_compatibility
      || snapshot->tenant->lifecycle_generation !=
      journal->destination_tenant_lifecycle_generation
      || snapshot->tenant->reconciliation_generation !=
      journal->destination_tenant_reconciliation_generation))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    const WylPolicyFactBackupGraphSnapshot *entry = NULL;
    for (guint j = 0; j < snapshot->graphs->len; j++) {
      const WylPolicyFactBackupGraphSnapshot *candidate =
          g_ptr_array_index (snapshot->graphs, j);
      if (candidate->authority != NULL && g_strcmp0
            (candidate->authority->graph_id, graph->graph_id) == 0) {
        if (entry != NULL)
          rc = WYRELOG_E_POLICY;
        entry = candidate;
      }
    }
    const WylPolicyGraphAuthorityRecord *authority =
        entry != NULL ? entry->authority : NULL;
    if (authority == NULL || authority->lifecycle_state !=
        WYL_POLICY_GRAPH_LIFECYCLE_SEALED
        || !authority->sealed_compatibility
        || authority->materialization_state !=
        WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED
        || !authority->has_store_identity
        || authority->last_error_class != WYL_POLICY_GRAPH_ERROR_NONE
        || g_strcmp0 (authority->store_uuid, graph->store_uuid) != 0
        || authority->format_version != graph->format_version
        || authority->path_encoding_version != graph->path_encoding_version
        || g_strcmp0 (entry->active_schema_digest,
        (graph->old_schema_digest == NULL ? graph->schema_digest
        : graph->old_schema_digest)) != 0
        || authority->lifecycle_generation !=
        graph->destination_lifecycle_generation
        || authority->reconciliation_generation !=
        graph->destination_reconciliation_generation)
      rc = WYRELOG_E_POLICY;
    g_autoptr (GPtrArray) provisioning = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_graph_provisioning_list_for_graph (policy,
              journal->tenant_id, graph->graph_id, &provisioning);
    if (rc == WYRELOG_E_OK && provisioning->len != 1)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      const WylPolicyGraphProvisioningRecord *row =
          g_ptr_array_index (provisioning, 0);
      if (row->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE
          || g_strcmp0 (row->op_uuid,
          graph->old_provisioning_uuid) != 0
          || g_strcmp0 (row->store_uuid, graph->store_uuid) != 0)
        rc = WYRELOG_E_POLICY;
    }
  }
  wyl_policy_fact_backup_snapshot_free (snapshot);
  return rc;
}

static wyrelog_error_t
tenant_commit_v5_quiesce (wyl_policy_store_t *policy,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    WylFactGraphRuntimeManager *runtime,
    const WylFactOfflineRestoreJournal *journal, GBytes *canonical,
    const WylFactGraphKey *key, gint64 timeout_us,
    WylFactGraphQuiescenceToken **out_token)
{
  wyrelog_error_t rc = wyl_fact_graph_runtime_manager_quiesce (runtime,
          key, timeout_us, out_token);
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;
  rc = tenant_commit_v5_prove_reacquire (policy, lease, resolver, journal,
          canonical);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed (runtime,
            key, timeout_us, out_token);
  if (rc == WYRELOG_E_OK)
    rc = tenant_commit_v5_prove_reacquire (policy, lease, resolver, journal,
            canonical);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_token, wyl_fact_graph_quiescence_token_release);
  return rc;
}

static wyrelog_error_t
tenant_commit_v6_quiesce (wyl_policy_store_t *policy,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    WylFactGraphRuntimeManager *runtime,
    const WylPolicyOfflineRestoreRecord *expected,
    const WylFactGraphKey *key, gint64 timeout_us,
    WylFactGraphQuiescenceToken **out_token)
{
  wyrelog_error_t rc = wyl_fact_graph_runtime_manager_quiesce (runtime,
          key, timeout_us, out_token);
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;
  rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v6_prove (policy,
            expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed (runtime,
            key, timeout_us, out_token);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v6_prove (policy,
            expected);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_token, wyl_fact_graph_quiescence_token_release);
  return rc;
}

static wyrelog_error_t
tenant_commit_v7_quiesce (wyl_policy_store_t *policy,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    WylFactGraphRuntimeManager *runtime,
    const WylPolicyOfflineRestoreRecord *expected,
    const WylFactGraphKey *key, gint64 timeout_us,
    WylFactGraphQuiescenceToken **out_token)
{
  wyrelog_error_t rc = wyl_fact_graph_runtime_manager_quiesce (runtime,
          key, timeout_us, out_token);
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;
  rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v7_prove (policy,
            expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed (runtime,
            key, timeout_us, out_token);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v7_prove (policy,
            expected);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_token, wyl_fact_graph_quiescence_token_release);
  return rc;
}

static wyrelog_error_t
tenant_commit_v8_quiesce (wyl_policy_store_t *policy,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    WylFactGraphRuntimeManager *runtime,
    const WylPolicyOfflineRestoreRecord *expected,
    const WylFactGraphKey *key, gint64 timeout_us,
    WylFactGraphQuiescenceToken **out_token)
{
  wyrelog_error_t rc = wyl_fact_graph_runtime_manager_quiesce (runtime,
          key, timeout_us, out_token);
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;
  rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v8_prove (policy,
            expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed (runtime,
            key, timeout_us, out_token);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v8_prove (policy,
            expected);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_token, wyl_fact_graph_quiescence_token_release);
  return rc;
}

static wyrelog_error_t
tenant_bind_prove_graph (TenantBindEffect *context,
    const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreJournalGraph *graph,
    TenantBindGraph *held, const gchar *active_uuid)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (context->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (context->lease,
            context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (context->runtime, &held->key);
  g_autoptr (WylFactOfflineRestoreStageReader) reader = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_open (context->resolver,
            &held->directory, context->lease, journal->operation_uuid,
            &graph->staged_main_identity, &reader);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_verify_content (reader,
            graph->logical_bytes, graph->checksum);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_revalidate (reader);
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) initial = NULL;
  WylFactArtifactMainTransitionObservation observation = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture (held->provider,
            &lifecycle, &initial, &observation);
  WylFactArtifactMainTransitionRequest request = {
    .operation_uuid = journal->operation_uuid,
    .directory_identity = observation.directory_identity,
    .lease_identity = observation.lease_identity,
    .expected_main_absent = FALSE,
    .expected_main_identity = graph->expected_main_identity,
    .staged_main_identity = graph->staged_main_identity,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation ready = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture_provisioned
          (held->provider, active_uuid, &request,
            WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, &lifecycle,
            &snapshot, &ready);
  const WylFactArtifactMainTransitionEntryEvidence *stage =
      &ready.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE];
  if (rc == WYRELOG_E_OK
      && (!stage->present || stage->reparse || stage->link_count != 1
      || stage->owner_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING
      || !wyl_fact_artifact_inventory_identity_equal (&stage->identity,
      &graph->staged_main_identity)))
    rc = WYRELOG_E_POLICY;
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  WylFactArtifactMainTransitionResult result = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
            &ready, &result, &transition);
  if (rc == WYRELOG_E_OK
      && (transition == NULL || result.state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
      || result.next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED))
    rc = WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
tenant_bind_effect (GBytes *canonical_journal,
    const GPtrArray *active_uuids, gpointer user_data)
{
  TenantBindEffect *context = user_data;
  g_auto (WylFactOfflineRestoreJournal) decoded = { 0 };
  if (wyl_fact_offline_restore_journal_decode (canonical_journal,
      &decoded) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournal *journal = &decoded;
  if (journal == NULL || journal->graphs == NULL || active_uuids == NULL
      || journal->graphs->len != context->graph_count
      || active_uuids->len != context->graph_count)
    return WYRELOG_E_POLICY;
  for (guint i = 0; i < context->graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    const gchar *uuid = g_ptr_array_index ((GPtrArray *) active_uuids, i);
    wyrelog_error_t rc = tenant_bind_prove_graph (context, journal, graph,
            &context->graphs[i], uuid);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
tenant_reserve_effect (GBytes *canonical_journal,
    const GPtrArray *active_uuids, const GPtrArray *replacement_uuids,
    gpointer user_data)
{
  TenantBindEffect *context = user_data;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_decode
        (canonical_journal, &journal);
  if (rc != WYRELOG_E_OK || journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.graphs->len != context->graph_count
      || active_uuids == NULL || replacement_uuids == NULL
      || active_uuids->len != context->graph_count
      || replacement_uuids->len != context->graph_count)
    return WYRELOG_E_POLICY;
  for (guint pass = 0; pass < 2; pass++) {
    for (guint i = 0; i < context->graph_count; i++) {
      const WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal.graphs, i);
      TenantBindGraph *held = &context->graphs[i];
      const gchar *old_uuid = g_ptr_array_index ((GPtrArray *) active_uuids, i);
      const gchar *new_uuid = g_ptr_array_index
            ((GPtrArray *) replacement_uuids, i);
      if (old_uuid == NULL || new_uuid == NULL
          || g_strcmp0 (held->key.tenant_id, journal.tenant_id) != 0
          || g_strcmp0 (held->key.graph_id, graph->graph_id) != 0
          || g_strcmp0 (old_uuid, graph->old_provisioning_uuid) != 0
          || graph->transition_state !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
          || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
          || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
          || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
        return WYRELOG_E_POLICY;
#ifdef WYL_TEST_HANDLE_SEAMS
      if (pass == 0 && tenant_reserve_checkpoint != NULL) {
        rc = tenant_reserve_checkpoint (graph->graph_id, new_uuid,
                tenant_reserve_checkpoint_data);
        if (rc != WYRELOG_E_OK)
          return rc;
      }
#endif
      rc = wyl_fact_root_writer_lease_verify (context->lease);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_graph_resolver_revalidate (context->resolver);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_root_writer_lease_authorizes_resolver (context->lease,
                context->resolver);
      if (rc == WYRELOG_E_OK)
        rc = check_runtime (context->runtime, &held->key);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_graph_restore_tenant_reserved_post_publish_shape_open
              (context->resolver, &held->directory, context->lease,
                old_uuid, journal.operation_uuid, new_uuid,
                &graph->expected_main_identity,
                &graph->staged_main_identity);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
  }
  return WYRELOG_E_OK;
}

typedef struct
{
  TenantBindEffect binding;
  const gchar *graph_id;
  gboolean sync;
  WylFactArtifactMainTransitionEffect observed_effect;
} TenantSyncEffect;

static wyrelog_error_t
tenant_sync_staged_effect (GBytes *canonical_journal,
    const GPtrArray *active_uuids, gpointer user_data)
{
  TenantSyncEffect *context = user_data;
  wyrelog_error_t rc = tenant_bind_effect (canonical_journal, active_uuids,
          &context->binding);
  if (rc != WYRELOG_E_OK || !context->sync)
    return rc;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  rc = wyl_fact_offline_restore_journal_decode (canonical_journal, &journal);
  if (rc != WYRELOG_E_OK)
    return rc;
  for (guint i = 0; i < context->binding.graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (g_strcmp0 (graph->graph_id, context->graph_id) != 0)
      continue;
    if (graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
        || graph->pending_op !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED)
      return WYRELOG_E_POLICY;
    TenantBindGraph *held = &context->binding.graphs[i];
    const gchar *uuid = g_ptr_array_index ((GPtrArray *) active_uuids, i);
    WylFactArtifactTransitionPosixLifecycle lifecycle = {
      .sealed = TRUE, .main_binding_live = FALSE,
    };
    g_autoptr (WylFactArtifactInventorySnapshot) initial = NULL;
    WylFactArtifactMainTransitionObservation observed = { 0 };
    rc = wyl_fact_artifact_transition_posix_capture (held->provider,
            &lifecycle, &initial, &observed);
    WylFactArtifactMainTransitionRequest request = {
      .operation_uuid = journal.operation_uuid,
      .directory_identity = observed.directory_identity,
      .lease_identity = observed.lease_identity,
      .expected_main_absent = FALSE,
      .expected_main_identity = graph->expected_main_identity,
      .staged_main_identity = graph->staged_main_identity,
    };
    g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
    WylFactArtifactMainTransitionObservation before = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_capture_provisioned
            (held->provider, uuid, &request,
              WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, &lifecycle,
              &snapshot, &before);
    g_autoptr (WylFactArtifactMainTransition) transition = NULL;
    WylFactArtifactMainTransitionResult result = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
              &before, &result, &transition);
    if (rc == WYRELOG_E_OK
        && (transition == NULL || result.state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || result.next_op !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_main_transition_authorize (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED, &before,
              &result);
    WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_execute_provisioned
            (held->provider, uuid, &request, &before,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
              &context->observed_effect, &durability);
    if (rc == WYRELOG_E_OK
        && context->observed_effect ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED)
      return WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK
        && (context->observed_effect !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
        || durability.staged_file !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN))
      rc = WYRELOG_E_BUSY;
    g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
    WylFactArtifactMainTransitionObservation after = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_capture_provisioned
            (held->provider, uuid, &request,
              WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, &lifecycle,
              &snapshot, &after);
    if (rc == WYRELOG_E_OK) {
      after.durability = durability;
      rc = wyl_fact_artifact_main_transition_record (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
              context->observed_effect, &after, &result);
    }
    if (rc == WYRELOG_E_OK
        && (result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || result.next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN))
      rc = WYRELOG_E_POLICY;
    return rc;
  }
  return WYRELOG_E_POLICY;
}

typedef struct
{
  TenantBindEffect binding;
  const gchar *graph_id;
  gboolean execute;
  gboolean pending;
} TenantRetainEffect;

static wyrelog_error_t
tenant_retain_prove_graph (TenantBindEffect *context,
    const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreJournalGraph *graph,
    TenantBindGraph *held, const gchar *active_uuid,
    WylFactGraphProvisionedRestoreSlot slot,
    WylFactArtifactMainTransitionRequest *out_request,
    WylFactArtifactMainTransitionObservation *out_observation,
    WylFactArtifactMainTransition **out_transition)
{
  *out_transition = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (context->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (context->lease,
            context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (context->runtime, &held->key);
  g_autoptr (WylFactOfflineRestoreStageReader) reader = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_open (context->resolver,
            &held->directory, context->lease, journal->operation_uuid,
            &graph->staged_main_identity, &reader);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_verify_content (reader,
            graph->logical_bytes, graph->checksum);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_revalidate (reader);
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) preliminary = NULL;
  WylFactArtifactMainTransitionObservation observed = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture (held->provider,
            &lifecycle, &preliminary, &observed);
  WylFactArtifactMainTransitionRequest request = {
    .operation_uuid = journal->operation_uuid,
    .directory_identity = observed.directory_identity,
    .lease_identity = observed.lease_identity,
    .expected_main_absent = FALSE,
    .expected_main_identity = graph->expected_main_identity,
    .staged_main_identity = graph->staged_main_identity,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation proof = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture_provisioned
          (held->provider, active_uuid, &request, slot, &lifecycle,
            &snapshot, &proof);
  const WylFactArtifactMainTransitionEntryEvidence *stage =
      &proof.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE];
  if (rc == WYRELOG_E_OK
      && (!stage->present || stage->reparse || stage->link_count != 1
      || stage->owner_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING
      || !wyl_fact_artifact_inventory_identity_equal (&stage->identity,
      &graph->staged_main_identity)))
    rc = WYRELOG_E_POLICY;
  WylFactArtifactMainTransition *transition = NULL;
  WylFactArtifactMainTransitionResult result = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
            &proof, &result, &transition);
  if (rc == WYRELOG_E_OK
      && (transition == NULL
      || (slot == WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN
      ? result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
      : result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    *out_request = request;
    *out_observation = proof;
    *out_transition = transition;
  } else
    wyl_fact_artifact_main_transition_free (transition);
  return rc;
}

static wyrelog_error_t
tenant_retain_effect (GBytes *canonical_journal,
    const GPtrArray *active_uuids, gpointer user_data)
{
  TenantRetainEffect *context = user_data;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_decode
        (canonical_journal, &journal);
  if (rc != WYRELOG_E_OK || active_uuids == NULL
      || active_uuids->len != context->binding.graph_count
      || journal.graphs->len != context->binding.graph_count)
    return WYRELOG_E_POLICY;
  if (context->execute) {
    TenantRetainEffect preflight = *context;
    preflight.execute = FALSE;
    rc = tenant_retain_effect (canonical_journal, active_uuids, &preflight);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  for (guint i = 0; i < context->binding.graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *held = &context->binding.graphs[i];
    const gchar *uuid = g_ptr_array_index ((GPtrArray *) active_uuids, i);
    gboolean selected = g_strcmp0 (graph->graph_id, context->graph_id) == 0;
    WylFactGraphProvisionedRestoreSlot slot =
        graph->transition_state ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
        ? WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK
        : WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN;
    if (selected && context->pending) {
      if (graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
          || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN)
        return WYRELOG_E_POLICY;
      WylFactArtifactTransitionPosixLifecycle lifecycle = {
        .sealed = TRUE, .main_binding_live = FALSE,
      };
      g_autoptr (WylFactArtifactInventorySnapshot) preliminary = NULL;
      WylFactArtifactMainTransitionObservation observed = { 0 };
      rc = wyl_fact_artifact_transition_posix_capture (held->provider,
              &lifecycle, &preliminary, &observed);
      if (rc != WYRELOG_E_OK)
        return rc;
      if (!observed.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN].present)
        slot = WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK;
    }
    WylFactArtifactMainTransitionRequest request = { 0 };
    WylFactArtifactMainTransitionObservation before = { 0 };
    g_autoptr (WylFactArtifactMainTransition) transition = NULL;
    rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
            held, uuid, slot, &request, &before, &transition);
    if (rc != WYRELOG_E_OK || !selected || !context->execute) {
      if (rc != WYRELOG_E_OK)
        return rc;
      continue;
    }
    if (slot == WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN) {
      WylFactArtifactMainTransitionResult result = { 0 };
      rc = wyl_fact_artifact_main_transition_authorize (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
              &before, &result);
      WylFactArtifactMainTransitionEffect sync_effect =
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
      WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_artifact_transition_posix_execute_provisioned
              (held->provider, uuid, &request, &before,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
                &sync_effect, &durability);
      if (rc != WYRELOG_E_OK || sync_effect !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
          || durability.staged_file !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
        return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
      g_autoptr (WylFactArtifactMainTransition) synced_transition = NULL;
      WylFactArtifactMainTransitionObservation synced = { 0 };
      rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
              held, uuid, WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN,
              &request, &synced, &synced_transition);
      if (rc != WYRELOG_E_OK)
        return rc;
      synced.durability = durability;
      rc = wyl_fact_artifact_main_transition_record (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
              sync_effect, &synced, &result);
      if (rc == WYRELOG_E_OK
          && result.next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN)
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_artifact_main_transition_authorize (transition,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN,
                &synced, &result);
      WylFactArtifactMainTransitionEffect retain_effect =
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_artifact_transition_posix_execute_provisioned
              (held->provider, uuid, &request, &synced,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN,
                &retain_effect, &durability);
      if (rc != WYRELOG_E_OK || retain_effect !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
        return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
      if (tenant_retain_checkpoint != NULL) {
        rc = tenant_retain_checkpoint ("restore-retain-after-rename",
                tenant_retain_checkpoint_data);
        if (rc != WYRELOG_E_OK)
          return rc;
      }
#endif
    }
    g_autoptr (WylFactArtifactMainTransition) retained_transition = NULL;
    WylFactArtifactMainTransitionObservation retained = { 0 };
    rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
            held, uuid, WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
            &request, &retained, &retained_transition);
    if (rc != WYRELOG_E_OK)
      return rc;
    WylFactArtifactMainTransitionEffect sync_effect =
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
    rc = wyl_fact_artifact_transition_posix_execute_provisioned
          (held->provider, uuid, &request, &retained,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
            &sync_effect, &durability);
    if (rc != WYRELOG_E_OK || sync_effect !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
        || durability.directory_after_retain !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
      return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
    g_clear_pointer (&retained_transition,
        wyl_fact_artifact_main_transition_free);
    rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
            held, uuid, WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
            &request, &retained, &retained_transition);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

typedef struct
{
  TenantBindEffect binding;
  const gchar *graph_id;
  gboolean execute;
  WylFactArtifactMainTransitionOp target;
} TenantSyncRollbackEffect;

static wyrelog_error_t
tenant_sync_rollback_effect (GBytes *canonical_journal,
    const GPtrArray *active_uuids, gpointer user_data)
{
  TenantSyncRollbackEffect *context = user_data;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_decode
        (canonical_journal, &journal);
  if (rc != WYRELOG_E_OK || active_uuids == NULL
      || active_uuids->len != context->binding.graph_count
      || journal.graphs->len != context->binding.graph_count)
    return WYRELOG_E_POLICY;
  if (context->execute) {
    TenantSyncRollbackEffect preflight = *context;
    preflight.execute = FALSE;
    rc = tenant_sync_rollback_effect (canonical_journal, active_uuids,
            &preflight);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  for (guint i = 0; i < context->binding.graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *held = &context->binding.graphs[i];
    const gchar *uuid = g_ptr_array_index ((GPtrArray *) active_uuids, i);
    gboolean selected = g_strcmp0 (graph->graph_id, context->graph_id) == 0;
    WylFactGraphProvisionedRestoreSlot slot =
        graph->transition_state ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
        ? WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK
        : WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN;
    WylFactArtifactMainTransitionRequest request = { 0 };
    WylFactArtifactMainTransitionObservation observed = { 0 };
    g_autoptr (WylFactArtifactMainTransition) transition = NULL;
    rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
            held, uuid, slot, &request, &observed, &transition);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!selected || !context->execute)
      continue;
    if (slot != WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
        || graph->pending_op != context->target)
      return WYRELOG_E_POLICY;
    const WylFactArtifactMainTransitionOp operations[] = {
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
    };
    const guint count = context->target ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE ? 2 : 3;
    for (guint j = 0; j < count; j++) {
      WylFactArtifactMainTransitionResult result = { 0 };
      rc = wyl_fact_artifact_main_transition_authorize (transition,
              operations[j], &observed, &result);
      WylFactArtifactMainTransitionEffect effect =
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
      WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_artifact_transition_posix_execute_provisioned
              (held->provider, uuid, &request, &observed, operations[j],
                &effect, &durability);
      WylFactArtifactMainTransitionDurability proven = j == 0
        ? durability.staged_file : j == 1
        ? durability.rollback_file : durability.directory_after_retain;
      if (rc != WYRELOG_E_OK || effect !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
          || proven != WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
        return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
      if (j == 1 && context->target ==
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
          && tenant_sync_rollback_checkpoint != NULL) {
        rc = tenant_sync_rollback_checkpoint
              ("restore-sync-rollback-after-fsync",
                tenant_sync_rollback_checkpoint_data);
        if (rc != WYRELOG_E_OK)
          return rc;
      }
      if (j == 2 && tenant_sync_retain_dir_checkpoint != NULL) {
        rc = tenant_sync_retain_dir_checkpoint
              ("restore-sync-retain-dir-after-fsync",
                tenant_sync_retain_dir_checkpoint_data);
        if (rc != WYRELOG_E_OK)
          return rc;
      }
#endif
      g_autoptr (WylFactArtifactMainTransition) recaptured = NULL;
      WylFactArtifactMainTransitionObservation after = { 0 };
      rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
              held, uuid,
              WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
              &request, &after, &recaptured);
      if (rc != WYRELOG_E_OK)
        return rc;
      after.durability = durability;
      rc = wyl_fact_artifact_main_transition_record (transition,
              operations[j], effect, &after, &result);
      if (rc != WYRELOG_E_OK || result.state !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
          || result.next_op != (j == 0
          ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
          : j == 1
          ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
          : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH))
        return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
      observed = after;
    }
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
tenant_publish_prove_published (TenantBindEffect *context,
    const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreJournalGraph *graph,
    TenantBindGraph *held, const gchar *active_uuid,
    WylFactArtifactMainTransitionRequest *out_request,
    WylFactArtifactMainTransitionObservation *out_observation,
    WylFactArtifactMainTransition **out_transition)
{
  *out_transition = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (context->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (context->lease,
            context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (context->runtime, &held->key);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_tenant_post_publish_shape_open
          (context->resolver, &held->directory, context->lease, active_uuid,
            journal->operation_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity);
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) preliminary = NULL;
  WylFactArtifactMainTransitionObservation observed = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture (held->provider,
            &lifecycle, &preliminary, &observed);
  WylFactArtifactMainTransitionRequest request = {
    .operation_uuid = journal->operation_uuid,
    .directory_identity = observed.directory_identity,
    .lease_identity = observed.lease_identity,
    .expected_main_absent = FALSE,
    .expected_main_identity = graph->expected_main_identity,
    .staged_main_identity = graph->staged_main_identity,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation proof = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture_provisioned
          (held->provider, active_uuid, &request,
            WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
            &lifecycle, &snapshot, &proof);
  const WylFactArtifactMainTransitionEntryEvidence *main =
      &proof.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN];
  const WylFactArtifactMainTransitionEntryEvidence *stage =
      &proof.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE];
  if (rc == WYRELOG_E_OK
      && (!main->present || main->reparse || main->link_count != 1
      || main->owner_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING
      || !wyl_fact_artifact_inventory_identity_equal (&main->identity,
      &graph->staged_main_identity) || stage->present))
    rc = WYRELOG_E_POLICY;
  WylFactArtifactMainTransition *transition = NULL;
  WylFactArtifactMainTransitionResult result = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
            &proof, &result, &transition);
  if (rc == WYRELOG_E_OK
      && (transition == NULL || result.state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
      || result.next_op !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_tenant_post_publish_shape_open
          (context->resolver, &held->directory, context->lease, active_uuid,
            journal->operation_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity);
  if (rc == WYRELOG_E_OK) {
    *out_request = request;
    *out_observation = proof;
    *out_transition = transition;
  } else
    wyl_fact_artifact_main_transition_free (transition);
  return rc;
}

typedef struct
{
  TenantBindEffect binding;
  const gchar *graph_id;
  gboolean execute;
  gboolean pending;
  WylFactArtifactMainTransitionOp target;
} TenantPublishEffect;

static wyrelog_error_t
tenant_publish_effect (GBytes *canonical_journal,
    const GPtrArray *active_uuids, gpointer user_data)
{
  TenantPublishEffect *context = user_data;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_decode
        (canonical_journal, &journal);
  if (rc != WYRELOG_E_OK || active_uuids == NULL
      || active_uuids->len != context->binding.graph_count
      || journal.graphs->len != context->binding.graph_count)
    return WYRELOG_E_POLICY;
  if (context->execute) {
    TenantPublishEffect preflight = *context;
    preflight.execute = FALSE;
    rc = tenant_publish_effect (canonical_journal, active_uuids, &preflight);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  for (guint i = 0; i < context->binding.graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *held = &context->binding.graphs[i];
    const gchar *uuid = g_ptr_array_index ((GPtrArray *) active_uuids, i);
    gboolean selected = g_strcmp0 (graph->graph_id, context->graph_id) == 0;
    gboolean published = graph->transition_state ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
        || graph->transition_state ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE;
    if (selected && context->pending) {
      if (graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
          || graph->pending_op != context->target)
        return WYRELOG_E_POLICY;
      if (context->target == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH) {
        WylFactArtifactTransitionPosixLifecycle lifecycle = {
          .sealed = TRUE, .main_binding_live = FALSE,
        };
        g_autoptr (WylFactArtifactInventorySnapshot) preliminary = NULL;
        WylFactArtifactMainTransitionObservation observed = { 0 };
        rc = wyl_fact_artifact_transition_posix_capture (held->provider,
                &lifecycle, &preliminary, &observed);
        if (rc != WYRELOG_E_OK)
          return rc;
        published = observed.entries
            [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN].present;
      }
    }
    WylFactArtifactMainTransitionRequest request = { 0 };
    WylFactArtifactMainTransitionObservation observed = { 0 };
    g_autoptr (WylFactArtifactMainTransition) transition = NULL;
    if (published)
      rc = tenant_publish_prove_published (&context->binding, &journal,
              graph, held, uuid, &request, &observed, &transition);
    else
      rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
              held, uuid, graph->transition_state ==
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
              ? WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN
              : WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
              &request, &observed, &transition);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!selected || !context->execute)
      continue;
    if (!context->pending || graph->attempt !=
        WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
      return WYRELOG_E_POLICY;
    if (!published) {
      if (graph->transition_state !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED)
        return WYRELOG_E_POLICY;
      const WylFactArtifactMainTransitionOp prerequisites[] = {
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
      };
      for (guint j = 0; j < G_N_ELEMENTS (prerequisites); j++) {
        WylFactArtifactMainTransitionResult result = { 0 };
        rc = wyl_fact_artifact_main_transition_authorize (transition,
                prerequisites[j], &observed, &result);
        WylFactArtifactMainTransitionEffect effect =
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
        WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
        if (rc == WYRELOG_E_OK)
          rc = wyl_fact_artifact_transition_posix_execute_provisioned
                (held->provider, uuid, &request, &observed,
                  prerequisites[j], &effect, &durability);
        WylFactArtifactMainTransitionDurability proven = j == 0
          ? durability.staged_file : j == 1
          ? durability.rollback_file : durability.directory_after_retain;
        if (rc != WYRELOG_E_OK || effect !=
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
            || proven != WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
          return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
        g_autoptr (WylFactArtifactMainTransition) recaptured = NULL;
        WylFactArtifactMainTransitionObservation after = { 0 };
        rc = tenant_retain_prove_graph (&context->binding, &journal, graph,
                held, uuid,
                WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
                &request, &after, &recaptured);
        if (rc != WYRELOG_E_OK)
          return rc;
        after.durability = durability;
        rc = wyl_fact_artifact_main_transition_record (transition,
                prerequisites[j], effect, &after, &result);
        if (rc != WYRELOG_E_OK || result.next_op != (j == 0
            ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
            : j == 1
            ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
            : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH))
          return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
        observed = after;
      }
      WylFactArtifactMainTransitionResult result = { 0 };
      rc = wyl_fact_artifact_main_transition_authorize (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
              &observed, &result);
      WylFactArtifactMainTransitionEffect effect =
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
      WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_artifact_transition_posix_execute_provisioned
              (held->provider, uuid, &request, &observed,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
                &effect, &durability);
      if (rc != WYRELOG_E_OK || effect !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
        return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
      if (tenant_publish_checkpoint != NULL) {
        rc = tenant_publish_checkpoint ("restore-publish-after-rename",
                tenant_publish_checkpoint_data);
        if (rc != WYRELOG_E_OK)
          return rc;
      }
#endif
      g_autoptr (WylFactArtifactMainTransition) recaptured = NULL;
      WylFactArtifactMainTransitionObservation after = { 0 };
      rc = tenant_publish_prove_published (&context->binding, &journal,
              graph, held, uuid, &request, &after, &recaptured);
      if (rc != WYRELOG_E_OK)
        return rc;
      rc = wyl_fact_artifact_main_transition_record (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH, effect,
              &after, &result);
      if (rc != WYRELOG_E_OK || result.state !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
          || result.next_op !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR)
        return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
      observed = after;
    }
    if (context->target ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR
        && (graph->transition_state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED || !published))
      return WYRELOG_E_POLICY;
    WylFactArtifactMainTransitionResult result = { 0 };
    rc = wyl_fact_artifact_main_transition_authorize (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
            &observed, &result);
    WylFactArtifactMainTransitionEffect effect =
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_execute_provisioned
            (held->provider, uuid, &request, &observed,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
              &effect, &durability);
    if (rc != WYRELOG_E_OK || effect !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
        || durability.directory_after_publish !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
      return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
    if (context->target == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH
        && tenant_publish_checkpoint != NULL) {
      rc = tenant_publish_checkpoint ("restore-publish-after-fsync",
              tenant_publish_checkpoint_data);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
    if (context->target ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR
        && tenant_sync_publish_dir_checkpoint != NULL) {
      rc = tenant_sync_publish_dir_checkpoint
            ("restore-sync-publish-dir-after-fsync",
              tenant_sync_publish_dir_checkpoint_data);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
#endif
    g_autoptr (WylFactArtifactMainTransition) verified = NULL;
    WylFactArtifactMainTransitionObservation after = { 0 };
    rc = tenant_publish_prove_published (&context->binding, &journal,
            graph, held, uuid, &request, &after, &verified);
    if (rc != WYRELOG_E_OK)
      return rc;
    after.durability = durability;
    rc = wyl_fact_artifact_main_transition_record (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
            effect, &after, &result);
    if (rc != WYRELOG_E_OK || result.state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE)
      return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  }
  if (context->execute) {
    TenantPublishEffect final = *context;
    final.execute = FALSE;
    return tenant_publish_effect (canonical_journal, active_uuids, &final);
  }
  return WYRELOG_E_OK;
}
#endif

static wyrelog_error_t
tenant_bind_provisioned_old_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed,
    gboolean prove_bound)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || graph_id == NULL
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  WylPolicyOfflineRestoreRecord *committed = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  g_autoptr (GBytes) canonical = NULL;
  g_autofree gchar *old_uuid = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION
      && journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION)
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal.graphs == NULL))
    rc = WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournalGraph *selected = NULL;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (graph->expected_main_absent || !graph->replay_preflighted
        || graph->transition_state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
      rc = WYRELOG_E_POLICY;
    if (g_strcmp0 (graph->graph_id, graph_id) == 0)
      selected = graph;
  }
  if (rc == WYRELOG_E_OK && (selected == NULL
      || (selected->old_provisioning_uuid != NULL && !prove_bound)
      || (selected->old_provisioning_uuid == NULL && prove_bound)))
    rc = WYRELOG_E_POLICY;
  g_autoptr (GPtrArray) provisioning = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_provisioning_list_for_graph (policy,
            journal.tenant_id, graph_id, &provisioning);
  if (rc == WYRELOG_E_OK && provisioning->len != 1)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    const WylPolicyGraphProvisioningRecord *row =
        g_ptr_array_index (provisioning, 0);
    if (row->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE
        || g_strcmp0 (row->store_uuid, selected->store_uuid) != 0)
      rc = WYRELOG_E_POLICY;
    else
      old_uuid = g_strdup (row->op_uuid);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce (runtime, &item->key,
              remaining, &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
    WylFactArtifactTransitionPosixCapability capability = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_probe_capability
            (&item->directory, operation_uuid, &capability);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_open (&resolver,
              &item->directory, lease, operation_uuid, &capability,
              &item->provider);
  }
  WylPolicyOfflineRestoreStoreResult result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK) {
    TenantBindEffect effect = {
      .lease = lease, .resolver = &resolver, .runtime = runtime,
      .graphs = held, .graph_count = graph_count,
    };
    if (prove_bound) {
      rc = wyl_policy_store_tenant_restore_prove_bound_old_with_effect
            (policy, expected, tenant_bind_effect, &effect);
    } else
      rc = wyl_policy_store_tenant_restore_bind_provisioned_old_with_effect
            (policy, expected, graph_id, old_uuid, tenant_bind_effect,
              &effect, &result, &committed);
  }
  if (rc == WYRELOG_E_OK && !prove_bound
      && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode ((prove_bound ? expected :
            committed)->journal_blob,
            out_committed);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_artifact_transition_posix_free (held[i].provider);
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (committed);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_bind_provisioned_old_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  return tenant_bind_provisioned_old_run (policy, fact_root, runtime,
             operation_uuid, graph_id, expected_revision, drain_timeout_us,
             out_committed, FALSE);
}

/* Compare a reloaded journal with exactly one permitted binding transition.
 * Rebuilding the image through the journal codec also rejects unrelated
 * changes to the manifest, graph state, or already bound siblings. */
static wyrelog_error_t
tenant_bind_matches_next (const WylFactOfflineRestoreJournal *before,
    const WylFactOfflineRestoreJournal *after, const gchar *graph_id)
{
  g_autoptr (GBytes) before_bytes = NULL;
  g_autoptr (GBytes) expected_bytes = NULL;
  g_autoptr (GBytes) after_bytes = NULL;
  g_auto (WylFactOfflineRestoreJournal) expected = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_encode (before,
          &before_bytes);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (before_bytes, &expected);
  const gchar *old_uuid = NULL;
  if (rc == WYRELOG_E_OK) {
    if (after->graphs == NULL || before->graphs == NULL
        || after->graphs->len != before->graphs->len)
      return WYRELOG_E_BUSY;
    for (guint i = 0; i < after->graphs->len; i++) {
      const WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (after->graphs, i);
      if (g_strcmp0 (graph->graph_id, graph_id) == 0)
        old_uuid = graph->old_provisioning_uuid;
    }
    if (old_uuid == NULL)
      return WYRELOG_E_BUSY;
    rc = wyl_fact_offline_restore_journal_bind_tenant_provisioned_old
          (&expected, graph_id, old_uuid);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&expected, &expected_bytes);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (after, &after_bytes);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (expected_bytes, after_bytes))
    rc = WYRELOG_E_BUSY;
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_bind_all_provisioned_old_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || expected_revision >= G_MAXINT64 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  g_auto (WylFactOfflineRestoreJournal) current = { 0 };
  WylPolicyOfflineRestoreRecord *record = NULL;
  g_autoptr (GBytes) canonical = NULL;
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (policy,
          operation_uuid, &current);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &record);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&current, &canonical);
  if (rc == WYRELOG_E_OK && (current.revision != expected_revision
      || !g_bytes_equal (canonical, record->journal_blob)))
    rc = WYRELOG_E_BUSY;
  wyl_policy_offline_restore_record_free (record);
  if (rc == WYRELOG_E_OK && (current.scope !=
      WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || (current.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION
      && current.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION)
      || current.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || current.graphs == NULL || current.graphs->len == 0))
    rc = WYRELOG_E_POLICY;

  gboolean seen_unbound = FALSE;
  for (guint i = 0; rc == WYRELOG_E_OK && i < current.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (current.graphs, i);
    if (graph->expected_main_absent || !graph->replay_preflighted
        || graph->transition_state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || (seen_unbound && graph->old_provisioning_uuid != NULL)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    if (graph->old_provisioning_uuid == NULL)
      seen_unbound = TRUE;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; rc == WYRELOG_E_OK && i < current.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (current.graphs, i);
    if (graph->old_provisioning_uuid != NULL)
      continue;
    gint64 remaining = drain_timeout_us;
    if (deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0) {
        rc = WYRELOG_E_BUSY;
        break;
      }
    }
    g_autofree gchar *graph_id = g_strdup (graph->graph_id);
    g_auto (WylFactOfflineRestoreJournal) next = { 0 };
    wyrelog_error_t bind_rc =
        wyl_fact_offline_restore_tenant_bind_provisioned_old_run
          (policy, fact_root, runtime, operation_uuid, graph_id,
            current.revision, remaining, &next);
    if (bind_rc != WYRELOG_E_OK) {
      rc = wyl_fact_offline_restore_journal_store_load (policy,
              operation_uuid, &next);
      if (rc != WYRELOG_E_OK)
        break;
      WylPolicyOfflineRestoreRecord *loaded = NULL;
      g_autoptr (GBytes) reloaded_bytes = NULL;
      rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
              &loaded);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_offline_restore_journal_encode (&next,
                &reloaded_bytes);
      if (rc == WYRELOG_E_OK && !g_bytes_equal (reloaded_bytes,
          loaded->journal_blob))
        rc = WYRELOG_E_BUSY;
      wyl_policy_offline_restore_record_free (loaded);
      if (rc != WYRELOG_E_OK)
        break;
      g_autoptr (GBytes) current_bytes = NULL;
      rc = wyl_fact_offline_restore_journal_encode (&current, &current_bytes);
      if (rc != WYRELOG_E_OK)
        break;
      if (g_bytes_equal (current_bytes, reloaded_bytes)) {
        rc = bind_rc;
        break;
      }
    }
    rc = tenant_bind_matches_next (&current, &next, graph_id);
    if (rc != WYRELOG_E_OK)
      break;
    wyl_fact_offline_restore_journal_clear (&current);
    current = next;
    memset (&next, 0, sizeof next);
  }
  if (rc == WYRELOG_E_OK) {
    gint64 remaining = drain_timeout_us;
    if (deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc != WYRELOG_E_OK)
      goto done;
    const WylFactOfflineRestoreJournalGraph *first =
        g_ptr_array_index (current.graphs, 0);
    g_auto (WylFactOfflineRestoreJournal) proven = { 0 };
    rc = tenant_bind_provisioned_old_run (policy, fact_root, runtime,
            operation_uuid, first->graph_id, current.revision,
            remaining, &proven, TRUE);
    if (rc == WYRELOG_E_OK) {
      g_autoptr (GBytes) actual = NULL;
      g_autoptr (GBytes) expected = NULL;
      rc = wyl_fact_offline_restore_journal_encode (&current, &expected);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_offline_restore_journal_encode (&proven, &actual);
      if (rc == WYRELOG_E_OK && !g_bytes_equal (expected, actual))
        rc = WYRELOG_E_BUSY;
    }
  }
  if (rc == WYRELOG_E_OK
      && current.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    *out_committed = current;
    memset (&current, 0, sizeof current);
  }
done:
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_reserve_replacements_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || expected_revision >= G_MAXINT64 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  WylPolicyOfflineRestoreRecord *committed = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  g_autoptr (GBytes) canonical = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.graphs == NULL || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (graph->expected_main_absent || graph->old_provisioning_uuid == NULL
        || graph->transition_state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v5_quiesce (policy, lease, &resolver, runtime,
              &journal, canonical, &item->key, remaining,
              &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
  }
  WylPolicyOfflineRestoreStoreResult result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK) {
    TenantBindEffect effect = {
      .lease = lease, .resolver = &resolver, .runtime = runtime,
      .graphs = held, .graph_count = graph_count,
    };
    rc = wyl_policy_store_tenant_restore_reserve_replacements_with_effect
          (policy, expected, tenant_reserve_effect, &effect,
            &result, &committed);
  }
  if (rc == WYRELOG_E_OK
      && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (committed->journal_blob,
            out_committed);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (committed);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  TenantBindEffect binding;
  const WylFactOfflineRestoreJournal *journal;
  GBytes *encoded;
} TenantCompanionEffect;

static wyrelog_error_t
tenant_companion_open_graph (TenantCompanionEffect *effect,
    guint index, const gchar *phase,
    WylFactGraphRestorePostPublishLayout *out_layout,
    WylFactGraphProvisionedRestoreWitness **out_witness)
{
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (effect->journal->graphs, index);
  TenantBindGraph *held = &effect->binding.graphs[index];
  *out_layout = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  *out_witness = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (effect->binding.lease, effect->binding.resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (effect->binding.runtime, &held->key);
  if (rc == WYRELOG_E_OK && g_str_equal (phase, "reserved"))
    rc = wyl_fact_graph_restore_post_publish_reserved_shape_open
          (effect->binding.resolver, &held->directory,
            effect->binding.lease, graph->old_provisioning_uuid,
            effect->journal->operation_uuid,
            graph->replacement_provisioning_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            out_layout, out_witness);
  else if (rc == WYRELOG_E_OK && g_str_equal (phase, "companion_synced")) {
    rc = wyl_fact_graph_restore_post_publish_shape_open
          (effect->binding.resolver, &held->directory,
            effect->binding.lease, graph->old_provisioning_uuid,
            effect->journal->operation_uuid,
            graph->replacement_provisioning_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION,
            out_witness);
    if (rc == WYRELOG_E_OK)
      *out_layout = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION;
  } else if (rc == WYRELOG_E_OK)
    rc = WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
tenant_companion_effect (GBytes *canonical_journal,
    const GPtrArray *phases, guint selected_index, gpointer user_data)
{
  TenantCompanionEffect *effect = user_data;
  if (!g_bytes_equal (canonical_journal, effect->encoded)
      || phases->len != effect->binding.graph_count
      || selected_index >= phases->len)
    return WYRELOG_E_POLICY;
  WylFactGraphRestorePostPublishLayout *layouts = g_try_new0
        (WylFactGraphRestorePostPublishLayout, phases->len);
  if (layouts == NULL)
    return WYRELOG_E_NOMEM;
  WylFactGraphProvisionedRestoreWitness *selected_witness = NULL;
  wyrelog_error_t rc = WYRELOG_E_OK;
  for (guint i = 0; rc == WYRELOG_E_OK && i < phases->len; i++) {
    WylFactGraphProvisionedRestoreWitness *witness = NULL;
    rc = tenant_companion_open_graph (effect, i,
            g_ptr_array_index ((GPtrArray *) phases, i),
            &layouts[i], &witness);
    if (rc == WYRELOG_E_OK && i == selected_index)
      selected_witness = witness;
    else
      wyl_fact_graph_provisioned_restore_witness_free (witness);
  }
  const WylFactOfflineRestoreJournalGraph *selected =
      g_ptr_array_index (effect->journal->graphs, selected_index);
  TenantBindGraph *held = &effect->binding.graphs[selected_index];
  WylFactGraphProvisionedRestoreWitness *dual = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_companion_link_post_publish_for_layout
          (effect->binding.resolver, &held->directory,
            effect->binding.lease,
            layouts[selected_index] ==
            WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_MAIN_ONE_LINK ?
            selected_witness : NULL,
            selected->old_provisioning_uuid,
            effect->journal->operation_uuid,
            selected->replacement_provisioning_uuid,
            &selected->expected_main_identity,
            &selected->staged_main_identity, layouts[selected_index], &dual);
  wyl_fact_graph_provisioned_restore_witness_free (selected_witness);
  wyl_fact_graph_provisioned_restore_witness_free (dual);
  for (guint i = 0; rc == WYRELOG_E_OK && i < phases->len; i++) {
    WylFactGraphProvisionedRestoreWitness *witness = NULL;
    WylFactGraphRestorePostPublishLayout now =
        WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
    const gchar *required = i == selected_index ? "companion_synced" :
        g_ptr_array_index ((GPtrArray *) phases, i);
    rc = tenant_companion_open_graph (effect, i, required, &now, &witness);
    wyl_fact_graph_provisioned_restore_witness_free (witness);
    if (rc == WYRELOG_E_OK && i != selected_index && now != layouts[i])
      rc = WYRELOG_E_BUSY;
  }
  g_free (layouts);
  return rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_tenant_companion_sync_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || graph_id == NULL
      || expected_revision == 0 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  g_autoptr (GBytes) canonical = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)
      || journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.graphs == NULL || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v6_quiesce (policy, lease, &resolver, runtime,
              expected, &item->key, remaining, &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
#ifdef WYL_TEST_HANDLE_SEAMS
    if (rc == WYRELOG_E_OK) {
      item->directory.checkpoint = tenant_companion_checkpoint;
      item->directory.checkpoint_data = tenant_companion_checkpoint_data;
    }
#endif
  }
  WylPolicyOfflineRestoreStoreResult result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK) {
    TenantCompanionEffect effect = {
      .binding = { .lease = lease, .resolver = &resolver,
                   .runtime = runtime, .graphs = held,
                   .graph_count = graph_count },
      .journal = &journal, .encoded = canonical,
    };
    rc = wyl_policy_store_tenant_restore_companion_sync_with_effect
          (policy, expected, graph_id, tenant_companion_effect, &effect,
            &result);
  }
  if (rc == WYRELOG_E_OK
      && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED
      && result != WYL_POLICY_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (canonical, out_committed);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  return rc;
#endif
}

#ifdef __linux__
static wyrelog_error_t
tenant_select_effect (GBytes *canonical_journal, gpointer user_data)
{
  TenantCompanionEffect *effect = user_data;
  if (!g_bytes_equal (canonical_journal, effect->encoded)
      || effect->journal->graphs->len != effect->binding.graph_count)
    return WYRELOG_E_POLICY;
  for (guint pass = 0; pass < 2; pass++) {
    for (guint i = 0; i < effect->binding.graph_count; i++) {
      WylFactGraphRestorePostPublishLayout layout =
          WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
      WylFactGraphProvisionedRestoreWitness *witness = NULL;
      wyrelog_error_t rc = tenant_companion_open_graph (effect, i,
              "companion_synced", &layout, &witness);
      wyl_fact_graph_provisioned_restore_witness_free (witness);
      if (rc != WYRELOG_E_OK)
        return rc;
      if (layout != WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION)
        return WYRELOG_E_POLICY;
    }
  }
  return WYRELOG_E_OK;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_tenant_select_replacements_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  WylPolicyOfflineRestoreRecord *committed = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  g_autoptr (GBytes) canonical = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)
      || journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.graphs == NULL || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v6_quiesce (policy, lease, &resolver, runtime,
              expected, &item->key, remaining, &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
  }
  WylPolicyOfflineRestoreStoreResult result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK) {
    TenantCompanionEffect effect = {
      .binding = { .lease = lease, .resolver = &resolver,
                   .runtime = runtime, .graphs = held,
                   .graph_count = graph_count },
      .journal = &journal, .encoded = canonical,
    };
    rc = wyl_policy_store_tenant_restore_select_with_effect (policy,
            expected, tenant_select_effect, &effect, &result, &committed);
  }
  if (rc == WYRELOG_E_OK
      && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (committed->journal_blob,
            out_committed);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (committed);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  TenantBindEffect binding;
  const WylFactOfflineRestoreJournal *journal;
  GBytes *canonical;
  guint target;
} TenantFinalizeEffect;

static wyrelog_error_t
tenant_finalize_shapes (TenantFinalizeEffect *effect,
    gboolean target_completed)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (effect->binding.lease, effect->binding.resolver);
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < effect->binding.graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (effect->journal->graphs, i);
    TenantBindGraph *held = &effect->binding.graphs[i];
    rc = check_runtime (effect->binding.runtime, &held->key);
    WylFactGraphRestoreSelectedCleanupShape shape =
        WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_restore_selected_cleanup_shape_open
            (effect->binding.resolver, &held->directory,
              effect->binding.lease, graph->old_provisioning_uuid,
              effect->journal->operation_uuid,
              graph->replacement_provisioning_uuid,
              &graph->expected_main_identity,
              &graph->staged_main_identity, &shape);
    if (rc != WYRELOG_E_OK)
      break;
    gboolean finalized = graph->transition_state ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED;
    gboolean pending = graph->attempt ==
        WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
    if (i == effect->target && target_completed)
      finalized = TRUE;
    if ((finalized && shape !=
        WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL)
        || (!finalized && !pending && shape !=
        WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL)
        || (!finalized && pending && shape !=
        WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL
        && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_PARTIAL
        && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL))
      rc = WYRELOG_E_POLICY;
  }
  return rc;
}

static wyrelog_error_t
tenant_finalize_effect (GBytes *canonical_journal, gpointer user_data)
{
  TenantFinalizeEffect *effect = user_data;
  if (!g_bytes_equal (canonical_journal, effect->canonical)
      || effect->journal->graphs->len != effect->binding.graph_count)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = tenant_finalize_shapes (effect, FALSE);
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (effect->journal->graphs, effect->target);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_selected_cleanup_execute
          (effect->binding.resolver,
            &effect->binding.graphs[effect->target].directory,
            effect->binding.lease, graph->old_provisioning_uuid,
            effect->journal->operation_uuid,
            graph->replacement_provisioning_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity);
  if (rc == WYRELOG_E_OK)
    rc = tenant_finalize_shapes (effect, TRUE);
  return rc;
}

static wyrelog_error_t
tenant_promotion_effect (GBytes *canonical_journal, gpointer user_data)
{
  TenantFinalizeEffect *effect = user_data;
  if (!g_bytes_equal (canonical_journal, effect->canonical)
      || effect->journal->graphs->len != effect->binding.graph_count)
    return WYRELOG_E_POLICY;
  return tenant_finalize_shapes (effect, FALSE);
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_tenant_finalize_graph_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || graph_id == NULL
      || expected_revision == 0 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  WylPolicyOfflineRestoreRecord *committed = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  guint target = 0;
  gboolean found = FALSE;
  g_autoptr (GBytes) canonical = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)
      || journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || !journal.replacement_selected_pending_cleanup
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete || journal.graphs == NULL
      || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (g_strcmp0 (graph->graph_id, graph_id) == 0) {
      target = i;
      found = TRUE;
    }
  }
  if (rc == WYRELOG_E_OK && !found)
    rc = WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournalGraph *selected = rc == WYRELOG_E_OK ?
      g_ptr_array_index (journal.graphs, target) : NULL;
  gboolean fresh = selected != NULL && selected->attempt ==
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED;
  if (rc == WYRELOG_E_OK
      && (selected->transition_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
      || selected->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
      || selected->pending_op != (fresh ?
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE :
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE)
      || (!fresh && selected->attempt !=
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v7_quiesce (policy, lease, &resolver, runtime,
              expected, &item->key, remaining, &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
#ifdef WYL_TEST_HANDLE_SEAMS
    if (rc == WYRELOG_E_OK) {
      item->directory.checkpoint = finalize_checkpoint;
      item->directory.checkpoint_data = finalize_checkpoint_data;
    }
#endif
  }
  TenantFinalizeEffect effect = {
    .binding = { .lease = lease, .resolver = &resolver,
                 .runtime = runtime, .graphs = held,
                 .graph_count = graph_count },
    .journal = &journal, .canonical = canonical, .target = target,
  };
  if (rc == WYRELOG_E_OK)
    rc = tenant_finalize_shapes (&effect, FALSE);
  WylPolicyOfflineRestoreStoreResult result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK && fresh) {
    rc = wyl_policy_store_tenant_restore_selected_finalize_step
          (policy, expected, graph_id,
            WYL_POLICY_TENANT_RESTORE_SELECTED_FINALIZE_BEGIN,
            NULL, NULL, &result, &committed);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK) {
      wyl_fact_offline_restore_journal_clear (&journal);
      rc = wyl_fact_offline_restore_journal_decode
            (committed->journal_blob, &journal);
      if (rc == WYRELOG_E_OK) {
        wyl_policy_offline_restore_record_free (expected);
        expected = committed;
        committed = NULL;
        g_clear_pointer (&canonical, g_bytes_unref);
        canonical = g_bytes_ref (expected->journal_blob);
        effect.canonical = canonical;
      }
    }
  }
  if (rc == WYRELOG_E_OK) {
    result = WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    rc = wyl_policy_store_tenant_restore_selected_finalize_step
          (policy, expected, graph_id,
            WYL_POLICY_TENANT_RESTORE_SELECTED_FINALIZE_COMPLETE,
            tenant_finalize_effect, &effect, &result, &committed);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (committed->journal_blob,
            out_committed);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (committed);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_promote_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  WylPolicyOfflineRestoreRecord *committed = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  g_autoptr (GBytes) canonical = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)
      || journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || !journal.replacement_selected_pending_cleanup
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete || journal.graphs == NULL
      || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (graph->transition_state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
        || !graph->transition_terminal)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v7_quiesce (policy, lease, &resolver, runtime,
              expected, &item->key, remaining, &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
  }
  TenantFinalizeEffect effect = {
    .binding = { .lease = lease, .resolver = &resolver,
                 .runtime = runtime, .graphs = held,
                 .graph_count = graph_count },
    .journal = &journal, .canonical = canonical,
  };
  if (rc == WYRELOG_E_OK)
    rc = tenant_promotion_effect (canonical, &effect);
  WylPolicyOfflineRestoreStoreResult result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_selected_promote_with_effect
          (policy, expected, tenant_promotion_effect, &effect, &result,
            &committed);
  if (rc == WYRELOG_E_OK
      && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (committed->journal_blob,
            out_committed);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (committed);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  return rc;
#endif
}

static wyrelog_error_t
tenant_commit_step_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactArtifactMainTransitionOp operation,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || graph_id == NULL
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL
      || (operation != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
      && operation != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN
      && operation != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
      && operation != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
      && operation != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH
      && operation != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR))
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  WylPolicyOfflineRestoreRecord *committed = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  g_autoptr (GBytes) canonical = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.graphs == NULL))
    rc = WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournalGraph *selected = NULL;
  if (rc == WYRELOG_E_OK
      && !wyl_fact_offline_restore_tenant_commit_step_eligible
        (&journal, graph_id, operation))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (g_strcmp0 (graph->graph_id, graph_id) == 0)
      selected = graph;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v5_quiesce (policy, lease, &resolver, runtime,
              &journal, canonical, &item->key, remaining,
              &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
    WylFactArtifactTransitionPosixCapability capability = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_probe_capability
            (&item->directory, operation_uuid, &capability);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_open (&resolver,
              &item->directory, lease, operation_uuid, &capability,
              &item->provider);
  }
  TenantSyncEffect sync_effect = {
    .binding = {
      .lease = lease, .resolver = &resolver, .runtime = runtime,
      .graphs = held, .graph_count = graph_count,
    },
    .graph_id = graph_id,
  };
  TenantRetainEffect retain_effect = {
    .binding = sync_effect.binding,
    .graph_id = graph_id,
  };
  TenantSyncRollbackEffect rollback_effect = {
    .binding = sync_effect.binding,
    .graph_id = graph_id,
    .target = operation,
  };
  TenantPublishEffect publish_effect = {
    .binding = sync_effect.binding,
    .graph_id = graph_id,
    .target = operation,
  };
  WylPolicyOfflineRestoreStoreResult result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK
      && selected->attempt ==
      (operation != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
      ? WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
      : WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE)) {
    if (operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED)
      rc = wyl_policy_store_tenant_restore_sync_staged_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_STAGED_BEGIN,
              tenant_sync_staged_effect, &sync_effect, &result, &committed);
    else if (operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN)
      rc = wyl_policy_store_tenant_restore_retain_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_RETAIN_BEGIN,
              tenant_retain_effect, &retain_effect, &result, &committed);
    else if (operation ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE)
      rc = wyl_policy_store_tenant_restore_sync_rollback_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_ROLLBACK_BEGIN,
              tenant_sync_rollback_effect, &rollback_effect,
              &result, &committed);
    else if (operation ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR)
      rc = wyl_policy_store_tenant_restore_sync_retain_dir_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_RETAIN_DIR_BEGIN,
              tenant_sync_rollback_effect, &rollback_effect,
              &result, &committed);
    else if (operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH)
      rc = wyl_policy_store_tenant_restore_publish_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_PUBLISH_BEGIN,
              tenant_publish_effect, &publish_effect, &result, &committed);
    else
      rc = wyl_policy_store_tenant_restore_sync_publish_dir_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_PUBLISH_DIR_BEGIN,
              tenant_publish_effect, &publish_effect, &result, &committed);
    if (rc == WYRELOG_E_OK && result !=
        WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK) {
      wyl_policy_offline_restore_record_free (expected);
      expected = committed;
      committed = NULL;
      wyl_fact_offline_restore_journal_clear (&journal);
      rc = wyl_fact_offline_restore_journal_decode (expected->journal_blob,
              &journal);
    }
  }
  sync_effect.sync = TRUE;
  retain_effect.execute = TRUE;
  retain_effect.pending = TRUE;
  rollback_effect.execute = TRUE;
  publish_effect.execute = TRUE;
  publish_effect.pending = TRUE;
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK
      && operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
      && tenant_sync_staged_checkpoint != NULL)
    rc = tenant_sync_staged_checkpoint ("restore-sync-staged-after-begin",
            tenant_sync_staged_checkpoint_data);
  if (rc == WYRELOG_E_OK
      && operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN
      && tenant_retain_checkpoint != NULL)
    rc = tenant_retain_checkpoint ("restore-retain-after-begin",
            tenant_retain_checkpoint_data);
  if (rc == WYRELOG_E_OK
      && operation ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
      && tenant_sync_rollback_checkpoint != NULL)
    rc = tenant_sync_rollback_checkpoint ("restore-sync-rollback-after-begin",
            tenant_sync_rollback_checkpoint_data);
  if (rc == WYRELOG_E_OK
      && operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
      && tenant_sync_retain_dir_checkpoint != NULL)
    rc = tenant_sync_retain_dir_checkpoint
          ("restore-sync-retain-dir-after-begin",
            tenant_sync_retain_dir_checkpoint_data);
  if (rc == WYRELOG_E_OK
      && operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH
      && tenant_publish_checkpoint != NULL)
    rc = tenant_publish_checkpoint ("restore-publish-after-begin",
            tenant_publish_checkpoint_data);
  if (rc == WYRELOG_E_OK
      && operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR
      && tenant_sync_publish_dir_checkpoint != NULL)
    rc = tenant_sync_publish_dir_checkpoint
          ("restore-sync-publish-dir-after-begin",
            tenant_sync_publish_dir_checkpoint_data);
#endif
  if (rc == WYRELOG_E_OK) {
    if (operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED)
      rc = wyl_policy_store_tenant_restore_sync_staged_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_STAGED_COMPLETE,
              tenant_sync_staged_effect, &sync_effect, &result, &committed);
    else if (operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN)
      rc = wyl_policy_store_tenant_restore_retain_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_RETAIN_COMPLETE,
              tenant_retain_effect, &retain_effect, &result, &committed);
    else if (operation ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE)
      rc = wyl_policy_store_tenant_restore_sync_rollback_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_ROLLBACK_COMPLETE,
              tenant_sync_rollback_effect, &rollback_effect,
              &result, &committed);
    else if (operation ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR)
      rc = wyl_policy_store_tenant_restore_sync_retain_dir_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_RETAIN_DIR_COMPLETE,
              tenant_sync_rollback_effect, &rollback_effect,
              &result, &committed);
    else if (operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH)
      rc = wyl_policy_store_tenant_restore_publish_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_PUBLISH_COMPLETE,
              tenant_publish_effect, &publish_effect, &result, &committed);
    else
      rc = wyl_policy_store_tenant_restore_sync_publish_dir_step_with_effect
            (policy, expected, graph_id,
              WYL_POLICY_TENANT_RESTORE_SYNC_PUBLISH_DIR_COMPLETE,
              tenant_publish_effect, &publish_effect, &result, &committed);
  }
  if (rc == WYRELOG_E_OK && result !=
      WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (committed->journal_blob,
            out_committed);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_artifact_transition_posix_free (held[i].provider);
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (committed);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_sync_staged_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  return tenant_commit_step_run (policy, fact_root, runtime, operation_uuid,
             graph_id, expected_revision, drain_timeout_us,
             WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED, out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_retain_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  return tenant_commit_step_run (policy, fact_root, runtime, operation_uuid,
             graph_id, expected_revision, drain_timeout_us,
             WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN, out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_sync_rollback_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  return tenant_commit_step_run (policy, fact_root, runtime, operation_uuid,
             graph_id, expected_revision, drain_timeout_us,
             WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
             out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  return tenant_commit_step_run (policy, fact_root, runtime, operation_uuid,
             graph_id, expected_revision, drain_timeout_us,
             WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
             out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_publish_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  return tenant_commit_step_run (policy, fact_root, runtime, operation_uuid,
             graph_id, expected_revision, drain_timeout_us,
             WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH, out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  return tenant_commit_step_run (policy, fact_root, runtime, operation_uuid,
             graph_id, expected_revision, drain_timeout_us,
             WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
             out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_v5_prove_complete
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) canonical = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK && journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.graphs == NULL || journal.graphs->len == 0
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (tenant_commit_v5_graph_phase (graph) != 6)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = tenant_commit_v5_prove_reacquire (policy, lease, &resolver,
            &journal, canonical);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v5_quiesce (policy, lease, &resolver, runtime,
              &journal, canonical, &item->key, remaining,
              &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
  }
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    rc = wyl_fact_graph_restore_tenant_post_publish_shape_open
          (&resolver, &held[i].directory, lease, graph->old_provisioning_uuid,
            operation_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity);
  }
  if (rc == WYRELOG_E_OK)
    rc = tenant_commit_v5_prove_reacquire (policy, lease, &resolver,
            &journal, canonical);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (canonical, out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_v7_prove_selected
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  g_autoptr (GBytes) canonical = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK && (journal.revision != expected_revision
      || expected->revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || !journal.replacement_selected_pending_cleanup
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete || journal.graphs == NULL
      || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (graph->expected_main_absent || !graph->replay_preflighted
        || graph->transition_terminal
        || graph->old_provisioning_uuid == NULL
        || graph->replacement_provisioning_uuid == NULL
        || graph->transition_state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v7_prove (policy,
            expected);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v7_quiesce (policy, lease, &resolver, runtime,
              expected, &item->key, remaining, &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
  }
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    WylFactGraphRestoreSelectedCleanupShape shape =
        WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID;
    rc = check_runtime (runtime, &held[i].key);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_restore_selected_cleanup_shape_open
            (&resolver, &held[i].directory, lease,
              graph->old_provisioning_uuid, operation_uuid,
              graph->replacement_provisioning_uuid,
              &graph->expected_main_identity, &graph->staged_main_identity,
              &shape);
    if (rc == WYRELOG_E_OK
        && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v7_prove (policy,
            expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (canonical, out_committed);
  for (guint i = 0; i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_v8_prove_terminal
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylPolicyOfflineRestoreRecord *expected = NULL;
  g_autoptr (GBytes) canonical = NULL;
  TenantBindGraph *held = NULL;
  guint graph_count = 0;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
  if (rc == WYRELOG_E_OK && (journal.revision != expected_revision
      || expected->revision != expected_revision
      || !g_bytes_equal (canonical, expected->journal_blob)))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || !journal.replacement_selected_pending_cleanup
      || !journal.policy_generation_published
      || !journal.lifecycle_handoff_complete || journal.graphs == NULL
      || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (graph->expected_main_absent || !graph->replay_preflighted
        || graph->old_provisioning_uuid == NULL
        || graph->replacement_provisioning_uuid == NULL
        || graph->transition_state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
        || !graph->transition_terminal)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v8_prove (policy,
            expected);
  if (rc == WYRELOG_E_OK) {
    graph_count = journal.graphs->len;
    held = g_try_new0 (TenantBindGraph, graph_count);
    if (held == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  for (guint i = 0; held != NULL && i < graph_count; i++)
    held[i].directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    TenantBindGraph *item = &held[i];
    rc = wyl_fact_graph_key_init (&item->key, journal.tenant_id,
            graph->graph_id);
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc == WYRELOG_E_OK)
      rc = tenant_commit_v8_quiesce (policy, lease, &resolver, runtime,
              expected, &item->key, remaining, &item->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, graph->graph_id, FALSE, &item->directory);
  }
  for (guint i = 0; rc == WYRELOG_E_OK && i < graph_count; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    WylFactGraphRestoreSelectedCleanupShape shape =
        WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID;
    rc = check_runtime (runtime, &held[i].key);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_restore_selected_cleanup_shape_open
            (&resolver, &held[i].directory, lease,
              graph->old_provisioning_uuid, operation_uuid,
              graph->replacement_provisioning_uuid,
              &graph->expected_main_identity, &graph->staged_main_identity,
              &shape);
    if (rc == WYRELOG_E_OK
        && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_restore_reacquire_v8_prove (policy,
            expected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (canonical, out_committed);
  for (guint i = 0; held != NULL && i < graph_count; i++) {
    wyl_fact_graph_directory_clear (&held[i].directory);
    g_clear_pointer (&held[i].quiescence,
        wyl_fact_graph_quiescence_token_release);
    wyl_fact_graph_key_clear (&held[i].key);
  }
  g_free (held);
  wyl_policy_offline_restore_record_free (expected);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  return rc;
#endif
}

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*companion_checkpoint) (const gchar *, gpointer);
static gpointer companion_checkpoint_data;
static wyrelog_error_t (*sync_staged_checkpoint) (const gchar *, gpointer);
static gpointer sync_staged_checkpoint_data;
static wyrelog_error_t (*retain_checkpoint) (const gchar *, gpointer);
static gpointer retain_checkpoint_data;
static wyrelog_error_t (*sync_retained_checkpoint) (const gchar *, gpointer);
static gpointer sync_retained_checkpoint_data;
static wyrelog_error_t (*publish_checkpoint) (const gchar *, gpointer);
static gpointer publish_checkpoint_data;
#ifndef __linux__
static wyrelog_error_t (*finalize_checkpoint) (const gchar *, gpointer);
static gpointer finalize_checkpoint_data;
#endif

void
wyl_fact_offline_restore_graph_commit_companion_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  companion_checkpoint = checkpoint;
  companion_checkpoint_data = data;
}

void
wyl_fact_offline_restore_graph_commit_sync_staged_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  sync_staged_checkpoint = checkpoint;
  sync_staged_checkpoint_data = data;
}

void
wyl_fact_offline_restore_graph_commit_retain_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  retain_checkpoint = checkpoint;
  retain_checkpoint_data = data;
}

void
wyl_fact_offline_restore_graph_commit_sync_retained_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  sync_retained_checkpoint = checkpoint;
  sync_retained_checkpoint_data = data;
}

void
wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  publish_checkpoint = checkpoint;
  publish_checkpoint_data = data;
}

void
wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  finalize_checkpoint = checkpoint;
  finalize_checkpoint_data = data;
}
#endif


static gboolean
identity_present (const WylFactArtifactInventoryIdentity *identity)
{
  return identity != NULL && identity->domain != 0 && identity->object != 0
         && (identity->object_width == 0 || identity->object_width == 16);
}

static gboolean
commit_snapshot_valid (const WylFactOfflineRestoreJournal *journal,
    const WylPolicyGraphRestoreReplacementRecord *row,
    guint64 expected_revision)
{
  if (journal->version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_HANDOFF_VERSION
      || journal->revision != expected_revision
      || journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal->confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal->policy_generation_published || journal->lifecycle_handoff_complete
      || journal->graphs == NULL || journal->graphs->len != 1 || row == NULL
      || row->journal_revision == 0 || row->journal_revision > journal->revision
      || !(g_str_equal (row->phase, "reserved")
      || g_str_equal (row->phase, "companion_synced")))
    return FALSE;
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (journal->graphs, 0);
  return graph != NULL && !graph->expected_main_absent
         && graph->copied && graph->checksum_verified
         && graph->identity_verified && graph->schema_verified
         && graph->replay_preflighted
         && graph->transition_state ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
         && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
         && !graph->transition_terminal && !graph->resume_forbidden
         && graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
         && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
         && !graph->durability_unprovable_acknowledged
         && identity_present (&graph->expected_main_identity)
         && identity_present (&graph->staged_main_identity)
         && g_strcmp0 (journal->operation_uuid, row->operation_uuid) == 0
         && g_strcmp0 (journal->tenant_id, row->tenant_id) == 0
         && g_strcmp0 (journal->selected_graph_id, row->graph_id) == 0
         && g_strcmp0 (graph->graph_id, row->graph_id) == 0
         && g_strcmp0 (graph->store_uuid, row->store_uuid) == 0
         && g_strcmp0 (graph->old_provisioning_uuid,
             row->old_provisioning_uuid) == 0
         && g_strcmp0 (row->old_provisioning_uuid,
             row->replacement_uuid) != 0
         && journal->destination_tenant_lifecycle_generation ==
         row->tenant_lifecycle_generation
         && journal->destination_tenant_reconciliation_generation ==
         row->tenant_reconciliation_generation
         && graph->destination_lifecycle_generation ==
         row->graph_lifecycle_generation
         && graph->destination_reconciliation_generation ==
         row->graph_reconciliation_generation;
}

static gboolean
row_equal (const WylPolicyGraphRestoreReplacementRecord *a,
    const WylPolicyGraphRestoreReplacementRecord *b)
{
  return g_strcmp0 (a->operation_uuid, b->operation_uuid) == 0
         && g_strcmp0 (a->replacement_uuid, b->replacement_uuid) == 0
         && g_strcmp0 (a->tenant_id, b->tenant_id) == 0
         && g_strcmp0 (a->graph_id, b->graph_id) == 0
         && g_strcmp0 (a->old_provisioning_uuid, b->old_provisioning_uuid) == 0
         && g_strcmp0 (a->store_uuid, b->store_uuid) == 0
         && g_strcmp0 (a->companion_basename, b->companion_basename) == 0
         && g_strcmp0 (a->phase, b->phase) == 0
         && a->tenant_lifecycle_generation == b->tenant_lifecycle_generation
         && a->tenant_reconciliation_generation == b->tenant_reconciliation_generation
         && a->graph_lifecycle_generation == b->graph_lifecycle_generation
         && a->graph_reconciliation_generation == b->graph_reconciliation_generation
         && a->journal_revision == b->journal_revision
         && a->attempt == b->attempt;
}

static wyrelog_error_t
check_policy (wyl_policy_store_t *policy,
    const WylFactOfflineRestoreJournal *journal,
    const WylPolicyGraphRestoreReplacementRecord *row)
{
  WylPolicyFactBackupSnapshot *snapshot = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_fact_graph_backup_snapshot
        (policy, journal->tenant_id, journal->selected_graph_id, &snapshot);
  if (rc == WYRELOG_E_OK) {
    const WylPolicyTenantAuthorityRecord *tenant = snapshot->tenant;
    const WylPolicyFactBackupGraphSnapshot *current =
        snapshot->graphs != NULL && snapshot->graphs->len == 1
        ? g_ptr_array_index (snapshot->graphs, 0) : NULL;
    const WylPolicyGraphAuthorityRecord *graph =
        current != NULL ? current->authority : NULL;
    const WylFactOfflineRestoreJournalGraph *expected =
        g_ptr_array_index (journal->graphs, 0);
    if (tenant == NULL || graph == NULL
        || g_strcmp0 (tenant->tenant_id, journal->tenant_id) != 0
        || tenant->lifecycle_state != WYL_POLICY_TENANT_LIFECYCLE_SEALED
        || !tenant->sealed_compatibility
        || tenant->lifecycle_generation != row->tenant_lifecycle_generation
        || tenant->reconciliation_generation != row->tenant_reconciliation_generation
        || g_strcmp0 (graph->tenant_id, journal->tenant_id) != 0
        || g_strcmp0 (graph->graph_id, row->graph_id) != 0
        || graph->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED
        || !graph->sealed_compatibility || !graph->has_store_identity
        || graph->materialization_state !=
        WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED
        || graph->last_error_class != WYL_POLICY_GRAPH_ERROR_NONE
        || graph->lifecycle_generation != row->graph_lifecycle_generation
        || graph->reconciliation_generation != row->graph_reconciliation_generation
        || g_strcmp0 (graph->store_uuid, row->store_uuid) != 0
        || graph->format_version != expected->format_version
        || graph->path_encoding_version != expected->path_encoding_version)
      rc = WYRELOG_E_POLICY;
  }
  g_clear_pointer (&snapshot, wyl_policy_fact_backup_snapshot_free);
  g_autoptr (GPtrArray) records = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_provisioning_list_for_graph (policy,
            journal->tenant_id, journal->selected_graph_id, &records);
  guint active = 0;
  for (guint i = 0; rc == WYRELOG_E_OK && i < records->len; i++) {
    const WylPolicyGraphProvisioningRecord *record =
        g_ptr_array_index (records, i);
    if (record->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE)
      continue;
    active++;
    if (g_strcmp0 (record->op_uuid, row->old_provisioning_uuid) != 0
        || g_strcmp0 (record->tenant_id, row->tenant_id) != 0
        || g_strcmp0 (record->graph_id, row->graph_id) != 0
        || g_strcmp0 (record->store_uuid, row->store_uuid) != 0)
      rc = WYRELOG_E_POLICY;
  }
  return rc == WYRELOG_E_OK && active != 1 ? WYRELOG_E_POLICY : rc;
}

static wyrelog_error_t
check_runtime (WylFactGraphRuntimeManager *runtime,
    const WylFactGraphKey *key)
{
  WylFactGraphRuntimeStatus status = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_runtime_manager_get_status
        (runtime, key, &status);
  if (rc == WYRELOG_E_OK && (status.state == WYL_FACT_GRAPH_RUNTIME_ABANDONED
      || status.admission != WYL_FACT_GRAPH_ADMISSION_CLOSED
      || status.operation_active || status.active_engine_calls != 0
      || status.waiting_engine_calls != 0))
    rc = WYRELOG_E_BUSY;
  wyl_fact_graph_runtime_status_clear (&status);
  return rc;
}

static wyrelog_error_t
check_persisted (wyl_policy_store_t *policy, const gchar *operation_uuid,
    GBytes *expected_journal,
    const WylPolicyGraphRestoreReplacementRecord *expected_row,
    const WylFactOfflineRestoreJournal *journal)
{
  g_auto (WylFactOfflineRestoreJournal) current = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load
        (policy, operation_uuid, &current);
  g_autoptr (GBytes) encoded = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&current, &encoded);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (encoded, expected_journal))
    rc = WYRELOG_E_BUSY;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load
          (policy, operation_uuid, &row);
  if (rc == WYRELOG_E_OK && !row_equal (row, expected_row))
    rc = WYRELOG_E_BUSY;
  wyl_policy_graph_restore_replacement_record_free (row);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, journal, expected_row);
  return rc;
}

static wyrelog_error_t
graph_commit_quiesce (wyl_policy_store_t *policy,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    GBytes *encoded,
    const WylPolicyGraphRestoreReplacementRecord *row,
    gboolean selected, const WylFactGraphKey *key, gint64 timeout_us,
    WylFactGraphQuiescenceToken **out_token)
{
  wyrelog_error_t rc = wyl_fact_graph_runtime_manager_quiesce (runtime,
          key, timeout_us, out_token);
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;
  rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = selected ? wyl_policy_store_graph_restore_reacquire_v3_prove
          (policy, operation_uuid, encoded, row)
        : wyl_policy_store_graph_restore_reacquire_v2_prove
          (policy, operation_uuid, encoded, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed (runtime,
            key, timeout_us, out_token);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, resolver);
  if (rc == WYRELOG_E_OK)
    rc = selected ? wyl_policy_store_graph_restore_reacquire_v3_prove
          (policy, operation_uuid, encoded, row)
        : wyl_policy_store_graph_restore_reacquire_v2_prove
          (policy, operation_uuid, encoded, row);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_token, wyl_fact_graph_quiescence_token_release);
  return rc;
}

static wyrelog_error_t
open_shape (WylFactGraphResolver *resolver, WylFactGraphDirectory *directory,
    WylFactRootWriterLease *lease,
    const WylFactOfflineRestoreJournal *journal,
    const WylPolicyGraphRestoreReplacementRecord *row,
    WylFactGraphRestorePostPublishLayout *out_layout,
    WylFactGraphProvisionedRestoreWitness **out_witness)
{
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (journal->graphs, 0);
  WylFactGraphProvisionedRestoreWitness *witness = NULL;
  *out_layout = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  if (out_witness != NULL)
    *out_witness = NULL;
  wyrelog_error_t rc;
  if (g_str_equal (row->phase, "reserved"))
    rc = wyl_fact_graph_restore_post_publish_reserved_shape_open (resolver,
            directory, lease, row->old_provisioning_uuid,
            journal->operation_uuid, row->replacement_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            out_layout, &witness);
  else {
    rc = wyl_fact_graph_restore_post_publish_shape_open (resolver, directory,
            lease, row->old_provisioning_uuid, journal->operation_uuid,
            row->replacement_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity,
            WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION, &witness);
    if (rc == WYRELOG_E_OK)
      *out_layout = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION;
  }
  if (rc == WYRELOG_E_OK && out_witness != NULL)
    *out_witness = witness;
  else
    wyl_fact_graph_provisioned_restore_witness_free (witness);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_inspect
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactGraphCommitInspectionFunc callback, gpointer user_data)
{
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || callback == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  (void) user_data;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load
          (policy, operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load
          (policy, operation_uuid, &row);
  if (rc == WYRELOG_E_OK && !commit_snapshot_valid
        (&journal, row, expected_revision))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
  WylFactGraphRestorePostPublishLayout layout =
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = open_shape (&resolver, &directory, lease, &journal, row, &layout,
            NULL);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  WylFactGraphRestorePostPublishLayout final_layout =
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  if (rc == WYRELOG_E_OK)
    rc = open_shape (&resolver, &directory, lease, &journal, row,
            &final_layout, NULL);
  if (rc == WYRELOG_E_OK && layout != final_layout)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, 0);
    WylFactGraphCommitInspection inspection = {
      .operation_uuid = g_strdup (journal.operation_uuid),
      .tenant_id = g_strdup (journal.tenant_id),
      .graph_id = g_strdup (journal.selected_graph_id),
      .store_uuid = g_strdup (row->store_uuid),
      .old_provisioning_uuid = g_strdup (row->old_provisioning_uuid),
      .replacement_uuid = g_strdup (row->replacement_uuid),
      .replacement_phase = g_strdup (row->phase),
      .journal_revision = journal.revision,
      .old_main = graph->expected_main_identity,
      .new_main = graph->staged_main_identity,
      .layout = final_layout,
    };
    rc = callback (&inspection, user_data);
    g_free (inspection.operation_uuid);
    g_free (inspection.tenant_id);
    g_free (inspection.graph_id);
    g_free (inspection.store_uuid);
    g_free (inspection.old_provisioning_uuid);
    g_free (inspection.replacement_uuid);
    g_free (inspection.replacement_phase);
  }
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  WylFactGraphResolver *resolver;
  WylFactGraphDirectory *directory;
  WylFactRootWriterLease *lease;
  WylFactGraphRuntimeManager *runtime;
  WylFactGraphKey *key;
  const WylFactOfflineRestoreJournal *journal;
} SelectReplacementEffect;

static wyrelog_error_t
select_replacement_effect
  (const WylPolicyGraphRestoreReplacementRecord *row, gpointer user_data)
{
  SelectReplacementEffect *context = user_data;
  WylFactGraphRestorePostPublishLayout layout =
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (context->lease, context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (context->runtime, context->key);
  if (rc == WYRELOG_E_OK)
    rc = open_shape (context->resolver, context->directory, context->lease,
            context->journal, row, &layout, NULL);
  return rc == WYRELOG_E_OK
         && layout != WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION
    ? WYRELOG_E_POLICY : rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_select_replacement_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) selected = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  g_autoptr (GBytes) selected_bytes = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  if (rc == WYRELOG_E_OK
      && (!commit_snapshot_valid (&journal, row, expected_revision)
      || !g_str_equal (row->phase, "companion_synced")))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  WylFactGraphRestorePostPublishLayout layout =
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  if (rc == WYRELOG_E_OK)
    rc = open_shape (&resolver, &directory, lease, &journal, row, &layout,
            NULL);
  if (rc == WYRELOG_E_OK
      && layout != WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (encoded, &selected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_mark_replacement_selected
          (&selected);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&selected,
            &selected_bytes);
  if (rc == WYRELOG_E_OK) {
    WylPolicyOfflineRestoreRecord before = {
      .operation_uuid = journal.operation_uuid,
      .tenant_id = journal.tenant_id,
      .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH,
      .selected_graph_id = journal.selected_graph_id,
      .revision = journal.revision,
      .graph_count = 1,
      .journal_blob = encoded,
    };
    memcpy (before.manifest_sha256, journal.manifest_sha256, 32);
    WylPolicyOfflineRestoreRecord after = before;
    after.revision = selected.revision;
    after.journal_blob = selected_bytes;
    SelectReplacementEffect effect = { &resolver, &directory, lease,
                                       runtime, &key, &journal };
    WylPolicyOfflineRestoreStoreResult result =
        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    rc = wyl_policy_store_graph_restore_select_with_effect (policy, row,
            &before, &after, select_replacement_effect, &effect, &result);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK) {
      *out_committed = selected;
      memset (&selected, 0, sizeof selected);
    }
  }
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  WylFactGraphResolver *resolver;
  WylFactGraphDirectory *directory;
  WylFactRootWriterLease *lease;
  WylFactGraphRuntimeManager *runtime;
  const WylFactGraphKey *key;
  const WylFactOfflineRestoreJournal *journal;
  WylFactGraphRestorePostPublishLayout initial_layout;
} CompanionEffect;

static wyrelog_error_t
sync_companion_effect
  (const WylPolicyGraphRestoreReplacementRecord *current,
    gpointer user_data)
{
  CompanionEffect *effect = user_data;
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (effect->journal->graphs, 0);
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (effect->lease, effect->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (effect->runtime, effect->key);
  WylFactGraphRestorePostPublishLayout layout =
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  WylFactGraphProvisionedRestoreWitness *retained = NULL;
  if (rc == WYRELOG_E_OK)
    rc = open_shape (effect->resolver, effect->directory, effect->lease,
            effect->journal, current, &layout, &retained);
  if (rc == WYRELOG_E_OK && layout != effect->initial_layout)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && g_str_equal (current->phase, "companion_synced")
      && layout != WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION)
    rc = WYRELOG_E_POLICY;
  WylFactGraphProvisionedRestoreWitness *dual = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_companion_link_post_publish_for_layout
          (effect->resolver, effect->directory, effect->lease,
            layout == WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_MAIN_ONE_LINK
            ? retained : NULL, current->old_provisioning_uuid,
            effect->journal->operation_uuid, current->replacement_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            layout, &dual);
  wyl_fact_graph_provisioned_restore_witness_free (retained);
  wyl_fact_graph_provisioned_restore_witness_free (dual);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (effect->lease,
            effect->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (effect->runtime, effect->key);
  WylFactGraphProvisionedRestoreWitness *final = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_post_publish_shape_open (effect->resolver,
            effect->directory, effect->lease, current->old_provisioning_uuid,
            effect->journal->operation_uuid, current->replacement_uuid,
            &graph->expected_main_identity, &graph->staged_main_identity,
            WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION, &final);
  wyl_fact_graph_provisioned_restore_witness_free (final);
  return rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_companion_recover
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylPolicyGraphRestoreReplacementRecord **out_committed)
{
  if (out_committed != NULL)
    *out_committed = NULL;
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  WylPolicyOfflineRestoreRecord *raw_journal = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load
          (policy, operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load
          (policy, operation_uuid, &row);
  if (rc == WYRELOG_E_OK && !commit_snapshot_valid
        (&journal, row, expected_revision))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK) {
    directory.checkpoint = companion_checkpoint;
    directory.checkpoint_data = companion_checkpoint_data;
  }
#endif
  WylFactGraphRestorePostPublishLayout layout =
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = open_shape (&resolver, &directory, lease, &journal, row,
            &layout, NULL);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &raw_journal);
  if (rc == WYRELOG_E_OK
      && (raw_journal->revision != journal.revision
      || !g_bytes_equal (raw_journal->journal_blob, encoded)))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK) {
    CompanionEffect effect = {
      .resolver = &resolver, .directory = &directory, .lease = lease,
      .runtime = runtime, .key = &key, .journal = &journal,
      .initial_layout = layout,
    };
    WylPolicyOfflineRestoreStoreResult result =
        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    rc = wyl_policy_store_graph_restore_replacement_sync_with_effect
          (policy, row, raw_journal, sync_companion_effect, &effect,
            &result, out_committed);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY)
      rc = WYRELOG_E_BUSY;
  }
  if (rc != WYRELOG_E_OK) {
    wyl_policy_graph_restore_replacement_record_free (*out_committed);
    *out_committed = NULL;
  }
  wyl_policy_offline_restore_record_free (raw_journal);
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
static gboolean
sync_staged_snapshot_valid (const WylFactOfflineRestoreJournal *journal,
    const WylPolicyGraphRestoreReplacementRecord *row,
    guint64 expected_revision)
{
  if (journal->version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_HANDOFF_VERSION
      || journal->revision != expected_revision
      || journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal->confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal->policy_generation_published
      || journal->lifecycle_handoff_complete
      || journal->graphs == NULL || journal->graphs->len != 1
      || row == NULL || !g_str_equal (row->phase, "reserved")
      || row->journal_revision == 0
      || row->journal_revision > journal->revision)
    return FALSE;
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (journal->graphs, 0);
  return graph != NULL && !graph->expected_main_absent
         && graph->copied && graph->checksum_verified
         && graph->identity_verified && graph->schema_verified
         && graph->replay_preflighted && !graph->resume_forbidden
         && !graph->durability_unprovable_acknowledged
         && graph->transition_state ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
         && graph->next_op ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
         && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
         ? graph->pending_op ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
         : graph->pending_op ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
         && identity_present (&graph->expected_main_identity)
         && identity_present (&graph->staged_main_identity)
         && g_strcmp0 (journal->operation_uuid, row->operation_uuid) == 0
         && g_strcmp0 (journal->tenant_id, row->tenant_id) == 0
         && g_strcmp0 (journal->selected_graph_id, row->graph_id) == 0
         && g_strcmp0 (graph->graph_id, row->graph_id) == 0
         && g_strcmp0 (graph->store_uuid, row->store_uuid) == 0
         && g_strcmp0 (graph->old_provisioning_uuid,
             row->old_provisioning_uuid) == 0
         && journal->destination_tenant_lifecycle_generation ==
         row->tenant_lifecycle_generation
         && journal->destination_tenant_reconciliation_generation ==
         row->tenant_reconciliation_generation
         && graph->destination_lifecycle_generation ==
         row->graph_lifecycle_generation
         && graph->destination_reconciliation_generation ==
         row->graph_reconciliation_generation;
}

typedef enum
{
  SYNC_STAGED_BEGIN,
  SYNC_STAGED_NOT_APPLIED,
  SYNC_STAGED_COMPLETE,
} SyncStagedJournalChange;

static wyrelog_error_t
sync_staged_journal_cas (wyl_policy_store_t *policy,
    WylFactOfflineRestoreJournal *journal, SyncStagedJournalChange change)
{
  g_autoptr (GBytes) source = NULL;
  g_autoptr (GBytes) desired_bytes = NULL;
  g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_encode (journal,
          &source);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (source, &desired);
  if (rc == WYRELOG_E_OK) {
    switch (change) {
      case SYNC_STAGED_BEGIN:
        rc = wyl_fact_offline_restore_journal_begin_attempt (&desired,
                journal->selected_graph_id,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED);
        break;
      case SYNC_STAGED_NOT_APPLIED:
        rc = wyl_fact_offline_restore_journal_record_not_applied (&desired,
                journal->selected_graph_id,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED);
        break;
      case SYNC_STAGED_COMPLETE:
        rc = wyl_fact_offline_restore_journal_complete_attempt (&desired,
                journal->selected_graph_id,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN, FALSE);
        break;
    }
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&desired, &desired_bytes);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactOfflineRestoreStoreResult result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  rc = wyl_fact_offline_restore_journal_store_cas (policy,
          journal->revision, &desired, &result, &committed);
  if (rc != WYRELOG_E_OK
      || result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED) {
    wyrelog_error_t original = rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
    wyl_fact_offline_restore_journal_clear (&committed);
    wyrelog_error_t observed = wyl_fact_offline_restore_journal_store_load
          (policy, journal->operation_uuid, &committed);
    if (observed != WYRELOG_E_OK)
      return original;
    rc = WYRELOG_E_OK;
  }
  g_autoptr (GBytes) committed_bytes = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&committed,
            &committed_bytes);
  if (rc != WYRELOG_E_OK
      || !g_bytes_equal (desired_bytes, committed_bytes))
    return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
  wyl_fact_offline_restore_journal_clear (journal);
  *journal = committed;
  memset (&committed, 0, sizeof committed);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
sync_staged_capture_ready (WylFactArtifactTransitionPosix *provider,
    const WylFactOfflineRestoreJournal *journal,
    const gchar *old_provisioning_uuid,
    WylFactArtifactMainTransitionRequest *out_request,
    WylFactArtifactInventorySnapshot **out_snapshot,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  *out_snapshot = NULL;
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) initial = NULL;
  WylFactArtifactMainTransitionObservation observation = { 0 };
  wyrelog_error_t rc = wyl_fact_artifact_transition_posix_capture
        (provider, &lifecycle, &initial, &observation);
  if (rc != WYRELOG_E_OK)
    return rc;
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (journal->graphs, 0);
  WylFactArtifactMainTransitionRequest request = {
    .operation_uuid = journal->operation_uuid,
    .directory_identity = observation.directory_identity,
    .lease_identity = observation.lease_identity,
    .expected_main_absent = FALSE,
    .expected_main_identity = graph->expected_main_identity,
    .staged_main_identity = graph->staged_main_identity,
  };
  rc = wyl_fact_artifact_transition_posix_capture_provisioned (provider,
          old_provisioning_uuid, &request,
          WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, &lifecycle,
          out_snapshot, out_observation);
  if (rc == WYRELOG_E_OK)
    *out_request = request;
  return rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_sync_staged_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  WylFactArtifactTransitionPosix *provider = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  if (rc == WYRELOG_E_OK && !sync_staged_snapshot_valid (&journal, row,
      expected_revision))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
  WylFactArtifactTransitionPosixCapability capability = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_probe_capability (&directory,
            operation_uuid, &capability);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_open (&resolver, &directory,
            lease, operation_uuid, &capability, &provider);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK
      && ((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (journal.graphs, 0))->attempt !=
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN) {
    WylFactArtifactMainTransitionRequest request = { 0 };
    g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
    WylFactArtifactMainTransitionObservation observation = { 0 };
    rc = sync_staged_capture_ready (provider, &journal,
            row->old_provisioning_uuid, &request, &snapshot, &observation);
    if (rc == WYRELOG_E_OK)
      rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
    if (rc == WYRELOG_E_OK)
      rc = sync_staged_journal_cas (policy, &journal, SYNC_STAGED_BEGIN);
    if (rc == WYRELOG_E_OK) {
      g_clear_pointer (&encoded, g_bytes_unref);
      rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
    }
#ifdef WYL_TEST_HANDLE_SEAMS
    if (rc == WYRELOG_E_OK && sync_staged_checkpoint != NULL)
      rc = sync_staged_checkpoint ("restore-sync-staged-after-begin",
              sync_staged_checkpoint_data);
#endif
  }
  WylFactArtifactMainTransitionRequest request = { 0 };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation before = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  if (rc == WYRELOG_E_OK)
    rc = sync_staged_capture_ready (provider, &journal,
            row->old_provisioning_uuid, &request, &snapshot, &before);
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  WylFactArtifactMainTransitionResult transition_result = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
            &before, &transition_result, &transition);
  if (rc == WYRELOG_E_OK
      && (transition == NULL || transition_result.state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
      || transition_result.next_op !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_main_transition_authorize (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
            &before, &transition_result);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  WylFactArtifactMainTransitionEffect effect =
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_execute_provisioned (provider,
            row->old_provisioning_uuid, &request, &before,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
            &effect, &durability);
  if (rc == WYRELOG_E_OK
      && effect == WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED)
    rc = sync_staged_journal_cas (policy, &journal,
            SYNC_STAGED_NOT_APPLIED);
  else if (rc == WYRELOG_E_OK
      && (effect != WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
      || durability.staged_file !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN))
    rc = WYRELOG_E_BUSY;
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && effect ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
      && sync_staged_checkpoint != NULL)
    rc = sync_staged_checkpoint ("restore-sync-staged-after-fsync",
            sync_staged_checkpoint_data);
#endif
  WylFactArtifactMainTransitionObservation after = { 0 };
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  if (rc == WYRELOG_E_OK && effect ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
    rc = sync_staged_capture_ready (provider, &journal,
            row->old_provisioning_uuid, &request, &snapshot, &after);
  if (rc == WYRELOG_E_OK && effect ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED) {
    after.durability = durability;
    rc = wyl_fact_artifact_main_transition_record (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED, effect,
            &after, &transition_result);
  }
  if (rc == WYRELOG_E_OK && effect ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
      && (transition_result.state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
      || transition_result.next_op !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && effect ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
    rc = sync_staged_journal_cas (policy, &journal, SYNC_STAGED_COMPLETE);
  if (rc == WYRELOG_E_OK && effect ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED) {
    *out_committed = journal;
    memset (&journal, 0, sizeof journal);
  } else if (rc == WYRELOG_E_OK)
    rc = WYRELOG_E_BUSY;
  wyl_fact_artifact_transition_posix_free (provider);
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  WylFactArtifactTransitionPosix *provider;
  const WylFactOfflineRestoreJournal *journal;
} RetainEffectContext;

static wyrelog_error_t
early_commit_begin (wyl_policy_store_t *policy,
    WylFactOfflineRestoreJournal *journal,
    WylFactArtifactMainTransitionOp operation)
{
  g_autoptr (GBytes) source = NULL;
  g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_encode (journal,
          &source);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (source, &desired);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_begin_attempt (&desired,
            journal->selected_graph_id, operation);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactOfflineRestoreStoreResult result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  rc = wyl_fact_offline_restore_journal_store_cas (policy,
          journal->revision, &desired, &result, &committed);
  if (rc != WYRELOG_E_OK || result !=
      WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED)
    return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
  wyl_fact_offline_restore_journal_clear (journal);
  *journal = committed;
  memset (&committed, 0, sizeof committed);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
retain_capture (WylFactArtifactTransitionPosix *provider,
    const WylFactOfflineRestoreJournal *journal, const gchar *old_uuid,
    WylFactGraphProvisionedRestoreSlot slot,
    WylFactArtifactMainTransitionRequest *out_request,
    WylFactArtifactInventorySnapshot **out_snapshot,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) preliminary = NULL;
  WylFactArtifactMainTransitionObservation observed = { 0 };
  wyrelog_error_t rc = wyl_fact_artifact_transition_posix_capture
        (provider, &lifecycle, &preliminary, &observed);
  if (rc != WYRELOG_E_OK)
    return rc;
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (journal->graphs, 0);
  WylFactArtifactMainTransitionRequest request = {
    .operation_uuid = journal->operation_uuid,
    .directory_identity = observed.directory_identity,
    .lease_identity = observed.lease_identity,
    .expected_main_absent = FALSE,
    .expected_main_identity = graph->expected_main_identity,
    .staged_main_identity = graph->staged_main_identity,
  };
  rc = wyl_fact_artifact_transition_posix_capture_provisioned (provider,
          old_uuid, &request, slot, &lifecycle, out_snapshot,
          out_observation);
  if (rc == WYRELOG_E_OK)
    *out_request = request;
  return rc;
}

static wyrelog_error_t
retain_effect (const WylPolicyGraphRestoreReplacementRecord *row,
    gpointer user_data)
{
  RetainEffectContext *context = user_data;
  WylFactArtifactTransitionPosix *provider = context->provider;
  const WylFactOfflineRestoreJournal *journal = context->journal;
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) initial = NULL;
  WylFactArtifactMainTransitionObservation first = { 0 };
  wyrelog_error_t rc = wyl_fact_artifact_transition_posix_capture
        (provider, &lifecycle, &initial, &first);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean ready = first.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN]
      .present;
  WylFactGraphProvisionedRestoreSlot slot = ready
    ? WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN
    : WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK;
  WylFactArtifactMainTransitionRequest request = { 0 };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation before = { 0 };
  rc = retain_capture (provider, journal, row->old_provisioning_uuid,
          slot, &request, &snapshot, &before);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  WylFactArtifactMainTransitionResult result = { 0 };
  rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
          &before, &result, &transition);
  if (rc != WYRELOG_E_OK || transition == NULL)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  if (ready) {
    if (result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || result.next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED)
      return WYRELOG_E_POLICY;
    rc = wyl_fact_artifact_main_transition_authorize (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
            &before, &result);
    WylFactArtifactMainTransitionEffect effect =
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_execute_provisioned
            (provider, row->old_provisioning_uuid, &request, &before,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
              &effect, &durability);
    if (rc != WYRELOG_E_OK || effect !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
        || durability.staged_file !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
      return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
    g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
    WylFactArtifactMainTransitionObservation synced = { 0 };
    rc = retain_capture (provider, journal, row->old_provisioning_uuid,
            slot, &request, &snapshot, &synced);
    if (rc == WYRELOG_E_OK) {
      synced.durability = durability;
      rc = wyl_fact_artifact_main_transition_record (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
              effect, &synced, &result);
    }
    if (rc != WYRELOG_E_OK || result.next_op !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN)
      return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    rc = wyl_fact_artifact_main_transition_authorize (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN,
            &synced, &result);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_execute_provisioned
            (provider, row->old_provisioning_uuid, &request, &synced,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN,
              &effect, &durability);
    if (rc != WYRELOG_E_OK || effect !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
      return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
    if (retain_checkpoint != NULL) {
      rc = retain_checkpoint ("restore-retain-after-rename",
              retain_checkpoint_data);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
#endif
  } else if (result.state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED)
    return WYRELOG_E_POLICY;

  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  WylFactArtifactMainTransitionObservation retained = { 0 };
  rc = retain_capture (provider, journal, row->old_provisioning_uuid,
          WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
          &request, &snapshot, &retained);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactArtifactMainTransitionEffect sync_effect =
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
  WylFactArtifactMainTransitionDurabilityEvidence sync_durability = { 0 };
  rc = wyl_fact_artifact_transition_posix_execute_provisioned (provider,
          row->old_provisioning_uuid, &request, &retained,
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
          &sync_effect, &sync_durability);
  if (rc != WYRELOG_E_OK || sync_effect !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
      || sync_durability.directory_after_retain !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
    return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
  if (retain_checkpoint != NULL) {
    rc = retain_checkpoint ("restore-retain-after-fsync",
            retain_checkpoint_data);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
#endif
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  rc = retain_capture (provider, journal, row->old_provisioning_uuid,
          WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
          &request, &snapshot, &retained);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (WylFactArtifactMainTransition) verified = NULL;
  WylFactArtifactMainTransitionResult verified_result = { 0 };
  rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
          &retained, &verified_result, &verified);
  return rc == WYRELOG_E_OK
         && verified_result.state ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
    ? WYRELOG_E_OK : (rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc);
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_retain_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  WylFactArtifactTransitionPosix *provider = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  if (rc == WYRELOG_E_OK) {
    const WylFactOfflineRestoreJournalGraph *graph =
        journal.graphs != NULL && journal.graphs->len == 1
        ? g_ptr_array_index (journal.graphs, 0) : NULL;
    if (journal.revision != expected_revision
        || !(graph != NULL
        && journal.version == WYL_FACT_OFFLINE_RESTORE_JOURNAL_HANDOFF_VERSION
        && journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        && journal.confirmation == WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
        && journal.manifest_trust == WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
        && !journal.policy_generation_published
        && !journal.lifecycle_handoff_complete
        && row != NULL && g_str_equal (row->phase, "reserved")
        && graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN
        && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
        ? graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN
        : graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
        && graph->copied && graph->checksum_verified
        && graph->identity_verified && graph->schema_verified
        && graph->replay_preflighted && !graph->resume_forbidden
        && identity_present (&graph->expected_main_identity)
        && identity_present (&graph->staged_main_identity)
        && g_strcmp0 (graph->old_provisioning_uuid,
        row->old_provisioning_uuid) == 0
        && g_strcmp0 (graph->store_uuid, row->store_uuid) == 0))
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
  WylFactArtifactTransitionPosixCapability capability = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_probe_capability (&directory,
            operation_uuid, &capability);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_open (&resolver, &directory,
            lease, operation_uuid, &capability, &provider);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  WylFactOfflineRestoreJournalGraph *graph = rc == WYRELOG_E_OK
    ? g_ptr_array_index (journal.graphs, 0) : NULL;
  if (rc == WYRELOG_E_OK
      && graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
    rc = early_commit_begin (policy, &journal,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && retain_checkpoint != NULL)
    rc = retain_checkpoint ("restore-retain-after-begin",
            retain_checkpoint_data);
#endif
  if (rc == WYRELOG_E_OK) {
    g_clear_pointer (&encoded, g_bytes_unref);
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  }
  /* The filesystem effect is authorized by the pinned policy transaction. */
  if (rc == WYRELOG_E_OK) {
    g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
    rc = wyl_fact_offline_restore_journal_decode (encoded, &desired);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_complete_attempt (&desired,
              journal.selected_graph_id,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
              FALSE);
    g_autoptr (GBytes) desired_bytes = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&desired,
              &desired_bytes);
    if (rc == WYRELOG_E_OK) {
      WylPolicyOfflineRestoreRecord pending = {
        .operation_uuid = journal.operation_uuid,
        .tenant_id = journal.tenant_id,
        .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH,
        .selected_graph_id = journal.selected_graph_id,
        .revision = journal.revision,
        .graph_count = 1,
        .journal_blob = encoded,
      };
      memcpy (pending.manifest_sha256, journal.manifest_sha256, 32);
      WylPolicyOfflineRestoreRecord completed = pending;
      completed.revision = desired.revision;
      completed.journal_blob = desired_bytes;
      RetainEffectContext context = { provider, &journal };
      WylPolicyOfflineRestoreStoreResult result =
          WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
      rc = wyl_policy_store_graph_restore_retain_with_effect (policy,
              row, &pending, &completed, retain_effect, &context, &result);
      if (rc == WYRELOG_E_OK
          && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
        rc = WYRELOG_E_BUSY;
      if (rc == WYRELOG_E_OK) {
        *out_committed = desired;
        memset (&desired, 0, sizeof desired);
      }
    }
  }
  wyl_fact_artifact_transition_posix_free (provider);
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  WylFactArtifactTransitionPosix *provider;
  const WylFactOfflineRestoreJournal *journal;
  WylFactArtifactMainTransitionOp target;
} SyncRetainedEffectContext;

static wyrelog_error_t
sync_retained_effect (const WylPolicyGraphRestoreReplacementRecord *row,
    gpointer user_data)
{
  SyncRetainedEffectContext *context = user_data;
  WylFactArtifactMainTransitionRequest request = { 0 };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation observation = { 0 };
  wyrelog_error_t rc = retain_capture (context->provider, context->journal,
          row->old_provisioning_uuid,
          WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
          &request, &snapshot, &observation);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  WylFactArtifactMainTransitionResult result = { 0 };
  rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
          &observation, &result, &transition);
  if (rc != WYRELOG_E_OK || transition == NULL
      || result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
      || result.next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;

  const WylFactArtifactMainTransitionOp sequence[] = {
    WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
    WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
    WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
  };
  const guint count = context->target ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE ? 2 : 3;
  for (guint i = 0; i < count; i++) {
    WylFactArtifactMainTransitionOp operation = sequence[i];
    if (result.next_op != operation)
      return WYRELOG_E_POLICY;
    rc = wyl_fact_artifact_main_transition_authorize (transition,
            operation, &observation, &result);
    WylFactArtifactMainTransitionEffect effect =
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_execute_provisioned
            (context->provider, row->old_provisioning_uuid, &request,
              &observation, operation, &effect, &durability);
    WylFactArtifactMainTransitionDurability proven = i == 0
      ? durability.staged_file : i == 1
      ? durability.rollback_file : durability.directory_after_retain;
    if (rc != WYRELOG_E_OK || effect !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
        || proven != WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
      return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
    if (operation == context->target && sync_retained_checkpoint != NULL) {
      rc = sync_retained_checkpoint ("restore-sync-retained-after-fsync",
              sync_retained_checkpoint_data);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
#endif
    g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
    WylFactArtifactMainTransitionObservation after = { 0 };
    rc = retain_capture (context->provider, context->journal,
            row->old_provisioning_uuid,
            WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
            &request, &snapshot, &after);
    if (rc != WYRELOG_E_OK)
      return rc;
    after.durability = durability;
    rc = wyl_fact_artifact_main_transition_record (transition, operation,
            effect, &after, &result);
    if (rc != WYRELOG_E_OK
        || result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED)
      return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    observation = after;
  }
  if (result.next_op != (count == 2
      ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
      : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH))
    return WYRELOG_E_POLICY;
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  rc = retain_capture (context->provider, context->journal,
          row->old_provisioning_uuid,
          WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
          &request, &snapshot, &observation);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (WylFactArtifactMainTransition) verified = NULL;
  WylFactArtifactMainTransitionResult verified_result = { 0 };
  rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
          &observation, &verified_result, &verified);
  return rc == WYRELOG_E_OK
         && verified_result.state ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
    ? WYRELOG_E_OK : (rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc);
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_sync_retained_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  WylFactArtifactTransitionPosix *provider = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  if (rc == WYRELOG_E_OK) {
    const WylFactOfflineRestoreJournalGraph *graph =
        journal.graphs != NULL && journal.graphs->len == 1
        ? g_ptr_array_index (journal.graphs, 0) : NULL;
    if (journal.revision != expected_revision
        || !(graph != NULL
        && journal.version == WYL_FACT_OFFLINE_RESTORE_JOURNAL_HANDOFF_VERSION
        && journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        && journal.confirmation == WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
        && journal.manifest_trust == WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
        && !journal.policy_generation_published
        && !journal.lifecycle_handoff_complete
        && row != NULL && g_str_equal (row->phase, "reserved")
        && graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
        && (graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
        || graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR)
        && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
        ? graph->pending_op == graph->next_op
        : graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
        && graph->copied && graph->checksum_verified
        && graph->identity_verified && graph->schema_verified
        && graph->replay_preflighted && !graph->resume_forbidden
        && identity_present (&graph->expected_main_identity)
        && identity_present (&graph->staged_main_identity)
        && g_strcmp0 (graph->old_provisioning_uuid,
        row->old_provisioning_uuid) == 0
        && g_strcmp0 (graph->store_uuid, row->store_uuid) == 0))
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
  WylFactArtifactTransitionPosixCapability capability = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_probe_capability (&directory,
            operation_uuid, &capability);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_open (&resolver, &directory,
            lease, operation_uuid, &capability, &provider);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  WylFactOfflineRestoreJournalGraph *graph = rc == WYRELOG_E_OK
    ? g_ptr_array_index (journal.graphs, 0) : NULL;
  WylFactArtifactMainTransitionOp operation = rc == WYRELOG_E_OK
    ? graph->next_op : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  if (rc == WYRELOG_E_OK
      && graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
    rc = early_commit_begin (policy, &journal, operation);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && sync_retained_checkpoint != NULL)
    rc = sync_retained_checkpoint ("restore-sync-retained-after-begin",
            sync_retained_checkpoint_data);
#endif
  if (rc == WYRELOG_E_OK) {
    g_clear_pointer (&encoded, g_bytes_unref);
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  }
  /* The filesystem effect is authorized by the pinned policy transaction. */
  if (rc == WYRELOG_E_OK) {
    g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
    rc = wyl_fact_offline_restore_journal_decode (encoded, &desired);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_complete_attempt (&desired,
              journal.selected_graph_id,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED,
              operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
              ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
              : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH, FALSE);
    g_autoptr (GBytes) desired_bytes = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&desired,
              &desired_bytes);
    if (rc == WYRELOG_E_OK) {
      WylPolicyOfflineRestoreRecord pending = {
        .operation_uuid = journal.operation_uuid,
        .tenant_id = journal.tenant_id,
        .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH,
        .selected_graph_id = journal.selected_graph_id,
        .revision = journal.revision,
        .graph_count = 1,
        .journal_blob = encoded,
      };
      memcpy (pending.manifest_sha256, journal.manifest_sha256, 32);
      WylPolicyOfflineRestoreRecord completed = pending;
      completed.revision = desired.revision;
      completed.journal_blob = desired_bytes;
      SyncRetainedEffectContext context = { provider, &journal, operation };
      WylPolicyOfflineRestoreStoreResult result =
          WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
      rc = wyl_policy_store_graph_restore_sync_retained_with_effect
            (policy, row, &pending, &completed, operation,
              sync_retained_effect, &context, &result);
      if (rc == WYRELOG_E_OK
          && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
        rc = WYRELOG_E_BUSY;
      if (rc == WYRELOG_E_OK) {
        *out_committed = desired;
        memset (&desired, 0, sizeof desired);
      }
    }
  }
  wyl_fact_artifact_transition_posix_free (provider);
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  WylFactArtifactTransitionPosix *provider;
  const WylFactOfflineRestoreJournal *journal;
  WylFactArtifactMainTransitionOp target;
} PublishEffectContext;

static wyrelog_error_t
publish_capture (PublishEffectContext *context,
    const WylPolicyGraphRestoreReplacementRecord *row,
    WylFactArtifactMainTransitionRequest *request,
    WylFactArtifactInventorySnapshot **snapshot,
    WylFactArtifactMainTransitionObservation *observation)
{
  return retain_capture (context->provider, context->journal,
             row->old_provisioning_uuid,
             WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
             request, snapshot, observation);
}

static wyrelog_error_t
publish_effect (const WylPolicyGraphRestoreReplacementRecord *row,
    gpointer user_data)
{
  PublishEffectContext *context = user_data;
  WylFactArtifactMainTransitionRequest request = { 0 };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation observation = { 0 };
  wyrelog_error_t rc = publish_capture (context, row, &request,
          &snapshot, &observation);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  WylFactArtifactMainTransitionResult result = { 0 };
  rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
          &observation, &result, &transition);
  if (rc != WYRELOG_E_OK || transition == NULL)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;

  if (context->target == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH
      && result.state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED) {
    const WylFactArtifactMainTransitionOp prerequisites[] = {
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
    };
    for (guint i = 0; i < G_N_ELEMENTS (prerequisites); i++) {
      WylFactArtifactMainTransitionOp operation = prerequisites[i];
      if (result.next_op != operation)
        return WYRELOG_E_POLICY;
      rc = wyl_fact_artifact_main_transition_authorize (transition,
              operation, &observation, &result);
      WylFactArtifactMainTransitionEffect effect =
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
      WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_artifact_transition_posix_execute_provisioned
              (context->provider, row->old_provisioning_uuid, &request,
                &observation, operation, &effect, &durability);
      WylFactArtifactMainTransitionDurability proven = i == 0
        ? durability.staged_file : i == 1
        ? durability.rollback_file : durability.directory_after_retain;
      if (rc != WYRELOG_E_OK || effect !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
          || proven != WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
        return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
      g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
      WylFactArtifactMainTransitionObservation after = { 0 };
      rc = publish_capture (context, row, &request, &snapshot, &after);
      if (rc != WYRELOG_E_OK)
        return rc;
      after.durability = durability;
      rc = wyl_fact_artifact_main_transition_record (transition, operation,
              effect, &after, &result);
      if (rc != WYRELOG_E_OK || result.state !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED)
        return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
      observation = after;
    }
    if (result.next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH)
      return WYRELOG_E_POLICY;
    rc = wyl_fact_artifact_main_transition_authorize (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
            &observation, &result);
    WylFactArtifactMainTransitionEffect rename_effect =
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    WylFactArtifactMainTransitionDurabilityEvidence rename_durability = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_transition_posix_execute_provisioned
            (context->provider, row->old_provisioning_uuid, &request,
              &observation, WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
              &rename_effect, &rename_durability);
    if (rc != WYRELOG_E_OK || rename_effect !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
      return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
    if (publish_checkpoint != NULL) {
      rc = publish_checkpoint ("restore-publish-after-rename",
              publish_checkpoint_data);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
#endif
    g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
    WylFactArtifactMainTransitionObservation after = { 0 };
    rc = publish_capture (context, row, &request, &snapshot, &after);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_main_transition_record (transition,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH, rename_effect,
              &after, &result);
    if (rc != WYRELOG_E_OK || result.state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED)
      return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    observation = after;
  } else if (result.state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED)
    return WYRELOG_E_POLICY;

  if (result.next_op !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR)
    return WYRELOG_E_POLICY;
  rc = wyl_fact_artifact_main_transition_authorize (transition,
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
          &observation, &result);
  WylFactArtifactMainTransitionEffect sync_effect =
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
  WylFactArtifactMainTransitionDurabilityEvidence sync_durability = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_execute_provisioned
          (context->provider, row->old_provisioning_uuid, &request,
            &observation,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
            &sync_effect, &sync_durability);
  if (rc != WYRELOG_E_OK || sync_effect !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED
      || sync_durability.directory_after_publish !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN)
    return rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : rc;
#ifdef WYL_TEST_HANDLE_SEAMS
  if (publish_checkpoint != NULL) {
    rc = publish_checkpoint ("restore-publish-after-fsync",
            publish_checkpoint_data);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
#endif
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  WylFactArtifactMainTransitionObservation after_sync = { 0 };
  rc = publish_capture (context, row, &request, &snapshot, &after_sync);
  if (rc != WYRELOG_E_OK)
    return rc;
  after_sync.durability = sync_durability;
  rc = wyl_fact_artifact_main_transition_record (transition,
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
          sync_effect, &after_sync, &result);
  if (rc != WYRELOG_E_OK || result.state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  rc = publish_capture (context, row, &request, &snapshot, &observation);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (WylFactArtifactMainTransition) verified = NULL;
  WylFactArtifactMainTransitionResult verified_result = { 0 };
  rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
          &observation, &verified_result, &verified);
  return rc == WYRELOG_E_OK && verified_result.state ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
    ? WYRELOG_E_OK : (rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc);
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_publish_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  WylFactArtifactTransitionPosix *provider = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  if (rc == WYRELOG_E_OK) {
    const WylFactOfflineRestoreJournalGraph *graph =
        journal.graphs != NULL && journal.graphs->len == 1
        ? g_ptr_array_index (journal.graphs, 0) : NULL;
    if (journal.revision != expected_revision
        || !(graph != NULL
        && journal.version == WYL_FACT_OFFLINE_RESTORE_JOURNAL_HANDOFF_VERSION
        && journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        && journal.confirmation == WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
        && journal.manifest_trust == WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
        && !journal.policy_generation_published
        && !journal.lifecycle_handoff_complete
        && row != NULL && g_str_equal (row->phase, "reserved")
        && ((graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
        && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH)
        || (graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
        && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR))
        && (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
        ? graph->pending_op == graph->next_op
        : graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
        && graph->copied && graph->checksum_verified
        && graph->identity_verified && graph->schema_verified
        && graph->replay_preflighted && !graph->resume_forbidden
        && identity_present (&graph->expected_main_identity)
        && identity_present (&graph->staged_main_identity)
        && g_strcmp0 (graph->old_provisioning_uuid,
        row->old_provisioning_uuid) == 0
        && g_strcmp0 (graph->store_uuid, row->store_uuid) == 0))
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (policy, &journal, row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, FALSE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
  WylFactArtifactTransitionPosixCapability capability = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_probe_capability (&directory,
            operation_uuid, &capability);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_open (&resolver, &directory,
            lease, operation_uuid, &capability, &provider);
  if (rc == WYRELOG_E_OK)
    rc = check_persisted (policy, operation_uuid, encoded, row, &journal);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  WylFactOfflineRestoreJournalGraph *graph = rc == WYRELOG_E_OK
    ? g_ptr_array_index (journal.graphs, 0) : NULL;
  WylFactArtifactMainTransitionOp operation = rc == WYRELOG_E_OK
    ? graph->next_op : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  if (rc == WYRELOG_E_OK
      && graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
    rc = early_commit_begin (policy, &journal, operation);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && publish_checkpoint != NULL)
    rc = publish_checkpoint ("restore-publish-after-begin",
            publish_checkpoint_data);
#endif
  if (rc == WYRELOG_E_OK) {
    g_clear_pointer (&encoded, g_bytes_unref);
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  }
  /* The filesystem effect is authorized by the pinned policy transaction. */
  if (rc == WYRELOG_E_OK) {
    g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
    rc = wyl_fact_offline_restore_journal_decode (encoded, &desired);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_complete_attempt (&desired,
              journal.selected_graph_id,
              operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH
              ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
              : WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE,
              operation == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH
              ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR
              : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE, FALSE);
    g_autoptr (GBytes) desired_bytes = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&desired,
              &desired_bytes);
    if (rc == WYRELOG_E_OK) {
      WylPolicyOfflineRestoreRecord pending = {
        .operation_uuid = journal.operation_uuid,
        .tenant_id = journal.tenant_id,
        .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH,
        .selected_graph_id = journal.selected_graph_id,
        .revision = journal.revision,
        .graph_count = 1,
        .journal_blob = encoded,
      };
      memcpy (pending.manifest_sha256, journal.manifest_sha256, 32);
      WylPolicyOfflineRestoreRecord completed = pending;
      completed.revision = desired.revision;
      completed.journal_blob = desired_bytes;
      PublishEffectContext context = { provider, &journal, operation };
      WylPolicyOfflineRestoreStoreResult result =
          WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
      rc = wyl_policy_store_graph_restore_publish_with_effect
            (policy, row, &pending, &completed, operation,
              publish_effect, &context, &result);
      if (rc == WYRELOG_E_OK
          && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
        rc = WYRELOG_E_BUSY;
      if (rc == WYRELOG_E_OK) {
        *out_committed = desired;
        memset (&desired, 0, sizeof desired);
      }
    }
  }
  wyl_fact_artifact_transition_posix_free (provider);
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  WylFactGraphResolver *resolver;
  WylFactGraphDirectory *directory;
  WylFactRootWriterLease *lease;
  WylFactGraphRuntimeManager *runtime;
  WylFactGraphKey *key;
  const WylFactOfflineRestoreJournal *journal;
} FinalizeEffectContext;

static wyrelog_error_t
finalize_selected_effect
  (const WylPolicyGraphRestoreReplacementRecord *row, gpointer user_data)
{
  FinalizeEffectContext *context = user_data;
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (context->journal->graphs, 0);
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (context->lease, context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (context->runtime, context->key);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_selected_cleanup_execute
          (context->resolver, context->directory, context->lease,
            row->old_provisioning_uuid, row->operation_uuid,
            row->replacement_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity);
  return rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_finalize_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) pending = { 0 };
  g_auto (WylFactOfflineRestoreJournal) completed = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  g_autoptr (GBytes) pending_bytes = NULL;
  g_autoptr (GBytes) completed_bytes = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  const WylFactOfflineRestoreJournalGraph *graph =
      journal.graphs != NULL && journal.graphs->len == 1
      ? g_ptr_array_index (journal.graphs, 0) : NULL;
  gboolean fresh = graph != NULL
      && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED;
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION
      || !journal.replacement_selected_pending_cleanup
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete
      || graph == NULL || row == NULL
      || !g_str_equal (row->phase, "selected_pending_cleanup")
      || graph->transition_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
      || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
      || (fresh
      ? graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
      : graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
      || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE)
      || g_strcmp0 (journal.operation_uuid, row->operation_uuid) != 0
      || g_strcmp0 (journal.tenant_id, row->tenant_id) != 0
      || g_strcmp0 (journal.selected_graph_id, row->graph_id) != 0
      || g_strcmp0 (graph->graph_id, row->graph_id) != 0
      || g_strcmp0 (graph->store_uuid, row->store_uuid) != 0
      || g_strcmp0 (graph->old_provisioning_uuid,
      row->old_provisioning_uuid) != 0
      || journal.destination_tenant_lifecycle_generation !=
      row->tenant_lifecycle_generation
      || journal.destination_tenant_reconciliation_generation !=
      row->tenant_reconciliation_generation
      || graph->destination_lifecycle_generation !=
      row->graph_lifecycle_generation
      || graph->destination_reconciliation_generation !=
      row->graph_reconciliation_generation))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, TRUE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK) {
    directory.checkpoint = finalize_checkpoint;
    directory.checkpoint_data = finalize_checkpoint_data;
  }
#endif
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  WylFactGraphRestoreSelectedCleanupShape shape =
      WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_selected_cleanup_shape_open (&resolver,
            &directory, lease, row->old_provisioning_uuid, operation_uuid,
            row->replacement_uuid, &graph->expected_main_identity,
            &graph->staged_main_identity, &shape);
  if (rc == WYRELOG_E_OK && fresh
      && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_DUAL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (encoded, &pending);
  if (rc == WYRELOG_E_OK && fresh)
    rc = wyl_fact_offline_restore_journal_begin_attempt (&pending,
            pending.selected_graph_id,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&pending,
            &pending_bytes);
  if (rc == WYRELOG_E_OK && fresh) {
    WylPolicyOfflineRestoreRecord before = {
      .operation_uuid = journal.operation_uuid,
      .tenant_id = journal.tenant_id,
      .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH,
      .selected_graph_id = journal.selected_graph_id,
      .revision = journal.revision,
      .graph_count = 1,
      .journal_blob = encoded,
    };
    memcpy (before.manifest_sha256, journal.manifest_sha256, 32);
    WylPolicyOfflineRestoreRecord after = before;
    after.revision = pending.revision;
    after.journal_blob = pending_bytes;
    WylPolicyOfflineRestoreStoreResult result =
        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    rc = wyl_policy_store_graph_restore_selected_finalize_begin (policy,
            row, &before, &after, &result);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (pending_bytes, &completed);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_complete_attempt (&completed,
            completed.selected_graph_id,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE, TRUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&completed,
            &completed_bytes);
  if (rc == WYRELOG_E_OK) {
    WylPolicyOfflineRestoreRecord before = {
      .operation_uuid = pending.operation_uuid,
      .tenant_id = pending.tenant_id,
      .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH,
      .selected_graph_id = pending.selected_graph_id,
      .revision = pending.revision,
      .graph_count = 1,
      .journal_blob = pending_bytes,
    };
    memcpy (before.manifest_sha256, pending.manifest_sha256, 32);
    WylPolicyOfflineRestoreRecord after = before;
    after.revision = completed.revision;
    after.journal_blob = completed_bytes;
    FinalizeEffectContext effect = { &resolver, &directory, lease,
                                     runtime, &key, &pending };
    WylPolicyOfflineRestoreStoreResult result =
        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    rc = wyl_policy_store_graph_restore_selected_finalize_with_effect
          (policy, row, &before, &after, finalize_selected_effect,
            &effect, &result);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK) {
      *out_committed = completed;
      memset (&completed, 0, sizeof completed);
    }
  }
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

#ifdef __linux__
typedef struct
{
  WylFactGraphResolver *resolver;
  WylFactGraphDirectory *directory;
  WylFactRootWriterLease *lease;
  WylFactGraphRuntimeManager *runtime;
  WylFactGraphKey *key;
  const WylFactOfflineRestoreJournalGraph *graph;
} PromoteEffectContext;

static wyrelog_error_t
promote_selected_terminal_effect
  (const WylPolicyGraphRestoreReplacementRecord *row, gpointer user_data)
{
  PromoteEffectContext *context = user_data;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (context->lease, context->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (context->runtime, context->key);
  WylFactGraphRestoreSelectedCleanupShape shape =
      WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_INVALID;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_selected_cleanup_shape_open
          (context->resolver, context->directory, context->lease,
            row->old_provisioning_uuid, row->operation_uuid,
            row->replacement_uuid, &context->graph->expected_main_identity,
            &context->graph->staged_main_identity, &shape);
  if (rc == WYRELOG_E_OK
      && shape != WYL_FACT_GRAPH_RESTORE_SELECTED_CLEANUP_TERMINAL)
    rc = WYRELOG_E_POLICY;
  return rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_promote_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || expected_revision == 0
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphKey key = { 0 };
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load (policy,
            operation_uuid, &row);
  const WylFactOfflineRestoreJournalGraph *graph =
      journal.graphs != NULL && journal.graphs->len == 1
      ? g_ptr_array_index (journal.graphs, 0) : NULL;
  if (rc == WYRELOG_E_OK
      && (journal.revision != expected_revision
      || journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || !journal.replacement_selected_pending_cleanup
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete || graph == NULL || row == NULL
      || !g_str_equal (row->phase, "selected_pending_cleanup")
      || graph->transition_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
      || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
      || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
      || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
      || !graph->transition_terminal || !graph->replay_preflighted
      || g_strcmp0 (journal.operation_uuid, row->operation_uuid) != 0
      || g_strcmp0 (journal.tenant_id, row->tenant_id) != 0
      || g_strcmp0 (journal.selected_graph_id, row->graph_id) != 0
      || g_strcmp0 (graph->graph_id, row->graph_id) != 0
      || g_strcmp0 (graph->store_uuid, row->store_uuid) != 0
      || g_strcmp0 (graph->old_provisioning_uuid,
      row->old_provisioning_uuid) != 0
      || journal.destination_tenant_lifecycle_generation !=
      row->tenant_lifecycle_generation
      || journal.destination_tenant_reconciliation_generation !=
      row->tenant_reconciliation_generation
      || graph->destination_lifecycle_generation !=
      row->graph_lifecycle_generation
      || graph->destination_reconciliation_generation !=
      row->graph_reconciliation_generation))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = graph_commit_quiesce (policy, lease, &resolver, runtime,
            operation_uuid, encoded, row, TRUE, &key, drain_timeout_us,
            &quiescence);
  WylFactGraphLocator locator = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal.tenant_id,
            journal.selected_graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  wyl_fact_graph_locator_clear (&locator);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (runtime, &key);
  PromoteEffectContext effect = { &resolver, &directory, lease,
                                  runtime, &key, graph };
  if (rc == WYRELOG_E_OK)
    rc = promote_selected_terminal_effect (row, &effect);
  if (rc == WYRELOG_E_OK) {
    WylPolicyOfflineRestoreRecord before = {
      .operation_uuid = journal.operation_uuid,
      .tenant_id = journal.tenant_id,
      .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH,
      .selected_graph_id = journal.selected_graph_id,
      .revision = journal.revision,
      .graph_count = 1,
      .journal_blob = encoded,
    };
    memcpy (before.manifest_sha256, journal.manifest_sha256, 32);
    WylPolicyOfflineRestoreStoreResult result =
        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    rc = wyl_policy_store_graph_restore_selected_promote_with_effect
          (policy, row, &before, promote_selected_terminal_effect,
            &effect, &result);
    if (rc == WYRELOG_E_OK
        && result != WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_mark_policy_published (&journal);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_mark_lifecycle_handoff (&journal);
    if (rc == WYRELOG_E_OK) {
      *out_committed = journal;
      memset (&journal, 0, sizeof journal);
    }
  }
  wyl_fact_graph_directory_clear (&directory);
  g_clear_pointer (&quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_policy_graph_restore_replacement_record_free (row);
  return rc;
#endif
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-restore-rollback-private.h"

#include <string.h>

#include "fact/graph-artifact-transition-posix-private.h"
#ifdef __APPLE__
#include "fact/graph-locator-darwin-private.h"
#endif
#include "fact/offline-restore-journal-store-private.h"
#include "fact/root-writer-lease-private.h"

#ifndef G_OS_WIN32
#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*rollback_checkpoint)
  (WylFactOfflineRestoreRollbackCheckpoint, gpointer);
static gpointer rollback_checkpoint_data;

void
wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint)
    (WylFactOfflineRestoreRollbackCheckpoint point, gpointer user_data),
    gpointer user_data)
{
  rollback_checkpoint = checkpoint;
  rollback_checkpoint_data = user_data;
}

static wyrelog_error_t
run_checkpoint (WylFactOfflineRestoreRollbackCheckpoint point)
{
  return rollback_checkpoint == NULL ? WYRELOG_E_OK
    : rollback_checkpoint (point, rollback_checkpoint_data);
}
#endif

typedef struct
{
  wyl_policy_store_t *policy;
  WylFactGraphRuntimeManager *runtime;
  WylFactOfflineRestoreJournal journal;
  WylFactRootWriterLease *lease;
  WylFactGraphResolver resolver;
  WylFactGraphKey key;
  WylFactGraphQuiescenceToken *quiescence;
  WylFactGraphDirectory directory;
  WylFactGraphProvisionedPair *pair;
  gchar *provisioning_uuid;
  WylFactArtifactTransitionPosix *provider;
  guint selected_index;
} GraphRollback;

static WylFactOfflineRestoreJournalGraph *
selected_graph (GraphRollback *rollback)
{
  return g_ptr_array_index (rollback->journal.graphs, rollback->selected_index);
}

static void
rollback_graph_resources_clear (GraphRollback *rollback)
{
  g_clear_pointer (&rollback->provider, wyl_fact_artifact_transition_posix_free);
  g_clear_pointer (&rollback->pair, wyl_fact_graph_provisioned_pair_free);
  g_clear_pointer (&rollback->provisioning_uuid, g_free);
  wyl_fact_graph_directory_clear (&rollback->directory);
  g_clear_pointer (&rollback->quiescence,
      wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&rollback->key);
}

static void
rollback_clear (GraphRollback *rollback)
{
  rollback_graph_resources_clear (rollback);
  wyl_fact_graph_resolver_clear (&rollback->resolver);
  g_clear_pointer (&rollback->lease, wyl_fact_root_writer_lease_release);
  wyl_fact_offline_restore_journal_clear (&rollback->journal);
}

static wyrelog_error_t
check_policy (GraphRollback *rollback)
{
  const WylFactOfflineRestoreJournal *journal = &rollback->journal;
  const WylFactOfflineRestoreJournalGraph *expected = selected_graph (rollback);
  WylPolicyFactBackupSnapshot *snapshot = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_fact_graph_backup_snapshot
        (rollback->policy, journal->tenant_id, expected->graph_id, &snapshot);
  if (rc == WYRELOG_E_OK) {
    if (snapshot->tenant == NULL || snapshot->graphs == NULL
        || snapshot->graphs->len != 1
        || g_strcmp0 (snapshot->tenant->tenant_id, journal->tenant_id) != 0
        || snapshot->tenant->lifecycle_state != WYL_POLICY_TENANT_LIFECYCLE_SEALED
        || !snapshot->tenant->sealed_compatibility
        || snapshot->tenant->lifecycle_generation
        != journal->destination_tenant_lifecycle_generation
        || snapshot->tenant->reconciliation_generation
        != journal->destination_tenant_reconciliation_generation)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK) {
    const WylPolicyFactBackupGraphSnapshot *current
      = g_ptr_array_index (snapshot->graphs, 0);
    const WylPolicyGraphAuthorityRecord *record
      = current == NULL ? NULL : current->authority;
    if (record == NULL
        || g_strcmp0 (record->tenant_id, journal->tenant_id) != 0
        || g_strcmp0 (record->graph_id, expected->graph_id) != 0
        || record->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED
        || !record->sealed_compatibility || !record->has_store_identity
        || record->materialization_state
        != WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED
        || record->last_error_class != WYL_POLICY_GRAPH_ERROR_NONE
        || record->lifecycle_generation
        != expected->destination_lifecycle_generation
        || record->reconciliation_generation
        != expected->destination_reconciliation_generation
        || g_strcmp0 (record->store_uuid, expected->store_uuid) != 0
        || record->format_version != expected->format_version
        || record->path_encoding_version != expected->path_encoding_version
        || g_strcmp0 (current->active_schema_digest,
        expected->schema_digest) != 0)
      rc = WYRELOG_E_POLICY;
  }
  g_clear_pointer (&snapshot, wyl_policy_fact_backup_snapshot_free);
  return rc;
}

static wyrelog_error_t
check_runtime (GraphRollback *rollback)
{
  WylFactGraphRuntimeStatus status = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_runtime_manager_get_status
        (rollback->runtime, &rollback->key, &status);
  if (rc == WYRELOG_E_OK
      && (rollback->quiescence == NULL
      || status.state == WYL_FACT_GRAPH_RUNTIME_ABANDONED
      || status.admission != WYL_FACT_GRAPH_ADMISSION_CLOSED
      || status.operation_active || status.active_engine_calls != 0
      || status.waiting_engine_calls != 0))
    rc = WYRELOG_E_BUSY;
  wyl_fact_graph_runtime_status_clear (&status);
  return rc;
}

static wyrelog_error_t
open_active_pair (GraphRollback *rollback)
{
  const WylFactOfflineRestoreJournalGraph *graph = selected_graph (rollback);
  if (graph->expected_main_absent)
    return WYRELOG_E_OK;
  g_autoptr (GPtrArray) records = NULL;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list_for_graph
        (rollback->policy, rollback->journal.tenant_id, graph->graph_id,
          &records);
  const WylPolicyGraphProvisioningRecord *selected = NULL;
  for (guint i = 0; rc == WYRELOG_E_OK && i < records->len; i++) {
    const WylPolicyGraphProvisioningRecord *record
      = g_ptr_array_index (records, i);
    if (record->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE)
      continue;
    if (selected != NULL
        || g_strcmp0 (record->tenant_id, rollback->journal.tenant_id) != 0
        || g_strcmp0 (record->graph_id, graph->graph_id) != 0
        || g_strcmp0 (record->store_uuid, graph->store_uuid) != 0)
      return WYRELOG_E_POLICY;
    selected = record;
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  if (selected == NULL)
    return WYRELOG_E_POLICY;
#ifdef __APPLE__
  if (selected->darwin_operation_evidence == NULL)
    return WYRELOG_E_POLICY;
  gsize evidence_size = 0;
  const guint8 *evidence_bytes = g_bytes_get_data
        (selected->darwin_operation_evidence, &evidence_size);
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  rc = wyl_fact_graph_darwin_evidence_decode (evidence_bytes, evidence_size,
          selected->op_uuid, &evidence);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
          (&rollback->directory, selected->op_uuid, &evidence,
            &rollback->pair);
#else
  rc = wyl_fact_graph_directory_open_provisioned_pair_exact
        (&rollback->directory, selected->op_uuid, &rollback->pair);
#endif
  if (rc == WYRELOG_E_OK)
    rollback->provisioning_uuid = g_strdup (selected->op_uuid);
  return rc;
}

static wyrelog_error_t
check_provisioning (GraphRollback *rollback)
{
  if (rollback->provisioning_uuid == NULL)
    return WYRELOG_E_OK;
  const WylFactOfflineRestoreJournalGraph *graph = selected_graph (rollback);
  g_autoptr (GPtrArray) records = NULL;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list_for_graph
        (rollback->policy, rollback->journal.tenant_id, graph->graph_id,
          &records);
  guint active = 0;
  for (guint i = 0; rc == WYRELOG_E_OK && i < records->len; i++) {
    const WylPolicyGraphProvisioningRecord *record
      = g_ptr_array_index (records, i);
    if (record->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE)
      continue;
    active++;
    if (g_strcmp0 (record->op_uuid, rollback->provisioning_uuid) != 0
        || g_strcmp0 (record->store_uuid, graph->store_uuid) != 0)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK && active != 1)
    rc = WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
check_journal (GraphRollback *rollback)
{
  WylFactOfflineRestoreJournal current = { 0 };
  g_autoptr (GBytes) expected_bytes = NULL;
  g_autoptr (GBytes) current_bytes = NULL;
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load
        (rollback->policy, rollback->journal.operation_uuid, &current);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&rollback->journal,
            &expected_bytes);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&current, &current_bytes);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (expected_bytes, current_bytes))
    rc = WYRELOG_E_BUSY;
  wyl_fact_offline_restore_journal_clear (&current);
  return rc;
}

static wyrelog_error_t
check_current (GraphRollback *rollback)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (rollback->lease, &rollback->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (rollback);
  if (rc == WYRELOG_E_OK)
    rc = check_runtime (rollback);
  if (rc == WYRELOG_E_OK)
    rc = check_provisioning (rollback);
  if (rc == WYRELOG_E_OK && rollback->pair != NULL)
    rc = wyl_fact_graph_provisioned_pair_revalidate_in_directory
          (rollback->pair, &rollback->directory);
  if (rc == WYRELOG_E_OK)
    rc = check_journal (rollback);
  return rc;
}

typedef enum
{
  ROLLBACK_DECIDE,
  ROLLBACK_BEGIN,
  ROLLBACK_NOT_APPLIED,
  ROLLBACK_COMPLETE,
} RollbackChange;

static wyrelog_error_t
cas_change (GraphRollback *rollback, RollbackChange change)
{
  wyrelog_error_t rc = check_current (rollback);
  g_autoptr (GBytes) source = NULL;
  WylFactOfflineRestoreJournal desired = { 0 };
  WylFactOfflineRestoreJournal committed = { 0 };
  g_autoptr (GBytes) desired_bytes = NULL;
  g_autoptr (GBytes) committed_bytes = NULL;
  WylFactOfflineRestoreStoreResult result
    = WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&rollback->journal, &source);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (source, &desired);
  if (rc == WYRELOG_E_OK) {
    const gchar *graph_id = selected_graph (rollback)->graph_id;
    switch (change) {
      case ROLLBACK_DECIDE:
        rc = wyl_fact_offline_restore_journal_decide (&desired,
                WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK);
        break;
      case ROLLBACK_BEGIN:
        rc = wyl_fact_offline_restore_journal_begin_attempt (&desired,
                graph_id, WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE);
        break;
      case ROLLBACK_NOT_APPLIED:
        rc = wyl_fact_offline_restore_journal_record_not_applied (&desired,
                graph_id, WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE);
        break;
      case ROLLBACK_COMPLETE:
        rc = wyl_fact_offline_restore_journal_complete_attempt (&desired,
                graph_id, WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED,
                WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE, TRUE);
        break;
    }
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&desired, &desired_bytes);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && change == ROLLBACK_DECIDE)
    rc = run_checkpoint (WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_DECISION_CAS);
#endif
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_cas (rollback->policy,
            rollback->journal.revision, &desired, &result, &committed);
  if (rc == WYRELOG_E_OK && result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&committed,
            &committed_bytes);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (desired_bytes, committed_bytes))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    wyl_fact_offline_restore_journal_clear (&rollback->journal);
    rollback->journal = committed;
    memset (&committed, 0, sizeof committed);
  }
  wyl_fact_offline_restore_journal_clear (&desired);
  wyl_fact_offline_restore_journal_clear (&committed);
  return rc;
}

static WylFactArtifactMainTransitionRequest
request_for (GraphRollback *rollback,
    const WylFactArtifactMainTransitionObservation *observation)
{
  const WylFactOfflineRestoreJournalGraph *graph = selected_graph (rollback);
  WylFactArtifactMainTransitionRequest request = {
    .operation_uuid = rollback->journal.operation_uuid,
    .directory_identity = observation->directory_identity,
    .lease_identity = observation->lease_identity,
    .expected_main_absent = graph->expected_main_absent,
    .expected_main_identity = graph->expected_main_identity,
    .staged_main_identity = graph->staged_main_identity,
    .resume_forbidden = TRUE,
  };
  return request;
}

static wyrelog_error_t
recover_absent_callback (gpointer user_data)
{
  GraphRollback *rollback = user_data;
  WylFactOfflineRestoreJournalGraph *graph = selected_graph (rollback);
  if (rollback->journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK
      || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE
      || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
    return WYRELOG_E_POLICY;
#ifdef WYL_TEST_HANDLE_SEAMS
  wyrelog_error_t rc = run_checkpoint
        (WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_COMPLETE);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif
  return cas_change (rollback, ROLLBACK_COMPLETE);
}

static wyrelog_error_t
recover_unbound_callback (gpointer user_data)
{
  GraphRollback *rollback = user_data;
  const WylFactOfflineRestoreJournalGraph *graph = selected_graph (rollback);
  if (graph->staged_main_identity.domain != 0
      || graph->staged_main_identity.object != 0)
    return WYRELOG_E_POLICY;
  if (rollback->journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK)
    return graph->transition_state ==
           WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED
      ? check_current (rollback) : WYRELOG_E_POLICY;
  if (rollback->journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE)
    return WYRELOG_E_POLICY;
  return cas_change (rollback, ROLLBACK_DECIDE);
}

static wyrelog_error_t
open_provider (GraphRollback *rollback)
{
  WylFactArtifactTransitionPosixCapability capability = { 0 };
  wyrelog_error_t rc = wyl_fact_artifact_transition_posix_probe_capability
        (&rollback->directory, rollback->journal.operation_uuid,
          &capability);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_open (&rollback->resolver,
            &rollback->directory, rollback->lease,
            rollback->journal.operation_uuid, &capability,
            &rollback->provider);
  return rc;
}

static wyrelog_error_t
recover_unbound (GraphRollback *rollback)
{
  wyrelog_error_t rc = open_provider (rollback);
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  WylFactArtifactMainTransitionObservation observation = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_observe (rollback->provider,
            &lifecycle, &observation);
  if (rc == WYRELOG_E_OK) {
    WylFactArtifactMainTransitionRequest request = request_for (rollback,
            &observation);
    rc = wyl_fact_artifact_transition_posix_with_unbound_absence
          (rollback->provider, rollback->pair, &request, &lifecycle,
            recover_unbound_callback, rollback);
  }
  return rc;
}

static wyrelog_error_t
retire_stage (GraphRollback *rollback)
{
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation before = { 0 };
  wyrelog_error_t rc = check_current (rollback);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture (rollback->provider,
            &lifecycle, &snapshot, &before);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactArtifactMainTransitionRequest request = request_for (rollback,
          &before);
#ifndef __APPLE__
  if (rollback->pair != NULL) {
    WylFactArtifactMainTransitionEffect effect
      = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    rc = wyl_fact_artifact_transition_posix_with_ready_provisioned_retire
          (rollback->provider, rollback->pair, &request, &lifecycle,
            recover_absent_callback, rollback, &effect);
    if (effect == WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED) {
      wyrelog_error_t record_rc = cas_change (rollback,
              ROLLBACK_NOT_APPLIED);
      return record_rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : record_rc;
    }
    return rc;
  }
#endif
  if (!before.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE].present)
    return wyl_fact_artifact_transition_posix_with_retired_stage_recovery
             (rollback->provider, &request, &lifecycle,
               recover_absent_callback, rollback);

  WylFactArtifactMainTransitionResult result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  rc = wyl_fact_artifact_main_transition_admit (&request, snapshot,
          &before, &result, &transition);
  if (rc != WYRELOG_E_OK || transition == NULL
      || result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  rc = wyl_fact_artifact_main_transition_authorize (transition,
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE, &before,
          &result);
  if (rc != WYRELOG_E_OK || result.refusal
      != WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  rc = check_current (rollback);
  WylFactArtifactMainTransitionEffect effect
    = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_execute (rollback->provider,
            &before, WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE,
            &effect, &durability);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (effect == WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED)
    return cas_change (rollback, ROLLBACK_NOT_APPLIED);
  if (effect != WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
    return WYRELOG_E_BUSY;

  WylFactArtifactMainTransitionObservation after = { 0 };
  rc = wyl_fact_artifact_transition_posix_observe (rollback->provider,
          &lifecycle, &after);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_main_transition_record (transition,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE, effect,
            &after, &result);
  if (rc != WYRELOG_E_OK || result.refusal
      != WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE
      || result.state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED
      || !result.terminal)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  return cas_change (rollback, ROLLBACK_COMPLETE);
}

static wyrelog_error_t
verify_completed_stage_absent (GraphRollback *rollback)
{
  wyrelog_error_t rc = rollback->provider == NULL
    ? open_provider (rollback) : WYRELOG_E_OK;
  WylFactArtifactTransitionPosixLifecycle lifecycle = {
    .sealed = TRUE, .main_binding_live = FALSE,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactMainTransitionObservation observation = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_transition_posix_capture (rollback->provider,
            &lifecycle, &snapshot, &observation);
  if (rc == WYRELOG_E_OK)
    rc = check_current (rollback);
  if (rc == WYRELOG_E_OK) {
    const WylFactOfflineRestoreJournalGraph *graph = selected_graph (rollback);
    const WylFactArtifactMainTransitionEntryEvidence *main =
        &observation.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN];
    if (observation.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE].present
        || observation.entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK].present
        || main->present == graph->expected_main_absent
        || (main->present && !wyl_fact_artifact_inventory_identity_equal
          (&main->identity, &graph->expected_main_identity)))
      rc = WYRELOG_E_POLICY;
  }
  return rc;
}
#endif

static wyrelog_error_t
rollback_one_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    guint64 expected_revision, guint selected_index, gboolean tenant_scope,
    gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || operation_uuid == NULL
      || *operation_uuid == '\0' || expected_revision == 0
      || expected_revision >= G_MAXINT64 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  GraphRollback rollback = {
    .policy = policy, .runtime = runtime_manager,
    .selected_index = selected_index,
    .resolver = WYL_FACT_GRAPH_RESOLVER_INIT,
    .directory = WYL_FACT_GRAPH_DIRECTORY_INIT,
  };
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root,
          &rollback.lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root,
            rollback.lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy, operation_uuid,
            &rollback.journal);
  if (rc == WYRELOG_E_OK && rollback.journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (rollback.journal.scope != (tenant_scope ?
      WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT :
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
      || rollback.journal.graphs == NULL
      || selected_index >= rollback.journal.graphs->len
      || (!tenant_scope && (rollback.journal.graphs->len != 1
      || g_strcmp0 (rollback.journal.selected_graph_id,
      selected_graph (&rollback)->graph_id) != 0))
      || (tenant_scope && rollback.journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION
      && rollback.journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION)
      || rollback.journal.confirmation
      != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || rollback.journal.manifest_trust
      != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || rollback.journal.policy_generation_published
      || rollback.journal.lifecycle_handoff_complete
      || rollback.journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = check_policy (&rollback);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &rollback.resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&rollback.key, rollback.journal.tenant_id,
            selected_graph (&rollback)->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce (runtime_manager,
            &rollback.key, drain_timeout_us, &rollback.quiescence);
  if (rc == WYRELOG_E_NOT_FOUND) {
    rc = wyl_fact_root_writer_lease_authorizes_resolver (rollback.lease,
            &rollback.resolver);
    if (rc == WYRELOG_E_OK)
      rc = check_policy (&rollback);
    if (rc == WYRELOG_E_OK)
      rc = check_journal (&rollback);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed
            (runtime_manager, &rollback.key, drain_timeout_us,
              &rollback.quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_root_writer_lease_authorizes_resolver (rollback.lease,
              &rollback.resolver);
    if (rc == WYRELOG_E_OK)
      rc = check_policy (&rollback);
    if (rc == WYRELOG_E_OK)
      rc = check_journal (&rollback);
    if (rc != WYRELOG_E_OK)
      g_clear_pointer (&rollback.quiescence,
          wyl_fact_graph_quiescence_token_release);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
            rollback.journal.tenant_id,
            selected_graph (&rollback)->graph_id, FALSE,
            &rollback.directory);
  if (rc == WYRELOG_E_OK)
    rc = check_current (&rollback);
  if (rc == WYRELOG_E_OK)
    rc = open_active_pair (&rollback);
  gboolean unbound = rc == WYRELOG_E_OK
      && selected_graph (&rollback)->staged_main_identity.domain == 0
      && selected_graph (&rollback)->staged_main_identity.object == 0;
  if (rc == WYRELOG_E_OK && unbound)
    rc = recover_unbound (&rollback);
  if (rc == WYRELOG_E_OK && !unbound
      && rollback.journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_NONE)
    rc = cas_change (&rollback, ROLLBACK_DECIDE);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && !unbound && rollback.journal.revision
      == expected_revision + 1)
    rc = run_checkpoint (WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_DECISION);
#endif
  gboolean needs_cleanup = rc == WYRELOG_E_OK && !unbound
      && selected_graph (&rollback)->transition_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
  if (rc == WYRELOG_E_OK
      && needs_cleanup
      && selected_graph (&rollback)->attempt
      != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
    rc = cas_change (&rollback, ROLLBACK_BEGIN);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK
      && selected_graph (&rollback)->attempt
      == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
      && rollback.journal.revision > expected_revision)
    rc = run_checkpoint (WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_BEGIN);
#endif
  if (rc == WYRELOG_E_OK
      && needs_cleanup) {
    rc = open_provider (&rollback);
    if (rc == WYRELOG_E_OK)
      rc = retire_stage (&rollback);
  }
  if (rc == WYRELOG_E_OK && !unbound && !needs_cleanup)
    rc = verify_completed_stage_absent (&rollback);
  if (rc == WYRELOG_E_OK && selected_graph (&rollback)->transition_state !=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    *out_committed = rollback.journal;
    memset (&rollback.journal, 0, sizeof rollback.journal);
  }
  rollback_clear (&rollback);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_graph_rollback_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  return rollback_one_run (policy, fact_root, runtime_manager,
             operation_uuid, expected_revision, 0, FALSE,
             drain_timeout_us, out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_rollback_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || operation_uuid == NULL
      || *operation_uuid == '\0' || expected_revision == 0
      || expected_revision >= G_MAXINT64 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  g_auto (WylFactOfflineRestoreJournal) current = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (policy,
          operation_uuid, &current);
  if (rc == WYRELOG_E_OK && current.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (current.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || current.graphs == NULL || current.graphs->len == 0
      || (current.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION
      && current.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION)
      || current.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < current.graphs->len; i++) {
    g_auto (WylFactOfflineRestoreJournal) step = { 0 };
    rc = rollback_one_run (policy, fact_root, runtime_manager,
            operation_uuid, current.revision, i, TRUE, drain_timeout_us,
            &step);
    if (rc == WYRELOG_E_OK) {
      wyl_fact_offline_restore_journal_clear (&current);
      current = step;
      memset (&step, 0, sizeof step);
    }
  }
  if (rc == WYRELOG_E_OK && wyl_fact_offline_restore_journal_recovery
        (&current) != WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    *out_committed = current;
    memset (&current, 0, sizeof current);
  }
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_rollback_recover_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || operation_uuid == NULL
      || *operation_uuid == '\0' || out_committed == NULL)
    return WYRELOG_E_INVALID;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (policy,
          operation_uuid, &journal);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT)
    return WYRELOG_E_POLICY;
  if (journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT)
    return wyl_fact_offline_restore_tenant_rollback_run (policy, fact_root,
               runtime_manager, operation_uuid, journal.revision,
               drain_timeout_us, out_committed);
  if (journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
    return wyl_fact_offline_restore_graph_rollback_run (policy, fact_root,
               runtime_manager, operation_uuid, journal.revision,
               drain_timeout_us, out_committed);
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_offline_restore_rollback_release_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us)
{
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || operation_uuid == NULL
      || *operation_uuid == '\0' || expected_revision == 0
      || expected_revision >= G_MAXINT64)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  WylFactRootWriterLease *lease = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactOfflineRestoreJournal journal = { 0 };
  GArray *held = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy, operation_uuid,
            &journal);
  if (rc == WYRELOG_E_OK && journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && ((journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      && journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT)
      || journal.graphs == NULL || journal.graphs->len == 0
      || journal.confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal.manifest_trust != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK
      || journal.policy_generation_published || journal.lifecycle_handoff_complete
      || wyl_fact_offline_restore_journal_recovery (&journal)
      != WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    held = g_array_sized_new (FALSE, TRUE, sizeof (GraphRollback),
            journal.graphs->len);
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    GraphRollback graph = {
      .policy = policy, .runtime = runtime_manager, .journal = journal,
      .lease = lease, .resolver = resolver, .selected_index = i,
      .directory = WYL_FACT_GRAPH_DIRECTORY_INIT,
    };
    g_array_append_val (held, graph);
    GraphRollback *current = &g_array_index (held, GraphRollback, i);
    rc = check_policy (current);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_key_init (&current->key, journal.tenant_id,
              selected_graph (current)->graph_id);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce (runtime_manager,
              &current->key, drain_timeout_us, &current->quiescence);
    if (rc == WYRELOG_E_NOT_FOUND) {
      rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
      if (rc == WYRELOG_E_OK)
        rc = check_policy (current);
      if (rc == WYRELOG_E_OK)
        rc = check_journal (current);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed
              (runtime_manager, &current->key, drain_timeout_us,
                &current->quiescence);
    }
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              journal.tenant_id, selected_graph (current)->graph_id, FALSE,
              &current->directory);
    if (rc == WYRELOG_E_OK)
      rc = check_current (current);
    if (rc == WYRELOG_E_OK)
      rc = open_active_pair (current);
    if (rc == WYRELOG_E_OK)
      rc = verify_completed_stage_absent (current);
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK)
    rc = run_checkpoint (WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_RELEASE);
#endif
  for (guint i = 0; rc == WYRELOG_E_OK && i < held->len; i++)
    rc = verify_completed_stage_absent
          (&g_array_index (held, GraphRollback, i));
  if (rc == WYRELOG_E_OK) {
    WylFactOfflineRestoreStoreResult result =
        WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
    rc = wyl_fact_offline_restore_journal_store_release (policy,
            expected_revision, operation_uuid, &result);
    if (rc == WYRELOG_E_OK && result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED)
      rc = result == WYL_FACT_OFFLINE_RESTORE_STORE_NOT_FOUND
        ? WYRELOG_E_NOT_FOUND : WYRELOG_E_BUSY;
#ifdef WYL_TEST_HANDLE_SEAMS
    if (rc == WYRELOG_E_OK)
      rc = run_checkpoint (WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_RELEASE);
#endif
  }
  if (held != NULL) {
    for (guint i = 0; i < held->len; i++)
      rollback_graph_resources_clear (&g_array_index (held, GraphRollback, i));
    g_array_free (held, TRUE);
  }
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_fact_offline_restore_journal_clear (&journal);
  return rc;
#endif
}

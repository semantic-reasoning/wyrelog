/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-commit-authority-private.h"

#include <string.h>

#include "fact/graph-artifact-transition-posix-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/root-writer-lease-private.h"

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*companion_checkpoint) (const gchar *, gpointer);
static gpointer companion_checkpoint_data;
static wyrelog_error_t (*sync_staged_checkpoint) (const gchar *, gpointer);
static gpointer sync_staged_checkpoint_data;

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
    rc = wyl_fact_graph_runtime_manager_quiesce (runtime, &key,
            drain_timeout_us, &quiescence);
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
    rc = wyl_fact_graph_runtime_manager_quiesce (runtime, &key,
            drain_timeout_us, &quiescence);
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
    rc = wyl_fact_graph_runtime_manager_quiesce (runtime, &key,
            drain_timeout_us, &quiescence);
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

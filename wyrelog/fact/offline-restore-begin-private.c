/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-begin-private.h"

#include <string.h>

#include "fact/graph-locator-private.h"
#include "fact/offline-backup-manifest-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/root-writer-lease-private.h"
#include "fact/store-identity-types-private.h"

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylPolicyFactBackupSnapshot,
    wyl_policy_fact_backup_snapshot_free)

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*proof_checkpoint) (gpointer);
static gpointer proof_checkpoint_data;

void
wyl_fact_offline_restore_begin_set_proof_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer), gpointer user_data)
{
  proof_checkpoint = checkpoint;
  proof_checkpoint_data = user_data;
}
#endif

typedef struct
{
  WylFactGraphKey key;
  WylFactGraphQuiescenceToken *quiescence;
  gchar *provisioning_uuid;
  gchar *stage_basename;
  guint64 provisioning_attempt;
  GBytes *darwin_evidence;
  WylFactGraphPreStageInventory inventory;
} BeginGraph;

typedef struct
{
  WylFactRootWriterLease *lease;
  WylFactGraphResolver *resolver;
  WylFactGraphRuntimeManager *runtime;
  WylFactOfflineBackupBundle *bundle;
  const WylPolicyFactBackupSnapshot *initial;
  const GPtrArray *graphs;
} BeginProof;

static void
begin_graph_free (gpointer data)
{
  BeginGraph *graph = data;
  if (graph == NULL)
    return;
  g_clear_pointer (&graph->quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&graph->key);
  g_free (graph->provisioning_uuid);
  g_free (graph->stage_basename);
  g_clear_pointer (&graph->darwin_evidence, g_bytes_unref);
  g_free (graph);
}

static const WylFactOfflineBackupArtifact *
find_artifact (const WylFactOfflineBackupManifest *manifest,
    const gchar *graph_id)
{
  for (guint i = 0; i < manifest->artifacts->len; i++) {
    const WylFactOfflineBackupArtifact *artifact =
        g_ptr_array_index (manifest->artifacts, i);
    if (g_strcmp0 (artifact->graph_id, graph_id) == 0)
      return artifact;
  }
  return NULL;
}

static gboolean
target_matches (const WylPolicyFactBackupSnapshot *snapshot,
    const WylFactOfflineBackupManifest *manifest,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id)
{
  if (snapshot == NULL || snapshot->tenant == NULL
      || snapshot->graphs == NULL || snapshot->graphs->len == 0
      || manifest->version != WYL_FACT_OFFLINE_BACKUP_MANIFEST_VERSION
      || snapshot->tenant->lifecycle_state !=
      WYL_POLICY_TENANT_LIFECYCLE_SEALED
      || !snapshot->tenant->sealed_compatibility
      || g_strcmp0 (snapshot->tenant->tenant_id, manifest->tenant_id) != 0
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && snapshot->graphs->len != manifest->artifacts->len))
    return FALSE;
  for (guint i = 0; i < snapshot->graphs->len; i++) {
    const WylPolicyFactBackupGraphSnapshot *entry =
        g_ptr_array_index (snapshot->graphs, i);
    if (entry == NULL || entry->authority == NULL
        || entry->active_schema_digest == NULL)
      return FALSE;
    const WylPolicyGraphAuthorityRecord *authority = entry->authority;
    const WylFactOfflineBackupArtifact *artifact =
        find_artifact (manifest, authority->graph_id);
    if (artifact == NULL
        || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && g_strcmp0 (authority->graph_id, selected_graph_id) != 0)
        || authority->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED
        || !authority->sealed_compatibility
        || authority->materialization_state !=
        WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED
        || authority->last_error_class != WYL_POLICY_GRAPH_ERROR_NONE
        || !authority->has_store_identity
        || g_strcmp0 (authority->store_uuid, artifact->store_uuid) != 0
        || authority->format_version != artifact->format_version
        || authority->path_encoding_version != artifact->path_encoding_version
        || artifact->format_version != WYL_FACT_STORE_FORMAT_VERSION
        || artifact->path_encoding_version !=
        WYL_FACT_STORE_PATH_ENCODING_VERSION)
      return FALSE;
  }
  return TRUE;
}

static gboolean
provisioning_matches (const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority,
    const BeginGraph *initial)
{
  return record != NULL
         && record->phase == WYL_POLICY_GRAPH_PROVISIONING_ACTIVE
         && g_strcmp0 (record->tenant_id, authority->tenant_id) == 0
         && g_strcmp0 (record->graph_id, authority->graph_id) == 0
         && g_strcmp0 (record->store_uuid, authority->store_uuid) == 0
         && (initial == NULL
         || (g_strcmp0 (record->op_uuid, initial->provisioning_uuid) == 0
         && g_strcmp0 (record->stage_basename,
         initial->stage_basename) == 0
         && record->attempt == initial->provisioning_attempt
         && ((record->darwin_operation_evidence == NULL
         && initial->darwin_evidence == NULL)
         || (record->darwin_operation_evidence != NULL
         && initial->darwin_evidence != NULL
         && g_bytes_equal (record->darwin_operation_evidence,
         initial->darwin_evidence)))));
}

static wyrelog_error_t
observe (WylFactGraphResolver *resolver, WylFactRootWriterLease *lease,
    const WylPolicyGraphAuthorityRecord *authority,
    const WylPolicyGraphProvisioningRecord *provisioning,
    WylFactGraphPreStageInventory *out_inventory)
{
  memset (out_inventory, 0, sizeof *out_inventory);
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphProvisionedPair *pair = NULL;
  WylFactArtifactInventoryIdentity identity = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_locator_init (&locator,
          authority->tenant_id, authority->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (resolver, &locator, FALSE,
            &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            provisioning->op_uuid, &pair);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_provisioned_pair_main_identity (pair, &identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_pre_stage_inventory (resolver, &directory,
            lease, pair, &identity, out_inventory);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  return rc;
}

static gboolean
same_inventory (const WylFactGraphPreStageInventory *a,
    const WylFactGraphPreStageInventory *b)
{
  return a->main_present && b->main_present
         && wyl_fact_artifact_inventory_identity_equal
           (&a->main_identity, &b->main_identity)
         && wyl_fact_artifact_inventory_identity_equal
           (&a->observation.directory_identity,
             &b->observation.directory_identity)
         && wyl_fact_artifact_inventory_identity_equal
           (&a->observation.guard_identity,
             &b->observation.guard_identity)
         && a->observation.entry_fingerprint
         == b->observation.entry_fingerprint;
}

static wyrelog_error_t
prove_begin (const WylPolicyFactBackupSnapshot *current,
    const GPtrArray *provisioning, gpointer user_data)
{
#ifdef WYL_TEST_HANDLE_SEAMS
  if (proof_checkpoint != NULL) {
    wyrelog_error_t checkpoint_rc = proof_checkpoint
          (proof_checkpoint_data);
    if (checkpoint_rc != WYRELOG_E_OK)
      return checkpoint_rc;
  }
#endif
  BeginProof *proof = user_data;
  const WylPolicyFactBackupSnapshot *initial = proof->initial;
  if (current == NULL || current->tenant == NULL || current->graphs == NULL
      || provisioning == NULL || initial->tenant == NULL
      || initial->graphs == NULL
      || current->graphs->len != initial->graphs->len
      || provisioning->len != proof->graphs->len
      || current->tenant->lifecycle_generation
      != initial->tenant->lifecycle_generation
      || current->tenant->reconciliation_generation
      != initial->tenant->reconciliation_generation)
    return WYRELOG_E_BUSY;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (proof->lease, proof->resolver);
  for (guint i = 0; rc == WYRELOG_E_OK && i < proof->graphs->len; i++) {
    const WylPolicyFactBackupGraphSnapshot *old =
        g_ptr_array_index (initial->graphs, i);
    const WylPolicyFactBackupGraphSnapshot *now =
        g_ptr_array_index (current->graphs, i);
    const WylPolicyGraphProvisioningRecord *record =
        g_ptr_array_index ((GPtrArray *) provisioning, i);
    const BeginGraph *graph = g_ptr_array_index ((GPtrArray *) proof->graphs, i);
    if (old == NULL || now == NULL || old->authority == NULL
        || now->authority == NULL
        || g_strcmp0 (old->authority->graph_id,
        now->authority->graph_id) != 0
        || old->authority->lifecycle_generation
        != now->authority->lifecycle_generation
        || old->authority->reconciliation_generation
        != now->authority->reconciliation_generation
        || g_strcmp0 (old->active_schema_digest,
        now->active_schema_digest) != 0
        || !provisioning_matches (record, now->authority, graph)) {
      rc = WYRELOG_E_BUSY;
      break;
    }
    WylFactGraphRuntimeStatus status = { 0 };
    rc = wyl_fact_graph_runtime_manager_get_status (proof->runtime,
            &graph->key, &status);
    if (rc == WYRELOG_E_OK && (graph->quiescence == NULL
        || status.admission != WYL_FACT_GRAPH_ADMISSION_CLOSED
        || status.state == WYL_FACT_GRAPH_RUNTIME_ABANDONED
        || status.operation_active || status.active_engine_calls != 0
        || status.waiting_engine_calls != 0))
      rc = WYRELOG_E_BUSY;
    wyl_fact_graph_runtime_status_clear (&status);
    if (rc != WYRELOG_E_OK)
      break;
    WylFactGraphPreStageInventory repeated = { 0 };
    rc = observe (proof->resolver, proof->lease, now->authority,
            record, &repeated);
    if (rc == WYRELOG_E_OK
        && !same_inventory (&graph->inventory, &repeated))
      rc = WYRELOG_E_BUSY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (proof->bundle);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_begin_run (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactGraphRuntimeManager *runtime,
    WylFactOfflineBackupBundle *bundle, WylFactOfflineRestoreScope scope,
    const gchar *selected_graph_id, const gchar *operation_uuid,
    gboolean confirmed, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || bundle == NULL || operation_uuid == NULL
      || out_committed == NULL
      || (scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      ? selected_graph_id != NULL : selected_graph_id == NULL
      || *selected_graph_id == '\0'))
    return WYRELOG_E_INVALID;
  if (!confirmed)
    return WYRELOG_E_POLICY;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_autoptr (WylPolicyFactBackupSnapshot) snapshot = NULL;
  g_autoptr (GPtrArray) graphs = g_ptr_array_new_with_free_func
        (begin_graph_free);
  g_autoptr (GPtrArray) targets = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_restore_target_graph_free);
  g_autoptr (GBytes) manifest_bytes = NULL;
  g_auto (WylFactOfflineBackupManifest) manifest = { 0 };
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  wyrelog_error_t rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  if (rc == WYRELOG_E_OK)
    manifest_bytes = wyl_fact_offline_backup_bundle_manifest_bytes (bundle);
  if (rc == WYRELOG_E_OK && manifest_bytes == NULL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_manifest_decode (manifest_bytes, &manifest);
  if (rc == WYRELOG_E_OK && (manifest.artifacts == NULL
      || manifest.artifacts->len == 0
      || manifest.artifacts->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < manifest.artifacts->len; i++) {
    const WylFactOfflineBackupArtifact *artifact =
        g_ptr_array_index (manifest.artifacts, i);
    if (artifact->format_version != WYL_FACT_STORE_FORMAT_VERSION
        || artifact->path_encoding_version !=
        WYL_FACT_STORE_PATH_ENCODING_VERSION)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root,
            lease);
  if (rc == WYRELOG_E_OK)
    rc = scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT ?
        wyl_policy_store_read_fact_backup_snapshot (policy,
            manifest.tenant_id, &snapshot) :
        wyl_policy_store_read_fact_graph_backup_snapshot (policy,
            manifest.tenant_id, selected_graph_id, &snapshot);
  if (rc == WYRELOG_E_OK && !target_matches (snapshot, &manifest, scope,
      selected_graph_id))
    rc = WYRELOG_E_POLICY;
  gint64 now = g_get_monotonic_time ();
  gint64 deadline = drain_timeout_us > 0 ?
      (drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
      now + drain_timeout_us) : 0;
  for (guint i = 0; rc == WYRELOG_E_OK && i < snapshot->graphs->len; i++) {
    const WylPolicyFactBackupGraphSnapshot *entry =
        g_ptr_array_index (snapshot->graphs, i);
    const WylPolicyGraphAuthorityRecord *authority = entry->authority;
    BeginGraph *graph = g_new0 (BeginGraph, 1);
    g_ptr_array_add (graphs, graph);
    rc = wyl_fact_graph_key_init (&graph->key, manifest.tenant_id,
            authority->graph_id);
    gint64 remaining = drain_timeout_us > 0 ?
        MAX ((gint64) 0, deadline - g_get_monotonic_time ()) :
        drain_timeout_us;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce (runtime, &graph->key,
              remaining, &graph->quiescence);
    g_autoptr (GPtrArray) provisioning = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_graph_provisioning_list_for_graph (policy,
              manifest.tenant_id, authority->graph_id, &provisioning);
    if (rc == WYRELOG_E_OK && (provisioning == NULL
        || provisioning->len != 1))
      rc = WYRELOG_E_POLICY;
    const WylPolicyGraphProvisioningRecord *record =
        rc == WYRELOG_E_OK ? g_ptr_array_index (provisioning, 0) : NULL;
    if (rc == WYRELOG_E_OK
        && !provisioning_matches (record, authority, NULL))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      rc = observe (&resolver, lease, authority, record,
              &graph->inventory);
    if (rc == WYRELOG_E_OK) {
      graph->provisioning_uuid = g_strdup (record->op_uuid);
      graph->stage_basename = g_strdup (record->stage_basename);
      graph->provisioning_attempt = record->attempt;
      graph->darwin_evidence = record->darwin_operation_evidence == NULL ?
          NULL : g_bytes_ref (record->darwin_operation_evidence);
      WylFactOfflineRestoreTargetGraph *target = g_new0
            (WylFactOfflineRestoreTargetGraph, 1);
      target->graph_id = g_strdup (authority->graph_id);
      target->lifecycle_generation = authority->lifecycle_generation;
      target->reconciliation_generation =
          authority->reconciliation_generation;
      target->expected_main_identity = graph->inventory.main_identity;
      g_ptr_array_add (targets, target);
      if (graph->provisioning_uuid == NULL || target->graph_id == NULL)
        rc = WYRELOG_E_NOMEM;
    }
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_init (&journal, manifest_bytes,
            operation_uuid, scope, selected_graph_id,
            snapshot->tenant->lifecycle_generation,
            snapshot->tenant->reconciliation_generation, targets,
            WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
            WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  BeginProof proof = { lease, &resolver, runtime, bundle, snapshot, graphs };
  WylFactOfflineRestoreStoreResult result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_create_guarded (policy,
            &journal, prove_begin, &proof, &result, out_committed);
  if (rc == WYRELOG_E_OK && result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED
      && result != WYL_FACT_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  /* Runtime tokens must be released before the root lease. */
  g_ptr_array_set_size (graphs, 0);
  wyl_fact_graph_resolver_clear (&resolver);
  return rc;
#endif
}

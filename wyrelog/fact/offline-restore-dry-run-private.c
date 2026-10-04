/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-dry-run-private.h"

#include "fact/offline-backup-manifest-private.h"
#include "fact/root-writer-lease-private.h"
#include "fact/store-identity-types-private.h"
#include "wyl-id-private.h"

#include <string.h>

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylPolicyFactBackupSnapshot,
    wyl_policy_fact_backup_snapshot_free)

static gboolean
canonical_uuid (const gchar *value)
{
  if (value == NULL || strlen (value) != 36)
    return FALSE;
  wyl_id_t id;
  gchar canonical[WYL_ID_STRING_BUF];
  return wyl_id_parse (value, &id) == WYRELOG_E_OK
         && wyl_id_format (&id, canonical, sizeof canonical) == WYRELOG_E_OK
         && g_strcmp0 (value, canonical) == 0;
}

static gboolean
canonical_sha256 (const gchar *value)
{
  if (value == NULL || strlen (value) != 71
      || !g_str_has_prefix (value, "sha256:"))
    return FALSE;
  for (guint i = 7; i < 71; i++)
    if (!g_ascii_isdigit (value[i])
        && !(value[i] >= 'a' && value[i] <= 'f'))
      return FALSE;
  return TRUE;
}

static gboolean
manifest_supported (const WylFactOfflineBackupManifest *manifest)
{
  if ((manifest->version != WYL_FACT_OFFLINE_BACKUP_MANIFEST_VERSION
      && manifest->version != WYL_FACT_OFFLINE_BACKUP_MANIFEST_LEGACY_VERSION)
      || manifest->tenant_id == NULL || *manifest->tenant_id == '\0'
      || manifest->policy_generation == 0
      || manifest->artifacts == NULL || manifest->artifacts->len == 0
      || manifest->artifacts->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS)
    return FALSE;
  const gchar *previous = NULL;
  for (guint i = 0; i < manifest->artifacts->len; i++) {
    const WylFactOfflineBackupArtifact *artifact =
        g_ptr_array_index (manifest->artifacts, i);
    if (artifact == NULL || artifact->graph_id == NULL
        || *artifact->graph_id == '\0'
        || (previous != NULL && strcmp (previous, artifact->graph_id) >= 0)
        || !canonical_uuid (artifact->store_uuid)
        || !canonical_sha256 (artifact->schema_digest)
        || !canonical_sha256 (artifact->checksum)
        || artifact->format_version != WYL_FACT_STORE_FORMAT_VERSION
        || artifact->path_encoding_version !=
        WYL_FACT_STORE_PATH_ENCODING_VERSION
        || artifact->logical_bytes == 0
        || artifact->logical_bytes > G_MAXINT64)
      return FALSE;
    previous = artifact->graph_id;
  }
  return TRUE;
}

static void
dry_run_graph_free (gpointer data)
{
  WylFactOfflineRestoreDryRunGraph *graph = data;
  if (graph != NULL) {
    g_free (graph->graph_id);
    g_free (graph->target_schema_digest);
    g_free (graph);
  }
}

void
wyl_fact_offline_restore_dry_run_report_clear
  (WylFactOfflineRestoreDryRunReport *report)
{
  if (report == NULL)
    return;
  g_free (report->tenant_id);
  g_free (report->failed_graph_id);
  g_clear_pointer (&report->graphs, g_ptr_array_unref);
  memset (report, 0, sizeof *report);
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
snapshot_equal (const WylPolicyFactBackupSnapshot *a,
    const WylPolicyFactBackupSnapshot *b)
{
  if (a == NULL || b == NULL || a->tenant == NULL || b->tenant == NULL
      || a->graphs == NULL || b->graphs == NULL
      || g_strcmp0 (a->tenant->tenant_id, b->tenant->tenant_id) != 0
      || a->tenant->lifecycle_state != b->tenant->lifecycle_state
      || a->tenant->lifecycle_generation != b->tenant->lifecycle_generation
      || a->tenant->reconciliation_generation
      != b->tenant->reconciliation_generation
      || a->tenant->sealed_compatibility != b->tenant->sealed_compatibility
      || a->graphs->len != b->graphs->len)
    return FALSE;
  for (guint i = 0; i < a->graphs->len; i++) {
    const WylPolicyFactBackupGraphSnapshot *left =
        g_ptr_array_index (a->graphs, i);
    const WylPolicyFactBackupGraphSnapshot *right =
        g_ptr_array_index (b->graphs, i);
    if (left == NULL || right == NULL || left->authority == NULL
        || right->authority == NULL)
      return FALSE;
    const WylPolicyGraphAuthorityRecord *x = left->authority;
    const WylPolicyGraphAuthorityRecord *y = right->authority;
    if (g_strcmp0 (x->tenant_id, y->tenant_id) != 0
        || g_strcmp0 (x->graph_id, y->graph_id) != 0
        || x->lifecycle_state != y->lifecycle_state
        || g_strcmp0 (x->store_uuid, y->store_uuid) != 0
        || x->format_version != y->format_version
        || x->path_encoding_version != y->path_encoding_version
        || x->lifecycle_generation != y->lifecycle_generation
        || x->reconciliation_generation != y->reconciliation_generation
        || x->last_error_class != y->last_error_class
        || x->materialization_state != y->materialization_state
        || x->has_store_identity != y->has_store_identity
        || x->sealed_compatibility != y->sealed_compatibility
        || g_strcmp0 (left->active_schema_digest,
        right->active_schema_digest) != 0)
      return FALSE;
  }
  return TRUE;
}

static gboolean
inventory_observation_equal (const WylFactArtifactInventoryObservation *a,
    const WylFactArtifactInventoryObservation *b)
{
  return wyl_fact_artifact_inventory_identity_equal
           (&a->directory_identity, &b->directory_identity)
         && wyl_fact_artifact_inventory_identity_equal
           (&a->guard_identity, &b->guard_identity)
         && a->entry_fingerprint == b->entry_fingerprint;
}

static wyrelog_error_t
read_scope_snapshot (wyl_policy_store_t *policy, const gchar *tenant_id,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id,
    WylPolicyFactBackupSnapshot **out_snapshot)
{
  return scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      ? wyl_policy_store_read_fact_backup_snapshot (policy, tenant_id,
             out_snapshot)
      : wyl_policy_store_read_fact_graph_backup_snapshot (policy, tenant_id,
             selected_graph_id, out_snapshot);
}

static gboolean
target_matches (const WylPolicyFactBackupSnapshot *snapshot,
    const WylFactOfflineBackupManifest *manifest,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id)
{
  if (snapshot == NULL || snapshot->tenant == NULL
      || snapshot->graphs == NULL || snapshot->graphs->len == 0
      || snapshot->tenant->lifecycle_state !=
      WYL_POLICY_TENANT_LIFECYCLE_SEALED
      || !snapshot->tenant->sealed_compatibility
      || g_strcmp0 (snapshot->tenant->tenant_id, manifest->tenant_id) != 0
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && snapshot->graphs->len != manifest->artifacts->len))
    return FALSE;
  for (guint i = 0; i < snapshot->graphs->len; i++) {
    const WylPolicyFactBackupGraphSnapshot *graph =
        g_ptr_array_index (snapshot->graphs, i);
    if (graph == NULL || graph->authority == NULL)
      return FALSE;
    const WylPolicyGraphAuthorityRecord *authority = graph->authority;
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
        || authority->path_encoding_version !=
        artifact->path_encoding_version
        || artifact->format_version != WYL_FACT_STORE_FORMAT_VERSION
        || artifact->path_encoding_version !=
        WYL_FACT_STORE_PATH_ENCODING_VERSION
        || graph->active_schema_digest == NULL)
      return FALSE;
  }
  return TRUE;
}

static wyrelog_error_t
runtime_check (WylFactGraphRuntimeManager *runtime, const gchar *tenant_id,
    const gchar *graph_id)
{
  if (runtime == NULL)
    return WYRELOG_E_INVALID;
  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, tenant_id, graph_id);
  WylFactGraphRuntimeStatus status = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_get_status (runtime, &key, &status);
  /* A sealed graph may have no runtime entry after a process restart. */
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_OK;
  else if (rc == WYRELOG_E_OK
      && (status.admission != WYL_FACT_GRAPH_ADMISSION_CLOSED
      || status.state == WYL_FACT_GRAPH_RUNTIME_ABANDONED
      || status.operation_active || status.active_engine_calls != 0
      || status.waiting_engine_calls != 0 || status.waiting_drains != 0))
    rc = WYRELOG_E_BUSY;
  wyl_fact_graph_runtime_status_clear (&status);
  wyl_fact_graph_key_clear (&key);
  return rc;
}

static wyrelog_error_t
observe_graph (wyl_policy_store_t *policy, WylFactGraphResolver *resolver,
    WylFactRootWriterLease *lease,
    const gchar *tenant_id, const WylPolicyGraphAuthorityRecord *authority,
    WylFactGraphPreStageInventory *out_inventory, gchar **out_op_uuid)
{
  *out_op_uuid = NULL;
  memset (out_inventory, 0, sizeof *out_inventory);
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphProvisionedPair *pair = NULL;
  g_autoptr (GPtrArray) provisioning = NULL;
  WylFactArtifactInventoryIdentity main_identity = { 0 };
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list_for_graph
        (policy, tenant_id, authority->graph_id, &provisioning);
  if (rc == WYRELOG_E_OK && (provisioning == NULL
      || provisioning->len != 1))
    rc = WYRELOG_E_POLICY;
  WylPolicyGraphProvisioningRecord *record = rc == WYRELOG_E_OK
      ? g_ptr_array_index (provisioning, 0) : NULL;
  if (rc == WYRELOG_E_OK && (record == NULL
      || record->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE
      || g_strcmp0 (record->tenant_id, tenant_id) != 0
      || g_strcmp0 (record->graph_id, authority->graph_id) != 0
      || g_strcmp0 (record->store_uuid, authority->store_uuid) != 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, tenant_id,
            authority->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (resolver, &locator, FALSE,
            &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            record->op_uuid, &pair);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_provisioned_pair_main_identity (pair, &main_identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_pre_stage_inventory (resolver, &directory,
            lease, pair, &main_identity, out_inventory);
  if (rc == WYRELOG_E_OK) {
    *out_op_uuid = g_strdup (record->op_uuid);
    if (*out_op_uuid == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (rc != WYRELOG_E_OK)
    memset (out_inventory, 0, sizeof *out_inventory);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_dry_run (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactGraphRuntimeManager *runtime,
    WylFactOfflineBackupBundle *bundle, WylFactOfflineRestoreScope scope,
    const gchar *selected_graph_id,
    WylFactOfflineRestoreDryRunReport *out_report)
{
  if (out_report == NULL)
    return WYRELOG_E_INVALID;
  wyl_fact_offline_restore_dry_run_report_clear (out_report);
  if (policy == NULL || fact_root == NULL || runtime == NULL || bundle == NULL
      || (scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      ? selected_graph_id != NULL
      : selected_graph_id == NULL || *selected_graph_id == '\0'))
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) runtime;
  out_report->failure = WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_AUTHORITY;
  return WYRELOG_E_POLICY;
#else
  WylFactOfflineRestoreDryRunFailure failure =
      WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_BUNDLE;
  const gchar *failed_graph_id = NULL;
  WylFactOfflineRestoreDryRunReport result = { 0 };
  result.replay_result = WYL_FACT_OFFLINE_RESTORE_REPLAY_NOT_RUN;
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_autoptr (WylPolicyFactBackupSnapshot) before = NULL;
  g_autoptr (WylPolicyFactBackupSnapshot) after = NULL;
  g_autoptr (GChecksum) checksum = NULL;
  g_autoptr (GPtrArray) operation_uuids =
      g_ptr_array_new_with_free_func (g_free);
  g_auto (WylFactOfflineBackupManifest) manifest = { 0 };
  g_autoptr (GBytes) manifest_bytes = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  wyrelog_error_t rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  if (rc == WYRELOG_E_OK)
    manifest_bytes = wyl_fact_offline_backup_bundle_manifest_bytes (bundle);
  if (rc == WYRELOG_E_OK && manifest_bytes == NULL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_manifest_decode (manifest_bytes, &manifest);
  if (rc == WYRELOG_E_OK
      && (!manifest_supported (&manifest)
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      && find_artifact (&manifest, selected_graph_id) == NULL)))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    goto finish;
  gsize manifest_length = 0;
  const guint8 *manifest_data = g_bytes_get_data (manifest_bytes,
          &manifest_length);
  checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto finish;
  }
  g_checksum_update (checksum, manifest_data, manifest_length);
  gsize digest_length = sizeof result.manifest_sha256;
  g_checksum_get_digest (checksum, result.manifest_sha256, &digest_length);
  failure = WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_AUTHORITY;
  rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_check_fact_root_observational (policy, fact_root,
            lease, &resolver);
  if (rc != WYRELOG_E_OK)
    goto finish;
  failure = WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_TARGET;
  rc = read_scope_snapshot (policy, manifest.tenant_id, scope,
          selected_graph_id, &before);
  if (rc == WYRELOG_E_OK && !target_matches (before, &manifest, scope,
      selected_graph_id))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    goto finish;
  result.tenant_id = g_strdup (manifest.tenant_id);
  result.graphs = g_ptr_array_new_with_free_func (dry_run_graph_free);
  if (result.tenant_id == NULL || result.graphs == NULL
      || operation_uuids == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto finish;
  }
  result.tenant_lifecycle_generation = before->tenant->lifecycle_generation;
  result.tenant_reconciliation_generation =
      before->tenant->reconciliation_generation;
  for (guint i = 0; i < before->graphs->len; i++) {
    const WylPolicyFactBackupGraphSnapshot *entry =
        g_ptr_array_index (before->graphs, i);
    const WylPolicyGraphAuthorityRecord *authority = entry->authority;
    failed_graph_id = authority->graph_id;
    failure = WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_RUNTIME;
    rc = runtime_check (runtime, manifest.tenant_id, authority->graph_id);
    if (rc != WYRELOG_E_OK)
      goto finish;
    WylFactOfflineRestoreDryRunGraph *graph = g_new0
          (WylFactOfflineRestoreDryRunGraph, 1);
    if (graph == NULL) {
      rc = WYRELOG_E_NOMEM;
      goto finish;
    }
    graph->graph_id = g_strdup (authority->graph_id);
    graph->target_schema_digest = g_strdup (entry->active_schema_digest);
    graph->schema_transition_required = g_strcmp0
          (entry->active_schema_digest, find_artifact (&manifest,
            authority->graph_id)->schema_digest) != 0;
    graph->lifecycle_generation = authority->lifecycle_generation;
    graph->reconciliation_generation = authority->reconciliation_generation;
    if (graph->graph_id == NULL || graph->target_schema_digest == NULL) {
      dry_run_graph_free (graph);
      rc = WYRELOG_E_NOMEM;
      goto finish;
    }
    g_ptr_array_add (result.graphs, graph);
    failure = WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_COLLISION;
    gchar *op_uuid = NULL;
    rc = observe_graph (policy, &resolver, lease,
            manifest.tenant_id, authority, &graph->inventory, &op_uuid);
    if (rc != WYRELOG_E_OK)
      goto finish;
    g_ptr_array_add (operation_uuids, op_uuid);
  }
  failure = WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_CHANGED;
  rc = read_scope_snapshot (policy, manifest.tenant_id, scope,
          selected_graph_id, &after);
  if (rc == WYRELOG_E_OK && !snapshot_equal (before, after))
    rc = WYRELOG_E_BUSY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < after->graphs->len; i++) {
    const WylPolicyGraphAuthorityRecord *authority =
        ((WylPolicyFactBackupGraphSnapshot *)
        g_ptr_array_index (after->graphs, i))->authority;
    WylFactOfflineRestoreDryRunGraph *graph =
        g_ptr_array_index (result.graphs, i);
    failed_graph_id = authority->graph_id;
    rc = runtime_check (runtime, manifest.tenant_id, authority->graph_id);
    WylFactGraphPreStageInventory repeated = { 0 };
    gchar *op_uuid = NULL;
    if (rc == WYRELOG_E_OK)
      rc = observe_graph (policy, &resolver, lease,
              manifest.tenant_id, authority, &repeated, &op_uuid);
    if (rc == WYRELOG_E_OK
        && (g_strcmp0 (op_uuid, g_ptr_array_index (operation_uuids, i)) != 0
        || repeated.main_present != graph->inventory.main_present
        || !wyl_fact_artifact_inventory_identity_equal
          (&repeated.main_identity, &graph->inventory.main_identity)
        || !inventory_observation_equal (&repeated.observation,
        &graph->inventory.observation)))
      rc = WYRELOG_E_BUSY;
    g_free (op_uuid);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_check_fact_root_observational (policy, fact_root,
            lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  if (rc == WYRELOG_E_OK) {
    result.observed_eligible_for_staging = TRUE;
    *out_report = result;
    memset (&result, 0, sizeof result);
  }
finish:
  if (rc != WYRELOG_E_OK) {
    out_report->failure = failure;
    if (failed_graph_id != NULL)
      out_report->failed_graph_id = g_strdup (failed_graph_id);
  }
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_offline_restore_dry_run_report_clear (&result);
  return rc;
#endif
}

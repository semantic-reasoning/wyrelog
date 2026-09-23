/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-restore-coordinator-private.h"

#include <string.h>

#include "fact/offline-backup-manifest-private.h"
#include "fact/offline-restore-journal-stage-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/offline-restore-validation-private.h"

static WylFactOfflineRestoreJournalGraph *
find_journal_graph (WylFactOfflineRestoreJournal *journal,
    const gchar *graph_id)
{
  for (guint i = 0; journal->graphs != NULL && i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (journal->graphs, i);
    if (g_strcmp0 (graph->graph_id, graph_id) == 0)
      return graph;
  }
  return NULL;
}

static const WylFactOfflineBackupArtifact *
find_manifest_artifact (const WylFactOfflineBackupManifest *manifest,
    const gchar *graph_id)
{
  for (guint i = 0; manifest->artifacts != NULL
      && i < manifest->artifacts->len; i++) {
    const WylFactOfflineBackupArtifact *artifact = g_ptr_array_index
          (manifest->artifacts, i);
    if (g_strcmp0 (artifact->graph_id, graph_id) == 0)
      return artifact;
  }
  return NULL;
}

static gboolean
identity_is_zero (const WylFactArtifactInventoryIdentity *identity)
{
  WylFactArtifactInventoryIdentity zero = { 0 };
  return wyl_fact_artifact_inventory_identity_equal (identity, &zero);
}

static gboolean
source_artifact_matches (const WylFactOfflineBackupSourceArtifact *source,
    const WylFactOfflineBackupArtifact *manifest,
    const WylFactOfflineRestoreJournalGraph *journal)
{
  return source != NULL && manifest != NULL && journal != NULL
         && g_strcmp0 (source->graph_id, manifest->graph_id) == 0
         && g_strcmp0 (source->graph_id, journal->graph_id) == 0
         && g_strcmp0 (source->store_uuid, manifest->store_uuid) == 0
         && g_strcmp0 (source->store_uuid, journal->store_uuid) == 0
         && source->format_version == manifest->format_version
         && source->format_version == journal->format_version
         && source->path_encoding_version == manifest->path_encoding_version
         && source->path_encoding_version == journal->path_encoding_version
         && g_strcmp0 (source->schema_digest, manifest->schema_digest) == 0
         && g_strcmp0 (source->schema_digest, journal->schema_digest) == 0
         && source->logical_bytes == manifest->logical_bytes
         && source->logical_bytes == journal->logical_bytes
         && source->physical_bytes == manifest->physical_bytes
         && source->physical_bytes == journal->physical_bytes
         && g_strcmp0 (manifest->checksum, journal->checksum) == 0;
}

static wyrelog_error_t
validate_complete_source_set (WylFactOfflineBackupSource *source,
    const WylFactOfflineBackupManifest *manifest,
    WylFactOfflineRestoreJournal *journal, GHashTable **out_source_indexes)
{
  *out_source_indexes = NULL;
  if (g_strcmp0 (wyl_fact_offline_backup_source_tenant_id (source),
      journal->tenant_id) != 0
      || g_strcmp0 (manifest->tenant_id, journal->tenant_id) != 0
      || wyl_fact_offline_backup_source_policy_generation (source)
      != journal->source_tenant_lifecycle_generation)
    return WYRELOG_E_POLICY;

  gsize source_count = wyl_fact_offline_backup_source_count (source);
  if (source_count != journal->graphs->len
      || source_count != manifest->artifacts->len)
    return WYRELOG_E_POLICY;

  GHashTable *source_indexes = g_hash_table_new_full (g_str_hash, g_str_equal,
          g_free, NULL);
  GHashTable *journal_ids = g_hash_table_new (g_str_hash, g_str_equal);
  GHashTable *manifest_ids = g_hash_table_new (g_str_hash, g_str_equal);
  wyrelog_error_t rc = WYRELOG_E_OK;
  for (gsize i = 0; i < source_count && rc == WYRELOG_E_OK; i++) {
    WylFactOfflineBackupSourceArtifact artifact = { 0 };
    if (!wyl_fact_offline_backup_source_get (source, i, &artifact)
        || artifact.graph_id == NULL
        || g_hash_table_contains (source_indexes, artifact.graph_id)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    const WylFactOfflineBackupArtifact *manifest_artifact =
        find_manifest_artifact (manifest, artifact.graph_id);
    WylFactOfflineRestoreJournalGraph *journal_graph =
        find_journal_graph (journal, artifact.graph_id);
    if (manifest_artifact == NULL || journal_graph == NULL
        || !source_artifact_matches (&artifact, manifest_artifact,
        journal_graph)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    g_hash_table_insert (source_indexes, g_strdup (artifact.graph_id),
        GUINT_TO_POINTER ((guint) i + 1));
  }
  for (guint i = 0; i < journal->graphs->len && rc == WYRELOG_E_OK; i++) {
    WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (journal->graphs, i);
    if (graph == NULL || graph->graph_id == NULL
        || g_hash_table_contains (journal_ids, graph->graph_id)
        || find_manifest_artifact (manifest, graph->graph_id) == NULL
        || !g_hash_table_contains (source_indexes, graph->graph_id)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    g_hash_table_add (journal_ids, graph->graph_id);
  }
  for (guint i = 0; i < manifest->artifacts->len && rc == WYRELOG_E_OK; i++) {
    WylFactOfflineBackupArtifact *artifact = g_ptr_array_index
          (manifest->artifacts, i);
    if (artifact == NULL || artifact->graph_id == NULL
        || g_hash_table_contains (manifest_ids, artifact->graph_id)
        || !g_hash_table_contains (journal_ids, artifact->graph_id)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    g_hash_table_add (manifest_ids, artifact->graph_id);
  }
  g_hash_table_unref (journal_ids);
  g_hash_table_unref (manifest_ids);
  if (rc != WYRELOG_E_OK) {
    g_hash_table_unref (source_indexes);
    return rc;
  }
  *out_source_indexes = source_indexes;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
copy_journal (const WylFactOfflineRestoreJournal *source,
    WylFactOfflineRestoreJournal *destination)
{
  g_autoptr (GBytes) encoded = NULL;
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_encode (source,
          &encoded);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (encoded, destination);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_stages_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || fact_root[0] == '\0'
      || runtime_manager == NULL || tenant_id == NULL || tenant_id[0] == '\0'
      || canonical_manifest == NULL || operation_uuid == NULL
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (WylFactRootWriterLease) lease = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  WylFactOfflineRestoreJournal journal = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy, operation_uuid,
            &journal);
  if (rc == WYRELOG_E_OK && journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && g_strcmp0 (journal.tenant_id, tenant_id) != 0)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (canonical_manifest,
            &journal);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_offline_restore_journal_clear (&journal);
    return rc;
  }

  WylFactOfflineBackupManifest manifest = { 0 };
  rc = wyl_fact_offline_backup_manifest_decode (canonical_manifest, &manifest);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_offline_restore_journal_clear (&journal);
    wyl_fact_offline_backup_manifest_clear (&manifest);
    return rc;
  }
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  rc = wyl_fact_offline_backup_source_new_with_lease (policy, fact_root,
          runtime_manager, tenant_id, drain_timeout_us, lease, &source);
  GHashTable *source_indexes = NULL;
  if (rc == WYRELOG_E_OK)
    rc = validate_complete_source_set (source, &manifest, &journal,
            &source_indexes);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_source_revalidate (source);

  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (journal.graphs, i);
    if (!identity_is_zero (&graph->staged_main_identity))
      continue;
    gpointer encoded_index = g_hash_table_lookup (source_indexes,
            graph->graph_id);
    if (encoded_index == NULL) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    gsize source_index = GPOINTER_TO_UINT (encoded_index) - 1;
    rc = wyl_fact_root_writer_lease_verify (lease);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_backup_source_revalidate (source);
    if (rc != WYRELOG_E_OK)
      break;

    g_autoptr (WylFactOfflineRestoreJournalStage) session = NULL;
    rc = wyl_fact_offline_restore_journal_stage_new_with_lease (policy,
            fact_root, canonical_manifest, operation_uuid, graph->graph_id,
            journal.revision, lease, &session);
    if (rc != WYRELOG_E_OK)
      break;
    guint64 bytes_copied = 0;
    wyrelog_error_t copy_rc = wyl_fact_offline_backup_source_copy_to_sink
          (source, source_index, wyl_fact_offline_restore_journal_stage_sink,
            session, &bytes_copied);
    if (copy_rc == WYRELOG_E_OK
        && bytes_copied != graph->logical_bytes)
      copy_rc = WYRELOG_E_POLICY;
    if (copy_rc == WYRELOG_E_OK)
      copy_rc = wyl_fact_root_writer_lease_verify (lease);
    if (copy_rc == WYRELOG_E_OK)
      copy_rc = wyl_fact_offline_backup_source_revalidate (source);

    WylFactOfflineRestoreJournal committed = { 0 };
    wyrelog_error_t finish_rc =
        wyl_fact_offline_restore_journal_stage_finish (session, copy_rc,
            &committed);
    if (copy_rc != WYRELOG_E_OK)
      rc = copy_rc;
    else
      rc = finish_rc;
    if (rc == WYRELOG_E_OK) {
      wyl_fact_offline_restore_journal_clear (&journal);
      journal = committed;
      memset (&committed, 0, sizeof committed);
    }
    wyl_fact_offline_restore_journal_clear (&committed);
  }

  if (source_indexes != NULL)
    g_hash_table_unref (source_indexes);
  if (rc == WYRELOG_E_OK)
    rc = copy_journal (&journal, out_committed);
  wyl_fact_offline_restore_journal_clear (&journal);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  return rc;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-restore-coordinator-private.h"

#include <string.h>

#include "fact/offline-backup-manifest-private.h"
#include "fact/offline-restore-journal-stage-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/offline-restore-stage-private.h"
#include "fact/offline-restore-validation-session-private.h"
#include "fact/offline-restore-validation-private.h"

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylPolicyFactBackupSnapshot,
    wyl_policy_fact_backup_snapshot_free)

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
      || (journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && source_count != manifest->artifacts->len))
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
    if (journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && artifact != NULL
        && g_strcmp0 (artifact->graph_id, journal->selected_graph_id) != 0)
      continue;
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

/* The graph entry point deliberately cannot resume a bound stage. Unlike
 * tenant partial staging, all work here is one pristine singleton. Check the
 * complete staging contract before closing any source runtime admission. */
static gboolean
graph_journal_is_pristine (const WylFactOfflineRestoreJournal *journal,
    const gchar *graph_id)
{
  if (journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || g_strcmp0 (journal->selected_graph_id, graph_id) != 0
      || journal->revision != 1 || journal->graphs == NULL
      || journal->graphs->len != 1
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal->policy_generation_published || journal->lifecycle_handoff_complete
      || journal->confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED)
    return FALSE;
  const WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (journal->graphs, 0);
  return graph != NULL && g_strcmp0 (graph->graph_id, graph_id) == 0
         && identity_is_zero (&graph->staged_main_identity)
         && !graph->copied && !graph->checksum_verified && !graph->identity_verified
         && !graph->schema_verified && !graph->replay_preflighted
         && graph->transition_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
         && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
         && !graph->transition_terminal
         && graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
         && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
         && !graph->resume_forbidden && !graph->durability_unprovable_acknowledged;
}

static wyrelog_error_t
restore_stages_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    const gchar *selected_graph_id, GBytes *canonical_manifest, const gchar *operation_uuid,
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
  if (rc == WYRELOG_E_OK && (selected_graph_id != NULL
      ? !graph_journal_is_pristine (&journal, selected_graph_id)
      : journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT))
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
  rc = selected_graph_id != NULL
      ? wyl_fact_offline_backup_source_new_for_graph_with_lease (policy, fact_root,
          runtime_manager, tenant_id, selected_graph_id, drain_timeout_us, lease, &source)
      : wyl_fact_offline_backup_source_new_with_lease (policy, fact_root,
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

wyrelog_error_t
wyl_fact_offline_restore_tenant_stages_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  return restore_stages_run (policy, fact_root, runtime_manager, tenant_id,
             NULL, canonical_manifest, operation_uuid, expected_revision,
             drain_timeout_us, out_committed);
}

wyrelog_error_t
wyl_fact_offline_restore_graph_stage_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    const gchar *graph_id, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (graph_id == NULL || graph_id[0] == '\0')
    return WYRELOG_E_INVALID;
  return restore_stages_run (policy, fact_root, runtime_manager, tenant_id,
             graph_id, canonical_manifest, operation_uuid, expected_revision,
             drain_timeout_us, out_committed);
}

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*import_checkpoint) (gpointer);
static gpointer import_checkpoint_data;

void
wyl_fact_offline_restore_import_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer), gpointer data)
{
  import_checkpoint = checkpoint;
  import_checkpoint_data = data;
}
#endif

#ifndef G_OS_WIN32
static wyrelog_error_t
import_check_destination (wyl_policy_store_t *policy,
    WylFactGraphRuntimeManager *runtime, const WylFactGraphKey *key,
    WylFactOfflineBackupSource *destination,
    const WylFactOfflineRestoreJournal *journal, GBytes *journal_bytes)
{
  wyrelog_error_t rc = wyl_fact_offline_backup_source_revalidate (destination);
  WylFactGraphRuntimeStatus status = { 0 };
  if (rc == WYRELOG_E_OK && runtime != NULL)
    rc = wyl_fact_graph_runtime_manager_get_status (runtime, key, &status);
  if (rc == WYRELOG_E_OK && runtime != NULL
      && (status.state == WYL_FACT_GRAPH_RUNTIME_ABANDONED
      || status.admission != WYL_FACT_GRAPH_ADMISSION_CLOSED
      || status.operation_active || status.active_engine_calls != 0
      || status.waiting_engine_calls != 0))
    rc = WYRELOG_E_BUSY;
  wyl_fact_graph_runtime_status_clear (&status);

  const WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (journal->graphs, 0);
  WylFactOfflineBackupSourceArtifact artifact = { 0 };
  WylFactOfflineBackupSourceAuthority authority = { 0 };
  if (rc == WYRELOG_E_OK
      && (wyl_fact_offline_backup_source_count (destination) != 1
      || !wyl_fact_offline_backup_source_get (destination, 0, &artifact)
      || !wyl_fact_offline_backup_source_get_authority (destination, 0, &authority)
      || g_strcmp0 (wyl_fact_offline_backup_source_tenant_id (destination), journal->tenant_id) != 0
      || g_strcmp0 (artifact.graph_id, graph->graph_id) != 0
      || g_strcmp0 (artifact.store_uuid, graph->store_uuid) != 0
      || artifact.format_version != graph->format_version
      || artifact.path_encoding_version != graph->path_encoding_version
      || g_strcmp0 (artifact.schema_digest, graph->schema_digest) != 0
      || authority.tenant_lifecycle_generation != journal->destination_tenant_lifecycle_generation
      || authority.tenant_reconciliation_generation != journal->destination_tenant_reconciliation_generation
      || authority.graph_lifecycle_generation != graph->destination_lifecycle_generation
      || authority.graph_reconciliation_generation != graph->destination_reconciliation_generation
      || !wyl_fact_artifact_inventory_identity_equal (&authority.main_identity, &graph->expected_main_identity)))
    rc = WYRELOG_E_POLICY;
  g_auto (WylFactOfflineRestoreJournal) current = { 0 };
  g_autoptr (GBytes) current_bytes = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy, journal->operation_uuid, &current);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&current, &current_bytes);
  if (rc == WYRELOG_E_OK && (current.revision != journal->revision
      || !g_bytes_equal (current_bytes, journal_bytes)))
    rc = WYRELOG_E_BUSY;
  return rc;
}

static wyrelog_error_t
import_copy (const WylFactOfflineRestoreInput *input, gpointer data,
    guint64 expected_bytes, WylFactOfflineRestoreJournalStage *stage)
{
  guint8 buffer[64u * 1024u];
  guint64 offset = 0;
  while (offset < expected_bytes) {
    gsize capacity = (gsize) MIN ((guint64) sizeof buffer, expected_bytes - offset);
    gsize received = 0;
    wyrelog_error_t rc = input->read_at (offset, buffer, capacity, &received, data);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (received == 0 || received > capacity)
      return WYRELOG_E_POLICY;
    rc = wyl_fact_offline_restore_journal_stage_sink (offset, buffer, received, stage);
    if (rc != WYRELOG_E_OK)
      return rc;
    offset += received;
  }
  /* Exact length is part of the authenticated artifact contract. */
  gsize received = 0;
  wyrelog_error_t rc = input->read_at (offset, buffer, 1, &received, data);
  return rc != WYRELOG_E_OK ? rc : received == 0 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_graph_import_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    const gchar *graph_id, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us, const WylFactOfflineRestoreInput *input,
    gpointer input_data, WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || tenant_id == NULL || *tenant_id == '\0'
      || graph_id == NULL || *graph_id == '\0' || canonical_manifest == NULL
      || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || input == NULL || input->read_at == NULL || input->revalidate == NULL
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  (void) drain_timeout_us;
  (void) input_data;
  return WYRELOG_E_POLICY;
#else
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GBytes) journal_bytes = NULL;
  WylFactOfflineBackupSource *destination = NULL;
  WylFactGraphQuiescenceToken *quiescence = NULL;
  WylFactOfflineRestoreJournalStage *stage = NULL;
  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy, operation_uuid, &journal);
  if (rc == WYRELOG_E_OK && journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK && (!graph_journal_is_pristine (&journal, graph_id)
      || g_strcmp0 (journal.tenant_id, tenant_id) != 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (canonical_manifest, &journal);
  const WylFactOfflineRestoreJournalGraph *graph = rc == WYRELOG_E_OK
      ? g_ptr_array_index (journal.graphs, 0) : NULL;
  if (rc == WYRELOG_E_OK && graph->expected_main_absent)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&journal, &journal_bytes);

  gint64 now = g_get_monotonic_time ();
  gint64 deadline = drain_timeout_us > 0
      ? (drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 : now + drain_timeout_us) : 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_source_new_for_graph_with_lease (policy, fact_root,
            runtime_manager, tenant_id, graph_id, drain_timeout_us, lease, &destination);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && import_checkpoint != NULL)
    rc = import_checkpoint (import_checkpoint_data);
#endif
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, tenant_id, graph_id);
  gint64 remaining = drain_timeout_us > 0
      ? MAX ((gint64) 0, deadline - g_get_monotonic_time ()) : drain_timeout_us;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_quiesce (runtime_manager, &key, remaining, &quiescence);
  if (rc == WYRELOG_E_NOT_FOUND) {
    rc = wyl_fact_root_writer_lease_verify (lease);
    if (rc == WYRELOG_E_OK)
      rc = import_check_destination (policy, NULL, NULL, destination,
              &journal, journal_bytes);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed
            (runtime_manager, &key, remaining, &quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_root_writer_lease_verify (lease);
    if (rc == WYRELOG_E_OK)
      rc = import_check_destination (policy, NULL, NULL, destination,
              &journal, journal_bytes);
    if (rc != WYRELOG_E_OK)
      g_clear_pointer (&quiescence,
          wyl_fact_graph_quiescence_token_release);
  }
  if (rc == WYRELOG_E_OK)
    rc = import_check_destination (policy, runtime_manager, &key, destination, &journal, journal_bytes);
  if (rc == WYRELOG_E_OK)
    rc = input->revalidate (input_data);
  /* A source callback may have changed the destination's independent policy. */
  if (rc == WYRELOG_E_OK)
    rc = import_check_destination (policy, runtime_manager, &key, destination, &journal, journal_bytes);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_stage_new_with_lease (policy, fact_root,
            canonical_manifest, operation_uuid, graph_id, expected_revision, lease, &stage);
  if (rc == WYRELOG_E_OK)
    rc = import_copy (input, input_data, graph->logical_bytes, stage);
  if (rc == WYRELOG_E_OK)
    rc = input->revalidate (input_data);
  if (rc == WYRELOG_E_OK)
    rc = import_check_destination (policy, runtime_manager, &key, destination, &journal, journal_bytes);
  if (stage != NULL) {
    wyrelog_error_t finished = wyl_fact_offline_restore_journal_stage_finish (stage, rc, out_committed);
    if (rc == WYRELOG_E_OK)
      rc = finished;
  }
  wyl_fact_offline_restore_journal_stage_free (stage);
  wyl_fact_offline_backup_source_free (destination);
  wyl_fact_graph_quiescence_token_release (quiescence);
  wyl_fact_graph_key_clear (&key);
  return rc;
#endif
}

#ifdef __linux__
static gboolean
tenant_import_journal_is_staging (const WylFactOfflineRestoreJournal *journal)
{
  if (journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal->selected_graph_id != NULL || journal->graphs == NULL
      || journal->graphs->len == 0 || journal->revision == 0
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal->policy_generation_published
      || journal->lifecycle_handoff_complete
      || journal->confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust !=
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED)
    return FALSE;
  guint bound = 0;
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (graph == NULL || graph->copied || graph->checksum_verified
        || graph->identity_verified || graph->schema_verified
        || graph->replay_preflighted
        || graph->transition_state !=
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
        || graph->transition_terminal
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
        || graph->resume_forbidden || graph->durability_unprovable_acknowledged)
      return FALSE;
    if (!identity_is_zero (&graph->staged_main_identity))
      bound++;
  }
  return journal->revision == 1 + bound;
}

static wyrelog_error_t
tenant_import_check_destination (wyl_policy_store_t *policy,
    WylFactOfflineBackupSource *selected,
    const WylFactOfflineRestoreJournal *journal)
{
  g_autoptr (WylPolicyFactBackupSnapshot) snapshot = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_fact_backup_snapshot (policy,
          journal->tenant_id, &snapshot);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (snapshot->tenant == NULL || snapshot->graphs == NULL
      || snapshot->graphs->len != journal->graphs->len
      || snapshot->tenant->lifecycle_state !=
      WYL_POLICY_TENANT_LIFECYCLE_SEALED
      || !snapshot->tenant->sealed_compatibility
      || snapshot->tenant->lifecycle_generation !=
      journal->destination_tenant_lifecycle_generation
      || snapshot->tenant->reconciliation_generation !=
      journal->destination_tenant_reconciliation_generation)
    return WYRELOG_E_POLICY;
  g_autoptr (GHashTable) seen = g_hash_table_new (g_str_hash, g_str_equal);
  for (guint i = 0; i < snapshot->graphs->len; i++) {
    const WylPolicyFactBackupGraphSnapshot *entry =
        g_ptr_array_index (snapshot->graphs, i);
    const WylPolicyGraphAuthorityRecord *authority = entry->authority;
    if (authority == NULL || authority->graph_id == NULL
        || g_hash_table_contains (seen, authority->graph_id))
      return WYRELOG_E_POLICY;
    const WylFactOfflineRestoreJournalGraph *graph =
        find_journal_graph ((WylFactOfflineRestoreJournal *) journal,
            authority->graph_id);
    if (graph == NULL || authority->lifecycle_state !=
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
        graph->schema_digest) != 0
        || authority->lifecycle_generation !=
        graph->destination_lifecycle_generation
        || authority->reconciliation_generation !=
        graph->destination_reconciliation_generation)
      return WYRELOG_E_POLICY;
    g_hash_table_add (seen, authority->graph_id);
  }
  if (selected == NULL)
    return WYRELOG_E_OK;
  rc = wyl_fact_offline_backup_source_revalidate (selected);
  WylFactOfflineBackupSourceArtifact artifact = { 0 };
  WylFactOfflineBackupSourceAuthority authority = { 0 };
  if (rc != WYRELOG_E_OK)
    return rc;
  if (wyl_fact_offline_backup_source_count (selected) != 1
      || !wyl_fact_offline_backup_source_get (selected, 0, &artifact)
      || !wyl_fact_offline_backup_source_get_authority (selected, 0,
      &authority))
    return WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournalGraph *graph =
      find_journal_graph ((WylFactOfflineRestoreJournal *) journal,
          artifact.graph_id);
  if (graph == NULL || g_strcmp0 (artifact.store_uuid,
      graph->store_uuid) != 0
      || artifact.format_version != graph->format_version
      || artifact.path_encoding_version != graph->path_encoding_version
      || g_strcmp0 (artifact.schema_digest, graph->schema_digest) != 0
      || authority.tenant_lifecycle_generation !=
      journal->destination_tenant_lifecycle_generation
      || authority.tenant_reconciliation_generation !=
      journal->destination_tenant_reconciliation_generation
      || authority.graph_lifecycle_generation !=
      graph->destination_lifecycle_generation
      || authority.graph_reconciliation_generation !=
      graph->destination_reconciliation_generation
      || !wyl_fact_artifact_inventory_identity_equal
        (&authority.main_identity, &graph->expected_main_identity))
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
tenant_import_check_journal (wyl_policy_store_t *policy,
    const WylFactOfflineRestoreJournal *expected)
{
  g_auto (WylFactOfflineRestoreJournal) current = { 0 };
  g_autoptr (GBytes) before = NULL;
  g_autoptr (GBytes) after = NULL;
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (policy,
          expected->operation_uuid, &current);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (expected, &before);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&current, &after);
  return rc != WYRELOG_E_OK ? rc : current.revision != expected->revision
         || !g_bytes_equal (before, after) ? WYRELOG_E_BUSY : WYRELOG_E_OK;
}

static wyrelog_error_t
tenant_import_verify_bound (wyl_policy_store_t *policy,
    const gchar *fact_root,
    WylFactRootWriterLease *lease,
    const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreJournalGraph *graph)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphProvisionedPair *pair = NULL;
  WylFactGraphRestoreInventory inventory = { 0 };
  g_autoptr (WylFactOfflineRestoreStageReader) reader = NULL;
  g_autoptr (GPtrArray) provisioning = NULL;
  wyrelog_error_t rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, journal->tenant_id,
            graph->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator,
            FALSE, &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_provisioning_list_for_graph (policy,
            journal->tenant_id, graph->graph_id, &provisioning);
  if (rc == WYRELOG_E_OK
      && (provisioning->len != 1
      || ((WylPolicyGraphProvisioningRecord *)
      g_ptr_array_index (provisioning, 0))->phase !=
      WYL_POLICY_GRAPH_PROVISIONING_ACTIVE))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            ((WylPolicyGraphProvisioningRecord *)
            g_ptr_array_index (provisioning, 0))->op_uuid, &pair);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_inventory (&resolver, &directory,
            lease, pair, journal->operation_uuid,
            &graph->staged_main_identity, &graph->expected_main_identity,
            &inventory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_open (&resolver, &directory,
            lease, journal->operation_uuid, &graph->staged_main_identity,
            &reader);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_reader_verify_content (reader,
            graph->logical_bytes, graph->checksum);
  g_clear_pointer (&reader, wyl_fact_offline_restore_stage_reader_free);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  return rc;
}

static wyrelog_error_t
tenant_import_check_bound_set (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactRootWriterLease *lease,
    const WylFactOfflineRestoreJournal *journal)
{
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (identity_is_zero (&graph->staged_main_identity))
      continue;
    wyrelog_error_t rc = tenant_import_verify_bound (policy, fact_root,
            lease, journal, graph);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

typedef struct
{
  const WylFactOfflineRestoreTenantInput *input;
  const gchar *graph_id;
  gpointer data;
} TenantImportRead;

static wyrelog_error_t
tenant_import_read_at (guint64 offset, guint8 *buffer, gsize capacity,
    gsize *out_read, gpointer user_data)
{
  TenantImportRead *read = user_data;
  return read->input->read_at (read->graph_id, offset, buffer, capacity,
             out_read, read->data);
}

static wyrelog_error_t
tenant_import_revalidate (gpointer user_data)
{
  TenantImportRead *read = user_data;
  return read->input->revalidate (read->data);
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_tenant_import_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    const WylFactOfflineRestoreTenantInput *input, gpointer input_data,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || tenant_id == NULL || *tenant_id == '\0'
      || canonical_manifest == NULL || operation_uuid == NULL
      || *operation_uuid == '\0' || expected_revision == 0
      || expected_revision >= G_MAXINT64 || input == NULL
      || input->read_at == NULL || input->revalidate == NULL
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  (void) input_data;
  return WYRELOG_E_POLICY;
#else
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_autoptr (GPtrArray) selected_sources = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_backup_source_free);
  g_autoptr (GPtrArray) tokens = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_graph_quiescence_token_release);
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root,
            lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK && journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (!tenant_import_journal_is_staging (&journal)
      || g_strcmp0 (journal.tenant_id, tenant_id) != 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (canonical_manifest,
            &journal);
  if (rc == WYRELOG_E_OK)
    rc = tenant_import_check_destination (policy, NULL, &journal);
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    WylFactOfflineBackupSource *selected = NULL;
    if (identity_is_zero (&graph->staged_main_identity))
      rc = wyl_fact_offline_backup_source_new_for_graph_with_lease (policy,
              fact_root, runtime_manager, tenant_id, graph->graph_id,
              drain_timeout_us, lease, &selected);
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (selected_sources, selected);
  }
  gint64 now = g_get_monotonic_time ();
  gint64 deadline = drain_timeout_us > 0
      ? (drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64
      : now + drain_timeout_us) : 0;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    WylFactGraphKey key = { 0 };
    rc = wyl_fact_graph_key_init (&key, tenant_id, graph->graph_id);
    gint64 remaining = drain_timeout_us > 0
        ? MAX ((gint64) 0, deadline - g_get_monotonic_time ())
        : drain_timeout_us;
    WylFactGraphQuiescenceToken *token = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce (runtime_manager, &key,
              remaining, &token);
    if (rc == WYRELOG_E_NOT_FOUND) {
      rc = wyl_fact_root_writer_lease_verify (lease);
      if (rc == WYRELOG_E_OK)
        rc = tenant_import_check_destination (policy, NULL, &journal);
      if (rc == WYRELOG_E_OK)
        rc = tenant_import_check_journal (policy, &journal);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_graph_runtime_manager_quiesce_missing_closed
              (runtime_manager, &key, remaining, &token);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_root_writer_lease_verify (lease);
      if (rc == WYRELOG_E_OK)
        rc = tenant_import_check_destination (policy, NULL, &journal);
      if (rc == WYRELOG_E_OK)
        rc = tenant_import_check_journal (policy, &journal);
      if (rc != WYRELOG_E_OK)
        g_clear_pointer (&token, wyl_fact_graph_quiescence_token_release);
    }
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (tokens, token);
    wyl_fact_graph_key_clear (&key);
  }
  if (rc == WYRELOG_E_OK)
    rc = tenant_import_check_destination (policy, NULL, &journal);
  if (rc == WYRELOG_E_OK)
    rc = tenant_import_check_journal (policy, &journal);
  if (rc == WYRELOG_E_OK)
    rc = input->revalidate (input_data);
  if (rc == WYRELOG_E_OK)
    rc = tenant_import_check_bound_set (policy, fact_root, lease, &journal);
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (!identity_is_zero (&graph->staged_main_identity))
      continue;
    WylFactOfflineBackupSource *selected =
        g_ptr_array_index (selected_sources, i);
    rc = wyl_fact_root_writer_lease_verify (lease);
    if (rc == WYRELOG_E_OK)
      rc = input->revalidate (input_data);
    if (rc == WYRELOG_E_OK)
      rc = tenant_import_check_destination (policy, selected, &journal);
    if (rc == WYRELOG_E_OK)
      rc = tenant_import_check_journal (policy, &journal);
    if (rc == WYRELOG_E_OK)
      rc = tenant_import_check_bound_set (policy, fact_root, lease,
              &journal);
    if (rc != WYRELOG_E_OK)
      break;
    WylFactOfflineRestoreJournalStage *stage = NULL;
    rc = wyl_fact_offline_restore_journal_stage_new_with_lease (policy,
            fact_root, canonical_manifest, operation_uuid, graph->graph_id,
            journal.revision, lease, &stage);
    TenantImportRead read = { input, graph->graph_id, input_data };
    WylFactOfflineRestoreInput adapted = {
      tenant_import_read_at, tenant_import_revalidate,
    };
    if (rc == WYRELOG_E_OK)
      rc = import_copy (&adapted, &read, graph->logical_bytes, stage);
    if (rc == WYRELOG_E_OK)
      rc = input->revalidate (input_data);
    if (rc == WYRELOG_E_OK)
      rc = tenant_import_check_destination (policy, selected, &journal);
    if (rc == WYRELOG_E_OK)
      rc = tenant_import_check_journal (policy, &journal);
    if (rc == WYRELOG_E_OK)
      rc = tenant_import_check_bound_set (policy, fact_root, lease,
              &journal);
    if (stage != NULL) {
      WylFactOfflineRestoreJournal committed = { 0 };
      wyrelog_error_t finish_rc =
          wyl_fact_offline_restore_journal_stage_finish (stage, rc,
              &committed);
      if (rc == WYRELOG_E_OK)
        rc = finish_rc;
      if (rc == WYRELOG_E_OK) {
        wyl_fact_offline_restore_journal_clear (&journal);
        journal = committed;
        memset (&committed, 0, sizeof committed);
      }
      wyl_fact_offline_restore_journal_clear (&committed);
    }
    wyl_fact_offline_restore_journal_stage_free (stage);
  }
  if (rc == WYRELOG_E_OK)
    rc = tenant_import_check_destination (policy, NULL, &journal);
  if (rc == WYRELOG_E_OK)
    rc = tenant_import_check_journal (policy, &journal);
  if (rc == WYRELOG_E_OK)
    rc = tenant_import_check_bound_set (policy, fact_root, lease, &journal);
  if (rc == WYRELOG_E_OK)
    rc = copy_journal (&journal, out_committed);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_preflight_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactReplayJobContext *job_context,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || tenant_id == NULL || *tenant_id == '\0'
      || canonical_manifest == NULL || operation_uuid == NULL
      || *operation_uuid == '\0' || expected_revision == 0
      || expected_revision >= G_MAXINT64 || job_context == NULL
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  g_auto (WylFactOfflineRestoreJournal) observed = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (policy,
          operation_uuid, &observed);
  if (rc == WYRELOG_E_OK && observed.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (observed.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || g_strcmp0 (observed.tenant_id, tenant_id) != 0))
    rc = WYRELOG_E_POLICY;
  g_autoptr (WylFactOfflineRestoreValidationSession) session = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_validation_session_new_for_preflight
          (policy, fact_root, runtime_manager, canonical_manifest,
            operation_uuid, expected_revision, drain_timeout_us, &session);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_validation_session_run_and_record_preflight
          (session, job_context, out_committed);
  if (rc == WYRELOG_E_OK
      && (out_committed->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || out_committed->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || out_committed->graphs == NULL
      || out_committed->graphs->len != observed.graphs->len))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < out_committed->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (out_committed->graphs, i);
    if (!graph->replay_preflighted)
      rc = WYRELOG_E_POLICY;
  }
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (out_committed);
  return rc;
#endif
}

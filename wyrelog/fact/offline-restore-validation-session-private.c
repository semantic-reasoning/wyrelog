/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-restore-validation-session-private.h"

#include <string.h>

#include "fact/offline-restore-journal-store-private.h"
#include "fact/offline-restore-stage-replay-private.h"
#include "fact/root-writer-lease-private.h"

typedef struct
{
  WylFactGraphKey key;
  WylFactGraphQuiescenceToken *quiescence;
  WylFactGraphDirectory directory;
  WylFactGraphProvisionedPair *pair;
  WylFactOfflineRestoreStageReader *reader;
  gchar *provisioning_uuid;
  GBytes *provisioning_evidence;
  WylFactGraphRestoreInventory initial;
  gchar *replay_digest;
} ValidationGraph;

struct WylFactOfflineRestoreValidationSession
{
  wyl_policy_store_t *policy;
  WylFactGraphRuntimeManager *runtime;
  GBytes *manifest;
  GBytes *encoded_journal;
  WylFactOfflineRestoreJournal journal;
  WylFactRootWriterLease *lease;
  WylFactGraphResolver resolver;
  GPtrArray *graphs;
  gboolean terminal;
  gboolean record_preflight;
  wyrelog_error_t (*checkpoint) (const gchar *, gpointer);
  gpointer checkpoint_data;
  wyrelog_error_t (*record_checkpoint) (const gchar *, guint64, gboolean, gpointer);
  gpointer record_checkpoint_data;
};

#ifndef G_OS_WIN32
static void
validation_graph_free (ValidationGraph *graph)
{
  if (graph == NULL)
    return;
  g_clear_pointer (&graph->reader, wyl_fact_offline_restore_stage_reader_free);
  g_clear_pointer (&graph->pair, wyl_fact_graph_provisioned_pair_free);
  wyl_fact_graph_directory_clear (&graph->directory);
  g_clear_pointer (&graph->quiescence, wyl_fact_graph_quiescence_token_release);
  wyl_fact_graph_key_clear (&graph->key);
  g_clear_pointer (&graph->provisioning_evidence, g_bytes_unref);
  g_free (graph->provisioning_uuid);
  g_free (graph->replay_digest);
  g_free (graph);
}
#endif

static void
release_authority (WylFactOfflineRestoreValidationSession *session)
{
  g_clear_pointer (&session->graphs, g_ptr_array_unref);
  wyl_fact_graph_resolver_clear (&session->resolver);
  g_clear_pointer (&session->lease, wyl_fact_root_writer_lease_release);
}

void
wyl_fact_offline_restore_validation_session_free
  (WylFactOfflineRestoreValidationSession *session)
{
  if (session == NULL)
    return;
  release_authority (session);
  g_clear_pointer (&session->runtime, wyl_fact_graph_runtime_manager_unref);
  g_clear_pointer (&session->manifest, g_bytes_unref);
  g_clear_pointer (&session->encoded_journal, g_bytes_unref);
  wyl_fact_offline_restore_journal_clear (&session->journal);
  g_free (session);
}

void
wyl_fact_offline_restore_validation_session_set_checkpoint_for_test
  (WylFactOfflineRestoreValidationSession *session,
    wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data)
{
  if (session != NULL && !session->terminal) {
    session->checkpoint = checkpoint;
    session->checkpoint_data = data;
  }
}

void
wyl_fact_offline_restore_validation_session_set_record_checkpoint_for_test
  (WylFactOfflineRestoreValidationSession *session,
    wyrelog_error_t (*checkpoint) (const gchar *, guint64, gboolean, gpointer),
    gpointer data)
{
  if (session != NULL && !session->terminal) {
    session->record_checkpoint = checkpoint;
    session->record_checkpoint_data = data;
  }
}

#ifndef G_OS_WIN32
static gboolean
staged_phase (const WylFactOfflineRestoreJournal *journal)
{
  if ((journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
      || journal->graphs == NULL || journal->graphs->len == 0
      || journal->revision != 1 + journal->graphs->len
      || journal->confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal->policy_generation_published || journal->lifecycle_handoff_complete)
    return FALSE;
  const WylFactArtifactInventoryIdentity zero = { 0 };
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (journal->graphs, i);
    if (wyl_fact_artifact_inventory_identity_equal (&graph->staged_main_identity, &zero)
        || graph->copied || graph->checksum_verified || graph->identity_verified
        || graph->schema_verified || graph->replay_preflighted
        || graph->transition_state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
        || graph->transition_terminal || graph->resume_forbidden
        || graph->durability_unprovable_acknowledged
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
      return FALSE;
  }
  return TRUE;
}

static wyrelog_error_t
check_policy (WylFactOfflineRestoreValidationSession *session)
{
  WylPolicyFactBackupSnapshot *snapshot = NULL;
  const WylFactOfflineRestoreJournal *journal = &session->journal;
  wyrelog_error_t rc = journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      ? wyl_policy_store_read_fact_graph_backup_snapshot
        (session->policy, journal->tenant_id, journal->selected_graph_id, &snapshot)
      : wyl_policy_store_read_fact_backup_snapshot
        (session->policy, journal->tenant_id, &snapshot);
  if (rc == WYRELOG_E_OK
      && (snapshot->tenant == NULL || snapshot->graphs == NULL
      || g_strcmp0 (snapshot->tenant->tenant_id, journal->tenant_id) != 0
      || snapshot->tenant->lifecycle_state != WYL_POLICY_TENANT_LIFECYCLE_SEALED
      || !snapshot->tenant->sealed_compatibility
      || snapshot->tenant->lifecycle_generation != journal->destination_tenant_lifecycle_generation
      || snapshot->tenant->reconciliation_generation != journal->destination_tenant_reconciliation_generation
      || snapshot->graphs->len != journal->graphs->len))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *expected = g_ptr_array_index (journal->graphs, i);
    const WylPolicyFactBackupGraphSnapshot *current = g_ptr_array_index (snapshot->graphs, i);
    const WylPolicyGraphAuthorityRecord *record = current->authority;
    if (record == NULL || g_strcmp0 (record->tenant_id, journal->tenant_id) != 0
        || g_strcmp0 (record->graph_id, expected->graph_id) != 0
        || record->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED
        || !record->sealed_compatibility || !record->has_store_identity
        || record->materialization_state != WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED
        || record->last_error_class != WYL_POLICY_GRAPH_ERROR_NONE
        || record->lifecycle_generation != expected->destination_lifecycle_generation
        || record->reconciliation_generation != expected->destination_reconciliation_generation
        || g_strcmp0 (record->store_uuid, expected->store_uuid) != 0
        || record->format_version != expected->format_version
        || record->path_encoding_version != expected->path_encoding_version
        || g_strcmp0 (current->active_schema_digest, expected->schema_digest) != 0)
      rc = WYRELOG_E_POLICY;
  }
  g_clear_pointer (&snapshot, wyl_policy_fact_backup_snapshot_free);
  return rc;
}

static wyrelog_error_t
provisioning_record (WylFactOfflineRestoreValidationSession *session,
    const WylFactOfflineRestoreJournalGraph *expected,
    gchar **out_uuid, GBytes **out_evidence)
{
  *out_uuid = NULL;
  *out_evidence = NULL;
  g_autoptr (GPtrArray) records = NULL;
  wyrelog_error_t rc = session->journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      ? wyl_policy_store_graph_provisioning_list_for_graph
        (session->policy, session->journal.tenant_id, session->journal.selected_graph_id, &records)
      : wyl_policy_store_graph_provisioning_list
        (session->policy, session->journal.tenant_id, &records);
  gboolean found = FALSE;
  for (guint i = 0; rc == WYRELOG_E_OK && i < records->len; i++) {
    const WylPolicyGraphProvisioningRecord *record = g_ptr_array_index (records, i);
    if (g_strcmp0 (record->graph_id, expected->graph_id) != 0
        || record->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE)
      continue;
    if (found || g_strcmp0 (record->tenant_id, session->journal.tenant_id) != 0
        || g_strcmp0 (record->store_uuid, expected->store_uuid) != 0) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    found = TRUE;
    *out_uuid = g_strdup (record->op_uuid);
    if (record->darwin_operation_evidence != NULL)
      *out_evidence = g_bytes_ref (record->darwin_operation_evidence);
  }
  if (rc == WYRELOG_E_OK && !found)
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK) {
    g_clear_pointer (out_uuid, g_free);
    g_clear_pointer (out_evidence, g_bytes_unref);
  }
  return rc;
}

static wyrelog_error_t
open_pair (WylFactOfflineRestoreValidationSession *session,
    ValidationGraph *graph, const WylFactOfflineRestoreJournalGraph *expected)
{
  if (expected->expected_main_absent)
    return WYRELOG_E_OK;
  wyrelog_error_t rc = provisioning_record (session, expected,
          &graph->provisioning_uuid, &graph->provisioning_evidence);
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  gsize size = 0;
  const guint8 *bytes = graph->provisioning_evidence == NULL ? NULL :
      g_bytes_get_data (graph->provisioning_evidence, &size);
  if (rc == WYRELOG_E_OK)
    rc = bytes == NULL ? WYRELOG_E_POLICY :
        wyl_fact_graph_darwin_evidence_decode (bytes, size,
            graph->provisioning_uuid, &evidence);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
          (&graph->directory, graph->provisioning_uuid, &evidence, &graph->pair);
#else
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact
          (&graph->directory, graph->provisioning_uuid, &graph->pair);
#endif
  return rc;
}

static wyrelog_error_t
collect_inventory (WylFactOfflineRestoreValidationSession *session,
    ValidationGraph *graph, const WylFactOfflineRestoreJournalGraph *expected,
    WylFactGraphRestoreInventory *out_inventory)
{
  return wyl_fact_graph_directory_restore_inventory (&session->resolver,
             &graph->directory, session->lease, graph->pair,
             session->journal.operation_uuid, &expected->staged_main_identity,
             &expected->expected_main_identity, out_inventory);
}

static gboolean
observations_equal (const WylFactArtifactInventoryObservation *a,
    const WylFactArtifactInventoryObservation *b)
{
  return wyl_fact_artifact_inventory_identity_equal (&a->directory_identity, &b->directory_identity)
         && wyl_fact_artifact_inventory_identity_equal (&a->guard_identity, &b->guard_identity)
         && a->entry_fingerprint == b->entry_fingerprint;
}

static wyrelog_error_t
check_authority (WylFactOfflineRestoreValidationSession *session)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_authorizes_resolver
        (session->lease, &session->resolver);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (session);
  for (guint i = 0; rc == WYRELOG_E_OK && i < session->graphs->len; i++) {
    ValidationGraph *graph = g_ptr_array_index (session->graphs, i);
    const WylFactOfflineRestoreJournalGraph *expected = g_ptr_array_index (session->journal.graphs, i);
    WylFactGraphRuntimeStatus status = { 0 };
    rc = wyl_fact_graph_runtime_manager_get_status (session->runtime, &graph->key, &status);
    if (rc == WYRELOG_E_OK && (graph->quiescence == NULL
        || status.state == WYL_FACT_GRAPH_RUNTIME_ABANDONED
        || status.admission != WYL_FACT_GRAPH_ADMISSION_CLOSED
        || status.operation_active || status.active_engine_calls != 0
        || status.waiting_engine_calls != 0))
      rc = WYRELOG_E_BUSY;
    wyl_fact_graph_runtime_status_clear (&status);
    if (rc == WYRELOG_E_OK && !expected->expected_main_absent) {
      g_autofree gchar *uuid = NULL;
      g_autoptr (GBytes) evidence = NULL;
      rc = provisioning_record (session, expected, &uuid, &evidence);
      if (rc == WYRELOG_E_OK && (g_strcmp0 (uuid, graph->provisioning_uuid) != 0
          || ((evidence == NULL) != (graph->provisioning_evidence == NULL))
          || (evidence != NULL && !g_bytes_equal (evidence, graph->provisioning_evidence))))
        rc = WYRELOG_E_POLICY;
    }
  }
  WylFactOfflineRestoreJournal current = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (session->policy,
            session->journal.operation_uuid, &current);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&current, &encoded);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (encoded, session->encoded_journal))
    rc = WYRELOG_E_BUSY;
  wyl_fact_offline_restore_journal_clear (&current);
  return rc;
}
#endif

static wyrelog_error_t
session_new
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us, gboolean record_preflight,
    WylFactOfflineRestoreValidationSession **out_session)
{
  if (out_session != NULL)
    *out_session = NULL;
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime_manager == NULL || canonical_manifest == NULL
      || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_session == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  (void) drain_timeout_us;
  (void) record_preflight;
  return WYRELOG_E_POLICY;
#else
  WylFactOfflineRestoreValidationSession *session = g_new0 (WylFactOfflineRestoreValidationSession, 1);
  session->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  session->policy = policy;
  session->record_preflight = record_preflight;
  session->runtime = wyl_fact_graph_runtime_manager_ref (runtime_manager);
  session->manifest = g_bytes_ref (canonical_manifest);
  session->graphs = g_ptr_array_new_with_free_func ((GDestroyNotify) validation_graph_free);
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root, &session->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root, session->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy, operation_uuid, &session->journal);
  if (rc == WYRELOG_E_OK && session->journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK && (record_preflight
      ? (session->journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && session->journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
      || session->journal.confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || session->journal.manifest_trust != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || !wyl_fact_offline_restore_validation_progress_phase (&session->journal)
      : !staged_phase (&session->journal)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (canonical_manifest, &session->journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&session->journal, &session->encoded_journal);
  if (rc == WYRELOG_E_OK)
    rc = check_policy (session);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &session->resolver);
  gint64 now = g_get_monotonic_time ();
  gint64 deadline = drain_timeout_us > 0
      ? (drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 : now + drain_timeout_us) : 0;
  for (guint i = 0; rc == WYRELOG_E_OK && i < session->journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *expected = g_ptr_array_index (session->journal.graphs, i);
    ValidationGraph *graph = g_new0 (ValidationGraph, 1);
    graph->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
    g_ptr_array_add (session->graphs, graph);
    rc = wyl_fact_graph_key_init (&graph->key, session->journal.tenant_id, expected->graph_id);
    gint64 remaining = drain_timeout_us > 0 ? MAX ((gint64) 0, deadline - g_get_monotonic_time ()) : drain_timeout_us;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_runtime_manager_quiesce (session->runtime, &graph->key, remaining, &graph->quiescence);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              session->journal.tenant_id, expected->graph_id, FALSE, &graph->directory);
    if (rc == WYRELOG_E_OK)
      rc = open_pair (session, graph, expected);
    if (rc == WYRELOG_E_OK)
      rc = collect_inventory (session, graph, expected, &graph->initial);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_stage_reader_open (&session->resolver,
              &graph->directory, session->lease, operation_uuid,
              &expected->staged_main_identity, &graph->reader);
  }
  if (rc == WYRELOG_E_OK)
    rc = check_authority (session);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_offline_restore_validation_session_free (session);
    return rc;
  }
  *out_session = session;
  return WYRELOG_E_OK;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_validation_session_new
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreValidationSession **out_session)
{
  return session_new (policy, fact_root, runtime_manager, canonical_manifest,
             operation_uuid, expected_revision, drain_timeout_us, FALSE, out_session);
}

wyrelog_error_t
wyl_fact_offline_restore_validation_session_new_for_preflight
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreValidationSession **out_session)
{
  return session_new (policy, fact_root, runtime_manager, canonical_manifest,
             operation_uuid, expected_revision, drain_timeout_us, TRUE, out_session);
}

#ifndef G_OS_WIN32
static wyrelog_error_t
validate_current (WylFactOfflineRestoreValidationSession *session,
    WylFactReplayJobContext *job_context,
    WylFactOfflineRestoreValidationResult *out_result)
{
  wyrelog_error_t rc = wyl_fact_replay_job_context_checkpoint (job_context);
  GPtrArray *admission_graphs = g_ptr_array_new_with_free_func (g_free);
  GPtrArray *observations = g_ptr_array_new_with_free_func (g_free);
  for (guint i = 0; rc == WYRELOG_E_OK && i < session->graphs->len; i++) {
    ValidationGraph *graph = g_ptr_array_index (session->graphs, i);
    const WylFactOfflineRestoreJournalGraph *expected = g_ptr_array_index (session->journal.graphs, i);
    WylFactGraphRestoreInventory current = { 0 };
    rc = wyl_fact_replay_job_context_checkpoint (job_context);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_stage_reader_verify_content
            (graph->reader, expected->logical_bytes, expected->checksum);
    if (rc == WYRELOG_E_OK)
      rc = collect_inventory (session, graph, expected, &current);
    if (rc == WYRELOG_E_OK && !observations_equal (&graph->initial.observation, &current.observation))
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      break;
    WylFactOfflineRestoreAdmissionGraphEvidence *admission = g_new0 (WylFactOfflineRestoreAdmissionGraphEvidence, 1);
    *admission = (WylFactOfflineRestoreAdmissionGraphEvidence) {
      .graph_id = expected->graph_id,
      .lifecycle_generation = expected->destination_lifecycle_generation,
      .reconciliation_generation = expected->destination_reconciliation_generation,
      .expected_main_identity = current.main_identity,
      .staged_main_identity = current.stage_identity,
    };
    g_ptr_array_add (admission_graphs, admission);
    WylFactOfflineRestoreStagedObservation *observation = g_new0 (WylFactOfflineRestoreStagedObservation, 1);
    *observation = (WylFactOfflineRestoreStagedObservation) {
      .operation_uuid = session->journal.operation_uuid, .graph_id = expected->graph_id,
      .inventory_start = graph->initial.observation, .inventory_end = current.observation,
      .operation_owned_stages = 1, .present = TRUE, .regular = TRUE, .link_count = 1,
      .owner_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING,
      .identity = current.stage_identity, .logical_bytes = current.stage_bytes,
      .checksum = expected->checksum, .tenant_id = session->journal.tenant_id,
      .metadata_graph_id = expected->graph_id, .store_uuid = expected->store_uuid,
      .format_version = expected->format_version, .path_encoding_version = expected->path_encoding_version,
      .schema_digest = graph->replay_digest, .replay_result = WYL_FACT_OFFLINE_RESTORE_REPLAY_SUCCEEDED,
      .replay_identity = current.stage_identity, .replay_schema_digest = graph->replay_digest,
    };
    g_ptr_array_add (observations, observation);
  }
  if (rc == WYRELOG_E_OK)
    rc = check_authority (session);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc == WYRELOG_E_OK) {
    WylFactOfflineRestoreAdmissionEvidence admission = {
      .operation_uuid = session->journal.operation_uuid,
      .tenant_id = session->journal.tenant_id,
      .selected_graph_id = session->journal.selected_graph_id,
      .tenant_lifecycle_generation = session->journal.destination_tenant_lifecycle_generation,
      .tenant_reconciliation_generation = session->journal.destination_tenant_reconciliation_generation,
      .confirmed = TRUE, .manifest_authenticated = TRUE,
      .target_sealed = TRUE, .target_drained = TRUE,
      .exclusive_root_authority = TRUE, .inventory_stable = TRUE,
      .graphs = admission_graphs,
    };
    memcpy (admission.manifest_sha256, session->journal.manifest_sha256, sizeof admission.manifest_sha256);
    WylFactOfflineRestoreValidationMode mode = session->record_preflight
        ? WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED_PROGRESS
        : WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED;
    if (wyl_fact_offline_restore_validate (mode,
        session->manifest, &session->journal, &admission, observations, out_result)
        != WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED)
      rc = WYRELOG_E_POLICY;
  }
  g_ptr_array_unref (observations);
  g_ptr_array_unref (admission_graphs);
  return rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_validation_session_run
  (WylFactOfflineRestoreValidationSession *session,
    WylFactReplayJobContext *job_context,
    WylFactOfflineRestoreValidationResult *out_result)
{
  if (out_result != NULL) {
    memset (out_result, 0, sizeof *out_result);
    out_result->graph_index = G_MAXUINT;
  }
  if (session == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_INVALID;
  if (session->terminal || job_context == NULL || out_result == NULL)
    goto fail;
#ifdef G_OS_WIN32
  rc = WYRELOG_E_POLICY;
#else
  rc = wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc == WYRELOG_E_OK)
    rc = check_authority (session);
  for (guint i = 0; rc == WYRELOG_E_OK && i < session->graphs->len; i++) {
    ValidationGraph *graph = g_ptr_array_index (session->graphs, i);
    const WylFactOfflineRestoreJournalGraph *expected = g_ptr_array_index (session->journal.graphs, i);
    g_clear_pointer (&graph->replay_digest, g_free);
    WylFactStoreIdentity identity = {
      .tenant_id = session->journal.tenant_id, .graph_id = expected->graph_id,
      .store_uuid = expected->store_uuid, .format_version = expected->format_version,
      .path_encoding_version = expected->path_encoding_version,
    };
    wyl_policy_fact_graph_info_t selector = {
      .tenant_id = session->journal.tenant_id, .graph_id = expected->graph_id,
    };
    rc = wyl_fact_replay_job_context_checkpoint (job_context);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_stage_replay_validate (session->policy,
              graph->reader, expected->logical_bytes, expected->checksum,
              &identity, &selector, expected->schema_digest, job_context, &graph->replay_digest);
    if (rc == WYRELOG_E_OK && session->checkpoint != NULL)
      rc = session->checkpoint (expected->graph_id, session->checkpoint_data);
  }
  if (rc == WYRELOG_E_OK)
    rc = validate_current (session, job_context, out_result);
#endif
  if (rc == WYRELOG_E_OK)
    return rc;
fail:
  session->terminal = TRUE;
  release_authority (session);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_validation_session_run_and_record_preflight
  (WylFactOfflineRestoreValidationSession *session,
    WylFactReplayJobContext *job_context,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    memset (out_committed, 0, sizeof *out_committed);
  if (session == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_INVALID;
  if (session->terminal || !session->record_preflight
      || job_context == NULL || out_committed == NULL)
    goto fail;
#ifdef G_OS_WIN32
  rc = WYRELOG_E_POLICY;
#else
  WylFactOfflineRestoreValidationResult validation = { 0 };
  rc = wyl_fact_offline_restore_validation_session_run (session, job_context, &validation);
  for (guint i = 0; rc == WYRELOG_E_OK && i < session->journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (session->journal.graphs, i);
    if (graph->copied)
      continue;
    /* Journal replacement below invalidates all journal-owned pointers. */
    g_autofree gchar *graph_id = g_strdup (graph->graph_id);
    if (session->record_checkpoint != NULL)
      rc = session->record_checkpoint (graph_id, session->journal.revision, FALSE,
              session->record_checkpoint_data);
    if (rc == WYRELOG_E_OK)
      rc = validate_current (session, job_context, &validation);
    g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
    g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
    g_autoptr (GBytes) desired_bytes = NULL;
    g_autoptr (GBytes) committed_bytes = NULL;
    WylFactOfflineRestoreStoreResult result = WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_decode (session->encoded_journal, &desired);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_mark_preflight (&desired, graph_id);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&desired, &desired_bytes);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_store_cas (session->policy,
              session->journal.revision, &desired, &result, &committed);
    if (rc == WYRELOG_E_OK && result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&committed, &committed_bytes);
    if (rc == WYRELOG_E_OK && !g_bytes_equal (desired_bytes, committed_bytes))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      wyl_fact_offline_restore_journal_clear (&session->journal);
      session->journal = committed;
      memset (&committed, 0, sizeof committed);
      g_clear_pointer (&session->encoded_journal, g_bytes_unref);
      session->encoded_journal = g_bytes_ref (committed_bytes);
      if (session->record_checkpoint != NULL)
        rc = session->record_checkpoint (graph_id, session->journal.revision, TRUE,
                session->record_checkpoint_data);
    }
  }
  if (rc == WYRELOG_E_OK)
    rc = validate_current (session, job_context, &validation);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode (session->encoded_journal, out_committed);
#endif
  if (rc == WYRELOG_E_OK)
    return rc;
fail:
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  session->terminal = TRUE;
  release_authority (session);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_validation_session_with_publication_authority
  (WylFactOfflineRestoreValidationSession *session,
    WylFactReplayJobContext *job_context,
    WylFactOfflineRestorePublicationFunc callback, gpointer user_data)
{
  if (session == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_INVALID;
#ifndef G_OS_WIN32
  g_autoptr (GPtrArray) borrowed = NULL;
#endif
  if (session->terminal || !session->record_preflight
      || job_context == NULL || callback == NULL)
    goto fail;
#ifdef G_OS_WIN32
  rc = WYRELOG_E_POLICY;
#else
  for (guint i = 0; i < session->journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (session->journal.graphs, i);
    if (!graph->copied || !graph->checksum_verified
        || !graph->identity_verified || !graph->schema_verified
        || !graph->replay_preflighted) {
      rc = WYRELOG_E_POLICY;
      goto fail;
    }
  }

  /* Historical journal flags alone cannot authorize publication. Replay and
   * reobserve the entire selected scope while the session still owns every
   * graph's quiescence token and the exclusive root lease. */
  WylFactOfflineRestoreValidationResult validation = { 0 };
  rc = wyl_fact_offline_restore_validation_session_run (session, job_context,
          &validation);
  if (rc == WYRELOG_E_OK)
    rc = validate_current (session, job_context, &validation);
  if (rc != WYRELOG_E_OK)
    goto fail;

  borrowed = g_ptr_array_new_with_free_func (g_free);
  for (guint i = 0; i < session->graphs->len; i++) {
    ValidationGraph *graph = g_ptr_array_index (session->graphs, i);
    WylFactOfflineRestorePublicationGraph *view =
        g_new0 (WylFactOfflineRestorePublicationGraph, 1);
    view->graph_id = graph->key.graph_id;
    view->directory = &graph->directory;
    view->pair = graph->pair;
    g_ptr_array_add (borrowed, view);
  }
  rc = callback (&session->journal, session->lease, &session->resolver,
          borrowed, user_data);
  if (rc == WYRELOG_E_OK)
    return rc;
#endif
fail:
  session->terminal = TRUE;
  release_authority (session);
  return rc;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-prepare-private.h"

#include "fact/offline-restore-coordinator-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/offline-restore-stage-private.h"
#include "fact/root-writer-lease-private.h"
#include "fact/offline-restore-validation-private.h"
#include "fact/offline-restore-validation-session-private.h"

#include <sqlite3.h>
#include <string.h>

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*tenant_commit_admission_checkpoint) (gpointer);
static gpointer tenant_commit_admission_checkpoint_data;
static wyrelog_error_t (*graph_commit_admission_checkpoint) (gpointer);
static gpointer graph_commit_admission_checkpoint_data;

void
wyl_fact_offline_restore_tenant_commit_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer), gpointer user_data)
{
  tenant_commit_admission_checkpoint = checkpoint;
  tenant_commit_admission_checkpoint_data = user_data;
}

void
wyl_fact_offline_restore_graph_commit_admit_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer), gpointer user_data)
{
  graph_commit_admission_checkpoint = checkpoint;
  graph_commit_admission_checkpoint_data = user_data;
}
#endif

typedef struct
{
  WylFactOfflineRestoreValidationSession *session;
  WylFactOfflineRestoreJournal committed;
} PrepareJob;

static gboolean
identity_zero (const WylFactArtifactInventoryIdentity *identity)
{
  WylFactArtifactInventoryIdentity zero = { 0 };
  return wyl_fact_artifact_inventory_identity_equal (identity, &zero);
}

static wyrelog_error_t
prepare_job_run (WylFactReplayJobContext *context, gpointer data)
{
  PrepareJob *job = data;
  return wyl_fact_offline_restore_validation_session_run_and_record_preflight
           (job->session, context, &job->committed);
}
#endif

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
typedef struct
{
  wyl_policy_store_t *policy;
  WylFactOfflineRestoreValidationSession *session;
  WylFactOfflineBackupBundle *bundle;
  WylFactOfflineRestoreJournal committed;
} TenantCommitAdmission;

static wyrelog_error_t
tenant_commit_admit_callback (const WylFactOfflineRestoreJournal *journal,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    const GPtrArray *graphs, gpointer data)
{
  (void) lease;
  (void) resolver;
  (void) graphs;
  TenantCommitAdmission *admission = data;
#ifdef WYL_TEST_HANDLE_SEAMS
  if (tenant_commit_admission_checkpoint != NULL) {
    wyrelog_error_t checkpoint_rc = tenant_commit_admission_checkpoint
          (tenant_commit_admission_checkpoint_data);
    if (checkpoint_rc != WYRELOG_E_OK)
      return checkpoint_rc;
  }
#endif
  const guint8 *trusted_digest =
      wyl_fact_offline_backup_bundle_manifest_sha256 (admission->bundle);
  if (trusted_digest == NULL
      || memcmp (trusted_digest, journal->manifest_sha256, 32) != 0)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_offline_backup_bundle_revalidate
        (admission->bundle);
  WylFactOfflineRestoreStoreResult result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_decide_tenant_commit
          (admission->policy, journal, &result, &admission->committed);
  if (rc == WYRELOG_E_OK
      && result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED)
    rc = result == WYL_FACT_OFFLINE_RESTORE_STORE_STALE
        ? WYRELOG_E_BUSY : WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
tenant_commit_admit_job (WylFactReplayJobContext *context, gpointer data)
{
  TenantCommitAdmission *admission = data;
  return wyl_fact_offline_restore_validation_session_with_publication_authority
           (admission->session, context, tenant_commit_admit_callback, admission);
}

typedef struct
{
  wyl_policy_store_t *policy;
  WylFactOfflineRestoreValidationSession *session;
  WylFactOfflineBackupBundle *bundle;
  WylFactGraphRuntimeManager *runtime;
  const WylFactOfflineRestoreJournal *expected;
  WylFactRootWriterLease *lease;
  WylFactGraphResolver *resolver;
  const GPtrArray *graphs;
  WylFactReplayJobContext *context;
  WylFactOfflineRestoreJournal committed;
} GraphCommitAdmission;

static wyrelog_error_t
graph_commit_admission_proof (gpointer data)
{
  GraphCommitAdmission *admission = data;
  if (admission->expected == NULL || admission->expected->graphs == NULL
      || admission->expected->graphs->len != 1)
    return WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournalGraph *expected =
      g_ptr_array_index (admission->expected->graphs, 0);
  if (admission->lease == NULL || admission->resolver == NULL
      || admission->graphs == NULL || admission->graphs->len != 1)
    return WYRELOG_E_POLICY;
  WylFactOfflineRestorePublicationGraph *held =
      g_ptr_array_index ((GPtrArray *) admission->graphs, 0);
  if (held == NULL || held->directory == NULL || held->pair == NULL
      || g_strcmp0 (held->graph_id, expected->graph_id) != 0)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (admission->lease);
  if (rc == WYRELOG_E_OK && admission->context != NULL)
    rc = wyl_fact_replay_job_context_checkpoint (admission->context);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (admission->lease,
            admission->resolver);
  WylFactGraphKey key = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_key_init (&key, admission->expected->tenant_id,
            expected->graph_id);
  WylFactGraphRuntimeStatus status = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_get_status (admission->runtime,
            &key, &status);
  if (rc == WYRELOG_E_OK && (status.admission !=
      WYL_FACT_GRAPH_ADMISSION_CLOSED || status.operation_active
      || status.active_engine_calls != 0 || status.waiting_engine_calls != 0))
    rc = WYRELOG_E_BUSY;
  wyl_fact_graph_runtime_status_clear (&status);
  wyl_fact_graph_key_clear (&key);
  WylFactGraphRestoreInventory inventory = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_inventory (admission->resolver,
            held->directory, admission->lease, held->pair,
            admission->expected->operation_uuid,
            &expected->staged_main_identity, &expected->expected_main_identity,
            &inventory);
  if (rc == WYRELOG_E_OK && (!inventory.main_present
      || inventory.stage_bytes != expected->logical_bytes
      || !wyl_fact_artifact_inventory_identity_equal (&inventory.stage_identity,
      &expected->staged_main_identity)
      || !wyl_fact_artifact_inventory_identity_equal (&inventory.main_identity,
      &expected->expected_main_identity)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_verify (admission->lease);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (rc == WYRELOG_E_OK && graph_commit_admission_checkpoint != NULL) {
    rc = graph_commit_admission_checkpoint
          (graph_commit_admission_checkpoint_data);
  }
#endif
  return rc;
}

static wyrelog_error_t
graph_commit_admit_callback (const WylFactOfflineRestoreJournal *journal,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    const GPtrArray *graphs, gpointer data)
{
  GraphCommitAdmission *admission = data;
  if (journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || journal->graphs == NULL || journal->graphs->len != 1
      || graphs == NULL || graphs->len != 1)
    return WYRELOG_E_POLICY;
  admission->lease = lease;
  admission->resolver = resolver;
  admission->graphs = graphs;
  wyrelog_error_t rc = wyl_fact_replay_job_context_checkpoint
        (admission->context);
  if (rc != WYRELOG_E_OK)
    return rc;
  const guint8 *trusted_digest =
      wyl_fact_offline_backup_bundle_manifest_sha256 (admission->bundle);
  if (trusted_digest == NULL
      || memcmp (trusted_digest, journal->manifest_sha256, 32) != 0)
    return WYRELOG_E_POLICY;
  WylFactOfflineBackupGraphView view = { 0 };
  rc = wyl_fact_offline_backup_bundle_graph_view
        (admission->bundle, journal->selected_graph_id, &view);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (admission->bundle);
  WylFactOfflineRestoreStoreResult result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_replacement_reserve (admission->policy,
            journal, &result, &row);
  if (rc == WYRELOG_E_OK
      && result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED
      && result != WYL_FACT_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY)
    rc = result == WYL_FACT_OFFLINE_RESTORE_STORE_STALE
        ? WYRELOG_E_BUSY : WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (journal->graphs, 0);
  if (rc == WYRELOG_E_OK && (row == NULL
      || g_strcmp0 (row->operation_uuid, journal->operation_uuid) != 0
      || g_strcmp0 (row->tenant_id, journal->tenant_id) != 0
      || g_strcmp0 (row->graph_id, graph->graph_id) != 0
      || g_strcmp0 (row->old_provisioning_uuid,
      graph->old_provisioning_uuid) != 0
      || g_strcmp0 (row->phase, "reserved") != 0 || row->attempt != 0
      || row->journal_revision != journal->revision))
    rc = WYRELOG_E_POLICY;
  wyl_policy_graph_restore_replacement_record_free (row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (admission->bundle);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_decide_graph_commit
          (admission->policy, journal, graph_commit_admission_proof,
            admission, &result, &admission->committed);
  if (rc == WYRELOG_E_OK
      && result != WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED)
    rc = result == WYL_FACT_OFFLINE_RESTORE_STORE_STALE
        ? WYRELOG_E_BUSY : WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
graph_commit_admit_job (WylFactReplayJobContext *context, gpointer data)
{
  GraphCommitAdmission *admission = data;
  admission->context = context;
  return wyl_fact_offline_restore_validation_session_with_publication_authority
           (admission->session, context, graph_commit_admit_callback, admission);
}

static wyrelog_error_t
graph_commit_reload_durable (wyl_policy_store_t *policy,
    const gchar *operation_uuid, WylFactOfflineRestoreJournal *out_journal)
{
  sqlite3 *db = wyl_policy_store_get_db (policy);
  const gchar *path = db == NULL ? NULL : sqlite3_db_filename (db, "main");
  if (path == NULL || *path == '\0')
    return WYRELOG_E_IO;
  g_autoptr (wyl_policy_store_t) recovery = NULL;
  wyrelog_error_t rc = wyl_policy_store_open (path, &recovery);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_create_schema (recovery);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (recovery,
            operation_uuid, out_journal);
  return rc;
}
#endif

wyrelog_error_t
wyl_fact_offline_restore_prepare_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, WylFactReplayScheduler *scheduler,
    WylFactOfflineBackupBundle *bundle, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    GCancellable *cancellable,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || scheduler == NULL || bundle == NULL
      || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE
  (void) drain_timeout_us;
  (void) cancellable;
  return WYRELOG_E_POLICY;
#else
  g_autoptr (GBytes) manifest =
      wyl_fact_offline_backup_bundle_manifest_bytes (bundle);
  if (manifest == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  if (rc == WYRELOG_E_OK && journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION
      || journal.confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal.manifest_trust !=
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal.graphs == NULL || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (manifest, &journal);

  guint bound = 0;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (!identity_zero (&graph->staged_main_identity))
      bound++;
    else if (graph->replay_preflighted)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK && bound < journal.graphs->len) {
    if (journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT) {
      rc = wyl_fact_offline_restore_tenant_import_run (policy, fact_root,
              runtime, journal.tenant_id, manifest, operation_uuid,
              journal.revision, drain_timeout_us,
              wyl_fact_offline_backup_bundle_tenant_input (), bundle,
              out_committed);
    } else if (journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && bound == 0 && journal.revision == 1) {
      WylFactOfflineBackupGraphView view = { 0 };
      rc = wyl_fact_offline_backup_bundle_graph_view (bundle,
              journal.selected_graph_id, &view);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_offline_restore_graph_import_run (policy, fact_root,
                runtime, journal.tenant_id, journal.selected_graph_id,
                manifest, operation_uuid, journal.revision, drain_timeout_us,
                wyl_fact_offline_backup_bundle_graph_input (), &view,
                out_committed);
    } else
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      return rc;
    wyl_fact_offline_restore_journal_clear (out_committed);
    wyl_fact_offline_restore_journal_clear (&journal);
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_store_load (policy,
              operation_uuid, &journal);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_manifest_preflight (manifest, &journal);
  }
  if (rc == WYRELOG_E_OK
      && !wyl_fact_offline_restore_validation_progress_phase (&journal))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  g_autoptr (WylFactOfflineRestoreValidationSession) session = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_validation_session_new_for_preflight
          (policy, fact_root, runtime, manifest, operation_uuid,
            journal.revision, drain_timeout_us, &session);
  PrepareJob job = { .session = session };
  g_autoptr (WylFactReplayFuture) future = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_scheduler_submit (scheduler, journal.tenant_id,
            journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
            ? journal.selected_graph_id
            : ((WylFactOfflineRestoreJournalGraph *)
            g_ptr_array_index (journal.graphs, 0))->graph_id,
            cancellable, prepare_job_run, &job, NULL, &future);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_future_wait (future);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  g_auto (WylFactOfflineRestoreJournal) final = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &final);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (manifest, &final);
  g_autoptr (GBytes) worker_bytes = NULL;
  g_autoptr (GBytes) final_bytes = NULL;
  if (rc == WYRELOG_E_OK
      && (!wyl_fact_offline_restore_validation_progress_phase
        (&job.committed)
      || !wyl_fact_offline_restore_validation_progress_phase (&final)))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < final.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (final.graphs, i);
    if (!graph->replay_preflighted)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&job.committed,
            &worker_bytes);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode (&final, &final_bytes);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (worker_bytes, final_bytes))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK) {
    *out_committed = final;
    final = (WylFactOfflineRestoreJournal) { 0 };
  }
  wyl_fact_offline_restore_journal_clear (&job.committed);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_admit_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, WylFactReplayScheduler *scheduler,
    WylFactOfflineBackupBundle *bundle, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    GCancellable *cancellable,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || scheduler == NULL || bundle == NULL
      || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
  if (cancellable != NULL && g_cancellable_is_cancelled (cancellable))
    return WYRELOG_E_CANCELLED;
#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE
  (void) drain_timeout_us;
  (void) cancellable;
  return WYRELOG_E_POLICY;
#else
  wyrelog_error_t rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  const guint8 *trusted_digest =
      wyl_fact_offline_backup_bundle_manifest_sha256 (bundle);
  if (rc == WYRELOG_E_OK && (trusted_digest == NULL
      || journal.revision != expected_revision
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal.graphs == NULL || journal.graphs->len == 0
      || memcmp (trusted_digest, journal.manifest_sha256, 32) != 0))
    rc = journal.revision != expected_revision ? WYRELOG_E_BUSY
        : WYRELOG_E_POLICY;
  g_autoptr (GBytes) manifest = rc == WYRELOG_E_OK
      ? wyl_fact_offline_backup_bundle_manifest_bytes (bundle) : NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (manifest, &journal);
  g_autoptr (WylFactOfflineRestoreValidationSession) session = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_validation_session_new_for_commit_admission
          (policy, fact_root, runtime, manifest, operation_uuid,
            expected_revision, drain_timeout_us, &session);
  TenantCommitAdmission admission = {
    .policy = policy,
    .session = session,
    .bundle = bundle,
  };
  g_autoptr (WylFactReplayFuture) future = NULL;
  if (rc == WYRELOG_E_OK){
    const WylFactOfflineRestoreJournalGraph *first_graph =
        g_ptr_array_index (journal.graphs, 0);
    rc = wyl_fact_replay_scheduler_submit (scheduler, journal.tenant_id,
            first_graph->graph_id, cancellable,
            tenant_commit_admit_job, &admission, NULL, &future);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_future_wait (future);
  if (rc == WYRELOG_E_OK) {
    *out_committed = admission.committed;
    admission.committed = (WylFactOfflineRestoreJournal) { 0 };
  }
  wyl_fact_offline_restore_journal_clear (&admission.committed);
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_graph_commit_admit_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, WylFactReplayScheduler *scheduler,
    WylFactOfflineBackupBundle *bundle, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    GCancellable *cancellable,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || scheduler == NULL || bundle == NULL
      || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
  if (cancellable != NULL && g_cancellable_is_cancelled (cancellable))
    return WYRELOG_E_CANCELLED;
#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE
  (void) drain_timeout_us;
  (void) cancellable;
  return WYRELOG_E_POLICY;
#else
  wyrelog_error_t rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy,
            operation_uuid, &journal);
  const guint8 *trusted_digest =
      wyl_fact_offline_backup_bundle_manifest_sha256 (bundle);
  if (rc == WYRELOG_E_OK && (trusted_digest == NULL
      || journal.revision != expected_revision
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      || journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_HANDOFF_VERSION
      || journal.confirmation != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal.manifest_trust !=
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal.graphs == NULL || journal.graphs->len != 1
      || g_strcmp0 (journal.selected_graph_id,
      ((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (journal.graphs, 0))->graph_id) != 0
      || memcmp (trusted_digest, journal.manifest_sha256, 32) != 0))
    rc = journal.revision != expected_revision ? WYRELOG_E_BUSY
        : WYRELOG_E_POLICY;
  g_autoptr (GBytes) manifest = rc == WYRELOG_E_OK
      ? wyl_fact_offline_backup_bundle_manifest_bytes (bundle) : NULL;
  if (rc == WYRELOG_E_OK && manifest == NULL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_manifest_preflight (manifest, &journal);
  WylFactOfflineBackupGraphView view = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_graph_view (bundle,
            journal.selected_graph_id, &view);
  g_autoptr (WylFactOfflineRestoreValidationSession) session = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_validation_session_new_for_commit_admission
          (policy, fact_root, runtime, manifest, operation_uuid,
            expected_revision, drain_timeout_us, &session);
  GraphCommitAdmission admission = {
    .policy = policy,
    .session = session,
    .bundle = bundle,
    .runtime = runtime,
    .expected = &journal,
  };
  g_autoptr (WylFactReplayFuture) future = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_scheduler_submit (scheduler, journal.tenant_id,
            journal.selected_graph_id, cancellable,
            graph_commit_admit_job, &admission, NULL, &future);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_future_wait (future);

  /* A response can be lost after the guarded transaction commits. Accept only
   * the byte-for-byte canonical successor; every other state remains an
   * error and the caller must reload before constructing a fresh session. */
  if (rc != WYRELOG_E_OK) {
    wyrelog_error_t admission_rc = rc;
    wyrelog_error_t recovery_rc = WYRELOG_E_OK;
    g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
    g_auto (WylFactOfflineRestoreJournal) durable = { 0 };
    g_autoptr (GBytes) original_bytes = NULL;
    g_autoptr (GBytes) desired_bytes = NULL;
    g_autoptr (GBytes) durable_bytes = NULL;
    if (journal.revision < G_MAXINT64) {
      recovery_rc = wyl_fact_offline_restore_journal_encode (&journal,
              &original_bytes);
      if (recovery_rc == WYRELOG_E_OK)
        recovery_rc = wyl_fact_offline_restore_journal_decode (original_bytes,
                &desired);
      if (recovery_rc == WYRELOG_E_OK) {
        desired.decision = WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT;
        desired.revision++;
        recovery_rc = wyl_fact_offline_restore_journal_encode (&desired,
                &desired_bytes);
      }
      wyrelog_error_t load_rc = graph_commit_reload_durable (policy,
              operation_uuid, &durable);
      if (load_rc == WYRELOG_E_OK)
        load_rc = wyl_fact_offline_restore_journal_encode (&durable,
                &durable_bytes);
      if (recovery_rc == WYRELOG_E_OK && load_rc == WYRELOG_E_OK
          && g_bytes_equal (desired_bytes, durable_bytes)) {
        *out_committed = durable;
        durable = (WylFactOfflineRestoreJournal) { 0 };
        rc = WYRELOG_E_OK;
      }
    }
    if (rc != WYRELOG_E_OK)
      rc = admission_rc;
  }
  if (rc == WYRELOG_E_OK && admission.committed.graphs != NULL) {
    *out_committed = admission.committed;
    admission.committed = (WylFactOfflineRestoreJournal) { 0 };
  }
  wyl_fact_offline_restore_journal_clear (&admission.committed);
  return rc;
#endif
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-prepare-private.h"

#include "fact/offline-restore-coordinator-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/offline-restore-validation-private.h"
#include "fact/offline-restore-validation-session-private.h"

#include <string.h>

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t (*tenant_commit_admission_checkpoint) (gpointer);
static gpointer tenant_commit_admission_checkpoint_data;

void
wyl_fact_offline_restore_tenant_commit_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer), gpointer user_data)
{
  tenant_commit_admission_checkpoint = checkpoint;
  tenant_commit_admission_checkpoint_data = user_data;
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

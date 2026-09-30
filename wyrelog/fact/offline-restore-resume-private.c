/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-resume-private.h"

#include "fact/offline-restore-commit-authority-private.h"
#include "fact/offline-restore-journal-store-private.h"

static gint
step_rank (WylFactArtifactMainTransitionOp operation)
{
  switch (operation) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
      return 0;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
      return 1;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
      return 2;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      return 3;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      return 4;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      return 5;
    default:
      return -1;
  }
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_resume_one
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL
      || *operation_uuid == '\0' || expected_revision == 0
      || expected_revision >= G_MAXINT64 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (policy,
          operation_uuid, &journal);
  if (rc == WYRELOG_E_OK && journal.revision != expected_revision)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK
      && (journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete || journal.graphs == NULL
      || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  const WylFactOfflineRestoreJournalGraph *selected = NULL;
  gint selected_rank = 6;
  gboolean selected_unknown = FALSE;
  for (guint i = 0; rc == WYRELOG_E_OK && i < journal.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    if (graph == NULL || graph->old_provisioning_uuid == NULL
        || !graph->replay_preflighted) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    if (graph->transition_state ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
        && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
        && graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
      continue;
    gint rank = step_rank (graph->next_op);
    if (rank < 0) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    gboolean unknown = graph->attempt ==
        WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
    if (unknown && graph->pending_op != graph->next_op) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    if ((unknown && !selected_unknown)
        || (unknown == selected_unknown && rank < selected_rank)) {
      selected = graph;
      selected_rank = rank;
      selected_unknown = unknown;
    }
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  if (selected == NULL) {
    g_autoptr (GBytes) bytes = NULL;
    rc = wyl_fact_offline_restore_journal_encode (&journal, &bytes);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_decode (bytes, out_committed);
    return rc;
  }
  switch (selected->next_op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
      return wyl_fact_offline_restore_tenant_commit_sync_staged_run
               (policy, fact_root, runtime, operation_uuid,
                 selected->graph_id, expected_revision, drain_timeout_us,
                 out_committed);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
      return wyl_fact_offline_restore_tenant_commit_retain_run
               (policy, fact_root, runtime, operation_uuid,
                 selected->graph_id, expected_revision, drain_timeout_us,
                 out_committed);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
      return wyl_fact_offline_restore_tenant_commit_sync_rollback_run
               (policy, fact_root, runtime, operation_uuid,
                 selected->graph_id, expected_revision, drain_timeout_us,
                 out_committed);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      return wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
               (policy, fact_root, runtime, operation_uuid,
                 selected->graph_id, expected_revision, drain_timeout_us,
                 out_committed);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      return wyl_fact_offline_restore_tenant_commit_publish_run
               (policy, fact_root, runtime, operation_uuid,
                 selected->graph_id, expected_revision, drain_timeout_us,
                 out_committed);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      return wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
               (policy, fact_root, runtime, operation_uuid,
                 selected->graph_id, expected_revision, drain_timeout_us,
                 out_committed);
    default:
      return WYRELOG_E_POLICY;
  }
#endif
}

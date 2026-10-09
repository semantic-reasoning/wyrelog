/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-resume-private.h"

#include "fact/offline-restore-commit-authority-private.h"
#include "fact/offline-restore-journal-store-private.h"

#include <string.h>

static gint step_rank (WylFactArtifactMainTransitionOp operation);

wyrelog_error_t
wyl_fact_offline_restore_tenant_replacements_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  guint64 revision = expected_revision;
  guint steps = 0;
  guint limit = 0;
  for (;;) {
    g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
    WylPolicyOfflineRestoreRecord *record = NULL;
    g_autoptr (GBytes) canonical = NULL;
    wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load
          (policy, operation_uuid, &journal);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
              &record);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
    if (rc == WYRELOG_E_OK && (journal.revision != revision
        || record->revision != revision
        || !g_bytes_equal (canonical, record->journal_blob)))
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK
        && (journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
        || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        || journal.graphs == NULL || journal.graphs->len == 0
        || journal.policy_generation_published
        || journal.lifecycle_handoff_complete))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && limit == 0)
      limit = journal.graphs->len + 2;
    if (rc == WYRELOG_E_OK && (journal.graphs->len + 2 != limit
        || (steps >= limit && journal.version !=
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION)))
      rc = WYRELOG_E_POLICY;
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc != WYRELOG_E_OK) {
      wyl_policy_offline_restore_record_free (record);
      return rc;
    }
    if (journal.version ==
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION) {
      wyl_policy_offline_restore_record_free (record);
      return wyl_fact_offline_restore_tenant_commit_v7_prove_selected
               (policy, fact_root, runtime, operation_uuid, revision,
                 remaining, out_committed);
    }
    g_auto (WylFactOfflineRestoreJournal) result = { 0 };
    if (journal.version ==
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION) {
      rc = wyl_fact_offline_restore_tenant_commit_v5_prove_complete
            (policy, fact_root, runtime, operation_uuid, revision,
              remaining, &result);
      if (rc == WYRELOG_E_OK) {
        wyl_fact_offline_restore_journal_clear (&result);
        if (deadline > 0) {
          remaining = deadline - g_get_monotonic_time ();
          if (remaining <= 0)
            rc = WYRELOG_E_BUSY;
        }
      }
      if (rc == WYRELOG_E_OK) {
        rc = wyl_fact_offline_restore_tenant_reserve_replacements_run
              (policy, fact_root, runtime, operation_uuid, revision,
                remaining, &result);
      }
      if (rc == WYRELOG_E_OK && result.revision <= revision)
        rc = WYRELOG_E_POLICY;
    } else if (journal.version ==
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION) {
      GPtrArray *phases = NULL;
      rc = wyl_policy_store_tenant_restore_replacement_phases_load (policy,
              record, &phases);
      const gchar *selected_graph = NULL;
      guint synced = 0;
      for (guint i = 0; rc == WYRELOG_E_OK && i < phases->len; i++) {
        const gchar *phase = g_ptr_array_index (phases, i);
        if (g_str_equal (phase, "companion_synced"))
          synced++;
        else if (selected_graph == NULL && g_str_equal (phase, "reserved")) {
          const WylFactOfflineRestoreJournalGraph *graph =
              g_ptr_array_index (journal.graphs, i);
          selected_graph = graph->graph_id;
        }
      }
      if (rc == WYRELOG_E_OK && selected_graph != NULL) {
        rc = wyl_fact_offline_restore_tenant_companion_sync_run
              (policy, fact_root, runtime, operation_uuid, selected_graph,
                revision, remaining, &result);
        if (rc == WYRELOG_E_OK) {
          GPtrArray *after = NULL;
          rc = wyl_policy_store_tenant_restore_replacement_phases_load
                (policy, record, &after);
          guint after_synced = 0;
          for (guint i = 0; rc == WYRELOG_E_OK && i < after->len; i++)
            if (g_str_equal (g_ptr_array_index (after, i),
                "companion_synced"))
              after_synced++;
          if (rc == WYRELOG_E_OK && (after_synced != synced + 1
              || result.revision != revision))
            rc = WYRELOG_E_POLICY;
          g_clear_pointer (&after, g_ptr_array_unref);
        }
      } else if (rc == WYRELOG_E_OK) {
        rc = wyl_fact_offline_restore_tenant_select_replacements_run
              (policy, fact_root, runtime, operation_uuid, revision,
                remaining, &result);
        if (rc == WYRELOG_E_OK && (synced != journal.graphs->len
            || result.revision <= revision))
          rc = WYRELOG_E_POLICY;
      }
      g_clear_pointer(&phases, g_ptr_array_unref);
    } else
      rc = WYRELOG_E_POLICY;
    wyl_policy_offline_restore_record_free(record);
    if (rc != WYRELOG_E_OK)
      return rc;
    revision = result.revision;
    steps++;
  }
#endif
}

static wyrelog_error_t
graph_selected_clone_journal(const WylFactOfflineRestoreJournal *source,
    WylFactOfflineRestoreJournal *out_clone) {
  g_autoptr(GBytes) encoded = NULL;
  wyrelog_error_t rc =
      wyl_fact_offline_restore_journal_encode(source, &encoded);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode(encoded, out_clone);
  return rc;
}

static gboolean graph_selected_row_matches_journal(
  const WylPolicyGraphRestoreReplacementRecord *row,
  const WylFactOfflineRestoreJournal *journal) {
  const WylFactOfflineRestoreJournalGraph *graph =
      journal->graphs != NULL && journal->graphs->len == 1
          ? g_ptr_array_index(journal->graphs, 0)
          : NULL;
  return row != NULL && graph != NULL &&
         g_strcmp0(row->operation_uuid, journal->operation_uuid) == 0 &&
         g_strcmp0(row->tenant_id, journal->tenant_id) == 0 &&
         g_strcmp0(row->graph_id, journal->selected_graph_id) == 0 &&
         g_strcmp0(graph->graph_id, row->graph_id) == 0 &&
         g_strcmp0(graph->store_uuid, row->store_uuid) == 0 &&
         g_strcmp0(graph->old_provisioning_uuid, row->old_provisioning_uuid) ==
         0 &&
         (graph->replacement_provisioning_uuid == NULL ||
         g_strcmp0(graph->replacement_provisioning_uuid,
         row->replacement_uuid) == 0) &&
         journal->destination_tenant_lifecycle_generation ==
         row->tenant_lifecycle_generation &&
         journal->destination_tenant_reconciliation_generation ==
         row->tenant_reconciliation_generation &&
         graph->destination_lifecycle_generation ==
         row->graph_lifecycle_generation &&
         graph->destination_reconciliation_generation ==
         row->graph_reconciliation_generation;
}

static wyrelog_error_t graph_selected_load_durable(
  wyl_policy_store_t *policy, const gchar *operation_uuid,
  WylFactOfflineRestoreJournal *journal,
  WylPolicyOfflineRestoreRecord **out_record,
  WylPolicyGraphRestoreReplacementRecord **out_row, GBytes **out_canonical) {
  *out_record = NULL;
  *out_row = NULL;
  *out_canonical = NULL;
  wyrelog_error_t rc =
      wyl_policy_store_offline_restore_load(policy, operation_uuid, out_record);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode((*out_record)->journal_blob,
            journal);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_restore_replacement_load(policy, operation_uuid,
            out_row);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode(journal, out_canonical);
  if (rc == WYRELOG_E_OK &&
      ((*out_record)->revision != journal->revision ||
      (*out_record)->scope != WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH ||
      (*out_record)->graph_count != 1 ||
      g_strcmp0((*out_record)->operation_uuid, journal->operation_uuid) != 0 ||
      g_strcmp0(operation_uuid, journal->operation_uuid) != 0 ||
      g_strcmp0((*out_record)->tenant_id, journal->tenant_id) != 0 ||
      g_strcmp0((*out_record)->selected_graph_id,
      journal->selected_graph_id) != 0 ||
      memcmp((*out_record)->manifest_sha256, journal->manifest_sha256, 32) !=
      0 ||
      !g_bytes_equal(*out_canonical, (*out_record)->journal_blob)))
    rc = WYRELOG_E_BUSY;
  if (rc != WYRELOG_E_OK) {
    wyl_policy_offline_restore_record_free(*out_record);
    *out_record = NULL;
    wyl_policy_graph_restore_replacement_record_free(*out_row);
    *out_row = NULL;
    wyl_fact_offline_restore_journal_clear(journal);
    g_clear_pointer(out_canonical, g_bytes_unref);
  }
  return rc;
}

static gboolean
graph_selected_finalized_shape(const WylFactOfflineRestoreJournal *journal) {
  const WylFactOfflineRestoreJournalGraph *graph =
      journal->graphs != NULL && journal->graphs->len == 1
          ? g_ptr_array_index(journal->graphs, 0)
          : NULL;
  return journal->version ==
         WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION &&
         journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH &&
         journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT &&
         journal->replacement_selected_pending_cleanup &&
         !journal->policy_generation_published &&
         !journal->lifecycle_handoff_complete && graph != NULL &&
         graph->transition_state ==
         WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED &&
         graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE &&
         graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE &&
         graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED &&
         graph->transition_terminal;
}

wyrelog_error_t wyl_fact_offline_restore_graph_selected_finalize_resume_run(
  wyl_policy_store_t *policy, const gchar *fact_root,
  WylFactGraphRuntimeManager *runtime,
  const WylFactOfflineRestoreJournal *expected, gint64 drain_timeout_us,
  WylFactOfflineRestoreJournal *out_committed) {
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear(out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0' ||
      runtime == NULL || expected == NULL || expected->operation_uuid == NULL ||
      expected->revision == 0 || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void)drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  g_autoptr(GBytes) expected_blob = NULL;
  wyrelog_error_t rc =
      wyl_fact_offline_restore_journal_encode(expected, &expected_blob);
  const WylFactOfflineRestoreJournalGraph *expected_graph =
      expected->graphs != NULL && expected->graphs->len == 1
          ? g_ptr_array_index(expected->graphs, 0)
          : NULL;
  gboolean fresh =
      expected_graph != NULL &&
      expected_graph->transition_state ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE &&
      expected_graph->next_op ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE &&
      expected_graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE &&
      expected_graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED;
  gboolean unknown =
      expected_graph != NULL &&
      expected_graph->next_op ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE &&
      expected_graph->pending_op ==
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE &&
      expected_graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
  if (rc == WYRELOG_E_OK &&
      (expected->version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION ||
      expected->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH ||
      expected->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT ||
      !expected->replacement_selected_pending_cleanup ||
      expected->policy_generation_published ||
      expected->lifecycle_handoff_complete || expected_graph == NULL ||
      (!fresh && !unknown)))
    rc = WYRELOG_E_POLICY;
  WylFactOfflineRestoreJournal current = {0};
  WylPolicyOfflineRestoreRecord *record = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  g_autoptr(GBytes) current_blob = NULL;
  if (rc == WYRELOG_E_OK)
    rc = graph_selected_load_durable(policy, expected->operation_uuid, &current,
            &record, &row, &current_blob);
  if (rc == WYRELOG_E_OK &&
      (!graph_selected_row_matches_journal(row, &current) ||
      !g_str_equal(row->phase, "selected_pending_cleanup")))
    rc = WYRELOG_E_POLICY;

  gboolean exact_input = rc == WYRELOG_E_OK &&
      current.revision == expected->revision &&
      g_bytes_equal(current_blob, expected_blob);

  g_auto(WylFactOfflineRestoreJournal) pending = {0};
  g_auto(WylFactOfflineRestoreJournal) completed = {0};
  g_autoptr(GBytes) pending_blob = NULL;
  g_autoptr(GBytes) completed_blob = NULL;
  if (rc == WYRELOG_E_OK)
    rc = graph_selected_clone_journal(expected, &pending);
  if (rc == WYRELOG_E_OK && fresh)
    rc = wyl_fact_offline_restore_journal_begin_attempt(
      &pending, pending.selected_graph_id,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode(&pending, &pending_blob);
  if (rc == WYRELOG_E_OK)
    rc = graph_selected_clone_journal(&pending, &completed);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_complete_attempt(
      &completed, completed.selected_graph_id,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE, TRUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode(&completed, &completed_blob);
  gboolean lost_begin = rc == WYRELOG_E_OK && fresh && !exact_input &&
      current.revision == expected->revision + 1 &&
      g_bytes_equal(current_blob, pending_blob);
  gboolean lost_complete =
      rc == WYRELOG_E_OK && !exact_input &&
      graph_selected_finalized_shape(&current) &&
      current.revision == expected->revision + (fresh ? 2 : 1) &&
      g_bytes_equal(current_blob, completed_blob);
  if (rc == WYRELOG_E_OK && !exact_input && !lost_begin && !lost_complete)
    rc = WYRELOG_E_BUSY;
  wyl_policy_offline_restore_record_free(record);
  record = NULL;
  wyl_policy_graph_restore_replacement_record_free(row);
  row = NULL;
  wyl_fact_offline_restore_journal_clear(&current);
  g_clear_pointer(&current_blob, g_bytes_unref);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (lost_complete)
    return wyl_fact_offline_restore_graph_commit_finalized_prove_terminal(
      policy, fact_root, runtime, &completed, drain_timeout_us,
      out_committed);
  guint64 revision = lost_begin ? pending.revision : expected->revision;
  g_auto(WylFactOfflineRestoreJournal) result = {0};
  rc = wyl_fact_offline_restore_graph_commit_finalize_run(
    policy, fact_root, runtime, expected->operation_uuid, revision,
    drain_timeout_us, &result);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_graph_commit_finalized_prove_terminal(
      policy, fact_root, runtime, &result, drain_timeout_us, out_committed);
  return rc;
#endif
}

wyrelog_error_t wyl_fact_offline_restore_graph_selected_promote_resume_run(
  wyl_policy_store_t *policy, const gchar *fact_root,
  WylFactGraphRuntimeManager *runtime,
  const WylFactOfflineRestoreJournal *finalized, gint64 drain_timeout_us,
  WylFactOfflineRestoreJournal *out_committed) {
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear(out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0' ||
      runtime == NULL || finalized == NULL ||
      finalized->operation_uuid == NULL || finalized->revision == 0 ||
      out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void)drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  g_autoptr(GBytes) finalized_blob = NULL;
  wyrelog_error_t rc =
      wyl_fact_offline_restore_journal_encode(finalized, &finalized_blob);
  if (rc == WYRELOG_E_OK && !graph_selected_finalized_shape(finalized))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    wyrelog_error_t terminal_rc =
        wyl_fact_offline_restore_graph_commit_published_prove_terminal(
      policy, fact_root, runtime, finalized, drain_timeout_us,
      out_committed);
    if (terminal_rc == WYRELOG_E_OK)
      return WYRELOG_E_OK;
    if (terminal_rc != WYRELOG_E_POLICY)
      return terminal_rc;
  }
  WylPolicyOfflineRestoreRecord *record = NULL;
  WylFactOfflineRestoreJournal current = {0};
  g_autoptr(GBytes) current_blob = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_load(policy, finalized->operation_uuid,
            &record);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_decode(record->journal_blob, &current);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_encode(&current, &current_blob);
  if (rc == WYRELOG_E_OK &&
      (record->revision != current.revision ||
      record->scope != WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH ||
      record->graph_count != 1 ||
      g_strcmp0(record->operation_uuid, current.operation_uuid) != 0 ||
      g_strcmp0(record->tenant_id, current.tenant_id) != 0 ||
      g_strcmp0(record->selected_graph_id, current.selected_graph_id) != 0 ||
      memcmp(record->manifest_sha256, current.manifest_sha256, 32) != 0 ||
      !g_bytes_equal(current_blob, record->journal_blob)))
    rc = WYRELOG_E_BUSY;
  gboolean candidate_terminal = rc == WYRELOG_E_OK &&
      current.version == WYL_FACT_OFFLINE_RESTORE_JOURNAL_PUBLISHED_VERSION &&
      current.revision == finalized->revision + 2;
  if (candidate_terminal) {
    wyl_policy_offline_restore_record_free(record);
    wyl_fact_offline_restore_journal_clear(&current);
    return wyl_fact_offline_restore_graph_commit_published_prove_terminal(
      policy, fact_root, runtime, finalized, drain_timeout_us, out_committed);
  }
  gboolean exact_input = rc == WYRELOG_E_OK &&
      current.revision == finalized->revision &&
      g_bytes_equal(current_blob, finalized_blob);
  if (rc == WYRELOG_E_OK && !exact_input)
    rc = WYRELOG_E_BUSY;
  wyl_policy_offline_restore_record_free(record);
  record = NULL;
  wyl_fact_offline_restore_journal_clear(&current);
  g_clear_pointer(&current_blob, g_bytes_unref);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylPolicyOfflineRestoreRecord *checked_record = NULL;
  WylPolicyGraphRestoreReplacementRecord *row = NULL;
  WylFactOfflineRestoreJournal selected = {0};
  g_autoptr(GBytes) selected_blob = NULL;
  rc = graph_selected_load_durable(policy, finalized->operation_uuid, &selected,
          &checked_record, &row, &selected_blob);
  if (rc == WYRELOG_E_OK &&
      (!graph_selected_row_matches_journal(row, &selected) ||
      !g_str_equal(row->phase, "selected_pending_cleanup")))
    rc = WYRELOG_E_POLICY;
  wyl_policy_offline_restore_record_free(checked_record);
  wyl_policy_graph_restore_replacement_record_free(row);
  wyl_fact_offline_restore_journal_clear(&selected);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_auto(WylFactOfflineRestoreJournal) promoted = {0};
  rc = wyl_fact_offline_restore_graph_commit_promote_run(
    policy, fact_root, runtime, finalized->operation_uuid,
    finalized->revision, drain_timeout_us, &promoted);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (promoted.revision != finalized->revision + 2
      || promoted.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_PUBLISHED_VERSION
      || promoted.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || !promoted.lifecycle_handoff_complete)
    return WYRELOG_E_POLICY;
  /* Promotion stores a terminal receipt and removes the live journal in the
   * same transaction. Return the journal state proven by that promotion. */
  *out_committed = promoted;
  memset (&promoted, 0, sizeof promoted);
  return WYRELOG_E_OK;
#endif
}

wyrelog_error_t wyl_fact_offline_restore_tenant_selected_cleanup_run(
  wyl_policy_store_t *policy, const gchar *fact_root,
  WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
  guint64 expected_revision, gint64 drain_timeout_us,
  WylFactOfflineRestoreJournal *out_committed) {
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear(out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0' ||
      runtime == NULL || operation_uuid == NULL || *operation_uuid == '\0' ||
      expected_revision == 0 || expected_revision >= G_MAXINT64 ||
      out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void)drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64
                                                   : now + drain_timeout_us;
  }
  guint64 revision = expected_revision;
  guint steps = 0;
  guint limit = 0;
  for (;;) {
    g_auto(WylFactOfflineRestoreJournal) journal = {0};
    WylPolicyOfflineRestoreRecord *record = NULL;
    g_autoptr(GBytes) canonical = NULL;
    wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load(
      policy, operation_uuid, &journal);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_offline_restore_load(policy, operation_uuid,
              &record);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode(&journal, &canonical);
    if (rc == WYRELOG_E_OK &&
        (journal.revision != revision || record->revision != revision ||
        !g_bytes_equal(canonical, record->journal_blob)))
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK &&
        (journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT ||
        journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT ||
        journal.graphs == NULL || journal.graphs->len == 0))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && limit == 0)
      limit = journal.graphs->len + 1;
    if (rc == WYRELOG_E_OK && (journal.graphs->len + 1 != limit
        || (steps >= limit && journal.version !=
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION)))
      rc = WYRELOG_E_POLICY;
    gint64 remaining = drain_timeout_us;
    if (rc == WYRELOG_E_OK && deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        rc = WYRELOG_E_BUSY;
    }
    if (rc != WYRELOG_E_OK) {
      wyl_policy_offline_restore_record_free (record);
      return rc;
    }
    if (journal.version ==
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION) {
      wyl_policy_offline_restore_record_free (record);
      return wyl_fact_offline_restore_tenant_commit_v8_prove_terminal
               (policy, fact_root, runtime, operation_uuid, revision,
                 remaining, out_committed);
    }
    if (journal.version !=
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION
        || !journal.replacement_selected_pending_cleanup
        || journal.policy_generation_published
        || journal.lifecycle_handoff_complete) {
      wyl_policy_offline_restore_record_free (record);
      return WYRELOG_E_POLICY;
    }
    rc = wyl_policy_store_tenant_restore_reacquire_v7_prove (policy, record);
    if (rc != WYRELOG_E_OK) {
      wyl_policy_offline_restore_record_free (record);
      return rc;
    }
    const WylFactOfflineRestoreJournalGraph *selected = NULL;
    gboolean selected_unknown = FALSE;
    for (guint i = 0; i < journal.graphs->len; i++) {
      const WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal.graphs, i);
      gboolean finalized = graph->transition_state ==
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
          && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          && graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
          && graph->transition_terminal;
      if (graph->expected_main_absent || !graph->replay_preflighted
          || graph->old_provisioning_uuid == NULL
          || graph->replacement_provisioning_uuid == NULL) {
        rc = WYRELOG_E_POLICY;
        break;
      }
      if (finalized)
        continue;
      gboolean unknown = graph->attempt ==
          WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
      gboolean pending = graph->transition_state ==
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
          && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
          && graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED;
      gboolean retry = graph->next_op ==
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
          && graph->pending_op ==
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE && unknown;
      if (!pending && !retry) {
        rc = WYRELOG_E_POLICY;
        break;
      }
      if (selected == NULL || (unknown && !selected_unknown)) {
        selected = graph;
        selected_unknown = unknown;
      }
    }
    if (rc != WYRELOG_E_OK) {
      wyl_policy_offline_restore_record_free (record);
      return rc;
    }
    g_auto (WylFactOfflineRestoreJournal) result = { 0 };
    if (selected == NULL)
      rc = wyl_fact_offline_restore_tenant_promote_run (policy, fact_root,
              runtime, operation_uuid, revision, remaining, &result);
    else
      rc = wyl_fact_offline_restore_tenant_finalize_graph_run
            (policy, fact_root, runtime, operation_uuid, selected->graph_id,
              revision, remaining, &result);
    wyl_policy_offline_restore_record_free (record);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (result.version !=
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION
        && result.version !=
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION)
      return WYRELOG_E_POLICY;
    if (result.revision <= revision)
      return WYRELOG_E_POLICY;
    revision = result.revision;
    steps++;
  }
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_tenant_commit_v5_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (policy == NULL || fact_root == NULL || *fact_root == '\0'
      || runtime == NULL || operation_uuid == NULL || *operation_uuid == '\0'
      || expected_revision == 0 || expected_revision >= G_MAXINT64
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
#ifndef __linux__
  (void) drain_timeout_us;
  return WYRELOG_E_POLICY;
#else
  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  guint64 revision = expected_revision;
  for (;;) {
    g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
    WylPolicyOfflineRestoreRecord *record = NULL;
    g_autoptr (GBytes) canonical = NULL;
    wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load
          (policy, operation_uuid, &journal);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
              &record);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
    if (rc == WYRELOG_E_OK && (journal.revision != revision
        || record->revision != revision
        || !g_bytes_equal (canonical, record->journal_blob)))
      rc = WYRELOG_E_BUSY;
    wyl_policy_offline_restore_record_free (record);
    if (rc == WYRELOG_E_OK
        && (journal.version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
        || journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
        || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        || journal.graphs == NULL || journal.graphs->len == 0
        || journal.policy_generation_published
        || journal.lifecycle_handoff_complete))
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      return rc;
    const WylFactOfflineRestoreJournalGraph *selected = NULL;
    gboolean terminal = TRUE;
    for (guint i = 0; i < journal.graphs->len; i++) {
      const WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal.graphs, i);
      if (graph == NULL || graph->old_provisioning_uuid == NULL
          || !graph->replay_preflighted || graph->expected_main_absent)
        return WYRELOG_E_POLICY;
      gboolean done = graph->transition_state ==
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
          && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
          && graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
          && !graph->transition_terminal;
      if (done)
        continue;
      terminal = FALSE;
      gint rank = step_rank (graph->next_op);
      if (rank < 0)
        return WYRELOG_E_POLICY;
      if (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
          && graph->pending_op != graph->next_op)
        return WYRELOG_E_POLICY;
      if (!wyl_fact_offline_restore_tenant_commit_step_eligible
            (&journal, graph->graph_id, graph->next_op))
        continue;
      gboolean unknown = graph->attempt ==
          WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
      gboolean selected_unknown = selected != NULL && selected->attempt ==
          WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
      if (selected == NULL || (unknown && !selected_unknown)
          || (unknown == selected_unknown
          && rank < step_rank (selected->next_op)))
        selected = graph;
    }
    gint64 remaining = drain_timeout_us;
    if (deadline > 0) {
      remaining = deadline - g_get_monotonic_time ();
      if (remaining <= 0)
        return WYRELOG_E_BUSY;
    }
    if (terminal)
      return wyl_fact_offline_restore_tenant_commit_v5_prove_complete
               (policy, fact_root, runtime, operation_uuid, revision,
                 remaining, out_committed);
    if (selected == NULL)
      return WYRELOG_E_POLICY;
    g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
    switch (selected->next_op) {
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
        rc = wyl_fact_offline_restore_tenant_commit_sync_staged_run
              (policy, fact_root, runtime, operation_uuid,
                selected->graph_id, revision, remaining, &committed);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
        rc = wyl_fact_offline_restore_tenant_commit_retain_run
              (policy, fact_root, runtime, operation_uuid,
                selected->graph_id, revision, remaining, &committed);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
        rc = wyl_fact_offline_restore_tenant_commit_sync_rollback_run
              (policy, fact_root, runtime, operation_uuid,
                selected->graph_id, revision, remaining, &committed);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
        rc = wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
              (policy, fact_root, runtime, operation_uuid,
                selected->graph_id, revision, remaining, &committed);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
        rc = wyl_fact_offline_restore_tenant_commit_publish_run
              (policy, fact_root, runtime, operation_uuid,
                selected->graph_id, revision, remaining, &committed);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
        rc = wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
              (policy, fact_root, runtime, operation_uuid,
                selected->graph_id, revision, remaining, &committed);
        break;
      default:
        return WYRELOG_E_POLICY;
    }
    if (rc != WYRELOG_E_OK)
      return rc;
    if (committed.revision <= revision)
      return WYRELOG_E_POLICY;
    revision = committed.revision;
  }
#endif
}

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
      && (journal.scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      || journal.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal.graphs == NULL
      || journal.graphs->len == 0))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    return rc;
  if (journal.version ==
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION) {
    WylPolicyOfflineRestoreRecord *expected = NULL;
    GPtrArray *phases = NULL;
    rc = wyl_policy_store_offline_restore_load (policy, operation_uuid,
            &expected);
    if (rc == WYRELOG_E_OK && expected->revision != expected_revision)
      rc = WYRELOG_E_BUSY;
    g_autoptr (GBytes) canonical = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_encode (&journal, &canonical);
    if (rc == WYRELOG_E_OK
        && !g_bytes_equal (canonical, expected->journal_blob))
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_tenant_restore_replacement_phases_load (policy,
              expected, &phases);
    const gchar *selected_graph = NULL;
    for (guint i = 0; rc == WYRELOG_E_OK && i < phases->len; i++) {
      if (g_str_equal (g_ptr_array_index (phases, i), "reserved")) {
        const WylFactOfflineRestoreJournalGraph *graph =
            g_ptr_array_index (journal.graphs, i);
        selected_graph = graph->graph_id;
        break;
      }
    }
    if (rc == WYRELOG_E_OK)
      rc = selected_graph != NULL ?
          wyl_fact_offline_restore_tenant_companion_sync_run
            (policy, fact_root, runtime, operation_uuid, selected_graph,
              expected_revision, drain_timeout_us, out_committed) :
          wyl_fact_offline_restore_tenant_select_replacements_run
            (policy, fact_root, runtime, operation_uuid, expected_revision,
              drain_timeout_us, out_committed);
    g_clear_pointer (&phases, g_ptr_array_unref);
    wyl_policy_offline_restore_record_free (expected);
    return rc;
  }
  if (journal.version ==
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION) {
    const WylFactOfflineRestoreJournalGraph *selected = NULL;
    gboolean selected_unknown = FALSE;
    if (!journal.replacement_selected_pending_cleanup
        || journal.policy_generation_published
        || journal.lifecycle_handoff_complete)
      return WYRELOG_E_POLICY;
    for (guint i = 0; i < journal.graphs->len; i++) {
      const WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal.graphs, i);
      gboolean terminal = graph->transition_state ==
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
          && graph->transition_terminal
          && graph->next_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          && graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED;
      if (terminal)
        continue;
      gboolean unknown = graph->attempt ==
          WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
      if (graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
          || (unknown && graph->pending_op !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE)
          || (!unknown && (graph->transition_state !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
          || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED)))
        return WYRELOG_E_POLICY;
      if (selected == NULL || (unknown && !selected_unknown)) {
        selected = graph;
        selected_unknown = unknown;
      }
    }
    if (selected != NULL)
      return wyl_fact_offline_restore_tenant_finalize_graph_run
               (policy, fact_root, runtime, operation_uuid,
                 selected->graph_id, expected_revision, drain_timeout_us,
                 out_committed);
    g_auto (WylFactOfflineRestoreJournal) promoted = { 0 };
    rc = wyl_fact_offline_restore_tenant_promote_run (policy, fact_root,
            runtime, operation_uuid, expected_revision, drain_timeout_us,
            &promoted);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (promoted.version !=
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION
        || promoted.decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        || !promoted.lifecycle_handoff_complete)
      return WYRELOG_E_POLICY;
    /* Promotion proves the committed handoff; terminal filesystem proof runs
     * after this stage and retains the live journal until then. */
    *out_committed = promoted;
    memset (&promoted, 0, sizeof promoted);
    return WYRELOG_E_OK;
  }
  if (journal.version ==
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION) {
    if (!journal.replacement_selected_pending_cleanup
        || !journal.policy_generation_published
        || !journal.lifecycle_handoff_complete)
      return WYRELOG_E_POLICY;
    for (guint i = 0; i < journal.graphs->len; i++) {
      const WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal.graphs, i);
      if (graph->transition_state !=
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
          || !graph->transition_terminal
          || graph->next_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
          || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED)
        return WYRELOG_E_POLICY;
    }
    return wyl_fact_offline_restore_tenant_commit_v8_prove_terminal
             (policy, fact_root, runtime, operation_uuid, expected_revision,
               drain_timeout_us, out_committed);
  }
  if (journal.version !=
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION
      || journal.policy_generation_published
      || journal.lifecycle_handoff_complete)
    return WYRELOG_E_POLICY;
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
    return wyl_fact_offline_restore_tenant_reserve_replacements_run
             (policy, fact_root, runtime, operation_uuid, expected_revision,
               drain_timeout_us, out_committed);
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

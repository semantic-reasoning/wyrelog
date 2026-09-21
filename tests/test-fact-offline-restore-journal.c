/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>

#include "wyrelog/fact/offline-restore-journal-private.h"

#define OP "018f22d0-7b6d-7a5b-8c31-123456789abc"

static WylFactArtifactInventoryIdentity
identity (guint64 object)
{
  WylFactArtifactInventoryIdentity value = {
    .domain = 1, .object = object, .object_width = 0,
  };
  return value;
}

static GBytes *
manifest_bytes (gboolean two_graphs)
{
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init
        (&manifest, "tenant-a", 7), ==, WYRELOG_E_OK);
  WylFactOfflineBackupArtifact first = {
    .graph_id = "alpha", .store_uuid = "store-alpha",
    .format_version = 1, .path_encoding_version = 1,
    .schema_digest = "schema-alpha", .logical_bytes = 10,
    .physical_bytes = 4096, .checksum = "sha256:alpha",
  };
  WylFactOfflineBackupArtifact second = {
    .graph_id = "zeta", .store_uuid = "store-zeta",
    .format_version = 1, .path_encoding_version = 1,
    .schema_digest = "schema-zeta", .logical_bytes = 20,
    .physical_bytes = 8192, .checksum = "sha256:zeta",
  };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add
        (&manifest, &first), ==, WYRELOG_E_OK);
  if (two_graphs)
    g_assert_cmpint (wyl_fact_offline_backup_manifest_add
          (&manifest, &second), ==, WYRELOG_E_OK);
  GBytes *bytes = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode
        (&manifest, &bytes), ==, WYRELOG_E_OK);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  return bytes;
}

static GPtrArray *
target_graphs (void)
{
  GPtrArray *targets = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_restore_target_graph_free);
  WylFactOfflineRestoreTargetGraph *alpha = g_new0
        (WylFactOfflineRestoreTargetGraph, 1);
  alpha->graph_id = g_strdup ("alpha");
  alpha->lifecycle_generation = 11;
  alpha->reconciliation_generation = 12;
  alpha->expected_main_identity = identity (101);
  g_ptr_array_add (targets, alpha);
  WylFactOfflineRestoreTargetGraph *zeta = g_new0
        (WylFactOfflineRestoreTargetGraph, 1);
  zeta->graph_id = g_strdup ("zeta");
  zeta->lifecycle_generation = 21;
  zeta->reconciliation_generation = 22;
  zeta->expected_main_absent = TRUE;
  g_ptr_array_add (targets, zeta);
  return targets;
}

static void
round_trip_and_scope (void)
{
  g_autoptr (GBytes) manifest = manifest_bytes (TRUE);
  g_autoptr (GPtrArray) targets = target_graphs ();
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  g_assert_cmpuint (journal.graphs->len, ==, 2);
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&journal, &encoded), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournal decoded = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode
        (encoded, &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpstr (decoded.operation_uuid, ==, OP);
  g_assert_cmpstr (decoded.tenant_id, ==, "tenant-a");
  g_assert_cmpuint (decoded.graphs->len, ==, 2);
  g_autoptr (GBytes) reencoded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&decoded, &reencoded), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (encoded, reencoded));
  wyl_fact_offline_restore_journal_clear (&decoded);
  wyl_fact_offline_restore_journal_clear (&journal);

  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP, WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "zeta", 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  g_assert_cmpuint (journal.graphs->len, ==, 1);
  WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
        (journal.graphs, 0);
  g_assert_cmpstr (graph->graph_id, ==, "zeta");
  wyl_fact_offline_restore_journal_clear (&journal);
}

static void
admission_is_fail_closed (void)
{
  g_autoptr (GBytes) manifest = manifest_bytes (TRUE);
  g_autoptr (GPtrArray) targets = target_graphs ();
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreAdmissionEvidence evidence = {
    .operation_uuid = OP, .tenant_id = "tenant-a",
    .tenant_lifecycle_generation = 31,
    .tenant_reconciliation_generation = 32,
    .confirmed = TRUE, .manifest_authenticated = TRUE,
    .target_sealed = TRUE, .target_drained = TRUE,
    .exclusive_root_authority = TRUE, .inventory_stable = TRUE,
  };
  WylFactOfflineRestoreAdmissionGraphEvidence graph_evidence[2] = { 0 };
  g_autoptr (GPtrArray) evidence_graphs = g_ptr_array_new ();
  for (guint i = 0; i < journal.graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal.graphs, i);
    graph_evidence[i].graph_id = graph->graph_id;
    graph_evidence[i].lifecycle_generation =
        graph->destination_lifecycle_generation;
    graph_evidence[i].reconciliation_generation =
        graph->destination_reconciliation_generation;
    graph_evidence[i].expected_main_identity = graph->expected_main_identity;
    graph_evidence[i].staged_main_identity = graph->staged_main_identity;
    g_ptr_array_add (evidence_graphs, &graph_evidence[i]);
  }
  evidence.graphs = evidence_graphs;
  memcpy (evidence.manifest_sha256, journal.manifest_sha256,
      sizeof evidence.manifest_sha256);
  g_assert_cmpint (wyl_fact_offline_restore_classify_admission
        (&journal, &evidence),
      ==, WYL_FACT_OFFLINE_RESTORE_CONFLICT_NONE);
  evidence.unknown_artifacts = 1;
  g_assert_cmpint (wyl_fact_offline_restore_classify_admission
        (&journal, &evidence),
      ==, WYL_FACT_OFFLINE_RESTORE_CONFLICT_UNKNOWN_ARTIFACT);
  evidence.unknown_artifacts = 0;
  graph_evidence[0].lifecycle_generation++;
  g_assert_cmpint (wyl_fact_offline_restore_classify_admission
        (&journal, &evidence), ==,
      WYL_FACT_OFFLINE_RESTORE_CONFLICT_GENERATION);
  graph_evidence[0].lifecycle_generation--;
  graph_evidence[0].expected_main_identity.object++;
  g_assert_cmpint (wyl_fact_offline_restore_classify_admission
        (&journal, &evidence), ==,
      WYL_FACT_OFFLINE_RESTORE_CONFLICT_INVENTORY);
  graph_evidence[0].expected_main_identity.object--;
  evidence.foreign_main = TRUE;
  g_assert_cmpint (wyl_fact_offline_restore_classify_admission
        (&journal, &evidence),
      ==, WYL_FACT_OFFLINE_RESTORE_CONFLICT_FOREIGN_MAIN);
  g_assert_cmpint (wyl_fact_offline_restore_classify_admission (NULL, NULL),
      ==, WYL_FACT_OFFLINE_RESTORE_CONFLICT_AUTHORITY);
  wyl_fact_offline_restore_journal_clear (&journal);
}

static void
complete_step (WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    WylFactArtifactMainTransitionOp operation,
    WylFactArtifactMainTransitionState state,
    WylFactArtifactMainTransitionOp next_operation, gboolean terminal)
{
  g_assert_cmpint (wyl_fact_offline_restore_journal_begin_attempt
        (journal, graph_id, operation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_complete_attempt
        (journal, graph_id, state, next_operation, terminal), ==,
      WYRELOG_E_OK);
}

static void
decision_barrier_and_recovery (void)
{
  g_autoptr (GBytes) manifest = manifest_bytes (TRUE);
  g_autoptr (GPtrArray) targets = target_graphs ();
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&journal,
      WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_ROLLBACK);
  WylFactArtifactInventoryIdentity alpha_stage = identity (201);
  WylFactArtifactInventoryIdentity zeta_stage = {
    .domain = 2, .object_width = 16,
    .object_bytes = { 0xca, 0xfe, 0xba, 0xbe },
  };
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, "alpha", &alpha_stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_preflight
        (&journal, "alpha"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&journal,
      WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, "zeta", &zeta_stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_preflight
        (&journal, "zeta"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&journal,
      WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_CONTINUE_COMMIT);
  g_autoptr (GBytes) before_rejection = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&journal, &before_rejection), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_begin_attempt (&journal,
      "alpha", WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE), ==,
      WYRELOG_E_POLICY);
  g_autoptr (GBytes) after_rejection = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&journal, &after_rejection), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (before_rejection, after_rejection));
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN, FALSE);
  g_assert_cmpint (wyl_fact_offline_restore_journal_begin_attempt (&journal,
      "alpha", WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_INSPECT_ONLY);
  g_assert_cmpint (wyl_fact_offline_restore_journal_complete_attempt (&journal,
      "alpha", WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE, FALSE), ==,
      WYRELOG_E_OK);
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR, FALSE);
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH, FALSE);
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR, FALSE);
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE, FALSE);
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE, TRUE);

  complete_step (&journal, "zeta",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH, FALSE);
  complete_step (&journal, "zeta",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR, FALSE);
  complete_step (&journal, "zeta",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE, FALSE);
  complete_step (&journal, "zeta",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE, TRUE);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_POLICY_CAS);
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_lifecycle_handoff
        (&journal), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_policy_published
        (&journal), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_LIFECYCLE_HANDOFF);
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_lifecycle_handoff
        (&journal), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);
  wyl_fact_offline_restore_journal_clear (&journal);
}

static void
rollback_converges (void)
{
  g_autoptr (GBytes) manifest = manifest_bytes (TRUE);
  g_autoptr (GPtrArray) targets = target_graphs ();
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  WylFactArtifactInventoryIdentity staged = identity (301);
  guint64 revision = journal.revision;
  journal.revision = G_MAXUINT64;
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, "alpha", &staged), ==, WYRELOG_E_POLICY);
  WylFactOfflineRestoreJournalGraph *alpha = g_ptr_array_index
        (journal.graphs, 0);
  g_assert_cmpuint (alpha->staged_main_identity.object_width, ==, 0);
  journal.revision = revision;
  WylFactArtifactInventoryIdentity invalid = identity (302);
  invalid.object_width = 8;
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, "alpha", &invalid), ==, WYRELOG_E_POLICY);
  WylFactOfflineRestoreJournalGraph *alpha_graph = g_ptr_array_index
        (journal.graphs, 0);
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, "alpha", &alpha_graph->expected_main_identity), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, "alpha", &staged), ==, WYRELOG_E_OK);
  WylFactArtifactInventoryIdentity saved_stage =
      alpha_graph->staged_main_identity;
  alpha_graph->staged_main_identity = alpha_graph->expected_main_identity;
  g_autoptr (GBytes) stage_is_main = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&journal, &stage_is_main), ==, WYRELOG_E_INVALID);
  alpha_graph->staged_main_identity = saved_stage;
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&journal,
      WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_begin_attempt (&journal,
      "alpha", WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED), ==,
      WYRELOG_E_POLICY);
  alpha_graph->transition_state =
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED;
  alpha_graph->next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK;
  g_autoptr (GBytes) retained_recovery = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&journal, &retained_recovery), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_ROLLBACK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_begin_attempt (&journal,
      "alpha", WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK), ==,
      WYRELOG_E_OK);
  guint64 attempted_revision = journal.revision;
  g_assert_cmpint (wyl_fact_offline_restore_journal_complete_attempt (&journal,
      "alpha", WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE, FALSE), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (journal.revision, ==, attempted_revision);
  g_assert_cmpint (alpha_graph->transition_state, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED);
  g_assert_cmpint (alpha_graph->attempt, ==,
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
  g_assert_cmpint (wyl_fact_offline_restore_journal_complete_attempt (&journal,
      "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK, FALSE), ==,
      WYRELOG_E_OK);
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE, FALSE);
  complete_step (&journal, "alpha",
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE, TRUE);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&journal), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);

  wyl_fact_offline_restore_journal_clear (&journal);
}

static void
tamper_and_invalid_scope (void)
{
  g_autoptr (GBytes) manifest = manifest_bytes (TRUE);
  g_autoptr (GPtrArray) targets = target_graphs ();
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP, WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "missing", 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==,
      WYRELOG_E_POLICY);
  g_assert_null (journal.graphs);
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      "018F22D0-7B6D-7A5B-8C31-123456789ABC",
      WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==,
      WYRELOG_E_INVALID);

  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&journal, &encoded), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournalGraph *first = g_ptr_array_index
        (journal.graphs, 0);
  WylFactArtifactMainTransitionOp saved_next = first->next_op;
  first->next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE;
  g_autoptr (GBytes) impossible = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&journal, &impossible), ==, WYRELOG_E_INVALID);
  g_assert_null (impossible);
  first->next_op = saved_next;
  gsize length = 0;
  const guint8 *data = g_bytes_get_data (encoded, &length);
  guint8 *changed = g_memdup2 (data, length);
  changed[length / 2] ^= 1;
  g_autoptr (GBytes) tampered = g_bytes_new_take (changed, length);
  WylFactOfflineRestoreJournal decoded;
  memset (&decoded, 0xa5, sizeof decoded);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode
        (tampered, &decoded), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded.graphs);
  g_assert_null (decoded.operation_uuid);
  wyl_fact_offline_restore_journal_clear (&journal);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/offline-restore/round-trip-scope",
      round_trip_and_scope);
  g_test_add_func ("/fact/offline-restore/admission",
      admission_is_fail_closed);
  g_test_add_func ("/fact/offline-restore/decision-recovery",
      decision_barrier_and_recovery);
  g_test_add_func ("/fact/offline-restore/rollback-converges",
      rollback_converges);
  g_test_add_func ("/fact/offline-restore/tamper-scope",
      tamper_and_invalid_scope);
  return wyl_test_normalize_exit_status (g_test_run ());
}

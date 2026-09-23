/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-artifact-transition-names-private.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-backup-manifest-private.h"
#include "wyrelog/fact/offline-restore-journal-private.h"
#include "wyrelog/fact/offline-restore-journal-stage-private.h"
#include "wyrelog/fact/offline-restore-journal-store-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-id-private.h"

#define OP_A "018f22d0-7b6d-7a5b-8c31-123456789abc"
#define STORE_ALPHA "018f22d0-7b6d-7a5b-8c31-123456789abd"
#define STORE_ZETA "018f22d0-7b6d-7a5b-8c31-123456789abe"

typedef struct
{
  gchar *root;
  gchar *policy_path;
  wyl_policy_store_t *policy;
} Fixture;

static void
remove_tree (const gchar *path)
{
  if (path == NULL)
    return;
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  if (directory != NULL) {
    const gchar *name = NULL;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_tree (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

static gchar *
sha256_text (const guint8 *bytes, gsize length)
{
  g_autofree gchar *digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
          bytes, length);
  return g_strdup_printf ("sha256:%s", digest);
}

static GBytes *
manifest_bytes (const guint8 *bytes, gsize length, gboolean two_graphs)
{
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init (&manifest,
      "tenant-a", 7), ==, WYRELOG_E_OK);
  g_autofree gchar *checksum = sha256_text (bytes, length);
  g_autofree gchar *schema_digest = sha256_text
        ((const guint8 *) "restore schema", 14);
  WylFactOfflineBackupArtifact alpha = {
    .graph_id = "alpha",
    .store_uuid = STORE_ALPHA,
    .format_version = 1,
    .path_encoding_version = 1,
    .schema_digest = schema_digest,
    .logical_bytes = length,
    .physical_bytes = MAX ((guint64) 4096, (guint64) length),
    .checksum = checksum,
  };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add (&manifest, &alpha),
      ==, WYRELOG_E_OK);
  if (two_graphs) {
    WylFactOfflineBackupArtifact zeta = alpha;
    zeta.graph_id = "zeta";
    zeta.store_uuid = STORE_ZETA;
    g_assert_cmpint (wyl_fact_offline_backup_manifest_add (&manifest, &zeta),
        ==, WYRELOG_E_OK);
  }
  GBytes *result = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&manifest,
      &result), ==, WYRELOG_E_OK);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  return result;
}

static void
open_policy (Fixture *fixture)
{
  g_assert_cmpint (wyl_policy_store_open (fixture->policy_path,
      &fixture->policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture->policy), ==,
      WYRELOG_E_OK);
}

static void
create_restore_journal (Fixture *fixture, const guint8 *bytes, gsize length,
    gboolean two_graphs)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (fixture->policy,
      "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);

  g_autoptr (GBytes) manifest = manifest_bytes (bytes, length, two_graphs);
  g_autoptr (GPtrArray) targets = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_restore_target_graph_free);
  static const gchar *const graph_ids[] = { "alpha", "zeta" };
  for (guint i = 0; i < (two_graphs ? 2u : 1u); i++) {
    WylFactOfflineRestoreTargetGraph *target = g_new0
          (WylFactOfflineRestoreTargetGraph, 1);
    target->graph_id = g_strdup (graph_ids[i]);
    target->lifecycle_generation = 11;
    target->reconciliation_generation = 12;
    target->expected_main_absent = TRUE;
    g_ptr_array_add (targets, target);
  }
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      OP_A, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournal committed = { 0 };
  WylFactOfflineRestoreStoreResult result = WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (fixture->policy, &journal, &result, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_assert_cmpuint (committed.revision, ==, 1);
  wyl_fact_offline_restore_journal_clear (&committed);
  wyl_fact_offline_restore_journal_clear (&journal);
}

static void
create_graph_directories (Fixture *fixture, gboolean two_graphs)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root, &resolver),
      ==, WYRELOG_E_OK);
  static const gchar *const graph_ids[] = { "alpha", "zeta" };
  for (guint i = 0; i < (two_graphs ? 2u : 1u); i++) {
    WylFactGraphLocator locator = { 0 };
    WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
    g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a",
        graph_ids[i]), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
        &locator, TRUE, &directory), ==, WYRELOG_E_OK);
    wyl_fact_graph_directory_clear (&directory);
    wyl_fact_graph_locator_clear (&locator);
  }
  wyl_fact_graph_resolver_clear (&resolver);
}

static void
fixture_init (Fixture *fixture, const guint8 *bytes, gsize length,
    gboolean two_graphs)
{
  g_autoptr (GError) error = NULL;
  fixture->root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-journal-stage-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (fixture->root);
  fixture->policy_path = g_build_filename (fixture->root, "policy.db", NULL);
  open_policy (fixture);
  create_restore_journal (fixture, bytes, length, two_graphs);
  create_graph_directories (fixture, two_graphs);
}

static void
fixture_clear (Fixture *fixture)
{
  g_clear_pointer (&fixture->policy, wyl_policy_store_close);
  remove_tree (fixture->root);
  g_clear_pointer (&fixture->policy_path, g_free);
  g_clear_pointer (&fixture->root, g_free);
}

static WylFactOfflineRestoreJournalGraph *
find_graph (WylFactOfflineRestoreJournal *journal, const gchar *graph_id)
{
  for (guint i = 0; journal != NULL && journal->graphs != NULL
      && i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (journal->graphs, i);
    if (g_strcmp0 (graph->graph_id, graph_id) == 0)
      return graph;
  }
  return NULL;
}

static gboolean
identity_is_zero (const WylFactArtifactInventoryIdentity *identity)
{
  WylFactArtifactInventoryIdentity zero = { 0 };
  return wyl_fact_artifact_inventory_identity_equal (identity, &zero);
}

static void
bind_graph_directly (wyl_policy_store_t *policy,
    WylFactOfflineRestoreJournal *journal, const gchar *graph_id)
{
  WylFactOfflineRestoreJournal desired = { 0 };
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (journal, &encoded),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (encoded, &desired),
      ==, WYRELOG_E_OK);
  WylFactArtifactInventoryIdentity identity = {
    .domain = 1,
#ifdef G_OS_WIN32
    .object_width = 16,
    .object_bytes = { 1 },
#else
    .object = 1,
#endif
  };
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&desired, graph_id, &identity), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreStoreResult result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas (policy,
      journal->revision, &desired, &result, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  wyl_fact_offline_restore_journal_clear (journal);
  *journal = committed;
  memset (&committed, 0, sizeof committed);
  wyl_fact_offline_restore_journal_clear (&desired);
}

static void
assert_unbound_pristine (const WylFactOfflineRestoreJournal *journal)
{
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (journal->graphs, i);
    g_assert_cmpuint (graph->staged_main_identity.domain, ==, 0);
    g_assert_cmpuint (graph->staged_main_identity.object, ==, 0);
    g_assert_cmpuint (graph->staged_main_identity.object_width, ==, 0);
    g_assert_false (graph->copied);
    g_assert_false (graph->checksum_verified);
    g_assert_false (graph->identity_verified);
    g_assert_false (graph->schema_verified);
    g_assert_false (graph->replay_preflighted);
  }
}

static void
stage_artifact (WylFactOfflineRestoreJournalStage *session,
    const guint8 *bytes, gsize length)
{
  gsize offset = 0;
  while (offset < length) {
    gsize chunk = MIN ((gsize) 8191, length - offset);
    g_assert_cmpint (wyl_fact_offline_restore_journal_stage_sink (offset,
        bytes + offset, chunk, session), ==, WYRELOG_E_OK);
    offset += chunk;
  }
}

static gboolean
journals_equal (const WylFactOfflineRestoreJournal *left,
    const WylFactOfflineRestoreJournal *right)
{
  g_autoptr (GBytes) left_bytes = NULL;
  g_autoptr (GBytes) right_bytes = NULL;
  return wyl_fact_offline_restore_journal_encode (left, &left_bytes)
         == WYRELOG_E_OK
         && wyl_fact_offline_restore_journal_encode (right, &right_bytes)
         == WYRELOG_E_OK
         && g_bytes_equal (left_bytes, right_bytes);
}

static void
test_copy_finalize_and_durable_identity_binding (void)
{
  const gsize length = 2 * 64 * 1024 + 17;
  g_autofree guint8 *bytes = g_malloc (length);
  for (gsize i = 0; i < length; i++)
    bytes[i] = (guint8) (i % 256);
  Fixture fixture = { 0 };
  fixture_init (&fixture, bytes, length, TRUE);

  WylFactOfflineRestoreJournalStage *session = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_new (fixture.policy,
      fixture.root, OP_A, "alpha", 1, &session), ==, WYRELOG_E_OK);
  stage_artifact (session, bytes, length);
  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_finish (session,
      WYRELOG_E_OK, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 2);
  WylFactOfflineRestoreJournalGraph *alpha = find_graph (&committed, "alpha");
  WylFactOfflineRestoreJournalGraph *zeta = find_graph (&committed, "zeta");
  g_assert_nonnull (alpha);
  g_assert_nonnull (zeta);
  g_assert_false (identity_is_zero (&alpha->staged_main_identity));
  g_assert_cmpuint (zeta->staged_main_identity.domain, ==, 0);
  g_assert_cmpuint (zeta->staged_main_identity.object, ==, 0);
  g_assert_false (alpha->copied);
  g_assert_false (alpha->checksum_verified);
  g_assert_false (alpha->identity_verified);
  g_assert_false (alpha->schema_verified);
  g_assert_false (alpha->replay_preflighted);
  g_assert_cmpint (committed.decision, ==,
      WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  open_policy (&fixture);
  WylFactOfflineRestoreJournal loaded = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load (fixture.policy,
      OP_A, &loaded), ==, WYRELOG_E_OK);
  g_assert_true (journals_equal (&committed, &loaded));
  WylFactOfflineRestoreJournalGraph *loaded_alpha =
      find_graph (&loaded, "alpha");
  g_assert_nonnull (loaded_alpha);
  g_assert_false (loaded_alpha->checksum_verified);
  g_assert_false (loaded_alpha->replay_preflighted);

  WylFactArtifactTransitionNames names = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (OP_A, &names),
      ==, WYRELOG_E_OK);
  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_autofree gchar *directory = wyl_fact_graph_locator_descriptive_path
        (fixture.root, &locator);
  g_autofree gchar *stage_path = g_build_filename (directory, names.stage, NULL);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_IS_REGULAR));
  wyl_fact_offline_restore_journal_stage_free (session);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_artifact_transition_names_clear (&names);
  wyl_fact_offline_restore_journal_clear (&loaded);
  wyl_fact_offline_restore_journal_clear (&committed);
  fixture_clear (&fixture);
}

static void
test_sequential_graph_binding_revision_accounting (void)
{
  static const guint8 bytes[] = "small artifact";
  Fixture fixture = { 0 };
  fixture_init (&fixture, bytes, sizeof bytes - 1, TRUE);
  const gchar *graphs[] = { "alpha", "zeta" };
  for (guint i = 0; i < G_N_ELEMENTS (graphs); i++) {
    WylFactOfflineRestoreJournalStage *session = NULL;
    g_assert_cmpint (wyl_fact_offline_restore_journal_stage_new
          (fixture.policy, fixture.root, OP_A, graphs[i], i + 1, &session),
        ==, WYRELOG_E_OK);
    stage_artifact (session, bytes, sizeof bytes - 1);
    WylFactOfflineRestoreJournal committed = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_journal_stage_finish (session,
        WYRELOG_E_OK, &committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (committed.revision, ==, i + 2);
    g_assert_cmpuint (committed.graphs->len, ==, 2);
    for (guint j = 0; j < G_N_ELEMENTS (graphs); j++) {
      WylFactOfflineRestoreJournalGraph *graph = find_graph (&committed,
              graphs[j]);
      g_assert_nonnull (graph);
      g_assert_cmpint (!identity_is_zero (&graph->staged_main_identity), ==,
          j <= i);
    }
    wyl_fact_offline_restore_journal_clear (&committed);
    wyl_fact_offline_restore_journal_stage_free (session);
  }
  fixture_clear (&fixture);
}

static void
test_sink_failure_terminalizes_without_journal_mutation (void)
{
  static const guint8 bytes[] = "sink artifact";
  Fixture fixture = { 0 };
  fixture_init (&fixture, bytes, sizeof bytes - 1, FALSE);
  WylFactOfflineRestoreJournalStage *session = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_new (fixture.policy,
      fixture.root, OP_A, "alpha", 1, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_sink (1, bytes,
      sizeof bytes - 1, session), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_sink (0, bytes,
      sizeof bytes - 1, session), ==, WYRELOG_E_INVALID);
  WylFactOfflineRestoreJournal output = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_finish (session,
      WYRELOG_E_OK, &output), !=, WYRELOG_E_OK);
  g_assert_null (output.operation_uuid);
  WylFactOfflineRestoreJournal persisted = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, OP_A, &persisted), ==, WYRELOG_E_OK);
  g_assert_cmpuint (persisted.revision, ==, 1);
  assert_unbound_pristine (&persisted);
  wyl_fact_offline_restore_journal_clear (&persisted);
  wyl_fact_offline_restore_journal_clear (&output);
  wyl_fact_offline_restore_journal_stage_free (session);
  fixture_clear (&fixture);
}

static void
test_stale_cas_retains_stage_and_does_not_overwrite (void)
{
  static const guint8 bytes[] = "stale candidate";
  Fixture fixture = { 0 };
  fixture_init (&fixture, bytes, sizeof bytes - 1, TRUE);
  WylFactOfflineRestoreJournalStage *session = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_new (fixture.policy,
      fixture.root, OP_A, "alpha", 1, &session), ==, WYRELOG_E_OK);
  stage_artifact (session, bytes, sizeof bytes - 1);
  WylFactOfflineRestoreJournal concurrent = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, OP_A, &concurrent), ==, WYRELOG_E_OK);
  bind_graph_directly (fixture.policy, &concurrent, "zeta");
  WylFactOfflineRestoreJournal output = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_finish (session,
      WYRELOG_E_OK, &output), ==, WYRELOG_E_BUSY);
  g_assert_null (output.operation_uuid);
  WylFactOfflineRestoreJournal persisted = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, OP_A, &persisted), ==, WYRELOG_E_OK);
  g_assert_cmpuint (persisted.revision, ==, 2);
  g_assert_true (identity_is_zero (&find_graph (&persisted,
      "alpha")->staged_main_identity));
  g_assert_false (identity_is_zero (&find_graph (&persisted,
      "zeta")->staged_main_identity));
  WylFactArtifactTransitionNames names = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (OP_A, &names),
      ==, WYRELOG_E_OK);
  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_autofree gchar *directory = wyl_fact_graph_locator_descriptive_path
        (fixture.root, &locator);
  g_autofree gchar *stage_path = g_build_filename (directory, names.stage, NULL);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_IS_REGULAR));
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_artifact_transition_names_clear (&names);
  wyl_fact_offline_restore_journal_clear (&persisted);
  wyl_fact_offline_restore_journal_clear (&output);
  wyl_fact_offline_restore_journal_clear (&concurrent);
  wyl_fact_offline_restore_journal_stage_free (session);
  fixture_clear (&fixture);
}

#ifdef WYL_TEST_HANDLE_SEAMS
static void
test_ambiguous_commit_preserves_recovery_state (void)
{
  static const guint8 bytes[] = "commit response lost";
  Fixture fixture = { 0 };
  fixture_init (&fixture, bytes, sizeof bytes - 1, FALSE);
  WylFactOfflineRestoreJournalStage *session = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_new (fixture.policy,
      fixture.root, OP_A, "alpha", 1, &session), ==, WYRELOG_E_OK);
  stage_artifact (session, bytes, sizeof bytes - 1);
  wyl_policy_store_offline_restore_fail_once (fixture.policy,
      WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
  WylFactOfflineRestoreJournal output = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_finish (session,
      WYRELOG_E_OK, &output), ==, WYRELOG_E_IO);
  g_assert_null (output.operation_uuid);
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  open_policy (&fixture);
  WylFactOfflineRestoreJournal persisted = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, OP_A, &persisted), ==, WYRELOG_E_OK);
  g_assert_cmpuint (persisted.revision, ==, 2);
  g_assert_false (identity_is_zero (&find_graph (&persisted,
      "alpha")->staged_main_identity));
  WylFactArtifactTransitionNames names = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (OP_A, &names),
      ==, WYRELOG_E_OK);
  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_autofree gchar *directory = wyl_fact_graph_locator_descriptive_path
        (fixture.root, &locator);
  g_autofree gchar *stage_path = g_build_filename (directory, names.stage, NULL);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_IS_REGULAR));
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_artifact_transition_names_clear (&names);
  wyl_fact_offline_restore_journal_clear (&persisted);
  wyl_fact_offline_restore_journal_clear (&output);
  wyl_fact_offline_restore_journal_stage_free (session);
  fixture_clear (&fixture);
}
#endif

static void
test_producer_failure_after_all_bytes_does_not_finalize_or_bind (void)
{
  static const guint8 bytes[] = "all bytes delivered";
  Fixture fixture = { 0 };
  fixture_init (&fixture, bytes, sizeof bytes - 1, FALSE);
  WylFactOfflineRestoreJournalStage *session = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_new (fixture.policy,
      fixture.root, OP_A, "alpha", 1, &session), ==, WYRELOG_E_OK);
  stage_artifact (session, bytes, sizeof bytes - 1);
  WylFactOfflineRestoreJournal output = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_stage_finish (session,
      WYRELOG_E_IO, &output), ==, WYRELOG_E_IO);
  g_assert_null (output.operation_uuid);
  g_assert_cmpuint (output.revision, ==, 0);
  WylFactOfflineRestoreJournal persisted = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, OP_A, &persisted), ==, WYRELOG_E_OK);
  g_assert_cmpuint (persisted.revision, ==, 1);
  assert_unbound_pristine (&persisted);
  wyl_fact_offline_restore_journal_stage_free (session);
  wyl_fact_offline_restore_journal_clear (&persisted);
  wyl_fact_offline_restore_journal_clear (&output);
  fixture_clear (&fixture);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-offline-restore-journal-stage/copy-bind-durable",
      test_copy_finalize_and_durable_identity_binding);
  g_test_add_func ("/fact-offline-restore-journal-stage/producer-failure",
      test_producer_failure_after_all_bytes_does_not_finalize_or_bind);
  g_test_add_func ("/fact-offline-restore-journal-stage/sequential-graphs",
      test_sequential_graph_binding_revision_accounting);
  g_test_add_func ("/fact-offline-restore-journal-stage/sink-failure",
      test_sink_failure_terminalizes_without_journal_mutation);
  g_test_add_func ("/fact-offline-restore-journal-stage/stale-cas",
      test_stale_cas_retains_stage_and_does_not_overwrite);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_func ("/fact-offline-restore-journal-stage/ambiguous-commit",
      test_ambiguous_commit_preserves_recovery_state);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

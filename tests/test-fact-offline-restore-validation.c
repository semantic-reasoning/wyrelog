/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>

#include "wyrelog/fact/offline-restore-validation-private.h"
#include "wyrelog/fact/store-identity-types-private.h"

#define OP "018f22d0-7b6d-7a5b-8c31-123456789abc"
#define STORE_A "018f22d0-7b6d-7a5b-8c31-123456789abd"
#define STORE_Z "018f22d0-7b6d-7a5b-8c31-123456789abe"
#define SHA_A "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SHA_B "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SHA_C "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define SHA_D "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

typedef struct
{
  GBytes *manifest;
  GPtrArray *targets;
  WylFactOfflineRestoreJournal journal;
  WylFactOfflineRestoreAdmissionEvidence admission;
  WylFactOfflineRestoreAdmissionGraphEvidence admission_graphs[2];
  GPtrArray *admission_array;
  WylFactOfflineRestoreStagedObservation observations[2];
  GPtrArray *staged;
} Fixture;

static WylFactArtifactInventoryIdentity
identity (guint64 domain, guint64 object)
{
  WylFactArtifactInventoryIdentity value = {
    .domain = domain, .object = object, .object_width = 0,
  };
  return value;
}

static WylFactArtifactInventoryIdentity
wide_identity (guint64 domain, guint8 byte)
{
  WylFactArtifactInventoryIdentity value = {
    .domain = domain, .object_width = 16,
  };
  value.object_bytes[0] = byte;
  return value;
}

static GBytes *
manifest_bytes (guint64 format, guint64 path)
{
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init
        (&manifest, "tenant-a", 7), ==, WYRELOG_E_OK);
  WylFactOfflineBackupArtifact alpha = {
    .graph_id = "alpha", .store_uuid = STORE_A,
    .format_version = format, .path_encoding_version = path,
    .schema_digest = SHA_A, .logical_bytes = 10,
    .physical_bytes = 4096, .checksum = SHA_B,
  };
  WylFactOfflineBackupArtifact zeta = {
    .graph_id = "zeta", .store_uuid = STORE_Z,
    .format_version = format, .path_encoding_version = path,
    .schema_digest = SHA_C, .logical_bytes = 20,
    .physical_bytes = 8192, .checksum = SHA_D,
  };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add
        (&manifest, &alpha), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add
        (&manifest, &zeta), ==, WYRELOG_E_OK);
  GBytes *bytes = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode
        (&manifest, &bytes), ==, WYRELOG_E_OK);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  return bytes;
}

static void
fixture_clear (Fixture *fixture)
{
  wyl_fact_offline_restore_journal_clear (&fixture->journal);
  g_clear_pointer (&fixture->manifest, g_bytes_unref);
  g_clear_pointer (&fixture->targets, g_ptr_array_unref);
  g_clear_pointer (&fixture->admission_array, g_ptr_array_unref);
  g_clear_pointer (&fixture->staged, g_ptr_array_unref);
  memset (fixture, 0, sizeof *fixture);
}

static void
fixture_init_scope_versions (Fixture *fixture, gboolean staged,
    WylFactOfflineRestoreScope scope, guint64 format, guint64 path)
{
  memset (fixture, 0, sizeof *fixture);
  fixture->manifest = manifest_bytes (format, path);
  fixture->targets = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_restore_target_graph_free);
  WylFactOfflineRestoreTargetGraph *alpha = g_new0
        (WylFactOfflineRestoreTargetGraph, 1);
  alpha->graph_id = g_strdup ("alpha");
  alpha->lifecycle_generation = 11;
  alpha->reconciliation_generation = 12;
  alpha->expected_main_identity = identity (1, 101);
  g_ptr_array_add (fixture->targets, alpha);
  WylFactOfflineRestoreTargetGraph *zeta = g_new0
        (WylFactOfflineRestoreTargetGraph, 1);
  zeta->graph_id = g_strdup ("zeta");
  zeta->lifecycle_generation = 21;
  zeta->reconciliation_generation = 22;
  zeta->expected_main_absent = TRUE;
  g_ptr_array_add (fixture->targets, zeta);
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&fixture->journal,
      fixture->manifest, OP, scope,
      scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH ? "zeta" : NULL,
      31, 32, fixture->targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  if (staged) {
    for (guint i = 0; i < fixture->journal.graphs->len; i++) {
      WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (fixture->journal.graphs, i);
      WylFactArtifactInventoryIdentity staged_identity =
          g_str_equal (graph->graph_id, "alpha") ? identity (2, 201) :
          wide_identity (3, 0xca);
      g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
            (&fixture->journal, graph->graph_id, &staged_identity), ==,
          WYRELOG_E_OK);
    }
  }

  fixture->admission.operation_uuid = OP;
  fixture->admission.tenant_id = "tenant-a";
  fixture->admission.selected_graph_id = fixture->journal.selected_graph_id;
  fixture->admission.tenant_lifecycle_generation = 31;
  fixture->admission.tenant_reconciliation_generation = 32;
  fixture->admission.confirmed = TRUE;
  fixture->admission.manifest_authenticated = TRUE;
  fixture->admission.target_sealed = TRUE;
  fixture->admission.target_drained = TRUE;
  fixture->admission.exclusive_root_authority = TRUE;
  fixture->admission.inventory_stable = TRUE;
  memcpy (fixture->admission.manifest_sha256,
      fixture->journal.manifest_sha256, 32);
  fixture->admission_array = g_ptr_array_new ();
  fixture->staged = g_ptr_array_new ();
  for (guint i = 0; i < fixture->journal.graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (fixture->journal.graphs, i);
    fixture->admission_graphs[i].graph_id = graph->graph_id;
    fixture->admission_graphs[i].lifecycle_generation =
        graph->destination_lifecycle_generation;
    fixture->admission_graphs[i].reconciliation_generation =
        graph->destination_reconciliation_generation;
    fixture->admission_graphs[i].expected_main_identity =
        graph->expected_main_identity;
    fixture->admission_graphs[i].staged_main_identity =
        graph->staged_main_identity;
    g_ptr_array_add (fixture->admission_array,
        &fixture->admission_graphs[i]);

    WylFactOfflineRestoreStagedObservation *observation =
        &fixture->observations[i];
    observation->operation_uuid = OP;
    observation->graph_id = graph->graph_id;
    observation->inventory_start.directory_identity = identity (10 + i, 1);
    observation->inventory_start.guard_identity = identity (10 + i, 2);
    observation->inventory_start.entry_fingerprint = 100 + i;
    observation->inventory_end = observation->inventory_start;
    observation->operation_owned_stages = 1;
    observation->present = TRUE;
    observation->regular = TRUE;
    observation->link_count = 1;
    observation->owner_state =
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING;
    observation->identity = graph->staged_main_identity;
    observation->logical_bytes = graph->logical_bytes;
    observation->checksum = graph->checksum;
    observation->tenant_id = "tenant-a";
    observation->metadata_graph_id = graph->graph_id;
    observation->store_uuid = graph->store_uuid;
    observation->format_version = graph->format_version;
    observation->path_encoding_version = graph->path_encoding_version;
    observation->schema_digest = graph->schema_digest;
    observation->replay_result = WYL_FACT_OFFLINE_RESTORE_REPLAY_SUCCEEDED;
    observation->replay_identity = graph->staged_main_identity;
    observation->replay_schema_digest = graph->schema_digest;
    g_ptr_array_add (fixture->staged, observation);
  }
  fixture->admission.graphs = fixture->admission_array;
}

static void
fixture_init_versions (Fixture *fixture, gboolean staged, guint64 format,
    guint64 path)
{
  fixture_init_scope_versions (fixture, staged,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, format, path);
}

static void
fixture_init (Fixture *fixture, gboolean staged)
{
  fixture_init_versions (fixture, staged, WYL_FACT_STORE_FORMAT_VERSION,
      WYL_FACT_STORE_PATH_ENCODING_VERSION);
}

static void
assert_failure (Fixture *fixture,
    WylFactOfflineRestoreValidationFailure expected)
{
  g_autoptr (GBytes) before = NULL;
  g_autoptr (GBytes) after = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&fixture->journal, &before), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreValidationResult result;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED,
      fixture->manifest, &fixture->journal, &fixture->admission,
      fixture->staged, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==, expected);
  g_assert_cmpuint (result.pending_checks, ==,
      WYL_FACT_OFFLINE_RESTORE_PENDING_NONE);
  if (expected == WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT) {
    g_assert_cmpuint (result.graph_index, ==, G_MAXUINT);
    g_assert_cmpuint (result.checked_graph_count, ==, 0);
    g_assert_cmpuint (result.validated_revision, ==, 0);
  }
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&fixture->journal, &after), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (before, after));
}

static void
dry_run_and_staged_are_pure (void)
{
  Fixture dry;
  fixture_init (&dry, FALSE);
  g_autoptr (GBytes) before = NULL;
  g_autoptr (GBytes) after = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&dry.journal, &before), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreValidationResult result;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, dry.manifest,
      &dry.journal, &dry.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_DRY_RUN_VALIDATED);
  g_assert_cmpuint (result.checked_graph_count, ==, 2);
  g_assert_cmpuint (result.validated_revision, ==, 1);
  g_assert_cmpuint (result.pending_checks, ==,
      WYL_FACT_OFFLINE_RESTORE_PENDING_ALL);
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&dry.journal, &after), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (before, after));
  fixture_clear (&dry);

  Fixture staged;
  fixture_init (&staged, TRUE);
  g_clear_pointer (&before, g_bytes_unref);
  g_clear_pointer (&after, g_bytes_unref);
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&staged.journal, &before), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED, staged.manifest,
      &staged.journal, &staged.admission, staged.staged, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED);
  g_assert_cmpuint (result.checked_graph_count, ==, 2);
  g_assert_cmpuint (result.validated_revision, ==, 3);
  g_assert_cmpuint (result.pending_checks, ==,
      WYL_FACT_OFFLINE_RESTORE_PENDING_NONE);
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (&staged.journal, &after), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (before, after));
  fixture_clear (&staged);
}

static void
phase_order_and_admission_precedence (void)
{
  Fixture fixture;
  fixture_init (&fixture, TRUE);
  WylFactOfflineRestoreValidationResult result;
  g_autoptr (GPtrArray) empty = g_ptr_array_new ();
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, fixture.manifest,
      &fixture.journal, &fixture.admission, empty, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  g_assert_cmpuint (result.graph_index, ==, G_MAXUINT);
  g_assert_cmpuint (result.checked_graph_count, ==, 0);
  g_assert_cmpuint (result.validated_revision, ==, 0);
  g_assert_cmpuint (result.pending_checks, ==,
      WYL_FACT_OFFLINE_RESTORE_PENDING_NONE);

  gpointer last = g_ptr_array_index (fixture.staged, 1);
  g_ptr_array_set_size (fixture.staged, 1);
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_CARDINALITY);
  g_ptr_array_add (fixture.staged, last);
  g_ptr_array_add (fixture.staged, last);
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_CARDINALITY);
  g_ptr_array_set_size (fixture.staged, 2);

  gpointer first = g_ptr_array_index (fixture.staged, 0);
  g_ptr_array_index (fixture.staged, 0) = g_ptr_array_index (fixture.staged, 1);
  g_ptr_array_index (fixture.staged, 1) = first;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_ORDER);
  first = g_ptr_array_index (fixture.staged, 0);
  g_ptr_array_index (fixture.staged, 0) = g_ptr_array_index (fixture.staged, 1);
  g_ptr_array_index (fixture.staged, 1) = first;

  WylFactOfflineRestoreJournalGraph *graph =
      g_ptr_array_index (fixture.journal.graphs, 0);
  WylFactArtifactInventoryIdentity staged_identity =
      graph->staged_main_identity;
  graph->staged_main_identity = (WylFactArtifactInventoryIdentity) { 0 };
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_JOURNAL_PHASE);
  graph->staged_main_identity = staged_identity;
  fixture.journal.revision--;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_JOURNAL_PHASE);
  fixture.journal.revision++;

  fixture.admission.confirmed = FALSE;
  fixture.observations[0].present = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_CONFIRMATION);
  fixture.admission.confirmed = TRUE;
  fixture.observations[0].present = TRUE;

  graph->copied = graph->checksum_verified = graph->identity_verified =
      graph->schema_verified = graph->replay_preflighted = TRUE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_JOURNAL_PHASE);
  fixture_clear (&fixture);
}

static void
inventory_and_entry_fail_closed (void)
{
  Fixture fixture;
  fixture_init (&fixture, TRUE);
  WylFactOfflineRestoreStagedObservation *observation =
      &fixture.observations[0];
  observation->inventory_end.directory_identity.object++;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVENTORY_UNSTABLE);
  observation->inventory_end = observation->inventory_start;
  observation->inventory_end.guard_identity.object++;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVENTORY_UNSTABLE);
  observation->inventory_end = observation->inventory_start;
  observation->inventory_end.entry_fingerprint++;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVENTORY_UNSTABLE);
  observation->inventory_end = observation->inventory_start;
  observation->operation_owned_stages = 2;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_POPULATION);
  observation->operation_owned_stages = 1;
  observation->foreign_restore_stages = 1;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FOREIGN_STAGE);
  observation->foreign_restore_stages = 0;
  observation->unknown_entries = 1;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_UNKNOWN_ENTRY);
  observation->unknown_entries = 0;
  observation->present = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_MISSING);
  observation->present = TRUE;
  observation->regular = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_TYPE);
  observation->regular = TRUE;
  observation->reparse = TRUE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_REPARSE);
  observation->reparse = FALSE;
  observation->link_count = 2;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_LINK_COUNT);
  observation->link_count = 1;
  observation->owner_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNKNOWN;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_OWNER);
  observation->owner_state =
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING;
  observation->identity.object_width = 8;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_IDENTITY);
  observation->identity = ((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (fixture.journal.graphs, 0))->staged_main_identity;
  observation->identity.object++;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_IDENTITY);
  fixture_clear (&fixture);
}

static void
content_metadata_and_replay_fail_closed (void)
{
  Fixture fixture;
  fixture_init (&fixture, TRUE);
  WylFactOfflineRestoreStagedObservation *observation =
      &fixture.observations[0];
  observation->logical_bytes++;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_LOGICAL_BYTES);
  observation->logical_bytes--;
  observation->checksum =
      "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_CHECKSUM);
  observation->checksum = SHA_A;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_CHECKSUM);
  observation->checksum = SHA_B;
  observation->store_uuid = STORE_Z;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STORE_UUID);
  observation->store_uuid = STORE_A;
  observation->tenant_id = "tenant-b";
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_TENANT);
  observation->tenant_id = "tenant-a";
  observation->metadata_graph_id = "zeta";
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_GRAPH);
  observation->metadata_graph_id = "alpha";
  observation->format_version = 2;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FORMAT);
  observation->format_version = 1;
  observation->path_encoding_version = 2;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_PATH);
  observation->path_encoding_version = 1;
  observation->schema_digest = SHA_C;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_SCHEMA);
  observation->schema_digest = SHA_A;
  observation->replay_result = WYL_FACT_OFFLINE_RESTORE_REPLAY_OPEN_FAILED;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_REPLAY);
  observation->replay_result = WYL_FACT_OFFLINE_RESTORE_REPLAY_SUCCEEDED;
  observation->replay_identity.object++;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_REPLAY);
  observation->replay_identity = ((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (fixture.journal.graphs, 0))->staged_main_identity;
  observation->replay_identity.object_width = 8;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_REPLAY);
  observation->replay_identity = ((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (fixture.journal.graphs, 0))->staged_main_identity;
  observation->replay_schema_digest = SHA_C;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_REPLAY);
  fixture_clear (&fixture);
}

static void
graph_scope_and_result_index_are_exact (void)
{
  Fixture fixture;
  fixture_init_scope_versions (&fixture, FALSE,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, WYL_FACT_STORE_FORMAT_VERSION,
      WYL_FACT_STORE_PATH_ENCODING_VERSION);
  WylFactOfflineRestoreValidationResult result;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, fixture.manifest,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_DRY_RUN_VALIDATED);
  g_assert_cmpuint (result.checked_graph_count, ==, 1);
  fixture_clear (&fixture);

  fixture_init_scope_versions (&fixture, TRUE,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, WYL_FACT_STORE_FORMAT_VERSION,
      WYL_FACT_STORE_PATH_ENCODING_VERSION);
  g_assert_cmpstr (fixture.observations[0].graph_id, ==, "zeta");
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED, fixture.manifest,
      &fixture.journal, &fixture.admission, fixture.staged, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED);
  fixture_clear (&fixture);

  fixture_init (&fixture, TRUE);
  fixture.observations[1].logical_bytes++;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED, fixture.manifest,
      &fixture.journal, &fixture.admission, fixture.staged, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_LOGICAL_BYTES);
  g_assert_cmpuint (result.graph_index, ==, 1);
  g_assert_cmpuint (result.checked_graph_count, ==, 1);
  fixture_clear (&fixture);
}

static void
zero_wide_identity_is_not_present (void)
{
  Fixture fixture;
  fixture_init (&fixture, FALSE);
  WylFactArtifactInventoryIdentity zero_wide = { .object_width = 16 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&fixture.journal, "alpha", &zero_wide), ==, WYRELOG_E_POLICY);
  fixture_clear (&fixture);

  fixture_init (&fixture, TRUE);
  fixture.observations[0].identity = zero_wide;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_IDENTITY);
  fixture.observations[0].identity = ((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (fixture.journal.graphs, 0))->staged_main_identity;
  fixture.observations[0].inventory_start.directory_identity = zero_wide;
  fixture.observations[0].inventory_end.directory_identity = zero_wide;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVENTORY_UNSTABLE);
  fixture_clear (&fixture);
}

static void
admission_conflicts_are_distinct (void)
{
  Fixture fixture;
  fixture_init (&fixture, TRUE);

  fixture.admission.confirmed = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_CONFIRMATION);
  fixture.admission.confirmed = TRUE;
  fixture.admission.manifest_authenticated = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_MANIFEST_TRUST);
  fixture.admission.manifest_authenticated = TRUE;
  fixture.admission.target_sealed = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_NOT_SEALED);
  fixture.admission.target_sealed = TRUE;
  fixture.admission.target_drained = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_NOT_DRAINED);
  fixture.admission.target_drained = TRUE;
  fixture.admission.exclusive_root_authority = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_AUTHORITY);
  fixture.admission.exclusive_root_authority = TRUE;
  fixture.admission.manifest_sha256[0] ^= 1;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_MAPPING);
  fixture.admission.manifest_sha256[0] ^= 1;
  fixture.admission.tenant_lifecycle_generation++;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_GENERATION);
  fixture.admission.tenant_lifecycle_generation--;
  fixture.admission.inventory_stable = FALSE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_INVENTORY);
  fixture.admission.inventory_stable = TRUE;
  fixture.admission.unknown_artifacts = 1;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_UNKNOWN_ARTIFACT);
  fixture.admission.unknown_artifacts = 0;
  fixture.admission.foreign_operation_artifact = TRUE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_FOREIGN_OPERATION);
  fixture.admission.foreign_operation_artifact = FALSE;
  fixture.admission.foreign_main = TRUE;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_FOREIGN_MAIN);
  fixture_clear (&fixture);
}

static void
bounded_inputs_fail_closed (void)
{
  Fixture fixture;
  fixture_init (&fixture, TRUE);
  g_autofree gchar *at_limit = g_strnfill
        (WYL_FACT_OFFLINE_RESTORE_MAX_TEXT, 'x');
  g_autofree gchar *over_limit = g_strnfill
        (WYL_FACT_OFFLINE_RESTORE_MAX_TEXT + 1u, 'x');
  fixture.admission.tenant_id = at_limit;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_MAPPING);
  fixture.admission.tenant_id = over_limit;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  fixture.admission.tenant_id = "tenant-a";
  fixture.admission.operation_uuid = "not-a-uuid";
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  g_autofree gchar *over_uuid = g_strnfill (37, 'a');
  fixture.admission.operation_uuid = over_uuid;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  fixture.admission.operation_uuid = OP;

  WylFactArtifactInventoryIdentity expected_identity =
      fixture.admission_graphs[0].expected_main_identity;
  fixture.admission_graphs[0].expected_main_identity.object_width = 8;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  fixture.admission_graphs[0].expected_main_identity = expected_identity;
  WylFactArtifactInventoryIdentity staged_identity =
      fixture.admission_graphs[0].staged_main_identity;
  fixture.admission_graphs[0].staged_main_identity =
      (WylFactArtifactInventoryIdentity) { .object_width = 16 };
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  fixture.admission_graphs[0].staged_main_identity = staged_identity;

  g_autoptr (GPtrArray) too_many = g_ptr_array_sized_new
        (WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS + 1u);
  g_ptr_array_set_size (too_many,
      WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS + 1u);
  fixture.admission.graphs = too_many;
  assert_failure (&fixture,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  fixture.admission.graphs = fixture.admission_array;

  WylFactOfflineRestoreJournal invalid_journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&invalid_journal,
      fixture.manifest, over_uuid, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT,
      NULL, 31, 32, fixture.targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==,
      WYRELOG_E_INVALID);
  wyl_fact_offline_restore_journal_clear (&invalid_journal);
  fixture_clear (&fixture);

  fixture_init (&fixture, FALSE);
  g_autoptr (GBytes) max_manifest = g_bytes_new_take
        (g_malloc0 (WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES),
          WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES);
  WylFactOfflineRestoreValidationResult result;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, max_manifest,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_INVALID);
  g_autoptr (GBytes) over_manifest = g_bytes_new_take
        (g_malloc0 (WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES + 1u),
          WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES + 1u);
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, over_manifest,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT);
  fixture_clear (&fixture);
}

static void
manifest_binding_is_exact (void)
{
  Fixture fixture;
  fixture_init (&fixture, FALSE);
  fixture.journal.manifest_sha256[0] ^= 1;
  memcpy (fixture.admission.manifest_sha256,
      fixture.journal.manifest_sha256, 32);
  WylFactOfflineRestoreValidationResult result;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, fixture.manifest,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_BINDING);
  g_assert_cmpuint (result.graph_index, ==, G_MAXUINT);
  g_assert_cmpuint (result.checked_graph_count, ==, 0);
  fixture_clear (&fixture);

  fixture_init (&fixture, FALSE);
  g_autoptr (GBytes) malformed = g_bytes_new_static ("{}", 2);
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, malformed,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_INVALID);
  fixture_clear (&fixture);

  fixture_init (&fixture, FALSE);
  ((WylFactOfflineRestoreJournalGraph *) g_ptr_array_index
    (fixture.journal.graphs, 0))->logical_bytes++;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, fixture.manifest,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_BINDING);
  fixture_clear (&fixture);
}

static void
compatibility_is_internal (void)
{
  Fixture fixture;
  fixture_init_versions (&fixture, FALSE, WYL_FACT_STORE_FORMAT_VERSION + 1u,
      WYL_FACT_STORE_PATH_ENCODING_VERSION);
  WylFactOfflineRestoreValidationResult result;
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, fixture.manifest,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FORMAT_UNSUPPORTED);
  fixture_clear (&fixture);

  fixture_init_versions (&fixture, FALSE, WYL_FACT_STORE_FORMAT_VERSION,
      WYL_FACT_STORE_PATH_ENCODING_VERSION + 1u);
  g_assert_cmpint (wyl_fact_offline_restore_validate
        (WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN, fixture.manifest,
      &fixture.journal, &fixture.admission, NULL, &result), ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED);
  g_assert_cmpint (result.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_PATH_UNSUPPORTED);
  fixture_clear (&fixture);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/offline-restore-validation/pure-success",
      dry_run_and_staged_are_pure);
  g_test_add_func ("/fact/offline-restore-validation/precedence",
      phase_order_and_admission_precedence);
  g_test_add_func ("/fact/offline-restore-validation/inventory-entry",
      inventory_and_entry_fail_closed);
  g_test_add_func ("/fact/offline-restore-validation/content-replay",
      content_metadata_and_replay_fail_closed);
  g_test_add_func ("/fact/offline-restore-validation/graph-scope-index",
      graph_scope_and_result_index_are_exact);
  g_test_add_func ("/fact/offline-restore-validation/zero-wide-identity",
      zero_wide_identity_is_not_present);
  g_test_add_func ("/fact/offline-restore-validation/admission-conflicts",
      admission_conflicts_are_distinct);
  g_test_add_func ("/fact/offline-restore-validation/bounds",
      bounded_inputs_fail_closed);
  g_test_add_func ("/fact/offline-restore-validation/manifest-binding",
      manifest_binding_is_exact);
  g_test_add_func ("/fact/offline-restore-validation/compatibility",
      compatibility_is_internal);
  return wyl_test_normalize_exit_status (g_test_run ());
}

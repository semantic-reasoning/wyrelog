/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <stdio.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-backup-generation-private.h"
#include "wyrelog/fact/offline-backup-manifest-private.h"
#include "wyrelog/fact/offline-backup-source-private.h"
#include "wyrelog/fact/offline-restore-coordinator-private.h"
#include "wyrelog/fact/offline-restore-journal-private.h"
#include "wyrelog/fact/offline-restore-journal-store-private.h"
#include "wyrelog/fact/offline-restore-stage-private.h"
#include "wyrelog/fact/offline-restore-validation-session-private.h"
#include "wyrelog/fact/provisioning-run-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"
#include "wyrelog/fact/store-open-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/wyl-engine-private.h"

typedef struct
{
  gchar *root;
  wyl_policy_store_t *policy;
  WylFactGraphRuntimeManager *runtime;
} BackupFixture;

static gchar *graph_file_path (BackupFixture *fixture,
    const gchar *graph_id, const gchar *basename);

static void
remove_tree (const gchar *path)
{
  if (path == NULL)
    return;
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name = NULL;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

static void
fixture_init (BackupFixture *fixture, const gchar *name)
{
  g_autoptr (GError) error = NULL;
  fixture->root = wyl_test_make_secure_fact_root (name, &error);
  g_assert_no_error (error);
  g_assert_nonnull (fixture->root);
  g_autofree gchar *policy_path = g_build_filename (fixture->root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture->policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture->policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture->runtime), ==,
      WYRELOG_E_OK);
}

static void
fixture_clear (BackupFixture *fixture)
{
  g_clear_pointer (&fixture->runtime, wyl_fact_graph_runtime_manager_unref);
  g_clear_pointer (&fixture->policy, wyl_policy_store_close);
  remove_tree (fixture->root);
  g_clear_pointer (&fixture->root, g_free);
}

static void
create_tenant (BackupFixture *fixture)
{
  gboolean created = FALSE;
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_create_tenant (fixture->policy,
      "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority
        (fixture->policy, "tenant-a", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
      0, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
}

static void
create_graph (BackupFixture *fixture, const gchar *graph_id)
{
  const wyl_policy_fact_graph_column_t columns[] = {
    { "id", "symbol" },
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    { "items", columns, G_N_ELEMENTS (columns) },
  };
  const wyl_policy_fact_graph_create_options_t options = {
    .tenant_id = "tenant-a",
    .graph_id = graph_id,
    .fact_root = fixture->root,
    .schema_version = 1,
    .owner_scope = "tenant-a",
    .relations = relations,
    .n_relations = G_N_ELEMENTS (relations),
  };
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_policy_store_create_fact_graph_provisioning
        (fixture->policy, &options, NULL, operation_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (fixture->policy,
      operation_uuid, fixture->root, NULL), ==, WYRELOG_E_OK);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (fixture->policy,
      fixture->root, "tenant-a", graph_id, TRUE, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  g_clear_pointer (&store, wyl_fact_store_close);
  g_autofree gchar *main_path = graph_file_path (fixture, graph_id,
          "facts.duckdb");
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (main_path, &error));
  g_assert_no_error (error);
  const wyl_policy_fact_relation_schema_column_t schema_columns[] = {
    { "id", "symbol", FALSE, TRUE },
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = "tenant-a",
    .graph_id = graph_id,
    .namespace_id = "backup",
    .relation_name = "items",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = schema_columns,
    .n_columns = G_N_ELEMENTS (schema_columns),
  };
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema
        (fixture->policy, &schema), ==, WYRELOG_E_OK);
  WylPolicyAuthorityMutationResult activation_result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_reserve_relation_activation
        (fixture->policy, "tenant-a", graph_id, "backup", "items",
      &activation_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (activation_result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_relation_activation
        (fixture->policy, "tenant-a", graph_id, "backup", "items",
      WYL_POLICY_RELATION_ACTIVATION_UNBOUND, 0,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, FALSE, 0, TRUE, 1,
      "none", &activation_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (activation_result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_relation_activation
        (fixture->policy, "tenant-a", graph_id, "backup", "items",
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, 1,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVE, TRUE, 1, FALSE, 0,
      "none", &activation_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (activation_result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_transition_fact_graph_materialization
        (fixture->policy, "tenant-a", graph_id,
      WYL_POLICY_GRAPH_MATERIALIZATION_NEVER,
      WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
}

static void
seal_graph (BackupFixture *fixture, const gchar *graph_id)
{
  g_assert_cmpint (wyl_policy_store_seal_fact_graph (fixture->policy,
      "tenant-a", graph_id), ==, WYRELOG_E_OK);
}

static void
seal_tenant (BackupFixture *fixture)
{
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority
        (fixture->policy, "tenant-a", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
      WYL_POLICY_TENANT_LIFECYCLE_SEALING, 1, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority
        (fixture->policy, "tenant-a", WYL_POLICY_TENANT_LIFECYCLE_SEALING,
      WYL_POLICY_TENANT_LIFECYCLE_SEALED, 2, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
}

static void
assert_backup_authority (BackupFixture *fixture, guint expected_graphs)
{
  WylPolicyTenantAuthorityRecord *tenant = NULL;
  GPtrArray *graphs = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (fixture->policy,
      "tenant-a", &tenant), ==, WYRELOG_E_OK);
  g_assert_cmpint (tenant->lifecycle_state, ==,
      WYL_POLICY_TENANT_LIFECYCLE_SEALED);
  g_assert_true (tenant->sealed_compatibility);
  g_assert_cmpuint (tenant->lifecycle_generation, >, 0);
  g_assert_cmpint (wyl_policy_store_list_graph_authorities (fixture->policy,
      "tenant-a", &graphs), ==, WYRELOG_E_OK);
  g_assert_cmpuint (graphs->len, ==, expected_graphs);
  for (guint i = 0; i < graphs->len; i++) {
    WylPolicyGraphAuthorityRecord *graph = g_ptr_array_index (graphs, i);
    g_assert_cmpint (graph->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
    g_assert_true (graph->sealed_compatibility);
    g_assert_cmpint (graph->materialization_state, ==,
        WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED);
    g_assert_true (graph->has_store_identity);
    g_assert_cmpint (graph->last_error_class, ==,
        WYL_POLICY_GRAPH_ERROR_NONE);
  }
  g_ptr_array_unref (graphs);
  wyl_policy_tenant_authority_record_free (tenant);
}

static gchar *
graph_file_path (BackupFixture *fixture, const gchar *graph_id,
    const gchar *basename)
{
  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a",
      graph_id), ==, WYRELOG_E_OK);
  g_autofree gchar *directory = wyl_fact_graph_locator_descriptive_path
        (fixture->root, &locator);
  gchar *result = g_build_filename (directory, basename, NULL);
  wyl_fact_graph_locator_clear (&locator);
  return result;
}

typedef struct
{
  GByteArray *bytes;
  guint calls;
} CopyCapture;

static wyrelog_error_t
capture_bytes (guint64 offset, const guint8 *bytes, gsize length,
    gpointer user_data)
{
  CopyCapture *capture = user_data;
  g_assert_cmpuint (offset, ==, capture->bytes->len);
  g_byte_array_append (capture->bytes, bytes, length);
  capture->calls++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reject_bytes (guint64 offset, const guint8 *bytes, gsize length,
    gpointer user_data)
{
  (void) offset;
  (void) bytes;
  (void) length;
  (void) user_data;
  return WYRELOG_E_CANCELLED;
}

typedef enum
{
  DESTINATION_FAIL_NONE,
  DESTINATION_FAIL_BEGIN,
  DESTINATION_FAIL_WRITE,
  DESTINATION_FAIL_FINISH,
  DESTINATION_FAIL_PUBLISH,
  DESTINATION_FAIL_INVALID_PUBLISH,
  DESTINATION_MUTATE_SCHEMA_DURING_WRITE,
  DESTINATION_MUTATE_DURING_PUBLISH,
} DestinationBehavior;

typedef struct
{
  BackupFixture *fixture;
  DestinationBehavior behavior;
  GByteArray *bytes;
  GBytes *manifest;
  GString *events;
  gchar *checksum;
  gchar *current_graph;
  guint current_writes;
  GPtrArray *completed_graphs;
  GPtrArray *artifact_bytes;
  GPtrArray *artifact_checksums;
  guint aborts;
  guint publishes;
  gboolean mutated;
} DestinationCapture;

static void
destination_capture_clear (DestinationCapture *capture)
{
  g_clear_pointer (&capture->bytes, g_byte_array_unref);
  g_clear_pointer (&capture->manifest, g_bytes_unref);
  if (capture->events != NULL)
    g_string_free (capture->events, TRUE);
  capture->events = NULL;
  g_clear_pointer (&capture->checksum, g_free);
  g_clear_pointer (&capture->current_graph, g_free);
  g_clear_pointer (&capture->completed_graphs, g_ptr_array_unref);
  g_clear_pointer (&capture->artifact_bytes, g_ptr_array_unref);
  g_clear_pointer (&capture->artifact_checksums, g_ptr_array_unref);
}

static void
mutate_tenant_after_snapshot (DestinationCapture *capture)
{
  if (capture->mutated)
    return;
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority
        (capture->fixture->policy, "tenant-a",
      WYL_POLICY_TENANT_LIFECYCLE_SEALED,
      WYL_POLICY_TENANT_LIFECYCLE_UNSEALING, 3, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  capture->mutated = TRUE;
}

static wyrelog_error_t
destination_begin (const gchar *graph_id, guint64 logical_bytes,
    gpointer user_data)
{
  DestinationCapture *capture = user_data;
  g_assert_null (capture->current_graph);
  g_string_append_printf (capture->events, "begin:%s:%" G_GUINT64_FORMAT ";",
      graph_id, logical_bytes);
  if (capture->behavior == DESTINATION_FAIL_BEGIN)
    return WYRELOG_E_CANCELLED;
  capture->current_graph = g_strdup (graph_id);
  capture->current_writes = 0;
  g_byte_array_set_size (capture->bytes, 0);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
destination_write (const gchar *graph_id, guint64 offset,
    const guint8 *bytes, gsize length, gpointer user_data)
{
  DestinationCapture *capture = user_data;
  g_assert_nonnull (graph_id);
  g_assert_cmpstr (capture->current_graph, ==, graph_id);
  g_assert_cmpuint (offset, ==, capture->bytes->len);
  g_string_append (capture->events, "write;");
  if (capture->behavior == DESTINATION_FAIL_WRITE)
    return WYRELOG_E_CANCELLED;
  g_byte_array_append (capture->bytes, bytes, length);
  capture->current_writes++;
  if (capture->behavior == DESTINATION_MUTATE_SCHEMA_DURING_WRITE
      && !capture->mutated) {
    sqlite3 *db = wyl_policy_store_get_db (capture->fixture->policy);
    g_assert_cmpint (sqlite3_exec (db,
        "UPDATE fact_relation_schema_columns SET visible=0 "
        "WHERE tenant_id='tenant-a' AND graph_id='zeta' "
        "AND namespace_id='backup' AND relation_name='items' "
        "AND schema_version=1 AND column_index=0;",
        NULL, NULL, NULL), ==, SQLITE_OK);
    capture->mutated = TRUE;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
destination_finish (const gchar *graph_id, const gchar *checksum,
    gpointer user_data)
{
  DestinationCapture *capture = user_data;
  g_assert_nonnull (graph_id);
  g_assert_cmpstr (capture->current_graph, ==, graph_id);
  g_assert_cmpuint (capture->current_writes, >, 0);
  g_string_append (capture->events, "finish;");
  if (capture->behavior == DESTINATION_FAIL_FINISH)
    return WYRELOG_E_CANCELLED;
  g_ptr_array_add (capture->completed_graphs, g_steal_pointer (
        &capture->current_graph));
  g_ptr_array_add (capture->artifact_bytes, g_bytes_new (capture->bytes->data,
      capture->bytes->len));
  g_ptr_array_add (capture->artifact_checksums, g_strdup (checksum));
  g_clear_pointer (&capture->checksum, g_free);
  capture->checksum = g_strdup (checksum);
  return capture->checksum == NULL ? WYRELOG_E_NOMEM : WYRELOG_E_OK;
}

static WylFactOfflineBackupPublishOutcome
destination_publish (GBytes *manifest, gpointer user_data)
{
  DestinationCapture *capture = user_data;
  capture->publishes++;
  g_string_append (capture->events, "publish;");
  if (capture->behavior == DESTINATION_FAIL_PUBLISH)
    return WYL_FACT_OFFLINE_BACKUP_NOT_PUBLISHED;
  if (capture->behavior == DESTINATION_FAIL_INVALID_PUBLISH)
    return (WylFactOfflineBackupPublishOutcome) 99;
  capture->manifest = g_bytes_ref (manifest);
  if (capture->behavior == DESTINATION_MUTATE_DURING_PUBLISH)
    mutate_tenant_after_snapshot (capture);
  return WYL_FACT_OFFLINE_BACKUP_PUBLISHED;
}

static void
destination_abort (gpointer user_data)
{
  DestinationCapture *capture = user_data;
  capture->aborts++;
  g_string_append (capture->events, "abort;");
}

static const WylFactOfflineBackupDestination capture_destination = {
  destination_begin,
  destination_write,
  destination_finish,
  destination_publish,
  destination_abort,
};

static void
destination_capture_init (DestinationCapture *capture, BackupFixture *fixture,
    DestinationBehavior behavior)
{
  *capture = (DestinationCapture) {
    .fixture = fixture,
    .behavior = behavior,
    .bytes = g_byte_array_new (),
    .events = g_string_new (NULL),
    .completed_graphs = g_ptr_array_new_with_free_func (g_free),
    .artifact_bytes = g_ptr_array_new_with_free_func (
      (GDestroyNotify) g_bytes_unref),
    .artifact_checksums = g_ptr_array_new_with_free_func (g_free),
  };
}

static void
assert_captured_artifact (DestinationCapture *capture,
    WylFactOfflineBackupManifest *manifest, guint index,
    const gchar *expected_graph_id)
{
  g_assert_cmpstr (g_ptr_array_index (capture->completed_graphs, index), ==,
      expected_graph_id);
  GBytes *bytes = g_ptr_array_index (capture->artifact_bytes, index);
  gsize length = 0;
  const guint8 *data = g_bytes_get_data (bytes, &length);
  g_autofree gchar *digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
          data, length);
  g_autofree gchar *tagged = g_strdup_printf ("sha256:%s", digest);
  g_assert_cmpstr (g_ptr_array_index (capture->artifact_checksums, index), ==,
      tagged);
  WylFactOfflineBackupArtifact *artifact =
      g_ptr_array_index (manifest->artifacts, index);
  g_assert_cmpstr (artifact->graph_id, ==, expected_graph_id);
  g_assert_cmpstr (artifact->checksum, ==, tagged);
  g_assert_cmpuint (artifact->logical_bytes, ==, length);
}

static void
test_multi_graph_copy_and_lease_lifetime (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-backup-source-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "zeta");
  create_graph (&fixture, "alpha");
  seal_graph (&fixture, "zeta");
  seal_graph (&fixture, "alpha");
  seal_tenant (&fixture);
  assert_backup_authority (&fixture, 2);

  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (wyl_fact_offline_backup_source_count (source), ==, 2);
  g_assert_cmpuint (wyl_fact_offline_backup_source_policy_generation (source),
      >, 0);
  WylFactOfflineBackupSourceArtifact artifact = { 0 };
  g_assert_true (wyl_fact_offline_backup_source_get (source, 0, &artifact));
  g_assert_cmpstr (artifact.graph_id, ==, "alpha");
  g_assert_cmpuint (artifact.logical_bytes, >, 0);
  g_assert_cmpuint (artifact.physical_bytes, >, 0);
  g_autofree gchar *main_path = graph_file_path (&fixture, "alpha",
          "facts.duckdb");
  g_autofree gchar *expected = NULL;
  gsize expected_len = 0;
  g_assert_true (g_file_get_contents (main_path, &expected, &expected_len,
      NULL));
  g_assert_cmpuint (artifact.logical_bytes, ==, expected_len);

  CopyCapture capture = { g_byte_array_new (), 0 };
  guint64 copied = G_MAXUINT64;
  g_assert_cmpint (wyl_fact_offline_backup_source_copy_to_sink (source, 0,
      capture_bytes, &capture, &copied), ==, WYRELOG_E_OK);
  g_assert_cmpuint (copied, ==, expected_len);
  g_assert_cmpuint (capture.calls, >, 0);
  g_assert_cmpmem (capture.bytes->data, capture.bytes->len, expected,
      expected_len);
  g_byte_array_unref (capture.bytes);

  WylFactRootWriterLease *other = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture.root, &other),
      ==, WYRELOG_E_BUSY);
  g_assert_null (other);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture.root, &other),
      ==, WYRELOG_E_OK);
  g_autoptr (WylFactOfflineBackupSource) borrowed = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new_with_lease
        (fixture.policy, fixture.root, fixture.runtime, "tenant-a", 0, other,
      &borrowed), ==, WYRELOG_E_OK);
  g_clear_pointer (&borrowed, wyl_fact_offline_backup_source_free);
  g_assert_cmpint (wyl_fact_root_writer_lease_verify (other), ==,
      WYRELOG_E_OK);
  WylFactRootWriterLease *duplicate = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture.root,
      &duplicate), ==, WYRELOG_E_BUSY);
  g_assert_null (duplicate);
  wyl_fact_root_writer_lease_release (other);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture.root,
      &other), ==, WYRELOG_E_OK);
  wyl_fact_root_writer_lease_release (other);
  fixture_clear (&fixture);
}

static void
test_empty_tenant_and_active_tenant_rejected (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-backup-empty-XXXXXX");
  create_tenant (&fixture);
  WylFactOfflineBackupSource *source = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_POLICY);
  g_assert_null (source);
  seal_tenant (&fixture);
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (wyl_fact_offline_backup_source_count (source), ==, 0);
  wyl_fact_offline_backup_source_free (source);
  fixture_clear (&fixture);
}

static void
test_unsealed_graph_and_wal_rejected (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-backup-reject-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "orders");
  seal_tenant (&fixture);
  WylFactOfflineBackupSource *source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_POLICY);
  g_assert_null (source);
  seal_graph (&fixture, "orders");
  g_autofree gchar *wal = graph_file_path (&fixture, "orders",
          "facts.duckdb.wal");
  g_assert_true (g_file_set_contents (wal, "wal", 3, NULL));
  g_assert_cmpint (g_chmod (wal, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), !=,
      WYRELOG_E_OK);
  g_assert_null (source);
  fixture_clear (&fixture);
}

static void
test_sink_failure_and_policy_revalidation (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-backup-revalidate-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "orders");
  seal_graph (&fixture, "orders");
  seal_tenant (&fixture);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  guint64 copied = G_MAXUINT64;
  g_assert_cmpint (wyl_fact_offline_backup_source_copy_to_sink (source, 0,
      reject_bytes, NULL, &copied), ==, WYRELOG_E_CANCELLED);
  g_assert_cmpuint (copied, ==, 0);
  copied = G_MAXUINT64;
  g_assert_cmpint (wyl_fact_offline_backup_source_copy_to_sink (source, 99,
      capture_bytes, NULL, &copied), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (copied, ==, 0);
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority
        (fixture.policy, "tenant-a", WYL_POLICY_TENANT_LIFECYCLE_SEALED,
      WYL_POLICY_TENANT_LIFECYCLE_UNSEALING, 3, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_fact_offline_backup_source_revalidate (source), ==,
      WYRELOG_E_BUSY);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  fixture_clear (&fixture);
}

static void
test_generation_publication_and_failure_contract (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-backup-generate-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "orders");
  seal_graph (&fixture, "orders");
  seal_tenant (&fixture);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);

  DestinationCapture capture;
  destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_assert_cmpuint (capture.publishes, ==, 1);
  g_assert_cmpuint (capture.aborts, ==, 0);
  g_assert_true (g_str_has_prefix (capture.events->str, "begin:orders:"));
  g_assert_true (g_str_has_suffix (capture.events->str, "finish;publish;"));
  g_autofree gchar *expected_checksum = g_compute_checksum_for_data
        (G_CHECKSUM_SHA256, capture.bytes->data, capture.bytes->len);
  g_autofree gchar *tagged_checksum = g_strdup_printf ("sha256:%s",
          expected_checksum);
  g_assert_cmpstr (capture.checksum, ==, tagged_checksum);
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (capture.manifest,
      &manifest), ==, WYRELOG_E_OK);
  g_assert_cmpuint (manifest.artifacts->len, ==, 1);
  WylFactOfflineBackupArtifact *artifact =
      g_ptr_array_index (manifest.artifacts, 0);
  g_assert_cmpstr (artifact->graph_id, ==, "orders");
  g_assert_cmpstr (artifact->checksum, ==, tagged_checksum);
  g_assert_true (g_str_has_prefix (artifact->schema_digest, "sha256:"));
  g_assert_cmpuint (artifact->logical_bytes, ==, capture.bytes->len);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  destination_capture_clear (&capture);

  const DestinationBehavior failures[] = {
    DESTINATION_FAIL_BEGIN,
    DESTINATION_FAIL_WRITE,
    DESTINATION_FAIL_FINISH,
    DESTINATION_FAIL_PUBLISH,
    DESTINATION_FAIL_INVALID_PUBLISH,
  };
  for (guint i = 0; i < G_N_ELEMENTS (failures); i++) {
    destination_capture_init (&capture, &fixture, failures[i]);
    g_assert_cmpint (wyl_fact_offline_backup_generate (source,
        &capture_destination, &capture), !=, WYRELOG_E_OK);
    g_assert_cmpuint (capture.aborts, ==, 1);
    g_assert_true (g_str_has_suffix (capture.events->str, "abort;"));
    g_assert_cmpuint (capture.publishes, ==,
        failures[i] >= DESTINATION_FAIL_PUBLISH ? 1 : 0);
    g_assert_null (capture.manifest);
    destination_capture_clear (&capture);
  }
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  fixture_clear (&fixture);
}

static void
test_generation_policy_linearization (void)
{
  BackupFixture before = { 0 };
  fixture_init (&before, "wyl-offline-backup-before-XXXXXX");
  create_tenant (&before);
  create_graph (&before, "zeta");
  create_graph (&before, "alpha");
  seal_graph (&before, "zeta");
  seal_graph (&before, "alpha");
  seal_tenant (&before);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (before.policy,
      before.root, before.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  DestinationCapture capture;
  destination_capture_init (&capture, &before,
      DESTINATION_MUTATE_SCHEMA_DURING_WRITE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_BUSY);
  g_assert_true (capture.mutated);
  g_assert_cmpuint (capture.publishes, ==, 0);
  g_assert_cmpuint (capture.aborts, ==, 1);
  destination_capture_clear (&capture);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  fixture_clear (&before);

  BackupFixture after = { 0 };
  fixture_init (&after, "wyl-offline-backup-after-XXXXXX");
  create_tenant (&after);
  create_graph (&after, "orders");
  seal_graph (&after, "orders");
  seal_tenant (&after);
  g_assert_cmpint (wyl_fact_offline_backup_source_new (after.policy,
      after.root, after.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  destination_capture_init (&capture, &after,
      DESTINATION_MUTATE_DURING_PUBLISH);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_assert_true (capture.mutated);
  g_assert_cmpuint (capture.publishes, ==, 1);
  g_assert_cmpuint (capture.aborts, ==, 0);
  destination_capture_clear (&capture);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  fixture_clear (&after);
}

static void
test_generation_empty_tenant (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-backup-empty-generate-XXXXXX");
  create_tenant (&fixture);
  seal_tenant (&fixture);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  DestinationCapture capture;
  destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_assert_cmpstr (capture.events->str, ==, "publish;");
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (capture.manifest,
      &manifest), ==, WYRELOG_E_OK);
  g_assert_cmpuint (manifest.artifacts->len, ==, 0);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  destination_capture_clear (&capture);
  fixture_clear (&fixture);
}

static void
test_generation_multi_graph_order (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-backup-multi-generate-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "zeta");
  create_graph (&fixture, "alpha");
  seal_graph (&fixture, "zeta");
  seal_graph (&fixture, "alpha");
  seal_tenant (&fixture);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  DestinationCapture capture;
  destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_assert_null (capture.current_graph);
  g_assert_cmpuint (capture.completed_graphs->len, ==, 2);
  g_assert_cmpuint (capture.artifact_bytes->len, ==, 2);
  g_assert_cmpuint (capture.artifact_checksums->len, ==, 2);
  g_assert_cmpuint (capture.publishes, ==, 1);
  g_assert_cmpuint (capture.aborts, ==, 0);
  g_assert_true (g_str_has_suffix (capture.events->str, "finish;publish;"));
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (capture.manifest,
      &manifest), ==, WYRELOG_E_OK);
  g_assert_cmpuint (manifest.artifacts->len, ==, 2);
  assert_captured_artifact (&capture, &manifest, 0, "alpha");
  assert_captured_artifact (&capture, &manifest, 1, "zeta");
  wyl_fact_offline_backup_manifest_clear (&manifest);
  destination_capture_clear (&capture);
  fixture_clear (&fixture);
}

static void
create_restore_journal_for_manifest_internal (BackupFixture *fixture, GBytes *manifest,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id,
    const gchar *operation_uuid, gboolean session_identity, const gchar *mode)
{
  WylPolicyTenantAuthorityRecord *tenant = NULL;
  GPtrArray *authorities = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (fixture->policy,
      "tenant-a", &tenant), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_list_graph_authorities (fixture->policy,
      "tenant-a", &authorities), ==, WYRELOG_E_OK);
  g_autoptr (GPtrArray) targets = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_restore_target_graph_free);
  for (guint i = 0; i < authorities->len; i++) {
    WylPolicyGraphAuthorityRecord *authority = g_ptr_array_index
          (authorities, i);
    if (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && g_strcmp0 (authority->graph_id, selected_graph_id) != 0)
      continue;
    WylFactOfflineRestoreTargetGraph *target = g_new0
          (WylFactOfflineRestoreTargetGraph, 1);
    target->graph_id = g_strdup (authority->graph_id);
    target->lifecycle_generation = MAX (authority->lifecycle_generation,
            (guint64) 1);
    target->reconciliation_generation = MAX
          (authority->reconciliation_generation, (guint64) 1);
    target->expected_main_absent = TRUE;
#ifndef G_OS_WIN32
    if (session_identity) {
      target->lifecycle_generation = authority->lifecycle_generation;
      target->reconciliation_generation = authority->reconciliation_generation;
      g_autofree gchar *path = graph_file_path (fixture, authority->graph_id,
              "facts.duckdb");
      GStatBuf statbuf;
      g_assert_cmpint (g_stat (path, &statbuf), ==, 0);
      target->expected_main_absent = FALSE;
      target->expected_main_identity.domain = (guint64) statbuf.st_dev;
      target->expected_main_identity.object = (guint64) statbuf.st_ino;
    }
#else
    (void) session_identity;
#endif
    g_ptr_array_add (targets, target);
  }
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      operation_uuid, scope, selected_graph_id, tenant->lifecycle_generation,
      tenant->reconciliation_generation, targets,
      g_strcmp0 (mode, "unconfirmed") == 0
      ? WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_NONE
      : WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      g_strcmp0 (mode, "untrusted") == 0
      ? WYL_FACT_OFFLINE_RESTORE_MANIFEST_UNVERIFIED
      : WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournal committed = { 0 };
  WylFactOfflineRestoreStoreResult result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (fixture->policy, &journal, &result, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_assert_cmpuint (committed.revision, ==, 1);
  wyl_fact_offline_restore_journal_clear (&committed);
  wyl_fact_offline_restore_journal_clear (&journal);
  g_ptr_array_unref (authorities);
  wyl_policy_tenant_authority_record_free (tenant);
}

static void
create_restore_journal_for_manifest (BackupFixture *fixture, GBytes *manifest,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id,
    const gchar *operation_uuid)
{
  create_restore_journal_for_manifest_internal (fixture, manifest, scope,
      selected_graph_id, operation_uuid, FALSE, NULL);
}

static gboolean
artifact_identity_is_zero (const WylFactArtifactInventoryIdentity *identity)
{
  WylFactArtifactInventoryIdentity zero = { 0 };
  return wyl_fact_artifact_inventory_identity_equal (identity, &zero);
}

static void
test_tenant_restore_staging_coordinator (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-restore-coordinator-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "zeta");
  create_graph (&fixture, "alpha");
  seal_graph (&fixture, "zeta");
  seal_graph (&fixture, "alpha");
  seal_tenant (&fixture);

  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  DestinationCapture capture;
  destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  g_assert_nonnull (capture.manifest);
  create_restore_journal_for_manifest (&fixture, capture.manifest,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL,
      "018f22d0-7b6d-7a5b-8c31-123456789ab1");

  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_stages_run
        (fixture.policy, fixture.root, fixture.runtime, "tenant-a",
      capture.manifest, "018f22d0-7b6d-7a5b-8c31-123456789ab1", 1, 0,
      &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 3);
  g_assert_cmpuint (committed.graphs->len, ==, 2);
  for (guint i = 0; i < committed.graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (committed.graphs, i);
    g_assert_false (artifact_identity_is_zero (&graph->staged_main_identity));
    g_assert_false (graph->copied);
    g_assert_false (graph->checksum_verified);
    g_assert_false (graph->schema_verified);
  }
  wyl_fact_offline_restore_journal_clear (&committed);

  /* A graph-local journal is rejected before source construction/drain. Use
   * another policy store because active restore claims are exclusive per
   * tenant and the successful tenant journal still owns this fixture. */
  BackupFixture scope_fixture = { 0 };
  fixture_init (&scope_fixture,
      "wyl-offline-restore-coordinator-graph-scope-XXXXXX");
  create_tenant (&scope_fixture);
  create_graph (&scope_fixture, "alpha");
  seal_graph (&scope_fixture, "alpha");
  seal_tenant (&scope_fixture);
  create_restore_journal_for_manifest (&scope_fixture, capture.manifest,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha",
      "018f22d0-7b6d-7a5b-8c31-123456789ab2");
  g_assert_cmpint (wyl_fact_offline_restore_tenant_stages_run
        (scope_fixture.policy, scope_fixture.root, scope_fixture.runtime,
      "tenant-a",
      capture.manifest, "018f22d0-7b6d-7a5b-8c31-123456789ab2", 1, 0,
      &committed), ==, WYRELOG_E_POLICY);
  WylFactRootWriterLease *lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (scope_fixture.root,
      &lease), ==, WYRELOG_E_OK);
  wyl_fact_root_writer_lease_release (lease);
  fixture_clear (&scope_fixture);
  destination_capture_clear (&capture);
  fixture_clear (&fixture);
}

static void
test_tenant_restore_staging_rejects_bad_checksum (void)
{
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-restore-bad-checksum-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "orders");
  seal_graph (&fixture, "orders");
  seal_tenant (&fixture);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  DestinationCapture capture;
  destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);

  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (capture.manifest,
      &manifest), ==, WYRELOG_E_OK);
  WylFactOfflineBackupArtifact *artifact = g_ptr_array_index
        (manifest.artifacts, 0);
  g_free (artifact->checksum);
  artifact->checksum = g_strdup
        ("sha256:0000000000000000000000000000000000000000000000000000000000000000");
  g_autoptr (GBytes) bad_manifest = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&manifest,
      &bad_manifest), ==, WYRELOG_E_OK);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  const gchar *const operation_uuid =
      "018f22d0-7b6d-7a5b-8c31-123456789ab3";
  create_restore_journal_for_manifest (&fixture, bad_manifest,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, operation_uuid);

  WylFactOfflineRestoreJournal result = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_stages_run
        (fixture.policy, fixture.root, fixture.runtime, "tenant-a",
      bad_manifest, operation_uuid, 1, 0, &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.graphs);
  WylFactOfflineRestoreJournal durable = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load (fixture.policy,
      operation_uuid, &durable), ==, WYRELOG_E_OK);
  g_assert_cmpuint (durable.revision, ==, 1);
  WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
        (durable.graphs, 0);
  g_assert_true (artifact_identity_is_zero (&graph->staged_main_identity));
  wyl_fact_offline_restore_journal_clear (&durable);
  destination_capture_clear (&capture);
  fixture_clear (&fixture);
}

#ifndef G_OS_WIN32
static const gchar *session_operation =
    "018f22d0-7b6d-7a5b-8c31-123456789ab4";

typedef struct
{
  BackupFixture fixture;
  DestinationCapture capture;
  WylFactGraphSnapshot *snapshots[2];
  GBytes *journal_before;
  WylFactOfflineRestoreValidationSession *session;
  WylFactOfflineRestoreValidationResult result;
  const gchar *mode;
  guint checkpoints;
  GCancellable *cancel;
} SessionFixture;

static wyrelog_error_t
session_build_engine (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer data)
{
  (void) key;
  (void) data;
  return wyl_engine_open_source (".decl marker(value: int64)\n"
             ".decl observed(value: int64)\nobserved(V) :- marker(V).\n",
             1, out_engine);
}

static wyrelog_error_t
session_snapshot_callback (WylEngine *engine, gpointer data)
{
  g_assert_nonnull (engine);
  (*(guint *) data)++;
  return WYRELOG_E_OK;
}

static void
session_assert_authority (SessionFixture *f, gboolean retained)
{
  WylFactRootWriterLease *lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (f->fixture.root,
      &lease), ==, retained ? WYRELOG_E_BUSY : WYRELOG_E_OK);
  wyl_fact_root_writer_lease_release (lease);
  for (guint i = 0; i < 2; i++) {
    if (f->snapshots[i] == NULL)
      continue;
    guint calls = 0;
    g_assert_cmpint (wyl_fact_graph_snapshot_use (f->snapshots[i],
        session_snapshot_callback, &calls), ==,
        retained ? WYRELOG_E_BUSY : WYRELOG_E_OK);
    g_assert_cmpuint (calls, ==, retained ? 0 : 1);
  }
}

static GHashTable *
session_graph_files (SessionFixture *f)
{
  GHashTable *files = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
          (GDestroyNotify) g_bytes_unref);
  const gchar *graphs[] = { "alpha", "zeta" };
  for (guint i = 0; i < 2; i++) {
    g_autofree gchar *main = graph_file_path (&f->fixture, graphs[i],
            "facts.duckdb");
    g_autofree gchar *directory = g_path_get_dirname (main);
    g_autoptr (GDir) dir = g_dir_open (directory, 0, NULL);
    g_assert_nonnull (dir);
    const gchar *name;
    while ((name = g_dir_read_name (dir)) != NULL) {
      gchar *path = g_build_filename (directory, name, NULL);
      gchar *contents = NULL;
      gsize length = 0;
      g_assert_true (g_file_get_contents (path, &contents, &length, NULL));
      g_hash_table_insert (files, path, g_bytes_new_take (contents, length));
    }
  }
  return files;
}

static void
session_assert_files_unchanged (SessionFixture *f, GHashTable *before)
{
  g_autoptr (GHashTable) after = session_graph_files (f);
  g_assert_cmpuint (g_hash_table_size (before), ==, g_hash_table_size (after));
  GHashTableIter iter;
  gpointer path, bytes;
  g_hash_table_iter_init (&iter, before);
  while (g_hash_table_iter_next (&iter, &path, &bytes)) {
    GBytes *actual = g_hash_table_lookup (after, path);
    g_assert_nonnull (actual);
    g_assert_true (g_bytes_equal (bytes, actual));
  }
}

static GBytes *
session_journal_bytes (SessionFixture *f)
{
  WylFactOfflineRestoreJournal journal = { 0 };
  GBytes *bytes = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f->fixture.policy, session_operation, &journal), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&journal,
      &bytes), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_journal_clear (&journal);
  return bytes;
}

static void
session_stage_one_graph (SessionFixture *f, guint index)
{
  const gchar *graph = index == 0 ? "alpha" : "zeta";
  WylFactGraphLocator locator = { 0 };
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactRootWriterLease *lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (f->fixture.root,
      &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-a", graph),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (f->fixture.root, &resolver),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
      &locator, FALSE, &directory), ==, WYRELOG_E_OK);
  GBytes *payload = g_ptr_array_index (f->capture.artifact_bytes, index);
  gsize length = 0;
  const guint8 *bytes = g_bytes_get_data (payload, &length);
  g_autoptr (WylFactOfflineRestoreStage) stage = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&resolver, &directory,
      lease, session_operation, length,
      g_ptr_array_index (f->capture.artifact_checksums, index), &stage), ==,
      WYRELOG_E_OK);
  for (gsize offset = 0; offset < length;) {
    gsize chunk = MIN ((gsize) 64 * 1024, length - offset);
    g_assert_cmpint (wyl_fact_offline_restore_stage_sink (offset,
        bytes + offset, chunk, stage), ==, WYRELOG_E_OK);
    offset += chunk;
  }
  guint64 written = 0;
  WylFactArtifactInventoryIdentity identity = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &written,
      &identity), ==, WYRELOG_E_OK);
  g_assert_cmpuint (written, ==, length);
  g_clear_pointer (&stage, wyl_fact_offline_restore_stage_free);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_root_writer_lease_release (lease);
  WylFactOfflineRestoreJournal journal = { 0 }, committed = { 0 };
  WylFactOfflineRestoreStoreResult result;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f->fixture.policy, session_operation, &journal), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, graph, &identity), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (f->fixture.policy, index + 1, &journal, &result, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_assert_cmpuint (committed.revision, ==, index + 2);
  wyl_fact_offline_restore_journal_clear (&journal);
  wyl_fact_offline_restore_journal_clear (&committed);
}

static void
session_remove_main_pair (SessionFixture *f, gboolean leave_companion)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (f->fixture.policy),
      "SELECT graph_id,stage_basename FROM fact_graph_provisioning "
      "WHERE tenant_id='tenant-a' ORDER BY graph_id;", -1, &stmt, NULL),
      ==, SQLITE_OK);
  guint removed = 0;
  gint rc;
  while ((rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *graph = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *companion = (const gchar *) sqlite3_column_text (stmt, 1);
    g_autofree gchar *main_path = graph_file_path (&f->fixture, graph,
            "facts.duckdb");
    g_assert_cmpint (g_remove (main_path), ==, 0);
    g_autofree gchar *companion_path = graph_file_path (&f->fixture, graph,
            companion);
#ifdef __APPLE__
    /* Darwin publishes without a retained provisioning hard link. Create
     * an actual orphan for the negative case instead of assuming it exists. */
    g_assert_false (g_file_test (companion_path, G_FILE_TEST_EXISTS));
    if (leave_companion) {
      g_assert_true (g_file_set_contents (companion_path, "orphan", -1, NULL));
      g_assert_cmpint (g_chmod (companion_path, 0600), ==, 0);
    }
#else
    if (!leave_companion)
      g_assert_cmpint (g_remove (companion_path), ==, 0);
#endif
    removed++;
  }
  g_assert_cmpint (rc, ==, SQLITE_DONE);
  g_assert_cmpuint (removed, ==, 2);
  g_assert_cmpint (sqlite3_finalize (stmt), ==, SQLITE_OK);
}

static void
session_fixture_init (SessionFixture *f, const gchar *mode)
{
  f->mode = mode;
  fixture_init (&f->fixture, "wyl-restore-session-XXXXXX");
  create_tenant (&f->fixture);
  const gchar *graphs[] = { "alpha", "zeta" };
  for (guint i = 0; i < 2; i++) {
    create_graph (&f->fixture, graphs[i]);
    /* Populate the active projection so session success proves real replay. */
    g_autoptr (wyl_fact_store_t) store = NULL;
    g_assert_cmpint (wyl_fact_store_open_provisioned_graph (f->fixture.policy,
        f->fixture.root, "tenant-a", graphs[i], TRUE, &store), ==,
        WYRELOG_E_OK);
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      { "id", "symbol", FALSE, TRUE },
    };
    const wyl_policy_fact_relation_schema_options_t schema = {
      .tenant_id = "tenant-a", .graph_id = graphs[i],
      .namespace_id = "backup", .relation_name = "items",
      .schema_version = 1, .relation_visible = TRUE,
      .columns = columns, .n_columns = G_N_ELEMENTS (columns),
    };
    const wyl_fact_value_t values[] = {
      { .type = WYL_FACT_VALUE_SYMBOL, .as.text = "session-row" },
    };
    const wyl_fact_row_t rows[] = { { values, G_N_ELEMENTS (values) } };
    const wyl_fact_store_batch_t batch = {
      .batch_id = "session-batch", .tenant_id = "tenant-a",
      .graph_id = graphs[i], .namespace_id = "backup",
      .relation_name = "items", .schema_version = 1, .source = "test",
      .idempotency_key = "session", .op = WYL_FACT_STORE_OP_ASSERT,
      .rows = rows, .n_rows = G_N_ELEMENTS (rows),
    };
    gboolean created = FALSE;
    g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
        &created), ==, WYRELOG_E_OK);
    g_assert_true (created);
    g_clear_pointer (&store, wyl_fact_store_close);
    if (!(i == 1 && g_str_equal (mode, "missing-runtime"))) {
      WylFactGraphKey key = { 0 };
      g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", graphs[i]),
          ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh
            (f->fixture.runtime, &key, session_build_engine, NULL, NULL),
          ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot
            (f->fixture.runtime, &key, &f->snapshots[i]), ==, WYRELOG_E_OK);
      wyl_fact_graph_key_clear (&key);
    }
    /* Establish a positive reconciliation epoch through legal transitions,
     * so the journal copies exact generations without MAX rounding. */
    WylPolicyGraphAuthorityRecord *authority = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (f->fixture.policy,
        "tenant-a", graphs[i], &authority), ==, WYRELOG_E_OK);
    WylPolicyAuthorityMutationResult mutation;
    g_assert_cmpint (wyl_policy_store_transition_graph_authority
          (f->fixture.policy, "tenant-a", graphs[i],
        WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
        WYL_POLICY_GRAPH_ERROR_REPLAY, authority->lifecycle_generation,
        authority->reconciliation_generation, &mutation), ==, WYRELOG_E_OK);
    g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    g_assert_cmpint (wyl_policy_store_reconcile_graph_authority
          (f->fixture.policy, "tenant-a", graphs[i],
        authority->lifecycle_generation + 1,
        authority->reconciliation_generation, &mutation), ==, WYRELOG_E_OK);
    g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    wyl_policy_graph_authority_record_free (authority);
    seal_graph (&f->fixture, graphs[i]);
  }
  seal_tenant (&f->fixture);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (f->fixture.policy,
      f->fixture.root, f->fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  destination_capture_init (&f->capture, &f->fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &f->capture), ==, WYRELOG_E_OK);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  gboolean graph_scope = g_str_equal (mode, "graph-scope");
  create_restore_journal_for_manifest_internal (&f->fixture,
      f->capture.manifest, graph_scope ? WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      : WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT,
      graph_scope ? "alpha" : NULL, session_operation,
      !(g_str_equal (mode, "main-absence-violated")
      || g_str_equal (mode, "stage-only")
      || g_str_equal (mode, "orphan-provision")), mode);
  if (g_str_equal (mode, "partial-staging"))
    session_stage_one_graph (f, 0);
  else if (g_str_equal (mode, "untrusted") || g_str_equal (mode, "unconfirmed")) {
    session_stage_one_graph (f, 0);
    session_stage_one_graph (f, 1);
  }else if (!graph_scope && !g_str_equal (mode, "unstaged")) {
    WylFactOfflineRestoreJournal staged = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_tenant_stages_run
          (f->fixture.policy, f->fixture.root, f->fixture.runtime, "tenant-a",
        f->capture.manifest, session_operation, 1, 0, &staged), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (staged.revision, ==, 3);
    wyl_fact_offline_restore_journal_clear (&staged);
  }
  if (g_str_equal (mode, "stage-only") || g_str_equal (mode, "orphan-provision"))
    session_remove_main_pair (f, g_str_equal (mode, "orphan-provision"));
  if (g_str_equal (mode, "preflight-flags")) {
    WylFactOfflineRestoreJournal journal = { 0 }, committed = { 0 };
    WylFactOfflineRestoreStoreResult result;
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (f->fixture.policy, session_operation, &journal), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_mark_preflight (&journal,
        "alpha"), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
          (f->fixture.policy, 3, &journal, &result, &committed), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
    wyl_fact_offline_restore_journal_clear (&journal);
    wyl_fact_offline_restore_journal_clear (&committed);
  }
  f->journal_before = session_journal_bytes (f);
  f->cancel = g_cancellable_new ();
  session_assert_authority (f, FALSE);
}

static void
session_fixture_clear (SessionFixture *f)
{
  g_autoptr (GBytes) after = session_journal_bytes (f);
  g_assert_true (g_bytes_equal (f->journal_before, after));
  g_clear_pointer (&f->session,
      wyl_fact_offline_restore_validation_session_free);
  session_assert_authority (f, FALSE);
  for (guint i = 0; i < 2; i++)
    g_clear_pointer (&f->snapshots[i], wyl_fact_graph_snapshot_unref);
  g_clear_object (&f->cancel);
  g_bytes_unref (f->journal_before);
  destination_capture_clear (&f->capture);
  fixture_clear (&f->fixture);
}

static gchar *
session_stage_path (SessionFixture *f, const gchar *graph)
{
  g_autofree gchar *name = g_strdup_printf ("restore-%s.duckdb",
          session_operation);
  return graph_file_path (&f->fixture, graph, name);
}

static void
session_corrupt_stage (SessionFixture *f, const gchar *graph)
{
  g_autofree gchar *path = session_stage_path (f, graph);
  FILE *file = g_fopen (path, "r+b");
  g_assert_nonnull (file);
  gint original = fgetc (file);
  g_assert_cmpint (original, !=, EOF);
  g_assert_cmpint (fseek (file, 0, SEEK_SET), ==, 0);
  g_assert_cmpint (fputc (original ^ 0xff, file), !=, EOF);
  g_assert_cmpint (fclose (file), ==, 0);
}

static wyrelog_error_t
session_checkpoint (const gchar *graph, gpointer data)
{
  SessionFixture *f = data;
  f->checkpoints++;
  g_assert_cmpstr (graph, ==, f->checkpoints % 2 == 1 ? "alpha" : "zeta");
  session_assert_authority (f, TRUE);
  if (g_str_equal (f->mode, "second-graph-failure") && f->checkpoints == 1)
    session_corrupt_stage (f, "zeta");
  if (g_str_equal (f->mode, "first-graph-late-mutation")
      && f->checkpoints == 2)
    session_corrupt_stage (f, "alpha");
  if (g_str_equal (f->mode, "cancel"))
    g_cancellable_cancel (f->cancel);
  if (f->checkpoints == 2 && g_str_equal (f->mode, "policy-change"))
    mutate_tenant_after_snapshot (&f->capture);
  if (f->checkpoints == 2 && g_str_equal (f->mode, "schema-change"))
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f->fixture.policy),
        "UPDATE fact_relation_schema_columns SET visible=0 "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
  if (f->checkpoints == 2 && g_str_equal (f->mode, "provision-change"))
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f->fixture.policy),
        "DELETE FROM fact_graph_provisioning "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
session_job (WylFactReplayJobContext *context, gpointer data)
{
  SessionFixture *f = data;
  return wyl_fact_offline_restore_validation_session_run (f->session,
             context, &f->result);
}

static wyrelog_error_t
session_run_worker (SessionFixture *f)
{
  WylFactReplaySchedulerConfig config;
  wyl_fact_replay_scheduler_config_defaults (&config);
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant-a",
      "alpha", f->cancel, session_job, f, NULL, &future), ==, WYRELOG_E_OK);
  wyrelog_error_t rc = wyl_fact_replay_future_wait (future);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  return rc;
}

static void
test_restore_validation_session_run (gconstpointer data)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, data);
  g_autoptr (GHashTable) files_before = session_graph_files (&f);
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
      session_operation, 3, 0, &f.session), ==, WYRELOG_E_OK);
  session_assert_authority (&f, TRUE);
  wyl_fact_offline_restore_validation_session_set_checkpoint_for_test
    (f.session, session_checkpoint, &f);
  wyrelog_error_t rc = session_run_worker (&f);
  if (g_str_equal (f.mode, "success") || g_str_equal (f.mode, "stage-only")
      || g_str_equal (f.mode, "successful-rerun-mutation")) {
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    g_assert_cmpint (f.result.status, ==,
        WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED);
    g_assert_cmpuint (f.result.checked_graph_count, ==, 2);
    g_assert_cmpuint (f.result.validated_revision, ==, 3);
    g_assert_cmpuint (f.result.pending_checks, ==, 0);
    g_assert_cmpuint (f.checkpoints, ==, 2);
    session_assert_authority (&f, TRUE);
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.checkpoints, ==, 4);
    session_assert_authority (&f, TRUE);
    session_assert_files_unchanged (&f, files_before);
    if (!g_str_equal (f.mode, "successful-rerun-mutation")) {
      g_clear_pointer (&f.session,
          wyl_fact_offline_restore_validation_session_free);
      session_assert_files_unchanged (&f, files_before);
      session_fixture_clear (&f);
      return;
    }
    /* A successful rerun must collect fresh evidence too. */
    session_corrupt_stage (&f, "alpha");
    g_assert_cmpint (session_run_worker (&f), !=, WYRELOG_E_OK);
  } else {
    g_assert_cmpint (rc, !=, WYRELOG_E_OK);
    if (g_str_equal (f.mode, "cancel"))
      g_assert_cmpint (rc, ==, WYRELOG_E_CANCELLED);
    g_assert_cmpuint (f.checkpoints, ==,
        g_str_equal (f.mode, "second-graph-failure")
        || g_str_equal (f.mode, "cancel") ? 1 : 2);
  }
  session_assert_authority (&f, FALSE);
  g_cancellable_reset (f.cancel);
  g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_INVALID);
  session_fixture_clear (&f);
}

static void
test_restore_validation_session_constructor_rejects (gconstpointer data)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, data);
  const gchar *entry = NULL;
  if (g_str_equal (f.mode, "unknown-entry"))
    entry = "unexpected";
  else if (g_str_equal (f.mode, "foreign-stage"))
    entry = "restore-018f22d0-7b6d-7a5b-8c31-123456789ab5.duckdb";
  else if (g_str_equal (f.mode, "operation-sidecar"))
    entry = "restore-018f22d0-7b6d-7a5b-8c31-123456789ab4.duckdb.wal";
  else if (g_str_equal (f.mode, "foreign-provision"))
    entry = "provision-018f22d0-7b6d-7a5b-8c31-123456789ab5.sqlite";
  if (entry != NULL) {
    g_autofree gchar *path = graph_file_path (&f.fixture, "zeta", entry);
    g_assert_true (g_file_set_contents (path, "foreign", -1, NULL));
    g_assert_cmpint (g_chmod (path, 0600), ==, 0);
  }
  if (g_str_equal (f.mode, "missing-stage")) {
    g_autofree gchar *path = session_stage_path (&f, "zeta");
    g_assert_cmpint (g_remove (path), ==, 0);
  }
  guint64 revision = g_str_equal (f.mode, "stale-revision")
      || g_str_equal (f.mode, "partial-staging") ? 2 : 3;
  if (g_str_equal (f.mode, "unstaged") || g_str_equal (f.mode, "graph-scope"))
    revision = 1;
  if (g_str_equal (f.mode, "preflight-flags"))
    revision = 4;
  wyrelog_error_t rc = wyl_fact_offline_restore_validation_session_new
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
          session_operation, revision, 0, &f.session);
  g_assert_cmpint (rc, !=, WYRELOG_E_OK);
  if (g_str_equal (f.mode, "missing-runtime"))
    g_assert_cmpint (rc, ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (f.session);
  session_assert_authority (&f, FALSE);
  session_fixture_clear (&f);
}
#endif

static void
test_restore_validation_session_invalid_constructor (void)
{
  g_autoptr (WylFactOfflineRestoreValidationSession) session = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new (NULL,
      NULL, NULL, NULL, NULL, 0, 0, &session), ==, WYRELOG_E_INVALID);
  g_assert_null (session);
}

static void
test_restore_validation_session_windows_fail_closed (void)
{
#ifdef G_OS_WIN32
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-session-windows-XXXXXX");
  g_auto (WylFactOfflineBackupManifest) manifest = { 0 };
  g_autoptr (GBytes) canonical = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init (&manifest,
      "tenant-a", 1), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&manifest,
      &canonical), ==, WYRELOG_E_OK);
  g_autoptr (WylFactOfflineRestoreValidationSession) session = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new
        (fixture.policy, fixture.root, fixture.runtime, canonical,
      "018f22d0-7b6d-7a5b-8c31-123456789ab4", 1, 0, &session), ==,
      WYRELOG_E_POLICY);
  g_assert_null (session);
  fixture_clear (&fixture);
#else
  g_test_skip ("Windows-only fail-closed boundary");
#endif
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-offline-backup-source/session-invalid-constructor",
      test_restore_validation_session_invalid_constructor);
  g_test_add_func ("/fact-offline-backup-source/session-windows-fail-closed",
      test_restore_validation_session_windows_fail_closed);
#ifndef G_OS_WIN32
  const gchar *session_runs[] = { "success", "stage-only", "successful-rerun-mutation",
                                  "second-graph-failure",
                                  "first-graph-late-mutation", "cancel", "policy-change", "schema-change",
                                  "provision-change" };
  for (guint i = 0; i < G_N_ELEMENTS (session_runs); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/session/",
            session_runs[i], NULL);
    g_test_add_data_func (path, session_runs[i], test_restore_validation_session_run);
  }
  const gchar *session_rejections[] = { "unknown-entry", "foreign-stage",
                                        "operation-sidecar", "foreign-provision", "missing-stage",
                                        "main-absence-violated", "stale-revision", "unstaged", "graph-scope",
                                        "missing-runtime", "partial-staging", "orphan-provision",
                                        "untrusted", "unconfirmed", "preflight-flags" };
  for (guint i = 0; i < G_N_ELEMENTS (session_rejections); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/session/",
            session_rejections[i], NULL);
    g_test_add_data_func (path, session_rejections[i],
        test_restore_validation_session_constructor_rejects);
  }
#endif
  g_test_add_func ("/fact-offline-backup-source/multi-graph-copy",
      test_multi_graph_copy_and_lease_lifetime);
  g_test_add_func ("/fact-offline-backup-source/empty-active",
      test_empty_tenant_and_active_tenant_rejected);
  g_test_add_func ("/fact-offline-backup-source/unsealed-wal",
      test_unsealed_graph_and_wal_rejected);
  g_test_add_func ("/fact-offline-backup-source/sink-revalidate",
      test_sink_failure_and_policy_revalidation);
  g_test_add_func ("/fact-offline-backup-source/generation-publication",
      test_generation_publication_and_failure_contract);
  g_test_add_func ("/fact-offline-backup-source/generation-linearization",
      test_generation_policy_linearization);
  g_test_add_func ("/fact-offline-backup-source/generation-empty",
      test_generation_empty_tenant);
  g_test_add_func ("/fact-offline-backup-source/generation-multi-graph",
      test_generation_multi_graph_order);
  g_test_add_func ("/fact-offline-backup-source/restore-staging-coordinator",
      test_tenant_restore_staging_coordinator);
  g_test_add_func
    ("/fact-offline-backup-source/restore-staging-bad-checksum",
      test_tenant_restore_staging_rejects_bad_checksum);
  return wyl_test_normalize_exit_status (g_test_run ());
}

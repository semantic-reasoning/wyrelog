/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-backup-generation-private.h"
#include "wyrelog/fact/offline-backup-manifest-private.h"
#include "wyrelog/fact/offline-backup-source-private.h"
#include "wyrelog/fact/offline-restore-coordinator-private.h"
#include "wyrelog/fact/offline-restore-journal-private.h"
#include "wyrelog/fact/offline-restore-journal-store-private.h"
#include "wyrelog/fact/provisioning-run-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"
#include "wyrelog/fact/store-open-private.h"
#include "wyrelog/fact/store-private.h"

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
create_restore_journal_for_manifest (BackupFixture *fixture, GBytes *manifest,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id,
    const gchar *operation_uuid)
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
    g_ptr_array_add (targets, target);
  }
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&journal, manifest,
      operation_uuid, scope, selected_graph_id, tenant->lifecycle_generation,
      tenant->reconciliation_generation, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
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

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
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

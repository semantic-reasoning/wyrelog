/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <string.h>
#include <stdio.h>
#include <duckdb.h>
#ifndef G_OS_WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "fact-test-support.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/graph-artifact-transition-posix-private.h"
#include "wyrelog/fact/offline-backup-generation-private.h"
#include "wyrelog/fact/offline-backup-manifest-private.h"
#include "wyrelog/fact/offline-backup-bundle-private.h"
#include "wyrelog/fact/offline-backup-source-private.h"
#include "wyrelog/fact/offline-restore-coordinator-private.h"
#include "wyrelog/fact/offline-restore-begin-private.h"
#include "wyrelog/fact/offline-restore-prepare-private.h"
#include "wyrelog/fact/offline-restore-resume-private.h"
#include "wyrelog/fact/offline-restore-dry-run-private.h"
#include "wyrelog/fact/offline-restore-commit-authority-private.h"
#include "wyrelog/fact/offline-restore-journal-private.h"
#include "wyrelog/fact/offline-restore-journal-store-private.h"
#include "wyrelog/fact/offline-restore-rollback-private.h"
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
static wyrelog_error_t session_build_engine (const WylFactGraphKey *key,
    WylEngine **out_engine, gpointer data);

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
assert_dry_run_graph_namespace_unchanged (BackupFixture *fixture,
    const gchar *graph_id, GHashTable *before)
{
  g_autofree gchar *main_path = graph_file_path (fixture, graph_id,
          "facts.duckdb");
  g_autofree gchar *directory = g_path_get_dirname (main_path);
  g_autoptr (GError) error = NULL;
  g_autoptr (GDir) dir = g_dir_open (directory, 0, &error);
  g_assert_no_error (error);
  g_assert_nonnull (dir);
  guint count = 0;
  for (const gchar *name; (name = g_dir_read_name (dir)) != NULL;) {
    GBytes *expected = g_hash_table_lookup (before, name);
    g_assert_nonnull (expected);
    g_autofree gchar *path = g_build_filename (directory, name, NULL);
    g_autofree gchar *contents = NULL;
    gsize length = 0;
    g_assert_true (g_file_get_contents (path, &contents, &length, &error));
    g_assert_no_error (error);
    g_autoptr (GBytes) current = g_bytes_new (contents, length);
    g_assert_true (g_bytes_equal (expected, current));
    count++;
  }
  g_assert_cmpuint (count, ==, g_hash_table_size (before));
}

static GHashTable *
capture_dry_run_graph_namespace (BackupFixture *fixture,
    const gchar *graph_id)
{
  GHashTable *files = g_hash_table_new_full (g_str_hash, g_str_equal,
          g_free, (GDestroyNotify) g_bytes_unref);
  g_autofree gchar *main_path = graph_file_path (fixture, graph_id,
          "facts.duckdb");
  g_autofree gchar *directory = g_path_get_dirname (main_path);
  g_autoptr (GError) error = NULL;
  g_autoptr (GDir) dir = g_dir_open (directory, 0, &error);
  g_assert_no_error (error);
  g_assert_nonnull (dir);
  for (const gchar *name; (name = g_dir_read_name (dir)) != NULL;) {
    g_autofree gchar *path = g_build_filename (directory, name, NULL);
    g_autofree gchar *contents = NULL;
    gsize length = 0;
    g_assert_true (g_file_get_contents (path, &contents, &length, &error));
    g_assert_no_error (error);
    g_hash_table_insert (files, g_strdup (name),
        g_bytes_new_take (g_steal_pointer (&contents), length));
  }
  return files;
}

static void
test_restore_dry_run_read_only (void)
{
#ifndef __linux__
  return;
#else
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-offline-restore-dry-run-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "alpha");
  create_graph (&fixture, "zeta");
  seal_graph (&fixture, "alpha");
  seal_graph (&fixture, "zeta");
  seal_tenant (&fixture);
  const gchar *graphs[] = { "alpha", "zeta" };
  for (guint i = 0; i < G_N_ELEMENTS (graphs); i++) {
    WylFactGraphKey key = { 0 };
    g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", graphs[i]),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh
          (fixture.runtime, &key, session_build_engine, NULL, NULL), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission
          (fixture.runtime, &key), ==, WYRELOG_E_OK);
    wyl_fact_graph_key_clear (&key);
  }
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  DestinationCapture capture;
  destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  g_autoptr (GError) error = NULL;
  g_autofree gchar *bundle_root = g_dir_make_tmp
        ("wyl-offline-restore-dry-run-bundle-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (bundle_root);
  g_autofree gchar *manifest_path = g_build_filename (bundle_root,
          "manifest", NULL);
  gsize manifest_length = 0;
  const guint8 *manifest_data = g_bytes_get_data (capture.manifest,
          &manifest_length);
  g_assert_true (g_file_set_contents (manifest_path,
      (const gchar *) manifest_data, manifest_length, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (manifest_path, 0600), ==, 0);
  for (guint i = 0; i < capture.completed_graphs->len; i++) {
    const gchar *graph_id = g_ptr_array_index (capture.completed_graphs, i);
    GBytes *bytes = g_ptr_array_index (capture.artifact_bytes, i);
    g_autofree gchar *component = NULL;
    g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
        &component), ==, WYRELOG_E_OK);
    g_autofree gchar *name = g_strdup_printf ("graph-%s.duckdb", component);
    g_autofree gchar *path = g_build_filename (bundle_root, name, NULL);
    gsize length = 0;
    const gchar *data = g_bytes_get_data (bytes, &length);
    g_assert_true (g_file_set_contents (path, data, length, &error));
    g_assert_no_error (error);
    g_assert_cmpint (g_chmod (path, 0600), ==, 0);
  }
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, manifest_data, manifest_length);
  guint8 digest[32];
  gsize digest_length = sizeof digest;
  g_checksum_get_digest (checksum, digest, &digest_length);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (bundle_root,
      digest, &bundle), ==, WYRELOG_E_OK);
  g_autofree gchar *main_path = graph_file_path (&fixture, "alpha",
          "facts.duckdb");
  g_autofree gchar *policy_path = g_build_filename (fixture.root,
          "policy.db", NULL);
  g_autofree gchar *policy_before = NULL;
  gsize policy_length = 0;
  g_assert_true (g_file_get_contents (policy_path, &policy_before,
      &policy_length, &error));
  g_assert_no_error (error);
  g_autofree gchar *main_before = NULL;
  gsize main_length = 0;
  g_assert_true (g_file_get_contents (main_path, &main_before,
      &main_length, &error));
  g_assert_no_error (error);
  g_autoptr (GHashTable) alpha_before =
      capture_dry_run_graph_namespace (&fixture, "alpha");
  g_autoptr (GHashTable) zeta_before =
      capture_dry_run_graph_namespace (&fixture, "zeta");
  WylFactGraphKey sibling = { 0 };
  WylFactGraphRuntimeStatus sibling_before = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&sibling, "tenant-a", "zeta"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (fixture.runtime, &sibling, &sibling_before), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreDryRunReport report = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
      fixture.root, fixture.runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, &report), ==,
      WYRELOG_E_OK);
  g_assert_true (report.observed_eligible_for_staging);
  g_assert_false (report.publication_eligible);
  g_assert_cmpint (report.replay_result, ==,
      WYL_FACT_OFFLINE_RESTORE_REPLAY_NOT_RUN);
  g_assert_cmpuint (report.graphs->len, ==, 2);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
      fixture.root, fixture.runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", &report), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (report.graphs->len, ==, 1);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  WylFactGraphRuntimeManager *empty_runtime = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&empty_runtime), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
      fixture.root, empty_runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", &report), ==,
      WYRELOG_E_OK);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  wyl_fact_graph_runtime_manager_unref (empty_runtime);
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
      fixture.root, NULL, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", &report), ==,
      WYRELOG_E_INVALID);
  g_assert_false (report.observed_eligible_for_staging);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  g_autofree gchar *main_after = NULL;
  gsize after_length = 0;
  g_assert_true (g_file_get_contents (main_path, &main_after,
      &after_length, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (main_before, main_length, main_after, after_length);
  assert_dry_run_graph_namespace_unchanged (&fixture, "alpha",
      alpha_before);
  assert_dry_run_graph_namespace_unchanged (&fixture, "zeta",
      zeta_before);
  g_autofree gchar *policy_after = NULL;
  gsize policy_after_length = 0;
  g_assert_true (g_file_get_contents (policy_path, &policy_after,
      &policy_after_length, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (policy_before, policy_length, policy_after,
      policy_after_length);
  WylFactGraphRuntimeStatus sibling_after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (fixture.runtime, &sibling, &sibling_after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (sibling_before.operation_generation, ==,
      sibling_after.operation_generation);
  g_assert_cmpuint (sibling_before.engine_generation, ==,
      sibling_after.engine_generation);
  g_assert_cmpint (sibling_before.admission, ==, sibling_after.admission);
  wyl_fact_graph_runtime_status_clear (&sibling_before);
  wyl_fact_graph_runtime_status_clear (&sibling_after);
  wyl_fact_graph_key_clear (&sibling);
  wyl_policy_store_t *fresh_policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fresh_policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fresh_policy,
      fixture.root, fixture.runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", &report), ==,
      WYRELOG_E_OK);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  g_autofree gchar *other_root = wyl_test_make_secure_fact_root
        ("wyl-offline-restore-dry-run-other-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_cmpint (wyl_policy_store_bind_fact_root (fresh_policy,
      other_root), ==, WYRELOG_E_OK);
  wyl_policy_store_close (fresh_policy);
  remove_tree (other_root);
  WylFactOfflineBackupManifest changed_manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (capture.manifest,
      &changed_manifest), ==, WYRELOG_E_OK);
  gboolean changed_alpha = FALSE;
  for (guint i = 0; i < changed_manifest.artifacts->len; i++) {
    WylFactOfflineBackupArtifact *artifact =
        g_ptr_array_index (changed_manifest.artifacts, i);
    if (g_strcmp0 (artifact->graph_id, "alpha") == 0) {
      g_free (artifact->schema_digest);
      artifact->schema_digest = g_strdup_printf ("sha256:%064d", 0);
      changed_alpha = TRUE;
    }
  }
  g_assert_true (changed_alpha);
  g_autoptr (GBytes) changed_bytes = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode
        (&changed_manifest, &changed_bytes), ==, WYRELOG_E_OK);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  gsize changed_length = 0;
  const guint8 *changed_data = g_bytes_get_data (changed_bytes,
          &changed_length);
  g_assert_true (g_file_set_contents (manifest_path,
      (const gchar *) changed_data, changed_length, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (manifest_path, 0600), ==, 0);
  g_autoptr (GChecksum) changed_checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (changed_checksum, changed_data, changed_length);
  gsize changed_digest_length = sizeof digest;
  g_checksum_get_digest (changed_checksum, digest, &changed_digest_length);
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (bundle_root,
      digest, &bundle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
      fixture.root, fixture.runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", &report), ==,
      WYRELOG_E_OK);
  g_assert_true (((WylFactOfflineRestoreDryRunGraph *)
      g_ptr_array_index (report.graphs, 0))->schema_transition_required);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  wyl_fact_offline_backup_manifest_clear (&changed_manifest);
  g_autofree gchar *wal = graph_file_path (&fixture, "alpha",
          "facts.duckdb.wal");
  g_assert_true (g_file_set_contents (wal, "foreign", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (wal, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
      fixture.root, fixture.runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", &report), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (report.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_COLLISION);
  g_assert_false (report.observed_eligible_for_staging);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  g_assert_cmpint (g_remove (wal), ==, 0);
  g_autofree gchar *alpha_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode ("alpha",
      &alpha_component), ==, WYRELOG_E_OK);
  g_autofree gchar *alpha_name = g_strdup_printf ("graph-%s.duckdb",
          alpha_component);
  g_autofree gchar *alpha_backup = g_build_filename (bundle_root,
          alpha_name, NULL);
  gint backup_fd = g_open (alpha_backup, O_WRONLY, 0);
  g_assert_cmpint (backup_fd, >=, 0);
  g_assert_cmpint (pwrite (backup_fd, "X", 1, 0), ==, 1);
  g_assert_cmpint (close (backup_fd), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
      fixture.root, fixture.runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", &report), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (report.failure, ==,
      WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_BUNDLE);
  wyl_fact_offline_restore_dry_run_report_clear (&report);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  g_assert_cmpint (g_remove (manifest_path), ==, 0);
  for (guint i = 0; i < capture.completed_graphs->len; i++) {
    const gchar *graph_id = g_ptr_array_index (capture.completed_graphs, i);
    g_autofree gchar *component = NULL;
    g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
        &component), ==, WYRELOG_E_OK);
    g_autofree gchar *name = g_strdup_printf ("graph-%s.duckdb", component);
    g_autofree gchar *path = g_build_filename (bundle_root, name, NULL);
    g_assert_cmpint (g_remove (path), ==, 0);
  }
  g_assert_cmpint (g_rmdir (bundle_root), ==, 0);
  destination_capture_clear (&capture);
  fixture_clear (&fixture);
#endif
}

#ifdef WYL_TEST_HANDLE_SEAMS
typedef struct
{
  const gchar *path;
  gboolean fired;
} BeginProofCollision;

static wyrelog_error_t
begin_proof_collision (gpointer data)
{
  BeginProofCollision *collision = data;
  collision->fired = TRUE;
  if (!g_file_set_contents (collision->path, "foreign", -1, NULL)
      || g_chmod (collision->path, 0600) != 0)
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}
#endif

typedef struct
{
  WylFactOfflineBackupBundle *bundle;
  guint revalidations;
} PreparePartialInput;

static wyrelog_error_t
prepare_partial_read (const gchar *graph_id, guint64 offset,
    guint8 *buffer, gsize capacity, gsize *out_read, gpointer data)
{
  PreparePartialInput *input = data;
  return wyl_fact_offline_backup_bundle_read_at (input->bundle, graph_id,
             offset, buffer, capacity, out_read);
}

static wyrelog_error_t
prepare_partial_revalidate (gpointer data)
{
  PreparePartialInput *input = data;
  input->revalidations++;
  if (input->revalidations == 4)
    return WYRELOG_E_IO;
  return wyl_fact_offline_backup_bundle_revalidate (input->bundle);
}

static void
test_restore_begin_authenticated (void)
{
#ifndef __linux__
  return;
#else
  const WylFactOfflineRestoreScope scopes[] = {
    WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT,
    WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH,
    WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT,
    WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH,
  };
  for (guint pass = 0; pass < G_N_ELEMENTS (scopes); pass++) {
    const gboolean schema_transition = pass >= 2;
    BackupFixture fixture = { 0 };
    fixture_init (&fixture, "wyl-offline-restore-begin-XXXXXX");
    create_tenant (&fixture);
    create_graph (&fixture, "alpha");
    create_graph (&fixture, "zeta");
    if (schema_transition) {
      const gchar *selected_graphs[] = { "alpha", "zeta" };
      const guint count = scopes[pass] == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
          ? 2 : 1;
      for (guint i = 0; i < count; i++) {
        const wyl_policy_fact_relation_schema_column_t columns[] = {
          { "id", "symbol", FALSE, TRUE },
        };
        const wyl_policy_fact_relation_schema_query_t queries[] = {
          { "items_v2", "wr.datalog.query", 1000 },
        };
        const wyl_policy_fact_relation_schema_options_t schema = {
          .tenant_id = "tenant-a", .graph_id = selected_graphs[i],
          .namespace_id = "backup", .relation_name = "items",
          .schema_version = 2, .relation_visible = TRUE,
          .columns = columns, .n_columns = G_N_ELEMENTS (columns),
          .queries = queries, .n_queries = G_N_ELEMENTS (queries),
        };
        g_assert_cmpint (wyl_policy_store_register_fact_relation_schema
              (fixture.policy, &schema), ==, WYRELOG_E_OK);
      }
    }
    seal_graph (&fixture, "alpha");
    seal_graph (&fixture, "zeta");
    seal_tenant (&fixture);
    const gchar *ids[] = { "alpha", "zeta" };
    for (guint i = 0; i < G_N_ELEMENTS (ids); i++) {
      WylFactGraphKey key = { 0 };
      g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", ids[i]),
          ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh
            (fixture.runtime, &key, session_build_engine, NULL, NULL), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission
            (fixture.runtime, &key), ==, WYRELOG_E_OK);
      wyl_fact_graph_key_clear (&key);
    }
    g_autoptr (WylFactOfflineBackupSource) source = NULL;
    g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
        fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
        WYRELOG_E_OK);
    DestinationCapture capture;
    destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
    g_assert_cmpint (wyl_fact_offline_backup_generate (source,
        &capture_destination, &capture), ==, WYRELOG_E_OK);
    g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
    if (schema_transition) {
      const gchar *selected_graphs[] = { "alpha", "zeta" };
      const guint count = scopes[pass] == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
          ? 2 : 1;
      for (guint i = 0; i < count; i++) {
        WylPolicyRelationActivationRecord *active = NULL;
        g_assert_cmpint (wyl_policy_store_read_relation_activation
              (fixture.policy, "tenant-a", selected_graphs[i], "backup",
            "items", &active), ==, WYRELOG_E_OK);
        g_assert_cmpint (active->lifecycle_state, ==,
            WYL_POLICY_RELATION_ACTIVATION_ACTIVE);
        WylPolicyAuthorityMutationResult mutation;
        g_assert_cmpint (wyl_policy_store_transition_relation_activation
              (fixture.policy, "tenant-a", selected_graphs[i], "backup",
            "items", WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
            active->activation_generation,
            WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
            TRUE, 1, TRUE, 2, "none", &mutation), ==, WYRELOG_E_OK);
        g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
        g_assert_cmpint (wyl_policy_store_transition_relation_activation
              (fixture.policy, "tenant-a", selected_graphs[i], "backup",
            "items", WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
            active->activation_generation + 1,
            WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
            TRUE, 2, FALSE, 0, "none", &mutation), ==, WYRELOG_E_OK);
        g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
        wyl_policy_relation_activation_record_free (active);
      }
    }
    g_autoptr (GError) error = NULL;
    g_autofree gchar *bundle_root = g_dir_make_tmp
          ("wyl-offline-restore-begin-bundle-XXXXXX", &error);
    g_assert_no_error (error);
    g_autofree gchar *manifest_path = g_build_filename (bundle_root,
            "manifest", NULL);
    gsize manifest_length = 0;
    const guint8 *manifest_data = g_bytes_get_data (capture.manifest,
            &manifest_length);
    g_assert_true (g_file_set_contents (manifest_path,
        (const gchar *) manifest_data, manifest_length, &error));
    g_assert_no_error (error);
    g_assert_cmpint (g_chmod (manifest_path, 0600), ==, 0);
    for (guint i = 0; i < capture.completed_graphs->len; i++) {
      const gchar *id = g_ptr_array_index (capture.completed_graphs, i);
      GBytes *bytes = g_ptr_array_index (capture.artifact_bytes, i);
      g_autofree gchar *component = NULL;
      g_assert_cmpint (wyl_fact_graph_component_encode (id,
          &component), ==, WYRELOG_E_OK);
      g_autofree gchar *name = g_strdup_printf ("graph-%s.duckdb",
              component);
      g_autofree gchar *path = g_build_filename (bundle_root, name, NULL);
      gsize length = 0;
      const gchar *data = g_bytes_get_data (bytes, &length);
      g_assert_true (g_file_set_contents (path, data, length, &error));
      g_assert_no_error (error);
      g_assert_cmpint (g_chmod (path, 0600), ==, 0);
    }
    g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
    g_checksum_update (checksum, manifest_data, manifest_length);
    guint8 digest[32];
    gsize digest_length = sizeof digest;
    g_checksum_get_digest (checksum, digest, &digest_length);
    g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
    g_assert_cmpint (wyl_fact_offline_backup_bundle_open (bundle_root,
        digest, &bundle), ==, WYRELOG_E_OK);
    if (schema_transition) {
      WylFactOfflineRestoreDryRunReport report = { 0 };
      g_assert_cmpint (wyl_fact_offline_restore_dry_run (fixture.policy,
          fixture.root, fixture.runtime, bundle, scopes[pass],
          scopes[pass] == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
            ? "alpha" : NULL, &report), ==, WYRELOG_E_OK);
      g_assert_cmpuint (report.graphs->len, ==,
          scopes[pass] == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT ? 2 : 1);
      for (guint i = 0; i < report.graphs->len; i++)
        g_assert_true (((WylFactOfflineRestoreDryRunGraph *)
            g_ptr_array_index (report.graphs, i))->schema_transition_required);
      wyl_fact_offline_restore_dry_run_report_clear (&report);
    }
    g_autoptr (GHashTable) alpha_before =
        capture_dry_run_graph_namespace (&fixture, "alpha");
    g_autoptr (GHashTable) zeta_before =
        capture_dry_run_graph_namespace (&fixture, "zeta");
    const gchar *selected = scopes[pass] ==
        WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH ? "alpha" : NULL;
    const gchar *operation = pass == 0 ?
        "018f22d0-7b6d-7a5b-8c31-123456789ad1" :
        "018f22d0-7b6d-7a5b-8c31-123456789ad2";
    WylFactOfflineRestoreJournal committed = { 0 };
    if (schema_transition) {
      /* The selected definition is wrong even though the old active v2
       * version and sealed graph authority are unchanged. */
      sqlite3 *db = wyl_policy_store_get_db (fixture.policy);
      g_assert_cmpint (sqlite3_exec (db,
          "UPDATE fact_relation_schema_columns SET column_type='int64' "
          "WHERE tenant_id='tenant-a' AND graph_id='alpha' "
          "AND namespace_id='backup' AND relation_name='items' "
          "AND schema_version=1 AND column_index=0;",
          NULL, NULL, NULL), ==, SQLITE_OK);
      g_assert_cmpint (sqlite3_changes (db), ==, 1);
      g_assert_cmpint (wyl_fact_offline_restore_begin_run (fixture.policy,
          fixture.root, fixture.runtime, bundle, scopes[pass], selected,
          operation, TRUE, 0, &committed), ==, WYRELOG_E_POLICY);
      g_assert_null (committed.graphs);
      g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
            (fixture.policy, operation, &committed), ==,
          WYRELOG_E_NOT_FOUND);
      g_assert_cmpint (sqlite3_exec (db,
          "UPDATE fact_relation_schema_columns SET column_type='symbol' "
          "WHERE tenant_id='tenant-a' AND graph_id='alpha' "
          "AND namespace_id='backup' AND relation_name='items' "
          "AND schema_version=1 AND column_index=0;",
          NULL, NULL, NULL), ==, SQLITE_OK);
      g_assert_cmpint (sqlite3_changes (db), ==, 1);
    }
    g_assert_cmpint (wyl_fact_offline_restore_begin_run (fixture.policy,
        fixture.root, fixture.runtime, bundle, scopes[pass], selected,
        operation, FALSE, 0, &committed), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (fixture.policy, operation, &committed), ==,
        WYRELOG_E_NOT_FOUND);
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (fixture.policy),
        "UPDATE fact_relation_schema_columns SET visible=1-visible "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (wyl_policy_store_get_db
          (fixture.policy)), >, 0);
    g_assert_cmpint (wyl_fact_offline_restore_begin_run (fixture.policy,
        fixture.root, fixture.runtime, bundle, scopes[pass], selected,
        operation, TRUE, 0, &committed), ==, WYRELOG_E_POLICY);
    g_assert_null (committed.graphs);
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (fixture.policy, operation, &committed), ==,
        WYRELOG_E_NOT_FOUND);
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (fixture.policy),
        "UPDATE fact_relation_schema_columns SET visible=1-visible "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
#ifdef WYL_TEST_HANDLE_SEAMS
    g_autofree gchar *collision = graph_file_path (&fixture, "alpha",
            "facts.duckdb.wal");
    BeginProofCollision collision_data = { collision, FALSE };
    wyl_fact_offline_restore_begin_set_proof_checkpoint_for_test
      (begin_proof_collision, &collision_data);
    g_assert_cmpint (wyl_fact_offline_restore_begin_run (fixture.policy,
        fixture.root, fixture.runtime, bundle, scopes[pass], selected,
        operation, TRUE, 0, &committed), ==, WYRELOG_E_POLICY);
    g_assert_null (committed.operation_uuid);
    wyl_fact_offline_restore_begin_set_proof_checkpoint_for_test (NULL,
        NULL);
    g_assert_true (collision_data.fired);
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (fixture.policy, operation, &committed), ==,
        WYRELOG_E_NOT_FOUND);
    sqlite3_stmt *no_claim = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
          (fixture.policy),
        "SELECT (SELECT count(*) FROM fact_offline_restore_journals "
        "WHERE operation_uuid=?) + "
        "(SELECT count(*) FROM fact_offline_restore_tenant_claims "
        "WHERE operation_uuid=?) + "
        "(SELECT count(*) FROM fact_offline_restore_graph_claims "
        "WHERE operation_uuid=?);", -1, &no_claim, NULL), ==, SQLITE_OK);
    for (gint column = 1; column <= 3; column++)
      g_assert_cmpint (sqlite3_bind_text (no_claim, column, operation, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_step (no_claim), ==, SQLITE_ROW);
    g_assert_cmpint (sqlite3_column_int (no_claim, 0), ==, 0);
    g_assert_cmpint (sqlite3_finalize (no_claim), ==, SQLITE_OK);
    g_assert_cmpint (g_remove (collision), ==, 0);
#endif
    g_clear_pointer (&fixture.runtime,
        wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_begin_run (fixture.policy,
        fixture.root, fixture.runtime, bundle, scopes[pass], selected,
        operation, TRUE, 0, &committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (committed.revision, ==, 1);
    g_assert_cmpint (committed.decision, ==,
        WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
    g_assert_cmpuint (committed.graphs->len, ==, selected == NULL ? 2 : 1);
    wyl_fact_offline_restore_journal_clear (&committed);
    g_clear_pointer (&fixture.runtime,
        wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_begin_run (fixture.policy,
        fixture.root, fixture.runtime, bundle, scopes[pass], selected,
        operation, TRUE, 0, &committed), ==, WYRELOG_E_OK);
    wyl_fact_offline_restore_journal_clear (&committed);
    assert_dry_run_graph_namespace_unchanged (&fixture, "alpha",
        alpha_before);
    assert_dry_run_graph_namespace_unchanged (&fixture, "zeta",
        zeta_before);
    WylFactReplaySchedulerConfig config;
    wyl_fact_replay_scheduler_config_defaults (&config);
    g_autoptr (WylFactReplayScheduler) scheduler = NULL;
    g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL,
        &scheduler), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_prepare_run (fixture.policy,
        fixture.root, fixture.runtime, scheduler, bundle, operation, 2, 0,
        NULL, &committed), ==, WYRELOG_E_BUSY);
    g_assert_null (committed.graphs);
    g_assert_cmpint (wyl_fact_offline_restore_prepare_run (fixture.policy,
        fixture.root, fixture.runtime, scheduler, bundle,
        "018f22d0-7b6d-7a5b-8c31-123456789ad3", 1, 0,
        NULL, &committed), ==, WYRELOG_E_NOT_FOUND);
    g_assert_null (committed.graphs);
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (fixture.policy),
        "UPDATE fact_relation_schema_columns SET visible=1-visible "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (wyl_policy_store_get_db
          (fixture.policy)), >, 0);
    g_assert_cmpint (wyl_fact_offline_restore_prepare_run (fixture.policy,
        fixture.root, fixture.runtime, scheduler, bundle, operation, 1, 0,
        NULL, &committed), ==, WYRELOG_E_POLICY);
    g_assert_null (committed.graphs);
    if (schema_transition) {
      WylPolicyRelationActivationRecord *active = NULL;
      g_assert_cmpint (wyl_policy_store_read_relation_activation
            (fixture.policy, "tenant-a", "alpha", "backup", "items",
          &active), ==, WYRELOG_E_OK);
      g_assert_true (active->has_active_schema_version);
      g_assert_cmpuint (active->active_schema_version, ==, 2);
      wyl_policy_relation_activation_record_free (active);
    }
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (fixture.policy),
        "UPDATE fact_relation_schema_columns SET visible=1-visible "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
    guint64 prepare_revision = 1;
    if (selected == NULL) {
      PreparePartialInput partial = { .bundle = bundle };
      const WylFactOfflineRestoreTenantInput callbacks = {
        prepare_partial_read, prepare_partial_revalidate,
      };
      g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
            (fixture.policy, fixture.root, fixture.runtime, "tenant-a",
          capture.manifest, operation, 1, 0, &callbacks, &partial,
          &committed), ==, WYRELOG_E_IO);
      g_assert_null (committed.graphs);
      g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
            (fixture.policy, operation, &committed), ==, WYRELOG_E_OK);
      g_assert_cmpuint (committed.revision, ==, 2);
      prepare_revision = committed.revision;
      wyl_fact_offline_restore_journal_clear (&committed);
    }
    g_assert_cmpint (wyl_fact_offline_restore_prepare_run (fixture.policy,
        fixture.root, fixture.runtime, scheduler, bundle, operation,
        prepare_revision, 0,
        NULL, &committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (committed.revision, ==,
        1 + 2 * committed.graphs->len);
    for (guint i = 0; i < committed.graphs->len; i++) {
      WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (committed.graphs, i);
      g_assert_true (graph->replay_preflighted);
    }
    g_assert_cmpint (committed.decision, ==,
        WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
    if (selected != NULL)
      assert_dry_run_graph_namespace_unchanged (&fixture, "zeta",
          zeta_before);
    guint64 prepared_revision = committed.revision;
    wyl_fact_offline_restore_journal_clear (&committed);
    g_clear_pointer (&fixture.runtime,
        wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
    g_autoptr (GCancellable) cancelled = g_cancellable_new ();
    g_cancellable_cancel (cancelled);
    g_assert_cmpint (wyl_fact_offline_restore_prepare_run (fixture.policy,
        fixture.root, fixture.runtime, scheduler, bundle, operation,
        prepared_revision, 0, cancelled, &committed), ==,
        WYRELOG_E_CANCELLED);
    g_assert_null (committed.graphs);
    g_assert_cmpint (wyl_fact_offline_restore_prepare_run (fixture.policy,
        fixture.root, fixture.runtime, scheduler, bundle, operation,
        prepared_revision, 0, NULL, &committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (committed.revision, ==, prepared_revision);
    wyl_fact_offline_restore_journal_clear (&committed);
    g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
        WYRELOG_E_OK);
    g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
    remove_tree (bundle_root);
    destination_capture_clear (&capture);
    fixture_clear (&fixture);
  }
#endif
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
    if (mode != NULL && g_str_has_prefix (mode, "schema-transition")) {
      WylPolicyFactBackupSnapshot *snapshot = NULL;
      g_assert_cmpint (wyl_policy_store_read_fact_graph_backup_snapshot
            (fixture->policy, "tenant-a", authority->graph_id,
          &snapshot), ==, WYRELOG_E_OK);
      const WylPolicyFactBackupGraphSnapshot *entry =
          g_ptr_array_index (snapshot->graphs, 0);
      target->old_schema_digest = g_strdup (entry->active_schema_digest);
      wyl_policy_fact_backup_snapshot_free (snapshot);
    }
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
    /* Malformed destination expectations are established before creation;
     * never rewrite an already durable journal to arrange a rejection. */
    if (g_strcmp0 (mode, "wrong-inode") == 0)
      target->expected_main_identity.object++;
    if (g_strcmp0 (mode, "graph-lifecycle") == 0)
      target->lifecycle_generation++;
    if (g_strcmp0 (mode, "graph-reconciliation") == 0)
      target->reconciliation_generation++;
#else
    (void) session_identity;
#endif
    g_ptr_array_add (targets, target);
  }
  WylFactOfflineRestoreJournal journal = { 0 };
  if (g_strcmp0 (mode, "tenant-lifecycle") == 0)
    tenant->lifecycle_generation++;
  if (g_strcmp0 (mode, "tenant-reconciliation") == 0)
    tenant->reconciliation_generation++;
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
  gboolean record_preflight;
  WylFactOfflineRestoreJournal committed;
  guint writes;
  const gchar *selected_graph;
  guint publication_callbacks;
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
    gboolean excluded = retained && (f->selected_graph == NULL
        || g_str_equal (f->selected_graph, i == 0 ? "alpha" : "zeta"));
    guint calls = 0;
    g_assert_cmpint (wyl_fact_graph_snapshot_use (f->snapshots[i],
        session_snapshot_callback, &calls), ==,
        excluded ? WYRELOG_E_BUSY : WYRELOG_E_OK);
    g_assert_cmpuint (calls, ==, excluded ? 0 : 1);
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
  guint64 revision = journal.revision;
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
        (&journal, graph, &identity), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (f->fixture.policy, revision, &journal, &result, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_assert_cmpuint (committed.revision, ==, revision + 1);
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
session_fixture_init_selected (SessionFixture *f, const gchar *mode,
    const gchar *selected_graph)
{
  f->mode = mode;
  f->selected_graph = selected_graph;
  fixture_init (&f->fixture, "wyl-restore-session-XXXXXX");
  create_tenant (&f->fixture);
  const gchar *graphs[] = { "alpha", "zeta" };
  for (guint i = 0; i < 2; i++) {
    create_graph (&f->fixture, graphs[i]);
    if (g_str_has_prefix (mode, "schema-transition")) {
      const wyl_policy_fact_relation_schema_column_t selected_columns[] = {
        { "id", "symbol", FALSE, TRUE },
      };
      const wyl_policy_fact_relation_schema_query_t selected_queries[] = {
        { "items_v2", "wr.datalog.query", 1000 },
      };
      const wyl_policy_fact_relation_schema_options_t selected_schema = {
        .tenant_id = "tenant-a", .graph_id = graphs[i],
        .namespace_id = "backup", .relation_name = "items",
        .schema_version = 2, .relation_visible = TRUE,
        .columns = selected_columns,
        .n_columns = G_N_ELEMENTS (selected_columns),
        .queries = selected_queries,
        .n_queries = G_N_ELEMENTS (selected_queries),
      };
      g_assert_cmpint (wyl_policy_store_register_fact_relation_schema
            (f->fixture.policy, &selected_schema), ==, WYRELOG_E_OK);
    }
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
  if (g_str_has_prefix (mode, "schema-transition")) {
    const guint count = selected_graph == NULL ? 2 : 1;
    for (guint i = 0; i < count; i++) {
      const gchar *id = selected_graph == NULL ? graphs[i] : selected_graph;
      WylPolicyRelationActivationRecord *active = NULL;
      g_assert_cmpint (wyl_policy_store_read_relation_activation
            (f->fixture.policy, "tenant-a", id, "backup", "items",
          &active), ==, WYRELOG_E_OK);
      WylPolicyAuthorityMutationResult mutation;
      g_assert_cmpint (wyl_policy_store_transition_relation_activation
            (f->fixture.policy, "tenant-a", id, "backup", "items",
          WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
          active->activation_generation,
          WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
          TRUE, 1, TRUE, 2, "none", &mutation), ==, WYRELOG_E_OK);
      g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
      g_assert_cmpint (wyl_policy_store_transition_relation_activation
            (f->fixture.policy, "tenant-a", id, "backup", "items",
          WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
          active->activation_generation + 1,
          WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
          TRUE, 2, FALSE, 0, "none", &mutation), ==, WYRELOG_E_OK);
      g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
      wyl_policy_relation_activation_record_free (active);
    }
  }
  if (g_str_equal (mode, "coordinator/import-historical")) {
    /* Capture A first, then append real data B in place, preserving the
     * provisioned inode, store identity and relation schema. */
    g_autoptr (wyl_fact_store_t) store = NULL;
    g_assert_cmpint (wyl_fact_store_open_provisioned_graph (f->fixture.policy,
        f->fixture.root, "tenant-a", selected_graph, TRUE, &store), ==, WYRELOG_E_OK);
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      { "id", "symbol", FALSE, TRUE },
    };
    const wyl_policy_fact_relation_schema_options_t schema = {
      .tenant_id = "tenant-a", .graph_id = selected_graph,
      .namespace_id = "backup", .relation_name = "items",
      .schema_version = 1, .relation_visible = TRUE,
      .columns = columns, .n_columns = G_N_ELEMENTS (columns),
    };
    const wyl_fact_value_t values[] = {
      { .type = WYL_FACT_VALUE_SYMBOL, .as.text = "current-main-B" },
    };
    const wyl_fact_row_t rows[] = { { values, G_N_ELEMENTS (values) } };
    const wyl_fact_store_batch_t batch = {
      .batch_id = "import-current-B", .tenant_id = "tenant-a",
      .graph_id = selected_graph, .namespace_id = "backup",
      .relation_name = "items", .schema_version = 1, .source = "test",
      .idempotency_key = "import-B", .op = WYL_FACT_STORE_OP_ASSERT,
      .rows = rows, .n_rows = G_N_ELEMENTS (rows),
    };
    gboolean created = FALSE;
    g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
        &created), ==, WYRELOG_E_OK);
    g_assert_true (created);
    g_clear_pointer (&store, wyl_fact_store_close);
    const WylPolicyTenantLifecycleState states[] = {
      WYL_POLICY_TENANT_LIFECYCLE_SEALED, WYL_POLICY_TENANT_LIFECYCLE_UNSEALING,
      WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, WYL_POLICY_TENANT_LIFECYCLE_SEALING,
      WYL_POLICY_TENANT_LIFECYCLE_SEALED,
    };
    for (guint i = 1; i < G_N_ELEMENTS (states); i++) {
      WylPolicyAuthorityMutationResult mutation;
      g_assert_cmpint (wyl_policy_store_transition_tenant_authority
            (f->fixture.policy, "tenant-a", states[i - 1], states[i],
          2 + i, 1, &mutation), ==, WYRELOG_E_OK);
      g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    }
  }
  if (g_str_equal (mode, "coordinator/checksum")) {
    WylFactOfflineBackupManifest manifest = { 0 };
    g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (f->capture.manifest,
        &manifest), ==, WYRELOG_E_OK);
    for (guint i = 0; i < manifest.artifacts->len; i++) {
      WylFactOfflineBackupArtifact *artifact = g_ptr_array_index (manifest.artifacts, i);
      if (g_strcmp0 (artifact->graph_id, selected_graph) == 0) {
        g_free (artifact->checksum);
        artifact->checksum = g_strdup ("sha256:0000000000000000000000000000000000000000000000000000000000000000");
      }
    }
    g_clear_pointer (&f->capture.manifest, g_bytes_unref);
    g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&manifest,
        &f->capture.manifest), ==, WYRELOG_E_OK);
    wyl_fact_offline_backup_manifest_clear (&manifest);
  }
  gboolean graph_scope = !g_str_equal (mode, "coordinator/tenant")
      && (selected_graph != NULL || g_str_equal (mode, "graph-scope"));
  const gchar *journal_mode = g_str_has_prefix (mode, "coordinator/")
      ? mode + strlen ("coordinator/") : mode;
  create_restore_journal_for_manifest_internal (&f->fixture,
      f->capture.manifest, graph_scope ? WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      : WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT,
      graph_scope ? selected_graph != NULL ? selected_graph : "alpha" : NULL, session_operation,
      !(g_str_equal (mode, "main-absence-violated")
      || g_str_equal (mode, "stage-only")
      || g_str_equal (mode, "coordinator/expected-main-absent")
      || g_str_equal (mode, "orphan-provision")), journal_mode);
  if (selected_graph != NULL && !g_str_has_prefix (mode, "coordinator"))
    session_stage_one_graph (f, g_str_equal (selected_graph, "alpha") ? 0 : 1);
  else if (g_str_equal (mode, "partial-staging"))
    session_stage_one_graph (f, 0);
  else if (g_str_equal (mode, "untrusted") || g_str_equal (mode, "unconfirmed")) {
    session_stage_one_graph (f, 0);
    session_stage_one_graph (f, 1);
  }else if (!graph_scope && !g_str_equal (mode, "unstaged")
      && !g_str_has_prefix (mode, "coordinator")) {
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
session_fixture_init (SessionFixture *f, const gchar *mode)
{
  session_fixture_init_selected (f, mode, NULL);
}

static void
session_fixture_clear (SessionFixture *f)
{
  if (f->journal_before != NULL) {
    g_autoptr (GBytes) after = session_journal_bytes (f);
    g_assert_true (g_bytes_equal (f->journal_before, after));
  }
  g_clear_pointer (&f->session,
      wyl_fact_offline_restore_validation_session_free);
  session_assert_authority (f, FALSE);
  for (guint i = 0; i < 2; i++)
    g_clear_pointer (&f->snapshots[i], wyl_fact_graph_snapshot_unref);
  g_clear_object (&f->cancel);
  g_clear_pointer (&f->journal_before, g_bytes_unref);
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
  if (f->record_preflight)
    return wyl_fact_offline_restore_validation_session_run_and_record_preflight
             (f->session, context, &f->committed);
  return wyl_fact_offline_restore_validation_session_run (f->session,
             context, &f->result);
}

static wyrelog_error_t
publication_authority_callback (const WylFactOfflineRestoreJournal *journal,
    WylFactRootWriterLease *lease, WylFactGraphResolver *resolver,
    const GPtrArray *graphs, gpointer data)
{
  SessionFixture *f = data;
  f->publication_callbacks++;
  session_assert_authority (f, TRUE);
  g_assert_nonnull (lease);
  g_assert_nonnull (resolver);
  g_assert_cmpuint (graphs->len, ==, 1);
  g_assert_cmpuint (journal->revision, ==, 3);
  g_assert_cmpint (journal->decision, ==, WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  const WylFactOfflineRestorePublicationGraph *graph = g_ptr_array_index (graphs, 0);
  g_assert_cmpstr (graph->graph_id, ==, f->selected_graph);
  g_assert_nonnull (graph->directory);
  g_assert_nonnull (graph->pair);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
publication_authority_job (WylFactReplayJobContext *context, gpointer data)
{
  SessionFixture *f = data;
  return wyl_fact_offline_restore_validation_session_with_publication_authority
           (f->session, context, publication_authority_callback, f);
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

static wyrelog_error_t
publication_authority_run_worker (SessionFixture *f)
{
  WylFactReplaySchedulerConfig config;
  wyl_fact_replay_scheduler_config_defaults (&config);
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_autoptr (WylFactReplayFuture) future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, "tenant-a",
      f->selected_graph, f->cancel, publication_authority_job, f, NULL,
      &future), ==, WYRELOG_E_OK);
  wyrelog_error_t rc = wyl_fact_replay_future_wait (future);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  return rc;
}

static void
test_restore_publication_authority (gconstpointer data)
{
  SessionFixture f = { 0 };
  f.selected_graph = "alpha";
  session_fixture_init_selected (&f,
      g_str_equal (data, "schema-transition")
      ? "schema-transition-graph" : "success", f.selected_graph);
  f.record_preflight = TRUE;
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      f.capture.manifest, session_operation, 2, 0, &f.session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 3);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  if (g_str_equal (data, "corrupt"))
    session_corrupt_stage (&f, "alpha");
  if (g_str_equal (data, "policy"))
    mutate_tenant_after_snapshot (&f.capture);
  wyrelog_error_t rc = publication_authority_run_worker (&f);
  if (!g_str_equal (data, "success")
      && !g_str_equal (data, "schema-transition")) {
    g_assert_cmpint (rc, !=, WYRELOG_E_OK);
    g_assert_cmpuint (f.publication_callbacks, ==, 0);
    session_assert_authority (&f, FALSE);
  } else {
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.publication_callbacks, ==, 1);
    session_assert_authority (&f, TRUE);
  }
  wyl_fact_offline_restore_journal_clear (&f.committed);
  session_fixture_clear (&f);
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
session_mark_preflight (SessionFixture *f, const gchar *graph_id)
{
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  WylFactOfflineRestoreStoreResult result;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f->fixture.policy, session_operation, &journal), ==, WYRELOG_E_OK);
  guint64 revision = journal.revision;
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_preflight
        (&journal, graph_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (f->fixture.policy, revision, &journal, &result, &committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
}

static wyrelog_error_t
session_record_checkpoint (const gchar *graph, guint64 revision,
    gboolean after_write, gpointer data)
{
  SessionFixture *f = data;
  (void) graph;
  session_assert_authority (f, TRUE);
  if (after_write)
    f->writes++;
  if ((!after_write && revision == 3 && g_str_equal (f->mode, "fail-before"))
      || (after_write && revision == 4 && g_str_equal (f->mode, "fail-between"))
      || (after_write && revision == 5 && g_str_equal (f->mode, "fail-after")))
    return WYRELOG_E_IO;
  if ((!after_write && revision == 3 && g_str_equal (f->mode, "cancel-before"))
      || (after_write && revision == 4 && g_str_equal (f->mode, "cancel-between"))
      || (after_write && revision == 5 && g_str_equal (f->mode, "cancel-after")))
    g_cancellable_cancel (f->cancel);
  if (!after_write && revision == 3 && g_str_equal (f->mode, "stale-write"))
    session_mark_preflight (f, "zeta");
  if (!after_write && revision == 3 && g_str_equal (f->mode, "boundary-policy"))
    mutate_tenant_after_snapshot (&f->capture);
  if (!after_write && revision == 3 && g_str_equal (f->mode, "boundary-schema"))
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f->fixture.policy),
        "UPDATE fact_relation_schema_columns SET visible=0 "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
  if (!after_write && revision == 3 && g_str_equal (f->mode, "boundary-provision"))
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f->fixture.policy),
        "DELETE FROM fact_graph_provisioning "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
        NULL, NULL, NULL), ==, SQLITE_OK);
  if (!after_write && revision == 4 && g_str_equal (f->mode, "boundary-content"))
    session_corrupt_stage (f, "alpha");
  if (!after_write && revision == 3 && g_str_equal (f->mode, "boundary-entry")) {
    g_autofree gchar *path = graph_file_path (&f->fixture, "alpha", "foreign");
    g_assert_true (g_file_set_contents (path, "foreign", -1, NULL));
    g_assert_cmpint (g_chmod (path, 0600), ==, 0);
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  if (!after_write && revision == 3 && g_str_equal (f->mode, "commit-response"))
    wyl_policy_store_offline_restore_fail_once (f->fixture.policy,
        WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
#endif
  return WYRELOG_E_OK;
}

static void
test_restore_record_preflight (gconstpointer data)
{
  const gchar *mode = data;
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  f.mode = mode;
  f.record_preflight = TRUE;
  guint64 revision = 3;
  if (g_str_equal (mode, "partial") || g_str_equal (mode, "full")
      || g_str_equal (mode, "verified-corrupt")) {
    session_mark_preflight (&f, "alpha");
    revision++;
  }
  if (g_str_equal (mode, "nonprefix") || g_str_equal (mode, "full")) {
    session_mark_preflight (&f, "zeta");
    revision++;
  }
  if (g_str_equal (mode, "verified-corrupt"))
    session_corrupt_stage (&f, "alpha");
  g_autoptr (GHashTable) files_before = session_graph_files (&f);
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
      session_operation, revision, 0, &f.session), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_validation_session_set_checkpoint_for_test
    (f.session, session_checkpoint, &f);
  wyl_fact_offline_restore_validation_session_set_record_checkpoint_for_test
    (f.session, session_record_checkpoint, &f);
  if (g_str_equal (mode, "nonprefix")) {
    /* Reading a recording session remains observational, even with progress. */
    g_autoptr (GBytes) before = session_journal_bytes (&f);
    f.record_preflight = FALSE;
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.result.validated_revision, ==, revision);
    g_autoptr (GBytes) after = session_journal_bytes (&f);
    g_assert_true (g_bytes_equal (before, after));
    f.record_preflight = TRUE;
    f.checkpoints = 0;
  }
  wyrelog_error_t rc = session_run_worker (&f);
  gboolean success = g_str_equal (mode, "success") || g_str_equal (mode, "partial")
      || g_str_equal (mode, "nonprefix") || g_str_equal (mode, "full");
  if (success) {
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, ==, 5);
    g_assert_cmpuint (f.writes, ==, 5 - revision);
    g_assert_cmpuint (f.checkpoints, ==, 2);
    session_assert_authority (&f, TRUE);
    g_autoptr (GBytes) returned = NULL;
    g_autoptr (GBytes) durable = session_journal_bytes (&f);
    g_assert_cmpint (wyl_fact_offline_restore_journal_encode
          (&f.committed, &returned), ==, WYRELOG_E_OK);
    g_assert_true (g_bytes_equal (returned, durable));
    wyl_fact_offline_restore_journal_clear (&f.committed);
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.checkpoints, ==, 4);
    g_assert_cmpuint (f.writes, ==, 5 - revision);
    session_assert_files_unchanged (&f, files_before);
  } else {
    g_assert_cmpint (rc, !=, WYRELOG_E_OK);
    g_assert_null (f.committed.graphs);
    g_assert_cmpuint (f.committed.revision, ==, 0);
    session_assert_authority (&f, FALSE);
    g_cancellable_reset (f.cancel);
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_INVALID);
  }
  g_clear_pointer (&f.session, wyl_fact_offline_restore_validation_session_free);
  if (g_str_equal (mode, "commit-response")) {
    g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
    g_autofree gchar *path = g_build_filename (f.fixture.root, "policy.db", NULL);
    g_assert_cmpint (wyl_policy_store_open (path, &f.fixture.policy), ==, WYRELOG_E_OK);
  }
  g_auto (WylFactOfflineRestoreJournal) durable = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &durable), ==, WYRELOG_E_OK);
  guint64 expected_revision = success ? 5 : revision;
  if (g_str_equal (mode, "fail-between") || g_str_equal (mode, "cancel-between")
      || g_str_equal (mode, "stale-write") || g_str_equal (mode, "boundary-content"))
    expected_revision = 4;
  if (g_str_equal (mode, "fail-after") || g_str_equal (mode, "cancel-after"))
    expected_revision = 5;
  if (g_str_equal (mode, "commit-response")) {
    g_assert_cmpuint (durable.revision, >=, 3);
    g_assert_cmpuint (durable.revision, <=, 4);
  } else
    g_assert_cmpuint (durable.revision, ==, expected_revision);
  g_assert_cmpint (durable.decision, ==, WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  g_assert_false (durable.policy_generation_published);
  g_assert_false (durable.lifecycle_handoff_complete);
  guint verified = 0;
  for (guint i = 0; i < durable.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (durable.graphs, i);
    g_assert_cmpint (graph->copied, ==, graph->checksum_verified);
    g_assert_cmpint (graph->copied, ==, graph->identity_verified);
    g_assert_cmpint (graph->copied, ==, graph->schema_verified);
    g_assert_cmpint (graph->copied, ==, graph->replay_preflighted);
    verified += graph->copied ? 1 : 0;
  }
  g_assert_cmpuint (verified, ==, durable.revision - 3);
  gboolean retry = g_str_has_prefix (mode, "fail-")
      || g_str_has_prefix (mode, "cancel-") || g_str_equal (mode, "commit-response");
  if (retry) {
    f.mode = "success";
    f.checkpoints = 0;
    g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
        session_operation, durable.revision, 0, &f.session), ==, WYRELOG_E_OK);
    wyl_fact_offline_restore_validation_session_set_checkpoint_for_test
      (f.session, session_checkpoint, &f);
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.checkpoints, ==, 2);
    g_assert_cmpuint (f.committed.revision, ==, 5);
    session_assert_files_unchanged (&f, files_before);
  }
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void
test_restore_observational_session_cannot_record (void)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  f.record_preflight = TRUE;
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
      session_operation, 3, 0, &f.session), ==, WYRELOG_E_OK);
  g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_INVALID);
  g_assert_null (f.committed.graphs);
  session_fixture_clear (&f);
}

static void
graph_corrupt_provision (SessionFixture *f, const gchar *graph)
{
  g_autofree gchar *sql = g_strdup_printf (
    "PRAGMA ignore_check_constraints=ON;"
    "UPDATE fact_graph_provisioning SET updated_at='malformed' "
    "WHERE tenant_id='tenant-a' AND graph_id='%s';"
    "PRAGMA ignore_check_constraints=OFF;", graph);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f->fixture.policy),
      sql, NULL, NULL, NULL), ==, SQLITE_OK);
}

static void
graph_corrupt_schema (SessionFixture *f, const gchar *graph)
{
  g_autofree gchar *sql = g_strdup_printf (
    "UPDATE fact_relation_activation SET last_error_class='schema' "
    "WHERE tenant_id='tenant-a' AND graph_id='%s';", graph);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f->fixture.policy),
      sql, NULL, NULL, NULL), ==, SQLITE_OK);
}

static void
test_graph_coordinator_rejects_before_drain (gconstpointer data)
{
  const gchar *mode = data;
  g_autofree gchar *fixture_mode = g_strconcat ("coordinator/", mode, NULL);
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, fixture_mode, "zeta");
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "zeta"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission
        (f.fixture.runtime, &key), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus before = { 0 }, after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (f.fixture.runtime,
      &key, &before), ==, WYRELOG_E_OK);
  g_assert_cmpint (before.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  g_autoptr (GHashTable) files = session_graph_files (&f);
  g_assert_cmpint (wyl_fact_offline_restore_graph_stage_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a", "zeta",
      f.capture.manifest, session_operation, 1, 0, &f.committed), ==, WYRELOG_E_POLICY);
  g_assert_null (f.committed.graphs);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (f.fixture.runtime,
      &key, &after), ==, WYRELOG_E_OK);
  g_assert_cmpint (before.admission, ==, after.admission);
  g_assert_cmpuint (before.operation_generation, ==, after.operation_generation);
  g_assert_cmpuint (before.engine_generation, ==, after.engine_generation);
  g_autoptr (GBytes) journal_after = session_journal_bytes (&f);
  g_assert_true (g_bytes_equal (journal_after, f.journal_before));
  session_assert_files_unchanged (&f, files);
  wyl_fact_graph_runtime_status_clear (&before);
  wyl_fact_graph_runtime_status_clear (&after);
  wyl_fact_graph_key_clear (&key);
  session_fixture_clear (&f);
}

static wyrelog_error_t
graph_source_drift_sink (guint64 offset, const guint8 *bytes, gsize length,
    gpointer data)
{
  SessionFixture *f = data;
  g_assert_nonnull (bytes);
  g_assert_cmpuint (length, >, 0);
  if (offset == 0) {
    if (g_str_equal (f->mode, "sibling-provision"))
      graph_corrupt_provision (f, "alpha");
    else if (g_str_equal (f->mode, "selected-provision"))
      graph_corrupt_provision (f, "zeta");
    else if (g_str_equal (f->mode, "selected-schema"))
      graph_corrupt_schema (f, "zeta");
    else if (g_str_equal (f->mode, "sibling-schema"))
      graph_corrupt_schema (f, "alpha");
    else if (g_str_equal (f->mode, "tenant-change"))
      mutate_tenant_after_snapshot (&f->capture);
  }
  return WYRELOG_E_OK;
}

static void
test_graph_source_late_drift (gconstpointer data)
{
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "coordinator", "zeta");
  f.mode = data;
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (f.fixture.root, &lease), ==, WYRELOG_E_OK);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new_for_graph_with_lease
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a", "zeta",
      0, lease, &source), ==, WYRELOG_E_OK);
  g_assert_cmpuint (wyl_fact_offline_backup_source_count (source), ==, 1);
  WylFactOfflineBackupSourceArtifact artifact = { 0 };
  g_assert_true (wyl_fact_offline_backup_source_get (source, 0, &artifact));
  g_assert_cmpstr (artifact.graph_id, ==, "zeta");
  guint64 copied = 999;
  wyrelog_error_t rc = wyl_fact_offline_backup_source_copy_to_sink
        (source, 0, graph_source_drift_sink, &f, &copied);
  gboolean success = g_str_has_prefix (f.mode, "sibling-");
  g_assert_cmpint (rc == WYRELOG_E_OK, ==, success);
  g_assert_cmpuint (copied, ==, success ? artifact.logical_bytes : 0);
  g_assert_cmpint (wyl_fact_offline_backup_source_revalidate (source)
      == WYRELOG_E_OK, ==, success);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  session_assert_authority (&f, FALSE);
  session_fixture_clear (&f);
}

static void
test_graph_staging_coordinator (gconstpointer data)
{
  const gchar *mode = data;
  const gchar *selected = g_str_equal (mode, "alpha") ? "alpha" : "zeta";
  const gchar *sibling = g_str_equal (selected, "alpha") ? "zeta" : "alpha";
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, g_str_equal (mode, "checksum")
      ? "coordinator/checksum" : "coordinator", selected);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", sibling), ==, WYRELOG_E_OK);
  /* Fixture backup closed admission. Reopen the sibling before the operation
   * under test, so accidentally draining it cannot pass unnoticed. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission
        (f.fixture.runtime, &key), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus before = { 0 }, after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (f.fixture.runtime,
      &key, &before), ==, WYRELOG_E_OK);
  g_assert_cmpint (before.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  if (g_str_equal (mode, "sibling-schema"))
    graph_corrupt_schema (&f, sibling);
  if (g_str_equal (mode, "sibling-provision"))
    graph_corrupt_provision (&f, sibling);
  if (g_str_equal (mode, "selected-provision"))
    graph_corrupt_provision (&f, selected);
  if (g_str_equal (mode, "selected-schema"))
    graph_corrupt_schema (&f, selected);
  if (g_str_equal (mode, "sibling-artifact")) {
    g_autofree gchar *path = graph_file_path (&f.fixture, sibling, "foreign");
    g_assert_true (g_file_set_contents (path, "keep", -1, NULL));
  }
  g_autoptr (GHashTable) files = session_graph_files (&f);
#ifdef WYL_TEST_HANDLE_SEAMS
  if (g_str_equal (mode, "commit-response"))
    wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
        WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
#endif
  wyrelog_error_t rc = wyl_fact_offline_restore_graph_stage_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          g_str_equal (mode, "wrong-tenant") ? "other" : "tenant-a",
          g_str_equal (mode, "wrong-graph") ? sibling : selected,
          f.capture.manifest, session_operation,
          g_str_equal (mode, "stale") ? 2 : 1, 0, &f.committed);
  gboolean failure = g_str_has_prefix (mode, "wrong-")
      || g_str_has_prefix (mode, "selected-") || g_str_equal (mode, "stale")
      || g_str_equal (mode, "commit-response") || g_str_equal (mode, "checksum");
  g_assert_cmpint (rc == WYRELOG_E_OK, ==, !failure);
  if (failure)
    g_assert_null (f.committed.graphs);
  if (g_str_equal (mode, "commit-response")) {
    g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
    g_autofree gchar *path = g_build_filename (f.fixture.root, "policy.db", NULL);
    g_assert_cmpint (wyl_policy_store_open (path, &f.fixture.policy), ==, WYRELOG_E_OK);
  }
  g_auto (WylFactOfflineRestoreJournal) durable = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load (f.fixture.policy,
      session_operation, &durable), ==, WYRELOG_E_OK);
  g_assert_cmpuint (durable.graphs->len, ==, 1);
  WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (durable.graphs, 0);
  g_assert_cmpstr (graph->graph_id, ==, selected);
  gboolean bound = !failure || g_str_equal (mode, "commit-response");
  g_assert_cmpuint (durable.revision, ==, bound ? 2 : 1);
  g_assert_cmpint (artifact_identity_is_zero (&graph->staged_main_identity), ==, !bound);
  g_assert_false (graph->copied);
  g_assert_false (graph->checksum_verified);
  g_assert_false (graph->identity_verified);
  g_assert_false (graph->schema_verified);
  g_assert_false (graph->replay_preflighted);
  g_assert_cmpint (durable.decision, ==, WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  /* Every preexisting graph file, including the sibling's foreign file,
   * remains byte-identical. Only the selected stage may be added. */
  g_autoptr (GHashTable) current = session_graph_files (&f);
  g_assert_cmpuint (g_hash_table_size (current), ==,
      g_hash_table_size (files) + (bound || g_str_equal (mode, "checksum") ? 1 : 0));
  GHashTableIter iter;
  gpointer path, bytes;
  g_hash_table_iter_init (&iter, files);
  while (g_hash_table_iter_next (&iter, &path, &bytes)) {
    GBytes *actual = g_hash_table_lookup (current, path);
    g_assert_nonnull (actual);
    g_assert_true (g_bytes_equal (bytes, actual));
  }
  if (bound) {
    g_autoptr (GBytes) journal_before = session_journal_bytes (&f);
    g_auto (WylFactOfflineRestoreJournal) retry = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_graph_stage_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
        selected, f.capture.manifest, session_operation, 2, 0, &retry), ==, WYRELOG_E_POLICY);
    g_assert_null (retry.graphs);
    g_autoptr (GBytes) journal_after = session_journal_bytes (&f);
    g_assert_true (g_bytes_equal (journal_before, journal_after));
    session_assert_files_unchanged (&f, current);
  }
  if (g_str_equal (mode, "checksum")) {
    /* A failed checksum leaves a recovery-owned orphan, not permission to
     * overwrite it on retry, even though the journal is still revision 1. */
    g_auto (WylFactOfflineRestoreJournal) retry = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_graph_stage_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a", selected,
        f.capture.manifest, session_operation, 1, 0, &retry), !=, WYRELOG_E_OK);
    g_assert_null (retry.graphs);
    g_autoptr (GBytes) unchanged = session_journal_bytes (&f);
    g_assert_true (g_bytes_equal (unchanged, f.journal_before));
    session_assert_files_unchanged (&f, current);
  }
  if (!failure) {
    f.mode = "success";
    f.record_preflight = TRUE;
    g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
        session_operation, 2, 0, &f.session), ==, WYRELOG_E_OK);
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, ==, 3);
    graph = g_ptr_array_index (f.committed.graphs, 0);
    g_assert_true (graph->replay_preflighted);
    g_clear_pointer (&f.session, wyl_fact_offline_restore_validation_session_free);
    g_auto (WylFactOfflineRestoreJournal) retry = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_graph_stage_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a", selected,
        f.capture.manifest, session_operation, 3, 0, &retry), ==, WYRELOG_E_POLICY);
    session_assert_files_unchanged (&f, current);
  }
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (f.fixture.runtime,
      &key, &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (before.operation_generation, ==, after.operation_generation);
  g_assert_cmpuint (before.engine_generation, ==, after.engine_generation);
  g_assert_cmpint (before.admission, ==, after.admission);
  g_assert_cmpint (before.state, ==, after.state);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot
        (f.fixture.runtime, &key, &snapshot), ==, WYRELOG_E_OK);
  guint calls = 0;
  g_assert_cmpint (wyl_fact_graph_snapshot_use (snapshot, session_snapshot_callback, &calls), ==, WYRELOG_E_OK);
  g_assert_cmpuint (calls, ==, 1);
  wyl_fact_graph_snapshot_unref (snapshot);
  wyl_fact_graph_runtime_status_clear (&before);
  wyl_fact_graph_runtime_status_clear (&after);
  wyl_fact_graph_key_clear (&key);
  session_assert_authority (&f, FALSE);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static wyrelog_error_t
graph_session_checkpoint (const gchar *graph, gpointer data)
{
  SessionFixture *f = data;
  g_assert_cmpstr (graph, ==, f->selected_graph);
  f->checkpoints++;
  session_assert_authority (f, TRUE);
  if (g_str_equal (f->mode, "cancel"))
    g_cancellable_cancel (f->cancel);
  if (g_str_equal (f->mode, "tenant-change"))
    mutate_tenant_after_snapshot (&f->capture);
  if (g_str_equal (f->mode, "late-corrupt"))
    session_corrupt_stage (f, graph);
  if (g_str_equal (f->mode, "selected-provision-late"))
    graph_corrupt_provision (f, graph);
  if (g_str_equal (f->mode, "sibling-provision-late"))
    graph_corrupt_provision (f, g_str_equal (graph, "alpha") ? "zeta" : "alpha");
  if (g_str_equal (f->mode, "selected-schema-late"))
    graph_corrupt_schema (f, graph);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
graph_record_checkpoint (const gchar *graph, guint64 revision,
    gboolean after_write, gpointer data)
{
  SessionFixture *f = data;
  g_assert_cmpstr (graph, ==, f->selected_graph);
  session_assert_authority (f, TRUE);
  g_assert_cmpuint (revision, ==, after_write ? 3 : 2);
  if (after_write)
    f->writes++;
  return after_write && g_str_equal (f->mode, "after-write-failure")
         ? WYRELOG_E_IO : WYRELOG_E_OK;
}

static void
test_graph_scoped_session (gconstpointer data)
{
  const gchar *name = data;
  const gchar *selected = g_str_has_prefix (name, "alpha/") ? "alpha" : "zeta";
  const gchar *mode = strchr (name, '/') + 1;
  const gchar *sibling = g_str_equal (selected, "alpha") ? "zeta" : "alpha";
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f,
      g_str_equal (mode, "missing-sibling-runtime")
      || g_str_equal (mode, "missing-selected-runtime") ? "missing-runtime" : "success", selected);
  f.mode = mode;
  f.record_preflight = !g_str_equal (mode, "observe");
  if (g_str_equal (mode, "sibling-schema"))
    graph_corrupt_schema (&f, sibling);
  if (g_str_equal (mode, "sibling-provision"))
    graph_corrupt_provision (&f, sibling);
  if (g_str_equal (mode, "selected-provision"))
    graph_corrupt_provision (&f, selected);
  if (g_str_equal (mode, "sibling-artifact")) {
    g_autofree gchar *path = graph_file_path (&f.fixture, sibling, "foreign");
    g_assert_true (g_file_set_contents (path, "foreign", -1, NULL));
  }
  WylFactGraphKey sibling_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&sibling_key, "tenant-a", sibling), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus before = { 0 }, after = { 0 };
  gboolean has_sibling = !g_str_equal (mode, "missing-sibling-runtime");
  if (has_sibling)
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
          (f.fixture.runtime, &sibling_key, &before), ==, WYRELOG_E_OK);
  g_autoptr (GHashTable) files = session_graph_files (&f);
  wyrelog_error_t rc = f.record_preflight
      ? wyl_fact_offline_restore_validation_session_new_for_preflight
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
          session_operation, 2, 0, &f.session)
      : wyl_fact_offline_restore_validation_session_new
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
          session_operation, 2, 0, &f.session);
  gboolean constructor_failure = g_str_equal (mode, "selected-provision");
  if (constructor_failure) {
    g_assert_cmpint (rc, !=, WYRELOG_E_OK);
    g_assert_null (f.session);
  } else {
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    session_assert_authority (&f, TRUE);
    wyl_fact_offline_restore_validation_session_set_checkpoint_for_test
      (f.session, graph_session_checkpoint, &f);
    wyl_fact_offline_restore_validation_session_set_record_checkpoint_for_test
      (f.session, graph_record_checkpoint, &f);
    rc = session_run_worker (&f);
    gboolean failed = g_str_equal (mode, "cancel") || g_str_equal (mode, "tenant-change")
        || g_str_equal (mode, "late-corrupt") || g_str_equal (mode, "selected-schema-late")
        || g_str_equal (mode, "selected-provision-late") || g_str_equal (mode, "after-write-failure");
    if (failed) {
      g_assert_cmpint (rc, !=, WYRELOG_E_OK);
      g_assert_null (f.committed.graphs);
      g_assert_cmpuint (f.writes, ==, g_str_equal (mode, "after-write-failure") ? 1 : 0);
      if (!g_str_equal (mode, "after-write-failure")) {
        g_autoptr (GBytes) unchanged = session_journal_bytes (&f);
        g_assert_true (g_bytes_equal (unchanged, f.journal_before));
      }
      session_assert_authority (&f, FALSE);
      g_cancellable_reset (f.cancel);
      g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_INVALID);
    } else {
      g_assert_cmpint (rc, ==, WYRELOG_E_OK);
      g_assert_cmpuint (f.checkpoints, ==, 1);
      session_assert_authority (&f, TRUE);
      if (!f.record_preflight) {
        g_assert_cmpuint (f.result.checked_graph_count, ==, 1);
        g_assert_cmpuint (f.result.validated_revision, ==, 2);
        g_autoptr (GBytes) journal = session_journal_bytes (&f);
        g_assert_true (g_bytes_equal (journal, f.journal_before));
      } else {
        g_assert_cmpuint (f.committed.revision, ==, 3);
        g_assert_cmpuint (f.committed.graphs->len, ==, 1);
        g_assert_cmpstr (f.committed.selected_graph_id, ==, selected);
        g_assert_cmpuint (f.writes, ==, 1);
        wyl_fact_offline_restore_journal_clear (&f.committed);
        g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
        g_assert_cmpuint (f.writes, ==, 1);
        g_assert_cmpuint (f.checkpoints, ==, 2);
      }
      session_assert_files_unchanged (&f, files);
    }
  }
  g_clear_pointer (&f.session, wyl_fact_offline_restore_validation_session_free);
  if (g_str_equal (mode, "record") || g_str_equal (mode, "after-write-failure")) {
    f.mode = "record";
    g_assert_cmpint (wyl_fact_offline_restore_validation_session_new
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
        session_operation, 3, 0, &f.session), ==, WYRELOG_E_POLICY);
    g_assert_null (f.session);
    g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
        session_operation, 3, 0, &f.session), ==, WYRELOG_E_OK);
    wyl_fact_offline_restore_journal_clear (&f.committed);
    wyl_fact_offline_restore_validation_session_set_checkpoint_for_test
      (f.session, graph_session_checkpoint, &f);
    guint checkpoints = f.checkpoints;
    f.record_preflight = FALSE;
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.result.checked_graph_count, ==, 1);
    g_assert_cmpuint (f.result.validated_revision, ==, 3);
    f.record_preflight = TRUE;
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.checkpoints, ==, checkpoints + 2);
    g_assert_cmpuint (f.committed.revision, ==, 3);
    session_corrupt_stage (&f, selected);
    wyl_fact_offline_restore_journal_clear (&f.committed);
    g_assert_cmpint (session_run_worker (&f), !=, WYRELOG_E_OK);
    g_assert_null (f.committed.graphs);
  }
  if (has_sibling) {
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
          (f.fixture.runtime, &sibling_key, &after), ==, WYRELOG_E_OK);
    g_assert_cmpuint (before.operation_generation, ==, after.operation_generation);
    g_assert_cmpuint (before.engine_generation, ==, after.engine_generation);
    g_assert_cmpint (before.admission, ==, after.admission);
    g_assert_cmpint (before.state, ==, after.state);
  }
  wyl_fact_graph_runtime_status_clear (&before);
  wyl_fact_graph_runtime_status_clear (&after);
  wyl_fact_graph_key_clear (&sibling_key);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
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
  if (g_str_equal (f.mode, "missing-runtime")) {
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    WylFactGraphKey key = { 0 };
    WylFactGraphRuntimeStatus status = { 0 };
    g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "zeta"),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
          (f.fixture.runtime, &key, &status), ==, WYRELOG_E_OK);
    g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_EMPTY);
    g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
    g_assert_false (status.queryable);
    g_assert_cmpuint (status.operation_generation, ==, 0);
    g_assert_cmpuint (status.engine_generation, ==, 0);
    wyl_fact_graph_runtime_status_clear (&status);
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpint (f.result.status, ==,
        WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED);
    g_clear_pointer (&f.session,
        wyl_fact_offline_restore_validation_session_free);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
          (f.fixture.runtime, &key, &status), ==, WYRELOG_E_OK);
    g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
    wyl_fact_graph_runtime_status_clear (&status);
    wyl_fact_graph_key_clear (&key);
    session_fixture_clear (&f);
    return;
  }
  g_assert_cmpint (rc, !=, WYRELOG_E_OK);
  g_assert_null (f.session);
  session_assert_authority (&f, FALSE);
  session_fixture_clear (&f);
}

static void
test_restore_validation_session_fresh_runtime (gconstpointer data)
{
  const gchar *selected = data;
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "success", selected);
  for (guint i = 0; i < 2; i++)
    g_clear_pointer (&f.snapshots[i], wyl_fact_graph_snapshot_unref);
  g_clear_pointer (&f.fixture.runtime,
      wyl_fact_graph_runtime_manager_unref);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      f.capture.manifest, session_operation, selected == NULL ? 3 : 2, 0,
      &f.session), ==, WYRELOG_E_OK);
  g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
  g_assert_cmpint (f.result.status, ==,
      WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED);
  WylFactGraphKey sibling = { 0 };
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&sibling, "tenant-a", "zeta"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (f.fixture.runtime, &sibling, &status), ==,
      selected == NULL ? WYRELOG_E_OK : WYRELOG_E_NOT_FOUND);
  if (selected == NULL) {
    g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_EMPTY);
    g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
    g_assert_false (status.queryable);
  }
  wyl_fact_graph_runtime_status_clear (&status);
  wyl_fact_graph_key_clear (&sibling);
  session_fixture_clear (&f);
}

static void
test_restore_validation_session_missing_runtime_policy_drift (void)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, "missing-runtime");
  mutate_tenant_after_snapshot (&f.capture);
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      f.capture.manifest, session_operation, 3, 0, &f.session), !=,
      WYRELOG_E_OK);
  g_assert_null (f.session);
  WylFactGraphKey key = { 0 };
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "zeta"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (f.fixture.runtime, &key, &status), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_graph_runtime_status_clear (&status);
  wyl_fact_graph_key_clear (&key);
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
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
        (NULL, NULL, NULL, NULL, NULL, 0, 0, &session), ==, WYRELOG_E_INVALID);
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
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
        (fixture.policy, fixture.root, fixture.runtime, canonical,
      "018f22d0-7b6d-7a5b-8c31-123456789ab4", 1, 0, &session), ==,
      WYRELOG_E_POLICY);
  g_assert_null (session);
  fixture_clear (&fixture);
#else
  g_test_skip ("Windows-only fail-closed boundary");
#endif
}

static void
test_graph_coordinator_invalid_input (void)
{
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_stage_run (NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, 0, 0, &journal), ==, WYRELOG_E_INVALID);
  g_assert_null (journal.graphs);
  WylFactOfflineBackupSource *source = (gpointer) 1;
  g_assert_cmpint (wyl_fact_offline_backup_source_new_for_graph_with_lease
        (NULL, NULL, NULL, NULL, NULL, 0, NULL, &source), ==, WYRELOG_E_INVALID);
  g_assert_null (source);
#ifdef G_OS_WIN32
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-graph-source-windows-XXXXXX");
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture.root, &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_backup_source_new_for_graph_with_lease
        (fixture.policy, fixture.root, fixture.runtime, "tenant-a", "alpha",
      0, lease, &source), ==, WYRELOG_E_POLICY);
  g_assert_null (source);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  fixture_clear (&fixture);
#endif
}

static void
test_graph_import_invalid_input (void)
{
  WylFactOfflineRestoreJournal journal = { 0 };
  WylFactOfflineRestoreInput input = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_import_run (NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, 0, 0, &input, NULL, &journal), ==,
      WYRELOG_E_INVALID);
  g_assert_null (journal.graphs);
}

#ifdef G_OS_WIN32
static wyrelog_error_t
import_windows_read (guint64 offset, guint8 *buffer, gsize capacity,
    gsize *out_read, gpointer data)
{
  (void) offset;
  (void) buffer;
  (void) capacity;
  (void) out_read;
  (*(guint *) data)++;
  return WYRELOG_E_IO;
}

static wyrelog_error_t
import_windows_revalidate (gpointer data)
{
  (*(guint *) data)++;
  return WYRELOG_E_IO;
}
#endif

static void
test_graph_import_windows (void)
{
#ifdef G_OS_WIN32
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "wyl-import-windows-XXXXXX");
  guint calls = 0;
  const WylFactOfflineRestoreInput input = {
    import_windows_read, import_windows_revalidate,
  };
  g_autoptr (GBytes) manifest = g_bytes_new_static ("{}", 2);
  WylFactOfflineRestoreJournal journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_import_run
        (fixture.policy, fixture.root, fixture.runtime, "tenant-a", "zeta",
      manifest, "018f22d0-7b6d-7a5b-8c31-123456789ab4", 1, 0,
      &input, &calls, &journal), ==, WYRELOG_E_POLICY);
  g_assert_null (journal.graphs);
  g_assert_cmpuint (calls, ==, 0);
  fixture_clear (&fixture);
#else
  g_test_skip ("Windows-only fail-closed boundary");
#endif
}

#ifndef G_OS_WIN32
static void
rollback_test_advance (SessionFixture *f, gboolean begin)
{
  WylFactOfflineRestoreJournal journal = { 0 }, committed = { 0 };
  WylFactOfflineRestoreStoreResult result;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f->fixture.policy, session_operation, &journal), ==, WYRELOG_E_OK);
  guint64 revision = journal.revision;
  if (journal.decision == WYL_FACT_OFFLINE_RESTORE_DECISION_NONE)
    g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&journal,
        WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK), ==, WYRELOG_E_OK);
  else {
    g_assert_true (begin);
    g_assert_cmpint (wyl_fact_offline_restore_journal_begin_attempt (&journal,
        "zeta", WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE), ==,
        WYRELOG_E_OK);
  }
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (f->fixture.policy, revision, &journal, &result, &committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  wyl_fact_offline_restore_journal_clear (&journal);
  wyl_fact_offline_restore_journal_clear (&committed);
}

static void
test_graph_rollback (gconstpointer data)
{
  const gchar *mode = data;
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f,
      g_str_equal (mode, "schema-transition")
      ? "schema-transition-graph" : "success", "zeta");
  g_autofree gchar *stage = session_stage_path (&f, "zeta");
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_autofree gchar *sibling = graph_file_path (&f.fixture, "alpha",
          "facts.duckdb");
  GStatBuf sibling_before = { 0 }, sibling_after = { 0 };
  g_assert_cmpint (g_stat (sibling, &sibling_before), ==, 0);
  guint64 revision = 2;
  if (!g_str_equal (mode, "fresh") && !g_str_equal (mode, "restart")) {
    rollback_test_advance (&f, FALSE);
    rollback_test_advance (&f, TRUE);
    revision = 4;
  }
  if (g_str_equal (mode, "pending-absent")) {
    g_assert_cmpint (g_remove (stage), ==, 0);
    g_clear_pointer (&f.capture.manifest, g_bytes_unref);
    g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
    g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
            "policy.db", NULL);
    g_assert_cmpint (wyl_policy_store_open (policy_path,
        &f.fixture.policy), ==, WYRELOG_E_OK);
  }
  if (g_str_equal (mode, "restart")
      || g_str_equal (mode, "restart-pending")) {
    for (guint i = 0; i < 2; i++)
      g_clear_pointer (&f.snapshots[i], wyl_fact_graph_snapshot_unref);
    g_clear_pointer (&f.fixture.runtime,
        wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime),
        ==, WYRELOG_E_OK);
  }
  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 5);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&committed), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);
  g_assert_false (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_assert_cmpint (g_stat (sibling, &sibling_after), ==, 0);
  g_assert_cmpuint (sibling_after.st_ino, ==, sibling_before.st_ino);
  g_assert_cmpint (sibling_after.st_size, ==, sibling_before.st_size);
  if (g_str_equal (mode, "schema-transition")) {
    WylPolicyRelationActivationRecord *active = NULL;
    g_assert_cmpint (wyl_policy_store_read_relation_activation
          (f.fixture.policy, "tenant-a", "zeta", "backup", "items",
        &active), ==, WYRELOG_E_OK);
    g_assert_cmpuint (active->active_schema_version, ==, 2);
    wyl_policy_relation_activation_record_free (active);
  }
  wyl_fact_offline_restore_journal_clear (&committed);
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 5, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 5);
  wyl_fact_offline_restore_journal_clear (&committed);
  if (g_str_equal (mode, "fresh")) {
    g_assert_cmpint (wyl_fact_offline_restore_rollback_release_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, 5, 0), ==, WYRELOG_E_OK);
    g_clear_pointer (&f.journal_before, g_bytes_unref);
  } else {
    g_clear_pointer (&f.journal_before, g_bytes_unref);
    f.journal_before = session_journal_bytes (&f);
  }
  session_fixture_clear (&f);
}

static void
test_graph_rollback_absent_main (void)
{
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "stage-only", "zeta");
  g_autofree gchar *stage = session_stage_path (&f, "zeta");
  g_autofree gchar *main_path = graph_file_path (&f.fixture, "zeta",
          "facts.duckdb");
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (main_path, G_FILE_TEST_EXISTS));
  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 2, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 5);
  g_assert_false (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (main_path, G_FILE_TEST_EXISTS));
  wyl_fact_offline_restore_journal_clear (&committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t
rollback_release_fault (WylFactOfflineRestoreRollbackCheckpoint point,
    gpointer data)
{
  return point == *(WylFactOfflineRestoreRollbackCheckpoint *) data
    ? WYRELOG_E_IO : WYRELOG_E_OK;
}

static wyrelog_error_t
rollback_release_inject_stage (WylFactOfflineRestoreRollbackCheckpoint point,
    gpointer data)
{
  if (point == WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_RELEASE) {
    const gchar *path = data;
    g_assert_true (g_file_set_contents (path, "foreign", -1, NULL));
    g_assert_cmpint (g_chmod (path, 0600), ==, 0);
  }
  return WYRELOG_E_OK;
}
#endif

static void
test_tenant_rollback_two_graphs (gconstpointer data)
{
  gboolean partial = g_strcmp0 (data, "partial") == 0;
  gboolean schema_transition = g_strcmp0 (data, "schema-transition") == 0;
  SessionFixture f = { 0 };
  session_fixture_init (&f, partial ? "partial-staging" :
      schema_transition ? "schema-transition-tenant" : "success");
  g_autofree gchar *alpha_stage = session_stage_path (&f, "alpha");
  g_autofree gchar *zeta_stage = session_stage_path (&f, "zeta");
  g_assert_true (g_file_test (alpha_stage, G_FILE_TEST_EXISTS));
  g_assert_cmpint (g_file_test (zeta_stage, G_FILE_TEST_EXISTS), ==, !partial);
  for (guint i = 0; i < 2; i++)
    g_clear_pointer (&f.snapshots[i], wyl_fact_graph_snapshot_unref);
  g_clear_pointer (&f.fixture.runtime,
      wyl_fact_graph_runtime_manager_unref);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime),
      ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, partial ? 2 : 3, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&committed), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);
  g_assert_false (g_file_test (alpha_stage, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (zeta_stage, G_FILE_TEST_EXISTS));
  if (schema_transition) {
    const gchar *graphs[] = { "alpha", "zeta" };
    for (guint i = 0; i < G_N_ELEMENTS (graphs); i++) {
      WylPolicyRelationActivationRecord *active = NULL;
      g_assert_cmpint (wyl_policy_store_read_relation_activation
            (f.fixture.policy, "tenant-a", graphs[i], "backup", "items",
          &active), ==, WYRELOG_E_OK);
      g_assert_cmpuint (active->active_schema_version, ==, 2);
      wyl_policy_relation_activation_record_free (active);
    }
  }
  guint64 revision = committed.revision;
  wyl_fact_offline_restore_journal_clear (&committed);
  g_assert_cmpint (wyl_fact_offline_restore_rollback_recover_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, revision);
  wyl_fact_offline_restore_journal_clear (&committed);
#ifdef WYL_TEST_HANDLE_SEAMS
  gboolean release_before = g_strcmp0 (data, "release-before") == 0;
  gboolean release_after = g_strcmp0 (data, "release-after") == 0;
  WylFactOfflineRestoreRollbackCheckpoint fault = release_before
    ? WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_RELEASE
    : WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_RELEASE;
  if (release_before || release_after)
    wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
      (rollback_release_fault, &fault);
  wyrelog_error_t release_rc = wyl_fact_offline_restore_rollback_release_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          session_operation, revision, 0);
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test (NULL, NULL);
  if (release_before || release_after) {
    g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
    g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
            "policy.db", NULL);
    g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy),
        ==, WYRELOG_E_OK);
  }
  g_assert_cmpint (release_rc, ==,
      release_before || release_after ? WYRELOG_E_IO : WYRELOG_E_OK);
  if (release_before)
    g_assert_cmpint (wyl_fact_offline_restore_rollback_release_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, revision, 0), ==, WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_fact_offline_restore_rollback_release_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0), ==, WYRELOG_E_OK);
#endif
  g_assert_cmpint (wyl_fact_offline_restore_rollback_release_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0), ==, WYRELOG_E_NOT_FOUND);
  g_auto (WylFactOfflineRestoreJournal) gone = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &gone), ==, WYRELOG_E_NOT_FOUND);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  session_fixture_clear (&f);
}

#ifdef WYL_TEST_HANDLE_SEAMS
static void
test_tenant_rollback_release_late_stage (void)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  g_autofree gchar *stage = session_stage_path (&f, "zeta");
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 3, 0, &committed), ==, WYRELOG_E_OK);
  guint64 revision = committed.revision;
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
    (rollback_release_inject_stage, stage);
  g_assert_cmpint (wyl_fact_offline_restore_rollback_release_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0), ==, WYRELOG_E_POLICY);
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test (NULL, NULL);
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_auto (WylFactOfflineRestoreJournal) retained = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &retained), ==, WYRELOG_E_OK);
  g_assert_cmpint (g_remove (stage), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_rollback_release_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0), ==, WYRELOG_E_OK);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  session_fixture_clear (&f);
}
#endif

static void rollback_write_foreign (const gchar *path);

static void
test_tenant_rollback_rejects (gconstpointer data)
{
  const gchar *mode = data;
  gboolean orphan = g_str_equal (mode, "unbound-orphan");
  SessionFixture f = { 0 };
  session_fixture_init (&f, orphan ? "partial-staging" : "success");
  g_autofree gchar *stage = session_stage_path (&f,
          orphan ? "zeta" : "alpha");
  if (orphan)
    rollback_write_foreign (stage);
  else if (g_str_equal (mode, "substituted-stage")
      || g_str_equal (mode, "changed-inode")) {
    g_autofree gchar *parked = graph_file_path (&f.fixture, "alpha",
            "parked-stage.duckdb");
    g_assert_cmpint (g_rename (stage, parked), ==, 0);
    if (g_str_equal (mode, "changed-inode")) {
      g_autofree gchar *bytes = NULL;
      gsize length = 0;
      g_assert_true (g_file_get_contents (parked, &bytes, &length, NULL));
      g_assert_true (g_file_set_contents (stage, bytes, length, NULL));
    } else
      rollback_write_foreign (stage);
  }
  if (g_str_equal (mode, "missing-claim")) {
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        "DELETE FROM fact_offline_restore_tenant_claims WHERE "
        "operation_uuid='018f22d0-7b6d-7a5b-8c31-123456789ab4';",
        NULL, NULL, NULL), ==, SQLITE_OK);
  }
  GStatBuf before = { 0 }, after = { 0 };
  g_assert_cmpint (g_stat (stage, &before), ==, 0);
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_tenant_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          session_operation, g_str_equal (mode, "stale") ? 1
          : orphan ? 2 : 3, 0, &committed);
  g_assert_cmpint (rc, !=, WYRELOG_E_OK);
  g_assert_null (committed.graphs);
  g_assert_cmpint (g_stat (stage, &after), ==, 0);
  g_assert_cmpuint (after.st_ino, ==, before.st_ino);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  if (!g_str_equal (mode, "missing-claim"))
    f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void
test_tenant_rollback_partial_progress (void)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  g_autofree gchar *alpha = session_stage_path (&f, "alpha");
  g_autofree gchar *zeta = session_stage_path (&f, "zeta");
  g_autofree gchar *parked = graph_file_path (&f.fixture, "zeta",
          "parked-stage.duckdb");
  g_assert_cmpint (g_rename (zeta, parked), ==, 0);
  rollback_write_foreign (zeta);
  GStatBuf foreign_before = { 0 }, foreign_after = { 0 };
  g_assert_cmpint (g_stat (zeta, &foreign_before), ==, 0);
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 3, 0, &committed), ==, WYRELOG_E_POLICY);
  g_assert_false (g_file_test (alpha, G_FILE_TEST_EXISTS));
  g_assert_cmpint (g_stat (zeta, &foreign_after), ==, 0);
  g_assert_cmpuint (foreign_after.st_ino, ==, foreign_before.st_ino);
  g_auto (WylFactOfflineRestoreJournal) pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &pending), ==, WYRELOG_E_OK);
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (pending.graphs, 0))->transition_state, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED);
  g_assert_cmpint (pending.decision, ==,
      WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK);
  g_assert_cmpint (g_remove (zeta), ==, 0);
  g_assert_cmpint (g_rename (parked, zeta), ==, 0);
  for (guint i = 0; i < 2; i++)
    g_clear_pointer (&f.snapshots[i], wyl_fact_graph_snapshot_unref);
  g_clear_pointer (&f.fixture.runtime, wyl_fact_graph_runtime_manager_unref);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_rollback_recover_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&committed), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);
  g_assert_false (g_file_test (zeta, G_FILE_TEST_EXISTS));
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void
test_graph_rollback_unbound_orphan (void)
{
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "coordinator", "zeta");
  g_autofree gchar *stage = session_stage_path (&f, "zeta");
  g_assert_true (g_file_set_contents (stage, "orphan", -1, NULL));
  g_auto (WylFactOfflineRestoreJournal) before = { 0 };
  g_auto (WylFactOfflineRestoreJournal) after = { 0 };
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &before), ==, WYRELOG_E_OK);
  g_assert_cmpuint (before.revision, ==, 1);
  g_assert_true (artifact_identity_is_zero
        (&((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (before.graphs, 0))->staged_main_identity));
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 1, 0, &committed), ==, WYRELOG_E_POLICY);
  g_assert_null (committed.graphs);
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (after.revision, ==, 1);
  g_assert_cmpint (after.decision, ==, WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void
test_graph_rollback_unbound_absent (void)
{
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "coordinator", "zeta");
  g_autofree gchar *stage = session_stage_path (&f, "zeta");
  g_assert_false (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_autofree gchar *sibling = graph_file_path (&f.fixture, "alpha",
          "facts.duckdb");
  GStatBuf sibling_before = { 0 }, sibling_after = { 0 };
  g_assert_cmpint (g_stat (sibling, &sibling_before), ==, 0);
  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 1, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 2);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&committed), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);
  g_assert_false (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_assert_cmpint (g_stat (sibling, &sibling_after), ==, 0);
  g_assert_cmpuint (sibling_after.st_ino, ==, sibling_before.st_ino);
  wyl_fact_offline_restore_journal_clear (&committed);
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 2, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 2);
  wyl_fact_offline_restore_journal_clear (&committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

#ifdef WYL_TEST_HANDLE_SEAMS
static void
create_unbound_stage_after_sync (G_GNUC_UNUSED gint directory_fd,
    gpointer user_data)
{
  const gchar *path = user_data;
  g_assert_true (g_file_set_contents (path, "late-stage", -1, NULL));
  g_assert_cmpint (g_chmod (path, 0600), ==, 0);
}

static void
test_graph_rollback_unbound_post_sync_stage (void)
{
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "coordinator", "zeta");
  g_autofree gchar *stage = session_stage_path (&f, "zeta");
  wyl_fact_artifact_transition_posix_set_recovery_post_sync_hook_for_test
    (create_unbound_stage_after_sync, stage);
  WylFactOfflineRestoreJournal committed = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          session_operation, 1, 0, &committed);
  wyl_fact_artifact_transition_posix_set_recovery_post_sync_hook_for_test
    (NULL, NULL);
  g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
  g_assert_null (committed.graphs);
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_auto (WylFactOfflineRestoreJournal) durable = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &durable), ==, WYRELOG_E_OK);
  g_assert_cmpuint (durable.revision, ==, 1);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void
test_graph_rollback_unbound_sync_failure (void)
{
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "coordinator", "zeta");
  WylFactOfflineRestoreJournal committed = { 0 };
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_RECOVER_RETIRE_SYNC_DIR);
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 1, 0, &committed), ==, WYRELOG_E_IO);
  g_assert_null (committed.graphs);
  g_auto (WylFactOfflineRestoreJournal) durable = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &durable), ==, WYRELOG_E_OK);
  g_assert_cmpuint (durable.revision, ==, 1);
  g_assert_cmpint (durable.decision, ==, WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}
#endif

static void
rollback_write_foreign (const gchar *path)
{
  g_assert_true (g_file_set_contents (path, "foreign", 7, NULL));
  g_assert_cmpint (g_chmod (path, 0600), ==, 0);
}

static void
test_graph_rollback_rejects (gconstpointer data)
{
  const gchar *mode = data;
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "success", "zeta");
  g_autofree gchar *stage = session_stage_path (&f, "zeta");
  g_autofree gchar *main_path = graph_file_path (&f.fixture, "zeta",
          "facts.duckdb");
  if (g_str_equal (mode, "foreign-stage")) {
    g_autofree gchar *parked = graph_file_path (&f.fixture, "zeta",
            "parked-stage.duckdb");
    g_assert_cmpint (g_rename (stage, parked), ==, 0);
    rollback_write_foreign (stage);
  } else if (g_str_equal (mode, "foreign-main")) {
    g_autofree gchar *parked = graph_file_path (&f.fixture, "zeta",
            "parked-main.duckdb");
    g_assert_cmpint (g_rename (main_path, parked), ==, 0);
    rollback_write_foreign (main_path);
  } else if (g_str_equal (mode, "sidecar")) {
    g_autofree gchar *sidecar = graph_file_path (&f.fixture, "zeta",
            "facts.duckdb-wal");
    rollback_write_foreign (sidecar);
  } else if (g_str_equal (mode, "extra-link")) {
    g_autofree gchar *extra = graph_file_path (&f.fixture, "zeta",
            "extra-main-link");
    g_assert_cmpint (link (main_path, extra), ==, 0);
  } else if (g_str_equal (mode, "stage-link")) {
    g_autofree gchar *extra = graph_file_path (&f.fixture, "zeta",
            "extra-stage-link");
    g_assert_cmpint (link (stage, extra), ==, 0);
  } else if (g_str_equal (mode, "wrong-companion")) {
    sqlite3_stmt *stmt = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
          (f.fixture.policy),
        "SELECT stage_basename FROM fact_graph_provisioning "
        "WHERE tenant_id='tenant-a' AND graph_id='zeta' "
        "AND phase='active';", -1, &stmt, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
    const gchar *basename = (const gchar *) sqlite3_column_text (stmt, 0);
    g_autofree gchar *companion = graph_file_path (&f.fixture, "zeta",
            basename);
    g_assert_cmpint (sqlite3_finalize (stmt), ==, SQLITE_OK);
    g_autofree gchar *parked = graph_file_path (&f.fixture, "zeta",
            "parked-companion");
    g_assert_cmpint (g_rename (companion, parked), ==, 0);
    rollback_write_foreign (companion);
  } else if (g_str_equal (mode, "tenant-generation"))
    mutate_tenant_after_snapshot (&f.capture);

  guint64 revision = g_str_equal (mode, "stale") ? 1 : 2;
  if (g_str_equal (mode, "commit")) {
    WylFactOfflineRestoreJournal journal = { 0 }, committed = { 0 };
    WylFactOfflineRestoreStoreResult result;
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (f.fixture.policy, session_operation, &journal), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_mark_preflight
          (&journal, "zeta"), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
          (f.fixture.policy, 2, &journal, &result, &committed), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
    wyl_fact_offline_restore_journal_clear (&journal);
    journal = committed;
    memset (&committed, 0, sizeof committed);
    g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&journal,
        WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT), ==, WYRELOG_E_POLICY);
    wyl_fact_offline_restore_journal_clear (&journal);
    wyl_fact_offline_restore_journal_clear (&committed);
    g_clear_pointer (&f.journal_before, g_bytes_unref);
    f.journal_before = session_journal_bytes (&f);
    session_fixture_clear (&f);
    return;
  }

  GStatBuf stage_before = { 0 }, stage_after = { 0 };
  g_assert_cmpint (g_stat (stage, &stage_before), ==, 0);
  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &committed), !=, WYRELOG_E_OK);
  g_assert_null (committed.graphs);
  g_assert_cmpint (g_stat (stage, &stage_after), ==, 0);
  g_assert_cmpuint (stage_after.st_ino, ==, stage_before.st_ino);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

#ifdef WYL_TEST_HANDLE_SEAMS
typedef struct
{
  WylFactOfflineRestoreRollbackCheckpoint target;
  guint calls;
} RollbackCrash;

static wyrelog_error_t
rollback_crash_checkpoint (WylFactOfflineRestoreRollbackCheckpoint point,
    gpointer user_data)
{
  RollbackCrash *crash = user_data;
  if (point != crash->target)
    return WYRELOG_E_OK;
  crash->calls++;
  return WYRELOG_E_IO;
}

static void
test_graph_rollback_crash (gconstpointer data)
{
  const gchar *mode = data;
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "success", "zeta");
  RollbackCrash crash = {
    .target = g_str_equal (mode, "decision")
      ? WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_DECISION
      : g_str_equal (mode, "begin")
      ? WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_BEGIN
      : WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_COMPLETE,
  };
  if (!g_str_equal (mode, "sync"))
    wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
      (rollback_crash_checkpoint, &crash);
  else
    wyl_fact_artifact_transition_posix_set_test_fault
      (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_RETIRE_STAGE_SYNC_DIR);
  WylFactOfflineRestoreJournal committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 2, 0, &committed), !=, WYRELOG_E_OK);
  g_assert_null (committed.graphs);
  if (!g_str_equal (mode, "sync"))
    g_assert_cmpuint (crash.calls, ==, 1);
  else
    g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
          (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_RETIRE_STAGE_SYNC_DIR));
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
    (NULL, NULL);
  WylFactOfflineRestoreJournal pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &pending), ==, WYRELOG_E_OK);
  guint64 revision = pending.revision;
  g_assert_cmpuint (revision, ==,
      g_str_equal (mode, "decision") ? 3 : 4);
  WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
        (pending.graphs, 0);
  if (revision == 4)
    g_assert_cmpint (graph->attempt, ==,
        WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
  wyl_fact_offline_restore_journal_clear (&pending);
  g_clear_pointer (&f.capture.manifest, g_bytes_unref);
  g_assert_cmpint (wyl_fact_offline_restore_graph_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.revision, ==, 5);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&committed), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);
  wyl_fact_offline_restore_journal_clear (&committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void
test_tenant_rollback_crash (gconstpointer data)
{
  const gchar *mode = data;
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  RollbackCrash crash = {
    .target = g_str_equal (mode, "decision")
      ? WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_DECISION
      : g_str_equal (mode, "begin")
      ? WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_BEGIN
      : WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_COMPLETE,
  };
  if (!g_str_equal (mode, "sync") && !g_str_equal (mode, "unlink"))
    wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
      (rollback_crash_checkpoint, &crash);
  else
    wyl_fact_artifact_transition_posix_set_test_fault
      (g_str_equal (mode, "sync")
      ? WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_RETIRE_STAGE_SYNC_DIR
      : WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_RETIRE_STAGE_UNLINK);
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 3, 0, &committed), !=, WYRELOG_E_OK);
  g_assert_null (committed.graphs);
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test (NULL, NULL);
  g_auto (WylFactOfflineRestoreJournal) pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &pending), ==, WYRELOG_E_OK);
  guint64 revision = pending.revision;
  g_assert_cmpuint (revision, >=, 4);
  for (guint i = 0; i < 2; i++)
    g_clear_pointer (&f.snapshots[i], wyl_fact_graph_snapshot_unref);
  g_clear_pointer (&f.fixture.runtime, wyl_fact_graph_runtime_manager_unref);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&f.capture.manifest, g_bytes_unref);
  g_assert_cmpint (wyl_fact_offline_restore_rollback_recover_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 0, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&committed), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static wyrelog_error_t
tenant_prepare_race (WylFactOfflineRestoreRollbackCheckpoint point,
    gpointer data)
{
  if (point != WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_DECISION_CAS)
    return WYRELOG_E_OK;
  SessionFixture *f = data;
  g_auto (WylFactOfflineRestoreJournal) desired = { 0 }, committed = { 0 };
  WylFactOfflineRestoreStoreResult result;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f->fixture.policy, session_operation, &desired), ==, WYRELOG_E_OK);
  guint64 revision = desired.revision;
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_preflight
        (&desired, "alpha"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (f->fixture.policy, revision, &desired, &result, &committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test (NULL, NULL);
  return WYRELOG_E_OK;
}

static void
test_tenant_rollback_prepare_race (void)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  g_autofree gchar *stage = session_stage_path (&f, "alpha");
  GStatBuf before = { 0 }, after = { 0 };
  g_assert_cmpint (g_stat (stage, &before), ==, 0);
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
    (tenant_prepare_race, &f);
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_rollback_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, 3, 0, &committed), ==, WYRELOG_E_BUSY);
  wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test (NULL, NULL);
  g_assert_cmpint (g_stat (stage, &after), ==, 0);
  g_assert_cmpuint (after.st_ino, ==, before.st_ino);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}
#endif

static void
test_graph_import_authority_accessor (void)
{
  WylFactOfflineBackupSourceAuthority authority;
  memset (&authority, 0xff, sizeof authority);
  g_assert_false (wyl_fact_offline_backup_source_get_authority (NULL, 0, &authority));
  g_assert_true (artifact_identity_is_zero (&authority.main_identity));
  g_assert_cmpuint (authority.tenant_lifecycle_generation, ==, 0);
  g_assert_cmpuint (authority.tenant_reconciliation_generation, ==, 0);
  g_assert_cmpuint (authority.graph_lifecycle_generation, ==, 0);
  g_assert_cmpuint (authority.graph_reconciliation_generation, ==, 0);
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, "coordinator", "zeta");
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (f.fixture.root, &lease), ==, WYRELOG_E_OK);
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new_for_graph_with_lease
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a", "zeta",
      0, lease, &source), ==, WYRELOG_E_OK);
  g_assert_false (wyl_fact_offline_backup_source_get_authority (source, 0, NULL));
  memset (&authority, 0xff, sizeof authority);
  g_assert_false (wyl_fact_offline_backup_source_get_authority (source, 1, &authority));
  g_assert_true (artifact_identity_is_zero (&authority.main_identity));
  g_assert_cmpuint (authority.tenant_lifecycle_generation, ==, 0);
  g_assert_cmpuint (authority.tenant_reconciliation_generation, ==, 0);
  g_assert_cmpuint (authority.graph_lifecycle_generation, ==, 0);
  g_assert_cmpuint (authority.graph_reconciliation_generation, ==, 0);
  g_assert_true (wyl_fact_offline_backup_source_get_authority (source, 0, &authority));
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &journal), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (journal.graphs, 0);
  g_assert_cmpuint (authority.main_identity.domain, ==, graph->expected_main_identity.domain);
  g_assert_cmpuint (authority.main_identity.object, ==, graph->expected_main_identity.object);
  g_assert_cmpuint (authority.tenant_lifecycle_generation, ==, journal.destination_tenant_lifecycle_generation);
  g_assert_cmpuint (authority.tenant_reconciliation_generation, ==, journal.destination_tenant_reconciliation_generation);
  g_assert_cmpuint (authority.graph_lifecycle_generation, ==, graph->destination_lifecycle_generation);
  g_assert_cmpuint (authority.graph_reconciliation_generation, ==, graph->destination_reconciliation_generation);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  session_fixture_clear (&f);
}

typedef struct
{
  SessionFixture *fixture;
  const gchar *mode;
  GBytes *payload;
  guint reads;
  guint validations;
  guint64 offset;
} ImportInput;

static wyrelog_error_t
import_read (guint64 offset, guint8 *buffer, gsize capacity,
    gsize *out_read, gpointer data)
{
  ImportInput *input = data;
  if (g_str_equal (input->mode, "missing-runtime")) {
    WylFactRootWriterLease *competing = NULL;
    g_assert_cmpint (wyl_fact_root_writer_lease_acquire
          (input->fixture->fixture.root, &competing), ==, WYRELOG_E_BUSY);
    wyl_fact_root_writer_lease_release (competing);
  } else
    session_assert_authority (input->fixture, TRUE);
  g_assert_cmpuint (offset, ==, input->offset);
  g_assert_cmpuint (capacity, >, 0);
  g_assert_cmpuint (capacity, <=, 64 * 1024);
  input->reads++;
  *out_read = 0;
  gsize length;
  const guint8 *bytes = g_bytes_get_data (input->payload, &length);
  if (g_str_equal (input->mode, "read-error"))
    return WYRELOG_E_IO;
  if (g_str_equal (input->mode, "count-overflow")) {
    *out_read = capacity + 1;
    return WYRELOG_E_OK;
  }
  if (offset == length) {
    g_assert_cmpuint (capacity, ==, 1);
    if (g_str_equal (input->mode, "final-eof-error"))
      return WYRELOG_E_IO;
    if (g_str_equal (input->mode, "excess")) {
      buffer[0] = 42;
      *out_read = 1;
      input->offset++;
    }
    return WYRELOG_E_OK;
  }
  g_assert_cmpuint (offset, <, length);
  if (g_str_equal (input->mode, "truncated") && offset >= length / 2)
    return WYRELOG_E_OK;
  /* Deliberately exercise positive partial reads on every successful stream. */
  *out_read = MIN (MIN (capacity, (gsize) 17003), length - offset);
  memcpy (buffer, bytes + offset, *out_read);
  if (g_str_equal (input->mode, "corrupt") && offset == 0)
    buffer[0] ^= 1;
  if (offset == 0 && g_str_equal (input->mode, "late-provision"))
    graph_corrupt_provision (input->fixture, "zeta");
  if (offset == 0 && g_str_equal (input->mode, "late-schema"))
    graph_corrupt_schema (input->fixture, "zeta");
  if (offset == 0 && g_str_equal (input->mode, "late-tenant"))
    mutate_tenant_after_snapshot (&input->fixture->capture);
  if (offset == 0 && g_str_equal (input->mode, "late-journal")) {
    g_auto (WylFactOfflineRestoreJournal) desired = { 0 }, committed = { 0 };
    WylFactOfflineRestoreStoreResult result;
    wyl_policy_store_t *policy = input->fixture->fixture.policy;
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (policy, session_operation, &desired), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&desired,
        WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
          (policy, 1, &desired, &result, &committed), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
    g_assert_cmpuint (committed.revision, ==, 2);
  }
  input->offset += *out_read;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
import_revalidate (gpointer data)
{
  ImportInput *input = data;
  if (g_str_equal (input->mode, "missing-runtime")) {
    WylFactRootWriterLease *competing = NULL;
    g_assert_cmpint (wyl_fact_root_writer_lease_acquire
          (input->fixture->fixture.root, &competing), ==, WYRELOG_E_BUSY);
    wyl_fact_root_writer_lease_release (competing);
  } else
    session_assert_authority (input->fixture, TRUE);
  input->validations++;
  if (g_str_equal (input->mode, "revalidate-before")
      || (g_str_equal (input->mode, "revalidate-after") && input->validations == 2))
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

typedef struct
{
  SessionFixture *fixture;
  guint validations;
  guint reads;
  guint fail_validation;
  const gchar *mode;
} TenantImportTestInput;

static wyrelog_error_t
tenant_import_test_read (const gchar *graph_id, guint64 offset,
    guint8 *buffer, gsize capacity, gsize *out_read, gpointer data)
{
  TenantImportTestInput *input = data;
  guint index = g_strcmp0 (graph_id, "alpha") == 0 ? 0 : 1;
  g_assert_cmpstr (graph_id, ==, index == 0 ? "alpha" : "zeta");
  GBytes *payload = g_ptr_array_index (input->fixture->capture.artifact_bytes,
          index);
  gsize length = 0;
  const guint8 *bytes = g_bytes_get_data (payload, &length);
  g_assert_cmpuint (offset, <=, length);
  *out_read = MIN (capacity, length - offset);
  if (index == 1 && g_strcmp0 (input->mode, "short") == 0
      && offset >= length / 2)
    *out_read = 0;
  if (index == 1 && g_strcmp0 (input->mode, "excess") == 0
      && offset == length) {
    buffer[0] = 42;
    *out_read = 1;
  }
  if (*out_read != 0)
    memcpy (buffer, bytes + offset, *out_read);
  input->reads++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
tenant_import_test_revalidate (gpointer data)
{
  TenantImportTestInput *input = data;
  input->validations++;
  return input->validations == input->fail_validation
         ? WYRELOG_E_IO : WYRELOG_E_OK;
}

typedef struct
{
  SessionFixture *fixture;
  guint64 revision;
  GBytes *manifest;
} TenantPreflightTestJob;

static wyrelog_error_t
tenant_preflight_test_job (WylFactReplayJobContext *context, gpointer data)
{
  TenantPreflightTestJob *job = data;
  SessionFixture *f = job->fixture;
  return wyl_fact_offline_restore_tenant_preflight_run (f->fixture.policy,
             f->fixture.root, f->fixture.runtime, "tenant-a", job->manifest,
             session_operation, job->revision, 0, context, &f->committed);
}

static wyrelog_error_t
tenant_preflight_test_worker (TenantPreflightTestJob *job)
{
  WylFactReplaySchedulerConfig config;
  wyl_fact_replay_scheduler_config_defaults (&config);
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_autoptr (WylFactReplayFuture) future = NULL;
  wyrelog_error_t rc = wyl_fact_replay_scheduler_new (&config, NULL,
          &scheduler);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_scheduler_submit (scheduler, "tenant-a", "alpha",
            job->fixture->cancel, tenant_preflight_test_job, job, NULL,
            &future);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_future_wait (future);
  if (scheduler != NULL)
    g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
        WYRELOG_E_OK);
  return rc;
}

static void
test_tenant_provisioned_binding (void)
{
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  TenantPreflightTestJob job = { &f, 3, f.capture.manifest };
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 5);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "alpha", 4, 0, &f.committed), ==, WYRELOG_E_BUSY);
  g_assert_null (f.committed.graphs);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "alpha", 5, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.version, ==,
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION);
  g_assert_cmpuint (f.committed.revision, ==, 6);
  const WylFactOfflineRestoreJournalGraph *alpha =
      g_ptr_array_index (f.committed.graphs, 0);
  g_autofree gchar *old_uuid = g_strdup (alpha->old_provisioning_uuid);
  g_assert_nonnull (old_uuid);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "alpha", 6, 0, &f.committed), ==, WYRELOG_E_POLICY);
  g_assert_null (f.committed.graphs);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "zeta", 6, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 7);
  alpha = g_ptr_array_index (f.committed.graphs, 0);
  g_assert_cmpstr (alpha->old_provisioning_uuid, ==, old_uuid);
  g_assert_nonnull (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (f.committed.graphs, 1))->old_provisioning_uuid);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void import_restore_journal_for_test (wyl_policy_store_t *policy,
    const WylFactOfflineRestoreJournal *journal);

static wyrelog_error_t
tenant_sync_test_begin_effect (GBytes *journal, const GPtrArray *active_uuids,
    gpointer user_data)
{
  g_assert_nonnull (journal);
  g_assert_cmpuint (active_uuids->len, ==, 2);
  (*(guint *) user_data)++;
  return WYRELOG_E_OK;
}

static void
test_tenant_commit_resume_v5 (gconstpointer data)
{
  SessionFixture f = { 0 };
  gboolean schema_transition = data != NULL;
  session_fixture_init (&f, schema_transition ?
      "schema-transition-tenant" : "success");
  TenantPreflightTestJob job = { &f, 3, f.capture.manifest };
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  const gchar *graphs[] = { "alpha", "zeta" };
  for (guint i = 0; i < G_N_ELEMENTS (graphs); i++) {
    g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, graphs[i], 5 + i, 0, &f.committed), ==,
        WYRELOG_E_OK);
    if (i + 1 < G_N_ELEMENTS (graphs))
      wyl_fact_offline_restore_journal_clear (&f.committed);
  }
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&f.committed,
      WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT), ==, WYRELOG_E_OK);
  import_restore_journal_for_test (f.fixture.policy, &f.committed);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  guint64 revision = 8;
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision - 1, 0, &f.committed), ==,
      WYRELOG_E_BUSY);
  g_assert_null (f.committed.graphs);
#ifdef WYL_TEST_HANDLE_SEAMS
  wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
      WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &f.committed), ==, WYRELOG_E_IO);
  g_assert_null (f.committed.graphs);
  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &f.committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 9);
  revision = f.committed.revision;
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_autofree gchar *foreign = graph_file_path (&f.fixture, "alpha",
          "foreign");
  g_assert_true (g_file_set_contents (foreign, "foreign", -1, NULL));
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &f.committed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (f.committed.graphs);
  g_assert_cmpint (g_remove (foreign), ==, 0);
#endif
  for (guint step = 0; step < 12; step++) {
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, revision, 0, &f.committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, >, revision);
    revision = f.committed.revision;
    wyl_fact_offline_restore_journal_clear (&f.committed);
  }
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, >, revision);
  g_assert_cmpuint (f.committed.version, ==,
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION);
  revision = f.committed.revision;
  WylPolicyOfflineRestoreRecord *reserved = NULL;
  GPtrArray *phases = NULL;
  g_assert_cmpint (wyl_policy_store_offline_restore_load (f.fixture.policy,
      session_operation, &reserved), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_tenant_restore_replacement_phases_load
        (f.fixture.policy, reserved, &phases), ==, WYRELOG_E_OK);
  g_assert_cmpuint (phases->len, ==, 2);
  g_assert_cmpstr (g_ptr_array_index (phases, 0), ==, "reserved");
  g_assert_cmpstr (g_ptr_array_index (phases, 1), ==, "reserved");
  g_clear_pointer (&phases, g_ptr_array_unref);
  wyl_policy_offline_restore_record_free (reserved);
  for (guint i = 0; i < f.committed.graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (f.committed.graphs, i);
    g_assert_cmpint (graph->transition_state, ==,
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE);
  }
  wyl_fact_offline_restore_journal_clear (&f.committed);
  for (guint step = 0; step < 2; step++) {
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, revision, 0, &f.committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, ==, revision);
    g_assert_cmpuint (f.committed.version, ==,
        WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION);
    wyl_fact_offline_restore_journal_clear (&f.committed);
    g_assert_cmpint (wyl_policy_store_offline_restore_load (f.fixture.policy,
        session_operation, &reserved), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_tenant_restore_replacement_phases_load
          (f.fixture.policy, reserved, &phases), ==, WYRELOG_E_OK);
    g_assert_cmpstr (g_ptr_array_index (phases, step), ==,
        "companion_synced");
    if (step == 0)
      g_assert_cmpstr (g_ptr_array_index (phases, 1), ==, "reserved");
    g_clear_pointer (&phases, g_ptr_array_unref);
    wyl_policy_offline_restore_record_free (reserved);
    reserved = NULL;
  }
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.version, ==,
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION);
  revision = f.committed.revision;
  wyl_fact_offline_restore_journal_clear (&f.committed);
#ifdef WYL_TEST_HANDLE_SEAMS
  wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
      WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &f.committed), ==, WYRELOG_E_IO);
  g_assert_null (f.committed.graphs);
  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
  g_autofree gchar *selected_policy_path = g_build_filename (f.fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (selected_policy_path,
      &f.fixture.policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &f.committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, >, revision);
  revision = f.committed.revision;
  wyl_fact_offline_restore_journal_clear (&f.committed);
#endif
  for (guint step = 0; step < 2; step++) {
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, revision, 0, &f.committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, >, revision);
    revision = f.committed.revision;
    wyl_fact_offline_restore_journal_clear (&f.committed);
  }
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.version, ==,
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION);
  revision = f.committed.revision;
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_resume_one
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, revision, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, revision);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  if (schema_transition) {
    for (guint i = 0; i < G_N_ELEMENTS (graphs); i++) {
      WylPolicyRelationActivationRecord *active = NULL;
      g_assert_cmpint (wyl_policy_store_read_relation_activation
            (f.fixture.policy, "tenant-a", graphs[i], "backup", "items",
          &active), ==, WYRELOG_E_OK);
      g_assert_true (active->has_active_schema_version);
      g_assert_cmpuint (active->active_schema_version, ==, 1);
      wyl_policy_relation_activation_record_free (active);
    }
  }
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static void
test_tenant_commit_sync_staged_first (gconstpointer data)
{
  gboolean pending = g_strcmp0 (data, "pending") == 0;
  gboolean ambiguous_begin = g_strcmp0 (data, "begin-response") == 0;
  gboolean ambiguous_complete = g_strcmp0 (data, "complete-response") == 0;
  gboolean sibling_unknown = g_strcmp0 (data, "sibling-unknown") == 0;
  gboolean sibling_schema = g_strcmp0 (data, "sibling-schema") == 0;
  gboolean sibling_foreign = g_strcmp0 (data, "sibling-foreign") == 0;
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  TenantPreflightTestJob job = { &f, 3, f.capture.manifest };
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "alpha", 5, 0, &f.committed), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "zeta", 6, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&f.committed,
      WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 8);
  import_restore_journal_for_test (f.fixture.policy, &f.committed);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_autofree gchar *foreign = NULL;
  if (sibling_schema) {
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        "UPDATE fact_namespaces SET visibility=1-visibility "
        "WHERE tenant_id='tenant-a' AND graph_id='zeta';",
        NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (wyl_policy_store_get_db
          (f.fixture.policy)), >, 0);
  }
  if (sibling_foreign) {
    foreign = graph_file_path (&f.fixture, "zeta", "foreign");
    g_assert_true (g_file_set_contents (foreign, "foreign", -1, NULL));
  }
  if (sibling_schema || sibling_foreign) {
    g_assert_cmpint
      (wyl_fact_offline_restore_tenant_commit_sync_staged_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, "alpha", 8, 0, &f.committed), ==,
        WYRELOG_E_POLICY);
    g_assert_null (f.committed.graphs);
    g_auto (WylFactOfflineRestoreJournal) unchanged = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (f.fixture.policy, session_operation, &unchanged), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (unchanged.revision, ==, 8);
  }
  if (sibling_schema)
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        "UPDATE fact_namespaces SET visibility=1-visibility "
        "WHERE tenant_id='tenant-a' AND graph_id='zeta';",
        NULL, NULL, NULL), ==, SQLITE_OK);
  if (sibling_foreign)
    g_assert_cmpint (g_remove (foreign), ==, 0);
  guint64 revision = 8;
  if (pending || ambiguous_begin || ambiguous_complete || sibling_unknown) {
    WylPolicyOfflineRestoreRecord *raw = NULL, *begun = NULL;
    WylPolicyOfflineRestoreStoreResult result =
        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    guint calls = 0;
    g_assert_cmpint (wyl_policy_store_offline_restore_load
          (f.fixture.policy, session_operation, &raw), ==, WYRELOG_E_OK);
#ifdef WYL_TEST_HANDLE_SEAMS
    if (ambiguous_begin)
      wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
          WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
#endif
    wyrelog_error_t begin_rc =
        wyl_policy_store_tenant_restore_sync_staged_step_with_effect
          (f.fixture.policy, raw, "alpha",
            WYL_POLICY_TENANT_RESTORE_SYNC_STAGED_BEGIN,
            tenant_sync_test_begin_effect, &calls, &result, &begun);
    g_assert_cmpint (begin_rc, ==,
        ambiguous_begin ? WYRELOG_E_IO : WYRELOG_E_OK);
    if (!ambiguous_begin)
      g_assert_cmpint (result, ==,
          WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED);
    g_assert_cmpuint (calls, ==, 1);
    if (ambiguous_begin)
      g_assert_null (begun);
    else
      g_assert_nonnull (begun);
    revision = 9;
    wyl_policy_offline_restore_record_free (begun);
    wyl_policy_offline_restore_record_free (raw);
    if (ambiguous_begin) {
      g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
      g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
              "policy.db", NULL);
      g_assert_cmpint (wyl_policy_store_open (policy_path,
          &f.fixture.policy), ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
          WYRELOG_E_OK);
    }
  }
  if (sibling_unknown) {
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_staged_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, "zeta", revision, 0, &f.committed), ==,
        WYRELOG_E_POLICY);
    g_assert_null (f.committed.graphs);
    g_auto (WylFactOfflineRestoreJournal) unchanged = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (f.fixture.policy, session_operation, &unchanged), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (unchanged.revision, ==, revision);
  }
 #ifdef WYL_TEST_HANDLE_SEAMS
  if (ambiguous_complete)
    wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
        WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
 #endif
  wyrelog_error_t sync_rc =
      wyl_fact_offline_restore_tenant_commit_sync_staged_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          session_operation, "alpha", revision, 0, &f.committed);
  g_assert_cmpint (sync_rc, ==,
      ambiguous_complete ? WYRELOG_E_IO : WYRELOG_E_OK);
  if (ambiguous_complete) {
    g_assert_null (f.committed.graphs);
    g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
    g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
            "policy.db", NULL);
    g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (f.fixture.policy, session_operation, &f.committed), ==,
        WYRELOG_E_OK);
  }
  g_assert_cmpuint (f.committed.revision, ==, 10);
  const WylFactOfflineRestoreJournalGraph *alpha =
      g_ptr_array_index (f.committed.graphs, 0);
  const WylFactOfflineRestoreJournalGraph *zeta =
      g_ptr_array_index (f.committed.graphs, 1);
  g_assert_cmpint (alpha->transition_state, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY);
  g_assert_cmpint (alpha->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN);
  g_assert_cmpint (alpha->attempt, ==,
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED);
  g_assert_cmpint (zeta->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED);
  g_assert_cmpint (zeta->attempt, ==,
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static wyrelog_error_t fail_retain_once (const gchar *point,
    gpointer user_data);

static wyrelog_error_t
tenant_reserve_test_effect (GBytes *journal, const GPtrArray *uuids,
    const GPtrArray *replacements, gpointer user_data)
{
  g_assert_nonnull (journal);
  g_assert_cmpuint (uuids->len, ==, 2);
  g_assert_cmpuint (replacements->len, ==, 2);
  (*(guint *) user_data)++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reject_tenant_finalize_effect (GBytes *journal, gpointer user_data)
{
  g_assert_nonnull (journal);
  (*(guint *) user_data)++;
  return WYRELOG_E_POLICY;
}

static wyrelog_error_t
accept_tenant_promotion_effect (GBytes *journal, gpointer user_data)
{
  g_assert_nonnull (journal);
  (*(guint *) user_data)++;
  return WYRELOG_E_OK;
}

/* Import the exact post-selection SQL image to exercise reopen validation
 * before the scoped tenant selection writer exists. */
static void
tenant_selected_schema_fixture (wyl_policy_store_t *store,
    const WylFactOfflineRestoreJournal *bound)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_autoptr (GBytes) before = NULL;
  g_autoptr (GBytes) selected_bytes = NULL;
  g_auto (WylFactOfflineRestoreJournal) selected = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (bound,
      &before), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (before,
      &selected), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_tenant_replacements_selected
        (&selected), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&selected,
      &selected_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (db, "BEGIN IMMEDIATE;", NULL, NULL, NULL),
      ==, SQLITE_OK);
  sqlite3_stmt *update = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "UPDATE fact_offline_restore_journals SET revision=?1,journal_blob=?2 "
      "WHERE operation_uuid=?3 AND revision=?4;", -1, &update, NULL), ==,
      SQLITE_OK);
  gsize size = 0;
  const void *bytes = g_bytes_get_data (selected_bytes, &size);
  g_assert_cmpint (sqlite3_bind_int64 (update, 1, selected.revision), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob64 (update, 2, bytes, size,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (update, 3, selected.operation_uuid, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (update, 4, bound->revision), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (update), ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_changes (db), ==, 1);
  sqlite3_finalize (update);
  for (guint i = 0; i < selected.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (selected.graphs, i);
    gchar *sql = sqlite3_mprintf
          ("DELETE FROM fact_graph_provisioning WHERE op_uuid='%q' AND "
            "phase='active';", graph->old_provisioning_uuid);
    g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (db), ==, 1);
    sqlite3_free (sql);
    sql = sqlite3_mprintf
          ("INSERT INTO fact_graph_provisioning (op_uuid,tenant_id,graph_id,"
            "store_uuid,stage_basename,expected_lifecycle_generation,"
            "expected_reconciliation_generation,phase,attempt,created_at,"
            "updated_at) VALUES('%q','%q','%q','%q',"
            "'provision-%q.sqlite',%lld,%lld,'restore_selected',0,"
            "unixepoch(),unixepoch());",
            graph->replacement_provisioning_uuid, selected.tenant_id,
            graph->graph_id, graph->store_uuid,
            graph->replacement_provisioning_uuid,
            (long long) graph->destination_lifecycle_generation,
            (long long) graph->destination_reconciliation_generation);
    g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (db), ==, 1);
    sqlite3_free (sql);
  }
  sqlite3_stmt *guard = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "SELECT sql FROM sqlite_master WHERE "
      "name='fact_tenant_restore_replacement_update_guard';",
      -1, &guard, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
  g_autofree gchar *guard_sql = g_strdup
        ((const gchar *) sqlite3_column_text (guard, 0));
  sqlite3_finalize (guard);
  g_assert_cmpint (sqlite3_exec (db,
      "DROP TRIGGER fact_tenant_restore_replacement_update_guard;",
      NULL, NULL, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (db,
      "UPDATE fact_tenant_restore_replacements SET "
      "phase='selected_pending_cleanup' WHERE phase='companion_synced';",
      NULL, NULL, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_changes (db), ==, selected.graphs->len);
  g_assert_cmpint (sqlite3_exec (db, guard_sql, NULL, NULL, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (db, "COMMIT;", NULL, NULL, NULL), ==,
      SQLITE_OK);
}

/* Import the all-graph terminal SQL image before the scoped v8 writer exists. */
static void
tenant_published_schema_fixture (wyl_policy_store_t *store,
    const WylFactOfflineRestoreJournal *selected)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_autoptr (GBytes) before = NULL;
  g_autoptr (GBytes) published_bytes = NULL;
  g_auto (WylFactOfflineRestoreJournal) published = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (selected,
      &before), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (before,
      &published), ==, WYRELOG_E_OK);
  for (guint i = 0; i < published.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (published.graphs, i);
    g_autofree gchar *graph_id = g_strdup (graph->graph_id);
    g_assert_cmpint (wyl_fact_offline_restore_journal_begin_tenant_selected_finalize
          (&published, graph_id), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_complete_tenant_selected_finalize
          (&published, graph_id), ==, WYRELOG_E_OK);
  }
  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_tenant_selected_published
        (&published), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&published,
      &published_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (db, "BEGIN IMMEDIATE;", NULL, NULL, NULL),
      ==, SQLITE_OK);
  sqlite3_stmt *journal_guard = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "SELECT sql FROM sqlite_master WHERE "
      "name='fact_offline_restore_journal_update_guard';",
      -1, &journal_guard, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (journal_guard), ==, SQLITE_ROW);
  g_autofree gchar *journal_guard_sql = g_strdup
        ((const gchar *) sqlite3_column_text (journal_guard, 0));
  sqlite3_finalize (journal_guard);
  g_assert_cmpint (sqlite3_exec (db,
      "DROP TRIGGER fact_offline_restore_journal_update_guard;",
      NULL, NULL, NULL), ==, SQLITE_OK);
  sqlite3_stmt *update = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "UPDATE fact_offline_restore_journals SET revision=?1,journal_blob=?2 "
      "WHERE operation_uuid=?3 AND revision=?4;", -1, &update, NULL), ==,
      SQLITE_OK);
  gsize size = 0;
  const void *bytes = g_bytes_get_data (published_bytes, &size);
  g_assert_cmpint (sqlite3_bind_int64 (update, 1, published.revision), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob64 (update, 2, bytes, size,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (update, 3, published.operation_uuid, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (update, 4, selected->revision), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (update), ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_changes (db), ==, 1);
  sqlite3_finalize (update);
  g_assert_cmpint (sqlite3_exec (db, journal_guard_sql,
      NULL, NULL, NULL), ==, SQLITE_OK);
  for (guint i = 0; i < published.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (published.graphs, i);
    gchar *sql = sqlite3_mprintf
          ("UPDATE fact_graphs SET lifecycle_state='active',sealed=0,"
            "lifecycle_generation=lifecycle_generation+1 "
            "WHERE tenant_id='%q' AND graph_id='%q' AND "
            "lifecycle_state='sealed';", published.tenant_id,
            graph->graph_id);
    g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (db), ==, 1);
    sqlite3_free (sql);
    sql = sqlite3_mprintf
          ("UPDATE fact_graph_provisioning SET phase='active' "
            "WHERE op_uuid='%q' AND phase='restore_selected';",
            graph->replacement_provisioning_uuid);
    g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (db), ==, 1);
    sqlite3_free (sql);
  }
  sqlite3_stmt *guard = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "SELECT sql FROM sqlite_master WHERE "
      "name='fact_tenant_restore_replacement_update_guard';",
      -1, &guard, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
  g_autofree gchar *guard_sql = g_strdup
        ((const gchar *) sqlite3_column_text (guard, 0));
  sqlite3_finalize (guard);
  g_assert_cmpint (sqlite3_exec (db,
      "DROP TRIGGER fact_tenant_restore_replacement_update_guard;",
      NULL, NULL, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (db,
      "UPDATE fact_tenant_restore_replacements SET phase='verified' "
      "WHERE phase='selected_pending_cleanup';", NULL, NULL, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_changes (db), ==, published.graphs->len);
  g_assert_cmpint (sqlite3_exec (db, guard_sql, NULL, NULL, NULL), ==,
      SQLITE_OK);
  gchar *sql = sqlite3_mprintf
        ("UPDATE tenants SET lifecycle_state='unsealing',"
          "lifecycle_generation=lifecycle_generation+1 "
          "WHERE tenant_id='%q' AND lifecycle_state='sealed';"
          "UPDATE tenants SET lifecycle_state='active',sealed=0,"
          "sealed_generation=sealed_generation+1,"
          "lifecycle_generation=lifecycle_generation+1 "
          "WHERE tenant_id='%q' AND lifecycle_state='unsealing';"
          "DELETE FROM fact_offline_restore_tenant_claims "
          "WHERE tenant_id='%q' AND operation_uuid='%q';",
          published.tenant_id, published.tenant_id,
          published.tenant_id, published.operation_uuid);
  g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
  sqlite3_free (sql);
  g_assert_cmpint (sqlite3_exec (db, "COMMIT;", NULL, NULL, NULL), ==,
      SQLITE_OK);
}

static void
tenant_published_tamper_guarded (sqlite3 *db, const gchar *guard_name,
    const gchar *mutation)
{
  gchar *query = sqlite3_mprintf
        ("SELECT sql FROM sqlite_master WHERE name='%q';", guard_name);
  sqlite3_stmt *guard = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, query, -1, &guard, NULL), ==,
      SQLITE_OK);
  sqlite3_free (query);
  g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
  g_autofree gchar *guard_sql = g_strdup
        ((const gchar *) sqlite3_column_text (guard, 0));
  sqlite3_finalize (guard);
  query = sqlite3_mprintf ("DROP TRIGGER \"%w\";", guard_name);
  g_assert_cmpint (sqlite3_exec (db, query, NULL, NULL, NULL), ==, SQLITE_OK);
  sqlite3_free (query);
  g_assert_cmpint (sqlite3_exec (db, mutation, NULL, NULL, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (db, guard_sql, NULL, NULL, NULL), ==,
      SQLITE_OK);
}

/* Model a later, fully published tenant operation directly in policy. The
 * filesystem publication path is covered by the driver tests above; this
 * fixture exercises reopen validation of immutable historical authority. */
static void
tenant_published_successor_fixture (wyl_policy_store_t *store,
    const WylFactOfflineRestoreJournal *first, guint sequence,
    guint forged_predecessors, gboolean selected)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_autoptr (GBytes) first_bytes = NULL;
  g_autoptr (GBytes) next_bytes = NULL;
  g_auto (WylFactOfflineRestoreJournal) next = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (first,
      &first_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (first_bytes,
      &next), ==, WYRELOG_E_OK);
  g_free (next.operation_uuid);
  next.operation_uuid = g_strdup_printf
        ("00000000-0000-7000-8000-0000000000%c1",
          sequence == 1 ? 'b' : 'c');
  next.source_tenant_lifecycle_generation =
      first->destination_tenant_lifecycle_generation + 2;
  next.destination_tenant_lifecycle_generation =
      first->destination_tenant_lifecycle_generation + 4;
  for (guint i = 0; i < next.graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (next.graphs, i);
    g_free (graph->old_provisioning_uuid);
    graph->old_provisioning_uuid =
        g_strdup (graph->replacement_provisioning_uuid);
    if (i < forged_predecessors) {
      g_free (graph->old_provisioning_uuid);
      graph->old_provisioning_uuid = g_strdup_printf
            ("00000000-0000-7000-8000-0000000000d%u", i + 2);
    }
    g_free (graph->replacement_provisioning_uuid);
    graph->replacement_provisioning_uuid = g_strdup_printf
          ("00000000-0000-7000-8000-0000000000%c%u",
            sequence == 1 ? 'b' : 'c', i + 2);
    graph->destination_lifecycle_generation += 3;
  }
  if (selected) {
    next.version = WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION;
    next.revision--;
    next.policy_generation_published = FALSE;
    next.lifecycle_handoff_complete = FALSE;
  }
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&next,
      &next_bytes), ==, WYRELOG_E_OK);
  const gchar *guards[] = {
    "fact_graph_provisioning_insert_guard",
    "fact_graph_authority_update_guard",
    "tenant_authority_update_guard",
    "fact_tenant_restore_replacement_insert_guard",
  };
  gchar *guard_sql[G_N_ELEMENTS (guards)] = { 0 };
  g_assert_cmpint (sqlite3_exec (db, "BEGIN IMMEDIATE;", NULL, NULL,
      NULL), ==, SQLITE_OK);
  for (guint i = 0; i < G_N_ELEMENTS (guards); i++) {
    gchar *sql = sqlite3_mprintf
          ("SELECT sql FROM sqlite_master WHERE name='%q';", guards[i]);
    sqlite3_stmt *stmt = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt,
        NULL), ==, SQLITE_OK);
    sqlite3_free (sql);
    g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
    guard_sql[i] = g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
    sqlite3_finalize (stmt);
    sql = sqlite3_mprintf ("DROP TRIGGER \"%w\";", guards[i]);
    g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
    sqlite3_free (sql);
  }
  sqlite3_stmt *insert = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "INSERT INTO fact_offline_restore_journals("
      "operation_uuid,tenant_id,scope,selected_graph_id,revision,"
      "manifest_sha256,graph_count,journal_blob,created_at,updated_at) "
      "VALUES(?1,?2,'tenant',NULL,?3,?4,?5,?6,unixepoch(),unixepoch());",
      -1, &insert, NULL), ==, SQLITE_OK);
  gsize bytes_len = 0;
  const void *bytes = g_bytes_get_data (next_bytes, &bytes_len);
  g_assert_cmpint (sqlite3_bind_text (insert, 1, next.operation_uuid, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (insert, 2, next.tenant_id, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (insert, 3, next.revision), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob (insert, 4, next.manifest_sha256,
      sizeof next.manifest_sha256, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int (insert, 5, next.graphs->len), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob64 (insert, 6, bytes, bytes_len,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (insert), ==, SQLITE_DONE);
  sqlite3_finalize (insert);
  for (guint i = 0; i < next.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *previous_graph =
        g_ptr_array_index (first->graphs, i);
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (next.graphs, i);
    gchar *sql = sqlite3_mprintf
          ("DELETE FROM fact_graph_provisioning WHERE op_uuid='%q';"
            "UPDATE fact_graphs SET lifecycle_state='%q',sealed=%d,"
            "lifecycle_generation=%lld "
            "WHERE tenant_id='%q' AND graph_id='%q';"
            "INSERT INTO fact_graph_provisioning("
            "op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
            "expected_lifecycle_generation,"
            "expected_reconciliation_generation,phase,attempt,created_at,"
            "updated_at) VALUES('%q','%q','%q','%q',"
            "'provision-%q.sqlite',%lld,%lld,'%q',0,unixepoch(),"
            "unixepoch());"
            "INSERT INTO fact_tenant_restore_replacements("
            "restore_operation_uuid,tenant_id,graph_id,replacement_uuid,"
            "old_provisioning_uuid,store_uuid,"
            "tenant_lifecycle_generation,tenant_reconciliation_generation,"
            "graph_lifecycle_generation,graph_reconciliation_generation,"
            "journal_revision,companion_basename,phase,created_at,updated_at) "
            "VALUES('%q','%q','%q','%q','%q','%q',%lld,%lld,%lld,%lld,%lld,"
            "'provision-%q.sqlite','%q',unixepoch(),unixepoch());",
            previous_graph->replacement_provisioning_uuid,
            selected ? "sealed" : "active", selected ? 1 : 0,
            (long long) graph->destination_lifecycle_generation
            + (selected ? 0 : 1),
            next.tenant_id, graph->graph_id,
            graph->replacement_provisioning_uuid, next.tenant_id,
            graph->graph_id, graph->store_uuid,
            graph->replacement_provisioning_uuid,
            (long long) graph->destination_lifecycle_generation,
            (long long) graph->destination_reconciliation_generation,
            selected ? "restore_selected" : "active",
            next.operation_uuid, next.tenant_id, graph->graph_id,
            graph->replacement_provisioning_uuid,
            graph->old_provisioning_uuid, graph->store_uuid,
            (long long) next.destination_tenant_lifecycle_generation,
            (long long) next.destination_tenant_reconciliation_generation,
            (long long) graph->destination_lifecycle_generation,
            (long long) graph->destination_reconciliation_generation,
            (long long) next.revision - (selected ? 5 : 6),
            graph->replacement_provisioning_uuid,
            selected ? "selected_pending_cleanup" : "verified");
    int fixture_rc = sqlite3_exec (db, sql, NULL, NULL, NULL);
    if (fixture_rc != SQLITE_OK)
      g_error ("successor fixture SQL: %s; old=%s new=%s",
          sqlite3_errmsg (db), graph->old_provisioning_uuid,
          graph->replacement_provisioning_uuid);
    sqlite3_free (sql);
  }
  gchar *sql = sqlite3_mprintf
        ("UPDATE tenants SET lifecycle_state='%q',sealed=%d,"
          "lifecycle_generation=%lld,"
          "sealed_generation=sealed_generation+1 WHERE tenant_id='%q';",
          selected ? "sealed" : "active", selected ? 1 : 0,
          (long long) next.destination_tenant_lifecycle_generation
          + (selected ? 0 : 2),
          next.tenant_id);
  g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
  sqlite3_free (sql);
  if (selected) {
    sql = sqlite3_mprintf
          ("INSERT INTO fact_offline_restore_tenant_claims(tenant_id,"
            "operation_uuid) VALUES('%q','%q');", next.tenant_id,
            next.operation_uuid);
    g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
    sqlite3_free (sql);
  }
  for (guint i = 0; i < G_N_ELEMENTS (guards); i++) {
    g_assert_cmpint (sqlite3_exec (db, guard_sql[i], NULL, NULL,
        NULL), ==, SQLITE_OK);
    g_free (guard_sql[i]);
  }
  g_assert_cmpint (sqlite3_exec (db, "COMMIT;", NULL, NULL, NULL), ==,
      SQLITE_OK);
}

static void
tenant_published_fork_fixture (wyl_policy_store_t *store,
    const WylFactOfflineRestoreJournal *first)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_autoptr (GBytes) original = NULL;
  g_autoptr (GBytes) encoded = NULL;
  g_auto (WylFactOfflineRestoreJournal) fork = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (first,
      &original), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (original,
      &fork), ==, WYRELOG_E_OK);
  g_free (fork.operation_uuid);
  fork.operation_uuid = g_strdup ("00000000-0000-7000-8000-0000000000c1");
  fork.destination_tenant_lifecycle_generation += 4;
  for (guint i = 0; i < fork.graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (fork.graphs, i);
    g_free (graph->old_provisioning_uuid);
    graph->old_provisioning_uuid =
        g_strdup (graph->replacement_provisioning_uuid);
    g_free (graph->replacement_provisioning_uuid);
    graph->replacement_provisioning_uuid = g_strdup_printf
          ("00000000-0000-7000-8000-0000000000c%u", i + 2);
    graph->destination_lifecycle_generation += 3;
  }
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&fork,
      &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (db, "BEGIN IMMEDIATE;", NULL, NULL,
      NULL), ==, SQLITE_OK);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "INSERT INTO fact_offline_restore_journals("
      "operation_uuid,tenant_id,scope,selected_graph_id,revision,"
      "manifest_sha256,graph_count,journal_blob,created_at,updated_at) "
      "VALUES(?1,?2,'tenant',NULL,?3,?4,?5,?6,unixepoch(),unixepoch());",
      -1, &stmt, NULL), ==, SQLITE_OK);
  gsize length = 0;
  const void *bytes = g_bytes_get_data (encoded, &length);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, fork.operation_uuid, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 2, fork.tenant_id, -1,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (stmt, 3, fork.revision), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob (stmt, 4, fork.manifest_sha256,
      sizeof fork.manifest_sha256, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int (stmt, 5, fork.graphs->len), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob64 (stmt, 6, bytes, length,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "SELECT sql FROM sqlite_master WHERE "
      "name='fact_tenant_restore_replacement_insert_guard';",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_autofree gchar *guard_sql = g_strdup
        ((const gchar *) sqlite3_column_text (stmt, 0));
  sqlite3_finalize (stmt);
  g_assert_cmpint (sqlite3_exec (db,
      "DROP TRIGGER fact_tenant_restore_replacement_insert_guard;",
      NULL, NULL, NULL), ==, SQLITE_OK);
  for (guint i = 0; i < fork.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (fork.graphs, i);
    gchar *sql = sqlite3_mprintf
          ("INSERT INTO fact_tenant_restore_replacements("
            "restore_operation_uuid,tenant_id,graph_id,replacement_uuid,"
            "old_provisioning_uuid,store_uuid,"
            "tenant_lifecycle_generation,tenant_reconciliation_generation,"
            "graph_lifecycle_generation,graph_reconciliation_generation,"
            "journal_revision,companion_basename,phase,created_at,updated_at) "
            "VALUES('%q','%q','%q','%q','%q','%q',%lld,%lld,%lld,%lld,%lld,"
            "'provision-%q.sqlite','verified',unixepoch(),unixepoch());",
            fork.operation_uuid, fork.tenant_id, graph->graph_id,
            graph->replacement_provisioning_uuid,
            graph->old_provisioning_uuid, graph->store_uuid,
            (long long) fork.destination_tenant_lifecycle_generation,
            (long long) fork.destination_tenant_reconciliation_generation,
            (long long) graph->destination_lifecycle_generation,
            (long long) graph->destination_reconciliation_generation,
            (long long) fork.revision - 6,
            graph->replacement_provisioning_uuid);
    g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
    sqlite3_free (sql);
  }
  g_assert_cmpint (sqlite3_exec (db, guard_sql, NULL, NULL, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (db, "COMMIT;", NULL, NULL, NULL), ==,
      SQLITE_OK);
}

#ifdef WYL_TEST_HANDLE_SEAMS
typedef struct
{
  SessionFixture *fixture;
  gchar *intruder;
} TenantReservationIntruder;

static wyrelog_error_t
tenant_reserve_intrude (const gchar *graph_id, const gchar *replacement_uuid,
    gpointer data)
{
  TenantReservationIntruder *intruder = data;
  if (g_strcmp0 (graph_id, "alpha") != 0)
    return WYRELOG_E_OK;
  g_autofree gchar *basename = g_strdup_printf ("provision-%s.sqlite",
          replacement_uuid);
  intruder->intruder = graph_file_path (&intruder->fixture->fixture,
          graph_id, basename);
  return g_file_set_contents (intruder->intruder, "foreign", -1, NULL) ?
         WYRELOG_E_OK : WYRELOG_E_IO;
}
#endif

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t fail_companion_linked_once
  (const gchar *point, gpointer user_data);
#endif
static void
test_tenant_commit_sync_staged_both (gconstpointer data)
{
  const gchar *mode = data;
  gboolean reverse = g_str_equal (mode, "reverse")
      || g_str_equal (mode, "retain-reverse")
      || g_str_equal (mode, "retain-sync-reverse")
      || g_str_equal (mode, "retain-sync-dir-reverse")
      || g_str_equal (mode, "retain-sync-dir-publish-reverse")
      || g_str_equal (mode, "retain-sync-dir-publish-sync-reverse");
  const gchar *first = reverse ? "zeta" : "alpha";
  const gchar *second = reverse ? "alpha" : "zeta";
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  TenantPreflightTestJob job = { &f, 3, f.capture.manifest };
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "alpha", 5, 0, &f.committed), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_bind_provisioned_old_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, "zeta", 6, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&f.committed,
      WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT), ==, WYRELOG_E_OK);
  import_restore_journal_for_test (f.fixture.policy, &f.committed);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_staged_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, first, 8, 0, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 10);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
      WYRELOG_E_OK);
  guint64 revision = 10;
  if (g_str_equal (mode, "pending-second")
      || g_str_equal (mode, "restart-pending-second")) {
    WylPolicyOfflineRestoreRecord *raw = NULL, *begun = NULL;
    WylPolicyOfflineRestoreStoreResult result =
        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
    guint calls = 0;
    g_assert_cmpint (wyl_policy_store_offline_restore_load
          (f.fixture.policy, session_operation, &raw), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_tenant_restore_sync_staged_step_with_effect
          (f.fixture.policy, raw, second,
        WYL_POLICY_TENANT_RESTORE_SYNC_STAGED_BEGIN,
        tenant_sync_test_begin_effect, &calls, &result, &begun), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (calls, ==, 1);
    g_assert_cmpint (result, ==,
        WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED);
    revision = 11;
    wyl_policy_offline_restore_record_free (begun);
    wyl_policy_offline_restore_record_free (raw);
  }
  g_autofree gchar *foreign = NULL;
  g_autofree gchar *stage = NULL;
  guint8 original = 0;
  if (g_str_equal (mode, "completed-sibling-foreign")) {
    foreign = graph_file_path (&f.fixture, first, "foreign");
    g_assert_true (g_file_set_contents (foreign, "foreign", -1, NULL));
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_staged_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, second, revision, 0, &f.committed), ==,
        WYRELOG_E_POLICY);
    g_assert_null (f.committed.graphs);
    g_assert_cmpint (g_remove (foreign), ==, 0);
  }
  if (g_str_equal (mode, "completed-sibling-stage-content")) {
    stage = session_stage_path (&f, first);
    gint fd = g_open (stage, O_RDWR, 0);
    g_assert_cmpint (fd, >=, 0);
    g_assert_cmpint (read (fd, &original, 1), ==, 1);
    guint8 changed = original ^ 1;
    g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
    g_assert_cmpint (write (fd, &changed, 1), ==, 1);
    g_assert_cmpint (fsync (fd), ==, 0);
    g_assert_cmpint (close (fd), ==, 0);
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_staged_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, second, revision, 0, &f.committed), ==,
        WYRELOG_E_POLICY);
    g_assert_null (f.committed.graphs);
    fd = g_open (stage, O_RDWR, 0);
    g_assert_cmpint (fd, >=, 0);
    g_assert_cmpint (write (fd, &original, 1), ==, 1);
    g_assert_cmpint (fsync (fd), ==, 0);
    g_assert_cmpint (close (fd), ==, 0);
  }
  if (g_str_equal (mode, "stale-second")) {
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_staged_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, second, revision - 1, 0, &f.committed), ==,
        WYRELOG_E_BUSY);
    g_assert_null (f.committed.graphs);
  }
  if (g_str_equal (mode, "restart-second")
      || g_str_equal (mode, "restart-pending-second")) {
    g_clear_pointer (&f.fixture.runtime,
        wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime),
        ==, WYRELOG_E_OK);
  }
  g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_staged_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      session_operation, second, revision, 0, &f.committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 12);
  for (guint i = 0; i < f.committed.graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (f.committed.graphs, i);
    g_assert_cmpint (graph->transition_state, ==,
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY);
    g_assert_cmpint (graph->next_op, ==,
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN);
    g_assert_cmpint (graph->attempt, ==,
        WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED);
  }
  if (g_str_has_prefix (mode, "retain-")) {
    if (g_str_equal (mode, "retain-after-begin")
        || g_str_equal (mode, "retain-after-rename")) {
      const gchar *failure = g_str_equal (mode, "retain-after-begin")
          ? "restore-retain-after-begin" : "restore-retain-after-rename";
      wyl_fact_offline_restore_tenant_commit_retain_set_checkpoint_for_test
        (fail_retain_once, &failure);
      g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_retain_run
            (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          session_operation, first, 12, 0, &f.committed), ==, WYRELOG_E_IO);
      g_assert_null (failure);
      g_assert_null (f.committed.graphs);
      wyl_fact_offline_restore_tenant_commit_retain_set_checkpoint_for_test
        (NULL, NULL);
      g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
      g_assert_cmpint (wyl_policy_store_open (policy_path,
          &f.fixture.policy), ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
          WYRELOG_E_OK);
      if (g_str_equal (mode, "retain-after-begin")) {
        g_clear_pointer (&f.fixture.runtime,
            wyl_fact_graph_runtime_manager_unref);
        g_assert_cmpint (wyl_fact_graph_runtime_manager_new
              (&f.fixture.runtime), ==, WYRELOG_E_OK);
      }
      WylFactOfflineRestoreJournal pending = { 0 };
      g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
            (f.fixture.policy, session_operation, &pending), ==,
          WYRELOG_E_OK);
      g_assert_cmpuint (pending.revision, ==, 13);
      const WylFactOfflineRestoreJournalGraph *pending_graph =
          g_ptr_array_index (pending.graphs, reverse ? 1 : 0);
      g_assert_cmpint (pending_graph->attempt, ==,
          WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
      wyl_fact_offline_restore_journal_clear (&pending);
      if (g_str_equal (mode, "retain-after-rename")) {
        g_autofree gchar *name = g_strdup_printf
              ("restore-%s.duckdb.superseded", session_operation);
        g_autofree gchar *rollback = graph_file_path (&f.fixture, first, name);
        g_autofree gchar *parked = graph_file_path (&f.fixture, first,
                "parked-rollback-test");
        g_assert_cmpint (g_rename (rollback, parked), ==, 0);
        g_assert_true (g_file_set_contents (rollback, "foreign", -1, NULL));
        g_assert_cmpint (g_chmod (rollback, 0600), ==, 0);
        g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_retain_run
              (f.fixture.policy, f.fixture.root, f.fixture.runtime,
            session_operation, first, 13, 0, &f.committed), !=,
            WYRELOG_E_OK);
        g_assert_null (f.committed.graphs);
        g_assert_cmpint (g_remove (rollback), ==, 0);
        g_assert_cmpint (g_rename (parked, rollback), ==, 0);
      }
    }
    wyl_fact_offline_restore_journal_clear (&f.committed);
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_retain_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, first,
        g_str_equal (mode, "retain-after-begin")
        || g_str_equal (mode, "retain-after-rename") ? 13 : 12,
        0, &f.committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, ==, 14);
    wyl_fact_offline_restore_journal_clear (&f.committed);
    g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_retain_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
        session_operation, second, 14, 0, &f.committed), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, ==, 16);
    for (guint i = 0; i < f.committed.graphs->len; i++) {
      const WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (f.committed.graphs, i);
      g_assert_cmpint (graph->transition_state, ==,
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED);
      g_assert_cmpint (graph->next_op, ==,
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE);
      g_assert_cmpint (graph->attempt, ==,
          WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED);
    }
    if (g_str_has_prefix (mode, "retain-sync-")) {
      guint64 sync_revision = 16;
      if (g_str_equal (mode, "retain-sync-after-begin")
          || g_str_equal (mode, "retain-sync-after-fsync")) {
        const gchar *failure = g_str_equal (mode, "retain-sync-after-begin")
            ? "restore-sync-rollback-after-begin"
            : "restore-sync-rollback-after-fsync";
        wyl_fact_offline_restore_tenant_commit_sync_rollback_set_checkpoint_for_test
          (fail_retain_once, &failure);
        wyl_fact_offline_restore_journal_clear (&f.committed);
        g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_rollback_run
              (f.fixture.policy, f.fixture.root, f.fixture.runtime,
            session_operation, first, 16, 0, &f.committed), ==,
            WYRELOG_E_IO);
        g_assert_null (failure);
        g_assert_null (f.committed.graphs);
        wyl_fact_offline_restore_tenant_commit_sync_rollback_set_checkpoint_for_test
          (NULL, NULL);
        g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
        g_assert_cmpint (wyl_policy_store_open (policy_path,
            &f.fixture.policy), ==, WYRELOG_E_OK);
        g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy),
            ==, WYRELOG_E_OK);
        WylFactOfflineRestoreJournal pending = { 0 };
        g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
              (f.fixture.policy, session_operation, &pending), ==,
            WYRELOG_E_OK);
        g_assert_cmpuint (pending.revision, ==, 17);
        const WylFactOfflineRestoreJournalGraph *pending_graph =
            g_ptr_array_index (pending.graphs, 0);
        g_assert_cmpint (pending_graph->attempt, ==,
            WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
        wyl_fact_offline_restore_journal_clear (&pending);
        if (g_str_equal (mode, "retain-sync-after-begin")) {
          g_autofree gchar *name = g_strdup_printf
                ("restore-%s.duckdb.superseded", session_operation);
          g_autofree gchar *rollback = graph_file_path (&f.fixture, first,
                  name);
          g_autofree gchar *parked = graph_file_path (&f.fixture, first,
                  "parked-sync-rollback-test");
          g_assert_cmpint (g_rename (rollback, parked), ==, 0);
          g_assert_true (g_file_set_contents (rollback, "foreign", -1,
              NULL));
          g_assert_cmpint (g_chmod (rollback, 0600), ==, 0);
          g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_rollback_run
                (f.fixture.policy, f.fixture.root, f.fixture.runtime,
              session_operation, first, 17, 0, &f.committed), !=,
              WYRELOG_E_OK);
          g_assert_null (f.committed.graphs);
          g_assert_cmpint (g_remove (rollback), ==, 0);
          g_assert_cmpint (g_rename (parked, rollback), ==, 0);
        }
        sync_revision = 17;
      }
      wyl_fact_offline_restore_journal_clear (&f.committed);
      g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_rollback_run
            (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          session_operation, first, sync_revision, 0, &f.committed), ==,
          WYRELOG_E_OK);
      g_assert_cmpuint (f.committed.revision, ==, 18);
      wyl_fact_offline_restore_journal_clear (&f.committed);
      g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_rollback_run
            (f.fixture.policy, f.fixture.root, f.fixture.runtime,
          session_operation, second, 18, 0, &f.committed), ==,
          WYRELOG_E_OK);
      g_assert_cmpuint (f.committed.revision, ==, 20);
      for (guint i = 0; i < f.committed.graphs->len; i++) {
        const WylFactOfflineRestoreJournalGraph *graph =
            g_ptr_array_index (f.committed.graphs, i);
        g_assert_cmpint (graph->transition_state, ==,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED);
        g_assert_cmpint (graph->next_op, ==,
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR);
        g_assert_cmpint (graph->attempt, ==,
            WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED);
      }
      if (g_str_has_prefix (mode, "retain-sync-dir-")) {
        guint64 dir_revision = 20;
        if (g_str_equal (mode, "retain-sync-dir-after-begin")
            || g_str_equal (mode, "retain-sync-dir-after-fsync")) {
          const gchar *failure =
              g_str_equal (mode, "retain-sync-dir-after-begin")
              ? "restore-sync-retain-dir-after-begin"
              : "restore-sync-retain-dir-after-fsync";
          wyl_fact_offline_restore_tenant_commit_sync_retain_dir_set_checkpoint_for_test
            (fail_retain_once, &failure);
          wyl_fact_offline_restore_journal_clear (&f.committed);
          g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
                (f.fixture.policy, f.fixture.root, f.fixture.runtime,
              session_operation, first, 20, 0, &f.committed), ==,
              WYRELOG_E_IO);
          g_assert_null (failure);
          g_assert_null (f.committed.graphs);
          wyl_fact_offline_restore_tenant_commit_sync_retain_dir_set_checkpoint_for_test
            (NULL, NULL);
          g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
          g_assert_cmpint (wyl_policy_store_open (policy_path,
              &f.fixture.policy), ==, WYRELOG_E_OK);
          g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy),
              ==, WYRELOG_E_OK);
          WylFactOfflineRestoreJournal pending = { 0 };
          g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                (f.fixture.policy, session_operation, &pending), ==,
              WYRELOG_E_OK);
          g_assert_cmpuint (pending.revision, ==, 21);
          const WylFactOfflineRestoreJournalGraph *pending_graph =
              g_ptr_array_index (pending.graphs, 0);
          g_assert_cmpint (pending_graph->attempt, ==,
              WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
          wyl_fact_offline_restore_journal_clear (&pending);
          if (g_str_equal (mode, "retain-sync-dir-after-begin")) {
            g_autofree gchar *name = g_strdup_printf
                  ("restore-%s.duckdb.superseded", session_operation);
            g_autofree gchar *rollback = graph_file_path (&f.fixture, first,
                    name);
            g_autofree gchar *parked = graph_file_path (&f.fixture, first,
                    "parked-sync-retain-dir-test");
            g_assert_cmpint (g_rename (rollback, parked), ==, 0);
            g_assert_true (g_file_set_contents (rollback, "foreign", -1,
                NULL));
            g_assert_cmpint (g_chmod (rollback, 0600), ==, 0);
            g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
                  (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                session_operation, first, 21, 0, &f.committed), !=,
                WYRELOG_E_OK);
            g_assert_null (f.committed.graphs);
            g_assert_cmpint (g_remove (rollback), ==, 0);
            g_assert_cmpint (g_rename (parked, rollback), ==, 0);
            wyl_fact_artifact_transition_posix_set_test_fault
              (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_RETAIN_DIR_FSYNC);
            g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
                  (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                session_operation, first, 21, 0, &f.committed), !=,
                WYRELOG_E_OK);
            g_assert_null (f.committed.graphs);
            wyl_fact_artifact_transition_posix_set_test_fault
              (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
          }
          dir_revision = 21;
        }
        wyl_fact_offline_restore_journal_clear (&f.committed);
        g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
              (f.fixture.policy, f.fixture.root, f.fixture.runtime,
            session_operation, first, dir_revision, 0, &f.committed), ==,
            WYRELOG_E_OK);
        g_assert_cmpuint (f.committed.revision, ==, 22);
        wyl_fact_offline_restore_journal_clear (&f.committed);
        g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
              (f.fixture.policy, f.fixture.root, f.fixture.runtime,
            session_operation, second, 22, 0, &f.committed), ==,
            WYRELOG_E_OK);
        g_assert_cmpuint (f.committed.revision, ==, 24);
        for (guint i = 0; i < f.committed.graphs->len; i++) {
          const WylFactOfflineRestoreJournalGraph *graph =
              g_ptr_array_index (f.committed.graphs, i);
          g_assert_cmpint (graph->transition_state, ==,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED);
          g_assert_cmpint (graph->next_op, ==,
              WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH);
          g_assert_cmpint (graph->attempt, ==,
              WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED);
        }
        if (g_str_has_prefix (mode, "retain-sync-dir-publish-")) {
          gboolean interleaved = g_str_equal (mode,
                  "retain-sync-dir-publish-sync-interleaved");
          guint64 publish_revision = 24;
          if (g_str_equal (mode, "retain-sync-dir-publish-after-begin")
              || g_str_equal (mode,
              "retain-sync-dir-publish-after-rename")
              || g_str_equal (mode,
              "retain-sync-dir-publish-after-fsync")) {
            const gchar *failure = g_str_equal (mode,
                    "retain-sync-dir-publish-after-begin")
                ? "restore-publish-after-begin"
                : g_str_equal (mode,
                    "retain-sync-dir-publish-after-rename")
                ? "restore-publish-after-rename"
                : "restore-publish-after-fsync";
            wyl_fact_offline_restore_tenant_commit_publish_set_checkpoint_for_test
              (fail_retain_once, &failure);
            wyl_fact_offline_restore_journal_clear (&f.committed);
            g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_publish_run
                  (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                session_operation, first, 24, 0, &f.committed), ==,
                WYRELOG_E_IO);
            g_assert_null (failure);
            g_assert_null (f.committed.graphs);
            wyl_fact_offline_restore_tenant_commit_publish_set_checkpoint_for_test
              (NULL, NULL);
            g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
            g_assert_cmpint (wyl_policy_store_open (policy_path,
                &f.fixture.policy), ==, WYRELOG_E_OK);
            g_assert_cmpint (wyl_policy_store_create_schema
                  (f.fixture.policy), ==, WYRELOG_E_OK);
            WylFactOfflineRestoreJournal pending = { 0 };
            g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                  (f.fixture.policy, session_operation, &pending), ==,
                WYRELOG_E_OK);
            g_assert_cmpuint (pending.revision, ==, 25);
            const WylFactOfflineRestoreJournalGraph *pending_graph =
                g_ptr_array_index (pending.graphs, 0);
            g_assert_cmpint (pending_graph->attempt, ==,
                WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
            wyl_fact_offline_restore_journal_clear (&pending);
            if (g_str_equal (mode,
                "retain-sync-dir-publish-after-rename")) {
              g_autofree gchar *main = graph_file_path (&f.fixture, first,
                      "facts.duckdb");
              g_autofree gchar *parked = graph_file_path (&f.fixture, first,
                      "parked-published-main-test");
              g_assert_cmpint (g_rename (main, parked), ==, 0);
              g_assert_true (g_file_set_contents (main, "foreign", -1,
                  NULL));
              g_assert_cmpint (g_chmod (main, 0600), ==, 0);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_publish_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, first, 25, 0, &f.committed), !=,
                  WYRELOG_E_OK);
              g_assert_null (f.committed.graphs);
              g_assert_cmpint (g_remove (main), ==, 0);
              g_assert_cmpint (g_rename (parked, main), ==, 0);
            }
            if (g_str_equal (mode,
                "retain-sync-dir-publish-after-begin")) {
              wyl_fact_artifact_transition_posix_set_test_fault
                (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_PUBLISH_DIR_FSYNC);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_publish_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, first, 25, 0, &f.committed), !=,
                  WYRELOG_E_OK);
              g_assert_null (f.committed.graphs);
              wyl_fact_artifact_transition_posix_set_test_fault
                (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
            }
            publish_revision = 25;
          }
          wyl_fact_offline_restore_journal_clear (&f.committed);
          g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_publish_run
                (f.fixture.policy, f.fixture.root, f.fixture.runtime,
              session_operation, first, publish_revision, 0,
              &f.committed), ==, WYRELOG_E_OK);
          g_assert_cmpuint (f.committed.revision, ==, 26);
          wyl_fact_offline_restore_journal_clear (&f.committed);
          if (interleaved) {
            g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
                  (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                session_operation, first, 26, 0, &f.committed), ==,
                WYRELOG_E_OK);
            g_assert_cmpuint (f.committed.revision, ==, 28);
            wyl_fact_offline_restore_journal_clear (&f.committed);
          }
          if (g_str_equal (mode,
              "retain-sync-dir-publish-sibling-foreign")) {
            g_autofree gchar *foreign = graph_file_path (&f.fixture, first,
                    "foreign-published-sidecar");
            g_assert_true (g_file_set_contents (foreign, "foreign", -1,
                NULL));
            g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_publish_run
                  (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                session_operation, second, 26, 0, &f.committed), !=,
                WYRELOG_E_OK);
            g_assert_null (f.committed.graphs);
            g_assert_cmpint (g_remove (foreign), ==, 0);
          }
          g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_publish_run
                (f.fixture.policy, f.fixture.root, f.fixture.runtime,
              session_operation, second, interleaved ? 28 : 26,
              0, &f.committed), ==,
              WYRELOG_E_OK);
          g_assert_cmpuint (f.committed.revision, ==, interleaved ? 30 : 28);
          for (guint i = 0; i < f.committed.graphs->len; i++) {
            const WylFactOfflineRestoreJournalGraph *graph =
                g_ptr_array_index (f.committed.graphs, i);
            g_assert_cmpint (graph->transition_state, ==,
                interleaved && g_str_equal (graph->graph_id, first)
                ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
                : WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED);
            g_assert_cmpint (graph->next_op, ==,
                interleaved && g_str_equal (graph->graph_id, first)
                ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE
                : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR);
            g_assert_cmpint (graph->attempt, ==,
                WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED);
          }
          if (g_str_has_prefix (mode,
              "retain-sync-dir-publish-sync-")) {
            guint64 sync_publish_revision = interleaved ? 30 : 28;
            if (g_str_equal (mode,
                "retain-sync-dir-publish-sync-after-begin")
                || g_str_equal (mode,
                "retain-sync-dir-publish-sync-after-fsync")) {
              const gchar *failure = g_str_equal (mode,
                      "retain-sync-dir-publish-sync-after-begin")
                  ? "restore-sync-publish-dir-after-begin"
                  : "restore-sync-publish-dir-after-fsync";
              wyl_fact_offline_restore_tenant_commit_sync_publish_dir_set_checkpoint_for_test
                (fail_retain_once, &failure);
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, first, 28, 0, &f.committed), ==,
                  WYRELOG_E_IO);
              g_assert_null (failure);
              g_assert_null (f.committed.graphs);
              wyl_fact_offline_restore_tenant_commit_sync_publish_dir_set_checkpoint_for_test
                (NULL, NULL);
              g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
              g_assert_cmpint (wyl_policy_store_open (policy_path,
                  &f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_policy_store_create_schema
                    (f.fixture.policy), ==, WYRELOG_E_OK);
              WylFactOfflineRestoreJournal pending = { 0 };
              g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                    (f.fixture.policy, session_operation, &pending), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (pending.revision, ==, 29);
              const WylFactOfflineRestoreJournalGraph *pending_graph =
                  g_ptr_array_index (pending.graphs, 0);
              g_assert_cmpint (pending_graph->attempt, ==,
                  WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
              wyl_fact_offline_restore_journal_clear (&pending);
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-after-begin")) {
                wyl_fact_artifact_transition_posix_set_test_fault
                  (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_PUBLISH_DIR_FSYNC);
                g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                    session_operation, first, 29, 0, &f.committed), !=,
                    WYRELOG_E_OK);
                g_assert_null (f.committed.graphs);
                wyl_fact_artifact_transition_posix_set_test_fault
                  (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
              }
              sync_publish_revision = 29;
            }
            if (!interleaved) {
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, first, sync_publish_revision, 0,
                  &f.committed), ==, WYRELOG_E_OK);
              g_assert_cmpuint (f.committed.revision, ==, 30);
              wyl_fact_offline_restore_journal_clear (&f.committed);
            }
            g_assert_cmpint (wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
                  (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                session_operation, second, 30, 0, &f.committed), ==,
                WYRELOG_E_OK);
            g_assert_cmpuint (f.committed.revision, ==, 32);
            for (guint i = 0; i < f.committed.graphs->len; i++) {
              const WylFactOfflineRestoreJournalGraph *graph =
                  g_ptr_array_index (f.committed.graphs, i);
              g_assert_cmpint (graph->transition_state, ==,
                  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE);
              g_assert_cmpint (graph->next_op, ==,
                  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE);
              g_assert_cmpint (graph->attempt, ==,
                  WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED);
            }
            if (g_str_equal (mode,
                "retain-sync-dir-publish-sync-reserve")) {
              WylPolicyOfflineRestoreRecord *raw = NULL, *reserved = NULL;
              WylPolicyOfflineRestoreStoreResult result = 0;
              guint calls = 0;
              g_assert_cmpint (wyl_policy_store_offline_restore_load
                    (f.fixture.policy, session_operation, &raw), ==,
                  WYRELOG_E_OK);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), "CREATE TEMP TRIGGER fail_second_tenant_"
                  "reservation BEFORE INSERT ON fact_tenant_restore_replacements "
                  "WHEN NEW.graph_id='zeta' BEGIN SELECT RAISE(ABORT,"
                  "'injected second reservation failure'); END;",
                  NULL, NULL, NULL), ==, SQLITE_OK);
              g_assert_cmpint (wyl_policy_store_tenant_restore_reserve_replacements_with_effect
                    (f.fixture.policy, raw, tenant_reserve_test_effect,
                  &calls, &result, &reserved), !=, WYRELOG_E_OK);
              g_assert_null (reserved);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), "DROP TRIGGER fail_second_tenant_reservation;",
                  NULL, NULL, NULL), ==, SQLITE_OK);
              sqlite3_stmt *count_rows = NULL;
              g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
                    (f.fixture.policy), "SELECT COUNT(*) FROM "
                  "fact_tenant_restore_replacements;", -1, &count_rows,
                  NULL), ==, SQLITE_OK);
              g_assert_cmpint (sqlite3_step (count_rows), ==, SQLITE_ROW);
              g_assert_cmpint (sqlite3_column_int (count_rows, 0), ==, 0);
              sqlite3_finalize (count_rows);
              WylPolicyOfflineRestoreRecord *after_failure = NULL;
              g_assert_cmpint (wyl_policy_store_offline_restore_load
                    (f.fixture.policy, session_operation, &after_failure), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (after_failure->revision, ==, 32);
              wyl_policy_offline_restore_record_free (after_failure);
              g_assert_cmpint (wyl_policy_store_tenant_restore_reserve_replacements_with_effect
                    (f.fixture.policy, raw, tenant_reserve_test_effect,
                  &calls, &result, &reserved), ==, WYRELOG_E_OK);
              g_assert_cmpint (result, ==,
                  WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED);
              g_assert_cmpuint (calls, ==, 2);
              g_assert_nonnull (reserved);
              g_assert_cmpuint (reserved->revision, ==, 33);
              wyl_policy_offline_restore_record_free (reserved);
              reserved = NULL;
              g_assert_cmpint (wyl_policy_store_tenant_restore_reserve_replacements_with_effect
                    (f.fixture.policy, raw, tenant_reserve_test_effect,
                  &calls, &result, &reserved), ==, WYRELOG_E_OK);
              g_assert_cmpint (result, ==,
                  WYL_POLICY_OFFLINE_RESTORE_STORE_STALE);
              g_assert_cmpuint (calls, ==, 2);
              wyl_policy_offline_restore_record_free (raw);
              g_assert_null (reserved);
              g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
              g_assert_cmpint (wyl_policy_store_open (policy_path,
                  &f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_policy_store_create_schema
                    (f.fixture.policy), ==, WYRELOG_E_OK);
              g_auto (WylFactOfflineRestoreJournal) reloaded = { 0 };
              g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                    (f.fixture.policy, session_operation, &reloaded), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (reloaded.version, ==,
                  WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION);
              g_assert_cmpuint (reloaded.revision, ==, 33);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), "UPDATE "
                  "fact_tenant_restore_replacements SET "
                  "phase='companion_synced',updated_at=unixepoch() "
                  "WHERE graph_id='alpha';", NULL, NULL, NULL), ==,
                  SQLITE_CONSTRAINT_TRIGGER);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), "UPDATE "
                  "fact_tenant_restore_replacements SET "
                  "old_provisioning_uuid='018f22d0-7b6d-7a5b-8c31-123456789ac9' "
                  "WHERE graph_id='alpha';", NULL, NULL, NULL), ==,
                  SQLITE_CONSTRAINT_TRIGGER);
              sqlite3_stmt *guard_sql = NULL;
              g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
                    (f.fixture.policy), "SELECT sql FROM sqlite_master WHERE "
                  "name='fact_tenant_restore_replacement_delete_guard';",
                  -1, &guard_sql, NULL), ==, SQLITE_OK);
              g_assert_cmpint (sqlite3_step (guard_sql), ==, SQLITE_ROW);
              g_autofree gchar *recreate_guard = g_strdup
                    ((const gchar *) sqlite3_column_text (guard_sql, 0));
              sqlite3_finalize (guard_sql);
              g_assert_nonnull (recreate_guard);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), "DROP TRIGGER "
                  "fact_tenant_restore_replacement_delete_guard;",
                  NULL, NULL, NULL), ==, SQLITE_OK);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), "DELETE FROM "
                  "fact_tenant_restore_replacements WHERE graph_id='zeta';",
                  NULL, NULL, NULL), ==, SQLITE_OK);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), recreate_guard,
                  NULL, NULL, NULL), ==, SQLITE_OK);
              g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
              g_assert_cmpint (wyl_policy_store_open (policy_path,
                  &f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_policy_store_create_schema
                    (f.fixture.policy), ==, WYRELOG_E_POLICY);
            }
            if (g_str_equal (mode,
                "retain-sync-dir-publish-sync-driver")) {
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_clear_pointer (&f.fixture.runtime,
                  wyl_fact_graph_runtime_manager_unref);
              g_assert_cmpint (wyl_fact_graph_runtime_manager_new
                    (&f.fixture.runtime), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_reserve_replacements_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, 32, 0, &f.committed), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (f.committed.version, ==,
                  WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION);
              g_assert_cmpuint (f.committed.revision, ==, 33);
              g_assert_nonnull (((WylFactOfflineRestoreJournalGraph *)
                  g_ptr_array_index (f.committed.graphs, 0))->replacement_provisioning_uuid);
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
              g_assert_cmpint (wyl_policy_store_open (policy_path,
                  &f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_policy_store_create_schema
                    (f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_reserve_replacements_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, 32, 0, &f.committed), ==,
                  WYRELOG_E_BUSY);
              g_assert_null (f.committed.graphs);
            }
            if (g_str_has_prefix (mode,
                "retain-sync-dir-publish-sync-companion")) {
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_reserve_replacements_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, 32, 0, &f.committed), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (f.committed.revision, ==, 33);
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-foreign")
                  || g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-sibling-foreign")
                  || g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-symlink")) {
                gboolean sibling = g_str_has_suffix (mode, "sibling-foreign");
                const gchar *target_graph = sibling ? second : first;
                const WylFactOfflineRestoreJournalGraph *target = NULL;
                for (guint i = 0; i < f.committed.graphs->len; i++) {
                  const WylFactOfflineRestoreJournalGraph *candidate =
                      g_ptr_array_index (f.committed.graphs, i);
                  if (g_str_equal (candidate->graph_id, target_graph))
                    target = candidate;
                }
                g_assert_nonnull (target);
                g_autofree gchar *basename = g_strdup_printf
                      ("provision-%s.sqlite",
                        target->replacement_provisioning_uuid);
                g_autofree gchar *foreign = graph_file_path (&f.fixture,
                        target_graph, basename);
                if (g_str_has_suffix (mode, "symlink")) {
#ifdef __linux__
                  g_autoptr (GFile) link = g_file_new_for_path (foreign);
                  g_assert_true (g_file_make_symbolic_link (link, "/dev/null",
                      NULL, NULL));
#endif
                } else
                  g_assert_true (g_file_set_contents (foreign, "foreign", -1,
                      NULL));
                wyl_fact_offline_restore_journal_clear (&f.committed);
                g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                    session_operation, first, 33, 0, &f.committed), !=,
                    WYRELOG_E_OK);
                g_assert_null (f.committed.graphs);
                g_assert_cmpint (g_remove (foreign), ==, 0);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
              }
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-phase-fail")) {
                g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                      (f.fixture.policy), "CREATE TEMP TRIGGER "
                    "fail_tenant_companion_phase BEFORE UPDATE ON "
                    "main.fact_tenant_restore_replacements BEGIN "
                    "SELECT RAISE(ABORT,'injected phase failure'); END;",
                    NULL, NULL, NULL), ==, SQLITE_OK);
                wyl_fact_offline_restore_journal_clear (&f.committed);
                g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                    session_operation, first, 33, 0, &f.committed), !=,
                    WYRELOG_E_OK);
                g_assert_null (f.committed.graphs);
                g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                      (f.fixture.policy), "DROP TRIGGER "
                    "fail_tenant_companion_phase;", NULL, NULL, NULL), ==,
                    SQLITE_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                      (f.fixture.policy), "UPDATE "
                    "fact_tenant_restore_replacements SET "
                    "phase='companion_synced' WHERE graph_id='alpha';",
                    NULL, NULL, NULL), ==, SQLITE_CONSTRAINT_TRIGGER);
                g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                g_assert_cmpint (wyl_policy_store_open (policy_path,
                    &f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
              }
#ifdef WYL_TEST_HANDLE_SEAMS
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-before-dir-fsync")) {
                const gchar *failure = "restore-companion-before-dir-fsync";
                wyl_fact_offline_restore_tenant_companion_set_checkpoint_for_test
                  (fail_retain_once, &failure);
                wyl_fact_offline_restore_journal_clear (&f.committed);
                g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                    session_operation, first, 33, 0, &f.committed), ==,
                    WYRELOG_E_IO);
                g_assert_null (failure);
                g_assert_null (f.committed.graphs);
                wyl_fact_offline_restore_tenant_companion_set_checkpoint_for_test
                  (NULL, NULL);
                g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                g_assert_cmpint (wyl_policy_store_open (policy_path,
                    &f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
              }
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-after-link")) {
                gboolean linked = FALSE;
                wyl_fact_offline_restore_tenant_companion_set_checkpoint_for_test
                  (fail_companion_linked_once, &linked);
                wyl_fact_offline_restore_journal_clear (&f.committed);
                g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                    session_operation, first, 33, 0, &f.committed), ==,
                    WYRELOG_E_IO);
                g_assert_true (linked);
                g_assert_null (f.committed.graphs);
                wyl_fact_offline_restore_tenant_companion_set_checkpoint_for_test
                  (NULL, NULL);
                g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                g_assert_cmpint (wyl_policy_store_open (policy_path,
                    &f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
                sqlite3_stmt *phase = NULL;
                g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
                      (f.fixture.policy), "SELECT phase FROM "
                    "fact_tenant_restore_replacements WHERE graph_id='alpha';",
                    -1, &phase, NULL), ==, SQLITE_OK);
                g_assert_cmpint (sqlite3_step (phase), ==, SQLITE_ROW);
                g_assert_cmpstr ((const gchar *) sqlite3_column_text
                      (phase, 0), ==, "reserved");
                sqlite3_finalize (phase);
              }
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-commit-response")) {
                wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
                    WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
                wyl_fact_offline_restore_journal_clear (&f.committed);
                g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                    session_operation, first, 33, 0, &f.committed), ==,
                    WYRELOG_E_IO);
                g_assert_null (f.committed.graphs);
                g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                g_assert_cmpint (wyl_policy_store_open (policy_path,
                    &f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
              }
#endif
              gboolean companion_reverse = g_str_equal (mode,
                      "retain-sync-dir-publish-sync-companion-reverse");
              const gchar *companion_first = companion_reverse ? second : first;
              const gchar *companion_second = companion_reverse ? first : second;
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-restart")
                  || g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-restart-drift")) {
                g_clear_pointer (&f.fixture.runtime,
                    wyl_fact_graph_runtime_manager_unref);
                g_assert_cmpint (wyl_fact_graph_runtime_manager_new
                      (&f.fixture.runtime), ==, WYRELOG_E_OK);
              }
              if (g_str_equal (mode,
                  "retain-sync-dir-publish-sync-companion-restart-drift")) {
                sqlite3 *db = wyl_policy_store_get_db (f.fixture.policy);
                sqlite3_stmt *guard = NULL;
                g_assert_cmpint (sqlite3_prepare_v2 (db,
                    "SELECT sql FROM sqlite_master WHERE "
                    "name='fact_tenant_restore_replacement_update_guard';",
                    -1, &guard, NULL), ==, SQLITE_OK);
                g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
                g_autofree gchar *guard_sql = g_strdup
                      ((const gchar *) sqlite3_column_text (guard, 0));
                sqlite3_finalize (guard);
                g_assert_cmpint (sqlite3_exec (db,
                    "DROP TRIGGER fact_tenant_restore_replacement_update_guard;"
                    "UPDATE fact_tenant_restore_replacements SET "
                    "journal_revision=34 WHERE graph_id='alpha';",
                    NULL, NULL, NULL), ==, SQLITE_OK);
                wyl_fact_offline_restore_journal_clear (&f.committed);
                g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                    session_operation, companion_first, 33, 0, &f.committed),
                    ==, WYRELOG_E_POLICY);
                WylFactGraphKey key = { 0 };
                WylFactGraphRuntimeStatus status = { 0 };
                g_assert_cmpint (wyl_fact_graph_key_init (&key,
                    "tenant-a", "alpha"), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
                      (f.fixture.runtime, &key, &status), ==,
                    WYRELOG_E_NOT_FOUND);
                wyl_fact_graph_runtime_status_clear (&status);
                wyl_fact_graph_key_clear (&key);
                g_assert_cmpint (sqlite3_exec (db,
                    "UPDATE fact_tenant_restore_replacements SET "
                    "journal_revision=33 WHERE graph_id='alpha';",
                    NULL, NULL, NULL), ==, SQLITE_OK);
                g_assert_cmpint (sqlite3_exec (db, guard_sql,
                    NULL, NULL, NULL), ==, SQLITE_OK);
              }
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, companion_first, 33, 0, &f.committed), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (f.committed.revision, ==, 33);
              sqlite3_stmt *synced_count = NULL;
              g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
                    (f.fixture.policy), "SELECT COUNT(*) FROM "
                  "fact_tenant_restore_replacements WHERE "
                  "phase='companion_synced';", -1, &synced_count, NULL), ==,
                  SQLITE_OK);
              g_assert_cmpint (sqlite3_step (synced_count), ==, SQLITE_ROW);
              g_assert_cmpint (sqlite3_column_int (synced_count, 0), ==, 1);
              sqlite3_finalize (synced_count);
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, companion_first, 33, 0, &f.committed), ==,
                  WYRELOG_E_OK);
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, companion_second, 33, 0, &f.committed), ==,
                  WYRELOG_E_OK);
              synced_count = NULL;
              g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
                    (f.fixture.policy), "SELECT COUNT(*) FROM "
                  "fact_tenant_restore_replacements WHERE "
                  "phase='companion_synced';", -1, &synced_count, NULL), ==,
                  SQLITE_OK);
              g_assert_cmpint (sqlite3_step (synced_count), ==, SQLITE_ROW);
              g_assert_cmpint (sqlite3_column_int (synced_count, 0), ==, 2);
              sqlite3_finalize (synced_count);
              g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                    (f.fixture.policy), "UPDATE fact_tenant_restore_replacements "
                  "SET phase='reserved' WHERE graph_id='alpha';",
                  NULL, NULL, NULL), ==, SQLITE_CONSTRAINT_TRIGGER);
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
              g_assert_cmpint (wyl_policy_store_open (policy_path,
                  &f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_policy_store_create_schema
                    (f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_companion_sync_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, companion_second, 33, 0, &f.committed), ==,
                  WYRELOG_E_OK);
              if (g_str_has_prefix (mode,
                  "retain-sync-dir-publish-sync-companion-schema")) {
                tenant_selected_schema_fixture (f.fixture.policy,
                    &f.committed);
                g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                g_assert_cmpint (wyl_policy_store_open (policy_path,
                    &f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
                sqlite3 *db = wyl_policy_store_get_db (f.fixture.policy);
                g_assert_cmpint (sqlite3_exec (db,
                    "UPDATE fact_tenant_restore_replacements SET "
                    "phase='companion_synced' WHERE graph_id='zeta';",
                    NULL, NULL, NULL), ==, SQLITE_CONSTRAINT_TRIGGER);
                if (g_str_has_suffix (mode, "schema-phase")) {
                  sqlite3_stmt *guard = NULL;
                  g_assert_cmpint (sqlite3_prepare_v2 (db,
                      "SELECT sql FROM sqlite_master WHERE "
                      "name='fact_tenant_restore_replacement_update_guard';",
                      -1, &guard, NULL), ==, SQLITE_OK);
                  g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
                  g_autofree gchar *guard_sql = g_strdup
                        ((const gchar *) sqlite3_column_text (guard, 0));
                  sqlite3_finalize (guard);
                  g_assert_cmpint (sqlite3_exec (db,
                      "DROP TRIGGER fact_tenant_restore_replacement_update_guard;",
                      NULL, NULL, NULL), ==, SQLITE_OK);
                  g_assert_cmpint (sqlite3_exec (db,
                      "UPDATE fact_tenant_restore_replacements SET "
                      "phase='companion_synced' WHERE graph_id='zeta';",
                      NULL, NULL, NULL), ==, SQLITE_OK);
                  g_assert_cmpint (sqlite3_exec (db, guard_sql,
                      NULL, NULL, NULL), ==, SQLITE_OK);
                } else
                  g_assert_cmpint (sqlite3_exec (db,
                      "DELETE FROM fact_graph_provisioning "
                      "WHERE graph_id='alpha' AND phase='restore_selected';",
                      NULL, NULL, NULL), ==, SQLITE_OK);
                g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                g_assert_cmpint (wyl_policy_store_open (policy_path,
                    &f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_POLICY);
              }
              if (g_str_has_prefix (mode,
                  "retain-sync-dir-publish-sync-companion-select")) {
                gboolean insert_fail = g_str_has_suffix (mode,
                        "select-insert-fail");
                gboolean delete_fail = g_str_has_suffix (mode,
                        "select-delete-fail");
                gboolean phase_fail = g_str_has_suffix (mode,
                        "select-phase-fail");
                gboolean foreign = g_str_has_suffix (mode,
                        "select-foreign");
                gboolean response = g_str_has_suffix (mode,
                        "select-commit-response");
                gboolean stale = g_str_has_suffix (mode, "select-stale");
                sqlite3 *db = wyl_policy_store_get_db (f.fixture.policy);
                if (delete_fail)
                  g_assert_cmpint (sqlite3_exec (db,
                      "CREATE TEMP TRIGGER fail_second_selected_delete "
                      "BEFORE DELETE ON main.fact_graph_provisioning "
                      "WHEN OLD.graph_id='zeta' AND OLD.phase='active' BEGIN "
                      "SELECT RAISE(ABORT,'injected selected delete failure'); "
                      "END;", NULL, NULL, NULL), ==, SQLITE_OK);
                if (insert_fail)
                  g_assert_cmpint (sqlite3_exec (db,
                      "CREATE TEMP TRIGGER fail_second_selected_insert "
                      "BEFORE INSERT ON main.fact_graph_provisioning "
                      "WHEN NEW.graph_id='zeta' AND "
                      "NEW.phase='restore_selected' BEGIN "
                      "SELECT RAISE(ABORT,'injected selected insert failure'); "
                      "END;", NULL, NULL, NULL), ==, SQLITE_OK);
                if (phase_fail)
                  g_assert_cmpint (sqlite3_exec (db,
                      "CREATE TEMP TRIGGER fail_second_selected_phase "
                      "BEFORE UPDATE ON main.fact_tenant_restore_replacements "
                      "WHEN NEW.graph_id='zeta' BEGIN "
                      "SELECT RAISE(ABORT,'injected selected phase failure'); "
                      "END;", NULL, NULL, NULL), ==, SQLITE_OK);
                g_autofree gchar *foreign_path = foreign ?
                    graph_file_path (&f.fixture, second,
                        "foreign-selected-sidecar") : NULL;
                if (foreign)
                  g_assert_true (g_file_set_contents (foreign_path,
                      "foreign", -1, NULL));
                #ifdef WYL_TEST_HANDLE_SEAMS
                if (response)
                  wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
                      WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
                #endif
                if (g_str_equal (mode,
                    "retain-sync-dir-publish-sync-companion-select-restart")) {
                  g_clear_pointer (&f.fixture.runtime,
                      wyl_fact_graph_runtime_manager_unref);
                  g_assert_cmpint (wyl_fact_graph_runtime_manager_new
                        (&f.fixture.runtime), ==, WYRELOG_E_OK);
                }
                wyl_fact_offline_restore_journal_clear (&f.committed);
                if (stale) {
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_select_replacements_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, 32, 0, &f.committed), !=,
                      WYRELOG_E_OK);
                  g_assert_null (f.committed.graphs);
                }
                wyrelog_error_t selected_rc =
                    wyl_fact_offline_restore_tenant_select_replacements_run
                      (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                        session_operation, 33, 0, &f.committed);
                if (delete_fail || insert_fail || phase_fail || foreign) {
                  g_assert_cmpint (selected_rc, !=, WYRELOG_E_OK);
                  g_assert_null (f.committed.graphs);
                  if (delete_fail)
                    g_assert_cmpint (sqlite3_exec (db,
                        "DROP TRIGGER fail_second_selected_delete;",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                  if (insert_fail)
                    g_assert_cmpint (sqlite3_exec (db,
                        "DROP TRIGGER fail_second_selected_insert;",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                  if (phase_fail)
                    g_assert_cmpint (sqlite3_exec (db,
                        "DROP TRIGGER fail_second_selected_phase;",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                  if (foreign)
                    g_assert_cmpint (g_remove (foreign_path), ==, 0);
                  g_auto (WylFactOfflineRestoreJournal) unchanged = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &unchanged), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (unchanged.version, ==,
                      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION);
                  g_assert_cmpuint (unchanged.revision, ==, 33);
                  sqlite3_stmt *before_counts = NULL;
                  g_assert_cmpint (sqlite3_prepare_v2 (db,
                      "SELECT (SELECT count(*) FROM fact_graph_provisioning "
                      "WHERE phase='active'),(SELECT count(*) FROM "
                      "fact_graph_provisioning WHERE phase='restore_selected'),"
                      "(SELECT count(*) FROM fact_tenant_restore_replacements "
                      "WHERE phase='companion_synced');", -1,
                      &before_counts, NULL), ==, SQLITE_OK);
                  g_assert_cmpint (sqlite3_step (before_counts), ==,
                      SQLITE_ROW);
                  g_assert_cmpint (sqlite3_column_int (before_counts, 0), ==, 2);
                  g_assert_cmpint (sqlite3_column_int (before_counts, 1), ==, 0);
                  g_assert_cmpint (sqlite3_column_int (before_counts, 2), ==, 2);
                  sqlite3_finalize (before_counts);
                  selected_rc =
                      wyl_fact_offline_restore_tenant_select_replacements_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                          session_operation, 33, 0, &f.committed);
                }
                if (response) {
                  g_assert_cmpint (selected_rc, ==, WYRELOG_E_IO);
                  g_assert_null (f.committed.graphs);
                } else
                  g_assert_cmpint (selected_rc, ==, WYRELOG_E_OK);
                if (!response) {
                  g_assert_cmpuint (f.committed.version, ==,
                      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION);
                  g_assert_cmpuint (f.committed.revision, ==, 34);
                }
                g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                g_assert_cmpint (wyl_policy_store_open (policy_path,
                    &f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (wyl_policy_store_create_schema
                      (f.fixture.policy), ==, WYRELOG_E_OK);
                g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                      (f.fixture.policy),
                    "UPDATE fact_tenant_restore_replacements SET "
                    "phase='companion_synced' WHERE graph_id='alpha';",
                    NULL, NULL, NULL), ==, SQLITE_CONSTRAINT_TRIGGER);
                if (response) {
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &f.committed),
                      ==, WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.version, ==,
                      WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_SELECTED_VERSION);
                  g_assert_cmpuint (f.committed.revision, ==, 34);
                }
                sqlite3_stmt *selected_count = NULL;
                g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
                      (f.fixture.policy), "SELECT "
                    "(SELECT count(*) FROM fact_tenant_restore_replacements "
                    "WHERE phase='selected_pending_cleanup'),"
                    "(SELECT count(*) FROM fact_graph_provisioning "
                    "WHERE phase='restore_selected'),"
                    "(SELECT count(*) FROM fact_graph_provisioning "
                    "WHERE phase='active');", -1, &selected_count, NULL),
                    ==, SQLITE_OK);
                g_assert_cmpint (sqlite3_step (selected_count), ==,
                    SQLITE_ROW);
                g_assert_cmpint (sqlite3_column_int (selected_count, 0), ==, 2);
                g_assert_cmpint (sqlite3_column_int (selected_count, 1), ==, 2);
                g_assert_cmpint (sqlite3_column_int (selected_count, 2), ==, 0);
                sqlite3_finalize (selected_count);
                gboolean promote_driver = g_str_has_prefix (mode,
                        "retain-sync-dir-publish-sync-companion-select-promote-driver");
                if (g_str_has_suffix (mode, "select-promote-policy")
                    || promote_driver) {
                  if (g_str_equal (mode,
                      "retain-sync-dir-publish-sync-companion-select-promote-driver-restart")
                      || g_str_equal (mode,
                      "retain-sync-dir-publish-sync-companion-select-promote-driver-restart-drift")) {
                    g_clear_pointer (&f.fixture.runtime,
                        wyl_fact_graph_runtime_manager_unref);
                    g_assert_cmpint (wyl_fact_graph_runtime_manager_new
                          (&f.fixture.runtime), ==, WYRELOG_E_OK);
                  }
                  if (g_str_equal (mode,
                      "retain-sync-dir-publish-sync-companion-select-promote-driver-restart-drift")) {
                    sqlite3 *db = wyl_policy_store_get_db (f.fixture.policy);
                    sqlite3_stmt *guard = NULL;
                    g_assert_cmpint (sqlite3_prepare_v2 (db,
                        "SELECT sql FROM sqlite_master WHERE "
                        "name='fact_tenant_restore_replacement_update_guard';",
                        -1, &guard, NULL), ==, SQLITE_OK);
                    g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
                    g_autofree gchar *guard_sql = g_strdup
                          ((const gchar *) sqlite3_column_text (guard, 0));
                    sqlite3_finalize (guard);
                    g_assert_cmpint (sqlite3_exec (db,
                        "DROP TRIGGER fact_tenant_restore_replacement_update_guard;"
                        "UPDATE fact_tenant_restore_replacements SET "
                        "journal_revision=34 WHERE graph_id='alpha';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    wyl_fact_offline_restore_journal_clear (&f.committed);
                    g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                        session_operation, first, 34, 0, &f.committed), ==,
                        WYRELOG_E_POLICY);
                    WylFactGraphKey key = { 0 };
                    WylFactGraphRuntimeStatus status = { 0 };
                    g_assert_cmpint (wyl_fact_graph_key_init (&key,
                        "tenant-a", "alpha"), ==, WYRELOG_E_OK);
                    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
                          (f.fixture.runtime, &key, &status), ==,
                        WYRELOG_E_NOT_FOUND);
                    wyl_fact_graph_runtime_status_clear (&status);
                    wyl_fact_graph_key_clear (&key);
                    g_assert_cmpint (sqlite3_exec (db,
                        "UPDATE fact_tenant_restore_replacements SET "
                        "journal_revision=33 WHERE graph_id='alpha';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    g_assert_cmpint (sqlite3_exec (db, guard_sql,
                        NULL, NULL, NULL), ==, SQLITE_OK);
                  }
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 34, 0, &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 36);
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, second, 36, 0, &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 38);
                  if (promote_driver) {
                    if (g_str_equal (mode,
                        "retain-sync-dir-publish-sync-companion-select-promote-driver-restart")
                        || g_str_equal (mode,
                        "retain-sync-dir-publish-sync-companion-select-promote-driver-restart-drift")) {
                      g_clear_pointer (&f.fixture.runtime,
                          wyl_fact_graph_runtime_manager_unref);
                      g_assert_cmpint (wyl_fact_graph_runtime_manager_new
                            (&f.fixture.runtime), ==, WYRELOG_E_OK);
                    }
                    if (g_str_has_suffix (mode,
                        "promote-driver-stale")) {
                      wyl_fact_offline_restore_journal_clear (&f.committed);
                      g_assert_cmpint (wyl_fact_offline_restore_tenant_promote_run
                            (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                          session_operation, 37, 0, &f.committed), !=,
                          WYRELOG_E_OK);
                      g_assert_null (f.committed.graphs);
                    }
                    if (g_str_has_suffix (mode,
                        "promote-driver-foreign")) {
                      g_autofree gchar *intruder = graph_file_path
                            (&f.fixture, second, "foreign-promotion-sidecar");
                      g_assert_true (g_file_set_contents (intruder,
                          "foreign", -1, NULL));
                      wyl_fact_offline_restore_journal_clear (&f.committed);
                      g_assert_cmpint (wyl_fact_offline_restore_tenant_promote_run
                            (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                          session_operation, 38, 0, &f.committed), !=,
                          WYRELOG_E_OK);
                      g_assert_null (f.committed.graphs);
                      g_assert_cmpint (g_remove (intruder), ==, 0);
                    }
                    const gchar *fault_sql = NULL;
                    if (g_str_has_suffix (mode, "promote-driver-graph-fail"))
                      fault_sql = "CREATE TEMP TRIGGER fail_tenant_promotion "
                          "BEFORE UPDATE ON main.fact_graphs WHEN "
                          "NEW.graph_id='zeta' AND "
                          "NEW.lifecycle_state='active' BEGIN "
                          "SELECT RAISE(ABORT,'graph fault'); END;";
                    else if (g_str_has_suffix (mode,
                        "promote-driver-provision-fail"))
                      fault_sql = "CREATE TEMP TRIGGER fail_tenant_promotion "
                          "BEFORE UPDATE ON main.fact_graph_provisioning "
                          "WHEN NEW.graph_id='zeta' AND "
                          "NEW.phase='active' BEGIN "
                          "SELECT RAISE(ABORT,'provision fault'); END;";
                    else if (g_str_has_suffix (mode,
                        "promote-driver-row-fail"))
                      fault_sql = "CREATE TEMP TRIGGER fail_tenant_promotion "
                          "BEFORE UPDATE ON main.fact_tenant_restore_replacements "
                          "WHEN NEW.graph_id='zeta' AND "
                          "NEW.phase='verified' BEGIN "
                          "SELECT RAISE(ABORT,'row fault'); END;";
                    else if (g_str_has_suffix (mode,
                        "promote-driver-tenant-begin-fail"))
                      fault_sql = "CREATE TEMP TRIGGER fail_tenant_promotion "
                          "BEFORE UPDATE ON main.tenants WHEN "
                          "NEW.lifecycle_state='unsealing' BEGIN "
                          "SELECT RAISE(ABORT,'tenant begin fault'); END;";
                    else if (g_str_has_suffix (mode,
                        "promote-driver-tenant-finish-fail"))
                      fault_sql = "CREATE TEMP TRIGGER fail_tenant_promotion "
                          "BEFORE UPDATE ON main.tenants WHEN "
                          "NEW.lifecycle_state='active' BEGIN "
                          "SELECT RAISE(ABORT,'tenant finish fault'); END;";
                    else if (g_str_has_suffix (mode,
                        "promote-driver-claim-fail"))
                      fault_sql = "CREATE TEMP TRIGGER fail_tenant_promotion "
                          "BEFORE DELETE ON main.fact_offline_restore_tenant_claims "
                          "BEGIN SELECT RAISE(ABORT,'claim fault'); END;";
                    if (fault_sql != NULL) {
                      g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                            (f.fixture.policy), fault_sql,
                          NULL, NULL, NULL), ==, SQLITE_OK);
                      wyl_fact_offline_restore_journal_clear (&f.committed);
                      g_assert_cmpint (wyl_fact_offline_restore_tenant_promote_run
                            (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                          session_operation, 38, 0, &f.committed), !=,
                          WYRELOG_E_OK);
                      g_assert_null (f.committed.graphs);
                      g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db
                            (f.fixture.policy),
                          "DROP TRIGGER fail_tenant_promotion;",
                          NULL, NULL, NULL), ==, SQLITE_OK);
                      WylPolicyOfflineRestoreRecord *rolled_back = NULL;
                      g_assert_cmpint (wyl_policy_store_offline_restore_load
                            (f.fixture.policy, session_operation,
                          &rolled_back), ==, WYRELOG_E_OK);
                      g_assert_cmpuint (rolled_back->revision, ==, 38);
                      wyl_policy_offline_restore_record_free (rolled_back);
                      sqlite3_stmt *tuple = NULL;
                      g_assert_cmpint (sqlite3_prepare_v2
                            (wyl_policy_store_get_db (f.fixture.policy),
                          "SELECT (SELECT count(*) FROM "
                          "fact_tenant_restore_replacements WHERE "
                          "phase='selected_pending_cleanup'),"
                          "(SELECT count(*) FROM fact_graph_provisioning "
                          "WHERE phase='restore_selected'),"
                          "(SELECT count(*) FROM fact_offline_restore_tenant_claims "
                          "WHERE operation_uuid=?1);", -1, &tuple,
                          NULL), ==, SQLITE_OK);
                      g_assert_cmpint (sqlite3_bind_text (tuple, 1,
                          session_operation, -1, SQLITE_TRANSIENT), ==,
                          SQLITE_OK);
                      g_assert_cmpint (sqlite3_step (tuple), ==, SQLITE_ROW);
                      g_assert_cmpint (sqlite3_column_int (tuple, 0), ==, 2);
                      g_assert_cmpint (sqlite3_column_int (tuple, 1), ==, 2);
                      g_assert_cmpint (sqlite3_column_int (tuple, 2), ==, 1);
                      sqlite3_finalize (tuple);
                    }
                    gboolean ambiguous = g_str_has_suffix (mode,
                            "promote-driver-commit-response");
#ifdef WYL_TEST_HANDLE_SEAMS
                    if (ambiguous)
                      wyl_policy_store_offline_restore_fail_once
                        (f.fixture.policy,
                          WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
#endif
                    wyl_fact_offline_restore_journal_clear (&f.committed);
                    g_assert_cmpint (wyl_fact_offline_restore_tenant_promote_run
                          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                        session_operation, 38, 0, &f.committed), ==,
                        ambiguous ? WYRELOG_E_IO : WYRELOG_E_OK);
                    if (ambiguous)
                      g_assert_null (f.committed.graphs);
                    else {
                      g_assert_cmpuint (f.committed.version, ==,
                          WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_PUBLISHED_VERSION);
                      g_assert_cmpuint (f.committed.revision, ==, 39);
                    }
                  } else {
                    WylPolicyOfflineRestoreRecord *expected = NULL;
                    WylPolicyOfflineRestoreRecord *committed = NULL;
                    WylPolicyOfflineRestoreStoreResult result =
                        WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
                    guint effect_calls = 0;
                    g_assert_cmpint (wyl_policy_store_offline_restore_load
                          (f.fixture.policy, session_operation, &expected), ==,
                        WYRELOG_E_OK);
                    g_assert_cmpint (wyl_policy_store_tenant_restore_selected_promote_with_effect
                          (f.fixture.policy, expected,
                        accept_tenant_promotion_effect, &effect_calls,
                        &result, &committed), ==, WYRELOG_E_OK);
                    g_assert_cmpint (result, ==,
                        WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED);
                    g_assert_cmpuint (effect_calls, ==, 1);
                    g_assert_nonnull (committed);
                    g_assert_cmpuint (committed->revision, ==, 39);
                    wyl_policy_offline_restore_record_free (committed);
                    wyl_policy_offline_restore_record_free (expected);
                  }
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                  WylPolicyOfflineRestoreRecord *published_record = NULL;
                  g_assert_cmpint (wyl_policy_store_offline_restore_load
                        (f.fixture.policy, session_operation,
                      &published_record), ==, WYRELOG_E_OK);
                  g_assert_cmpuint (published_record->revision, ==, 39);
                  wyl_policy_offline_restore_record_free (published_record);
                  if (g_strrstr (mode,
                      "promote-driver-successor") != NULL) {
                    tenant_published_successor_fixture (f.fixture.policy,
                        &f.committed, 1,
                        g_str_has_suffix (mode,
                        "promote-driver-successor-forged") ? 2 :
                        g_str_has_suffix (mode,
                        "promote-driver-successor-mixed") ? 1 : 0,
                        g_str_has_suffix (mode,
                        "promote-driver-successor-selected"));
                    if (g_str_has_suffix (mode,
                        "promote-driver-successor-fork"))
                      tenant_published_fork_fixture (f.fixture.policy,
                          &f.committed);
                    g_clear_pointer (&f.fixture.policy,
                        wyl_policy_store_close);
                    g_assert_cmpint (wyl_policy_store_open (policy_path,
                        &f.fixture.policy), ==, WYRELOG_E_OK);
                    wyrelog_error_t successor_rc =
                        wyl_policy_store_create_schema (f.fixture.policy);
                    if (g_str_has_suffix (mode,
                        "promote-driver-successor-forged")
                        || g_str_has_suffix (mode,
                        "promote-driver-successor-mixed")
                        || g_str_has_suffix (mode,
                        "promote-driver-successor-fork")) {
                      g_assert_cmpint (successor_rc, ==, WYRELOG_E_POLICY);
                      g_clear_pointer (&f.session,
                          wyl_fact_offline_restore_validation_session_free);
                      for (guint i = 0; i < 2; i++)
                        g_clear_pointer (&f.snapshots[i],
                            wyl_fact_graph_snapshot_unref);
                      g_clear_object (&f.cancel);
                      g_clear_pointer (&f.journal_before, g_bytes_unref);
                      destination_capture_clear (&f.capture);
                      fixture_clear (&f.fixture);
                      return;
                    }
                    g_assert_cmpint (successor_rc, ==, WYRELOG_E_OK);
                    WylPolicyOfflineRestoreRecord *historical = NULL;
                    g_assert_cmpint (wyl_policy_store_offline_restore_load
                          (f.fixture.policy, session_operation,
                        &historical), ==, WYRELOG_E_OK);
                    g_assert_cmpuint (historical->revision, ==, 39);
                    wyl_policy_offline_restore_record_free (historical);
                    historical = NULL;
                    g_assert_cmpint (wyl_policy_store_offline_restore_load
                          (f.fixture.policy,
                        "00000000-0000-7000-8000-0000000000b1",
                        &historical), ==, WYRELOG_E_OK);
                    g_assert_cmpuint (historical->revision, ==,
                        g_str_has_suffix (mode,
                        "promote-driver-successor-selected") ? 38 : 39);
                    if (g_str_has_suffix (mode,
                        "promote-driver-successor-selected")) {
                      WylPolicyOfflineRestoreRecord *promoted = NULL;
                      WylPolicyOfflineRestoreStoreResult promote_result =
                          WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
                      guint effect_calls = 0;
                      g_assert_cmpint (wyl_policy_store_tenant_restore_selected_promote_with_effect
                            (f.fixture.policy, historical,
                          accept_tenant_promotion_effect, &effect_calls,
                          &promote_result, &promoted), ==, WYRELOG_E_OK);
                      g_assert_cmpint (promote_result, ==,
                          WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED);
                      g_assert_cmpuint (effect_calls, ==, 1);
                      g_assert_nonnull (promoted);
                      g_assert_cmpuint (promoted->revision, ==, 39);
                      wyl_policy_offline_restore_record_free (promoted);
                      g_clear_pointer (&f.fixture.policy,
                          wyl_policy_store_close);
                      g_assert_cmpint (wyl_policy_store_open (policy_path,
                          &f.fixture.policy), ==, WYRELOG_E_OK);
                      g_assert_cmpint (wyl_policy_store_create_schema
                            (f.fixture.policy), ==, WYRELOG_E_OK);
                    }
                    if (g_str_has_suffix (mode,
                        "promote-driver-successor-chain")) {
                      g_auto (WylFactOfflineRestoreJournal) second = { 0 };
                      g_assert_cmpint
                        (wyl_fact_offline_restore_journal_decode
                            (historical->journal_blob, &second), ==,
                          WYRELOG_E_OK);
                      tenant_published_successor_fixture
                        (f.fixture.policy, &second, 2, 0, FALSE);
                      g_clear_pointer (&f.fixture.policy,
                          wyl_policy_store_close);
                      g_assert_cmpint (wyl_policy_store_open (policy_path,
                          &f.fixture.policy), ==, WYRELOG_E_OK);
                      g_assert_cmpint (wyl_policy_store_create_schema
                            (f.fixture.policy), ==, WYRELOG_E_OK);
                      WylPolicyOfflineRestoreRecord *third = NULL;
                      g_assert_cmpint (wyl_policy_store_offline_restore_load
                            (f.fixture.policy,
                          "00000000-0000-7000-8000-0000000000c1",
                          &third), ==, WYRELOG_E_OK);
                      wyl_policy_offline_restore_record_free (third);
                    }
                    wyl_policy_offline_restore_record_free (historical);
                  }
                  g_clear_pointer (&f.session,
                      wyl_fact_offline_restore_validation_session_free);
                  for (guint i = 0; i < 2; i++)
                    g_clear_pointer (&f.snapshots[i],
                        wyl_fact_graph_snapshot_unref);
                  g_clear_object (&f.cancel);
                  g_clear_pointer (&f.journal_before, g_bytes_unref);
                  destination_capture_clear (&f.capture);
                  fixture_clear (&f.fixture);
                  return;
                }
                if (g_str_has_prefix (mode,
                    "retain-sync-dir-publish-sync-companion-select-published-schema")) {
                  tenant_published_schema_fixture (f.fixture.policy,
                      &f.committed);
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                  sqlite3 *published_db = wyl_policy_store_get_db
                        (f.fixture.policy);
                  g_assert_cmpint (sqlite3_exec (published_db,
                      "UPDATE fact_tenant_restore_replacements SET "
                      "phase='selected_pending_cleanup' WHERE graph_id='alpha';",
                      NULL, NULL, NULL), ==, SQLITE_CONSTRAINT_TRIGGER);
                  gboolean tampered = FALSE;
                  gboolean valid_change = FALSE;
                  if (g_str_has_suffix (mode, "published-schema-claim")) {
                    gchar *sql = sqlite3_mprintf
                          ("INSERT INTO fact_offline_restore_tenant_claims "
                            "(tenant_id,operation_uuid) VALUES('tenant-a','%q');",
                            session_operation);
                    g_assert_cmpint (sqlite3_exec (published_db, sql,
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    sqlite3_free (sql);
                    tampered = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-journal")) {
                    sqlite3_stmt *guard = NULL;
                    g_assert_cmpint (sqlite3_prepare_v2 (published_db,
                        "SELECT sql FROM sqlite_master WHERE "
                        "name='fact_offline_restore_journal_update_guard';",
                        -1, &guard, NULL), ==, SQLITE_OK);
                    g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
                    g_autofree gchar *guard_sql = g_strdup
                          ((const gchar *) sqlite3_column_text (guard, 0));
                    sqlite3_finalize (guard);
                    g_assert_cmpint (sqlite3_exec (published_db,
                        "DROP TRIGGER fact_offline_restore_journal_update_guard;"
                        "UPDATE fact_offline_restore_journals SET "
                        "revision=revision+1 WHERE scope='tenant';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    g_assert_cmpint (sqlite3_exec (published_db, guard_sql,
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    tampered = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-row")) {
                    sqlite3_stmt *guard = NULL;
                    g_assert_cmpint (sqlite3_prepare_v2 (published_db,
                        "SELECT sql FROM sqlite_master WHERE "
                        "name='fact_tenant_restore_replacement_update_guard';",
                        -1, &guard, NULL), ==, SQLITE_OK);
                    g_assert_cmpint (sqlite3_step (guard), ==, SQLITE_ROW);
                    g_autofree gchar *guard_sql = g_strdup
                          ((const gchar *) sqlite3_column_text (guard, 0));
                    sqlite3_finalize (guard);
                    g_assert_cmpint (sqlite3_exec (published_db,
                        "DROP TRIGGER fact_tenant_restore_replacement_update_guard;"
                        "UPDATE fact_tenant_restore_replacements SET "
                        "phase='selected_pending_cleanup' WHERE graph_id='alpha';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    g_assert_cmpint (sqlite3_exec (published_db, guard_sql,
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    tampered = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-graph")) {
                    tenant_published_tamper_guarded (published_db,
                        "fact_graph_authority_update_guard",
                        "UPDATE fact_graphs SET "
                        "lifecycle_generation=lifecycle_generation-1 "
                        "WHERE tenant_id='tenant-a' AND graph_id='alpha';");
                    tampered = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-tenant")) {
                    tenant_published_tamper_guarded (published_db,
                        "tenant_authority_update_guard",
                        "UPDATE tenants SET "
                        "lifecycle_generation=lifecycle_generation-1 "
                        "WHERE tenant_id='tenant-a';");
                    tampered = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-later-graph")) {
                    g_assert_cmpint (sqlite3_exec (published_db,
                        "UPDATE fact_graphs SET lifecycle_state='sealed',"
                        "sealed=1,lifecycle_generation=lifecycle_generation+1 "
                        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    tampered = TRUE;
                    valid_change = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-later-tenant")) {
                    g_assert_cmpint (sqlite3_exec (published_db,
                        "UPDATE tenants SET lifecycle_state='sealing',"
                        "lifecycle_generation=lifecycle_generation+1 "
                        "WHERE tenant_id='tenant-a';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    tampered = TRUE;
                    valid_change = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-later-graph-claim")) {
                    g_assert_cmpint (sqlite3_exec (published_db,
                        "UPDATE fact_graphs SET lifecycle_state='sealed',"
                        "sealed=1,lifecycle_generation=lifecycle_generation+1 "
                        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    create_restore_journal_for_manifest (&f.fixture,
                        f.capture.manifest,
                        WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha",
                        "018f22d0-7b6d-7a5b-8c31-123456789af9");
                    tampered = TRUE;
                    valid_change = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-later-tenant-claim")) {
                    g_assert_cmpint (sqlite3_exec (published_db,
                        "UPDATE fact_graphs SET lifecycle_state='sealed',"
                        "sealed=1,lifecycle_generation=lifecycle_generation+1 "
                        "WHERE tenant_id='tenant-a' AND "
                        "lifecycle_state='active';"
                        "UPDATE tenants SET lifecycle_state='sealing',"
                        "lifecycle_generation=lifecycle_generation+1 "
                        "WHERE tenant_id='tenant-a' AND "
                        "lifecycle_state='active';"
                        "UPDATE tenants SET lifecycle_state='sealed',sealed=1,"
                        "sealed_generation=sealed_generation+1,"
                        "lifecycle_generation=lifecycle_generation+1 "
                        "WHERE tenant_id='tenant-a' AND "
                        "lifecycle_state='sealing';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    create_restore_journal_for_manifest (&f.fixture,
                        f.capture.manifest,
                        WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL,
                        "018f22d0-7b6d-7a5b-8c31-123456789af8");
                    tampered = TRUE;
                    valid_change = TRUE;
                  } else if (g_str_has_suffix (mode,
                      "published-schema-provision")) {
                    g_assert_cmpint (sqlite3_exec (published_db,
                        "DELETE FROM fact_graph_provisioning "
                        "WHERE tenant_id='tenant-a' AND graph_id='alpha';",
                        NULL, NULL, NULL), ==, SQLITE_OK);
                    tampered = TRUE;
                  }
                  if (tampered) {
                    g_clear_pointer (&f.fixture.policy,
                        wyl_policy_store_close);
                    g_assert_cmpint (wyl_policy_store_open (policy_path,
                        &f.fixture.policy), ==, WYRELOG_E_OK);
                    g_assert_cmpint (wyl_policy_store_create_schema
                          (f.fixture.policy), ==, valid_change ?
                        WYRELOG_E_OK : WYRELOG_E_POLICY);
                  }
                  g_clear_pointer (&f.session,
                      wyl_fact_offline_restore_validation_session_free);
                  for (guint i = 0; i < 2; i++)
                    g_clear_pointer (&f.snapshots[i],
                        wyl_fact_graph_snapshot_unref);
                  g_clear_object (&f.cancel);
                  g_clear_pointer (&f.journal_before, g_bytes_unref);
                  destination_capture_clear (&f.capture);
                  fixture_clear (&f.fixture);
                  return;
                }
                if (g_str_has_suffix (mode, "select-finalize-policy")) {
                  WylPolicyOfflineRestoreRecord *selected_record = NULL;
                  WylPolicyOfflineRestoreRecord *pending_record = NULL;
                  WylPolicyOfflineRestoreRecord *ignored = NULL;
                  WylPolicyOfflineRestoreStoreResult step_result =
                      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
                  g_assert_cmpint (wyl_policy_store_offline_restore_load
                        (f.fixture.policy, session_operation,
                      &selected_record), ==, WYRELOG_E_OK);
                  selected_record->revision--;
                  g_assert_cmpint (wyl_policy_store_tenant_restore_selected_finalize_step
                        (f.fixture.policy, selected_record, first,
                      WYL_POLICY_TENANT_RESTORE_SELECTED_FINALIZE_BEGIN,
                      NULL, NULL, &step_result, &ignored), ==, WYRELOG_E_OK);
                  g_assert_cmpint (step_result, ==,
                      WYL_POLICY_OFFLINE_RESTORE_STORE_STALE);
                  g_assert_null (ignored);
                  selected_record->revision++;
                  g_assert_cmpint (wyl_policy_store_tenant_restore_selected_finalize_step
                        (f.fixture.policy, selected_record, first,
                      WYL_POLICY_TENANT_RESTORE_SELECTED_FINALIZE_BEGIN,
                      NULL, NULL, &step_result, &pending_record), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpint (step_result, ==,
                      WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED);
                  g_assert_cmpuint (pending_record->revision, ==, 35);
                  g_assert_cmpint (wyl_policy_store_tenant_restore_selected_finalize_step
                        (f.fixture.policy, pending_record, second,
                      WYL_POLICY_TENANT_RESTORE_SELECTED_FINALIZE_BEGIN,
                      NULL, NULL, &step_result, &ignored), ==,
                      WYRELOG_E_POLICY);
                  g_assert_null (ignored);
                  guint effect_calls = 0;
                  g_assert_cmpint (wyl_policy_store_tenant_restore_selected_finalize_step
                        (f.fixture.policy, pending_record, first,
                      WYL_POLICY_TENANT_RESTORE_SELECTED_FINALIZE_COMPLETE,
                      reject_tenant_finalize_effect, &effect_calls,
                      &step_result, &ignored), ==, WYRELOG_E_POLICY);
                  g_assert_cmpuint (effect_calls, ==, 1);
                  g_assert_null (ignored);
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                  g_auto (WylFactOfflineRestoreJournal) reopened = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &reopened), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (reopened.revision, ==, 35);
                  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
                      g_ptr_array_index (reopened.graphs, 0))->attempt, ==,
                      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
                  wyl_policy_offline_restore_record_free (pending_record);
                  wyl_policy_offline_restore_record_free (selected_record);
                }
                if (g_str_has_suffix (mode, "select-finalize-both")
                    || g_str_has_suffix (mode, "select-finalize-reverse")) {
                  gboolean reverse = g_str_has_suffix (mode,
                          "select-finalize-reverse");
                  const gchar *finalize_first = reverse ? second : first;
                  const gchar *finalize_second = reverse ? first : second;
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, finalize_first, 34, 0,
                      &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 36);
                  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
                      g_ptr_array_index (f.committed.graphs,
                      reverse ? 1 : 0))->transition_state,
                      ==, WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED);
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                  if (g_str_has_suffix (mode, "select-finalize-both")) {
                    g_clear_pointer (&f.fixture.runtime,
                        wyl_fact_graph_runtime_manager_unref);
                    g_assert_cmpint (wyl_fact_graph_runtime_manager_new
                          (&f.fixture.runtime), ==, WYRELOG_E_OK);
                  }
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, finalize_second, 36, 0,
                      &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 38);
                  for (guint graph_index = 0; graph_index < 2;
                      graph_index++)
                    g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
                        g_ptr_array_index (f.committed.graphs,
                        graph_index))->transition_state,
                        ==, WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED);
                  g_autoptr (GBytes) v7_blob = NULL;
                  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
                        (&f.committed, &v7_blob), ==, WYRELOG_E_OK);
                  g_auto (WylFactOfflineRestoreJournal) v8_candidate = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_decode
                        (v7_blob, &v8_candidate), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_fact_offline_restore_journal_mark_tenant_selected_published
                        (&v8_candidate), ==, WYRELOG_E_OK);
                  WylFactOfflineRestoreStoreResult generic_result =
                      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
                  g_auto (WylFactOfflineRestoreJournal) generic_committed = {
                    0
                  };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
                        (f.fixture.policy, f.committed.revision,
                      &v8_candidate, &generic_result,
                      &generic_committed), ==, WYRELOG_E_POLICY);
                  g_assert_null (generic_committed.graphs);
                  g_autoptr (GBytes) v8_blob = NULL;
                  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
                        (&v8_candidate, &v8_blob), ==, WYRELOG_E_OK);
                  WylPolicyOfflineRestoreRecord v8_record = {
                    .operation_uuid = v8_candidate.operation_uuid,
                    .tenant_id = v8_candidate.tenant_id,
                    .scope = WYL_POLICY_OFFLINE_RESTORE_SCOPE_TENANT,
                    .revision = v8_candidate.revision,
                    .graph_count = v8_candidate.graphs->len,
                    .journal_blob = v8_blob,
                  };
                  memcpy (v8_record.manifest_sha256,
                      v8_candidate.manifest_sha256, 32);
                  WylPolicyOfflineRestoreStoreResult policy_generic_result =
                      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
                  WylPolicyOfflineRestoreRecord *policy_generic_committed =
                      NULL;
                  g_assert_cmpint (wyl_policy_store_offline_restore_cas
                        (f.fixture.policy, f.committed.revision,
                      &v8_record, &policy_generic_result,
                      &policy_generic_committed), ==, WYRELOG_E_POLICY);
                  g_assert_null (policy_generic_committed);
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                }
                if (g_str_has_suffix (mode, "select-finalize-partial")
                    || g_str_has_suffix (mode,
                    "select-finalize-terminal")) {
#ifdef WYL_TEST_HANDLE_SEAMS
                  const gchar *failure = g_str_has_suffix (mode,
                          "select-finalize-partial") ?
                      "restore-selected-after-companion-unlink" :
                      "restore-selected-after-rollback-unlink";
                  wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
                    (fail_retain_once, &failure);
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 34, 0, &f.committed), ==,
                      WYRELOG_E_IO);
                  g_assert_null (failure);
                  wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
                    (NULL, NULL);
                  g_assert_null (f.committed.graphs);
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                  g_auto (WylFactOfflineRestoreJournal) pending = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &pending), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (pending.revision, ==, 35);
                  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
                      g_ptr_array_index (pending.graphs, 0))->attempt, ==,
                      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
                  g_clear_pointer (&f.fixture.runtime,
                      wyl_fact_graph_runtime_manager_unref);
                  g_assert_cmpint (wyl_fact_graph_runtime_manager_new
                        (&f.fixture.runtime), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 35, 0, &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 36);
#endif
                }
                if (g_str_has_suffix (mode, "select-finalize-foreign")) {
                  g_autofree gchar *intruder = graph_file_path (&f.fixture,
                          second, "foreign-finalize-sidecar");
                  g_assert_true (g_file_set_contents (intruder,
                      "foreign", -1, NULL));
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 34, 0, &f.committed), !=,
                      WYRELOG_E_OK);
                  g_assert_null (f.committed.graphs);
                  g_auto (WylFactOfflineRestoreJournal) unchanged = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &unchanged), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (unchanged.revision, ==, 34);
                  g_assert_cmpint (g_remove (intruder), ==, 0);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 34, 0, &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 36);
                }
                if (g_str_has_suffix (mode, "select-finalize-response")) {
                  WylPolicyOfflineRestoreRecord *selected_record = NULL;
                  WylPolicyOfflineRestoreRecord *pending_record = NULL;
                  WylPolicyOfflineRestoreStoreResult step_result =
                      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
                  g_assert_cmpint (wyl_policy_store_offline_restore_load
                        (f.fixture.policy, session_operation,
                      &selected_record), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_tenant_restore_selected_finalize_step
                        (f.fixture.policy, selected_record, first,
                      WYL_POLICY_TENANT_RESTORE_SELECTED_FINALIZE_BEGIN,
                      NULL, NULL, &step_result, &pending_record), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (pending_record->revision, ==, 35);
#ifdef WYL_TEST_HANDLE_SEAMS
                  wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
                      WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
#endif
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 35, 0, &f.committed), ==,
                      WYRELOG_E_IO);
                  g_assert_null (f.committed.graphs);
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                  g_auto (WylFactOfflineRestoreJournal) reopened = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &reopened), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (reopened.revision, ==, 36);
                  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
                      g_ptr_array_index (reopened.graphs, 0))->transition_state,
                      ==, WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED);
                  wyl_policy_offline_restore_record_free (pending_record);
                  wyl_policy_offline_restore_record_free (selected_record);
                }
                if (g_str_has_suffix (mode,
                    "select-finalize-begin-response")) {
#ifdef WYL_TEST_HANDLE_SEAMS
                  wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
                      WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 34, 0, &f.committed), ==,
                      WYRELOG_E_IO);
                  g_assert_null (f.committed.graphs);
                  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
                  g_assert_cmpint (wyl_policy_store_open (policy_path,
                      &f.fixture.policy), ==, WYRELOG_E_OK);
                  g_assert_cmpint (wyl_policy_store_create_schema
                        (f.fixture.policy), ==, WYRELOG_E_OK);
                  g_auto (WylFactOfflineRestoreJournal) pending = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &pending), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (pending.revision, ==, 35);
                  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
                      g_ptr_array_index (pending.graphs, 0))->attempt, ==,
                      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 35, 0, &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 36);
#endif
                }
                if (g_str_has_suffix (mode, "select-finalize-stale")) {
                  wyl_fact_offline_restore_journal_clear (&f.committed);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 33, 0, &f.committed), !=,
                      WYRELOG_E_OK);
                  g_assert_null (f.committed.graphs);
                  g_auto (WylFactOfflineRestoreJournal) unchanged = { 0 };
                  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                        (f.fixture.policy, session_operation, &unchanged), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (unchanged.revision, ==, 34);
                  g_assert_cmpint (wyl_fact_offline_restore_tenant_finalize_graph_run
                        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                      session_operation, first, 34, 0, &f.committed), ==,
                      WYRELOG_E_OK);
                  g_assert_cmpuint (f.committed.revision, ==, 36);
                }
              }
            }
#ifdef WYL_TEST_HANDLE_SEAMS
            if (g_str_equal (mode,
                "retain-sync-dir-publish-sync-driver-commit-response")) {
              wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
                  WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_reserve_replacements_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, 32, 0, &f.committed), ==,
                  WYRELOG_E_IO);
              g_assert_null (f.committed.graphs);
              g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
              g_assert_cmpint (wyl_policy_store_open (policy_path,
                  &f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_policy_store_create_schema
                    (f.fixture.policy), ==, WYRELOG_E_OK);
              g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                    (f.fixture.policy, session_operation, &f.committed), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (f.committed.version, ==,
                  WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_REPLACEMENTS_VERSION);
              g_assert_cmpuint (f.committed.revision, ==, 33);
            }
#endif
#ifdef WYL_TEST_HANDLE_SEAMS
            if (g_str_equal (mode,
                "retain-sync-dir-publish-sync-driver-conflict")) {
              TenantReservationIntruder intruder = { .fixture = &f };
              wyl_fact_offline_restore_tenant_reserve_set_checkpoint_for_test
                (tenant_reserve_intrude, &intruder);
              wyl_fact_offline_restore_journal_clear (&f.committed);
              g_assert_cmpint (wyl_fact_offline_restore_tenant_reserve_replacements_run
                    (f.fixture.policy, f.fixture.root, f.fixture.runtime,
                  session_operation, 32, 0, &f.committed), ==,
                  WYRELOG_E_POLICY);
              g_assert_null (f.committed.graphs);
              wyl_fact_offline_restore_tenant_reserve_set_checkpoint_for_test
                (NULL, NULL);
              g_assert_nonnull (intruder.intruder);
              g_assert_cmpint (g_remove (intruder.intruder), ==, 0);
              g_free (intruder.intruder);
              g_auto (WylFactOfflineRestoreJournal) unchanged = { 0 };
              g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
                    (f.fixture.policy, session_operation, &unchanged), ==,
                  WYRELOG_E_OK);
              g_assert_cmpuint (unchanged.version, ==,
                  WYL_FACT_OFFLINE_RESTORE_JOURNAL_TENANT_BOUND_VERSION);
              g_assert_cmpuint (unchanged.revision, ==, 32);
            }
#endif
          }
        }
      }
    }
  }
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

static wyrelog_error_t
tenant_bind_reject_effect (GBytes *journal, const GPtrArray *uuids,
    gpointer data)
{
  g_assert_nonnull (journal);
  g_assert_cmpuint (uuids->len, ==, 2);
  (*(guint *) data)++;
  return WYRELOG_E_IO;
}

static void
test_tenant_provisioned_binding_rejects (gconstpointer data)
{
  const gchar *mode = data;
  SessionFixture f = { 0 };
  session_fixture_init (&f, "success");
  TenantPreflightTestJob job = { &f, 3, f.capture.manifest };
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  g_autofree gchar *foreign = NULL;
  g_autofree gchar *stage = NULL;
  guint8 original = 0;
  if (g_str_equal (mode, "sibling-foreign")) {
    foreign = graph_file_path (&f.fixture, "zeta", "foreign");
    g_assert_true (g_file_set_contents (foreign, "foreign", -1, NULL));
  } else if (g_str_equal (mode, "sibling-stage-content")) {
    stage = session_stage_path (&f, "zeta");
    gint fd = g_open (stage, O_RDWR, 0);
    g_assert_cmpint (fd, >=, 0);
    g_assert_cmpint (read (fd, &original, 1), ==, 1);
    guint8 changed = original ^ 1;
    g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
    g_assert_cmpint (write (fd, &changed, 1), ==, 1);
    g_assert_cmpint (fsync (fd), ==, 0);
    g_assert_cmpint (close (fd), ==, 0);
  } else if (g_str_equal (mode, "sibling-schema")) {
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        "UPDATE fact_namespaces SET visibility=1-visibility "
        "WHERE tenant_id='tenant-a' AND graph_id='zeta';",
        NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (wyl_policy_store_get_db
          (f.fixture.policy)), >, 0);
  } else if (g_str_equal (mode, "extra-graph-row")) {
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        "INSERT INTO fact_graphs(tenant_id,graph_id,storage_uri,storage_path,"
        "schema_version,owner_scope,created_at,updated_at) VALUES"
        "('tenant-a','extra','file:///extra','/extra',1,'tenant-a',1,1);",
        NULL, NULL, NULL), ==, SQLITE_OK);
  } else if (g_str_equal (mode, "missing-claim")) {
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        "DELETE FROM fact_offline_restore_tenant_claims WHERE "
        "tenant_id='tenant-a';", NULL, NULL, NULL), ==, SQLITE_OK);
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  if (g_str_equal (mode, "commit-response"))
    wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
        WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
#endif
  wyrelog_error_t rc;
  if (g_str_equal (mode, "effect-refused")) {
    WylPolicyOfflineRestoreRecord *raw = NULL, *stored = NULL;
    g_autoptr (GPtrArray) records = NULL;
    WylPolicyOfflineRestoreStoreResult result;
    guint calls = 0;
    g_assert_cmpint (wyl_policy_store_offline_restore_load
          (f.fixture.policy, session_operation, &raw), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_graph_provisioning_list_for_graph
          (f.fixture.policy, "tenant-a", "alpha", &records), ==, WYRELOG_E_OK);
    g_assert_cmpuint (records->len, ==, 1);
    WylPolicyGraphProvisioningRecord *active = g_ptr_array_index (records, 0);
    rc = wyl_policy_store_tenant_restore_bind_provisioned_old_with_effect
          (f.fixture.policy, raw, "alpha", active->op_uuid,
            tenant_bind_reject_effect, &calls, &result, &stored);
    g_assert_cmpuint (calls, ==, 1);
    g_assert_null (stored);
    wyl_policy_offline_restore_record_free (raw);
  } else
    rc = wyl_fact_offline_restore_tenant_bind_provisioned_old_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime,
            session_operation, "alpha", 5, 0, &f.committed);
  if (g_str_equal (mode, "commit-response")
      || g_str_equal (mode, "effect-refused"))
    g_assert_cmpint (rc, ==, WYRELOG_E_IO);
  else
    g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
  g_assert_null (f.committed.graphs);
  if (foreign != NULL)
    g_assert_cmpint (g_remove (foreign), ==, 0);
  if (stage != NULL) {
    gint fd = g_open (stage, O_RDWR, 0);
    g_assert_cmpint (fd, >=, 0);
    g_assert_cmpint (write (fd, &original, 1), ==, 1);
    g_assert_cmpint (fsync (fd), ==, 0);
    g_assert_cmpint (close (fd), ==, 0);
  }
  if (g_str_equal (mode, "extra-graph-row"))
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        "DELETE FROM fact_graphs WHERE tenant_id='tenant-a' AND "
        "graph_id='extra';", NULL, NULL, NULL), ==, SQLITE_OK);
  if (g_str_equal (mode, "missing-claim")) {
    g_autofree gchar *sql = g_strdup_printf (
      "INSERT INTO fact_offline_restore_tenant_claims(tenant_id,operation_uuid) "
      "VALUES('tenant-a','%s');", session_operation);
    g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (f.fixture.policy),
        sql, NULL, NULL, NULL), ==, SQLITE_OK);
  }
  if (g_str_equal (mode, "commit-response")) {
    g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
    g_autofree gchar *path = g_build_filename (f.fixture.root,
            "policy.db", NULL);
    g_assert_cmpint (wyl_policy_store_open (path, &f.fixture.policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
        WYRELOG_E_OK);
    g_auto (WylFactOfflineRestoreJournal) recovered = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (f.fixture.policy, session_operation, &recovered), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (recovered.revision, ==, 6);
    g_assert_nonnull (((WylFactOfflineRestoreJournalGraph *)
        g_ptr_array_index (recovered.graphs, 0))->old_provisioning_uuid);
  }
  g_autoptr (GBytes) after = session_journal_bytes (&f);
  if (!g_str_equal (mode, "commit-response"))
    g_assert_true (g_bytes_equal (f.journal_before, after));
  else {
    g_clear_pointer (&f.journal_before, g_bytes_unref);
    f.journal_before = g_bytes_ref (after);
  }
  session_fixture_clear (&f);
}

static void
test_tenant_external_import (gconstpointer data)
{
  const gchar *mode = data;
  SessionFixture f = { 0 };
  session_fixture_init (&f, "coordinator/tenant");
  /* The input remains backup A while each provisioned destination main gains
   * new bytes B under the same store identity. */
  const gchar *graphs[] = { "alpha", "zeta" };
  for (guint i = 0; i < G_N_ELEMENTS (graphs); i++) {
    g_autoptr (wyl_fact_store_t) store = NULL;
    g_assert_cmpint (wyl_fact_store_open_provisioned_graph (f.fixture.policy,
        f.fixture.root, "tenant-a", graphs[i], TRUE, &store), ==,
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
      { .type = WYL_FACT_VALUE_SYMBOL, .as.text = "current-main-B" },
    };
    const wyl_fact_row_t rows[] = { { values, G_N_ELEMENTS (values) } };
    const wyl_fact_store_batch_t batch = {
      .batch_id = "tenant-import-current-B", .tenant_id = "tenant-a",
      .graph_id = graphs[i], .namespace_id = "backup",
      .relation_name = "items", .schema_version = 1, .source = "test",
      .idempotency_key = "tenant-import-B", .op = WYL_FACT_STORE_OP_ASSERT,
      .rows = rows, .n_rows = G_N_ELEMENTS (rows),
    };
    gboolean created = FALSE;
    g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
        &created), ==, WYRELOG_E_OK);
    g_assert_true (created);
    g_clear_pointer (&store, wyl_fact_store_close);
    g_autofree gchar *path = graph_file_path (&f.fixture, graphs[i],
            "facts.duckdb");
    gchar *current = NULL;
    gsize length = 0;
    g_assert_true (g_file_get_contents (path, &current, &length, NULL));
    g_autoptr (GBytes) current_bytes = g_bytes_new_take (current, length);
    g_assert_false (g_bytes_equal (current_bytes,
        g_ptr_array_index (f.capture.artifact_bytes, i)));
  }
  TenantImportTestInput test_input = { .fixture = &f,
                                       .fail_validation = 4,
                                       .mode = mode };
  const WylFactOfflineRestoreTenantInput callbacks = {
    tenant_import_test_read, tenant_import_test_revalidate,
  };
  g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
      f.capture.manifest, session_operation, 1, 0, &callbacks, &test_input,
      &f.committed), ==, WYRELOG_E_IO);
  g_assert_null (f.committed.graphs);
  g_auto (WylFactOfflineRestoreJournal) partial = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &partial), ==, WYRELOG_E_OK);
  g_assert_cmpuint (partial.revision, ==, 2);
  g_assert_false (artifact_identity_is_zero (&((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (partial.graphs, 0))->staged_main_identity));
  g_assert_true (artifact_identity_is_zero (&((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (partial.graphs, 1))->staged_main_identity));
  if (g_str_equal (mode, "restart")) {
    for (guint i = 0; i < 2; i++)
      g_clear_pointer (&f.snapshots[i], wyl_fact_graph_snapshot_unref);
    g_clear_pointer (&f.fixture.runtime,
        wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime),
        ==, WYRELOG_E_OK);
  }
  test_input.fail_validation = 0;
  test_input.validations = 0;
  g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
      f.capture.manifest, session_operation, 1, 0, &callbacks, &test_input,
      &f.committed), ==, WYRELOG_E_BUSY);
  g_autofree gchar *foreign = graph_file_path (&f.fixture, "alpha", "foreign");
  g_assert_true (g_file_set_contents (foreign, "foreign", -1, NULL));
  g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
      f.capture.manifest, session_operation, partial.revision, 0,
      &callbacks, &test_input, &f.committed), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (foreign), ==, 0);
  g_autofree gchar *bound_stage = session_stage_path (&f, "alpha");
  gint fd = g_open (bound_stage, O_RDWR, 0);
  g_assert_cmpint (fd, >=, 0);
  guint8 first = 0;
  g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
  g_assert_cmpint (read (fd, &first, 1), ==, 1);
  guint8 changed = first ^ 1;
  g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
  g_assert_cmpint (write (fd, &changed, 1), ==, 1);
  g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
      f.capture.manifest, session_operation, partial.revision, 0,
      &callbacks, &test_input, &f.committed), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
  g_assert_cmpint (write (fd, &first, 1), ==, 1);
  g_assert_cmpint (fsync (fd), ==, 0);
  g_assert_cmpint (close (fd), ==, 0);
  if (g_strcmp0 (mode, "short") == 0
      || g_strcmp0 (mode, "excess") == 0) {
    g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
        f.capture.manifest, session_operation, partial.revision, 0,
        &callbacks, &test_input, &f.committed), ==, WYRELOG_E_POLICY);
    g_assert_null (f.committed.graphs);
    test_input.mode = "resume";
    g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
        f.capture.manifest, session_operation, partial.revision, 0,
        &callbacks, &test_input, &f.committed), ==, WYRELOG_E_POLICY);
    g_clear_pointer (&f.journal_before, g_bytes_unref);
    f.journal_before = session_journal_bytes (&f);
    session_fixture_clear (&f);
    return;
  }
  g_assert_cmpint (wyl_fact_offline_restore_tenant_import_run
        (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a",
      f.capture.manifest, session_operation, partial.revision, 0,
      &callbacks, &test_input, &f.committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 3);
  for (guint i = 0; i < G_N_ELEMENTS (graphs); i++) {
    g_autofree gchar *path = session_stage_path (&f, graphs[i]);
    gchar *staged = NULL;
    gsize length = 0;
    g_assert_true (g_file_get_contents (path, &staged, &length, NULL));
    g_autoptr (GBytes) staged_bytes = g_bytes_new_take (staged, length);
    g_assert_true (g_bytes_equal (staged_bytes,
        g_ptr_array_index (f.capture.artifact_bytes, i)));
  }
  wyl_fact_offline_restore_journal_clear (&f.committed);
  if (g_strcmp0 (mode, "straight") == 0
      || g_strcmp0 (mode, "restart") == 0) {
    TenantPreflightTestJob straight = { &f, 3, f.capture.manifest };
    g_assert_cmpint (tenant_preflight_test_worker (&straight), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, ==, 5);
    g_assert_cmpint (f.committed.decision, ==,
        WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
    for (guint i = 0; i < f.committed.graphs->len; i++)
      g_assert_true (((WylFactOfflineRestoreJournalGraph *)
          g_ptr_array_index (f.committed.graphs, i))->replay_preflighted);
    g_clear_pointer (&f.journal_before, g_bytes_unref);
    f.journal_before = session_journal_bytes (&f);
    session_fixture_clear (&f);
    return;
  }
  TenantPreflightTestJob job = { &f, 2, f.capture.manifest };
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_BUSY);
  g_assert_null (f.committed.graphs);
  job.revision = 3;
  WylFactOfflineBackupManifest wrong = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode
        (f.capture.manifest, &wrong), ==, WYRELOG_E_OK);
  wrong.policy_generation++;
  g_autoptr (GBytes) wrong_manifest = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&wrong,
      &wrong_manifest), ==, WYRELOG_E_OK);
  wyl_fact_offline_backup_manifest_clear (&wrong);
  job.manifest = wrong_manifest;
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_POLICY);
  job.manifest = f.capture.manifest;
  fd = g_open (bound_stage, O_RDWR, 0);
  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
  g_assert_cmpint (read (fd, &first, 1), ==, 1);
  changed = first ^ 1;
  g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
  g_assert_cmpint (write (fd, &changed, 1), ==, 1);
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (lseek (fd, 0, SEEK_SET), ==, 0);
  g_assert_cmpint (write (fd, &first, 1), ==, 1);
  g_assert_cmpint (fsync (fd), ==, 0);
  g_assert_cmpint (close (fd), ==, 0);

  f.mode = "fail-between";
  f.record_preflight = TRUE;
  g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
        (f.fixture.policy, f.fixture.root, f.fixture.runtime,
      f.capture.manifest, session_operation, 3, 0, &f.session), ==,
      WYRELOG_E_OK);
  wyl_fact_offline_restore_validation_session_set_record_checkpoint_for_test
    (f.session, session_record_checkpoint, &f);
  g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_IO);
  g_assert_null (f.committed.graphs);
  g_clear_pointer (&f.session,
      wyl_fact_offline_restore_validation_session_free);
  g_auto (WylFactOfflineRestoreJournal) preflight_partial = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &preflight_partial), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (preflight_partial.revision, ==, 4);
  g_assert_true (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (preflight_partial.graphs, 0))->replay_preflighted);
  g_assert_false (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (preflight_partial.graphs, 1))->replay_preflighted);
  g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (f.fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (f.fixture.policy), ==,
      WYRELOG_E_OK);
  for (guint i = 0; i < 2; i++)
    g_clear_pointer (&f.snapshots[i], wyl_fact_graph_snapshot_unref);
  g_clear_pointer (&f.fixture.runtime,
      wyl_fact_graph_runtime_manager_unref);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&f.fixture.runtime),
      ==, WYRELOG_E_OK);
  job.revision = preflight_partial.revision;
  g_assert_cmpint (tenant_preflight_test_worker (&job), ==, WYRELOG_E_OK);
  g_assert_cmpuint (f.committed.revision, ==, 5);
  g_assert_cmpint (f.committed.decision, ==,
      WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  for (guint i = 0; i < f.committed.graphs->len; i++)
    g_assert_true (((WylFactOfflineRestoreJournalGraph *)
        g_ptr_array_index (f.committed.graphs, i))->replay_preflighted);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t
import_construction_gap (gpointer data)
{
  SessionFixture *f = data;
  f->checkpoints++;
  /* The destination snapshot already exists; quiescence has not begun. */
  guint calls = 0;
  g_assert_cmpint (wyl_fact_graph_snapshot_use (f->snapshots[1],
      session_snapshot_callback, &calls), ==, WYRELOG_E_OK);
  g_assert_cmpuint (calls, ==, 1);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "zeta"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission
        (f->fixture.runtime, &key), ==, WYRELOG_E_OK);
  wyl_fact_graph_key_clear (&key);
  if (!g_str_equal (f->mode, "coordinator/construction-reopen"))
    graph_corrupt_provision (f, "zeta");
  return WYRELOG_E_OK;
}
#endif

static void
test_graph_import (gconstpointer data)
{
  const gchar *mode = data;
  g_autofree gchar *fixture_mode = g_strconcat ("coordinator/", mode, NULL);
  SessionFixture f = { 0 };
  session_fixture_init_selected (&f, fixture_mode, "zeta");
  ImportInput input = { .fixture = &f, .mode = mode,
                        .payload = g_ptr_array_index (f.capture.artifact_bytes, 1) };
  WylFactOfflineRestoreInput callbacks = { import_read, import_revalidate };
  if (g_str_equal (mode, "null-read"))
    callbacks.read_at = NULL;
  if (g_str_equal (mode, "null-revalidate"))
    callbacks.revalidate = NULL;
  WylFactGraphKey sibling = { 0 }, selected = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&sibling, "tenant-a", "alpha"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&selected, "tenant-a", "zeta"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission
        (f.fixture.runtime, &sibling), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus before = { 0 }, after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (f.fixture.runtime, &sibling, &before), ==, WYRELOG_E_OK);
  if (g_str_equal (mode, "selected-provision"))
    graph_corrupt_provision (&f, "zeta");
  if (g_str_equal (mode, "selected-schema"))
    graph_corrupt_schema (&f, "zeta");
  if (g_str_equal (mode, "sibling-provision"))
    graph_corrupt_provision (&f, "alpha");
  if (g_str_equal (mode, "sibling-schema"))
    graph_corrupt_schema (&f, "alpha");
  if (g_str_equal (mode, "unsealed"))
    mutate_tenant_after_snapshot (&f.capture);
  g_autofree gchar *stage_path = session_stage_path (&f, "zeta");
  if (g_str_equal (mode, "collision")) {
    g_assert_true (g_file_set_contents (stage_path, "recovery-owned", -1, NULL));
    g_assert_cmpint (g_chmod (stage_path, 0600), ==, 0);
  }
  if (g_str_equal (mode, "sibling-artifact")) {
    g_autofree gchar *path = graph_file_path (&f.fixture, "alpha", "foreign");
    g_assert_true (g_file_set_contents (path, "keep", -1, NULL));
  }
  g_autoptr (GHashTable) files = session_graph_files (&f);
  g_autofree gchar *main_path = graph_file_path (&f.fixture, "zeta", "facts.duckdb");
  if (g_str_equal (mode, "import-historical")) {
    g_assert_false (g_bytes_equal (input.payload, g_hash_table_lookup (files, main_path)));
    g_assert_cmpuint (g_bytes_get_size (input.payload), !=,
        g_bytes_get_size (g_hash_table_lookup (files, main_path)));
    g_auto (WylFactOfflineBackupManifest) manifest = { 0 };
    g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (f.capture.manifest,
        &manifest), ==, WYRELOG_E_OK);
    WylPolicyTenantAuthorityRecord *tenant = NULL;
    g_assert_cmpint (wyl_policy_store_read_tenant_authority (f.fixture.policy,
        "tenant-a", &tenant), ==, WYRELOG_E_OK);
    g_assert_cmpuint (tenant->lifecycle_generation, >, manifest.policy_generation);
    wyl_policy_tenant_authority_record_free (tenant);
    GStatBuf st;
    g_assert_cmpint (g_stat (main_path, &st), ==, 0);
#ifdef __linux__
    g_assert_cmpuint (st.st_nlink, ==, 2);
#endif
    g_test_message ("backup A bytes=%" G_GSIZE_FORMAT ", current B bytes=%" G_GSIZE_FORMAT,
        g_bytes_get_size (input.payload),
        g_bytes_get_size (g_hash_table_lookup (files, main_path)));
  }
  g_autoptr (WylFactGraphRuntimeManager) empty_runtime = NULL;
  if (g_str_equal (mode, "missing-runtime"))
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&empty_runtime), ==, WYRELOG_E_OK);
  WylFactGraphQuiescenceToken *token = NULL;
  if (g_str_equal (mode, "token-held"))
    g_assert_cmpint (wyl_fact_graph_runtime_manager_quiesce
          (f.fixture.runtime, &selected, 0, &token), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) wrong_manifest = NULL;
  if (g_str_equal (mode, "wrong-manifest")) {
    g_auto (WylFactOfflineBackupManifest) manifest = { 0 };
    g_assert_cmpint (wyl_fact_offline_backup_manifest_decode (f.capture.manifest,
        &manifest), ==, WYRELOG_E_OK);
    manifest.policy_generation++;
    g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&manifest,
        &wrong_manifest), ==, WYRELOG_E_OK);
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  if (g_str_equal (mode, "commit-response"))
    wyl_policy_store_offline_restore_fail_once (f.fixture.policy,
        WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
  if (g_str_has_prefix (mode, "construction-"))
    wyl_fact_offline_restore_import_set_checkpoint_for_test (import_construction_gap, &f);
#endif
  wyrelog_error_t rc = wyl_fact_offline_restore_graph_import_run
        (f.fixture.policy, f.fixture.root, empty_runtime != NULL ? empty_runtime : f.fixture.runtime,
          "tenant-a", g_str_equal (mode, "wrong-graph") ? "alpha" : "zeta",
          wrong_manifest != NULL ? wrong_manifest : f.capture.manifest,
          session_operation, g_str_equal (mode, "stale") ? 2 : 1, 0,
          g_str_equal (mode, "null-input") ? NULL : &callbacks, &input, &f.committed);
#ifdef WYL_TEST_HANDLE_SEAMS
  wyl_fact_offline_restore_import_set_checkpoint_for_test (NULL, NULL);
  if (g_str_has_prefix (mode, "construction-"))
    g_assert_cmpuint (f.checkpoints, ==, 1);
#endif
  wyl_fact_graph_quiescence_token_release (token);
  gboolean success = g_str_equal (mode, "success")
      || g_str_equal (mode, "construction-reopen")
      || g_str_equal (mode, "import-historical")
      || g_str_equal (mode, "missing-runtime")
      || g_str_has_prefix (mode, "sibling-");
  g_assert_cmpint (rc == WYRELOG_E_OK, ==, success);
  if (g_str_equal (mode, "missing-runtime")) {
    WylFactGraphRuntimeStatus acquired = { 0 };
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
          (empty_runtime, &selected, &acquired), ==, WYRELOG_E_OK);
    g_assert_cmpint (acquired.state, ==, WYL_FACT_GRAPH_RUNTIME_EMPTY);
    g_assert_cmpint (acquired.admission, ==,
        WYL_FACT_GRAPH_ADMISSION_CLOSED);
    g_assert_false (acquired.queryable);
    wyl_fact_graph_runtime_status_clear (&acquired);
    g_assert_cmpuint (f.committed.revision, ==, 2);
    g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
          (f.fixture.runtime, &sibling, &after), ==, WYRELOG_E_OK);
    g_assert_cmpuint (before.operation_generation, ==,
        after.operation_generation);
    g_assert_cmpuint (before.engine_generation, ==, after.engine_generation);
    wyl_fact_graph_runtime_status_clear (&before);
    wyl_fact_graph_runtime_status_clear (&after);
    wyl_fact_graph_key_clear (&sibling);
    wyl_fact_graph_key_clear (&selected);
    wyl_fact_offline_restore_journal_clear (&f.committed);
    g_clear_pointer (&f.journal_before, g_bytes_unref);
    f.journal_before = session_journal_bytes (&f);
    session_fixture_clear (&f);
    return;
  }
  if (g_str_equal (mode, "token-held"))
    g_assert_cmpint (rc, ==, WYRELOG_E_BUSY);
  if (g_str_equal (mode, "late-journal"))
    g_assert_cmpint (rc, ==, WYRELOG_E_BUSY);
  if (g_str_equal (mode, "expected-main-absent"))
    g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
  if (g_str_has_prefix (mode, "null-"))
    g_assert_cmpint (rc, ==, WYRELOG_E_INVALID);
  if (g_str_equal (mode, "read-error") || g_str_equal (mode, "final-eof-error")
      || g_str_has_prefix (mode, "revalidate-"))
    g_assert_cmpint (rc, ==, WYRELOG_E_IO);
  if (!success)
    g_assert_null (f.committed.graphs);
  if (g_str_equal (mode, "commit-response")) {
    g_clear_pointer (&f.fixture.policy, wyl_policy_store_close);
    g_autofree gchar *policy_path = g_build_filename (f.fixture.root, "policy.db", NULL);
    g_assert_cmpint (wyl_policy_store_open (policy_path, &f.fixture.policy), ==, WYRELOG_E_OK);
  }
  g_auto (WylFactOfflineRestoreJournal) durable = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (f.fixture.policy, session_operation, &durable), ==, WYRELOG_E_OK);
  gboolean bound = success || g_str_equal (mode, "commit-response");
  g_assert_cmpuint (durable.revision, ==,
      bound || g_str_equal (mode, "late-journal") ? 2 : 1);
  g_assert_cmpuint (durable.graphs->len, ==, g_str_equal (mode, "tenant") ? 2 : 1);
  WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index (durable.graphs,
          g_str_equal (mode, "tenant") ? 1 : 0);
  g_assert_cmpstr (graph->graph_id, ==, "zeta");
  g_assert_cmpint (artifact_identity_is_zero (&graph->staged_main_identity), ==, !bound);
  g_assert_false (graph->copied);
  g_assert_false (graph->checksum_verified);
  g_assert_false (graph->identity_verified);
  g_assert_false (graph->schema_verified);
  g_assert_false (graph->replay_preflighted);
  g_assert_false (durable.policy_generation_published);
  g_assert_cmpint (durable.decision, ==, g_str_equal (mode, "late-journal")
      ? WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK : WYL_FACT_OFFLINE_RESTORE_DECISION_NONE);
  if (!bound && !g_str_equal (mode, "late-journal")) {
    g_autoptr (GBytes) unchanged = session_journal_bytes (&f);
    g_assert_true (g_bytes_equal (unchanged, f.journal_before));
  }
  /* Inspect cleanup admission before the subsequent preflight can drain it. */
  WylFactGraphRuntimeStatus selected_after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (f.fixture.runtime, &selected, &selected_after), ==, WYRELOG_E_OK);
  g_assert_cmpint (selected_after.admission, ==,
      g_str_has_prefix (mode, "construction-") ? WYL_FACT_GRAPH_ADMISSION_OPEN
      : WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&selected_after);
  if (success)
    assert_backup_authority (&f.fixture, 2);
  g_autoptr (GHashTable) current = session_graph_files (&f);
  GHashTableIter iter;
  gpointer path, bytes;
  g_hash_table_iter_init (&iter, files);
  while (g_hash_table_iter_next (&iter, &path, &bytes)) {
    GBytes *actual = g_hash_table_lookup (current, path);
    g_assert_nonnull (actual);
    g_assert_true (g_bytes_equal (bytes, actual));
  }
  if (bound) {
    GBytes *stage = g_hash_table_lookup (current, stage_path);
    g_assert_nonnull (stage);
    g_assert_true (g_bytes_equal (stage, input.payload));
    g_assert_cmpuint (input.validations, ==, 2);
    g_assert_cmpuint (input.offset, ==, g_bytes_get_size (input.payload));
    GStatBuf st;
    g_assert_cmpint (g_stat (stage_path, &st), ==, 0);
    g_assert_cmpuint (graph->staged_main_identity.domain, ==, st.st_dev);
    g_assert_cmpuint (graph->staged_main_identity.object, ==, st.st_ino);
  }
  if (!success && input.validations == 0) {
    g_assert_cmpuint (input.reads, ==, 0);
    session_assert_files_unchanged (&f, files);
  }
  if (g_str_has_prefix (mode, "wrong-") || g_str_has_prefix (mode, "null-")
      || g_str_has_prefix (mode, "selected-") || g_str_has_prefix (mode, "tenant-")
      || g_str_has_prefix (mode, "graph-") || g_str_equal (mode, "stale")
      || g_str_equal (mode, "unsealed") || g_str_equal (mode, "untrusted")
      || g_str_equal (mode, "unconfirmed") || g_str_equal (mode, "tenant")
      || g_str_equal (mode, "expected-main-absent")
      || g_str_equal (mode, "token-held") || g_str_equal (mode, "construction-gap")) {
    g_assert_cmpuint (input.validations, ==, 0);
    g_assert_cmpuint (input.reads, ==, 0);
    session_assert_files_unchanged (&f, files);
  }
  if (g_str_equal (mode, "revalidate-before")) {
    g_assert_cmpuint (input.reads, ==, 0);
    session_assert_files_unchanged (&f, files);
  }
  if (g_str_equal (mode, "corrupt")) {
    g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));
    g_auto (WylFactOfflineRestoreJournal) retry = { 0 };
    input.offset = 0;
    input.mode = "success";
    g_assert_cmpint (wyl_fact_offline_restore_graph_import_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a", "zeta",
        f.capture.manifest, session_operation, 1, 0, &callbacks, &input, &retry), !=, WYRELOG_E_OK);
    g_assert_null (retry.graphs);
    session_assert_files_unchanged (&f, current);
  }
  if (success) {
    /* A bound stage is recovery-owned even if the caller offers valid A again. */
    g_auto (WylFactOfflineRestoreJournal) retry = { 0 };
    guint reads = input.reads, validations = input.validations;
    g_assert_cmpint (wyl_fact_offline_restore_graph_import_run
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, "tenant-a", "zeta",
        f.capture.manifest, session_operation, 2, 0, &callbacks, &input, &retry), ==, WYRELOG_E_POLICY);
    g_assert_null (retry.graphs);
    g_assert_cmpuint (input.reads, ==, reads);
    g_assert_cmpuint (input.validations, ==, validations);
    session_assert_files_unchanged (&f, current);
    wyl_fact_offline_restore_journal_clear (&f.committed);
    f.mode = "success";
    f.record_preflight = TRUE;
    g_assert_cmpint (wyl_fact_offline_restore_validation_session_new_for_preflight
          (f.fixture.policy, f.fixture.root, f.fixture.runtime, f.capture.manifest,
        session_operation, 2, 0, &f.session), ==, WYRELOG_E_OK);
    g_assert_cmpint (session_run_worker (&f), ==, WYRELOG_E_OK);
    g_assert_cmpuint (f.committed.revision, ==, 3);
    graph = g_ptr_array_index (f.committed.graphs, 0);
    g_assert_true (graph->replay_preflighted);
    g_clear_pointer (&f.session, wyl_fact_offline_restore_validation_session_free);
    session_assert_files_unchanged (&f, current);
  }
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (f.fixture.runtime, &sibling, &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (before.operation_generation, ==, after.operation_generation);
  g_assert_cmpuint (before.engine_generation, ==, after.engine_generation);
  g_assert_cmpint (before.admission, ==, after.admission);
  g_assert_cmpint (before.state, ==, after.state);
  wyl_fact_graph_runtime_status_clear (&before);
  wyl_fact_graph_runtime_status_clear (&after);
  wyl_fact_graph_key_clear (&sibling);
  wyl_fact_graph_key_clear (&selected);
  wyl_fact_offline_restore_journal_clear (&f.committed);
  g_clear_pointer (&f.journal_before, g_bytes_unref);
  f.journal_before = session_journal_bytes (&f);
  session_fixture_clear (&f);
}
#endif

static wyrelog_error_t
inspect_graph_commit (const WylFactGraphCommitInspection *inspection,
    gpointer user_data)
{
  WylFactGraphRestorePostPublishLayout *layout = user_data;
  g_assert_cmpstr (inspection->tenant_id, ==, "tenant-a");
  g_assert_cmpstr (inspection->graph_id, ==, "alpha");
  g_assert_cmpuint (inspection->old_main.object, !=, 0);
  g_assert_cmpuint (inspection->new_main.object, !=, 0);
  *layout = inspection->layout;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
inspect_graph_commit_held_authority
  (const WylFactGraphCommitInspection *inspection, gpointer user_data)
{
  BackupFixture *fixture = user_data;
  g_assert_cmpstr (inspection->graph_id, ==, "alpha");
  WylFactRootWriterLease *other = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture->root,
      &other), ==, WYRELOG_E_BUSY);
  g_assert_null (other);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "alpha"), ==,
      WYRELOG_E_OK);
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status
        (fixture->runtime, &key, &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&status);
  wyl_fact_graph_key_clear (&key);
  return WYRELOG_E_OK;
}

#ifdef WYL_TEST_HANDLE_SEAMS
static wyrelog_error_t
fail_companion_linked_once (const gchar *point, gpointer user_data)
{
  gboolean *fired = user_data;
  if (!*fired && g_strcmp0 (point, "restore-companion-linked") == 0) {
    *fired = TRUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
fail_sync_staged_after_begin_once (const gchar *point, gpointer user_data)
{
  gboolean *fired = user_data;
  if (!*fired && g_strcmp0 (point, "restore-sync-staged-after-begin") == 0) {
    *fired = TRUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
fail_sync_staged_after_fsync_once (const gchar *point, gpointer user_data)
{
  gboolean *fired = user_data;
  if (!*fired && g_strcmp0 (point, "restore-sync-staged-after-fsync") == 0) {
    *fired = TRUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
fail_retain_once (const gchar *point, gpointer user_data)
{
  const gchar **wanted = user_data;
  if (*wanted != NULL && g_str_equal (point, *wanted)) {
    *wanted = NULL;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}
#endif

typedef struct
{
  const gchar *policy_path;
  gboolean called;
} CompanionFenceProbe;

static wyrelog_error_t
probe_companion_policy_fence
  (const WylPolicyGraphRestoreReplacementRecord *current,
    gpointer user_data)
{
  CompanionFenceProbe *probe = user_data;
  g_assert_cmpstr (current->phase, ==, "reserved");
  sqlite3 *other = NULL;
  g_assert_cmpint (sqlite3_open_v2 (probe->policy_path, &other,
      SQLITE_OPEN_READWRITE, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_busy_timeout (other, 0), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (other, "BEGIN IMMEDIATE;", NULL, NULL,
      NULL), ==, SQLITE_BUSY);
  g_assert_cmpint (sqlite3_close (other), ==, SQLITE_OK);
  probe->called = TRUE;
  return WYRELOG_E_IO;
}

static void
import_restore_journal_for_test (wyl_policy_store_t *policy,
    const WylFactOfflineRestoreJournal *journal)
{
  g_autoptr (GBytes) blob = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (journal,
      &blob), ==, WYRELOG_E_OK);
  sqlite3_stmt *update = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (policy),
      "UPDATE fact_offline_restore_journals SET revision=?1,"
      "journal_blob=?2,updated_at=unixepoch() WHERE operation_uuid=?3;",
      -1, &update, NULL), ==, SQLITE_OK);
  gsize length = 0;
  const guint8 *data = g_bytes_get_data (blob, &length);
  g_assert_cmpint (sqlite3_bind_int64 (update, 1, journal->revision), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob64 (update, 2, data, length,
      SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (update, 3, journal->operation_uuid,
      -1, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (update), ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_changes (wyl_policy_store_get_db (policy)), ==, 1);
  sqlite3_finalize (update);
}

static wyrelog_error_t
selected_promotion_shape_for_test
  (const WylPolicyGraphRestoreReplacementRecord *current, gpointer data)
{
  g_assert_cmpstr (current->phase, ==, "selected_pending_cleanup");
  return *(const gboolean *) data ? WYRELOG_E_IO : WYRELOG_E_OK;
}

static void
test_graph_populated_schema_transition_roundtrip (void)
{
#ifndef __linux__
  return;
#else
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "restore-populated-graph-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "alpha");
  create_graph (&fixture, "zeta");
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    { "id", "symbol", FALSE, TRUE },
  };
  const wyl_policy_fact_relation_schema_query_t queries[] = {
    { "items_v2", "wr.datalog.query", 1000 },
  };
  const wyl_policy_fact_relation_schema_options_t v2 = {
    .tenant_id = "tenant-a", .graph_id = "alpha",
    .namespace_id = "backup", .relation_name = "items",
    .schema_version = 2, .relation_visible = TRUE,
    .columns = columns, .n_columns = G_N_ELEMENTS (columns),
    .queries = queries, .n_queries = G_N_ELEMENTS (queries),
  };
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema
        (fixture.policy, &v2), ==, WYRELOG_E_OK);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (fixture.policy,
      fixture.root, "tenant-a", "alpha", TRUE, &store), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_options_t v1 = {
    .tenant_id = "tenant-a", .graph_id = "alpha",
    .namespace_id = "backup", .relation_name = "items",
    .schema_version = 1, .relation_visible = TRUE,
    .columns = columns, .n_columns = G_N_ELEMENTS (columns),
  };
  const wyl_fact_value_t values[] = {
    { .type = WYL_FACT_VALUE_SYMBOL, .as.text = "restored-row" },
  };
  const wyl_fact_row_t rows[] = { { values, G_N_ELEMENTS (values) } };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "restored-batch", .tenant_id = "tenant-a",
    .graph_id = "alpha", .namespace_id = "backup",
    .relation_name = "items", .schema_version = 1, .source = "test",
    .idempotency_key = "roundtrip", .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows, .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean created = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &v1, &batch,
      &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  g_clear_pointer (&store, wyl_fact_store_close);
  seal_graph (&fixture, "alpha");
  seal_graph (&fixture, "zeta");
  seal_tenant (&fixture);
  const gchar *ids[] = { "alpha", "zeta" };
  for (guint i = 0; i < G_N_ELEMENTS (ids); i++) {
    WylFactGraphKey key = { 0 };
    g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", ids[i]),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh
          (fixture.runtime, &key, session_build_engine, NULL, NULL),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission
          (fixture.runtime, &key), ==, WYRELOG_E_OK);
    wyl_fact_graph_key_clear (&key);
  }
  g_autoptr (WylFactOfflineBackupSource) source = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_source_new (fixture.policy,
      fixture.root, fixture.runtime, "tenant-a", 0, &source), ==,
      WYRELOG_E_OK);
  DestinationCapture capture;
  destination_capture_init (&capture, &fixture, DESTINATION_FAIL_NONE);
  g_assert_cmpint (wyl_fact_offline_backup_generate (source,
      &capture_destination, &capture), ==, WYRELOG_E_OK);
  g_clear_pointer (&source, wyl_fact_offline_backup_source_free);
  WylPolicyRelationActivationRecord *active = NULL;
  g_assert_cmpint (wyl_policy_store_read_relation_activation
        (fixture.policy, "tenant-a", "alpha", "backup", "items",
      &active), ==, WYRELOG_E_OK);
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_transition_relation_activation
        (fixture.policy, "tenant-a", "alpha", "backup", "items",
      WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
      active->activation_generation,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
      TRUE, 1, TRUE, 2, "none", &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transition_relation_activation
        (fixture.policy, "tenant-a", "alpha", "backup", "items",
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
      active->activation_generation + 1,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
      TRUE, 2, FALSE, 0, "none", &mutation), ==, WYRELOG_E_OK);
  wyl_policy_relation_activation_record_free (active);
  g_autoptr (GError) error = NULL;
  g_autofree gchar *bundle_root = g_dir_make_tmp
        ("restore-populated-bundle-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *manifest_path = g_build_filename (bundle_root,
          "manifest", NULL);
  gsize manifest_length = 0;
  const guint8 *manifest_data = g_bytes_get_data (capture.manifest,
          &manifest_length);
  g_assert_true (g_file_set_contents (manifest_path,
      (const gchar *) manifest_data, manifest_length, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (manifest_path, 0600), ==, 0);
  for (guint i = 0; i < capture.completed_graphs->len; i++) {
    const gchar *id = g_ptr_array_index (capture.completed_graphs, i);
    GBytes *bytes = g_ptr_array_index (capture.artifact_bytes, i);
    g_autofree gchar *component = NULL;
    g_assert_cmpint (wyl_fact_graph_component_encode (id,
        &component), ==, WYRELOG_E_OK);
    g_autofree gchar *name = g_strdup_printf ("graph-%s.duckdb", component);
    g_autofree gchar *path = g_build_filename (bundle_root, name, NULL);
    gsize length = 0;
    const gchar *data = g_bytes_get_data (bytes, &length);
    g_assert_true (g_file_set_contents (path, data, length, &error));
    g_assert_no_error (error);
    g_assert_cmpint (g_chmod (path, 0600), ==, 0);
  }
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, manifest_data, manifest_length);
  guint8 digest[32];
  gsize digest_length = sizeof digest;
  g_checksum_get_digest (checksum, digest, &digest_length);
  g_autoptr (WylFactOfflineBackupBundle) bundle = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_bundle_open (bundle_root,
      digest, &bundle), ==, WYRELOG_E_OK);
  const gchar *operation = "018f22d0-7b6d-7a5b-8c31-123456789af1";
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_begin_run (fixture.policy,
      fixture.root, fixture.runtime, bundle,
      WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, "alpha", operation, TRUE, 0,
      &journal), ==, WYRELOG_E_OK);
  guint64 revision = journal.revision;
  wyl_fact_offline_restore_journal_clear (&journal);
  WylFactReplaySchedulerConfig config;
  wyl_fact_replay_scheduler_config_defaults (&config);
  g_autoptr (WylFactReplayScheduler) scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL,
      &scheduler), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_prepare_run (fixture.policy,
      fixture.root, fixture.runtime, scheduler, bundle, operation,
      revision, 0, NULL, &journal), ==, WYRELOG_E_OK);
  g_assert_true (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (journal.graphs, 0))->replay_preflighted);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  g_autofree gchar *old_uuid = NULL;
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db
        (fixture.policy), "SELECT op_uuid FROM fact_graph_provisioning "
      "WHERE tenant_id='tenant-a' AND graph_id='alpha' AND phase='active';",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  old_uuid = g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
  g_assert_cmpint (sqlite3_finalize (stmt), ==, SQLITE_OK);
  revision = journal.revision;
  g_assert_cmpint (wyl_fact_offline_restore_journal_bind_provisioned_old
        (&journal, "alpha", old_uuid), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreStoreResult result = 0;
  g_auto (WylFactOfflineRestoreJournal) bound = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (fixture.policy, revision, &journal, &result, &bound), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  wyl_fact_offline_restore_journal_clear (&journal);
  WylPolicyGraphRestoreReplacementRecord *replacement = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_replacement_reserve
        (fixture.policy, &bound, &result, &replacement), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  wyl_policy_graph_restore_replacement_record_free (replacement);
  /* Graph replacement COMMIT is admitted through its reserved companion.
   * The generic journal decision helper only admits absent-main graphs. */
  bound.decision = WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT;
  bound.revision++;
  import_restore_journal_for_test (fixture.policy, &bound);
  revision = bound.revision;
  for (guint step = 0; step < 16; step++) {
    g_auto (WylFactOfflineRestoreJournal) next = { 0 };
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (bound.graphs, 0);
    wyrelog_error_t rc = WYRELOG_E_INVALID;
    switch (graph->next_op) {
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
        rc = wyl_fact_offline_restore_graph_commit_sync_staged_run
              (fixture.policy, fixture.root, fixture.runtime, operation,
                revision, 0, &next);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
        rc = wyl_fact_offline_restore_graph_commit_retain_run
              (fixture.policy, fixture.root, fixture.runtime, operation,
                revision, 0, &next);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
        rc = wyl_fact_offline_restore_graph_commit_sync_retained_run
              (fixture.policy, fixture.root, fixture.runtime, operation,
                revision, 0, &next);
        break;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
        rc = wyl_fact_offline_restore_graph_commit_publish_run
              (fixture.policy, fixture.root, fixture.runtime, operation,
                revision, 0, &next);
        break;
      default:
        g_assert_not_reached ();
    }
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    revision = next.revision;
    wyl_fact_offline_restore_journal_clear (&bound);
    bound = next;
    memset (&next, 0, sizeof next);
    graph = g_ptr_array_index (bound.graphs, 0);
    if (graph->transition_state ==
        WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE)
      break;
  }
  WylPolicyGraphRestoreReplacementRecord *companion = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_companion_recover
        (fixture.policy, fixture.root, fixture.runtime, operation,
      revision, 0, &companion), ==, WYRELOG_E_OK);
  wyl_policy_graph_restore_replacement_record_free (companion);
  g_auto (WylFactOfflineRestoreJournal) selected = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_select_replacement_run
        (fixture.policy, fixture.root, fixture.runtime, operation,
      revision, 0, &selected), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) finalized = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_finalize_run
        (fixture.policy, fixture.root, fixture.runtime, operation,
      selected.revision, 0, &finalized), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) promoted = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_promote_run
        (fixture.policy, fixture.root, fixture.runtime, operation,
      finalized.revision, 0, &promoted), ==, WYRELOG_E_OK);
  g_assert_true (promoted.policy_generation_published);
  g_clear_pointer (&fixture.runtime, wyl_fact_graph_runtime_manager_unref);
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_read_relation_activation
        (fixture.policy, "tenant-a", "alpha", "backup", "items",
      &active), ==, WYRELOG_E_OK);
  g_assert_cmpuint (active->active_schema_version, ==, 1);
  wyl_policy_relation_activation_record_free (active);
  g_autofree gchar *main_path = graph_file_path (&fixture, "alpha",
          "facts.duckdb");
  duckdb_database db;
  duckdb_connection connection;
  duckdb_result query = { 0 };
  g_assert_cmpint (duckdb_open (main_path, &db), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_connect (db, &connection), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_query (connection,
      "SELECT COUNT(*) FROM fact_event_log WHERE batch_id='restored-batch';",
      &query), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_value_int64 (&query, 0, 0), ==, 1);
  duckdb_destroy_result (&query);
  duckdb_disconnect (&connection);
  duckdb_close (&db);
  g_clear_pointer (&bundle, wyl_fact_offline_backup_bundle_free);
  remove_tree (bundle_root);
  destination_capture_clear (&capture);
  fixture_clear (&fixture);
#endif
}

static void
test_graph_restore_replacement_reservation (gconstpointer data)
{
  gboolean ambiguous_commit = g_strcmp0 (data, "commit-response") == 0;
  gboolean schema_transition = g_strcmp0 (data, "schema-transition") == 0;
  BackupFixture fixture = { 0 };
  fixture_init (&fixture, "restore-replacement-XXXXXX");
  create_tenant (&fixture);
  create_graph (&fixture, "alpha");
  if (schema_transition) {
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      { "id", "symbol", FALSE, TRUE },
    };
    const wyl_policy_fact_relation_schema_query_t queries[] = {
      { "items_v2", "wr.datalog.query", 1000 },
    };
    const wyl_policy_fact_relation_schema_options_t schema = {
      .tenant_id = "tenant-a", .graph_id = "alpha",
      .namespace_id = "backup", .relation_name = "items",
      .schema_version = 2, .relation_visible = TRUE,
      .columns = columns, .n_columns = G_N_ELEMENTS (columns),
      .queries = queries, .n_queries = G_N_ELEMENTS (queries),
    };
    g_assert_cmpint (wyl_policy_store_register_fact_relation_schema
          (fixture.policy, &schema), ==, WYRELOG_E_OK);
  }
  seal_graph (&fixture, "alpha");
  seal_tenant (&fixture);

  WylFactGraphKey runtime_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&runtime_key, "tenant-a", "alpha"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (fixture.runtime,
      &runtime_key, session_build_engine, NULL, NULL), ==, WYRELOG_E_OK);
  wyl_fact_graph_key_clear (&runtime_key);

  WylPolicyTenantAuthorityRecord *tenant = NULL;
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (fixture.policy,
      "tenant-a", &tenant), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
      "tenant-a", "alpha", &authority), ==, WYRELOG_E_OK);
  sqlite3_stmt *old_stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (fixture.policy),
      "SELECT op_uuid FROM fact_graph_provisioning WHERE tenant_id='tenant-a' "
      "AND graph_id='alpha' AND phase='active';", -1, &old_stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (old_stmt), ==, SQLITE_ROW);
  g_autofree gchar *old_uuid = g_strdup ((const gchar *) sqlite3_column_text
            (old_stmt, 0));
  sqlite3_finalize (old_stmt);

  g_autofree gchar *main_path = graph_file_path (&fixture, "alpha",
          "facts.duckdb");
  GStatBuf old_stat = { 0 };
  g_assert_cmpint (g_stat (main_path, &old_stat), ==, 0);
  WylFactArtifactInventoryIdentity old_identity = {
    .domain = (guint64) old_stat.st_dev,
    .object = (guint64) old_stat.st_ino,
  };

  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init (&manifest,
      "tenant-a", 1), ==, WYRELOG_E_OK);
  WylPolicyFactBackupSnapshot *schema_snapshot = NULL;
  g_assert_cmpint (wyl_policy_store_read_fact_graph_backup_snapshot
        (fixture.policy, "tenant-a", "alpha", &schema_snapshot), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (schema_snapshot->graphs->len, ==, 1);
  const WylPolicyFactBackupGraphSnapshot *schema_graph =
      g_ptr_array_index (schema_snapshot->graphs, 0);
  WylFactOfflineBackupArtifact artifact = {
    .graph_id = "alpha", .store_uuid = authority->store_uuid,
    .format_version = authority->format_version,
    .path_encoding_version = authority->path_encoding_version,
    .schema_digest = schema_graph->active_schema_digest, .logical_bytes = 10,
    .physical_bytes = 4096, .checksum = "sha256:alpha",
  };
  if (schema_transition) {
    artifact.schema_selections = g_ptr_array_new_with_free_func
          ((GDestroyNotify) wyl_fact_offline_backup_schema_selection_free);
    WylFactOfflineBackupSchemaSelection *selection = g_new0
          (WylFactOfflineBackupSchemaSelection, 1);
    selection->namespace_id = g_strdup ("backup");
    selection->relation_name = g_strdup ("items");
    selection->schema_version = 1;
    g_ptr_array_add (artifact.schema_selections, selection);
  }
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add (&manifest,
      &artifact), ==, WYRELOG_E_OK);
  g_clear_pointer (&artifact.schema_selections, g_ptr_array_unref);
  g_autoptr (GBytes) manifest_bytes = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode (&manifest,
      &manifest_bytes), ==, WYRELOG_E_OK);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  wyl_policy_fact_backup_snapshot_free (schema_snapshot);
  if (schema_transition) {
    WylPolicyRelationActivationRecord *active = NULL;
    g_assert_cmpint (wyl_policy_store_read_relation_activation
          (fixture.policy, "tenant-a", "alpha", "backup", "items",
        &active), ==, WYRELOG_E_OK);
    WylPolicyAuthorityMutationResult mutation;
    g_assert_cmpint (wyl_policy_store_transition_relation_activation
          (fixture.policy, "tenant-a", "alpha", "backup", "items",
        WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
        active->activation_generation,
        WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
        TRUE, 1, TRUE, 2, "none", &mutation), ==, WYRELOG_E_OK);
    g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    g_assert_cmpint (wyl_policy_store_transition_relation_activation
          (fixture.policy, "tenant-a", "alpha", "backup", "items",
        WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
        active->activation_generation + 1,
        WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
        TRUE, 2, FALSE, 0, "none", &mutation), ==, WYRELOG_E_OK);
    g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    wyl_policy_relation_activation_record_free (active);
    wyl_policy_fact_relation_query_info_t query = { 0 };
    g_assert_cmpint (wyl_policy_store_load_fact_relation_query
          (fixture.policy, "tenant-a", "alpha", "items", &query), ==,
        WYRELOG_E_NOT_FOUND);
    g_assert_cmpint (wyl_policy_store_load_fact_relation_query
          (fixture.policy, "tenant-a", "alpha", "items_v2", &query), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (query.schema_version, ==, 2);
    wyl_policy_fact_relation_query_info_clear (&query);
  }
  g_autoptr (GPtrArray) targets = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_restore_target_graph_free);
  WylFactOfflineRestoreTargetGraph *target = g_new0
        (WylFactOfflineRestoreTargetGraph, 1);
  target->graph_id = g_strdup ("alpha");
  if (schema_transition) {
    WylPolicyFactBackupSnapshot *snapshot = NULL;
    g_assert_cmpint (wyl_policy_store_read_fact_graph_backup_snapshot
          (fixture.policy, "tenant-a", "alpha", &snapshot), ==,
        WYRELOG_E_OK);
    const WylPolicyFactBackupGraphSnapshot *entry =
        g_ptr_array_index (snapshot->graphs, 0);
    target->old_schema_digest = g_strdup (entry->active_schema_digest);
    wyl_policy_fact_backup_snapshot_free (snapshot);
  }
  target->lifecycle_generation = authority->lifecycle_generation;
  target->reconciliation_generation = authority->reconciliation_generation;
  target->expected_main_absent = FALSE;
  target->expected_main_identity = old_identity;
  g_ptr_array_add (targets, target);
  gchar operation_uuid[WYL_ID_STRING_BUF];
  wyl_id_t operation_id;
  g_assert_cmpint (wyl_id_new (&operation_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation_id, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
  g_autofree gchar *stage_basename = g_strdup_printf ("restore-%s.duckdb",
          operation_uuid);
  g_autofree gchar *stage_path = graph_file_path (&fixture, "alpha",
          stage_basename);
  g_assert_true (g_file_set_contents (stage_path, "replacement", -1, NULL));
  g_assert_cmpint (g_chmod (stage_path, 0600), ==, 0);
  GStatBuf stage_stat = { 0 };
  g_assert_cmpint (g_stat (stage_path, &stage_stat), ==, 0);
  WylFactArtifactInventoryIdentity new_identity = {
    .domain = (guint64) stage_stat.st_dev,
    .object = (guint64) stage_stat.st_ino,
  };
  g_auto (WylFactOfflineRestoreJournal) initial = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (&initial,
      manifest_bytes, operation_uuid, WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH,
      "alpha", tenant->lifecycle_generation,
      tenant->reconciliation_generation, targets,
      WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
  WylPolicyGraphRestoreReplacementRecord *premature = NULL;
  WylFactOfflineRestoreStoreResult premature_result = 0;
  g_assert_cmpint (wyl_fact_offline_restore_replacement_reserve
        (fixture.policy, &initial, &premature_result, &premature), ==,
      WYRELOG_E_POLICY);
  g_assert_null (premature);
  WylFactOfflineRestoreStoreResult result = 0;
  g_auto (WylFactOfflineRestoreJournal) current = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (fixture.policy, &initial, &result, &current), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  for (guint step = 0; step < 3; step++) {
    g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
    g_autoptr (GBytes) encoded = NULL;
    g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&current,
        &encoded), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_offline_restore_journal_decode (encoded,
        &desired), ==, WYRELOG_E_OK);
    if (step == 0) {
      g_assert_cmpint (wyl_fact_offline_restore_journal_bind_staged_identity
            (&desired, "alpha", &new_identity), ==, WYRELOG_E_OK);
    } else if (step == 1) {
      g_assert_cmpint (wyl_fact_offline_restore_journal_mark_preflight
            (&desired, "alpha"), ==, WYRELOG_E_OK);
    } else {
      g_assert_cmpint (wyl_fact_offline_restore_journal_bind_provisioned_old
            (&desired, "alpha", old_uuid), ==, WYRELOG_E_OK);
    }
    g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas (fixture.policy,
        current.revision, &desired, &result, &committed), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
    wyl_fact_offline_restore_journal_clear (&current);
    current = committed;
    memset (&committed, 0, sizeof committed);
  }
  WylPolicyGraphRestoreReplacementRecord *reserved = NULL;
  WylPolicyGraphRestoreReplacementRecord *rejected = NULL;
  g_autoptr (GBytes) current_blob = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&current,
      &current_blob), ==, WYRELOG_E_OK);
  WylPolicyOfflineRestoreStoreResult policy_result = 0;
  WylPolicyGraphRestoreReplacementReservation attempt = {
    .operation_uuid = current.operation_uuid,
    .tenant_id = current.tenant_id,
    .graph_id = "alpha",
    .old_provisioning_uuid = operation_uuid,
    .store_uuid = authority->store_uuid,
    .tenant_lifecycle_generation = tenant->lifecycle_generation,
    .tenant_reconciliation_generation = tenant->reconciliation_generation,
    .graph_lifecycle_generation = authority->lifecycle_generation,
    .graph_reconciliation_generation = authority->reconciliation_generation,
    .journal_revision = current.revision,
    .journal_blob = current_blob,
  };
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_reserve
        (fixture.policy, &attempt, &policy_result, &rejected), ==,
      WYRELOG_E_INVALID);
  g_assert_null (rejected);
  attempt.old_provisioning_uuid = old_uuid;
  attempt.graph_lifecycle_generation++;
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_reserve
        (fixture.policy, &attempt, &policy_result, &rejected), ==,
      WYRELOG_E_INVALID);
  g_assert_null (rejected);
  attempt.graph_lifecycle_generation--;
  g_autoptr (GBytes) wrong_blob = g_bytes_new_static ("wrong", 5);
  attempt.journal_blob = wrong_blob;
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_reserve
        (fixture.policy, &attempt, &policy_result, &rejected), ==,
      WYRELOG_E_INVALID);
  g_assert_null (rejected);
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_load
        (fixture.policy, operation_uuid, &rejected), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_offline_restore_replacement_reserve
        (fixture.policy, &current, &result, &reserved), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_assert_nonnull (reserved);
  g_assert_cmpstr (reserved->old_provisioning_uuid, ==, old_uuid);
  g_assert_cmpstr (reserved->phase, ==, "reserved");
  WylPolicyGraphRestoreReplacementRecord *replayed = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_replacement_reserve
        (fixture.policy, &current, &result, &replayed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_FACT_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY);
  g_assert_cmpstr (reserved->replacement_uuid, ==, replayed->replacement_uuid);
  WylPolicyGraphRestoreReplacementRecord *loaded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_replacement_load
        (fixture.policy, operation_uuid, &loaded), ==, WYRELOG_E_OK);
  g_assert_cmpstr (reserved->replacement_uuid, ==, loaded->replacement_uuid);
  wyl_policy_graph_restore_replacement_record_free (loaded);
  g_auto (WylFactOfflineRestoreJournal) early = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (current_blob,
      &early), ==, WYRELOG_E_OK);
  early.decision = WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT;
  early.revision++;
  g_autoptr (GBytes) early_blob = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&early,
      &early_blob), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) early_begin = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (early_blob,
      &early_begin), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_begin_attempt
        (&early_begin, "alpha", WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED),
      ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) early_result = { 0 };
  import_restore_journal_for_test (fixture.policy, &early);
  if (g_strcmp0 (data, "restart") == 0) {
    g_clear_pointer (&fixture.runtime, wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
  }
#ifdef __linux__
#ifdef WYL_TEST_HANDLE_SEAMS
  gboolean began_before_failure = FALSE;
  wyl_fact_offline_restore_graph_commit_sync_staged_set_checkpoint_for_test
    (fail_sync_staged_after_begin_once, &began_before_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_staged_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      early.revision, 0, &early_result), ==, WYRELOG_E_IO);
  wyl_fact_offline_restore_graph_commit_sync_staged_set_checkpoint_for_test
    (NULL, NULL);
  g_assert_true (began_before_failure);
  g_assert_null (early_result.graphs);
  g_auto (WylFactOfflineRestoreJournal) pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &pending), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournalGraph *pending_graph = g_ptr_array_index
        (pending.graphs, 0);
  g_assert_cmpint (pending_graph->attempt, ==,
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
  g_assert_cmpint (pending_graph->pending_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED);
  g_autofree gchar *parked_stage = graph_file_path (&fixture, "alpha",
          "parked-restore-stage");
  g_assert_cmpint (g_rename (stage_path, parked_stage), ==, 0);
  g_assert_true (g_file_set_contents (stage_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (stage_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_staged_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      pending.revision, 0, &early_result), !=, WYRELOG_E_OK);
  g_assert_null (early_result.graphs);
  g_assert_cmpint (g_remove (stage_path), ==, 0);
  g_assert_cmpint (g_rename (parked_stage, stage_path), ==, 0);
  g_autofree gchar *old_companion_basename = g_strdup_printf
        ("provision-%s.sqlite", old_uuid);
  g_autofree gchar *old_companion = graph_file_path (&fixture, "alpha",
          old_companion_basename);
  g_autofree gchar *parked_companion = graph_file_path (&fixture, "alpha",
          "parked-old-companion");
  g_assert_cmpint (g_rename (old_companion, parked_companion), ==, 0);
  g_assert_true (g_file_set_contents (old_companion, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (old_companion, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_staged_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      pending.revision, 0, &early_result), !=, WYRELOG_E_OK);
  g_assert_null (early_result.graphs);
  g_assert_cmpint (g_remove (old_companion), ==, 0);
  g_assert_cmpint (g_rename (parked_companion, old_companion), ==, 0);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_STAGED_FSYNC);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_staged_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      pending.revision, 0, &early_result), !=, WYRELOG_E_OK);
  g_assert_null (early_result.graphs);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  gboolean synced_before_failure = FALSE;
  wyl_fact_offline_restore_graph_commit_sync_staged_set_checkpoint_for_test
    (fail_sync_staged_after_fsync_once, &synced_before_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_staged_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      pending.revision, 0, &early_result), ==, WYRELOG_E_IO);
  wyl_fact_offline_restore_graph_commit_sync_staged_set_checkpoint_for_test
    (NULL, NULL);
  g_assert_true (synced_before_failure);
  g_assert_null (early_result.graphs);
#endif
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_staged_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
#ifdef WYL_TEST_HANDLE_SEAMS
      pending.revision, 0, &early_result), ==, WYRELOG_E_OK);
#else
      early.revision, 0, &early_result), ==, WYRELOG_E_OK);
#endif
  WylFactOfflineRestoreJournalGraph *early_graph = g_ptr_array_index
        (early_result.graphs, 0);
  g_assert_cmpint (early_graph->transition_state, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY);
  g_assert_cmpint (early_graph->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN);
  g_auto (WylFactOfflineRestoreJournal) retained = { 0 };
  const gchar *retain_failure = "restore-retain-after-begin";
  wyl_fact_offline_restore_graph_commit_retain_set_checkpoint_for_test
    (fail_retain_once, &retain_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_retain_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      early_result.revision, 0, &retained), ==, WYRELOG_E_IO);
  g_assert_null (retain_failure);
  g_assert_null (retained.graphs);
  wyl_fact_offline_restore_graph_commit_retain_set_checkpoint_for_test
    (NULL, NULL);
  g_auto (WylFactOfflineRestoreJournal) retain_pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &retain_pending), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_STAGED_FSYNC);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_retain_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      retain_pending.revision, 0, &retained), !=, WYRELOG_E_OK);
  g_assert_null (retained.graphs);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  wyl_fact_offline_restore_journal_clear (&retain_pending);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &retain_pending), ==,
      WYRELOG_E_OK);
  WylFactOfflineRestoreJournalGraph *retain_pending_graph =
      g_ptr_array_index (retain_pending.graphs, 0);
  g_assert_cmpint (retain_pending_graph->attempt, ==,
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
  g_assert_cmpint (retain_pending_graph->pending_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN);
  retain_failure = "restore-retain-after-rename";
  wyl_fact_offline_restore_graph_commit_retain_set_checkpoint_for_test
    (fail_retain_once, &retain_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_retain_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      retain_pending.revision, 0, &retained), ==, WYRELOG_E_IO);
  g_assert_null (retain_failure);
  g_assert_null (retained.graphs);
  wyl_fact_offline_restore_graph_commit_retain_set_checkpoint_for_test
    (NULL, NULL);
  g_autofree gchar *retained_rollback_name = g_strdup_printf
        ("restore-%s.duckdb.superseded", operation_uuid);
  g_autofree gchar *retained_rollback_path = graph_file_path (&fixture,
          "alpha", retained_rollback_name);
  g_autofree gchar *parked_rollback_path = graph_file_path (&fixture,
          "alpha", "parked-rollback-test");
  g_assert_cmpint (g_rename (retained_rollback_path,
      parked_rollback_path), ==, 0);
  g_assert_true (g_file_set_contents (retained_rollback_path,
      "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (retained_rollback_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_retain_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      retain_pending.revision, 0, &retained), !=, WYRELOG_E_OK);
  g_assert_null (retained.graphs);
  g_assert_cmpint (g_remove (retained_rollback_path), ==, 0);
  g_assert_cmpint (g_rename (parked_rollback_path,
      retained_rollback_path), ==, 0);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_RETAIN_DIR_FSYNC);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_retain_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      retain_pending.revision, 0, &retained), !=, WYRELOG_E_OK);
  g_assert_null (retained.graphs);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_retain_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      retain_pending.revision, 0, &retained), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournalGraph *retained_graph =
      g_ptr_array_index (retained.graphs, 0);
  g_assert_cmpint (retained_graph->transition_state, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED);
  g_assert_cmpint (retained_graph->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE);
  g_auto (WylFactOfflineRestoreJournal) synced_rollback = { 0 };
  const gchar *sync_failure = "restore-sync-retained-after-begin";
  wyl_fact_offline_restore_graph_commit_sync_retained_set_checkpoint_for_test
    (fail_retain_once, &sync_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_retained_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      retained.revision, 0, &synced_rollback), ==, WYRELOG_E_IO);
  g_assert_null (sync_failure);
  wyl_fact_offline_restore_graph_commit_sync_retained_set_checkpoint_for_test
    (NULL, NULL);
  g_auto (WylFactOfflineRestoreJournal) rollback_pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &rollback_pending), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (rollback_pending.graphs, 0))->pending_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_ROLLBACK_FSYNC);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_retained_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      rollback_pending.revision, 0, &synced_rollback), !=, WYRELOG_E_OK);
  g_assert_null (synced_rollback.graphs);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  sync_failure = "restore-sync-retained-after-fsync";
  wyl_fact_offline_restore_graph_commit_sync_retained_set_checkpoint_for_test
    (fail_retain_once, &sync_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_retained_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      rollback_pending.revision, 0, &synced_rollback), ==, WYRELOG_E_IO);
  g_assert_null (sync_failure);
  wyl_fact_offline_restore_graph_commit_sync_retained_set_checkpoint_for_test
    (NULL, NULL);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_retained_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      rollback_pending.revision, 0, &synced_rollback), ==, WYRELOG_E_OK);
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (synced_rollback.graphs, 0))->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR);
  g_auto (WylFactOfflineRestoreJournal) synced_directory = { 0 };
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_RETAIN_DIR_FSYNC);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_retained_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      synced_rollback.revision, 0, &synced_directory), !=, WYRELOG_E_OK);
  g_assert_null (synced_directory.graphs);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  g_auto (WylFactOfflineRestoreJournal) directory_pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &directory_pending), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_sync_retained_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      directory_pending.revision, 0, &synced_directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (synced_directory.graphs, 0))->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH);
  g_auto (WylFactOfflineRestoreJournal) published_by_driver = { 0 };
  const gchar *publish_failure = "restore-publish-after-begin";
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (fail_retain_once, &publish_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      synced_directory.revision, 0, &published_by_driver), ==,
      WYRELOG_E_IO);
  g_assert_null (publish_failure);
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (NULL, NULL);
  g_auto (WylFactOfflineRestoreJournal) publish_pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &publish_pending), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_PUBLISH_RENAME);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_pending.revision, 0, &published_by_driver), !=,
      WYRELOG_E_OK);
  g_assert_null (published_by_driver.graphs);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  publish_failure = "restore-publish-after-rename";
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (fail_retain_once, &publish_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_pending.revision, 0, &published_by_driver), ==,
      WYRELOG_E_IO);
  g_assert_null (publish_failure);
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (NULL, NULL);
  g_assert_null (published_by_driver.graphs);
  g_autofree gchar *parked_published_main = graph_file_path (&fixture,
          "alpha", "parked-published-main-test");
  g_assert_cmpint (g_rename (main_path, parked_published_main), ==, 0);
  g_assert_true (g_file_set_contents (main_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (main_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_pending.revision, 0, &published_by_driver), !=,
      WYRELOG_E_OK);
  g_assert_cmpint (g_remove (main_path), ==, 0);
  g_assert_cmpint (g_rename (parked_published_main, main_path), ==, 0);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_PUBLISH_DIR_FSYNC);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_pending.revision, 0, &published_by_driver), !=,
      WYRELOG_E_OK);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_pending.revision, 0, &published_by_driver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (published_by_driver.graphs, 0))->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR);
  g_auto (WylFactOfflineRestoreJournal) synced_published = { 0 };
  publish_failure = "restore-publish-after-begin";
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (fail_retain_once, &publish_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published_by_driver.revision, 0, &synced_published), ==,
      WYRELOG_E_IO);
  g_assert_null (publish_failure);
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (NULL, NULL);
  g_auto (WylFactOfflineRestoreJournal) publish_sync_pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &publish_sync_pending), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_PUBLISH_DIR_FSYNC);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_sync_pending.revision, 0, &synced_published), !=,
      WYRELOG_E_OK);
  wyl_fact_artifact_transition_posix_set_test_fault
    (WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE);
  publish_failure = "restore-publish-after-fsync";
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (fail_retain_once, &publish_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_sync_pending.revision, 0, &synced_published), ==,
      WYRELOG_E_IO);
  g_assert_null (publish_failure);
  wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
    (NULL, NULL);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_publish_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      publish_sync_pending.revision, 0, &synced_published), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (synced_published.graphs, 0))->transition_state, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE);
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (synced_published.graphs, 0))->next_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE);
#else
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (fixture.policy, early.revision, &early_begin, &result,
      &early_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
#endif
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&early_result),
      ==, WYL_FACT_OFFLINE_RESTORE_RECOVERY_INSPECT_ONLY);
  /* Imported historical durable COMMIT shape for companion recovery. */
  g_auto (WylFactOfflineRestoreJournal) published = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode (current_blob,
      &published), ==, WYRELOG_E_OK);
  WylFactOfflineRestoreJournalGraph *published_graph =
      g_ptr_array_index (published.graphs, 0);
  published.decision = WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT;
#ifdef __linux__
  published.revision = synced_published.revision + 1;
#else
  published.revision = early_result.revision + 1;
#endif
  published_graph->transition_state =
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE;
  published_graph->next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE;
  published_graph->attempt = WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED;
  published_graph->copied = TRUE;
  published_graph->checksum_verified = TRUE;
  published_graph->identity_verified = TRUE;
  published_graph->schema_verified = TRUE;
  g_autoptr (GBytes) published_blob = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode (&published,
      &published_blob), ==, WYRELOG_E_OK);
  import_restore_journal_for_test (fixture.policy, &published);
#ifdef __linux__
  /* Synthetic imported COMMIT: normal mode-A admission still refuses it. */
  g_autofree gchar *rollback_basename = g_strdup_printf
        ("restore-%s.duckdb.superseded", operation_uuid);
  g_autofree gchar *rollback_path = graph_file_path (&fixture, "alpha",
          rollback_basename);
  WylFactGraphRestorePostPublishLayout observed =
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_inspect
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision + 1, 0, inspect_graph_commit, &observed), !=,
      WYRELOG_E_OK);
  g_assert_cmpint (observed, ==,
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_inspect
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, inspect_graph_commit, &observed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (observed, ==,
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_MAIN_ONE_LINK);
  g_autofree gchar *foreign_path = graph_file_path (&fixture, "alpha",
          "foreign-file");
  g_assert_true (g_file_set_contents (foreign_path, "foreign", -1, NULL));
  observed = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_inspect
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, inspect_graph_commit, &observed), !=,
      WYRELOG_E_OK);
  g_assert_cmpint (observed, ==,
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID);
  g_assert_cmpint (g_remove (foreign_path), ==, 0);
  g_autofree gchar *replacement_basename = g_strdup_printf
        ("provision-%s.sqlite", reserved->replacement_uuid);
  g_autofree gchar *replacement_path = graph_file_path (&fixture, "alpha",
          replacement_basename);
  WylPolicyOfflineRestoreRecord *fence_journal = NULL;
  g_assert_cmpint (wyl_policy_store_offline_restore_load (fixture.policy,
      operation_uuid, &fence_journal), ==, WYRELOG_E_OK);
  g_autofree gchar *fence_policy_path = g_build_filename (fixture.root,
          "policy.db", NULL);
  CompanionFenceProbe probe = { .policy_path = fence_policy_path };
  WylPolicyGraphRestoreReplacementRecord *fence_result = NULL;
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_sync_with_effect
        (fixture.policy, reserved, fence_journal,
      probe_companion_policy_fence, &probe, &policy_result, &fence_result), ==,
      WYRELOG_E_IO);
  g_assert_true (probe.called);
  g_assert_null (fence_result);
  g_assert_false (g_file_test (replacement_path, G_FILE_TEST_EXISTS));
  wyl_policy_offline_restore_record_free (fence_journal);
  WylPolicyGraphRestoreReplacementRecord *recovered = NULL;
#ifdef WYL_TEST_HANDLE_SEAMS
  gboolean linked_before_failure = FALSE;
  wyl_fact_offline_restore_graph_commit_companion_set_checkpoint_for_test
    (fail_companion_linked_once, &linked_before_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_companion_recover
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, &recovered), ==, WYRELOG_E_IO);
  wyl_fact_offline_restore_graph_commit_companion_set_checkpoint_for_test
    (NULL, NULL);
  g_assert_true (linked_before_failure);
  g_assert_null (recovered);
  g_assert_true (g_file_test (replacement_path, G_FILE_TEST_IS_REGULAR));
  WylPolicyGraphRestoreReplacementRecord *after_link = NULL;
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_load
        (fixture.policy, operation_uuid, &after_link), ==, WYRELOG_E_OK);
  g_assert_cmpstr (after_link->phase, ==, "reserved");
  wyl_policy_graph_restore_replacement_record_free (after_link);
  if (g_strcmp0 (data, "restart") == 0) {
    g_clear_pointer (&fixture.runtime, wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
  }
#endif
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_companion_recover
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, &recovered), ==, WYRELOG_E_OK);
  g_assert_nonnull (recovered);
  g_assert_cmpstr (recovered->phase, ==, "companion_synced");
  wyl_policy_graph_restore_replacement_record_free (recovered);
  g_assert_true (g_file_test (replacement_path, G_FILE_TEST_IS_REGULAR));
  observed = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_inspect
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, inspect_graph_commit, &observed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (observed, ==,
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_inspect
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, inspect_graph_commit_held_authority,
      &fixture), ==, WYRELOG_E_OK);
  WylFactRootWriterLease *released = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture.root,
      &released), ==, WYRELOG_E_OK);
  wyl_fact_root_writer_lease_release (released);
#endif
  WylPolicyOfflineRestoreRecord *published_record = NULL;
  g_assert_cmpint (wyl_policy_store_offline_restore_load (fixture.policy,
      operation_uuid, &published_record), ==, WYRELOG_E_OK);
  WylPolicyGraphRestoreReplacementRecord *synced = NULL;
  published_record->revision--;
  g_assert_cmpint
    (wyl_policy_store_graph_restore_replacement_mark_companion_synced
        (fixture.policy, reserved, published_record, &policy_result,
      &synced), ==, WYRELOG_E_INVALID);
  g_assert_null (synced);
  published_record->revision++;
  gchar *reserved_replacement = reserved->replacement_uuid;
  reserved->replacement_uuid = operation_uuid;
  g_assert_cmpint
    (wyl_policy_store_graph_restore_replacement_mark_companion_synced
        (fixture.policy, reserved, published_record, &policy_result,
      &synced), ==, WYRELOG_E_OK);
  g_assert_cmpint (policy_result, ==,
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT);
  g_assert_null (synced);
  reserved->replacement_uuid = reserved_replacement;
  g_assert_cmpint
    (wyl_policy_store_graph_restore_replacement_mark_companion_synced
        (fixture.policy, reserved, published_record, &policy_result,
      &synced), ==, WYRELOG_E_OK);
  g_assert_cmpint (policy_result, ==,
      WYL_POLICY_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY);
  g_assert_cmpstr (synced->phase, ==, "companion_synced");
  g_assert_cmpstr (synced->replacement_uuid, ==, reserved->replacement_uuid);
#ifdef __linux__
  observed = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_inspect
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, inspect_graph_commit, &observed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (observed, ==,
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_DUAL_COMPANION);
  g_assert_cmpint (g_remove (replacement_path), ==, 0);
  observed = WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID;
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_inspect
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, inspect_graph_commit, &observed), !=,
      WYRELOG_E_OK);
  g_assert_cmpint (observed, ==,
      WYL_FACT_GRAPH_RESTORE_POST_PUBLISH_INVALID);
  recovered = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_companion_recover
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, &recovered), !=, WYRELOG_E_OK);
  g_assert_null (recovered);
  g_assert_cmpint (link (main_path, replacement_path), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_companion_recover
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpstr (recovered->phase, ==, "companion_synced");
  wyl_policy_graph_restore_replacement_record_free (recovered);
#endif
  WylPolicyGraphRestoreReplacementRecord *synced_replay = NULL;
  g_assert_cmpint
    (wyl_policy_store_graph_restore_replacement_mark_companion_synced
        (fixture.policy, reserved, published_record, &policy_result,
      &synced_replay), ==, WYRELOG_E_OK);
  g_assert_cmpint (policy_result, ==,
      WYL_POLICY_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY);
  g_assert_cmpstr (synced_replay->phase, ==, "companion_synced");
  wyl_policy_graph_restore_replacement_record_free (synced_replay);
  wyl_policy_graph_restore_replacement_record_free (synced);
  wyl_policy_offline_restore_record_free (published_record);
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  g_autofree gchar *policy_path = g_build_filename (fixture.root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  loaded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_replacement_load
        (fixture.policy, operation_uuid, &loaded), ==, WYRELOG_E_OK);
  g_assert_cmpstr (reserved->replacement_uuid, ==, loaded->replacement_uuid);
  g_assert_cmpstr (loaded->phase, ==, "companion_synced");
  published_record = NULL;
  g_assert_cmpint (wyl_policy_store_offline_restore_load (fixture.policy,
      operation_uuid, &published_record), ==, WYRELOG_E_OK);
  synced_replay = NULL;
  g_assert_cmpint
    (wyl_policy_store_graph_restore_replacement_mark_companion_synced
        (fixture.policy, reserved, published_record, &policy_result,
      &synced_replay), ==, WYRELOG_E_OK);
  g_assert_cmpint (policy_result, ==,
      WYL_POLICY_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY);
  wyl_policy_graph_restore_replacement_record_free (synced_replay);
  wyl_policy_offline_restore_record_free (published_record);
  wyl_policy_graph_restore_replacement_record_free (loaded);
#ifdef __linux__
  if (g_strcmp0 (data, "restart") == 0) {
    g_clear_pointer (&fixture.runtime, wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
  }
  g_auto (WylFactOfflineRestoreJournal) selected = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_select_replacement_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision + 1, 0, &selected), !=, WYRELOG_E_OK);
  g_assert_true (g_file_set_contents (foreign_path, "foreign", -1, NULL));
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_select_replacement_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, &selected), !=, WYRELOG_E_OK);
  g_assert_cmpint (g_remove (foreign_path), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_select_replacement_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, &selected), ==, WYRELOG_E_OK);
  g_assert_cmpuint (selected.version, ==,
      WYL_FACT_OFFLINE_RESTORE_JOURNAL_SELECTED_VERSION);
  g_assert_true (selected.replacement_selected_pending_cleanup);
  g_assert_true (g_file_test (main_path, G_FILE_TEST_IS_REGULAR));
  g_assert_true (g_file_test (rollback_path, G_FILE_TEST_IS_REGULAR));
  g_assert_true (g_file_test (replacement_path, G_FILE_TEST_IS_REGULAR));
  g_autoptr (GPtrArray) selected_rows = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list_for_graph
        (fixture.policy, "tenant-a", "alpha", &selected_rows), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (selected_rows->len, ==, 1);
  const WylPolicyGraphProvisioningRecord *selected_row =
      g_ptr_array_index (selected_rows, 0);
  g_assert_cmpint (selected_row->phase, ==,
      WYL_POLICY_GRAPH_PROVISIONING_RESTORE_SELECTED);
  g_assert_cmpstr (selected_row->op_uuid, ==, reserved->replacement_uuid);
  WylPolicyGraphRestoreReplacementRecord *selected_replacement = NULL;
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_load
        (fixture.policy, operation_uuid, &selected_replacement), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (selected_replacement->phase, ==,
      "selected_pending_cleanup");
  wyl_policy_graph_restore_replacement_record_free (selected_replacement);
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) reopened_selected = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &reopened_selected), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (reopened_selected.revision, ==, selected.revision);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_select_replacement_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      published.revision, 0, &reopened_selected), !=, WYRELOG_E_OK);
  if (g_strcmp0 (data, "restart") == 0) {
    g_clear_pointer (&fixture.runtime, wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
  }
  g_auto (WylFactOfflineRestoreJournal) finalized = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_finalize_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      selected.revision + 1, 0, &finalized), !=, WYRELOG_E_OK);
#ifdef WYL_TEST_HANDLE_SEAMS
  const gchar *finalize_failure = "restore-selected-after-companion-unlink";
  wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
    (fail_retain_once, &finalize_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_finalize_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      selected.revision, 0, &finalized), ==, WYRELOG_E_IO);
  g_assert_null (finalize_failure);
  wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
    (NULL, NULL);
  g_auto (WylFactOfflineRestoreJournal) finalize_pending = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (fixture.policy, operation_uuid, &finalize_pending), ==,
      WYRELOG_E_OK);
  WylFactOfflineRestoreJournalGraph *finalize_pending_graph =
      g_ptr_array_index (finalize_pending.graphs, 0);
  g_assert_cmpint (finalize_pending_graph->attempt, ==,
      WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN);
  g_assert_cmpint (finalize_pending_graph->pending_op, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE);
  g_assert_false (g_file_test (old_companion, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_test (rollback_path, G_FILE_TEST_IS_REGULAR));
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  if (g_strcmp0 (data, "restart") == 0) {
    g_clear_pointer (&fixture.runtime, wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
  }
  finalize_failure = "restore-selected-after-rollback-unlink";
  wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
    (fail_retain_once, &finalize_failure);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_finalize_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      finalize_pending.revision, 0, &finalized), ==, WYRELOG_E_IO);
  g_assert_null (finalize_failure);
  wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
    (NULL, NULL);
  g_assert_false (g_file_test (rollback_path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_finalize_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      finalize_pending.revision, 0, &finalized), ==, WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_finalize_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      selected.revision, 0, &finalized), ==, WYRELOG_E_OK);
#endif
  g_assert_cmpint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (finalized.graphs, 0))->transition_state, ==,
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED);
  g_assert_true (g_file_test (main_path, G_FILE_TEST_IS_REGULAR));
  g_assert_true (g_file_test (replacement_path, G_FILE_TEST_IS_REGULAR));
  g_assert_false (g_file_test (rollback_path, G_FILE_TEST_EXISTS));
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  if (g_strcmp0 (data, "restart") == 0) {
    g_clear_pointer (&fixture.runtime, wyl_fact_graph_runtime_manager_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.runtime),
        ==, WYRELOG_E_OK);
  }
  WylPolicyGraphRestoreReplacementRecord *promote_row = NULL;
  WylPolicyOfflineRestoreRecord *promote_journal = NULL;
  g_assert_cmpint (wyl_policy_store_graph_restore_replacement_load
        (fixture.policy, operation_uuid, &promote_row), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_offline_restore_load (fixture.policy,
      operation_uuid, &promote_journal), ==, WYRELOG_E_OK);
  if (g_strcmp0 (data, "restart") == 0) {
    g_assert_cmpint (wyl_policy_store_graph_restore_reacquire_v3_prove
          (fixture.policy, operation_uuid, promote_journal->journal_blob,
        promote_row), ==, WYRELOG_E_OK);
    WylPolicyGraphRestoreReplacementRecord stale_row = *promote_row;
    stale_row.graph_lifecycle_generation++;
    g_assert_cmpint (wyl_policy_store_graph_restore_reacquire_v3_prove
          (fixture.policy, operation_uuid, promote_journal->journal_blob,
        &stale_row), !=, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_graph_restore_reacquire_v3_prove
          (fixture.policy, operation_uuid, published_blob, promote_row), !=,
        WYRELOG_E_OK);
    WylPolicyGraphRestoreReplacementRecord *still_selected = NULL;
    g_assert_cmpint (wyl_policy_store_graph_restore_replacement_load
          (fixture.policy, operation_uuid, &still_selected), ==,
        WYRELOG_E_OK);
    g_assert_cmpstr (still_selected->phase, ==,
        "selected_pending_cleanup");
    wyl_policy_graph_restore_replacement_record_free (still_selected);
  }
  sqlite3 *promotion_db = wyl_policy_store_get_db (fixture.policy);
  g_assert_cmpint (sqlite3_exec (promotion_db,
      "UPDATE fact_graph_provisioning SET phase='active' "
      "WHERE phase='restore_selected';", NULL, NULL, NULL), !=, SQLITE_OK);
  gboolean reject_shape = TRUE;
  WylPolicyOfflineRestoreStoreResult promotion_result =
      WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  g_assert_cmpint
    (wyl_policy_store_graph_restore_selected_promote_with_effect
        (fixture.policy, promote_row, promote_journal,
      selected_promotion_shape_for_test, &reject_shape,
      &promotion_result), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  reject_shape = FALSE;
  g_auto (WylFactOfflineRestoreJournal) promoted = { 0 };
  g_assert_true (g_file_set_contents (foreign_path, "foreign", -1, NULL));
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_promote_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      finalized.revision, 0, &promoted), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (foreign_path), ==, 0);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_promote_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      finalized.revision + 1, 0, &promoted), ==, WYRELOG_E_POLICY);
  if (schema_transition) {
    sqlite3 *db = wyl_policy_store_get_db (fixture.policy);
    g_assert_cmpint (sqlite3_exec (db,
        "UPDATE fact_relation_schema_columns SET column_type='int64' "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha' "
        "AND namespace_id='backup' AND relation_name='items' "
        "AND schema_version=1 AND column_index=0;",
        NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (db), ==, 1);
    g_assert_cmpint (wyl_fact_offline_restore_graph_commit_promote_run
          (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
        finalized.revision, 0, &promoted), ==, WYRELOG_E_POLICY);
    WylPolicyRelationActivationRecord *active = NULL;
    g_assert_cmpint (wyl_policy_store_read_relation_activation
          (fixture.policy, "tenant-a", "alpha", "backup", "items",
        &active), ==, WYRELOG_E_OK);
    g_assert_cmpuint (active->active_schema_version, ==, 2);
    wyl_policy_relation_activation_record_free (active);
    g_assert_cmpint (sqlite3_exec (db,
        "UPDATE fact_relation_schema_columns SET column_type='symbol' "
        "WHERE tenant_id='tenant-a' AND graph_id='alpha' "
        "AND namespace_id='backup' AND relation_name='items' "
        "AND schema_version=1 AND column_index=0;",
        NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_changes (db), ==, 1);
    /* Abort the second activation update after the first has run inside
     * promotion. The surrounding policy transaction must restore v2. */
    g_assert_cmpint (sqlite3_exec (db,
        "CREATE TEMP TRIGGER fail_selected_activation "
        "BEFORE UPDATE ON fact_relation_activation "
        "WHEN OLD.lifecycle_state='activating' "
        "AND NEW.active_schema_version=1 "
        "BEGIN SELECT RAISE(ABORT,'activation fault'); END;",
        NULL, NULL, NULL), ==, SQLITE_OK);
    g_assert_cmpint (wyl_fact_offline_restore_graph_commit_promote_run
          (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
        finalized.revision, 0, &promoted), !=, WYRELOG_E_OK);
    WylPolicyRelationActivationRecord *after_fault = NULL;
    g_assert_cmpint (wyl_policy_store_read_relation_activation
          (fixture.policy, "tenant-a", "alpha", "backup", "items",
        &after_fault), ==, WYRELOG_E_OK);
    g_assert_cmpint (after_fault->lifecycle_state, ==,
        WYL_POLICY_RELATION_ACTIVATION_ACTIVE);
    g_assert_cmpuint (after_fault->active_schema_version, ==, 2);
    wyl_policy_relation_activation_record_free (after_fault);
    g_auto (WylFactOfflineRestoreJournal) after_fault_journal = { 0 };
    g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
          (fixture.policy, operation_uuid, &after_fault_journal), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (after_fault_journal.revision, ==, finalized.revision);
    g_assert_false (after_fault_journal.policy_generation_published);
    g_assert_cmpint (sqlite3_exec (db,
        "DROP TRIGGER fail_selected_activation;", NULL, NULL, NULL), ==,
        SQLITE_OK);
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  if (ambiguous_commit)
    wyl_policy_store_offline_restore_fail_once (fixture.policy,
        WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
#endif
  wyrelog_error_t promote_rc =
      wyl_fact_offline_restore_graph_commit_promote_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
          finalized.revision, 0, &promoted);
  if (ambiguous_commit)
    g_assert_cmpint (promote_rc, ==, WYRELOG_E_IO);
  else {
    g_assert_cmpint (promote_rc, ==, WYRELOG_E_OK);
    g_assert_cmpuint (promoted.revision, ==, finalized.revision + 2);
    g_assert_true (promoted.policy_generation_published);
    g_assert_true (promoted.lifecycle_handoff_complete);
  }
  g_clear_pointer (&fixture.policy, wyl_policy_store_close);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_graph_commit_promote_run
        (fixture.policy, fixture.root, fixture.runtime, operation_uuid,
      finalized.revision, 0, &promoted), ==, WYRELOG_E_POLICY);
  promotion_result = WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT;
  g_assert_cmpint
    (wyl_policy_store_graph_restore_selected_promote_with_effect
        (fixture.policy, promote_row, promote_journal,
      selected_promotion_shape_for_test, &reject_shape,
      &promotion_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (promotion_result, ==,
      WYL_POLICY_OFFLINE_RESTORE_STORE_STALE);
  wyl_policy_offline_restore_record_free (promote_journal);
  wyl_policy_graph_restore_replacement_record_free (promote_row);
  sqlite3 *reopened_db = wyl_policy_store_get_db (fixture.policy);
  g_assert_cmpint (sqlite3_exec (reopened_db, "BEGIN IMMEDIATE;",
      NULL, NULL, NULL), ==, SQLITE_OK);
  sqlite3_stmt *stale_claim = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (reopened_db,
      "INSERT INTO fact_offline_restore_graph_claims "
      "(tenant_id,graph_id,operation_uuid) VALUES ('tenant-a','alpha',?1);",
      -1, &stale_claim, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stale_claim, 1, operation_uuid,
      -1, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stale_claim), ==, SQLITE_DONE);
  sqlite3_finalize (stale_claim);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (sqlite3_exec (reopened_db, "ROLLBACK;", NULL, NULL,
      NULL), ==, SQLITE_OK);
#endif
  if (schema_transition) {
    WylPolicyRelationActivationRecord *active = NULL;
    g_assert_cmpint (wyl_policy_store_read_relation_activation
          (fixture.policy, "tenant-a", "alpha", "backup", "items",
        &active), ==, WYRELOG_E_OK);
    g_assert_true (active->has_active_schema_version);
    g_assert_cmpuint (active->active_schema_version, ==, 1);
    wyl_policy_relation_activation_record_free (active);
    wyl_policy_fact_relation_query_info_t query = { 0 };
    g_assert_cmpint (wyl_policy_store_load_fact_relation_query
          (fixture.policy, "tenant-a", "alpha", "items_v2", &query), ==,
        WYRELOG_E_NOT_FOUND);
    g_assert_cmpint (wyl_policy_store_load_fact_relation_query
          (fixture.policy, "tenant-a", "alpha", "items", &query), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (query.schema_version, ==, 1);
    wyl_policy_fact_relation_query_info_clear (&query);
  }
  wyl_policy_graph_restore_replacement_record_free (replayed);
  wyl_policy_graph_restore_replacement_record_free (reserved);
  wyl_policy_graph_authority_record_free (authority);
  wyl_policy_tenant_authority_record_free (tenant);
  fixture_clear (&fixture);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-offline-backup-source/import/invalid",
      test_graph_import_invalid_input);
  g_test_add_func ("/fact-offline-backup-source/import/windows-fail-closed",
      test_graph_import_windows);
  g_test_add_func ("/fact-offline-backup-source/coordinator/invalid",
      test_graph_coordinator_invalid_input);
  g_test_add_func ("/fact-offline-backup-source/session-invalid-constructor",
      test_restore_validation_session_invalid_constructor);
  g_test_add_func ("/fact-offline-backup-source/session-windows-fail-closed",
      test_restore_validation_session_windows_fail_closed);
#ifdef __linux__
  g_test_add_data_func ("/fact-offline-backup-source/tenant-external-import/straight",
      "straight", test_tenant_external_import);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-external-import/restart",
      "restart", test_tenant_external_import);
  g_test_add_func ("/fact-offline-backup-source/tenant-provisioned-binding",
      test_tenant_provisioned_binding);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-resume-v5",
      NULL, test_tenant_commit_resume_v5);
  g_test_add_data_func
    ("/fact-offline-backup-source/tenant-schema-transition-commit",
      "schema-transition", test_tenant_commit_resume_v5);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/fresh",
      "fresh", test_tenant_commit_sync_staged_first);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/pending",
      "pending", test_tenant_commit_sync_staged_first);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/sibling-unknown",
      "sibling-unknown", test_tenant_commit_sync_staged_first);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/begin-response",
      "begin-response", test_tenant_commit_sync_staged_first);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/complete-response",
      "complete-response", test_tenant_commit_sync_staged_first);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/sibling-schema",
      "sibling-schema", test_tenant_commit_sync_staged_first);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/sibling-foreign",
      "sibling-foreign", test_tenant_commit_sync_staged_first);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/forward",
      "forward", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/reverse",
      "reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/pending-second",
      "pending-second", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/restart-second",
      "restart-second", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/restart-pending-second",
      "restart-pending-second", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/completed-sibling-foreign",
      "completed-sibling-foreign", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/completed-sibling-stage-content",
      "completed-sibling-stage-content", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-staged/both/stale-second",
      "stale-second", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-retain/both/forward",
      "retain-forward", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-retain/both/reverse",
      "retain-reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-retain/after-begin",
      "retain-after-begin", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-retain/after-rename",
      "retain-after-rename", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-rollback/both/forward",
      "retain-sync-forward", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-rollback/both/reverse",
      "retain-sync-reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-rollback/after-begin",
      "retain-sync-after-begin", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-rollback/after-fsync",
      "retain-sync-after-fsync", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-retain-dir/both/forward",
      "retain-sync-dir-forward", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-retain-dir/both/reverse",
      "retain-sync-dir-reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-retain-dir/after-begin",
      "retain-sync-dir-after-begin", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-retain-dir/after-fsync",
      "retain-sync-dir-after-fsync", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-publish/both/forward",
      "retain-sync-dir-publish-forward", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-publish/both/reverse",
      "retain-sync-dir-publish-reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-publish/after-begin",
      "retain-sync-dir-publish-after-begin", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-publish/after-rename",
      "retain-sync-dir-publish-after-rename", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-publish/after-fsync",
      "retain-sync-dir-publish-after-fsync", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-publish/sibling-foreign",
      "retain-sync-dir-publish-sibling-foreign", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-publish-dir/both/forward",
      "retain-sync-dir-publish-sync-forward", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-publish-dir/both/reverse",
      "retain-sync-dir-publish-sync-reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-publish-dir/after-begin",
      "retain-sync-dir-publish-sync-after-begin", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-publish-dir/after-fsync",
      "retain-sync-dir-publish-sync-after-fsync", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-commit-sync-publish-dir/interleaved",
      "retain-sync-dir-publish-sync-interleaved", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-reserve/both",
      "retain-sync-dir-publish-sync-reserve", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-reserve/driver",
      "retain-sync-dir-publish-sync-driver", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/both",
      "retain-sync-dir-publish-sync-companion", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/reverse",
      "retain-sync-dir-publish-sync-companion-reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/restart",
      "retain-sync-dir-publish-sync-companion-restart", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/restart-drift",
      "retain-sync-dir-publish-sync-companion-restart-drift", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/selected-schema",
      "retain-sync-dir-publish-sync-companion-schema", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/selected-schema-phase",
      "retain-sync-dir-publish-sync-companion-schema-phase", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/both",
      "retain-sync-dir-publish-sync-companion-select", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/restart",
      "retain-sync-dir-publish-sync-companion-select-restart", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-policy",
      "retain-sync-dir-publish-sync-companion-select-promote-policy", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver",
      "retain-sync-dir-publish-sync-companion-select-promote-driver", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-restart",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-restart", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-restart-drift",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-restart-drift", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-successor",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-successor", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-successor-chain",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-successor-chain", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-successor-forged",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-successor-forged", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-successor-mixed",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-successor-mixed", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-successor-fork",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-successor-fork", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-successor-selected",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-successor-selected", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-stale",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-stale", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-foreign",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-foreign", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-graph-fail",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-graph-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-provision-fail",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-provision-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-row-fail",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-row-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-tenant-begin-fail",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-tenant-begin-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-tenant-finish-fail",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-tenant-finish-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-claim-fail",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-claim-fail", test_tenant_commit_sync_staged_both);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/promote-driver-commit-response",
      "retain-sync-dir-publish-sync-companion-select-promote-driver-commit-response", test_tenant_commit_sync_staged_both);
#endif
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema",
      "retain-sync-dir-publish-sync-companion-select-published-schema", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-claim",
      "retain-sync-dir-publish-sync-companion-select-published-schema-claim", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-journal",
      "retain-sync-dir-publish-sync-companion-select-published-schema-journal", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-row",
      "retain-sync-dir-publish-sync-companion-select-published-schema-row", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-graph",
      "retain-sync-dir-publish-sync-companion-select-published-schema-graph", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-tenant",
      "retain-sync-dir-publish-sync-companion-select-published-schema-tenant", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-later-graph",
      "retain-sync-dir-publish-sync-companion-select-published-schema-later-graph", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-later-tenant",
      "retain-sync-dir-publish-sync-companion-select-published-schema-later-tenant", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-later-graph-claim",
      "retain-sync-dir-publish-sync-companion-select-published-schema-later-graph-claim", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-later-tenant-claim",
      "retain-sync-dir-publish-sync-companion-select-published-schema-later-tenant-claim", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/published-schema-provision",
      "retain-sync-dir-publish-sync-companion-select-published-schema-provision", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/delete-fail",
      "retain-sync-dir-publish-sync-companion-select-delete-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/insert-fail",
      "retain-sync-dir-publish-sync-companion-select-insert-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/phase-fail",
      "retain-sync-dir-publish-sync-companion-select-phase-fail", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/foreign",
      "retain-sync-dir-publish-sync-companion-select-foreign", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/stale",
      "retain-sync-dir-publish-sync-companion-select-stale", test_tenant_commit_sync_staged_both);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/commit-response",
      "retain-sync-dir-publish-sync-companion-select-commit-response", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-policy",
      "retain-sync-dir-publish-sync-companion-select-finalize-policy", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-both",
      "retain-sync-dir-publish-sync-companion-select-finalize-both", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-reverse",
      "retain-sync-dir-publish-sync-companion-select-finalize-reverse", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-partial",
      "retain-sync-dir-publish-sync-companion-select-finalize-partial", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-terminal",
      "retain-sync-dir-publish-sync-companion-select-finalize-terminal", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-foreign",
      "retain-sync-dir-publish-sync-companion-select-finalize-foreign", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-response",
      "retain-sync-dir-publish-sync-companion-select-finalize-response", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-begin-response",
      "retain-sync-dir-publish-sync-companion-select-finalize-begin-response", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-select/finalize-stale",
      "retain-sync-dir-publish-sync-companion-select-finalize-stale", test_tenant_commit_sync_staged_both);
#endif
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/foreign",
      "retain-sync-dir-publish-sync-companion-foreign", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/sibling-foreign",
      "retain-sync-dir-publish-sync-companion-sibling-foreign", test_tenant_commit_sync_staged_both);
#ifdef __linux__
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/symlink",
      "retain-sync-dir-publish-sync-companion-symlink", test_tenant_commit_sync_staged_both);
#endif
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/phase-fail",
      "retain-sync-dir-publish-sync-companion-phase-fail", test_tenant_commit_sync_staged_both);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/after-link",
      "retain-sync-dir-publish-sync-companion-after-link", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/before-dir-fsync",
      "retain-sync-dir-publish-sync-companion-before-dir-fsync", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-companion-sync/commit-response",
      "retain-sync-dir-publish-sync-companion-commit-response", test_tenant_commit_sync_staged_both);
#endif
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-reserve/driver-conflict",
      "retain-sync-dir-publish-sync-driver-conflict", test_tenant_commit_sync_staged_both);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-replacement-reserve/driver-commit-response",
      "retain-sync-dir-publish-sync-driver-commit-response", test_tenant_commit_sync_staged_both);
#endif
  g_test_add_data_func ("/fact-offline-backup-source/tenant-provisioned-binding/sibling-foreign",
      "sibling-foreign", test_tenant_provisioned_binding_rejects);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-provisioned-binding/sibling-stage-content",
      "sibling-stage-content", test_tenant_provisioned_binding_rejects);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-provisioned-binding/sibling-schema",
      "sibling-schema", test_tenant_provisioned_binding_rejects);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-provisioned-binding/extra-graph-row",
      "extra-graph-row", test_tenant_provisioned_binding_rejects);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-provisioned-binding/missing-claim",
      "missing-claim", test_tenant_provisioned_binding_rejects);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-provisioned-binding/effect-refused",
      "effect-refused", test_tenant_provisioned_binding_rejects);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_data_func ("/fact-offline-backup-source/tenant-provisioned-binding/commit-response",
      "commit-response", test_tenant_provisioned_binding_rejects);
#endif
  g_test_add_data_func ("/fact-offline-backup-source/tenant-external-import/resume",
      "resume", test_tenant_external_import);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-external-import/short",
      "short", test_tenant_external_import);
  g_test_add_data_func ("/fact-offline-backup-source/tenant-external-import/excess",
      "excess", test_tenant_external_import);
#endif
#ifndef G_OS_WIN32
  const gchar *import_modes[] = {
    "success", "import-historical", "truncated", "excess", "corrupt",
    "read-error", "revalidate-before", "revalidate-after", "count-overflow",
    "final-eof-error", "stale", "wrong-manifest", "wrong-graph", "unsealed",
    "expected-main-absent", "wrong-inode", "tenant-lifecycle", "tenant-reconciliation",
    "graph-lifecycle", "graph-reconciliation", "selected-provision", "selected-schema",
    "late-provision", "late-schema", "late-tenant", "late-journal", "collision", "missing-runtime",
    "token-held", "sibling-provision", "sibling-schema", "sibling-artifact",
    "untrusted", "unconfirmed", "tenant",
    "null-input", "null-read", "null-revalidate",
#ifdef WYL_TEST_HANDLE_SEAMS
    "commit-response", "construction-gap", "construction-reopen",
#endif
  };
  g_test_add_func ("/fact-offline-backup-source/import/authority-accessor",
      test_graph_import_authority_accessor);
  g_test_add_data_func ("/fact-offline-backup-source/rollback/fresh",
      "fresh", test_graph_rollback);
  g_test_add_data_func ("/fact-offline-backup-source/rollback/restart",
      "restart", test_graph_rollback);
  g_test_add_data_func
    ("/fact-offline-backup-source/rollback/schema-transition",
      "schema-transition", test_graph_rollback);
  g_test_add_data_func
    ("/fact-offline-backup-source/rollback/restart-pending",
      "restart-pending", test_graph_rollback);
  g_test_add_data_func ("/fact-offline-backup-source/rollback/pending-present",
      "pending-present", test_graph_rollback);
  g_test_add_data_func ("/fact-offline-backup-source/rollback/pending-absent",
      "pending-absent", test_graph_rollback);
  g_test_add_func ("/fact-offline-backup-source/rollback/absent-main",
      test_graph_rollback_absent_main);
  g_test_add_data_func ("/fact-offline-backup-source/rollback/tenant-two-graphs",
      "complete", test_tenant_rollback_two_graphs);
  g_test_add_data_func
    ("/fact-offline-backup-source/rollback/tenant-schema-transition",
      "schema-transition", test_tenant_rollback_two_graphs);
  g_test_add_data_func ("/fact-offline-backup-source/rollback/tenant-partial",
      "partial", test_tenant_rollback_two_graphs);
  g_test_add_func ("/fact-offline-backup-source/rollback/tenant-partial-progress",
      test_tenant_rollback_partial_progress);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_data_func ("/fact-offline-backup-source/rollback/release-before",
      "release-before", test_tenant_rollback_two_graphs);
  g_test_add_data_func ("/fact-offline-backup-source/rollback/release-after",
      "release-after", test_tenant_rollback_two_graphs);
  g_test_add_func ("/fact-offline-backup-source/rollback/release-late-stage",
      test_tenant_rollback_release_late_stage);
#endif
  const gchar *tenant_rejections[] = {
    "unbound-orphan", "substituted-stage", "changed-inode", "missing-claim",
    "stale",
  };
  for (guint i = 0; i < G_N_ELEMENTS (tenant_rejections); i++) {
    g_autofree gchar *path = g_strconcat
          ("/fact-offline-backup-source/rollback/tenant-reject/",
            tenant_rejections[i], NULL);
    g_test_add_data_func (path, tenant_rejections[i],
        test_tenant_rollback_rejects);
  }
  g_test_add_func ("/fact-offline-backup-source/rollback/unbound-orphan",
      test_graph_rollback_unbound_orphan);
  g_test_add_func ("/fact-offline-backup-source/rollback/unbound-absent",
      test_graph_rollback_unbound_absent);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_func ("/fact-offline-backup-source/rollback/unbound-post-sync-stage",
      test_graph_rollback_unbound_post_sync_stage);
  g_test_add_func ("/fact-offline-backup-source/rollback/unbound-sync-failure",
      test_graph_rollback_unbound_sync_failure);
#endif
  const gchar *rollback_rejections[] = {
    "foreign-stage", "foreign-main", "sidecar", "extra-link",
    "stage-link", "wrong-companion",
    "tenant-generation", "stale", "commit",
  };
  for (guint i = 0; i < G_N_ELEMENTS (rollback_rejections); i++) {
    g_autofree gchar *path = g_strconcat
          ("/fact-offline-backup-source/rollback/reject/",
            rollback_rejections[i], NULL);
    g_test_add_data_func (path, rollback_rejections[i],
        test_graph_rollback_rejects);
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  const gchar *rollback_crashes[] = { "decision", "begin", "complete", "sync" };
  for (guint i = 0; i < G_N_ELEMENTS (rollback_crashes); i++) {
    g_autofree gchar *path = g_strconcat
          ("/fact-offline-backup-source/rollback/crash/",
            rollback_crashes[i], NULL);
    g_test_add_data_func (path, rollback_crashes[i],
        test_graph_rollback_crash);
  }
  const gchar *tenant_crashes[] = {
    "decision", "begin", "complete", "unlink", "sync",
  };
  for (guint i = 0; i < G_N_ELEMENTS (tenant_crashes); i++) {
    g_autofree gchar *path = g_strconcat
          ("/fact-offline-backup-source/rollback/tenant-crash/",
            tenant_crashes[i], NULL);
    g_test_add_data_func (path, tenant_crashes[i], test_tenant_rollback_crash);
  }
  g_test_add_func ("/fact-offline-backup-source/rollback/tenant-prepare-race",
      test_tenant_rollback_prepare_race);
#endif
  for (guint i = 0; i < G_N_ELEMENTS (import_modes); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/import/",
            import_modes[i], NULL);
    g_test_add_data_func (path, import_modes[i], test_graph_import);
  }
  const gchar *reject_modes[] = { "untrusted", "unconfirmed", "tenant" };
  for (guint i = 0; i < G_N_ELEMENTS (reject_modes); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/coordinator/reject/",
            reject_modes[i], NULL);
    g_test_add_data_func (path, reject_modes[i], test_graph_coordinator_rejects_before_drain);
  }
  const gchar *source_modes[] = { "sibling-provision", "selected-provision",
                                  "sibling-schema", "selected-schema", "tenant-change" };
  for (guint i = 0; i < G_N_ELEMENTS (source_modes); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/coordinator/source/",
            source_modes[i], NULL);
    g_test_add_data_func (path, source_modes[i], test_graph_source_late_drift);
  }
  const gchar *coordinator_modes[] = { "alpha", "zeta", "sibling-schema",
                                       "sibling-provision", "sibling-artifact", "selected-schema",
                                       "selected-provision", "wrong-tenant", "wrong-graph", "stale", "checksum",
#ifdef WYL_TEST_HANDLE_SEAMS
                                       "commit-response",
#endif
  };
  for (guint i = 0; i < G_N_ELEMENTS (coordinator_modes); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/coordinator/",
            coordinator_modes[i], NULL);
    g_test_add_data_func (path, coordinator_modes[i], test_graph_staging_coordinator);
  }
  const gchar *graph_modes[] = { "alpha/observe", "zeta/observe", "alpha/record", "zeta/record",
                                 "alpha/missing-sibling-runtime", "zeta/missing-selected-runtime",
                                 "zeta/sibling-schema", "zeta/sibling-provision", "alpha/sibling-artifact",
                                 "zeta/sibling-provision-late", "zeta/selected-provision", "zeta/selected-provision-late",
                                 "zeta/selected-schema-late", "zeta/tenant-change", "zeta/cancel",
                                 "zeta/late-corrupt", "zeta/after-write-failure" };
  for (guint i = 0; i < G_N_ELEMENTS (graph_modes); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/graph/", graph_modes[i], NULL);
    g_test_add_data_func (path, graph_modes[i], test_graph_scoped_session);
  }
  g_test_add_data_func ("/fact-offline-backup-source/publication-authority/success",
      "success", test_restore_publication_authority);
  g_test_add_data_func
    ("/fact-offline-backup-source/publication-authority/schema-transition",
      "schema-transition", test_restore_publication_authority);
  g_test_add_data_func ("/fact-offline-backup-source/publication-authority/corrupt",
      "corrupt", test_restore_publication_authority);
  g_test_add_data_func ("/fact-offline-backup-source/publication-authority/policy",
      "policy", test_restore_publication_authority);
  g_test_add_func ("/fact-offline-backup-source/record/observational-refused",
      test_restore_observational_session_cannot_record);
  const gchar *record_modes[] = { "success", "partial", "nonprefix", "full",
                                  "verified-corrupt", "second-graph-failure", "first-graph-late-mutation",
                                  "fail-before", "fail-between", "fail-after", "cancel-before",
                                  "cancel-between", "cancel-after", "stale-write", "boundary-policy",
                                  "boundary-content", "boundary-entry", "boundary-schema", "boundary-provision",
#ifdef WYL_TEST_HANDLE_SEAMS
                                  "commit-response",
#endif
  };
  for (guint i = 0; i < G_N_ELEMENTS (record_modes); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/record/",
            record_modes[i], NULL);
    g_test_add_data_func (path, record_modes[i], test_restore_record_preflight);
  }
  const gchar *session_runs[] = { "success", "stage-only", "successful-rerun-mutation",
                                  "second-graph-failure",
                                  "first-graph-late-mutation", "cancel", "policy-change", "schema-change",
                                  "provision-change" };
  for (guint i = 0; i < G_N_ELEMENTS (session_runs); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-offline-backup-source/session/",
            session_runs[i], NULL);
    g_test_add_data_func (path, session_runs[i], test_restore_validation_session_run);
  }
  g_test_add_data_func ("/fact-offline-backup-source/session/fresh-runtime-tenant",
      NULL, test_restore_validation_session_fresh_runtime);
  g_test_add_data_func ("/fact-offline-backup-source/session/fresh-runtime-graph",
      "alpha", test_restore_validation_session_fresh_runtime);
  g_test_add_func ("/fact-offline-backup-source/session/missing-runtime-policy-drift",
      test_restore_validation_session_missing_runtime_policy_drift);
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
  g_test_add_data_func ("/fact-offline-backup-source/restore-replacement",
      NULL, test_graph_restore_replacement_reservation);
  g_test_add_data_func ("/fact-offline-backup-source/restore-replacement-restart",
      "restart", test_graph_restore_replacement_reservation);
  g_test_add_data_func
    ("/fact-offline-backup-source/restore-replacement-schema-transition",
      "schema-transition", test_graph_restore_replacement_reservation);
  g_test_add_func
    ("/fact-offline-backup-source/restore-populated-graph-schema-transition",
      test_graph_populated_schema_transition_roundtrip);
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_data_func
    ("/fact-offline-backup-source/restore-replacement-commit-response",
      "commit-response", test_graph_restore_replacement_reservation);
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
  g_test_add_func ("/fact-offline-backup-source/restore-dry-run-read-only",
      test_restore_dry_run_read_only);
  g_test_add_func ("/fact-offline-backup-source/restore-begin-authenticated",
      test_restore_begin_authenticated);
  g_test_add_func ("/fact-offline-backup-source/restore-staging-coordinator",
      test_tenant_restore_staging_coordinator);
  g_test_add_func
    ("/fact-offline-backup-source/restore-staging-bad-checksum",
      test_tenant_restore_staging_rejects_bad_checksum);
  return wyl_test_normalize_exit_status (g_test_run ());
}

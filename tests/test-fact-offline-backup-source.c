/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-backup-source-private.h"
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
  return wyl_test_normalize_exit_status (g_test_run ());
}

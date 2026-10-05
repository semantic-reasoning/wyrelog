/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/fact/offline-restore-stage-replay-private.h"
#include "test-exit-status.h"
#include "fact-test-support.h"

#include <glib/gstdio.h>
#include <string.h>
#include <stdio.h>

#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-backup-manifest-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"
#include "wyrelog/fact/secure-duckdb-bridge-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/compound-private.h"
#include "wyrelog/wyl-id-private.h"

#ifndef G_OS_WIN32
static const gchar *tenant = "tenant-replay";
static const gchar *graph = "orders";
static const gchar *store_uuid = "01890f47-3c4b-6cc2-b8c4-dc0c0c073989";
static const wyl_policy_fact_relation_schema_column_t columns[] = {
  { "item", "symbol", FALSE, TRUE },
  { "amount", "int64", FALSE, TRUE },
  { "valid", "bool", FALSE, TRUE },
  { "route", "compound_ref", FALSE, TRUE },
};

typedef struct
{
  gchar *root;
  gchar *source_path;
  gchar *stage_path;
  gchar *checksum;
  gchar *schema_digest;
  gchar *selected_schema_digest;
  GPtrArray *schema_selections;
  guint64 bytes;
  wyl_policy_store_t *policy;
  WylFactGraphLocator locator;
  WylFactGraphResolver resolver;
  WylFactGraphDirectory directory;
  WylFactRootWriterLease *lease;
  WylFactOfflineRestoreStageReader *reader;
  WylFactStoreIdentity identity;
  wyl_policy_fact_graph_info_t info;
} Fixture;

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
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

static wyl_policy_fact_relation_schema_options_t
schema (void)
{
  return (wyl_policy_fact_relation_schema_options_t) {
           .tenant_id = tenant, .graph_id = graph, .namespace_id = "shop",
           .relation_name = "items", .schema_version = 1, .relation_visible = TRUE,
           .columns = columns, .n_columns = G_N_ELEMENTS (columns),
  };
}

static void
query (duckdb_connection connection, const gchar *sql)
{
  duckdb_result result = { 0 };
  duckdb_state state = duckdb_query (connection, sql, &result);
  if (state != DuckDBSuccess)
    g_test_message ("fixture query failed: %s", duckdb_result_error (&result));
  g_assert_cmpint (state, ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
}

static void
fixture_init_internal (Fixture *f, gboolean drop_projection, gboolean sealed,
    gboolean selected_schema)
{
  memset (f, 0, sizeof *f);
  f->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  f->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  f->root = wyl_test_make_secure_fact_root ("wyl-stage-replay-XXXXXX", NULL);
  g_assert_nonnull (f->root);
  g_assert_cmpint (wyl_policy_store_open (NULL, &f->policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (f->policy), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (f->policy, tenant,
      "tenant-owner",
      &created), ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    { "item", "symbol" }, { "amount", "int64" }, { "valid", "bool" },
    { "route", "compound_ref" },
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    { "items", graph_columns, G_N_ELEMENTS (graph_columns) },
  };
  const wyl_policy_fact_graph_create_options_t options = {
    .tenant_id = tenant, .graph_id = graph, .fact_root = f->root,
    .schema_version = 1, .owner_scope = tenant, .relations = relations,
    .n_relations = G_N_ELEMENTS (relations),
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (f->policy, &options,
      NULL), ==, WYRELOG_E_OK);
  wyl_policy_fact_relation_schema_options_t relation = schema ();
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (f->policy,
      &relation), ==, WYRELOG_E_OK);
  if (selected_schema) {
    const wyl_policy_fact_relation_schema_query_t selected_queries[] = {
      { "items_v2", "wr.datalog.query", 1000 },
    };
    relation.schema_version = 2;
    relation.queries = selected_queries;
    relation.n_queries = G_N_ELEMENTS (selected_queries);
    g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (f->policy,
        &relation), ==, WYRELOG_E_OK);
    relation.queries = NULL;
    relation.n_queries = 0;
    WylPolicyAuthorityMutationResult activation =
        WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
    g_assert_cmpint (wyl_policy_store_reserve_relation_activation
          (f->policy, tenant, graph, "shop", "items", &activation), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (activation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    g_assert_cmpint (wyl_policy_store_transition_relation_activation
          (f->policy, tenant, graph, "shop", "items",
        WYL_POLICY_RELATION_ACTIVATION_UNBOUND, 0,
        WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
        FALSE, 0, TRUE, 1, "none", &activation), ==, WYRELOG_E_OK);
    g_assert_cmpint (activation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    g_assert_cmpint (wyl_policy_store_transition_relation_activation
          (f->policy, tenant, graph, "shop", "items",
        WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, 1,
        WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
        TRUE, 1, FALSE, 0, "none", &activation), ==, WYRELOG_E_OK);
    g_assert_cmpint (activation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  }
  f->source_path = g_build_filename (f->root, "source.duckdb", NULL);
  wyl_fact_store_t *source = NULL;
  g_assert_cmpint (wyl_fact_store_open (f->source_path, &source), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_compound_create_schema (source), ==, WYRELOG_E_OK);
  const wyl_fact_compound_arg_t child_args[] = {
    { .type = WYL_FACT_COMPOUND_ARG_SYMBOL, .as.text = "ICN" },
  };
  const wyl_fact_compound_value_t child = {
    .tenant_id = tenant, .graph_id = graph, .namespace_id = "shop",
    .functor = "path", .args = child_args, .n_args = 1,
  };
  gint64 child_ref = 0, parent_ref = 0;
  g_assert_cmpint (wyl_fact_compound_put (source, &child, &child_ref), ==,
      WYRELOG_E_OK);
  const wyl_fact_compound_arg_t parent_args[] = {
    { .type = WYL_FACT_COMPOUND_ARG_COMPOUND_REF,
      .as.compound_ref = child_ref },
  };
  const wyl_fact_compound_value_t parent = {
    .tenant_id = tenant, .graph_id = graph, .namespace_id = "shop",
    .functor = "wrap", .args = parent_args, .n_args = 1,
  };
  g_assert_cmpint (wyl_fact_compound_put (source, &parent, &parent_ref), ==,
      WYRELOG_E_OK);
  const wyl_fact_value_t values[] = {
    { .type = WYL_FACT_VALUE_SYMBOL, .as.text = "first" },
    { .type = WYL_FACT_VALUE_INT64, .as.int64_value = 42 },
    { .type = WYL_FACT_VALUE_BOOL, .as.bool_value = TRUE },
    { .type = WYL_FACT_VALUE_COMPOUND_REF, .as.compound_ref = parent_ref },
  };
  const wyl_fact_row_t rows[] = {
    { values, G_N_ELEMENTS (values) },
    { values, G_N_ELEMENTS (values) },
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "batch-1", .tenant_id = tenant, .graph_id = graph,
    .namespace_id = "shop", .relation_name = "items",
    .schema_version = selected_schema ? 2 : 1,
    .source = "test", .idempotency_key = "one",
    .op = WYL_FACT_STORE_OP_ASSERT, .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  g_assert_cmpint (wyl_fact_store_append_batch (source, &relation, &batch,
      &created), ==, WYRELOG_E_OK);
  wyl_fact_store_close (source);
  duckdb_database database = NULL;
  duckdb_connection connection = NULL;
  g_assert_cmpint (duckdb_open (f->source_path, &database), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_connect (database, &connection), ==, DuckDBSuccess);
  query (connection, "INSERT OR REPLACE INTO fact_store_metadata VALUES "
      "('format_version','1'),"
      "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
      "('path_encoding_version','1'),('tenant_id','tenant-replay'),"
      "('graph_id','orders');");
  if (drop_projection) {
    g_autofree gchar *table = wyl_fact_store_projection_table_name (&relation);
    g_autofree gchar *sql = g_strdup_printf ("DROP TABLE \"%s\";", table);
    query (connection, sql);
  }
  query (connection, "CHECKPOINT;");
  duckdb_disconnect (&connection);
  duckdb_close (&database);
  if (sealed)
    g_assert_cmpint (wyl_policy_store_seal_fact_graph (f->policy, tenant,
        graph), ==, WYRELOG_E_OK);
  WylPolicyFactBackupSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_policy_store_read_fact_backup_snapshot (f->policy,
      tenant, &snapshot), ==, WYRELOG_E_OK);
  WylPolicyFactBackupGraphSnapshot *entry = g_ptr_array_index
        (snapshot->graphs, 0);
  f->schema_digest = g_strdup (entry->active_schema_digest);
  if (selected_schema) {
    f->schema_selections = g_ptr_array_new_with_free_func
          ((GDestroyNotify) wyl_fact_offline_backup_schema_selection_free);
    WylFactOfflineBackupSchemaSelection *selection = g_new0
          (WylFactOfflineBackupSchemaSelection, 1);
    selection->namespace_id = g_strdup ("shop");
    selection->relation_name = g_strdup ("items");
    selection->schema_version = 2;
    g_ptr_array_add (f->schema_selections, selection);
    g_assert_cmpint (wyl_policy_store_fact_graph_selected_schema_digest
          (f->policy, tenant, graph, f->schema_selections,
        &f->selected_schema_digest), ==, WYRELOG_E_OK);
    g_assert_cmpstr (f->schema_digest, !=, f->selected_schema_digest);
  }
  wyl_policy_fact_backup_snapshot_free (snapshot);
  f->info = (wyl_policy_fact_graph_info_t) {
    .tenant_id = tenant, .graph_id = graph, .schema_version = 1, .sealed = TRUE,
  };
  f->identity = (WylFactStoreIdentity) { tenant, graph, store_uuid, 1, 1 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&f->locator, tenant, graph),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (f->root, &f->resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&f->resolver,
      &f->locator, TRUE, &f->directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (f->root, &f->lease),
      ==, WYRELOG_E_OK);
  gchar *raw = NULL;
  gsize size = 0;
  g_assert_true (g_file_get_contents (f->source_path, &raw, &size, NULL));
  g_autoptr (GBytes) payload = g_bytes_new_take (raw, size);
  g_autofree gchar *digest = g_compute_checksum_for_bytes
        (G_CHECKSUM_SHA256, payload);
  f->checksum = g_strdup_printf ("sha256:%s", digest);
  f->bytes = size;
  wyl_id_t operation;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
  g_autofree gchar *name = g_strdup_printf ("restore-%s.duckdb", operation_uuid);
  f->stage_path = wyl_fact_graph_directory_descriptive_file (&f->directory, name);
  WylFactOfflineRestoreStage *stage = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_stage_new (&f->resolver,
      &f->directory, f->lease, operation_uuid, size, f->checksum, &stage), ==,
      WYRELOG_E_OK);
  for (gsize offset = 0; offset < size;) {
    gsize chunk = MIN ((gsize) 64 * 1024, size - offset);
    g_assert_cmpint (wyl_fact_offline_restore_stage_sink (offset,
        (const guint8 *) raw + offset, chunk, stage), ==, WYRELOG_E_OK);
    offset += chunk;
  }
  guint64 written = 0;
  WylFactArtifactInventoryIdentity identity = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &written,
      &identity), ==, WYRELOG_E_OK);
  wyl_fact_offline_restore_stage_free (stage);
  g_assert_cmpint (wyl_fact_offline_restore_stage_reader_open (&f->resolver,
      &f->directory, f->lease, operation_uuid, &identity, &f->reader), ==,
      WYRELOG_E_OK);
}

static void
fixture_init (Fixture *f, gboolean drop_projection)
{
  fixture_init_internal (f, drop_projection, TRUE, FALSE);
}

static void
fixture_clear (Fixture *f)
{
  wyl_fact_offline_restore_stage_reader_free (f->reader);
  wyl_fact_graph_directory_clear (&f->directory);
  wyl_fact_graph_resolver_clear (&f->resolver);
  wyl_fact_root_writer_lease_release (f->lease);
  wyl_fact_graph_locator_clear (&f->locator);
  wyl_policy_store_close (f->policy);
  remove_tree (f->root);
  g_free (f->root);
  g_free (f->source_path);
  g_free (f->stage_path);
  g_free (f->checksum);
  g_free (f->schema_digest);
  g_free (f->selected_schema_digest);
  g_clear_pointer (&f->schema_selections, g_ptr_array_unref);
}

typedef struct
{
  Fixture *fixture;
  gchar *digest;
  GCancellable *cancellable;
  guint64 row_limit;
} ReplayCall;

static wyrelog_error_t
replay_job (WylFactReplayJobContext *context, gpointer user_data)
{
  ReplayCall *call = user_data;
  Fixture *f = call->fixture;
  return wyl_fact_offline_restore_stage_replay_validate_selected (f->policy,
             f->reader, f->bytes, f->checksum, &f->identity, &f->info,
             f->schema_digest, f->selected_schema_digest == NULL
             ? f->schema_digest : f->selected_schema_digest,
             f->schema_selections, context, &call->digest);
}

static wyrelog_error_t
run_replay (ReplayCall *call)
{
  WylFactReplaySchedulerConfig config;
  wyl_fact_replay_scheduler_config_defaults (&config);
  if (call->row_limit != 0)
    config.row_limit = call->row_limit;
  WylFactReplayScheduler *scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  WylFactReplayFuture *future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler, tenant, graph,
      call->cancellable, replay_job, call, NULL, &future), ==, WYRELOG_E_OK);
  wyrelog_error_t rc = wyl_fact_replay_future_wait (future);
  wyl_fact_replay_future_unref (future);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_scheduler_unref (scheduler);
  return rc;
}

static void
test_stage_replay (void)
{
  Fixture f;
  fixture_init (&f, FALSE);
  ReplayCall call = { .fixture = &f };
  g_assert_cmpint (run_replay (&call), ==, WYRELOG_E_OK);
  g_assert_cmpstr (call.digest, ==, f.schema_digest);
  g_free (call.digest);
  g_assert_cmpint (wyl_fact_offline_restore_stage_reader_verify_content
        (f.reader, f.bytes, f.checksum), ==, WYRELOG_E_OK);
  fixture_clear (&f);
}

static void
test_stage_replay_selected_schema (void)
{
  Fixture f;
  fixture_init_internal (&f, FALSE, TRUE, TRUE);
  ReplayCall call = { .fixture = &f };
  g_assert_cmpint (run_replay (&call), ==, WYRELOG_E_OK);
  g_assert_cmpstr (call.digest, ==, f.selected_schema_digest);
  g_clear_pointer (&call.digest, g_free);

  gchar original = f.schema_digest[7];
  f.schema_digest[7] = original == 'a' ? 'b' : 'a';
  g_assert_cmpint (run_replay (&call), ==, WYRELOG_E_POLICY);
  g_assert_null (call.digest);
  f.schema_digest[7] = original;

  /* A missing target version must refuse before reading the supplied rows. */
  WylFactOfflineBackupSchemaSelection *selection =
      g_ptr_array_index (f.schema_selections, 0);
  selection->schema_version = 3;
  g_assert_cmpint (run_replay (&call), ==, WYRELOG_E_POLICY);
  g_assert_null (call.digest);
  fixture_clear (&f);
}

static void
test_stage_replay_requires_projection (void)
{
  Fixture f;
  fixture_init (&f, TRUE);
  ReplayCall call = { .fixture = &f };
  g_assert_cmpint (run_replay (&call), !=, WYRELOG_E_OK);
  g_assert_null (call.digest);
  fixture_clear (&f);
}

typedef struct
{
  Fixture *fixture;
  GCancellable *cancel;
  WylSecureDuckdbRestoreStageTestPoint cancel_at;
  gboolean mutate;
  gboolean replace;
  gboolean invalidate_lease;
  gboolean sidecar;
  guint queries;
  guint closes;
  guint destroys;
  guint mutations;
} Probe;

static void
replay_hook (WylSecureDuckdbRestoreStageTestPoint point, gpointer data)
{
  Probe *p = data;
  if (point == WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_BEFORE_REPLAY_QUERY)
    p->queries++;
  if (point == WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_REPLAY_CLOSE)
    p->closes++;
  if (point == WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_REPLAY_DESTROY)
    p->destroys++;
  if (p->cancel != NULL && point == p->cancel_at)
    g_cancellable_cancel (p->cancel);
  if (point != WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_AFTER_CLOSE)
    return;
  if (p->invalidate_lease) {
    g_assert_cmpint (g_chmod (p->fixture->root, 0770), ==, 0);
    p->mutations++;
  } else if (p->sidecar) {
    g_autofree gchar *path = g_strconcat (p->fixture->stage_path, ".wal", NULL);
    g_assert_true (g_file_set_contents (path, "unexpected", -1, NULL));
    p->mutations++;
  } else if (p->replace) {
    g_autofree gchar *displaced = g_strconcat (p->fixture->stage_path,
            ".displaced", NULL);
    g_assert_cmpint (g_rename (p->fixture->stage_path, displaced), ==, 0);
    p->mutations++;
  } else if (p->mutate) {
    FILE *file = g_fopen (p->fixture->stage_path, "r+b");
    g_assert_nonnull (file);
    g_assert_cmpint (fputc (0x5a, file), !=, EOF);
    g_assert_cmpint (fclose (file), ==, 0);
    p->mutations++;
  }
}

static void
test_stage_replay_failures (gconstpointer data)
{
  const gchar *mode = data;
  Fixture f;
  fixture_init_internal (&f, FALSE, !g_str_equal (mode, "unsealed"), FALSE);
  g_autoptr (GCancellable) cancel = g_cancellable_new ();
  ReplayCall call = { .fixture = &f, .cancellable = cancel };
  Probe probe = { .fixture = &f };
  wyrelog_error_t expected = WYRELOG_E_POLICY;
  gboolean no_queries = FALSE;
  if (g_str_equal (mode, "identity")) {
    f.identity.store_uuid = "01890f47-3c4b-6cc2-b8c4-dc0c0c073980";
    no_queries = TRUE;
  } else if (g_str_equal (mode, "digest")) {
    f.schema_digest[7] = f.schema_digest[7] == 'a' ? 'b' : 'a';
    no_queries = TRUE;
  } else if (g_str_equal (mode, "unsealed")) {
    no_queries = TRUE;
  } else if (g_str_equal (mode, "limit")) {
    call.row_limit = 1;
    expected = WYRELOG_E_RESOURCE_LIMIT;
  } else if (g_str_equal (mode, "late-sidecar")) {
    probe.sidecar = TRUE;
  } else if (g_str_equal (mode, "lease")) {
    probe.invalidate_lease = TRUE;
  } else {
    probe.cancel = cancel;
    probe.cancel_at = WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_BEFORE_REPLAY_ROW;
    if (g_str_equal (mode, "cancel-close"))
      probe.cancel_at = WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_REPLAY_CLOSE;
    if (g_str_equal (mode, "cancel-final"))
      probe.cancel_at = WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_AFTER_CLOSE;
    probe.mutate = g_str_equal (mode, "cancel-content");
    probe.replace = g_str_equal (mode, "cancel-authority");
    if (probe.replace)
      expected = WYRELOG_E_NOT_FOUND;
    if (!probe.mutate && !probe.replace)
      expected = WYRELOG_E_CANCELLED;
  }
  wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test
    (replay_hook, &probe);
  g_assert_cmpint (run_replay (&call), ==, expected);
  wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test (NULL, NULL);
  g_assert_null (call.digest);
  if (no_queries)
    g_assert_cmpuint (probe.queries, ==, 0);
  else
    g_assert_cmpuint (probe.queries, >, 0);
  g_assert_cmpuint (probe.closes, ==, 1);
  g_assert_cmpuint (probe.destroys, ==, 1);
  if (probe.mutate || probe.replace || probe.sidecar || probe.invalidate_lease)
    g_assert_cmpuint (probe.mutations, ==, 1);
  if (probe.invalidate_lease)
    g_assert_cmpint (g_chmod (f.root, 0700), ==, 0);
  fixture_clear (&f);
}
#endif

static void
test_windows_fail_closed (void)
{
#ifdef G_OS_WIN32
  const WylFactStoreIdentity identity = {
    "tenant", "graph", "01890f47-3c4b-6cc2-b8c4-dc0c0c073989", 1, 1,
  };
  const wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant", .graph_id = "graph", .sealed = TRUE,
  };
  const gchar *digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
  gchar *output = (gchar *) GSIZE_TO_POINTER (1);
  g_assert_cmpint (wyl_fact_offline_restore_stage_replay_validate
        ((wyl_policy_store_t *) GSIZE_TO_POINTER (1),
      (WylFactOfflineRestoreStageReader *) GSIZE_TO_POINTER (1), 17, digest,
      &identity, &info, digest,
      (WylFactReplayJobContext *) GSIZE_TO_POINTER (1), &output), ==,
      WYRELOG_E_POLICY);
  g_assert_null (output);
#else
  g_test_skip ("Windows-only fail-closed boundary");
#endif
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact-stage-replay/success", test_stage_replay);
  g_test_add_func ("/fact-stage-replay/selected-schema",
      test_stage_replay_selected_schema);
  g_test_add_func ("/fact-stage-replay/missing-projection",
      test_stage_replay_requires_projection);
  const gchar *modes[] = { "identity", "digest", "unsealed", "limit",
                           "cancel", "cancel-content", "cancel-authority", "late-sidecar",
                           "lease", "cancel-close", "cancel-final" };
  for (guint i = 0; i < G_N_ELEMENTS (modes); i++) {
    g_autofree gchar *path = g_strconcat ("/fact-stage-replay/", modes[i], NULL);
    g_test_add_data_func (path, modes[i], test_stage_replay_failures);
  }
#endif
  g_test_add_func ("/fact-stage-replay/windows-fail-closed",
      test_windows_fail_closed);
  return wyl_test_normalize_exit_status (g_test_run ());
}

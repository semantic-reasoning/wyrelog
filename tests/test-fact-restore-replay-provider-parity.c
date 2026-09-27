/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact-test-support.h"
#include "test-exit-status.h"

#include <glib/gstdio.h>

#include "wyrelog/fact/replay-scheduler-private.h"
#include "wyrelog/fact/replay-store-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"
#include "wyrelog/fact/secure-duckdb-bridge-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/wyl-id-private.h"

#ifndef G_OS_WIN32
static const WylFactStoreIdentity identity = {
  "tenant-parity", "orders", "01890f47-3c4b-6cc2-b8c4-dc0c0c073989", 1, 1,
};
static const wyl_policy_fact_relation_schema_column_t columns[] = {
  { "select", "symbol", FALSE, TRUE },
  { "say\"what", "string", FALSE, TRUE },
  { "amount", "int64", FALSE, TRUE },
  { "enabled", "bool", FALSE, TRUE },
  { "nested", "compound_ref", FALSE, TRUE },
};
static const wyl_policy_fact_relation_schema_options_t schema = {
  .tenant_id = "tenant-parity", .graph_id = "orders",
  .namespace_id = "shop", .relation_name = "quoted\"items",
  .schema_version = 1, .relation_visible = TRUE,
  .columns = columns, .n_columns = G_N_ELEMENTS (columns),
};

typedef struct
{
  gchar *root;
  gchar *source_path;
  gchar *checksum;
  guint64 bytes;
  WylFactGraphLocator locator;
  WylFactGraphResolver resolver;
  WylFactGraphDirectory directory;
  WylFactRootWriterLease *lease;
  WylFactOfflineRestoreStageReader *reader;
} Fixture;

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  g_assert_nonnull (directory);
  const gchar *name;
  while ((name = g_dir_read_name (directory)) != NULL) {
    g_autofree gchar *child = g_build_filename (path, name, NULL);
    if (g_file_test (child, G_FILE_TEST_IS_DIR)
        && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
      remove_tree (child);
    else
      g_assert_cmpint (g_remove (child), ==, 0);
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

static void
query (duckdb_connection connection, const gchar *sql)
{
  duckdb_result result = { 0 };
  duckdb_state state = duckdb_query (connection, sql, &result);
  if (state != DuckDBSuccess)
    g_test_message ("fixture SQL failed: %s", duckdb_result_error (&result));
  g_assert_cmpint (state, ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
}

static void
fixture_init (Fixture *f)
{
  *f = (Fixture) { 0 };
  f->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  f->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  f->root = wyl_test_make_secure_fact_root ("wyl-replay-parity-XXXXXX", NULL);
  g_assert_nonnull (f->root);
  f->source_path = g_build_filename (f->root, "source.duckdb", NULL);
  duckdb_database database = NULL;
  duckdb_connection connection = NULL;
  g_assert_cmpint (duckdb_open (f->source_path, &database), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_connect (database, &connection), ==, DuckDBSuccess);
  /* Minimal provider-level tables deliberately allow NULLs and SQL types
   * different from replay cell types. This is not a wrapper-valid snapshot. */
  query (connection, "CREATE TABLE fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);"
      "INSERT INTO fact_store_metadata VALUES "
      "('store_kind','wyrelog.fact'),('format_version','1'),"
      "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
      "('path_encoding_version','1'),('tenant_id','tenant-parity'),"
      "('graph_id','orders');"
      "CREATE TABLE fact_batches(tenant_id VARCHAR,graph_id VARCHAR,"
      "namespace_id VARCHAR,relation_name VARCHAR,schema_version INTEGER);"
      "INSERT INTO fact_batches VALUES "
      "('tenant-parity','orders','z','last',2),"
      "('tenant-parity','orders','shop','quoted\"items',2),"
      "('tenant-parity','orders','shop','quoted\"items',1),"
      "('tenant-parity','orders','shop','quoted\"items',1),"
      "('other','orders','a','foreign',1),"
      "('tenant-parity','other','a','foreign',1);"
      "CREATE TABLE compound_terms(compound_ref BIGINT,tenant_id VARCHAR,"
      "graph_id VARCHAR,namespace_id VARCHAR,functor VARCHAR,arity INTEGER,"
      "content_hash VARCHAR);"
      "INSERT INTO compound_terms VALUES "
      "(20,'tenant-parity','orders','shop','leaf',1,'leaf-hash'),"
      "(10,'tenant-parity','orders','shop','outer',4,'outer-hash'),"
      "(30,'other','orders','shop','foreign',0,'foreign-hash');"
      "CREATE TABLE compound_args(compound_ref BIGINT,arg_index INTEGER,"
      "arg_type VARCHAR,symbol_value VARCHAR,string_value VARCHAR,"
      "int64_value BIGINT,bool_value BOOLEAN,child_compound_ref BIGINT);"
      "INSERT INTO compound_args VALUES "
      "(10,3,'compound',NULL,NULL,NULL,NULL,20),"
      "(20,0,'string',NULL,'nested text',NULL,NULL,NULL),"
      "(10,1,'int64',NULL,NULL,-9223372036854775808,NULL,NULL),"
      "(10,2,'bool',NULL,NULL,NULL,false,NULL),"
      "(10,0,'symbol','first',NULL,NULL,NULL,NULL);");
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  g_assert_nonnull (table);
  g_autofree gchar *sql = g_strdup_printf (
    "CREATE TABLE \"%s\"(\"select\" INTEGER,\"say\"\"what\" VARCHAR,"
    "amount VARCHAR,enabled INTEGER,nested VARCHAR,__wyl_valid INTEGER,"
    "__wyl_tenant_id VARCHAR,__wyl_graph_id VARCHAR,"
    "__wyl_seq BIGINT,__wyl_row_index INTEGER);"
    "INSERT INTO \"%s\" VALUES "
    "(9,'last','-7',0,'20',0,'tenant-parity','orders',2,0),"
    "(8,'invalid','not-an-integer',2,'9223372036854775808',1,"
    "'tenant-parity','orders',3,0),"
    "(NULL,NULL,NULL,NULL,NULL,NULL,'tenant-parity','orders',1,1),"
    "(42,'first','9223372036854775807',1,'10',1,"
    "'tenant-parity','orders',1,0),"
    "(0,'foreign','0',0,'0',0,'other','orders',0,0),"
    "(0,'foreign','0',0,'0',0,'tenant-parity','other',0,0);",
    table, table);
  query (connection, sql);
  query (connection, "CHECKPOINT;");
  duckdb_disconnect (&connection);
  duckdb_close (&database);

  g_assert_cmpint (wyl_fact_graph_locator_init (&f->locator,
      identity.tenant_id, identity.graph_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (f->root, &f->resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&f->resolver,
      &f->locator, TRUE, &f->directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (f->root, &f->lease), ==,
      WYRELOG_E_OK);
  g_autofree gchar *raw = NULL;
  gsize size = 0;
  g_assert_true (g_file_get_contents (f->source_path, &raw, &size, NULL));
  g_autofree gchar *digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
          (const guchar *) raw, size);
  f->checksum = g_strdup_printf ("sha256:%s", digest);
  f->bytes = size;
  wyl_id_t operation;
  gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_id_new (&operation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&operation, operation_uuid,
      sizeof operation_uuid), ==, WYRELOG_E_OK);
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
  WylFactArtifactInventoryIdentity artifact = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &written,
      &artifact), ==, WYRELOG_E_OK);
  g_assert_cmpuint (written, ==, size);
  wyl_fact_offline_restore_stage_free (stage);
  g_assert_cmpint (wyl_fact_offline_restore_stage_reader_open (&f->resolver,
      &f->directory, f->lease, operation_uuid, &artifact, &f->reader), ==,
      WYRELOG_E_OK);
}

static void
fixture_clear (Fixture *f)
{
  wyl_fact_offline_restore_stage_reader_free (f->reader);
  wyl_fact_graph_directory_clear (&f->directory);
  wyl_fact_graph_resolver_clear (&f->resolver);
  wyl_fact_root_writer_lease_release (f->lease);
  wyl_fact_graph_locator_clear (&f->locator);
  remove_tree (f->root);
  g_free (f->root);
  g_free (f->source_path);
  g_free (f->checksum);
}

/* Copy borrowed cells during the callback. Type tags and row delimiters make
 * NULL, false, empty text, integer zero and row ordering distinguishable. */
static wyrelog_error_t
collect_row (const WylFactReplayCell *cells, gsize n_cells, gpointer data)
{
  GString *out = data;
  for (gsize i = 0; i < n_cells; i++) {
    if (i != 0)
      g_string_append_c (out, '|');
    switch (cells[i].type) {
      case WYL_FACT_REPLAY_CELL_NULL:
        g_string_append (out, "N");
        break;
      case WYL_FACT_REPLAY_CELL_TEXT:
        g_assert_nonnull (cells[i].value.text);
        g_string_append_printf (out, "T:%s", cells[i].value.text);
        break;
      case WYL_FACT_REPLAY_CELL_INT64:
        g_string_append_printf (out, "I:%" G_GINT64_FORMAT,
            cells[i].value.int64_value);
        break;
      case WYL_FACT_REPLAY_CELL_BOOL:
        g_string_append_printf (out, "B:%d", !!cells[i].value.bool_value);
        break;
      default:
        g_assert_not_reached ();
    }
  }
  g_string_append_c (out, '\n');
  return WYRELOG_E_OK;
}

static WylFactReplayStoreRequest
request_default (void)
{
  return (WylFactReplayStoreRequest) {
           .tenant_id = identity.tenant_id, .graph_id = identity.graph_id,
           .namespace_id = "shop", .compound_ref = 10, .projection_schema = &schema,
  };
}

static void
assert_parity (WylFactReplayStore *legacy, WylFactReplayStore *restore,
    WylFactReplayJobContext *context, WylFactReplayStoreOperation operation,
    const WylFactReplayStoreRequest *request, const gchar *expected)
{
  g_autoptr (GString) a = g_string_new (NULL);
  g_autoptr (GString) b = g_string_new (NULL);
  g_assert_cmpint (wyl_fact_replay_store_execute (legacy, operation, request,
      context, collect_row, a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_store_execute (restore, operation, request,
      context, collect_row, b), ==, WYRELOG_E_OK);
  g_assert_cmpstr (a->str, ==, expected);
  g_assert_cmpstr (b->str, ==, a->str);
}

static wyrelog_error_t
run_job (WylFactReplayJobFunc function, gpointer data)
{
  WylFactReplaySchedulerConfig config;
  wyl_fact_replay_scheduler_config_defaults (&config);
  WylFactReplayScheduler *scheduler = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_new (&config, NULL, &scheduler),
      ==, WYRELOG_E_OK);
  WylFactReplayFuture *future = NULL;
  g_assert_cmpint (wyl_fact_replay_scheduler_submit (scheduler,
      identity.tenant_id, identity.graph_id, NULL, function, data, NULL,
      &future), ==, WYRELOG_E_OK);
  wyrelog_error_t rc = wyl_fact_replay_future_wait (future);
  wyl_fact_replay_future_unref (future);
  g_assert_cmpint (wyl_fact_replay_scheduler_shutdown (scheduler), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_scheduler_unref (scheduler);
  return rc;
}

static wyrelog_error_t
parity_job (WylFactReplayJobContext *context, gpointer data)
{
  Fixture *f = data;
  wyl_fact_store_t *source = NULL;
  WylFactReplayStore *legacy = NULL;
  WylFactReplayStore *restore = NULL;
  g_assert_cmpint (wyl_fact_store_open (f->source_path, &source), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_replay_store_new_c_store (source, context,
      &legacy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_restore_stage_replay_store
        (f->reader, f->bytes, f->checksum, &identity, context, &restore), ==,
      WYRELOG_E_OK);
  WylFactReplayStoreRequest request = request_default ();
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS, &request,
      "T:shop|T:quoted\"items|I:1\nT:shop|T:quoted\"items|I:2\n"
      "T:z|T:last|I:2\n");
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS, &request,
      "T:42|T:first|I:9223372036854775807|B:1|I:10|B:1\n"
      "N|N|N|N|N|N\nT:9|T:last|I:-7|B:0|I:20|B:0\n"
      "T:8|T:invalid|I:0|B:1|I:0|B:1\n");
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM, &request,
      "T:outer|I:4|T:outer-hash\n");
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS, &request,
      "I:0|T:symbol|T:first|N|N|N|N\n"
      "I:1|T:int64|N|N|I:-9223372036854775808|N|N\n"
      "I:2|T:bool|N|N|N|B:0|N\nI:3|T:compound|N|N|N|N|I:20\n");
  request.compound_ref = 20;
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM, &request,
      "T:leaf|I:1|T:leaf-hash\n");
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS, &request,
      "I:0|T:string|N|T:nested text|N|N|N\n");
  request.namespace_id = "absent";
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM, &request, "");
  assert_parity (legacy, restore, context,
      WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS, &request, "");
  g_assert_cmpint (wyl_fact_replay_store_close_checked (restore), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_store_free (restore);
  g_assert_cmpint (wyl_fact_replay_store_close_checked (legacy), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_store_free (legacy);
  g_assert_cmpint (wyl_fact_store_close_checked (source), ==, WYRELOG_E_OK);
  return WYRELOG_E_OK;
}

static void
assert_rejected (WylFactReplayStore *store, WylFactReplayJobContext *context,
    WylFactReplayStoreOperation operation,
    const WylFactReplayStoreRequest *request, wyrelog_error_t expected)
{
  g_autoptr (GString) rows = g_string_new (NULL);
  g_assert_cmpint (wyl_fact_replay_store_execute (store, operation, request,
      context, collect_row, rows), ==, expected);
  g_assert_cmpuint (rows->len, ==, 0);
}

static wyrelog_error_t
wrong_context_job (WylFactReplayJobContext *context, gpointer data)
{
  WylFactReplayStoreRequest request = request_default ();
  assert_rejected (data, context,
      WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS, &request,
      WYRELOG_E_INVALID);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
rejection_job (WylFactReplayJobContext *context, gpointer data)
{
  Fixture *f = data;
  WylFactReplayStore *restore = NULL;
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_restore_stage_replay_store
        (f->reader, f->bytes, f->checksum, &identity, context, &restore), ==,
      WYRELOG_E_OK);
  for (guint op = WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS;
      op <= WYL_FACT_REPLAY_STORE_READ_COMPOUND_ARGS; op++) {
    WylFactReplayStoreRequest request = request_default ();
    request.tenant_id = "other";
    assert_rejected (restore, context, op, &request, WYRELOG_E_POLICY);
    request = request_default ();
    request.graph_id = "other";
    assert_rejected (restore, context, op, &request, WYRELOG_E_POLICY);
  }
  WylFactReplayStoreRequest request = request_default ();
  wyl_policy_fact_relation_schema_options_t wrong_schema = schema;
  wrong_schema.tenant_id = "other";
  request.projection_schema = &wrong_schema;
  assert_rejected (restore, context, WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS,
      &request, WYRELOG_E_POLICY);
  request = request_default ();
  request.namespace_id = "other";
  assert_rejected (restore, context, WYL_FACT_REPLAY_STORE_READ_PROJECTION_ROWS,
      &request, WYRELOG_E_POLICY);
  request = request_default ();
  assert_rejected (restore, NULL, WYL_FACT_REPLAY_STORE_LIST_DURABLE_BATCH_KEYS,
      &request, WYRELOG_E_INVALID);
  /* Both contexts stay live: the owner waits for a second scheduler's job.
   * That job must reject before touching the owner's DuckDB connection. */
  g_assert_cmpint (run_job (wrong_context_job, restore), ==, WYRELOG_E_OK);
  g_autoptr (GString) rows = g_string_new (NULL);
  g_assert_cmpint (wyl_fact_replay_store_execute (restore,
      WYL_FACT_REPLAY_STORE_READ_COMPOUND_TERM, &request, context,
      collect_row, rows), ==, WYRELOG_E_OK);
  g_assert_cmpstr (rows->str, ==, "T:outer|I:4|T:outer-hash\n");
  g_assert_cmpint (wyl_fact_replay_store_close_checked (restore), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_store_free (restore);
  return WYRELOG_E_OK;
}

static void
test_parity (void)
{
  Fixture f;
  fixture_init (&f);
  g_assert_cmpint (run_job (parity_job, &f), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_stage_reader_verify_content
        (f.reader, f.bytes, f.checksum), ==, WYRELOG_E_OK);
  fixture_clear (&f);
}

static void
test_rejections (void)
{
  Fixture f;
  fixture_init (&f);
  g_assert_cmpint (run_job (rejection_job, &f), ==, WYRELOG_E_OK);
  fixture_clear (&f);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact-restore-replay-provider/parity", test_parity);
  g_test_add_func ("/fact-restore-replay-provider/rejections", test_rejections);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

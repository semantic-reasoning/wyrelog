/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include "fact-test-support.h"
#include "human-user-test-support.h"
#include "fact/graph-locator-private.h"
#include "fact/provisioning-run-private.h"
#include "fact/store-open-private.h"
#include "fact/store-private.h"
#include "fact/store-test-seams-private.h"
#include "fact/graph-artifact-namespace-private.h"
#include "fact/secure-duckdb-bridge-private.h"

G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
  (WylFactGraphProvisionedPair *, WylFactArtifactNamespace **);

static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070545";
static const gchar tenant_id[] = "tenant-provision";
static const gchar graph_id[] = "graph-provision";

static void
exec_sqlite_ok (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite error: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
seed_graph (wyl_policy_store_t *store)
{
  register_test_human (store, "tenant-owner");
  exec_sqlite_ok (wyl_policy_store_get_db (store),
      "INSERT INTO tenants (tenant_id,owner_subject_id,"
      "sealed,created_at,updated_at) "
      "VALUES ('tenant-provision','tenant-owner',0,1,1);"
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
      "('tenant-provision','graph-provision','file:///legacy','/legacy',1,"
      "'tenant-provision',0,1,1,NULL);");
}

static void
remove_root (const gchar *root)
{
  g_autoptr (GDir) directory = g_dir_open (root, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (root, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_root (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (root);
}

/* Open the ACTIVE graph through policy authority.  Darwin consumes the exact
 * durable operation evidence; Linux consumes the retained stage/final pair. */
static wyrelog_error_t
open_live (wyl_policy_store_t *policy_store, const gchar *root,
    gboolean writable, wyl_fact_store_t **out_store)
{
  return wyl_fact_store_open_provisioned_graph (policy_store, root, tenant_id,
             graph_id, writable, out_store);
}

static gboolean
exec_ok (wyl_fact_store_t *store, const gchar *sql)
{
  g_auto (GStrv) statements = g_strsplit (sql, ";", -1);
  for (gsize i = 0; statements[i] != NULL; i++)
    if (*statements[i] != '\0'
        && wyl_fact_store_test_exec_sql (store, statements[i])
        != WYRELOG_E_OK)
      return FALSE;
  return TRUE;
}

static gint64
probe_count (wyl_policy_store_t *policy_store, const gchar *root)
{
  wyl_fact_store_t *store = NULL;
  if (open_live (policy_store, root, FALSE, &store) != WYRELOG_E_OK)
    return -1;
  gint64 value = -1;
  (void) wyl_fact_store_test_query_int64 (store,
      "SELECT COUNT(*) FROM probe;", &value);
  wyl_fact_store_close (store);
  return value;
}

/* A provisioned store opens as a live, writable secure handle: writes through
 * the bounded filesystem persist across close and reopen, and policy-owned
 * authority selects the platform's authenticated provisioning shape. */
static void
test_open_provisioned_pair_persists_across_reopen (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-provisioned-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) policy_store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy_store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy_store), ==,
      WYRELOG_E_OK);
  seed_graph (policy_store);
  const WylPolicyGraphProvisioningInput input = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .store_uuid = store_uuid,
    .format_version = 1,
    .path_encoding_version = 1,
    .expected_lifecycle_generation = 0,
    .expected_reconciliation_generation = 0,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (policy_store, &input, root,
      &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);

  /* Write through the live handle, then close (checkpointing through the
   * bounded filesystem under the lease). */
  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (open_live (policy_store, root, TRUE, &store), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (store);
  WylPolicyFactConcurrentOpenQuotaStatus open_status = { 0 };
  g_assert_cmpint (wyl_policy_store_get_fact_concurrent_open_quota
        (policy_store, tenant_id, &open_status), ==, WYRELOG_E_OK);
  g_assert_cmpuint (open_status.charged, ==, 1);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_true (exec_ok (store, "CREATE TABLE probe (x INTEGER);"));
  g_assert_true (exec_ok (store, "INSERT INTO probe VALUES (42), (7);"));
  wyl_fact_store_close (store);
  g_assert_cmpint (wyl_policy_store_get_fact_concurrent_open_quota
        (policy_store, tenant_id, &open_status), ==, WYRELOG_E_OK);
  g_assert_cmpuint (open_status.charged, ==, 0);

  /* Reopen a fresh live handle on the same pair: the writes are durable. */
  g_assert_cmpint (probe_count (policy_store, root), ==, 2);

  /* Linux retains a hard-link pair; Darwin binds the single final name to the
   * exact evidence persisted in the ACTIVE policy record. */
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  g_autofree gchar *stage_path = g_build_filename (root, tenant_component,
          graph_component, record->stage_basename, NULL);
  struct stat status;
  g_assert_cmpint (stat (final_path, &status), ==, 0);
#if defined(__APPLE__) || defined(G_OS_WIN32)
  g_assert_cmpuint (status.st_nlink, ==, 1);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
#else
  g_assert_cmpuint (status.st_nlink, ==, 2);
  struct stat stage_status;
  g_assert_cmpint (stat (stage_path, &stage_status), ==, 0);
  g_assert_cmpuint (stage_status.st_nlink, ==, 2);
  g_assert_cmpuint (status.st_dev, ==, stage_status.st_dev);
  g_assert_cmpuint (status.st_ino, ==, stage_status.st_ino);
#endif

  wyl_policy_graph_provisioning_record_free (record);
  remove_root (root);
}

typedef struct
{
  const gchar *name;
  const gchar *mutation;
  const gchar *probe;
  const gchar *restore;
} MetadataCase;

static const MetadataCase metadata_cases[] = {
  { "audit", "CREATE TABLE audit_events(id INTEGER);",
    "SELECT COUNT(*) FROM duckdb_tables() WHERE table_name='audit_events';",
    "DROP TABLE audit_events;" },
  { "uuid", "UPDATE fact_store_metadata SET value="
    "'01890f47-3c4b-7cc2-b8c4-dc0c0c079999' WHERE key='store_uuid';",
    "SELECT COUNT(*) FROM fact_store_metadata WHERE key='store_uuid' AND "
    "value='01890f47-3c4b-7cc2-b8c4-dc0c0c079999';",
    "UPDATE fact_store_metadata SET value="
    "'01890f47-3c4b-7cc2-b8c4-dc0c0c070545' WHERE key='store_uuid';" },
  { "format", "UPDATE fact_store_metadata SET value='2' "
    "WHERE key='format_version';",
    "SELECT COUNT(*) FROM fact_store_metadata WHERE key='format_version' "
    "AND value='2';",
    "UPDATE fact_store_metadata SET value='1' WHERE key='format_version';" },
  { "encoding", "UPDATE fact_store_metadata SET value='2' "
    "WHERE key='path_encoding_version';",
    "SELECT COUNT(*) FROM fact_store_metadata "
    "WHERE key='path_encoding_version' AND value='2';",
    "UPDATE fact_store_metadata SET value='1' "
    "WHERE key='path_encoding_version';" },
  { "missing", "ALTER TABLE fact_store_metadata RENAME TO saved_metadata;",
    "SELECT 1-COUNT(*) FROM duckdb_tables() "
    "WHERE table_name='fact_store_metadata';",
    "ALTER TABLE saved_metadata RENAME TO fact_store_metadata;" },
  { "schema", "ALTER TABLE fact_store_metadata RENAME TO saved_metadata;"
    "CREATE TABLE fact_store_metadata AS SELECT * FROM saved_metadata;",
    "SELECT 1-COUNT(*) FROM duckdb_constraints() "
    "WHERE table_name='fact_store_metadata';",
    "DROP TABLE fact_store_metadata;"
    "ALTER TABLE saved_metadata RENAME TO fact_store_metadata;" },
};

static void
query_ok (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result;
  g_assert_cmpint (duckdb_query (conn, sql, &result), ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
}

static gchar *
metadata_snapshot (duckdb_connection conn)
{
  GString *snapshot = g_string_new (NULL);
  const gchar *queries[] = {
    "SELECT table_name,sql FROM duckdb_tables() WHERE schema_name='main' "
    "ORDER BY table_name;",
    "SELECT table_name,column_name,data_type,is_nullable,column_default "
    "FROM information_schema.columns WHERE table_schema='main' "
    "ORDER BY table_name,ordinal_position;",
    "SELECT table_name,constraint_type,constraint_text "
    "FROM duckdb_constraints() WHERE schema_name='main' "
    "ORDER BY table_name,constraint_type,constraint_text;",
    "SELECT key,value FROM saved_metadata ORDER BY key;",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (queries); i++) {
    duckdb_result result;
    g_assert_cmpint (duckdb_query (conn, queries[i], &result), ==,
        DuckDBSuccess);
    for (idx_t row = 0; row < duckdb_row_count (&result); row++)
      for (idx_t column = 0; column < duckdb_column_count (&result); column++) {
        gchar *value = duckdb_value_varchar (&result, column, row);
        g_string_append_printf (snapshot, "%zu:%s;",
            value == NULL ? 0 : strlen (value), value == NULL ? "" : value);
        duckdb_free (value);
      }
    duckdb_destroy_result (&result);
  }
  duckdb_result result;
  g_assert_cmpint (duckdb_query (conn,
      "SELECT COUNT(*) FROM duckdb_tables() "
      "WHERE table_name='fact_store_metadata';", &result), ==, DuckDBSuccess);
  gboolean exists = duckdb_value_int64 (&result, 0, 0) != 0;
  duckdb_destroy_result (&result);
  if (exists) {
    g_assert_cmpint (duckdb_query (conn,
        "SELECT key,value FROM fact_store_metadata ORDER BY key;", &result),
        ==, DuckDBSuccess);
    for (idx_t row = 0; row < duckdb_row_count (&result); row++)
      for (idx_t column = 0; column < 2; column++) {
        gchar *value = duckdb_value_varchar (&result, column, row);
        g_string_append_printf (snapshot, "%s;", value);
        duckdb_free (value);
      }
    duckdb_destroy_result (&result);
  }
  return g_string_free (snapshot, FALSE);
}

static void
close_test_bridge (WylSecureDuckdbBridge *bridge, duckdb_database *db,
    duckdb_connection *conn)
{
  duckdb_disconnect (conn);
  duckdb_close (db);
  g_assert_cmpint (wyl_secure_duckdb_bridge_release_live (bridge), ==,
      WYRELOG_E_OK);
}

static void
test_ordinary_open_rejects_metadata (gconstpointer data)
{
  static const gchar *keys[] = {
    "store_uuid", "format_version", "path_encoding_version", "missing", "schema"
  };
  guint selector = GPOINTER_TO_UINT (data);
  const gchar *key = keys[selector / 2];
  gboolean writable = (selector % 2) != 0;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-ordinary-metadata-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  seed_graph (policy);
  const WylPolicyGraphProvisioningInput input = {
    .tenant_id = tenant_id, .graph_id = graph_id, .store_uuid = store_uuid,
    .format_version = 1, .path_encoding_version = 1,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (policy, &input, root,
      &record), ==, WYRELOG_E_OK);
  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (open_live (policy, root, TRUE, &store), ==, WYRELOG_E_OK);
  g_assert_true (exec_ok (store, "CREATE TABLE probe(x INTEGER);"));
  g_assert_true (exec_ok (store, "INSERT INTO probe VALUES(42);"));
  wyl_fact_store_close (store);
  store = NULL;
  g_assert_cmpint (open_live (policy, root, writable, &store), ==, WYRELOG_E_OK);
  gint64 value = 0;
  g_assert_cmpint (wyl_fact_store_test_query_int64 (store,
      "SELECT x FROM probe;", &value), ==, WYRELOG_E_OK);
  g_assert_cmpint (value, ==, 42);
  wyl_fact_store_close (store);
  store = NULL;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_policy_store_open_fact_graph_directory (policy, root,
      tenant_id, graph_id, FALSE, &directory), ==, WYRELOG_E_OK);
  WylFactGraphProvisionedPair *pair = NULL;
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  gsize length = 0;
  const guint8 *bytes = g_bytes_get_data (record->darwin_operation_evidence,
          &length);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (bytes, length,
      record->op_uuid, &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint
    (wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
        (&directory, record->op_uuid, &evidence, &pair), ==, WYRELOG_E_OK);
#elif defined(G_OS_WIN32)
  g_assert_true (record->has_windows_evidence);
  g_assert_cmpint
    (wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence
        (&directory, record->op_uuid, &record->windows_evidence, &pair), ==,
      WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_fact_graph_directory_open_provisioned_pair_exact
        (&directory, record->op_uuid, &pair), ==, WYRELOG_E_OK);
#endif
  WylFactArtifactNamespace *namespace_ = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (pair, &namespace_), ==, WYRELOG_E_OK);
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  struct stat before, after;
  g_assert_cmpint (stat (path, &before), ==, 0);
  WylSecureDuckdbBridge *bridge = NULL;
  duckdb_database db = NULL;
  duckdb_connection conn = NULL;
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_live_pair (namespace_, TRUE,
      &bridge, &db, &conn), ==, WYRELOG_E_OK);
  query_ok (conn, "ALTER TABLE fact_store_metadata RENAME TO saved_metadata;");
  if (g_strcmp0 (key, "missing") != 0) {
    if (g_strcmp0 (key, "schema") == 0)
      query_ok (conn, "CREATE TABLE fact_store_metadata AS "
          "SELECT * FROM saved_metadata;");
    else {
      query_ok (conn, "CREATE TABLE fact_store_metadata(key VARCHAR PRIMARY KEY,"
          "value VARCHAR NOT NULL);"
          "INSERT INTO fact_store_metadata SELECT * FROM saved_metadata;");
      g_autofree gchar *sql = g_strdup_printf
            ("UPDATE fact_store_metadata SET value='%s' WHERE key='%s';",
              g_strcmp0 (key, "store_uuid") == 0
            ? "01890f47-3c4b-7cc2-b8c4-dc0c0c079999" : "2", key);
      query_ok (conn, sql);
    }
  }
  g_autofree gchar *metadata_before = metadata_snapshot (conn);
  close_test_bridge (bridge, &db, &conn);
  /* The provisioning-aware open reserves and settles a durable open slot even
   * when metadata validation rejects the native store.  That bookkeeping is
   * intentional, so sqlite3_total_changes() is not a valid no-mutation guard
   * here; the metadata snapshot below is the contract under test. */
  g_assert_cmpint (open_live (policy, root, writable, &store), ==,
      WYRELOG_E_POLICY);
  g_assert_null (store);
  g_assert_cmpint (stat (path, &after), ==, 0);
  g_assert_cmpuint (before.st_dev, ==, after.st_dev);
  g_assert_cmpuint (before.st_ino, ==, after.st_ino);
  WylFactArtifactMutationLease *lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (lease);
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_live_pair (namespace_, TRUE,
      &bridge, &db, &conn), ==, WYRELOG_E_OK);
  g_autofree gchar *metadata_after = metadata_snapshot (conn);
  g_assert_cmpstr (metadata_after, ==, metadata_before);
  query_ok (conn, "DROP TABLE IF EXISTS fact_store_metadata;"
      "ALTER TABLE saved_metadata RENAME TO fact_store_metadata;");
  close_test_bridge (bridge, &db, &conn);
  g_assert_cmpint (open_live (policy, root, writable, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_test_query_int64 (store,
      "SELECT x FROM probe;", &value), ==, WYRELOG_E_OK);
  g_assert_cmpint (value, ==, 42);
  wyl_fact_store_close (store);
  wyl_fact_artifact_namespace_free (namespace_);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_policy_graph_provisioning_record_free (record);
  g_clear_pointer (&policy, wyl_policy_store_close);
  remove_root (root);
}

static void
test_leased_open_rejects_corruption (gconstpointer data)
{
  const MetadataCase *test = data;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-leased-audit-rejection-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  seed_graph (policy);
  const WylPolicyGraphProvisioningInput input = {
    .tenant_id = tenant_id, .graph_id = graph_id, .store_uuid = store_uuid,
    .format_version = 1, .path_encoding_version = 1,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (policy, &input, root,
      &record), ==, WYRELOG_E_OK);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_policy_store_open_fact_graph_directory (policy, root,
      tenant_id, graph_id, FALSE, &directory), ==, WYRELOG_E_OK);
  WylFactGraphProvisionedPair *pair = NULL;
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  gsize length = 0;
  const guint8 *bytes = g_bytes_get_data (record->darwin_operation_evidence,
          &length);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (bytes, length,
      record->op_uuid, &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint
    (wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
        (&directory, record->op_uuid, &evidence, &pair), ==, WYRELOG_E_OK);
#elif defined(G_OS_WIN32)
  g_assert_true (record->has_windows_evidence);
  g_assert_cmpint
    (wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence
        (&directory, record->op_uuid, &record->windows_evidence, &pair), ==,
      WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_fact_graph_directory_open_provisioned_pair_exact
        (&directory, record->op_uuid, &pair), ==, WYRELOG_E_OK);
#endif
  WylFactArtifactNamespace *namespace_ = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (pair, &namespace_), ==, WYRELOG_E_OK);
  WylFactArtifactMutationLease *lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);
  const WylFactStoreIdentity identity = {
    .tenant_id = (gchar *) tenant_id, .graph_id = (gchar *) graph_id,
    .store_uuid = (gchar *) store_uuid, .format_version = 1,
    .path_encoding_version = 1,
  };
  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_namespace_with_lease
        (namespace_, lease, &identity, TRUE, &store), ==, WYRELOG_E_OK);
  g_assert_true (exec_ok (store, "CREATE TABLE probe(x INTEGER);"
      "INSERT INTO probe VALUES(42);"));
  g_assert_true (exec_ok (store, test->mutation));
  gint64 observed = 0;
  g_assert_cmpint (wyl_fact_store_test_query_int64 (store, test->probe,
      &observed), ==, WYRELOG_E_OK);
  g_assert_cmpint (observed, ==, 1);
  wyl_fact_store_close (store);
  store = NULL;
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  struct stat before, after;
  g_assert_cmpint (stat (path, &before), ==, 0);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
      graph_id, &authority), ==, WYRELOG_E_OK);
  guint64 generation = authority->lifecycle_generation;
  wyl_policy_graph_authority_record_free (authority);
  g_assert_cmpint (wyl_fact_store_open_provisioned_namespace_with_lease
        (namespace_, lease, &identity, TRUE, &store), ==, WYRELOG_E_POLICY);
  g_assert_null (store);
  /* Rejection must not consume the caller-owned lease. */
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_revalidate (lease), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (stat (path, &after), ==, 0);
  g_assert_cmpuint (after.st_dev, ==, before.st_dev);
  g_assert_cmpuint (after.st_ino, ==, before.st_ino);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
      graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_cmpuint (authority->lifecycle_generation, ==, generation);
  g_assert_cmpstr (authority->store_uuid, ==, store_uuid);
  wyl_policy_graph_authority_record_free (authority);

  /* Inspection/restoration deliberately bypasses the store identity gate,
   * but uses the same bounded namespace and caller-owned lease. */
  WylSecureDuckdbBridge *bridge = NULL;
  duckdb_database db = NULL;
  duckdb_connection conn = NULL;
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_live_with_lease (namespace_,
      lease, TRUE, &bridge, &db, &conn), ==, WYRELOG_E_OK);
  duckdb_result result;
  g_assert_cmpint (duckdb_query (conn, test->probe, &result), ==,
      DuckDBSuccess);
  g_assert_cmpint (duckdb_value_int64 (&result, 0, 0), ==, 1);
  duckdb_destroy_result (&result);
  g_assert_cmpint (duckdb_query (conn, "SELECT x FROM probe;", &result),
      ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_value_int64 (&result, 0, 0), ==, 42);
  duckdb_destroy_result (&result);
  g_assert_cmpint (duckdb_query (conn, test->restore, &result), ==,
      DuckDBSuccess);
  duckdb_destroy_result (&result);
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  wyl_secure_duckdb_bridge_free (bridge);
  g_assert_cmpint (wyl_fact_store_open_provisioned_namespace_with_lease
        (namespace_, lease, &identity, TRUE, &store), ==, WYRELOG_E_OK);
  wyl_fact_store_close (store);
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (namespace_);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_policy_graph_provisioning_record_free (record);
  g_clear_pointer (&policy, wyl_policy_store_close);
  remove_root (root);
}

#ifdef __APPLE__
/* Policy only constrains the Darwin envelope's size.  Store-open must decode
 * its contents before touching the caller's fact root. */
static void
test_malformed_darwin_evidence_fails_before_filesystem (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-provisioned-malformed-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) policy_store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy_store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy_store), ==,
      WYRELOG_E_OK);
  seed_graph (policy_store);
  const WylPolicyGraphProvisioningInput input = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .store_uuid = store_uuid,
    .format_version = 1,
    .path_encoding_version = 1,
    .expected_lifecycle_generation = 0,
    .expected_reconciliation_generation = 0,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_prepare (policy_store,
      &input, &record, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  guint8 malformed_bytes[WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE] = {
    0,
  };
  g_autoptr (GBytes) malformed = g_bytes_new_static (malformed_bytes,
          sizeof malformed_bytes);
  g_assert_cmpint (wyl_policy_store_graph_provisioning_set_darwin_evidence
        (policy_store, record->op_uuid, malformed, &mutation), ==,
      WYRELOG_E_OK);
  const WylPolicyGraphProvisioningPhase phases[] = {
    WYL_POLICY_GRAPH_PROVISIONING_RESERVED,
    WYL_POLICY_GRAPH_PROVISIONING_STAGED,
    WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED,
    WYL_POLICY_GRAPH_PROVISIONING_VERIFIED,
    WYL_POLICY_GRAPH_PROVISIONING_ACTIVE,
  };
  for (gsize i = 0; i + 1 < G_N_ELEMENTS (phases); i++)
    g_assert_cmpint (wyl_policy_store_graph_provisioning_transition
          (policy_store, record->op_uuid, phases[i], phases[i + 1], 0,
        WYL_POLICY_GRAPH_ERROR_NONE, &mutation), ==, WYRELOG_E_OK);
  wyl_policy_graph_provisioning_record_free (record);
  remove_root (root);

  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy_store, root,
      tenant_id, graph_id, FALSE, &store), ==, WYRELOG_E_POLICY);
  g_assert_null (store);
}
#endif

/* The Windows artifact namespace cannot export physical-quota evidence yet
 * (it fails closed with POLICY), so a Windows store has no physical admission
 * to settle; these cases run where the evidence exists. */
#ifndef G_OS_WIN32
/* #1499: a COMMIT that DuckDB reports as failed has an unknown outcome.  The
 * durable-autocheckpoint error says the transaction is durable; a commit that
 * DuckDB reverts is not.  Either way the physical quota must
 * settle from what is on disk instead of parking the reservation's whole
 * headroom in reconciling_bytes, which no later operation releases. */
typedef struct
{
  const gchar *name;
  const gchar *arm;
  gboolean durable;
  /* Run through the graph-wide update path instead of the append path. */
  gboolean update;
} CommitOutcomeCase;

static const CommitOutcomeCase commit_outcome_cases[] = {
  { "durable-commit-reported-failed",
    "SET auto_checkpoint_skip_wal_threshold=9999999999;"
    "SET wal_autocheckpoint_entries=1;"
    "SET debug_checkpoint_abort='before_header'", TRUE, FALSE },
  { "commit-failure-not-durable",
    "SET debug_force_commit_failure=true", FALSE, FALSE },
  { "durable-update-reported-failed",
    "SET auto_checkpoint_skip_wal_threshold=9999999999;"
    "SET wal_autocheckpoint_entries=1;"
    "SET debug_checkpoint_abort='before_header'", TRUE, TRUE },
  { "update-commit-failure-not-durable",
    "SET debug_force_commit_failure=true", FALSE, TRUE },
};

static sqlite3 *
policy_db (wyl_policy_store_t *policy_store)
{
  return wyl_policy_store_get_db (policy_store);
}

static gint64
graph_charge (wyl_policy_store_t *policy_store)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (policy_db (policy_store),
      "SELECT COALESCE(SUM(charged_bytes),0) FROM "
      "fact_physical_quota_graph_charges WHERE tenant_id='tenant-provision'",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 charged = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return charged;
}

static void
assert_physical_settled (wyl_policy_store_t *policy_store,
    WylPolicyFactPhysicalQuotaStatus *out_status)
{
  g_assert_cmpint (wyl_policy_store_get_fact_physical_quota_status
        (policy_store, tenant_id, out_status), ==, WYRELOG_E_OK);
  g_assert_cmpuint (out_status->pending_bytes, ==, 0);
  g_assert_cmpuint (out_status->reconciling_bytes, ==, 0);
  g_assert_cmpuint (out_status->committed_bytes, ==,
      (guint64) graph_charge (policy_store));
}

/* The reservation's state: an uncertain cancel parks it in "reconciling", a
 * definite one in "cancelled"; only a settle from observation leaves it
 * "settled" with the graph charged for what is on disk. */
static gchar *
reservation_state (wyl_policy_store_t *policy_store, const gchar *request)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (policy_db (policy_store),
      "SELECT state FROM fact_physical_quota_reservations WHERE request_id=?1",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, request, -1, SQLITE_STATIC),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gchar *state = g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
  sqlite3_finalize (stmt);
  return state;
}

/* #1523: what the physical reservation looked like when the retry's batch
 * transaction was about to COMMIT, i.e. after admission and before finish. */
typedef struct
{
  wyl_policy_store_t *policy_store;
  gboolean seen;
  gchar *state;
  guint64 pending_bytes;
} AdmissionProbe;

static wyrelog_error_t
admission_probe_hook (WylFactStoreTransactionTestKind kind,
    WylFactStoreTransactionTestPhase phase, gpointer user_data)
{
  AdmissionProbe *probe = user_data;
  if (kind != WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE
      || phase != WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT || probe->seen)
    return WYRELOG_E_OK;
  probe->seen = TRUE;
  probe->state = reservation_state (probe->policy_store, "outcome");
  WylPolicyFactPhysicalQuotaStatus status = { 0 };
  g_assert_cmpint (wyl_policy_store_get_fact_physical_quota_status
        (probe->policy_store, tenant_id, &status), ==, WYRELOG_E_OK);
  probe->pending_bytes = status.pending_bytes;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
commit_outcome_apply (wyl_fact_store_t *store, const CommitOutcomeCase *c,
    const wyl_policy_fact_relation_schema_options_t *schema,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted)
{
  if (!c->update)
    return wyl_fact_store_append_batch (store, schema, batch, out_inserted);
  wyl_fact_store_batch_t update = *batch;
  update.op = WYL_FACT_STORE_OP_UPDATE;
  const wyl_fact_store_update_part_t part = {.schema = schema,.batch = &update };
  return wyl_fact_store_update_graph_batches (store, &part, 1, out_inserted);
}

static void
test_commit_outcome_settles_physical_quota (gconstpointer data)
{
  const CommitOutcomeCase *c = data;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-commit-outcome-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) policy_store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy_store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy_store), ==,
      WYRELOG_E_OK);
  seed_graph (policy_store);
  const WylPolicyGraphProvisioningInput input = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .store_uuid = store_uuid,
    .format_version = 1,
    .path_encoding_version = 1,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (policy_store, &input, root,
      &record), ==, WYRELOG_E_OK);
  wyl_policy_graph_provisioning_record_free (record);
  WylPolicyFactQuotaConfig limit = {
    .has_limit = TRUE,
    .hard_limit = G_GUINT64_CONSTANT (1) << 30,
  };
  g_assert_cmpint (wyl_policy_store_set_fact_quota_config (policy_store,
      tenant_id, WYL_POLICY_FACT_QUOTA_PHYSICAL_BYTES, &limit), ==,
      WYRELOG_E_OK);

  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"k", "symbol", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop",
    .relation_name = "item",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  wyl_fact_value_t values[2] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "baseline" },
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "outcome" },
  };
  const wyl_fact_row_t rows[2] = {
    {.values = &values[0],.n_values = 1 },
    {.values = &values[1],.n_values = 1 },
  };
  wyl_fact_store_batch_t baseline = {
    .batch_id = "baseline",
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop",
    .relation_name = "item",
    .schema_version = 1,
    .source = "unit-test",
    .request_id = "baseline",
    .idempotency_key = "baseline",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = &rows[0],
    .n_rows = 1,
  };
  wyl_fact_store_batch_t batch = baseline;
  batch.batch_id = "outcome";
  batch.request_id = "outcome";
  batch.idempotency_key = "outcome";
  batch.rows = &rows[1];

  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (open_live (policy_store, root, TRUE, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &baseline,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  WylPolicyFactPhysicalQuotaStatus before = { 0 };
  assert_physical_settled (policy_store, &before);
  g_assert_cmpuint (before.committed_bytes, >, 0);

  g_assert_true (exec_ok (store, c->arm));
  /* The store poisons itself: the ROLLBACK after the failed COMMIT finds no
   * transaction. */
  g_assert_cmpint (commit_outcome_apply (store, c, &schema, &batch,
      &inserted), ==, WYRELOG_E_INTERNAL);
  WylPolicyFactPhysicalQuotaStatus after = { 0 };
  assert_physical_settled (policy_store, &after);
  g_assert_cmpuint (after.committed_bytes, >=, before.committed_bytes);
  g_autofree gchar *state = reservation_state (policy_store, "outcome");
  g_assert_cmpstr (state, ==, "settled");
  wyl_fact_store_close (store);

  /* Reopen: the batch is present exactly when the commit was durable, and the
   * identical retry is then a replay that leaves the accounting alone. */
  store = NULL;
  g_assert_cmpint (open_live (policy_store, root, TRUE, &store), ==,
      WYRELOG_E_OK);
  gint64 present = -1;
  g_assert_cmpint (wyl_fact_store_test_query_int64 (store,
      "SELECT COUNT(*) FROM fact_batches WHERE batch_id='outcome';",
      &present), ==, WYRELOG_E_OK);
  g_assert_cmpint (present, ==, c->durable ? 1 : 0);
  if (c->durable) {
    g_assert_cmpint (commit_outcome_apply (store, c, &schema, &batch,
        &inserted), ==, WYRELOG_E_OK);
    g_assert_false (inserted);
    WylPolicyFactPhysicalQuotaStatus replay = { 0 };
    assert_physical_settled (policy_store, &replay);
    g_assert_cmpuint (replay.committed_bytes, ==, after.committed_bytes);
  } else {
    /* #1523: the lost commit's identical retry, under the same key, is a new
     * attempt: admitted again (pending while its transaction commits), then
     * settled and charged once. */
    AdmissionProbe probe = {.policy_store = policy_store };
    wyl_fact_store_test_set_transaction_hook (store, admission_probe_hook,
        &probe);
    g_assert_cmpint (commit_outcome_apply (store, c, &schema, &batch,
        &inserted), ==, WYRELOG_E_OK);
    wyl_fact_store_test_set_transaction_hook (store, NULL, NULL);
    g_assert_true (inserted);
    g_assert_true (probe.seen);
    g_assert_cmpstr (probe.state, ==, "pending");
    g_assert_cmpuint (probe.pending_bytes, >, 0);
    g_free (probe.state);
    g_assert_cmpint (wyl_fact_store_test_query_int64 (store,
        "SELECT COUNT(*) FROM fact_batches WHERE batch_id='outcome';",
        &present), ==, WYRELOG_E_OK);
    g_assert_cmpint (present, ==, 1);
    WylPolicyFactPhysicalQuotaStatus retried = { 0 };
    assert_physical_settled (policy_store, &retried);
    g_assert_cmpuint (retried.committed_bytes, >=, after.committed_bytes);
    g_autofree gchar *retry_state = reservation_state (policy_store,
            "outcome");
    g_assert_cmpstr (retry_state, ==, "settled");
  }
  wyl_fact_store_close (store);
  remove_root (root);
}
#endif

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func (
    "/fact/store-provisioned/open-provisioned-pair-persists-across-reopen",
    test_open_provisioned_pair_persists_across_reopen);
  for (guint i = 0; i < 10; i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/metadata/%u/%s", i / 2,
            i % 2 != 0 ? "writable" : "readonly");
    g_test_add_data_func (name, GUINT_TO_POINTER (i),
        test_ordinary_open_rejects_metadata);
  }
  for (gsize i = 0; i < G_N_ELEMENTS (metadata_cases); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/leased-open-rejects-%s",
            metadata_cases[i].name);
    g_test_add_data_func (name, &metadata_cases[i],
        test_leased_open_rejects_corruption);
  }
#ifndef G_OS_WIN32
  for (gsize i = 0; i < G_N_ELEMENTS (commit_outcome_cases); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/physical-quota/%s",
            commit_outcome_cases[i].name);
    g_test_add_data_func (name, &commit_outcome_cases[i],
        test_commit_outcome_settles_physical_quota);
  }
#endif
#ifdef __APPLE__
  g_test_add_func (
    "/fact/store-provisioned/malformed-darwin-evidence-fails-before-filesystem",
    test_malformed_darwin_evidence_fails_before_filesystem);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

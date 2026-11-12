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

/* A provisioned graph with a physical limit and one committed baseline
 * batch; the batch under test and a second, unrelated one are prepared. */
typedef struct
{
  gchar *root;
  wyl_policy_store_t *policy_store;
  wyl_policy_fact_relation_schema_column_t columns[1];
  wyl_policy_fact_relation_schema_options_t schema;
  wyl_fact_value_t values[3];
  wyl_fact_row_t rows[3];
  wyl_fact_store_batch_t baseline;
  wyl_fact_store_batch_t batch;
  wyl_fact_store_batch_t other;
  wyl_fact_store_t *store;
} PhysicalFixture;

static void
physical_fixture_init (PhysicalFixture *fx)
{
  g_autoptr (GError) error = NULL;
  *fx = (PhysicalFixture) { 0 };
  fx->root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-commit-outcome-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_cmpint (wyl_policy_store_open (NULL, &fx->policy_store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fx->policy_store), ==,
      WYRELOG_E_OK);
  seed_graph (fx->policy_store);
  const WylPolicyGraphProvisioningInput input = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .store_uuid = store_uuid,
    .format_version = 1,
    .path_encoding_version = 1,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (fx->policy_store, &input,
      fx->root, &record), ==, WYRELOG_E_OK);
  wyl_policy_graph_provisioning_record_free (record);
  WylPolicyFactQuotaConfig limit = {
    .has_limit = TRUE,
    .hard_limit = G_GUINT64_CONSTANT (1) << 30,
  };
  g_assert_cmpint (wyl_policy_store_set_fact_quota_config (fx->policy_store,
      tenant_id, WYL_POLICY_FACT_QUOTA_PHYSICAL_BYTES, &limit), ==,
      WYRELOG_E_OK);
  fx->columns[0] = (wyl_policy_fact_relation_schema_column_t) {
    "k", "symbol", FALSE, TRUE
  };
  fx->schema = (wyl_policy_fact_relation_schema_options_t) {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop",
    .relation_name = "item",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = fx->columns,
    .n_columns = G_N_ELEMENTS (fx->columns),
  };
  const gchar *texts[3] = { "baseline", "outcome", "other" };
  for (gsize i = 0; i < 3; i++) {
    fx->values[i].type = WYL_FACT_VALUE_SYMBOL;
    fx->values[i].as.text = texts[i];
    fx->rows[i].values = &fx->values[i];
    fx->rows[i].n_values = 1;
  }
  fx->baseline = (wyl_fact_store_batch_t) {
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
    .rows = &fx->rows[0],
    .n_rows = 1,
  };
  fx->batch = fx->baseline;
  fx->batch.batch_id = "outcome";
  fx->batch.request_id = "outcome";
  fx->batch.idempotency_key = "outcome";
  fx->batch.rows = &fx->rows[1];
  fx->other = fx->baseline;
  fx->other.batch_id = "other";
  fx->other.request_id = "other";
  fx->other.idempotency_key = "other";
  fx->other.rows = &fx->rows[2];
  g_assert_cmpint (open_live (fx->policy_store, fx->root, TRUE, &fx->store),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_store_create_schema (fx->store), ==, WYRELOG_E_OK);
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (fx->store, &fx->schema,
      &fx->baseline, &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
}

static void
physical_fixture_clear (PhysicalFixture *fx)
{
  g_clear_pointer (&fx->store, wyl_fact_store_close);
  remove_root (fx->root);
  g_clear_pointer (&fx->root, g_free);
  g_clear_pointer (&fx->policy_store, wyl_policy_store_close);
}

static void
test_commit_outcome_settles_physical_quota (gconstpointer data)
{
  const CommitOutcomeCase *c = data;
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  wyl_policy_store_t *policy_store = fx.policy_store;
  const wyl_policy_fact_relation_schema_options_t schema = fx.schema;
  wyl_fact_store_batch_t batch = fx.batch;
  wyl_fact_store_t *store = fx.store;
  gboolean inserted = FALSE;
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
  g_assert_cmpint (open_live (policy_store, fx.root, TRUE, &store), ==,
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
  fx.store = store;
  physical_fixture_clear (&fx);
}

/* #1523: a mutation that fails before COMMIT is issued leaves no batch, so
 * its reservation must not hold the tenant's headroom: it settles from the
 * observation like any other attempt (normally charging nothing), the tenant
 * can keep appending, and the identical retry is admitted and settled once. */
typedef struct
{
  const gchar *name;
  WylFactStoreBatchFault fault;
  gboolean update;
} PrecommitCase;

static const PrecommitCase precommit_cases[] = {
  { "before-commit-append", WYL_FACT_STORE_BATCH_FAULT_BEFORE_COMMIT, FALSE },
  { "at-commit-append", WYL_FACT_STORE_BATCH_FAULT_AT_COMMIT, FALSE },
  { "before-commit-update", WYL_FACT_STORE_BATCH_FAULT_BEFORE_COMMIT, TRUE },
  { "at-commit-update", WYL_FACT_STORE_BATCH_FAULT_AT_COMMIT, TRUE },
};

static wyrelog_error_t
physical_apply (PhysicalFixture *fx, gboolean update,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted)
{
  const CommitOutcomeCase c = {.update = update };
  return commit_outcome_apply (fx->store, &c, &fx->schema, batch,
             out_inserted);
}

static void
test_precommit_failure_releases_physical_quota (gconstpointer data)
{
  const PrecommitCase *c = data;
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  WylPolicyFactPhysicalQuotaStatus before = { 0 };
  assert_physical_settled (fx.policy_store, &before);
  gboolean inserted = TRUE;
  wyl_fact_store_set_batch_fault_once_for_test (fx.store, c->fault);
  g_assert_cmpint (physical_apply (&fx, c->update, &fx.batch, &inserted), ==,
      WYRELOG_E_IO);
  g_assert_false (inserted);
  WylPolicyFactPhysicalQuotaStatus after = { 0 };
  assert_physical_settled (fx.policy_store, &after);
  g_assert_cmpuint (after.committed_bytes, >=, before.committed_bytes);
  g_autofree gchar *state = reservation_state (fx.policy_store, "outcome");
  g_assert_cmpstr (state, ==, "settled");

  /* The tenant is not locked out: an unrelated append is admitted. */
  g_assert_cmpint (physical_apply (&fx, FALSE, &fx.other, &inserted), ==,
      WYRELOG_E_OK);
  g_assert_true (inserted);

  /* The identical retry is a new attempt, admitted and settled once. */
  AdmissionProbe probe = {.policy_store = fx.policy_store };
  wyl_fact_store_test_set_transaction_hook (fx.store, admission_probe_hook,
      &probe);
  g_assert_cmpint (physical_apply (&fx, c->update, &fx.batch, &inserted), ==,
      WYRELOG_E_OK);
  wyl_fact_store_test_set_transaction_hook (fx.store, NULL, NULL);
  g_assert_true (inserted);
  g_assert_true (probe.seen);
  g_assert_cmpstr (probe.state, ==, "pending");
  g_assert_cmpuint (probe.pending_bytes, >, 0);
  g_free (probe.state);
  WylPolicyFactPhysicalQuotaStatus retried = { 0 };
  assert_physical_settled (fx.policy_store, &retried);
  g_autofree gchar *retry_state = reservation_state (fx.policy_store,
          "outcome");
  g_assert_cmpstr (retry_state, ==, "settled");
  physical_fixture_clear (&fx);
}

/* #1522: a tenant with a physical limit can append, and once the graph's
 * usage has reached the limit the next mutation is refused as over quota (the
 * daemon's 429) without writing it, reserving anything, or charging the
 * graph; raising the limit then admits it.  A limit below what the tenant
 * already uses cannot be configured at all: the policy store refuses it with
 * WYRELOG_E_CONFLICT. */
typedef struct
{
  const gchar *name;
  gboolean update;
} LimitCase;

static const LimitCase limit_cases[] = {
  { "append-at-limit", FALSE },
  { "update-at-limit", TRUE },
};

static gint64
reservation_count (wyl_policy_store_t *policy_store, const gchar *request)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (policy_db (policy_store),
      "SELECT COUNT(*) FROM fact_physical_quota_reservations "
      "WHERE request_id=?1", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, request, -1, SQLITE_STATIC),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static void
set_physical_limit (wyl_policy_store_t *policy_store, guint64 hard_limit)
{
  WylPolicyFactQuotaConfig limit = {
    .has_limit = TRUE,
    .hard_limit = hard_limit,
  };
  g_assert_cmpint (wyl_policy_store_set_fact_quota_config (policy_store,
      tenant_id, WYL_POLICY_FACT_QUOTA_PHYSICAL_BYTES, &limit), ==,
      WYRELOG_E_OK);
}

static wyrelog_error_t
physical_apply_delta (PhysicalFixture *fx, gboolean update,
    const wyl_fact_store_batch_t *batch, gboolean *out_inserted,
    wyl_fact_commit_delta_t *out_delta)
{
  if (!update)
    return wyl_fact_store_append_batch_delta (fx->store, &fx->schema, batch,
               out_inserted, out_delta);
  wyl_fact_store_batch_t as_update = *batch;
  as_update.op = WYL_FACT_STORE_OP_UPDATE;
  const wyl_fact_store_update_part_t part = {
    .schema = &fx->schema,
    .batch = &as_update,
  };
  return wyl_fact_store_update_graph_batches_delta (fx->store, &part, 1,
             out_inserted, out_delta);
}

static void
test_physical_limit_admits_and_refuses (gconstpointer data)
{
  const LimitCase *c = data;
  PhysicalFixture fx;
  /* The fixture's baseline append is itself admitted under the limit. */
  physical_fixture_init (&fx);
  WylPolicyFactPhysicalQuotaStatus before = { 0 };
  assert_physical_settled (fx.policy_store, &before);
  g_assert_cmpuint (before.committed_bytes, >, 0);
  const gint64 charge = graph_charge (fx.policy_store);
  WylPolicyFactQuotaConfig below_usage = {
    .has_limit = TRUE,
    .hard_limit = before.committed_bytes - 1,
  };
  g_assert_cmpint (wyl_policy_store_set_fact_quota_config (fx.policy_store,
      tenant_id, WYL_POLICY_FACT_QUOTA_PHYSICAL_BYTES, &below_usage), ==,
      WYRELOG_E_CONFLICT);

  set_physical_limit (fx.policy_store, before.committed_bytes);
  gboolean inserted = TRUE;
  wyl_fact_commit_delta_t delta = { 0 };
  g_assert_cmpint (physical_apply_delta (&fx, c->update, &fx.other, &inserted,
      &delta), ==, WYRELOG_E_POLICY);
  g_assert_true (delta.quota_exceeded);
  g_assert_false (inserted);
  WylPolicyFactPhysicalQuotaStatus refused = { 0 };
  assert_physical_settled (fx.policy_store, &refused);
  g_assert_cmpuint (refused.committed_bytes, ==, before.committed_bytes);
  g_assert_cmpint (graph_charge (fx.policy_store), ==, charge);
  g_assert_cmpint (reservation_count (fx.policy_store, "other"), ==, 0);
  gint64 present = -1;
  g_assert_cmpint (wyl_fact_store_test_query_int64 (fx.store,
      "SELECT COUNT(*) FROM fact_batches WHERE batch_id='other';",
      &present), ==, WYRELOG_E_OK);
  g_assert_cmpint (present, ==, 0);

  set_physical_limit (fx.policy_store, G_GUINT64_CONSTANT (1) << 30);
  delta = (wyl_fact_commit_delta_t) { 0 };
  g_assert_cmpint (physical_apply_delta (&fx, c->update, &fx.other, &inserted,
      &delta), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  g_assert_false (delta.quota_exceeded);
  WylPolicyFactPhysicalQuotaStatus admitted = { 0 };
  assert_physical_settled (fx.policy_store, &admitted);
  g_assert_cmpuint (admitted.committed_bytes, >=, before.committed_bytes);
  g_autofree gchar *state = reservation_state (fx.policy_store, "other");
  g_assert_cmpstr (state, ==, "settled");
  physical_fixture_clear (&fx);
}

/* The fallback cases arm the shared namespace test fault, which a Windows
 * build defines only with the artifact test hooks. */
#if !defined (G_OS_WIN32) || defined (WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS)

/* #1523: when the observation cannot be taken, or the settle fails, the
 * reservation is cancelled instead: definitely when no COMMIT was issued, so
 * nothing is held back, and as uncertain (reconciling) when COMMIT was issued,
 * whether it failed with an unknown outcome or succeeded. */
typedef enum
{
  FALLBACK_PRECOMMIT_EXPORT_FAILS,
  FALLBACK_PRECOMMIT_SETTLE_FAILS,
  FALLBACK_UNKNOWN_EXPORT_FAILS,
  FALLBACK_COMMIT_EXPORT_FAILS,
  FALLBACK_COMMIT_SETTLE_FAILS,
} FallbackMode;

typedef struct
{
  const gchar *name;
  FallbackMode mode;
  wyrelog_error_t rc;
  const gchar *state;
} FallbackCase;

static const FallbackCase fallback_cases[] = {
  { "precommit-observation-fails", FALLBACK_PRECOMMIT_EXPORT_FAILS,
    WYRELOG_E_IO, "cancelled" },
  { "precommit-settle-fails", FALLBACK_PRECOMMIT_SETTLE_FAILS, WYRELOG_E_IO,
    "cancelled" },
  { "unknown-outcome-observation-fails", FALLBACK_UNKNOWN_EXPORT_FAILS,
    WYRELOG_E_INTERNAL, "reconciling" },
  { "commit-observation-fails", FALLBACK_COMMIT_EXPORT_FAILS, WYRELOG_E_OK,
    "reconciling" },
  { "commit-settle-fails", FALLBACK_COMMIT_SETTLE_FAILS, WYRELOG_E_IO,
    "reconciling" },
};

/* Arms the inventory fault, so the next evidence export fails, at one phase
 * of the batch transaction itself: after the reserve-time export, before the
 * finish-time one. */
typedef struct
{
  WylFactStoreTransactionTestPhase phase;
  gboolean armed;
} ExportFaultHook;

static wyrelog_error_t
export_fault_hook (WylFactStoreTransactionTestKind kind,
    WylFactStoreTransactionTestPhase phase, gpointer user_data)
{
  ExportFaultHook *hook = user_data;
  if (kind == WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE
      && phase == hook->phase && !hook->armed) {
    hook->armed = TRUE;
    wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INVENTORY_PRE_FINALIZE);
  }
  return WYRELOG_E_OK;
}

static void
test_physical_quota_fallback (gconstpointer data)
{
  const FallbackCase *c = data;
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  ExportFaultHook hook = {
    .phase = c->mode == FALLBACK_COMMIT_EXPORT_FAILS
        ? WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT
        : WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK,
  };
  if (c->mode == FALLBACK_PRECOMMIT_EXPORT_FAILS
      || c->mode == FALLBACK_PRECOMMIT_SETTLE_FAILS)
    wyl_fact_store_set_batch_fault_once_for_test (fx.store,
        WYL_FACT_STORE_BATCH_FAULT_BEFORE_COMMIT);
  const gboolean settle_fails = c->mode == FALLBACK_PRECOMMIT_SETTLE_FAILS
      || c->mode == FALLBACK_COMMIT_SETTLE_FAILS;
  if (settle_fails)
    wyl_policy_store_fail_next_fact_physical_settle_for_test
      (fx.policy_store);
  else
    wyl_fact_store_test_set_transaction_hook (fx.store, export_fault_hook,
        &hook);
  if (c->mode == FALLBACK_UNKNOWN_EXPORT_FAILS)
    g_assert_true (exec_ok (fx.store,
        "SET auto_checkpoint_skip_wal_threshold=9999999999;"
        "SET wal_autocheckpoint_entries=1;"
        "SET debug_checkpoint_abort='before_header'"));
  gboolean inserted = FALSE;
  g_assert_cmpint (physical_apply (&fx, FALSE, &fx.batch, &inserted), ==,
      c->rc);
  wyl_fact_store_test_set_transaction_hook (fx.store, NULL, NULL);
  if (!settle_fails) {
    g_assert_true (hook.armed);
    g_assert_true (wyl_fact_artifact_namespace_test_fault_was_consumed
          (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INVENTORY_PRE_FINALIZE));
  }
  g_autofree gchar *state = reservation_state (fx.policy_store, "outcome");
  g_assert_cmpstr (state, ==, c->state);
  WylPolicyFactPhysicalQuotaStatus status = { 0 };
  g_assert_cmpint (wyl_policy_store_get_fact_physical_quota_status
        (fx.policy_store, tenant_id, &status), ==, WYRELOG_E_OK);
  g_assert_cmpuint (status.pending_bytes, ==, 0);
  if (g_strcmp0 (c->state, "cancelled") == 0)
    g_assert_cmpuint (status.reconciling_bytes, ==, 0);
  else
    g_assert_cmpuint (status.reconciling_bytes, >, 0);
  physical_fixture_clear (&fx);
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
  for (gsize i = 0; i < G_N_ELEMENTS (commit_outcome_cases); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/physical-quota/%s",
            commit_outcome_cases[i].name);
    g_test_add_data_func (name, &commit_outcome_cases[i],
        test_commit_outcome_settles_physical_quota);
  }
  for (gsize i = 0; i < G_N_ELEMENTS (precommit_cases); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/physical-quota/precommit/%s",
            precommit_cases[i].name);
    g_test_add_data_func (name, &precommit_cases[i],
        test_precommit_failure_releases_physical_quota);
  }
  for (gsize i = 0; i < G_N_ELEMENTS (limit_cases); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/physical-quota/limit/%s",
            limit_cases[i].name);
    g_test_add_data_func (name, &limit_cases[i],
        test_physical_limit_admits_and_refuses);
  }
#if !defined (G_OS_WIN32) || defined (WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS)
  for (gsize i = 0; i < G_N_ELEMENTS (fallback_cases); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/physical-quota/fallback/%s",
            fallback_cases[i].name);
    g_test_add_data_func (name, &fallback_cases[i],
        test_physical_quota_fallback);
  }
#endif
#ifdef __APPLE__
  g_test_add_func (
    "/fact/store-provisioned/malformed-darwin-evidence-fails-before-filesystem",
    test_malformed_darwin_evidence_fails_before_filesystem);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

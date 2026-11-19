/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <sys/stat.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#include "fact-test-support.h"
#include "wyl-request-id-private.h"
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
  gchar *policy_path;
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
physical_fixture_init_full (PhysicalFixture *fx, gboolean persistent)
{
  g_autoptr (GError) error = NULL;
  *fx = (PhysicalFixture) { 0 };
  fx->root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-commit-outcome-XXXXXX", &error);
  g_assert_no_error (error);
  if (persistent) {
    g_autofree gchar *uuid = g_uuid_string_random ();
    fx->policy_path = g_strdup_printf ("%s/wyl-quota-%s.sqlite", g_get_tmp_dir (), uuid);
  }
  g_assert_cmpint (wyl_policy_store_open (fx->policy_path, &fx->policy_store), ==,
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
  WylPolicyGraphMaterializationState materialization;
  g_assert_cmpint (wyl_policy_store_read_fact_graph_materialization (fx->policy_store,
      tenant_id, graph_id, &materialization), ==, WYRELOG_E_OK);
  WylPolicyAuthorityMutationResult changed = { 0 };
  if (materialization == WYL_POLICY_GRAPH_MATERIALIZATION_UNKNOWN) {
    g_assert_cmpint (wyl_policy_store_transition_fact_graph_materialization (fx->policy_store, tenant_id, graph_id, materialization, WYL_POLICY_GRAPH_MATERIALIZATION_PENDING, &changed), ==, WYRELOG_E_OK);
    materialization = WYL_POLICY_GRAPH_MATERIALIZATION_PENDING;
  }
  g_assert_cmpint (wyl_policy_store_transition_fact_graph_materialization (fx->policy_store,
      tenant_id, graph_id, materialization, WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED,
      &changed), ==, WYRELOG_E_OK);
}

static void
physical_fixture_init (PhysicalFixture *fx)
{
  physical_fixture_init_full (fx, FALSE);
}

static void
physical_fixture_clear (PhysicalFixture *fx)
{
  g_clear_pointer (&fx->store, wyl_fact_store_close);
  remove_root (fx->root);
  g_clear_pointer (&fx->root, g_free);
  g_clear_pointer (&fx->policy_store, wyl_policy_store_close);
  if (fx->policy_path != NULL) {
    g_unlink (fx->policy_path);
    g_autofree gchar *wal = g_strconcat (fx->policy_path, "-wal", NULL);
    g_autofree gchar *shm = g_strconcat (fx->policy_path, "-shm", NULL);
    g_unlink (wal);
    g_unlink (shm);
    g_clear_pointer (&fx->policy_path, g_free);
  }
}

static gint64
physical_scalar (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 result = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return result;
}

static void
physical_assert_invariant (sqlite3 *db)
{
  g_assert_cmpint (physical_scalar (db,
      "SELECT count(*) FROM fact_tenant_physical_quota_usage u WHERE committed_bytes != "
      "(SELECT coalesce(sum(charged_bytes),0) FROM fact_physical_quota_graph_charges g "
      "WHERE g.tenant_id=u.tenant_id);"), ==, 0);
  g_assert_cmpint (physical_scalar (db,
      "SELECT count(*) FROM fact_open_reservations WHERE state != 'settled';"), ==, 0);
}

static const gchar recompute_request[] = "0ujtsYcgvSTl8PAuAdqWYSMnLOv";

static wyrelog_error_t
physical_recompute (PhysicalFixture *fx, WylPolicyFactPhysicalQuotaRecomputeResult *result)
{
  return wyl_fact_store_recompute_graph_physical_quota (fx->policy_store,
             fx->root, tenant_id, graph_id, NULL, "tenant-owner", recompute_request, result);
}

static WylFactArtifactNamespace *
physical_namespace (PhysicalFixture *fx)
{
  WylPolicyGraphProvisioningRecord *record = NULL;
  GPtrArray *records = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list (fx->policy_store,
      tenant_id, &records), ==, WYRELOG_E_OK);
  for (guint i=0; i<records->len; i++) {
    WylPolicyGraphProvisioningRecord *r = g_ptr_array_index (records,i);
    if (!g_strcmp0 (r->graph_id, graph_id)) record=r;
  }
  g_assert_nonnull (record);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_policy_store_open_fact_graph_directory (fx->policy_store,
      fx->root, tenant_id, graph_id, FALSE, &directory), ==, WYRELOG_E_OK);
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
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  g_ptr_array_unref (records);
  return namespace_;
}

#ifndef G_OS_WIN32
static void
physical_settle_temp_peak (PhysicalFixture *fx)
{
  WylFactArtifactNamespace *ns = physical_namespace (fx);
  WylFactArtifactMutationLease *lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (ns, &lease), ==, WYRELOG_E_OK);
  WylFactDuckdbTempRoot *root = NULL;
  WylFactDuckdbTempChild *child = NULL;
  WylFactDuckdbTempChildBinding *binding = NULL;
  WylFactDuckdbTempOrphanEvidence *orphan = NULL;
  gint fd = -1;
  g_autofree gchar *temp_name = g_strdup_printf ("duckdb_temp_%ld_0_storage_DEFAULT-0.tmp", (long) getpid ());
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence (lease, &root, &orphan), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_binding (root,
      temp_name, &child, &binding, &fd, &orphan), ==, WYRELOG_E_OK);
  guint8 bytes[65536] = { 1 };
  for (guint i=0; i<256; i++) {
    g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding, fd), ==, WYRELOG_E_OK);
    g_assert_cmpint (write (fd, bytes, sizeof bytes), ==, sizeof bytes);
    g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding, fd), ==, WYRELOG_E_OK);
  }
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd), ==, WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  g_autoptr (WylFactArtifactPhysicalQuotaEvidence) evidence = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_export_physical_quota_evidence_with_lease (ns, lease, &evidence), ==, WYRELOG_E_OK);
  WylPolicyFactPhysicalOperationStatus status = { 0 };
  g_assert_cmpint (wyl_policy_store_reserve_fact_physical_quota_evidence (fx->policy_store,
      tenant_id, graph_id, "temp-peak", evidence, 0, &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_settle_fact_physical_quota_evidence (fx->policy_store,
      tenant_id, graph_id, "temp-peak", evidence, &status), ==, WYRELOG_E_OK);
  WylFactDuckdbTempRetireResult retired = { 0 };
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (child, &retired), ==, WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_free (child);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_retire (root, &retired), ==, WYRELOG_E_OK);
  wyl_fact_duckdb_temp_root_free (root);
  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (ns);
}
#endif

/* Use real secure engine files and their post-shutdown allocation, including WAL.
 * A previously settled peak is deliberately above current allocation. */
static void
test_physical_recompute_reset_and_growth (void)
{
  PhysicalFixture fx;
  physical_fixture_init_full (&fx, TRUE);
  g_clear_pointer (&fx.store, wyl_fact_store_close);
  sqlite3 *db = policy_db (fx.policy_store);
  exec_sqlite_ok (db,
      "INSERT INTO fact_graphs (tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
      "('tenant-provision','sibling','file:///sibling','/sibling',1,'tenant-provision',0,1,1,NULL);"
      "INSERT INTO fact_physical_quota_graph_charges VALUES ('tenant-provision','sibling',1024,1);"
      "UPDATE fact_tenant_physical_quota_usage SET committed_bytes=committed_bytes+1024;"
      "INSERT INTO tenants (tenant_id,owner_subject_id,sealed,created_at,updated_at) "
      "VALUES ('isolated','tenant-owner',0,1,1);"
      "INSERT INTO fact_graphs (tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
      "('isolated','sibling','file:///isolated','/isolated',1,'isolated',0,1,1,NULL);"
      "INSERT INTO fact_physical_quota_graph_charges VALUES ('isolated','sibling',512,1);"
      "INSERT INTO fact_tenant_physical_quota_usage VALUES ('isolated',512,0,0);");
#ifndef G_OS_WIN32
  physical_settle_temp_peak (&fx);
#else
  exec_sqlite_ok (db,
      "UPDATE fact_physical_quota_graph_charges SET charged_bytes=charged_bytes+16777216 "
      "WHERE tenant_id='tenant-provision' AND graph_id='graph-provision';"
      "UPDATE fact_tenant_physical_quota_usage SET committed_bytes=committed_bytes+16777216 "
      "WHERE tenant_id='tenant-provision';");
#endif
  WylPolicyFactPhysicalQuotaRecomputeResult result = { 0 };
  g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.committed);
  g_assert_false (result.outcome_unknown);
  g_assert_cmpuint (result.old_charged_bytes, >, result.new_charged_bytes);
  g_assert_cmpuint (result.old_committed_bytes-result.old_charged_bytes, ==, 1024);
  g_assert_cmpuint (result.old_committed_bytes-result.old_charged_bytes, ==,
      result.new_committed_bytes-result.new_charged_bytes);
  wyl_policy_store_close (fx.policy_store);
  fx.policy_store = NULL;
  g_assert_cmpint (wyl_policy_store_open (fx.policy_path, &fx.policy_store), ==, WYRELOG_E_OK);
  db = policy_db (fx.policy_store);
  physical_assert_invariant (db);
  g_assert_cmpint (physical_scalar (db,
      "SELECT count(*) FROM audit_events WHERE action='fact_physical_quota_recompute' "
      "AND subject_id='tenant-owner' AND resource_id='tenant-provision/graph-provision';"), ==, 1);
  /* Independent post-return observation: no second shutdown checkpoint inflated
   * files after the charge was recorded. Also prove scope/exclusive binding. */
  WylFactArtifactNamespace *ns = physical_namespace (&fx);
  WylFactArtifactNamespace *foreign = physical_namespace (&fx);
  WylFactArtifactMutationLease *lease = NULL;
  g_autoptr (WylFactArtifactPhysicalQuotaEvidence) measured = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (ns, &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_export_physical_quota_evidence_with_lease
        (ns, lease, &measured), ==, WYRELOG_E_POLICY);
  g_assert_null (measured);
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (ns, &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_export_physical_quota_evidence_with_lease
        (foreign, lease, &measured), ==, WYRELOG_E_POLICY);
  g_assert_null (measured);
  g_assert_cmpint (wyl_fact_artifact_namespace_export_physical_quota_evidence_with_lease
        (ns, lease, &measured), ==, WYRELOG_E_OK);
  g_assert_cmpuint (wyl_fact_artifact_physical_quota_evidence_allocated_bytes (measured), ==, result.new_charged_bytes);
  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (foreign);
  wyl_fact_artifact_namespace_free (ns);
  g_assert_cmpint (physical_scalar (db, "SELECT committed_bytes FROM fact_tenant_physical_quota_usage WHERE tenant_id='isolated';"), ==, 512);
  WylPolicyFactPhysicalQuotaRecomputeResult again = { 0 };
  g_assert_cmpint (physical_recompute (&fx, &again), ==, WYRELOG_E_OK);
  g_assert_cmpuint (again.old_charged_bytes, ==, result.new_charged_bytes);
  g_assert_cmpuint (again.new_charged_bytes, ==, result.new_charged_bytes);
  g_assert_cmpint (open_live (fx.policy_store, fx.root, TRUE, &fx.store), ==, WYRELOG_E_OK);
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (fx.store, &fx.schema, &fx.batch,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  g_clear_pointer (&fx.store, wyl_fact_store_close);
  WylPolicyFactPhysicalQuotaStatus status = { 0 };
  assert_physical_settled (fx.policy_store, &status);
  g_assert_cmpuint (status.committed_bytes, >, result.new_committed_bytes);
  physical_assert_invariant (db);
  physical_fixture_clear (&fx);
}

static void
test_physical_recompute_refuses_holds (void)
{
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  g_clear_pointer (&fx.store, wyl_fact_store_close);
  sqlite3 *db = policy_db (fx.policy_store);
  WylPolicyFactPhysicalQuotaOperation op = { .tenant_id=tenant_id, .graph_id=graph_id,
                                             .request_id="pending-recompute", .inventory_generation="test", .inventory_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
  WylPolicyFactPhysicalOperationStatus hold = { 0 };
  g_assert_cmpint (wyl_policy_store_reserve_fact_physical_quota (fx.policy_store,
      &op, 0, &hold), ==, WYRELOG_E_OK);
  WylPolicyFactPhysicalQuotaStatus before = { 0 }, after = { 0 };
  assert_physical_settled (fx.policy_store, &before);
  WylPolicyFactPhysicalQuotaRecomputeResult result = { 0 };
  g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_BUSY);
  g_assert_false (result.committed);
  exec_sqlite_ok (db, "UPDATE fact_physical_quota_reservations SET state='reconciling' WHERE request_id='pending-recompute';");
  g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_BUSY);
  assert_physical_settled (fx.policy_store, &after);
  g_assert_cmpuint (after.committed_bytes, ==, before.committed_bytes);
  physical_assert_invariant (db);
  g_assert_cmpint (physical_scalar (db, "SELECT count(*) FROM audit_events WHERE action='fact_physical_quota_recompute';"), ==, 0);
  exec_sqlite_ok (db, "UPDATE fact_physical_quota_reservations SET state='cancelled' WHERE request_id='pending-recompute';");
  WylPolicyFactLogicalQuotaOperation logical = { .tenant_id=tenant_id, .graph_id=graph_id,
                                                 .request_id="logical-recompute", .batch_id="logical-recompute",
                                                 .payload_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
  WylPolicyFactLogicalOperationStatus logical_hold = { 0 };
  g_assert_cmpint (wyl_policy_store_reserve_fact_logical_quota (fx.policy_store,
      &logical, 0, 0, &logical_hold), ==, WYRELOG_E_OK);
  g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_BUSY);
  exec_sqlite_ok (db, "UPDATE fact_logical_quota_operations SET state='reconciling' WHERE request_id='logical-recompute';");
  g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_BUSY);
  g_assert_false (result.committed);
  assert_physical_settled (fx.policy_store, &after);
  g_assert_cmpuint (after.committed_bytes, ==, before.committed_bytes);
  physical_assert_invariant (db);
  g_assert_cmpint (physical_scalar (db, "SELECT count(*) FROM audit_events WHERE action='fact_physical_quota_recompute';"), ==, 0);
  exec_sqlite_ok (db, "UPDATE fact_logical_quota_operations SET state='settled' WHERE request_id='logical-recompute';");
  logical.graph_id = "other-graph";
  g_assert_cmpint (wyl_policy_store_reserve_fact_logical_quota (fx.policy_store,
      &logical, 0, 0, &logical_hold), ==, WYRELOG_E_OK);
  g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_OK);
  g_assert_true (result.committed);
  physical_assert_invariant (db);
  physical_fixture_clear (&fx);
}

static void
test_physical_recompute_open_lifecycle (gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  WylPolicyFactPhysicalQuotaRecomputeResult result = { 0 };
  if (mode == 0) {
    /* The existing graph writer is still holding its exact exclusive lease. */
    g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_BUSY);
    g_clear_pointer (&fx.store, wyl_fact_store_close);
    physical_assert_invariant (policy_db (fx.policy_store));
  } else {
    g_clear_pointer (&fx.store, wyl_fact_store_close);
    if (mode == 1) {
      WylPolicyFactQuotaConfig limit = { .has_limit=TRUE, .hard_limit=0 };
      g_assert_cmpint (wyl_policy_store_set_fact_quota_config (fx.policy_store,
          tenant_id, WYL_POLICY_FACT_QUOTA_CONCURRENT_OPENS, &limit), ==, WYRELOG_E_OK);
      g_assert_cmpint (physical_recompute (&fx, &result), !=, WYRELOG_E_OK);
      g_assert_false (result.committed);
      physical_assert_invariant (policy_db (fx.policy_store));
    } else {
      /* Begin and active transitions pass. Every later cleanup transition
       * refuses: native resources still release once, durable hold survives. */
      wyl_fact_store_open_reservation_refuse_transitions_once_for_test (2, G_MAXUINT);
      g_assert_cmpint (physical_recompute (&fx, &result), ==, WYRELOG_E_BUSY);
      g_assert_true (result.committed);
      g_assert_false (result.outcome_unknown);
      WylFactArtifactNamespace *ns = physical_namespace (&fx);
      WylFactArtifactMutationLease *lease = NULL;
      g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (ns, &lease), ==, WYRELOG_E_OK);
      wyl_fact_artifact_mutation_lease_free (lease);
      wyl_fact_artifact_namespace_free (ns);
      g_assert_cmpint (physical_scalar (policy_db (fx.policy_store),
          "SELECT count(*) FROM fact_open_reservations WHERE state != 'settled';"), ==, 1);
    }
  }
  physical_fixture_clear (&fx);
}

static void
test_physical_recompute_never_materialized (void)
{
  wyl_policy_store_t *policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &policy), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  seed_graph (policy);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_prepare_fact_physical_quota_recompute
        (policy, tenant_id, graph_id, &authority), ==, WYRELOG_E_POLICY);
  g_assert_null (authority);
  wyl_policy_store_close (policy);
}

/* Exercise final transaction checks independently of the advisory preflight. */
static void
test_physical_recompute_transaction_refusals (gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  g_clear_pointer (&fx.store, wyl_fact_store_close);
  sqlite3 *db = policy_db (fx.policy_store);
  WylPolicyGraphAuthorityRecord *expected = NULL;
  g_assert_cmpint (wyl_policy_store_prepare_fact_physical_quota_recompute
        (fx.policy_store, tenant_id, graph_id, &expected), ==, WYRELOG_E_OK);
  WylFactArtifactNamespace *ns = physical_namespace (&fx);
  WylFactArtifactMutationLease *lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (ns, &lease), ==, WYRELOG_E_OK);
  wyrelog_error_t wanted = WYRELOG_E_IO;
  if (mode == 0) {
    expected->lifecycle_generation++;
    wanted = WYRELOG_E_CONFLICT;
  } else if (mode == 1) {
    g_assert_cmpint (wyl_policy_store_publication_transaction_begin (fx.policy_store), ==, WYRELOG_E_OK);
    wanted = WYRELOG_E_BUSY;
  } else if (mode == 2) {
    exec_sqlite_ok (db, "UPDATE fact_tenant_physical_quota_usage SET committed_bytes=committed_bytes+1;");
  } else if (mode == 3) {
    WylPolicyFactPhysicalQuotaOperation op = { .tenant_id=tenant_id, .graph_id=graph_id,
                                               .request_id="race-hold", .inventory_generation="test",
                                               .inventory_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    WylPolicyFactPhysicalOperationStatus hold = { 0 };
    g_assert_cmpint (wyl_policy_store_reserve_fact_physical_quota (fx.policy_store,
        &op, 0, &hold), ==, WYRELOG_E_OK);
    wanted = WYRELOG_E_BUSY;
  } else if (mode == 4 || mode == 5) {
    exec_sqlite_ok (db,
        "UPDATE fact_physical_quota_graph_charges SET charged_bytes=0;"
        "UPDATE fact_tenant_physical_quota_usage SET committed_bytes=9223372036854775807;"
        "INSERT INTO fact_graphs (tenant_id,graph_id,storage_uri,storage_path,schema_version,"
        "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
        "('tenant-provision','overflow','file:///overflow','/overflow',1,'tenant-provision',0,1,1,NULL);"
        "INSERT INTO fact_physical_quota_graph_charges VALUES ('tenant-provision','overflow',9223372036854775807,1);");
    if (mode == 5)
      exec_sqlite_ok (db, "UPDATE fact_physical_quota_graph_charges SET charged_bytes=1 WHERE graph_id='graph-provision';");
  } else {
    WylPolicyFactLogicalQuotaOperation logical = { .tenant_id=tenant_id, .graph_id=graph_id,
                                                   .request_id="logical-race", .batch_id="logical-race",
                                                   .payload_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    WylPolicyFactLogicalOperationStatus hold = { 0 };
    g_assert_cmpint (wyl_policy_store_reserve_fact_logical_quota (fx.policy_store,
        &logical, 0, 0, &hold), ==, WYRELOG_E_OK);
    if (mode == 7)
      exec_sqlite_ok (db, "UPDATE fact_logical_quota_operations SET state='reconciling' WHERE request_id='logical-race';");
    wanted = WYRELOG_E_BUSY;
  }
  gint64 before = physical_scalar (db, "SELECT committed_bytes FROM fact_tenant_physical_quota_usage;");
  WylPolicyFactPhysicalQuotaRecomputeResult result = { 0 };
  g_assert_cmpint (wyl_policy_store_recompute_fact_physical_quota (fx.policy_store,
      expected, ns, lease, "tenant-owner", recompute_request, &result), ==, wanted);
  g_assert_false (result.committed);
  g_assert_false (result.outcome_unknown);
  if (mode == 1)
    g_assert_cmpint (wyl_policy_store_publication_transaction_rollback_checked (fx.policy_store), ==, WYRELOG_E_OK);
  g_assert_cmpint (physical_scalar (db, "SELECT committed_bytes FROM fact_tenant_physical_quota_usage;"), ==, before);
  g_assert_cmpint (physical_scalar (db, "SELECT count(*) FROM audit_events WHERE action='fact_physical_quota_recompute';"), ==, 0);
  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (ns);
  wyl_policy_graph_authority_record_free (expected);
  physical_fixture_clear (&fx);
}

#if !defined(G_OS_WIN32) || defined(WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS)
static void
test_physical_recompute_shutdown_health_failure (void)
{
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  WylPolicyFactPhysicalQuotaStatus before = { 0 }, after = { 0 };
  assert_physical_settled (fx.policy_store, &before);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_prepare_fact_physical_quota_recompute
        (fx.policy_store, tenant_id, graph_id, &authority), ==, WYRELOG_E_OK);
  WylPolicyFactPhysicalQuotaRecomputeResult result = { 0 };
  wyl_fact_artifact_namespace_set_test_fault (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_store_recompute_physical_quota (fx.store,
      fx.policy_store, authority, "tenant-owner", recompute_request, &result), !=, WYRELOG_E_OK);
  g_assert_true (wyl_fact_artifact_namespace_test_fault_was_consumed (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_DIRECTORY_FSYNC));
  g_assert_false (result.committed);
  (void) wyl_fact_store_close_final (fx.store);
  fx.store = NULL;
  wyl_policy_graph_authority_record_free (authority);
  assert_physical_settled (fx.policy_store, &after);
  g_assert_cmpuint (after.committed_bytes, ==, before.committed_bytes);
  g_assert_cmpint (physical_scalar (policy_db (fx.policy_store),
      "SELECT count(*) FROM audit_events WHERE action='fact_physical_quota_recompute';"), ==, 0);
  physical_fixture_clear (&fx);
}

static void
test_physical_recompute_unstable_and_audit_rollback (void)
{
  PhysicalFixture fx;
  physical_fixture_init (&fx);
  g_clear_pointer (&fx.store, wyl_fact_store_close);
  sqlite3 *db = policy_db (fx.policy_store);
  WylPolicyFactPhysicalQuotaStatus before = { 0 }, after = { 0 };
  assert_physical_settled (fx.policy_store, &before);
  WylPolicyFactPhysicalQuotaRecomputeResult result = { 0 };
  wyl_fact_artifact_namespace_set_test_fault (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INVENTORY_PRE_FINALIZE);
  g_assert_cmpint (physical_recompute (&fx, &result), !=, WYRELOG_E_OK);
  g_assert_true (wyl_fact_artifact_namespace_test_fault_was_consumed (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INVENTORY_PRE_FINALIZE));
  g_assert_false (result.committed);
  exec_sqlite_ok (db, "CREATE TEMP TRIGGER fail_recompute_audit BEFORE INSERT ON audit_events "
      "WHEN NEW.action='fact_physical_quota_recompute' BEGIN SELECT RAISE(ABORT,'audit fault'); END;");
  g_assert_cmpint (physical_recompute (&fx, &result), !=, WYRELOG_E_OK);
  g_assert_false (result.committed);
  exec_sqlite_ok (db, "DROP TRIGGER fail_recompute_audit;");
  g_assert_true (wyl_policy_store_is_autocommit (fx.policy_store));
  exec_sqlite_ok (db, "CREATE TEMP TRIGGER fail_recompute_intention BEFORE INSERT ON audit_intentions "
      "WHEN NEW.action='fact_physical_quota_recompute' BEGIN SELECT RAISE(ABORT,'intention fault'); END;");
  g_assert_cmpint (physical_recompute (&fx, &result), !=, WYRELOG_E_OK);
  g_assert_false (result.committed);
  exec_sqlite_ok (db, "DROP TRIGGER fail_recompute_intention;");
  g_assert_true (wyl_policy_store_is_autocommit (fx.policy_store));
  assert_physical_settled (fx.policy_store, &after);
  g_assert_cmpuint (after.committed_bytes, ==, before.committed_bytes);
  physical_assert_invariant (db);
  g_assert_cmpint (physical_scalar (db, "SELECT count(*) FROM audit_events WHERE action='fact_physical_quota_recompute';"), ==, 0);
  physical_fixture_clear (&fx);
}
#endif

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
  g_test_add_func ("/fact/store-provisioned/physical-quota/recompute/never-materialized", test_physical_recompute_never_materialized);
  const gchar *lifecycle[] = { "existing-writer", "open-quota", "cleanup-after-commit" };
  for (guint i=0; i<G_N_ELEMENTS (lifecycle); i++) {
    g_autofree gchar *name = g_strdup_printf ("/fact/store-provisioned/physical-quota/recompute/%s", lifecycle[i]);
    g_test_add_data_func (name, GUINT_TO_POINTER (i), test_physical_recompute_open_lifecycle);
  }
  const gchar *refusals[] = { "stale-generation", "nested-transaction", "corrupt-sum", "reservation-race", "delta-overflow", "sum-overflow", "logical-pending-race", "logical-reconciling-race" };
  for (guint i=0; i<G_N_ELEMENTS (refusals); i++) {
    g_autofree gchar *name = g_strdup_printf ("/fact/store-provisioned/physical-quota/recompute/%s", refusals[i]);
    g_test_add_data_func (name, GUINT_TO_POINTER (i), test_physical_recompute_transaction_refusals);
  }
  g_test_add_func ("/fact/store-provisioned/physical-quota/recompute/reset-growth", test_physical_recompute_reset_and_growth);
  g_test_add_func ("/fact/store-provisioned/physical-quota/recompute/zero-holds", test_physical_recompute_refuses_holds);
#if !defined(G_OS_WIN32) || defined(WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS)
  g_test_add_func ("/fact/store-provisioned/physical-quota/recompute/shutdown-health-failure", test_physical_recompute_shutdown_health_failure);
  g_test_add_func ("/fact/store-provisioned/physical-quota/recompute/unstable-audit-rollback", test_physical_recompute_unstable_and_audit_rollback);
#endif
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

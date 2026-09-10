/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include "fact-test-support.h"
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
  exec_sqlite_ok (wyl_policy_store_get_db (store),
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('tenant-provision',0,1,1);"
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
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_true (exec_ok (store, "CREATE TABLE probe (x INTEGER);"));
  g_assert_true (exec_ok (store, "INSERT INTO probe VALUES (42), (7);"));
  wyl_fact_store_close (store);

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
#ifdef __APPLE__
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

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func (
    "/fact/store-provisioned/open-provisioned-pair-persists-across-reopen",
    test_open_provisioned_pair_persists_across_reopen);
  for (gsize i = 0; i < G_N_ELEMENTS (metadata_cases); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact/store-provisioned/leased-open-rejects-%s",
            metadata_cases[i].name);
    g_test_add_data_func (name, &metadata_cases[i],
        test_leased_open_rejects_corruption);
  }
#ifdef __APPLE__
  g_test_add_func (
    "/fact/store-provisioned/malformed-darwin-evidence-fails-before-filesystem",
    test_malformed_darwin_evidence_fails_before_filesystem);
#endif
  return g_test_run ();
}

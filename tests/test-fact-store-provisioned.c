/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>

#include "fact-test-support.h"
#include "fact/graph-locator-private.h"
#include "fact/provisioning-construct-private.h"
#include "fact/store-private.h"

static const gchar operation_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070545";
static const gchar tenant_id[] = "tenant-provision";
static const gchar graph_id[] = "graph-provision";

static WylPolicyGraphProvisioningRecord
make_record (void)
{
  WylPolicyGraphProvisioningRecord record = { 0 };
  record.op_uuid = (gchar *) operation_uuid;
  record.tenant_id = (gchar *) tenant_id;
  record.graph_id = (gchar *) graph_id;
  record.store_uuid = (gchar *) store_uuid;
  record.stage_basename = (gchar *)
      "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite";
  record.expected_lifecycle_generation = 1;
  record.expected_reconciliation_generation = 0;
  record.phase = WYL_POLICY_GRAPH_PROVISIONING_RESERVED;
  return record;
}

static WylPolicyGraphAuthorityRecord
make_authority (void)
{
  WylPolicyGraphAuthorityRecord authority = { 0 };
  authority.tenant_id = (gchar *) tenant_id;
  authority.graph_id = (gchar *) graph_id;
  authority.lifecycle_state = WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING;
  authority.store_uuid = (gchar *) store_uuid;
  authority.format_version = 1;
  authority.path_encoding_version = 1;
  authority.lifecycle_generation = 1;
  authority.reconciliation_generation = 0;
  authority.has_store_identity = TRUE;
  return authority;
}

static WylFactStoreIdentity
make_identity (void)
{
  WylFactStoreIdentity identity = { 0 };
  identity.tenant_id = (gchar *) tenant_id;
  identity.graph_id = (gchar *) graph_id;
  identity.store_uuid = (gchar *) store_uuid;
  identity.format_version = 1;
  identity.path_encoding_version = 1;
  return identity;
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

/* Open the retained pair for graph-provision under |root| through the secure
 * live handle.  Caller closes the store; the pair/directory are freed here. */
static wyrelog_error_t
open_live (const gchar *root, gboolean writable, wyl_fact_store_t **out_store)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphProvisionedPair *pair = NULL;
  WylFactStoreIdentity identity = make_identity ();

  wyrelog_error_t rc = wyl_fact_graph_resolver_open (root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, tenant_id, graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator, FALSE,
            &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            operation_uuid, &pair);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_store_open_provisioned_pair (pair, &identity, writable,
            out_store);

  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  return rc;
}

static gboolean
exec_ok (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result = { 0 };
  duckdb_state state = duckdb_query (conn, sql, &result);
  duckdb_destroy_result (&result);
  return state == DuckDBSuccess;
}

static gint64
probe_count (const gchar *root)
{
  wyl_fact_store_t *store = NULL;
  if (open_live (root, FALSE, &store) != WYRELOG_E_OK)
    return -1;
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  duckdb_result result = { 0 };
  gint64 value = -1;
  if (duckdb_query (conn, "SELECT COUNT(*) FROM probe;", &result)
      == DuckDBSuccess)
    value = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  wyl_fact_store_close (store);
  return value;
}

/* A provisioned pair opens as a live, writable secure handle: writes through
 * the bounded filesystem persist across close and reopen, the store's identity
 * validates, and the retained pair stays at nlink 2 throughout. */
static void
test_open_provisioned_pair_persists_across_reopen (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-provisioned-XXXXXX", &error);
  g_assert_no_error (error);
  WylPolicyGraphProvisioningRecord record = make_record ();
  WylPolicyGraphAuthorityRecord authority = make_authority ();
  g_assert_cmpint (wyl_fact_graph_provisioning_construct (root, &record,
      &authority), ==, WYRELOG_E_OK);

  /* Write through the live handle, then close (checkpointing through the
   * bounded filesystem under the lease). */
  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (open_live (root, TRUE, &store), ==, WYRELOG_E_OK);
  g_assert_nonnull (store);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  g_assert_true (exec_ok (conn, "CREATE TABLE probe (x INTEGER);"));
  g_assert_true (exec_ok (conn, "INSERT INTO probe VALUES (42), (7);"));
  wyl_fact_store_close (store);

  /* Reopen a fresh live handle on the same pair: the writes are durable. */
  g_assert_cmpint (probe_count (root), ==, 2);

  /* The store remains the retained pair at nlink 2. */
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  struct stat status;
  g_assert_cmpint (stat (final_path, &status), ==, 0);
  g_assert_cmpuint (status.st_nlink, ==, 2);

  remove_root (root);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func (
    "/fact/store-provisioned/open-provisioned-pair-persists-across-reopen",
    test_open_provisioned_pair_persists_across_reopen);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include "fact-test-support.h"
#include "fact/provisioning-construct-private.h"
#include "fact/provisioning-run-private.h"

static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070545";
static const gchar seam_op_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
static const gchar seam_stage_basename[] =
    "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite";

static void
exec_ok (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite error: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
seed_graph (sqlite3 *db, const gchar *tenant_id, const gchar *graph_id)
{
  g_autofree gchar *sql =
      g_strdup_printf
        ("INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
          "VALUES ('%s',0,1,1);" "INSERT INTO fact_graphs "
          "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
          "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
          "('%s','%s','file:///legacy','/legacy',1,'%s',0,1,1,NULL);",
          tenant_id, tenant_id, graph_id, tenant_id);
  exec_ok (db, sql);
}

static WylPolicyGraphProvisioningInput
make_input (const gchar *tenant_id, const gchar *graph_id)
{
  WylPolicyGraphProvisioningInput input = { 0 };
  input.tenant_id = tenant_id;
  input.graph_id = graph_id;
  input.store_uuid = store_uuid;
  input.format_version = 1;
  input.path_encoding_version = 1;
  input.expected_lifecycle_generation = 0;
  input.expected_reconciliation_generation = 0;
  return input;
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

/* Assert the graph directory holds the retained verified pair: facts.duckdb and
 * the staged name both exist, share one inode, at nlink 2. */
static void
assert_retained_pair (const gchar *root, const gchar *tenant_id,
    const gchar *graph_id, const gchar *stage_basename)
{
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  g_autofree gchar *stage_path = g_build_filename (root, tenant_component,
          graph_component, stage_basename, NULL);
  struct stat final_status;
  struct stat stage_status;
  g_assert_cmpint (stat (final_path, &final_status), ==, 0);
  g_assert_cmpint (stat (stage_path, &stage_status), ==, 0);
  g_assert_cmpuint (final_status.st_nlink, ==, 2);
  g_assert_cmpuint (final_status.st_ino, ==, stage_status.st_ino);
  g_assert_cmpuint (final_status.st_dev, ==, stage_status.st_dev);
}

static void
assert_authority_active (wyl_policy_store_t *store, const gchar *tenant_id,
    const gchar *graph_id)
{
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, tenant_id,
      graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_nonnull (authority);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  g_assert_true (authority->has_store_identity);
  wyl_policy_graph_authority_record_free (authority);
}

/* A fresh graph is reserved, staged, published, verified, and activated in one
 * call: the record reaches ACTIVE, the authority is ACTIVE with a bound
 * identity, and the on-disk store is the retained nlink-2 pair. */
static void
test_run_drives_fresh_graph_to_active (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-run", "graph-run");

  WylPolicyGraphProvisioningInput input = make_input ("tenant-run", "graph-run");
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root,
      &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);

  assert_retained_pair (root, "tenant-run", "graph-run", record->stage_basename);
  assert_authority_active (store, "tenant-run", "graph-run");

  wyl_policy_graph_provisioning_record_free (record);
  remove_root (root);
}

/* A second run over an already-active graph never overwrites it: the authority
 * is no longer reservable, so run fails closed with WYRELOG_E_POLICY. */
static void
test_run_rejects_reprovision_of_active (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-run", "graph-run");

  WylPolicyGraphProvisioningInput input = make_input ("tenant-run", "graph-run");
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root,
      &record), ==, WYRELOG_E_OK);
  wyl_policy_graph_provisioning_record_free (record);

  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root,
      NULL), ==, WYRELOG_E_POLICY);
  assert_authority_active (store, "tenant-run", "graph-run");

  remove_root (root);
}

/* Recovery resumes an operation left at RESERVED (reserved authority + record,
 * no store on disk) and drives it to ACTIVE with the retained pair. */
static void
test_recover_drives_reserved_to_active (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  seed_graph (db, "tenant-recover", "graph-recover");

  /* Reserve the authority (PROVISIONING) and stamp a durable reserved record,
   * exactly as a crash after prepare would leave the store. */
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-recover", "graph-recover", store_uuid, 1, 1, 0, 0, &mutation),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  const gchar *op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
  exec_ok (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070544','tenant-recover',"
      "'graph-recover','01890f47-3c4b-7cc2-b8c4-dc0c0c070545',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite',1,0,"
      "'reserved',0,1,1);");

  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
      &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);

  assert_retained_pair (root, "tenant-recover", "graph-recover",
      record->stage_basename);
  assert_authority_active (store, "tenant-recover", "graph-recover");

  /* Recovery is idempotent: replaying an ACTIVE operation is a no-op success. */
  wyl_policy_graph_provisioning_record_free (record);
  record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
      &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  wyl_policy_graph_provisioning_record_free (record);

  remove_root (root);
}

/* Build the retained pair on disk with committed identity (as a crash after
 * publish/verify would leave it), then stamp a policy provisioning record at
 * |phase_sql| plus its reserved authority.  Recovery must then drive the durable
 * phase forward over the already-published pair to ACTIVE. */
static void
recover_over_published_pair (const gchar *phase_sql)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);

  /* Materialize the S2 pair + identity with the unit-1 construct. */
  WylPolicyGraphProvisioningRecord frecord = { 0 };
  frecord.op_uuid = (gchar *) seam_op_uuid;
  frecord.tenant_id = (gchar *) "tenant-seam";
  frecord.graph_id = (gchar *) "graph-seam";
  frecord.store_uuid = (gchar *) store_uuid;
  frecord.stage_basename = (gchar *) seam_stage_basename;
  frecord.expected_lifecycle_generation = 1;
  frecord.expected_reconciliation_generation = 0;
  frecord.phase = WYL_POLICY_GRAPH_PROVISIONING_RESERVED;
  WylPolicyGraphAuthorityRecord fauthority = { 0 };
  fauthority.tenant_id = (gchar *) "tenant-seam";
  fauthority.graph_id = (gchar *) "graph-seam";
  fauthority.lifecycle_state = WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING;
  fauthority.store_uuid = (gchar *) store_uuid;
  fauthority.format_version = 1;
  fauthority.path_encoding_version = 1;
  fauthority.lifecycle_generation = 1;
  fauthority.reconciliation_generation = 0;
  fauthority.has_store_identity = TRUE;
  g_assert_cmpint (wyl_fact_graph_provisioning_construct (root, &frecord,
      &fauthority), ==, WYRELOG_E_OK);

  /* Stamp the matching policy state: reserved authority + a record whose durable
   * phase trails the on-disk pair. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  seed_graph (db, "tenant-seam", "graph-seam");
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-seam", "graph-seam", store_uuid, 1, 1, 0, 0, &mutation), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_autofree gchar *sql = g_strdup_printf (
    "INSERT INTO fact_graph_provisioning "
    "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
    "expected_lifecycle_generation,expected_reconciliation_generation,"
    "phase,attempt,created_at,updated_at) VALUES "
    "('%s','tenant-seam','graph-seam','%s','%s',1,0,'%s',0,1,1);",
    seam_op_uuid, store_uuid, seam_stage_basename, phase_sql);
  exec_ok (db, sql);

  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, seam_op_uuid,
      root, &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  assert_retained_pair (root, "tenant-seam", "graph-seam",
      record->stage_basename);
  assert_authority_active (store, "tenant-seam", "graph-seam");
  wyl_policy_graph_provisioning_record_free (record);

  remove_root (root);
}

/* Recovery over an already-published pair whose durable phase is PUBLISHED:
 * reopen, verify identity idempotently, then activate. */
static void
test_recover_from_published_pair (void)
{
  recover_over_published_pair ("published");
}

/* Write-behind: the pair is published on disk but the durable phase still trails
 * at STAGED (a crash between publish and the staged->published record).
 * stage_prepare reports the pair as E_POLICY; recovery resumes as published. */
static void
test_recover_from_staged_write_behind (void)
{
  recover_over_published_pair ("staged");
}

/* Recovery over a pair whose durable phase already reached VERIFIED only needs
 * the policy-side activation; the retained pair is untouched. */
static void
test_recover_from_verified (void)
{
  recover_over_published_pair ("verified");
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/provisioning-run/drives-fresh-graph-to-active",
      test_run_drives_fresh_graph_to_active);
  g_test_add_func ("/fact/provisioning-run/rejects-reprovision-of-active",
      test_run_rejects_reprovision_of_active);
  g_test_add_func ("/fact/provisioning-run/recover-drives-reserved-to-active",
      test_recover_drives_reserved_to_active);
  g_test_add_func ("/fact/provisioning-run/recover-from-published-pair",
      test_recover_from_published_pair);
  g_test_add_func ("/fact/provisioning-run/recover-from-staged-write-behind",
      test_recover_from_staged_write_behind);
  g_test_add_func ("/fact/provisioning-run/recover-from-verified",
      test_recover_from_verified);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>

#include "fact-test-support.h"
#include "fact/provisioning-construct-private.h"

static const gchar operation_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070545";

static WylPolicyGraphProvisioningRecord
make_record (void)
{
  WylPolicyGraphProvisioningRecord record = { 0 };
  record.op_uuid = (gchar *) operation_uuid;
  record.tenant_id = (gchar *) "tenant-provision";
  record.graph_id = (gchar *) "graph-provision";
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
  authority.tenant_id = (gchar *) "tenant-provision";
  authority.graph_id = (gchar *) "graph-provision";
  authority.lifecycle_state = WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING;
  authority.store_uuid = (gchar *) store_uuid;
  authority.format_version = 1;
  authority.path_encoding_version = 1;
  authority.lifecycle_generation = 1;
  authority.reconciliation_generation = 0;
  authority.has_store_identity = TRUE;
  return authority;
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

/* Construction stages, publishes, and initializes+validates exact identity,
 * leaving the retained facts.duckdb pair at nlink 2: both the final and staged
 * names bind the same inode, the anti-swap invariant the secure open requires. */
static void
test_construct_publishes_verified_single_store (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-construct-XXXXXX", &error);
  g_assert_no_error (error);
  WylPolicyGraphProvisioningRecord record = make_record ();
  WylPolicyGraphAuthorityRecord authority = make_authority ();

  g_assert_cmpint (wyl_fact_graph_provisioning_construct (root, &record,
      &authority), ==, WYRELOG_E_OK);

  /* The graph directory lives under the encoded tenant/graph components. */
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (record.tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (record.graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  g_autofree gchar *stage_path = g_build_filename (root, tenant_component,
          graph_component, record.stage_basename, NULL);

  /* The pair is retained: both names exist, bind the same inode, at nlink 2. */
  struct stat final_status;
  struct stat stage_status;
  g_assert_cmpint (stat (final_path, &final_status), ==, 0);
  g_assert_cmpint (stat (stage_path, &stage_status), ==, 0);
  g_assert_cmpuint (final_status.st_nlink, ==, 2);
  g_assert_cmpuint (stage_status.st_nlink, ==, 2);
  g_assert_cmpuint (final_status.st_ino, ==, stage_status.st_ino);
  g_assert_cmpuint (final_status.st_dev, ==, stage_status.st_dev);

  remove_root (root);
}

/* A second construction over a published store never overwrites it: the stage
 * gate rejects the already-final facts.duckdb. */
static void
test_construct_never_overwrites_published_store (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-construct-XXXXXX", &error);
  g_assert_no_error (error);
  WylPolicyGraphProvisioningRecord record = make_record ();
  WylPolicyGraphAuthorityRecord authority = make_authority ();

  g_assert_cmpint (wyl_fact_graph_provisioning_construct (root, &record,
      &authority), ==, WYRELOG_E_OK);

  /* Capture the published store's identity so the rejected retry can be proven
   * to have left it byte-for-byte untouched. */
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (record.tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (record.graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  struct stat before;
  g_assert_cmpint (stat (final_path, &before), ==, 0);

  g_assert_cmpint (wyl_fact_graph_provisioning_construct (root, &record,
      &authority), ==, WYRELOG_E_POLICY);

  /* The store is unchanged: same inode, size, and still the retained pair. */
  struct stat after;
  g_assert_cmpint (stat (final_path, &after), ==, 0);
  g_assert_cmpuint (after.st_ino, ==, before.st_ino);
  g_assert_cmpuint (after.st_nlink, ==, 2);
  g_assert_cmpint (after.st_size, ==, before.st_size);

  remove_root (root);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func (
    "/fact/provisioning-construct/publishes-verified-single-store",
    test_construct_publishes_verified_single_store);
  g_test_add_func (
    "/fact/provisioning-construct/never-overwrites-published-store",
    test_construct_never_overwrites_published_store);
  return g_test_run ();
}

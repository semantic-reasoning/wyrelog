/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "fact-test-support.h"
#include "fact/provisioning-private.h"

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

static void
test_prepare_exact_stage_reopens_after_crash (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
      ("wyl-fact-provisioning-XXXXXX", &error);
  g_assert_no_error (error);
  WylPolicyGraphProvisioningRecord record = make_record ();
  WylPolicyGraphAuthorityRecord authority = make_authority ();
  WylFactGraphProvisioningStage first = WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_provisioning_stage_prepare (root, &record,
          &authority, &first), ==, WYRELOG_E_OK);
  g_assert_cmpstr (first.stage.stage_basename, ==, record.stage_basename);
  g_assert_cmpstr (first.stage.final_basename, ==, "facts.duckdb");
  g_assert_cmpstr (first.identity.tenant_id, ==, record.tenant_id);
  g_assert_cmpstr (first.identity.graph_id, ==, record.graph_id);
  g_assert_cmpstr (first.identity.store_uuid, ==, record.store_uuid);
  g_assert_cmpuint (first.identity.format_version, ==, 1);
  g_assert_cmpuint (first.identity.path_encoding_version, ==, 1);
#ifndef G_OS_WIN32
  const guint64 inode = first.stage.inode;
#endif
  wyl_fact_graph_provisioning_stage_clear (&first);

  WylFactGraphProvisioningStage retry = WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_provisioning_stage_prepare (root, &record,
          &authority, &retry), ==, WYRELOG_E_OK);
#ifndef G_OS_WIN32
  g_assert_cmpuint (retry.stage.inode, ==, inode);
#endif
  wyl_fact_graph_provisioning_stage_clear (&retry);
  remove_root (root);
}

static void
test_prepare_rejects_mismatched_authority (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
      ("wyl-fact-provisioning-XXXXXX", &error);
  g_assert_no_error (error);
  WylPolicyGraphProvisioningRecord record = make_record ();
  WylPolicyGraphAuthorityRecord authority = make_authority ();
  authority.store_uuid = (gchar *) "01890f47-3c4b-7cc2-b8c4-dc0c0c070546";
  WylFactGraphProvisioningStage stage = WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_provisioning_stage_prepare (root, &record,
          &authority, &stage), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-provisioning/exact-stage-retry",
      test_prepare_exact_stage_reopens_after_crash);
  g_test_add_func ("/fact-provisioning/reject-mismatched-authority",
      test_prepare_rejects_mismatched_authority);
  return g_test_run ();
}

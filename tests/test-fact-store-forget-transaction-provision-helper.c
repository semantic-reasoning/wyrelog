/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>

#include "fact-test-support.h"
#include "fact/graph-locator-private.h"
#include "fact/provisioning-construct-private.h"

static const gchar *
error_name (wyrelog_error_t rc)
{
  switch (rc) {
    case WYRELOG_E_OK:
      return "WYRELOG_E_OK";
    case WYRELOG_E_INVALID:
      return "WYRELOG_E_INVALID";
    case WYRELOG_E_NOMEM:
      return "WYRELOG_E_NOMEM";
    case WYRELOG_E_IO:
      return "WYRELOG_E_IO";
    case WYRELOG_E_CRYPTO:
      return "WYRELOG_E_CRYPTO";
    case WYRELOG_E_POLICY:
      return "WYRELOG_E_POLICY";
    case WYRELOG_E_AUTH:
      return "WYRELOG_E_AUTH";
    case WYRELOG_E_INTERNAL:
      return "WYRELOG_E_INTERNAL";
    case WYRELOG_E_EXEC:
      return "WYRELOG_E_EXEC";
    case WYRELOG_E_NOT_FOUND:
      return "WYRELOG_E_NOT_FOUND";
    case WYRELOG_E_BREAK_GLASS_DISABLED:
      return "WYRELOG_E_BREAK_GLASS_DISABLED";
    case WYRELOG_E_BUSY:
      return "WYRELOG_E_BUSY";
    case WYRELOG_E_CANCELLED:
      return "WYRELOG_E_CANCELLED";
    case WYRELOG_E_CONFLICT:
      return "WYRELOG_E_CONFLICT";
  }
  return "WYRELOG_E_UNKNOWN";
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
report_failure (wyrelog_error_t rc, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id,
    const gchar *operation_uuid)
{
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  if (wyl_fact_graph_component_encode (tenant_id, &tenant_component)
      != WYRELOG_E_OK
      || wyl_fact_graph_component_encode (graph_id, &graph_component)
      != WYRELOG_E_OK) {
    g_printerr ("provisioning failed: %s (%d); paths=unavailable\n",
        error_name (rc), rc);
    return;
  }
  g_autofree gchar *stage_basename =
      g_strdup_printf ("provision-%s.sqlite", operation_uuid);
  g_autofree gchar *stage_path = g_build_filename (root, tenant_component,
          graph_component, stage_basename, NULL);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  struct stat stage_status;
  struct stat final_status;
  gboolean has_stage = stat (stage_path, &stage_status) == 0;
  gboolean has_final = stat (final_path, &final_status) == 0;
  gboolean same_inode = has_stage && has_final
      && stage_status.st_dev == final_status.st_dev
      && stage_status.st_ino == final_status.st_ino;
  g_printerr ("provisioning failed: %s (%d); stage=%d final=%d "
      "same_inode=%d stage_nlink=%" G_GUINT64_FORMAT " final_nlink=%"
      G_GUINT64_FORMAT "\n", error_name (rc), rc, has_stage, has_final,
      same_inode, has_stage ? (guint64) stage_status.st_nlink : 0,
      has_final ? (guint64) final_status.st_nlink : 0);
}

int
main (int argc, char **argv)
{
  if (argc != 5)
    return 2;
  for (gint i = 1; i < argc; i++) {
    if (argv[i] == NULL || argv[i][0] == '\0')
      return 2;
  }

  const gchar *tenant_id = argv[1];
  const gchar *graph_id = argv[2];
  const gchar *operation_uuid = argv[3];
  const gchar *store_uuid = argv[4];
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-store-forget-transaction-XXXXXX", &error);
  if (root == NULL || error != NULL || !g_path_is_absolute (root)) {
    g_printerr ("secure root creation failed\n");
    return 1;
  }
  g_autofree gchar *stage_basename =
      g_strdup_printf ("provision-%s.sqlite", operation_uuid);
  WylPolicyGraphProvisioningRecord record = { 0 };
  record.op_uuid = (gchar *) operation_uuid;
  record.tenant_id = (gchar *) tenant_id;
  record.graph_id = (gchar *) graph_id;
  record.store_uuid = (gchar *) store_uuid;
  record.stage_basename = stage_basename;
  record.expected_lifecycle_generation = 1;
  record.expected_reconciliation_generation = 0;
  record.phase = WYL_POLICY_GRAPH_PROVISIONING_RESERVED;
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

  wyrelog_error_t rc = wyl_fact_graph_provisioning_construct (root, &record,
          &authority);
  if (rc == WYRELOG_E_OK) {
    g_print ("%s\n", root);
    return 0;
  }
  report_failure (rc, root, tenant_id, graph_id, operation_uuid);
  remove_root (root);
  return 1;
}

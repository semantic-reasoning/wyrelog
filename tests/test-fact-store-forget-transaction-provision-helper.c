/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include "fact-test-support.h"
#include "fact/graph-locator-private.h"
#include "fact/provisioning-run-private.h"

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
    const gchar *stage_basename)
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
  g_autofree gchar *stage_path = stage_basename == NULL ? NULL :
      g_build_filename (root, tenant_component, graph_component,
          stage_basename, NULL);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  struct stat stage_status;
  struct stat final_status;
  gboolean has_stage = stage_path != NULL && stat (stage_path, &stage_status) == 0;
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

static gboolean
exec_ok (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_printerr ("sqlite error: %s\n", message != NULL ? message : "unknown");
  sqlite3_free (message);
  return rc == SQLITE_OK;
}

static gboolean
seed_graph (wyl_policy_store_t *store, const gchar *tenant_id,
    const gchar *graph_id)
{
  g_autofree gchar *sql = g_strdup_printf (
    "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
    "VALUES ('%s',0,1,1);"
    "INSERT INTO fact_graphs "
    "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
    "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
    "('%s','%s','file:///legacy','/legacy',1,'%s',0,1,1,NULL);",
    tenant_id, tenant_id, graph_id, tenant_id);
  return exec_ok (wyl_policy_store_get_db (store), sql);
}

int
main (int argc, char **argv)
{
  if (argc != 4)
    return 2;
  for (gint i = 1; i < argc; i++) {
    if (argv[i] == NULL || argv[i][0] == '\0')
      return 2;
  }

  const gchar *tenant_id = argv[1];
  const gchar *graph_id = argv[2];
  const gchar *store_uuid = argv[3];
  g_autoptr (GError) error = NULL;
  g_autofree gchar *container = wyl_test_make_secure_fact_root
        ("wyl-fact-store-forget-transaction-XXXXXX", &error);
  if (container == NULL || error != NULL || !g_path_is_absolute (container)) {
    g_printerr ("secure root creation failed\n");
    return 1;
  }
  g_autofree gchar *root = g_build_filename (container, "facts", NULL);
  g_autofree gchar *policy_path = g_build_filename (container, "policy.sqlite",
          NULL);
  if (g_mkdir (root, 0700) != 0) {
    g_printerr ("fact root creation failed\n");
    remove_root (container);
    return 1;
  }
  g_autoptr (wyl_policy_store_t) store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open (policy_path, &store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_create_schema (store);
  if (rc == WYRELOG_E_OK && !seed_graph (store, tenant_id, graph_id))
    rc = WYRELOG_E_POLICY;
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
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_provisioning_run (store, &input, root, &record);
  if (rc == WYRELOG_E_OK) {
    wyl_policy_graph_provisioning_record_free (record);
    g_clear_pointer (&store, wyl_policy_store_close);
    g_print ("%s\n%s\n", root, policy_path);
    return 0;
  }
  report_failure (rc, root, tenant_id, graph_id,
      record != NULL ? record->stage_basename : NULL);
  wyl_policy_graph_provisioning_record_free (record);
  g_clear_pointer (&store, wyl_policy_store_close);
  remove_root (container);
  return 1;
}

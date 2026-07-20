/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/policy/store-private.h"

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
exec_rejected (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  sqlite3_free (message);
  g_assert_cmpint (rc, !=, SQLITE_OK);
}

static gint64
scalar_int64 (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static gchar *
scalar_text (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  const gchar *value = (const gchar *) sqlite3_column_text (stmt, 0);
  g_assert_nonnull (value);
  gchar *copy = g_strdup (value);
  sqlite3_finalize (stmt);
  return copy;
}

static void
assert_column (sqlite3 *db, const gchar *table, const gchar *column)
{
  sqlite3_stmt *stmt = NULL;
  g_autofree gchar *sql = g_strdup_printf ("PRAGMA table_info(%s);", table);
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  gboolean found = FALSE;
  while (sqlite3_step (stmt) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 1);
    if (g_strcmp0 (name, column) == 0) {
      found = TRUE;
      break;
    }
  }
  sqlite3_finalize (stmt);
  g_assert_true (found);
}

static void
insert_graph (sqlite3 *db, const gchar *tenant_id, const gchar *graph_id,
    gboolean sealed)
{
  g_autofree gchar *sql =
      g_strdup_printf
      ("INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('%s',%d,1,1);" "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
      "('%s','%s','file:///legacy','/legacy',1,'%s',%d,1,1,NULL);",
      tenant_id, sealed ? 1 : 0, tenant_id, graph_id, tenant_id,
      sealed ? 1 : 0);
  exec_ok (db, sql);
}

static void
test_fresh_schema_is_legacy_unclassified (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);

  const gchar *tenant_columns[] = {
    "lifecycle_state", "lifecycle_generation", "reconciliation_generation",
  };
  const gchar *graph_columns[] = {
    "lifecycle_state", "store_uuid", "format_version",
    "path_encoding_version", "lifecycle_generation",
    "reconciliation_generation", "last_error_class",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_columns); i++)
    assert_column (db, "tenants", tenant_columns[i]);
  for (gsize i = 0; i < G_N_ELEMENTS (graph_columns); i++)
    assert_column (db, "fact_graphs", graph_columns[i]);

  insert_graph (db, "tenant-fresh", "graph-fresh", FALSE);
  g_autofree gchar *tenant_state = scalar_text (db,
      "SELECT lifecycle_state FROM tenants " "WHERE tenant_id='tenant-fresh';");
  g_autofree gchar *graph_state = scalar_text (db,
      "SELECT lifecycle_state FROM fact_graphs "
      "WHERE tenant_id='tenant-fresh' AND graph_id='graph-fresh';");
  g_assert_cmpstr (tenant_state, ==, "legacy_unclassified");
  g_assert_cmpstr (graph_state, ==, "legacy_unclassified");
  g_assert_cmpint (scalar_int64 (db,
          "SELECT lifecycle_generation + reconciliation_generation "
          "FROM fact_graphs WHERE tenant_id='tenant-fresh' "
          "AND graph_id='graph-fresh';"), ==, 0);
}

static void
create_pre_537_schema (sqlite3 *db)
{
  exec_ok (db,
      "PRAGMA foreign_keys=ON;"
      "CREATE TABLE tenants ("
      "tenant_id TEXT PRIMARY KEY, sealed INTEGER NOT NULL DEFAULT 0,"
      "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
      "CREATE TABLE fact_graphs ("
      "tenant_id TEXT NOT NULL, graph_id TEXT NOT NULL,"
      "storage_uri TEXT NOT NULL, storage_path TEXT NOT NULL,"
      "schema_version INTEGER NOT NULL, owner_scope TEXT NOT NULL,"
      "sealed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,"
      "updated_at INTEGER NOT NULL, sealed_at INTEGER,"
      "PRIMARY KEY (tenant_id,graph_id),"
      "FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id));");
}

static void
test_pre_537_rows_migrate_idempotently (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  insert_graph (db, "tenant-open", "graph-open", FALSE);
  insert_graph (db, "tenant-sealed", "graph-sealed", TRUE);

  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM fact_graphs;"), ==,
      2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM fact_graphs "
          "WHERE lifecycle_state='legacy_unclassified' "
          "AND lifecycle_generation=0 AND reconciliation_generation=0 "
          "AND store_uuid IS NULL AND format_version IS NULL "
          "AND path_encoding_version IS NULL AND last_error_class='none';"),
      ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM tenants "
          "WHERE tenant_id IN ('tenant-open','tenant-sealed') "
          "AND lifecycle_state='legacy_unclassified' "
          "AND lifecycle_generation=0 AND reconciliation_generation=0;"),
      ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT sum(sealed) FROM fact_graphs WHERE graph_id IN "
          "('graph-open','graph-sealed');"), ==, 1);
}

static void
test_graph_identity_and_state_constraints (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-a", "graph-a", FALSE);
  insert_graph (db, "tenant-b", "graph-b", FALSE);

  exec_rejected (db,
      "UPDATE fact_graphs SET store_uuid="
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073991' "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET "
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073991',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET "
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073992' "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET store_uuid=NULL "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET "
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073991',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-b' AND graph_id='graph-b';");
  exec_rejected (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "last_error_class='replay',lifecycle_generation=2 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "lifecycle_generation=2 WHERE tenant_id='tenant-a' "
      "AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='degraded',"
      "last_error_class='replay',lifecycle_generation=3 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "last_error_class='none',lifecycle_generation=4 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "last_error_class='none',lifecycle_generation=4,"
      "reconciliation_generation=1 WHERE tenant_id='tenant-a' "
      "AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET lifecycle_generation=9223372036854775807 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
}

static void
test_tenant_state_constraints (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('tenant-a',0,1,1);");
  exec_rejected (db,
      "UPDATE tenants SET lifecycle_state='active',"
      "lifecycle_generation=1 WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='active',"
      "lifecycle_generation=1,reconciliation_generation=1 "
      "WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='sealing',"
      "lifecycle_generation=2 WHERE tenant_id='tenant-a';");
  exec_rejected (db,
      "UPDATE tenants SET lifecycle_state='unsealing',"
      "lifecycle_generation=3 WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='sealed',sealed=1,"
      "lifecycle_generation=3 WHERE tenant_id='tenant-a';");
}

static void
test_integer_domain_constraints (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);

  exec_rejected (db,
      "INSERT INTO tenants "
      "(tenant_id,sealed,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-text-generation',0,'not-an-integer',1,1);");
  exec_rejected (db,
      "INSERT INTO tenants "
      "(tenant_id,sealed,reconciliation_generation,created_at,updated_at) "
      "VALUES ('tenant-overflow-generation',0,9223372036854775808,1,1);");
  exec_ok (db,
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('tenant-canonical',0,1,1);");

  const gchar *invalid_graphs[] = {
    "'not-an-integer',1,0,0",
    "1,'not-an-integer',0,0",
    "1,1,9223372036854775808,0",
    "1,1,0,'not-an-integer'",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_graphs); i++) {
    g_autofree gchar *sql = g_strdup_printf ("INSERT INTO fact_graphs "
        "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
        "owner_scope,sealed,lifecycle_state,store_uuid,format_version,"
        "path_encoding_version,lifecycle_generation,"
        "reconciliation_generation,created_at,updated_at) VALUES "
        "('tenant-canonical','graph-%" G_GSIZE_FORMAT "','file:///graph',"
        "'/graph',1,'tenant-canonical',0,'provisioning',"
        "'01890f47-3c4b-7cc2-b8c4-dc0c0c073%03" G_GSIZE_FORMAT "'," "%s,1,1);",
        i, i, invalid_graphs[i]);
    exec_rejected (db, sql);
  }
}

static gchar *
make_store_path (gchar **out_root)
{
  g_autoptr (GError) error = NULL;
  *out_root = g_dir_make_tmp ("wyl-graph-authority-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (*out_root);
  return g_build_filename (*out_root, "policy.db", NULL);
}

static void
cleanup_store_path (const gchar *root, const gchar *path)
{
  g_autofree gchar *wal = g_strconcat (path, "-wal", NULL);
  g_autofree gchar *shm = g_strconcat (path, "-shm", NULL);
  (void) g_remove (wal);
  (void) g_remove (shm);
  (void) g_remove (path);
  (void) g_rmdir (root);
}

static void
test_fresh_migration_failures_reopen_and_retry (void)
{
  for (WylPolicyGraphAuthorityMigrationFailStage stage =
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_BASE_DDL;
      stage < WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_COUNT; stage++) {
    g_autofree gchar *root = NULL;
    g_autofree gchar *path = make_store_path (&root);
    wyl_policy_store_t *store = NULL;
    g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
    wyl_policy_store_graph_authority_migration_fail_once (store, stage);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_IO);
    g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
            "SELECT count(*) FROM sqlite_master WHERE name IN "
            "('idx_fact_graphs_store_uuid',"
            "'tenant_authority_insert_guard',"
            "'tenant_authority_update_guard',"
            "'fact_graph_authority_insert_guard',"
            "'fact_graph_authority_update_guard');"), ==, 0);
    g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name='tenants';"), ==, 0);
    wyl_policy_store_close (store);

    store = NULL;
    g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    assert_column (wyl_policy_store_get_db (store), "fact_graphs",
        "store_uuid");
    wyl_policy_store_close (store);
    cleanup_store_path (root, path);
  }
}

static void
test_legacy_failure_preserves_rows_and_retries (void)
{
  g_autofree gchar *root = NULL;
  g_autofree gchar *path = make_store_path (&root);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  insert_graph (db, "tenant-legacy", "graph-legacy", TRUE);
  wyl_policy_store_graph_authority_migration_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_GRAPH_TRIGGERS);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_IO);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM fact_graphs;"), ==,
      1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM pragma_table_info('fact_graphs') "
          "WHERE name='store_uuid';"), ==, 0);
  wyl_policy_store_close (store);

  store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  db = wyl_policy_store_get_db (store);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM fact_graphs WHERE "
          "tenant_id='tenant-legacy' AND graph_id='graph-legacy' AND "
          "sealed=1 AND lifecycle_state='legacy_unclassified';"), ==, 1);
  wyl_policy_store_close (store);
  cleanup_store_path (root, path);
}

static void
test_malformed_preexisting_object_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  exec_ok (db, "CREATE INDEX idx_fact_graphs_store_uuid "
      "ON fact_graphs(graph_id);");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM pragma_table_info('fact_graphs') "
          "WHERE name='store_uuid';"), ==, 0);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
          "name='idx_fact_graphs_store_uuid' AND "
          "sql LIKE '%graph_id%';"), ==, 1);
}

static void
test_preexisting_column_without_constraint_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  exec_ok (db,
      "ALTER TABLE tenants ADD COLUMN lifecycle_state TEXT NOT NULL "
      "DEFAULT 'legacy_unclassified';");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM pragma_table_info('tenants') WHERE "
          "name='lifecycle_state';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM pragma_table_info('tenants') WHERE "
          "name='lifecycle_generation';"), ==, 0);
}

static void
test_preexisting_invalid_row_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "DROP TRIGGER tenant_authority_update_guard;"
      "PRAGMA ignore_check_constraints=ON;"
      "INSERT INTO tenants "
      "(tenant_id,sealed,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-invalid',0,'not-an-integer',1,1);"
      "PRAGMA ignore_check_constraints=OFF;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM tenants WHERE tenant_id='tenant-invalid' "
          "AND typeof(lifecycle_generation)='text';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND "
          "name IN ('tenant_authority_insert_guard',"
          "'tenant_authority_update_guard');"), ==, 0);
}

static void
test_malformed_preexisting_trigger_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "CREATE TRIGGER tenant_authority_insert_guard BEFORE INSERT ON tenants "
      "BEGIN SELECT 1; END;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/policy/graph-authority/fresh-schema",
      test_fresh_schema_is_legacy_unclassified);
  g_test_add_func ("/policy/graph-authority/pre-537-idempotent",
      test_pre_537_rows_migrate_idempotently);
  g_test_add_func ("/policy/graph-authority/identity-state-constraints",
      test_graph_identity_and_state_constraints);
  g_test_add_func ("/policy/graph-authority/tenant-state-constraints",
      test_tenant_state_constraints);
  g_test_add_func ("/policy/graph-authority/integer-domain-constraints",
      test_integer_domain_constraints);
  g_test_add_func ("/policy/graph-authority/fresh-fault-retry",
      test_fresh_migration_failures_reopen_and_retry);
  g_test_add_func ("/policy/graph-authority/legacy-fault-retry",
      test_legacy_failure_preserves_rows_and_retries);
  g_test_add_func ("/policy/graph-authority/malformed-object",
      test_malformed_preexisting_object_fails_closed);
  g_test_add_func ("/policy/graph-authority/missing-column-constraint",
      test_preexisting_column_without_constraint_fails_closed);
  g_test_add_func ("/policy/graph-authority/preexisting-invalid-row",
      test_preexisting_invalid_row_fails_closed);
  g_test_add_func ("/policy/graph-authority/malformed-trigger",
      test_malformed_preexisting_trigger_fails_closed);
  return g_test_run ();
}

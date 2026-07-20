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
  insert_graph (db, "tenant-sealed-bypass", "graph-sealed-bypass", TRUE);

  exec_rejected (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,lifecycle_state,store_uuid,format_version,"
      "path_encoding_version,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-a','graph-direct','file:///direct','/direct',1,"
      "'tenant-a',0,'active','01890f47-3c4b-7cc2-b8c4-dc0c0c073990',"
      "1,1,1,1,1);");
  const gchar *legacy_bypasses[] = {
    "lifecycle_state='active',last_error_class='none',sealed=0",
    "lifecycle_state='sealed',last_error_class='none',sealed=1",
    "lifecycle_state='degraded',last_error_class='replay',sealed=0",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (legacy_bypasses); i++) {
    g_autofree gchar *sql = g_strdup_printf ("UPDATE fact_graphs SET "
        "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c07398%" G_GSIZE_FORMAT
        "',format_version=1,path_encoding_version=1,%s,"
        "lifecycle_generation=1,reconciliation_generation=1 "
        "WHERE tenant_id='tenant-b' AND graph_id='graph-b';", i,
        legacy_bypasses[i]);
    exec_rejected (db, sql);
  }
  exec_rejected (db,
      "UPDATE fact_graphs SET sealed=0 "
      "WHERE tenant_id='tenant-sealed-bypass' "
      "AND graph_id='graph-sealed-bypass';");
  exec_rejected (db,
      "UPDATE fact_graphs SET sealed=0,"
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073989',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-sealed-bypass' "
      "AND graph_id='graph-sealed-bypass';");

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
      "UPDATE fact_graphs SET reconciliation_generation=2 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='degraded',"
      "last_error_class='replay',lifecycle_generation=5 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET last_error_class='recovery',"
      "reconciliation_generation=2 WHERE tenant_id='tenant-a' "
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
      "INSERT INTO tenants (tenant_id,sealed,lifecycle_state,"
      "lifecycle_generation,reconciliation_generation,created_at,updated_at) "
      "VALUES ('tenant-direct',0,'active',1,1,1,1);");
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
  exec_rejected (db,
      "UPDATE tenants SET reconciliation_generation=2 "
      "WHERE tenant_id='tenant-a';");
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

static void
test_typed_authority_reads_and_lists (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-b", "graph-b", FALSE);
  insert_graph (db, "tenant-a", "graph-a", TRUE);

  WylPolicyTenantAuthorityRecord *tenant = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (store, "tenant-a",
          &tenant), ==, WYRELOG_E_OK);
  g_assert_nonnull (tenant);
  g_assert_cmpstr (tenant->tenant_id, ==, "tenant-a");
  g_assert_cmpint (tenant->lifecycle_state, ==,
      WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED);
  g_assert_cmpuint (tenant->lifecycle_generation, ==, 0);
  g_assert_cmpuint (tenant->reconciliation_generation, ==, 0);
  g_assert_true (tenant->sealed_compatibility);
  wyl_policy_tenant_authority_record_free (tenant);

  tenant = GINT_TO_POINTER (1);
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (store, "missing",
          &tenant), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (tenant);

  WylPolicyGraphAuthorityRecord *graph = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "tenant-b",
          "graph-b", &graph), ==, WYRELOG_E_OK);
  g_assert_nonnull (graph);
  g_assert_cmpstr (graph->tenant_id, ==, "tenant-b");
  g_assert_cmpstr (graph->graph_id, ==, "graph-b");
  g_assert_cmpint (graph->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED);
  g_assert_false (graph->has_store_identity);
  g_assert_null (graph->store_uuid);
  g_assert_cmpint (graph->last_error_class, ==, WYL_POLICY_GRAPH_ERROR_NONE);
  wyl_policy_graph_authority_record_free (graph);

  GPtrArray *tenants = NULL;
  g_assert_cmpint (wyl_policy_store_list_tenant_authorities (store, &tenants),
      ==, WYRELOG_E_OK);
  g_assert_cmpuint (tenants->len, ==, 3);
  WylPolicyTenantAuthorityRecord *listed_tenant = g_ptr_array_index (tenants,
      1);
  g_assert_cmpstr (listed_tenant->tenant_id, ==, "tenant-a");
  g_ptr_array_unref (tenants);

  GPtrArray *graphs = NULL;
  g_assert_cmpint (wyl_policy_store_list_graph_authorities (store, NULL,
          &graphs), ==, WYRELOG_E_OK);
  g_assert_cmpuint (graphs->len, ==, 2);
  WylPolicyGraphAuthorityRecord *listed_graph = g_ptr_array_index (graphs, 0);
  g_assert_cmpstr (listed_graph->tenant_id, ==, "tenant-a");
  g_ptr_array_unref (graphs);
  graphs = NULL;
  g_assert_cmpint (wyl_policy_store_list_graph_authorities (store, "tenant-b",
          &graphs), ==, WYRELOG_E_OK);
  g_assert_cmpuint (graphs->len, ==, 1);
  listed_graph = g_ptr_array_index (graphs, 0);
  g_assert_cmpstr (listed_graph->graph_id, ==, "graph-b");
  g_ptr_array_unref (graphs);

  graph = GINT_TO_POINTER (1);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "tenant-b",
          "missing", &graph), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (graph);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "", "x",
          &graph), ==, WYRELOG_E_INVALID);

  exec_ok (db,
      "DROP TRIGGER fact_graph_authority_update_guard;"
      "UPDATE fact_graphs SET store_uuid='not-a-canonical-uuid',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-b' AND graph_id='graph-b';");
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "tenant-b",
          "graph-b", &graph), ==, WYRELOG_E_POLICY);
  g_assert_null (graph);
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
test_reservation_and_cross_connection_cas (void)
{
  g_autofree gchar *root = NULL;
  g_autofree gchar *path = make_store_path (&root);
  g_autoptr (wyl_policy_store_t) first = NULL;
  g_autoptr (wyl_policy_store_t) second = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (first), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (first);
  insert_graph (db, "tenant-cas", "graph-cas", FALSE);
  exec_ok (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at) VALUES "
      "('tenant-cas','graph-duplicate','file:///duplicate','/duplicate',1,"
      "'tenant-cas',0,1,1);");
  exec_ok (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at) VALUES "
      "('tenant-cas','graph-sealed-legacy','file:///sealed','/sealed',1,"
      "'tenant-cas',1,1,1);");
  g_assert_cmpint (wyl_policy_store_open (path, &second), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (second), ==, WYRELOG_E_OK);

  WylPolicyAuthorityMutationResult result;
  exec_ok (db, "BEGIN IMMEDIATE;");
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
          "tenant-cas", "graph-cas",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_BUSY);
  exec_ok (db, "ROLLBACK;");
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (first,
          "tenant-cas", "graph-cas",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
          "tenant-cas", "graph-cas",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
          "tenant-cas", "graph-duplicate",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  WylPolicyGraphAuthorityRecord *duplicate = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (first, "tenant-cas",
          "graph-duplicate", &duplicate), ==, WYRELOG_E_OK);
  g_assert_false (duplicate->has_store_identity);
  g_assert_cmpint (duplicate->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED);
  wyl_policy_graph_authority_record_free (duplicate);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
          "tenant-cas", "graph-sealed-legacy",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073104", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);

  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
          "tenant-cas", "graph-cas",
          WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
          WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1,
          0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (second,
          "tenant-cas", "graph-cas",
          WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
          WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_REPLAY,
          1, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_STALE);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (second,
          "tenant-cas", "graph-cas",
          WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
          WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1,
          0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);

  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
          "tenant-cas", "graph-cas", WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
          WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
          WYL_POLICY_GRAPH_ERROR_NONE, 2, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
          "tenant-cas", "graph-cas", WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
          WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_REPLAY,
          2, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
          "tenant-cas", "graph-cas", WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
          WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 3,
          0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_reconcile_graph_authority (first,
          "tenant-cas", "graph-cas", 3, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reconcile_graph_authority (second,
          "tenant-cas", "graph-cas", 3, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);

  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (first,
          "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0, &result),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (second,
          "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0, &result),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (first,
          "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
          WYL_POLICY_TENANT_LIFECYCLE_SEALING, 1, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (second,
          "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
          WYL_POLICY_TENANT_LIFECYCLE_SEALING, 1, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (first,
          "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_SEALING,
          WYL_POLICY_TENANT_LIFECYCLE_SEALED, 2, 1, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (first,
          "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_SEALED,
          WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 3, 1, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);

  exec_ok (db, "DROP TRIGGER fact_graph_authority_insert_guard;");
  exec_ok (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,lifecycle_state,store_uuid,format_version,"
      "path_encoding_version,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-cas','graph-max','file:///max','/max',1,"
      "'tenant-cas',0,'active',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073102',1,1,"
      "9223372036854775807,1,1);");
  g_assert_cmpint (wyl_policy_store_create_schema (first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
          "tenant-cas", "graph-max", WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
          WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE,
          G_MAXINT64, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  WylPolicyGraphAuthorityRecord *max_graph = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (first, "tenant-cas",
          "graph-max", &max_graph), ==, WYRELOG_E_OK);
  g_assert_cmpuint (max_graph->lifecycle_generation, ==, G_MAXINT64);
  g_assert_cmpint (max_graph->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  wyl_policy_graph_authority_record_free (max_graph);

  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (first,
          "tenant-cas", "missing",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073103", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_NOT_FOUND);

  g_clear_pointer (&second, wyl_policy_store_close);
  g_clear_pointer (&first, wyl_policy_store_close);
  cleanup_store_path (root, path);
}

static void
prepare_graph_matrix_state (wyl_policy_store_t *store, sqlite3 *db,
    const gchar *tenant_id, const gchar *graph_id, const gchar *store_uuid,
    WylPolicyGraphLifecycleState state, guint64 *out_lifecycle_generation,
    guint64 *out_reconciliation_generation)
{
  insert_graph (db, tenant_id, graph_id, FALSE);
  *out_lifecycle_generation = 0;
  *out_reconciliation_generation = 0;
  if (state == WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED)
    return;

  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store, tenant_id,
          graph_id, store_uuid, 1, 1, 0, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 1;
  if (state == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING)
    return;

  WylPolicyGraphLifecycleState target =
      state == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED ?
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED : WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE;
  WylPolicyGraphErrorClass error =
      target == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED ?
      WYL_POLICY_GRAPH_ERROR_REPLAY : WYL_POLICY_GRAPH_ERROR_NONE;
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          tenant_id, graph_id, WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
          target, error, 1, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 2;
  if (state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED)
    return;

  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          tenant_id, graph_id, WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
          WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE, 2,
          0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 3;
}

static gboolean
graph_matrix_edge_is_legal (WylPolicyGraphLifecycleState from,
    WylPolicyGraphLifecycleState to)
{
  return (from == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING
      && (to == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED))
      || (from == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
      && (to == WYL_POLICY_GRAPH_LIFECYCLE_SEALED
          || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED))
      || (from == WYL_POLICY_GRAPH_LIFECYCLE_SEALED
      && (to == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED));
}

static void
prepare_tenant_matrix_state (wyl_policy_store_t *store, sqlite3 *db,
    const gchar *tenant_id, WylPolicyTenantLifecycleState state,
    guint64 *out_lifecycle_generation, guint64 *out_reconciliation_generation)
{
  g_autofree gchar *insert = g_strdup_printf ("INSERT INTO tenants "
      "(tenant_id,sealed,created_at,updated_at) VALUES ('%s',0,1,1);",
      tenant_id);
  exec_ok (db, insert);
  *out_lifecycle_generation = 0;
  *out_reconciliation_generation = 0;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED)
    return;

  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
          tenant_id, WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 1;
  *out_reconciliation_generation = 1;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE)
    return;

  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
          tenant_id, WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
          WYL_POLICY_TENANT_LIFECYCLE_SEALING, 1, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 2;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_SEALING)
    return;

  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
          tenant_id, WYL_POLICY_TENANT_LIFECYCLE_SEALING,
          WYL_POLICY_TENANT_LIFECYCLE_SEALED, 2, 1, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 3;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_SEALED)
    return;

  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
          tenant_id, WYL_POLICY_TENANT_LIFECYCLE_SEALED,
          WYL_POLICY_TENANT_LIFECYCLE_UNSEALING, 3, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 4;
}

static gboolean
tenant_matrix_edge_is_legal (WylPolicyTenantLifecycleState from,
    WylPolicyTenantLifecycleState to)
{
  return (from == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
      && to == WYL_POLICY_TENANT_LIFECYCLE_SEALING)
      || (from == WYL_POLICY_TENANT_LIFECYCLE_SEALING
      && (to == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_TENANT_LIFECYCLE_SEALED))
      || (from == WYL_POLICY_TENANT_LIFECYCLE_SEALED
      && to == WYL_POLICY_TENANT_LIFECYCLE_UNSEALING)
      || (from == WYL_POLICY_TENANT_LIFECYCLE_UNSEALING
      && (to == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_TENANT_LIFECYCLE_SEALED));
}

static void
test_complete_transition_matrices (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  const WylPolicyGraphLifecycleState graph_states[] = {
    WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED,
    WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
    WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
    WYL_POLICY_GRAPH_LIFECYCLE_SEALED,
    WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
  };
  guint sequence = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (graph_states); i++) {
    for (gsize j = 0; j < G_N_ELEMENTS (graph_states); j++, sequence++) {
      g_autofree gchar *tenant = g_strdup_printf ("tenant-gmatrix-%u",
          sequence);
      g_autofree gchar *graph = g_strdup_printf ("graph-gmatrix-%u",
          sequence);
      g_autofree gchar *uuid =
          g_strdup_printf ("01890f47-3c4b-7cc2-b8c4-dc0c0c%06u", sequence);
      guint64 lifecycle_generation, reconciliation_generation;
      prepare_graph_matrix_state (store, db, tenant, graph, uuid,
          graph_states[i], &lifecycle_generation, &reconciliation_generation);
      WylPolicyGraphErrorClass error =
          graph_states[j] == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED ?
          WYL_POLICY_GRAPH_ERROR_REPLAY : WYL_POLICY_GRAPH_ERROR_NONE;
      WylPolicyAuthorityMutationResult result;
      g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
              tenant, graph, graph_states[i], graph_states[j], error,
              lifecycle_generation, reconciliation_generation, &result), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (result, ==,
          graph_matrix_edge_is_legal (graph_states[i], graph_states[j]) ?
          WYL_POLICY_AUTHORITY_MUTATION_APPLIED :
          WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
    }
  }

  const WylPolicyTenantLifecycleState tenant_states[] = {
    WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED,
    WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
    WYL_POLICY_TENANT_LIFECYCLE_UNSEALING,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_states); i++) {
    for (gsize j = 0; j < G_N_ELEMENTS (tenant_states); j++, sequence++) {
      g_autofree gchar *tenant = g_strdup_printf ("tenant-tmatrix-%u",
          sequence);
      guint64 lifecycle_generation, reconciliation_generation;
      prepare_tenant_matrix_state (store, db, tenant, tenant_states[i],
          &lifecycle_generation, &reconciliation_generation);
      WylPolicyAuthorityMutationResult result;
      g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
              tenant, tenant_states[i], tenant_states[j],
              lifecycle_generation, reconciliation_generation, &result), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (result, ==,
          tenant_matrix_edge_is_legal (tenant_states[i], tenant_states[j]) ?
          WYL_POLICY_AUTHORITY_MUTATION_APPLIED :
          WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
    }
  }
}

static void
test_complete_transition_tables_and_overflow (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "DROP TRIGGER fact_graph_authority_insert_guard;");
  exec_ok (db,
      "INSERT INTO tenants(tenant_id,sealed,created_at,updated_at) "
      "VALUES('tenant-transitions',0,1,1);"
      "INSERT INTO tenants(tenant_id,sealed,reconciliation_generation,"
      "created_at,updated_at) VALUES"
      "('tenant-reconciliation-max',0,9223372036854775807,1,1);"
      "INSERT INTO tenants(tenant_id,sealed,lifecycle_state,"
      "lifecycle_generation,created_at,updated_at) VALUES"
      "('tenant-lifecycle-max',0,'active',9223372036854775807,1,1);"
      "INSERT INTO fact_graphs(tenant_id,graph_id,storage_uri,storage_path,"
      "schema_version,owner_scope,sealed,lifecycle_state,store_uuid,"
      "format_version,path_encoding_version,lifecycle_generation,"
      "reconciliation_generation,last_error_class,created_at,updated_at) "
      "VALUES"
      "('tenant-transitions','graph-pd','file:///pd','/pd',1,"
      "'tenant-transitions',0,'provisioning',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073201',1,1,0,0,'none',1,1),"
      "('tenant-transitions','graph-as','file:///as','/as',1,"
      "'tenant-transitions',0,'active',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073202',1,1,0,0,'none',1,1),"
      "('tenant-transitions','graph-sd','file:///sd','/sd',1,"
      "'tenant-transitions',1,'sealed',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073203',1,1,0,0,'none',1,1),"
      "('tenant-transitions','graph-reconciliation-max','file:///rm','/rm',1,"
      "'tenant-transitions',0,'degraded',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073204',1,1,0,"
      "9223372036854775807,'recovery',1,1),"
      "('tenant-transitions','graph-lifecycle-max','file:///lm','/lm',1,"
      "'tenant-transitions',0,'active',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073205',1,1,"
      "9223372036854775807,0,'none',1,1);");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);

  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          "tenant-transitions", "graph-pd",
          WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
          WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_PATH, 0,
          0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          "tenant-transitions", "graph-as",
          WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
          WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE, 0, 0,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          "tenant-transitions", "graph-as",
          WYL_POLICY_GRAPH_LIFECYCLE_SEALED,
          WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1, 0,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          "tenant-transitions", "graph-sd",
          WYL_POLICY_GRAPH_LIFECYCLE_SEALED,
          WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
          WYL_POLICY_GRAPH_ERROR_INTERNAL, 0, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reconcile_graph_authority (store,
          "tenant-transitions", "graph-reconciliation-max", 0, G_MAXINT64,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          "tenant-transitions", "graph-lifecycle-max",
          WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
          WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE,
          G_MAXINT64, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);

  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
          "tenant-transitions", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  const WylPolicyTenantLifecycleState tenant_path[] = {
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
    WYL_POLICY_TENANT_LIFECYCLE_UNSEALING,
    WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
    WYL_POLICY_TENANT_LIFECYCLE_UNSEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
  };
  WylPolicyTenantLifecycleState tenant_state =
      WYL_POLICY_TENANT_LIFECYCLE_ACTIVE;
  guint64 lifecycle_generation = 1;
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_path); i++) {
    g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
            "tenant-transitions", tenant_state, tenant_path[i],
            lifecycle_generation, 1, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    tenant_state = tenant_path[i];
    lifecycle_generation++;
  }
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
          "tenant-reconciliation-max", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0,
          G_MAXINT64, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
          "tenant-lifecycle-max", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
          WYL_POLICY_TENANT_LIFECYCLE_SEALING, G_MAXINT64, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
}

static void
test_nested_transaction_uses_savepoint (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-nested", "graph-nested", FALSE);

  exec_ok (db, "BEGIN;");
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
          "tenant-nested", "graph-nested",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073105", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_false (sqlite3_get_autocommit (db));
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM fact_graphs "
          "WHERE tenant_id='tenant-nested' AND graph_id='graph-nested' "
          "AND lifecycle_state='provisioning' AND lifecycle_generation=1;"),
      ==, 1);

  exec_ok (db, "ROLLBACK;");
  g_assert_true (sqlite3_get_autocommit (db));
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM fact_graphs "
          "WHERE tenant_id='tenant-nested' AND graph_id='graph-nested' "
          "AND lifecycle_state='legacy_unclassified' "
          "AND lifecycle_generation=0 AND store_uuid IS NULL;"), ==, 1);
}

static void
test_mutation_faults_roll_back (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-fault-a", "graph-fault-a", FALSE);
  insert_graph (db, "tenant-fault-b", "graph-fault-b", FALSE);
  insert_graph (db, "tenant-fault-nested", "graph-fault-nested", FALSE);

  const WylPolicyGraphAuthorityMutationFailStage stages[] = {
    WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE,
    WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH,
  };
  const gchar *tenants[] = { "tenant-fault-a", "tenant-fault-b" };
  const gchar *graphs[] = { "graph-fault-a", "graph-fault-b" };
  const gchar *uuids[] = {
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073301",
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073302",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (stages); i++) {
    wyl_policy_store_graph_authority_mutation_fail_once (store, stages[i]);
    WylPolicyAuthorityMutationResult result;
    g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
            tenants[i], graphs[i], uuids[i], 1, 1, 0, 0, &result), ==,
        WYRELOG_E_IO);
    g_assert_true (sqlite3_get_autocommit (db));
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM fact_graphs WHERE "
            "lifecycle_state='legacy_unclassified' "
            "AND lifecycle_generation=0 AND store_uuid IS NULL;"), ==, 3);
  }

  exec_ok (db,
      "BEGIN;"
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('tenant-outer-marker',0,1,1);");
  wyl_policy_store_graph_authority_mutation_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
          "tenant-fault-nested", "graph-fault-nested",
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073303", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_IO);
  g_assert_false (sqlite3_get_autocommit (db));
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM tenants "
          "WHERE tenant_id='tenant-outer-marker';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM fact_graphs "
          "WHERE tenant_id='tenant-fault-nested' "
          "AND graph_id='graph-fault-nested' "
          "AND lifecycle_state='legacy_unclassified' "
          "AND lifecycle_generation=0 AND store_uuid IS NULL;"), ==, 1);
  exec_ok (db, "COMMIT;");
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM tenants "
          "WHERE tenant_id='tenant-outer-marker';"), ==, 1);
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
test_constraint_comment_spoof_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  exec_ok (db,
      "ALTER TABLE tenants ADD COLUMN lifecycle_state TEXT NOT NULL "
      "DEFAULT 'legacy_unclassified' /* CHECK(lifecycle_state IN "
      "('legacy_unclassified','active','sealing','sealed','unsealing')) */;");
  g_assert_cmpint (scalar_int64 (db,
          "SELECT instr(sql,'CHECK(lifecycle_state IN') > 0 "
          "FROM sqlite_master WHERE type='table' AND name='tenants';"), ==, 1);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
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
  g_test_add_func ("/policy/graph-authority/typed-read-list",
      test_typed_authority_reads_and_lists);
  g_test_add_func ("/policy/graph-authority/reservation-cross-connection-cas",
      test_reservation_and_cross_connection_cas);
  g_test_add_func ("/policy/graph-authority/complete-transition-matrices",
      test_complete_transition_matrices);
  g_test_add_func ("/policy/graph-authority/complete-transition-tables",
      test_complete_transition_tables_and_overflow);
  g_test_add_func ("/policy/graph-authority/nested-transaction-savepoint",
      test_nested_transaction_uses_savepoint);
  g_test_add_func ("/policy/graph-authority/mutation-fault-rollback",
      test_mutation_faults_roll_back);
  g_test_add_func ("/policy/graph-authority/fresh-fault-retry",
      test_fresh_migration_failures_reopen_and_retry);
  g_test_add_func ("/policy/graph-authority/legacy-fault-retry",
      test_legacy_failure_preserves_rows_and_retries);
  g_test_add_func ("/policy/graph-authority/malformed-object",
      test_malformed_preexisting_object_fails_closed);
  g_test_add_func ("/policy/graph-authority/missing-column-constraint",
      test_preexisting_column_without_constraint_fails_closed);
  g_test_add_func ("/policy/graph-authority/constraint-comment-spoof",
      test_constraint_comment_spoof_fails_closed);
  g_test_add_func ("/policy/graph-authority/preexisting-invalid-row",
      test_preexisting_invalid_row_fails_closed);
  g_test_add_func ("/policy/graph-authority/malformed-trigger",
      test_malformed_preexisting_trigger_fails_closed);
  return g_test_run ();
}

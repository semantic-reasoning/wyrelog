/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

#ifndef WYL_TEST_SQLITE_SCHEMA_PATH
#error "WYL_TEST_SQLITE_SCHEMA_PATH must be defined"
#endif

static const gchar *const service_tables[] = {
  "service_principals",
  "service_credentials",
  "service_credential_cvk",
  "service_principal_events",
  "service_credential_events",
  "service_domain_requests",
  "service_exchange_audit_intentions",
  "service_credential_operation_fences",
};

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

static gint64
row_count (sqlite3 *db, const gchar *table)
{
  g_autofree gchar *sql = g_strdup_printf ("SELECT count(*) FROM %s;", table);
  return scalar_int64 (db, sql);
}

static void
assert_no_foreign_key_errors (sqlite3 *db)
{
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM pragma_foreign_key_check;"), ==, 0);
}

static void
assert_service_tables_empty (wyl_policy_store_t *store)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  for (gsize i = 0; i < G_N_ELEMENTS (service_tables); i++)
    g_assert_cmpint (row_count (db, service_tables[i]), ==, 0);
}

static gint64
service_object_count (sqlite3 *db)
{
  return scalar_int64 (db,
      "SELECT count(*) FROM sqlite_schema WHERE tbl_name IN ("
      "'service_principals','service_credentials','service_credential_cvk',"
      "'service_principal_events','service_credential_events',"
      "'service_domain_requests','service_exchange_audit_intentions',"
      "'service_credential_operation_fences');");
}

static gchar *
compact_sql (const gchar *sql)
{
  if (sql == NULL)
    return g_strdup ("");
  GString *out = g_string_sized_new (strlen (sql));
  for (const gchar * p = sql; *p != '\0'; p++) {
    if (!g_ascii_isspace (*p) && *p != '`' && *p != '"')
      g_string_append_c (out, g_ascii_tolower (*p));
  }
  return g_string_free (out, FALSE);
}

static gchar *
service_schema_fingerprint (sqlite3 *db)
{
  static const gchar *sql =
      "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name IN ("
      "'service_principals','service_credentials','service_credential_cvk',"
      "'service_principal_events','service_credential_events',"
      "'service_domain_requests','service_exchange_audit_intentions',"
      "'service_credential_operation_fences') "
      "ORDER BY type,name;";
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  GString *fingerprint = g_string_new (NULL);
  int rc;
  while ((rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *type = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *table = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *object_sql = (const gchar *) sqlite3_column_text (stmt, 3);
    g_autofree gchar *compacted = compact_sql (object_sql);
    g_string_append_printf (fingerprint, "%s|%s|%s|%s\n", type, name,
        table, compacted);
  }
  sqlite3_finalize (stmt);
  g_assert_cmpint (rc, ==, SQLITE_DONE);

  static const gchar *index_sql =
      "SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name IN ("
      "'service_principals','service_credentials','service_credential_cvk',"
      "'service_principal_events','service_credential_events',"
      "'service_domain_requests','service_credential_operation_fences') "
      "ORDER BY name;";
  g_assert_cmpint (sqlite3_prepare_v2 (db, index_sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  while ((rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 0);
    g_assert_nonnull (name);
    g_string_append_printf (fingerprint, "index_xinfo|%s|", name);
    g_autofree gchar *pragma =
        g_strdup_printf ("PRAGMA index_xinfo(\"%s\");", name);
    sqlite3_stmt *xinfo = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (db, pragma, -1, &xinfo, NULL), ==,
        SQLITE_OK);
    int xrc;
    while ((xrc = sqlite3_step (xinfo)) == SQLITE_ROW) {
      const gchar *column = (const gchar *) sqlite3_column_text (xinfo, 2);
      const gchar *collation = (const gchar *) sqlite3_column_text (xinfo, 4);
      g_assert_nonnull (collation);
      g_string_append_printf (fingerprint, "%d:%d:%s:%d:%s:%d,",
          sqlite3_column_int (xinfo, 0), sqlite3_column_int (xinfo, 1),
          column != NULL ? column : "", sqlite3_column_int (xinfo, 3),
          collation, sqlite3_column_int (xinfo, 5));
    }
    sqlite3_finalize (xinfo);
    g_assert_cmpint (xrc, ==, SQLITE_DONE);
    g_string_append_c (fingerprint, '\n');
  }
  sqlite3_finalize (stmt);
  g_assert_cmpint (rc, ==, SQLITE_DONE);
  return g_string_free (fingerprint, FALSE);
}

static void
assert_embedded_nul_identifiers_rejected (wyl_policy_store_t *store)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db, "SAVEPOINT nul_identifier_test;"
      "INSERT OR IGNORE INTO tenants(tenant_id,sealed,created_at,updated_at)"
      " VALUES('tenant-a',0,1,1);");
  exec_rejected (db,
      "INSERT INTO service_principals"
      " (subject_id,display_name,state,generation,created_by,created_at_us,updated_at_us)"
      " VALUES(CAST(x'7376633a610062' AS TEXT),'bad','active',1,'admin',1,1);");
  exec_ok (db,
      "INSERT INTO service_principals"
      " (subject_id,display_name,state,generation,created_by,created_at_us,updated_at_us)"
      " VALUES('svc:tenant-a:worker','worker','active',1,'admin',1,1);");
  exec_rejected (db,
      "INSERT INTO service_credentials"
      " (credential_id,credential_format_version,subject_id,tenant_id,generation,"
      " state,verifier_version,salt,verifier,created_by,created_at_us,updated_at_us)"
      " VALUES(CAST(x'637265640078' AS TEXT),1,'svc:tenant-a:worker','tenant-a',"
      " 1,'active',1,zeroblob(16),zeroblob(32),'admin',1,1);");
  exec_ok (db, "ROLLBACK TO nul_identifier_test;RELEASE nul_identifier_test;");
}

static void
test_runtime_and_template_fingerprints (void)
{
  g_autoptr (wyl_policy_store_t) runtime = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &runtime), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (runtime), ==, WYRELOG_E_OK);

  g_autofree gchar *schema = NULL;
  gsize schema_len = 0;
  g_assert_true (g_file_get_contents (WYL_TEST_SQLITE_SCHEMA_PATH, &schema,
          &schema_len, NULL));
  g_assert_cmpuint (schema_len, >, 0);
  g_autoptr (wyl_policy_store_t) templated = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &templated), ==, WYRELOG_E_OK);
  exec_ok (wyl_policy_store_get_db (templated), schema);

  g_assert_cmpint (wyl_policy_store_validate_service_schema (runtime), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_validate_service_schema (templated), ==,
      WYRELOG_E_OK);
  g_autofree gchar *runtime_fp =
      service_schema_fingerprint (wyl_policy_store_get_db (runtime));
  g_autofree gchar *template_fp =
      service_schema_fingerprint (wyl_policy_store_get_db (templated));
  g_assert_cmpstr (runtime_fp, ==, template_fp);
  assert_embedded_nul_identifiers_rejected (runtime);
  assert_embedded_nul_identifiers_rejected (templated);
  assert_service_tables_empty (runtime);
  assert_service_tables_empty (templated);
}

static void
test_service_subject_parser (void)
{
  static const gchar *const valid[] = {
    "svc:a", "svc:a.b_c-d", "svc:tenant:Worker-9", "svc:0:Z",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (valid); i++)
    g_assert_true (wyl_policy_service_subject_is_valid (valid[i],
            strlen (valid[i])));
  static const gchar *const invalid[] = {
    "", "svc:", "SVC:a", "Svc:a", "svc::a", "svc:a:", "svc:-a",
    "svc:a-", "svc:.a", "svc:a.", "svc:a/b", "svc:a b", "svc:a\n",
    "svc:\303\251", "service:a", "svc:wr.",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++)
    g_assert_false (wyl_policy_service_subject_is_valid (invalid[i],
            strlen (invalid[i])));
  static const gchar embedded_nul[] = { 's', 'v', 'c', ':', 'a', 0, 'b' };
  g_assert_false (wyl_policy_service_subject_is_valid (embedded_nul,
          sizeof embedded_nul));
  gchar too_long[129];
  memset (too_long, 'a', sizeof too_long);
  memcpy (too_long, "svc:", 4);
  g_assert_false (wyl_policy_service_subject_is_valid (too_long,
          sizeof too_long));
  g_assert_false (wyl_policy_service_subject_is_valid (NULL, 5));
}

static void
insert_fixture_principal (sqlite3 *db)
{
  exec_ok (db,
      "INSERT OR IGNORE INTO tenants (tenant_id,sealed,created_at,updated_at)"
      " VALUES ('tenant-a',0,1,1);"
      "INSERT INTO service_principals"
      " (subject_id,display_name,state,generation,created_by,created_at_us,updated_at_us)"
      " VALUES ('svc:tenant-a:worker','worker','active',1,'admin',1,1);");
}

static void
insert_credential (sqlite3 *db, const gchar *credential_id, gint64 generation)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_credentials"
      " (credential_id,credential_format_version,subject_id,tenant_id,"
      " generation,state,verifier_version,salt,verifier,created_by,"
      " created_at_us,updated_at_us)"
      " VALUES (?,1,'svc:tenant-a:worker','tenant-a',?,'active',1,"
      " zeroblob(16),zeroblob(32),'admin',1,1);";
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, credential_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (stmt, 2, generation), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
}

static void
test_constraints_and_triggers (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);

  exec_rejected (db,
      "INSERT INTO service_principals"
      " (subject_id,display_name,state,generation,created_by,created_at_us,updated_at_us)"
      " VALUES ('svc::bad','bad','active',1,'admin',1,1);");
  exec_rejected (db,
      "INSERT INTO service_principals"
      " (subject_id,display_name,state,generation,created_by,created_at_us,updated_at_us)"
      " VALUES ('svc:empty','bad','active',1,'',1,1);");
  insert_fixture_principal (db);
  insert_credential (db, "opaque-1", 1);
  insert_credential (db, "opaque-2", 1);
  g_assert_cmpint (row_count (db, "service_credentials"), ==, 2);

  exec_rejected (db,
      "INSERT INTO service_credentials"
      " (credential_id,credential_format_version,subject_id,tenant_id,generation,"
      " state,verifier_version,salt,verifier,created_by,created_at_us,updated_at_us)"
      " VALUES ('bad-salt',1,'svc:tenant-a:worker','tenant-a',2,'active',1,"
      " '0000000000000000',zeroblob(32),'admin',1,1);");
  exec_rejected (db,
      "INSERT INTO service_credentials"
      " (credential_id,credential_format_version,subject_id,tenant_id,generation,"
      " state,verifier_version,salt,verifier,created_by,created_at_us,updated_at_us)"
      " VALUES ('bad-verifier',1,'svc:tenant-a:worker','tenant-a',2,'active',1,"
      " zeroblob(16),'00000000000000000000000000000000','admin',1,1);");
  exec_rejected (db,
      "INSERT INTO service_credential_cvk"
      " (slot,generation,envelope_format_version,provider_binding,sealed_cvk,"
      " created_at_us,updated_at_us) VALUES"
      " (1,1,1,'00000000000000000000000000000000',x'01',1,1);");
  exec_rejected (db,
      "INSERT INTO service_credential_cvk"
      " (slot,generation,envelope_format_version,provider_binding,sealed_cvk,"
      " created_at_us,updated_at_us) VALUES" " (1,1,1,zeroblob(32),'x',1,1);");

  exec_ok (db,
      "UPDATE service_credentials SET updated_at_us=2,last_used_at_us=2"
      " WHERE credential_id='opaque-1';");
  exec_rejected (db,
      "UPDATE service_principals SET state='disabled',disabled_by='',"
      " disabled_at_us=2,updated_at_us=2"
      " WHERE subject_id='svc:tenant-a:worker';");
  exec_rejected (db,
      "UPDATE service_credentials SET state='revoked',revoked_by='',"
      " revoked_at_us=2,updated_at_us=2 WHERE credential_id='opaque-1';");
  exec_rejected (db,
      "UPDATE service_principals SET subject_id='svc:other'"
      " WHERE subject_id='svc:tenant-a:worker';");
  exec_rejected (db,
      "UPDATE service_credentials SET tenant_id='__wr_default'"
      " WHERE credential_id='opaque-1';");
  exec_rejected (db, "DELETE FROM tenants WHERE tenant_id='tenant-a';");

  exec_ok (db,
      "INSERT INTO service_principal_events"
      " (subject_id,event,from_state,to_state,generation,actor_subject_id,created_at_us)"
      " VALUES ('svc:tenant-a:worker','created',NULL,'active',1,'admin',1);"
      "INSERT INTO service_credential_events"
      " (credential_id,subject_id,tenant_id,event,from_state,to_state,generation,"
      " actor_subject_id,created_at_us) VALUES"
      " ('opaque-1','svc:tenant-a:worker','tenant-a','issued',NULL,'active',1,"
      " 'admin',1);");
  exec_rejected (db,
      "INSERT INTO service_principal_events"
      " (subject_id,event,from_state,to_state,generation,actor_subject_id,created_at_us)"
      " VALUES ('svc:tenant-a:worker','created',NULL,'active',1,'',1);");
  exec_rejected (db,
      "UPDATE service_principal_events SET event='disabled' WHERE event_id=1;");
  exec_rejected (db, "DELETE FROM service_principal_events WHERE event_id=1;");
  exec_rejected (db,
      "UPDATE service_credential_events SET event='revoked' WHERE event_id=1;");
  exec_rejected (db, "DELETE FROM service_credential_events WHERE event_id=1;");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);
}

static void
test_collision_policy (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_fixture_principal (db);
  wyl_policy_principal_kind_t kind = WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:tenant-a:worker", &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_SERVICE);

  exec_ok (db,
      "INSERT INTO role_memberships(subject_id,role_id,scope,granted_at,granted_by)"
      " VALUES('svc:tenant-a:worker','wr.viewer','tenant-a',1,'admin');"
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at)"
      " VALUES('svc:tenant-a:worker','wr.fact.read','tenant-a',1);");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:tenant-a:worker", &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_SERVICE);

  exec_ok (db,
      "INSERT INTO principal_states(subject_id,state,updated_at)"
      " VALUES('svc:tenant-a:worker','idle',1);");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:tenant-a:worker", &kind), ==, WYRELOG_E_POLICY);
  exec_ok (db,
      "DELETE FROM principal_states WHERE subject_id='svc:tenant-a:worker';"
      "INSERT INTO totp_enrollments(subject_id,secret_blob,last_verified_step,"
      " enrolled_at,id_uuidv7) VALUES"
      " ('svc:tenant-a:worker',zeroblob(20),-1,1,'totp-id');");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:tenant-a:worker", &kind), ==, WYRELOG_E_POLICY);
  exec_ok (db,
      "DELETE FROM totp_enrollments WHERE subject_id='svc:tenant-a:worker';"
      "INSERT INTO wyrelog_config(config_key,config_value,updated_at)"
      " VALUES('bootstrap_admin_subject','svc:tenant-a:worker',1);"
      "INSERT INTO wyrelog_config(config_key,config_value,updated_at)"
      " VALUES('bootstrap_admin_sealed_at_us','1',1);");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:tenant-a:worker", &kind), ==, WYRELOG_E_POLICY);
  exec_ok (db,
      "DELETE FROM wyrelog_config WHERE config_key LIKE 'bootstrap_admin_%';"
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at)"
      " VALUES('svc:tenant-a:worker','wr.login.skip_mfa','login',1);");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:tenant-a:worker", &kind), ==, WYRELOG_E_POLICY);
}

static void
test_unregistered_legacy_service_artifacts (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "INSERT INTO role_memberships(subject_id,role_id,scope,granted_at,granted_by)"
      " VALUES('svc:legacy','wr.viewer','__wr_default',1,'admin');"
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at)"
      " VALUES('svc:legacy','wr.fact.read','__wr_default',1);");
  wyl_policy_principal_kind_t kind = WYL_POLICY_PRINCIPAL_KIND_SERVICE;
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "svc:legacy",
          &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_UNKNOWN);

  exec_ok (db,
      "INSERT INTO principal_states(subject_id,state,updated_at)"
      " VALUES('svc:legacy','idle',1);");
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "svc:legacy",
          &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_HUMAN);
  exec_ok (db,
      "DELETE FROM principal_states WHERE subject_id='svc:legacy';"
      "INSERT INTO totp_enrollments(subject_id,secret_blob,last_verified_step,"
      " enrolled_at,id_uuidv7) VALUES"
      " ('svc:legacy',zeroblob(20),-1,1,'legacy-service-totp');");
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "svc:legacy",
          &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_HUMAN);
  exec_ok (db,
      "DELETE FROM totp_enrollments WHERE subject_id='svc:legacy';"
      "INSERT INTO wyrelog_config(config_key,config_value,updated_at)"
      " VALUES('bootstrap_admin_subject','svc:legacy',1);");
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "svc:legacy",
          &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_HUMAN);
  exec_ok (db,
      "DELETE FROM wyrelog_config WHERE config_key='bootstrap_admin_subject';"
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at)"
      " VALUES('svc:legacy','wr.login.skip_mfa','login',1);");
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "svc:legacy",
          &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_HUMAN);
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "svc:unknown",
          &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_UNKNOWN);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principals"
          " WHERE subject_id='svc:legacy';"), ==, 0);
}

static gchar *
replace_once (const gchar *source, const gchar *needle,
    const gchar *replacement)
{
  const gchar *at = strstr (source, needle);
  g_assert_nonnull (at);
  GString *result = g_string_new_len (source, at - source);
  g_string_append (result, replacement);
  g_string_append (result, at + strlen (needle));
  return g_string_free (result, FALSE);
}

static void
assert_table_corruption_rejected (const gchar *table, const gchar *needle,
    const gchar *replacement)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_autofree gchar *query =
      g_strdup_printf
      ("SELECT sql FROM sqlite_schema WHERE type='table' AND name='%s';",
      table);
  g_autofree gchar *original = scalar_text (db, query);
  g_autofree gchar *corrupt = replace_once (original, needle, replacement);
  exec_ok (db, "PRAGMA foreign_keys=OFF;");
  g_autofree gchar *drop = g_strdup_printf ("DROP TABLE %s;", table);
  exec_ok (db, drop);
  exec_ok (db, corrupt);
  exec_ok (db, "PRAGMA foreign_keys=ON;");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
}

static void
test_corruption_matrix (void)
{
  assert_table_corruption_rejected ("service_credentials",
      "updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),",
      "");
  assert_table_corruption_rejected ("service_credentials",
      "rotated_from_id TEXT,", "rotated_from_id TEXT, extra_column TEXT,");
  assert_table_corruption_rejected ("service_credentials",
      "updated_at_us INTEGER", "updated_at_us TEXT");
  assert_table_corruption_rejected ("service_credentials",
      "generation INTEGER NOT NULL DEFAULT 1",
      "generation INTEGER NOT NULL DEFAULT 2");
  assert_table_corruption_rejected ("service_credentials",
      "typeof(salt) = 'blob'", "typeof(salt) = 'text'");
  assert_table_corruption_rejected ("service_credentials",
      "REFERENCES tenants", "REFERENCES missing_tenants");
  assert_table_corruption_rejected ("service_credentials",
      "ON UPDATE RESTRICT ON DELETE RESTRICT",
      "ON UPDATE CASCADE ON DELETE RESTRICT");
  assert_table_corruption_rejected ("service_credentials",
      "UNIQUE (credential_id, subject_id, tenant_id)",
      "UNIQUE (subject_id, credential_id, tenant_id)");
  assert_table_corruption_rejected ("service_credentials",
      "credential_id TEXT NOT NULL PRIMARY KEY",
      "credential_id TEXT COLLATE NOCASE NOT NULL PRIMARY KEY");

  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "DROP INDEX idx_service_credentials_tenant_state_expiry;"
        "CREATE INDEX idx_service_credentials_tenant_state_expiry"
        " ON service_credentials(state,tenant_id,expires_at_us);");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "CREATE TRIGGER trg_service_exchange_extra BEFORE INSERT ON"
        " service_exchange_audit_intentions BEGIN SELECT 1; END;");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "CREATE TEMP TRIGGER trg_temp_service_exchange_extra BEFORE INSERT ON"
        " main.service_exchange_audit_intentions BEGIN SELECT 1; END;");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "CREATE TRIGGER trg_service_credential_operation_fences_extra"
        " BEFORE INSERT ON service_credential_operation_fences"
        " BEGIN SELECT 1; END;");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    sqlite3 *db = wyl_policy_store_get_db (store);
    exec_ok (db,
        "INSERT INTO service_credential_operation_fences"
        " (request_id,operation,operation_fingerprint,terminal_state,created_at_us)"
        " VALUES('req-append-only','credential_issue',zeroblob(32),'not_committed',1);");
    exec_rejected (db,
        "UPDATE service_credential_operation_fences"
        " SET terminal_state='not_committed' WHERE request_id='req-append-only';");
    exec_rejected (db,
        "DELETE FROM service_credential_operation_fences"
        " WHERE request_id='req-append-only';");
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "DROP INDEX idx_service_credentials_tenant_state_expiry;"
        "CREATE INDEX idx_service_credentials_tenant_state_expiry"
        " ON service_credentials(tenant_id COLLATE NOCASE,state,expires_at_us);");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "DROP INDEX idx_service_credentials_tenant_state_expiry;"
        "CREATE INDEX idx_service_credentials_tenant_state_expiry"
        " ON service_credentials(tenant_id DESC,state,expires_at_us);");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "DROP TRIGGER trg_service_credential_events_no_delete;");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "DROP TRIGGER trg_service_credential_events_no_delete;"
        "CREATE TRIGGER trg_service_credential_events_no_delete"
        " BEFORE DELETE ON service_credential_events BEGIN SELECT 1; END;");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    exec_ok (wyl_policy_store_get_db (store),
        "CREATE TRIGGER trg_service_extra BEFORE INSERT ON service_principals"
        " BEGIN SELECT 1; END;");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    sqlite3 *db = wyl_policy_store_get_db (store);
    exec_ok (db, "PRAGMA foreign_keys=OFF;");
    exec_ok (db,
        "INSERT INTO service_principal_events"
        " (subject_id,event,from_state,to_state,generation,actor_subject_id,created_at_us)"
        " VALUES('svc:missing','created',NULL,'active',1,'admin',1);");
    exec_ok (db, "PRAGMA foreign_keys=ON;");
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_POLICY);
  }
}

static wyrelog_error_t
collect_principal (const wyl_policy_service_principal_info_t *info,
    gpointer user_data)
{
  g_ptr_array_add (user_data, g_strdup (info->subject_id));
  return WYRELOG_E_OK;
}

static wyrelog_error_t
collect_credential (const wyl_policy_service_credential_info_t *info,
    gpointer user_data)
{
  g_assert_cmpuint (info->salt[0], ==, 0);
  g_assert_cmpuint (info->verifier[0], ==, 0);
  g_ptr_array_add (user_data, g_strdup (info->credential_id));
  return WYRELOG_E_OK;
}

static wyrelog_error_t
collect_principal_event (const wyl_policy_service_principal_event_info_t *info,
    gpointer user_data)
{
  g_ptr_array_add (user_data, g_strdup (info->event));
  return WYRELOG_E_OK;
}

static wyrelog_error_t
collect_credential_event (const wyl_policy_service_credential_event_info_t
    *info, gpointer user_data)
{
  g_ptr_array_add (user_data, g_strdup (info->event));
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reject_principal (const wyl_policy_service_principal_info_t *info,
    gpointer user_data)
{
  (void) info;
  (void) user_data;
  return WYRELOG_E_INTERNAL;
}

static void
assert_principal_cleared (const wyl_policy_service_principal_info_t *info)
{
  g_assert_null (info->subject_id);
  g_assert_null (info->display_name);
  g_assert_cmpuint (info->generation, ==, 0);
  g_assert_cmpint (info->created_at_us, ==, 0);
}

static void
assert_credential_cleared (const wyl_policy_service_credential_info_t *info)
{
  g_assert_null (info->credential_id);
  g_assert_null (info->subject_id);
  g_assert_null (info->tenant_id);
  g_assert_cmpuint (info->generation, ==, 0);
  for (gsize i = 0; i < sizeof info->salt; i++)
    g_assert_cmpuint (info->salt[i], ==, 0);
  for (gsize i = 0; i < sizeof info->verifier; i++)
    g_assert_cmpuint (info->verifier[i], ==, 0);
}

static void
assert_cvk_cleared (const wyl_policy_service_cvk_info_t *info)
{
  g_assert_null (info->sealed_cvk);
  g_assert_cmpuint (info->sealed_cvk_len, ==, 0);
  g_assert_cmpuint (info->generation, ==, 0);
  for (gsize i = 0; i < sizeof info->provider_binding; i++)
    g_assert_cmpuint (info->provider_binding[i], ==, 0);
}

static void
test_read_only_service_schema_access (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_fixture_principal (db);
  exec_ok (db,
      "INSERT INTO service_principals"
      " (subject_id,display_name,state,generation,created_by,created_at_us,updated_at_us)"
      " VALUES('svc:a','a','active',1,'admin',1,1);"
      "INSERT INTO service_credentials"
      " (credential_id,credential_format_version,subject_id,tenant_id,generation,"
      " state,verifier_version,salt,verifier,created_by,created_at_us,updated_at_us)"
      " VALUES('cred-b',1,'svc:tenant-a:worker','tenant-a',1,'active',1,"
      " zeroblob(16),zeroblob(32),'admin',1,1);"
      "INSERT INTO service_credentials"
      " (credential_id,credential_format_version,subject_id,tenant_id,generation,"
      " state,verifier_version,salt,verifier,created_by,created_at_us,updated_at_us)"
      " VALUES('cred-a',1,'svc:tenant-a:worker','tenant-a',1,'active',1,"
      " zeroblob(16),zeroblob(32),'admin',1,1);"
      "INSERT INTO service_credential_cvk"
      " (slot,generation,envelope_format_version,provider_binding,sealed_cvk,"
      " created_at_us,updated_at_us) VALUES(1,2,1,zeroblob(32),x'010203',1,2);"
      "INSERT INTO service_principal_events"
      " (subject_id,event,from_state,to_state,generation,actor_subject_id,"
      " request_id,created_at_us) VALUES"
      " ('svc:tenant-a:worker','disabled','active','disabled',2,'admin','r2',3);"
      "INSERT INTO service_principal_events"
      " (subject_id,event,from_state,to_state,generation,actor_subject_id,"
      " request_id,created_at_us) VALUES"
      " ('svc:tenant-a:worker','created',NULL,'active',1,'admin','r1',2);"
      "INSERT INTO service_credential_events"
      " (credential_id,subject_id,tenant_id,event,from_state,to_state,generation,"
      " actor_subject_id,request_id,created_at_us) VALUES"
      " ('cred-a','svc:tenant-a:worker','tenant-a','revoked','active','revoked',"
      " 2,'admin','r2',3);"
      "INSERT INTO service_credential_events"
      " (credential_id,subject_id,tenant_id,event,from_state,to_state,generation,"
      " actor_subject_id,request_id,created_at_us) VALUES"
      " ('cred-a','svc:tenant-a:worker','tenant-a','issued',NULL,'active',"
      " 1,'admin','r1',2);");

  wyl_policy_service_principal_info_t principal = { 0 };
  g_assert_cmpint (wyl_policy_store_lookup_service_principal (store,
          "svc:tenant-a:worker", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.display_name, ==, "worker");
  g_assert_cmpint (wyl_policy_store_lookup_service_principal (store, "svc:a",
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.subject_id, ==, "svc:a");
  g_assert_cmpint (wyl_policy_store_lookup_service_principal (store,
          "svc:missing", &principal), ==, WYRELOG_E_NOT_FOUND);
  assert_principal_cleared (&principal);
  g_assert_cmpint (wyl_policy_store_lookup_service_principal (store, "bad",
          &principal), ==, WYRELOG_E_INVALID);
  assert_principal_cleared (&principal);

  g_autoptr (GPtrArray) rows = g_ptr_array_new_with_free_func (g_free);
  g_assert_cmpint (wyl_policy_store_foreach_service_principal (store,
          collect_principal, rows), ==, WYRELOG_E_OK);
  g_assert_cmpuint (rows->len, ==, 2);
  g_assert_cmpstr (g_ptr_array_index (rows, 0), ==, "svc:a");
  g_assert_cmpint (wyl_policy_store_foreach_service_principal (store,
          reject_principal, NULL), ==, WYRELOG_E_INTERNAL);

  wyl_policy_service_credential_info_t credential = { 0 };
  g_assert_cmpint (wyl_policy_store_lookup_service_credential (store, "cred-a",
          "svc:tenant-a:worker", "tenant-a", &credential), ==, WYRELOG_E_OK);
  g_assert_cmpstr (credential.credential_id, ==, "cred-a");
  g_assert_cmpint (wyl_policy_store_lookup_service_credential (store, "cred-b",
          "svc:tenant-a:worker", "tenant-a", &credential), ==, WYRELOG_E_OK);
  g_assert_cmpstr (credential.credential_id, ==, "cred-b");
  g_assert_cmpint (wyl_policy_store_lookup_service_credential (store, "cred-a",
          "svc:tenant-a:worker", "__wr_default", &credential), ==,
      WYRELOG_E_NOT_FOUND);
  assert_credential_cleared (&credential);
  g_assert_cmpint (wyl_policy_store_lookup_service_credential (store, "cred-a",
          "svc:tenant-a:worker", "tenant-a", &credential), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_lookup_service_credential (store, NULL,
          "svc:tenant-a:worker", "tenant-a", &credential), ==,
      WYRELOG_E_INVALID);
  assert_credential_cleared (&credential);
  g_ptr_array_set_size (rows, 0);
  g_assert_cmpint (wyl_policy_store_foreach_service_credential (store,
          "svc:tenant-a:worker", "tenant-a", collect_credential, rows), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (g_ptr_array_index (rows, 0), ==, "cred-a");
  g_assert_cmpstr (g_ptr_array_index (rows, 1), ==, "cred-b");

  wyl_policy_service_cvk_info_t cvk = { 0 };
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &cvk), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (cvk.generation, ==, 2);
  g_assert_cmpuint (cvk.sealed_cvk_len, ==, 3);
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &cvk), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (cvk.sealed_cvk_len, ==, 3);
  exec_ok (db, "DELETE FROM service_credential_cvk;");
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &cvk), ==,
      WYRELOG_E_NOT_FOUND);
  assert_cvk_cleared (&cvk);
  exec_ok (db,
      "INSERT INTO service_credential_cvk"
      " (slot,generation,envelope_format_version,provider_binding,sealed_cvk,"
      " created_at_us,updated_at_us) VALUES(1,3,1,zeroblob(32),x'04',3,3);");
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &cvk), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_load_service_cvk (NULL, &cvk), ==,
      WYRELOG_E_INVALID);
  assert_cvk_cleared (&cvk);

  g_ptr_array_set_size (rows, 0);
  g_assert_cmpint (wyl_policy_store_foreach_service_principal_event (store,
          "svc:tenant-a:worker", collect_principal_event, rows), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (g_ptr_array_index (rows, 0), ==, "created");
  g_assert_cmpstr (g_ptr_array_index (rows, 1), ==, "disabled");
  g_ptr_array_set_size (rows, 0);
  g_assert_cmpint (wyl_policy_store_foreach_service_credential_event (store,
          "cred-a", "svc:tenant-a:worker", "tenant-a",
          collect_credential_event, rows), ==, WYRELOG_E_OK);
  g_assert_cmpstr (g_ptr_array_index (rows, 0), ==, "issued");
  g_assert_cmpstr (g_ptr_array_index (rows, 1), ==, "revoked");
  g_assert_cmpint (wyl_policy_store_foreach_service_credential_event (store,
          "cred-a", "svc:tenant-a:worker", "__wr_default",
          collect_credential_event, rows), ==, WYRELOG_E_OK);

  wyl_policy_service_principal_event_info_t principal_event = {
    .event_id = 1,
    .subject_id = g_strdup ("svc:a"),
    .event = g_strdup ("created")
  };
  wyl_policy_service_principal_event_info_clear (&principal_event);
  g_assert_cmpint (principal_event.event_id, ==, 0);
  g_assert_null (principal_event.subject_id);
  wyl_policy_service_credential_event_info_t credential_event = {
    .event_id = 1,
    .credential_id = g_strdup ("cred-a"),
    .subject_id = g_strdup ("svc:a")
  };
  wyl_policy_service_credential_event_info_clear (&credential_event);
  g_assert_cmpint (credential_event.event_id, ==, 0);
  g_assert_null (credential_event.credential_id);
}

static void
test_malformed_service_row_read (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db, "PRAGMA foreign_keys=OFF;DROP TABLE service_principals;"
      "CREATE TABLE service_principals(subject_id TEXT,display_name TEXT,"
      " state TEXT,generation INTEGER,created_by TEXT,created_at_us INTEGER,"
      " updated_at_us INTEGER,disabled_by TEXT,disabled_at_us INTEGER);"
      "INSERT INTO service_principals VALUES"
      " (CAST(x'7376633a610062' AS TEXT),'bad','active',1,'admin',1,1,NULL,NULL);");
  g_assert_cmpint (wyl_policy_store_foreach_service_principal (store,
          collect_principal, NULL), ==, WYRELOG_E_POLICY);
  exec_ok (db, "DELETE FROM service_principals;"
      "INSERT INTO service_principals VALUES"
      " ('SVC:a','bad','active',1,'admin',1,1,NULL,NULL);");
  wyl_policy_principal_kind_t kind = WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "SVC:a",
          &kind), ==, WYRELOG_E_POLICY);
  exec_ok (db, "DELETE FROM service_principals;"
      "INSERT INTO service_principals VALUES"
      " ('svc:bad','bad','corrupt',1,'admin',1,1,NULL,NULL);");
  wyl_policy_service_principal_info_t principal = { 0 };
  g_assert_cmpint (wyl_policy_store_lookup_service_principal (store, "svc:bad",
          &principal), ==, WYRELOG_E_POLICY);
  assert_principal_cleared (&principal);
}

static const gchar legacy_parent_ddl[] =
    "CREATE TABLE wyrelog_config("
    " config_key TEXT PRIMARY KEY,config_value TEXT NOT NULL CHECK("
    " (config_key='deployment_mode' AND config_value IN"
    " ('production','development','demo')) OR"
    " config_key='bootstrap_admin_subject' OR"
    " config_key='bootstrap_admin_sealed_at_us' OR"
    " (config_key='bootstrap_admin_allow_skip_mfa' AND config_value IN('0','1')) OR"
    " config_key NOT IN('deployment_mode','bootstrap_admin_subject',"
    " 'bootstrap_admin_sealed_at_us','bootstrap_admin_allow_skip_mfa')),"
    " updated_at INTEGER NOT NULL);"
    "CREATE TABLE tenants(tenant_id TEXT PRIMARY KEY,sealed INTEGER NOT NULL"
    " DEFAULT 0 CHECK(sealed IN(0,1)),created_at INTEGER NOT NULL,"
    " updated_at INTEGER NOT NULL);"
    "CREATE TABLE roles(role_id TEXT PRIMARY KEY,role_name TEXT UNIQUE NOT NULL,"
    " description TEXT,created_at INTEGER,modified_at INTEGER);"
    "CREATE TABLE permissions(perm_id TEXT PRIMARY KEY,perm_name TEXT UNIQUE NOT NULL,"
    " class TEXT NOT NULL CHECK(class IN('basic','sensitive','critical')),"
    " created_at INTEGER);"
    "CREATE TABLE role_memberships(subject_id TEXT NOT NULL,role_id TEXT NOT NULL,"
    " scope TEXT NOT NULL,granted_at INTEGER,granted_by TEXT,"
    " PRIMARY KEY(subject_id,role_id,scope),"
    " FOREIGN KEY(role_id) REFERENCES roles(role_id));"
    "CREATE INDEX idx_role_memberships_role_id ON role_memberships(role_id);"
    "CREATE INDEX idx_role_memberships_subject_scope"
    " ON role_memberships(subject_id,scope);"
    "CREATE TABLE direct_permissions(subject_id TEXT NOT NULL,perm_id TEXT NOT NULL,"
    " scope TEXT NOT NULL,granted_at INTEGER,PRIMARY KEY(subject_id,perm_id,scope),"
    " FOREIGN KEY(perm_id) REFERENCES permissions(perm_id));"
    "CREATE INDEX idx_direct_permissions_perm_id ON direct_permissions(perm_id);"
    "CREATE INDEX idx_direct_permissions_subject_scope"
    " ON direct_permissions(subject_id,scope);"
    "CREATE TABLE principal_states(subject_id TEXT PRIMARY KEY,state TEXT NOT NULL,"
    " updated_at INTEGER,failed_attempt_count INTEGER NOT NULL DEFAULT 0,"
    " locked_at INTEGER);"
    "CREATE INDEX idx_principal_states_state ON principal_states(state);"
    "CREATE TABLE totp_enrollments(subject_id TEXT PRIMARY KEY,secret_blob BLOB NOT NULL,"
    " last_verified_step INTEGER NOT NULL,enrolled_at INTEGER NOT NULL,"
    " id_uuidv7 TEXT NOT NULL);";

static void
seed_legacy_values (sqlite3 *db)
{
  exec_ok (db,
      "INSERT INTO wyrelog_config VALUES('deployment_mode','development',11);"
      "INSERT INTO wyrelog_config VALUES"
      " ('bootstrap_admin_subject','svc:legacy',12);"
      "INSERT INTO wyrelog_config VALUES"
      " ('bootstrap_admin_sealed_at_us','777',13);"
      "INSERT INTO wyrelog_config VALUES"
      " ('bootstrap_admin_allow_skip_mfa','1',14);"
      "INSERT OR REPLACE INTO tenants VALUES('__wr_default',0,21,22);"
      "INSERT INTO roles VALUES('wr.system_admin','system admin','legacy',31,32);"
      "INSERT INTO permissions VALUES"
      " ('wr.login.skip_mfa','login skip mfa','critical',41);"
      "INSERT INTO permissions VALUES('legacy.read','legacy read','basic',42);"
      "INSERT INTO role_memberships VALUES"
      " ('legacy-human','wr.system_admin','__wr_default',51,'legacy-root');"
      "INSERT INTO role_memberships VALUES"
      " ('svc:legacy','wr.system_admin','__wr_default',52,'legacy-root');"
      "INSERT INTO direct_permissions VALUES"
      " ('legacy-human','wr.login.skip_mfa','login',61);"
      "INSERT INTO direct_permissions VALUES"
      " ('legacy-human','legacy.read','__wr_default',62);"
      "INSERT INTO direct_permissions VALUES"
      " ('svc:legacy','wr.login.skip_mfa','login',63);"
      "INSERT INTO direct_permissions VALUES"
      " ('svc:legacy','legacy.read','__wr_default',64);"
      "INSERT INTO principal_states VALUES('legacy-human','idle',71,3,NULL);"
      "INSERT INTO principal_states VALUES('svc:legacy','idle',72,4,NULL);"
      "INSERT INTO totp_enrollments VALUES"
      " ('legacy-human',x'0102030405060708090a0b0c0d0e0f1011121314',9,81,"
      " 'legacy-totp-id');"
      "INSERT INTO totp_enrollments VALUES"
      " ('svc:legacy',x'14131211100f0e0d0c0b0a090807060504030201',10,82,"
      " 'legacy-service-totp-id');");
}

static void
build_legacy_parent_fixture (sqlite3 *db, gboolean malformed_service_table)
{
  exec_ok (db, legacy_parent_ddl);
  seed_legacy_values (db);
  if (malformed_service_table)
    exec_ok (db, "CREATE TABLE service_credentials(credential_id TEXT);");
  assert_no_foreign_key_errors (db);
}

static void
assert_immediate_parent_objects (sqlite3 *db)
{
  for (gsize i = 0; i < wyl_policy_store_required_table_count (); i++) {
    const gchar *name = wyl_policy_store_required_table_name (i);
    g_assert_nonnull (name);
    if (g_str_has_prefix (name, "service_"))
      continue;
    g_autofree gchar *sql =
        g_strdup_printf
        ("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='%s';",
        name);
    g_assert_cmpint (scalar_int64 (db, sql), ==, 1);
  }
  g_assert_cmpint (service_object_count (db), ==, 0);
  assert_no_foreign_key_errors (db);
}

static void
build_immediate_parent_fixture (sqlite3 *db)
{
  static const gchar start_marker[] =
      "-- Inert service identity and credential authority (#353).";
  static const gchar end_marker[] = "-- Table: policy_signatures";
  g_autofree gchar *schema = NULL;
  gsize schema_len = 0;
  g_assert_true (g_file_get_contents (WYL_TEST_SQLITE_SCHEMA_PATH, &schema,
          &schema_len, NULL));
  const gchar *start = strstr (schema, start_marker);
  const gchar *end = strstr (schema, end_marker);
  g_assert_nonnull (start);
  g_assert_nonnull (end);
  g_assert_true (start < end);
  g_assert_null (strstr (start + strlen (start_marker), start_marker));
  g_assert_null (strstr (end + strlen (end_marker), end_marker));

  GString *parent = g_string_new_len (schema, start - schema);
  g_string_append_len (parent, end, schema_len - (gsize) (end - schema));
  exec_ok (db, parent->str);
  g_string_free (parent, TRUE);
  assert_immediate_parent_objects (db);
  seed_legacy_values (db);
  assert_immediate_parent_objects (db);
}

static void
assert_legacy_values (sqlite3 *db)
{
  g_autofree gchar *mode = scalar_text (db,
      "SELECT config_value FROM wyrelog_config"
      " WHERE config_key='deployment_mode';");
  g_assert_cmpstr (mode, ==, "development");
  g_autofree gchar *bootstrap = scalar_text (db,
      "SELECT config_value FROM wyrelog_config"
      " WHERE config_key='bootstrap_admin_subject';");
  g_assert_cmpstr (bootstrap, ==, "svc:legacy");
  g_assert_cmpint (scalar_int64 (db,
          "SELECT failed_attempt_count FROM principal_states"
          " WHERE subject_id='legacy-human';"), ==, 3);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT last_verified_step FROM totp_enrollments"
          " WHERE subject_id='legacy-human';"), ==, 9);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM role_memberships"
          " WHERE subject_id='legacy-human' AND role_id='wr.system_admin'"
          " AND scope='__wr_default' AND granted_by='legacy-root';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM direct_permissions"
          " WHERE subject_id='legacy-human' AND perm_id IN"
          " ('wr.login.skip_mfa','legacy.read');"), ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT failed_attempt_count FROM principal_states"
          " WHERE subject_id='svc:legacy';"), ==, 4);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT last_verified_step FROM totp_enrollments"
          " WHERE subject_id='svc:legacy';"), ==, 10);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM role_memberships"
          " WHERE subject_id='svc:legacy' AND role_id='wr.system_admin';"),
      ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM direct_permissions"
          " WHERE subject_id='svc:legacy' AND perm_id IN"
          " ('wr.login.skip_mfa','legacy.read');"), ==, 2);
}

static void
assert_legacy_service_unregistered (sqlite3 *db)
{
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principals"
          " WHERE subject_id='svc:legacy';"), ==, 0);
}

static gboolean
write_policy_key (const gchar *path, guint8 seed)
{
  guint8 key[32];
  for (gsize i = 0; i < sizeof key; i++)
    key[i] = (guint8) (seed + i);
  return g_file_set_contents (path, (const gchar *) key, sizeof key, NULL);
}

static wyrelog_error_t
open_encrypted (const gchar *path, const gchar *key_path,
    wyl_policy_store_t **out_store)
{
  wyl_keyprovider_file_t *provider = wyl_keyprovider_file_new (key_path);
  if (provider == NULL)
    return WYRELOG_E_IO;
  wyl_policy_store_open_options_t opts = {
    .path = path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = provider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_open_with_options (&opts, out_store);
}

static void
create_plaintext_legacy (const gchar *path, gboolean immediate_parent,
    gboolean malformed)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  if (immediate_parent) {
    g_assert_false (malformed);
    build_immediate_parent_fixture (wyl_policy_store_get_db (store));
  } else {
    build_legacy_parent_fixture (wyl_policy_store_get_db (store), malformed);
  }
  if (!malformed)
    g_assert_cmpint (service_object_count (wyl_policy_store_get_db (store)),
        ==, 0);
}

static void
backup_to_encrypted (const gchar *source_path, const gchar *encrypted_path,
    const gchar *key_path)
{
  g_autoptr (wyl_policy_store_t) source = NULL;
  g_autoptr (wyl_policy_store_t) destination = NULL;
  g_assert_cmpint (wyl_policy_store_open (source_path, &source), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (open_encrypted (encrypted_path, key_path, &destination), ==,
      WYRELOG_E_OK);
  sqlite3_backup *backup =
      sqlite3_backup_init (wyl_policy_store_get_db (destination), "main",
      wyl_policy_store_get_db (source), "main");
  g_assert_nonnull (backup);
  g_assert_cmpint (sqlite3_backup_step (backup, -1), ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_backup_remaining (backup), ==, 0);
  g_assert_cmpint (sqlite3_backup_pagecount (backup), >, 0);
  g_assert_cmpint (sqlite3_backup_finish (backup), ==, SQLITE_OK);
  assert_no_foreign_key_errors (wyl_policy_store_get_db (destination));
  g_clear_pointer (&destination, wyl_policy_store_close);
  g_autofree gchar *clear_path =
      g_strdup_printf ("%s.wyrelog-clear", encrypted_path);
  g_assert_false (g_file_test (clear_path, G_FILE_TEST_EXISTS));
}

static void
assert_encrypted_envelope (const gchar *path)
{
  g_autofree gchar *bytes = NULL;
  gsize len = 0;
  g_assert_true (g_file_get_contents (path, &bytes, &len, NULL));
  g_assert_cmpuint (len, >, 96);
  g_assert_cmpmem (bytes, 5, "WYLPS", 5);
  g_assert_null (g_strstr_len (bytes, len, "legacy-human"));
  g_assert_null (g_strstr_len (bytes, len, "svc:legacy"));
}

static void
test_old_store_subset_migration (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-svc-old-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_autofree gchar *path = g_build_filename (tmpdir, "policy.db", NULL);
  create_plaintext_legacy (path, FALSE, FALSE);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  assert_legacy_values (wyl_policy_store_get_db (store));
  assert_legacy_service_unregistered (wyl_policy_store_get_db (store));
  assert_service_tables_empty (store);
  g_clear_pointer (&store, wyl_policy_store_close);
  g_remove (path);
  g_rmdir (tmpdir);
}

static void
test_plaintext_legacy_migration (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-svc-plain-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_autofree gchar *path = g_build_filename (tmpdir, "policy.db", NULL);
  create_plaintext_legacy (path, TRUE, FALSE);
  for (guint pass = 0; pass < 2; pass++) {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_OK);
    assert_legacy_values (wyl_policy_store_get_db (store));
    assert_legacy_service_unregistered (wyl_policy_store_get_db (store));
    assert_service_tables_empty (store);
  }
  g_remove (path);
  g_rmdir (tmpdir);
}

static void
test_encrypted_legacy_migration (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-svc-enc-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_autofree gchar *source_path = g_build_filename (tmpdir, "source.db", NULL);
  g_autofree gchar *encrypted_path =
      g_build_filename (tmpdir, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (tmpdir, "right.key", NULL);
  g_autofree gchar *wrong_key_path =
      g_build_filename (tmpdir, "wrong.key", NULL);
  g_assert_true (write_policy_key (key_path, 1));
  g_assert_true (write_policy_key (wrong_key_path, 99));
  create_plaintext_legacy (source_path, TRUE, FALSE);
  backup_to_encrypted (source_path, encrypted_path, key_path);
  assert_encrypted_envelope (encrypted_path);

  g_autofree gchar *before = NULL;
  gsize before_len = 0;
  g_assert_true (g_file_get_contents (encrypted_path, &before, &before_len,
          NULL));
  g_autoptr (wyl_policy_store_t) wrong = NULL;
  g_assert_cmpint (open_encrypted (encrypted_path, wrong_key_path, &wrong), !=,
      WYRELOG_E_OK);
  g_autofree gchar *after = NULL;
  gsize after_len = 0;
  g_assert_true (g_file_get_contents (encrypted_path, &after, &after_len,
          NULL));
  g_assert_cmpmem (before, before_len, after, after_len);

  for (guint pass = 0; pass < 2; pass++) {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (open_encrypted (encrypted_path, key_path, &store), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    assert_legacy_values (wyl_policy_store_get_db (store));
    assert_legacy_service_unregistered (wyl_policy_store_get_db (store));
    assert_service_tables_empty (store);
  }
  assert_encrypted_envelope (encrypted_path);
  g_remove (source_path);
  g_remove (encrypted_path);
  g_remove (key_path);
  g_remove (wrong_key_path);
  g_rmdir (tmpdir);
}

static void
exercise_failed_migration (gboolean encrypted)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-svc-fail-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_autofree gchar *source_path = g_build_filename (tmpdir, "source.db", NULL);
  g_autofree gchar *store_path = g_build_filename (tmpdir,
      encrypted ? "policy.store" : "policy.db", NULL);
  g_autofree gchar *key_path = g_build_filename (tmpdir, "policy.key", NULL);
  if (encrypted)
    g_assert_true (write_policy_key (key_path, 7));
  create_plaintext_legacy (encrypted ? source_path : store_path, FALSE, TRUE);
  if (encrypted)
    backup_to_encrypted (source_path, store_path, key_path);

  for (guint pass = 0; pass < 2; pass++) {
    g_autoptr (wyl_policy_store_t) store = NULL;
    wyrelog_error_t rc = encrypted ? open_encrypted (store_path, key_path,
        &store) : wyl_policy_store_open (store_path, &store);
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), !=, WYRELOG_E_OK);
    sqlite3 *db = wyl_policy_store_get_db (store);
    assert_legacy_values (db);
    g_assert_cmpint (row_count (db, "service_credentials"), ==, 0);
    g_assert_cmpint (service_object_count (db), ==, 1);
    g_autofree gchar *columns = scalar_text (db,
        "SELECT group_concat(name,',') FROM pragma_table_info"
        " ('service_credentials');");
    g_assert_cmpstr (columns, ==, "credential_id");
  }
  g_remove (source_path);
  g_remove (store_path);
  g_remove (key_path);
  g_rmdir (tmpdir);
}

static void
test_failed_migration_preserves_plaintext (void)
{
  exercise_failed_migration (FALSE);
}

static void
test_failed_migration_preserves_encrypted (void)
{
  exercise_failed_migration (TRUE);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/policy/service-schema/subject-parser",
      test_service_subject_parser);
  g_test_add_func ("/policy/service-schema/runtime-template-fingerprint",
      test_runtime_and_template_fingerprints);
  g_test_add_func ("/policy/service-schema/constraints",
      test_constraints_and_triggers);
  g_test_add_func ("/policy/service-schema/collision-policy",
      test_collision_policy);
  g_test_add_func ("/policy/service-schema/unregistered-legacy-service",
      test_unregistered_legacy_service_artifacts);
  g_test_add_func ("/policy/service-schema/corruption-matrix",
      test_corruption_matrix);
  g_test_add_func ("/policy/service-schema/read-only-access",
      test_read_only_service_schema_access);
  g_test_add_func ("/policy/service-schema/malformed-row-read",
      test_malformed_service_row_read);
  g_test_add_func ("/policy/service-schema/old-store-subset",
      test_old_store_subset_migration);
  g_test_add_func ("/policy/service-schema/plaintext-legacy",
      test_plaintext_legacy_migration);
  g_test_add_func ("/policy/service-schema/encrypted-legacy",
      test_encrypted_legacy_migration);
  g_test_add_func ("/policy/service-schema/plaintext-failure-preserves",
      test_failed_migration_preserves_plaintext);
  g_test_add_func ("/policy/service-schema/encrypted-failure-preserves",
      test_failed_migration_preserves_encrypted);
  return g_test_run ();
}

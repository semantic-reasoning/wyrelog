/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <duckdb.h>

#include "wyrelog/audit/conn-private.h"

#ifndef WYL_TEST_DUCKDB_SCHEMA_PATH
#error "WYL_TEST_DUCKDB_SCHEMA_PATH must be defined by the build."
#endif

/* --- in-memory open/close lifecycle ---------------------------- */

static gint
check_open_memory_null_path (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 1;
  if (conn == NULL)
    return 2;
  return 0;
}

static gint
check_open_memory_literal (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (":memory:", &conn) != WYRELOG_E_OK)
    return 10;
  if (conn == NULL)
    return 11;
  return 0;
}

/* --- on-disk open + DDL round-trip ----------------------------- */

static gint
check_open_tempfile_and_query (void)
{
  g_autoptr (GError) err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-audit-XXXXXX", &err);
  if (tmpdir == NULL)
    return 20;
  g_autofree gchar *path = g_build_filename (tmpdir, "audit.db", NULL);

  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK) {
    g_rmdir (tmpdir);
    return 21;
  }
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  duckdb_result result;
  if (duckdb_query (h, "CREATE TABLE t (x INTEGER);", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    g_unlink (path);
    g_rmdir (tmpdir);
    return 22;
  }
  duckdb_destroy_result (&result);

  /* close before unlink so the database file is no longer mapped. */
  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_unlink (path);
  g_rmdir (tmpdir);
  return 0;
}

/* --- bad path fails closed ------------------------------------- */

static gint
check_open_bad_path (void)
{
  /* An obviously unwritable parent. The sentinel pointer must
   * survive the call untouched. */
  wyl_audit_conn_t *sentinel = (wyl_audit_conn_t *) (gpointer) 0xDEADBEEF;
  wyl_audit_conn_t *conn = sentinel;
  wyrelog_error_t rc =
      wyl_audit_conn_open ("/nonexistent-dir-wyrelog-audit/audit.db", &conn);
  if (rc == WYRELOG_E_OK)
    return 30;
  if (conn != sentinel)
    return 31;
  return 0;
}

/* --- argument validation --------------------------------------- */

static gint
check_invalid_args (void)
{
  if (wyl_audit_conn_open ("anything", NULL) != WYRELOG_E_INVALID)
    return 40;
  return 0;
}

/* --- close semantics ------------------------------------------- */

static gint
check_close_null_noop (void)
{
  /* Direct NULL close is a no-op. */
  wyl_audit_conn_close (NULL);

  /* Open then explicit close, then a second close on a NULL local
   * is also a no-op. autoptr cleanup at scope-end on the same
   * NULL-after-steal pointer is a no-op too. */
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 50;
  wyl_audit_conn_close (g_steal_pointer (&conn));
  /* conn is now NULL; the autoptr scope-end will see NULL. */
  if (conn != NULL)
    return 51;
  return 0;
}

/* --- handle accessor on NULL ---------------------------------- */

static gint
check_get_connection_null (void)
{
  duckdb_connection h = wyl_audit_conn_get_connection (NULL);
  /* The accessor returns a zero-initialised handle on NULL input;
   * DuckDB treats that as not-a-connection. We can't dereference
   * it here without crashing, but we can confirm the field is
   * zero by reading the bytes. Since the type is opaque we
   * compare against a freshly memset zero buffer of the same
   * size. */
  duckdb_connection zero;
  memset (&zero, 0, sizeof (zero));
  if (memcmp (&h, &zero, sizeof (h)) != 0)
    return 60;
  return 0;
}

/* --- DDL schema creation -------------------------------------- */

static gint
check_create_schema (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 70;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 71;
  /* Idempotent: a second call must also succeed because the DDL
   * uses CREATE TABLE IF NOT EXISTS. */
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 72;

  /* The freshly created table must be queryable and empty. */
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  duckdb_result result;
  if (duckdb_query (h, "SELECT COUNT(*) FROM audit_events;",
          &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 73;
  }
  if (duckdb_value_int64 (&result, 0, 0) != 0) {
    duckdb_destroy_result (&result);
    return 74;
  }
  duckdb_destroy_result (&result);
  return 0;
}

static gint
check_create_schema_null_arg (void)
{
  if (wyl_audit_conn_create_schema (NULL) != WYRELOG_E_INVALID)
    return 80;
  return 0;
}

static gint
check_template_schema_creates_audit_events (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  g_autofree gchar *schema = NULL;
  gsize schema_len = 0;
  g_autoptr (GError) error = NULL;
  duckdb_result result;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 85;
  if (!g_file_get_contents (WYL_TEST_DUCKDB_SCHEMA_PATH, &schema,
          &schema_len, &error))
    return 86;

  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  if (duckdb_query (h, schema, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 87;
  }
  duckdb_destroy_result (&result);

  gboolean exists = FALSE;
  if (wyl_audit_conn_table_exists (conn, "audit_events", &exists)
      != WYRELOG_E_OK)
    return 88;
  if (!exists)
    return 89;
  return 0;
}

static gint
check_table_probe_reports_schema (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 90;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 91;

  gboolean exists = FALSE;
  if (wyl_audit_conn_table_exists (conn, "audit_events", &exists)
      != WYRELOG_E_OK)
    return 92;
  if (!exists)
    return 93;

  if (wyl_audit_conn_table_exists (conn, "missing_table", &exists)
      != WYRELOG_E_OK)
    return 94;
  if (exists)
    return 95;
  return 0;
}

static gint
check_table_probe_rejects_invalid_args (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  gboolean exists = FALSE;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 100;
  if (wyl_audit_conn_table_exists (NULL, "audit_events", &exists)
      != WYRELOG_E_INVALID)
    return 101;
  if (wyl_audit_conn_table_exists (conn, NULL, &exists)
      != WYRELOG_E_INVALID)
    return 102;
  if (wyl_audit_conn_table_exists (conn, "audit_events", NULL)
      != WYRELOG_E_INVALID)
    return 103;
  return 0;
}

static gint
check_reserved_stream_guard (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 110;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 111;
  if (!wyl_audit_conn_stream_name_is_reserved ("__wyrelog.audit"))
    return 112;
  if (wyl_audit_conn_validate_user_stream_name ("__wyrelog.audit")
      != WYRELOG_E_POLICY)
    return 113;
  if (wyl_audit_conn_create_user_stream (conn, "__wyrelog.security")
      != WYRELOG_E_POLICY)
    return 114;
  if (wyl_audit_conn_drop_user_stream (conn, "__wyrelog.audit")
      != WYRELOG_E_POLICY)
    return 115;
  if (wyl_audit_conn_rename_user_stream (conn, "tenant.audit",
          "__wyrelog.audit") != WYRELOG_E_POLICY)
    return 116;
  if (wyl_audit_conn_create_user_stream (conn, "tenant.audit")
      != WYRELOG_E_OK)
    return 117;
  if (wyl_audit_conn_rename_user_stream (conn, "tenant.audit",
          "tenant.audit.v2") != WYRELOG_E_OK)
    return 118;
  if (wyl_audit_conn_drop_user_stream (conn, "tenant.audit.v2")
      != WYRELOG_E_OK)
    return 119;
  return 0;
}

static gint
insert_chain_event (wyl_audit_conn_t *conn, const gchar *id,
    const gchar *subject)
{
  gboolean inserted = FALSE;
  return wyl_audit_conn_insert_event_full (conn, id, 1000, subject,
      "read", "resource", NULL, NULL, "req", WYL_DECISION_ALLOW,
      &inserted) == WYRELOG_E_OK && inserted ? 0 : 1;
}

static gint
check_chain_verifies_clean_store (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  g_autofree gchar *error = NULL;

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 120;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 121;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000101",
          "alice") != 0)
    return 122;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000102",
          "bob") != 0)
    return 123;
  if (wyl_audit_conn_verify_chain (conn, &error) != WYRELOG_E_OK)
    return 124;
  if (error != NULL)
    return 125;
  return 0;
}

static gint
check_chain_tail_cache_hydrates_after_reopen (void)
{
  g_autoptr (GError) err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-audit-chain-XXXXXX", &err);
  if (tmpdir == NULL)
    return 126;
  g_autofree gchar *path = g_build_filename (tmpdir, "audit.db", NULL);

  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK)
    return 127;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 128;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000103",
          "alice") != 0)
    return 129;
  wyl_audit_conn_close (g_steal_pointer (&conn));

  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK)
    return 136;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 137;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000104",
          "bob") != 0)
    return 138;

  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  duckdb_result result = { 0 };
  if (duckdb_query (h,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE sequence_no = 2 AND previous_hash != '';",
          &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 139;
  }
  gboolean linked = duckdb_value_int64 (&result, 0, 0) == 1;
  duckdb_destroy_result (&result);
  if (!linked)
    return 149;

  g_autofree gchar *chain_error = NULL;
  if (wyl_audit_conn_verify_chain (conn, &chain_error) != WYRELOG_E_OK)
    return 156;

  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_unlink (path);
  g_rmdir (tmpdir);
  return 0;
}

static gint
check_chain_detects_record_modification (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  g_autofree gchar *error = NULL;
  duckdb_result result = { 0 };

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 130;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 131;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000201",
          "alice") != 0)
    return 132;
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  if (duckdb_query (h,
          "UPDATE audit_events SET subject_id = 'mallory' "
          "WHERE sequence_no = 1;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 133;
  }
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_verify_chain (conn, &error) != WYRELOG_E_POLICY)
    return 134;
  if (g_strcmp0 (error, "record_hash_mismatch") != 0)
    return 135;
  return 0;
}

static gint
check_chain_detects_missing_link_and_reorder (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  g_autofree gchar *error = NULL;
  duckdb_result result = { 0 };

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 140;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 141;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000301",
          "alice") != 0)
    return 142;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000302",
          "bob") != 0)
    return 143;
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  if (duckdb_query (h,
          "UPDATE audit_events SET sequence_no = 3 WHERE sequence_no = 2;",
          &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 144;
  }
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_verify_chain (conn, &error) != WYRELOG_E_POLICY)
    return 145;
  if (g_strcmp0 (error, "missing_link") != 0)
    return 146;
  return 0;
}

static gint
check_chain_detects_deleted_tail_record (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  g_autofree gchar *error = NULL;
  duckdb_result result = { 0 };

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 147;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 148;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000401",
          "alice") != 0)
    return 149;
  if (insert_chain_event (conn, "01890c10-2e3f-7000-8000-000000000402",
          "bob") != 0)
    return 156;
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  if (duckdb_query (h, "DELETE FROM audit_events WHERE sequence_no = 2;",
          &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 157;
  }
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_verify_chain (conn, &error) != WYRELOG_E_POLICY)
    return 158;
  if (g_strcmp0 (error, "missing_link") != 0)
    return 159;
  return 0;
}

static gint
check_duplicate_checkpoint_and_tombstone_flow (void)
{
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  gboolean inserted = FALSE;
  duckdb_result result = { 0 };

  if (wyl_audit_conn_open (NULL, &conn) != WYRELOG_E_OK)
    return 150;
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 151;
  if (wyl_audit_conn_append_tombstone (conn, "subject-to-erase",
          "erase-request", &inserted) != WYRELOG_E_OK || !inserted)
    return 152;
  duckdb_connection h = wyl_audit_conn_get_connection (conn);
  if (duckdb_query (h,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'privacy.erase.tombstone' "
          "AND deny_reason = 'erasure_tombstone';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 153;
  }
  if (duckdb_value_int64 (&result, 0, 0) != 1) {
    duckdb_destroy_result (&result);
    return 154;
  }
  duckdb_destroy_result (&result);
  if (duckdb_query (h,
          "INSERT INTO audit_checkpoints "
          "(stream_name, sequence_no, root_hash, created_at_us) "
          "VALUES ('__wyrelog.audit', 1, 'duplicate', 1);", &result)
      == DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 155;
  }
  duckdb_destroy_result (&result);
  return 0;
}

typedef struct
{
  wyl_service_exchange_audit_material_t material;
  WylAuditServiceExchangeProjection projection;
} ProjectionFixture;

static void
projection_fixture_clear (ProjectionFixture *fixture)
{
  wyl_service_exchange_audit_material_clear (&fixture->material);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (ProjectionFixture, projection_fixture_clear);

static void
projection_fixture_init (ProjectionFixture *fixture, const gchar *intention)
{
  static const gchar session[] = "01890f47-3c4b-7cc2-98c4-dc0c0c07398f";
  static const gchar jti[] = "01890f47-3c4b-7cc2-a8c4-dc0c0c073990";
  memset (fixture, 0, sizeof *fixture);
  wyl_service_exchange_audit_input_t input = {
    .request_id = {"000000000000000000000000000", 27},
    .credential_id = {"wlc_000000000000000000000000000", 31},
    .credential_generation = G_GUINT64_CONSTANT (0x0102030405060708),
    .service_principal = {"svc:billing:reader", 18},
    .tenant_id = {"tenant-a", 8},
    .session_id = {session, 36},
    .jti = {jti, 36},
    .created_at_us = G_GINT64_CONSTANT (1712345678901234),
  };
  g_assert_cmpint (wyl_id_parse (intention, &input.intention_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_audit_encode (&input,
          &fixture->material), ==, WYRELOG_E_OK);
  fixture->projection = (WylAuditServiceExchangeProjection) {
  .intention_id = fixture->material.intention_id,.payload_digest =
        fixture->material.payload_digest,.request_id =
        fixture->material.request_id,.credential_id =
        input.credential_id.data,.credential_generation =
        input.credential_generation,.service_principal =
        input.service_principal.data,.tenant_id =
        input.tenant_id.data,.created_at_us =
        input.created_at_us,.payload_schema_version =
        WYL_SERVICE_EXCHANGE_PAYLOAD_SCHEMA_VERSION,.fingerprint_schema_version
        =
        WYL_SERVICE_EXCHANGE_FINGERPRINT_SCHEMA_VERSION,.session_fingerprint =
        fixture->material.session_fingerprint,.jti_fingerprint =
        fixture->material.jti_fingerprint,.canonical_payload =
        fixture->material.canonical_payload,};
}

static void
assert_projection_invalid (wyl_audit_conn_t *conn,
    WylAuditServiceExchangeProjection projection)
{
  WylAuditServiceExchangeProjectionReadback out;
  memset (&out, 0xa5, sizeof out);
  g_assert_cmpint (wyl_audit_conn_service_exchange_project (conn,
          &projection, &out), ==, WYRELOG_E_INVALID);
  static const WylAuditServiceExchangeProjectionReadback zero = { 0 };
  g_assert_cmpmem (&out, sizeof out, &zero, sizeof zero);
}

static gint
check_service_exchange_projection_validates_full_transcript (void)
{
  g_auto (ProjectionFixture) fixture = { 0 };
  projection_fixture_init (&fixture, "01890c10-2e3f-7000-8000-000000000901");
  WylAuditServiceExchangeProjection base = fixture.projection;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-projection-canary-XXXXXX",
      &error);
  g_autofree gchar *path = g_build_filename (dir, "audit.db", NULL);
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (dir == NULL || wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 189;

#define MUTATE(field, value) G_STMT_START { \
  WylAuditServiceExchangeProjection mutant = base; \
  mutant.field = (value); \
  assert_projection_invalid (conn, mutant); \
} G_STMT_END
  MUTATE (intention_id, "01890c10-2e3f-7000-8000-000000000902");
  MUTATE (payload_digest,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  MUTATE (request_id, "000000000000000000000000002");
  MUTATE (credential_id, "wlc_000000000000000000000000002");
  MUTATE (credential_generation, base.credential_generation + 1);
  MUTATE (service_principal, "svc:billing:writer");
  MUTATE (tenant_id, "tenant-b");
  MUTATE (created_at_us, base.created_at_us + 1);
  MUTATE (payload_schema_version, 2);
  MUTATE (fingerprint_schema_version, 2);
  MUTATE (session_fingerprint,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  MUTATE (jti_fingerprint,
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  MUTATE (service_principal, "svc:RAW_SESSION_CANARY_387_9f4b");
  MUTATE (tenant_id, "JWT_SECRET_CANARY_387_63ac");
  MUTATE (credential_id, "PATH_CANARY_387_/tmp/private.db");
#undef MUTATE

  gsize payload_len = 0;
  const guint8 *payload = g_bytes_get_data (base.canonical_payload,
      &payload_len);
  g_autofree guint8 *changed = g_memdup2 (payload, payload_len);
  changed[payload_len / 2] ^= 1;
  g_autoptr (GBytes) changed_payload = g_bytes_new_take
      (g_steal_pointer (&changed), payload_len);
  WylAuditServiceExchangeProjection mutant = base;
  mutant.canonical_payload = changed_payload;
  assert_projection_invalid (conn, mutant);
  duckdb_result result = { 0 };
  if (duckdb_query (wyl_audit_conn_get_connection (conn),
          "SELECT (SELECT count(*) FROM service_exchange_receipt_projections)"
          "+(SELECT count(*) FROM audit_events WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "');", &result)
      != DuckDBSuccess || duckdb_value_int64 (&result, 0, 0) != 0) {
    duckdb_destroy_result (&result);
    return 196;
  }
  duckdb_destroy_result (&result);
  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_autofree gchar *database = NULL;
  gsize database_len = 0;
  if (!g_file_get_contents (path, &database, &database_len, NULL)
      || g_strstr_len (database, database_len,
          "RAW_SESSION_CANARY_387_9f4b") != NULL
      || g_strstr_len (database, database_len,
          "JWT_SECRET_CANARY_387_63ac") != NULL
      || g_strstr_len (database, database_len,
          "PATH_CANARY_387_/tmp/private.db") != NULL
      || g_strstr_len (database, database_len, path) != NULL)
    return 197;
  g_unlink (path);
  g_rmdir (dir);
  return 0;
}

static gint
check_service_exchange_projection_schema_is_exact (void)
{
  static const gchar *mutations[] = {
    "ALTER TABLE service_exchange_receipt_projections ALTER COLUMN "
        "event_type DROP NOT NULL;",
    "ALTER TABLE service_exchange_receipt_projections ALTER COLUMN "
        "tenant_id SET DEFAULT 'tenant-default';",
    "DROP TABLE audit_sink_metadata;"
        "CREATE TABLE audit_sink_metadata(logical_sink_name VARCHAR NOT NULL,"
        "sink_uuid VARCHAR NOT NULL,schema_version INTEGER NOT NULL);"
        "INSERT INTO audit_sink_metadata VALUES"
        "('__wyrelog.service-exchange',"
        "'01890c10-2e3f-7000-8000-000000000911',1),"
        "('__wyrelog.service-exchange',"
        "'01890c10-2e3f-7000-8000-000000000912',1);",
    "ALTER TABLE audit_sink_metadata RENAME TO old_metadata;"
        "CREATE TABLE audit_sink_metadata("
        "logical_sink_name VARCHAR PRIMARY KEY,"
        "sink_uuid VARCHAR NOT NULL UNIQUE,schema_version INTEGER NOT NULL,"
        "CHECK(schema_version=1));"
        "INSERT INTO audit_sink_metadata SELECT * FROM old_metadata;"
        "DROP TABLE old_metadata;",
    "CREATE TABLE sink_uuid_references(sink_uuid VARCHAR PRIMARY KEY);"
        "INSERT INTO sink_uuid_references SELECT sink_uuid "
        "FROM audit_sink_metadata;"
        "ALTER TABLE audit_sink_metadata RENAME TO old_metadata;"
        "CREATE TABLE audit_sink_metadata("
        "logical_sink_name VARCHAR PRIMARY KEY,"
        "sink_uuid VARCHAR NOT NULL UNIQUE,schema_version INTEGER NOT NULL,"
        "FOREIGN KEY(sink_uuid) REFERENCES sink_uuid_references(sink_uuid));"
        "INSERT INTO audit_sink_metadata SELECT * FROM old_metadata;"
        "DROP TABLE old_metadata;",
    "CREATE UNIQUE INDEX extra_projection_unique ON "
        "service_exchange_receipt_projections(sink_uuid,tenant_id);",
    "ALTER TABLE service_exchange_receipt_projections RENAME TO old_p;"
        "CREATE TABLE service_exchange_receipt_projections("
        "sink_uuid VARCHAR NOT NULL,intention_id VARCHAR NOT NULL,"
        "payload_digest VARCHAR NOT NULL,event_type VARCHAR NOT NULL,"
        "outcome VARCHAR NOT NULL,created_at_us BIGINT NOT NULL,"
        "request_id VARCHAR NOT NULL,credential_id VARCHAR NOT NULL,"
        "credential_generation BLOB NOT NULL,"
        "service_principal VARCHAR NOT NULL,tenant_id VARCHAR NOT NULL,"
        "payload_schema_version INTEGER NOT NULL,"
        "fingerprint_schema_version INTEGER NOT NULL,"
        "session_fingerprint VARCHAR NOT NULL,jti_fingerprint VARCHAR NOT NULL,"
        "canonical_payload BLOB NOT NULL,PRIMARY KEY(sink_uuid,intention_id),"
        "UNIQUE(sink_uuid,payload_digest),"
        "CHECK(event_type='service.credential.exchange'),"
        "CHECK(outcome='allowed'),CHECK(payload_schema_version=1),"
        "CHECK(fingerprint_schema_version=1),"
        "CHECK(octet_length(credential_generation)=8),"
        "CHECK(octet_length(canonical_payload) BETWEEN 1 AND 4096),"
        "CHECK(created_at_us>0));DROP TABLE old_p;",
  };
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-projection-schema-XXXXXX",
      &error);
  g_autofree gchar *path = g_build_filename (dir, "audit.db", NULL);
  for (guint i = 0; i < G_N_ELEMENTS (mutations); i++) {
    g_unlink (path);
    g_autoptr (wyl_audit_conn_t) conn = NULL;
    if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK
        || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
      return 193;
    duckdb_result result = { 0 };
    if (duckdb_query (wyl_audit_conn_get_connection (conn), mutations[i],
            &result) != DuckDBSuccess) {
      duckdb_destroy_result (&result);
      return 194;
    }
    duckdb_destroy_result (&result);
    if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_POLICY)
      return 195;
  }
  g_unlink (path);
  g_rmdir (dir);
  return 0;
}

static gint
check_service_exchange_metadata_transaction_readback (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-metadata-readback-XXXXXX",
      &error);
  g_autofree gchar *path = g_build_filename (dir, "audit.db", NULL);
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (dir == NULL || wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK)
    return 201;
  wyl_audit_conn_service_exchange_fail_once (conn,
      WYL_AUDIT_SERVICE_EXCHANGE_FAIL_METADATA_IN_TXN_READBACK);
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_IO
      || wyl_audit_conn_service_exchange_get_rollback_count_for_test (conn)
      != 1)
    return 202;
  duckdb_result result = { 0 };
  duckdb_connection raw = wyl_audit_conn_get_connection (conn);
  if (duckdb_query (raw, "SELECT COUNT(*) FROM audit_sink_metadata;", &result)
      != DuckDBSuccess || duckdb_value_int64 (&result, 0, 0) != 0) {
    duckdb_destroy_result (&result);
    return 203;
  }
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK
      || wyl_audit_conn_service_exchange_get_rollback_count_for_test (conn)
      != 1)
    return 204;
  if (duckdb_query (raw,
          "SELECT logical_sink_name,sink_uuid,schema_version "
          "FROM audit_sink_metadata;", &result) != DuckDBSuccess
      || duckdb_row_count (&result) != 1)
    return 205;
  gchar *logical_name = duckdb_value_varchar (&result, 0, 0);
  gchar *uuid = duckdb_value_varchar (&result, 1, 0);
  gboolean exact = g_strcmp0 (logical_name,
      WYL_AUDIT_SERVICE_EXCHANGE_STREAM) == 0
      && uuid != NULL && strlen (uuid) == 36
      && duckdb_value_int64 (&result, 2, 0) == 1;
  g_autofree gchar *first_uuid = g_strdup (uuid);
  duckdb_free (logical_name);
  duckdb_free (uuid);
  duckdb_destroy_result (&result);
  if (!exact || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 206;
  if (duckdb_query (raw, "SELECT sink_uuid FROM audit_sink_metadata;", &result)
      != DuckDBSuccess || duckdb_row_count (&result) != 1)
    return 207;
  uuid = duckdb_value_varchar (&result, 0, 0);
  exact = g_strcmp0 (uuid, first_uuid) == 0;
  duckdb_free (uuid);
  duckdb_destroy_result (&result);
  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_unlink (path);
  g_rmdir (dir);
  return exact ? 0 : 208;
}

static gint
checkpoint_corruption_is_denied (duckdb_connection raw,
    wyl_audit_conn_t *conn, const WylAuditServiceExchangeProjection *p,
    const gchar *mutation, const gchar *restore)
{
  duckdb_result result = { 0 };
  if (duckdb_query (raw, mutation, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return FALSE;
  }
  duckdb_destroy_result (&result);
  WylAuditServiceExchangeProjectionReadback out;
  memset (&out, 0xa5, sizeof out);
  if (wyl_audit_conn_service_exchange_project (conn, p, &out)
      != WYRELOG_E_POLICY
      || out.sink_uuid[0] != '\0' || out.sequence_no != 0
      || out.record_hash[0] != '\0')
    return FALSE;
  if (duckdb_query (raw, restore, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return FALSE;
  }
  duckdb_destroy_result (&result);
  return TRUE;
}

static gint
check_service_exchange_projection_durable_exact (void)
{
  g_auto (ProjectionFixture) fixture = { 0 };
  projection_fixture_init (&fixture, "01890c10-2e3f-7000-8000-000000000501");
  WylAuditServiceExchangeProjection p = fixture.projection;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-projection-XXXXXX", &error);
  if (dir == NULL)
    return 160;
  g_autofree gchar *path = g_build_filename (dir, "audit.db", NULL);
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 161;
  WylAuditServiceExchangeProjectionReadback first = { 0 }, replay = { 0 };
  wyrelog_error_t project_rc =
      wyl_audit_conn_service_exchange_project (conn, &p, &first);
  if (project_rc != WYRELOG_E_OK || first.sequence_no != 1
      || strcmp (first.intention_id, p.intention_id) != 0
      || strcmp (first.record_hash,
          "060e74f0177ea5d3ac5962f31665162ae24f9142bd296e73ba023835f5bc0cfc")
      != 0)
    return 162;
  if (wyl_audit_conn_service_exchange_project (conn, &p, &replay)
      != WYRELOG_E_OK || replay.sequence_no != first.sequence_no
      || strcmp (replay.sink_uuid, first.sink_uuid) != 0)
    return 163;
  duckdb_result result = { 0 };
  if (duckdb_query (wyl_audit_conn_get_connection (conn),
          "SELECT (SELECT count(*) FROM service_exchange_receipt_projections),"
          "(SELECT count(*) FROM audit_events WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "'),"
          "(SELECT count(*) FROM audit_checkpoints WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "');", &result) != DuckDBSuccess)
    return 164;
  gboolean one_each = duckdb_value_int64 (&result, 0, 0) == 1
      && duckdb_value_int64 (&result, 1, 0) == 1
      && duckdb_value_int64 (&result, 2, 0) == 1;
  duckdb_destroy_result (&result);
  if (!one_each)
    return 165;
  wyl_audit_conn_close (g_steal_pointer (&conn));
  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
    return 166;
  WylAuditServiceExchangeProjectionReadback reopened = { 0 };
  if (wyl_audit_conn_service_exchange_project (conn, &p, &reopened)
      != WYRELOG_E_OK || strcmp (reopened.sink_uuid, first.sink_uuid) != 0
      || reopened.sequence_no != 1)
    return 167;

  /* Every field participates in exact replay. */
  WylAuditServiceExchangeProjection changed = p;
  changed.tenant_id = "tenant-b";
  if (wyl_audit_conn_service_exchange_project (conn, &changed, &reopened)
      != WYRELOG_E_INVALID)
    return 168;
  const struct
  {
    const gchar *mutation;
    const gchar *restore;
  } anchor_corruption[] = {
    {"record_hash=NULL", NULL},
    {"previous_hash=NULL", "previous_hash=''"},
    {"checkpoint_root=NULL", NULL},
    {"record_hash='short'", NULL},
    {"record_hash='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        NULL},
    {"previous_hash='a'", "previous_hash=''"},
    {"subject_id=NULL", "subject_id='svc:billing:reader'"},
  };
  duckdb_connection raw = wyl_audit_conn_get_connection (conn);
  for (guint i = 0; i < G_N_ELEMENTS (anchor_corruption); i++) {
    g_autofree gchar *sql = g_strdup_printf
        ("UPDATE audit_events SET %s WHERE id='%s';",
        anchor_corruption[i].mutation, p.intention_id);
    duckdb_result mutation_result = { 0 };
    if (duckdb_query (raw, sql, &mutation_result) != DuckDBSuccess)
      return 190;
    duckdb_destroy_result (&mutation_result);
    if (wyl_audit_conn_service_exchange_project (conn, &p, &reopened)
        != WYRELOG_E_POLICY)
      return 191;
    const gchar *restore = anchor_corruption[i].restore;
    g_autofree gchar *dynamic_restore = NULL;
    if (restore == NULL) {
      const gchar *column = g_str_has_prefix (anchor_corruption[i].mutation,
          "checkpoint_root") ? "checkpoint_root" : "record_hash";
      dynamic_restore = g_strdup_printf ("%s='%s'", column, first.record_hash);
      restore = dynamic_restore;
    }
    g_clear_pointer (&sql, g_free);
    sql = g_strdup_printf ("UPDATE audit_events SET %s WHERE id='%s';",
        restore, p.intention_id);
    if (duckdb_query (raw, sql, &mutation_result) != DuckDBSuccess)
      return 192;
    duckdb_destroy_result (&mutation_result);
  }

  /* The checkpoint is the third authoritative record. Database corruption
   * must be observed even after the chain-tail cache has been populated. */
  g_autofree gchar *checkpoint_insert = g_strdup_printf
      ("INSERT INTO audit_checkpoints VALUES ('%s',1,'%s',%" G_GINT64_FORMAT
      ");", WYL_AUDIT_SERVICE_EXCHANGE_STREAM, first.record_hash,
      p.created_at_us);
  g_autofree gchar *restore_root = g_strdup_printf
      ("UPDATE audit_checkpoints SET root_hash='%s' WHERE stream_name='%s' "
      "AND sequence_no=1;", first.record_hash,
      WYL_AUDIT_SERVICE_EXCHANGE_STREAM);
  g_autofree gchar *restore_time = g_strdup_printf
      ("UPDATE audit_checkpoints SET created_at_us=%" G_GINT64_FORMAT
      " WHERE stream_name='%s' AND sequence_no=1;", p.created_at_us,
      WYL_AUDIT_SERVICE_EXCHANGE_STREAM);
  if (!checkpoint_corruption_is_denied (raw, conn, &p,
          "DELETE FROM audit_checkpoints WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND sequence_no=1;",
          checkpoint_insert)
      || !checkpoint_corruption_is_denied (raw, conn, &p,
          "UPDATE audit_checkpoints SET root_hash='short' WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND sequence_no=1;",
          restore_root)
      || !checkpoint_corruption_is_denied (raw, conn, &p,
          "UPDATE audit_checkpoints SET "
          "root_hash='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAA' WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND sequence_no=1;",
          restore_root)
      || !checkpoint_corruption_is_denied (raw, conn, &p,
          "UPDATE audit_checkpoints SET created_at_us=1 WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND sequence_no=1;",
          restore_time)
      || !checkpoint_corruption_is_denied (raw, conn, &p,
          "UPDATE audit_checkpoints SET sequence_no=2 WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND sequence_no=1;",
          "UPDATE audit_checkpoints SET sequence_no=1 WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND sequence_no=2;")
      || !checkpoint_corruption_is_denied (raw, conn, &p,
          "UPDATE audit_checkpoints SET stream_name='corrupt' WHERE "
          "stream_name='" WYL_AUDIT_SERVICE_EXCHANGE_STREAM
          "' AND sequence_no=1;",
          "UPDATE audit_checkpoints SET stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM
          "' WHERE stream_name='corrupt' AND sequence_no=1;"))
    return 193;

  /* NOT NULL and the primary key make NULL and duplicate states
   * unrepresentable; prove those mutations are rejected by DuckDB. */
  if (duckdb_query (raw,
          "UPDATE audit_checkpoints SET root_hash=NULL WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND sequence_no=1;", &result)
      == DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 194;
  }
  duckdb_destroy_result (&result);
  memset (&result, 0, sizeof result);
  if (duckdb_query (raw, checkpoint_insert, &result) == DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return 194;
  }
  duckdb_destroy_result (&result);
  memset (&result, 0, sizeof result);
  if (wyl_audit_conn_service_exchange_project (conn, &p, &reopened)
      != WYRELOG_E_OK || reopened.sequence_no != 1)
    return 195;

  g_auto (ProjectionFixture) fixture_two = { 0 };
  projection_fixture_init (&fixture_two,
      "01890c10-2e3f-7000-8000-000000000502");
  WylAuditServiceExchangeProjection p2 = fixture_two.projection;
  if (wyl_audit_conn_service_exchange_project (conn, &p2, &reopened)
      != WYRELOG_E_OK || reopened.sequence_no != 2)
    return 181;
  WylAuditServiceExchangeProjection crossed = p2;
  crossed.intention_id = p.intention_id;
  if (wyl_audit_conn_service_exchange_project (conn, &crossed, &reopened)
      != WYRELOG_E_INVALID)
    return 182;
  if (duckdb_query (raw,
          "UPDATE service_exchange_receipt_projections SET tenant_id='corrupt';",
          &result) != DuckDBSuccess)
    return 169;
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_service_exchange_project (conn, &p, &reopened)
      != WYRELOG_E_POLICY)
    return 170;
  if (duckdb_query (raw,
          "DELETE FROM service_exchange_receipt_projections;", &result)
      != DuckDBSuccess)
    return 196;
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_service_exchange_project (conn, &p, &reopened)
      != WYRELOG_E_POLICY || reopened.sink_uuid[0] != '\0')
    return 197;
  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_autofree gchar *database_bytes = NULL;
  gsize database_len = 0;
  if (!g_file_get_contents (path, &database_bytes, &database_len, NULL)
      || g_strstr_len (database_bytes, database_len,
          "RAW_SESSION_CANARY_387_9f4b") != NULL
      || g_strstr_len (database_bytes, database_len,
          "JWT_SECRET_CANARY_387_63ac") != NULL
      || g_strstr_len (database_bytes, database_len, path) != NULL)
    return 188;
  g_unlink (path);
  g_rmdir (dir);
  return 0;
}

static gint
check_service_exchange_projection_guards (void)
{
  g_auto (ProjectionFixture) fixture = { 0 };
  projection_fixture_init (&fixture, "01890c10-2e3f-7000-8000-000000000601");
  WylAuditServiceExchangeProjection p = fixture.projection;
  WylAuditServiceExchangeProjectionReadback out = { 0 };
  g_autoptr (wyl_audit_conn_t) memory = NULL;
  if (wyl_audit_conn_open (NULL, &memory) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (memory) != WYRELOG_E_OK
      || wyl_audit_conn_service_exchange_project (memory, &p, &out)
      != WYRELOG_E_POLICY)
    return 171;

  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-projection-guard-XXXXXX",
      &error);
  g_autofree gchar *path = g_build_filename (dir, "audit.db", NULL);
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK
      || wyl_audit_conn_service_exchange_project (conn, &p, &out)
      != WYRELOG_E_OK)
    return 172;
  duckdb_result result = { 0 };
  if (duckdb_query (wyl_audit_conn_get_connection (conn),
          "DELETE FROM audit_events WHERE stream_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';", &result) != DuckDBSuccess)
    return 173;
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_service_exchange_project (conn, &p, &out)
      != WYRELOG_E_POLICY)
    return 174;
  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_unlink (path);
  g_rmdir (dir);
  return 0;
}

static gint
check_service_exchange_projection_fault_stages (void)
{
  static const WylAuditServiceExchangeFailStage precommit[] = {
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_BEGIN,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_PREFLIGHT,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_SIDECAR,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_ANCHOR,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_IN_TXN_READBACK,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_QUERY,
  };
  g_auto (ProjectionFixture) fixture = { 0 };
  projection_fixture_init (&fixture, "01890c10-2e3f-7000-8000-000000000701");
  WylAuditServiceExchangeProjection p = fixture.projection;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-projection-fault-XXXXXX",
      &error);
  g_autofree gchar *path = g_build_filename (dir, "audit.db", NULL);
  for (guint i = 0; i < G_N_ELEMENTS (precommit); i++) {
    g_unlink (path);
    g_autoptr (wyl_audit_conn_t) conn = NULL;
    if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK
        || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
      return 175;
    wyl_audit_conn_service_exchange_fail_once (conn, precommit[i]);
    guint rollback_before =
        wyl_audit_conn_service_exchange_get_rollback_count_for_test (conn);
    WylAuditServiceExchangeProjectionReadback out = { 0 };
    if (wyl_audit_conn_service_exchange_project (conn, &p, &out)
        != WYRELOG_E_IO || out.sink_uuid[0] != '\0')
      return 176;
    duckdb_result result = { 0 };
    if (duckdb_query (wyl_audit_conn_get_connection (conn),
            "SELECT (SELECT count(*) FROM service_exchange_receipt_projections)"
            "+(SELECT count(*) FROM audit_events WHERE stream_name='"
            WYL_AUDIT_SERVICE_EXCHANGE_STREAM "')"
            "+(SELECT count(*) FROM audit_checkpoints WHERE stream_name='"
            WYL_AUDIT_SERVICE_EXCHANGE_STREAM "');", &result)
        != DuckDBSuccess || duckdb_value_int64 (&result, 0, 0) != 0) {
      duckdb_destroy_result (&result);
      return 177;
    }
    duckdb_destroy_result (&result);
    if (wyl_audit_conn_service_exchange_get_rollback_count_for_test (conn)
        != rollback_before + 1)
      return 199;
    if (wyl_audit_conn_service_exchange_project (conn, &p, &out)
        != WYRELOG_E_OK || out.sequence_no != 1)
      return 198;
    if (wyl_audit_conn_service_exchange_get_rollback_count_for_test (conn)
        != rollback_before + 1)
      return 200;
  }

  static const WylAuditServiceExchangeFailStage committed[] = {
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_RESPONSE_LOST,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_CHECKPOINT,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_POST_COMMIT_READBACK,
  };
  for (guint i = 0; i < G_N_ELEMENTS (committed); i++) {
    g_unlink (path);
    g_autoptr (wyl_audit_conn_t) conn = NULL;
    if (wyl_audit_conn_open (path, &conn) != WYRELOG_E_OK
        || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK)
      return 178;
    wyl_audit_conn_service_exchange_fail_once (conn, committed[i]);
    WylAuditServiceExchangeProjectionReadback out = { 0 };
    if (wyl_audit_conn_service_exchange_project (conn, &p, &out)
        != WYRELOG_E_IO || out.sink_uuid[0] != '\0')
      return 179;
    /* A committed-but-unacknowledged boundary never reports success; exact
     * retry reconciles without allocating another sequence. */
    if (wyl_audit_conn_service_exchange_project (conn, &p, &out)
        != WYRELOG_E_OK || out.sequence_no != 1)
      return 180;
  }
  g_unlink (path);
  g_rmdir (dir);
  return 0;
}

static gint
check_service_exchange_sink_uuid_lifecycle (void)
{
  g_auto (ProjectionFixture) fixture = { 0 };
  projection_fixture_init (&fixture, "01890c10-2e3f-7000-8000-000000000801");
  WylAuditServiceExchangeProjection p = fixture.projection;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-projection-uuid-XXXXXX",
      &error);
  g_autofree gchar *path_a = g_build_filename (dir, "a.db", NULL);
  g_autofree gchar *path_b = g_build_filename (dir, "moved.db", NULL);
  g_autofree gchar *path_new = g_build_filename (dir, "new.db", NULL);
  g_autoptr (wyl_audit_conn_t) conn = NULL;
  WylAuditServiceExchangeProjectionReadback before = { 0 }, moved = { 0 };
  if (wyl_audit_conn_open (path_a, &conn) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK
      || wyl_audit_conn_service_exchange_project (conn, &p, &before)
      != WYRELOG_E_OK)
    return 183;
  wyl_audit_conn_close (g_steal_pointer (&conn));
  if (g_rename (path_a, path_b) != 0
      || wyl_audit_conn_open (path_b, &conn) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK
      || wyl_audit_conn_service_exchange_project (conn, &p, &moved)
      != WYRELOG_E_OK || strcmp (before.sink_uuid, moved.sink_uuid) != 0)
    return 184;
  wyl_audit_conn_close (g_steal_pointer (&conn));

  WylAuditServiceExchangeProjectionReadback fresh = { 0 };
  if (wyl_audit_conn_open (path_new, &conn) != WYRELOG_E_OK
      || wyl_audit_conn_create_schema (conn) != WYRELOG_E_OK
      || wyl_audit_conn_service_exchange_project (conn, &p, &fresh)
      != WYRELOG_E_OK || strcmp (before.sink_uuid, fresh.sink_uuid) == 0)
    return 185;
  duckdb_result result = { 0 };
  if (duckdb_query (wyl_audit_conn_get_connection (conn),
          "DELETE FROM audit_sink_metadata WHERE logical_sink_name='"
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';", &result) != DuckDBSuccess)
    return 186;
  duckdb_destroy_result (&result);
  if (wyl_audit_conn_service_exchange_project (conn, &p, &fresh)
      != WYRELOG_E_POLICY)
    return 187;
  wyl_audit_conn_close (g_steal_pointer (&conn));
  g_unlink (path_b);
  g_unlink (path_new);
  g_rmdir (dir);
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_open_memory_null_path ()) != 0)
    return rc;
  if ((rc = check_open_memory_literal ()) != 0)
    return rc;
  if ((rc = check_open_tempfile_and_query ()) != 0)
    return rc;
  if ((rc = check_open_bad_path ()) != 0)
    return rc;
  if ((rc = check_invalid_args ()) != 0)
    return rc;
  if ((rc = check_close_null_noop ()) != 0)
    return rc;
  if ((rc = check_get_connection_null ()) != 0)
    return rc;
  if ((rc = check_create_schema ()) != 0)
    return rc;
  if ((rc = check_create_schema_null_arg ()) != 0)
    return rc;
  if ((rc = check_template_schema_creates_audit_events ()) != 0)
    return rc;
  if ((rc = check_table_probe_reports_schema ()) != 0)
    return rc;
  if ((rc = check_table_probe_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_reserved_stream_guard ()) != 0)
    return rc;
  if ((rc = check_chain_verifies_clean_store ()) != 0)
    return rc;
  if ((rc = check_chain_tail_cache_hydrates_after_reopen ()) != 0)
    return rc;
  if ((rc = check_chain_detects_record_modification ()) != 0)
    return rc;
  if ((rc = check_chain_detects_missing_link_and_reorder ()) != 0)
    return rc;
  if ((rc = check_chain_detects_deleted_tail_record ()) != 0)
    return rc;
  if ((rc = check_duplicate_checkpoint_and_tombstone_flow ()) != 0)
    return rc;
  if ((rc = check_service_exchange_projection_durable_exact ()) != 0)
    return rc;
  if ((rc = check_service_exchange_projection_guards ()) != 0)
    return rc;
  if ((rc = check_service_exchange_projection_fault_stages ()) != 0)
    return rc;
  if ((rc = check_service_exchange_sink_uuid_lifecycle ()) != 0)
    return rc;
  if ((rc = check_service_exchange_projection_validates_full_transcript ())
      != 0)
    return rc;
  if ((rc = check_service_exchange_projection_schema_is_exact ()) != 0)
    return rc;
  if ((rc = check_service_exchange_metadata_transaction_readback ()) != 0)
    return rc;
  return 0;
}

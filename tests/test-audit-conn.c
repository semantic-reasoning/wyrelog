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
  return 0;
}

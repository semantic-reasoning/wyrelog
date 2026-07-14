/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "conn-private.h"

#include <string.h>

#include "wyrelog/decide.h"
#include "wyrelog/wyl-id-private.h"

#define WYL_AUDIT_RESERVED_PREFIX "__wyrelog."
#define WYL_AUDIT_STREAM_AUDIT "__wyrelog.audit"
#define WYL_AUDIT_CHECKPOINT_INTERVAL 1
#define WYL_SERVICE_EXCHANGE_EVENT_KIND "service.credential.exchange"

static wyrelog_error_t ensure_service_exchange_schema
    (wyl_audit_conn_t * conn, gboolean allow_create_metadata);

typedef struct
{
  gint64 last_sequence_no;
  gchar *last_record_hash;
} WylAuditChainTail;

struct wyl_audit_conn_t
{
  duckdb_database db;
  duckdb_connection conn;
  GMutex lock;
  GHashTable *chain_tail_cache;
  gboolean fail_insert_once;
  gboolean persistent;
  WylAuditServiceExchangeFailStage service_exchange_fail_stage;
  guint service_exchange_rollback_count;
  gint service_exchange_entry_count;
  GMutex service_exchange_checkpoint_lock;
  void (*service_exchange_entry_checkpoint) (gpointer data);
  gpointer service_exchange_entry_checkpoint_data;
  gboolean sink_metadata_initialization_pending;
};

guint64
wyl_audit_conn_service_exchange_get_entry_count_for_test (wyl_audit_conn_t
    *conn)
{
  return conn != NULL ? (guint64) g_atomic_int_get
      (&conn->service_exchange_entry_count) : 0;
}

void
wyl_audit_conn_service_exchange_reset_entry_count_for_test (wyl_audit_conn_t
    *conn)
{
  if (conn != NULL)
    g_atomic_int_set (&conn->service_exchange_entry_count, 0);
}

void wyl_audit_conn_service_exchange_set_entry_checkpoint_for_test
    (wyl_audit_conn_t * conn, void (*checkpoint) (gpointer data), gpointer data)
{
  if (conn == NULL)
    return;
  g_mutex_lock (&conn->service_exchange_checkpoint_lock);
  conn->service_exchange_entry_checkpoint = checkpoint;
  conn->service_exchange_entry_checkpoint_data = data;
  g_mutex_unlock (&conn->service_exchange_checkpoint_lock);
}

static gboolean
service_exchange_fail (wyl_audit_conn_t *conn,
    WylAuditServiceExchangeFailStage stage)
{
  if (conn->service_exchange_fail_stage != stage)
    return FALSE;
  conn->service_exchange_fail_stage = WYL_AUDIT_SERVICE_EXCHANGE_FAIL_NONE;
  return TRUE;
}

void
wyl_audit_conn_service_exchange_fail_once (wyl_audit_conn_t *conn,
    WylAuditServiceExchangeFailStage stage)
{
  if (conn == NULL)
    return;
  g_mutex_lock (&conn->lock);
  conn->service_exchange_fail_stage = stage;
  g_mutex_unlock (&conn->lock);
}

guint
    wyl_audit_conn_service_exchange_get_rollback_count_for_test
    (wyl_audit_conn_t * conn) {
  if (conn == NULL)
    return 0;
  g_mutex_lock (&conn->lock);
  guint count = conn->service_exchange_rollback_count;
  g_mutex_unlock (&conn->lock);
  return count;
}

static WylAuditChainTail *
audit_chain_tail_new (gint64 last_sequence_no, const gchar *last_record_hash)
{
  WylAuditChainTail *tail = g_new0 (WylAuditChainTail, 1);
  tail->last_sequence_no = last_sequence_no;
  tail->last_record_hash = g_strdup (last_record_hash != NULL ?
      last_record_hash : "");
  return tail;
}

static void
audit_chain_tail_free (WylAuditChainTail *tail)
{
  if (tail == NULL)
    return;
  g_free (tail->last_record_hash);
  g_free (tail);
}

gboolean
wyl_audit_conn_stream_name_is_reserved (const gchar *stream_name)
{
  return stream_name != NULL &&
      g_str_has_prefix (stream_name, WYL_AUDIT_RESERVED_PREFIX);
}

wyrelog_error_t
wyl_audit_conn_validate_user_stream_name (const gchar *stream_name)
{
  if (stream_name == NULL || stream_name[0] == '\0')
    return WYRELOG_E_INVALID;
  return wyl_audit_conn_stream_name_is_reserved (stream_name) ?
      WYRELOG_E_POLICY : WYRELOG_E_OK;
}

static wyrelog_error_t
table_exists_unlocked (wyl_audit_conn_t *conn, const gchar *table_name,
    gboolean *out_exists)
{
  duckdb_prepared_statement stmt;
  duckdb_result result;
  duckdb_state rc;

  if (conn == NULL || table_name == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  if (duckdb_bind_varchar (stmt, 1, table_name) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (rc != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  *out_exists = duckdb_value_int64 (&result, 0, 0) > 0;
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_audit_conn_open (const gchar *path, wyl_audit_conn_t **out_conn)
{
  if (out_conn == NULL)
    return WYRELOG_E_INVALID;

  /* DuckDB treats NULL as "open an in-memory database"; the
   * literal ":memory:" string maps to the same outcome but going
   * through NULL avoids a DuckDB-version-dependent string parse. */
  const gchar *effective_path = path;
  if (path != NULL && g_strcmp0 (path, ":memory:") == 0)
    effective_path = NULL;

  wyl_audit_conn_t *self = g_new0 (wyl_audit_conn_t, 1);
  if (duckdb_open (effective_path, &self->db) != DuckDBSuccess) {
    g_free (self);
    return WYRELOG_E_IO;
  }
  if (duckdb_connect (self->db, &self->conn) != DuckDBSuccess) {
    duckdb_close (&self->db);
    g_free (self);
    return WYRELOG_E_INTERNAL;
  }
  g_mutex_init (&self->lock);
  g_mutex_init (&self->service_exchange_checkpoint_lock);
  self->chain_tail_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) audit_chain_tail_free);
  self->persistent = effective_path != NULL && effective_path[0] != '\0';

  *out_conn = self;
  return WYRELOG_E_OK;
}

void
wyl_audit_conn_close (wyl_audit_conn_t *conn)
{
  if (conn == NULL)
    return;
  /* DuckDB requires disconnect before close, in that order; both
   * APIs zero their handle so re-entering this function on an
   * already-closed conn would still be safe, but the caller has
   * already free'd the wrapper at that point. */
  duckdb_disconnect (&conn->conn);
  duckdb_close (&conn->db);
  g_mutex_clear (&conn->lock);
  g_mutex_clear (&conn->service_exchange_checkpoint_lock);
  g_clear_pointer (&conn->chain_tail_cache, g_hash_table_destroy);
  g_free (conn);
}

duckdb_connection
wyl_audit_conn_get_connection (wyl_audit_conn_t *conn)
{
  if (conn == NULL) {
    duckdb_connection zero;
    memset (&zero, 0, sizeof (zero));
    return zero;
  }
  return conn->conn;
}

void
wyl_audit_conn_fail_insert_once (wyl_audit_conn_t *conn)
{
  if (conn == NULL)
    return;
  g_mutex_lock (&conn->lock);
  conn->fail_insert_once = TRUE;
  g_mutex_unlock (&conn->lock);
}

static wyrelog_error_t
bind_nullable_varchar (duckdb_prepared_statement stmt, idx_t index,
    const gchar *value)
{
  if (value == NULL)
    return duckdb_bind_null (stmt, index) == DuckDBSuccess ?
        WYRELOG_E_OK : WYRELOG_E_IO;
  return duckdb_bind_varchar (stmt, index, value) == DuckDBSuccess ?
      WYRELOG_E_OK : WYRELOG_E_IO;
}

static gboolean
result_nullable_varchar_equal (duckdb_result *result, idx_t col, idx_t row,
    const gchar *expected)
{
  if (duckdb_value_is_null (result, col, row))
    return expected == NULL;

  gchar *actual = duckdb_value_varchar (result, col, row);
  gboolean equal = g_strcmp0 (actual, expected) == 0;
  duckdb_free (actual);
  return equal;
}

static wyrelog_error_t
audit_event_matches_existing (wyl_audit_conn_t *conn, const gchar *id,
    gint64 created_at_us, const gchar *subject_id, const gchar *action,
    const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gboolean *out_exists)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result;
  memset (&result, 0, sizeof (result));

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision "
      "FROM audit_events WHERE id = ?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  duckdb_state step_rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (step_rc != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  idx_t rows = duckdb_row_count (&result);
  if (rows == 0) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_OK;
  }
  if (rows != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }

  *out_exists = TRUE;
  gboolean equal =
      duckdb_value_int64 (&result, 0, 0) == created_at_us
      && result_nullable_varchar_equal (&result, 1, 0, subject_id)
      && result_nullable_varchar_equal (&result, 2, 0, action)
      && result_nullable_varchar_equal (&result, 3, 0, resource_id)
      && result_nullable_varchar_equal (&result, 4, 0, deny_reason)
      && result_nullable_varchar_equal (&result, 5, 0, deny_origin)
      && result_nullable_varchar_equal (&result, 6, 0, request_id)
      && duckdb_value_int64 (&result, 7, 0) == decision;

  duckdb_destroy_result (&result);
  return equal ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
ensure_audit_events_request_id_column (wyl_audit_conn_t *conn)
{
  duckdb_result result = { 0 };
  /* DuckDB's information_schema.columns view can bind an internal
   * "system" catalog that is not resolvable on an open in-memory database,
   * surfacing as a Binder Error and breaking init for every caller that
   * runs the audit schema migration. pragma_table_info is the portable
   * column-existence probe in DuckDB and matches the SQLite migration in
   * wyl_policy_store_create_schema. */
  static const gchar *probe_sql =
      "SELECT COUNT(*) FROM pragma_table_info('audit_events') "
      "WHERE name = 'request_id';";

  if (duckdb_query (conn->conn, probe_sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gboolean exists = duckdb_value_int64 (&result, 0, 0) > 0;
  duckdb_destroy_result (&result);
  if (exists)
    return WYRELOG_E_OK;

  if (duckdb_query (conn->conn,
          "ALTER TABLE audit_events ADD COLUMN request_id VARCHAR;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
ensure_column (wyl_audit_conn_t *conn, const gchar *table_name,
    const gchar *column_name, const gchar *column_def)
{
  duckdb_result result = { 0 };
  g_autofree gchar *probe_sql =
      g_strdup_printf
      ("SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name = '%s';",
      table_name, column_name);

  if (duckdb_query (conn->conn, probe_sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gboolean exists = duckdb_value_int64 (&result, 0, 0) > 0;
  duckdb_destroy_result (&result);
  if (exists)
    return WYRELOG_E_OK;

  g_autofree gchar *alter_sql =
      g_strdup_printf ("ALTER TABLE %s ADD COLUMN %s %s;", table_name,
      column_name, column_def);
  if (duckdb_query (conn->conn, alter_sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_audit_conn_create_schema (wyl_audit_conn_t *conn)
{
  static const gchar *ddl =
      "CREATE TABLE IF NOT EXISTS audit_events ("
      "  id            VARCHAR PRIMARY KEY,"
      "  created_at_us BIGINT  NOT NULL,"
      "  subject_id    VARCHAR,"
      "  action        VARCHAR,"
      "  resource_id   VARCHAR,"
      "  deny_reason   VARCHAR,"
      "  deny_origin   VARCHAR,"
      "  request_id    VARCHAR,"
      "  decision      SMALLINT NOT NULL,"
      "  stream_name   VARCHAR NOT NULL DEFAULT '" WYL_AUDIT_STREAM_AUDIT "',"
      "  event_kind    VARCHAR NOT NULL DEFAULT 'audit.decision',"
      "  sequence_no   BIGINT,"
      "  previous_hash VARCHAR,"
      "  record_hash   VARCHAR,"
      "  checkpoint_root VARCHAR"
      ");"
      "CREATE TABLE IF NOT EXISTS audit_checkpoints ("
      "  stream_name VARCHAR NOT NULL,"
      "  sequence_no BIGINT NOT NULL,"
      "  root_hash   VARCHAR NOT NULL,"
      "  created_at_us BIGINT NOT NULL,"
      "  PRIMARY KEY (stream_name, sequence_no)"
      ");"
      "CREATE TABLE IF NOT EXISTS user_audit_streams ("
      "  name VARCHAR PRIMARY KEY,"
      "  created_at_us BIGINT NOT NULL"
      ");"
      "CREATE TABLE IF NOT EXISTS audit_sink_metadata ("
      "  logical_sink_name VARCHAR PRIMARY KEY,"
      "  sink_uuid VARCHAR NOT NULL UNIQUE,"
      "  schema_version INTEGER NOT NULL"
      ");"
      "CREATE TABLE IF NOT EXISTS service_exchange_receipt_projections ("
      "  sink_uuid VARCHAR NOT NULL,"
      "  intention_id VARCHAR NOT NULL,"
      "  payload_digest VARCHAR NOT NULL,"
      "  event_type VARCHAR NOT NULL,"
      "  outcome VARCHAR NOT NULL,"
      "  created_at_us BIGINT NOT NULL,"
      "  request_id VARCHAR NOT NULL,"
      "  credential_id VARCHAR NOT NULL,"
      "  credential_generation BLOB NOT NULL,"
      "  service_principal VARCHAR NOT NULL,"
      "  tenant_id VARCHAR NOT NULL,"
      "  payload_schema_version INTEGER NOT NULL,"
      "  fingerprint_schema_version INTEGER NOT NULL,"
      "  session_fingerprint VARCHAR NOT NULL,"
      "  jti_fingerprint VARCHAR NOT NULL,"
      "  canonical_payload BLOB NOT NULL,"
      "  PRIMARY KEY (sink_uuid, intention_id),"
      "  UNIQUE (sink_uuid, payload_digest),"
      "  CHECK (event_type = 'service.credential.exchange'),"
      "  CHECK (outcome = 'allowed'),"
      "  CHECK (payload_schema_version = 1),"
      "  CHECK (fingerprint_schema_version = 1),"
      "  CHECK (octet_length(credential_generation) = 8),"
      "  CHECK (octet_length(canonical_payload) BETWEEN 1 AND 4096)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_created_at_us "
      "  ON audit_events (created_at_us);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_stream_sequence "
      "  ON audit_events (stream_name, sequence_no);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_subject_id "
      "  ON audit_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_action "
      "  ON audit_events (action);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_decision "
      "  ON audit_events (decision);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_reason "
      "  ON audit_events (deny_reason);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_origin "
      "  ON audit_events (deny_origin);";

  if (conn == NULL)
    return WYRELOG_E_INVALID;

  gboolean had_audit_events = FALSE;
  wyrelog_error_t rc =
      table_exists_unlocked (conn, "audit_events", &had_audit_events);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean had_sink_metadata = FALSE;
  rc = table_exists_unlocked (conn, "audit_sink_metadata", &had_sink_metadata);
  if (rc != WYRELOG_E_OK)
    return rc;

  duckdb_result result;
  if (duckdb_query (conn->conn, ddl, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  rc = ensure_audit_events_request_id_column (conn);
  if (rc != WYRELOG_E_OK)
    return rc;
  const struct
  {
    const gchar *name;
    const gchar *def;
  } chain_columns[] = {
    {"stream_name", "VARCHAR"},
    {"event_kind", "VARCHAR"},
    {"sequence_no", "BIGINT"},
    {"previous_hash", "VARCHAR"},
    {"record_hash", "VARCHAR"},
    {"checkpoint_root", "VARCHAR"},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (chain_columns); i++) {
    rc = ensure_column (conn, "audit_events", chain_columns[i].name,
        chain_columns[i].def);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  if (duckdb_query (conn->conn,
          "CREATE INDEX IF NOT EXISTS idx_audit_events_request_id "
          "ON audit_events (request_id);", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);

  if (!had_sink_metadata)
    conn->sink_metadata_initialization_pending = TRUE;
  rc = ensure_service_exchange_schema (conn,
      conn->sink_metadata_initialization_pending);
  if (rc == WYRELOG_E_OK)
    conn->sink_metadata_initialization_pending = FALSE;
  if (rc != WYRELOG_E_OK)
    return rc;

  if (!had_audit_events) {
    if (duckdb_query (conn->conn, "DELETE FROM audit_checkpoints;", &result)
        != DuckDBSuccess) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_IO;
    }
    duckdb_destroy_result (&result);
  }

  return WYRELOG_E_OK;
}

static gchar *
compute_audit_record_hash (const gchar *stream_name, gint64 sequence_no,
    const gchar *previous_hash, const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, const gchar *event_kind)
{
  g_autofree gchar *payload =
      g_strdup_printf ("v1|%s|%" G_GINT64_FORMAT "|%s|%s|%" G_GINT64_FORMAT
      "|%s|%s|%s|%s|%s|%s|%d|%s",
      stream_name, sequence_no, previous_hash, id, created_at_us,
      subject_id != NULL ? subject_id : "", action != NULL ? action : "",
      resource_id != NULL ? resource_id : "",
      deny_reason != NULL ? deny_reason : "",
      deny_origin != NULL ? deny_origin : "",
      request_id != NULL ? request_id : "", (gint) decision, event_kind);
  return g_compute_checksum_for_string (G_CHECKSUM_SHA256, payload, -1);
}

static wyrelog_error_t
get_next_chain_state (wyl_audit_conn_t *conn, const gchar *stream_name,
    gint64 *out_sequence_no, gchar **out_previous_hash)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  *out_sequence_no = 1;
  *out_previous_hash = g_strdup ("");
  static const gchar *sql =
      "SELECT sequence_no, record_hash FROM audit_events "
      "WHERE stream_name = ? ORDER BY sequence_no DESC LIMIT 1;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, stream_name) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state step_rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (step_rc != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  if (duckdb_row_count (&result) == 1) {
    *out_sequence_no = duckdb_value_int64 (&result, 0, 0) + 1;
    g_free (*out_previous_hash);
    if (duckdb_value_is_null (&result, 1, 0)) {
      *out_previous_hash = g_strdup ("");
    } else {
      gchar *value = duckdb_value_varchar (&result, 1, 0);
      *out_previous_hash = g_strdup (value);
      duckdb_free (value);
    }
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
get_next_chain_state_cached (wyl_audit_conn_t *conn, const gchar *stream_name,
    gint64 *out_sequence_no, gchar **out_previous_hash)
{
  if (conn == NULL || stream_name == NULL || out_sequence_no == NULL ||
      out_previous_hash == NULL)
    return WYRELOG_E_INVALID;

  WylAuditChainTail *tail =
      g_hash_table_lookup (conn->chain_tail_cache, stream_name);
  if (tail == NULL) {
    gint64 sequence_no = 0;
    g_autofree gchar *previous_hash = NULL;
    wyrelog_error_t rc = get_next_chain_state (conn, stream_name,
        &sequence_no, &previous_hash);
    if (rc != WYRELOG_E_OK)
      return rc;

    tail = audit_chain_tail_new (sequence_no - 1, previous_hash);
    g_hash_table_insert (conn->chain_tail_cache, g_strdup (stream_name), tail);
  }

  *out_sequence_no = tail->last_sequence_no + 1;
  *out_previous_hash = g_strdup (tail->last_record_hash);
  return WYRELOG_E_OK;
}

static void
evict_chain_tail_cache (wyl_audit_conn_t *conn, const gchar *stream_name)
{
  if (conn == NULL || stream_name == NULL)
    return;
  g_hash_table_remove (conn->chain_tail_cache, stream_name);
}

static void
update_chain_tail_cache (wyl_audit_conn_t *conn, const gchar *stream_name,
    gint64 sequence_no, const gchar *record_hash)
{
  if (conn == NULL || stream_name == NULL || record_hash == NULL)
    return;
  g_hash_table_replace (conn->chain_tail_cache, g_strdup (stream_name),
      audit_chain_tail_new (sequence_no, record_hash));
}

static wyrelog_error_t
query_ok (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result = { 0 };
  duckdb_state state = duckdb_query (conn, sql, &result);
  duckdb_destroy_result (&result);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
rollback_transaction_unlocked (wyl_audit_conn_t *conn)
{
  conn->service_exchange_rollback_count++;
  return query_ok (conn->conn, "ROLLBACK;");
}

static wyrelog_error_t
commit_transaction_unlocked (wyl_audit_conn_t *conn)
{
  if (service_exchange_fail (conn,
          WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_QUERY)) {
    /* Exercise DuckDB's query execution boundary with a syntactically invalid
     * COMMIT. DuckDB returns failure and leaves the active transaction valid
     * for the exactly-once rollback below. */
    duckdb_result result = { 0 };
    duckdb_state state = duckdb_query (conn->conn,
        "COMMIT __wyrelog_injected_failure__;", &result);
    duckdb_destroy_result (&result);
    return state == DuckDBSuccess ? WYRELOG_E_INTERNAL : WYRELOG_E_IO;
  }
  return query_ok (conn->conn, "COMMIT;");
}

static gboolean
canonical_uuidv7 (const gchar *value)
{
  wyl_id_t id;
  gchar formatted[WYL_ID_STRING_BUF];
  return value != NULL && strlen (value) == WYL_ID_STRING_LEN
      && value[14] == '7' && strchr ("89ab", value[19]) != NULL
      && wyl_id_parse (value, &id) == WYRELOG_E_OK
      && wyl_id_format (&id, formatted, sizeof formatted) == WYRELOG_E_OK
      && strcmp (value, formatted) == 0;
}

static gboolean
canonical_hash64 (const gchar *value)
{
  if (value == NULL || strlen (value) != 64)
    return FALSE;
  for (guint i = 0; i < 64; i++)
    if (!g_ascii_isdigit (value[i])
        && (value[i] < 'a' || value[i] > 'f'))
      return FALSE;
  return TRUE;
}

static wyrelog_error_t
validate_table_columns (wyl_audit_conn_t *conn, const gchar *table,
    const gchar *const *names, const gchar *const *types,
    const gboolean *primary_key, gsize n_columns)
{
  duckdb_result result = { 0 };
  g_autofree gchar *sql = g_strdup_printf
      ("SELECT name,type,\"notnull\",dflt_value,pk "
      "FROM pragma_table_info('%s') " "ORDER BY cid;", table);
  if (duckdb_query (conn->conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != n_columns) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  for (idx_t row = 0; row < n_columns; row++) {
    gchar *name = duckdb_value_varchar (&result, 0, row);
    gchar *type = duckdb_value_varchar (&result, 1, row);
    gboolean equal = strcmp (name, names[row]) == 0
        && strcmp (type, types[row]) == 0
        && duckdb_value_boolean (&result, 2, row)
        && duckdb_value_is_null (&result, 3, row)
        && duckdb_value_boolean (&result, 4, row) == primary_key[row];
    duckdb_free (name);
    duckdb_free (type);
    if (!equal) {
      duckdb_destroy_result (&result);
      return WYRELOG_E_POLICY;
    }
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
require_constraint (wyl_audit_conn_t *conn, const gchar *table,
    const gchar *type, const gchar *columns)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT COUNT(*) FROM duckdb_constraints() WHERE table_name=? "
      "AND constraint_type=? AND constraint_column_names::VARCHAR=?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, table) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, type) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 3, columns) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (state != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gboolean exact = duckdb_value_int64 (&result, 0, 0) == 1;
  duckdb_destroy_result (&result);
  return exact ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
require_constraint_count (wyl_audit_conn_t *conn, const gchar *table,
    const gchar *type, gint64 expected)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT COUNT(*) FROM duckdb_constraints() WHERE table_name=? "
      "AND constraint_type=?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, table) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, type) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (state != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gboolean exact = duckdb_value_int64 (&result, 0, 0) == expected;
  duckdb_destroy_result (&result);
  return exact ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
require_total_constraint_count (wyl_audit_conn_t *conn, const gchar *table,
    gint64 expected)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT COUNT(*) FROM duckdb_constraints() WHERE table_name=?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, table) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (state != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gboolean exact = duckdb_value_int64 (&result, 0, 0) == expected;
  duckdb_destroy_result (&result);
  return exact ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
require_no_extra_indexes (wyl_audit_conn_t *conn, const gchar *table)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT COUNT(*) FROM duckdb_indexes() WHERE table_name=?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, table) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (state != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  gboolean exact = duckdb_value_int64 (&result, 0, 0) == 0;
  duckdb_destroy_result (&result);
  return exact ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
ensure_service_exchange_schema (wyl_audit_conn_t *conn,
    gboolean allow_create_metadata)
{
  static const gchar *metadata_names[] = {
    "logical_sink_name", "sink_uuid", "schema_version"
  };
  static const gchar *metadata_types[] = { "VARCHAR", "VARCHAR", "INTEGER" };
  static const gboolean metadata_pk[] = { TRUE, FALSE, FALSE };
  static const gchar *projection_names[] = {
    "sink_uuid", "intention_id", "payload_digest", "event_type", "outcome",
    "created_at_us", "request_id", "credential_id", "credential_generation",
    "service_principal", "tenant_id", "payload_schema_version",
    "fingerprint_schema_version", "session_fingerprint", "jti_fingerprint",
    "canonical_payload"
  };
  static const gchar *projection_types[] = {
    "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "BIGINT",
    "VARCHAR", "VARCHAR", "BLOB", "VARCHAR", "VARCHAR", "INTEGER",
    "INTEGER", "VARCHAR", "VARCHAR", "BLOB"
  };
  static const gboolean projection_pk[] = {
    TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE
  };
  wyrelog_error_t rc = validate_table_columns (conn, "audit_sink_metadata",
      metadata_names, metadata_types, metadata_pk,
      G_N_ELEMENTS (metadata_names));
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = validate_table_columns (conn, "service_exchange_receipt_projections",
      projection_names, projection_types, projection_pk,
      G_N_ELEMENTS (projection_names));
  if (rc == WYRELOG_E_OK)
    rc = require_constraint (conn, "audit_sink_metadata", "PRIMARY KEY",
        "[logical_sink_name]");
  if (rc == WYRELOG_E_OK)
    rc = require_constraint (conn, "audit_sink_metadata", "UNIQUE",
        "[sink_uuid]");
  if (rc == WYRELOG_E_OK)
    rc = require_constraint (conn, "service_exchange_receipt_projections",
        "PRIMARY KEY", "[sink_uuid, intention_id]");
  if (rc == WYRELOG_E_OK)
    rc = require_constraint (conn, "service_exchange_receipt_projections",
        "UNIQUE", "[sink_uuid, payload_digest]");
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn, "audit_sink_metadata", "PRIMARY KEY",
        1);
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn, "audit_sink_metadata", "UNIQUE", 1);
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn, "audit_sink_metadata", "NOT NULL", 3);
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn, "audit_sink_metadata", "CHECK", 0);
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn,
        "service_exchange_receipt_projections", "PRIMARY KEY", 1);
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn,
        "service_exchange_receipt_projections", "UNIQUE", 1);
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn,
        "service_exchange_receipt_projections", "NOT NULL", 16);
  if (rc == WYRELOG_E_OK)
    rc = require_constraint_count (conn,
        "service_exchange_receipt_projections", "CHECK", 6);
  if (rc == WYRELOG_E_OK) {
    duckdb_result constraints = { 0 };
    static const gchar *constraint_sql =
        "SELECT COUNT(*) FROM duckdb_constraints() WHERE table_name="
        "'service_exchange_receipt_projections' AND constraint_type='CHECK' "
        "AND constraint_text IN ("
        "'CHECK((event_type = ''service.credential.exchange''))',"
        "'CHECK((outcome = ''allowed''))',"
        "'CHECK((payload_schema_version = 1))',"
        "'CHECK((fingerprint_schema_version = 1))',"
        "'CHECK((octet_length(credential_generation) = 8))',"
        "'CHECK((octet_length(canonical_payload) BETWEEN 1 AND 4096))');";
    if (duckdb_query (conn->conn, constraint_sql, &constraints)
        != DuckDBSuccess)
      rc = WYRELOG_E_IO;
    else if (duckdb_value_int64 (&constraints, 0, 0) != 6)
      rc = WYRELOG_E_POLICY;
    duckdb_destroy_result (&constraints);
  }
  if (rc == WYRELOG_E_OK)
    rc = require_total_constraint_count (conn, "audit_sink_metadata", 5);
  if (rc == WYRELOG_E_OK)
    rc = require_total_constraint_count (conn,
        "service_exchange_receipt_projections", 24);
  if (rc == WYRELOG_E_OK)
    rc = require_no_extra_indexes (conn, "audit_sink_metadata");
  if (rc == WYRELOG_E_OK)
    rc = require_no_extra_indexes (conn,
        "service_exchange_receipt_projections");
  if (rc != WYRELOG_E_OK || !conn->persistent)
    return rc;

  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *select_sql =
      "SELECT sink_uuid, schema_version FROM audit_sink_metadata "
      "WHERE logical_sink_name = ?;";
  if (duckdb_prepare (conn->conn, select_sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, WYL_AUDIT_SERVICE_EXCHANGE_STREAM)
      != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (state != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  idx_t rows = duckdb_row_count (&result);
  if (rows == 1) {
    gchar *uuid = duckdb_value_varchar (&result, 0, 0);
    gboolean valid = canonical_uuidv7 (uuid)
        && duckdb_value_int64 (&result, 1, 0) == 1;
    duckdb_free (uuid);
    duckdb_destroy_result (&result);
    return valid ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  }
  duckdb_destroy_result (&result);
  if (rows != 0)
    return WYRELOG_E_POLICY;
  if (!allow_create_metadata)
    return WYRELOG_E_POLICY;

  wyl_id_t id;
  gchar uuid[WYL_ID_STRING_BUF];
  if (wyl_id_new (&id) != WYRELOG_E_OK
      || wyl_id_format (&id, uuid, sizeof uuid) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  if (query_ok (conn->conn, "BEGIN TRANSACTION;") != WYRELOG_E_OK)
    return WYRELOG_E_IO;
  gboolean metadata_transaction_active = TRUE;
  static const gchar *insert_sql =
      "INSERT INTO audit_sink_metadata VALUES (?, ?, 1);";
  if (duckdb_prepare (conn->conn, insert_sql, &stmt) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 1, WYL_AUDIT_SERVICE_EXCHANGE_STREAM)
      != DuckDBSuccess || duckdb_bind_varchar (stmt, 2, uuid) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    rollback_transaction_unlocked (conn);
    return WYRELOG_E_IO;
  }
  state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  wyrelog_error_t metadata_rc = state == DuckDBSuccess ? WYRELOG_E_OK :
      WYRELOG_E_IO;
  if (metadata_rc == WYRELOG_E_OK && service_exchange_fail (conn,
          WYL_AUDIT_SERVICE_EXCHANGE_FAIL_METADATA_IN_TXN_READBACK))
    metadata_rc = WYRELOG_E_IO;
  if (metadata_rc == WYRELOG_E_OK) {
    static const gchar *readback_sql =
        "SELECT logical_sink_name,sink_uuid,schema_version "
        "FROM audit_sink_metadata;";
    memset (&result, 0, sizeof result);
    if (duckdb_query (conn->conn, readback_sql, &result) != DuckDBSuccess) {
      metadata_rc = WYRELOG_E_IO;
    } else if (duckdb_row_count (&result) != 1
        || duckdb_value_is_null (&result, 0, 0)
        || duckdb_value_is_null (&result, 1, 0)
        || duckdb_value_is_null (&result, 2, 0)) {
      metadata_rc = WYRELOG_E_POLICY;
    } else {
      gchar *logical_name = duckdb_value_varchar (&result, 0, 0);
      gchar *stored_uuid = duckdb_value_varchar (&result, 1, 0);
      gboolean exact = logical_name != NULL && stored_uuid != NULL
          && strcmp (logical_name, WYL_AUDIT_SERVICE_EXCHANGE_STREAM) == 0
          && strcmp (stored_uuid, uuid) == 0 && canonical_uuidv7 (stored_uuid)
          && duckdb_value_int64 (&result, 2, 0) == 1;
      duckdb_free (logical_name);
      duckdb_free (stored_uuid);
      if (!exact)
        metadata_rc = WYRELOG_E_POLICY;
    }
    duckdb_destroy_result (&result);
  }
  if (metadata_rc == WYRELOG_E_OK) {
    metadata_rc = query_ok (conn->conn, "COMMIT;");
    if (metadata_rc == WYRELOG_E_OK)
      metadata_transaction_active = FALSE;
  }
  if (metadata_rc != WYRELOG_E_OK && metadata_transaction_active) {
    wyrelog_error_t rollback_rc = rollback_transaction_unlocked (conn);
    metadata_transaction_active = FALSE;
    if (rollback_rc != WYRELOG_E_OK)
      return WYRELOG_E_IO;
  }
  return metadata_rc;
}

wyrelog_error_t
wyl_audit_conn_table_exists (wyl_audit_conn_t *conn, const gchar *table_name,
    gboolean *out_exists)
{
  return table_exists_unlocked (conn, table_name, out_exists);
}

static wyrelog_error_t
insert_event_full_unlocked (wyl_audit_conn_t *conn, const gchar *id,
    gint64 created_at_us, const gchar *subject_id, const gchar *action,
    const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gboolean *out_inserted)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result;
  duckdb_state step_rc;
  wyl_id_t parsed_id;
  gboolean exists = FALSE;

  memset (&result, 0, sizeof (result));

  if (conn == NULL || id == NULL || created_at_us < 0 || out_inserted == NULL)
    return WYRELOG_E_INVALID;
  if (conn->fail_insert_once) {
    conn->fail_insert_once = FALSE;
    return WYRELOG_E_IO;
  }
  *out_inserted = FALSE;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  if (decision != WYL_DECISION_DENY && decision != WYL_DECISION_ALLOW)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = audit_event_matches_existing (conn, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, request_id,
      decision, &exists);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (exists)
    return WYRELOG_E_OK;

  g_autofree gchar *previous_hash = NULL;
  gint64 sequence_no = 0;
  rc = get_next_chain_state_cached (conn, WYL_AUDIT_STREAM_AUDIT,
      &sequence_no, &previous_hash);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *record_hash =
      compute_audit_record_hash (WYL_AUDIT_STREAM_AUDIT, sequence_no,
      previous_hash, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, request_id,
      decision, "audit.decision");

  static const gchar *sql =
      "INSERT INTO audit_events "
      "(id, created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision, stream_name, "
      "event_kind, sequence_no, previous_hash, record_hash, checkpoint_root) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  if (duckdb_bind_varchar (stmt, 1, id) != DuckDBSuccess
      || duckdb_bind_int64 (stmt, 2, created_at_us) != DuckDBSuccess
      || bind_nullable_varchar (stmt, 3, subject_id) != WYRELOG_E_OK
      || bind_nullable_varchar (stmt, 4, action) != WYRELOG_E_OK
      || bind_nullable_varchar (stmt, 5, resource_id) != WYRELOG_E_OK
      || bind_nullable_varchar (stmt, 6, deny_reason) != WYRELOG_E_OK
      || bind_nullable_varchar (stmt, 7, deny_origin) != WYRELOG_E_OK
      || bind_nullable_varchar (stmt, 8, request_id) != WYRELOG_E_OK
      || duckdb_bind_int16 (stmt, 9, (int16_t) decision) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 10, WYL_AUDIT_STREAM_AUDIT)
      != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 11, "audit.decision") != DuckDBSuccess
      || duckdb_bind_int64 (stmt, 12, sequence_no) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 13, previous_hash) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 14, record_hash) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 15, record_hash) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  step_rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  if (step_rc != DuckDBSuccess) {
    evict_chain_tail_cache (conn, WYL_AUDIT_STREAM_AUDIT);
    return WYRELOG_E_IO;
  }

  if (sequence_no % WYL_AUDIT_CHECKPOINT_INTERVAL == 0) {
    static const gchar *checkpoint_sql =
        "INSERT INTO audit_checkpoints "
        "(stream_name, sequence_no, root_hash, created_at_us) "
        "VALUES (?, ?, ?, ?);";
    if (duckdb_prepare (conn->conn, checkpoint_sql, &stmt) != DuckDBSuccess)
      return WYRELOG_E_IO;
    if (duckdb_bind_varchar (stmt, 1, WYL_AUDIT_STREAM_AUDIT)
        != DuckDBSuccess
        || duckdb_bind_int64 (stmt, 2, sequence_no) != DuckDBSuccess
        || duckdb_bind_varchar (stmt, 3, record_hash) != DuckDBSuccess
        || duckdb_bind_int64 (stmt, 4, g_get_real_time ()) != DuckDBSuccess) {
      duckdb_destroy_prepare (&stmt);
      return WYRELOG_E_IO;
    }
    step_rc = duckdb_execute_prepared (stmt, &result);
    duckdb_destroy_result (&result);
    duckdb_destroy_prepare (&stmt);
    if (step_rc != DuckDBSuccess) {
      evict_chain_tail_cache (conn, WYL_AUDIT_STREAM_AUDIT);
      return WYRELOG_E_POLICY;
    }
  }

  update_chain_tail_cache (conn, WYL_AUDIT_STREAM_AUDIT, sequence_no,
      record_hash);
  *out_inserted = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_audit_conn_insert_event_full (wyl_audit_conn_t *conn, const gchar *id,
    gint64 created_at_us, const gchar *subject_id, const gchar *action,
    const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gboolean *out_inserted)
{
  if (conn == NULL)
    return WYRELOG_E_INVALID;

  g_mutex_lock (&conn->lock);
  wyrelog_error_t rc = insert_event_full_unlocked (conn, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, request_id,
      decision, out_inserted);
  g_mutex_unlock (&conn->lock);
  return rc;
}

wyrelog_error_t
wyl_audit_conn_insert_event (wyl_audit_conn_t *conn, const gchar *id,
    gint64 created_at_us, const gchar *subject_id, const gchar *action,
    const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, wyl_decision_t decision)
{
  gboolean inserted = FALSE;

  return wyl_audit_conn_insert_event_full (conn, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, NULL, decision,
      &inserted);
}

static gboolean
projection_input_valid (const WylAuditServiceExchangeProjection *p)
{
  return wyl_service_exchange_audit_projection_validate (p)
      == WYRELOG_E_OK;
}

static void
generation_to_be (guint64 value, guint8 out[8])
{
  for (guint i = 0; i < 8; i++)
    out[i] = (guint8) (value >> (56 - i * 8));
}

static gboolean
result_text_equal (duckdb_result *result, idx_t col, idx_t row,
    const gchar *expected)
{
  gchar *actual = duckdb_value_varchar (result, col, row);
  gboolean equal = actual != NULL && strcmp (actual, expected) == 0;
  duckdb_free (actual);
  return equal;
}

static gboolean
projection_row_matches (duckdb_result *result, idx_t row,
    const WylAuditServiceExchangeProjection *p)
{
  guint8 generation[8];
  generation_to_be (p->credential_generation, generation);
  duckdb_blob stored_generation = duckdb_value_blob (result, 8, row);
  duckdb_blob stored_payload = duckdb_value_blob (result, 15, row);
  gsize payload_len = 0;
  const guint8 *payload = g_bytes_get_data (p->canonical_payload, &payload_len);
  gboolean equal = result_text_equal (result, 1, row, p->intention_id)
      && result_text_equal (result, 2, row, p->payload_digest)
      && result_text_equal (result, 3, row, WYL_SERVICE_EXCHANGE_EVENT_KIND)
      && result_text_equal (result, 4, row, "allowed")
      && duckdb_value_int64 (result, 5, row) == p->created_at_us
      && result_text_equal (result, 6, row, p->request_id)
      && result_text_equal (result, 7, row, p->credential_id)
      && stored_generation.size == 8
      && memcmp (stored_generation.data, generation, 8) == 0
      && result_text_equal (result, 9, row, p->service_principal)
      && result_text_equal (result, 10, row, p->tenant_id)
      && duckdb_value_int64 (result, 11, row) == p->payload_schema_version
      && duckdb_value_int64 (result, 12, row) ==
      p->fingerprint_schema_version
      && result_text_equal (result, 13, row, p->session_fingerprint)
      && result_text_equal (result, 14, row, p->jti_fingerprint)
      && stored_payload.size == payload_len
      && memcmp (stored_payload.data, payload, payload_len) == 0;
  duckdb_free (stored_generation.data);
  duckdb_free (stored_payload.data);
  memset (generation, 0, sizeof generation);
  return equal;
}

static wyrelog_error_t
load_sink_uuid_unlocked (wyl_audit_conn_t *conn, gchar out[WYL_ID_STRING_BUF])
{
  duckdb_result result = { 0 };
  static const gchar *sql =
      "SELECT sink_uuid, schema_version FROM audit_sink_metadata WHERE "
      "logical_sink_name = '" WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';";
  if (duckdb_query (conn->conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != 1
      || duckdb_value_int64 (&result, 1, 0) != 1) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  gchar *uuid = duckdb_value_varchar (&result, 0, 0);
  gboolean valid = canonical_uuidv7 (uuid);
  if (valid)
    memcpy (out, uuid, WYL_ID_STRING_BUF);
  duckdb_free (uuid);
  duckdb_destroy_result (&result);
  return valid ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_audit_conn_service_exchange_get_sink_identity (wyl_audit_conn_t *conn,
    gchar out_logical_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM],
    gchar out_sink_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF])
{
  if (out_logical_name != NULL)
    memset (out_logical_name, 0, sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM);
  if (out_sink_uuid != NULL)
    memset (out_sink_uuid, 0, WYL_SERVICE_EXCHANGE_UUID_BUF);
  if (conn == NULL || out_logical_name == NULL || out_sink_uuid == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&conn->lock);
  wyrelog_error_t rc = ensure_service_exchange_schema (conn, FALSE);
  if (rc == WYRELOG_E_OK)
    rc = load_sink_uuid_unlocked (conn, out_sink_uuid);
  if (rc == WYRELOG_E_OK)
    memcpy (out_logical_name, WYL_AUDIT_SERVICE_EXCHANGE_STREAM,
        sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM);
  g_mutex_unlock (&conn->lock);
  return rc;
}

static wyrelog_error_t
load_projection_candidates (wyl_audit_conn_t *conn, const gchar *sink_uuid,
    const WylAuditServiceExchangeProjection *p, duckdb_result *out)
{
  duckdb_prepared_statement stmt = NULL;
  static const gchar *sql =
      "SELECT sink_uuid,intention_id,payload_digest,event_type,outcome,"
      "created_at_us,request_id,credential_id,credential_generation,"
      "service_principal,tenant_id,payload_schema_version,"
      "fingerprint_schema_version,session_fingerprint,jti_fingerprint,"
      "canonical_payload FROM service_exchange_receipt_projections "
      "WHERE sink_uuid=? AND (intention_id=? OR payload_digest=?);";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, sink_uuid) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, p->intention_id) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 3, p->payload_digest) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, out);
  duckdb_destroy_prepare (&stmt);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
load_anchor (wyl_audit_conn_t *conn,
    const WylAuditServiceExchangeProjection *p, duckdb_result *out)
{
  duckdb_prepared_statement stmt = NULL;
  static const gchar *sql =
      "SELECT created_at_us,subject_id,action,resource_id,deny_reason,"
      "deny_origin,request_id,decision,sequence_no,previous_hash,record_hash,"
      "checkpoint_root,event_kind FROM audit_events WHERE stream_name='"
      WYL_AUDIT_SERVICE_EXCHANGE_STREAM "' AND id=?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, p->intention_id) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, out);
  duckdb_destroy_prepare (&stmt);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
load_projection_checkpoint (wyl_audit_conn_t *conn, gint64 sequence_no,
    duckdb_result *out)
{
  duckdb_prepared_statement stmt = NULL;
  static const gchar *sql =
      "SELECT stream_name,sequence_no,root_hash,created_at_us "
      "FROM audit_checkpoints WHERE stream_name=? AND sequence_no=?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, WYL_AUDIT_SERVICE_EXCHANGE_STREAM)
      != DuckDBSuccess
      || duckdb_bind_int64 (stmt, 2, sequence_no) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, out);
  duckdb_destroy_prepare (&stmt);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static gboolean
checkpoint_matches (duckdb_result *result, gint64 sequence_no,
    const gchar *record_hash, gint64 created_at_us)
{
  if (result == NULL || sequence_no <= 0 || !canonical_hash64 (record_hash)
      || duckdb_row_count (result) != 1)
    return FALSE;
  for (idx_t col = 0; col < 4; col++)
    if (duckdb_value_is_null (result, col, 0))
      return FALSE;
  return result_text_equal (result, 0, 0, WYL_AUDIT_SERVICE_EXCHANGE_STREAM)
      && duckdb_value_int64 (result, 1, 0) == sequence_no
      && result_text_equal (result, 2, 0, record_hash)
      && duckdb_value_int64 (result, 3, 0) == created_at_us;
}

static gboolean
anchor_matches (duckdb_result *result,
    const WylAuditServiceExchangeProjection *p)
{
  if (duckdb_row_count (result) != 1)
    return FALSE;
  for (idx_t col = 0; col < 13; col++)
    if (duckdb_value_is_null (result, col, 0))
      return FALSE;
  gint64 sequence = duckdb_value_int64 (result, 8, 0);
  gchar *previous = duckdb_value_varchar (result, 9, 0);
  gchar *stored_hash = duckdb_value_varchar (result, 10, 0);
  if (previous == NULL || stored_hash == NULL || !canonical_hash64 (stored_hash)
      || (sequence == 1 ? previous[0] != '\0' : !canonical_hash64 (previous))) {
    duckdb_free (previous);
    duckdb_free (stored_hash);
    return FALSE;
  }
  g_autofree gchar *expected_hash = compute_audit_record_hash
      (WYL_AUDIT_SERVICE_EXCHANGE_STREAM, sequence, previous, p->intention_id,
      p->created_at_us, p->service_principal, WYL_SERVICE_EXCHANGE_EVENT_KIND,
      p->credential_id, p->payload_digest, p->tenant_id, p->request_id,
      WYL_DECISION_ALLOW, WYL_SERVICE_EXCHANGE_EVENT_KIND);
  gboolean equal = sequence > 0
      && duckdb_value_int64 (result, 0, 0) == p->created_at_us
      && result_text_equal (result, 1, 0, p->service_principal)
      && result_text_equal (result, 2, 0, WYL_SERVICE_EXCHANGE_EVENT_KIND)
      && result_text_equal (result, 3, 0, p->credential_id)
      && result_text_equal (result, 4, 0, p->payload_digest)
      && result_text_equal (result, 5, 0, p->tenant_id)
      && result_text_equal (result, 6, 0, p->request_id)
      && duckdb_value_int64 (result, 7, 0) == WYL_DECISION_ALLOW
      && strcmp (stored_hash, expected_hash) == 0
      && result_text_equal (result, 11, 0, stored_hash)
      && result_text_equal (result, 12, 0, WYL_SERVICE_EXCHANGE_EVENT_KIND);
  duckdb_free (previous);
  duckdb_free (stored_hash);
  return equal;
}

static wyrelog_error_t
insert_projection_unlocked (wyl_audit_conn_t *conn, const gchar *sink_uuid,
    const WylAuditServiceExchangeProjection *p)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  guint8 generation[8];
  generation_to_be (p->credential_generation, generation);
  gsize payload_len = 0;
  const guint8 *payload = g_bytes_get_data (p->canonical_payload, &payload_len);
  static const gchar *sql =
      "INSERT INTO service_exchange_receipt_projections VALUES "
      "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
#define BIND_OK(expr) ((expr) == DuckDBSuccess)
  gboolean bound = BIND_OK (duckdb_bind_varchar (stmt, 1, sink_uuid))
      && BIND_OK (duckdb_bind_varchar (stmt, 2, p->intention_id))
      && BIND_OK (duckdb_bind_varchar (stmt, 3, p->payload_digest))
      && BIND_OK (duckdb_bind_varchar (stmt, 4,
          WYL_SERVICE_EXCHANGE_EVENT_KIND))
      && BIND_OK (duckdb_bind_varchar (stmt, 5, "allowed"))
      && BIND_OK (duckdb_bind_int64 (stmt, 6, p->created_at_us))
      && BIND_OK (duckdb_bind_varchar (stmt, 7, p->request_id))
      && BIND_OK (duckdb_bind_varchar (stmt, 8, p->credential_id))
      && BIND_OK (duckdb_bind_blob (stmt, 9, generation, sizeof generation))
      && BIND_OK (duckdb_bind_varchar (stmt, 10, p->service_principal))
      && BIND_OK (duckdb_bind_varchar (stmt, 11, p->tenant_id))
      && BIND_OK (duckdb_bind_int32 (stmt, 12,
          (gint32) p->payload_schema_version))
      && BIND_OK (duckdb_bind_int32 (stmt, 13,
          (gint32) p->fingerprint_schema_version))
      && BIND_OK (duckdb_bind_varchar (stmt, 14, p->session_fingerprint))
      && BIND_OK (duckdb_bind_varchar (stmt, 15, p->jti_fingerprint))
      && BIND_OK (duckdb_bind_blob (stmt, 16, payload, payload_len));
#undef BIND_OK
  memset (generation, 0, sizeof generation);
  if (!bound) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  return state == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
insert_projection_anchor_unlocked (wyl_audit_conn_t *conn,
    const WylAuditServiceExchangeProjection *p, gint64 *out_sequence,
    gchar **out_hash)
{
  gint64 sequence = 0;
  g_autofree gchar *previous = NULL;
  wyrelog_error_t rc = get_next_chain_state_cached (conn,
      WYL_AUDIT_SERVICE_EXCHANGE_STREAM, &sequence, &previous);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *record_hash = compute_audit_record_hash
      (WYL_AUDIT_SERVICE_EXCHANGE_STREAM, sequence, previous, p->intention_id,
      p->created_at_us, p->service_principal, WYL_SERVICE_EXCHANGE_EVENT_KIND,
      p->credential_id, p->payload_digest, p->tenant_id, p->request_id,
      WYL_DECISION_ALLOW, WYL_SERVICE_EXCHANGE_EVENT_KIND);
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  static const gchar *sql =
      "INSERT INTO audit_events (id,created_at_us,subject_id,action,resource_id,"
      "deny_reason,deny_origin,request_id,decision,stream_name,event_kind,"
      "sequence_no,previous_hash,record_hash,checkpoint_root) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
#define BIND_OK(expr) ((expr) == DuckDBSuccess)
  gboolean bound = BIND_OK (duckdb_bind_varchar (stmt, 1, p->intention_id))
      && BIND_OK (duckdb_bind_int64 (stmt, 2, p->created_at_us))
      && BIND_OK (duckdb_bind_varchar (stmt, 3, p->service_principal))
      && BIND_OK (duckdb_bind_varchar (stmt, 4,
          WYL_SERVICE_EXCHANGE_EVENT_KIND))
      && BIND_OK (duckdb_bind_varchar (stmt, 5, p->credential_id))
      && BIND_OK (duckdb_bind_varchar (stmt, 6, p->payload_digest))
      && BIND_OK (duckdb_bind_varchar (stmt, 7, p->tenant_id))
      && BIND_OK (duckdb_bind_varchar (stmt, 8, p->request_id))
      && BIND_OK (duckdb_bind_int16 (stmt, 9, WYL_DECISION_ALLOW))
      && BIND_OK (duckdb_bind_varchar (stmt, 10,
          WYL_AUDIT_SERVICE_EXCHANGE_STREAM))
      && BIND_OK (duckdb_bind_varchar (stmt, 11,
          WYL_SERVICE_EXCHANGE_EVENT_KIND))
      && BIND_OK (duckdb_bind_int64 (stmt, 12, sequence))
      && BIND_OK (duckdb_bind_varchar (stmt, 13, previous))
      && BIND_OK (duckdb_bind_varchar (stmt, 14, record_hash))
      && BIND_OK (duckdb_bind_varchar (stmt, 15, record_hash));
#undef BIND_OK
  if (!bound) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  if (state != DuckDBSuccess)
    return WYRELOG_E_POLICY;

  static const gchar *checkpoint_sql =
      "INSERT INTO audit_checkpoints VALUES (?,?,?,?);";
  if (duckdb_prepare (conn->conn, checkpoint_sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  bound = duckdb_bind_varchar (stmt, 1,
      WYL_AUDIT_SERVICE_EXCHANGE_STREAM) == DuckDBSuccess
      && duckdb_bind_int64 (stmt, 2, sequence) == DuckDBSuccess
      && duckdb_bind_varchar (stmt, 3, record_hash) == DuckDBSuccess
      && duckdb_bind_int64 (stmt, 4, p->created_at_us) == DuckDBSuccess;
  if (!bound) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  state = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  if (state != DuckDBSuccess)
    return WYRELOG_E_POLICY;
  *out_sequence = sequence;
  *out_hash = g_strdup (record_hash);
  return *out_hash != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

wyrelog_error_t
wyl_audit_conn_service_exchange_project (wyl_audit_conn_t *conn,
    const WylAuditServiceExchangeProjection *p,
    WylAuditServiceExchangeProjectionReadback *out)
{
  if (out != NULL)
    memset (out, 0, sizeof *out);
  if (conn == NULL || out == NULL || !projection_input_valid (p))
    return WYRELOG_E_INVALID;
  if (!conn->persistent)
    return WYRELOG_E_POLICY;
  g_atomic_int_inc (&conn->service_exchange_entry_count);

  g_mutex_lock (&conn->service_exchange_checkpoint_lock);
  void (*entry_checkpoint) (gpointer data) =
      conn->service_exchange_entry_checkpoint;
  gpointer checkpoint_data = conn->service_exchange_entry_checkpoint_data;
  conn->service_exchange_entry_checkpoint = NULL;
  conn->service_exchange_entry_checkpoint_data = NULL;
  g_mutex_unlock (&conn->service_exchange_checkpoint_lock);
  if (entry_checkpoint != NULL)
    entry_checkpoint (checkpoint_data);

  g_mutex_lock (&conn->lock);
  wyrelog_error_t rc = ensure_service_exchange_schema (conn, FALSE);
  gchar sink_uuid[WYL_ID_STRING_BUF] = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = load_sink_uuid_unlocked (conn, sink_uuid);
  gboolean in_transaction = FALSE;
  gboolean replay = FALSE;
  gint64 sequence = 0;
  g_autofree gchar *record_hash = NULL;

  if (rc == WYRELOG_E_OK) {
    rc = query_ok (conn->conn, "BEGIN TRANSACTION;");
    in_transaction = rc == WYRELOG_E_OK;
    if (rc == WYRELOG_E_OK && service_exchange_fail (conn,
            WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_BEGIN))
      rc = WYRELOG_E_IO;
  }
  duckdb_result side = { 0 }, anchor = { 0 }, checkpoint = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = load_projection_candidates (conn, sink_uuid, p, &side);
  if (rc == WYRELOG_E_OK)
    rc = load_anchor (conn, p, &anchor);
  if (rc == WYRELOG_E_OK) {
    if (duckdb_row_count (&anchor) == 1
        && !duckdb_value_is_null (&anchor, 8, 0))
      sequence = duckdb_value_int64 (&anchor, 8, 0);
    else {
      g_autofree gchar *ignored_previous = NULL;
      rc = get_next_chain_state (conn, WYL_AUDIT_SERVICE_EXCHANGE_STREAM,
          &sequence, &ignored_previous);
    }
  }
  if (rc == WYRELOG_E_OK && sequence > 0)
    rc = load_projection_checkpoint (conn, sequence, &checkpoint);
  if (rc == WYRELOG_E_OK && service_exchange_fail (conn,
          WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_PREFLIGHT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK) {
    idx_t side_rows = duckdb_row_count (&side);
    idx_t anchor_rows = duckdb_row_count (&anchor);
    idx_t checkpoint_rows = duckdb_row_count (&checkpoint);
    if (side_rows == 0 && anchor_rows == 0 && checkpoint_rows == 0) {
      rc = insert_projection_unlocked (conn, sink_uuid, p);
      if (rc == WYRELOG_E_OK && service_exchange_fail (conn,
              WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_SIDECAR))
        rc = WYRELOG_E_IO;
      if (rc == WYRELOG_E_OK)
        rc = insert_projection_anchor_unlocked (conn, p, &sequence,
            &record_hash);
      if (rc == WYRELOG_E_OK && service_exchange_fail (conn,
              WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_ANCHOR))
        rc = WYRELOG_E_IO;
    } else if (side_rows == 1 && anchor_rows == 1 && checkpoint_rows == 1
        && result_text_equal (&side, 0, 0, sink_uuid)
        && projection_row_matches (&side, 0, p) && anchor_matches (&anchor, p)) {
      gchar *stored_hash = duckdb_value_varchar (&anchor, 10, 0);
      gboolean checkpoint_exact = checkpoint_matches (&checkpoint, sequence,
          stored_hash, p->created_at_us);
      duckdb_free (stored_hash);
      if (!checkpoint_exact) {
        rc = WYRELOG_E_POLICY;
      } else {
        replay = TRUE;
        record_hash = duckdb_value_varchar (&anchor, 10, 0);
      }
    } else {
      rc = WYRELOG_E_POLICY;
    }
  }
  duckdb_destroy_result (&side);
  duckdb_destroy_result (&anchor);
  duckdb_destroy_result (&checkpoint);
  memset (&side, 0, sizeof side);
  memset (&anchor, 0, sizeof anchor);
  memset (&checkpoint, 0, sizeof checkpoint);

  /* Exact in-transaction readback is mandatory for both insertion and replay. */
  if (rc == WYRELOG_E_OK) {
    rc = load_projection_candidates (conn, sink_uuid, p, &side);
    if (rc == WYRELOG_E_OK)
      rc = load_anchor (conn, p, &anchor);
    if (rc == WYRELOG_E_OK
        && (duckdb_row_count (&side) != 1
            || !result_text_equal (&side, 0, 0, sink_uuid)
            || !projection_row_matches (&side, 0, p)
            || !anchor_matches (&anchor, p)))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      sequence = duckdb_value_int64 (&anchor, 8, 0);
      gchar *stored_hash = duckdb_value_varchar (&anchor, 10, 0);
      rc = load_projection_checkpoint (conn, sequence, &checkpoint);
      if (rc == WYRELOG_E_OK
          && !checkpoint_matches (&checkpoint, sequence, stored_hash,
              p->created_at_us))
        rc = WYRELOG_E_POLICY;
      duckdb_free (stored_hash);
    }
    duckdb_destroy_result (&side);
    duckdb_destroy_result (&anchor);
    duckdb_destroy_result (&checkpoint);
    memset (&side, 0, sizeof side);
    memset (&anchor, 0, sizeof anchor);
    memset (&checkpoint, 0, sizeof checkpoint);
    if (rc == WYRELOG_E_OK && service_exchange_fail (conn,
            WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_IN_TXN_READBACK))
      rc = WYRELOG_E_IO;
  }
  if (rc == WYRELOG_E_OK) {
    rc = commit_transaction_unlocked (conn);
    if (rc == WYRELOG_E_OK) {
      in_transaction = FALSE;
      if (service_exchange_fail (conn,
              WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_RESPONSE_LOST))
        rc = WYRELOG_E_IO;
    }
  }
  if (rc != WYRELOG_E_OK && in_transaction) {
    wyrelog_error_t rollback_rc = rollback_transaction_unlocked (conn);
    in_transaction = FALSE;
    evict_chain_tail_cache (conn, WYL_AUDIT_SERVICE_EXCHANGE_STREAM);
    if (rollback_rc != WYRELOG_E_OK)
      rc = WYRELOG_E_IO;
  }
  if (rc == WYRELOG_E_OK) {
    if (service_exchange_fail (conn, WYL_AUDIT_SERVICE_EXCHANGE_FAIL_CHECKPOINT)
        || query_ok (conn->conn, "CHECKPOINT;") != WYRELOG_E_OK)
      rc = WYRELOG_E_IO;
  }

  /* A fresh post-commit read proves metadata, sidecar and anchor survived the
   * transaction boundary. No acknowledgement object is created here. */
  if (rc == WYRELOG_E_OK)
    rc = load_sink_uuid_unlocked (conn, sink_uuid);
  if (rc == WYRELOG_E_OK && service_exchange_fail (conn,
          WYL_AUDIT_SERVICE_EXCHANGE_FAIL_POST_COMMIT_READBACK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = load_projection_candidates (conn, sink_uuid, p, &side);
  if (rc == WYRELOG_E_OK)
    rc = load_anchor (conn, p, &anchor);
  if (rc == WYRELOG_E_OK
      && (duckdb_row_count (&side) != 1
          || !result_text_equal (&side, 0, 0, sink_uuid)
          || !projection_row_matches (&side, 0, p)
          || !anchor_matches (&anchor, p)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    sequence = duckdb_value_int64 (&anchor, 8, 0);
    gchar *stored_hash = duckdb_value_varchar (&anchor, 10, 0);
    rc = load_projection_checkpoint (conn, sequence, &checkpoint);
    if (rc == WYRELOG_E_OK
        && !checkpoint_matches (&checkpoint, sequence, stored_hash,
            p->created_at_us))
      rc = WYRELOG_E_POLICY;
    duckdb_free (stored_hash);
  }
  if (rc == WYRELOG_E_OK) {
    memcpy (out->sink_uuid, sink_uuid, sizeof out->sink_uuid);
    memcpy (out->intention_id, p->intention_id, sizeof out->intention_id);
    memcpy (out->payload_digest, p->payload_digest, sizeof out->payload_digest);
    out->sequence_no = duckdb_value_int64 (&anchor, 8, 0);
    gchar *fresh_hash = duckdb_value_varchar (&anchor, 10, 0);
    memcpy (out->record_hash, fresh_hash, sizeof out->record_hash);
    memcpy (out->checkpoint_root, fresh_hash, sizeof out->checkpoint_root);
    duckdb_free (fresh_hash);
    if (!replay)
      update_chain_tail_cache (conn, WYL_AUDIT_SERVICE_EXCHANGE_STREAM,
          sequence, record_hash);
  } else {
    memset (out, 0, sizeof *out);
    evict_chain_tail_cache (conn, WYL_AUDIT_SERVICE_EXCHANGE_STREAM);
  }
  duckdb_destroy_result (&side);
  duckdb_destroy_result (&anchor);
  duckdb_destroy_result (&checkpoint);
  g_mutex_unlock (&conn->lock);
  return rc;
}

wyrelog_error_t
wyl_audit_conn_delete_event (wyl_audit_conn_t *conn, const gchar *id)
{
  wyl_id_t parsed_id;

  if (conn == NULL || id == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_audit_conn_create_user_stream (wyl_audit_conn_t *conn,
    const gchar *stream_name)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  if (conn == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_audit_conn_validate_user_stream_name (stream_name);
  if (rc != WYRELOG_E_OK)
    return rc;

  static const gchar *sql =
      "INSERT INTO user_audit_streams (name, created_at_us) VALUES (?, ?);";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, stream_name) != DuckDBSuccess
      || duckdb_bind_int64 (stmt, 2, g_get_real_time ()) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state step_rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  return step_rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_audit_conn_drop_user_stream (wyl_audit_conn_t *conn,
    const gchar *stream_name)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  if (conn == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_audit_conn_validate_user_stream_name (stream_name);
  if (rc != WYRELOG_E_OK)
    return rc;

  static const gchar *sql = "DELETE FROM user_audit_streams WHERE name = ?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, stream_name) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state step_rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  return step_rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_audit_conn_rename_user_stream (wyl_audit_conn_t *conn,
    const gchar *old_name, const gchar *new_name)
{
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };

  if (conn == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_audit_conn_validate_user_stream_name (old_name);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_audit_conn_validate_user_stream_name (new_name);
  if (rc != WYRELOG_E_OK)
    return rc;

  static const gchar *sql =
      "UPDATE user_audit_streams SET name = ? WHERE name = ?;";
  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess)
    return WYRELOG_E_IO;
  if (duckdb_bind_varchar (stmt, 1, new_name) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, old_name) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }
  duckdb_state step_rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&stmt);
  return step_rc == DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_audit_conn_append_tombstone (wyl_audit_conn_t *conn,
    const gchar *subject_id, const gchar *request_id, gboolean *out_inserted)
{
  wyl_id_t id;
  gchar id_buf[WYL_ID_STRING_BUF];

  wyrelog_error_t rc = wyl_id_new (&id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_id_format (&id, id_buf, sizeof id_buf);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_audit_conn_insert_event_full (conn, id_buf, g_get_real_time (),
      subject_id, "privacy.erase.tombstone", "subject", "erasure_tombstone",
      "system", request_id, WYL_DECISION_ALLOW, out_inserted);
}

static gchar *
dup_result_varchar (duckdb_result *result, idx_t col, idx_t row)
{
  if (duckdb_value_is_null (result, col, row))
    return g_strdup ("");
  gchar *value = duckdb_value_varchar (result, col, row);
  gchar *copy = g_strdup (value);
  duckdb_free (value);
  return copy;
}

wyrelog_error_t
wyl_audit_conn_verify_chain (wyl_audit_conn_t *conn, gchar **out_error)
{
  duckdb_result result = { 0 };

  if (conn == NULL)
    return WYRELOG_E_INVALID;
  if (out_error != NULL)
    *out_error = NULL;

  static const gchar *sql =
      "SELECT id, created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision, stream_name, "
      "event_kind, sequence_no, previous_hash, record_hash, checkpoint_root "
      "FROM audit_events WHERE stream_name = '" WYL_AUDIT_STREAM_AUDIT "' "
      "ORDER BY sequence_no ASC;";
  if (duckdb_query (conn->conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  g_autofree gchar *previous_hash = g_strdup ("");
  idx_t rows = duckdb_row_count (&result);
  for (idx_t row = 0; row < rows; row++) {
    gint64 expected_sequence = (gint64) row + 1;
    gint64 sequence_no = duckdb_value_int64 (&result, 11, row);
    if (sequence_no != expected_sequence) {
      if (out_error != NULL)
        *out_error = g_strdup ("missing_link");
      duckdb_destroy_result (&result);
      return WYRELOG_E_POLICY;
    }

    g_autofree gchar *id = dup_result_varchar (&result, 0, row);
    gint64 created_at_us = duckdb_value_int64 (&result, 1, row);
    g_autofree gchar *subject_id = dup_result_varchar (&result, 2, row);
    g_autofree gchar *action = dup_result_varchar (&result, 3, row);
    g_autofree gchar *resource_id = dup_result_varchar (&result, 4, row);
    g_autofree gchar *deny_reason = dup_result_varchar (&result, 5, row);
    g_autofree gchar *deny_origin = dup_result_varchar (&result, 6, row);
    g_autofree gchar *request_id = dup_result_varchar (&result, 7, row);
    wyl_decision_t decision =
        (wyl_decision_t) duckdb_value_int64 (&result, 8, row);
    g_autofree gchar *stream_name = dup_result_varchar (&result, 9, row);
    g_autofree gchar *event_kind = dup_result_varchar (&result, 10, row);
    g_autofree gchar *stored_previous = dup_result_varchar (&result, 12, row);
    g_autofree gchar *stored_hash = dup_result_varchar (&result, 13, row);
    g_autofree gchar *checkpoint_root = dup_result_varchar (&result, 14, row);

    if (g_strcmp0 (stream_name, WYL_AUDIT_STREAM_AUDIT) != 0
        || g_strcmp0 (stored_previous, previous_hash) != 0) {
      if (out_error != NULL)
        *out_error = g_strdup ("chain_link_mismatch");
      duckdb_destroy_result (&result);
      return WYRELOG_E_POLICY;
    }

    g_autofree gchar *expected_hash = compute_audit_record_hash (stream_name,
        sequence_no, stored_previous, id, created_at_us, subject_id, action,
        resource_id, deny_reason, deny_origin, request_id, decision,
        event_kind);
    if (g_strcmp0 (stored_hash, expected_hash) != 0
        || g_strcmp0 (checkpoint_root, expected_hash) != 0) {
      if (out_error != NULL)
        *out_error = g_strdup ("record_hash_mismatch");
      duckdb_destroy_result (&result);
      return WYRELOG_E_POLICY;
    }

    g_free (previous_hash);
    previous_hash = g_strdup (stored_hash);
  }
  duckdb_destroy_result (&result);

  if (duckdb_query (conn->conn,
          "SELECT COUNT(*) FROM audit_checkpoints c "
          "LEFT JOIN audit_events e "
          "ON c.stream_name = e.stream_name "
          "AND c.sequence_no = e.sequence_no "
          "WHERE c.stream_name = '" WYL_AUDIT_STREAM_AUDIT "' "
          "AND e.id IS NULL;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_value_int64 (&result, 0, 0) != 0) {
    if (out_error != NULL)
      *out_error = g_strdup ("missing_link");
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  duckdb_destroy_result (&result);

  if (duckdb_query (conn->conn,
          "SELECT COUNT(*) FROM audit_checkpoints c "
          "JOIN audit_events e "
          "ON c.stream_name = e.stream_name "
          "AND c.sequence_no = e.sequence_no "
          "WHERE c.stream_name = '" WYL_AUDIT_STREAM_AUDIT "' "
          "AND c.root_hash != e.checkpoint_root;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_value_int64 (&result, 0, 0) != 0) {
    if (out_error != NULL)
      *out_error = g_strdup ("record_hash_mismatch");
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  duckdb_destroy_result (&result);

  if (duckdb_query (conn->conn,
          "SELECT stream_name, sequence_no, COUNT(*) FROM audit_checkpoints "
          "GROUP BY stream_name, sequence_no HAVING COUNT(*) > 1;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  if (duckdb_row_count (&result) != 0) {
    if (out_error != NULL)
      *out_error = g_strdup ("duplicate_checkpoint");
    duckdb_destroy_result (&result);
    return WYRELOG_E_POLICY;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static void
append_json_string (GString *json, const gchar *value)
{
  g_string_append_c (json, '"');

  for (const guchar * p = (const guchar *)value; *p != '\0'; p++) {
    switch (*p) {
      case '"':
        g_string_append (json, "\\\"");
        break;
      case '\\':
        g_string_append (json, "\\\\");
        break;
      case '\b':
        g_string_append (json, "\\b");
        break;
      case '\f':
        g_string_append (json, "\\f");
        break;
      case '\n':
        g_string_append (json, "\\n");
        break;
      case '\r':
        g_string_append (json, "\\r");
        break;
      case '\t':
        g_string_append (json, "\\t");
        break;
      default:
        if (*p < 0x20)
          g_string_append_printf (json, "\\u%04x", *p);
        else
          g_string_append_c (json, (gchar) * p);
        break;
    }
  }

  g_string_append_c (json, '"');
}

static void
append_json_member_string (GString *json, const gchar *name,
    duckdb_result *result, idx_t col, idx_t row)
{
  g_string_append_c (json, '"');
  g_string_append (json, name);
  g_string_append (json, "\":");

  if (duckdb_value_is_null (result, col, row)) {
    g_string_append (json, "null");
    return;
  }

  gchar *value = duckdb_value_varchar (result, col, row);
  append_json_string (json, value);
  duckdb_free (value);
}

static gboolean
parse_filter_key_value (const gchar *filter, gchar **out_key, gchar **out_value)
{
  const gchar *eq = strchr (filter, '=');
  if (eq == NULL)
    return FALSE;
  if (eq == filter || eq[1] == '\0')
    return FALSE;

  *out_key = g_strndup (filter, (gsize) (eq - filter));
  *out_value = g_strdup (eq + 1);
  return TRUE;
}

static gboolean
parse_filter_compound_term (const gchar *filter, gchar **out_key,
    gchar **out_value)
{
  const gchar *open = strchr (filter, '(');
  if (open == NULL)
    return FALSE;
  if (open == filter)
    return FALSE;

  const gchar *close = filter + strlen (filter);
  while (close > open && g_ascii_isspace (close[-1]))
    close--;
  if (close <= open + 1 || close[-1] != ')')
    return FALSE;
  close--;

  const gchar *value_start = open + 1;
  const gchar *value_end = close;
  while (value_start < value_end && g_ascii_isspace (*value_start))
    value_start++;
  while (value_end > value_start && g_ascii_isspace (value_end[-1]))
    value_end--;
  if (value_start >= value_end)
    return FALSE;

  if (*value_start == '"') {
    value_start++;
    if (value_end <= value_start || value_end[-1] != '"')
      return FALSE;
    value_end--;
  }
  if (value_start >= value_end)
    return FALSE;

  *out_key = g_strndup (filter, (gsize) (open - filter));
  g_strstrip (*out_key);
  *out_value = g_strndup (value_start, (gsize) (value_end - value_start));
  return (*out_key)[0] != '\0';
}

static gboolean
parse_audit_filter (const gchar *filter, const gchar **out_column,
    gint16 *out_decision, gchar **out_string)
{
  *out_column = NULL;
  *out_string = NULL;
  *out_decision = WYL_DECISION_DENY;

  if (filter == NULL || filter[0] == '\0')
    return TRUE;

  g_autofree gchar *key = NULL;
  g_autofree gchar *value = NULL;
  if (!parse_filter_key_value (filter, &key, &value)
      && !parse_filter_compound_term (filter, &key, &value))
    return FALSE;

  if (g_strcmp0 (key, "decision") == 0) {
    *out_column = "decision";
    if (g_strcmp0 (value, "deny") == 0) {
      *out_decision = WYL_DECISION_DENY;
      return TRUE;
    }
    if (g_strcmp0 (value, "allow") == 0) {
      *out_decision = WYL_DECISION_ALLOW;
      return TRUE;
    }
    return FALSE;
  }

  if (g_strcmp0 (key, "subject_id") == 0)
    *out_column = "subject_id";
  else if (g_strcmp0 (key, "action") == 0)
    *out_column = "action";
  else if (g_strcmp0 (key, "resource_id") == 0)
    *out_column = "resource_id";
  else if (g_strcmp0 (key, "deny_reason") == 0)
    *out_column = "deny_reason";
  else if (g_strcmp0 (key, "deny_origin") == 0)
    *out_column = "deny_origin";
  else if (g_strcmp0 (key, "request_id") == 0)
    *out_column = "request_id";

  if (*out_column != NULL) {
    *out_string = g_steal_pointer (&value);
    return TRUE;
  }

  return FALSE;
}

wyrelog_error_t
wyl_audit_conn_query_events_json (wyl_audit_conn_t *conn,
    const gchar *filter, gchar **out_json)
{
  const gchar *column;
  g_autofree gchar *string_value = NULL;
  gint16 decision_value;
  duckdb_prepared_statement stmt;
  duckdb_result result;
  duckdb_state rc;

  if (conn == NULL || out_json == NULL)
    return WYRELOG_E_INVALID;
  *out_json = NULL;

  if (!parse_audit_filter (filter, &column, &decision_value, &string_value))
    return WYRELOG_E_INVALID;

  g_autofree gchar *sql = NULL;
  if (column == NULL) {
    sql =
        g_strdup ("SELECT id, created_at_us, subject_id, action, resource_id, "
        "deny_reason, deny_origin, request_id, decision " "FROM audit_events "
        "ORDER BY created_at_us DESC, id DESC " "LIMIT 100;");
  } else {
    sql =
        g_strdup_printf
        ("SELECT id, created_at_us, subject_id, action, resource_id, "
        "deny_reason, deny_origin, request_id, decision " "FROM audit_events "
        "WHERE %s = ? " "ORDER BY created_at_us DESC, id DESC " "LIMIT 100;",
        column);
  }

  if (duckdb_prepare (conn->conn, sql, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    return WYRELOG_E_IO;
  }

  if (column != NULL) {
    duckdb_state bind_rc;
    if (g_strcmp0 (column, "decision") == 0)
      bind_rc = duckdb_bind_int16 (stmt, 1, decision_value);
    else
      bind_rc = duckdb_bind_varchar (stmt, 1, string_value);
    if (bind_rc != DuckDBSuccess) {
      duckdb_destroy_prepare (&stmt);
      return WYRELOG_E_IO;
    }
  }

  rc = duckdb_execute_prepared (stmt, &result);
  duckdb_destroy_prepare (&stmt);
  if (rc != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  g_autoptr (GString) json = g_string_new ("[");
  idx_t rows = duckdb_row_count (&result);
  for (idx_t row = 0; row < rows; row++) {
    if (row > 0)
      g_string_append_c (json, ',');

    g_string_append_c (json, '{');
    append_json_member_string (json, "id", &result, 0, row);
    g_string_append_printf (json, ",\"created_at_us\":%" G_GINT64_FORMAT,
        duckdb_value_int64 (&result, 1, row));
    g_string_append_c (json, ',');
    append_json_member_string (json, "subject_id", &result, 2, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "action", &result, 3, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "resource_id", &result, 4, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "deny_reason", &result, 5, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "deny_origin", &result, 6, row);
    g_string_append_c (json, ',');
    append_json_member_string (json, "request_id", &result, 7, row);
    g_string_append_printf (json, ",\"decision\":%" G_GINT16_FORMAT "}",
        (gint16) duckdb_value_int64 (&result, 8, row));
  }
  g_string_append_c (json, ']');

  duckdb_destroy_result (&result);
  *out_json = g_string_free (g_steal_pointer (&json), FALSE);
  return WYRELOG_E_OK;
}

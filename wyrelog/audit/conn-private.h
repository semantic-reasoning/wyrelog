/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <duckdb.h>

#include "wyrelog/decide.h"
#include "wyrelog/error.h"
#include "wyrelog/auth/service-exchange-audit-private.h"

G_BEGIN_DECLS;

/*
 * Audit-log connection lifecycle wrapper.
 *
 * Owns a DuckDB database handle and a single connection to it,
 * which downstream audit modules consume to issue DDL and append
 * statements. The handle pair is opaque from outside this header
 * but the borrowed `duckdb_connection` returned by the accessor
 * is the raw DuckDB ABI; callers must remain inside libwyrelog.
 *
 * Lifecycle:
 *   1. wyl_audit_conn_open(path, &conn) -- on success owns *conn.
 *   2. wyl_audit_conn_get_connection(conn) -- borrowed, lifetime
 *      tied to *conn.
 *   3. wyl_audit_conn_close(conn) -- disconnect then close, in
 *      that order (DuckDB requirement). NULL-safe and idempotent.
 *
 * Threading: a connection is not safe for concurrent use; the
 * engine layer serialises writers. Tests run single-threaded.
 *
 * Path semantics: NULL or the literal ":memory:" both yield an
 * in-memory database. Other paths are passed verbatim to DuckDB,
 * which interprets them as filesystem paths.
 */

typedef struct wyl_audit_conn_t wyl_audit_conn_t;

#define WYL_AUDIT_SERVICE_EXCHANGE_STREAM "__wyrelog.service-exchange"

typedef wyl_service_exchange_audit_projection_t
    WylAuditServiceExchangeProjection;

typedef struct WylAuditServiceExchangeProjectionReadback
{
  gchar sink_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF];
  gchar intention_id[WYL_SERVICE_EXCHANGE_UUID_BUF];
  gchar payload_digest[WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_BUF];
  gint64 sequence_no;
  gchar record_hash[WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_BUF];
  gchar checkpoint_root[WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_BUF];
} WylAuditServiceExchangeProjectionReadback;

typedef enum
{
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_NONE,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_METADATA_IN_TXN_READBACK,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_BEGIN,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_PREFLIGHT,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_SIDECAR,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_ANCHOR,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_IN_TXN_READBACK,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_QUERY,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_RESPONSE_LOST,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_CHECKPOINT,
  WYL_AUDIT_SERVICE_EXCHANGE_FAIL_POST_COMMIT_READBACK,
} WylAuditServiceExchangeFailStage;

void wyl_audit_conn_service_exchange_fail_once
    (wyl_audit_conn_t * conn, WylAuditServiceExchangeFailStage stage);
guint wyl_audit_conn_service_exchange_get_rollback_count_for_test
    (wyl_audit_conn_t * conn);
/* WYL_TEST-only observation: number of entries into Atom A projection. */
guint64 wyl_audit_conn_service_exchange_get_entry_count_for_test
    (wyl_audit_conn_t * conn);
void wyl_audit_conn_service_exchange_reset_entry_count_for_test
    (wyl_audit_conn_t * conn);

/* Exact identity of the durable service-exchange sink. */
wyrelog_error_t wyl_audit_conn_service_exchange_get_sink_identity
    (wyl_audit_conn_t * conn,
    gchar out_logical_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM],
    gchar out_sink_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF]);

/* Private durable projection primitive. It deliberately consumes sanitized
 * material rather than a receipt; receipt validation and acknowledgement are
 * owned by the later projector layer. */
wyrelog_error_t wyl_audit_conn_service_exchange_project
    (wyl_audit_conn_t * conn,
    const WylAuditServiceExchangeProjection * projection,
    WylAuditServiceExchangeProjectionReadback * out_readback);

/*
 * Opens an audit log at `path`. On WYRELOG_E_OK *out_conn owns
 * the new handle pair; on any non-OK return *out_conn is left
 * untouched.
 *
 *   WYRELOG_E_OK       database opened and connected.
 *   WYRELOG_E_INVALID  out_conn == NULL.
 *   WYRELOG_E_IO       DuckDB rejected the path or could not
 *                      create the database file.
 *   WYRELOG_E_INTERNAL DuckDB connect failed against an
 *                      already-opened database (rare; OOM-class).
 */
wyrelog_error_t wyl_audit_conn_open (const gchar * path,
    wyl_audit_conn_t ** out_conn);

/*
 * Closes the connection and releases the database. NULL-safe;
 * after the call the pointer is invalid.
 */
void wyl_audit_conn_close (wyl_audit_conn_t * conn);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_audit_conn_t, wyl_audit_conn_close);

/*
 * Returns the borrowed underlying DuckDB connection handle.
 * Lifetime is bounded by the parent wyl_audit_conn_t. Returns a
 * zero-initialised handle on NULL input so callers passing a
 * stale pointer get a deterministic fail-closed shape rather than
 * a crash.
 */
duckdb_connection wyl_audit_conn_get_connection (wyl_audit_conn_t * conn);

/* Test-only, thread-safe one-shot sink fault. The next event insert returns
 * WYRELOG_E_IO before touching DuckDB. Production defaults to disabled. */
void wyl_audit_conn_fail_insert_once (wyl_audit_conn_t * conn);

/*
 * Ensures the audit_events table exists on the open connection.
 * Idempotent: subsequent calls on the same connection are no-ops.
 * The table mirrors the WylAuditEvent public surface:
 *
 *   id            VARCHAR PRIMARY KEY  -- canonical 36-char form
 *   created_at_us BIGINT               -- g_get_real_time stamp
 *   subject_id    VARCHAR
 *   action        VARCHAR
 *   resource_id   VARCHAR
 *   deny_reason   VARCHAR              -- representative deny code
 *   deny_origin   VARCHAR              -- source relation tag
 *   request_id    VARCHAR              -- optional request lifecycle id
 *   decision      SMALLINT             -- 0 = DENY, 1 = ALLOW
 *
 * Returns WYRELOG_E_OK on success, WYRELOG_E_INVALID for a NULL
 * argument, and WYRELOG_E_IO if DuckDB rejects the DDL.
 */
wyrelog_error_t wyl_audit_conn_create_schema (wyl_audit_conn_t * conn);

/*
 * Probes whether @table_name exists in the audit DuckDB catalog. Intended for
 * daemon readiness checks and private tests; append/query paths should use
 * their typed APIs rather than catalog inspection.
 */
wyrelog_error_t wyl_audit_conn_table_exists (wyl_audit_conn_t * conn,
    const gchar * table_name, gboolean * out_exists);

/*
 * Inserts a fully materialised audit row into the runtime DuckDB view.
 * This is used by both freshly emitted events and policy-store replay;
 * callers are responsible for deciding whether the source row should
 * also be persisted elsewhere.
 */
wyrelog_error_t wyl_audit_conn_insert_event (wyl_audit_conn_t * conn,
    const gchar * id, gint64 created_at_us, const gchar * subject_id,
    const gchar * action, const gchar * resource_id,
    const gchar * deny_reason, const gchar * deny_origin,
    wyl_decision_t decision);

wyrelog_error_t wyl_audit_conn_insert_event_full (wyl_audit_conn_t * conn,
    const gchar * id, gint64 created_at_us, const gchar * subject_id,
    const gchar * action, const gchar * resource_id,
    const gchar * deny_reason, const gchar * deny_origin,
    const gchar * request_id, wyl_decision_t decision, gboolean * out_inserted);

wyrelog_error_t wyl_audit_conn_delete_event (wyl_audit_conn_t * conn,
    const gchar * id);

/*
 * Reserved system stream guard. User-managed streams must not use the
 * __wyrelog.* namespace; mutation attempts return WYRELOG_E_POLICY with a
 * stable fail-closed shape.
 */
gboolean wyl_audit_conn_stream_name_is_reserved (const gchar * stream_name);
wyrelog_error_t wyl_audit_conn_validate_user_stream_name
    (const gchar * stream_name);
wyrelog_error_t wyl_audit_conn_create_user_stream (wyl_audit_conn_t * conn,
    const gchar * stream_name);
wyrelog_error_t wyl_audit_conn_drop_user_stream (wyl_audit_conn_t * conn,
    const gchar * stream_name);
wyrelog_error_t wyl_audit_conn_rename_user_stream (wyl_audit_conn_t * conn,
    const gchar * old_name, const gchar * new_name);
wyrelog_error_t wyl_audit_conn_append_tombstone (wyl_audit_conn_t * conn,
    const gchar * subject_id, const gchar * request_id,
    gboolean * out_inserted);
wyrelog_error_t wyl_audit_conn_verify_chain (wyl_audit_conn_t * conn,
    gchar ** out_error);

/*
 * Serialises audit_events rows to a compact JSON array ordered by newest
 * first. @filter may be NULL/empty or one exact-match term. Both
 * key=value and compound predicate forms are accepted:
 *
 *   decision=deny|allow
 *   decision("deny"|"allow")
 *   subject_id=<value>
 *   subject_id("<value>")
 *   action=<value>
 *   action("<value>")
 *   resource_id=<value>
 *   resource_id("<value>")
 *   deny_reason=<value>
 *   deny_reason("<value>")
 *   deny_origin=<value>
 *   deny_origin("<value>")
 *   request_id=<value>
 *   request_id("<value>")
 *
 * On success @out_json owns a newly allocated string.
 */
wyrelog_error_t wyl_audit_conn_query_events_json (wyl_audit_conn_t * conn,
    const gchar * filter, gchar ** out_json);

G_END_DECLS;

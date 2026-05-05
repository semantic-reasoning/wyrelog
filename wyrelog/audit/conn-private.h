/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <duckdb.h>

#include "wyrelog/error.h"

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
 *
 * On success @out_json owns a newly allocated string.
 */
wyrelog_error_t wyl_audit_conn_query_events_json (wyl_audit_conn_t * conn,
    const gchar * filter, gchar ** out_json);

G_END_DECLS;

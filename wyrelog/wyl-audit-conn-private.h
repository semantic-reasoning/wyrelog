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

G_END_DECLS;

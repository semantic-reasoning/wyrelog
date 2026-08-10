/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

/* The live-open handoff exposes duckdb C-API handles.  The amalgamated
 * duckdb.hpp bundles an unguarded copy of the C API, so a C++ translation unit
 * must take the types from duckdb.hpp (never both headers), while C consumers
 * use duckdb.h. */
#ifdef __cplusplus
#include <duckdb.hpp>
#else
#include <duckdb.h>
#endif
#include <glib.h>

#include "wyrelog/error.h"
#include "fact/graph-artifact-namespace-private.h"

G_BEGIN_DECLS;

typedef struct WylSecureDuckdbBridge WylSecureDuckdbBridge;
typedef enum
{ WYL_SECURE_DUCKDB_INIT_EMPTY = 0,
  WYL_SECURE_DUCKDB_VALIDATE_ONLY = 1} WylSecureDuckdbMode;

/* This experimental lifecycle bridge owns a DuckDB instance and connection.
 * The namespace constructor injects the bounded filesystem without exposing
 * paths, descriptors, C API handles, or C++ implementation types.  Call
 * finalize when terminal cleanup success must be observed; free remains a
 * best-effort cleanup for C ownership conventions. */
wyrelog_error_t wyl_secure_duckdb_bridge_new (WylSecureDuckdbBridge ** out);
wyrelog_error_t
wyl_secure_duckdb_bridge_new_with_namespace (WylFactArtifactNamespace *,
    WylSecureDuckdbMode, WylSecureDuckdbBridge **);
wyrelog_error_t wyl_secure_duckdb_bridge_health (WylSecureDuckdbBridge * self);
wyrelog_error_t
wyl_secure_duckdb_bridge_finalize (WylSecureDuckdbBridge * self);
void wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge * self);

/* Live secure open of a provisioned pair.  Builds a bounded DuckDB instance and
 * hands back a live C-API database + connection routed through the secure
 * filesystem, while the returned bridge retains only the authority lease and
 * health (no DuckDB reference).  The returned handle owns the instance, so
 * closing it -- duckdb_disconnect then duckdb_close -- destructs the instance
 * and its shutdown checkpoint runs through the still-live bounded filesystem
 * under the still-held lease.  Call wyl_secure_duckdb_bridge_release_live AFTER
 * duckdb_close to observe health and release the lease.  This is the live
 * counterpart to the one-shot pinned identity open, not a replacement. */
wyrelog_error_t wyl_secure_duckdb_bridge_open_live_pair
  (WylFactArtifactNamespace * namespace_, gboolean writable,
    WylSecureDuckdbBridge ** out_bridge, duckdb_database * out_db,
    duckdb_connection * out_conn);
/* Observe health and release the authority lease of a live bridge, then free it.
 * Must be called only after the handle returned by open_live_pair has been
 * duckdb_close'd, so the shutdown checkpoint has already run under the lease. */
wyrelog_error_t
wyl_secure_duckdb_bridge_release_live (WylSecureDuckdbBridge * self);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylSecureDuckdbBridge,
    wyl_secure_duckdb_bridge_free)
G_END_DECLS;

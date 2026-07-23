/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct WylSecureDuckdbBridge WylSecureDuckdbBridge;

/* This experimental lifecycle bridge owns only an in-memory DuckDB instance
 * and connection.  It deliberately accepts and exposes no paths, file
 * descriptors, C API handles, or C++ implementation types. */
wyrelog_error_t wyl_secure_duckdb_bridge_new (WylSecureDuckdbBridge ** out);
wyrelog_error_t wyl_secure_duckdb_bridge_health (WylSecureDuckdbBridge * self);
void wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge * self);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylSecureDuckdbBridge,
    wyl_secure_duckdb_bridge_free)
    G_END_DECLS;

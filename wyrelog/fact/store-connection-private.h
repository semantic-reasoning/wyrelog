/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#if !defined(WYL_FACT_STORE_CONNECTION_ROLE)
#error "fact-store connection authority is restricted to store/compound/replay"
#endif

#include <duckdb.h>
#include <glib.h>

#include "wyrelog/error.h"

typedef struct wyl_fact_store_t wyl_fact_store_t;

typedef struct
{
  wyl_fact_store_t *store;
  duckdb_connection connection;
  gboolean held;
} WylFactStoreConnectionSession;

wyrelog_error_t wyl_fact_store_connection_session_begin
  (wyl_fact_store_t * store, WylFactStoreConnectionSession * session);
duckdb_connection wyl_fact_store_connection_session_get
  (const WylFactStoreConnectionSession * session);
void wyl_fact_store_connection_session_end
  (WylFactStoreConnectionSession * session);

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#if !defined(WYL_FACT_STORE_CONNECTION_ROLE)
#error "fact-store connection authority is restricted to store/compound/replay"
#endif

#include <duckdb.h>
#include <glib.h>

#include "wyrelog/error.h"

typedef struct wyl_fact_store_t wyl_fact_store_t;
typedef struct WylFactStoreConnectionSession WylFactStoreConnectionSession;

struct WylFactStoreConnectionSession
{
  wyl_fact_store_t *store;
  duckdb_connection connection;
  GThread *owner;
  gboolean held;
};

typedef enum
{
  WYL_FACT_STORE_TRANSACTION_APPEND_CORE = 0,
  WYL_FACT_STORE_TRANSACTION_RETRACT_BY_BATCH,
  WYL_FACT_STORE_TRANSACTION_COMPOUND_PUT,
  WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE,
} WylFactStoreTransactionKind;

typedef enum
{
  WYL_FACT_STORE_TRANSACTION_BEFORE_COMMIT = 0,
  WYL_FACT_STORE_TRANSACTION_BEFORE_ROLLBACK,
} WylFactStoreTransactionPhase;

typedef struct
{
  WylFactStoreConnectionSession *session;
  WylFactStoreTransactionKind kind;
  gboolean open;
} WylFactStoreTransaction;

wyrelog_error_t wyl_fact_store_connection_session_begin
  (wyl_fact_store_t * store, WylFactStoreConnectionSession * session);
duckdb_connection wyl_fact_store_connection_session_get
  (const WylFactStoreConnectionSession * session);
void wyl_fact_store_connection_session_end
  (WylFactStoreConnectionSession * session);
wyrelog_error_t wyl_fact_store_transaction_begin
  (WylFactStoreConnectionSession * session, WylFactStoreTransactionKind kind,
    WylFactStoreTransaction * transaction);
wyrelog_error_t wyl_fact_store_transaction_finish
  (WylFactStoreTransaction * transaction, wyrelog_error_t primary_rc);

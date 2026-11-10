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
  WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION,
  WYL_FACT_STORE_TRANSACTION_SCHEMA_MIGRATION,
  /* The #1103 rebuild that converges a migrated store's
   * fact_batches.logical_bytes to NOT NULL.  Deliberately distinct from
   * SCHEMA_MIGRATION above: a fault injected at that kind targets the
   * ALTER block, and sharing one kind would make its injected-failure
   * count depend on the store's shape.  Kept parallel with
   * WylFactStoreTransactionTestKind, which transaction_test_hook_unlocked
   * casts to positionally. */
  WYL_FACT_STORE_TRANSACTION_LOGICAL_BYTES_MIGRATION,
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
  /* Set when COMMIT was issued and DuckDB reported it failed.  Such a
   * transaction may be durable: DuckDB 2.0 reports a durable commit whose
   * autocheckpoint failed as an error (#1499), and neither the error type
   * nor, on the skip-WAL path, its text tells durable from lost. */
  gboolean commit_outcome_unknown;
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

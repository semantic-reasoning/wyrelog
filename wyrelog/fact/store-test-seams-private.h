/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#if !defined(WYL_TEST_HANDLE_SEAMS)
#error "fact-store SQL test helpers require WYL_TEST_HANDLE_SEAMS"
#endif

#include <glib.h>

#include "wyrelog/error.h"

typedef struct wyl_fact_store_t wyl_fact_store_t;

typedef enum
{
  WYL_FACT_STORE_TRANSACTION_TEST_APPEND_CORE = 0,
  WYL_FACT_STORE_TRANSACTION_TEST_RETRACT_BY_BATCH,
  WYL_FACT_STORE_TRANSACTION_TEST_COMPOUND_PUT,
  WYL_FACT_STORE_TRANSACTION_TEST_FORGET_COMPLETE,
} WylFactStoreTransactionTestKind;

typedef enum
{
  WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_COMMIT = 0,
  WYL_FACT_STORE_TRANSACTION_TEST_BEFORE_ROLLBACK,
} WylFactStoreTransactionTestPhase;

typedef wyrelog_error_t (*WylFactStoreTransactionTestHook)
  (WylFactStoreTransactionTestKind kind,
    WylFactStoreTransactionTestPhase phase, gpointer user_data);
typedef void (*WylFactStoreSessionAdmissionTestHook) (gpointer user_data);

void wyl_fact_store_test_set_transaction_hook (wyl_fact_store_t * store,
    WylFactStoreTransactionTestHook hook, gpointer user_data);
void wyl_fact_store_test_set_session_admission_hook (wyl_fact_store_t * store,
    WylFactStoreSessionAdmissionTestHook hook, gpointer user_data);
gboolean wyl_fact_store_test_try_lock (wyl_fact_store_t * store);
guint wyl_fact_store_test_session_admission_count (wyl_fact_store_t * store);
guint wyl_fact_store_test_duckdb_call_count (wyl_fact_store_t * store);

wyrelog_error_t wyl_fact_store_test_exec_sql (wyl_fact_store_t * store,
    const gchar * sql);
wyrelog_error_t wyl_fact_store_test_query_int64 (wyl_fact_store_t * store,
    const gchar * sql, gint64 * out_value);
wyrelog_error_t wyl_fact_store_test_query_text (wyl_fact_store_t * store,
    const gchar * sql, gchar ** out_value);
wyrelog_error_t
wyl_fact_store_test_rename_metadata_value_column_at_checkpoint
  (wyl_fact_store_t * store);

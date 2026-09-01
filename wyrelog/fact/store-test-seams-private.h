/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#if !defined(WYL_TEST_HANDLE_SEAMS)
#error "fact-store SQL test helpers require WYL_TEST_HANDLE_SEAMS"
#endif

#include <glib.h>

#include "wyrelog/error.h"

typedef struct wyl_fact_store_t wyl_fact_store_t;

wyrelog_error_t wyl_fact_store_test_exec_sql (wyl_fact_store_t * store,
    const gchar * sql);
wyrelog_error_t wyl_fact_store_test_query_int64 (wyl_fact_store_t * store,
    const gchar * sql, gint64 * out_value);
wyrelog_error_t wyl_fact_store_test_query_text (wyl_fact_store_t * store,
    const gchar * sql, gchar ** out_value);
wyrelog_error_t
wyl_fact_store_test_rename_metadata_value_column_at_checkpoint
  (wyl_fact_store_t * store);

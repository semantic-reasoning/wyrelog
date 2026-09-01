/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_FACT_STORE_DUCKDB_CONFIG_NONE = 0,
  WYL_FACT_STORE_DUCKDB_CONFIG_THREADS,
  WYL_FACT_STORE_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS,
  WYL_FACT_STORE_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS,
  WYL_FACT_STORE_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS,
  WYL_FACT_STORE_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS,
  WYL_FACT_STORE_DUCKDB_CONFIG_ACCESS_MODE,
} WylFactStoreDuckdbConfigSetting;

#if defined(WYL_TEST_HANDLE_SEAMS)
typedef struct wyl_fact_store_t wyl_fact_store_t;

void wyl_fact_store_duckdb_config_fail_once_for_test
  (WylFactStoreDuckdbConfigSetting setting);
wyrelog_error_t wyl_fact_store_duckdb_config_get_for_test
  (wyl_fact_store_t * store, WylFactStoreDuckdbConfigSetting setting,
    gchar ** out_value);
#endif

G_END_DECLS;

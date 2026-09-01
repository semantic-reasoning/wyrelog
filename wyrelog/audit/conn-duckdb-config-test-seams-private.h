/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS;

typedef enum
{
  WYL_AUDIT_DUCKDB_CONFIG_NONE = 0,
  WYL_AUDIT_DUCKDB_CONFIG_CREATE,
  WYL_AUDIT_DUCKDB_CONFIG_THREADS,
  WYL_AUDIT_DUCKDB_CONFIG_ENABLE_EXTERNAL_ACCESS,
  WYL_AUDIT_DUCKDB_CONFIG_ALLOW_COMMUNITY_EXTENSIONS,
  WYL_AUDIT_DUCKDB_CONFIG_AUTOINSTALL_KNOWN_EXTENSIONS,
  WYL_AUDIT_DUCKDB_CONFIG_AUTOLOAD_KNOWN_EXTENSIONS,
} WylAuditDuckdbConfigOperation;

#if defined(WYL_TEST_HANDLE_SEAMS)
typedef struct
{
  guint config_creations;
  guint config_destroys;
  guint open_attempts;
} WylAuditDuckdbConfigSnapshot;

void wyl_audit_conn_duckdb_config_fail_once_for_test
  (WylAuditDuckdbConfigOperation operation);
void wyl_audit_conn_duckdb_config_snapshot_for_test
  (WylAuditDuckdbConfigSnapshot * out_snapshot);
#endif

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-locator-private.h"
#include "fact/offline-backup-bundle-private.h"
#include "fact/offline-restore-journal-private.h"
#include "fact/offline-restore-validation-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_NONE = 0,
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_BUNDLE,
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_AUTHORITY,
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_TARGET,
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_MAPPING,
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_RUNTIME,
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_COLLISION,
  WYL_FACT_OFFLINE_RESTORE_DRY_RUN_FAILURE_CHANGED,
} WylFactOfflineRestoreDryRunFailure;

typedef struct
{
  gchar *graph_id;
  guint64 lifecycle_generation;
  guint64 reconciliation_generation;
  gchar *target_schema_digest;
  gboolean schema_transition_required;
  WylFactGraphPreStageInventory inventory;
} WylFactOfflineRestoreDryRunGraph;

typedef struct
{
  WylFactOfflineRestoreDryRunFailure failure;
  gchar *tenant_id;
  gchar *failed_graph_id;
  guint8 manifest_sha256[32];
  guint64 tenant_lifecycle_generation;
  guint64 tenant_reconciliation_generation;
  GPtrArray *graphs;
  /* Point-in-time observation only. Must be repeated under retained
   * quiescence before an actual stage is created. */
  gboolean observed_eligible_for_staging;
  gboolean publication_eligible;
  WylFactOfflineRestoreReplayResult replay_result;
} WylFactOfflineRestoreDryRunReport;

void wyl_fact_offline_restore_dry_run_report_clear
  (WylFactOfflineRestoreDryRunReport *report);

/* Collect an authenticated, read-only pre-import observation. Success means
 * the destination was eligible at the two observation boundaries; it grants
 * no durable authorization and does not run replay. The caller must repeat
 * admission under retained quiescence before mutation.
 * No journal, stage, policy write, root binding, or runtime admission change
 * is performed. Initialize out_report to zero before its first call; clear
 * it between calls. On failure, only failure and failed_graph_id remain. */
wyrelog_error_t wyl_fact_offline_restore_dry_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, WylFactOfflineBackupBundle *bundle,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id,
    WylFactOfflineRestoreDryRunReport *out_report);

G_END_DECLS

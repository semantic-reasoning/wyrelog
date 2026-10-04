/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/offline-restore-journal-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Roll back one graph-scoped restore using its durable journal. The external
 * backup source and manifest are intentionally unnecessary for cleanup of the
 * operation-owned stage. The caller must pass a current policy handle and a
 * zero-initialized output. A failed/ambiguous CAS leaves output empty; reload
 * the journal and retry with its actual revision. The tenant stays sealed.
 * Windows fails closed before destination mutation. */
wyrelog_error_t wyl_fact_offline_restore_graph_rollback_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Abort an undecided tenant restore one graph at a time. On an ambiguous
 * result, reload by UUID and retry with the durable revision. The claim and
 * journal remain until an explicit, verified release. */
wyrelog_error_t wyl_fact_offline_restore_tenant_rollback_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* UUID recovery entry point for a confirmed undecided or rollback journal.
 * Reload durable revision after any ambiguous response, then call again.
 * COMMIT decisions require the separate commit resume path. */
wyrelog_error_t wyl_fact_offline_restore_rollback_recover_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Release a completed rollback only after rechecking every graph's stage,
 * main identity, policy, journal and closed runtime under one root lease. */
wyrelog_error_t wyl_fact_offline_restore_rollback_release_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us);

#ifdef WYL_TEST_HANDLE_SEAMS
typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_DECISION_CAS,
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_DECISION,
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_BEGIN,
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_COMPLETE,
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_RELEASE,
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_RELEASE,
} WylFactOfflineRestoreRollbackCheckpoint;
void wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint)
    (WylFactOfflineRestoreRollbackCheckpoint point, gpointer user_data),
    gpointer user_data);
#endif

G_END_DECLS

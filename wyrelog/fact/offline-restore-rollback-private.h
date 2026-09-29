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

#ifdef WYL_TEST_HANDLE_SEAMS
typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_DECISION,
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_AFTER_BEGIN,
  WYL_FACT_OFFLINE_RESTORE_ROLLBACK_BEFORE_COMPLETE,
} WylFactOfflineRestoreRollbackCheckpoint;
void wyl_fact_offline_restore_graph_rollback_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint)
    (WylFactOfflineRestoreRollbackCheckpoint point, gpointer user_data),
    gpointer user_data);
#endif

G_END_DECLS

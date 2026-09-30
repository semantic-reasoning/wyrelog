/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/offline-backup-bundle-private.h"
#include "fact/offline-restore-journal-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Establish a pristine revision-1 restore claim from an authenticated bundle.
 * The trusted digest must have been supplied to bundle_open independently.
 * Explicit confirmation, sealed policy, selected runtime quiescence, exact
 * ACTIVE pairs, matching active/backup schema digests, and collision-free
 * destination inventories are required.
 * Success mutates only policy journal/claim rows. An error after SQLite COMMIT
 * may still leave a durable claim; reload by operation UUID before retry.
 * out_committed must be zero-initialized or previously cleared. Linux only. */
wyrelog_error_t wyl_fact_offline_restore_begin_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, WylFactOfflineBackupBundle *bundle,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id,
    const gchar *operation_uuid, gboolean confirmed, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

#ifdef WYL_TEST_HANDLE_SEAMS
/* Runs after the guarded policy transaction has read its authority rows and
 * before the filesystem proof. No destination capability is exposed. */
void wyl_fact_offline_restore_begin_set_proof_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer), gpointer user_data);
#endif

G_END_DECLS

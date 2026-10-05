/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/offline-backup-bundle-private.h"
#include "fact/offline-restore-journal-private.h"
#include "fact/replay-scheduler-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Continues an authenticated, undecided BEGIN through import and replay
 * preflight. The bundle must have been opened with an independently trusted
 * digest. Every invocation loads durable state; after any error, invoke again
 * with a fresh bundle and revision observed from the policy store. This
 * function never decides COMMIT, publishes a main, or unseals the tenant.
 * The current import and validation sessions require the destination's
 * active schema digest to equal the backup schema digest; a schema change
 * remains a separate restore transition and fails closed here. It must be
 * called outside a replay worker and owns no caller inputs. */
wyrelog_error_t wyl_fact_offline_restore_prepare_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, WylFactReplayScheduler *scheduler,
    WylFactOfflineBackupBundle *bundle, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    GCancellable *cancellable,
    WylFactOfflineRestoreJournal *out_committed);

/* Admit tenant COMMIT from a separately authenticated bundle. Reopens the
 * prepared journal at the exact revision, repeats full-scope replay on the
 * supplied real scheduler while retaining root and graph authority, then
 * performs the fenced policy decision CAS. No resume driver runs here. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_admit_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, WylFactReplayScheduler *scheduler,
    WylFactOfflineBackupBundle *bundle, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    GCancellable *cancellable,
    WylFactOfflineRestoreJournal *out_committed);

#ifdef WYL_TEST_HANDLE_SEAMS
void wyl_fact_offline_restore_tenant_commit_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer user_data), gpointer user_data);
#endif

G_END_DECLS

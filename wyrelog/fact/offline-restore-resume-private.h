/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/offline-restore-journal-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Dispatch the six v5 tenant COMMIT file steps to durable post-publish.
 * Reloads the exact journal and policy claim before each step and returns
 * only after a read-only all-graph terminal proof. Does not reserve v6
 * replacements or open admission. Errors leave output empty. Linux only. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_v5_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Resume durable v5 post-publish through an exact, all-graph v7 selected
 * vector. Reloads policy and journal after each scoped driver result; v6
 * companion phases may advance without a journal revision change. Stops
 * before v7 cleanup, promotion, generation publication or admission. */
wyrelog_error_t wyl_fact_offline_restore_tenant_replacements_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Advances one tenant COMMIT step from v5 through v8. A v6 companion phase
 * can advance without changing the journal revision. Each driver rechecks
 * its authority under the root lease and all-graph quiescence. An error
 * leaves output empty; retry must reload durable state. v8 returns unchanged
 * after checking the terminal graph vector. Admission and unseal are separate.
 * Linux only. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_resume_one
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

G_END_DECLS

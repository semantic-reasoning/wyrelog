/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/graph-locator-private.h"
#include "fact/offline-restore-journal-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Callback-scoped, copied observation. It grants no publication or policy
 * authority and cannot be used as evidence for a later filesystem effect. */
typedef struct
{
  gchar *operation_uuid;
  gchar *tenant_id;
  gchar *graph_id;
  gchar *store_uuid;
  gchar *old_provisioning_uuid;
  gchar *replacement_uuid;
  gchar *replacement_phase;
  guint64 journal_revision;
  WylFactArtifactInventoryIdentity old_main;
  WylFactArtifactInventoryIdentity new_main;
  WylFactGraphRestorePostPublishLayout layout;
} WylFactGraphCommitInspection;

typedef wyrelog_error_t (*WylFactGraphCommitInspectionFunc)
  (const WylFactGraphCommitInspection *inspection, gpointer user_data);

/* Bind one old ACTIVE provisioning UUID to an imported, fully preflighted
 * tenant journal. The root lease and every graph's quiescence remain held
 * through a transaction-scoped exact filesystem proof. Only the journal
 * changes; COMMIT admission and publication remain separate. */
wyrelog_error_t wyl_fact_offline_restore_tenant_bind_provisioned_old_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Drive one v5 tenant COMMIT SYNC_STAGED step while every graph retains its
 * exact READY file pair. Earlier siblings may have completed their own stage
 * sync; their journal latch is historical and is not reconstructed from a
 * fresh capture. UNKNOWN commits before file sync and retries recapture. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_sync_staged_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Drive one imported v5 tenant COMMIT RETAIN transition after every stage is
 * synced. A durable UNKNOWN intent precedes the rename; retry accepts only
 * an exact READY or RETAINED provisioned shape and proves directory sync. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_retain_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Drive one v5 tenant COMMIT rollback-file fsync under full tenant authority.
 * UNKNOWN retries the exact retained inode and leaves output empty on error. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_sync_rollback_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Prove the full v5 retained set, then durably sync the selected directory
 * before advancing the selected journal entry to PUBLISH. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_sync_retain_dir_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Crash-safe v5 tenant stage-to-main publication. An exact post-rename
 * shape is accepted on UNKNOWN retry; foreign or mixed shapes are refused. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_publish_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Recheck the exact tenant post-PUBLISH shape and durably sync its directory
 * before advancing the selected journal entry to FINALIZE. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_sync_publish_dir_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Reserve every replacement UUID after all tenant graphs have durable
 * post-publish shapes. Proves each proposed companion name is absent under
 * the root lease and all graph quiescence, then commits one v6 policy image. */
wyrelog_error_t wyl_fact_offline_restore_tenant_reserve_replacements_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Prove the entire v6 tenant post-publish vector, durably link the selected
 * replacement companion, then advance only its scoped policy phase. A retry
 * reopens and re-syncs an exact dual pair before reporting unchanged replay. */
wyrelog_error_t wyl_fact_offline_restore_tenant_companion_sync_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    const gchar *graph_id, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Prove every tenant graph's exact dual post-publish pair under one root
 * lease and all-graph quiescence, then atomically select the full replacement
 * vector in policy. Leaves old rollback and companion files in place. */
wyrelog_error_t wyl_fact_offline_restore_tenant_select_replacements_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Linux-only, read-only inspection of an imported durable graph mode-A COMMIT
 * state. All lease, resolver, directory, runtime and witness handles remain
 * private and are released on return. Normal mode-A COMMIT admission and
 * recovery remain closed. The callback must not retain inspection pointers;
 * its result is a historical observation, never a mutation permit. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_inspect
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactGraphCommitInspectionFunc callback, gpointer user_data);

/* Recover the companion of an already durable imported graph mode-A
 * COMMIT/PUBLISHED_DURABLE journal. The scoped policy transaction pins the
 * checked authority while the exact A/B filesystem effect and sync run.
 * Success returns an owned companion_synced row; any failure empties output.
 * A failed policy commit may leave the exact dual filesystem shape in place,
 * so retry must reload both durable records and reobserve the full shape.
 * This does not admit COMMIT, finalize, publish policy generations or unseal. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_companion_recover
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylPolicyGraphRestoreReplacementRecord **out_committed);

/* Drive one imported v2 graph COMMIT SYNC_STAGED intent. The journal begin
 * CAS is durable before the exact stage file is synced. A pending UNKNOWN
 * intent is retried only after a fresh provisioned READY capture. Completion
 * requires proven file durability and returns the owned READY/RETAIN journal.
 * Errors leave output empty; retry from a fresh policy handle if a commit
 * response was ambiguous. This neither renames files nor admits COMMIT. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_sync_staged_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Drive one imported graph COMMIT RETAIN intent. A durable begin precedes
 * rename; recovery accepts only an exact provisioned retained shape and
 * proves directory durability before completing the journal. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_retain_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Advance one imported graph COMMIT retained durability operation. Each call
 * completes SYNC_ROLLBACK_FILE or SYNC_RETAIN_DIR and returns the next journal
 * state. PUBLISH is left for a separate publication driver. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_sync_retained_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Advance one imported graph COMMIT PUBLISH or SYNC_PUBLISH_DIR operation.
 * The exact post-publish shape is proved before journal completion. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_publish_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Select the imported replacement in one sealed policy transaction after
 * proving the exact dual companion shape under the root lease. Leaves both
 * file pairs in place for selected-authority cleanup. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_select_replacement_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Durable selected-authority FINALIZE: commit UNKNOWN intent before old-pair
 * cleanup, then complete the v3 journal only after exact terminal proof and
 * directory fsync. A failed response requires a fresh policy handle and
 * journal/namespace observation before retry. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_finalize_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Promote a durably FINALIZED selected graph after proving the exact terminal
 * namespace under the root lease and graph quiescence. The terminal proof is
 * repeated inside the fenced policy transaction. On an ambiguous commit
 * response the caller must reopen policy and observe the full tuple. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_promote_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

#ifdef WYL_TEST_HANDLE_SEAMS
void wyl_fact_offline_restore_tenant_commit_retain_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_tenant_commit_sync_rollback_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_tenant_commit_sync_retain_dir_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_tenant_commit_publish_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_tenant_commit_sync_publish_dir_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_tenant_reserve_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, const gchar *, gpointer),
    gpointer data);
void wyl_fact_offline_restore_tenant_companion_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_graph_commit_companion_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_graph_commit_sync_staged_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_graph_commit_retain_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_graph_commit_sync_retained_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_graph_commit_publish_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
void wyl_fact_offline_restore_graph_commit_finalize_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (const gchar *, gpointer), gpointer data);
#endif

G_END_DECLS

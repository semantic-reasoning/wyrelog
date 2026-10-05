/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/offline-backup-source-private.h"
#include "fact/offline-restore-journal-private.h"
#include "fact/replay-scheduler-private.h"
#include "fact/runtime-private.h"
#include "fact/root-writer-lease-private.h"
#include "policy/store-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

/* Streams a complete tenant-scoped source set into existing journal-bound
 * stages. The caller must establish authenticated manifest provenance before
 * calling; the journal trust marker and canonical preflight do not establish
 * provenance. Graph-scoped journals are rejected before source construction.
 *
 * Source revalidation is a point-in-time check immediately before each stage
 * finish/CAS, not an atomic transaction with the journal mutation. A failure
 * after earlier graphs were committed may leave those stage identities bound;
 * reload the durable journal before recovery. |out_committed| must be
 * zero-initialized or previously cleared and remains empty on failure. */
wyrelog_error_t wyl_fact_offline_restore_tenant_stages_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

/* Graph-local counterpart: only the explicitly selected graph is sourced,
 * drained and staged. A complete canonical tenant manifest is accepted, but
 * its selected artifact must exactly match the singleton graph journal.
 * Requires a confirmed/authenticated pristine unbound journal at revision 1
 * before constructing the source. Bound or preflighted retries are rejected;
 * reload durable state after any ambiguous failure and use recovery, never
 * overwrite an existing stage. The tenant remains sealed and root authority
 * remains exclusive. No publication, verification flags or unseal occurs.
 * Source provenance and point-in-time revalidation limitations above apply.
 * This still sources the existing local main, not an external backup import. */
wyrelog_error_t wyl_fact_offline_restore_graph_stage_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    const gchar *graph_id, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us, WylFactOfflineRestoreJournal *out_committed);

/* Borrowed, authenticated backup input. read_at may return a positive short
 * read; OK with zero bytes means EOF. It must never write more than capacity.
 * revalidate proves the caller's retained source/provenance binding. Neither
 * callback may reenter this coordinator or free its borrowed arguments. */
typedef struct
{
  wyrelog_error_t (*read_at) (guint64 offset, guint8 *buffer, gsize capacity,
      gsize *out_read, gpointer user_data);
  wyrelog_error_t (*revalidate) (gpointer user_data);
} WylFactOfflineRestoreInput;

/* Authenticated tenant backup bundle. Graph IDs are canonical manifest IDs;
 * revalidate must prove the entire bundle remains bound to that manifest.
 * The caller retains provenance authority through this operation. */
typedef struct
{
  wyrelog_error_t (*read_at) (const gchar *graph_id, guint64 offset,
      guint8 *buffer, gsize capacity, gsize *out_read, gpointer user_data);
  wyrelog_error_t (*revalidate) (gpointer user_data);
} WylFactOfflineRestoreTenantInput;

/* Import every tenant graph from external backup bytes into journal-bound
 * stages. Prior successful graph CASes remain durable after a later failure;
 * retry must reload the journal and pass its current revision. Bound stages
 * are reopened and fully checksummed before being skipped. Linux only;
 * other platforms fail closed. No publish or unseal occurs, and an ambiguous
 * CAS requires a fresh policy observation. */
wyrelog_error_t wyl_fact_offline_restore_tenant_import_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    const WylFactOfflineRestoreTenantInput *input, gpointer input_data,
    WylFactOfflineRestoreJournal *out_committed);

/* Replay and durably record preflight for every bound tenant graph. May be
 * called after an import or after restart at the current journal revision.
 * A failed CAS may have committed, so retry only after a fresh journal load.
 * The caller retains manifest provenance; success leaves decision NONE and
 * grants no publication or unseal authority. Must run in a replay job. */
wyrelog_error_t wyl_fact_offline_restore_tenant_preflight_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactReplayJobContext *job_context,
    WylFactOfflineRestoreJournal *out_committed);

/* Imports external backup bytes, never the destination main's contents.
 * Requires a pristine confirmed/authenticated singleton journal at revision 1,
 * an existing provisioned main, and an existing selected runtime entry. The
 * historical source generation and file size may differ from the destination;
 * all destination generations, main identity, store identity and schema must
 * match the journal. Windows fails closed before filesystem/input access.
 *
 * Retains root authority, destination reader guard and selected quiescence.
 * Only after fresh admission checks does it call input or create a stage.
 * Input is bounded to the manifest length plus one EOF byte; checksum,
 * readback, flush and exact identity-binding CAS use the journal-stage API.
 * Success returns revision 2, no verification flags or COMMIT/publication.
 * The coordinator never explicitly opens admission or unseals policy.
 * Quiescence release restores admission as observed at acquisition: a
 * concurrent reopen before acquisition can leave admission OPEN on cleanup.
 * No sibling runtime is touched.
 *
 * Source/destination checks immediately precede finish, not an atomic policy
 * transaction with CAS. Retained guards do not freeze independent policy or
 * external filesystem writers; destination revalidation does not rescan all
 * newly introduced sidecars or hash main contents. Caller must authenticate
 * provenance before invocation; durable trust markers are assertions only.
 * Failure clears output but preserves recovery-owned stages; ambiguous CAS
 * requires reload through a healthy handle. Bound/orphan retries never
 * overwrite. out_committed must be zero-initialized or previously cleared. */
wyrelog_error_t wyl_fact_offline_restore_graph_import_run
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    const gchar *graph_id, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us, const WylFactOfflineRestoreInput *input,
    gpointer input_data, WylFactOfflineRestoreJournal *out_committed);

#ifdef WYL_TEST_HANDLE_SEAMS
/* The staging match between a backup source, its manifest artifact and its
 * journal graph (#1348). */
gboolean wyl_fact_offline_restore_source_artifact_matches_for_test
  (const WylFactOfflineBackupSourceArtifact * source,
    const WylFactOfflineBackupArtifact * manifest,
    const WylFactOfflineRestoreJournalGraph * journal);
/* Construction-to-quiescence race seam; no destination capability escapes. */
void wyl_fact_offline_restore_import_set_checkpoint_for_test
  (wyrelog_error_t (*checkpoint) (gpointer), gpointer user_data);
#endif

G_END_DECLS

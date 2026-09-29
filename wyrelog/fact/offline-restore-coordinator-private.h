/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/offline-backup-source-private.h"
#include "fact/offline-restore-journal-private.h"
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

G_END_DECLS

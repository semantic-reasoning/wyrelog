/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/offline-restore-journal-private.h"
#include "policy/store-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

typedef struct WylFactOfflineRestoreJournalStage
    WylFactOfflineRestoreJournalStage;

/* The session borrows |policy| and owns its exclusive root lease, resolver,
 * journal-derived destination directory, stage, and journal snapshot. It
 * loads but never creates an operation. Expectations come only from that
 * durable journal. |expected_revision| must match exactly and leave room for
 * the journal store's signed-integer CAS revision. A policy/root binding may
 * be established even if a later constructor check fails.
 *
 * Checking confirmation and manifest-trust fields only checks durable
 * assertions; it does not authenticate their provenance. The caller must
 * retain source/lifecycle authority and report producer success truthfully.
 * Operations are serialized and non-reentrant. */
wyrelog_error_t wyl_fact_offline_restore_journal_stage_new
  (wyl_policy_store_t *policy, const gchar *fact_root, GBytes *canonical_manifest,
    const gchar *operation_uuid, const gchar *graph_id,
    guint64 expected_revision,
    WylFactOfflineRestoreJournalStage **out_session);

/* Adapter for a complete sequential producer. Any sink error terminalizes the
 * session, even if the underlying stage could accept a later corrected write.
 * The producer must finish its own authority checks before reporting success
 * to |finish|. */
wyrelog_error_t wyl_fact_offline_restore_journal_stage_sink
  (guint64 offset, const guint8 *bytes, gsize length, gpointer user_data);

/* Every call consumes a live session. |out_committed| must be zero-initialized
 * or cleared; it is cleared on entry and remains zero on failure. Producer
 * failure never finalizes the stage or changes the journal. Success finalizes
 * the checksummed held stage, binds only its observed identity, and CASes the
 * captured journal revision. A failed/ambiguous CAS retains the stage and
 * requires recovery to reload actual durable state. No verification flags,
 * replay, publication, or lifecycle transition are performed. The session
 * retains its exclusive root lease until freed. */
wyrelog_error_t wyl_fact_offline_restore_journal_stage_finish
  (WylFactOfflineRestoreJournalStage *session,
    wyrelog_error_t producer_result,
    WylFactOfflineRestoreJournal *out_committed);

void wyl_fact_offline_restore_journal_stage_free
  (WylFactOfflineRestoreJournalStage *session);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactOfflineRestoreJournalStage,
    wyl_fact_offline_restore_journal_stage_free)

G_END_DECLS

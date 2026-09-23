/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-restore-journal-stage-private.h"

#include <string.h>

#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-locator-private.h"
#include "fact/offline-restore-journal-store-private.h"
#include "fact/offline-restore-stage-private.h"
#include "fact/offline-restore-validation-private.h"
#include "fact/root-writer-lease-private.h"

struct WylFactOfflineRestoreJournalStage
{
  /* Borrowed for the session lifetime. */
  wyl_policy_store_t *policy;
  gchar *fact_root;
  gchar *graph_id;
  WylFactRootWriterLease *lease;
  WylFactGraphResolver resolver;
  WylFactGraphDirectory directory;
  WylFactOfflineRestoreStage *stage;
  WylFactOfflineRestoreJournal journal;
  guint64 expected_revision;
  guint64 expected_bytes;
  wyrelog_error_t sink_error;
  gboolean terminal;
};

static WylFactOfflineRestoreJournalGraph *
journal_graph (WylFactOfflineRestoreJournal *journal, const gchar *graph_id)
{
  if (journal == NULL || journal->graphs == NULL || graph_id == NULL)
    return NULL;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (journal->graphs, i);
    if (g_strcmp0 (graph->graph_id, graph_id) == 0)
      return graph;
  }
  return NULL;
}

static gboolean
identity_zero (const WylFactArtifactInventoryIdentity *identity)
{
  WylFactArtifactInventoryIdentity zero = { 0 };
  return wyl_fact_artifact_inventory_identity_equal (identity, &zero);
}

static gboolean
identity_valid (const WylFactArtifactInventoryIdentity *identity)
{
  return wyl_fact_artifact_inventory_identity_equal (identity, identity)
         && !identity_zero (identity);
}

static gboolean
graph_is_pristine (const WylFactOfflineRestoreJournalGraph *graph)
{
  return graph != NULL
         && !graph->copied
         && !graph->checksum_verified
         && !graph->identity_verified
         && !graph->schema_verified
         && !graph->replay_preflighted
         && graph->transition_state
         == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
         && graph->next_op
         == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
         && !graph->transition_terminal
         && graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
         && graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
         && !graph->resume_forbidden
         && !graph->durability_unprovable_acknowledged;
}

static gboolean
journal_is_staging (const WylFactOfflineRestoreJournal *journal,
    guint64 expected_revision)
{
  if (journal == NULL || journal->graphs == NULL
      || journal->revision != expected_revision
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal->policy_generation_published
      || journal->lifecycle_handoff_complete
      || journal->confirmation
      != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust
      != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal->graphs->len == 0
      || journal->graphs->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS)
    return FALSE;

  guint bound_graphs = 0;
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph = g_ptr_array_index
          (journal->graphs, i);
    if (!graph_is_pristine (graph))
      return FALSE;
    if (identity_zero (&graph->staged_main_identity))
      continue;
    if (!identity_valid (&graph->staged_main_identity))
      return FALSE;
    bound_graphs++;
  }
  return expected_revision == 1 + bound_graphs;
}

static wyrelog_error_t
session_authority_revalidate (WylFactOfflineRestoreJournalStage *session)
{
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (session->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (&session->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (session->lease,
            &session->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (session->policy,
            session->fact_root, session->lease);
  return rc;
}

static void
session_clear (WylFactOfflineRestoreJournalStage *session)
{
  if (session == NULL)
    return;
  /* The stage borrows the directory and lease; release it first. */
  if (session->stage != NULL) {
    wyl_fact_offline_restore_stage_free (session->stage);
    session->stage = NULL;
  }
#ifdef G_OS_WIN32
  if (session->directory.graph_handle != NULL)
#else
  if (session->directory.graph_fd >= 0)
#endif
    wyl_fact_graph_directory_clear (&session->directory);
#ifdef G_OS_WIN32
  if (session->resolver.handle != NULL)
#else
  if (session->resolver.fd >= 0)
#endif
    wyl_fact_graph_resolver_clear (&session->resolver);
  g_clear_pointer (&session->lease, wyl_fact_root_writer_lease_release);
  wyl_fact_offline_restore_journal_clear (&session->journal);
  g_clear_pointer (&session->graph_id, g_free);
  g_clear_pointer (&session->fact_root, g_free);
  g_free (session);
}

static wyrelog_error_t
constructor_fail (WylFactOfflineRestoreJournalStage *session,
    wyrelog_error_t rc)
{
  session_clear (session);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_stage_new (wyl_policy_store_t *policy,
    const gchar *fact_root, GBytes *canonical_manifest,
    const gchar *operation_uuid, const gchar *graph_id,
    guint64 expected_revision,
    WylFactOfflineRestoreJournalStage **out_session)
{
  if (out_session != NULL)
    *out_session = NULL;
  if (policy == NULL || fact_root == NULL || fact_root[0] == '\0'
      || canonical_manifest == NULL
      || operation_uuid == NULL || graph_id == NULL || out_session == NULL
      || expected_revision == 0 || expected_revision >= G_MAXINT64)
    return WYRELOG_E_INVALID;

  WylFactOfflineRestoreJournalStage *session = g_try_new0
        (WylFactOfflineRestoreJournalStage, 1);
  if (session == NULL)
    return WYRELOG_E_NOMEM;
  session->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  session->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  session->policy = policy;
  session->expected_revision = expected_revision;
  session->fact_root = g_strdup (fact_root);
  session->graph_id = g_strdup (graph_id);
  if (session->fact_root == NULL || session->graph_id == NULL)
    return constructor_fail (session, WYRELOG_E_NOMEM);

  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root,
          &session->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &session->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (session->lease,
            &session->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root,
            session->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_load (policy, operation_uuid,
            &session->journal);
  if (rc != WYRELOG_E_OK)
    return constructor_fail (session, rc);

  if (session->journal.revision != expected_revision)
    return constructor_fail (session, WYRELOG_E_BUSY);
  if (!journal_is_staging (&session->journal, expected_revision))
    return constructor_fail (session, WYRELOG_E_POLICY);
  if (wyl_fact_offline_restore_manifest_preflight (canonical_manifest,
      &session->journal) != WYRELOG_E_OK)
    return constructor_fail (session, WYRELOG_E_POLICY);
  WylFactOfflineRestoreJournalGraph *graph = journal_graph (&session->journal,
          graph_id);
  if (graph == NULL
      || (session->journal.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      && g_strcmp0 (session->journal.selected_graph_id, graph_id) != 0))
    return constructor_fail (session, WYRELOG_E_NOT_FOUND);
  if (!identity_zero (&graph->staged_main_identity))
    return constructor_fail (session, WYRELOG_E_POLICY);

  WylFactGraphLocator locator = { 0 };
  rc = wyl_fact_graph_locator_init (&locator, session->journal.tenant_id,
          graph->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&session->resolver,
            &locator, FALSE, &session->directory);
  wyl_fact_graph_locator_clear (&locator);
  if (rc == WYRELOG_E_OK)
    rc = session_authority_revalidate (session);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_new (&session->resolver,
            &session->directory, session->lease,
            session->journal.operation_uuid, graph->logical_bytes,
            graph->checksum, &session->stage);
  if (rc != WYRELOG_E_OK)
    return constructor_fail (session, rc);

  session->expected_bytes = graph->logical_bytes;
  *out_session = session;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_stage_sink (guint64 offset,
    const guint8 *bytes, gsize length, gpointer user_data)
{
  WylFactOfflineRestoreJournalStage *session = user_data;
  if (session == NULL || session->terminal || session->sink_error != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_offline_restore_stage_sink (offset, bytes,
          length, session->stage);
  if (rc != WYRELOG_E_OK)
    session->sink_error = rc;
  return rc;
}

static wyrelog_error_t
store_result_error (WylFactOfflineRestoreStoreResult result)
{
  switch (result) {
    case WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED:
    case WYL_FACT_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY:
      return WYRELOG_E_OK;
    case WYL_FACT_OFFLINE_RESTORE_STORE_STALE:
      return WYRELOG_E_BUSY;
    case WYL_FACT_OFFLINE_RESTORE_STORE_NOT_FOUND:
      return WYRELOG_E_NOT_FOUND;
    case WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT:
    default:
      return WYRELOG_E_CONFLICT;
  }
}

wyrelog_error_t
wyl_fact_offline_restore_journal_stage_finish
  (WylFactOfflineRestoreJournalStage *session,
    wyrelog_error_t producer_result,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_committed != NULL)
    wyl_fact_offline_restore_journal_clear (out_committed);
  if (session == NULL || session->terminal)
    return WYRELOG_E_INVALID;
  session->terminal = TRUE;
  if (out_committed == NULL)
    return WYRELOG_E_INVALID;
  if (session->sink_error != WYRELOG_E_OK)
    return session->sink_error;
  if (producer_result != WYRELOG_E_OK)
    return producer_result;

  wyrelog_error_t rc = session_authority_revalidate (session);
  guint64 bytes_written = 0;
  WylFactArtifactInventoryIdentity identity = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_stage_finalize (session->stage,
            &bytes_written, &identity);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (bytes_written != session->expected_bytes)
    return WYRELOG_E_POLICY;

  WylFactOfflineRestoreJournalGraph *graph = journal_graph
        (&session->journal, session->graph_id);
  if (graph == NULL)
    return WYRELOG_E_INTERNAL;
  rc = wyl_fact_offline_restore_journal_bind_staged_identity
        (&session->journal, session->graph_id, &identity);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (GBytes) desired_bytes = NULL;
  rc = wyl_fact_offline_restore_journal_encode (&session->journal,
          &desired_bytes);
  WylFactOfflineRestoreStoreResult store_result =
      WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  WylFactOfflineRestoreJournal committed = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_restore_journal_store_cas (session->policy,
            session->expected_revision, &session->journal, &store_result,
            &committed);
  if (rc == WYRELOG_E_OK)
    rc = store_result_error (store_result);
  if (rc == WYRELOG_E_OK) {
    g_autoptr (GBytes) committed_bytes = NULL;
    rc = wyl_fact_offline_restore_journal_encode (&committed,
            &committed_bytes);
    if (rc == WYRELOG_E_OK
        && (committed.revision != session->expected_revision + 1
        || !g_bytes_equal (desired_bytes, committed_bytes)))
      rc = WYRELOG_E_POLICY;
  }
  if (rc != WYRELOG_E_OK) {
    wyl_fact_offline_restore_journal_clear (&committed);
    return rc;
  }
  /* The finalized orphan is recovery-owned now, not a stage object the
   * destructor may attempt to interpret as an open name/descriptor pair. */
  *out_committed = committed;
  memset (&committed, 0, sizeof committed);
  /* Finalization leaves the operation-named stage as a recovery-owned
   * orphan. Destroy the in-memory wrapper but never remove the file. */
  return WYRELOG_E_OK;
}

void
wyl_fact_offline_restore_journal_stage_free
  (WylFactOfflineRestoreJournalStage *session)
{
  session_clear (session);
}

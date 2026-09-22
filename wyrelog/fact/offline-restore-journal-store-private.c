/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-journal-store-private.h"

#include <string.h>

static void
journal_free (WylFactOfflineRestoreJournal *journal)
{
  if (journal == NULL)
    return;
  wyl_fact_offline_restore_journal_clear (journal);
  g_free (journal);
}

static WylFactOfflineRestoreStoreResult
map_result (WylPolicyOfflineRestoreStoreResult result)
{
  switch (result) {
    case WYL_POLICY_OFFLINE_RESTORE_STORE_APPLIED:
      return WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED;
    case WYL_POLICY_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY:
      return WYL_FACT_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY;
    case WYL_POLICY_OFFLINE_RESTORE_STORE_CONFLICT:
      return WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
    case WYL_POLICY_OFFLINE_RESTORE_STORE_STALE:
      return WYL_FACT_OFFLINE_RESTORE_STORE_STALE;
    case WYL_POLICY_OFFLINE_RESTORE_STORE_NOT_FOUND:
      return WYL_FACT_OFFLINE_RESTORE_STORE_NOT_FOUND;
    default:
      return WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  }
}

static gboolean
identity_zero (const WylFactArtifactInventoryIdentity *identity)
{
  return identity != NULL
         && (identity->object_width == 0 || identity->object_width == 16)
         && identity->domain == 0 && identity->object == 0
         && memcmp (identity->object_bytes, (guint8[16]) { 0 }, 16) == 0;
}

static gboolean
pristine (const WylFactOfflineRestoreJournal *journal)
{
  if (journal == NULL || journal->revision != 1
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal->policy_generation_published
      || journal->lifecycle_handoff_complete || journal->graphs == NULL)
    return FALSE;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (graph == NULL || !identity_zero (&graph->staged_main_identity)
        || graph->copied
        || graph->checksum_verified || graph->identity_verified
        || graph->schema_verified || graph->replay_preflighted
        || graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || graph->next_op
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
        || graph->transition_terminal
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
        || graph->resume_forbidden
        || graph->durability_unprovable_acknowledged)
      return FALSE;
  }
  return TRUE;
}

static wyrelog_error_t
record_from_journal (const WylFactOfflineRestoreJournal *journal,
    WylPolicyOfflineRestoreRecord *out_record)
{
  *out_record = (WylPolicyOfflineRestoreRecord) { 0 };
  if (journal == NULL || journal->revision == 0
      || journal->revision > G_MAXINT64 || journal->graphs == NULL)
    return WYRELOG_E_POLICY;
  GBytes *encoded = NULL;
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_encode (journal,
          &encoded);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactOfflineRestoreJournal decoded = { 0 };
  rc = wyl_fact_offline_restore_journal_decode (encoded, &decoded);
  if (rc != WYRELOG_E_OK) {
    g_bytes_unref (encoded);
    return rc;
  }
  GBytes *canonical = NULL;
  rc = wyl_fact_offline_restore_journal_encode (&decoded, &canonical);
  if (rc != WYRELOG_E_OK || !g_bytes_equal (encoded, canonical))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    out_record->operation_uuid = decoded.operation_uuid;
    decoded.operation_uuid = NULL;
    out_record->tenant_id = decoded.tenant_id;
    decoded.tenant_id = NULL;
    out_record->scope = decoded.scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT ?
        WYL_POLICY_OFFLINE_RESTORE_SCOPE_TENANT :
        WYL_POLICY_OFFLINE_RESTORE_SCOPE_GRAPH;
    out_record->selected_graph_id = decoded.selected_graph_id;
    decoded.selected_graph_id = NULL;
    out_record->revision = decoded.revision;
    memcpy (out_record->manifest_sha256, decoded.manifest_sha256, 32);
    out_record->graph_count = decoded.graphs->len;
    out_record->journal_blob = g_bytes_ref (canonical);
  }
  g_clear_pointer (&canonical, g_bytes_unref);
  g_bytes_unref (encoded);
  wyl_fact_offline_restore_journal_clear (&decoded);
  return rc;
}

static void
record_clear (WylPolicyOfflineRestoreRecord *record)
{
  g_free (record->operation_uuid);
  g_free (record->tenant_id);
  g_free (record->selected_graph_id);
  g_clear_pointer (&record->journal_blob, g_bytes_unref);
  *record = (WylPolicyOfflineRestoreRecord) { 0 };
}

static wyrelog_error_t
decode_record (const WylPolicyOfflineRestoreRecord *record,
    WylFactOfflineRestoreJournal *out_journal)
{
  memset (out_journal, 0, sizeof *out_journal);
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_decode
        (record->journal_blob, out_journal);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylPolicyOfflineRestoreRecord derived = { 0 };
  rc = record_from_journal (out_journal, &derived);
  gboolean matches = rc == WYRELOG_E_OK
      && g_strcmp0 (derived.operation_uuid, record->operation_uuid) == 0
      && g_strcmp0 (derived.tenant_id, record->tenant_id) == 0
      && derived.scope == record->scope
      && g_strcmp0 (derived.selected_graph_id,
          record->selected_graph_id) == 0
      && derived.revision == record->revision
      && memcmp (derived.manifest_sha256, record->manifest_sha256, 32) == 0
      && derived.graph_count == record->graph_count
      && g_bytes_equal (derived.journal_blob, record->journal_blob);
  record_clear (&derived);
  if (!matches) {
    wyl_fact_offline_restore_journal_clear (out_journal);
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_store_load (wyl_policy_store_t *store,
    const gchar *operation_uuid, WylFactOfflineRestoreJournal *out_journal)
{
  if (out_journal == NULL)
    return WYRELOG_E_INVALID;
  memset (out_journal, 0, sizeof *out_journal);
  WylPolicyOfflineRestoreRecord *record = NULL;
  wyrelog_error_t rc = wyl_policy_store_offline_restore_load
        (store, operation_uuid, &record);
  if (rc == WYRELOG_E_OK)
    rc = decode_record (record, out_journal);
  wyl_policy_offline_restore_record_free (record);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_store_create (wyl_policy_store_t *store,
    const WylFactOfflineRestoreJournal *journal,
    WylFactOfflineRestoreStoreResult *out_result,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_result != NULL)
    *out_result = WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  if (out_committed != NULL)
    memset (out_committed, 0, sizeof *out_committed);
  if (store == NULL || !pristine (journal) || out_result == NULL
      || out_committed == NULL)
    return WYRELOG_E_INVALID;
  WylPolicyOfflineRestoreRecord record = { 0 };
  wyrelog_error_t rc = record_from_journal (journal, &record);
  WylPolicyOfflineRestoreRecord *committed = NULL;
  WylPolicyOfflineRestoreStoreResult result;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_create (store, &record, &result,
            &committed);
  if (rc == WYRELOG_E_OK) {
    *out_result = map_result (result);
    if (committed != NULL)
      rc = decode_record (committed, out_committed);
  }
  wyl_policy_offline_restore_record_free (committed);
  record_clear (&record);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_store_cas (wyl_policy_store_t *store,
    guint64 expected_revision, const WylFactOfflineRestoreJournal *desired,
    WylFactOfflineRestoreStoreResult *out_result,
    WylFactOfflineRestoreJournal *out_committed)
{
  if (out_result != NULL)
    *out_result = WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  if (out_committed != NULL)
    memset (out_committed, 0, sizeof *out_committed);
  if (store == NULL || desired == NULL || out_result == NULL
      || out_committed == NULL || expected_revision == 0
      || expected_revision >= G_MAXINT64
      || desired->revision != expected_revision + 1)
    return WYRELOG_E_INVALID;
  WylFactOfflineRestoreJournal current = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (store,
          desired->operation_uuid, &current);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (current.revision != expected_revision) {
    *out_result = WYL_FACT_OFFLINE_RESTORE_STORE_STALE;
    *out_committed = current;
    return WYRELOG_E_OK;
  }
  if (!wyl_fact_offline_restore_journal_is_legal_successor (&current,
      desired)) {
    wyl_fact_offline_restore_journal_clear (&current);
    return WYRELOG_E_POLICY;
  }
  wyl_fact_offline_restore_journal_clear (&current);
  WylPolicyOfflineRestoreRecord record = { 0 };
  rc = record_from_journal (desired, &record);
  WylPolicyOfflineRestoreRecord *committed = NULL;
  WylPolicyOfflineRestoreStoreResult result;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_cas (store, expected_revision,
            &record, &result, &committed);
  if (rc == WYRELOG_E_OK) {
    *out_result = map_result (result);
    if (committed != NULL)
      rc = decode_record (committed, out_committed);
  }
  wyl_policy_offline_restore_record_free (committed);
  record_clear (&record);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_store_release (wyl_policy_store_t *store,
    guint64 expected_revision, const gchar *operation_uuid,
    WylFactOfflineRestoreStoreResult *out_result)
{
  if (out_result != NULL)
    *out_result = WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT;
  if (store == NULL || operation_uuid == NULL || expected_revision == 0
      || out_result == NULL)
    return WYRELOG_E_INVALID;
  WylFactOfflineRestoreJournal journal = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (store,
          operation_uuid, &journal);
  if (rc == WYRELOG_E_NOT_FOUND) {
    *out_result = WYL_FACT_OFFLINE_RESTORE_STORE_NOT_FOUND;
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  if (journal.revision != expected_revision) {
    *out_result = WYL_FACT_OFFLINE_RESTORE_STORE_STALE;
    wyl_fact_offline_restore_journal_clear (&journal);
    return WYRELOG_E_OK;
  }
  if (wyl_fact_offline_restore_journal_recovery (&journal)
      != WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE) {
    wyl_fact_offline_restore_journal_clear (&journal);
    return WYRELOG_E_POLICY;
  }
  WylPolicyOfflineRestoreRecord record = { 0 };
  rc = record_from_journal (&journal, &record);
  wyl_fact_offline_restore_journal_clear (&journal);
  WylPolicyOfflineRestoreStoreResult result;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_offline_restore_release (store, &record, &result);
  if (rc == WYRELOG_E_OK)
    *out_result = map_result (result);
  record_clear (&record);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_store_list (wyl_policy_store_t *store,
    const gchar *tenant_id, guint limit, GPtrArray **out_journals)
{
  if (out_journals != NULL)
    *out_journals = NULL;
  if (store == NULL || out_journals == NULL)
    return WYRELOG_E_INVALID;
  GPtrArray *records = NULL;
  wyrelog_error_t rc = wyl_policy_store_offline_restore_list (store,
          tenant_id, limit, &records);
  if (rc != WYRELOG_E_OK)
    return rc;
  GPtrArray *journals = g_ptr_array_new_with_free_func
        ((GDestroyNotify) journal_free);
  for (guint i = 0; i < records->len; i++) {
    WylFactOfflineRestoreJournal *journal =
        g_new0 (WylFactOfflineRestoreJournal, 1);
    rc = decode_record (g_ptr_array_index (records, i), journal);
    if (rc != WYRELOG_E_OK) {
      journal_free (journal);
      break;
    }
    g_ptr_array_add (journals, journal);
  }
  g_ptr_array_unref (records);
  if (rc != WYRELOG_E_OK) {
    g_ptr_array_unref (journals);
    return rc;
  }
  *out_journals = journals;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_record (const WylPolicyOfflineRestoreRecord *record,
    G_GNUC_UNUSED gpointer user_data)
{
  WylFactOfflineRestoreJournal journal = { 0 };
  wyrelog_error_t rc = decode_record (record, &journal);
  wyl_fact_offline_restore_journal_clear (&journal);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_store_validate (wyl_policy_store_t *store)
{
  return wyl_policy_store_offline_restore_foreach (store, validate_record,
             NULL);
}

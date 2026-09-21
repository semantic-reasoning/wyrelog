/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-validation-private.h"

#include <string.h>

#include "fact/store-identity-types-private.h"
#include "wyl-id-private.h"

static gboolean
bounded_text (const gchar *text)
{
  if (text == NULL)
    return FALSE;
  gsize length = 0;
  while (length <= WYL_FACT_OFFLINE_RESTORE_MAX_TEXT
      && text[length] != '\0')
    length++;
  return length > 0 && length <= WYL_FACT_OFFLINE_RESTORE_MAX_TEXT
         && g_utf8_validate (text, length, NULL);
}

static gboolean
canonical_uuid (const gchar *text)
{
  if (text == NULL)
    return FALSE;
  for (guint i = 0; i < 36; i++)
    if (text[i] == '\0')
      return FALSE;
  if (text[36] != '\0')
    return FALSE;
  wyl_id_t id;
  gchar canonical[WYL_ID_STRING_BUF];
  return wyl_id_parse (text, &id) == WYRELOG_E_OK
         && wyl_id_format (&id, canonical, sizeof canonical) == WYRELOG_E_OK
         && g_strcmp0 (text, canonical) == 0;
}

static gboolean
canonical_sha256 (const gchar *text)
{
  if (text == NULL || strlen (text) != 71
      || !g_str_has_prefix (text, "sha256:"))
    return FALSE;
  for (guint i = 7; i < 71; i++)
    if (!g_ascii_isdigit (text[i])
        && !(text[i] >= 'a' && text[i] <= 'f'))
      return FALSE;
  return TRUE;
}

static gboolean
identity_representation_valid
  (const WylFactArtifactInventoryIdentity *identity)
{
  if (identity == NULL
      || (identity->object_width != 0 && identity->object_width != 16))
    return FALSE;
  return identity->object_width == 16 ? identity->object == 0 :
         memcmp (identity->object_bytes, (guint8[16]) { 0 }, 16) == 0;
}

static gboolean
identity_zero (const WylFactArtifactInventoryIdentity *identity)
{
  return identity_representation_valid (identity)
         && identity->domain == 0 && identity->object == 0
         && memcmp (identity->object_bytes, (guint8[16]) { 0 }, 16) == 0;
}

static gboolean
identity_valid (const WylFactArtifactInventoryIdentity *identity)
{
  return identity_representation_valid (identity) && !identity_zero (identity);
}

static gboolean
identity_equal (const WylFactArtifactInventoryIdentity *left,
    const WylFactArtifactInventoryIdentity *right)
{
  if (!identity_representation_valid (left)
      || !identity_representation_valid (right)
      || left->domain != right->domain
      || left->object_width != right->object_width)
    return FALSE;
  return left->object_width == 0 ? left->object == right->object :
         memcmp (left->object_bytes, right->object_bytes, 16) == 0;
}

static gboolean
observation_valid (const WylFactArtifactInventoryObservation *observation)
{
  return observation != NULL
         && identity_valid (&observation->directory_identity)
         && identity_valid (&observation->guard_identity)
         && observation->entry_fingerprint != 0;
}

static gboolean
observation_equal (const WylFactArtifactInventoryObservation *left,
    const WylFactArtifactInventoryObservation *right)
{
  return observation_valid (left) && observation_valid (right)
         && identity_equal (&left->directory_identity,
             &right->directory_identity)
         && identity_equal (&left->guard_identity, &right->guard_identity)
         && left->entry_fingerprint == right->entry_fingerprint;
}

static void
result_init (WylFactOfflineRestoreValidationResult *result)
{
  if (result == NULL)
    return;
  memset (result, 0, sizeof *result);
  result->graph_index = G_MAXUINT;
}

static WylFactOfflineRestoreValidationStatus
blocked (WylFactOfflineRestoreValidationResult *result,
    WylFactOfflineRestoreValidationFailure failure, guint graph_index,
    guint checked)
{
  if (result != NULL) {
    result->status = WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED;
    result->failure = failure;
    result->graph_index = graph_index;
    result->checked_graph_count = checked;
    result->validated_revision = 0;
    result->pending_checks = WYL_FACT_OFFLINE_RESTORE_PENDING_NONE;
  }
  return WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED;
}

static WylFactOfflineRestoreValidationFailure
admission_failure (WylFactOfflineRestoreConflict conflict)
{
  switch (conflict) {
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_CONFIRMATION:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_CONFIRMATION;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_MANIFEST_TRUST:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_MANIFEST_TRUST;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_TARGET_NOT_SEALED:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_NOT_SEALED;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_TARGET_NOT_DRAINED:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_NOT_DRAINED;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_AUTHORITY:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_AUTHORITY;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_MAPPING:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_MAPPING;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_GENERATION:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_GENERATION;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_INVENTORY:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_INVENTORY;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_UNKNOWN_ARTIFACT:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_UNKNOWN_ARTIFACT;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_FOREIGN_OPERATION:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_FOREIGN_OPERATION;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_FOREIGN_MAIN:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_FOREIGN_MAIN;
    case WYL_FACT_OFFLINE_RESTORE_CONFLICT_NONE:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_NONE;
    default:
      return WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_AUTHORITY;
  }
}

static gboolean
admission_input_valid (WylFactOfflineRestoreValidationMode mode,
    const WylFactOfflineRestoreAdmissionEvidence *admission)
{
  if (admission == NULL || !canonical_uuid (admission->operation_uuid)
      || !bounded_text (admission->tenant_id)
      || (admission->selected_graph_id != NULL
      && !bounded_text (admission->selected_graph_id))
      || admission->graphs == NULL || admission->graphs->len == 0
      || admission->graphs->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS)
    return FALSE;
  for (guint i = 0; i < admission->graphs->len; i++) {
    const WylFactOfflineRestoreAdmissionGraphEvidence *graph =
        g_ptr_array_index ((GPtrArray *) admission->graphs, i);
    if (graph == NULL || !bounded_text (graph->graph_id)
        || !identity_representation_valid (&graph->expected_main_identity)
        || (mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN
        ? !identity_zero (&graph->staged_main_identity)
        : !identity_valid (&graph->staged_main_identity)))
      return FALSE;
  }
  return TRUE;
}

static gboolean
journal_phase_valid (WylFactOfflineRestoreValidationMode mode,
    const WylFactOfflineRestoreJournal *journal)
{
  if (journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || journal->policy_generation_published
      || journal->lifecycle_handoff_complete)
    return FALSE;
  if ((mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN
      && journal->revision != 1)
      || (mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED
      && journal->revision != 1 + journal->graphs->len))
    return FALSE;
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || graph->next_op
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
        || graph->transition_terminal || graph->resume_forbidden
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE
        || graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        || graph->copied || graph->checksum_verified
        || graph->identity_verified || graph->schema_verified
        || graph->replay_preflighted)
      return FALSE;
    if (mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN
        ? !identity_zero (&graph->staged_main_identity)
        : !identity_valid (&graph->staged_main_identity))
      return FALSE;
  }
  return TRUE;
}

static void
sha256 (GBytes *bytes, guint8 out[32])
{
  gsize length = 0;
  const guint8 *data = g_bytes_get_data (bytes, &length);
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, data, length);
  gsize digest_length = 32;
  g_checksum_get_digest (checksum, out, &digest_length);
}

static const WylFactOfflineBackupArtifact *
selected_manifest_artifact (const WylFactOfflineBackupManifest *manifest,
    const WylFactOfflineRestoreJournal *journal, guint index)
{
  if (journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT)
    return g_ptr_array_index (manifest->artifacts, index);
  for (guint i = 0; i < manifest->artifacts->len; i++) {
    const WylFactOfflineBackupArtifact *artifact =
        g_ptr_array_index (manifest->artifacts, i);
    if (g_strcmp0 (artifact->graph_id, journal->selected_graph_id) == 0)
      return artifact;
  }
  return NULL;
}

static gboolean
manifest_matches_journal (const WylFactOfflineBackupManifest *manifest,
    const WylFactOfflineRestoreJournal *journal)
{
  if (g_strcmp0 (manifest->tenant_id, journal->tenant_id) != 0
      || manifest->policy_generation
      != journal->source_tenant_lifecycle_generation
      || (journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && manifest->artifacts->len != journal->graphs->len))
    return FALSE;
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    const WylFactOfflineBackupArtifact *artifact =
        selected_manifest_artifact (manifest, journal, i);
    if (artifact == NULL || g_strcmp0 (artifact->graph_id, graph->graph_id) != 0
        || g_strcmp0 (artifact->store_uuid, graph->store_uuid) != 0
        || artifact->format_version != graph->format_version
        || artifact->path_encoding_version != graph->path_encoding_version
        || g_strcmp0 (artifact->schema_digest, graph->schema_digest) != 0
        || artifact->logical_bytes != graph->logical_bytes
        || artifact->physical_bytes != graph->physical_bytes
        || g_strcmp0 (artifact->checksum, graph->checksum) != 0)
      return FALSE;
  }
  return TRUE;
}

WylFactOfflineRestoreValidationStatus
wyl_fact_offline_restore_validate (WylFactOfflineRestoreValidationMode mode,
    GBytes *canonical_manifest, const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreAdmissionEvidence *admission,
    const GPtrArray *staged,
    WylFactOfflineRestoreValidationResult *out_result)
{
  result_init (out_result);
  gsize manifest_length = canonical_manifest == NULL ? 0 :
      g_bytes_get_size (canonical_manifest);
  if (out_result == NULL || canonical_manifest == NULL || journal == NULL
      || admission == NULL
      || (mode != WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN
      && mode != WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED)
      || manifest_length == 0
      || manifest_length > WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES
      || (mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN
      && staged != NULL)
      || (mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED
      && (staged == NULL
      || staged->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS)))
    return blocked (out_result,
               WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT,
               G_MAXUINT, 0);
  if (!admission_input_valid (mode, admission))
    return blocked (out_result,
               WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT,
               G_MAXUINT, 0);
  if (mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED)
    for (guint i = 0; i < staged->len; i++) {
      const WylFactOfflineRestoreStagedObservation *observation =
          g_ptr_array_index ((GPtrArray *) staged, i);
      if (observation == NULL || !bounded_text (observation->operation_uuid)
          || !bounded_text (observation->graph_id)
          || !bounded_text (observation->checksum)
          || !bounded_text (observation->tenant_id)
          || !bounded_text (observation->metadata_graph_id)
          || !bounded_text (observation->store_uuid)
          || !bounded_text (observation->schema_digest)
          || !bounded_text (observation->replay_schema_digest))
        return blocked (out_result,
                   WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT, i, 0);
    }

  g_autoptr (GBytes) encoded_journal = NULL;
  if (wyl_fact_offline_restore_journal_encode (journal, &encoded_journal)
      != WYRELOG_E_OK)
    return blocked (out_result,
               WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_JOURNAL_INVALID,
               G_MAXUINT, 0);
  if (!journal_phase_valid (mode, journal))
    return blocked (out_result,
               WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_JOURNAL_PHASE,
               G_MAXUINT, 0);

  WylFactOfflineBackupManifest manifest = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_backup_manifest_decode
        (canonical_manifest, &manifest);
  g_autoptr (GBytes) reencoded = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_manifest_encode (&manifest, &reencoded);
  if (rc != WYRELOG_E_OK || !g_bytes_equal (canonical_manifest, reencoded)) {
    wyl_fact_offline_backup_manifest_clear (&manifest);
    return blocked (out_result,
               WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_INVALID,
               G_MAXUINT, 0);
  }
  guint8 manifest_digest[32];
  sha256 (canonical_manifest, manifest_digest);
  if (memcmp (manifest_digest, journal->manifest_sha256, 32) != 0
      || !manifest_matches_journal (&manifest, journal)) {
    wyl_fact_offline_backup_manifest_clear (&manifest);
    return blocked (out_result,
               WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_BINDING,
               G_MAXUINT, 0);
  }
  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (graph->format_version != WYL_FACT_STORE_FORMAT_VERSION) {
      wyl_fact_offline_backup_manifest_clear (&manifest);
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FORMAT_UNSUPPORTED,
                 i, i);
    }
    if (graph->path_encoding_version
        != WYL_FACT_STORE_PATH_ENCODING_VERSION) {
      wyl_fact_offline_backup_manifest_clear (&manifest);
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_PATH_UNSUPPORTED,
                 i, i);
    }
    if (!canonical_uuid (graph->store_uuid)
        || !canonical_sha256 (graph->checksum)
        || !canonical_sha256 (graph->schema_digest)) {
      wyl_fact_offline_backup_manifest_clear (&manifest);
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_INVALID,
                 i, i);
    }
  }
  wyl_fact_offline_backup_manifest_clear (&manifest);

  WylFactOfflineRestoreConflict conflict =
      wyl_fact_offline_restore_classify_admission (journal, admission);
  if (conflict != WYL_FACT_OFFLINE_RESTORE_CONFLICT_NONE)
    return blocked (out_result, admission_failure (conflict), G_MAXUINT, 0);

  if (mode == WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN) {
    out_result->status = WYL_FACT_OFFLINE_RESTORE_VALIDATION_DRY_RUN_VALIDATED;
    out_result->failure = WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_NONE;
    out_result->checked_graph_count = journal->graphs->len;
    out_result->validated_revision = journal->revision;
    out_result->pending_checks = WYL_FACT_OFFLINE_RESTORE_PENDING_ALL;
    return out_result->status;
  }
  if (staged->len != journal->graphs->len)
    return blocked (out_result,
               WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_CARDINALITY,
               G_MAXUINT, 0);

  for (guint i = 0; i < journal->graphs->len; i++) {
    const WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    const WylFactOfflineRestoreStagedObservation *observation =
        g_ptr_array_index ((GPtrArray *) staged, i);
    if (g_strcmp0 (observation->operation_uuid, journal->operation_uuid) != 0
        || g_strcmp0 (observation->graph_id, graph->graph_id) != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_ORDER, i, i);
    if (!observation_equal (&observation->inventory_start,
        &observation->inventory_end))
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVENTORY_UNSTABLE,
                 i, i);
    if (observation->operation_owned_stages != 1)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_POPULATION,
                 i, i);
    if (observation->foreign_restore_stages != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FOREIGN_STAGE, i, i);
    if (observation->unknown_entries != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_UNKNOWN_ENTRY, i, i);
    if (!observation->present)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_MISSING, i, i);
    if (!observation->regular)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_TYPE, i, i);
    if (observation->reparse)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_REPARSE, i, i);
    if (observation->link_count != 1)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_LINK_COUNT, i, i);
    if (observation->owner_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_OWNER, i, i);
    if (!identity_equal (&observation->identity,
        &graph->staged_main_identity)
        || (!graph->expected_main_absent && identity_equal
          (&observation->identity, &graph->expected_main_identity)))
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_IDENTITY, i, i);
    if (observation->logical_bytes != graph->logical_bytes)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_LOGICAL_BYTES, i, i);
    if (!canonical_sha256 (observation->checksum)
        || g_strcmp0 (observation->checksum, graph->checksum) != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_CHECKSUM, i, i);
    if (!canonical_uuid (observation->store_uuid)
        || g_strcmp0 (observation->store_uuid, graph->store_uuid) != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STORE_UUID, i, i);
    if (g_strcmp0 (observation->tenant_id, journal->tenant_id) != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_TENANT, i, i);
    if (g_strcmp0 (observation->metadata_graph_id, graph->graph_id) != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_GRAPH, i, i);
    if (observation->format_version != graph->format_version)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FORMAT, i, i);
    if (observation->path_encoding_version != graph->path_encoding_version)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_PATH, i, i);
    if (!canonical_sha256 (observation->schema_digest)
        || g_strcmp0 (observation->schema_digest, graph->schema_digest) != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_SCHEMA, i, i);
    if (observation->replay_result
        != WYL_FACT_OFFLINE_RESTORE_REPLAY_SUCCEEDED
        || !identity_equal (&observation->replay_identity,
        &graph->staged_main_identity)
        || !canonical_sha256 (observation->replay_schema_digest)
        || g_strcmp0 (observation->replay_schema_digest,
        graph->schema_digest) != 0)
      return blocked (out_result,
                 WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_REPLAY, i, i);
  }

  out_result->status = WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED;
  out_result->failure = WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_NONE;
  out_result->checked_graph_count = journal->graphs->len;
  out_result->validated_revision = journal->revision;
  out_result->pending_checks = WYL_FACT_OFFLINE_RESTORE_PENDING_NONE;
  return out_result->status;
}

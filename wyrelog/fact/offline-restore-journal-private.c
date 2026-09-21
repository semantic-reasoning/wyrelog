/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/offline-restore-journal-private.h"

#include <errno.h>
#include <string.h>

#include "wyl-id-private.h"

static void
journal_graph_free (WylFactOfflineRestoreJournalGraph *graph)
{
  if (graph == NULL)
    return;
  g_free (graph->graph_id);
  g_free (graph->store_uuid);
  g_free (graph->schema_digest);
  g_free (graph->checksum);
  g_free (graph);
}

void
wyl_fact_offline_restore_target_graph_free
  (WylFactOfflineRestoreTargetGraph *graph)
{
  if (graph == NULL)
    return;
  g_free (graph->graph_id);
  g_free (graph);
}

void
wyl_fact_offline_restore_journal_clear (WylFactOfflineRestoreJournal *journal)
{
  if (journal == NULL)
    return;
  g_free (journal->operation_uuid);
  g_free (journal->tenant_id);
  g_free (journal->selected_graph_id);
  g_clear_pointer (&journal->graphs, g_ptr_array_unref);
  memset (journal, 0, sizeof *journal);
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
identity_representation_valid
  (const WylFactArtifactInventoryIdentity *identity)
{
  if (identity == NULL
      || (identity->object_width != 0 && identity->object_width != 16))
    return FALSE;
  return identity->object_width == 16 ?
         identity->object == 0 :
         memcmp (identity->object_bytes, (guint8[16]) { 0 },
             sizeof identity->object_bytes) == 0;
}

static gboolean
identity_is_zero (const WylFactArtifactInventoryIdentity *identity)
{
  return identity_representation_valid (identity)
         && identity->domain == 0 && identity->object == 0
         && memcmp (identity->object_bytes, (guint8[16]) { 0 },
             sizeof identity->object_bytes) == 0;
}

static gboolean
identity_is_valid (const WylFactArtifactInventoryIdentity *identity)
{
  return identity_representation_valid (identity)
         && !identity_is_zero (identity);
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
         memcmp (left->object_bytes, right->object_bytes,
             sizeof left->object_bytes) == 0;
}

static gboolean
parse_u64 (const gchar *text, guint64 *out)
{
  gchar *end = NULL;
  errno = 0;
  guint64 value = g_ascii_strtoull (text, &end, 10);
  if (errno != 0 || end == text || *end != '\0')
    return FALSE;
  *out = value;
  return TRUE;
}

static gboolean
parse_uint (const gchar *text, guint *out)
{
  guint64 value = 0;
  if (!parse_u64 (text, &value) || value > G_MAXUINT)
    return FALSE;
  *out = (guint) value;
  return TRUE;
}

static gchar *
encode_text (const gchar *text)
{
  return g_base64_encode ((const guchar *) text, strlen (text));
}

static gchar *
decode_text (const gchar *text)
{
  gsize length = 0;
  g_autofree guchar *raw = g_base64_decode (text, &length);
  if (raw == NULL || length == 0
      || length > WYL_FACT_OFFLINE_RESTORE_MAX_TEXT
      || memchr (raw, '\0', length) != NULL
      || !g_utf8_validate ((const gchar *) raw, length, NULL))
    return NULL;
  return g_strndup ((const gchar *) raw, length);
}

static void
digest (const guint8 *bytes, gsize length, guint8 out[32])
{
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, bytes, length);
  gsize digest_length = 32;
  g_checksum_get_digest (checksum, out, &digest_length);
  g_assert_cmpuint (digest_length, ==, 32);
}

static gchar *
hex_digest (const guint8 bytes[32])
{
  GString *text = g_string_sized_new (64);
  for (guint i = 0; i < 32; i++)
    g_string_append_printf (text, "%02x", bytes[i]);
  return g_string_free (text, FALSE);
}

static gboolean
parse_hex_digest (const gchar *text, guint8 out[32])
{
  if (text == NULL || strlen (text) != 64)
    return FALSE;
  for (guint i = 0; i < 32; i++) {
    gint high = g_ascii_xdigit_value (text[i * 2]);
    gint low = g_ascii_xdigit_value (text[i * 2 + 1]);
    if (high < 0 || low < 0 || g_ascii_isupper (text[i * 2])
        || g_ascii_isupper (text[i * 2 + 1]))
      return FALSE;
    out[i] = (guint8) ((high << 4) | low);
  }
  return TRUE;
}

static gboolean valid_journal
  (const WylFactOfflineRestoreJournal *journal);

WylFactOfflineRestoreConflict
wyl_fact_offline_restore_classify_admission
  (const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreAdmissionEvidence *evidence)
{
  if (!valid_journal (journal) || evidence == NULL
      || !evidence->exclusive_root_authority)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_AUTHORITY;
  if (g_strcmp0 (evidence->operation_uuid, journal->operation_uuid) != 0
      || g_strcmp0 (evidence->tenant_id, journal->tenant_id) != 0
      || g_strcmp0 (evidence->selected_graph_id,
      journal->selected_graph_id) != 0
      || memcmp (evidence->manifest_sha256, journal->manifest_sha256,
      sizeof journal->manifest_sha256) != 0)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_MAPPING;
  if (evidence->tenant_lifecycle_generation
      != journal->destination_tenant_lifecycle_generation
      || evidence->tenant_reconciliation_generation
      != journal->destination_tenant_reconciliation_generation)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_GENERATION;
  if (evidence->graphs == NULL
      || evidence->graphs->len != journal->graphs->len)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_MAPPING;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *expected =
        g_ptr_array_index (journal->graphs, i);
    WylFactOfflineRestoreAdmissionGraphEvidence *actual =
        g_ptr_array_index ((GPtrArray *) evidence->graphs, i);
    if (actual == NULL || g_strcmp0 (actual->graph_id,
        expected->graph_id) != 0)
      return WYL_FACT_OFFLINE_RESTORE_CONFLICT_MAPPING;
    if (actual->lifecycle_generation
        != expected->destination_lifecycle_generation
        || actual->reconciliation_generation
        != expected->destination_reconciliation_generation)
      return WYL_FACT_OFFLINE_RESTORE_CONFLICT_GENERATION;
    if (!identity_equal
          (&actual->expected_main_identity, &expected->expected_main_identity)
        || !identity_equal
          (&actual->staged_main_identity, &expected->staged_main_identity))
      return WYL_FACT_OFFLINE_RESTORE_CONFLICT_INVENTORY;
  }
  if (evidence->confirmed
      != (journal->confirmation
      == WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT))
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_CONFIRMATION;
  if (evidence->manifest_authenticated
      != (journal->manifest_trust
      == WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED))
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_MANIFEST_TRUST;
  if (!evidence->target_sealed)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_TARGET_NOT_SEALED;
  if (!evidence->target_drained)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_TARGET_NOT_DRAINED;
  if (!evidence->inventory_stable)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_INVENTORY;
  if (evidence->unknown_artifacts != 0)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_UNKNOWN_ARTIFACT;
  if (evidence->foreign_operation_artifact)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_FOREIGN_OPERATION;
  if (evidence->foreign_main)
    return WYL_FACT_OFFLINE_RESTORE_CONFLICT_FOREIGN_MAIN;
  return WYL_FACT_OFFLINE_RESTORE_CONFLICT_NONE;
}

static const WylFactOfflineRestoreTargetGraph *
find_target (const GPtrArray *targets, const gchar *graph_id)
{
  if (targets == NULL)
    return NULL;
  const WylFactOfflineRestoreTargetGraph *match = NULL;
  for (guint i = 0; i < targets->len; i++) {
    const WylFactOfflineRestoreTargetGraph *target =
        g_ptr_array_index ((GPtrArray *) targets, i);
    if (target != NULL && g_strcmp0 (target->graph_id, graph_id) == 0) {
      if (match != NULL)
        return NULL;
      match = target;
    }
  }
  return match;
}

static WylFactOfflineRestoreJournalGraph *
copy_graph (const WylFactOfflineBackupArtifact *artifact,
    const WylFactOfflineRestoreTargetGraph *target)
{
  WylFactOfflineRestoreJournalGraph *graph = g_try_new0
        (WylFactOfflineRestoreJournalGraph, 1);
  if (graph == NULL)
    return NULL;
  graph->graph_id = g_strdup (artifact->graph_id);
  graph->store_uuid = g_strdup (artifact->store_uuid);
  graph->schema_digest = g_strdup (artifact->schema_digest);
  graph->checksum = g_strdup (artifact->checksum);
  graph->format_version = artifact->format_version;
  graph->path_encoding_version = artifact->path_encoding_version;
  graph->logical_bytes = artifact->logical_bytes;
  graph->physical_bytes = artifact->physical_bytes;
  graph->destination_lifecycle_generation = target->lifecycle_generation;
  graph->destination_reconciliation_generation =
      target->reconciliation_generation;
  graph->expected_main_absent = target->expected_main_absent;
  graph->expected_main_identity = target->expected_main_identity;
  graph->transition_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY;
  graph->next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED;
  if (graph->graph_id == NULL || graph->store_uuid == NULL
      || graph->schema_digest == NULL || graph->checksum == NULL) {
    journal_graph_free (graph);
    return NULL;
  }
  return graph;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_init (WylFactOfflineRestoreJournal *journal,
    GBytes *canonical_manifest, const gchar *operation_uuid,
    WylFactOfflineRestoreScope scope, const gchar *selected_graph_id,
    guint64 destination_tenant_lifecycle,
    guint64 destination_tenant_reconciliation,
    const GPtrArray *destination_graphs,
    WylFactOfflineRestoreConfirmation confirmation,
    WylFactOfflineRestoreManifestTrust manifest_trust)
{
  if (journal == NULL)
    return WYRELOG_E_INVALID;
  wyl_fact_offline_restore_journal_clear (journal);
  gsize manifest_length = canonical_manifest == NULL ? 0 :
      g_bytes_get_size (canonical_manifest);
  if (canonical_manifest == NULL || manifest_length == 0
      || manifest_length > WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES
      || !canonical_uuid (operation_uuid)
      || (scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      && !bounded_text (selected_graph_id))
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && selected_graph_id != NULL)
      || destination_tenant_lifecycle == 0
      || destination_tenant_reconciliation == 0
      || confirmation > WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || manifest_trust > WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED)
    return WYRELOG_E_INVALID;

  WylFactOfflineBackupManifest manifest = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_backup_manifest_decode
        (canonical_manifest, &manifest);
  g_autoptr (GBytes) reencoded = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_manifest_encode (&manifest, &reencoded);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (canonical_manifest, reencoded))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && !bounded_text (manifest.tenant_id))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && (manifest.artifacts->len == 0
      || manifest.artifacts->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS))
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < manifest.artifacts->len; i++) {
    WylFactOfflineBackupArtifact *artifact = g_ptr_array_index
          (manifest.artifacts, i);
    if (!bounded_text (artifact->graph_id)
        || !bounded_text (artifact->store_uuid)
        || !bounded_text (artifact->schema_digest)
        || !bounded_text (artifact->checksum)
        || artifact->format_version == 0 || artifact->path_encoding_version == 0
        || (i != 0 && g_strcmp0 (((WylFactOfflineBackupArtifact *)
        g_ptr_array_index (manifest.artifacts, i - 1))->graph_id,
        artifact->graph_id) >= 0))
      rc = WYRELOG_E_POLICY;
  }
  if (rc != WYRELOG_E_OK) {
    wyl_fact_offline_backup_manifest_clear (&manifest);
    return rc;
  }

  journal->version = WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION;
  journal->revision = 1;
  journal->operation_uuid = g_strdup (operation_uuid);
  journal->scope = scope;
  journal->tenant_id = g_strdup (manifest.tenant_id);
  journal->selected_graph_id = g_strdup (selected_graph_id);
  journal->source_tenant_lifecycle_generation = manifest.policy_generation;
  journal->destination_tenant_lifecycle_generation =
      destination_tenant_lifecycle;
  journal->destination_tenant_reconciliation_generation =
      destination_tenant_reconciliation;
  journal->confirmation = confirmation;
  journal->manifest_trust = manifest_trust;
  journal->graphs = g_ptr_array_new_with_free_func
        ((GDestroyNotify) journal_graph_free);
  manifest_length = 0;
  const guint8 *manifest_data = g_bytes_get_data
        (canonical_manifest, &manifest_length);
  digest (manifest_data, manifest_length, journal->manifest_sha256);
  if (journal->operation_uuid == NULL || journal->tenant_id == NULL
      || journal->graphs == NULL
      || (selected_graph_id != NULL && journal->selected_graph_id == NULL))
    rc = WYRELOG_E_NOMEM;

  gboolean selected = FALSE;
  for (guint i = 0; rc == WYRELOG_E_OK && i < manifest.artifacts->len; i++) {
    WylFactOfflineBackupArtifact *artifact = g_ptr_array_index
          (manifest.artifacts, i);
    if (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && g_strcmp0 (selected_graph_id, artifact->graph_id) != 0)
      continue;
    const WylFactOfflineRestoreTargetGraph *target = find_target
          (destination_graphs, artifact->graph_id);
    if (target == NULL || target->lifecycle_generation == 0
        || target->reconciliation_generation == 0
        || (target->expected_main_absent
            ? !identity_is_zero (&target->expected_main_identity)
            : !identity_is_valid (&target->expected_main_identity))) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    WylFactOfflineRestoreJournalGraph *graph = copy_graph (artifact, target);
    if (graph == NULL) {
      rc = WYRELOG_E_NOMEM;
      break;
    }
    g_ptr_array_add (journal->graphs, graph);
    selected = TRUE;
  }
  if (rc == WYRELOG_E_OK && (!selected
      || (scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && journal->graphs->len != manifest.artifacts->len)))
    rc = WYRELOG_E_POLICY;
  wyl_fact_offline_backup_manifest_clear (&manifest);
  if (rc != WYRELOG_E_OK)
    wyl_fact_offline_restore_journal_clear (journal);
  return rc;
}

static gboolean
next_op_matches_state (const WylFactOfflineRestoreJournalGraph *graph)
{
  gboolean final_state = graph->transition_state
      == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
      || graph->transition_state
      == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
  if (graph->transition_terminal != final_state)
    return FALSE;
  gboolean mode_a = !graph->expected_main_absent;
  WylFactArtifactMainTransitionOp op = graph->next_op;
  switch (graph->transition_state) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY:
      return (!graph->resume_forbidden
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED)
             || (!graph->resume_forbidden && mode_a
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN)
             || (!graph->resume_forbidden && !mode_a
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH)
             || (graph->resume_forbidden
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED:
      return mode_a && (graph->resume_forbidden ?
             op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK :
             op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
             || op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
             || op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
             || op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST:
      return mode_a && graph->resume_forbidden
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED:
      if (graph->resume_forbidden)
        return mode_a ?
               op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK :
               op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
      return op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR
             || (graph->durability_unprovable_acknowledged
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE:
      return graph->resume_forbidden ?
             mode_a && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK :
             op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK:
      return mode_a && graph->resume_forbidden
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED:
      return graph->transition_terminal
             && op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
    default:
      return FALSE;
  }
}

static gboolean
valid_journal (const WylFactOfflineRestoreJournal *journal)
{
  if (journal == NULL
      || journal->version != WYL_FACT_OFFLINE_RESTORE_JOURNAL_VERSION
      || journal->revision == 0 || !canonical_uuid (journal->operation_uuid)
      || !bounded_text (journal->tenant_id) || journal->graphs == NULL
      || journal->source_tenant_lifecycle_generation == 0
      || journal->destination_tenant_lifecycle_generation == 0
      || journal->destination_tenant_reconciliation_generation == 0
      || journal->graphs->len == 0
      || journal->graphs->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS
      || (journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && journal->scope != WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH)
      || (journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
      && (!bounded_text (journal->selected_graph_id)
      || journal->graphs->len != 1))
      || (journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT
      && journal->selected_graph_id != NULL)
      || journal->confirmation > WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust
      > WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED
      || journal->decision > WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK
      || (journal->policy_generation_published
      && journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT)
      || (journal->lifecycle_handoff_complete
      && !journal->policy_generation_published)
      || (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      && (journal->confirmation
      != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
      || journal->manifest_trust
      != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED)))
    return FALSE;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (graph == NULL || !bounded_text (graph->graph_id)
        || !bounded_text (graph->store_uuid)
        || !bounded_text (graph->schema_digest)
        || !bounded_text (graph->checksum)
        || graph->format_version == 0 || graph->path_encoding_version == 0
        || graph->destination_lifecycle_generation == 0
        || graph->destination_reconciliation_generation == 0
        || graph->transition_state <= WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID
        || graph->transition_state >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_COUNT
        || graph->next_op >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT
        || graph->pending_op >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT
        || graph->attempt > WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED
        || (graph->expected_main_absent
        ? !identity_is_zero (&graph->expected_main_identity)
        : !identity_is_valid (&graph->expected_main_identity))
        || (graph->copied != graph->checksum_verified
        || graph->copied != graph->identity_verified
        || graph->copied != graph->schema_verified
        || graph->copied != graph->replay_preflighted)
        || (!identity_is_zero (&graph->staged_main_identity)
        && !identity_is_valid (&graph->staged_main_identity))
        || (!graph->expected_main_absent
        && !identity_is_zero (&graph->staged_main_identity)
        && identity_equal (&graph->staged_main_identity,
        &graph->expected_main_identity))
        || (graph->replay_preflighted
        && !identity_is_valid (&graph->staged_main_identity))
        || (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
        ? graph->pending_op != graph->next_op
        || graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
        : graph->pending_op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE)
        || !next_op_matches_state (graph)
        || (graph->transition_terminal
        != (graph->transition_state
        == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
        || graph->transition_state
        == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED))
        || (i != 0 && g_strcmp0 (((WylFactOfflineRestoreJournalGraph *)
        g_ptr_array_index (journal->graphs, i - 1))->graph_id,
        graph->graph_id) >= 0))
      return FALSE;
    if (journal->scope == WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH
        && g_strcmp0 (journal->selected_graph_id, graph->graph_id) != 0)
      return FALSE;
    if (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        && (!graph->replay_preflighted || graph->resume_forbidden))
      return FALSE;
    if (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK
        && !graph->resume_forbidden)
      return FALSE;
    if (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
        && (graph->resume_forbidden
        || graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE))
      return FALSE;
    if (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED)
      return FALSE;
    if (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
        && (graph->transition_state
        == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED
        || graph->transition_state
        == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK))
      return FALSE;
    if (journal->policy_generation_published
        && graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED)
      return FALSE;
  }
  return TRUE;
}

static void
append_bool (GString *text, gboolean value)
{
  g_string_append_c (text, value ? '1' : '0');
}

static void
append_identity (GString *text,
    const WylFactArtifactInventoryIdentity *identity)
{
  g_string_append_printf (text, "%" G_GUINT64_FORMAT ",%" G_GUINT64_FORMAT
      ",%u,", identity->domain, identity->object, identity->object_width);
  for (guint i = 0; i < sizeof identity->object_bytes; i++)
    g_string_append_printf (text, "%02x", identity->object_bytes[i]);
}

wyrelog_error_t
wyl_fact_offline_restore_journal_encode
  (const WylFactOfflineRestoreJournal *journal, GBytes **out_bytes)
{
  if (out_bytes != NULL)
    *out_bytes = NULL;
  if (out_bytes == NULL || !valid_journal (journal))
    return WYRELOG_E_INVALID;
  g_autofree gchar *tenant = encode_text (journal->tenant_id);
  g_autofree gchar *selected = journal->selected_graph_id == NULL ?
      g_strdup ("-") : encode_text (journal->selected_graph_id);
  g_autofree gchar *manifest_digest = hex_digest (journal->manifest_sha256);
  GString *text = g_string_new ("wyrelog-offline-restore-journal\n");
  g_string_append_printf (text, "version=%u\nrevision=%" G_GUINT64_FORMAT
      "\noperation=%s\nscope=%u\ntenant=%s\nselected=%s\nmanifest=%s\n"
      "source_generation=%" G_GUINT64_FORMAT
      "\ndestination_tenant_lifecycle=%" G_GUINT64_FORMAT
      "\ndestination_tenant_reconciliation=%" G_GUINT64_FORMAT
      "\nconfirmation=%u\nmanifest_trust=%u\ndecision=%u\npolicy_published=%u"
      "\nlifecycle_handoff=%u\ngraph_count=%u\n", journal->version,
      journal->revision, journal->operation_uuid, journal->scope, tenant,
      selected, manifest_digest, journal->source_tenant_lifecycle_generation,
      journal->destination_tenant_lifecycle_generation,
      journal->destination_tenant_reconciliation_generation,
      journal->confirmation, journal->manifest_trust, journal->decision,
      journal->policy_generation_published, journal->lifecycle_handoff_complete,
      journal->graphs->len);
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    g_autofree gchar *id = encode_text (graph->graph_id);
    g_autofree gchar *uuid = encode_text (graph->store_uuid);
    g_autofree gchar *schema = encode_text (graph->schema_digest);
    g_autofree gchar *checksum = encode_text (graph->checksum);
    g_string_append_printf (text, "graph=%s|%s|%" G_GUINT64_FORMAT
        "|%" G_GUINT64_FORMAT "|%s|%" G_GUINT64_FORMAT
        "|%" G_GUINT64_FORMAT "|%s|%" G_GUINT64_FORMAT
        "|%" G_GUINT64_FORMAT "|", id, uuid, graph->format_version,
        graph->path_encoding_version, schema, graph->logical_bytes,
        graph->physical_bytes, checksum,
        graph->destination_lifecycle_generation,
        graph->destination_reconciliation_generation);
    append_bool (text, graph->expected_main_absent);
    g_string_append_c (text, '|');
    append_identity (text, &graph->expected_main_identity);
    g_string_append_c (text, '|');
    append_identity (text, &graph->staged_main_identity);
    g_string_append_c (text, '|');
    append_bool (text, graph->copied);
    append_bool (text, graph->checksum_verified);
    append_bool (text, graph->identity_verified);
    append_bool (text, graph->schema_verified);
    append_bool (text, graph->replay_preflighted);
    g_string_append_printf (text, "|%u|%u|%u|%u|%u|",
        graph->transition_state, graph->next_op,
        graph->transition_terminal, graph->pending_op, graph->attempt);
    append_bool (text, graph->resume_forbidden);
    append_bool (text, graph->durability_unprovable_acknowledged);
    g_string_append_c (text, '\n');
  }
  guint8 checksum_bytes[32];
  digest ((const guint8 *) text->str, text->len, checksum_bytes);
  g_autofree gchar *checksum = hex_digest (checksum_bytes);
  g_string_append_printf (text, "checksum=%s\n", checksum);
  if (text->len > WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES) {
    g_string_free (text, TRUE);
    return WYRELOG_E_INVALID;
  }
  gsize length = text->len;
  *out_bytes = g_bytes_new_take (g_string_free (text, FALSE), length);
  return WYRELOG_E_OK;
}

static gboolean
line_value (gchar **lines, guint index, const gchar *key, const gchar **out)
{
  gsize length = strlen (key);
  if (lines[index] == NULL || !g_str_has_prefix (lines[index], key)
      || lines[index][length] != '=')
    return FALSE;
  *out = lines[index] + length + 1;
  return TRUE;
}

static gboolean
parse_bool (const gchar *text, gboolean *out)
{
  if (g_strcmp0 (text, "0") == 0) {
    *out = FALSE;
    return TRUE;
  }
  if (g_strcmp0 (text, "1") == 0) {
    *out = TRUE;
    return TRUE;
  }
  return FALSE;
}

static gboolean
parse_identity (const gchar *text,
    WylFactArtifactInventoryIdentity *out)
{
  g_auto (GStrv) fields = g_strsplit (text, ",", -1);
  guint64 domain = 0, object = 0;
  guint width = 0;
  if (g_strv_length (fields) != 4 || !parse_u64 (fields[0], &domain)
      || !parse_u64 (fields[1], &object) || !parse_uint (fields[2], &width)
      || width > sizeof out->object_bytes
      || strlen (fields[3]) != sizeof out->object_bytes * 2)
    return FALSE;
  memset (out, 0, sizeof *out);
  out->domain = domain;
  out->object = object;
  out->object_width = (guint8) width;
  for (guint i = 0; i < sizeof out->object_bytes; i++) {
    gint high = g_ascii_xdigit_value (fields[3][i * 2]);
    gint low = g_ascii_xdigit_value (fields[3][i * 2 + 1]);
    if (high < 0 || low < 0)
      return FALSE;
    out->object_bytes[i] = (guint8) ((high << 4) | low);
  }
  return TRUE;
}

static WylFactOfflineRestoreJournalGraph *
decode_graph (const gchar *line)
{
  if (!g_str_has_prefix (line, "graph="))
    return NULL;
  g_auto (GStrv) fields = g_strsplit (line + 6, "|", -1);
  if (g_strv_length (fields) != 20 || strlen (fields[13]) != 5
      || strlen (fields[19]) != 2)
    return NULL;
  WylFactOfflineRestoreJournalGraph *graph = g_new0
        (WylFactOfflineRestoreJournalGraph, 1);
  guint state = 0, next = 0, operation = 0, attempt = 0;
  graph->graph_id = decode_text (fields[0]);
  graph->store_uuid = decode_text (fields[1]);
  graph->schema_digest = decode_text (fields[4]);
  graph->checksum = decode_text (fields[7]);
  gboolean valid = graph->graph_id != NULL && graph->store_uuid != NULL
      && graph->schema_digest != NULL && graph->checksum != NULL
      && parse_u64 (fields[2], &graph->format_version)
      && parse_u64 (fields[3], &graph->path_encoding_version)
      && parse_u64 (fields[5], &graph->logical_bytes)
      && parse_u64 (fields[6], &graph->physical_bytes)
      && parse_u64 (fields[8], &graph->destination_lifecycle_generation)
      && parse_u64 (fields[9], &graph->destination_reconciliation_generation)
      && parse_bool (fields[10], &graph->expected_main_absent)
      && parse_identity (fields[11], &graph->expected_main_identity)
      && parse_identity (fields[12], &graph->staged_main_identity);
  gboolean *flags[] = { &graph->copied, &graph->checksum_verified,
                        &graph->identity_verified, &graph->schema_verified,
                        &graph->replay_preflighted };
  for (guint i = 0; valid && i < G_N_ELEMENTS (flags); i++) {
    gchar value[2] = { fields[13][i], '\0' };
    valid = parse_bool (value, flags[i]);
  }
  valid = valid && parse_uint (fields[14], &state)
      && parse_uint (fields[15], &next)
      && parse_bool (fields[16], &graph->transition_terminal)
      && parse_uint (fields[17], &operation)
      && parse_uint (fields[18], &attempt);
  gchar resume[2] = { fields[19][0], '\0' };
  gchar acknowledge[2] = { fields[19][1], '\0' };
  valid = valid && parse_bool (resume, &graph->resume_forbidden)
      && parse_bool (acknowledge,
          &graph->durability_unprovable_acknowledged);
  graph->transition_state = (WylFactArtifactMainTransitionState) state;
  graph->next_op = (WylFactArtifactMainTransitionOp) next;
  graph->pending_op = (WylFactArtifactMainTransitionOp) operation;
  graph->attempt = (WylFactOfflineRestoreAttempt) attempt;
  if (!valid) {
    journal_graph_free (graph);
    return NULL;
  }
  return graph;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_decode
  (GBytes *bytes, WylFactOfflineRestoreJournal *out_journal)
{
  if (out_journal == NULL)
    return WYRELOG_E_INVALID;
  memset (out_journal, 0, sizeof *out_journal);
  if (bytes == NULL)
    return WYRELOG_E_INVALID;
  gsize length = 0;
  const guint8 *raw = g_bytes_get_data (bytes, &length);
  if (length == 0
      || length > WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES
      || raw[length - 1] != '\n' || memchr (raw, '\0', length) != NULL)
    return WYRELOG_E_POLICY;
  g_autofree gchar *text = g_strndup ((const gchar *) raw, length);
  gchar *checksum_line = g_strrstr (text, "checksum=");
  if (checksum_line == NULL || checksum_line == text
      || checksum_line[-1] != '\n' || strchr (checksum_line, '\n')
      != text + length - 1)
    return WYRELOG_E_POLICY;
  guint8 expected[32], actual[32];
  if (!parse_hex_digest (checksum_line + strlen ("checksum="), expected)) {
    /* Exclude the final newline while parsing the textual digest. */
    gchar saved = text[length - 1];
    text[length - 1] = '\0';
    gboolean parsed = parse_hex_digest (checksum_line + 9, expected);
    text[length - 1] = saved;
    if (!parsed)
      return WYRELOG_E_POLICY;
  }
  gsize prefix_length = (gsize) (checksum_line - text);
  digest (raw, prefix_length, actual);
  if (memcmp (expected, actual, sizeof expected) != 0)
    return WYRELOG_E_POLICY;
  g_auto (GStrv) lines = g_strsplit (text, "\n", -1);
  if (g_strcmp0 (lines[0], "wyrelog-offline-restore-journal") != 0)
    return WYRELOG_E_POLICY;
  const gchar *value = NULL;
  guint version = 0, scope = 0, confirmation = 0, trust = 0, decision = 0;
  guint graph_count = 0;
  gboolean policy_published = FALSE, handoff = FALSE;
  gboolean valid = line_value (lines, 1, "version", &value)
      && parse_uint (value, &version)
      && line_value (lines, 2, "revision", &value)
      && parse_u64 (value, &out_journal->revision)
      && line_value (lines, 3, "operation", &value)
      && (out_journal->operation_uuid = g_strdup (value)) != NULL
      && line_value (lines, 4, "scope", &value) && parse_uint (value, &scope)
      && line_value (lines, 5, "tenant", &value)
      && (out_journal->tenant_id = decode_text (value)) != NULL
      && line_value (lines, 6, "selected", &value);
  if (valid && g_strcmp0 (value, "-") != 0)
    valid = (out_journal->selected_graph_id = decode_text (value)) != NULL;
  valid = valid && line_value (lines, 7, "manifest", &value)
      && parse_hex_digest (value, out_journal->manifest_sha256)
      && line_value (lines, 8, "source_generation", &value)
      && parse_u64 (value, &out_journal->source_tenant_lifecycle_generation)
      && line_value (lines, 9, "destination_tenant_lifecycle", &value)
      && parse_u64 (value,
          &out_journal->destination_tenant_lifecycle_generation)
      && line_value (lines, 10, "destination_tenant_reconciliation", &value)
      && parse_u64 (value,
          &out_journal->destination_tenant_reconciliation_generation)
      && line_value (lines, 11, "confirmation", &value)
      && parse_uint (value, &confirmation)
      && line_value (lines, 12, "manifest_trust", &value)
      && parse_uint (value, &trust)
      && line_value (lines, 13, "decision", &value)
      && parse_uint (value, &decision)
      && line_value (lines, 14, "policy_published", &value)
      && parse_bool (value, &policy_published)
      && line_value (lines, 15, "lifecycle_handoff", &value)
      && parse_bool (value, &handoff)
      && line_value (lines, 16, "graph_count", &value)
      && parse_uint (value, &graph_count)
      && graph_count > 0 && graph_count <= WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS;
  out_journal->version = version;
  out_journal->scope = (WylFactOfflineRestoreScope) scope;
  out_journal->confirmation = (WylFactOfflineRestoreConfirmation) confirmation;
  out_journal->manifest_trust = (WylFactOfflineRestoreManifestTrust) trust;
  out_journal->decision = (WylFactOfflineRestoreDecision) decision;
  out_journal->policy_generation_published = policy_published;
  out_journal->lifecycle_handoff_complete = handoff;
  if (valid)
    out_journal->graphs = g_ptr_array_new_with_free_func
          ((GDestroyNotify) journal_graph_free);
  for (guint i = 0; valid && i < graph_count; i++) {
    WylFactOfflineRestoreJournalGraph *graph = decode_graph (lines[17 + i]);
    valid = graph != NULL;
    if (valid)
      g_ptr_array_add (out_journal->graphs, graph);
  }
  valid = valid && line_value (lines, 17 + graph_count, "checksum", &value)
      && lines[18 + graph_count] != NULL
      && lines[18 + graph_count][0] == '\0'
      && lines[19 + graph_count] == NULL && valid_journal (out_journal);
  g_autoptr (GBytes) canonical = NULL;
  if (valid)
    valid = wyl_fact_offline_restore_journal_encode
          (out_journal, &canonical) == WYRELOG_E_OK
        && g_bytes_equal (bytes, canonical);
  if (!valid) {
    wyl_fact_offline_restore_journal_clear (out_journal);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static WylFactOfflineRestoreJournalGraph *
find_graph (WylFactOfflineRestoreJournal *journal, const gchar *graph_id)
{
  if (journal == NULL || graph_id == NULL || journal->graphs == NULL)
    return NULL;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (g_strcmp0 (graph->graph_id, graph_id) == 0)
      return graph;
  }
  return NULL;
}

static gboolean
can_advance_revision (const WylFactOfflineRestoreJournal *journal)
{
  return journal != NULL && journal->revision < G_MAXUINT64;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_bind_staged_identity
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    const WylFactArtifactInventoryIdentity *identity)
{
  WylFactOfflineRestoreJournalGraph *graph = find_graph (journal, graph_id);
  if (graph == NULL || !valid_journal (journal)
      || !can_advance_revision (journal)
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || !identity_is_valid (identity)
      || (!graph->expected_main_absent
      && identity_equal
        (identity, &graph->expected_main_identity))
      || !identity_is_zero (&graph->staged_main_identity)
      || graph->copied)
    return WYRELOG_E_POLICY;
  graph->staged_main_identity = *identity;
  journal->revision++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_mark_preflight
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id)
{
  WylFactOfflineRestoreJournalGraph *graph = find_graph (journal, graph_id);
  if (graph == NULL || !valid_journal (journal)
      || !can_advance_revision (journal)
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE)
    return WYRELOG_E_POLICY;
  if (!identity_is_valid (&graph->staged_main_identity) || graph->copied)
    return WYRELOG_E_POLICY;
  graph->copied = TRUE;
  graph->checksum_verified = TRUE;
  graph->identity_verified = TRUE;
  graph->schema_verified = TRUE;
  graph->replay_preflighted = TRUE;
  journal->revision++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_decide (WylFactOfflineRestoreJournal *journal,
    WylFactOfflineRestoreDecision decision)
{
  if (!valid_journal (journal)
      || !can_advance_revision (journal)
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || (decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      && decision != WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK))
    return WYRELOG_E_POLICY;
  if (decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT) {
    if (journal->confirmation
        != WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT
        || journal->manifest_trust
        != WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED)
      return WYRELOG_E_POLICY;
    for (guint i = 0; i < journal->graphs->len; i++) {
      WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal->graphs, i);
      if (!graph->copied || !graph->checksum_verified
          || !graph->identity_verified || !graph->schema_verified
          || !graph->replay_preflighted
          || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_NONE)
        return WYRELOG_E_POLICY;
    }
  }
  journal->decision = decision;
  if (decision == WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK) {
    for (guint i = 0; i < journal->graphs->len; i++) {
      WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal->graphs, i);
      graph->resume_forbidden = TRUE;
      if (identity_is_zero (&graph->staged_main_identity)) {
        graph->transition_state =
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
        graph->next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
        graph->transition_terminal = TRUE;
      } else {
        graph->next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE;
      }
    }
  }
  journal->revision++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_begin_attempt
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    WylFactArtifactMainTransitionOp operation)
{
  WylFactOfflineRestoreJournalGraph *graph = find_graph (journal, graph_id);
  if (graph == NULL || !valid_journal (journal)
      || !can_advance_revision (journal)
      || journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_NONE
      || (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      && !graph->replay_preflighted)
      || graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
      || operation != graph->next_op
      || operation < WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
      || operation >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT)
    return WYRELOG_E_POLICY;
  graph->pending_op = operation;
  graph->attempt = WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN;
  journal->revision++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_mark_policy_published
  (WylFactOfflineRestoreJournal *journal)
{
  if (!valid_journal (journal)
      || !can_advance_revision (journal)
      || journal->decision != WYL_FACT_OFFLINE_RESTORE_DECISION_COMMIT
      || journal->policy_generation_published)
    return WYRELOG_E_POLICY;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
        || graph->transition_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED)
      return WYRELOG_E_POLICY;
  }
  journal->policy_generation_published = TRUE;
  journal->revision++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_mark_lifecycle_handoff
  (WylFactOfflineRestoreJournal *journal)
{
  if (!valid_journal (journal) || !journal->policy_generation_published
      || journal->lifecycle_handoff_complete
      || !can_advance_revision (journal))
    return WYRELOG_E_POLICY;
  journal->lifecycle_handoff_complete = TRUE;
  journal->revision++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_journal_complete_attempt
  (WylFactOfflineRestoreJournal *journal, const gchar *graph_id,
    WylFactArtifactMainTransitionState state,
    WylFactArtifactMainTransitionOp next_op, gboolean terminal)
{
  WylFactOfflineRestoreJournalGraph *graph = find_graph (journal, graph_id);
  if (graph == NULL || !valid_journal (journal)
      || !can_advance_revision (journal)
      || graph->attempt != WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN
      || graph->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
      || state <= WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID
      || state >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_COUNT)
    return WYRELOG_E_POLICY;
  gboolean matching = FALSE;
  switch (graph->pending_op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
      matching = state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED;
      break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      matching = state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED;
      break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      matching = state == graph->transition_state
          || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE;
      break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK:
      if (graph->transition_state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
          || graph->transition_state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE)
        matching = state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED;
      else if (graph->transition_state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
          || graph->transition_state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST)
        matching = state
            == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK
            || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
      break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE:
      matching = state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
      break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE:
      matching = state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED;
      break;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      matching = state == graph->transition_state;
      break;
    default:
      break;
  }
  if (!matching)
    return WYRELOG_E_POLICY;
  WylFactOfflineRestoreJournalGraph completed = *graph;
  completed.transition_state = state;
  completed.next_op = next_op;
  completed.transition_terminal = terminal;
  completed.pending_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  completed.attempt = WYL_FACT_OFFLINE_RESTORE_ATTEMPT_COMPLETED;
  if (!next_op_matches_state (&completed))
    return WYRELOG_E_POLICY;
  WylFactOfflineRestoreJournal candidate = *journal;
  candidate.revision++;
  candidate.graphs = g_ptr_array_sized_new (journal->graphs->len);
  if (candidate.graphs == NULL)
    return WYRELOG_E_NOMEM;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *entry =
        g_ptr_array_index (journal->graphs, i);
    g_ptr_array_add (candidate.graphs, entry == graph ? &completed : entry);
  }
  gboolean candidate_valid = valid_journal (&candidate);
  g_ptr_array_unref (candidate.graphs);
  if (!candidate_valid)
    return WYRELOG_E_POLICY;
  graph->transition_state = completed.transition_state;
  graph->next_op = completed.next_op;
  graph->transition_terminal = completed.transition_terminal;
  graph->pending_op = completed.pending_op;
  graph->attempt = completed.attempt;
  journal->revision++;
  return WYRELOG_E_OK;
}

WylFactOfflineRestoreRecovery
wyl_fact_offline_restore_journal_recovery
  (const WylFactOfflineRestoreJournal *journal)
{
  if (!valid_journal (journal))
    return WYL_FACT_OFFLINE_RESTORE_RECOVERY_REFUSE;
  for (guint i = 0; i < journal->graphs->len; i++) {
    WylFactOfflineRestoreJournalGraph *graph =
        g_ptr_array_index (journal->graphs, i);
    if (graph->attempt == WYL_FACT_OFFLINE_RESTORE_ATTEMPT_UNKNOWN)
      return WYL_FACT_OFFLINE_RESTORE_RECOVERY_INSPECT_ONLY;
  }
  if (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_NONE)
    return WYL_FACT_OFFLINE_RESTORE_RECOVERY_ROLLBACK;
  if (journal->decision == WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK) {
    for (guint i = 0; i < journal->graphs->len; i++) {
      WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal->graphs, i);
      if (graph->transition_state
          != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED)
        return WYL_FACT_OFFLINE_RESTORE_RECOVERY_ROLLBACK;
    }
    return WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE;
  }
  if (!journal->policy_generation_published) {
    gboolean finalized = TRUE;
    for (guint i = 0; i < journal->graphs->len; i++) {
      WylFactOfflineRestoreJournalGraph *graph =
          g_ptr_array_index (journal->graphs, i);
      if (graph->transition_state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED
          || graph->transition_state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK)
        return WYL_FACT_OFFLINE_RESTORE_RECOVERY_REFUSE;
      finalized = finalized && graph->transition_state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED;
    }
    return finalized ? WYL_FACT_OFFLINE_RESTORE_RECOVERY_POLICY_CAS
                     : WYL_FACT_OFFLINE_RESTORE_RECOVERY_CONTINUE_COMMIT;
  }
  if (!journal->lifecycle_handoff_complete)
    return WYL_FACT_OFFLINE_RESTORE_RECOVERY_LIFECYCLE_HANDOFF;
  return WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE;
}

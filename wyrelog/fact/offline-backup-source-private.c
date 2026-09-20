/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-backup-source-private.h"

#include <string.h>

#include "fact/artifact-io-session-private.h"
#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-artifact-namespace-private.h"
#include "fact/graph-locator-private.h"
#include "fact/root-writer-lease-private.h"
#include "fact/store-identity-private.h"

#define OFFLINE_BACKUP_COPY_CHUNK (64u * 1024u)

#ifndef G_OS_WIN32
G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
  (WylFactGraphProvisionedPair *, WylFactArtifactNamespace **);
#endif

typedef struct
{
  gchar *tenant_id;
  gchar *graph_id;
  gchar *store_uuid;
  WylPolicyGraphLifecycleState lifecycle_state;
  guint64 format_version;
  guint64 path_encoding_version;
  gchar *schema_digest;
  guint64 lifecycle_generation;
  guint64 reconciliation_generation;
  WylPolicyGraphErrorClass last_error_class;
  WylPolicyGraphMaterializationState materialization_state;
  gboolean has_store_identity;
  gboolean sealed_compatibility;
  guint64 logical_bytes;
  guint64 physical_bytes;
  WylFactArtifactNamespace *namespace_;
  WylFactArtifactMutationLease *reader_guard;
} OfflineBackupGraph;

struct WylFactOfflineBackupSource
{
  /* Borrowed: documented by the constructor contract. */
  wyl_policy_store_t *policy;
  WylFactGraphRuntimeManager *runtime_manager;
  WylFactRootWriterLease *root_lease;
  gchar *tenant_id;
  WylPolicyTenantLifecycleState tenant_state;
  guint64 tenant_lifecycle_generation;
  guint64 tenant_reconciliation_generation;
  gboolean tenant_sealed_compatibility;
  GPtrArray *graphs;
};

static void
offline_backup_graph_free (OfflineBackupGraph *graph)
{
  if (graph == NULL)
    return;
  g_clear_pointer (&graph->reader_guard,
      wyl_fact_artifact_mutation_lease_free);
  g_clear_pointer (&graph->namespace_, wyl_fact_artifact_namespace_free);
  g_free (graph->tenant_id);
  g_free (graph->graph_id);
  g_free (graph->store_uuid);
  g_free (graph->schema_digest);
  g_free (graph);
}

void
wyl_fact_offline_backup_source_free (WylFactOfflineBackupSource *source)
{
  if (source == NULL)
    return;
  /* Graph capabilities must disappear before root authority. */
  g_clear_pointer (&source->graphs, g_ptr_array_unref);
  g_clear_pointer (&source->runtime_manager,
      wyl_fact_graph_runtime_manager_unref);
  g_clear_pointer (&source->root_lease, wyl_fact_root_writer_lease_release);
  g_free (source->tenant_id);
  g_free (source);
}

static gboolean
tenant_record_equal (const WylFactOfflineBackupSource *source,
    const WylPolicyTenantAuthorityRecord *record)
{
  return record != NULL
         && g_strcmp0 (source->tenant_id, record->tenant_id) == 0
         && source->tenant_state == record->lifecycle_state
         && source->tenant_lifecycle_generation == record->lifecycle_generation
         && source->tenant_reconciliation_generation
         == record->reconciliation_generation
         && source->tenant_sealed_compatibility == record->sealed_compatibility;
}

static gboolean
graph_record_equal (const OfflineBackupGraph *graph,
    const WylPolicyFactBackupGraphSnapshot *snapshot)
{
  const WylPolicyGraphAuthorityRecord *record = snapshot == NULL ? NULL :
      snapshot->authority;
  return record != NULL
         && g_strcmp0 (graph->tenant_id, record->tenant_id) == 0
         && g_strcmp0 (graph->graph_id, record->graph_id) == 0
         && graph->lifecycle_state == record->lifecycle_state
         && g_strcmp0 (graph->store_uuid, record->store_uuid) == 0
         && graph->format_version == record->format_version
         && graph->path_encoding_version == record->path_encoding_version
         && graph->lifecycle_generation == record->lifecycle_generation
         && graph->reconciliation_generation == record->reconciliation_generation
         && graph->last_error_class == record->last_error_class
         && graph->materialization_state == record->materialization_state
         && graph->has_store_identity == record->has_store_identity
         && graph->sealed_compatibility == record->sealed_compatibility
         && g_strcmp0 (graph->schema_digest,
             snapshot->active_schema_digest) == 0;
}

static gboolean
graph_record_is_backup_source (const WylPolicyGraphAuthorityRecord *record)
{
  if (record == NULL
      || record->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED
      || !record->sealed_compatibility
      || record->materialization_state
      != WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED
      || !record->has_store_identity
      || record->last_error_class != WYL_POLICY_GRAPH_ERROR_NONE)
    return FALSE;
  WylFactStoreIdentity identity = {
    .tenant_id = record->tenant_id,
    .graph_id = record->graph_id,
    .store_uuid = record->store_uuid,
    .format_version = record->format_version,
    .path_encoding_version = record->path_encoding_version,
  };
  return wyl_fact_store_identity_input_is_valid (&identity);
}

static OfflineBackupGraph *
offline_backup_graph_new (const WylPolicyGraphAuthorityRecord *record,
    const gchar *schema_digest)
{
  OfflineBackupGraph *graph = g_try_new0 (OfflineBackupGraph, 1);
  if (graph == NULL)
    return NULL;
  graph->tenant_id = g_strdup (record->tenant_id);
  graph->graph_id = g_strdup (record->graph_id);
  graph->store_uuid = g_strdup (record->store_uuid);
  graph->schema_digest = g_strdup (schema_digest);
  if (graph->tenant_id == NULL || graph->graph_id == NULL
      || graph->store_uuid == NULL || graph->schema_digest == NULL) {
    offline_backup_graph_free (graph);
    return NULL;
  }
  graph->lifecycle_state = record->lifecycle_state;
  graph->format_version = record->format_version;
  graph->path_encoding_version = record->path_encoding_version;
  graph->lifecycle_generation = record->lifecycle_generation;
  graph->reconciliation_generation = record->reconciliation_generation;
  graph->last_error_class = record->last_error_class;
  graph->materialization_state = record->materialization_state;
  graph->has_store_identity = record->has_store_identity;
  graph->sealed_compatibility = record->sealed_compatibility;
  return graph;
}

static gint64
remaining_timeout (gint64 timeout_us, gint64 deadline)
{
  if (timeout_us < 0)
    return -1;
  if (timeout_us == 0)
    return 0;
  gint64 now = g_get_monotonic_time ();
  return now >= deadline ? 0 : deadline - now;
}

static wyrelog_error_t
drain_graph (WylFactOfflineBackupSource *source,
    const WylPolicyGraphAuthorityRecord *record, gint64 timeout_us,
    gint64 deadline)
{
  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, record->tenant_id,
          record->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_graph_runtime_manager_close_admission
        (source->runtime_manager, &key);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_OK;
  else if (rc == WYRELOG_E_OK) {
    WylFactGraphRuntimeStatus status = { 0 };
    rc = wyl_fact_graph_runtime_manager_drain (source->runtime_manager, &key,
            remaining_timeout (timeout_us, deadline), &status);
    wyl_fact_graph_runtime_status_clear (&status);
    if (rc == WYRELOG_E_NOT_FOUND)
      rc = WYRELOG_E_OK;
  }
  wyl_fact_graph_key_clear (&key);
  return rc;
}

static void
regular_file_identity (const WylFactGraphRegularFile *file,
    WylFactArtifactInventoryIdentity *out_identity)
{
  memset (out_identity, 0, sizeof *out_identity);
#ifdef G_OS_WIN32
  out_identity->domain = file->identity.volume_serial;
  memcpy (out_identity->object_bytes, file->identity.file_id,
      sizeof out_identity->object_bytes);
  out_identity->object_width = sizeof out_identity->object_bytes;
#else
  out_identity->domain = file->device;
  out_identity->object = file->inode;
#endif
}

static gboolean
inventory_is_main_only (const WylFactArtifactInventorySnapshot *snapshot,
    const WylFactGraphRegularFile *main_file,
    WylFactArtifactInventorySlotEvidence *out_main)
{
  memset (out_main, 0, sizeof *out_main);
  if (wyl_fact_artifact_inventory_snapshot_status (snapshot)
      != WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE)
    return FALSE;
  for (guint i = 0; i < WYL_FACT_ARTIFACT_INVENTORY_ANOMALY_COUNT; i++) {
    if (wyl_fact_artifact_inventory_snapshot_anomaly_count (snapshot, i) != 0)
      return FALSE;
  }
  if (!wyl_fact_artifact_inventory_snapshot_get_slot_evidence (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, out_main)
      || !out_main->present || !out_main->allocation_supported)
    return FALSE;
  if (main_file != NULL) {
    if (out_main->logical_bytes != main_file->size_bytes)
      return FALSE;
    WylFactArtifactInventoryIdentity held = { 0 };
    regular_file_identity (main_file, &held);
    if (!wyl_fact_artifact_inventory_identity_equal (&held,
        &out_main->identity))
      return FALSE;
  }
  const WylFactArtifactInventorySlot rejected[] = {
    WYL_FACT_ARTIFACT_INVENTORY_WAL,
    WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT,
    WYL_FACT_ARTIFACT_INVENTORY_RECOVERY,
    WYL_FACT_ARTIFACT_INVENTORY_TEMP,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (rejected); i++) {
    if (wyl_fact_artifact_inventory_snapshot_slot_present (snapshot,
        rejected[i]))
      return FALSE;
  }
  return TRUE;
}

static wyrelog_error_t
find_active_operation (WylFactOfflineBackupSource *source,
    const WylPolicyGraphAuthorityRecord *authority, gchar **out_operation_uuid
#ifdef __APPLE__
    , WylFactGraphDarwinOperationEvidence *out_evidence
#endif
    )
{
  *out_operation_uuid = NULL;
  GPtrArray *records = NULL;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list
        (source->policy, authority->tenant_id, &records);
  gboolean found = FALSE;
  for (guint i = 0; rc == WYRELOG_E_OK && i < records->len; i++) {
    WylPolicyGraphProvisioningRecord *record = g_ptr_array_index (records, i);
    if (g_strcmp0 (record->graph_id, authority->graph_id) != 0
        || record->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE)
      continue;
    if (found || g_strcmp0 (record->tenant_id, authority->tenant_id) != 0
        || g_strcmp0 (record->store_uuid, authority->store_uuid) != 0) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    found = TRUE;
    *out_operation_uuid = g_strdup (record->op_uuid);
    if (*out_operation_uuid == NULL) {
      rc = WYRELOG_E_NOMEM;
      break;
    }
#ifdef __APPLE__
    gsize length = 0;
    const guint8 *bytes = record->darwin_operation_evidence == NULL ? NULL :
        g_bytes_get_data (record->darwin_operation_evidence, &length);
    if (bytes == NULL
        || length != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE)
      rc = WYRELOG_E_POLICY;
    else
      rc = wyl_fact_graph_darwin_evidence_decode (bytes, length,
              record->op_uuid, out_evidence);
#endif
  }
  if (rc == WYRELOG_E_OK && !found)
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_operation_uuid, g_free);
  g_clear_pointer (&records, g_ptr_array_unref);
  return rc;
}

static wyrelog_error_t
open_graph_source (WylFactOfflineBackupSource *source,
    WylFactGraphResolver *resolver, const gchar *fact_root,
    const WylPolicyGraphAuthorityRecord *record, OfflineBackupGraph *graph)
{
#ifndef G_OS_WIN32
  (void) resolver;
#endif
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
#ifndef G_OS_WIN32
  WylFactGraphProvisionedPair *pair = NULL;
  g_autofree gchar *operation_uuid = NULL;
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
#endif
#else
  WylFactGraphRegularFile main_file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_autofree gchar *relative_dir = NULL;
  g_autofree gchar *relative_main = NULL;
#endif
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  WylFactArtifactInventorySlotEvidence main_evidence = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_locator_init (&locator,
          record->tenant_id, record->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_open_fact_graph_directory (source->policy, fact_root,
            record->tenant_id, record->graph_id, FALSE, &directory);
#ifndef G_OS_WIN32
  if (rc == WYRELOG_E_OK)
    rc = find_active_operation (source, record, &operation_uuid
#ifdef __APPLE__
            , &evidence
#endif
            );
  if (rc == WYRELOG_E_OK)
#ifdef __APPLE__
    rc = wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
          (&directory, operation_uuid, &evidence, &pair);
#else
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            operation_uuid, &pair);
#endif
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_namespace_open_provisioned_pair_internal (pair,
            &graph->namespace_);
#else
  if (rc == WYRELOG_E_OK) {
    relative_dir = wyl_fact_graph_locator_relative_dir (&locator);
    relative_main = relative_dir == NULL ? NULL :
        g_strdup_printf ("%s/facts.duckdb", relative_dir);
    if (relative_main == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_relative_regular (resolver,
            relative_main, &main_file);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_namespace_open (&directory, &main_file,
            &graph->namespace_);
#endif
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_namespace_acquire_reader_guard (graph->namespace_,
            &graph->reader_guard);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_namespace_inventory_snapshot (graph->namespace_,
            &snapshot);
  if (rc == WYRELOG_E_OK
      && !inventory_is_main_only (snapshot,
#ifdef G_OS_WIN32
      &main_file,
#else
      NULL,
#endif
      &main_evidence))
    rc = WYRELOG_E_POLICY;
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  if (rc == WYRELOG_E_OK) {
    WylFactStoreIdentity identity = {
      .tenant_id = record->tenant_id,
      .graph_id = record->graph_id,
      .store_uuid = record->store_uuid,
      .format_version = record->format_version,
      .path_encoding_version = record->path_encoding_version,
    };
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    rc = wyl_fact_store_open_identified_pinned (graph->namespace_, &identity,
            WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result);
    if (rc == WYRELOG_E_OK && result != WYL_FACT_STORE_IDENTITY_RESULT_NONE)
      rc = WYRELOG_E_POLICY;
  }
#else
  if (rc == WYRELOG_E_OK)
    rc = WYRELOG_E_POLICY;
#endif
  if (rc == WYRELOG_E_OK) {
    graph->logical_bytes = main_evidence.logical_bytes;
    graph->physical_bytes = main_evidence.allocated_bytes;
  }
#ifndef G_OS_WIN32
  wyl_fact_graph_provisioned_pair_free (pair);
#else
  wyl_fact_graph_regular_file_clear (&main_file);
#endif
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  return rc;
}

static wyrelog_error_t
revalidate_policy (WylFactOfflineBackupSource *source)
{
  WylPolicyFactBackupSnapshot *snapshot = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_fact_backup_snapshot
        (source->policy, source->tenant_id, &snapshot);
  if (rc == WYRELOG_E_OK && !tenant_record_equal (source, snapshot->tenant))
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK && snapshot->graphs->len != source->graphs->len)
    rc = WYRELOG_E_BUSY;
  for (guint i = 0; rc == WYRELOG_E_OK && i < snapshot->graphs->len; i++) {
    OfflineBackupGraph *graph = g_ptr_array_index (source->graphs, i);
    WylPolicyFactBackupGraphSnapshot *current =
        g_ptr_array_index (snapshot->graphs, i);
    if (!graph_record_equal (graph, current))
      rc = WYRELOG_E_BUSY;
  }
  g_clear_pointer (&snapshot, wyl_policy_fact_backup_snapshot_free);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_backup_source_revalidate (WylFactOfflineBackupSource *source)
{
  if (source == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (source->root_lease);
  for (guint i = 0; rc == WYRELOG_E_OK && i < source->graphs->len; i++) {
    OfflineBackupGraph *graph = g_ptr_array_index (source->graphs, i);
    rc = wyl_fact_artifact_namespace_revalidate (graph->namespace_);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_mutation_lease_revalidate (graph->reader_guard);
  }
  if (rc == WYRELOG_E_OK)
    rc = revalidate_policy (source);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_backup_source_new (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactGraphRuntimeManager *runtime_manager,
    const gchar *tenant_id, gint64 drain_timeout_us,
    WylFactOfflineBackupSource **out_source)
{
  if (out_source != NULL)
    *out_source = NULL;
  if (policy == NULL || fact_root == NULL || fact_root[0] == '\0'
      || runtime_manager == NULL || tenant_id == NULL || tenant_id[0] == '\0'
      || out_source == NULL)
    return WYRELOG_E_INVALID;
  WylFactOfflineBackupSource *source = g_try_new0
        (WylFactOfflineBackupSource, 1);
  if (source == NULL)
    return WYRELOG_E_NOMEM;
  source->policy = policy;
  source->runtime_manager = wyl_fact_graph_runtime_manager_ref
        (runtime_manager);
  source->tenant_id = g_strdup (tenant_id);
  source->graphs = g_ptr_array_new_with_free_func
        ((GDestroyNotify) offline_backup_graph_free);
  if (source->tenant_id == NULL) {
    wyl_fact_offline_backup_source_free (source);
    return WYRELOG_E_NOMEM;
  }

  gint64 deadline = 0;
  if (drain_timeout_us > 0) {
    gint64 now = g_get_monotonic_time ();
    deadline = drain_timeout_us > G_MAXINT64 - now ? G_MAXINT64 :
        now + drain_timeout_us;
  }
  WylPolicyFactBackupSnapshot *snapshot = NULL;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (fact_root,
          &source->root_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_bind_fact_root_authorized (policy, fact_root,
            source->root_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (source->root_lease,
            &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_read_fact_backup_snapshot (policy, tenant_id,
            &snapshot);
  if (rc == WYRELOG_E_OK
      && (snapshot->tenant->lifecycle_state
      != WYL_POLICY_TENANT_LIFECYCLE_SEALED
      || !snapshot->tenant->sealed_compatibility
      || snapshot->tenant->lifecycle_generation == 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    source->tenant_state = snapshot->tenant->lifecycle_state;
    source->tenant_lifecycle_generation =
        snapshot->tenant->lifecycle_generation;
    source->tenant_reconciliation_generation =
        snapshot->tenant->reconciliation_generation;
    source->tenant_sealed_compatibility =
        snapshot->tenant->sealed_compatibility;
  }
  for (guint i = 0; rc == WYRELOG_E_OK && i < snapshot->graphs->len; i++) {
    WylPolicyFactBackupGraphSnapshot *graph_snapshot =
        g_ptr_array_index (snapshot->graphs, i);
    WylPolicyGraphAuthorityRecord *record = graph_snapshot->authority;
    if (!graph_record_is_backup_source (record)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    rc = drain_graph (source, record, drain_timeout_us, deadline);
    if (rc != WYRELOG_E_OK)
      break;
    OfflineBackupGraph *graph = offline_backup_graph_new (record,
            graph_snapshot->active_schema_digest);
    if (graph == NULL) {
      rc = WYRELOG_E_NOMEM;
      break;
    }
    g_ptr_array_add (source->graphs, graph);
    rc = open_graph_source (source, &resolver, fact_root, record, graph);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (&resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_source_revalidate (source);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&snapshot, wyl_policy_fact_backup_snapshot_free);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_offline_backup_source_free (source);
    return rc;
  }
  *out_source = source;
  return WYRELOG_E_OK;
}

const gchar *
wyl_fact_offline_backup_source_tenant_id
  (const WylFactOfflineBackupSource *source)
{
  return source == NULL ? NULL : source->tenant_id;
}

guint64
wyl_fact_offline_backup_source_policy_generation
  (const WylFactOfflineBackupSource *source)
{
  return source == NULL ? 0 : source->tenant_lifecycle_generation;
}

gsize
wyl_fact_offline_backup_source_count (const WylFactOfflineBackupSource *source)
{
  return source == NULL ? 0 : source->graphs->len;
}

gboolean
wyl_fact_offline_backup_source_get (const WylFactOfflineBackupSource *source,
    gsize index, WylFactOfflineBackupSourceArtifact *out_artifact)
{
  if (out_artifact != NULL)
    memset (out_artifact, 0, sizeof *out_artifact);
  if (source == NULL || out_artifact == NULL || index >= source->graphs->len)
    return FALSE;
  OfflineBackupGraph *graph = g_ptr_array_index (source->graphs, index);
  out_artifact->graph_id = graph->graph_id;
  out_artifact->store_uuid = graph->store_uuid;
  out_artifact->format_version = graph->format_version;
  out_artifact->path_encoding_version = graph->path_encoding_version;
  out_artifact->schema_digest = graph->schema_digest;
  out_artifact->logical_bytes = graph->logical_bytes;
  out_artifact->physical_bytes = graph->physical_bytes;
  return TRUE;
}

wyrelog_error_t
wyl_fact_offline_backup_source_copy_to_sink
  (WylFactOfflineBackupSource *source, gsize index,
    WylFactOfflineBackupSinkFunc sink, gpointer user_data,
    guint64 *out_bytes_copied)
{
  if (out_bytes_copied != NULL)
    *out_bytes_copied = 0;
  if (source == NULL || sink == NULL || out_bytes_copied == NULL
      || index >= source->graphs->len)
    return WYRELOG_E_INVALID;
  OfflineBackupGraph *graph = g_ptr_array_index (source->graphs, index);
  WylFactArtifactIoSession *session = NULL;
  wyrelog_error_t rc = wyl_fact_artifact_io_session_open_reader_main
        (graph->reader_guard, &session);
  guint64 size = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_io_session_size (session, &size);
  if (rc == WYRELOG_E_OK && size != graph->logical_bytes)
    rc = WYRELOG_E_BUSY;
  guint8 buffer[OFFLINE_BACKUP_COPY_CHUNK];
  guint64 offset = 0;
  while (rc == WYRELOG_E_OK && offset < graph->logical_bytes) {
    guint64 remaining = graph->logical_bytes - offset;
    gsize requested = remaining < sizeof buffer ? (gsize) remaining :
        sizeof buffer;
    gsize n_read = 0;
    rc = wyl_fact_artifact_io_session_read (session, offset, buffer,
            requested, &n_read);
    if (rc == WYRELOG_E_OK && n_read != requested)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK)
      rc = sink (offset, buffer, n_read, user_data);
    if (rc == WYRELOG_E_OK)
      offset += n_read;
  }
  if (rc == WYRELOG_E_OK) {
    guint8 extra = 0;
    gsize n_read = 0;
    rc = wyl_fact_artifact_io_session_read (session, offset, &extra, 1,
            &n_read);
    if (rc == WYRELOG_E_OK && n_read != 0)
      rc = WYRELOG_E_BUSY;
  }
  if (rc == WYRELOG_E_OK) {
    guint64 final_size = 0;
    rc = wyl_fact_artifact_io_session_size (session, &final_size);
    if (rc == WYRELOG_E_OK && final_size != graph->logical_bytes)
      rc = WYRELOG_E_BUSY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_io_session_revalidate (session);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_fact_artifact_io_session_finish (session);
    session = NULL;
  } else if (session != NULL) {
    wyl_fact_artifact_io_session_abort (session);
    session = NULL;
  }
  g_clear_pointer (&session, wyl_fact_artifact_io_session_free);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_source_revalidate (source);
  if (rc == WYRELOG_E_OK)
    *out_bytes_copied = offset;
  return rc;
}

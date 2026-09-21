/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-main-transition-private.h"
#include "fact/offline-restore-journal-private.h"

G_BEGIN_DECLS

/*
 * Value-only validation projection for #552 unit 2.  A successful result is
 * neither a capability nor durable authorization.  The caller must retain
 * root, lifecycle, and inventory authority while collecting and validating
 * these values.  DRY_RUN accepts only pristine revision 1 with no staged
 * identities.  STAGED accepts revision 1 + graph_count after every staged
 * identity is bound, with all verification flags still pristine.  Unit 3
 * must copy, bind, replay, validate, freshly revalidate the authority epoch,
 * and durably CAS the journal from validated_revision before any mutation.
 */
typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_INVALID = 0,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_DRY_RUN,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_MODE_STAGED,
} WylFactOfflineRestoreValidationMode;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_BLOCKED = 0,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_DRY_RUN_VALIDATED,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_STAGED_VALIDATED,
} WylFactOfflineRestoreValidationStatus;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_REPLAY_NOT_RUN = 0,
  WYL_FACT_OFFLINE_RESTORE_REPLAY_SUCCEEDED,
  WYL_FACT_OFFLINE_RESTORE_REPLAY_IDENTITY_FAILED,
  WYL_FACT_OFFLINE_RESTORE_REPLAY_SCHEMA_FAILED,
  WYL_FACT_OFFLINE_RESTORE_REPLAY_OPEN_FAILED,
} WylFactOfflineRestoreReplayResult;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_NONE = 0,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVALID_INPUT,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_JOURNAL_INVALID,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_JOURNAL_PHASE,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_INVALID,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_MANIFEST_BINDING,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FORMAT_UNSUPPORTED,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_PATH_UNSUPPORTED,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_CONFIRMATION,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_MANIFEST_TRUST,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_NOT_SEALED,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_NOT_DRAINED,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_AUTHORITY,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_MAPPING,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_GENERATION,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_INVENTORY,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_UNKNOWN_ARTIFACT,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_FOREIGN_OPERATION,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_ADMISSION_FOREIGN_MAIN,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_CARDINALITY,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_ORDER,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_INVENTORY_UNSTABLE,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGED_POPULATION,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FOREIGN_STAGE,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_UNKNOWN_ENTRY,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_MISSING,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_TYPE,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_REPARSE,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_LINK_COUNT,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_OWNER,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STAGE_IDENTITY,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_LOGICAL_BYTES,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_CHECKSUM,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_STORE_UUID,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_TENANT,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_GRAPH,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_FORMAT,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_PATH,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_SCHEMA,
  WYL_FACT_OFFLINE_RESTORE_VALIDATION_FAILURE_REPLAY,
} WylFactOfflineRestoreValidationFailure;

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_PENDING_NONE = 0,
  WYL_FACT_OFFLINE_RESTORE_PENDING_INVENTORY = 1u << 0,
  WYL_FACT_OFFLINE_RESTORE_PENDING_ENTRY = 1u << 1,
  WYL_FACT_OFFLINE_RESTORE_PENDING_CONTENT = 1u << 2,
  WYL_FACT_OFFLINE_RESTORE_PENDING_METADATA = 1u << 3,
  WYL_FACT_OFFLINE_RESTORE_PENDING_REPLAY = 1u << 4,
  WYL_FACT_OFFLINE_RESTORE_PENDING_ALL =
      WYL_FACT_OFFLINE_RESTORE_PENDING_INVENTORY
      | WYL_FACT_OFFLINE_RESTORE_PENDING_ENTRY
      | WYL_FACT_OFFLINE_RESTORE_PENDING_CONTENT
      | WYL_FACT_OFFLINE_RESTORE_PENDING_METADATA
      | WYL_FACT_OFFLINE_RESTORE_PENDING_REPLAY,
} WylFactOfflineRestorePendingChecks;

/* Assertions emitted by a future authority-retaining collector.  This value
 * is not provenance and cannot authorize reopening or mutation.  CONFORMING
 * means exact POSIX owner/mode or protected owner-only Windows ACL. */
typedef struct
{
  const gchar *operation_uuid;
  const gchar *graph_id;
  WylFactArtifactInventoryObservation inventory_start;
  WylFactArtifactInventoryObservation inventory_end;
  guint operation_owned_stages;
  guint foreign_restore_stages;
  guint unknown_entries;
  gboolean present;
  gboolean regular;
  gboolean reparse;
  guint link_count;
  WylFactArtifactMainTransitionOwnerState owner_state;
  WylFactArtifactInventoryIdentity identity;
  guint64 logical_bytes;
  const gchar *checksum;
  const gchar *tenant_id;
  const gchar *metadata_graph_id;
  const gchar *store_uuid;
  guint64 format_version;
  guint64 path_encoding_version;
  const gchar *schema_digest;
  WylFactOfflineRestoreReplayResult replay_result;
  WylFactArtifactInventoryIdentity replay_identity;
  const gchar *replay_schema_digest;
} WylFactOfflineRestoreStagedObservation;

typedef struct
{
  WylFactOfflineRestoreValidationStatus status;
  WylFactOfflineRestoreValidationFailure failure;
  guint graph_index;
  guint checked_graph_count;
  guint64 validated_revision;
  guint pending_checks;
} WylFactOfflineRestoreValidationResult;

/* Failure precedence is input/bounds, journal phase, manifest binding,
 * compatibility, admission, staged cardinality/order, then each graph's
 * inventory, entry, content, metadata, and replay evidence.  graph_index is
 * G_MAXUINT for non-graph failures; checked_graph_count excludes the failing
 * graph.  DRY_RUN requires |staged| to be NULL, not an empty array. */
WylFactOfflineRestoreValidationStatus wyl_fact_offline_restore_validate
  (WylFactOfflineRestoreValidationMode mode, GBytes *canonical_manifest,
    const WylFactOfflineRestoreJournal *journal,
    const WylFactOfflineRestoreAdmissionEvidence *admission,
    const GPtrArray *staged,
    WylFactOfflineRestoreValidationResult *out_result);

G_END_DECLS

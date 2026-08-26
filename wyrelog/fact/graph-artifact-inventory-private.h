/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS

/*
 * This is deliberately a value-only contract.  An inventory never returns a
 * directory entry name, path, descriptor, HANDLE, or reopen token.  Provider
 * implementations build the snapshot while holding the namespace's existing
 * cooperative reader guard and publish it only after the guard and every
 * observed identity have been revalidated.
 */
typedef struct WylFactArtifactInventorySnapshot
    WylFactArtifactInventorySnapshot;

typedef enum
{
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID = 0,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSTABLE,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSUPPORTED_ALLOCATION,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_CANCELLED,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY,
  WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
} WylFactArtifactInventoryStatus;

typedef enum
{
  WYL_FACT_ARTIFACT_INVENTORY_MAIN = 0,
  WYL_FACT_ARTIFACT_INVENTORY_WAL,
  WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT,
  WYL_FACT_ARTIFACT_INVENTORY_RECOVERY,
  WYL_FACT_ARTIFACT_INVENTORY_LOCK,
  /* Aggregate of bounded DuckDB private temporary roots and children. */
  WYL_FACT_ARTIFACT_INVENTORY_TEMP,
  WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT,
} WylFactArtifactInventorySlot;

typedef enum
{
  WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY = 0,
  WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY,
  WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY,
  WYL_FACT_ARTIFACT_INVENTORY_SUBSTITUTED_ENTRY,
  WYL_FACT_ARTIFACT_INVENTORY_OVER_LIMIT_ENTRY,
  WYL_FACT_ARTIFACT_INVENTORY_UNREADABLE_ENTRY,
  WYL_FACT_ARTIFACT_INVENTORY_ANOMALY_COUNT,
} WylFactArtifactInventoryAnomaly;

typedef struct
{
  guint64 domain;
  /* POSIX uses object with width zero.  Windows uses all 16 bytes below with
   * width 16 and leaves object zero; no provider may publish a partial width. */
  guint64 object;
  guint8 object_bytes[16];
  guint8 object_width;
} WylFactArtifactInventoryIdentity;

gboolean wyl_fact_artifact_inventory_identity_equal
  (const WylFactArtifactInventoryIdentity *,
    const WylFactArtifactInventoryIdentity *);

/* These opaque observations are provider-owned identity/fingerprint values.
 * They are not filesystem handles or caller-selected names. */
typedef struct
{
  WylFactArtifactInventoryIdentity directory_identity;
  WylFactArtifactInventoryIdentity guard_identity;
  guint64 entry_fingerprint;
} WylFactArtifactInventoryObservation;

/* Published per-slot evidence is value-only.  In particular, it carries no
 * entry name, path, descriptor, HANDLE, or token that can reopen or mutate an
 * artifact.  A FALSE return from the accessor below always leaves this value
 * fully initialized to zero. */
typedef struct
{
  gboolean present;
  WylFactArtifactInventoryIdentity identity;
  guint64 logical_bytes;
  gboolean allocation_supported;
  guint64 allocated_bytes;
} WylFactArtifactInventorySlotEvidence;

WylFactArtifactInventorySnapshot *
wyl_fact_artifact_inventory_snapshot_new (guint max_anomalies);
void wyl_fact_artifact_inventory_snapshot_free
  (WylFactArtifactInventorySnapshot *snapshot);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactArtifactInventorySnapshot,
    wyl_fact_artifact_inventory_snapshot_free)
void wyl_fact_artifact_inventory_snapshot_clear
  (WylFactArtifactInventorySnapshot *snapshot);

/* Start/end observations are compared at finalization.  A mismatch discards
 * all temporary slots and byte totals and returns UNSTABLE.  The caller must
 * hold the existing shared reader guard for the whole interval; the
 * observation check does not claim to stop non-cooperating writers. */
void wyl_fact_artifact_inventory_snapshot_begin
  (WylFactArtifactInventorySnapshot *snapshot,
    const WylFactArtifactInventoryObservation *observation);
void wyl_fact_artifact_inventory_snapshot_end
  (WylFactArtifactInventorySnapshot *snapshot,
    const WylFactArtifactInventoryObservation *observation);

wyrelog_error_t wyl_fact_artifact_inventory_snapshot_set_slot
  (WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot,
    const WylFactArtifactInventoryIdentity *identity, gboolean present,
    guint64 logical_bytes, gboolean allocation_supported,
    guint64 allocated_bytes);
wyrelog_error_t wyl_fact_artifact_inventory_snapshot_add_anomaly
  (WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventoryAnomaly anomaly);
wyrelog_error_t wyl_fact_artifact_inventory_snapshot_cancel
  (WylFactArtifactInventorySnapshot *snapshot);
wyrelog_error_t wyl_fact_artifact_inventory_snapshot_fail
  (WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventoryStatus status);
wyrelog_error_t wyl_fact_artifact_inventory_snapshot_finalize
  (WylFactArtifactInventorySnapshot *snapshot);

WylFactArtifactInventoryStatus
wyl_fact_artifact_inventory_snapshot_status
  (const WylFactArtifactInventorySnapshot *snapshot);
gboolean wyl_fact_artifact_inventory_snapshot_get_slot_evidence
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot,
    WylFactArtifactInventorySlotEvidence *out_evidence);
gboolean wyl_fact_artifact_inventory_snapshot_slot_present
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot);
void wyl_fact_artifact_inventory_snapshot_slot_identity
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot,
    WylFactArtifactInventoryIdentity *out_identity);
guint64 wyl_fact_artifact_inventory_snapshot_logical_bytes
  (const WylFactArtifactInventorySnapshot *snapshot);
guint64 wyl_fact_artifact_inventory_snapshot_allocated_bytes
  (const WylFactArtifactInventorySnapshot *snapshot);
guint wyl_fact_artifact_inventory_snapshot_anomaly_count
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventoryAnomaly anomaly);

G_END_DECLS

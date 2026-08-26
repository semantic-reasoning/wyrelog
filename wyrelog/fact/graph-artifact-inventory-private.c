/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "fact/graph-artifact-inventory-private.h"

#include <stdint.h>
#include <string.h>

#define WYL_FACT_ARTIFACT_INVENTORY_DEFAULT_MAX_ANOMALIES 256u

typedef struct
{
  WylFactArtifactInventoryIdentity identity;
  gboolean present;
  guint64 logical_bytes;
  guint64 allocated_bytes;
  gboolean allocation_unsupported;
  gboolean allocation_supported;
} WylFactArtifactInventorySlotState;

struct WylFactArtifactInventorySnapshot
{
  WylFactArtifactInventoryStatus status;
  guint max_anomalies;
  guint anomalies[WYL_FACT_ARTIFACT_INVENTORY_ANOMALY_COUNT];
  WylFactArtifactInventorySlotState slots
  [WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT];
  gboolean slot_set[WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT];
  guint64 logical_bytes;
  guint64 allocated_bytes;
  gboolean allocation_unsupported;
  WylFactArtifactInventoryObservation begin;
  WylFactArtifactInventoryObservation end;
  gboolean began;
  gboolean ended;
  gboolean finalized;
};

static void
snapshot_zero_result (WylFactArtifactInventorySnapshot *snapshot)
{
  guint max_anomalies = snapshot->max_anomalies;
  memset (snapshot, 0, sizeof *snapshot);
  snapshot->max_anomalies = max_anomalies;
  snapshot->status = WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID;
}

static gboolean
inventory_identity_valid (const WylFactArtifactInventoryIdentity *identity)
{
  if (identity == NULL || (identity->object_width != 0
      && identity->object_width != 16))
    return FALSE;
  if (identity->object_width == 16)
    return identity->object == 0;
  return memcmp (identity->object_bytes, (guint8[16]) { 0 },
             sizeof identity->object_bytes) == 0;
}

gboolean
wyl_fact_artifact_inventory_identity_equal
  (const WylFactArtifactInventoryIdentity *left,
    const WylFactArtifactInventoryIdentity *right)
{
  if (!inventory_identity_valid (left) || !inventory_identity_valid (right)
      || left->domain != right->domain
      || left->object_width != right->object_width)
    return FALSE;
  if (left->object_width == 0)
    return left->object == right->object
           && memcmp (left->object_bytes, right->object_bytes,
               sizeof left->object_bytes) == 0;
  return left->object == 0 && right->object == 0
         && memcmp (left->object_bytes, right->object_bytes,
             sizeof left->object_bytes) == 0;
}

static gboolean
observation_equal (const WylFactArtifactInventoryObservation *left,
    const WylFactArtifactInventoryObservation *right)
{
  return wyl_fact_artifact_inventory_identity_equal
           (&left->directory_identity, &right->directory_identity)
         && wyl_fact_artifact_inventory_identity_equal
           (&left->guard_identity, &right->guard_identity)
         && left->entry_fingerprint == right->entry_fingerprint;
}

static gboolean
snapshot_mutable (const WylFactArtifactInventorySnapshot *snapshot)
{
  return snapshot != NULL
         && !snapshot->finalized
         && snapshot->status == WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID;
}

static gboolean
snapshot_building (const WylFactArtifactInventorySnapshot *snapshot)
{
  return snapshot_mutable (snapshot) && snapshot->began && !snapshot->ended;
}

static gboolean
snapshot_ready_to_finalize
  (const WylFactArtifactInventorySnapshot *snapshot)
{
  return snapshot_mutable (snapshot) && snapshot->began && snapshot->ended;
}

static gboolean
snapshot_published (const WylFactArtifactInventorySnapshot *snapshot)
{
  return snapshot != NULL && snapshot->finalized
         && (snapshot->status == WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE
         || snapshot->status
         == WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN);
}

WylFactArtifactInventorySnapshot *
wyl_fact_artifact_inventory_snapshot_new (guint max_anomalies)
{
  WylFactArtifactInventorySnapshot *snapshot = g_new0
        (WylFactArtifactInventorySnapshot, 1);
  snapshot->max_anomalies = max_anomalies == 0
      ? WYL_FACT_ARTIFACT_INVENTORY_DEFAULT_MAX_ANOMALIES : max_anomalies;
  snapshot->status = WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID;
  return snapshot;
}

void
wyl_fact_artifact_inventory_snapshot_free
  (WylFactArtifactInventorySnapshot *snapshot)
{
  g_free (snapshot);
}

void
wyl_fact_artifact_inventory_snapshot_clear
  (WylFactArtifactInventorySnapshot *snapshot)
{
  if (snapshot != NULL)
    snapshot_zero_result (snapshot);
}

void
wyl_fact_artifact_inventory_snapshot_begin
  (WylFactArtifactInventorySnapshot *snapshot,
    const WylFactArtifactInventoryObservation *observation)
{
  if (!snapshot_mutable (snapshot) || snapshot->began
      || observation == NULL
      || !inventory_identity_valid (&observation->directory_identity)
      || !inventory_identity_valid (&observation->guard_identity))
    return;
  snapshot->begin = *observation;
  snapshot->began = TRUE;
}

void
wyl_fact_artifact_inventory_snapshot_end
  (WylFactArtifactInventorySnapshot *snapshot,
    const WylFactArtifactInventoryObservation *observation)
{
  if (!snapshot_building (snapshot) || observation == NULL
      || !inventory_identity_valid (&observation->directory_identity)
      || !inventory_identity_valid (&observation->guard_identity))
    return;
  snapshot->end = *observation;
  snapshot->ended = TRUE;
}

static gboolean
add_u64_checked (guint64 left, guint64 right, guint64 *out)
{
  if (G_MAXUINT64 - left < right)
    return FALSE;
  *out = left + right;
  return TRUE;
}

wyrelog_error_t
wyl_fact_artifact_inventory_snapshot_set_slot
  (WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot,
    const WylFactArtifactInventoryIdentity *identity, gboolean present,
    guint64 logical_bytes, gboolean allocation_supported,
    guint64 allocated_bytes)
{
  WylFactArtifactInventorySlotState *state;
  guint64 logical_total;
  guint64 allocated_total;
  if (!snapshot_building (snapshot)
      || slot >= WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT)
    return WYRELOG_E_INVALID;
  if ((present && slot < WYL_FACT_ARTIFACT_INVENTORY_TEMP
      && identity == NULL)
      || (present && slot == WYL_FACT_ARTIFACT_INVENTORY_TEMP
      && identity != NULL)
      || (!present && (identity != NULL || logical_bytes != 0
      || !allocation_supported || allocated_bytes != 0))
      || (identity != NULL && !inventory_identity_valid (identity)))
    return wyl_fact_artifact_inventory_snapshot_fail (snapshot,
               WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);
  if (!allocation_supported && allocated_bytes != 0)
    return wyl_fact_artifact_inventory_snapshot_fail (snapshot,
               WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSUPPORTED_ALLOCATION);
  if (!add_u64_checked (snapshot->logical_bytes, logical_bytes,
      &logical_total)
      || (allocation_supported
      && !add_u64_checked (snapshot->allocated_bytes, allocated_bytes,
      &allocated_total)))
    return wyl_fact_artifact_inventory_snapshot_fail (snapshot,
               WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW);
  state = &snapshot->slots[slot];
  if (snapshot->slot_set[slot])
    return wyl_fact_artifact_inventory_snapshot_fail (snapshot,
               WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);
  snapshot->slot_set[slot] = TRUE;
  state->identity = identity == NULL
      ? (WylFactArtifactInventoryIdentity) { 0 } : *identity;
  state->present = present;
  state->logical_bytes = logical_bytes;
  state->allocation_supported = allocation_supported;
  state->allocated_bytes = allocated_bytes;
  snapshot->logical_bytes = logical_total;
  if (allocation_supported)
    snapshot->allocated_bytes = allocated_total;
  else
    snapshot->allocation_unsupported = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_inventory_snapshot_add_anomaly
  (WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventoryAnomaly anomaly)
{
  if (!snapshot_building (snapshot)
      || anomaly >= WYL_FACT_ARTIFACT_INVENTORY_ANOMALY_COUNT)
    return WYRELOG_E_INVALID;
  if (snapshot->anomalies[anomaly] == snapshot->max_anomalies)
    return wyl_fact_artifact_inventory_snapshot_fail (snapshot,
               WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW);
  snapshot->anomalies[anomaly]++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_inventory_snapshot_cancel
  (WylFactArtifactInventorySnapshot *snapshot)
{
  return wyl_fact_artifact_inventory_snapshot_fail (snapshot,
             WYL_FACT_ARTIFACT_INVENTORY_STATUS_CANCELLED);
}

wyrelog_error_t
wyl_fact_artifact_inventory_snapshot_fail
  (WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventoryStatus status)
{
  if (!snapshot_building (snapshot)
      || status <= WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID
      || status == WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE
      || status == WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN)
    return WYRELOG_E_INVALID;
  snapshot_zero_result (snapshot);
  snapshot->status = status;
  return status == WYL_FACT_ARTIFACT_INVENTORY_STATUS_CANCELLED
      ? WYRELOG_E_CANCELLED : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_inventory_snapshot_finalize
  (WylFactArtifactInventorySnapshot *snapshot)
{
  if (!snapshot_ready_to_finalize (snapshot))
    return WYRELOG_E_INVALID;
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    if (!snapshot->slot_set[slot]) {
      snapshot_zero_result (snapshot);
      snapshot->status = WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY;
      return WYRELOG_E_POLICY;
    }
  }
  if (!observation_equal (&snapshot->begin, &snapshot->end)) {
    snapshot_zero_result (snapshot);
    snapshot->status = WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSTABLE;
    return WYRELOG_E_BUSY;
  }
  if (snapshot->allocation_unsupported) {
    snapshot_zero_result (snapshot);
    snapshot->status =
        WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSUPPORTED_ALLOCATION;
    return WYRELOG_E_POLICY;
  }
  snapshot->status = snapshot->anomalies[WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY]
      || snapshot->anomalies[WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY]
      || snapshot->anomalies[WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY]
      || snapshot->anomalies[WYL_FACT_ARTIFACT_INVENTORY_SUBSTITUTED_ENTRY]
      || snapshot->anomalies[WYL_FACT_ARTIFACT_INVENTORY_OVER_LIMIT_ENTRY]
      || snapshot->anomalies[WYL_FACT_ARTIFACT_INVENTORY_UNREADABLE_ENTRY]
      ? WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN
      : WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE;
  snapshot->finalized = TRUE;
  return WYRELOG_E_OK;
}

WylFactArtifactInventoryStatus
wyl_fact_artifact_inventory_snapshot_status
  (const WylFactArtifactInventorySnapshot *snapshot)
{
  return snapshot == NULL ? WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID
      : snapshot->status;
}

gboolean
wyl_fact_artifact_inventory_snapshot_get_slot_evidence
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot,
    WylFactArtifactInventorySlotEvidence *out_evidence)
{
  if (out_evidence != NULL)
    *out_evidence = (WylFactArtifactInventorySlotEvidence) { 0 };
  if (out_evidence == NULL || !snapshot_published (snapshot)
      || slot >= WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT)
    return FALSE;
  const WylFactArtifactInventorySlotState *state = &snapshot->slots[slot];
  *out_evidence = (WylFactArtifactInventorySlotEvidence) {
    .present = state->present,
    .identity = state->identity,
    .logical_bytes = state->logical_bytes,
    .allocation_supported = state->allocation_supported,
    .allocated_bytes = state->allocated_bytes,
  };
  return TRUE;
}

gboolean
wyl_fact_artifact_inventory_snapshot_get_observation
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventoryObservation *out_observation)
{
  if (out_observation != NULL)
    *out_observation = (WylFactArtifactInventoryObservation) { 0 };
  if (out_observation == NULL || !snapshot_published (snapshot))
    return FALSE;
  *out_observation = snapshot->begin;
  return TRUE;
}

gboolean
wyl_fact_artifact_inventory_snapshot_slot_present
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot)
{
  WylFactArtifactInventorySlotEvidence evidence = { 0 };
  return wyl_fact_artifact_inventory_snapshot_get_slot_evidence (snapshot,
             slot, &evidence)
         && evidence.present;
}

void
wyl_fact_artifact_inventory_snapshot_slot_identity
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot,
    WylFactArtifactInventoryIdentity *out_identity)
{
  WylFactArtifactInventorySlotEvidence evidence = { 0 };
  if (out_identity != NULL) {
    *out_identity = (WylFactArtifactInventoryIdentity) { 0 };
    if (wyl_fact_artifact_inventory_snapshot_get_slot_evidence (snapshot,
        slot, &evidence))
      *out_identity = evidence.identity;
  }
}

guint64
wyl_fact_artifact_inventory_snapshot_logical_bytes
  (const WylFactArtifactInventorySnapshot *snapshot)
{
  return snapshot_published (snapshot) ? snapshot->logical_bytes : 0;
}

guint64
wyl_fact_artifact_inventory_snapshot_allocated_bytes
  (const WylFactArtifactInventorySnapshot *snapshot)
{
  return snapshot_published (snapshot) ? snapshot->allocated_bytes : 0;
}

guint
wyl_fact_artifact_inventory_snapshot_anomaly_count
  (const WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventoryAnomaly anomaly)
{
  return !snapshot_published (snapshot)
         || anomaly >= WYL_FACT_ARTIFACT_INVENTORY_ANOMALY_COUNT
      ? 0 : snapshot->anomalies[anomaly];
}

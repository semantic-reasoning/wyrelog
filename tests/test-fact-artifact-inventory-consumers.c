/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>

#include "fact/graph-artifact-inventory-private.h"

typedef enum
{
  QUOTA_EVIDENCE_UNAVAILABLE = 0,
  QUOTA_EVIDENCE_EXACT,
  QUOTA_EVIDENCE_LOWER_BOUND_BLOCKED,
} QuotaEvidenceClass;

static WylFactArtifactInventorySnapshot *
build_consumer_snapshot (gboolean unknown)
{
  WylFactArtifactInventoryObservation point = {
    .directory_identity = { 1, 11, { 0 }, 0 },
    .guard_identity = { 2, 17, { 0 }, 0 },
    .entry_fingerprint = 23,
  };
  WylFactArtifactInventorySnapshot *snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    gboolean present = slot == WYL_FACT_ARTIFACT_INVENTORY_MAIN
        || slot == WYL_FACT_ARTIFACT_INVENTORY_WAL;
    WylFactArtifactInventoryIdentity identity = {
      .domain = 3,
      .object = 31 + slot,
    };
    const WylFactArtifactInventoryIdentity *identity_ptr =
        present ? &identity : NULL;
    guint64 logical = slot == WYL_FACT_ARTIFACT_INVENTORY_MAIN ? 10
        : slot == WYL_FACT_ARTIFACT_INVENTORY_WAL ? 5 : 0;
    guint64 allocated = slot == WYL_FACT_ARTIFACT_INVENTORY_MAIN ? 4096
        : slot == WYL_FACT_ARTIFACT_INVENTORY_WAL ? 512 : 0;
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
        slot, identity_ptr, present, logical, TRUE, allocated), ==,
        WYRELOG_E_OK);
  }
  if (unknown)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly
          (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==,
        WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  return snapshot;
}

/* #551 may choose checkpoint/main-only or a multi-artifact manifest later.
 * This contract probe proves only that complete namespace closure is
 * distinguishable without receiving raw filesystem authority. */
static gboolean
backup_like_has_complete_closure
  (const WylFactArtifactInventorySnapshot *snapshot)
{
  if (wyl_fact_artifact_inventory_snapshot_status (snapshot)
      != WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE)
    return FALSE;
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    WylFactArtifactInventorySlotEvidence evidence = { 0 };
    if (!wyl_fact_artifact_inventory_snapshot_get_slot_evidence (snapshot,
        slot, &evidence) || !evidence.allocation_supported)
      return FALSE;
  }
  return TRUE;
}

/* #553 owns quota policy and reservations.  This probe establishes only the
 * neutral evidence rule: unknown state can provide a lower bound, but cannot
 * reduce accounting or authorize admission as an exact observation. */
static QuotaEvidenceClass
quota_like_classify (const WylFactArtifactInventorySnapshot *snapshot,
    guint64 *out_allocated_lower_bound)
{
  *out_allocated_lower_bound = 0;
  WylFactArtifactInventoryStatus status =
      wyl_fact_artifact_inventory_snapshot_status (snapshot);
  if (status != WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE
      && status != WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN)
    return QUOTA_EVIDENCE_UNAVAILABLE;
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    WylFactArtifactInventorySlotEvidence evidence = { 0 };
    if (!wyl_fact_artifact_inventory_snapshot_get_slot_evidence (snapshot,
        slot, &evidence) || !evidence.allocation_supported
        || G_MAXUINT64 - *out_allocated_lower_bound < evidence.allocated_bytes) {
      *out_allocated_lower_bound = 0;
      return QUOTA_EVIDENCE_UNAVAILABLE;
    }
    *out_allocated_lower_bound += evidence.allocated_bytes;
  }
  return status == WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE
      ? QUOTA_EVIDENCE_EXACT : QUOTA_EVIDENCE_LOWER_BOUND_BLOCKED;
}

static void
test_stable_snapshot_supports_consumers (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      build_consumer_snapshot (FALSE);
  g_assert_true (backup_like_has_complete_closure (snapshot));
  guint64 lower_bound = 0;
  g_assert_cmpint (quota_like_classify (snapshot, &lower_bound), ==,
      QUOTA_EVIDENCE_EXACT);
  g_assert_cmpuint (lower_bound, ==, 4608);
  g_assert_cmpuint (lower_bound, ==,
      wyl_fact_artifact_inventory_snapshot_allocated_bytes (snapshot));
}

static void
test_unknown_snapshot_blocks_completion_without_reducing_usage (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      build_consumer_snapshot (TRUE);
  g_assert_false (backup_like_has_complete_closure (snapshot));
  guint64 lower_bound = 0;
  g_assert_cmpint (quota_like_classify (snapshot, &lower_bound), ==,
      QUOTA_EVIDENCE_LOWER_BOUND_BLOCKED);
  g_assert_cmpuint (lower_bound, ==, 4608);
  g_assert_cmpuint (lower_bound, ==,
      wyl_fact_artifact_inventory_snapshot_allocated_bytes (snapshot));
}

static void
test_failure_snapshot_is_not_consumable (void)
{
  WylFactArtifactInventoryObservation point = {
    .directory_identity = { 1, 11, { 0 }, 0 },
    .guard_identity = { 2, 17, { 0 }, 0 },
    .entry_fingerprint = 23,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_cancel (snapshot), ==,
      WYRELOG_E_CANCELLED);
  g_assert_false (backup_like_has_complete_closure (snapshot));
  guint64 lower_bound = 99;
  g_assert_cmpint (quota_like_classify (snapshot, &lower_bound), ==,
      QUOTA_EVIDENCE_UNAVAILABLE);
  g_assert_cmpuint (lower_bound, ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/artifact-inventory-consumers/stable",
      test_stable_snapshot_supports_consumers);
  g_test_add_func ("/fact/artifact-inventory-consumers/unknown-blocked",
      test_unknown_snapshot_blocks_completion_without_reducing_usage);
  g_test_add_func ("/fact/artifact-inventory-consumers/failure-unavailable",
      test_failure_snapshot_is_not_consumable);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>

#include "fact/graph-artifact-inventory-private.h"

static WylFactArtifactInventoryObservation
observation (guint64 fingerprint)
{
  WylFactArtifactInventoryObservation result = { { 1, 11 }, { 2, 17 },
                                                 fingerprint };
  return result;
}

static void
test_stable_typed_snapshot (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (23);
  WylFactArtifactInventoryObservation point_after = observation (24);
  g_assert_nonnull (snapshot);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN,
      &(WylFactArtifactInventoryIdentity) { 3, 1 }, TRUE, 10, TRUE, 4096), !=,
      WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN,
      &(WylFactArtifactInventoryIdentity) { 3, 1 }, TRUE, 10, TRUE, 4096), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point_after);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot),
      ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN);
  g_assert_true (wyl_fact_artifact_inventory_snapshot_slot_present (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN));
  WylFactArtifactInventoryIdentity identity = { 0, 0 };
  wyl_fact_artifact_inventory_snapshot_slot_identity (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &identity);
  g_assert_cmpuint (identity.domain, ==, 3);
  g_assert_cmpuint (identity.object, ==, 1);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_logical_bytes
        (snapshot), ==, 10);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_allocated_bytes
        (snapshot), ==, 4096);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_anomaly_count
        (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, 1);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_WAL,
      &(WylFactArtifactInventoryIdentity) { 3, 2 }, TRUE, 1, TRUE, 512), !=,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot),
      ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN);
}

static void
test_mismatch_discards_complete_result (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation before = observation (1);
  WylFactArtifactInventoryObservation after = observation (2);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &before);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_WAL,
      &(WylFactArtifactInventoryIdentity) { 3, 2 }, TRUE, 9, TRUE, 512), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &after);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot),
      ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSTABLE);
  g_assert_false (wyl_fact_artifact_inventory_snapshot_slot_present (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_WAL));
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_logical_bytes
        (snapshot), ==, 0);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_allocated_bytes
        (snapshot), ==, 0);
}

static void
test_bounded_failure_statuses_clear_result (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (1);
  WylFactArtifactInventoryObservation point = observation (7);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot),
      ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_logical_bytes
        (snapshot), ==, 0);
  wyl_fact_artifact_inventory_snapshot_clear (snapshot);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN,
      &(WylFactArtifactInventoryIdentity) { 3, 1 }, TRUE, 1, FALSE, 0), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot),
      ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSUPPORTED_ALLOCATION);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_logical_bytes
        (snapshot), ==, 0);
  wyl_fact_artifact_inventory_snapshot_clear (snapshot);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_cancel (snapshot),
      !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot),
      ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_CANCELLED);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/artifact-inventory/stable-typed-snapshot",
      test_stable_typed_snapshot);
  g_test_add_func ("/fact/artifact-inventory/mismatch-discards-result",
      test_mismatch_discards_complete_result);
  g_test_add_func ("/fact/artifact-inventory/bounded-failure-statuses",
      test_bounded_failure_statuses_clear_result);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <string.h>

#include "fact/graph-artifact-inventory-private.h"

static WylFactArtifactInventoryObservation
observation (guint64 fingerprint)
{
  WylFactArtifactInventoryObservation result = { { 1, 11, { 0 }, 0 },
                                                 { 2, 17, { 0 }, 0 },
                                                 fingerprint };
  return result;
}

static WylFactArtifactInventoryIdentity
extended_identity (guint64 domain, guint64 object, guint8 tail)
{
  WylFactArtifactInventoryIdentity result = { domain, object, { 0 }, 0 };
  result.object_bytes[0] = 0x80;
  result.object_bytes[15] = tail;
  result.object = 0;
  result.object_width = 16;
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
      &(WylFactArtifactInventoryIdentity) { 3, 1, { 0 }, 0 }, TRUE, 10, TRUE,
      4096), !=,
      WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN,
      &(WylFactArtifactInventoryIdentity) { 3, 1, { 0 }, 0 }, TRUE, 10, TRUE,
      4096), ==,
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
  WylFactArtifactInventoryIdentity identity = { 0 };
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
      &(WylFactArtifactInventoryIdentity) { 3, 2, { 0 }, 0 }, TRUE, 1, TRUE,
      512), !=,
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
      &(WylFactArtifactInventoryIdentity) { 3, 2, { 0 }, 0 }, TRUE, 9, TRUE,
      512), ==,
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
      &(WylFactArtifactInventoryIdentity) { 3, 1, { 0 }, 0 }, TRUE, 1, FALSE,
      0), ==,
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

static void
test_extended_identity_is_value_preserved (void)
{
  WylFactArtifactInventoryIdentity first = extended_identity (7, 0, 1);
  WylFactArtifactInventoryIdentity second = extended_identity (7, 0, 2);
  WylFactArtifactInventoryObservation point = observation (31);
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &first, TRUE, 1, TRUE, 1), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  WylFactArtifactInventoryIdentity round_trip = { 0 };
  wyl_fact_artifact_inventory_snapshot_slot_identity (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &round_trip);
  g_assert_cmpuint (round_trip.domain, ==, first.domain);
  g_assert_cmpuint (round_trip.object, ==, first.object);
  g_assert_cmpint (memcmp (round_trip.object_bytes, first.object_bytes,
      sizeof first.object_bytes), ==, 0);
  g_assert_cmpint (memcmp (first.object_bytes, second.object_bytes,
      sizeof first.object_bytes), !=, 0);
  g_assert_true (wyl_fact_artifact_inventory_identity_equal (&first, &first));
  WylFactArtifactInventoryIdentity contradictory = first;
  contradictory.object = 99;
  g_assert_false (wyl_fact_artifact_inventory_identity_equal (&first,
      &contradictory));
  g_autoptr (WylFactArtifactInventorySnapshot) invalid_snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  wyl_fact_artifact_inventory_snapshot_begin (invalid_snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot
        (invalid_snapshot, WYL_FACT_ARTIFACT_INVENTORY_MAIN, &contradictory,
      TRUE, 1, TRUE, 1), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status
        (invalid_snapshot), ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);

  g_autoptr (WylFactArtifactInventorySnapshot) changed_snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation extended_point = observation (31);
  extended_point.directory_identity = extended_identity (1, 0, 1);
  extended_point.guard_identity = extended_identity (2, 0, 1);
  WylFactArtifactInventoryObservation changed = extended_point;
  changed.directory_identity.object_bytes[15] = 2;
  wyl_fact_artifact_inventory_snapshot_begin (changed_snapshot,
      &extended_point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot
        (changed_snapshot, WYL_FACT_ARTIFACT_INVENTORY_MAIN, &first, TRUE, 1,
      TRUE, 1), ==, WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (changed_snapshot, &changed);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize
        (changed_snapshot), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status
        (changed_snapshot), ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSTABLE);
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
  g_test_add_func ("/fact/artifact-inventory/extended-identity",
      test_extended_identity_is_value_preserved);
  return g_test_run ();
}

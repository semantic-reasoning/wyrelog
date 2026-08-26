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
identity_for_slot (WylFactArtifactInventorySlot slot)
{
  return (WylFactArtifactInventoryIdentity) {
           .domain = 7,
           .object = 100 + slot,
  };
}

static WylFactArtifactInventoryIdentity
extended_identity (guint64 domain, guint8 tail)
{
  WylFactArtifactInventoryIdentity result = { domain, 0, { 0 }, 16 };
  result.object_bytes[0] = 0x80;
  result.object_bytes[15] = tail;
  return result;
}

static gboolean
slot_is_present (WylFactArtifactInventorySlot slot)
{
  return slot == WYL_FACT_ARTIFACT_INVENTORY_MAIN
         || slot == WYL_FACT_ARTIFACT_INVENTORY_WAL
         || slot == WYL_FACT_ARTIFACT_INVENTORY_LOCK
         || slot == WYL_FACT_ARTIFACT_INVENTORY_TEMP;
}

static guint64
slot_logical_bytes (WylFactArtifactInventorySlot slot)
{
  static const guint64 values[WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT] = {
    10, 5, 0, 0, 1, 7,
  };
  return values[slot];
}

static guint64
slot_allocated_bytes (WylFactArtifactInventorySlot slot)
{
  static const guint64 values[WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT] = {
    4096, 512, 0, 0, 512, 1024,
  };
  return values[slot];
}

static wyrelog_error_t
set_canonical_slot (WylFactArtifactInventorySnapshot *snapshot,
    WylFactArtifactInventorySlot slot)
{
  gboolean present = slot_is_present (slot);
  WylFactArtifactInventoryIdentity identity = identity_for_slot (slot);
  const WylFactArtifactInventoryIdentity *identity_ptr =
      present && slot != WYL_FACT_ARTIFACT_INVENTORY_TEMP ? &identity : NULL;
  return wyl_fact_artifact_inventory_snapshot_set_slot (snapshot, slot,
             identity_ptr, present, slot_logical_bytes (slot), TRUE,
             slot_allocated_bytes (slot));
}

static void
populate_slots_except (WylFactArtifactInventorySnapshot *snapshot,
    gint omitted_slot, const WylFactArtifactInventoryObservation *point)
{
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, point);
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    if ((gint) slot == omitted_slot)
      continue;
    g_assert_cmpint (set_canonical_slot (snapshot, slot), ==, WYRELOG_E_OK);
  }
}

static void
assert_no_published_evidence (WylFactArtifactInventorySnapshot *snapshot)
{
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    WylFactArtifactInventorySlotEvidence evidence = {
      .present = TRUE,
      .identity = { 9, 9, { 9 }, 0 },
      .logical_bytes = 9,
      .allocation_supported = TRUE,
      .allocated_bytes = 9,
    };
    g_assert_false (wyl_fact_artifact_inventory_snapshot_get_slot_evidence
          (snapshot, slot, &evidence));
    g_assert_false (evidence.present);
    g_assert_cmpuint (evidence.identity.domain, ==, 0);
    g_assert_cmpuint (evidence.identity.object, ==, 0);
    g_assert_cmpuint (evidence.logical_bytes, ==, 0);
    g_assert_false (evidence.allocation_supported);
    g_assert_cmpuint (evidence.allocated_bytes, ==, 0);
  }
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_logical_bytes
        (snapshot), ==, 0);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_allocated_bytes
        (snapshot), ==, 0);
  WylFactArtifactInventoryObservation published = {
    .directory_identity = { 9, 9, { 9 }, 0 },
    .guard_identity = { 9, 9, { 9 }, 0 },
    .entry_fingerprint = 9,
  };
  g_assert_false (wyl_fact_artifact_inventory_snapshot_get_observation
        (snapshot, &published));
  g_assert_cmpuint (published.directory_identity.domain, ==, 0);
  g_assert_cmpuint (published.guard_identity.domain, ==, 0);
  g_assert_cmpuint (published.entry_fingerprint, ==, 0);
}

static void
test_complete_slot_evidence (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (23);
  populate_slots_except (snapshot, -1, &point);
  assert_no_published_evidence (snapshot);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE);

  guint64 logical_total = 0;
  guint64 allocated_total = 0;
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    WylFactArtifactInventorySlotEvidence evidence = { 0 };
    g_assert_true (wyl_fact_artifact_inventory_snapshot_get_slot_evidence
          (snapshot, slot, &evidence));
    g_assert_cmpint (evidence.present, ==, slot_is_present (slot));
    g_assert_cmpuint (evidence.logical_bytes, ==, slot_logical_bytes (slot));
    g_assert_true (evidence.allocation_supported);
    g_assert_cmpuint (evidence.allocated_bytes, ==,
        slot_allocated_bytes (slot));
    if (evidence.present && slot != WYL_FACT_ARTIFACT_INVENTORY_TEMP) {
      WylFactArtifactInventoryIdentity expected = identity_for_slot (slot);
      g_assert_true (wyl_fact_artifact_inventory_identity_equal
            (&evidence.identity, &expected));
    } else {
      g_assert_cmpuint (evidence.identity.domain, ==, 0);
      g_assert_cmpuint (evidence.identity.object, ==, 0);
    }
    logical_total += evidence.logical_bytes;
    allocated_total += evidence.allocated_bytes;
  }
  g_assert_cmpuint (logical_total, ==,
      wyl_fact_artifact_inventory_snapshot_logical_bytes (snapshot));
  g_assert_cmpuint (allocated_total, ==,
      wyl_fact_artifact_inventory_snapshot_allocated_bytes (snapshot));
  g_assert_true (wyl_fact_artifact_inventory_snapshot_slot_present (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN));
  g_assert_false (wyl_fact_artifact_inventory_snapshot_slot_present (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT));
}

static void
test_unknown_snapshot_publishes_lower_bound (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (31);
  populate_slots_except (snapshot, -1, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN);
  WylFactArtifactInventorySlotEvidence evidence = { 0 };
  g_assert_true (wyl_fact_artifact_inventory_snapshot_get_slot_evidence
        (snapshot, WYL_FACT_ARTIFACT_INVENTORY_MAIN, &evidence));
  g_assert_true (evidence.present);
  g_assert_cmpuint (evidence.logical_bytes, ==, 10);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_anomaly_count
        (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, 1);
}

static void
test_omitted_slot_matrix_fails_closed (void)
{
  WylFactArtifactInventoryObservation point = observation (41);
  for (guint omitted = 0; omitted < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT;
      omitted++) {
    g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
        wyl_fact_artifact_inventory_snapshot_new (4);
    populate_slots_except (snapshot, (gint) omitted, &point);
    wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
        ==, WYRELOG_E_POLICY);
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot),
        ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);
    assert_no_published_evidence (snapshot);
  }
}

static void
assert_noncanonical_slot_fails (WylFactArtifactInventorySlot slot,
    const WylFactArtifactInventoryIdentity *identity, gboolean present,
    guint64 logical, gboolean allocation_supported, guint64 allocated)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (51);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      slot, identity, present, logical, allocation_supported, allocated), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);
  assert_no_published_evidence (snapshot);
}

static void
test_slot_canonicalization_and_duplicate (void)
{
  WylFactArtifactInventoryIdentity identity = identity_for_slot
        (WYL_FACT_ARTIFACT_INVENTORY_MAIN);
  assert_noncanonical_slot_fails (WYL_FACT_ARTIFACT_INVENTORY_MAIN, NULL,
      TRUE, 1, TRUE, 1);
  assert_noncanonical_slot_fails (WYL_FACT_ARTIFACT_INVENTORY_TEMP, &identity,
      TRUE, 1, TRUE, 1);
  assert_noncanonical_slot_fails (WYL_FACT_ARTIFACT_INVENTORY_WAL, &identity,
      FALSE, 0, TRUE, 0);
  assert_noncanonical_slot_fails (WYL_FACT_ARTIFACT_INVENTORY_WAL, NULL,
      FALSE, 1, TRUE, 0);
  assert_noncanonical_slot_fails (WYL_FACT_ARTIFACT_INVENTORY_WAL, NULL,
      FALSE, 0, FALSE, 0);

  g_autoptr (WylFactArtifactInventorySnapshot) duplicate =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (52);
  wyl_fact_artifact_inventory_snapshot_begin (duplicate, &point);
  g_assert_cmpint (set_canonical_slot (duplicate,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN), ==, WYRELOG_E_OK);
  g_assert_cmpint (set_canonical_slot (duplicate,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (duplicate), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);
  assert_no_published_evidence (duplicate);
}

static void
test_failure_statuses_clear_evidence (void)
{
  WylFactArtifactInventoryObservation point = observation (61);
  WylFactArtifactInventoryObservation changed = observation (62);
  g_autoptr (WylFactArtifactInventorySnapshot) unstable =
      wyl_fact_artifact_inventory_snapshot_new (4);
  populate_slots_except (unstable, -1, &point);
  wyl_fact_artifact_inventory_snapshot_end (unstable, &changed);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (unstable),
      ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (unstable), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSTABLE);
  assert_no_published_evidence (unstable);

  g_autoptr (WylFactArtifactInventorySnapshot) cancelled =
      wyl_fact_artifact_inventory_snapshot_new (4);
  wyl_fact_artifact_inventory_snapshot_begin (cancelled, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_cancel (cancelled), ==,
      WYRELOG_E_CANCELLED);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (cancelled), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_CANCELLED);
  assert_no_published_evidence (cancelled);

  g_autoptr (WylFactArtifactInventorySnapshot) unsupported =
      wyl_fact_artifact_inventory_snapshot_new (4);
  wyl_fact_artifact_inventory_snapshot_begin (unsupported, &point);
  for (guint slot = 0; slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++) {
    if (slot == WYL_FACT_ARTIFACT_INVENTORY_MAIN) {
      WylFactArtifactInventoryIdentity identity = identity_for_slot (slot);
      g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot
            (unsupported, slot, &identity, TRUE, 1, FALSE, 0), ==,
          WYRELOG_E_OK);
    } else {
      g_assert_cmpint (set_canonical_slot (unsupported, slot), ==,
          WYRELOG_E_OK);
    }
  }
  wyl_fact_artifact_inventory_snapshot_end (unsupported, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (unsupported),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (unsupported),
      ==, WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSUPPORTED_ALLOCATION);
  assert_no_published_evidence (unsupported);

  g_autoptr (WylFactArtifactInventorySnapshot) overflow =
      wyl_fact_artifact_inventory_snapshot_new (4);
  wyl_fact_artifact_inventory_snapshot_begin (overflow, &point);
  WylFactArtifactInventoryIdentity main_identity = identity_for_slot
        (WYL_FACT_ARTIFACT_INVENTORY_MAIN);
  WylFactArtifactInventoryIdentity wal_identity = identity_for_slot
        (WYL_FACT_ARTIFACT_INVENTORY_WAL);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (overflow,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &main_identity, TRUE, G_MAXUINT64,
      TRUE, G_MAXUINT64), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (overflow,
      WYL_FACT_ARTIFACT_INVENTORY_WAL, &wal_identity, TRUE, 1, TRUE, 1), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (overflow), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW);
  assert_no_published_evidence (overflow);
}

static void
test_anomaly_limit_overflow_clears_evidence (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (1);
  WylFactArtifactInventoryObservation point = observation (69);
  populate_slots_except (snapshot, -1, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW);
  assert_no_published_evidence (snapshot);
}

static void
test_contradictory_extended_identity_fails_closed (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (70);
  WylFactArtifactInventoryIdentity contradictory = extended_identity (13, 1);
  contradictory.object = 99;
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &contradictory, TRUE, 1, TRUE, 1), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY);
  assert_no_published_evidence (snapshot);
}

static void
test_extended_observation_mismatch_clears_evidence (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (71);
  point.directory_identity = extended_identity (21, 1);
  point.guard_identity = extended_identity (22, 1);
  WylFactArtifactInventoryObservation changed = point;
  changed.directory_identity.object_bytes[15] = 2;
  populate_slots_except (snapshot, -1, &point);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &changed);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSTABLE);
  assert_no_published_evidence (snapshot);
}

static void
test_extended_identity_and_sparse_allocation (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (71);
  WylFactArtifactInventoryIdentity main_identity = extended_identity (13, 1);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &main_identity, TRUE, 1024 * 1024,
      TRUE, 4096), ==, WYRELOG_E_OK);
  for (guint slot = WYL_FACT_ARTIFACT_INVENTORY_WAL;
      slot < WYL_FACT_ARTIFACT_INVENTORY_SLOT_COUNT; slot++)
    g_assert_cmpint (set_canonical_slot (snapshot, slot), ==, WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  WylFactArtifactInventorySlotEvidence evidence = { 0 };
  g_assert_true (wyl_fact_artifact_inventory_snapshot_get_slot_evidence
        (snapshot, WYL_FACT_ARTIFACT_INVENTORY_MAIN, &evidence));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&evidence.identity, &main_identity));
  g_assert_cmpuint (evidence.logical_bytes, ==, 1024 * 1024);
  g_assert_cmpuint (evidence.allocated_bytes, ==, 4096);

  WylFactArtifactInventoryIdentity different = extended_identity (13, 2);
  g_assert_false (wyl_fact_artifact_inventory_identity_equal (&main_identity,
      &different));
  WylFactArtifactInventoryIdentity contradictory = main_identity;
  contradictory.object = 99;
  g_assert_false (wyl_fact_artifact_inventory_identity_equal (&main_identity,
      &contradictory));
}

/* The observation accessor is what lets a consumer BIND a snapshot to the
 * directory it is reasoning about.  Corroboration cannot substitute for it:
 * identity.domain proves only same-volume and a slot identity proves an inode
 * rather than a directory, so this is the only direct proof in the surface. */
static void
test_published_observation_binding (void)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot =
      wyl_fact_artifact_inventory_snapshot_new (4);
  WylFactArtifactInventoryObservation point = observation (73);
  point.directory_identity = extended_identity (31, 5);
  point.guard_identity = extended_identity (32, 6);
  WylFactArtifactInventoryObservation published = {
    .directory_identity = { 9, 9, { 9 }, 0 },
    .guard_identity = { 9, 9, { 9 }, 0 },
    .entry_fingerprint = 9,
  };
  g_assert_false (wyl_fact_artifact_inventory_snapshot_get_observation (NULL,
      &published));
  g_assert_cmpuint (published.entry_fingerprint, ==, 0);
  populate_slots_except (snapshot, -1, &point);
  published.entry_fingerprint = 9;
  g_assert_false (wyl_fact_artifact_inventory_snapshot_get_observation
        (snapshot, &published));
  g_assert_cmpuint (published.entry_fingerprint, ==, 0);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  g_assert_true (wyl_fact_artifact_inventory_snapshot_get_observation
        (snapshot, &published));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&published.directory_identity, &point.directory_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&published.guard_identity, &point.guard_identity));
  g_assert_cmpuint (published.entry_fingerprint, ==, 73);
  g_assert_false (wyl_fact_artifact_inventory_snapshot_get_observation
        (snapshot, NULL));
  WylFactArtifactInventoryIdentity neighbour = extended_identity (31, 6);
  g_assert_false (wyl_fact_artifact_inventory_identity_equal
        (&published.directory_identity, &neighbour));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/artifact-inventory/complete-slot-evidence",
      test_complete_slot_evidence);
  g_test_add_func ("/fact/artifact-inventory/unknown-lower-bound",
      test_unknown_snapshot_publishes_lower_bound);
  g_test_add_func ("/fact/artifact-inventory/omitted-slot-matrix",
      test_omitted_slot_matrix_fails_closed);
  g_test_add_func ("/fact/artifact-inventory/canonical-and-duplicate",
      test_slot_canonicalization_and_duplicate);
  g_test_add_func ("/fact/artifact-inventory/failure-zeroing",
      test_failure_statuses_clear_evidence);
  g_test_add_func ("/fact/artifact-inventory/anomaly-limit-overflow",
      test_anomaly_limit_overflow_clears_evidence);
  g_test_add_func ("/fact/artifact-inventory/contradictory-extended-identity",
      test_contradictory_extended_identity_fails_closed);
  g_test_add_func ("/fact/artifact-inventory/extended-observation-mismatch",
      test_extended_observation_mismatch_clears_evidence);
  g_test_add_func ("/fact/artifact-inventory/extended-identity-sparse",
      test_extended_identity_and_sparse_allocation);
  g_test_add_func ("/fact/artifact-inventory/published-observation-binding",
      test_published_observation_binding);
  return g_test_run ();
}

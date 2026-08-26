/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <string.h>

#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-artifact-main-transition-private.h"
#include "fact/graph-artifact-transition-names-private.h"

#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name

typedef WylFactArtifactMainTransitionObservation Observation;
typedef WylFactArtifactMainTransitionRequest Request;
typedef WylFactArtifactMainTransitionResult Result;
typedef WylFactArtifactMainTransition Transition;
typedef WylFactArtifactInventoryIdentity Identity;
typedef WylFactArtifactInventorySnapshot Snapshot;
typedef WylFactArtifactTransitionNames Names;

/*
 * THE NAME-DERIVATION AGREEMENT TEST, AND IT IS PLATFORM-NEUTRAL ON PURPOSE.
 *
 * There are exactly two derivations of the operation-scoped names in the
 * tree: the contract's own, inside graph-artifact-main-transition-private.c,
 * and the shared backend-side one in
 * graph-artifact-transition-names-private.h that the POSIX backend uses today
 * and the native Windows backend will include.  This is the one test that
 * holds them equal.
 *
 * IT LIVES IN ITS OWN UNCONDITIONALLY-REGISTERED FILE RATHER THAN IN THE
 * POSIX SUITE.  Both sides are portable C, so running it only on POSIX would
 * have been sufficient by an ARGUMENT about platform-neutrality -- and that
 * argument decays the moment anyone adds a platform conditional to either
 * derivation, which is exactly when the check would matter most.  Registered
 * unconditionally, it runs on every leg by CONSTRUCTION, including the one
 * the Windows backend will land on.
 *
 * IT CAN CALL dup_stage_name, which is what makes it writable at all: a TEST
 * may hand-build a synthetic admissible Observation to obtain a transition,
 * exactly as the contract's own tests do.  The circularity that forces a
 * backend to derive its own names binds the PROVIDER, not the test.
 */

/* The five fixed names the derived names must never collide with. */
static const gchar *const FIXED_NAMES[] = {
  "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",
  "facts.duckdb.wal.recovery", "facts.duckdb.lock",
};

static Snapshot *
admissible_snapshot (const Observation *observation)
{
  Snapshot *snapshot = wyl_fact_artifact_inventory_snapshot_new (16);
  WylFactArtifactInventoryObservation point = {
    .directory_identity = observation->directory_identity,
    .guard_identity = observation->lease_identity,
    .entry_fingerprint = 11,
  };
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  Identity main_identity = observation->entries[MT (SLOT_MAIN)].identity;
  Identity lock_identity = observation->lease_identity;
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &main_identity, TRUE, 1, TRUE, 1),
      ==, WYRELOG_E_OK);
  const WylFactArtifactInventorySlot absent[] = {
    WYL_FACT_ARTIFACT_INVENTORY_WAL,
    WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT,
    WYL_FACT_ARTIFACT_INVENTORY_RECOVERY,
  };
  for (gsize index = 0; index < G_N_ELEMENTS (absent); index++)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
        absent[index], NULL, FALSE, 0, TRUE, 0), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_LOCK, &lock_identity, TRUE, 1, TRUE, 1),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_TEMP, NULL, FALSE, 0, TRUE, 0), ==,
      WYRELOG_E_OK);
  /* One unknown entry, for the resident stage. */
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  return snapshot;
}

static Transition *
synthetic_transition (const gchar *operation_uuid, const guint8 uuid_bytes[16])
{
  Identity directory = { .domain = 7, .object = 1 };
  Identity lease = { .domain = 7, .object = 2 };
  Identity expected_main = { .domain = 7, .object = 101 };
  Identity staged_main = { .domain = 7, .object = 202 };
  Observation observation = {
    .directory_identity = directory,
    .lease_identity = lease,
    .sealed = TRUE,
    .no_replace_supported = TRUE,
  };
  memcpy (observation.operation_uuid, uuid_bytes,
      sizeof observation.operation_uuid);
  observation.entries[MT (SLOT_MAIN)] =
      (WylFactArtifactMainTransitionEntryEvidence) {
    .present = TRUE, .identity = expected_main, .link_count = 1,
    .owner_state = MT (OWNER_CONFORMING),
  };
  observation.entries[MT (SLOT_STAGE)] =
      (WylFactArtifactMainTransitionEntryEvidence) {
    .present = TRUE, .identity = staged_main, .link_count = 1,
    .owner_state = MT (OWNER_CONFORMING),
  };
  Request request = {
    .operation_uuid = operation_uuid,
    .directory_identity = directory,
    .lease_identity = lease,
    .expected_main_identity = expected_main,
    .staged_main_identity = staged_main,
  };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot
    = admissible_snapshot (&observation);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request,
      snapshot, &observation, &result, &transition), ==, WYRELOG_E_OK);
  g_assert_nonnull (transition);
  return transition;
}

typedef struct
{
  const gchar *uuid;
  guint8 bytes[16];
} CorpusEntry;

static const CorpusEntry CORPUS[] = {
  { "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b",
    { 0x01, 0x8f, 0x1a, 0x2b, 0x3c, 0x4d, 0x7e, 0x5f,
      0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b } },
  { "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5c",
    { 0x01, 0x8f, 0x1a, 0x2b, 0x3c, 0x4d, 0x7e, 0x5f,
      0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5c } },
  /* All-low and all-high nibbles in the random field, so a formatter that
   * mishandles either end of the hex range diverges. */
  { "00000000-0000-7000-8000-000000000000",
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00,
      0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
  { "ffffffff-ffff-7fff-bfff-ffffffffffff",
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff,
      0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};

static void
test_derivations_agree (void)
{
  for (gsize index = 0; index < G_N_ELEMENTS (CORPUS); index++) {
    Names names = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_names_derive
          (CORPUS[index].uuid, &names), ==, WYRELOG_E_OK);
    Transition *transition = synthetic_transition (CORPUS[index].uuid,
            CORPUS[index].bytes);
    g_autofree gchar *contract_stage
      = wyl_fact_artifact_main_transition_dup_stage_name (transition);
    g_autofree gchar *contract_rollback
      = wyl_fact_artifact_main_transition_dup_rollback_name (transition);
    g_assert_nonnull (contract_stage);
    g_assert_nonnull (contract_rollback);
    g_assert_cmpstr (names.stage, ==, contract_stage);
    g_assert_cmpstr (names.rollback, ==, contract_rollback);
    wyl_fact_artifact_main_transition_free (transition);
    wyl_fact_artifact_transition_names_clear (&names);
  }
}

static void
test_derivation_rejects_what_the_contract_rejects (void)
{
  /* The corpus must include inputs whose canonical form differs from a
   * plausible non-canonical spelling, or this asserts nothing. */
  static const gchar *const rejected[] = {
    "018F1A2B-3C4D-7E5F-8A9B-0C1D2E3F4A5B",   /* uppercase */
    "018f1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b",   /* v4, not v7 */
    "018f1a2b-3c4d-7e5f-0a9b-0c1d2e3f4a5b",   /* wrong variant nibble */
    "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5",    /* 35 characters */
    "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5bb",  /* 37 characters */
    "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b/",  /* trailing separator */
    "018f1a2b3c4d7e5f8a9b0c1d2e3f4a5b",       /* unhyphenated */
    "",
  };
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++) {
    Names names = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_names_derive
          (rejected[index], &names), ==, WYRELOG_E_INVALID);
    /* Nothing is published on a rejection, so a caller cannot pick up a
     * partially derived name. */
    g_assert_null (names.stage);
    g_assert_null (names.rollback);
    g_assert_null (names.probe);
    g_assert_null (names.probe_moved);
  }
  Names names = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (NULL, &names),
      ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive
        (CORPUS[0].uuid, NULL), ==, WYRELOG_E_INVALID);
}

/*
 * THE PROBE NAMES MUST COLLIDE WITH NOTHING, AND THIS IS A GUARD ON A
 * DESTRUCTIVE PATH RATHER THAN A COMPLETENESS NICETY.
 *
 * The probe's step 0 unlinks BOTH probe names UNCONDITIONALLY, before
 * anything else runs, because that is the crash-recovery path.  If a future
 * suffix change ever made a probe name equal the STAGE name, step 0 would
 * unlink THE STAGED DATABASE -- silently, on the recovery path, before any
 * other check could object.  Nobody should trim these assertions as
 * redundant; they are what stands between a suffix edit and data loss.
 *
 * The DIFFERENT-OPERATION rows matter for the same reason: the probe names
 * are UUID-scoped, and step 0's licence to unlink them rests entirely on
 * their belonging to THIS operation.  A suffix change that broke that scoping
 * would let one operation's probe clear another's artifacts.
 */
static void
test_probe_names_collide_with_nothing (void)
{
  Names self = { 0 };
  Names other = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (CORPUS[0].uuid,
      &self), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (CORPUS[1].uuid,
      &other), ==, WYRELOG_E_OK);

  const gchar *const self_names[] = {
    self.stage, self.rollback, self.probe, self.probe_moved,
  };
  const gchar *const other_names[] = {
    other.stage, other.rollback, other.probe, other.probe_moved,
  };
  /* All four of this operation's names are pairwise distinct. */
  for (gsize left = 0; left < G_N_ELEMENTS (self_names); left++) {
    g_assert_nonnull (self_names[left]);
    for (gsize right = left + 1; right < G_N_ELEMENTS (self_names); right++)
      g_assert_cmpstr (self_names[left], !=, self_names[right]);
  }
  /* And none of them is any of the five fixed names. */
  for (gsize index = 0; index < G_N_ELEMENTS (self_names); index++) {
    for (gsize fixed = 0; fixed < G_N_ELEMENTS (FIXED_NAMES); fixed++)
      g_assert_cmpstr (self_names[index], !=, FIXED_NAMES[fixed]);
  }
  /* And no name of this operation is any name of a DIFFERENT operation --
   * which is what step 0's unconditional unlink depends on. */
  for (gsize index = 0; index < G_N_ELEMENTS (self_names); index++) {
    for (gsize peer = 0; peer < G_N_ELEMENTS (other_names); peer++)
      g_assert_cmpstr (self_names[index], !=, other_names[peer]);
  }
  wyl_fact_artifact_transition_names_clear (&self);
  wyl_fact_artifact_transition_names_clear (&other);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/artifact-transition-names/derivations-agree",
      test_derivations_agree);
  g_test_add_func ("/fact/artifact-transition-names/rejection-parity",
      test_derivation_rejects_what_the_contract_rejects);
  g_test_add_func ("/fact/artifact-transition-names/probe-name-disjointness",
      test_probe_names_collide_with_nothing);
  return g_test_run ();
}

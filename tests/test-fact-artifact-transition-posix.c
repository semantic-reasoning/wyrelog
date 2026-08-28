/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include <glib.h>
#include <glib/gstdio.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fact-test-support.h"
#include "fact-artifact-transition-driver-fixture.h"
#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-artifact-main-transition-private.h"
#include "fact/graph-artifact-transition-names-private.h"
#include "fact/graph-artifact-transition-posix-private.h"
#include "fact/graph-locator-private.h"
#include "fact/root-writer-lease-private.h"

#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name
#define PF(name) WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_ ## name

#define SLOT_MAIN     MT (SLOT_MAIN)
#define SLOT_STAGE    MT (SLOT_STAGE)
#define SLOT_ROLLBACK MT (SLOT_ROLLBACK)

typedef WylFactArtifactMainTransitionObservation Observation;
typedef WylFactArtifactMainTransitionRequest Request;
typedef WylFactArtifactMainTransitionResult Result;
typedef WylFactArtifactMainTransition Transition;
typedef WylFactArtifactInventoryIdentity Identity;
typedef WylFactArtifactInventorySnapshot Snapshot;
typedef WylFactArtifactTransitionPosix Provider;
typedef WylFactArtifactTransitionPosixCapability Capability;
typedef WylFactArtifactTransitionPosixLifecycle Lifecycle;

static const gchar OPERATION_UUID[] = "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b";
static gchar *driver_test_executable;

/*
 * A real fact root, a real writer lease and a real #606 graph directory, so
 * the provider is exercised against the locator that will hand it a graph_fd
 * in production rather than against a hand-built struct.
 */
typedef struct
{
  gchar *root;
  WylFactRootWriterLease *lease;
  WylFactGraphResolver resolver;
  WylFactGraphLocator locator;
  WylFactGraphDirectory directory;
  WylFactArtifactTransitionNames names;
  gchar *graph_path;
} Fixture;

static void
fixture_init (Fixture *fixture, const gchar *tag)
{
  g_autoptr (GError) error = NULL;
  memset (fixture, 0, sizeof *fixture);
  fixture->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  fixture->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  fixture->root = wyl_test_make_secure_fact_root (tag, &error);
  g_assert_no_error (error);
  g_assert_nonnull (fixture->root);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture->root,
      &fixture->lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator, "tenant",
      "graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, TRUE, &fixture->directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (OPERATION_UUID,
      &fixture->names), ==, WYRELOG_E_OK);
  fixture->graph_path
    = wyl_fact_graph_directory_descriptive_path (&fixture->directory);
  g_assert_nonnull (fixture->graph_path);
  /* The lock is what lease_identity is read from; every fixture needs one. */
  gint lock = openat (fixture->directory.graph_fd,
          WYL_FACT_ARTIFACT_TRANSITION_LOCK_NAME,
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (lock, >=, 0);
  close (lock);
}

static void
fixture_open_existing (Fixture *fixture, const gchar *root)
{
  memset (fixture, 0, sizeof *fixture);
  fixture->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  fixture->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  fixture->root = g_strdup (root);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture->root,
      &fixture->lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator, "tenant",
      "graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, FALSE, &fixture->directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (OPERATION_UUID,
      &fixture->names), ==, WYRELOG_E_OK);
  fixture->graph_path
    = wyl_fact_graph_directory_descriptive_path (&fixture->directory);
  g_assert_nonnull (fixture->graph_path);
}

static void
fixture_clear (Fixture *fixture)
{
  wyl_fact_artifact_transition_posix_set_test_fault (PF (NONE));
  /* LOAD-BEARING, not belt-and-braces.  The injected levels clear themselves
   * only when their seam FIRES; a level set for a seam the probe never
   * reaches -- because it failed earlier, at preclean or create -- survives
   * into the next test.  These two lines are what bound that. */
  wyl_fact_artifact_transition_posix_set_test_rename_errno (0);
  wyl_fact_artifact_transition_posix_set_test_flush_errno (0);
  wyl_fact_artifact_transition_posix_set_test_post_open_hook (NULL, NULL);
  wyl_fact_artifact_transition_names_clear (&fixture->names);
  wyl_fact_graph_directory_clear (&fixture->directory);
  wyl_fact_graph_locator_clear (&fixture->locator);
  wyl_fact_graph_resolver_clear (&fixture->resolver);
  wyl_fact_root_writer_lease_release (fixture->lease);
  g_clear_pointer (&fixture->graph_path, g_free);
  g_clear_pointer (&fixture->root, g_free);
}

static void
make_conforming (Fixture *fixture, const gchar *name, gsize size)
{
  gint fd = openat (fixture->directory.graph_fd, name,
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd, >=, 0);
  for (gsize written = 0; written < size; written++)
    g_assert_cmpint (write (fd, "x", 1), ==, 1);
  close (fd);
}

static Identity
real_identity (Fixture *fixture, const gchar *name)
{
  struct stat st = { 0 };
  g_assert_cmpint (fstatat (fixture->directory.graph_fd, name, &st,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  return (Identity) {
           .domain = (guint64) st.st_dev, .object = (guint64) st.st_ino,
  };
}

static Provider *
open_provider (Fixture *fixture)
{
  Capability capability = {
    .no_replace_supported = TRUE,
    .directory_flush = MT (DURABILITY_PROVEN),
  };
  Provider *provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_open
        (&fixture->resolver, &fixture->directory, fixture->lease,
      OPERATION_UUID, &capability,
      &provider), ==, WYRELOG_E_OK);
  g_assert_nonnull (provider);
  return provider;
}

static wyrelog_error_t
observe (Fixture *fixture, Observation *out_observation)
{
  Provider *provider = open_provider (fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  wyrelog_error_t status = wyl_fact_artifact_transition_posix_observe
        (provider, &lifecycle, out_observation);
  wyl_fact_artifact_transition_posix_free (provider);
  return status;
}

static wyrelog_error_t
execute_current (Provider *provider, WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionEffect *out_effect,
    WylFactArtifactMainTransitionDurabilityEvidence *out_durability)
{
  if (provider == NULL)
    return wyl_fact_artifact_transition_posix_execute (NULL, NULL, op,
               out_effect, out_durability);

  Observation authorized = { 0 };
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  wyrelog_error_t status = wyl_fact_artifact_transition_posix_observe
        (provider, &lifecycle, &authorized);
  if (status != WYRELOG_E_OK)
    return status;
  return wyl_fact_artifact_transition_posix_execute (provider, &authorized,
             op, out_effect, out_durability);
}

/*
 * RULE 2 -- SNAPSHOT CONSTRUCTION.  The admit-coupled cases hand-build their
 * #622 snapshot rather than taking a real one.
 *
 * This is not a dodge, and the reason is specific.  The real readdir scanner
 * sends any non-fixed-name entry that fails S_ISLNK / !S_ISREG / nlink != 1 /
 * mode != 0600 / uid to AMBIGUOUS_ENTRY or MALFORMED_ENTRY and never reaches
 * the UNKNOWN_ENTRY line.  Every hostile fixture in this file sits AT the
 * stage or rollback name, which are non-fixed names, so against a real
 * snapshot conjunct (b) would refuse INVENTORY_ANOMALOUS before the
 * provider's evidence was ever consulted -- and the case would pass for the
 * wrong reason, proving nothing about the detection it is named for.
 *
 * The inventory and the provider are INDEPENDENT evidence sources and the
 * contract deliberately requires both, so a test isolating one must
 * neutralise the other or it is testing their conjunction and cannot say
 * which fired.
 *
 * THE COST IS REAL AND IS NOT CLOSED IN THIS UNIT: nothing here exercises the
 * provider's triple against a snapshot the real scanner produced.  That
 * belongs to unit 2b's fuller fixture or unit 4's integration pass.
 */
static Snapshot *
hand_built_snapshot (const Observation *observation, gboolean lock_present)
{
  Snapshot *snapshot = wyl_fact_artifact_inventory_snapshot_new (32);
  WylFactArtifactInventoryObservation point = {
    .directory_identity = observation->directory_identity,
    .guard_identity = observation->lease_identity,
    .entry_fingerprint = 11,
  };
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  gboolean main_present = observation->entries[SLOT_MAIN].present;
  Identity main_identity = observation->entries[SLOT_MAIN].identity;
  Identity lock_identity = observation->lease_identity;
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN,
      main_present ? &main_identity : NULL, main_present,
      main_present ? 1 : 0, TRUE, main_present ? 1 : 0), ==, WYRELOG_E_OK);
  const WylFactArtifactInventorySlot absent[] = {
    WYL_FACT_ARTIFACT_INVENTORY_WAL,
    WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT,
    WYL_FACT_ARTIFACT_INVENTORY_RECOVERY,
  };
  for (gsize index = 0; index < G_N_ELEMENTS (absent); index++)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
        absent[index], NULL, FALSE, 0, TRUE, 0), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_LOCK,
      lock_present ? &lock_identity : NULL, lock_present,
      lock_present ? 1 : 0, TRUE, lock_present ? 1 : 0), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_TEMP, NULL, FALSE, 0, TRUE, 0), ==,
      WYRELOG_E_OK);
  guint unknown = (observation->entries[SLOT_STAGE].present ? 1u : 0u)
      + (observation->entries[SLOT_ROLLBACK].present ? 1u : 0u);
  for (guint index = 0; index < unknown; index++)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly
          (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==,
        WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  return snapshot;
}

static Request
request_for (const Observation *observation, Identity expected_main,
    Identity staged_main, gboolean expected_main_absent)
{
  Request request = {
    .operation_uuid = OPERATION_UUID,
    .directory_identity = observation->directory_identity,
    .lease_identity = observation->lease_identity,
    .expected_main_absent = expected_main_absent,
    .expected_main_identity = expected_main_absent ? (Identity) { 0 }
        : expected_main,
    .staged_main_identity = staged_main,
  };
  return request;
}

static WylTestDriverStoredValue
completed_driver_value (const Request *request,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionState state)
{
  WylTestDriverStoredValue value = {
    .version = 1,
    .revision = 29,
    .consumer_generation = 31,
    .directory_identity = request->directory_identity,
    .lease_identity = request->lease_identity,
    .expected_main_absent = request->expected_main_absent,
    .expected_main_identity = request->expected_main_identity,
    .staged_main_identity = request->staged_main_identity,
    .resume_forbidden = request->resume_forbidden,
    .durability_unprovable_acknowledged
      = request->durability_unprovable_acknowledged,
    .marker = WYL_TEST_DRIVER_MARKER_COMPLETED,
    .pending_op = op,
    .completed_state = state,
  };
  g_strlcpy (value.operation_uuid, request->operation_uuid,
      sizeof value.operation_uuid);
  return value;
}

static wyrelog_error_t
admit (const Observation *observation, const Request *request,
    Result *out_result, Transition **out_transition)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot
    = hand_built_snapshot (observation, TRUE);
  return wyl_fact_artifact_main_transition_admit (request, snapshot,
             observation, out_result, out_transition);
}

/* Directory entry set, for the probe-cleanliness cases. */
static GPtrArray *
entry_set (Fixture *fixture)
{
  GPtrArray *entries = g_ptr_array_new_with_free_func (g_free);
  DIR *stream = opendir (fixture->graph_path);
  g_assert_nonnull (stream);
  for (struct dirent *entry = readdir (stream); entry != NULL;
      entry = readdir (stream)) {
    if (g_strcmp0 (entry->d_name, ".") == 0
        || g_strcmp0 (entry->d_name, "..") == 0)
      continue;
    g_ptr_array_add (entries, g_strdup (entry->d_name));
  }
  closedir (stream);
  g_ptr_array_sort_values (entries, (GCompareFunc) g_strcmp0);
  return entries;
}

static void
assert_entry_sets_equal (GPtrArray *left, GPtrArray *right)
{
  g_assert_cmpuint (left->len, ==, right->len);
  for (guint index = 0; index < left->len; index++)
    g_assert_cmpstr (left->pdata[index], ==, right->pdata[index]);
}

/* ------------------------------------------------------------------ */
/* T1 triple and identity                                              */
/* ------------------------------------------------------------------ */

static void
test_triple_and_identity (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t1-XXXXXX");
  /* Deliberately different sizes and therefore different inodes, so a
   * slot-to-name mix-up diverges instead of comparing equal. */
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
  make_conforming (&fixture, fixture.names.stage, 2);
  make_conforming (&fixture, fixture.names.rollback, 3);

  Observation observation;
  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);

  const gchar *names[] = {
    WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, fixture.names.stage,
    fixture.names.rollback,
  };
  for (guint slot = 0; slot < MT (SLOT_COUNT); slot++) {
    Identity expected = real_identity (&fixture, names[slot]);
    g_assert_true (observation.entries[slot].present);
    g_assert_false (observation.entries[slot].reparse);
    g_assert_cmpuint (observation.entries[slot].link_count, ==, 1);
    g_assert_cmpint (observation.entries[slot].owner_state, ==,
        MT (OWNER_CONFORMING));
    g_assert_true (wyl_fact_artifact_inventory_identity_equal
          (&observation.entries[slot].identity, &expected));
  }
  struct stat directory = { 0 };
  g_assert_cmpint (fstat (fixture.directory.graph_fd, &directory), ==, 0);
  g_assert_cmpuint (observation.directory_identity.domain, ==,
      (guint64) directory.st_dev);
  g_assert_cmpuint (observation.directory_identity.object, ==,
      (guint64) directory.st_ino);
  fixture_clear (&fixture);
}

/* ------------------------------------------------------------------ */
/* T2 absent slots, all eight presence combinations                    */
/* ------------------------------------------------------------------ */

static void
test_absent_slot_combinations (void)
{
  for (guint mask = 0; mask < 8; mask++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t2-%u-XXXXXX", mask);
    fixture_init (&fixture, tag);
    const gchar *names[] = {
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, fixture.names.stage,
      fixture.names.rollback,
    };
    for (guint slot = 0; slot < MT (SLOT_COUNT); slot++) {
      if ((mask & (1u << slot)) != 0)
        make_conforming (&fixture, names[slot], slot + 1);
    }
    g_autoptr (WylFactArtifactTransitionPosix) provider
      = open_provider (&fixture);
    Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
    g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
    Observation observation = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
        &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
    for (guint slot = 0; slot < MT (SLOT_COUNT); slot++) {
      gboolean expected = (mask & (1u << slot)) != 0;
      g_assert_cmpint (observation.entries[slot].present, ==, expected);
      if (!expected) {
        g_assert_cmpuint (observation.entries[slot].identity.domain, ==, 0);
        g_assert_cmpuint (observation.entries[slot].link_count, ==, 0);
        g_assert_cmpint (observation.entries[slot].owner_state, ==,
            MT (OWNER_UNKNOWN));
      }
    }
    fixture_clear (&fixture);
  }
}

/* ------------------------------------------------------------------ */
/* T3 an unreadable slot is not an absent slot                         */
/* ------------------------------------------------------------------ */

static void
test_unreadable_slot_is_not_absent (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t3-XXXXXX");
  make_conforming (&fixture, fixture.names.stage, 1);
  /* The seam models the openat failure directly, because a mode-based
   * fixture is unreliable when the suite runs as root -- which some CI
   * containers do, and where a 0000 file is still readable. */
  wyl_fact_artifact_transition_posix_set_test_fault (PF (OBSERVE_SLOT_OPEN));
  Observation observation;
  g_assert_cmpint (observe (&fixture, &observation), !=, WYRELOG_E_OK);
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
        (PF (OBSERVE_SLOT_OPEN)));
  fixture_clear (&fixture);
}

/* ------------------------------------------------------------------ */
/* T4 symlink detection -- the highest-value case in this unit         */
/* ------------------------------------------------------------------ */

static void
test_symlink_detection (void)
{
  for (guint slot = 0; slot < MT (SLOT_COUNT); slot++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t4-%u-XXXXXX", slot);
    fixture_init (&fixture, tag);
    const gchar *names[] = {
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, fixture.names.stage,
      fixture.names.rollback,
    };
    /*
     * RULE 1 -- FIXTURE PLACEMENT.  The symlink TARGET lives OUTSIDE the
     * graph directory.  With it inside, the defect refuses
     * COLLISION_AMBIGUOUS on the extra entry and the case passes without ever
     * demonstrating that the symlink was followed.
     */
    g_autofree gchar *outside = g_build_filename (fixture.root,
            "outside-target", NULL);
    gint target = g_open (outside, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
            0600);
    g_assert_cmpint (target, >=, 0);
    close (target);
    struct stat target_stat = { 0 };
    g_assert_cmpint (stat (outside, &target_stat), ==, 0);
    g_assert_cmpint (symlinkat (outside, fixture.directory.graph_fd,
        names[slot]), ==, 0);

    Observation observation;
    g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
    g_assert_true (observation.entries[slot].present);
    g_assert_true (observation.entries[slot].reparse);
    /* No identity is published for a reparse slot: the target's identity is
     * not this slot's, and publishing it is exactly the defect. */
    g_assert_cmpuint (observation.entries[slot].identity.domain, ==, 0);
    g_assert_cmpuint (observation.entries[slot].identity.object, ==, 0);
    g_assert_cmpuint (observation.entries[slot].identity.object, !=,
        (guint64) target_stat.st_ino);

    /* Declare the request's expected identity to be THE TARGET's, so the
     * defect has every chance to sail through admission. */
    Identity target_identity = {
      .domain = (guint64) target_stat.st_dev,
      .object = (guint64) target_stat.st_ino,
    };
    Identity other = { .domain = target_identity.domain, .object = 999999 };
    Request request = slot == SLOT_STAGE
        ? request_for (&observation, other, target_identity, FALSE)
        : request_for (&observation, target_identity, other, FALSE);
    Result result;
    Transition *transition = NULL;
    g_assert_cmpint (admit (&observation, &request, &result, &transition),
        ==, WYRELOG_E_POLICY);
    g_assert_null (transition);
    g_assert_cmpint (result.refusal, ==, MT (REFUSAL_REPARSE));
    fixture_clear (&fixture);
  }
}

/* ------------------------------------------------------------------ */
/* T5 hard-link detection                                              */
/* ------------------------------------------------------------------ */

static void
test_hard_link_detection (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t5-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
  make_conforming (&fixture, fixture.names.stage, 2);
  /* RULE 1: the partner lives OUTSIDE the graph directory.  Inside, the case
   * can refuse COLLISION_AMBIGUOUS and pass without consulting st_nlink at
   * all -- and here moving it out is not optional, because it is the stage
   * file's OWN nlink that the real scanner would trip on. */
  g_autofree gchar *partner = g_build_filename (fixture.root, "partner",
          NULL);
  g_autofree gchar *stage_path = g_build_filename (fixture.graph_path,
          fixture.names.stage, NULL);
  g_assert_cmpint (link (stage_path, partner), ==, 0);

  Observation observation;
  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpuint (observation.entries[SLOT_STAGE].link_count, ==, 2);

  Request request = request_for (&observation,
          observation.entries[SLOT_MAIN].identity,
          observation.entries[SLOT_STAGE].identity, FALSE);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&observation, &request, &result, &transition), ==,
      WYRELOG_E_POLICY);
  g_assert_null (transition);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_LINK_SUBSTITUTION));
  fixture_clear (&fixture);
}

/* ------------------------------------------------------------------ */
/* T6 ownership detection                                              */
/* ------------------------------------------------------------------ */

static void
test_ownership_detection (void)
{
  /*
   * THE SETUID VARIANT IS THE ONE THAT CARRIES THE DEFECT.  Masking with 0777
   * instead of 07777 reports WRONG_MODE for 0644 either way, so 0644 alone
   * cannot catch it; 04600 reports CONFORMING under the defect and WRONG_MODE
   * when correct.
   *
   * A WRONG-UID case is NOT attempted: it needs privilege the CI runner does
   * not have.  That path is unproven here rather than pretended.
   */
  const mode_t modes[] = { 0644, 04600 };
  for (gsize index = 0; index < G_N_ELEMENTS (modes); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t6-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);
    make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
    make_conforming (&fixture, fixture.names.stage, 2);
    g_assert_cmpint (fchmodat (fixture.directory.graph_fd,
        fixture.names.stage, modes[index], 0), ==, 0);

    Observation observation;
    g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
    g_assert_cmpint (observation.entries[SLOT_STAGE].owner_state, ==,
        MT (OWNER_WRONG_MODE));

    Request request = request_for (&observation,
            observation.entries[SLOT_MAIN].identity,
            observation.entries[SLOT_STAGE].identity, FALSE);
    Result result;
    Transition *transition = NULL;
    g_assert_cmpint (admit (&observation, &request, &result, &transition),
        ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result.refusal, ==, MT (REFUSAL_OWNERSHIP));
    fixture_clear (&fixture);
  }
}

/* ------------------------------------------------------------------ */
/* T7 non-regular files                                                */
/* ------------------------------------------------------------------ */

static void
test_non_regular_is_not_conforming (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t7-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
  g_autofree gchar *fifo_path = g_build_filename (fixture.graph_path,
          fixture.names.stage, NULL);
  g_assert_cmpint (mkfifo (fifo_path, 0600), ==, 0);

  Observation observation;
  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_true (observation.entries[SLOT_STAGE].present);
  /* A FIFO with conforming permission bits must not read as CONFORMING: the
   * defect is checking S_ISREG only inside the mode comparison. */
  g_assert_cmpint (observation.entries[SLOT_STAGE].owner_state, ==,
      MT (OWNER_UNKNOWN));

  Request request = request_for (&observation,
          observation.entries[SLOT_MAIN].identity,
          observation.entries[SLOT_STAGE].identity, FALSE);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&observation, &request, &result, &transition), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_OWNERSHIP));
  fixture_clear (&fixture);
}

/* ------------------------------------------------------------------ */
/* T8 / T9 the capability probe                                        */
/* ------------------------------------------------------------------ */

static void
test_probe_supported (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t8-XXXXXX");
  Capability capability = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_probe_capability
        (&fixture.directory, OPERATION_UUID, &capability), ==, WYRELOG_E_OK);
  g_assert_true (capability.no_replace_supported);
  g_assert_cmpint (capability.directory_flush, ==, MT (DURABILITY_PROVEN));
  fixture_clear (&fixture);
}

static void
test_probe_unambiguity (void)
{
  /*
   * ONE TABLE, NO PLATFORM CONDITIONALS.  The probe classifies from the
   * syscall's own errno, so every row is asserted the same way on every
   * target.  The previous shape had to split this arm per platform, and that
   * split existed only to work around a collapsed return value this backend
   * no longer inherits.
   *
   * ENOTSUP AND EOPNOTSUPP ARE BOTH DRIVEN DELIBERATELY.  They are the same
   * value on Linux, so one row is redundant there -- and different on Darwin,
   * where omitting either would let a genuine capability gap be reported as a
   * probe failure.  The redundancy on one platform is the price of covering
   * the other, and dropping the "duplicate" is the regression this row
   * guards.
   */
  const struct
  {
    const gchar *label;
    gint injected;
    gboolean probe_succeeds;
  } rows[] = {
    { "enosys", ENOSYS, TRUE },
    { "einval", EINVAL, TRUE },
    { "enotsup", ENOTSUP, TRUE },
    { "eopnotsupp", EOPNOTSUPP, TRUE },
    /* The probe's OWN preconditions were violated -- step 0 cleared both
     * names and step 1 created the source -- so neither is evidence about
     * capability and neither may be reported as a capability gap. */
    { "eexist", EEXIST, FALSE },
    { "enoent", ENOENT, FALSE },
    /* Unclassified.  Never silently swallowed as "unsupported". */
    { "eio", EIO, FALSE },
    { "eacces", EACCES, FALSE },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (rows); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t9-%s-XXXXXX",
            rows[index].label);
    fixture_init (&fixture, tag);
    Capability capability = { .no_replace_supported = TRUE };
    wyl_fact_artifact_transition_posix_set_test_rename_errno
      (rows[index].injected);
    wyl_fact_artifact_transition_posix_set_test_fault (PF (PROBE_RENAME));
    wyrelog_error_t status
      = wyl_fact_artifact_transition_posix_probe_capability
          (&fixture.directory, OPERATION_UUID, &capability);
    if (rows[index].probe_succeeds) {
      g_assert_cmpint (status, ==, WYRELOG_E_OK);
      g_assert_false (capability.no_replace_supported);
    } else {
      g_assert_cmpint (status, !=, WYRELOG_E_OK);
      g_assert_false (capability.no_replace_supported);
    }
    g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
          (PF (PROBE_RENAME)));
    fixture_clear (&fixture);
  }

  /* A CREATE failure is not a capability answer either: without a created
   * source the rename's errno says nothing about the flag. */
  Fixture create_fixture;
  fixture_init (&create_fixture, "u2a-t9-create-XXXXXX");
  Capability create_capability = { .no_replace_supported = TRUE };
  wyl_fact_artifact_transition_posix_set_test_fault (PF (PROBE_CREATE));
  g_assert_cmpint (wyl_fact_artifact_transition_posix_probe_capability
        (&create_fixture.directory, OPERATION_UUID, &create_capability), !=,
      WYRELOG_E_OK);
  g_assert_false (create_capability.no_replace_supported);
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
        (PF (PROBE_CREATE)));
  fixture_clear (&create_fixture);
}

/*
 * N2 -- THE PRECLEAN RULE, WHICH WAS STATED AND UNASSERTED.
 *
 * The rule only bites when a leftover exists: with a clean directory an
 * ignored unlink failure is harmless, so arming PRECLEAN against an empty
 * directory proves nothing about fail-closed behaviour.  PLANT a leftover
 * first, then arm it, and the assertion is that the probe FAILS rather than
 * proceeding to a confusing EEXIST at step 1.
 */
static void
test_probe_preclean_fails_closed (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t9c-XXXXXX");
  make_conforming (&fixture, fixture.names.probe, 4);
  Capability capability = { .no_replace_supported = TRUE };
  wyl_fact_artifact_transition_posix_set_test_fault (PF (PROBE_PRECLEAN));
  g_assert_cmpint (wyl_fact_artifact_transition_posix_probe_capability
        (&fixture.directory, OPERATION_UUID, &capability), !=,
      WYRELOG_E_OK);
  g_assert_false (capability.no_replace_supported);
  g_assert_cmpint (capability.directory_flush, ==, MT (DURABILITY_UNPROVEN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
        (PF (PROBE_PRECLEAN)));
  fixture_clear (&fixture);
}


/*
 * THE DIRECTORY-FLUSH ROW MUST ACCEPT THE SAME PAIR THE RENAME ROW DOES.
 *
 * ENOTSUP is the row that matters and the one that was missing.  On Linux it
 * is the same value as EOPNOTSUPP and this asserts nothing new; on Darwin
 * they are distinct, and without ENOTSUP a macOS filesystem whose fsync
 * answers it falls through to "anything else" and the probe FAILS.
 *
 * THE TWO OUTCOMES ARE NOT BOTH MERELY CONSERVATIVE, which is why this is a
 * correctness row and not a tidiness one.  UNSUPPORTED claims nothing: it
 * reports the flush as unprovable, blocks PUBLISHED_DURABLE, and requires an
 * explicit acknowledgement before FINALIZE.  A probe failure means that
 * filesystem cannot run a restore at all.  Reporting the second where the
 * first is true denies restore on a filesystem that was merely honest about
 * its durability.
 */
static void
test_probe_flush_capability_rows (void)
{
  const struct
  {
    const gchar *label;
    gint injected;
    gboolean probe_succeeds;
    WylFactArtifactMainTransitionDurability expected;
  } rows[] = {
    { "einval", EINVAL, TRUE, MT (DURABILITY_UNSUPPORTED) },
    { "enotsup", ENOTSUP, TRUE, MT (DURABILITY_UNSUPPORTED) },
    { "eopnotsupp", EOPNOTSUPP, TRUE, MT (DURABILITY_UNSUPPORTED) },
    /* Not a capability answer.  Never silently reported as unsupported. */
    { "eio", EIO, FALSE, MT (DURABILITY_UNPROVEN) },
    { "eacces", EACCES, FALSE, MT (DURABILITY_UNPROVEN) },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (rows); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-flush-%s-XXXXXX",
            rows[index].label);
    fixture_init (&fixture, tag);
    /* POISONED, not zero-filled: { 0 } already means UNPROVEN, so asserting
     * UNPROVEN on the failure rows against a zero-filled probe could only
     * catch a defect that LEAVES a classification set.  Poisoning proves the
     * out-parameter is actually written on every path, including the reset
     * the failure path performs. */
    Capability capability = {
      .no_replace_supported = TRUE,
      .directory_flush = MT (DURABILITY_PROVEN),
    };
    wyl_fact_artifact_transition_posix_set_test_flush_errno
      (rows[index].injected);
    wyl_fact_artifact_transition_posix_set_test_fault
      (PF (PROBE_DIRECTORY_FSYNC));
    wyrelog_error_t status
      = wyl_fact_artifact_transition_posix_probe_capability
          (&fixture.directory, OPERATION_UUID, &capability);
    if (rows[index].probe_succeeds) {
      g_assert_cmpint (status, ==, WYRELOG_E_OK);
      /* The rename is real on these rows, so the other half of the
       * capability is genuinely established rather than left poisoned. */
      g_assert_true (capability.no_replace_supported);
    } else {
      g_assert_cmpint (status, !=, WYRELOG_E_OK);
      /* A failed probe yields NO capability: the poison must be gone. */
      g_assert_false (capability.no_replace_supported);
    }
    g_assert_cmpint (capability.directory_flush, ==, rows[index].expected);
    g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
          (PF (PROBE_DIRECTORY_FSYNC)));
    fixture_clear (&fixture);
  }
}

/* ------------------------------------------------------------------ */
/* T10 the probe leaves nothing behind                                 */
/* ------------------------------------------------------------------ */

static void
test_probe_leaves_nothing_behind (void)
{
  /*
   * THE RETIRE ARM IS DELIBERATELY ABSENT FROM THIS LIST, and the reason is
   * worth recording because it is easy to re-add by reflex.  With
   * PROBE_RETIRE armed the probe BY DEFINITION cannot clean up, so a blanket
   * "identical after every arm" quantifier asserts something that never held
   * -- against correct code, from the first version onwards.  The defect was
   * never that a later fix interacted with it; it is that the quantifier hid
   * a case it did not cover.  The retire arm's honest assertions are in
   * test_probe_retire_leftover_is_recoverable below.
   */
  const WylFactArtifactTransitionPosixTestFault arms[] = {
    PF (NONE), PF (PROBE_PRECLEAN), PF (PROBE_CREATE), PF (PROBE_RENAME),
    PF (PROBE_DIRECTORY_FSYNC),
  };
  for (gsize index = 0; index < G_N_ELEMENTS (arms); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t10-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);
    make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
    g_autoptr (GPtrArray) before = entry_set (&fixture);
    Capability capability = { 0 };
    wyl_fact_artifact_transition_posix_set_test_fault (arms[index]);
    (void) wyl_fact_artifact_transition_posix_probe_capability
      (&fixture.directory, OPERATION_UUID, &capability);
    g_autoptr (GPtrArray) after = entry_set (&fixture);
    assert_entry_sets_equal (before, after);
    fixture_clear (&fixture);
  }
}

static void
test_probe_retire_leftover_is_recoverable (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t10r-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
  g_autoptr (GPtrArray) baseline = entry_set (&fixture);

  Capability capability = { 0 };
  wyl_fact_artifact_transition_posix_set_test_fault (PF (PROBE_RETIRE));
  (void) wyl_fact_artifact_transition_posix_probe_capability
    (&fixture.directory, OPERATION_UUID, &capability);
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
        (PF (PROBE_RETIRE)));
  /* A probe name MAY be resident here; that is permitted, not asserted. */

  /* THE CLAUSE THAT MAKES THE LEFTOVER RECOVERABLE RATHER THAN FATAL: a
   * subsequent probe succeeds and returns the directory to the baseline. */
  Capability again = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_probe_capability
        (&fixture.directory, OPERATION_UUID, &again), ==, WYRELOG_E_OK);
  g_autoptr (GPtrArray) after = entry_set (&fixture);
  assert_entry_sets_equal (baseline, after);
  fixture_clear (&fixture);
}

/*
 * T10b -- THE CASE T10 CANNOT CATCH.  T10's arms are in-process failures
 * where the return path still runs its cleanup, so they never exercise the
 * state a DYING process leaves.
 *
 * THE BASELINE IS TAKEN BEFORE PLANTING, NOT BEFORE THE PROBE.  Step 0
 * deliberately removes the planted leftover, so the post-probe set equals the
 * PRE-PLANT set: asserting against a pre-probe baseline would fail against
 * correct code.
 */
static void
test_probe_recovers_from_crashed_predecessor (void)
{
  const guint plant_probe = 1u;
  const guint plant_moved = 2u;
  for (guint plant = plant_probe; plant <= (plant_probe | plant_moved);
      plant++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t10b-%u-XXXXXX", plant);
    fixture_init (&fixture, tag);
    make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
    g_autoptr (GPtrArray) baseline = entry_set (&fixture);
    if ((plant & plant_probe) != 0)
      make_conforming (&fixture, fixture.names.probe, 5);
    if ((plant & plant_moved) != 0)
      make_conforming (&fixture, fixture.names.probe_moved, 6);

    Capability capability = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_posix_probe_capability
          (&fixture.directory, OPERATION_UUID, &capability), ==,
        WYRELOG_E_OK);
    g_assert_true (capability.no_replace_supported);
    g_autoptr (GPtrArray) after = entry_set (&fixture);
    /* As if neither the crashed predecessor nor this probe had ever run. */
    assert_entry_sets_equal (baseline, after);
    fixture_clear (&fixture);
  }
}

/* ------------------------------------------------------------------ */
/* T11 end-to-end classification                                       */
/* ------------------------------------------------------------------ */

typedef struct
{
  const gchar *label;
  gboolean main_present;
  gboolean main_is_stage;
  gboolean stage_present;
  gboolean rollback_present;
  gboolean expected_main_absent;
  WylFactArtifactMainTransitionState expected;
} ClassificationRow;

static void
test_end_to_end_classification (void)
{
  const ClassificationRow rows[] = {
    { "ready", TRUE, FALSE, TRUE, FALSE, FALSE, MT (STATE_READY) },
    { "retained", FALSE, FALSE, TRUE, TRUE, FALSE, MT (STATE_RETAINED) },
    { "stage-lost", FALSE, FALSE, FALSE, TRUE, FALSE,
      MT (STATE_RETAINED_STAGE_LOST) },
    { "published", TRUE, TRUE, FALSE, TRUE, FALSE, MT (STATE_PUBLISHED) },
    { "finalized", TRUE, TRUE, FALSE, FALSE, FALSE, MT (STATE_FINALIZED) },
    { "abandoned", TRUE, FALSE, FALSE, FALSE, FALSE, MT (STATE_ABANDONED) },
    { "mode-b-ready", FALSE, FALSE, TRUE, FALSE, TRUE, MT (STATE_READY) },
    { "mode-b-published", TRUE, TRUE, FALSE, FALSE, TRUE,
      MT (STATE_PUBLISHED) },
    { "mode-b-abandoned", FALSE, FALSE, FALSE, FALSE, TRUE,
      MT (STATE_ABANDONED) },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (rows); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t11-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);
    /* Every fixture entry is an independent conforming file, NOT a hard link
     * to another.  A hard link would give link_count 2 and every row would
     * refuse LINK_SUBSTITUTION before classification ran, so this must stay
     * as it is -- the rows below supply the expected-main identity from
     * whichever entry plays that role instead. */
    if (rows[index].main_present)
      make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
    if (rows[index].stage_present)
      make_conforming (&fixture, fixture.names.stage, 2);
    if (rows[index].rollback_present)
      make_conforming (&fixture, fixture.names.rollback, 3);

    g_autoptr (WylFactArtifactTransitionPosix) provider
      = open_provider (&fixture);
    Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
    g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
    Observation observation = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
        &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);

    /* expected_main is whichever entry the row says holds it; staged_main is
     * the entry that holds the restore content. */
    Identity expected_main = { .domain = observation.directory_identity.domain,
                               .object = 900001 };
    Identity staged_main = { .domain = observation.directory_identity.domain,
                             .object = 900002 };
    if (rows[index].rollback_present)
      expected_main = observation.entries[SLOT_ROLLBACK].identity;
    else if (rows[index].main_present && !rows[index].main_is_stage)
      expected_main = observation.entries[SLOT_MAIN].identity;
    if (rows[index].stage_present)
      staged_main = observation.entries[SLOT_STAGE].identity;
    else if (rows[index].main_is_stage)
      staged_main = observation.entries[SLOT_MAIN].identity;

    Request request = request_for (&observation, expected_main, staged_main,
            rows[index].expected_main_absent);
    Result result;
    Transition *transition = NULL;
    wyrelog_error_t status = wyl_fact_artifact_main_transition_admit (&request,
            snapshot, &observation, &result, &transition);
    g_assert_cmpint (status, ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==, rows[index].expected);
    wyl_fact_artifact_main_transition_free (transition);
    fixture_clear (&fixture);
  }
}

/* ------------------------------------------------------------------ */
/* T12 lease and directory identity                                    */
/* ------------------------------------------------------------------ */

static void
test_lease_and_directory_identity (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t12-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
  make_conforming (&fixture, fixture.names.stage, 2);

  Observation observation;
  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  Identity lock = real_identity (&fixture,
          WYL_FACT_ARTIFACT_TRANSITION_LOCK_NAME);
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&observation.lease_identity, &lock));

  /* A request naming a DIFFERENT directory must be refused: the provider
   * publishes what it observed, never the request's own values echoed back. */
  Request request = request_for (&observation,
          observation.entries[SLOT_MAIN].identity,
          observation.entries[SLOT_STAGE].identity, FALSE);
  request.directory_identity.object += 1;
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&observation, &request, &result, &transition), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_DIRECTORY_AUTHORITY));
  fixture_clear (&fixture);
}

/* ------------------------------------------------------------------ */
/* T13 durability fields are always UNPROVEN                           */
/* ------------------------------------------------------------------ */

static void
test_durability_fields_are_unproven (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2a-t13-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
  make_conforming (&fixture, fixture.names.stage, 2);
  Observation observation;
  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (observation.durability.staged_file, ==,
      MT (DURABILITY_UNPROVEN));
  g_assert_cmpint (observation.durability.rollback_file, ==,
      MT (DURABILITY_UNPROVEN));
  g_assert_cmpint (observation.durability.directory_after_retain, ==,
      MT (DURABILITY_UNPROVEN));
  g_assert_cmpint (observation.durability.directory_after_publish, ==,
      MT (DURABILITY_UNPROVEN));
  fixture_clear (&fixture);
}

/* ------------------------------------------------------------------ */
/* T14 every declared seam is reachable                                */
/* ------------------------------------------------------------------ */

static void
test_fault_seams_are_reachable (void)
{
  /* A seam declared but never reached is dead vocabulary.  Each arm below
   * drives the path that must consume it. */
  const WylFactArtifactTransitionPosixTestFault probe_arms[] = {
    PF (PROBE_PRECLEAN), PF (PROBE_CREATE), PF (PROBE_RENAME),
    PF (PROBE_DIRECTORY_FSYNC), PF (PROBE_RETIRE),
  };
  for (gsize index = 0; index < G_N_ELEMENTS (probe_arms); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t14p-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);
    Capability capability = { 0 };
    wyl_fact_artifact_transition_posix_set_test_fault (probe_arms[index]);
    (void) wyl_fact_artifact_transition_posix_probe_capability
      (&fixture.directory, OPERATION_UUID, &capability);
    g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
          (probe_arms[index]));
    fixture_clear (&fixture);
  }

  const WylFactArtifactTransitionPosixTestFault observe_arms[] = {
    PF (OBSERVE_DIRECTORY_FSTAT), PF (OBSERVE_LEASE_FSTAT),
    PF (OBSERVE_SLOT_OPEN), PF (OBSERVE_SLOT_SUBSTITUTE),
  };
  for (gsize index = 0; index < G_N_ELEMENTS (observe_arms); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2a-t14o-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);
    make_conforming (&fixture, fixture.names.stage, 2);
    Observation observation;
    wyl_fact_artifact_transition_posix_set_test_fault (observe_arms[index]);
    wyrelog_error_t status = observe (&fixture, &observation);
    g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
          (observe_arms[index]));
    /*
     * SUBSTITUTE is the one seam whose EFFECT nothing else pins, so
     * was_consumed alone would leave its semantics undefined for unit 2b,
     * which inherits it.  It models a slot that turned into a reparse point,
     * so the observation SUCCEEDS and the first slot reports present with
     * reparse set -- unlike the other three arms, which fail the whole
     * observation.
     */
    if (observe_arms[index] == PF (OBSERVE_SLOT_SUBSTITUTE)) {
      g_assert_cmpint (status, ==, WYRELOG_E_OK);
      g_assert_true (observation.entries[SLOT_MAIN].present);
      g_assert_true (observation.entries[SLOT_MAIN].reparse);
      g_assert_cmpuint (observation.entries[SLOT_MAIN].identity.domain, ==, 0);
    } else {
      g_assert_cmpint (status, !=, WYRELOG_E_OK);
    }
    fixture_clear (&fixture);
  }
}

/* ------------------------------------------------------------------ */
/* Unit 2b: Executor tests                                             */
/* ------------------------------------------------------------------ */

static void
test_execute_invalid_parameters (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-inv-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = {
    .staged_file = MT (DURABILITY_PROVEN),
  };

  /* NULL provider */
  g_assert_cmpint (execute_current (NULL,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_cmpint (durability.staged_file, ==, MT (DURABILITY_UNPROVEN));

  /* NULL effect */
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), NULL, &durability), ==, WYRELOG_E_INVALID);

  /* NULL durability */
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), &effect, NULL), ==, WYRELOG_E_INVALID);

  Observation authorized = { 0 };
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_observe (provider,
      &lifecycle, &authorized), ==, WYRELOG_E_OK);

  /* NULL or foreign authorization observation */
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider, NULL,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_INVALID);
  authorized.operation_uuid[0] ^= 1;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &authorized, MT (OP_SYNC_STAGED), &effect, &durability), ==,
      WYRELOG_E_INVALID);

  /* Invalid Op: OP_NONE */
  g_assert_cmpint (execute_current (provider,
      MT (OP_NONE), &effect, &durability), ==, WYRELOG_E_INVALID);

  /* Invalid Op: OP_INSPECT */
  g_assert_cmpint (execute_current (provider,
      MT (OP_INSPECT), &effect, &durability), ==, WYRELOG_E_INVALID);

  /* Invalid Op: OP_COUNT */
  g_assert_cmpint (execute_current (provider,
      MT (OP_COUNT), &effect, &durability), ==, WYRELOG_E_INVALID);

  /* Lease verification failure */
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_LEASE_VERIFY));
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_POLICY);
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_LEASE_VERIFY)));

  fixture_clear (&fixture);
}

static void
test_execute_sync_staged (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-stg-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Missing stage file -> NOT_APPLIED */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = {
    .staged_file = MT (DURABILITY_PROVEN),
  };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_cmpint (durability.staged_file, ==, MT (DURABILITY_UNPROVEN));

  /* 2. Symlink at stage file -> NOT_APPLIED (target outside graph dir) */
  g_autofree gchar *target_path = g_build_filename (fixture.root, "external.txt", NULL);
  g_file_set_contents (target_path, "ext", 3, NULL);
  g_assert_cmpint (symlinkat (target_path, fixture.directory.graph_fd, fixture.names.stage), ==, 0);

  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { .staged_file = MT (DURABILITY_PROVEN) };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_cmpint (durability.staged_file, ==, MT (DURABILITY_UNPROVEN));
  unlinkat (fixture.directory.graph_fd, fixture.names.stage, 0);

  /* 3. Conforming stage file -> APPLIED + PROVEN */
  make_conforming (&fixture, fixture.names.stage, 16);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.staged_file, ==, MT (DURABILITY_PROVEN));

  /* 4. Open fault -> UNKNOWN */
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_SYNC_STAGED_OPEN));
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { .staged_file = MT (DURABILITY_PROVEN) };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_cmpint (durability.staged_file, ==, MT (DURABILITY_UNPROVEN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_SYNC_STAGED_OPEN)));

  /* 5. Fsync fault -> UNKNOWN */
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_SYNC_STAGED_FSYNC));
  wyl_fact_artifact_transition_posix_set_test_flush_errno (EIO);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { .staged_file = MT (DURABILITY_PROVEN) };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_STAGED), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_cmpint (durability.staged_file, ==, MT (DURABILITY_UNPROVEN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_SYNC_STAGED_FSYNC)));

  fixture_clear (&fixture);
}

static void
test_execute_retain (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-ret-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Missing source (final) -> NOT_APPLIED */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETAIN), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));

  /* 2. Destination already exists -> NOT_APPLIED */
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 10);
  make_conforming (&fixture, fixture.names.rollback, 20);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETAIN), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  unlinkat (fixture.directory.graph_fd, fixture.names.rollback, 0);

  /* 3. Successful RETAIN -> APPLIED */
  Identity main_id = real_identity (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETAIN), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  /* Verify final is gone and rollback has the original identity */
  struct stat st;
  g_assert_cmpint (fstatat (fixture.directory.graph_fd,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, &st, AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);
  Identity rb_id = real_identity (&fixture, fixture.names.rollback);
  g_assert_cmpuint (rb_id.domain, ==, main_id.domain);
  g_assert_cmpuint (rb_id.object, ==, main_id.object);

  /* 4. Injected rename fault with EIO -> UNKNOWN */
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 11);
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_RETAIN_RENAME));
  wyl_fact_artifact_transition_posix_set_test_rename_errno (EIO);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETAIN), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_RETAIN_RENAME)));

  fixture_clear (&fixture);
}

static void
test_execute_sync_rollback_file (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-srb-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Missing rollback file -> NOT_APPLIED */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = {
    .rollback_file = MT (DURABILITY_PROVEN),
  };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_ROLLBACK_FILE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_cmpint (durability.rollback_file, ==, MT (DURABILITY_UNPROVEN));

  /* 2. Conforming rollback file -> APPLIED + PROVEN */
  make_conforming (&fixture, fixture.names.rollback, 16);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_ROLLBACK_FILE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.rollback_file, ==, MT (DURABILITY_PROVEN));

  /* 3. Open fault -> UNKNOWN */
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_SYNC_ROLLBACK_OPEN));
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { .rollback_file = MT (DURABILITY_PROVEN) };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_ROLLBACK_FILE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_cmpint (durability.rollback_file, ==, MT (DURABILITY_UNPROVEN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_SYNC_ROLLBACK_OPEN)));

  fixture_clear (&fixture);
}

static void
test_execute_sync_retain_dir (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-srd-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Success path on capable filesystem -> APPLIED + PROVEN */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_RETAIN_DIR), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.directory_after_retain, ==, MT (DURABILITY_PROVEN));

  /* 2. Runtime failure when capability was PROVEN (e.g. EIO) -> UNKNOWN + UNPROVEN */
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_SYNC_RETAIN_DIR_FSYNC));
  wyl_fact_artifact_transition_posix_set_test_flush_errno (EIO);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { .directory_after_retain = MT (DURABILITY_PROVEN) };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_RETAIN_DIR), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_cmpint (durability.directory_after_retain, ==, MT (DURABILITY_UNPROVEN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_SYNC_RETAIN_DIR_FSYNC)));

  /* 3. Capability gap provider (directory_flush == UNSUPPORTED) + ENOTSUP -> APPLIED + UNSUPPORTED */
  Capability unsupp_cap = {
    .no_replace_supported = TRUE,
    .directory_flush = MT (DURABILITY_UNSUPPORTED),
  };
  g_autoptr (WylFactArtifactTransitionPosix) unsupp_provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_open (&fixture.resolver,
      &fixture.directory, fixture.lease, OPERATION_UUID, &unsupp_cap,
      &unsupp_provider), ==, WYRELOG_E_OK);

  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_SYNC_RETAIN_DIR_FSYNC));
  wyl_fact_artifact_transition_posix_set_test_flush_errno (ENOTSUP);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { 0 };
  g_assert_cmpint (execute_current (unsupp_provider,
      MT (OP_SYNC_RETAIN_DIR), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.directory_after_retain, ==, MT (DURABILITY_UNSUPPORTED));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_SYNC_RETAIN_DIR_FSYNC)));

  fixture_clear (&fixture);
}

static void
test_execute_publish (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-pub-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Missing stage -> NOT_APPLIED */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_PUBLISH), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));

  /* 2. Destination already exists -> NOT_APPLIED */
  make_conforming (&fixture, fixture.names.stage, 12);
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 24);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_PUBLISH), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  unlinkat (fixture.directory.graph_fd, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 0);

  /* 3. Successful PUBLISH -> APPLIED */
  Identity stg_id = real_identity (&fixture, fixture.names.stage);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_PUBLISH), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  /* Verify stage is gone and final has stage's identity */
  struct stat st;
  g_assert_cmpint (fstatat (fixture.directory.graph_fd, fixture.names.stage,
      &st, AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);
  Identity final_id = real_identity (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME);
  g_assert_cmpuint (final_id.domain, ==, stg_id.domain);
  g_assert_cmpuint (final_id.object, ==, stg_id.object);

  /* 4. Injected fault with EINTR -> UNKNOWN */
  make_conforming (&fixture, fixture.names.stage, 13);
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_PUBLISH_RENAME));
  wyl_fact_artifact_transition_posix_set_test_rename_errno (EINTR);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_PUBLISH), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_PUBLISH_RENAME)));

  fixture_clear (&fixture);
}

static void
test_execute_sync_publish_dir (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-spd-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Success path -> APPLIED + PROVEN */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_PUBLISH_DIR), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.directory_after_publish, ==, MT (DURABILITY_PROVEN));

  /* 2. Injected fsync fault -> UNKNOWN + UNPROVEN */
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_SYNC_PUBLISH_DIR_FSYNC));
  wyl_fact_artifact_transition_posix_set_test_flush_errno (EIO);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  durability = (WylFactArtifactMainTransitionDurabilityEvidence) { .directory_after_publish = MT (DURABILITY_PROVEN) };
  g_assert_cmpint (execute_current (provider,
      MT (OP_SYNC_PUBLISH_DIR), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_cmpint (durability.directory_after_publish, ==, MT (DURABILITY_UNPROVEN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_SYNC_PUBLISH_DIR_FSYNC)));

  fixture_clear (&fixture);
}

static void
test_execute_rollback_op (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-rol-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Missing rollback file -> NOT_APPLIED */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_ROLLBACK), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));

  /* 2. Successful ROLLBACK -> APPLIED */
  make_conforming (&fixture, fixture.names.rollback, 18);
  Identity rb_id = real_identity (&fixture, fixture.names.rollback);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_ROLLBACK), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  /* Verify rollback gone and final restored */
  struct stat st;
  g_assert_cmpint (fstatat (fixture.directory.graph_fd, fixture.names.rollback,
      &st, AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);
  Identity final_id = real_identity (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME);
  g_assert_cmpuint (final_id.domain, ==, rb_id.domain);
  g_assert_cmpuint (final_id.object, ==, rb_id.object);

  fixture_clear (&fixture);
}

static void
test_execute_retire_stage (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-rst-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Already absent stage file -> APPLIED */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETIRE_STAGE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  /* 2. Symlink at stage file -> NOT_APPLIED, target file preserved */
  g_autofree gchar *target_path = g_build_filename (fixture.root, "preserved.txt", NULL);
  g_file_set_contents (target_path, "content", 7, NULL);
  g_assert_cmpint (symlinkat (target_path, fixture.directory.graph_fd, fixture.names.stage), ==, 0);

  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETIRE_STAGE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_true (g_file_test (target_path, G_FILE_TEST_EXISTS));
  unlinkat (fixture.directory.graph_fd, fixture.names.stage, 0);

  /* 3. Conforming stage file -> APPLIED, unlinked */
  make_conforming (&fixture, fixture.names.stage, 22);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETIRE_STAGE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  struct stat st;
  g_assert_cmpint (fstatat (fixture.directory.graph_fd, fixture.names.stage,
      &st, AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);

  /* 4. Unlink fault -> UNKNOWN */
  make_conforming (&fixture, fixture.names.stage, 22);
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_RETIRE_STAGE_UNLINK));
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_RETIRE_STAGE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_RETIRE_STAGE_UNLINK)));

  fixture_clear (&fixture);
}

static void
test_execute_finalize (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-fin-XXXXXX");
  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);

  /* 1. Missing rollback link (Mode B or already finalized) -> APPLIED */
  WylFactArtifactMainTransitionEffect effect = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (execute_current (provider,
      MT (OP_FINALIZE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  /* 2. Symlink at rollback file -> NOT_APPLIED, target preserved */
  g_autofree gchar *target_path = g_build_filename (fixture.root, "fin_target.txt", NULL);
  g_file_set_contents (target_path, "data", 4, NULL);
  g_assert_cmpint (symlinkat (target_path, fixture.directory.graph_fd, fixture.names.rollback), ==, 0);

  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_FINALIZE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_true (g_file_test (target_path, G_FILE_TEST_EXISTS));
  unlinkat (fixture.directory.graph_fd, fixture.names.rollback, 0);

  /* 3. Conforming rollback file -> APPLIED, unlinked */
  make_conforming (&fixture, fixture.names.rollback, 30);
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_FINALIZE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  struct stat st;
  g_assert_cmpint (fstatat (fixture.directory.graph_fd, fixture.names.rollback,
      &st, AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);

  /* 4. Unlink fault -> UNKNOWN */
  make_conforming (&fixture, fixture.names.rollback, 30);
  wyl_fact_artifact_transition_posix_set_test_fault (PF (EXECUTE_FINALIZE_UNLINK));
  effect = (WylFactArtifactMainTransitionEffect) 999;
  g_assert_cmpint (execute_current (provider,
      MT (OP_FINALIZE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
        PF (EXECUTE_FINALIZE_UNLINK)));

  fixture_clear (&fixture);
}

static void
test_execute_mode_a_full_lifecycle (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-mda-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 100);
  make_conforming (&fixture, fixture.names.stage, 200);

  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);

  Identity main_id = real_identity (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME);
  Identity stage_id = real_identity (&fixture, fixture.names.stage);
  Request request = request_for (&observation, main_id, stage_id, FALSE);

  Result result;
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  g_assert_cmpint (result.next_op, ==, MT (OP_SYNC_STAGED));

  /* Op 1: SYNC_STAGED */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_SYNC_STAGED), &observation, &result), ==, WYRELOG_E_OK);
  WylFactArtifactMainTransitionEffect effect;
  WylFactArtifactMainTransitionDurabilityEvidence durability;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_SYNC_STAGED), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.staged_file, ==, MT (DURABILITY_PROVEN));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  observation.durability = durability;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_SYNC_STAGED), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  g_assert_cmpint (result.next_op, ==, MT (OP_RETAIN));

  /* Op 2: RETAIN */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_RETAIN), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_RETAIN), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_RETAIN), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));
  g_assert_cmpint (result.next_op, ==, MT (OP_SYNC_ROLLBACK_FILE));

  /* Op 3: SYNC_ROLLBACK_FILE */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_SYNC_ROLLBACK_FILE), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_SYNC_ROLLBACK_FILE), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.rollback_file, ==, MT (DURABILITY_PROVEN));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  observation.durability = durability;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_SYNC_ROLLBACK_FILE), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));
  g_assert_cmpint (result.next_op, ==, MT (OP_SYNC_RETAIN_DIR));

  /* Op 4: SYNC_RETAIN_DIR */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_SYNC_RETAIN_DIR), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_SYNC_RETAIN_DIR), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.directory_after_retain, ==, MT (DURABILITY_PROVEN));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  observation.durability = durability;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_SYNC_RETAIN_DIR), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));
  g_assert_cmpint (result.next_op, ==, MT (OP_PUBLISH));

  /* Op 5: PUBLISH */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_PUBLISH), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_PUBLISH), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_PUBLISH), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_PUBLISHED));
  g_assert_cmpint (result.next_op, ==, MT (OP_SYNC_PUBLISH_DIR));

  /* Op 6: SYNC_PUBLISH_DIR */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_SYNC_PUBLISH_DIR), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_SYNC_PUBLISH_DIR), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (durability.directory_after_publish, ==, MT (DURABILITY_PROVEN));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  observation.durability = durability;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_SYNC_PUBLISH_DIR), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_PUBLISHED_DURABLE));
  g_assert_cmpint (result.next_op, ==, MT (OP_FINALIZE));

  WylTestDriverStoredValue synced = completed_driver_value (&request,
          MT (OP_SYNC_PUBLISH_DIR), result.state);
  g_autoptr (WylFactArtifactInventorySnapshot) restarted_snapshot = NULL;
  Observation restarted_observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &restarted_snapshot, &restarted_observation), ==,
      WYRELOG_E_OK);
  Result restarted_result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) restarted_transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request,
      restarted_snapshot, &restarted_observation, &restarted_result,
      &restarted_transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (restarted_result.state, ==, MT (STATE_PUBLISHED));
  g_assert_cmpint (wyl_test_driver_restart_action (&synced,
      restarted_result.state), ==,
      WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR);

  /* Op 7: FINALIZE */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_FINALIZE), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_FINALIZE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_FINALIZE), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_FINALIZED));
  g_assert_true (result.terminal);

  fixture_clear (&fixture);
}

static void
test_execute_mode_b_full_lifecycle (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-mdb-XXXXXX");
  make_conforming (&fixture, fixture.names.stage, 200);

  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);

  Identity stage_id = real_identity (&fixture, fixture.names.stage);
  Request request = request_for (&observation, (Identity) { 0 }, stage_id, TRUE);

  Result result;
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  g_assert_cmpint (result.next_op, ==, MT (OP_SYNC_STAGED));

  /* Op 1: SYNC_STAGED */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_SYNC_STAGED), &observation, &result), ==, WYRELOG_E_OK);
  WylFactArtifactMainTransitionEffect effect;
  WylFactArtifactMainTransitionDurabilityEvidence durability;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_SYNC_STAGED), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  observation.durability = durability;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_SYNC_STAGED), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  g_assert_cmpint (result.next_op, ==, MT (OP_PUBLISH));

  /* Op 2: PUBLISH */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_PUBLISH), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_PUBLISH), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_PUBLISH), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_PUBLISHED));
  g_assert_cmpint (result.next_op, ==, MT (OP_SYNC_PUBLISH_DIR));

  /* Op 3: SYNC_PUBLISH_DIR */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_SYNC_PUBLISH_DIR), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_SYNC_PUBLISH_DIR), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  observation.durability = durability;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_SYNC_PUBLISH_DIR), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_PUBLISHED_DURABLE));
  g_assert_cmpint (result.next_op, ==, MT (OP_FINALIZE));

  /* Op 4: FINALIZE (rollback file was never created -> returns APPLIED) */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_FINALIZE), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_FINALIZE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_FINALIZE), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_FINALIZED));
  g_assert_true (result.terminal);

  fixture_clear (&fixture);
}

static void
test_execute_mode_a_rollback_lifecycle (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u2b-mdr-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 100);
  make_conforming (&fixture, fixture.names.stage, 200);

  g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);

  Identity main_id = real_identity (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME);
  Identity stage_id = real_identity (&fixture, fixture.names.stage);
  Request request = request_for (&observation, main_id, stage_id, FALSE);

  Result result;
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_OK);

  /* SYNC_STAGED */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_SYNC_STAGED), &observation, &result), ==, WYRELOG_E_OK);
  WylFactArtifactMainTransitionEffect effect;
  WylFactArtifactMainTransitionDurabilityEvidence durability;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_SYNC_STAGED), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  observation.durability = durability;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_SYNC_STAGED), effect, &observation, &result), ==, WYRELOG_E_OK);

  /* RETAIN */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (transition,
      MT (OP_RETAIN), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_RETAIN), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));
  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (transition,
      MT (OP_RETAIN), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));

  /* Re-admit under resume_forbidden to unlock ROLLBACK */
  Transition *abandon_tr = NULL;
  request.resume_forbidden = TRUE;
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &abandon_tr), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.next_op, ==, MT (OP_ROLLBACK));

  /* ROLLBACK */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (abandon_tr,
      MT (OP_ROLLBACK), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_ROLLBACK), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (abandon_tr,
      MT (OP_ROLLBACK), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_ROLLED_BACK));
  g_assert_cmpint (result.next_op, ==, MT (OP_RETIRE_STAGE));

  WylTestDriverStoredValue rolled_back = completed_driver_value (&request,
          MT (OP_ROLLBACK), result.state);
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  Result restarted_result = { 0 };
  Transition *restarted_transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &restarted_result, &restarted_transition), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (restarted_result.state, ==, MT (STATE_READY));
  g_assert_cmpint (wyl_test_driver_restart_action (&rolled_back,
      restarted_result.state), ==, WYL_TEST_DRIVER_RESTART_RETIRE_STAGE);
  wyl_fact_artifact_main_transition_free (abandon_tr);
  abandon_tr = restarted_transition;
  result = restarted_result;

  /* RETIRE_STAGE */
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (abandon_tr,
      MT (OP_RETIRE_STAGE), &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &observation, MT (OP_RETIRE_STAGE), &effect, &durability), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

  g_assert_cmpint (observe (&fixture, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (abandon_tr,
      MT (OP_RETIRE_STAGE), effect, &observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_ABANDONED));
  g_assert_true (result.terminal);

  wyl_fact_artifact_main_transition_free (abandon_tr);
  fixture_clear (&fixture);
}

static void
test_execute_authorization_binding (void)
{
  Fixture first;
  Fixture second;
  fixture_init (&first, "u2b-auth-a-XXXXXX");
  fixture_init (&second, "u2b-auth-b-XXXXXX");

  Observation first_authorized;
  Observation second_authorized;
  g_assert_cmpint (observe (&first, &first_authorized), ==, WYRELOG_E_OK);
  g_assert_cmpint (observe (&second, &second_authorized), ==, WYRELOG_E_OK);
  g_autoptr (WylFactArtifactTransitionPosix) second_provider
    = open_provider (&second);

  WylFactArtifactMainTransitionEffect effect
    = (WylFactArtifactMainTransitionEffect) 999;
  WylFactArtifactMainTransitionDurabilityEvidence durability = {
    .directory_after_retain = MT (DURABILITY_PROVEN),
  };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute
        (second_provider, &first_authorized, MT (OP_SYNC_RETAIN_DIR),
      &effect, &durability), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_cmpint (durability.directory_after_retain, ==,
      MT (DURABILITY_UNPROVEN));

  Observation wrong_lease = second_authorized;
  wrong_lease.lease_identity = first_authorized.lease_identity;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute
        (second_provider, &wrong_lease, MT (OP_SYNC_RETAIN_DIR),
      &effect, &durability), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (durability.directory_after_retain, ==,
      MT (DURABILITY_UNPROVEN));

  fixture_clear (&second);
  fixture_clear (&first);
}

typedef struct
{
  const gchar *parked;
} PostOpenSubstitution;

static void
substitute_after_open (gint directory_fd, const gchar *name,
    gpointer user_data)
{
  const PostOpenSubstitution *substitution = user_data;
  g_assert_cmpint (renameat (directory_fd, name, directory_fd,
      substitution->parked), ==, 0);
  gint fd = openat (directory_fd, name,
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (write (fd, "foreign", 7), ==, 7);
  g_assert_cmpint (close (fd), ==, 0);
}

static void
test_execute_post_open_substitution (void)
{
  const WylFactArtifactMainTransitionOp ops[] = {
    MT (OP_PUBLISH),
    MT (OP_RETIRE_STAGE),
  };
  for (gsize index = 0; index < G_N_ELEMENTS (ops); index++) {
    Fixture fixture;
    g_autofree gchar *tag
      = g_strdup_printf ("u2b-post-open-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);
    make_conforming (&fixture, fixture.names.stage, 44);

    Observation authorized;
    g_assert_cmpint (observe (&fixture, &authorized), ==, WYRELOG_E_OK);
    PostOpenSubstitution substitution = {
      .parked = index == 0 ? "publish-authorized-away.duckdb"
        : "retire-authorized-away.duckdb",
    };
    wyl_fact_artifact_transition_posix_set_test_post_open_hook
      (substitute_after_open, &substitution);
    wyl_fact_artifact_transition_posix_set_test_fault
      (PF (EXECUTE_ENTRY_SUBSTITUTE));

    g_autoptr (WylFactArtifactTransitionPosix) provider
      = open_provider (&fixture);
    WylFactArtifactMainTransitionEffect effect;
    WylFactArtifactMainTransitionDurabilityEvidence durability;
    g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
        &authorized, ops[index], &effect, &durability), ==, WYRELOG_E_OK);
    g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
    g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
          (PF (EXECUTE_ENTRY_SUBSTITUTE)));

    Identity authorized_identity
      = authorized.entries[SLOT_STAGE].identity;
    Identity foreign = real_identity (&fixture, fixture.names.stage);
    g_assert_false (wyl_fact_artifact_inventory_identity_equal
          (&authorized_identity, &foreign));
    Identity parked = real_identity (&fixture, substitution.parked);
    g_assert_true (wyl_fact_artifact_inventory_identity_equal
          (&authorized_identity, &parked));
    if (ops[index] == MT (OP_PUBLISH)) {
      struct stat st = { 0 };
      g_assert_cmpint (fstatat (fixture.directory.graph_fd,
          WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, &st,
          AT_SYMLINK_NOFOLLOW), ==, -1);
      g_assert_cmpint (errno, ==, ENOENT);
    }
    fixture_clear (&fixture);
  }
}

static void
test_execute_identity_substitution (void)
{
  const WylFactArtifactMainTransitionOp ops[] = {
    MT (OP_RETAIN),
    MT (OP_PUBLISH),
    MT (OP_ROLLBACK),
    MT (OP_RETIRE_STAGE),
    MT (OP_FINALIZE),
  };

  for (gsize index = 0; index < G_N_ELEMENTS (ops); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2b-id-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);

    const gchar *source;
    const gchar *destination = NULL;
    switch (ops[index]) {
      case MT (OP_RETAIN):
        source = WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME;
        destination = fixture.names.rollback;
        break;
      case MT (OP_PUBLISH):
        source = fixture.names.stage;
        destination = WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME;
        break;
      case MT (OP_ROLLBACK):
        source = fixture.names.rollback;
        destination = WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME;
        break;
      case MT (OP_RETIRE_STAGE):
        source = fixture.names.stage;
        break;
      case MT (OP_FINALIZE):
        source = fixture.names.rollback;
        break;
      default:
        g_assert_not_reached ();
    }

    make_conforming (&fixture, source, 11);
    Observation authorized;
    g_assert_cmpint (observe (&fixture, &authorized), ==, WYRELOG_E_OK);

    g_autofree gchar *parked
      = g_strdup_printf ("authorized-away-%zu.duckdb", index);
    g_assert_cmpint (renameat (fixture.directory.graph_fd, source,
        fixture.directory.graph_fd, parked), ==, 0);
    make_conforming (&fixture, source, 22);
    Identity foreign = real_identity (&fixture, source);

    g_autoptr (WylFactArtifactTransitionPosix) provider
      = open_provider (&fixture);
    WylFactArtifactMainTransitionEffect effect;
    WylFactArtifactMainTransitionDurabilityEvidence durability;
    g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
        &authorized, ops[index], &effect, &durability), ==, WYRELOG_E_OK);
    g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));

    Identity after = real_identity (&fixture, source);
    g_assert_true (wyl_fact_artifact_inventory_identity_equal (&foreign,
        &after));
    struct stat st = { 0 };
    g_assert_cmpint (fstatat (fixture.directory.graph_fd, parked, &st,
        AT_SYMLINK_NOFOLLOW), ==, 0);
    if (destination != NULL) {
      g_assert_cmpint (fstatat (fixture.directory.graph_fd, destination, &st,
          AT_SYMLINK_NOFOLLOW), ==, -1);
      g_assert_cmpint (errno, ==, ENOENT);
    }
    fixture_clear (&fixture);
  }

  /* Mode B authorizes an absent rollback name.  A later foreign occupant is
   * not an "already finalized" success and must be preserved. */
  Fixture fixture;
  fixture_init (&fixture, "u2b-id-mode-b-XXXXXX");
  Observation authorized;
  g_assert_cmpint (observe (&fixture, &authorized), ==, WYRELOG_E_OK);
  make_conforming (&fixture, fixture.names.rollback, 33);
  Identity foreign = real_identity (&fixture, fixture.names.rollback);
  g_autoptr (WylFactArtifactTransitionPosix) provider
    = open_provider (&fixture);
  WylFactArtifactMainTransitionEffect effect;
  WylFactArtifactMainTransitionDurabilityEvidence durability;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &authorized, MT (OP_FINALIZE), &effect, &durability), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  Identity after = real_identity (&fixture, fixture.names.rollback);
  g_assert_true (wyl_fact_artifact_inventory_identity_equal (&foreign,
      &after));
  fixture_clear (&fixture);
}

static void
test_execute_fault_seams_are_reachable (void)
{
  const WylFactArtifactTransitionPosixTestFault execute_arms[] = {
    PF (EXECUTE_LEASE_VERIFY),
    PF (EXECUTE_SYNC_STAGED_OPEN),
    PF (EXECUTE_SYNC_STAGED_FSYNC),
    PF (EXECUTE_RETAIN_RENAME),
    PF (EXECUTE_SYNC_ROLLBACK_OPEN),
    PF (EXECUTE_SYNC_ROLLBACK_FSYNC),
    PF (EXECUTE_SYNC_RETAIN_DIR_FSYNC),
    PF (EXECUTE_PUBLISH_RENAME),
    PF (EXECUTE_SYNC_PUBLISH_DIR_FSYNC),
    PF (EXECUTE_ROLLBACK_RENAME),
    PF (EXECUTE_RETIRE_STAGE_VERIFY),
    PF (EXECUTE_RETIRE_STAGE_UNLINK),
    PF (EXECUTE_FINALIZE_VERIFY),
    PF (EXECUTE_FINALIZE_UNLINK),
  };
  for (gsize index = 0; index < G_N_ELEMENTS (execute_arms); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("u2b-t15e-%zu-XXXXXX", index);
    fixture_init (&fixture, tag);
    make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 1);
    make_conforming (&fixture, fixture.names.stage, 2);
    make_conforming (&fixture, fixture.names.rollback, 3);

    g_autoptr (WylFactArtifactTransitionPosix) provider = open_provider (&fixture);
    g_autoptr (GPtrArray) before = entry_set (&fixture);
    wyl_fact_artifact_transition_posix_set_test_fault (execute_arms[index]);

    WylFactArtifactMainTransitionOp op;
    switch (execute_arms[index]) {
      case PF (EXECUTE_SYNC_STAGED_OPEN):
      case PF (EXECUTE_SYNC_STAGED_FSYNC):
        op = MT (OP_SYNC_STAGED);
        break;
      case PF (EXECUTE_RETAIN_RENAME):
        wyl_fact_artifact_transition_posix_set_test_rename_errno (EIO);
        op = MT (OP_RETAIN);
        break;
      case PF (EXECUTE_SYNC_ROLLBACK_OPEN):
      case PF (EXECUTE_SYNC_ROLLBACK_FSYNC):
        op = MT (OP_SYNC_ROLLBACK_FILE);
        break;
      case PF (EXECUTE_SYNC_RETAIN_DIR_FSYNC):
        op = MT (OP_SYNC_RETAIN_DIR);
        break;
      case PF (EXECUTE_PUBLISH_RENAME):
        wyl_fact_artifact_transition_posix_set_test_rename_errno (EIO);
        op = MT (OP_PUBLISH);
        break;
      case PF (EXECUTE_SYNC_PUBLISH_DIR_FSYNC):
        op = MT (OP_SYNC_PUBLISH_DIR);
        break;
      case PF (EXECUTE_ROLLBACK_RENAME):
        wyl_fact_artifact_transition_posix_set_test_rename_errno (EIO);
        op = MT (OP_ROLLBACK);
        break;
      case PF (EXECUTE_RETIRE_STAGE_VERIFY):
      case PF (EXECUTE_RETIRE_STAGE_UNLINK):
        op = MT (OP_RETIRE_STAGE);
        break;
      case PF (EXECUTE_FINALIZE_VERIFY):
      case PF (EXECUTE_FINALIZE_UNLINK):
        op = MT (OP_FINALIZE);
        break;
      default:
        op = MT (OP_SYNC_STAGED);
        break;
    }

    WylFactArtifactMainTransitionEffect effect;
    WylFactArtifactMainTransitionDurabilityEvidence durability;
    wyrelog_error_t status
      = execute_current (provider, op, &effect, &durability);
    if (execute_arms[index] == PF (EXECUTE_LEASE_VERIFY))
      g_assert_cmpint (status, ==, WYRELOG_E_POLICY);
    else {
      g_assert_cmpint (status, ==, WYRELOG_E_OK);
      g_assert_cmpint (effect, ==, MT (EFFECT_UNKNOWN));
    }
    g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed (
          execute_arms[index]));
    g_autoptr (GPtrArray) after = entry_set (&fixture);
    assert_entry_sets_equal (before, after);
    fixture_clear (&fixture);
  }
}

static void
test_capture_is_correlated_and_unstable_is_not_published (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u4-capture-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 3);
  make_conforming (&fixture, fixture.names.stage, 5);
  g_autoptr (WylFactArtifactTransitionPosix) provider
    = open_provider (&fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_anomaly_count
        (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, 1);
  WylFactArtifactInventoryObservation inventory = { 0 };
  g_assert_true (wyl_fact_artifact_inventory_snapshot_get_observation
        (snapshot, &inventory));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&inventory.directory_identity, &observation.directory_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&inventory.guard_identity, &observation.lease_identity));

  Identity main_identity = real_identity (&fixture,
          WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME);
  Identity stage_identity = real_identity (&fixture, fixture.names.stage);
  Request request = request_for (&observation, main_identity, stage_identity,
          FALSE);
  Result result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));

  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  observation = (Observation) { 0 };
  wyl_fact_artifact_transition_posix_set_test_fault
    (PF (CAPTURE_PRE_FINALIZE_MUTATE_STAGE));
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_BUSY);
  g_assert_null (snapshot);
  g_assert_cmpuint (observation.directory_identity.domain, ==, 0);
  g_assert_true (wyl_fact_artifact_transition_posix_test_fault_was_consumed
        (PF (CAPTURE_PRE_FINALIZE_MUTATE_STAGE)));
  fixture_clear (&fixture);
}

static void
test_foreign_root_authority_never_mutates (void)
{
  Fixture fixture;
  Fixture foreign;
  fixture_init (&fixture, "u4-authority-a-XXXXXX");
  fixture_init (&foreign, "u4-authority-b-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 3);
  make_conforming (&fixture, fixture.names.stage, 5);
  g_autoptr (WylFactArtifactTransitionPosix) provider
    = open_provider (&fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation authorized = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_observe (provider,
      &lifecycle, &authorized), ==, WYRELOG_E_OK);

  Capability capability = {
    .no_replace_supported = TRUE,
    .directory_flush = MT (DURABILITY_PROVEN),
  };
  g_autoptr (WylFactArtifactTransitionPosix) refused = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_posix_open (&foreign.resolver,
      &foreign.directory, fixture.lease, OPERATION_UUID, &capability,
      &refused), ==, WYRELOG_E_POLICY);
  g_assert_null (refused);

  WylFactGraphResolver original = fixture.resolver;
  fixture.resolver = foreign.resolver;
  foreign.resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_POLICY);
  g_assert_null (snapshot);
  WylFactArtifactMainTransitionEffect effect = MT (EFFECT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_execute (provider,
      &authorized, MT (OP_RETAIN), &effect, &durability), ==,
      WYRELOG_E_POLICY);
  struct stat present = { 0 };
  g_assert_cmpint (fstatat (fixture.directory.graph_fd,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, &present,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  g_assert_cmpint (fstatat (fixture.directory.graph_fd,
      fixture.names.rollback, &present, AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);

  WylFactGraphResolver foreign_value = fixture.resolver;
  fixture.resolver = original;
  foreign.resolver = foreign_value;
  fixture_clear (&foreign);
  fixture_clear (&fixture);
}

typedef struct
{
  const gchar *path;
} PosixFileStore;

static wyrelog_error_t
posix_store_load (gpointer user_data, WylTestDriverStoredValue *out_value)
{
  PosixFileStore *store = user_data;
  gint fd = g_open (store->path, O_RDONLY | O_CLOEXEC, 0);
  if (fd < 0)
    return WYRELOG_E_IO;
  gsize offset = 0;
  while (offset < sizeof *out_value) {
    ssize_t got = read (fd, (guint8 *) out_value + offset,
            sizeof *out_value - offset);
    if (got <= 0) {
      close (fd);
      return WYRELOG_E_IO;
    }
    offset += (gsize) got;
  }
  guint8 extra;
  ssize_t tail = read (fd, &extra, 1);
  gboolean closed = close (fd) == 0;
  return tail == 0 && closed ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
posix_store_write (const gchar *path, const WylTestDriverStoredValue *value,
    gboolean exclusive)
{
  gint flags = O_WRONLY | O_CLOEXEC | (exclusive ? O_CREAT | O_EXCL : O_TRUNC);
  gint fd = g_open (path, flags, 0600);
  if (fd < 0)
    return WYRELOG_E_IO;
  gsize offset = 0;
  while (offset < sizeof *value) {
    ssize_t wrote = write (fd, (const guint8 *) value + offset,
            sizeof *value - offset);
    if (wrote <= 0) {
      close (fd);
      return WYRELOG_E_IO;
    }
    offset += (gsize) wrote;
  }
  gboolean ok = fsync (fd) == 0 && close (fd) == 0;
  return ok ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
posix_store_cas (gpointer user_data, guint64 expected_revision,
    const WylTestDriverStoredValue *desired,
    WylTestDriverStoredValue *out_committed)
{
  PosixFileStore *store = user_data;
  WylTestDriverStoredValue current = { 0 };
  wyrelog_error_t rc = posix_store_load (store, &current);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (current.revision != expected_revision)
    return WYRELOG_E_BUSY;
  rc = posix_store_write (store->path, desired, FALSE);
  if (rc == WYRELOG_E_OK)
    *out_committed = *desired;
  return rc;
}

static WylTestDriverValueStore
posix_value_store (PosixFileStore *file)
{
  return (WylTestDriverValueStore) {
           .load = posix_store_load,
           .compare_and_swap = posix_store_cas,
           .user_data = file,
  };
}

static Request
request_from_stored (const WylTestDriverStoredValue *stored)
{
  return (Request) {
           .operation_uuid = stored->operation_uuid,
           .directory_identity = stored->directory_identity,
           .lease_identity = stored->lease_identity,
           .expected_main_absent = stored->expected_main_absent,
           .expected_main_identity = stored->expected_main_identity,
           .staged_main_identity = stored->staged_main_identity,
           .resume_forbidden = stored->resume_forbidden,
           .durability_unprovable_acknowledged
             = stored->durability_unprovable_acknowledged,
  };
}

static gboolean
write_counter (const gchar *path, guint value)
{
  gchar encoded[32];
  gint length = g_snprintf (encoded, sizeof encoded, "%u", value);
  gint fd = g_open (path, O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0 || write (fd, encoded, length) != length) {
    if (fd >= 0)
      close (fd);
    return FALSE;
  }
  return fsync (fd) == 0 && close (fd) == 0;
}

typedef struct
{
  Provider *provider;
  Transition *transition;
  Lifecycle lifecycle;
  Observation observation;
  Result result;
  gboolean crash_after_execute;
  const gchar *counter_path;
} PosixDriverAction;

static wyrelog_error_t
run_posix_backend_action (WylFactArtifactMainTransitionOp op,
    gpointer user_data,
    WylFactArtifactMainTransitionState *out_completed_state)
{
  PosixDriverAction *action = user_data;
  wyrelog_error_t rc = wyl_fact_artifact_main_transition_authorize
        (action->transition, op, &action->observation, &action->result);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactArtifactMainTransitionEffect effect = MT (EFFECT_NOT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  rc = wyl_fact_artifact_transition_posix_execute (action->provider,
          &action->observation, op, &effect, &durability);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (action->crash_after_execute) {
    if (effect == MT (EFFECT_APPLIED)
        && write_counter (action->counter_path, 1))
      _exit (77);
    _exit (78);
  }
  rc = wyl_fact_artifact_transition_posix_observe (action->provider,
          &action->lifecycle, &action->observation);
  if (rc != WYRELOG_E_OK)
    return rc;
  action->observation.durability = durability;
  rc = wyl_fact_artifact_main_transition_record (action->transition, op,
          effect, &action->observation, &action->result);
  if (rc == WYRELOG_E_OK)
    *out_completed_state = action->result.state;
  return rc;
}

static int
run_posix_driver_crash_child (const gchar *root, const gchar *store_path,
    const gchar *counter_path)
{
  Fixture fixture;
  fixture_open_existing (&fixture, root);
  PosixFileStore file = { .path = store_path };
  WylTestDriverValueStore store = posix_value_store (&file);
  WylTestDriverStoredValue stored = { 0 };
  if (store.load (store.user_data, &stored) != WYRELOG_E_OK)
    return 78;
  g_autoptr (WylFactArtifactTransitionPosix) provider
    = open_provider (&fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  if (wyl_fact_artifact_transition_posix_capture (provider, &lifecycle,
      &snapshot, &observation) != WYRELOG_E_OK)
    return 78;
  Request request = request_from_stored (&stored);
  Result result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  if (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition) != WYRELOG_E_OK)
    return 78;
  PosixDriverAction action = { .provider = provider,
                               .transition = transition,
                               .lifecycle = lifecycle,
                               .observation = observation,
                               .result = result };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  if (wyl_test_driver_run_mutation (&store, FALSE,
      stored.consumer_generation,
      MT (OP_SYNC_STAGED), run_posix_backend_action, &action, NULL, NULL,
      &attempt, &completed_state) != WYRELOG_E_OK)
    return 78;
  WylTestDriverStoredValue completed = { 0 };
  if (wyl_test_driver_complete_mutation (&store, MT (OP_SYNC_STAGED),
      completed_state, NULL, NULL, &completed) != WYRELOG_E_OK)
    return 78;
  action.crash_after_execute = TRUE;
  action.counter_path = counter_path;
  return wyl_test_driver_run_mutation (&store, FALSE,
             stored.consumer_generation,
             MT (OP_RETAIN), run_posix_backend_action, &action, NULL, NULL,
             &attempt, &completed_state) == WYRELOG_E_OK ? 79 : 78;
}

static void
test_child_crash_restarts_from_fresh_capture (void)
{
  Fixture fixture;
  fixture_init (&fixture, "u4-child-crash-XXXXXX");
  make_conforming (&fixture, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, 3);
  make_conforming (&fixture, fixture.names.stage, 5);
  g_autoptr (WylFactArtifactTransitionPosix) provider
    = open_provider (&fixture);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  Request request = request_for (&observation,
          observation.entries[SLOT_MAIN].identity,
          observation.entries[SLOT_STAGE].identity, FALSE);
  WylTestDriverStoredValue initial = {
    .version = 1,
    .revision = 11,
    .consumer_generation = 23,
    .directory_identity = request.directory_identity,
    .lease_identity = request.lease_identity,
    .expected_main_absent = request.expected_main_absent,
    .expected_main_identity = request.expected_main_identity,
    .staged_main_identity = request.staged_main_identity,
    .resume_forbidden = request.resume_forbidden,
    .durability_unprovable_acknowledged
      = request.durability_unprovable_acknowledged,
    .marker = WYL_TEST_DRIVER_MARKER_NONE,
    .pending_op = MT (OP_NONE),
    .completed_state = MT (STATE_INVALID),
  };
  g_strlcpy (initial.operation_uuid, OPERATION_UUID,
      sizeof initial.operation_uuid);
  g_autofree gchar *root = g_strdup (fixture.root);
  g_autofree gchar *store_path = g_build_filename (root, "driver-state",
          NULL);
  g_autofree gchar *counter_path = g_build_filename (root, "driver-count",
          NULL);
  g_assert_cmpint (posix_store_write (store_path, &initial, TRUE), ==,
      WYRELOG_E_OK);
  gint counter = g_open (counter_path,
          O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  g_assert_cmpint (counter, >=, 0);
  g_assert_cmpint (write (counter, "0", 1), ==, 1);
  g_assert_cmpint (fsync (counter), ==, 0);
  g_assert_cmpint (close (counter), ==, 0);
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  g_clear_pointer (&provider, wyl_fact_artifact_transition_posix_free);
  fixture_clear (&fixture);

  gchar *child_argv[] = { driver_test_executable, "--driver-crash-child",
                          root, store_path, counter_path, NULL };
  gint child_status = 0;
  g_autoptr (GError) error = NULL;
  g_assert_true (g_spawn_sync (NULL, child_argv, NULL, 0, NULL, NULL, NULL,
      NULL, &child_status, &error));
  g_assert_no_error (error);
  g_assert_true (WIFEXITED (child_status));
  g_assert_cmpint (WEXITSTATUS (child_status), ==, 77);

  PosixFileStore file = { .path = store_path };
  WylTestDriverValueStore store = posix_value_store (&file);
  WylTestDriverStoredValue stored = { 0 };
  g_assert_cmpint (store.load (store.user_data, &stored), ==, WYRELOG_E_OK);
  g_assert_cmpint (stored.marker, ==, WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN);
  g_assert_cmpint (stored.pending_op, ==, MT (OP_RETAIN));
  g_assert_cmpuint (stored.consumer_generation, ==, 23);
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&stored.expected_main_identity, &initial.expected_main_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&stored.staged_main_identity, &initial.staged_main_identity));

  fixture_open_existing (&fixture, root);
  provider = open_provider (&fixture);
  observation = (Observation) { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_posix_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  request = request_from_stored (&stored);
  Result result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));
  g_assert_cmpint (wyl_test_driver_restart_action (&stored, result.state), ==,
      WYL_TEST_DRIVER_RESTART_INSPECT_ONLY);
  g_autofree gchar *count = NULL;
  g_assert_true (g_file_get_contents (counter_path, &count, NULL, NULL));
  g_assert_cmpstr (count, ==, "1");
  fixture_clear (&fixture);
}

int
main (int argc, char **argv)
{
  if (argc == 5 && strcmp (argv[1], "--driver-crash-child") == 0)
    return run_posix_driver_crash_child (argv[2], argv[3], argv[4]);
  driver_test_executable = g_canonicalize_filename (argv[0], NULL);
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/artifact-transition-posix/triple-and-identity",
      test_triple_and_identity);
  g_test_add_func ("/fact/artifact-transition-posix/absent-slots",
      test_absent_slot_combinations);
  g_test_add_func ("/fact/artifact-transition-posix/unreadable-not-absent",
      test_unreadable_slot_is_not_absent);
  g_test_add_func ("/fact/artifact-transition-posix/symlink-detection",
      test_symlink_detection);
  g_test_add_func ("/fact/artifact-transition-posix/hard-link-detection",
      test_hard_link_detection);
  g_test_add_func ("/fact/artifact-transition-posix/ownership-detection",
      test_ownership_detection);
  g_test_add_func ("/fact/artifact-transition-posix/non-regular",
      test_non_regular_is_not_conforming);
  g_test_add_func ("/fact/artifact-transition-posix/probe-supported",
      test_probe_supported);
  g_test_add_func ("/fact/artifact-transition-posix/probe-unambiguity",
      test_probe_unambiguity);
  g_test_add_func ("/fact/artifact-transition-posix/probe-preclean",
      test_probe_preclean_fails_closed);
  g_test_add_func ("/fact/artifact-transition-posix/probe-flush-rows",
      test_probe_flush_capability_rows);
  g_test_add_func ("/fact/artifact-transition-posix/probe-clean-exit",
      test_probe_leaves_nothing_behind);
  g_test_add_func ("/fact/artifact-transition-posix/probe-retire-recovery",
      test_probe_retire_leftover_is_recoverable);
  g_test_add_func ("/fact/artifact-transition-posix/probe-crash-recovery",
      test_probe_recovers_from_crashed_predecessor);
  g_test_add_func ("/fact/artifact-transition-posix/classification",
      test_end_to_end_classification);
  g_test_add_func ("/fact/artifact-transition-posix/identities",
      test_lease_and_directory_identity);
  g_test_add_func ("/fact/artifact-transition-posix/durability-unproven",
      test_durability_fields_are_unproven);
  g_test_add_func ("/fact/artifact-transition-posix/fault-seams",
      test_fault_seams_are_reachable);
  g_test_add_func ("/fact/artifact-transition-posix/execute/invalid-params",
      test_execute_invalid_parameters);
  g_test_add_func ("/fact/artifact-transition-posix/execute/sync-staged",
      test_execute_sync_staged);
  g_test_add_func ("/fact/artifact-transition-posix/execute/retain",
      test_execute_retain);
  g_test_add_func ("/fact/artifact-transition-posix/execute/sync-rollback",
      test_execute_sync_rollback_file);
  g_test_add_func ("/fact/artifact-transition-posix/execute/sync-retain-dir",
      test_execute_sync_retain_dir);
  g_test_add_func ("/fact/artifact-transition-posix/execute/publish",
      test_execute_publish);
  g_test_add_func ("/fact/artifact-transition-posix/execute/sync-publish-dir",
      test_execute_sync_publish_dir);
  g_test_add_func ("/fact/artifact-transition-posix/execute/rollback",
      test_execute_rollback_op);
  g_test_add_func ("/fact/artifact-transition-posix/execute/retire-stage",
      test_execute_retire_stage);
  g_test_add_func ("/fact/artifact-transition-posix/execute/finalize",
      test_execute_finalize);
  g_test_add_func ("/fact/artifact-transition-posix/execute/authorization-binding",
      test_execute_authorization_binding);
  g_test_add_func ("/fact/artifact-transition-posix/execute/post-open-substitution",
      test_execute_post_open_substitution);
  g_test_add_func ("/fact/artifact-transition-posix/execute/identity-substitution",
      test_execute_identity_substitution);
  g_test_add_func ("/fact/artifact-transition-posix/execute/mode-a-lifecycle",
      test_execute_mode_a_full_lifecycle);
  g_test_add_func ("/fact/artifact-transition-posix/execute/mode-b-lifecycle",
      test_execute_mode_b_full_lifecycle);
  g_test_add_func ("/fact/artifact-transition-posix/execute/mode-a-rollback-lifecycle",
      test_execute_mode_a_rollback_lifecycle);
  g_test_add_func ("/fact/artifact-transition-posix/execute/fault-seams",
      test_execute_fault_seams_are_reachable);
  g_test_add_func ("/fact/artifact-transition-posix/driver/correlated-capture",
      test_capture_is_correlated_and_unstable_is_not_published);
  g_test_add_func ("/fact/artifact-transition-posix/driver/root-authority",
      test_foreign_root_authority_never_mutates);
  g_test_add_func ("/fact/artifact-transition-posix/driver/child-crash-restart",
      test_child_crash_restarts_from_fresh_capture);
  return g_test_run ();
}

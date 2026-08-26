/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <string.h>

#include "fact/graph-artifact-main-transition-private.h"

#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name

typedef WylFactArtifactMainTransition Transition;
typedef WylFactArtifactMainTransitionObservation Observation;
typedef WylFactArtifactMainTransitionRequest Request;
typedef WylFactArtifactMainTransitionResult Result;
typedef WylFactArtifactMainTransitionOp Op;
typedef WylFactArtifactMainTransitionRefusal Refusal;
typedef WylFactArtifactMainTransitionState State;
typedef WylFactArtifactMainTransitionDurability Durability;
typedef WylFactArtifactMainTransitionEffect Effect;
typedef WylFactArtifactInventoryIdentity Identity;
typedef WylFactArtifactInventorySnapshot Snapshot;

#define SLOT_MAIN     MT (SLOT_MAIN)
#define SLOT_STAGE    MT (SLOT_STAGE)
#define SLOT_ROLLBACK MT (SLOT_ROLLBACK)
#define AUTHORIZED    MT (REFUSAL_NONE)

static const gchar CANONICAL_UUID[] = "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b";
static const guint8 CANONICAL_BYTES[16] = {
  0x01, 0x8f, 0x1a, 0x2b, 0x3c, 0x4d, 0x7e, 0x5f,
  0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b,
};
static const gchar OTHER_UUID[] = "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5c";
static const guint8 OTHER_BYTES[16] = {
  0x01, 0x8f, 0x1a, 0x2b, 0x3c, 0x4d, 0x7e, 0x5f,
  0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5c,
};

/* The five fixed names this contract must stay disjoint from. */
static const gchar *const FIXED_NAMES[] = {
  "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",
  "facts.duckdb.wal.recovery", "facts.duckdb.lock",
};

#define VOLUME_DOMAIN 7

static Identity
identity (guint64 object)
{
  return (Identity) { .domain = VOLUME_DOMAIN, .object = object };
}

/* Windows publishes a 16-byte FileId with object zero.  A pair differing only
 * in the last byte is what a comparison written against identity.object alone
 * would wrongly admit. */
static Identity
extended_identity (guint64 domain, guint8 tail)
{
  Identity result = { domain, 0, { 0 }, 16 };
  result.object_bytes[0] = 0x80;
  result.object_bytes[15] = tail;
  return result;
}

#define DIRECTORY_IDENTITY  identity (1)
#define LEASE_IDENTITY      identity (2)
#define EXPECTED_MAIN       identity (101)
#define STAGED_MAIN         identity (202)
#define FOREIGN_IDENTITY    identity (303)

typedef enum
{
  F_ABSENT = 0,
  F_MAIN,
  F_STAGE,
  F_FOREIGN,
} MainKind;

typedef struct
{
  gboolean mode_b;
  gboolean resume_forbidden;
  gboolean ack;
} Options;

static Request
make_request (const Options *options)
{
  Request request = {
    .operation_uuid = CANONICAL_UUID,
    .directory_identity = DIRECTORY_IDENTITY,
    .lease_identity = LEASE_IDENTITY,
    .expected_main_absent = options->mode_b,
    .expected_main_identity = options->mode_b ? (Identity) { 0 }
        : EXPECTED_MAIN,
    .staged_main_identity = STAGED_MAIN,
    .resume_forbidden = options->resume_forbidden,
    .durability_unprovable_acknowledged = options->ack,
  };
  return request;
}

static void
set_entry (Observation *observation, guint slot, gboolean present,
    Identity value)
{
  observation->entries[slot] = (WylFactArtifactMainTransitionEntryEvidence) {
    .present = present,
    .identity = present ? value : (Identity) { 0 },
    .link_count = present ? 1u : 0u,
    .reparse = FALSE,
    .owner_state = present ? MT (OWNER_CONFORMING) : MT (OWNER_UNKNOWN),
  };
}

static Observation
observe (MainKind kind, gboolean stage, gboolean rollback)
{
  Observation observation = {
    .directory_identity = DIRECTORY_IDENTITY,
    .lease_identity = LEASE_IDENTITY,
    .sealed = TRUE,
    .main_binding_live = FALSE,
    .no_replace_supported = TRUE,
  };
  memcpy (observation.operation_uuid, CANONICAL_BYTES,
      sizeof observation.operation_uuid);
  set_entry (&observation, SLOT_MAIN, kind != F_ABSENT,
      kind == F_MAIN ? EXPECTED_MAIN
      : kind == F_STAGE ? STAGED_MAIN : FOREIGN_IDENTITY);
  set_entry (&observation, SLOT_STAGE, stage, STAGED_MAIN);
  set_entry (&observation, SLOT_ROLLBACK, rollback, EXPECTED_MAIN);
  return observation;
}

/* ------------------------------------------------------------------ */
/* the #622 snapshot the gate is evaluated against                     */
/* ------------------------------------------------------------------ */

typedef struct
{
  gint unknown_delta;
  guint malformed;
  gboolean lock_absent;
  gboolean wal_present;
  gboolean main_absent;
  gboolean main_foreign;
  gboolean unbound;
  gboolean unstable;
} SnapshotTweak;

static Snapshot *
snapshot_build (const Observation *observation, const SnapshotTweak *tweak)
{
  static const SnapshotTweak none = { 0 };
  const SnapshotTweak *t = tweak == NULL ? &none : tweak;
  WylFactArtifactInventoryObservation point = {
    .directory_identity = t->unbound ? identity (77)
        : observation->directory_identity,
    .guard_identity = identity (3),
    .entry_fingerprint = 5,
  };
  Snapshot *snapshot = wyl_fact_artifact_inventory_snapshot_new (32);
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);

  gboolean main_present = t->main_foreign
      || (observation->entries[SLOT_MAIN].present && !t->main_absent);
  Identity main_identity = t->main_foreign ? identity (911)
      : observation->entries[SLOT_MAIN].identity;
  Identity wal_identity = identity (912);
  Identity lock_identity = identity (913);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, main_present ? &main_identity : NULL,
      main_present, main_present ? 1 : 0, TRUE, main_present ? 1 : 0), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_WAL, t->wal_present ? &wal_identity : NULL,
      t->wal_present, t->wal_present ? 1 : 0, TRUE, t->wal_present ? 1 : 0),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT, NULL, FALSE, 0, TRUE, 0), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_RECOVERY, NULL, FALSE, 0, TRUE, 0), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_LOCK,
      t->lock_absent ? NULL : &lock_identity, !t->lock_absent,
      t->lock_absent ? 0 : 1, TRUE, t->lock_absent ? 0 : 1), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_TEMP, NULL, FALSE, 0, TRUE, 0), ==,
      WYRELOG_E_OK);

  /* The stage and rollback artifacts are not fixed names and not valid temp
   * roots, so the provider's readdir fallthrough counts each as an unknown
   * entry.  Conjunct (c) is exactly that count against the triple. */
  gint unknown = (observation->entries[SLOT_STAGE].present ? 1 : 0)
      + (observation->entries[SLOT_ROLLBACK].present ? 1 : 0)
      + t->unknown_delta;
  for (gint index = 0; index < unknown; index++)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly
          (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==,
        WYRELOG_E_OK);
  for (guint index = 0; index < t->malformed; index++)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly
          (snapshot, WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY), ==,
        WYRELOG_E_OK);

  if (t->unstable) {
    WylFactArtifactInventoryObservation moved = point;
    moved.entry_fingerprint = point.entry_fingerprint + 1;
    wyl_fact_artifact_inventory_snapshot_end (snapshot, &moved);
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
        ==, WYRELOG_E_BUSY);
    return snapshot;
  }
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  return snapshot;
}

/* ------------------------------------------------------------------ */
/* admission and drive helpers                                         */
/* ------------------------------------------------------------------ */

static wyrelog_error_t
admit (const Request *request, const Observation *observation,
    const SnapshotTweak *tweak, Result *out_result, Transition **out)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot
    = snapshot_build (observation, tweak);
  return wyl_fact_artifact_main_transition_admit (request, snapshot,
             observation, out_result, out);
}

static Transition *
admit_ok (const Options *options, const Observation *observation)
{
  Request request = make_request (options);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&request, observation, NULL, &result, &transition),
      ==, WYRELOG_E_OK);
  g_assert_nonnull (transition);
  return transition;
}

static Refusal
admit_refusal (const Options *options, const Observation *observation,
    const SnapshotTweak *tweak)
{
  Request request = make_request (options);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&request, observation, tweak, &result, &transition),
      ==, WYRELOG_E_POLICY);
  g_assert_null (transition);
  g_assert_cmpint (result.next_op, ==, MT (OP_NONE));
  /* INVALID is an input-validation value and is never driven into: a refused
   * admission reports it and yields no object to drive. */
  g_assert_cmpint (result.state, ==, MT (STATE_INVALID));
  g_assert_false (result.terminal);
  return result.refusal;
}

typedef struct
{
  Transition *transition;
  Observation observation;
} Drive;

static void
drive_clear (Drive *drive)
{
  wyl_fact_artifact_main_transition_free (drive->transition);
  drive->transition = NULL;
}

static Observation
with_seam (const Observation *base, Op sync_op, Durability value)
{
  Observation result = *base;
  switch (sync_op) {
    case MT (OP_SYNC_STAGED):
      result.durability.staged_file = value;
      break;
    case MT (OP_SYNC_ROLLBACK_FILE):
      result.durability.rollback_file = value;
      break;
    case MT (OP_SYNC_RETAIN_DIR):
      result.durability.directory_after_retain = value;
      break;
    default:
      result.durability.directory_after_publish = value;
      break;
  }
  return result;
}

static void
latch_seam (Drive *drive, Op sync_op, Durability value)
{
  Result result;
  Observation post = with_seam (&drive->observation, sync_op, value);
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (drive->transition, sync_op, &drive->observation, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record
        (drive->transition, sync_op, MT (EFFECT_APPLIED), &post, &result), ==,
      WYRELOG_E_OK);
}

static void
mutate (Drive *drive, Op op, Observation post)
{
  Result result;
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (drive->transition, op, &drive->observation, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record
        (drive->transition, op, MT (EFFECT_APPLIED), &post, &result), ==,
      WYRELOG_E_OK);
  drive->observation = post;
}

/*
 * Each state is left with every seam that state itself can produce latched,
 * so a table cell that refuses is refusing on the transition rule rather than
 * on a seam the drive forgot.  THE MODE-A SEQUENCE INCLUDES SYNC_RETAIN_DIR
 * DELIBERATELY: PUBLISH cannot be authorized until that latch is PROVEN or
 * UNSUPPORTED, so a drive helper that omits it makes the whole mode-A table
 * undrivable and every downstream state unreachable.
 */
static Drive
drive_to (State target, const Options *options)
{
  Drive drive = { 0 };
  if (target == MT (STATE_RETAINED_STAGE_LOST)) {
    drive.observation = observe (F_ABSENT, FALSE, TRUE);
    drive.transition = admit_ok (options, &drive.observation);
    return drive;
  }
  drive.observation = options->mode_b ? observe (F_ABSENT, TRUE, FALSE)
      : observe (F_MAIN, TRUE, FALSE);
  drive.transition = admit_ok (options, &drive.observation);
  if (options->resume_forbidden) {
    /* Under the flag RETIRE_STAGE is the ONLY legal op, so the drive cannot
     * latch anything on the way: READY and ABANDONED are the only reachable
     * states and the one legal op consults no seam. */
    if (target == MT (STATE_READY))
      return drive;
    g_assert_cmpint (target, ==, MT (STATE_ABANDONED));
    mutate (&drive, MT (OP_RETIRE_STAGE),
        options->mode_b ? observe (F_ABSENT, FALSE, FALSE)
        : observe (F_MAIN, FALSE, FALSE));
    return drive;
  }
  latch_seam (&drive, MT (OP_SYNC_STAGED), MT (DURABILITY_PROVEN));
  if (target == MT (STATE_READY))
    return drive;

  if (options->mode_b) {
    mutate (&drive, MT (OP_PUBLISH), observe (F_STAGE, FALSE, FALSE));
    if (target == MT (STATE_PUBLISHED))
      return drive;
    latch_seam (&drive, MT (OP_SYNC_PUBLISH_DIR), MT (DURABILITY_PROVEN));
    if (target == MT (STATE_PUBLISHED_DURABLE))
      return drive;
    mutate (&drive, MT (OP_FINALIZE), observe (F_STAGE, FALSE, FALSE));
    return drive;
  }

  mutate (&drive, MT (OP_RETAIN), observe (F_ABSENT, TRUE, TRUE));
  latch_seam (&drive, MT (OP_SYNC_ROLLBACK_FILE), MT (DURABILITY_PROVEN));
  latch_seam (&drive, MT (OP_SYNC_RETAIN_DIR), MT (DURABILITY_PROVEN));
  if (target == MT (STATE_RETAINED))
    return drive;
  if (target == MT (STATE_ROLLED_BACK) || target == MT (STATE_ABANDONED)) {
    mutate (&drive, MT (OP_ROLLBACK), observe (F_MAIN, TRUE, FALSE));
    if (target == MT (STATE_ROLLED_BACK))
      return drive;
    mutate (&drive, MT (OP_RETIRE_STAGE), observe (F_MAIN, FALSE, FALSE));
    return drive;
  }
  mutate (&drive, MT (OP_PUBLISH), observe (F_STAGE, FALSE, TRUE));
  if (target == MT (STATE_PUBLISHED))
    return drive;
  latch_seam (&drive, MT (OP_SYNC_PUBLISH_DIR), MT (DURABILITY_PROVEN));
  if (target == MT (STATE_PUBLISHED_DURABLE))
    return drive;
  mutate (&drive, MT (OP_FINALIZE), observe (F_STAGE, FALSE, FALSE));
  return drive;
}

static Refusal
authorize_refusal (Transition *transition, Op op,
    const Observation *observation)
{
  Result result;
  wyrelog_error_t status = wyl_fact_artifact_main_transition_authorize
        (transition, op, observation, &result);
  if (status == WYRELOG_E_OK) {
    g_assert_cmpint (result.refusal, ==, AUTHORIZED);
    g_assert_cmpint (result.next_op, ==, op);
    return AUTHORIZED;
  }
  g_assert_cmpint (status, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.next_op, ==, MT (OP_NONE));
  g_assert_cmpint (result.refusal, !=, AUTHORIZED);
  return result.refusal;
}

static Refusal
gate_at (State state, const Options *options, Op op)
{
  Drive drive = drive_to (state, options);
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (drive.transition),
      ==, state);
  Refusal refusal = authorize_refusal (drive.transition, op,
          &drive.observation);
  drive_clear (&drive);
  return refusal;
}

/* ------------------------------------------------------------------ */
/* T1 derived identities                                               */
/* ------------------------------------------------------------------ */

static void
test_derived_identities (void)
{
  static const gchar *const rejected[] = {
    "018F1A2B-3C4D-7E5F-8A9B-0C1D2E3F4A5B",   /* uppercase */
    "018f1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b",   /* v4, not v7 */
    "018f1a2b-3c4d-7e5f-0a9b-0c1d2e3f4a5b",   /* wrong variant nibble */
    "018f1a2b3c4d7e5f8a9b0c1d2e3f4a5b",       /* unhyphenated */
    "",
  };
  Options options = { 0 };
  Observation observation = observe (F_MAIN, TRUE, FALSE);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++) {
    Request request = make_request (&options);
    request.operation_uuid = rejected[index];
    Result result = { .state = MT (STATE_FINALIZED) };
    Transition *transition = (Transition *) &result;
    g_assert_cmpint (admit (&request, &observation, NULL, &result,
        &transition), ==, WYRELOG_E_INVALID);
    g_assert_null (transition);
    g_assert_cmpint (result.state, ==, MT (STATE_INVALID));
  }
  Request request = make_request (&options);
  request.operation_uuid = NULL;
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&request, &observation, NULL, &result, &transition),
      ==, WYRELOG_E_INVALID);
  g_assert_null (transition);

  Transition *live = admit_ok (&options, &observation);
  g_autofree gchar *stage
    = wyl_fact_artifact_main_transition_dup_stage_name (live);
  g_autofree gchar *rollback
    = wyl_fact_artifact_main_transition_dup_rollback_name (live);
  g_assert_cmpstr (stage, ==, "restore-018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b"
      ".duckdb");
  g_assert_cmpstr (rollback, ==, "restore-018f1a2b-3c4d-7e5f-8a9b-"
      "0c1d2e3f4a5b.duckdb.superseded");
  wyl_fact_artifact_main_transition_free (live);
}

/* ------------------------------------------------------------------ */
/* T2 / T2b admission refusal matrix                                   */
/* ------------------------------------------------------------------ */

typedef struct
{
  const gchar *label;
  Refusal expected;
  void (*apply)(Observation *observation);
} ObservationRow;

static void row_unsealed (Observation *o) {
  o->sealed = FALSE;
}
static void row_live_binding (Observation *o) {
  o->main_binding_live = TRUE;
}
static void row_directory (Observation *o)
{
  o->directory_identity = identity (44);
}
static void row_lease (Observation *o) {
  o->lease_identity = identity (45);
}
static void row_stale (Observation *o)
{
  memcpy (o->operation_uuid, OTHER_BYTES, sizeof o->operation_uuid);
}
static void row_no_replace (Observation *o)
{
  o->no_replace_supported = FALSE;
}
static void row_reparse (Observation *o)
{
  o->entries[SLOT_STAGE].reparse = TRUE;
}
static void row_links (Observation *o) {
  o->entries[SLOT_STAGE].link_count
    = 2;
}
static void row_cross_device (Observation *o)
{
  o->entries[SLOT_STAGE].identity.domain = VOLUME_DOMAIN + 1;
}
static void row_foreign_stage (Observation *o)
{
  o->entries[SLOT_STAGE].identity = FOREIGN_IDENTITY;
}
static void row_foreign_main (Observation *o)
{
  o->entries[SLOT_MAIN].identity = FOREIGN_IDENTITY;
}
static void row_rollback_occupied (Observation *o)
{
  set_entry (o, SLOT_ROLLBACK, TRUE, EXPECTED_MAIN);
}
static void row_expected_main_missing (Observation *o)
{
  set_entry (o, SLOT_MAIN, FALSE, EXPECTED_MAIN);
}

static const ObservationRow OBSERVATION_ROWS[] = {
  { "unsealed", MT (REFUSAL_GRAPH_NOT_SEALED), row_unsealed },
  { "live-binding", MT (REFUSAL_LIVE_MAIN_BINDING), row_live_binding },
  { "directory", MT (REFUSAL_DIRECTORY_AUTHORITY), row_directory },
  { "lease", MT (REFUSAL_LEASE_AUTHORITY), row_lease },
  { "stale-operation", MT (REFUSAL_STALE_OPERATION), row_stale },
  { "no-replace", MT (REFUSAL_PRIMITIVE_UNSUPPORTED), row_no_replace },
  { "reparse", MT (REFUSAL_REPARSE), row_reparse },
  { "link-substitution", MT (REFUSAL_LINK_SUBSTITUTION), row_links },
  { "cross-device", MT (REFUSAL_CROSS_DEVICE), row_cross_device },
  { "foreign-stage", MT (REFUSAL_FOREIGN_STAGE), row_foreign_stage },
  { "foreign-main", MT (REFUSAL_FOREIGN_MAIN), row_foreign_main },
  { "rollback-occupied", MT (REFUSAL_ROLLBACK_NAME_OCCUPIED),
    row_rollback_occupied },
  { "expected-main-missing", MT (REFUSAL_EXPECTED_MAIN_MISSING),
    row_expected_main_missing },
};

static void
test_admission_refusal_matrix (void)
{
  Options options = { 0 };
  Observation base = observe (F_MAIN, TRUE, FALSE);
  Request request = make_request (&options);
  Result result;
  Transition *transition = NULL;
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot
    = snapshot_build (&base, NULL);

  /* NULL-argument rows are WYRELOG_E_INVALID, not POLICY. */
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (NULL, snapshot,
      &base, &result, &transition), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, NULL,
      &base, &result, &transition), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request,
      snapshot, NULL, &result, &transition), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request,
      snapshot, &base, NULL, &transition), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request,
      snapshot, &base, &result, NULL), ==, WYRELOG_E_INVALID);

  for (gsize index = 0; index < G_N_ELEMENTS (OBSERVATION_ROWS); index++) {
    Observation mutated = base;
    OBSERVATION_ROWS[index].apply (&mutated);
    g_assert_cmpint (admit_refusal (&options, &mutated, NULL), ==,
        OBSERVATION_ROWS[index].expected);
  }

  /* Every owner_state value, UNKNOWN included, because a zero-filled entry
   * must fail closed rather than read as conforming. */
  for (guint owner = 0; owner < MT (OWNER_STATE_COUNT); owner++) {
    Observation mutated = base;
    mutated.entries[SLOT_STAGE].owner_state = owner;
    if (owner == MT (OWNER_CONFORMING))
      continue;
    g_assert_cmpint (admit_refusal (&options, &mutated, NULL), ==,
        MT (REFUSAL_OWNERSHIP));
  }

  /* STAGE_IS_MAIN: identity equality alone suffices, because a hard link
   * shares the POSIX (device, inode) pair and the Windows FileId. */
  Request colliding = make_request (&options);
  colliding.staged_main_identity = EXPECTED_MAIN;
  Transition *refused = NULL;
  g_assert_cmpint (admit (&colliding, &base, NULL, &result, &refused), ==,
      WYRELOG_E_POLICY);
  g_assert_null (refused);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_STAGE_IS_MAIN));
}

static void
test_refusal_matrix_at_inspect_and_authorize (void)
{
  Options options = { 0 };
  Observation base = observe (F_MAIN, TRUE, FALSE);
  for (gsize index = 0; index < G_N_ELEMENTS (OBSERVATION_ROWS); index++) {
    Observation mutated = base;
    OBSERVATION_ROWS[index].apply (&mutated);
    Transition *transition = admit_ok (&options, &base);
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect (transition,
        &mutated, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result.refusal, ==, OBSERVATION_ROWS[index].expected);
    g_assert_cmpint (result.next_op, ==, MT (OP_NONE));
    g_assert_false (result.terminal);
    /* A re-validation refusal BLOCKS; it is not terminal. */
    g_assert_false (wyl_fact_artifact_main_transition_is_terminal
          (transition));
    g_assert_cmpint (authorize_refusal (transition, MT (OP_SYNC_STAGED),
        &mutated), ==, OBSERVATION_ROWS[index].expected);
    g_assert_false (wyl_fact_artifact_main_transition_is_terminal
          (transition));
    /* And a later conforming observation proceeds normally. */
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect (transition,
        &base, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==, MT (STATE_READY));
    wyl_fact_artifact_main_transition_free (transition);
  }
}

/* ------------------------------------------------------------------ */
/* T3 the inventory gate                                               */
/* ------------------------------------------------------------------ */

static void
test_inventory_gate (void)
{
  Options options = { 0 };
  Observation ready = observe (F_MAIN, TRUE, FALSE);
  Observation retained = observe (F_ABSENT, TRUE, TRUE);

  /* (a) STABLE_WITH_UNKNOWN with the stage counted once is the happy path. */
  Transition *transition = admit_ok (&options, &ready);
  wyl_fact_artifact_main_transition_free (transition);

  /* (b)/(c)/(d) EQUALITY, not <=: a stray gives 2 against 1. */
  SnapshotTweak stray = { .unknown_delta = 1 };
  g_assert_cmpint (admit_refusal (&options, &ready, &stray), ==,
      MT (REFUSAL_COLLISION_AMBIGUOUS));
  SnapshotTweak short_count = { .unknown_delta = -1 };
  g_assert_cmpint (admit_refusal (&options, &ready, &short_count), ==,
      MT (REFUSAL_COLLISION_AMBIGUOUS));
  SnapshotTweak malformed = { .malformed = 1 };
  g_assert_cmpint (admit_refusal (&options, &ready, &malformed), ==,
      MT (REFUSAL_INVENTORY_ANOMALOUS));

  /* The RETAINED triple carries two unknown entries, not one or three. */
  Transition *retained_transition = admit_ok (&options, &retained);
  wyl_fact_artifact_main_transition_free (retained_transition);
  g_assert_cmpint (admit_refusal (&options, &retained, &stray), ==,
      MT (REFUSAL_COLLISION_AMBIGUOUS));
  g_assert_cmpint (admit_refusal (&options, &retained, &short_count), ==,
      MT (REFUSAL_COLLISION_AMBIGUOUS));

  /* (e) the lock is present by construction on any leased graph directory. */
  SnapshotTweak lock = { .lock_absent = TRUE };
  g_assert_cmpint (admit_refusal (&options, &ready, &lock), ==,
      MT (REFUSAL_LOCK_MISSING));
  /* (f) sidecars must have converged before a restore may proceed. */
  SnapshotTweak wal = { .wal_present = TRUE };
  g_assert_cmpint (admit_refusal (&options, &ready, &wal), ==,
      MT (REFUSAL_SIDECAR_UNCONVERGED));
  /* (d) the snapshot MAIN slot must agree with the observed triple. */
  SnapshotTweak main_absent = { .main_absent = TRUE };
  g_assert_cmpint (admit_refusal (&options, &ready, &main_absent), ==,
      MT (REFUSAL_EXPECTED_MAIN_MISSING));
  SnapshotTweak main_foreign = { .main_foreign = TRUE };
  g_assert_cmpint (admit_refusal (&options, &ready, &main_foreign), ==,
      MT (REFUSAL_FOREIGN_MAIN));
  g_assert_cmpint (admit_refusal (&options, &retained, &main_foreign), ==,
      MT (REFUSAL_FOREIGN_MAIN));
  /* (g) directory_identity equality is the only DIRECT binding proof. */
  SnapshotTweak unbound = { .unbound = TRUE };
  g_assert_cmpint (admit_refusal (&options, &ready, &unbound), ==,
      MT (REFUSAL_INVENTORY_UNBOUND));
  /* (a) an unstable snapshot publishes nothing at all. */
  SnapshotTweak unstable = { .unstable = TRUE };
  g_assert_cmpint (admit_refusal (&options, &ready, &unstable), ==,
      MT (REFUSAL_INVENTORY_UNSTABLE));
}

/* ------------------------------------------------------------------ */
/* T4 legal-transition tables                                          */
/* ------------------------------------------------------------------ */

static const Op AUTHORIZABLE_OPS[] = {
  MT (OP_SYNC_STAGED), MT (OP_RETAIN), MT (OP_SYNC_ROLLBACK_FILE),
  MT (OP_SYNC_RETAIN_DIR), MT (OP_PUBLISH), MT (OP_SYNC_PUBLISH_DIR),
  MT (OP_ROLLBACK), MT (OP_RETIRE_STAGE), MT (OP_FINALIZE),
};

typedef struct
{
  State state;
  Refusal expected[G_N_ELEMENTS (AUTHORIZABLE_OPS)];
} TableRow;

#define ILLEGAL  MT (REFUSAL_ILLEGAL_TRANSITION)
#define TERMINAL MT (REFUSAL_TERMINAL)
#define UNPROVEN MT (REFUSAL_DURABILITY_UNPROVEN)

/* Table A: rollback_required mode, all 8 drivable states by all 9 ops. */
static const TableRow TABLE_A[] = {
  { MT (STATE_READY),
    { AUTHORIZED, AUTHORIZED, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL,
      ILLEGAL, ILLEGAL } },
  { MT (STATE_RETAINED),
    { AUTHORIZED, ILLEGAL, AUTHORIZED, AUTHORIZED, AUTHORIZED, ILLEGAL,
      AUTHORIZED, ILLEGAL, ILLEGAL } },
  { MT (STATE_RETAINED_STAGE_LOST),
    { ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, AUTHORIZED,
      ILLEGAL, ILLEGAL } },
  { MT (STATE_PUBLISHED),
    { ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, AUTHORIZED, AUTHORIZED,
      ILLEGAL, UNPROVEN } },
  { MT (STATE_PUBLISHED_DURABLE),
    { ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, AUTHORIZED,
      ILLEGAL, AUTHORIZED } },
  { MT (STATE_FINALIZED),
    { TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL,
      TERMINAL, TERMINAL } },
  { MT (STATE_ROLLED_BACK),
    { ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL,
      AUTHORIZED, ILLEGAL } },
  { MT (STATE_ABANDONED),
    { TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL,
      TERMINAL, TERMINAL } },
};

/* Table B: expected_main_absent mode.  ABANDONED is drivable here through the
 * resume_forbidden cleanup edge, which is mode B's ONLY cleanup path. */
static const TableRow TABLE_B[] = {
  { MT (STATE_READY),
    { AUTHORIZED, ILLEGAL, ILLEGAL, ILLEGAL, AUTHORIZED, ILLEGAL, ILLEGAL,
      ILLEGAL, ILLEGAL } },
  { MT (STATE_PUBLISHED),
    { ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, AUTHORIZED, ILLEGAL,
      ILLEGAL, UNPROVEN } },
  { MT (STATE_PUBLISHED_DURABLE),
    { ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL, ILLEGAL,
      AUTHORIZED } },
  { MT (STATE_FINALIZED),
    { TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL,
      TERMINAL, TERMINAL } },
  { MT (STATE_ABANDONED),
    { TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL, TERMINAL,
      TERMINAL, TERMINAL } },
};

static void
walk_table (const TableRow *rows, gsize row_count, gboolean mode_b)
{
  for (gsize row = 0; row < row_count; row++) {
    for (gsize column = 0; column < G_N_ELEMENTS (AUTHORIZABLE_OPS);
        column++) {
      Options options = {
        .mode_b = mode_b,
        /* Mode B enters ABANDONED only through the resume_forbidden cleanup
         * edge; every other state is driven without the flag. */
        .resume_forbidden = mode_b && rows[row].state == MT (STATE_ABANDONED),
      };
      g_assert_cmpint (gate_at (rows[row].state, &options,
          AUTHORIZABLE_OPS[column]), ==, rows[row].expected[column]);
    }
  }
}

static void
test_legal_transition_tables (void)
{
  walk_table (TABLE_A, G_N_ELEMENTS (TABLE_A), FALSE);
  walk_table (TABLE_B, G_N_ELEMENTS (TABLE_B), TRUE);
}

/*
 * The three mode-B states that cannot be driven, because mode B cannot enter
 * them at all: feed the observation whose shape would define each and assert
 * the shape refusal at admission, at inspect and at authorize.
 */
static void
test_mode_b_undrivable_shapes (void)
{
  Options options = { .mode_b = TRUE };
  Observation ready = observe (F_ABSENT, TRUE, FALSE);
  Observation retained = observe (F_ABSENT, TRUE, TRUE);
  Observation stage_lost = observe (F_ABSENT, FALSE, TRUE);
  Observation rolled_back = observe (F_FOREIGN, TRUE, FALSE);
  const struct
  {
    const Observation *shape;
    Refusal expected;
  } shapes[] = {
    { &retained, MT (REFUSAL_ROLLBACK_NAME_OCCUPIED) },
    { &stage_lost, MT (REFUSAL_ROLLBACK_NAME_OCCUPIED) },
    { &rolled_back, MT (REFUSAL_NO_MAIN_ARTIFACT) },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (shapes); index++) {
    g_assert_cmpint (admit_refusal (&options, shapes[index].shape, NULL), ==,
        shapes[index].expected);
    Transition *transition = admit_ok (&options, &ready);
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect (transition,
        shapes[index].shape, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result.refusal, ==, shapes[index].expected);
    g_assert_cmpint (authorize_refusal (transition, MT (OP_PUBLISH),
        shapes[index].shape), ==, shapes[index].expected);
    wyl_fact_artifact_main_transition_free (transition);
  }
}

static void
test_non_authorizable_ops (void)
{
  static const State states[] = {
    MT (STATE_READY), MT (STATE_RETAINED), MT (STATE_PUBLISHED),
    MT (STATE_PUBLISHED_DURABLE), MT (STATE_FINALIZED),
    MT (STATE_ROLLED_BACK), MT (STATE_ABANDONED),
  };
  Options options = { 0 };
  for (gsize index = 0; index < G_N_ELEMENTS (states); index++) {
    Drive drive = drive_to (states[index], &options);
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
          (drive.transition, MT (OP_INSPECT), &drive.observation, &result),
        ==, WYRELOG_E_INVALID);
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
          (drive.transition, MT (OP_NONE), &drive.observation, &result), ==,
        WYRELOG_E_INVALID);
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
          (drive.transition, MT (OP_COUNT), &drive.observation, &result), ==,
        WYRELOG_E_INVALID);
    drive_clear (&drive);
  }
}

/*
 * The load-bearing cells, asserted by enumerator rather than merely by
 * refusal.  The mode-B PUBLISH row is THE DEADLOCK GUARD: if an implementer
 * hoists mode A's ordering conjunct into a shared helper, mode B can never
 * publish and this is the only assertion that catches it.
 */
static void
test_load_bearing_cells (void)
{
  Options mode_a = { 0 };
  Options mode_b = { .mode_b = TRUE };

  /* Mode A: RETAINED --PUBLISH--> with directory_after_retain UNPROVEN. */
  Drive retained = drive_to (MT (STATE_READY), &mode_a);
  mutate (&retained, MT (OP_RETAIN), observe (F_ABSENT, TRUE, TRUE));
  latch_seam (&retained, MT (OP_SYNC_ROLLBACK_FILE), MT (DURABILITY_PROVEN));
  g_assert_cmpint (authorize_refusal (retained.transition, MT (OP_PUBLISH),
      &retained.observation), ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  drive_clear (&retained);

  /* Mode B: READY --PUBLISH--> with directory_after_retain UNPROVEN is
   * AUTHORIZED, because that seam is not consulted here at all. */
  Drive ready = drive_to (MT (STATE_READY), &mode_b);
  /* Mode B cannot latch that seam at all: the recording op is unreachable
   * there, which is why the applicability rule can require it UNPROVEN. */
  g_assert_cmpint (gate_at (MT (STATE_READY), &mode_b,
      MT (OP_SYNC_RETAIN_DIR)), ==, ILLEGAL);
  g_assert_cmpint (authorize_refusal (ready.transition, MT (OP_RETAIN),
      &ready.observation), ==, ILLEGAL);
  g_assert_cmpint (authorize_refusal (ready.transition, MT (OP_PUBLISH),
      &ready.observation), ==, AUTHORIZED);
  drive_clear (&ready);

  /* PUBLISHED --FINALIZE--> with directory_after_publish UNPROVEN is
   * DURABILITY_UNPROVEN, NOT DURABILITY_ACK_REQUIRED: an acknowledgement is
   * meaningless for a recoverable seam. */
  g_assert_cmpint (gate_at (MT (STATE_PUBLISHED), &mode_a, MT (OP_FINALIZE)),
      ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  g_assert_cmpint (gate_at (MT (STATE_PUBLISHED), &mode_b, MT (OP_FINALIZE)),
      ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  g_assert_cmpint (gate_at (MT (STATE_PUBLISHED), &mode_b, MT (OP_ROLLBACK)),
      ==, ILLEGAL);
}

/* ------------------------------------------------------------------ */
/* T5 durability seams                                                 */
/* ------------------------------------------------------------------ */

static void
test_file_seams_gate_forward_progress (void)
{
  Options options = { 0 };
  Observation ready = observe (F_MAIN, TRUE, FALSE);

  /* staged_file unlatched: RETAIN refuses. */
  Transition *transition = admit_ok (&options, &ready);
  g_assert_cmpint (authorize_refusal (transition, MT (OP_RETAIN), &ready), ==,
      MT (REFUSAL_DURABILITY_UNPROVEN));
  wyl_fact_artifact_main_transition_free (transition);

  /* Mode B PUBLISH is gated by the same file seam. */
  Options mode_b = { .mode_b = TRUE };
  Observation mode_b_ready = observe (F_ABSENT, TRUE, FALSE);
  Transition *published = admit_ok (&mode_b, &mode_b_ready);
  g_assert_cmpint (authorize_refusal (published, MT (OP_PUBLISH),
      &mode_b_ready), ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  wyl_fact_artifact_main_transition_free (published);

  /* rollback_file unlatched: mode-A PUBLISH refuses even with the two other
   * seams satisfied. */
  Drive drive = drive_to (MT (STATE_READY), &options);
  mutate (&drive, MT (OP_RETAIN), observe (F_ABSENT, TRUE, TRUE));
  latch_seam (&drive, MT (OP_SYNC_RETAIN_DIR), MT (DURABILITY_PROVEN));
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_PUBLISH),
      &drive.observation), ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  latch_seam (&drive, MT (OP_SYNC_ROLLBACK_FILE), MT (DURABILITY_PROVEN));
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_PUBLISH),
      &drive.observation), ==, AUTHORIZED);
  drive_clear (&drive);

  /* Only directory seams may report UNSUPPORTED.  A file seam reporting it is
   * itself a refusal, and the latch is not set. */
  Drive file_seam = { .observation = ready };
  file_seam.transition = admit_ok (&options, &ready);
  Result result;
  Observation unsupported = with_seam (&file_seam.observation,
          MT (OP_SYNC_STAGED), MT (DURABILITY_UNSUPPORTED));
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (file_seam.transition, MT (OP_SYNC_STAGED), &file_seam.observation,
      &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record
        (file_seam.transition, MT (OP_SYNC_STAGED), MT (EFFECT_APPLIED),
      &unsupported, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_DURABILITY_UNSUPPORTED));
  g_assert_cmpint (authorize_refusal (file_seam.transition, MT (OP_RETAIN),
      &file_seam.observation), ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  drive_clear (&file_seam);
}

static void
test_mode_a_ordering_barrier (void)
{
  Options options = { 0 };
  static const Durability values[] = {
    MT (DURABILITY_UNPROVEN), MT (DURABILITY_UNSUPPORTED),
    MT (DURABILITY_PROVEN),
  };
  static const Refusal expected[] = {
    MT (REFUSAL_DURABILITY_UNPROVEN), AUTHORIZED, AUTHORIZED,
  };
  for (gsize index = 0; index < G_N_ELEMENTS (values); index++) {
    Drive drive = drive_to (MT (STATE_READY), &options);
    /* With the barrier unset, RETAIN has already happened and ROLLBACK is
     * still available, so RETAINED stays an INTERVAL rather than a resting
     * state on every filesystem. */
    mutate (&drive, MT (OP_RETAIN), observe (F_ABSENT, TRUE, TRUE));
    latch_seam (&drive, MT (OP_SYNC_ROLLBACK_FILE), MT (DURABILITY_PROVEN));
    if (values[index] != MT (DURABILITY_UNPROVEN))
      latch_seam (&drive, MT (OP_SYNC_RETAIN_DIR), values[index]);
    g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_ROLLBACK),
        &drive.observation), ==, AUTHORIZED);
    Transition *fresh = drive.transition;
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect (fresh,
        &drive.observation, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_PUBLISH),
        &drive.observation), ==, expected[index]);
    drive_clear (&drive);
  }
}

static void
test_finalize_is_gated_by_publish_dir_alone (void)
{
  /* directory_after_retain UNSUPPORTED with directory_after_publish PROVEN
   * finalizes with NO acknowledgement required: one fsync of a directory
   * persists every pending entry change in it. */
  Options options = { .ack = FALSE };
  Drive drive = drive_to (MT (STATE_READY), &options);
  mutate (&drive, MT (OP_RETAIN), observe (F_ABSENT, TRUE, TRUE));
  latch_seam (&drive, MT (OP_SYNC_ROLLBACK_FILE), MT (DURABILITY_PROVEN));
  latch_seam (&drive, MT (OP_SYNC_RETAIN_DIR), MT (DURABILITY_UNSUPPORTED));
  mutate (&drive, MT (OP_PUBLISH), observe (F_STAGE, FALSE, TRUE));
  latch_seam (&drive, MT (OP_SYNC_PUBLISH_DIR), MT (DURABILITY_PROVEN));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (drive.transition),
      ==, MT (STATE_PUBLISHED_DURABLE));
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_FINALIZE),
      &drive.observation), ==, AUTHORIZED);
  drive_clear (&drive);
}

static void
test_latching_within_an_epoch (void)
{
  Options options = { 0 };
  Drive drive = drive_to (MT (STATE_RETAINED), &options);

  /* A seam PROVEN by an earlier record stays PROVEN when a later observation
   * reports it UNPROVEN, and the dependent op is still authorized. */
  Observation regressed = drive.observation;
  regressed.durability.staged_file = MT (DURABILITY_UNPROVEN);
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_PUBLISH),
      &regressed), ==, AUTHORIZED);
  drive_clear (&drive);

  /* UNSUPPORTED is not absorbing: a seam latched UNSUPPORTED and later
   * recorded PROVEN is PROVEN, and PUBLISHED_DURABLE becomes reachable. */
  Drive published = drive_to (MT (STATE_PUBLISHED), &options);
  latch_seam (&published, MT (OP_SYNC_PUBLISH_DIR),
      MT (DURABILITY_UNSUPPORTED));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (published.transition), ==, MT (STATE_PUBLISHED));
  latch_seam (&published, MT (OP_SYNC_PUBLISH_DIR), MT (DURABILITY_PROVEN));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (published.transition), ==, MT (STATE_PUBLISHED_DURABLE));

  /* PROVEN then REPORTED UNSUPPORTED: authorize reads the latch and never the
   * observation, so the state does not regress and FINALIZE stays open. */
  Observation downgraded = published.observation;
  downgraded.durability.directory_after_publish = MT (DURABILITY_UNSUPPORTED);
  Result result;
  g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
        (published.transition, &downgraded, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_PUBLISHED_DURABLE));
  g_assert_cmpint (authorize_refusal (published.transition, MT (OP_FINALIZE),
      &downgraded), ==, AUTHORIZED);
  drive_clear (&published);

  /* The same lattice row at the RECORD layer, which the publish-dir seam
   * cannot express: SYNC_PUBLISH_DIR is legal only from PUBLISHED, so once
   * PUBLISHED_DURABLE is entered no second value can be recorded for it.
   * SYNC_RETAIN_DIR is legal repeatedly from RETAINED, so the merge is
   * observable there -- a latched PROVEN is not overwritten by a later
   * UNSUPPORTED and the dependent op stays authorized. */
  Drive retain_dir = drive_to (MT (STATE_RETAINED), &options);
  latch_seam (&retain_dir, MT (OP_SYNC_RETAIN_DIR), MT (DURABILITY_PROVEN));
  latch_seam (&retain_dir, MT (OP_SYNC_RETAIN_DIR),
      MT (DURABILITY_UNSUPPORTED));
  /*
   * AUTHORIZED ALONE CANNOT FAIL HERE, so it is not the assertion.  Mode-A
   * PUBLISH's retain-dir conjunct refuses only UNPROVEN -- UNSUPPORTED passes
   * by design, which test_mode_a_ordering_barrier asserts as a deliberate
   * contract property -- so the outcome is identical whether the merge
   * preserved PROVEN or let UNSUPPORTED overwrite it.  The discriminating
   * value is the LATCH, and gate_op assigns the retain-dir latch to
   * out_durability last, so result.durability here IS that latch: PROVEN
   * under the absorbing rule, UNSUPPORTED under the defect.
   */
  Result publish;
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (retain_dir.transition, MT (OP_PUBLISH), &retain_dir.observation,
      &publish), ==, WYRELOG_E_OK);
  g_assert_cmpint (publish.durability, ==, MT (DURABILITY_PROVEN));
  drive_clear (&retain_dir);
}

/*
 * The epoch boundary.  Without it a receipt outlives the directory it
 * describes, and FINALIZE -- the irreversible unlink of the rollback link --
 * is authorized while the second publish is only page-cache-visible.
 */
static void
test_directory_epoch_boundary (void)
{
  Options options = { 0 };
  Drive drive = drive_to (MT (STATE_PUBLISHED_DURABLE), &options);
  mutate (&drive, MT (OP_ROLLBACK), observe (F_ABSENT, TRUE, TRUE));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (drive.transition),
      ==, MT (STATE_RETAINED));

  /* The FILE seams survive the two renames: they attest inode data, which a
   * rename does not change, so PUBLISH needs no second fsync of either. */
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_PUBLISH),
      &drive.observation), ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  latch_seam (&drive, MT (OP_SYNC_RETAIN_DIR), MT (DURABILITY_PROVEN));
  mutate (&drive, MT (OP_PUBLISH), observe (F_STAGE, FALSE, TRUE));

  /* The DIRECTORY receipt taken before those two mutations is gone. */
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_FINALIZE),
      &drive.observation), ==, MT (REFUSAL_DURABILITY_UNPROVEN));
  latch_seam (&drive, MT (OP_SYNC_PUBLISH_DIR), MT (DURABILITY_PROVEN));
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_FINALIZE),
      &drive.observation), ==, AUTHORIZED);
  drive_clear (&drive);
}

/* ------------------------------------------------------------------ */
/* T5b the bounded exit                                                */
/* ------------------------------------------------------------------ */

static Drive
drive_to_unsupported_publish (const Options *options)
{
  Drive drive = drive_to (MT (STATE_PUBLISHED), options);
  latch_seam (&drive, MT (OP_SYNC_PUBLISH_DIR), MT (DURABILITY_UNSUPPORTED));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (drive.transition),
      ==, MT (STATE_PUBLISHED));
  return drive;
}

static void
test_bounded_exit (void)
{
  Options without_ack = { 0 };
  Options with_ack = { .ack = TRUE };

  /* (a) the acknowledgement is necessary. */
  Drive unacknowledged = drive_to_unsupported_publish (&without_ack);
  g_assert_cmpint (authorize_refusal (unacknowledged.transition,
      MT (OP_FINALIZE), &unacknowledged.observation), ==,
      MT (REFUSAL_DURABILITY_ACK_REQUIRED));
  drive_clear (&unacknowledged);

  /* (b) with it, FINALIZE lands FINALIZED and the rollback link is retired. */
  Drive acknowledged = drive_to_unsupported_publish (&with_ack);
  mutate (&acknowledged, MT (OP_FINALIZE), observe (F_STAGE, FALSE, FALSE));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (acknowledged.transition), ==, MT (STATE_FINALIZED));
  g_assert_true (wyl_fact_artifact_main_transition_is_terminal
        (acknowledged.transition));

  /* (e) a new operation can admit against the namespace that leaves. */
  Observation after = acknowledged.observation;
  Request fresh = make_request (&without_ack);
  fresh.operation_uuid = OTHER_UUID;
  fresh.expected_main_identity = STAGED_MAIN;
  fresh.staged_main_identity = identity (555);
  memcpy (after.operation_uuid, OTHER_BYTES, sizeof after.operation_uuid);
  set_entry (&after, SLOT_STAGE, TRUE, identity (555));
  Result result;
  Transition *next = NULL;
  g_assert_cmpint (admit (&fresh, &after, NULL, &result, &next), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  wyl_fact_artifact_main_transition_free (next);
  drive_clear (&acknowledged);

  /* (c) the acknowledgement is not sufficient: UNPROVEN is the recoverable
   * case and must be retried, never acknowledged. */
  g_assert_cmpint (gate_at (MT (STATE_PUBLISHED), &with_ack,
      MT (OP_FINALIZE)), ==, MT (REFUSAL_DURABILITY_UNPROVEN));

  /* (d) a mode-B receipt for a referent-less seam is a caller wiring bug and
   * refuses in kind, not as a durability state. */
  Options mode_b = { .mode_b = TRUE, .ack = TRUE };
  Drive published = drive_to (MT (STATE_PUBLISHED), &mode_b);
  Observation misreported = published.observation;
  misreported.durability.directory_after_retain = MT (DURABILITY_PROVEN);
  g_assert_cmpint (authorize_refusal (published.transition, MT (OP_FINALIZE),
      &misreported), ==, MT (REFUSAL_SEAM_NOT_APPLICABLE));
  /* rollback_file is equally referent-less in mode B and covered by the same
   * rule; the latch is unreachable there, which makes the rule cheap rather
   * than unnecessary. */
  misreported = published.observation;
  misreported.durability.rollback_file = MT (DURABILITY_PROVEN);
  g_assert_cmpint (authorize_refusal (published.transition, MT (OP_FINALIZE),
      &misreported), ==, MT (REFUSAL_SEAM_NOT_APPLICABLE));
  drive_clear (&published);
}

/* ------------------------------------------------------------------ */
/* T5d seam reachability                                               */
/* ------------------------------------------------------------------ */

/*
 * The invariant, not a single edge: for every gate "op X requires seam S
 * PROVEN", S's recording op must be legal from every state from which X is
 * legal, unless that state is unreachable without S already latched.  Written
 * as a loop so that adding a fifth seam without its recording op fails here.
 */
static void
test_seam_reachability (void)
{
  static const Op PUBLISH_SEAM_OPS[] = {
    MT (OP_SYNC_STAGED), MT (OP_SYNC_ROLLBACK_FILE), MT (OP_SYNC_RETAIN_DIR),
  };
  Options options = { 0 };
  /* A restart clears every latch, and a fresh admit on the RETAINED triple is
   * exactly what a restarted backend performs. */
  Observation retained = observe (F_ABSENT, TRUE, TRUE);
  Drive drive = { .observation = retained };
  drive.transition = admit_ok (&options, &retained);
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (drive.transition),
      ==, MT (STATE_RETAINED));

  for (gsize index = 0; index < G_N_ELEMENTS (PUBLISH_SEAM_OPS); index++) {
    g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_PUBLISH),
        &drive.observation), ==, MT (REFUSAL_DURABILITY_UNPROVEN));
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
          (drive.transition, &drive.observation, &result), ==, WYRELOG_E_OK);
    latch_seam (&drive, PUBLISH_SEAM_OPS[index], MT (DURABILITY_PROVEN));
    /* Every recording op returns to RETAINED without leaving it. */
    g_assert_cmpint (wyl_fact_artifact_main_transition_state
          (drive.transition), ==, MT (STATE_RETAINED));
  }
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_PUBLISH),
      &drive.observation), ==, AUTHORIZED);
  drive_clear (&drive);

  /* There is no stage to fsync in RETAINED_STAGE_LOST, so the edge is
   * deliberately absent there. */
  g_assert_cmpint (gate_at (MT (STATE_RETAINED_STAGE_LOST), &options,
      MT (OP_SYNC_STAGED)), ==, ILLEGAL);

  /* The escape-clause case, exercised rather than assumed: PUBLISHED_DURABLE
   * cannot be entered with directory_after_publish unlatched, so the gate
   * that consults it from there is never a dead end. */
  Drive published = drive_to (MT (STATE_PUBLISHED), &options);
  latch_seam (&published, MT (OP_SYNC_PUBLISH_DIR),
      MT (DURABILITY_UNSUPPORTED));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (published.transition), ==, MT (STATE_PUBLISHED));
  latch_seam (&published, MT (OP_SYNC_PUBLISH_DIR), MT (DURABILITY_PROVEN));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (published.transition), ==, MT (STATE_PUBLISHED_DURABLE));
  drive_clear (&published);
}

/* ------------------------------------------------------------------ */
/* T6 convergence and restart                                          */
/* ------------------------------------------------------------------ */

static void
test_convergence_and_restart (void)
{
  static const State states[] = {
    MT (STATE_READY), MT (STATE_RETAINED), MT (STATE_RETAINED_STAGE_LOST),
    MT (STATE_PUBLISHED), MT (STATE_PUBLISHED_DURABLE),
    MT (STATE_FINALIZED), MT (STATE_ROLLED_BACK), MT (STATE_ABANDONED),
  };
  Options options = { 0 };
  for (gsize index = 0; index < G_N_ELEMENTS (states); index++) {
    Drive drive = drive_to (states[index], &options);
    Result first;
    Result again;
    Result third;
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
          (drive.transition, &drive.observation, &first), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
          (drive.transition, &drive.observation, &again), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
          (drive.transition, &drive.observation, &third), ==, WYRELOG_E_OK);
    g_assert_cmpint (first.state, ==, states[index]);
    g_assert_cmpint (again.state, ==, first.state);
    g_assert_cmpint (third.state, ==, first.state);
    g_assert_cmpint (again.next_op, ==, first.next_op);
    g_assert_cmpint (third.next_op, ==, first.next_op);
    g_assert_cmpint (again.refusal, ==, first.refusal);
    g_assert_cmpint (again.terminal, ==, first.terminal);

    /*
     * The fresh-admit half applies to SIX states, not eight.  ROLLED_BACK's
     * triple is byte-identical to READY's, and PUBLISHED_DURABLE is
     * distinguished from PUBLISHED only by a latch that does not survive a
     * restart.  Both exclusions are the same cause: the distinguishing
     * evidence is IN-PROCESS, not in the triple.  Asserting the exclusion is
     * what keeps admit from reading observation durability, which is the
     * Observation-read design the latch model exists to remove.
     */
    State expected = states[index];
    if (expected == MT (STATE_ROLLED_BACK))
      expected = MT (STATE_READY);
    if (expected == MT (STATE_PUBLISHED_DURABLE))
      expected = MT (STATE_PUBLISHED);
    Transition *restarted = admit_ok (&options, &drive.observation);
    g_assert_cmpint (wyl_fact_artifact_main_transition_state (restarted), ==,
        expected);
    wyl_fact_artifact_main_transition_free (restarted);
    drive_clear (&drive);
  }

  /*
   * A fresh admit takes both identities from the Request, so a STALE
   * expected_main_identity on an ABANDONED-shaped triple is caught by
   * admission's F.identity comparison, NOT by STAGE_IS_MAIN -- which still
   * passes here, because the two declared identities do differ.
   */
  Options stale_options = { 0 };
  Observation abandoned = observe (F_MAIN, FALSE, FALSE);
  Request stale = make_request (&stale_options);
  stale.expected_main_identity = identity (999);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&stale, &abandoned, NULL, &result, &transition), ==,
      WYRELOG_E_POLICY);
  g_assert_null (transition);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_FOREIGN_MAIN));
  g_assert_false (wyl_fact_artifact_inventory_identity_equal
        (&stale.expected_main_identity, &stale.staged_main_identity));
}

/* ------------------------------------------------------------------ */
/* T7 record semantics                                                 */
/* ------------------------------------------------------------------ */

static void
test_record_effect_shape_matrix (void)
{
  Options options = { 0 };
  Observation pre = observe (F_MAIN, TRUE, FALSE);
  Observation post = observe (F_ABSENT, TRUE, TRUE);
  Observation third = observe (F_MAIN, FALSE, FALSE);
  const struct
  {
    Effect effect;
    const Observation *shape;
    wyrelog_error_t status;
    State state;
    gboolean terminal;
  } rows[] = {
    { MT (EFFECT_APPLIED), &post, WYRELOG_E_OK, MT (STATE_RETAINED), FALSE },
    { MT (EFFECT_APPLIED), &pre, WYRELOG_E_OK, MT (STATE_READY), FALSE },
    { MT (EFFECT_UNKNOWN), &post, WYRELOG_E_OK, MT (STATE_RETAINED), FALSE },
    { MT (EFFECT_UNKNOWN), &pre, WYRELOG_E_OK, MT (STATE_READY), FALSE },
    { MT (EFFECT_NOT_APPLIED), &pre, WYRELOG_E_OK, MT (STATE_READY), FALSE },
    /* Adjacent to the row above so the asymmetry reads as deliberate: either
     * the backend owed us UNKNOWN or a third party produced that shape. */
    { MT (EFFECT_NOT_APPLIED), &post, WYRELOG_E_POLICY, MT (STATE_READY),
      TRUE },
    { MT (EFFECT_APPLIED), &third, WYRELOG_E_POLICY, MT (STATE_READY), TRUE },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (rows); index++) {
    Drive drive = drive_to (MT (STATE_READY), &options);
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
          (drive.transition, MT (OP_RETAIN), &drive.observation, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_main_transition_record
          (drive.transition, MT (OP_RETAIN), rows[index].effect,
        rows[index].shape, &result), ==, rows[index].status);
    g_assert_cmpint (result.state, ==, rows[index].state);
    g_assert_cmpint (result.terminal, ==, rows[index].terminal);
    if (rows[index].status == WYRELOG_E_POLICY)
      g_assert_cmpint (result.refusal, ==,
          MT (REFUSAL_COLLISION_AMBIGUOUS));
    else if (rows[index].state == MT (STATE_READY))
      /* A FAILED mutation leaves the same op re-authorizable. */
      g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_RETAIN),
          &drive.observation), ==, AUTHORIZED);
    drive_clear (&drive);
  }
}

static void
test_record_post_conditions (void)
{
  Options options = { 0 };
  Result result;

  /* record(FINALIZE) is not satisfied by the rollback link being absent: the
   * main artifact must hold the staged identity too. */
  Drive finalize = drive_to (MT (STATE_PUBLISHED_DURABLE), &options);
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (finalize.transition, MT (OP_FINALIZE), &finalize.observation,
      &result), ==, WYRELOG_E_OK);
  Observation wrong = observe (F_MAIN, FALSE, FALSE);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record
        (finalize.transition, MT (OP_FINALIZE), MT (EFFECT_APPLIED), &wrong,
      &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_COLLISION_AMBIGUOUS));
  drive_clear (&finalize);

  /* record(RETIRE_STAGE) is mode-parameterized on the main slot, so mode B's
   * (0,0,0) post is ACCEPTED rather than falling through to a third shape. */
  Options mode_b = { .mode_b = TRUE, .resume_forbidden = TRUE };
  Drive cleanup = drive_to (MT (STATE_READY), &mode_b);
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (cleanup.transition, MT (OP_RETIRE_STAGE), &cleanup.observation,
      &result), ==, WYRELOG_E_OK);
  Observation empty = observe (F_ABSENT, FALSE, FALSE);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record
        (cleanup.transition, MT (OP_RETIRE_STAGE), MT (EFFECT_APPLIED),
      &empty, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_ABANDONED));
  g_assert_true (result.terminal);
  drive_clear (&cleanup);

  /* record(RETAIN) requires both destinations to hold the exact identities,
   * never merely that the main name is gone. */
  Drive retain = drive_to (MT (STATE_READY), &options);
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (retain.transition, MT (OP_RETAIN), &retain.observation, &result), ==,
      WYRELOG_E_OK);
  Observation half = observe (F_ABSENT, TRUE, TRUE);
  half.entries[SLOT_ROLLBACK].identity = FOREIGN_IDENTITY;
  g_assert_cmpint (wyl_fact_artifact_main_transition_record
        (retain.transition, MT (OP_RETAIN), MT (EFFECT_APPLIED), &half,
      &result), ==, WYRELOG_E_POLICY);
  drive_clear (&retain);
}

/* ------------------------------------------------------------------ */
/* T8 the pairing interlock                                            */
/* ------------------------------------------------------------------ */

static void
test_pairing_interlock (void)
{
  Options options = { 0 };
  Result result;
  Drive drive = drive_to (MT (STATE_READY), &options);
  Observation post = observe (F_ABSENT, TRUE, TRUE);

  g_assert_cmpint (wyl_fact_artifact_main_transition_record (drive.transition,
      MT (OP_RETAIN), MT (EFFECT_APPLIED), &post, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_NO_PENDING_MUTATION));

  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (drive.transition, MT (OP_RETAIN), &drive.observation, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (authorize_refusal (drive.transition, MT (OP_SYNC_STAGED),
      &drive.observation), ==, MT (REFUSAL_PENDING_MUTATION));
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (drive.transition,
      MT (OP_SYNC_STAGED), MT (EFFECT_APPLIED), &drive.observation, &result),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_NO_PENDING_MUTATION));
  /* A mismatched record is a caller error and must not silently cancel the
   * standing authorization: the authorized op is still recordable. */
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (drive.transition,
      MT (OP_RETAIN), MT (EFFECT_APPLIED), &post, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));
  drive_clear (&drive);

  /* Inspect is the load-bearing invalidation. */
  drive = drive_to (MT (STATE_READY), &options);
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (drive.transition, MT (OP_RETAIN), &drive.observation, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
        (drive.transition, &drive.observation, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (drive.transition,
      MT (OP_RETAIN), MT (EFFECT_APPLIED), &post, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_NO_PENDING_MUTATION));
  drive_clear (&drive);

  /* ROLLBACK is two ops, not one: each is separately authorized and
   * separately recorded. */
  Drive published = drive_to (MT (STATE_PUBLISHED), &options);
  mutate (&published, MT (OP_ROLLBACK), observe (F_ABSENT, TRUE, TRUE));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (published.transition), ==, MT (STATE_RETAINED));
  g_assert_cmpint (wyl_fact_artifact_main_transition_record
        (published.transition, MT (OP_ROLLBACK), MT (EFFECT_APPLIED),
      &published.observation, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_NO_PENDING_MUTATION));
  mutate (&published, MT (OP_ROLLBACK), observe (F_MAIN, TRUE, FALSE));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (published.transition), ==, MT (STATE_ROLLED_BACK));
  drive_clear (&published);

  /*
   * A BLOCKING RE-VALIDATION REFUSAL AT record MUST NOT BURN THE
   * AUTHORIZATION.  The refusal is not terminal and the backend may already
   * have performed the mutation, so clearing the authorization before
   * re-validating would leave it holding a landed rename with no way to
   * record it.  Divergence if the clears sit above the re-validation: the
   * second record below returns NO_PENDING_MUTATION instead of advancing.
   */
  Drive kept = drive_to (MT (STATE_READY), &options);
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (kept.transition, MT (OP_RETAIN), &kept.observation, &result), ==,
      WYRELOG_E_OK);
  Observation released = post;
  released.lease_identity = identity (99);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (kept.transition,
      MT (OP_RETAIN), MT (EFFECT_APPLIED), &released, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_LEASE_AUTHORITY));
  g_assert_false (result.terminal);
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (kept.transition,
      MT (OP_RETAIN), MT (EFFECT_APPLIED), &post, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));
  drive_clear (&kept);
}

/* ------------------------------------------------------------------ */
/* T9 the no-orphan invariant, both modes                              */
/* ------------------------------------------------------------------ */

static void
assert_new_operation_admits (const Observation *namespace_after,
    gboolean mode_b, Identity expected_main, Identity new_stage)
{
  Options options = { .mode_b = mode_b };
  Request request = make_request (&options);
  request.operation_uuid = OTHER_UUID;
  if (!mode_b)
    request.expected_main_identity = expected_main;
  request.staged_main_identity = new_stage;
  Observation staged = *namespace_after;
  memcpy (staged.operation_uuid, OTHER_BYTES, sizeof staged.operation_uuid);
  set_entry (&staged, SLOT_STAGE, TRUE, new_stage);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&request, &staged, NULL, &result, &transition), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  wyl_fact_artifact_main_transition_free (transition);
}

static void
test_no_orphan_invariant (void)
{
  Options options = { 0 };

  /* (i) mode A: ROLLED_BACK --RETIRE_STAGE--> ABANDONED, and the namespace
   * that leaves admits a new operation rather than refusing it forever. */
  Drive drive = drive_to (MT (STATE_ABANDONED), &options);
  g_assert_true (wyl_fact_artifact_main_transition_is_terminal
        (drive.transition));
  assert_new_operation_admits (&drive.observation, FALSE, EXPECTED_MAIN,
      identity (555));
  drive_clear (&drive);

  /* (ii) mode A restart path. */
  Observation resident = observe (F_MAIN, TRUE, FALSE);
  Options forbidden = { .resume_forbidden = TRUE };
  Transition *cleanup = admit_ok (&forbidden, &resident);
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (cleanup), ==,
      MT (STATE_READY));
  g_assert_false (wyl_fact_artifact_main_transition_is_terminal (cleanup));
  g_assert_cmpint (authorize_refusal (cleanup, MT (OP_RETIRE_STAGE),
      &resident), ==, AUTHORIZED);
  wyl_fact_artifact_main_transition_free (cleanup);
  Transition *blocked = admit_ok (&forbidden, &resident);
  g_assert_cmpint (authorize_refusal (blocked, MT (OP_RETAIN), &resident), ==,
      ILLEGAL);
  g_assert_cmpint (authorize_refusal (blocked, MT (OP_SYNC_STAGED),
      &resident), ==, ILLEGAL);
  wyl_fact_artifact_main_transition_free (blocked);
  /* The same admit WITHOUT the flag classifies READY and authorizes RETAIN,
   * so a driver must never treat READY as proof of freshness. */
  Drive fresh = drive_to (MT (STATE_READY), &options);
  g_assert_cmpint (authorize_refusal (fresh.transition, MT (OP_RETAIN),
      &fresh.observation), ==, AUTHORIZED);
  drive_clear (&fresh);

  /* (ii-B) mode B restart path: the assertion that matters is that
   * record(RETIRE_STAGE, APPLIED, (0,0,0)) is ACCEPTED and lands ABANDONED. */
  Options mode_b = { .mode_b = TRUE, .resume_forbidden = TRUE };
  Drive mode_b_cleanup = drive_to (MT (STATE_READY), &mode_b);
  g_assert_cmpint (authorize_refusal (mode_b_cleanup.transition,
      MT (OP_PUBLISH), &mode_b_cleanup.observation), ==, ILLEGAL);
  mutate (&mode_b_cleanup, MT (OP_RETIRE_STAGE),
      observe (F_ABSENT, FALSE, FALSE));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (mode_b_cleanup.transition), ==, MT (STATE_ABANDONED));
  g_assert_true (wyl_fact_artifact_main_transition_is_terminal
        (mode_b_cleanup.transition));
  assert_new_operation_admits (&mode_b_cleanup.observation, TRUE,
      (Identity) { 0 }, identity (556));
  drive_clear (&mode_b_cleanup);

  /* (iii) a foreign stage in ROLLED_BACK: RETIRE_STAGE refuses on identity
   * and the artifact stays resident, which is REQUIRED rather than forbidden
   * once it is no longer operation-owned. */
  Drive rolled_back = drive_to (MT (STATE_ROLLED_BACK), &options);
  Observation foreign = rolled_back.observation;
  foreign.entries[SLOT_STAGE].identity = FOREIGN_IDENTITY;
  g_assert_cmpint (authorize_refusal (rolled_back.transition,
      MT (OP_RETIRE_STAGE), &foreign), ==, MT (REFUSAL_FOREIGN_STAGE));
  drive_clear (&rolled_back);
}


/*
 * THE FLAG MUST NOT STRAND A CLASSIFICATION.  A flagged admit classifies from
 * the triple like any other, so it can land in RETAINED, RETAINED_STAGE_LOST
 * or mode-A PUBLISHED.  RETIRE_STAGE never touches the rollback link, and in
 * the first two facts.duckdb does not exist and that link is the only artifact
 * that can restore it -- so with RETIRE_STAGE as the only permitted op those
 * objects are non-terminal with ZERO legal ops, which is section 7 violated by
 * exactly the caller 7b describes.  ROLLBACK is the exit.
 *
 * Divergence for the defect: every assertion below fails at the first step,
 * because no op is authorized and next_op advertises one that refuses.
 */
static Observation
post_for_flagged_exit (State from, Op op)
{
  if (op == MT (OP_ROLLBACK)) {
    if (from == MT (STATE_PUBLISHED)
        || from == MT (STATE_PUBLISHED_DURABLE))
      return observe (F_ABSENT, TRUE, TRUE);
    if (from == MT (STATE_RETAINED))
      return observe (F_MAIN, TRUE, FALSE);
    return observe (F_MAIN, FALSE, FALSE);
  }
  return observe (F_MAIN, FALSE, FALSE);
}

static void
test_resume_forbidden_always_has_an_exit (void)
{
  Options forbidden = { .resume_forbidden = TRUE };
  const struct
  {
    MainKind kind;
    gboolean stage;
    gboolean rollback;
    State classified;
  } rows[] = {
    { F_ABSENT, TRUE, TRUE, MT (STATE_RETAINED) },
    { F_ABSENT, FALSE, TRUE, MT (STATE_RETAINED_STAGE_LOST) },
    { F_STAGE, FALSE, TRUE, MT (STATE_PUBLISHED) },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (rows); index++) {
    Observation start = observe (rows[index].kind, rows[index].stage,
            rows[index].rollback);
    Drive drive = { .observation = start };
    drive.transition = admit_ok (&forbidden, &start);
    g_assert_cmpint (wyl_fact_artifact_main_transition_state
          (drive.transition), ==, rows[index].classified);
    g_assert_false (wyl_fact_artifact_main_transition_is_terminal
          (drive.transition));

    /* next_op ADVERTISES the exit.  Advertising anything else sends #552
     * into a refusal, which is the same defect one layer up. */
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
          (drive.transition, &drive.observation, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.next_op, ==, MT (OP_ROLLBACK));
    /* RETIRE_STAGE is NOT the exit from any of these three: it would leave
     * the rollback link resident and facts.duckdb still absent. */
    g_assert_cmpint (authorize_refusal (drive.transition,
        MT (OP_RETIRE_STAGE), &drive.observation), ==, ILLEGAL);
    /*
     * THE ALLOWLIST SHAPE, PINNED.  Finding 8's protection is intact because
     * ROLLBACK is the exit rather than forward progress, but asserting only
     * RETAIN and PUBLISH would let a regression that converts gate_op's
     * clause into a DENYLIST over those two pass every test in this file --
     * and FINALIZE is the one op that could complete a restore the flag
     * exists to forbid.  Every op but the two permitted ones must refuse.
     */
    for (gsize op = 0; op < G_N_ELEMENTS (AUTHORIZABLE_OPS); op++) {
      if (AUTHORIZABLE_OPS[op] == MT (OP_ROLLBACK)
          || AUTHORIZABLE_OPS[op] == MT (OP_RETIRE_STAGE))
        continue;
      g_assert_cmpint (authorize_refusal (drive.transition,
          AUTHORIZABLE_OPS[op], &drive.observation), ==, ILLEGAL);
    }

    /* Following next_op reaches ABANDONED: one step from
     * RETAINED_STAGE_LOST, two from RETAINED, three from mode-A PUBLISHED. */
    guint steps = 0;
    while (!wyl_fact_artifact_main_transition_is_terminal (drive.transition)) {
      Result step;
      g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
            (drive.transition, &drive.observation, &step), ==, WYRELOG_E_OK);
      g_assert_cmpint (step.next_op, !=, MT (OP_NONE));
      mutate (&drive, step.next_op,
          post_for_flagged_exit (step.state, step.next_op));
      steps++;
      g_assert_cmpuint (steps, <=, 3);
    }
    g_assert_cmpint (wyl_fact_artifact_main_transition_state
          (drive.transition), ==, MT (STATE_ABANDONED));
    drive_clear (&drive);
  }
}

/*
 * MODE-B PUBLISHED UNDER THE FLAG HAS ZERO LEGAL OPS, AND THAT IS CORRECT.
 * ROLLBACK's gate is mode_a-only and must stay so.  This triple is
 * (F ~= E_stage, S absent, R absent): the stage became the new main rather
 * than being orphaned, and mode B has no rollback link, so no operation-owned
 * artifact is resident and section 7 has nothing to retire.  It is a dead
 * OBJECT on a HEALTHY GRAPH, which is what the last assertion proves and what
 * separates it from the bricked case above.  Permitting FINALIZE to tidy it
 * would be a mode-conditional special case that in mode A would destroy the
 * rollback link.
 */
static void
test_resume_forbidden_mode_b_published_is_a_healthy_dead_end (void)
{
  Options forbidden = { .mode_b = TRUE, .resume_forbidden = TRUE };
  Observation published = observe (F_STAGE, FALSE, FALSE);
  Transition *transition = admit_ok (&forbidden, &published);
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (transition), ==,
      MT (STATE_PUBLISHED));
  g_assert_false (wyl_fact_artifact_main_transition_is_terminal (transition));

  Result result;
  g_assert_cmpint (wyl_fact_artifact_main_transition_inspect (transition,
      &published, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.next_op, ==, MT (OP_NONE));
  for (gsize index = 0; index < G_N_ELEMENTS (AUTHORIZABLE_OPS); index++)
    g_assert_cmpint (authorize_refusal (transition, AUTHORIZABLE_OPS[index],
        &published), ==, ILLEGAL);
  wyl_fact_artifact_main_transition_free (transition);

  /* The graph is healthy: a NEW operation admits against this namespace, so
   * the dead object costs nothing.  The new operation is mode A -- its
   * expected main is the content this one published. */
  assert_new_operation_admits (&published, FALSE, STAGED_MAIN,
      identity (557));
}


/*
 * A TERMINAL TRANSITION MUST ADVERTISE NOTHING.  record_collision leaves the
 * state unchanged and only sets the terminal flag, so the state's own switch
 * case stays live: before the fix, inspect on a collision-terminal object
 * reported terminal together with an op that authorize and record both
 * refuse.  Nothing was ever authorized, but next_op's contract is that it
 * advertises only what gate_op will accept.
 */
static void
test_terminal_advertises_no_op (void)
{
  const struct
  {
    gboolean resume_forbidden;
    Op op;
    MainKind third_kind;
    gboolean third_stage;
    gboolean third_rollback;
  } rows[] = {
    { FALSE, MT (OP_RETAIN), F_MAIN, FALSE, FALSE },
    { TRUE, MT (OP_RETIRE_STAGE), F_ABSENT, TRUE, TRUE },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (rows); index++) {
    Options options = { .resume_forbidden = rows[index].resume_forbidden };
    Drive drive = drive_to (MT (STATE_READY), &options);
    Result result;
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
          (drive.transition, rows[index].op, &drive.observation, &result),
        ==, WYRELOG_E_OK);
    Observation third = observe (rows[index].third_kind,
            rows[index].third_stage, rows[index].third_rollback);
    g_assert_cmpint (wyl_fact_artifact_main_transition_record
          (drive.transition, rows[index].op, MT (EFFECT_APPLIED), &third,
        &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result.refusal, ==, MT (REFUSAL_COLLISION_AMBIGUOUS));
    g_assert_true (wyl_fact_artifact_main_transition_is_terminal
          (drive.transition));
    /* The state is deliberately unchanged, which is what keeps its switch
     * case reachable and made this defect possible. */
    g_assert_cmpint (wyl_fact_artifact_main_transition_state
          (drive.transition), ==, MT (STATE_READY));
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
          (drive.transition, &drive.observation, &result), ==, WYRELOG_E_OK);
    g_assert_true (result.terminal);
    g_assert_cmpint (result.next_op, ==, MT (OP_NONE));
    drive_clear (&drive);
  }
}

/* ------------------------------------------------------------------ */
/* T10 the rename-mutation invariant                                   */
/* ------------------------------------------------------------------ */

static void
test_rename_mutation_invariant (void)
{
  Options options = { 0 };
  Options mode_b = { .mode_b = TRUE };
  const struct
  {
    State state;
    Op op;
    guint destination;
    gboolean mode_b;
    gboolean occupant_is_stage;
    Refusal occupied;
  } renames[] = {
    { MT (STATE_READY), MT (OP_RETAIN), SLOT_ROLLBACK, FALSE, FALSE,
      MT (REFUSAL_ROLLBACK_NAME_OCCUPIED) },
    { MT (STATE_RETAINED), MT (OP_PUBLISH), SLOT_MAIN, FALSE, FALSE,
      MT (REFUSAL_ROLLBACK_NAME_OCCUPIED) },
    { MT (STATE_READY), MT (OP_PUBLISH), SLOT_MAIN, TRUE, TRUE,
      MT (REFUSAL_COLLISION_AMBIGUOUS) },
    { MT (STATE_RETAINED), MT (OP_ROLLBACK), SLOT_MAIN, FALSE, FALSE,
      MT (REFUSAL_ROLLBACK_NAME_OCCUPIED) },
    { MT (STATE_RETAINED_STAGE_LOST), MT (OP_ROLLBACK), SLOT_MAIN, FALSE,
      FALSE, MT (REFUSAL_ROLLBACK_NAME_OCCUPIED) },
    { MT (STATE_PUBLISHED), MT (OP_ROLLBACK), SLOT_STAGE, FALSE, TRUE,
      MT (REFUSAL_COLLISION_AMBIGUOUS) },
    { MT (STATE_PUBLISHED_DURABLE), MT (OP_ROLLBACK), SLOT_STAGE, FALSE, TRUE,
      MT (REFUSAL_COLLISION_AMBIGUOUS) },
  };
  for (gsize index = 0; index < G_N_ELEMENTS (renames); index++) {
    const Options *selected = renames[index].mode_b ? &mode_b : &options;
    Drive drive = drive_to (renames[index].state, selected);
    g_assert_cmpint (authorize_refusal (drive.transition, renames[index].op,
        &drive.observation), ==, AUTHORIZED);
    /* The assertion that can actually fail: occupy the destination and the
     * same op must refuse.  Asserting only that the fixture built it absent
     * tests the fixture, not the implementation. */
    Observation occupied = drive.observation;
    set_entry (&occupied, renames[index].destination, TRUE,
        renames[index].occupant_is_stage ? STAGED_MAIN : EXPECTED_MAIN);
    Result invalidate;
    g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
          (drive.transition, &drive.observation, &invalidate), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (authorize_refusal (drive.transition, renames[index].op,
        &occupied), ==, renames[index].occupied);
    /* Every rename in this transition is a no-replace rename, so the
     * authorizing observation must show the destination absent. */
    g_assert_false (drive.observation.entries[renames[index].destination]
        .present);
    drive_clear (&drive);
  }

  /* The four SYNC ops consult no destination.  SYNC_PUBLISH_DIR is authorized
   * from mode-A PUBLISHED and mode-B PUBLISHED alike, and those two states
   * differ in exactly the rollback slot, so an implementation that consulted
   * a destination here would diverge between them. */
  Drive mode_a_published = drive_to (MT (STATE_PUBLISHED), &options);
  Drive mode_b_published = drive_to (MT (STATE_PUBLISHED), &mode_b);
  g_assert_true (mode_a_published.observation.entries[SLOT_ROLLBACK].present);
  g_assert_false (mode_b_published.observation.entries[SLOT_ROLLBACK].present);
  g_assert_cmpint (authorize_refusal (mode_a_published.transition,
      MT (OP_SYNC_PUBLISH_DIR), &mode_a_published.observation), ==,
      AUTHORIZED);
  g_assert_cmpint (authorize_refusal (mode_b_published.transition,
      MT (OP_SYNC_PUBLISH_DIR), &mode_b_published.observation), ==,
      AUTHORIZED);
  drive_clear (&mode_a_published);
  drive_clear (&mode_b_published);

  /* The two unlink ops have no destination and an identity-verified source. */
  Drive rolled_back = drive_to (MT (STATE_ROLLED_BACK), &options);
  g_assert_true (rolled_back.observation.entries[SLOT_STAGE].present);
  Identity owned_stage = STAGED_MAIN;
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&rolled_back.observation.entries[SLOT_STAGE].identity,
      &owned_stage));
  drive_clear (&rolled_back);

  /* The derived names are disjoint from every fixed name. */
  Drive named = drive_to (MT (STATE_READY), &options);
  g_autofree gchar *stage
    = wyl_fact_artifact_main_transition_dup_stage_name (named.transition);
  g_autofree gchar *rollback
    = wyl_fact_artifact_main_transition_dup_rollback_name (named.transition);
  g_assert_cmpstr (stage, !=, rollback);
  for (gsize index = 0; index < G_N_ELEMENTS (FIXED_NAMES); index++) {
    g_assert_cmpstr (stage, !=, FIXED_NAMES[index]);
    g_assert_cmpstr (rollback, !=, FIXED_NAMES[index]);
  }
  drive_clear (&named);

  /* Capability is an out-of-band probe, never inferred from a failed rename. */
  Observation ready = observe (F_MAIN, TRUE, FALSE);
  ready.no_replace_supported = FALSE;
  g_assert_cmpint (admit_refusal (&options, &ready, NULL), ==,
      MT (REFUSAL_PRIMITIVE_UNSUPPORTED));
}

/* ------------------------------------------------------------------ */
/* T11 terminal and cancel                                             */
/* ------------------------------------------------------------------ */

static void
test_terminal_and_cancel (void)
{
  Options options = { 0 };
  static const State terminals[] = {
    MT (STATE_FINALIZED), MT (STATE_ABANDONED),
  };
  for (gsize index = 0; index < G_N_ELEMENTS (terminals); index++) {
    Drive drive = drive_to (terminals[index], &options);
    g_assert_true (wyl_fact_artifact_main_transition_is_terminal
          (drive.transition));
    g_assert_null (wyl_fact_artifact_main_transition_dup_stage_name
          (drive.transition));
    g_assert_null (wyl_fact_artifact_main_transition_dup_rollback_name
          (drive.transition));
    drive_clear (&drive);
  }

  /* ROLLED_BACK is NOT terminal and admits exactly one op, and the stage name
   * is still available there -- which is what makes RETIRE_STAGE usable. */
  Drive rolled_back = drive_to (MT (STATE_ROLLED_BACK), &options);
  g_assert_false (wyl_fact_artifact_main_transition_is_terminal
        (rolled_back.transition));
  g_autofree gchar *stage
    = wyl_fact_artifact_main_transition_dup_stage_name
        (rolled_back.transition);
  g_assert_nonnull (stage);
  drive_clear (&rolled_back);

  Options forbidden = { .resume_forbidden = TRUE };
  Drive cleanup = drive_to (MT (STATE_READY), &forbidden);
  g_assert_false (wyl_fact_artifact_main_transition_is_terminal
        (cleanup.transition));
  g_autofree gchar *cleanup_stage
    = wyl_fact_artifact_main_transition_dup_stage_name (cleanup.transition);
  g_assert_nonnull (cleanup_stage);
  drive_clear (&cleanup);

  /* Cancel, then the no-observation status path. */
  Drive live = drive_to (MT (STATE_RETAINED), &options);
  g_assert_cmpint (wyl_fact_artifact_main_transition_cancel (live.transition),
      ==, WYRELOG_E_CANCELLED);
  g_assert_cmpint (wyl_fact_artifact_main_transition_cancel (live.transition),
      ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_main_transition_refusal
        (live.transition), ==, MT (REFUSAL_CANCELLED));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (live.transition),
      ==, MT (STATE_RETAINED));
  g_assert_true (wyl_fact_artifact_main_transition_is_terminal
        (live.transition));
  g_assert_true (wyl_fact_artifact_main_transition_rollback_required
        (live.transition));
  drive_clear (&live);

  /*
   * The status path keeps answering after a re-validation refusal, and
   * rollback_required returns its Request-derived value in BOTH modes
   * regardless of state or observation.
   */
  Options mode_b = { .mode_b = TRUE };
  Drive released = drive_to (MT (STATE_PUBLISHED), &mode_b);
  Observation no_lease = released.observation;
  no_lease.lease_identity = identity (99);
  Result result;
  g_assert_cmpint (wyl_fact_artifact_main_transition_inspect
        (released.transition, &no_lease, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_LEASE_AUTHORITY));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state
        (released.transition), ==, MT (STATE_PUBLISHED));
  g_assert_false (wyl_fact_artifact_main_transition_rollback_required
        (released.transition));
  g_assert_false (wyl_fact_artifact_main_transition_is_terminal
        (released.transition));
  drive_clear (&released);
}

/* ------------------------------------------------------------------ */
/* T12 result initialized on every path                                */
/* ------------------------------------------------------------------ */

/*
 * A zero-filled probe would NOT catch an unwritten result, because zero reads
 * as INVALID/NONE and looks correct.  These probes are poisoned instead.
 */
static Result
poisoned (void)
{
  return (Result) {
           .state = MT (STATE_FINALIZED),
           .refusal = MT (REFUSAL_NONE),
           .next_op = MT (OP_FINALIZE),
           .terminal = FALSE,
           .durability = MT (DURABILITY_PROVEN),
  };
}

static void
assert_result_written (const Result *result)
{
  g_assert_cmpint (result->state, !=, MT (STATE_FINALIZED));
  g_assert_cmpint (result->next_op, !=, MT (OP_FINALIZE));
}

static void
test_result_initialized_on_every_path (void)
{
  Options options = { 0 };
  Observation ready = observe (F_MAIN, TRUE, FALSE);
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot
    = snapshot_build (&ready, NULL);
  Request request = make_request (&options);
  Transition *transition = NULL;

  Result probe = poisoned ();
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (NULL, snapshot,
      &ready, &probe, &transition), ==, WYRELOG_E_INVALID);
  assert_result_written (&probe);

  probe = poisoned ();
  Request bad = request;
  bad.operation_uuid = "not-a-uuid";
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&bad, snapshot,
      &ready, &probe, &transition), ==, WYRELOG_E_INVALID);
  assert_result_written (&probe);

  Drive drive = drive_to (MT (STATE_READY), &options);
  probe = poisoned ();
  g_assert_cmpint (wyl_fact_artifact_main_transition_inspect (NULL,
      &drive.observation, &probe), ==, WYRELOG_E_INVALID);
  assert_result_written (&probe);

  probe = poisoned ();
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (drive.transition, MT (OP_INSPECT), &drive.observation, &probe), ==,
      WYRELOG_E_INVALID);
  assert_result_written (&probe);

  probe = poisoned ();
  g_assert_cmpint (wyl_fact_artifact_main_transition_authorize
        (drive.transition, MT (OP_FINALIZE), &drive.observation, &probe), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (probe.refusal, ==, ILLEGAL);
  g_assert_cmpint (probe.next_op, ==, MT (OP_NONE));

  probe = poisoned ();
  g_assert_cmpint (wyl_fact_artifact_main_transition_record (drive.transition,
      MT (OP_FINALIZE), MT (EFFECT_APPLIED), &drive.observation, &probe), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (probe.refusal, ==, MT (REFUSAL_NO_PENDING_MUTATION));
  g_assert_cmpint (probe.next_op, ==, MT (OP_NONE));
  drive_clear (&drive);
}

/* ------------------------------------------------------------------ */
/* T13 proven-absent main                                              */
/* ------------------------------------------------------------------ */

static void
test_proven_absent_main (void)
{
  Options mode_b = { .mode_b = TRUE };
  Options mode_a = { 0 };
  Drive drive = drive_to (MT (STATE_READY), &mode_b);
  g_assert_false (wyl_fact_artifact_main_transition_rollback_required
        (drive.transition));
  g_assert_false (drive.observation.entries[SLOT_MAIN].present);
  mutate (&drive, MT (OP_PUBLISH), observe (F_STAGE, FALSE, FALSE));
  g_assert_cmpint (wyl_fact_artifact_main_transition_state (drive.transition),
      ==, MT (STATE_PUBLISHED));
  drive_clear (&drive);

  Drive rollback_mode = drive_to (MT (STATE_READY), &mode_a);
  g_assert_true (wyl_fact_artifact_main_transition_rollback_required
        (rollback_mode.transition));
  drive_clear (&rollback_mode);

  /* A mode-B request that also names an expected main is an argument-shape
   * failure, which is what makes the two incoherent boolean combinations
   * unrepresentable rather than merely refused. */
  Request contradictory = make_request (&mode_b);
  contradictory.expected_main_identity = EXPECTED_MAIN;
  Observation ready = observe (F_ABSENT, TRUE, FALSE);
  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&contradictory, &ready, NULL, &result,
      &transition), ==, WYRELOG_E_INVALID);
  g_assert_null (transition);
}

/* ------------------------------------------------------------------ */
/* T14 Windows-width identity parity                                   */
/* ------------------------------------------------------------------ */

/*
 * A comparison written against identity.object alone admits a pair that
 * differs only in the last FileId byte.  The POSIX rows pass either way, so
 * without this the defect would surface only in unit 3.
 */
static void
test_windows_width_identity_parity (void)
{
  Identity directory = extended_identity (VOLUME_DOMAIN, 1);
  Identity lease = extended_identity (VOLUME_DOMAIN, 2);
  Identity expected_main = extended_identity (VOLUME_DOMAIN, 3);
  Identity staged_main = extended_identity (VOLUME_DOMAIN, 4);
  Identity neighbour = extended_identity (VOLUME_DOMAIN, 5);
  g_assert_cmpuint (expected_main.object, ==, neighbour.object);
  g_assert_false (wyl_fact_artifact_inventory_identity_equal (&expected_main,
      &neighbour));

  Request request = {
    .operation_uuid = CANONICAL_UUID,
    .directory_identity = directory,
    .lease_identity = lease,
    .expected_main_absent = FALSE,
    .expected_main_identity = expected_main,
    .staged_main_identity = staged_main,
  };
  Observation observation = {
    .directory_identity = directory,
    .lease_identity = lease,
    .sealed = TRUE,
    .no_replace_supported = TRUE,
  };
  memcpy (observation.operation_uuid, CANONICAL_BYTES,
      sizeof observation.operation_uuid);
  set_entry (&observation, SLOT_MAIN, TRUE, expected_main);
  set_entry (&observation, SLOT_STAGE, TRUE, staged_main);
  set_entry (&observation, SLOT_ROLLBACK, FALSE, expected_main);

  Result result;
  Transition *transition = NULL;
  g_assert_cmpint (admit (&request, &observation, NULL, &result,
      &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  wyl_fact_artifact_main_transition_free (transition);

  /* The neighbour differs from the expected main only in the last FileId
   * byte and must be refused. */
  Observation substituted = observation;
  set_entry (&substituted, SLOT_MAIN, TRUE, neighbour);
  Transition *refused = NULL;
  g_assert_cmpint (admit (&request, &substituted, NULL, &result, &refused),
      ==, WYRELOG_E_POLICY);
  g_assert_null (refused);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_FOREIGN_MAIN));

  Observation stage_substituted = observation;
  set_entry (&stage_substituted, SLOT_STAGE, TRUE, neighbour);
  g_assert_cmpint (admit (&request, &stage_substituted, NULL, &result,
      &refused), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_FOREIGN_STAGE));

  /* A stage hard-linked to the current main compares EQUAL, so STAGE_IS_MAIN
   * fires on the declared identities at full Windows width too. */
  Request colliding = request;
  colliding.staged_main_identity = expected_main;
  g_assert_cmpint (admit (&colliding, &observation, NULL, &result, &refused),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_STAGE_IS_MAIN));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/artifact-main-transition/derived-identities",
      test_derived_identities);
  g_test_add_func ("/fact/artifact-main-transition/admission-refusals",
      test_admission_refusal_matrix);
  g_test_add_func ("/fact/artifact-main-transition/refusals-re-driven",
      test_refusal_matrix_at_inspect_and_authorize);
  g_test_add_func ("/fact/artifact-main-transition/inventory-gate",
      test_inventory_gate);
  g_test_add_func ("/fact/artifact-main-transition/transition-tables",
      test_legal_transition_tables);
  g_test_add_func ("/fact/artifact-main-transition/mode-b-undrivable-shapes",
      test_mode_b_undrivable_shapes);
  g_test_add_func ("/fact/artifact-main-transition/non-authorizable-ops",
      test_non_authorizable_ops);
  g_test_add_func ("/fact/artifact-main-transition/load-bearing-cells",
      test_load_bearing_cells);
  g_test_add_func ("/fact/artifact-main-transition/file-seams",
      test_file_seams_gate_forward_progress);
  g_test_add_func ("/fact/artifact-main-transition/ordering-barrier",
      test_mode_a_ordering_barrier);
  g_test_add_func ("/fact/artifact-main-transition/finalize-seam-scope",
      test_finalize_is_gated_by_publish_dir_alone);
  g_test_add_func ("/fact/artifact-main-transition/latching-within-epoch",
      test_latching_within_an_epoch);
  g_test_add_func ("/fact/artifact-main-transition/epoch-boundary",
      test_directory_epoch_boundary);
  g_test_add_func ("/fact/artifact-main-transition/bounded-exit",
      test_bounded_exit);
  g_test_add_func ("/fact/artifact-main-transition/seam-reachability",
      test_seam_reachability);
  g_test_add_func ("/fact/artifact-main-transition/convergence-and-restart",
      test_convergence_and_restart);
  g_test_add_func ("/fact/artifact-main-transition/record-effect-shape",
      test_record_effect_shape_matrix);
  g_test_add_func ("/fact/artifact-main-transition/record-post-conditions",
      test_record_post_conditions);
  g_test_add_func ("/fact/artifact-main-transition/pairing-interlock",
      test_pairing_interlock);
  g_test_add_func ("/fact/artifact-main-transition/no-orphan",
      test_no_orphan_invariant);
  g_test_add_func ("/fact/artifact-main-transition/resume-forbidden-exit",
      test_resume_forbidden_always_has_an_exit);
  g_test_add_func ("/fact/artifact-main-transition/resume-forbidden-mode-b",
      test_resume_forbidden_mode_b_published_is_a_healthy_dead_end);
  g_test_add_func ("/fact/artifact-main-transition/terminal-advertises-none",
      test_terminal_advertises_no_op);
  g_test_add_func ("/fact/artifact-main-transition/rename-invariant",
      test_rename_mutation_invariant);
  g_test_add_func ("/fact/artifact-main-transition/terminal-and-cancel",
      test_terminal_and_cancel);
  g_test_add_func ("/fact/artifact-main-transition/result-initialized",
      test_result_initialized_on_every_path);
  g_test_add_func ("/fact/artifact-main-transition/proven-absent-main",
      test_proven_absent_main);
  g_test_add_func ("/fact/artifact-main-transition/windows-width-parity",
      test_windows_width_identity_parity);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "fact/graph-artifact-main-transition-private.h"

#include "wyl-id-private.h"

#include <string.h>

#define MT_SLOT_MAIN     WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN
#define MT_SLOT_STAGE    WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE
#define MT_SLOT_ROLLBACK WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK
#define MT_SLOT_COUNT    WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_COUNT

#define MT_UNPROVEN     WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN
#define MT_PROVEN       WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN
#define MT_UNSUPPORTED  WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNSUPPORTED

/* Internal seam index.  One recording op per seam, so a partial outcome
 * always has vocabulary against a three-valued effect. */
typedef enum
{
  MT_SEAM_STAGED_FILE = 0,
  MT_SEAM_ROLLBACK_FILE,
  MT_SEAM_RETAIN_DIR,
  MT_SEAM_PUBLISH_DIR,
  MT_SEAM_COUNT,
} MtSeam;

struct WylFactArtifactMainTransition
{
  /* Request-derived and fixed at admission. */
  guint8 operation_uuid[WYL_ID_BYTES];
  gchar *stage_name;
  gchar *rollback_name;
  WylFactArtifactInventoryIdentity directory_identity;
  WylFactArtifactInventoryIdentity lease_identity;
  gboolean expected_main_absent;
  WylFactArtifactInventoryIdentity expected_main_identity;
  WylFactArtifactInventoryIdentity staged_main_identity;
  gboolean resume_forbidden;
  gboolean durability_unprovable_acknowledged;

  WylFactArtifactMainTransitionState state;
  WylFactArtifactMainTransitionRefusal refusal;
  gboolean terminal;
  gboolean cancelled;

  /* Receipts are latched here, never read back out of an Observation. */
  WylFactArtifactMainTransitionDurability latch[MT_SEAM_COUNT];

  gboolean pending;
  WylFactArtifactMainTransitionOp pending_op;
  guint64 pending_digest;
  WylFactArtifactMainTransitionEntryEvidence pending_pre[MT_SLOT_COUNT];
};

/* ------------------------------------------------------------------ */
/* identity helpers                                                    */
/* ------------------------------------------------------------------ */

static gboolean
identity_valid (const WylFactArtifactInventoryIdentity *identity)
{
  if (identity == NULL
      || (identity->object_width != 0 && identity->object_width != 16))
    return FALSE;
  if (identity->object_width == 16)
    return identity->object == 0;
  return memcmp (identity->object_bytes, (guint8[16]) { 0 },
             sizeof identity->object_bytes) == 0;
}

static gboolean
identity_present (const WylFactArtifactInventoryIdentity *identity)
{
  return identity_valid (identity)
         && (identity->domain != 0 || identity->object != 0
         || memcmp (identity->object_bytes, (guint8[16]) { 0 },
         sizeof identity->object_bytes) != 0);
}

static gboolean
identity_same (const WylFactArtifactInventoryIdentity *left,
    const WylFactArtifactInventoryIdentity *right)
{
  return wyl_fact_artifact_inventory_identity_equal (left, right);
}

/* ------------------------------------------------------------------ */
/* result helpers                                                      */
/* ------------------------------------------------------------------ */

static void
result_clear (WylFactArtifactMainTransitionResult *out_result)
{
  if (out_result != NULL)
    *out_result = (WylFactArtifactMainTransitionResult) {
      .state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID,
      .refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE,
      .next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE,
      .terminal = FALSE,
      .durability = MT_UNPROVEN,
    };
}

static WylFactArtifactMainTransitionOp
next_op_for (const WylFactArtifactMainTransition *transition)
{
  gboolean mode_a = !transition->expected_main_absent;
  /*
   * A TERMINAL TRANSITION ADVERTISES NOTHING.  record_collision leaves the
   * state unchanged and only sets the flag, so without this the state's own
   * switch case stays live and a terminal object offers an op that authorize
   * and record both refuse.  FINALIZED and ABANDONED already fell to OP_NONE
   * through the default case; this covers the collision path.
   */
  if (transition->terminal)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  /*
   * UNDER THE FLAG next_op MUST ADVERTISE ONLY WHAT gate_op WILL AUTHORIZE.
   * Consulting resume_forbidden in the READY case alone would have a flagged
   * RETAINED advertise SYNC_STAGED or PUBLISH and then refuse them, which is
   * the stranding defect one layer up: a driver that follows next_op walks
   * into a refusal instead of the exit.
   */
  if (transition->resume_forbidden) {
    switch (transition->state) {
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY:
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK:
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE;
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED:
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST:
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED:
      case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE:
        /*
         * MODE-B PUBLISHED HAS NO LEGAL OP AND OP_NONE IS THE TRUTH.  Its
         * triple is (F ~= E_stage, S absent, R absent): the stage became the
         * new main rather than being orphaned, and mode B has no rollback
         * link, so no operation-owned artifact is resident, section 7 has
         * nothing to retire, and conjunct (c) sees zero unknown entries so a
         * NEW operation admits cleanly.  It is a dead OBJECT on a HEALTHY
         * GRAPH.  Permitting FINALIZE to tidy it would have to be a
         * mode-conditional special case, and in mode A the same permission
         * would destroy the rollback link.
         */
        return mode_a ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK
               : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
      default:
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
    }
  }
  switch (transition->state) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY:
      if (transition->latch[MT_SEAM_STAGED_FILE] != MT_PROVEN)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED;
      return mode_a ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN
             : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED:
      if (transition->latch[MT_SEAM_STAGED_FILE] != MT_PROVEN)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED;
      if (transition->latch[MT_SEAM_ROLLBACK_FILE] != MT_PROVEN)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE;
      if (transition->latch[MT_SEAM_RETAIN_DIR] == MT_UNPROVEN)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST:
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED:
      if (transition->latch[MT_SEAM_PUBLISH_DIR] == MT_UNSUPPORTED
          && transition->durability_unprovable_acknowledged)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE:
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK:
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE;
    default:
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  }
}

static void
result_from_state (const WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionResult *out_result)
{
  *out_result = (WylFactArtifactMainTransitionResult) {
    .state = transition->state,
    .refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE,
    .next_op = next_op_for (transition),
    .terminal = transition->terminal,
    .durability = MT_UNPROVEN,
  };
}

static wyrelog_error_t
result_refuse (const WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionRefusal refusal,
    WylFactArtifactMainTransitionDurability durability,
    WylFactArtifactMainTransitionResult *out_result)
{
  *out_result = (WylFactArtifactMainTransitionResult) {
    .state = transition == NULL
        ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID : transition->state,
    .refusal = refusal,
    .next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE,
    .terminal = transition != NULL && transition->terminal,
    .durability = durability,
  };
  return WYRELOG_E_POLICY;
}

/* ------------------------------------------------------------------ */
/* derived names                                                       */
/* ------------------------------------------------------------------ */

static gboolean
restore_name_is_canonical (const gchar *name, const gchar *suffix)
{
  static const gchar prefix[] = "restore-";
  gsize prefix_len = sizeof prefix - 1;
  gsize suffix_len = strlen (suffix);
  gsize name_len = strlen (name);
  if (name_len != prefix_len + WYL_ID_STRING_LEN + suffix_len
      || memcmp (name, prefix, prefix_len) != 0
      || memcmp (name + prefix_len + WYL_ID_STRING_LEN, suffix, suffix_len)
      != 0)
    return FALSE;
  gchar uuid[WYL_ID_STRING_BUF];
  memcpy (uuid, name + prefix_len, WYL_ID_STRING_LEN);
  uuid[WYL_ID_STRING_LEN] = '\0';
  wyl_id_t id;
  if (wyl_id_parse (uuid, &id) != WYRELOG_E_OK)
    return FALSE;
  gchar canonical[WYL_ID_STRING_BUF];
  return wyl_id_format (&id, canonical, sizeof canonical) == WYRELOG_E_OK
         && memcmp (canonical, uuid, WYL_ID_STRING_LEN) == 0;
}

/*
 * One canonical UUIDv7 string in, nothing else.  The round trip through
 * wyl_id_parse and wyl_id_format plus the canonicality self-check on the
 * produced name is the same shape provisioning_stage_name_from_operation
 * uses.  Disjointness from "tmp-<token>" holds on UUID VERSION as well as
 * prefix, because a temp token requires token[14] == '4'.
 */
static wyrelog_error_t
derive_names (const gchar *operation_uuid, wyl_id_t *out_id,
    gchar **out_stage, gchar **out_rollback)
{
  *out_stage = NULL;
  *out_rollback = NULL;
  if (operation_uuid == NULL)
    return WYRELOG_E_INVALID;
  wyl_id_t id;
  gchar canonical[WYL_ID_STRING_BUF];
  if (wyl_id_parse (operation_uuid, &id) != WYRELOG_E_OK
      || wyl_id_format (&id, canonical, sizeof canonical) != WYRELOG_E_OK
      || g_strcmp0 (operation_uuid, canonical) != 0)
    return WYRELOG_E_INVALID;
  gchar *stage = g_strdup_printf ("restore-%s.duckdb", canonical);
  gchar *rollback = g_strdup_printf ("restore-%s.duckdb.superseded",
          canonical);
  if (!restore_name_is_canonical (stage, ".duckdb")
      || !restore_name_is_canonical (rollback, ".duckdb.superseded")) {
    g_free (stage);
    g_free (rollback);
    return WYRELOG_E_INTERNAL;
  }
  *out_id = id;
  *out_stage = stage;
  *out_rollback = rollback;
  return WYRELOG_E_OK;
}

/* ------------------------------------------------------------------ */
/* re-validation                                                       */
/* ------------------------------------------------------------------ */

static guint64
digest_mix (guint64 accumulator, const guint8 *bytes, gsize length)
{
  for (gsize index = 0; index < length; index++) {
    accumulator ^= bytes[index];
    accumulator *= G_GUINT64_CONSTANT (0x100000001b3);
  }
  return accumulator;
}

static guint64
digest_identity (guint64 accumulator,
    const WylFactArtifactInventoryIdentity *identity)
{
  guint64 domain = identity->domain;
  guint64 object = identity->object;
  accumulator = digest_mix (accumulator, (const guint8 *) &domain,
          sizeof domain);
  accumulator = digest_mix (accumulator, (const guint8 *) &object,
          sizeof object);
  accumulator = digest_mix (accumulator, identity->object_bytes,
          sizeof identity->object_bytes);
  return digest_mix (accumulator, &identity->object_width,
             sizeof identity->object_width);
}

/*
 * The digest covers exactly the five authority-context values re-validation
 * already re-checks, so it is corroboration that a record has not been paired
 * with an observation from a different transition.  It is NOT the defence
 * against re-observation reuse: that hazard lives in the triple, which is
 * expected to change across a mutation and is therefore excluded here.
 * Invalidation on inspect is the load-bearing mechanism.
 */
static guint64
observation_digest (const WylFactArtifactMainTransitionObservation *o)
{
  guint64 accumulator = G_GUINT64_CONSTANT (0xcbf29ce484222325);
  guint8 flags[2] = { o->sealed ? 1u : 0u, o->main_binding_live ? 1u : 0u };
  accumulator = digest_identity (accumulator, &o->directory_identity);
  accumulator = digest_identity (accumulator, &o->lease_identity);
  accumulator = digest_mix (accumulator, o->operation_uuid,
          sizeof o->operation_uuid);
  return digest_mix (accumulator, flags, sizeof flags);
}

static WylFactArtifactMainTransitionRefusal
revalidate (const WylFactArtifactMainTransition *transition,
    const WylFactArtifactMainTransitionObservation *o)
{
  if (!o->sealed)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_GRAPH_NOT_SEALED;
  if (o->main_binding_live)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LIVE_MAIN_BINDING;
  if (!identity_same (&o->directory_identity, &transition->directory_identity))
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DIRECTORY_AUTHORITY;
  if (!identity_same (&o->lease_identity, &transition->lease_identity))
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LEASE_AUTHORITY;
  if (memcmp (o->operation_uuid, transition->operation_uuid,
      sizeof transition->operation_uuid) != 0)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_STALE_OPERATION;
  if (!o->no_replace_supported)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_PRIMITIVE_UNSUPPORTED;
  /*
   * Referent-less seam hygiene, not a durability gate.  Mode B performs no
   * retain rename and can never reach the state SYNC_ROLLBACK_FILE is legal
   * from, so a receipt for either seam is a CALLER WIRING BUG and refuses in
   * the wiring-consistency family rather than as DURABILITY_UNPROVEN, which
   * would be wrong in kind.  rollback_file is covered alongside
   * directory_after_retain because it is equally referent-less here; the
   * latch being unreachable makes the rule cheap rather than unnecessary.
   */
  if (transition->expected_main_absent
      && (o->durability.directory_after_retain != MT_UNPROVEN
      || o->durability.rollback_file != MT_UNPROVEN))
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_SEAM_NOT_APPLICABLE;
  for (guint slot = 0; slot < MT_SLOT_COUNT; slot++) {
    const WylFactArtifactMainTransitionEntryEvidence *entry
      = &o->entries[slot];
    if (!entry->present)
      continue;
    if (entry->reparse)
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_REPARSE;
    if (entry->link_count != 1)
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LINK_SUBSTITUTION;
    if (entry->owner_state
        != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING)
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_OWNERSHIP;
    if (!identity_present (&entry->identity)
        || entry->identity.domain != transition->directory_identity.domain)
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_CROSS_DEVICE;
  }
  return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
}

/* ------------------------------------------------------------------ */
/* classification                                                      */
/* ------------------------------------------------------------------ */

typedef enum
{
  MT_MAIN_ABSENT = 0,
  MT_MAIN_EXPECTED,
  MT_MAIN_STAGED,
  MT_MAIN_OTHER,
} MtMainClass;

static MtMainClass
main_class (const WylFactArtifactMainTransition *transition,
    const WylFactArtifactMainTransitionObservation *o)
{
  const WylFactArtifactMainTransitionEntryEvidence *main_entry
    = &o->entries[MT_SLOT_MAIN];
  if (!main_entry->present)
    return MT_MAIN_ABSENT;
  if (!transition->expected_main_absent
      && identity_same (&main_entry->identity,
      &transition->expected_main_identity))
    return MT_MAIN_EXPECTED;
  if (identity_same (&main_entry->identity,
      &transition->staged_main_identity))
    return MT_MAIN_STAGED;
  return MT_MAIN_OTHER;
}

/*
 * Classification is a pure function of the observed triple.  ROLLED_BACK and
 * PUBLISHED_DURABLE are deliberately unreachable here: the first has a triple
 * byte-identical to READY's and the second is distinguished only by a latch
 * that does not survive a restart, so both are IN-PROCESS states a fresh
 * observation cannot and must not reproduce.
 */
static WylFactArtifactMainTransitionState
classify (const WylFactArtifactMainTransition *transition,
    const WylFactArtifactMainTransitionObservation *o,
    WylFactArtifactMainTransitionRefusal *out_refusal)
{
  const WylFactArtifactMainTransitionEntryEvidence *stage
    = &o->entries[MT_SLOT_STAGE];
  const WylFactArtifactMainTransitionEntryEvidence *rollback
    = &o->entries[MT_SLOT_ROLLBACK];
  MtMainClass main_kind = main_class (transition, o);
  *out_refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;

  if (stage->present
      && !identity_same (&stage->identity, &transition->staged_main_identity)){
    *out_refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_FOREIGN_STAGE;
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
  }
  if (rollback->present
      && (transition->expected_main_absent
      || !identity_same (&rollback->identity,
      &transition->expected_main_identity))){
    *out_refusal
      = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ROLLBACK_NAME_OCCUPIED;
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
  }

  if (transition->expected_main_absent) {
    /*
     * NO_MAIN_ARTIFACT is the mode-B main-slot contradiction: the caller
     * declared expected_main_absent and the namespace disagrees.  It is
     * deliberately NOT fired on an F-absent observation before a recorded
     * PUBLISH, which is exactly the window mode-B RETIRE_STAGE lands in.
     */
    if (main_kind == MT_MAIN_OTHER) {
      *out_refusal
        = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NO_MAIN_ARTIFACT;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
    }
    if (main_kind == MT_MAIN_STAGED) {
      if (stage->present) {
        *out_refusal
          = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_COLLISION_AMBIGUOUS;
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
      }
      /* Mode-B FINALIZED shares this triple with mode-B PUBLISHED, because
       * FINALIZE retires nothing here.  Classifying the fail-closed member
       * of the pair keeps the directory_after_publish gate in force. */
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED;
    }
    return stage->present
        ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
        : WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
  }

  switch (main_kind) {
    case MT_MAIN_EXPECTED:
      if (rollback->present) {
        *out_refusal
          = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ROLLBACK_NAME_OCCUPIED;
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
      }
      return stage->present
          ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
          : WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
    case MT_MAIN_STAGED:
      if (stage->present) {
        *out_refusal
          = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_COLLISION_AMBIGUOUS;
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
      }
      return rollback->present
          ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
          : WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED;
    case MT_MAIN_ABSENT:
      if (!rollback->present) {
        *out_refusal
          = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_EXPECTED_MAIN_MISSING;
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
      }
      return stage->present
          ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
          : WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST;
    default:
      *out_refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_FOREIGN_MAIN;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
  }
}

/* ------------------------------------------------------------------ */
/* the inventory gate                                                  */
/* ------------------------------------------------------------------ */

static WylFactArtifactMainTransitionRefusal
inventory_gate (const WylFactArtifactInventorySnapshot *snapshot,
    const WylFactArtifactMainTransitionObservation *o,
    const WylFactArtifactInventoryIdentity *directory_identity)
{
  static const WylFactArtifactInventoryAnomaly hard_anomalies[] = {
    WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY,
    WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY,
    WYL_FACT_ARTIFACT_INVENTORY_SUBSTITUTED_ENTRY,
    WYL_FACT_ARTIFACT_INVENTORY_OVER_LIMIT_ENTRY,
    WYL_FACT_ARTIFACT_INVENTORY_UNREADABLE_ENTRY,
  };
  static const WylFactArtifactInventorySlot sidecars[] = {
    WYL_FACT_ARTIFACT_INVENTORY_WAL,
    WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT,
    WYL_FACT_ARTIFACT_INVENTORY_RECOVERY,
    WYL_FACT_ARTIFACT_INVENTORY_TEMP,
  };
  WylFactArtifactInventoryStatus status
    = wyl_fact_artifact_inventory_snapshot_status (snapshot);
  /*
   * (a) is not "status == STABLE".  The stage artifact is not a fixed name
   * and not a valid temp root, so the provider's readdir fallthrough counts
   * it as an UNKNOWN_ENTRY and finalize reports STABLE_WITH_UNKNOWN.  A
   * status-only gate would be unsatisfiable in its own happy path.
   */
  if (status != WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE
      && status != WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_INVENTORY_UNSTABLE;
  for (gsize index = 0; index < G_N_ELEMENTS (hard_anomalies); index++) {
    if (wyl_fact_artifact_inventory_snapshot_anomaly_count (snapshot,
        hard_anomalies[index]) != 0)
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_INVENTORY_ANOMALOUS;
  }
  /*
   * (c) is EQUALITY, not <=.  UNKNOWN_ENTRY is a count, not a set, so it is
   * evidence only when paired with the triple: stage plus one stray gives 2
   * against 1 and refuses, and one stray with no stage gives 1 against an
   * expected 0 and is refused by this same count check.
   */
  guint expected_unknown
    = (o->entries[MT_SLOT_STAGE].present ? 1u : 0u)
      + (o->entries[MT_SLOT_ROLLBACK].present ? 1u : 0u);
  if (wyl_fact_artifact_inventory_snapshot_anomaly_count (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY) != expected_unknown)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_COLLISION_AMBIGUOUS;

  WylFactArtifactInventorySlotEvidence main_evidence = { 0 };
  wyl_fact_artifact_inventory_snapshot_get_slot_evidence (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN, &main_evidence);
  gboolean observed_main = o->entries[MT_SLOT_MAIN].present;
  if (observed_main && !main_evidence.present)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_EXPECTED_MAIN_MISSING;
  if ((!observed_main && main_evidence.present)
      || (observed_main
      && !identity_same (&main_evidence.identity,
      &o->entries[MT_SLOT_MAIN].identity)))
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_FOREIGN_MAIN;

  /*
   * (e) is a requirement, not a choice.  This transition requires an
   * exclusive #612 lease, and the cooperative contract fixes the lock as a
   * same-owner regular file for any directory a lease can be held on, so the
   * lock is present by construction.  LOCK absent proves the snapshot does
   * not describe a leased graph directory.  It is a fixed name, produces no
   * anomaly, and does not disturb (c).
   */
  if (!wyl_fact_artifact_inventory_snapshot_slot_present (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_LOCK))
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LOCK_MISSING;
  for (gsize index = 0; index < G_N_ELEMENTS (sidecars); index++) {
    if (wyl_fact_artifact_inventory_snapshot_slot_present (snapshot,
        sidecars[index]))
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_SIDECAR_UNCONVERGED;
  }
  /*
   * (g) directory_identity equality is the only DIRECT proof that the
   * snapshot describes this directory.  Corroboration cannot substitute:
   * identity.domain proves only same-volume, the MAIN conjunct proves an
   * inode rather than a directory, and the LOCK conjunct proves only that
   * some lock is present.
   */
  WylFactArtifactInventoryObservation snapshot_observation = { 0 };
  if (!wyl_fact_artifact_inventory_snapshot_get_observation (snapshot,
      &snapshot_observation)
      || !identity_same (&snapshot_observation.directory_identity,
      directory_identity))
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_INVENTORY_UNBOUND;
  return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
}

/* ------------------------------------------------------------------ */
/* admission                                                           */
/* ------------------------------------------------------------------ */

static gboolean
request_shape_valid (const WylFactArtifactMainTransitionRequest *request)
{
  if (!identity_present (&request->directory_identity)
      || !identity_present (&request->lease_identity)
      || !identity_present (&request->staged_main_identity))
    return FALSE;
  if (request->expected_main_absent)
    return !identity_present (&request->expected_main_identity);
  return identity_present (&request->expected_main_identity);
}

wyrelog_error_t
wyl_fact_artifact_main_transition_admit
  (const WylFactArtifactMainTransitionRequest *request,
    const WylFactArtifactInventorySnapshot *snapshot,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result,
    WylFactArtifactMainTransition **out_transition)
{
  result_clear (out_result);
  if (out_transition != NULL)
    *out_transition = NULL;
  if (request == NULL || snapshot == NULL || observation == NULL
      || out_result == NULL || out_transition == NULL
      || !request_shape_valid (request))
    return WYRELOG_E_INVALID;

  wyl_id_t id;
  gchar *stage_name = NULL;
  gchar *rollback_name = NULL;
  wyrelog_error_t derived = derive_names (request->operation_uuid, &id,
          &stage_name, &rollback_name);
  if (derived != WYRELOG_E_OK)
    return derived;

  WylFactArtifactMainTransition scratch = {
    .stage_name = stage_name,
    .rollback_name = rollback_name,
    .directory_identity = request->directory_identity,
    .lease_identity = request->lease_identity,
    .expected_main_absent = request->expected_main_absent,
    .expected_main_identity = request->expected_main_identity,
    .staged_main_identity = request->staged_main_identity,
    .resume_forbidden = request->resume_forbidden,
    .durability_unprovable_acknowledged
      = request->durability_unprovable_acknowledged,
    .state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID,
  };
  memcpy (scratch.operation_uuid, id.bytes, sizeof scratch.operation_uuid);

  /*
   * STAGE_IS_MAIN keeps mode-A ABANDONED (F ~= E_main) disjoint from
   * FINALIZED (F ~= E_stage).  Identity equality alone suffices: a hard link
   * shares the POSIX (device, inode) pair and the Windows FileId, so a staged
   * file hard-linked to the current main compares EQUAL and this fires.
   * link_count keeps its separate nlink == 1 job.
   */
  if (!request->expected_main_absent
      && identity_same (&request->expected_main_identity,
      &request->staged_main_identity)) {
    g_free (stage_name);
    g_free (rollback_name);
    return result_refuse (NULL,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_STAGE_IS_MAIN,
               MT_UNPROVEN, out_result);
  }

  WylFactArtifactMainTransitionRefusal refusal = revalidate (&scratch,
          observation);
  if (refusal == WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE)
    refusal = inventory_gate (snapshot, observation,
            &request->directory_identity);
  WylFactArtifactMainTransitionState state
    = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
  if (refusal == WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE)
    state = classify (&scratch, observation, &refusal);
  if (refusal != WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE) {
    g_free (stage_name);
    g_free (rollback_name);
    return result_refuse (NULL, refusal, MT_UNPROVEN, out_result);
  }

  WylFactArtifactMainTransition *transition
    = g_new0 (WylFactArtifactMainTransition, 1);
  *transition = scratch;
  transition->state = state;
  transition->terminal
    = state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
      || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
  result_from_state (transition, out_result);
  *out_transition = transition;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_main_transition_free
  (WylFactArtifactMainTransition *transition)
{
  if (transition == NULL)
    return;
  g_free (transition->stage_name);
  g_free (transition->rollback_name);
  g_free (transition);
}

/* ------------------------------------------------------------------ */
/* inspect                                                             */
/* ------------------------------------------------------------------ */

static wyrelog_error_t
reclassify (WylFactArtifactMainTransition *transition,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result)
{
  WylFactArtifactMainTransitionRefusal refusal = revalidate (transition,
          observation);
  if (refusal != WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE)
    return result_refuse (transition, refusal, MT_UNPROVEN, out_result);
  if (transition->terminal) {
    result_from_state (transition, out_result);
    return WYRELOG_E_OK;
  }
  WylFactArtifactMainTransitionState state = classify (transition,
          observation, &refusal);
  if (refusal != WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE)
    return result_refuse (transition, refusal, MT_UNPROVEN, out_result);
  /*
   * PUBLISHED_DURABLE is distinguished from PUBLISHED only by a latch, and a
   * live transition must not be demoted by a re-observation that cannot see
   * one.  A fresh admit has no latch and correctly classifies PUBLISHED.
   */
  if (state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
      && transition->state
      == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE)
    state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE;
  if (state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
      && transition->state
      == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK)
    state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK;
  transition->state = state;
  transition->terminal
    = state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
      || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
  result_from_state (transition, out_result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_main_transition_inspect
  (WylFactArtifactMainTransition *transition,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result)
{
  result_clear (out_result);
  if (transition == NULL || observation == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  if (transition->cancelled)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_CANCELLED,
               MT_UNPROVEN, out_result);
  /* Inspect is the load-bearing invalidation: an authorization must not be
   * reused across a re-observation. */
  transition->pending = FALSE;
  transition->pending_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  return reclassify (transition, observation, out_result);
}

/* ------------------------------------------------------------------ */
/* authorize                                                           */
/* ------------------------------------------------------------------ */

static gboolean
op_is_authorizable (WylFactArtifactMainTransitionOp op)
{
  return op >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
         && op < WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT;
}

static WylFactArtifactMainTransitionRefusal
gate_op (const WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionDurability *out_durability)
{
  gboolean mode_a = !transition->expected_main_absent;
  WylFactArtifactMainTransitionState state = transition->state;
  *out_durability = MT_UNPROVEN;

  /*
   * resume_forbidden permits exactly two ops: RETIRE_STAGE, the cleanup, and
   * ROLLBACK, the EXIT.  RETAIN and PUBLISH stay unreachable, so finding 8's
   * protection is intact -- ROLLBACK is not forward progress.
   *
   * RETIRE_STAGE ALONE IS NOT ENOUGH, and assuming it is strands three
   * states.  A flagged admit classifies from the triple like any other, so it
   * can land in RETAINED, RETAINED_STAGE_LOST or mode-A PUBLISHED.  In the
   * first two facts.duckdb does not exist and the only artifact that can
   * restore it is the rollback link, which RETIRE_STAGE never touches; with
   * RETIRE_STAGE as the only permitted op those objects are non-terminal with
   * zero legal ops, which is section 7 violated by exactly the caller 7b
   * describes.  ROLLBACK reaches ROLLED_BACK or ABANDONED from each of them.
   */
  if (transition->resume_forbidden
      && op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE
      && op != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;

  switch (op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
      /* Legal from RETAINED as well as READY: a transition restarted in
       * RETAINED must be able to re-establish the latch PUBLISH consults, and
       * an idempotent fsync of the operation's own stage file is how.
       * RETAINED_STAGE_LOST deliberately does not get the edge. */
      if (state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
          || (mode_a
          && state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED))
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
      if (!mode_a || state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
      *out_durability = transition->latch[MT_SEAM_STAGED_FILE];
      if (*out_durability != MT_PROVEN)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNPROVEN;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      if (mode_a
          && state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      if (mode_a) {
        if (state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED)
          return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
        *out_durability = transition->latch[MT_SEAM_STAGED_FILE];
        if (*out_durability != MT_PROVEN)
          return
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNPROVEN;
        *out_durability = transition->latch[MT_SEAM_ROLLBACK_FILE];
        if (*out_durability != MT_PROVEN)
          return
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNPROVEN;
        /* The ordering barrier between two renames.  UNSUPPORTED passes:
         * the platform cannot establish it and refusing would recreate the
         * missing-final resting state, a residual the FINALIZE
         * acknowledgement carries instead.  UNPROVEN blocks, and blocks
         * nothing permanently. */
        *out_durability = transition->latch[MT_SEAM_RETAIN_DIR];
        if (*out_durability == MT_UNPROVEN)
          return
            WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNPROVEN;
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
      }
      /* Mode B has one rename, so there is no ordering to establish and
       * directory_after_retain is NOT consulted.  Applying mode A's third
       * conjunct here deadlocks mode B permanently and by construction. */
      if (state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
      *out_durability = transition->latch[MT_SEAM_STAGED_FILE];
      if (*out_durability != MT_PROVEN)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNPROVEN;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      /* Deliberately does not require its own latch: that would deadlock the
       * first flush. */
      if (state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK:
      if (mode_a
          && (state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
          || state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST
          || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
          || state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE))
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE:
      if ((mode_a
          && state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK)
          || (transition->resume_forbidden
          && state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY))
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE:
      if (state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
      if (state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
      /* The bounded exit.  UNPROVEN NEVER QUALIFIES: it is the recoverable
       * case and must be retried, and answering ACK_REQUIRED here would
       * invite #552 to prompt an operator for a condition a retry clears. */
      *out_durability = transition->latch[MT_SEAM_PUBLISH_DIR];
      if (*out_durability == MT_UNPROVEN)
        return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNPROVEN;
      if (!transition->durability_unprovable_acknowledged)
        return
          WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_ACK_REQUIRED;
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE;
    default:
      return WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION;
  }
}

wyrelog_error_t
wyl_fact_artifact_main_transition_authorize
  (WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionOp op,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result)
{
  result_clear (out_result);
  if (transition == NULL || observation == NULL || out_result == NULL
      || !op_is_authorizable (op))
    return WYRELOG_E_INVALID;
  if (transition->cancelled)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_CANCELLED,
               MT_UNPROVEN, out_result);
  if (transition->pending)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_PENDING_MUTATION,
               MT_UNPROVEN, out_result);

  WylFactArtifactMainTransitionResult classified;
  wyrelog_error_t status = reclassify (transition, observation, &classified);
  if (status != WYRELOG_E_OK) {
    *out_result = classified;
    return status;
  }
  if (transition->terminal)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_TERMINAL,
               MT_UNPROVEN, out_result);

  WylFactArtifactMainTransitionDurability durability = MT_UNPROVEN;
  WylFactArtifactMainTransitionRefusal refusal = gate_op (transition, op,
          &durability);
  if (refusal != WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE)
    return result_refuse (transition, refusal, durability, out_result);

  transition->pending = TRUE;
  transition->pending_op = op;
  transition->pending_digest = observation_digest (observation);
  for (guint slot = 0; slot < MT_SLOT_COUNT; slot++)
    transition->pending_pre[slot] = observation->entries[slot];
  *out_result = (WylFactArtifactMainTransitionResult) {
    .state = transition->state,
    .refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE,
    .next_op = op,
    .terminal = FALSE,
    .durability = durability,
  };
  return WYRELOG_E_OK;
}

/* ------------------------------------------------------------------ */
/* record                                                              */
/* ------------------------------------------------------------------ */

static gboolean
entries_shape_equal (const WylFactArtifactMainTransitionEntryEvidence *left,
    const WylFactArtifactMainTransitionEntryEvidence *right)
{
  for (guint slot = 0; slot < MT_SLOT_COUNT; slot++) {
    if (left[slot].present != right[slot].present)
      return FALSE;
    if (left[slot].present
        && !identity_same (&left[slot].identity, &right[slot].identity))
      return FALSE;
  }
  return TRUE;
}

/*
 * Never infer success from absence alone: each post condition names what must
 * be PRESENT and what identity it must hold, not merely what is gone.
 */
static gboolean
post_shape_ok (const WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionOp op,
    const WylFactArtifactMainTransitionObservation *o,
    WylFactArtifactMainTransitionState *out_state)
{
  gboolean mode_a = !transition->expected_main_absent;
  const WylFactArtifactMainTransitionEntryEvidence *main_entry
    = &o->entries[MT_SLOT_MAIN];
  const WylFactArtifactMainTransitionEntryEvidence *stage
    = &o->entries[MT_SLOT_STAGE];
  const WylFactArtifactMainTransitionEntryEvidence *rollback
    = &o->entries[MT_SLOT_ROLLBACK];
  gboolean main_is_expected = main_entry->present && mode_a
      && identity_same (&main_entry->identity,
          &transition->expected_main_identity);
  gboolean main_is_staged = main_entry->present
      && identity_same (&main_entry->identity,
          &transition->staged_main_identity);
  gboolean rollback_is_main = rollback->present && mode_a
      && identity_same (&rollback->identity,
          &transition->expected_main_identity);
  gboolean stage_is_stage = stage->present
      && identity_same (&stage->identity, &transition->staged_main_identity);

  switch (op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
      *out_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED;
      return !main_entry->present && rollback_is_main && stage_is_stage;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      *out_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED;
      return main_is_staged && !stage->present
             && (mode_a ? rollback_is_main : !rollback->present);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK:
      /* The landing state is a function of the observed triple, not a fixed
       * cell: a rollback taken with the stage already gone lands ABANDONED
       * rather than leaving an orphan no op can retire. */
      if (transition->state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
          || transition->state
          == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST) {
        *out_state = stage->present
            ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK
            : WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
        return main_is_expected && !rollback->present
               && (!stage->present || stage_is_stage);
      }
      *out_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED;
      return !main_entry->present && stage_is_stage && rollback_is_main;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE:
      *out_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
      return !stage->present && !rollback->present
             && (mode_a ? main_is_expected : !main_entry->present);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE:
      *out_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED;
      return !rollback->present && main_is_staged;
    default:
      *out_state = transition->state;
      return TRUE;
  }
}

static MtSeam
seam_for_op (WylFactArtifactMainTransitionOp op)
{
  switch (op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
      return MT_SEAM_STAGED_FILE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
      return MT_SEAM_ROLLBACK_FILE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      return MT_SEAM_RETAIN_DIR;
    default:
      return MT_SEAM_PUBLISH_DIR;
  }
}

static gboolean
op_is_sync (WylFactArtifactMainTransitionOp op)
{
  return op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED
         || op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE
         || op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR
         || op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR;
}

static WylFactArtifactMainTransitionDurability
reported_seam (const WylFactArtifactMainTransitionObservation *o, MtSeam seam)
{
  switch (seam) {
    case MT_SEAM_STAGED_FILE:
      return o->durability.staged_file;
    case MT_SEAM_ROLLBACK_FILE:
      return o->durability.rollback_file;
    case MT_SEAM_RETAIN_DIR:
      return o->durability.directory_after_retain;
    default:
      return o->durability.directory_after_publish;
  }
}

/* PROVEN is absorbing within a directory epoch; UNSUPPORTED is not absorbing
 * at all; UNPROVEN is the unset state and never overwrites either. */
static WylFactArtifactMainTransitionDurability
latch_merge (WylFactArtifactMainTransitionDurability latched,
    WylFactArtifactMainTransitionDurability reported)
{
  if (reported == MT_PROVEN || latched == MT_PROVEN)
    return MT_PROVEN;
  if (reported == MT_UNSUPPORTED)
    return MT_UNSUPPORTED;
  return latched;
}

static wyrelog_error_t
record_failed_mutation (WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionResult *out_result)
{
  result_from_state (transition, out_result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
record_collision (WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionResult *out_result)
{
  transition->terminal = TRUE;
  transition->refusal
    = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_COLLISION_AMBIGUOUS;
  *out_result = (WylFactArtifactMainTransitionResult) {
    .state = transition->state,
    .refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_COLLISION_AMBIGUOUS,
    .next_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE,
    .terminal = TRUE,
    .durability = MT_UNPROVEN,
  };
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_main_transition_record
  (WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionOp applied,
    WylFactArtifactMainTransitionEffect effect,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result)
{
  result_clear (out_result);
  if (transition == NULL || observation == NULL || out_result == NULL
      || !op_is_authorizable (applied)
      || effect > WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN)
    return WYRELOG_E_INVALID;
  if (transition->cancelled)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_CANCELLED,
               MT_UNPROVEN, out_result);
  if (transition->terminal)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_TERMINAL,
               MT_UNPROVEN, out_result);
  if (!transition->pending || transition->pending_op != applied)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NO_PENDING_MUTATION,
               MT_UNPROVEN, out_result);

  WylFactArtifactMainTransitionEntryEvidence pre[MT_SLOT_COUNT];
  guint64 pending_digest = transition->pending_digest;
  memcpy (pre, transition->pending_pre, sizeof pre);

  /*
   * RE-VALIDATION RUNS BEFORE THE AUTHORIZATION IS CLEARED.  A re-validation
   * refusal BLOCKS and is not terminal, so burning the authorization here
   * would leave the backend holding a mutation it may already have performed
   * and no way to spend the authorization for it.  A mismatched `applied`
   * still returns above, before the clears.
   */
  WylFactArtifactMainTransitionRefusal refusal = revalidate (transition,
          observation);
  if (refusal != WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE)
    return result_refuse (transition, refusal, MT_UNPROVEN, out_result);
  transition->pending = FALSE;
  transition->pending_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  if (observation_digest (observation) != pending_digest)
    return result_refuse (transition,
               WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NO_PENDING_MUTATION,
               MT_UNPROVEN, out_result);

  gboolean pre_ok = entries_shape_equal (observation->entries, pre);

  if (op_is_sync (applied)) {
    /* A SYNC op mutates no name, so shape carries no evidence about it and
     * the effect alone decides.  A changed shape is still a third shape. */
    if (!pre_ok)
      return record_collision (transition, out_result);
    if (effect != WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED)
      return record_failed_mutation (transition, out_result);
    MtSeam seam = seam_for_op (applied);
    WylFactArtifactMainTransitionDurability reported
      = reported_seam (observation, seam);
    /* Only directory seams may report UNSUPPORTED; a file seam reporting it
     * is itself a refusal. */
    if (reported == MT_UNSUPPORTED
        && (seam == MT_SEAM_STAGED_FILE || seam == MT_SEAM_ROLLBACK_FILE)){
      WylFactArtifactMainTransitionRefusal unsupported
        = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNSUPPORTED;
      return result_refuse (transition, unsupported, reported, out_result);
    }
    transition->latch[seam] = latch_merge (transition->latch[seam], reported);
    if (applied == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR
        && transition->latch[MT_SEAM_PUBLISH_DIR] == MT_PROVEN)
      transition->state
        = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE;
    result_from_state (transition, out_result);
    out_result->durability = transition->latch[seam];
    return WYRELOG_E_OK;
  }

  WylFactArtifactMainTransitionState landed = transition->state;
  gboolean post_ok = post_shape_ok (transition, applied, observation, &landed);

  if (post_ok && pre_ok) {
    /* Mode-B FINALIZE retires nothing, so its pre and post shapes coincide
     * and the shape is no evidence either way.  NOT_APPLIED is then a failed
     * mutation rather than the third-party substitution the disjoint case
     * reports. */
    if (effect == WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED)
      return record_failed_mutation (transition, out_result);
  } else if (post_ok) {
    if (effect == WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED)
      return record_collision (transition, out_result);
  } else if (pre_ok) {
    return record_failed_mutation (transition, out_result);
  } else {
    return record_collision (transition, out_result);
  }

  transition->state = landed;
  transition->terminal
    = landed == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
      || landed == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
  /*
   * A successful record of any RENAME or UNLINK op ends the directory epoch
   * and clears both directory-seam latches: the receipt no longer describes
   * the current directory and must be re-earned.  FILE-seam latches are not
   * cleared, because they attest INODE DATA and a rename does not change an
   * inode's contents.
   */
  transition->latch[MT_SEAM_RETAIN_DIR] = MT_UNPROVEN;
  transition->latch[MT_SEAM_PUBLISH_DIR] = MT_UNPROVEN;
  result_from_state (transition, out_result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_main_transition_cancel
  (WylFactArtifactMainTransition *transition)
{
  if (transition == NULL || transition->cancelled)
    return WYRELOG_E_INVALID;
  transition->pending = FALSE;
  transition->pending_op = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE;
  transition->cancelled = TRUE;
  transition->terminal = TRUE;
  transition->refusal = WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_CANCELLED;
  return WYRELOG_E_CANCELLED;
}

/* ------------------------------------------------------------------ */
/* the no-observation status path                                      */
/* ------------------------------------------------------------------ */

WylFactArtifactMainTransitionState
wyl_fact_artifact_main_transition_state
  (const WylFactArtifactMainTransition *transition)
{
  return transition == NULL
      ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID : transition->state;
}

WylFactArtifactMainTransitionRefusal
wyl_fact_artifact_main_transition_refusal
  (const WylFactArtifactMainTransition *transition)
{
  return transition == NULL
      ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE : transition->refusal;
}

gboolean
wyl_fact_artifact_main_transition_is_terminal
  (const WylFactArtifactMainTransition *transition)
{
  return transition != NULL && transition->terminal;
}

gboolean
wyl_fact_artifact_main_transition_rollback_required
  (const WylFactArtifactMainTransition *transition)
{
  return transition != NULL && !transition->expected_main_absent;
}

gchar *
wyl_fact_artifact_main_transition_dup_stage_name
  (const WylFactArtifactMainTransition *transition)
{
  return transition == NULL || transition->terminal
      ? NULL : g_strdup (transition->stage_name);
}

gchar *
wyl_fact_artifact_main_transition_dup_rollback_name
  (const WylFactArtifactMainTransition *transition)
{
  return transition == NULL || transition->terminal
      ? NULL : g_strdup (transition->rollback_name);
}

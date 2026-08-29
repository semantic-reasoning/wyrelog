/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "fact/graph-artifact-durability-private.h"

#include "wyl-id-private.h"

#include <string.h>

static gboolean
bytes_are_zero (const guint8 *bytes, gsize length)
{
  for (gsize i = 0; i < length; i++) {
    if (bytes[i] != 0)
      return FALSE;
  }
  return TRUE;
}

static gboolean
identity_is_present
  (const WylFactArtifactInventoryIdentity *identity)
{
  /* Self-equality is the inventory contract's public canonical-layout check:
   * it rejects partial Windows widths and mixed POSIX/Windows forms.  Do not
   * require any individual native field to be nonzero, but reject the wholly
   * zero sentinel because it carries no authority identity.  This is the same
   * presence rule used by #623's main-transition contract. */
  return identity != NULL
         && wyl_fact_artifact_inventory_identity_equal (identity, identity)
         && (identity->domain != 0 || identity->object != 0
         || !bytes_are_zero (identity->object_bytes,
         sizeof identity->object_bytes));
}

static gboolean
canonical_operation_uuid (const gchar *value)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  return value != NULL && value[WYL_ID_STRING_LEN] == '\0'
         && wyl_id_parse (value, &parsed) == WYRELOG_E_OK
         && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
         && g_strcmp0 (value, canonical) == 0;
}

static gboolean
artifact_is_zero (const WylFactArtifactDurabilityArtifact *artifact)
{
  return artifact->role == WYL_FACT_ARTIFACT_DURABILITY_ROLE_INVALID
         && !artifact->present && artifact->identity.domain == 0
         && artifact->identity.object == 0
         && bytes_are_zero (artifact->identity.object_bytes,
             sizeof artifact->identity.object_bytes)
         && artifact->identity.object_width == 0
         && artifact->logical_bytes == 0
         && bytes_are_zero (artifact->sha256, sizeof artifact->sha256);
}

static gboolean
artifact_is_valid (const WylFactArtifactDurabilityArtifact *artifact)
{
  if (artifact->role <= WYL_FACT_ARTIFACT_DURABILITY_ROLE_INVALID
      || artifact->role >= WYL_FACT_ARTIFACT_DURABILITY_ROLE_COUNT
      || (artifact->present != FALSE && artifact->present != TRUE))
    return FALSE;
  if (!artifact->present)
    return artifact->identity.domain == 0 && artifact->identity.object == 0
           && artifact->identity.object_width == 0
           && bytes_are_zero (artifact->identity.object_bytes,
               sizeof artifact->identity.object_bytes)
           && artifact->logical_bytes == 0
           && bytes_are_zero (artifact->sha256, sizeof artifact->sha256);
  return identity_is_present (&artifact->identity)
         && !bytes_are_zero (artifact->sha256, sizeof artifact->sha256);
}

gboolean
wyl_fact_artifact_durability_scope_is_valid
  (const WylFactArtifactDurabilityScope *scope)
{
  if (scope == NULL || !canonical_operation_uuid (scope->operation_uuid)
      || scope->consumer_generation == 0
      || !identity_is_present (&scope->observation.directory_identity)
      || !identity_is_present (&scope->observation.guard_identity)
      || scope->artifact_count == 0
      || scope->artifact_count > WYL_FACT_ARTIFACT_DURABILITY_MAX_ARTIFACTS)
    return FALSE;

  WylFactArtifactDurabilityRole previous =
      WYL_FACT_ARTIFACT_DURABILITY_ROLE_INVALID;
  for (guint i = 0; i < scope->artifact_count; i++) {
    const WylFactArtifactDurabilityArtifact *artifact = &scope->artifacts[i];
    if (!artifact_is_valid (artifact) || artifact->role <= previous)
      return FALSE;
    previous = artifact->role;
  }
  for (guint i = scope->artifact_count;
      i < WYL_FACT_ARTIFACT_DURABILITY_MAX_ARTIFACTS; i++) {
    if (!artifact_is_zero (&scope->artifacts[i]))
      return FALSE;
  }
  return TRUE;
}

static gboolean
boundary_is_directory (WylFactArtifactDurabilityBoundary boundary)
{
  return boundary
         == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY
         || boundary
         == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_RETAIN_DIRECTORY
         || boundary
         == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY;
}

static gboolean
producer_owns_boundary (WylFactArtifactDurabilityProducer producer,
    WylFactArtifactDurabilityBoundary boundary)
{
  if (producer == WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING)
    return boundary
           == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE
           || boundary
           == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY;
  if (producer == WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION)
    return boundary
           == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE
           || boundary
           == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE
           || boundary
           == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_RETAIN_DIRECTORY
           || boundary
           == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY;
  return FALSE;
}

static gboolean
scope_has_roles (const WylFactArtifactDurabilityScope *scope,
    const WylFactArtifactDurabilityRole *roles, guint role_count)
{
  if (scope->artifact_count != role_count)
    return FALSE;
  for (guint i = 0; i < role_count; i++) {
    if (scope->artifacts[i].role != roles[i])
      return FALSE;
  }
  return TRUE;
}

static gboolean
artifacts_describe_same_file
  (const WylFactArtifactDurabilityArtifact *left,
    const WylFactArtifactDurabilityArtifact *right)
{
  return left->present && right->present
         && wyl_fact_artifact_inventory_identity_equal (&left->identity,
             &right->identity)
         && left->logical_bytes == right->logical_bytes
         && memcmp (left->sha256, right->sha256, sizeof left->sha256) == 0;
}

/* V1 records the complete operation-scoped profile at each boundary.  That
 * prevents a valid receipt for one object from being relabelled as evidence
 * for another object in the same directory. */
static gboolean
scope_matches_boundary (const WylFactArtifactDurabilityScope *scope,
    WylFactArtifactDurabilityBoundary boundary)
{
  static const WylFactArtifactDurabilityRole provisioning_roles[] = {
    WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN,
    WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE,
  };
  static const WylFactArtifactDurabilityRole transition_roles[] = {
    WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN,
    WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE,
    WYL_FACT_ARTIFACT_DURABILITY_ROLE_ROLLBACK,
  };
  if (boundary
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE)
    return scope_has_roles (scope, provisioning_roles,
               G_N_ELEMENTS (provisioning_roles))
           && !scope->artifacts[0].present && scope->artifacts[1].present;
  if (boundary
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY)
    return scope_has_roles (scope, provisioning_roles,
               G_N_ELEMENTS (provisioning_roles))
           && scope->artifacts[0].present
           && (!scope->artifacts[1].present
           || artifacts_describe_same_file (&scope->artifacts[0],
           &scope->artifacts[1]));
  if (!scope_has_roles (scope, transition_roles,
      G_N_ELEMENTS (transition_roles)))
    return FALSE;
  switch (boundary) {
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE:
      return scope->artifacts[1].present && !scope->artifacts[2].present;
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE:
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_RETAIN_DIRECTORY:
      return !scope->artifacts[0].present && scope->artifacts[1].present
             && scope->artifacts[2].present;
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY:
      return scope->artifacts[0].present && !scope->artifacts[1].present;
    default:
      return FALSE;
  }
}

static gboolean
outcome_reason_is_legal (WylFactArtifactDurabilityOutcome outcome,
    WylFactArtifactDurabilityRecordReason reason,
    WylFactArtifactDurabilityBoundary boundary)
{
  switch (outcome) {
    case WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN:
      return reason == WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_PREPARED
             || reason
             == WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETION_AMBIGUOUS
             || reason
             == WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_TERMINAL_COMMIT_AMBIGUOUS;
    case WYL_FACT_ARTIFACT_DURABILITY_DURABLE:
      return reason
             == WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED;
    case WYL_FACT_ARTIFACT_DURABILITY_NOT_DURABLE:
      return reason == WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_FAILED;
    case WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED:
      return boundary_is_directory (boundary)
             && reason
             == WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED;
    default:
      return FALSE;
  }
}

gboolean
wyl_fact_artifact_durability_evidence_is_valid
  (const WylFactArtifactDurabilityEvidence *evidence)
{
  return evidence != NULL
         && evidence->version == WYL_FACT_ARTIFACT_DURABILITY_EVIDENCE_V1
         && producer_owns_boundary (evidence->producer, evidence->boundary)
         && outcome_reason_is_legal (evidence->outcome, evidence->reason,
             evidence->boundary)
         && wyl_fact_artifact_durability_scope_is_valid (&evidence->scope)
         && scope_matches_boundary (&evidence->scope, evidence->boundary);
}

static void
classification_unknown (WylFactArtifactDurabilityClassification *result,
    WylFactArtifactDurabilityMatchReason reason)
{
  result->outcome = WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN;
  result->record_reason =
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_INVALID;
  result->match_reason = reason;
}

static gboolean
artifact_shape_equal (const WylFactArtifactDurabilityArtifact *historical,
    const WylFactArtifactDurabilityArtifact *current)
{
  return historical->role == current->role
         && historical->present == current->present;
}

void
wyl_fact_artifact_durability_classify
  (const WylFactArtifactDurabilityEvidence *evidence,
    WylFactArtifactDurabilityProducer expected_producer,
    WylFactArtifactDurabilityBoundary expected_boundary,
    const WylFactArtifactDurabilityScope *current,
    WylFactArtifactDurabilityClassification *out_classification)
{
  if (out_classification == NULL)
    return;
  *out_classification = (WylFactArtifactDurabilityClassification) { 0 };
  if (evidence == NULL) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_EVIDENCE_ABSENT);
    return;
  }
  if (!wyl_fact_artifact_durability_evidence_is_valid (evidence)) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_EVIDENCE_INVALID);
    return;
  }
  if (!producer_owns_boundary (expected_producer, expected_boundary)
      || !wyl_fact_artifact_durability_scope_is_valid (current)
      || !scope_matches_boundary (current, expected_boundary)) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXPECTATION_INVALID);
    return;
  }
  if (evidence->producer != expected_producer) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_PRODUCER_MISMATCH);
    return;
  }
  if (evidence->boundary != expected_boundary) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_BOUNDARY_MISMATCH);
    return;
  }

  const WylFactArtifactDurabilityScope *historical = &evidence->scope;
  if (g_strcmp0 (historical->operation_uuid, current->operation_uuid) != 0) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_OPERATION_STALE);
    return;
  }
  if (historical->consumer_generation != current->consumer_generation) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_GENERATION_STALE);
    return;
  }
  if (!wyl_fact_artifact_inventory_identity_equal
        (&historical->observation.directory_identity,
      &current->observation.directory_identity)) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_DIRECTORY_SUBSTITUTED);
    return;
  }
  if (!wyl_fact_artifact_inventory_identity_equal
        (&historical->observation.guard_identity,
      &current->observation.guard_identity)) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_GUARD_SUBSTITUTED);
    return;
  }
  if (historical->observation.entry_fingerprint
      != current->observation.entry_fingerprint
      || historical->artifact_count != current->artifact_count) {
    classification_unknown (out_classification,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_SET_CHANGED);
    return;
  }

  for (guint i = 0; i < historical->artifact_count; i++) {
    const WylFactArtifactDurabilityArtifact *prior = &historical->artifacts[i];
    const WylFactArtifactDurabilityArtifact *now = &current->artifacts[i];
    if (!artifact_shape_equal (prior, now)) {
      classification_unknown (out_classification,
          WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_SET_CHANGED);
      return;
    }
    if (!prior->present)
      continue;
    if (!wyl_fact_artifact_inventory_identity_equal (&prior->identity,
        &now->identity)) {
      classification_unknown (out_classification,
          WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_IDENTITY_SUBSTITUTED);
      return;
    }
    if (prior->logical_bytes != now->logical_bytes) {
      classification_unknown (out_classification,
          WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_SIZE_CHANGED);
      return;
    }
    if (memcmp (prior->sha256, now->sha256, sizeof prior->sha256) != 0) {
      classification_unknown (out_classification,
          WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_CONTENT_CHANGED);
      return;
    }
  }

  *out_classification = (WylFactArtifactDurabilityClassification) {
    .outcome = evidence->outcome,
    .record_reason = evidence->reason,
    .match_reason = WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXACT,
  };
}

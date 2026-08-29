/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <string.h>

#include "fact/graph-artifact-durability-private.h"

static const gchar operation_uuid[] =
    "01890f3e-7b32-7cc2-98c4-dc0c0c07398f";
static const gchar other_operation_uuid[] =
    "01890f3e-7b32-7cc2-98c4-dc0c0c073990";

static WylFactArtifactInventoryIdentity
identity (guint64 domain, guint64 object)
{
  return (WylFactArtifactInventoryIdentity) {
           .domain = domain,
           .object = object,
  };
}

static WylFactArtifactDurabilityArtifact
present_artifact (WylFactArtifactDurabilityRole role, guint64 object,
    guint64 logical_bytes, guint8 digest_seed)
{
  WylFactArtifactDurabilityArtifact artifact = {
    .role = role,
    .present = TRUE,
    .identity = { .domain = 7, .object = object },
    .logical_bytes = logical_bytes,
  };
  for (guint i = 0; i < G_N_ELEMENTS (artifact.sha256); i++)
    artifact.sha256[i] = digest_seed + (guint8) i;
  return artifact;
}

static WylFactArtifactDurabilityArtifact
absent_artifact (WylFactArtifactDurabilityRole role)
{
  return (WylFactArtifactDurabilityArtifact) { .role = role };
}

static WylFactArtifactDurabilityScope
valid_scope (void)
{
  WylFactArtifactDurabilityScope scope = {
    .consumer_generation = 41,
    .observation = {
      .directory_identity = { .domain = 1, .object = 11 },
      .guard_identity = { .domain = 2, .object = 17 },
      .entry_fingerprint = 23,
    },
    .artifact_count = 3,
  };
  g_strlcpy (scope.operation_uuid, operation_uuid,
      sizeof scope.operation_uuid);
  scope.artifacts[0] = present_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN, 101, 4096, 1);
  scope.artifacts[1] = present_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE, 102, 4096, 2);
  scope.artifacts[2] = absent_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_ROLLBACK);
  return scope;
}

static WylFactArtifactDurabilityEvidence
valid_evidence (void)
{
  return (WylFactArtifactDurabilityEvidence) {
           .version = WYL_FACT_ARTIFACT_DURABILITY_EVIDENCE_V1,
           .producer = WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION,
           .boundary =
               WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
           .outcome = WYL_FACT_ARTIFACT_DURABILITY_DURABLE,
           .reason = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED,
           .scope = valid_scope (),
  };
}

static WylFactArtifactDurabilityScope
scope_for_boundary (WylFactArtifactDurabilityBoundary boundary)
{
  WylFactArtifactDurabilityScope scope = valid_scope ();
  if (boundary
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE)
    return scope;
  if (boundary
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE
      || boundary
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_RETAIN_DIRECTORY) {
    scope.artifacts[0] = absent_artifact
          (WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN);
    scope.artifacts[2] = present_artifact
          (WYL_FACT_ARTIFACT_DURABILITY_ROLE_ROLLBACK, 103, 4096, 3);
    return scope;
  }
  if (boundary
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY) {
    scope.artifacts[1] = absent_artifact
          (WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE);
    return scope;
  }
  scope.artifact_count = 2;
  memset (&scope.artifacts[2], 0, sizeof scope.artifacts[2]);
  if (boundary
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE) {
    scope.artifacts[0] = absent_artifact
          (WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN);
    return scope;
  }
  scope.artifacts[1] = absent_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE);
  return scope;
}

static WylFactArtifactDurabilityProducer
producer_for_boundary (WylFactArtifactDurabilityBoundary boundary)
{
  return boundary
         <= WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY
      ? WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING
      : WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION;
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

static WylFactArtifactDurabilityClassification
classify (const WylFactArtifactDurabilityEvidence *evidence,
    const WylFactArtifactDurabilityScope *scope)
{
  WylFactArtifactDurabilityClassification result = {
    .outcome = WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED,
    .record_reason =
        WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED,
    .match_reason = WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXACT,
  };
  WylFactArtifactDurabilityProducer producer = evidence == NULL
      ? WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION
      : evidence->producer;
  WylFactArtifactDurabilityBoundary boundary = evidence == NULL
      ? WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE
      : evidence->boundary;
  wyl_fact_artifact_durability_classify (evidence, producer, boundary, scope,
      &result);
  return result;
}

static void
assert_unknown (const WylFactArtifactDurabilityClassification *result,
    WylFactArtifactDurabilityMatchReason reason)
{
  g_assert_cmpint (result->outcome, ==,
      WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN);
  g_assert_cmpint (result->record_reason, ==,
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_INVALID);
  g_assert_cmpint (result->match_reason, ==, reason);
}

static void
test_exact_outcome_matrix (void)
{
  WylFactArtifactDurabilityScope current = valid_scope ();
  WylFactArtifactDurabilityEvidence evidence = valid_evidence ();
  struct
  {
    WylFactArtifactDurabilityBoundary boundary;
    WylFactArtifactDurabilityOutcome outcome;
    WylFactArtifactDurabilityRecordReason reason;
  } cases[] = {
    {
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
      WYL_FACT_ARTIFACT_DURABILITY_DURABLE,
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED,
    },
    {
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
      WYL_FACT_ARTIFACT_DURABILITY_NOT_DURABLE,
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_FAILED,
    },
    {
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
      WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN,
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_PREPARED,
    },
    {
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
      WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN,
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETION_AMBIGUOUS,
    },
    {
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY,
      WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED,
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED,
    },
    {
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
      WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN,
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_TERMINAL_COMMIT_AMBIGUOUS,
    },
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
    evidence.boundary = cases[i].boundary;
    evidence.outcome = cases[i].outcome;
    evidence.reason = cases[i].reason;
    evidence.scope = scope_for_boundary (cases[i].boundary);
    current = evidence.scope;
    g_assert_true (wyl_fact_artifact_durability_evidence_is_valid (&evidence));
    WylFactArtifactDurabilityClassification result = classify
          (&evidence, &current);
    g_assert_cmpint (result.outcome, ==, cases[i].outcome);
    g_assert_cmpint (result.record_reason, ==, cases[i].reason);
    g_assert_cmpint (result.match_reason, ==,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXACT);
  }
}

static void
test_complete_boundary_legality_matrix (void)
{
  for (WylFactArtifactDurabilityBoundary boundary =
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE;
      boundary < WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_COUNT; boundary++) {
    WylFactArtifactDurabilityEvidence evidence = {
      .version = WYL_FACT_ARTIFACT_DURABILITY_EVIDENCE_V1,
      .producer = producer_for_boundary (boundary),
      .boundary = boundary,
      .outcome = WYL_FACT_ARTIFACT_DURABILITY_DURABLE,
      .reason = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED,
      .scope = scope_for_boundary (boundary),
    };
    g_assert_true (wyl_fact_artifact_durability_evidence_is_valid (&evidence));
    WylFactArtifactDurabilityClassification result = classify
          (&evidence, &evidence.scope);
    g_assert_cmpint (result.outcome, ==,
        WYL_FACT_ARTIFACT_DURABILITY_DURABLE);
    g_assert_cmpint (result.match_reason, ==,
        WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXACT);

    evidence.outcome = WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN;
    evidence.reason =
        WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_TERMINAL_COMMIT_AMBIGUOUS;
    g_assert_true (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

    evidence.outcome = WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED;
    evidence.reason =
        WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED;
    g_assert_cmpint (wyl_fact_artifact_durability_evidence_is_valid
          (&evidence), ==, boundary_is_directory (boundary));

    evidence.outcome = WYL_FACT_ARTIFACT_DURABILITY_DURABLE;
    evidence.reason =
        WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED;
    evidence.producer = evidence.producer
        == WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING
        ? WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION
        : WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING;
    g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));
  }
}

static void
test_provisioning_publish_platform_shapes (void)
{
  WylFactArtifactDurabilityEvidence evidence = {
    .version = WYL_FACT_ARTIFACT_DURABILITY_EVIDENCE_V1,
    .producer = WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING,
    .boundary =
        WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY,
    .outcome = WYL_FACT_ARTIFACT_DURABILITY_DURABLE,
    .reason = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED,
    .scope = scope_for_boundary
          (WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY),
  };
  /* Windows rename publication consumes the stage name. */
  g_assert_false (evidence.scope.artifacts[1].present);
  g_assert_true (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

  /* POSIX publication retains MAIN and STAGE as two names for one file. */
  evidence.scope.artifacts[1] = evidence.scope.artifacts[0];
  evidence.scope.artifacts[1].role =
      WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE;
  g_assert_true (wyl_fact_artifact_durability_evidence_is_valid (&evidence));
  WylFactArtifactDurabilityClassification result = classify
        (&evidence, &evidence.scope);
  g_assert_cmpint (result.outcome, ==, WYL_FACT_ARTIFACT_DURABILITY_DURABLE);
  g_assert_cmpint (result.match_reason, ==,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXACT);

  WylFactArtifactDurabilityEvidence changed = evidence;
  changed.scope.artifacts[1].identity.object++;
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&changed));

  changed = evidence;
  changed.scope.artifacts[1].logical_bytes++;
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&changed));

  changed = evidence;
  changed.scope.artifacts[1].sha256[0] ^= 0x80;
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&changed));

  changed = evidence;
  changed.scope.artifacts[0] = absent_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN);
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&changed));
}

static void
test_absent_history_stays_unknown (void)
{
  WylFactArtifactDurabilityScope current = valid_scope ();
  WylFactArtifactDurabilityClassification result = classify (NULL, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_EVIDENCE_ABSENT);

  /* A complete current identity/size/digest observation is still current
   * observation, not proof that any historical flush completed. */
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid (&current));
}

static void
test_scope_validation (void)
{
  WylFactArtifactDurabilityScope scope = valid_scope ();
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid (&scope));

  WylFactArtifactDurabilityScope changed = scope;
  changed.consumer_generation = 0;
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.operation_uuid[0] = 'A';
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.observation.directory_identity =
      (WylFactArtifactInventoryIdentity) { 0 };
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.observation.directory_identity = identity (0, 12);
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.observation.directory_identity = identity (9, 0);
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.observation.guard_identity.object_width = 8;
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.artifacts[0].identity = (WylFactArtifactInventoryIdentity) {
    .domain = 9,
    .object_bytes = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .object_width = 16,
  };
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid (&changed));
  changed.artifacts[0].identity.object = 1;
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.artifacts[0].identity = (WylFactArtifactInventoryIdentity) {
    .object_width = 16,
  };
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.artifact_count = WYL_FACT_ARTIFACT_DURABILITY_MAX_ARTIFACTS + 1;
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.artifacts[2].role = WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE;
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  memset (changed.artifacts[0].sha256, 0,
      sizeof changed.artifacts[0].sha256);
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.artifacts[0].present = 2;
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));

  changed = scope;
  changed.artifacts[3] = absent_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_RECOVERY);
  g_assert_false (wyl_fact_artifact_durability_scope_is_valid (&changed));
}

static void
test_record_legality_matrix (void)
{
  WylFactArtifactDurabilityEvidence evidence = valid_evidence ();

  evidence.outcome = WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED;
  evidence.reason =
      WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED;
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

  evidence = valid_evidence ();
  evidence.reason = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_FAILED;
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

  evidence = valid_evidence ();
  evidence.producer = WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING;
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

  evidence = valid_evidence ();
  evidence.version++;
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

  evidence = valid_evidence ();
  evidence.scope.artifacts[1] = absent_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE);
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid
        (&evidence.scope));
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

  evidence = valid_evidence ();
  evidence.scope.artifact_count = 1;
  memset (&evidence.scope.artifacts[1], 0,
      sizeof evidence.scope.artifacts[1]);
  memset (&evidence.scope.artifacts[2], 0,
      sizeof evidence.scope.artifacts[2]);
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid
        (&evidence.scope));
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));

  evidence = valid_evidence ();
  evidence.scope.artifacts[2] = present_artifact
        (WYL_FACT_ARTIFACT_DURABILITY_ROLE_ROLLBACK, 103, 4096, 3);
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid
        (&evidence.scope));
  g_assert_false (wyl_fact_artifact_durability_evidence_is_valid (&evidence));
}

static void
test_expected_boundary_is_bound (void)
{
  WylFactArtifactDurabilityEvidence evidence = valid_evidence ();
  WylFactArtifactDurabilityScope current = scope_for_boundary
        (WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE);
  WylFactArtifactDurabilityClassification result = { 0 };
  wyl_fact_artifact_durability_classify (&evidence,
      WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION,
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE,
      &current, &result);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_BOUNDARY_MISMATCH);

  current = scope_for_boundary
        (WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE);
  wyl_fact_artifact_durability_classify (&evidence,
      WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING,
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE,
      &current, &result);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_PRODUCER_MISMATCH);

  current = valid_scope ();
  wyl_fact_artifact_durability_classify (&evidence,
      WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_INVALID,
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
      &current, &result);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXPECTATION_INVALID);
}

static void
test_scope_mismatch_matrix (void)
{
  WylFactArtifactDurabilityEvidence evidence = valid_evidence ();
  WylFactArtifactDurabilityScope current = evidence.scope;
  WylFactArtifactDurabilityClassification result;

  g_strlcpy (current.operation_uuid, other_operation_uuid,
      sizeof current.operation_uuid);
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_OPERATION_STALE);

  current = evidence.scope;
  current.consumer_generation++;
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_GENERATION_STALE);

  current = evidence.scope;
  current.observation.directory_identity = identity (1, 12);
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_DIRECTORY_SUBSTITUTED);

  current = evidence.scope;
  current.observation.guard_identity = identity (2, 18);
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_GUARD_SUBSTITUTED);

  current = evidence.scope;
  current.observation.entry_fingerprint++;
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_SET_CHANGED);

  current = evidence.scope;
  memset (&current.artifacts[2], 0, sizeof current.artifacts[2]);
  current.artifact_count = 2;
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid (&current));
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXPECTATION_INVALID);
}

static void
test_artifact_substitution_matrix (void)
{
  WylFactArtifactDurabilityEvidence evidence = valid_evidence ();
  WylFactArtifactDurabilityScope current = evidence.scope;
  WylFactArtifactDurabilityClassification result;

  current.artifacts[1].identity.object++;
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_IDENTITY_SUBSTITUTED);

  current = evidence.scope;
  current.artifacts[1].logical_bytes++;
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_SIZE_CHANGED);

  /* Same inode and same size are deliberately insufficient: an in-place
   * rewrite that changes only content must invalidate the receipt. */
  current = evidence.scope;
  current.artifacts[1].sha256[31] ^= 0x80;
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_CONTENT_CHANGED);

  current = evidence.scope;
  current.artifacts[1].present = FALSE;
  current.artifacts[1].identity = (WylFactArtifactInventoryIdentity) { 0 };
  current.artifacts[1].logical_bytes = 0;
  memset (current.artifacts[1].sha256, 0,
      sizeof current.artifacts[1].sha256);
  g_assert_true (wyl_fact_artifact_durability_scope_is_valid (&current));
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXPECTATION_INVALID);
}

static void
test_invalid_inputs_initialize_output (void)
{
  WylFactArtifactDurabilityEvidence evidence = valid_evidence ();
  WylFactArtifactDurabilityScope current = evidence.scope;

  evidence.scope.artifacts[0].identity.object_width = 9;
  WylFactArtifactDurabilityClassification result = classify
        (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_EVIDENCE_INVALID);

  evidence = valid_evidence ();
  memset (current.artifacts[0].sha256, 0,
      sizeof current.artifacts[0].sha256);
  result = classify (&evidence, &current);
  assert_unknown (&result,
      WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXPECTATION_INVALID);

  /* NULL output is an explicitly supported no-op. */
  wyl_fact_artifact_durability_classify (&evidence, evidence.producer,
      evidence.boundary, &current, NULL);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-artifact-durability/exact-outcome-matrix",
      test_exact_outcome_matrix);
  g_test_add_func ("/fact-artifact-durability/boundary-legality-matrix",
      test_complete_boundary_legality_matrix);
  g_test_add_func ("/fact-artifact-durability/provisioning-publish-shapes",
      test_provisioning_publish_platform_shapes);
  g_test_add_func ("/fact-artifact-durability/absent-history",
      test_absent_history_stays_unknown);
  g_test_add_func ("/fact-artifact-durability/scope-validation",
      test_scope_validation);
  g_test_add_func ("/fact-artifact-durability/record-legality",
      test_record_legality_matrix);
  g_test_add_func ("/fact-artifact-durability/expected-boundary",
      test_expected_boundary_is_bound);
  g_test_add_func ("/fact-artifact-durability/scope-mismatch",
      test_scope_mismatch_matrix);
  g_test_add_func ("/fact-artifact-durability/artifact-substitution",
      test_artifact_substitution_matrix);
  g_test_add_func ("/fact-artifact-durability/output-initialization",
      test_invalid_inputs_initialize_output);
  return g_test_run ();
}

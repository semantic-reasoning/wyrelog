/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <string.h>

#include "fact/graph-artifact-durability-journal-codec-private.h"

#define HEADER_BYTES 14u
#define PAYLOAD_PREFIX_BYTES 124u
#define ARTIFACT_BYTES 75u
#define CHECKSUM_BYTES 32u
#define PAYLOAD_LENGTH_OFFSET 10u
#define EVIDENCE_VERSION_OFFSET 14u
#define UUID_OFFSET 19u
#define GENERATION_OFFSET 55u
#define DIRECTORY_WIDTH_OFFSET 95u
#define ARTIFACT_COUNT_OFFSET 137u
#define FIRST_ARTIFACT_OFFSET 138u

static const gchar operation_uuid[] =
    "01890f3e-7b32-7cc2-98c4-dc0c0c07398f";

/* Independently assembled from the frozen field table, including checksum. */
static const gchar golden_v1_hex[] =
    "57594c44524a3100000100000112010101010230313839306633652d37623332"
    "2d376363322d393863342d646330633063303733393866000000000000002900"
    "00000000000001000000000000000b0000000000000000000000000000000000"
    "0000000000000002000000000000001100000000000000000000000000000000"
    "0000000000000000170201000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000601000000000000000700"
    "0000000000006600000000000000000000000000000000000000000000001000"
    "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"
    "5d18d7746685a2f2b0c56bf1109a64a7dbd3646573d3268bd7546c2b19d9cbd5";

static WylFactArtifactInventoryIdentity
windows_identity (guint64 domain, guint8 seed)
{
  WylFactArtifactInventoryIdentity identity = {
    .domain = domain,
    .object_width = 16,
  };
  for (guint i = 0; i < sizeof identity.object_bytes; i++)
    identity.object_bytes[i] = seed + (guint8) i;
  return identity;
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
  for (guint i = 0; i < sizeof artifact.sha256; i++)
    artifact.sha256[i] = digest_seed + (guint8) i;
  return artifact;
}

static WylFactArtifactDurabilityArtifact
absent_artifact (WylFactArtifactDurabilityRole role)
{
  return (WylFactArtifactDurabilityArtifact) { .role = role };
}

static WylFactArtifactDurabilityScope
scope_for_boundary (WylFactArtifactDurabilityBoundary boundary)
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
      == WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE)
    scope.artifacts[0] = absent_artifact
          (WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN);
  else
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

static WylFactArtifactDurabilityEvidence
evidence_for_boundary (WylFactArtifactDurabilityBoundary boundary)
{
  return (WylFactArtifactDurabilityEvidence) {
           .version = WYL_FACT_ARTIFACT_DURABILITY_EVIDENCE_V1,
           .producer = producer_for_boundary (boundary),
           .boundary = boundary,
           .outcome = WYL_FACT_ARTIFACT_DURABILITY_DURABLE,
           .reason =
               WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED,
           .scope = scope_for_boundary (boundary),
  };
}

static guint8
hex_nibble (gchar value)
{
  if (value >= '0' && value <= '9')
    return (guint8) (value - '0');
  if (value >= 'a' && value <= 'f')
    return (guint8) (value - 'a' + 10);
  g_assert_not_reached ();
}

static GBytes *
golden_bytes (void)
{
  gsize hex_length = strlen (golden_v1_hex);
  g_assert_cmpuint (hex_length % 2, ==, 0);
  guint8 *decoded = g_malloc (hex_length / 2);
  for (gsize i = 0; i < hex_length; i += 2)
    decoded[i / 2] = (guint8) ((hex_nibble (golden_v1_hex[i]) << 4)
        | hex_nibble (golden_v1_hex[i + 1]));
  return g_bytes_new_take (decoded, hex_length / 2);
}

static void
write_u32 (guint8 *out, guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static void
rehash (GByteArray *record)
{
  g_assert_cmpuint (record->len, >=, CHECKSUM_BYTES);
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, record->data, record->len - CHECKSUM_BYTES);
  gsize digest_length = CHECKSUM_BYTES;
  g_checksum_get_digest (checksum,
      record->data + record->len - CHECKSUM_BYTES, &digest_length);
  g_assert_cmpuint (digest_length, ==, CHECKSUM_BYTES);
}

static GByteArray *
mutable_copy (GBytes *bytes)
{
  gsize length;
  const guint8 *data = g_bytes_get_data (bytes, &length);
  GByteArray *copy = g_byte_array_sized_new (length);
  g_byte_array_append (copy, data, length);
  return copy;
}

static void
assert_bytes_zero (const guint8 *bytes, gsize length)
{
  for (gsize i = 0; i < length; i++)
    g_assert_cmpuint (bytes[i], ==, 0);
}

static void
assert_identity_zero (const WylFactArtifactInventoryIdentity *identity)
{
  g_assert_cmpuint (identity->domain, ==, 0);
  g_assert_cmpuint (identity->object, ==, 0);
  assert_bytes_zero (identity->object_bytes, sizeof identity->object_bytes);
  g_assert_cmpuint (identity->object_width, ==, 0);
}

static void
assert_evidence_zero (const WylFactArtifactDurabilityEvidence *evidence)
{
  g_assert_cmpuint (evidence->version, ==, 0);
  g_assert_cmpint (evidence->producer, ==, 0);
  g_assert_cmpint (evidence->boundary, ==, 0);
  g_assert_cmpint (evidence->outcome, ==, 0);
  g_assert_cmpint (evidence->reason, ==, 0);
  assert_bytes_zero ((const guint8 *) evidence->scope.operation_uuid,
      sizeof evidence->scope.operation_uuid);
  g_assert_cmpuint (evidence->scope.consumer_generation, ==, 0);
  assert_identity_zero (&evidence->scope.observation.directory_identity);
  assert_identity_zero (&evidence->scope.observation.guard_identity);
  g_assert_cmpuint (evidence->scope.observation.entry_fingerprint, ==, 0);
  g_assert_cmpuint (evidence->scope.artifact_count, ==, 0);
  for (guint i = 0;
      i < WYL_FACT_ARTIFACT_DURABILITY_MAX_ARTIFACTS; i++) {
    g_assert_cmpint (evidence->scope.artifacts[i].role, ==, 0);
    g_assert_false (evidence->scope.artifacts[i].present);
    assert_identity_zero (&evidence->scope.artifacts[i].identity);
    g_assert_cmpuint (evidence->scope.artifacts[i].logical_bytes, ==, 0);
    assert_bytes_zero (evidence->scope.artifacts[i].sha256,
        sizeof evidence->scope.artifacts[i].sha256);
  }
}

static void
assert_policy_and_zero (GBytes *bytes)
{
  WylFactArtifactDurabilityEvidence decoded;
  memset (&decoded, 0xa5, sizeof decoded);
  g_assert_cmpint (wyl_fact_artifact_durability_journal_decode
        (bytes, &decoded), ==, WYRELOG_E_POLICY);
  assert_evidence_zero (&decoded);
}

static void
assert_round_trip (const WylFactArtifactDurabilityEvidence *evidence)
{
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_artifact_durability_journal_encode
        (evidence, &encoded), ==, WYRELOG_E_OK);
  g_assert_nonnull (encoded);

  WylFactArtifactDurabilityEvidence decoded;
  memset (&decoded, 0xa5, sizeof decoded);
  g_assert_cmpint (wyl_fact_artifact_durability_journal_decode
        (encoded, &decoded), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) reencoded = NULL;
  g_assert_cmpint (wyl_fact_artifact_durability_journal_encode
        (&decoded, &reencoded), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (encoded, reencoded));
}

static void
test_golden_v1 (void)
{
  WylFactArtifactDurabilityEvidence evidence = evidence_for_boundary
        (WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE);
  g_autoptr (GBytes) actual = NULL;
  g_autoptr (GBytes) expected = golden_bytes ();
  g_assert_cmpint (wyl_fact_artifact_durability_journal_encode
        (&evidence, &actual), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (actual, expected));
  assert_round_trip (&evidence);
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

static void
test_profiles_and_outcomes (void)
{
  for (WylFactArtifactDurabilityBoundary boundary =
      WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE;
      boundary < WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_COUNT; boundary++) {
    WylFactArtifactDurabilityEvidence evidence =
        evidence_for_boundary (boundary);
    assert_round_trip (&evidence);

    evidence.outcome = WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN;
    evidence.reason = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_PREPARED;
    assert_round_trip (&evidence);
    evidence.reason =
        WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETION_AMBIGUOUS;
    assert_round_trip (&evidence);
    evidence.reason =
        WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_TERMINAL_COMMIT_AMBIGUOUS;
    assert_round_trip (&evidence);

    evidence.outcome = WYL_FACT_ARTIFACT_DURABILITY_NOT_DURABLE;
    evidence.reason =
        WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_FAILED;
    assert_round_trip (&evidence);
    if (boundary_is_directory (boundary)) {
      evidence.outcome = WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED;
      evidence.reason =
          WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED;
      assert_round_trip (&evidence);
    }
  }
}

static void
test_largest_legal_and_windows_identity (void)
{
  WylFactArtifactDurabilityEvidence evidence = evidence_for_boundary
        (WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE);
  g_assert_cmpuint (evidence.scope.artifact_count, ==, 3);
  evidence.scope.consumer_generation = G_MAXUINT64;
  evidence.scope.observation.directory_identity = windows_identity (8, 11);
  evidence.scope.observation.guard_identity = windows_identity (9, 31);
  evidence.scope.artifacts[0].identity = windows_identity (10, 51);
  evidence.scope.artifacts[1].identity = windows_identity (11, 71);
  assert_round_trip (&evidence);
}

static void
test_failure_contract (void)
{
  WylFactArtifactDurabilityEvidence evidence = evidence_for_boundary
        (WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE);
  g_autoptr (GBytes) stale = g_bytes_new_static ("stale", 5);
  GBytes *out = stale;
  evidence.scope.consumer_generation = 0;
  g_assert_cmpint (wyl_fact_artifact_durability_journal_encode
        (&evidence, &out), ==, WYRELOG_E_INVALID);
  g_assert_null (out);
  g_assert_cmpint (wyl_fact_artifact_durability_journal_encode
        (&evidence, NULL), ==, WYRELOG_E_INVALID);

  WylFactArtifactDurabilityEvidence decoded;
  memset (&decoded, 0xa5, sizeof decoded);
  g_assert_cmpint (wyl_fact_artifact_durability_journal_decode
        (NULL, &decoded), ==, WYRELOG_E_INVALID);
  assert_evidence_zero (&decoded);
  g_assert_cmpint (wyl_fact_artifact_durability_journal_decode
        (stale, NULL), ==, WYRELOG_E_INVALID);
}

static void
test_truncation_and_structural_corruption (void)
{
  g_autoptr (GBytes) golden = golden_bytes ();
  gsize length;
  const guint8 *data = g_bytes_get_data (golden, &length);
  for (gsize i = 0; i < length; i++) {
    g_autoptr (GBytes) truncated = g_bytes_new (data, i);
    assert_policy_and_zero (truncated);
  }

  g_autoptr (GByteArray) changed = mutable_copy (golden);
  changed->data[0] ^= 0x01;
  g_autoptr (GBytes) bad_magic = g_byte_array_free_to_bytes
        (g_steal_pointer (&changed));
  assert_policy_and_zero (bad_magic);

  changed = mutable_copy (golden);
  changed->data[length - 1] ^= 0x01;
  g_autoptr (GBytes) bad_checksum = g_byte_array_free_to_bytes
        (g_steal_pointer (&changed));
  assert_policy_and_zero (bad_checksum);

  changed = mutable_copy (golden);
  changed->data[PAYLOAD_LENGTH_OFFSET + 3] ^= 0x01;
  g_autoptr (GBytes) bad_length = g_byte_array_free_to_bytes
        (g_steal_pointer (&changed));
  assert_policy_and_zero (bad_length);

  changed = mutable_copy (golden);
  const guint8 extra = 0;
  g_byte_array_append (changed, &extra, 1);
  g_autoptr (GBytes) trailing = g_byte_array_free_to_bytes
        (g_steal_pointer (&changed));
  assert_policy_and_zero (trailing);

  changed = mutable_copy (golden);
  changed->data[8] = 0;
  changed->data[9] = 2;
  rehash (changed);
  g_autoptr (GBytes) unknown_codec = g_byte_array_free_to_bytes
        (g_steal_pointer (&changed));
  assert_policy_and_zero (unknown_codec);
}

static void
assert_semantic_mutation_rejected (GBytes *golden, gsize offset,
    guint8 replacement)
{
  g_autoptr (GByteArray) changed = mutable_copy (golden);
  changed->data[offset] = replacement;
  rehash (changed);
  g_autoptr (GBytes) bytes = g_byte_array_free_to_bytes
        (g_steal_pointer (&changed));
  assert_policy_and_zero (bytes);
}

static void
test_semantic_corruption_with_valid_checksum (void)
{
  g_autoptr (GBytes) golden = golden_bytes ();
  assert_semantic_mutation_rejected (golden, EVIDENCE_VERSION_OFFSET, 2);
  assert_semantic_mutation_rejected (golden, EVIDENCE_VERSION_OFFSET + 1, 9);
  assert_semantic_mutation_rejected (golden, EVIDENCE_VERSION_OFFSET + 2, 9);
  assert_semantic_mutation_rejected (golden, EVIDENCE_VERSION_OFFSET + 3, 9);
  assert_semantic_mutation_rejected (golden, EVIDENCE_VERSION_OFFSET + 4, 9);
  assert_semantic_mutation_rejected (golden, UUID_OFFSET + 5, 'F');
  assert_semantic_mutation_rejected (golden, GENERATION_OFFSET + 7, 0);
  assert_semantic_mutation_rejected (golden, DIRECTORY_WIDTH_OFFSET, 8);
  assert_semantic_mutation_rejected (golden, FIRST_ARTIFACT_OFFSET + 1, 2);
  assert_semantic_mutation_rejected (golden, FIRST_ARTIFACT_OFFSET, 6);

  g_autoptr (GByteArray) changed = mutable_copy (golden);
  memset (changed->data + FIRST_ARTIFACT_OFFSET + ARTIFACT_BYTES + 43, 0,
      32);
  rehash (changed);
  g_autoptr (GBytes) zero_digest = g_byte_array_free_to_bytes
        (g_steal_pointer (&changed));
  assert_policy_and_zero (zero_digest);
}

static void
append_zero_artifact (GByteArray *record, guint8 role)
{
  guint8 artifact[ARTIFACT_BYTES] = { 0 };
  artifact[0] = role;
  g_byte_array_append (record, artifact, sizeof artifact);
}

static GBytes *
artifact_record (guint8 artifact_count)
{
  g_autoptr (GBytes) golden = golden_bytes ();
  gsize length;
  const guint8 *data = g_bytes_get_data (golden, &length);
  guint32 payload_length = PAYLOAD_PREFIX_BYTES
      + artifact_count * ARTIFACT_BYTES;
  GByteArray *record = g_byte_array_sized_new
        (HEADER_BYTES + payload_length + CHECKSUM_BYTES);
  g_byte_array_append (record, data, FIRST_ARTIFACT_OFFSET);
  write_u32 (record->data + PAYLOAD_LENGTH_OFFSET, payload_length);
  record->data[ARTIFACT_COUNT_OFFSET] = artifact_count;
  for (guint8 i = 0; i < artifact_count; i++)
    append_zero_artifact (record, (guint8) (i % 7 + 1));
  const guint8 checksum[CHECKSUM_BYTES] = { 0 };
  g_byte_array_append (record, checksum, sizeof checksum);
  rehash (record);
  return g_byte_array_free_to_bytes (record);
}

static void
test_frozen_maximum_rejections (void)
{
  g_autoptr (GBytes) seven = artifact_record (7);
  /* Structurally complete, ordered seven-entry input is semantically illegal
   * for every closed V1 producer boundary. */
  assert_policy_and_zero (seven);

  /* Count, payload length, eight complete entries, total length, and checksum
   * agree.  Rejection therefore proves the frozen seven-entry bound rather
   * than an incidental envelope mismatch. */
  g_autoptr (GBytes) count_eight = artifact_record (8);
  g_assert_cmpuint (g_bytes_get_size (count_eight), ==,
      HEADER_BYTES + PAYLOAD_PREFIX_BYTES + 8 * ARTIFACT_BYTES
      + CHECKSUM_BYTES);
  assert_policy_and_zero (count_eight);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/durability-journal/golden-v1", test_golden_v1);
  g_test_add_func ("/fact/durability-journal/profiles-outcomes",
      test_profiles_and_outcomes);
  g_test_add_func ("/fact/durability-journal/largest-legal-windows",
      test_largest_legal_and_windows_identity);
  g_test_add_func ("/fact/durability-journal/failure-contract",
      test_failure_contract);
  g_test_add_func ("/fact/durability-journal/truncation-structure",
      test_truncation_and_structural_corruption);
  g_test_add_func ("/fact/durability-journal/semantic-corruption",
      test_semantic_corruption_with_valid_checksum);
  g_test_add_func ("/fact/durability-journal/frozen-maximum",
      test_frozen_maximum_rejections);
  return g_test_run ();
}

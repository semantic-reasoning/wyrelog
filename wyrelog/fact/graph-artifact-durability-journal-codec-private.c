/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "fact/graph-artifact-durability-journal-codec-private.h"

#include <string.h>

#define V1_CODEC_VERSION 1u
#define V1_UUID_BYTES 36u
#define V1_OBJECT_BYTES 16u
#define V1_DIGEST_BYTES 32u
#define V1_MAX_ARTIFACTS 7u
#define V1_HEADER_BYTES 14u
#define V1_IDENTITY_BYTES (8u + 8u + V1_OBJECT_BYTES + 1u)
#define V1_PAYLOAD_PREFIX_BYTES \
  (5u + V1_UUID_BYTES + 8u + 2u * V1_IDENTITY_BYTES + 8u + 1u)
#define V1_ARTIFACT_BYTES \
  (1u + 1u + V1_IDENTITY_BYTES + 8u + V1_DIGEST_BYTES)
#define V1_MAX_PAYLOAD_BYTES \
  (V1_PAYLOAD_PREFIX_BYTES + V1_MAX_ARTIFACTS * V1_ARTIFACT_BYTES)
#define V1_MAX_RECORD_BYTES \
  (V1_HEADER_BYTES + V1_MAX_PAYLOAD_BYTES + V1_DIGEST_BYTES)

static const guint8 v1_magic[8] = { 'W', 'Y', 'L', 'D', 'R', 'J', '1', 0 };

G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_OPERATION_UUID_BYTES
    == V1_UUID_BYTES + 1u);
G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_SHA256_BYTES == V1_DIGEST_BYTES);
G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_MAX_ARTIFACTS
    == V1_MAX_ARTIFACTS);
G_STATIC_ASSERT (sizeof (guint64) == 8u);
G_STATIC_ASSERT (sizeof (((WylFactArtifactInventoryIdentity *) 0)->object_bytes)
    == V1_OBJECT_BYTES);
G_STATIC_ASSERT (V1_IDENTITY_BYTES == 33u);
G_STATIC_ASSERT (V1_PAYLOAD_PREFIX_BYTES == 124u);
G_STATIC_ASSERT (V1_ARTIFACT_BYTES == 75u);
G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_COUNT == 3);
G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_COUNT == 7);
G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_ROLE_COUNT == 8);
G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_OUTCOME_COUNT == 4);
G_STATIC_ASSERT (WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_COUNT == 7);

typedef struct
{
  const guint8 *cursor;
  const guint8 *end;
} V1Reader;

static void
append_u8 (GByteArray *bytes, guint8 value)
{
  g_byte_array_append (bytes, &value, 1);
}

static void
append_u16 (GByteArray *bytes, guint16 value)
{
  const guint8 encoded[] = { (guint8) (value >> 8), (guint8) value };
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_u32 (GByteArray *bytes, guint32 value)
{
  const guint8 encoded[] = {
    (guint8) (value >> 24),
    (guint8) (value >> 16),
    (guint8) (value >> 8),
    (guint8) value,
  };
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_u64 (GByteArray *bytes, guint64 value)
{
  guint8 encoded[8];
  for (guint i = 0; i < G_N_ELEMENTS (encoded); i++)
    encoded[i] = (guint8) (value >> ((7u - i) * 8u));
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static gboolean
read_bytes (V1Reader *reader, guint8 *out, gsize length)
{
  if ((gsize) (reader->end - reader->cursor) < length)
    return FALSE;
  if (out != NULL)
    memcpy (out, reader->cursor, length);
  reader->cursor += length;
  return TRUE;
}

static gboolean
read_u8 (V1Reader *reader, guint8 *out)
{
  return read_bytes (reader, out, 1);
}

static gboolean
read_u64 (V1Reader *reader, guint64 *out)
{
  guint8 encoded[8];
  if (!read_bytes (reader, encoded, sizeof encoded))
    return FALSE;
  guint64 value = 0;
  for (guint i = 0; i < G_N_ELEMENTS (encoded); i++)
    value = (value << 8) | encoded[i];
  *out = value;
  return TRUE;
}

static guint16
load_u16 (const guint8 *bytes)
{
  return ((guint16) bytes[0] << 8) | bytes[1];
}

static guint32
load_u32 (const guint8 *bytes)
{
  return ((guint32) bytes[0] << 24) | ((guint32) bytes[1] << 16)
         | ((guint32) bytes[2] << 8) | bytes[3];
}

static void
sha256 (const guint8 *data, gsize length, guint8 out[V1_DIGEST_BYTES])
{
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, data, length);
  gsize digest_length = V1_DIGEST_BYTES;
  g_checksum_get_digest (checksum, out, &digest_length);
  g_assert (digest_length == V1_DIGEST_BYTES);
}

static gboolean
producer_to_tag (WylFactArtifactDurabilityProducer value, guint8 *tag)
{
  switch (value) {
    case WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING:
      *tag = 1;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION:
      *tag = 2;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
producer_from_tag (guint8 tag, WylFactArtifactDurabilityProducer *value)
{
  switch (tag) {
    case 1:
      *value = WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING;
      return TRUE;
    case 2:
      *value = WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
boundary_to_tag (WylFactArtifactDurabilityBoundary value, guint8 *tag)
{
  switch (value) {
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE:
      *tag = 1;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY:
      *tag = 2;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE:
      *tag = 3;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE:
      *tag = 4;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_RETAIN_DIRECTORY:
      *tag = 5;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY:
      *tag = 6;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
boundary_from_tag (guint8 tag, WylFactArtifactDurabilityBoundary *value)
{
  switch (tag) {
    case 1:
      *value =
          WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE;
      return TRUE;
    case 2:
      *value =
          WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY;
      return TRUE;
    case 3:
      *value = WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE;
      return TRUE;
    case 4:
      *value = WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE;
      return TRUE;
    case 5:
      *value =
          WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_RETAIN_DIRECTORY;
      return TRUE;
    case 6:
      *value =
          WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
outcome_to_tag (WylFactArtifactDurabilityOutcome value, guint8 *tag)
{
  switch (value) {
    case WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN:
      *tag = 0;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_DURABLE:
      *tag = 1;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_NOT_DURABLE:
      *tag = 2;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED:
      *tag = 3;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
outcome_from_tag (guint8 tag, WylFactArtifactDurabilityOutcome *value)
{
  switch (tag) {
    case 0:
      *value = WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN;
      return TRUE;
    case 1:
      *value = WYL_FACT_ARTIFACT_DURABILITY_DURABLE;
      return TRUE;
    case 2:
      *value = WYL_FACT_ARTIFACT_DURABILITY_NOT_DURABLE;
      return TRUE;
    case 3:
      *value = WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
reason_to_tag (WylFactArtifactDurabilityRecordReason value, guint8 *tag)
{
  switch (value) {
    case WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_PREPARED:
      *tag = 1;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED:
      *tag = 2;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_FAILED:
      *tag = 3;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETION_AMBIGUOUS:
      *tag = 4;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_TERMINAL_COMMIT_AMBIGUOUS:
      *tag = 5;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED:
      *tag = 6;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
reason_from_tag (guint8 tag, WylFactArtifactDurabilityRecordReason *value)
{
  switch (tag) {
    case 1:
      *value = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_PREPARED;
      return TRUE;
    case 2:
      *value = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED;
      return TRUE;
    case 3:
      *value = WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_FAILED;
      return TRUE;
    case 4:
      *value =
          WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETION_AMBIGUOUS;
      return TRUE;
    case 5:
      *value =
          WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_TERMINAL_COMMIT_AMBIGUOUS;
      return TRUE;
    case 6:
      *value =
          WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
role_to_tag (WylFactArtifactDurabilityRole value, guint8 *tag)
{
  switch (value) {
    case WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN:
      *tag = 1;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_ROLE_WAL:
      *tag = 2;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_ROLE_CHECKPOINT:
      *tag = 3;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_ROLE_RECOVERY:
      *tag = 4;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_ROLE_LOCK:
      *tag = 5;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE:
      *tag = 6;
      return TRUE;
    case WYL_FACT_ARTIFACT_DURABILITY_ROLE_ROLLBACK:
      *tag = 7;
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
role_from_tag (guint8 tag, WylFactArtifactDurabilityRole *value)
{
  switch (tag) {
    case 1:
      *value = WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN;
      return TRUE;
    case 2:
      *value = WYL_FACT_ARTIFACT_DURABILITY_ROLE_WAL;
      return TRUE;
    case 3:
      *value = WYL_FACT_ARTIFACT_DURABILITY_ROLE_CHECKPOINT;
      return TRUE;
    case 4:
      *value = WYL_FACT_ARTIFACT_DURABILITY_ROLE_RECOVERY;
      return TRUE;
    case 5:
      *value = WYL_FACT_ARTIFACT_DURABILITY_ROLE_LOCK;
      return TRUE;
    case 6:
      *value = WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE;
      return TRUE;
    case 7:
      *value = WYL_FACT_ARTIFACT_DURABILITY_ROLE_ROLLBACK;
      return TRUE;
    default:
      return FALSE;
  }
}

static void
append_identity (GByteArray *bytes,
    const WylFactArtifactInventoryIdentity *identity)
{
  append_u64 (bytes, identity->domain);
  append_u64 (bytes, identity->object);
  g_byte_array_append (bytes, identity->object_bytes, V1_OBJECT_BYTES);
  append_u8 (bytes, identity->object_width);
}

static gboolean
read_identity (V1Reader *reader,
    WylFactArtifactInventoryIdentity *identity)
{
  return read_u64 (reader, &identity->domain)
         && read_u64 (reader, &identity->object)
         && read_bytes (reader, identity->object_bytes, V1_OBJECT_BYTES)
         && read_u8 (reader, &identity->object_width);
}

wyrelog_error_t
wyl_fact_artifact_durability_journal_encode
  (const WylFactArtifactDurabilityEvidence *evidence, GBytes **out_bytes)
{
  if (out_bytes == NULL)
    return WYRELOG_E_INVALID;
  *out_bytes = NULL;
  if (!wyl_fact_artifact_durability_evidence_is_valid (evidence))
    return WYRELOG_E_INVALID;

  guint8 producer;
  guint8 boundary;
  guint8 outcome;
  guint8 reason;
  if (!producer_to_tag (evidence->producer, &producer)
      || !boundary_to_tag (evidence->boundary, &boundary)
      || !outcome_to_tag (evidence->outcome, &outcome)
      || !reason_to_tag (evidence->reason, &reason))
    return WYRELOG_E_INVALID;

  guint32 payload_length = V1_PAYLOAD_PREFIX_BYTES
      + evidence->scope.artifact_count
      * V1_ARTIFACT_BYTES;
  GByteArray *record = g_byte_array_sized_new
        (V1_HEADER_BYTES + payload_length + V1_DIGEST_BYTES);
  g_byte_array_append (record, v1_magic, sizeof v1_magic);
  append_u16 (record, V1_CODEC_VERSION);
  append_u32 (record, payload_length);
  append_u8 (record, 1);
  append_u8 (record, producer);
  append_u8 (record, boundary);
  append_u8 (record, outcome);
  append_u8 (record, reason);
  g_byte_array_append (record, (const guint8 *) evidence->scope.operation_uuid,
      V1_UUID_BYTES);
  append_u64 (record, evidence->scope.consumer_generation);
  append_identity (record, &evidence->scope.observation.directory_identity);
  append_identity (record, &evidence->scope.observation.guard_identity);
  append_u64 (record, evidence->scope.observation.entry_fingerprint);
  append_u8 (record, (guint8) evidence->scope.artifact_count);

  for (guint i = 0; i < evidence->scope.artifact_count; i++) {
    const WylFactArtifactDurabilityArtifact *artifact =
        &evidence->scope.artifacts[i];
    guint8 role;
    if (!role_to_tag (artifact->role, &role)) {
      g_byte_array_unref (record);
      return WYRELOG_E_INVALID;
    }
    append_u8 (record, role);
    append_u8 (record, artifact->present ? 1 : 0);
    append_identity (record, &artifact->identity);
    append_u64 (record, artifact->logical_bytes);
    g_byte_array_append (record, artifact->sha256, sizeof artifact->sha256);
  }

  guint8 digest[V1_DIGEST_BYTES];
  sha256 (record->data, record->len, digest);
  g_byte_array_append (record, digest, sizeof digest);
  g_assert (record->len <= V1_MAX_RECORD_BYTES);
  *out_bytes = g_byte_array_free_to_bytes (record);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_durability_journal_decode
  (GBytes *bytes, WylFactArtifactDurabilityEvidence *out_evidence)
{
  if (out_evidence == NULL)
    return WYRELOG_E_INVALID;
  *out_evidence = (WylFactArtifactDurabilityEvidence) { 0 };
  if (bytes == NULL)
    return WYRELOG_E_INVALID;

  gsize record_length;
  const guint8 *record = g_bytes_get_data (bytes, &record_length);
  if (record_length < V1_HEADER_BYTES + V1_PAYLOAD_PREFIX_BYTES
      + V1_DIGEST_BYTES
      || record_length > V1_MAX_RECORD_BYTES
      || memcmp (record, v1_magic, sizeof v1_magic) != 0
      || load_u16 (record + 8) != V1_CODEC_VERSION)
    return WYRELOG_E_POLICY;

  guint32 payload_length = load_u32 (record + 10);
  if (payload_length < V1_PAYLOAD_PREFIX_BYTES
      || payload_length > V1_MAX_PAYLOAD_BYTES
      || record_length
      != V1_HEADER_BYTES + payload_length + V1_DIGEST_BYTES)
    return WYRELOG_E_POLICY;

  guint8 computed[V1_DIGEST_BYTES];
  sha256 (record, V1_HEADER_BYTES + payload_length, computed);
  if (memcmp (computed, record + V1_HEADER_BYTES + payload_length,
      sizeof computed) != 0)
    return WYRELOG_E_POLICY;

  WylFactArtifactDurabilityEvidence candidate = { 0 };
  V1Reader reader = {
    .cursor = record + V1_HEADER_BYTES,
    .end = record + V1_HEADER_BYTES + payload_length,
  };
  guint8 evidence_version;
  guint8 producer;
  guint8 boundary;
  guint8 outcome;
  guint8 reason;
  guint8 artifact_count;
  if (!read_u8 (&reader, &evidence_version) || evidence_version != 1
      || !read_u8 (&reader, &producer)
      || !producer_from_tag (producer, &candidate.producer)
      || !read_u8 (&reader, &boundary)
      || !boundary_from_tag (boundary, &candidate.boundary)
      || !read_u8 (&reader, &outcome)
      || !outcome_from_tag (outcome, &candidate.outcome)
      || !read_u8 (&reader, &reason)
      || !reason_from_tag (reason, &candidate.reason)
      || !read_bytes (&reader,
      (guint8 *) candidate.scope.operation_uuid, V1_UUID_BYTES)
      || !read_u64 (&reader, &candidate.scope.consumer_generation)
      || !read_identity (&reader,
      &candidate.scope.observation.directory_identity)
      || !read_identity (&reader, &candidate.scope.observation.guard_identity)
      || !read_u64 (&reader,
      &candidate.scope.observation.entry_fingerprint)
      || !read_u8 (&reader, &artifact_count)
      || artifact_count > V1_MAX_ARTIFACTS
      || payload_length
      != V1_PAYLOAD_PREFIX_BYTES + artifact_count * V1_ARTIFACT_BYTES)
    return WYRELOG_E_POLICY;
  candidate.version = WYL_FACT_ARTIFACT_DURABILITY_EVIDENCE_V1;
  candidate.scope.operation_uuid[V1_UUID_BYTES] = '\0';
  candidate.scope.artifact_count = artifact_count;

  for (guint i = 0; i < artifact_count; i++) {
    WylFactArtifactDurabilityArtifact *artifact =
        &candidate.scope.artifacts[i];
    guint8 role;
    guint8 present;
    if (!read_u8 (&reader, &role)
        || !role_from_tag (role, &artifact->role)
        || !read_u8 (&reader, &present) || present > 1
        || !read_identity (&reader, &artifact->identity)
        || !read_u64 (&reader, &artifact->logical_bytes)
        || !read_bytes (&reader, artifact->sha256, sizeof artifact->sha256))
      return WYRELOG_E_POLICY;
    artifact->present = present == 1;
  }
  if (reader.cursor != reader.end
      || !wyl_fact_artifact_durability_evidence_is_valid (&candidate))
    return WYRELOG_E_POLICY;

  *out_evidence = candidate;
  return WYRELOG_E_OK;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "fact/graph-locator-darwin-private.h"

#include "wyl-id-private.h"

#include <string.h>

#ifdef __APPLE__
#include <sys/attr.h>
#include <sys/mount.h>
#include <unistd.h>
#include <uuid/uuid.h>
#endif

#define VERSION_OFFSET 0u
#define KIND_OFFSET 4u
#define OPERATION_UUID_OFFSET 8u
#define VOLUME_UUID_OFFSET 24u
#define GRAPH_FILE_ID_OFFSET 40u
#define ARTIFACT_FILE_ID_OFFSET 48u

static gboolean
bytes_are_zero (const guint8 *bytes, gsize length)
{
  guint8 accumulator = 0;
  for (gsize i = 0; i < length; i++)
    accumulator |= bytes[i];
  return accumulator == 0;
}

static void
write_u32_be (guint8 *destination, guint32 value)
{
  value = GUINT32_TO_BE (value);
  memcpy (destination, &value, sizeof value);
}

static void
write_u64_be (guint8 *destination, guint64 value)
{
  value = GUINT64_TO_BE (value);
  memcpy (destination, &value, sizeof value);
}

static guint32
read_u32_be (const guint8 *source)
{
  guint32 value;
  memcpy (&value, source, sizeof value);
  return GUINT32_FROM_BE (value);
}

static guint64
read_u64_be (const guint8 *source)
{
  guint64 value;
  memcpy (&value, source, sizeof value);
  return GUINT64_FROM_BE (value);
}

static wyrelog_error_t
operation_uuid_bytes (const gchar *operation_uuid, guint8 out_bytes[16])
{
  if (operation_uuid == NULL || out_bytes == NULL)
    return WYRELOG_E_INVALID;
  wyl_id_t id;
  gchar canonical[WYL_ID_STRING_BUF];
  if (wyl_id_parse (operation_uuid, &id) != WYRELOG_E_OK
      || wyl_id_format (&id, canonical, sizeof canonical) != WYRELOG_E_OK
      || g_strcmp0 (operation_uuid, canonical) != 0
      || (id.bytes[6] & 0xf0u) != 0x70u
      || (id.bytes[8] & 0xc0u) != 0x80u)
    return WYRELOG_E_INVALID;
  memcpy (out_bytes, id.bytes, 16);
  return WYRELOG_E_OK;
}

gboolean
wyl_fact_graph_darwin_operation_uuid_is_valid (const gchar *operation_uuid)
{
  guint8 bytes[16];
  return operation_uuid_bytes (operation_uuid, bytes) == WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_darwin_volume_observation_validate (
  const WylFactGraphDarwinVolumeObservation *observation)
{
  if (observation == NULL)
    return WYRELOG_E_INVALID;
  return observation->apfs && observation->local
         && observation->returned_attributes
         && observation->returned_capabilities
         && observation->returned_volume_uuid
         && observation->fileid64_valid
         && observation->fileid64_supported
         && observation->path_from_id_valid
         && observation->path_from_id_supported
         && !bytes_are_zero (observation->volume_uuid,
             sizeof observation->volume_uuid) ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_graph_darwin_file_id_observation_validate (
  const WylFactGraphDarwinFileIdObservation *observation)
{
  if (observation == NULL)
    return WYRELOG_E_INVALID;
  return observation->returned_attributes && observation->returned_file_id
         && observation->file_id != 0 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_graph_darwin_identity_pair_encode (const gchar *operation_uuid,
    const guint8 graph_volume_uuid[16], guint64 graph_file_id,
    const guint8 artifact_volume_uuid[16], guint64 artifact_file_id,
    WylFactGraphDarwinOperationEvidence *out_evidence)
{
  if (out_evidence != NULL)
    memset (out_evidence, 0, sizeof *out_evidence);
  if (graph_volume_uuid == NULL || artifact_volume_uuid == NULL
      || out_evidence == NULL)
    return WYRELOG_E_INVALID;
  if (memcmp (graph_volume_uuid, artifact_volume_uuid, 16) != 0)
    return WYRELOG_E_POLICY;
  return wyl_fact_graph_darwin_evidence_encode (operation_uuid,
             graph_volume_uuid, graph_file_id, artifact_file_id, out_evidence);
}

wyrelog_error_t
wyl_fact_graph_darwin_evidence_encode (const gchar *operation_uuid,
    const guint8 volume_uuid[16], guint64 graph_file_id,
    guint64 artifact_file_id,
    WylFactGraphDarwinOperationEvidence *out_evidence)
{
  if (out_evidence != NULL)
    memset (out_evidence, 0, sizeof *out_evidence);
  if (volume_uuid == NULL || out_evidence == NULL || graph_file_id == 0
      || artifact_file_id == 0 || graph_file_id == artifact_file_id
      || bytes_are_zero (volume_uuid, 16))
    return WYRELOG_E_INVALID;
  guint8 operation_bytes[16];
  wyrelog_error_t rc = operation_uuid_bytes (operation_uuid, operation_bytes);
  if (rc != WYRELOG_E_OK)
    return rc;

  write_u32_be (out_evidence->bytes + VERSION_OFFSET,
      WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_VERSION);
  write_u32_be (out_evidence->bytes + KIND_OFFSET,
      WYL_FACT_GRAPH_DARWIN_IDENTITY_KIND_FILEID64);
  memcpy (out_evidence->bytes + OPERATION_UUID_OFFSET, operation_bytes, 16);
  memcpy (out_evidence->bytes + VOLUME_UUID_OFFSET, volume_uuid, 16);
  write_u64_be (out_evidence->bytes + GRAPH_FILE_ID_OFFSET, graph_file_id);
  write_u64_be (out_evidence->bytes + ARTIFACT_FILE_ID_OFFSET,
      artifact_file_id);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_darwin_evidence_decode (const guint8 *bytes, gsize length,
    const gchar *expected_operation_uuid,
    WylFactGraphDarwinOperationEvidence *out_evidence)
{
  if (out_evidence != NULL)
    memset (out_evidence, 0, sizeof *out_evidence);
  if (bytes == NULL || expected_operation_uuid == NULL || out_evidence == NULL)
    return WYRELOG_E_INVALID;
  guint8 expected_operation[16];
  if (operation_uuid_bytes (expected_operation_uuid, expected_operation)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  if (length != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE
      || read_u32_be (bytes + VERSION_OFFSET)
      != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_VERSION
      || read_u32_be (bytes + KIND_OFFSET)
      != WYL_FACT_GRAPH_DARWIN_IDENTITY_KIND_FILEID64
      || (bytes[OPERATION_UUID_OFFSET + 6] & 0xf0u) != 0x70u
      || (bytes[OPERATION_UUID_OFFSET + 8] & 0xc0u) != 0x80u
      || memcmp (bytes + OPERATION_UUID_OFFSET, expected_operation, 16) != 0
      || bytes_are_zero (bytes + VOLUME_UUID_OFFSET, 16)
      || read_u64_be (bytes + GRAPH_FILE_ID_OFFSET) == 0
      || read_u64_be (bytes + ARTIFACT_FILE_ID_OFFSET) == 0
      || read_u64_be (bytes + GRAPH_FILE_ID_OFFSET)
      == read_u64_be (bytes + ARTIFACT_FILE_ID_OFFSET))
    return WYRELOG_E_POLICY;
  memcpy (out_evidence->bytes, bytes, sizeof out_evidence->bytes);
  return WYRELOG_E_OK;
}

gboolean
wyl_fact_graph_darwin_evidence_equal (
  const WylFactGraphDarwinOperationEvidence *left,
  const WylFactGraphDarwinOperationEvidence *right)
{
  return left != NULL && right != NULL
         && memcmp (left->bytes, right->bytes, sizeof left->bytes) == 0;
}

#ifdef __APPLE__
typedef struct
{
  guint32 length;
  attribute_set_t returned;
  vol_capabilities_attr_t capabilities;
  uuid_t volume_uuid;
} VolumeAttributeBuffer;

typedef struct
{
  guint32 length;
  attribute_set_t returned;
  guint64 file_id;
} FileIdAttributeBuffer;

typedef struct
{
  guint8 volume_uuid[16];
  guint64 file_id;
} DarwinDescriptorIdentity;

static wyrelog_error_t
volume_contract_for_fd (gint fd, guint8 out_uuid[16])
{
  struct statfs filesystem = { 0 };
  if (fstatfs (fd, &filesystem) != 0)
    return WYRELOG_E_IO;

  struct attrlist attributes = {
    .bitmapcount = ATTR_BIT_MAP_COUNT,
    .commonattr = ATTR_CMN_RETURNED_ATTRS,
    .volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES | ATTR_VOL_UUID,
  };
  VolumeAttributeBuffer buffer = { 0 };
  if (fgetattrlist (fd, &attributes, &buffer, sizeof buffer, 0) != 0)
    return WYRELOG_E_IO;
  const guint32 valid =
      buffer.capabilities.valid[VOL_CAPABILITIES_FORMAT];
  const guint32 supported =
      buffer.capabilities.capabilities[VOL_CAPABILITIES_FORMAT];
  WylFactGraphDarwinVolumeObservation observation = {
    .apfs = strcmp (filesystem.f_fstypename, "apfs") == 0,
    .local = (filesystem.f_flags & MNT_LOCAL) != 0,
    .returned_attributes = buffer.length == sizeof buffer
        && (buffer.returned.commonattr & ATTR_CMN_RETURNED_ATTRS) != 0,
    .returned_capabilities = (buffer.returned.volattr
        & ATTR_VOL_CAPABILITIES) != 0,
    .returned_volume_uuid = (buffer.returned.volattr & ATTR_VOL_UUID) != 0,
    .fileid64_valid = (valid & VOL_CAP_FMT_64BIT_OBJECT_IDS) != 0,
    .fileid64_supported =
        (supported & VOL_CAP_FMT_64BIT_OBJECT_IDS) != 0,
    .path_from_id_valid = (valid & VOL_CAP_FMT_PATH_FROM_ID) != 0,
    .path_from_id_supported =
        (supported & VOL_CAP_FMT_PATH_FROM_ID) != 0,
  };
  memcpy (observation.volume_uuid, buffer.volume_uuid,
      sizeof observation.volume_uuid);
  wyrelog_error_t rc =
      wyl_fact_graph_darwin_volume_observation_validate (&observation);
  if (rc == WYRELOG_E_OK)
    memcpy (out_uuid, observation.volume_uuid, 16);
  return rc;
}

static wyrelog_error_t
file_id_for_fd (gint fd, guint64 *out_file_id)
{
  struct attrlist attributes = {
    .bitmapcount = ATTR_BIT_MAP_COUNT,
    .commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FILEID,
  };
  FileIdAttributeBuffer buffer = { 0 };
  if (fgetattrlist (fd, &attributes, &buffer, sizeof buffer, 0) != 0)
    return WYRELOG_E_IO;
  WylFactGraphDarwinFileIdObservation observation = {
    .returned_attributes = buffer.length == sizeof buffer
        && (buffer.returned.commonattr & ATTR_CMN_RETURNED_ATTRS) != 0,
    .returned_file_id = (buffer.returned.commonattr & ATTR_CMN_FILEID) != 0,
    .file_id = buffer.file_id,
  };
  wyrelog_error_t rc =
      wyl_fact_graph_darwin_file_id_observation_validate (&observation);
  if (rc == WYRELOG_E_OK)
    *out_file_id = observation.file_id;
  return rc;
}

static wyrelog_error_t
identity_for_fd (gint fd, DarwinDescriptorIdentity *out_identity)
{
  DarwinDescriptorIdentity identity = { 0 };
  wyrelog_error_t rc = volume_contract_for_fd (fd, identity.volume_uuid);
  if (rc == WYRELOG_E_OK)
    rc = file_id_for_fd (fd, &identity.file_id);
  if (rc == WYRELOG_E_OK)
    *out_identity = identity;
  return rc;
}

wyrelog_error_t
wyl_fact_graph_darwin_volume_preflight (gint directory_fd)
{
  if (directory_fd < 0)
    return WYRELOG_E_INVALID;
  guint8 volume_uuid[16];
  return volume_contract_for_fd (directory_fd, volume_uuid);
}

wyrelog_error_t
wyl_fact_graph_darwin_evidence_capture (gint graph_directory_fd,
    gint artifact_fd, const gchar *operation_uuid,
    WylFactGraphDarwinOperationEvidence *out_evidence)
{
  if (out_evidence != NULL)
    memset (out_evidence, 0, sizeof *out_evidence);
  if (graph_directory_fd < 0 || artifact_fd < 0 || out_evidence == NULL)
    return WYRELOG_E_INVALID;
  DarwinDescriptorIdentity graph = { 0 };
  DarwinDescriptorIdentity artifact = { 0 };
  wyrelog_error_t rc = identity_for_fd (graph_directory_fd, &graph);
  if (rc == WYRELOG_E_OK)
    rc = identity_for_fd (artifact_fd, &artifact);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_darwin_identity_pair_encode (operation_uuid,
            graph.volume_uuid, graph.file_id, artifact.volume_uuid,
            artifact.file_id, out_evidence);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_darwin_evidence_compare (gint graph_directory_fd,
    gint artifact_fd, const gchar *operation_uuid,
    const WylFactGraphDarwinOperationEvidence *expected_evidence)
{
  if (expected_evidence == NULL)
    return WYRELOG_E_INVALID;
  WylFactGraphDarwinOperationEvidence decoded = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_darwin_evidence_decode (
    expected_evidence->bytes, sizeof expected_evidence->bytes,
    operation_uuid, &decoded);
  WylFactGraphDarwinOperationEvidence actual = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_darwin_evidence_capture (graph_directory_fd,
            artifact_fd, operation_uuid, &actual);
  if (rc == WYRELOG_E_OK
      && !wyl_fact_graph_darwin_evidence_equal (&decoded, &actual))
    rc = WYRELOG_E_POLICY;
  return rc;
}
#endif

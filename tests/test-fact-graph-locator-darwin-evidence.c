/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "fact/graph-locator-darwin-private.h"

static const gchar operation_uuid[] =
    "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";

static WylFactGraphDarwinOperationEvidence
valid_evidence (void)
{
  const guint8 volume_uuid[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_encode (operation_uuid,
      volume_uuid, G_GUINT64_CONSTANT (0x0102030405060708),
      G_GUINT64_CONSTANT (0x1112131415161718), &evidence), ==,
      WYRELOG_E_OK);
  return evidence;
}

static void
test_golden_encoding (void)
{
  const guint8 expected[WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE] = {
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x01, 0x89, 0x0f, 0x47, 0x3c, 0x4b, 0x7c, 0xc2,
    0xb8, 0xc4, 0xdc, 0x0c, 0x0c, 0x07, 0x05, 0x44,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  };
  WylFactGraphDarwinOperationEvidence evidence = valid_evidence ();
  g_assert_cmpmem (evidence.bytes, sizeof evidence.bytes, expected,
      sizeof expected);

  WylFactGraphDarwinOperationEvidence decoded = { 0 };
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (evidence.bytes,
      sizeof evidence.bytes, operation_uuid, &decoded), ==, WYRELOG_E_OK);
  g_assert_true (wyl_fact_graph_darwin_evidence_equal (&evidence, &decoded));
}

static void
assert_decode_rejected (const guint8 *bytes, gsize length,
    const gchar *expected_operation_uuid)
{
  WylFactGraphDarwinOperationEvidence decoded;
  memset (&decoded, 0xa5, sizeof decoded);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (bytes, length,
      expected_operation_uuid, &decoded), ==, WYRELOG_E_POLICY);
  const WylFactGraphDarwinOperationEvidence zero = { 0 };
  g_assert_cmpmem (&decoded, sizeof decoded, &zero, sizeof zero);
}

static void
test_strict_decode (void)
{
  WylFactGraphDarwinOperationEvidence evidence = valid_evidence ();

  assert_decode_rejected (evidence.bytes, sizeof evidence.bytes - 1,
      operation_uuid);
  guint8 trailing[sizeof evidence.bytes + 1];
  memcpy (trailing, evidence.bytes, sizeof evidence.bytes);
  trailing[sizeof evidence.bytes] = 0;
  assert_decode_rejected (trailing, sizeof trailing, operation_uuid);

  const gsize offsets[] = { 3, 7, 24, 40, 48 };
  for (gsize i = 0; i < G_N_ELEMENTS (offsets); i++) {
    WylFactGraphDarwinOperationEvidence malformed = evidence;
    if (offsets[i] == 24)
      memset (malformed.bytes + 24, 0, 16);
    else if (offsets[i] == 40 || offsets[i] == 48)
      memset (malformed.bytes + offsets[i], 0, 8);
    else
      malformed.bytes[offsets[i]]++;
    assert_decode_rejected (malformed.bytes, sizeof malformed.bytes,
        operation_uuid);
  }

  WylFactGraphDarwinOperationEvidence equal_ids = evidence;
  memcpy (equal_ids.bytes + 48, equal_ids.bytes + 40, 8);
  assert_decode_rejected (equal_ids.bytes, sizeof equal_ids.bytes,
      operation_uuid);

  WylFactGraphDarwinOperationEvidence invalid_version = evidence;
  invalid_version.bytes[14] = 0x6c;
  assert_decode_rejected (invalid_version.bytes, sizeof invalid_version.bytes,
      operation_uuid);
  WylFactGraphDarwinOperationEvidence invalid_variant = evidence;
  invalid_variant.bytes[16] = 0x38;
  assert_decode_rejected (invalid_variant.bytes, sizeof invalid_variant.bytes,
      operation_uuid);
  assert_decode_rejected (evidence.bytes, sizeof evidence.bytes,
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070545");
}

static void
test_encode_rejects_invalid_fields (void)
{
  guint8 volume_uuid[16] = { 0 };
  WylFactGraphDarwinOperationEvidence evidence;
  memset (&evidence, 0xa5, sizeof evidence);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_encode (operation_uuid,
      volume_uuid, 1, 2, &evidence), ==, WYRELOG_E_INVALID);
  const WylFactGraphDarwinOperationEvidence zero = { 0 };
  g_assert_cmpmem (&evidence, sizeof evidence, &zero, sizeof zero);

  volume_uuid[0] = 1;
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_encode (operation_uuid,
      volume_uuid, 0, 2, &evidence), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_encode (operation_uuid,
      volume_uuid, 1, 0, &evidence), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_encode (operation_uuid,
      volume_uuid, 1, 1, &evidence), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_encode (
        "01890f47-3c4b-6cc2-b8c4-dc0c0c070544", volume_uuid, 1, 2,
        &evidence), ==, WYRELOG_E_INVALID);
}

static WylFactGraphDarwinVolumeObservation
valid_volume_observation (void)
{
  WylFactGraphDarwinVolumeObservation observation = {
    .apfs = TRUE,
    .local = TRUE,
    .returned_attributes = TRUE,
    .returned_capabilities = TRUE,
    .returned_volume_uuid = TRUE,
    .fileid64_valid = TRUE,
    .fileid64_supported = TRUE,
    .path_from_id_valid = TRUE,
    .path_from_id_supported = TRUE,
  };
  observation.volume_uuid[0] = 1;
  return observation;
}

static void
test_native_observation_classifier (void)
{
  WylFactGraphDarwinVolumeObservation observation =
      valid_volume_observation ();
  g_assert_cmpint (wyl_fact_graph_darwin_volume_observation_validate
        (&observation), ==, WYRELOG_E_OK);
  gboolean *requirements[] = {
    &observation.apfs,
    &observation.local,
    &observation.returned_attributes,
    &observation.returned_capabilities,
    &observation.returned_volume_uuid,
    &observation.fileid64_valid,
    &observation.fileid64_supported,
    &observation.path_from_id_valid,
    &observation.path_from_id_supported,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (requirements); i++) {
    *requirements[i] = FALSE;
    g_assert_cmpint (wyl_fact_graph_darwin_volume_observation_validate
          (&observation), ==, WYRELOG_E_POLICY);
    *requirements[i] = TRUE;
  }
  memset (observation.volume_uuid, 0, sizeof observation.volume_uuid);
  g_assert_cmpint (wyl_fact_graph_darwin_volume_observation_validate
        (&observation), ==, WYRELOG_E_POLICY);

  WylFactGraphDarwinFileIdObservation file_id = {
    .returned_attributes = TRUE,
    .returned_file_id = TRUE,
    .file_id = 1,
  };
  g_assert_cmpint (wyl_fact_graph_darwin_file_id_observation_validate
        (&file_id), ==, WYRELOG_E_OK);
  file_id.returned_attributes = FALSE;
  g_assert_cmpint (wyl_fact_graph_darwin_file_id_observation_validate
        (&file_id), ==, WYRELOG_E_POLICY);
  file_id.returned_attributes = TRUE;
  file_id.returned_file_id = FALSE;
  g_assert_cmpint (wyl_fact_graph_darwin_file_id_observation_validate
        (&file_id), ==, WYRELOG_E_POLICY);
  file_id.returned_file_id = TRUE;
  file_id.file_id = 0;
  g_assert_cmpint (wyl_fact_graph_darwin_file_id_observation_validate
        (&file_id), ==, WYRELOG_E_POLICY);
}

static void
test_cross_volume_rejected (void)
{
  guint8 graph_volume[16] = { 1 };
  guint8 artifact_volume[16] = { 2 };
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  g_assert_cmpint (wyl_fact_graph_darwin_identity_pair_encode (operation_uuid,
      graph_volume, 1, artifact_volume, 2, &evidence), ==, WYRELOG_E_POLICY);
  memcpy (artifact_volume, graph_volume, sizeof graph_volume);
  g_assert_cmpint (wyl_fact_graph_darwin_identity_pair_encode (operation_uuid,
      graph_volume, 1, artifact_volume, 2, &evidence), ==, WYRELOG_E_OK);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/darwin-evidence/golden-encoding",
      test_golden_encoding);
  g_test_add_func ("/fact/darwin-evidence/strict-decode",
      test_strict_decode);
  g_test_add_func ("/fact/darwin-evidence/encode-rejects-invalid-fields",
      test_encode_rejects_invalid_fields);
  g_test_add_func ("/fact/darwin-evidence/native-observation-classifier",
      test_native_observation_classifier);
  g_test_add_func ("/fact/darwin-evidence/cross-volume-rejected",
      test_cross_volume_rejected);
  return g_test_run ();
}

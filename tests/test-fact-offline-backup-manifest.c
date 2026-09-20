/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/fact/offline-backup-manifest-private.h"

static void
round_trip (void)
{
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init
        (&manifest, "tenant-a", 7), ==, WYRELOG_E_OK);
  WylFactOfflineBackupArtifact artifact = {
    .graph_id = "orders",
    .store_uuid = "00000000-0000-4000-8000-000000000001",
    .format_version = 1,
    .path_encoding_version = 1,
    .schema_digest = "schema-digest",
    .logical_bytes = 12,
    .physical_bytes = 4096,
    .checksum = "file-checksum",
  };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add
        (&manifest, &artifact), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode
        (&manifest, &encoded), ==, WYRELOG_E_OK);
  WylFactOfflineBackupManifest decoded = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode
        (encoded, &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpstr (decoded.tenant_id, ==, "tenant-a");
  g_assert_cmpuint (decoded.policy_generation, ==, 7);
  g_assert_cmpuint (decoded.artifacts->len, ==, 1);
  WylFactOfflineBackupArtifact *actual = g_ptr_array_index
        (decoded.artifacts, 0);
  g_assert_cmpstr (actual->graph_id, ==, "orders");
  g_assert_cmpstr (actual->store_uuid, ==,
      "00000000-0000-4000-8000-000000000001");
  g_assert_cmpuint (actual->physical_bytes, ==, 4096);
  wyl_fact_offline_backup_manifest_clear (&decoded);
  wyl_fact_offline_backup_manifest_clear (&manifest);
}

static void
rejects_duplicates_and_unknown_fields (void)
{
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init
        (&manifest, "tenant-a", 1), ==, WYRELOG_E_OK);
  WylFactOfflineBackupArtifact artifact = {
    .graph_id = "orders", .store_uuid = "uuid",
    .schema_digest = "schema", .checksum = "checksum",
  };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add
        (&manifest, &artifact), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add
        (&manifest, &artifact), ==, WYRELOG_E_POLICY);
  g_autoptr (GBytes) invalid = g_bytes_new_static
        ("wyrelog-offline-backup-manifest\nversion=1\nunknown=x\n", 57);
  WylFactOfflineBackupManifest decoded = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_decode
        (invalid, &decoded), ==, WYRELOG_E_POLICY);
  wyl_fact_offline_backup_manifest_clear (&manifest);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/offline-backup-manifest/round-trip", round_trip);
  g_test_add_func ("/fact/offline-backup-manifest/rejects-invalid",
      rejects_duplicates_and_unknown_fields);
  return g_test_run ();
}

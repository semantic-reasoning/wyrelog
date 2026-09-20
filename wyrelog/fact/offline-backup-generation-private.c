/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-backup-generation-private.h"

#include "fact/offline-backup-manifest-private.h"

typedef struct
{
  const WylFactOfflineBackupDestination *destination;
  gpointer user_data;
  const gchar *graph_id;
  GChecksum *checksum;
} CopyContext;

static wyrelog_error_t
copy_to_destination (guint64 offset, const guint8 *bytes, gsize length,
    gpointer user_data)
{
  CopyContext *context = user_data;
  wyrelog_error_t rc = context->destination->write_artifact
        (context->graph_id, offset, bytes, length, context->user_data);
  if (rc == WYRELOG_E_OK)
    g_checksum_update (context->checksum, bytes, length);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_backup_generate (WylFactOfflineBackupSource *source,
    const WylFactOfflineBackupDestination *destination, gpointer user_data)
{
  if (source == NULL || destination == NULL
      || destination->begin_artifact == NULL
      || destination->write_artifact == NULL
      || destination->finish_artifact == NULL
      || destination->publish_manifest == NULL
      || destination->abort == NULL)
    return WYRELOG_E_INVALID;

  WylFactOfflineBackupManifest manifest = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_backup_manifest_init (&manifest,
          wyl_fact_offline_backup_source_tenant_id (source),
          wyl_fact_offline_backup_source_policy_generation (source));
  for (gsize i = 0; rc == WYRELOG_E_OK
      && i < wyl_fact_offline_backup_source_count (source); i++) {
    WylFactOfflineBackupSourceArtifact source_artifact = { 0 };
    if (!wyl_fact_offline_backup_source_get (source, i, &source_artifact)) {
      rc = WYRELOG_E_INTERNAL;
      break;
    }
    rc = destination->begin_artifact (source_artifact.graph_id,
            source_artifact.logical_bytes, user_data);
    g_autoptr (GChecksum) checksum = NULL;
    if (rc == WYRELOG_E_OK) {
      checksum = g_checksum_new (G_CHECKSUM_SHA256);
      if (checksum == NULL)
        rc = WYRELOG_E_NOMEM;
    }
    guint64 copied = 0;
    if (rc == WYRELOG_E_OK) {
      CopyContext context = {
        .destination = destination,
        .user_data = user_data,
        .graph_id = source_artifact.graph_id,
        .checksum = checksum,
      };
      rc = wyl_fact_offline_backup_source_copy_to_sink (source, i,
              copy_to_destination, &context, &copied);
    }
    g_autofree gchar *checksum_text = NULL;
    if (rc == WYRELOG_E_OK && copied != source_artifact.logical_bytes)
      rc = WYRELOG_E_BUSY;
    if (rc == WYRELOG_E_OK) {
      checksum_text = g_strdup_printf ("sha256:%s",
              g_checksum_get_string (checksum));
      if (checksum_text == NULL)
        rc = WYRELOG_E_NOMEM;
    }
    if (rc == WYRELOG_E_OK)
      rc = destination->finish_artifact (source_artifact.graph_id,
              checksum_text, user_data);
    if (rc == WYRELOG_E_OK) {
      WylFactOfflineBackupArtifact artifact = {
        .graph_id = (gchar *) source_artifact.graph_id,
        .store_uuid = (gchar *) source_artifact.store_uuid,
        .format_version = source_artifact.format_version,
        .path_encoding_version = source_artifact.path_encoding_version,
        .schema_digest = (gchar *) source_artifact.schema_digest,
        .logical_bytes = source_artifact.logical_bytes,
        .physical_bytes = source_artifact.physical_bytes,
        .checksum = checksum_text,
      };
      rc = wyl_fact_offline_backup_manifest_add (&manifest, &artifact);
    }
  }

  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_source_revalidate (source);
  g_autoptr (GBytes) manifest_bytes = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_manifest_encode (&manifest, &manifest_bytes);
  if (rc == WYRELOG_E_OK) {
    WylFactOfflineBackupPublishOutcome outcome =
        destination->publish_manifest (manifest_bytes, user_data);
    if (outcome == WYL_FACT_OFFLINE_BACKUP_PUBLISHED) {
      wyl_fact_offline_backup_manifest_clear (&manifest);
      return WYRELOG_E_OK;
    }
    rc = WYRELOG_E_IO;
  }
  destination->abort (user_data);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  return rc;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_FACT_OFFLINE_BACKUP_MANIFEST_VERSION 1u

typedef struct
{
  gchar *graph_id;
  gchar *store_uuid;
  guint64 format_version;
  guint64 path_encoding_version;
  gchar *schema_digest;
  guint64 logical_bytes;
  guint64 physical_bytes;
  gchar *checksum;
} WylFactOfflineBackupArtifact;

typedef struct
{
  guint version;
  gchar *tenant_id;
  guint64 policy_generation;
  GPtrArray *artifacts;
} WylFactOfflineBackupManifest;

void wyl_fact_offline_backup_artifact_free
  (WylFactOfflineBackupArtifact *artifact);
void wyl_fact_offline_backup_manifest_clear
  (WylFactOfflineBackupManifest *manifest);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylFactOfflineBackupManifest,
    wyl_fact_offline_backup_manifest_clear)

wyrelog_error_t wyl_fact_offline_backup_manifest_init
  (WylFactOfflineBackupManifest *manifest, const gchar *tenant_id,
    guint64 policy_generation);
wyrelog_error_t wyl_fact_offline_backup_manifest_add
  (WylFactOfflineBackupManifest *manifest,
    const WylFactOfflineBackupArtifact *artifact);
wyrelog_error_t wyl_fact_offline_backup_manifest_encode
  (const WylFactOfflineBackupManifest *manifest, GBytes **out_bytes);
wyrelog_error_t wyl_fact_offline_backup_manifest_decode
  (GBytes *bytes, WylFactOfflineBackupManifest *out_manifest);

G_END_DECLS;

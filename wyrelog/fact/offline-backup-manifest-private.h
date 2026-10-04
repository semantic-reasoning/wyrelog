/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_FACT_OFFLINE_BACKUP_MANIFEST_LEGACY_VERSION 1u
#define WYL_FACT_OFFLINE_BACKUP_MANIFEST_VERSION 2u

typedef struct
{
  gchar *namespace_id;
  gchar *relation_name;
  guint32 schema_version;
} WylFactOfflineBackupSchemaSelection;

void wyl_fact_offline_backup_schema_selection_free
  (WylFactOfflineBackupSchemaSelection *selection);
GPtrArray *wyl_fact_offline_backup_schema_selections_copy
  (const GPtrArray *source);
gchar *wyl_fact_offline_backup_schema_selections_encode
  (const GPtrArray *selections);
GPtrArray *wyl_fact_offline_backup_schema_selections_decode
  (const gchar *encoded);

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
  /* Authenticated active relation-version vector; empty for legacy backups. */
  GPtrArray *schema_selections;
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

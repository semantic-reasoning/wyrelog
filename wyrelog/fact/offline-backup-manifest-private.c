/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-backup-manifest-private.h"

#include <errno.h>
#include <string.h>

static gchar *encode (const gchar *value)
{
  return g_base64_encode ((const guchar *) value, strlen (value));
}

static gchar *decode (const gchar *value)
{
  gsize length = 0;
  g_autofree guchar *data = g_base64_decode (value, &length);
  if (data == NULL || memchr (data, '\0', length) != NULL)
    return NULL;
  return g_strndup ((const gchar *) data, length);
}

static gboolean parse_u64 (const gchar *value, guint64 *out)
{
  gchar *end = NULL;
  errno = 0;
  *out = g_ascii_strtoull (value, &end, 10);
  return errno == 0 && end != value && *end == '\0';
}

void wyl_fact_offline_backup_artifact_free
  (WylFactOfflineBackupArtifact *artifact)
{
  if (artifact == NULL)
    return;
  g_free (artifact->graph_id);
  g_free (artifact->store_uuid);
  g_free (artifact->schema_digest);
  g_free (artifact->checksum);
  g_free (artifact);
}

void wyl_fact_offline_backup_manifest_clear
  (WylFactOfflineBackupManifest *manifest)
{
  if (manifest == NULL)
    return;
  g_free (manifest->tenant_id);
  g_clear_pointer (&manifest->artifacts, g_ptr_array_unref);
  memset (manifest, 0, sizeof (*manifest));
}

wyrelog_error_t wyl_fact_offline_backup_manifest_init
  (WylFactOfflineBackupManifest *manifest, const gchar *tenant_id,
    guint64 policy_generation)
{
  if (manifest == NULL || tenant_id == NULL || *tenant_id == '\0'
      || policy_generation == 0)
    return WYRELOG_E_INVALID;
  wyl_fact_offline_backup_manifest_clear (manifest);
  manifest->version = WYL_FACT_OFFLINE_BACKUP_MANIFEST_VERSION;
  manifest->tenant_id = g_strdup (tenant_id);
  manifest->policy_generation = policy_generation;
  manifest->artifacts = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_backup_artifact_free);
  return manifest->tenant_id == NULL || manifest->artifacts == NULL
      ? WYRELOG_E_NOMEM : WYRELOG_E_OK;
}

wyrelog_error_t wyl_fact_offline_backup_manifest_add
  (WylFactOfflineBackupManifest *manifest,
    const WylFactOfflineBackupArtifact *artifact)
{
  if (manifest == NULL || manifest->artifacts == NULL || artifact == NULL
      || artifact->graph_id == NULL || artifact->store_uuid == NULL
      || artifact->schema_digest == NULL || artifact->checksum == NULL)
    return WYRELOG_E_INVALID;
  for (guint i = 0; i < manifest->artifacts->len; i++) {
    WylFactOfflineBackupArtifact *old = g_ptr_array_index
          (manifest->artifacts, i);
    if (g_strcmp0 (old->graph_id, artifact->graph_id) == 0)
      return WYRELOG_E_POLICY;
  }
  WylFactOfflineBackupArtifact *copy = g_new0
        (WylFactOfflineBackupArtifact, 1);
  copy->graph_id = g_strdup (artifact->graph_id);
  copy->store_uuid = g_strdup (artifact->store_uuid);
  copy->schema_digest = g_strdup (artifact->schema_digest);
  copy->checksum = g_strdup (artifact->checksum);
  copy->format_version = artifact->format_version;
  copy->path_encoding_version = artifact->path_encoding_version;
  copy->logical_bytes = artifact->logical_bytes;
  copy->physical_bytes = artifact->physical_bytes;
  if (copy->graph_id == NULL || copy->store_uuid == NULL
      || copy->schema_digest == NULL || copy->checksum == NULL) {
    wyl_fact_offline_backup_artifact_free (copy);
    return WYRELOG_E_NOMEM;
  }
  g_ptr_array_add (manifest->artifacts, copy);
  return WYRELOG_E_OK;
}

wyrelog_error_t wyl_fact_offline_backup_manifest_encode
  (const WylFactOfflineBackupManifest *manifest, GBytes **out_bytes)
{
  if (out_bytes != NULL)
    *out_bytes = NULL;
  if (manifest == NULL || out_bytes == NULL
      || manifest->version != WYL_FACT_OFFLINE_BACKUP_MANIFEST_VERSION
      || manifest->tenant_id == NULL || manifest->artifacts == NULL)
    return WYRELOG_E_INVALID;
  g_autofree gchar *tenant = encode (manifest->tenant_id);
  GString *text = g_string_new ("wyrelog-offline-backup-manifest\n");
  g_string_append_printf (text, "version=%u\ntenant=%s\npolicy_generation=%"
      G_GUINT64_FORMAT "\nartifact_count=%u\n", manifest->version, tenant,
      manifest->policy_generation, manifest->artifacts->len);
  for (guint i = 0; i < manifest->artifacts->len; i++) {
    WylFactOfflineBackupArtifact *a = g_ptr_array_index (manifest->artifacts, i);
    g_autofree gchar *graph = encode (a->graph_id);
    g_autofree gchar *uuid = encode (a->store_uuid);
    g_autofree gchar *schema = encode (a->schema_digest);
    g_autofree gchar *checksum = encode (a->checksum);
    g_string_append_printf (text, "artifact=%s,%s,%" G_GUINT64_FORMAT ",%"
        G_GUINT64_FORMAT ",%s,%" G_GUINT64_FORMAT ",%" G_GUINT64_FORMAT ",%s\n",
        graph, uuid, a->format_version, a->path_encoding_version, schema,
        a->logical_bytes, a->physical_bytes, checksum);
  }
  gsize length = text->len;
  gchar *data = g_string_free (text, FALSE);
  *out_bytes = g_bytes_new_take (data, length);
  return WYRELOG_E_OK;
}

wyrelog_error_t wyl_fact_offline_backup_manifest_decode
  (GBytes *bytes, WylFactOfflineBackupManifest *out_manifest)
{
  if (bytes == NULL || out_manifest == NULL)
    return WYRELOG_E_INVALID;
  wyl_fact_offline_backup_manifest_clear (out_manifest);
  gsize length = 0;
  const gchar *raw = g_bytes_get_data (bytes, &length);
  g_autofree gchar *text = g_strndup (raw, length);
  if (text == NULL || !g_str_has_suffix (text, "\n"))
    return WYRELOG_E_POLICY;
  g_auto (GStrv) lines = g_strsplit (text, "\n", -1);
  if (g_strcmp0 (lines[0], "wyrelog-offline-backup-manifest") != 0)
    return WYRELOG_E_POLICY;
  guint version = 0, count = 0;
  guint64 generation = 0;
  g_autofree gchar *tenant = NULL;
  for (guint i = 1; lines[i][0] != '\0'; i++) {
    gchar **pair = g_strsplit (lines[i], "=", 2);
    guint64 value = 0;
    gboolean known = FALSE;
    if (pair[1] == NULL)
      known = FALSE;
    else if (g_strcmp0 (pair[0], "version") == 0)
      known = parse_u64 (pair[1], &value), version = (guint) value;
    else if (g_strcmp0 (pair[0], "tenant") == 0)
      known = (tenant = decode (pair[1])) != NULL;
    else if (g_strcmp0 (pair[0], "policy_generation") == 0)
      known = parse_u64 (pair[1], &generation);
    else if (g_strcmp0 (pair[0], "artifact_count") == 0)
      known = parse_u64 (pair[1], &value), count = (guint) value;
    else if (g_strcmp0 (pair[0], "artifact") == 0) {
      g_auto (GStrv) fields = g_strsplit (pair[1], ",", -1);
      guint64 format = 0, path_encoding = 0, logical = 0, physical = 0;
      WylFactOfflineBackupArtifact artifact = { 0 };
      known = g_strv_length (fields) == 8
          && (artifact.graph_id = decode (fields[0])) != NULL
          && (artifact.store_uuid = decode (fields[1])) != NULL
          && parse_u64 (fields[2], &format)
          && parse_u64 (fields[3], &path_encoding)
          && (artifact.schema_digest = decode (fields[4])) != NULL
          && parse_u64 (fields[5], &logical)
          && parse_u64 (fields[6], &physical)
          && (artifact.checksum = decode (fields[7])) != NULL;
      artifact.format_version = format;
      artifact.path_encoding_version = path_encoding;
      artifact.logical_bytes = logical;
      artifact.physical_bytes = physical;
      if (known && out_manifest->artifacts == NULL)
        known = wyl_fact_offline_backup_manifest_init (out_manifest, tenant,
                generation) == WYRELOG_E_OK;
      if (known)
        known = wyl_fact_offline_backup_manifest_add (out_manifest, &artifact)
            == WYRELOG_E_OK;
      g_free (artifact.graph_id);
      g_free (artifact.store_uuid);
      g_free (artifact.schema_digest);
      g_free (artifact.checksum);
    }
    g_strfreev (pair);
    if (!known)
      return WYRELOG_E_POLICY;
  }
  if (version != WYL_FACT_OFFLINE_BACKUP_MANIFEST_VERSION || tenant == NULL
      || generation == 0)
    return WYRELOG_E_POLICY;
  if (out_manifest->artifacts == NULL)
    return count == 0 ? wyl_fact_offline_backup_manifest_init
             (out_manifest, tenant, generation) : WYRELOG_E_POLICY;
  return count == out_manifest->artifacts->len ? WYRELOG_E_OK
      : WYRELOG_E_POLICY;
}

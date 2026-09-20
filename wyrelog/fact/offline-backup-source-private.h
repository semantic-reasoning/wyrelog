/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/runtime-private.h"
#include "wyrelog/error.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS

typedef struct WylFactOfflineBackupSource WylFactOfflineBackupSource;

/* Borrowed value view.  Its strings remain valid only until |source| is
 * freed; it contains no pathname, descriptor, HANDLE, or reopen capability. */
typedef struct
{
  const gchar *graph_id;
  const gchar *store_uuid;
  guint64 format_version;
  guint64 path_encoding_version;
  const gchar *schema_digest;
  guint64 logical_bytes;
  guint64 physical_bytes;
} WylFactOfflineBackupSourceArtifact;

/* The buffer is valid only for the duration of the call.  WYRELOG_E_OK
 * accepts the complete chunk; partial acceptance is not representable.
 * The callback must not recursively use or free |source|. */
typedef wyrelog_error_t (*WylFactOfflineBackupSinkFunc)
  (guint64 offset, const guint8 *bytes, gsize length, gpointer user_data);

/* Builds one immutable, main-only source set.  |policy| is borrowed and must
 * outlive the result.  |drain_timeout_us| is one total construction budget,
 * not a per-graph budget; a negative value waits without a deadline.
 * Authorized fact-root binding persists on |policy| even when this fails. */
wyrelog_error_t wyl_fact_offline_backup_source_new
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, const gchar *tenant_id,
    gint64 drain_timeout_us, WylFactOfflineBackupSource **out_source);

const gchar *wyl_fact_offline_backup_source_tenant_id
  (const WylFactOfflineBackupSource *source);
/* This is the sealed tenant lifecycle generation. */
guint64 wyl_fact_offline_backup_source_policy_generation
  (const WylFactOfflineBackupSource *source);
gsize wyl_fact_offline_backup_source_count
  (const WylFactOfflineBackupSource *source);
gboolean wyl_fact_offline_backup_source_get
  (const WylFactOfflineBackupSource *source, gsize index,
    WylFactOfflineBackupSourceArtifact *out_artifact);

/* Rechecks the borrowed policy authority and every retained capability. */
wyrelog_error_t wyl_fact_offline_backup_source_revalidate
  (WylFactOfflineBackupSource *source);

/* Streams the exact inventoried main file through a fresh validated reader.
 * |out_bytes_copied| is zero on every failure and the full size on success. */
wyrelog_error_t wyl_fact_offline_backup_source_copy_to_sink
  (WylFactOfflineBackupSource *source, gsize index,
    WylFactOfflineBackupSinkFunc sink, gpointer user_data,
    guint64 *out_bytes_copied);

void wyl_fact_offline_backup_source_free
  (WylFactOfflineBackupSource *source);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactOfflineBackupSource,
    wyl_fact_offline_backup_source_free)

G_END_DECLS

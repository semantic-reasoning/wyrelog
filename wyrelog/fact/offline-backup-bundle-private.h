/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/offline-restore-coordinator-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

typedef struct WylFactOfflineBackupBundle WylFactOfflineBackupBundle;
typedef struct
{
  WylFactOfflineBackupBundle *bundle;
  const gchar *graph_id;
} WylFactOfflineBackupGraphView;

/* Version 1 on-disk layout: an owner-only directory containing exactly
 * "manifest" and one "graph-<v1 encoded graph ID>.duckdb" regular file per
 * manifest artifact. The digest MUST come from an independently trusted
 * channel; a digest stored beside the bundle is not authentication. This
 * read-only opener never creates, repairs, or removes source files. */
wyrelog_error_t wyl_fact_offline_backup_bundle_open
  (const gchar *directory, const guint8 trusted_manifest_sha256[32],
    WylFactOfflineBackupBundle **out_bundle);

GBytes *wyl_fact_offline_backup_bundle_manifest_bytes
  (WylFactOfflineBackupBundle *bundle);
const guint8 *wyl_fact_offline_backup_bundle_manifest_sha256
  (WylFactOfflineBackupBundle *bundle);

/* Rechecks the named directory, its exact entry set, pinned file identities,
 * and the full checksums. Call before and after a restore import. Each read
 * additionally checks the pinned identity and exact file length. */
wyrelog_error_t wyl_fact_offline_backup_bundle_revalidate
  (WylFactOfflineBackupBundle *bundle);
wyrelog_error_t wyl_fact_offline_backup_bundle_read_at
  (WylFactOfflineBackupBundle *bundle, const gchar *graph_id, guint64 offset,
    guint8 *buffer, gsize capacity, gsize *out_read);

/* Adapters borrow the bundle for the entire coordinator invocation. */
wyrelog_error_t wyl_fact_offline_backup_bundle_graph_view
  (WylFactOfflineBackupBundle *bundle, const gchar *graph_id,
    WylFactOfflineBackupGraphView *out_view);
const WylFactOfflineRestoreTenantInput *
wyl_fact_offline_backup_bundle_tenant_input (void);
const WylFactOfflineRestoreInput *
wyl_fact_offline_backup_bundle_graph_input (void);
void wyl_fact_offline_backup_bundle_free (WylFactOfflineBackupBundle *bundle);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactOfflineBackupBundle,
    wyl_fact_offline_backup_bundle_free)

G_END_DECLS

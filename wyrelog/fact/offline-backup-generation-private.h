/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/offline-backup-source-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

typedef enum
{
  WYL_FACT_OFFLINE_BACKUP_NOT_PUBLISHED = 0,
  WYL_FACT_OFFLINE_BACKUP_PUBLISHED = 1,
} WylFactOfflineBackupPublishOutcome;

typedef struct
{
  /* Artifact callbacks stage one graph at a time, in source order.  Staged
   * bytes are not a completed backup and must not expose a success marker. */
  wyrelog_error_t (*begin_artifact) (const gchar *graph_id,
      guint64 logical_bytes, gpointer user_data);
  wyrelog_error_t (*write_artifact) (const gchar *graph_id, guint64 offset,
      const guint8 *bytes, gsize length, gpointer user_data);
  wyrelog_error_t (*finish_artifact) (const gchar *graph_id,
      const gchar *checksum, gpointer user_data);

  /* This is the only publication boundary.  PUBLISHED means the manifest was
   * durably and atomically installed as the success marker.  NOT_PUBLISHED
   * guarantees that no marker became visible.  No ambiguous outcome is
   * representable; an invalid enum value fails closed as NOT_PUBLISHED. */
  WylFactOfflineBackupPublishOutcome (*publish_manifest)
    (GBytes *manifest, gpointer user_data);

  /* Called exactly once after any pre-publication failure, including an
   * explicit or invalid NOT_PUBLISHED outcome.  No callback follows abort. */
  void (*abort) (gpointer user_data);
} WylFactOfflineBackupDestination;

/* Success linearizes at the final whole-tenant policy/source revalidation
 * immediately before publish_manifest.  A policy mutation performed by the
 * publication callback is ordered after that point. */
wyrelog_error_t wyl_fact_offline_backup_generate
  (WylFactOfflineBackupSource *source,
    const WylFactOfflineBackupDestination *destination, gpointer user_data);

G_END_DECLS

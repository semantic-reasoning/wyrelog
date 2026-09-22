/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-locator-private.h"
#include "fact/root-writer-lease-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

typedef struct WylFactOfflineRestoreStage WylFactOfflineRestoreStage;

/* Create an operation-named destination stage under a separately held
 * destination writer lease. Resolver, directory, and lease are borrowed and
 * must outlive the capability. No path or native handle is exposed. */
wyrelog_error_t wyl_fact_offline_restore_stage_new
  (WylFactGraphResolver *resolver, WylFactGraphDirectory *directory,
    WylFactRootWriterLease *writer_lease, const gchar *operation_uuid,
    guint64 expected_bytes, WylFactOfflineRestoreStage **out_stage);

/* Writes one complete sequential chunk. |offset| must equal the number of
 * bytes already accepted and the total may not exceed |expected_bytes|; any
 * short/error write terminally fails the stage. Callers must set
 * |expected_bytes| from the validated artifact-size contract before admitting
 * this capability. Finalization succeeds only after exactly that many bytes. */
wyrelog_error_t wyl_fact_offline_restore_stage_write
  (WylFactOfflineRestoreStage *stage, guint64 offset,
    const guint8 *bytes, gsize length);

/* Revalidates both destination authority and the held stage identity. */
wyrelog_error_t wyl_fact_offline_restore_stage_revalidate
  (WylFactOfflineRestoreStage *stage);

/* Flushes stage contents and the containing directory. Identity and byte count
 * are returned only after both durability checks and final revalidation pass. */
wyrelog_error_t wyl_fact_offline_restore_stage_finalize
  (WylFactOfflineRestoreStage *stage, guint64 *out_bytes_written,
    WylFactArtifactInventoryIdentity *out_identity);

void wyl_fact_offline_restore_stage_free (WylFactOfflineRestoreStage *stage);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactOfflineRestoreStage,
    wyl_fact_offline_restore_stage_free)

G_END_DECLS

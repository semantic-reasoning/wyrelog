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
 * must outlive the capability. No path or native handle is exposed.
 * |expected_bytes| is logical file length, not allocated storage size.
 * |expected_checksum| is sha256: followed by 64 lowercase hex digits; its
 * value is copied. The caller must authenticate the manifest, bind these
 * values to the destination, retain sealed/drained lifecycle authority, and
 * sequence durable journal ownership before using this primitive.
 * All operations are single-threaded and non-reentrant. */
wyrelog_error_t wyl_fact_offline_restore_stage_new
  (WylFactGraphResolver *resolver, WylFactGraphDirectory *directory,
    WylFactRootWriterLease *writer_lease, const gchar *operation_uuid,
    guint64 expected_bytes, const gchar *expected_checksum,
    WylFactOfflineRestoreStage **out_stage);

/* Writes one complete sequential chunk. |offset| must equal the number of
 * bytes already accepted and the total may not exceed |expected_bytes|; any
 * short/error write terminally fails the stage. Callers must set
 * |expected_bytes| from the validated artifact-size contract before admitting
 * this capability. Finalization succeeds only after exactly that many bytes. */
wyrelog_error_t wyl_fact_offline_restore_stage_write
  (WylFactOfflineRestoreStage *stage, guint64 offset,
    const guint8 *bytes, gsize length);

/* Adapter for a backup-source sink or another authenticated stream producer.
 * |user_data| is the stage. This never finalizes: the caller may finalize only
 * after the producer succeeds, including its final authority checks. */
wyrelog_error_t wyl_fact_offline_restore_stage_sink
  (guint64 offset, const guint8 *bytes, gsize length, gpointer user_data);

/* Revalidates both destination authority and the held stage identity. */
wyrelog_error_t wyl_fact_offline_restore_stage_revalidate
  (WylFactOfflineRestoreStage *stage);

/* Checks the stream checksum, flushes file and directory, then verifies exact
 * length and checksum by bounded readback from the held descriptor. Returns
 * byte count and identity only after final size/authority checks; all supplied
 * outputs are cleared on failure. Any finalize attempt consumes a live stage,
 * including invalid output arguments. Failure leaves a recovery-owned orphan.
 * Readback proves observed content, not immunity to subsequent mutation. This
 * does not validate database metadata/schema/replay, authenticate a manifest,
 * set journal verification flags, or authorize publication. */
wyrelog_error_t wyl_fact_offline_restore_stage_finalize
  (WylFactOfflineRestoreStage *stage, guint64 *out_bytes_written,
    WylFactArtifactInventoryIdentity *out_identity);

void wyl_fact_offline_restore_stage_free (WylFactOfflineRestoreStage *stage);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactOfflineRestoreStage,
    wyl_fact_offline_restore_stage_free)

G_END_DECLS

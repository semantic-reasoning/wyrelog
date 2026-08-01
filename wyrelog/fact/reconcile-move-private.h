/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

#ifndef G_OS_WIN32

/*
 * Private, reconciler-only MOVING->MOVED file-move phase.  It securely copies
 * a verified legacy graph artifact into its canonical graph-local
 * `facts.duckdb` and commits the durable journal MOVING->MOVED via CAS.  The
 * source is never removed: this is a copy, not a destructive move.  There is
 * deliberately no public API, HTTP, CLI, daemon or startup surface here.
 *
 * POSIX only: the copy relies on same-directory atomic staging and on the
 * POSIX writer lease, so the unit compiles to nothing on Windows.
 */

typedef enum
{
  /* Bytes were copied, published and the journal CAS applied MOVING->MOVED. */
  WYL_FACT_RECONCILE_MOVE_APPLIED = 0,
  /*
   * Nothing durable changed this call: the journal was already MOVED, or the
   * canonical target was already our own published artifact and the CAS then
   * converged MOVING->MOVED idempotently.
   */
  WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY,
} WylFactReconcileMoveOutcome;

typedef struct
{
  const gchar *fact_root;
  wyl_policy_store_t *store;
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *op_uuid;
  /* Test-only fault-injection seam; NULL in production. */
    wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data);
  gpointer checkpoint_data;
} WylFactReconcileMoveContext;

/*
 * Runs the move phase for one reconciliation operation.  Acquires the writer
 * lease, revalidates the resolver against it, reads and validates the
 * journal record, then either converges on an already-published target or
 * copies+publishes the verified source before committing the CAS.  The
 * source artifact is left in place.
 */
wyrelog_error_t wyl_fact_reconcile_move_publish (const
    WylFactReconcileMoveContext * ctx, WylFactReconcileMoveOutcome *
    out_outcome);

/*
 * Canonical producer of source-artifact evidence: fstat identity plus a
 * SHA-256 over the whole file's raw bytes read from the held handle.  This is
 * the single collector used both to seed the journal and to re-verify the
 * source at move time, so a matching digest proves the same bytes across
 * different inodes.
 */
wyrelog_error_t wyl_fact_reconcile_capture_artifact_evidence (gint fd,
    WylPolicyFactReconcileArtifactEvidence * out_evidence);

#endif /* !G_OS_WIN32 */

G_END_DECLS;

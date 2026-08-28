/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-artifact-main-transition-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

#ifndef G_OS_WIN32
typedef wyrelog_error_t (*WylFactArtifactInventoryPosixRevalidate)
  (gpointer user_data);
typedef void (*WylFactArtifactInventoryPosixBeforeEnd)
  (gint graph_fd, gpointer user_data);

/*
 * The one POSIX inventory scanner used by both the normal namespace and the
 * bounded main-transition provider.  Operation names are optional; when
 * supplied, their value-only evidence is captured in the same begin/end
 * directory epoch as the #622 snapshot.  They remain UNKNOWN_ENTRY anomalies
 * in that snapshot, so #623's exact-count inventory gate stays authoritative.
 */
wyrelog_error_t wyl_fact_artifact_inventory_posix_capture
  (gint graph_fd, guint64 owner, gint guard_fd, const gchar *stage_name,
    const gchar *rollback_name,
    WylFactArtifactInventoryPosixRevalidate revalidate,
    WylFactArtifactInventoryPosixBeforeEnd before_end, gpointer user_data,
    WylFactArtifactInventorySnapshot **out_snapshot,
    WylFactArtifactMainTransitionEntryEvidence
    out_entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_COUNT]);
#endif

G_END_DECLS

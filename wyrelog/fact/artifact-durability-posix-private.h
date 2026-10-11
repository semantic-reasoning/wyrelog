/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_PROVEN,
  WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED,
  WYL_FACT_ARTIFACT_DURABILITY_ERROR,
} WylFactArtifactDurabilityResult;

/* Sync the object named by a held descriptor. The helper verifies its kind
 * with fstat and never substitutes a weaker Darwin barrier. */
WylFactArtifactDurabilityResult wyl_fact_artifact_durability_sync_fd (gint fd);
gboolean wyl_fact_artifact_durability_sync_fd_proven (gint fd);

/* Stable classification seam for the Darwin F_FULLFSYNC error contract. */
WylFactArtifactDurabilityResult
wyl_fact_artifact_durability_classify_fullfsync_errno (gint error_number);
WylFactArtifactDurabilityResult
wyl_fact_artifact_durability_classify_directory_fsync_errno (gint error_number);

G_END_DECLS

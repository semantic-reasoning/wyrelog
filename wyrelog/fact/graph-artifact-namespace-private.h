/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "wyrelog/error.h"
#include "fact/graph-locator-private.h"

G_BEGIN_DECLS typedef struct WylFactArtifactNamespace WylFactArtifactNamespace;

/* Only these names are part of the authority.  Callers cannot supply a path. */
typedef enum
{
  WYL_FACT_ARTIFACT_MAIN,
  WYL_FACT_ARTIFACT_WAL,
  WYL_FACT_ARTIFACT_CHECKPOINT,
  WYL_FACT_ARTIFACT_RECOVERY,
  WYL_FACT_ARTIFACT_LOCK,
  WYL_FACT_ARTIFACT_TEMP,
} WylFactArtifactName;

wyrelog_error_t wyl_fact_artifact_namespace_open
    (const WylFactGraphDirectory * directory,
    WylFactArtifactNamespace ** out_namespace);
void wyl_fact_artifact_namespace_free (WylFactArtifactNamespace * namespace_);
wyrelog_error_t wyl_fact_artifact_namespace_revalidate
    (WylFactArtifactNamespace * namespace_);
wyrelog_error_t wyl_fact_artifact_namespace_open_file
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName name,
    gboolean create, gboolean writable, gint * out_fd);
wyrelog_error_t wyl_fact_artifact_namespace_unlink
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName name);
wyrelog_error_t wyl_fact_artifact_namespace_sync
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName name);
wyrelog_error_t wyl_fact_artifact_namespace_lock
    (WylFactArtifactNamespace * namespace_, gboolean exclusive, gint * out_fd);

G_END_DECLS

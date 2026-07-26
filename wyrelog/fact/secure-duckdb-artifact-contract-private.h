/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include <string_view>
#include "fact/graph-artifact-namespace-private.h"

static inline bool
wyl_secure_duckdb_artifact_name (std::string_view name,
    WylFactArtifactName *out)
{
  if (!out)
    return false;
  if (name == "facts.duckdb")
    *out = WYL_FACT_ARTIFACT_MAIN;
  else if (name == "facts.duckdb.wal")
    *out = WYL_FACT_ARTIFACT_WAL;
  else if (name == "facts.duckdb.wal.checkpoint")
    *out = WYL_FACT_ARTIFACT_CHECKPOINT;
  else if (name == "facts.duckdb.wal.recovery")
    *out = WYL_FACT_ARTIFACT_RECOVERY;
  else if (name == "facts.duckdb.lock")
    *out = WYL_FACT_ARTIFACT_LOCK;
  else
    return false;
  return true;
}

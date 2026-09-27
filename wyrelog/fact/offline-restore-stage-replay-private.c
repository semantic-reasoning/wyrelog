/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "offline-restore-stage-replay-private.h"

#include "fact/replay-private.h"
#include "fact/secure-duckdb-bridge-private.h"
#include "fact/store-identity-private.h"

wyrelog_error_t
wyl_fact_offline_restore_stage_replay_validate
  (wyl_policy_store_t *policy, WylFactOfflineRestoreStageReader *reader,
    guint64 expected_bytes, const gchar *expected_checksum,
    const WylFactStoreIdentity *expected_identity,
    const wyl_policy_fact_graph_info_t *graph_info,
    const gchar *expected_schema_digest,
    WylFactReplayJobContext *job_context, gchar **out_schema_digest)
{
  if (out_schema_digest != NULL)
    *out_schema_digest = NULL;
  if (policy == NULL || reader == NULL || expected_bytes == 0
      || expected_checksum == NULL
      || !wyl_fact_store_identity_input_is_valid (expected_identity)
      || graph_info == NULL || graph_info->tenant_id == NULL
      || graph_info->graph_id == NULL || expected_schema_digest == NULL
      || job_context == NULL || out_schema_digest == NULL)
    return WYRELOG_E_INVALID;
  if (g_strcmp0 (expected_identity->tenant_id, graph_info->tenant_id) != 0
      || g_strcmp0 (expected_identity->graph_id, graph_info->graph_id) != 0)
    return WYRELOG_E_POLICY;

  WylFactReplayStore *store = NULL;
  wyrelog_error_t rc =
      wyl_secure_duckdb_bridge_open_restore_stage_replay_store (reader,
          expected_bytes, expected_checksum, expected_identity, job_context,
          &store);
  if (rc != WYRELOG_E_OK)
    return rc;
  /* The consuming validator closes/destroys the provider on every path,
   * including invalid snapshot/digest input and cancellation. */
  return wyl_fact_replay_validate_replay_store_for_restore (policy, &store,
             graph_info, expected_schema_digest, job_context,
             out_schema_digest);
}

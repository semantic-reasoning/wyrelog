/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/provisioning-private.h"

#include "wyl-id-private.h"

#include <string.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#else
#include <io.h>
#endif

static gboolean
canonical_uuid (const gchar *value)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  return value != NULL && wyl_id_parse (value, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && g_strcmp0 (value, canonical) == 0;
}

static gboolean
record_matches_authority (const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority)
{
  return record != NULL && authority != NULL
      && (record->phase == WYL_POLICY_GRAPH_PROVISIONING_RESERVED
      || record->phase == WYL_POLICY_GRAPH_PROVISIONING_STAGED)
      && canonical_uuid (record->op_uuid) && canonical_uuid (record->store_uuid)
      && g_strcmp0 (record->tenant_id, authority->tenant_id) == 0
      && g_strcmp0 (record->graph_id, authority->graph_id) == 0
      && g_strcmp0 (record->store_uuid, authority->store_uuid) == 0
      && authority->has_store_identity
      && authority->lifecycle_state == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING
      && authority->format_version > 0 && authority->path_encoding_version > 0
      && authority->lifecycle_generation
      == record->expected_lifecycle_generation
      && authority->reconciliation_generation
      == record->expected_reconciliation_generation;
}

void
wyl_fact_graph_provisioning_stage_clear (WylFactGraphProvisioningStage *stage)
{
  if (stage == NULL)
    return;
  wyl_fact_graph_stage_clear (&stage->stage);
  wyl_fact_graph_directory_clear (&stage->directory);
  wyl_fact_graph_resolver_clear (&stage->resolver);
  g_clear_pointer (&stage->tenant_id, g_free);
  g_clear_pointer (&stage->graph_id, g_free);
  g_clear_pointer (&stage->store_uuid, g_free);
  stage->identity = (WylFactStoreIdentity) {
  0};
}

wyrelog_error_t
wyl_fact_graph_provisioning_stage_prepare (const gchar *fact_root,
    const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority,
    WylFactGraphProvisioningStage *out_stage)
{
  if (out_stage == NULL)
    return WYRELOG_E_INVALID;
  *out_stage = (WylFactGraphProvisioningStage)
      WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;
  if (fact_root == NULL || fact_root[0] == '\0'
      || !record_matches_authority (record, authority))
    return WYRELOG_E_INVALID;

  WylFactGraphLocator locator = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_locator_init (&locator, record->tenant_id,
      record->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &out_stage->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&out_stage->resolver, &locator,
        TRUE, &out_stage->directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_stage_create_exact (&out_stage->directory,
        record->op_uuid, &out_stage->stage);
  if (rc == WYRELOG_E_BUSY)
    rc = wyl_fact_graph_directory_stage_open_exact (&out_stage->directory,
        record->op_uuid, &out_stage->stage);
  wyl_fact_graph_locator_clear (&locator);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_graph_provisioning_stage_clear (out_stage);
    return rc;
  }

  /* A two-link stage is already a published pair, never a STAGED retry. */
#ifndef G_OS_WIN32
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  rc = wyl_fact_graph_directory_open_provisioned_final_exact
      (&out_stage->directory, record->op_uuid, &final);
  wyl_fact_graph_regular_file_clear (&final);
#else
  gint final_fd = -1;
  rc = wyl_fact_graph_directory_open_file (&out_stage->directory,
      "facts.duckdb", FALSE, &final_fd);
  if (final_fd >= 0)
    _close (final_fd);
#endif
  if (rc == WYRELOG_E_OK) {
    wyl_fact_graph_provisioning_stage_clear (out_stage);
    return WYRELOG_E_POLICY;
  }
  if (rc != WYRELOG_E_NOT_FOUND) {
    wyl_fact_graph_provisioning_stage_clear (out_stage);
    return rc;
  }

  out_stage->tenant_id = g_strdup (record->tenant_id);
  out_stage->graph_id = g_strdup (record->graph_id);
  out_stage->store_uuid = g_strdup (record->store_uuid);
  if (out_stage->tenant_id == NULL || out_stage->graph_id == NULL
      || out_stage->store_uuid == NULL) {
    wyl_fact_graph_provisioning_stage_clear (out_stage);
    return WYRELOG_E_NOMEM;
  }
  out_stage->identity = (WylFactStoreIdentity) {
  0};
  out_stage->identity.tenant_id = out_stage->tenant_id;
  out_stage->identity.graph_id = out_stage->graph_id;
  out_stage->identity.store_uuid = out_stage->store_uuid;
  out_stage->identity.format_version = authority->format_version;
  out_stage->identity.path_encoding_version = authority->path_encoding_version;
  return WYRELOG_E_OK;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/store-open-private.h"

#include "fact/graph-locator-private.h"
#include "fact/provisioning-run-private.h"

/* Resolve the in-flight or active provisioning operation for a graph. */
static wyrelog_error_t
open_provisioned_find_op (wyl_policy_store_t *policy_store,
    const gchar *tenant_id, const gchar *graph_id,
    WylPolicyGraphProvisioningRecord **out_record)
{
  *out_record = NULL;
  GPtrArray *records = NULL;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_list (policy_store,
          tenant_id, &records);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = WYRELOG_E_NOT_FOUND;
  for (guint i = 0; i < records->len; i++) {
    const WylPolicyGraphProvisioningRecord *record =
        g_ptr_array_index (records, i);
    if (g_strcmp0 (record->graph_id, graph_id) == 0) {
      *out_record = g_ptr_array_steal_index (records, i);
      rc = WYRELOG_E_OK;
      break;
    }
  }
  g_ptr_array_unref (records);
  return rc;
}

static wyrelog_error_t
open_provisioned_active (const gchar *fact_root,
    const WylPolicyGraphAuthorityRecord *authority,
    const WylPolicyGraphProvisioningRecord *record, gboolean writable,
    wyl_fact_store_t **out_store)
{
  if (record == NULL
      || record->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE
      || g_strcmp0 (record->tenant_id, authority->tenant_id) != 0
      || g_strcmp0 (record->graph_id, authority->graph_id) != 0
      || g_strcmp0 (record->store_uuid, authority->store_uuid) != 0)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  gsize evidence_length = 0;
  const guint8 *evidence_bytes =
      record->darwin_operation_evidence == NULL ? NULL :
      g_bytes_get_data (record->darwin_operation_evidence, &evidence_length);
  if (evidence_bytes == NULL
      || evidence_length != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE)
    return WYRELOG_E_POLICY;
  rc = wyl_fact_graph_darwin_evidence_decode (evidence_bytes, evidence_length,
          record->op_uuid, &evidence);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif
  WylFactStoreIdentity identity = { 0 };
  identity.tenant_id = authority->tenant_id;
  identity.graph_id = authority->graph_id;
  identity.store_uuid = authority->store_uuid;
  identity.format_version = authority->format_version;
  identity.path_encoding_version = authority->path_encoding_version;

  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphProvisionedPair *pair = NULL;

  rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, authority->tenant_id,
            authority->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator, FALSE,
            &directory);
#ifdef __APPLE__
  if (rc == WYRELOG_E_OK)
    rc =
        wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
          (&directory, record->op_uuid, &evidence, &pair);
#else
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            record->op_uuid, &pair);
#endif
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_store_open_provisioned_pair (pair, &identity, writable,
            out_store);

  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  return rc;
}

wyrelog_error_t
wyl_fact_store_open_provisioned_graph (wyl_policy_store_t *policy_store,
    const gchar *fact_root, const gchar *tenant_id, const gchar *graph_id,
    gboolean writable, wyl_fact_store_t **out_store)
{
  if (out_store != NULL)
    *out_store = NULL;
  if (policy_store == NULL || fact_root == NULL || fact_root[0] == '\0'
      || tenant_id == NULL || graph_id == NULL || out_store == NULL)
    return WYRELOG_E_INVALID;

  WylPolicyGraphAuthorityRecord *authority = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_graph_authority (policy_store,
          tenant_id, graph_id, &authority);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* A provisioning graph is finished (or degraded) by the idempotent
   * coordinator, then re-read as active. */
  if (authority->lifecycle_state == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING) {
    WylPolicyGraphProvisioningRecord *record = NULL;
    rc = open_provisioned_find_op (policy_store, tenant_id, graph_id, &record);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_provisioning_recover (policy_store, record->op_uuid,
              fact_root, NULL);
    wyl_policy_graph_provisioning_record_free (record);
    wyl_policy_graph_authority_record_free (authority);
    authority = NULL;
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_policy_store_read_graph_authority (policy_store, tenant_id,
            graph_id, &authority);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  /* Active and sealed graphs both open the retained pair: sealing blocks new
   * appends at the request boundary, but the store stays readable and
   * forgettable (GDPR erasure).  Legacy graphs use the caller's path open;
   * degraded graphs fail closed. */
  if (authority->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
      && authority->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED) {
    wyl_policy_graph_authority_record_free (authority);
    return WYRELOG_E_POLICY;
  }

  WylPolicyGraphProvisioningRecord *record = NULL;
  rc = open_provisioned_find_op (policy_store, tenant_id, graph_id, &record);
  if (rc == WYRELOG_E_OK)
    rc = open_provisioned_active (fact_root, authority, record, writable,
            out_store);
  wyl_policy_graph_provisioning_record_free (record);
  wyl_policy_graph_authority_record_free (authority);
  return rc;
}

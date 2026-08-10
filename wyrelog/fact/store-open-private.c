/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/store-open-private.h"

#ifndef G_OS_WIN32
#include "fact/graph-locator-private.h"
#include "fact/provisioning-run-private.h"
#include "wyl-id-private.h"

/* Resolve the in-flight or active provisioning operation for a graph. */
static wyrelog_error_t
open_provisioned_find_op (wyl_policy_store_t *policy_store,
    const gchar *tenant_id, const gchar *graph_id, gchar *out_op_uuid)
{
  out_op_uuid[0] = '\0';
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
      g_strlcpy (out_op_uuid, record->op_uuid, WYL_ID_STRING_BUF);
      rc = WYRELOG_E_OK;
      break;
    }
  }
  g_ptr_array_unref (records);
  return rc;
}

static wyrelog_error_t
open_provisioned_active (wyl_policy_store_t *policy_store,
    const gchar *fact_root, const WylPolicyGraphAuthorityRecord *authority,
    const gchar *op_uuid, gboolean writable, wyl_fact_store_t **out_store)
{
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

  wyrelog_error_t rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_locator_init (&locator, authority->tenant_id,
            authority->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator, FALSE,
            &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&directory,
            op_uuid, &pair);
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
    gchar op_uuid[WYL_ID_STRING_BUF];
    rc = open_provisioned_find_op (policy_store, tenant_id, graph_id, op_uuid);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_graph_provisioning_recover (policy_store, op_uuid, fact_root,
              NULL);
    wyl_policy_graph_authority_record_free (authority);
    authority = NULL;
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_policy_store_read_graph_authority (policy_store, tenant_id,
            graph_id, &authority);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  if (authority->lifecycle_state != WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE) {
    /* Legacy graphs use the caller's path open; sealed/degraded fail closed. */
    wyl_policy_graph_authority_record_free (authority);
    return WYRELOG_E_POLICY;
  }

  gchar op_uuid[WYL_ID_STRING_BUF];
  rc = open_provisioned_find_op (policy_store, tenant_id, graph_id, op_uuid);
  if (rc == WYRELOG_E_OK)
    rc = open_provisioned_active (policy_store, fact_root, authority, op_uuid,
            writable, out_store);
  wyl_policy_graph_authority_record_free (authority);
  return rc;
}
#endif

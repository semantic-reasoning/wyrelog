/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "fact/provisioning-construct-private.h"

int
main (int argc, char **argv)
{
  if (argc != 6)
    return 2;
  for (gint i = 1; i < argc; i++) {
    if (argv[i] == NULL || argv[i][0] == '\0')
      return 2;
  }

  const gchar *root = argv[1];
  const gchar *tenant_id = argv[2];
  const gchar *graph_id = argv[3];
  const gchar *operation_uuid = argv[4];
  const gchar *store_uuid = argv[5];
  g_autofree gchar *stage_basename =
      g_strdup_printf ("provision-%s.sqlite", operation_uuid);
  WylPolicyGraphProvisioningRecord record = { 0 };
  record.op_uuid = (gchar *) operation_uuid;
  record.tenant_id = (gchar *) tenant_id;
  record.graph_id = (gchar *) graph_id;
  record.store_uuid = (gchar *) store_uuid;
  record.stage_basename = stage_basename;
  record.expected_lifecycle_generation = 1;
  record.expected_reconciliation_generation = 0;
  record.phase = WYL_POLICY_GRAPH_PROVISIONING_RESERVED;
  WylPolicyGraphAuthorityRecord authority = { 0 };
  authority.tenant_id = (gchar *) tenant_id;
  authority.graph_id = (gchar *) graph_id;
  authority.lifecycle_state = WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING;
  authority.store_uuid = (gchar *) store_uuid;
  authority.format_version = 1;
  authority.path_encoding_version = 1;
  authority.lifecycle_generation = 1;
  authority.reconciliation_generation = 0;
  authority.has_store_identity = TRUE;

  wyrelog_error_t rc = wyl_fact_graph_provisioning_construct (root, &record,
          &authority);
  if (rc == WYRELOG_E_OK)
    return 0;
  g_printerr ("provisioning failed: %d\n", rc);
  return 1;
}

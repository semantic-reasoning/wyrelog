/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/provisioning-construct-private.h"

wyrelog_error_t
wyl_fact_graph_provisioning_construct (const gchar *fact_root,
    const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority)
{
  WylFactGraphProvisioningStage stage = WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;
  WylFactGraphProvisionedPair *pair = NULL;
  WylFactStoreIdentityResult identity_result =
      WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  wyrelog_error_t rc;

  if (record == NULL || authority == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_graph_provisioning_stage_prepare (fact_root, record, authority,
          &stage);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Durably land the staged file, then publish it.  A no-replace publish never
   * overwrites an existing final store. */
#ifdef G_OS_WIN32
  /* Capture the evidence BEFORE publishing: the publishing rename forgets it,
   * and reading it afterwards yields WYRELOG_E_INVALID.  Windows also needs
   * the evidence-bound publish -- the name-only form refuses an exact stage
   * there, because a name is not provenance. */
  WylFactGraphWinOperationEvidence evidence = { 0 };
  rc = wyl_fact_graph_stage_get_windows_operation_evidence (&stage.stage,
          &evidence);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_stage_sync (&stage.stage);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_stage_publish_with_evidence (&stage.directory,
            &stage.stage, &evidence);
#else
  rc = wyl_fact_graph_stage_sync (&stage.stage);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_stage_publish (&stage.directory, &stage.stage);
#endif
  if (rc != WYRELOG_E_OK) {
    wyl_fact_graph_stage_abort (&stage.directory, &stage.stage);
    wyl_fact_graph_provisioning_stage_clear (&stage);
    return rc;
  }

  /* Initialize the exact identity through the secure bridge, then re-open to
   * validate it: identity is committed to the published store, never to a
   * caller-named path.
   *
   * On POSIX facts.duckdb now shares the staged inode as a retained pair at
   * nlink 2, deliberately kept there because the secure open path revalidates
   * that both names still bind the same inode -- an anti-swap invariant, so
   * the staged name is never retired.  Windows published by rename, so the
   * stage name is gone and the anti-swap witness is the evidence tuple minted
   * above. */
#ifdef G_OS_WIN32
  rc = wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence
        (&stage.directory, record->op_uuid, &evidence, &pair);
#else
  rc = wyl_fact_graph_directory_open_provisioned_pair_exact (&stage.directory,
          record->op_uuid, &pair);
#endif
  if (rc == WYRELOG_E_OK) {
    rc = wyl_fact_store_open_identified_provisioned_pair_pinned (pair,
            &stage.identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &identity_result);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_store_open_identified_provisioned_pair_pinned (pair,
              &stage.identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
              &identity_result);
    wyl_fact_graph_provisioned_pair_free (pair);
  }

  wyl_fact_graph_provisioning_stage_clear (&stage);
  return rc;
}

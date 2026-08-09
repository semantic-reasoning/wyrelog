/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/provisioning-run-private.h"

#ifndef G_OS_WIN32

/* Open the graph directory (without staging) and build the exact store identity
 * from a durable record and its authority.  Used to resume an already-published
 * pair, where stage_prepare would reject the two-link final.  Leaves the stage
 * handle at INIT; only resolver, directory, and identity are populated. */
static wyrelog_error_t
provisioning_reopen_context (const gchar *fact_root,
    const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority,
    WylFactGraphProvisioningStage *out_stage)
{
  *out_stage = (WylFactGraphProvisioningStage)
      WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;

  WylFactGraphLocator locator = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_locator_init (&locator, record->tenant_id,
          record->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &out_stage->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&out_stage->resolver, &locator,
            FALSE, &out_stage->directory);
  wyl_fact_graph_locator_clear (&locator);
  if (rc != WYRELOG_E_OK) {
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
    0
  };
  out_stage->identity.tenant_id = out_stage->tenant_id;
  out_stage->identity.graph_id = out_stage->graph_id;
  out_stage->identity.store_uuid = out_stage->store_uuid;
  out_stage->identity.format_version = authority->format_version;
  out_stage->identity.path_encoding_version = authority->path_encoding_version;
  return WYRELOG_E_OK;
}

/* Open the retained pair and commit-then-validate the exact identity through the
 * secure bridge.  Idempotent: INITIALIZE_IF_EMPTY is a no-op on an already
 * initialized store, and VALIDATE_ONLY re-checks it.  Reports the seam that
 * faulted through out_class so the coordinator can degrade with fidelity. */
static wyrelog_error_t
provisioning_verify_pair (WylFactGraphProvisioningStage *stage,
    const gchar *op_uuid, WylPolicyGraphErrorClass *out_class)
{
  WylFactGraphProvisionedPair *pair = NULL;
  wyrelog_error_t rc = wyl_fact_graph_directory_open_provisioned_pair_exact
        (&stage->directory, op_uuid, &pair);
  if (rc != WYRELOG_E_OK) {
    *out_class = WYL_POLICY_GRAPH_ERROR_OPEN;
    return rc;
  }

  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  rc = wyl_fact_store_open_identified_provisioned_pair_pinned (pair,
          &stage->identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
          &result);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_store_open_identified_provisioned_pair_pinned (pair,
            &stage->identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result);
  wyl_fact_graph_provisioned_pair_free (pair);
  if (rc != WYRELOG_E_OK)
    *out_class = WYL_POLICY_GRAPH_ERROR_IDENTITY;
  return rc;
}

/* Record one forward phase step.  APPLIED or an idempotent replay is success; a
 * lost CAS (a concurrent coordinator advanced the phase underneath us, seen as a
 * zero-row WYRELOG_E_POLICY or a non-applied mutation result) maps to
 * WYRELOG_E_BUSY without degrading -- the operation is still resumable.  A hard
 * store fault (I/O, out of memory) is propagated unchanged, never masked as a
 * benign retry. */
static wyrelog_error_t
provisioning_advance (wyl_policy_store_t *store, const gchar *op_uuid,
    guint64 attempt, WylPolicyGraphProvisioningPhase from,
    WylPolicyGraphProvisioningPhase to)
{
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_transition (store,
          op_uuid, from, to, attempt, WYL_POLICY_GRAPH_ERROR_NONE, &result);
  if (rc == WYRELOG_E_OK
      && (result == WYL_POLICY_AUTHORITY_MUTATION_APPLIED
      || result == WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY))
    return WYRELOG_E_OK;
  if (rc == WYRELOG_E_OK || rc == WYRELOG_E_POLICY)
    return WYRELOG_E_BUSY;
  return rc;
}

/* Best-effort move the record and its coupled authority to DEGRADED. */
static void
provisioning_degrade (wyl_policy_store_t *store, const gchar *op_uuid,
    guint64 attempt, WylPolicyGraphProvisioningPhase from,
    WylPolicyGraphErrorClass error_class)
{
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  (void) wyl_policy_store_graph_provisioning_transition (store, op_uuid, from,
      WYL_POLICY_GRAPH_PROVISIONING_DEGRADED, attempt, error_class, &result);
}

static wyrelog_error_t
provisioning_read_out (wyl_policy_store_t *store, const gchar *op_uuid,
    WylPolicyGraphProvisioningRecord **out_record)
{
  if (out_record == NULL)
    return WYRELOG_E_OK;
  return wyl_policy_store_graph_provisioning_read (store, op_uuid, out_record);
}

/* Drive record->phase forward to ACTIVE, resuming from whatever seam the durable
 * phase names.  Borrows record and authority. */
static wyrelog_error_t
provisioning_drive (wyl_policy_store_t *store,
    const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority, const gchar *fact_root,
    WylPolicyGraphProvisioningRecord **out_record)
{
  const gchar *op_uuid = record->op_uuid;
  const guint64 attempt = record->attempt;
  WylPolicyGraphProvisioningPhase phase = record->phase;

  if (phase == WYL_POLICY_GRAPH_PROVISIONING_ACTIVE)
    return provisioning_read_out (store, op_uuid, out_record);
  if (phase == WYL_POLICY_GRAPH_PROVISIONING_DEGRADED)
    return WYRELOG_E_POLICY;

  WylFactGraphProvisioningStage stage = WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;
  gboolean staged_flow = (phase == WYL_POLICY_GRAPH_PROVISIONING_RESERVED
      || phase == WYL_POLICY_GRAPH_PROVISIONING_STAGED);
  wyrelog_error_t rc = WYRELOG_E_OK;

  if (staged_flow) {
    rc = wyl_fact_graph_provisioning_stage_prepare (fact_root, record, authority,
            &stage);
    if (rc == WYRELOG_E_POLICY) {
      /* The pair already exists though the durable phase still trails it: a
       * crash landed between publish and the staged->published record.  Resume
       * as an already-published operation. */
      wyl_fact_graph_provisioning_stage_clear (&stage);
      staged_flow = FALSE;
      rc = WYRELOG_E_OK;
    } else if (rc != WYRELOG_E_OK) {
      provisioning_degrade (store, op_uuid, attempt, phase,
          WYL_POLICY_GRAPH_ERROR_PATH);
      return rc;
    }
  }

  if (!staged_flow
      && stage.identity.store_uuid == NULL
      && phase != WYL_POLICY_GRAPH_PROVISIONING_VERIFIED) {
    /* Need the directory + identity to verify the retained pair. */
    rc = provisioning_reopen_context (fact_root, record, authority, &stage);
    if (rc != WYRELOG_E_OK) {
      provisioning_degrade (store, op_uuid, attempt, phase,
          WYL_POLICY_GRAPH_ERROR_OPEN);
      return rc;
    }
  }

  WylPolicyGraphProvisioningPhase cur = phase;
  while (rc == WYRELOG_E_OK
      && cur != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE) {
    switch (cur) {
      case WYL_POLICY_GRAPH_PROVISIONING_RESERVED:
        /* The staged file exists (created or reopened by stage_prepare). */
        rc = provisioning_advance (store, op_uuid, attempt, cur,
                WYL_POLICY_GRAPH_PROVISIONING_STAGED);
        cur = WYL_POLICY_GRAPH_PROVISIONING_STAGED;
        break;
      case WYL_POLICY_GRAPH_PROVISIONING_STAGED:
        if (staged_flow) {
          rc = wyl_fact_graph_stage_sync (&stage.stage);
          if (rc == WYRELOG_E_OK)
            rc = wyl_fact_graph_stage_publish (&stage.directory, &stage.stage);
          if (rc != WYRELOG_E_OK) {
            provisioning_degrade (store, op_uuid, attempt, cur,
                WYL_POLICY_GRAPH_ERROR_PATH);
            break;
          }
        }
        rc = provisioning_advance (store, op_uuid, attempt, cur,
                WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED);
        cur = WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED;
        break;
      case WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED:
      {
        WylPolicyGraphErrorClass fault = WYL_POLICY_GRAPH_ERROR_INTERNAL;
        rc = provisioning_verify_pair (&stage, op_uuid, &fault);
        if (rc != WYRELOG_E_OK) {
          provisioning_degrade (store, op_uuid, attempt, cur, fault);
          break;
        }
      }
        rc = provisioning_advance (store, op_uuid, attempt, cur,
                WYL_POLICY_GRAPH_PROVISIONING_VERIFIED);
        cur = WYL_POLICY_GRAPH_PROVISIONING_VERIFIED;
        break;
      case WYL_POLICY_GRAPH_PROVISIONING_VERIFIED:
        /* Finalize is policy-only: the transition couples the authority to ACTIVE.
         * The retained pair stays at nlink 2 -- the secure open requires it. */
        rc = provisioning_advance (store, op_uuid, attempt, cur,
                WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
        cur = WYL_POLICY_GRAPH_PROVISIONING_ACTIVE;
        break;
      default:
        rc = WYRELOG_E_INTERNAL;
        break;
    }
  }

  wyl_fact_graph_provisioning_stage_clear (&stage);
  if (rc != WYRELOG_E_OK)
    return rc;
  return provisioning_read_out (store, op_uuid, out_record);
}

wyrelog_error_t
wyl_fact_graph_provisioning_run (wyl_policy_store_t *store,
    const WylPolicyGraphProvisioningInput *input, const gchar *fact_root,
    WylPolicyGraphProvisioningRecord **out_record)
{
  if (store == NULL || input == NULL || fact_root == NULL
      || fact_root[0] == '\0')
    return WYRELOG_E_INVALID;
  if (out_record != NULL)
    *out_record = NULL;

  WylPolicyGraphProvisioningRecord *record = NULL;
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_prepare (store, input,
          &record, &result);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (result != WYL_POLICY_AUTHORITY_MUTATION_APPLIED
      && result != WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY) {
    wyl_policy_graph_provisioning_record_free (record);
    return WYRELOG_E_POLICY;
  }

  WylPolicyGraphAuthorityRecord *authority = NULL;
  rc = wyl_policy_store_read_graph_authority (store, record->tenant_id,
          record->graph_id, &authority);
  if (rc == WYRELOG_E_OK)
    rc = provisioning_drive (store, record, authority, fact_root, out_record);

  wyl_policy_graph_authority_record_free (authority);
  wyl_policy_graph_provisioning_record_free (record);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_provisioning_recover (wyl_policy_store_t *store,
    const gchar *op_uuid, const gchar *fact_root,
    WylPolicyGraphProvisioningRecord **out_record)
{
  if (store == NULL || op_uuid == NULL || fact_root == NULL
      || fact_root[0] == '\0')
    return WYRELOG_E_INVALID;
  if (out_record != NULL)
    *out_record = NULL;

  WylPolicyGraphProvisioningRecord *record = NULL;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_read (store, op_uuid,
          &record);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylPolicyGraphAuthorityRecord *authority = NULL;
  rc = wyl_policy_store_read_graph_authority (store, record->tenant_id,
          record->graph_id, &authority);
  if (rc == WYRELOG_E_OK)
    rc = provisioning_drive (store, record, authority, fact_root, out_record);

  wyl_policy_graph_authority_record_free (authority);
  wyl_policy_graph_provisioning_record_free (record);
  return rc;
}
#endif

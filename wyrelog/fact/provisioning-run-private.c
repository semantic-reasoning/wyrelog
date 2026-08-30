/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/provisioning-run-private.h"

/* Open the graph directory (without staging) and build the exact store identity
 * from a durable record and its authority.  Used to resume an already-published
 * pair, where stage_prepare would reject the two-link final.  Leaves the stage
 * handle at INIT; only resolver, directory, and identity are populated. */
static wyrelog_error_t
provisioning_open_context (const gchar *fact_root,
    const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority,
    gboolean create_directory, WylFactGraphProvisioningStage *out_stage)
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
            create_directory, &out_stage->directory);
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
#ifdef G_OS_WIN32
  if (record->has_windows_evidence)
    out_stage->stage.operation_evidence = record->windows_evidence;
#endif
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
#ifdef G_OS_WIN32
  wyrelog_error_t rc =
      wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence
        (&stage->directory, op_uuid, &stage->stage.operation_evidence, &pair);
#else
  wyrelog_error_t rc = wyl_fact_graph_directory_open_provisioned_pair_exact
        (&stage->directory, op_uuid, &pair);
#endif
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

#ifdef G_OS_WIN32
static wyrelog_error_t
provisioning_persist_windows_evidence (wyl_policy_store_t *store,
    const gchar *op_uuid, WylFactGraphProvisioningStage *stage)
{
  WylFactGraphWinOperationEvidence evidence = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_stage_get_windows_operation_evidence
        (&stage->stage, &evidence);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_graph_provisioning_set_windows_evidence (store,
            op_uuid, &evidence);
  return rc;
}
#endif

#ifdef __APPLE__
static GMutex provisioning_darwin_mutex;

#ifdef WYL_TEST_HANDLE_SEAMS
static WylFactGraphDarwinCoordinatorTestHook provisioning_darwin_test_hook;
static gpointer provisioning_darwin_test_hook_data;

void
wyl_fact_graph_darwin_coordinator_set_test_hook (
  WylFactGraphDarwinCoordinatorTestHook hook, gpointer user_data)
{
  provisioning_darwin_test_hook = hook;
  provisioning_darwin_test_hook_data = user_data;
}

static void
provisioning_darwin_checkpoint (
  WylFactGraphDarwinCoordinatorCheckpoint checkpoint, const gchar *op_uuid)
{
  if (provisioning_darwin_test_hook != NULL)
    provisioning_darwin_test_hook (checkpoint, op_uuid,
        provisioning_darwin_test_hook_data);
}

static void
provisioning_darwin_phase_checkpoint (WylPolicyGraphProvisioningPhase phase,
    const gchar *op_uuid)
{
  WylFactGraphDarwinCoordinatorCheckpoint checkpoint = phase
      == WYL_POLICY_GRAPH_PROVISIONING_STAGED ?
      WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_STAGED_PUBLICATION :
      phase == WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED ?
      WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_PUBLISHED_PUBLICATION :
      phase == WYL_POLICY_GRAPH_PROVISIONING_VERIFIED ?
      WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_VERIFIED_PUBLICATION :
      WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_ACTIVE_PUBLICATION;
  provisioning_darwin_checkpoint (checkpoint, op_uuid);
}
#else
#define provisioning_darwin_checkpoint(checkpoint, op_uuid) ((void) 0)
#define provisioning_darwin_phase_checkpoint(phase, op_uuid) ((void) 0)
#endif

static gboolean
provisioning_darwin_record_identity_matches (
  const WylPolicyGraphProvisioningRecord *expected,
  const WylPolicyGraphProvisioningRecord *actual)
{
  return expected != NULL && actual != NULL
         && g_strcmp0 (actual->op_uuid, expected->op_uuid) == 0
         && g_strcmp0 (actual->tenant_id, expected->tenant_id) == 0
         && g_strcmp0 (actual->graph_id, expected->graph_id) == 0
         && g_strcmp0 (actual->store_uuid, expected->store_uuid) == 0
         && g_strcmp0 (actual->stage_basename,
             expected->stage_basename) == 0
         && actual->expected_lifecycle_generation
         == expected->expected_lifecycle_generation
         && actual->expected_reconciliation_generation
         == expected->expected_reconciliation_generation
         && actual->attempt == expected->attempt;
}

static gboolean
provisioning_darwin_record_matches (
  const WylPolicyGraphProvisioningRecord *expected,
  const WylPolicyGraphProvisioningRecord *actual, GBytes *expected_evidence)
{
  return provisioning_darwin_record_identity_matches (expected, actual)
         && ((expected_evidence == NULL
         && actual->darwin_operation_evidence == NULL)
         || (expected_evidence != NULL
         && actual->darwin_operation_evidence != NULL
         && g_bytes_equal (actual->darwin_operation_evidence,
         expected_evidence)));
}

static gboolean
provisioning_darwin_authority_matches (
  const WylPolicyGraphProvisioningRecord *record,
  const WylPolicyGraphAuthorityRecord *authority)
{
  if (record == NULL || authority == NULL || !authority->has_store_identity
      || g_strcmp0 (record->tenant_id, authority->tenant_id) != 0
      || g_strcmp0 (record->graph_id, authority->graph_id) != 0
      || g_strcmp0 (record->store_uuid, authority->store_uuid) != 0
      || authority->format_version == 0
      || authority->path_encoding_version == 0
      || authority->reconciliation_generation
      != record->expected_reconciliation_generation)
    return FALSE;
  if (record->phase == WYL_POLICY_GRAPH_PROVISIONING_ACTIVE)
    return authority->lifecycle_state == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
           && authority->lifecycle_generation
           == record->expected_lifecycle_generation + 1;
  return record->phase >= WYL_POLICY_GRAPH_PROVISIONING_RESERVED
         && record->phase <= WYL_POLICY_GRAPH_PROVISIONING_VERIFIED
         && authority->lifecycle_state
         == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING
         && authority->lifecycle_generation
         == record->expected_lifecycle_generation;
}

static wyrelog_error_t
provisioning_darwin_decode_evidence (
  const WylPolicyGraphProvisioningRecord *record,
  WylFactGraphDarwinOperationEvidence *out_evidence)
{
  memset (out_evidence, 0, sizeof *out_evidence);
  if (record == NULL || record->darwin_operation_evidence == NULL)
    return WYRELOG_E_POLICY;
  gsize length = 0;
  const guint8 *bytes = g_bytes_get_data (record->darwin_operation_evidence,
          &length);
  if (bytes == NULL
      || length != WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE)
    return WYRELOG_E_POLICY;
  return wyl_fact_graph_darwin_evidence_decode (bytes, length,
             record->op_uuid, out_evidence);
}

static WylPolicyGraphErrorClass
provisioning_darwin_identity_error_class (WylFactStoreIdentityResult result)
{
  switch (result) {
    case WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY:
      return WYL_POLICY_GRAPH_ERROR_IDENTITY;
    case WYL_FACT_STORE_IDENTITY_RESULT_FORMAT:
    case WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING:
      return WYL_POLICY_GRAPH_ERROR_FORMAT;
    case WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA:
      return WYL_POLICY_GRAPH_ERROR_SCHEMA;
    case WYL_FACT_STORE_IDENTITY_RESULT_OPEN:
      return WYL_POLICY_GRAPH_ERROR_OPEN;
    case WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL:
    case WYL_FACT_STORE_IDENTITY_RESULT_NONE:
    default:
      return WYL_POLICY_GRAPH_ERROR_INTERNAL;
  }
}

static wyrelog_error_t
provisioning_darwin_open_pair (WylFactGraphProvisioningStage *stage,
    const WylPolicyGraphProvisioningRecord *record,
    WylFactGraphProvisionedPair **out_pair)
{
  *out_pair = NULL;
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  wyrelog_error_t rc = provisioning_darwin_decode_evidence (record,
          &evidence);
  if (rc == WYRELOG_E_OK)
    rc =
        wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
          (&stage->directory, record->op_uuid, &evidence, out_pair);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_provisioned_pair_revalidate (*out_pair);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_pair, wyl_fact_graph_provisioned_pair_free);
  return rc;
}

static wyrelog_error_t
provisioning_darwin_secure_pair (WylFactGraphProvisioningStage *stage,
    const WylPolicyGraphProvisioningRecord *record, gboolean initialize,
    WylPolicyGraphErrorClass *out_class, gboolean *out_degrade_allowed)
{
  *out_class = WYL_POLICY_GRAPH_ERROR_OPEN;
  *out_degrade_allowed = FALSE;
  WylFactGraphProvisionedPair *pair = NULL;
  wyrelog_error_t rc = provisioning_darwin_open_pair (stage, record, &pair);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  WylFactStorePinnedFailureOrigin failure_origin =
      WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_NONE;
  if (initialize)
    rc = wyl_fact_store_open_identified_provisioned_pair_pinned_classified
          (pair, &stage->identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result,
            &failure_origin);
  if (rc == WYRELOG_E_OK) {
    result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    failure_origin = WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_NONE;
    rc = wyl_fact_store_open_identified_provisioned_pair_pinned_classified
          (pair, &stage->identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
            &result, &failure_origin);
  }
  if (rc != WYRELOG_E_OK) {
    if (failure_origin == WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_PROVENANCE) {
      *out_class = WYL_POLICY_GRAPH_ERROR_IDENTITY;
    } else if (failure_origin ==
        WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_STORAGE) {
      *out_class = provisioning_darwin_identity_error_class (result);
      *out_degrade_allowed = TRUE;
    } else {
      *out_class = WYL_POLICY_GRAPH_ERROR_INTERNAL;
    }
  } else {
    rc = wyl_fact_graph_provisioned_pair_revalidate (pair);
    if (rc != WYRELOG_E_OK)
      *out_class = WYL_POLICY_GRAPH_ERROR_IDENTITY;
  }
  wyl_fact_graph_provisioned_pair_free (pair);
  return rc;
}

static wyrelog_error_t
provisioning_darwin_degrade_checked (wyl_policy_store_t *store,
    WylPolicyStoreCoordinatorFence *fence,
    const WylPolicyGraphProvisioningRecord *record,
    WylPolicyGraphErrorClass error_class, wyrelog_error_t original)
{
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  wyrelog_error_t transition_rc =
      wyl_policy_store_graph_provisioning_transition (store, record->op_uuid,
          record->phase,
          WYL_POLICY_GRAPH_PROVISIONING_DEGRADED, record->attempt, error_class,
          &result);
  WylPolicyGraphProvisioningRecord *current = NULL;
  wyrelog_error_t read_rc = wyl_policy_store_graph_provisioning_read (store,
          record->op_uuid, &current);
  if (read_rc != WYRELOG_E_OK)
    return read_rc;
  gboolean exact = provisioning_darwin_record_matches (record, current,
          record->darwin_operation_evidence);
  if (!exact) {
    wyl_policy_graph_provisioning_record_free (current);
    return WYRELOG_E_POLICY;
  }
  if (current->phase == WYL_POLICY_GRAPH_PROVISIONING_DEGRADED) {
    WylPolicyGraphAuthorityRecord *authority = NULL;
    wyrelog_error_t authority_rc = wyl_policy_store_read_graph_authority (store,
            current->tenant_id, current->graph_id, &authority);
    gboolean authority_exact = authority_rc == WYRELOG_E_OK
        && authority->has_store_identity
        && g_strcmp0 (authority->store_uuid, current->store_uuid) == 0
        && authority->lifecycle_state == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED
        && authority->lifecycle_generation
        == current->expected_lifecycle_generation + 1
        && authority->reconciliation_generation
        == current->expected_reconciliation_generation
        && authority->last_error_class == error_class;
    wyl_policy_graph_authority_record_free (authority);
    wyl_policy_graph_provisioning_record_free (current);
    if (authority_rc != WYRELOG_E_OK)
      return authority_rc;
    if (!authority_exact)
      return WYRELOG_E_BUSY;
    wyrelog_error_t publication_rc =
        wyl_policy_store_coordinator_fence_publish (fence);
    if (publication_rc != WYRELOG_E_OK)
      return publication_rc;
    return original;
  }
  gboolean concurrent_progress = current->phase != record->phase;
  wyl_policy_graph_provisioning_record_free (current);
  if (concurrent_progress)
    return WYRELOG_E_BUSY;
  return transition_rc != WYRELOG_E_OK ? transition_rc : WYRELOG_E_POLICY;
}

static wyrelog_error_t
provisioning_darwin_advance_exact (wyl_policy_store_t *store,
    WylPolicyStoreCoordinatorFence *fence,
    const WylPolicyGraphProvisioningRecord *record,
    WylPolicyGraphProvisioningPhase target,
    WylPolicyGraphProvisioningRecord **out_next)
{
  *out_next = NULL;
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  wyrelog_error_t transition_rc =
      wyl_policy_store_graph_provisioning_transition (store, record->op_uuid,
          record->phase, target, record->attempt,
          WYL_POLICY_GRAPH_ERROR_NONE, &result);
  WylPolicyGraphProvisioningRecord *current = NULL;
  wyrelog_error_t read_rc = wyl_policy_store_graph_provisioning_read (store,
          record->op_uuid, &current);
  if (read_rc != WYRELOG_E_OK)
    return read_rc;
  gboolean exact = provisioning_darwin_record_matches (record, current,
          record->darwin_operation_evidence);
  if (!exact) {
    wyl_policy_graph_provisioning_record_free (current);
    return WYRELOG_E_POLICY;
  }
  if (current->phase == target) {
    if (target == WYL_POLICY_GRAPH_PROVISIONING_ACTIVE) {
      WylPolicyGraphAuthorityRecord *authority = NULL;
      wyrelog_error_t authority_rc = wyl_policy_store_read_graph_authority
            (store, current->tenant_id, current->graph_id, &authority);
      gboolean authority_exact = authority_rc == WYRELOG_E_OK
          && provisioning_darwin_authority_matches (current, authority)
          && authority->last_error_class == WYL_POLICY_GRAPH_ERROR_NONE;
      wyl_policy_graph_authority_record_free (authority);
      if (authority_rc != WYRELOG_E_OK || !authority_exact) {
        wyl_policy_graph_provisioning_record_free (current);
        return authority_rc != WYRELOG_E_OK ? authority_rc : WYRELOG_E_POLICY;
      }
    }
    wyrelog_error_t publication_rc =
        wyl_policy_store_coordinator_fence_publish (fence);
    if (publication_rc != WYRELOG_E_OK) {
      wyl_policy_graph_provisioning_record_free (current);
      return publication_rc;
    }
    provisioning_darwin_phase_checkpoint (target, current->op_uuid);
    *out_next = current;
    return WYRELOG_E_OK;
  }
  gboolean concurrent_progress = current->phase > target
      && current->phase < WYL_POLICY_GRAPH_PROVISIONING_DEGRADED;
  wyl_policy_graph_provisioning_record_free (current);
  if (concurrent_progress)
    return WYRELOG_E_BUSY;
  if (transition_rc != WYRELOG_E_OK)
    return transition_rc;
  return result == WYL_POLICY_AUTHORITY_MUTATION_STALE ? WYRELOG_E_BUSY :
         WYRELOG_E_POLICY;
}

static wyrelog_error_t
provisioning_darwin_persist_evidence_uncertain (wyl_policy_store_t *store,
    WylPolicyStoreCoordinatorFence *fence,
    const WylPolicyGraphProvisioningRecord *record,
    const WylFactGraphDarwinOperationEvidence *evidence,
    WylPolicyGraphProvisioningRecord **out_current)
{
  *out_current = NULL;
  g_autoptr (GBytes) bytes = g_bytes_new (evidence->bytes,
          sizeof evidence->bytes);
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  wyrelog_error_t setter_rc =
      wyl_policy_store_graph_provisioning_set_darwin_evidence (store,
          record->op_uuid, bytes, &result);
  WylPolicyGraphProvisioningRecord *current = NULL;
  wyrelog_error_t read_rc = wyl_policy_store_graph_provisioning_read (store,
          record->op_uuid, &current);
  if (read_rc != WYRELOG_E_OK)
    return read_rc;
  WylFactGraphDarwinOperationEvidence decoded = { 0 };
  gboolean exact = provisioning_darwin_record_matches (record, current, bytes)
      && provisioning_darwin_decode_evidence (current, &decoded)
      == WYRELOG_E_OK;
  if (!exact) {
    wyl_policy_graph_provisioning_record_free (current);
    return setter_rc != WYRELOG_E_OK ? setter_rc : WYRELOG_E_POLICY;
  }
  if (current->phase == WYL_POLICY_GRAPH_PROVISIONING_RESERVED) {
    wyrelog_error_t publication_rc =
        wyl_policy_store_coordinator_fence_publish (fence);
    if (publication_rc != WYRELOG_E_OK) {
      wyl_policy_graph_provisioning_record_free (current);
      return publication_rc;
    }
    *out_current = current;
    return WYRELOG_E_OK;
  }
  gboolean concurrent_progress = current->phase
      > WYL_POLICY_GRAPH_PROVISIONING_RESERVED
      && current->phase < WYL_POLICY_GRAPH_PROVISIONING_DEGRADED;
  wyl_policy_graph_provisioning_record_free (current);
  return concurrent_progress ? WYRELOG_E_BUSY : WYRELOG_E_POLICY;
}

static wyrelog_error_t
provisioning_darwin_resolve_existing_final (wyl_policy_store_t *store,
    const WylPolicyGraphProvisioningRecord *record,
    WylPolicyGraphProvisioningRecord **out_current)
{
  *out_current = NULL;
  WylPolicyGraphProvisioningRecord *current = NULL;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_read (store,
          record->op_uuid, &current);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!provisioning_darwin_record_identity_matches (record, current)) {
    wyl_policy_graph_provisioning_record_free (current);
    return WYRELOG_E_POLICY;
  }
  if (current->darwin_operation_evidence == NULL) {
    wyl_policy_graph_provisioning_record_free (current);
    return WYRELOG_E_POLICY;
  }
  WylFactGraphDarwinOperationEvidence decoded = { 0 };
  rc = provisioning_darwin_decode_evidence (current, &decoded);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_graph_provisioning_record_free (current);
    return rc;
  }
  if (current->phase == WYL_POLICY_GRAPH_PROVISIONING_RESERVED) {
    *out_current = current;
    return WYRELOG_E_OK;
  }
  gboolean concurrent_progress = current->phase
      > WYL_POLICY_GRAPH_PROVISIONING_RESERVED
      && current->phase < WYL_POLICY_GRAPH_PROVISIONING_DEGRADED;
  wyl_policy_graph_provisioning_record_free (current);
  return concurrent_progress ? WYRELOG_E_BUSY : WYRELOG_E_POLICY;
}

static wyrelog_error_t
provisioning_darwin_open_failure (wyl_policy_store_t *store,
    WylPolicyStoreCoordinatorFence *fence,
    const WylPolicyGraphProvisioningRecord *record, wyrelog_error_t rc)
{
  if (rc == WYRELOG_E_POLICY)
    return rc;
  WylPolicyGraphErrorClass error_class = rc == WYRELOG_E_NOT_FOUND ?
      WYL_POLICY_GRAPH_ERROR_RECOVERY : WYL_POLICY_GRAPH_ERROR_OPEN;
  return provisioning_darwin_degrade_checked (store, fence, record,
             error_class, rc);
}

static wyrelog_error_t
provisioning_drive_darwin (wyl_policy_store_t *store, const gchar *op_uuid,
    const gchar *fact_root, WylPolicyStoreCoordinatorFence *fence,
    WylPolicyGraphProvisioningRecord **out_record)
{
  g_autoptr (GMutexLocker) locker =
      g_mutex_locker_new (&provisioning_darwin_mutex);
  WylPolicyGraphProvisioningRecord *current = NULL;
  WylPolicyGraphAuthorityRecord *authority = NULL;
  WylFactGraphProvisioningStage stage = WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT;
  wyrelog_error_t rc = wyl_policy_store_graph_provisioning_read (store,
          op_uuid, &current);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (current->phase == WYL_POLICY_GRAPH_PROVISIONING_DEGRADED) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  rc = wyl_policy_store_read_graph_authority (store, current->tenant_id,
          current->graph_id, &authority);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (!provisioning_darwin_authority_matches (current, authority)) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  if (current->darwin_operation_evidence != NULL) {
    WylFactGraphDarwinOperationEvidence decoded = { 0 };
    rc = provisioning_darwin_decode_evidence (current, &decoded);
    if (rc != WYRELOG_E_OK)
      goto out;
  } else if (current->phase != WYL_POLICY_GRAPH_PROVISIONING_RESERVED) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }

  /* Recovery can begin from a reservation prepared by a caller that never
   * published its encrypted in-memory image.  Make the exact policy snapshot
   * durable before the first filesystem mutation. */
  rc = wyl_policy_store_coordinator_fence_publish (fence);
  if (rc != WYRELOG_E_OK)
    goto out;

  rc = provisioning_open_context (fact_root, current, authority,
          current->phase == WYL_POLICY_GRAPH_PROVISIONING_RESERVED
          && current->darwin_operation_evidence == NULL, &stage);
  if (rc != WYRELOG_E_OK) {
    if (current->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE
        && current->darwin_operation_evidence != NULL)
      rc = provisioning_darwin_open_failure (store, fence, current, rc);
    goto out;
  }

  if (current->phase == WYL_POLICY_GRAPH_PROVISIONING_RESERVED
      && current->darwin_operation_evidence == NULL) {
    WylFactGraphDarwinOperationEvidence evidence = { 0 };
    WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
    provisioning_darwin_checkpoint (
      WYL_FACT_GRAPH_DARWIN_COORDINATOR_BEFORE_FINAL_CREATION,
      current->op_uuid);
    rc = wyl_fact_graph_directory_create_darwin_provisioned_final
          (&stage.directory, current->op_uuid, &evidence, &final);
    wyl_fact_graph_regular_file_clear (&final);
    if (rc == WYRELOG_E_BUSY) {
      WylPolicyGraphProvisioningRecord *resolved = NULL;
      rc = provisioning_darwin_resolve_existing_final (store, current,
              &resolved);
      if (rc != WYRELOG_E_OK)
        goto out;
      wyl_policy_graph_provisioning_record_free (current);
      current = resolved;
      rc = wyl_policy_store_coordinator_fence_publish (fence);
      if (rc != WYRELOG_E_OK)
        goto out;
    } else {
      if (rc != WYRELOG_E_OK)
        goto out;
      provisioning_darwin_checkpoint (
        WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_FINAL_CREATION,
        current->op_uuid);
      WylPolicyGraphProvisioningRecord *persisted = NULL;
      rc = provisioning_darwin_persist_evidence_uncertain (store, fence,
              current, &evidence, &persisted);
      if (rc != WYRELOG_E_OK)
        goto out;
      wyl_policy_graph_provisioning_record_free (current);
      current = persisted;
      provisioning_darwin_checkpoint (
        WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_EVIDENCE_PUBLICATION,
        current->op_uuid);
    }
  } else if (current->darwin_operation_evidence == NULL) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }

  while (current->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE) {
    WylPolicyGraphProvisioningRecord *next = NULL;
    if (current->phase == WYL_POLICY_GRAPH_PROVISIONING_RESERVED
        || current->phase == WYL_POLICY_GRAPH_PROVISIONING_STAGED) {
      WylFactGraphProvisionedPair *pair = NULL;
      rc = provisioning_darwin_open_pair (&stage, current, &pair);
      wyl_fact_graph_provisioned_pair_free (pair);
      if (rc != WYRELOG_E_OK) {
        rc = provisioning_darwin_open_failure (store, fence, current, rc);
        goto out;
      }
      WylPolicyGraphProvisioningPhase target = current->phase
          == WYL_POLICY_GRAPH_PROVISIONING_RESERVED ?
          WYL_POLICY_GRAPH_PROVISIONING_STAGED :
          WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED;
      rc = provisioning_darwin_advance_exact (store, fence, current, target,
              &next);
    } else if (current->phase == WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED
        || current->phase == WYL_POLICY_GRAPH_PROVISIONING_VERIFIED) {
      WylPolicyGraphErrorClass error_class = WYL_POLICY_GRAPH_ERROR_INTERNAL;
      gboolean degrade_allowed = FALSE;
      gboolean initialize = current->phase
          == WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED;
      rc = provisioning_darwin_secure_pair (&stage, current, initialize,
              &error_class, &degrade_allowed);
      if (rc != WYRELOG_E_OK) {
        rc = degrade_allowed ? provisioning_darwin_degrade_checked (store,
                fence, current, error_class, rc) :
            rc;
        goto out;
      }
      WylPolicyGraphProvisioningPhase target = initialize ?
          WYL_POLICY_GRAPH_PROVISIONING_VERIFIED :
          WYL_POLICY_GRAPH_PROVISIONING_ACTIVE;
      rc = provisioning_darwin_advance_exact (store, fence, current, target,
              &next);
    } else {
      rc = WYRELOG_E_POLICY;
    }
    if (rc != WYRELOG_E_OK)
      goto out;
    wyl_policy_graph_provisioning_record_free (current);
    current = next;
  }

  /* ACTIVE is an admission state, not a trusted fast path.  Re-read both
   * authorities and revalidate the exact evidence-bound pair and identity. */
  g_clear_pointer (&authority, wyl_policy_graph_authority_record_free);
  rc = wyl_policy_store_read_graph_authority (store, current->tenant_id,
          current->graph_id, &authority);
  if (rc != WYRELOG_E_OK
      || !provisioning_darwin_authority_matches (current, authority)) {
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    goto out;
  }
  WylPolicyGraphErrorClass active_class = WYL_POLICY_GRAPH_ERROR_INTERNAL;
  gboolean active_degrade_allowed = FALSE;
  rc = provisioning_darwin_secure_pair (&stage, current, FALSE, &active_class,
          &active_degrade_allowed);
  if (rc != WYRELOG_E_OK)
    goto out;
  WylPolicyGraphProvisioningRecord *fresh = NULL;
  rc = wyl_policy_store_graph_provisioning_read (store, current->op_uuid,
          &fresh);
  if (rc == WYRELOG_E_OK
      && (!provisioning_darwin_record_matches (current, fresh,
      current->darwin_operation_evidence)
      || fresh->phase != WYL_POLICY_GRAPH_PROVISIONING_ACTIVE))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK) {
    wyl_policy_graph_provisioning_record_free (fresh);
    goto out;
  }
  wyl_policy_graph_provisioning_record_free (current);
  current = fresh;
  g_clear_pointer (&authority, wyl_policy_graph_authority_record_free);
  rc = wyl_policy_store_read_graph_authority (store, current->tenant_id,
          current->graph_id, &authority);
  if (rc != WYRELOG_E_OK
      || !provisioning_darwin_authority_matches (current, authority)) {
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    goto out;
  }
  if (out_record != NULL) {
    *out_record = current;
    current = NULL;
  }

out:
  wyl_fact_graph_provisioning_stage_clear (&stage);
  wyl_policy_graph_authority_record_free (authority);
  wyl_policy_graph_provisioning_record_free (current);
  return rc;
}
#endif

/* Drive record->phase forward to ACTIVE, resuming from whatever seam the durable
 * phase names.  Borrows record and authority. */
static wyrelog_error_t
provisioning_drive (wyl_policy_store_t *store,
    const WylPolicyGraphProvisioningRecord *record,
    const WylPolicyGraphAuthorityRecord *authority, const gchar *fact_root,
    WylPolicyStoreCoordinatorFence *coordinator_fence,
    WylPolicyGraphProvisioningRecord **out_record)
{
#ifdef __APPLE__
  (void) authority;
  return provisioning_drive_darwin (store, record->op_uuid, fact_root,
             coordinator_fence, out_record);
#else
  (void) coordinator_fence;
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
#ifdef G_OS_WIN32
    if (staged_flow && !record->has_windows_evidence) {
      rc = provisioning_persist_windows_evidence (store, op_uuid, &stage);
      if (rc != WYRELOG_E_OK) {
        provisioning_degrade (store, op_uuid, attempt, phase,
            WYL_POLICY_GRAPH_ERROR_IDENTITY);
        return rc;
      }
    }
#endif
  }

  if (!staged_flow
      && stage.identity.store_uuid == NULL
      && phase != WYL_POLICY_GRAPH_PROVISIONING_VERIFIED) {
    /* Need the directory + identity to verify the retained pair. */
    rc = provisioning_open_context (fact_root, record, authority, FALSE,
            &stage);
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
#ifdef G_OS_WIN32
          WylFactGraphWinOperationEvidence evidence = { 0 };
          rc = wyl_fact_graph_stage_get_windows_operation_evidence
                (&stage.stage, &evidence);
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
         * POSIX retains nlink 2; Windows retains its persisted evidence tuple. */
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
#endif
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

  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef __APPLE__
  g_auto (WylPolicyStoreCoordinatorFence) fence =
      WYL_POLICY_STORE_COORDINATOR_FENCE_INIT;
  rc = wyl_policy_store_coordinator_fence_acquire (store, &fence);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif

  WylPolicyGraphProvisioningRecord *record = NULL;
  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  rc = wyl_policy_store_graph_provisioning_prepare (store, input, &record,
          &result);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (result != WYL_POLICY_AUTHORITY_MUTATION_APPLIED
      && result != WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY) {
    wyl_policy_graph_provisioning_record_free (record);
    return WYRELOG_E_POLICY;
  }
#ifdef __APPLE__
  rc = wyl_policy_store_coordinator_fence_publish (&fence);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_graph_provisioning_record_free (record);
    return rc;
  }
  provisioning_darwin_checkpoint (
    WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_RESERVED_PUBLICATION,
    record->op_uuid);
#endif

  WylPolicyGraphAuthorityRecord *authority = NULL;
  rc = wyl_policy_store_read_graph_authority (store, record->tenant_id,
          record->graph_id, &authority);
  if (rc == WYRELOG_E_OK)
    rc = provisioning_drive (store, record, authority, fact_root,
#ifdef __APPLE__
            &fence,
#else
            NULL,
#endif
            out_record);

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

  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef __APPLE__
  g_auto (WylPolicyStoreCoordinatorFence) fence =
      WYL_POLICY_STORE_COORDINATOR_FENCE_INIT;
  rc = wyl_policy_store_coordinator_fence_acquire (store, &fence);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif

  WylPolicyGraphProvisioningRecord *record = NULL;
  rc = wyl_policy_store_graph_provisioning_read (store, op_uuid, &record);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylPolicyGraphAuthorityRecord *authority = NULL;
  rc = wyl_policy_store_read_graph_authority (store, record->tenant_id,
          record->graph_id, &authority);
  if (rc == WYRELOG_E_OK)
    rc = provisioning_drive (store, record, authority, fact_root,
#ifdef __APPLE__
            &fence,
#else
            NULL,
#endif
            out_record);

  wyl_policy_graph_authority_record_free (authority);
  wyl_policy_graph_provisioning_record_free (record);
  return rc;
}

wyrelog_error_t
wyl_fact_relation_activation_reconcile
  (wyl_policy_store_t *policy_store, wyl_fact_store_t *fact_store,
    const gchar *tenant_id, const gchar *graph_id, const gchar *namespace_id,
    const gchar *relation_name, guint64 expected_activation_generation,
    WylPolicyAuthorityMutationResult *out_result)
{
  if (out_result != NULL)
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  if (policy_store == NULL || fact_store == NULL || out_result == NULL
      || tenant_id == NULL || graph_id == NULL || namespace_id == NULL
      || relation_name == NULL || expected_activation_generation >= G_MAXINT64)
    return WYRELOG_E_INVALID;

  WylPolicyRelationActivationRecord *record = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_relation_activation (policy_store,
          tenant_id, graph_id, namespace_id, relation_name, &record);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (record->activation_generation != expected_activation_generation) {
    wyl_policy_relation_activation_record_free (record);
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_STALE;
    return WYRELOG_E_POLICY;
  }
  if (record->lifecycle_state == WYL_POLICY_RELATION_ACTIVATION_ACTIVE) {
    wyl_policy_relation_activation_record_free (record);
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY;
    return WYRELOG_E_OK;
  }
  if (record->lifecycle_state != WYL_POLICY_RELATION_ACTIVATION_ACTIVATING
      || !record->has_pending_schema_version) {
    wyl_policy_relation_activation_record_free (record);
    return WYRELOG_E_POLICY;
  }

  gboolean relation_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *loaded = NULL;
  gsize n_loaded = 0;
  if (record->pending_schema_version > G_MAXUINT32)
    rc = WYRELOG_E_POLICY;
  else
    rc = wyl_policy_store_load_fact_relation_schema_columns (policy_store,
            tenant_id, graph_id, namespace_id, relation_name,
            (guint32) record->pending_schema_version, &relation_visible,
            &loaded, &n_loaded);
  const gchar *error_class = rc == WYRELOG_E_OK ? "projection" : "schema";
  if (rc == WYRELOG_E_OK) {
    wyl_policy_fact_relation_schema_column_t *columns =
        g_new0 (wyl_policy_fact_relation_schema_column_t, n_loaded);
    if (columns == NULL && n_loaded != 0)
      rc = WYRELOG_E_NOMEM;
    for (gsize i = 0; rc == WYRELOG_E_OK && i < n_loaded; i++)
      columns[i] = (wyl_policy_fact_relation_schema_column_t) {
        .column_name = loaded[i].column_name,
        .column_type = loaded[i].column_type,
        .nullable = loaded[i].nullable,
        .visible = loaded[i].visible
      };
    wyl_policy_fact_relation_schema_options_t schema = {
      .tenant_id = tenant_id,
      .graph_id = graph_id,
      .namespace_id = namespace_id,
      .relation_name = relation_name,
      .schema_version = (guint32) record->pending_schema_version,
      .relation_visible = relation_visible,
      .columns = columns,
      .n_columns = n_loaded,
      .queries = NULL,
      .n_queries = 0
    };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_store_ensure_projection (fact_store, &schema, NULL);
    gboolean exists = FALSE;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_store_validate_projection (fact_store, &schema, &exists);
    if (rc == WYRELOG_E_OK && !exists)
      rc = WYRELOG_E_POLICY;
    g_free (columns);
  }
  wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_transition_relation_activation (policy_store,
            tenant_id, graph_id, namespace_id, relation_name,
            WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
            expected_activation_generation,
            WYL_POLICY_RELATION_ACTIVATION_ACTIVE,
            TRUE, record->pending_schema_version, FALSE, 0, "none",
            out_result);
    wyl_policy_relation_activation_record_free (record);
    return rc;
  }

  /* A failed projection must never publish the pending version.  DEGRADED is
   * an explicit terminal state and may retain the prior active schema. */
  WylPolicyAuthorityMutationResult degrade_result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  wyrelog_error_t degrade_rc =
      wyl_policy_store_transition_relation_activation (policy_store,
          tenant_id, graph_id, namespace_id, relation_name,
          WYL_POLICY_RELATION_ACTIVATION_ACTIVATING,
          expected_activation_generation,
          WYL_POLICY_RELATION_ACTIVATION_DEGRADED,
          record->has_active_schema_version, record->active_schema_version,
          FALSE, 0, error_class, &degrade_result);
  wyl_policy_relation_activation_record_free (record);
  if (degrade_rc != WYRELOG_E_OK)
    return degrade_rc;
  *out_result = degrade_result;
  return rc;
}

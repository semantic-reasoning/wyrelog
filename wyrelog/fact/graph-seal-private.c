/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "graph-seal-private.h"

#include <string.h>

#include "replay-private.h"
#include "../wyl-handle-private.h"
#include "graph-artifact-namespace-private.h"
#include "graph-locator-private.h"

void
wyl_fact_graph_seal_outcome_clear (WylFactGraphSealOutcome *outcome)
{
  if (outcome == NULL)
    return;
  wyl_fact_graph_runtime_status_clear (&outcome->status);
  memset (outcome, 0, sizeof *outcome);
}

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  gboolean found;
  gboolean sealed;
} SealGraphProbe;

static wyrelog_error_t
capture_seal_state_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  SealGraphProbe *probe = user_data;
  if (g_strcmp0 (probe->tenant_id, info->tenant_id) == 0
      && g_strcmp0 (probe->graph_id, info->graph_id) == 0) {
    probe->found = TRUE;
    probe->sealed = info->sealed;
  }
  return WYRELOG_E_OK;
}

/* The graph's own existence and seal bit, never wyl_policy_store_fact_graph_
 * is_active.  That helper folds three conditions into one boolean -- the
 * graph does not exist, its tenant is sealed, or it is sealed -- and both
 * reads in this file need them apart. */
#if defined(WYL_TEST_HANDLE_SEAMS)
static WylFactGraphSealTestHook seal_test_hook;
static gpointer seal_test_hook_data;

void
wyl_fact_graph_seal_set_test_hook (WylFactGraphSealTestHook hook,
    gpointer user_data)
{
  seal_test_hook = hook;
  seal_test_hook_data = user_data;
}
#endif

/* Non-OK from the hook means the step fails *without running*.  See the
 * header: a hook that ran the step and then replaced its result would not
 * reach the branch it claims to test. */
static wyrelog_error_t
seal_step_fault (const gchar *phase)
{
#if defined(WYL_TEST_HANDLE_SEAMS)
  if (seal_test_hook != NULL)
    return seal_test_hook (phase, seal_test_hook_data);
#else
  (void) phase;
#endif
  return WYRELOG_E_OK;
}

static wyrelog_error_t
read_seal_state (wyl_policy_store_t *policy, const gchar *tenant_id,
    const gchar *graph_id, gboolean *out_found, gboolean *out_sealed)
{
  SealGraphProbe probe = { tenant_id, graph_id, FALSE, FALSE };
  wyrelog_error_t rc = wyl_policy_store_foreach_fact_graph (policy, tenant_id,
          capture_seal_state_cb, &probe);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_found = probe.found;
  *out_sealed = probe.sealed;
  return WYRELOG_E_OK;
}

/* Reopen after an abort, and only when the graph is not durably sealed.  The
 * rc is discarded on purpose: the seal is already failing and its own rc is
 * what the caller acts on, while a failed reopen leaves the graph closed but
 * unsealed -- which the next boot corrects, because the boot pass writes
 * admission from the durable bit in both directions. */
static void
reopen_after_abort (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key)
{
  (void) wyl_fact_graph_runtime_manager_open_admission (manager, key);
}

wyrelog_error_t
wyl_fact_graph_seal (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *manager, gint64 drain_timeout_us,
    WylFactGraphSealOutcome *out_outcome)
{
  if (out_outcome != NULL)
    memset (out_outcome, 0, sizeof *out_outcome);
  if (policy == NULL || graph_info == NULL || manager == NULL)
    return WYRELOG_E_INVALID;
  if (graph_info->tenant_id == NULL || graph_info->graph_id == NULL)
    return WYRELOG_E_INVALID;

  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* S1.  Read the graph's OWN durable seal, and its existence, separately.
   *
   * wyl_policy_store_fact_graph_is_active collapses three different
   * conditions into one boolean -- the graph does not exist, the tenant is
   * sealed, or the graph is sealed -- and skipping the durable write on any
   * of them is wrong in a different way each time.  A sealed tenant would
   * make this report success while never writing the graph's bit, so the seal
   * would evaporate at the next boot; a nonexistent graph would be reported
   * as sealed rather than NOT_FOUND.  Reading the graph's own flag is also
   * what the boot hook reads, so the two halves of this unit cannot disagree
   * about what "sealed" means. */
  gboolean found = FALSE, already_sealed = FALSE;
  rc = read_seal_state (policy, graph_info->tenant_id, graph_info->graph_id,
          &found, &already_sealed);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_graph_key_clear (&key);
    return rc;
  }
  if (!found) {
    wyl_fact_graph_key_clear (&key);
    return WYRELOG_E_NOT_FOUND;
  }

  /* S2.  Deny new work.  NOT_FOUND is not a failure: the runtime holds no
   * entry, so nothing can be admitted through it and the durable bit alone
   * carries the barrier until the next boot materializes one. */
  rc = wyl_fact_graph_runtime_manager_close_admission (manager, &key);
  gboolean barrier = rc == WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_NOT_FOUND) {
    wyl_fact_graph_key_clear (&key);
    return rc;
  }

  /* S3.  Wait for work admitted before the close.  A timeout aborts and
   * reopens, so the caller may retry from the top; the drain's filled status
   * names what was still running. */
  if (barrier) {
    WylFactGraphRuntimeStatus drained = { 0 };
    rc = wyl_fact_graph_runtime_manager_drain (manager, &key, drain_timeout_us,
            &drained);
    if (rc != WYRELOG_E_OK) {
      /* Gated on already_sealed, not merely on "before S4 in this call".  A
       * graph sealed by an earlier call -- or by the pre-existing endpoint,
       * which writes the durable bit with no runtime involvement at all --
       * must not be reopened by an aborted seal, or the abort produces the
       * one state this unit exists to make unrepresentable.
       *
       * That is the whole predicate.  An earlier draft also excluded the
       * ABANDONED case, which reads like a second rule but is not one:
       * open_admission refuses an abandoned entry anyway, so both sides of
       * that branch behaved identically.  A rule worth stating in one
       * sentence is worth keeping checkable. */
      if (!already_sealed)
        reopen_after_abort (manager, &key);
      if (out_outcome != NULL) {
        out_outcome->status = drained;
        /* An abort against an already-sealed graph leaves it closed, so
         * reporting FALSE here would tell a caller the graph is untouched
         * when it is in fact offline -- the same inaccuracy the ambiguous
         * write path carries a note about. */
        out_outcome->runtime_barrier_established = already_sealed;
      } else {
        wyl_fact_graph_runtime_status_clear (&drained);
      }
      wyl_fact_graph_key_clear (&key);
      return rc;
    }
    wyl_fact_graph_runtime_status_clear (&drained);
  }

  /* S4.  The linearization point.  Everything above is reversible and
   * everything below is not. */
  if (!already_sealed) {
    rc = seal_step_fault (WYL_FACT_GRAPH_SEAL_PHASE_DURABLE_WRITE);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_seal_fact_graph (policy, graph_info->tenant_id,
              graph_info->graph_id);
    if (rc != WYRELOG_E_OK) {
      /* A write that failed after committing is indistinguishable from one
       * that never committed, and the two need opposite compensations, so the
       * store is asked which it was.
       *
       * Asking whether the graph's own bit is set -- rather than whether it is
       * "active" -- is what keeps a sealed TENANT from making a failed write
       * look committed, the same conflation the read at the top of this
       * function exists to avoid.
       *
       * The probe guard below stays because the unknown case must fail
       * closed: reopening a possibly-sealed graph is the one direction that
       * produces "durably sealed and admitting".  Both the branch and that
       * guard are now driven -- see
       * /fact-graph-seal/ambiguous-write-{rolls-back,stands}, which fail when
       * the guard is dropped. */
      gboolean recheck_found = FALSE, recheck_sealed = FALSE;
      wyrelog_error_t probe_rc =
          seal_step_fault (WYL_FACT_GRAPH_SEAL_PHASE_RESEAL_PROBE);
      if (probe_rc == WYRELOG_E_OK)
        probe_rc = read_seal_state (policy, graph_info->tenant_id,
                graph_info->graph_id, &recheck_found, &recheck_sealed);
      if (probe_rc == WYRELOG_E_OK && recheck_found && recheck_sealed) {
        rc = WYRELOG_E_OK;              /* it committed after all */
      } else {
        /* Two sub-cases reach here, and they compensate and report
         * differently.  When the re-read succeeded, the graph is found and
         * unsealed: the write genuinely never committed, so the close is
         * rolled back and there is no barrier left to report.
         *
         * When the re-read itself failed the durable state is unknown, and
         * the close deliberately stands -- leaving a possibly-sealed graph
         * admitting is the one unsafe direction, and the next boot converges
         * whichever it turns out to be.  Reporting FALSE there would read as
         * "nothing happened" to a caller whose graph is in fact offline. */
        gboolean reopened = probe_rc == WYRELOG_E_OK && barrier;
        if (reopened)
          reopen_after_abort (manager, &key);
        if (out_outcome != NULL) {
          (void) wyl_fact_graph_runtime_manager_get_status (manager, &key,
              &out_outcome->status);
          /* Read the barrier off the admission actually observed after the
           * compensation rather than off the intent to reopen.
           * reopen_after_abort discards its rc and open_admission refuses a
           * shut-down or abandoned entry, so an intended reopen can leave the
           * graph closed; deriving the field makes both outcomes right
           * without a second rule to keep in step.
           *
           * Argued, not proved, and it is worth recording why this one keeps
           * that marker while the branch around it lost it.  Intent and
           * outcome agree whenever the reopen takes effect, and the only way
           * to make an intended reopen fail is to shut the manager down --
           * which also makes the status read fail, so the derived form
           * degrades to FALSE and the case proves nothing either way.  No
           * reachable test separates the two forms today. */
          out_outcome->runtime_barrier_established =
              out_outcome->status.admission == WYL_FACT_GRAPH_ADMISSION_CLOSED;
        }
        wyl_fact_graph_key_clear (&key);
        return rc;
      }
    }
  }

  if (out_outcome != NULL)
    out_outcome->sealed_committed = TRUE;

  /* S5.  Take the engine away.  Only reached with the drain done, which is
   * what makes evict_closed's blocking writer_lock wait bounded here -- it has
   * no timeout, so it must never follow a drain that did not finish. */
  if (barrier) {
    gboolean evicted = FALSE;
    wyrelog_error_t evict_rc = wyl_fact_graph_runtime_manager_evict_closed
          (manager, &key, &evicted);
    if (out_outcome != NULL)
      out_outcome->engine_evicted = evicted;
    /* A shutdown racing the eviction is not a seal failure: the durable bit
     * is set and the manager is tearing the engine down anyway. */
    /* INVALID means admission was reopened between S4 and S5, which leaves a
     * durably sealed graph admitting with its engine still published -- the
     * unrepresentable state, arrived at from the one direction the
     * compensation rule cannot cover.  Only a caller that violated the
     * documented locking can produce it, so re-close and retry once rather
     * than returning an argument-shaped error for a barrier failure. */
    if (evict_rc == WYRELOG_E_INVALID) {
      if (wyl_fact_graph_runtime_manager_close_admission (manager, &key)
          == WYRELOG_E_OK)
        evict_rc = wyl_fact_graph_runtime_manager_evict_closed (manager, &key,
                &evicted);
      if (out_outcome != NULL)
        out_outcome->engine_evicted = evicted;
    }
    if (evict_rc != WYRELOG_E_OK && evict_rc != WYRELOG_E_BUSY
        && evict_rc != WYRELOG_E_NOT_FOUND) {
      wyl_fact_graph_key_clear (&key);
      return evict_rc;
    }
  }

  if (out_outcome != NULL) {
    out_outcome->runtime_barrier_established = barrier;
    (void) wyl_fact_graph_runtime_manager_get_status (manager, &key,
        &out_outcome->status);
  }
  wyl_fact_graph_key_clear (&key);
  return WYRELOG_E_OK;
}

void
wyl_fact_graph_unseal_outcome_clear (WylFactGraphUnsealOutcome *outcome)
{
  if (outcome == NULL)
    return;
  wyl_fact_graph_runtime_status_clear (&outcome->status);
  memset (outcome, 0, sizeof *outcome);
}

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  wyl_policy_fact_graph_info_t info;
  gboolean found;
} UnsealGraphProbe;

static void
clear_unseal_graph_info (wyl_policy_fact_graph_info_t *info)
{
  g_free ((gchar *) info->tenant_id);
  g_free ((gchar *) info->graph_id);
  g_free ((gchar *) info->storage_uri);
  g_free ((gchar *) info->storage_path);
  g_free ((gchar *) info->owner_scope);
  memset (info, 0, sizeof *info);
}

static wyrelog_error_t
capture_unseal_graph_info_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  UnsealGraphProbe *probe = user_data;
  if (g_strcmp0 (probe->tenant_id, info->tenant_id) != 0
      || g_strcmp0 (probe->graph_id, info->graph_id) != 0)
    return WYRELOG_E_OK;
  probe->info.tenant_id = g_strdup (info->tenant_id);
  probe->info.graph_id = g_strdup (info->graph_id);
  probe->info.storage_uri = g_strdup (info->storage_uri);
  probe->info.storage_path = g_strdup (info->storage_path);
  probe->info.schema_version = info->schema_version;
  probe->info.owner_scope = g_strdup (info->owner_scope);
  probe->info.sealed = info->sealed;
  probe->found = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
read_unsealed_graph_info (wyl_policy_store_t *policy, const gchar *tenant_id,
    const gchar *graph_id, wyl_policy_fact_graph_info_t *out_info)
{
  UnsealGraphProbe probe = { .tenant_id = tenant_id, .graph_id = graph_id };
  wyrelog_error_t rc = wyl_policy_store_foreach_fact_graph (policy, tenant_id,
          capture_unseal_graph_info_cb, &probe);
  if (rc != WYRELOG_E_OK) {
    clear_unseal_graph_info (&probe.info);
    return rc;
  }
  if (!probe.found)
    return WYRELOG_E_NOT_FOUND;
  if (probe.info.sealed) {
    clear_unseal_graph_info (&probe.info);
    return WYRELOG_E_POLICY;
  }
  *out_info = probe.info;
  return WYRELOG_E_OK;
}

/* Compensation is part of the unseal transition, not best-effort cleanup.
 * Once the durable bit has been cleared, a failed eviction or reseal must be
 * visible to the caller: silently returning the triggering build/open error
 * strands an active graph behind a closed barrier and makes a retry look
 * stale.  NOT_FOUND from eviction is benign because there was no publication
 * to remove; every other failure is retained while the durable reseal is
 * still attempted. */
static wyrelog_error_t
compensate_unseal (wyl_policy_store_t *policy, const gchar *tenant_id,
    const gchar *graph_id, WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, WylFactGraphUnsealOutcome *outcome)
{
  gboolean evicted = FALSE;
  wyrelog_error_t evict_rc =
      wyl_fact_graph_runtime_manager_evict_closed (manager, key, &evicted);
  wyrelog_error_t reseal_rc = seal_step_fault
        (WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_RESEAL);
  if (reseal_rc == WYRELOG_E_OK)
    reseal_rc = wyl_policy_store_seal_fact_graph (policy, tenant_id, graph_id);

  wyrelog_error_t compensation_rc = WYRELOG_E_OK;
  if (evict_rc != WYRELOG_E_OK && evict_rc != WYRELOG_E_NOT_FOUND)
    compensation_rc = evict_rc;
  if (reseal_rc != WYRELOG_E_OK && compensation_rc == WYRELOG_E_OK)
    compensation_rc = reseal_rc;

  if (outcome != NULL) {
    outcome->engine_evicted = evict_rc == WYRELOG_E_OK && evicted;
    outcome->durable_reseal_applied = reseal_rc == WYRELOG_E_OK;
    outcome->compensation_failed = compensation_rc != WYRELOG_E_OK;
    outcome->compensation_error = compensation_rc;
    WylFactGraphRuntimeStatus after = { 0 };
    wyrelog_error_t status_rc =
        wyl_fact_graph_runtime_manager_get_status (manager, key, &after);
    outcome->engine_published = status_rc == WYRELOG_E_OK && after.queryable;
    wyl_fact_graph_runtime_status_clear (&after);
  }
  return compensation_rc;
}

/* The policy row and physical graph artifact are separate authorities. Keep
 * the artifact mutation lease alive for the complete unseal sequence so a
 * cooperative publisher cannot replace facts.duckdb between validation and
 * engine publication. Legacy graphs retain their path-only behavior because
 * they have no provisioned artifact namespace to fence. */
static wyrelog_error_t
acquire_graph_artifact_lease (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactArtifactNamespace **out_namespace,
    WylFactArtifactMutationLease **out_lease)
{
  *out_namespace = NULL;
  *out_lease = NULL;
  WylPolicyGraphAuthorityRecord *authority = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_graph_authority (policy,
          graph_info->tenant_id, graph_info->graph_id, &authority);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean provisioned = authority != NULL
      && authority->lifecycle_state
      != WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED;
  wyl_policy_graph_authority_record_free (authority);
  if (!provisioned)
    return WYRELOG_E_OK;

  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphRegularFile main_file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_autofree gchar *relative_dir = NULL;
  g_autofree gchar *relative_file = NULL;
  rc = wyl_fact_graph_locator_init (&locator, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
            graph_info->tenant_id, graph_info->graph_id, FALSE, &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK)
    relative_dir = wyl_fact_graph_locator_relative_dir (&locator);
  if (rc == WYRELOG_E_OK && relative_dir == NULL)
    rc = WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK)
    relative_file = g_strdup_printf ("%s/facts.duckdb", relative_dir);
  if (rc == WYRELOG_E_OK && relative_file == NULL)
    rc = WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_relative_regular (&resolver,
            relative_file, &main_file);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_namespace_open (&directory, &main_file,
            out_namespace);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_namespace_acquire_mutation_lease (*out_namespace,
            out_lease);
  /* Some lifecycle fixtures intentionally have an authority row before the
   * physical graph directory is provisioned. Preserve their existing
   * unseal/compensation path; a present artifact is still fail-closed below. */
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_namespace_free (*out_namespace);
    *out_namespace = NULL;
    *out_lease = NULL;
  }
  wyl_fact_graph_regular_file_clear (&main_file);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_directory_clear (&directory);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_unseal_core (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactRootWriterLease *root_lease,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *manager, gint64 drain_timeout_us,
    WylFactGraphUnsealOutcome *out_outcome)
{
  if (out_outcome != NULL) {
    memset (out_outcome, 0, sizeof *out_outcome);
    out_outcome->policy_result =
        WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  }
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (policy == NULL || graph_info == NULL || manager == NULL
      || graph_info->tenant_id == NULL || graph_info->graph_id == NULL)
    return WYRELOG_E_INVALID;
  if (root_lease != NULL) {
    rc = wyl_fact_root_writer_lease_verify (root_lease);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  WylFactGraphKey key = { 0 };
  rc = wyl_fact_graph_key_init (&key, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactArtifactNamespace *artifact_namespace = NULL;
  WylFactArtifactMutationLease *artifact_lease = NULL;
  rc = acquire_graph_artifact_lease (policy, fact_root, graph_info,
          &artifact_namespace, &artifact_lease);
  if (rc != WYRELOG_E_OK)
    goto finish;

  /* Close and drain before changing durable authority.  A pre-existing
   * runtime entry therefore cannot admit work while the engine is rebuilt;
   * a graph not yet held by the manager is safely minted CLOSED by the
   * refresh_closed primitive below. */
  WylFactGraphAdmission previous_admission = WYL_FACT_GRAPH_ADMISSION_CLOSED;
  guint64 admission_generation = 0;
  rc = wyl_fact_graph_runtime_manager_close_admission_with_previous (manager,
          &key, &previous_admission, &admission_generation);
  gboolean barrier = rc == WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_NOT_FOUND)
    goto finish;
  if (barrier) {
    WylFactGraphRuntimeStatus drained = { 0 };
    rc = wyl_fact_graph_runtime_manager_drain (manager, &key,
            drain_timeout_us, &drained);
    wyl_fact_graph_runtime_status_clear (&drained);
    if (rc != WYRELOG_E_OK)
      goto finish;
  }

  /* Take the runtime writer before the policy fence.  The token keeps the
   * entry CLOSED across the build and the durable commit, so no reader can
   * observe an engine whose authority transaction is not committed yet. */
  WylFactGraphRuntimePublication publication = { 0 };
  rc = wyl_fact_graph_runtime_publication_begin_closed (manager, &key,
          previous_admission,
          admission_generation,
          &publication);
  if (rc != WYRELOG_E_OK)
    goto finish;

  WylPolicyGraphPublicationFence fence =
      WYL_POLICY_GRAPH_PUBLICATION_FENCE_INIT;
  rc = wyl_policy_store_graph_publication_fence_begin (policy,
          graph_info->tenant_id, graph_info->graph_id, &fence);
  if (rc != WYRELOG_E_OK)
    goto publication_abort;

  WylPolicyAuthorityMutationResult result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  rc = wyl_policy_store_unseal_fact_graph_with_result (policy,
          graph_info->tenant_id, graph_info->graph_id, &result);
  if (out_outcome != NULL)
    out_outcome->policy_result = result;
  if (rc != WYRELOG_E_OK)
    goto fence_abort;
  if (result != WYL_POLICY_AUTHORITY_MUTATION_APPLIED) {
    rc = result == WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION
        ? WYRELOG_E_POLICY : WYRELOG_E_BUSY;
    goto fence_abort;
  }
  if (out_outcome != NULL)
    out_outcome->durable_unseal_applied = TRUE;

  /* The input metadata was read while sealed.  Re-read it after the CAS so
   * replay sees the current unsealed authority and storage/schema contract. */
  wyl_policy_fact_graph_info_t current = { 0 };
  rc = read_unsealed_graph_info (policy, graph_info->tenant_id,
          graph_info->graph_id, &current);
  if (rc != WYRELOG_E_OK)
    goto compensate;
  WylPolicyGraphAuthorityRecord *authority = NULL;
  rc = wyl_policy_store_graph_publication_fence_validate (&fence,
          graph_info->tenant_id, graph_info->graph_id, &authority);
  gboolean authority_active = rc == WYRELOG_E_OK && authority != NULL
      && authority->lifecycle_state == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
      && authority->has_store_identity;
  wyl_policy_graph_authority_record_free (authority);
  if (rc != WYRELOG_E_OK || !authority_active) {
    rc = rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    clear_unseal_graph_info (&current);
    goto compensate;
  }

  /* Keep the barrier closed while independently validating the physical
   * store identity/metadata schema and the policy replay schema.  The engine
   * builder repeats these checks, but making the sequencer's gate explicit
   * prevents a future publication path from treating a mere authority
   * readback as sufficient validation. */
  rc = wyl_fact_replay_validate_graph (policy, fact_root, &current);
  if (rc != WYRELOG_E_OK) {
    clear_unseal_graph_info (&current);
    goto compensate;
  }
  if (root_lease != NULL) {
    rc = wyl_fact_root_writer_lease_verify (root_lease);
    if (rc != WYRELOG_E_OK) {
      clear_unseal_graph_info (&current);
      goto compensate;
    }
  }
  if (artifact_lease != NULL) {
    rc = wyl_fact_artifact_mutation_lease_revalidate (artifact_lease);
    if (rc != WYRELOG_E_OK) {
      clear_unseal_graph_info (&current);
      goto compensate;
    }
  }

  rc = seal_step_fault (WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_BEFORE_PUBLICATION);
  if (rc != WYRELOG_E_OK) {
    clear_unseal_graph_info (&current);
    goto compensate;
  }

  /* The durable state is ACTIVE while the runtime barrier remains CLOSED.
   * Every admission/acquire path rejects CLOSED, so this is the only safe
   * transient while the engine is being built. */
  WylFactGraphRuntimeStatus status = { 0 };
  rc = wyl_fact_replay_refresh_graph_publication (policy, fact_root,
          &current, &publication, &status);
  clear_unseal_graph_info (&current);
  if (out_outcome != NULL) {
    out_outcome->status = status;
    memset (&status, 0, sizeof status);
    out_outcome->engine_published = rc == WYRELOG_E_OK;
  }
  wyl_fact_graph_runtime_status_clear (&status);
  if (rc != WYRELOG_E_OK)
    goto compensate;
  rc = wyl_policy_store_graph_publication_fence_commit (&fence);
  if (root_lease != NULL) {
    rc = wyl_fact_root_writer_lease_verify (root_lease);
    if (rc != WYRELOG_E_OK)
      goto compensate;
  }
  if (artifact_lease != NULL) {
    rc = wyl_fact_artifact_mutation_lease_revalidate (artifact_lease);
    if (rc != WYRELOG_E_OK)
      goto compensate;
  }
  if (rc != WYRELOG_E_OK) {
    /* A failed COMMIT may leave the transaction outcome uncertain.  Make the
     * runtime safe before releasing the fence: a closed, evicted entry is
     * recoverable whether the durable transaction rolled back or committed. */
    wyl_fact_graph_runtime_publication_release_writer (&publication);
    gboolean evicted = FALSE;
    (void) wyl_fact_graph_runtime_manager_evict_closed (manager, &key,
        &evicted);
    wyl_fact_graph_runtime_publication_fail_closed (&publication);
    wyl_fact_graph_runtime_publication_abort (&publication);
    wyl_policy_store_graph_publication_fence_clear (&fence);
    if (out_outcome != NULL)
      out_outcome->runtime_admission_open = FALSE;
    goto finish;
  }
  /* Keep the graph mutex until this post-commit read.  It closes the small
   * interval in which the transaction is durable but an independent policy
   * mutation could otherwise invalidate the runtime publication. */
  authority = NULL;
  rc = wyl_policy_store_graph_publication_fence_validate (&fence,
          graph_info->tenant_id, graph_info->graph_id, &authority);
  authority_active = rc == WYRELOG_E_OK && authority != NULL
      && authority->lifecycle_state == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
      && authority->has_store_identity;
  wyl_policy_graph_authority_record_free (authority);
  if (rc != WYRELOG_E_OK || !authority_active) {
    gboolean evicted = FALSE;
    wyl_fact_graph_runtime_publication_release_writer (&publication);
    (void) wyl_fact_graph_runtime_manager_evict_closed (manager, &key,
        &evicted);
    wyl_fact_graph_runtime_publication_fail_closed (&publication);
    wyl_fact_graph_runtime_publication_abort (&publication);
    wyl_policy_store_graph_publication_fence_clear (&fence);
    goto finish;
  }
  rc = wyl_fact_graph_runtime_publication_open (&publication);
  if (rc != WYRELOG_E_OK) {
    gboolean evicted = FALSE;
    (void) wyl_fact_graph_runtime_manager_close_admission (manager, &key);
    (void) wyl_fact_graph_runtime_manager_evict_closed (manager, &key,
        &evicted);
    wyl_policy_store_graph_publication_fence_clear (&fence);
    goto finish;
  }
  if (out_outcome != NULL) {
    out_outcome->runtime_admission_open = TRUE;
    out_outcome->engine_published = TRUE;
  }
  wyl_policy_store_graph_publication_fence_clear (&fence);
  goto finish;

compensate:
  /* The durable transition is already committed but no usable engine is
   * available.  Evict any stale publication, then re-seal while admission is
   * still closed.  A compensation failure is retained in the outcome and is
   * returned so callers cannot mistake an unreconciled transition for an
   * ordinary replay failure. */
  /* The build token is no longer needed for compensation.  Release its
   * entry writer before eviction, which acquires the same writer lock, while
   * retaining publication_active so external opens still fail closed. */
  wyl_fact_graph_runtime_publication_release_writer (&publication);
  wyrelog_error_t compensation_rc = compensate_unseal (policy,
          graph_info->tenant_id, graph_info->graph_id, manager, &key,
          out_outcome);
  if (compensation_rc != WYRELOG_E_OK)
    rc = compensation_rc;
  /* The transaction contains either the compensating reseal or the durable
   * unseal whose compensation failed.  Commit both cases deliberately so the
   * caller can observe the established outcome and a later recovery can act
   * on it; blindly clearing the fence would roll the original CAS back. */
  wyrelog_error_t commit_rc =
      wyl_policy_store_graph_publication_fence_commit (&fence);
  if (commit_rc != WYRELOG_E_OK && rc == WYRELOG_E_OK)
    rc = commit_rc;
  wyl_policy_store_graph_publication_fence_clear (&fence);
  wyl_fact_graph_runtime_publication_abort (&publication);
  goto finish;

fence_abort:
  wyl_policy_store_graph_publication_fence_clear (&fence);
publication_abort:
  wyl_fact_graph_runtime_publication_abort (&publication);
finish:
  if (out_outcome != NULL) {
    (void) wyl_fact_graph_runtime_manager_get_status (manager, &key,
        &out_outcome->status);
  }
  wyl_fact_graph_key_clear (&key);
  wyl_fact_artifact_mutation_lease_free (artifact_lease);
  wyl_fact_artifact_namespace_free (artifact_namespace);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_unseal (wyl_policy_store_t *policy, WylHandle *handle,
    WylServiceAuthWriteLease *write_lease, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *manager, gint64 drain_timeout_us,
    WylFactGraphUnsealOutcome *out_outcome)
{
  wyl_policy_store_t *lease_policy = NULL;
  wyrelog_error_t rc = wyl_service_auth_write_lease_get_policy_store
        (write_lease, handle, &lease_policy);
  if (rc != WYRELOG_E_OK || lease_policy != policy)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  rc = wyl_service_auth_write_lease_validate_operation (write_lease, handle);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_fact_graph_unseal_core (policy, fact_root, NULL, graph_info, manager,
             drain_timeout_us, out_outcome);
}

#if defined(WYL_TEST_HANDLE_SEAMS)
wyrelog_error_t
wyl_fact_graph_unseal_for_test (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *manager, gint64 drain_timeout_us,
    WylFactGraphUnsealOutcome *out_outcome)
{
  return wyl_fact_graph_unseal_core (policy, fact_root, NULL, graph_info, manager,
             drain_timeout_us, out_outcome);
}
#endif

wyrelog_error_t
wyl_fact_graph_unseal_with_root_lease
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactRootWriterLease *root_lease,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *manager, gint64 drain_timeout_us,
    WylFactGraphUnsealOutcome *out_outcome)
{
  if (root_lease == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_graph_unseal_core (policy, fact_root, root_lease,
             graph_info, manager, drain_timeout_us, out_outcome);
}

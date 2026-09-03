/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "graph-seal-private.h"

#include <string.h>

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
    rc = wyl_policy_store_seal_fact_graph (policy, graph_info->tenant_id,
            graph_info->graph_id);
    if (rc != WYRELOG_E_OK) {
      /* Argued, not proved, and that now covers the predicate as well as the
       * branch.  Asking whether the graph's own bit is set -- rather than
       * whether it is "active" -- is what keeps a sealed TENANT from making a
       * failed write look committed, which is the same conflation the read at
       * the top of this function exists to avoid.  Dropping the sealed test
       * here leaves the suite green, because reaching this needs a policy
       * write that fails and there is no seam for one.
       *
       * A write that failed after committing is
       * indistinguishable from one that never committed, and the two need
       * opposite compensations, so the store is asked which it was.  There is
       * no fault seam on the policy write, so no test reaches this branch and
       * removing the probe guard -- reopening even when the durable state is
       * unknown -- leaves the suite green.  It stays because the unknown case
       * must fail closed: reopening a possibly-sealed graph is the one
       * direction that produces "durably sealed and admitting". */
      gboolean recheck_found = FALSE, recheck_sealed = FALSE;
      wyrelog_error_t probe_rc = read_seal_state (policy,
              graph_info->tenant_id, graph_info->graph_id, &recheck_found,
              &recheck_sealed);
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
           * without a second rule to keep in step. */
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

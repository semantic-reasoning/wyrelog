/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "graph-seal-private.h"

#include <string.h>

#include "replay-private.h"

void
wyl_fact_graph_seal_outcome_clear (WylFactGraphSealOutcome *outcome)
{
  if (outcome == NULL)
    return;
  wyl_fact_graph_runtime_status_clear (&outcome->status);
  memset (outcome, 0, sizeof *outcome);
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

/* Report the graph as it actually is, on every return that got far enough to
 * have touched it.  Deriving the two booleans from a status that could not be
 * read would report ADMISSION_OPEN, which is 0 -- exactly backwards for a
 * shut-down manager -- so a failed read leaves them FALSE. */
static void
fill_unseal_outcome (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, WylFactGraphUnsealOutcome *outcome)
{
  if (outcome == NULL)
    return;
  wyl_fact_graph_runtime_status_clear (&outcome->status);
  if (wyl_fact_graph_runtime_manager_get_status (manager, key,
      &outcome->status) != WYRELOG_E_OK)
    return;
  outcome->engine_published = outcome->status.queryable;
  outcome->admission_open =
      outcome->status.admission == WYL_FACT_GRAPH_ADMISSION_OPEN;
}

wyrelog_error_t
wyl_fact_graph_unseal (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *manager, WylFactGraphUnsealOutcome *out)
{
  if (out != NULL)
    memset (out, 0, sizeof *out);
  if (policy == NULL || graph_info == NULL || manager == NULL)
    return WYRELOG_E_INVALID;
  if (graph_info->tenant_id == NULL || graph_info->graph_id == NULL)
    return WYRELOG_E_INVALID;
  /* fact_root is checked HERE and not left to the builder, which is the one
   * argument where that distinction matters.  refresh_one_graph tolerates a
   * NULL or empty root -- it just skips the bind -- so the refusal comes from
   * open_graph_engine at U5, which is past U3.
   *
   * Measured rather than reasoned: deleting this guard and driving a sealed
   * graph with a NULL root returns WYRELOG_E_INVALID with unseal_committed
   * TRUE, the durable seal bit CLEARED and the graph left barred.  The caller
   * is told its arguments were bad about a graph this call just unsealed.
   * The argument test cannot show that on its own -- its graph is unsealed
   * and takes the fast path -- so the guard is pinned there and the harm is
   * recorded here.  The seal takes no root and needs no such check. */
  if (fact_root == NULL || fact_root[0] == '\0')
    return WYRELOG_E_INVALID;

  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* U1.  The graph's own bit, for the reason the seal's S1 gives. */
  gboolean found = FALSE, sealed = FALSE;
  rc = read_seal_state (policy, graph_info->tenant_id, graph_info->graph_id,
          &found, &sealed);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_graph_key_clear (&key);
    return rc;
  }
  if (!found) {
    wyl_fact_graph_key_clear (&key);
    return WYRELOG_E_NOT_FOUND;
  }
  if (out != NULL)
    out->already_unsealed = !sealed;

  if (sealed) {
    /* U2.  Rebuild behind a barrier.  NOT_FOUND is success: no entry means
     * nothing can be admitted through one, and U5 mints it CLOSED. */
    rc = wyl_fact_graph_runtime_manager_close_admission (manager, &key);
    if (rc != WYRELOG_E_OK && rc != WYRELOG_E_NOT_FOUND) {
      fill_unseal_outcome (manager, &key, out);
      wyl_fact_graph_key_clear (&key);
      return rc;
    }
  } else {
    /* Durably unsealed already.  Two very different states hide behind that,
     * and only one of them is finished: a graph that is also admitting needs
     * nothing, while one left barred by a call that died between U3 and U6
     * needs exactly the republish below.  So the fast path tests the runtime
     * rather than assuming, and every other case falls through -- including
     * a key the runtime has never held, which U5 mints CLOSED and U6 opens.
     *
     * Skipping the republish here is not an optimisation.  Closing a healthy
     * admitting graph in order to rebuild it would take it offline for the
     * duration and, if the rebuild then failed, leave it barred -- turning
     * an idempotent request into an outage. */
    WylFactGraphRuntimeStatus current = { 0 };
    wyrelog_error_t status_rc = wyl_fact_graph_runtime_manager_get_status
          (manager, &key, &current);
    gboolean admitting = status_rc == WYRELOG_E_OK
        && current.admission == WYL_FACT_GRAPH_ADMISSION_OPEN;
    wyl_fact_graph_runtime_status_clear (&current);
    if (admitting) {
      fill_unseal_outcome (manager, &key, out);
      wyl_fact_graph_key_clear (&key);
      return WYRELOG_E_OK;
    }
  }

  /* U3.  The durable clear.  No compensating re-seal exists: re-sealing would
   * have to drain, and a caller that reached here asked for the graph back. */
  if (sealed) {
    rc = seal_step_fault (WYL_FACT_GRAPH_UNSEAL_PHASE_DURABLE_WRITE);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_unseal_fact_graph (policy, graph_info->tenant_id,
              graph_info->graph_id);
    if (rc != WYRELOG_E_OK) {
      fill_unseal_outcome (manager, &key, out);
      wyl_fact_graph_key_clear (&key);
      return rc;
    }
  }

  /* U4.  Mandatory.  wyl_policy_store_unseal_fact_graph reports OK for a
   * compare-and-swap that matched nothing, so this read is the only thing
   * that establishes the bit is actually clear.
   *
   * What it protects is U6, not U5.  open_graph_engine does refuse a sealed
   * info, but that guard cannot fire here -- the info built below carries
   * sealed FALSE unconditionally -- so it is this read, and nothing else,
   * that keeps a reopen from landing on a graph the store still calls
   * sealed. */
  gboolean back_found = FALSE, back_sealed = FALSE;
  rc = seal_step_fault (WYL_FACT_GRAPH_UNSEAL_PHASE_READBACK_PROBE);
  if (rc == WYRELOG_E_OK)
    rc = read_seal_state (policy, graph_info->tenant_id, graph_info->graph_id,
            &back_found, &back_sealed);
  if (rc != WYRELOG_E_OK || !back_found || back_sealed) {
    /* The !back_found arm is argued, not proved: reaching it needs the row to
     * disappear between U3 and U4, and the policy store exposes no delete for
     * a fact graph at all -- grep for one -- so no test can drive it.  It is
     * kept because U1's own NOT_FOUND has the same shape and a caller should
     * not have to distinguish which read found nothing. */
    if (rc == WYRELOG_E_OK)
      rc = back_found ? WYRELOG_E_BUSY : WYRELOG_E_NOT_FOUND;
    if (out != NULL)
      out->readback_still_sealed = back_found && back_sealed;
    fill_unseal_outcome (manager, &key, out);
    wyl_fact_graph_key_clear (&key);
    return rc;
  }
  /* Past the readback, deliberately: the field means "confirmed unsealed",
   * so a probe that could not run leaves it FALSE even though the write
   * landed.  Setting it at U3 would make it mean "the write returned OK",
   * which the store also reports for a compare-and-swap that matched
   * nothing. */
  if (out != NULL)
    out->unseal_committed = sealed;

  /* U5.  Publish into the still-closed entry.
   *
   * The info handed to the builder is constructed here rather than forwarded
   * from the caller, and the field that forces it is |sealed|: a caller holds
   * the row it read BEFORE the durable clear, and open_graph_engine refuses a
   * sealed info outright.  The builder consults exactly three fields -- the
   * two names and that one; storage_uri, storage_path, schema_version and
   * owner_scope are never read on this path, so copying them back from the
   * store would imply a dependency that does not exist. */
  wyl_policy_fact_graph_info_t fresh = {
    .tenant_id = graph_info->tenant_id,
    .graph_id = graph_info->graph_id,
    .sealed = FALSE,
  };
  WylFactGraphRuntimeStatus published = { 0 };
  rc = wyl_fact_replay_refresh_graph_closed (policy, fact_root, &fresh,
          manager, &published);
  wyl_fact_graph_runtime_status_clear (&published);
  if (rc != WYRELOG_E_OK) {
    /* Durably unsealed and still barred.  A retry of this call converges it,
     * and so does the next boot pass, which writes the axis from the durable
     * bit in both directions. */
    fill_unseal_outcome (manager, &key, out);
    wyl_fact_graph_key_clear (&key);
    return rc;
  }

  /* U6.  The observable edge.  Everything a reader can see about this unseal
   * happens here, which is why the engine is already attached. */
  rc = seal_step_fault (WYL_FACT_GRAPH_UNSEAL_PHASE_OPEN_ADMISSION);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_open_admission (manager, &key);
  if (rc != WYRELOG_E_OK) {
    /* The engine is attached behind a barrier nothing will lift, and the next
     * open_admission would serve it whether or not this unseal ever finished
     * -- so detach it.
     *
     * Argued, not proved, and measured rather than assumed: deleting this
     * eviction leaves the whole suite green.  The refusals reachable HERE are
     * a shut-down manager and an abandoned entry -- open_admission also
     * answers NOT_FOUND for a key the runtime never held, but U5 has just
     * minted and published one -- and a shut-down manager fails this eviction
     * too, so no single-threaded test can separate the two.  The
     * outcome is read off the graph afterwards rather than off this call, so
     * the report is right either way. */
    gboolean evicted = FALSE;
    (void) wyl_fact_graph_runtime_manager_evict_closed (manager, &key,
        &evicted);
  }
  fill_unseal_outcome (manager, &key, out);
  wyl_fact_graph_key_clear (&key);
  return rc;
}

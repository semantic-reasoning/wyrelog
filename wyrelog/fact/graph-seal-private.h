/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

typedef struct
{
  /* TRUE once the durable transition has committed.  This is the field a
   * caller must read before deciding to retry: a seal that got this far
   * cannot be retried from the top, because the graph is already sealed and
   * the compensating reopen is no longer safe. */
  gboolean sealed_committed;
  /* TRUE if the graph is closed on return.  FALSE means it is admitting:
   * either the runtime held no entry for the key -- nothing could be admitted
   * through it, so the durable bit alone carries the barrier until the next
   * boot -- or an abort rolled the close back. */
  gboolean runtime_barrier_established;
  gboolean engine_evicted;
  WylFactGraphRuntimeStatus status;
} WylFactGraphSealOutcome;

/*
 * Seal ordering
 * -------------
 * Deny new work, wait for admitted work, commit the durable bit, then take
 * the engine away.  The caller owns the policy write lease and the replay
 * coordinator lock; this takes neither, so it can be composed under whichever
 * the caller already holds.
 *
 * The compensation rule is one sentence: reopen admission on an abort if and
 * only if the graph is not durably sealed.  That subsumes "never after the
 * commit" and also covers a graph sealed by an earlier call, or by the
 * pre-existing seal route that writes the durable bit with no runtime
 * involvement at all -- an abort against one of those must leave it closed.
 * Reopening a graph that may be durably sealed is the one unsafe direction --
 * it produces "durably sealed and admitting", which is the state this whole
 * unit exists to make unrepresentable.  When the durable write fails
 * ambiguously and the state cannot be re-read, the graph is deliberately left
 * closed with its durable state unknown; the next boot converges it, because
 * the boot pass sets admission from whatever the durable bit turns out to be.
 *
 * What a successful seal guarantees: no new operation is admitted, every
 * operation admitted before the close has retired, the durable bit is set,
 * and no engine is published.  It does NOT revoke a snapshot pinned before
 * the close -- see the admission contract for why that is a separate
 * decision, and note that the pinned generation stays readable until its
 * holder releases it.
 *
 * drain_timeout_us is passed through to drain().  It must be finite when the
 * caller holds a process-wide lease: an indefinite drain there blocks every
 * other writer until the graph goes quiet.  A drain that times out aborts the
 * seal and reopens, so the caller may retry.
 *
 * WYRELOG_E_BUSY when the drain did not finish or the manager is shutting
 * down; WYRELOG_E_NOT_FOUND for a graph the policy store does not hold;
 * WYRELOG_E_POLICY for a lifecycle that cannot be sealed -- provisioning or
 * degraded -- which propagates from the durable write and reopens.
 *
 * out_outcome is zeroed on entry and filled on the returns where the runtime
 * state changed: a drain abort, an ambiguous durable write, and success.  The
 * early argument and lookup failures leave it zeroed, which is accurate --
 * nothing was touched.  The field that matters on a failure is
 * runtime_barrier_established: FALSE with a zeroed status means the graph was
 * never closed.  The ambiguous-write return reports the barrier only when it
 * could not re-read the durable state: the close stands there until a restart
 * or a re-replay.  When the re-read succeeds and says the write never landed,
 * the close is rolled back and the field reports FALSE with the graph
 * admitting again. */
wyrelog_error_t wyl_fact_graph_seal (wyl_policy_store_t * policy,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeManager * manager, gint64 drain_timeout_us,
    WylFactGraphSealOutcome * out_outcome);

void wyl_fact_graph_seal_outcome_clear (WylFactGraphSealOutcome * outcome);

G_END_DECLS;

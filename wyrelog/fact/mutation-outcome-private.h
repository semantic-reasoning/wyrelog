/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

#include "runtime-private.h"

G_BEGIN_DECLS;

/*
 * Typed outcome of a fact mutation (append or retract) for issue #546.
 *
 * The mutation path linearizes at the exact graph's DuckDB commit and then
 * refreshes only that graph's runtime engine.  Two layers report distinct
 * facts, so they carry distinct types:
 *
 *   - the STORE layer reports what durably committed: whether a batch was
 *     inserted (versus an idempotent no-op) and the committed resource
 *     deltas that later quota accounting consumes;
 *
 *   - the ORCHESTRATION layer (handle/HTTP) reports the end-to-end class,
 *     folding the store delta together with the post-commit targeted-refresh
 *     result so a client can distinguish a pre-commit failure, a fully-ready
 *     commit, and a durable-but-degraded commit whose engine is stale.
 */

/*
 * Committed resource deltas produced by a single append/retract commit.
 *
 * The deltas are LOGICAL, not physical DuckDB storage: they measure the row
 * count and a stable per-value logical byte size so quota accounting does not
 * depend on the backend's physical layout.  Both deltas are signed so a
 * future retract-as-credit policy (issue #547) can be expressed without an
 * ABI reshape; append/retract currently report non-negative values.
 *
 * On an idempotent no-op (a byte-identical batch replayed under the same
 * idempotency key) inserted is FALSE and both deltas are zero.
 */
typedef struct
{
  gboolean inserted;
  gint64 committed_row_delta;
  gint64 logical_byte_delta;
} wyl_fact_commit_delta_t;

/*
 * End-to-end outcome class of a mutation request.
 *
 *   PRECOMMIT_FAILED    Nothing durable changed; the commit did not happen.
 *   COMMITTED_READY     The batch (or idempotent no-op) is durable AND the
 *                       graph's engine was refreshed to reflect it.
 *   COMMITTED_DEGRADED  The batch is durable, but the post-commit targeted
 *                       refresh failed; the engine is stale (a prior complete
 *                       generation may still be queryable) and reconciliation
 *                       is needed.  It is never reported as ready.
 */
typedef enum
{
  WYL_FACT_MUTATION_PRECOMMIT_FAILED = 0,
  WYL_FACT_MUTATION_COMMITTED_READY,
  WYL_FACT_MUTATION_COMMITTED_DEGRADED,
  /* The commit is durable and the post-commit refresh was refused by the
   * graph's admission barrier rather than failing.  Distinct from DEGRADED
   * because nothing is broken: no replay failed, the durable state is intact,
   * and the engine catches up when the graph is unsealed.  Appended so the
   * existing values keep their numbers. */
  WYL_FACT_MUTATION_COMMITTED_BARRIER,
} wyl_fact_mutation_class_t;

/*
 * Full mutation outcome assembled at the orchestration layer.
 *
 * Invariants:
 *   - mutation_class == PRECOMMIT_FAILED implies delta is zero-valued and
 *     every engine field below is unset (engine_queryable FALSE,
 *     engine_generation 0, no reconciliation need);
 *   - the degraded_class, engine_queryable, and engine_generation fields are a
 *     projection of the graph's WylFactGraphRuntimeStatus and are meaningful
 *     only when mutation_class == COMMITTED_DEGRADED (degraded_class) or when
 *     a refresh published a generation (engine_generation);
 *   - mutation_class == COMMITTED_BARRIER implies degraded_class is NONE and
 *     needs_durable_reconcile is FALSE: the refusal is a lifecycle decision,
 *     not a fault, and the durable state it was refused against is intact.
 *     needs_runtime_reconcile stays TRUE, because the engine really does lack
 *     the batch until the graph is unsealed;
 *   - needs_durable_reconcile is an in-memory hint only.  A durable
 *     reconciliation queue is deliberately out of scope for #546 (startup
 *     replay plus durable idempotency already close the crash window); it is
 *     tracked as a follow-up.
 */
typedef struct
{
  wyl_fact_mutation_class_t mutation_class;
  wyl_fact_commit_delta_t delta;
  WylFactGraphReplayClass degraded_class;
  gboolean engine_queryable;
  gboolean needs_runtime_reconcile;
  gboolean needs_durable_reconcile;
  guint64 engine_generation;
} wyl_fact_mutation_outcome_t;

/*
 * Zero-initialize a delta to the idempotent-no-op state.
 */
static inline void
wyl_fact_commit_delta_init (wyl_fact_commit_delta_t *delta)
{
  if (delta != NULL) {
    delta->inserted = FALSE;
    delta->committed_row_delta = 0;
    delta->logical_byte_delta = 0;
  }
}

/*
 * Zero-initialize an outcome to the PRECOMMIT_FAILED state, which satisfies
 * the mutation_class == PRECOMMIT_FAILED invariant above.
 */
static inline void
wyl_fact_mutation_outcome_init (wyl_fact_mutation_outcome_t *outcome)
{
  if (outcome != NULL) {
    outcome->mutation_class = WYL_FACT_MUTATION_PRECOMMIT_FAILED;
    wyl_fact_commit_delta_init (&outcome->delta);
    outcome->degraded_class = WYL_FACT_GRAPH_REPLAY_NONE;
    outcome->engine_queryable = FALSE;
    outcome->needs_runtime_reconcile = FALSE;
    outcome->needs_durable_reconcile = FALSE;
    outcome->engine_generation = 0;
  }
}

/*
 * Stable lexical name of a mutation class, for diagnostics and audit.
 * Returns a non-NULL literal for every defined class and "unknown" otherwise.
 */
static inline const gchar *
wyl_fact_mutation_class_name (wyl_fact_mutation_class_t mutation_class)
{
  switch (mutation_class) {
    case WYL_FACT_MUTATION_PRECOMMIT_FAILED:
      return "precommit_failed";
    case WYL_FACT_MUTATION_COMMITTED_READY:
      return "committed_ready";
    case WYL_FACT_MUTATION_COMMITTED_DEGRADED:
      return "committed_degraded";
    case WYL_FACT_MUTATION_COMMITTED_BARRIER:
      return "committed_barrier";
  }
  return "unknown";
}

G_END_DECLS;

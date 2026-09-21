/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/engine.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/policy/store-private.h"
#include "fact/graph-artifact-namespace-private.h"
#include "fact/replay-scheduler-private.h"

G_BEGIN_DECLS;

typedef struct
{
  guint graphs_seen;
  guint graphs_loaded;
  guint graphs_degraded;
  /* Graphs the policy store reports sealed.  Counted apart from
   * graphs_degraded because sealing is a decision, not a fault: the engine
   * build refuses a sealed graph with WYRELOG_E_POLICY, which classify_replay_
   * error maps to SCHEMA_MISMATCH, so before this counter existed every sealed
   * graph told an operator it had a schema problem. */
  guint graphs_sealed;
  /* Graphs whose forget ledger was read and whose pending intents could not
   * be converged at startup.  Counted, never returned: a graph that cannot
   * reconcile must not stop the daemon from opening. */
  guint graphs_forget_reconcile_failed;
  /* Graphs whose store would not open, so the forget ledger was never read.
   * Distinct from the above because nothing was learned about any erasure:
   * merging them would make this counter a near-duplicate of graphs_degraded
   * while diluting the one signal no other counter carries. */
  guint graphs_forget_probe_unavailable;
  /* Graphs whose store refused the forget probe and then served the engine
   * build moments later.  Two opens with byte-identical arguments disagreed,
   * so the pending-erasure state of the graph was never established -- which
   * is neither of the two above: nothing was learned, but not because the
   * store was unopenable.  A lost lease is NOT the only cause and this is not
   * unreachable off-bridge: any transient resource failure that clears between
   * the two opens produces the identical signal, and EMFILE at probe time is
   * neither bridge-specific nor rare.  Under the bridge the reader guard also
   * takes LOCK_SH|LOCK_NB and can lose to contention.  Read the rc on the BOOT
   * line before concluding which occurred -- only the lease case is evidence
   * for the population #550 asks about. */
  guint graphs_forget_probe_disagreed;
} wyl_fact_replay_summary_t;

typedef enum
{
  WYL_FACT_GRAPH_STATE_READY = 0,
  WYL_FACT_GRAPH_STATE_DEGRADED,
  WYL_FACT_GRAPH_STATE_SCHEMA_MISMATCH,
  WYL_FACT_GRAPH_STATE_REPLAY_FAILED,
  WYL_FACT_GRAPH_STATE_STORE_UNAVAILABLE,
  /* The engine is complete and the graph serves queries, but a forget
   * recorded against it did not converge at startup.  Appended, so the
   * existing values keep their numbers across the test binaries that compile
   * daemon/fact-status.c separately. */
  WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE,
  /* Admission is closed: the graph refuses every new query and mutation
   * while its engine may still be published.  A lifecycle state, not a
   * failure -- it says nothing about replay health, which an unseal
   * restores from fields the seal never wrote.  Appended for the reason
   * above. */
  WYL_FACT_GRAPH_STATE_SEALED,
  /* The graph is provisioned but has no published engine because its lazy
   * store has not received a first append.  This is a normal lifecycle state,
   * not a storage failure. */
  WYL_FACT_GRAPH_STATE_EMPTY,
} wyl_fact_graph_state_t;

typedef struct
{
  gchar *tenant_id;
  gchar *graph_id;
  wyl_fact_graph_state_t state;
  gchar *last_error_class;
  gboolean queryable;
  guint64 operation_generation;
  guint64 engine_generation;
  gint64 last_replay_at_us;
} wyl_fact_graph_status_t;

const gchar *wyl_fact_graph_state_name (wyl_fact_graph_state_t state);
void wyl_fact_graph_status_free (gpointer data);

gchar *wyl_fact_replay_wirelog_relation_name (const gchar * namespace_id,
    const gchar * relation_name);

wyrelog_error_t wyl_fact_replay_open_graph_engine (wyl_policy_store_t * policy,
    const gchar * fact_root, const wyl_policy_fact_graph_info_t * graph_info,
    WylEngine ** out_engine);

/* Validate the durable graph identity and replay schema without publishing an
 * engine.  Unseal uses this while admission is closed so a malformed or
 * relocated store cannot reach the runtime publication step. */
wyrelog_error_t wyl_fact_replay_validate_graph
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info);
wyrelog_error_t wyl_fact_replay_validate_graph_bounded
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactReplayJobContext * job_context);
wyrelog_error_t wyl_fact_replay_validate_graph_with_artifact_lease
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactArtifactNamespace * artifact_namespace,
    WylFactArtifactMutationLease * artifact_lease);
wyrelog_error_t wyl_fact_replay_validate_graph_with_artifact_lease_bounded
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactArtifactNamespace * artifact_namespace,
    WylFactArtifactMutationLease * artifact_lease,
    WylFactReplayJobContext * job_context);
#if defined(WYL_TEST_HANDLE_SEAMS)
typedef enum
{
  WYL_FACT_REPLAY_TEST_FAULT_NONE = 0,
  WYL_FACT_REPLAY_TEST_FAULT_OPEN_GRAPH_ENGINE,
} WylFactReplayTestFault;

void wyl_fact_replay_set_test_fault (WylFactReplayTestFault fault);
typedef void (*WylFactReplayScheduledStartTestHook)
  (const gchar *tenant_id, const gchar *graph_id, gpointer user_data);
void wyl_fact_replay_set_scheduled_start_test_hook
  (WylFactReplayScheduledStartTestHook hook, gpointer user_data);
typedef void (*WylFactReplayValidationConnectedTestHook)
  (WylFactReplayJobContext *job_context, gpointer user_data);
void wyl_fact_replay_set_validation_connected_test_hook
  (WylFactReplayValidationConnectedTestHook hook, gpointer user_data);

wyrelog_error_t wyl_fact_replay_open_graph_engine_with_store_for_test
  (wyl_policy_store_t * policy, wyl_fact_store_t * store,
    const wyl_policy_fact_graph_info_t * graph_info, WylEngine ** out_engine);
#endif

wyrelog_error_t wyl_fact_replay_policy_graphs (wyl_policy_store_t * policy,
    const gchar * fact_root, WylFactGraphRuntimeManager * runtime_manager,
    wyl_fact_replay_summary_t * out_summary);
wyrelog_error_t wyl_fact_replay_policy_graphs_scheduled
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactReplayScheduler *scheduler,
    const WylFactReplaySchedulerConfig *config,
    wyl_fact_replay_summary_t *out_summary);
typedef struct
{
  wyrelog_error_t (*pin) (gpointer user_data,
      wyl_policy_store_t **out_policy);
  void (*unpin) (gpointer user_data, wyl_policy_store_t *policy);
  void (*snapshot_complete) (gpointer user_data);
  gpointer user_data;
} WylFactReplayPolicyProvider;
wyrelog_error_t wyl_fact_replay_policy_graphs_scheduled_with_provider
  (wyl_policy_store_t *snapshot_policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactReplayScheduler *scheduler,
    const WylFactReplaySchedulerConfig *config,
    const WylFactReplayPolicyProvider *provider,
    wyl_fact_replay_summary_t *out_summary);

/* Refresh exactly one graph's runtime engine (issue #546).  Unlike
 * wyl_fact_replay_policy_graphs this touches only the given key and never
 * retires sibling entries, so an append/retract converges its own graph
 * without disturbing any other graph's generation.  |out_status| receives the
 * post-refresh runtime status (READY on success; READY_STALE/DEGRADED with a
 * replay class on a post-commit refresh failure). */
wyrelog_error_t wyl_fact_replay_refresh_graph (wyl_policy_store_t * policy,
    const gchar * fact_root, const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeManager * runtime_manager,
    WylFactGraphRuntimeStatus * out_status);
wyrelog_error_t wyl_fact_replay_refresh_graph_bounded
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactReplayJobContext *job_context,
    WylFactGraphRuntimeStatus *out_status);

/* Rebuild and publish one graph while its runtime admission remains CLOSED.
 * This is the publication half of a graph unseal sequencer: callers must
 * validate and durably activate policy first, then reopen admission only after
 * this returns successfully. */
wyrelog_error_t wyl_fact_replay_refresh_graph_closed
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeManager * runtime_manager,
    WylFactGraphRuntimeStatus * out_status);
wyrelog_error_t wyl_fact_replay_refresh_graph_closed_with_artifact_lease
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeManager * runtime_manager,
    WylFactArtifactNamespace * artifact_namespace,
    WylFactArtifactMutationLease * artifact_lease,
    WylFactGraphRuntimeStatus * out_status);

wyrelog_error_t wyl_fact_replay_publish_graph_closed_and_open
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeManager * runtime_manager,
    WylFactGraphRuntimeStatus * out_status);

wyrelog_error_t wyl_fact_replay_refresh_graph_publication
  (wyl_policy_store_t * policy, const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimePublication * publication,
    WylFactArtifactNamespace * artifact_namespace,
    WylFactArtifactMutationLease * artifact_lease,
    WylFactGraphRuntimeStatus * out_status);
wyrelog_error_t wyl_fact_replay_refresh_graph_publication_bounded
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimePublication *publication,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactReplayJobContext *job_context,
    WylFactGraphRuntimeStatus *out_status);

G_END_DECLS;

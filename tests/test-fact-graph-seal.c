/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-seal-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/policy/store-private.h"

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
#include "wyrelog/fact/provisioning-run-private.h"
#include "wyrelog/fact/store-open-private.h"
#endif
#include "wyrelog/wyl-id-private.h"

/* The graph fixture is duplicated from tests/test-fact-replay.c rather than
 * shared.  Extracting it would mean deleting it there, and two open pull
 * requests rewrite that file; a third conflict in it would cost more than
 * these forty lines.  Dedupe once those land. */
static wyl_policy_fact_relation_schema_options_t
make_schema (const gchar *tenant_id, const gchar *graph_id,
    const wyl_policy_fact_relation_schema_column_t *columns, gsize n_columns)
{
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = n_columns,
  };
  return schema;
}

static void
create_graph_with_schema (wyl_policy_store_t *store, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, tenant_id, &created),
      ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"},
    {"amount", "int64"},
    {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (store, &graph_opts,
      NULL), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (store,
      &schema), ==, WYRELOG_E_OK);
}

/* Proves the pinned generation is still live after the seal detached the
 * entry's reference.  What it computes is beside the point; that it runs at
 * all is the assertion. */
static wyrelog_error_t
engine_is_reachable (WylEngine *engine, gpointer user_data)
{
  gboolean *reached = user_data;
  *reached = engine != NULL;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  gchar *storage_path;
} GraphPathProbe;

static wyrelog_error_t
capture_graph_path_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  GraphPathProbe *probe = user_data;
  if (g_strcmp0 (probe->tenant_id, info->tenant_id) == 0
      && g_strcmp0 (probe->graph_id, info->graph_id) == 0)
    probe->storage_path = g_strdup (info->storage_path);
  return WYRELOG_E_OK;
}

/* One row, so the replayed engine has something in it.  Shared by both
 * materialize helpers below: they differ only in how the store handle is
 * obtained, which is the part the graph's lifecycle decides. */
static void
append_seed_batch (wyl_fact_store_t *store, const gchar *tenant_id,
    const gchar *graph_id)
{
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-a"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 11},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
  };
  wyl_fact_row_t rows[] = { {values, 3} };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "batch-1",
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = 1,
    .source = "test",
    .idempotency_key = "key-1",
    .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
}

/* Give the graph a real store so its engine builds and a seal has something
 * to evict.  Three of these four steps are obvious; the fourth is not, and it
 * is the one that blocks: open_graph_store refuses facts.duckdb unless it is
 * mode 0600, so without the chmod the build fails at its first step with
 * WYRELOG_E_POLICY and every later ingredient is irrelevant. */
static void
materialize_graph_engine (wyl_policy_store_t *policy, const gchar *tenant_id,
    const gchar *graph_id)
{
  GraphPathProbe probe = { tenant_id, graph_id, NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (policy, tenant_id,
      capture_graph_path_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_nonnull (probe.storage_path);
  g_autofree gchar *storage_path = probe.storage_path;
  g_autofree gchar *fact_path = g_build_filename (storage_path,
          "facts.duckdb", NULL);

  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==,
        WYRELOG_E_OK);
    append_seed_batch (store, tenant_id, graph_id);
  }

  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (fact_path, &error));
}

static void
remove_tree (const gchar *path)
{
  if (path == NULL)
    return;
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name = NULL;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (path);
}

static WylFactGraphRuntimeStatus
status_of (WylFactGraphRuntimeManager *manager, const gchar *tenant_id,
    const gchar *graph_id)
{
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, tenant_id, graph_id), ==,
      WYRELOG_E_OK);
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &key,
      &status), ==, WYRELOG_E_OK);
  wyl_fact_graph_key_clear (&key);
  return status;
}

/* A seal is durable in the policy store and was not durable in the runtime:
 * before the boot hook, a restart reopened every graph the policy store still
 * called sealed.  The hook writes the axis in both directions, because
 * closing the sealed ones and leaving the rest alone would strand any graph
 * unsealed out of band while the daemon was down. */
static void
test_boot_reestablishes_admission_from_the_durable_seal (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "sealed-graph");
    create_graph_with_schema (policy, root, "tenant-a", "open-graph");
    g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
        "sealed-graph"), ==, WYRELOG_E_OK);
  }

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* Sealing is a decision, not a fault.  Before this the sealed graph landed
   * in graphs_degraded and reported schema_mismatch to an operator.
   *
   * degraded is 1, and it is the OTHER graph: this fixture writes no fact
   * store to disk, so an unsealed graph's engine build legitimately fails.
   * That is what makes the pair discriminating -- without the hook both
   * graphs land in degraded and graphs_sealed stays zero. */
  g_assert_cmpuint (summary.graphs_sealed, ==, 1);
  g_assert_cmpuint (summary.graphs_degraded, ==, 1);

  WylFactGraphRuntimeStatus sealed = status_of (manager, "tenant-a",
          "sealed-graph");
  g_assert_cmpint (sealed.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  /* DEGRADED, not EVICTED: boot closes admission and leaves the state alone.
   * Evicting here would only move it to EVICTED, which the status reader
   * skips -- the graph would vanish from an operator's listing rather than
   * merely being misclassified.  The live seal owns the eviction, together
   * with the surface change that makes a sealed graph reportable. */
  g_assert_cmpint (sealed.state, ==, WYL_FACT_GRAPH_RUNTIME_DEGRADED);
  g_assert_false (sealed.queryable);
  wyl_fact_graph_runtime_status_clear (&sealed);

  /* The other direction, and it is the half that is easy to omit. */
  WylFactGraphRuntimeStatus open = status_of (manager, "tenant-a",
          "open-graph");
  g_assert_cmpint (open.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  wyl_fact_graph_runtime_status_clear (&open);

  /* The open direction is not a no-op, and this is the case that shows it.
   * Close the unsealed graph by hand -- standing in for a previous boot that
   * closed it while it was sealed -- and run the pass again.  The hook has to
   * be a function of the durable bit, so it must reopen; a hook that only
   * closes would leave a graph unsealed out of band permanently barred. */
  WylFactGraphKey open_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&open_key, "tenant-a",
      "open-graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &open_key), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus barred = status_of (manager, "tenant-a",
          "open-graph");
  g_assert_cmpint (barred.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&barred);

  wyl_fact_replay_summary_t again = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &again);
  WylFactGraphRuntimeStatus reopened = status_of (manager, "tenant-a",
          "open-graph");
  g_assert_cmpint (reopened.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  /* The axis is restored; the graph is not.  The reopen runs after the
   * refresh in the same pass, so the refresh that would have rebuilt the
   * engine was still refused -- recovery takes a second pass.  Latent today
   * because there is no unseal route at all, but it is the half the stated
   * motivation actually needs, so it is pinned rather than assumed. */
  g_assert_false (reopened.queryable);
  wyl_fact_graph_runtime_status_clear (&reopened);
  /* And the sealed one is still closed after a second pass. */
  WylFactGraphRuntimeStatus still = status_of (manager, "tenant-a",
          "sealed-graph");
  g_assert_cmpint (still.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&still);
  wyl_fact_graph_key_clear (&open_key);

  /* The barrier really holds: no new snapshot on the sealed graph. */
  WylFactGraphKey sealed_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&sealed_key, "tenant-a",
      "sealed-graph"), ==, WYRELOG_E_OK);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &sealed_key, &snapshot), ==, WYRELOG_E_BUSY);
  g_assert_null (snapshot);
  wyl_fact_graph_key_clear (&sealed_key);
  remove_tree (root);
}

/* Closing admission does not disturb the erasure verdict.  That is all this
 * proves, and it is worth proving because the two writes sit next to each
 * other in the boot loop.
 *
 * It does NOT prove the ordering between them.  set_forget_state refuses an
 * EVICTED entry, so once the live seal starts evicting, an admission write
 * placed ahead of it would leave the axis at its default CONVERGED over an
 * erasure that is still owed.  The boot path does not evict, so swapping the
 * two blocks today changes nothing and no test can tell -- verified by doing
 * it.  Whoever adds the eviction owns making that ordering falsifiable. */
static void
test_boot_admission_write_does_not_clobber_the_forget_verdict (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-forget-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "sealed-graph");
    g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
        "sealed-graph"), ==, WYRELOG_E_OK);
  }

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* Write the verdict the way the loop does for a graph with a pending
   * intent, then read it back through the same surface the loop wrote the
   * admission axis on. */
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "sealed-graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &key, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_OK);

  WylFactGraphRuntimeStatus after = status_of (manager, "tenant-a",
          "sealed-graph");
  g_assert_cmpint (after.forget_state, ==, WYL_FACT_GRAPH_FORGET_INCOMPLETE);
  g_assert_cmpint (after.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&after);

  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

/* A live seal denies new work, waits for admitted work, commits the durable
 * bit, and only then takes the engine away.  Success means all four. */
/* Fail a named phase of the seal, and count every phase reached.
 *
 * The counts are what make the two tests below evidence rather than
 * description.  A seam that never fires leaves the seal succeeding, and the
 * assertions would then be pinning the ordinary path while claiming to pin the
 * ambiguous one.  #945 records exactly that mistake being made once already:
 * the first version of this seam let the write run and replaced its result
 * afterwards, so the compensating re-read found the graph genuinely sealed and
 * control took the recovery arm -- measuring identically to the unhooked code,
 * which reads as "no difference" rather than "the branch was never reached". */
typedef struct
{
  gboolean fail_write;
  gboolean fail_probe;
  gboolean shutdown_at_write;
  WylFactGraphRuntimeManager *manager;
  guint write_seen;
  guint probe_seen;
} SealPhaseFault;

static wyrelog_error_t
seal_phase_fault (const gchar *phase, gpointer user_data)
{
  SealPhaseFault *fault = user_data;
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_SEAL_PHASE_DURABLE_WRITE) == 0) {
    fault->write_seen++;
    /* Shutting the manager down here is what makes the compensating reopen
     * intended but ineffective: open_admission refuses a shut-down manager.
     * It happens at the write phase because that is the last point before
     * the branch under test decides what to report. */
    if (fault->shutdown_at_write)
      wyl_fact_graph_runtime_manager_shutdown (fault->manager);
    return fault->fail_write ? WYRELOG_E_IO : WYRELOG_E_OK;
  }
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_SEAL_PHASE_RESEAL_PROBE) == 0) {
    fault->probe_seen++;
    return fault->fail_probe ? WYRELOG_E_IO : WYRELOG_E_OK;
  }
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  gboolean found;
  gboolean sealed;
} SealedBitProbe;

static wyrelog_error_t
capture_sealed_bit_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  SealedBitProbe *probe = user_data;
  if (g_strcmp0 (probe->tenant_id, info->tenant_id) == 0
      && g_strcmp0 (probe->graph_id, info->graph_id) == 0) {
    probe->found = TRUE;
    probe->sealed = info->sealed;
  }
  return WYRELOG_E_OK;
}

/* A live, replayed, sealable graph: the same fixture the barrier test builds,
 * factored out because the two ambiguous-write cases need it twice more. */
typedef struct
{
  gchar *root;
  wyl_policy_store_t *policy;
  WylFactGraphRuntimeManager *manager;
} SealFixture;

static void
seal_fixture_init (SealFixture *fixture, const gchar *template_name)
{
  g_autoptr (GError) error = NULL;
  fixture->root = wyl_test_make_secure_fact_root (template_name, &error);
  g_assert_nonnull (fixture->root);
  g_autofree gchar *policy_path = g_build_filename (fixture->root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture->policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture->policy), ==,
      WYRELOG_E_OK);
  create_graph_with_schema (fixture->policy, fixture->root, "tenant-a",
      "orders");
  materialize_graph_engine (fixture->policy, "tenant-a", "orders");
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture->manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (fixture->policy, fixture->root,
      fixture->manager, &summary);
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);
}

static void
seal_fixture_clear (SealFixture *fixture)
{
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  g_clear_pointer (&fixture->manager, wyl_fact_graph_runtime_manager_unref);
  g_clear_pointer (&fixture->policy, wyl_policy_store_close);
  /* wyl_test_make_secure_fact_root registers no cleanup of its own, so
   * without this every fixture abandons a tree holding a policy.db and a
   * DuckDB store.  Harmless when this file had two of them and not when it
   * has seventeen; ASan stays silent either way, because a directory is not
   * a leak. */
  remove_tree (fixture->root);
  g_clear_pointer (&fixture->root, g_free);
}

/* S4's ambiguous durable write, sub-case one: the write fails and the
 * compensating re-read succeeds, reporting the graph unsealed.
 *
 * The write never committed, so the close is rolled back and there is no
 * barrier left to report.
 *
 * Kills: `reopened = FALSE` (the close is never rolled back, so admission
 * stays CLOSED) and `runtime_barrier_established = TRUE`.  No pre-existing
 * test in this file kills either -- both survive the whole suite without
 * these two cases. */
static void
test_seal_ambiguous_write_rolls_back_when_the_reread_says_unsealed (void)
{
  SealFixture fixture = { 0 };
  seal_fixture_init (&fixture, "wyl-graph-seal-ambig-a-XXXXXX");

  SealPhaseFault fault = {TRUE, FALSE, 0, 0};
  wyl_fact_graph_seal_set_test_hook (seal_phase_fault, &fault);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info,
      fixture.manager, -1, &outcome), ==, WYRELOG_E_IO);

  /* The seam fired and the probe ran, so this really is the ambiguous-write
   * branch and really is its re-read-succeeded arm. */
  g_assert_cmpuint (fault.write_seen, ==, 1);
  g_assert_cmpuint (fault.probe_seen, ==, 1);

  g_assert_false (outcome.sealed_committed);
  g_assert_false (outcome.runtime_barrier_established);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_OPEN);

  /* The durable bit really is clear: the write was skipped, not run and
   * relabelled.  Without this the seam could be masking a committed seal,
   * which is the failure mode #945 warns about. */
  SealedBitProbe probe = {"tenant-a", "orders", FALSE, TRUE};
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (fixture.policy,
      "tenant-a", capture_sealed_bit_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_true (probe.found);
  g_assert_false (probe.sealed);

  wyl_fact_graph_seal_outcome_clear (&outcome);
  seal_fixture_clear (&fixture);
}

/* Sub-case two: the write fails and the re-read fails too, so the durable
 * state is unknown.
 *
 * The close deliberately stands -- leaving a possibly-sealed graph admitting
 * is the one unsafe direction -- and the barrier is reported TRUE because the
 * graph really is offline.
 *
 * Kills: dropping the `probe_rc == WYRELOG_E_OK` term from the reopen guard,
 * `reopened = TRUE`, and `runtime_barrier_established = FALSE`.
 *
 * Two mutations of these lines survive both cases, and saying so is the point
 * of listing the ones that do not:
 *
 *   - dropping `&& barrier` from the reopen guard.  Both fixtures replay the
 *     graph first, so S2 always establishes a barrier and the term is never
 *     the deciding one.  A fixture without an entry would make it FALSE, but
 *     reopening a graph that was never closed is a no-op, so the reported
 *     values would not move either.  The term guards a pointless call rather
 *     than a wrong report.
 *   - deriving the barrier from the intent (`= !reopened`) instead of from
 *     the admission observed afterwards.  The two agree whenever the reopen
 *     takes effect, and the only way to make an intended reopen fail is to
 *     shut the manager down -- which also makes the status read fail, so the
 *     derived form degrades to FALSE and the case proves nothing.  That line
 *     keeps its "argued, not proved" marker for this reason. */
static void
test_seal_ambiguous_write_stands_when_the_reread_fails (void)
{
  SealFixture fixture = { 0 };
  seal_fixture_init (&fixture, "wyl-graph-seal-ambig-b-XXXXXX");

  SealPhaseFault fault = {TRUE, TRUE, 0, 0};
  wyl_fact_graph_seal_set_test_hook (seal_phase_fault, &fault);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info,
      fixture.manager, -1, &outcome), ==, WYRELOG_E_IO);

  g_assert_cmpuint (fault.write_seen, ==, 1);
  g_assert_cmpuint (fault.probe_seen, ==, 1);

  g_assert_false (outcome.sealed_committed);
  g_assert_true (outcome.runtime_barrier_established);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);

  wyl_fact_graph_seal_outcome_clear (&outcome);
  seal_fixture_clear (&fixture);
}

static void
test_seal_establishes_the_barrier_and_the_durable_bit (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-live-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");
  materialize_graph_engine (policy, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);
  /* Without a published engine the eviction assertions below pin the call and
   * not its effect: evict_closed reports out_evicted TRUE whether or not
   * there was a generation to detach. */
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);

  /* Pinned before the seal.  The eviction detaches the entry's reference
   * while this one keeps the generation alive -- the carve-out that lets a
   * seal use evict_closed where try_evict refuses. */
  WylFactGraphKey pinned_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&pinned_key, "tenant-a",
      "orders"), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) pinned = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &pinned_key, &pinned), ==, WYRELOG_E_OK);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_true (outcome.sealed_committed);
  g_assert_true (outcome.runtime_barrier_established);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  /* The fourth postcondition, and the one an admission assertion cannot
   * stand in for: acquire_snapshot is refused by the barrier whether or not
   * the engine went away, so without this the eviction can be deleted
   * outright and nothing notices.
   *
   * These are only meaningful because the fixture publishes a real engine.
   * Without one, entry->current is already NULL and evict_closed reports
   * out_evicted TRUE regardless, so queryable would read FALSE whether or not
   * the eviction did anything. */
  g_assert_true (outcome.engine_evicted);
  g_assert_cmpint (outcome.status.state, ==, WYL_FACT_GRAPH_RUNTIME_EVICTED);
  g_assert_false (outcome.status.queryable);
  /* And the distinguishing promise: the generation pinned before the close
   * is still alive and still usable after the seal detached the entry's
   * reference. */
  g_assert_cmpuint (outcome.status.active_snapshots, ==, 1);
  gboolean reached = FALSE;
  g_assert_cmpint (wyl_fact_graph_snapshot_use (pinned, engine_is_reachable,
      &reached), ==, WYRELOG_E_OK);
  g_assert_true (reached);
  wyl_fact_graph_seal_outcome_clear (&outcome);
  wyl_fact_graph_key_clear (&pinned_key);

  /* Durable, and the barrier holds against new work. */
  gboolean active = TRUE;
  g_assert_cmpint (wyl_policy_store_fact_graph_is_active (policy, "tenant-a",
      "orders", &active), ==, WYRELOG_E_OK);
  g_assert_false (active);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &key, &snapshot), ==, WYRELOG_E_BUSY);
  g_assert_null (snapshot);

  /* Idempotent: a repeat commits nothing and still converges the runtime. */
  WylFactGraphSealOutcome again = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &again),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (again.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_seal_outcome_clear (&again);

  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean entered;
  gboolean released;
} BuildGate;

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *key;
  BuildGate *gate;
  wyrelog_error_t result;
} GatedRefresh;

static wyrelog_error_t
gated_build (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  BuildGate *gate = user_data;
  (void) key;
  *out_engine = NULL;
  g_mutex_lock (&gate->mutex);
  gate->entered = TRUE;
  g_cond_broadcast (&gate->changed);
  while (!gate->released)
    g_cond_wait (&gate->changed, &gate->mutex);
  g_mutex_unlock (&gate->mutex);
  /* Fail the build rather than open an engine: this test is about the seal's
   * drain, and an engine would drag the whole wirelog fixture in for nothing.
   * A failed build still consumes and releases operation_active, which is the
   * admitted work the drain has to wait for. */
  return WYRELOG_E_IO;
}

static gpointer
gated_refresh_thread (gpointer user_data)
{
  GatedRefresh *r = user_data;
  r->result = wyl_fact_graph_runtime_manager_refresh (r->manager, r->key,
          gated_build, r->gate, NULL);
  return NULL;
}

/* The compensation rule.  A seal that aborts before the durable commit must
 * leave the graph admitting again -- otherwise a failed seal bars the graph
 * with nothing recorded anywhere to say why, and only a restart clears it. */
static void
test_seal_aborted_by_a_drain_timeout_reopens_admission (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-abort-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);

  /* Admitted work, held open.  A build in flight is what the seal's drain has
   * to wait for, and it needs no engine to be one. */
  BuildGate gate = { 0 };
  g_mutex_init (&gate.mutex);
  g_cond_init (&gate.changed);
  GatedRefresh refresh = {.manager = manager,.key = &key,.gate = &gate,
                          .result = WYRELOG_E_OK };
  GThread *worker = g_thread_new ("gated-build", gated_refresh_thread,
          &refresh);
  g_mutex_lock (&gate.mutex);
  while (!gate.entered)
    g_cond_wait (&gate.changed, &gate.mutex);
  g_mutex_unlock (&gate.mutex);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome aborted = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, 50 * 1000,
      &aborted), ==, WYRELOG_E_BUSY);
  g_assert_false (aborted.sealed_committed);
  g_assert_true (aborted.status.operation_active);
  /* The abort rolled the close back, so the graph is admitting.  This field
   * has been wrong on two of three return paths across two rounds, each time
   * because nothing held it. */
  g_assert_false (aborted.runtime_barrier_established);
  wyl_fact_graph_seal_outcome_clear (&aborted);

  /* Nothing durable happened, and the graph admits again -- this is the
   * assertion the compensation rule exists for. */
  gboolean active = FALSE;
  g_assert_cmpint (wyl_policy_store_fact_graph_is_active (policy, "tenant-a",
      "orders", &active), ==, WYRELOG_E_OK);
  g_assert_true (active);
  WylFactGraphRuntimeStatus after = status_of (manager, "tenant-a", "orders");
  g_assert_cmpint (after.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  wyl_fact_graph_runtime_status_clear (&after);

  g_mutex_lock (&gate.mutex);
  gate.released = TRUE;
  g_cond_broadcast (&gate.changed);
  g_mutex_unlock (&gate.mutex);
  g_thread_join (worker);

  /* With the build finished the same seal succeeds, which proves the abort
   * was the drain and not something permanent. */
  WylFactGraphSealOutcome retried = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &retried),
      ==, WYRELOG_E_OK);
  g_assert_true (retried.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&retried);

  g_cond_clear (&gate.changed);
  g_mutex_clear (&gate.mutex);
  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

/* The three conditions wyl_policy_store_fact_graph_is_active folds together,
 * each of which needs a different answer.  Reading it instead of the graph's
 * own seal made all three silently wrong. */
static void
test_seal_refuses_an_absent_graph_and_seals_a_real_one (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-states-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* A graph the store has never heard of is NOT_FOUND, not a successful
   * seal.  Reading is_active reported it inactive, so the durable write was
   * skipped and the call returned OK with sealed_committed set. */
  wyl_policy_fact_graph_info_t absent = {
    .tenant_id = "tenant-a",
    .graph_id = "no-such-graph",
  };
  WylFactGraphSealOutcome missing = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &absent, manager, -1,
      &missing), ==, WYRELOG_E_NOT_FOUND);
  g_assert_false (missing.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&missing);

  /* A real graph seals, and the durable bit really lands. */
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &sealed),
      ==, WYRELOG_E_OK);
  g_assert_true (sealed.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  /* Durable enough to survive a fresh manager, which is what "the seal
   * evaporated" means concretely. */
  g_autoptr (WylFactGraphRuntimeManager) rebooted = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&rebooted), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t after_boot = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, rebooted, &after_boot);
  g_assert_cmpuint (after_boot.graphs_sealed, ==, 1);
  WylFactGraphRuntimeStatus rebooted_status = status_of (rebooted, "tenant-a",
          "orders");
  g_assert_cmpint (rebooted_status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&rebooted_status);

  remove_tree (root);
}

/* An aborted seal must not reopen a graph that is ALREADY durably sealed.
 * The pre-existing endpoint writes the durable bit with no runtime
 * involvement, so "durably sealed with an open runtime entry" exists in the
 * shipped daemon -- and an aborted seal against one used to reopen it. */
static void
test_aborted_seal_does_not_reopen_an_already_sealed_graph (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-resealed-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);

  /* Seal durably the way the old endpoint does -- no runtime involvement --
   * so the entry is open while the graph is sealed. */
  g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
      "orders"), ==, WYRELOG_E_OK);

  BuildGate gate = { 0 };
  g_mutex_init (&gate.mutex);
  g_cond_init (&gate.changed);
  GatedRefresh refresh = {.manager = manager,.key = &key,.gate = &gate,
                          .result = WYRELOG_E_OK };
  GThread *worker = g_thread_new ("gated-build", gated_refresh_thread,
          &refresh);
  g_mutex_lock (&gate.mutex);
  while (!gate.entered)
    g_cond_wait (&gate.changed, &gate.mutex);
  g_mutex_unlock (&gate.mutex);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome aborted = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, 50 * 1000,
      &aborted), ==, WYRELOG_E_BUSY);
  /* The other direction: an already-sealed graph stays closed, so the field
   * must report the barrier that is really there. */
  g_assert_true (aborted.runtime_barrier_established);
  wyl_fact_graph_seal_outcome_clear (&aborted);

  /* The abort must leave it CLOSED.  Reopening here produces "durably sealed
   * and admitting", which is the state the compensation rule exists to make
   * unrepresentable. */
  WylFactGraphRuntimeStatus after = status_of (manager, "tenant-a", "orders");
  g_assert_cmpint (after.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&after);

  g_mutex_lock (&gate.mutex);
  gate.released = TRUE;
  g_cond_broadcast (&gate.changed);
  g_mutex_unlock (&gate.mutex);
  g_thread_join (worker);

  g_cond_clear (&gate.changed);
  g_mutex_clear (&gate.mutex);
  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

/* The condition that separates the graph's own seal from "is this graph
 * active": a SEALED TENANT holding an UNSEALED graph.  Sourcing the flag from
 * wyl_policy_store_fact_graph_is_active makes those indistinguishable, so the
 * durable write was skipped and the call reported success having written
 * nothing -- the seal then evaporated at the next boot.
 *
 * Every other fixture here has an active tenant, so without this test the
 * regression is invisible: collapsing S1 back into the one-call helper, which
 * is exactly the tidy-up a later reader would make, leaves the suite green. */
static void
test_seal_writes_durably_inside_a_sealed_tenant (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-tenant-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* Seal the tenant.  The graph's own bit stays unset, which is the whole
   * point: is_active now reports FALSE for a graph that is not sealed. */
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (policy, "tenant-a",
      TRUE), ==, WYRELOG_E_OK);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_true (outcome.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&outcome);

  /* The durable write really happened.  Unseal the tenant so nothing but the
   * graph's own bit can be keeping it sealed, then boot a fresh manager:
   * before the fix this reported graphs_sealed == 0 and an open graph. */
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (policy, "tenant-a",
      FALSE), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) rebooted = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&rebooted), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t after_boot = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, rebooted, &after_boot);
  g_assert_cmpuint (after_boot.graphs_sealed, ==, 1);
  WylFactGraphRuntimeStatus status = status_of (rebooted, "tenant-a",
          "orders");
  g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&status);

  remove_tree (root);
}


/* ------------------------------------------------------------------ */
/* Unseal (issue #548, unit 3b).  No production caller yet: the handle and
 * daemon routes land in the units above this one, and wiring them has a
 * precondition the sequencer's header names -- the two seal routes do not
 * exclude each other, so neither excludes an unseal.
 *
 * These fixtures build an AUTHORITY-MANAGED graph, where the seal fixture
 * above builds a legacy_unclassified one, and the difference is forced rather
 * than stylistic: wyl_policy_store_unseal_fact_graph refuses a sealed
 * legacy_unclassified graph outright, because the schema permits sealed = 1
 * for that state and offers no transition out of it.  A seal accepts that
 * population and an unseal does not.  The refusal is pinned by its own case
 * at the end of this group. */

static void
register_orders_schema (wyl_policy_store_t *policy, const gchar *tenant_id,
    const gchar *graph_id)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (policy,
      &schema), ==, WYRELOG_E_OK);
}

/* Reserve the graph through the authority, and optionally finish it.
 *
 * |construct| is what separates a graph whose engine can be built from one
 * whose cannot, and it has to be a parameter rather than two fixtures
 * because the two configurations disagree about what "finished" means.  Under
 * the bridge the provisioning run creates the retained pair that
 * open_provisioned_graph later opens; off-bridge nothing constructs anything
 * and the engine builder resolves facts.duckdb through the fact-root
 * directory instead -- on the tenant and graph names, never on the row's
 * storage_path -- so the caller writes that file itself.  materialize_graph_
 * engine does address it by storage_path, which is fine because the two
 * resolve to the same file; the distinction matters only for what the
 * BUILDER depends on.  What both
 * configurations share is that an authority-managed graph left un-constructed
 * cannot be opened, which is exactly the state the U5-failure case needs. */
static void
create_authority_graph (wyl_policy_store_t *policy, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id, gboolean construct)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (policy, tenant_id,
      &created), ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"},
    {"amount", "int64"},
    {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  gchar op_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_policy_store_create_fact_graph_provisioning (policy,
      &graph_opts, NULL, op_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpstr (op_uuid, !=, "");

  gboolean constructed = FALSE;
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  if (construct) {
    /* The provisioning run is the only thing that builds the retained pair
     * open_provisioned_graph later opens. */
    g_assert_cmpint (wyl_fact_graph_provisioning_recover (policy, op_uuid,
        root, NULL), ==, WYRELOG_E_OK);
    constructed = TRUE;
  }
#else
  (void) construct;
#endif
  if (!constructed) {
    /* Straight to active through the authority, constructing nothing.  For
     * |construct| off-bridge that is the whole job -- the caller then writes
     * facts.duckdb itself.  For !construct it is the point: the engine
     * builder finds no facts.duckdb off-bridge, and no retained pair under
     * the bridge, so the build fails for a reason that is the graph's state
     * rather than a corrupted file. */
    WylPolicyAuthorityMutationResult mutation =
        WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
    g_assert_cmpint (wyl_policy_store_transition_graph_authority (policy,
        tenant_id, graph_id, WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
        WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1, 0,
        &mutation), ==, WYRELOG_E_OK);
  }
  register_orders_schema (policy, tenant_id, graph_id);
}

/* Seed the constructed graph's store, through whichever open the runtime will
 * use to read it back. */
static void
materialize_authority_graph_engine (wyl_policy_store_t *policy,
    const gchar *root, const gchar *tenant_id, const gchar *graph_id)
{
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy, root,
      tenant_id, graph_id, TRUE, &store), ==, WYRELOG_E_OK);
  append_seed_batch (store, tenant_id, graph_id);
#else
  (void) root;
  materialize_graph_engine (policy, tenant_id, graph_id);
#endif
}

/* The seal fixture's shape, over an authority-managed graph. */
static void
unseal_fixture_init (SealFixture *fixture, const gchar *template_name,
    gboolean construct)
{
  g_autoptr (GError) error = NULL;
  fixture->root = wyl_test_make_secure_fact_root (template_name, &error);
  g_assert_nonnull (fixture->root);
  g_autofree gchar *policy_path = g_build_filename (fixture->root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture->policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture->policy), ==,
      WYRELOG_E_OK);
  create_authority_graph (fixture->policy, fixture->root, "tenant-a", "orders",
      construct);
  if (construct)
    materialize_authority_graph_engine (fixture->policy, fixture->root,
        "tenant-a", "orders");
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture->manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (fixture->policy, fixture->root,
      fixture->manager, &summary);
  if (construct)
    g_assert_cmpuint (summary.graphs_loaded, ==, 1);
  else
    g_assert_cmpuint (summary.graphs_degraded, ==, 1);
}

/* The unseal's three seams.  Two of them fail a step; the third only watches,
 * because the claim it exists to prove is an ordering: the engine is already
 * published when admission reopens.  A seam that merely substituted a result
 * there would prove nothing about that order. */
typedef struct
{
  gboolean fail_write;
  gboolean fail_probe;
  gboolean reseal_at_probe;
  gboolean shutdown_at_open;
  wyl_policy_store_t *policy;
  WylFactGraphRuntimeManager *manager;
  guint write_seen;
  guint probe_seen;
  guint open_seen;
  gboolean open_saw_engine;
  WylFactGraphAdmission open_saw_admission;
} UnsealPhaseFault;

static wyrelog_error_t
unseal_phase_fault (const gchar *phase, gpointer user_data)
{
  UnsealPhaseFault *fault = user_data;
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_UNSEAL_PHASE_DURABLE_WRITE) == 0) {
    fault->write_seen++;
    return fault->fail_write ? WYRELOG_E_IO : WYRELOG_E_OK;
  }
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_UNSEAL_PHASE_READBACK_PROBE) == 0) {
    fault->probe_seen++;
    /* Re-seal from inside the seam rather than substituting the readback's
     * answer.  The branch under test is "the row really does read back
     * sealed", and a concurrent re-seal is how that happens for real; a faked
     * answer would leave the durable bit clear, and the assertions below
     * could not tell the two apart. */
    if (fault->reseal_at_probe)
      g_assert_cmpint (wyl_policy_store_seal_fact_graph (fault->policy,
          "tenant-a", "orders"), ==, WYRELOG_E_OK);
    return fault->fail_probe ? WYRELOG_E_IO : WYRELOG_E_OK;
  }
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_UNSEAL_PHASE_OPEN_ADMISSION) == 0) {
    fault->open_seen++;
    WylFactGraphRuntimeStatus at_open = status_of (fault->manager, "tenant-a",
            "orders");
    fault->open_saw_engine = at_open.queryable;
    fault->open_saw_admission = at_open.admission;
    wyl_fact_graph_runtime_status_clear (&at_open);
    /* Shut the manager down so the reopen fails for the manager's own
     * reason.  Returning non-OK here would fail the step without running it,
     * which does not put an engine behind an unliftable barrier. */
    if (fault->shutdown_at_open)
      wyl_fact_graph_runtime_manager_shutdown (fault->manager);
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_OK;
}

static void
seal_the_orders_graph (SealFixture *fixture)
{
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture->policy, &info,
      fixture->manager, -1, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&outcome);
}

static gboolean
durable_seal_bit (wyl_policy_store_t *policy, const gchar *graph_id)
{
  SealedBitProbe probe = {"tenant-a", graph_id, FALSE, FALSE};
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (policy, "tenant-a",
      capture_sealed_bit_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_true (probe.found);
  return probe.sealed;
}

/* sealed = TRUE on purpose, in every case including the ones where the graph
 * is not sealed at all.  A real caller holds the row it read before the
 * durable clear, so this is the shape the sequencer will actually be handed
 * -- and passing it proves two things at once: U1 reads the store rather than
 * trusting the argument, and U5 builds from an info it constructed rather
 * than forwarding this one, which open_graph_engine would refuse. */
static wyrelog_error_t
unseal_orders (SealFixture *fixture, WylFactGraphUnsealOutcome *outcome)
{
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .sealed = TRUE,
  };
  return wyl_fact_graph_unseal (fixture->policy, fixture->root, &info,
             fixture->manager, outcome);
}

/* The whole point of the unit: a sealed graph comes back, durably and in the
 * runtime, and a reader can pin it again. */
static void
test_unseal_restores_a_sealed_graph (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-ok-XXXXXX", TRUE);
  seal_the_orders_graph (&fixture);
  g_assert_true (durable_seal_bit (fixture.policy, "orders"));

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.unseal_committed);
  g_assert_false (outcome.already_unsealed);
  g_assert_false (outcome.readback_still_sealed);
  g_assert_true (outcome.engine_published);
  g_assert_true (outcome.admission_open);
  g_assert_cmpint (outcome.status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  g_assert_false (durable_seal_bit (fixture.policy, "orders"));

  /* The durable bit and the axis are both restored; this is the third thing,
   * and the only one a reader would notice.  acquire_snapshot answers BUSY
   * behind a barrier, so its success here is the barrier being gone. */
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot
        (fixture.manager, &key, &snapshot), ==, WYRELOG_E_OK);
  g_assert_nonnull (snapshot);
  gboolean reached = FALSE;
  g_assert_cmpint (wyl_fact_graph_snapshot_use (snapshot,
      engine_is_reachable, &reached), ==, WYRELOG_E_OK);
  g_assert_true (reached);
  wyl_fact_graph_snapshot_unref (snapshot);
  wyl_fact_graph_key_clear (&key);

  seal_fixture_clear (&fixture);
}

/* A graph the policy store does not hold is NOT_FOUND, and nothing is
 * touched: U1 runs before the close. */
static void
test_unseal_refuses_an_absent_graph (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-absent-XXXXXX", TRUE);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "no-such-graph",
  };
  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, fixture.root, &info,
      fixture.manager, &outcome), ==, WYRELOG_E_NOT_FOUND);
  g_assert_false (outcome.unseal_committed);
  g_assert_false (outcome.already_unsealed);
  g_assert_false (outcome.engine_published);
  g_assert_false (outcome.admission_open);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  /* The real graph beside it is untouched. */
  WylFactGraphRuntimeStatus orders = status_of (fixture.manager, "tenant-a",
          "orders");
  g_assert_cmpint (orders.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  wyl_fact_graph_runtime_status_clear (&orders);

  seal_fixture_clear (&fixture);
}

/* Both new entrypoints reject their own missing arguments.  The replay
 * wrapper is thin enough that this, plus the gate it inherits, is all of it
 * that is worth pinning apart from the paths the unseal drives.
 *
 * fact_root is the case that earns its place.  refresh_one_graph tolerates a
 * NULL or empty root, so without the sequencer's own check the refusal would
 * arrive from the builder at U5 -- past the durable clear -- and the graph
 * would be left unsealed and barred by a call reporting an argument error. */
static void
test_unseal_rejects_missing_arguments (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-args-XXXXXX", TRUE);
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  wyl_policy_fact_graph_info_t no_tenant = {.graph_id = "orders" };
  wyl_policy_fact_graph_info_t no_graph = {.tenant_id = "tenant-a" };
  WylFactGraphUnsealOutcome outcome = { 0 };

  g_assert_cmpint (wyl_fact_graph_unseal (NULL, fixture.root, &info,
      fixture.manager, &outcome), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, fixture.root, NULL,
      fixture.manager, &outcome), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, fixture.root, &info,
      NULL, &outcome), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, fixture.root,
      &no_tenant, fixture.manager, &outcome), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, fixture.root,
      &no_graph, fixture.manager, &outcome), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, NULL, &info,
      fixture.manager, &outcome), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, "", &info,
      fixture.manager, &outcome), ==, WYRELOG_E_INVALID);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  /* The graph is untouched by all of the above: an argument refusal must not
   * have closed anything on its way out. */
  WylFactGraphRuntimeStatus untouched = status_of (fixture.manager, "tenant-a",
          "orders");
  g_assert_cmpint (untouched.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  wyl_fact_graph_runtime_status_clear (&untouched);

  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_replay_refresh_graph_closed (NULL, fixture.root,
      &info, fixture.manager, &status), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_replay_refresh_graph_closed (fixture.policy,
      fixture.root, NULL, fixture.manager, &status), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_replay_refresh_graph_closed (fixture.policy,
      fixture.root, &info, NULL, &status), ==, WYRELOG_E_INVALID);
  wyl_fact_graph_runtime_status_clear (&status);

  /* And the gate the wrapper inherits from refresh_closed: republishing an
   * admitting graph is plain refresh's job.  This graph was never sealed. */
  g_assert_cmpint (wyl_fact_replay_refresh_graph_closed (fixture.policy,
      fixture.root, &info, fixture.manager, &status), ==, WYRELOG_E_INVALID);
  wyl_fact_graph_runtime_status_clear (&status);

  seal_fixture_clear (&fixture);
}

/* A graph that is durably unsealed AND admitting is finished.  Rebuilding it
 * would take a healthy graph offline for the duration and, on a failed
 * rebuild, leave it barred -- so the fast path is a correctness choice, and
 * the unchanged engine generation is what proves it was taken. */
static void
test_unseal_of_an_admitting_graph_changes_nothing (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-noop-XXXXXX", TRUE);

  WylFactGraphRuntimeStatus before = status_of (fixture.manager, "tenant-a",
          "orders");
  g_assert_cmpint (before.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  g_assert_true (before.queryable);
  guint64 generation = before.engine_generation;
  wyl_fact_graph_runtime_status_clear (&before);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.already_unsealed);
  g_assert_false (outcome.unseal_committed);
  g_assert_true (outcome.engine_published);
  g_assert_true (outcome.admission_open);
  g_assert_cmpuint (outcome.status.engine_generation, ==, generation);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  seal_fixture_clear (&fixture);
}

/* Durably unsealed but barred is the state a call that died between U3 and U6
 * leaves behind, and it is reachable on any U5 or U6 failure.  A retry has to
 * converge it; returning OK on already_unsealed alone would report success
 * over a graph nobody can reach until the next boot. */
static void
test_unseal_converges_a_barred_but_unsealed_graph (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-converge-XXXXXX", TRUE);

  /* Stand in for the mid-failure state by hand: close the axis and detach
   * the engine, without ever setting the durable bit. */
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission
        (fixture.manager, &key), ==, WYRELOG_E_OK);
  gboolean evicted = FALSE;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_evict_closed
        (fixture.manager, &key, &evicted), ==, WYRELOG_E_OK);
  g_assert_true (evicted);
  wyl_fact_graph_key_clear (&key);
  g_assert_false (durable_seal_bit (fixture.policy, "orders"));

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.already_unsealed);
  g_assert_false (outcome.unseal_committed);
  g_assert_true (outcome.engine_published);
  g_assert_true (outcome.admission_open);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  seal_fixture_clear (&fixture);
}

/* The ordering claim, and the reason U6 is last rather than first: at the
 * instant admission reopens, the engine is already attached.
 *
 * The order is not held by this case alone -- refresh_closed refuses an
 * admitting graph, so reversing U5 and U6 makes the build fail outright and
 * the restore case catches it, measured.  What this one adds is the state at
 * the seam itself: a rebuild that published nothing, or one that reopened
 * early and republished afterwards, would still reach U6 and would fail
 * here. */
static void
test_unseal_publishes_the_engine_before_it_reopens (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-order-XXXXXX", TRUE);
  seal_the_orders_graph (&fixture);

  UnsealPhaseFault fault = { 0 };
  fault.policy = fixture.policy;
  fault.manager = fixture.manager;
  wyl_fact_graph_seal_set_test_hook (unseal_phase_fault, &fault);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpuint (fault.open_seen, ==, 1);
  g_assert_true (fault.open_saw_engine);
  g_assert_cmpint (fault.open_saw_admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  g_assert_true (outcome.admission_open);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  seal_fixture_clear (&fixture);
}

/* U3 fails: the graph stays sealed in both places, and U4 is never reached --
 * so nothing downstream can mistake a failed write for a lost race. */
static void
test_unseal_durable_write_failure_leaves_the_graph_sealed (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-write-XXXXXX", TRUE);
  seal_the_orders_graph (&fixture);

  UnsealPhaseFault fault = { 0 };
  fault.fail_write = TRUE;
  fault.policy = fixture.policy;
  fault.manager = fixture.manager;
  wyl_fact_graph_seal_set_test_hook (unseal_phase_fault, &fault);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_IO);
  g_assert_cmpuint (fault.write_seen, ==, 1);
  g_assert_cmpuint (fault.probe_seen, ==, 0);
  g_assert_false (outcome.unseal_committed);
  g_assert_false (outcome.readback_still_sealed);
  g_assert_false (outcome.admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  g_assert_true (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

/* The readback exists because the store's unseal reports OK for a lost
 * compare-and-swap.  Re-seal the row from inside the seam and the readback
 * finds it sealed: the graph must stay closed, because reopening a
 * possibly-sealed graph is the one direction that produces "durably sealed
 * and admitting".
 *
 * Kills dropping the readback entirely: without it the sequencer walks on to
 * U5 and U6 and reopens a graph that is sealed on disk. */
static void
test_unseal_readback_that_is_still_sealed_keeps_the_barrier (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-lostcas-XXXXXX", TRUE);
  seal_the_orders_graph (&fixture);

  UnsealPhaseFault fault = { 0 };
  fault.reseal_at_probe = TRUE;
  fault.policy = fixture.policy;
  fault.manager = fixture.manager;
  wyl_fact_graph_seal_set_test_hook (unseal_phase_fault, &fault);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (fault.write_seen, ==, 1);
  g_assert_cmpuint (fault.probe_seen, ==, 1);
  g_assert_cmpuint (fault.open_seen, ==, 0);
  g_assert_true (outcome.readback_still_sealed);
  g_assert_false (outcome.unseal_committed);
  g_assert_false (outcome.admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  g_assert_true (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

/* A readback that cannot run at all is a different case from one that runs
 * and says sealed, and it reports differently: the durable bit really is
 * clear here -- the write landed -- but nothing confirmed it, so the graph
 * stays barred and readback_still_sealed stays FALSE. */
static void
test_unseal_readback_failure_leaves_the_graph_barred (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-probe-XXXXXX", TRUE);
  seal_the_orders_graph (&fixture);

  UnsealPhaseFault fault = { 0 };
  fault.fail_probe = TRUE;
  fault.policy = fixture.policy;
  fault.manager = fixture.manager;
  wyl_fact_graph_seal_set_test_hook (unseal_phase_fault, &fault);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_IO);
  g_assert_cmpuint (fault.probe_seen, ==, 1);
  g_assert_cmpuint (fault.open_seen, ==, 0);
  g_assert_false (outcome.readback_still_sealed);
  g_assert_false (outcome.unseal_committed);
  g_assert_false (outcome.admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  /* The write is not rolled back, because there is no rollback: U3 is
   * irreversible by construction.  A retry converges from here -- that is
   * what /fact-graph-seal/unseal-converges-a-barred-graph proves. */
  g_assert_false (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

/* U5 fails.  The durable clear stands -- it is past the linearization point
 * -- and the graph is left barred rather than admitting with no engine.  A
 * graph reserved through the authority but never constructed is what makes
 * the build fail in both build configurations for the same reason. */
static void
test_unseal_engine_build_failure_leaves_a_barred_graph (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-build-XXXXXX", FALSE);
  seal_the_orders_graph (&fixture);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), !=, WYRELOG_E_OK);
  g_assert_true (outcome.unseal_committed);
  g_assert_false (outcome.engine_published);
  g_assert_false (outcome.admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  /* Durably unsealed and still barred: the state the converge case starts
   * from, arrived at for real rather than staged by hand. */
  g_assert_false (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

/* U6 fails.  The engine was published, so it is detached again -- and the
 * report is read off the graph rather than off the intent, which is why both
 * observed fields are FALSE here even though U5 succeeded. */
static void
test_unseal_reopen_failure_reports_a_graph_that_is_not_admitting (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-reopen-XXXXXX", TRUE);
  seal_the_orders_graph (&fixture);

  UnsealPhaseFault fault = { 0 };
  fault.shutdown_at_open = TRUE;
  fault.policy = fixture.policy;
  fault.manager = fixture.manager;
  wyl_fact_graph_seal_set_test_hook (unseal_phase_fault, &fault);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (fault.open_seen, ==, 1);
  /* U5 really did publish before the shutdown -- otherwise this case would
   * be pinning a failure that happened earlier than it claims. */
  g_assert_true (fault.open_saw_engine);
  g_assert_true (outcome.unseal_committed);
  g_assert_false (outcome.admission_open);
  g_assert_false (outcome.engine_published);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  /* The durable half committed regardless; the next boot converges the
   * runtime half. */
  g_assert_false (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

/* An owed erasure survives a seal and an unseal.  evict_closed preserves
 * forget_state where the sweepers clear it, and refresh_closed leaves it
 * alone -- so a graph sealed with a verdict outstanding comes back still
 * owing it, rather than reading CONVERGED over an erasure that never ran. */
static void
test_unseal_preserves_the_forget_verdict (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-forget-XXXXXX", TRUE);

  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state
        (fixture.manager, &key, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==,
      WYRELOG_E_OK);
  wyl_fact_graph_key_clear (&key);

  seal_the_orders_graph (&fixture);
  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.status.forget_state, ==,
      WYL_FACT_GRAPH_FORGET_INCOMPLETE);
  g_assert_true (outcome.admission_open);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  seal_fixture_clear (&fixture);
}

/* A graph sealed durably with its runtime entry left admitting.  Not a
 * contrived state: the daemon's graph_seal_handler writes the durable bit
 * under the policy write lease alone and never touches the runtime, so any
 * graph sealed through that route sits exactly here until the next boot.
 *
 * U2 is what makes it work.  Without the close, U5 meets an OPEN entry and
 * refresh_closed refuses it with WYRELOG_E_INVALID -- deleting the close
 * leaves every other case in this file green, because they all reach U3
 * through wyl_fact_graph_seal, which closed the axis on the way in. */
static void
test_unseal_closes_a_graph_sealed_out_of_band (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-oob-XXXXXX", TRUE);

  g_assert_cmpint (wyl_policy_store_seal_fact_graph (fixture.policy,
      "tenant-a", "orders"), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus before = status_of (fixture.manager, "tenant-a",
          "orders");
  g_assert_cmpint (before.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  wyl_fact_graph_runtime_status_clear (&before);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.unseal_committed);
  g_assert_false (outcome.already_unsealed);
  g_assert_true (outcome.engine_published);
  g_assert_true (outcome.admission_open);
  wyl_fact_graph_unseal_outcome_clear (&outcome);
  g_assert_false (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

/* U2 fails.  A manager shutdown racing the unseal is the only way to make
 * close_admission refuse, and the whole point is where it lands: before U3,
 * so the durable bit is untouched and the graph is still sealed on disk.
 *
 * It is also the case that shows the outcome fields are answers to "is it
 * definitely admitting", not to "is it barred" -- the status cannot be read
 * through a shut-down manager either, so both stay FALSE without observing
 * anything. */
static void
test_unseal_refuses_when_the_manager_is_shutting_down (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-shutdown-XXXXXX", TRUE);
  seal_the_orders_graph (&fixture);
  wyl_fact_graph_runtime_manager_shutdown (fixture.manager);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_BUSY);
  g_assert_false (outcome.unseal_committed);
  g_assert_false (outcome.readback_still_sealed);
  g_assert_false (outcome.admission_open);
  g_assert_false (outcome.engine_published);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  g_assert_true (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

/* The runtime holds no entry at all: a graph created and sealed after boot,
 * which nothing has refreshed.  U2's close_admission answers NOT_FOUND and
 * the sequencer treats that as success -- nothing can be admitted through an
 * entry that does not exist -- then U5 mints the entry CLOSED and U6 opens it.
 *
 * Built without a replay pass on purpose; every other case here runs
 * wyl_fact_replay_policy_graphs first, so the runtime always holds an entry
 * and the NOT_FOUND tolerance is never the deciding branch.  Deleting
 * "&& rc != WYRELOG_E_NOT_FOUND" from U2 leaves the rest of this file green
 * and fails here. */
static void
test_unseal_tolerates_a_graph_the_runtime_never_held (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-unseal-noentry-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_authority_graph (policy, root, "tenant-a", "orders", TRUE);
  materialize_authority_graph_engine (policy, root, "tenant-a", "orders");
  g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
      "orders"), ==, WYRELOG_E_OK);

  /* No wyl_fact_replay_policy_graphs: the manager is empty. */
  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  WylFactGraphRuntimeStatus absent = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &key,
      &absent), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_graph_runtime_status_clear (&absent);
  wyl_fact_graph_key_clear (&key);

  SealFixture fixture = { root, policy, manager };
  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.unseal_committed);
  g_assert_true (outcome.engine_published);
  g_assert_true (outcome.admission_open);
  wyl_fact_graph_unseal_outcome_clear (&outcome);
  g_assert_false (durable_seal_bit (policy, "orders"));

  /* The fixture's fields are borrowed; g_autoptr owns them.  Close the store
   * BEFORE unlinking the tree, the order seal_fixture_clear uses: removing
   * policy.db out from under an open SQLite handle is benign on POSIX and
   * fails on Windows, which would leave this one tree behind and reintroduce
   * for a single test the leak seal_fixture_clear exists to close. */
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  g_clear_pointer (&manager, wyl_fact_graph_runtime_manager_unref);
  g_clear_pointer (&policy, wyl_policy_store_close);
  remove_tree (root);
}

/* Admitting is not serving, and the fast path returns OK over the difference.
 *
 * retire_unseen rewrites an entry to EVICTED and leaves the admission axis
 * alone, so a graph can admit with no engine published.  The header says the
 * fast path returns OK there -- republishing an admitting graph is plain
 * refresh's job -- and that a caller must read engine_published rather than
 * the return code.  That was argued and not pinned; this pins it. */
static void
test_unseal_of_an_admitting_graph_with_no_engine_reports_it (void)
{
  SealFixture fixture = { 0 };
  unseal_fixture_init (&fixture, "wyl-graph-unseal-evicted-XXXXXX", TRUE);

  /* An empty seen set retires every entry: state EVICTED, axis untouched. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_retire_unseen
        (fixture.manager, NULL, 0), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus retired = status_of (fixture.manager, "tenant-a",
          "orders");
  g_assert_cmpint (retired.state, ==, WYL_FACT_GRAPH_RUNTIME_EVICTED);
  g_assert_cmpint (retired.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  g_assert_false (retired.queryable);
  wyl_fact_graph_runtime_status_clear (&retired);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.already_unsealed);
  g_assert_false (outcome.unseal_committed);
  /* OK, admitting, and NOT serving -- the three together are the contract. */
  g_assert_true (outcome.admission_open);
  g_assert_false (outcome.engine_published);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  seal_fixture_clear (&fixture);
}

/* The population with no inverse.  A legacy_unclassified graph can be sealed
 * and cannot be unsealed: the schema allows sealed = 1 for that state and
 * offers no transition out of it, so the store answers POLICY and the
 * sequencer stops at U3 with the barrier intact.
 *
 * This is why every case above builds an authority-managed graph, and it is
 * the reason worth pinning rather than leaving as a fixture detail: a reader
 * who swaps in the ordinary seal fixture gets POLICY and no explanation. */
static void
test_unseal_refuses_a_legacy_unclassified_graph (void)
{
  SealFixture fixture = { 0 };
  seal_fixture_init (&fixture, "wyl-graph-unseal-legacy-XXXXXX");
  seal_the_orders_graph (&fixture);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (unseal_orders (&fixture, &outcome), ==, WYRELOG_E_POLICY);
  g_assert_false (outcome.unseal_committed);
  g_assert_false (outcome.already_unsealed);
  g_assert_false (outcome.admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  g_assert_true (durable_seal_bit (fixture.policy, "orders"));

  seal_fixture_clear (&fixture);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-graph-seal/boot-reestablishes-admission",
      test_boot_reestablishes_admission_from_the_durable_seal);
  g_test_add_func ("/fact-graph-seal/boot-preserves-forget-verdict",
      test_boot_admission_write_does_not_clobber_the_forget_verdict);
  g_test_add_func ("/fact-graph-seal/ambiguous-write-rolls-back",
      test_seal_ambiguous_write_rolls_back_when_the_reread_says_unsealed);
  g_test_add_func ("/fact-graph-seal/ambiguous-write-stands",
      test_seal_ambiguous_write_stands_when_the_reread_fails);
  g_test_add_func ("/fact-graph-seal/seal-establishes-barrier",
      test_seal_establishes_the_barrier_and_the_durable_bit);
  g_test_add_func ("/fact-graph-seal/seal-abort-reopens",
      test_seal_aborted_by_a_drain_timeout_reopens_admission);
  g_test_add_func ("/fact-graph-seal/seal-distinguishes-graph-states",
      test_seal_refuses_an_absent_graph_and_seals_a_real_one);
  g_test_add_func ("/fact-graph-seal/seal-writes-inside-a-sealed-tenant",
      test_seal_writes_durably_inside_a_sealed_tenant);
  g_test_add_func ("/fact-graph-seal/abort-keeps-a-sealed-graph-closed",
      test_aborted_seal_does_not_reopen_an_already_sealed_graph);
  g_test_add_func ("/fact-graph-seal/unseal-restores-a-sealed-graph",
      test_unseal_restores_a_sealed_graph);
  g_test_add_func ("/fact-graph-seal/unseal-refuses-an-absent-graph",
      test_unseal_refuses_an_absent_graph);
  g_test_add_func ("/fact-graph-seal/unseal-rejects-missing-arguments",
      test_unseal_rejects_missing_arguments);
  g_test_add_func ("/fact-graph-seal/unseal-of-an-admitting-graph-is-a-no-op",
      test_unseal_of_an_admitting_graph_changes_nothing);
  g_test_add_func ("/fact-graph-seal/unseal-converges-a-barred-graph",
      test_unseal_converges_a_barred_but_unsealed_graph);
  g_test_add_func ("/fact-graph-seal/unseal-publishes-before-reopening",
      test_unseal_publishes_the_engine_before_it_reopens);
  g_test_add_func ("/fact-graph-seal/unseal-write-failure-stays-sealed",
      test_unseal_durable_write_failure_leaves_the_graph_sealed);
  g_test_add_func ("/fact-graph-seal/unseal-readback-still-sealed",
      test_unseal_readback_that_is_still_sealed_keeps_the_barrier);
  g_test_add_func ("/fact-graph-seal/unseal-readback-failure-stays-barred",
      test_unseal_readback_failure_leaves_the_graph_barred);
  g_test_add_func ("/fact-graph-seal/unseal-build-failure-stays-barred",
      test_unseal_engine_build_failure_leaves_a_barred_graph);
  g_test_add_func ("/fact-graph-seal/unseal-reopen-failure",
      test_unseal_reopen_failure_reports_a_graph_that_is_not_admitting);
  g_test_add_func ("/fact-graph-seal/unseal-preserves-forget-verdict",
      test_unseal_preserves_the_forget_verdict);
  g_test_add_func ("/fact-graph-seal/unseal-closes-a-graph-sealed-out-of-band",
      test_unseal_closes_a_graph_sealed_out_of_band);
  g_test_add_func ("/fact-graph-seal/unseal-refuses-during-shutdown",
      test_unseal_refuses_when_the_manager_is_shutting_down);
  g_test_add_func ("/fact-graph-seal/unseal-tolerates-an-unheld-graph",
      test_unseal_tolerates_a_graph_the_runtime_never_held);
  g_test_add_func ("/fact-graph-seal/unseal-admitting-without-an-engine",
      test_unseal_of_an_admitting_graph_with_no_engine_reports_it);
  g_test_add_func ("/fact-graph-seal/unseal-refuses-a-legacy-graph",
      test_unseal_refuses_a_legacy_unclassified_graph);
  return g_test_run ();
}

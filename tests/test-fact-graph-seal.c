/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-seal-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/policy/store-private.h"

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
  return g_test_run ();
}

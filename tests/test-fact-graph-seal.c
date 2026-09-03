/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "fact-test-support.h"
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

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-graph-seal/boot-reestablishes-admission",
      test_boot_reestablishes_admission_from_the_durable_seal);
  g_test_add_func ("/fact-graph-seal/boot-preserves-forget-verdict",
      test_boot_admission_write_does_not_clobber_the_forget_verdict);
  return g_test_run ();
}

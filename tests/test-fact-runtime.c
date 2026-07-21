/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/wyl-engine-private.h"

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean entered;
  gboolean released;
} Gate;

typedef struct
{
  gint64 marker;
  wyrelog_error_t failure;
  Gate *gate;
} BuildSpec;

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean completed;
} Completion;

#define DEADLOCK_CEILING_US (30 * G_TIME_SPAN_SECOND)

static void
gate_init (Gate *gate)
{
  g_mutex_init (&gate->mutex);
  g_cond_init (&gate->changed);
}

static void
gate_clear (Gate *gate)
{
  g_cond_clear (&gate->changed);
  g_mutex_clear (&gate->mutex);
}

static void
gate_wait_entered (Gate *gate)
{
  gint64 deadline = g_get_monotonic_time () + DEADLOCK_CEILING_US;
  g_mutex_lock (&gate->mutex);
  while (!gate->entered) {
    gboolean signaled = g_cond_wait_until (&gate->changed, &gate->mutex,
        deadline);
    g_assert_true (signaled || gate->entered);
  }
  g_mutex_unlock (&gate->mutex);
}

static void
gate_release (Gate *gate)
{
  g_mutex_lock (&gate->mutex);
  gate->released = TRUE;
  g_cond_broadcast (&gate->changed);
  g_mutex_unlock (&gate->mutex);
}

static void
completion_init (Completion *completion)
{
  g_mutex_init (&completion->mutex);
  g_cond_init (&completion->changed);
}

static void
completion_clear (Completion *completion)
{
  g_cond_clear (&completion->changed);
  g_mutex_clear (&completion->mutex);
}

static void
completion_signal (Completion *completion)
{
  if (completion == NULL)
    return;
  g_mutex_lock (&completion->mutex);
  completion->completed = TRUE;
  g_cond_broadcast (&completion->changed);
  g_mutex_unlock (&completion->mutex);
}

static void
completion_wait (Completion *completion)
{
  gint64 deadline = g_get_monotonic_time () + DEADLOCK_CEILING_US;
  g_mutex_lock (&completion->mutex);
  while (!completion->completed) {
    gboolean signaled = g_cond_wait_until (&completion->changed,
        &completion->mutex, deadline);
    g_assert_true (signaled || completion->completed);
  }
  g_mutex_unlock (&completion->mutex);
}

static wyrelog_error_t
build_marker_engine (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  BuildSpec *spec = user_data;
  (void) key;
  *out_engine = NULL;
  if (spec->gate != NULL) {
    gint64 deadline = g_get_monotonic_time () + DEADLOCK_CEILING_US;
    g_mutex_lock (&spec->gate->mutex);
    spec->gate->entered = TRUE;
    g_cond_broadcast (&spec->gate->changed);
    while (!spec->gate->released) {
      gboolean signaled = g_cond_wait_until (&spec->gate->changed,
          &spec->gate->mutex, deadline);
      g_assert_true (signaled || spec->gate->released);
    }
    g_mutex_unlock (&spec->gate->mutex);
  }
  if (spec->failure != WYRELOG_E_OK)
    return spec->failure;

  wyrelog_error_t rc = wyl_engine_open_source
      (".decl marker(value: int64)\n"
      ".decl marker_observed(value: int64)\n"
      "marker_observed(V) :- marker(V).\n", 1, out_engine);
  if (rc == WYRELOG_E_OK)
    rc = wyl_engine_insert (*out_engine, "marker", &spec->marker, 1);
  if (rc != WYRELOG_E_OK)
    g_clear_object (out_engine);
  return rc;
}

typedef struct
{
  guint rows;
  gint64 marker;
} MarkerProbe;

static void
marker_tuple (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  MarkerProbe *probe = user_data;
  if (g_strcmp0 (relation, "marker_observed") == 0 && ncols == 1) {
    probe->rows++;
    probe->marker = row[0];
  }
}

static wyrelog_error_t
read_marker (WylEngine *engine, gpointer user_data)
{
  return wyl_engine_snapshot (engine, "marker_observed", marker_tuple,
      user_data);
}

static gint64
snapshot_marker (WylFactGraphSnapshot *snapshot)
{
  MarkerProbe probe = { 0 };
  g_assert_cmpint (wyl_fact_graph_snapshot_use (snapshot, read_marker, &probe),
      ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.rows, ==, 1);
  return probe.marker;
}

typedef struct
{
  WylFactGraphSnapshot **owner;
  gboolean called;
} DropOwnerProbe;

static wyrelog_error_t
drop_owner_while_in_use (WylEngine *engine, gpointer user_data)
{
  DropOwnerProbe *probe = user_data;
  (void) engine;
  probe->called = TRUE;
  g_clear_pointer (probe->owner, wyl_fact_graph_snapshot_unref);
  return WYRELOG_E_OK;
}

static WylFactGraphRuntimeManager *
new_manager (void)
{
  WylFactGraphRuntimeManager *manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  return manager;
}

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  guint count;
} StatusProbe;

static wyrelog_error_t
status_reentrant_cb (const WylFactGraphRuntimeStatus *status,
    gpointer user_data)
{
  StatusProbe *probe = user_data;
  WylFactGraphRuntimeStatus copy = { 0 };
  probe->count++;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (probe->manager,
          &status->key, &copy), ==, WYRELOG_E_OK);
  g_assert_cmpuint (copy.operation_generation, ==,
      status->operation_generation);
  wyl_fact_graph_runtime_status_clear (&copy);
  return WYRELOG_E_OK;
}

static void
test_refresh_snapshot_status_and_evict (void)
{
  WylFactGraphKey a = { 0 }, b = { 0 }, missing = { 0 }, invalid = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&b, "tenant-b", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&missing, "tenant-a", "missing"),
      ==, WYRELOG_E_OK);
  g_assert_false (wyl_fact_graph_key_equal (&a, &b));
  g_assert_cmpint (wyl_fact_graph_key_init (&invalid, "tenant-a",
          "wr.internal"), ==, WYRELOG_E_INVALID);

  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec a1 = {.marker = 11 }, b1 = {.marker = 21 };
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
          build_marker_engine, &a1, &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_cmpuint (status.operation_generation, ==, 1);
  g_assert_cmpuint (status.engine_generation, ==, 1);
  wyl_fact_graph_runtime_status_clear (&status);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &b,
          build_marker_engine, &b1, NULL), ==, WYRELOG_E_OK);

  g_autoptr (WylFactGraphSnapshot) old = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &a, &old), ==, WYRELOG_E_OK);
  BuildSpec a2 = {.marker = 12 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
          build_marker_engine, &a2, &status), ==, WYRELOG_E_OK);
  g_assert_cmpuint (status.operation_generation, ==, 2);
  g_assert_cmpuint (status.engine_generation, ==, 2);
  wyl_fact_graph_runtime_status_clear (&status);
  g_assert_cmpint (snapshot_marker (old), ==, 11);

  g_autoptr (WylFactGraphSnapshot) current = NULL;
  g_autoptr (WylFactGraphSnapshot) other = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &a, &current), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &b, &other), ==, WYRELOG_E_OK);
  g_assert_cmpint (snapshot_marker (current), ==, 12);
  g_assert_cmpint (snapshot_marker (other), ==, 21);
  const WylFactGraphKey *seen[] = { &a };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_retire_unseen (manager,
          seen, G_N_ELEMENTS (seen)), ==, WYRELOG_E_OK);
  g_assert_cmpint (snapshot_marker (other), ==, 21);
  WylFactGraphSnapshot *retired = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &b, &retired), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (retired);

  BuildSpec failed = {.failure = WYRELOG_E_IO };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
          build_marker_engine, &failed, &status), ==, WYRELOG_E_IO);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY_STALE);
  g_assert_cmpint (status.last_replay_class, ==,
      WYL_FACT_GRAPH_REPLAY_STORE_UNAVAILABLE);
  g_assert_cmpuint (status.operation_generation, ==, 3);
  g_assert_cmpuint (status.engine_generation, ==, 2);
  g_assert_true (status.queryable);
  wyl_fact_graph_runtime_status_clear (&status);
  g_assert_cmpint (snapshot_marker (current), ==, 12);

  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &missing,
          build_marker_engine, &failed, &status), ==, WYRELOG_E_IO);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_DEGRADED);
  g_assert_false (status.queryable);
  wyl_fact_graph_runtime_status_clear (&status);
  StatusProbe statuses = { manager, 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_foreach_status (manager,
          status_reentrant_cb, &statuses), ==, WYRELOG_E_OK);
  g_assert_cmpuint (statuses.count, ==, 3);

  gboolean evicted = FALSE;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &a,
          &evicted), ==, WYRELOG_E_BUSY);
  g_clear_pointer (&old, wyl_fact_graph_snapshot_unref);
  g_clear_pointer (&current, wyl_fact_graph_snapshot_unref);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &a,
          &evicted), ==, WYRELOG_E_OK);
  g_assert_true (evicted);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &a,
          &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_EVICTED);
  g_assert_cmpuint (status.operation_generation, ==, 3);
  g_assert_cmpuint (status.engine_generation, ==, 2);
  wyl_fact_graph_runtime_status_clear (&status);
  BuildSpec a3 = {.marker = 13 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
          build_marker_engine, &a3, &status), ==, WYRELOG_E_OK);
  g_assert_cmpuint (status.operation_generation, ==, 4);
  g_assert_cmpuint (status.engine_generation, ==, 3);
  wyl_fact_graph_runtime_status_clear (&status);
  wyl_fact_graph_key_clear (&missing);
  wyl_fact_graph_key_clear (&b);
  wyl_fact_graph_key_clear (&a);
}

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *key;
  BuildSpec *spec;
  wyrelog_error_t result;
  Completion *completion;
} RefreshThread;

static gpointer
refresh_thread (gpointer user_data)
{
  RefreshThread *thread = user_data;
  thread->result = wyl_fact_graph_runtime_manager_refresh (thread->manager,
      thread->key, build_marker_engine, thread->spec, NULL);
  completion_signal (thread->completion);
  return NULL;
}

static void
test_slow_build_is_graph_local (void)
{
  WylFactGraphKey slow = { 0 }, fast = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&slow, "tenant-a", "slow"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&fast, "tenant-b", "fast"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  Gate gate = { 0 };
  gate_init (&gate);
  BuildSpec slow_spec = {.marker = 31,.gate = &gate };
  RefreshThread slow_thread = {
    .manager = manager,
    .key = &slow,
    .spec = &slow_spec,
    .result = WYRELOG_E_INTERNAL,
  };
  GThread *worker = g_thread_new ("slow-build", refresh_thread, &slow_thread);
  gate_wait_entered (&gate);
  gboolean evicted = FALSE;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &slow,
          &evicted), ==, WYRELOG_E_BUSY);
  g_assert_false (evicted);
  BuildSpec fast_spec = {.marker = 41 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &fast,
          build_marker_engine, &fast_spec, NULL), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &fast, &snapshot), ==, WYRELOG_E_OK);
  g_assert_cmpint (snapshot_marker (snapshot), ==, 41);
  gate_release (&gate);
  g_thread_join (worker);
  g_assert_cmpint (slow_thread.result, ==, WYRELOG_E_OK);
  gate_clear (&gate);
  wyl_fact_graph_key_clear (&fast);
  wyl_fact_graph_key_clear (&slow);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean started;
  gboolean entered;
  gboolean released;
} UseGate;

typedef struct
{
  WylFactGraphSnapshot *snapshot;
  UseGate *gate;
  wyrelog_error_t result;
} UseThread;

typedef struct
{
  WylFactGraphSnapshot *snapshot;
  UseGate *gate;
  MarkerProbe probe;
  wyrelog_error_t result;
  Completion *completion;
} QueryThread;

static wyrelog_error_t
gated_read_marker (WylEngine *engine, gpointer user_data)
{
  QueryThread *thread = user_data;
  gint64 deadline = g_get_monotonic_time () + DEADLOCK_CEILING_US;
  g_mutex_lock (&thread->gate->mutex);
  thread->gate->entered = TRUE;
  g_cond_broadcast (&thread->gate->changed);
  while (!thread->gate->released) {
    gboolean signaled = g_cond_wait_until (&thread->gate->changed,
        &thread->gate->mutex, deadline);
    g_assert_true (signaled || thread->gate->released);
  }
  g_mutex_unlock (&thread->gate->mutex);
  return read_marker (engine, &thread->probe);
}

static gpointer
query_thread (gpointer user_data)
{
  QueryThread *thread = user_data;
  thread->result = wyl_fact_graph_snapshot_use (thread->snapshot,
      gated_read_marker, thread);
  completion_signal (thread->completion);
  return NULL;
}

static void
use_gate_wait_entered (UseGate *gate)
{
  gint64 deadline = g_get_monotonic_time () + DEADLOCK_CEILING_US;
  g_mutex_lock (&gate->mutex);
  while (!gate->entered) {
    gboolean signaled = g_cond_wait_until (&gate->changed, &gate->mutex,
        deadline);
    g_assert_true (signaled || gate->entered);
  }
  g_mutex_unlock (&gate->mutex);
}

static void
use_gate_release (UseGate *gate)
{
  g_mutex_lock (&gate->mutex);
  gate->released = TRUE;
  g_cond_broadcast (&gate->changed);
  g_mutex_unlock (&gate->mutex);
}

static wyrelog_error_t
blocking_use (WylEngine *engine, gpointer user_data)
{
  UseGate *gate = user_data;
  (void) engine;
  g_mutex_lock (&gate->mutex);
  gate->entered = TRUE;
  g_cond_broadcast (&gate->changed);
  while (!gate->released)
    g_cond_wait (&gate->changed, &gate->mutex);
  g_mutex_unlock (&gate->mutex);
  return WYRELOG_E_OK;
}

static gpointer
use_thread (gpointer user_data)
{
  UseThread *thread = user_data;
  g_mutex_lock (&thread->gate->mutex);
  thread->gate->started = TRUE;
  g_cond_broadcast (&thread->gate->changed);
  g_mutex_unlock (&thread->gate->mutex);
  thread->result = wyl_fact_graph_snapshot_use (thread->snapshot,
      blocking_use, thread->gate);
  return NULL;
}

typedef struct
{
  WylFactGraphSnapshot *snapshot;
  wyrelog_error_t nested;
} RecursiveUse;

static wyrelog_error_t
recursive_use (WylEngine *engine, gpointer user_data)
{
  RecursiveUse *use = user_data;
  MarkerProbe ignored = { 0 };
  (void) engine;
  use->nested = wyl_fact_graph_snapshot_use (use->snapshot, read_marker,
      &ignored);
  return WYRELOG_E_OK;
}

static void
test_engine_calls_serialize_and_reject_recursion (void)
{
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "serial"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec first = {.marker = 51 }, second = {.marker = 52 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &key,
          build_marker_engine, &first, NULL), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) old = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &key, &old), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &key,
          build_marker_engine, &second, NULL), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) current = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &key, &current), ==, WYRELOG_E_OK);

  UseGate old_gate = { 0 }, new_gate = { 0 };
  g_mutex_init (&old_gate.mutex);
  g_cond_init (&old_gate.changed);
  g_mutex_init (&new_gate.mutex);
  g_cond_init (&new_gate.changed);
  UseThread old_use = { old, &old_gate, WYRELOG_E_INTERNAL };
  UseThread new_use = { current, &new_gate, WYRELOG_E_INTERNAL };
  GThread *ta = g_thread_new ("old-use", use_thread, &old_use);
  g_mutex_lock (&old_gate.mutex);
  while (!old_gate.entered)
    g_cond_wait (&old_gate.changed, &old_gate.mutex);
  g_mutex_unlock (&old_gate.mutex);
  GThread *tb = g_thread_new ("new-use", use_thread, &new_use);
  g_mutex_lock (&new_gate.mutex);
  while (!new_gate.started)
    g_cond_wait (&new_gate.changed, &new_gate.mutex);
  g_mutex_unlock (&new_gate.mutex);
  WylFactGraphRuntimeStatus call_status = { 0 };
  do {
    wyl_fact_graph_runtime_status_clear (&call_status);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &key,
            &call_status), ==, WYRELOG_E_OK);
    if (call_status.waiting_engine_calls == 0)
      g_thread_yield ();
  } while (call_status.waiting_engine_calls == 0);
  g_assert_cmpuint (call_status.active_engine_calls, ==, 1);
  g_assert_false (new_gate.entered);
  wyl_fact_graph_runtime_status_clear (&call_status);
  g_mutex_lock (&old_gate.mutex);
  old_gate.released = TRUE;
  g_cond_broadcast (&old_gate.changed);
  g_mutex_unlock (&old_gate.mutex);
  g_mutex_lock (&new_gate.mutex);
  while (!new_gate.entered)
    g_cond_wait (&new_gate.changed, &new_gate.mutex);
  new_gate.released = TRUE;
  g_cond_broadcast (&new_gate.changed);
  g_mutex_unlock (&new_gate.mutex);
  g_thread_join (ta);
  g_thread_join (tb);
  g_assert_cmpint (old_use.result, ==, WYRELOG_E_OK);
  g_assert_cmpint (new_use.result, ==, WYRELOG_E_OK);
  RecursiveUse recursive = { current, WYRELOG_E_OK };
  g_assert_cmpint (wyl_fact_graph_snapshot_use (current, recursive_use,
          &recursive), ==, WYRELOG_E_OK);
  g_assert_cmpint (recursive.nested, ==, WYRELOG_E_INVALID);
  g_cond_clear (&new_gate.changed);
  g_mutex_clear (&new_gate.mutex);
  g_cond_clear (&old_gate.changed);
  g_mutex_clear (&old_gate.mutex);
  wyl_fact_graph_key_clear (&key);
}

static void
test_shutdown_keeps_pinned_snapshot_alive (void)
{
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "shutdown"), ==,
      WYRELOG_E_OK);
  WylFactGraphRuntimeManager *manager = new_manager ();
  BuildSpec spec = {.marker = 61 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &key,
          build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);
  WylFactGraphSnapshot *dropped = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &key, &dropped), ==, WYRELOG_E_OK);
  Gate gate = { 0 };
  gate_init (&gate);
  BuildSpec replacement = {.marker = 62,.gate = &gate };
  RefreshThread thread = {
    .manager = manager,
    .key = &key,
    .spec = &replacement,
    .result = WYRELOG_E_INTERNAL,
  };
  GThread *builder = g_thread_new ("shutdown-build", refresh_thread, &thread);
  gate_wait_entered (&gate);
  wyl_fact_graph_runtime_manager_shutdown (manager);
  g_assert_cmpint (snapshot_marker (dropped), ==, 61);
  gate_release (&gate);
  g_thread_join (builder);
  g_assert_cmpint (thread.result, ==, WYRELOG_E_BUSY);
  gate_clear (&gate);
  WylFactGraphSnapshot *after_shutdown = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          &key, &after_shutdown), ==, WYRELOG_E_BUSY);
  g_assert_null (after_shutdown);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &key,
          build_marker_engine, &spec, NULL), ==, WYRELOG_E_BUSY);
  wyl_fact_graph_runtime_manager_unref (manager);
  DropOwnerProbe drop = {.owner = &dropped };
  g_assert_cmpint (wyl_fact_graph_snapshot_use (dropped,
          drop_owner_while_in_use, &drop), ==, WYRELOG_E_OK);
  g_assert_true (drop.called);
  g_assert_null (dropped);
  wyl_fact_graph_key_clear (&key);
}

static void
test_bounded_query_swap_evict_stress (void)
{
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-stress", "graph"),
      ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec initial = {.marker = 1000 };
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &key,
          build_marker_engine, &initial, &status), ==, WYRELOG_E_OK);
  guint64 operation_generation = 1;
  guint64 engine_generation = 1;
  gint64 published_marker = initial.marker;
  wyl_fact_graph_runtime_status_clear (&status);

  for (guint iteration = 0; iteration < 16; iteration++) {
    g_autoptr (WylFactGraphSnapshot) old = NULL;
    g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
            &key, &old), ==, WYRELOG_E_OK);
    g_assert_cmpuint (wyl_fact_graph_snapshot_engine_generation (old), ==,
        engine_generation);
    g_assert_cmpint (snapshot_marker (old), ==, published_marker);

    UseGate query_gate = { 0 };
    g_mutex_init (&query_gate.mutex);
    g_cond_init (&query_gate.changed);
    Completion query_completion = { 0 };
    completion_init (&query_completion);
    QueryThread query = {
      old, &query_gate, {0}, WYRELOG_E_INTERNAL, &query_completion
    };
    GThread *query_worker = g_thread_new ("stress-query", query_thread,
        &query);
    use_gate_wait_entered (&query_gate);

    Gate build_gate = { 0 };
    gate_init (&build_gate);
    Completion build_completion = { 0 };
    completion_init (&build_completion);
    BuildSpec swap = {
      .marker = 2000 + (gint64) iteration * 2,
      .gate = &build_gate,
    };
    RefreshThread swap_thread = { manager, &key, &swap, WYRELOG_E_INTERNAL,
      &build_completion
    };
    GThread *builder = g_thread_new ("stress-swap", refresh_thread,
        &swap_thread);
    gate_wait_entered (&build_gate);

    g_autoptr (WylFactGraphSnapshot) during_build = NULL;
    g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
            &key, &during_build), ==, WYRELOG_E_OK);
    g_assert_cmpuint (wyl_fact_graph_snapshot_engine_generation (during_build),
        ==, engine_generation);
    gboolean evicted = FALSE;
    g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &key,
            &evicted), ==, WYRELOG_E_BUSY);
    g_assert_false (evicted);

    gate_release (&build_gate);
    completion_wait (&build_completion);
    g_thread_join (builder);
    completion_clear (&build_completion);
    gate_clear (&build_gate);
    g_assert_cmpint (swap_thread.result, ==, WYRELOG_E_OK);
    operation_generation++;
    engine_generation++;

    g_autoptr (WylFactGraphSnapshot) current = NULL;
    g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
            &key, &current), ==, WYRELOG_E_OK);
    g_assert_cmpuint (wyl_fact_graph_snapshot_engine_generation (current), ==,
        engine_generation);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &key,
            &evicted), ==, WYRELOG_E_BUSY);
    g_assert_false (evicted);

    use_gate_release (&query_gate);
    completion_wait (&query_completion);
    g_thread_join (query_worker);
    g_assert_cmpint (query.result, ==, WYRELOG_E_OK);
    g_assert_cmpuint (query.probe.rows, ==, 1);
    g_assert_cmpint (query.probe.marker, ==, published_marker);
    completion_clear (&query_completion);
    g_cond_clear (&query_gate.changed);
    g_mutex_clear (&query_gate.mutex);

    g_assert_cmpint (snapshot_marker (current), ==, swap.marker);
    g_assert_cmpint (snapshot_marker (during_build), ==, published_marker);

    g_clear_pointer (&current, wyl_fact_graph_snapshot_unref);
    g_clear_pointer (&during_build, wyl_fact_graph_snapshot_unref);
    g_clear_pointer (&old, wyl_fact_graph_snapshot_unref);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &key,
            &evicted), ==, WYRELOG_E_OK);
    g_assert_true (evicted);
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &key,
            &status), ==, WYRELOG_E_OK);
    g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_EVICTED);
    g_assert_cmpuint (status.operation_generation, ==, operation_generation);
    g_assert_cmpuint (status.engine_generation, ==, engine_generation);
    wyl_fact_graph_runtime_status_clear (&status);

    BuildSpec republish = {
      .marker = swap.marker + 1,
    };
    g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &key,
            build_marker_engine, &republish, &status), ==, WYRELOG_E_OK);
    operation_generation++;
    engine_generation++;
    g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
    g_assert_cmpuint (status.operation_generation, ==, operation_generation);
    g_assert_cmpuint (status.engine_generation, ==, engine_generation);
    wyl_fact_graph_runtime_status_clear (&status);
    g_autoptr (WylFactGraphSnapshot) republished = NULL;
    g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
            &key, &republished), ==, WYRELOG_E_OK);
    g_assert_cmpuint (wyl_fact_graph_snapshot_engine_generation (republished),
        ==, engine_generation);
    g_assert_cmpint (snapshot_marker (republished), ==, republish.marker);
    published_marker = republish.marker;
  }
  wyl_fact_graph_key_clear (&key);
}

static void
assert_generation_and_marker (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, guint64 operation_generation,
    guint64 engine_generation, gint64 marker)
{
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, key,
          &status), ==, WYRELOG_E_OK);
  g_assert_cmpuint (status.operation_generation, ==, operation_generation);
  g_assert_cmpuint (status.engine_generation, ==, engine_generation);
  wyl_fact_graph_runtime_status_clear (&status);
  g_autoptr (WylFactGraphSnapshot) snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
          key, &snapshot), ==, WYRELOG_E_OK);
  g_assert_cmpint (snapshot_marker (snapshot), ==, marker);
}

static void
test_two_tenant_two_graph_generation_isolation (void)
{
  WylFactGraphKey keys[4] = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&keys[0], "tenant-a", "graph-a"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&keys[1], "tenant-a", "graph-b"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&keys[2], "tenant-b", "graph-a"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&keys[3], "tenant-b", "graph-b"),
      ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec initial[4] = {
    {.marker = 101}, {.marker = 102},
    {.marker = 201}, {.marker = 202},
  };
  guint64 operation_generations[4] = { 1, 1, 1, 1 };
  guint64 engine_generations[4] = { 1, 1, 1, 1 };
  gint64 markers[4] = { 101, 102, 201, 202 };
  for (guint i = 0; i < G_N_ELEMENTS (keys); i++) {
    g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &keys[i],
            build_marker_engine, &initial[i], NULL), ==, WYRELOG_E_OK);
  }

  for (guint target = 0; target < G_N_ELEMENTS (keys); target++) {
    BuildSpec replacement = {
      .marker = initial[target].marker + 1000,
    };
    g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager,
            &keys[target], build_marker_engine, &replacement, NULL), ==,
        WYRELOG_E_OK);
    operation_generations[target]++;
    engine_generations[target]++;
    markers[target] = replacement.marker;
    for (guint observed = 0; observed < G_N_ELEMENTS (keys); observed++)
      assert_generation_and_marker (manager, &keys[observed],
          operation_generations[observed], engine_generations[observed],
          markers[observed]);
  }

  for (guint i = 0; i < G_N_ELEMENTS (keys); i++)
    wyl_fact_graph_key_clear (&keys[i]);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-runtime/refresh-snapshot-status-evict",
      test_refresh_snapshot_status_and_evict);
  g_test_add_func ("/fact-runtime/slow-build-graph-local",
      test_slow_build_is_graph_local);
  g_test_add_func ("/fact-runtime/engine-call-serialization",
      test_engine_calls_serialize_and_reject_recursion);
  g_test_add_func ("/fact-runtime/shutdown-pinned-lifetime",
      test_shutdown_keeps_pinned_snapshot_alive);
  g_test_add_func ("/fact-runtime/bounded-query-swap-evict-stress",
      test_bounded_query_swap_evict_stress);
  g_test_add_func ("/fact-runtime/two-tenant-two-graph-isolation",
      test_two_tenant_two_graph_generation_isolation);
  return g_test_run ();
}

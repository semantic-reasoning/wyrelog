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

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *key;
  BuildSpec *spec;
  wyrelog_error_t result;
  WylFactGraphRuntimeStatus status;
} StatusRefreshThread;

static gpointer
status_refresh_thread (gpointer user_data)
{
  StatusRefreshThread *thread = user_data;
  thread->result = wyl_fact_graph_runtime_manager_refresh (thread->manager,
          thread->key, build_marker_engine, thread->spec, &thread->status);
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
                                  &build_completion};
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
/* Issue #870: the per-graph forget-reconcile axis on the runtime entry.
 *
 * Seven properties, each of which a plausible implementation gets wrong in a
 * different way:
 *   1. a successful refresh must NOT clear it -- the axis is orthogonal to
 *      replay health, and an implementation that recomputes it from
 *      last_replay_class or resets it on READY would pass every other test;
 *   2. the setter is total, not a latch -- writing CONVERGED after INCOMPLETE
 *      must clear, so a later boot that converges self-heals;
 *   3. it must be visible through foreach_status as well as get_status --
 *      status_fill_locked is the single fill point feeding both, and omitting
 *      the field there is the likeliest silent bug in this unit;
 *   4. the setter must not mint an entry -- create=FALSE, so an unknown key is
 *      NOT_FOUND rather than a silently created entry reported OK;
 *   5. a FAILED refresh must not clear it either -- the orthogonality claim is
 *      unconditional, and a success-only test proves the easy half while
 *      leaving this issue's own bug shape uncovered: a transient store error
 *      erasing an outstanding-erasure signal so the graph reports ready;
 *   6. it is per-graph, not per-manager -- an implementation holding the axis
 *      on the manager would satisfy every property above;
 *   7. tombstoning both clears it and refuses later writes, which cover
 *      disjoint orderings -- the reset handles a verdict written before the
 *      tombstone, the refusal one arriving after, and try_evict and
 *      retire_unseen each need their own case because a fix to one leaves the
 *      other unproven.
 */
typedef struct
{
  const WylFactGraphKey *want;
  WylFactGraphForgetState seen;
  guint matched;
} ForgetStateProbe;

static wyrelog_error_t
forget_state_cb (const WylFactGraphRuntimeStatus *status, gpointer user_data)
{
  ForgetStateProbe *probe = user_data;
  if (wyl_fact_graph_key_equal (&status->key, probe->want)) {
    probe->matched++;
    probe->seen = status->forget_state;
  }
  return WYRELOG_E_OK;
}

static WylFactGraphForgetState
forget_state_via_foreach (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key)
{
  ForgetStateProbe probe = { key, WYL_FACT_GRAPH_FORGET_CONVERGED, 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_foreach_status (manager,
      forget_state_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.matched, ==, 1);
  return probe.seen;
}

static WylFactGraphForgetState
forget_state_via_get (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key)
{
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, key,
      &status), ==, WYRELOG_E_OK);
  WylFactGraphForgetState state = status.forget_state;
  wyl_fact_graph_runtime_status_clear (&status);
  return state;
}

static WylFactGraphAdmission
admission_via_get (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key)
{
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, key,
      &status), ==, WYRELOG_E_OK);
  WylFactGraphAdmission admission = status.admission;
  wyl_fact_graph_runtime_status_clear (&status);
  return admission;
}

/* Closing admission denies new work on exactly one graph, leaves every other
 * axis alone, and is reversible. */
static void
test_admission_denies_new_work (void)
{
  WylFactGraphKey a = { 0 }, b = { 0 }, absent = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&b, "tenant-b", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&absent, "tenant-a", "absent"),
      ==, WYRELOG_E_OK);

  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec_a = {.marker = 11 };
  BuildSpec spec_b = {.marker = 12 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec_a, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &b,
      build_marker_engine, &spec_b, NULL), ==, WYRELOG_E_OK);

  /* A graph nothing has closed admits. */
  g_assert_cmpint (admission_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_ADMISSION_OPEN);

  /* Neither setter mints an entry. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &absent), ==, WYRELOG_E_NOT_FOUND);
  WylFactGraphRuntimeStatus absent_status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager,
      &absent, &absent_status), ==, WYRELOG_E_NOT_FOUND);

  WylFactGraphRuntimeStatus before = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &a,
      &before), ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);
  g_assert_cmpint (admission_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);

  /* Refused, and the refusal is distinguishable from shutdown: BUSY with a
   * filled status naming a CLOSED graph, where shutdown clears it. */
  BuildSpec denied = {.marker = 13 };
  WylFactGraphRuntimeStatus refused = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &denied, &refused), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (refused.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  g_assert_cmpstr (refused.key.graph_id, ==, "orders");
  wyl_fact_graph_runtime_status_clear (&refused);

  WylFactGraphSnapshot *denied_snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &denied_snapshot), ==, WYRELOG_E_BUSY);
  g_assert_null (denied_snapshot);

  /* The refusal consumed no generation and disturbed no other axis. */
  WylFactGraphRuntimeStatus after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &a,
      &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (after.operation_generation, ==,
      before.operation_generation);
  g_assert_cmpuint (after.engine_generation, ==, before.engine_generation);
  g_assert_cmpint (after.state, ==, before.state);
  g_assert_cmpint (after.last_replay_class, ==, before.last_replay_class);
  g_assert_cmpint (after.forget_state, ==, before.forget_state);
  g_assert_true (after.queryable);
  wyl_fact_graph_runtime_status_clear (&after);

  /* One graph only.  A barrier that closed the manager would pass every
   * assertion above. */
  BuildSpec other = {.marker = 14 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &b,
      build_marker_engine, &other, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (admission_via_get (manager, &b), ==,
      WYL_FACT_GRAPH_ADMISSION_OPEN);

  /* Reversible, and the graph resumes from where it left off. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission (manager,
      &a), ==, WYRELOG_E_OK);
  BuildSpec resumed = {.marker = 15 };
  WylFactGraphRuntimeStatus reopened = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &resumed, &reopened), ==, WYRELOG_E_OK);
  g_assert_cmpuint (reopened.operation_generation, ==,
      before.operation_generation + 1);
  g_assert_cmpuint (reopened.engine_generation, ==,
      before.engine_generation + 1);
  wyl_fact_graph_runtime_status_clear (&reopened);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &snapshot), ==, WYRELOG_E_OK);
  wyl_fact_graph_snapshot_unref (snapshot);

  wyl_fact_graph_runtime_status_clear (&before);
  wyl_fact_graph_key_clear (&a);
  wyl_fact_graph_key_clear (&b);
  wyl_fact_graph_key_clear (&absent);
}

/* Repeating either transition is a no-op, and retirement does not reopen a
 * closed graph -- which it would if admission lived in the state enum. */
static void
test_admission_is_idempotent_and_survives_retirement (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);

  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 21 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);

  WylFactGraphRuntimeStatus before = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &a,
      &before), ==, WYRELOG_E_OK);

  for (int i = 0; i < 3; i++) {
    g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
        &a), ==, WYRELOG_E_OK);
  }
  g_assert_cmpint (admission_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);

  /* Eviction is exempt: a caller that closed admission in order to evict must
   * not have locked itself out. */
  gboolean evicted = FALSE;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &a,
      &evicted), ==, WYRELOG_E_OK);
  g_assert_true (evicted);

  /* The tombstone is still closed, and a refresh that would republish it is
   * still refused. */
  g_assert_cmpint (admission_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  BuildSpec republish = {.marker = 22 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &republish, NULL), ==, WYRELOG_E_BUSY);

  /* Retirement likewise leaves the axis alone. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_retire_unseen (manager,
      NULL, 0), ==, WYRELOG_E_OK);
  g_assert_cmpint (admission_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);

  for (int i = 0; i < 2; i++) {
    g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission (manager,
        &a), ==, WYRELOG_E_OK);
  }
  g_assert_cmpint (admission_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_ADMISSION_OPEN);

  /* Counters resume, proving the whole cycle consumed none of them. */
  BuildSpec resumed = {.marker = 23 };
  WylFactGraphRuntimeStatus after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &resumed, &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (after.operation_generation, ==,
      before.operation_generation + 1);
  g_assert_cmpuint (after.engine_generation, ==, before.engine_generation + 1);
  wyl_fact_graph_runtime_status_clear (&after);
  wyl_fact_graph_runtime_status_clear (&before);
  wyl_fact_graph_key_clear (&a);
}

/* Closing admission mid-build is prompt and does not disturb the build: the
 * admitted refresh runs to completion and publishes, and a snapshot pinned
 * before the close stays usable.  Without this the barrier could be
 * implemented by taking writer_lock (which would block for the whole build)
 * or by discarding the build result (which would not stop the builder, still
 * inside the store holding its handles) and nothing would notice. */
static void
test_admission_close_does_not_disturb_admitted_work (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();

  /* Publish once so there is a snapshot to pin across the close. */
  BuildSpec first = {.marker = 51 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &first, NULL), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) pinned = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &pinned), ==, WYRELOG_E_OK);

  Gate gate = { 0 };
  gate_init (&gate);
  BuildSpec slow = {.marker = 52,.gate = &gate };
  RefreshThread worker_spec = {
    .manager = manager,
    .key = &a,
    .spec = &slow,
    .result = WYRELOG_E_INTERNAL,
  };
  Completion done = { 0 };
  completion_init (&done);
  worker_spec.completion = &done;
  GThread *worker = g_thread_new ("admitted-build", refresh_thread,
          &worker_spec);
  gate_wait_entered (&gate);

  /* Prompt: this returns while the build still owns writer_lock.  Taking
   * writer_lock here would hang until gate_release below. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);

  /* The already-pinned snapshot is unaffected -- admission gates admission,
   * not possession. */
  g_assert_cmpint (snapshot_marker (pinned), ==, 51);

  gate_release (&gate);
  g_thread_join (worker);

  /* The admitted build published rather than being discarded. */
  g_assert_cmpint (worker_spec.result, ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &a,
      &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  g_assert_cmpuint (status.engine_generation, ==, 2);
  wyl_fact_graph_runtime_status_clear (&status);

  /* But the next one is refused, so the barrier really did close. */
  BuildSpec after = {.marker = 53 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &after, NULL), ==, WYRELOG_E_BUSY);

  completion_clear (&done);
  gate_clear (&gate);
  wyl_fact_graph_key_clear (&a);
}

/* The barrier outranks NOT_FOUND, and both setters refuse a shut-down
 * manager. */
static void
test_admission_precedence_and_shutdown (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 61 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);

  /* A closed tombstone has no published engine, so this is the case where
   * admission and NOT_FOUND disagree.  BUSY wins: a closed graph will not be
   * rebuilt either, and NOT_FOUND would invite a refresh that is refused. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);
  gboolean evicted = FALSE;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &a,
      &evicted), ==, WYRELOG_E_OK);
  g_assert_true (evicted);
  WylFactGraphSnapshot *none = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &none), ==, WYRELOG_E_BUSY);
  g_assert_null (none);

  /* Reopening the tombstone restores NOT_FOUND, which is what proves the
   * BUSY above came from admission and not from the eviction. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission (manager,
      &a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &none), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (none);

  /* Shutdown refuses both setters.  This BUSY comes from the lookup, which
   * refuses a shut-down manager before set_admission runs -- not from the
   * abandoned guard inside it, which covers only the window between the
   * lookup releasing map_lock and the write taking state_lock and is
   * unreachable from one thread. */
  wyl_fact_graph_runtime_manager_shutdown (manager);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission (manager,
      &a), ==, WYRELOG_E_BUSY);
  wyl_fact_graph_key_clear (&a);
}

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *key;
  wyrelog_error_t drain_rc;
  Gate *gate;
  gint64 marker;
} DrainFromBuild;

static wyrelog_error_t
build_then_drain_own_key (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  DrainFromBuild *probe = user_data;
  /* Announce that the build is in flight and wait until the main thread has
   * closed admission.  The drain must run against a CLOSED graph, or it is
   * refused for being open and the self-wait guard is never reached -- which
   * is exactly how an earlier version of this test passed while proving
   * nothing. */
  g_mutex_lock (&probe->gate->mutex);
  probe->gate->entered = TRUE;
  g_cond_broadcast (&probe->gate->changed);
  while (!probe->gate->released)
    g_cond_wait (&probe->gate->changed, &probe->gate->mutex);
  g_mutex_unlock (&probe->gate->mutex);

  /* Draining this entry now would wait on operation_active, which this very
   * frame set and only this frame will clear.  Refused, not parked. */
  probe->drain_rc = wyl_fact_graph_runtime_manager_drain (probe->manager,
          probe->key, -1, NULL);
  BuildSpec spec = {.marker = probe->marker };
  return build_marker_engine (key, out_engine, &spec);
}

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *key;
  DrainFromBuild *probe;
  wyrelog_error_t result;
} ProbeRefreshThread;

static gpointer
probe_refresh_thread (gpointer user_data)
{
  ProbeRefreshThread *thread = user_data;
  thread->result = wyl_fact_graph_runtime_manager_refresh (thread->manager,
          thread->key, build_then_drain_own_key, thread->probe, NULL);
  return NULL;
}

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *same;
  const WylFactGraphKey *other;
  wyrelog_error_t same_entry;
  wyrelog_error_t other_entry;
} DrainFromCallback;

static wyrelog_error_t
drain_from_engine_callback (WylEngine *engine, gpointer user_data)
{
  DrainFromCallback *probe = user_data;
  (void) engine;
  /* Draining this entry from inside its own engine callback would wait for
   * active_engine_calls to reach zero while being one of them.  Refused, not
   * answered slowly. */
  probe->same_entry = wyl_fact_graph_runtime_manager_drain (probe->manager,
          probe->same, -1, NULL);
  /* A different entry is not this thread's problem and stays legal, as the
   * status readers already are. */
  probe->other_entry = wyl_fact_graph_runtime_manager_drain (probe->manager,
          probe->other, 0, NULL);
  return WYRELOG_E_OK;
}

static gboolean
completion_peek (Completion *completion)
{
  g_mutex_lock (&completion->mutex);
  gboolean done = completion->completed;
  g_mutex_unlock (&completion->mutex);
  return done;
}

static void
wait_for_queued_engine_call (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key)
{
  gint64 ceiling = g_get_monotonic_time () + DEADLOCK_CEILING_US;
  for (;;) {
    WylFactGraphRuntimeStatus status = { 0 };
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, key,
        &status), ==, WYRELOG_E_OK);
    guint queued = status.waiting_engine_calls;
    wyl_fact_graph_runtime_status_clear (&status);
    if (queued > 0)
      return;
    g_assert_cmpint (g_get_monotonic_time (), <, ceiling);
    g_usleep (1000);
  }
}

static void
wait_for_parked_drain (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key)
{
  /* Spawning a drain thread does not mean it has reached the wait.  Without
   * this the gate could be released first, the drain would find the entry
   * already quiet, and the test would pass without ever exercising the
   * broadcast it exists to prove. */
  gint64 ceiling = g_get_monotonic_time () + DEADLOCK_CEILING_US;
  for (;;) {
    WylFactGraphRuntimeStatus status = { 0 };
    g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, key,
        &status), ==, WYRELOG_E_OK);
    guint parked = status.waiting_drains;
    wyl_fact_graph_runtime_status_clear (&status);
    if (parked > 0)
      return;
    g_assert_cmpint (g_get_monotonic_time (), <, ceiling);
    g_usleep (1000);
  }
}

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *key;
  gint64 timeout_us;
  wyrelog_error_t result;
  Completion *completion;
} DrainThread;

static gpointer
drain_thread (gpointer user_data)
{
  DrainThread *thread = user_data;
  thread->result = wyl_fact_graph_runtime_manager_drain (thread->manager,
          thread->key, thread->timeout_us, NULL);
  completion_signal (thread->completion);
  return NULL;
}

/* A drain waits out an admitted engine call and does not wait on a snapshot
 * that is merely pinned.  The distinction is the whole design: admitted work
 * is bounded by callbacks that must return, while a pinned snapshot may be
 * held forever, so draining on it could never terminate. */
static void
test_drain_waits_for_admitted_engine_call (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 71 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);

  g_autoptr (WylFactGraphSnapshot) busy = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &busy), ==, WYRELOG_E_OK);
  /* A second snapshot that nobody uses.  It must not hold the drain open. */
  g_autoptr (WylFactGraphSnapshot) idle = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &idle), ==, WYRELOG_E_OK);

  UseGate use_gate = { 0 };
  g_mutex_init (&use_gate.mutex);
  g_cond_init (&use_gate.changed);
  UseThread user = {.snapshot = busy,.gate = &use_gate,
                    .result = WYRELOG_E_INTERNAL };
  GThread *worker = g_thread_new ("engine-call", use_thread, &user);
  use_gate_wait_entered (&use_gate);

  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);

  /* Polling says not drained, and names what is outstanding. */
  WylFactGraphRuntimeStatus polled = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_drain (manager, &a, 0,
      &polled), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (polled.active_engine_calls, ==, 1);
  g_assert_cmpuint (polled.active_snapshots, ==, 2);
  wyl_fact_graph_runtime_status_clear (&polled);

  /* A short deadline expires while the call is still inside its callback,
   * and the status names what is still running.  That promise is the reason
   * the timeout answers from the predicate rather than from the wait's
   * return value. */
  WylFactGraphRuntimeStatus expired = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_drain (manager, &a,
      50 * 1000, &expired), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (expired.active_engine_calls, ==, 1);
  wyl_fact_graph_runtime_status_clear (&expired);

  Completion drained = { 0 };
  completion_init (&drained);
  DrainThread blocker = {.manager = manager,.key = &a,.timeout_us = -1,
                         .result = WYRELOG_E_INTERNAL,
                         .completion = &drained };
  GThread *drainer = g_thread_new ("drain", drain_thread, &blocker);
  wait_for_parked_drain (manager, &a);
  use_gate_release (&use_gate);
  g_thread_join (worker);
  completion_wait (&drained);
  g_thread_join (drainer);

  g_assert_cmpint (user.result, ==, WYRELOG_E_OK);
  /* Drained even though two snapshots are still pinned. */
  g_assert_cmpint (blocker.result, ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &a,
      &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (after.active_snapshots, ==, 2);
  g_assert_cmpuint (after.active_engine_calls, ==, 0);
  wyl_fact_graph_runtime_status_clear (&after);

  completion_clear (&drained);
  g_cond_clear (&use_gate.changed);
  g_mutex_clear (&use_gate.mutex);
  wyl_fact_graph_key_clear (&a);
}

/* Draining an open graph is refused rather than answered, a blocked drain
 * wakes on shutdown instead of running to its deadline, and a drain issued
 * from inside the entry's own engine callback is refused rather than
 * self-deadlocking. */
static void
test_drain_refusals_and_shutdown_wake (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 81 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);

  /* Open: refused, because new work could be admitted while we waited. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_drain (manager, &a, -1,
      NULL), ==, WYRELOG_E_INVALID);

  g_autoptr (WylFactGraphSnapshot) snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &snapshot), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);

  /* Nothing admitted is outstanding, so this returns at once. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_drain (manager, &a, -1,
      NULL), ==, WYRELOG_E_OK);

  UseGate use_gate = { 0 };
  g_mutex_init (&use_gate.mutex);
  g_cond_init (&use_gate.changed);
  UseThread user = {.snapshot = snapshot,.gate = &use_gate,
                    .result = WYRELOG_E_INTERNAL };
  GThread *worker = g_thread_new ("engine-call", use_thread, &user);
  use_gate_wait_entered (&use_gate);

  Completion woke = { 0 };
  completion_init (&woke);
  DrainThread blocker = {.manager = manager,.key = &a,.timeout_us = -1,
                         .result = WYRELOG_E_INTERNAL,.completion = &woke };
  GThread *drainer = g_thread_new ("drain", drain_thread, &blocker);
  wait_for_parked_drain (manager, &a);

  /* An indefinite drain is blocked on the gated call.  Shutdown must wake it
   * rather than leaving it parked, which is the reason shutdown broadcasts. */
  wyl_fact_graph_runtime_manager_shutdown (manager);
  completion_wait (&woke);
  g_thread_join (drainer);
  g_assert_cmpint (blocker.result, ==, WYRELOG_E_BUSY);

  use_gate_release (&use_gate);
  g_thread_join (worker);
  completion_clear (&woke);
  g_cond_clear (&use_gate.changed);
  g_mutex_clear (&use_gate.mutex);
  wyl_fact_graph_key_clear (&a);
}

/* The self-wait refusal.  Without it this test does not fail -- it hangs,
 * which is the point: the guard turns a deadlock into an error. */
static void
test_drain_refuses_its_own_engine_callback (void)
{
  WylFactGraphKey a = { 0 }, b = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&b, "tenant-b", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec_a = {.marker = 91 };
  BuildSpec spec_b = {.marker = 92 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec_a, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &b,
      build_marker_engine, &spec_b, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &b), ==, WYRELOG_E_OK);

  g_autoptr (WylFactGraphSnapshot) snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &snapshot), ==, WYRELOG_E_BUSY);
  g_assert_null (snapshot);

  /* Reopen just long enough to take the pin, then close again: the callback
   * must run on a closed graph for the refusal to be the thing under test. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission (manager,
      &a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &snapshot), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);

  DrainFromCallback probe = { manager, &a, &b, WYRELOG_E_INTERNAL,
                              WYRELOG_E_INTERNAL };
  g_assert_cmpint (wyl_fact_graph_snapshot_use (snapshot,
      drain_from_engine_callback, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpint (probe.same_entry, ==, WYRELOG_E_INVALID);
  g_assert_cmpint (probe.other_entry, ==, WYRELOG_E_OK);

  wyl_fact_graph_key_clear (&a);
  wyl_fact_graph_key_clear (&b);
}

/* The drain's other term.  Every test above drives engine calls; this one
 * drives a build, which is the counter the primitive exists for -- a seal
 * that returned while a builder was still inside the store would assert its
 * postcondition falsely. */
static void
test_drain_waits_for_admitted_build (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec first = {.marker = 101 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &first, NULL), ==, WYRELOG_E_OK);

  Gate gate = { 0 };
  gate_init (&gate);
  BuildSpec slow = {.marker = 102,.gate = &gate };
  RefreshThread builder = {
    .manager = manager,
    .key = &a,
    .spec = &slow,
    .result = WYRELOG_E_INTERNAL,
  };
  GThread *worker = g_thread_new ("admitted-build", refresh_thread, &builder);
  gate_wait_entered (&gate);

  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);

  /* Polling names the build as what is outstanding. */
  WylFactGraphRuntimeStatus polled = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_drain (manager, &a, 0,
      &polled), ==, WYRELOG_E_BUSY);
  g_assert_true (polled.operation_active);
  g_assert_cmpuint (polled.active_engine_calls, ==, 0);
  wyl_fact_graph_runtime_status_clear (&polled);

  Completion drained = { 0 };
  completion_init (&drained);
  DrainThread blocker = {.manager = manager,.key = &a,.timeout_us = -1,
                         .result = WYRELOG_E_INTERNAL,
                         .completion = &drained };
  GThread *drainer = g_thread_new ("drain", drain_thread, &blocker);
  wait_for_parked_drain (manager, &a);

  gate_release (&gate);
  g_thread_join (worker);
  completion_wait (&drained);
  g_thread_join (drainer);

  g_assert_cmpint (builder.result, ==, WYRELOG_E_OK);
  g_assert_cmpint (blocker.result, ==, WYRELOG_E_OK);
  /* The drain returned only after the build published. */
  WylFactGraphRuntimeStatus after = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &a,
      &after), ==, WYRELOG_E_OK);
  g_assert_false (after.operation_active);
  g_assert_cmpuint (after.engine_generation, ==, 2);
  wyl_fact_graph_runtime_status_clear (&after);

  completion_clear (&drained);
  gate_clear (&gate);
  wyl_fact_graph_key_clear (&a);
}

/* A drain issued from inside the entry's own build callback is refused, not
 * parked.  Nothing else could clear the term it would wait on. */
static void
test_drain_refuses_its_own_build_callback (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec seed = {.marker = 111 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &seed, NULL), ==, WYRELOG_E_OK);
  Gate gate = { 0 };
  gate_init (&gate);
  DrainFromBuild probe = { manager, &a, WYRELOG_E_INTERNAL, &gate, 112 };
  ProbeRefreshThread builder = { manager, &a, &probe, WYRELOG_E_INTERNAL };
  GThread *worker = g_thread_new ("probe-build", probe_refresh_thread,
          &builder);
  gate_wait_entered (&gate);
  /* Close while the build owns the entry, so the drain inside it meets a
   * closed graph and must be refused by the self-wait guard rather than by
   * the open-graph check. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);
  gate_release (&gate);
  g_thread_join (worker);

  g_assert_cmpint (builder.result, ==, WYRELOG_E_OK);
  /* INVALID for the self-wait, not BUSY from a timeout and not a hang. */
  g_assert_cmpint (probe.drain_rc, ==, WYRELOG_E_INVALID);
  gate_clear (&gate);
  wyl_fact_graph_key_clear (&a);
}

/* The queued term.  A thread blocked on engine_call_lock has already passed
 * the admission check and will run, so the drain must wait for it too.  That
 * state -- no active call, one queued -- exists only in the instant between
 * one caller leaving the lock and the next taking it, so it cannot be
 * observed directly.  Gating the SECOND callback makes the claim testable:
 * with the term present the drain is still parked while that call runs, and
 * without it the drain has already returned. */
static void
drain_waits_for_queued_engine_call_once (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 121 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);

  g_autoptr (WylFactGraphSnapshot) first = NULL;
  g_autoptr (WylFactGraphSnapshot) second = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &second), ==, WYRELOG_E_OK);

  UseGate gate_one = { 0 }, gate_two = { 0 };
  g_mutex_init (&gate_one.mutex);
  g_cond_init (&gate_one.changed);
  g_mutex_init (&gate_two.mutex);
  g_cond_init (&gate_two.changed);
  UseThread running = {.snapshot = first,.gate = &gate_one,
                       .result = WYRELOG_E_INTERNAL };
  GThread *worker_one = g_thread_new ("engine-one", use_thread, &running);
  use_gate_wait_entered (&gate_one);

  UseThread queued = {.snapshot = second,.gate = &gate_two,
                      .result = WYRELOG_E_INTERNAL };
  GThread *worker_two = g_thread_new ("engine-two", use_thread, &queued);
  wait_for_queued_engine_call (manager, &a);

  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);
  Completion drained = { 0 };
  completion_init (&drained);
  DrainThread blocker = {.manager = manager,.key = &a,.timeout_us = -1,
                         .result = WYRELOG_E_INTERNAL,
                         .completion = &drained };
  GThread *drainer = g_thread_new ("drain", drain_thread, &blocker);
  wait_for_parked_drain (manager, &a);

  /* Let the first call finish.  The second now owns engine_call_lock and is
   * inside its callback. */
  use_gate_release (&gate_one);
  g_thread_join (worker_one);
  g_assert_cmpint (running.result, ==, WYRELOG_E_OK);
  use_gate_wait_entered (&gate_two);

  /* The discriminating assertion: the queued call was admitted before the
   * close, so the drain must still be waiting for it. */
  g_assert_false (completion_peek (&drained));

  use_gate_release (&gate_two);
  g_thread_join (worker_two);
  completion_wait (&drained);
  g_thread_join (drainer);
  g_assert_cmpint (queued.result, ==, WYRELOG_E_OK);
  g_assert_cmpint (blocker.result, ==, WYRELOG_E_OK);

  completion_clear (&drained);
  g_cond_clear (&gate_two.changed);
  g_mutex_clear (&gate_two.mutex);
  g_cond_clear (&gate_one.changed);
  g_mutex_clear (&gate_one.mutex);
  wyl_fact_graph_key_clear (&a);
}

/* Repeated, because the discriminating assertion is racy by construction.
 * The broadcast that retires the first call and the moment the second takes
 * engine_call_lock are ordered, but state_lock is not FIFO: when the second
 * caller barges ahead of the woken drain, active_engine_calls is already back
 * to one and a predicate missing the queued term is false too, so the mutant
 * re-parks and escapes.  Measured at roughly one run in five for a single
 * pass.  Five passes put that near a thousandth, which is the difference
 * between a test that pins the term and one that manufactures confidence. */
static void
test_drain_waits_for_queued_engine_call (void)
{
  for (int i = 0; i < 5; i++)
    drain_waits_for_queued_engine_call_once ();
}

/* Reopening a graph while a drain is parked makes that drain's answer
 * meaningless, so it is refused rather than left waiting -- and the reopen
 * has to wake it, or the refusal would arrive only when something unrelated
 * happened to signal. */
static void
test_drain_refused_when_reopened_while_parked (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 131 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &snapshot), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);

  UseGate use_gate = { 0 };
  g_mutex_init (&use_gate.mutex);
  g_cond_init (&use_gate.changed);
  UseThread user = {.snapshot = snapshot,.gate = &use_gate,
                    .result = WYRELOG_E_INTERNAL };
  GThread *worker = g_thread_new ("engine-call", use_thread, &user);
  use_gate_wait_entered (&use_gate);

  Completion refused = { 0 };
  completion_init (&refused);
  DrainThread blocker = {.manager = manager,.key = &a,.timeout_us = -1,
                         .result = WYRELOG_E_INTERNAL,
                         .completion = &refused };
  GThread *drainer = g_thread_new ("drain", drain_thread, &blocker);
  wait_for_parked_drain (manager, &a);

  g_assert_cmpint (wyl_fact_graph_runtime_manager_open_admission (manager,
      &a), ==, WYRELOG_E_OK);
  completion_wait (&refused);
  g_thread_join (drainer);
  g_assert_cmpint (blocker.result, ==, WYRELOG_E_INVALID);

  use_gate_release (&use_gate);
  g_thread_join (worker);
  completion_clear (&refused);
  g_cond_clear (&use_gate.changed);
  g_mutex_clear (&use_gate.mutex);
  wyl_fact_graph_key_clear (&a);
}

/* A very large timeout must still park.  Adding it to the monotonic clock
 * blind overflows to a deadline already in the past, which makes
 * g_cond_wait_until return at once -- so a caller asking for a long bounded
 * wait would get an instant BUSY, the opposite of the request. */
static void
test_drain_clamps_a_huge_deadline (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 141 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &a, &snapshot), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);

  UseGate use_gate = { 0 };
  g_mutex_init (&use_gate.mutex);
  g_cond_init (&use_gate.changed);
  UseThread user = {.snapshot = snapshot,.gate = &use_gate,
                    .result = WYRELOG_E_INTERNAL };
  GThread *worker = g_thread_new ("engine-call", use_thread, &user);
  use_gate_wait_entered (&use_gate);

  Completion drained = { 0 };
  completion_init (&drained);
  DrainThread blocker = {.manager = manager,.key = &a,
                         .timeout_us = G_MAXINT64,
                         .result = WYRELOG_E_INTERNAL,
                         .completion = &drained };
  GThread *drainer = g_thread_new ("drain", drain_thread, &blocker);
  /* Without the clamp the deadline has already passed and the drain never
   * parks at all, so this is the assertion that fails. */
  wait_for_parked_drain (manager, &a);

  use_gate_release (&use_gate);
  g_thread_join (worker);
  completion_wait (&drained);
  g_thread_join (drainer);
  g_assert_cmpint (blocker.result, ==, WYRELOG_E_OK);

  completion_clear (&drained);
  g_cond_clear (&use_gate.changed);
  g_mutex_clear (&use_gate.mutex);
  wyl_fact_graph_key_clear (&a);
}

/* Both facts can be true at once, and the contract says to read state first.
 * refresh's post-build shutdown race fills a status that is ABANDONED and
 * CLOSED together, so a caller testing admission first would read a barrier
 * and retry forever against a manager that is gone.  Nothing asserted this
 * before; a later change that cleared admission on the abandoned branch would
 * have made the documented precedence quietly false. */
static void
test_abandoned_outranks_closed_in_a_filled_status (void)
{
  WylFactGraphKey a = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec seed = {.marker = 151 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &seed, NULL), ==, WYRELOG_E_OK);

  Gate gate = { 0 };
  gate_init (&gate);
  BuildSpec slow = {.marker = 152,.gate = &gate };
  StatusRefreshThread builder = {
    .manager = manager,
    .key = &a,
    .spec = &slow,
    .result = WYRELOG_E_INTERNAL,
  };
  GThread *worker = g_thread_new ("racing-build", status_refresh_thread,
          &builder);
  gate_wait_entered (&gate);

  /* Close while the build owns the entry, then shut the manager down.  The
   * build is already admitted, so it runs to completion and its post-build
   * path is what fills the status. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &a), ==, WYRELOG_E_OK);
  wyl_fact_graph_runtime_manager_shutdown (manager);
  gate_release (&gate);
  g_thread_join (worker);

  g_assert_cmpint (builder.result, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (builder.status.state, ==,
      WYL_FACT_GRAPH_RUNTIME_ABANDONED);
  g_assert_cmpint (builder.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&builder.status);

  gate_clear (&gate);
  wyl_fact_graph_key_clear (&a);
}

static void
test_forget_state_is_orthogonal_and_total (void)
{
  WylFactGraphKey a = { 0 }, absent = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&a, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&absent, "tenant-a", "absent"),
      ==, WYRELOG_E_OK);

  g_autoptr (WylFactGraphRuntimeManager) manager = new_manager ();
  BuildSpec spec = {.marker = 7 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &spec, NULL), ==, WYRELOG_E_OK);

  /* A graph nothing has reported on is converged, not unknown. */
  g_assert_cmpint (forget_state_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);

  /* 4: the setter never mints an entry. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &absent, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_NOT_FOUND);
  ForgetStateProbe absent_probe = { &absent,
                                    WYL_FACT_GRAPH_FORGET_CONVERGED, 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_foreach_status (manager,
      forget_state_cb, &absent_probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (absent_probe.matched, ==, 0);

  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &a, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_OK);

  /* 3: visible through both readers, because one fill point feeds both. */
  g_assert_cmpint (forget_state_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_INCOMPLETE);
  g_assert_cmpint (forget_state_via_foreach (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_INCOMPLETE);

  /* 1: a successful refresh leaves it alone.  Replay health and erasure
   * convergence are independent, and only a forget reconcile may clear it. */
  BuildSpec again = {.marker = 8 };
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &again, &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_cmpint (status.forget_state, ==,
      WYL_FACT_GRAPH_FORGET_INCOMPLETE);
  wyl_fact_graph_runtime_status_clear (&status);
  g_assert_cmpint (forget_state_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_INCOMPLETE);

  /* 2: total, not a latch. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &a, WYL_FACT_GRAPH_FORGET_CONVERGED), ==, WYRELOG_E_OK);
  g_assert_cmpint (forget_state_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);
  g_assert_cmpint (forget_state_via_foreach (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);

  /* A FAILED refresh must leave the axis alone too, and this is the half that
   * matters: the orthogonality claim is unconditional, but a success-only test
   * proves only the easy direction.  Clearing the axis on a failed rebuild is
   * this issue's own bug shape -- a transient store error would silently erase
   * an outstanding-erasure signal, and the graph would report ready. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &a, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_OK);
  BuildSpec broken = {.failure = WYRELOG_E_IO };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &broken, &status), ==, WYRELOG_E_IO);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY_STALE);
  g_assert_cmpint (status.forget_state, ==,
      WYL_FACT_GRAPH_FORGET_INCOMPLETE);
  wyl_fact_graph_runtime_status_clear (&status);

  /* Per-graph, not per-manager: a verdict on one graph must not colour
   * another.  The issue is explicitly per-graph, so an implementation that
   * stored this on the manager would satisfy every assertion above. */
  WylFactGraphKey other = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&other, "tenant-b", "orders"), ==,
      WYRELOG_E_OK);
  BuildSpec other_spec = {.marker = 21 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &other,
      build_marker_engine, &other_spec, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (forget_state_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_INCOMPLETE);
  g_assert_cmpint (forget_state_via_get (manager, &other), ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);
  wyl_fact_graph_key_clear (&other);

  /* Tombstoning clears the axis, and the assertion is made after republish
   * rather than on the tombstone: the status reader skips EVICTED, so a
   * tombstone assertion would test a value no consumer ever reads.  An entry
   * republished under the same key has not been probed, so carrying the
   * predecessor's INCOMPLETE would report an erasure for a graph the runtime
   * no longer holds -- and since the only in-product caller of full replay is
   * handle open, that stale claim would persist until restart. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &a, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_retire_unseen (manager,
      NULL, 0), ==, WYRELOG_E_OK);
  BuildSpec republished = {.marker = 9 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &republished, &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_cmpint (status.forget_state, ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);
  wyl_fact_graph_runtime_status_clear (&status);
  g_assert_cmpint (forget_state_via_get (manager, &a), ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);

  /* try_evict clears it too, and needs its own case: retire_unseen and
   * try_evict are separate tombstone paths, so a test that exercises only one
   * leaves the other's reset unproven.  Verified by mutation -- removing
   * either reset alone must fail this test. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &a, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_OK);
  gboolean evicted = FALSE;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_try_evict (manager, &a,
      &evicted), ==, WYRELOG_E_OK);
  g_assert_true (evicted);
  BuildSpec after_evict = {.marker = 10 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &after_evict, &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.forget_state, ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);
  wyl_fact_graph_runtime_status_clear (&status);

  /* A tombstone refuses the write, under the same lock as the write itself.
   * The tombstone paths clear the axis but release state_lock before a
   * reconciler verdict can land, so clearing alone leaves a window in which a
   * late write re-poisons the tombstone and a later refresh republishes a
   * predecessor's erasure onto a READY graph.  Refusing here is what closes
   * it.  Asserted through a republish, because that is where the damage would
   * have surfaced. */
  g_assert_cmpint (wyl_fact_graph_runtime_manager_retire_unseen (manager,
      NULL, 0), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &a, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_BUSY);
  BuildSpec after_refuse = {.marker = 12 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &a,
      build_marker_engine, &after_refuse, &status), ==, WYRELOG_E_OK);
  g_assert_cmpint (status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_cmpint (status.forget_state, ==,
      WYL_FACT_GRAPH_FORGET_CONVERGED);
  wyl_fact_graph_runtime_status_clear (&status);

  /* 4, second half: a shut-down manager refuses rather than reports OK. */
  wyl_fact_graph_runtime_manager_shutdown (manager);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &a, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_BUSY);

  wyl_fact_graph_key_clear (&a);
  wyl_fact_graph_key_clear (&absent);
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
  g_test_add_func ("/fact-runtime/forget-state-orthogonal-and-total",
      test_forget_state_is_orthogonal_and_total);
  g_test_add_func ("/fact-runtime/admission-denies-new-work",
      test_admission_denies_new_work);
  g_test_add_func ("/fact-runtime/admission-idempotent-survives-retirement",
      test_admission_is_idempotent_and_survives_retirement);
  g_test_add_func ("/fact-runtime/admission-close-preserves-admitted-work",
      test_admission_close_does_not_disturb_admitted_work);
  g_test_add_func ("/fact-runtime/admission-precedence-and-shutdown",
      test_admission_precedence_and_shutdown);
  g_test_add_func ("/fact-runtime/drain-waits-for-admitted-engine-call",
      test_drain_waits_for_admitted_engine_call);
  g_test_add_func ("/fact-runtime/drain-refusals-and-shutdown-wake",
      test_drain_refusals_and_shutdown_wake);
  g_test_add_func ("/fact-runtime/drain-refuses-own-engine-callback",
      test_drain_refuses_its_own_engine_callback);
  g_test_add_func ("/fact-runtime/drain-waits-for-admitted-build",
      test_drain_waits_for_admitted_build);
  g_test_add_func ("/fact-runtime/drain-refuses-own-build-callback",
      test_drain_refuses_its_own_build_callback);
  g_test_add_func ("/fact-runtime/drain-waits-for-queued-engine-call",
      test_drain_waits_for_queued_engine_call);
  g_test_add_func ("/fact-runtime/drain-refused-when-reopened-while-parked",
      test_drain_refused_when_reopened_while_parked);
  g_test_add_func ("/fact-runtime/drain-clamps-a-huge-deadline",
      test_drain_clamps_a_huge_deadline);
  g_test_add_func ("/fact-runtime/abandoned-outranks-closed",
      test_abandoned_outranks_closed_in_a_filled_status);
  g_test_add_func ("/fact-runtime/two-tenant-two-graph-isolation",
      test_two_tenant_two_graph_generation_isolation);
  return g_test_run ();
}

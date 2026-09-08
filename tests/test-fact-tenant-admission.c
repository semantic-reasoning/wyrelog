/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "fact/tenant-admission-private.h"
#include "fact/runtime-private.h"
#include "wyl-engine-private.h"

static wyrelog_error_t
build_empty_engine (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  (void) key;
  (void) user_data;
  return wyl_engine_open_source
           (".decl marker(value: int64)\n"
             ".decl marker_observed(value: int64)\n"
             "marker_observed(V) :- marker(V).\n", 1, out_engine);
}

static void
open_close_and_writer_preference (void)
{
  g_autoptr (WylFactTenantAdmissionManager) manager = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_manager_new (&manager), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactTenantAdmissionLease) read = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_read
        (manager, "tenant-a", NULL, &read), ==, WYRELOG_E_OK);
  g_autoptr (WylFactTenantAdmissionLease) second_read = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_read
        (manager, "tenant-a", NULL, &second_read), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_tenant_admission_lease_validate
        (read, "tenant-a"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_tenant_admission_close
        (manager, "tenant-a"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_tenant_admission_open
        (manager, "tenant-a"), ==, WYRELOG_E_BUSY);
  g_autoptr (WylFactTenantAdmissionLease) rejected = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_read
        (manager, "tenant-a", NULL, &rejected), ==, WYRELOG_E_BUSY);
  g_clear_pointer (&read, wyl_fact_tenant_admission_lease_cleanup);
  g_clear_pointer (&second_read, wyl_fact_tenant_admission_lease_cleanup);
  g_assert_cmpint (wyl_fact_tenant_admission_open
        (manager, "tenant-a"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_read
        (manager, "tenant-a", NULL, &read), ==, WYRELOG_E_OK);
}

static void
cancellation_and_shutdown (void)
{
  g_autoptr (WylFactTenantAdmissionManager) manager = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_manager_new (&manager), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactTenantAdmissionLease) writer = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_write
        (manager, "tenant-b", NULL, &writer), ==, WYRELOG_E_OK);
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  g_cancellable_cancel (cancellable);
  g_autoptr (WylFactTenantAdmissionLease) cancelled = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_read
        (manager, "tenant-b", cancellable, &cancelled), ==,
      WYRELOG_E_CANCELLED);
  g_assert_cmpint (wyl_fact_tenant_admission_manager_shutdown (manager), ==,
      WYRELOG_E_BUSY);
  g_clear_pointer (&writer, wyl_fact_tenant_admission_lease_cleanup);
  g_assert_cmpint (wyl_fact_tenant_admission_manager_shutdown (manager), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_write
        (manager, "tenant-b", NULL, &writer), ==, WYRELOG_E_BUSY);
}

typedef struct
{
  WylFactTenantAdmissionLease *lease;
  wyrelog_error_t result;
} ReleaseAttempt;

static gpointer
release_from_other_thread (gpointer data)
{
  ReleaseAttempt *attempt = data;
  attempt->result = wyl_fact_tenant_admission_lease_release (attempt->lease);
  return NULL;
}

static void
wrong_thread_release_is_reported (void)
{
  g_autoptr (WylFactTenantAdmissionManager) manager = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_manager_new (&manager), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactTenantAdmissionLease) lease = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_read
        (manager, "tenant-c", NULL, &lease), ==, WYRELOG_E_OK);
  ReleaseAttempt attempt = { lease, WYRELOG_E_INTERNAL };
  GThread *thread = g_thread_new ("wrong-release",
          release_from_other_thread, &attempt);
  g_thread_join (thread);
  g_assert_cmpint (attempt.result, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_tenant_admission_lease_release
        (g_steal_pointer (&lease)), ==, WYRELOG_E_OK);
}

static void
invalid_inputs (void)
{
  g_autoptr (WylFactTenantAdmissionManager) manager = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_manager_new (&manager), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactTenantAdmissionLease) lease = NULL;
  g_assert_cmpint (wyl_fact_tenant_admission_acquire_read
        (manager, "../foreign", NULL, &lease), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_tenant_admission_close
        (manager, "../foreign"), ==, WYRELOG_E_INVALID);
}

static void
canonical_graph_order (void)
{
  WylFactGraphKey first = { 0 };
  WylFactGraphKey second = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&first, "tenant-a", "graph-2"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&second, "tenant-a", "graph-10"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_compare (&first, &second), >, 0);
  wyl_fact_graph_key_clear (&first);
  wyl_fact_graph_key_clear (&second);
}

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  WylFactGraphKey *key;
  gsize n_keys;
  GCancellable *cancellable;
  GMutex mutex;
  GCond changed;
  gboolean started;
  wyrelog_error_t result;
} LockWaiter;

typedef struct
{
  WylFactGraphLockSet *locks;
  wyrelog_error_t result;
} LockReleaseAttempt;

static gpointer
release_lock_set_from_other_thread (gpointer data)
{
  LockReleaseAttempt *attempt = data;
  attempt->result = wyl_fact_graph_lock_set_unref (attempt->locks);
  return NULL;
}

static gpointer
ordered_lock_waiter (gpointer data)
{
  LockWaiter *waiter = data;
  g_mutex_lock (&waiter->mutex);
  waiter->started = TRUE;
  g_cond_broadcast (&waiter->changed);
  g_mutex_unlock (&waiter->mutex);
  WylFactGraphLockSet *locks = NULL;
  waiter->result = wyl_fact_graph_runtime_manager_acquire_ordered_locks
        (waiter->manager, waiter->key, waiter->n_keys, waiter->cancellable,
          &locks);
  if (locks != NULL)
    wyl_fact_graph_lock_set_unref (locks);
  return NULL;
}

static void
ordered_lock_set (void)
{
  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  WylFactGraphKey keys[2] = { { 0 }, { 0 } };
  g_assert_cmpint (wyl_fact_graph_key_init (&keys[0], "tenant-a", "graph-a"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_key_init (&keys[1], "tenant-a", "graph-b"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh
        (manager, &keys[0], build_empty_engine, NULL, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh
        (manager, &keys[1], build_empty_engine, NULL, NULL), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphLockSet) held = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_ordered_locks
        (manager, &keys[0], 1, NULL, &held), ==, WYRELOG_E_OK);
  LockWaiter waiter = { 0 };
  waiter.manager = manager;
  waiter.key = &keys[0];
  waiter.n_keys = 1;
  g_mutex_init (&waiter.mutex);
  g_cond_init (&waiter.changed);
  waiter.cancellable = g_cancellable_new ();
  GThread *thread = g_thread_new ("ordered-cancel", ordered_lock_waiter,
          &waiter);
  g_mutex_lock (&waiter.mutex);
  while (!waiter.started)
    g_cond_wait (&waiter.changed, &waiter.mutex);
  g_mutex_unlock (&waiter.mutex);
  g_cancellable_cancel (waiter.cancellable);
  g_thread_join (thread);
  g_assert_cmpint (waiter.result, ==, WYRELOG_E_CANCELLED);
  g_clear_object (&waiter.cancellable);
  g_cond_clear (&waiter.changed);
  g_mutex_clear (&waiter.mutex);
  g_assert_cmpint (wyl_fact_graph_lock_set_unref
        (g_steal_pointer (&held)), ==, WYRELOG_E_OK);
  WylFactGraphKey second_order[2] = { keys[0], keys[1] };
  g_autoptr (WylFactGraphLockSet) held_second = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_ordered_locks
        (manager, &keys[1], 1, NULL, &held_second), ==, WYRELOG_E_OK);
  LockWaiter partial = { 0 };
  partial.manager = manager;
  partial.key = second_order;
  partial.n_keys = 2;
  partial.cancellable = g_cancellable_new ();
  g_mutex_init (&partial.mutex);
  g_cond_init (&partial.changed);
  thread = g_thread_new ("ordered-partial-cancel", ordered_lock_waiter,
          &partial);
  g_mutex_lock (&partial.mutex);
  while (!partial.started)
    g_cond_wait (&partial.changed, &partial.mutex);
  g_mutex_unlock (&partial.mutex);
  g_cancellable_cancel (partial.cancellable);
  g_thread_join (thread);
  g_assert_cmpint (partial.result, ==, WYRELOG_E_CANCELLED);
  g_clear_object (&partial.cancellable);
  g_cond_clear (&partial.changed);
  g_mutex_clear (&partial.mutex);
  g_assert_cmpint (wyl_fact_graph_lock_set_unref
        (g_steal_pointer (&held_second)), ==, WYRELOG_E_OK);
  WylFactGraphKey reverse[2] = { keys[1], keys[0] };
  g_autoptr (WylFactGraphLockSet) lock_set = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_ordered_locks
        (manager, reverse, 2, NULL, &lock_set), ==, WYRELOG_E_OK);
  LockReleaseAttempt release_attempt = { lock_set, WYRELOG_E_INTERNAL };
  thread = g_thread_new ("wrong-lockset-release",
          release_lock_set_from_other_thread, &release_attempt);
  g_thread_join (thread);
  g_assert_cmpint (release_attempt.result, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh
        (manager, &keys[0], build_empty_engine, NULL, NULL), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_lock_set_unref
        (g_steal_pointer (&lock_set)), ==, WYRELOG_E_OK);
  WylFactGraphKey duplicate[2] = { keys[0], keys[0] };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_ordered_locks
        (manager, duplicate, 2, NULL, &lock_set), ==, WYRELOG_E_INVALID);
  wyl_fact_graph_key_clear (&keys[0]);
  wyl_fact_graph_key_clear (&keys[1]);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/tenant-admission/open-close", open_close_and_writer_preference);
  g_test_add_func ("/fact/tenant-admission/cancel-shutdown", cancellation_and_shutdown);
  g_test_add_func ("/fact/tenant-admission/wrong-thread-release", wrong_thread_release_is_reported);
  g_test_add_func ("/fact/tenant-admission/invalid", invalid_inputs);
  g_test_add_func ("/fact/tenant-admission/canonical-graph-order", canonical_graph_order);
  g_test_add_func ("/fact/tenant-admission/ordered-lock-set", ordered_lock_set);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "fact-artifact-transition-driver-fixture.h"

#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name

typedef struct
{
  WylTestDriverStoredValue value;
  gboolean force_stale;
  gboolean corrupt_committed;
} MemoryStore;

typedef struct
{
  guint calls;
  wyrelog_error_t result;
  WylFactArtifactMainTransitionState completed_state;
} ActionProbe;

static wyrelog_error_t
memory_load (gpointer user_data, WylTestDriverStoredValue *out_value)
{
  *out_value = ((MemoryStore *) user_data)->value;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
memory_cas (gpointer user_data, guint64 expected_revision,
    const WylTestDriverStoredValue *desired,
    WylTestDriverStoredValue *out_committed)
{
  MemoryStore *store = user_data;
  *out_committed = (WylTestDriverStoredValue) { 0 };
  if (store->force_stale || store->value.revision != expected_revision)
    return WYRELOG_E_BUSY;
  store->value = *desired;
  *out_committed = store->value;
  if (store->corrupt_committed)
    out_committed->consumer_generation++;
  return WYRELOG_E_OK;
}

static void
trace_append (WylTestDriverTraceEvent event, gpointer user_data)
{
  g_array_append_val ((GArray *) user_data, event);
}

static wyrelog_error_t
probe_action (WylFactArtifactMainTransitionOp op, gpointer user_data,
    WylFactArtifactMainTransitionState *out_completed_state)
{
  ActionProbe *probe = user_data;
  g_assert_cmpint (op, >, MT (OP_INSPECT));
  probe->calls++;
  *out_completed_state = probe->completed_state;
  return probe->result;
}

static MemoryStore
memory_store_new (void)
{
  MemoryStore store = { 0 };
  store.value.version = 1;
  store.value.revision = 7;
  store.value.consumer_generation = 19;
  g_strlcpy (store.value.operation_uuid,
      "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b",
      sizeof store.value.operation_uuid);
  store.value.directory_identity.domain = 1;
  store.value.directory_identity.object = 11;
  store.value.lease_identity.domain = 2;
  store.value.lease_identity.object = 12;
  store.value.expected_main_identity.domain = 3;
  store.value.expected_main_identity.object = 13;
  store.value.staged_main_identity.domain = 4;
  store.value.staged_main_identity.object = 14;
  store.value.resume_forbidden = TRUE;
  store.value.durability_unprovable_acknowledged = TRUE;
  return store;
}

static WylTestDriverValueStore
value_store (MemoryStore *memory)
{
  return (WylTestDriverValueStore) {
           .load = memory_load,
           .compare_and_swap = memory_cas,
           .user_data = memory,
  };
}

static void
test_attempt_is_durable_before_execute (void)
{
  MemoryStore memory = memory_store_new ();
  WylTestDriverValueStore store = value_store (&memory);
  g_autoptr (GArray) trace = g_array_new (FALSE, FALSE,
          sizeof (WylTestDriverTraceEvent));
  ActionProbe action = { .result = WYRELOG_E_OK,
                         .completed_state = MT (STATE_RETAINED) };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, FALSE, 19,
      MT (OP_RETAIN),
      probe_action, &action, trace_append, trace, &attempt,
      &completed_state), ==, WYRELOG_E_OK);
  g_assert_cmpuint (action.calls, ==, 1);
  g_assert_cmpint (completed_state, ==, MT (STATE_RETAINED));
  g_assert_cmpint (g_array_index (trace, WylTestDriverTraceEvent, 0), ==,
      WYL_TEST_DRIVER_TRACE_LOAD);
  g_assert_cmpint (g_array_index (trace, WylTestDriverTraceEvent, 1), ==,
      WYL_TEST_DRIVER_TRACE_CAS_ATTEMPT);
  g_assert_cmpint (g_array_index (trace, WylTestDriverTraceEvent, 2), ==,
      WYL_TEST_DRIVER_TRACE_EXECUTE);
  g_assert_cmpint (attempt.marker, ==,
      WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN);
  g_assert_cmpuint (attempt.consumer_generation, ==, 19);
  g_assert_cmpstr (attempt.operation_uuid, ==,
      "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b");
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&attempt.directory_identity, &memory.value.directory_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&attempt.lease_identity, &memory.value.lease_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&attempt.expected_main_identity,
      &memory.value.expected_main_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&attempt.staged_main_identity, &memory.value.staged_main_identity));
  g_assert_true (attempt.resume_forbidden);
  g_assert_true (attempt.durability_unprovable_acknowledged);

  WylTestDriverStoredValue completed = { 0 };
  g_assert_cmpint (wyl_test_driver_complete_mutation (&store, MT (OP_RETAIN),
      MT (STATE_RETAINED), trace_append, trace, &completed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (g_array_index (trace, WylTestDriverTraceEvent, 3), ==,
      WYL_TEST_DRIVER_TRACE_LOAD);
  g_assert_cmpint (g_array_index (trace, WylTestDriverTraceEvent, 4), ==,
      WYL_TEST_DRIVER_TRACE_CAS_COMPLETE);
  g_assert_cmpint (completed.marker, ==, WYL_TEST_DRIVER_MARKER_COMPLETED);
  g_assert_cmpint (completed.completed_state, ==, MT (STATE_RETAINED));
}

static void
test_stale_cas_suppresses_finalize (void)
{
  MemoryStore memory = memory_store_new ();
  memory.force_stale = TRUE;
  WylTestDriverValueStore store = value_store (&memory);
  g_autoptr (GArray) trace = g_array_new (FALSE, FALSE,
          sizeof (WylTestDriverTraceEvent));
  ActionProbe action = { .result = WYRELOG_E_OK,
                         .completed_state = MT (STATE_FINALIZED) };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, FALSE, 19,
      MT (OP_FINALIZE), probe_action, &action, trace_append, trace, &attempt,
      &completed_state), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (trace->len, ==, 2);
  g_assert_cmpuint (action.calls, ==, 0);
  g_assert_cmpint (memory.value.marker, ==, WYL_TEST_DRIVER_MARKER_NONE);

  memory.force_stale = FALSE;
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, FALSE, 20,
      MT (OP_FINALIZE), probe_action, &action, trace_append, trace, &attempt,
      &completed_state), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (action.calls, ==, 0);
}

static void
test_post_execute_stale_completion_stays_unknown (void)
{
  MemoryStore memory = memory_store_new ();
  WylTestDriverValueStore store = value_store (&memory);
  ActionProbe action = { .result = WYRELOG_E_OK,
                         .completed_state = MT (STATE_RETAINED) };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, FALSE, 19,
      MT (OP_RETAIN),
      probe_action, &action, NULL, NULL, &attempt, &completed_state), ==,
      WYRELOG_E_OK);
  memory.force_stale = TRUE;
  WylTestDriverStoredValue completed = { 0 };
  g_assert_cmpint (wyl_test_driver_complete_mutation (&store, MT (OP_RETAIN),
      completed_state, NULL, NULL, &completed), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (action.calls, ==, 1);
  g_assert_cmpint (memory.value.marker, ==,
      WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_RETAINED)), ==, WYL_TEST_DRIVER_RESTART_INSPECT_ONLY);
}

static void
test_corrupt_cas_result_never_enables_action (void)
{
  MemoryStore memory = memory_store_new ();
  memory.corrupt_committed = TRUE;
  WylTestDriverValueStore store = value_store (&memory);
  ActionProbe action = { .result = WYRELOG_E_OK,
                         .completed_state = MT (STATE_RETAINED) };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, FALSE, 19,
      MT (OP_RETAIN),
      probe_action, &action, NULL, NULL, &attempt, &completed_state), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (action.calls, ==, 0);
  g_assert_cmpint (memory.value.marker, ==,
      WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN);
}

static void
test_cancellation_stops_before_attempt_boundary (void)
{
  MemoryStore memory = memory_store_new ();
  WylTestDriverValueStore store = value_store (&memory);
  g_autoptr (GArray) trace = g_array_new (FALSE, FALSE,
          sizeof (WylTestDriverTraceEvent));
  ActionProbe action = { .result = WYRELOG_E_OK,
                         .completed_state = MT (STATE_RETAINED) };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, TRUE, 19,
      MT (OP_RETAIN), probe_action, &action, trace_append, trace, &attempt,
      &completed_state), ==, WYRELOG_E_CANCELLED);
  g_assert_cmpuint (trace->len, ==, 0);
  g_assert_cmpuint (action.calls, ==, 0);
  g_assert_cmpint (memory.value.marker, ==, WYL_TEST_DRIVER_MARKER_NONE);
}

static void
test_retryable_and_unsupported_sync_remain_nondurable (void)
{
  MemoryStore memory = memory_store_new ();
  WylTestDriverValueStore store = value_store (&memory);
  ActionProbe action = { .result = WYRELOG_E_OK,
                         .completed_state = MT (STATE_READY) };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, FALSE, 19,
      MT (OP_SYNC_STAGED), probe_action, &action, NULL, NULL, &attempt,
      &completed_state), ==, WYRELOG_E_OK);
  WylTestDriverStoredValue completed = { 0 };
  g_assert_cmpint (wyl_test_driver_complete_mutation (&store,
      MT (OP_SYNC_STAGED), completed_state, NULL, NULL, &completed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (completed.completed_state, ==, MT (STATE_READY));
  g_assert_cmpint (wyl_test_driver_restart_action (&completed,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_CONTINUE);

  memory = memory_store_new ();
  store = value_store (&memory);
  action = (ActionProbe) { .result = WYRELOG_E_OK,
                           .completed_state = MT (STATE_PUBLISHED) };
  g_assert_cmpint (wyl_test_driver_run_mutation (&store, FALSE, 19,
      MT (OP_SYNC_PUBLISH_DIR), probe_action, &action, NULL, NULL, &attempt,
      &completed_state), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_test_driver_complete_mutation (&store,
      MT (OP_SYNC_PUBLISH_DIR), completed_state, NULL, NULL, &completed), ==,
      WYRELOG_E_OK);
  g_assert_true (completed.durability_unprovable_acknowledged);
  g_assert_cmpint (completed.completed_state, ==, MT (STATE_PUBLISHED));
  g_assert_cmpint (wyl_test_driver_restart_action (&completed,
      MT (STATE_PUBLISHED)), ==,
      WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR);
}

static void
test_restart_never_replays_unknown_attempt (void)
{
  MemoryStore memory = memory_store_new ();
  memory.value.marker = WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN;
  memory.value.pending_op = MT (OP_PUBLISH);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_PUBLISHED)), ==, WYL_TEST_DRIVER_RESTART_INSPECT_ONLY);

  memory.value.marker = WYL_TEST_DRIVER_MARKER_COMPLETED;
  memory.value.completed_state = MT (STATE_PUBLISHED);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_PUBLISHED)), ==,
      WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR);
  memory.value.pending_op = MT (OP_SYNC_PUBLISH_DIR);
  memory.value.completed_state = MT (STATE_PUBLISHED_DURABLE);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_PUBLISHED)), ==,
      WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR);
  memory.value.pending_op = MT (OP_ROLLBACK);
  memory.value.completed_state = MT (STATE_RETAINED);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_RETAINED)), ==, WYL_TEST_DRIVER_RESTART_CONTINUE);
  memory.value.completed_state = MT (STATE_ROLLED_BACK);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_RETIRE_STAGE);
  memory.value.resume_forbidden = FALSE;
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_REFUSE);
  memory.value.resume_forbidden = TRUE;
  memory.value.completed_state = MT (STATE_ABANDONED);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_ABANDONED)), ==,
      WYL_TEST_DRIVER_RESTART_COMPLETE_MARKER);
  memory.value.resume_forbidden = TRUE;
  memory.value.marker = WYL_TEST_DRIVER_MARKER_NONE;
  memory.value.pending_op = MT (OP_NONE);
  memory.value.completed_state = MT (STATE_INVALID);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_ROLLBACK_ONLY);
}

static void
test_corrupt_store_always_refuses (void)
{
  MemoryStore memory = memory_store_new ();
  memory.value.marker = (WylTestDriverMarker) 99;
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_REFUSE);
  memory = memory_store_new ();
  memory.value.marker = WYL_TEST_DRIVER_MARKER_COMPLETED;
  memory.value.pending_op = MT (OP_RETAIN);
  memory.value.completed_state = MT (STATE_FINALIZED);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_FINALIZED)), ==, WYL_TEST_DRIVER_RESTART_REFUSE);
  memory = memory_store_new ();
  memory.value.marker = WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN;
  memory.value.pending_op = MT (OP_NONE);
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_REFUSE);
  memory = memory_store_new ();
  memory.value.operation_uuid[8] = 'x';
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_REFUSE);
  memory = memory_store_new ();
  memory.value.staged_main_identity.object_width = 1;
  g_assert_cmpint (wyl_test_driver_restart_action (&memory.value,
      MT (STATE_READY)), ==, WYL_TEST_DRIVER_RESTART_REFUSE);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/artifact-transition-driver/attempt-before-execute",
      test_attempt_is_durable_before_execute);
  g_test_add_func ("/fact/artifact-transition-driver/stale-cas",
      test_stale_cas_suppresses_finalize);
  g_test_add_func ("/fact/artifact-transition-driver/post-execute-stale",
      test_post_execute_stale_completion_stays_unknown);
  g_test_add_func ("/fact/artifact-transition-driver/corrupt-cas-result",
      test_corrupt_cas_result_never_enables_action);
  g_test_add_func ("/fact/artifact-transition-driver/cancellation-boundary",
      test_cancellation_stops_before_attempt_boundary);
  g_test_add_func ("/fact/artifact-transition-driver/sync-retry-unsupported",
      test_retryable_and_unsupported_sync_remain_nondurable);
  g_test_add_func ("/fact/artifact-transition-driver/restart-table",
      test_restart_never_replays_unknown_attempt);
  g_test_add_func ("/fact/artifact-transition-driver/corrupt-store",
      test_corrupt_store_always_refuses);
  return g_test_run ();
}

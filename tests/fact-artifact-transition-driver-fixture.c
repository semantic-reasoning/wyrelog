/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact-artifact-transition-driver-fixture.h"

#include <string.h>

#define DRIVER_VALUE_VERSION 1u

static gboolean
identity_valid (const WylFactArtifactInventoryIdentity *identity)
{
  gboolean bytes_present = FALSE;
  for (gsize index = 0; index < sizeof identity->object_bytes; index++)
    if (identity->object_bytes[index] != 0)
      bytes_present = TRUE;
  if (identity->domain == 0)
    return FALSE;
  if (identity->object_width == 0)
    return identity->object != 0 && !bytes_present;
  return identity->object_width == sizeof identity->object_bytes
         && identity->object == 0 && bytes_present;
}

static gboolean
identity_zero (const WylFactArtifactInventoryIdentity *identity)
{
  if (identity->domain != 0 || identity->object != 0
      || identity->object_width != 0)
    return FALSE;
  for (gsize index = 0; index < sizeof identity->object_bytes; index++)
    if (identity->object_bytes[index] != 0)
      return FALSE;
  return TRUE;
}

static gboolean
uuid_valid (const gchar operation_uuid[37])
{
  for (gsize index = 0; index < 36; index++) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (operation_uuid[index] != '-')
        return FALSE;
    } else if (!g_ascii_isxdigit (operation_uuid[index])) {
      return FALSE;
    }
  }
  return operation_uuid[36] == '\0';
}

static gboolean
boolean_valid (gboolean value)
{
  return value == FALSE || value == TRUE;
}

static gboolean
request_semantics_equal (const WylTestDriverStoredValue *left,
    const WylTestDriverStoredValue *right)
{
  return left->version == right->version
         && left->consumer_generation == right->consumer_generation
         && strcmp (left->operation_uuid, right->operation_uuid) == 0
         && wyl_fact_artifact_inventory_identity_equal
           (&left->directory_identity, &right->directory_identity)
         && wyl_fact_artifact_inventory_identity_equal
           (&left->lease_identity, &right->lease_identity)
         && left->expected_main_absent == right->expected_main_absent
         && wyl_fact_artifact_inventory_identity_equal
           (&left->expected_main_identity, &right->expected_main_identity)
         && wyl_fact_artifact_inventory_identity_equal
           (&left->staged_main_identity, &right->staged_main_identity)
         && left->resume_forbidden == right->resume_forbidden
         && left->durability_unprovable_acknowledged
         == right->durability_unprovable_acknowledged;
}

static gboolean
completed_state_legal (WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionState state)
{
  switch (op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
      return state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY
             || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      return state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      return state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      return state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED
             || state
             == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK:
      return state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED
             || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK
             || state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE:
      return state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE:
      return state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED;
    default:
      return FALSE;
  }
}

static gboolean
stored_value_valid (const WylTestDriverStoredValue *value)
{
  if (value == NULL)
    return FALSE;
  if (value->version != DRIVER_VALUE_VERSION
      || !uuid_valid (value->operation_uuid)
      || memchr (value->operation_uuid, '\0', 36) != NULL
      || !identity_valid (&value->directory_identity)
      || !identity_valid (&value->lease_identity)
      || !identity_valid (&value->staged_main_identity)
      || !boolean_valid (value->expected_main_absent)
      || !boolean_valid (value->resume_forbidden)
      || !boolean_valid (value->durability_unprovable_acknowledged)
      || (value->expected_main_absent
      && !identity_zero (&value->expected_main_identity))
      || (!value->expected_main_absent
      && !identity_valid (&value->expected_main_identity)))
    return FALSE;
  switch (value->marker) {
    case WYL_TEST_DRIVER_MARKER_NONE:
      return value->pending_op
             == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE
             && value->completed_state
             == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
    case WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN:
      return value->pending_op
             > WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_INSPECT
             && value->pending_op
             < WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT
             && value->completed_state
             == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
    case WYL_TEST_DRIVER_MARKER_COMPLETED:
      return completed_state_legal (value->pending_op,
                 value->completed_state);
    default:
      return FALSE;
  }
}

static wyrelog_error_t
load_valid (const WylTestDriverValueStore *store, WylTestDriverTrace trace,
    gpointer trace_data, WylTestDriverStoredValue *out_value)
{
  if (out_value != NULL)
    *out_value = (WylTestDriverStoredValue) { 0 };
  if (store == NULL || store->load == NULL || store->compare_and_swap == NULL
      || out_value == NULL)
    return WYRELOG_E_INVALID;
  if (trace != NULL)
    trace (WYL_TEST_DRIVER_TRACE_LOAD, trace_data);
  wyrelog_error_t rc = store->load (store->user_data, out_value);
  if (rc == WYRELOG_E_OK && !stored_value_valid (out_value))
    rc = WYRELOG_E_POLICY;
  return rc;
}

wyrelog_error_t
wyl_test_driver_run_mutation (const WylTestDriverValueStore *store,
    gboolean cancelled, guint64 expected_consumer_generation,
    WylFactArtifactMainTransitionOp op, WylTestDriverAction action,
    gpointer action_data, WylTestDriverTrace trace, gpointer trace_data,
    WylTestDriverStoredValue *out_attempt,
    WylFactArtifactMainTransitionState *out_completed_state)
{
  if (out_attempt != NULL)
    *out_attempt = (WylTestDriverStoredValue) { 0 };
  if (out_completed_state != NULL)
    *out_completed_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
  if (out_attempt == NULL || out_completed_state == NULL || action == NULL
      || op <= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_INSPECT
      || op >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT)
    return WYRELOG_E_INVALID;
  if (cancelled)
    return WYRELOG_E_CANCELLED;
  WylTestDriverStoredValue loaded = { 0 };
  wyrelog_error_t rc = load_valid (store, trace, trace_data, &loaded);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (loaded.marker == WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN)
    return WYRELOG_E_BUSY;
  if (loaded.consumer_generation != expected_consumer_generation)
    return WYRELOG_E_BUSY;
  if (loaded.revision == G_MAXUINT64)
    return WYRELOG_E_POLICY;
  WylTestDriverStoredValue desired = loaded;
  desired.revision++;
  desired.marker = WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN;
  desired.pending_op = op;
  desired.completed_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID;
  if (trace != NULL)
    trace (WYL_TEST_DRIVER_TRACE_CAS_ATTEMPT, trace_data);
  rc = store->compare_and_swap (store->user_data, loaded.revision, &desired,
          out_attempt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!stored_value_valid (out_attempt)
      || out_attempt->revision != desired.revision
      || !request_semantics_equal (out_attempt, &desired)
      || out_attempt->marker != WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN
      || out_attempt->pending_op != op)
    return WYRELOG_E_POLICY;
  if (trace != NULL)
    trace (WYL_TEST_DRIVER_TRACE_EXECUTE, trace_data);
  return action (op, action_data, out_completed_state);
}

wyrelog_error_t
wyl_test_driver_complete_mutation (const WylTestDriverValueStore *store,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionState completed_state,
    WylTestDriverTrace trace, gpointer trace_data,
    WylTestDriverStoredValue *out_completed)
{
  if (out_completed != NULL)
    *out_completed = (WylTestDriverStoredValue) { 0 };
  if (out_completed == NULL || completed_state <=
      WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID
      || completed_state >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_COUNT
      || !completed_state_legal (op, completed_state))
    return WYRELOG_E_INVALID;
  WylTestDriverStoredValue loaded = { 0 };
  wyrelog_error_t rc = load_valid (store, trace, trace_data, &loaded);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (loaded.marker != WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN
      || loaded.pending_op != op)
    return WYRELOG_E_POLICY;
  if (loaded.revision == G_MAXUINT64)
    return WYRELOG_E_POLICY;
  WylTestDriverStoredValue desired = loaded;
  desired.revision++;
  desired.marker = WYL_TEST_DRIVER_MARKER_COMPLETED;
  desired.completed_state = completed_state;
  if (trace != NULL)
    trace (WYL_TEST_DRIVER_TRACE_CAS_COMPLETE, trace_data);
  rc = store->compare_and_swap (store->user_data, loaded.revision, &desired,
          out_completed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!stored_value_valid (out_completed)
      || out_completed->revision != desired.revision
      || !request_semantics_equal (out_completed, &desired)
      || out_completed->marker != WYL_TEST_DRIVER_MARKER_COMPLETED
      || out_completed->pending_op != op
      || out_completed->completed_state != completed_state)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

WylTestDriverRestartAction
wyl_test_driver_restart_action (const WylTestDriverStoredValue *stored,
    WylFactArtifactMainTransitionState fresh_state)
{
  if (!stored_value_valid (stored))
    return WYL_TEST_DRIVER_RESTART_REFUSE;
  if (stored->marker == WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN)
    return WYL_TEST_DRIVER_RESTART_INSPECT_ONLY;
  if (stored->marker == WYL_TEST_DRIVER_MARKER_NONE
      && stored->resume_forbidden
      && fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY)
    return WYL_TEST_DRIVER_RESTART_ROLLBACK_ONLY;
  if (stored->marker == WYL_TEST_DRIVER_MARKER_NONE)
    return WYL_TEST_DRIVER_RESTART_CONTINUE;
  if (stored->completed_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED
      && stored->expected_main_absent
      && fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED)
    return WYL_TEST_DRIVER_RESTART_COMPLETE_MARKER;
  if (stored->pending_op
      == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR
      && stored->completed_state
      == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE
      && fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED)
    return WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR;
  if (stored->pending_op == WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK
      && stored->completed_state
      == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK
      && fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY)
    return stored->resume_forbidden
        ? WYL_TEST_DRIVER_RESTART_RETIRE_STAGE
        : WYL_TEST_DRIVER_RESTART_REFUSE;
  if (fresh_state != stored->completed_state)
    return WYL_TEST_DRIVER_RESTART_REFUSE;
  switch (stored->pending_op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      return WYL_TEST_DRIVER_RESTART_CONTINUE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      return WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      return WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK:
      return fresh_state == WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED
          ? WYL_TEST_DRIVER_RESTART_COMPLETE_MARKER
          : WYL_TEST_DRIVER_RESTART_CONTINUE;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE:
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE:
      return WYL_TEST_DRIVER_RESTART_COMPLETE_MARKER;
    default:
      return WYL_TEST_DRIVER_RESTART_REFUSE;
  }
}

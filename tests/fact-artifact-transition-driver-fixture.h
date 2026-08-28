/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-main-transition-private.h"
#include "wyrelog/error.h"

typedef enum
{
  WYL_TEST_DRIVER_MARKER_NONE = 0,
  WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN,
  WYL_TEST_DRIVER_MARKER_COMPLETED,
} WylTestDriverMarker;

typedef struct
{
  guint version;
  guint64 revision;
  guint64 consumer_generation;
  gchar operation_uuid[37];
  WylFactArtifactInventoryIdentity directory_identity;
  WylFactArtifactInventoryIdentity lease_identity;
  gboolean expected_main_absent;
  WylFactArtifactInventoryIdentity expected_main_identity;
  WylFactArtifactInventoryIdentity staged_main_identity;
  gboolean resume_forbidden;
  gboolean durability_unprovable_acknowledged;
  WylTestDriverMarker marker;
  WylFactArtifactMainTransitionOp pending_op;
  WylFactArtifactMainTransitionState completed_state;
} WylTestDriverStoredValue;

typedef struct
{
  wyrelog_error_t (*load) (gpointer user_data,
      WylTestDriverStoredValue *out_value);
  wyrelog_error_t (*compare_and_swap) (gpointer user_data,
      guint64 expected_revision, const WylTestDriverStoredValue *desired,
      WylTestDriverStoredValue *out_committed);
  gpointer user_data;
} WylTestDriverValueStore;

typedef enum
{
  WYL_TEST_DRIVER_TRACE_LOAD = 1,
  WYL_TEST_DRIVER_TRACE_CAS_ATTEMPT,
  WYL_TEST_DRIVER_TRACE_EXECUTE,
  WYL_TEST_DRIVER_TRACE_CAS_COMPLETE,
} WylTestDriverTraceEvent;

typedef void (*WylTestDriverTrace) (WylTestDriverTraceEvent event,
    gpointer user_data);

typedef wyrelog_error_t (*WylTestDriverAction)
  (WylFactArtifactMainTransitionOp op, gpointer user_data,
    WylFactArtifactMainTransitionState *out_completed_state);

typedef enum
{
  WYL_TEST_DRIVER_RESTART_REFUSE = 0,
  WYL_TEST_DRIVER_RESTART_INSPECT_ONLY,
  WYL_TEST_DRIVER_RESTART_CONTINUE,
  WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR,
  WYL_TEST_DRIVER_RESTART_RETIRE_STAGE,
  WYL_TEST_DRIVER_RESTART_ROLLBACK_ONLY,
  WYL_TEST_DRIVER_RESTART_COMPLETE_MARKER,
} WylTestDriverRestartAction;

wyrelog_error_t wyl_test_driver_run_mutation
  (const WylTestDriverValueStore *store, gboolean cancelled,
    guint64 expected_consumer_generation,
    WylFactArtifactMainTransitionOp op, WylTestDriverAction action,
    gpointer action_data, WylTestDriverTrace trace, gpointer trace_data,
    WylTestDriverStoredValue *out_attempt,
    WylFactArtifactMainTransitionState *out_completed_state);
wyrelog_error_t wyl_test_driver_complete_mutation
  (const WylTestDriverValueStore *store,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionState completed_state,
    WylTestDriverTrace trace, gpointer trace_data,
    WylTestDriverStoredValue *out_completed);
WylTestDriverRestartAction wyl_test_driver_restart_action
  (const WylTestDriverStoredValue *stored,
    WylFactArtifactMainTransitionState fresh_state);

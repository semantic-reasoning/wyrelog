/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-cancel-private.h"

/* Reuse the established private handoff fixture and publication probes in one
 * translation unit.  Renaming its test entry point keeps this executable
 * focused on cancellation while avoiding a second, subtly different policy
 * authority harness. */
#define main handoff_execute_fixture_main
#include "test-service-credential-operation-coordinator-execute.c"
#undef main

static void
fresh_uuid (gchar out[WYL_ID_STRING_BUF])
{
  wyl_id_t id;
  g_assert_cmpint (wyl_id_new (&id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&id, out, WYL_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
}

static gint64
count_cancellation_claims (sqlite3 *db, const gchar *request_id)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM service_credential_handoff_cancellation_claims"
          " WHERE original_request_id=?;", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, request_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static gint64
count_cancellation_audits (sqlite3 *db, const gchar *cancellation_request_id)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM audit_events WHERE action="
          "'service.credential.handoff.cancel' AND request_id=?;", -1,
          &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, cancellation_request_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static void
set_handoff_permission (WylHandle *handle, const gchar *actor,
    const gchar *session_id, gboolean granted)
{
  wyl_policy_store_t *store = store_of (handle);
  wyrelog_error_t rc = granted ?
      wyl_policy_store_grant_direct_permission (store, actor,
      "wr.service_credential.manage", session_id) :
      wyl_policy_store_revoke_direct_permission (store, actor,
      "wr.service_credential.manage", session_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  if (granted) {
    g_assert_cmpint (wyl_policy_store_set_principal_state (store, actor,
            "authenticated"), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_set_session_state (store, session_id,
            "active"), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_set_permission_state (store, actor,
            "wr.service_credential.manage", session_id, "armed"), ==,
        WYRELOG_E_OK);
  }
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
}

static void
cancel_request_ids_new (WylServiceCredentialOperationHandoffCancelRequest
    *request, gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF],
    gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF],
    gchar disposition_id[WYL_ID_STRING_BUF], gchar audit_id[WYL_ID_STRING_BUF])
{
  fresh_request_id (cancellation_request_id);
  fresh_request_id (decision_request_id);
  fresh_uuid (disposition_id);
  fresh_uuid (audit_id);
  *request = (WylServiceCredentialOperationHandoffCancelRequest) {
  .cancellation_request_id = cancellation_request_id,.disposition_id =
        disposition_id,.audit_id = audit_id,};
}

static void
materialize_rotate_handoff_for_cancel (WylHandle *handle,
    const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor, gint64 now_us,
    gchar request_id[WYL_REQUEST_ID_STRING_BUF], wyl_id_t *escrow,
    WylServiceCredentialOperationCoordinatorRequest *request,
    WylServiceCredentialOperationRecord *record)
{
  gchar seed_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar escrow_id[WYL_ID_STRING_BUF];
  wyl_service_credential_issue_result_t seed = { 0 };
  fresh_request_id (seed_request_id);
  g_assert_cmpint (wyl_service_credential_issue (handle,
          "svc:handoff:executor", "tenant-a", "admin", seed_request_id,
          now_us + 4 * G_TIME_SPAN_HOUR, &seed), ==, WYRELOG_E_OK);
  g_autofree gchar *old_credential_id =
      g_strdup (seed.credential.credential_id);
  guint64 old_generation = seed.credential.generation;
  wyl_service_credential_issue_result_clear (&seed);

  fresh_request_id (request_id);
  g_assert_cmpint (wyl_id_new (escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (escrow, escrow_id, sizeof escrow_id), ==,
      WYRELOG_E_OK);
  *request = (WylServiceCredentialOperationCoordinatorRequest)
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  request->kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  request->request_id = g_strdup (request_id);
  request->subject_id = g_strdup ("svc:handoff:executor");
  request->destination = g_strdup ("rotate-credentials.json");
  request->parent_identity = g_strdup ("test-parent-identity");
  request->actor_subject_id = g_strdup ("admin");
  request->old_credential_id = g_strdup (old_credential_id);
  request->escrow_id = g_strdup (escrow_id);
  request->expires_at_us = now_us + G_TIME_SPAN_HOUR;
  request->expected_generation = old_generation;
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = TRUE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (storage,
          anchor, request, now_us, &replayed, &prepared), ==, WYRELOG_E_OK);
  g_assert_false (replayed);

  guint8 target_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES] = { 0 };
  g_assert_cmpint (wyl_service_credential_operation_handoff_target_digest
      (&prepared, target_digest), ==, WYRELOG_E_OK);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = escrow,
    .target_digest = target_digest,
    .deadline_at_us = prepared.expires_at_us,
  };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = allow_handoff_mutation,
  };
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .old_credential_generation = old_generation,
    .authorization = &authorization,
  };
  wyl_service_credential_handoff_result_t rotated = { 0 };
  g_assert_cmpint
      (wyl_service_credential_rotate_handoff_checked_with_runtime (handle,
          old_credential_id, "admin", request_id,
          now_us + 4 * G_TIME_SPAN_HOUR, &handoff, &rotate_runtime,
          &rotated), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed_bound
      (storage, anchor, request_id, rotated.handoff.credential_id,
          rotated.handoff.credential_generation,
          rotated.handoff.binding_digest, now_us + 1, &replayed, record), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  wyl_service_credential_handoff_result_clear (&rotated);
  wyl_service_credential_operation_record_clear (&prepared);
}

static void
test_cancellation_tenant_binding (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  sqlite3 *db = db_of (handle);
  prepare_authority (handle, "svc:handoff:executor");
  gboolean tenant_created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store_of (handle),
          "tenant-b", &tenant_created), ==, WYRELOG_E_OK);
  g_assert_true (tenant_created);
  g_autofree gchar *operation_root = g_build_filename (fixture.dir,
      "cancel-tenant-operations", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_autoptr (WylSession) cross_tenant_session =
      handoff_human_session_new ("operator", "tenant-b");
  g_autofree gchar *session_id =
      wyl_session_dup_id_string (cross_tenant_session);
  set_handoff_permission (handle, "operator", session_id, TRUE);
  guint authorization_calls = 0;
  WylServiceCredentialOperationHandoffCancelRuntime runtime = {
    .session = cross_tenant_session,
    .authenticated_actor_subject_id = "operator",
    .guard_timestamp = g_get_real_time (),
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .after_authorization = count_handoff_authorization,
    .authorization_checkpoint_data = &authorization_calls,
  };

  for (guint rotate = 0; rotate < 2; rotate++) {
    gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar disposition_id[WYL_ID_STRING_BUF];
    gchar audit_id[WYL_ID_STRING_BUF];
    wyl_id_t escrow;
    WylServiceCredentialOperationCoordinatorRequest operation =
        WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
    WylServiceCredentialOperationRecord record =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    gint64 now = g_get_real_time () + rotate * 10;
    if (rotate != 0)
      materialize_rotate_handoff_for_cancel (handle, &storage, &anchor, now,
          original_request_id, &escrow, &operation, &record);
    else
      materialize_handoff_state_for_maintenance (handle, &storage, &anchor,
          now, WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
          original_request_id, &escrow, &operation, &record);
    WylServiceCredentialOperationHandoffCancelRequest request;
    cancel_request_ids_new (&request, cancellation_request_id,
        decision_request_id, disposition_id, audit_id);
    runtime.decision_request_id = decision_request_id;
    g_autoptr (GBytes) before = read_handoff_journal_bytes (operation_root,
        original_request_id);
    wyl_service_credential_handoff_cancellation_result_t result = { 0 };
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
            &storage, &anchor, original_request_id, &request, &runtime,
            &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpuint (authorization_calls, ==, 0);
    g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==,
        0);
    g_assert_cmpint (count_handoff_rows_for_request (db, original_request_id,
            "operation_cancelled"), ==, 0);
    g_assert_cmpint (count_cancellation_audits (db,
            cancellation_request_id), ==, 0);
    g_autoptr (GBytes) after = read_handoff_journal_bytes (operation_root,
        original_request_id);
    g_assert_true (g_bytes_equal (before, after));
    wyl_service_credential_operation_record_clear (&record);
    wyl_service_credential_operation_coordinator_request_clear (&operation);
  }

  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

typedef struct
{
  WylHandle *handle;
  const WylServiceCredentialOperationStorage *storage;
  const WylServiceCredentialOperationRootAnchor *anchor;
  const gchar *request_id;
  const WylServiceCredentialOperationHandoffCancelRequest *request;
  const WylServiceCredentialOperationHandoffCancelRuntime *runtime;
  wyl_service_credential_handoff_cancellation_result_t result;
  wyrelog_error_t rc;
} HandoffCancelCall;

static gpointer
handoff_cancel_thread (gpointer data)
{
  HandoffCancelCall *call = data;
  call->rc = wyl_service_credential_operation_coordinator_cancel_handoff
      (call->handle, call->storage, call->anchor, call->request_id,
      call->request, call->runtime, &call->result);
  return NULL;
}

typedef struct
{
  GMutex mutex;
  GCond cond;
  gboolean executor_started;
  gboolean first_attempt_done;
  gboolean retry_allowed;
  gboolean executor_done;
  guint publication_calls;
  guint authorization_calls;
  guint clock_calls;
  guint unseal_calls;
} CancellationContentionProbe;

typedef struct
{
  HandoffExecuteCall execute;
  CancellationContentionProbe *probe;
  wyrelog_error_t first_rc;
} ContendedExecuteCall;

static void
contention_probe_increment (CancellationContentionProbe *probe, guint *field)
{
  g_mutex_lock (&probe->mutex);
  (*field)++;
  g_cond_broadcast (&probe->cond);
  g_mutex_unlock (&probe->mutex);
}

static void
contention_authorization (gpointer data)
{
  CancellationContentionProbe *probe = data;
  contention_probe_increment (probe, &probe->authorization_calls);
}

static gint64
contention_clock (gpointer data)
{
  CancellationContentionProbe *probe = data;
  contention_probe_increment (probe, &probe->clock_calls);
  return g_get_real_time ();
}

static wyrelog_error_t
contention_unseal (gpointer data)
{
  CancellationContentionProbe *probe = data;
  contention_probe_increment (probe, &probe->unseal_calls);
  return WYRELOG_E_IO;
}

static wyrelog_error_t
contention_plan (gpointer data, const WyctlPublicationPlan *request,
    WyctlPublicationPlan *out)
{
  CancellationContentionProbe *probe = data;
  (void) request;
  (void) out;
  contention_probe_increment (probe, &probe->publication_calls);
  return WYRELOG_E_IO;
}

static wyrelog_error_t
contention_stage (gpointer data, const WyctlPublicationPlan *plan,
    const gchar *credential_id, const WyctlSensitiveText *secret,
    WyctlPublicationReceipt *receipt, WyctlPublicationResult *result,
    gboolean *replayed)
{
  CancellationContentionProbe *probe = data;
  (void) plan;
  (void) credential_id;
  (void) secret;
  (void) receipt;
  (void) result;
  (void) replayed;
  contention_probe_increment (probe, &probe->publication_calls);
  return WYRELOG_E_IO;
}

static wyrelog_error_t
contention_target_acquire (gpointer data, const WyctlPublicationPlan *plan,
    const WyctlPublicationReceipt *receipt, gboolean require_destination,
    WyctlPublicationReceiptTargetLease **lease,
    WyctlPublicationReceiptTargetKind *kind)
{
  CancellationContentionProbe *probe = data;
  (void) plan;
  (void) receipt;
  (void) require_destination;
  (void) lease;
  (void) kind;
  contention_probe_increment (probe, &probe->publication_calls);
  return WYRELOG_E_IO;
}

static wyrelog_error_t
contention_target_operation (gpointer data,
    WyctlPublicationReceiptTargetLease *lease, const gchar *credential_id,
    const WyctlSensitiveText *secret, WyctlPublicationResult *result)
{
  CancellationContentionProbe *probe = data;
  (void) lease;
  (void) credential_id;
  (void) secret;
  (void) result;
  contention_probe_increment (probe, &probe->publication_calls);
  return WYRELOG_E_IO;
}

static void
contention_target_release (gpointer data,
    WyctlPublicationReceiptTargetLease *lease)
{
  CancellationContentionProbe *probe = data;
  (void) lease;
  contention_probe_increment (probe, &probe->publication_calls);
}

static gpointer
contended_execute_thread (gpointer data)
{
  ContendedExecuteCall *call = data;
  g_mutex_lock (&call->probe->mutex);
  call->probe->executor_started = TRUE;
  g_cond_broadcast (&call->probe->cond);
  g_mutex_unlock (&call->probe->mutex);
  handoff_execute_thread (&call->execute);
  call->first_rc = call->execute.rc;
  g_mutex_lock (&call->probe->mutex);
  call->probe->first_attempt_done = TRUE;
  g_cond_broadcast (&call->probe->cond);
  while (!call->probe->retry_allowed)
    g_cond_wait (&call->probe->cond, &call->probe->mutex);
  g_mutex_unlock (&call->probe->mutex);
  if (call->first_rc == WYRELOG_E_BUSY) {
    wyl_service_credential_operation_record_clear (&call->execute.outcome);
    call->execute.rc = WYRELOG_E_INTERNAL;
    handoff_execute_thread (&call->execute);
  }
  g_mutex_lock (&call->probe->mutex);
  call->probe->executor_done = TRUE;
  g_cond_broadcast (&call->probe->cond);
  g_mutex_unlock (&call->probe->mutex);
  return NULL;
}

static void
test_cancellation_lifecycle_contention (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  wyl_policy_store_t *store = store_of (handle);
  prepare_authority (handle, "svc:handoff:executor");
  g_autofree gchar *operation_root = g_build_filename (fixture.dir,
      "cancel-contention-operations", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);

  gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t escrow;
  WylServiceCredentialOperationCoordinatorRequest operation =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gint64 now = g_get_real_time ();
  materialize_handoff_state_for_maintenance (handle, &storage, &anchor, now,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
      original_request_id, &escrow, &operation, &committed);
  g_autoptr (GBytes) journal_before = read_handoff_journal_bytes
      (operation_root, original_request_id);

  g_autoptr (WylSession) operator_session =
      handoff_human_session_new ("operator", "tenant-a");
  g_autofree gchar *operator_session_id =
      wyl_session_dup_id_string (operator_session);
  set_handoff_permission (handle, "operator", operator_session_id, TRUE);
  g_autoptr (WylSession) original_session =
      handoff_human_session_new ("admin", "tenant-a");
  g_autofree gchar *original_session_id =
      wyl_session_dup_id_string (original_session);
  set_handoff_permission (handle, "admin", original_session_id, TRUE);

  gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  WylServiceCredentialOperationHandoffCancelRequest request;
  cancel_request_ids_new (&request, cancellation_request_id,
      decision_request_id, disposition_id, audit_id);
  HandoffAuthorizationBarrier cancellation_barrier = { 0 };
  g_mutex_init (&cancellation_barrier.mutex);
  g_cond_init (&cancellation_barrier.cond);
  WylServiceCredentialOperationHandoffCancelRuntime cancel_runtime = {
    .session = operator_session,
    .authenticated_actor_subject_id = "operator",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = decision_request_id,
    .after_authorization = handoff_authorization_barrier,
    .authorization_checkpoint_data = &cancellation_barrier,
  };
  HandoffCancelCall cancel_call = {
    .handle = handle,
    .storage = &storage,
    .anchor = &anchor,
    .request_id = original_request_id,
    .request = &request,
    .runtime = &cancel_runtime,
    .rc = WYRELOG_E_INTERNAL,
  };
  GThread *canceller = g_thread_new ("handoff-cancel-first",
      handoff_cancel_thread, &cancel_call);
  g_mutex_lock (&cancellation_barrier.mutex);
  while (!cancellation_barrier.entered)
    g_cond_wait (&cancellation_barrier.cond, &cancellation_barrier.mutex);
  g_mutex_unlock (&cancellation_barrier.mutex);

  CancellationContentionProbe probe = { 0 };
  g_mutex_init (&probe.mutex);
  g_cond_init (&probe.cond);
  const WyctlPublicationBackendVTable publication = {
    .plan = contention_plan,
    .stage_exact = contention_stage,
    .receipt_target_acquire = contention_target_acquire,
    .receipt_target_inspect = contention_target_operation,
    .receipt_target_commit = contention_target_operation,
    .receipt_target_release = contention_target_release,
  };
  WylServiceCredentialOperationHandoffExecuteRuntime execute_runtime = {
    .session = original_session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = original_request_id,
    .publication = &publication,
    .publication_data = &probe,
    .now_us = contention_clock,
    .clock_data = &probe,
    .after_authorization = contention_authorization,
    .authorization_checkpoint_data = &probe,
  };
  ContendedExecuteCall execute_call = {
    .execute = {
          .handle = handle,
          .storage = &storage,
          .anchor = &anchor,
          .request_id = original_request_id,
          .runtime = &execute_runtime,
          .outcome = WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT,
          .rc = WYRELOG_E_INTERNAL,
        },
    .probe = &probe,
    .first_rc = WYRELOG_E_INTERNAL,
  };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      contention_unseal, &probe);
  GThread *executor = g_thread_new ("handoff-execute-after-cancel",
      contended_execute_thread, &execute_call);
  g_mutex_lock (&probe.mutex);
  while (!probe.first_attempt_done)
    g_cond_wait (&probe.cond, &probe.mutex);
  g_assert_false (probe.executor_done);
  g_assert_cmpuint (probe.publication_calls, ==, 0);
  g_assert_cmpuint (probe.authorization_calls, ==, 0);
  g_assert_cmpuint (probe.clock_calls, ==, 0);
  g_assert_cmpuint (probe.unseal_calls, ==, 0);
  g_mutex_unlock (&probe.mutex);
  g_assert_cmpint (execute_call.first_rc, ==, WYRELOG_E_BUSY);

  g_mutex_lock (&cancellation_barrier.mutex);
  cancellation_barrier.release = TRUE;
  g_cond_broadcast (&cancellation_barrier.cond);
  g_mutex_unlock (&cancellation_barrier.mutex);
  g_thread_join (canceller);
  g_mutex_lock (&probe.mutex);
  probe.retry_allowed = TRUE;
  g_cond_broadcast (&probe.cond);
  g_mutex_unlock (&probe.mutex);
  g_thread_join (executor);
  g_assert_cmpint (cancel_call.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (execute_call.execute.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (execute_call.execute.outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_mutex_lock (&probe.mutex);
  g_assert_true (probe.executor_done);
  g_assert_cmpuint (probe.publication_calls, ==, 0);
  g_assert_cmpuint (probe.authorization_calls, ==, 0);
  g_assert_cmpuint (probe.clock_calls, ==, 0);
  g_assert_cmpuint (probe.unseal_calls, ==, 0);
  g_mutex_unlock (&probe.mutex);
  g_autoptr (GBytes) journal_after = read_handoff_journal_bytes
      (operation_root, original_request_id);
  g_assert_true (g_bytes_equal (journal_before, journal_after));

  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  wyl_service_credential_handoff_cancellation_result_clear
      (&cancel_call.result);
  wyl_service_credential_operation_record_clear (&execute_call.execute.outcome);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_coordinator_request_clear (&operation);
  g_cond_clear (&probe.cond);
  g_mutex_clear (&probe.mutex);
  g_cond_clear (&cancellation_barrier.cond);
  g_mutex_clear (&cancellation_barrier.mutex);
  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

static void
test_cancellation_state_matrix (void)
{
  static const WylServiceCredentialOperationState committed_states[] = {
    WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED,
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED,
  };
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  sqlite3 *db = db_of (handle);
  prepare_authority (handle, "svc:handoff:executor");
  g_autofree gchar *operation_root = g_build_filename (fixture.dir,
      "cancel-state-operations", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_autoptr (WylSession) operator_session =
      handoff_human_session_new ("operator", "tenant-a");
  g_autofree gchar *operator_session_id =
      wyl_session_dup_id_string (operator_session);
  set_handoff_permission (handle, "operator", operator_session_id, TRUE);
  guint authorization_calls = 0;
  WylServiceCredentialOperationHandoffCancelRuntime runtime = {
    .session = operator_session,
    .authenticated_actor_subject_id = "operator",
    .guard_timestamp = g_get_real_time (),
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .after_authorization = count_handoff_authorization,
    .authorization_checkpoint_data = &authorization_calls,
  };

  for (gsize i = 0; i < G_N_ELEMENTS (committed_states); i++) {
    gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar disposition_id[WYL_ID_STRING_BUF];
    gchar audit_id[WYL_ID_STRING_BUF];
    wyl_id_t escrow;
    WylServiceCredentialOperationCoordinatorRequest operation =
        WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
    WylServiceCredentialOperationRecord record =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    WylServiceCredentialOperationHandoffCancelRequest request;
    materialize_handoff_state_for_maintenance (handle, &storage, &anchor,
        g_get_real_time () + (gint64) i * 10, committed_states[i],
        original_request_id, &escrow, &operation, &record);
    cancel_request_ids_new (&request, cancellation_request_id,
        decision_request_id, disposition_id, audit_id);
    runtime.decision_request_id = decision_request_id;
    g_autoptr (GBytes) before = read_handoff_journal_bytes (operation_root,
        original_request_id);
    wyl_service_credential_handoff_cancellation_result_t result = { 0 };
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
            &storage, &anchor, original_request_id, &request, &runtime,
            &result), ==, WYRELOG_E_OK);
    g_assert_false (result.replayed);
    g_assert_cmpstr (result.disposition_id, ==, disposition_id);
    g_assert_cmpstr (result.audit_id, ==, audit_id);
    g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==,
        1);
    g_assert_cmpint (count_handoff_rows_for_request (db, original_request_id,
            "operation_cancelled"), ==, 1);
    g_assert_cmpint (count_cancellation_audits (db,
            cancellation_request_id), ==, 1);
    g_autoptr (GBytes) after = read_handoff_journal_bytes (operation_root,
        original_request_id);
    g_assert_true (g_bytes_equal (before, after));
    wyl_service_credential_handoff_cancellation_result_clear (&result);
    wyl_service_credential_operation_record_clear (&record);
    wyl_service_credential_operation_coordinator_request_clear (&operation);
  }
  g_assert_cmpuint (authorization_calls, ==, G_N_ELEMENTS (committed_states));

  /* Non-committed, OAR, and terminal journals are rejected before a fresh
   * domain authorization callback can append a claim. */
  static const WylServiceCredentialOperationState rejected_states[] = {
    WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED,
    WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED,
    WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED,
    WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED,
    WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (rejected_states); i++) {
    gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
    gchar disposition_id[WYL_ID_STRING_BUF];
    gchar audit_id[WYL_ID_STRING_BUF];
    wyl_id_t escrow;
    WylServiceCredentialOperationCoordinatorRequest operation =
        WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
    WylServiceCredentialOperationRecord record =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    WylServiceCredentialOperationRecord rejected =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    gboolean replayed = FALSE;
    gint64 state_now = g_get_real_time () + 100 + (gint64) i * 10;
    if (rejected_states[i] == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED) {
      begin_handoff_issue_for_test (&storage, &anchor, state_now,
          original_request_id, &escrow, &operation, &record);
    } else {
      WylServiceCredentialOperationState source = rejected_states[i];
      if (rejected_states[i] ==
          WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED)
        source = WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED;
      else if (rejected_states[i] == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL)
        source = WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED;
      materialize_handoff_state_for_maintenance (handle, &storage, &anchor,
          state_now, source, original_request_id, &escrow, &operation, &record);
      if (rejected_states[i] ==
          WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED
          || rejected_states[i] == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL) {
        wyrelog_error_t checkpoint_rc = rejected_states[i] ==
            WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL ?
            wyl_service_credential_operation_coordinator_checkpoint_terminal_file_published
            (&storage, &anchor, original_request_id, state_now + 10,
            &replayed, &rejected) :
            wyl_service_credential_operation_coordinator_checkpoint_successor_inactive_oar
            (&storage, &anchor, original_request_id,
            WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_REVOKED,
            state_now + 10, &replayed, &rejected);
        g_assert_cmpint (checkpoint_rc, ==, WYRELOG_E_OK);
        wyl_service_credential_operation_record_clear (&record);
        record = rejected;
        rejected = (WylServiceCredentialOperationRecord)
            WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
      }
    }
    g_assert_cmpint (record.state, ==, rejected_states[i]);
    WylServiceCredentialOperationHandoffCancelRequest request;
    cancel_request_ids_new (&request, cancellation_request_id,
        decision_request_id, disposition_id, audit_id);
    runtime.decision_request_id = decision_request_id;
    guint calls_before = authorization_calls;
    wyl_service_credential_handoff_cancellation_result_t result = { 0 };
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
            &storage, &anchor, original_request_id, &request, &runtime,
            &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpuint (authorization_calls, ==, calls_before);
    g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==,
        0);
    g_assert_cmpint (count_handoff_rows_for_request (db, original_request_id,
            "operation_cancelled"), ==, 0);
    g_assert_cmpint (count_cancellation_audits (db,
            cancellation_request_id), ==, 0);
    wyl_service_credential_operation_record_clear (&rejected);
    wyl_service_credential_operation_record_clear (&record);
    wyl_service_credential_operation_coordinator_request_clear (&operation);
  }

  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

static void
test_authenticated_cancellation_and_executor_gate (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  wyl_policy_store_t *store = store_of (handle);
  sqlite3 *db = db_of (handle);
  prepare_authority (handle, "svc:handoff:executor");

  g_autofree gchar *operation_root = g_build_filename (fixture.dir,
      "cancel-operations", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);

  gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t escrow;
  WylServiceCredentialOperationCoordinatorRequest operation =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gint64 now = g_get_real_time ();
  materialize_handoff_state_for_maintenance (handle, &storage, &anchor, now,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
      original_request_id, &escrow, &operation, &committed);
  g_autoptr (GBytes) journal_before = read_handoff_journal_bytes
      (operation_root, original_request_id);

  g_autoptr (WylSession) operator_session =
      handoff_human_session_new ("operator", "tenant-a");
  g_autofree gchar *operator_session_id =
      wyl_session_dup_id_string (operator_session);
  gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  fresh_request_id (cancellation_request_id);
  fresh_request_id (decision_request_id);
  fresh_uuid (disposition_id);
  fresh_uuid (audit_id);
  WylServiceCredentialOperationHandoffCancelRequest request = {
    .cancellation_request_id = cancellation_request_id,
    .disposition_id = disposition_id,
    .audit_id = audit_id,
  };
  guint cancellation_authorizations = 0;
  WylServiceCredentialOperationHandoffCancelRuntime runtime = {
    .session = operator_session,
    .authenticated_actor_subject_id = "operator",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = decision_request_id,
    .after_authorization = count_handoff_authorization,
    .authorization_checkpoint_data = &cancellation_authorizations,
  };
  wyl_service_credential_handoff_cancellation_result_t result = { 0 };

  /* Transport cancellation is not a durable cancellation claim. */
  g_autoptr (GCancellable) cancelled = g_cancellable_new ();
  g_cancellable_cancel (cancelled);
  runtime.cancellable = cancelled;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
          &storage, &anchor, original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (cancellation_authorizations, ==, 0);
  g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==, 0);
  g_assert_cmpint (count_handoff_rows_for_request (db, original_request_id,
          "operation_cancelled"), ==, 0);
  g_assert_cmpint (count_cancellation_audits (db,
          cancellation_request_id), ==, 0);
  runtime.cancellable = NULL;

  /* A fresh decision denial leaves every durable cancellation row absent. */
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
          &storage, &anchor, original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (cancellation_authorizations, ==, 0);
  g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==, 0);
  g_assert_cmpint (count_handoff_rows_for_request (db, original_request_id,
          "operation_cancelled"), ==, 0);

  set_handoff_permission (handle, "operator", operator_session_id, TRUE);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
          &storage, &anchor, original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_OK);
  g_assert_false (result.replayed);
  g_assert_cmpstr (result.disposition_id, ==, disposition_id);
  g_assert_cmpstr (result.audit_id, ==, audit_id);
  g_assert_cmpint (result.created_at_us, >, 0);
  g_assert_cmpuint (cancellation_authorizations, ==, 1);
  g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==, 1);
  g_assert_cmpint (count_handoff_rows_for_request (db, original_request_id,
          "operation_cancelled"), ==, 1);
  g_assert_cmpint (count_cancellation_audits (db,
          cancellation_request_id), ==, 1);
  g_autoptr (GBytes) journal_after = read_handoff_journal_bytes
      (operation_root, original_request_id);
  g_assert_true (g_bytes_equal (journal_before, journal_after));
  wyl_service_credential_handoff_cancellation_result_clear (&result);

  /* Even an exact durable replay is refused after current authority loss. */
  set_handoff_permission (handle, "operator", operator_session_id, FALSE);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
          &storage, &anchor, original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (cancellation_authorizations, ==, 1);
  g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==, 1);
  set_handoff_permission (handle, "operator", operator_session_id, TRUE);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
          &storage, &anchor, original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result.replayed);
  g_assert_cmpuint (cancellation_authorizations, ==, 2);
  g_assert_cmpint (count_cancellation_claims (db, original_request_id), ==, 1);
  g_assert_cmpint (count_handoff_rows_for_request (db, original_request_id,
          "operation_cancelled"), ==, 1);
  wyl_service_credential_handoff_cancellation_result_clear (&result);

  /* The unchanged journal is now stopped by maintenance ATTENTION before the
   * original actor's runtime, auth, unseal, or publication callbacks. */
  g_autoptr (WylSession) original_session =
      handoff_human_session_new ("admin", "tenant-a");
  g_autofree gchar *original_session_id =
      wyl_session_dup_id_string (original_session);
  set_handoff_permission (handle, "admin", original_session_id, TRUE);
  HandoffPublication publication = {.store = store };
  HandoffUnsealGate unseal = {.rc = WYRELOG_E_IO };
  CountingHandoffClock clock = {.value = now };
  guint execution_authorizations = 0;
  const WyctlPublicationBackendVTable publication_vtable = {
    .plan = handoff_test_plan,
    .stage_exact = handoff_test_stage,
    .receipt_target_acquire = handoff_test_target_acquire,
    .receipt_target_inspect = handoff_test_target_inspect,
    .receipt_target_commit = handoff_test_target_commit,
    .receipt_target_release = handoff_test_target_release,
  };
  WylServiceCredentialOperationHandoffExecuteRuntime execute_runtime = {
    .session = original_session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = original_request_id,
    .publication = &publication_vtable,
    .publication_data = &publication,
    .now_us = counting_handoff_now,
    .clock_data = &clock,
    .after_authorization = count_handoff_authorization,
    .authorization_checkpoint_data = &execution_authorizations,
  };
  WylServiceCredentialOperationRecord stopped =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &unseal);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, original_request_id, &execute_runtime,
          &stopped), ==, WYRELOG_E_OK);
  g_assert_cmpint (stopped.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  assert_no_handoff_execution_callbacks (&publication, &unseal,
      execution_authorizations, &clock);
  g_autoptr (GBytes) journal_stopped = read_handoff_journal_bytes
      (operation_root, original_request_id);
  g_assert_true (g_bytes_equal (journal_before, journal_stopped));

  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  wyl_service_credential_operation_record_clear (&stopped);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_coordinator_request_clear (&operation);
  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-credential-operation-cancel/state-matrix",
      test_cancellation_state_matrix);
  g_test_add_func ("/service-credential-operation-cancel/tenant-binding",
      test_cancellation_tenant_binding);
  g_test_add_func ("/service-credential-operation-cancel/lifecycle-contention",
      test_cancellation_lifecycle_contention);
  g_test_add_func ("/service-credential-operation-cancel/auth-replay-gate",
      test_authenticated_cancellation_and_executor_gate);
  return g_test_run ();
}

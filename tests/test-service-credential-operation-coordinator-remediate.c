/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-cancel-private.h"
#include "auth/service-credential-operation-coordinator-remediate-private.h"

#ifdef G_OS_WIN32
#include <windows.h>
#endif

#define main handoff_execute_fixture_main
#include "test-service-credential-operation-coordinator-execute.c"
#undef main

static void
remediation_fresh_uuid (gchar out[WYL_ID_STRING_BUF])
{
  wyl_id_t id;
  g_assert_cmpint (wyl_id_new (&id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&id, out, WYL_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
}

static void
remediation_set_permission (WylHandle *handle, const gchar *actor,
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

typedef struct
{
  gchar original_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar cancellation_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar cancellation_decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar source_audit_id[WYL_ID_STRING_BUF];
  wyl_id_t escrow_id;
  WylServiceCredentialOperationCoordinatorRequest operation;
  WylServiceCredentialOperationRecord record;
  wyl_service_credential_handoff_cancellation_result_t cancellation;
} RemediationAttention;

static void
remediation_attention_clear (RemediationAttention *attention)
{
  wyl_service_credential_handoff_cancellation_result_clear
      (&attention->cancellation);
  wyl_service_credential_operation_record_clear (&attention->record);
  wyl_service_credential_operation_coordinator_request_clear
      (&attention->operation);
  sodium_memzero (attention, sizeof *attention);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (RemediationAttention,
    remediation_attention_clear);

static void
remediation_attention_init (WylHandle *handle,
    const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    WylSession *operator_session, gint64 now_us,
    WylServiceCredentialOperationState state, RemediationAttention *attention)
{
  memset (attention, 0, sizeof *attention);
  attention->operation = (WylServiceCredentialOperationCoordinatorRequest)
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  attention->record = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  materialize_handoff_state_for_maintenance (handle, storage, anchor, now_us,
      state, attention->original_request_id, &attention->escrow_id,
      &attention->operation, &attention->record);
  fresh_request_id (attention->cancellation_request_id);
  fresh_request_id (attention->cancellation_decision_id);
  remediation_fresh_uuid (attention->disposition_id);
  remediation_fresh_uuid (attention->source_audit_id);
  WylServiceCredentialOperationHandoffCancelRequest request = {
    .cancellation_request_id = attention->cancellation_request_id,
    .disposition_id = attention->disposition_id,
    .audit_id = attention->source_audit_id,
  };
  WylServiceCredentialOperationHandoffCancelRuntime runtime = {
    .session = operator_session,
    .authenticated_actor_subject_id = "operator",
    .guard_timestamp = now_us,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = attention->cancellation_decision_id,
  };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_cancel_handoff (handle,
          storage, anchor, attention->original_request_id, &request, &runtime,
          &attention->cancellation), ==, WYRELOG_E_OK);
  g_assert_cmpint (attention->cancellation.outcome, ==,
      WYL_SERVICE_HANDOFF_CANCELLATION_COMMITTED_ATTENTION);
}

static void
    remediation_request_init
    (WylServiceCredentialOperationHandoffRemediationRequest * request,
    gchar remediation_id[WYL_REQUEST_ID_STRING_BUF],
    gchar decision_id[WYL_REQUEST_ID_STRING_BUF],
    gchar audit_id[WYL_ID_STRING_BUF],
    wyl_service_credential_handoff_remediation_action_t action)
{
  fresh_request_id (remediation_id);
  fresh_request_id (decision_id);
  remediation_fresh_uuid (audit_id);
  *request = (WylServiceCredentialOperationHandoffRemediationRequest) {
  .remediation_request_id = remediation_id,.audit_id = audit_id,.action =
        action,.confirmation_version =
        action ==
        WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE ? 1 : 0,.confirmed =
        action == WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE,};
}

static WylServiceCredentialOperationHandoffRemediationRuntime
remediation_runtime (WylSession *session, const gchar *decision_id,
    guint *authorization_calls)
{
  return (WylServiceCredentialOperationHandoffRemediationRuntime) {
  .session = session,.authenticated_actor_subject_id =
        "operator",.guard_timestamp = g_get_real_time (),.guard_loc_class =
        "trusted",.guard_risk = 0,.decision_request_id =
        decision_id,.after_authorization =
        count_handoff_authorization,.authorization_checkpoint_data =
        authorization_calls,};
}

static void
test_authenticated_resume_replay_and_new_epoch (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autofree gchar *operation_root =
      service_credential_operation_root_for_test (fixture.dir,
      "remediation-resume-operations");
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_autoptr (WylSession) session =
      handoff_human_session_new ("operator", "tenant-a");
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  remediation_set_permission (handle, "operator", session_id, TRUE);
  g_auto (RemediationAttention) attention = { 0 };
  gint64 now_us = g_get_real_time ();
  remediation_attention_init (handle, &storage, &anchor, session, now_us,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED, &attention);

  gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  WylServiceCredentialOperationHandoffRemediationRequest request;
  remediation_request_init (&request, remediation_id, decision_id, audit_id,
      WYL_SERVICE_HANDOFF_REMEDIATION_RESUME);
  guint authorization_calls = 0;
  WylServiceCredentialOperationHandoffRemediationRuntime runtime =
      remediation_runtime (session, decision_id, &authorization_calls);
  WylServiceCredentialOperationHandoffRemediationResult result =
      WYL_SERVICE_CREDENTIAL_OPERATION_HANDOFF_REMEDIATION_RESULT_INIT;
  gboolean tenant_created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store_of (handle),
          "tenant-b", &tenant_created), ==, WYRELOG_E_OK);
  g_assert_true (tenant_created);
  g_autoptr (WylSession) cross_tenant_session =
      handoff_human_session_new ("operator", "tenant-b");
  g_autofree gchar *cross_tenant_session_id =
      wyl_session_dup_id_string (cross_tenant_session);
  remediation_set_permission (handle, "operator", cross_tenant_session_id,
      TRUE);
  guint cross_tenant_authorizations = 0;
  WylServiceCredentialOperationHandoffRemediationRuntime cross_runtime =
      remediation_runtime (cross_tenant_session, decision_id,
      &cross_tenant_authorizations);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request,
          &cross_runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (cross_tenant_authorizations, ==, 0);
  g_assert_null (result.remediation_request_id);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (authorization_calls, ==, 1);
  g_assert_false (result.authority_replayed);
  g_assert_false (result.journal_replayed);
  g_assert_cmpstr (result.remediation_request_id, ==, remediation_id);
  g_assert_cmpstr (result.audit_id, ==, audit_id);
  g_assert_cmpint (result.source_kind, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION);
  g_assert_cmpint (result.source_reason, ==,
      WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED);
  g_assert_cmpint (result.checkpoint_state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpint (result.checkpoint_target_state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  wyl_service_credential_operation_handoff_remediation_result_clear (&result);

  g_autoptr (GBytes) journal_before_denial =
      read_handoff_journal_bytes (operation_root,
      attention.original_request_id);
  remediation_set_permission (handle, "operator", session_id, FALSE);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (authorization_calls, ==, 1);
  g_assert_null (result.remediation_request_id);
  g_autoptr (GBytes) journal_after_denial =
      read_handoff_journal_bytes (operation_root,
      attention.original_request_id);
  g_assert_true (g_bytes_equal (journal_before_denial, journal_after_denial));
  remediation_set_permission (handle, "operator", session_id, TRUE);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (authorization_calls, ==, 2);
  g_assert_true (result.authority_replayed);
  g_assert_true (result.journal_replayed);
  wyl_service_credential_operation_handoff_remediation_result_clear (&result);

  gchar different_audit[WYL_ID_STRING_BUF];
  remediation_fresh_uuid (different_audit);
  request.audit_id = different_audit;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (authorization_calls, ==, 3);
  g_assert_null (result.remediation_request_id);
  request.audit_id = audit_id;

  WylServiceCredentialOperationRecord oar =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean checkpoint_replayed = TRUE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_escrow_oar
      (&storage, &anchor, attention.original_request_id,
          WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_UNCERTAIN,
          g_get_real_time () + G_TIME_SPAN_SECOND,
          &checkpoint_replayed, &oar), ==, WYRELOG_E_OK);
  g_assert_false (checkpoint_replayed);
  g_assert_cmpint (oar.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED);

  gchar second_remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar second_decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar second_audit_id[WYL_ID_STRING_BUF];
  remediation_request_init (&request, second_remediation_id,
      second_decision_id, second_audit_id,
      WYL_SERVICE_HANDOFF_REMEDIATION_RESUME);
  runtime.decision_request_id = second_decision_id;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (authorization_calls, ==, 4);
  g_assert_false (result.authority_replayed);
  g_assert_cmpint (result.source_kind, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED);
  g_assert_cmpint (result.oar_cause, ==,
      WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_UNCERTAIN);
  g_assert_cmpstr (result.remediation_request_id, ==, second_remediation_id);
  wyl_service_credential_operation_handoff_remediation_result_clear (&result);

  request.confirmation_version = 1;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (authorization_calls, ==, 4);
  g_assert_null (result.remediation_request_id);

  wyl_service_credential_operation_record_clear (&oar);
  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

typedef struct
{
  guint calls;
  gchar *credential_id;
  guint64 generation;
} RemediationInvalidation;

static wyrelog_error_t
remediation_invalidate (gpointer data, const gchar *credential_id,
    guint64 generation)
{
  RemediationInvalidation *probe = data;
  probe->calls++;
  g_free (probe->credential_id);
  probe->credential_id = g_strdup (credential_id);
  probe->generation = generation;
  return probe->credential_id != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

static void
test_revoke_replay_invalidation (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autofree gchar *operation_root =
      service_credential_operation_root_for_test (fixture.dir,
      "remediation-revoke-operations");
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_autoptr (WylSession) session =
      handoff_human_session_new ("operator", "tenant-a");
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  remediation_set_permission (handle, "operator", session_id, TRUE);
  g_auto (RemediationAttention) attention = { 0 };
  remediation_attention_init (handle, &storage, &anchor, session,
      g_get_real_time (), WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
      &attention);

  gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  WylServiceCredentialOperationHandoffRemediationRequest request;
  remediation_request_init (&request, remediation_id, decision_id, audit_id,
      WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE);
  guint authorization_calls = 0;
  RemediationInvalidation invalidation = { 0 };
  WylServiceCredentialOperationHandoffRemediationRuntime runtime =
      remediation_runtime (session, decision_id, &authorization_calls);
  runtime.invalidate_credential = remediation_invalidate;
  runtime.invalidation_data = &invalidation;
  WylServiceCredentialOperationHandoffRemediationResult result =
      WYL_SERVICE_CREDENTIAL_OPERATION_HANDOFF_REMEDIATION_RESULT_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (authorization_calls, ==, 1);
  g_assert_cmpuint (invalidation.calls, ==, 1);
  g_assert_cmpuint (invalidation.generation, ==, 1);
  g_assert_cmpint (result.checkpoint_state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpint (result.checkpoint_target_state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  wyl_service_credential_operation_handoff_remediation_result_clear (&result);

  wyrelog_error_t revoke_replay_rc =
      wyl_service_credential_operation_coordinator_remediate_handoff (handle,
      &storage, &anchor, attention.original_request_id, &request, &runtime,
      &result);
  g_assert_cmpint (revoke_replay_rc, ==, WYRELOG_E_OK);
  g_assert_cmpuint (authorization_calls, ==, 2);
  g_assert_cmpuint (invalidation.calls, ==, 2);
  g_assert_true (result.authority_replayed);
  g_assert_true (result.journal_replayed);
  wyl_service_credential_operation_handoff_remediation_result_clear (&result);

  g_clear_pointer (&invalidation.credential_id, g_free);
  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

/* Force the post-authorization checkpoint write to fail so remediation
 * converges instead of committing.  On POSIX a non-writable operation root
 * (0500) blocks the atomic temp-create.  On Windows a read-only directory
 * does not gate child creation, so instead mark the target journal file
 * read-only: the checkpoint commits via a FileRenameInformation replace,
 * which cannot overwrite a read-only destination and fails with
 * STATUS_ACCESS_DENIED (mapped to WYRELOG_E_POLICY), leaving it untouched. */
static void
remediation_block_checkpoint_writes (const gchar *operation_root,
    const gchar *request_id)
{
#ifdef G_OS_WIN32
  g_autofree gchar *child = g_strdup_printf ("op-%s", request_id);
  g_autofree gchar *target =
      g_build_filename (operation_root, child, NULL);
  g_autofree gunichar2 *target_utf16 =
      g_utf8_to_utf16 (target, -1, NULL, NULL, NULL);
  g_assert_nonnull (target_utf16);
  DWORD attrs = GetFileAttributesW ((wchar_t *) target_utf16);
  g_assert_cmpuint (attrs, !=, INVALID_FILE_ATTRIBUTES);
  g_assert_true (SetFileAttributesW ((wchar_t *) target_utf16,
          attrs | FILE_ATTRIBUTE_READONLY));
#else
  (void) request_id;
  g_assert_cmpint (g_chmod (operation_root, 0500), ==, 0);
#endif
}

static void
remediation_unblock_checkpoint_writes (const gchar *operation_root,
    const gchar *request_id)
{
#ifdef G_OS_WIN32
  g_autofree gchar *child = g_strdup_printf ("op-%s", request_id);
  g_autofree gchar *target =
      g_build_filename (operation_root, child, NULL);
  g_autofree gunichar2 *target_utf16 =
      g_utf8_to_utf16 (target, -1, NULL, NULL, NULL);
  g_assert_nonnull (target_utf16);
  DWORD attrs = GetFileAttributesW ((wchar_t *) target_utf16);
  g_assert_cmpuint (attrs, !=, INVALID_FILE_ATTRIBUTES);
  g_assert_true (SetFileAttributesW ((wchar_t *) target_utf16,
          attrs & ~FILE_ATTRIBUTE_READONLY));
#else
  (void) request_id;
  g_assert_cmpint (g_chmod (operation_root, 0700), ==, 0);
#endif
}

typedef struct
{
  const gchar *operation_root;
  const gchar *original_request_id;
  guint *authorization_calls;
} CrashCheckpoint;

static void
deny_checkpoint_after_authorization (gpointer data)
{
  CrashCheckpoint *checkpoint = data;
  (*checkpoint->authorization_calls)++;
  remediation_block_checkpoint_writes (checkpoint->operation_root,
      checkpoint->original_request_id);
}

static void
test_authority_before_checkpoint_converges (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autofree gchar *operation_root =
      service_credential_operation_root_for_test (fixture.dir,
      "remediation-crash-operations");
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  g_autoptr (WylSession) session =
      handoff_human_session_new ("operator", "tenant-a");
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  remediation_set_permission (handle, "operator", session_id, TRUE);
  g_auto (RemediationAttention) attention = { 0 };
  remediation_attention_init (handle, &storage, &anchor, session,
      g_get_real_time (), WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
      &attention);

  gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  WylServiceCredentialOperationHandoffRemediationRequest request;
  remediation_request_init (&request, remediation_id, decision_id, audit_id,
      WYL_SERVICE_HANDOFF_REMEDIATION_RESUME);
  guint authorization_calls = 0;
  WylServiceCredentialOperationHandoffRemediationRuntime runtime =
      remediation_runtime (session, decision_id, &authorization_calls);
  CrashCheckpoint checkpoint = {
    .operation_root = operation_root,
    .original_request_id = attention.original_request_id,
    .authorization_calls = &authorization_calls,
  };
  runtime.after_authorization = deny_checkpoint_after_authorization;
  runtime.authorization_checkpoint_data = &checkpoint;
  WylServiceCredentialOperationHandoffRemediationResult result =
      WYL_SERVICE_CREDENTIAL_OPERATION_HANDOFF_REMEDIATION_RESULT_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_null (result.remediation_request_id);
  g_assert_cmpuint (authorization_calls, ==, 1);
  remediation_unblock_checkpoint_writes (operation_root,
      attention.original_request_id);
  g_autoptr (GBytes) journal_after_crash =
      read_handoff_journal_bytes (operation_root,
      attention.original_request_id);

  gchar other_remediation_id[WYL_REQUEST_ID_STRING_BUF];
  gchar other_decision_id[WYL_REQUEST_ID_STRING_BUF];
  gchar other_audit_id[WYL_ID_STRING_BUF];
  WylServiceCredentialOperationHandoffRemediationRequest other_request;
  remediation_request_init (&other_request, other_remediation_id,
      other_decision_id, other_audit_id,
      WYL_SERVICE_HANDOFF_REMEDIATION_RESUME);
  WylServiceCredentialOperationHandoffRemediationRuntime other_runtime =
      remediation_runtime (session, other_decision_id, &authorization_calls);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &other_request,
          &other_runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (authorization_calls, ==, 2);
  g_assert_null (result.remediation_request_id);
  g_autoptr (GBytes) journal_after_other_request =
      read_handoff_journal_bytes (operation_root,
      attention.original_request_id);
  g_assert_true (g_bytes_equal (journal_after_crash,
          journal_after_other_request));

  gchar tampered_audit_id[WYL_ID_STRING_BUF];
  remediation_fresh_uuid (tampered_audit_id);
  WylServiceCredentialOperationHandoffRemediationRequest tampered_request =
      request;
  tampered_request.audit_id = tampered_audit_id;
  runtime.after_authorization = count_handoff_authorization;
  runtime.authorization_checkpoint_data = &authorization_calls;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &tampered_request,
          &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (authorization_calls, ==, 3);
  g_assert_null (result.remediation_request_id);
  g_autoptr (GBytes) journal_after_tampered_request =
      read_handoff_journal_bytes (operation_root,
      attention.original_request_id);
  g_assert_true (g_bytes_equal (journal_after_crash,
          journal_after_tampered_request));

  WylServiceCredentialOperationHandoffRemediationRequest tampered_action =
      request;
  tampered_action.action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE;
  tampered_action.confirmation_version = 1;
  tampered_action.confirmed = TRUE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &tampered_action,
          &runtime, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (authorization_calls, ==, 4);
  g_assert_null (result.remediation_request_id);
  g_autoptr (GBytes) journal_after_tampered_action =
      read_handoff_journal_bytes (operation_root,
      attention.original_request_id);
  g_assert_true (g_bytes_equal (journal_after_crash,
          journal_after_tampered_action));

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_remediate_handoff (handle,
          &storage, &anchor, attention.original_request_id, &request, &runtime,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpuint (authorization_calls, ==, 5);
  g_assert_true (result.authority_replayed);
  g_assert_false (result.journal_replayed);
  g_assert_cmpint (result.checkpoint_state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpint (result.checkpoint_target_state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);

  wyl_service_credential_operation_handoff_remediation_result_clear (&result);
  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func
      ("/service-credential-operation-remediate/resume-replay-epoch",
      test_authenticated_resume_replay_and_new_epoch);
  g_test_add_func ("/service-credential-operation-remediate/revoke-replay",
      test_revoke_replay_invalidation);
  g_test_add_func ("/service-credential-operation-remediate/crash-converges",
      test_authority_before_checkpoint_converges);
  return g_test_run ();
}

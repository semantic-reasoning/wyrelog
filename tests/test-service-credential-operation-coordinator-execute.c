/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <sqlite3.h>
#include <string.h>

#include "auth/service-credential-operation-coordinator-execute-private.h"
#include "auth/service-credential-operation-coordinator-maintenance-private.h"
#include "auth/service-auth-coordination-private.h"
#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "auth/service-credential-domain-private.h"
#include "auth/service-credential-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyl-session-layout-private.h"
#include "wyl-request-id-private.h"
#include "../wyrelog/wyctl/wyctl-publication-private.h"

#define ROTATE_CANONICAL_ID "wlc_000000000000000000000000000"

#ifdef WYL_HAS_AUDIT
#define HANDOFF_DECISION_AUDIT_DELTA(n) (n)
#else
#define HANDOFF_DECISION_AUDIT_DELTA(n) 0
#endif

typedef struct
{
  WylHandle *handle;
  gchar *dir;
  gchar *db_path;
  gchar *audit_path;
  gchar *key_path;
  gchar *key_spec;
} Fixture;

typedef struct
{
  WylHandle *handle;
  guint calls;
  wyrelog_error_t rc;
  gchar *seen_actor;
  gboolean saw_write_lease;
} Stub;

static wyl_policy_store_t *store_of (WylHandle * handle);
static sqlite3 *db_of (WylHandle * handle);
static gint64 scalar (sqlite3 * db, const gchar * sql);
static void prepare_authority (WylHandle * handle, const gchar * subject_id);
static void fresh_request_id (gchar * buf);
static void fresh_execute_uuid (gchar out[WYL_ID_STRING_BUF]);
static gint64 count_credentials (sqlite3 * db);
static gint64 count_events (sqlite3 * db);

static wyrelog_error_t
stub_revalidate (gpointer data, const gchar *actor_subject_id)
{
  Stub *stub = data;
  stub->calls++;
  g_free (stub->seen_actor);
  stub->seen_actor = g_strdup (actor_subject_id);
  if (stub->handle != NULL) {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_service_auth_authority_snapshot
        (wyl_handle_get_service_auth_authority (stub->handle), &snapshot);
    stub->saw_write_lease = snapshot.writer_active;
  }
  return stub->rc;
}

static wyrelog_error_t
allow_handoff_mutation (gpointer data, const gchar *actor_subject_id)
{
  (void) data;
  return g_strcmp0 (actor_subject_id, "admin") == 0 ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
allow_operator_remediation (gpointer data, const gchar *actor_subject_id)
{
  (void) data;
  return g_strcmp0 (actor_subject_id, "operator") == 0 ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

typedef struct
{
  gint64 value;
  guint calls;
} CountingHandoffClock;

static gint64
counting_handoff_now (gpointer data)
{
  CountingHandoffClock *clock = data;
  clock->calls++;
  return clock->value;
}

static void
count_handoff_authorization (gpointer data)
{
  guint *calls = data;
  (*calls)++;
}

static void
fixture_clear (Fixture *fixture)
{
  g_clear_object (&fixture->handle);
  if (fixture->db_path != NULL) {
    (void) g_remove (fixture->db_path);
    g_autofree gchar *clear = g_strdup_printf ("%s.wyrelog-clear",
        fixture->db_path);
    g_autofree gchar *lock = g_strdup_printf ("%s.wyrelog-lock",
        fixture->db_path);
    (void) g_remove (clear);
    (void) g_remove (lock);
  }
  if (fixture->key_path != NULL)
    (void) g_remove (fixture->key_path);
  if (fixture->audit_path != NULL)
    (void) g_remove (fixture->audit_path);
  if (fixture->dir != NULL)
    (void) g_rmdir (fixture->dir);
  g_free (fixture->key_spec);
  g_free (fixture->key_path);
  g_free (fixture->audit_path);
  g_free (fixture->db_path);
  g_free (fixture->dir);
  memset (fixture, 0, sizeof (*fixture));
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Fixture, fixture_clear);

static void
fixture_init (Fixture *fixture)
{
  fixture->dir = g_dir_make_tmp ("wyl-credential-execute-XXXXXX", NULL);
  g_assert_nonnull (fixture->dir);
  fixture->db_path = g_build_filename (fixture->dir, "policy.db", NULL);
  fixture->key_path = g_build_filename (fixture->dir, "policy.key", NULL);
  fixture->audit_path = g_build_filename (fixture->dir, "audit.db", NULL);
  guint8 key[32];
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) (i + 1);
  g_assert_true (g_file_set_contents (fixture->key_path,
          (const gchar *) key, sizeof key, NULL));
  fixture->key_spec = g_strdup_printf ("file:%s", fixture->key_path);
  WylHandleOpenOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = fixture->db_path,
    .policy_keyprovider_path = fixture->key_spec,
    .audit_store_path = fixture->audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &fixture->handle),
      ==, WYRELOG_E_OK);
}

typedef struct
{
  wyl_policy_store_t *store;
  guint plan_calls;
  guint stage_calls;
  guint preflight_calls;
  guint inspect_calls;
  guint commit_calls;
  guint active_leases;
  guint release_calls;
  gboolean published;
  gboolean foreign_stage;
  gboolean foreign_receipt;
  gboolean fail_plan_once;
  gboolean fail_commit_after_publish_once;
  guint fail_release_after_on_inspect_call;
  guint fail_handoff_after_on_inspect_call;
  WylPolicyServiceHandoffFailStage fail_handoff_stage;
  guint foreign_after_inspect_call;
  guint revoke_after_inspect_call;
  const gchar *revoke_request_id;
  wyrelog_error_t revoke_rc;
} HandoffPublication;

typedef struct
{
  HandoffPublication *owner;
  gboolean destination_target;
} HandoffTargetLease;

typedef struct
{
  guint calls;
  wyrelog_error_t rc;
  HandoffPublication *publication;
  gboolean replace_on_call;
} HandoffUnsealGate;

static wyrelog_error_t
handoff_unseal_gate (gpointer data)
{
  HandoffUnsealGate *gate = data;
  gate->calls++;
  if (gate->replace_on_call && gate->publication != NULL)
    gate->publication->foreign_receipt = TRUE;
  return gate->rc;
}

typedef struct
{
  GMutex mutex;
  GCond cond;
  gboolean entered;
  gboolean release;
  guint calls;
} HandoffAuthorizationBarrier;

static void
handoff_authorization_barrier (gpointer data)
{
  HandoffAuthorizationBarrier *barrier = data;
  g_mutex_lock (&barrier->mutex);
  barrier->calls++;
  if (!barrier->entered) {
    barrier->entered = TRUE;
    g_cond_broadcast (&barrier->cond);
    while (!barrier->release)
      g_cond_wait (&barrier->cond, &barrier->mutex);
  }
  g_mutex_unlock (&barrier->mutex);
}

typedef struct
{
  WylHandle *handle;
  const WylServiceCredentialOperationStorage *storage;
  const WylServiceCredentialOperationRootAnchor *anchor;
  const gchar *request_id;
  WylServiceCredentialOperationHandoffExecuteRuntime *runtime;
  WylServiceCredentialOperationRecord outcome;
  wyrelog_error_t rc;
} HandoffExecuteCall;

static gpointer
handoff_execute_thread (gpointer data)
{
  HandoffExecuteCall *call = data;
  call->rc = wyl_service_credential_operation_coordinator_execute_handoff
      (call->handle, call->storage, call->anchor, call->request_id,
      call->runtime, &call->outcome);
  return NULL;
}

typedef struct
{
  WylHandle *handle;
  const gchar *session_id;
  wyrelog_error_t rc;
} HandoffRevokeCall;

static gpointer
handoff_revoke_thread (gpointer data)
{
  HandoffRevokeCall *call = data;
  WylServiceAuthWriteLease *lease = NULL;
  wyl_policy_store_t *store = NULL;
  call->rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (call->handle), call->handle,
      NULL, &lease);
  if (call->rc == WYRELOG_E_OK)
    call->rc = wyl_service_auth_write_lease_get_policy_store (lease,
        call->handle, &store);
  if (call->rc == WYRELOG_E_OK)
    call->rc = wyl_policy_store_revoke_direct_permission (store, "admin",
        "wr.service_credential.manage", call->session_id);
  if (call->rc == WYRELOG_E_OK)
    call->rc = wyl_handle_reload_engine_pair (call->handle);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (call->rc == WYRELOG_E_OK)
      call->rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  return NULL;
}

static void
copy_plan_for_test (const WyctlPublicationPlan *source,
    WyctlPublicationPlan *out)
{
  *out = (WyctlPublicationPlan) {
  .version = source->version,.destination =
        g_strdup (source->destination),.reservation_id =
        g_strdup (source->reservation_id),.parent_identity =
        g_strdup (source->parent_identity),.stage_basename =
        g_strdup (source->stage_basename),};
}

static wyrelog_error_t
handoff_test_plan (gpointer data, const WyctlPublicationPlan *request,
    WyctlPublicationPlan *out)
{
  HandoffPublication *backend = data;
  backend->plan_calls++;
  if (backend->fail_plan_once) {
    backend->fail_plan_once = FALSE;
    return WYRELOG_E_IO;
  }
  copy_plan_for_test (request, out);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
handoff_test_stage (gpointer data, const WyctlPublicationPlan *plan,
    const gchar *credential_id, const WyctlSensitiveText *secret,
    WyctlPublicationReceipt *out_receipt, WyctlPublicationResult *out_result,
    gboolean *out_replayed)
{
  HandoffPublication *backend = data;
  g_assert_nonnull (credential_id);
  g_assert_nonnull (secret);
  g_assert_cmpuint (secret->len, ==, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  backend->stage_calls++;
  if (backend->foreign_stage) {
    *out_result = (WyctlPublicationResult) {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN,};
    *out_replayed = FALSE;
    return WYRELOG_E_OK;
  }
  *out_receipt = (WyctlPublicationReceipt) {
  .version = WYCTL_PUBLICATION_RECEIPT_VERSION,.destination =
        g_strdup (plan->destination),.reservation_id =
        g_strdup (plan->reservation_id),.parent_identity =
        g_strdup (plan->parent_identity),.stage_basename =
        g_strdup (plan->stage_basename),.stage_identity =
        g_strdup ("test-stage-identity"),};
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,.exact_identity = TRUE,};
  *out_replayed = FALSE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
handoff_test_target_acquire (gpointer data, const WyctlPublicationPlan *plan,
    const WyctlPublicationReceipt *receipt, gboolean require_destination,
    WyctlPublicationReceiptTargetLease **out_lease,
    WyctlPublicationReceiptTargetKind *out_kind)
{
  HandoffPublication *backend = data;
  (void) plan;
  (void) receipt;
  backend->preflight_calls++;
  if (backend->foreign_receipt || (require_destination && !backend->published)) {
    *out_lease = NULL;
    *out_kind = WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
    return WYRELOG_E_OK;
  }
  HandoffTargetLease *lease = g_new0 (HandoffTargetLease, 1);
  lease->owner = backend;
  lease->destination_target = backend->published;
  backend->active_leases++;
  *out_lease = (WyctlPublicationReceiptTargetLease *) lease;
  *out_kind = backend->published ?
      WYCTL_PUBLICATION_RECEIPT_TARGET_DESTINATION :
      WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
handoff_test_target_commit (gpointer data,
    WyctlPublicationReceiptTargetLease *target_lease,
    const gchar *credential_id, const WyctlSensitiveText *secret,
    WyctlPublicationResult *out_result)
{
  HandoffPublication *backend = data;
  HandoffTargetLease *lease = (HandoffTargetLease *) target_lease;
  g_assert_true (lease->owner == backend);
  g_assert_false (lease->destination_target);
  g_assert_nonnull (credential_id);
  g_assert_cmpuint (secret->len, ==, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  backend->commit_calls++;
  backend->published = TRUE;
  lease->destination_target = TRUE;
  if (backend->fail_commit_after_publish_once) {
    backend->fail_commit_after_publish_once = FALSE;
    return WYRELOG_E_IO;
  }
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,.exact_identity = TRUE,};
  return WYRELOG_E_OK;
}

static wyrelog_error_t
handoff_test_target_inspect (gpointer data,
    WyctlPublicationReceiptTargetLease *target_lease,
    const gchar *credential_id, const WyctlSensitiveText *secret,
    WyctlPublicationResult *out_result)
{
  HandoffPublication *backend = data;
  HandoffTargetLease *lease = (HandoffTargetLease *) target_lease;
  g_assert_true (lease->owner == backend);
  g_assert_nonnull (credential_id);
  g_assert_cmpuint (secret->len, ==, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  backend->inspect_calls++;
  if (backend->foreign_receipt) {
    *out_result = (WyctlPublicationResult) {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN,};
    return WYRELOG_E_OK;
  }
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        lease->destination_target ?
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE :
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED,.exact_identity =
        TRUE,.cleanup_required = !lease->destination_target,};
  if (backend->store != NULL
      && backend->inspect_calls ==
      backend->fail_release_after_on_inspect_call) {
    backend->fail_release_after_on_inspect_call = 0;
    wyl_policy_store_service_authority_transaction_fail_once (backend->store,
        WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
  }
  if (backend->store != NULL
      && backend->inspect_calls ==
      backend->fail_handoff_after_on_inspect_call) {
    backend->fail_handoff_after_on_inspect_call = 0;
    wyl_policy_store_service_handoff_fail_once (backend->store,
        backend->fail_handoff_stage);
  }
  if (backend->store != NULL
      && backend->inspect_calls == backend->revoke_after_inspect_call) {
    wyl_policy_service_credential_info_t revoked = { 0 };
    backend->revoke_after_inspect_call = 0;
    backend->revoke_rc = wyl_policy_store_revoke_service_credential
        (backend->store, credential_id, "admin", backend->revoke_request_id,
        &revoked);
    wyl_policy_service_credential_info_clear (&revoked);
  }
  if (backend->inspect_calls == backend->foreign_after_inspect_call) {
    backend->foreign_after_inspect_call = 0;
    backend->foreign_receipt = TRUE;
  }
  return WYRELOG_E_OK;
}

static void
handoff_test_target_release (gpointer data,
    WyctlPublicationReceiptTargetLease *target_lease)
{
  HandoffPublication *backend = data;
  HandoffTargetLease *lease = (HandoffTargetLease *) target_lease;
  g_assert_true (lease->owner == backend);
  g_assert_cmpuint (backend->active_leases, >, 0);
  backend->active_leases--;
  backend->release_calls++;
  g_free (lease);
}

static WylSession *
handoff_human_session_new (const gchar *username, const gchar *tenant)
{
  WylSession *session = g_object_new (WYL_TYPE_SESSION, NULL);
  g_assert_cmpint (wyl_id_new (&session->id), ==, WYRELOG_E_OK);
  session->username = g_strdup (username);
  session->tenant = g_strdup (tenant);
  session->state = WYL_SESSION_STATE_ACTIVE;
  session->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;
  return session;
}

static void
replace_journal_destination_for_test (const gchar *path,
    const gchar *expected, const gchar *replacement)
{
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gsize text_len = strlen (expected);
  gboolean replaced = FALSE;

  g_assert_cmpuint (text_len, ==, strlen (replacement));
  g_assert_true (g_file_get_contents (path, &contents, &len, NULL));
  for (gsize i = 0; i + text_len <= len; i++) {
    if (memcmp (contents + i, expected, text_len) == 0) {
      memcpy (contents + i, replacement, text_len);
      replaced = TRUE;
      break;
    }
  }
  g_assert_true (replaced);
  g_assert_true (g_file_set_contents (path, contents, len, NULL));
}

static gint64
count_handoff_rows_for_request (sqlite3 *db, const gchar *request_id,
    const gchar *reason)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM service_credential_handoff_dispositions"
          " WHERE original_request_id=? AND reason=?;", -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, request_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 2, reason, -1, SQLITE_TRANSIENT),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static gint64
count_handoff_audits_for_request (sqlite3 *db, const gchar *request_id)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM audit_events WHERE action="
          "'service.credential.handoff.disposition' AND request_id=?;", -1,
          &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, request_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static void
begin_handoff_issue_for_test (const WylServiceCredentialOperationStorage
    *storage, const WylServiceCredentialOperationRootAnchor *anchor,
    gint64 now_us, gchar request_id[WYL_REQUEST_ID_STRING_BUF],
    wyl_id_t *escrow, WylServiceCredentialOperationCoordinatorRequest *request,
    WylServiceCredentialOperationRecord *prepared)
{
  gchar escrow_id[WYL_ID_STRING_BUF];
  gboolean replayed = TRUE;
  fresh_request_id (request_id);
  g_assert_cmpint (wyl_id_new (escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (escrow, escrow_id, sizeof escrow_id), ==,
      WYRELOG_E_OK);
  *request = (WylServiceCredentialOperationCoordinatorRequest)
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  request->kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  request->request_id = g_strdup (request_id);
  request->subject_id = g_strdup ("svc:handoff:executor");
  request->tenant_id = g_strdup ("tenant-a");
  request->destination = g_strdup ("credentials.json");
  request->parent_identity = g_strdup ("test-parent-identity");
  request->actor_subject_id = g_strdup ("admin");
  request->escrow_id = g_strdup (escrow_id);
  request->expires_at_us = now_us + G_TIME_SPAN_HOUR;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (storage,
          anchor, request, now_us, &replayed, prepared), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
}

static void
handoff_target_put_u32be (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static void
    handoff_target_digest_for_test
    (const WylServiceCredentialOperationRecord * record,
    guint8 out[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES])
{
  const gchar *fields[] = {
    "wyrelog.service-credential-owner-publication-target.v1",
    record->destination,
    record->parent_identity,
  };
  crypto_generichash_state state;
  g_assert_cmpint (crypto_generichash_init (&state, NULL, 0,
          WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES), ==, 0);
  for (gsize i = 0; i < G_N_ELEMENTS (fields); i++) {
    gsize len = strlen (fields[i]);
    g_assert_cmpuint (len, <=, G_MAXUINT32);
    guint8 encoded_len[4];
    handoff_target_put_u32be (encoded_len, (guint32) len);
    g_assert_cmpint (crypto_generichash_update (&state, encoded_len,
            sizeof encoded_len), ==, 0);
    g_assert_cmpint (crypto_generichash_update (&state,
            (const guint8 *) fields[i], len), ==, 0);
  }
  g_assert_cmpint (crypto_generichash_final (&state, out,
          WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES), ==, 0);
  sodium_memzero (&state, sizeof state);
}

static GBytes *
read_handoff_journal_bytes (const gchar *root, const gchar *request_id)
{
  g_autofree gchar *path = g_strdup_printf ("%s/op-%s", root, request_id);
  gchar *contents = NULL;
  gsize len = 0;
  g_assert_true (g_file_get_contents (path, &contents, &len, NULL));
  return g_bytes_new_take (contents, len);
}

static void
    assert_escrow_info_equal
    (const wyl_policy_service_handoff_escrow_info_t * left,
    const wyl_policy_service_handoff_escrow_info_t * right)
{
  g_assert_true (wyl_id_equal (&left->escrow_id, &right->escrow_id));
  g_assert_cmpstr (left->operation, ==, right->operation);
  g_assert_cmpstr (left->request_id, ==, right->request_id);
  g_assert_cmpstr (left->actor_subject_id, ==, right->actor_subject_id);
  g_assert_cmpmem (left->target_digest, sizeof left->target_digest,
      right->target_digest, sizeof right->target_digest);
  g_assert_cmpstr (left->credential_id, ==, right->credential_id);
  g_assert_cmpuint (left->credential_generation, ==,
      right->credential_generation);
  g_assert_cmpint (left->deadline_at_us, ==, right->deadline_at_us);
  g_assert_cmpmem (left->binding_digest, sizeof left->binding_digest,
      right->binding_digest, sizeof right->binding_digest);
}

static void
assert_credential_equal (const wyl_service_credential_t *left,
    const wyl_service_credential_t *right)
{
  g_assert_cmpstr (left->credential_id, ==, right->credential_id);
  g_assert_cmpuint (left->credential_format_version, ==,
      right->credential_format_version);
  g_assert_cmpstr (left->subject_id, ==, right->subject_id);
  g_assert_cmpstr (left->tenant_id, ==, right->tenant_id);
  g_assert_cmpuint (left->generation, ==, right->generation);
  g_assert_cmpstr (left->state, ==, right->state);
  g_assert_cmpstr (left->created_by, ==, right->created_by);
  g_assert_cmpint (left->created_at_us, ==, right->created_at_us);
  g_assert_cmpint (left->updated_at_us, ==, right->updated_at_us);
  g_assert_cmpint (left->expires_at_us, ==, right->expires_at_us);
  g_assert_cmpint (left->last_used_at_us, ==, right->last_used_at_us);
  g_assert_cmpstr (left->revoked_by, ==, right->revoked_by);
  g_assert_cmpint (left->revoked_at_us, ==, right->revoked_at_us);
  g_assert_cmpstr (left->rotated_from_id, ==, right->rotated_from_id);
}

static void
assert_no_handoff_execution_callbacks (const HandoffPublication *publication,
    const HandoffUnsealGate *gate, guint authorization_calls,
    const CountingHandoffClock *clock)
{
  g_assert_cmpuint (publication->plan_calls, ==, 0);
  g_assert_cmpuint (publication->stage_calls, ==, 0);
  g_assert_cmpuint (publication->preflight_calls, ==, 0);
  g_assert_cmpuint (publication->inspect_calls, ==, 0);
  g_assert_cmpuint (publication->commit_calls, ==, 0);
  g_assert_cmpuint (publication->active_leases, ==, 0);
  g_assert_cmpuint (publication->release_calls, ==, 0);
  g_assert_false (publication->published);
  g_assert_cmpuint (gate->calls, ==, 0);
  g_assert_cmpuint (authorization_calls, ==, 0);
  g_assert_cmpuint (clock->calls, ==, 0);
}

static void
materialize_handoff_state_for_maintenance (WylHandle *handle,
    const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor, gint64 now_us,
    WylServiceCredentialOperationState state,
    gchar request_id[WYL_REQUEST_ID_STRING_BUF], wyl_id_t *escrow,
    WylServiceCredentialOperationCoordinatorRequest *request,
    WylServiceCredentialOperationRecord *record)
{
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  begin_handoff_issue_for_test (storage, anchor, now_us, request_id, escrow,
      request, &prepared);
  guint8 target_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES] = { 0 };
  handoff_target_digest_for_test (&prepared, target_digest);
  wyl_service_credential_handoff_request_t handoff = {
    .escrow_id = escrow,
    .target_digest = target_digest,
    .deadline_at_us = prepared.expires_at_us,
  };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = allow_handoff_mutation,
  };
  wyl_service_credential_issue_runtime_t runtime = {
    .authorization = &authorization,
  };
  wyl_service_credential_handoff_result_t issued = { 0 };
  gint64 successor_expiry = g_get_real_time () + G_TIME_SPAN_HOUR;
  g_assert_cmpint (wyl_service_credential_issue_handoff_with_runtime (handle,
          prepared.subject_id, prepared.tenant_id, prepared.actor_subject_id,
          request_id, successor_expiry, &handoff, &runtime, &issued), ==,
      WYRELOG_E_OK);
  gboolean replayed = TRUE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed_bound
      (storage, anchor, request_id, issued.handoff.credential_id,
          issued.handoff.credential_generation, issued.handoff.binding_digest,
          now_us + 1, &replayed, record), ==, WYRELOG_E_OK);
  g_assert_false (replayed);

  wyl_id_t reservation;
  gchar reservation_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&reservation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&reservation, reservation_id,
          sizeof reservation_id), ==, WYRELOG_E_OK);
  if (state != WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED) {
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_checkpoint_publication_planned
        (storage, anchor, request_id, reservation_id, "maintenance-stage",
            reservation_id, now_us + 2, &replayed, record), ==, WYRELOG_E_OK);
    g_assert_false (replayed);
  }
  if (state == WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED) {
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_checkpoint_publication_prepared
        (storage, anchor, request_id, reservation_id, "maintenance-stage",
            "maintenance-stage-identity", reservation_id, now_us + 3,
            &replayed, record), ==, WYRELOG_E_OK);
    g_assert_false (replayed);
  }
  if (state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
      || state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED) {
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_checkpoint_file_published
        (storage, anchor, request_id, reservation_id, "maintenance-stage",
            "maintenance-stage-identity", reservation_id, now_us + 4,
            &replayed, record), ==, WYRELOG_E_OK);
    g_assert_false (replayed);
  }
  if (state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED) {
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_checkpoint_cleanup_required
        (storage, anchor, request_id, now_us + 5, &replayed, record), ==,
        WYRELOG_E_OK);
    g_assert_false (replayed);
  }
  g_assert_cmpint (record->state, ==, state);
  memset (target_digest, 0, sizeof target_digest);
  wyl_service_credential_handoff_result_clear (&issued);
  wyl_service_credential_operation_record_clear (&prepared);
}

static void
delete_escrow_for_legacy_test (sqlite3 *db, const wyl_id_t *escrow)
{
  gchar escrow_id[WYL_ID_STRING_BUF];
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (wyl_id_format (escrow, escrow_id, sizeof escrow_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "DELETE FROM service_credential_handoff_escrows WHERE escrow_id=?;",
          -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, escrow_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_changes (db), ==, 1);
  sqlite3_finalize (stmt);
}

static void
make_escrow_foreign_for_maintenance_test (sqlite3 *db, const wyl_id_t *escrow)
{
  gchar escrow_id[WYL_ID_STRING_BUF];
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (wyl_id_format (escrow, escrow_id, sizeof escrow_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "UPDATE service_credential_handoff_escrows"
          " SET target_digest=zeroblob(32) WHERE escrow_id=?;", -1, &stmt,
          NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, escrow_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_changes (db), ==, 1);
  sqlite3_finalize (stmt);
}

static void
remove_operation_root_for_test (const gchar *root)
{
  GDir *dir = g_dir_open (root, 0, NULL);
  if (dir != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *path = g_build_filename (root, name, NULL);
      (void) g_remove (path);
    }
    g_dir_close (dir);
  }
  (void) g_rmdir (root);
}

static void
test_authenticated_handoff_issue_end_to_end (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  wyl_policy_store_t *store = store_of (handle);
  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store, "admin",
          "wr.service_credential.manage", session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store, "admin",
          "authenticated"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_session_state (store, session_id,
          "active"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store, "admin",
          "wr.service_credential.manage", session_id, "armed"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);

#ifdef G_OS_WIN32
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_autofree gchar *operation_name = g_strdup_printf
      ("wyrelog-handoff-execute-%lu-%u", (gulong) GetCurrentProcessId (),
      g_random_int ());
  g_autofree gchar *operation_root = g_build_filename (local, operation_name,
      NULL);
#else
  g_autofree gchar *operation_root = g_build_filename (fixture.dir,
      "operations", NULL);
#endif
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  wyl_id_t escrow;
  gchar escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&escrow, escrow_id, sizeof escrow_id), ==,
      WYRELOG_E_OK);
  gint64 now = g_get_real_time ();
  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  request.request_id = g_strdup (request_id);
  request.subject_id = g_strdup ("svc:handoff:executor");
  request.tenant_id = g_strdup ("tenant-a");
  request.destination = g_strdup ("credentials.json");
  request.parent_identity = g_strdup ("test-parent-identity");
  request.actor_subject_id = g_strdup ("admin");
  request.escrow_id = g_strdup (escrow_id);
  request.expires_at_us = now + G_TIME_SPAN_HOUR;
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = FALSE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &prepared), ==, WYRELOG_E_OK);
  g_assert_false (replayed);

  HandoffPublication publication = {
    .store = store,
  };
  const WyctlPublicationBackendVTable vtable = {
    .plan = handoff_test_plan,
    .stage_exact = handoff_test_stage,
    .receipt_target_acquire = handoff_test_target_acquire,
    .receipt_target_inspect = handoff_test_target_inspect,
    .receipt_target_commit = handoff_test_target_commit,
    .receipt_target_release = handoff_test_target_release,
  };
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = request_id,
    .publication = &vtable,
    .publication_data = &publication,
  };
  WylServiceCredentialOperationRecord outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;

  /* A corrupted legacy/adversarial PREPARED record must fail in decode,
   * before credential RNG/domain mutation, escrow creation, unseal, or any
   * publication callback. */
  gchar malformed_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (malformed_request_id);
  wyl_id_t malformed_escrow;
  gchar malformed_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&malformed_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&malformed_escrow, malformed_escrow_id,
          sizeof malformed_escrow_id), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationCoordinatorRequest malformed_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  malformed_request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  malformed_request.request_id = g_strdup (malformed_request_id);
  malformed_request.subject_id = g_strdup ("svc:handoff:executor");
  malformed_request.tenant_id = g_strdup ("tenant-a");
  malformed_request.destination = g_strdup ("credentials.json");
  malformed_request.parent_identity = g_strdup ("test-parent-identity");
  malformed_request.actor_subject_id = g_strdup ("admin");
  malformed_request.escrow_id = g_strdup (malformed_escrow_id);
  malformed_request.expires_at_us = now + G_TIME_SPAN_HOUR;
  WylServiceCredentialOperationRecord malformed_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &malformed_request, now, &replayed, &malformed_prepared), ==,
      WYRELOG_E_OK);
  g_autofree gchar *malformed_journal = g_strdup_printf ("%s/op-%s",
      operation_root, malformed_request_id);
  replace_journal_destination_for_test (malformed_journal,
      "credentials.json", "nested/file.json");
  HandoffUnsealGate malformed_unseal_gate = {.rc = WYRELOG_E_IO };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &malformed_unseal_gate);
  runtime.decision_request_id = malformed_request_id;
  gint64 credentials_before_malformed = count_credentials (db_of (handle));
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, malformed_request_id, &runtime, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_before_malformed);
  g_assert_cmpuint (publication.plan_calls, ==, 0);
  g_assert_cmpuint (publication.stage_calls, ==, 0);
  g_assert_cmpuint (publication.preflight_calls, ==, 0);
  g_assert_cmpuint (publication.inspect_calls, ==, 0);
  g_assert_cmpuint (publication.commit_calls, ==, 0);
  g_assert_cmpuint (malformed_unseal_gate.calls, ==, 0);
  wyl_policy_service_handoff_escrow_info_t absent = { 0 };
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &malformed_escrow, &absent), ==, WYRELOG_E_NOT_FOUND);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  runtime.decision_request_id = request_id;
  wyl_service_credential_operation_record_clear (&malformed_prepared);
  wyl_service_credential_operation_coordinator_request_clear
      (&malformed_request);

  gint64 decision_audits_before = scalar (db_of (handle),
      "SELECT count(*) FROM audit_events WHERE action="
      "'wr.service_credential.manage';");
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, request_id, &runtime, &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpuint (publication.plan_calls, ==, 1);
  g_assert_cmpuint (publication.stage_calls, ==, 1);
  g_assert_cmpuint (publication.preflight_calls, ==, 2);
  g_assert_cmpuint (publication.commit_calls, ==, 1);
  g_assert_cmpuint (publication.inspect_calls, ==, 3);
  g_assert_cmpuint (publication.active_leases, ==, 0);
  g_assert_cmpuint (publication.release_calls, ==, 2);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE action="
          "'wr.service_credential.manage';"), ==,
      decision_audits_before + HANDOFF_DECISION_AUDIT_DELTA (2));
  wyl_policy_service_handoff_escrow_info_t deleted = { 0 };
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &escrow, &deleted), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (count_handoff_rows_for_request (db_of (handle), request_id,
          "delivered"), ==, 1);
  g_assert_cmpint (count_handoff_audits_for_request (db_of (handle),
          request_id), ==, 1);
  g_assert_cmpint (count_credentials (db_of (handle)), ==, 1);

  WylServiceCredentialOperationRecord duplicate =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  HandoffUnsealGate duplicate_unseal_gate = {.rc = WYRELOG_E_IO };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &duplicate_unseal_gate);
  guint plan_calls_before_duplicate = publication.plan_calls;
  guint stage_calls_before_duplicate = publication.stage_calls;
  guint inspect_calls_before_duplicate = publication.inspect_calls;
  guint commit_calls_before_duplicate = publication.commit_calls;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, request_id, &runtime, &duplicate), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (duplicate.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpstr (duplicate.request_id, ==, outcome.request_id);
  g_assert_cmpstr (duplicate.successor_credential_id, ==,
      outcome.successor_credential_id);
  g_assert_cmpuint (duplicate.successor_generation, ==,
      outcome.successor_generation);
  g_assert_cmpstr (duplicate.reservation_id, ==, outcome.reservation_id);
  g_assert_cmpstr (duplicate.stage_identity, ==, outcome.stage_identity);
  g_assert_cmpint (duplicate.updated_at_us, ==, outcome.updated_at_us);
  g_assert_cmpint (count_credentials (db_of (handle)), ==, 1);
  g_assert_cmpuint (publication.plan_calls, ==, plan_calls_before_duplicate);
  g_assert_cmpuint (publication.stage_calls, ==, stage_calls_before_duplicate);
  g_assert_cmpuint (publication.inspect_calls, ==,
      inspect_calls_before_duplicate);
  g_assert_cmpuint (publication.commit_calls, ==,
      commit_calls_before_duplicate);
  g_assert_cmpuint (publication.preflight_calls, ==, 2);
  g_assert_cmpuint (duplicate_unseal_gate.calls, ==, 0);
  g_assert_cmpuint (publication.active_leases, ==, 0);
  g_assert_cmpuint (publication.release_calls, ==, 2);
  g_assert_cmpint (count_handoff_rows_for_request (db_of (handle), request_id,
          "delivered"), ==, 1);
  g_assert_cmpint (count_handoff_audits_for_request (db_of (handle),
          request_id), ==, 1);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);

  gchar denied_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (denied_request_id);
  wyl_id_t denied_escrow;
  gchar denied_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&denied_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&denied_escrow, denied_escrow_id,
          sizeof denied_escrow_id), ==, WYRELOG_E_OK);
  g_free (request.request_id);
  g_free (request.escrow_id);
  request.request_id = g_strdup (denied_request_id);
  request.escrow_id = g_strdup (denied_escrow_id);
  WylServiceCredentialOperationRecord denied_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &denied_prepared), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_revoke_direct_permission (store, "admin",
          "wr.service_credential.manage", session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  runtime.decision_request_id = denied_request_id;
  WylServiceCredentialOperationRecord denied_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gint64 denial_audits_before = scalar (db_of (handle),
      "SELECT count(*) FROM audit_events WHERE action="
      "'wr.service_credential.manage';");
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, denied_request_id, &runtime, &denied_outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE action="
          "'wr.service_credential.manage';"), ==,
      denial_audits_before + HANDOFF_DECISION_AUDIT_DELTA (1));
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE action="
          "'service.credential.issue' AND request_id IS NOT NULL;"), ==, 1);
  g_assert_cmpint (count_credentials (db_of (handle)), ==, 1);
  g_assert_cmpuint (publication.plan_calls, ==, 1);
  g_assert_cmpuint (publication.stage_calls, ==, 1);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &denied_escrow, &deleted), ==, WYRELOG_E_NOT_FOUND);

  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store, "admin",
          "wr.service_credential.manage", session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store, "admin",
          "wr.service_credential.manage", session_id, "armed"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  gchar rotate_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (rotate_request_id);
  wyl_id_t rotate_escrow;
  gchar rotate_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&rotate_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&rotate_escrow, rotate_escrow_id,
          sizeof rotate_escrow_id), ==, WYRELOG_E_OK);
  request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_free (request.request_id);
  g_free (request.subject_id);
  g_free (request.tenant_id);
  g_free (request.escrow_id);
  request.request_id = g_strdup (rotate_request_id);
  request.subject_id = g_strdup ("svc:handoff:executor");
  request.tenant_id = NULL;
  request.old_credential_id = g_strdup (outcome.successor_credential_id);
  request.escrow_id = g_strdup (rotate_escrow_id);
  request.expected_generation = outcome.successor_generation;
  g_assert_true
      (wyl_service_credential_operation_coordinator_request_is_valid
      (&request));
  WylServiceCredentialOperationRecord rotate_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &rotate_prepared), ==,
      WYRELOG_E_OK);
  publication = (HandoffPublication) {
  0};
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .old_credential_generation = outcome.successor_generation,
  };
  runtime.decision_request_id = rotate_request_id;
  runtime.rotate_runtime = &rotate_runtime;
  WylServiceCredentialOperationRecord rotate_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gint64 rotate_decisions_before = scalar (db_of (handle),
      "SELECT count(*) FROM audit_events WHERE action="
      "'wr.service_credential.manage';");
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, rotate_request_id, &runtime, &rotate_outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (rotate_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpuint (publication.stage_calls, ==, 1);
  g_assert_cmpuint (publication.commit_calls, ==, 1);
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE action="
          "'wr.service_credential.manage';"), ==,
      rotate_decisions_before + HANDOFF_DECISION_AUDIT_DELTA (2));
  g_assert_cmpint (scalar (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE action="
          "'service.credential.rotate';"), ==, 1);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &rotate_escrow, &deleted), ==, WYRELOG_E_NOT_FOUND);

  gchar plan_crash_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (plan_crash_request_id);
  wyl_id_t plan_crash_escrow;
  gchar plan_crash_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&plan_crash_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&plan_crash_escrow, plan_crash_escrow_id,
          sizeof plan_crash_escrow_id), ==, WYRELOG_E_OK);
  request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  g_free (request.request_id);
  g_free (request.subject_id);
  g_free (request.tenant_id);
  g_free (request.old_credential_id);
  g_free (request.escrow_id);
  request.request_id = g_strdup (plan_crash_request_id);
  request.subject_id = g_strdup ("svc:handoff:executor");
  request.tenant_id = g_strdup ("tenant-a");
  request.old_credential_id = NULL;
  request.escrow_id = g_strdup (plan_crash_escrow_id);
  request.expected_generation = 0;
  WylServiceCredentialOperationRecord plan_crash_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &plan_crash_prepared), ==,
      WYRELOG_E_OK);
  publication = (HandoffPublication) {
  .fail_plan_once = TRUE};
  runtime.decision_request_id = plan_crash_request_id;
  runtime.rotate_runtime = NULL;
  WylServiceCredentialOperationRecord crash_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gint64 credentials_before_crash = count_credentials (db_of (handle));
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, plan_crash_request_id, &runtime, &crash_outcome),
      ==, WYRELOG_E_IO);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_before_crash + 1);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (&storage,
          &anchor, plan_crash_request_id, &crash_outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (crash_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, plan_crash_request_id, &runtime, &crash_outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_before_crash + 1);
  g_assert_cmpuint (publication.plan_calls, ==, 2);

  gchar publish_crash_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (publish_crash_request_id);
  wyl_id_t publish_crash_escrow;
  gchar publish_crash_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&publish_crash_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&publish_crash_escrow,
          publish_crash_escrow_id, sizeof publish_crash_escrow_id), ==,
      WYRELOG_E_OK);
  g_free (request.request_id);
  g_free (request.escrow_id);
  request.request_id = g_strdup (publish_crash_request_id);
  request.escrow_id = g_strdup (publish_crash_escrow_id);
  WylServiceCredentialOperationRecord publish_crash_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &publish_crash_prepared), ==,
      WYRELOG_E_OK);
  publication = (HandoffPublication) {
  .fail_commit_after_publish_once = TRUE,};
  runtime.decision_request_id = publish_crash_request_id;
  credentials_before_crash = count_credentials (db_of (handle));
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, publish_crash_request_id, &runtime,
          &crash_outcome), ==, WYRELOG_E_IO);
  g_assert_true (publication.published);
  g_assert_cmpuint (publication.active_leases, ==, 0);
  g_assert_cmpuint (publication.release_calls, ==, 1);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (&storage,
          &anchor, publish_crash_request_id, &crash_outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (crash_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED);
  publication.foreign_receipt = TRUE;
  HandoffUnsealGate foreign_unseal_gate = {.rc = WYRELOG_E_IO };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &foreign_unseal_gate);
  guint inspect_calls_before_foreign_receipt = publication.inspect_calls;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, publish_crash_request_id, &runtime,
          &crash_outcome), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (publication.inspect_calls, ==,
      inspect_calls_before_foreign_receipt);
  g_assert_cmpuint (publication.commit_calls, ==, 1);
  g_assert_cmpuint (foreign_unseal_gate.calls, ==, 0);
  g_assert_cmpuint (publication.active_leases, ==, 0);
  g_assert_cmpuint (publication.release_calls, ==, 1);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &publish_crash_escrow, &deleted), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_escrow_info_clear (&deleted);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  publication.foreign_receipt = FALSE;
  HandoffUnsealGate pin_first_race_gate = {
    .rc = WYRELOG_E_OK,
    .publication = &publication,
    .replace_on_call = TRUE,
  };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &pin_first_race_gate);
  guint inspect_calls_before_pin_first_race = publication.inspect_calls;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, publish_crash_request_id, &runtime,
          &crash_outcome), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (pin_first_race_gate.calls, ==, 1);
  g_assert_cmpuint (publication.inspect_calls, ==,
      inspect_calls_before_pin_first_race + 1);
  g_assert_cmpuint (publication.commit_calls, ==, 1);
  g_assert_cmpuint (publication.active_leases, ==, 0);
  g_assert_cmpuint (publication.release_calls, ==, 2);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (&storage,
          &anchor, publish_crash_request_id, &crash_outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (crash_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &publish_crash_escrow, &deleted), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_escrow_info_clear (&deleted);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  publication.foreign_receipt = FALSE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, publish_crash_request_id, &runtime,
          &crash_outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_before_crash + 1);
  g_assert_cmpuint (publication.commit_calls, ==, 1);
  g_assert_cmpuint (publication.active_leases, ==, 0);
  g_assert_cmpuint (publication.release_calls, ==, 4);

  gchar foreign_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (foreign_request_id);
  wyl_id_t foreign_escrow;
  gchar foreign_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&foreign_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&foreign_escrow, foreign_escrow_id,
          sizeof foreign_escrow_id), ==, WYRELOG_E_OK);
  g_free (request.request_id);
  g_free (request.escrow_id);
  request.request_id = g_strdup (foreign_request_id);
  request.escrow_id = g_strdup (foreign_escrow_id);
  WylServiceCredentialOperationRecord foreign_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &foreign_prepared), ==,
      WYRELOG_E_OK);
  publication = (HandoffPublication) {
  .foreign_stage = TRUE};
  runtime.decision_request_id = foreign_request_id;
  gint64 credentials_before_foreign = count_credentials (db_of (handle));
  WylServiceCredentialOperationRecord foreign_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, foreign_request_id, &runtime, &foreign_outcome),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (&storage,
          &anchor, foreign_request_id, &foreign_outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (foreign_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED);
  g_autofree gchar *foreign_successor =
      g_strdup (foreign_outcome.successor_credential_id);
  guint64 foreign_generation = foreign_outcome.successor_generation;
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &foreign_escrow, &deleted), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_escrow_info_clear (&deleted);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, foreign_request_id, &runtime, &foreign_outcome),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (foreign_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED);
  g_assert_cmpstr (foreign_outcome.successor_credential_id, ==,
      foreign_successor);
  g_assert_cmpuint (foreign_outcome.successor_generation, ==,
      foreign_generation);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_before_foreign + 1);
  g_assert_cmpuint (publication.commit_calls, ==, 0);
  g_assert_false (publication.published);

  gchar allow_first_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (allow_first_request_id);
  wyl_id_t allow_first_escrow;
  gchar allow_first_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&allow_first_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&allow_first_escrow, allow_first_escrow_id,
          sizeof allow_first_escrow_id), ==, WYRELOG_E_OK);
  g_free (request.request_id);
  g_free (request.escrow_id);
  request.request_id = g_strdup (allow_first_request_id);
  request.escrow_id = g_strdup (allow_first_escrow_id);
  WylServiceCredentialOperationRecord allow_first_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &allow_first_prepared), ==,
      WYRELOG_E_OK);
  publication = (HandoffPublication) {
  0};
  HandoffAuthorizationBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.cond);
  runtime.decision_request_id = allow_first_request_id;
  runtime.after_authorization = handoff_authorization_barrier;
  runtime.authorization_checkpoint_data = &barrier;
  HandoffExecuteCall allow_first = {
    .handle = handle,
    .storage = &storage,
    .anchor = &anchor,
    .request_id = allow_first_request_id,
    .runtime = &runtime,
    .outcome = WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT,
    .rc = WYRELOG_E_INTERNAL,
  };
  gint64 credentials_before_allow_race = count_credentials (db_of (handle));
  GThread *executor = g_thread_new ("handoff-allow-first",
      handoff_execute_thread, &allow_first);
  g_mutex_lock (&barrier.mutex);
  while (!barrier.entered)
    g_cond_wait (&barrier.cond, &barrier.mutex);
  g_mutex_unlock (&barrier.mutex);
  HandoffRevokeCall revoke = {
    .handle = handle,
    .session_id = session_id,
    .rc = WYRELOG_E_INTERNAL,
  };
  GThread *revoker = g_thread_new ("handoff-revoke", handoff_revoke_thread,
      &revoke);
  gint64 race_deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  for (;;) {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_service_auth_authority_snapshot
        (wyl_handle_get_service_auth_authority (handle), &snapshot);
    if (snapshot.waiting_writers > 0)
      break;
    g_assert_cmpint (g_get_monotonic_time (), <, race_deadline);
    g_thread_yield ();
  }
  g_mutex_lock (&barrier.mutex);
  barrier.release = TRUE;
  g_cond_broadcast (&barrier.cond);
  g_mutex_unlock (&barrier.mutex);
  g_thread_join (executor);
  g_thread_join (revoker);
  g_assert_cmpint (revoke.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (allow_first.rc, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_before_allow_race + 1);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (&storage,
          &anchor, allow_first_request_id, &allow_first.outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (allow_first.outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpuint (publication.plan_calls, ==, 0);
  g_cond_clear (&barrier.cond);
  g_mutex_clear (&barrier.mutex);
  runtime.after_authorization = NULL;
  runtime.authorization_checkpoint_data = NULL;

  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store, "admin",
          "wr.service_credential.manage", session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store, "admin",
          "wr.service_credential.manage", session_id, "armed"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  gchar revoke_first_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (revoke_first_request_id);
  wyl_id_t revoke_first_escrow;
  gchar revoke_first_escrow_id[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&revoke_first_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&revoke_first_escrow,
          revoke_first_escrow_id, sizeof revoke_first_escrow_id), ==,
      WYRELOG_E_OK);
  g_free (request.request_id);
  g_free (request.escrow_id);
  request.request_id = g_strdup (revoke_first_request_id);
  request.escrow_id = g_strdup (revoke_first_escrow_id);
  WylServiceCredentialOperationRecord revoke_first_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay (&storage,
          &anchor, &request, now, &replayed, &revoke_first_prepared), ==,
      WYRELOG_E_OK);
  WylServiceAuthWriteLease *blocking_lease = NULL;
  wyl_policy_store_t *blocking_store = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &blocking_lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_get_policy_store
      (blocking_lease, handle, &blocking_store), ==, WYRELOG_E_OK);
  runtime.decision_request_id = revoke_first_request_id;
  HandoffExecuteCall revoke_first = {
    .handle = handle,
    .storage = &storage,
    .anchor = &anchor,
    .request_id = revoke_first_request_id,
    .runtime = &runtime,
    .outcome = WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT,
    .rc = WYRELOG_E_INTERNAL,
  };
  gint64 credentials_before_revoke_race = count_credentials (db_of (handle));
  executor = g_thread_new ("handoff-revoke-first", handoff_execute_thread,
      &revoke_first);
  race_deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  for (;;) {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_service_auth_authority_snapshot
        (wyl_handle_get_service_auth_authority (handle), &snapshot);
    if (snapshot.waiting_readers > 0 || snapshot.waiting_writers > 0)
      break;
    g_assert_cmpint (g_get_monotonic_time (), <, race_deadline);
    g_thread_yield ();
  }
  g_assert_cmpint (wyl_policy_store_revoke_direct_permission (blocking_store,
          "admin", "wr.service_credential.manage", session_id), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_release (blocking_lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (blocking_lease);
  g_thread_join (executor);
  g_assert_cmpint (revoke_first.rc, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_before_revoke_race);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &revoke_first_escrow, &deleted), ==, WYRELOG_E_NOT_FOUND);

  wyl_service_credential_operation_record_clear (&revoke_first.outcome);
  wyl_service_credential_operation_record_clear (&revoke_first_prepared);
  wyl_service_credential_operation_record_clear (&allow_first.outcome);
  wyl_service_credential_operation_record_clear (&allow_first_prepared);
  wyl_service_credential_operation_record_clear (&foreign_outcome);
  wyl_service_credential_operation_record_clear (&foreign_prepared);
  wyl_service_credential_operation_record_clear (&crash_outcome);
  wyl_service_credential_operation_record_clear (&publish_crash_prepared);
  wyl_service_credential_operation_record_clear (&plan_crash_prepared);
  wyl_service_credential_operation_record_clear (&rotate_outcome);
  wyl_service_credential_operation_record_clear (&rotate_prepared);
  wyl_service_credential_operation_record_clear (&denied_outcome);
  wyl_service_credential_operation_record_clear (&denied_prepared);
  wyl_service_credential_operation_record_clear (&duplicate);
  wyl_service_credential_operation_record_clear (&outcome);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_coordinator_request_clear (&request);
  wyl_service_credential_operation_storage_clear (&storage);
  g_autofree gchar *journal = g_strdup_printf ("%s/op-%s", operation_root,
      request_id);
  g_autofree gchar *journal_lock = g_strdup_printf ("%s/op-%s.lock",
      operation_root, request_id);
  g_autofree gchar *lifecycle = g_strdup_printf ("%s/lifecycle-%s.lock",
      operation_root, request_id);
  g_autofree gchar *malformed_journal_lock = g_strdup_printf ("%s/op-%s.lock",
      operation_root, malformed_request_id);
  g_autofree gchar *malformed_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, malformed_request_id);
  g_autofree gchar *denied_journal = g_strdup_printf ("%s/op-%s",
      operation_root, denied_request_id);
  g_autofree gchar *denied_journal_lock = g_strdup_printf ("%s/op-%s.lock",
      operation_root, denied_request_id);
  g_autofree gchar *denied_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, denied_request_id);
  g_autofree gchar *rotate_journal = g_strdup_printf ("%s/op-%s",
      operation_root, rotate_request_id);
  g_autofree gchar *rotate_journal_lock = g_strdup_printf ("%s/op-%s.lock",
      operation_root, rotate_request_id);
  g_autofree gchar *rotate_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, rotate_request_id);
  g_autofree gchar *plan_crash_journal = g_strdup_printf ("%s/op-%s",
      operation_root, plan_crash_request_id);
  g_autofree gchar *plan_crash_journal_lock = g_strdup_printf
      ("%s/op-%s.lock", operation_root, plan_crash_request_id);
  g_autofree gchar *plan_crash_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, plan_crash_request_id);
  g_autofree gchar *publish_crash_journal = g_strdup_printf ("%s/op-%s",
      operation_root, publish_crash_request_id);
  g_autofree gchar *publish_crash_journal_lock = g_strdup_printf
      ("%s/op-%s.lock", operation_root, publish_crash_request_id);
  g_autofree gchar *publish_crash_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, publish_crash_request_id);
  g_autofree gchar *foreign_journal = g_strdup_printf ("%s/op-%s",
      operation_root, foreign_request_id);
  g_autofree gchar *foreign_journal_lock = g_strdup_printf ("%s/op-%s.lock",
      operation_root, foreign_request_id);
  g_autofree gchar *foreign_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, foreign_request_id);
  g_autofree gchar *allow_first_journal = g_strdup_printf ("%s/op-%s",
      operation_root, allow_first_request_id);
  g_autofree gchar *allow_first_journal_lock = g_strdup_printf
      ("%s/op-%s.lock", operation_root, allow_first_request_id);
  g_autofree gchar *allow_first_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, allow_first_request_id);
  g_autofree gchar *revoke_first_journal = g_strdup_printf ("%s/op-%s",
      operation_root, revoke_first_request_id);
  g_autofree gchar *revoke_first_journal_lock = g_strdup_printf
      ("%s/op-%s.lock", operation_root, revoke_first_request_id);
  g_autofree gchar *revoke_first_lifecycle = g_strdup_printf
      ("%s/lifecycle-%s.lock", operation_root, revoke_first_request_id);
  (void) g_remove (journal);
  (void) g_remove (journal_lock);
  (void) g_remove (lifecycle);
  (void) g_remove (malformed_journal);
  (void) g_remove (malformed_journal_lock);
  (void) g_remove (malformed_lifecycle);
  (void) g_remove (denied_journal);
  (void) g_remove (denied_journal_lock);
  (void) g_remove (denied_lifecycle);
  (void) g_remove (rotate_journal);
  (void) g_remove (rotate_journal_lock);
  (void) g_remove (rotate_lifecycle);
  (void) g_remove (plan_crash_journal);
  (void) g_remove (plan_crash_journal_lock);
  (void) g_remove (plan_crash_lifecycle);
  (void) g_remove (publish_crash_journal);
  (void) g_remove (publish_crash_journal_lock);
  (void) g_remove (publish_crash_lifecycle);
  (void) g_remove (foreign_journal);
  (void) g_remove (foreign_journal_lock);
  (void) g_remove (foreign_lifecycle);
  (void) g_remove (allow_first_journal);
  (void) g_remove (allow_first_journal_lock);
  (void) g_remove (allow_first_lifecycle);
  (void) g_remove (revoke_first_journal);
  (void) g_remove (revoke_first_journal_lock);
  (void) g_remove (revoke_first_lifecycle);
  (void) g_rmdir (operation_root);
}

static void
test_handoff_delivery_recovery_matrix (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  wyl_policy_store_t *store = store_of (handle);
  sqlite3 *db = db_of (handle);
  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store, "admin",
          "wr.service_credential.manage", session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store, "admin",
          "authenticated"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_session_state (store, session_id,
          "active"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store, "admin",
          "wr.service_credential.manage", session_id, "armed"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);

  g_autofree gchar *operation_root = g_build_filename (fixture.dir,
      "delivery-operations", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  const WyctlPublicationBackendVTable vtable = {
    .plan = handoff_test_plan,
    .stage_exact = handoff_test_stage,
    .receipt_target_acquire = handoff_test_target_acquire,
    .receipt_target_inspect = handoff_test_target_inspect,
    .receipt_target_commit = handoff_test_target_commit,
    .receipt_target_release = handoff_test_target_release,
  };
  gint64 now = g_get_real_time ();
  HandoffPublication publication = { 0 };
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .publication = &vtable,
    .publication_data = &publication,
  };

  /* RELEASE SAVEPOINT can report failure after the delivered tombstone and
   * exact escrow delete are already durable.  The FILE -> CLEANUP transition
   * must retain the same proof identity, so retry terminates without touching
   * the receipt or secret again. */
  gchar release_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t release_escrow;
  WylServiceCredentialOperationCoordinatorRequest release_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord release_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord release_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  begin_handoff_issue_for_test (&storage, &anchor, now, release_request_id,
      &release_escrow, &release_request, &release_prepared);
  publication = (HandoffPublication) {
  .store = store,.fail_release_after_on_inspect_call = 3,};
  HandoffUnsealGate release_gate = {.rc = WYRELOG_E_OK };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &release_gate);
  runtime.decision_request_id = release_request_id;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, release_request_id, &runtime, &release_outcome),
      ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (&storage,
          &anchor, release_request_id, &release_outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (release_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED);
  g_assert_cmpuint (publication.inspect_calls, ==, 3);
  g_assert_cmpuint (release_gate.calls, ==, 3);
  g_assert_cmpint (count_handoff_rows_for_request (db, release_request_id,
          "delivered"), ==, 1);
  g_assert_cmpint (count_handoff_audits_for_request (db, release_request_id),
      ==, 1);
  wyl_policy_service_handoff_escrow_info_t escrow_info = { 0 };
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &release_escrow, &escrow_info), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, release_request_id, &runtime, &release_outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (release_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpuint (publication.inspect_calls, ==, 3);
  g_assert_cmpuint (release_gate.calls, ==, 3);
  g_assert_cmpint (count_handoff_rows_for_request (db, release_request_id,
          "delivered"), ==, 1);
  g_assert_cmpint (count_handoff_audits_for_request (db, release_request_id),
      ==, 1);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  wyl_service_credential_operation_record_clear (&release_outcome);
  wyl_service_credential_operation_record_clear (&release_prepared);
  wyl_service_credential_operation_coordinator_request_clear (&release_request);

  /* Every delivered mutation seam is inside the same authority savepoint.
   * Failure retains escrow and rolls back both provenance rows; CLEANUP retry
   * re-inspects once and commits exactly one pair. */
  static const WylPolicyServiceHandoffFailStage rollback_stages[] = {
    WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT,
    WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE,
    WYL_POLICY_HANDOFF_FAIL_AFTER_ESCROW_DELETE,
  };
  for (guint i = 0; i < G_N_ELEMENTS (rollback_stages); i++) {
    gchar request_id[WYL_REQUEST_ID_STRING_BUF];
    wyl_id_t escrow;
    WylServiceCredentialOperationCoordinatorRequest request =
        WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
    WylServiceCredentialOperationRecord prepared =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    WylServiceCredentialOperationRecord outcome =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    begin_handoff_issue_for_test (&storage, &anchor, now, request_id, &escrow,
        &request, &prepared);
    publication = (HandoffPublication) {
    .store = store,.fail_handoff_after_on_inspect_call =
          3,.fail_handoff_stage = rollback_stages[i],};
    HandoffUnsealGate gate = {.rc = WYRELOG_E_OK };
    wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
        handoff_unseal_gate, &gate);
    runtime.decision_request_id = request_id;
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_IO);
    g_assert_cmpint (wyl_service_credential_operation_coordinator_load
        (&storage, &anchor, request_id, &outcome), ==, WYRELOG_E_OK);
    g_assert_cmpint (outcome.state, ==,
        WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED);
    g_assert_cmpint (count_handoff_rows_for_request (db, request_id,
            "delivered"), ==, 0);
    g_assert_cmpint (count_handoff_audits_for_request (db, request_id), ==, 0);
    g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
            &escrow, &escrow_info), ==, WYRELOG_E_OK);
    wyl_policy_service_handoff_escrow_info_clear (&escrow_info);
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (outcome.state, ==,
        WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
    g_assert_cmpuint (publication.inspect_calls, ==, 4);
    g_assert_cmpuint (gate.calls, ==, 4);
    g_assert_cmpint (count_handoff_rows_for_request (db, request_id,
            "delivered"), ==, 1);
    g_assert_cmpint (count_handoff_audits_for_request (db, request_id), ==, 1);
    g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
            &escrow, &escrow_info), ==, WYRELOG_E_NOT_FOUND);
    wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL,
        NULL);
    wyl_service_credential_operation_record_clear (&outcome);
    wyl_service_credential_operation_record_clear (&prepared);
    wyl_service_credential_operation_coordinator_request_clear (&request);
  }

  /* A foreign destination discovered by the FILE acquire is durable OAR and
   * performs no delivery unseal, inspection, tombstone, or delete. */
  gchar foreign_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t foreign_escrow;
  WylServiceCredentialOperationCoordinatorRequest foreign_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord foreign_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord foreign_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  begin_handoff_issue_for_test (&storage, &anchor, now, foreign_request_id,
      &foreign_escrow, &foreign_request, &foreign_prepared);
  publication = (HandoffPublication) {
  .store = store,.foreign_after_inspect_call = 2,};
  HandoffUnsealGate foreign_gate = {.rc = WYRELOG_E_OK };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &foreign_gate);
  runtime.decision_request_id = foreign_request_id;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, foreign_request_id, &runtime, &foreign_outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (foreign_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED);
  g_assert_cmpstr (foreign_outcome.terminal_reason, ==,
      "oar.v1:file-published:receipt-foreign");
  g_assert_cmpuint (publication.inspect_calls, ==, 2);
  g_assert_cmpuint (foreign_gate.calls, ==, 2);
  g_assert_cmpint (count_handoff_rows_for_request (db, foreign_request_id,
          "delivered"), ==, 0);
  g_assert_cmpint (count_handoff_audits_for_request (db, foreign_request_id),
      ==, 0);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &foreign_escrow, &escrow_info), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_escrow_info_clear (&escrow_info);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  wyl_service_credential_operation_record_clear (&foreign_outcome);
  wyl_service_credential_operation_record_clear (&foreign_prepared);
  wyl_service_credential_operation_coordinator_request_clear (&foreign_request);

  /* Revocation after the second durable FILE inspection but before the consume
   * transaction is caught by the consume-inner exact classifier. */
  gchar inactive_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar revoke_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t inactive_escrow;
  WylServiceCredentialOperationCoordinatorRequest inactive_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord inactive_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord inactive_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  fresh_request_id (revoke_request_id);
  begin_handoff_issue_for_test (&storage, &anchor, now, inactive_request_id,
      &inactive_escrow, &inactive_request, &inactive_prepared);
  publication = (HandoffPublication) {
  .store = store,.revoke_after_inspect_call = 3,.revoke_request_id =
        revoke_request_id,.revoke_rc = WYRELOG_E_INTERNAL,};
  HandoffUnsealGate inactive_gate = {.rc = WYRELOG_E_OK };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &inactive_gate);
  runtime.decision_request_id = inactive_request_id;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, inactive_request_id, &runtime, &inactive_outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (publication.revoke_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (inactive_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED);
  g_assert_cmpstr (inactive_outcome.terminal_reason, ==,
      "oar.v1:file-published:successor-revoked");
  g_assert_cmpint (count_handoff_rows_for_request (db, inactive_request_id,
          "successor_revoked"), ==, 1);
  g_assert_cmpint (count_handoff_rows_for_request (db, inactive_request_id,
          "delivered"), ==, 0);
  g_assert_cmpint (count_handoff_audits_for_request (db, inactive_request_id),
      ==, 1);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &inactive_escrow, &escrow_info), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_escrow_info_clear (&escrow_info);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  wyl_service_credential_operation_record_clear (&inactive_outcome);
  wyl_service_credential_operation_record_clear (&inactive_prepared);
  wyl_service_credential_operation_coordinator_request_clear
      (&inactive_request);

  /* Legacy FILE with an already-absent escrow may adopt one proof-bound
   * tombstone.  The same absence from CLEANUP is typed escrow-missing OAR. */
  for (guint cleanup = 0; cleanup < 2; cleanup++) {
    gchar request_id[WYL_REQUEST_ID_STRING_BUF];
    wyl_id_t escrow;
    WylServiceCredentialOperationCoordinatorRequest request =
        WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
    WylServiceCredentialOperationRecord prepared =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    WylServiceCredentialOperationRecord outcome =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    begin_handoff_issue_for_test (&storage, &anchor, now, request_id, &escrow,
        &request, &prepared);
    publication = (HandoffPublication) {
    .store = store,.fail_release_after_on_inspect_call = 2,};
    HandoffUnsealGate gate = {.rc = WYRELOG_E_OK };
    wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
        handoff_unseal_gate, &gate);
    runtime.decision_request_id = request_id;
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_IO);
    g_assert_cmpint (wyl_service_credential_operation_coordinator_load
        (&storage, &anchor, request_id, &outcome), ==, WYRELOG_E_OK);
    g_assert_cmpint (outcome.state, ==,
        WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED);
    if (cleanup != 0) {
      gboolean replayed = TRUE;
      g_assert_cmpint
          (wyl_service_credential_operation_coordinator_checkpoint_cleanup_required
          (&storage, &anchor, request_id, g_get_real_time (), &replayed,
              &outcome), ==, WYRELOG_E_OK);
      g_assert_false (replayed);
      g_assert_cmpint (outcome.state, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED);
    }
    delete_escrow_for_legacy_test (db, &escrow);
    guint inspect_before = publication.inspect_calls;
    guint unseal_before = gate.calls;
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (publication.inspect_calls, ==, inspect_before);
    g_assert_cmpuint (gate.calls, ==, unseal_before);
    g_assert_cmpint (count_handoff_rows_for_request (db, request_id,
            "delivered"), ==, cleanup == 0 ? 1 : 0);
    g_assert_cmpint (count_handoff_audits_for_request (db, request_id), ==,
        cleanup == 0 ? 1 : 0);
    if (cleanup == 0) {
      g_assert_cmpint (outcome.state, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
      g_assert_cmpint
          (wyl_service_credential_operation_coordinator_execute_handoff (handle,
              &storage, &anchor, request_id, &runtime, &outcome), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (count_handoff_rows_for_request (db, request_id,
              "delivered"), ==, 1);
      g_assert_cmpint (count_handoff_audits_for_request (db, request_id), ==,
          1);
    } else {
      g_assert_cmpint (outcome.state, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED);
      g_assert_cmpstr (outcome.terminal_reason, ==,
          "oar.v1:cleanup-required:escrow-missing");
    }
    wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL,
        NULL);
    wyl_service_credential_operation_record_clear (&outcome);
    wyl_service_credential_operation_record_clear (&prepared);
    wyl_service_credential_operation_coordinator_request_clear (&request);
  }

  /* A same-length tamper of a pinned receipt field cannot be converted into a
   * new delivery proof and leaves the exact escrow intact. */
  gchar tamper_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t tamper_escrow;
  WylServiceCredentialOperationCoordinatorRequest tamper_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord tamper_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord tamper_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  begin_handoff_issue_for_test (&storage, &anchor, now, tamper_request_id,
      &tamper_escrow, &tamper_request, &tamper_prepared);
  publication = (HandoffPublication) {
  .store = store,.fail_release_after_on_inspect_call = 2,};
  HandoffUnsealGate tamper_gate = {.rc = WYRELOG_E_OK };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &tamper_gate);
  runtime.decision_request_id = tamper_request_id;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, tamper_request_id, &runtime, &tamper_outcome), ==,
      WYRELOG_E_IO);
  g_autofree gchar *tamper_journal = g_strdup_printf ("%s/op-%s",
      operation_root, tamper_request_id);
  replace_journal_destination_for_test (tamper_journal, "credentials.json",
      "nested/file.json");
  guint tamper_inspects = publication.inspect_calls;
  guint tamper_unseals = tamper_gate.calls;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, tamper_request_id, &runtime, &tamper_outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (publication.inspect_calls, ==, tamper_inspects);
  g_assert_cmpuint (tamper_gate.calls, ==, tamper_unseals);
  g_assert_cmpint (count_handoff_rows_for_request (db, tamper_request_id,
          "delivered"), ==, 0);
  g_assert_cmpint (count_handoff_audits_for_request (db, tamper_request_id), ==,
      0);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &tamper_escrow, &escrow_info), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_escrow_info_clear (&escrow_info);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  wyl_service_credential_operation_record_clear (&tamper_outcome);
  wyl_service_credential_operation_record_clear (&tamper_prepared);
  wyl_service_credential_operation_coordinator_request_clear (&tamper_request);

  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

static void
test_handoff_automatic_maintenance_gate (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  wyl_policy_store_t *store = store_of (handle);
  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store, "admin",
          "wr.service_credential.manage", session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store, "admin",
          "authenticated"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_session_state (store, session_id,
          "active"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store, "admin",
          "wr.service_credential.manage", session_id, "armed"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  sqlite3 *db = db_of (handle);
  g_autofree gchar *operation_root = g_build_filename (fixture.dir,
      "maintenance-operations", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (operation_root, &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);
  const WyctlPublicationBackendVTable vtable = {
    .plan = handoff_test_plan,
    .stage_exact = handoff_test_stage,
    .receipt_target_acquire = handoff_test_target_acquire,
    .receipt_target_inspect = handoff_test_target_inspect,
    .receipt_target_commit = handoff_test_target_commit,
    .receipt_target_release = handoff_test_target_release,
  };
  HandoffPublication publication = {.store = store };
  HandoffUnsealGate gate = {.rc = WYRELOG_E_IO };
  CountingHandoffClock runtime_clock = {.value = 0 };
  guint authorization_calls = 0;
  gint64 real_now = g_get_real_time ();
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = real_now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .publication = &vtable,
    .publication_data = &publication,
    .now_us = counting_handoff_now,
    .clock_data = &runtime_clock,
    .after_authorization = count_handoff_authorization,
    .authorization_checkpoint_data = &authorization_calls,
  };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store,
      handoff_unseal_gate, &gate);

  static const WylServiceCredentialOperationState committed_states[] = {
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED,
    WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED,
    WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED,
    WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (committed_states); i++) {
    gchar request_id[WYL_REQUEST_ID_STRING_BUF];
    wyl_id_t escrow;
    WylServiceCredentialOperationCoordinatorRequest request =
        WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
    WylServiceCredentialOperationRecord record =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    WylServiceCredentialOperationRecord outcome =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    materialize_handoff_state_for_maintenance (handle, &storage, &anchor,
        real_now - G_TIME_SPAN_HOUR - G_TIME_SPAN_SECOND - (gint64) i * 10,
        committed_states[i], request_id, &escrow, &request, &record);
    runtime.decision_request_id = request_id;
    publication = (HandoffPublication) {
    .store = store};
    gate = (HandoffUnsealGate) {
    .rc = WYRELOG_E_IO};
    authorization_calls = 0;
    runtime_clock = (CountingHandoffClock) {
    .value = 0};
    g_autoptr (GBytes) journal_before = read_handoff_journal_bytes
        (operation_root, request_id);
    wyl_policy_service_handoff_escrow_info_t escrow_before = { 0 };
    wyl_policy_service_handoff_escrow_info_t escrow_after = { 0 };
    wyl_service_credential_t credential_before = { 0 };
    wyl_service_credential_t credential_after = { 0 };
    g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
            &escrow, &escrow_before), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_credential_get (handle,
            record.successor_credential_id, &credential_before), ==,
        WYRELOG_E_OK);
    gint64 events_before = count_events (db);
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (outcome.state, ==, committed_states[i]);
    g_autoptr (GBytes) journal_after = read_handoff_journal_bytes
        (operation_root, request_id);
    g_assert_true (g_bytes_equal (journal_before, journal_after));
    g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
            &escrow, &escrow_after), ==, WYRELOG_E_OK);
    assert_escrow_info_equal (&escrow_before, &escrow_after);
    g_assert_cmpint (wyl_service_credential_get (handle,
            record.successor_credential_id, &credential_after), ==,
        WYRELOG_E_OK);
    assert_credential_equal (&credential_before, &credential_after);
    g_assert_cmpint (count_events (db), ==, events_before);
    g_assert_cmpint (count_handoff_rows_for_request (db, request_id,
            "operation_expired"), ==, 1);
    g_assert_cmpint (count_handoff_audits_for_request (db, request_id), ==, 1);
    assert_no_handoff_execution_callbacks (&publication, &gate,
        authorization_calls, &runtime_clock);

    /* Re-entry replays the same durable attention without new effects. */
    wyl_service_credential_operation_record_clear (&outcome);
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (outcome.state, ==, committed_states[i]);
    g_autoptr (GBytes) journal_replay = read_handoff_journal_bytes
        (operation_root, request_id);
    g_assert_true (g_bytes_equal (journal_before, journal_replay));
    g_assert_cmpint (count_handoff_rows_for_request (db, request_id,
            "operation_expired"), ==, 1);
    g_assert_cmpint (count_handoff_audits_for_request (db, request_id), ==, 1);
    assert_no_handoff_execution_callbacks (&publication, &gate,
        authorization_calls, &runtime_clock);

    if (i == 0) {
      /* Simulate response loss after authority committed an exact revoke but
       * before the old journal snapshot was replaced.  The next execute must
       * reconcile this action before delivery/backfill and absorb terminally
       * without invoking any execution callback. */
      sqlite3_stmt *source_stmt = NULL;
      g_assert_cmpint (sqlite3_prepare_v2 (db,
              "SELECT disposition_id,audit_id FROM"
              " service_credential_handoff_dispositions"
              " WHERE original_request_id=?"
              " AND reason='operation_expired';", -1, &source_stmt, NULL),
          ==, SQLITE_OK);
      g_assert_cmpint (sqlite3_bind_text (source_stmt, 1, request_id, -1,
              SQLITE_TRANSIENT), ==, SQLITE_OK);
      g_assert_cmpint (sqlite3_step (source_stmt), ==, SQLITE_ROW);
      g_autofree gchar *source_disposition = g_strdup
          ((const gchar *) sqlite3_column_text (source_stmt, 0));
      g_autofree gchar *source_audit = g_strdup
          ((const gchar *) sqlite3_column_text (source_stmt, 1));
      g_assert_cmpint (sqlite3_step (source_stmt), ==, SQLITE_DONE);
      sqlite3_finalize (source_stmt);
      g_assert_nonnull (source_disposition);
      g_assert_nonnull (source_audit);
      gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
      gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
      gchar remediation_audit[WYL_ID_STRING_BUF];
      fresh_request_id (remediation_id);
      fresh_request_id (decision_id);
      fresh_execute_uuid (remediation_audit);
      guint8 snapshot_digest[crypto_generichash_BYTES] = { 0 };
      gsize journal_len = 0;
      const guint8 *journal_data = g_bytes_get_data (journal_before,
          &journal_len);
      g_assert_cmpint (crypto_generichash (snapshot_digest,
              sizeof snapshot_digest, journal_data, journal_len, NULL, 0), ==,
          0);
      wyl_service_credential_handoff_remediation_input_t remediation_input = {
        .remediation_request_id = remediation_id,
        .decision_request_id = decision_id,
        .current_actor_subject_id = "operator",
        .audit_id = remediation_audit,
        .tuple = {
              .original_request_id = request_id,
              .escrow_id = &escrow,
              .successor_credential_id = record.successor_credential_id,
              .successor_issuance_generation = record.successor_generation,
              .original_actor_subject_id = record.actor_subject_id,
            },
        .action = WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE,
        .confirmation_version = 1,
        .confirmed = TRUE,
        .source_kind =
            WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION,
        .observed_state =
            WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PLANNED,
        .source_disposition_id = source_disposition,
        .source_audit_id = source_audit,
        .source_reason = WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED,
      };
      memcpy (remediation_input.journal_snapshot_digest, snapshot_digest,
          sizeof snapshot_digest);
      memcpy (remediation_input.tuple.binding_digest,
          record.escrow_binding_digest,
          sizeof remediation_input.tuple.binding_digest);
      wyl_service_credential_mutation_authorization_t remediation_authority = {
        .authorize = allow_operator_remediation,
      };
      wyl_service_credential_handoff_remediation_runtime_t remediation_runtime = {
        .authorization = &remediation_authority,
      };
      wyl_service_credential_handoff_remediation_result_t
          remediation_result = { 0 };
      g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
              &remediation_input, &remediation_runtime, &remediation_result),
          ==, WYRELOG_E_OK);
      g_assert_false (remediation_result.replayed);
      g_assert_true (remediation_result.revoked_now);
      g_autoptr (GBytes) crash_window = read_handoff_journal_bytes
          (operation_root, request_id);
      g_assert_true (g_bytes_equal (journal_before, crash_window));
      wyl_service_credential_handoff_remediation_result_clear
          (&remediation_result);

      wyl_service_credential_operation_record_clear (&outcome);
      g_assert_cmpint
          (wyl_service_credential_operation_coordinator_execute_handoff
          (handle, &storage, &anchor, request_id, &runtime, &outcome), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (outcome.state, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
      g_assert_cmpint (outcome.last_remediation_action, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_REVOKE_AND_WIPE);
      g_assert_cmpstr (outcome.last_remediation_request_id, ==, remediation_id);
      assert_no_handoff_execution_callbacks (&publication, &gate,
          authorization_calls, &runtime_clock);
      g_autoptr (GBytes) reconciled = read_handoff_journal_bytes
          (operation_root, request_id);
      g_assert_false (g_bytes_equal (journal_before, reconciled));
      wyl_policy_service_handoff_escrow_info_t deleted = { 0 };
      g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
              &escrow, &deleted), ==, WYRELOG_E_NOT_FOUND);
    } else if (i == 1) {
      /* A committed RESUME has the same response-loss window.  Recovery must
       * apply its marker before maintenance sees the old attention source,
       * suppress a duplicate disposition, and continue normal publication. */
      sqlite3_stmt *source_stmt = NULL;
      g_assert_cmpint (sqlite3_prepare_v2 (db,
              "SELECT disposition_id,audit_id FROM"
              " service_credential_handoff_dispositions"
              " WHERE original_request_id=?"
              " AND reason='operation_expired';", -1, &source_stmt, NULL),
          ==, SQLITE_OK);
      g_assert_cmpint (sqlite3_bind_text (source_stmt, 1, request_id, -1,
              SQLITE_TRANSIENT), ==, SQLITE_OK);
      g_assert_cmpint (sqlite3_step (source_stmt), ==, SQLITE_ROW);
      g_autofree gchar *source_disposition = g_strdup
          ((const gchar *) sqlite3_column_text (source_stmt, 0));
      g_autofree gchar *source_audit = g_strdup
          ((const gchar *) sqlite3_column_text (source_stmt, 1));
      g_assert_cmpint (sqlite3_step (source_stmt), ==, SQLITE_DONE);
      sqlite3_finalize (source_stmt);
      gchar remediation_id[WYL_REQUEST_ID_STRING_BUF];
      gchar decision_id[WYL_REQUEST_ID_STRING_BUF];
      gchar remediation_audit[WYL_ID_STRING_BUF];
      fresh_request_id (remediation_id);
      fresh_request_id (decision_id);
      fresh_execute_uuid (remediation_audit);
      guint8 snapshot_digest[crypto_generichash_BYTES] = { 0 };
      gsize journal_len = 0;
      const guint8 *journal_data = g_bytes_get_data (journal_before,
          &journal_len);
      g_assert_cmpint (crypto_generichash (snapshot_digest,
              sizeof snapshot_digest, journal_data, journal_len, NULL, 0), ==,
          0);
      wyl_service_credential_handoff_remediation_input_t remediation_input = {
        .remediation_request_id = remediation_id,
        .decision_request_id = decision_id,
        .current_actor_subject_id = "operator",
        .audit_id = remediation_audit,
        .tuple = {
              .original_request_id = request_id,
              .escrow_id = &escrow,
              .successor_credential_id = record.successor_credential_id,
              .successor_issuance_generation = record.successor_generation,
              .original_actor_subject_id = record.actor_subject_id,
            },
        .action = WYL_SERVICE_HANDOFF_REMEDIATION_RESUME,
        .source_kind =
            WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION,
        .observed_state =
            WYL_SERVICE_HANDOFF_REMEDIATION_STATE_SERVER_COMMITTED,
        .source_disposition_id = source_disposition,
        .source_audit_id = source_audit,
        .source_reason = WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED,
      };
      memcpy (remediation_input.journal_snapshot_digest, snapshot_digest,
          sizeof snapshot_digest);
      memcpy (remediation_input.tuple.binding_digest,
          record.escrow_binding_digest,
          sizeof remediation_input.tuple.binding_digest);
      wyl_service_credential_mutation_authorization_t remediation_authority = {
        .authorize = allow_operator_remediation,
      };
      wyl_service_credential_handoff_remediation_runtime_t remediation_runtime = {
        .authorization = &remediation_authority,
      };
      wyl_service_credential_handoff_remediation_result_t
          remediation_result = { 0 };
      g_assert_cmpint (wyl_service_credential_handoff_remediate_exact (handle,
              &remediation_input, &remediation_runtime, &remediation_result),
          ==, WYRELOG_E_OK);
      g_assert_false (remediation_result.replayed);
      g_autoptr (GBytes) crash_window = read_handoff_journal_bytes
          (operation_root, request_id);
      g_assert_true (g_bytes_equal (journal_before, crash_window));
      wyl_service_credential_handoff_remediation_result_clear
          (&remediation_result);

      publication = (HandoffPublication) {
      .store = store};
      gate = (HandoffUnsealGate) {
      .rc = WYRELOG_E_OK};
      authorization_calls = 0;
      runtime_clock = (CountingHandoffClock) {
      .value = g_get_real_time ()};
      wyl_service_credential_operation_record_clear (&outcome);
      g_assert_cmpint
          (wyl_service_credential_operation_coordinator_execute_handoff
          (handle, &storage, &anchor, request_id, &runtime, &outcome), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (outcome.state, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
      g_assert_cmpint (outcome.last_remediation_action, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_RESUME);
      g_assert_cmpstr (outcome.last_remediation_request_id, ==, remediation_id);
      g_assert_cmpint (count_handoff_rows_for_request (db, request_id,
              "operation_expired"), ==, 1);
      g_assert_cmpuint (publication.inspect_calls, >, 0);
      g_assert_cmpuint (gate.calls, >, 0);
    }

    wyl_service_credential_clear (&credential_after);
    wyl_service_credential_clear (&credential_before);
    wyl_policy_service_handoff_escrow_info_clear (&escrow_after);
    wyl_policy_service_handoff_escrow_info_clear (&escrow_before);
    wyl_service_credential_operation_record_clear (&outcome);
    wyl_service_credential_operation_record_clear (&record);
    wyl_service_credential_operation_coordinator_request_clear (&request);
  }

  /* Missing and foreign escrow proofs become durable OAR before any caller
   * clock, authorization, publication, or unseal callback. */
  for (guint foreign = 0; foreign < 2; foreign++) {
    gchar request_id[WYL_REQUEST_ID_STRING_BUF];
    wyl_id_t escrow;
    WylServiceCredentialOperationCoordinatorRequest request =
        WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
    WylServiceCredentialOperationRecord record =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    WylServiceCredentialOperationRecord outcome =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    materialize_handoff_state_for_maintenance (handle, &storage, &anchor,
        real_now + 100 + foreign,
        WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED, request_id, &escrow,
        &request, &record);
    if (foreign != 0)
      make_escrow_foreign_for_maintenance_test (db, &escrow);
    else
      delete_escrow_for_legacy_test (db, &escrow);
    runtime.decision_request_id = request_id;
    publication = (HandoffPublication) {
    .store = store};
    gate = (HandoffUnsealGate) {
    .rc = WYRELOG_E_IO};
    authorization_calls = 0;
    runtime_clock = (CountingHandoffClock) {
    .value = 0};
    wyl_service_credential_t credential_before = { 0 };
    wyl_service_credential_t credential_after = { 0 };
    g_assert_cmpint (wyl_service_credential_get (handle,
            record.successor_credential_id, &credential_before), ==,
        WYRELOG_E_OK);
    wyl_policy_service_handoff_escrow_info_t escrow_before = { 0 };
    wyl_policy_service_handoff_escrow_info_t escrow_after = { 0 };
    if (foreign != 0)
      g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
              &escrow, &escrow_before), ==, WYRELOG_E_OK);
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (outcome.state, ==,
        WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED);
    g_assert_cmpstr (outcome.terminal_reason, ==, foreign != 0 ?
        "oar.v1:server-committed:escrow-foreign" :
        "oar.v1:server-committed:escrow-missing");
    g_autoptr (GBytes) oar_journal = read_handoff_journal_bytes
        (operation_root, request_id);
    if (foreign != 0) {
      g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
              &escrow, &escrow_after), ==, WYRELOG_E_OK);
      assert_escrow_info_equal (&escrow_before, &escrow_after);
    }
    g_assert_cmpint (wyl_service_credential_get (handle,
            record.successor_credential_id, &credential_after), ==,
        WYRELOG_E_OK);
    assert_credential_equal (&credential_before, &credential_after);
    g_assert_cmpint (count_handoff_audits_for_request (db, request_id), ==, 0);
    assert_no_handoff_execution_callbacks (&publication, &gate,
        authorization_calls, &runtime_clock);

    wyl_service_credential_operation_record_clear (&outcome);
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_execute_handoff (handle,
            &storage, &anchor, request_id, &runtime, &outcome), ==,
        WYRELOG_E_OK);
    g_autoptr (GBytes) oar_replay = read_handoff_journal_bytes
        (operation_root, request_id);
    g_assert_true (g_bytes_equal (oar_journal, oar_replay));
    assert_no_handoff_execution_callbacks (&publication, &gate,
        authorization_calls, &runtime_clock);
    wyl_policy_service_handoff_escrow_info_clear (&escrow_after);
    wyl_policy_service_handoff_escrow_info_clear (&escrow_before);
    wyl_service_credential_clear (&credential_after);
    wyl_service_credential_clear (&credential_before);
    wyl_service_credential_operation_record_clear (&outcome);
    wyl_service_credential_operation_record_clear (&record);
    wyl_service_credential_operation_coordinator_request_clear (&request);
  }

  /* An expired PREPARED operation reaches terminal-not-committed without a
   * credential mutation.  A cancelled maintenance attempt writes nothing. */
  gchar prepared_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t prepared_escrow;
  WylServiceCredentialOperationCoordinatorRequest prepared_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord prepared_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  begin_handoff_issue_for_test (&storage, &anchor,
      real_now - G_TIME_SPAN_HOUR - G_TIME_SPAN_SECOND, prepared_request_id,
      &prepared_escrow, &prepared_request, &prepared);
  runtime.decision_request_id = prepared_request_id;
  publication = (HandoffPublication) {
  .store = store};
  gate = (HandoffUnsealGate) {
  .rc = WYRELOG_E_IO};
  authorization_calls = 0;
  runtime_clock = (CountingHandoffClock) {
  .value = 0};
  gint64 credentials_before = count_credentials (db);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, prepared_request_id, &runtime,
          &prepared_outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (prepared_outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpstr (prepared_outcome.terminal_reason, ==,
      "terminal.v1:not-committed");
  g_assert_cmpint (count_credentials (db), ==, credentials_before);
  g_assert_cmpint (count_handoff_rows_for_request (db, prepared_request_id,
          "not_committed"), ==, 1);
  g_assert_cmpint (count_handoff_audits_for_request (db,
          prepared_request_id), ==, 1);
  wyl_policy_service_handoff_escrow_info_t absent_escrow = { 0 };
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &prepared_escrow, &absent_escrow), ==, WYRELOG_E_NOT_FOUND);
  assert_no_handoff_execution_callbacks (&publication, &gate,
      authorization_calls, &runtime_clock);
  g_autoptr (GBytes) prepared_terminal = read_handoff_journal_bytes
      (operation_root, prepared_request_id);
  wyl_service_credential_operation_record_clear (&prepared_outcome);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, prepared_request_id, &runtime,
          &prepared_outcome), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) prepared_replay = read_handoff_journal_bytes
      (operation_root, prepared_request_id);
  g_assert_true (g_bytes_equal (prepared_terminal, prepared_replay));
  g_assert_cmpint (count_handoff_rows_for_request (db, prepared_request_id,
          "not_committed"), ==, 1);
  g_assert_cmpint (count_handoff_audits_for_request (db,
          prepared_request_id), ==, 1);
  assert_no_handoff_execution_callbacks (&publication, &gate,
      authorization_calls, &runtime_clock);
  wyl_service_credential_operation_record_clear (&prepared_outcome);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_coordinator_request_clear
      (&prepared_request);

  gchar cancelled_request_id[WYL_REQUEST_ID_STRING_BUF];
  wyl_id_t cancelled_escrow;
  WylServiceCredentialOperationCoordinatorRequest cancelled_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord cancelled_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord cancelled_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  begin_handoff_issue_for_test (&storage, &anchor, real_now + 300,
      cancelled_request_id, &cancelled_escrow, &cancelled_request,
      &cancelled_prepared);
  g_autoptr (GBytes) cancelled_before = read_handoff_journal_bytes
      (operation_root, cancelled_request_id);
  g_autoptr (GCancellable) cancelled = g_cancellable_new ();
  g_cancellable_cancel (cancelled);
  runtime.decision_request_id = cancelled_request_id;
  runtime.cancellable = cancelled;
  publication = (HandoffPublication) {
  .store = store};
  gate = (HandoffUnsealGate) {
  .rc = WYRELOG_E_IO};
  authorization_calls = 0;
  runtime_clock = (CountingHandoffClock) {
  .value = 0};
  credentials_before = count_credentials (db);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_execute_handoff (handle,
          &storage, &anchor, cancelled_request_id, &runtime,
          &cancelled_outcome), !=, WYRELOG_E_OK);
  g_autoptr (GBytes) cancelled_after = read_handoff_journal_bytes
      (operation_root, cancelled_request_id);
  g_assert_true (g_bytes_equal (cancelled_before, cancelled_after));
  g_assert_cmpint (count_credentials (db), ==, credentials_before);
  g_assert_cmpint (count_handoff_rows_for_request (db, cancelled_request_id,
          "not_committed"), ==, 0);
  g_assert_cmpint (count_handoff_rows_for_request (db, cancelled_request_id,
          "operation_cancelled"), ==, 0);
  g_assert_cmpint (count_handoff_audits_for_request (db,
          cancelled_request_id), ==, 0);
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load (store,
          &cancelled_escrow, &absent_escrow), ==, WYRELOG_E_NOT_FOUND);
  assert_no_handoff_execution_callbacks (&publication, &gate,
      authorization_calls, &runtime_clock);
  runtime.cancellable = NULL;
  wyl_service_credential_operation_record_clear (&cancelled_outcome);
  wyl_service_credential_operation_record_clear (&cancelled_prepared);
  wyl_service_credential_operation_coordinator_request_clear
      (&cancelled_request);

  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store, NULL, NULL);
  wyl_service_credential_operation_storage_clear (&storage);
  remove_operation_root_for_test (operation_root);
}

static wyl_policy_store_t *
store_of (WylHandle *handle)
{
  return wyl_handle_get_policy_store (handle);
}

static sqlite3 *
db_of (WylHandle *handle)
{
  return wyl_policy_store_get_db (store_of (handle));
}

static gint64
scalar (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static gboolean
contains_bytes (const guint8 *haystack, gsize haystack_len,
    const guint8 *needle, gsize needle_len)
{
  if (needle_len > haystack_len)
    return FALSE;
  for (gsize i = 0; i <= haystack_len - needle_len; i++)
    if (memcmp (haystack + i, needle, needle_len) == 0)
      return TRUE;
  return FALSE;
}

static gint64
like_scan (sqlite3 *db, const gchar *sql, const gchar *secret)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_autofree gchar *pattern = g_strdup_printf ("%%%s%%", secret);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, pattern, -1, SQLITE_TRANSIENT),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static void
prepare_authority (WylHandle *handle, const gchar *subject_id)
{
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, subject_id,
          subject_id, "admin", "principal-create", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store_of (handle),
          "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
}

static void
fresh_request_id (gchar *buf)
{
  g_assert_cmpint (wyl_request_id_new (buf, WYL_REQUEST_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
}

static void
fresh_execute_uuid (gchar out[WYL_ID_STRING_BUF])
{
  wyl_id_t id;
  g_assert_cmpint (wyl_id_new (&id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&id, out, WYL_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
}

static WylServiceCredentialOperationRecord
prepared_issue_record (const gchar *actor, const gchar *request_id,
    gint64 expiry)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED,
    .operation_id = g_strdup ("op-1"),
    .request_id = g_strdup (request_id),
    .subject_id = g_strdup ("svc:issue:worker"),
    .tenant_id = g_strdup ("tenant-a"),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup (actor),
    .old_credential_id = g_strdup (""),
    .successor_credential_id = g_strdup (""),
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = 0,
    .successor_generation = 0,
    .expires_at_us = expiry,
    .created_at_us = 100,
    .updated_at_us = 100,
  };
  g_assert_true (wyl_service_credential_operation_record_is_valid (&record));
  return record;
}

static WylServiceCredentialOperationRecord
prepared_rotate_record (const gchar *actor, const gchar *request_id,
    const gchar *old_credential_id, guint64 expected_generation, gint64 expiry)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED,
    .operation_id = g_strdup ("op-1"),
    .request_id = g_strdup (request_id),
    .subject_id = g_strdup ("svc:rotate:worker"),
    .tenant_id = g_strdup (""),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup (actor),
    .old_credential_id = g_strdup (old_credential_id),
    .successor_credential_id = g_strdup (""),
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = expected_generation,
    .successor_generation = 0,
    .expires_at_us = expiry,
    .created_at_us = 100,
    .updated_at_us = 100,
  };
  g_assert_true (wyl_service_credential_operation_record_is_valid (&record));
  return record;
}

static WylServiceCredentialOperationRecord
server_committed_record (const gchar *actor, const gchar *request_id,
    gint64 expiry)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
    .operation_id = g_strdup ("op-1"),
    .request_id = g_strdup (request_id),
    .subject_id = g_strdup ("svc:issue:worker"),
    .tenant_id = g_strdup ("tenant-a"),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup (actor),
    .old_credential_id = g_strdup (""),
    .successor_credential_id = g_strdup (ROTATE_CANONICAL_ID),
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = 0,
    .successor_generation = 1,
    .expires_at_us = expiry,
    .created_at_us = 100,
    .updated_at_us = 100,
  };
  for (guint i = 0; i < sizeof record.escrow_binding_digest; i++)
    record.escrow_binding_digest[i] = (guint8) (i + 1);
  g_assert_true (wyl_service_credential_operation_record_is_valid (&record));
  return record;
}

static gint64
count_credentials (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM service_credentials;");
}

static gint64
count_events (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM service_credential_events;");
}

static gint64
count_audits (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM audit_events;");
}

static gint64
count_requests (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM service_domain_requests;");
}

static gint64
count_cvk (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM service_credential_cvk;");
}

static gint64
count_fences (sqlite3 *db)
{
  return scalar (db,
      "SELECT count(*) FROM service_credential_operation_fences;");
}

static gint64
count_audit_intentions (sqlite3 *db)
{
  return scalar (db, "SELECT count(*) FROM audit_intentions;");
}

static void
test_issue_success (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.handle = handle,.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint (count_credentials (db), ==, 0);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);
  g_assert_cmpstr (out.credential.subject_id, ==, "svc:issue:worker");
  g_assert_cmpstr (out.credential.tenant_id, ==, "tenant-a");
  g_assert_cmpuint (out.credential.generation, ==, 1);
  g_assert_cmpuint (stub.calls, ==, 1);
  g_assert_true (stub.saw_write_lease);
  g_assert_cmpstr (stub.seen_actor, ==, "admin");

  g_assert_cmpint (count_credentials (db), ==, 1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM service_credential_events "
          "WHERE event='issued' AND actor_subject_id='admin';"), ==, 1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM audit_events "
          "WHERE action='service.credential.issue' AND subject_id='admin';"),
      ==, 1);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

static void
test_rotate_success (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:rotate:worker");
  sqlite3 *db = db_of (handle);

  gchar issue_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (issue_request);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  wyl_service_credential_issue_result_t seed = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:rotate:worker",
          "tenant-a", "admin", issue_request, expiry, &seed), ==, WYRELOG_E_OK);
  g_autofree gchar *old_id = g_strdup (seed.credential.credential_id);
  guint64 generation = seed.credential.generation;
  g_assert_cmpuint (generation, ==, 1);
  wyl_service_credential_issue_result_clear (&seed);

  gchar rotate_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (rotate_request);
  WylServiceCredentialOperationRecord record =
      prepared_rotate_record ("admin", rotate_request, old_id, generation,
      expiry);
  Stub stub = {.handle = handle,.rc = WYRELOG_E_OK };
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .old_credential_generation = generation,
  };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
    .rotate_runtime = &rotate_runtime,
  };
  wyl_service_credential_issue_result_t out = { 0 };

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);
  g_assert_cmpstr (out.credential.subject_id, ==, "svc:rotate:worker");
  g_assert_cmpstr (out.credential.rotated_from_id, ==, old_id);
  g_assert_cmpuint (stub.calls, ==, 1);
  g_assert_true (stub.saw_write_lease);
  g_assert_cmpstr (stub.seen_actor, ==, "admin");
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM service_credentials WHERE state='active';"),
      ==, 1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM audit_events "
          "WHERE action='service.credential.rotate' AND subject_id='admin';"),
      ==, 1);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

static void
test_actor_mismatch (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  gint64 before_creds = count_credentials (db);
  gint64 before_events = count_events (db);
  gint64 before_audits = count_audits (db);
  gint64 before_requests = count_requests (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "mallory", &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpuint (stub.calls, ==, 0);
  g_assert_cmpint (count_credentials (db), ==, before_creds);
  g_assert_cmpint (count_events (db), ==, before_events);
  g_assert_cmpint (count_audits (db), ==, before_audits);
  g_assert_cmpint (count_requests (db), ==, before_requests);

  wyl_service_credential_operation_record_clear (&record);
}

static void
test_permission_loss (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.handle = handle,.rc = WYRELOG_E_POLICY };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  gint64 before_creds = count_credentials (db);
  gint64 before_events = count_events (db);
  gint64 before_audits = count_audits (db);
  gint64 before_requests = count_requests (db);
  gint64 before_cvk = count_cvk (db);
  gint64 before_fences = count_fences (db);
  gint64 before_audit_intentions = count_audit_intentions (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpuint (stub.calls, ==, 1);
  g_assert_true (stub.saw_write_lease);
  g_assert_cmpint (count_credentials (db), ==, before_creds);
  g_assert_cmpint (count_events (db), ==, before_events);
  g_assert_cmpint (count_audits (db), ==, before_audits);
  g_assert_cmpint (count_requests (db), ==, before_requests);
  g_assert_cmpint (count_cvk (db), ==, before_cvk);
  g_assert_cmpint (count_fences (db), ==, before_fences);
  g_assert_cmpint (count_audit_intentions (db), ==, before_audit_intentions);

  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

typedef struct
{
  GMutex mutex;
  GCond cond;
  WylHandle *handle;
  gboolean entered;
  gboolean release;
  gboolean saw_write_lease;
} AuthorizationBarrier;

static wyrelog_error_t
barrier_revalidate (gpointer data, const gchar *actor_subject_id)
{
  AuthorizationBarrier *barrier = data;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  g_assert_cmpstr (actor_subject_id, ==, "admin");
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (barrier->handle), &snapshot);
  g_mutex_lock (&barrier->mutex);
  barrier->saw_write_lease = snapshot.writer_active;
  barrier->entered = TRUE;
  g_cond_signal (&barrier->cond);
  while (!barrier->release)
    g_cond_wait (&barrier->cond, &barrier->mutex);
  g_mutex_unlock (&barrier->mutex);
  return WYRELOG_E_OK;
}

typedef struct
{
  WylHandle *handle;
  WylServiceCredentialOperationRecord *record;
  WylServiceCredentialOperationExecuteRuntime *runtime;
  wyrelog_error_t rc;
  wyl_service_credential_issue_result_t result;
} ExecuteCall;

static gpointer
execute_thread (gpointer data)
{
  ExecuteCall *call = data;
  call->rc =
      wyl_service_credential_operation_coordinator_authorize_and_execute
      (call->handle, call->record, "admin", call->runtime, &call->result);
  return NULL;
}

typedef struct
{
  WylHandle *handle;
  wyrelog_error_t rc;
  wyl_service_principal_t principal;
} ContendingMutation;

static gpointer
contending_mutation_thread (gpointer data)
{
  ContendingMutation *mutation = data;
  mutation->rc = wyl_service_principal_create (mutation->handle,
      "svc:execute:contender", "contender", "admin", "execute-contender",
      &mutation->principal);
  return NULL;
}

static void
test_authorization_holds_write_lease_against_contender (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:execute:worker");
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylServiceCredentialOperationRecord record = prepared_issue_record
      ("admin", request_id, g_get_real_time () + 60 * G_USEC_PER_SEC);
  g_free (record.subject_id);
  record.subject_id = g_strdup ("svc:execute:worker");
  AuthorizationBarrier barrier = {.handle = handle };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.cond);
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = barrier_revalidate,
    .revalidate_data = &barrier,
  };
  ExecuteCall call = {
    .handle = handle,
    .record = &record,
    .runtime = &runtime,
    .rc = WYRELOG_E_INTERNAL,
  };
  GThread *executor = g_thread_new ("credential-execute", execute_thread,
      &call);
  g_mutex_lock (&barrier.mutex);
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  while (!barrier.entered)
    g_assert_true (g_cond_wait_until (&barrier.cond, &barrier.mutex, deadline));
  g_mutex_unlock (&barrier.mutex);
  g_assert_true (barrier.saw_write_lease);

  ContendingMutation contender = {
    .handle = handle,
    .rc = WYRELOG_E_INTERNAL,
  };
  GThread *contending = g_thread_new ("credential-contender",
      contending_mutation_thread, &contender);
  for (;;) {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_service_auth_authority_snapshot
        (wyl_handle_get_service_auth_authority (handle), &snapshot);
    if (snapshot.waiting_writers == 1)
      break;
    g_assert_cmpint (g_get_monotonic_time (), <, deadline);
    g_thread_yield ();
  }

  g_mutex_lock (&barrier.mutex);
  barrier.release = TRUE;
  g_cond_signal (&barrier.cond);
  g_mutex_unlock (&barrier.mutex);
  g_thread_join (executor);
  g_thread_join (contending);
  g_assert_cmpint (call.rc, ==, WYRELOG_E_OK);
  g_assert_nonnull (call.result.secret);
  g_assert_cmpint (contender.rc, ==, WYRELOG_E_OK);
  wyl_service_credential_issue_result_clear (&call.result);
  wyl_service_principal_clear (&contender.principal);
  wyl_service_credential_operation_record_clear (&record);
  g_cond_clear (&barrier.cond);
  g_mutex_clear (&barrier.mutex);
}

/* Not a threaded race: exercises the durable request-id fence when the same
 * PREPARED intent is executed twice. Threaded concurrency of the mutation is
 * owned by the domain/fence suites. */
static void
test_duplicate_fence_idempotency (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };

  WylServiceCredentialOperationRecord first =
      prepared_issue_record ("admin", request_id, expiry);
  wyl_service_credential_issue_result_t out_first = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &first, "admin", &runtime, &out_first), ==, WYRELOG_E_OK);
  g_assert_nonnull (out_first.secret);

  WylServiceCredentialOperationRecord second =
      prepared_issue_record ("admin", request_id, expiry);
  wyl_service_credential_issue_result_t out_second = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &second, "admin", &runtime, &out_second), ==, WYRELOG_E_POLICY);
  g_assert_null (out_second.secret);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM service_credentials "
          "WHERE subject_id='svc:issue:worker' AND state='active';"), ==, 1);

  wyl_service_credential_issue_result_clear (&out_first);
  wyl_service_credential_operation_record_clear (&first);
  wyl_service_credential_operation_record_clear (&second);
  g_free (stub.seen_actor);
}

static void
test_output_byte_preservation (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);

  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (out.secret, &secret_len);
  g_assert_cmpuint (secret_len, ==, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  gboolean authenticated = FALSE;
  g_assert_cmpint (wyl_service_credential_verify_authoritative (handle,
          out.credential.credential_id, secret, secret_len, &authenticated),
      ==, WYRELOG_E_OK);
  g_assert_true (authenticated);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
}

static void
test_no_secret_leakage (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_OK);
  g_assert_nonnull (out.secret);

  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (out.secret, &secret_len);
  g_autofree gchar *secret_copy = g_strndup (secret, secret_len);

  g_assert_cmpint (like_scan (db_of (handle),
          "SELECT count(*) FROM audit_events WHERE "
          "coalesce(subject_id,'')||coalesce(action,'')||"
          "coalesce(resource_id,'')||coalesce(request_id,'') LIKE ?;",
          secret_copy), ==, 0);
  g_assert_cmpint (like_scan (db_of (handle),
          "SELECT count(*) FROM service_credential_events WHERE "
          "coalesce(credential_id,'')||coalesce(subject_id,'')||"
          "coalesce(tenant_id,'')||coalesce(actor_subject_id,'')||"
          "coalesce(request_id,'') LIKE ?;", secret_copy), ==, 0);

  wyl_service_credential_issue_result_clear (&out);
  wyl_service_credential_operation_record_clear (&record);
  g_free (stub.seen_actor);
  g_clear_object (&fixture.handle);

  g_autofree gchar *encrypted = NULL;
  gsize encrypted_len = 0;
  g_assert_true (g_file_get_contents (fixture.db_path, &encrypted,
          &encrypted_len, NULL));
  g_assert_false (contains_bytes ((const guint8 *) encrypted, encrypted_len,
          (const guint8 *) secret_copy, secret_len));
}

static void
test_state_guard_server_committed (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord record =
      server_committed_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };
  gint64 before_creds = count_credentials (db);
  gint64 before_events = count_events (db);
  gint64 before_audits = count_audits (db);
  gint64 before_requests = count_requests (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &record, "admin", &runtime, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out.secret);
  g_assert_null (out.credential.credential_id);
  g_assert_cmpuint (stub.calls, ==, 0);
  g_assert_cmpint (count_credentials (db), ==, before_creds);
  g_assert_cmpint (count_events (db), ==, before_events);
  g_assert_cmpint (count_audits (db), ==, before_audits);
  g_assert_cmpint (count_requests (db), ==, before_requests);

  wyl_service_credential_operation_record_clear (&record);
}

static void
test_dispatch_guards (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:issue:worker");
  sqlite3 *db = db_of (handle);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  WylServiceCredentialOperationRecord issue =
      prepared_issue_record ("admin", request_id, expiry);
  Stub stub = {.rc = WYRELOG_E_OK };
  WylServiceCredentialOperationExecuteRuntime runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
  };
  wyl_service_credential_issue_result_t out = { 0 };

  gint64 before_creds = count_credentials (db);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (NULL, &issue, "admin", &runtime, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, NULL, "admin", &runtime, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, NULL, &runtime, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, "admin", NULL, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, "admin", &runtime, NULL), ==, WYRELOG_E_INVALID);

  WylServiceCredentialOperationExecuteRuntime no_fn = {
    .revalidate = NULL,
    .revalidate_data = &stub,
  };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &issue, "admin", &no_fn, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (stub.calls, ==, 0);

  /* ROTATE record with a NULL rotate_runtime -> WYRELOG_E_INVALID as a
   * structural argument check, before the authority callback ever fires. */
  gchar rotate_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (rotate_request);
  WylServiceCredentialOperationRecord rotate_missing =
      prepared_rotate_record ("admin", rotate_request, ROTATE_CANONICAL_ID, 1,
      expiry);
  WylServiceCredentialOperationExecuteRuntime rotate_no_runtime = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
    .rotate_runtime = NULL,
  };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &rotate_missing, "admin", &rotate_no_runtime, &out), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpuint (stub.calls, ==, 0);

  /* ROTATE record whose bound generation disagrees with the CAS runtime
   * generation -> WYRELOG_E_POLICY before the authority callback fires, so a
   * request that can never execute leaves no audit side effect. */
  gchar mismatch_request[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (mismatch_request);
  WylServiceCredentialOperationRecord rotate_mismatch =
      prepared_rotate_record ("admin", mismatch_request, ROTATE_CANONICAL_ID, 1,
      expiry);
  wyl_service_credential_rotate_runtime_t bad_runtime = {
    .old_credential_generation = 2,
  };
  WylServiceCredentialOperationExecuteRuntime rotate_bad_gen = {
    .revalidate = stub_revalidate,
    .revalidate_data = &stub,
    .rotate_runtime = &bad_runtime,
  };
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_authorize_and_execute
      (handle, &rotate_mismatch, "admin", &rotate_bad_gen, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (stub.calls, ==, 0);
  g_assert_null (out.secret);
  g_assert_cmpint (count_credentials (db), ==, before_creds);

  wyl_service_credential_operation_record_clear (&issue);
  wyl_service_credential_operation_record_clear (&rotate_missing);
  wyl_service_credential_operation_record_clear (&rotate_mismatch);
  g_free (stub.seen_actor);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-credential-operation-execute/issue-success",
      test_issue_success);
  g_test_add_func ("/service-credential-operation-execute/rotate-success",
      test_rotate_success);
  g_test_add_func ("/service-credential-operation-execute/actor-mismatch",
      test_actor_mismatch);
  g_test_add_func ("/service-credential-operation-execute/permission-loss",
      test_permission_loss);
  g_test_add_func ("/service-credential-operation-execute/authorization-race",
      test_authorization_holds_write_lease_against_contender);
  g_test_add_func ("/service-credential-operation-execute/duplicate-fence",
      test_duplicate_fence_idempotency);
  g_test_add_func ("/service-credential-operation-execute/byte-preservation",
      test_output_byte_preservation);
  g_test_add_func ("/service-credential-operation-execute/no-secret-leakage",
      test_no_secret_leakage);
  g_test_add_func ("/service-credential-operation-execute/state-guard",
      test_state_guard_server_committed);
  g_test_add_func ("/service-credential-operation-execute/dispatch-guards",
      test_dispatch_guards);
  g_test_add_func ("/service-credential-operation-execute/handoff-e2e",
      test_authenticated_handoff_issue_end_to_end);
  g_test_add_func
      ("/service-credential-operation-execute/handoff-delivery-recovery",
      test_handoff_delivery_recovery_matrix);
  g_test_add_func
      ("/service-credential-operation-execute/handoff-maintenance-gate",
      test_handoff_automatic_maintenance_gate);
  return g_test_run ();
}

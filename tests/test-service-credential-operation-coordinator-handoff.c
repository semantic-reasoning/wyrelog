/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <sqlite3.h>
#include <string.h>

#include "auth/service-credential-operation-coordinator-execute-private.h"
#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "auth/service-credential-domain-private.h"
#include "auth/service-credential-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyl-id-private.h"
#include "wyl-session-layout-private.h"
#include "wyl-request-id-private.h"
#include "../wyrelog/wyctl/wyctl-publication-private.h"
#include "test-service-credential-operation-root.h"

typedef struct
{
  WylHandle *handle;
  gchar *dir;
  gchar *db_path;
  gchar *audit_path;
  gchar *key_path;
  gchar *key_spec;
  gchar *operation_root;
  WylServiceCredentialOperationStorage storage;
  WylServiceCredentialOperationRootAnchor anchor;
} Fixture;

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

/* Grant the human session actor authority to run the escrow handoff manage
 * decision so the executor's per-lease wyl_decide resolves to ALLOW. */
static void
authorize_session (WylHandle *handle, const gchar *actor, WylSession *session)
{
  wyl_policy_store_t *store = store_of (handle);
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store, actor,
          "wr.service_credential.manage", session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store, actor,
          "authenticated"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_session_state (store, session_id,
          "active"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store, actor,
          "wr.service_credential.manage", session_id, "armed"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
}

static void
fixture_clear (Fixture *fixture)
{
  wyl_service_credential_operation_storage_clear (&fixture->storage);
  g_clear_object (&fixture->handle);
  if (fixture->operation_root != NULL) {
    GDir *dir = g_dir_open (fixture->operation_root, 0, NULL);
    if (dir != NULL) {
      const gchar *name;
      while ((name = g_dir_read_name (dir)) != NULL) {
        g_autofree gchar *path = g_build_filename (fixture->operation_root,
            name, NULL);
        (void) g_remove (path);
      }
      g_dir_close (dir);
    }
    (void) g_rmdir (fixture->operation_root);
  }
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
  g_free (fixture->operation_root);
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
  *fixture = (Fixture) {
  .storage = WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT,.anchor =
        WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT,};
  fixture->dir = g_dir_make_tmp ("wyl-credential-handoff-XXXXXX", NULL);
  g_assert_nonnull (fixture->dir);
  fixture->db_path = g_build_filename (fixture->dir, "policy.db", NULL);
  fixture->key_path = g_build_filename (fixture->dir, "policy.key", NULL);
  fixture->audit_path = g_build_filename (fixture->dir, "audit.db", NULL);
  fixture->operation_root = service_credential_operation_root_for_test
      (fixture->dir, "handoff-frontdoor-operations");
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
  g_assert_cmpint (wyl_service_credential_operation_storage_open
      (fixture->operation_root, &fixture->storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&fixture->storage, &fixture->anchor), ==, WYRELOG_E_OK);
}

/* Mock owner publication backend; the non-failure subset drives a fresh ISSUE
 * request from SERVER_COMMITTED all the way to a delivered TERMINAL. */
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
} HandoffUnsealGate;

static wyrelog_error_t
handoff_unseal_gate (gpointer data)
{
  HandoffUnsealGate *gate = data;
  gate->calls++;
  return gate->rc;
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
  if (require_destination && !backend->published) {
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
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        lease->destination_target ?
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE :
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED,.exact_identity =
        TRUE,.cleanup_required = !lease->destination_target,};
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

static const WyctlPublicationBackendVTable handoff_test_vtable = {
  .plan = handoff_test_plan,
  .stage_exact = handoff_test_stage,
  .receipt_target_acquire = handoff_test_target_acquire,
  .receipt_target_inspect = handoff_test_target_inspect,
  .receipt_target_commit = handoff_test_target_commit,
  .receipt_target_release = handoff_test_target_release,
};

/* Build an ISSUE front-door request that carries NO escrow identity; the front
 * door derives escrow_id and escrow_binding_digest from request_id. */
static WylServiceCredentialOperationCoordinatorRequest
issue_request_new (const gchar *request_id, const gchar *subject_id,
    gint64 now_us)
{
  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  request.request_id = g_strdup (request_id);
  request.subject_id = g_strdup (subject_id);
  request.tenant_id = g_strdup ("tenant-a");
  request.destination = g_strdup ("credentials.json");
  request.parent_identity = g_strdup ("test-parent-identity");
  request.actor_subject_id = g_strdup ("admin");
  request.expires_at_us = now_us + G_TIME_SPAN_HOUR;
  return request;
}

static void
put_u32be (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

/* Independent re-derivation of the front-door escrow_id, byte-identical to the
 * production derivation, used to prove determinism and to build begin-layer
 * requests.  escrow_binding_digest is intentionally not derived: it is minted
 * at server-commit and stays zero on an uncommitted request. */
static void
derive_escrow_id_for_test (const gchar *request_id,
    gchar out_escrow_id[WYL_ID_STRING_BUF])
{
  guint8 id_bytes[WYL_ID_BYTES];
  wyl_id_t id;
  crypto_generichash_state state;
  const gchar *inputs[2] = { "wyrelog.sc.escrow.id.v1", request_id };
  g_assert_cmpint (crypto_generichash_init (&state, NULL, 0, WYL_ID_BYTES), ==,
      0);
  for (gsize i = 0; i < G_N_ELEMENTS (inputs); i++) {
    gsize len = strlen (inputs[i]);
    guint8 encoded_len[4];
    put_u32be (encoded_len, (guint32) len);
    g_assert_cmpint (crypto_generichash_update (&state, encoded_len,
            sizeof encoded_len), ==, 0);
    g_assert_cmpint (crypto_generichash_update (&state,
            (const guint8 *) inputs[i], len), ==, 0);
  }
  g_assert_cmpint (crypto_generichash_final (&state, id_bytes, WYL_ID_BYTES),
      ==, 0);
  sodium_memzero (&state, sizeof state);
  id_bytes[6] = (guint8) (0x70 | (id_bytes[6] & 0x0f));
  id_bytes[8] = (guint8) (0x80 | (id_bytes[8] & 0x3f));
  memcpy (id.bytes, id_bytes, sizeof id.bytes);
  g_assert_cmpint (wyl_id_format (&id, out_escrow_id, WYL_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
}

static void
assert_escrow_round_trips (const gchar *escrow_id)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_parse (escrow_id, &parsed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&parsed, canonical, sizeof canonical), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (canonical, ==, escrow_id);
}

static gboolean
digest_is_nonzero (const guint8 *digest, gsize len)
{
  for (gsize i = 0; i < len; i++)
    if (digest[i] != 0)
      return TRUE;
  return FALSE;
}

/* Issue happy path: a request without escrow is derived, begun, and driven to a
 * delivered TERMINAL, minting exactly one credential with no secret returned. */
static void
test_frontdoor_issue_happy_path (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 now = g_get_real_time ();
  WylServiceCredentialOperationCoordinatorRequest request =
      issue_request_new (request_id, "svc:handoff:executor", now);

  HandoffPublication publication = {.store = store_of (handle) };
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = request_id,
    .publication = &handoff_test_vtable,
    .publication_data = &publication,
  };
  WylServiceCredentialOperationRecord outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;

  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &request, &runtime, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpuint (publication.plan_calls, ==, 1);
  g_assert_cmpuint (publication.stage_calls, ==, 1);
  g_assert_cmpuint (publication.preflight_calls, ==, 2);
  g_assert_cmpuint (publication.commit_calls, ==, 1);
  g_assert_cmpuint (publication.inspect_calls, ==, 3);
  g_assert_cmpuint (publication.active_leases, ==, 0);
  g_assert_cmpuint (publication.release_calls, ==, 2);
  g_assert_cmpint (count_credentials (db_of (handle)), ==, 1);
  g_assert_cmpint (count_events (db_of (handle)), >=, 1);
  g_assert_cmpint (count_handoff_rows_for_request (db_of (handle), request_id,
          "delivered"), ==, 1);

  /* No secret is ever surfaced: the outcome carries only durable identifiers,
   * never a credential secret of the fixed base64 length. */
  g_assert_nonnull (outcome.successor_credential_id);
  g_assert_cmpuint (strlen (outcome.successor_credential_id), !=,
      WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);

  /* The front door derived the escrow_id deterministically from request_id and
   * committed the real (non-zero) escrow binding at server-commit. */
  WylServiceCredentialOperationRecord loaded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture.storage, &fixture.anchor, request_id, &loaded), ==,
      WYRELOG_E_OK);
  gchar derived_escrow_id[WYL_ID_STRING_BUF];
  derive_escrow_id_for_test (request_id, derived_escrow_id);
  g_assert_cmpstr (loaded.escrow_id, ==, derived_escrow_id);
  g_assert_true (digest_is_nonzero (loaded.escrow_binding_digest,
          sizeof loaded.escrow_binding_digest));
  assert_escrow_round_trips (loaded.escrow_id);

  wyl_service_credential_operation_record_clear (&loaded);
  wyl_service_credential_operation_record_clear (&outcome);
  wyl_service_credential_operation_coordinator_request_clear (&request);
}

/* Retry with an independently built request sharing the same request_id must
 * replay to a byte-identical record, mint no second credential, deliver once,
 * and never unseal a second secret. */
static void
test_frontdoor_retry_is_replay (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 now = g_get_real_time ();
  WylServiceCredentialOperationCoordinatorRequest first =
      issue_request_new (request_id, "svc:handoff:executor", now);

  HandoffPublication publication = {.store = store_of (handle) };
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = request_id,
    .publication = &handoff_test_vtable,
    .publication_data = &publication,
  };
  WylServiceCredentialOperationRecord outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &first, &runtime, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpint (count_credentials (db_of (handle)), ==, 1);

  guint plan_before = publication.plan_calls;
  guint stage_before = publication.stage_calls;
  guint inspect_before = publication.inspect_calls;
  guint commit_before = publication.commit_calls;

  /* A hard-failing unseal gate proves the replay recovers no second secret. */
  HandoffUnsealGate gate = {.rc = WYRELOG_E_IO };
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store_of (handle),
      handoff_unseal_gate, &gate);

  WylServiceCredentialOperationCoordinatorRequest second =
      issue_request_new (request_id, "svc:handoff:executor", now);
  WylServiceCredentialOperationRecord replay =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &second, &runtime, &replay), ==,
      WYRELOG_E_OK);
  wyl_policy_store_service_handoff_set_unseal_gate_for_test (store_of (handle),
      NULL, NULL);

  g_assert_cmpint (replay.state, ==, WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpstr (replay.request_id, ==, outcome.request_id);
  g_assert_cmpstr (replay.successor_credential_id, ==,
      outcome.successor_credential_id);
  g_assert_cmpuint (replay.successor_generation, ==,
      outcome.successor_generation);
  g_assert_cmpstr (replay.reservation_id, ==, outcome.reservation_id);
  g_assert_cmpstr (replay.stage_identity, ==, outcome.stage_identity);
  g_assert_cmpstr (replay.escrow_id, ==, outcome.escrow_id);
  g_assert_cmpint (replay.updated_at_us, ==, outcome.updated_at_us);
  g_assert_cmpint (count_credentials (db_of (handle)), ==, 1);
  g_assert_cmpuint (publication.plan_calls, ==, plan_before);
  g_assert_cmpuint (publication.stage_calls, ==, stage_before);
  g_assert_cmpuint (publication.inspect_calls, ==, inspect_before);
  g_assert_cmpuint (publication.commit_calls, ==, commit_before);
  g_assert_cmpuint (gate.calls, ==, 0);
  g_assert_cmpint (count_handoff_rows_for_request (db_of (handle), request_id,
          "delivered"), ==, 1);

  wyl_service_credential_operation_record_clear (&replay);
  wyl_service_credential_operation_record_clear (&outcome);
  wyl_service_credential_operation_coordinator_request_clear (&second);
  wyl_service_credential_operation_coordinator_request_clear (&first);
}

/* Begin-layer proof: two independently built requests sharing a request_id
 * derive a byte-identical escrow; the durable begin replays the identical
 * identity and fails closed on any immutable-field change, so the deterministic
 * escrow is an identity token that cannot hijack a foreign operation. */
static void
test_begin_layer_determinism_and_no_hijack (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 now = g_get_real_time ();

  gchar escrow_a[WYL_ID_STRING_BUF];
  gchar escrow_b[WYL_ID_STRING_BUF];
  derive_escrow_id_for_test (request_id, escrow_a);
  derive_escrow_id_for_test (request_id, escrow_b);
  g_assert_cmpstr (escrow_a, ==, escrow_b);
  assert_escrow_round_trips (escrow_a);

  WylServiceCredentialOperationCoordinatorRequest first =
      issue_request_new (request_id, "svc:handoff:executor", now);
  first.escrow_id = g_strdup (escrow_a);

  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = TRUE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&fixture.storage, &fixture.anchor, &first, now, &replayed, &record), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  wyl_service_credential_operation_record_clear (&record);

  /* A second, independently allocated request with identical immutable fields
   * replays the same durable record, not a fresh begin. */
  WylServiceCredentialOperationCoordinatorRequest replay_request =
      issue_request_new (request_id, "svc:handoff:executor", now);
  replay_request.escrow_id = g_strdup (escrow_b);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&fixture.storage, &fixture.anchor, &replay_request, now, &replayed,
          &record), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpstr (record.subject_id, ==, "svc:handoff:executor");
  wyl_service_credential_operation_record_clear (&record);

  /* Same request_id and identical (deterministic) escrow, but a differing
   * immutable subject, is rejected as a distinct identity and leaves the
   * original durable record untouched. */
  WylServiceCredentialOperationCoordinatorRequest hijack =
      issue_request_new (request_id, "svc:handoff:intruder", now);
  hijack.escrow_id = g_strdup (escrow_a);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&fixture.storage, &fixture.anchor, &hijack, now, &replayed, &record), ==,
      WYRELOG_E_POLICY);
  wyl_service_credential_operation_record_clear (&record);

  WylServiceCredentialOperationRecord surviving =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture.storage, &fixture.anchor, request_id, &surviving), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (surviving.subject_id, ==, "svc:handoff:executor");
  wyl_service_credential_operation_record_clear (&surviving);

  wyl_service_credential_operation_coordinator_request_clear (&hijack);
  wyl_service_credential_operation_coordinator_request_clear (&replay_request);
  wyl_service_credential_operation_coordinator_request_clear (&first);
}

/* Malformed requests fail closed with INVALID before any storage or delivery
 * side effect. */
static void
test_frontdoor_malformed_is_invalid (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (handle, "admin", session);

  HandoffPublication publication = {.store = store_of (handle) };
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 now = g_get_real_time ();
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = request_id,
    .publication = &handoff_test_vtable,
    .publication_data = &publication,
  };
  WylServiceCredentialOperationRecord outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;

  /* ROTATE intent missing the required old_credential_id. */
  WylServiceCredentialOperationCoordinatorRequest rotate =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  rotate.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  rotate.request_id = g_strdup (request_id);
  rotate.subject_id = NULL;
  rotate.destination = g_strdup ("credentials.json");
  rotate.parent_identity = g_strdup ("test-parent-identity");
  rotate.actor_subject_id = g_strdup ("admin");
  rotate.expected_generation = 1;
  rotate.expires_at_us = now + G_TIME_SPAN_HOUR;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &rotate, &runtime, &outcome), ==,
      WYRELOG_E_INVALID);

  /* ISSUE intent with a traversal destination. */
  gchar bad_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (bad_request_id);
  WylServiceCredentialOperationCoordinatorRequest bad_destination =
      issue_request_new (bad_request_id, "svc:handoff:executor", now);
  g_free (bad_destination.destination);
  bad_destination.destination = g_strdup ("../escape.json");
  runtime.decision_request_id = bad_request_id;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &bad_destination, &runtime,
          &outcome), ==, WYRELOG_E_INVALID);

  g_assert_cmpint (count_credentials (db_of (handle)), ==, 0);
  g_assert_cmpuint (publication.plan_calls, ==, 0);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture.storage, &fixture.anchor, request_id, &outcome), ==,
      WYRELOG_E_NOT_FOUND);

  wyl_service_credential_operation_coordinator_request_clear (&bad_destination);
  wyl_service_credential_operation_coordinator_request_clear (&rotate);
}

/* A request_id with a durable retirement receipt fails closed with POLICY and
 * creates no operation record. */
static void
test_frontdoor_retired_is_policy (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  g_autofree gchar *sql =
      g_strdup_printf
      ("INSERT INTO service_credential_handoff_retirement_receipts("
      "original_request_id,terminal_kind,raw_journal_snapshot_digest,"
      "delivery_disposition_id,delivery_audit_id,delivery_proof_digest,"
      "revoke_remediation_request_id,revoke_audit_id,revoke_event_id,"
      "resume_remediation_request_id,resume_audit_id,"
      "remediation_source_snapshot_digest,remediation_request_fingerprint,"
      "retention_basis_at_us,retired_at_us) VALUES("
      "'%s','file_published',randomblob(32),"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073991',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073992',randomblob(32),"
      "NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,2592000000001);", request_id);
  gchar *message = NULL;
  g_assert_cmpint (sqlite3_exec (db_of (handle), sql, NULL, NULL, &message), ==,
      SQLITE_OK);
  sqlite3_free (message);

  HandoffPublication publication = {.store = store_of (handle) };
  gint64 now = g_get_real_time ();
  WylServiceCredentialOperationCoordinatorRequest request =
      issue_request_new (request_id, "svc:handoff:executor", now);
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = request_id,
    .publication = &handoff_test_vtable,
    .publication_data = &publication,
  };
  WylServiceCredentialOperationRecord outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;

  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &request, &runtime, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (publication.plan_calls, ==, 0);
  g_assert_cmpint (count_credentials (db_of (handle)), ==, 0);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture.storage, &fixture.anchor, request_id, &outcome), ==,
      WYRELOG_E_NOT_FOUND);

  wyl_service_credential_operation_coordinator_request_clear (&request);
}

/* A foreign but valid human session cannot drive an existing operation bound to
 * a different actor: execution fails closed with POLICY and changes nothing. */
static void
test_frontdoor_actor_mismatch_is_policy (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:handoff:executor");
  g_autoptr (WylSession) admin_session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (handle, "admin", admin_session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  gint64 now = g_get_real_time ();
  WylServiceCredentialOperationCoordinatorRequest request =
      issue_request_new (request_id, "svc:handoff:executor", now);
  HandoffPublication publication = {.store = store_of (handle) };
  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = admin_session,
    .authenticated_actor_subject_id = "admin",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = request_id,
    .publication = &handoff_test_vtable,
    .publication_data = &publication,
  };
  WylServiceCredentialOperationRecord outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &request, &runtime, &outcome), ==,
      WYRELOG_E_OK);
  gint64 credentials_after_issue = count_credentials (db_of (handle));

  /* A different active human session (mallory) submits the same request_id. */
  g_autoptr (WylSession) intruder_session =
      handoff_human_session_new ("mallory", "tenant-a");
  WylServiceCredentialOperationCoordinatorRequest replay_request =
      issue_request_new (request_id, "svc:handoff:executor", now);
  WylServiceCredentialOperationHandoffExecuteRuntime intruder_runtime = {
    .session = intruder_session,
    .authenticated_actor_subject_id = "mallory",
    .guard_timestamp = now,
    .guard_loc_class = "trusted",
    .guard_risk = 0,
    .decision_request_id = request_id,
    .publication = &handoff_test_vtable,
    .publication_data = &publication,
  };
  WylServiceCredentialOperationRecord intruder_outcome =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_handoff (handle,
          &fixture.storage, &fixture.anchor, &replay_request, &intruder_runtime,
          &intruder_outcome), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (count_credentials (db_of (handle)), ==,
      credentials_after_issue);

  wyl_service_credential_operation_record_clear (&intruder_outcome);
  wyl_service_credential_operation_record_clear (&outcome);
  wyl_service_credential_operation_coordinator_request_clear (&replay_request);
  wyl_service_credential_operation_coordinator_request_clear (&request);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-credential-operation-handoff/issue-happy-path",
      test_frontdoor_issue_happy_path);
  g_test_add_func ("/service-credential-operation-handoff/retry-replay",
      test_frontdoor_retry_is_replay);
  g_test_add_func
      ("/service-credential-operation-handoff/begin-determinism-no-hijack",
      test_begin_layer_determinism_and_no_hijack);
  g_test_add_func ("/service-credential-operation-handoff/malformed-invalid",
      test_frontdoor_malformed_is_invalid);
  g_test_add_func ("/service-credential-operation-handoff/retired-policy",
      test_frontdoor_retired_is_policy);
  g_test_add_func
      ("/service-credential-operation-handoff/actor-mismatch-policy",
      test_frontdoor_actor_mismatch_is_policy);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <sqlite3.h>
#include <string.h>

#include "daemon/service-credential-handoff-private.h"
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
  gchar *publication_root;
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
count_delivered (sqlite3 *db, const gchar *request_id)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM service_credential_handoff_dispositions"
          " WHERE original_request_id=? AND reason='delivered';", -1, &stmt,
          NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, request_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
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
  if (fixture->publication_root != NULL)
    (void) g_rmdir (fixture->publication_root);
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
  g_free (fixture->publication_root);
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
  memset (fixture, 0, sizeof *fixture);
  fixture->dir = g_dir_make_tmp ("wyl-daemon-handoff-XXXXXX", NULL);
  g_assert_nonnull (fixture->dir);
  fixture->db_path = g_build_filename (fixture->dir, "policy.db", NULL);
  fixture->key_path = g_build_filename (fixture->dir, "policy.key", NULL);
  fixture->audit_path = g_build_filename (fixture->dir, "audit.db", NULL);
  fixture->operation_root = service_credential_operation_root_for_test
      (fixture->dir, "daemon-handoff-operations");
  fixture->publication_root = g_build_filename (fixture->dir, "publication",
      NULL);
  g_assert_cmpint (g_mkdir_with_parents (fixture->publication_root, 0700), ==,
      0);
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

/* Mock owner publication backend; the non-failure subset drives a fresh ISSUE
 * request from SERVER_COMMITTED all the way to a delivered TERMINAL. */
typedef struct
{
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

/* The daemon module derives the request parent_identity through this accessor;
 * the mock echoes a fixed value that the mock plan copies verbatim into the
 * receipt. */
static wyrelog_error_t
handoff_test_root_identity (gpointer data, gchar **out_identity)
{
  (void) data;
  *out_identity = g_strdup ("test-parent-identity");
  return WYRELOG_E_OK;
}

static const WyctlPublicationBackendVTable handoff_test_vtable = {
  .plan = handoff_test_plan,
  .stage_exact = handoff_test_stage,
  .receipt_target_acquire = handoff_test_target_acquire,
  .receipt_target_inspect = handoff_test_target_inspect,
  .receipt_target_commit = handoff_test_target_commit,
  .receipt_target_release = handoff_test_target_release,
  .root_identity = handoff_test_root_identity,
};

static WylDaemonServiceCredentialHandoffContext
context_for (Fixture *fixture, WylSession *session, const gchar *request_id,
    HandoffPublication *publication)
{
  return (WylDaemonServiceCredentialHandoffContext) {
  .handle = fixture->handle,.session =
        session,.authenticated_actor_subject_id = "admin",.guard_timestamp =
        g_get_real_time (),.guard_loc_class = "trusted",.guard_risk =
        0,.decision_request_id = request_id,.operation_root =
        fixture->operation_root,.credential_publication_root =
        fixture->publication_root,.publication_override =
        &handoff_test_vtable,.publication_override_data = publication,};
}

static WylDaemonServiceCredentialHandoffInputs
issue_inputs_for (const gchar *request_id)
{
  return (WylDaemonServiceCredentialHandoffInputs) {
  .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,.request_id =
        request_id,.subject_id = "svc:handoff:executor",.tenant_id =
        "tenant-a",.destination = "credentials.json",.expires_at_us =
        g_get_real_time () + G_TIME_SPAN_HOUR,};
}

/* A configured issue emits a non-secret JSON receipt, mints one credential and
 * records exactly one delivery. */
static void
test_daemon_handoff_issue (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (fixture.handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  HandoffPublication publication = { 0 };
  WylDaemonServiceCredentialHandoffContext ctx =
      context_for (&fixture, session, request_id, &publication);
  WylDaemonServiceCredentialHandoffInputs inputs =
      issue_inputs_for (request_id);

  g_autofree gchar *json = NULL;
  g_assert_cmpint (wyl_daemon_service_credential_handoff (&ctx, &inputs, &json),
      ==, WYRELOG_E_OK);
  g_assert_nonnull (json);
  g_assert_nonnull (strstr (json, "\"state\":\"terminal\""));
  g_assert_nonnull (strstr (json, "\"delivered\":true"));
  g_assert_nonnull (strstr (json, "\"request_id\":"));
  g_assert_nonnull (strstr (json, "\"credential_id\":"));
  g_assert_nonnull (strstr (json, "\"destination\":\"credentials.json\""));
  /* The receipt is non-secret: it carries no secret field and no base64 secret
   * of the fixed length. */
  g_assert_null (strstr (json, "secret"));
  g_assert_cmpint (count_credentials (db_of (fixture.handle)), ==, 1);
  g_assert_cmpint (count_delivered (db_of (fixture.handle), request_id), ==, 1);
  g_assert_cmpuint (publication.commit_calls, ==, 1);
}

/* Re-submitting the same request_id replays to a byte-identical receipt with no
 * second credential and a single delivery. */
static void
test_daemon_handoff_retry_is_replay (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (fixture.handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  HandoffPublication publication = { 0 };
  WylDaemonServiceCredentialHandoffContext ctx =
      context_for (&fixture, session, request_id, &publication);
  WylDaemonServiceCredentialHandoffInputs inputs =
      issue_inputs_for (request_id);

  g_autofree gchar *first = NULL;
  g_assert_cmpint (wyl_daemon_service_credential_handoff (&ctx, &inputs,
          &first), ==, WYRELOG_E_OK);
  guint commit_after_first = publication.commit_calls;

  g_autofree gchar *second = NULL;
  g_assert_cmpint (wyl_daemon_service_credential_handoff (&ctx, &inputs,
          &second), ==, WYRELOG_E_OK);
  g_assert_cmpstr (second, ==, first);
  g_assert_cmpint (count_credentials (db_of (fixture.handle)), ==, 1);
  g_assert_cmpint (count_delivered (db_of (fixture.handle), request_id), ==, 1);
  g_assert_cmpuint (publication.commit_calls, ==, commit_after_first);
}

/* A malformed request fails closed before any state or delivery. */
static void
test_daemon_handoff_malformed (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (fixture.handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  HandoffPublication publication = { 0 };
  WylDaemonServiceCredentialHandoffContext ctx =
      context_for (&fixture, session, request_id, &publication);
  WylDaemonServiceCredentialHandoffInputs inputs =
      issue_inputs_for (request_id);
  inputs.destination = "../escape.json";

  g_autofree gchar *json = NULL;
  g_assert_cmpint (wyl_daemon_service_credential_handoff (&ctx, &inputs, &json),
      ==, WYRELOG_E_INVALID);
  g_assert_null (json);
  g_assert_cmpint (count_credentials (db_of (fixture.handle)), ==, 0);
  g_assert_cmpuint (publication.plan_calls, ==, 0);
}

/* An unconfigured handoff surface reports unavailable and touches no state. */
static void
test_daemon_handoff_unconfigured (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (fixture.handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  HandoffPublication publication = { 0 };
  WylDaemonServiceCredentialHandoffInputs inputs =
      issue_inputs_for (request_id);

  WylDaemonServiceCredentialHandoffContext no_operation =
      context_for (&fixture, session, request_id, &publication);
  no_operation.operation_root = NULL;
  g_autofree gchar *json_a = NULL;
  g_assert_cmpint (wyl_daemon_service_credential_handoff (&no_operation,
          &inputs, &json_a), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (json_a);

  WylDaemonServiceCredentialHandoffContext no_publication =
      context_for (&fixture, session, request_id, &publication);
  no_publication.credential_publication_root = "";
  g_autofree gchar *json_b = NULL;
  g_assert_cmpint (wyl_daemon_service_credential_handoff (&no_publication,
          &inputs, &json_b), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (json_b);

  g_assert_cmpint (count_credentials (db_of (fixture.handle)), ==, 0);
  g_assert_cmpuint (publication.plan_calls, ==, 0);
}

/* Drives the module against the REAL POSIX publication backend with no override:
 * the module opens the backend on the fixture's 0700 publication_root and
 * derives parent_identity through the real accessor. A green delivered receipt
 * proves the derived parent_identity equals what plan() stamps -- any divergence
 * would trip the executor's plan/record parent_identity assertion and fail
 * closed with POLICY. This is the sole regression guard for the crux; the mock
 * path cannot catch an accessor != plan divergence. (Windows accessor==plan
 * equality rests on code review; there is no real-Windows daemon test here.) */
static void
test_daemon_handoff_issue_real_publication (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  prepare_authority (fixture.handle, "svc:handoff:executor");
  g_autoptr (WylSession) session = handoff_human_session_new ("admin",
      "tenant-a");
  authorize_session (fixture.handle, "admin", session);

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylDaemonServiceCredentialHandoffContext ctx =
      context_for (&fixture, session, request_id, NULL);
  ctx.publication_override = NULL;
  ctx.publication_override_data = NULL;
  WylDaemonServiceCredentialHandoffInputs inputs =
      issue_inputs_for (request_id);

  g_autofree gchar *json = NULL;
  g_assert_cmpint (wyl_daemon_service_credential_handoff (&ctx, &inputs, &json),
      ==, WYRELOG_E_OK);
  g_assert_nonnull (json);
  g_assert_nonnull (strstr (json, "\"state\":\"terminal\""));
  g_assert_nonnull (strstr (json, "\"delivered\":true"));
  g_assert_cmpint (count_credentials (db_of (fixture.handle)), ==, 1);
  g_assert_cmpint (count_delivered (db_of (fixture.handle), request_id), ==, 1);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/daemon-service-credential-handoff/issue",
      test_daemon_handoff_issue);
  g_test_add_func ("/daemon-service-credential-handoff/retry-replay",
      test_daemon_handoff_retry_is_replay);
  g_test_add_func ("/daemon-service-credential-handoff/malformed",
      test_daemon_handoff_malformed);
  g_test_add_func ("/daemon-service-credential-handoff/unconfigured",
      test_daemon_handoff_unconfigured);
  g_test_add_func ("/daemon-service-credential-handoff/issue-real-publication",
      test_daemon_handoff_issue_real_publication);
  return g_test_run ();
}

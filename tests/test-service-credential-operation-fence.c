/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <sqlite3.h>
#include <string.h>

#include "auth/service-credential-domain-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-fence-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-journal-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-recovery-private.h"
#include "wyrelog/auth/service-credential-operation-storage-private.h"
#ifdef G_OS_WIN32
#include "wyrelog/auth/service-credential-operation-storage-windows-private.h"
#endif
#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyl-request-id-private.h"

typedef struct
{
  WylServiceAuthWriteLease *lease;
  WylServiceAuthorityTransaction *txn;
  WylServiceAuthorityCommitEvidence *evidence;
} Txn;

typedef struct
{
  WylHandle *handle;
  Txn txn;
  gboolean ready;
  gboolean release;
  GMutex mutex;
  GCond cond;
  wyrelog_error_t rc;
  WylServiceCredentialFenceResult result;
} OvertakeContender;

typedef struct
{
  WylHandle *handle;
  gchar *dir;
  gchar *db_path;
  gchar *audit_path;
  gchar *key_path;
  gchar *key_spec;
} ProvisionedHandle;

static WylHandle *
open_handle (const gchar *path)
{
  WylHandleOpenOptions options = {.policy_store_path = path };
  WylHandle *handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  return handle;
}

static WylHandle *
open_provisioned_handle (void)
{
  ProvisionedHandle fixture = { 0 };
  fixture.dir = g_dir_make_tmp ("wyl-fence-issue-XXXXXX", NULL);
  g_assert_nonnull (fixture.dir);
  fixture.db_path = g_build_filename (fixture.dir, "policy.db", NULL);
  fixture.audit_path = g_build_filename (fixture.dir, "audit.db", NULL);
  fixture.key_path = g_build_filename (fixture.dir, "policy.key", NULL);
  guint8 key[32];
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) (i + 1);
  g_assert_true (g_file_set_contents (fixture.key_path,
          (const gchar *) key, sizeof key, NULL));
  fixture.key_spec = g_strdup_printf ("file:%s", fixture.key_path);
  WylHandleOpenOptions options = {
    .policy_store_path = fixture.db_path,
    .policy_keyprovider_path = fixture.key_spec,
    .audit_store_path = fixture.audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &fixture.handle),
      ==, WYRELOG_E_OK);
  return g_steal_pointer (&fixture.handle);
}

/* Mirrors tests/test-service-exchange-intention-store.c's fixture: prepares
 * commit evidence unconditionally (wyl_policy_store_reconcile_service_credential_operation_fence
 * requires it before it can acquire its own write intent). */
static Txn
begin_txn (WylHandle *handle)
{
  Txn t = { 0 };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &t.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, t.lease, &t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (t.txn, store, &t.evidence), ==, WYRELOG_E_OK);
  return t;
}

static void
finish_txn (Txn *t, gboolean commit)
{
  g_assert_cmpint (commit ?
      wyl_policy_store_service_authority_transaction_commit (t->txn) :
      wyl_policy_store_service_authority_transaction_rollback (t->txn), ==,
      WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (t->txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t->evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t->lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t->lease);
  memset (t, 0, sizeof *t);
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

static void
exec_sql (sqlite3 *db, const gchar *sql)
{
  gchar *error = NULL;
  g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, &error), ==, SQLITE_OK);
  g_assert_null (error);
}

static void
open_recovery_storage (WylServiceCredentialOperationStorage *storage,
    WylServiceCredentialOperationRootAnchor *anchor, gchar **out_root)
{
  *storage = (WylServiceCredentialOperationStorage)
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  *anchor = (WylServiceCredentialOperationRootAnchor)
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
#ifdef G_OS_WIN32
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_autofree gchar *name = g_strdup_printf ("wyrelog-recovery-%lu-%u",
      (gulong) GetCurrentProcessId (), g_random_int ());
  *out_root = g_build_filename (local, name, NULL);
#else
  *out_root = g_dir_make_tmp ("wyrelog-recovery-XXXXXX", NULL);
#endif
  g_assert_nonnull (*out_root);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (*out_root,
          storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (storage, anchor), ==, WYRELOG_E_OK);
}

static gpointer
overtake_contender_thread (gpointer data)
{
  OvertakeContender *contender = data;
  contender->txn = begin_txn (contender->handle);
  g_mutex_lock (&contender->mutex);
  contender->ready = TRUE;
  g_cond_signal (&contender->cond);
  while (!contender->release)
    g_cond_wait (&contender->cond, &contender->mutex);
  g_mutex_unlock (&contender->mutex);

  contender->rc = wyl_policy_store_reconcile_service_credential_operation_fence
      (contender->txn.txn, wyl_handle_get_policy_store (contender->handle),
      NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "req-overtake", NULL,
      NULL, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &contender->result);
  finish_txn (&contender->txn, FALSE);
  return NULL;
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
  g_assert_cmpint (wyl_policy_store_create_tenant
      (wyl_handle_get_policy_store (handle), "tenant-a", &created), ==,
      WYRELOG_E_OK);
  g_assert_true (created);
  g_assert_cmpint (wyl_policy_store_create_tenant
      (wyl_handle_get_policy_store (handle), "tenant-b", &created), ==,
      WYRELOG_E_OK);
}

static void
assert_hex_fingerprint (WylServiceCredentialFenceOperation operation,
    const gchar *field_a, const gchar *field_b, const gchar *expected_hex)
{
  guint8 out[crypto_generichash_BYTES];
  g_assert_cmpint
      (wyl_policy_store_service_credential_operation_fence_fingerprint
      (operation, field_a, strlen (field_a), field_b,
          field_b != NULL ? strlen (field_b) : 0, out), ==, WYRELOG_E_OK);
  gchar hex[crypto_generichash_BYTES * 2 + 1];
  sodium_bin2hex (hex, sizeof hex, out, sizeof out);
  g_assert_cmpstr (hex, ==, expected_hex);
}

static void
test_golden_vectors_exact (void)
{
  /* Issue #384 frozen v1 golden vectors, reproduced byte-for-byte by the
   * production helper. */
  assert_hex_fingerprint (WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
      "svc:jobs:worker", "tenant-a",
      "837cd354ecae23554bba18f88977ace65c573d1638274222a263f08a90acb3d4");
  assert_hex_fingerprint (WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", NULL,
      "092063eaaa86526c6b25a526f9d69476b94f95d26f0adfc9bca119048696eeb2");

  /* Near-collision framing pair: unframed concatenated field bytes are
   * identical ("svc:jobs:worker" + "tenant-a" == "svc:jobs:worke" +
   * "rtenant-a"), but the u32be length framing must still separate them. */
  assert_hex_fingerprint (WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
      "svc:jobs:worke", "rtenant-a",
      "1b0f6b3aa5facf3f9467f1f32e304867cd45f976d2f77b0f127d4e8fcc0478ee");
}

static void
test_invalid_field_shape (void)
{
  guint8 out[crypto_generichash_BYTES];
  /* issue requires both fields. */
  g_assert_cmpint
      (wyl_policy_store_service_credential_operation_fence_fingerprint
      (WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "svc:a", 5, NULL, 0, out), ==,
      WYRELOG_E_INVALID);
  /* rotate forbids a second field. */
  g_assert_cmpint
      (wyl_policy_store_service_credential_operation_fence_fingerprint
      (WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "wlc_x", 5, "extra", 5, out),
      ==, WYRELOG_E_INVALID);
  /* unknown operation tag. */
  g_assert_cmpint
      (wyl_policy_store_service_credential_operation_fence_fingerprint
      (0, "wlc_x", 5, NULL, 0, out), ==, WYRELOG_E_INVALID);
}

static void
assert_hex_ne (WylServiceCredentialFenceOperation operation,
    const gchar *field_a, const gchar *field_b, const gchar *other_hex)
{
  guint8 out[crypto_generichash_BYTES];
  g_assert_cmpint
      (wyl_policy_store_service_credential_operation_fence_fingerprint
      (operation, field_a, strlen (field_a), field_b,
          field_b != NULL ? strlen (field_b) : 0, out), ==, WYRELOG_E_OK);
  gchar hex[crypto_generichash_BYTES * 2 + 1];
  sodium_bin2hex (hex, sizeof hex, out, sizeof out);
  g_assert_cmpstr (hex, !=, other_hex);
}

static void
test_fingerprint_differentiates_inputs (void)
{
  guint8 issue_out[crypto_generichash_BYTES];
  guint8 rotate_out[crypto_generichash_BYTES];
  g_assert_cmpint
      (wyl_policy_store_service_credential_operation_fence_fingerprint
      (WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "same-bytes",
          strlen ("same-bytes"), "", 0, issue_out), ==, WYRELOG_E_OK);
  gchar issue_hex[crypto_generichash_BYTES * 2 + 1];
  sodium_bin2hex (issue_hex, sizeof issue_hex, issue_out, sizeof issue_out);

  /* Same field_a bytes under the other operation tag must diverge: the tag
   * is part of the hashed transcript, not just a routing decision. */
  g_assert_cmpint
      (wyl_policy_store_service_credential_operation_fence_fingerprint
      (WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "same-bytes",
          strlen ("same-bytes"), NULL, 0, rotate_out), ==, WYRELOG_E_OK);
  gchar rotate_hex[crypto_generichash_BYTES * 2 + 1];
  sodium_bin2hex (rotate_hex, sizeof rotate_hex, rotate_out, sizeof rotate_out);
  g_assert_cmpstr (issue_hex, !=, rotate_hex);

  /* A single differing byte anywhere in a field must change the digest. */
  assert_hex_ne (WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "same-bytex", "",
      issue_hex);
  assert_hex_ne (WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "same-bytex", NULL,
      rotate_hex);
}

static void
test_fresh_request_creates_fence (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_operation_fences"
          " WHERE request_id='req-committed-issue';"), ==, 0);
  Txn t = begin_txn (handle);
  WylServiceCredentialFenceResult result = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "req-fresh-1",
          "svc:fence:worker", "tenant-a", NULL, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
  g_assert_cmpstr (result.successor_credential_id, ==, "");
  g_assert_cmpuint (result.successor_generation, ==, 0);
  finish_txn (&t, TRUE);

  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_operation_fences"
          " WHERE request_id='req-fresh-1' AND operation='credential_issue'"
          " AND terminal_state='not_committed';"), ==, 1);
}

static void
test_fence_replay_is_idempotent (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  {
    Txn t = begin_txn (handle);
    WylServiceCredentialFenceResult result = { 0 };
    g_assert_cmpint
        (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
            store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "req-replay",
            "svc:fence:worker", "tenant-a", NULL, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==,
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
    finish_txn (&t, TRUE);
  }
  {
    Txn t = begin_txn (handle);
    WylServiceCredentialFenceResult result = { 0 };
    g_assert_cmpint
        (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
            store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "req-replay",
            "svc:fence:worker", "tenant-a", NULL, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==,
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
    finish_txn (&t, FALSE);
  }
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_operation_fences"
          " WHERE request_id='req-replay';"), ==, 1);
}

static void
test_fence_conflict_on_target_mismatch (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  {
    Txn t = begin_txn (handle);
    WylServiceCredentialFenceResult result = { 0 };
    g_assert_cmpint
        (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
            store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
            "req-conflict", "svc:fence:worker", "tenant-a", NULL, &result),
        ==, WYRELOG_E_OK);
    finish_txn (&t, TRUE);
  }
  {
    Txn t = begin_txn (handle);
    WylServiceCredentialFenceResult result = { 0 };
    g_assert_cmpint
        (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
            store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
            "req-conflict", "svc:fence:worker", "tenant-b", NULL, &result),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==,
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT);
    g_assert_cmpstr (result.successor_credential_id, ==, "");
    g_assert_cmpuint (result.successor_generation, ==, 0);
    finish_txn (&t, FALSE);
  }
  {
    Txn t = begin_txn (handle);
    WylServiceCredentialFenceResult result = { 0 };
    g_assert_cmpint
        (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
            store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
            "req-conflict", NULL, NULL, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
            &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==,
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT);
    finish_txn (&t, FALSE);
  }
}

static void
test_committed_issue_returns_successor (void)
{
  g_autoptr (WylHandle) handle = open_provisioned_handle ();
  prepare_authority (handle, "svc:fence:issue");
  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:fence:issue",
          "tenant-a", "admin", "req-committed-issue", 0, &issued), ==,
      WYRELOG_E_OK);
  g_autofree gchar *credential_id = g_strdup (issued.credential.credential_id);
  guint64 generation = issued.credential.generation;
  wyl_service_credential_issue_result_clear (&issued);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  Txn t = begin_txn (handle);
  WylServiceCredentialFenceResult result = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          "req-committed-issue", "svc:fence:issue", "tenant-a", NULL,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED);
  g_assert_cmpstr (result.successor_credential_id, ==, credential_id);
  g_assert_cmpuint (result.successor_generation, ==, generation);
  finish_txn (&t, FALSE);

  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_operation_fences"
          " WHERE request_id='req-committed-issue';"), ==, 1);
}

static void
test_committed_issue_conflict_on_mismatch (void)
{
  g_autoptr (WylHandle) handle = open_provisioned_handle ();
  prepare_authority (handle, "svc:fence:issue2");
  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:fence:issue2",
          "tenant-a", "admin", "req-committed-mismatch", 0, &issued), ==,
      WYRELOG_E_OK);
  wyl_service_credential_issue_result_clear (&issued);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  Txn t = begin_txn (handle);
  WylServiceCredentialFenceResult result = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          "req-committed-mismatch", "svc:fence:issue2", "tenant-b", NULL,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT);
  finish_txn (&t, FALSE);
}

static void
test_committed_rotate_returns_new_successor (void)
{
  g_autoptr (WylHandle) handle = open_provisioned_handle ();
  prepare_authority (handle, "svc:fence:rotate");
  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:fence:rotate",
          "tenant-a", "admin", "req-rotate-issue", 0, &issued), ==,
      WYRELOG_E_OK);
  g_autofree gchar *old_id = g_strdup (issued.credential.credential_id);
  wyl_service_credential_issue_result_clear (&issued);

  wyl_service_credential_issue_result_t rotated = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate (handle, old_id, "admin",
          "req-rotate-commit", 0, &rotated), ==, WYRELOG_E_OK);
  g_autofree gchar *new_id = g_strdup (rotated.credential.credential_id);
  guint64 new_generation = rotated.credential.generation;
  g_assert_cmpstr (new_id, !=, old_id);
  wyl_service_credential_issue_result_clear (&rotated);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  Txn t = begin_txn (handle);
  WylServiceCredentialFenceResult result = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
          "req-rotate-commit", NULL, NULL, old_id, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED);
  g_assert_cmpstr (result.successor_credential_id, ==, new_id);
  g_assert_cmpuint (result.successor_generation, ==, new_generation);
  finish_txn (&t, FALSE);
}

static void
test_precheck_with_committed (void)
{
  const gchar *old_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  g_autoptr (WylHandle) handle = open_provisioned_handle ();
  prepare_authority (handle, "svc:fence:precheck");
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceCredentialFenceResult result = { 0 };
  gchar journal_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (journal_request_id,
          sizeof journal_request_id), ==, WYRELOG_E_OK);
  gint total_changes = sqlite3_total_changes (db);

  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "req-no-row",
          "svc:fence:precheck", "tenant-a", NULL, &result), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (result.state, ==, 0);
  g_assert_cmpint (sqlite3_total_changes (db), ==, total_changes);

  wyl_service_credential_issue_result_t issued = { 0 };
  g_assert_cmpint (wyl_service_credential_issue (handle, "svc:fence:precheck",
          "tenant-a", "admin", journal_request_id, 0, &issued), ==,
      WYRELOG_E_OK);
  g_autofree gchar *issued_id = g_strdup (issued.credential.credential_id);
  guint64 issued_generation = issued.credential.generation;
  wyl_service_credential_issue_result_clear (&issued);

  total_changes = sqlite3_total_changes (db);
  memset (&result, 0xff, sizeof result);
  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          journal_request_id, "svc:fence:precheck", "tenant-a", NULL,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED);
  g_assert_cmpstr (result.successor_credential_id, ==, issued_id);
  g_assert_cmpuint (result.successor_generation, ==, issued_generation);
  g_assert_cmpint (sqlite3_total_changes (db), ==, total_changes);

  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  request.request_id = journal_request_id;
  request.subject_id = "svc:fence:precheck";
  request.tenant_id = "tenant-a";
  request.destination = "credential";
  request.parent_identity = "parent";
  request.actor_subject_id = "admin";
  request.escrow_id = "01890f47-3c4b-7cc2-b8c4-dc0c0c073991";
  memset (request.escrow_binding_digest, 0x31,
      sizeof request.escrow_binding_digest);
  request.expires_at_us = 1;
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationFenceClassification classification = 0;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&request, journal_request_id, 1, &prepared), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&prepared, WYRELOG_E_OK, &result, &classification), ==, WYRELOG_E_OK);
  g_assert_cmpint (classification, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_COMMIT_REQUIRED);
  wyl_service_credential_operation_record_clear (&prepared);

  WylServiceCredentialOperationStorage storage;
  WylServiceCredentialOperationRootAnchor anchor;
  g_autofree gchar *journal_root = NULL;
  open_recovery_storage (&storage, &anchor, &journal_root);
  WylServiceCredentialOperationRecord begun =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord recovered =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecoveryOutcome recovery = 0;
  gboolean begin_replayed = TRUE;

  gchar pending_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (pending_request_id,
          sizeof pending_request_id), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationCoordinatorRequest pending_request = request;
  pending_request.request_id = pending_request_id;
  pending_request.expires_at_us = 3;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&storage, &anchor, &pending_request, 1, NULL, &begun), ==, WYRELOG_E_OK);
  total_changes = sqlite3_total_changes (db);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, pending_request_id, 2, &recovery,
          &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_PENDING);
  g_assert_cmpint (recovered.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_assert_cmpstr (recovered.actor_subject_id, ==, "admin");
  g_assert_cmpint (sqlite3_total_changes (db), ==, total_changes);
  wyl_service_credential_operation_record_clear (&recovered);
  wyl_service_credential_operation_record_clear (&begun);

  gchar expired_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (expired_request_id,
          sizeof expired_request_id), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationCoordinatorRequest expired_request = request;
  expired_request.request_id = expired_request_id;
  expired_request.expires_at_us = 2;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&storage, &anchor, &expired_request, 1, NULL, &begun), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) begun_bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&begun,
          &begun_bytes), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationRecord preserved =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  recovery = 99;
  total_changes = sqlite3_total_changes (db);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, expired_request_id, 2, &recovery,
          &preserved), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_PENDING);
  g_assert_cmpint (preserved.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_autoptr (GBytes) preserved_after = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&preserved,
          &preserved_after), ==, WYRELOG_E_OK);
  /* Recovery no longer treats the caller's clock as authoritative expiry.
   * The durable PREPARED bytes therefore remain the recovered snapshot. */
  g_assert_true (g_bytes_equal (begun_bytes, preserved_after));
  WylServiceCredentialOperationRecord loaded_expired =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (&storage,
          &anchor, expired_request_id, &loaded_expired), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) loaded_expired_bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode
      (&loaded_expired, &loaded_expired_bytes), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (begun_bytes, loaded_expired_bytes));
  g_assert_cmpint (sqlite3_total_changes (db), ==, total_changes);
  wyl_service_credential_operation_record_clear (&loaded_expired);
  wyl_service_credential_operation_record_clear (&preserved);
  wyl_service_credential_operation_record_clear (&begun);

  gchar terminal_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (terminal_request_id,
          sizeof terminal_request_id), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationCoordinatorRequest terminal_request = request;
  terminal_request.request_id = terminal_request_id;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&storage, &anchor, &terminal_request, 1, NULL, &begun), ==,
      WYRELOG_E_OK);
  Txn terminal_txn = begin_txn (handle);
  memset (&result, 0, sizeof result);
  g_assert_cmpint (wyl_policy_store_reconcile_service_credential_operation_fence
      (terminal_txn.txn, store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          terminal_request_id, request.subject_id, request.tenant_id, NULL,
          &result), ==, WYRELOG_E_OK);
  finish_txn (&terminal_txn, TRUE);
  total_changes = sqlite3_total_changes (db);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, terminal_request_id, 2, &recovery,
          &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_TERMINAL_NO_COMMIT);
  g_assert_cmpint (recovered.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_assert_cmpint (sqlite3_total_changes (db), ==, total_changes);
  wyl_service_credential_operation_record_clear (&recovered);
  wyl_service_credential_operation_record_clear (&begun);

  gchar conflict_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (conflict_request_id,
          sizeof conflict_request_id), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationCoordinatorRequest conflict_request = request;
  conflict_request.request_id = conflict_request_id;
  conflict_request.tenant_id = "tenant-b";
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&storage, &anchor, &conflict_request, 1, NULL, &begun), ==,
      WYRELOG_E_OK);
  Txn conflict_txn = begin_txn (handle);
  memset (&result, 0, sizeof result);
  g_assert_cmpint (wyl_policy_store_reconcile_service_credential_operation_fence
      (conflict_txn.txn, store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          conflict_request_id, request.subject_id, request.tenant_id, NULL,
          &result), ==, WYRELOG_E_OK);
  finish_txn (&conflict_txn, TRUE);
  total_changes = sqlite3_total_changes (db);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, conflict_request_id, 2, &recovery,
          &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_CONFLICT);
  g_assert_cmpint (recovered.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_assert_cmpint (sqlite3_total_changes (db), ==, total_changes);
  wyl_service_credential_operation_record_clear (&recovered);
  wyl_service_credential_operation_record_clear (&begun);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&storage, &anchor, &request, 1, &begin_replayed, &begun), ==,
      WYRELOG_E_OK);
  g_assert_false (begin_replayed);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, journal_request_id, 2, &recovery,
          &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED);
  g_assert_cmpint (recovered.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpstr (recovered.actor_subject_id, ==, "admin");
  g_assert_cmpstr (recovered.successor_credential_id, ==, issued_id);
  g_assert_cmpuint (recovered.successor_generation, ==, issued_generation);
  gint64 recovered_updated_at_us = recovered.updated_at_us;
  wyl_service_credential_operation_record_clear (&recovered);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, journal_request_id, 3, &recovery,
          &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED_REPLAY);
  g_assert_cmpint (recovered.updated_at_us, ==, recovered_updated_at_us);
  wyl_service_credential_operation_record_clear (&recovered);
  wyl_service_credential_operation_record_clear (&begun);

  memset (&result, 0, sizeof result);
  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          journal_request_id, "svc:fence:precheck", "tenant-b", NULL,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT);

  memset (&result, 0, sizeof result);
  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
          journal_request_id, NULL, NULL, old_id, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT);

  gchar rotate_request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (rotate_request_id,
          sizeof rotate_request_id), ==, WYRELOG_E_OK);
  wyl_service_credential_issue_result_t rotated = { 0 };
  g_assert_cmpint (wyl_service_credential_rotate (handle, issued_id, "admin",
          rotate_request_id, 0, &rotated), ==, WYRELOG_E_OK);
  g_autofree gchar *rotated_id = g_strdup (rotated.credential.credential_id);
  guint64 rotated_generation = rotated.credential.generation;
  wyl_service_credential_issue_result_clear (&rotated);
  memset (&result, 0, sizeof result);
  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
          rotate_request_id, NULL, NULL, issued_id, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED);
  g_assert_cmpstr (result.successor_credential_id, ==, rotated_id);
  g_assert_cmpuint (result.successor_generation, ==, rotated_generation);
  /* v3 preserves the immutable pre-rotate expected generation separately
   * from the durable successor tuple. This service returns both as 1. */
  g_assert_cmpuint (rotated_generation, ==, issued_generation);

  WylServiceCredentialOperationCoordinatorRequest rotate_request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  rotate_request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  rotate_request.request_id = rotate_request_id;
  rotate_request.subject_id = "svc:fence:precheck";
  rotate_request.destination = "rotated-credential";
  rotate_request.parent_identity = "parent";
  rotate_request.actor_subject_id = "admin";
  rotate_request.escrow_id = "01890f47-3c4b-7cc2-b8c4-dc0c0c073992";
  memset (rotate_request.escrow_binding_digest, 0x32,
      sizeof rotate_request.escrow_binding_digest);
  rotate_request.old_credential_id = issued_id;
  rotate_request.expected_generation = issued_generation;
  rotate_request.expires_at_us = 1;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (&storage, &anchor, &rotate_request, 1, NULL, &begun), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, rotate_request_id, 2, &recovery,
          &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED);
  g_assert_cmpint (recovered.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpstr (recovered.actor_subject_id, ==, "admin");
  g_assert_cmpstr (recovered.successor_credential_id, ==, rotated_id);
  g_assert_cmpuint (recovered.successor_generation, ==, rotated_generation);
  wyl_service_credential_operation_record_clear (&recovered);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_recover
      (&storage, &anchor, store, NULL, rotate_request_id, 3, &recovery,
          &recovered), ==, WYRELOG_E_OK);
  g_assert_cmpint (recovery, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_RECOVERY_SERVER_COMMITTED_REPLAY);
  g_assert_cmpint (recovered.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  wyl_service_credential_operation_record_clear (&recovered);
  wyl_service_credential_operation_record_clear (&begun);
  Txn t = begin_txn (handle);
  memset (&result, 0, sizeof result);
  g_assert_cmpint (wyl_policy_store_reconcile_service_credential_operation_fence
      (t.txn, store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
          "req-precheck-terminal", NULL, NULL, old_id, &result), ==,
      WYRELOG_E_OK);
  finish_txn (&t, TRUE);
  memset (&result, 0, sizeof result);
  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,
          "req-precheck-terminal", NULL, NULL, old_id, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);

  exec_sql (db,
      "INSERT INTO service_domain_requests(request_id,operation,resource_id,"
      "input_fingerprint,created_at_us) VALUES('req-precheck-missing-event',"
      "'credential_issue','svc:fence:precheck',zeroblob(32),1);");
  memset (&result, 0xff, sizeof result);
  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          "req-precheck-missing-event", "svc:fence:precheck", "tenant-a",
          NULL, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.state, ==, 0);

  exec_sql (db, "PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;");
  exec_sql (db,
      "INSERT INTO service_domain_requests(request_id,operation,resource_id,"
      "input_fingerprint,created_at_us) VALUES('req-precheck-malformed',"
      "'credential_issue','svc:fence:precheck',zeroblob(32),1);");
  exec_sql (db,
      "INSERT INTO service_credential_events(credential_id,subject_id,tenant_id,"
      "event,from_state,to_state,generation,actor_subject_id,request_id,"
      "created_at_us) VALUES('bad','svc:fence:precheck','tenant-a','issued',"
      "NULL,'active',1,'admin','req-precheck-malformed',1);");
  exec_sql (db, "PRAGMA ignore_check_constraints=OFF; PRAGMA foreign_keys=ON;");
  memset (&result, 0xff, sizeof result);
  g_assert_cmpint
      (wyl_policy_store_precheck_service_credential_operation_fence_with_committed
      (store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE,
          "req-precheck-malformed", "svc:fence:precheck", "tenant-a", NULL,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.state, ==, 0);
  wyl_service_credential_operation_storage_clear (&storage);
  g_autofree gchar *issue_child = g_strdup_printf ("op-%s", journal_request_id);
  g_autofree gchar *pending_child =
      g_strdup_printf ("op-%s", pending_request_id);
  g_autofree gchar *expired_child =
      g_strdup_printf ("op-%s", expired_request_id);
  g_autofree gchar *terminal_child =
      g_strdup_printf ("op-%s", terminal_request_id);
  g_autofree gchar *conflict_child =
      g_strdup_printf ("op-%s", conflict_request_id);
  g_autofree gchar *rotate_child = g_strdup_printf ("op-%s", rotate_request_id);
  g_autofree gchar *issue_path = g_build_filename (journal_root, issue_child,
      NULL);
  g_autofree gchar *rotate_path = g_build_filename (journal_root, rotate_child,
      NULL);
  g_autofree gchar *pending_path =
      g_build_filename (journal_root, pending_child,
      NULL);
  g_autofree gchar *terminal_path = g_build_filename (journal_root,
      terminal_child, NULL);
  g_autofree gchar *expired_path = g_build_filename (journal_root,
      expired_child, NULL);
  g_autofree gchar *conflict_path = g_build_filename (journal_root,
      conflict_child, NULL);
  g_remove (issue_path);
  g_remove (rotate_path);
  g_remove (pending_path);
  g_remove (expired_path);
  g_remove (terminal_path);
  g_remove (conflict_path);
  g_rmdir (journal_root);
}

static void
test_fence_survives_restart (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fence-XXXXXX", NULL);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  {
    g_autoptr (WylHandle) handle = open_handle (path);
    Txn t = begin_txn (handle);
    WylServiceCredentialFenceResult result = { 0 };
    g_assert_cmpint
        (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
            wyl_handle_get_policy_store (handle), NULL,
            WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "req-restart", NULL, NULL,
            "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==,
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
    finish_txn (&t, TRUE);
  }
  {
    g_autoptr (WylHandle) handle = open_handle (path);
    Txn t = begin_txn (handle);
    WylServiceCredentialFenceResult result = { 0 };
    g_assert_cmpint
        (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
            wyl_handle_get_policy_store (handle), NULL,
            WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "req-restart", NULL, NULL,
            "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==,
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
    finish_txn (&t, FALSE);
  }
  g_remove (path);
  g_rmdir (dir);
}

/* Deterministic two-connection overtaking proof: a second, independent
 * store connection racing the exact same request identity while the first
 * connection's write intent is still held must observe retryable
 * uncertainty (WYRELOG_E_BUSY), never a second fence row and never a
 * guessed terminal result. Once the first connection durably commits, the
 * retry deterministically observes the same durable fence. Mirrors
 * tests/test-service-auth-coordination.c's
 * test_authority_transaction_write_intent_connections, which proves the
 * same two-connection contention at the write-intent layer this reconcile
 * call is built on. */
static void
test_reconcile_overtaking_across_connections (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-fence-race-XXXXXX", NULL);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  g_autoptr (WylHandle) first = open_handle (path);
  g_autoptr (WylHandle) second = open_handle (path);

  OvertakeContender contender = {
    .handle = second,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&contender.mutex);
  g_cond_init (&contender.cond);
  g_autoptr (GThread) thread = g_thread_new ("fence-overtake-contender",
      overtake_contender_thread, &contender);
  g_mutex_lock (&contender.mutex);
  while (!contender.ready)
    g_cond_wait (&contender.cond, &contender.mutex);
  g_mutex_unlock (&contender.mutex);

  Txn t1 = begin_txn (first);
  WylServiceCredentialFenceResult result1 = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t1.txn,
          wyl_handle_get_policy_store (first), NULL,
          WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "req-overtake", NULL, NULL,
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &result1), ==, WYRELOG_E_OK);
  g_assert_cmpint (result1.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);

  /* Second connection races the identical request identity while the first
   * connection's write intent and SQLite write transaction are still open:
   * it must fail closed, not silently insert a second row. */
  g_mutex_lock (&contender.mutex);
  contender.release = TRUE;
  g_cond_signal (&contender.cond);
  g_mutex_unlock (&contender.mutex);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (contender.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (contender.result.state, ==, 0);

  /* The first connection's fence commits durably. */
  finish_txn (&t1, TRUE);

  /* The retry on the second connection now deterministically observes the
   * exact durable fence rather than guessing or duplicating it. */
  Txn t2_retry = begin_txn (second);
  WylServiceCredentialFenceResult result2_retry = { 0 };
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence
      (t2_retry.txn, wyl_handle_get_policy_store (second), NULL,
          WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "req-overtake", NULL, NULL,
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &result2_retry), ==, WYRELOG_E_OK);
  g_assert_cmpint (result2_retry.state, ==,
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL);
  finish_txn (&t2_retry, FALSE);

  g_assert_cmpint (scalar (wyl_policy_store_get_db
          (wyl_handle_get_policy_store (second)),
          "SELECT count(*) FROM service_credential_operation_fences"
          " WHERE request_id='req-overtake';"), ==, 1);

  g_clear_object (&second);
  g_clear_object (&first);
  g_remove (path);
  g_autofree gchar *wal = g_strdup_printf ("%s-wal", path);
  g_autofree gchar *shm = g_strdup_printf ("%s-shm", path);
  g_remove (wal);
  g_remove (shm);
  g_rmdir (dir);
}

static void
test_reconcile_invalid_arguments (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  Txn t = begin_txn (handle);
  WylServiceCredentialFenceResult result = { 0xff, "x", 7 };

  /* issue without tenant. */
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, "req-invalid",
          "svc:x", NULL, NULL, &result), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (result.state, ==, 0);
  g_assert_cmpuint (result.successor_generation, ==, 0);

  /* rotate with a subject_id supplied. */
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, "req-invalid",
          "svc:x", NULL, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &result), ==,
      WYRELOG_E_INVALID);

  /* request_id too long. */
  g_autofree gchar *long_id = g_strnfill (257, 'a');
  g_assert_cmpint
      (wyl_policy_store_reconcile_service_credential_operation_fence (t.txn,
          store, NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, long_id, NULL,
          NULL, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &result), ==,
      WYRELOG_E_INVALID);

  finish_txn (&t, FALSE);
}

static void
test_handoff_cores_commit_once_and_stale_rotate_rolls_back (void)
{
  g_autoptr (WylHandle) handle = open_provisioned_handle ();
  const gchar *subject = "svc:fence:handoff";
  prepare_authority (handle, subject);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &cvk_len), ==, WYRELOG_E_OK);

  guint8 issue_target[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  memset (issue_target, 0x51, sizeof issue_target);
  wyl_id_t issue_escrow_id;
  g_assert_cmpint (wyl_id_new (&issue_escrow_id), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_request_t issue_handoff = {
    .escrow_id = &issue_escrow_id,.target_digest = issue_target,
    .deadline_at_us = g_get_real_time () + G_USEC_PER_SEC,
  };
  wyl_policy_service_credential_info_t issued = { 0 };
  wyl_policy_service_handoff_escrow_info_t issue_escrow = { 0 };
  Txn issue_txn = begin_txn (handle);
  g_assert_cmpint (wyl_policy_store_issue_service_credential_handoff_core
      (issue_txn.txn, store, subject, "tenant-a", "admin", "handoff-issue",
          0, NULL, cvk, cvk_len, &issue_handoff, &issued, &issue_escrow), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (issued.credential_id, ==, issue_escrow.credential_id);
  g_assert_cmpuint (issued.generation, ==, issue_escrow.credential_generation);
  finish_txn (&issue_txn, TRUE);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credentials;"), ==, 1);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_handoff_escrows "
          "WHERE request_id='handoff-issue';"), ==, 1);
  wyl_policy_service_handoff_escrow_info_t replay = { 0 };
  g_assert_cmpint (wyl_policy_store_service_handoff_escrow_load_by_request
      (store, "handoff-issue", &replay), ==, WYRELOG_E_OK);
  g_assert_cmpmem (replay.binding_digest, sizeof replay.binding_digest,
      issue_escrow.binding_digest, sizeof issue_escrow.binding_digest);
  g_assert_cmpstr (replay.credential_id, ==, issued.credential_id);
  wyl_policy_service_handoff_escrow_info_clear (&replay);

  /* A committed request replays its exact sealed tuple, rather than invoking
   * generation or claiming a second domain request. */
  Txn replay_txn = begin_txn (handle);
  wyl_policy_service_credential_info_t replayed = { 0 };
  wyl_policy_service_handoff_escrow_info_t replayed_escrow = { 0 };
  g_assert_cmpint (wyl_policy_store_issue_service_credential_handoff_core
      (replay_txn.txn, store, subject, "tenant-a", "admin", "handoff-issue",
          0, NULL, cvk, cvk_len, &issue_handoff, &replayed,
          &replayed_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpstr (replayed.credential_id, ==, issued.credential_id);
  g_assert_cmpmem (replayed_escrow.binding_digest,
      sizeof replayed_escrow.binding_digest, issue_escrow.binding_digest,
      sizeof issue_escrow.binding_digest);
  finish_txn (&replay_txn, TRUE);
  wyl_policy_service_handoff_escrow_info_clear (&replayed_escrow);
  wyl_policy_service_credential_info_clear (&replayed);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credentials;"), ==, 1);

  /* Reusing a request ID with changed domain input must not replay it. */
  Txn mismatched_replay_txn = begin_txn (handle);
  g_assert_cmpint (wyl_policy_store_issue_service_credential_handoff_core
      (mismatched_replay_txn.txn, store, subject, "tenant-b", "admin",
          "handoff-issue", 0, NULL, cvk, cvk_len, &issue_handoff,
          &replayed, &replayed_escrow), ==, WYRELOG_E_POLICY);
  finish_txn (&mismatched_replay_txn, FALSE);

  /* Required output validation precedes every credential or escrow write. */
  Txn invalid_output_txn = begin_txn (handle);
  g_assert_cmpint (wyl_policy_store_issue_service_credential_handoff_core
      (invalid_output_txn.txn, store, subject, "tenant-a", "admin",
          "handoff-invalid-output", 0, NULL, cvk, cvk_len, &issue_handoff,
          &replayed, NULL), ==, WYRELOG_E_INVALID);
  finish_txn (&invalid_output_txn, FALSE);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credentials;"), ==, 1);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_handoff_escrows;"), ==, 1);

  guint8 rotate_target[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  memset (rotate_target, 0x52, sizeof rotate_target);
  wyl_id_t rotate_escrow_id;
  g_assert_cmpint (wyl_id_new (&rotate_escrow_id), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_request_t rotate_handoff = {
    .escrow_id = &rotate_escrow_id,.target_digest = rotate_target,
    .deadline_at_us = g_get_real_time () + G_USEC_PER_SEC,
  };
  wyl_policy_service_credential_info_t rotated = { 0 };
  wyl_policy_service_handoff_escrow_info_t rotate_escrow = { 0 };
  Txn rotate_txn = begin_txn (handle);
  g_assert_cmpint (wyl_policy_store_rotate_service_credential_handoff_core
      (rotate_txn.txn, store, issued.credential_id, "admin", "handoff-rotate",
          0, NULL, NULL, NULL, issued.generation, cvk, cvk_len,
          &rotate_handoff, &rotated, &rotate_escrow), ==, WYRELOG_E_OK);
  g_assert_cmpstr (rotated.credential_id, ==, rotate_escrow.credential_id);
  g_assert_cmpuint (rotated.generation, ==,
      rotate_escrow.credential_generation);
  finish_txn (&rotate_txn, TRUE);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credentials WHERE state='active';"),
      ==, 1);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_handoff_escrows;"), ==, 2);

  guint8 stale_target[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  memset (stale_target, 0x53, sizeof stale_target);
  wyl_id_t stale_escrow_id;
  g_assert_cmpint (wyl_id_new (&stale_escrow_id), ==, WYRELOG_E_OK);
  wyl_policy_service_handoff_request_t stale_handoff = {
    .escrow_id = &stale_escrow_id,.target_digest = stale_target,
    .deadline_at_us = g_get_real_time () + G_USEC_PER_SEC,
  };
  g_autofree gchar *stale_old_id = g_strdup (rotated.credential_id);
  guint64 stale_generation = rotated.generation;
  wyl_policy_service_handoff_escrow_info_t stale_escrow = { 0 };
  Txn stale_txn = begin_txn (handle);
  g_assert_cmpint (wyl_policy_store_rotate_service_credential_handoff_core
      (stale_txn.txn, store, stale_old_id, "admin", "handoff-stale",
          0, NULL, NULL, NULL, stale_generation + 1, cvk, cvk_len,
          &stale_handoff, &rotated, &stale_escrow), ==, WYRELOG_E_POLICY);
  finish_txn (&stale_txn, FALSE);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credentials;"), ==, 2);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_credential_handoff_escrows "
          "WHERE request_id='handoff-stale';"), ==, 0);

  wyl_policy_service_credential_info_clear (&rotated);
  wyl_policy_service_handoff_escrow_info_clear (&stale_escrow);
  wyl_policy_service_handoff_escrow_info_clear (&rotate_escrow);
  wyl_policy_service_handoff_escrow_info_clear (&issue_escrow);
  wyl_policy_service_credential_info_clear (&issued);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-credential-operation-fence/golden-vectors",
      test_golden_vectors_exact);
  g_test_add_func ("/service-credential-operation-fence/invalid-field-shape",
      test_invalid_field_shape);
  g_test_add_func
      ("/service-credential-operation-fence/differentiates-inputs",
      test_fingerprint_differentiates_inputs);
  g_test_add_func ("/service-credential-operation-fence/fresh-creates-fence",
      test_fresh_request_creates_fence);
  g_test_add_func ("/service-credential-operation-fence/replay-idempotent",
      test_fence_replay_is_idempotent);
  g_test_add_func
      ("/service-credential-operation-fence/conflict-on-target-mismatch",
      test_fence_conflict_on_target_mismatch);
  g_test_add_func
      ("/service-credential-operation-fence/committed-issue-successor",
      test_committed_issue_returns_successor);
  g_test_add_func
      ("/service-credential-operation-fence/committed-issue-conflict",
      test_committed_issue_conflict_on_mismatch);
  g_test_add_func ("/service-credential-operation-fence/committed-rotate",
      test_committed_rotate_returns_new_successor);
  g_test_add_func
      ("/service-credential-operation-fence/precheck-with-committed",
      test_precheck_with_committed);
  g_test_add_func ("/service-credential-operation-fence/survives-restart",
      test_fence_survives_restart);
  g_test_add_func
      ("/service-credential-operation-fence/overtaking-across-connections",
      test_reconcile_overtaking_across_connections);
  g_test_add_func ("/service-credential-operation-fence/invalid-arguments",
      test_reconcile_invalid_arguments);
  g_test_add_func ("/service-credential-operation-fence/handoff-cores-atomic",
      test_handoff_cores_commit_once_and_stale_rotate_rolls_back);
  return g_test_run ();
}

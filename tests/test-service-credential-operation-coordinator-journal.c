/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include "wyrelog/auth/service-credential-operation-coordinator-journal-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-fence-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-storage-private.h"
#include "wyrelog/auth/service-credential-operation-storage-private.h"
#ifdef G_OS_WIN32
#include "wyrelog/auth/service-credential-operation-storage-windows-private.h"
#endif
#include "wyl-request-id-private.h"
static WylServiceCredentialOperationCoordinatorRequest
request (void)
{
  WylServiceCredentialOperationCoordinatorRequest r =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  r.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request_id, sizeof request_id), ==,
      WYRELOG_E_OK);
  r.request_id = g_strdup (request_id);
  r.subject_id = g_strdup ("subject");
  r.tenant_id = g_strdup ("tenant");
  r.destination = g_strdup ("record");
  r.parent_identity = g_strdup ("parent");
  r.actor_subject_id = g_strdup ("admin");
  r.escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991");
  for (guint i = 0; i < sizeof r.escrow_binding_digest; i++)
    r.escrow_binding_digest[i] = (guint8) (i + 1);
  r.expires_at_us = 1;
  return r;
}

static void
test_builder (void)
{
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_OK);
  g_assert_cmpint (out.state, ==, WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_assert_cmpstr (out.request_id, ==, r.request_id);
  g_assert_cmpint (out.expires_at_us, ==, r.expires_at_us);
  g_assert_cmpint (out.created_at_us, ==, 1);
  g_autofree gchar *saved_operation = g_strdup (out.operation_id);
  g_autofree gchar *saved_request = g_strdup (out.request_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "", 1, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpstr (out.operation_id, ==, saved_operation);
  g_assert_cmpstr (out.request_id, ==, saved_request);
  g_autofree gchar *too_long = g_malloc0 (4098);
  memset (too_long, 'x', 4097);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, too_long, 1, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 0, &out), ==, WYRELOG_E_INVALID);
  r.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_clear_pointer (&r.tenant_id, g_free);
  r.old_credential_id = g_strdup ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv");
  r.expected_generation = 1;
  g_clear_pointer (&r.subject_id, g_free);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_INVALID);
  r.subject_id = g_strdup ("subject");
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_OK);
  g_assert_cmpint (out.kind, ==, WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE);
  g_assert_null (out.tenant_id);
  g_assert_cmpstr (out.old_credential_id, ==,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv");
  g_assert_cmpuint (out.expected_generation, ==, 1);
  g_assert_cmpuint (out.successor_generation, ==, 0);
  g_assert_cmpint (out.created_at_us, ==, 1);
  g_assert_cmpint (out.updated_at_us, ==, 1);
  g_autofree gchar *rotate_operation = g_strdup (out.operation_id);
  g_clear_pointer (&r.subject_id, g_free);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpstr (out.operation_id, ==, rotate_operation);
  r.subject_id = g_strdup ("subject");
  wyl_service_credential_operation_record_clear (&out);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_server_committed_builder (void)
{
  const gchar *successor = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  WylServiceCredentialOperationCoordinatorRequest issue = request ();
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&issue, issue.request_id, 10, &prepared), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 1, 11, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (committed.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpstr (committed.successor_credential_id, ==, successor);
  g_assert_cmpuint (committed.successor_generation, ==, 1);
  g_assert_cmpuint (committed.expected_generation, ==, 0);
  g_assert_cmpint (committed.created_at_us, ==, 10);
  g_assert_cmpint (committed.updated_at_us, ==, 11);
  g_autofree gchar *saved_id = g_strdup (committed.successor_credential_id);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&committed, successor, 1, 1000, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (committed.updated_at_us, ==, 11);
  g_assert_cmpstr (committed.successor_credential_id, ==, saved_id);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&committed, successor, 2, 12, &committed), ==, WYRELOG_E_POLICY);
  g_assert_cmpstr (committed.successor_credential_id, ==, saved_id);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&prepared);

  WylServiceCredentialOperationCoordinatorRequest rotate = request ();
  rotate.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_clear_pointer (&rotate.tenant_id, g_free);
  rotate.old_credential_id = g_strdup (successor);
  rotate.expected_generation = 1;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&rotate, rotate.request_id, 10, &prepared), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 1, 10, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.successor_generation, ==, 1);
  g_assert_cmpuint (committed.expected_generation, ==, 1);
  wyl_service_credential_operation_record_clear (&committed);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, "not-canonical", 1, 10, &committed), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 0, 10, &committed), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 1, 9, &committed), ==, WYRELOG_E_INVALID);
  g_assert_null (committed.operation_id);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_coordinator_request_clear (&rotate);

  memset (issue.escrow_binding_digest, 0, sizeof issue.escrow_binding_digest);
  guint8 binding[WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES]
  = { 1 };
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&issue, issue.request_id, 20, &prepared), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed_bound
      (&prepared, successor, 1, binding, 21, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpmem (committed.escrow_binding_digest,
      sizeof committed.escrow_binding_digest, binding, sizeof binding);
  binding[0]++;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed_bound
      (&committed, successor, 1, binding, 22, &prepared), ==, WYRELOG_E_POLICY);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_coordinator_request_clear (&issue);
}

static void
assert_record_bytes_unchanged (const WylServiceCredentialOperationRecord
    *record, GBytes *before)
{
  g_autoptr (GBytes) after = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (record,
          &after), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (before, after));
}

static void
test_fence_classification (void)
{
  const gchar *successor = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *other_successor = "wlc_000000000000000000000000001";
  WylServiceCredentialOperationCoordinatorRequest issue = request ();
  WylServiceCredentialOperationCoordinatorRequest rotate = request ();
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialFenceResult fence = { 0 };
  WylServiceCredentialOperationFenceClassification output;
  g_autoptr (GBytes) prepared_bytes = NULL;
  g_autoptr (GBytes) committed_bytes = NULL;

  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&issue, issue.request_id, 10, &prepared), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 1, 11, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&prepared,
          &prepared_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&committed,
          &committed_bytes), ==, WYRELOG_E_OK);

  rotate.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_clear_pointer (&rotate.tenant_id, g_free);
  rotate.old_credential_id = g_strdup (successor);
  rotate.expected_generation = 1;
  WylServiceCredentialOperationRecord rotate_prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&rotate, rotate.request_id, 10, &rotate_prepared), ==, WYRELOG_E_OK);
  memset (&fence, 0, sizeof fence);
  fence.state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED;
  g_strlcpy (fence.successor_credential_id, successor,
      sizeof fence.successor_credential_id);
  fence.successor_generation = 2;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&rotate_prepared, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_OK);
  g_assert_cmpint (output, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_COMMIT_REQUIRED);
  /* A rotate target is exactly the old credential: a tenant-bearing rotate
   * record cannot be interpreted as the same immutable fence target. */
  rotate_prepared.tenant_id = g_strdup ("unexpected-tenant");
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&rotate_prepared, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);
  g_clear_pointer (&rotate_prepared.tenant_id, g_free);

  typedef struct
  {
    const gchar *name;
    const WylServiceCredentialOperationRecord *record;
    wyrelog_error_t precheck_rc;
    WylServiceCredentialFenceResultState state;
    gboolean committed_successor;
    wyrelog_error_t expected_rc;
    WylServiceCredentialOperationFenceClassification expected;
  } Case;
  const Case cases[] = {
    {"prepared/no-fence", &prepared, WYRELOG_E_NOT_FOUND, 0, FALSE,
        WYRELOG_E_OK, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING},
    {"prepared/committed", &prepared, WYRELOG_E_OK,
          WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED, TRUE, WYRELOG_E_OK,
        WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_COMMIT_REQUIRED},
    {"prepared/terminal", &prepared, WYRELOG_E_OK,
          WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL, FALSE,
          WYRELOG_E_OK,
        WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_TERMINAL_NO_COMMIT},
    {"prepared/conflict", &prepared, WYRELOG_E_OK,
          WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT, FALSE, WYRELOG_E_OK,
        WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_CONFLICT},
    {"committed/no-fence", &committed, WYRELOG_E_NOT_FOUND, 0, FALSE,
        WYRELOG_E_POLICY, 0},
    {"committed/committed", &committed, WYRELOG_E_OK,
          WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED, TRUE, WYRELOG_E_OK,
        WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_REPLAY_COMMITTED},
    {"committed/terminal", &committed, WYRELOG_E_OK,
          WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL, FALSE,
        WYRELOG_E_POLICY, 0},
    {"committed/conflict", &committed, WYRELOG_E_OK,
          WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT, FALSE, WYRELOG_E_POLICY,
        0},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_test_message ("%s", cases[i].name);
    memset (&fence, 0, sizeof fence);
    fence.state = cases[i].state;
    if (cases[i].committed_successor) {
      g_strlcpy (fence.successor_credential_id, successor,
          sizeof fence.successor_credential_id);
      fence.successor_generation = 1;
    }
    WylServiceCredentialFenceResult fence_before = fence;
    output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_CONFLICT;
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_classify_fence
        (cases[i].record, cases[i].precheck_rc, &fence, &output), ==,
        cases[i].expected_rc);
    if (cases[i].expected_rc == WYRELOG_E_OK)
      g_assert_cmpint (output, ==, cases[i].expected);
    else
      g_assert_cmpint (output, ==,
          WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_CONFLICT);
    g_assert_cmpmem (&fence, sizeof fence, &fence_before, sizeof fence_before);
    assert_record_bytes_unchanged (cases[i].record,
        cases[i].record == &prepared ? prepared_bytes : committed_bytes);
  }

  /* Neither a malformed fence result nor a mismatched committed tuple may
   * cause a journal write or overwrite the caller's output. */
  memset (&fence, 0, sizeof fence);
  fence.state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED;
  g_strlcpy (fence.successor_credential_id, "not-canonical",
      sizeof fence.successor_credential_id);
  fence.successor_generation = 1;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&prepared, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);
  assert_record_bytes_unchanged (&prepared, prepared_bytes);

  memset (&fence, 'x', sizeof fence);
  fence.state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED;
  fence.successor_generation = 1;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&prepared, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);
  assert_record_bytes_unchanged (&prepared, prepared_bytes);

  memset (&fence, 0, sizeof fence);
  fence.state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED;
  g_strlcpy (fence.successor_credential_id, successor,
      sizeof fence.successor_credential_id);
  fence.successor_generation = 2;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&committed, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);
  assert_record_bytes_unchanged (&committed, committed_bytes);

  g_strlcpy (fence.successor_credential_id, other_successor,
      sizeof fence.successor_credential_id);
  fence.successor_generation = 1;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&committed, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);
  assert_record_bytes_unchanged (&committed, committed_bytes);

  memset (&fence, 0, sizeof fence);
  fence.state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL;
  fence.successor_generation = 1;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&prepared, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);

  memset (&fence, 0, sizeof fence);
  fence.state = (WylServiceCredentialFenceResultState) 99;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&prepared, WYRELOG_E_OK, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);

  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&prepared, WYRELOG_E_BUSY, &fence, &output), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);

  memset (&fence, 0, sizeof fence);
  fence.state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&prepared, WYRELOG_E_NOT_FOUND, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);

  WylServiceCredentialOperationRecord invalid = prepared;
  invalid.state = (WylServiceCredentialOperationState) 99;
  output = WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_classify_fence
      (&invalid, WYRELOG_E_NOT_FOUND, &fence, &output), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (output, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FENCE_PENDING);
  /* invalid aliases prepared's owned fields; never clear it */

  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_record_clear (&rotate_prepared);
  wyl_service_credential_operation_coordinator_request_clear (&rotate);
  wyl_service_credential_operation_coordinator_request_clear (&issue);
}

typedef struct
{
  gchar *root;
  WylServiceCredentialOperationStorage storage;
  WylServiceCredentialOperationRootAnchor anchor;
} JournalFixture;

static void
journal_fixture_set_up (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  fixture->storage = (WylServiceCredentialOperationStorage)
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  fixture->anchor = (WylServiceCredentialOperationRootAnchor)
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
#ifdef G_OS_WIN32
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_autofree gchar *name = g_strdup_printf ("wyrelog-operation-journal-%lu-%u",
      (gulong) GetCurrentProcessId (),
      g_random_int ());
  fixture->root = g_build_filename (local, name, NULL);
#else
  fixture->root = g_dir_make_tmp ("wyrelog-operation-journal-XXXXXX", NULL);
#endif
  g_assert_nonnull (fixture->root);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (fixture->root,
          &fixture->storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&fixture->storage, &fixture->anchor), ==, WYRELOG_E_OK);
}

static void
journal_fixture_tear_down (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  wyl_service_credential_operation_storage_clear (&fixture->storage);
  g_autoptr (GDir) directory = g_dir_open (fixture->root, 0, NULL);
  const gchar *entry;
  g_assert_nonnull (directory);
  while ((entry = g_dir_read_name (directory)) != NULL) {
    g_autofree gchar *path = g_build_filename (fixture->root, entry, NULL);
    g_assert_cmpint (g_remove (path), ==, 0);
  }
  g_assert_cmpint (g_rmdir (fixture->root), ==, 0);
  g_clear_pointer (&fixture->root, g_free);
}

static void
record_name (const gchar *request_id,
    WylServiceCredentialOperationChildName *out_name)
{
  g_autofree gchar *raw = g_strdup_printf ("op-%s", request_id);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate (raw,
          out_name), ==, WYRELOG_E_OK);
}

static wyrelog_error_t
fixture_child_create (JournalFixture *fixture,
    const WylServiceCredentialOperationChildName *name, GBytes *bytes)
{
#ifdef G_OS_WIN32
  return wyl_win_child_create (&fixture->storage, &fixture->anchor, name,
      bytes);
#else
  return wyl_service_credential_operation_child_create (&fixture->storage,
      &fixture->anchor, name, bytes);
#endif
}

static wyrelog_error_t
fixture_child_read (JournalFixture *fixture,
    const WylServiceCredentialOperationChildName *name, GBytes **out_bytes)
{
#ifdef G_OS_WIN32
  return wyl_win_child_read (&fixture->storage, &fixture->anchor, name,
      out_bytes);
#else
  return wyl_service_credential_operation_child_read (&fixture->storage,
      &fixture->anchor, name, out_bytes);
#endif
}

static void
store_record (JournalFixture *fixture,
    const WylServiceCredentialOperationCoordinatorRequest *r,
    WylServiceCredentialOperationRecord *record)
{
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (r, r->request_id, 1, record), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (record,
          &bytes), ==, WYRELOG_E_OK);
  record_name (r->request_id, &name);
  g_assert_cmpint (fixture_child_create (fixture, &name, bytes), ==,
      WYRELOG_E_OK);
  wyl_service_credential_operation_child_name_clear (&name);
}

#ifndef G_OS_WIN32
typedef gint FixtureLock;
#define FIXTURE_LOCK_INIT (-1)
static wyrelog_error_t
fixture_child_lock (JournalFixture *fixture,
    const WylServiceCredentialOperationChildName *name, FixtureLock *out_lock)
{
  return wyl_service_credential_operation_child_lock (&fixture->storage,
      &fixture->anchor, name, out_lock);
}

static void
fixture_child_unlock (JournalFixture *fixture,
    const WylServiceCredentialOperationChildName *name, FixtureLock lock)
{
  wyl_service_credential_operation_child_unlock (&fixture->storage,
      &fixture->anchor, name, lock);
}
#else
typedef HANDLE FixtureLock;
#define FIXTURE_LOCK_INIT INVALID_HANDLE_VALUE
static wyrelog_error_t
fixture_child_lock (JournalFixture *fixture,
    const WylServiceCredentialOperationChildName *name, FixtureLock *out_lock)
{
  return wyl_win_child_lock (&fixture->storage, &fixture->anchor, name,
      out_lock);
}

static void
fixture_child_unlock (JournalFixture *fixture,
    const WylServiceCredentialOperationChildName *name, FixtureLock lock)
{
  wyl_win_child_unlock (&fixture->storage, &fixture->anchor, name, lock);
}
#endif

static void
test_begin_or_replay (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord first =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord second =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord third =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) bytes = NULL;
  gboolean replayed = TRUE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 10, &replayed, &first), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (first.state, ==, WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_assert_cmpstr (first.operation_id, ==, r.request_id);
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_read (fixture, &name, &bytes), ==,
      WYRELOG_E_OK);
  gsize size = 0;
  const gchar *serialized = g_bytes_get_data (bytes, &size);
  g_assert_null (g_strstr_len (serialized, size, "secret-canary"));
  WylServiceCredentialOperationRecord decoded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_record_decode (bytes,
          &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpstr (decoded.operation_id, ==, r.request_id);
  g_assert_cmpstr (decoded.subject_id, ==, "subject");
  g_assert_cmpstr (decoded.actor_subject_id, ==, "admin");
  wyl_service_credential_operation_record_clear (&decoded);
  g_clear_pointer (&bytes, g_bytes_unref);
  wyl_service_credential_operation_storage_clear (&fixture->storage);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (fixture->root,
          &fixture->storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&fixture->storage, &fixture->anchor), ==, WYRELOG_E_OK);
  replayed = FALSE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 99, &replayed, &second), ==,
      WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpstr (second.operation_id, ==, first.operation_id);
  g_assert_cmpint (second.created_at_us, ==, first.created_at_us);
  WylServiceCredentialOperationCoordinatorRequest r2 = request ();
  replayed = TRUE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r2, 100, &replayed, &third), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpstr (third.operation_id, ==, r2.request_id);
  g_assert_cmpstr (third.operation_id, !=, first.operation_id);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_coordinator_request_clear (&r2);
  wyl_service_credential_operation_record_clear (&third);
  wyl_service_credential_operation_record_clear (&second);
  wyl_service_credential_operation_record_clear (&first);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_begin_rejects_oversized_destination_before_write (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = TRUE;
  g_autofree gchar *max_leaf = g_strnfill (255, 'a');
  g_autofree gchar *too_long = g_strnfill (256, 'a');
  const gchar *invalid[] = { "nested/file", "CON.txt", too_long };

  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    g_free (r.destination);
    r.destination = g_strdup (invalid[i]);
    replayed = TRUE;
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_begin_or_replay
        (&fixture->storage, &fixture->anchor, &r, 1, &replayed, &out), ==,
        WYRELOG_E_INVALID);
    g_assert_false (replayed);
    g_assert_null (out.request_id);
  }
  {
    g_autoptr (GDir) directory = g_dir_open (fixture->root, 0, NULL);
    g_assert_nonnull (directory);
    g_assert_null (g_dir_read_name (directory));
  }

  g_free (r.destination);
  r.destination = g_strdup (max_leaf);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 1, &replayed, &out), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpstr (out.destination, ==, max_leaf);

  wyl_service_credential_operation_record_clear (&out);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_begin_or_replay_conflict (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) before = NULL;
  g_autoptr (GBytes) after = NULL;
  gboolean replayed = FALSE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 1, &replayed, &out), ==,
      WYRELOG_E_OK);
  g_autofree gchar *saved_operation = g_strdup (out.operation_id);
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_read (fixture, &name, &before), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&r.actor_subject_id, g_free);
  r.actor_subject_id = g_strdup ("other-admin");
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 2, &replayed, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved_operation);
  g_assert_cmpint (fixture_child_read (fixture, &name, &after), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (before, after));
  g_clear_pointer (&after, g_bytes_unref);
  g_clear_pointer (&r.actor_subject_id, g_free);
  r.actor_subject_id = g_strdup ("admin");
  g_clear_pointer (&r.destination, g_free);
  r.destination = g_strdup ("changed");
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 2, &replayed, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved_operation);
  wyl_service_credential_operation_child_name_clear (&name);
  g_clear_pointer (&r.destination, g_free);
  r.destination = g_strdup ("record");
  r.escrow_binding_digest[0] ^= 0xff;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 3, &replayed, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved_operation);
  r.escrow_binding_digest[0] ^= 0xff;
  r.expires_at_us++;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 3, &replayed, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved_operation);
  wyl_service_credential_operation_record_clear (&out);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_begin_or_replay_malformed_fails_closed (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autoptr (GBytes) malformed = g_bytes_new_static ("truncated", 9);
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_create (fixture, &name, malformed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 1, NULL, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_null (out.operation_id);
  g_autoptr (GBytes) after = NULL;
  g_assert_cmpint (fixture_child_read (fixture, &name, &after), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (malformed, after));
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_begin_or_replay_busy (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  FixtureLock lock = FIXTURE_LOCK_INIT;
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_lock (fixture, &name, &lock), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 1, NULL, &out), ==,
      WYRELOG_E_BUSY);
  g_assert_null (out.operation_id);
  fixture_child_unlock (fixture, &name, lock);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_begin_or_replay_rejects_noncanonical_request (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_clear_pointer (&r.request_id, g_free);
  r.request_id = g_strdup ("not-a-canonical-request-id");
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 1, NULL, &out), ==,
      WYRELOG_E_INVALID);
  g_assert_null (out.operation_id);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_server_committed_checkpoint (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  const gchar *successor = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord begun =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord loaded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) first_bytes = NULL;
  g_autoptr (GBytes) replay_bytes = NULL;
  gboolean replayed = TRUE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 10, NULL, &begun), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, r.request_id, successor, 1, 11,
          &replayed, &committed), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (committed.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_read (fixture, &name, &first_bytes), ==,
      WYRELOG_E_OK);
  gsize size = 0;
  const gchar *serialized = g_bytes_get_data (first_bytes, &size);
  g_assert_null (g_strstr_len (serialized, size, "secret-canary"));
  wyl_service_credential_operation_storage_clear (&fixture->storage);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (fixture->root,
          &fixture->storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&fixture->storage, &fixture->anchor), ==, WYRELOG_E_OK);
  replayed = FALSE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, r.request_id, successor, 1, 99,
          &replayed, &loaded), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpint (loaded.updated_at_us, ==, 11);
  g_assert_cmpstr (loaded.actor_subject_id, ==, "admin");
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (first_bytes, replay_bytes));
  g_clear_pointer (&r.actor_subject_id, g_free);
  r.actor_subject_id = g_strdup ("other-admin");
  g_autofree gchar *saved_actor = g_strdup (loaded.actor_subject_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 100, NULL, &loaded), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (loaded.actor_subject_id, ==, saved_actor);
  g_clear_pointer (&replay_bytes, g_bytes_unref);
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (first_bytes, replay_bytes));
  g_autofree gchar *saved = g_strdup (loaded.operation_id);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, r.request_id, successor, 2, 100,
          &replayed, &loaded), ==, WYRELOG_E_POLICY);
  g_assert_cmpstr (loaded.operation_id, ==, saved);
  g_clear_pointer (&replay_bytes, g_bytes_unref);
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (first_bytes, replay_bytes));
  WylServiceCredentialOperationRootAnchor wrong_anchor = fixture->anchor;
  wrong_anchor.identity_a++;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &wrong_anchor, r.request_id, successor, 1, 100,
          &replayed, &loaded), ==, WYRELOG_E_POLICY);
  g_assert_cmpstr (loaded.operation_id, ==, saved);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&loaded);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&begun);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_server_committed_checkpoint_fails_closed (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  const gchar *successor = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationCoordinatorRequest saved_request = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  FixtureLock lock = FIXTURE_LOCK_INIT;
  g_autoptr (GBytes) malformed = g_bytes_new_static ("truncated", 9);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&saved_request, saved_request.request_id, 1, &out), ==, WYRELOG_E_OK);
  g_autofree gchar *saved = g_strdup (out.operation_id);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, r.request_id, successor, 1, 2, NULL,
          &out), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpstr (out.operation_id, ==, saved);
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_create (fixture, &name, malformed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, r.request_id, successor, 1, 2, NULL,
          &out), ==, WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved);
  g_autoptr (GBytes) after = NULL;
  g_assert_cmpint (fixture_child_read (fixture, &name, &after), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (malformed, after));
  /* A separately locked request cannot be inspected or replaced. */
  WylServiceCredentialOperationCoordinatorRequest busy = request ();
  WylServiceCredentialOperationChildName busy_name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  record_name (busy.request_id, &busy_name);
  g_assert_cmpint (fixture_child_lock (fixture, &busy_name, &lock), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, busy.request_id, successor, 1, 2,
          NULL, &out), ==, WYRELOG_E_BUSY);
  g_assert_cmpstr (out.operation_id, ==, saved);
  fixture_child_unlock (fixture, &busy_name, lock);
  wyl_service_credential_operation_child_name_clear (&busy_name);
  wyl_service_credential_operation_coordinator_request_clear (&busy);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&out);
  wyl_service_credential_operation_coordinator_request_clear (&saved_request);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_load_missing_and_noncanonical (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, r.request_id, &out), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_null (out.operation_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, "not-a-canonical-request-id",
          &out), ==, WYRELOG_E_INVALID);
  g_assert_null (out.operation_id);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
test_load_valid_snapshots (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest prepared_request = request ();
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  store_record (fixture, &prepared_request, &prepared);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, prepared_request.request_id, &out),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (out.state, ==, WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_assert_cmpstr (out.operation_id, ==, prepared_request.request_id);
  wyl_service_credential_operation_record_clear (&out);

  WylServiceCredentialOperationCoordinatorRequest committed_request =
      request ();
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&committed_request, committed_request.request_id, 1, &committed), ==,
      WYRELOG_E_OK);
  committed.state = WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED;
  committed.successor_credential_id =
      g_strdup ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv");
  committed.successor_generation = 1;
  g_autoptr (GBytes) bytes = NULL;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&committed,
          &bytes), ==, WYRELOG_E_OK);
  record_name (committed_request.request_id, &name);
  g_assert_cmpint (fixture_child_create (fixture, &name, bytes), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, committed_request.request_id,
          &out), ==, WYRELOG_E_OK);
  g_assert_cmpint (out.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpstr (out.operation_id, ==, committed_request.request_id);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&out);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_coordinator_request_clear
      (&committed_request);
  wyl_service_credential_operation_coordinator_request_clear
      (&prepared_request);
}

static void
test_rotate_expected_generation_is_immutable (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  const gchar *successor = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  WylServiceCredentialOperationCoordinatorRequest rotate = request ();
  WylServiceCredentialOperationCoordinatorRequest changed = request ();
  WylServiceCredentialOperationRecord begun =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord loaded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) committed_bytes = NULL;
  g_autoptr (GBytes) replay_bytes = NULL;
  gboolean replayed = FALSE;

  rotate.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_clear_pointer (&rotate.tenant_id, g_free);
  rotate.old_credential_id = g_strdup (successor);
  rotate.expected_generation = 1;
  g_clear_pointer (&changed.request_id, g_free);
  changed.request_id = g_strdup (rotate.request_id);
  changed.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_clear_pointer (&changed.tenant_id, g_free);
  changed.old_credential_id = g_strdup (successor);
  changed.expected_generation = 2;

  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &rotate, 10, &replayed,
          &begun), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpuint (begun.expected_generation, ==, 1);
  g_assert_cmpuint (begun.successor_generation, ==, 0);
  g_autofree gchar *saved_operation = g_strdup (begun.operation_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &changed, 11, NULL, &begun), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (begun.operation_id, ==, saved_operation);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, rotate.request_id, successor, 1,
          12, &replayed, &committed), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (committed.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpuint (committed.expected_generation, ==, 1);
  g_assert_cmpuint (committed.successor_generation, ==, 1);
  g_assert_cmpstr (committed.successor_credential_id, ==, successor);
  record_name (rotate.request_id, &name);
  g_assert_cmpint (fixture_child_read (fixture, &name, &committed_bytes), ==,
      WYRELOG_E_OK);

  wyl_service_credential_operation_storage_clear (&fixture->storage);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (fixture->root,
          &fixture->storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&fixture->storage, &fixture->anchor), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, rotate.request_id, &loaded), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (loaded.expected_generation, ==, 1);
  g_assert_cmpuint (loaded.successor_generation, ==, 1);
  g_assert_cmpstr (loaded.successor_credential_id, ==, successor);
  wyl_service_credential_operation_record_clear (&loaded);

  replayed = FALSE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &rotate, 99, &replayed,
          &loaded), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpint (loaded.updated_at_us, ==, 12);
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (committed_bytes, replay_bytes));
  g_autofree gchar *saved_loaded = g_strdup (loaded.operation_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &changed, 100, NULL, &loaded), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (loaded.operation_id, ==, saved_loaded);
  g_clear_pointer (&replay_bytes, g_bytes_unref);
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (committed_bytes, replay_bytes));

  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&loaded);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&begun);
  wyl_service_credential_operation_coordinator_request_clear (&changed);
  wyl_service_credential_operation_coordinator_request_clear (&rotate);
}

static void
test_load_fails_closed_and_preserves_output (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationCoordinatorRequest other = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord mismatched =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) malformed = g_bytes_new_static ("truncated", 9);
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_create (fixture, &name, malformed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&other, other.request_id, 1, &out), ==, WYRELOG_E_OK);
  g_autofree gchar *saved = g_strdup (out.operation_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, r.request_id, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved);
  wyl_service_credential_operation_child_name_clear (&name);

  WylServiceCredentialOperationCoordinatorRequest r2 = request ();
  g_autoptr (GBytes) mismatched_bytes = NULL;
  record_name (r2.request_id, &name);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&other, other.request_id, 1, &mismatched), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&mismatched,
          &mismatched_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint (fixture_child_create (fixture, &name, mismatched_bytes), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, r2.request_id, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved);
  wyl_service_credential_operation_child_name_clear (&name);

  WylServiceCredentialOperationCoordinatorRequest legacy_request = request ();
  WylServiceCredentialOperationRecord legacy =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autoptr (GBytes) encoded_legacy = NULL;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&legacy_request, legacy_request.request_id, 1, &legacy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&legacy,
          &encoded_legacy), ==, WYRELOG_E_OK);
  gsize legacy_len = 0;
  const guint8 *legacy_data = g_bytes_get_data (encoded_legacy, &legacy_len);
  guint8 *v1_data = g_memdup2 (legacy_data, legacy_len);
  v1_data[8] = 0;
  v1_data[9] = 0;
  v1_data[10] = 0;
  v1_data[11] = 1;
  g_autoptr (GBytes) v1 = g_bytes_new_take (v1_data, legacy_len);
  record_name (legacy_request.request_id, &name);
  g_assert_cmpint (fixture_child_create (fixture, &name, v1), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &fixture->anchor, legacy_request.request_id, &out),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved);
  wyl_service_credential_operation_child_name_clear (&name);

  WylServiceCredentialOperationRootAnchor wrong_anchor = fixture->anchor;
  wrong_anchor.identity_a++;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load
      (&fixture->storage, &wrong_anchor, r.request_id, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved);
  wyl_service_credential_operation_record_clear (&mismatched);
  wyl_service_credential_operation_record_clear (&legacy);
  wyl_service_credential_operation_record_clear (&out);
  wyl_service_credential_operation_coordinator_request_clear (&legacy_request);
  wyl_service_credential_operation_coordinator_request_clear (&r2);
  wyl_service_credential_operation_coordinator_request_clear (&other);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

static void
assert_handoff_tuple_preserved (const WylServiceCredentialOperationRecord *a,
    const WylServiceCredentialOperationRecord *b)
{
  g_assert_cmpuint (a->version, ==, b->version);
  g_assert_cmpint (a->kind, ==, b->kind);
  g_assert_cmpstr (a->operation_id, ==, b->operation_id);
  g_assert_cmpstr (a->request_id, ==, b->request_id);
  g_assert_cmpstr (a->subject_id, ==, b->subject_id);
  g_assert_cmpstr (a->tenant_id, ==, b->tenant_id);
  g_assert_cmpstr (a->destination, ==, b->destination);
  g_assert_cmpstr (a->parent_identity, ==, b->parent_identity);
  g_assert_cmpstr (a->actor_subject_id, ==, b->actor_subject_id);
  g_assert_cmpstr (a->old_credential_id, ==, b->old_credential_id);
  g_assert_cmpstr (a->successor_credential_id, ==, b->successor_credential_id);
  g_assert_cmpuint (a->successor_generation, ==, b->successor_generation);
  g_assert_cmpstr (a->escrow_id, ==, b->escrow_id);
  g_assert_cmpmem (a->escrow_binding_digest,
      sizeof a->escrow_binding_digest, b->escrow_binding_digest,
      sizeof b->escrow_binding_digest);
  g_assert_cmpuint (a->publication_receipt_version, ==,
      b->publication_receipt_version);
  g_assert_cmpstr (a->reservation_id, ==, b->reservation_id);
  g_assert_cmpstr (a->stage_basename, ==, b->stage_basename);
  g_assert_cmpstr (a->stage_identity, ==, b->stage_identity);
  g_assert_cmpstr (a->publication_receipt_id, ==, b->publication_receipt_id);
  g_assert_cmpuint (a->expected_generation, ==, b->expected_generation);
  g_assert_cmpint (a->expires_at_us, ==, b->expires_at_us);
  g_assert_cmpint (a->created_at_us, ==, b->created_at_us);
  g_assert_cmpuint (a->attempts, ==, b->attempts);
}

static void
test_v5_handoff_lifecycle_builders (void)
{
  const gchar *successor = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  WylServiceCredentialOperationCoordinatorRequest request_value = request ();
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord planned =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord publication =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord published =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord cleanup =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord oar =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord resumed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord terminal =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&request_value, request_value.request_id, 10, &prepared), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 1, 11, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_publication_planned
      (&committed, "reservation", "stage", "receipt", 12, &planned), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (planned.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED);
  g_assert_cmpstr (planned.stage_identity, ==, "");
  g_autoptr (GBytes) planned_bytes = NULL;
  g_autoptr (GBytes) replay_bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&planned,
          &planned_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_publication_planned
      (&planned, "reservation", "stage", "receipt", 99, &published), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&published,
          &replay_bytes), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (planned_bytes, replay_bytes));
  wyl_service_credential_operation_record_clear (&published);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_publication_planned
      (&planned, "other", "stage", "receipt", 13, &published), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_file_published
      (&planned, "reservation", "stage", "stage-id", "receipt", 13,
          &published), ==, WYRELOG_E_POLICY);
  g_assert_null (published.operation_id);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_publication_prepared
      (&committed, "reservation", "stage", "stage-id", "receipt", 13,
          &publication), ==, WYRELOG_E_POLICY);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_publication_prepared
      (&planned, "reservation", "stage", "stage-id", "receipt", 13,
          &publication), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_file_published
      (&publication, "reservation", "stage", "wrong", "receipt", 14,
          &published), ==, WYRELOG_E_POLICY);
  g_assert_null (published.operation_id);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_file_published
      (&publication, "reservation", "stage", "stage-id", "receipt", 14,
          &published), ==, WYRELOG_E_OK);
  g_assert_cmpint (published.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_cleanup_required
      (&published, 15, &cleanup), ==, WYRELOG_E_OK);
  g_assert_cmpint (cleanup.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED);

  const WylServiceCredentialOperationRecord *source_records[] = {
    &committed, &planned, &publication, &published, &cleanup,
  };
  const WylServiceCredentialOperationState source_states[] = {
    WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED,
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED,
    WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED,
    WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED,
  };
  for (guint i = 0; i < G_N_ELEMENTS (source_records); i++) {
    WylServiceCredentialOperationRecord probe_oar =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    WylServiceCredentialOperationRecord probe_resume =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_build_operator_action_required
        (source_records[i], WYL_SERVICE_CREDENTIAL_OPERATION_OAR_EXPLICIT_HOLD,
            16, &probe_oar), ==, WYRELOG_E_OK);
    WylServiceCredentialOperationState probe_source = 0;
    WylServiceCredentialOperationOarCause probe_cause = 0;
    g_assert_true (wyl_service_credential_operation_oar_reason_parse
        (probe_oar.terminal_reason, &probe_source, &probe_cause));
    g_assert_cmpint (probe_source, ==, source_states[i]);
    g_assert_cmpint (probe_cause, ==,
        WYL_SERVICE_CREDENTIAL_OPERATION_OAR_EXPLICIT_HOLD);
    assert_handoff_tuple_preserved (source_records[i], &probe_oar);
    g_assert_cmpint
        (wyl_service_credential_operation_coordinator_build_operator_resume
        (&probe_oar, 17, &probe_resume), ==, WYRELOG_E_OK);
    g_assert_cmpint (probe_resume.state, ==, source_states[i]);
    assert_handoff_tuple_preserved (&probe_oar, &probe_resume);
    wyl_service_credential_operation_record_clear (&probe_resume);
    wyl_service_credential_operation_record_clear (&probe_oar);
  }
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&cleanup, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN, 16,
          &oar), ==, WYRELOG_E_OK);
  g_assert_cmpint (oar.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED);
  g_assert_cmpstr (oar.terminal_reason, ==,
      "oar.v1:cleanup-required:receipt-uncertain");
  WylServiceCredentialOperationState source = 0;
  WylServiceCredentialOperationOarCause cause = 0;
  g_assert_true (wyl_service_credential_operation_oar_reason_parse
      (oar.terminal_reason, &source, &cause));
  g_assert_cmpint (source, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED);
  g_assert_cmpint (cause, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN);
  g_assert_cmpstr (oar.escrow_id, ==, prepared.escrow_id);
  g_assert_cmpmem (oar.escrow_binding_digest,
      sizeof oar.escrow_binding_digest, prepared.escrow_binding_digest,
      sizeof prepared.escrow_binding_digest);
  g_assert_cmpstr (oar.successor_credential_id, ==, successor);
  assert_handoff_tuple_preserved (&cleanup, &oar);

  g_autoptr (GBytes) oar_bytes = NULL;
  g_autoptr (GBytes) oar_replay_bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&oar,
          &oar_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&oar, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN, 99,
          &resumed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&resumed,
          &oar_replay_bytes), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (oar_bytes, oar_replay_bytes));
  wyl_service_credential_operation_record_clear (&resumed);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&oar, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_UNCERTAIN, 99,
          &resumed), ==, WYRELOG_E_POLICY);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_resume
      (&oar, 17, &resumed), ==, WYRELOG_E_OK);
  g_assert_cmpint (resumed.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED);
  g_assert_null (resumed.terminal_reason);
  assert_handoff_tuple_preserved (&oar, &resumed);
  g_autoptr (GBytes) before_time_rollback = NULL;
  g_autoptr (GBytes) after_time_rollback = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&resumed,
          &before_time_rollback), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&committed, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_EXPIRED, 10,
          &resumed), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&resumed,
          &after_time_rollback), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (before_time_rollback, after_time_rollback));

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_terminal
      (&resumed, WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED,
          NULL, 18, &terminal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (terminal.terminal_reason, ==, "terminal.v1:file-published");
  assert_handoff_tuple_preserved (&resumed, &terminal);
  g_autoptr (GBytes) terminal_bytes = NULL;
  g_autoptr (GBytes) terminal_replay_bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&terminal,
          &terminal_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_terminal
      (&terminal, WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED,
          NULL, 99, &resumed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&resumed,
          &terminal_replay_bytes), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (terminal_bytes, terminal_replay_bytes));
  wyl_service_credential_operation_record_clear (&resumed);
  wyl_service_credential_operation_record_clear (&terminal);

  gchar remediation_request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (remediation_request,
          sizeof remediation_request), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_terminal
      (&oar,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE,
          remediation_request, 18, &terminal), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationTerminalKind terminal_kind = 0;
  g_autofree gchar *parsed_remediation = NULL;
  g_assert_true (wyl_service_credential_operation_terminal_reason_parse
      (terminal.terminal_reason, &terminal_kind, &parsed_remediation));
  g_assert_cmpint (terminal_kind, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE);
  g_assert_cmpstr (parsed_remediation, ==, remediation_request);
  assert_handoff_tuple_preserved (&oar, &terminal);
  g_free (terminal.terminal_reason);
  terminal.terminal_reason = g_strdup_printf
      ("terminal.v1:operator-revoke-and-wipe:%s", terminal.request_id);
  g_assert_false (wyl_service_credential_operation_record_is_valid (&terminal));
  wyl_service_credential_operation_record_clear (&terminal);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_terminal
      (&prepared, WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_NOT_COMMITTED,
          NULL, 17, &terminal), ==, WYRELOG_E_OK);
  g_assert_cmpint (terminal.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL);
  g_assert_cmpstr (terminal.terminal_reason, ==, "terminal.v1:not-committed");
  g_assert_true (terminal.successor_credential_id == NULL
      || terminal.successor_credential_id[0] == '\0');
  g_assert_cmpuint (terminal.successor_generation, ==, 0);

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&committed, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN, 19,
          &resumed), ==, WYRELOG_E_POLICY);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&committed, (WylServiceCredentialOperationOarCause) 99, 19,
          &resumed), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_terminal
      (&oar,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE,
          oar.request_id, 19, &resumed), ==, WYRELOG_E_POLICY);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_terminal
      (&oar,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE,
          "not-canonical", 19, &resumed), ==, WYRELOG_E_INVALID);

  g_free (oar.terminal_reason);
  oar.terminal_reason = g_strdup ("receipt-uncertain");
  g_assert_false (wyl_service_credential_operation_record_is_valid (&oar));
  g_free (oar.terminal_reason);
  oar.terminal_reason = g_strdup ("oar.v1:cleanup-required:receipt-uncertain");

  WylServiceCredentialOperationRecord missing_oar =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&committed, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_MISSING, 19,
          &missing_oar), ==, WYRELOG_E_OK);
  g_assert_true (wyl_service_credential_operation_oar_reason_parse
      (missing_oar.terminal_reason, &source, &cause));
  g_assert_cmpint (source, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  g_assert_cmpint (cause, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_MISSING);
  g_assert_cmpstr (missing_oar.terminal_reason, ==,
      "oar.v1:server-committed:escrow-missing");
  g_autoptr (GBytes) missing_oar_bytes = NULL;
  g_autoptr (GBytes) missing_oar_replay_bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode
      (&missing_oar, &missing_oar_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&missing_oar, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_MISSING, 99,
          &resumed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&resumed,
          &missing_oar_replay_bytes), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (missing_oar_bytes, missing_oar_replay_bytes));
  wyl_service_credential_operation_record_clear (&resumed);
  g_autoptr (GBytes) missing_preserved_output = NULL;
  g_autoptr (GBytes) after_missing_denied_resume = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&terminal,
          &missing_preserved_output), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_resume
      (&missing_oar, 20, &terminal), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&terminal,
          &after_missing_denied_resume), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (missing_preserved_output,
          after_missing_denied_resume));
  wyl_service_credential_operation_record_clear (&missing_oar);

  WylServiceCredentialOperationRecord inactive_oar =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_action_required
      (&committed, WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_EXPIRED, 19,
          &inactive_oar), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) preserved_output = NULL;
  g_autoptr (GBytes) after_denied_resume = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&terminal,
          &preserved_output), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_operator_resume
      (&inactive_oar, 20, &terminal), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&terminal,
          &after_denied_resume), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (preserved_output, after_denied_resume));
  wyl_service_credential_operation_record_clear (&inactive_oar);

  wyl_service_credential_operation_record_clear (&terminal);
  wyl_service_credential_operation_record_clear (&resumed);
  wyl_service_credential_operation_record_clear (&oar);
  wyl_service_credential_operation_record_clear (&cleanup);
  wyl_service_credential_operation_record_clear (&published);
  wyl_service_credential_operation_record_clear (&publication);
  wyl_service_credential_operation_record_clear (&planned);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_coordinator_request_clear (&request_value);
}

static void
test_publication_checkpoints_and_operation_lock (JournalFixture *fixture,
    gconstpointer unused)
{
  (void) unused;
  const gchar *successor = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationCoordinatorLock lifecycle =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationCoordinatorLock contender =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) planned_bytes = NULL;
  g_autoptr (GBytes) replay_bytes = NULL;
  g_autoptr (GBytes) prepared_bytes = NULL;
  gboolean replayed = TRUE;

  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 10, NULL, &record), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (&fixture->storage, &fixture->anchor, r.request_id, successor, 1, 11,
          NULL, &record), ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_service_credential_operation_coordinator_lock_acquire
      (&fixture->storage, &fixture->anchor, r.request_id, &lifecycle), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (strlen (lifecycle.child_name.component), <=,
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_MAX_BYTES);
  g_assert_true (g_str_has_prefix (lifecycle.child_name.component,
          "lifecycle-"));
  g_assert_cmpint (wyl_service_credential_operation_coordinator_lock_acquire
      (&fixture->storage, &fixture->anchor, r.request_id, &contender), ==,
      WYRELOG_E_BUSY);
  g_assert_null (contender.native_handle);

  /* The lifecycle lock stays held while checkpoint APIs take their distinct,
   * short-lived journal lock. */
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_publication_planned
      (&fixture->storage, &fixture->anchor, r.request_id, "reservation",
          "stage", "receipt", 12, &replayed, &record), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (record.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED);
  g_assert_cmpstr (record.stage_identity, ==, "");
  record_name (r.request_id, &name);
  g_assert_cmpint (fixture_child_read (fixture, &name, &planned_bytes), ==,
      WYRELOG_E_OK);
  replayed = FALSE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_publication_planned
      (&fixture->storage, &fixture->anchor, r.request_id, "reservation",
          "stage", "receipt", 99, &replayed, &record), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (planned_bytes, replay_bytes));

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_publication_prepared
      (&fixture->storage, &fixture->anchor, r.request_id, "wrong",
          "stage", "stage-id", "receipt", 13, NULL, &record), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&replay_bytes, g_bytes_unref);
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (planned_bytes, replay_bytes));
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_publication_prepared
      (&fixture->storage, &fixture->anchor, r.request_id, "reservation",
          "stage", "stage-id", "receipt", 13, NULL, &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (record.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED);
  g_assert_cmpstr (record.stage_identity, ==, "stage-id");
  g_assert_cmpint (fixture_child_read (fixture, &name, &prepared_bytes), ==,
      WYRELOG_E_OK);
  replayed = FALSE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_publication_prepared
      (&fixture->storage, &fixture->anchor, r.request_id, "reservation",
          "stage", "stage-id", "receipt", 99, &replayed, &record), ==,
      WYRELOG_E_OK);
  g_assert_true (replayed);
  g_clear_pointer (&replay_bytes, g_bytes_unref);
  g_assert_cmpint (fixture_child_read (fixture, &name, &replay_bytes), ==,
      WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (prepared_bytes, replay_bytes));

  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_file_published
      (&fixture->storage, &fixture->anchor, r.request_id, "reservation",
          "stage", "stage-id", "receipt", 14, &replayed, &record), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (record.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED);
  wyl_service_credential_operation_coordinator_lock_release (&fixture->storage,
      &fixture->anchor, &lifecycle);
  g_assert_null (lifecycle.native_handle);
  g_assert_null (lifecycle.child_name.component);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_lock_acquire
      (&fixture->storage, &fixture->anchor, r.request_id, &contender), ==,
      WYRELOG_E_OK);
  wyl_service_credential_operation_coordinator_lock_release (&fixture->storage,
      &fixture->anchor, &contender);

  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&record);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/coordinator/journal/builder", test_builder);
  g_test_add_func ("/coordinator/journal/server-committed-builder",
      test_server_committed_builder);
  g_test_add_func ("/coordinator/journal/fence-classification",
      test_fence_classification);
  g_test_add ("/coordinator/journal/begin-or-replay", JournalFixture, NULL,
      journal_fixture_set_up, test_begin_or_replay, journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/begin-rejects-oversized-destination",
      JournalFixture, NULL, journal_fixture_set_up,
      test_begin_rejects_oversized_destination_before_write,
      journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/begin-or-replay-conflict", JournalFixture,
      NULL, journal_fixture_set_up, test_begin_or_replay_conflict,
      journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/begin-or-replay-malformed", JournalFixture,
      NULL, journal_fixture_set_up, test_begin_or_replay_malformed_fails_closed,
      journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/begin-or-replay-busy", JournalFixture,
      NULL, journal_fixture_set_up, test_begin_or_replay_busy,
      journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/begin-or-replay-noncanonical-request",
      JournalFixture, NULL, journal_fixture_set_up,
      test_begin_or_replay_rejects_noncanonical_request,
      journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/server-committed-checkpoint",
      JournalFixture, NULL, journal_fixture_set_up,
      test_server_committed_checkpoint, journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/server-committed-checkpoint-fails-closed",
      JournalFixture, NULL, journal_fixture_set_up,
      test_server_committed_checkpoint_fails_closed, journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/load-missing-and-noncanonical",
      JournalFixture, NULL, journal_fixture_set_up,
      test_load_missing_and_noncanonical, journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/load-valid-snapshots", JournalFixture,
      NULL, journal_fixture_set_up, test_load_valid_snapshots,
      journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/rotate-expected-generation", JournalFixture,
      NULL, journal_fixture_set_up,
      test_rotate_expected_generation_is_immutable, journal_fixture_tear_down);
  g_test_add ("/coordinator/journal/load-fails-closed", JournalFixture, NULL,
      journal_fixture_set_up, test_load_fails_closed_and_preserves_output,
      journal_fixture_tear_down);
  g_test_add_func ("/coordinator/journal/v5-handoff-lifecycle",
      test_v5_handoff_lifecycle_builders);
  g_test_add ("/coordinator/journal/publication-checkpoints-operation-lock",
      JournalFixture, NULL, journal_fixture_set_up,
      test_publication_checkpoints_and_operation_lock,
      journal_fixture_tear_down);
  return g_test_run ();
}

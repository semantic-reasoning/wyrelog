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
  g_assert_cmpuint (out.successor_generation, ==, 1);
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
      (&prepared, successor, 2, 10, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (committed.successor_generation, ==, 2);
  wyl_service_credential_operation_record_clear (&committed);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, "not-canonical", 2, 10, &committed), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 1, 10, &committed), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_build_server_committed
      (&prepared, successor, 2, 9, &committed), ==, WYRELOG_E_INVALID);
  g_assert_null (committed.operation_id);
  wyl_service_credential_operation_record_clear (&prepared);
  wyl_service_credential_operation_coordinator_request_clear (&rotate);
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
test_begin_or_replay_conflict (JournalFixture *fixture, gconstpointer unused)
{
  (void) unused;
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = FALSE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 1, &replayed, &out), ==,
      WYRELOG_E_OK);
  g_autofree gchar *saved_operation = g_strdup (out.operation_id);
  g_clear_pointer (&r.destination, g_free);
  r.destination = g_strdup ("changed");
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, 2, &replayed, &out), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpstr (out.operation_id, ==, saved_operation);
  g_clear_pointer (&r.destination, g_free);
  r.destination = g_strdup ("record");
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
  g_test_add ("/coordinator/journal/load-fails-closed", JournalFixture, NULL,
      journal_fixture_set_up, test_load_fails_closed_and_preserves_output,
      journal_fixture_tear_down);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include "wyrelog/auth/service-credential-operation-coordinator-journal-private.h"
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
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) bytes = NULL;
  gboolean replayed = TRUE;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, "operation", 10, &replayed,
          &first), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (first.state, ==, WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
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
  g_assert_cmpstr (decoded.operation_id, ==, "operation");
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
      (&fixture->storage, &fixture->anchor, &r, "operation", 99, &replayed,
          &second), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpstr (second.operation_id, ==, first.operation_id);
  g_assert_cmpint (second.created_at_us, ==, first.created_at_us);
  wyl_service_credential_operation_child_name_clear (&name);
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
      (&fixture->storage, &fixture->anchor, &r, "operation", 1, &replayed,
          &out), ==, WYRELOG_E_OK);
  g_autofree gchar *saved_operation = g_strdup (out.operation_id);
  g_clear_pointer (&r.destination, g_free);
  r.destination = g_strdup ("changed");
  g_assert_cmpint (wyl_service_credential_operation_coordinator_begin_or_replay
      (&fixture->storage, &fixture->anchor, &r, "operation", 2, &replayed,
          &out), ==, WYRELOG_E_POLICY);
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
      (&fixture->storage, &fixture->anchor, &r, "operation", 1, NULL, &out),
      ==, WYRELOG_E_POLICY);
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
      (&fixture->storage, &fixture->anchor, &r, "operation", 1, NULL, &out),
      ==, WYRELOG_E_BUSY);
  g_assert_null (out.operation_id);
  fixture_child_unlock (fixture, &name, lock);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/coordinator/journal/builder", test_builder);
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
  return g_test_run ();
}

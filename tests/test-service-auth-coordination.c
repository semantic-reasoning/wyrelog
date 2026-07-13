/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/wyl-handle-private.h"

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  GCancellable *cancellable;
  gboolean acquired;
  gboolean may_release;
  wyrelog_error_t rc;
} LeaseThread;

static void
lease_thread_init (LeaseThread *thread, WylServiceAuthAuthority *authority,
    WylHandle *handle)
{
  g_mutex_init (&thread->mutex);
  g_cond_init (&thread->changed);
  thread->authority = authority;
  thread->handle = handle;
}

static void
lease_thread_clear (LeaseThread *thread)
{
  g_clear_object (&thread->cancellable);
  g_cond_clear (&thread->changed);
  g_mutex_clear (&thread->mutex);
}

static void
wait_for_flag (LeaseThread *thread, gboolean *flag)
{
  g_mutex_lock (&thread->mutex);
  while (!*flag)
    g_cond_wait (&thread->changed, &thread->mutex);
  g_mutex_unlock (&thread->mutex);
}

static gpointer
writer_thread (gpointer data)
{
  LeaseThread *thread = data;
  WylServiceAuthWriteLease *lease = NULL;
  thread->rc = wyl_service_auth_authority_acquire_write (thread->authority,
      thread->handle, thread->cancellable, &lease);
  if (thread->rc != WYRELOG_E_OK)
    return NULL;

  g_mutex_lock (&thread->mutex);
  thread->acquired = TRUE;
  g_cond_broadcast (&thread->changed);
  while (!thread->may_release)
    g_cond_wait (&thread->changed, &thread->mutex);
  g_mutex_unlock (&thread->mutex);

  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
  return NULL;
}

static gpointer
reader_thread (gpointer data)
{
  LeaseThread *thread = data;
  WylServiceAuthReadLease *lease = NULL;
  thread->rc = wyl_service_auth_authority_acquire_read (thread->authority,
      thread->handle, thread->cancellable, &lease);
  if (thread->rc != WYRELOG_E_OK)
    return NULL;

  g_mutex_lock (&thread->mutex);
  thread->acquired = TRUE;
  g_cond_broadcast (&thread->changed);
  while (!thread->may_release)
    g_cond_wait (&thread->changed, &thread->mutex);
  g_mutex_unlock (&thread->mutex);

  g_assert_cmpint (wyl_service_auth_read_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (lease);
  return NULL;
}

static void
wait_for_snapshot (WylServiceAuthAuthority *authority,
    gboolean (*predicate) (const WylServiceAuthAuthoritySnapshot *snapshot))
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  for (;;) {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_service_auth_authority_snapshot (authority, &snapshot);
    if (predicate (&snapshot))
      return;
    g_assert_cmpint (g_get_monotonic_time (), <, deadline);
    g_thread_yield ();
  }
}

static gboolean
writer_is_waiting (const WylServiceAuthAuthoritySnapshot *snapshot)
{
  return snapshot->waiting_writers == 1;
}

static gboolean
    reader_is_waiting_behind_writer
    (const WylServiceAuthAuthoritySnapshot * snapshot)
{
  return snapshot->waiting_writers == 1 && snapshot->waiting_readers == 1;
}

static gboolean
authority_is_closing (const WylServiceAuthAuthoritySnapshot *snapshot)
{
  return snapshot->closing;
}

static WylHandle *
new_handle (void)
{
  return g_object_new (WYL_TYPE_HANDLE, NULL);
}

static void
test_basic_validation_and_reentry (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  g_autoptr (WylHandle) other = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *read = NULL;
  WylServiceAuthReadLease *nested_read = NULL;
  WylServiceAuthWriteLease *upgrade = NULL;

  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &read), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_validate (read, handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_validate (read, other), ==,
      WYRELOG_E_INVALID);
  wyl_service_auth_read_lease_test_corrupt_serial (read);
  g_assert_cmpint (wyl_service_auth_read_lease_validate (read, handle), ==,
      WYRELOG_E_INVALID);
  wyl_service_auth_read_lease_test_corrupt_serial (read);
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &nested_read), ==, WYRELOG_E_BUSY);
  g_assert_null (nested_read);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority,
          handle, NULL, &upgrade), ==, WYRELOG_E_BUSY);
  g_assert_null (upgrade);
  g_assert_cmpint (wyl_service_auth_authority_close (authority), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_service_auth_read_lease_release (read), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_release (read), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_read_lease_validate (read, handle), ==,
      WYRELOG_E_INVALID);
  wyl_service_auth_read_lease_free (read);
}

typedef struct
{
  WylServiceAuthReadLease *lease;
  gboolean free_instead;
  wyrelog_error_t rc;
} WrongThreadRelease;

static gpointer
wrong_thread_release (gpointer data)
{
  WrongThreadRelease *attempt = data;
  if (attempt->free_instead) {
    wyl_service_auth_read_lease_free (attempt->lease);
    attempt->rc = WYRELOG_E_OK;
  } else {
    attempt->rc = wyl_service_auth_read_lease_release (attempt->lease);
  }
  return NULL;
}

static void
test_wrong_thread_release (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthReadLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  WrongThreadRelease attempt = { lease, FALSE, WYRELOG_E_OK };
  g_autoptr (GThread) thread = g_thread_new ("wrong-release",
      wrong_thread_release, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  attempt.free_instead = TRUE;
  thread = g_thread_new ("wrong-free", wrong_thread_release, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_validate (lease, handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (lease);
}

static void
test_rank_inversion_and_write_serial (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *reversed = NULL;

  g_assert_cmpint (wyl_service_auth_rank_enter (handle,
          WYL_SERVICE_AUTH_RANK_REGISTRY), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &reversed), ==, WYRELOG_E_BUSY);
  g_assert_null (reversed);
  g_assert_cmpint (wyl_service_auth_authority_close (authority), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_service_auth_rank_leave (handle,
          WYL_SERVICE_AUTH_RANK_REGISTRY), ==, WYRELOG_E_OK);

  WylServiceAuthWriteLease *write = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority,
          handle, NULL, &write), ==, WYRELOG_E_OK);
  wyl_service_auth_write_lease_test_corrupt_serial (write);
  g_assert_cmpint (wyl_service_auth_write_lease_validate (write, handle), ==,
      WYRELOG_E_INVALID);
  wyl_service_auth_write_lease_test_corrupt_serial (write);
  g_assert_cmpint (wyl_service_auth_write_lease_release (write), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (write);
}

static void
test_waiting_writer_blocks_later_reader (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *first_reader = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &first_reader), ==, WYRELOG_E_OK);

  LeaseThread writer = { 0 };
  LeaseThread reader = { 0 };
  lease_thread_init (&writer, authority, handle);
  lease_thread_init (&reader, authority, handle);
  g_autoptr (GThread) writer_handle = g_thread_new ("waiting-writer",
      writer_thread, &writer);
  wait_for_snapshot (authority, writer_is_waiting);
  g_autoptr (GThread) reader_handle = g_thread_new ("later-reader",
      reader_thread, &reader);
  wait_for_snapshot (authority, reader_is_waiting_behind_writer);

  g_assert_cmpint (wyl_service_auth_read_lease_release (first_reader), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (first_reader);
  wait_for_flag (&writer, &writer.acquired);

  g_mutex_lock (&reader.mutex);
  g_assert_false (reader.acquired);
  g_mutex_unlock (&reader.mutex);

  g_mutex_lock (&writer.mutex);
  writer.may_release = TRUE;
  g_cond_broadcast (&writer.changed);
  g_mutex_unlock (&writer.mutex);
  wait_for_flag (&reader, &reader.acquired);
  g_mutex_lock (&reader.mutex);
  reader.may_release = TRUE;
  g_cond_broadcast (&reader.changed);
  g_mutex_unlock (&reader.mutex);

  g_thread_join (g_steal_pointer (&writer_handle));
  g_thread_join (g_steal_pointer (&reader_handle));
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (reader.rc, ==, WYRELOG_E_OK);
  lease_thread_clear (&reader);
  lease_thread_clear (&writer);
}

static void
test_writer_cancellation_restores_progress (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *reader = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &reader), ==, WYRELOG_E_OK);

  LeaseThread writer = { 0 };
  lease_thread_init (&writer, authority, handle);
  writer.cancellable = g_cancellable_new ();
  g_autoptr (GThread) writer_handle = g_thread_new ("cancelled-writer",
      writer_thread, &writer);
  wait_for_snapshot (authority, writer_is_waiting);
  g_cancellable_cancel (writer.cancellable);
  g_thread_join (g_steal_pointer (&writer_handle));
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_BUSY);

  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot (authority, &snapshot);
  g_assert_cmpuint (snapshot.waiting_writers, ==, 0);
  g_assert_cmpint (wyl_service_auth_read_lease_release (reader), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (reader);

  WylServiceAuthReadLease *next = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &next), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_release (next), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (next);
  lease_thread_clear (&writer);
}

typedef struct
{
  WylServiceAuthAuthority *authority;
  wyrelog_error_t rc;
} CloseThread;

static gpointer
close_thread (gpointer data)
{
  CloseThread *close = data;
  close->rc = wyl_service_auth_authority_close (close->authority);
  return NULL;
}

static void
test_close_wakes_and_drains (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  LeaseThread reader = { 0 };
  LeaseThread writer = { 0 };
  lease_thread_init (&reader, authority, handle);
  lease_thread_init (&writer, authority, handle);
  g_autoptr (GThread) reader_handle = g_thread_new ("closing-reader",
      reader_thread, &reader);
  wait_for_flag (&reader, &reader.acquired);

  g_autoptr (GThread) writer_handle = g_thread_new ("closing-writer",
      writer_thread, &writer);
  wait_for_snapshot (authority, writer_is_waiting);

  CloseThread close = { authority, WYRELOG_E_INTERNAL };
  g_autoptr (GThread) closer = g_thread_new ("closer", close_thread, &close);
  wait_for_snapshot (authority, authority_is_closing);
  WylServiceAuthReadLease *rejected = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &rejected), ==, WYRELOG_E_BUSY);
  g_assert_null (rejected);

  g_mutex_lock (&reader.mutex);
  reader.may_release = TRUE;
  g_cond_broadcast (&reader.changed);
  g_mutex_unlock (&reader.mutex);
  g_thread_join (g_steal_pointer (&reader_handle));
  g_thread_join (g_steal_pointer (&writer_handle));
  g_thread_join (g_steal_pointer (&closer));
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (close.rc, ==, WYRELOG_E_OK);
  lease_thread_clear (&writer);
  lease_thread_clear (&reader);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-auth/lease/basic-validation-reentry",
      test_basic_validation_and_reentry);
  g_test_add_func ("/service-auth/lease/wrong-thread-release",
      test_wrong_thread_release);
  g_test_add_func ("/service-auth/lease/rank-inversion-write-serial",
      test_rank_inversion_and_write_serial);
  g_test_add_func ("/service-auth/authority/writer-preference",
      test_waiting_writer_blocks_later_reader);
  g_test_add_func ("/service-auth/authority/writer-cancellation",
      test_writer_cancellation_restores_progress);
  g_test_add_func ("/service-auth/authority/close-drain",
      test_close_wakes_and_drains);
  return g_test_run ();
}

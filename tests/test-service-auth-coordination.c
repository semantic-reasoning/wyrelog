/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

#define LAST_USED_CREDENTIAL_ID "wlc_000000000000000000000000000"
#define LAST_USED_ABSENT_ID "wlc_000000000000000000000000001"

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  GCancellable *cancellable;
  gboolean acquired;
  gboolean may_release;
  gboolean gated;               /* honor the start gate before acquiring */
  gboolean start_gate;          /* released by the test to launch the acquire */
  gint *order_source;           /* shared counter recording acquisition order */
  gint acquire_order;           /* value observed on acquire; -1 until acquired */
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

static WylHandle *new_handle (void);

static void
terminal_entry_checkpoint (gpointer data)
{
  guint *entries = data;
  (*entries)++;
}

typedef struct
{
  WylServiceAuthReadLease **lease;
  wyrelog_error_t rc;
} WrongThreadTerminal;

static gpointer
wrong_thread_terminal (gpointer data)
{
  WrongThreadTerminal *attempt = data;
  attempt->rc = wyl_service_auth_read_lease_release_terminal (attempt->lease);
  return NULL;
}

static void
finish_writer (LeaseThread *writer, GThread **thread)
{
  g_mutex_lock (&writer->mutex);
  writer->may_release = TRUE;
  g_cond_broadcast (&writer->changed);
  g_mutex_unlock (&writer->mutex);
  g_thread_join (g_steal_pointer (thread));
}

/* Writer variant that records the order in which it wins the lease and then
   releases it immediately, so the acquisition sequence can be asserted without
   any thread having to hold the lease (which would deadlock if a barge stole
   it out of the expected order).  When gated, it parks until the test opens the
   gate so a newcomer can be primed to race a queued writer for a just-freed
   lease. */
static gpointer
ordered_writer_thread (gpointer data)
{
  LeaseThread *thread = data;
  if (thread->gated) {
    g_mutex_lock (&thread->mutex);
    while (!thread->start_gate)
      g_cond_wait (&thread->changed, &thread->mutex);
    g_mutex_unlock (&thread->mutex);
  }

  WylServiceAuthWriteLease *lease = NULL;
  thread->rc = wyl_service_auth_authority_acquire_write (thread->authority,
      thread->handle, thread->cancellable, &lease);
  if (thread->rc != WYRELOG_E_OK)
    return NULL;

  thread->acquire_order = g_atomic_int_add (thread->order_source, 1);
  g_mutex_lock (&thread->mutex);
  thread->acquired = TRUE;
  g_cond_broadcast (&thread->changed);
  g_mutex_unlock (&thread->mutex);

  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
  return NULL;
}

static void
open_gate (LeaseThread *thread)
{
  g_mutex_lock (&thread->mutex);
  thread->start_gate = TRUE;
  g_cond_broadcast (&thread->changed);
  g_mutex_unlock (&thread->mutex);
}

static void
ordered_writer_init (LeaseThread *thread, WylServiceAuthAuthority *authority,
    WylHandle *handle, gint *order_source)
{
  lease_thread_init (thread, authority, handle);
  thread->order_source = order_source;
  thread->acquire_order = -1;
}

static gboolean
two_writers_waiting (const WylServiceAuthAuthoritySnapshot *snapshot)
{
  return snapshot->waiting_writers == 2;
}

static void
test_read_terminal_release_contract (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *lease = NULL;
  guint entries = 0;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &lease), ==, WYRELOG_E_OK);
  wyl_service_auth_read_lease_test_set_terminal_checkpoint (lease,
      terminal_entry_checkpoint, &entries);
  LeaseThread writer = { 0 };
  lease_thread_init (&writer, authority, handle);
  GThread *writer_handle = g_thread_new ("terminal-normal-writer",
      writer_thread, &writer);
  wait_for_snapshot (authority, writer_is_waiting);
  g_assert_cmpint (wyl_service_auth_read_lease_release_terminal (&lease), ==,
      WYRELOG_E_OK);
  g_assert_null (lease);
  g_assert_cmpuint (entries, ==, 1);
  wait_for_flag (&writer, &writer.acquired);
  finish_writer (&writer, &writer_handle);
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_release_terminal (&lease), ==,
      WYRELOG_E_INVALID);
  lease_thread_clear (&writer);
}

static void
assert_terminal_fault_consumes (gboolean corrupt_serial)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *lease = NULL;
  guint entries = 0;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &lease), ==, WYRELOG_E_OK);
  wyl_service_auth_read_lease_test_set_terminal_checkpoint (lease,
      terminal_entry_checkpoint, &entries);
  if (corrupt_serial)
    wyl_service_auth_read_lease_test_corrupt_serial (lease);
  else
    wyl_service_auth_read_lease_test_fail_terminal_prevalidation (lease);
  LeaseThread writer = { 0 };
  lease_thread_init (&writer, authority, handle);
  GThread *writer_handle = g_thread_new ("terminal-fault-writer",
      writer_thread, &writer);
  wait_for_snapshot (authority, writer_is_waiting);
  g_assert_cmpint (wyl_service_auth_read_lease_release_terminal (&lease), ==,
      corrupt_serial ? WYRELOG_E_INVALID : WYRELOG_E_INTERNAL);
  g_assert_null (lease);
  g_assert_cmpuint (entries, ==, 1);
  g_thread_join (writer_handle);
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_BUSY);
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot (authority, &snapshot);
  g_assert_cmpuint (snapshot.active_readers, ==, 0);
  g_assert_cmpuint (snapshot.waiting_writers, ==, 0);
  g_assert_false (snapshot.writer_active);
  g_assert_cmpint (wyl_service_auth_rank_enter (handle,
          WYL_SERVICE_AUTH_RANK_COORDINATION), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_rank_leave (handle,
          WYL_SERVICE_AUTH_RANK_COORDINATION), ==, WYRELOG_E_OK);
  lease_thread_clear (&writer);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
}

static void
test_read_terminal_release_faults (void)
{
  assert_terminal_fault_consumes (FALSE);
  assert_terminal_fault_consumes (TRUE);
}

static void
test_read_terminal_release_wrong_thread (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *lease = NULL;
  guint entries = 0;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &lease), ==, WYRELOG_E_OK);
  wyl_service_auth_read_lease_test_set_terminal_checkpoint (lease,
      terminal_entry_checkpoint, &entries);
  WrongThreadTerminal attempt = {
    .lease = &lease,.rc = WYRELOG_E_OK,
  };
  g_autoptr (GThread) thread = g_thread_new ("wrong-terminal-owner",
      wrong_thread_terminal, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  g_assert_nonnull (lease);
  g_assert_cmpuint (entries, ==, 1);
  g_assert_cmpint (wyl_service_auth_read_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (lease);
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

static WylHandle *
new_store_handle (void)
{
  WylHandle *handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  return handle;
}

static gint64
sqlite_scalar (sqlite3 *db, const gchar *sql)
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
sqlite_exec_ok (sqlite3 *db, const gchar *sql)
{
  g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
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
  WylHandle *handle;
  wyl_policy_store_t *store;
  wyrelog_error_t rc;
} ReadStoreAttempt;

static gpointer
read_store_wrong_thread (gpointer data)
{
  ReadStoreAttempt *attempt = data;
  attempt->store = (wyl_policy_store_t *) attempt;
  attempt->rc = wyl_service_auth_read_lease_get_policy_store (attempt->lease,
      attempt->handle, &attempt->store);
  return NULL;
}

static void
pin_checkpoint_count (gpointer data)
{
  guint *count = data;
  (*count)++;
}

static void
test_read_lease_pinned_policy_store (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  g_autoptr (WylHandle) other = new_store_handle ();
  WylServiceAuthReadLease *lease = NULL;
  wyl_policy_store_t *store = (wyl_policy_store_t *) handle;

  g_assert_cmpint (wyl_service_auth_read_lease_get_policy_store (NULL, handle,
          &store), ==, WYRELOG_E_INVALID);
  g_assert_null (store);
  g_assert_cmpint (wyl_service_auth_authority_acquire_read
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);

  guint pin_checkpoints = 0;
  wyl_handle_policy_store_set_pin_checkpoint (handle, pin_checkpoint_count,
      &pin_checkpoints);
  g_assert_cmpint (wyl_service_auth_read_lease_get_policy_store (lease, handle,
          &store), ==, WYRELOG_E_OK);
  g_assert_nonnull (store);
  g_assert_true (store == wyl_handle_get_policy_store (handle));
  wyl_policy_store_t *same_store = NULL;
  g_assert_cmpint (wyl_service_auth_read_lease_get_policy_store (lease, handle,
          &same_store), ==, WYRELOG_E_OK);
  g_assert_true (same_store == store);
  g_assert_cmpuint (pin_checkpoints, ==, 0);

  same_store = store;
  g_assert_cmpint (wyl_service_auth_read_lease_get_policy_store (lease, other,
          &same_store), ==, WYRELOG_E_INVALID);
  g_assert_null (same_store);

  wyl_policy_store_t *saved =
      wyl_service_auth_read_lease_test_swap_pinned_store (lease, NULL);
  g_assert_true (saved == store);
  same_store = store;
  g_assert_cmpint (wyl_service_auth_read_lease_get_policy_store (lease, handle,
          &same_store), ==, WYRELOG_E_INVALID);
  g_assert_null (same_store);
  g_assert_null (wyl_service_auth_read_lease_test_swap_pinned_store (lease,
          saved));

  wyl_service_auth_read_lease_test_corrupt_serial (lease);
  same_store = store;
  g_assert_cmpint (wyl_service_auth_read_lease_get_policy_store (lease, handle,
          &same_store), ==, WYRELOG_E_INVALID);
  g_assert_null (same_store);
  wyl_service_auth_read_lease_test_corrupt_serial (lease);

  ReadStoreAttempt attempt = { lease, handle, NULL, WYRELOG_E_OK };
  g_autoptr (GThread) thread = g_thread_new ("wrong-read-store",
      read_store_wrong_thread, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  g_assert_null (attempt.store);

  wyl_policy_store_t *extra_pin = NULL;
  g_assert_cmpint (wyl_handle_policy_store_pin_current (handle, &extra_pin), ==,
      WYRELOG_E_OK);
  g_assert_true (extra_pin == store);
  g_assert_cmpuint (pin_checkpoints, ==, 1);
  wyl_handle_policy_store_unpin (handle, extra_pin);

  g_assert_cmpint (wyl_service_auth_read_lease_release (lease), ==,
      WYRELOG_E_OK);
  same_store = store;
  g_assert_cmpint (wyl_service_auth_read_lease_get_policy_store (lease, handle,
          &same_store), ==, WYRELOG_E_INVALID);
  g_assert_null (same_store);
  wyl_service_auth_read_lease_free (lease);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_shutdown_ordered (other), ==, WYRELOG_E_OK);
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

typedef struct
{
  WylHandle *handle;
  wyrelog_error_t rc;
} HandleShutdownThread;

static gpointer
close_thread (gpointer data)
{
  CloseThread *close = data;
  close->rc = wyl_service_auth_authority_close (close->authority);
  return NULL;
}

typedef struct
{
  WylServiceAuthWriteLease *lease;
  WylHandle *handle;
  wyrelog_error_t rc;
} TerminalizeThread;

static gpointer
terminalize_thread (gpointer data)
{
  TerminalizeThread *terminal = data;
  terminal->rc = wyl_service_auth_write_lease_terminalize_cleanup
      (terminal->lease, terminal->handle);
  return NULL;
}

static void
test_terminalize_cleanup_exact_token (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  g_autoptr (WylHandle) other = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (authority, handle, NULL, &lease), ==, WYRELOG_E_OK);

  wyl_service_auth_write_lease_test_corrupt_serial (lease);
  g_assert_cmpint (wyl_service_auth_write_lease_terminalize_cleanup
      (lease, handle), ==, WYRELOG_E_INVALID);
  wyl_service_auth_write_lease_test_corrupt_serial (lease);
  g_assert_cmpint (wyl_service_auth_write_lease_terminalize_cleanup
      (lease, other), ==, WYRELOG_E_INVALID);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (authority, handle, &reason), ==, WYRELOG_E_OK);

  TerminalizeThread terminal = { lease, handle, WYRELOG_E_OK };
  g_autoptr (GThread) wrong_owner = g_thread_new ("wrong-terminal-owner",
      terminalize_thread, &terminal);
  g_thread_join (g_steal_pointer (&wrong_owner));
  g_assert_cmpint (terminal.rc, ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (authority, handle, &reason), ==, WYRELOG_E_OK);

  CloseThread close = { authority, WYRELOG_E_INTERNAL };
  g_autoptr (GThread) closer = g_thread_new ("terminal-close", close_thread,
      &close);
  wait_for_snapshot (authority, authority_is_closing);
  g_assert_cmpint (wyl_service_auth_write_lease_terminalize_cleanup
      (lease, handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (authority, handle, &reason), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
  g_thread_join (g_steal_pointer (&closer));
  g_assert_cmpint (close.rc, ==, WYRELOG_E_OK);
}

static gpointer
handle_shutdown_thread (gpointer data)
{
  HandleShutdownThread *shutdown = data;
  shutdown->rc = wyl_handle_shutdown_ordered (shutdown->handle);
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

/* A writer that queues before the lease is freed must win it ahead of a
   writer that only arrives after the release, no matter which of the two
   reaches the authority mutex first. */
static void
test_writer_no_barge_after_write_release (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  gint order = 0;

  WylServiceAuthWriteLease *holder = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority, handle,
          NULL, &holder), ==, WYRELOG_E_OK);

  LeaseThread queued = { 0 };
  ordered_writer_init (&queued, authority, handle, &order);
  GThread *queued_handle = g_thread_new ("no-barge-queued",
      ordered_writer_thread, &queued);
  wait_for_snapshot (authority, writer_is_waiting);

  LeaseThread newcomer = { 0 };
  ordered_writer_init (&newcomer, authority, handle, &order);
  newcomer.gated = TRUE;
  GThread *newcomer_handle = g_thread_new ("no-barge-newcomer",
      ordered_writer_thread, &newcomer);

  /* Free the lease, then immediately release the primed newcomer so it races
     the queued writer for the just-freed lease.  Both writers record their
     order and self-release, so the sequence resolves regardless of who wins. */
  g_assert_cmpint (wyl_service_auth_write_lease_release (holder), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (holder);
  open_gate (&newcomer);

  g_thread_join (g_steal_pointer (&queued_handle));
  g_thread_join (g_steal_pointer (&newcomer_handle));

  g_assert_cmpint (queued.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (newcomer.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (queued.acquire_order, ==, 0);
  g_assert_cmpint (newcomer.acquire_order, ==, 1);

  lease_thread_clear (&queued);
  lease_thread_clear (&newcomer);
}

/* Same guarantee when the lease is freed by the last reader draining rather
   than by a writer releasing. */
static void
test_writer_no_barge_after_reader_drain (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  gint order = 0;

  WylServiceAuthReadLease *reader = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &reader), ==, WYRELOG_E_OK);

  LeaseThread queued = { 0 };
  ordered_writer_init (&queued, authority, handle, &order);
  GThread *queued_handle = g_thread_new ("drain-queued",
      ordered_writer_thread, &queued);
  wait_for_snapshot (authority, writer_is_waiting);

  LeaseThread newcomer = { 0 };
  ordered_writer_init (&newcomer, authority, handle, &order);
  newcomer.gated = TRUE;
  GThread *newcomer_handle = g_thread_new ("drain-newcomer",
      ordered_writer_thread, &newcomer);

  g_assert_cmpint (wyl_service_auth_read_lease_release (reader), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (reader);
  open_gate (&newcomer);

  g_thread_join (g_steal_pointer (&queued_handle));
  g_thread_join (g_steal_pointer (&newcomer_handle));

  g_assert_cmpint (queued.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (newcomer.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (queued.acquire_order, ==, 0);
  g_assert_cmpint (newcomer.acquire_order, ==, 1);

  lease_thread_clear (&queued);
  lease_thread_clear (&newcomer);
}

/* Same guarantee when the last reader drains through the terminal release path
   (production-reachable via the daemon bearer resolver), not just the ordinary
   read release. */
static void
test_writer_no_barge_after_terminal_drain (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  gint order = 0;

  WylServiceAuthReadLease *reader = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &reader), ==, WYRELOG_E_OK);

  LeaseThread queued = { 0 };
  ordered_writer_init (&queued, authority, handle, &order);
  GThread *queued_handle = g_thread_new ("terminal-drain-queued",
      ordered_writer_thread, &queued);
  wait_for_snapshot (authority, writer_is_waiting);

  LeaseThread newcomer = { 0 };
  ordered_writer_init (&newcomer, authority, handle, &order);
  newcomer.gated = TRUE;
  GThread *newcomer_handle = g_thread_new ("terminal-drain-newcomer",
      ordered_writer_thread, &newcomer);

  /* A successful terminal drain of the last reader must reserve the freed
     lease for the queued writer, exactly like the ordinary read release. */
  g_assert_cmpint (wyl_service_auth_read_lease_release_terminal (&reader), ==,
      WYRELOG_E_OK);
  g_assert_null (reader);
  open_gate (&newcomer);

  g_thread_join (g_steal_pointer (&queued_handle));
  g_thread_join (g_steal_pointer (&newcomer_handle));

  g_assert_cmpint (queued.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (newcomer.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (queued.acquire_order, ==, 0);
  g_assert_cmpint (newcomer.acquire_order, ==, 1);

  lease_thread_clear (&queued);
  lease_thread_clear (&newcomer);
}

/* A writer that cancels mid-wait must not leave a reservation that stalls a
   later writer. */
static void
test_writer_cancel_does_not_strand_reservation (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  gint order = 0;

  WylServiceAuthWriteLease *holder = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority, handle,
          NULL, &holder), ==, WYRELOG_E_OK);

  LeaseThread cancelled = { 0 };
  ordered_writer_init (&cancelled, authority, handle, &order);
  cancelled.cancellable = g_cancellable_new ();
  GThread *cancelled_handle = g_thread_new ("cancel-queued",
      ordered_writer_thread, &cancelled);
  wait_for_snapshot (authority, writer_is_waiting);

  g_cancellable_cancel (cancelled.cancellable);
  g_thread_join (g_steal_pointer (&cancelled_handle));
  g_assert_cmpint (cancelled.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (cancelled.acquire_order, ==, -1);

  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot (authority, &snapshot);
  g_assert_cmpuint (snapshot.waiting_writers, ==, 0);

  g_assert_cmpint (wyl_service_auth_write_lease_release (holder), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (holder);

  LeaseThread later = { 0 };
  ordered_writer_init (&later, authority, handle, &order);
  GThread *later_handle = g_thread_new ("cancel-later", ordered_writer_thread,
      &later);
  g_thread_join (g_steal_pointer (&later_handle));
  g_assert_cmpint (later.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (later.acquire_order, ==, 0);

  lease_thread_clear (&cancelled);
  lease_thread_clear (&later);
}

/* Closing an authority with writers queued must wake every queued writer with
   WYRELOG_E_BUSY and let the drain complete; the reservation must never keep a
   waiter parked. */
static void
test_close_drains_queued_writers (void)
{
  g_autoptr (WylHandle) handle = new_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  gint order = 0;

  LeaseThread holder = { 0 };
  lease_thread_init (&holder, authority, handle);
  GThread *holder_handle = g_thread_new ("close-holder", reader_thread,
      &holder);
  wait_for_flag (&holder, &holder.acquired);

  LeaseThread first = { 0 };
  LeaseThread second = { 0 };
  ordered_writer_init (&first, authority, handle, &order);
  ordered_writer_init (&second, authority, handle, &order);
  GThread *first_handle = g_thread_new ("close-writer-1",
      ordered_writer_thread, &first);
  GThread *second_handle = g_thread_new ("close-writer-2",
      ordered_writer_thread, &second);
  wait_for_snapshot (authority, two_writers_waiting);

  CloseThread close = { authority, WYRELOG_E_INTERNAL };
  GThread *closer = g_thread_new ("close-drain", close_thread, &close);
  wait_for_snapshot (authority, authority_is_closing);

  g_mutex_lock (&holder.mutex);
  holder.may_release = TRUE;
  g_cond_broadcast (&holder.changed);
  g_mutex_unlock (&holder.mutex);

  g_thread_join (g_steal_pointer (&first_handle));
  g_thread_join (g_steal_pointer (&second_handle));
  g_thread_join (g_steal_pointer (&holder_handle));
  g_thread_join (g_steal_pointer (&closer));

  g_assert_cmpint (first.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (second.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (first.acquire_order, ==, -1);
  g_assert_cmpint (second.acquire_order, ==, -1);
  g_assert_cmpint (close.rc, ==, WYRELOG_E_OK);

  lease_thread_clear (&holder);
  lease_thread_clear (&first);
  lease_thread_clear (&second);
}

static void
test_handle_shutdown_wakes_queued_leases_and_drains_pins (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *holder = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority,
          handle, NULL, &holder), ==, WYRELOG_E_OK);

  /* An owner must not transition its own authority into CLOSING. */
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_BUSY);
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot (authority, &snapshot);
  g_assert_false (snapshot.closing);

  LeaseThread reader = { 0 };
  LeaseThread writer = { 0 };
  lease_thread_init (&reader, authority, handle);
  lease_thread_init (&writer, authority, handle);
  g_autoptr (GThread) reader_handle = g_thread_new ("queued-reader",
      reader_thread, &reader);
  g_autoptr (GThread) writer_handle = g_thread_new ("queued-writer",
      writer_thread, &writer);
  wait_for_snapshot (authority, reader_is_waiting_behind_writer);

  /* Both waiters have already pinned the store before joining the queue. */
  HandleShutdownThread shutdown = { handle, WYRELOG_E_INTERNAL };
  g_autoptr (GThread) shutdown_handle = g_thread_new ("handle-shutdown",
      handle_shutdown_thread, &shutdown);
  wait_for_snapshot (authority, authority_is_closing);
  g_assert_true (wyl_handle_get_policy_store (handle) == store);

  g_thread_join (g_steal_pointer (&reader_handle));
  g_thread_join (g_steal_pointer (&writer_handle));
  g_assert_cmpint (reader.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_BUSY);
  g_assert_true (wyl_handle_get_policy_store (handle) == store);

  g_assert_cmpint (wyl_service_auth_write_lease_release (holder), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (holder);
  g_thread_join (g_steal_pointer (&shutdown_handle));
  g_assert_cmpint (shutdown.rc, ==, WYRELOG_E_OK);
  g_assert_null (wyl_handle_get_policy_store (handle));

  WylServiceAuthReadLease *rejected = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &rejected), ==, WYRELOG_E_BUSY);
  g_assert_null (rejected);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  lease_thread_clear (&writer);
  lease_thread_clear (&reader);
}

typedef struct
{
  WylServiceAuthWriteLease *lease;
  WylHandle *handle;
  WylServiceAuthUnavailableReason reason;
  wyrelog_error_t rc;
} UnavailableSetterThread;

static gpointer
unavailable_setter_thread (gpointer data)
{
  UnavailableSetterThread *setter = data;
  setter->rc = wyl_service_auth_write_lease_mark_unavailable (setter->lease,
      setter->handle, setter->reason);
  return NULL;
}

static void
test_unavailable_latch_validation_wakes_waiters_and_first_reason_wins (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  g_autoptr (WylHandle) other = new_store_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthWriteLease *owner = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority,
          handle, NULL, &owner), ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (NULL,
          handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (owner,
          other, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (owner,
          handle, WYL_SERVICE_AUTH_UNAVAILABLE_NONE), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (owner,
          handle, 99), ==, WYRELOG_E_INVALID);
  WylServiceAuthUnavailableReason invalid_reason =
      WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT;
  g_assert_cmpint (wyl_service_auth_authority_validate_available (authority,
          other, &invalid_reason), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (invalid_reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_NONE);
  g_assert_cmpint (wyl_service_auth_authority_validate_available (authority,
          handle, NULL), ==, WYRELOG_E_INVALID);

  UnavailableSetterThread wrong_thread = {
    owner,
    handle,
    WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT,
    WYRELOG_E_OK,
  };
  g_autoptr (GThread) wrong = g_thread_new ("wrong-unavailable-owner",
      unavailable_setter_thread, &wrong_thread);
  g_thread_join (g_steal_pointer (&wrong));
  g_assert_cmpint (wrong_thread.rc, ==, WYRELOG_E_INVALID);

  LeaseThread reader = { 0 };
  LeaseThread writer = { 0 };
  lease_thread_init (&reader, authority, handle);
  lease_thread_init (&writer, authority, handle);
  g_autoptr (GThread) queued_reader = g_thread_new ("unavailable-reader",
      reader_thread, &reader);
  g_autoptr (GThread) queued_writer = g_thread_new ("unavailable-writer",
      writer_thread, &writer);
  wait_for_snapshot (authority, reader_is_waiting_behind_writer);

  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (owner,
          handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (owner,
          handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INDEX_CONFLICT), ==,
      WYRELOG_E_BUSY);

  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available (authority,
          handle, &reason), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT);
  g_thread_join (g_steal_pointer (&queued_reader));
  g_thread_join (g_steal_pointer (&queued_writer));
  g_assert_cmpint (reader.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_BUSY);

  /* The owner remains valid solely to finish cleanup and release. */
  g_assert_cmpint (wyl_service_auth_write_lease_validate (owner, handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_validate_operation (owner,
          handle), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_service_auth_write_lease_release (owner), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (owner);

  WylServiceAuthReadLease *new_reader = NULL;
  WylServiceAuthWriteLease *new_writer = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &new_reader), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority,
          handle, NULL, &new_writer), ==, WYRELOG_E_BUSY);
  g_assert_null (new_reader);
  g_assert_null (new_writer);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  lease_thread_clear (&writer);
  lease_thread_clear (&reader);
}

typedef struct
{
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  wyrelog_error_t acquire_rc;
  wyrelog_error_t mark_rc;
} MarkAfterRead;

static gpointer
mark_after_read_thread (gpointer data)
{
  MarkAfterRead *mark = data;
  WylServiceAuthWriteLease *lease = NULL;
  mark->acquire_rc = wyl_service_auth_authority_acquire_write
      (mark->authority, mark->handle, NULL, &lease);
  if (mark->acquire_rc == WYRELOG_E_OK) {
    mark->mark_rc = wyl_service_auth_write_lease_mark_unavailable (lease,
        mark->handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INDEX_CONFLICT);
    g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
        WYRELOG_E_OK);
    wyl_service_auth_write_lease_free (lease);
  }
  return NULL;
}

static void
test_unavailable_latch_serializes_after_acquired_read (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthReadLease *reader = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read (authority, handle,
          NULL, &reader), ==, WYRELOG_E_OK);

  MarkAfterRead mark = {
    authority,
    handle,
    WYRELOG_E_INTERNAL,
    WYRELOG_E_INTERNAL,
  };
  g_autoptr (GThread) marker = g_thread_new ("mark-after-read",
      mark_after_read_thread, &mark);
  wait_for_snapshot (authority, writer_is_waiting);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available (authority,
          handle, &reason), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_read_lease_release (reader), ==,
      WYRELOG_E_OK);
  wyl_service_auth_read_lease_free (reader);
  g_thread_join (g_steal_pointer (&marker));
  g_assert_cmpint (mark.acquire_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (mark.mark_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_authority_validate_available (authority,
          handle, &reason), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INDEX_CONFLICT);
}

typedef struct
{
  guint fill_random_calls;
} UnavailableCoreRuntime;

static int
unavailable_core_fill_random (gpointer data, guint8 *out, gsize len)
{
  UnavailableCoreRuntime *runtime = data;
  runtime->fill_random_calls++;
  memset (out, 0x5a, len);
  return 0;
}

static void
    test_unavailable_latch_rejects_active_transaction_core_before_side_effects
    (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (sqlite_scalar (wyl_policy_store_get_db (store),
          "PRAGMA busy_timeout;"), ==, 0);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  const gchar *tables[] = {
    "service_principals",
    "service_credentials",
    "service_principal_events",
    "service_credential_events",
    "service_domain_requests",
    "audit_events",
  };
  gint64 before[G_N_ELEMENTS (tables)];
  for (guint i = 0; i < G_N_ELEMENTS (tables); i++) {
    g_autofree gchar *sql = g_strdup_printf ("SELECT count(*) FROM %s;",
        tables[i]);
    before[i] = sqlite_scalar (db, sql);
  }

  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (lease,
          handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT), ==,
      WYRELOG_E_OK);
  UnavailableCoreRuntime runtime_state = { 0 };
  wyl_service_credential_runtime_t runtime = {
    .fill_random = unavailable_core_fill_random,
    .data = &runtime_state,
  };
  guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES] = { 0 };
  wyl_policy_service_credential_info_t credential = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (wyl_policy_store_issue_service_credential_core (txn,
          store, "svc:unavailable:core", "__wr_default", "admin",
          "unavailable-core", 0, &runtime, cvk, sizeof cvk, &credential,
          &secret), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (runtime_state.fill_random_calls, ==, 0);
  g_assert_null (credential.credential_id);
  g_assert_null (secret);
  for (guint i = 0; i < G_N_ELEMENTS (tables); i++) {
    g_autofree gchar *sql = g_strdup_printf ("SELECT count(*) FROM %s;",
        tables[i]);
    g_assert_cmpint (sqlite_scalar (db, sql), ==, before[i]);
  }

  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_unavailable_latch_fresh_handle_and_close_interaction (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  WylServiceAuthUnavailableReason reason =
      WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT;
  g_assert_cmpint (wyl_service_auth_authority_validate_available (authority,
          handle, &reason), ==, WYRELOG_E_OK);
  g_assert_cmpint (reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_NONE);

  WylServiceAuthWriteLease *owner = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write (authority,
          handle, NULL, &owner), ==, WYRELOG_E_OK);
  HandleShutdownThread shutdown = { handle, WYRELOG_E_INTERNAL };
  g_autoptr (GThread) closer = g_thread_new ("close-before-unavailable",
      handle_shutdown_thread, &shutdown);
  wait_for_snapshot (authority, authority_is_closing);
  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (owner,
          handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_service_auth_write_lease_release (owner), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (owner);
  g_thread_join (g_steal_pointer (&closer));
  g_assert_cmpint (shutdown.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_authority_validate_available (authority,
          handle, &reason), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_NONE);
}

static void
test_authority_transaction_commit_and_claim (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);

  g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_get_state
      (txn), ==, WYL_SERVICE_AUTHORITY_TXN_ACTIVE);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_abort (txn),
      ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_BUSY);
  wyl_policy_service_principal_info_t reentrant = { 0 };
  g_assert_cmpint (wyl_policy_store_create_service_principal (store,
          "svc:reentrant:test", "reentrant", "admin", "reentrant-request",
          &reentrant), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_service_auth_rank_enter (handle,
          WYL_SERVICE_AUTH_RANK_REGISTRY), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_rank_leave (handle,
          WYL_SERVICE_AUTH_RANK_REGISTRY), ==, WYRELOG_E_OK);
  WylServiceAuthorityTransaction *nested = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &nested), ==, WYRELOG_E_BUSY);
  g_assert_null (nested);

  sqlite_exec_ok (db, "PRAGMA user_version = 11;");
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_get_state
      (txn), ==, WYL_SERVICE_AUTHORITY_TXN_COMMITTED);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_primary_result (txn),
      ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_cleanup_result (txn),
      ==, WYRELOG_E_OK);
  g_assert_true (sqlite3_get_autocommit (db));
  g_assert_cmpint (sqlite_scalar (db, "PRAGMA user_version;"), ==, 11);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_authority_transaction_rollback_and_cleanup (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);

  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  sqlite_exec_ok (db, "PRAGMA user_version = 19;");
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_get_state
      (txn), ==, WYL_SERVICE_AUTHORITY_TXN_ROLLED_BACK);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_true (sqlite3_get_autocommit (db));
  g_assert_cmpint (sqlite_scalar (db, "PRAGMA user_version;"), ==, 0);

  txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  sqlite_exec_ok (db, "PRAGMA user_version = 23;");
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_true (sqlite3_get_autocommit (db));
  g_assert_cmpint (sqlite_scalar (db, "PRAGMA user_version;"), ==, 0);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_authority_transaction_rejects_outer_transaction (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  sqlite_exec_ok (db, "BEGIN;");
  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_BUSY);
  g_assert_null (txn);
  sqlite_exec_ok (db, "ROLLBACK;");
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

typedef struct
{
  wyl_policy_store_t *store;
  WylHandle *handle;
  WylServiceAuthWriteLease *lease;
  wyrelog_error_t rc;
} TransactionBeginThread;

static gpointer
wrong_thread_transaction_begin (gpointer data)
{
  TransactionBeginThread *attempt = data;
  WylServiceAuthorityTransaction *txn = NULL;
  attempt->rc = wyl_policy_store_service_authority_transaction_begin
      (attempt->store, attempt->handle, attempt->lease, &txn);
  g_assert_null (txn);
  return NULL;
}

static void
test_authority_transaction_rejects_wrong_owner (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  g_autoptr (WylHandle) other = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);

  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (wyl_handle_get_policy_store (other), other, lease, &txn), ==,
      WYRELOG_E_INVALID);
  g_assert_null (txn);

  TransactionBeginThread attempt = { store, handle, lease, WYRELOG_E_OK };
  g_autoptr (GThread) thread = g_thread_new ("wrong-txn-owner",
      wrong_thread_transaction_begin, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_authority_transaction_release_faults (void)
{
  const WylPolicyAuthorityTransactionFailStage stages[] = {
    WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER,
  };
  for (guint i = 0; i < G_N_ELEMENTS (stages); i++) {
    g_autoptr (WylHandle) handle = new_store_handle ();
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    sqlite3 *db = wyl_policy_store_get_db (store);
    WylServiceAuthWriteLease *lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_write
        (wyl_handle_get_service_auth_authority (handle), handle, NULL,
            &lease), ==, WYRELOG_E_OK);
    wyl_policy_store_service_authority_transaction_fail_once (store, stages[i]);
    g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
        (store, handle, lease, &txn), ==, WYRELOG_E_OK);
    sqlite_exec_ok (db, "PRAGMA user_version = 29;");
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
        (txn), ==, WYRELOG_E_IO);
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_get_state
        (txn), ==, WYL_SERVICE_AUTHORITY_TXN_FAILED_COMMIT);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_get_primary_result
        (txn), ==, WYRELOG_E_IO);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_get_cleanup_result
        (txn), ==, WYRELOG_E_OK);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_get_primary_sqlite_extended_error
        (txn), ==,
        stages[i] == WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE
        ? SQLITE_AUTH : SQLITE_OK);
    g_assert_true (sqlite3_get_autocommit (db));
    g_assert_false (wyl_policy_store_service_authority_transaction_is_poisoned
        (store));
    g_assert_cmpint (sqlite_scalar (db, "PRAGMA user_version;"), ==,
        stages[i] == WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER ? 29 : 0);
    g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
        WYRELOG_E_OK);
    wyl_service_auth_write_lease_free (lease);
  }
}

static void
test_authority_transaction_poison_on_failed_rollback (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_fail_once (store,
      WYL_POLICY_AUTHORITY_TXN_FAIL_ROLLBACK);
  g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_get_state
      (txn), ==, WYL_SERVICE_AUTHORITY_TXN_FAILED_ROLLBACK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_cleanup_result (txn),
      ==, WYRELOG_E_IO);
  g_assert_false (sqlite3_get_autocommit (db));
  g_assert_true (wyl_policy_store_service_authority_transaction_is_poisoned
      (store));
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_BUSY);
  wyl_policy_service_principal_info_t rejected = { 0 };
  g_assert_cmpint (wyl_policy_store_create_service_principal (store,
          "svc:poison:test", "poison", "admin", "poison-request",
          &rejected), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_abort (txn),
      ==, WYRELOG_E_OK);
  g_assert_true (sqlite3_get_autocommit (db));
  g_assert_false (wyl_policy_store_service_authority_transaction_is_poisoned
      (store));
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylHandle *handle;
  wyl_policy_store_t *store;
  gboolean shutdown_started;
  gboolean transaction_started;
  gboolean finish_transaction;
  wyrelog_error_t begin_rc;
  wyrelog_error_t rollback_rc;
} PinShutdownRace;

static gpointer
pin_shutdown_begin_thread (gpointer data)
{
  PinShutdownRace *race = data;
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (race->handle), race->handle,
          NULL, &lease), ==, WYRELOG_E_OK);
  WylServiceAuthorityTransaction *txn = NULL;
  race->begin_rc = wyl_policy_store_service_authority_transaction_begin
      (race->store, race->handle, lease, &txn);

  g_mutex_lock (&race->mutex);
  race->transaction_started = TRUE;
  g_cond_broadcast (&race->changed);
  while (!race->finish_transaction)
    g_cond_wait (&race->changed, &race->mutex);
  g_mutex_unlock (&race->mutex);

  if (race->begin_rc == WYRELOG_E_OK)
    race->rollback_rc =
        wyl_policy_store_service_authority_transaction_rollback (txn);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
  wyl_policy_store_service_authority_transaction_free (txn);
  return NULL;
}

static gpointer
pin_shutdown_thread (gpointer data)
{
  PinShutdownRace *race = data;
  g_mutex_lock (&race->mutex);
  race->shutdown_started = TRUE;
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
  wyl_shutdown (race->handle);
  return NULL;
}

static void
test_authority_transaction_pin_precedes_shutdown (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  PinShutdownRace race = {
    .handle = handle,
    .store = wyl_handle_get_policy_store (handle),
    .begin_rc = WYRELOG_E_INTERNAL,
    .rollback_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);

  g_autoptr (GThread) begin = g_thread_new ("pin-before-shutdown",
      pin_shutdown_begin_thread, &race);
  g_mutex_lock (&race.mutex);
  while (!race.transaction_started)
    g_cond_wait (&race.changed, &race.mutex);
  g_assert_cmpint (race.begin_rc, ==, WYRELOG_E_OK);
  g_mutex_unlock (&race.mutex);

  g_autoptr (GThread) shutdown = g_thread_new ("shutdown-after-pin",
      pin_shutdown_thread, &race);
  g_mutex_lock (&race.mutex);
  while (!race.shutdown_started)
    g_cond_wait (&race.changed, &race.mutex);
  g_mutex_unlock (&race.mutex);

  wait_for_snapshot (wyl_handle_get_service_auth_authority (handle),
      authority_is_closing);
  g_mutex_lock (&race.mutex);
  g_assert_true (wyl_handle_get_policy_store (handle) == race.store);
  race.finish_transaction = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&begin));
  g_thread_join (g_steal_pointer (&shutdown));

  g_assert_cmpint (race.rollback_rc, ==, WYRELOG_E_OK);
  g_assert_null (wyl_handle_get_policy_store (handle));
  wyl_policy_store_t *rejected = NULL;
  g_assert_cmpint (wyl_handle_policy_store_pin_current (handle, &rejected), ==,
      WYRELOG_E_BUSY);
  g_assert_null (rejected);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
}

typedef struct
{
  sqlite3 *db;
  int rc;
  int matrix_rc[5];
} ConcurrentCommit;

static gpointer
concurrent_commit_thread (gpointer data)
{
  ConcurrentCommit *commit = data;
  commit->rc = sqlite3_exec (commit->db, "COMMIT;", NULL, NULL, NULL);
  return NULL;
}

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  ConcurrentCommit *commit;
} AbortBarrierObserver;

static gpointer
abort_barrier_observer_thread (gpointer data)
{
  AbortBarrierObserver *observer = data;
  wyl_policy_store_service_authority_transaction_abort_barrier_wait
      (observer->txn);
  concurrent_commit_thread (observer->commit);
  const gchar *sql[] = {
    "SELECT 1;", "CREATE TABLE poison_probe(x);", "SAVEPOINT poison_probe;",
    "PRAGMA user_version;", "ROLLBACK;",
  };
  for (guint i = 0; i < G_N_ELEMENTS (sql); i++)
    observer->commit->matrix_rc[i] = sqlite3_exec (observer->commit->db,
        sql[i], NULL, NULL, NULL);
  wyl_policy_store_service_authority_transaction_abort_barrier_release
      (observer->txn);
  return NULL;
}

static void
test_authority_transaction_preserves_commit_cleanup_failure (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_fail_once (store,
      WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AND_ROLLBACK);
  g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_get_state
      (txn), ==, WYL_SERVICE_AUTHORITY_TXN_FAILED_COMMIT);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_primary_result (txn),
      ==, WYRELOG_E_IO);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_cleanup_result (txn),
      ==, WYRELOG_E_IO);
  g_assert_false (sqlite3_get_autocommit (db));
  g_assert_true (wyl_policy_store_service_authority_transaction_is_poisoned
      (store));
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_primary_sqlite_extended_error
      (txn), ==, SQLITE_AUTH);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_recovery_sqlite_extended_error
      (txn), ==, SQLITE_AUTH);
  ConcurrentCommit concurrent = {.db = db,.rc = SQLITE_OK };
  wyl_policy_store_service_authority_transaction_abort_barrier_arm (txn);
  AbortBarrierObserver observer = { txn, &concurrent };
  g_autoptr (GThread) commit_thread = g_thread_new ("poison-commit",
      abort_barrier_observer_thread, &observer);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_abort (txn),
      ==, WYRELOG_E_OK);
  g_thread_join (g_steal_pointer (&commit_thread));
  g_assert_cmpint (concurrent.rc, ==, SQLITE_AUTH);
  for (guint i = 0; i < G_N_ELEMENTS (concurrent.matrix_rc); i++)
    g_assert_cmpint (concurrent.matrix_rc[i], ==, SQLITE_AUTH);
  g_assert_false (wyl_policy_store_service_authority_transaction_is_poisoned
      (store));
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  WylServiceAuthReadLease *lease;
  wyrelog_error_t rc;
} CleanupBarrierObserver;

static gpointer
cleanup_barrier_observer_thread (gpointer data)
{
  CleanupBarrierObserver *observer = data;
  wyl_policy_store_service_authority_transaction_cleanup_barrier_wait
      (observer->txn);
  observer->rc = wyl_service_auth_authority_acquire_read
      (observer->authority, observer->handle, NULL, &observer->lease);
  wyl_policy_store_service_authority_transaction_cleanup_barrier_release
      (observer->txn);
  return NULL;
}

static void
test_authority_transaction_cleanup_after_faults (void)
{
  const WylPolicyAuthorityTransactionFailStage stages[] = {
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AND_CLAIM_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_LEASE_SERIAL_AT_FINISH,
  };
  for (guint i = 0; i < G_N_ELEMENTS (stages); i++) {
    g_autoptr (WylHandle) handle = new_store_handle ();
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    WylServiceAuthWriteLease *lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_write
        (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
        ==, WYRELOG_E_OK);
    wyl_policy_store_service_authority_transaction_fail_once (store, stages[i]);
    g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
        (store, handle, lease, &txn), ==, WYRELOG_E_OK);
    WylServiceAuthorityCommitEvidence *evidence = NULL;
    g_assert_cmpint
        (wyl_policy_store_service_authority_prepare_commit_evidence (txn,
            store, &evidence), ==, WYRELOG_E_OK);
    CleanupBarrierObserver cleanup_observer = { 0 };
    g_autoptr (GThread) cleanup_thread = NULL;
    if (stages[i] == WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_BEFORE) {
      wyl_policy_store_service_authority_transaction_cleanup_barrier_arm (txn);
      cleanup_observer.txn = txn;
      cleanup_observer.authority =
          wyl_handle_get_service_auth_authority (handle);
      cleanup_observer.handle = handle;
      cleanup_thread = g_thread_new ("cleanup-observer",
          cleanup_barrier_observer_thread, &cleanup_observer);
    }
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
        (txn), ==, WYRELOG_E_OK);
    if (cleanup_thread != NULL) {
      g_thread_join (g_steal_pointer (&cleanup_thread));
      g_assert_cmpint (cleanup_observer.rc, ==, WYRELOG_E_BUSY);
      g_assert_null (cleanup_observer.lease);
    }
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_get_cleanup_result
        (txn), ==, WYRELOG_E_INTERNAL);
    g_assert_cmpint
        (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
        (evidence, handle, store), ==, WYRELOG_E_OK);
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (reason, ==,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
    g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
        WYRELOG_E_OK);
    wyl_service_auth_write_lease_free (lease);
    wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  }
}

static void
test_authority_transaction_authorizer_faults (void)
{
  const WylPolicyAuthorityTransactionFailStage stages[] = {
    WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_INSTALL,
    WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_REMOVE,
  };
  for (guint i = 0; i < G_N_ELEMENTS (stages); i++) {
    g_autoptr (WylHandle) handle = new_store_handle ();
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    WylServiceAuthWriteLease *lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_write
        (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
        ==, WYRELOG_E_OK);
    wyl_policy_store_service_authority_transaction_fail_once (store, stages[i]);
    g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
        (store, handle, lease, &txn), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
        (txn), ==, WYRELOG_E_IO);
    if (stages[i] == WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_INSTALL) {
      g_assert_false
          (wyl_policy_store_service_authority_transaction_is_poisoned (store));
      g_assert_true
          (wyl_policy_store_service_authority_transaction_test_poison_identity_is_clear
          (txn));
      g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
          WYRELOG_E_OK);
      wyl_service_auth_write_lease_free (lease);
      continue;
    }
    g_assert_true (wyl_policy_store_service_authority_transaction_is_poisoned
        (store));
    wyl_policy_store_service_authority_transaction_test_set_poison_identity
        (txn, TRUE, FALSE);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_abort (txn), ==,
        WYRELOG_E_INVALID);
    g_assert_true (wyl_policy_store_service_authority_transaction_is_poisoned
        (store));
    wyl_policy_store_service_authority_transaction_test_set_poison_identity
        (txn, FALSE, TRUE);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_abort (txn), ==,
        WYRELOG_E_INVALID);
    g_assert_true (wyl_policy_store_service_authority_transaction_is_poisoned
        (store));
    wyl_policy_store_service_authority_transaction_test_set_poison_identity
        (txn, TRUE, TRUE);
    wyl_service_auth_write_lease_test_corrupt_serial (lease);
    wyrelog_error_t abort_rc =
        wyl_policy_store_service_authority_transaction_abort (txn);
    g_assert_cmpint (abort_rc, ==,
        stages[i] == WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_REMOVE
        ? WYRELOG_E_INTERNAL : WYRELOG_E_OK);
    g_assert_true
        (wyl_policy_store_service_authority_transaction_test_poison_identity_is_clear
        (txn));
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (reason, ==,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
    g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
        WYRELOG_E_OK);
    wyl_service_auth_write_lease_free (lease);
    g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  }
}

typedef struct
{
  WylServiceAuthorityCommitEvidence *evidence;
  WylHandle *handle;
  wyl_policy_store_t *store;
  wyrelog_error_t rc;
} EvidenceValidationThread;

typedef struct
{
  WylServiceAuthorityTransaction *transaction;
  wyl_policy_store_t *store;
  wyrelog_error_t rc;
} EvidencePrepareThread;

static gpointer
commit_evidence_prepare_thread (gpointer data)
{
  EvidencePrepareThread *prepare = data;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  prepare->rc = wyl_policy_store_service_authority_prepare_commit_evidence
      (prepare->transaction, prepare->store, &evidence);
  g_assert_null (evidence);
  return NULL;
}

static gpointer
committed_evidence_validation_thread (gpointer data)
{
  EvidenceValidationThread *validation = data;
  WylServiceAuthorityCommitEvidence *evidence =
      wyl_policy_store_service_authority_commit_evidence_ref
      (validation->evidence);
  validation->rc =
      wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, validation->handle, validation->store);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  return NULL;
}

static void
test_authority_commit_evidence_commit_and_lifetime (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  g_autoptr (WylHandle) other = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  guint64 transaction_serial =
      wyl_policy_store_service_authority_transaction_get_serial (txn);
  g_assert_cmpuint (transaction_serial, >, 0);

  WylServiceAuthorityCommitEvidence *evidence = NULL;
  EvidencePrepareThread prepare = { txn, store, WYRELOG_E_OK };
  g_autoptr (GThread) prepare_thread = g_thread_new ("evidence-prepare",
      commit_evidence_prepare_thread, &prepare);
  g_thread_join (g_steal_pointer (&prepare_thread));
  g_assert_cmpint (prepare.rc, ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn,
          wyl_handle_get_policy_store (other), &evidence), ==,
      WYRELOG_E_INVALID);
  g_assert_null (evidence);
  wyl_policy_store_service_authority_transaction_fail_evidence_allocation_once
      (txn);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_NOMEM);
  g_assert_null (evidence);
  g_assert_cmpuint
      (wyl_policy_store_service_authority_transaction_get_evidence_allocation_count
      (txn), ==, 0);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_OK);
  g_assert_nonnull (evidence);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_pending
      (evidence, txn, handle, store), ==, WYRELOG_E_OK);
  WylServiceAuthorityCommitEvidence *duplicate = NULL;
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &duplicate), ==, WYRELOG_E_BUSY);
  g_assert_null (duplicate);

  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_OK);
  g_assert_cmpuint
      (wyl_policy_store_service_authority_transaction_get_evidence_allocation_count
      (txn), ==, 1);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_pending
      (evidence, txn, handle, store), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (evidence, lease, handle, store, transaction_serial), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (evidence, lease, handle, store, transaction_serial + 1), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (evidence, lease, other, wyl_handle_get_policy_store (other),
          transaction_serial), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_transaction_free (txn);

  txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  guint64 next_transaction_serial =
      wyl_policy_store_service_authority_transaction_get_serial (txn);
  g_assert_cmpuint (next_transaction_serial, !=, transaction_serial);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (evidence, lease, handle, store, next_transaction_serial), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);

  EvidenceValidationThread validation = { evidence, handle, store,
    WYRELOG_E_INTERNAL
  };
  g_autoptr (GThread) thread = g_thread_new ("evidence-validation",
      committed_evidence_validation_thread, &validation);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (validation.rc, ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (evidence, lease, handle, store, transaction_serial), ==,
      WYRELOG_E_INVALID);
  wyl_service_auth_write_lease_free (lease);
  WylServiceAuthWriteLease *other_lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &other_lease), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (evidence, other_lease, handle, store, transaction_serial), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_write_lease_release (other_lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (other_lease);
  g_assert_true
      (wyl_policy_store_service_authority_commit_evidence_test_ref_overflow_rejected
      (evidence));
  wyl_handle_policy_store_test_advance_generation (handle);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store), ==, WYRELOG_E_INVALID);
  wyl_handle_policy_store_test_set_generation_max (handle);
  wyl_handle_policy_store_test_advance_generation (handle);
  guint64 exhausted_generation = 0;
  g_assert_cmpint (wyl_handle_policy_store_capture_generation (handle, store,
          &exhausted_generation), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (exhausted_generation, ==, 0);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
}

static void
test_authority_commit_evidence_invalid_paths (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);

  WylServiceAuthorityTransaction *txn = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_service_principal_core (txn, store,
          NULL, NULL, NULL, NULL, NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_BUSY);
  g_assert_null (evidence);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);

  txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_transaction_free (txn);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);

  txn = NULL;
  evidence = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);

  txn = NULL;
  evidence = NULL;
  wyl_policy_store_service_authority_transaction_fail_once (store,
      WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  guint64 release_after_serial =
      wyl_policy_store_service_authority_transaction_get_serial (txn);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_OK);
  sqlite_exec_ok (wyl_policy_store_get_db (store),
      "PRAGMA user_version = 371;");
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_IO);
  g_assert_cmpint (sqlite_scalar (wyl_policy_store_get_db (store),
          "PRAGMA user_version;"), ==, 371);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (evidence, lease, handle, store, release_after_serial), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_authority_commit_evidence_does_not_block_shutdown (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_OK);
  g_clear_pointer (&txn, wyl_policy_store_service_authority_transaction_free);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);

  HandleShutdownThread shutdown = { handle, WYRELOG_E_INTERNAL };
  g_autoptr (GThread) thread = g_thread_new ("evidence-shutdown",
      handle_shutdown_thread, &shutdown);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (shutdown.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
}

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  wyl_policy_store_t *store;
  wyrelog_error_t rc;
} LastUsedThread;

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  wyl_policy_store_t *store;
  wyrelog_error_t rc;
} ParticipantThread;

static gpointer
participant_wrong_thread (gpointer data)
{
  ParticipantThread *attempt = data;
  attempt->rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (attempt->txn, attempt->store);
  return NULL;
}

static gpointer
last_used_wrong_thread (gpointer data)
{
  LastUsedThread *attempt = data;
  attempt->rc =
      wyl_policy_store_service_authority_transaction_record_credential_last_used
      (attempt->txn, attempt->store, LAST_USED_CREDENTIAL_ID, 7,
      "svc:last:used", "tenant-last", 150);
  return NULL;
}

static void
setup_last_used_credential (sqlite3 *db)
{
  sqlite_exec_ok (db,
      "INSERT INTO tenants(tenant_id,sealed,created_at,updated_at)"
      " VALUES('tenant-last',0,1,1);"
      "INSERT INTO service_principals(subject_id,display_name,state,generation,"
      "created_by,created_at_us,updated_at_us) VALUES"
      "('svc:last:used','last used','active',1,'admin',1,1);"
      "INSERT INTO service_credentials(credential_id,credential_format_version,"
      "subject_id,tenant_id,generation,state,verifier_version,salt,verifier,"
      "created_by,created_at_us,updated_at_us) VALUES('"
      LAST_USED_CREDENTIAL_ID
      "',1,'svc:last:used','tenant-last',7,'active',1,zeroblob(16),"
      "zeroblob(32),'admin',100,100);");
}

static gint64
read_last_used (sqlite3 *db)
{
  return sqlite_scalar (db,
      "SELECT coalesce(last_used_at_us,-1) FROM service_credentials"
      " WHERE credential_id='" LAST_USED_CREDENTIAL_ID "';");
}

static void
test_authority_transaction_credential_last_used (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  g_autoptr (WylHandle) other = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  setup_last_used_credential (db);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);

  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  LastUsedThread attempt = { txn, store, WYRELOG_E_OK };
  g_autoptr (GThread) thread = g_thread_new ("last-used-owner",
      last_used_wrong_thread, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, wyl_handle_get_policy_store (other), LAST_USED_CREDENTIAL_ID, 7,
          "svc:last:used", "tenant-last", 150), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_ABSENT_ID, 7, "svc:last:used", "tenant-last",
          150), ==, WYRELOG_E_NOT_FOUND);
  WylServiceAuthorityCommitEvidence *late_evidence = NULL;
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &late_evidence), ==, WYRELOG_E_BUSY);
  g_assert_null (late_evidence);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 8, "svc:last:used", "tenant-last",
          150), ==, WYRELOG_E_POLICY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:other", "tenant-last",
          150), ==, WYRELOG_E_POLICY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-other",
          150), ==, WYRELOG_E_POLICY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          99), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, G_MAXUINT64, "svc:last:used",
          "tenant-last", 150), ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          0), ==, WYRELOG_E_INVALID);
  sqlite_exec_ok (db,
      "UPDATE service_credentials SET state='revoked',revoked_by='admin',"
      "revoked_at_us=100,updated_at_us=100 WHERE credential_id='"
      LAST_USED_CREDENTIAL_ID "';");
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          150), ==, WYRELOG_E_POLICY);
  sqlite_exec_ok (db,
      "UPDATE service_credentials SET state='active',revoked_by=NULL,"
      "revoked_at_us=NULL WHERE credential_id='" LAST_USED_CREDENTIAL_ID "';");
  g_assert_cmpint (read_last_used (db), ==, -1);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          150), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_cmpint (read_last_used (db), ==, -1);

  txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          200), ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_t created = { 0 };
  g_assert_cmpint (wyl_policy_store_create_service_principal_core (txn, store,
          "svc:last:peer", "peer", "admin", "last-used-peer", &created), ==,
      WYRELOG_E_OK);
  wyl_policy_service_principal_info_clear (&created);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          225), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_cmpint (read_last_used (db), ==, 200);

  txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          200), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          150), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_fail_last_used_sql_once (txn);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          250), ==, WYRELOG_E_IO);
  g_assert_cmpint (read_last_used (db), ==, 200);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);

  wyl_policy_store_service_authority_transaction_fail_once (store,
      WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
  txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          300), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_IO);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_cmpint (read_last_used (db), ==, 300);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_authority_transaction_credential_last_used_unavailable (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  setup_last_used_credential (db);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (lease,
          handle, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT), ==,
      WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_BUSY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_record_credential_last_used
      (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used", "tenant-last",
          150), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (read_last_used (db), ==, -1);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_authority_transaction_participant_contract (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  g_autoptr (WylHandle) other = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);

  WylServiceAuthorityTransaction *txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  gint changes_before = sqlite3_total_changes (db);
  guint allocations_before =
      wyl_policy_store_service_authority_transaction_get_evidence_allocation_count
      (txn);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          wyl_handle_get_policy_store (other)), ==, WYRELOG_E_INVALID);
  ParticipantThread attempt = { txn, store, WYRELOG_E_OK };
  g_autoptr (GThread) thread = g_thread_new ("participant-owner",
      participant_wrong_thread, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_total_changes (db), ==, changes_before);
  g_assert_cmpuint
      (wyl_policy_store_service_authority_transaction_get_evidence_allocation_count
      (txn), ==, allocations_before);
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (txn, store,
          &evidence), ==, WYRELOG_E_BUSY);
  g_assert_null (evidence);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_transaction_free (txn);

  txn = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_transaction_free (txn);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static WylHandle *
new_file_store_handle (const gchar *path)
{
  WylHandleOpenOptions options = {
    .policy_store_path = path,
  };
  WylHandle *handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  return handle;
}

static void
begin_with_evidence (WylHandle *handle, WylServiceAuthWriteLease **out_lease,
    WylServiceAuthorityTransaction **out_txn,
    WylServiceAuthorityCommitEvidence **out_evidence)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          out_lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, *out_lease, out_txn), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_prepare_commit_evidence (*out_txn,
          store, out_evidence), ==, WYRELOG_E_OK);
}

static void
finish_rolled_back (WylServiceAuthWriteLease *lease,
    WylServiceAuthorityTransaction *txn,
    WylServiceAuthorityCommitEvidence *evidence)
{
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_authority_transaction_write_intent (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  WylServiceAuthorityTransaction *txn = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  begin_with_evidence (handle, &lease, &txn, &evidence);
  WylServiceAuthorityWriteIntentOutcome outcome = { 0 };
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.result, ==,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_ACQUIRED);
  g_assert_cmpint (outcome.sqlite_extended_code, ==, SQLITE_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_OK);
  gint changes = sqlite3_total_changes (wyl_policy_store_get_db (store));
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_total_changes (wyl_policy_store_get_db (store)), ==,
      changes);
  finish_rolled_back (lease, txn, evidence);

  lease = NULL;
  txn = NULL;
  evidence = NULL;
  begin_with_evidence (handle, &lease, &txn, &evidence);
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  g_cancellable_cancel (cancellable);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, cancellable, &outcome), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (outcome.result, ==,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_CANCELLED);
  g_assert_cmpint (outcome.sqlite_extended_code, ==, SQLITE_INTERRUPT);
  WylServiceAuthorityWriteIntentOutcome repeated = { 0 };
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &repeated), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (repeated.result, ==, outcome.result);
  g_assert_cmpint (repeated.sqlite_extended_code, ==,
      outcome.sqlite_extended_code);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_BUSY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_BUSY);
  finish_rolled_back (lease, txn, evidence);

  lease = NULL;
  txn = NULL;
  evidence = NULL;
  begin_with_evidence (handle, &lease, &txn, &evidence);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_enter_participant (txn,
          store), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &outcome), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (outcome.result, ==,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_POLICY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &repeated), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (repeated.result, ==, outcome.result);
  g_assert_cmpint (repeated.sqlite_extended_code, ==,
      outcome.sqlite_extended_code);
  finish_rolled_back (lease, txn, evidence);

  const int forced_codes[] = { SQLITE_LOCKED, SQLITE_IOERR };
  const wyrelog_error_t forced_rcs[] = { WYRELOG_E_BUSY, WYRELOG_E_IO };
  const WylServiceAuthorityWriteIntentResult forced_results[] = {
    WYL_SERVICE_AUTHORITY_WRITE_INTENT_LOCKED,
    WYL_SERVICE_AUTHORITY_WRITE_INTENT_IO,
  };
  for (guint i = 0; i < G_N_ELEMENTS (forced_codes); i++) {
    lease = NULL;
    txn = NULL;
    evidence = NULL;
    begin_with_evidence (handle, &lease, &txn, &evidence);
    wyl_policy_store_service_authority_transaction_test_fail_intent_once (txn,
        forced_codes[i]);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_acquire_write_intent
        (txn, store, NULL, &outcome), ==, forced_rcs[i]);
    g_assert_cmpint (outcome.result, ==, forced_results[i]);
    g_assert_cmpint (outcome.sqlite_extended_code, ==, forced_codes[i]);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_acquire_write_intent
        (txn, store, NULL, &repeated), ==, forced_rcs[i]);
    g_assert_cmpint (repeated.result, ==, outcome.result);
    g_assert_cmpint (repeated.sqlite_extended_code, ==,
        outcome.sqlite_extended_code);
    finish_rolled_back (lease, txn, evidence);
  }

  sqlite_exec_ok (wyl_policy_store_get_db (store),
      "DELETE FROM service_authority_writer_gate;");
  lease = NULL;
  txn = NULL;
  evidence = NULL;
  begin_with_evidence (handle, &lease, &txn, &evidence);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &outcome), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (outcome.result, ==,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_POLICY);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &repeated), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (repeated.result, ==, outcome.result);
  g_assert_cmpint (repeated.sqlite_extended_code, ==,
      outcome.sqlite_extended_code);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_BUSY);
  finish_rolled_back (lease, txn, evidence);
  sqlite_exec_ok (wyl_policy_store_get_db (store),
      "INSERT INTO service_authority_writer_gate(singleton,lock_word)"
      " VALUES(1,0);");

  wyl_policy_store_service_authority_transaction_fail_once (store,
      WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
  lease = NULL;
  txn = NULL;
  evidence = NULL;
  begin_with_evidence (handle, &lease, &txn, &evidence);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (txn), ==, WYRELOG_E_IO);
  g_assert_cmpint
      (wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (txn);
  wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_service_exchange_intention_created_replay_rollback (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  WylServiceAuthorityTransaction *txn = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  begin_with_evidence (handle, &lease, &txn, &evidence);
  WylServiceAuthorityWriteIntentOutcome outcome = { 0 };
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, NULL, &outcome), ==, WYRELOG_E_OK);

  wyl_service_exchange_audit_input_t input = {
    .request_id = {"000000000000000000000000000", 27},
    .credential_id = {"wlc_000000000000000000000000000", 31},
    .credential_generation = 7,
    .service_principal = {"svc:test", 8},
    .tenant_id = {"tenant-a", 8},
    .session_id = {"01890f47-3c4b-7cc2-98c4-dc0c0c07398f", 36},
    .jti = {"01890f47-3c4b-7cc2-a8c4-dc0c0c073990", 36},
    .created_at_us = 42,
  };
  g_assert_cmpint (wyl_id_parse ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
          &input.intention_id), ==, WYRELOG_E_OK);
  WylServiceExchangeIntentionClassification classification;
  g_autoptr (WylServiceExchangeIntentionRecord) created = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (txn,
          store, &input, &classification, &created), ==, WYRELOG_E_OK);
  g_assert_cmpint (classification, ==, WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  g_assert_cmpstr (created->tenant_id, ==, "tenant-a");
  g_autoptr (WylServiceExchangeIntentionRecord) replay = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (txn,
          store, &input, &classification, &replay), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (classification, ==, WYL_SERVICE_EXCHANGE_INTENTION_NONE);
  g_assert_null (replay);
  g_autoptr (WylServiceExchangeIntentionRecord) loaded = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load (txn,
          store, &input.intention_id, created->material.payload_digest,
          &loaded), ==, WYRELOG_E_OK);
  g_assert_cmpuint (loaded->credential_generation, ==, 7);
  g_autoptr (GPtrArray) records = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate (txn,
          store, &records), ==, WYRELOG_E_OK);
  g_assert_cmpuint (records->len, ==, 1);
  input.created_at_us++;
  WylServiceExchangeIntentionRecord *conflict = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (txn,
          store, &input, &classification, &conflict), ==, WYRELOG_E_POLICY);
  g_assert_null (conflict);
  g_assert_cmpint (sqlite_scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM audit_intentions;"), ==, 0);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE service_exchange_audit_intentions SET created_at_us=43;",
          NULL, NULL, NULL), !=, SQLITE_OK);
  finish_rolled_back (lease, txn, evidence);
  g_assert_cmpint (sqlite_scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_exchange_audit_intentions;"), ==, 0);
}

typedef struct
{
  WylHandle *handle;
  gboolean commit;
  wyrelog_error_t rc;
  WylServiceAuthorityWriteIntentOutcome outcome;
} WriteIntentConnectionAttempt;

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylHandle *handle;
  GCancellable *cancellable;
  WylServiceAuthorityTransaction *txn;
  gboolean ready;
  wyrelog_error_t rc;
  WylServiceAuthorityWriteIntentOutcome outcome;
} WriteIntentCancelBarrier;

static gpointer
write_intent_cancel_barrier_thread (gpointer data)
{
  WriteIntentCancelBarrier *barrier = data;
  WylServiceAuthWriteLease *lease = NULL;
  WylServiceAuthorityTransaction *txn = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  begin_with_evidence (barrier->handle, &lease, &txn, &evidence);
  wyl_policy_store_service_authority_transaction_test_arm_intent_barrier (txn);
  g_mutex_lock (&barrier->mutex);
  barrier->txn = txn;
  barrier->ready = TRUE;
  g_cond_broadcast (&barrier->changed);
  g_mutex_unlock (&barrier->mutex);
  barrier->rc =
      wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, wyl_handle_get_policy_store (barrier->handle),
      barrier->cancellable, &barrier->outcome);
  finish_rolled_back (lease, txn, evidence);
  return NULL;
}

static void
test_authority_transaction_write_intent_cancel_barrier (void)
{
  g_autoptr (WylHandle) handle = new_store_handle ();
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  WriteIntentCancelBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  barrier.handle = handle;
  barrier.cancellable = cancellable;
  barrier.rc = WYRELOG_E_INTERNAL;
  g_autoptr (GThread) thread = g_thread_new ("intent-cancel-barrier",
      write_intent_cancel_barrier_thread, &barrier);
  g_mutex_lock (&barrier.mutex);
  while (!barrier.ready)
    g_cond_wait (&barrier.changed, &barrier.mutex);
  WylServiceAuthorityTransaction *txn = barrier.txn;
  g_mutex_unlock (&barrier.mutex);
  wyl_policy_store_service_authority_transaction_test_wait_intent_barrier (txn);
  g_cancellable_cancel (cancellable);
  wyl_policy_store_service_authority_transaction_test_release_intent_barrier
      (txn);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (barrier.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (barrier.outcome.result, ==,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_CANCELLED);
  g_assert_cmpint (barrier.outcome.sqlite_extended_code, ==, SQLITE_INTERRUPT);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
}

static gpointer
write_intent_connection_thread (gpointer data)
{
  WriteIntentConnectionAttempt *attempt = data;
  WylServiceAuthWriteLease *lease = NULL;
  WylServiceAuthorityTransaction *txn = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  begin_with_evidence (attempt->handle, &lease, &txn, &evidence);
  attempt->rc =
      wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, wyl_handle_get_policy_store (attempt->handle), NULL,
      &attempt->outcome);
  if (attempt->rc != WYRELOG_E_OK) {
    wyrelog_error_t first_rc = attempt->rc;
    WylServiceAuthorityWriteIntentOutcome first = attempt->outcome;
    WylServiceAuthorityWriteIntentOutcome repeated = { 0 };
    attempt->rc =
        wyl_policy_store_service_authority_transaction_acquire_write_intent
        (txn, wyl_handle_get_policy_store (attempt->handle), NULL, &repeated);
    g_assert_cmpint (attempt->rc, ==, first_rc);
    g_assert_cmpint (repeated.result, ==, first.result);
    g_assert_cmpint (repeated.sqlite_extended_code, ==,
        first.sqlite_extended_code);
  }
  if (attempt->rc == WYRELOG_E_OK && attempt->commit) {
    sqlite_exec_ok (wyl_policy_store_get_db
        (wyl_handle_get_policy_store (attempt->handle)),
        "PRAGMA user_version=371;");
    attempt->rc = wyl_policy_store_service_authority_transaction_commit (txn);
    wyl_policy_store_service_authority_transaction_free (txn);
    wyl_policy_store_service_authority_commit_evidence_unref (evidence);
    g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
        WYRELOG_E_OK);
    wyl_service_auth_write_lease_free (lease);
  } else {
    finish_rolled_back (lease, txn, evidence);
  }
  return NULL;
}

static void
test_authority_transaction_write_intent_connections (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-write-intent-XXXXXX", NULL);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  g_autoptr (WylHandle) first = new_file_store_handle (path);
  g_autoptr (WylHandle) second = new_file_store_handle (path);
  wyl_policy_store_t *first_store = wyl_handle_get_policy_store (first);
  wyl_policy_store_t *second_store = wyl_handle_get_policy_store (second);

  WylServiceAuthWriteLease *first_lease = NULL;
  WylServiceAuthorityTransaction *first_txn = NULL;
  WylServiceAuthorityCommitEvidence *first_evidence = NULL;
  begin_with_evidence (first, &first_lease, &first_txn, &first_evidence);
  WylServiceAuthorityWriteIntentOutcome outcome = { 0 };
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (first_txn, first_store, NULL, &outcome), ==, WYRELOG_E_OK);

  WriteIntentConnectionAttempt attempt = { second, FALSE, WYRELOG_E_OK, {0} };
  g_autoptr (GThread) contender = g_thread_new ("write-intent-contender",
      write_intent_connection_thread, &attempt);
  g_thread_join (g_steal_pointer (&contender));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_BUSY);
  g_assert_cmpint (attempt.outcome.result, ==,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_BUSY);
  finish_rolled_back (first_lease, first_txn, first_evidence);

  WylServiceAuthWriteLease *second_lease = NULL;
  WylServiceAuthorityTransaction *second_txn = NULL;
  WylServiceAuthorityCommitEvidence *second_evidence = NULL;
  begin_with_evidence (second, &second_lease, &second_txn, &second_evidence);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (second_txn, second_store, NULL, &outcome), ==, WYRELOG_E_OK);
  finish_rolled_back (second_lease, second_txn, second_evidence);

  second_lease = NULL;
  second_txn = NULL;
  second_evidence = NULL;
  begin_with_evidence (second, &second_lease, &second_txn, &second_evidence);
  g_assert_cmpint (sqlite_scalar (wyl_policy_store_get_db (second_store),
          "SELECT lock_word FROM service_authority_writer_gate;"), ==, 0);
  WriteIntentConnectionAttempt writer = { first, TRUE, WYRELOG_E_INTERNAL,
    {0}
  };
  g_autoptr (GThread) writer_thread = g_thread_new ("write-intent-writer",
      write_intent_connection_thread, &writer);
  g_thread_join (g_steal_pointer (&writer_thread));
  g_assert_cmpint (writer.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (second_txn, second_store, NULL, &outcome), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (outcome.result, ==,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_BUSY_SNAPSHOT);
  g_assert_cmpint (outcome.sqlite_extended_code, ==, SQLITE_BUSY_SNAPSHOT);
  WylServiceAuthorityWriteIntentOutcome snapshot_repeated = { 0 };
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (second_txn, second_store, NULL, &snapshot_repeated), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (snapshot_repeated.result, ==, outcome.result);
  g_assert_cmpint (snapshot_repeated.sqlite_extended_code, ==,
      outcome.sqlite_extended_code);
  finish_rolled_back (second_lease, second_txn, second_evidence);

  g_clear_object (&second);
  g_clear_object (&first);
  (void) g_remove (path);
  g_autofree gchar *wal = g_strdup_printf ("%s-wal", path);
  g_autofree gchar *shm = g_strdup_printf ("%s-shm", path);
  (void) g_remove (wal);
  (void) g_remove (shm);
  (void) g_rmdir (dir);
}

static void
test_authority_transaction_credential_last_used_corrupt_text (void)
{
  static const gchar *subject_values[] = {
    "CAST(x'7376633a6c6173743a757365640078' AS TEXT)",
    "'svc:last:used'",
    "'svc:last:used'",
    "'svc:last:used'",
  };
  static const gchar *tenant_values[] = {
    "'tenant-last'",
    "CAST(x'74656e616e742d6c6173740078' AS TEXT)",
    "'tenant-last'",
    "'tenant-last'",
  };
  static const gchar *state_values[] = {
    "'active'",
    "'active'",
    "CAST(x'6163746976650078' AS TEXT)",
    "CAST(x'61ff' AS TEXT)",
  };

  for (guint i = 0; i < G_N_ELEMENTS (subject_values); i++) {
    g_autoptr (WylHandle) handle = new_store_handle ();
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    sqlite3 *db = wyl_policy_store_get_db (store);
    sqlite_exec_ok (db,
        "INSERT INTO tenants(tenant_id,sealed,created_at,updated_at)"
        " VALUES('tenant-last',0,1,1);"
        "INSERT INTO service_principals(subject_id,display_name,state,"
        "generation,created_by,created_at_us,updated_at_us) VALUES"
        "('svc:last:used','last used','active',1,'admin',1,1);"
        "PRAGMA foreign_keys=OFF;PRAGMA ignore_check_constraints=ON;");
    g_autofree gchar *insert =
        g_strdup_printf ("INSERT INTO service_credentials(credential_id,"
        "credential_format_version,subject_id,tenant_id,generation,state,"
        "verifier_version,salt,verifier,created_by,created_at_us,updated_at_us)"
        " VALUES('%s',1,%s,%s,7,%s,1,zeroblob(16),zeroblob(32),'admin',100,100);"
        "PRAGMA ignore_check_constraints=OFF;PRAGMA foreign_keys=ON;",
        LAST_USED_CREDENTIAL_ID, subject_values[i], tenant_values[i],
        state_values[i]);
    sqlite_exec_ok (db, insert);

    WylServiceAuthWriteLease *lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_write
        (wyl_handle_get_service_auth_authority (handle), handle, NULL,
            &lease), ==, WYRELOG_E_OK);
    WylServiceAuthorityTransaction *txn = NULL;
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
        (store, handle, lease, &txn), ==, WYRELOG_E_OK);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_record_credential_last_used
        (txn, store, LAST_USED_CREDENTIAL_ID, 7, "svc:last:used",
            "tenant-last", 150), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (read_last_used (db), ==, -1);
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
        (txn), ==, WYRELOG_E_OK);
    wyl_policy_store_service_authority_transaction_free (txn);
    g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
        WYRELOG_E_OK);
    wyl_service_auth_write_lease_free (lease);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-auth/lease/basic-validation-reentry",
      test_basic_validation_and_reentry);
  g_test_add_func ("/service-auth/lease/read-pinned-policy-store",
      test_read_lease_pinned_policy_store);
  g_test_add_func ("/service-auth/lease/wrong-thread-release",
      test_wrong_thread_release);
  g_test_add_func ("/service-auth/lease/terminal-release",
      test_read_terminal_release_contract);
  g_test_add_func ("/service-auth/lease/terminal-release-faults",
      test_read_terminal_release_faults);
  g_test_add_func ("/service-auth/lease/terminal-release-wrong-thread",
      test_read_terminal_release_wrong_thread);
  g_test_add_func ("/service-auth/lease/rank-inversion-write-serial",
      test_rank_inversion_and_write_serial);
  g_test_add_func ("/service-auth/authority/writer-preference",
      test_waiting_writer_blocks_later_reader);
  g_test_add_func ("/service-auth/authority/writer-cancellation",
      test_writer_cancellation_restores_progress);
  g_test_add_func ("/service-auth/authority/writer-no-barge-write-release",
      test_writer_no_barge_after_write_release);
  g_test_add_func ("/service-auth/authority/writer-no-barge-reader-drain",
      test_writer_no_barge_after_reader_drain);
  g_test_add_func ("/service-auth/authority/writer-no-barge-terminal-drain",
      test_writer_no_barge_after_terminal_drain);
  g_test_add_func ("/service-auth/authority/writer-cancel-no-strand",
      test_writer_cancel_does_not_strand_reservation);
  g_test_add_func ("/service-auth/authority/close-drains-queued-writers",
      test_close_drains_queued_writers);
  g_test_add_func ("/service-auth/authority/close-drain",
      test_close_wakes_and_drains);
  g_test_add_func ("/service-auth/unavailable/terminal-exact-token",
      test_terminalize_cleanup_exact_token);
  g_test_add_func ("/service-auth/authority/handle-shutdown-drains-pins",
      test_handle_shutdown_wakes_queued_leases_and_drains_pins);
  g_test_add_func ("/service-auth/unavailable/validation-waiters-first-reason",
      test_unavailable_latch_validation_wakes_waiters_and_first_reason_wins);
  g_test_add_func ("/service-auth/unavailable/acquired-read-race",
      test_unavailable_latch_serializes_after_acquired_read);
  g_test_add_func ("/service-auth/unavailable/active-txn-core-no-side-effects",
      test_unavailable_latch_rejects_active_transaction_core_before_side_effects);
  g_test_add_func ("/service-auth/unavailable/fresh-handle-close",
      test_unavailable_latch_fresh_handle_and_close_interaction);
  g_test_add_func ("/service-auth/transaction/commit-claim",
      test_authority_transaction_commit_and_claim);
  g_test_add_func ("/service-auth/transaction/rollback-cleanup",
      test_authority_transaction_rollback_and_cleanup);
  g_test_add_func ("/service-auth/transaction/reject-outer",
      test_authority_transaction_rejects_outer_transaction);
  g_test_add_func ("/service-auth/transaction/reject-wrong-owner",
      test_authority_transaction_rejects_wrong_owner);
  g_test_add_func ("/service-auth/transaction/release-faults",
      test_authority_transaction_release_faults);
  g_test_add_func ("/service-auth/transaction/rollback-poison",
      test_authority_transaction_poison_on_failed_rollback);
  g_test_add_func ("/service-auth/transaction/commit-cleanup-failure",
      test_authority_transaction_preserves_commit_cleanup_failure);
  g_test_add_func ("/service-auth/transaction/cleanup-after-faults",
      test_authority_transaction_cleanup_after_faults);
  g_test_add_func ("/service-auth/transaction/authorizer-faults",
      test_authority_transaction_authorizer_faults);
  g_test_add_func ("/service-auth/transaction/pin-precedes-shutdown",
      test_authority_transaction_pin_precedes_shutdown);
  g_test_add_func ("/service-auth/evidence/commit-lifetime",
      test_authority_commit_evidence_commit_and_lifetime);
  g_test_add_func ("/service-auth/evidence/invalid-paths",
      test_authority_commit_evidence_invalid_paths);
  g_test_add_func ("/service-auth/evidence/shutdown",
      test_authority_commit_evidence_does_not_block_shutdown);
  g_test_add_func ("/service-auth/transaction/credential-last-used",
      test_authority_transaction_credential_last_used);
  g_test_add_func ("/service-auth/transaction/credential-last-used-unavailable",
      test_authority_transaction_credential_last_used_unavailable);
  g_test_add_func ("/service-auth/transaction/participant-contract",
      test_authority_transaction_participant_contract);
  g_test_add_func ("/service-auth/transaction/write-intent",
      test_authority_transaction_write_intent);
  g_test_add_func ("/service-auth/transaction/service-exchange-intention",
      test_service_exchange_intention_created_replay_rollback);
  g_test_add_func ("/service-auth/transaction/write-intent-connections",
      test_authority_transaction_write_intent_connections);
  g_test_add_func ("/service-auth/transaction/write-intent-cancel-barrier",
      test_authority_transaction_write_intent_cancel_barrier);
  g_test_add_func
      ("/service-auth/transaction/credential-last-used-corrupt-text",
      test_authority_transaction_credential_last_used_corrupt_text);
  return g_test_run ();
}

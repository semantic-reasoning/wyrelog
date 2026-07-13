/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "service-auth-coordination-private.h"

typedef enum
{
  WYL_SERVICE_AUTH_LEASE_ACTIVE,
  WYL_SERVICE_AUTH_LEASE_RELEASED,
} WylServiceAuthLeaseState;

struct _WylServiceAuthAuthority
{
  gint refs;
  GMutex mutex;
  GCond changed;
  WylHandle *handle;            /* identity only; leases keep the handle alive */
  GHashTable *reader_owners;    /* GThread* set; recursion is forbidden */
  GThread *writer_owner;
  guint active_readers;
  guint waiting_writers;
  gboolean writer_active;
  gboolean closing;
  guint64 next_serial;
};

struct _WylServiceAuthReadLease
{
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  GThread *owner;
  guint64 serial;
  WylServiceAuthLeaseState state;
};

struct _WylServiceAuthWriteLease
{
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  GThread *owner;
  guint64 serial;
  WylServiceAuthLeaseState state;
};

static gboolean
thread_owns_lease_locked (WylServiceAuthAuthority *authority, GThread *thread)
{
  return authority->writer_owner == thread
      || g_hash_table_contains (authority->reader_owners, thread);
}

WylServiceAuthAuthority *
wyl_service_auth_authority_new (WylHandle *handle)
{
  g_return_val_if_fail (WYL_IS_HANDLE (handle), NULL);

  WylServiceAuthAuthority *authority = g_new0 (WylServiceAuthAuthority, 1);
  g_atomic_int_set (&authority->refs, 1);
  g_mutex_init (&authority->mutex);
  g_cond_init (&authority->changed);
  authority->handle = handle;
  authority->reader_owners = g_hash_table_new (g_direct_hash, g_direct_equal);
  authority->next_serial = 1;
  return authority;
}

WylServiceAuthAuthority *
wyl_service_auth_authority_ref (WylServiceAuthAuthority *authority)
{
  g_return_val_if_fail (authority != NULL, NULL);
  g_atomic_int_inc (&authority->refs);
  return authority;
}

void
wyl_service_auth_authority_unref (WylServiceAuthAuthority *authority)
{
  if (authority == NULL || !g_atomic_int_dec_and_test (&authority->refs))
    return;

  g_assert_cmpuint (authority->active_readers, ==, 0);
  g_assert_false (authority->writer_active);
  g_assert_cmpuint (authority->waiting_writers, ==, 0);
  g_hash_table_unref (authority->reader_owners);
  g_cond_clear (&authority->changed);
  g_mutex_clear (&authority->mutex);
  g_free (authority);
}

static void
cancellable_wakeup (GCancellable *cancellable, gpointer user_data)
{
  WylServiceAuthAuthority *authority = user_data;
  (void) cancellable;
  g_mutex_lock (&authority->mutex);
  g_cond_broadcast (&authority->changed);
  g_mutex_unlock (&authority->mutex);
}

static gulong
connect_cancellable (GCancellable *cancellable,
    WylServiceAuthAuthority *authority)
{
  return cancellable == NULL ? 0 : g_cancellable_connect (cancellable,
      G_CALLBACK (cancellable_wakeup), authority, NULL);
}

static gboolean
acquisition_cancelled (GCancellable *cancellable)
{
  return cancellable != NULL && g_cancellable_is_cancelled (cancellable);
}

static wyrelog_error_t
next_serial_locked (WylServiceAuthAuthority *authority, guint64 *out_serial)
{
  if (authority->next_serial == 0)
    return WYRELOG_E_INTERNAL;
  *out_serial = authority->next_serial++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_authority_acquire_read (WylServiceAuthAuthority *authority,
    GCancellable *cancellable, WylServiceAuthReadLease **out_lease)
{
  if (out_lease != NULL)
    *out_lease = NULL;
  if (authority == NULL || out_lease == NULL
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;

  wyl_service_auth_authority_ref (authority);
  gulong cancel_id = connect_cancellable (cancellable, authority);
  GThread *thread = g_thread_self ();
  wyrelog_error_t rc = WYRELOG_E_OK;
  guint64 serial = 0;

  g_mutex_lock (&authority->mutex);
  if (thread_owns_lease_locked (authority, thread)) {
    rc = WYRELOG_E_BUSY;
  } else {
    while (!authority->closing && !acquisition_cancelled (cancellable)
        && (authority->writer_active || authority->waiting_writers > 0))
      g_cond_wait (&authority->changed, &authority->mutex);
    if (authority->closing || acquisition_cancelled (cancellable))
      rc = WYRELOG_E_BUSY;
  }
  if (rc == WYRELOG_E_OK)
    rc = next_serial_locked (authority, &serial);
  if (rc == WYRELOG_E_OK) {
    authority->active_readers++;
    g_hash_table_add (authority->reader_owners, thread);
  }
  g_mutex_unlock (&authority->mutex);
  if (cancel_id != 0)
    g_cancellable_disconnect (cancellable, cancel_id);

  if (rc == WYRELOG_E_OK) {
    WylServiceAuthReadLease *lease = g_new0 (WylServiceAuthReadLease, 1);
    lease->authority = authority;
    lease->handle = g_object_ref (authority->handle);
    lease->owner = thread;
    lease->serial = serial;
    lease->state = WYL_SERVICE_AUTH_LEASE_ACTIVE;
    *out_lease = lease;
  } else {
    wyl_service_auth_authority_unref (authority);
  }
  return rc;
}

wyrelog_error_t
wyl_service_auth_authority_acquire_write (WylServiceAuthAuthority *authority,
    GCancellable *cancellable, WylServiceAuthWriteLease **out_lease)
{
  if (out_lease != NULL)
    *out_lease = NULL;
  if (authority == NULL || out_lease == NULL
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;

  wyl_service_auth_authority_ref (authority);
  gulong cancel_id = connect_cancellable (cancellable, authority);
  GThread *thread = g_thread_self ();
  wyrelog_error_t rc = WYRELOG_E_OK;
  guint64 serial = 0;

  g_mutex_lock (&authority->mutex);
  if (thread_owns_lease_locked (authority, thread)) {
    rc = WYRELOG_E_BUSY;
  } else {
    authority->waiting_writers++;
    while (!authority->closing && !acquisition_cancelled (cancellable)
        && (authority->writer_active || authority->active_readers > 0))
      g_cond_wait (&authority->changed, &authority->mutex);
    authority->waiting_writers--;
    if (authority->closing || acquisition_cancelled (cancellable))
      rc = WYRELOG_E_BUSY;
    if (rc != WYRELOG_E_OK)
      g_cond_broadcast (&authority->changed);
  }
  if (rc == WYRELOG_E_OK)
    rc = next_serial_locked (authority, &serial);
  if (rc == WYRELOG_E_OK) {
    authority->writer_active = TRUE;
    authority->writer_owner = thread;
  }
  g_mutex_unlock (&authority->mutex);
  if (cancel_id != 0)
    g_cancellable_disconnect (cancellable, cancel_id);

  if (rc == WYRELOG_E_OK) {
    WylServiceAuthWriteLease *lease = g_new0 (WylServiceAuthWriteLease, 1);
    lease->authority = authority;
    lease->handle = g_object_ref (authority->handle);
    lease->owner = thread;
    lease->serial = serial;
    lease->state = WYL_SERVICE_AUTH_LEASE_ACTIVE;
    *out_lease = lease;
  } else {
    wyl_service_auth_authority_unref (authority);
  }
  return rc;
}

static wyrelog_error_t
validate_read_locked (WylServiceAuthReadLease *lease, WylHandle *handle)
{
  if (lease->state != WYL_SERVICE_AUTH_LEASE_ACTIVE
      || lease->owner != g_thread_self () || lease->handle != handle
      || lease->authority->handle != handle || lease->serial == 0
      || !g_hash_table_contains (lease->authority->reader_owners, lease->owner))
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_write_locked (WylServiceAuthWriteLease *lease, WylHandle *handle)
{
  if (lease->state != WYL_SERVICE_AUTH_LEASE_ACTIVE
      || lease->owner != g_thread_self () || lease->handle != handle
      || lease->authority->handle != handle || lease->serial == 0
      || !lease->authority->writer_active
      || lease->authority->writer_owner != lease->owner)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_read_lease_validate (WylServiceAuthReadLease *lease,
    WylHandle *handle)
{
  if (lease == NULL || !WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&lease->authority->mutex);
  wyrelog_error_t rc = validate_read_locked (lease, handle);
  g_mutex_unlock (&lease->authority->mutex);
  return rc;
}

wyrelog_error_t
wyl_service_auth_write_lease_validate (WylServiceAuthWriteLease *lease,
    WylHandle *handle)
{
  if (lease == NULL || !WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&lease->authority->mutex);
  wyrelog_error_t rc = validate_write_locked (lease, handle);
  g_mutex_unlock (&lease->authority->mutex);
  return rc;
}

wyrelog_error_t
wyl_service_auth_read_lease_release (WylServiceAuthReadLease *lease)
{
  if (lease == NULL)
    return WYRELOG_E_INVALID;
  WylServiceAuthAuthority *authority = lease->authority;
  g_mutex_lock (&authority->mutex);
  wyrelog_error_t rc = validate_read_locked (lease, lease->handle);
  if (rc == WYRELOG_E_OK) {
    lease->state = WYL_SERVICE_AUTH_LEASE_RELEASED;
    g_hash_table_remove (authority->reader_owners, lease->owner);
    authority->active_readers--;
    g_cond_broadcast (&authority->changed);
  }
  g_mutex_unlock (&authority->mutex);
  return rc;
}

wyrelog_error_t
wyl_service_auth_write_lease_release (WylServiceAuthWriteLease *lease)
{
  if (lease == NULL)
    return WYRELOG_E_INVALID;
  WylServiceAuthAuthority *authority = lease->authority;
  g_mutex_lock (&authority->mutex);
  wyrelog_error_t rc = validate_write_locked (lease, lease->handle);
  if (rc == WYRELOG_E_OK) {
    lease->state = WYL_SERVICE_AUTH_LEASE_RELEASED;
    authority->writer_active = FALSE;
    authority->writer_owner = NULL;
    g_cond_broadcast (&authority->changed);
  }
  g_mutex_unlock (&authority->mutex);
  return rc;
}

void
wyl_service_auth_read_lease_free (WylServiceAuthReadLease *lease)
{
  if (lease == NULL)
    return;
  if (lease->state == WYL_SERVICE_AUTH_LEASE_ACTIVE)
    g_assert_cmpint (wyl_service_auth_read_lease_release (lease), ==,
        WYRELOG_E_OK);
  g_clear_object (&lease->handle);
  wyl_service_auth_authority_unref (lease->authority);
  g_free (lease);
}

void
wyl_service_auth_write_lease_free (WylServiceAuthWriteLease *lease)
{
  if (lease == NULL)
    return;
  if (lease->state == WYL_SERVICE_AUTH_LEASE_ACTIVE)
    g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
        WYRELOG_E_OK);
  g_clear_object (&lease->handle);
  wyl_service_auth_authority_unref (lease->authority);
  g_free (lease);
}

wyrelog_error_t
wyl_service_auth_authority_close (WylServiceAuthAuthority *authority)
{
  if (authority == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&authority->mutex);
  if (thread_owns_lease_locked (authority, g_thread_self ())) {
    g_mutex_unlock (&authority->mutex);
    return WYRELOG_E_BUSY;
  }
  authority->closing = TRUE;
  g_cond_broadcast (&authority->changed);
  while (authority->active_readers > 0 || authority->writer_active)
    g_cond_wait (&authority->changed, &authority->mutex);
  g_mutex_unlock (&authority->mutex);
  return WYRELOG_E_OK;
}

void
wyl_service_auth_authority_snapshot (WylServiceAuthAuthority *authority,
    WylServiceAuthAuthoritySnapshot *out_snapshot)
{
  if (authority == NULL || out_snapshot == NULL)
    return;
  g_mutex_lock (&authority->mutex);
  out_snapshot->active_readers = authority->active_readers;
  out_snapshot->waiting_writers = authority->waiting_writers;
  out_snapshot->writer_active = authority->writer_active;
  out_snapshot->closing = authority->closing;
  g_mutex_unlock (&authority->mutex);
}

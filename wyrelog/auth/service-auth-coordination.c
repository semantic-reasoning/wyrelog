/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "service-auth-coordination-private.h"

#include "wyrelog/wyl-handle-private.h"

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
  guint waiting_readers;
  guint waiting_writers;
  gboolean writer_active;
  gboolean closing;
  void (*close_checkpoint) (gpointer data);
  gpointer close_checkpoint_data;
  guint64 next_serial;
  guint64 writer_serial;
};

typedef struct
{
  WylHandle *handles[4];
  WylServiceAuthRank ranks[4];
  guint depth;
} WylServiceAuthRankState;

static GPrivate service_auth_rank_state = G_PRIVATE_INIT (g_free);

static WylServiceAuthRankState *
rank_state_get (gboolean create)
{
  WylServiceAuthRankState *state = g_private_get (&service_auth_rank_state);
  if (state == NULL && create) {
    state = g_new0 (WylServiceAuthRankState, 1);
    g_private_set (&service_auth_rank_state, state);
  }
  return state;
}

static gboolean
rank_can_enter (WylHandle *handle, WylServiceAuthRank rank)
{
  WylServiceAuthRankState *state = rank_state_get (FALSE);
  if (state == NULL || state->depth == 0)
    return TRUE;
  return state->depth < G_N_ELEMENTS (state->ranks)
      && state->handles[state->depth - 1] == handle
      && state->ranks[state->depth - 1] < rank;
}

static gboolean
rank_is_top (WylHandle *handle, WylServiceAuthRank rank)
{
  WylServiceAuthRankState *state = rank_state_get (FALSE);
  return state != NULL && state->depth > 0
      && state->handles[state->depth - 1] == handle
      && state->ranks[state->depth - 1] == rank;
}

wyrelog_error_t
wyl_service_auth_rank_enter (WylHandle *handle, WylServiceAuthRank rank)
{
  if (!WYL_IS_HANDLE (handle) || rank < WYL_SERVICE_AUTH_RANK_COORDINATION
      || rank > WYL_SERVICE_AUTH_RANK_REGISTRY
      || !rank_can_enter (handle, rank))
    return WYRELOG_E_BUSY;
  WylServiceAuthRankState *state = rank_state_get (TRUE);
  state->handles[state->depth] = handle;
  state->ranks[state->depth] = rank;
  state->depth++;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_rank_leave (WylHandle *handle, WylServiceAuthRank rank)
{
  WylServiceAuthRankState *state = rank_state_get (FALSE);
  if (!WYL_IS_HANDLE (handle) || state == NULL || state->depth == 0
      || state->handles[state->depth - 1] != handle
      || state->ranks[state->depth - 1] != rank)
    return WYRELOG_E_INVALID;
  state->depth--;
  state->handles[state->depth] = NULL;
  state->ranks[state->depth] = 0;
  return WYRELOG_E_OK;
}

struct _WylServiceAuthReadLease
{
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  GThread *owner;
  guint64 serial;
  WylServiceAuthLeaseState state;
  wyl_policy_store_t *pinned_store;
};

struct _WylServiceAuthWriteLease
{
  WylServiceAuthAuthority *authority;
  WylHandle *handle;
  GThread *owner;
  guint64 serial;
  WylServiceAuthLeaseState state;
  gboolean transaction_claimed;
  wyl_policy_store_t *pinned_store;
};

static gboolean
thread_owns_lease_locked (WylServiceAuthAuthority *authority, GThread *thread)
{
  return authority->writer_owner == thread
      || g_hash_table_contains (authority->reader_owners, thread);
}

static guint64
reader_serial_locked (WylServiceAuthAuthority *authority, GThread *thread)
{
  guint64 *serial = g_hash_table_lookup (authority->reader_owners, thread);
  return serial != NULL ? *serial : 0;
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
  authority->reader_owners = g_hash_table_new_full (g_direct_hash,
      g_direct_equal, NULL, g_free);
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
    WylHandle *handle, GCancellable *cancellable,
    WylServiceAuthReadLease **out_lease)
{
  if (out_lease != NULL)
    *out_lease = NULL;
  if (authority == NULL || !WYL_IS_HANDLE (handle) || out_lease == NULL
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  if (authority->handle != handle
      || !rank_can_enter (handle, WYL_SERVICE_AUTH_RANK_COORDINATION))
    return WYRELOG_E_BUSY;

  wyl_policy_store_t *pinned_store = NULL;
  wyrelog_error_t pin_rc = wyl_handle_policy_store_pin_current (handle,
      &pinned_store);
  if (pin_rc != WYRELOG_E_OK)
    return pin_rc;

  wyl_service_auth_authority_ref (authority);
  g_object_ref (handle);
  gulong cancel_id = connect_cancellable (cancellable, authority);
  GThread *thread = g_thread_self ();
  wyrelog_error_t rc = WYRELOG_E_OK;
  guint64 serial = 0;

  g_mutex_lock (&authority->mutex);
  if (thread_owns_lease_locked (authority, thread)) {
    rc = WYRELOG_E_BUSY;
  } else {
    authority->waiting_readers++;
    while (!authority->closing && !acquisition_cancelled (cancellable)
        && (authority->writer_active || authority->waiting_writers > 0))
      g_cond_wait (&authority->changed, &authority->mutex);
    authority->waiting_readers--;
    if (authority->closing || acquisition_cancelled (cancellable))
      rc = WYRELOG_E_BUSY;
    if (rc != WYRELOG_E_OK)
      g_cond_broadcast (&authority->changed);
  }
  if (rc == WYRELOG_E_OK)
    rc = next_serial_locked (authority, &serial);
  if (rc == WYRELOG_E_OK) {
    authority->active_readers++;
    guint64 *stored_serial = g_new (guint64, 1);
    *stored_serial = serial;
    g_hash_table_insert (authority->reader_owners, thread, stored_serial);
  }
  g_mutex_unlock (&authority->mutex);
  if (cancel_id != 0)
    g_cancellable_disconnect (cancellable, cancel_id);

  if (rc == WYRELOG_E_OK) {
    WylServiceAuthReadLease *lease = g_new0 (WylServiceAuthReadLease, 1);
    lease->authority = authority;
    lease->handle = handle;
    lease->owner = thread;
    lease->serial = serial;
    lease->state = WYL_SERVICE_AUTH_LEASE_ACTIVE;
    lease->pinned_store = pinned_store;
    g_assert_cmpint (wyl_service_auth_rank_enter (handle,
            WYL_SERVICE_AUTH_RANK_COORDINATION), ==, WYRELOG_E_OK);
    *out_lease = lease;
  } else {
    wyl_handle_policy_store_unpin (handle, pinned_store);
    g_object_unref (handle);
    wyl_service_auth_authority_unref (authority);
  }
  return rc;
}

wyrelog_error_t
wyl_service_auth_authority_acquire_write (WylServiceAuthAuthority *authority,
    WylHandle *handle, GCancellable *cancellable,
    WylServiceAuthWriteLease **out_lease)
{
  if (out_lease != NULL)
    *out_lease = NULL;
  if (authority == NULL || !WYL_IS_HANDLE (handle) || out_lease == NULL
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  if (authority->handle != handle
      || !rank_can_enter (handle, WYL_SERVICE_AUTH_RANK_COORDINATION))
    return WYRELOG_E_BUSY;

  wyl_policy_store_t *pinned_store = NULL;
  wyrelog_error_t pin_rc = wyl_handle_policy_store_pin_current (handle,
      &pinned_store);
  if (pin_rc != WYRELOG_E_OK)
    return pin_rc;

  wyl_service_auth_authority_ref (authority);
  g_object_ref (handle);
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
    authority->writer_serial = serial;
  }
  g_mutex_unlock (&authority->mutex);
  if (cancel_id != 0)
    g_cancellable_disconnect (cancellable, cancel_id);

  if (rc == WYRELOG_E_OK) {
    WylServiceAuthWriteLease *lease = g_new0 (WylServiceAuthWriteLease, 1);
    lease->authority = authority;
    lease->handle = handle;
    lease->owner = thread;
    lease->serial = serial;
    lease->state = WYL_SERVICE_AUTH_LEASE_ACTIVE;
    lease->pinned_store = pinned_store;
    g_assert_cmpint (wyl_service_auth_rank_enter (handle,
            WYL_SERVICE_AUTH_RANK_COORDINATION), ==, WYRELOG_E_OK);
    *out_lease = lease;
  } else {
    wyl_handle_policy_store_unpin (handle, pinned_store);
    g_object_unref (handle);
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
      || !rank_is_top (handle, WYL_SERVICE_AUTH_RANK_COORDINATION)
      || reader_serial_locked (lease->authority, lease->owner) != lease->serial)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_write_locked_at_rank (WylServiceAuthWriteLease *lease,
    WylHandle *handle, WylServiceAuthRank rank)
{
  if (lease->state != WYL_SERVICE_AUTH_LEASE_ACTIVE
      || lease->owner != g_thread_self () || lease->handle != handle
      || lease->authority->handle != handle || lease->serial == 0
      || !rank_is_top (handle, rank)
      || !lease->authority->writer_active
      || lease->authority->writer_owner != lease->owner
      || lease->authority->writer_serial != lease->serial)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_write_locked (WylServiceAuthWriteLease *lease, WylHandle *handle)
{
  return validate_write_locked_at_rank (lease, handle,
      lease->transaction_claimed ? WYL_SERVICE_AUTH_RANK_STORE
      : WYL_SERVICE_AUTH_RANK_COORDINATION);
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
wyl_service_auth_write_lease_get_policy_store (WylServiceAuthWriteLease *lease,
    WylHandle *handle, wyl_policy_store_t **out_store)
{
  if (out_store != NULL)
    *out_store = NULL;
  if (lease == NULL || !WYL_IS_HANDLE (handle) || out_store == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&lease->authority->mutex);
  wyrelog_error_t rc = validate_write_locked (lease, handle);
  if (rc == WYRELOG_E_OK && lease->pinned_store == NULL)
    rc = WYRELOG_E_INVALID;
  if (rc == WYRELOG_E_OK)
    *out_store = lease->pinned_store;
  g_mutex_unlock (&lease->authority->mutex);
  return rc;
}

wyrelog_error_t
    wyl_service_auth_write_lease_claim_transaction
    (WylServiceAuthWriteLease * lease, WylHandle * handle) {
  if (lease == NULL || !WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&lease->authority->mutex);
  wyrelog_error_t rc = validate_write_locked (lease, handle);
  if (rc == WYRELOG_E_OK && lease->transaction_claimed)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK)
    lease->transaction_claimed = TRUE;
  g_mutex_unlock (&lease->authority->mutex);
  return rc;
}

wyrelog_error_t
    wyl_service_auth_write_lease_unclaim_transaction
    (WylServiceAuthWriteLease * lease, WylHandle * handle) {
  if (lease == NULL || !WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&lease->authority->mutex);
  wyrelog_error_t rc = validate_write_locked_at_rank (lease, handle,
      WYL_SERVICE_AUTH_RANK_COORDINATION);
  if (rc == WYRELOG_E_OK && !lease->transaction_claimed)
    rc = WYRELOG_E_INVALID;
  if (rc == WYRELOG_E_OK)
    lease->transaction_claimed = FALSE;
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
    g_assert_cmpint (wyl_service_auth_rank_leave (lease->handle,
            WYL_SERVICE_AUTH_RANK_COORDINATION), ==, WYRELOG_E_OK);
    g_cond_broadcast (&authority->changed);
  }
  g_mutex_unlock (&authority->mutex);
  if (rc == WYRELOG_E_OK) {
    wyl_handle_policy_store_unpin (lease->handle, lease->pinned_store);
    lease->pinned_store = NULL;
  }
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
  if (rc == WYRELOG_E_OK && lease->transaction_claimed)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK) {
    lease->state = WYL_SERVICE_AUTH_LEASE_RELEASED;
    authority->writer_active = FALSE;
    authority->writer_owner = NULL;
    authority->writer_serial = 0;
    g_assert_cmpint (wyl_service_auth_rank_leave (lease->handle,
            WYL_SERVICE_AUTH_RANK_COORDINATION), ==, WYRELOG_E_OK);
    g_cond_broadcast (&authority->changed);
  }
  g_mutex_unlock (&authority->mutex);
  if (rc == WYRELOG_E_OK) {
    wyl_handle_policy_store_unpin (lease->handle, lease->pinned_store);
    lease->pinned_store = NULL;
  }
  return rc;
}

void
wyl_service_auth_read_lease_free (WylServiceAuthReadLease *lease)
{
  if (lease == NULL)
    return;
  if (lease->state == WYL_SERVICE_AUTH_LEASE_ACTIVE)
    if (wyl_service_auth_read_lease_release (lease) != WYRELOG_E_OK)
      return;
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
    if (wyl_service_auth_write_lease_release (lease) != WYRELOG_E_OK)
      return;
  g_clear_object (&lease->handle);
  wyl_service_auth_authority_unref (lease->authority);
  g_free (lease);
}

wyrelog_error_t
wyl_service_auth_authority_close (WylServiceAuthAuthority *authority)
{
  if (authority == NULL)
    return WYRELOG_E_INVALID;
  if (!rank_can_enter (authority->handle, WYL_SERVICE_AUTH_RANK_COORDINATION))
    return WYRELOG_E_BUSY;
  g_mutex_lock (&authority->mutex);
  if (thread_owns_lease_locked (authority, g_thread_self ())) {
    g_mutex_unlock (&authority->mutex);
    return WYRELOG_E_BUSY;
  }
  authority->closing = TRUE;
  g_cond_broadcast (&authority->changed);
  void (*checkpoint) (gpointer data) = authority->close_checkpoint;
  gpointer checkpoint_data = authority->close_checkpoint_data;
  authority->close_checkpoint = NULL;
  authority->close_checkpoint_data = NULL;
  g_mutex_unlock (&authority->mutex);
  if (checkpoint != NULL)
    checkpoint (checkpoint_data);
  g_mutex_lock (&authority->mutex);
  while (authority->active_readers > 0 || authority->writer_active
      || authority->waiting_readers > 0 || authority->waiting_writers > 0)
    g_cond_wait (&authority->changed, &authority->mutex);
  g_mutex_unlock (&authority->mutex);
  return WYRELOG_E_OK;
}

void wyl_service_auth_authority_set_close_checkpoint
    (WylServiceAuthAuthority * authority,
    void (*checkpoint) (gpointer data), gpointer data)
{
  g_return_if_fail (authority != NULL);
  g_mutex_lock (&authority->mutex);
  authority->close_checkpoint = checkpoint;
  authority->close_checkpoint_data = data;
  g_mutex_unlock (&authority->mutex);
}

void
wyl_service_auth_authority_snapshot (WylServiceAuthAuthority *authority,
    WylServiceAuthAuthoritySnapshot *out_snapshot)
{
  if (authority == NULL || out_snapshot == NULL)
    return;
  g_mutex_lock (&authority->mutex);
  out_snapshot->active_readers = authority->active_readers;
  out_snapshot->waiting_readers = authority->waiting_readers;
  out_snapshot->waiting_writers = authority->waiting_writers;
  out_snapshot->writer_active = authority->writer_active;
  out_snapshot->closing = authority->closing;
  g_mutex_unlock (&authority->mutex);
}

void
wyl_service_auth_read_lease_test_corrupt_serial (WylServiceAuthReadLease *lease)
{
  if (lease != NULL)
    lease->serial ^= G_GUINT64_CONSTANT (1) << 63;
}

void wyl_service_auth_write_lease_test_corrupt_serial
    (WylServiceAuthWriteLease * lease)
{
  if (lease != NULL)
    lease->serial ^= G_GUINT64_CONSTANT (1) << 63;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth-registry-private.h"

#include <string.h>

#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-id-private.h"

typedef struct
{
  gatomicrefcount ref_count;
  WylServiceAuthReservation reservation;
  WylServiceAuthState state;
  WylServiceAuthAllocator allocator;
} ServiceAuthEntry;

struct _WylServiceAuthRegistry
{
  gatomicrefcount ref_count;
  GMutex mutex;
  GHashTable *by_session;
  GHashTable *by_jti;
  WylServiceAuthAllocator allocator;
};

static gpointer
default_try_alloc (gsize size, gpointer user_data)
{
  (void) user_data;
  return g_try_malloc (size);
}

static void
default_free (gpointer memory, gpointer user_data)
{
  (void) user_data;
  g_free (memory);
}

static void
reservation_clear_with_allocator (const WylServiceAuthAllocator *allocator,
    WylServiceAuthReservation *reservation)
{
  if (reservation == NULL)
    return;

  if (reservation->session_id != NULL)
    allocator->free (reservation->session_id, allocator->user_data);
  if (reservation->jti != NULL)
    allocator->free (reservation->jti, allocator->user_data);
  if (reservation->credential_id != NULL)
    allocator->free (reservation->credential_id, allocator->user_data);
  if (reservation->principal != NULL)
    allocator->free (reservation->principal, allocator->user_data);
  if (reservation->tenant != NULL)
    allocator->free (reservation->tenant, allocator->user_data);
  memset (reservation, 0, sizeof *reservation);
}

static void
entry_free (gpointer data)
{
  ServiceAuthEntry *entry = data;
  if (!g_atomic_ref_count_dec (&entry->ref_count))
    return;
  WylServiceAuthAllocator allocator = entry->allocator;

  reservation_clear_with_allocator (&allocator, &entry->reservation);
  allocator.free (entry, allocator.user_data);
}

static ServiceAuthEntry *
entry_ref (ServiceAuthEntry *entry)
{
  g_atomic_ref_count_inc (&entry->ref_count);
  return entry;
}

static gboolean
uuidv7_is_canonical (const gchar *value)
{
  wyl_id_t id;
  gchar formatted[WYL_ID_STRING_BUF];

  if (value == NULL || strlen (value) != WYL_ID_STRING_LEN
      || wyl_id_parse (value, &id) != WYRELOG_E_OK
      || wyl_id_format (&id, formatted, sizeof formatted) != WYRELOG_E_OK)
    return FALSE;
  return strcmp (value, formatted) == 0;
}

static gboolean
reservation_is_valid (const WylServiceAuthReservation *reservation)
{
  if (reservation == NULL || !uuidv7_is_canonical (reservation->session_id)
      || !uuidv7_is_canonical (reservation->jti)
      || strcmp (reservation->session_id, reservation->jti) == 0
      || reservation->credential_id == NULL
      || !wyl_service_credential_id_is_canonical
      (reservation->credential_id, strlen (reservation->credential_id))
      || reservation->principal == NULL
      || !wyl_policy_service_subject_is_valid (reservation->principal,
          strlen (reservation->principal))
      || !wyl_policy_store_tenant_id_is_valid (reservation->tenant)
      || reservation->generation < 1)
    return FALSE;
  return TRUE;
}

static gchar *
try_strdup_with_allocator (const WylServiceAuthAllocator *allocator,
    const gchar *value)
{
  gsize size = strlen (value) + 1;
  gchar *copy = allocator->try_alloc (size, allocator->user_data);

  if (copy != NULL)
    memcpy (copy, value, size);
  return copy;
}

static wyrelog_error_t
reservation_copy_with_allocator (const WylServiceAuthAllocator *allocator,
    const WylServiceAuthReservation *source,
    WylServiceAuthReservation *destination)
{
  WylServiceAuthReservation copy = { 0 };

  copy.session_id = try_strdup_with_allocator (allocator, source->session_id);
  if (copy.session_id == NULL)
    goto nomem;
  copy.jti = try_strdup_with_allocator (allocator, source->jti);
  if (copy.jti == NULL)
    goto nomem;
  copy.credential_id = try_strdup_with_allocator (allocator,
      source->credential_id);
  if (copy.credential_id == NULL)
    goto nomem;
  copy.principal = try_strdup_with_allocator (allocator, source->principal);
  if (copy.principal == NULL)
    goto nomem;
  copy.tenant = try_strdup_with_allocator (allocator, source->tenant);
  if (copy.tenant == NULL)
    goto nomem;
  copy.generation = source->generation;

  copy._free = allocator->free;
  copy._free_data = allocator->user_data;
  *destination = copy;
  return WYRELOG_E_OK;

nomem:
  reservation_clear_with_allocator (allocator, &copy);
  return WYRELOG_E_NOMEM;
}

static gboolean
reservation_equal (const WylServiceAuthReservation *left,
    const WylServiceAuthReservation *right)
{
  return left->generation == right->generation
      && strcmp (left->session_id, right->session_id) == 0
      && strcmp (left->jti, right->jti) == 0
      && strcmp (left->credential_id, right->credential_id) == 0
      && strcmp (left->principal, right->principal) == 0
      && strcmp (left->tenant, right->tenant) == 0;
}

static wyrelog_error_t
find_exact_locked (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation, ServiceAuthEntry **out_entry)
{
  ServiceAuthEntry *by_session = g_hash_table_lookup (registry->by_session,
      reservation->session_id);
  ServiceAuthEntry *by_jti = g_hash_table_lookup (registry->by_jti,
      reservation->jti);

  *out_entry = NULL;
  if (by_session == NULL && by_jti == NULL)
    return WYRELOG_E_NOT_FOUND;
  if (by_session == NULL || by_jti == NULL || by_session != by_jti
      || !reservation_equal (&by_session->reservation, reservation))
    return WYRELOG_E_POLICY;
  *out_entry = by_session;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
registry_new_with_allocator (const WylServiceAuthAllocator *allocator,
    WylServiceAuthRegistry **out_registry)
{
  WylServiceAuthRegistry *registry;

  if (out_registry == NULL)
    return WYRELOG_E_INVALID;
  *out_registry = NULL;
  if (allocator == NULL || allocator->try_alloc == NULL
      || allocator->free == NULL)
    return WYRELOG_E_INVALID;

  registry = g_try_new0 (WylServiceAuthRegistry, 1);
  if (registry == NULL)
    return WYRELOG_E_NOMEM;
  g_atomic_ref_count_init (&registry->ref_count);
  g_mutex_init (&registry->mutex);
  registry->allocator = *allocator;

  /*
   * by_session solely owns entries and their string keys.  by_jti borrows
   * both.  GLib container allocation is process-fatal on OOM and therefore
   * intentionally outside this API's recoverable allocator contract.
   */
  registry->by_session = g_hash_table_new_full (g_str_hash, g_str_equal,
      NULL, entry_free);
  registry->by_jti = g_hash_table_new (g_str_hash, g_str_equal);
  *out_registry = registry;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_registry_new (WylServiceAuthRegistry **out_registry)
{
  WylServiceAuthAllocator allocator = {
    .try_alloc = default_try_alloc,
    .free = default_free,
  };
  return registry_new_with_allocator (&allocator, out_registry);
}

#ifdef WYL_AUTH_REGISTRY_TESTING
wyrelog_error_t
    wyl_service_auth_registry_new_with_allocator
    (const WylServiceAuthAllocator * allocator,
    WylServiceAuthRegistry ** out_registry)
{
  return registry_new_with_allocator (allocator, out_registry);
}
#endif

WylServiceAuthRegistry *
wyl_service_auth_registry_ref (WylServiceAuthRegistry *registry)
{
  if (registry != NULL)
    g_atomic_ref_count_inc (&registry->ref_count);
  return registry;
}

void
wyl_service_auth_registry_unref (WylServiceAuthRegistry *registry)
{
  if (registry == NULL || !g_atomic_ref_count_dec (&registry->ref_count))
    return;

  g_hash_table_destroy (registry->by_jti);
  g_hash_table_destroy (registry->by_session);
  g_mutex_clear (&registry->mutex);
  g_free (registry);
}

void
wyl_service_auth_registry_clear (WylServiceAuthRegistry *registry)
{
  GHashTable *old_by_session;
  GHashTable *old_by_jti;
  GHashTable *new_by_session;
  GHashTable *new_by_jti;

  if (registry == NULL)
    return;

  /* GLib container OOM is process-fatal, as documented by new(). */
  new_by_session = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
      entry_free);
  new_by_jti = g_hash_table_new (g_str_hash, g_str_equal);

  g_mutex_lock (&registry->mutex);
  old_by_session = registry->by_session;
  old_by_jti = registry->by_jti;
  registry->by_session = new_by_session;
  registry->by_jti = new_by_jti;
  g_mutex_unlock (&registry->mutex);

  /* The borrowed index must disappear before its owning entries. */
  g_hash_table_destroy (old_by_jti);
  g_hash_table_destroy (old_by_session);
}

wyrelog_error_t
wyl_service_auth_registry_reserve (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation)
{
  ServiceAuthEntry *entry;
  wyrelog_error_t rc;

  if (registry == NULL || !reservation_is_valid (reservation))
    return WYRELOG_E_INVALID;

  entry = registry->allocator.try_alloc (sizeof *entry,
      registry->allocator.user_data);
  if (entry == NULL)
    return WYRELOG_E_NOMEM;
  memset (entry, 0, sizeof *entry);
  g_atomic_ref_count_init (&entry->ref_count);
  entry->allocator = registry->allocator;
  entry->state = WYL_SERVICE_AUTH_PENDING;
  rc = reservation_copy_with_allocator (&registry->allocator, reservation,
      &entry->reservation);
  if (rc != WYRELOG_E_OK) {
    entry_free (entry);
    return rc;
  }

  g_mutex_lock (&registry->mutex);
  if (g_hash_table_contains (registry->by_session, reservation->session_id)
      || g_hash_table_contains (registry->by_jti, reservation->jti)) {
    g_mutex_unlock (&registry->mutex);
    entry_free (entry);
    return WYRELOG_E_POLICY;
  }
  g_hash_table_insert (registry->by_session, entry->reservation.session_id,
      entry);
  g_hash_table_insert (registry->by_jti, entry->reservation.jti, entry);
  g_mutex_unlock (&registry->mutex);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_registry_activate (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation, gboolean *out_changed)
{
  ServiceAuthEntry *entry;
  wyrelog_error_t rc;

  if (out_changed != NULL)
    *out_changed = FALSE;
  if (registry == NULL || out_changed == NULL
      || !reservation_is_valid (reservation))
    return WYRELOG_E_INVALID;

  g_mutex_lock (&registry->mutex);
  rc = find_exact_locked (registry, reservation, &entry);
  if (rc != WYRELOG_E_OK) {
    g_mutex_unlock (&registry->mutex);
    return rc;
  }
  if (entry->state != WYL_SERVICE_AUTH_PENDING) {
    g_mutex_unlock (&registry->mutex);
    return WYRELOG_E_POLICY;
  }
  entry->state = WYL_SERVICE_AUTH_ACTIVE;
  *out_changed = TRUE;
  g_mutex_unlock (&registry->mutex);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_registry_revoke_exact (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation, gboolean *out_changed)
{
  ServiceAuthEntry *entry;
  wyrelog_error_t rc;

  if (out_changed != NULL)
    *out_changed = FALSE;
  if (registry == NULL || out_changed == NULL
      || !reservation_is_valid (reservation))
    return WYRELOG_E_INVALID;

  g_mutex_lock (&registry->mutex);
  rc = find_exact_locked (registry, reservation, &entry);
  if (rc != WYRELOG_E_OK) {
    g_mutex_unlock (&registry->mutex);
    return rc;
  }
  if (entry->state != WYL_SERVICE_AUTH_REVOKED) {
    entry->state = WYL_SERVICE_AUTH_REVOKED;
    *out_changed = TRUE;
  }
  g_mutex_unlock (&registry->mutex);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_registry_remove_exact (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation, gboolean *out_removed)
{
  ServiceAuthEntry *by_session;
  ServiceAuthEntry *by_jti;

  if (out_removed != NULL)
    *out_removed = FALSE;
  if (registry == NULL || out_removed == NULL
      || !reservation_is_valid (reservation))
    return WYRELOG_E_INVALID;

  g_mutex_lock (&registry->mutex);
  by_session = g_hash_table_lookup (registry->by_session,
      reservation->session_id);
  by_jti = g_hash_table_lookup (registry->by_jti, reservation->jti);
  if (by_session == NULL && by_jti == NULL) {
    g_mutex_unlock (&registry->mutex);
    return WYRELOG_E_OK;
  }
  if (by_session == NULL || by_jti == NULL || by_session != by_jti
      || !reservation_equal (&by_session->reservation, reservation)) {
    g_mutex_unlock (&registry->mutex);
    return WYRELOG_E_POLICY;
  }

  g_hash_table_remove (registry->by_jti, by_jti->reservation.jti);
  g_hash_table_steal (registry->by_session, by_session->reservation.session_id);
  *out_removed = TRUE;
  g_mutex_unlock (&registry->mutex);
  entry_free (by_session);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_auth_registry_lookup (WylServiceAuthRegistry *registry,
    const gchar *session_id, const gchar *jti,
    WylServiceAuthReservation *out_reservation,
    WylServiceAuthState *out_state, gboolean *out_found)
{
  ServiceAuthEntry *by_session = NULL;
  ServiceAuthEntry *by_jti;
  WylServiceAuthReservation copy = { 0 };
  WylServiceAuthState state = WYL_SERVICE_AUTH_PENDING;
  wyrelog_error_t rc = WYRELOG_E_OK;

  if (registry == NULL || out_reservation == NULL || out_state == NULL
      || out_found == NULL) {
    rc = WYRELOG_E_INVALID;
    goto reset_outputs;
  }
  if (!uuidv7_is_canonical (session_id) || !uuidv7_is_canonical (jti)
      || strcmp (session_id, jti) == 0) {
    rc = WYRELOG_E_INVALID;
    goto reset_outputs;
  }

  g_mutex_lock (&registry->mutex);
  by_session = g_hash_table_lookup (registry->by_session, session_id);
  by_jti = g_hash_table_lookup (registry->by_jti, jti);
  if (by_session == NULL && by_jti == NULL) {
    by_session = NULL;
  } else if (by_session == NULL || by_jti == NULL || by_session != by_jti) {
    by_session = NULL;
    rc = WYRELOG_E_POLICY;
  } else {
    by_session = entry_ref (by_session);
    state = by_session->state;
  }
  g_mutex_unlock (&registry->mutex);

reset_outputs:
  if (out_reservation != NULL) {
    if (out_reservation->_free != NULL)
      wyl_service_auth_reservation_clear (out_reservation);
    else
      memset (out_reservation, 0, sizeof *out_reservation);
  }
  if (out_state != NULL)
    *out_state = WYL_SERVICE_AUTH_PENDING;
  if (out_found != NULL)
    *out_found = FALSE;
  if (by_session == NULL)
    return rc;

  rc = reservation_copy_with_allocator (&registry->allocator,
      &by_session->reservation, &copy);
  if (rc == WYRELOG_E_OK) {
    *out_reservation = copy;
    *out_state = state;
    *out_found = TRUE;
  }
  entry_free (by_session);
  return rc;
}

void
wyl_service_auth_reservation_clear (WylServiceAuthReservation *reservation)
{
  WylServiceAuthAllocator allocator;

  if (reservation == NULL || reservation->_free == NULL)
    return;
  allocator.try_alloc = NULL;
  allocator.free = reservation->_free;
  allocator.user_data = reservation->_free_data;
  reservation_clear_with_allocator (&allocator, reservation);
}

#ifdef WYL_AUTH_REGISTRY_TESTING
gboolean
    wyl_service_auth_registry_check_invariants_for_test
    (WylServiceAuthRegistry * registry) {
  GHashTableIter iter;
  gpointer key;
  gpointer value;
  gboolean valid = TRUE;

  if (registry == NULL)
    return FALSE;
  g_mutex_lock (&registry->mutex);
  if (g_hash_table_size (registry->by_session)
      != g_hash_table_size (registry->by_jti))
    valid = FALSE;
  g_hash_table_iter_init (&iter, registry->by_session);
  while (valid && g_hash_table_iter_next (&iter, &key, &value)) {
    ServiceAuthEntry *entry = value;
    if (key != entry->reservation.session_id
        || g_hash_table_lookup (registry->by_jti,
            entry->reservation.jti) != entry
        || entry->state < WYL_SERVICE_AUTH_PENDING
        || entry->state > WYL_SERVICE_AUTH_REVOKED)
      valid = FALSE;
  }
  g_mutex_unlock (&registry->mutex);
  return valid;
}

gsize
wyl_service_auth_registry_size_for_test (WylServiceAuthRegistry *registry)
{
  gsize size;

  if (registry == NULL)
    return 0;
  g_mutex_lock (&registry->mutex);
  size = g_hash_table_size (registry->by_session);
  g_mutex_unlock (&registry->mutex);
  return size;
}
#endif

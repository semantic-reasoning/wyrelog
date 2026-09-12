/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "tenant-admission-private.h"

#include <string.h>

typedef struct
{
  gatomicrefcount ref_count;
  gchar *tenant_id;
  GCond changed;
  WylFactTenantAdmissionState state;
  guint active_readers;
  guint waiting_readers;
  guint waiting_writers;
  gboolean active_writer;
  guint64 next_serial;
} TenantEntry;

struct _WylFactTenantAdmissionManager
{
  gatomicrefcount ref_count;
  GMutex lock;
  GCond changed;
  GHashTable *entries;
  GHashTable *active_leases;
  gboolean shutting_down;
};

struct _WylFactTenantAdmissionLease
{
  WylFactTenantAdmissionManager *manager;
  TenantEntry *entry;
  GThread *owner;
  guint64 serial;
  gboolean writer;
  gboolean released;
};

static gboolean
tenant_id_valid (const gchar *tenant_id)
{
  if (tenant_id == NULL || *tenant_id == '\0' || strlen (tenant_id) > 128)
    return FALSE;
  for (const guchar *p = (const guchar *) tenant_id; *p != '\0'; p++)
    if (!g_ascii_isalnum (*p) && *p != '.' && *p != '_' && *p != ':'
        && *p != '-')
      return FALSE;
  return TRUE;
}

static TenantEntry *
entry_ref (TenantEntry *entry)
{
  if (entry != NULL)
    g_atomic_ref_count_inc (&entry->ref_count);
  return entry;
}

static void
entry_unref (TenantEntry *entry)
{
  if (entry == NULL || !g_atomic_ref_count_dec (&entry->ref_count))
    return;
  g_cond_clear (&entry->changed);
  g_free (entry->tenant_id);
  g_free (entry);
}

static TenantEntry *
entry_new (const gchar *tenant_id)
{
  TenantEntry *entry = g_try_new0 (TenantEntry, 1);
  if (entry == NULL)
    return NULL;
  g_atomic_ref_count_init (&entry->ref_count);
  entry->tenant_id = g_strdup (tenant_id);
  if (entry->tenant_id == NULL) {
    entry_unref (entry);
    return NULL;
  }
  g_cond_init (&entry->changed);
  return entry;
}

static TenantEntry *
lookup_or_create_locked (WylFactTenantAdmissionManager *manager,
    const gchar *tenant_id, gboolean create)
{
  TenantEntry *entry = g_hash_table_lookup (manager->entries, tenant_id);
  if (entry != NULL)
    return entry_ref (entry);
  if (!create)
    return NULL;
  entry = entry_new (tenant_id);
  if (entry == NULL)
    return NULL;
  g_hash_table_insert (manager->entries, entry->tenant_id, entry);
  return entry_ref (entry);
}

wyrelog_error_t
wyl_fact_tenant_admission_manager_new
  (WylFactTenantAdmissionManager **out_manager)
{
  if (out_manager == NULL)
    return WYRELOG_E_INVALID;
  *out_manager = NULL;
  WylFactTenantAdmissionManager *manager = g_try_new0
        (WylFactTenantAdmissionManager, 1);
  if (manager == NULL)
    return WYRELOG_E_NOMEM;
  g_atomic_ref_count_init (&manager->ref_count);
  g_mutex_init (&manager->lock);
  g_cond_init (&manager->changed);
  manager->entries = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
          (GDestroyNotify) entry_unref);
  manager->active_leases = g_hash_table_new (g_direct_hash, g_direct_equal);
  *out_manager = manager;
  return WYRELOG_E_OK;
}

WylFactTenantAdmissionManager *
wyl_fact_tenant_admission_manager_ref (WylFactTenantAdmissionManager *manager)
{
  if (manager != NULL)
    g_atomic_ref_count_inc (&manager->ref_count);
  return manager;
}

wyrelog_error_t
wyl_fact_tenant_admission_manager_shutdown
  (WylFactTenantAdmissionManager *manager)
{
  if (manager == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&manager->lock);
  if (!manager->shutting_down) {
    manager->shutting_down = TRUE;
    GHashTableIter iter;
    gpointer value;
    g_hash_table_iter_init (&iter, manager->entries);
    while (g_hash_table_iter_next (&iter, NULL, &value)) {
      TenantEntry *entry = value;
      entry->state = entry->active_writer || entry->active_readers > 0
          ? WYL_FACT_TENANT_ADMISSION_CLOSING
          : WYL_FACT_TENANT_ADMISSION_CLOSED;
      g_cond_broadcast (&entry->changed);
    }
  }
  for (;;) {
    gboolean owned = FALSE;
    GHashTableIter iter;
    gpointer key;
    g_hash_table_iter_init (&iter, manager->active_leases);
    while (g_hash_table_iter_next (&iter, &key, NULL)) {
      WylFactTenantAdmissionLease *lease = key;
      if (lease->owner == g_thread_self ()) {
        owned = TRUE;
        break;
      }
    }
    if (owned) {
      g_mutex_unlock (&manager->lock);
      return WYRELOG_E_BUSY;
    }
    if (g_hash_table_size (manager->active_leases) == 0)
      break;
    g_cond_wait (&manager->changed, &manager->lock);
  }
  g_mutex_unlock (&manager->lock);
  return WYRELOG_E_OK;
}

void
wyl_fact_tenant_admission_manager_unref
  (WylFactTenantAdmissionManager *manager)
{
  if (manager == NULL || !g_atomic_ref_count_dec (&manager->ref_count))
    return;
  wyl_fact_tenant_admission_manager_shutdown (manager);
  g_hash_table_destroy (manager->active_leases);
  g_hash_table_destroy (manager->entries);
  g_cond_clear (&manager->changed);
  g_mutex_clear (&manager->lock);
  g_free (manager);
}

static gboolean
thread_holds_read_lease_locked (WylFactTenantAdmissionManager *manager,
    TenantEntry *entry, GThread *thread)
{
  GHashTableIter iter;
  gpointer key;
  g_hash_table_iter_init (&iter, manager->active_leases);
  while (g_hash_table_iter_next (&iter, &key, NULL)) {
    WylFactTenantAdmissionLease *lease = key;
    if (!lease->writer && lease->entry == entry && lease->owner == thread)
      return TRUE;
  }
  return FALSE;
}

static gboolean
lease_can_acquire (WylFactTenantAdmissionManager *manager, TenantEntry *entry,
    gboolean writer, GThread *thread)
{
  return entry->state == WYL_FACT_TENANT_ADMISSION_OPEN
         && !entry->active_writer
         && (writer ? entry->active_readers == 0
                 : entry->waiting_writers == 0
         || thread_holds_read_lease_locked (manager, entry, thread));
}

static wyrelog_error_t
acquire (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    gboolean writer, GCancellable *cancellable,
    WylFactTenantAdmissionLease **out_lease)
{
  if (out_lease != NULL)
    *out_lease = NULL;
  if (manager == NULL || !tenant_id_valid (tenant_id) || out_lease == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&manager->lock);
  TenantEntry *entry = lookup_or_create_locked (manager, tenant_id, TRUE);
  if (entry == NULL) {
    g_mutex_unlock (&manager->lock);
    return WYRELOG_E_NOMEM;
  }
  if (manager->shutting_down) {
    g_mutex_unlock (&manager->lock);
    entry_unref (entry);
    return WYRELOG_E_BUSY;
  }
  if (writer)
    entry->waiting_writers++;
  else
    entry->waiting_readers++;
  wyrelog_error_t rc = WYRELOG_E_OK;
  while (!lease_can_acquire (manager, entry, writer, g_thread_self ())) {
    if (manager->shutting_down || entry->state != WYL_FACT_TENANT_ADMISSION_OPEN) {
      rc = WYRELOG_E_BUSY;
      break;
    }
    if (cancellable != NULL && g_cancellable_is_cancelled (cancellable)) {
      rc = WYRELOG_E_CANCELLED;
      break;
    }
    g_cond_wait_until (&entry->changed, &manager->lock,
        g_get_monotonic_time () + 1000);
  }
  if (writer)
    entry->waiting_writers--;
  else
    entry->waiting_readers--;
  if (rc == WYRELOG_E_OK) {
    WylFactTenantAdmissionLease *lease = g_try_new0
          (WylFactTenantAdmissionLease, 1);
    if (lease == NULL)
      rc = WYRELOG_E_NOMEM;
    else {
      lease->manager = wyl_fact_tenant_admission_manager_ref (manager);
      lease->entry = entry_ref (entry);
      lease->owner = g_thread_self ();
      lease->writer = writer;
      lease->serial = ++entry->next_serial;
      if (writer)
        entry->active_writer = TRUE;
      else
        entry->active_readers++;
      g_hash_table_insert (manager->active_leases, lease, lease);
      *out_lease = lease;
    }
  }
  g_cond_broadcast (&entry->changed);
  g_mutex_unlock (&manager->lock);
  entry_unref (entry);
  return rc;
}

wyrelog_error_t
wyl_fact_tenant_admission_acquire_read
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    GCancellable *cancellable, WylFactTenantAdmissionLease **out_lease)
{
  return acquire (manager, tenant_id, FALSE, cancellable, out_lease);
}

wyrelog_error_t
wyl_fact_tenant_admission_acquire_write
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    GCancellable *cancellable, WylFactTenantAdmissionLease **out_lease)
{
  return acquire (manager, tenant_id, TRUE, cancellable, out_lease);
}

wyrelog_error_t
wyl_fact_tenant_admission_lease_validate
  (WylFactTenantAdmissionLease *lease, const gchar *tenant_id)
{
  if (lease == NULL || lease->released || lease->owner != g_thread_self ()
      || !tenant_id_valid (tenant_id)
      || g_strcmp0 (lease->entry->tenant_id, tenant_id) != 0)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_tenant_admission_lease_release
  (WylFactTenantAdmissionLease *lease)
{
  if (lease == NULL)
    return WYRELOG_E_INVALID;
  if (lease->released)
    return WYRELOG_E_INVALID;
  if (lease->owner != g_thread_self ())
    return WYRELOG_E_BUSY;
  {
    g_mutex_lock (&lease->manager->lock);
    if (lease->writer)
      lease->entry->active_writer = FALSE;
    else if (lease->entry->active_readers > 0)
      lease->entry->active_readers--;
    if (!lease->entry->active_writer && lease->entry->active_readers == 0
        && lease->entry->state == WYL_FACT_TENANT_ADMISSION_CLOSING)
      lease->entry->state = WYL_FACT_TENANT_ADMISSION_CLOSED;
    lease->released = TRUE;
    g_hash_table_remove (lease->manager->active_leases, lease);
    g_cond_broadcast (&lease->entry->changed);
    g_cond_broadcast (&lease->manager->changed);
    g_mutex_unlock (&lease->manager->lock);
  }
  if (lease->released) {
    entry_unref (lease->entry);
    wyl_fact_tenant_admission_manager_unref (lease->manager);
    g_free (lease);
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
set_state (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    WylFactTenantAdmissionState state)
{
  if (manager == NULL || !tenant_id_valid (tenant_id))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&manager->lock);
  TenantEntry *entry = lookup_or_create_locked (manager, tenant_id, TRUE);
  if (entry == NULL) {
    g_mutex_unlock (&manager->lock);
    return WYRELOG_E_NOMEM;
  }
  wyrelog_error_t rc = manager->shutting_down ? WYRELOG_E_BUSY : WYRELOG_E_OK;
  if (rc == WYRELOG_E_OK && state == WYL_FACT_TENANT_ADMISSION_CLOSED
      && (entry->active_writer || entry->active_readers > 0))
    entry->state = WYL_FACT_TENANT_ADMISSION_CLOSING;
  else if (rc == WYRELOG_E_OK && state == WYL_FACT_TENANT_ADMISSION_OPEN
      && entry->state == WYL_FACT_TENANT_ADMISSION_CLOSING)
    rc = WYRELOG_E_BUSY;
  else if (rc == WYRELOG_E_OK)
    entry->state = state;
  g_cond_broadcast (&entry->changed);
  g_mutex_unlock (&manager->lock);
  entry_unref (entry);
  return rc;
}

wyrelog_error_t
wyl_fact_tenant_admission_close
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id)
{
  return set_state (manager, tenant_id, WYL_FACT_TENANT_ADMISSION_CLOSED);
}

wyrelog_error_t
wyl_fact_tenant_admission_open
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id)
{
  return set_state (manager, tenant_id, WYL_FACT_TENANT_ADMISSION_OPEN);
}

wyrelog_error_t
wyl_fact_tenant_admission_get_state
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    WylFactTenantAdmissionState *out_state, guint *out_readers,
    guint *out_waiters)
{
  if (manager == NULL || !tenant_id_valid (tenant_id) || out_state == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&manager->lock);
  TenantEntry *entry = lookup_or_create_locked (manager, tenant_id, FALSE);
  if (entry == NULL) {
    g_mutex_unlock (&manager->lock);
    return WYRELOG_E_NOT_FOUND;
  }
  *out_state = entry->state;
  if (out_readers != NULL)
    *out_readers = entry->active_readers;
  if (out_waiters != NULL)
    *out_waiters = entry->waiting_readers + entry->waiting_writers;
  g_mutex_unlock (&manager->lock);
  entry_unref (entry);
  return WYRELOG_E_OK;
}

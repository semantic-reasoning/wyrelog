/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif

#include "fact/root-writer-lease-private.h"

#ifndef G_OS_WIN32
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

struct _WylFactRootWriterLease
{
  WylFactGraphResolver resolver;
  gchar *registry_key;
  WylFactRootWriterLease *borrowed_parent;
  WylFactRootWriterLeaseBorrowScope *borrowed_scope;
  gint ref_count;
};

static GMutex root_lease_registry_mutex;
static GHashTable *root_lease_registry;
static GPrivate borrowed_root_lease_scope = G_PRIVATE_INIT (NULL);

static void
root_writer_lease_unref (WylFactRootWriterLease *lease)
{
  if (!g_atomic_int_dec_and_test (&lease->ref_count))
    return;
  if (lease->borrowed_parent != NULL) {
    WylFactRootWriterLease *parent = lease->borrowed_parent;
    g_atomic_int_add (&lease->borrowed_scope->active_children, -1);
    wyl_fact_graph_resolver_clear (&lease->resolver);
    g_free (lease->registry_key);
    g_free (lease);
    root_writer_lease_unref (parent);
    return;
  }
  g_mutex_lock (&root_lease_registry_mutex);
  if (root_lease_registry != NULL && lease->registry_key != NULL
      && g_hash_table_lookup (root_lease_registry,
      lease->registry_key) == lease)
    g_hash_table_remove (root_lease_registry, lease->registry_key);
  wyl_fact_graph_resolver_clear (&lease->resolver);
  g_mutex_unlock (&root_lease_registry_mutex);
  g_free (lease->registry_key);
  g_free (lease);
}

static GHashTable *
root_lease_registry_get (void)
{
  if (root_lease_registry == NULL)
    root_lease_registry = g_hash_table_new (g_str_hash, g_str_equal);
  return root_lease_registry;
}

static gchar *
root_identity_key (const WylFactGraphResolver *resolver)
{
  return g_strdup_printf ("%" G_GUINT64_FORMAT ":%" G_GUINT64_FORMAT,
             resolver->device, resolver->inode);
}

static wyrelog_error_t
lock_root_nonblocking (gint fd)
{
  if (flock (fd, LOCK_EX | LOCK_NB) == 0)
    return WYRELOG_E_OK;
  return errno == EWOULDBLOCK || errno == EAGAIN ? WYRELOG_E_BUSY :
         WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_root_writer_lease_acquire (const gchar *fact_root,
    WylFactRootWriterLease **out_lease)
{
  if (out_lease != NULL)
    *out_lease = NULL;
  if (fact_root == NULL || fact_root[0] == '\0' || out_lease == NULL)
    return WYRELOG_E_INVALID;

  WylFactRootWriterLease *lease = g_new0 (WylFactRootWriterLease, 1);
  g_atomic_int_set (&lease->ref_count, 1);
  lease->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  wyrelog_error_t rc = wyl_fact_graph_resolver_open (fact_root,
          &lease->resolver);
  if (rc != WYRELOG_E_OK)
    goto fail;
  lease->registry_key = root_identity_key (&lease->resolver);

  WylFactRootWriterLeaseBorrowScope *scope =
      g_private_get (&borrowed_root_lease_scope);
  for (; scope != NULL; scope = scope->previous_scope) {
    WylFactRootWriterLease *parent = scope->lease;
    if (g_strcmp0 (parent->registry_key, lease->registry_key) != 0)
      continue;
    rc = wyl_fact_root_writer_lease_verify (parent);
    if (rc == WYRELOG_E_OK
        && (parent->resolver.device != lease->resolver.device
        || parent->resolver.inode != lease->resolver.inode))
      rc = WYRELOG_E_POLICY;
    if (rc != WYRELOG_E_OK)
      goto fail;
    lease->borrowed_parent = parent;
    lease->borrowed_scope = scope;
    g_atomic_int_inc (&parent->ref_count);
    g_atomic_int_inc (&scope->active_children);
    *out_lease = lease;
    return WYRELOG_E_OK;
  }

  g_mutex_lock (&root_lease_registry_mutex);
  if (g_hash_table_contains (root_lease_registry_get (), lease->registry_key))
    rc = WYRELOG_E_BUSY;
  else
    rc = lock_root_nonblocking (lease->resolver.fd);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (&lease->resolver);
  if (rc == WYRELOG_E_OK)
    g_hash_table_insert (root_lease_registry_get (), lease->registry_key,
        lease);
  g_mutex_unlock (&root_lease_registry_mutex);
  if (rc != WYRELOG_E_OK)
    goto fail;

  *out_lease = lease;
  return WYRELOG_E_OK;

fail:
  wyl_fact_graph_resolver_clear (&lease->resolver);
  g_free (lease->registry_key);
  g_free (lease);
  return rc;
}

wyrelog_error_t
wyl_fact_root_writer_lease_borrow_scope_begin
  (WylFactRootWriterLease *lease,
    WylFactRootWriterLeaseBorrowScope *scope)
{
  if (lease == NULL || scope == NULL || scope->active)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc != WYRELOG_E_OK)
    return rc;
  scope->lease = lease;
  scope->previous_scope = g_private_get (&borrowed_root_lease_scope);
  scope->owner_thread = g_thread_self ();
  g_atomic_int_set (&scope->active_children, 0);
  scope->active = TRUE;
  g_atomic_int_inc (&lease->ref_count);
  g_private_set (&borrowed_root_lease_scope, scope);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_root_writer_lease_borrow_scope_end
  (WylFactRootWriterLeaseBorrowScope *scope)
{
  if (scope == NULL || !scope->active)
    return WYRELOG_E_INVALID;
  if (scope->owner_thread != g_thread_self ())
    return WYRELOG_E_INVALID;
  if (g_private_get (&borrowed_root_lease_scope) != scope)
    return WYRELOG_E_INVALID;
  if (g_atomic_int_get (&scope->active_children) != 0)
    return WYRELOG_E_BUSY;
  g_private_set (&borrowed_root_lease_scope, scope->previous_scope);
  WylFactRootWriterLease *lease = scope->lease;
  scope->lease = NULL;
  scope->previous_scope = NULL;
  scope->owner_thread = NULL;
  scope->active = FALSE;
  root_writer_lease_unref (lease);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_root_writer_lease_verify (WylFactRootWriterLease *lease)
{
  if (lease == NULL || lease->resolver.fd < 0 || lease->registry_key == NULL)
    return WYRELOG_E_INVALID;
  if (lease->borrowed_parent != NULL) {
    wyrelog_error_t parent_rc =
        wyl_fact_root_writer_lease_verify (lease->borrowed_parent);
    if (parent_rc != WYRELOG_E_OK)
      return parent_rc;
    if (lease->borrowed_parent->resolver.device != lease->resolver.device
        || lease->borrowed_parent->resolver.inode != lease->resolver.inode)
      return WYRELOG_E_POLICY;
  }
  struct stat st;
  if (fstat (lease->resolver.fd, &st) != 0)
    return WYRELOG_E_IO;
  if (!S_ISDIR (st.st_mode)
      || (guint64) st.st_dev != lease->resolver.device
      || (guint64) st.st_ino != lease->resolver.inode)
    return WYRELOG_E_POLICY;
  return wyl_fact_graph_resolver_revalidate (&lease->resolver);
}

wyrelog_error_t
wyl_fact_root_writer_lease_authorizes_resolver
  (WylFactRootWriterLease * lease, WylFactGraphResolver * resolver) {
  if (lease == NULL || resolver == NULL || resolver->fd < 0)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK
      && (lease->resolver.device != resolver->device
      || lease->resolver.inode != resolver->inode))
    rc = WYRELOG_E_POLICY;
  return rc;
}

void
wyl_fact_root_writer_lease_release (WylFactRootWriterLease *lease)
{
  if (lease == NULL)
    return;
  /* The final reference closes the resolver and releases the kernel flock. */
  root_writer_lease_unref (lease);
}
#endif

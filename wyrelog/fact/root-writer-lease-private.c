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
};

static GMutex root_lease_registry_mutex;
static GHashTable *root_lease_registry;

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
  lease->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  wyrelog_error_t rc = wyl_fact_graph_resolver_open (fact_root,
      &lease->resolver);
  if (rc != WYRELOG_E_OK)
    goto fail;
  lease->registry_key = root_identity_key (&lease->resolver);

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
wyl_fact_root_writer_lease_verify (WylFactRootWriterLease *lease)
{
  if (lease == NULL || lease->resolver.fd < 0 || lease->registry_key == NULL)
    return WYRELOG_E_INVALID;
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
  g_mutex_lock (&root_lease_registry_mutex);
  if (root_lease_registry != NULL && lease->registry_key != NULL
      && g_hash_table_lookup (root_lease_registry,
          lease->registry_key) == lease)
    g_hash_table_remove (root_lease_registry, lease->registry_key);
  /* Closing the resolver fd releases the kernel flock.  Do not issue an
   * explicit unlock: keeping authority until the final close avoids a gap. */
  wyl_fact_graph_resolver_clear (&lease->resolver);
  g_mutex_unlock (&root_lease_registry_mutex);
  g_free (lease->registry_key);
  g_free (lease);
}
#endif

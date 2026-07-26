/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#endif
#include "fact/graph-artifact-namespace-private.h"
#include <string.h>

#ifdef G_OS_WIN32
struct WylFactArtifactNamespace
{
  gint unused;
};
struct WylFactArtifactMutationLease
{
  gint unused;
};
static wyrelog_error_t
closed (void)
{
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_namespace_open (const WylFactGraphDirectory *d,
    WylFactArtifactNamespace **o)
{
  (void) d;
  if (o)
    *o = NULL;
  return closed ();
}

void
wyl_fact_artifact_namespace_free (WylFactArtifactNamespace *n)
{
  (void) n;
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate (WylFactArtifactNamespace *n)
{
  (void) n;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_reader_guard (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **o)
{
  (void) n;
  if (o)
    *o = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_mutation_lease (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **o)
{
  (void) n;
  if (o)
    *o = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_revalidate (WylFactArtifactMutationLease *l)
{
  (void) l;
  return closed ();
}

void
wyl_fact_artifact_mutation_lease_free (WylFactArtifactMutationLease *l)
{
  (void) l;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_file (WylFactArtifactMutationLease *l,
    WylFactArtifactName a, gboolean c, gboolean w, gint *o)
{
  (void) l;
  (void) a;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_temp (WylFactArtifactMutationLease *l,
    const gchar *t, gboolean c, gboolean w, gint *o)
{
  (void) l;
  (void) t;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_unlink (WylFactArtifactMutationLease *l,
    WylFactArtifactName a)
{
  (void) l;
  (void) a;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_rename (WylFactArtifactMutationLease *l,
    WylFactArtifactName a, WylFactArtifactName b)
{
  (void) l;
  (void) a;
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_file (WylFactArtifactNamespace *n,
    WylFactArtifactName a, gboolean c, gboolean w, gint *o)
{
  (void) n;
  (void) a;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_unlink (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  (void) n;
  (void) a;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  (void) n;
  (void) a;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_lock (WylFactArtifactNamespace *n, gboolean e,
    gint *o)
{
  (void) n;
  (void) e;
  if (o)
    *o = -1;
  return !n || !o ? WYRELOG_E_INVALID : closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_bind_main (WylFactArtifactNamespace *n)
{
  (void) n;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate_main (WylFactArtifactNamespace *n)
{
  (void) n;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_temp (WylFactArtifactNamespace *n,
    const gchar *t, gboolean c, gboolean w, gint *o)
{
  (void) n;
  (void) t;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_rename (WylFactArtifactNamespace *n,
    WylFactArtifactName a, WylFactArtifactName b)
{
  (void) n;
  (void) a;
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync_directory (WylFactArtifactNamespace *n)
{
  (void) n;
  return closed ();
}
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
typedef struct WylFactArtifactLockDomain WylFactArtifactLockDomain;
struct WylFactArtifactNamespace
{
  gint references;
  gint fd;
  guint64 device, inode;
  gint main_fd;
  guint64 main_device, main_inode;
  gint lock_pin_fd;
  guint64 lock_device, lock_inode;
  WylFactArtifactLockDomain *lock_domain;
};
struct WylFactArtifactLockDomain
{
  guint64 directory_device, directory_inode;
  gint pin_fd;
  guint64 lock_device, lock_inode;
  guint references;
};
struct WylFactArtifactMutationLease
{
  WylFactArtifactNamespace *namespace_;
  gint lock_fd;
  guint64 directory_device, directory_inode;
  guint64 lock_device, lock_inode;
  gboolean exclusive;
};
static const gchar *names[] =
    { "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",
  "facts.duckdb.wal.recovery", "facts.duckdb.lock", NULL
};

static GMutex lock_domains_mutex;
static GPtrArray *lock_domains;
static void release_lock_domain (WylFactArtifactNamespace *);

static const gchar *
name_for (WylFactArtifactName n)
{
  return n <= WYL_FACT_ARTIFACT_LOCK ? names[n] : NULL;
}

static gboolean
valid (WylFactArtifactName n)
{
  return n <= WYL_FACT_ARTIFACT_LOCK;
}

static wyrelog_error_t
named_regular (WylFactArtifactNamespace *n, const gchar *name,
    gboolean allow_missing)
{
  struct stat s;
  if (fstatat (n->fd, name, &s, AT_SYMLINK_NOFOLLOW) != 0)
    return allow_missing && errno == ENOENT ? WYRELOG_E_OK :
        (errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO);
  return S_ISREG (s.st_mode) && s.st_nlink == 1 ? WYRELOG_E_OK :
      WYRELOG_E_POLICY;
}

static wyrelog_error_t
check (WylFactArtifactNamespace *n)
{
  struct stat s;
  if (!n || n->fd < 0 || fstat (n->fd, &s) || !S_ISDIR (s.st_mode)
      || (guint64) s.st_dev != n->device || (guint64) s.st_ino != n->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static WylFactArtifactNamespace *
namespace_ref (WylFactArtifactNamespace *n)
{
  if (n)
    g_atomic_int_inc (&n->references);
  return n;
}

static void
namespace_unref (WylFactArtifactNamespace *n)
{
  if (!n || !g_atomic_int_dec_and_test (&n->references))
    return;
  if (n->fd >= 0)
    close (n->fd);
  if (n->main_fd >= 0)
    close (n->main_fd);
  if (n->lock_pin_fd >= 0)
    close (n->lock_pin_fd);
  release_lock_domain (n);
  g_free (n);
}

static wyrelog_error_t
lock_stat_matches (WylFactArtifactNamespace *n, gint fd,
    guint64 device, guint64 inode)
{
  struct stat held, named;
  if (check (n) != WYRELOG_E_OK || fd < 0 || fstat (fd, &held) != 0
      || !S_ISREG (held.st_mode) || held.st_nlink != 1
      || (guint64) held.st_dev != device || (guint64) held.st_ino != inode)
    return WYRELOG_E_POLICY;
  if (fstatat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK), &named,
          AT_SYMLINK_NOFOLLOW) != 0)
    return WYRELOG_E_POLICY;
  return S_ISREG (named.st_mode) && named.st_nlink == 1
      && (guint64) named.st_dev == device && (guint64) named.st_ino == inode
      ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
lock_open_error (gint error)
{
  return error == ELOOP || error == EISDIR || error == ENOTDIR
      ? WYRELOG_E_POLICY :
      (error == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO);
}

/* The retained pin is never used for flock.  Every guard gets a separately
 * opened file description so the kernel sees real independent lock holders. */
static wyrelog_error_t
open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!n || !out_fd)
    return WYRELOG_E_INVALID;
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;

  if (n->lock_pin_fd < 0) {
    gboolean created = FALSE;
    gint pin = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),
        O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
        0600);
    if (pin >= 0)
      created = TRUE;
    else if (errno == EEXIST)
      pin = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),
          O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (pin < 0)
      return lock_open_error (errno);
    struct stat s;
    if (fstat (pin, &s) != 0 || !S_ISREG (s.st_mode) || s.st_nlink != 1) {
      close (pin);
      return WYRELOG_E_POLICY;
    }
    if (lock_stat_matches (n, pin, s.st_dev, s.st_ino) != WYRELOG_E_OK) {
      close (pin);
      return WYRELOG_E_POLICY;
    }
    if (created && fsync (n->fd) != 0) {
      close (pin);
      return WYRELOG_E_IO;
    }
    if (lock_stat_matches (n, pin, s.st_dev, s.st_ino) != WYRELOG_E_OK) {
      close (pin);
      return WYRELOG_E_POLICY;
    }
    n->lock_pin_fd = pin;
    n->lock_device = s.st_dev;
    n->lock_inode = s.st_ino;
  }

  if (lock_stat_matches (n, n->lock_pin_fd, n->lock_device,
          n->lock_inode) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  gint fd = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),
      O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return lock_open_error (errno);
  if (lock_stat_matches (n, fd, n->lock_device, n->lock_inode)
      != WYRELOG_E_OK) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

static WylFactArtifactLockDomain *
find_lock_domain (guint64 device, guint64 inode)
{
  if (!lock_domains)
    return NULL;
  for (guint i = 0; i < lock_domains->len; i++) {
    WylFactArtifactLockDomain *domain = g_ptr_array_index (lock_domains, i);
    if (domain->directory_device == device && domain->directory_inode == inode)
      return domain;
  }
  return NULL;
}

/* A process-wide domain makes every live namespace for the same held
 * directory reject a replaced lock entry instead of silently splitting into
 * two flock domains.  The namespace-local duplicate keeps lease lifetime
 * independent from other namespace objects. */
static wyrelog_error_t
pin_lock_domain (WylFactArtifactNamespace *n)
{
  g_mutex_lock (&lock_domains_mutex);
  WylFactArtifactLockDomain *domain = find_lock_domain (n->device, n->inode);
  if (domain) {
    gint pin = dup (domain->pin_fd);
    if (pin < 0) {
      g_mutex_unlock (&lock_domains_mutex);
      return WYRELOG_E_IO;
    }
    n->lock_pin_fd = pin;
    n->lock_device = domain->lock_device;
    n->lock_inode = domain->lock_inode;
    n->lock_domain = domain;
    domain->references++;
    wyrelog_error_t r = lock_stat_matches (n, pin, n->lock_device,
        n->lock_inode);
    if (r != WYRELOG_E_OK) {
      domain->references--;
      n->lock_domain = NULL;
      n->lock_pin_fd = -1;
      close (pin);
    }
    g_mutex_unlock (&lock_domains_mutex);
    return r;
  }

  gint fd = -1;
  wyrelog_error_t r = open_checked_lock (n, &fd);
  if (r != WYRELOG_E_OK) {
    g_mutex_unlock (&lock_domains_mutex);
    return r;
  }
  close (fd);
  domain = g_new0 (WylFactArtifactLockDomain, 1);
  domain->directory_device = n->device;
  domain->directory_inode = n->inode;
  domain->pin_fd = dup (n->lock_pin_fd);
  if (domain->pin_fd < 0) {
    g_free (domain);
    close (n->lock_pin_fd);
    n->lock_pin_fd = -1;
    g_mutex_unlock (&lock_domains_mutex);
    return WYRELOG_E_IO;
  }
  domain->lock_device = n->lock_device;
  domain->lock_inode = n->lock_inode;
  domain->references = 1;
  if (!lock_domains)
    lock_domains = g_ptr_array_new ();
  g_ptr_array_add (lock_domains, domain);
  n->lock_domain = domain;
  g_mutex_unlock (&lock_domains_mutex);
  return WYRELOG_E_OK;
}

static void
release_lock_domain (WylFactArtifactNamespace *n)
{
  if (!n->lock_domain)
    return;
  g_mutex_lock (&lock_domains_mutex);
  WylFactArtifactLockDomain *domain = n->lock_domain;
  g_assert_cmpuint (domain->references, >, 0);
  if (--domain->references == 0) {
    for (guint i = 0; i < lock_domains->len; i++)
      if (g_ptr_array_index (lock_domains, i) == domain) {
        g_ptr_array_remove_index_fast (lock_domains, i);
        break;
      }
    close (domain->pin_fd);
    g_free (domain);
  }
  n->lock_domain = NULL;
  g_mutex_unlock (&lock_domains_mutex);
}

static wyrelog_error_t open_file_unchecked (WylFactArtifactNamespace *,
    WylFactArtifactName, gboolean, gboolean, gint *);
static wyrelog_error_t unlink_unchecked (WylFactArtifactNamespace *,
    WylFactArtifactName);
static wyrelog_error_t rename_unchecked (WylFactArtifactNamespace *,
    WylFactArtifactName, WylFactArtifactName);
static wyrelog_error_t open_temp_unchecked (WylFactArtifactNamespace *,
    const gchar *, gboolean, gboolean, gint *);

wyrelog_error_t
wyl_fact_artifact_namespace_open (const WylFactGraphDirectory *d,
    WylFactArtifactNamespace **o)
{
  if (o)
    *o = NULL;
  if (!d || !o || d->graph_fd < 0)
    return WYRELOG_E_INVALID;
  gint fd = dup (d->graph_fd);
  if (fd < 0)
    return WYRELOG_E_IO;
  struct stat s;
  if (fstat (fd, &s) || !S_ISDIR (s.st_mode)) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  WylFactArtifactNamespace *n = g_new0 (WylFactArtifactNamespace, 1);
  n->references = 1;
  n->fd = fd;
  n->main_fd = -1;
  n->lock_pin_fd = -1;
  n->device = s.st_dev;
  n->inode = s.st_ino;
  /* Pin and register before publishing n: no concurrent namespace can choose
   * a different inode for this held graph directory. */
  wyrelog_error_t lock_result = pin_lock_domain (n);
  if (lock_result != WYRELOG_E_OK) {
    close (n->fd);
    g_free (n);
    return lock_result;
  }
  *o = n;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_namespace_free (WylFactArtifactNamespace *n)
{
  namespace_unref (n);
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate (WylFactArtifactNamespace *n)
{
  return check (n);
}

static wyrelog_error_t
acquire_lease (WylFactArtifactNamespace *n, gboolean exclusive,
    WylFactArtifactMutationLease **out_lease)
{
  if (out_lease)
    *out_lease = NULL;
  if (!n || !out_lease)
    return WYRELOG_E_INVALID;
  gint fd = -1;
  wyrelog_error_t r = open_checked_lock (n, &fd);
  if (r != WYRELOG_E_OK)
    return r;
  if (flock (fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0) {
    close (fd);
    return errno == EWOULDBLOCK || errno == EAGAIN ? WYRELOG_E_BUSY :
        WYRELOG_E_IO;
  }
  WylFactArtifactMutationLease *lease =
      g_new0 (WylFactArtifactMutationLease, 1);
  lease->namespace_ = namespace_ref (n);
  lease->lock_fd = fd;
  lease->directory_device = n->device;
  lease->directory_inode = n->inode;
  lease->lock_device = n->lock_device;
  lease->lock_inode = n->lock_inode;
  lease->exclusive = exclusive;
  r = wyl_fact_artifact_mutation_lease_revalidate (lease);
  if (r != WYRELOG_E_OK) {
    wyl_fact_artifact_mutation_lease_free (lease);
    return r;
  }
  *out_lease = lease;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_reader_guard (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **out_lease)
{
  return acquire_lease (n, FALSE, out_lease);
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_mutation_lease (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **out_lease)
{
  return acquire_lease (n, TRUE, out_lease);
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_revalidate (WylFactArtifactMutationLease *l)
{
  if (!l || !l->namespace_ || l->lock_fd < 0
      || l->directory_device != l->namespace_->device
      || l->directory_inode != l->namespace_->inode
      || l->lock_device != l->namespace_->lock_device
      || l->lock_inode != l->namespace_->lock_inode)
    return WYRELOG_E_POLICY;
  return lock_stat_matches (l->namespace_, l->lock_fd, l->lock_device,
      l->lock_inode);
}

void
wyl_fact_artifact_mutation_lease_free (WylFactArtifactMutationLease *l)
{
  if (!l)
    return;
  if (l->lock_fd >= 0)
    close (l->lock_fd);
  namespace_unref (l->namespace_);
  g_free (l);
}

wyrelog_error_t
open_file_unchecked (WylFactArtifactNamespace *n,
    WylFactArtifactName a, gboolean create, gboolean writable, gint *o)
{
  if (o)
    *o = -1;
  if (!valid (a) || !o)
    return WYRELOG_E_INVALID;
  wyrelog_error_t r = check (n);
  if (r)
    return r;
  gint flags = (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW;
  if (create)
    flags |= O_CREAT | O_EXCL;
  gint fd = openat (n->fd, name_for (a), flags, 0600);
  if (fd < 0)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  struct stat s;
  if (fstat (fd, &s) != 0 || !S_ISREG (s.st_mode) || s.st_nlink != 1
      || check (n) != WYRELOG_E_OK) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *o = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_file (WylFactArtifactNamespace *n,
    WylFactArtifactName a, gboolean create, gboolean writable, gint *o)
{
  if (o)
    *o = -1;
  /* Direct namespace access is read-only.  A guard is required before any
   * writable descriptor can be handed to a caller. */
  if (a == WYL_FACT_ARTIFACT_LOCK || create || writable)
    return WYRELOG_E_POLICY;
  return open_file_unchecked (n, a, FALSE, FALSE, o);
}

wyrelog_error_t
unlink_unchecked (WylFactArtifactNamespace *n, WylFactArtifactName a)
{
  if (!valid (a))
    return WYRELOG_E_INVALID;
  wyrelog_error_t r = check (n);
  if (r)
    return r;
  r = named_regular (n, name_for (a), FALSE);
  if (r != WYRELOG_E_OK)
    return r;
  return unlinkat (n->fd, name_for (a), 0) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_artifact_namespace_unlink (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  (void) n;
  return valid (a) ? WYRELOG_E_POLICY : WYRELOG_E_INVALID;
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  gint fd = -1;
  wyrelog_error_t r =
      wyl_fact_artifact_namespace_open_file (n, a, FALSE, FALSE, &fd);
  if (r)
    return r;
  r = fsync (fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
  close (fd);
  return r;
}

wyrelog_error_t
wyl_fact_artifact_namespace_lock (WylFactArtifactNamespace *n, gboolean ex,
    gint *o)
{
  if (o)
    *o = -1;
  (void) ex;
  return !n || !o ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_namespace_bind_main (WylFactArtifactNamespace *n)
{
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  gint fd = -1;
  wyrelog_error_t r = wyl_fact_artifact_namespace_open_file
      (n, WYL_FACT_ARTIFACT_MAIN, FALSE, FALSE, &fd);
  if (r != WYRELOG_E_OK)
    return r;
  struct stat s;
  if (fstat (fd, &s) != 0) {
    close (fd);
    return WYRELOG_E_IO;
  }
  if (n->main_fd >= 0)
    close (n->main_fd);
  n->main_fd = fd;
  n->main_device = s.st_dev;
  n->main_inode = s.st_ino;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate_main (WylFactArtifactNamespace *n)
{
  struct stat s;
  if (!n || n->main_fd < 0 || check (n) != WYRELOG_E_OK
      || fstat (n->main_fd, &s) != 0 || !S_ISREG (s.st_mode)
      || s.st_nlink != 1 || (guint64) s.st_dev != n->main_device
      || (guint64) s.st_ino != n->main_inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static gboolean
temp_token_valid (const gchar *token)
{
  if (!token || !*token || strlen (token) > 48)
    return FALSE;
  for (const gchar * p = token; *p; p++)
    if (!(g_ascii_isalnum (*p) || *p == '-'))
      return FALSE;
  return TRUE;
}

wyrelog_error_t
open_temp_unchecked (WylFactArtifactNamespace *n,
    const gchar *token, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!out_fd || !temp_token_valid (token))
    return WYRELOG_E_INVALID;
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  g_autofree gchar *name = g_strdup_printf ("tmp-%s", token);
  gint flags = (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW;
  if (create)
    flags |= O_CREAT | O_EXCL;
  gint fd = openat (n->fd, name, flags, 0600);
  if (fd < 0)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  struct stat s;
  if (fstat (fd, &s) != 0 || !S_ISREG (s.st_mode) || s.st_nlink != 1
      || check (n) != WYRELOG_E_OK) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_temp (WylFactArtifactNamespace *n,
    const gchar *token, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (create || writable)
    return WYRELOG_E_POLICY;
  return open_temp_unchecked (n, token, FALSE, FALSE, out_fd);
}

wyrelog_error_t
rename_unchecked (WylFactArtifactNamespace *n,
    WylFactArtifactName source, WylFactArtifactName destination)
{
  if (!valid (source) || !valid (destination) || source == destination)
    return WYRELOG_E_INVALID;
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  wyrelog_error_t r = named_regular (n, name_for (source), FALSE);
  if (r != WYRELOG_E_OK)
    return r;
  r = named_regular (n, name_for (destination), TRUE);
  if (r != WYRELOG_E_OK)
    return r;
  if (renameat (n->fd, name_for (source), n->fd, name_for (destination)) != 0)
    return WYRELOG_E_IO;
  return fsync (n->fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_artifact_namespace_rename (WylFactArtifactNamespace *n,
    WylFactArtifactName source, WylFactArtifactName destination)
{
  (void) n;
  return !valid (source) || !valid (destination) || source == destination
      ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}

/* A post-check is mandatory even when the syscall reports an error: it may
 * have raced after changing the namespace.  A failed identity check wins so
 * callers never continue after observing a substituted lock or directory. */
static wyrelog_error_t
post_mutation_check (WylFactArtifactMutationLease *l, wyrelog_error_t result)
{
  wyrelog_error_t post = wyl_fact_artifact_mutation_lease_revalidate (l);
  return post == WYRELOG_E_OK ? result : post;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_file (WylFactArtifactMutationLease *l,
    WylFactArtifactName a, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!l || !out_fd)
    return WYRELOG_E_INVALID;
  if (create && !l->exclusive)
    return WYRELOG_E_POLICY;
  if (a == WYL_FACT_ARTIFACT_LOCK)
    return WYRELOG_E_POLICY;
  wyrelog_error_t r = wyl_fact_artifact_mutation_lease_revalidate (l);
  if (r != WYRELOG_E_OK)
    return r;
  r = open_file_unchecked (l->namespace_, a, create, writable, out_fd);
  if (!create)
    return r;
  r = post_mutation_check (l, r);
  if (r != WYRELOG_E_OK) {
    if (*out_fd >= 0) {
      close (*out_fd);
      *out_fd = -1;
    }
  }
  return r;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_temp (WylFactArtifactMutationLease *l,
    const gchar *token, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!l || !out_fd)
    return WYRELOG_E_INVALID;
  if (create && !l->exclusive)
    return WYRELOG_E_POLICY;
  wyrelog_error_t r = wyl_fact_artifact_mutation_lease_revalidate (l);
  if (r != WYRELOG_E_OK)
    return r;
  r = open_temp_unchecked (l->namespace_, token, create, writable, out_fd);
  if (!create)
    return r;
  r = post_mutation_check (l, r);
  if (r != WYRELOG_E_OK) {
    if (*out_fd >= 0) {
      close (*out_fd);
      *out_fd = -1;
    }
  }
  return r;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_unlink (WylFactArtifactMutationLease *l,
    WylFactArtifactName a)
{
  if (!l || !l->exclusive)
    return WYRELOG_E_POLICY;
  if (a == WYL_FACT_ARTIFACT_LOCK)
    return WYRELOG_E_POLICY;
  wyrelog_error_t r = wyl_fact_artifact_mutation_lease_revalidate (l);
  if (r != WYRELOG_E_OK)
    return r;
  r = unlink_unchecked (l->namespace_, a);
  return post_mutation_check (l, r);
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_rename (WylFactArtifactMutationLease *l,
    WylFactArtifactName source, WylFactArtifactName destination)
{
  if (!l || !l->exclusive)
    return WYRELOG_E_POLICY;
  if (source == WYL_FACT_ARTIFACT_LOCK || destination == WYL_FACT_ARTIFACT_LOCK)
    return WYRELOG_E_POLICY;
  wyrelog_error_t r = wyl_fact_artifact_mutation_lease_revalidate (l);
  if (r != WYRELOG_E_OK)
    return r;
  r = rename_unchecked (l->namespace_, source, destination);
  return post_mutation_check (l, r);
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync_directory (WylFactArtifactNamespace *n)
{
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  return fsync (n->fd) == 0 && check (n) == WYRELOG_E_OK
      ? WYRELOG_E_OK : WYRELOG_E_IO;
}
#endif

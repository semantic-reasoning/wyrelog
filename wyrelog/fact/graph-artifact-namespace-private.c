/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "fact/graph-artifact-namespace-private.h"

#ifdef G_OS_WIN32
struct WylFactArtifactNamespace
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
  return closed ();
}
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
struct WylFactArtifactNamespace
{
  gint fd;
  guint64 device, inode;
};
static const gchar *names[] =
    { "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",
  "facts.duckdb.wal.recovery", "facts.duckdb.lock", NULL
};

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
check (WylFactArtifactNamespace *n)
{
  struct stat s;
  if (!n || n->fd < 0 || fstat (n->fd, &s) || !S_ISDIR (s.st_mode)
      || (guint64) s.st_dev != n->device || (guint64) s.st_ino != n->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

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
  n->fd = fd;
  n->device = s.st_dev;
  n->inode = s.st_ino;
  *o = n;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_namespace_free (WylFactArtifactNamespace *n)
{
  if (n) {
    if (n->fd >= 0)
      close (n->fd);
    g_free (n);
  }
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate (WylFactArtifactNamespace *n)
{
  return check (n);
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_file (WylFactArtifactNamespace *n,
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
    flags |= O_CREAT;
  gint fd = openat (n->fd, name_for (a), flags, 0600);
  if (fd < 0)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  *o = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_unlink (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  if (!valid (a))
    return WYRELOG_E_INVALID;
  wyrelog_error_t r = check (n);
  if (r)
    return r;
  return unlinkat (n->fd, name_for (a),
      0) == 0 ? WYRELOG_E_OK : (errno ==
      ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO);
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
  gint fd = -1;
  wyrelog_error_t r =
      wyl_fact_artifact_namespace_open_file (n, WYL_FACT_ARTIFACT_LOCK, TRUE,
      TRUE, &fd);
  if (r)
    return r;
  if (flock (fd, (ex ? LOCK_EX : LOCK_SH) | LOCK_NB)) {
    close (fd);
    return errno == EWOULDBLOCK ? WYRELOG_E_BUSY : WYRELOG_E_IO;
  }
  *o = fd;
  return WYRELOG_E_OK;
}
#endif

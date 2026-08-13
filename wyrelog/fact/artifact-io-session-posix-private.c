/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32

#if !defined(__APPLE__)
#define _POSIX_C_SOURCE 200809L
#endif

#include "fact/artifact-io-session-private.h"
#include "fact/secure-duckdb-filesystem-test-faults-private.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

struct WylFactArtifactIoSession
{
  WylFactArtifactIoSessionKind kind;
  int fd;
  union
  {
    WylFactArtifactMainBinding *writer_main;
    WylFactArtifactReaderMainBinding *reader_main;
    WylFactArtifactSidecarBinding *writer_sidecar;
    WylFactArtifactReaderWalBinding *reader_wal;
    WylFactDuckdbTempChildBinding *temp_child;
  } binding;
};

static wyrelog_error_t
io_session_revalidate_unlocked (const WylFactArtifactIoSession *session)
{
  if (session == NULL || session->fd < 0)
    return WYRELOG_E_POLICY;
  switch (session->kind) {
    case WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN:
      return wyl_fact_artifact_main_binding_revalidate_fd (
        session->binding.writer_main, session->fd);
    case WYL_FACT_ARTIFACT_IO_SESSION_READER_MAIN:
      return wyl_fact_artifact_reader_main_binding_revalidate_fd (
        session->binding.reader_main, session->fd);
    case WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR:
      return wyl_fact_artifact_sidecar_binding_revalidate_fd (
        session->binding.writer_sidecar, session->fd);
    case WYL_FACT_ARTIFACT_IO_SESSION_READER_WAL:
      return wyl_fact_artifact_reader_wal_binding_revalidate_fd (
        session->binding.reader_wal, session->fd);
    case WYL_FACT_ARTIFACT_IO_SESSION_TEMP_CHILD:
      return wyl_fact_duckdb_temp_child_binding_revalidate_fd (
        session->binding.temp_child, session->fd);
  }
  return WYRELOG_E_POLICY;
}

static wyrelog_error_t
io_session_close_binding (WylFactArtifactIoSession *session)
{
  if (session == NULL || session->fd < 0)
    return WYRELOG_E_OK;

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  if (wyl_secure_duckdb_filesystem_take_test_fault (
        WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION))
    (void) close (session->fd);
#endif

  int fd = session->fd;
  wyrelog_error_t rc = WYRELOG_E_POLICY;
  switch (session->kind) {
    case WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN:
      rc = wyl_fact_artifact_main_binding_close (
        session->binding.writer_main, &fd);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_READER_MAIN:
      rc = wyl_fact_artifact_reader_main_binding_close (
        session->binding.reader_main, &fd);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR:
      rc = wyl_fact_artifact_sidecar_binding_close (
        session->binding.writer_sidecar, &fd);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_READER_WAL:
      rc = wyl_fact_artifact_reader_wal_binding_close (
        session->binding.reader_wal, &fd);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_TEMP_CHILD:
      rc = wyl_fact_duckdb_temp_child_binding_close (
        session->binding.temp_child, &fd);
      break;
  }
  session->fd = -1;
  return rc;
}

static void
io_session_free_binding (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return;
  switch (session->kind) {
    case WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN:
      g_clear_pointer (&session->binding.writer_main,
          wyl_fact_artifact_main_binding_free);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_READER_MAIN:
      g_clear_pointer (&session->binding.reader_main,
          wyl_fact_artifact_reader_main_binding_free);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR:
      g_clear_pointer (&session->binding.writer_sidecar,
          wyl_fact_artifact_sidecar_binding_free);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_READER_WAL:
      g_clear_pointer (&session->binding.reader_wal,
          wyl_fact_artifact_reader_wal_binding_free);
      break;
    case WYL_FACT_ARTIFACT_IO_SESSION_TEMP_CHILD:
      g_clear_pointer (&session->binding.temp_child,
          wyl_fact_duckdb_temp_child_binding_free);
      break;
  }
  if (session->fd >= 0) {
    (void) close (session->fd);
    session->fd = -1;
  }
}

wyrelog_error_t
wyl_fact_artifact_io_session_new_writer_main (
  WylFactArtifactMainBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session)
{
  if (out_session != NULL)
    *out_session = NULL;
  if (binding == NULL || fd < 0 || out_session == NULL)
    return WYRELOG_E_INVALID;
  WylFactArtifactIoSession *s = g_new0 (WylFactArtifactIoSession, 1);
  s->kind = WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN;
  s->fd = fd;
  s->binding.writer_main = binding;
  *out_session = s;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_new_reader_main (
  WylFactArtifactReaderMainBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session)
{
  if (out_session != NULL)
    *out_session = NULL;
  if (binding == NULL || fd < 0 || out_session == NULL)
    return WYRELOG_E_INVALID;
  WylFactArtifactIoSession *s = g_new0 (WylFactArtifactIoSession, 1);
  s->kind = WYL_FACT_ARTIFACT_IO_SESSION_READER_MAIN;
  s->fd = fd;
  s->binding.reader_main = binding;
  *out_session = s;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_new_writer_sidecar (
  WylFactArtifactSidecarBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session)
{
  if (out_session != NULL)
    *out_session = NULL;
  if (binding == NULL || fd < 0 || out_session == NULL)
    return WYRELOG_E_INVALID;
  WylFactArtifactIoSession *s = g_new0 (WylFactArtifactIoSession, 1);
  s->kind = WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR;
  s->fd = fd;
  s->binding.writer_sidecar = binding;
  *out_session = s;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_new_reader_wal (
  WylFactArtifactReaderWalBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session)
{
  if (out_session != NULL)
    *out_session = NULL;
  if (binding == NULL || fd < 0 || out_session == NULL)
    return WYRELOG_E_INVALID;
  WylFactArtifactIoSession *s = g_new0 (WylFactArtifactIoSession, 1);
  s->kind = WYL_FACT_ARTIFACT_IO_SESSION_READER_WAL;
  s->fd = fd;
  s->binding.reader_wal = binding;
  *out_session = s;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_new_temp_child (
  WylFactDuckdbTempChildBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session)
{
  if (out_session != NULL)
    *out_session = NULL;
  if (binding == NULL || fd < 0 || out_session == NULL)
    return WYRELOG_E_INVALID;
  WylFactArtifactIoSession *s = g_new0 (WylFactArtifactIoSession, 1);
  s->kind = WYL_FACT_ARTIFACT_IO_SESSION_TEMP_CHILD;
  s->fd = fd;
  s->binding.temp_child = binding;
  *out_session = s;
  return WYRELOG_E_OK;
}

WylFactArtifactIoSessionKind
wyl_fact_artifact_io_session_get_kind (const WylFactArtifactIoSession *session)
{
  return session != NULL ? session->kind : WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN;
}

wyrelog_error_t
wyl_fact_artifact_io_session_read (
  WylFactArtifactIoSession *session,
  guint64 offset,
  void *buf,
  gsize count,
  gsize *out_bytes_read)
{
  if (out_bytes_read != NULL)
    *out_bytes_read = 0;
  if (session == NULL || (count > 0 && buf == NULL) || out_bytes_read == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  ssize_t n = pread (session->fd, buf, count, (off_t) offset);
  if (n < 0)
    return WYRELOG_E_IO;

  rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_bytes_read = (gsize) n;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_write (
  WylFactArtifactIoSession *session,
  guint64 offset,
  const void *buf,
  gsize count,
  gsize *out_bytes_written)
{
  if (out_bytes_written != NULL)
    *out_bytes_written = 0;
  if (session == NULL || (count > 0 && buf == NULL) || out_bytes_written == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  ssize_t n = pwrite (session->fd, buf, count, (off_t) offset);
  if (n < 0)
    return WYRELOG_E_IO;

  rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_bytes_written = (gsize) n;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_flush (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (fsync (session->fd) != 0)
    return WYRELOG_E_IO;

  return io_session_revalidate_unlocked (session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_truncate (
  WylFactArtifactIoSession *session,
  guint64 size)
{
  if (session == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (ftruncate (session->fd, (off_t) size) != 0)
    return WYRELOG_E_IO;

  return io_session_revalidate_unlocked (session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_size (
  WylFactArtifactIoSession *session,
  guint64 *out_size)
{
  if (out_size != NULL)
    *out_size = 0;
  if (session == NULL || out_size == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  struct stat st;
  if (fstat (session->fd, &st) != 0)
    return WYRELOG_E_IO;

  rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_size = (guint64) st.st_size;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_last_modified (
  WylFactArtifactIoSession *session,
  guint64 *out_sec,
  guint32 *out_nsec)
{
  if (out_sec != NULL)
    *out_sec = 0;
  if (out_nsec != NULL)
    *out_nsec = 0;
  if (session == NULL || out_sec == NULL || out_nsec == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  struct stat st;
  if (fstat (session->fd, &st) != 0)
    return WYRELOG_E_IO;

  rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_sec = (guint64) st.st_mtime;
#if defined(__APPLE__)
  *out_nsec = (guint32) st.st_mtimespec.tv_nsec;
#else
  *out_nsec = (guint32) st.st_mtim.tv_nsec;
#endif
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_revalidate (WylFactArtifactIoSession *session)
{
  return io_session_revalidate_unlocked (session);
}

/* Revalidated close of the working descriptor (the security boundary), leaving
 * the binding object attached so the caller can retire or inspect it before
 * releasing it with wyl_fact_artifact_io_session_free.  Sets the descriptor to
 * -1 and, on success, the binding's io_open to FALSE. */
wyrelog_error_t
wyl_fact_artifact_io_session_close (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return WYRELOG_E_INVALID;
  return io_session_close_binding (session);
}

/* Terminal teardown: revalidated close of the working descriptor followed by
 * release of the binding object (dropping its mutation-lease reference and pin
 * descriptor) and the session itself. */
wyrelog_error_t
wyl_fact_artifact_io_session_finish (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = io_session_close_binding (session);
  io_session_free_binding (session);
  g_free (session);
  return rc;
}

void
wyl_fact_artifact_io_session_free (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return;
  io_session_free_binding (session);
  g_free (session);
}

void
wyl_fact_artifact_io_session_abort (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return;
  io_session_free_binding (session);
  g_free (session);
}

WylFactArtifactSidecarBinding *
wyl_fact_artifact_io_session_detach_writer_sidecar (
  WylFactArtifactIoSession *session)
{
  if (session == NULL || session->kind != WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR)
    return NULL;
  WylFactArtifactSidecarBinding *ret = session->binding.writer_sidecar;
  session->binding.writer_sidecar = NULL;
  return ret;
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_writer_main (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactMainBinding *binding = NULL;
  int fd = -1;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_mutation_lease_open_main_binding (lease, &binding, &fd);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_fact_artifact_io_session_new_writer_main (binding, fd, out_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_reader_main (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactReaderMainBinding *binding = NULL;
  int fd = -1;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_reader_guard_open_main_binding (lease, &binding, &fd);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_fact_artifact_io_session_new_reader_main (binding, fd, out_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_sidecar (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactName artifact,
  gboolean create_if_missing,
  gboolean writable,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactSidecarBinding *binding = NULL;
  int fd = -1;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  /* The two underlying authorities partition this space and each rejects the
   * other's half with WYRELOG_E_POLICY.  The narrow recovery authority is
   * writable-only and never creates; the general one refuses a writable open
   * that is not also a create.  Only (!create_if_missing && writable) belongs
   * to the recovery authority. */
  if (!create_if_missing && writable)
    rc = wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease, artifact, writable, &binding, &fd);
  else
    rc = wyl_fact_artifact_mutation_lease_open_sidecar_binding (lease, artifact, create_if_missing, writable, &binding, &fd);

  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_fact_artifact_io_session_new_writer_sidecar (binding, fd, out_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_reader_wal (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactReaderWalBinding *binding = NULL;
  int fd = -1;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_reader_guard_open_existing_wal_binding (lease, &binding, &fd);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_fact_artifact_io_session_new_reader_wal (binding, fd, out_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_create_temp_root (
  WylFactArtifactMutationLease *lease,
  WylFactDuckdbTempRoot **out_root)
{
  return wyl_fact_duckdb_temp_root_create (lease, out_root);
}

wyrelog_error_t
wyl_fact_artifact_io_session_create_temp_child (
  WylFactDuckdbTempRoot *root,
  const gchar *name,
  gboolean writable,
  WylFactDuckdbTempChild **out_child,
  WylFactArtifactIoSession **out_session,
  WylFactDuckdbTempOrphanEvidence **out_evidence)
{
  WylFactDuckdbTempChildBinding *binding = NULL;
  int fd = -1;
  wyrelog_error_t rc;

  if (out_child != NULL)
    *out_child = NULL;
  if (out_session != NULL)
    *out_session = NULL;
  if (out_evidence != NULL)
    *out_evidence = NULL;

  if (root == NULL || name == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_duckdb_temp_root_create_child_binding (root, name, out_child, &binding, &fd, out_evidence);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_fact_artifact_io_session_new_temp_child (binding, fd, out_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_existing_temp_child (
  WylFactDuckdbTempChild *child,
  gboolean writable,
  WylFactArtifactIoSession **out_session)
{
  WylFactDuckdbTempChildBinding *binding = NULL;
  int fd = -1;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (child == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_duckdb_temp_child_open_binding (child, writable, &binding, &fd);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_fact_artifact_io_session_new_temp_child (binding, fd, out_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_version_tag (
  WylFactArtifactIoSession *session,
  gchar **out_tag)
{
  guint64 size = 0;
  wyrelog_error_t rc;

  if (out_tag != NULL)
    *out_tag = NULL;
  if (session == NULL || session->fd < 0 || out_tag == NULL)
    return WYRELOG_E_INVALID;

  rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  struct stat st;
  if (fstat (session->fd, &st) != 0)
    return WYRELOG_E_IO;

  rc = io_session_revalidate_unlocked (session);
  if (rc != WYRELOG_E_OK)
    return rc;

  size = (guint64) st.st_size;
  *out_tag = g_strdup_printf ("posix:%llu:%llu:%" G_GUINT64_FORMAT,
          (unsigned long long) st.st_dev,
          (unsigned long long) st.st_ino,
          size);
  return *out_tag != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

#endif /* !G_OS_WIN32 */

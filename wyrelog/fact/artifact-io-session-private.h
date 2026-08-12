/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WYL_FACT_ARTIFACT_IO_SESSION_PRIVATE_H
#define WYL_FACT_ARTIFACT_IO_SESSION_PRIVATE_H

#include "wyrelog.h"
#include "fact/graph-artifact-namespace-private.h"
#include <glib.h>

G_BEGIN_DECLS

typedef struct WylFactArtifactIoSession WylFactArtifactIoSession;

typedef enum
{
  WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN,
  WYL_FACT_ARTIFACT_IO_SESSION_READER_MAIN,
  WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR,
  WYL_FACT_ARTIFACT_IO_SESSION_READER_WAL,
  WYL_FACT_ARTIFACT_IO_SESSION_TEMP_CHILD
} WylFactArtifactIoSessionKind;

/* High-level platform-neutral openers */

wyrelog_error_t wyl_fact_artifact_io_session_open_writer_main (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_open_reader_main (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_open_sidecar (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactName artifact,
  gboolean create_if_missing,
  gboolean writable,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_open_reader_wal (
  WylFactArtifactMutationLease *lease,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_create_temp_root (
  WylFactArtifactMutationLease *lease,
  WylFactDuckdbTempRoot **out_root);

wyrelog_error_t wyl_fact_artifact_io_session_create_temp_child (
  WylFactDuckdbTempRoot *root,
  const gchar *name,
  gboolean writable,
  WylFactDuckdbTempChild **out_child,
  WylFactArtifactIoSession **out_session,
  WylFactDuckdbTempOrphanEvidence **out_evidence);

wyrelog_error_t wyl_fact_artifact_io_session_open_existing_temp_child (
  WylFactDuckdbTempChild *child,
  gboolean writable,
  WylFactArtifactIoSession **out_session);

/* POSIX low-level constructor helpers */
#ifndef G_OS_WIN32
wyrelog_error_t wyl_fact_artifact_io_session_new_writer_main (
  WylFactArtifactMainBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_new_reader_main (
  WylFactArtifactReaderMainBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_new_writer_sidecar (
  WylFactArtifactSidecarBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_new_reader_wal (
  WylFactArtifactReaderWalBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session);

wyrelog_error_t wyl_fact_artifact_io_session_new_temp_child (
  WylFactDuckdbTempChildBinding *binding,
  int fd,
  WylFactArtifactIoSession **out_session);

WylFactArtifactSidecarBinding *
wyl_fact_artifact_io_session_detach_writer_sidecar (
  WylFactArtifactIoSession *session);
#endif /* !G_OS_WIN32 */

/* Platform-neutral bounded I/O session API */

WylFactArtifactIoSessionKind wyl_fact_artifact_io_session_get_kind (
  const WylFactArtifactIoSession *session);

wyrelog_error_t wyl_fact_artifact_io_session_read (
  WylFactArtifactIoSession *session,
  guint64 offset,
  void *buf,
  gsize count,
  gsize *out_bytes_read);

wyrelog_error_t wyl_fact_artifact_io_session_write (
  WylFactArtifactIoSession *session,
  guint64 offset,
  const void *buf,
  gsize count,
  gsize *out_bytes_written);

wyrelog_error_t wyl_fact_artifact_io_session_flush (
  WylFactArtifactIoSession *session);

wyrelog_error_t wyl_fact_artifact_io_session_truncate (
  WylFactArtifactIoSession *session,
  guint64 size);

wyrelog_error_t wyl_fact_artifact_io_session_size (
  WylFactArtifactIoSession *session,
  guint64 *out_size);

wyrelog_error_t wyl_fact_artifact_io_session_last_modified (
  WylFactArtifactIoSession *session,
  guint64 *out_sec,
  guint32 *out_nsec);

wyrelog_error_t wyl_fact_artifact_io_session_revalidate (
  WylFactArtifactIoSession *session);

wyrelog_error_t wyl_fact_artifact_io_session_close (
  WylFactArtifactIoSession *session);

wyrelog_error_t wyl_fact_artifact_io_session_finish (
  WylFactArtifactIoSession *session);

void wyl_fact_artifact_io_session_free (
  WylFactArtifactIoSession *session);

void wyl_fact_artifact_io_session_abort (
  WylFactArtifactIoSession *session);

wyrelog_error_t wyl_fact_artifact_io_session_version_tag (
  WylFactArtifactIoSession *session,
  gchar **out_tag);

G_END_DECLS

#endif /* WYL_FACT_ARTIFACT_IO_SESSION_PRIVATE_H */

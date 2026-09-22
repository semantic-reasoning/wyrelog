/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "fact/offline-restore-stage-private.h"

#include <errno.h>
#include <string.h>

#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#define RESTORE_STAGE_MAX_WRITE (1024u * 1024u)

struct WylFactOfflineRestoreStage
{
  WylFactGraphResolver *resolver;
  WylFactGraphDirectory *directory;
  WylFactRootWriterLease *writer_lease;
  WylFactGraphStage native_stage;
  guint64 bytes_written;
  guint64 expected_bytes;
  gboolean failed;
  gboolean finalized;
};

static gboolean
same_root (const WylFactGraphResolver *resolver,
    const WylFactGraphDirectory *directory)
{
#ifdef G_OS_WIN32
  return resolver->identity.volume_serial
         == directory->root_identity.volume_serial
         && memcmp (resolver->identity.file_id,
             directory->root_identity.file_id,
             sizeof resolver->identity.file_id) == 0;
#else
  return resolver->device == directory->root_device
         && resolver->inode == directory->root_inode;
#endif
}

static wyrelog_error_t
authority_revalidate (WylFactOfflineRestoreStage *stage)
{
  if (stage == NULL || stage->resolver == NULL || stage->directory == NULL
      || stage->writer_lease == NULL
      || !same_root (stage->resolver, stage->directory))
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify
        (stage->writer_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver
          (stage->writer_lease, stage->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (stage->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_revalidate
          (stage->directory, &stage->native_stage);
  return rc;
}

static void
stage_identity (const WylFactGraphStage *stage,
    WylFactArtifactInventoryIdentity *out_identity)
{
  memset (out_identity, 0, sizeof *out_identity);
#ifdef G_OS_WIN32
  out_identity->domain = stage->identity.volume_serial;
  memcpy (out_identity->object_bytes, stage->identity.file_id,
      sizeof out_identity->object_bytes);
  out_identity->object_width = sizeof out_identity->object_bytes;
#else
  out_identity->domain = stage->device;
  out_identity->object = stage->inode;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_stage_new (WylFactGraphResolver *resolver,
    WylFactGraphDirectory *directory, WylFactRootWriterLease *writer_lease,
    const gchar *operation_uuid, guint64 expected_bytes,
    WylFactOfflineRestoreStage **out_stage)
{
  if (out_stage != NULL)
    *out_stage = NULL;
  if (resolver == NULL || directory == NULL || writer_lease == NULL
      || operation_uuid == NULL || out_stage == NULL
      || expected_bytes == 0 || expected_bytes > G_MAXINT64
      || !same_root (resolver, directory))
    return WYRELOG_E_INVALID;

  WylFactOfflineRestoreStage *stage = g_try_new0
        (WylFactOfflineRestoreStage, 1);
  if (stage == NULL)
    return WYRELOG_E_NOMEM;
  stage->resolver = resolver;
  stage->directory = directory;
  stage->writer_lease = writer_lease;
  stage->expected_bytes = expected_bytes;
  stage->native_stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;

  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (writer_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (writer_lease,
            resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_create_exact (directory,
            operation_uuid, &stage->native_stage);
  if (rc == WYRELOG_E_OK)
    rc = authority_revalidate (stage);
  if (rc != WYRELOG_E_OK) {
    /* A post-create authority failure leaves a possible orphan. Never unlink
     * by name; close the held object and leave classification to recovery. */
    wyl_fact_graph_stage_clear (&stage->native_stage);
    g_free (stage);
    return rc;
  }
  *out_stage = stage;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_stage_revalidate (WylFactOfflineRestoreStage *stage)
{
  if (stage == NULL || stage->failed || stage->finalized)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = authority_revalidate (stage);
  if (rc != WYRELOG_E_OK)
    stage->failed = TRUE;
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_stage_write (WylFactOfflineRestoreStage *stage,
    guint64 offset, const guint8 *bytes, gsize length)
{
  if (stage == NULL || bytes == NULL || length == 0
      || length > RESTORE_STAGE_MAX_WRITE || stage->failed
      || stage->finalized || offset != stage->bytes_written
      || G_MAXUINT64 - stage->bytes_written < length
      || stage->bytes_written > stage->expected_bytes
      || (guint64) length > stage->expected_bytes - stage->bytes_written)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = authority_revalidate (stage);
  gsize written = 0;
  while (rc == WYRELOG_E_OK && written < length) {
#ifdef G_OS_WIN32
    int n = _write (stage->native_stage.fd, bytes + written,
            (unsigned int) (length - written));
#else
    ssize_t n = write (stage->native_stage.fd, bytes + written,
            length - written);
#endif
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      rc = WYRELOG_E_IO;
      break;
    }
    written += (gsize) n;
  }
  if (rc == WYRELOG_E_OK) {
    stage->bytes_written += written;
    rc = authority_revalidate (stage);
  }
  if (rc != WYRELOG_E_OK)
    stage->failed = TRUE;
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_stage_finalize (WylFactOfflineRestoreStage *stage,
    guint64 *out_bytes_written,
    WylFactArtifactInventoryIdentity *out_identity)
{
  if (out_bytes_written != NULL)
    *out_bytes_written = 0;
  if (out_identity != NULL)
    memset (out_identity, 0, sizeof *out_identity);
  if (stage == NULL || out_bytes_written == NULL || out_identity == NULL
      || stage->failed || stage->finalized)
    return WYRELOG_E_INVALID;
  if (stage->bytes_written != stage->expected_bytes) {
    stage->failed = TRUE;
    return WYRELOG_E_POLICY;
  }
  wyrelog_error_t rc = authority_revalidate (stage);
  guint64 staged_size = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_get_size (stage->directory,
            &stage->native_stage, &staged_size);
  if (rc == WYRELOG_E_OK && staged_size != stage->expected_bytes)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_sync (stage->directory,
            &stage->native_stage);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_get_size (stage->directory,
            &stage->native_stage, &staged_size);
  if (rc == WYRELOG_E_OK && staged_size != stage->expected_bytes)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = authority_revalidate (stage);
  if (rc == WYRELOG_E_OK) {
    stage_identity (&stage->native_stage, out_identity);
    *out_bytes_written = stage->bytes_written;
    stage->finalized = TRUE;
  } else {
    stage->failed = TRUE;
  }
  return rc;
}

void
wyl_fact_offline_restore_stage_free (WylFactOfflineRestoreStage *stage)
{
  if (stage == NULL)
    return;
  /* Closing is not cleanup: operation-named orphans are recovery-owned. */
  wyl_fact_graph_stage_clear (&stage->native_stage);
  g_free (stage);
}
